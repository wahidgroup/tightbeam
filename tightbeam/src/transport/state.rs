//! Session state and provisioning for the encrypted transports.
//!
//! It holds the phase table a session moves through, the provisioning an
//! endpoint starts from, and the sealed traits that give each transport its
//! state accessors apart from I/O.

use core::marker::PhantomData;
use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::clock::{Clock, MonotonicInstant};
use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::utils::ValidityClock;
use crate::transport::builders::EnvelopeBuilder;
use crate::transport::envelopes::WireEnvelope;
use crate::transport::error::{ArrivalCause, ArrivalRefusal, TransportError, TransportFailure};
use crate::transport::handshake::receipt::StoredReceipt;
use crate::transport::handshake::{EstablishedSession, SessionPeer};
use crate::transport::handshake::{HandshakeProtocolKind, PeerAuthentication};
use crate::transport::TransportResult;
use crate::transport::{CheckedLimits, TransportLimits};
use crate::x509::Certificate;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::KeyPurposes;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::ObjectIdentifier;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::envelopes::TransportEnvelope;
#[cfg(all(
	any(feature = "tcp", feature = "async-transport"),
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::transport::handshake::negotiation::TransportAuthorizer;
#[cfg(mux_rekey)]
use crate::transport::handshake::negotiation::TransportOffer;
#[cfg(all(
	any(feature = "tcp", feature = "async-transport"),
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{
	BoxedServerHandshake, HandshakeMessage, HandshakeProvider, ServerIdentity, ValidatorChain,
};
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::{CmsIdentityPair, ProvisionedTrust};
#[cfg(mux_rekey)]
use crate::transport::handshake::{EpochMaterials, HandshakeError};
#[cfg(mux_rekey)]
use crate::transport::rekey::{RekeyDriver, Renewal};

mod dialable_encryption;

pub use dialable_encryption::DialableEncryption;
pub(crate) use dialable_encryption::Negotiation;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use dialable_encryption::Endpoint;

/// The wire mode a session may write, and the state that backs it.
///
/// Each arm carries what its phase needs. Session keys live in
/// [`SessionPhase::Encrypted`], so a completed handshake and its keys always
/// exist together.
///
/// # Sources
///
/// - CWE-311, missing encryption of sensitive data: <https://cwe.mitre.org/data/definitions/311.html>
pub enum SessionPhase {
	/// The endpoint names cleartext in place of encryption provisioning, so
	/// frames travel in the clear as a configured choice.
	Cleartext,
	/// Encryption is provisioned, and the session awaits the first handshake
	/// round. A write in this phase fails with
	/// [`TransportFailure::EncryptorUnavailable`].
	Provisioned,
	/// A handshake is in flight, and its deadline counts from `initiated_at`.
	Handshaking {
		/// The instant the handshake began, on the endpoint's clock.
		initiated_at: MonotonicInstant,
	},
	/// The handshake is complete, and the phase carries everything it agreed,
	/// so a move out of this phase drops the keys and their terms together.
	Encrypted(Box<EstablishedSession>),
	/// An exchange broke after its write, so the position of the stream is
	/// unknown. The phase is terminal: a pool discards the connection, and
	/// every later write and arrival fails with
	/// [`TransportError::ConnectionFailed`].
	Failed,
}

impl SessionPhase {
	/// Returns the start phase of an endpoint provisioned with `encryption`,
	/// and the phase the circuit breaker returns it to.
	///
	/// It is the one place that pairs provisioning with a phase. An endpoint
	/// with encryption material starts in `Provisioned`, because `Cleartext`
	/// would write application data in the clear (CWE-311).
	fn start_for<P: CryptoProvider>(encryption: &EncryptionConfig<P>) -> Self {
		if encryption.is_provisioned() {
			return Self::Provisioned;
		}

		Self::Cleartext
	}

	/// Whether this phase may write application traffic: cleartext, or an
	/// established session whose send cipher has a record left.
	///
	/// The pool leases a connection only in a writable phase, so a peer that
	/// stalls its handshake, and a session that spent its send cipher, keep
	/// that connection out of the pool. A phase added later stays unwritable
	/// until this method names it.
	pub fn is_writable(&self) -> bool {
		matches!(self, Self::Cleartext | Self::Encrypted(_)) && !self.is_spent()
	}

	/// Whether this phase holds a session whose send cipher has no record
	/// left. A multiplexed session renews its keys before the limit, and
	/// nothing renews a spent cipher, so the session carries no further
	/// exchange.
	pub(crate) fn is_spent(&self) -> bool {
		matches!(self, Self::Encrypted(session) if session.keys().send().is_spent())
	}

	/// Whether this phase admits `event`.
	///
	/// The alphabet is small and each event names one move, so two events that
	/// land on the same phase keep their own legality.
	const fn admits(&self, event: &SessionEvent) -> bool {
		// The circuit breaker resets a live session, and a broken exchange
		// fails it. `Failed` is terminal.
		let live = matches!(
			self,
			Self::Cleartext | Self::Provisioned | Self::Handshaking { .. } | Self::Encrypted(_)
		);

		match event {
			// A handshake may take more than one round.
			SessionEvent::BeginHandshake(_) => matches!(self, Self::Provisioned | Self::Handshaking { .. }),
			SessionEvent::Install(_) => matches!(self, Self::Handshaking { .. }),
			SessionEvent::Reset => live,
			#[cfg(any(feature = "tcp", feature = "async-transport"))]
			SessionEvent::Fail => live,
		}
	}

	/// Whether application traffic on this session must be encrypted.
	///
	/// The phase decides this for both directions, so a reader and a writer on
	/// one session reach the same answer.
	pub const fn requires_encryption(&self) -> bool {
		matches!(self, Self::Encrypted(_))
	}

	/// Whether the session awaits the end of a provisioned handshake.
	pub const fn is_handshake_pending(&self) -> bool {
		matches!(self, Self::Provisioned | Self::Handshaking { .. })
	}

	/// Whether a client owes the first round of its handshake: the session is
	/// provisioned for encryption, and no round began.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::state::SessionPhase;
	///
	/// assert!(SessionPhase::Provisioned.awaits_handshake());
	/// assert!(!SessionPhase::Cleartext.awaits_handshake());
	/// ```
	pub const fn awaits_handshake(&self) -> bool {
		matches!(self, Self::Provisioned)
	}

	/// The instant the in-flight handshake began, if one is in flight.
	pub const fn initiated_at(&self) -> Option<MonotonicInstant> {
		match self {
			Self::Handshaking { initiated_at } => Some(*initiated_at),
			_ => None,
		}
	}

	/// The bounds of a read in this phase at `now`, under `limits`.
	///
	/// The phase owns the instant a handshake began, so it alone derives the
	/// handshake deadline:
	///
	/// - A read while a handshake is pending faces an unauthenticated peer. It
	///   admits `handshake_wire` and must finish by the handshake deadline,
	///   counted from the first round, or from `now` before it.
	/// - Any other read admits the larger envelope ceiling and must finish
	///   within `operation_timeout` of `now`.
	/// - A deadline past every instant the clock can read never arrives, so the policy holds `None`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::clock::{Clock, SystemClock};
	/// use tightbeam::transport::state::SessionPhase;
	/// use tightbeam::transport::TransportLimits;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// let limits = TransportLimits::default();
	/// let now = SystemClock.monotonic();
	///
	/// // A read before the first handshake round faces an unauthenticated
	/// // peer, so it takes the handshake ceiling and the handshake allowance.
	/// let policy = SessionPhase::Provisioned.read_policy(&limits, now);
	///
	/// assert_eq!(policy.cap(), limits.handshake_wire);
	/// assert_eq!(policy.remaining(now)?, Some(limits.handshake_timeout));
	/// # Ok(())
	/// # }
	/// ```
	#[must_use]
	pub fn read_policy(&self, limits: &TransportLimits, now: MonotonicInstant) -> ReadPolicy {
		if !self.is_handshake_pending() {
			return ReadPolicy::established(limits.max_envelope(), limits, now);
		}

		let started = self.initiated_at().unwrap_or(now);
		let deadline = IoDeadline(started.checked_add(limits.handshake_timeout));

		ReadPolicy { cap: limits.handshake_wire, deadline }
	}
}

/// The bounds one read on a session runs under: the largest envelope it
/// admits and the instant it must finish by.
///
/// [`SessionPhase::read_policy`] decides it for a session, and
/// [`Self::established`] for a half split from an established one, so every
/// reader runs under the same ceiling and the same deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadPolicy {
	cap: usize,
	deadline: IoDeadline,
}

impl ReadPolicy {
	/// The bounds of a read on an established session at `now`: it admits
	/// `cap` and must finish within `operation_timeout`.
	///
	/// [`SessionPhase::read_policy`] yields it for every phase that awaits no
	/// handshake.
	#[must_use]
	pub fn established(cap: usize, limits: &TransportLimits, now: MonotonicInstant) -> Self {
		let deadline = IoDeadline(now.checked_add(limits.operation_timeout));
		Self { cap, deadline }
	}

	/// The largest envelope the read admits, in bytes on the wire.
	#[must_use]
	pub const fn cap(&self) -> usize {
		self.cap
	}

	/// The instant the read must finish by, or `None` when no deadline bounds
	/// it.
	#[must_use]
	pub const fn deadline(&self) -> Option<MonotonicInstant> {
		self.deadline.0
	}

	/// The budget left at `now`, or `None` when no deadline bounds the read.
	///
	/// It refuses a read whose deadline has passed before the reader awaits
	/// any byte, so a reader that re-arms per stage and one that arms once
	/// both stop at the same instant.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::DeadlineExceeded`] -- `now` is at or past the
	///   deadline.
	pub fn remaining(&self, now: MonotonicInstant) -> TransportResult<Option<Duration>> {
		self.deadline.remaining(now)
	}
}

/// The instant one read or write must finish by, or `None` when nothing
/// bounds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IoDeadline(pub(crate) Option<MonotonicInstant>);

impl IoDeadline {
	/// The budget left at `now`, or `None` when nothing bounds the I/O.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::DeadlineExceeded`] -- `now` is at or past the
	///   deadline.
	pub(crate) fn remaining(self, now: MonotonicInstant) -> TransportResult<Option<Duration>> {
		let Some(deadline) = self.0 else {
			return Ok(None);
		};

		let remaining = deadline.saturating_duration_since(now);
		if remaining.is_zero() {
			return Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded));
		}

		Ok(Some(remaining))
	}
}

/// Restricts [`EncryptedProtocolState`] and [`ServerHandshakeSlot`] to this
/// crate.
///
/// Only the in-crate transports implement [`sealed::Sealed`], each by name, so
/// no outside implementation can supply the session ciphers or the server
/// handshake slot that the traits hand out.
pub(crate) mod sealed {
	/// Each in-crate transport implements this trait by name.
	pub trait Sealed {}
}

/// The events that can happen to a session, which form the alphabet the phase
/// table reads.
pub(crate) enum SessionEvent {
	/// A handshake round starts at the given reading.
	BeginHandshake(MonotonicInstant),
	/// A completed handshake hands over everything it agreed.
	Install(Box<EstablishedSession>),
	/// The circuit breaker drops any session and returns to the start.
	Reset,
	/// An exchange broke after its write, so the session fails and stays
	/// failed. The emit of a TCP transport raises it.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	Fail,
}

/// The state of a session, which one constructor sets whole:
///
/// - Its phase, the provisioning it starts from, and its negotiation input.
/// - The mark of an exchange in flight, and the server orchestrator in flight.
/// - The clock its handshakes read.
///
/// Every field is private, so the phase an endpoint starts in and returns to
/// on a reset follows from its provisioning. Every later move consults the
/// transition table, so a session sits only in a phase the table names.
pub struct SessionState<P: CryptoProvider> {
	encryption: DialableEncryption<P>,
	negotiation: Negotiation,
	phase: SessionPhase,
	/// Whether an exchange began and has not settled. A caller that drops an
	/// exchange before it settles leaves the mark set.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	exchange_in_flight: bool,
	/// The server orchestrator that drives the handshake in flight, which
	/// each round advances only after the phase admits the round.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	handshake: HandshakeSlot,
	/// The clock that each handshake reads the validity period of a peer
	/// certificate on: the clock of the endpoint, or the crate clock.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	clock: ValidityClock<dyn Clock>,
}

impl<P: CryptoProvider> SessionState<P> {
	/// A session for `encryption`, at the phase that provisioning starts in.
	/// Its handshakes read the crate clock.
	///
	/// [`DialableEncryption`] guarantees the endpoint either holds a peer
	/// authority or names cleartext, so the start is `Provisioned` or a
	/// chosen `Cleartext`.
	pub fn new(encryption: DialableEncryption<P>) -> Self {
		Self::negotiating(encryption, Negotiation::default(), ValidityClock::CRATE)
	}

	/// A session for `encryption` that starts with the negotiation input
	/// `negotiation`, at the phase that provisioning starts in, whose
	/// handshakes read `clock`.
	pub(crate) fn negotiating(
		encryption: DialableEncryption<P>,
		negotiation: Negotiation,
		clock: ValidityClock<dyn Clock>,
	) -> Self {
		let phase = SessionPhase::start_for(encryption.encryption());

		// Only a handshake protocol reads the clock, so a build without one
		// drops it here.
		#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
		drop(clock);

		Self {
			encryption,
			negotiation,
			phase,
			#[cfg(any(feature = "tcp", feature = "async-transport"))]
			exchange_in_flight: false,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			handshake: HandshakeSlot::empty(),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			clock,
		}
	}

	/// The provisioning this endpoint holds.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		self.encryption.encryption()
	}

	/// The handshake protocol this session runs once provisioned.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::transport::handshake::HandshakeProtocolKind;
	/// use tightbeam::transport::state::{DialableEncryption, SessionState};
	///
	/// // A session built with no negotiation input reports the default
	/// // protocol.
	/// let session = SessionState::new(DialableEncryption::<DefaultCryptoProvider>::cleartext());
	/// assert_eq!(session.handshake_protocol(), HandshakeProtocolKind::Hpke);
	/// ```
	pub fn handshake_protocol(&self) -> HandshakeProtocolKind {
		self.negotiation.handshake_protocol()
	}

	/// The endpoint this session runs as. It lends the proof that the
	/// provisioning passed both checks of [`DialableEncryption::new`], beside
	/// the negotiation input as the setters below last wrote it, and the clock
	/// of its handshakes.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn endpoint(&self) -> Endpoint<'_, P> {
		Endpoint::new(&self.encryption, &self.negotiation, &self.clock)
	}

	/// The phase this session sits in.
	pub fn phase(&self) -> &SessionPhase {
		&self.phase
	}

	/// Applies `event`, and hands back the phase it replaced when the table
	/// admits it.
	///
	/// - It is the one writer of the phase, and it is private, so the named moves below are the only events.
	/// - A refused event leaves the session in its phase and yields `None`.
	/// - The replaced phase travels out whole, so a caller that detaches a session takes its keys from here.
	/// - A reset or a failure empties the handshake slot in the same move, so
	///   the next round builds a fresh orchestrator.
	fn apply(&mut self, event: SessionEvent) -> Option<SessionPhase> {
		if !self.phase.admits(&event) {
			return None;
		}

		let next = match event {
			SessionEvent::BeginHandshake(now) => {
				let initiated_at = self.phase.initiated_at().unwrap_or(now);
				SessionPhase::Handshaking { initiated_at }
			}
			SessionEvent::Install(session) => SessionPhase::Encrypted(session),
			SessionEvent::Reset => {
				#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				{
					self.handshake = HandshakeSlot::empty();
				}
				SessionPhase::start_for(self.encryption.encryption())
			}
			#[cfg(any(feature = "tcp", feature = "async-transport"))]
			SessionEvent::Fail => {
				#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				{
					self.handshake = HandshakeSlot::empty();
				}
				SessionPhase::Failed
			}
		};
		let replaced = core::mem::replace(&mut self.phase, next);

		Some(replaced)
	}

	/// Records a handshake round at `now`, and reports whether the phase table
	/// admits it.
	///
	/// The first round starts the deadline. A later round keeps the instant
	/// the first one recorded, so a slow peer cannot stretch the handshake by
	/// one allowance per round.
	#[must_use]
	pub fn begin_handshake(&mut self, now: MonotonicInstant) -> bool {
		self.apply(SessionEvent::BeginHandshake(now)).is_some()
	}

	/// Installs everything a completed handshake agreed, and bounds the send
	/// cipher by `encrypted_envelope`, this endpoint's encrypted-envelope
	/// ceiling (RFC 9846 § 5.5). The receive cipher counts the bytes it opens.
	///
	/// The terms enter the phase together, so an encrypted session always
	/// carries its terms and a per-key volume inside the AES-GCM bound at that
	/// ceiling.
	#[must_use]
	pub fn install_session(&mut self, session: EstablishedSession, encrypted_envelope: usize) -> bool {
		let bounded = session.with_envelope_ceiling(encrypted_envelope);
		self.apply(SessionEvent::Install(Box::new(bounded))).is_some()
	}

	/// The circuit breaker: drops any session and returns to the phase this
	/// endpoint's provisioning starts in. A [`SessionPhase::Failed`] session
	/// stays failed, because its stream has no sound position to return to.
	pub fn reset(&mut self) {
		// The session the breaker drops is spent, and a failed session stays
		// failed, so the replaced phase carries nothing a caller could act on.
		let _dropped = self.apply(SessionEvent::Reset);
	}

	/// Marks an exchange in flight, before its first write.
	/// [`Self::settle_exchange`] clears the mark, and
	/// [`SettledExchange::settled_exchange`] pairs the two around each
	/// exchange.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	fn begin_exchange(&mut self) {
		self.exchange_in_flight = true;
	}

	/// Settles `outcome`, the outcome of the exchange that
	/// [`Self::begin_exchange`] marked, and hands it back.
	///
	/// The mark clears. Every phase but [`SessionPhase::Failed`] moves to
	/// `Failed` on each error that [`TransportError::is_connection_error`]
	/// names, a handshake error included, because the stream position is then
	/// unknown and no later reader or writer can trust it (CWE-672).
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	fn settle_exchange<T>(&mut self, outcome: TransportResult<T>) -> TransportResult<T> {
		self.exchange_in_flight = false;

		let broke = outcome.as_ref().err().is_some_and(TransportError::is_connection_error);
		if broke {
			// The replaced phase holds the session of a stream whose position
			// is lost, so it drops here.
			let _broken = self.apply(SessionEvent::Fail);
		}

		outcome
	}

	/// Whether a pool may lease this connection again: its phase is writable,
	/// and no exchange is in flight.
	///
	/// [`TcpTransport::is_leasable`] is its one reader, for the house pool
	/// and for an outside protocol over the TCP transport alike.
	///
	/// [`TcpTransport::is_leasable`]: crate::transport::TcpTransport::is_leasable
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	#[cfg_attr(not(feature = "async-transport"), allow(dead_code))]
	pub(crate) fn is_leasable(&self) -> bool {
		self.phase.is_writable() && !self.exchange_in_flight
	}

	/// Admits `wire`, the DER of one wire envelope that arrived on this
	/// session, under `limits`, and returns the DER of the transport envelope
	/// it carries.
	///
	/// It is the receive twin of [`EncryptedProtocolState::apply_wire_mode`].
	/// The outer tag names the wire mode, and the phase decides which mode it
	/// admits, before a byte of the contents decodes:
	///
	/// - The session refuses an envelope past the ceiling of its mode, and keeps its phase.
	/// - An established session admits records alone, and opens each under its receive cipher.
	/// - Every other phase admits cleartext alone.
	/// - A refused mode, and a record that fails to open, trip the circuit
	///   breaker, so the session resets before the error returns. The refusal
	///   then holds the peer of the session that the breaker dropped.
	/// - A failed session refuses every arrival, because its stream has no sound position.
	///
	/// # Errors
	///
	/// Each refusal names the peer of the session, and reads as the
	/// [`TransportError`] it converts into:
	///
	/// - [`TransportError::ConnectionFailed`] -- the session is [`SessionPhase::Failed`].
	/// - [`TransportError::DerError`] -- `wire` is no wire envelope.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the envelope passes the ceiling
	///   of its mode.
	/// - The refusals of [`ArrivingEnvelope::admit_under`], under the receive
	///   cipher of an established session.
	///
	/// [`ArrivingEnvelope::admit_under`]: crate::transport::envelopes::ArrivingEnvelope::admit_under
	pub(crate) fn admit_arrival<'w>(
		&mut self,
		wire: &'w mut (impl AsMut<[u8]> + ?Sized),
		limits: &TransportLimits,
	) -> Result<&'w [u8], ArrivalRefusal> {
		if matches!(self.phase, SessionPhase::Failed) {
			return Err(self.refuse(TransportError::ConnectionFailed));
		}

		let wire = wire.as_mut();
		let wire_len = wire.len();
		let arriving = WireEnvelope::admit(wire).map_err(|error| self.refuse(TransportError::from(error)))?;
		if wire_len > limits.envelope_ceiling(arriving.mode()) {
			let oversize = TransportError::OperationFailed(TransportFailure::SizeExceeded);
			return Err(self.refuse(oversize));
		}

		let recv = self.recv_cipher();
		let admitted = arriving.admit_under(recv);

		admitted.map_err(|cause| self.trip(cause))
	}

	/// The receive cipher of the established session, lent exclusively, so
	/// one open runs on the key at a time.
	fn recv_cipher(&mut self) -> Option<&mut RecvCipher> {
		match &mut self.phase {
			SessionPhase::Encrypted(session) => Some(session.keys_mut().recv_mut()),
			_ => None,
		}
	}

	/// The refusal of an arrival for `cause`, with the peer of this session,
	/// which keeps its phase.
	pub(crate) fn refuse(&self, cause: impl Into<ArrivalCause>) -> ArrivalRefusal {
		ArrivalRefusal::new(cause, self.session_peer())
	}

	/// Trips the circuit breaker for an arrival refused for `cause`, and
	/// returns the refusal with the peer of the session that the breaker
	/// dropped.
	fn trip(&mut self, cause: ArrivalCause) -> ArrivalRefusal {
		let dropped = self.apply(SessionEvent::Reset);
		let peer = match dropped {
			Some(SessionPhase::Encrypted(session)) => session.into_session_peer(),
			_ => None,
		};

		ArrivalRefusal::of_dropped(cause, peer)
	}

	/// Classifies `envelope`, which [`Self::admit_arrival`] admitted, as one
	/// step of the inbound collector.
	///
	/// While a handshake is pending, the one cleartext this session admits is
	/// a handshake container, for the server's dispatcher. Any other envelope
	/// then is unsealed application traffic, so it trips the circuit breaker.
	/// Every other phase hands the envelope on.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- an envelope other than a
	///   handshake container arrived while a handshake is pending, and the
	///   circuit breaker resets the session.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn collect(&mut self, envelope: TransportEnvelope) -> TransportResult<CollectStep> {
		if !self.phase.is_handshake_pending() {
			return Ok(CollectStep::Envelope(envelope));
		}

		// The refusal names its cause, `MissingEncryption`, in place of the
		// `InvalidMessage` of the conversion.
		let Ok(message) = HandshakeMessage::try_from(envelope) else {
			self.reset();
			return Err(TransportError::MissingEncryption);
		};

		Ok(CollectStep::Handshake(message))
	}

	/// Detaches the keys of this session for the two halves of a split.
	///
	/// - A cleartext session answers `None`, because its halves take no keys.
	/// - An established session hands over both ciphers and returns to its start, which holds none.
	/// - A pending or failed session stays where it is, so a pending handshake keeps its deadline.
	///
	/// Only the async transport splits, so the method exists where that
	/// transport does.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the session is provisioned for
	///   encryption and its handshake has not completed.
	/// - [`TransportError::ConnectionFailed`] -- the session is [`SessionPhase::Failed`].
	#[cfg(any(feature = "tokio", feature = "async-transport"))]
	pub(crate) fn take_split_keys(&mut self) -> TransportResult<Option<(SendCipher, RecvCipher)>> {
		match self.phase {
			SessionPhase::Cleartext => Ok(None),
			SessionPhase::Provisioned | SessionPhase::Handshaking { .. } => Err(TransportError::InvalidState),
			SessionPhase::Failed => Err(TransportError::ConnectionFailed),
			SessionPhase::Encrypted(_) => {
				// The reset hands back the phase it replaced, which holds the
				// keys.
				let Some(SessionPhase::Encrypted(session)) = self.apply(SessionEvent::Reset) else {
					return Err(TransportError::InvalidState);
				};

				Ok(Some(session.into_keys().into_parts()))
			}
		}
	}

	/// Replaces the budget-grant policy a server consults.
	///
	/// This setter and the ones below change negotiation input alone, not the
	/// peer authority or the identities, so they change neither the start phase
	/// nor the answer of [`DialableEncryption::new`].
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(crate) fn authorize_transport(&mut self, authorizer: Arc<dyn TransportAuthorizer>) {
		self.negotiation.authorize_transport(authorizer);
	}

	/// Replaces the observer of budget-bearing handshake outcomes.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(crate) fn observe_sessions(&mut self, observer: Arc<dyn SessionObserver>) {
		self.negotiation.observe_sessions(observer);
	}

	/// Replaces the approver a client consults before it countersigns a
	/// challenge-bearing receipt.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(crate) fn approve_receipts(&mut self, approver: Arc<dyn ReceiptApprover>) {
		self.negotiation.approve_receipts(approver);
	}

	/// Replaces the handshake protocol a provisioned endpoint runs. The
	/// protocol decides how a handshake runs, and provisioning decides whether
	/// one is expected.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	pub(crate) fn select_handshake(&mut self, kind: HandshakeProtocolKind) {
		self.negotiation.select_handshake(kind);
	}

	/// The session this endpoint established, if it has one.
	pub fn established(&self) -> Option<&EstablishedSession> {
		match &self.phase {
			SessionPhase::Encrypted(session) => Some(session),
			_ => None,
		}
	}

	/// The send-direction cipher, which exists exactly while a session does.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptorUnavailable`] -- no handshake has
	///   installed keys on this session yet.
	pub fn encryptor(&self) -> TransportResult<&SendCipher> {
		let session = self
			.established()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))?;
		Ok(session.keys().send())
	}

	/// The receive-direction cipher, which exists exactly while a session does.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptorUnavailable`] -- no handshake has
	///   installed keys on this session yet.
	pub fn decryptor(&self) -> TransportResult<&RecvCipher> {
		let session = self
			.established()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))?;
		Ok(session.keys().recv())
	}

	/// The validated peer certificate: the client identity on a mutual-auth
	/// server, and the trust-store-validated server identity on a client.
	///
	/// It comes from the established session, so it is present while that
	/// session holds a validated peer.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.established()?.peer()
	}

	/// A shared handle to the validated peer certificate.
	pub fn peer_certificate_arc(&self) -> Option<Arc<Certificate>> {
		self.established()?.peer_arc()
	}

	/// The peer the established session recorded, with the identity of its
	/// key, as one record a session context shares.
	pub(crate) fn session_peer(&self) -> Option<&Arc<SessionPeer>> {
		self.established()?.session_peer()
	}

	/// The dual-signed session receipt of the established session.
	pub fn receipt(&self) -> Option<&StoredReceipt> {
		self.established()?.receipt()
	}

	/// A shared handle to the dual-signed session receipt.
	pub fn receipt_arc(&self) -> Option<Arc<StoredReceipt>> {
		self.established()?.receipt_arc()
	}

	/// Builds a state that sits directly in `phase`, so a test of the table
	/// starts from any phase and skips the moves that reach it.
	#[cfg(test)]
	pub(crate) fn at(encryption: EncryptionConfig<P>, phase: SessionPhase) -> Self {
		let encryption = DialableEncryption::unchecked(encryption);
		Self {
			encryption,
			negotiation: Negotiation::default(),
			phase,
			#[cfg(any(feature = "tcp", feature = "async-transport"))]
			exchange_in_flight: false,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			handshake: HandshakeSlot::empty(),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			clock: ValidityClock::CRATE,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: CryptoProvider> SessionState<P> {
	/// The slot of the server orchestrator in flight, which a TCP transport
	/// lends through [`ServerHandshakeSlot::handshake_slot`].
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	pub(crate) fn handshake_slot(&mut self) -> &mut HandshakeSlot {
		&mut self.handshake
	}

	/// Builds the server orchestrator of this endpoint into an empty slot,
	/// once per handshake.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the errors of the orchestrator build, which leave the slot empty.
	pub(crate) fn occupy_handshake(&mut self) -> TransportResult<()>
	where
		P: HandshakeProvider,
	{
		let Self { encryption, negotiation, handshake, clock, .. } = self;
		handshake.occupy(|| Endpoint::new(encryption, negotiation, clock).server_handshake())
	}

	/// Serves `request`, one handshake round at `now`: the phase admits the
	/// round first, and the orchestrator in the slot advances only then.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the phase refuses the round, or
	///   the slot holds no orchestrator. Either leaves the slot as it was.
	/// - The errors of [`HandshakeSlot::advance`].
	pub(crate) async fn advance_handshake(
		&mut self,
		request: HandshakeMessage,
		now: MonotonicInstant,
	) -> TransportResult<Round> {
		if !self.begin_handshake(now) {
			return Err(TransportError::InvalidState);
		}

		self.handshake.advance(request).await
	}
}

/// The outcome of one protocol-agnostic collector step.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub enum CollectStep {
	/// The step reads a cleartext handshake container for the server-side
	/// dispatcher, decoded once with the bytes it arrived as.
	Handshake(HandshakeMessage),
	/// The step reads an application envelope, decrypted, or in cleartext
	/// where the session admits cleartext.
	Envelope(TransportEnvelope),
}

#[cfg(mux_rekey)]
impl<P: CryptoProvider> SessionState<P> {
	/// Replaces the multiplexing capability this endpoint offers.
	///
	/// It changes negotiation input alone, as [`Self::authorize_transport`]
	/// does.
	pub(crate) fn offer_mux(&mut self, offer: Option<Arc<TransportOffer>>) {
		self.negotiation.offer_mux(offer);
	}

	/// Detaches the epoch rekey materials the handshake left, once, for
	/// [`Self::renew`] alone.
	///
	/// It is the only write into an installed session. A handle to the session
	/// itself would let a caller swap the keys under a phase that already
	/// reports the terms it agreed.
	fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		match &mut self.phase {
			SessionPhase::Encrypted(session) => session.take_epoch(),
			_ => None,
		}
	}

	/// Renews the established session under the terms of one mux role, which
	/// `renewal` reads from this session's endpoint, into its rekey driver and
	/// the dual-signed receipt it rotates.
	///
	/// - `renewal` runs once the session holds a receipt and a peer, so it
	///   builds the terms only for a session that renews.
	/// - The session refuses before the epoch materials leave it, so a refused
	///   session keeps its receipt, its peer, and its epoch.
	///
	/// # Returns
	///
	/// - `Ok(None)` when the session holds no dual-signed receipt, no recorded
	///   peer, or no epoch materials, or when `renewal` names no terms for the
	///   endpoint.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the signing use or
	///   the purpose of the peer's role refuses the peer's certificate.
	pub(crate) fn renew(
		&mut self,
		renewal: impl FnOnce(&Endpoint<'_, P>) -> Option<Renewal<P>>,
	) -> Result<Option<(RekeyDriver, Arc<StoredReceipt>)>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let Some(receipt) = self.receipt_arc() else {
			return Ok(None);
		};
		let Some(peer) = self.session_peer() else {
			return Ok(None);
		};
		let Some(renewal) = renewal(&self.endpoint()) else {
			return Ok(None);
		};

		// A rekey's server ephemeral differs from every static key the
		// handshake compared it with, a CMS server's key-agreement key among
		// them, so the renewal admits the whole peer the session recorded.
		let admitted = renewal.admit(peer)?;

		let Some(epoch) = self.take_epoch_materials() else {
			return Ok(None);
		};

		let reference = receipt.receipt().clone();
		let driver = admitted.driver(epoch, reference);
		Ok(Some((driver, receipt)))
	}
}

/// The identity a server endpoint presents: a signing identity alone, or the
/// CMS server's pair, which [`with_key_agreement`] builds once.
///
/// [`with_key_agreement`]: crate::transport::TransportEncryptionConfig::with_key_agreement
pub(crate) enum ServerIdentities<P: CryptoProvider> {
	/// A signing identity alone, which serves the HPKE flow under the
	/// provider `P`.
	Signing(SigningIdentity, PhantomData<fn() -> P>),
	/// The CMS server's signing and key-agreement identities, which serve
	/// both flows.
	#[cfg(feature = "transport-cms")]
	Cms(CmsIdentityPair<P::Kem>),
}

impl<P: CryptoProvider> Clone for ServerIdentities<P> {
	fn clone(&self) -> Self {
		match self {
			Self::Signing(identity, provider) => Self::Signing(identity.clone(), *provider),
			#[cfg(feature = "transport-cms")]
			Self::Cms(pair) => Self::Cms(pair.clone()),
		}
	}
}

impl<P: CryptoProvider> From<SigningIdentity> for ServerIdentities<P> {
	fn from(identity: SigningIdentity) -> Self {
		Self::Signing(identity, PhantomData)
	}
}

impl<P: CryptoProvider> ServerIdentities<P> {
	/// The identity that signs the endpoint's replies and receipts.
	pub(crate) fn signing(&self) -> &SigningIdentity {
		match self {
			Self::Signing(identity, _) => identity,
			#[cfg(feature = "transport-cms")]
			Self::Cms(pair) => pair.signing(),
		}
	}

	/// The identity that signs, moved out of the endpoint's identities.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn into_signing(self) -> SigningIdentity {
		match self {
			Self::Signing(identity, _) => identity,
			Self::Cms(pair) => pair.into_signing(),
		}
	}

	/// Refuses these identities for the server role unless each certificate
	/// admits the key purpose `purpose` (RFC 5280 §4.2.1.12).
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the errors of [`CertificateExt::require_purpose`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError> {
		match self {
			Self::Signing(identity, _) => identity.require_purpose(purpose),
			#[cfg(feature = "transport-cms")]
			Self::Cms(pair) => pair.require_purpose(purpose),
		}
	}

	/// The pair of a CMS server, which the CMS flow opens and signs with.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingKeyAgreementIdentity`] -- the server holds a signing identity alone.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn cms_pair(&self) -> TransportResult<&CmsIdentityPair<P::Kem>> {
		match self {
			Self::Cms(pair) => Ok(pair),
			Self::Signing(..) => Err(TransportError::MissingKeyAgreementIdentity),
		}
	}
}

/// The provisioning an endpoint holds before any handshake runs.
///
/// A builder decides it once, at build, so it travels as one value, and a
/// transport hands every field out through one accessor.
#[non_exhaustive]
#[derive(Clone)]
pub struct EncryptionConfig<P: CryptoProvider> {
	/// The trust store that validates the peer's certificate. `None` leaves
	/// the peer identity to a lower layer, so [`Self::check_dial_permitted`]
	/// requires another peer authority or a named cleartext choice.
	pub(crate) trust_store: Option<Arc<dyn CertificateTrust>>,
	/// The identity this endpoint presents as a server: the certificate and
	/// the key that signs its replies and its receipts, and for a CMS server
	/// the key-agreement identity its opening seals to.
	pub(crate) server_identity: Option<ServerIdentities<P>>,
	/// The trust in the CMS server, built once over its pinned key-agreement
	/// certificate, which the CMS handshake needs before the server speaks.
	#[cfg(feature = "transport-cms")]
	pub(crate) cms_server: Option<ProvisionedTrust>,
	/// The server policy each client handshake runs on its server's identity
	/// certificate, under either flow, or `None` for a client that sets none.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) server_policy: Option<ValidatorChain>,
	/// The identity this endpoint presents as a client for mutual
	/// authentication: the certificate and the key that proves it.
	pub(crate) client_identity: Option<SigningIdentity>,
	/// How a server endpoint authenticates its client.
	pub(crate) peer_authentication: PeerAuthentication,
	/// The key purpose of each role the endpoint's handshakes admit.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) key_purposes: KeyPurposes,
	/// Whether this endpoint names cleartext, and so accepts a peer it cannot
	/// authenticate.
	pub(crate) allow_cleartext: bool,
	/// The provider the endpoint's handshakes and sessions run under.
	pub(crate) provider: PhantomData<fn() -> P>,
}

impl<P: CryptoProvider> EncryptionConfig<P> {
	/// The trust store that validates the peer's certificate.
	pub fn trust_store(&self) -> Option<&Arc<dyn CertificateTrust>> {
		self.trust_store.as_ref()
	}

	/// The server certificate this endpoint presents, the one whose key
	/// signs its replies.
	pub fn server_certificate(&self) -> Option<&Certificate> {
		let identity = self.server_identity.as_ref();
		identity.map(|identity| identity.signing().certificate())
	}

	/// The client certificate this endpoint presents to a mutual-auth server.
	pub fn client_certificate(&self) -> Option<&Certificate> {
		self.client_identity.as_ref().map(SigningIdentity::certificate)
	}

	/// Whether this endpoint is provisioned to encrypt, which is whether it can
	/// establish who its peer is.
	///
	/// Each item names a peer authority, so the endpoint expects a handshake:
	///
	/// - A server certificate this endpoint presents.
	/// - Mutual authentication a server demands of its client.
	/// - A trust store a client checks the server certificate against.
	/// - The trust in a CMS server a client provisioned, which holds its store.
	///
	/// A client certificate proves the identity of this endpoint alone, so the
	/// list above leaves it out. A server policy narrows which server a trust
	/// admits, so the trust in a server answers for it here.
	pub fn is_provisioned(&self) -> bool {
		// The pattern names every field without `..`, so an added field breaks
		// the build until someone says whether it implies a handshake, and key
		// material cannot leave the endpoint in `Cleartext` unseen (CWE-311).
		let Self {
			server_identity,
			trust_store: _,
			peer_authentication,
			#[cfg(feature = "transport-cms")]
				cms_server: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				server_policy: _,
			client_identity: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				key_purposes: _,
			allow_cleartext: _,
			provider: _,
		} = self;

		server_identity.is_some() || self.trusts_a_server() || peer_authentication.requires_certificate()
	}

	/// Whether this endpoint holds a trust in a server, a trust store or the
	/// trust in a CMS server, which [`Self::is_provisioned`] and the dialer
	/// rule both read.
	fn trusts_a_server(&self) -> bool {
		// The pattern names every field without `..`, so an added field breaks
		// the build until someone says whether it trusts a server. The start
		// phase and the dialer rule then read every trust (CWE-311, CWE-295).
		let Self {
			trust_store,
			#[cfg(feature = "transport-cms")]
			cms_server,
			server_identity: _,
			peer_authentication: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				server_policy: _,
			client_identity: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				key_purposes: _,
			allow_cleartext: _,
			provider: _,
		} = self;
		#[cfg(feature = "transport-cms")]
		let cms_server = cms_server.is_some();
		#[cfg(not(feature = "transport-cms"))]
		let cms_server = false;

		trust_store.is_some() || cms_server
	}

	/// Whether this endpoint carries a client identity.
	pub fn has_client_identity(&self) -> bool {
		self.client_identity.is_some()
	}

	/// Checks whether this endpoint may reach a peer it cannot authenticate.
	///
	/// An endpoint that can establish nothing about its peer reaches whoever
	/// answers (CWE-295), and a named cleartext choice is the one way to
	/// accept that. Every transport holds provisioning that passed this rule,
	/// so a cleartext phase always carries a named choice.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- the endpoint
	///   authenticates no peer and names no cleartext, or it sets a server
	///   policy with no trust in a server, with or without cleartext, because
	///   the policy runs on the server a trust admits.
	pub fn check_dial_permitted(&self) -> TransportResult<()> {
		if !self.is_provisioned() && !self.allow_cleartext {
			return Err(TransportError::PeerAuthenticationUnconfigured);
		}
		if self.server_policy_without_trust() {
			return Err(TransportError::PeerAuthenticationUnconfigured);
		}

		Ok(())
	}

	/// Whether this endpoint sets a server policy and holds no trust in a
	/// server for the policy to read, a trust store or a CMS server trust.
	fn server_policy_without_trust(&self) -> bool {
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		let policy = self.server_policy.is_some();
		#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
		let policy = false;

		policy && !self.trusts_a_server()
	}

	/// Refuses this provisioning when an identity it presents names a key
	/// purpose other than its role's (RFC 5280 §4.2.1.12). It runs once, in
	/// [`DialableEncryption::new`].
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the errors of
	///   [`CertificateExt::require_purpose`], for the server identity under
	///   the server purpose or the client identity under the client's.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn admit_own_identities(&self) -> Result<(), CertificateValidationError> {
		if let Some(identity) = &self.server_identity {
			identity.require_purpose(self.key_purposes.server)?;
		}
		if let Some(identity) = &self.client_identity {
			identity.certificate().require_purpose(self.key_purposes.client)?;
		}

		Ok(())
	}

	/// Returns empty provisioning, which a builder accumulates into.
	///
	/// It authenticates no peer and names no cleartext, so it becomes a
	/// transport only after [`DialableEncryption::new`] accepts the additions.
	pub(crate) fn unconfigured() -> Self {
		Self {
			trust_store: None,
			server_identity: None,
			#[cfg(feature = "transport-cms")]
			cms_server: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			server_policy: None,
			client_identity: None,
			peer_authentication: PeerAuthentication::Anonymous,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			key_purposes: KeyPurposes::default(),
			allow_cleartext: false,
			provider: PhantomData,
		}
	}
}

/// The one server orchestrator in flight on an endpoint that accepts
/// handshakes, or none.
///
/// The slot is empty before the first client message arrives, again once the
/// handshake completes and the endpoint installs its terms, and again when the
/// session resets or fails. A round advances the orchestrator only after the
/// session phase admits the round.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct HandshakeSlot {
	orchestrator: Option<BoxedServerHandshake>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeSlot {
	/// A slot that holds no orchestrator.
	const fn empty() -> Self {
		Self { orchestrator: None }
	}

	/// Places `orchestrator` in the slot, in place of any orchestrator in
	/// flight, so the next round the endpoint serves runs it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::handshake::BoxedServerHandshake;
	/// use tightbeam::transport::state::ServerHandshakeSlot;
	/// use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
	///
	/// /// Serve the next handshake on `transport` with `orchestrator`.
	/// fn serve_with(transport: &mut TcpTransport<TokioStream>, orchestrator: BoxedServerHandshake) {
	///     transport.handshake_slot().install(orchestrator);
	/// }
	/// ```
	pub fn install(&mut self, orchestrator: BoxedServerHandshake) {
		self.orchestrator = Some(orchestrator);
	}

	/// Places the orchestrator that `build` returns in an empty slot, and
	/// keeps the orchestrator of a handshake in flight.
	///
	/// # Errors
	///
	/// - The error of `build`, which leaves the slot empty.
	pub(crate) fn occupy(
		&mut self,
		build: impl FnOnce() -> TransportResult<BoxedServerHandshake>,
	) -> TransportResult<()> {
		if self.orchestrator.is_some() {
			return Ok(());
		}

		let orchestrator = build()?;
		self.orchestrator = Some(orchestrator);
		Ok(())
	}

	/// Runs the orchestrator in the slot on `request`, one client message.
	///
	/// A reply means another round follows, and the orchestrator stays. No
	/// reply means the handshake is complete, so the orchestrator leaves the
	/// slot with the session it agreed.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the slot holds no orchestrator.
	/// - [`TransportError::HandshakeError`] -- the orchestrator refuses the
	///   request, or fails to complete the session.
	pub(crate) async fn advance(&mut self, request: HandshakeMessage) -> TransportResult<Round> {
		let orchestrator = self.orchestrator.as_mut().ok_or(TransportError::InvalidState)?;
		let reply = orchestrator.handle_request(request).await?;
		if let Some(reply) = reply {
			return Ok(Round::Reply(reply));
		}

		let finished = self.orchestrator.take().ok_or(TransportError::InvalidState)?;
		let session = finished.complete().await?;
		Ok(Round::Complete(session))
	}
}

/// The outcome of one server handshake round.
// A round lives for one step of the driver, so its session stays inline
// until the install boxes it once.
#[allow(clippy::large_enum_variant)]
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) enum Round {
	/// The orchestrator answers the round, and another round follows.
	Reply(HandshakeMessage),
	/// The orchestrator completed the handshake with the session it agreed.
	Complete(EstablishedSession),
}

/// An endpoint that accepts handshakes, and so keeps the orchestrator that
/// drives the one in flight.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait ServerHandshakeSlot: sealed::Sealed {
	/// The slot of this endpoint's in-flight server orchestrator.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::state::{HandshakeSlot, ServerHandshakeSlot};
	/// use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
	///
	/// /// The slot that serves the next handshake round of `transport`.
	/// fn slot_of(transport: &mut TcpTransport<TokioStream>) -> &mut HandshakeSlot {
	///     transport.handshake_slot()
	/// }
	/// ```
	fn handshake_slot(&mut self) -> &mut HandshakeSlot;

	/// Runs `operation` within `budget`, the time left to the handshake.
	///
	/// Each transport states in its impl how the budget binds.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::DeadlineExceeded`] -- the budget ran out.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::FailedPrecondition`] -- no timer can bind it.
	/// - The errors of `operation`.
	///
	/// # Examples
	///
	/// ```
	/// use std::net::TcpStream;
	/// use std::time::Duration;
	///
	/// use tightbeam::runtime::rt;
	/// use tightbeam::transport::state::ServerHandshakeSlot;
	/// use tightbeam::transport::tcp::sync::TcpTransport;
	///
	/// let operation = async { Ok(7) };
	/// let budget = Duration::from_secs(1);
	/// let bounded = <TcpTransport<TcpStream> as ServerHandshakeSlot>::within_budget(budget, operation);
	///
	/// assert_eq!(rt::block_on(bounded)?, 7);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[allow(async_fn_in_trait)]
	async fn within_budget<T, F>(budget: Duration, operation: F) -> TransportResult<T>
	where
		F: core::future::Future<Output = TransportResult<T>>;
}

/// The state accessors of an encrypted transport, separate from I/O.
///
/// The trait is sealed: only this crate's transports implement it, so the
/// session ciphers it hands out come from a handshake this crate ran.
///
/// ```compile_fail,E0277
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::transport::state::{EncryptedProtocolState, SessionState};
/// use tightbeam::transport::CheckedLimits;
///
/// struct Forged;
///
/// impl EncryptedProtocolState for Forged {
///     type CryptoProvider = DefaultCryptoProvider;
///
///     fn session_state(&self) -> &SessionState<DefaultCryptoProvider> {
///         unimplemented!()
///     }
///
///     fn session_state_mut(&mut self) -> &mut SessionState<DefaultCryptoProvider> {
///         unimplemented!()
///     }
///
///     fn limits(&self) -> &CheckedLimits {
///         unimplemented!()
///     }
/// }
/// ```
pub trait EncryptedProtocolState: sealed::Sealed {
	/// The crypto provider bound to this transport.
	type CryptoProvider: CryptoProvider + Send + Sync + 'static;

	/// This endpoint's session state.
	fn session_state(&self) -> &SessionState<Self::CryptoProvider>;

	/// Mutable access to this endpoint's session state.
	///
	/// The state guards its own phase, so a caller that reaches this places
	/// the session only in a phase that the transition table names.
	fn session_state_mut(&mut self) -> &mut SessionState<Self::CryptoProvider>;

	/// Applies this session's wire mode to `builder`.
	///
	/// Every envelope this endpoint writes passes through here, so the phase
	/// decides the wire mode once per session instead of once per call site.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptorUnavailable`] -- the session is
	///   [`SessionPhase::Provisioned`] or [`SessionPhase::Handshaking`], before
	///   the handshake installs keys.
	/// - [`TransportError::ConnectionFailed`] -- the session is [`SessionPhase::Failed`].
	fn apply_wire_mode<'a>(&'a self, builder: EnvelopeBuilder<'a>) -> TransportResult<EnvelopeBuilder<'a>> {
		match self.session_state().phase() {
			SessionPhase::Encrypted(session) => Ok(builder.sealed_by(session.keys().send())),
			SessionPhase::Cleartext => Ok(builder.cleartext()),
			SessionPhase::Provisioned | SessionPhase::Handshaking { .. } => {
				Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
			}
			SessionPhase::Failed => Err(TransportError::ConnectionFailed),
		}
	}

	/// Installs the session that a completed handshake agreed, under this
	/// endpoint's encrypted-envelope ceiling
	/// ([`SessionState::install_session`]).
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the phase refuses the install.
	fn install_established(&mut self, session: EstablishedSession) -> TransportResult<()> {
		let encrypted_envelope = self.limits().encrypted_envelope;
		if !self.session_state_mut().install_session(session, encrypted_envelope) {
			return Err(TransportError::InvalidState);
		}

		Ok(())
	}

	/// The provisioning this endpoint holds.
	fn encryption(&self) -> &EncryptionConfig<Self::CryptoProvider> {
		self.session_state().encryption()
	}

	/// Every ceiling this endpoint enforces, as a set whose ceilings agree.
	fn limits(&self) -> &CheckedLimits;

	/// Returns the allowance for the whole handshake, which bounds
	/// handshake-phase reads.
	fn to_handshake_timeout(&self) -> Duration {
		self.limits().handshake_timeout
	}

	/// The production instrumentation collector attached to this transport.
	#[cfg(feature = "instrument")]
	fn to_trace_ref(&self) -> Option<&TraceCollector> {
		None
	}

	/// Attaches `trace` as the production instrumentation collector of this
	/// transport, the trail [`Self::to_trace_ref`] reads.
	///
	/// An accept loop attaches its collector to each transport it accepts, so
	/// the events of the connection reach the owner's collector.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::transport::state::EncryptedProtocolState;
	/// use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
	///
	/// /// Hand `transport` the collector of the server that accepted it.
	/// fn adopt(transport: TcpTransport<TokioStream>, trace: &TraceCollector) -> TcpTransport<TokioStream> {
	///     EncryptedProtocolState::with_trace(transport, trace.share())
	/// }
	/// ```
	#[cfg(feature = "instrument")]
	fn with_trace(self, trace: TraceCollector) -> Self
	where
		Self: Sized;

	/// The peer address that a listener accepted this endpoint from, which the
	/// acceptance record names, or `None` for an endpoint no listener accepted.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::state::EncryptedProtocolState;
	/// use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
	///
	/// /// Whether a listener accepted `transport`.
	/// fn was_accepted(transport: &TcpTransport<TokioStream>) -> bool {
	///     transport.accepted_from().is_some()
	/// }
	/// ```
	#[cfg(feature = "instrument")]
	fn accepted_from(&self) -> Option<core::net::SocketAddr> {
		None
	}
}

/// Runs one exchange of an endpoint whole: the mark of the exchange in
/// flight, the exchange, and its settlement.
///
/// The TCP transports of both planes run each exchange through it, so the
/// mark and the settlement of one exchange always pair. Every
/// [`EncryptedProtocolState`] implements it, inside this crate alone.
#[cfg(any(feature = "tcp", feature = "async-transport"))]
pub(crate) trait SettledExchange: EncryptedProtocolState + Sized {
	/// Marks an exchange in flight, runs `exchange` on this endpoint, and
	/// settles its outcome.
	///
	/// A broken exchange fails the session ([`SessionState::settle_exchange`]).
	/// A caller that drops the future before it settles leaves the mark set,
	/// so [`SessionState::is_leasable`] keeps the connection out of a pool.
	async fn settled_exchange<T>(
		&mut self,
		exchange: impl AsyncFnOnce(&mut Self) -> TransportResult<T>,
	) -> TransportResult<T> {
		self.session_state_mut().begin_exchange();
		let outcome = exchange(self).await;
		self.session_state_mut().settle_exchange(outcome)
	}
}

#[cfg(any(feature = "tcp", feature = "async-transport"))]
impl<E: EncryptedProtocolState> SettledExchange for E {}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::clock::{Clock, ManualClock};
	use crate::constants::{DEFAULT_MAX_ENCRYPTED_ENVELOPE, DEFAULT_REKEY_RECORD_LIMIT};
	use crate::crypto::aead::SessionKeys;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::testing::TestFrame;

	#[cfg(feature = "testing")]
	use crate::crypto::x509::CanonicalKey;
	#[cfg(feature = "testing")]
	use crate::policy::SessionContext;
	#[cfg(all(feature = "transport-cms", feature = "testing"))]
	use crate::testing::fixtures::TestCmsServer;
	#[cfg(feature = "testing")]
	use crate::testing::fixtures::{TestCertificate, TestKey};
	#[cfg(feature = "testing")]
	use crate::transport::handshake::SessionPeer;

	/// A probe that holds the phase the trait reads back.
	struct PhaseProbe {
		state: SessionState<DefaultCryptoProvider>,
		limits: CheckedLimits,
	}

	impl PhaseProbe {
		/// Mutual authentication alone makes the probe expect encryption.
		fn provisioned(phase: SessionPhase) -> Self {
			Self::holding(provisioned_encryption(), phase)
		}

		fn cleartext(phase: SessionPhase) -> Self {
			Self::holding(DialableEncryption::cleartext().encryption().clone(), phase)
		}

		fn holding(encryption: EncryptionConfig<DefaultCryptoProvider>, phase: SessionPhase) -> Self {
			Self { state: SessionState::at(encryption, phase), limits: CheckedLimits::default() }
		}
	}

	impl sealed::Sealed for PhaseProbe {}

	impl EncryptedProtocolState for PhaseProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &CheckedLimits {
			&self.limits
		}

		fn session_state(&self) -> &SessionState<DefaultCryptoProvider> {
			&self.state
		}

		fn session_state_mut(&mut self) -> &mut SessionState<DefaultCryptoProvider> {
			&mut self.state
		}

		// The phase probe reads its trail through the default `to_trace_ref`,
		// so `with_trace` drops the collector.
		#[cfg(feature = "instrument")]
		fn with_trace(self, _trace: TraceCollector) -> Self {
			self
		}
	}

	fn provisioned_encryption() -> EncryptionConfig<DefaultCryptoProvider> {
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator::default());
		let peer_authentication = PeerAuthentication::Anonymous.and(validator);
		EncryptionConfig { peer_authentication, ..EncryptionConfig::unconfigured() }
	}

	fn handshaking() -> SessionPhase {
		SessionPhase::Handshaking { initiated_at: ManualClock::default().monotonic() }
	}

	/// A provisioned endpoint starts where it expects a handshake, and a
	/// cleartext one only where its provisioning names cleartext (CWE-311).
	#[test]
	fn a_session_starts_where_its_provisioning_says() -> TransportResult<()> {
		let provisioned = SessionState::new(DialableEncryption::new(provisioned_encryption())?);
		assert!(matches!(provisioned.phase(), SessionPhase::Provisioned));

		let cleartext = SessionState::<DefaultCryptoProvider>::new(DialableEncryption::cleartext());
		assert!(matches!(cleartext.phase(), SessionPhase::Cleartext));
		Ok(())
	}

	/// A CMS client with a provisioned server trust holds a peer authority,
	/// so it starts where it expects a handshake, even when it names
	/// cleartext (CWE-311).
	#[cfg(all(feature = "transport-cms", feature = "testing"))]
	#[test]
	fn a_cms_client_of_a_provisioned_server_starts_provisioned() -> TransportResult<()> {
		let server = TestCmsServer::generate("tightbeam provisioned client");
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			cms_server: Some(server.trust()),
			allow_cleartext: true,
			..EncryptionConfig::unconfigured()
		};

		let session = SessionState::new(DialableEncryption::new(encryption)?);
		assert!(matches!(session.phase(), SessionPhase::Provisioned));
		Ok(())
	}

	/// `DialableEncryption::new` refuses provisioning that neither
	/// authenticates a peer nor names cleartext (CWE-295).
	#[test]
	fn provisioning_without_a_peer_authority_or_cleartext_is_refused() {
		let refused = DialableEncryption::<DefaultCryptoProvider>::new(EncryptionConfig::unconfigured());
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
	}

	/// The breaker returns a provisioned session to `Provisioned` whatever
	/// phase it reached, so a broken session never writes in the clear
	/// (CWE-311).
	#[test]
	fn resetting_a_provisioned_session_returns_it_to_provisioned() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.session_state_mut().reset();
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
	}

	#[test]
	fn resetting_a_cleartext_session_returns_it_to_cleartext() {
		let mut probe = PhaseProbe::cleartext(SessionPhase::Cleartext);
		probe.session_state_mut().reset();
		assert!(matches!(probe.session_state().phase(), SessionPhase::Cleartext));
	}

	#[test]
	fn only_cleartext_and_encrypted_phases_are_writable() {
		assert!(SessionPhase::Cleartext.is_writable());
		assert!(!SessionPhase::Provisioned.is_writable());
		assert!(!handshaking().is_writable());
		assert!(!SessionPhase::Failed.is_writable());
	}

	/// A failed session writes nothing, because its stream has no sound
	/// position.
	#[test]
	fn a_failed_session_refuses_to_apply_a_wire_mode() -> TransportResult<()> {
		let probe = PhaseProbe::cleartext(SessionPhase::Failed);
		let builder = EnvelopeBuilder::request(TestFrame::v0(None, None));
		let refusal = probe.apply_wire_mode(builder);
		assert!(matches!(refusal, Err(TransportError::ConnectionFailed)));
		Ok(())
	}

	/// A failed session reads nothing, because its stream has no sound
	/// position.
	#[test]
	fn a_failed_session_refuses_an_arrival() -> TransportResult<()> {
		let mut state = SessionState::at(provisioned_encryption(), SessionPhase::Failed);
		let mut wire = [0x30u8, 0x00];
		let limits = TransportLimits::default();
		let admitted = state.admit_arrival(&mut wire, &limits).map_err(TransportError::from);
		assert!(matches!(admitted, Err(TransportError::ConnectionFailed)));
		Ok(())
	}

	/// An exchange in flight keeps its connection out of a pool, and its
	/// settlement returns the connection.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	#[test]
	fn an_exchange_in_flight_is_leasable_once_it_settles() -> TransportResult<()> {
		let mut state = SessionState::at(provisioned_encryption(), SessionPhase::Cleartext);
		state.begin_exchange();
		let in_flight = state.is_leasable();

		state.settle_exchange(Ok(()))?;
		assert_eq!((in_flight, state.is_leasable()), (false, true));
		Ok(())
	}

	// A pool leases an established session while its send cipher has a record
	// left. A ceiling past the renewal volume spends the cipher before its
	// first record.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	crate::tb_cases! {
		fn an_established_session_is_leasable_while_its_cipher_has_a_record((ceiling, expected): (usize, bool)) {
			let keys = SessionKeys::for_client(crate::testing::TestKey::insecure_directional_keys());
			let session = EstablishedSession::forged(keys.with_envelope_ceiling(ceiling), None, None);
			let state = SessionState::at(provisioned_encryption(), SessionPhase::Encrypted(Box::new(session)));
			assert_eq!(state.is_leasable(), expected);
		}
		cases {
			a_cipher_with_records_left => (DEFAULT_MAX_ENCRYPTED_ENVELOPE, true),
			a_spent_cipher => (usize::MAX, false),
		}
	}

	/// The seal of the last record a send cipher holds takes its session out
	/// of the pool. A ceiling of the whole renewal volume leaves one record.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	#[test]
	fn the_last_seal_of_a_send_cipher_takes_its_session_out_of_the_pool() -> TransportResult<()> {
		let ceiling = crate::constants::RENEWAL_VOLUME_BYTES as usize;
		let keys = SessionKeys::for_client(crate::testing::TestKey::insecure_directional_keys());
		let session = EstablishedSession::forged(keys.with_envelope_ceiling(ceiling), None, None);
		let state = SessionState::at(provisioned_encryption(), SessionPhase::Encrypted(Box::new(session)));
		let before = state.is_leasable();

		state.encryptor()?.encrypt_next(b"the last record".to_vec())?;
		assert_eq!((before, state.is_leasable()), (true, false));
		Ok(())
	}

	// An exchange settles under one rule: every phase but `Failed` fails on
	// an error that leaves the stream unsound, a handshake error included, and
	// keeps its phase on an error that proves the frame never left.
	#[cfg(all(feature = "testing", any(feature = "tcp", feature = "async-transport")))]
	crate::tb_cases! {
		fn an_exchange_settles_its_session((phase, error, landing): (&str, TransportError, &str)) -> TransportResult<()> {
			let mut state = SessionState::at(provisioned_encryption(), phase_named(phase));
			let settled = state.settle_exchange::<()>(Err(error));
			assert!(settled.is_err());
			assert_eq!(
				core::mem::discriminant(state.phase()),
				core::mem::discriminant(&phase_named(landing)),
				"{phase} must land in {landing}"
			);
			Ok(())
		}
		cases {
			a_close_fails_an_encrypted_session => ("encrypted", TransportError::ConnectionClosed, "failed"),
			a_deadline_fails_a_cleartext_session => (
				"cleartext",
				TransportError::OperationFailed(TransportFailure::DeadlineExceeded),
				"failed"
			),
			a_handshake_error_fails_a_handshaking_session => (
				"handshaking",
				TransportError::HandshakeError(crate::transport::handshake::HandshakeError::InvalidState),
				"failed"
			),
			an_undecodable_answer_fails_a_cleartext_session => ("cleartext", TransportError::InvalidMessage, "failed"),
			a_missing_encryptor_keeps_a_provisioned_session => (
				"provisioned",
				TransportError::OperationFailed(TransportFailure::EncryptorUnavailable),
				"provisioned"
			),
			a_failed_session_stays_failed => ("failed", TransportError::ConnectionClosed, "failed"),
		}
	}

	/// Every envelope path applies the wire mode here, so this refusal is the
	/// one guard against a cleartext write from a stalled session (CWE-311).
	#[test]
	fn pending_session_refuses_to_apply_a_wire_mode() {
		let probe = PhaseProbe::provisioned(handshaking());
		let frame = TestFrame::v0(None, None);

		let builder = EnvelopeBuilder::request(frame);
		let refusal = probe.apply_wire_mode(builder);
		assert!(matches!(
			refusal,
			Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
		));
	}

	/// A provisioned session writes nothing in the clear after a reset from
	/// any phase, even a reset through the public `reset` method.
	#[test]
	fn a_reset_provisioned_session_refuses_a_cleartext_write() -> TransportResult<()> {
		let mut state = SessionState::new(DialableEncryption::new(provisioned_encryption())?);
		state.reset();

		let probe = PhaseProbe { state, limits: CheckedLimits::default() };
		let builder = EnvelopeBuilder::request(TestFrame::v0(None, None));
		let refusal = probe.apply_wire_mode(builder);
		assert!(matches!(
			refusal,
			Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
		));
		Ok(())
	}

	// The cases check every event a session can raise from every phase it can
	// sit in against the table. `SessionState::apply` is the only writer of
	// the phase, so a pair the table omits is a move no caller can make.
	#[cfg(feature = "testing")]
	crate::tb_cases! {
		fn the_phase_table((phase, event, admitted, landing): (&str, &str, bool, &str)) {
			let mut state = SessionState::at(provisioned_encryption(), phase_named(phase));
			assert_eq!(state.apply(event_named(event)).is_some(), admitted, "{phase} on {event}");
			assert_eq!(
				core::mem::discriminant(state.phase()),
				core::mem::discriminant(&phase_named(landing)),
				"{phase} on {event} must land in {landing}"
			);
		}
		cases {
			cleartext_refuses_begin => ("cleartext", "begin", false, "cleartext"),
			cleartext_refuses_install => ("cleartext", "install", false, "cleartext"),
			cleartext_resets_to_start => ("cleartext", "reset", true, "provisioned"),
			provisioned_begins => ("provisioned", "begin", true, "handshaking"),
			provisioned_refuses_install => ("provisioned", "install", false, "provisioned"),
			provisioned_resets_to_start => ("provisioned", "reset", true, "provisioned"),
			handshaking_begins_again => ("handshaking", "begin", true, "handshaking"),
			handshaking_installs => ("handshaking", "install", true, "encrypted"),
			handshaking_resets_to_start => ("handshaking", "reset", true, "provisioned"),
			encrypted_refuses_begin => ("encrypted", "begin", false, "encrypted"),
			encrypted_refuses_install => ("encrypted", "install", false, "encrypted"),
			encrypted_resets_to_start => ("encrypted", "reset", true, "provisioned"),
			failed_refuses_begin => ("failed", "begin", false, "failed"),
			failed_refuses_install => ("failed", "install", false, "failed"),
			failed_refuses_reset => ("failed", "reset", false, "failed"),
		}
	}

	// The failure of an exchange moves every live phase to `Failed`, and a
	// failed session refuses it again. A build with a TCP transport raises it.
	#[cfg(all(feature = "testing", any(feature = "tcp", feature = "async-transport")))]
	crate::tb_cases! {
		fn the_failure_rows_of_the_phase_table((phase, admitted): (&str, bool)) -> TransportResult<()> {
			let mut state = SessionState::at(provisioned_encryption(), phase_named(phase));
			assert_eq!(state.apply(SessionEvent::Fail).is_some(), admitted, "{phase} on fail");
			assert!(matches!(state.phase(), SessionPhase::Failed), "{phase} on fail must land in failed");
			Ok(())
		}
		cases {
			cleartext_fails => ("cleartext", true),
			provisioned_fails => ("provisioned", true),
			handshaking_fails => ("handshaking", true),
			encrypted_fails => ("encrypted", true),
			failed_refuses_fail => ("failed", false),
		}
	}

	#[cfg(feature = "testing")]
	fn phase_named(name: &str) -> SessionPhase {
		match name {
			"cleartext" => SessionPhase::Cleartext,
			"provisioned" => SessionPhase::Provisioned,
			"handshaking" => handshaking(),
			"failed" => SessionPhase::Failed,
			_ => SessionPhase::Encrypted(Box::new(established_session())),
		}
	}

	#[cfg(feature = "testing")]
	fn event_named(name: &str) -> SessionEvent {
		match name {
			"begin" => SessionEvent::BeginHandshake(ManualClock::default().monotonic()),
			"install" => SessionEvent::Install(Box::new(established_session())),
			_ => SessionEvent::Reset,
		}
	}

	/// A later handshake round keeps the instant the first round recorded, so
	/// the deadline covers the whole exchange instead of one round.
	#[test]
	fn a_later_handshake_round_keeps_the_first_rounds_deadline() {
		let clock = ManualClock::default();
		let started = clock.monotonic();
		let mut state = SessionState::at(provisioned_encryption(), SessionPhase::Provisioned);
		assert!(state.begin_handshake(started));

		clock.advance(Duration::from_secs(5));

		assert!(state.begin_handshake(clock.monotonic()));
		assert_eq!(state.phase().initiated_at(), Some(started));
	}

	/// A handshake read admits the handshake ceiling and counts its deadline
	/// from the first round, so a later reading gets what is left of the one
	/// allowance.
	#[test]
	fn a_handshake_read_counts_from_the_first_round() -> TransportResult<()> {
		let clock = ManualClock::default();
		let started = clock.monotonic();
		let limits = TransportLimits { handshake_timeout: Duration::from_secs(10), ..TransportLimits::default() };
		let phase = SessionPhase::Handshaking { initiated_at: started };

		clock.advance(Duration::from_secs(4));

		let policy = phase.read_policy(&limits, clock.monotonic());
		let remaining = policy.remaining(clock.monotonic())?;
		assert_eq!(policy.cap(), limits.handshake_wire);
		assert_eq!(remaining, Some(Duration::from_secs(6)));
		Ok(())
	}

	/// The policy refuses a handshake read at or past its deadline before the
	/// reader awaits any byte.
	#[test]
	fn a_handshake_read_past_its_deadline_is_refused() {
		let clock = ManualClock::default();
		let started = clock.monotonic();
		let limits = TransportLimits { handshake_timeout: Duration::from_secs(10), ..TransportLimits::default() };
		let phase = SessionPhase::Handshaking { initiated_at: started };

		clock.advance(Duration::from_secs(10));

		let policy = phase.read_policy(&limits, clock.monotonic());
		let refused = policy.remaining(clock.monotonic());
		assert!(matches!(
			refused,
			Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
		));
	}

	/// A read before the first handshake round faces an unauthenticated peer
	/// too, so it takes the handshake ceiling and the full allowance from the
	/// reading it starts at.
	#[test]
	fn a_provisioned_read_gets_the_full_handshake_allowance() -> TransportResult<()> {
		let clock = ManualClock::default();
		let limits = TransportLimits { handshake_timeout: Duration::from_secs(10), ..TransportLimits::default() };

		let policy = SessionPhase::Provisioned.read_policy(&limits, clock.monotonic());
		let remaining = policy.remaining(clock.monotonic())?;

		assert_eq!(policy.cap(), limits.handshake_wire);
		assert_eq!(remaining, Some(Duration::from_secs(10)));
		Ok(())
	}

	/// A read outside the handshake admits the larger envelope ceiling and runs
	/// under the operation timeout.
	#[test]
	fn a_cleartext_read_admits_the_envelope_ceiling_under_the_operation_timeout() -> TransportResult<()> {
		let clock = ManualClock::default();
		let limits = TransportLimits { operation_timeout: Duration::from_secs(3), ..TransportLimits::default() };

		let policy = SessionPhase::Cleartext.read_policy(&limits, clock.monotonic());
		let remaining = policy.remaining(clock.monotonic())?;
		assert_eq!(policy.cap(), limits.max_envelope());
		assert_eq!(remaining, Some(Duration::from_secs(3)));
		Ok(())
	}

	/// An admitted event hands back the phase it replaced, whole, so the
	/// instant a handshake recorded leaves through the table, which is the one
	/// writer of the phase.
	#[test]
	fn an_admitted_event_hands_back_the_phase_it_replaced() {
		let clock = ManualClock::default();
		let started = clock.monotonic();
		let mut state = SessionState::at(provisioned_encryption(), SessionPhase::Handshaking { initiated_at: started });

		let replaced = state.apply(SessionEvent::Reset);
		assert!(matches!(replaced, Some(SessionPhase::Handshaking { initiated_at }) if initiated_at == started));
		assert!(matches!(state.phase(), SessionPhase::Provisioned));
	}

	/// A split takes the keys of an established session and leaves the state
	/// at its start, through the same table every other move takes.
	#[cfg(all(feature = "testing", any(feature = "tokio", feature = "async-transport")))]
	#[test]
	fn a_split_takes_the_keys_and_returns_the_session_to_its_start() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(established_session())?;

		let keys = probe.session_state_mut().take_split_keys()?;
		assert!(keys.is_some());
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
		Ok(())
	}

	/// A handshake in flight holds no keys, so a split refuses it and leaves it
	/// in place, and its deadline counts from the instant that it recorded.
	#[cfg(any(feature = "tokio", feature = "async-transport"))]
	#[test]
	fn a_split_of_a_pending_handshake_leaves_its_deadline_in_place() {
		let clock = ManualClock::default();
		let started = clock.monotonic();
		let mut state = SessionState::at(provisioned_encryption(), SessionPhase::Handshaking { initiated_at: started });

		let refused = state.take_split_keys();
		assert!(matches!(refused, Err(TransportError::InvalidState)));
		assert_eq!(state.phase().initiated_at(), Some(started));
	}

	// A split answers on the phase alone: a cleartext session splits with no
	// keys, an established one hands over its keys, a pending handshake is
	// refused as invalid, and a failed session as failed.
	#[cfg(all(feature = "testing", any(feature = "tokio", feature = "async-transport")))]
	crate::tb_cases! {
		fn a_split_answers_by_phase((phase, answer): (&str, &str)) {
			let mut state = SessionState::at(provisioned_encryption(), phase_named(phase));
			let split = state.take_split_keys();
			assert_eq!(split_named(&split), answer, "{phase} must split as {answer}");
		}
		cases {
			cleartext_splits_without_keys => ("cleartext", "cleartext"),
			encrypted_hands_over_its_keys => ("encrypted", "keys"),
			provisioned_is_refused => ("provisioned", "invalid"),
			handshaking_is_refused => ("handshaking", "invalid"),
			failed_is_refused_as_failed => ("failed", "failed"),
		}
	}

	/// The name of the answer of a split, as the cases of
	/// `a_split_answers_by_phase` spell it.
	#[cfg(all(feature = "testing", any(feature = "tokio", feature = "async-transport")))]
	fn split_named(split: &TransportResult<Option<(SendCipher, RecvCipher)>>) -> &'static str {
		match split {
			Ok(None) => "cleartext",
			Ok(Some(_)) => "keys",
			Err(TransportError::InvalidState) => "invalid",
			Err(TransportError::ConnectionFailed) => "failed",
			Err(_) => "another error",
		}
	}

	/// A handshake restart under a live session would drop its keys, so the
	/// table refuses the move and the session survives it.
	#[cfg(feature = "testing")]
	#[test]
	fn the_phase_table_refuses_restarting_a_handshake_on_a_live_session() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(established_session())?;

		let now = ManualClock::default().monotonic();
		assert!(!probe.session_state_mut().begin_handshake(now));
		assert!(probe.session_state().peer_certificate().is_some());
		Ok(())
	}

	/// An established session admits encrypted records alone, so an injected
	/// handshake container cannot draw a cleartext reply out of it (CWE-319).
	#[cfg(feature = "testing")]
	#[test]
	fn an_established_session_reads_only_encrypted() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(established_session())?;
		assert!(probe.session_state().phase().requires_encryption());
		Ok(())
	}

	/// A completed handshake and the terms it agreed enter the phase together.
	#[cfg(feature = "testing")]
	#[test]
	fn installing_a_session_lands_every_term_it_agreed() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(established_session())?;

		let session = probe.session_state().established().ok_or(TransportError::InvalidState)?;
		assert!(session.peer().is_some());
		assert!(probe.session_state().peer_certificate().is_some());
		Ok(())
	}

	/// An installed session's send cipher takes this endpoint's
	/// encrypted-envelope ceiling, so a doubled ceiling halves the send record
	/// limit (RFC 9846 § 5.5). The receive cipher keeps its fixed record
	/// limit, because it bounds the volume by the bytes it opens.
	#[cfg(feature = "testing")]
	#[test]
	fn installing_a_session_bounds_its_send_cipher_by_the_envelope_ceiling() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		let limits = TransportLimits { encrypted_envelope: 2 * DEFAULT_MAX_ENCRYPTED_ENVELOPE, ..*probe.limits };
		probe.limits = limits.checked()?;
		probe.install_established(established_session())?;

		let send_limit = probe.session_state().encryptor()?.rekey_limit();
		let recv_limit = probe.session_state().decryptor()?.rekey_limit();
		assert_eq!(send_limit, DEFAULT_REKEY_RECORD_LIMIT / 2);
		assert_eq!(recv_limit, DEFAULT_REKEY_RECORD_LIMIT);
		Ok(())
	}

	/// The circuit breaker drops the session whole. The peer identity of the
	/// dropped session must not stay readable, because authorization reads it.
	#[cfg(feature = "testing")]
	#[test]
	fn a_reset_drops_the_peer_the_dead_session_established() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(established_session())?;
		assert!(probe.session_state().peer_certificate().is_some());

		probe.session_state_mut().reset();
		assert!(probe.session_state().peer_certificate().is_none());
		Ok(())
	}

	/// A split takes the keys out, and the state left behind holds none, so a
	/// second split is refused.
	#[cfg(all(feature = "testing", any(feature = "tokio", feature = "async-transport")))]
	#[test]
	fn a_split_leaves_no_keys_behind() -> TransportResult<()> {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(established_session())?;
		let _keys = probe.session_state_mut().take_split_keys()?;

		let again = probe.session_state_mut().take_split_keys();
		assert!(probe.session_state().established().is_none());
		assert!(matches!(again, Err(TransportError::InvalidState)));
		Ok(())
	}

	/// A capture lends the key identity its session recorded, so a session
	/// whose peer holds a secp256k1 key in the compressed form proves the
	/// identity of that key in the uncompressed form.
	#[cfg(feature = "testing")]
	#[test]
	fn a_capture_proves_the_peer_of_a_key_in_either_form() -> TransportResult<()> {
		let certificate = fixture_certificate();
		let expected = CanonicalKey::of(&certificate.tbs_certificate.subject_public_key_info)?;
		let compressed = TestCertificate::with_compressed_key(certificate);
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.install_established(session_of(compressed))?;

		let captured = SessionContext::capture(&probe);
		let proven = captured.proven_peer().map(|peer| peer.as_key());
		assert_eq!(proven, Some(&expected));
		Ok(())
	}

	/// A session runs the handshake protocol its last selection named, and
	/// reports it.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	#[test]
	fn a_session_reports_the_handshake_protocol_it_selected() {
		let mut state = SessionState::at(provisioned_encryption(), SessionPhase::Provisioned);
		state.select_handshake(HandshakeProtocolKind::Cms);
		assert_eq!(state.handshake_protocol(), HandshakeProtocolKind::Cms);
	}

	/// A completed session with a peer identity, which authorization reads.
	#[cfg(feature = "testing")]
	fn established_session() -> EstablishedSession {
		session_of(fixture_certificate())
	}

	/// A completed session whose peer is `certificate`.
	#[cfg(feature = "testing")]
	fn session_of(certificate: Certificate) -> EstablishedSession {
		let keys = SessionKeys::for_client(crate::testing::TestKey::insecure_directional_keys());
		let peer = SessionPeer::try_from(Arc::new(certificate)).expect("a test certificate records its peer");
		EstablishedSession::forged(keys, None, Some(peer))
	}

	#[cfg(feature = "testing")]
	fn fixture_certificate() -> Certificate {
		TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
	}
}
