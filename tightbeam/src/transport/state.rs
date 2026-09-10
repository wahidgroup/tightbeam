//! Protocol state management traits
//!
//! Separates encrypted-transport state accessors from I/O.

use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::store::CertificateTrust;
use crate::transport::builders::EnvelopeBuilder;
use crate::transport::envelopes::WireMode;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver, StoredReceipt};
use crate::transport::handshake::{HandshakeInstant, HandshakeKeyManager, HandshakeProtocolKind};

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::BoxedServerHandshake;
use crate::transport::TransportLimits;
use crate::transport::TransportResult;
use crate::x509::Certificate;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "aead")]
use crate::transport::handshake::{EpochMaterials, EstablishedSession};

/// Which wire mode a session is entitled to write, and the state backing it.
///
/// The phase is stored rather than derived, and each arm carries what that
/// phase needs. Session keys live in [`SessionPhase::Encrypted`], so a
/// completed handshake without keys, or keys without a completed handshake,
/// cannot be built.
///
/// # Sources
///
/// - CWE-311, missing encryption of sensitive data:
///   <https://cwe.mitre.org/data/definitions/311.html>
#[cfg(feature = "x509")]
#[derive(Default)]
pub enum SessionPhase {
	/// The endpoint carries no encryption provisioning, so frames travel in
	/// the clear as a configured choice.
	#[default]
	Cleartext,
	/// Encryption is provisioned and no handshake has started. A write in
	/// this phase fails with [`TransportFailure::EncryptorUnavailable`].
	Provisioned,
	/// A handshake is in flight, measured against `initiated_at`.
	Handshaking { initiated_at: HandshakeInstant },
	/// The handshake completed. The phase carries everything it agreed, so a
	/// session's keys and the terms that go with them cannot be separated, and
	/// leaving this phase drops all of them together.
	Encrypted(Box<EstablishedSession>),
}

#[cfg(feature = "x509")]
impl SessionPhase {
	/// A pooled connection is leased only in a writable phase, so a peer that
	/// stalls its handshake keeps that connection out of the pool. A phase
	/// added later stays unwritable until it is named here.
	pub const fn is_writable(&self) -> bool {
		matches!(self, Self::Cleartext | Self::Encrypted(_))
	}

	/// Whether a session may move from this phase to `next`.
	///
	/// A session either stays cleartext, or runs
	/// `Provisioned -> Handshaking -> Encrypted`. The circuit breaker returns
	/// any provisioned phase to its start.
	const fn permits(&self, next: &Self) -> bool {
		matches!(
			(self, next),
			// Provisioning, then the handshake that follows it.
			(Self::Cleartext, Self::Provisioned)
				| (Self::Provisioned, Self::Handshaking { .. })
				| (Self::Handshaking { .. }, Self::Handshaking { .. })
				| (Self::Handshaking { .. }, Self::Encrypted(_))
				// The circuit breaker, which returns a session to its start.
				| (
					Self::Provisioned | Self::Handshaking { .. } | Self::Encrypted(_),
					Self::Provisioned | Self::Cleartext,
				)
				| (Self::Cleartext, Self::Cleartext)
		)
	}

	/// Whether application traffic on this session must be encrypted.
	///
	/// The phase decides this for both directions, so a reader and a writer on
	/// one session reach the same answer.
	pub const fn requires_encryption(&self) -> bool {
		matches!(self, Self::Encrypted(_))
	}

	/// Whether a handshake is provisioned but not yet complete.
	pub const fn is_handshake_pending(&self) -> bool {
		matches!(self, Self::Provisioned | Self::Handshaking { .. })
	}

	/// When the in-flight handshake began, if one is in flight.
	pub const fn initiated_at(&self) -> Option<HandshakeInstant> {
		match self {
			Self::Handshaking { initiated_at } => Some(*initiated_at),
			_ => None,
		}
	}
}

/// Restricts [`EncryptedProtocolState`] to this crate.
///
/// The trait hands out session ciphers and the server handshake slot, which an
/// outside implementation could supply from anywhere. Implementing it is kept
/// in-crate so those come from a handshake this crate ran.
#[cfg(feature = "x509")]
mod sealed {
	pub trait Sealed {}
}

/// Marks a type as an in-crate transport state, which is what
/// [`EncryptedProtocolState`] requires.
#[cfg(feature = "x509")]
pub trait SealedProtocolState: sealed::Sealed {}

#[cfg(feature = "x509")]
impl<T: SealedProtocolState> sealed::Sealed for T {}

/// A session's phase, which moves only along the transition table.
///
/// The phase is private and every move below consults the table, so a caller
/// cannot place a session in a phase the table does not name.
#[cfg(feature = "x509")]
#[derive(Default)]
pub struct SessionState {
	phase: SessionPhase,
}

#[cfg(feature = "x509")]
impl SessionState {
	/// Where this session currently sits.
	pub fn phase(&self) -> &SessionPhase {
		&self.phase
	}

	/// Advance to `next`, reporting whether the table allowed the move.
	///
	/// The one writer of the phase, private so that the named transitions
	/// below are the only moves a caller can ask for. A refused move leaves
	/// the session where it was.
	fn advance(&mut self, next: SessionPhase) -> bool {
		if !self.phase.permits(&next) {
			return false;
		}

		self.phase = next;

		true
	}

	/// Move to `Provisioned` when `encryption` holds material a handshake
	/// needs.
	///
	/// The one place that pairs the configuration's answer with the phase it
	/// implies. A transport holding a certificate but still claiming
	/// `Cleartext` would write application data in the clear (CWE-311).
	pub fn provision_for<P: CryptoProvider>(&mut self, encryption: &EncryptionConfig<P>) {
		if !encryption.is_provisioned() {
			return;
		}

		// A session past `Cleartext` is already provisioned or beyond, so a
		// declined move is one that would change nothing.
		let _provisioned = self.advance(SessionPhase::Provisioned);
	}

	/// Record that a handshake has started, timed from now.
	#[must_use]
	pub fn begin_handshake(&mut self) -> bool {
		self.advance(SessionPhase::Handshaking { initiated_at: HandshakeInstant::now() })
	}

	/// Install everything a completed handshake agreed.
	///
	/// The terms enter the phase together, so a session that reports itself
	/// encrypted always carries the terms it runs under.
	#[must_use]
	pub fn install_session(&mut self, session: EstablishedSession) -> bool {
		self.advance(SessionPhase::Encrypted(Box::new(session)))
	}

	/// Drop any session and return to the phase this endpoint starts in.
	///
	/// The circuit breaker. `expects_encryption` names which start that is:
	/// an endpoint holding encryption material returns to `Provisioned`, one
	/// without it to `Cleartext`.
	pub fn reset(&mut self, expects_encryption: bool) {
		let start = if expects_encryption {
			SessionPhase::Provisioned
		} else {
			SessionPhase::Cleartext
		};

		// The breaker runs on a session already in trouble, so a phase that
		// declines the move is already where the reset would put it.
		let _returned_to_start = self.advance(start);
	}

	/// Detach the epoch rekey materials the handshake left, once.
	///
	/// The only write into an installed session. Handing out the session
	/// itself would let a caller swap the keys under a phase that already
	/// reports the terms it agreed.
	#[cfg(feature = "aead")]
	pub fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		match &mut self.phase {
			SessionPhase::Encrypted(session) => session.epoch.take(),
			_ => None,
		}
	}

	/// The session this endpoint established, if it has one.
	pub fn established(&self) -> Option<&EstablishedSession> {
		match &self.phase {
			SessionPhase::Encrypted(session) => Some(session),
			_ => None,
		}
	}

	/// Send-direction cipher, which exists exactly while a session does.
	///
	/// # Errors
	///
	/// - [`TransportFailure::EncryptorUnavailable`] -- no handshake has
	///   installed keys on this session yet.
	pub fn encryptor(&self) -> TransportResult<&SendCipher> {
		let session = self
			.established()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))?;
		Ok(session.keys.send())
	}

	/// Receive-direction cipher, which exists exactly while a session does.
	///
	/// # Errors
	///
	/// - [`TransportFailure::EncryptorUnavailable`] -- no handshake has
	///   installed keys on this session yet.
	pub fn decryptor(&self) -> TransportResult<&RecvCipher> {
		let session = self
			.established()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))?;
		Ok(session.keys.recv())
	}

	/// Validated peer certificate: client identity on a mutual-auth server,
	/// trust-store-validated server identity on a client.
	///
	/// Read from the established session, so it is present exactly while that
	/// session is.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.established()?.peer.as_deref()
	}

	/// Shared handle to the validated peer certificate.
	pub fn peer_certificate_arc(&self) -> Option<Arc<Certificate>> {
		self.established()?.peer.as_ref().map(Arc::clone)
	}

	/// Dual-signed session receipt from the established session.
	pub fn receipt(&self) -> Option<&StoredReceipt> {
		self.established()?.receipt.as_deref()
	}

	/// Shared handle to the dual-signed session receipt.
	pub fn receipt_arc(&self) -> Option<Arc<StoredReceipt>> {
		self.established()?.receipt.as_ref().map(Arc::clone)
	}

	/// Take the phase out, for a caller that consumes the endpoint.
	pub fn into_phase(self) -> SessionPhase {
		self.phase
	}

	/// Place a probe directly in `phase`, so a test of the table does not have
	/// to walk the table to reach its starting point.
	#[cfg(test)]
	pub(crate) fn at(phase: SessionPhase) -> Self {
		Self { phase }
	}
}

/// A client certificate bound to the handshake key that proves it.
///
/// The pair travels together, so a caller cannot hand over one without the
/// other. Both halves are `Arc`, so passing it copies neither.
#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct ClientIdentity<C: CryptoProvider = DefaultCryptoProvider> {
	certificate: Arc<Certificate>,
	key: Arc<HandshakeKeyManager<C>>,
}

#[cfg(feature = "x509")]
impl<C: CryptoProvider> ClientIdentity<C> {
	/// Bind a certificate to the handshake key that proves it.
	pub fn new(certificate: Arc<Certificate>, key: Arc<HandshakeKeyManager<C>>) -> Self {
		Self { certificate, key }
	}

	/// Write this identity into `encryption`, so both halves land together.
	pub fn install(&self, encryption: &mut EncryptionConfig<C>) {
		encryption.client_certificate = Some(Arc::clone(&self.certificate));
		encryption.key_manager = Some(Arc::clone(&self.key));
	}
}

/// Everything an endpoint was provisioned with before any handshake runs.
///
/// Provisioning is decided once, when the endpoint is built, so it travels as
/// one value. A transport supplies it through a single accessor and every
/// field is then present, rather than each being asked for separately.
#[cfg(feature = "x509")]
#[non_exhaustive]
#[derive(Clone)]
pub struct EncryptionConfig<P: CryptoProvider> {
	/// Trust store that validates the peer's certificate. `None` leaves the peer
	/// identity to a lower layer, which [`Self::check_peer_authentication`]
	/// requires the endpoint to have named.
	pub(crate) trust_store: Option<Arc<dyn CertificateTrust>>,
	/// Local server certificate this endpoint presents.
	pub(crate) server_certificate: Option<Arc<Certificate>>,
	/// Provisioned server chain, ordered root to leaf, required by the CMS
	/// key-transport handshake before the server speaks.
	pub(crate) server_certificate_chain: Option<Arc<[Certificate]>>,
	/// Client certificate presented for mutual authentication.
	pub(crate) client_certificate: Option<Arc<Certificate>>,
	/// Validators applied to a peer client certificate under mutual
	/// authentication.
	pub(crate) client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	/// Signing key manager backing this endpoint's identity and
	/// countersignatures.
	pub(crate) key_manager: Option<Arc<HandshakeKeyManager<P>>>,
	/// Domain separation tag mixed into AEAD associated data.
	pub(crate) aad_domain_tag: Option<&'static [u8]>,
	/// Local multiplexing capability advertised in the handshake.
	pub(crate) mux_offer: Option<Arc<TransportOffer>>,
	/// Budget-grant policy between the client's offer and the server's accept.
	/// `None` grants the local configuration ceiling.
	pub(crate) transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	/// Approver consulted for a challenge-bearing session receipt. `None`
	/// fails closed when a challenge is present.
	pub(crate) receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	/// Observer recording budget-bearing handshake outcomes.
	pub(crate) session_observer: Option<Arc<dyn SessionObserver>>,
	/// Handshake protocol used once encryption is provisioned.
	pub(crate) handshake_protocol: HandshakeProtocolKind,
	/// Whether this endpoint accepts running without authenticating its peer.
	pub(crate) allow_cleartext: bool,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> EncryptionConfig<P> {
	/// Whether this endpoint can establish who its peer is.
	///
	/// A server presents its own certificate and validates a client through
	/// `client_validators`. A client validates the server through its trust
	/// store. A client certificate proves who this endpoint is, so it answers
	/// a different question and is absent here.
	pub fn authenticates_peer(&self) -> bool {
		self.trust_store.is_some() || self.client_validators.is_some() || self.server_certificate.is_some()
	}

	/// Trust store that validates the peer's certificate.
	pub fn trust_store(&self) -> Option<&Arc<dyn CertificateTrust>> {
		self.trust_store.as_ref()
	}

	/// Local server certificate this endpoint presents.
	pub fn server_certificate(&self) -> Option<&Certificate> {
		self.server_certificate.as_deref()
	}

	/// Client certificate presented for mutual authentication.
	pub fn client_certificate(&self) -> Option<&Certificate> {
		self.client_certificate.as_deref()
	}

	/// Handshake protocol used once encryption is provisioned.
	pub fn handshake_protocol(&self) -> HandshakeProtocolKind {
		self.handshake_protocol
	}

	/// Whether this endpoint is provisioned to encrypt.
	///
	/// A server certificate, a trust store, or client validators each mean a
	/// handshake is expected. This is the one definition the handshake
	/// dispatcher, the inbound collector, and the cleartext split all read.
	pub fn is_provisioned(&self) -> bool {
		self.server_certificate.is_some() || self.trust_store.is_some() || self.client_validators.is_some()
	}

	/// Whether this endpoint carries a client identity.
	pub fn has_client_identity(&self) -> bool {
		self.client_certificate.is_some()
	}

	/// Whether any encryption material is installed at all.
	///
	/// Broader than [`Self::is_provisioned`]: a client identity alone starts no
	/// handshake, yet it means this endpoint was configured for a secured link,
	/// so handing it a cleartext path is a configuration error.
	pub fn has_encryption_material(&self) -> bool {
		self.is_provisioned() || self.has_client_identity() || self.key_manager.is_some()
	}

	/// Whether this configuration must name cleartext before it is used.
	///
	/// A builder refuses an endpoint that authenticates no peer, so choosing
	/// an unauthenticated session is something the caller states.
	pub fn requires_named_cleartext(&self) -> bool {
		!self.authenticates_peer() && !self.allow_cleartext
	}

	/// The one definition of an endpoint that must not reach the wire.
	///
	/// A client that presents an identity while it can establish nothing about
	/// its peer would hand that identity, and its traffic, to whoever answered
	/// the address (CWE-295). Naming cleartext accepts that.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- a client
	///   identity is provisioned with no means of authenticating the peer.
	pub fn check_peer_authentication(&self) -> TransportResult<()> {
		if self.has_client_identity() && !self.authenticates_peer() && !self.allow_cleartext {
			return Err(TransportError::PeerAuthenticationUnconfigured);
		}

		Ok(())
	}
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> Default for EncryptionConfig<P> {
	fn default() -> Self {
		Self {
			trust_store: None,
			server_certificate: None,
			server_certificate_chain: None,
			client_certificate: None,
			client_validators: None,
			key_manager: None,
			aad_domain_tag: None,
			mux_offer: None,
			transport_authorizer: None,
			receipt_approver: None,
			session_observer: None,
			handshake_protocol: HandshakeProtocolKind::default(),
			allow_cleartext: false,
		}
	}
}

/// An endpoint that accepts handshakes, and so keeps the orchestrator driving
/// the one in flight.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub trait ServerHandshakeSlot: SealedProtocolState {
	/// The orchestrator carrying this endpoint's in-flight server handshake.
	///
	/// `None` before the first client message arrives, and again once the
	/// handshake completes and its terms are installed.
	fn server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake>;
}

/// State accessors for encrypted transports, separate from I/O.
#[cfg(feature = "x509")]
pub trait EncryptedProtocolState: SealedProtocolState {
	/// Crypto provider bound to this transport.
	type CryptoProvider: CryptoProvider + Send + Sync + 'static;

	/// This endpoint's session state.
	fn session_state(&self) -> &SessionState;

	/// Mutable access to this endpoint's session state.
	///
	/// The state guards its own phase, so a caller reaching this still cannot
	/// place the session in a phase the transition table does not name.
	fn session_state_mut(&mut self) -> &mut SessionState;

	/// A server certificate, a trust store, or client validators each imply a
	/// handshake, so the dispatcher and the wire-mode decision agree on what
	/// counts as provisioned.
	fn expects_encryption(&self) -> bool {
		self.encryption().is_provisioned()
	}

	/// Drop any session and return to the phase this endpoint starts in.
	fn reset_session(&mut self) {
		let expects_encryption = self.expects_encryption();
		self.session_state_mut().reset(expects_encryption);
	}

	/// Every envelope this endpoint writes passes through here, so the wire
	/// mode is decided once per session rather than once per call site.
	///
	/// # Errors
	///
	/// - [`TransportFailure::EncryptorUnavailable`] -- the session is
	///   [`SessionPhase::Provisioned`] or [`SessionPhase::Handshaking`], so the
	///   frame waits for the handshake to install keys.
	fn apply_wire_mode<'a>(&'a self, builder: EnvelopeBuilder<'a>) -> TransportResult<EnvelopeBuilder<'a>> {
		match self.session_state().phase() {
			SessionPhase::Encrypted(session) => {
				Ok(builder.with_wire_mode(WireMode::Encrypted).with_encryptor(session.keys.send()))
			}
			SessionPhase::Cleartext => {
				self.encryption().check_peer_authentication()?;
				Ok(builder.with_wire_mode(WireMode::Cleartext))
			}
			SessionPhase::Provisioned | SessionPhase::Handshaking { .. } => {
				Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
			}
		}
	}

	/// What this endpoint was provisioned with.
	fn encryption(&self) -> &EncryptionConfig<Self::CryptoProvider>;

	/// Every ceiling this endpoint enforces.
	fn limits(&self) -> &TransportLimits;

	/// Absolute deadline applied to handshake-phase reads.
	fn to_handshake_timeout(&self) -> Duration {
		self.limits().handshake_timeout
	}

	/// Production instrumentation collector attached to this transport.
	#[cfg(feature = "instrument")]
	fn to_trace_ref(&self) -> Option<&TraceCollector> {
		None
	}
}

#[cfg(all(test, feature = "x509", feature = "aead"))]
mod tests {
	use super::*;
	use crate::asn1::{Frame, Metadata};
	use crate::crypto::aead::SessionKeys;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::Version;

	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	use crate::testing::utils::{create_test_certificate, create_test_signing_key};

	/// Holds the phase the trait reads back.
	struct PhaseProbe {
		state: SessionState,
		encryption: EncryptionConfig<DefaultCryptoProvider>,
		limits: TransportLimits,
	}

	impl PhaseProbe {
		/// Client validators alone make the probe expect encryption, which is
		/// what `provision` reads.
		fn provisioned(phase: SessionPhase) -> Self {
			let client_validators = Some(Arc::new(Vec::new()));
			let encryption = EncryptionConfig { client_validators, ..EncryptionConfig::default() };
			Self { state: SessionState::at(phase), encryption, limits: TransportLimits::default() }
		}

		fn unprovisioned(phase: SessionPhase) -> Self {
			Self {
				state: SessionState::at(phase),
				encryption: EncryptionConfig::default(),
				limits: TransportLimits::default(),
			}
		}
	}

	impl SealedProtocolState for PhaseProbe {}

	impl EncryptedProtocolState for PhaseProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &TransportLimits {
			&self.limits
		}

		fn encryption(&self) -> &EncryptionConfig<DefaultCryptoProvider> {
			&self.encryption
		}

		fn session_state(&self) -> &SessionState {
			&self.state
		}

		fn session_state_mut(&mut self) -> &mut SessionState {
			&mut self.state
		}
	}

	fn handshaking() -> SessionPhase {
		SessionPhase::Handshaking { initiated_at: HandshakeInstant::now() }
	}

	#[test]
	fn an_unprovisioned_session_is_cleartext() {
		let probe = PhaseProbe::unprovisioned(SessionPhase::Cleartext);
		assert!(matches!(probe.session_state().phase(), SessionPhase::Cleartext));
	}

	/// Every move a session can attempt, checked against the table that admits
	/// it. `SessionState::advance` is the only writer of the phase, so a pair
	/// the table omits is a move no caller can make.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn the_table_admits_exactly_the_moves_a_session_may_make() {
		// Ordered so the permitted matrix below reads row by row.
		let names = ["cleartext", "provisioned", "handshaking", "encrypted"];
		let phase_for = |name: &str| match name {
			"cleartext" => SessionPhase::Cleartext,
			"provisioned" => SessionPhase::Provisioned,
			"handshaking" => handshaking(),
			_ => SessionPhase::Encrypted(Box::new(established_session())),
		};

		// A session either stays cleartext, or walks provisioned to
		// handshaking to encrypted. Any provisioned phase may reset.
		let permitted = [
			("cleartext", "cleartext"),
			("cleartext", "provisioned"),
			("provisioned", "provisioned"),
			("provisioned", "handshaking"),
			("provisioned", "cleartext"),
			("handshaking", "handshaking"),
			("handshaking", "encrypted"),
			("handshaking", "provisioned"),
			("handshaking", "cleartext"),
			("encrypted", "provisioned"),
			("encrypted", "cleartext"),
		];

		for from in names {
			for to in names {
				let mut state = SessionState::at(phase_for(from));
				let moved = state.advance(phase_for(to));
				let expected = permitted.contains(&(from, to));

				assert_eq!(moved, expected, "{from} to {to}");

				// A refused move leaves the session where it was, so a caller
				// that ignores the answer still cannot corrupt the phase.
				let landed = if moved {
					to
				} else {
					from
				};
				assert_eq!(
					core::mem::discriminant(state.phase()),
					core::mem::discriminant(&phase_for(landed)),
					"{from} to {to} must land in {landed}"
				);
			}
		}
	}

	/// Restarting a handshake under a live session would drop its keys, so the
	/// table refuses the move and the session survives it.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn the_phase_table_refuses_restarting_a_handshake_on_a_live_session() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		assert!(probe.session_state_mut().install_session(established_session()));
		assert!(!probe.session_state_mut().begin_handshake());
		assert!(probe.session_state().peer_certificate().is_some());
	}

	/// An established session admits nothing cleartext, so an injected
	/// handshake container cannot draw a cleartext reply out of it (CWE-319).
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn an_established_session_reads_only_encrypted() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		assert!(probe.session_state_mut().install_session(established_session()));
		assert!(probe.session_state().phase().requires_encryption());

		// The breaker returns the session to its start, so the peer the dead
		// session established is no longer readable.
		probe.reset_session();
		assert!(probe.session_state().peer_certificate().is_none());
	}

	/// A caller that names cleartext and also presents an identity reaches the
	/// wire. The decision the caller made and the check that guards the wire
	/// read one value, so they cannot disagree.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn a_named_cleartext_client_with_an_identity_reaches_the_wire() {
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			client_certificate: Some(Arc::new(fixture_certificate())),
			allow_cleartext: true,
			..EncryptionConfig::default()
		};

		let probe = PhaseProbe {
			state: SessionState::at(SessionPhase::Cleartext),
			encryption,
			limits: TransportLimits::default(),
		};
		let frame = Frame {
			version: Version::V0,
			metadata: Metadata::default(),
			message: Vec::new(),
			integrity: None,
			nonrepudiation: None,
		};

		let builder = EnvelopeBuilder::request(frame);
		assert!(probe.apply_wire_mode(builder).is_ok());
	}

	/// A completed handshake and the terms it agreed enter the phase together.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn installing_a_session_lands_every_term_it_agreed() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		assert!(probe.session_state_mut().install_session(established_session()));
		let SessionPhase::Encrypted(session) = probe.session_state().phase() else {
			panic!("installing a session must leave the phase encrypted");
		};

		assert!(session.peer.is_some());
		assert!(probe.session_state().peer_certificate().is_some());
	}

	/// The circuit breaker drops the session whole. A previous session's peer
	/// identity must not stay readable, because authorization reads it.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn a_reset_drops_the_peer_the_dead_session_established() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		assert!(probe.session_state_mut().install_session(established_session()));
		assert!(probe.session_state().peer_certificate().is_some());

		probe.reset_session();
		assert!(probe.session_state().peer_certificate().is_none());
	}

	/// The circuit breaker returns a provisioned endpoint to a phase whose
	/// writes stay encrypted, in one transition (CWE-311).
	#[test]
	fn resetting_a_provisioned_session_returns_it_to_provisioned() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		probe.reset_session();
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
	}

	/// A completed session carrying a peer identity, which authorization reads.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	fn established_session() -> EstablishedSession {
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid, KeyInit};
		use crate::der::oid::AssociatedOid;

		EstablishedSession {
			keys: SessionKeys::for_client(
				Aes256Gcm::new(&[0u8; 32].into()),
				Aes256Gcm::new(&[1u8; 32].into()),
				Aes256GcmOid::OID,
			),
			mux: None,
			receipt: None,
			peer: Some(Arc::new(fixture_certificate())),
			epoch: None,
		}
	}

	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	fn fixture_certificate() -> Certificate {
		create_test_certificate(&create_test_signing_key())
	}

	/// A client identity proves who this endpoint is and says nothing about the
	/// peer, so a cleartext write carrying one is refused wherever the
	/// transport was built (CWE-295).
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn a_client_identity_without_peer_authentication_refuses_to_write() {
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			client_certificate: Some(Arc::new(fixture_certificate())),
			..EncryptionConfig::default()
		};
		assert!(matches!(
			encryption.check_peer_authentication(),
			Err(TransportError::PeerAuthenticationUnconfigured)
		));
	}

	/// Naming cleartext accepts the unauthenticated peer, so the same
	/// configuration is admitted.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn naming_cleartext_admits_a_client_identity() {
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			client_certificate: Some(Arc::new(fixture_certificate())),
			allow_cleartext: true,
			..EncryptionConfig::default()
		};
		assert!(encryption.check_peer_authentication().is_ok());
	}

	/// A trust store answers for the peer, so the pairing is complete.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn a_trust_store_admits_a_client_identity() {
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			client_certificate: Some(Arc::new(fixture_certificate())),
			client_validators: Some(Arc::new(Vec::new())),
			..EncryptionConfig::default()
		};
		assert!(encryption.check_peer_authentication().is_ok());
	}

	/// A server presents its own certificate rather than a client identity, so
	/// it is untouched by the pairing rule.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn a_server_without_client_validators_still_writes() {
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			server_certificate: Some(Arc::new(fixture_certificate())),
			..EncryptionConfig::default()
		};
		assert!(encryption.check_peer_authentication().is_ok());
	}

	#[test]
	fn resetting_an_unprovisioned_session_returns_it_to_cleartext() {
		let mut probe = PhaseProbe::unprovisioned(handshaking());
		probe.reset_session();
		assert!(matches!(probe.session_state().phase(), SessionPhase::Cleartext));
	}

	#[test]
	fn only_cleartext_and_encrypted_phases_are_writable() {
		assert!(SessionPhase::Cleartext.is_writable());
		assert!(!SessionPhase::Provisioned.is_writable());
		assert!(!handshaking().is_writable());
	}

	/// Every envelope path applies the wire mode here, so this refusal is the
	/// one that keeps a stalled session from writing in the clear (CWE-311).
	#[test]
	fn pending_session_refuses_to_apply_a_wire_mode() {
		let probe = PhaseProbe::provisioned(handshaking());
		let frame = Frame {
			version: Version::V0,
			metadata: Metadata::default(),
			message: Vec::new(),
			integrity: None,
			nonrepudiation: None,
		};

		let builder = EnvelopeBuilder::request(frame);
		let refusal = probe.apply_wire_mode(builder);
		assert!(matches!(
			refusal,
			Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
		));
	}
}
