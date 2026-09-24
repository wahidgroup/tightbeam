//! Protocol state management traits.
//!
//! The module separates encrypted-transport state accessors from I/O.

use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::CertificateSpec;
use crate::transport::builders::EnvelopeBuilder;
use crate::transport::envelopes::WireMode;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::handshake::receipt::StoredReceipt;
use crate::transport::handshake::{HandshakeKeyManager, HandshakeProtocolKind, PeerAuthentication};
use crate::transport::TransportLimits;
use crate::transport::TransportResult;
use crate::utils::time::MonotonicInstant;
use crate::x509::Certificate;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::BoxedServerHandshake;
#[cfg(feature = "aead")]
use crate::transport::handshake::{EpochMaterials, EstablishedSession};

/// Which wire mode a session is entitled to write, and the state backing it.
///
/// The phase is stored instead of derived, and each arm carries what that
/// phase needs. Session keys live in [`SessionPhase::Encrypted`], so a
/// completed handshake without keys, or keys without a completed handshake,
/// cannot be built.
///
/// # Sources
///
/// - CWE-311, missing encryption of sensitive data:
///   <https://cwe.mitre.org/data/definitions/311.html>
#[cfg(feature = "x509")]
pub enum SessionPhase {
	/// The endpoint carries no encryption provisioning and named cleartext,
	/// so frames travel in the clear as a configured choice.
	Cleartext,
	/// Encryption is provisioned and no handshake has started. A write in
	/// this phase fails with [`TransportFailure::EncryptorUnavailable`].
	Provisioned,
	/// A handshake is in flight, measured against `initiated_at`.
	Handshaking {
		/// The instant the handshake began, on the endpoint's clock. The
		/// handshake deadline counts from it.
		initiated_at: MonotonicInstant,
	},
	/// The handshake completed. The phase carries everything it agreed, so a
	/// session's keys and the terms that go with them cannot be separated, and
	/// leaving this phase drops all of them together.
	Encrypted(Box<EstablishedSession>),
}

#[cfg(feature = "x509")]
impl SessionPhase {
	/// The phase an endpoint provisioned with `encryption` starts in, and
	/// returns to when its session breaks.
	///
	/// It is the one place that pairs provisioning with a phase. An endpoint
	/// that holds encryption material never starts in `Cleartext`, which would
	/// write application data in the clear (CWE-311).
	fn start_for<P: CryptoProvider>(encryption: &EncryptionConfig<P>) -> Self {
		if encryption.is_provisioned() {
			return Self::Provisioned;
		}

		Self::Cleartext
	}

	/// Whether this phase may write application traffic.
	///
	/// A pooled connection is leased only in a writable phase, so a peer that
	/// stalls its handshake keeps that connection out of the pool. A phase
	/// added later stays unwritable until it is named here.
	pub const fn is_writable(&self) -> bool {
		matches!(self, Self::Cleartext | Self::Encrypted(_))
	}

	/// Whether this phase admits `event`.
	///
	/// The alphabet is small and each event names one move, so two events that
	/// land on the same phase keep their own legality.
	const fn admits(&self, event: &SessionEvent) -> bool {
		matches!(
			(self, event),
			// The handshake, which may take several rounds.
			(Self::Provisioned | Self::Handshaking { .. }, SessionEvent::BeginHandshake(_))
				| (Self::Handshaking { .. }, SessionEvent::Install(_))
				// The circuit breaker, from wherever the session got to.
				| (_, SessionEvent::Reset)
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
	pub const fn initiated_at(&self) -> Option<MonotonicInstant> {
		match self {
			Self::Handshaking { initiated_at } => Some(*initiated_at),
			_ => None,
		}
	}
}

/// Restricts [`EncryptedProtocolState`] and [`ServerHandshakeSlot`] to this
/// crate.
///
/// The traits hand out session ciphers and the server handshake slot, which an
/// outside implementation could supply from anywhere. Each in-crate transport
/// implements [`sealed::Sealed`] by name, and no blanket implementation
/// exists, so those come from a handshake this crate ran.
#[cfg(feature = "x509")]
pub(crate) mod sealed {
	/// Implemented by name for each in-crate transport.
	pub trait Sealed {}
}

/// What can happen to a session, which is the alphabet the phase table reads.
#[cfg(feature = "x509")]
pub(crate) enum SessionEvent {
	/// A handshake round starts at the given reading.
	BeginHandshake(MonotonicInstant),
	/// A handshake completed and hands over everything it agreed.
	Install(Box<EstablishedSession>),
	/// The circuit breaker drops any session and returns to the start.
	Reset,
}

/// A session's phase and the provisioning it was built for.
///
/// Both are private and one constructor sets them together, so the phase an
/// endpoint starts in, and returns to on a reset, always follows from the
/// provisioning it holds. Every move afterwards consults the transition
/// table, so a caller cannot place a session in a phase the table does not
/// name.
#[cfg(feature = "x509")]
pub struct SessionState<P: CryptoProvider> {
	encryption: EncryptionConfig<P>,
	phase: SessionPhase,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> SessionState<P> {
	/// A session for `encryption`, at the phase that provisioning starts in.
	///
	/// [`DialableEncryption`] guarantees the endpoint either holds a peer
	/// authority or named cleartext, so the start is `Provisioned` or a
	/// chosen `Cleartext`.
	pub fn new(encryption: DialableEncryption<P>) -> Self {
		let encryption = encryption.0;
		let phase = SessionPhase::start_for(&encryption);

		Self { encryption, phase }
	}

	/// What this endpoint was provisioned with.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		&self.encryption
	}

	/// Where this session currently sits.
	pub fn phase(&self) -> &SessionPhase {
		&self.phase
	}

	/// Apply `event`, reporting whether the table admitted it.
	///
	/// It is the one writer of the phase, and it is private, so the named moves
	/// below are the only events a caller can raise. A refused event leaves the
	/// session where it was.
	fn apply(&mut self, event: SessionEvent) -> bool {
		if !self.phase.admits(&event) {
			return false;
		}

		self.phase = match event {
			SessionEvent::BeginHandshake(now) => {
				let initiated_at = self.phase.initiated_at().unwrap_or(now);
				SessionPhase::Handshaking { initiated_at }
			}
			SessionEvent::Install(session) => SessionPhase::Encrypted(session),
			SessionEvent::Reset => SessionPhase::start_for(&self.encryption),
		};

		true
	}

	/// Record a handshake round at `now`.
	///
	/// The first round starts the deadline. A later round keeps the instant
	/// the first one recorded, so a slow peer cannot stretch the handshake by
	/// one allowance per round.
	#[must_use]
	pub fn begin_handshake(&mut self, now: MonotonicInstant) -> bool {
		self.apply(SessionEvent::BeginHandshake(now))
	}

	/// Install everything a completed handshake agreed.
	///
	/// The terms enter the phase together, so a session that reports itself
	/// encrypted always carries the terms it runs under.
	#[must_use]
	pub fn install_session(&mut self, session: EstablishedSession) -> bool {
		self.apply(SessionEvent::Install(Box::new(session)))
	}

	/// Drop any session and return to the phase this endpoint's provisioning
	/// starts in.
	///
	/// This is the circuit breaker. It reads the destination from the
	/// provisioning this state holds, so no caller names it.
	pub fn reset(&mut self) {
		// The breaker is admitted from every phase, so its answer carries no
		// information a caller could act on.
		let _returned_to_start = self.apply(SessionEvent::Reset);
	}

	/// Detach the established session, returning this state to its start.
	///
	/// A caller that splits the endpoint into halves uses it. The halves take
	/// the keys, and the state they leave behind holds none. Only the async
	/// transport splits, so the method exists where that transport does.
	#[cfg(any(feature = "tokio", feature = "async-transport"))]
	pub(crate) fn take_established(&mut self) -> Option<Box<EstablishedSession>> {
		if !self.phase.requires_encryption() {
			return None;
		}

		let start = SessionPhase::start_for(&self.encryption);
		let SessionPhase::Encrypted(session) = core::mem::replace(&mut self.phase, start) else {
			return None;
		};

		Some(session)
	}

	/// Replace the multiplexing capability this endpoint offers.
	///
	/// This setter and the ones below change negotiation input and leave the
	/// peer authority alone, so the phase this state starts in is independent
	/// of them.
	#[cfg(all(
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) fn offer_mux(&mut self, offer: Option<Arc<TransportOffer>>) {
		self.encryption.mux_offer = offer;
	}

	/// Replace the budget-grant policy a server consults.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) fn authorize_transport(&mut self, authorizer: Arc<dyn TransportAuthorizer>) {
		self.encryption.transport_authorizer = Some(authorizer);
	}

	/// Replace the observer of budget-bearing handshake outcomes.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) fn observe_sessions(&mut self, observer: Arc<dyn SessionObserver>) {
		self.encryption.session_observer = Some(observer);
	}

	/// Replace the approver consulted before countersigning a
	/// challenge-bearing receipt.
	#[cfg(all(
		any(feature = "tcp", feature = "async-transport"),
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) fn approve_receipts(&mut self, approver: Arc<dyn ReceiptApprover>) {
		self.encryption.receipt_approver = Some(approver);
	}

	/// Replace the handshake protocol a provisioned endpoint runs.
	///
	/// The protocol decides how a handshake runs, and provisioning decides
	/// whether one is expected, so the phase this state starts in is
	/// independent of the protocol.
	#[cfg(any(feature = "tcp", feature = "async-transport"))]
	pub(crate) fn select_handshake(&mut self, kind: HandshakeProtocolKind) {
		self.encryption.handshake_protocol = kind;
	}

	/// Detach the epoch rekey materials the handshake left, once.
	///
	/// It is the only write into an installed session. Handing out the session
	/// itself would let a caller swap the keys under a phase that already
	/// reports the terms it agreed.
	#[cfg(feature = "aead")]
	pub fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		match &mut self.phase {
			SessionPhase::Encrypted(session) => session.take_epoch(),
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
		Ok(session.keys().send())
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
		Ok(session.keys().recv())
	}

	/// Validated peer certificate. It is the client identity on a mutual-auth
	/// server, and the trust-store-validated server identity on a client.
	///
	/// It comes from the established session, so it is present exactly while
	/// that session is.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.established()?.peer()
	}

	/// Shared handle to the validated peer certificate.
	pub fn peer_certificate_arc(&self) -> Option<Arc<Certificate>> {
		self.established()?.peer_arc()
	}

	/// Dual-signed session receipt from the established session.
	pub fn receipt(&self) -> Option<&StoredReceipt> {
		self.established()?.receipt()
	}

	/// Shared handle to the dual-signed session receipt.
	pub fn receipt_arc(&self) -> Option<Arc<StoredReceipt>> {
		self.established()?.receipt_arc()
	}

	/// Place a probe directly in `phase`, so a test of the table does not have
	/// to walk the table to reach its starting point.
	#[cfg(test)]
	pub(crate) fn at(encryption: EncryptionConfig<P>, phase: SessionPhase) -> Self {
		Self { encryption, phase }
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

	/// Decode `certificate` and bind it to the key that proves it.
	///
	/// It is the one place a [`CertificateSpec`] becomes an endpoint identity,
	/// so every builder that accepts one decodes it the same way and holds the
	/// result as shared handles.
	///
	/// # Errors
	///
	/// - [`SerializationError`] -- `certificate` holds PEM or DER that does not
	///   decode as a certificate.
	///
	/// [`SerializationError`]: crate::TightBeamError::SerializationError
	pub fn from_spec(
		certificate: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
	) -> Result<Self, crate::TightBeamError>
	where
		C: Send + Sync + 'static,
	{
		let certificate = Certificate::try_from(certificate)?;
		let key_manager = HandshakeKeyManager::new(key);

		Ok(Self::new(Arc::new(certificate), Arc::new(key_manager)))
	}

	/// The certificate and the key that proves it, as handles.
	pub fn parts(&self) -> (Arc<Certificate>, Arc<HandshakeKeyManager<C>>) {
		(Arc::clone(&self.certificate), Arc::clone(&self.key))
	}

	/// Shared handle to the certificate this identity presents.
	///
	/// A caller that needs the certificate alone takes this half, so it pays
	/// one refcount instead of the two that [`Self::parts`] charges for a pair.
	pub fn certificate_arc(&self) -> Arc<Certificate> {
		Arc::clone(&self.certificate)
	}

	/// The certificate this identity presents.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}

	/// The signing key provider behind this identity, read from its key
	/// manager through [`HandshakeKeyManager::provider`].
	pub fn signing_provider(&self) -> &dyn SigningKeyProvider {
		self.key.provider()
	}

	/// Write this identity into `encryption`, so both halves land together.
	///
	/// The key also answers as this endpoint's own signing key, the role a
	/// server's key manager fills, so both land in one write.
	pub fn install(&self, encryption: &mut EncryptionConfig<C>) {
		encryption.client_identity = Some(self.clone());
		encryption.key_manager = Some(Arc::clone(&self.key));
	}
}

/// Everything an endpoint was provisioned with before any handshake runs.
///
/// Provisioning is decided once, when the endpoint is built, so it travels as
/// one value. A transport supplies it through a single accessor, so every
/// field is present at once instead of each being asked for separately.
#[cfg(feature = "x509")]
#[non_exhaustive]
#[derive(Clone)]
pub struct EncryptionConfig<P: CryptoProvider> {
	/// Trust store that validates the peer's certificate. `None` leaves the
	/// peer identity to a lower layer, which [`Self::check_dial_permitted`]
	/// requires the endpoint to have named.
	pub(crate) trust_store: Option<Arc<dyn CertificateTrust>>,
	/// Local server certificate this endpoint presents.
	pub(crate) server_certificate: Option<Arc<Certificate>>,
	/// Provisioned server chain, ordered root to leaf, required by the CMS
	/// key-transport handshake before the server speaks.
	pub(crate) server_certificate_chain: Option<Arc<[Certificate]>>,
	/// Client identity presented for mutual authentication: the certificate
	/// and the key that proves it, bound as one value.
	pub(crate) client_identity: Option<ClientIdentity<P>>,
	/// How a server endpoint authenticates its client.
	pub(crate) peer_authentication: PeerAuthentication,
	/// Signing key manager backing this endpoint's identity and
	/// countersignatures.
	pub(crate) key_manager: Option<Arc<HandshakeKeyManager<P>>>,
	/// Domain-separation tag of the ECIES key exchange. Both ECIES endpoints
	/// MUST hold the same tag for a session to complete.
	pub(crate) aad_domain_tag: &'static [u8],
	/// Local multiplexing capability advertised in the handshake.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) mux_offer: Option<Arc<TransportOffer>>,
	/// Budget-grant policy between the client's offer and the server's accept.
	/// `None` grants the local configuration ceiling.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	/// Approver consulted for a challenge-bearing session receipt. `None`
	/// fails closed when a challenge is present.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	/// Observer recording budget-bearing handshake outcomes.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) session_observer: Option<Arc<dyn SessionObserver>>,
	/// Handshake protocol used once encryption is provisioned.
	pub(crate) handshake_protocol: HandshakeProtocolKind,
	/// Whether this endpoint accepts running without authenticating its peer.
	pub(crate) allow_cleartext: bool,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> EncryptionConfig<P> {
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
		self.client_identity.as_ref().map(ClientIdentity::certificate)
	}

	/// Handshake protocol used once encryption is provisioned.
	pub fn handshake_protocol(&self) -> HandshakeProtocolKind {
		self.handshake_protocol
	}

	/// Whether this endpoint is provisioned to encrypt, which is the same as
	/// whether it can establish who its peer is.
	///
	/// Each of these means a handshake is expected and names a peer authority:
	///
	/// - A server certificate this endpoint presents.
	/// - Mutual authentication a server demands of its client.
	/// - A trust store a client checks the server certificate against.
	///
	/// A client certificate proves who this endpoint is, so it answers a
	/// different question and is absent here.
	pub fn is_provisioned(&self) -> bool {
		// The binding destructures without `..`, so a field added to this
		// configuration stops compiling here until someone says whether it
		// implies a handshake. Without that break, a new kind of encryption
		// material would silently leave the endpoint in `Cleartext` (CWE-311).
		let Self {
			server_certificate,
			trust_store,
			peer_authentication,
			server_certificate_chain: _,
			client_identity: _,
			key_manager: _,
			aad_domain_tag: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				mux_offer: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				transport_authorizer: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				receipt_approver: _,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				session_observer: _,
			handshake_protocol: _,
			allow_cleartext: _,
		} = self;

		server_certificate.is_some() || trust_store.is_some() || peer_authentication.requires_certificate()
	}

	/// Whether this endpoint carries a client identity.
	pub fn has_client_identity(&self) -> bool {
		self.client_identity.is_some()
	}

	/// Whether this endpoint may reach a peer it cannot authenticate.
	///
	/// An endpoint that can establish nothing about its peer reaches whoever
	/// answered (CWE-295), and naming cleartext is the only way to accept that.
	/// Every transport is built from provisioning that passed this rule, so a
	/// cleartext phase always carries a named choice.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- the endpoint
	///   authenticates no peer and did not name cleartext.
	pub fn check_dial_permitted(&self) -> TransportResult<()> {
		if !self.is_provisioned() && !self.allow_cleartext {
			return Err(TransportError::PeerAuthenticationUnconfigured);
		}

		Ok(())
	}

	/// Provisioning with nothing installed, which a builder accumulates into.
	///
	/// It authenticates no peer and names no cleartext, so it becomes a
	/// transport only after [`DialableEncryption::new`] accepts what was added.
	pub(crate) fn unconfigured() -> Self {
		Self {
			trust_store: None,
			server_certificate: None,
			server_certificate_chain: None,
			client_identity: None,
			peer_authentication: PeerAuthentication::Anonymous,
			key_manager: None,
			aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			mux_offer: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			transport_authorizer: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			receipt_approver: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			session_observer: None,
			handshake_protocol: HandshakeProtocolKind::default(),
			allow_cleartext: false,
		}
	}
}

/// An endpoint that accepts handshakes, and so keeps the orchestrator driving
/// the one in flight.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub trait ServerHandshakeSlot: sealed::Sealed {
	/// The orchestrator carrying this endpoint's in-flight server handshake.
	///
	/// It is `None` before the first client message arrives, and again once
	/// the handshake completes and its terms are installed.
	fn server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake>;
}

/// Provisioning that has passed [`EncryptionConfig::check_dial_permitted`].
///
/// A transport is built only from this form, through [`SessionState::new`],
/// so every installed provisioning has answered the dialer rule.
#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct DialableEncryption<P: CryptoProvider>(EncryptionConfig<P>);

#[cfg(feature = "x509")]
impl<P: CryptoProvider> DialableEncryption<P> {
	/// Check `encryption` against the dialer rule.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- the endpoint
	///   authenticates no peer and did not name cleartext.
	pub fn new(encryption: EncryptionConfig<P>) -> TransportResult<Self> {
		encryption.check_dial_permitted()?;
		Ok(Self(encryption))
	}

	/// Cleartext as a named choice: no peer authority and no encryption.
	///
	/// Frames travel with no confidentiality, integrity, or peer
	/// authentication, which suits a loopback fixture or a link a lower layer
	/// already secures.
	pub fn cleartext() -> Self {
		let encryption = EncryptionConfig { allow_cleartext: true, ..EncryptionConfig::unconfigured() };
		Self(encryption)
	}

	/// Accept provisioning that carries a peer authority by construction.
	///
	/// [`TransportEncryptionConfig`] holds a server certificate instead of an
	/// `Option` of one, so [`EncryptionConfig::is_provisioned`] holds for every
	/// value it converts to and the rule has no work to do. That conversion is
	/// the only caller, and every other path goes through [`Self::new`].
	///
	/// [`TransportEncryptionConfig`]: crate::transport::TransportEncryptionConfig
	pub(crate) fn from_peer_authority(encryption: EncryptionConfig<P>) -> Self {
		Self(encryption)
	}

	/// The provisioning this answer was given for.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		&self.0
	}
}

/// State accessors for encrypted transports, separate from I/O.
///
/// The trait is sealed: only this crate's transports implement it, so the
/// session ciphers it hands out come from a handshake this crate ran.
///
/// ```compile_fail,E0277
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::transport::state::{EncryptedProtocolState, SessionState};
/// use tightbeam::transport::TransportLimits;
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
///     fn limits(&self) -> &TransportLimits {
///         unimplemented!()
///     }
/// }
/// ```
#[cfg(feature = "x509")]
pub trait EncryptedProtocolState: sealed::Sealed {
	/// Crypto provider bound to this transport.
	type CryptoProvider: CryptoProvider + Send + Sync + 'static;

	/// This endpoint's session state.
	fn session_state(&self) -> &SessionState<Self::CryptoProvider>;

	/// Mutable access to this endpoint's session state.
	///
	/// The state guards its own phase, so a caller reaching this still cannot
	/// place the session in a phase the transition table does not name.
	fn session_state_mut(&mut self) -> &mut SessionState<Self::CryptoProvider>;

	/// Apply this session's wire mode to `builder`.
	///
	/// Every envelope this endpoint writes passes through here, so the wire
	/// mode is decided once per session instead of once per call site.
	///
	/// # Errors
	///
	/// - [`TransportFailure::EncryptorUnavailable`] -- the session is
	///   [`SessionPhase::Provisioned`] or [`SessionPhase::Handshaking`], so the
	///   frame waits for the handshake to install keys.
	fn apply_wire_mode<'a>(&'a self, builder: EnvelopeBuilder<'a>) -> TransportResult<EnvelopeBuilder<'a>> {
		match self.session_state().phase() {
			SessionPhase::Encrypted(session) => Ok(builder
				.with_wire_mode(WireMode::Encrypted)
				.with_encryptor(session.keys().send())),
			SessionPhase::Cleartext => Ok(builder.with_wire_mode(WireMode::Cleartext)),
			SessionPhase::Provisioned | SessionPhase::Handshaking { .. } => {
				Err(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
			}
		}
	}

	/// What this endpoint was provisioned with.
	fn encryption(&self) -> &EncryptionConfig<Self::CryptoProvider> {
		self.session_state().encryption()
	}

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
	use crate::crypto::aead::SessionKeys;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::testing::TestFrame;
	use crate::utils::time::{Clock, ManualClock};

	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	use crate::testing::fixtures::{TestCertificate, TestKey};

	/// Holds the phase the trait reads back.
	struct PhaseProbe {
		state: SessionState<DefaultCryptoProvider>,
		limits: TransportLimits,
	}

	impl PhaseProbe {
		/// Mutual authentication alone makes the probe expect encryption.
		fn provisioned(phase: SessionPhase) -> Self {
			Self::holding(provisioned_encryption(), phase)
		}

		fn cleartext(phase: SessionPhase) -> Self {
			Self::holding(DialableEncryption::cleartext().0, phase)
		}

		fn holding(encryption: EncryptionConfig<DefaultCryptoProvider>, phase: SessionPhase) -> Self {
			Self { state: SessionState::at(encryption, phase), limits: TransportLimits::default() }
		}
	}

	impl sealed::Sealed for PhaseProbe {}

	impl EncryptedProtocolState for PhaseProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &TransportLimits {
			&self.limits
		}

		fn session_state(&self) -> &SessionState<DefaultCryptoProvider> {
			&self.state
		}

		fn session_state_mut(&mut self) -> &mut SessionState<DefaultCryptoProvider> {
			&mut self.state
		}
	}

	fn provisioned_encryption() -> EncryptionConfig<DefaultCryptoProvider> {
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
		let peer_authentication = PeerAuthentication::mutual([validator]);
		EncryptionConfig { peer_authentication, ..EncryptionConfig::unconfigured() }
	}

	fn handshaking() -> SessionPhase {
		SessionPhase::Handshaking { initiated_at: ManualClock::default().monotonic() }
	}

	/// A provisioned endpoint starts where a handshake is expected, and a
	/// cleartext one only where cleartext was named (CWE-311).
	#[test]
	fn a_session_starts_where_its_provisioning_says() -> TransportResult<()> {
		let provisioned = SessionState::new(DialableEncryption::new(provisioned_encryption())?);
		assert!(matches!(provisioned.phase(), SessionPhase::Provisioned));

		let cleartext = SessionState::<DefaultCryptoProvider>::new(DialableEncryption::cleartext());
		assert!(matches!(cleartext.phase(), SessionPhase::Cleartext));
		Ok(())
	}

	/// Provisioning that neither authenticates a peer nor names cleartext
	/// never becomes a session (CWE-295).
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
	}

	/// Every envelope path applies the wire mode here, so this refusal is the
	/// one that keeps a stalled session from writing in the clear (CWE-311).
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

	/// A provisioned session that is reset from any phase writes nothing in
	/// the clear, including a reset that a public reset flag triggers.
	#[test]
	fn a_reset_provisioned_session_refuses_a_cleartext_write() -> TransportResult<()> {
		let mut state = SessionState::new(DialableEncryption::new(provisioned_encryption())?);
		state.reset();

		let probe = PhaseProbe { state, limits: TransportLimits::default() };
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
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	crate::tb_cases! {
		fn the_phase_table((phase, event, admitted, landing): (&str, &str, bool, &str)) {
			let mut state = SessionState::at(provisioned_encryption(), phase_named(phase));
			assert_eq!(state.apply(event_named(event)), admitted, "{phase} on {event}");
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
		}
	}

	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	fn phase_named(name: &str) -> SessionPhase {
		match name {
			"cleartext" => SessionPhase::Cleartext,
			"provisioned" => SessionPhase::Provisioned,
			"handshaking" => handshaking(),
			_ => SessionPhase::Encrypted(Box::new(established_session())),
		}
	}

	#[cfg(all(feature = "testing", feature = "secp256k1"))]
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

	/// Restarting a handshake under a live session would drop its keys, so the
	/// table refuses the move and the session survives it.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn the_phase_table_refuses_restarting_a_handshake_on_a_live_session() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		assert!(probe.session_state_mut().install_session(established_session()));

		let now = ManualClock::default().monotonic();
		assert!(!probe.session_state_mut().begin_handshake(now));
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
		assert!(session.peer().is_some());
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

		probe.session_state_mut().reset();
		assert!(probe.session_state().peer_certificate().is_none());
	}

	/// Splitting takes the keys out, and the state left behind holds none.
	#[cfg(all(
		feature = "testing",
		feature = "secp256k1",
		any(feature = "tokio", feature = "async-transport")
	))]
	#[test]
	fn taking_the_established_session_returns_the_state_to_its_start() {
		let mut probe = PhaseProbe::provisioned(handshaking());
		assert!(probe.session_state_mut().install_session(established_session()));
		assert!(probe.session_state_mut().take_established().is_some());
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
		assert!(probe.session_state_mut().take_established().is_none());
	}

	/// A completed session carrying a peer identity, which authorization reads.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	fn established_session() -> EstablishedSession {
		use crate::crypto::aead::{Aes256Gcm, DirectionalCiphers, KeyInit};

		let keys = SessionKeys::for_client(DirectionalCiphers {
			client_to_server: Aes256Gcm::new(&[0u8; 32].into()),
			server_to_client: Aes256Gcm::new(&[1u8; 32].into()),
		});

		EstablishedSession::new(keys, None, None, Some(Arc::new(fixture_certificate())), None)
	}

	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	fn fixture_certificate() -> Certificate {
		TestCertificate::self_signed(&TestKey::signing())
	}
}
