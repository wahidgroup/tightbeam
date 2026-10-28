//! The handshake orchestrator.
//!
//! [`Handshake`] runs the three [legs](crate::transport::handshake#legs) for
//! one role over one flow. The step order and every negotiation and admission
//! decision are written once per role. A flow contributes the messages of its
//! protocol and the checks those messages define.
//!
//! ## Phases
//!
//! A phase holds the facts that the steps before it established, so a fact
//! exists only after its step ran. Each step takes the phase by value:
//!
//! - A step called in a phase that does not admit it stores the phase back and
//!   refuses with [`HandshakeError::InvalidState`].
//! - A step that began and failed leaves the handshake
//!   [`HandshakePhase::Spent`], and the step drops every secret the phase held.
//!
//! ```text
//! Client   Idle ── start ──▶ Exchanging ── respond ──▶ Agreed ── complete ──▶ Completed
//! Server   Idle ── reply ──▶ Exchanging ── finish ───▶ Agreed ── complete ──▶ Completed
//! ```

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use core::marker::PhantomData;
use core::mem;

use crate::crypto::aead::{DirectionalCiphers, RuntimeAead, SessionKeys};
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::KeyPurposes;
use crate::random::OsRng;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	ClientAgreement, ClientFlow, Closing, ClosingDraft, ClosingParts, ConfirmedClosing, HandshakeFlow, Opened,
	OpeningIntake, OpeningParts, ReplyBinding, ReplyIntake, ReplyParts, ServerConfirmed, ServerFlow, ServerPending,
};
use crate::transport::handshake::negotiation::{
	AuthorizedTransport, MuxSettings, ProfilePolicy, SecurityOffer, SupportedProfiles, TransportAuthorizer,
	TransportNegotiation, TransportOffer,
};
use crate::transport::handshake::peer::{PeerAuthentication, ServerAdmission, ServerTrust, ValidatorChain};
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::receipt::{
	CountersignedReceipt, IssuedReceipt, PendingReceipt, ReceiptApprover, SessionObserver, Settlement, StoredReceipt,
};
use crate::transport::handshake::schedule::{Agreed, PeerEphemeral, SecretSeal, Terms};
use crate::transport::handshake::{
	Arc, ClientHandshakeProtocol, EstablishedSession, HandshakeMessage, HandshakeProvider, ServerHandshakeProtocol,
	ServerIdentity,
};
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::x509::Certificate;

mod sealed {
	pub trait Sealed {}
}

/// Where a handshake stands, for either role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
	/// The handshake is ready for its first leg.
	Idle,
	/// The role sent its first message and awaits the peer.
	Exchanging,
	/// The handshake secret exists, and completion can take it.
	Agreed,
	/// Completion took everything the handshake agreed.
	Completed,
	/// A step began and failed. Every step refuses a spent handshake.
	Spent,
}

/// The role-generic view of a phase.
pub trait PhaseView<P: HandshakeProvider>: sealed::Sealed + MaybeSend + MaybeSync + Sized {
	/// The phase a step leaves behind while it runs.
	fn spent() -> Self;

	/// The phase completion leaves behind.
	fn completed() -> Self;

	/// Where the handshake stands.
	fn kind(&self) -> HandshakePhase;

	/// The negotiated terms, from the leg that fixed them to completion.
	fn terms(&self) -> Option<&Terms<P>>;

	/// What the handshake agreed, from the last leg to completion.
	fn agreed(&self) -> Option<&Agreed<P>>;

	/// Takes what the handshake agreed, or hands the phase back unchanged.
	fn take_agreed(self) -> Result<Agreed<P>, Self>;
}

/// A side of the handshake. The trait is sealed, so [`Client`] and [`Server`]
/// are the only roles.
pub trait Role<F: HandshakeFlow, P: HandshakeProvider>: sealed::Sealed + MaybeSend + MaybeSync + 'static {
	/// The phases of this role.
	type Phase: PhaseView<P>;
	/// What this role is provisioned with.
	type Config: MaybeSend + MaybeSync;

	/// Maps the directional ciphers to the keys that this role sends and
	/// receives on.
	fn session_keys(ciphers: DirectionalCiphers<RuntimeAead>) -> SessionKeys;
}

/// The client role, which sends the opening and the closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client;

impl sealed::Sealed for Client {}

impl<F: ClientFlow<P>, P: HandshakeProvider> Role<F, P> for Client {
	type Phase = ClientPhase<F, P>;
	type Config = ClientConfig<F, P>;

	fn session_keys(ciphers: DirectionalCiphers<RuntimeAead>) -> SessionKeys {
		SessionKeys::for_client(ciphers)
	}
}

/// What a client is provisioned with before any leg runs.
///
/// [`Self::new`] admits the client's own identity for the client purpose, so
/// a configuration holds an identity of its role.
pub struct ClientConfig<F: ClientFlow<P>, P: HandshakeProvider> {
	/// What the protocol itself needs: the server trust and the identity.
	flow: F::Settings,
	/// The security profiles offered to the server. Without an offer the
	/// server picks its default profile (dealer's choice).
	pub security_offer: Option<SecurityOffer>,
	/// The transport capabilities offered to the server. Without an offer the
	/// connection stays single-flight.
	pub transport_offer: Option<TransportOffer>,
	/// The policy that admits the server's profile selection.
	pub profiles: ProfilePolicy<P>,
	/// The key purpose of each role: the server's certificates carry the
	/// server's, and the client's own identity the client's.
	key_purposes: KeyPurposes,
	/// The approver that the client consults before it countersigns a session
	/// receipt. Without one a challenge-bearing receipt fails closed.
	pub receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	/// The server policy, which [`Self::with_server_policy`] sets, or `None`
	/// for a client that sets none.
	server_policy: Option<ValidatorChain>,
}

impl<F: ClientFlow<P>, P: HandshakeProvider> ClientConfig<F, P> {
	/// A configuration that offers nothing, applies the default strength
	/// floor, and admits each role under `key_purposes`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate of
	///   the client's identity names another key purpose.
	pub fn new(flow: F::Settings, key_purposes: KeyPurposes) -> Result<Self, HandshakeError> {
		if let Some(identity) = F::identity(&flow) {
			identity.certificate().require_purpose(key_purposes.client)?;
		}

		Ok(Self::offering_nothing(flow, key_purposes))
	}

	/// The configuration of a client whose client identity was admitted for
	/// the client purpose where the transport's provisioning was answered,
	/// once. The transport offer, the receipt approver, and the server policy
	/// are required parameters, so the builder of each flow passes them alike.
	pub(crate) fn admitted(
		flow: F::Settings,
		key_purposes: KeyPurposes,
		transport_offer: Option<TransportOffer>,
		receipt_approver: Option<Arc<dyn ReceiptApprover>>,
		server_policy: Option<ValidatorChain>,
	) -> Self {
		Self {
			transport_offer,
			receipt_approver,
			server_policy,
			..Self::offering_nothing(flow, key_purposes)
		}
	}

	/// A configuration that offers nothing, sets no server policy, applies
	/// the default strength floor, and admits each role under `key_purposes`.
	fn offering_nothing(flow: F::Settings, key_purposes: KeyPurposes) -> Self {
		Self {
			flow,
			security_offer: None,
			transport_offer: None,
			profiles: ProfilePolicy::new(),
			key_purposes,
			receipt_approver: None,
			server_policy: None,
		}
	}

	/// What the protocol itself needs: the server trust and the identity.
	pub fn flow(&self) -> &F::Settings {
		&self.flow
	}

	/// The key purpose of each role.
	pub fn key_purposes(&self) -> &KeyPurposes {
		&self.key_purposes
	}

	/// Sets the server policy, which every validator of `validators` runs on
	/// the identity certificate of the server once its trust admits it:
	///
	/// - CMS: the pinned key-agreement certificate, before the opening seals to it.
	/// - HPKE: the signing certificate the reply names.
	///
	/// An empty set sets no policy. A check of every certificate, such as a
	/// denylist, belongs in the store's
	/// [`RevocationChecker`](crate::crypto::x509::store::RevocationChecker).
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator, ExpiryValidator};
	/// use tightbeam::crypto::x509::KeyPurposes;
	/// use tightbeam::transport::handshake::{ClientConfig, Hpke, HpkeClientSettings, LearnedTrust};
	///
	/// let trust = LearnedTrust::new(DirectTrustValidator::default());
	/// let settings = HpkeClientSettings::new(trust);
	/// let config = ClientConfig::<Hpke, DefaultCryptoProvider>::new(settings, KeyPurposes::HOUSE)?;
	///
	/// // The policy reads the signing certificate the reply names.
	/// let expiry: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
	/// let _config = config.with_server_policy([expiry]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn with_server_policy(mut self, validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Self {
		self.server_policy = ValidatorChain::new(validators);
		self
	}

	/// The server policy, which each trust runs on the identity certificate
	/// of its flow.
	pub(crate) fn server_policy(&self) -> Option<&ValidatorChain> {
		self.server_policy.as_ref()
	}
}

/// The phases of a client, each with the facts its steps established.
pub enum ClientPhase<F: ClientFlow<P>, P: HandshakeProvider> {
	/// The handshake is ready for its first leg.
	Idle,
	/// The opening is out.
	OpeningSent {
		/// What the flow reads the reply against.
		opening: F::Opening,
		/// The secrets the flow holds until the agreement.
		pending: F::Pending,
	},
	/// The closing is out, and the handshake secret exists.
	ClosingSent {
		/// What the handshake agreed. It is boxed, so a phase move copies a
		/// pointer.
		agreed: Box<Agreed<P>>,
	},
	/// Completion took everything the handshake agreed.
	Completed,
	/// A step began and failed.
	Spent,
}

impl<F: ClientFlow<P>, P: HandshakeProvider> sealed::Sealed for ClientPhase<F, P> {}

impl<F: ClientFlow<P>, P: HandshakeProvider> PhaseView<P> for ClientPhase<F, P> {
	fn spent() -> Self {
		Self::Spent
	}

	fn completed() -> Self {
		Self::Completed
	}

	fn kind(&self) -> HandshakePhase {
		match self {
			Self::Idle => HandshakePhase::Idle,
			Self::OpeningSent { .. } => HandshakePhase::Exchanging,
			Self::ClosingSent { .. } => HandshakePhase::Agreed,
			Self::Completed => HandshakePhase::Completed,
			Self::Spent => HandshakePhase::Spent,
		}
	}

	fn terms(&self) -> Option<&Terms<P>> {
		self.agreed().map(Agreed::terms)
	}

	fn agreed(&self) -> Option<&Agreed<P>> {
		match self {
			Self::ClosingSent { agreed } => Some(agreed),
			Self::Idle | Self::OpeningSent { .. } | Self::Completed | Self::Spent => None,
		}
	}

	fn take_agreed(self) -> Result<Agreed<P>, Self> {
		match self {
			Self::ClosingSent { agreed } => Ok(*agreed),
			other => Err(other),
		}
	}
}

/// The server role, which sends the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Server;

impl sealed::Sealed for Server {}

impl<F: ServerFlow<P>, P: HandshakeProvider> Role<F, P> for Server {
	type Phase = ServerPhase<F, P>;
	type Config = ServerConfig<F, P>;

	fn session_keys(ciphers: DirectionalCiphers<RuntimeAead>) -> SessionKeys {
		SessionKeys::for_server(ciphers)
	}
}

/// What a server is provisioned with before any leg runs.
///
/// [`Self::new`] admits the server's own identity for the server purpose, so
/// a configuration holds an identity of its role.
pub struct ServerConfig<F: ServerFlow<P>, P: HandshakeProvider> {
	/// What the protocol itself needs.
	pub flow: F::Settings,
	/// What the server signs and agrees with: the identity whose key signs
	/// the reply and its receipt, and for the CMS flow the key-agreement
	/// identity that opens what the client seals to the server.
	identity: F::Identity,
	/// The security profiles the server runs, in preference order.
	pub profiles: SupportedProfiles,
	/// The policy that chooses among those profiles.
	pub policy: ProfilePolicy<P>,
	/// How the server authenticates its client.
	pub peer_authentication: PeerAuthentication,
	/// The key purpose of each role: the server's own identity carries the
	/// server's, and an offered client certificate the client's.
	key_purposes: KeyPurposes,
	/// The local transport advertisement. Multiplexing activates only when
	/// the client also offers it.
	pub transport: Option<TransportOffer>,
	/// The budget-grant policy consulted between the client's transport offer
	/// and the server's accept. Without one the server grants the request up
	/// to its local configuration ceiling.
	pub transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	/// The observer that records the outcome of every budget-bearing session
	/// whose receipt exchange concluded, activated or refused.
	pub session_observer: Option<Arc<dyn SessionObserver>>,
}

impl<F: ServerFlow<P>, P: HandshakeProvider> ServerConfig<F, P> {
	/// A configuration for an anonymous-client server that advertises no
	/// transport capability, applies the default strength floor, and admits
	/// each role under `key_purposes`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a certificate of
	///   `identity` names another key purpose.
	pub fn new(
		flow: F::Settings,
		identity: F::Identity,
		profiles: SupportedProfiles,
		key_purposes: KeyPurposes,
	) -> Result<Self, HandshakeError> {
		identity.require_purpose(key_purposes.server)?;
		Ok(Self::admitted(flow, identity, profiles, key_purposes))
	}

	/// A configuration whose identity was admitted for the server purpose of
	/// `key_purposes` where the transport's provisioning was answered, once.
	pub(crate) fn admitted(
		flow: F::Settings,
		identity: F::Identity,
		profiles: SupportedProfiles,
		key_purposes: KeyPurposes,
	) -> Self {
		Self {
			flow,
			identity,
			profiles,
			policy: ProfilePolicy::new(),
			peer_authentication: PeerAuthentication::Anonymous,
			key_purposes,
			transport: None,
			transport_authorizer: None,
			session_observer: None,
		}
	}

	/// What the server signs and agrees with.
	pub fn identity(&self) -> &F::Identity {
		&self.identity
	}

	/// The key purpose of each role.
	pub fn key_purposes(&self) -> &KeyPurposes {
		&self.key_purposes
	}
}

/// What a server holds from its reply to the closing.
pub struct SentReply<F: ServerFlow<P>, P: HandshakeProvider> {
	/// What the reply negotiated.
	terms: Terms<P>,
	/// The handshake secret and the client ephemeral the closing opens with.
	pending: ServerPending<P::Curve>,
	/// The receipt of a budget-bearing session, which the closing settles.
	issued: Option<IssuedReceipt>,
	/// The flow the reply ran.
	flow: PhantomData<fn() -> F>,
}

/// The phases of a server, each with the facts its steps established.
pub enum ServerPhase<F: ServerFlow<P>, P: HandshakeProvider> {
	/// The handshake is ready for its first leg.
	Idle,
	/// The reply is out.
	ReplySent {
		/// What the closing is read against. It is boxed, so a phase move
		/// copies a pointer.
		reply: Box<SentReply<F, P>>,
	},
	/// The closing is in, and the handshake secret exists.
	ClosingReceived {
		/// What the handshake agreed. It is boxed, so a phase move copies a
		/// pointer.
		agreed: Box<Agreed<P>>,
	},
	/// Completion took everything the handshake agreed.
	Completed,
	/// A step began and failed.
	Spent,
}

impl<F: ServerFlow<P>, P: HandshakeProvider> sealed::Sealed for ServerPhase<F, P> {}

impl<F: ServerFlow<P>, P: HandshakeProvider> PhaseView<P> for ServerPhase<F, P> {
	fn spent() -> Self {
		Self::Spent
	}

	fn completed() -> Self {
		Self::Completed
	}

	fn kind(&self) -> HandshakePhase {
		match self {
			Self::Idle => HandshakePhase::Idle,
			Self::ReplySent { .. } => HandshakePhase::Exchanging,
			Self::ClosingReceived { .. } => HandshakePhase::Agreed,
			Self::Completed => HandshakePhase::Completed,
			Self::Spent => HandshakePhase::Spent,
		}
	}

	fn terms(&self) -> Option<&Terms<P>> {
		match self {
			Self::ReplySent { reply } => Some(&reply.terms),
			Self::ClosingReceived { agreed } => Some(agreed.terms()),
			Self::Idle | Self::Completed | Self::Spent => None,
		}
	}

	fn agreed(&self) -> Option<&Agreed<P>> {
		match self {
			Self::ClosingReceived { agreed } => Some(agreed),
			Self::Idle | Self::ReplySent { .. } | Self::Completed | Self::Spent => None,
		}
	}

	fn take_agreed(self) -> Result<Agreed<P>, Self> {
		match self {
			Self::ClosingReceived { agreed } => Ok(*agreed),
			other => Err(other),
		}
	}
}

/// A handshake for role `R` over flow `F`, under provider `P`.
///
/// [`Self::client`] and [`Self::server`] create one, and the configuration
/// names the flow and the provider.
///
/// - A client runs [`Self::start`], [`Self::respond`], and [`Self::complete`].
/// - A server runs [`Self::reply`], [`Self::finish`], and [`Self::complete`].
///
/// # Examples
///
/// The type parameters of a configuration name the flow and the provider.
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::crypto::key::Secp256k1KeyProvider;
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::crypto::sign::SigningIdentity;
/// use tightbeam::crypto::x509::policy::DirectTrustValidator;
/// use tightbeam::crypto::x509::KeyPurposes;
/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
/// use tightbeam::transport::handshake::negotiation::RunnableProfile;
/// use tightbeam::transport::handshake::{
///     ClientConfig, Hpke, HpkeClientSettings, HpkeServerSettings, Handshake, HandshakeError, LearnedTrust,
///     ServerConfig, SupportedProfiles,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
/// # runtime.block_on(async {
/// // The fixture key is public, so it serves an example alone. A real server
/// // holds a key of its own.
/// let server_key = TestKey::insecure_fixed_signing();
/// let certificate = TestCertificate::self_signed(&server_key);
///
/// // The client admits the one server certificate it pins.
/// let pinned = DirectTrustValidator::default().with_trust_chain([certificate.clone()])?;
/// let settings = HpkeClientSettings::new(LearnedTrust::new(pinned));
/// let config = ClientConfig::<Hpke, DefaultCryptoProvider>::new(settings, KeyPurposes::HOUSE)?;
/// let mut client = Handshake::client(config);
///
/// // The server runs the native profile of its provider, and signs under the
/// // identity that pairs its certificate with its key.
/// let native = RunnableProfile::<DefaultCryptoProvider>::native().descriptor();
/// let key = Arc::new(Secp256k1KeyProvider::from(server_key));
/// let identity = SigningIdentity::new(certificate, key)?;
/// let profiles = SupportedProfiles::from(native);
/// let settings = HpkeServerSettings::new();
/// let config = ServerConfig::<Hpke, DefaultCryptoProvider>::new(settings, identity, profiles, KeyPurposes::HOUSE)?;
/// let mut server = Handshake::server(config);
///
/// let opening = client.start()?;
/// let reply = server.reply(opening).await?;
/// let closing = client.respond(reply).await?;
/// server.finish(closing).await?;
///
/// client.complete()?;
/// server.complete()?;
/// # Ok::<(), HandshakeError>(())
/// # })?;
/// # Ok(())
/// # }
/// ```
pub struct Handshake<R: Role<F, P>, F: HandshakeFlow, P: HandshakeProvider> {
	config: R::Config,
	phase: R::Phase,
	_markers: PhantomData<fn() -> (F, P)>,
}

impl<R: Role<F, P>, F: HandshakeFlow, P: HandshakeProvider> Handshake<R, F, P> {
	/// Takes the phase, and leaves the handshake spent until a step stores the
	/// next one.
	///
	/// This is the one place a phase leaves the handshake. A step holds what
	/// it took as locals, so each secret drops with the step on a failure and
	/// on a dropped future.
	fn take_phase(&mut self) -> R::Phase {
		mem::replace(&mut self.phase, R::Phase::spent())
	}

	/// Takes what `select` picks out of the phase, for a step that runs in one
	/// phase alone.
	///
	/// A phase that `select` hands back returns to the handshake unchanged,
	/// so a step out of order costs the handshake nothing.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the handshake is in another phase.
	fn step<T>(&mut self, select: impl FnOnce(R::Phase) -> Result<T, R::Phase>) -> Result<T, HandshakeError> {
		match select(self.take_phase()) {
			Ok(taken) => Ok(taken),
			Err(other) => {
				self.phase = other;
				Err(HandshakeError::InvalidState)
			}
		}
	}

	/// Completes the handshake and takes everything it agreed.
	///
	/// The handshake secret moves out, so one handshake derives one session.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the last leg has not run.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused a session key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused a derived key.
	pub fn complete(&mut self) -> Result<EstablishedSession, HandshakeError> {
		let agreed = self.step(PhaseView::take_agreed)?;
		let session = agreed.complete(R::session_keys)?;

		self.phase = R::Phase::completed();

		Ok(session)
	}

	/// Where the handshake stands.
	pub fn phase(&self) -> HandshakePhase {
		self.phase.kind()
	}

	/// Whether completion took everything the handshake agreed.
	pub fn is_complete(&self) -> bool {
		self.phase() == HandshakePhase::Completed
	}

	/// The security profile that negotiation selected, until completion.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.phase.terms().map(|terms| terms.profile().descriptor())
	}

	/// The negotiated multiplexing settings, if any, until completion.
	pub fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.phase.terms().and_then(Terms::mux)
	}

	/// The hash of the sealed transcript, until completion.
	pub fn transcript_hash(&self) -> Option<TranscriptHash> {
		self.phase.terms().map(|terms| *terms.transcript_hash())
	}

	/// The dual-signed session receipt, when the handshake carried budgets,
	/// from the last leg to completion.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.phase.agreed().and_then(Agreed::receipt)
	}

	/// The certificate of the peer this role recorded, from the last leg to
	/// completion.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		let recorded = self.phase.agreed().and_then(Agreed::peer);
		recorded.map(|peer| peer.certificate().as_ref())
	}
}

/// What the client holds once its closing is bound.
struct BoundClosing<'a, P: HandshakeProvider> {
	/// The handshake secret both sides derive, as the server Finished
	/// confirmed it.
	confirmed: ServerConfirmed,
	/// The dual-signed receipt, when the session carries budgets.
	receipt: Option<StoredReceipt>,
	/// The closing, which signs its client Finished as it seals.
	closing: ClosingDraft<'a, P>,
}

impl<F: ClientFlow<P>, P: HandshakeProvider> Handshake<Client, F, P> {
	/// Creates a client handshake under `config`, in [`HandshakePhase::Idle`]
	/// until [`Self::start`] builds the opening.
	pub fn client(config: ClientConfig<F, P>) -> Self {
		Self { config, phase: ClientPhase::Idle, _markers: PhantomData }
	}

	/// Builds the opening, the first message for the server.
	///
	/// The client admits a provisioned server identity, under the server
	/// policy, before it encrypts anything to it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the client is past [`HandshakePhase::Idle`].
	/// - [`HandshakeError::MissingServerCertificate`] -- the provisioned chain is empty.
	/// - [`HandshakeError::CertificateValidationError`] -- the trust or the
	///   server policy refused the provisioned server.
	/// - [`HandshakeError::InvalidPublicKey`] -- the provisioned server
	///   certificate key is not a point on the curve.
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError::Envelope`] -- the CMS opening fails to seal to the
	///   provisioned server's certificate.
	pub fn start(&mut self) -> Result<HandshakeMessage, HandshakeError> {
		// 1. Take the phase, which must be Idle.
		self.step(|phase| match phase {
			ClientPhase::Idle => Ok(()),
			other => Err(other),
		})?;

		// 2. Admit the server when its identity is provisioned.
		let config = &self.config;
		let trust = F::server_trust(&config.flow);
		let server = trust.admit_provisioned(ServerAdmission::of(config))?;

		// 3. Build the opening.
		let parts = OpeningParts {
			security_offer: config.security_offer.as_ref(),
			transport_offer: config.transport_offer.as_ref(),
		};

		let Opened { message, opening, pending } = F::open(&config.flow, server, parts, &mut OsRng)?;

		// 4. Keep what the reply is read against.
		self.phase = ClientPhase::OpeningSent { opening, pending };
		Ok(message)
	}

	/// Processes the reply of the server, and builds the closing, the last
	/// message of the client.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no opening was sent.
	/// - [`HandshakeError::UnexpectedContainer`] -- the reply travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the reply carries an abort alert.
	/// - [`HandshakeError::MissingAttribute`] -- the reply carries no server
	///   ephemeral, or no server Finished.
	/// - [`HandshakeError::DuplicateAttribute`] -- an attribute of the reply repeats.
	/// - [`HandshakeError::DerError`] -- the reply fails to decode, the HPKE
	///   reply's server Finished is no OCTET STRING of 32 to 64 bytes, or the
	///   encoder refuses the key of the admitted server.
	/// - [`HandshakeError::OctetStringLengthError`] -- a fixed-width field of the reply has another width.
	/// - [`HandshakeError::CertificateValidationError`] -- the trust or the
	///   server policy refused the server the reply names, its key reads as no
	///   point of its curve, or a `subjectAltName` of the empty subject of a
	///   CMS pair fails to decode.
	/// - [`HandshakeError::SubjectMismatch`] -- the CMS reply's certificate names another subject.
	/// - [`HandshakeError::AnchorMismatch`] -- the CMS reply's certificate ends at another trust anchor.
	/// - [`HandshakeError::KeyReuse`] -- the CMS reply's certificate holds the key of the pinned one.
	/// - [`HandshakeError::MissingServerCertificate`] -- the reply carries no certificate its signer names.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the reply fails to
	///   verify or signs another transcript, or the receipt fails the server
	///   signature check.
	/// - [`HandshakeError::InvalidProfileSelection`] -- the server selected
	///   nothing, or a profile outside the offer.
	/// - [`HandshakeError::NegotiationError`] -- the selected profile is below
	///   the strength floor or unrunnable, or the transport accept is invalid.
	/// - [`HandshakeError::InvalidPublicKey`] -- the named server certificate
	///   key or the signed server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the signed server
	///   ephemeral is the server's static key.
	/// - [`HandshakeError::ReceiptMissing`] -- a budget-bearing accept has no signed receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the receipt disagrees with the negotiated session.
	/// - [`HandshakeError::MutualAuthRequired`] -- the server or a receipt
	///   requires a client identity, and none is set.
	/// - [`HandshakeError::ApprovalRefused`] -- the receipt approver refused.
	/// - [`HandshakeError::KeyError`] -- the signing key provider failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake
	///   secret, a `MacKey`, the acknowledgement key, or the closing key.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the server Finished of the reply fails to verify.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the provider digest is not 32 to 64 bytes wide.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the envelope refused to seal the countersignature.
	/// - [`HandshakeError::SealedClosing`] -- the envelope refused to seal the closing.
	/// - [`HandshakeError::SealedFrame`] -- the closing exceeds the frame.
	pub async fn respond(&mut self, reply: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		// 1. Take the phase, which must hold the sent opening.
		let (opening, pending) = self.step(|phase| match phase {
			ClientPhase::OpeningSent { opening, pending } => Ok((opening, pending)),
			other => Err(other),
		})?;
		let config = &self.config;
		let settings = &config.flow;

		// 2. Decode the reply, and bind its legs into the sealed transcript.
		let ReplyIntake {
			server,
			security_accept,
			transport_accept,
			server_ephemeral,
			receipt,
			client_cert_required,
			transcript_hash,
			salt,
			reply,
		} = F::read_reply(opening, settings, reply)?;

		// 3. Admit the server the reply names.
		let server = F::server_trust(settings).admit_named(server, ServerAdmission::of(config))?;

		// 4. Verify the reply signature, which covers the transcript hash,
		//    under the admitted server's signing certificate.
		let verified = F::verify_reply(&reply, server.signing(), &transcript_hash)?;

		// 5. Admit the profile selection against the offer.
		let offer = config.security_offer.as_ref();
		let profile = config.profiles.admit(offer, security_accept.as_ref())?;

		// 6. Admit the transport terms, and fix what the reply negotiated. An
		//    accept of terms the client never offered fails closed.
		let mux = MuxSettings::for_client(config.transport_offer.as_ref(), transport_accept.as_ref())?;
		let terms = Terms::new(profile, mux, transcript_hash, salt);

		// 7. Parse the server ephemeral that the reply signature authenticated,
		//    beside every static key of the server it must differ from.
		let server_ephemeral = server.server_ephemeral(&server_ephemeral)?;

		// 8. Refuse a server that demands an identity this client does not
		//    hold. The refusal runs before the approver is asked and before
		//    the handshake secret is derived.
		let identity = F::identity(settings);
		if client_cert_required && identity.is_none() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		// 9. Derive the handshake secret, and verify the server Finished under
		//    it before the receipt is read or any part of the closing exists.
		//    The Finished proves that the holder of the secret stood behind the
		//    reply's signature (RFC 9846 §4.5.3), so a certificate the store
		//    admits for the server's name that this server never sent reaches
		//    neither the receipt check nor the approver.
		let secret = pending.agree(&server_ephemeral, terms.kdf_salt()?)?;
		let confirmed = ServerConfirmed::confirm(&reply, verified, secret, &terms)?;

		// 10. Verify the session receipt against the accept, which fails closed on a mismatch.
		let accept = transport_accept.as_ref();
		let signing = server.signing();
		let pending_receipt = PendingReceipt::verify::<P>(&confirmed, receipt, accept, &transcript_hash, signing)?;

		// 11. Approve and countersign the receipt. The confirmed secret waits
		//     on the heap across the approver and the signing key, and it is
		//     wiped where it drops, so a dropped step leaves no copy.
		let countersigned = match pending_receipt {
			Some(pending_receipt) => {
				let approver = config.receipt_approver.as_deref();
				Some(pending_receipt.countersign(approver, identity).await?)
			}
			None => None,
		};

		// 12. Seal the countersignature, and build the closing up to its
		//     client Finished. The step is synchronous.
		let bound = Self::close(confirmed, identity, countersigned, &terms)?;
		let BoundClosing { confirmed, receipt, closing } = bound;

		// 13. Sign the client Finished under the client identity, and seal the closing.
		let closing = closing.seal().await?;

		// 14. Keep what the handshake agreed. The server's certificates stay for post-handshake renewals.
		let agreed = Agreed::client(terms, confirmed, receipt, server);
		self.phase = ClientPhase::ClosingSent { agreed: Box::new(agreed) };

		Ok(closing)
	}

	/// Seals the countersignature, and builds the closing up to its client
	/// Finished, under the secret of a server whose Finished verified.
	///
	/// It is synchronous, so it runs inside one poll. It takes
	/// [`ServerConfirmed`], so a closing exists only after the server Finished
	/// verified.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the
	///   acknowledgement key, the closing key, or the key-confirmation tag.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the envelope refused to seal the countersignature.
	/// - [`HandshakeError`] -- the content the client Finished signs fails to encode or to hash.
	fn close<'a>(
		confirmed: ServerConfirmed,
		identity: Option<&'a SigningIdentity>,
		countersigned: Option<CountersignedReceipt>,
		terms: &Terms<P>,
	) -> Result<BoundClosing<'a, P>, HandshakeError> {
		let secret = confirmed.secret();

		// 1. Seal the countersignature under the handshake secret.
		let sealed = countersigned.map(|countersigned| countersigned.seal(secret, terms));
		let (sealed_ack, receipt) = sealed.transpose()?.unzip();

		// 2. Derive the key-confirmation tag, which proves this secret to the
		//    server, and the sealer of the closing.
		let transcript_hash = terms.transcript_hash();
		let confirmation = terms.confirmation(secret)?;
		let sealer = terms.sealer(secret, SecretSeal::Closing)?;

		// 3. Build the closing up to its client Finished.
		let parts = ClosingParts { transcript_hash, sealed_ack, confirmation, sealer };
		let closing = ClosingDraft::bind(identity, parts)?;
		Ok(BoundClosing { confirmed, receipt, closing })
	}
}

impl<F: ServerFlow<P>, P: HandshakeProvider> Handshake<Server, F, P> {
	/// Creates a server handshake under `config`, in [`HandshakePhase::Idle`]
	/// until [`Self::reply`] reads the opening.
	pub fn server(config: ServerConfig<F, P>) -> Self {
		Self { config, phase: ServerPhase::Idle, _markers: PhantomData }
	}

	/// Processes the opening of the client, and builds the reply.
	///
	/// The server draws the per-handshake ephemeral here. Its public half
	/// enters the signed transcript, and its private half serves one agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the server is past [`HandshakePhase::Idle`].
	/// - [`HandshakeError::UnexpectedContainer`] -- the opening travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the CMS opening carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an offer or the abort alert repeats.
	/// - [`HandshakeError::Envelope`] -- the CMS opening fails to open: its
	///   recipient, its `ukm`, its key, or its tag is refused, or the key
	///   provider failed the agreement.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client's ephemeral is not a point on the curve.
	/// - [`HandshakeError::InvalidKeySize`] -- the opened base secret is not 32 bytes.
	/// - [`HandshakeError::DerError`] -- the opened content fails to decode.
	/// - [`HandshakeError::NegotiationError`] -- profile or transport negotiation failed.
	/// - [`HandshakeError::MutualAuthRequired`] -- the accept grants budgets,
	///   and the server demands no client certificate.
	/// - [`HandshakeError::KeyError`] -- the key provider failed to sign.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake
	///   secret or the server's `MacKey`.
	pub async fn reply(&mut self, opening: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		// 1. Take the phase, which must be Idle.
		self.step(|phase| match phase {
			ServerPhase::Idle => Ok(()),
			other => Err(other),
		})?;
		let config = &self.config;
		let settings = &config.flow;
		let identity = config.identity.signing();

		// 2. Decode the opening, and open the transcript over it.
		let OpeningIntake { security_offer, transport_offer, sealed } = F::read_opening(settings, opening)?;

		// 3. Open what the opening sealed to a static key, before any offer
		//    reaches the policy or the authorizer. The CMS opening's tag
		//    covers its offers.
		let mut opened = F::open_opening(sealed, &config.identity).await?;

		// 4. Choose the security profile for the offer, or by dealer's choice without one.
		let profile = config.policy.choose(&config.profiles, security_offer.as_ref())?;

		// 5. Negotiate the transport terms. A configured authorizer decides
		//    the budget grant and the settlement challenge before the accept
		//    enters the transcript.
		let offer = transport_offer.as_ref();
		let negotiation = TransportNegotiation { offer, local: config.transport.as_ref() };
		let authorized = negotiation.authorize(config.transport_authorizer.as_deref()).await?;
		let (transport_accept, challenge, mux) = match authorized.map(AuthorizedTransport::into_parts) {
			Some((accept, challenge, mux)) => (Some(accept), challenge, Some(mux)),
			None => (None, None, None),
		};

		// 6. Draw the per-handshake ephemeral. It is boxed before the first
		//    await that it crosses, so every later move copies a pointer and
		//    the scalar is wiped where the box drops.
		let ephemeral = Box::new(EphemeralSecret::<P::Curve>::random(&mut OsRng));

		// 7. Bind the reply legs into the transcript and seal it, which fixes what the reply negotiated.
		let client_cert_required = config.peer_authentication.requires_certificate();
		let transport_accept = transport_accept.as_ref();
		let server_ephemeral = ephemeral.public_key();
		let parts = ReplyParts { identity, profile, transport_accept, server_ephemeral, client_cert_required };
		let bound = F::bind_reply(&mut opened, settings, parts, &mut OsRng)?;
		let ReplyBinding { transcript_hash, salt, prehash, draft } = bound;
		let terms = Terms::new(profile, mux, transcript_hash, salt);

		// 8. Sign the sealed transcript under the server identity.
		let signature = identity.sign_prehash(&prehash).await?;

		// 9. Issue the session receipt. The transcript hash pins it to this
		//    session, and the server signature lets a third party verify it.
		let issue = IssuedReceipt::issue;
		let issuing = issue(transcript_hash, transport_accept, challenge, client_cert_required, identity);
		let issued = issuing.await?;

		// 10. Derive the handshake secret, which the reply's server Finished
		//     and the closing derive from, and fix what the server carries to
		//     the closing.
		let pending = ServerPending::settle(opened, ephemeral, &terms)?;

		// 11. Encode the reply, and attach its server Finished.
		let artifact = issued.as_ref().map(IssuedReceipt::artifact);
		let reply = F::encode_reply(draft, signature, artifact)?;
		let reply = pending.finish_reply(reply, &terms)?;

		// 12. Keep what the closing is read against.
		let sent = SentReply { terms, pending, issued, flow: PhantomData };
		self.phase = ServerPhase::ReplySent { reply: Box::new(sent) };
		Ok(reply)
	}

	/// Processes the closing of the client: it opens the closing, confirms the
	/// handshake secret, admits the client, and settles the session receipt.
	///
	/// The phase leaves the handshake before any byte of the closing is read,
	/// so a refused closing drops the server ephemeral and the handshake
	/// secret with this step.
	///
	/// # Settlement
	///
	/// Settlement is irreversible, so it runs last, after the key-confirmation
	/// tag proved that the client holds the same handshake secret. Every
	/// budget-bearing session in [`HandshakePhase::Agreed`] is settled.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no reply was sent.
	/// - [`HandshakeError::UnexpectedContainer`] -- the closing travels in
	///   another container, or its content is neither a client Finished nor an
	///   attribute set.
	/// - [`HandshakeError::AbortReceived`] -- the closing carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an attribute of the closing repeats.
	/// - [`HandshakeError::MissingAttribute`] -- the closing carries no key-confirmation tag.
	/// - [`HandshakeError::DerError`] -- the key-confirmation tag is narrower
	///   than 32 bytes or wider than 64, the opened content fails to decode,
	///   or the encoder refuses the key of the admitted client.
	/// - [`HandshakeError::MissingClientCertificate`] -- the server demands a
	///   certificate and none came, or a client Finished came without one.
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, a validator refused it, the signing use
	///   or the client's key purpose refused it, or its key reads as no point
	///   of its curve.
	/// - [`HandshakeError::InvalidPublicKey`] -- the offered certificate key is not a point on the curve.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the client Finished
	///   fails to verify, or the countersignature fails to verify.
	/// - [`HandshakeError::SealedClosing`] -- the closing fails to open: its
	///   envelope, its key, its tag, or its transcript is refused.
	/// - [`HandshakeError::SealedFrame`] -- the opened closing's frame is malformed.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the client's agreement
	///   ephemeral `R` collapses into the key of the certificate the closing
	///   offers.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the closing
	///   key, the key-confirmation tag, or the acknowledgement key.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the client derived another handshake secret.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the sealed countersignature fails to open.
	/// - [`HandshakeError::ReceiptMismatch`] -- an acknowledgement came, and no receipt was issued.
	/// - [`HandshakeError::CountersignatureMissing`] -- an issued receipt got no countersignature.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refused the settlement answer.
	pub async fn finish(&mut self, closing: HandshakeMessage) -> Result<(), HandshakeError> {
		// 1. Take the phase, which must hold the sent reply.
		let reply = self.step(|phase| match phase {
			ServerPhase::ReplySent { reply } => Ok(reply),
			other => Err(other),
		})?;
		let SentReply { terms, pending, issued, .. } = *reply;
		let config = &self.config;

		// 2. Decode the closing.
		let closing = Closing::read(closing)?;

		// 3. Open the closing under the closing key of the handshake secret,
		//    which the reply derived. The client identity sits behind that
		//    key, so the server knows its client before any static key runs.
		let opening = closing.open(pending, &terms, config.key_purposes.client);
		let opened = opening.await?;

		// 4. Verify that the client derived the same handshake secret. The
		//    offer leaves the closing only through this check, so only a
		//    client that holds the same secret reaches a validator.
		let confirmed = opened.confirm(&terms)?;
		let ConfirmedClosing { secret, receipt_ack, offer } = confirmed;

		// 5. Admit the offered identity. Every validator runs when the server
		//    demands a certificate, and an offered certificate's proof is
		//    verified in either mode.
		let peer = config.peer_authentication.admit(offer, &terms)?;

		// 6. Open and verify the receipt countersignature, and settle.
		let authorizer = config.transport_authorizer.as_deref();
		let observer = config.session_observer.as_deref();
		let settlement = Settlement { secret: &secret, terms: &terms, peer: &peer, authorizer, observer };
		let settling = IssuedReceipt::settle_issued(issued, receipt_ack, settlement);
		let receipt = settling.await?;

		// 7. Keep what the handshake agreed.
		let agreed = Agreed::server(terms, secret, receipt, peer);
		self.phase = ServerPhase::ClosingReceived { agreed: Box::new(agreed) };
		Ok(())
	}
}

impl<F: ClientFlow<P>, P: HandshakeProvider> ClientHandshakeProtocol for Handshake<Client, F, P> {
	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<HandshakeMessage, HandshakeError>> {
		Box::pin(async move { Handshake::start(self) })
	}

	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, HandshakeError>> {
		Box::pin(async move {
			let closing = self.respond(msg).await?;
			Ok(Some(closing))
		})
	}

	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, HandshakeError>> {
		Box::pin(async move {
			let mut handshake = self;
			Handshake::complete(&mut handshake)
		})
	}

	fn is_complete(&self) -> bool {
		Handshake::is_complete(self)
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		Handshake::selected_profile(self)
	}
}

impl<F: ServerFlow<P>, P: HandshakeProvider> ServerHandshakeProtocol for Handshake<Server, F, P> {
	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, HandshakeError>> {
		Box::pin(async move {
			// The first message is the opening, which is owed a reply. Every
			// later one is read as the closing, which ends the exchange.
			if self.phase() == HandshakePhase::Idle {
				let reply = self.reply(msg).await?;
				return Ok(Some(reply));
			}

			self.finish(msg).await?;
			Ok(None)
		})
	}

	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, HandshakeError>> {
		Box::pin(async move {
			let mut handshake = self;
			Handshake::complete(&mut handshake)
		})
	}

	fn is_complete(&self) -> bool {
		Handshake::is_complete(self)
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		Handshake::selected_profile(self)
	}
}

#[cfg(test)]
mod tests;
