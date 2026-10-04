//! The handshake orchestrator.
//!
//! [`Handshake`] runs the three [legs](crate::transport::handshake#legs) for
//! one role over one flow. The step order and every negotiation and admission
//! decision are written once per role. A flow contributes the wire of its
//! protocol and the checks that wire defines.
//!
//! ## Phases
//!
//! A phase holds the facts that the steps before it established, so a fact
//! exists only after its step ran. Each step takes the phase by value:
//!
//! - A step called in a phase that does not admit it stores the phase back and
//!   refuses with [`HandshakeError::InvalidState`].
//! - A step that began and failed leaves the handshake [`HandshakePhase::Spent`],
//!   and every secret the phase held drops with the step.
//!
//! ```text
//! Client   Idle ── start ──▶ Exchanging ── respond ──▶ Agreed ── complete ──▶ Completed
//! Server   Idle ── reply ──▶ Exchanging ── finish ───▶ Agreed ── complete ──▶ Completed
//! ```

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use core::marker::PhantomData;
use core::mem;

use crate::crypto::aead::{DirectionalCiphers, SessionKeys};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::random::OsRng;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	ClientFlow, ClosingBinding, ClosingIntake, ClosingOpened, ClosingParts, HandshakeFlow, Opened, OpeningIntake,
	OpeningParts, ProofRequest, ReplyBinding, ReplyIntake, ReplyParts, ServerFlow, Signed,
};
use crate::transport::handshake::negotiation::{
	AuthorizedTransport, MuxSettings, ProfilePolicy, SecurityOffer, SupportedProfiles, TransportAuthorizer,
	TransportNegotiation, TransportOffer,
};
use crate::transport::handshake::peer::{AdmittedPeer, AdmittedServer, PeerAuthentication, ServerTrust};
use crate::transport::handshake::receipt::{
	IssuedReceipt, PendingReceipt, ReceiptApprover, SessionObserver, StoredReceipt,
};
use crate::transport::handshake::schedule::{Agreed, HandshakeVerifyingKey, PeerIdentity, ServerEphemeral, Terms};
use crate::transport::handshake::{
	Arc, ClientHandshakeProtocol, EstablishedSession, HandshakeMessage, HandshakeProvider, ServerHandshakeProtocol,
};
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::x509::Certificate;

mod sealed {
	pub trait Sealed {}
}

/// Where a handshake stands, for either role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
	/// No leg has run.
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
	/// The peer the role records.
	type Peer: PeerIdentity;

	/// The phase a step leaves behind while it runs.
	fn spent() -> Self;

	/// The phase completion leaves behind.
	fn completed() -> Self;

	/// Where the handshake stands.
	fn kind(&self) -> HandshakePhase;

	/// The negotiated terms, from the leg that fixed them to completion.
	fn terms(&self) -> Option<&Terms<P>>;

	/// What the handshake agreed, from the last leg to completion.
	fn agreed(&self) -> Option<&Agreed<P, Self::Peer>>;

	/// Take what the handshake agreed, or hand the phase back unchanged.
	fn take_agreed(self) -> Result<Agreed<P, Self::Peer>, Self>;
}

/// A side of the handshake. The trait is sealed, so [`Client`] and [`Server`]
/// are the only roles.
pub trait Role<F: HandshakeFlow, P: HandshakeProvider>: sealed::Sealed + MaybeSend + MaybeSync + 'static {
	/// The phases of this role.
	type Phase: PhaseView<P>;
	/// What this role is provisioned with.
	type Config: MaybeSend + MaybeSync;

	/// Map the directional ciphers to the keys this role sends and receives on.
	fn session_keys(ciphers: DirectionalCiphers<P::AeadCipher>) -> SessionKeys;
}

/// The client role, which sends the opening and the closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client;

impl sealed::Sealed for Client {}

impl<F: ClientFlow<P>, P: HandshakeProvider> Role<F, P> for Client {
	type Phase = ClientPhase<F, P>;
	type Config = ClientConfig<F, P>;

	fn session_keys(ciphers: DirectionalCiphers<P::AeadCipher>) -> SessionKeys {
		SessionKeys::for_client(ciphers)
	}
}

/// What a client is provisioned with before any leg runs.
pub struct ClientConfig<F: ClientFlow<P>, P: HandshakeProvider> {
	/// What the protocol itself needs: the server trust and the identity.
	pub flow: F::Settings,
	/// The security profiles offered to the server. Without an offer the
	/// server picks its default profile (dealer's choice).
	pub security_offer: Option<SecurityOffer>,
	/// The transport capabilities offered to the server. Without an offer the
	/// connection stays single-flight.
	pub transport_offer: Option<TransportOffer>,
	/// The policy that admits the server's profile selection.
	pub profiles: ProfilePolicy<P>,
	/// The approver consulted before a session receipt is countersigned.
	/// Without one a challenge-bearing receipt fails closed.
	pub receipt_approver: Option<Arc<dyn ReceiptApprover>>,
}

impl<F: ClientFlow<P>, P: HandshakeProvider> ClientConfig<F, P> {
	/// A configuration that offers nothing and applies the default strength
	/// floor.
	pub fn new(flow: F::Settings) -> Self {
		Self {
			flow,
			security_offer: None,
			transport_offer: None,
			profiles: ProfilePolicy::new(),
			receipt_approver: None,
		}
	}
}

/// The phases of a client, each with the facts its steps established.
pub enum ClientPhase<F: ClientFlow<P>, P: HandshakeProvider> {
	/// No leg has run.
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
		agreed: Box<Agreed<P, AdmittedServer>>,
	},
	/// Completion took everything the handshake agreed.
	Completed,
	/// A step began and failed.
	Spent,
}

impl<F: ClientFlow<P>, P: HandshakeProvider> sealed::Sealed for ClientPhase<F, P> {}

impl<F: ClientFlow<P>, P: HandshakeProvider> PhaseView<P> for ClientPhase<F, P> {
	type Peer = AdmittedServer;

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

	fn agreed(&self) -> Option<&Agreed<P, Self::Peer>> {
		match self {
			Self::ClosingSent { agreed } => Some(agreed),
			Self::Idle | Self::OpeningSent { .. } | Self::Completed | Self::Spent => None,
		}
	}

	fn take_agreed(self) -> Result<Agreed<P, Self::Peer>, Self> {
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

	fn session_keys(ciphers: DirectionalCiphers<P::AeadCipher>) -> SessionKeys {
		SessionKeys::for_server(ciphers)
	}
}

/// What a server is provisioned with before any leg runs.
pub struct ServerConfig<F: ServerFlow<P>, P: HandshakeProvider> {
	/// What the protocol itself needs.
	pub flow: F::Settings,
	/// The provider of the server's static key, which signs the reply and
	/// opens what the client seals to the server.
	pub key: Arc<dyn SigningKeyProvider>,
	/// The security profiles the server runs, in preference order.
	pub profiles: SupportedProfiles,
	/// The policy that chooses among those profiles.
	pub policy: ProfilePolicy<P>,
	/// How the server authenticates its client.
	pub peer_authentication: PeerAuthentication,
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
	/// transport capability and applies the default strength floor.
	pub fn new(flow: F::Settings, key: Arc<dyn SigningKeyProvider>, profiles: SupportedProfiles) -> Self {
		Self {
			flow,
			key,
			profiles,
			policy: ProfilePolicy::new(),
			peer_authentication: PeerAuthentication::Anonymous,
			transport: None,
			transport_authorizer: None,
			session_observer: None,
		}
	}
}

/// What a server holds from its reply to the closing.
pub struct SentReply<F: ServerFlow<P>, P: HandshakeProvider> {
	/// What the reply negotiated.
	terms: Terms<P>,
	/// The secrets the flow holds until the closing.
	pending: F::Pending,
	/// The receipt of a budget-bearing session, which the closing settles.
	issued: Option<IssuedReceipt>,
}

/// The phases of a server, each with the facts its steps established.
pub enum ServerPhase<F: ServerFlow<P>, P: HandshakeProvider> {
	/// No leg has run.
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
		agreed: Box<Agreed<P, AdmittedPeer>>,
	},
	/// Completion took everything the handshake agreed.
	Completed,
	/// A step began and failed.
	Spent,
}

impl<F: ServerFlow<P>, P: HandshakeProvider> sealed::Sealed for ServerPhase<F, P> {}

impl<F: ServerFlow<P>, P: HandshakeProvider> PhaseView<P> for ServerPhase<F, P> {
	type Peer = AdmittedPeer;

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

	fn agreed(&self) -> Option<&Agreed<P, Self::Peer>> {
		match self {
			Self::ClosingReceived { agreed } => Some(agreed),
			Self::Idle | Self::ReplySent { .. } | Self::Completed | Self::Spent => None,
		}
	}

	fn take_agreed(self) -> Result<Agreed<P, Self::Peer>, Self> {
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
/// use tightbeam::crypto::x509::policy::DirectTrustValidator;
/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
/// use tightbeam::transport::handshake::negotiation::RunnableProfile;
/// use tightbeam::transport::handshake::{
///     ClientConfig, Ecies, EciesClientSettings, EciesServerSettings, Handshake, HandshakeError, LearnedTrust,
///     ServerConfig, SupportedProfiles,
/// };
///
/// # fn main() -> Result<(), HandshakeError> {
/// # let runtime = tokio::runtime::Builder::new_current_thread().build().expect("doctest runtime");
/// # runtime.block_on(async {
/// // The fixture key is public, so it serves an example alone. A real server
/// // holds a key of its own.
/// let server_key = TestKey::insecure_fixed_signing();
/// let certificate = TestCertificate::self_signed(&server_key);
///
/// // The client admits the one server certificate it pins.
/// let pinned = DirectTrustValidator::default().with_trust_chain([certificate.clone()]);
/// let settings = EciesClientSettings::new(LearnedTrust::new(pinned));
/// let config = ClientConfig::<Ecies, DefaultCryptoProvider>::new(settings);
/// let mut client = Handshake::client(config);
///
/// // The server runs the native profile of its provider.
/// let native = RunnableProfile::<DefaultCryptoProvider>::native().descriptor();
/// let settings = EciesServerSettings::new(certificate);
/// let key = Arc::new(Secp256k1KeyProvider::from(server_key));
/// let config = ServerConfig::<Ecies, DefaultCryptoProvider>::new(settings, key, SupportedProfiles::from(native));
/// let mut server = Handshake::server(config);
///
/// let opening = client.start()?;
/// let reply = server.reply(opening).await?;
/// let closing = client.respond(reply).await?;
/// server.finish(closing).await?;
///
/// client.complete()?;
/// server.complete()?;
/// # Ok(())
/// # })
/// # }
/// ```
pub struct Handshake<R: Role<F, P>, F: HandshakeFlow, P: HandshakeProvider> {
	config: R::Config,
	phase: R::Phase,
	_markers: PhantomData<fn() -> (F, P)>,
}

impl<R: Role<F, P>, F: HandshakeFlow, P: HandshakeProvider> Handshake<R, F, P> {
	/// Take the phase, and leave the handshake spent until a step stores the
	/// next one.
	///
	/// This is the one place a phase leaves the handshake. A step holds what
	/// it took as locals, so each secret drops with the step on a failure and
	/// on a dropped future.
	fn take_phase(&mut self) -> R::Phase {
		mem::replace(&mut self.phase, R::Phase::spent())
	}

	/// Take what `select` picks out of the phase, for a step that runs in one
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

	/// Sign `prehash` under `key`, and fetch the public key that verifies it.
	async fn sign_with(key: &dyn SigningKeyProvider, prehash: &[u8]) -> Result<Signed, HandshakeError> {
		let signature = key.sign_prehash(prehash).await?;
		let signer_spki = key.to_public_key_bytes().await?;
		Ok(Signed { signature, signer_spki })
	}

	/// Complete the handshake and take everything it agreed.
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
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
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
		let recorded = self.phase.agreed().and_then(|agreed| agreed.peer().certificate());
		recorded.map(Arc::as_ref)
	}
}

impl<F: ClientFlow<P>, P: HandshakeProvider> Handshake<Client, F, P> {
	/// Create a client handshake under `config`, in [`HandshakePhase::Idle`]
	/// until [`Self::start`] builds the opening.
	pub fn client(config: ClientConfig<F, P>) -> Self {
		Self { config, phase: ClientPhase::Idle, _markers: PhantomData }
	}

	/// Build the opening, the first message for the server.
	///
	/// A provisioned server identity is admitted before anything is encrypted
	/// to it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the client is past [`HandshakePhase::Idle`].
	/// - [`HandshakeError::MissingServerCertificate`] -- the provisioned chain is empty.
	/// - [`HandshakeError::CertificateValidationError`] -- the trust refused the provisioned server.
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError::MissingKeyWrapAlgorithm`] -- the profile names no key wrap.
	pub fn start(&mut self) -> Result<HandshakeMessage, HandshakeError> {
		// 1. Take the phase, which must be Idle.
		self.step(|phase| match phase {
			ClientPhase::Idle => Ok(()),
			other => Err(other),
		})?;

		// 2. Admit the server when its identity is provisioned.
		let config = &self.config;
		let server = F::server_trust(&config.flow).admit_provisioned()?;

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

	/// Process the reply of the server, and build the closing, the last
	/// message of the client.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no opening was sent.
	/// - [`HandshakeError::UnexpectedContainer`] -- the reply travels in the other container.
	/// - [`HandshakeError::AbortReceived`] -- the reply carries an abort alert.
	/// - [`HandshakeError::MissingAttribute`] -- the reply carries no server ephemeral.
	/// - [`HandshakeError::OctetStringLengthError`] -- a fixed-width field of the reply has another width.
	/// - [`HandshakeError::CertificateValidationError`] -- the trust refused the server the reply names.
	/// - [`HandshakeError::SignatureError`] or
	///   [`HandshakeError::SignatureVerificationFailed`] -- the reply signature
	///   fails to verify, or the receipt fails the server signature check.
	/// - [`HandshakeError::InvalidProfileSelection`] -- the server selected
	///   nothing, or a profile outside the offer.
	/// - [`HandshakeError::NegotiationError`] -- the selected profile is below
	///   the strength floor or unrunnable, or the transport accept is invalid.
	/// - [`HandshakeError::InvalidPublicKey`] -- the signed server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the signed server
	///   ephemeral is the server's static key.
	/// - [`HandshakeError::ReceiptMissing`] -- a budget-bearing accept has no signed receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the receipt disagrees with the negotiated session.
	/// - [`HandshakeError::MutualAuthRequired`] -- the server or a receipt
	///   requires a client identity, and none is set.
	/// - [`HandshakeError::ApprovalRefused`] -- the receipt approver refused.
	/// - [`HandshakeError::KeyError`] -- the signing key provider failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake
	///   secret or the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused to seal the countersignature.
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
		let server = F::server_trust(settings).admit_named(server)?;

		// 4. Verify the reply signature over the transcript hash, under the admitted server's key.
		let static_key = server.certificate().verifying_key::<P::Curve>()?;
		F::verify_reply(&reply, P::VerifyingKey::from(static_key), &transcript_hash)?;

		// 5. Admit the profile selection against the offer.
		let offer = config.security_offer.as_ref();
		let profile = config.profiles.admit(offer, security_accept.as_ref())?;

		// 6. Admit the transport terms, and fix what the reply negotiated. An
		//    accept of terms the client never offered fails closed.
		let mux = MuxSettings::for_client(config.transport_offer.as_ref(), transport_accept.as_ref())?;
		let terms = Terms::new(profile, mux, transcript_hash, salt);

		// 7. Parse the server ephemeral the signature just authenticated,
		//    beside the static key it must differ from.
		let server_ephemeral = static_key.server_ephemeral(&server_ephemeral)?;

		// 8. Verify the session receipt against the accept, which fails closed on a mismatch.
		let accept = transport_accept.as_ref();
		let pending_receipt = PendingReceipt::verify::<P>(receipt, accept, &transcript_hash, server.certificate())?;

		// 9. Derive the handshake secret from the base secret and the ephemeral-ephemeral agreement.
		let (secret, agreed) = F::agree(pending, &server_ephemeral, terms.kdf_salt(), &mut OsRng)?;

		// 10. Approve and countersign the receipt, and seal the countersignature under the handshake secret.
		let identity = F::identity(settings);
		let (sealed_ack, receipt) = match pending_receipt {
			Some(pending_receipt) => {
				let approver = config.receipt_approver.as_deref();
				let countersigning = pending_receipt.countersign(approver, identity, &secret, &terms);
				let (sealed, stored) = countersigning.await?;
				(Some(sealed), Some(stored))
			}
			None => (None, None),
		};

		// 11. Build the closing up to its possession proof.
		let parts = ClosingParts { server: server.certificate(), transcript_hash: &transcript_hash, sealed_ack };
		let ClosingBinding { proof, draft } = F::bind_closing(agreed, reply, settings, parts)?;

		// 12. Sign the proof under the client identity. A client that holds no
		//     identity refuses a server that demands one.
		if client_cert_required && identity.is_none() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		let proof = match proof {
			Some(ProofRequest { prehash, signer }) => Some(Self::sign_with(signer, &prehash).await?),
			None => None,
		};

		// 13. Encode the closing.
		let closing = F::encode_closing(draft, proof)?;

		// 14. Keep what the handshake agreed. The admitted server stays for post-handshake renewals.
		let agreed = Agreed::new(terms, secret, receipt, server);
		self.phase = ClientPhase::ClosingSent { agreed: Box::new(agreed) };
		Ok(closing)
	}
}

impl<F: ServerFlow<P>, P: HandshakeProvider> Handshake<Server, F, P> {
	/// Create a server handshake under `config`, in [`HandshakePhase::Idle`]
	/// until [`Self::reply`] reads the opening.
	pub fn server(config: ServerConfig<F, P>) -> Self {
		Self { config, phase: ServerPhase::Idle, _markers: PhantomData }
	}

	/// Process the opening of the client, and build the reply.
	///
	/// The per-handshake ephemeral is drawn here. Its public half enters the
	/// signed transcript, and its private half serves one agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the server is past [`HandshakePhase::Idle`].
	/// - [`HandshakeError::UnexpectedContainer`] -- the opening travels in the other container.
	/// - [`HandshakeError::AbortReceived`] -- the opening carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an offer or the certificate attribute repeats.
	/// - [`HandshakeError::NegotiationError`] -- profile or transport negotiation failed.
	/// - [`HandshakeError::InvalidClientKeyExchange`] -- the opening carries no usable key agreement.
	/// - [`HandshakeError::MissingUkm`] -- the key agreement carries no user keying material.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client's key is not a point on the curve.
	/// - [`HandshakeError::AesKeyWrap`] -- the wrapped content key fails to unwrap.
	/// - [`HandshakeError::InvalidKeySize`] -- the opened content is not a 32-byte base secret.
	/// - [`HandshakeError::MutualAuthRequired`] -- the accept grants budgets,
	///   and the server demands no client certificate.
	/// - [`HandshakeError::KeyError`] -- the key provider failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	pub async fn reply(&mut self, opening: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		// 1. Take the phase, which must be Idle.
		self.step(|phase| match phase {
			ServerPhase::Idle => Ok(()),
			other => Err(other),
		})?;
		let config = &self.config;
		let settings = &config.flow;
		let key = config.key.as_ref();

		// 2. Decode the opening, and open the transcript over it.
		let OpeningIntake { security_offer, transport_offer, sealed } = F::read_opening(settings, opening)?;

		// 3. Choose the security profile for the offer, or by dealer's choice without one.
		let profile = config.policy.choose(&config.profiles, security_offer.as_ref())?;

		// 4. Negotiate the transport terms. A configured authorizer decides
		//    the budget grant and the settlement challenge before the accept
		//    enters the transcript.
		let offer = transport_offer.as_ref();
		let negotiation = TransportNegotiation { offer, local: config.transport.as_ref() };
		let authorized = negotiation.authorize(config.transport_authorizer.as_deref()).await?;
		let (transport_accept, challenge) = match authorized {
			Some(AuthorizedTransport { accept, challenge }) => (Some(accept), challenge),
			None => (None, None),
		};
		let negotiated = offer.zip(transport_accept.as_ref());
		let mux = negotiated.map(|(offer, accept)| MuxSettings::for_server(offer, accept));

		// 5. Open what the opening sealed to the static key.
		let mut opened = F::open_opening(sealed, key).await?;

		// 6. Draw the per-handshake ephemeral. It is boxed before the first
		//    await that it crosses, so every later move copies a pointer and
		//    the scalar is wiped where the box drops.
		let ephemeral = Box::new(EphemeralSecret::<P::Curve>::random(&mut OsRng));

		// 7. Bind the reply legs into the transcript and seal it, which fixes what the reply negotiated.
		let client_cert_required = config.peer_authentication.requires_certificate();
		let transport_accept = transport_accept.as_ref();
		let server_ephemeral = ephemeral.public_key();
		let parts = ReplyParts { profile, transport_accept, server_ephemeral, client_cert_required };
		let bound = F::bind_reply(&mut opened, settings, parts, &mut OsRng)?;
		let ReplyBinding { transcript_hash, salt, prehash, draft } = bound;
		let terms = Terms::new(profile, mux, transcript_hash, salt);

		// 8. Sign the sealed transcript under the static key.
		let signed = Self::sign_with(key, &prehash).await?;

		// 9. Issue the session receipt. The transcript hash pins it to this
		//    session, and the server signature lets a third party verify it.
		let issue = IssuedReceipt::issue::<P::Digest>;
		let issuing = issue(transcript_hash, transport_accept, challenge, client_cert_required, key);
		let issued = issuing.await?;

		// 10. Encode the reply.
		let artifact = issued.as_ref().map(IssuedReceipt::artifact);
		let reply = F::encode_reply(draft, signed, artifact)?;

		// 11. Fix what the server carries to the closing.
		let pending = F::pend(opened, ephemeral, &terms)?;

		// 12. Keep what the closing is read against.
		let sent = SentReply { terms, pending, issued };
		self.phase = ServerPhase::ReplySent { reply: Box::new(sent) };
		Ok(reply)
	}

	/// Process the closing of the client: admit the client, derive the
	/// handshake secret, and settle the session receipt.
	///
	/// The phase leaves the handshake before any byte of the closing is read,
	/// so a refused closing drops the server ephemeral and the handshake
	/// secret with this step.
	///
	/// # Settlement
	///
	/// Settlement is irreversible, so it runs last. No budget-bearing session
	/// reaches [`HandshakePhase::Agreed`] unsettled.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no reply was sent.
	/// - [`HandshakeError::UnexpectedContainer`] -- the closing travels in the other container.
	/// - [`HandshakeError::AbortReceived`] -- the closing carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an attribute of the closing repeats.
	/// - [`HandshakeError::ClientCertificateMismatch`] -- the closing names
	///   another certificate than the opening bound.
	/// - [`HandshakeError::MissingClientCertificate`] -- the server demands a
	///   certificate and none came, or a proof came without one.
	/// - [`HandshakeError::CertificateValidationError`] -- a validator refused the client certificate.
	/// - [`HandshakeError::SignatureError`] or
	///   [`HandshakeError::SignatureVerificationFailed`] -- the possession
	///   proof is missing or wrong, or the countersignature fails to verify.
	/// - [`HandshakeError::EciesError`] -- the sealed payload fails to open, as
	///   it does under a swapped client certificate.
	/// - [`HandshakeError::ClientRandomMismatchReplay`] -- the payload echoes another client random.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake
	///   secret or the acknowledgement key.
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
		let SentReply { terms, pending, issued } = *reply;
		let config = &self.config;

		// 2. Decode the closing.
		let ClosingIntake { offered, proof, closing } = F::read_closing(&pending, &config.flow, closing)?;

		// 3. Admit the offered identity. Every validator runs when the server
		//    demands a certificate, and an offered certificate's proof is
		//    verified in either mode.
		let peer = config.peer_authentication.admit(offered, proof, &terms)?;

		// 4. Open what the closing sealed, and derive the handshake secret.
		//    The static key serves an admitted client alone.
		let opening = F::settle(pending, closing, &terms, config.key.as_ref());
		let ClosingOpened { secret, receipt_ack } = opening.await?;

		// 5. Open and verify the receipt countersignature, and settle.
		let authorizer = config.transport_authorizer.as_deref();
		let observer = config.session_observer.as_deref();
		let settling = IssuedReceipt::settle_issued(issued, receipt_ack, &secret, &terms, &peer, authorizer, observer);
		let receipt = settling.await?;

		// 6. Keep what the handshake agreed.
		let agreed = Agreed::new(terms, secret, receipt, peer);
		self.phase = ServerPhase::ClosingReceived { agreed: Box::new(agreed) };
		Ok(())
	}
}

impl<F: ClientFlow<P>, P: HandshakeProvider> ClientHandshakeProtocol for Handshake<Client, F, P> {
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<HandshakeMessage, Self::Error>> {
		Box::pin(async move { Handshake::start(self) })
	}

	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, Self::Error>> {
		Box::pin(async move {
			let closing = self.respond(msg).await?;
			Ok(Some(closing))
		})
	}

	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, Self::Error>> {
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
	type Error = HandshakeError;

	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, Self::Error>> {
		Box::pin(async move {
			// The first message is the opening, which is owed a reply. Every
			// later one is read as the closing, which is owed nothing.
			if self.phase() == HandshakePhase::Idle {
				let reply = self.reply(msg).await?;
				return Ok(Some(reply));
			}

			self.finish(msg).await?;
			Ok(None)
		})
	}

	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, Self::Error>> {
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
