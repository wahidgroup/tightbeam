//! Common helpers and fixtures for security threat integration tests.
//!
//! The module gives one protocol-agnostic interface for testing security
//! threats across the handshake backends (ECIES, CMS), so each threat test
//! runs against every backend from one body.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::der::asn1::OctetString;
use tightbeam::{
	crypto::{
		aead::{Aes128Gcm, Aes128GcmOid, Aes256Gcm},
		ecies::{self, Secp256k1EciesMessage},
		hash::Sha3_256,
		kdf::HkdfSha3_256,
		profiles::{
			AeadProvider, CryptoProvider, CurveProvider, DefaultCryptoProvider, DigestProvider, KdfProvider,
			SecurityProfile, SecurityProfileDesc, SigningProvider,
		},
		secret::ToInsecure,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey},
	},
	oids::AES_128_WRAP,
	testing::error::{FdrConfigError, TestingError},
	transport::handshake::{
		negotiation::{NoStrengthFloor, ProfilePolicy, ProfileStrengthPolicy, SecurityOffer},
		Client, ClientHandshakeProtocol, Ecies, Handshake, HandshakeError, HandshakeMessage, HandshakeProvider, Server,
		ServerHandshakeProtocol,
	},
	transport::wire_der::WireDer,
	TightBeamError,
};

#[cfg(feature = "transport-cms")]
use tightbeam::cms::signed_data::SignedData;
#[cfg(feature = "transport-cms")]
use tightbeam::der::{Any, Decode, Encode};
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::Cms;

/// A security profile on AES-128-GCM, which is weaker than the default
/// AES-256-GCM.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Profile;

impl SecurityProfile for Aes128Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type Curve = k256::Secp256k1;

	const KEY_WRAP_OID: Option<tightbeam::der::asn1::ObjectIdentifier> = Some(AES_128_WRAP);
}

/// A crypto provider on AES-128-GCM, for a downgrade attack test.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128CryptoProvider {
	profile: Aes128Profile,
}

impl DigestProvider for Aes128CryptoProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for Aes128CryptoProvider {
	type AeadCipher = Aes128Gcm;
}

impl SigningProvider for Aes128CryptoProvider {
	type Signature = Secp256k1Signature;
	type SigningKey = Secp256k1SigningKey;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for Aes128CryptoProvider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for Aes128CryptoProvider {
	type Curve = k256::Secp256k1;
	type EciesMessage = Secp256k1EciesMessage;
}

impl CryptoProvider for Aes128CryptoProvider {
	type Profile = Aes128Profile;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The direction a handshake message travels in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
	ClientToServer,
	ServerToClient,
}

/// A single handshake message captured during the flow.
#[derive(Debug, Clone)]
pub struct CapturedMessage {
	/// The step number the protocol assigns this message, which is its
	/// [`FlowStep::index`].
	pub step: usize,
	/// Which endpoint sent the message.
	pub direction: Direction,
	/// Exact DER bytes as they crossed the wire.
	pub payload: Vec<u8>,
}

/// The result of running a full handshake with capture.
#[derive(Debug, Clone)]
pub struct CapturedHandshake {
	/// Every message the flow produced, in send order.
	pub messages: Vec<CapturedMessage>,
	/// Handshake backend that produced the capture.
	pub kind: HandshakeBackendKind,
}

impl CapturedHandshake {
	/// Return the last client-to-server message, the common replay target.
	pub fn final_client_message(&self) -> Option<&CapturedMessage> {
		self.messages.iter().rev().find(|m| m.direction == Direction::ClientToServer)
	}

	/// Return every client-to-server message.
	pub fn client_messages(&self) -> impl Iterator<Item = &CapturedMessage> {
		self.messages.iter().filter(|m| m.direction == Direction::ClientToServer)
	}

	/// Return the message at a specific step.
	#[allow(dead_code)]
	pub fn message_at(&self, step: usize) -> Option<&CapturedMessage> {
		self.messages.iter().find(|m| m.step == step)
	}
}

/// The outcome of injecting a message during a handshake.
#[derive(Debug)]
#[allow(dead_code)]
pub enum InjectionOutcome {
	/// The handshake continued or completed, which fails a replay attack test.
	Accepted,
	/// The handshake rejected the message with an error, which passes a replay
	/// attack test.
	Rejected(TightBeamError),
}

/// The boxed future a flow step returns, which borrows the session it runs on.
type FlowFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TightBeamError>> + Send + 'a>>;

/// The CMS container a handshake message travels in.
#[derive(Debug, Clone, Copy)]
pub enum Container {
	/// A `SignedData`.
	Signed,
	/// An `EnvelopedData`.
	Enveloped,
}

impl Container {
	/// Read `der` as a message in this container, with the bytes it arrived as.
	fn message(self, der: &[u8]) -> Result<HandshakeMessage, TightBeamError> {
		let message = match self {
			Self::Signed => HandshakeMessage::SignedData(Box::new(WireDer::try_from(der)?)),
			Self::Enveloped => HandshakeMessage::EnvelopedData(Box::new(WireDer::try_from(der)?)),
		};

		Ok(message)
	}
}

/// One message in a handshake flow.
#[derive(Debug, Clone, Copy)]
pub struct FlowStep {
	/// The step number the protocol assigns this message.
	pub index: usize,
	/// The endpoint that sends it.
	pub direction: Direction,
	/// The container the message travels in.
	pub container: Container,
}

/// A handshake flow described as its ordered steps.
///
/// A backend states its step table and how one step advances to the next. The
/// sequence is then written once here, so capture and injection drive the same
/// machine rather than each transcribing the protocol again.
pub trait HandshakeFlow: Send {
	/// The backend this flow belongs to.
	fn backend(&self) -> HandshakeBackendKind;

	/// The ordered steps this protocol exchanges.
	fn steps(&self) -> &'static [FlowStep];

	/// Build the opening message, which no earlier step produces.
	fn open(&mut self) -> FlowFuture<'_, Vec<u8>>;

	/// Hand `msg` to the endpoint that receives step `index`, returning that
	/// endpoint's reply when the flow continues.
	fn advance<'a>(
		&'a mut self,
		index: usize,
		msg: &'a (impl AsRef<[u8]> + ?Sized + Sync),
	) -> FlowFuture<'a, Option<Vec<u8>>>;
}

/// Protocol-agnostic handshake operations for security testing.
///
/// Both operations are derived from the flow's step table, so a backend states
/// its sequence once and gets capture and injection from it.
#[allow(dead_code)]
pub trait HandshakeProtocol: Send {
	/// Return the backend kind for this session.
	fn kind(&self) -> HandshakeBackendKind;

	/// Run a complete handshake, capturing all exchanged messages.
	fn capture_full(&mut self) -> FlowFuture<'_, CapturedHandshake>;

	/// Run the handshake up to step N, then inject a different message at
	/// step N.
	fn inject_at_step(&mut self, step: usize, msg: &[u8]) -> FlowFuture<'_, InjectionOutcome>;
}

impl<F: HandshakeFlow> HandshakeProtocol for F {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeFlow::backend(self)
	}

	fn capture_full(&mut self) -> FlowFuture<'_, CapturedHandshake> {
		Box::pin(async move {
			let steps = self.steps();
			let backend = HandshakeFlow::backend(self);
			let mut messages = Vec::with_capacity(steps.len());
			let mut pending = Some(self.open().await?);

			for step in steps {
				let Some(payload) = pending else {
					break;
				};

				pending = self.advance(step.index, &payload).await?;
				messages.push(CapturedMessage { step: step.index, direction: step.direction, payload });
			}

			Ok(CapturedHandshake { messages, kind: backend })
		})
	}

	fn inject_at_step(&mut self, step: usize, msg: &[u8]) -> FlowFuture<'_, InjectionOutcome> {
		let msg = msg.to_vec();
		Box::pin(async move {
			let steps = self.steps();
			if !steps.iter().any(|candidate| candidate.index == step) {
				return Err(invalid_step_error("step is not part of this handshake flow"));
			}

			// The opening message is built only once a step before the target
			// needs it, so injecting at step 0 leaves the client untouched.
			let mut pending = None;
			for candidate in steps.iter().take_while(|candidate| candidate.index != step) {
				let payload = match pending {
					Some(payload) => payload,
					None => self.open().await?,
				};

				pending = self.advance(candidate.index, &payload).await?;
			}

			match self.advance(step, &msg).await {
				Ok(_) => Ok(InjectionOutcome::Accepted),
				Err(e) => Ok(InjectionOutcome::Rejected(e)),
			}
		})
	}
}

// Shared fixtures live in the crate-wide `common` module so threat suites do
// not depend on one another's helpers.
pub use crate::common::security::{
	default_security_profile, expectation_failure, pinning_validator, weak_security_profile, ServerMaterials,
};

use crate::common::security::{
	carried_key_exchange, ecies_client_config, ecies_server_config, tunneled_handshake, tunneled_reply,
};
#[cfg(feature = "transport-cms")]
use crate::common::security::{cms_client_config, cms_server_config, pinning_trust_store, ClientMaterials};
#[cfg(feature = "transport-cms")]
use tightbeam::transport::{handshake::HandshakeKeyManager, state::ClientIdentity};

/// The total number of handshake backends the security harness exercises.
pub const BACKEND_COUNT: usize = 1 + cfg!(feature = "transport-cms") as usize;
/// [`BACKEND_COUNT`] as a `u32`, for the spec macros.
pub const BACKEND_COUNT_U32: u32 = BACKEND_COUNT as u32;

/// The handshake backends the harness can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeBackendKind {
	Ecies,
	#[cfg(feature = "transport-cms")]
	Cms,
}

impl HandshakeBackendKind {
	/// The human-readable backend label, for logging and trace events.
	#[allow(dead_code)]
	pub fn label(self) -> &'static str {
		match self {
			Self::Ecies => "ecies",
			#[cfg(feature = "transport-cms")]
			Self::Cms => "cms",
		}
	}

	/// Return every enabled backend.
	pub fn all() -> Vec<Self> {
		let mut kinds = vec![Self::Ecies];
		#[cfg(feature = "transport-cms")]
		{
			kinds.push(Self::Cms);
		}
		kinds
	}

	/// Flip one byte of the signed content in this backend's server message.
	///
	/// This simulates a MITM attacker modifying the message in transit. The
	/// edit goes through the decoded message and re-encodes it, so the result
	/// is well-formed DER that only a transcript or signature check can refuse.
	///
	/// - ECIES tampers the `ServerHandshake` server random.
	/// - CMS tampers the first byte of the content the `ServerFinished` signs,
	///   which sits in the domain label ahead of the transcript hash.
	pub fn tamper_server_message(self, payload: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
		let payload = payload.as_ref();
		match self {
			Self::Ecies => {
				let mut message = tunneled_handshake(Container::Signed.message(payload)?);
				let server_random = flip_first_byte(message.server_random.as_bytes())?;
				message.server_random = OctetString::new(server_random)?;
				Ok(tunneled_reply(&message).der().to_vec())
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => {
				let mut signed_data = SignedData::from_der(payload)?;
				let content = signed_data
					.encap_content_info
					.econtent
					.as_ref()
					.ok_or_else(|| expectation_failure("ServerFinished carries no content"))?;

				let transcript_hash: OctetString = content.decode_as()?;
				let tampered_hash = OctetString::new(flip_first_byte(transcript_hash.as_bytes())?)?;
				signed_data.encap_content_info.econtent = Some(Any::encode_from(&tampered_hash)?);
				Ok(signed_data.to_der()?)
			}
		}
	}
}

/// Copy `bytes` with the first byte inverted.
fn flip_first_byte(bytes: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let mut flipped = bytes.to_vec();
	let first = flipped
		.first_mut()
		.ok_or_else(|| expectation_failure("tamper target is empty"))?;

	*first ^= 0xFF;

	Ok(flipped)
}

use tightbeam::trace::TraceCollector;
use tightbeam::utils::urn::Urn;

/// A harness that spawns handshake sessions across every enabled backend.
///
/// The harness can hold a `TraceCollector` that emits internal (hidden)
/// events during handshake operations, so a process spec can validate
/// internal state.
#[derive(Clone)]
pub struct SecurityThreatHarness {
	materials: ServerMaterials,
	trace: Option<Arc<TraceCollector>>,
}

impl Default for SecurityThreatHarness {
	fn default() -> Self {
		Self { materials: ServerMaterials::generate(), trace: None }
	}
}

impl SecurityThreatHarness {
	/// Hidden CSP event: a handshake session is about to be constructed.
	pub const HARNESS_SPAWN_SESSION: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-session");
	/// Hidden CSP event: the ECIES backend is selected for the session.
	pub const HARNESS_SPAWN_ECIES: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-ecies");
	/// Hidden CSP event: the CMS backend is selected for the session.
	pub const HARNESS_SPAWN_CMS: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-cms");
	/// Hidden CSP event: the weak-cipher spawn path is entered.
	pub const HARNESS_SPAWN_WEAK: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-weak");
	/// Hidden CSP event: the weak ECIES backend is selected.
	pub const HARNESS_SPAWN_ECIES_WEAK: Urn<'static> =
		tightbeam::urn!("test", "event:security-harness/spawn-ecies-weak");
	/// Hidden CSP event: the weak CMS backend is selected.
	pub const HARNESS_SPAWN_CMS_WEAK: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-cms-weak");

	/// Create a harness with a trace collector for internal event emission.
	pub fn with_trace(trace: Arc<TraceCollector>) -> Self {
		Self { materials: ServerMaterials::generate(), trace: Some(trace) }
	}

	/// Return the server materials for test verification.
	pub fn materials(&self) -> &ServerMaterials {
		&self.materials
	}

	/// Emit a hidden event when a trace collector is configured.
	fn emit(&self, event: Urn<'static>) -> Result<(), TightBeamError> {
		if let Some(ref trace) = self.trace {
			trace.event(event)?;
		}
		Ok(())
	}

	/// Spawn a protocol session for the given backend kind with default
	/// profiles.
	pub fn spawn(&self, kind: HandshakeBackendKind) -> Box<dyn HandshakeProtocol> {
		let client_profiles = vec![default_security_profile()];
		let server_profiles = vec![default_security_profile()];
		self.spawn_with_profiles(kind, client_profiles, server_profiles)
	}

	/// Spawn a protocol session with specific client and server profiles.
	///
	/// The method supports cross-session downgrade attack tests:
	///
	/// - The client offers `client_profiles`.
	/// - The server accepts `server_profiles`.
	pub fn spawn_with_profiles(
		&self,
		kind: HandshakeBackendKind,
		client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> Box<dyn HandshakeProtocol> {
		let client_profiles: Vec<SecurityProfileDesc> = client_profiles.into_iter().collect();
		let server_profiles: Vec<SecurityProfileDesc> = server_profiles.into_iter().collect();

		self.emit(Self::HARNESS_SPAWN_SESSION).ok();

		match kind {
			HandshakeBackendKind::Ecies => {
				self.emit(Self::HARNESS_SPAWN_ECIES).ok();
				Box::new(Session::<Ecies, DefaultCryptoProvider>::with_profiles(
					&self.materials,
					client_profiles,
					server_profiles,
					None,
				))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit(Self::HARNESS_SPAWN_CMS).ok();
				Box::new(Session::<Cms, DefaultCryptoProvider>::with_profiles(
					&self.materials,
					client_profiles,
					server_profiles,
					None,
				))
			}
		}
	}

	/// Spawn a session with the WEAK cipher (AES-128-GCM) for downgrade
	/// testing.
	///
	/// `Aes128CryptoProvider` runs AES-128 at the cipher level as well as
	/// naming it in the profile descriptor OIDs.
	pub fn spawn_weak(&self, kind: HandshakeBackendKind) -> Box<dyn HandshakeProtocol> {
		self.emit(Self::HARNESS_SPAWN_WEAK).ok();
		match kind {
			HandshakeBackendKind::Ecies => {
				self.emit(Self::HARNESS_SPAWN_ECIES_WEAK).ok();
				// The session is deliberately weak. It opts out of the default
				// strength floor, so the downgrade harness can capture AES-128
				// wire bytes.
				Box::new(Session::<Ecies, Aes128CryptoProvider>::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
					Some(Arc::new(NoStrengthFloor)),
				))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit(Self::HARNESS_SPAWN_CMS_WEAK).ok();
				// The session is deliberately weak. It opts out of the default
				// strength floor, so the downgrade harness can capture AES-128
				// wire bytes.
				Box::new(Session::<Cms, Aes128CryptoProvider>::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
					Some(Arc::new(NoStrengthFloor)),
				))
			}
		}
	}
}

/// Create the error for an invalid injection step.
fn invalid_step_error(msg: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "inject_at_step",
		reason: msg,
	}))
}

/// Tamper with a message by appending extra bytes.
///
/// The function simulates a MITM attacker that adds data to a message.
#[allow(dead_code)]
pub fn tamper_payload_append(payload: impl AsRef<[u8]>, extra: impl AsRef<[u8]>) -> Vec<u8> {
	let payload = payload.as_ref();
	let extra = extra.as_ref();
	let mut tampered = payload.to_vec();
	tampered.extend_from_slice(extra);
	tampered
}

/// Tamper with a message by truncating bytes.
///
/// The function simulates a MITM attacker that truncates a message.
#[allow(dead_code)]
pub fn tamper_payload_truncate(payload: impl AsRef<[u8]>, keep_bytes: usize) -> Vec<u8> {
	let payload = payload.as_ref();
	payload.iter().take(keep_bytes).copied().collect()
}

/// The result of an attempt to decrypt an ECIES payload.
#[derive(Debug)]
pub enum DecryptionResult {
	/// Decryption succeeded. `plaintext_len` is the length of the recovered
	/// plaintext, which the caller checks against the size it expects.
	Success { plaintext_len: usize },
	/// Decryption failed, for example on a wrong key or a corrupted ciphertext.
	Failed,
}

/// Return the encrypted ECIES blob from the DER of a captured ECIES closing,
/// which carries the `ClientKeyExchange`.
pub fn extract_ecies_ciphertext(closing_der: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let closing = Container::Enveloped.message(closing_der.as_ref())?;
	let client_kex = carried_key_exchange(closing);
	Ok(client_kex.encrypted_data.as_bytes().to_vec())
}

/// Extract the ephemeral public key from an ECIES ciphertext.
///
/// The ephemeral public key is the first 33 bytes (compressed secp256k1
/// point) of the raw ECIES blob, so the function returns those 33 bytes.
pub fn extract_ephemeral_pubkey(ecies_ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
	let ecies_ciphertext = ecies_ciphertext.as_ref();
	// The ECIES message format is
	// [ephemeral_pubkey (33 bytes) || nonce+ciphertext+tag].
	const EPHEMERAL_PUBKEY_SIZE: usize = 33;

	if ecies_ciphertext.len() < EPHEMERAL_PUBKEY_SIZE {
		return Err(TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
			field: "ephemeral_pubkey",
			reason: "ECIES ciphertext too short",
		})));
	}

	Ok(ecies_ciphertext[..EPHEMERAL_PUBKEY_SIZE].to_vec())
}

/// The default domain tag an ECIES closing payload is sealed under. It is the
/// whole associated data when the client presents no certificate.
pub const HANDSHAKE_AAD: &[u8] = b"tb/aead/v1";

/// Attempt to decrypt an ECIES ciphertext with the recipient's secret key.
///
/// `aad` defaults to [`HANDSHAKE_AAD`] when it is `None`.
///
/// # Returns
///
/// - `DecryptionResult::Success` with the plaintext length when decryption worked.
/// - `DecryptionResult::Failed` when decryption failed, for example on a wrong key or invalid data.
pub fn try_decrypt_ecies(
	ciphertext: impl AsRef<[u8]>,
	secret_key: &k256::SecretKey,
	aad: Option<&[u8]>,
) -> DecryptionResult {
	let ciphertext = ciphertext.as_ref();
	let message = match Secp256k1EciesMessage::from_bytes(ciphertext) {
		Ok(m) => m,
		Err(_) => return DecryptionResult::Failed,
	};

	let aad = aad.or(Some(HANDSHAKE_AAD));

	match ecies::decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(secret_key, &message, aad) {
		Ok(plaintext) => {
			let plaintext_bytes = plaintext.to_insecure();
			DecryptionResult::Success { plaintext_len: plaintext_bytes.len() }
		}
		Err(_) => DecryptionResult::Failed,
	}
}

/// Generate a random secret key, to test decryption with a wrong key.
pub fn generate_wrong_secret_key() -> k256::SecretKey {
	k256::SecretKey::random(&mut rand_core::OsRng)
}

/// The three messages an ECIES handshake exchanges.
const ECIES_FLOW: &[FlowStep] = &[
	FlowStep { index: 0, direction: Direction::ClientToServer, container: Container::Signed },
	FlowStep { index: 1, direction: Direction::ServerToClient, container: Container::Signed },
	FlowStep { index: 2, direction: Direction::ClientToServer, container: Container::Enveloped },
];

/// The three messages a CMS handshake exchanges. The intervening odd steps are
/// the receiving half of each, so they carry no message of their own.
#[cfg(feature = "transport-cms")]
const CMS_FLOW: &[FlowStep] = &[
	FlowStep { index: 0, direction: Direction::ClientToServer, container: Container::Enveloped },
	FlowStep { index: 2, direction: Direction::ServerToClient, container: Container::Signed },
	FlowStep { index: 4, direction: Direction::ClientToServer, container: Container::Signed },
];

/// A handshake protocol the harness runs sessions of, under provider `P`.
///
/// The library's flow markers implement it. The library keeps the traits that
/// bound [`Handshake`] over a flow private, so a test cannot name
/// `Handshake<Client, F, P>` for a generic `F`. A flow names its two handshakes
/// here, and [`Session`] drives them through the protocol traits that both
/// implement.
pub trait SessionFlow<P: HandshakeProvider> {
	/// The client handshake, `Handshake<Client, Self, P>`.
	type Client: ClientHandshakeProtocol<Error = HandshakeError>;
	/// The server handshake, `Handshake<Server, Self, P>`.
	type Server: ServerHandshakeProtocol<Error = HandshakeError>;

	/// The backend this flow belongs to.
	const BACKEND: HandshakeBackendKind;
	/// The ordered steps this flow exchanges.
	const STEPS: &'static [FlowStep];

	/// A client that admits the server of `materials`, sends `offer`, and
	/// admits the selection under `policy`.
	fn client(materials: &ServerMaterials, offer: SecurityOffer, policy: ProfilePolicy<P>) -> Self::Client;

	/// An anonymous-client server over `materials` that runs `profiles` and
	/// chooses among them under `policy`.
	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Self::Server;
}

impl<P: HandshakeProvider> SessionFlow<P> for Ecies {
	type Client = Handshake<Client, Ecies, P>;
	type Server = Handshake<Server, Ecies, P>;

	const BACKEND: HandshakeBackendKind = HandshakeBackendKind::Ecies;
	const STEPS: &'static [FlowStep] = ECIES_FLOW;

	fn client(materials: &ServerMaterials, offer: SecurityOffer, policy: ProfilePolicy<P>) -> Self::Client {
		let mut config = ecies_client_config(pinning_validator(&materials.certificate));
		config.security_offer = Some(offer);
		config.profiles = policy;
		Handshake::client(config)
	}

	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Self::Server {
		let mut config = ecies_server_config(materials, profiles);
		config.policy = policy;
		Handshake::server(config)
	}
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> SessionFlow<P> for Cms {
	type Client = Handshake<Client, Cms, P>;
	type Server = Handshake<Server, Cms, P>;

	const BACKEND: HandshakeBackendKind = HandshakeBackendKind::Cms;
	const STEPS: &'static [FlowStep] = CMS_FLOW;

	/// The client pins the server certificate and presents a fresh identity.
	fn client(materials: &ServerMaterials, offer: SecurityOffer, policy: ProfilePolicy<P>) -> Self::Client {
		let client_materials = ClientMaterials::generate();
		let trust_store = pinning_trust_store(&materials.certificate)
			.expect("a trust store builds from the generated server certificate");

		let key_provider = Arc::clone(&client_materials.key_provider);
		let key_manager = Arc::new(HandshakeKeyManager::<P>::new(key_provider));
		let identity = ClientIdentity::new(Arc::clone(&client_materials.certificate), key_manager);

		let mut config = cms_client_config(&materials.certificate, trust_store, identity);
		config.security_offer = Some(offer);
		config.profiles = policy;
		Handshake::client(config)
	}

	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Self::Server {
		let mut config = cms_server_config(materials, profiles);
		config.policy = policy;
		Handshake::server(config)
	}
}

/// One handshake of flow `F` under provider `P`, with both of its endpoints.
pub struct Session<F: SessionFlow<P>, P: HandshakeProvider> {
	client: F::Client,
	server: F::Server,
}

impl<F: SessionFlow<P>, P: HandshakeProvider> Session<F, P> {
	/// Create a session with specific client and server profiles.
	///
	/// `strength_policy` overrides both endpoints' default strength floor,
	/// which a deliberately weak downgrade session needs.
	fn with_profiles(
		materials: &ServerMaterials,
		client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		strength_policy: Option<Arc<dyn ProfileStrengthPolicy + Send + Sync>>,
	) -> Self {
		let offer = SecurityOffer::new(client_profiles);
		let server_profiles: Vec<SecurityProfileDesc> = server_profiles.into_iter().collect();
		let policy = strength_policy.map(ProfilePolicy::with_floor).unwrap_or_default();

		Self {
			client: F::client(materials, offer, policy.clone()),
			server: F::server(materials, server_profiles, policy),
		}
	}
}

impl<F: SessionFlow<P>, P: HandshakeProvider> HandshakeFlow for Session<F, P> {
	fn backend(&self) -> HandshakeBackendKind {
		F::BACKEND
	}

	fn steps(&self) -> &'static [FlowStep] {
		F::STEPS
	}

	fn open(&mut self) -> FlowFuture<'_, Vec<u8>> {
		Box::pin(async move { Ok(self.client.start().await?.der().to_vec()) })
	}

	fn advance<'a>(
		&'a mut self,
		index: usize,
		msg: &'a (impl AsRef<[u8]> + ?Sized + Sync),
	) -> FlowFuture<'a, Option<Vec<u8>>> {
		let msg = msg.as_ref();
		Box::pin(async move {
			let step = F::STEPS.iter().find(|step| step.index == index);
			let step = step.ok_or_else(|| invalid_step_error("step is not part of this handshake flow"))?;

			// The server answers the opening with its reply and the closing
			// with nothing, and the client answers the reply with its closing.
			let message = step.container.message(msg)?;
			let answer = match step.direction {
				Direction::ClientToServer => self.server.handle_request(message).await?,
				Direction::ServerToClient => self.client.handle_response(message).await?,
			};

			Ok(answer.map(|answer| answer.der().to_vec()))
		})
	}
}
