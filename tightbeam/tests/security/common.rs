//! Common helpers and fixtures for security threat integration tests.
//!
//! This module provides a protocol-agnostic abstraction for testing security threats
//! across multiple handshake backends (ECIES, CMS) without code duplication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::der::Encode;
use tightbeam::{
	crypto::{
		aead::{Aes128Gcm, Aes128GcmOid, Aes256Gcm},
		curves::Secp256k1Oid,
		ecies::{self, Secp256k1EciesMessage},
		hash::Sha3_256,
		kdf::{HkdfSha3_256, HkdfSha3_256Oid},
		kem::Kyber1024Oid,
		profiles::{
			AeadProvider, CryptoProvider, CurveProvider, DefaultCryptoProvider, DigestProvider, KdfProvider,
			SecurityProfile, SecurityProfileDesc, SigningProvider,
		},
		secret::ToInsecure,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey},
	},
	der::Decode,
	oids::AES_128_WRAP,
	testing::error::{FdrConfigError, TestingError},
	transport::handshake::{
		client::EciesHandshakeClient,
		negotiation::{NoStrengthFloor, ProfileStrengthPolicy, SecurityOffer},
		server::EciesHandshakeServer,
		ClientKeyExchange,
	},
	TightBeamError,
};

#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{client::CmsHandshakeClient, server::CmsHandshakeServer};

// ============================================================================
// AES-128 Crypto Provider for Downgrade Attack Testing
// ============================================================================

/// Security profile using AES-128-GCM (weaker than default AES-256-GCM).
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Profile;

impl SecurityProfile for Aes128Profile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type KdfOid = HkdfSha3_256Oid;
	type CurveOid = Secp256k1Oid;
	type KemOid = Kyber1024Oid;

	const KEY_WRAP_OID: Option<tightbeam::der::asn1::ObjectIdentifier> = Some(AES_128_WRAP);
}

/// Crypto provider using AES-128-GCM for downgrade attack testing.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128CryptoProvider {
	profile: Aes128Profile,
}

impl DigestProvider for Aes128CryptoProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for Aes128CryptoProvider {
	type AeadCipher = Aes128Gcm;
	type AeadOid = Aes128GcmOid;
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

// ============================================================================
// Core Types for Protocol Abstraction
// ============================================================================

/// Direction of a handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
	ClientToServer,
	ServerToClient,
}

/// A single handshake message captured during the flow.
#[derive(Debug, Clone)]
pub struct CapturedMessage {
	/// Position of this message in the handshake flow, starting at zero.
	pub step: usize,
	/// Which endpoint sent the message.
	pub direction: Direction,
	/// Exact DER bytes as they crossed the wire.
	pub payload: Vec<u8>,
}

/// Result of running a full handshake with capture.
#[derive(Debug, Clone)]
pub struct CapturedHandshake {
	/// Every message the flow produced, in send order.
	pub messages: Vec<CapturedMessage>,
	/// Handshake backend that produced the capture.
	pub kind: HandshakeBackendKind,
}

impl CapturedHandshake {
	/// Get the last client-to-server message (common replay target).
	pub fn final_client_message(&self) -> Option<&CapturedMessage> {
		self.messages.iter().rev().find(|m| m.direction == Direction::ClientToServer)
	}

	/// Get all client-to-server messages.
	pub fn client_messages(&self) -> impl Iterator<Item = &CapturedMessage> {
		self.messages.iter().filter(|m| m.direction == Direction::ClientToServer)
	}

	/// Get message at a specific step.
	#[allow(dead_code)]
	pub fn message_at(&self, step: usize) -> Option<&CapturedMessage> {
		self.messages.iter().find(|m| m.step == step)
	}
}

/// Outcome of injecting a message during handshake.
#[derive(Debug)]
#[allow(dead_code)]
pub enum InjectionOutcome {
	/// Handshake continued/completed (bad for replay attack tests).
	Accepted,
	/// Handshake was rejected with an error (good for replay attack tests).
	Rejected(TightBeamError),
}

/// Boxed future a flow step returns, borrowing the session it runs on.
type FlowFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TightBeamError>> + Send + 'a>>;

/// One message in a handshake flow.
#[derive(Debug, Clone, Copy)]
pub struct FlowStep {
	/// Step number the protocol assigns this message.
	pub index: usize,
	/// Endpoint that sends it.
	pub direction: Direction,
}

/// A handshake flow described as its ordered steps.
///
/// A backend states its step table and how one step advances to the next. The
/// sequence is then written once here, so capture and injection drive the same
/// machine rather than each transcribing the protocol again.
pub trait HandshakeFlow: Send {
	/// Backend this flow belongs to.
	fn backend(&self) -> HandshakeBackendKind;

	/// Ordered steps this protocol exchanges.
	fn steps(&self) -> &'static [FlowStep];

	/// Build the opening message, which no earlier step produces.
	fn open(&mut self) -> FlowFuture<'_, Vec<u8>>;

	/// Hand `msg` to the endpoint that receives step `index`, returning that
	/// endpoint's reply when the flow continues.
	fn advance<'a>(&'a mut self, index: usize, msg: &'a [u8]) -> FlowFuture<'a, Option<Vec<u8>>>;
}

/// Protocol-agnostic handshake operations for security testing.
///
/// Both operations are derived from the flow's step table, so a backend states
/// its sequence once and gets capture and injection from it.
#[allow(dead_code)]
pub trait HandshakeProtocol: Send {
	/// Returns the backend kind for this session.
	fn kind(&self) -> HandshakeBackendKind;

	/// Run a complete handshake, capturing all exchanged messages.
	fn capture_full(&mut self) -> FlowFuture<'_, CapturedHandshake>;

	/// Run handshake up to step N, then inject a different message at step N.
	/// Returns the outcome of the injection attempt.
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

			// Run the flow normally up to the step under attack. The opening
			// message is built only once a step before the target needs it, so
			// injecting at step 0 leaves the client untouched.
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

// ============================================================================
// Server Materials & Profiles
// ============================================================================

// Shared fixtures live in the crate-wide `common` module so threat suites do
// not depend on one another's helpers.
pub use crate::common::security::{
	default_security_profile, expectation_failure, pinning_validator, weak_security_profile, ServerMaterials,
};

#[cfg(feature = "transport-cms")]
use crate::common::security::cms_handshake_pair;

// ============================================================================
// Backend Kind
// ============================================================================

/// Total number of handshake backends exercised by the security harness.
pub const BACKEND_COUNT: usize = 1 + cfg!(feature = "transport-cms") as usize;
/// Same as [`BACKEND_COUNT`] but with a `u32` representation for spec macros.
pub const BACKEND_COUNT_U32: u32 = BACKEND_COUNT as u32;

/// Supported backend identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeBackendKind {
	Ecies,
	#[cfg(feature = "transport-cms")]
	Cms,
}

impl HandshakeBackendKind {
	/// Human-readable backend label (useful for logging/trace events).
	#[allow(dead_code)]
	pub fn label(self) -> &'static str {
		match self {
			Self::Ecies => "ecies",
			#[cfg(feature = "transport-cms")]
			Self::Cms => "cms",
		}
	}

	/// Iterate over all enabled backends.
	pub fn all() -> Vec<Self> {
		let mut kinds = vec![Self::Ecies];
		#[cfg(feature = "transport-cms")]
		{
			kinds.push(Self::Cms);
		}
		kinds
	}
}

// ============================================================================
// Security Threat Harness
// ============================================================================

use tightbeam::trace::TraceCollector;
use tightbeam::utils::urn::Urn;

/// Harness that can spawn handshake sessions across all enabled backends.
///
/// Optionally holds a `TraceCollector` to emit internal (hidden) events during
/// handshake operations, enabling process spec validation of internal state.
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
	pub const HARNESS_SPAWN_SESSION: Urn<'static> = Urn::new("test", "event:security-harness/spawn-session");
	/// Hidden CSP event: ECIES backend selected for the session.
	pub const HARNESS_SPAWN_ECIES: Urn<'static> = Urn::new("test", "event:security-harness/spawn-ecies");
	/// Hidden CSP event: CMS backend selected for the session.
	pub const HARNESS_SPAWN_CMS: Urn<'static> = Urn::new("test", "event:security-harness/spawn-cms");
	/// Hidden CSP event: weak-cipher spawn path entered.
	pub const HARNESS_SPAWN_WEAK: Urn<'static> = Urn::new("test", "event:security-harness/spawn-weak");
	/// Hidden CSP event: weak ECIES backend selected.
	pub const HARNESS_SPAWN_ECIES_WEAK: Urn<'static> = Urn::new("test", "event:security-harness/spawn-ecies-weak");
	/// Hidden CSP event: weak CMS backend selected.
	pub const HARNESS_SPAWN_CMS_WEAK: Urn<'static> = Urn::new("test", "event:security-harness/spawn-cms-weak");

	/// Create a harness with a trace collector for internal event emission.
	pub fn with_trace(trace: Arc<TraceCollector>) -> Self {
		Self { materials: ServerMaterials::generate(), trace: Some(trace) }
	}

	/// Get access to the server materials for test verification.
	pub fn materials(&self) -> &ServerMaterials {
		&self.materials
	}

	/// Emit a hidden event if trace is configured.
	fn emit(&self, event: Urn<'static>) -> Result<(), TightBeamError> {
		if let Some(ref trace) = self.trace {
			trace.event(event)?;
		}
		Ok(())
	}

	/// Spawn a protocol session for the given backend kind with default profiles.
	pub fn spawn(&self, kind: HandshakeBackendKind) -> Box<dyn HandshakeProtocol> {
		let client_profiles = vec![default_security_profile()];
		let server_profiles = vec![default_security_profile()];
		self.spawn_with_profiles(kind, client_profiles, server_profiles)
	}

	/// Spawn a protocol session with specific client and server profiles.
	///
	/// This enables cross-session downgrade attack testing where:
	/// - Client offers certain profiles (client_profiles)
	/// - Server accepts certain profiles (server_profiles)
	pub fn spawn_with_profiles(
		&self,
		kind: HandshakeBackendKind,
		client_profiles: Vec<SecurityProfileDesc>,
		server_profiles: Vec<SecurityProfileDesc>,
	) -> Box<dyn HandshakeProtocol> {
		self.emit(Self::HARNESS_SPAWN_SESSION).ok();
		match kind {
			HandshakeBackendKind::Ecies => {
				self.emit(Self::HARNESS_SPAWN_ECIES).ok();
				Box::new(EciesSession::with_profiles(
					&self.materials,
					client_profiles,
					server_profiles,
					None,
				))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit(Self::HARNESS_SPAWN_CMS).ok();
				Box::new(CmsSession::with_profiles(
					&self.materials,
					client_profiles,
					server_profiles,
					None,
				))
			}
		}
	}

	/// Spawn a session using the WEAK cipher (AES-128-GCM) for downgrade testing.
	///
	/// This uses `Aes128CryptoProvider` which actually uses AES-128 at the cipher level,
	/// not just in the profile descriptor OIDs.
	pub fn spawn_weak(&self, kind: HandshakeBackendKind) -> Box<dyn HandshakeProtocol> {
		self.emit(Self::HARNESS_SPAWN_WEAK).ok();
		match kind {
			HandshakeBackendKind::Ecies => {
				self.emit(Self::HARNESS_SPAWN_ECIES_WEAK).ok();
				// Deliberately weak session: opt out of the default strength
				// floor so the downgrade harness can capture AES-128 wire bytes.
				Box::new(Aes128EciesSession::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
					Some(Arc::new(NoStrengthFloor)),
				))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit(Self::HARNESS_SPAWN_CMS_WEAK).ok();
				// CMS with AES-128 would require Aes128CmsSession - use default for now.
				// Weak profiles fail the default floor, so opt out explicitly.
				Box::new(CmsSession::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
					Some(Arc::new(NoStrengthFloor)),
				))
			}
		}
	}
}

/// Helper to create an error for invalid injection step.
fn invalid_step_error(msg: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "inject_at_step",
		reason: msg,
	}))
}

// ============================================================================
// Message Tampering Helpers (for MITM Testing)
// ============================================================================

/// Tamper with a message payload by flipping bits deep in the trailing content.
///
/// This simulates a MITM attacker modifying message bytes in transit. The
/// tampering targets bytes in the last quarter of the payload, which for a
/// certificate-bearing handshake message lands inside the signature / signed
/// content, ahead of the outer DER tag+length octets at the front.
///
/// # Parameters
/// - `payload`: Original message bytes
///
/// # Returns
/// Modified payload with flipped bits
pub fn tamper_payload(payload: &[u8]) -> Vec<u8> {
	let mut tampered = payload.to_vec();
	if tampered.is_empty() {
		return tampered;
	}

	// Anchor in the final quarter (past the front tag+length header) and flip
	// a short run of content bytes so the DER framing stays intact.
	let anchor = tampered.len().saturating_sub(tampered.len() / 4).min(tampered.len() - 1);
	let positions = [anchor, anchor.saturating_add(1), anchor.saturating_add(2)];

	for pos in positions {
		if pos < tampered.len() {
			tampered[pos] ^= 0xFF;
		}
	}

	tampered
}

/// Tamper with a message by appending extra bytes.
///
/// This simulates a MITM attacker adding data to a message.
#[allow(dead_code)]
pub fn tamper_payload_append(payload: &[u8], extra: &[u8]) -> Vec<u8> {
	let mut tampered = payload.to_vec();
	tampered.extend_from_slice(extra);
	tampered
}

/// Tamper with a message by truncating bytes.
///
/// This simulates a MITM attacker truncating a message.
#[allow(dead_code)]
pub fn tamper_payload_truncate(payload: &[u8], keep_bytes: usize) -> Vec<u8> {
	payload.iter().take(keep_bytes).copied().collect()
}

// ============================================================================
// ECIES Decryption Helpers (for Confidentiality Testing)
// ============================================================================

/// Result of attempting to decrypt an ECIES payload.
#[derive(Debug)]
pub enum DecryptionResult {
	/// Decryption succeeded, plaintext has expected size (64 bytes for session material).
	Success { plaintext_len: usize },
	/// Decryption failed (wrong key, corrupted ciphertext, etc.).
	Failed,
}

/// Extract the ECIES encrypted data from a ClientKeyExchange message.
///
/// # Parameters
/// - `client_kex_der`: DER-encoded ClientKeyExchange message
///
/// # Returns
/// The encrypted ECIES blob bytes
pub fn extract_ecies_ciphertext(client_kex_der: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let client_kex = ClientKeyExchange::from_der(client_kex_der)?;
	Ok(client_kex.encrypted_data.as_bytes().to_vec())
}

/// Extract the ephemeral public key from an ECIES ciphertext.
///
/// The ephemeral public key is the first 33 bytes (compressed secp256k1 point)
/// of the ECIES message.
///
/// # Parameters
/// - `ecies_ciphertext`: The raw ECIES blob
///
/// # Returns
/// The 33-byte ephemeral public key
pub fn extract_ephemeral_pubkey(ecies_ciphertext: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	// ECIES message format: [ephemeral_pubkey (33 bytes) || nonce+ciphertext+tag]
	const EPHEMERAL_PUBKEY_SIZE: usize = 33;

	if ecies_ciphertext.len() < EPHEMERAL_PUBKEY_SIZE {
		return Err(TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
			field: "ephemeral_pubkey",
			reason: "ECIES ciphertext too short",
		})));
	}

	Ok(ecies_ciphertext[..EPHEMERAL_PUBKEY_SIZE].to_vec())
}

/// Default AAD used by the handshake for ECIES encryption.
pub const HANDSHAKE_AAD: &[u8] = b"tb/aead/v1";

/// Attempt to decrypt an ECIES ciphertext using the provided secret key.
///
/// # Parameters
/// - `ciphertext`: The ECIES encrypted blob
/// - `secret_key`: The recipient's secret key
/// - `aad`: Optional AAD (defaults to HANDSHAKE_AAD if None)
///
/// # Returns
/// `DecryptionResult::Success` with plaintext length if decryption worked,
/// `DecryptionResult::Failed` if decryption failed (wrong key, invalid data, etc.)
pub fn try_decrypt_ecies(ciphertext: &[u8], secret_key: &k256::SecretKey, aad: Option<&[u8]>) -> DecryptionResult {
	// Parse the ECIES message
	let message = match Secp256k1EciesMessage::from_bytes(ciphertext) {
		Ok(m) => m,
		Err(_) => return DecryptionResult::Failed,
	};

	// Use provided AAD or default to handshake AAD
	let aad = aad.or(Some(HANDSHAKE_AAD));

	// Attempt decryption
	match ecies::decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(secret_key, &message, aad) {
		Ok(plaintext) => {
			let plaintext_bytes = match plaintext.to_insecure() {
				Ok(b) => b,
				Err(_) => return DecryptionResult::Failed,
			};
			DecryptionResult::Success { plaintext_len: plaintext_bytes.len() }
		}
		Err(_) => DecryptionResult::Failed,
	}
}

/// Generate a random secret key for testing decryption with wrong key.
pub fn generate_wrong_secret_key() -> k256::SecretKey {
	k256::SecretKey::random(&mut rand_core::OsRng)
}

// ============================================================================
// ECIES Session Implementation
// ============================================================================

// ============================================================================
// ECIES Session Implementation
// ============================================================================

/// The three messages an ECIES handshake exchanges.
const ECIES_FLOW: &[FlowStep] = &[
	FlowStep { index: 0, direction: Direction::ClientToServer },
	FlowStep { index: 1, direction: Direction::ServerToClient },
	FlowStep { index: 2, direction: Direction::ClientToServer },
];

/// Declare an ECIES session over one crypto provider.
///
/// The provider bounds cannot be named once on stable, because Rust does not
/// elaborate associated-type bounds from a supertrait. The sequence itself is
/// stated once here instead of once per session.
macro_rules! ecies_session {
	($name:ident, $provider:ty) => {
		pub struct $name {
			client: EciesHandshakeClient<$provider, Secp256k1EciesMessage>,
			server: EciesHandshakeServer<$provider>,
		}

		impl $name {
			/// Create a session with specific client and server profiles.
			///
			/// `strength_policy` overrides the server's default strength floor,
			/// which a deliberately weak downgrade session needs.
			fn with_profiles(
				materials: &ServerMaterials,
				client_profiles: Vec<SecurityProfileDesc>,
				server_profiles: Vec<SecurityProfileDesc>,
				strength_policy: Option<Arc<dyn ProfileStrengthPolicy + Send + Sync>>,
			) -> Self {
				let validator = pinning_validator(&materials.certificate);
				let client = EciesHandshakeClient::<$provider, Secp256k1EciesMessage>::new(None)
					.with_security_offer(SecurityOffer::new(client_profiles))
					.with_certificate_validator(validator);

				let mut server = EciesHandshakeServer::<$provider>::new(
					Arc::clone(&materials.key_provider),
					Arc::clone(&materials.certificate),
					None,
					None,
				)
				.with_supported_profiles(server_profiles);

				if let Some(policy) = strength_policy {
					server = server.with_strength_policy(policy);
				}

				Self { client, server }
			}
		}

		impl HandshakeFlow for $name {
			fn backend(&self) -> HandshakeBackendKind {
				HandshakeBackendKind::Ecies
			}

			fn steps(&self) -> &'static [FlowStep] {
				ECIES_FLOW
			}

			fn open(&mut self) -> FlowFuture<'_, Vec<u8>> {
				Box::pin(async move { Ok(self.client.build_client_hello()?.to_der()?) })
			}

			fn advance<'a>(&'a mut self, index: usize, msg: &'a [u8]) -> FlowFuture<'a, Option<Vec<u8>>> {
				Box::pin(async move {
					match index {
						0 => Ok(Some(self.server.process_client_hello(msg).await?.to_der()?)),
						1 => Ok(Some(self.client.process_server_handshake(msg).await?.to_der()?)),
						2 => {
							self.server.process_client_key_exchange(msg).await?;
							Ok(None)
						}
						_ => Err(invalid_step_error("ECIES has only 3 steps (0-2)")),
					}
				})
			}
		}
	};
}

ecies_session!(EciesSession, DefaultCryptoProvider);
ecies_session!(Aes128EciesSession, Aes128CryptoProvider);

// ============================================================================
// CMS Session Implementation
// ============================================================================

/// CMS handshake session bundle.
#[cfg(feature = "transport-cms")]
pub struct CmsSession {
	client: CmsHandshakeClient<DefaultCryptoProvider>,
	server: CmsHandshakeServer<DefaultCryptoProvider>,
}

#[cfg(feature = "transport-cms")]
impl CmsSession {
	/// Create session with specific client and server profiles.
	///
	/// `strength_policy` overrides the server's default strength floor
	/// (needed for deliberately weak downgrade-testing sessions).
	fn with_profiles(
		materials: &ServerMaterials,
		client_profiles: Vec<SecurityProfileDesc>,
		server_profiles: Vec<SecurityProfileDesc>,
		strength_policy: Option<Arc<dyn ProfileStrengthPolicy + Send + Sync>>,
	) -> Self {
		let pair = cms_handshake_pair(materials, client_profiles, server_profiles, None)
			.expect("CMS pair fixture builds from generated materials");

		let mut server = pair.server;
		if let Some(policy) = strength_policy {
			server = server.with_strength_policy(policy);
		}

		Self { client: pair.client, server }
	}
}

/// The three messages a CMS handshake exchanges. The intervening odd steps are
/// the receiving half of each, so they carry no message of their own.
#[cfg(feature = "transport-cms")]
const CMS_FLOW: &[FlowStep] = &[
	FlowStep { index: 0, direction: Direction::ClientToServer },
	FlowStep { index: 2, direction: Direction::ServerToClient },
	FlowStep { index: 4, direction: Direction::ClientToServer },
];

/// Fixed session key the CMS capture wraps, so a captured flow is reproducible.
#[cfg(feature = "transport-cms")]
const CMS_SESSION_KEY: [u8; 32] = [0xA5; 32];

#[cfg(feature = "transport-cms")]
impl HandshakeFlow for CmsSession {
	fn backend(&self) -> HandshakeBackendKind {
		HandshakeBackendKind::Cms
	}

	fn steps(&self) -> &'static [FlowStep] {
		CMS_FLOW
	}

	fn open(&mut self) -> FlowFuture<'_, Vec<u8>> {
		Box::pin(async move {
			let session_key = tightbeam::ZeroizingBytes::new(CMS_SESSION_KEY.to_vec());
			Ok(self.client.build_key_exchange(session_key, None)?.to_der()?)
		})
	}

	fn advance<'a>(&'a mut self, index: usize, msg: &'a [u8]) -> FlowFuture<'a, Option<Vec<u8>>> {
		Box::pin(async move {
			match index {
				0 => {
					self.server.process_key_exchange(msg).await?;
					Ok(Some(self.server.build_server_finished().await?.to_der()?))
				}
				2 => {
					self.client.process_server_finished(msg)?;
					Ok(Some(self.client.build_client_finished().await?.to_der()?))
				}
				4 => {
					self.server.process_client_finished(msg)?;
					Ok(None)
				}
				_ => Err(invalid_step_error("CMS steps are 0, 2, 4")),
			}
		})
	}
}
