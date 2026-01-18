//! Common helpers and fixtures for security threat integration tests.
//!
//! This module provides a protocol-agnostic abstraction for testing security threats
//! across multiple handshake backends (ECIES, CMS) without code duplication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::{
	crypto::{
		aead::{Aes128Gcm, Aes128GcmOid},
		curves::Secp256k1Oid,
		ecies::{self, Secp256k1EciesMessage},
		hash::Sha3_256,
		kdf::{HkdfSha3_256, HkdfSha3_256Oid},
		kem::Kyber1024Oid,
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		profiles::{
			AeadProvider, CryptoProvider, CurveProvider, DefaultCryptoProvider, DigestProvider, KdfProvider,
			SecurityProfile, SecurityProfileDesc, SigningProvider, TightbeamProfile,
		},
		secret::ToInsecure,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey},
	},
	der::Decode,
	oids::{AES_128_GCM, AES_128_WRAP, AES_256_GCM, CURVE_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256},
	testing::{
		error::{FdrConfigError, TestingError},
		utils::{create_test_certificate, create_test_signing_key},
	},
	transport::handshake::{
		client::EciesHandshakeClient, negotiation::SecurityOffer, server::EciesHandshakeServer, ClientKeyExchange,
	},
	TightBeamError,
};

#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{client::CmsHandshakeClient, server::CmsHandshakeServer};

use tightbeam::x509::Certificate;

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
	pub step: usize,
	pub direction: Direction,
	pub payload: Vec<u8>,
}

/// Result of running a full handshake with capture.
#[derive(Debug, Clone)]
pub struct CapturedHandshake {
	pub messages: Vec<CapturedMessage>,
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

/// Protocol-agnostic handshake operations for security testing.
///
/// This trait abstracts the differences between ECIES and CMS handshake flows,
/// allowing tests to work with any backend without code duplication.
#[allow(dead_code)]
pub trait HandshakeProtocol: Send {
	/// Returns the backend kind for this session.
	fn kind(&self) -> HandshakeBackendKind;

	/// Run a complete handshake, capturing all exchanged messages.
	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>>;

	/// Run handshake up to step N, then inject a different message at step N.
	/// Returns the outcome of the injection attempt.
	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>>;
}

// ============================================================================
// Server Materials
// ============================================================================

/// Generated server-side credentials for handshake orchestration.
#[derive(Clone)]
pub struct ServerMaterials {
	pub certificate: Arc<Certificate>,
	pub key_provider: Arc<dyn SigningKeyProvider>,
	/// Secret key for test verification (ECIES decryption).
	/// Stored as Arc to allow Clone without copying secret material.
	secret_key: Arc<k256::SecretKey>,
}

impl ServerMaterials {
	pub fn generate() -> Self {
		let signing_key = create_test_signing_key();
		let certificate = Arc::new(create_test_certificate(&signing_key));

		// Convert signing key to secret key for ECIES operations
		// The signing key scalar is the same as the secret key scalar
		let secret_key_bytes = signing_key.to_bytes();
		let secret_key = k256::SecretKey::from_bytes(&secret_key_bytes).expect("valid secret key");

		let server_key = Secp256k1SigningKey::from(signing_key);
		let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(server_key));
		Self { certificate, key_provider: provider, secret_key: Arc::new(secret_key) }
	}

	/// Get the secret key for ECIES decryption (test verification only).
	pub fn secret_key(&self) -> &k256::SecretKey {
		&self.secret_key
	}
}

/// Default profile descriptor reused across threats.
pub fn default_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&TightbeamProfile)
}

/// Strong security profile (AES-256-GCM) for downgrade attack testing.
#[allow(dead_code)]
pub fn strong_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: HASH_SHA3_256,
		aead: Some(AES_256_GCM),
		aead_key_size: Some(32), // 256-bit key
		signature: Some(SIGNER_ECDSA_WITH_SHA3_256),
		kdf: Some(HASH_SHA3_256),
		curve: Some(CURVE_SECP256K1),
		key_wrap: None,
		kem: None,
	}
}

/// Weak security profile (AES-128-GCM) for downgrade attack testing.
pub fn weak_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: HASH_SHA3_256,
		aead: Some(AES_128_GCM),
		aead_key_size: Some(16), // 128-bit key (weaker)
		signature: Some(SIGNER_ECDSA_WITH_SHA3_256),
		kdf: Some(HASH_SHA3_256),
		curve: Some(CURVE_SECP256K1),
		key_wrap: None,
		kem: None,
	}
}

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
	/// Create a harness with a trace collector for internal event emission.
	pub fn with_trace(trace: Arc<TraceCollector>) -> Self {
		Self { materials: ServerMaterials::generate(), trace: Some(trace) }
	}

	/// Get access to the server materials for test verification.
	pub fn materials(&self) -> &ServerMaterials {
		&self.materials
	}

	/// Emit a hidden event if trace is configured.
	fn emit(&self, event: &'static str) -> Result<(), TightBeamError> {
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
		self.emit("harness_spawn_session").ok();
		match kind {
			HandshakeBackendKind::Ecies => {
				self.emit("harness_spawn_ecies").ok();
				Box::new(EciesSession::with_profiles(&self.materials, client_profiles, server_profiles))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit("harness_spawn_cms").ok();
				Box::new(CmsSession::with_profiles(&self.materials, client_profiles, server_profiles))
			}
		}
	}

	/// Spawn a session using the WEAK cipher (AES-128-GCM) for downgrade testing.
	///
	/// This uses `Aes128CryptoProvider` which actually uses AES-128 at the cipher level,
	/// not just in the profile descriptor OIDs.
	pub fn spawn_weak(&self, kind: HandshakeBackendKind) -> Box<dyn HandshakeProtocol> {
		self.emit("harness_spawn_weak").ok();
		match kind {
			HandshakeBackendKind::Ecies => {
				self.emit("harness_spawn_ecies_weak").ok();
				Box::new(Aes128EciesSession::new(&self.materials))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit("harness_spawn_cms_weak").ok();
				// CMS with AES-128 would require Aes128CmsSession - use default for now
				Box::new(CmsSession::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
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

/// Tamper with a message payload by flipping bits at strategic positions.
///
/// This simulates a MITM attacker modifying message bytes in transit.
/// The tampering is designed to:
/// 1. Preserve DER structure validity (where possible)
/// 2. Cause transcript hash mismatch
/// 3. Invalidate signatures over the original content
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

	// Flip bits in the middle of the payload to avoid DER header corruption
	// This targets the actual content rather than structural bytes
	let mid = tampered.len() / 2;
	let positions = [mid, mid.saturating_add(1), mid.saturating_add(2)];

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
	match ecies::decrypt(secret_key, &message, aad) {
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

/// ECIES handshake session bundle.
pub struct EciesSession {
	client: EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage>,
	server: EciesHandshakeServer<DefaultCryptoProvider>,
}

impl EciesSession {
	/// Create session with specific client and server profiles.
	fn with_profiles(
		materials: &ServerMaterials,
		client_profiles: Vec<SecurityProfileDesc>,
		server_profiles: Vec<SecurityProfileDesc>,
	) -> Self {
		let client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
			.with_security_offer(SecurityOffer::new(client_profiles));

		let server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
			Arc::clone(&materials.key_provider),
			Arc::clone(&materials.certificate),
			None,
			None,
		)
		.with_supported_profiles(server_profiles);

		Self { client, server }
	}
}

impl HandshakeProtocol for EciesSession {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeBackendKind::Ecies
	}

	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>> {
		Box::pin(async move {
			let mut messages = Vec::new();

			// Step 0: Client Hello (C -> S)
			let client_hello = self.client.build_client_hello()?;
			messages.push(CapturedMessage {
				step: 0,
				direction: Direction::ClientToServer,
				payload: client_hello.clone(),
			});

			// Step 1: Server Handshake (S -> C)
			let server_handshake = self.server.process_client_hello(&client_hello).await?;
			messages.push(CapturedMessage {
				step: 1,
				direction: Direction::ServerToClient,
				payload: server_handshake.clone(),
			});

			// Step 2: Client Key Exchange (C -> S)
			let client_kex = self.client.process_server_handshake(&server_handshake).await?;
			messages.push(CapturedMessage {
				step: 2,
				direction: Direction::ClientToServer,
				payload: client_kex.clone(),
			});

			// Step 3: Server processes KEX (no message, but completes handshake)
			self.server.process_client_key_exchange(&client_kex).await?;

			// Complete both sides
			let _ = self.client.complete()?;
			let _ = self.server.complete()?;

			Ok(CapturedHandshake { messages, kind: HandshakeBackendKind::Ecies })
		})
	}

	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>> {
		let msg = msg.to_vec();
		Box::pin(async move {
			// Run handshake up to the injection point, then inject the message
			match step {
				0 => {
					// Inject at ClientHello - process injected message as client hello
					match self.server.process_client_hello(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				1 => {
					// Run step 0 normally, then inject at ServerHandshake
					let client_hello = self.client.build_client_hello()?;
					let _ = self.server.process_client_hello(&client_hello).await?;
					// Now inject the message as server handshake response
					match self.client.process_server_handshake(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				2 => {
					// Run steps 0-1 normally, then inject at ClientKeyExchange
					let client_hello = self.client.build_client_hello()?;
					let server_handshake = self.server.process_client_hello(&client_hello).await?;
					let _ = self.client.process_server_handshake(&server_handshake).await?;
					// Now inject the message as client key exchange
					match self.server.process_client_key_exchange(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				_ => Err(invalid_step_error("ECIES has only 3 injectable steps (0-2)")),
			}
		})
	}
}

// ============================================================================
// AES-128 ECIES Session (for Downgrade Testing)
// ============================================================================

/// ECIES handshake session using AES-128-GCM (weaker cipher).
pub struct Aes128EciesSession {
	client: EciesHandshakeClient<Aes128CryptoProvider, Secp256k1EciesMessage>,
	server: EciesHandshakeServer<Aes128CryptoProvider>,
}

impl Aes128EciesSession {
	/// Create session with the weak AES-128 profile.
	fn new(materials: &ServerMaterials) -> Self {
		let weak_profile = weak_security_profile();

		let client = EciesHandshakeClient::<Aes128CryptoProvider, Secp256k1EciesMessage>::new(None)
			.with_security_offer(SecurityOffer::new(vec![weak_profile]));

		let server = EciesHandshakeServer::<Aes128CryptoProvider>::new(
			Arc::clone(&materials.key_provider),
			Arc::clone(&materials.certificate),
			None,
			None,
		)
		.with_supported_profiles(vec![weak_profile]);

		Self { client, server }
	}
}

impl HandshakeProtocol for Aes128EciesSession {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeBackendKind::Ecies
	}

	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>> {
		Box::pin(async move {
			let mut messages = Vec::new();

			// Step 0: Client Hello (C -> S)
			let client_hello = self.client.build_client_hello()?;
			messages.push(CapturedMessage {
				step: 0,
				direction: Direction::ClientToServer,
				payload: client_hello.clone(),
			});

			// Step 1: Server Handshake (S -> C)
			let server_handshake = self.server.process_client_hello(&client_hello).await?;
			messages.push(CapturedMessage {
				step: 1,
				direction: Direction::ServerToClient,
				payload: server_handshake.clone(),
			});

			// Step 2: Client Key Exchange (C -> S)
			let client_kex = self.client.process_server_handshake(&server_handshake).await?;
			messages.push(CapturedMessage {
				step: 2,
				direction: Direction::ClientToServer,
				payload: client_kex.clone(),
			});

			// Step 3: Server processes KEX (completes handshake)
			self.server.process_client_key_exchange(&client_kex).await?;

			// Complete both sides
			let _ = self.client.complete()?;
			let _ = self.server.complete()?;

			Ok(CapturedHandshake { messages, kind: HandshakeBackendKind::Ecies })
		})
	}

	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>> {
		let msg = msg.to_vec();
		Box::pin(async move {
			match step {
				0 => match self.server.process_client_hello(&msg).await {
					Ok(_) => Ok(InjectionOutcome::Accepted),
					Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
				},
				1 => {
					let client_hello = self.client.build_client_hello()?;
					let _ = self.server.process_client_hello(&client_hello).await?;
					match self.client.process_server_handshake(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				2 => {
					let client_hello = self.client.build_client_hello()?;
					let server_handshake = self.server.process_client_hello(&client_hello).await?;
					let _ = self.client.process_server_handshake(&server_handshake).await?;
					match self.server.process_client_key_exchange(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				_ => Err(invalid_step_error("ECIES has only 3 injectable steps (0-2)")),
			}
		})
	}
}

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
	fn with_profiles(
		materials: &ServerMaterials,
		client_profiles: Vec<SecurityProfileDesc>,
		server_profiles: Vec<SecurityProfileDesc>,
	) -> Self {
		// Create client credentials
		let client_key = create_test_signing_key();
		let client_cert = Arc::new(create_test_certificate(&client_key));
		let client_key = Secp256k1SigningKey::from(client_key);
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(client_key));

		// Use internal transcript computation for proper replay detection
		let client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			client_provider,
			Arc::clone(&materials.certificate),
		)
		.with_security_offer(SecurityOffer::new(client_profiles));

		let server_key_provider = Arc::clone(&materials.key_provider);
		let mut server = CmsHandshakeServer::<DefaultCryptoProvider>::new(server_key_provider, None)
			.with_supported_profiles(server_profiles);

		// Set client certificate on server for mutual auth
		server.set_client_certificate((*client_cert).clone()).ok();

		Self { client, server }
	}
}

#[cfg(feature = "transport-cms")]
impl HandshakeProtocol for CmsSession {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeBackendKind::Cms
	}

	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>> {
		Box::pin(async move {
			let mut messages = Vec::new();
			let session_key = vec![0xA5; 32];

			// Step 0: Key Exchange (C -> S)
			let key_exchange = self.client.build_key_exchange(session_key)?;
			messages.push(CapturedMessage {
				step: 0,
				direction: Direction::ClientToServer,
				payload: key_exchange.clone(),
			});

			// Step 1: Server processes KEX (internal)
			self.server.process_key_exchange(&key_exchange).await?;

			// Step 2: Server Finished (S -> C)
			let server_finished = self.server.build_server_finished().await?;
			messages.push(CapturedMessage {
				step: 2,
				direction: Direction::ServerToClient,
				payload: server_finished.clone(),
			});

			// Step 3: Client processes Server Finished (internal)
			self.client.process_server_finished(&server_finished)?;

			// Step 4: Client Finished (C -> S)
			let client_finished = self.client.build_client_finished().await?;
			messages.push(CapturedMessage {
				step: 4,
				direction: Direction::ClientToServer,
				payload: client_finished.clone(),
			});

			// Step 5: Server processes Client Finished
			self.server.process_client_finished(&client_finished)?;

			// Complete both sides
			self.client.complete()?;
			self.server.complete()?;

			Ok(CapturedHandshake { messages, kind: HandshakeBackendKind::Cms })
		})
	}

	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>> {
		let msg = msg.to_vec();
		Box::pin(async move {
			let session_key = vec![0xA5; 32];

			match step {
				0 => {
					// Inject at KeyExchange
					match self.server.process_key_exchange(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				2 => {
					// Run step 0-1 normally, then inject at ServerFinished
					let key_exchange = self.client.build_key_exchange(session_key)?;
					self.server.process_key_exchange(&key_exchange).await?;
					// Now inject the message as server finished
					match self.client.process_server_finished(&msg) {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				4 => {
					// Run steps 0-3 normally, then inject at ClientFinished
					let key_exchange = self.client.build_key_exchange(session_key)?;
					self.server.process_key_exchange(&key_exchange).await?;
					let server_finished = self.server.build_server_finished().await?;
					self.client.process_server_finished(&server_finished)?;
					// Now inject the message as client finished
					match self.server.process_client_finished(&msg) {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				_ => Err(invalid_step_error("CMS injectable steps are 0, 2, 4")),
			}
		})
	}
}
