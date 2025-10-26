#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc as ArcAlloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
pub use std::sync::Arc;
#[cfg(not(feature = "std"))]
pub use ArcAlloc as Arc;

mod error;
pub use error::HandshakeError;

use crate::asn1::OctetString;
use crate::crypto::aead::{Aes256Gcm, KeyInit};
use crate::crypto::ecies::encrypt;
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{hkdf, HkdfSha3_256};
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
use crate::crypto::sign::Verifier;
use crate::der::{Decode, Encode, Sequence};
use crate::random::generate_nonce;
use crate::transport::error::TransportError;
use crate::transport::TransportEnvelope;
use crate::Beamable;

#[cfg(feature = "x509")]
use crate::x509::Certificate;

#[cfg(feature = "std")]
use std::time::Instant;

// ============================================================================
// Server key abstraction for handshake (sign + decrypt), hides raw key material
// ============================================================================

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub trait ServerHandshakeKey: Send + Sync {
	/// Sign the server's handshake challenge (server_random)
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError>;

	/// Decrypt ECIES message produced by the client key exchange
	fn decrypt_ecies(
		&self,
		msg: &crate::crypto::ecies::Secp256k1EciesMessage,
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<[u8]>, crate::crypto::ecies::EciesError>;
}

#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl ServerHandshakeKey for crate::crypto::sign::ecdsa::Secp256k1SigningKey {
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError> {
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::crypto::sign::Signer;
		let sig: Secp256k1Signature = self.try_sign(msg).map_err(|_| HandshakeError::SignatureVerificationFailed)?;
		Ok(sig.to_bytes().to_vec())
	}

	fn decrypt_ecies(
		&self,
		msg: &crate::crypto::ecies::Secp256k1EciesMessage,
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<[u8]>, crate::crypto::ecies::EciesError> {
		use crate::crypto::ecies::decrypt;
		let scalar = self.as_nonzero_scalar();
		let sk = k256::SecretKey::from(scalar);
		decrypt(&sk, msg, aad)
	}
}

// ============================================================================
// Handshake State Machine
// ============================================================================
///
/// ```text
/// Client emit(msg) → Check: need handshake?
///                    ├─ Yes → perform_client_handshake()
///                    │         ├─ Send ClientKeyExchange
///                    │         ├─ Receive ServerHandshake
///                    │         ├─ Derive session key
///                    │         └─ Set handshake_state = Complete
///                    └─ No → Send encrypted message
/// ```
/// Handshake state tracking with timeout support
///
/// In `std` environments, uses `Instant` for precise timeout tracking.
/// In `no_std` environments, uses `u64` monotonic counter that must be
/// provided by the user (e.g., from a hardware timer or tick counter).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
	/// No handshake in progress
	#[default]
	None,
	/// Client waiting for server response (with timeout tracking)
	#[cfg(feature = "std")]
	AwaitingServerResponse { initiated_at: Instant },
	/// Client waiting for server response
	#[cfg(not(feature = "std"))]
	AwaitingServerResponse { initiated_at: u64 },
	/// Server waiting for client to send encrypted message (with timeout tracking)
	#[cfg(feature = "std")]
	AwaitingClientFinish { initiated_at: Instant },
	/// Server waiting for client to send encrypted message
	#[cfg(not(feature = "std"))]
	AwaitingClientFinish { initiated_at: u64 },
	/// Handshake complete, ready for encrypted communication
	Complete,
}

// ============================================================================
// Handshake Protocol Abstraction
// ============================================================================

/// Abstraction for different handshake protocols
///
/// This trait allows pluggable handshake implementations:
/// - TightBeam's simplified ECDHE handshake (default)
/// - rustls TLS 1.2/1.3 integration (user-provided)
/// - Custom protocols (user-defined)
///
/// # Examples
///
/// ```ignore
/// // Default TightBeam handshake
/// let handshake = TightBeamHandshake::new_client(server_cert);
/// let transport = TcpTransport::with_handshake(stream, handshake);
///
/// // Or with rustls (user implements)
/// let handshake = RustlsHandshake::new(rustls_config);
/// let transport = TcpTransport::with_handshake(stream, handshake);
/// ```
pub trait HandshakeProtocol: Send {
	/// Session key type (e.g., AES-256-GCM key)
	type SessionKey;

	/// Error type for handshake operations
	type Error: Into<TransportError>;

	/// Initiate handshake as client
	/// Returns client handshake message to send over wire
	#[allow(async_fn_in_trait)]
	async fn initiate_client(&mut self) -> Result<Vec<u8>, Self::Error>;

	/// Process server's handshake response as client
	/// Returns derived session key
	#[allow(async_fn_in_trait)]
	async fn process_server_response(&mut self, response: &[u8]) -> Result<Self::SessionKey, Self::Error>;

	/// Handle client handshake request as server
	/// Returns server handshake message to send back
	#[allow(async_fn_in_trait)]
	async fn handle_client_request(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;

	/// Complete server handshake and derive session key
	#[allow(async_fn_in_trait)]
	async fn complete_server_handshake(&mut self) -> Result<Self::SessionKey, Self::Error>;
}

// ============================================================================
// TLS-like ECIES + Server Randomness Protocol Structures
// ============================================================================

/// ClientHello - Client initiates handshake
///
/// The client sends its random nonce to begin the handshake. The server
/// must include this in its response to prove it's not replaying old messages.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	/// Client random nonce (32 bytes) for mutual randomness contribution
	/// Also provides replay protection
	pub client_random: OctetString,
}

/// ServerHandshake - Server responds with certificate and randomness challenge
///
/// The server sends its certificate, server randomness, and a signature proving
/// it owns the certificate private key and received the client's ClientHello.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerHandshake {
	/// Server's X.509 certificate for authentication
	#[cfg(feature = "x509")]
	pub certificate: Certificate,
	/// Server random nonce (32 bytes) for mutual randomness contribution
	pub server_random: OctetString,
	/// Digital signature over (client_random || server_random)
	/// Proves server owns the certificate private key and received ClientHello
	pub signature: OctetString,
}

/// ClientKeyExchange - Client sends ECIES-encrypted session key material
///
/// The client generates a base session key and client randomness, then
/// encrypts both using ECIES with the server's certificate public key.
/// This provides forward secrecy (ECIES ephemeral keys) and authenticated
/// encryption (AES-256-GCM within ECIES).
///
/// After this message, both client and server derive the final session key
/// and begin encrypted communication. No explicit confirmation message is needed -
/// successful decryption of subsequent messages proves handshake success.
/// If decryption fails, circuit breakers trip and handshake restarts.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	/// ECIES-encrypted payload: (base_session_key || client_random)
	/// Format: ephemeral_pubkey (33) || nonce (12) || ciphertext (64) || tag (16)
	/// Total: 125 bytes for 32-byte base_key + 32-byte client_random
	pub encrypted_data: OctetString,
}

// ============================================================================
// TightBeam Default Handshake Implementation
// ============================================================================

/// Helper for encoding transport envelopes with error conversion
fn encode_envelope(envelope: TransportEnvelope) -> Result<Vec<u8>, TransportError> {
	envelope.to_der().map_err(TransportError::DerError)
}

/// Helper for decoding transport envelopes with error conversion
fn decode_envelope(bytes: &[u8]) -> Result<TransportEnvelope, TransportError> {
	TransportEnvelope::from_der(bytes).map_err(TransportError::DerError)
}

/// Helper for generating random nonces with error conversion
fn generate_random_nonce() -> Result<[u8; 32], HandshakeError> {
	generate_nonce::<32>(None).map_err(HandshakeError::from)
}

/// Helper for converting octet strings to fixed-size arrays
fn octet_string_to_array<const N: usize>(
	octet_string: &OctetString,
	error_msg: &str,
) -> Result<[u8; N], HandshakeError> {
	octet_string
		.as_bytes()
		.try_into()
		.map_err(|_| HandshakeError::ProtocolError(error_msg.into()))
}

/// Helper for validating handshake role
fn ensure_client_role(role: HandshakeRole) -> Result<(), HandshakeError> {
	if role != HandshakeRole::Client {
		return Err(HandshakeError::InvalidState);
	}
	Ok(())
}

/// Helper for validating handshake role
fn ensure_server_role(role: HandshakeRole) -> Result<(), HandshakeError> {
	if role != HandshakeRole::Server {
		return Err(HandshakeError::InvalidState);
	}
	Ok(())
}

/// Compute transcript hash H(client_random || server_random || SPKI)
fn compute_transcript_hash(client_random: &[u8; 32], server_random: &[u8; 32], spki_bytes: &[u8]) -> [u8; 32] {
	let mut data = Vec::with_capacity(32 + 32 + spki_bytes.len());
	data.extend_from_slice(client_random);
	data.extend_from_slice(server_random);
	data.extend_from_slice(spki_bytes);
	let digest_arr = Sha3_256::digest(&data);
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&digest_arr);
	digest
}

/// Verify server's signature over the transcript hash
fn verify_server_signature(
	verifying_key: &Secp256k1VerifyingKey,
	digest: &[u8; 32],
	signature_bytes: &[u8],
) -> Result<(), HandshakeError> {
	let signature =
		Secp256k1Signature::try_from(signature_bytes).map_err(|_| HandshakeError::SignatureVerificationFailed)?;
	verifying_key
		.verify(digest, &signature)
		.map_err(|_| HandshakeError::SignatureVerificationFailed)
}

/// Perform ECIES encryption of base_key || client_random using server's certificate
fn perform_ecies_encryption(
	base_key: &[u8; 32],
	client_random: &[u8; 32],
	server_certificate: &Certificate,
	aad_domain_tag: Option<&[u8]>,
) -> Result<Vec<u8>, HandshakeError> {
	// Concatenate base_key || client_random for ECIES encryption
	let mut plaintext = [0u8; 64];
	plaintext[..32].copy_from_slice(base_key);
	plaintext[32..].copy_from_slice(client_random);

	// Encrypt using ECIES with server's certificate public key
	let server_pubkey = k256::PublicKey::from_sec1_bytes(
		server_certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes(),
	)
	.map_err(HandshakeError::from)?;

	let encrypted_message = encrypt::<_, _, _, crate::crypto::ecies::Secp256k1EciesMessage>(
		&server_pubkey,
		&plaintext,
		aad_domain_tag,
		Some(&mut rand_core::OsRng),
	)
	.map_err(|_| HandshakeError::ProtocolError("ECIES encryption failed".into()))?;

	// Serialize ECIES message
	Ok(encrypted_message.to_bytes())
}

/// TightBeam's ECIES + Server Randomness handshake protocol
///
/// Protocol flow:
/// 1. Client sends: ClientHello(client_random)
/// 2. Server sends: ServerHandshake(certificate, server_random, signature)
/// 3. Client sends: ClientKeyExchange(ECIES encrypted: base_key || client_random)
/// 4. Both derive: final_key = HKDF(base_key, salt: client_random || server_random)
/// 5. Encrypted communication begins (no explicit confirmation needed)
///
/// Security properties:
/// - Forward secrecy from ECIES ephemeral keys
/// - Mutual randomness contribution (both parties contribute entropy)
/// - Non-malleability from ECIES KDF (includes ephemeral pubkey)
/// - Authentication from signatures and ECIES AES-GCM
/// - Circuit breaker: if decryption fails, handshake restarts
pub struct TightBeamHandshake {
	role: HandshakeRole,
	// Client state
	client_random: Option<[u8; 32]>,
	base_session_key: Option<[u8; 32]>,
	// Server state
	server_random: Option<[u8; 32]>,
	server_cert: Option<Certificate>,
	server_key: Option<Arc<dyn ServerHandshakeKey>>,
	// Optional AAD/domain tag to bind context
	aad_domain_tag: Option<Vec<u8>>,
	// Server's certificate public key (extracted on client side)
	server_verifying_key: Option<Secp256k1VerifyingKey>,
	// Pending ClientKeyExchange bytes to send (client only)
	pending_client_kex: Option<Vec<u8>>,
	// Transcript binder: H(client_random || server_random || SPKI)
	transcript_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeRole {
	Client,
	Server,
}

impl TightBeamHandshake {
	/// Create new client-side handshake
	pub fn new_client() -> Self {
		Self {
			role: HandshakeRole::Client,
			client_random: None,
			base_session_key: None,
			server_random: None,
			server_cert: None,
			server_key: None,
			aad_domain_tag: Some(b"tb-v1".to_vec()),
			server_verifying_key: None,
			pending_client_kex: None,
			transcript_hash: None,
		}
	}

	/// Create new server-side handshake with certificate, signatory, and optional AAD domain tag
	pub fn new_server(
		certificate: Certificate,
		server_key: Arc<dyn ServerHandshakeKey>,
		aad_domain_tag: Option<Vec<u8>>,
	) -> Self {
		Self {
			role: HandshakeRole::Server,
			client_random: None,
			base_session_key: None,
			server_random: None,
			server_cert: Some(certificate),
			server_key: Some(server_key),
			aad_domain_tag,
			server_verifying_key: None,
			pending_client_kex: None,
			transcript_hash: None,
		}
	}

	/// Derive final session key from base key and both randoms
	/// final_key = HKDF(base_key, salt: client_random || server_random, info: "tightbeam-session-v1")
	fn derive_final_session_key(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		server_random: &[u8; 32],
	) -> Result<Aes256Gcm, HandshakeError> {
		// Concatenate client_random || server_random for salt
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		// Derive final key using HKDF
		let final_key_bytes = hkdf::<HkdfSha3_256, 32>(base_key, b"tightbeam-session-v1", Some(&salt))?;

		// Create AES-256-GCM cipher from derived key
		Aes256Gcm::new_from_slice(&final_key_bytes[..]).map_err(HandshakeError::from)
	}
	fn extract_verifying_key(cert: &Certificate) -> Result<Secp256k1VerifyingKey, HandshakeError> {
		let spki = &cert.tbs_certificate.subject_public_key_info;
		let public_key_bytes = spki.subject_public_key.raw_bytes();
		let public_key = k256::PublicKey::from_sec1_bytes(public_key_bytes)?;
		Ok(Secp256k1VerifyingKey::from(public_key))
	}
}

impl HandshakeProtocol for TightBeamHandshake {
	type SessionKey = Aes256Gcm;
	type Error = TransportError;

	async fn initiate_client(&mut self) -> Result<Vec<u8>, Self::Error> {
		// Client initiates handshake by sending ClientHello with client_random
		ensure_client_role(self.role)?;

		// Generate client random
		let client_random = generate_random_nonce()?;
		self.client_random = Some(client_random); // Create ClientHello
		let client_hello = ClientHello { client_random: OctetString::new(&client_random)? };

		// Encode as TransportEnvelope
		let envelope = TransportEnvelope::ClientHello(client_hello);
		encode_envelope(envelope)
	}

	async fn process_server_response(&mut self, response: &[u8]) -> Result<Self::SessionKey, Self::Error> {
		ensure_client_role(self.role)?;

		// Parse ServerHandshake
		let envelope = decode_envelope(response)?;
		let server_handshake = match envelope {
			TransportEnvelope::ServerHandshake(handshake) => handshake,
			_ => return Err(HandshakeError::InvalidServerKeyExchange.into()),
		};

		// Extract server_random
		let server_random: [u8; 32] =
			octet_string_to_array(&server_handshake.server_random, "Invalid server_random size")?;

		self.server_random = Some(server_random);

		// Extract and verify server's certificate public key
		let verifying_key = Self::extract_verifying_key(&server_handshake.certificate)?;
		self.server_verifying_key = Some(verifying_key.clone());

		// Verify signature over H(client_random || server_random || SPKI)
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;
		let spki_bytes = server_handshake
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		// Compute transcript hash H(client_random || server_random || SPKI)
		let digest = compute_transcript_hash(&client_random, &server_random, spki_bytes);
		// Record transcript hash for channel binding AAD
		self.transcript_hash = Some(digest);

		verify_server_signature(&verifying_key, &digest, server_handshake.signature.as_bytes())?;

		// Generate base session key
		let base_key = generate_random_nonce()?;

		// Reuse client_random from initiate_client() (sent in ClientHello)
		// This provides replay protection - server can verify it matches
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;

		self.base_session_key = Some(base_key);

		// Perform ECIES encryption of base_key || client_random using server's certificate
		let encrypted_bytes = perform_ecies_encryption(
			&base_key,
			&client_random,
			&server_handshake.certificate,
			self.aad_domain_tag.as_deref(),
		)?;

		// Create ClientKeyExchange
		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes).map_err(|_| HandshakeError::InvalidClientKeyExchange)?,
		};

		// Encode and store for transport layer to send
		let envelope = TransportEnvelope::ClientKeyExchange(client_kex);
		self.pending_client_kex = Some(encode_envelope(envelope)?);

		// Derive final session key (we'll use it after receiving ServerHandshake confirmation)
		self.derive_final_session_key(&base_key, &client_random, &server_random)
			.map_err(Into::into)
	}

	async fn handle_client_request(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
		ensure_server_role(self.role)?;

		// Parse the request to see what it is
		let envelope = decode_envelope(request)?;
		match envelope {
			// First message: ClientHello
			TransportEnvelope::ClientHello(client_hello) => self.handle_client_hello(client_hello),

			// Second message: ClientKeyExchange
			TransportEnvelope::ClientKeyExchange(client_kex) => {
				// Parse ECIES message from encrypted_data
				let encrypted_bytes = client_kex.encrypted_data.as_bytes();
				let encrypted_message = crate::crypto::ecies::Secp256k1EciesMessage::from_bytes(encrypted_bytes)
					.map_err(|_| HandshakeError::ProtocolError("Invalid ECIES message".into()))?;

				// Decrypt using configured server key
				let server_key = self
					.server_key
					.as_ref()
					.ok_or_else(|| HandshakeError::ProtocolError("No server key".into()))?;
				let decrypted = server_key
					.decrypt_ecies(&encrypted_message, self.aad_domain_tag.as_deref())
					.map_err(|_| HandshakeError::ProtocolError("ECIES decryption failed".into()))?;

				// Consume the secret to get the raw bytes for parsing
				let decrypted = decrypted.to_insecure();

				// Extract base_key and client_random
				if decrypted.len() != 64 {
					return Err(HandshakeError::ProtocolError("Invalid decrypted payload size".into()).into());
				}

				let mut base_key = [0u8; 32];
				let mut client_random = [0u8; 32];
				base_key.copy_from_slice(&decrypted[..32]);
				client_random.copy_from_slice(&decrypted[32..]);

				// Verify client_random matches the one from ClientHello (replay protection)
				let expected_client_random = self
					.client_random
					.ok_or_else(|| HandshakeError::ProtocolError("No client_random from ClientHello".into()))?;

				if client_random != expected_client_random {
					return Err(HandshakeError::ProtocolError(
						"client_random mismatch - possible replay attack".into(),
					)
					.into());
				}

				self.base_session_key = Some(base_key);
				// client_random already set from ClientHello, no need to overwrite

				// Handshake complete - no explicit confirmation needed
				// Both sides now derive session key and begin encrypted communication
				// If decryption fails, circuit breaker trips and handshake restarts
				Ok(Vec::new()) // Return empty response - handshake is done
			}

			_ => Err(HandshakeError::InvalidClientKeyExchange.into()),
		}
	}

	async fn complete_server_handshake(&mut self) -> Result<Self::SessionKey, Self::Error> {
		ensure_server_role(self.role)?; // Derive final session key
		let base_key = self
			.base_session_key
			.as_ref()
			.ok_or_else(|| HandshakeError::ProtocolError("No base session key".into()))?;
		let client_random = self
			.client_random
			.as_ref()
			.ok_or_else(|| HandshakeError::ProtocolError("No client random".into()))?;
		let server_random = self
			.server_random
			.as_ref()
			.ok_or_else(|| HandshakeError::ProtocolError("No server random".into()))?;

		let final_key: Aes256Gcm = self
			.derive_final_session_key(base_key, client_random, server_random)
			.map_err(|e| TransportError::from(e))?;

		// Zeroize sensitive material after deriving key
		if let Some(mut bk) = self.base_session_key.take() {
			bk.fill(0);
		}
		if let Some(mut cr) = self.client_random.take() {
			cr.fill(0);
		}
		if let Some(mut sr) = self.server_random.take() {
			sr.fill(0);
		}

		Ok(final_key)
	}
}

impl TightBeamHandshake {
	/// Take the pending ClientKeyExchange bytes (consumes them)
	/// This is used by the transport layer after calling process_server_response()
	pub fn take_client_key_exchange(&mut self) -> Option<Vec<u8>> {
		self.pending_client_kex.take()
	}

	/// Get the transcript hash H(client_random || server_random || SPKI) if available
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.transcript_hash
	}

	/// Handle ClientHello message from client
	fn handle_client_hello(&mut self, client_hello: ClientHello) -> Result<Vec<u8>, TransportError> {
		// Extract client_random
		let client_random: [u8; 32] = octet_string_to_array(&client_hello.client_random, "Invalid client_random size")?;

		self.client_random = Some(client_random);

		// Generate server random
		let server_random = generate_random_nonce()?;
		self.server_random = Some(server_random);

		// Sign H(client_random || server_random || SPKI) using configured server key
		let server_key = self
			.server_key
			.as_ref()
			.ok_or_else(|| HandshakeError::ProtocolError("No server key".into()))?;

		// Compute digest H(client_random || server_random || SPKI)
		let spki_bytes = self
			.server_cert
			.as_ref()
			.ok_or_else(|| HandshakeError::InvalidCertificate)?
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let digest = compute_transcript_hash(&client_random, &server_random, spki_bytes);
		// Record transcript hash for channel binding AAD
		self.transcript_hash = Some(digest);

		let sig_bytes = server_key
			.sign_server_challenge(&digest)
			.map_err(|_| HandshakeError::SignatureVerificationFailed)?;
		let signature = Secp256k1Signature::try_from(sig_bytes.as_slice())
			.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

		// Create ServerHandshake
		let server_handshake = ServerHandshake {
			certificate: self.server_cert.clone().ok_or_else(|| HandshakeError::InvalidCertificate)?,
			server_random: OctetString::new(&server_random).map_err(|_| HandshakeError::InvalidServerKeyExchange)?,
			signature: OctetString::new(signature.to_bytes().as_slice())
				.map_err(|_| HandshakeError::SignatureVerificationFailed)?,
		};

		// Encode as TransportEnvelope
		let envelope = TransportEnvelope::ServerHandshake(server_handshake);
		encode_envelope(envelope)
	}
}
