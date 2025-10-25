#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

mod error;
pub use error::HandshakeError;

use crate::asn1::{ObjectIdentifier, OctetString};
use crate::der::Sequence;
use crate::transport::error::TransportError;
use crate::Beamable;

#[cfg(feature = "x509")]
use crate::x509::Certificate;

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
// TLS 1.2 Inspired Structures (RFC 5246, RFC 5480)
// ============================================================================

/// ServerECDHParams - Elliptic Curve Diffie-Hellman parameters sent by server
/// Per RFC 5246 Section 7.4.3 and RFC 5480 for EC parameters
#[derive(Sequence, Debug, Clone, PartialEq)]
pub struct ServerECDHParams {
	/// Named curve OID (e.g., secp256k1)
	pub curve: ObjectIdentifier,
	/// Uncompressed EC point (server's public key)
	/// Format: 0x04 || x || y (65 bytes for secp256k1)
	pub public: OctetString,
}

/// ClientECDHParams - Client's Elliptic Curve Diffie-Hellman public key
/// Per RFC 5246 Section 7.4.7
#[derive(Sequence, Debug, Clone, PartialEq)]
pub struct ClientECDHParams {
	/// Uncompressed EC point (client's public key)
	/// Format: 0x04 || x || y (65 bytes for secp256k1)
	pub public: OctetString,
}

/// ClientKeyExchange message for ECDHE key exchange
/// TLS-inspired but simplified for TightBeam protocol
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	/// Client's ECDH public key
	pub params: ClientECDHParams,
	/// Client random nonce (32 bytes) for replay protection
	/// Follows TLS client_random pattern
	pub random: OctetString,
}

/// ServerKeyExchange message for ECDHE key exchange
/// TLS-inspired but simplified for TightBeam protocol
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerKeyExchange {
	/// ECDH parameters (curve + server public key)
	pub params: ServerECDHParams,
	/// Server random nonce (32 bytes) for replay protection
	/// Follows TLS server_random pattern
	pub random: OctetString,
	/// Server's X.509 certificate for authentication
	#[cfg(feature = "x509")]
	pub certificate: Certificate,
	/// Digital signature over (client_random || server_random || params)
	/// Signature algorithm determined by server certificate
	pub signature: OctetString,
}

// ============================================================================
// TightBeam Default Handshake Implementation
// ============================================================================

#[cfg(all(feature = "x509", feature = "secp256k1"))]
mod tightbeam_handshake {
	use super::*;
	use crate::crypto::aead::{Aes256Gcm, KeyInit};
	use crate::crypto::kdf::ecies_kdf_sha256;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
	use crate::crypto::sign::{Signer, Verifier};
	use crate::der::{Decode, Encode};
	use crate::random::generate_nonce;
	use crate::transport::TransportEnvelope;
	use crate::x509::Certificate;
	use crate::ZeroizingBytes;

	/// OID for secp256k1 curve
	const SECP256K1_OID: &str = "1.3.132.0.10";

	/// TightBeam's default simplified handshake protocol
	///
	/// This provides a TLS-inspired but simplified ECDHE handshake with:
	/// - Ephemeral ECDH key exchange (forward secrecy)
	/// - Random nonces (replay protection)
	/// - Certificate-based authentication
	/// - Stateless operation
	///
	/// Signature payload: `client_random || server_random || server_params`
	/// Session key derivation: `KDF(shared_secret || client_random || server_random)`
	pub struct TightBeamHandshake {
		role: HandshakeRole,
		// Client state
		client_random: Option<[u8; 32]>,
		client_secret: Option<k256::SecretKey>,
		// Server state
		server_random: Option<[u8; 32]>,
		server_secret: Option<k256::SecretKey>,
		server_cert: Option<Certificate>,
		signing_key: Option<Secp256k1SigningKey>,
		// Shared state
		peer_public: Option<k256::PublicKey>,
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
				client_secret: None,
				server_random: None,
				server_secret: None,
				server_cert: None,
				signing_key: None,
				peer_public: None,
			}
		}

		/// Create new server-side handshake with certificate and signing key
		pub fn new_server(certificate: Certificate, signing_key: Secp256k1SigningKey) -> Self {
			Self {
				role: HandshakeRole::Server,
				client_random: None,
				client_secret: None,
				server_random: None,
				server_secret: None,
				server_cert: Some(certificate),
				signing_key: Some(signing_key),
				peer_public: None,
			}
		}

		/// Derive session key from ECDH shared secret and nonces
		fn derive_session_key(
			&self,
			shared_secret: &ZeroizingBytes,
			client_random: &[u8; 32],
			server_random: &[u8; 32],
		) -> Result<Aes256Gcm, HandshakeError> {
			let mut kdf_input = Vec::with_capacity(32 + 32 + 32);
			kdf_input.extend_from_slice(shared_secret.as_slice());
			kdf_input.extend_from_slice(client_random);
			kdf_input.extend_from_slice(server_random);

			let mut session_key_bytes = [0u8; 32];
			ecies_kdf_sha256(&kdf_input, b"tightbeam-handshake-v1", &[], Some(&mut session_key_bytes))
				.map_err(|_| HandshakeError::KeyDerivationFailed)?;

			Aes256Gcm::new_from_slice(&session_key_bytes).map_err(|_| HandshakeError::KeyDerivationFailed)
		}

		/// Extract public key from certificate
		fn extract_verifying_key(cert: &Certificate) -> Result<Secp256k1VerifyingKey, HandshakeError> {
			let spki = &cert.tbs_certificate.subject_public_key_info;
			let public_key_bytes = spki.subject_public_key.raw_bytes();
			let public_key =
				k256::PublicKey::from_sec1_bytes(public_key_bytes).map_err(|_| HandshakeError::InvalidCertificate)?;
			Ok(Secp256k1VerifyingKey::from(public_key))
		}
	}

	impl HandshakeProtocol for TightBeamHandshake {
		type SessionKey = Aes256Gcm;
		type Error = TransportError;

		async fn initiate_client(&mut self) -> Result<Vec<u8>, Self::Error> {
			if self.role != HandshakeRole::Client {
				return Err(HandshakeError::InvalidState.into());
			}

			// Generate ephemeral ECDH key
			let secret = k256::SecretKey::random(&mut rand_core::OsRng);
			let public = secret.public_key();
			self.client_secret = Some(secret);

			// Generate random nonce
			let nonce = generate_nonce::<32>(None)
				.map_err(|_| HandshakeError::ProtocolError("Nonce generation failed".into()))?;
			self.client_random = Some(nonce);

			// Create ClientKeyExchange
			let public_bytes = public.to_sec1_bytes();
			let client_kex = ClientKeyExchange {
				params: ClientECDHParams {
					public: OctetString::new(public_bytes.as_ref()).map_err(|_| HandshakeError::InvalidPublicKey)?,
				},
				random: OctetString::new(&nonce).map_err(|_| HandshakeError::InvalidClientKeyExchange)?,
			};

			// Encode as TransportEnvelope
			let envelope = TransportEnvelope::ClientKeyExchange(client_kex);
			envelope.to_der().map_err(|e| TransportError::DerError(e))
		}

		async fn process_server_response(&mut self, response: &[u8]) -> Result<Self::SessionKey, Self::Error> {
			if self.role != HandshakeRole::Client {
				return Err(HandshakeError::InvalidState.into());
			}

			// Parse ServerKeyExchange
			let envelope = TransportEnvelope::from_der(response).map_err(|e| TransportError::DerError(e))?;

			let server_kex = match envelope {
				TransportEnvelope::ServerKeyExchange(kex) => kex,
				_ => return Err(HandshakeError::InvalidServerKeyExchange.into()),
			};

			// Extract server public key and nonce
			let server_public = k256::PublicKey::from_sec1_bytes(server_kex.params.public.as_bytes())
				.map_err(|_| HandshakeError::InvalidPublicKey)?;

			let server_random: [u8; 32] = server_kex
				.random
				.as_bytes()
				.try_into()
				.map_err(|_| HandshakeError::InvalidServerKeyExchange)?;

			self.server_random = Some(server_random);
			self.peer_public = Some(server_public);

			// Verify signature over (client_random || server_random || server_params)
			let verifying_key = Self::extract_verifying_key(&server_kex.certificate)?;

			let mut sig_payload = Vec::with_capacity(32 + 32 + server_kex.params.public.as_bytes().len());
			sig_payload.extend_from_slice(&self.client_random.unwrap());
			sig_payload.extend_from_slice(&server_random);
			sig_payload.extend_from_slice(server_kex.params.public.as_bytes());

			let signature = Secp256k1Signature::try_from(server_kex.signature.as_bytes())
				.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

			verifying_key
				.verify(&sig_payload, &signature)
				.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

			// Perform ECDH and derive session key
			let shared = k256::ecdh::diffie_hellman(
				self.client_secret.as_ref().unwrap().to_nonzero_scalar(),
				server_public.as_affine(),
			);

			let shared_bytes = ZeroizingBytes::new(shared.raw_secret_bytes().to_vec());
			self.derive_session_key(&shared_bytes, &self.client_random.unwrap(), &server_random)
				.map_err(Into::into)
		}

		async fn handle_client_request(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
			if self.role != HandshakeRole::Server {
				return Err(HandshakeError::InvalidState.into());
			}

			// Parse ClientKeyExchange
			let envelope = TransportEnvelope::from_der(request).map_err(|e| TransportError::DerError(e))?;

			let client_kex = match envelope {
				TransportEnvelope::ClientKeyExchange(kex) => kex,
				_ => return Err(HandshakeError::InvalidClientKeyExchange.into()),
			};

			// Extract client public key and nonce
			let client_public = k256::PublicKey::from_sec1_bytes(client_kex.params.public.as_bytes())
				.map_err(|_| HandshakeError::InvalidPublicKey)?;

			let client_random: [u8; 32] = client_kex
				.random
				.as_bytes()
				.try_into()
				.map_err(|_| HandshakeError::InvalidClientKeyExchange)?;

			self.client_random = Some(client_random);
			self.peer_public = Some(client_public);

			// Generate server ephemeral key and nonce
			let secret = k256::SecretKey::random(&mut rand_core::OsRng);
			let public = secret.public_key();
			self.server_secret = Some(secret);

			let nonce = generate_nonce::<32>(None)
				.map_err(|_| HandshakeError::ProtocolError("Nonce generation failed".into()))?;
			self.server_random = Some(nonce);

			// Create signature payload: client_random || server_random || server_params
			let public_bytes = public.to_sec1_bytes();
			let mut sig_payload = Vec::with_capacity(32 + 32 + public_bytes.len());
			sig_payload.extend_from_slice(&client_random);
			sig_payload.extend_from_slice(&nonce);
			sig_payload.extend_from_slice(&public_bytes);

			// Sign with server's certificate key
			let signing_key = self
				.signing_key
				.as_ref()
				.ok_or_else(|| HandshakeError::ProtocolError("No signing key".into()))?;

			let signature: Secp256k1Signature = signing_key
				.try_sign(&sig_payload)
				.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

			// Create ServerKeyExchange
			let server_kex = ServerKeyExchange {
				params: ServerECDHParams {
					curve: ObjectIdentifier::new(SECP256K1_OID)
						.map_err(|_| HandshakeError::ProtocolError("Invalid OID".into()))?,
					public: OctetString::new(public_bytes.as_ref()).map_err(|_| HandshakeError::InvalidPublicKey)?,
				},
				random: OctetString::new(&nonce).map_err(|_| HandshakeError::InvalidServerKeyExchange)?,
				certificate: self.server_cert.clone().ok_or_else(|| HandshakeError::InvalidCertificate)?,
				signature: OctetString::new(signature.to_bytes().as_slice())
					.map_err(|_| HandshakeError::SignatureVerificationFailed)?,
			};

			// Encode as TransportEnvelope
			let envelope = TransportEnvelope::ServerKeyExchange(server_kex);
			envelope.to_der().map_err(|e| TransportError::DerError(e))
		}

		async fn complete_server_handshake(&mut self) -> Result<Self::SessionKey, Self::Error> {
			if self.role != HandshakeRole::Server {
				return Err(HandshakeError::InvalidState.into());
			}

			// Perform ECDH and derive session key
			let shared = k256::ecdh::diffie_hellman(
				self.server_secret.as_ref().unwrap().to_nonzero_scalar(),
				self.peer_public.as_ref().unwrap().as_affine(),
			);

			let shared_bytes = ZeroizingBytes::new(shared.raw_secret_bytes().to_vec());
			self.derive_session_key(&shared_bytes, &self.client_random.unwrap(), &self.server_random.unwrap())
				.map_err(Into::into)
		}
	}
}

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub use tightbeam_handshake::TightBeamHandshake;
