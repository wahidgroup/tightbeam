//! ECIES-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam ECIES handshake protocol.

#![cfg(all(feature = "x509", feature = "secp256k1"))]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::crypto::aead::{Aes256Gcm, KeyInit};
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{hkdf, HkdfSha3_256};
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::state::{HandshakeState, ServerStateTransition, StateTransition};
use crate::transport::handshake::{
	ClientHello, ClientKeyExchange, ServerHandshake, ServerHandshakeKey, ServerHandshakeProtocol,
};
use crate::x509::Certificate;

/// Server-side ECIES handshake orchestrator.
///
/// Manages the complete server handshake flow:
/// 1. Receives ClientHello with random nonce
/// 2. Sends ServerHandshake (certificate, random, signature over transcript)
/// 3. Receives and decrypts ClientKeyExchange with ECIES-encrypted session key
pub struct EciesHandshakeServer {
	state: ServerStateTransition,
	server_key: Arc<dyn ServerHandshakeKey>,
	server_cert: Certificate,
	client_random: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	base_session_key: Option<[u8; 32]>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: Option<Vec<u8>>,
}

impl EciesHandshakeServer {
	/// Create a new ECIES handshake server.
	///
	/// # Parameters
	/// - `server_key`: The server's signing key for authentication (trait object)
	/// - `server_cert`: The server's certificate
	/// - `aad_domain_tag`: Optional domain tag for ECIES decryption (defaults to "tb-v1")
	pub fn new(
		server_key: Arc<dyn ServerHandshakeKey>,
		server_cert: Certificate,
		aad_domain_tag: Option<Vec<u8>>,
	) -> Self {
		Self {
			state: ServerStateTransition::new(),
			server_key,
			server_cert,
			client_random: None,
			server_random: None,
			base_session_key: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.or_else(|| Some(b"tb-v1".to_vec())),
		}
	}

	/// Process ClientHello and build ServerHandshake message.
	///
	/// # Parameters
	/// - `client_hello_der`: DER-encoded ClientHello from client
	///
	/// # Returns
	/// DER-encoded ServerHandshake
	pub fn process_client_hello(&mut self, client_hello_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::Init {
			return Err(HandshakeError::InvalidState);
		}

		// Decode ClientHello
		let client_hello = ClientHello::from_der(client_hello_der)?;

		// Extract client random
		let client_random = self.octet_string_to_array(&client_hello.client_random)?;
		self.client_random = Some(client_random);

		// Generate server random
		let server_random = generate_nonce::<32>(None)?;
		self.server_random = Some(server_random);

		// Compute transcript hash
		let spki_bytes = self
			.server_cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let digest = self.compute_transcript_hash(&client_random, &server_random, spki_bytes);
		self.transcript_hash = Some(digest);

		// Sign transcript hash using trait method
		let signature_bytes = self.server_key.sign_server_challenge(&digest)?;

		// Build ServerHandshake
		let server_handshake = ServerHandshake {
			certificate: self.server_cert.clone(),
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature_bytes)?,
		};

		// Note: State doesn't transition yet - we're waiting for ClientKeyExchange
		Ok(server_handshake.to_der()?)
	}

	/// Process ClientKeyExchange message (decrypt ECIES-encrypted session key).
	///
	/// # Parameters
	/// - `client_kex_der`: DER-encoded ClientKeyExchange from client
	///
	/// # Returns
	/// Success (session key stored internally)
	pub fn process_client_key_exchange(&mut self, client_kex_der: &[u8]) -> Result<(), HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::Init {
			return Err(HandshakeError::InvalidState);
		}

		// Decode ClientKeyExchange
		let client_kex = ClientKeyExchange::from_der(client_kex_der)?;

		// Parse ECIES message
		let encrypted_bytes = client_kex.encrypted_data.as_bytes();
		let encrypted_message = crate::crypto::ecies::Secp256k1EciesMessage::from_bytes(encrypted_bytes)
			.map_err(|e| HandshakeError::InvalidEciesMessage(format!("{e:?}")))?;

		// Decrypt with ECIES using trait method
		let decrypted = self
			.server_key
			.decrypt_ecies(&encrypted_message, self.aad_domain_tag.as_deref())
			.map_err(|e| HandshakeError::EciesDecryptionFailed(format!("{e:?}")))?;

		let decrypted = decrypted.to_insecure();
		if decrypted.len() != 64 {
			return Err(HandshakeError::InvalidDecryptedPayloadSize);
		}

		// Extract base key and client random
		let mut base_key = [0u8; 32];
		let mut client_random_from_payload = [0u8; 32];
		base_key.copy_from_slice(&decrypted[..32]);
		client_random_from_payload.copy_from_slice(&decrypted[32..]);

		// Verify client random matches (prevents replay attacks)
		let expected_client_random = self.client_random.ok_or(HandshakeError::MissingClientRandom)?;
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
		let is_equal: bool = client_random_from_payload.ct_eq(&expected_client_random).into();
		if !is_equal {
			return Err(HandshakeError::ClientRandomMismatchReplay);
		}
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		// Store base session key
		self.base_session_key = Some(base_key);

		// Transition state
		self.state.transition(HandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// Complete the handshake and derive the final session key.
	///
	/// # Returns
	/// AES-256-GCM session key
	pub fn complete(&mut self) -> Result<Aes256Gcm, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::KeyExchangeReceived {
			return Err(HandshakeError::InvalidState);
		}

		// Derive final session key
		let base_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;

		let session_key = self.derive_final_session_key(base_key, client_random, server_random)?;

		// Transition to complete
		self.state.transition(HandshakeState::Complete)?;

		// Clear sensitive data
		if let Some(mut bk) = self.base_session_key.take() {
			bk.fill(0);
		}
		if let Some(mut cr) = self.client_random.take() {
			cr.fill(0);
		}
		if let Some(mut sr) = self.server_random.take() {
			sr.fill(0);
		}

		Ok(session_key)
	}

	/// Get the current handshake state.
	pub fn state(&self) -> HandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_complete()
	}

	/// Get the transcript hash (if available).
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.transcript_hash
	}

	// Helper methods

	fn octet_string_to_array(&self, octet_string: &OctetString) -> Result<[u8; 32], HandshakeError> {
		let bytes = octet_string.as_bytes();
		if bytes.len() != 32 {
			return Err(HandshakeError::OctetStringLengthError((bytes.len(), 32).into()));
		}
		let mut out = [0u8; 32];
		out.copy_from_slice(bytes);
		Ok(out)
	}

	fn compute_transcript_hash(
		&self,
		client_random: &[u8; 32],
		server_random: &[u8; 32],
		spki_bytes: &[u8],
	) -> [u8; 32] {
		let mut data = Vec::with_capacity(32 + 32 + spki_bytes.len());
		data.extend_from_slice(client_random);
		data.extend_from_slice(server_random);
		data.extend_from_slice(spki_bytes);
		let digest_arr = Sha3_256::digest(&data);
		let mut digest = [0u8; 32];
		digest.copy_from_slice(&digest_arr);
		digest
	}

	fn derive_final_session_key(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		server_random: &[u8; 32],
	) -> Result<Aes256Gcm, HandshakeError> {
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);
		let final_key_bytes = hkdf::<HkdfSha3_256, 32>(base_key, b"tightbeam-session-v1", Some(&salt))?;
		Ok(Aes256Gcm::new_from_slice(&final_key_bytes[..])?)
	}
}

// ============================================================================
// ServerHandshakeProtocol Implementation
// ============================================================================

impl ServerHandshakeProtocol for EciesHandshakeServer {
	type SessionKey = Aes256Gcm;
	type Error = HandshakeError;

	async fn handle_request(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
		// Determine which message type this is based on state
		match self.state() {
			HandshakeState::Init => {
				// This is ClientHello - respond with ServerHandshake
				let server_handshake = self.process_client_hello(msg)?;
				Ok(Some(server_handshake))
			}
			_ => {
				// This is ClientKeyExchange - no response needed
				self.process_client_key_exchange(msg)?;
				Ok(None)
			}
		}
	}

	async fn complete(&mut self) -> Result<Self::SessionKey, Self::Error> {
		self.complete()
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::ecies::encrypt;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::der::asn1::ObjectIdentifier;
	use crate::random::OsRng;
	use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
	use crate::x509::time::Validity;
	use crate::x509::{name::RdnSequence, TbsCertificate};

	fn create_test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
		let verifying_key = *signing_key.verifying_key();
		let public_key_der = verifying_key.to_public_key_der().unwrap();

		let tbs_cert = TbsCertificate {
			version: crate::x509::Version::V3,
			serial_number: crate::x509::serial_number::SerialNumber::new(&[1]).unwrap(),
			signature: AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
				parameters: None,
			},
			issuer: RdnSequence::default(),
			validity: Validity {
				not_before: crate::x509::time::Time::GeneralTime(
					crate::der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap(),
				),
				not_after: crate::x509::time::Time::GeneralTime(
					crate::der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(
						u32::MAX as u64,
					))
					.unwrap(),
				),
			},
			subject: RdnSequence::default(),
			subject_public_key_info: crate::spki::SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())
				.unwrap(),
			issuer_unique_id: None,
			subject_unique_id: None,
			extensions: None,
		};

		Certificate {
			tbs_certificate: tbs_cert,
			signature_algorithm: AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
				parameters: None,
			},
			signature: crate::der::asn1::BitString::new(0, vec![0; 64]).unwrap(),
		}
	}

	#[test]
	fn test_server_state_flow() -> Result<(), Box<dyn std::error::Error>> {
		// Setup
		let server_key = Secp256k1SigningKey::random(&mut OsRng);
		let server_cert = create_test_certificate(&server_key);

		// Create server (wrap key in Arc for trait object)
		let server_key_arc: Arc<dyn crate::transport::handshake::ServerHandshakeKey> = Arc::new(server_key.clone());
		let mut server = EciesHandshakeServer::new(server_key_arc, server_cert.clone(), Some(b"test-domain".to_vec()));
		assert_eq!(server.state(), HandshakeState::Init);

		// Client builds ClientHello
		let client_random = generate_nonce::<32>(None)?;
		let client_hello = ClientHello { client_random: OctetString::new(client_random)? };

		// Process ClientHello
		let _server_handshake = server.process_client_hello(&client_hello.to_der()?)?;
		assert_eq!(server.state(), HandshakeState::Init); // Still waiting for ClientKeyExchange
		assert!(server.client_random.is_some());
		assert!(server.server_random.is_some());
		assert!(server.transcript_hash.is_some());

		// Client builds ClientKeyExchange
		let base_key = generate_nonce::<32>(None)?;
		let mut plaintext = [0u8; 64];
		plaintext[..32].copy_from_slice(&base_key);
		plaintext[32..].copy_from_slice(&client_random);

		let server_pubkey = k256::PublicKey::from_sec1_bytes(
			server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		let encrypted_message = encrypt::<_, _, _, crate::crypto::ecies::Secp256k1EciesMessage>(
			&server_pubkey,
			&plaintext,
			Some(b"test-domain"),
			Some(&mut rand_core::OsRng),
		)?;

		let client_kex = ClientKeyExchange { encrypted_data: OctetString::new(encrypted_message.to_bytes())? };

		// Process ClientKeyExchange
		server.process_client_key_exchange(&client_kex.to_der()?)?;
		assert_eq!(server.state(), HandshakeState::KeyExchangeReceived);
		assert!(server.base_session_key.is_some());

		// Complete
		let _session_key = server.complete()?;
		assert!(server.is_complete());
		assert_eq!(server.state(), HandshakeState::Complete);

		Ok(())
	}

	#[test]
	fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
		let server_key = Secp256k1SigningKey::random(&mut OsRng);
		let server_cert = create_test_certificate(&server_key);
		let server_key_arc: Arc<dyn crate::transport::handshake::ServerHandshakeKey> = Arc::new(server_key);
		let mut server = EciesHandshakeServer::new(server_key_arc, server_cert, None);

		// Can't process client key exchange before client hello
		let result = server.process_client_key_exchange(&[]);
		assert!(result.is_err());

		// Can't complete before processing client key exchange
		let result = server.complete();
		assert!(result.is_err());

		Ok(())
	}
}
