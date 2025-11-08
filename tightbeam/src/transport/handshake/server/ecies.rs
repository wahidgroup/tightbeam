//! ECIES-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam ECIES handshake protocol.

#![cfg(feature = "x509")]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::constants::{TIGHTBEAM_AAD_DOMAIN_TAG, TIGHTBEAM_SESSION_KDF_INFO};
use crate::crypto::aead::{Aes256Gcm, KeyInit};
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{hkdf, HkdfSha3_256};
use crate::crypto::secret::{Secret, ToInsecure};
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
	/// - `aad_domain_tag`: Optional domain tag for ECIES decryption (defaults to `TIGHTBEAM_AAD_DOMAIN_TAG`)
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
			aad_domain_tag: aad_domain_tag.or_else(|| Some(TIGHTBEAM_AAD_DOMAIN_TAG.to_vec())),
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
		// 1. Validate current state is Init
		self.validate_expected_state(HandshakeState::Init)?;

		// 2. Decode ClientHello message
		let client_hello = self.decode_client_hello(client_hello_der)?;

		// 3. Extract and store client random
		let client_random = self.octet_string_to_array(&client_hello.client_random)?;
		self.client_random = Some(client_random);

		// 4. Generate and store server random
		let server_random = self.generate_server_random()?;

		// 5. Compute transcript hash
		let spki_bytes = self
			.server_cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let transcript_digest = self.compute_transcript_hash(&client_random, &server_random, spki_bytes);
		self.transcript_hash = Some(transcript_digest);

		// 6. Sign transcript hash
		let signature_bytes = self.sign_transcript_hash(&transcript_digest)?;

		// 7. Build and encode ServerHandshake
		let server_handshake_der = self.build_server_handshake(server_random, signature_bytes)?;

		// 8. Transition state through ServerHelloReceived to ServerHelloSent
		self.state.transition(HandshakeState::ServerHelloReceived)?;
		self.state.transition(HandshakeState::ServerHelloSent)?;

		Ok(server_handshake_der)
	}

	/// Process ClientKeyExchange message (decrypt ECIES-encrypted session key).
	///
	/// # Parameters
	/// - `client_kex_der`: DER-encoded ClientKeyExchange from client
	///
	/// # Returns
	/// Success (session key stored internally)
	pub fn process_client_key_exchange(&mut self, client_kex_der: &[u8]) -> Result<(), HandshakeError> {
		// 1. Validate current state is ServerHelloSent
		self.validate_expected_state(HandshakeState::ServerHelloSent)?;

		// 2. Decode ClientKeyExchange message
		let client_kex = self.decode_client_key_exchange(client_kex_der)?;

		// 3. Get encrypted bytes from the message
		let encrypted_bytes = client_kex.encrypted_data.as_bytes();

		// 4. Decrypt ECIES payload
		let decrypted_payload = self.decrypt_ecies_payload(encrypted_bytes)?;

		// 5. Extract base session key and client random from payload
		let (base_session_key, client_random_from_payload) =
			self.extract_session_data_from_payload(&decrypted_payload)?;

		// 6. Verify client random matches stored value (prevents replay attacks)
		self.verify_client_random(&client_random_from_payload)?;

		// 7. Store base session key
		self.base_session_key = Some(base_session_key);

		// 8. Transition state to KeyExchangeReceived
		self.state.transition(HandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// Complete the handshake and derive the final session key.
	///
	/// # Returns
	/// AES-256-GCM session key
	pub fn complete(&mut self) -> Result<Aes256Gcm, HandshakeError> {
		// 1. Validate current state is KeyExchangeReceived
		self.validate_expected_state(HandshakeState::KeyExchangeReceived)?;

		// 2. Get required values for key derivation
		let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;

		// 3. Derive final session key
		let session_key = self.derive_final_session_key(base_session_key, client_random, server_random)?;

		// 4. Transition to complete state
		self.state.transition(HandshakeState::Complete)?;

		// 5. Clear sensitive data
		self.clear_sensitive_data();

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

		let final_key_bytes = hkdf::<HkdfSha3_256, 32>(base_key, TIGHTBEAM_SESSION_KDF_INFO, Some(&salt))?;
		Ok(Aes256Gcm::new_from_slice(&final_key_bytes[..])?)
	}

	fn derive_final_session_key_bytes(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		server_random: &[u8; 32],
	) -> Result<Vec<u8>, HandshakeError> {
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		let final_key_bytes = hkdf::<HkdfSha3_256, 32>(base_key, TIGHTBEAM_SESSION_KDF_INFO, Some(&salt))?;
		Ok(final_key_bytes.to_vec())
	}

	fn validate_expected_state(&self, expected: HandshakeState) -> Result<(), HandshakeError> {
		if self.state.state() != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	fn decode_client_hello(&self, client_hello_der: &[u8]) -> Result<ClientHello, HandshakeError> {
		Ok(ClientHello::from_der(client_hello_der)?)
	}

	fn generate_server_random(&mut self) -> Result<[u8; 32], HandshakeError> {
		let server_random = generate_nonce::<32>(None)?;
		self.server_random = Some(server_random);
		Ok(server_random)
	}

	fn sign_transcript_hash(&self, transcript_digest: &[u8; 32]) -> Result<Vec<u8>, HandshakeError> {
		self.server_key.sign_server_challenge(transcript_digest)
	}

	fn build_server_handshake(
		&self,
		server_random: [u8; 32],
		signature_bytes: Vec<u8>,
	) -> Result<Vec<u8>, HandshakeError> {
		let server_handshake = ServerHandshake {
			certificate: self.server_cert.clone(),
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature_bytes)?,
		};

		Ok(server_handshake.to_der()?)
	}

	fn decode_client_key_exchange(&self, client_kex_der: &[u8]) -> Result<ClientKeyExchange, HandshakeError> {
		Ok(ClientKeyExchange::from_der(client_kex_der)?)
	}

	fn decrypt_ecies_payload(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let decrypted_payload = self.server_key.decrypt_ecies(encrypted_bytes, self.aad_domain_tag.as_deref())?;
		Ok(decrypted_payload.to_insecure())
	}

	fn extract_session_data_from_payload(
		&self,
		decrypted_payload: &[u8],
	) -> Result<([u8; 32], [u8; 32]), HandshakeError> {
		if decrypted_payload.len() != 64 {
			return Err(HandshakeError::InvalidDecryptedPayloadSize);
		}
		let mut base_session_key = [0u8; 32];
		let mut client_random_from_payload = [0u8; 32];
		base_session_key.copy_from_slice(&decrypted_payload[..32]);
		client_random_from_payload.copy_from_slice(&decrypted_payload[32..]);
		Ok((base_session_key, client_random_from_payload))
	}

	fn verify_client_random(&self, client_random_from_payload: &[u8; 32]) -> Result<(), HandshakeError> {
		let expected_client_random = self.client_random.ok_or(HandshakeError::MissingClientRandom)?;

		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
		let is_equal: bool = client_random_from_payload.ct_eq(&expected_client_random).into();
		if !is_equal {
			return Err(HandshakeError::ClientRandomMismatchReplay);
		}
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		Ok(())
	}

	fn clear_sensitive_data(&mut self) {
		if let Some(mut bk) = self.base_session_key.take() {
			bk.fill(0);
		}
		if let Some(mut cr) = self.client_random.take() {
			cr.fill(0);
		}
		if let Some(mut sr) = self.server_random.take() {
			sr.fill(0);
		}
	}
}

// ============================================================================
// ServerHandshakeProtocol Implementation
// ============================================================================

impl ServerHandshakeProtocol for EciesHandshakeServer {
	type SessionKey = Secret<Vec<u8>>;
	type Error = HandshakeError;

	fn handle_request<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a,
	{
		Box::pin(async move {
			// Determine which message type this is based on state
			match self.state() {
				HandshakeState::Init => {
					// This is ClientHello - respond with ServerHandshake
					let server_handshake = self.process_client_hello(msg)?;
					Ok(Some(server_handshake))
				}
				HandshakeState::ServerHelloSent => {
					// This is ClientKeyExchange - no response needed
					self.process_client_key_exchange(msg)?;
					Ok(None)
				}
				_ => Err(HandshakeError::InvalidState),
			}
		})
	}

	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>> {
		Box::pin(async move {
			// 1. Validate current state is KeyExchangeReceived
			self.validate_expected_state(HandshakeState::KeyExchangeReceived)?;

			// 2. Get required values for key derivation
			let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
			let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;

			// 3. Derive final session key as raw bytes
			let session_key_bytes =
				self.derive_final_session_key_bytes(base_session_key, client_random, server_random)?;

			// 4. Transition to complete state
			self.state.transition(HandshakeState::Complete)?;

			// 5. Clear sensitive data
			self.clear_sensitive_data();

			Ok(Secret::from(session_key_bytes))
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::ecies::encrypt;
	use crate::random::OsRng;
	use crate::transport::handshake::tests::*;

	#[test]
	fn test_server_state_flow() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A server in init state
		let mut server = TestEciesServerBuilder::new().build();
		assert_eq!(server.state(), HandshakeState::Init);

		// And: A valid client hello message
		let client_random = crate::random::generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;

		// When: Server processes the client hello
		let server_handshake_der = server.process_client_hello(&client_hello_der)?;
		assert_eq!(server.state(), HandshakeState::ServerHelloSent);
		assert!(server.client_random.is_some());
		assert!(server.server_random.is_some());
		assert!(server.transcript_hash.is_some());

		// And: Server handshake message is valid
		let _server_handshake = ServerHandshake::from_der(&server_handshake_der)?;

		// When: Server processes a valid client key exchange
		let server_pubkey = k256::PublicKey::from_sec1_bytes(
			server
				.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		// Use the actual client_random that was stored by the server
		let stored_client_random = server.client_random.unwrap();
		let base_session_key = crate::random::generate_nonce::<32>(None)?;

		let mut plaintext = [0u8; 64];
		plaintext[..32].copy_from_slice(&base_session_key);
		plaintext[32..].copy_from_slice(&stored_client_random);

		let encrypted_message = encrypt::<_, _, _, crate::crypto::ecies::Secp256k1EciesMessage>(
			&server_pubkey,
			&plaintext,
			Some(b"test-domain"),
			Some(&mut OsRng),
		)?;

		let client_kex_der = create_test_client_key_exchange(&encrypted_message.to_bytes())?;
		server.process_client_key_exchange(&client_kex_der)?;
		assert_eq!(server.state(), HandshakeState::KeyExchangeReceived);
		assert!(server.base_session_key.is_some());

		// When: Server completes the handshake
		let _session_key = server.complete()?;
		assert!(server.is_complete());
		assert_eq!(server.state(), HandshakeState::Complete);

		Ok(())
	}

	#[test]
	fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A fresh server in init state
		let mut server = TestEciesServerBuilder::new().build();

		// When: Trying to process client key exchange before client hello
		let result = server.process_client_key_exchange(&[]);
		assert!(result.is_err());

		// When: Trying to complete before any handshake steps
		let result = server.complete();
		assert!(result.is_err());

		// Given: Server has processed client hello
		let client_random = crate::random::generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der)?;

		// When: Trying to process client hello again
		let result = server.process_client_hello(&client_hello_der);
		assert!(result.is_err());

		// When: Trying to complete before client key exchange
		let result = server.complete();
		assert!(result.is_err());

		// Given: Server has processed client key exchange
		let server_pubkey = k256::PublicKey::from_sec1_bytes(
			server
				.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		let stored_client_random = server.client_random.unwrap();
		let base_session_key = crate::random::generate_nonce::<32>(None)?;

		let mut plaintext = [0u8; 64];
		plaintext[..32].copy_from_slice(&base_session_key);
		plaintext[32..].copy_from_slice(&stored_client_random);

		let encrypted_message = encrypt::<_, _, _, crate::crypto::ecies::Secp256k1EciesMessage>(
			&server_pubkey,
			&plaintext,
			Some(b"test-domain"),
			Some(&mut OsRng),
		)?;

		let client_kex_der = create_test_client_key_exchange(&encrypted_message.to_bytes())?;
		server.process_client_key_exchange(&client_kex_der)?;

		// When: Trying to process client key exchange again
		let result = server.process_client_key_exchange(&client_kex_der);
		assert!(result.is_err());

		// When: Trying to process client hello after key exchange
		let result = server.process_client_hello(&client_hello_der);
		assert!(result.is_err());

		Ok(())
	}
}
