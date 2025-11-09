//! ECIES-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam ECIES handshake protocol.
//! Generic over `P: CryptoProvider` for cryptographic operations.

#![cfg(feature = "x509")]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use core::marker::PhantomData;

#[cfg(feature = "std")]
use std::marker::PhantomData;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::constants::{TIGHTBEAM_AAD_DOMAIN_TAG, TIGHTBEAM_SESSION_KDF_INFO};
use crate::crypto::aead::KeyInit;
use crate::crypto::hash::Digest;
use crate::crypto::kdf::KdfProvider;
use crate::crypto::negotiation::select_profile;
use crate::crypto::negotiation::SecurityAccept;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::Verifier;
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
///
/// Generic over `P: CryptoProvider` for cryptographic operations.
pub struct EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	state: ServerStateTransition,
	server_key: Arc<dyn ServerHandshakeKey>,
	server_cert: Certificate,
	client_random: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	base_session_key: Option<[u8; 32]>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: Option<Vec<u8>>,
	supported_profiles: Vec<crate::crypto::profiles::SecurityProfileDesc>,
	selected_profile: Option<crate::crypto::profiles::SecurityProfileDesc>,
	client_validators: Option<Arc<Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>>>,
	validated_client_cert: Option<Certificate>,
	_phantom: PhantomData<P>,
}

impl<P> EciesHandshakeServer<P>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
{
	/// Create a new ECIES handshake server.
	///
	/// # Parameters
	/// - `server_key`: The server's signing key for authentication (trait object)
	/// - `server_cert`: The server's certificate to send to client
	/// - `aad_domain_tag`: Optional domain tag for ECIES decryption (defaults to `TIGHTBEAM_AAD_DOMAIN_TAG`)
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	pub fn new(
		server_key: Arc<dyn ServerHandshakeKey>,
		server_cert: Certificate,
		aad_domain_tag: Option<Vec<u8>>,
		client_validators: Option<Arc<Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>>>,
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
			supported_profiles: Vec::new(), // Must be set via with_supported_profiles()
			selected_profile: None,
			client_validators,
			validated_client_cert: None,
			_phantom: PhantomData,
		}
	}
	/// Set the server's supported security profiles for negotiation.
	/// Server must have at least one supported profile configured.
	pub fn with_supported_profiles(mut self, profiles: Vec<crate::crypto::profiles::SecurityProfileDesc>) -> Self {
		self.supported_profiles = profiles;
		self
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

		// 3. Profile negotiation (two modes: negotiation or dealer's choice)
		// Server must have supported_profiles configured
		if self.supported_profiles.is_empty() {
			return Err(HandshakeError::InvalidState);
		}

		let security_accept = match &client_hello.security_offer {
			Some(offer) => {
				// Mode 1: Negotiation - client offered, server selects mutual
				let selected = select_profile(offer, &self.supported_profiles)?;
				self.selected_profile = Some(selected);
				SecurityAccept::new(selected)
			}
			None => {
				// Mode 2: Dealer's choice - client didn't offer, server picks default
				let selected = self.supported_profiles[0];
				self.selected_profile = Some(selected);
				SecurityAccept::new(selected)
			}
		};

		// 4. Extract and store client random
		let client_random = self.octet_string_to_array(&client_hello.client_random)?;
		self.client_random = Some(client_random);

		// 5. Generate and store server random
		let server_random = self.generate_server_random()?;

		// 6. Compute transcript hash
		let spki_bytes = self
			.server_cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let transcript_digest = self.compute_transcript_hash(&client_random, &server_random, spki_bytes);
		self.transcript_hash = Some(transcript_digest);

		// 7. Sign transcript hash
		let signature_bytes = self.sign_transcript_hash(&transcript_digest)?;

		// 8. Build and encode ServerHandshake
		let server_handshake_der =
			self.build_server_handshake(server_random, signature_bytes, Some(security_accept))?;

		// 9. Transition state through ServerHelloReceived to ServerHelloSent
		self.state.dispatch(HandshakeState::ServerHelloReceived)?;
		self.state.dispatch(HandshakeState::ServerHelloSent)?;

		Ok(server_handshake_der)
	}

	/// Process ClientKeyExchange message (decrypt ECIES-encrypted session key).
	///
	/// # Parameters
	/// - `client_kex_der`: DER-encoded ClientKeyExchange from client
	///
	/// # Returns
	/// Success (session key stored internally)
	pub fn process_client_key_exchange(&mut self, client_kex_der: &[u8]) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: Verifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		// 1. Validate current state is ServerHelloSent
		self.validate_expected_state(HandshakeState::ServerHelloSent)?;

		// 2. Decode ClientKeyExchange message
		let client_kex = self.decode_client_key_exchange(client_kex_der)?;

		// 3. Validate client certificate if mutual auth is configured
		self.validate_client_certificate(&client_kex)?;

		// 4. Get encrypted bytes from the message
		let encrypted_bytes = client_kex.encrypted_data.as_bytes();

		// 5. Decrypt ECIES payload
		let decrypted_payload = self.decrypt_ecies_payload(encrypted_bytes)?;

		// 6. Extract base session key and client random from payload
		let (base_session_key, client_random_from_payload) =
			self.extract_session_data_from_payload(&decrypted_payload)?;

		// 7. Verify client random matches stored value (prevents replay attacks)
		self.verify_client_random(&client_random_from_payload)?;

		// 8. Store base session key
		self.base_session_key = Some(base_session_key);

		// 9. Transition state to KeyExchangeReceived
		self.state.dispatch(HandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// Complete the handshake and derive the final session key.
	///
	/// # Returns
	/// AES-256-GCM session key
	pub fn complete(&mut self) -> Result<P::AeadCipher, HandshakeError> {
		// 1. Validate current state is KeyExchangeReceived
		self.validate_expected_state(HandshakeState::KeyExchangeReceived)?;

		// 2. Get required values for key derivation
		let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;

		// 3. Derive final session key
		let session_key = self.derive_final_session_key(base_session_key, client_random, server_random)?;

		// 4. Transition to complete state
		self.state.dispatch(HandshakeState::Complete)?;

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
		let digest_arr = P::Digest::digest(&data);
		let mut digest = [0u8; 32];
		digest.copy_from_slice(&digest_arr);
		digest
	}

	fn derive_final_session_key(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		server_random: &[u8; 32],
	) -> Result<P::AeadCipher, HandshakeError> {
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		// Get key size from negotiated profile
		let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
		let key_size = profile.aead_key_size.ok_or(HandshakeError::InvalidState)? as usize;

		// Derive key with dynamic size based on negotiated cipher
		// Use provider's KDF with its concrete digest type
		let final_key_bytes = P::Kdf::derive_dynamic_key(base_key, TIGHTBEAM_SESSION_KDF_INFO, Some(&salt), key_size)?;

		Ok(P::AeadCipher::new_from_slice(&final_key_bytes[..])?)
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
		security_accept: Option<crate::crypto::negotiation::SecurityAccept>,
	) -> Result<Vec<u8>, HandshakeError> {
		let server_handshake = ServerHandshake {
			certificate: self.server_cert.clone(),
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature_bytes)?,
			security_accept,
			client_cert_required: self.client_validators.is_some(),
		};

		Ok(server_handshake.to_der()?)
	}

	pub fn decode_client_key_exchange(&self, der_bytes: &[u8]) -> Result<ClientKeyExchange, HandshakeError> {
		ClientKeyExchange::from_der(der_bytes).map_err(Into::into)
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

	#[cfg(feature = "x509")]
	fn validate_client_certificate(&mut self, client_kex: &ClientKeyExchange) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: Verifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		if let Some(validators) = &self.client_validators {
			// Client cert is required when validators are present
			let client_cert = client_kex
				.client_certificate
				.as_ref()
				.ok_or(HandshakeError::MissingClientCertificate)?;

			// Check for identity immutability - reject if cert changes on re-handshake
			if let Some(existing_cert) = &self.validated_client_cert {
				if existing_cert != client_cert {
					return Err(HandshakeError::PeerIdentityMismatch);
				}
			}

			// Run validator chain (includes expiry, pinning, policy, etc.)
			for (_, validator) in validators.iter().enumerate() {
				validator.evaluate(client_cert)?;
			}

			// Verify client signature over transcript hash
			let client_signature = client_kex
				.client_signature
				.as_ref()
				.ok_or(HandshakeError::SignatureVerificationFailed)?;

			let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

			// Extract public key from client certificate
			let pubkey_bytes = client_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes();

			// Parse public key
			let public_key = PublicKey::<P::Curve>::from_sec1_bytes(pubkey_bytes)?;

			// Parse signature
			let signature = P::Signature::try_from(client_signature.as_bytes())
				.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

			// Create verifying key from public key
			let verifying_key = P::VerifyingKey::from(&public_key);

			// Verify signature over transcript hash
			verifying_key
				.verify(&transcript_hash, &signature)
				.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

			// Store validated cert (identity is now locked)
			self.validated_client_cert = Some(client_cert.clone());
		}

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

impl<P> ServerHandshakeProtocol for EciesHandshakeServer<P>
where
	P: CryptoProvider + Send + Sync,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::VerifyingKey: Verifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	P::AeadCipher: KeyInit + Send + Sync + 'static,
{
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

	#[cfg(feature = "aead")]
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<
		Box<dyn core::future::Future<Output = Result<crate::crypto::aead::RuntimeAead, Self::Error>> + Send + 'a>,
	> {
		Box::pin(async move {
			// 1. Validate current state is KeyExchangeReceived
			self.validate_expected_state(HandshakeState::KeyExchangeReceived)?;

			// 2. Get required values for key derivation
			let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
			let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;

			// 3. Get negotiated profile and AEAD OID
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;

			// 4. Derive final session key as P::AeadCipher (compile-time type known)
			let cipher = self.derive_final_session_key(base_session_key, client_random, server_random)?;

			// 5. Transition to complete state
			self.state.dispatch(HandshakeState::Complete)?;

			// 6. Clear sensitive data
			self.clear_sensitive_data();

			// 7. Wrap cipher in RuntimeAead with negotiated OID
			Ok(crate::crypto::aead::RuntimeAead::new(cipher, aead_oid))
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}

	#[cfg(feature = "x509")]
	fn peer_certificate(&self) -> Option<&Certificate> {
		self.validated_client_cert.as_ref()
	}

	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc> {
		self.selected_profile
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::ecies::encrypt;
	use crate::crypto::negotiation::SecurityOffer;
	use crate::crypto::profiles::SecurityProfileDesc;
	use crate::der::asn1::ObjectIdentifier;
	use crate::random::OsRng;
	use crate::transport::handshake::tests::*;

	fn create_test_client_hello_with_offer(
		client_random: &[u8; 32],
		offer: Option<SecurityOffer>,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		let client_hello = ClientHello {
			client_random: crate::asn1::OctetString::new(*client_random)?,
			security_offer: offer,
		};
		Ok(client_hello.to_der()?)
	}

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

	/// Test profile negotiation modes
	#[test]
	fn test_profile_negotiation() -> Result<(), Box<dyn std::error::Error>> {
		let mk_profile = |id: u8| SecurityProfileDesc {
			digest: match id {
				1 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8"), // SHA3-256
				2 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9"), // SHA3-384
				_ => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10"), // SHA3-512
			},
			#[cfg(feature = "aead")]
			aead: Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46")),
			#[cfg(feature = "aead")]
			aead_key_size: Some(32),
			#[cfg(feature = "signature")]
			signature: Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10")),
			key_wrap: if id % 2 == 0 {
				Some(ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"))
			} else {
				None
			},
		};

		let (p_a, p_b, p_c) = (mk_profile(1), mk_profile(2), mk_profile(3));

		// Mode 1: Negotiation - client offers [A, B], server supports [B, C] → selects B
		{
			let offer = SecurityOffer::new(vec![p_a, p_b]);
			let selected = select_profile(&offer, &[p_b, p_c])?;
			assert_eq!(selected, p_b);

			let mut server = TestEciesServerBuilder::new().build().with_supported_profiles(vec![p_b, p_c]);
			let client_random = [0u8; 32];
			let client_hello_der = create_test_client_hello_with_offer(&client_random, Some(offer.clone()))?;
			let _response = server.process_client_hello(&client_hello_der)?;
			assert_eq!(server.selected_profile, Some(p_b));
		}

		// Mode 2: Dealer's choice - no client offer, server picks first
		{
			let mut server = TestEciesServerBuilder::new().build().with_supported_profiles(vec![p_a, p_b]);
			let client_random = [1u8; 32];
			let client_hello_der = create_test_client_hello(&client_random)?;
			let _response = server.process_client_hello(&client_hello_der)?;
			assert_eq!(server.selected_profile, Some(p_a)); // First in list
		}

		// Error case: No mutual profile
		{
			let offer = SecurityOffer::new(vec![p_a, p_b]);
			let result = select_profile(&offer, &[p_c]);
			assert!(result.is_err());
		}

		Ok(())
	}
}
