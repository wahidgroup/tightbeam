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
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::KeyInit;
use crate::crypto::hash::Digest;
use crate::crypto::negotiation::SecurityAccept;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::Verifier;
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::{
	ClientHello, ClientKeyExchange, ServerHandshake, ServerHandshakeKey, ServerHandshakeProtocol,
};
use crate::transport::handshake::{HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation};
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
	state: ServerStateMachine,
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
	invariants: HandshakeInvariant,
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
			state: ServerStateMachine::new(),
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
			invariants: HandshakeInvariant::default(),
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
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Decode ClientHello message
		let client_hello = self.decode_client_hello(client_hello_der)?;

		// 3. Profile negotiation using trait method
		let selected = self.negotiate_profile(client_hello.security_offer.as_ref())?;
		self.selected_profile = Some(selected);
		let security_accept = SecurityAccept::new(selected);

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
		if let Err(e) = self.invariants.lock_transcript() {
			return Err(e);
		}

		// 7. Sign transcript hash
		let signature_bytes = self.sign_transcript_hash(&transcript_digest)?;

		// 8. Build and encode ServerHandshake
		let server_handshake_der =
			self.build_server_handshake(server_random, signature_bytes, Some(security_accept))?;

		// 9. Transition state through ServerHelloReceived to ServerHelloSent
		self.state.transition(ServerHandshakeState::ClientHelloReceived)?;
		self.state.transition(ServerHandshakeState::ServerHelloSent)?;

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
		self.validate_expected_state(ServerHandshakeState::ServerHelloSent)?;

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
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// Complete the handshake and derive the final session key.
	///
	/// # Returns
	/// AES-256-GCM session key
	pub fn complete(&mut self) -> Result<P::AeadCipher, HandshakeError> {
		// 1. Validate current state is KeyExchangeReceived
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)?;

		// 2. Get required values for key derivation
		let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;

		// 3. Derive final session key using trait finalization (client_random || server_random)
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);
		let session_key = self.derive_session_aead(base_session_key, &salt)?;
		if let Err(e) = self.invariants.derive_aead_once() {
			return Err(e);
		}

		// 4. Transition to complete state
		self.state.transition(ServerHandshakeState::Completed)?;

		// 5. Clear sensitive data
		self.clear_sensitive_data();

		Ok(session_key)
	}

	/// Get the current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
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

	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
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

			// Check for identity immutability
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
// Common Handshake Trait Implementations
// ============================================================================

impl<P> HandshakeNegotiation for EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn supported_profiles(&self) -> &[SecurityProfileDesc] {
		&self.supported_profiles
	}
}

impl<P> HandshakeFinalization<P> for EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for EciesHandshakeServer<P> where P: CryptoProvider {}

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
				ServerHandshakeState::Init => {
					// This is ClientHello - respond with ServerHandshake
					let server_handshake = self.process_client_hello(msg)?;
					Ok(Some(server_handshake))
				}
				ServerHandshakeState::ServerHelloSent => {
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
			self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)?;

			// 2. Get required values for key derivation
			let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
			let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;

			// 3. Get negotiated profile and AEAD OID
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;

			// 4. Derive final session key as P::AeadCipher (client_random || server_random)
			let mut salt = [0u8; 64];
			salt[..32].copy_from_slice(client_random);
			salt[32..].copy_from_slice(server_random);
			let cipher = self.derive_session_aead(base_session_key, &salt)?;

			// 5. Transition to complete state
			self.state.transition(ServerHandshakeState::Completed)?;

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
	use crate::crypto::negotiation::{select_profile, SecurityOffer};
	use crate::crypto::profiles::SecurityProfileDesc;
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

	/// Test the full server state flow through a complete handshake.
	///
	/// Verifies that the server correctly transitions through all states:
	/// Init → ServerHelloSent → KeyExchangeReceived → Complete
	#[test]
	fn test_server_state_flow() -> Result<(), Box<dyn std::error::Error>> {
		let mut server = TestEciesServerBuilder::new().build();
		assert_eq!(server.state(), ServerHandshakeState::Init);

		// Process ClientHello
		let client_random = crate::random::generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		let server_handshake_der = server.process_client_hello(&client_hello_der)?;

		assert_eq!(server.state(), ServerHandshakeState::ServerHelloSent);
		assert!(server.client_random.is_some());
		assert!(server.server_random.is_some());
		assert!(server.transcript_hash.is_some());

		// Verify server handshake message is valid
		let _server_handshake = ServerHandshake::from_der(&server_handshake_der)?;

		// Process ClientKeyExchange
		let client_kex_der = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(&client_kex_der)?;
		assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
		assert!(server.base_session_key.is_some());

		// Complete handshake
		let _session_key = server.complete()?;
		assert!(server.is_complete());
		assert_eq!(server.state(), ServerHandshakeState::Completed);

		Ok(())
	}

	/// Test that state transitions are properly enforced.
	///
	/// Verifies that operations fail when called in the wrong state.
	#[test]
	fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
		let mut server = TestEciesServerBuilder::new().build();

		// Cannot process client key exchange before client hello
		assert!(server.process_client_key_exchange(&[]).is_err());

		// Cannot complete before any handshake steps
		assert!(server.complete().is_err());

		// Process client hello to advance state
		let client_random = crate::random::generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der)?;

		// Cannot process client hello again
		assert!(server.process_client_hello(&client_hello_der).is_err());

		// Cannot complete before client key exchange
		assert!(server.complete().is_err());

		// Process client key exchange to advance state
		let client_kex_der = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(&client_kex_der)?;

		// Cannot process client key exchange again
		assert!(server.process_client_key_exchange(&client_kex_der).is_err());

		// Cannot process client hello after key exchange
		assert!(server.process_client_hello(&client_hello_der).is_err());

		Ok(())
	}

	/// Test profile negotiation modes (negotiation vs dealer's choice).
	///
	/// Verifies that the server correctly handles both explicit client offers
	/// and dealer's choice mode when no offer is present.
	#[test]
	fn test_profile_negotiation() -> Result<(), Box<dyn std::error::Error>> {
		use crate::asn1::{
			AES_256_GCM_OID, AES_256_WRAP_OID, HASH_SHA3_256_OID, HASH_SHA3_384_OID, HASH_SHA3_512_OID,
			SIGNER_ECDSA_WITH_SHA3_512_OID,
		};

		let mk_profile = |id: u8| SecurityProfileDesc {
			digest: match id {
				1 => HASH_SHA3_256_OID,
				2 => HASH_SHA3_384_OID,
				_ => HASH_SHA3_512_OID,
			},
			#[cfg(feature = "aead")]
			aead: Some(AES_256_GCM_OID),
			#[cfg(feature = "aead")]
			aead_key_size: Some(32),
			#[cfg(feature = "signature")]
			signature: Some(SIGNER_ECDSA_WITH_SHA3_512_OID),
			key_wrap: if id % 2 == 0 {
				Some(AES_256_WRAP_OID)
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

	// ========================================================================
	// Test Helper Functions
	// ========================================================================

	/// Build a test ClientKeyExchange with ECIES-encrypted session key.
	///
	/// Extracts the server's public key and stored client random, then creates
	/// a properly encrypted payload containing [session_key || client_random].
	fn build_test_client_key_exchange<P>(
		server: &EciesHandshakeServer<P>,
	) -> Result<Vec<u8>, Box<dyn std::error::Error>>
	where
		P: CryptoProvider,
	{
		use crate::crypto::ecies::encrypt;

		// Extract server's public key from certificate
		let server_pubkey = k256::PublicKey::from_sec1_bytes(
			server
				.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		// Use the stored client_random from the server
		let stored_client_random = server.client_random.ok_or("Missing client random")?;
		let base_session_key = crate::random::generate_nonce::<32>(None)?;

		// Build plaintext: [session_key || client_random]
		let mut plaintext = [0u8; 64];
		plaintext[..32].copy_from_slice(&base_session_key);
		plaintext[32..].copy_from_slice(&stored_client_random);

		// Encrypt with ECIES
		let encrypted_message = encrypt::<_, _, _, crate::crypto::ecies::Secp256k1EciesMessage>(
			&server_pubkey,
			&plaintext,
			Some(b"test-domain"),
			Some(&mut OsRng),
		)?;

		// Build ClientKeyExchange message
		create_test_client_key_exchange(&encrypted_message.to_bytes())
	}
}
