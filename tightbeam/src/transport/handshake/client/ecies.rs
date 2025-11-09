//! ECIES-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam ECIES handshake protocol.
//!
//! Generic over `P: CryptoProvider` which defines the complete cryptographic suite,
//! and ECIES message type `M` which is curve-specific.

#![cfg(feature = "x509")]

use core::marker::PhantomData;

use crate::asn1::OctetString;
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::KeyInit;
use crate::crypto::ecies::EciesEphemeral;
use crate::crypto::ecies::{encrypt, EciesMessageOps, EciesPublicKeyOps};
use crate::crypto::hash::Digest;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::SignatureEncoding;
use crate::crypto::sign::Verifier;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::validate_certificate_expiry;
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine};
use crate::transport::handshake::HandshakeFinalization; // for derive_session_aead
use crate::transport::handshake::{Arc, ClientHandshakeProtocol, ClientHello, ClientKeyExchange, ServerHandshake};
use crate::x509::Certificate;

/// Client-side ECIES handshake orchestrator.
///
/// Generic over `P: CryptoProvider` which defines the complete cryptographic suite
/// (curve, signature algorithm, digest, AEAD, KDF), and ECIES message type `M`.
pub struct EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
{
	state: ClientStateMachine,
	client_random: Option<[u8; 32]>,
	base_session_key: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: Option<Vec<u8>>,
	security_offer: Option<crate::crypto::negotiation::SecurityOffer>,
	selected_profile: Option<crate::crypto::profiles::SecurityProfileDesc>,
	certificate_validator: Option<Arc<dyn CertificateValidation>>,
	client_certificate: Option<Arc<Certificate>>,
	client_signing_key: Option<Arc<dyn crate::transport::handshake::ServerHandshakeKey>>,
	_phantom_provider: PhantomData<P>,
	_phantom_message: PhantomData<M>,
	invariants: HandshakeInvariant,
}

/// Helper trait for extracting verifying keys from certificates.
/// This trait exists to work around orphan rules when implementing
/// `TryFrom<&Certificate>` for external types.
pub trait ExtractVerifyingKey: Sized {
	fn extract_from_certificate(cert: &Certificate) -> Result<Self, HandshakeError>;
}

impl<P, M> EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EciesPublicKeyOps,
	<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
	P::Signature: SignatureEncoding,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: Verifier<P::Signature> + ExtractVerifyingKey,
	P::AeadCipher: KeyInit,
	M: EciesMessageOps,
{
	/// Create a new ECIES handshake client.
	///
	/// # Parameters
	/// - `aad_domain_tag`: Optional domain tag for ECIES encryption (defaults to "tb-v1")
	pub fn new(aad_domain_tag: Option<Vec<u8>>) -> Self {
		Self {
			state: ClientStateMachine::new(),
			client_random: None,
			base_session_key: None,
			server_random: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.or_else(|| Some(TIGHTBEAM_AAD_DOMAIN_TAG.to_vec())),
			security_offer: None, // No offer = dealer's choice mode
			selected_profile: None,
			certificate_validator: None,
			client_certificate: None,
			client_signing_key: None,
			_phantom_provider: PhantomData,
			_phantom_message: PhantomData,
			invariants: HandshakeInvariant::default(),
		}
	}

	/// Set a certificate validator for the handshake.
	pub fn with_certificate_validator(mut self, validator: Arc<dyn CertificateValidation>) -> Self {
		self.certificate_validator = Some(validator);
		self
	}

	/// Set client identity for mutual authentication.
	///
	/// # Parameters
	/// - `certificate`: The client's X.509 certificate
	/// - `signing_key`: The client's signing key (must match certificate)
	pub fn with_client_identity(
		mut self,
		certificate: Certificate,
		signing_key: Arc<dyn crate::transport::handshake::ServerHandshakeKey>,
	) -> Self {
		self.client_certificate = Some(Arc::new(certificate));
		self.client_signing_key = Some(signing_key);
		self
	}

	/// Set the security profile offer for negotiation.
	/// If not set, server will pick default profile (dealer's choice mode).
	pub fn with_security_offer(mut self, offer: crate::crypto::negotiation::SecurityOffer) -> Self {
		self.security_offer = Some(offer);
		self
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		if self.state.state() != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	/// Validate server handshake and extract components.
	fn validate_and_extract_server_handshake(
		&self,
		server_handshake_der: &[u8],
	) -> Result<ServerHandshake, HandshakeError> {
		// Decode ServerHandshake
		let server_handshake = ServerHandshake::from_der(server_handshake_der)?;

		// Use provided validator if available, otherwise default to expiry check
		if let Some(validator) = &self.certificate_validator {
			validator.evaluate(&server_handshake.certificate)?;
		} else {
			validate_certificate_expiry(&server_handshake.certificate)?;
		}

		Ok(server_handshake)
	}

	/// Extract and store server random from handshake.
	fn extract_server_random(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let server_random = self.octet_string_to_array(&server_handshake.server_random)?;
		self.server_random = Some(server_random);

		Ok(())
	}

	/// Compute and store transcript hash.
	fn compute_and_store_transcript_hash(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.ok_or(HandshakeError::InvalidState)?;
		let subject_public_key_info_bytes = server_handshake
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		let transcript_digest =
			self.compute_transcript_hash(&client_random, &server_random, subject_public_key_info_bytes);
		self.transcript_hash = Some(transcript_digest);
		// Invariant: transcript becomes immutable after hash computed
		self.invariants.lock_transcript()?;

		Ok(())
	}

	/// Generate and store base session key.
	fn generate_base_session_key(&mut self) -> Result<(), HandshakeError> {
		let base_key = generate_nonce::<32>(None)?;
		self.base_session_key = Some(base_key);

		Ok(())
	}

	/// Build ClientHello message.
	///
	/// # Returns
	/// DER-encoded ClientHello
	pub fn build_client_hello(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::Init)?;

		// 2. Generate client random
		let client_random = generate_nonce::<32>(None)?;
		self.client_random = Some(client_random);

		// 3. Build ClientHello
		let client_hello = ClientHello {
			client_random: OctetString::new(client_random)?,
			security_offer: self.security_offer.clone(),
		};

		// Transition: mark hello sent
		self.state.transition(ClientHandshakeState::HelloSent)?;
		Ok(client_hello.to_der()?)
	}

	/// Process ServerHandshake message and build ClientKeyExchange.
	///
	/// # Parameters
	/// - `server_handshake_der`: DER-encoded ServerHandshake from server
	///
	/// # Returns
	/// DER-encoded ClientKeyExchange
	pub fn process_server_handshake(&mut self, server_handshake_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation: must have sent hello
		self.validate_expected_state(ClientHandshakeState::HelloSent)?;
		let _client_random_check = self.client_random.ok_or(HandshakeError::InvalidState)?;

		// 2. Decode and validate server handshake
		let server_handshake = self.validate_and_extract_server_handshake(server_handshake_der)?;

		// 3. Validate profile negotiation
		self.validate_profile_selection(&server_handshake)?;

		// 4. Extract server random
		self.extract_server_random(&server_handshake)?;

		// 5. Verify server signature
		self.verify_server_handshake_signature(&server_handshake)?;

		// 6. Generate and encrypt session key
		let encrypted_bytes = self.generate_and_encrypt_session_key(&server_handshake)?;

		// 7. Handle mutual authentication
		let (client_certificate, client_signature) = self.prepare_client_auth(&server_handshake)?;

		// 8. Build and encode ClientKeyExchange
		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		};

		// 9. Transition through intermediate ServerHelloReceived then KeyExchangeSent
		self.state.transition(ClientHandshakeState::ServerHelloReceived)?;
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(client_kex.to_der()?)
	}

	/// Validate server's profile selection against client's offer.
	///
	/// Handles both negotiation mode (client sent offer) and dealer's choice mode (no offer).
	fn validate_profile_selection(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let accept = server_handshake.security_accept.as_ref().ok_or(HandshakeError::InvalidState)?;

		match &self.security_offer {
			Some(offer) => {
				// Mode 1: Negotiation - verify server's selection is from our offer
				if !offer.profiles.contains(&accept.profile) {
					return Err(HandshakeError::InvalidProfileSelection);
				}
				self.selected_profile = Some(accept.profile);
			}
			None => {
				// Mode 2: Dealer's choice - accept whatever server picked
				self.selected_profile = Some(accept.profile);
			}
		}

		Ok(())
	}

	/// Verify server's signature over the transcript hash.
	fn verify_server_handshake_signature(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let verifying_key = self.extract_verifying_key(&server_handshake.certificate)?;
		self.compute_and_store_transcript_hash(server_handshake)?;
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		self.verify_server_signature(&verifying_key, &transcript_digest, server_handshake.signature.as_bytes())
	}

	/// Generate base session key and encrypt with server's public key.
	fn generate_and_encrypt_session_key(
		&mut self,
		server_handshake: &ServerHandshake,
	) -> Result<Vec<u8>, HandshakeError> {
		self.generate_base_session_key()?;
		let base_key = self.base_session_key.ok_or(HandshakeError::InvalidState)?;
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;

		self.perform_ecies_encryption(
			&base_key,
			&client_random,
			&server_handshake.certificate,
			self.aad_domain_tag.as_deref(),
		)
	}

	/// Prepare client authentication materials if required or available.
	///
	/// Returns tuple of (optional certificate, optional signature).
	fn prepare_client_auth(
		&self,
		server_handshake: &ServerHandshake,
	) -> Result<(Option<Certificate>, Option<OctetString>), HandshakeError> {
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		if server_handshake.client_cert_required {
			// Server requires mutual auth - ensure we have client identity
			let cert = self.client_certificate.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
			let signing_key = self.client_signing_key.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;

			let signature_bytes = signing_key.sign_server_challenge(&transcript_digest)?;
			Ok((Some((**cert).clone()), Some(OctetString::new(signature_bytes)?)))
		} else if let Some(cert) = &self.client_certificate {
			// Client wants mutual auth but server doesn't require it - include anyway
			let signing_key = self.client_signing_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let signature_bytes = signing_key.sign_server_challenge(&transcript_digest)?;
			Ok((Some((**cert).clone()), Some(OctetString::new(signature_bytes)?)))
		} else {
			// No mutual auth
			Ok((None, None))
		}
	}
	/// Complete the handshake and derive the final session key.
	///
	/// # Returns
	/// AEAD cipher session key from the provider
	pub fn complete(&mut self) -> Result<P::AeadCipher, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Derive final session key
		let base_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;

		// Concatenate client_random || server_random as salt for AEAD derivation
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);
		let session_key = self.derive_session_aead(base_key, &salt)?;
		// Invariant: AEAD key derivation occurs exactly once after transcript locked
		self.invariants.derive_aead_once()?;

		// 3. Transition to complete
		self.state.transition(ClientHandshakeState::Completed)?;

		// 4. Clear sensitive data
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
	pub fn state(&self) -> ClientHandshakeState {
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

	fn extract_verifying_key(&self, cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		P::VerifyingKey::extract_from_certificate(cert)
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

	fn verify_server_signature(
		&self,
		verifying_key: &P::VerifyingKey,
		digest: &[u8; 32],
		signature_bytes: &[u8],
	) -> Result<(), HandshakeError> {
		let signature = P::Signature::try_from(signature_bytes).map_err(|e| e.into())?;

		verifying_key.verify(digest, &signature)?;

		Ok(())
	}

	fn perform_ecies_encryption(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		server_certificate: &Certificate,
		associated_data: Option<&[u8]>,
	) -> Result<Vec<u8>, HandshakeError> {
		let mut plaintext = [0u8; 64];
		plaintext[..32].copy_from_slice(base_key);
		plaintext[32..].copy_from_slice(client_random);

		let recipient_pubkey = PublicKey::<P::Curve>::from_sec1_bytes(
			server_certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		let encrypted_message =
			encrypt::<_, _, _, M>(&recipient_pubkey, &plaintext, associated_data, Some(&mut rand_core::OsRng))?;

		Ok(encrypted_message.to_bytes())
	}
}

// ============================================================================
// Common Handshake Trait Implementations
// ============================================================================

impl<P, M> crate::transport::handshake::HandshakeFinalization<P> for EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P, M> crate::transport::handshake::HandshakeAlertHandler for EciesHandshakeClient<P, M> where P: CryptoProvider {}

// ============================================================================
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<P, M> ClientHandshakeProtocol for EciesHandshakeClient<P, M>
where
	P: CryptoProvider + Send + Sync,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EciesPublicKeyOps,
	<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
	P::Signature: SignatureEncoding + Send + Sync,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: Verifier<P::Signature> + ExtractVerifyingKey + Send + Sync,
	P::AeadCipher: KeyInit + Send + Sync + 'static,
	M: EciesMessageOps + Send + Sync,
{
	type Error = HandshakeError;

	fn start<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a>> {
		Box::pin(async move { self.build_client_hello() })
	}

	fn handle_response<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a,
	{
		Box::pin(async move {
			// Process server handshake and build client key exchange
			let client_kex = self.process_server_handshake(msg)?;
			Ok(Some(client_kex))
		})
	}

	#[cfg(feature = "aead")]
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<
		Box<dyn core::future::Future<Output = Result<crate::crypto::aead::RuntimeAead, Self::Error>> + Send + 'a>,
	> {
		Box::pin(async move {
			if self.state.state() != ClientHandshakeState::KeyExchangeSent {
				return Err(HandshakeError::InvalidState);
			}
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;
			let base_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
			let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;
			let mut salt = [0u8; 64];
			salt[..32].copy_from_slice(client_random);
			salt[32..].copy_from_slice(server_random);
			let cipher = self.derive_session_aead(base_key, &salt)?;
			self.state.transition(ClientHandshakeState::Completed)?;
			if let Some(mut bk) = self.base_session_key.take() {
				bk.fill(0);
			}
			if let Some(mut cr) = self.client_random.take() {
				cr.fill(0);
			}
			if let Some(mut sr) = self.server_random.take() {
				sr.fill(0);
			}
			Ok(crate::crypto::aead::RuntimeAead::new(cipher, aead_oid))
		})
	}

	fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc> {
		self.selected_profile
	}
}

// ============================================================================
// Type Alias for secp256k1
// ============================================================================

/// Type alias for ECIES client using secp256k1 curve.
///
/// This is the default curve used in TightBeam and is provided as a
/// convenient alias for the generic `EciesHandshakeClient`.
#[cfg(feature = "secp256k1")]
pub type EciesHandshakeClientSecp256k1 =
	EciesHandshakeClient<crate::crypto::profiles::DefaultCryptoProvider, crate::crypto::ecies::Secp256k1EciesMessage>;

// Implement helper trait for secp256k1 verifying key
#[cfg(feature = "secp256k1")]
impl ExtractVerifyingKey for crate::crypto::sign::ecdsa::Secp256k1VerifyingKey {
	fn extract_from_certificate(cert: &Certificate) -> Result<Self, HandshakeError> {
		let spki = &cert.tbs_certificate.subject_public_key_info;
		let public_key_bytes = spki.subject_public_key.raw_bytes();
		let public_key = k256::PublicKey::from_sec1_bytes(public_key_bytes)?;
		Ok(Self::from(public_key))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::sign::Signer;
	use crate::transport::handshake::tests::*;

	#[test]
	fn test_client_state_flow() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A client in init state
		let mut client = TestEciesClientBuilder::new().build();
		assert_eq!(client.state(), ClientHandshakeState::Init);

		// When: Client builds client hello
		let _client_hello_der = client.build_client_hello()?;
		assert_eq!(client.state(), ClientHandshakeState::HelloSent); // Hello sent
		assert!(client.client_random.is_some());

		// And: Server creates a valid server handshake response
		let test_cert = create_test_certificate();
		let client_random = client.client_random.unwrap();
		let server_random = crate::random::generate_nonce::<32>(None)?;
		let transcript_hash = compute_test_transcript_hash(
			&client_random,
			&server_random,
			test_cert
				.certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		);

		let signature_bytes: crate::crypto::sign::ecdsa::Secp256k1Signature =
			test_cert.signing_key.try_sign(&transcript_hash)?;
		let server_handshake_der =
			create_test_server_handshake(&test_cert.certificate, &server_random, &signature_bytes.to_bytes())?;

		// When: Client processes the server handshake
		let client_kex_der = client.process_server_handshake(&server_handshake_der)?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert!(client.base_session_key.is_some());
		assert!(client.transcript_hash.is_some());

		// And: Client key exchange message is valid
		let _client_kex = ClientKeyExchange::from_der(&client_kex_der)?;
		// When: Client completes the handshake
		let _session_key = client.complete()?;

		// Then: Handshake is complete
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);

		Ok(())
	}

	#[test]
	fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A fresh client in init state
		let mut client = TestEciesClientBuilder::new().build();

		// When: Trying to process server handshake before building client hello
		let result = client.process_server_handshake(&[]);
		assert!(result.is_err());

		// When: Client builds client hello
		let _client_hello = client.build_client_hello()?;
		assert_eq!(client.state(), ClientHandshakeState::HelloSent);

		// When: Trying to complete before processing server handshake
		let result = client.complete();
		assert!(result.is_err());

		Ok(())
	}

	/// Test client-side profile validation
	#[test]
	fn test_client_profile_validation() -> Result<(), Box<dyn std::error::Error>> {
		use crate::crypto::negotiation::{SecurityAccept, SecurityOffer};
		use crate::crypto::profiles::SecurityProfileDesc;
		use crate::der::Encode;
		use crate::transport::handshake::ServerHandshake;

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
		let test_cert = create_test_certificate();

		// Test 1: Client offers [A, B], server accepts B → OK
		{
			let mut client = TestEciesClientBuilder::new()
				.build()
				.with_security_offer(SecurityOffer::new(vec![p_a, p_b]));
			let _hello = client.build_client_hello()?;

			// Get the actual client random that was generated
			let client_random = client.client_random.ok_or("No client random")?;
			let server_random = [2u8; 32];
			let transcript_hash = compute_test_transcript_hash(
				&client_random,
				&server_random,
				test_cert
					.certificate
					.tbs_certificate
					.subject_public_key_info
					.subject_public_key
					.raw_bytes(),
			);
			let signature: crate::crypto::sign::ecdsa::Secp256k1Signature =
				test_cert.signing_key.try_sign(&transcript_hash)?;
			let signature_bytes = signature.to_bytes().to_vec();

			let response = ServerHandshake {
				certificate: test_cert.certificate.clone(),
				server_random: crate::asn1::OctetString::new(server_random)?,
				signature: crate::asn1::OctetString::new(signature_bytes)?,
				security_accept: Some(SecurityAccept::new(p_b)),
				client_cert_required: false,
			};
			let _kex = client.process_server_handshake(&response.to_der()?)?;
			assert_eq!(client.selected_profile, Some(p_b));
		}

		// Test 2: Client offers [A, B], server accepts C (not in offer) → FAIL
		{
			let mut client = TestEciesClientBuilder::new()
				.build()
				.with_security_offer(SecurityOffer::new(vec![p_a, p_b]));
			let _hello = client.build_client_hello()?;

			let client_random = client.client_random.ok_or("No client random")?;
			let server_random = [3u8; 32];
			let transcript_hash = compute_test_transcript_hash(
				&client_random,
				&server_random,
				test_cert
					.certificate
					.tbs_certificate
					.subject_public_key_info
					.subject_public_key
					.raw_bytes(),
			);
			let signature: crate::crypto::sign::ecdsa::Secp256k1Signature =
				test_cert.signing_key.try_sign(&transcript_hash)?;
			let signature_bytes = signature.to_bytes().to_vec();

			let response = ServerHandshake {
				certificate: test_cert.certificate.clone(),
				server_random: crate::asn1::OctetString::new(server_random)?,
				signature: crate::asn1::OctetString::new(signature_bytes)?,
				security_accept: Some(SecurityAccept::new(p_c)), // Not in offer!
				client_cert_required: false,
			};
			let result = client.process_server_handshake(&response.to_der()?);
			assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
		}

		// Test 3: No offer, server picks → OK (dealer's choice)
		{
			let mut client = TestEciesClientBuilder::new().build();
			let _hello = client.build_client_hello()?;

			let client_random = client.client_random.ok_or("No client random")?;
			let server_random = [4u8; 32];
			let transcript_hash = compute_test_transcript_hash(
				&client_random,
				&server_random,
				test_cert
					.certificate
					.tbs_certificate
					.subject_public_key_info
					.subject_public_key
					.raw_bytes(),
			);
			let signature: crate::crypto::sign::ecdsa::Secp256k1Signature =
				test_cert.signing_key.try_sign(&transcript_hash)?;
			let signature_bytes = signature.to_bytes().to_vec();

			let response = ServerHandshake {
				certificate: test_cert.certificate.clone(),
				server_random: crate::asn1::OctetString::new(server_random)?,
				signature: crate::asn1::OctetString::new(signature_bytes)?,
				security_accept: Some(SecurityAccept::new(p_a)),
				client_cert_required: false,
			};
			let _kex = client.process_server_handshake(&response.to_der()?)?;
			assert_eq!(client.selected_profile, Some(p_a));
		}

		Ok(())
	}
}
