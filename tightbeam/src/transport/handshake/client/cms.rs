//! CMS-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam handshake protocol using
//! CMS builders and processors.

use core::future::Future;
use core::pin::Pin;

use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::cms::{cert::IssuerAndSerialNumber, signed_data::SignerIdentifier};
use crate::crypto::aead::KeyInit;
use crate::crypto::negotiation::SecurityOffer;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile, SecurityProfileDesc};
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::crypto::sign::EcdsaSignatureVerifier;
use crate::crypto::sign::SignatureAlgorithmIdentifier;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::validate_certificate_expiry;
use crate::crypto::x509::Certificate;
use crate::der::oid::AssociatedOid;
use crate::der::Decode;
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::builders::{
	TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine};
use crate::transport::handshake::{Arc, ClientHandshakeProtocol};

/// Client-side CMS handshake orchestrator.
///
/// Generic over `P: CryptoProvider` which defines the complete cryptographic suite
/// (curve, signature algorithm, digest, AEAD, KDF).
///
/// Manages the complete client handshake flow:
/// 1. Sends KeyExchange (EnvelopedData with KARI)
/// 2. Receives and verifies server Finished (SignedData)
/// 3. Sends client Finished (SignedData)
///
/// Supports cryptographic profile negotiation via optional `security_offer` field.
pub struct CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	state: ClientStateMachine,
	client_key: P::SigningKey,
	client_certificate: Option<Certificate>,
	server_cert: Certificate,
	transcript_hash: Option<[u8; 32]>,
	session_key: Option<Secret<Vec<u8>>>,
	security_offer: Option<SecurityOffer>,
	selected_profile: Option<SecurityProfileDesc>,
	provider: P,
	certificate_validator: Option<Arc<dyn CertificateValidation>>,
	invariants: HandshakeInvariant,
}

impl<P> CmsHandshakeClient<P>
where
	P: CryptoProvider,
	P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::SigningKey: Clone + signature::Keypair + 'static,
	<P::SigningKey as signature::Keypair>::VerifyingKey: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: 'static,
	P::AeadCipher: KeyInit,
{
	/// Create a new CMS handshake client.
	///
	/// # Parameters
	/// - `provider`: The cryptographic provider defining the security profile
	/// - `client_key`: The client's signing key for authentication
	/// - `server_cert`: The server's certificate (for key agreement)
	/// - `transcript_hash`: The handshake transcript hash (32 bytes)
	pub fn new(provider: P, client_key: P::SigningKey, server_cert: Certificate, transcript_hash: [u8; 32]) -> Self {
		Self {
			state: ClientStateMachine::new(),
			client_key,
			client_certificate: None,
			server_cert,
			transcript_hash: Some(transcript_hash),
			session_key: None,
			security_offer: None,
			selected_profile: None,
			provider,
			certificate_validator: None,
			invariants: HandshakeInvariant::default(),
		}
	}

	/// Set a certificate validator for the handshake.
	pub fn with_certificate_validator(mut self, validator: Arc<dyn CertificateValidation>) -> Self {
		self.certificate_validator = Some(validator);
		self
	}

	/// Set client certificate for mutual authentication.
	pub fn with_client_certificate(mut self, certificate: Certificate) -> Self {
		self.client_certificate = Some(certificate);
		self
	}

	/// Configures the security offer for negotiation.
	///
	/// When configured, the client will send this offer to the server,
	/// and the server will select a mutually supported profile.
	#[must_use]
	pub fn with_security_offer(mut self, offer: SecurityOffer) -> Self {
		self.security_offer = Some(offer);
		self
	}

	/// Get the selected security profile after negotiation.
	///
	/// Returns `None` if no negotiation occurred or not yet determined.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		if self.state.state() != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	/// Validate state and server certificate for key exchange.
	fn validate_state_and_certificate(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::Init)?;

		// Use provided validator if available, otherwise default to expiry check
		if let Some(validator) = &self.certificate_validator {
			validator.evaluate(&self.server_cert)?;
		} else {
			validate_certificate_expiry(&self.server_cert)?;
		}

		Ok(())
	}

	/// Extract the server's public key from certificate.
	fn extract_server_public_key(&self) -> Result<PublicKey<P::Curve>, HandshakeError> {
		Ok(PublicKey::<P::Curve>::from_sec1_bytes(
			self.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?)
	}

	/// Create ephemeral keypair for the sender.
	fn create_ephemeral_keypair(&self) -> Result<(SecretKey<P::Curve>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let sender_ephemeral = SecretKey::<P::Curve>::random(&mut OsRng);
		let sender_public = sender_ephemeral.public_key();
		let sender_pub_spki = sender_public.to_public_key_der()?;
		let sender_pub_spki = SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes())?;

		Ok((sender_ephemeral, sender_pub_spki))
	}

	/// Build the recipient identifier from server certificate.
	fn build_recipient_identifier(&self) -> KeyAgreeRecipientIdentifier {
		KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
			issuer: self.server_cert.tbs_certificate.issuer.clone(),
			serial_number: self.server_cert.tbs_certificate.serial_number.clone(),
		})
	}

	/// Extract the server's verifying key from a certificate or similar.
	fn extract_server_verifying_key(&self, server_cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		let server_public_key = PublicKey::<P::Curve>::from_sec1_bytes(
			server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;
		Ok(P::VerifyingKey::from(server_public_key))
	}

	/// Compute the signer identifier from the server's verifying key.
	fn compute_signer_identifier(&self, verifying_key: &P::VerifyingKey) -> Result<SignerIdentifier, HandshakeError> {
		Ok(crate::crypto::x509::utils::compute_signer_identifier::<P::Digest, _>(
			verifying_key,
		)?)
	}

	/// Verify the signature and content of the SignedData.
	fn verify_signature(
		&self,
		signed_data_der: &[u8],
		server_verifying_key: P::VerifyingKey,
		expected_sid: SignerIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		let verifier = EcdsaSignatureVerifier::<P::VerifyingKey, P::Signature, P::Digest>::from_verifying_key_with_sid(
			server_verifying_key,
			expected_sid,
		);
		let processor = TightBeamSignedDataProcessor::new(verifier);

		// Verify content matches our transcript hash
		let digest_oid = P::Digest::OID;
		let verified_content = processor.process_der(signed_data_der, &digest_oid)?;

		let expected_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		if verified_content.len() != 32 || verified_content.as_slice() != &expected_hash {
			Err(HandshakeError::SignatureVerificationFailed)
		} else {
			Ok(verified_content)
		}
	}

	/// Build KeyExchange message (EnvelopedData with KARI containing session key).
	///
	/// # Parameters
	/// - `session_key`: The session key to wrap and send
	///
	/// # Returns
	/// DER-encoded EnvelopedData
	pub fn build_key_exchange(&mut self, session_key: Vec<u8>) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		// Accept both Init (fresh) or HelloSent (if future hello phase added)
		if self.state.state() == ClientHandshakeState::Init {
			self.validate_state_and_certificate()?;
		} else if self.state.state() != ClientHandshakeState::HelloSent {
			return Err(HandshakeError::InvalidState);
		}

		// 2. Extract cryptographic material
		let server_public_key = self.extract_server_public_key()?;
		let (sender_ephemeral, sender_pub_spki) = self.create_ephemeral_keypair()?;

		// 3. Create UKM (user keying material)
		let ukm_bytes = generate_nonce::<64>(None)?;
		let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

		// 4. Build recipient identifier
		let rid = self.build_recipient_identifier();

		// 5. Key encryption algorithm from provider (ECDH + HKDF + key wrap)
		let key_wrap_oid = self
			.provider
			.profile()
			.key_wrap_oid()
			.ok_or(HandshakeError::MissingKeyWrapAlgorithm)?;
		let key_enc_alg = AlgorithmIdentifierOwned { oid: key_wrap_oid, parameters: None };

		// 6. Build KARI (Key Agreement Recipient Info) structure
		let kari_builder = TightBeamKariBuilder::new(self.provider.clone())
			.with_sender_priv(sender_ephemeral)
			.with_sender_pub_spki(sender_pub_spki)
			.with_recipient_pub(server_public_key)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		// 7. Create EnvelopedData builder with generic curve type
		let mut enveloped_builder = TightBeamEnvelopedDataBuilder::new(kari_builder);
		enveloped_builder = enveloped_builder.with_content_encryption_alg(self.provider.to_aead_algorithm_identifier());

		// 8. Add SecurityOffer as unprotected attribute if configured
		if let Some(ref offer) = self.security_offer {
			let offer_attr = crate::transport::handshake::attributes::encode_security_offer(offer)?;
			enveloped_builder = enveloped_builder.with_unprotected_attr(offer_attr);
		}

		// 9. Build and encode
		let enveloped_data_der = enveloped_builder.build_der(&session_key, None)?;

		// 10. Store session key and transition state
		self.session_key = Some(Secret::from(session_key));
		// Transition directly from Init -> KeyExchangeSent (CMS path) or HelloSent -> KeyExchangeSent
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(enveloped_data_der)
	}

	/// Process server Finished message (SignedData over transcript hash).
	///
	/// # Parameters
	/// - `signed_data_der`: DER-encoded SignedData from server
	///
	/// # Returns
	/// Verified transcript hash
	pub fn process_server_finished(&mut self, signed_data_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Extract cryptographic material
		let server_verifying_key = self.extract_server_verifying_key(&self.server_cert)?;
		let expected_signer_identifier = self.compute_signer_identifier(&server_verifying_key)?;

		// 3. Verify signature and content
		let verified_content =
			self.verify_signature(signed_data_der, server_verifying_key, expected_signer_identifier)?;

		// 4. Transition state & lock transcript (transcript hash verified)
		self.state.transition(ClientHandshakeState::ServerFinishedReceived)?;
		self.invariants.lock_transcript()?;

		Ok(verified_content)
	}

	/// Build client Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub fn build_client_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::ServerFinishedReceived)?;

		// 2. Algorithm identifiers
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };

		// 3. Get transcript hash
		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		// 4. Build SignedData
		let mut builder = TightBeamSignedDataBuilder::<P>::new(self.client_key.clone(), digest_alg, signature_alg)?;
		let signed_data_der = builder.build_der(&transcript_hash)?;

		// 5. Transition state & mark finished sent invariant
		self.state.transition(ClientHandshakeState::ClientFinishedSent)?;
		self.invariants.mark_finished_sent()?;

		Ok(signed_data_der)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::ClientFinishedSent)?;

		// 2. Transition to complete
		self.state.transition(ClientHandshakeState::Completed)?;

		Ok(())
	}

	/// Get the current handshake state.
	pub fn state(&self) -> ClientHandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// Get the session key (if available).
	///
	/// Returns a reference to the Secret-wrapped session key bytes.
	pub fn session_key(&self) -> Option<&Secret<Vec<u8>>> {
		self.session_key.as_ref()
	}
}

// ============================================================================
// Common Handshake Trait Implementations
// ============================================================================

impl<P> crate::transport::handshake::HandshakeFinalization<P> for CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P> crate::transport::handshake::HandshakeAlertHandler for CmsHandshakeClient<P> where P: CryptoProvider {}

// ============================================================================
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<P> ClientHandshakeProtocol for CmsHandshakeClient<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: Curve + CurveArithmetic + Send + Sync,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::SigningKey: Send + Clone + signature::Keypair + 'static,
	<P::SigningKey as signature::Keypair>::VerifyingKey: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: 'static,
	P::AeadCipher: Send + Sync + KeyInit,
{
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a>> {
		Box::pin(async move { self.build_key_exchange(vec![0u8; 32]) })
	}

	fn handle_response<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a,
	{
		Box::pin(async move {
			// Process server finished
			self.process_server_finished(msg)?;

			// Build client finished
			let client_finished = self.build_client_finished()?;
			Ok(Some(client_finished))
		})
	}

	#[cfg(feature = "aead")]
	fn complete<'a>(
		&'a mut self,
	) -> Pin<Box<dyn Future<Output = Result<crate::crypto::aead::RuntimeAead, Self::Error>> + Send + 'a>> {
		Box::pin(async move {
			// 1. Validate state
			if self.state.state() != ClientHandshakeState::ClientFinishedSent {
				return Err(HandshakeError::InvalidState);
			}

			// 2. Get CEK (session_key) and profile
			let cek = self.session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;
			let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

			// 3. Derive final session key as P::AeadCipher
			use crate::transport::handshake::HandshakeFinalization;
			let cipher = cek.with(|key_bytes| self.derive_session_aead(key_bytes, &transcript_hash))?;

			// 4. Transition to complete
			self.state.transition(ClientHandshakeState::Completed)?;

			// 5. Wrap cipher in RuntimeAead with negotiated OID
			Ok(crate::crypto::aead::RuntimeAead::new(cipher, aead_oid))
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}

	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc> {
		self.selected_profile
	}
}

/// Type alias for CMS client using secp256k1 curve.
///
/// This is the default curve used in TightBeam and is provided as a
/// convenient alias for the generic `CmsHandshakeClient`.
#[cfg(feature = "secp256k1")]
pub type CmsHandshakeClientSecp256k1 = CmsHandshakeClient<crate::crypto::profiles::DefaultCryptoProvider>;

#[cfg(test)]
mod tests {
	use crate::cms::enveloped_data::EnvelopedData;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::elliptic_curve::SecretKey;
	use crate::der::Decode;
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	use crate::transport::handshake::processors::{
		AesGcmContentDecryptor, TightBeamEnvelopedDataProcessor, TightBeamKariRecipient,
	};
	use crate::transport::handshake::state::ClientHandshakeState;
	use crate::transport::handshake::tests::*;
	use crate::{HASH_SHA3_256_OID, SIGNER_ECDSA_WITH_SHA3_256_OID};

	#[test]
	fn test_client_state_flow() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A CMS client in init state with a server certificate
		let transcript_hash = [1u8; 32];
		let server_test_cert = create_test_certificate();
		let mut client = TestCmsClientBuilder::new()
			.with_server_cert(server_test_cert.certificate.clone())
			.with_transcript_hash(transcript_hash)
			.build();
		assert_eq!(client.state(), ClientHandshakeState::Init);

		// When: Client builds a valid key exchange
		let session_key = vec![2u8; 32];
		let key_exchange = client.build_key_exchange(session_key.clone())?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		// Verify session key is stored
		assert!(client.session_key().is_some());

		// Then: Server should be able to decrypt it using the matching private key
		let enveloped_data = EnvelopedData::from_der(&key_exchange)?;
		let server_secret = SecretKey::from(server_test_cert.signing_key.clone());
		let provider = DefaultCryptoProvider::default();
		let kari_processor = TightBeamKariRecipient::new(provider, server_secret);
		let content_decryptor = AesGcmContentDecryptor;
		let processor = TightBeamEnvelopedDataProcessor::new(kari_processor, content_decryptor);
		let decrypted = processor.process(&enveloped_data)?;
		assert_eq!(decrypted, session_key);

		// When: Client processes server Finished
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256_OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None };
		let mut server_finished_builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider>::new(
			server_test_cert.signing_key,
			digest_alg,
			signature_alg,
		)?;
		let server_finished = server_finished_builder.build_der(&transcript_hash)?;

		let verified = client.process_server_finished(&server_finished)?;
		assert_eq!(verified, transcript_hash);
		assert_eq!(client.state(), ClientHandshakeState::ServerFinishedReceived);

		// Build client Finished
		let _client_finished = client.build_client_finished()?;
		assert_eq!(client.state(), ClientHandshakeState::ClientFinishedSent);

		// Complete
		client.complete()?;
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);

		Ok(())
	}

	#[test]
	fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A CMS client in init state
		let mut client = TestCmsClientBuilder::new().build();

		// When: Trying to process server finished before sending key exchange
		let result = client.process_server_finished(&[]);
		assert!(result.is_err());

		// When: Trying to build client finished before processing server finished
		let result = client.build_client_finished();
		assert!(result.is_err());

		Ok(())
	}
}
