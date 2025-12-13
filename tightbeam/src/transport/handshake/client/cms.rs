//! CMS-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam handshake protocol using
//! CMS builders and processors.

use core::future::Future;
use core::pin::Pin;

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfo};
use crate::cms::{cert::IssuerAndSerialNumber, signed_data::SignerIdentifier};
use crate::crypto::aead::KeyInit;
use crate::crypto::hash::Digest;
use crate::crypto::key::KeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile, SecurityProfileDesc};
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, PublicKey, SecretKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, SignatureAlgorithmIdentifier};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::validate_certificate_expiry;
use crate::crypto::x509::Certificate;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode};
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::builders::{TightBeamEnvelopedDataBuilder, TightBeamKariBuilder};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::SecurityOffer;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine};
use crate::transport::handshake::utils::{compute_transcript_digest, extract_verifying_key_from_cert, validate_state};
use crate::transport::handshake::{Arc, ClientHandshakeProtocol, HandshakeAlertHandler, HandshakeFinalization};

/// Client-side CMS handshake orchestrator.
///
/// Generic over `P: CryptoProvider` which defines the complete cryptographic
/// suite (curve, signature algorithm, digest, AEAD, KDF). Supports
/// cryptographic profile negotiation via optional `security_offer` field.
///
/// Manages the complete client handshake flow:
/// 1. Sends KeyExchange (EnvelopedData with KARI)
/// 2. Receives and verifies server Finished (SignedData)
/// 3. Sends client Finished (SignedData)
pub struct CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	state: ClientStateMachine,
	client_key_provider: Arc<dyn KeyProvider>,
	client_certificate: Option<Arc<Certificate>>,
	server_cert: Arc<Certificate>,
	transcript_hash: Option<[u8; 32]>,
	transcript_buffer: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	security_offer: Option<SecurityOffer>,
	selected_profile: Option<SecurityProfileDesc>,
	provider: P,
	server_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	invariants: HandshakeInvariant,
}

impl<P> CmsHandshakeClient<P>
where
	P: CryptoProvider,
	P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: KeyInit,
{
	/// Create a new CMS handshake client.
	///
	/// # Parameters
	/// - `provider`: The cryptographic provider defining the security profile
	/// - `client_key_provider`: The client's key provider for authentication
	/// - `server_cert`: The server's certificate (for key agreement)
	///
	/// # Transcript Hash
	/// The transcript hash is computed internally from handshake messages.
	/// If you need to provide an external transcript hash (for testing),
	/// use `with_transcript_hash()` after construction.
	pub fn new(provider: P, client_key_provider: Arc<dyn KeyProvider>, server_cert: Arc<Certificate>) -> Self {
		Self {
			state: ClientStateMachine::default(),
			client_key_provider,
			client_certificate: None,
			server_cert,
			transcript_hash: None,
			transcript_buffer: Vec::new(),
			session_key: None,
			security_offer: None,
			selected_profile: None,
			provider,
			server_validators: None,
			invariants: HandshakeInvariant::default(),
		}
	}

	/// Set an external transcript hash (for testing or custom protocols).
	///
	/// When set, the internal transcript buffer is not used.
	#[must_use]
	pub fn with_transcript_hash(mut self, hash: [u8; 32]) -> Self {
		self.transcript_hash = Some(hash);
		self
	}

	/// Set certificate validators for server certificate validation.
	///
	/// Validators will be applied during the handshake when the server
	/// certificate is validated.
	#[must_use]
	pub fn with_server_validators(mut self, validators: Arc<Vec<Arc<dyn CertificateValidation>>>) -> Self {
		self.server_validators = Some(validators);
		self
	}

	/// Set client certificate for mutual authentication.
	pub fn with_client_certificate(mut self, certificate: impl Into<Certificate>) -> Self {
		self.client_certificate = Some(Arc::new(certificate.into()));
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
		validate_state(self.state.state(), expected)
	}

	/// Validate state and server certificate for key exchange.
	fn validate_state_and_certificate(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::Init)?;

		// Validate server certificate using configured validators
		if let Some(validators) = &self.server_validators {
			for validator in validators.iter() {
				validator.evaluate(&self.server_cert)?;
			}
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
		// Cloning here is cheaper than Arc
		KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
			issuer: self.server_cert.tbs_certificate.issuer.clone(),
			serial_number: self.server_cert.tbs_certificate.serial_number.clone(),
		})
	}

	/// Extract the server's verifying key from a certificate or similar.
	fn extract_server_verifying_key(&self, server_cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		let server_public_key = extract_verifying_key_from_cert::<P::Curve>(server_cert)?;
		Ok(P::VerifyingKey::from(server_public_key))
	}

	/// Compute the signer identifier from the server's verifying key.
	fn compute_signer_identifier(&self, verifying_key: &P::VerifyingKey) -> Result<SignerIdentifier, HandshakeError> {
		Ok(crate::crypto::x509::utils::compute_signer_identifier::<P::Digest, _>(
			verifying_key,
		)?)
	}

	/// Compute transcript hash from the accumulated buffer.
	///
	/// Uses the provider's digest algorithm for consistency with signatures.
	fn compute_transcript_hash(&self) -> [u8; 32] {
		compute_transcript_digest::<P::Digest>(&self.transcript_buffer)
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
		if verified_content.len() != 32 || verified_content.as_slice() != expected_hash {
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
		// 1. Validate state and certificate
		self.validate_key_exchange_prerequisites()?;

		// 2. Extract cryptographic material
		let (server_public_key, sender_ephemeral, sender_pub_spki) = self.extract_key_exchange_crypto_material()?;

		// 3. Create UKM and recipient identifier
		let ukm = self.create_user_keying_material()?;
		let rid = self.build_recipient_identifier();

		// 4. Build KARI structure
		let kari_builder = self.build_kari_structure(sender_ephemeral, sender_pub_spki, server_public_key, rid, ukm)?;

		// 5. Create EnvelopedData with optional security offer
		let enveloped_data_der = self.build_enveloped_data(kari_builder, &session_key)?;

		// 6. Update transcript and state
		self.finalize_key_exchange(&enveloped_data_der, session_key)?;

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

		// 2. Compute transcript hash BEFORE adding server_finished (to match server's hash)
		if self.transcript_hash.is_none() {
			self.transcript_hash = Some(self.compute_transcript_hash());
		}

		// 3. Extract cryptographic material
		let server_verifying_key = self.extract_server_verifying_key(&self.server_cert)?;
		let expected_signer_identifier = self.compute_signer_identifier(&server_verifying_key)?;

		// 4. Verify signature and content
		let verified_content =
			self.verify_signature(signed_data_der, server_verifying_key, expected_signer_identifier)?;

		// 5. Add server finished to transcript AFTER verification
		self.transcript_buffer.extend_from_slice(signed_data_der);

		// 6. Transition state & lock transcript (transcript hash verified)
		self.state.transition(ClientHandshakeState::ServerFinishedReceived)?;
		self.invariants.lock_transcript()?;

		Ok(verified_content)
	}

	/// Build client Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub async fn build_client_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate state
		self.validate_client_finished_prerequisites()?;

		// 2. Get transcript hash and prepare digest
		let (transcript_hash, digest) = self.prepare_finished_digest()?;

		// 3. Sign the digest
		let signature_bytes = self.sign_finished_digest(&digest).await?;

		// 4. Build cryptographic components
		let (signer_id, digest_alg, signature_alg) = self.build_finished_crypto_components().await?;

		// 5. Build SignedData structure
		let signed_data_der =
			self.build_signed_data(transcript_hash, &signature_bytes, signer_id, digest_alg, signature_alg)?;

		// 6. Transition state
		self.finalize_client_finished()?;

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

	/// Validate state and certificate for key exchange.
	fn validate_key_exchange_prerequisites(&self) -> Result<(), HandshakeError> {
		// Accept both Init (fresh) or HelloSent (if future hello phase added)
		if self.state.state() == ClientHandshakeState::Init {
			self.validate_state_and_certificate()?;
		} else if self.state.state() != ClientHandshakeState::HelloSent {
			return Err(HandshakeError::InvalidState);
		}

		Ok(())
	}

	/// Extract cryptographic material needed for key exchange.
	#[allow(clippy::type_complexity)]
	fn extract_key_exchange_crypto_material(
		&self,
	) -> Result<(PublicKey<P::Curve>, SecretKey<P::Curve>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let server_public_key = self.extract_server_public_key()?;
		let (sender_ephemeral, sender_pub_spki) = self.create_ephemeral_keypair()?;
		Ok((server_public_key, sender_ephemeral, sender_pub_spki))
	}

	/// Create user keying material for the key agreement.
	fn create_user_keying_material(&self) -> Result<UserKeyingMaterial, HandshakeError> {
		let ukm_bytes = generate_nonce::<64>(None)?;
		UserKeyingMaterial::new(ukm_bytes.to_vec()).map_err(Into::into)
	}

	/// Build KARI structure with all required components.
	fn build_kari_structure(
		&self,
		sender_ephemeral: SecretKey<P::Curve>,
		sender_pub_spki: SubjectPublicKeyInfoOwned,
		server_public_key: PublicKey<P::Curve>,
		rid: KeyAgreeRecipientIdentifier,
		ukm: UserKeyingMaterial,
	) -> Result<TightBeamKariBuilder<P>, HandshakeError> {
		let key_wrap_oid =
			<P::Profile as SecurityProfile>::KEY_WRAP_OID.ok_or(HandshakeError::MissingKeyWrapAlgorithm)?;
		let key_enc_alg = AlgorithmIdentifierOwned { oid: key_wrap_oid, parameters: None };

		let kari_builder = TightBeamKariBuilder::new(self.provider)
			.with_sender_priv(sender_ephemeral)
			.with_sender_pub_spki(sender_pub_spki)
			.with_recipient_pub(server_public_key)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		Ok(kari_builder)
	}

	/// Build EnvelopedData with optional security offer.
	fn build_enveloped_data(
		&self,
		kari_builder: TightBeamKariBuilder<P>,
		session_key: &[u8],
	) -> Result<Vec<u8>, HandshakeError> {
		let mut enveloped_builder = TightBeamEnvelopedDataBuilder::new(kari_builder);

		// Add SecurityOffer as unprotected attribute if configured
		if let Some(ref offer) = self.security_offer {
			let offer_attr = crate::transport::handshake::attributes::encode_security_offer(offer)?;
			enveloped_builder = enveloped_builder.with_unprotected_attr(offer_attr);
		}

		let enveloped_data = enveloped_builder.build(session_key, None)?;
		enveloped_data.to_der().map_err(Into::into)
	}

	/// Finalize key exchange by updating transcript and state.
	fn finalize_key_exchange(&mut self, enveloped_data_der: &[u8], session_key: Vec<u8>) -> Result<(), HandshakeError> {
		// Add to transcript if we're computing it internally
		if self.transcript_hash.is_none() {
			self.transcript_buffer.extend_from_slice(enveloped_data_der);
		}

		// Store session key and transition state
		self.session_key = Some(Secret::from(session_key));
		// Transition directly from Init -> KeyExchangeSent (CMS path) or HelloSent -> KeyExchangeSent
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(())
	}

	/// Validate prerequisites for building client finished message.
	fn validate_client_finished_prerequisites(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::ServerFinishedReceived)
	}

	/// Prepare transcript hash and compute digest for signing.
	fn prepare_finished_digest(&self) -> Result<([u8; 32], Vec<u8>), HandshakeError> {
		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		let mut hasher = P::Digest::new();
		hasher.update(transcript_hash);
		let digest = hasher.finalize();
		let digest_bytes = digest.to_vec();

		Ok((transcript_hash, digest_bytes))
	}

	/// Sign the finished digest using the client key provider.
	async fn sign_finished_digest(&self, digest: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let signature_bytes = self.client_key_provider.sign(digest).await?;
		Ok(signature_bytes)
	}

	/// Build cryptographic components needed for SignedData.
	async fn build_finished_crypto_components(
		&self,
	) -> Result<(SignerIdentifier, AlgorithmIdentifierOwned, AlgorithmIdentifierOwned), HandshakeError> {
		use crate::crypto::x509::utils::compute_signer_identifier_from_der;

		let public_key_bytes = self.client_key_provider.to_public_key_bytes().await?;
		let signer_id = compute_signer_identifier_from_der::<P::Digest>(&public_key_bytes)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };

		Ok((signer_id, digest_alg, signature_alg))
	}

	/// Build the complete SignedData structure.
	fn build_signed_data(
		&self,
		transcript_hash: [u8; 32],
		signature_bytes: &[u8],
		signer_id: SignerIdentifier,
		digest_alg: AlgorithmIdentifierOwned,
		signature_alg: AlgorithmIdentifierOwned,
	) -> Result<Vec<u8>, HandshakeError> {
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: signer_id,
			digest_alg: digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: signature_alg,
			signature: OctetString::new(signature_bytes)?,
			unsigned_attrs: None,
		};

		let octet_string = OctetString::new(transcript_hash)?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = crate::der::Any::from_der(&econtent_der)?;
		let encap_content_info =
			EncapsulatedContentInfo { econtent_type: crate::oids::DATA, econtent: Some(econtent_any) };

		let signed_data = SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![digest_alg].try_into()?,
			encap_content_info,
			certificates: None,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		};

		signed_data.to_der().map_err(Into::into)
	}

	/// Finalize client finished by transitioning state and marking invariant.
	fn finalize_client_finished(&mut self) -> Result<(), HandshakeError> {
		self.state.transition(ClientHandshakeState::ClientFinishedSent)?;
		self.invariants.mark_finished_sent()?;
		Ok(())
	}
}

// ============================================================================
// Common Handshake Trait Implementations
// ============================================================================

impl<P> HandshakeFinalization<P> for CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for CmsHandshakeClient<P> where P: CryptoProvider {}

// ============================================================================
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<P> ClientHandshakeProtocol for CmsHandshakeClient<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: Send + 'static,
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
			let client_finished = self.build_client_finished().await?;
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
			let cipher = cek.with(|key_bytes| self.derive_session_aead(key_bytes, &transcript_hash))??;

			// 4. Transition to complete
			self.state.transition(ClientHandshakeState::Completed)?;

			// 5. Wrap cipher in RuntimeAead with negotiated OID
			Ok(crate::crypto::aead::RuntimeAead::new(cipher, aead_oid))
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

#[cfg(test)]
mod tests {
	use crate::cms::enveloped_data::EnvelopedData;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::elliptic_curve::SecretKey;
	use crate::der::{Decode, Encode};
	use crate::oids::{HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	use crate::transport::handshake::processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};
	use crate::transport::handshake::state::ClientHandshakeState;
	use crate::transport::handshake::tests::*;

	#[tokio::test]
	async fn test_client_state_flow() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A CMS client in init state with a server certificate
		let transcript_hash = [1u8; 32];
		let server_test_cert = create_test_certificate();
		let mut client = TestCmsClientBuilder::new()
			.with_server_cert(server_test_cert.certificate.clone())
			.with_transcript_hash(transcript_hash)
			.build()?;
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
		let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(kari_processor);
		let decrypted = processor.process(&enveloped_data)?;
		assert_eq!(decrypted, session_key);

		// When: Client processes server Finished
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
		let server_finished_builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(
			&server_test_cert.signing_key,
			digest_alg,
			signature_alg,
		)?;
		let server_finished = server_finished_builder.build(&transcript_hash)?;
		let server_finished = server_finished.to_der()?;

		let verified = client.process_server_finished(&server_finished)?;
		assert_eq!(verified, transcript_hash);
		assert_eq!(client.state(), ClientHandshakeState::ServerFinishedReceived);

		// Build client Finished
		let _client_finished = client.build_client_finished().await?;
		assert_eq!(client.state(), ClientHandshakeState::ClientFinishedSent);

		// Complete
		client.complete()?;
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);

		Ok(())
	}

	#[tokio::test]
	async fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
		// Given: A CMS client in init state
		let mut client = TestCmsClientBuilder::new().build()?;

		// When: Trying to process server finished before sending key exchange
		let result = client.process_server_finished(&[]);
		assert!(result.is_err());

		// When: Trying to build client finished before processing server finished
		let result = client.build_client_finished().await;
		assert!(result.is_err());

		Ok(())
	}
}
