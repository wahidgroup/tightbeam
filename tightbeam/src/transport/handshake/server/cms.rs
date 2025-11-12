//! CMS-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam handshake protocol using
//! CMS builders and processors.
//!
//! Generic over `P: CryptoProvider` for cryptographic operations.

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

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EnvelopedData, OriginatorIdentifierOrKey, RecipientInfo};
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::aead::{Decryptor, KeyInit};
use crate::crypto::hash::Digest;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, SignatureAlgorithmIdentifier, Verifier};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::compute_signer_identifier;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode};
use crate::spki::AlgorithmIdentifierOwned;
use crate::spki::EncodePublicKey;
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::ServerHandshakeProtocol;
use crate::transport::handshake::{HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation};
use crate::x509::attr::Attributes;
use crate::x509::Certificate;

/// Server-side CMS handshake orchestrator.
///
/// Generic over:
/// - `P: CryptoProvider` for cryptographic operations
/// - `K: Clone` for the concrete signing key type
///
/// Manages the complete server handshake flow:
/// 1. Receives and decrypts KeyExchange (EnvelopedData with KARI)
/// 2. Sends server Finished (SignedData)
/// 3. Receives and verifies client Finished (SignedData)
///
/// Supports cryptographic profile negotiation via `supported_profiles` configuration.
pub struct CmsHandshakeServer<P>
where
	P: CryptoProvider,
{
	state: ServerStateMachine,
	server_key_provider: Arc<dyn crate::crypto::key::KeyProvider>,
	client_cert: Option<Arc<Certificate>>,
	validated_client_cert: Option<Arc<Certificate>>,
	transcript_hash: Option<[u8; 32]>,
	transcript_buffer: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	supported_profiles: Vec<SecurityProfileDesc>,
	selected_profile: Option<SecurityProfileDesc>,
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	_phantom: PhantomData<P>,
	invariants: HandshakeInvariant,
}

impl<P> CmsHandshakeServer<P>
where
	P: CryptoProvider + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: Send + 'static + AssociatedOid,
	P::AeadCipher: KeyInit + 'static,
{
	/// Create a new CMS handshake server.
	///
	/// # Parameters
	/// - `server_key_provider`: The key provider for cryptographic operations
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	pub fn new(
		server_key_provider: Arc<dyn crate::crypto::key::KeyProvider>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Self {
		Self {
			state: ServerStateMachine::default(),
			server_key_provider,
			client_cert: None,
			validated_client_cert: None,
			transcript_hash: None,
			transcript_buffer: Vec::new(),
			session_key: None,
			supported_profiles: Vec::new(),
			selected_profile: None,
			client_validators,
			_phantom: PhantomData,
			invariants: { HandshakeInvariant::default() },
		}
	}

	/// Set an external transcript hash (for testing or custom protocols).
	///
	/// When set, the internal transcript buffer is not used.
	#[must_use]
	pub fn with_transcript_hash(mut self, hash: [u8; 32]) -> Self {
		self.transcript_hash = Some(hash);

		// Lock transcript immediately since it's externally provided
		let _ = self.invariants.lock_transcript();
		self
	}

	/// Configures supported cryptographic profiles for negotiation.
	///
	/// When profiles are configured, the server will select the first mutually
	/// supported profile from client's offer. If no profiles are configured or
	/// client sends no offer, the server uses dealer's choice mode (default profile).
	#[must_use]
	pub fn with_supported_profiles(mut self, profiles: Vec<crate::crypto::profiles::SecurityProfileDesc>) -> Self {
		self.supported_profiles = profiles;
		self
	}

	/// Set the client certificate (optional, for mutual authentication).
	///
	/// Validates the certificate using the configured validator chain and enforces
	/// identity immutability (certificate cannot change during re-handshake).
	pub fn set_client_certificate(&mut self, cert: Certificate) -> Result<(), HandshakeError> {
		// Check for identity immutability - reject if cert changes on re-handshake
		if let Some(existing_cert) = &self.validated_client_cert {
			if existing_cert.as_ref() != &cert {
				return Err(HandshakeError::PeerIdentityMismatch);
			}
		}

		// Run validator chain if configured
		if let Some(validators) = &self.client_validators {
			for validator in validators.iter() {
				validator.evaluate(&cert)?;
			}
		}

		// Store the cert (used for extracting public key later)
		let cert_arc = Arc::new(cert);
		self.client_cert = Some(Arc::clone(&cert_arc));

		// Store as validated cert (identity is now locked)
		self.validated_client_cert = Some(cert_arc);

		Ok(())
	}

	/// Get the selected security profile after negotiation.
	///
	/// Returns `None` if no negotiation occurred (no profiles configured).
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}

	/// Compute transcript hash from the accumulated buffer.
	///
	/// Uses SHA3-256 for consistency with the protocol.
	fn compute_transcript_hash(&self) -> [u8; 32] {
		let mut hasher = P::Digest::default();
		hasher.update(&self.transcript_buffer);
		let hash_result = hasher.finalize();
		let mut hash_array = [0u8; 32];
		hash_array.copy_from_slice(&hash_result);
		hash_array
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		if self.state.state() != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	/// Process SecurityOffer from unprotected attributes and perform profile negotiation.
	///
	/// Handles the complex logic of:
	/// 1. Converting x509_cert attributes to HandshakeAttributes
	/// 2. Finding SecurityOffer in the attributes
	/// 3. Performing profile negotiation or dealer's choice selection
	///
	/// # Parameters
	/// - `unprotected_attrs`: Optional unprotected attributes from EnvelopedData
	///
	/// # Returns
	/// Success if negotiation completed (profile selected or dealer's choice applied)
	fn process_security_offer(&mut self, unprotected_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		// If no attributes and no profiles configured, nothing to do
		if unprotected_attrs.is_none() && self.supported_profiles.is_empty() {
			return Ok(());
		}

		// Extract SecurityOffer from attributes if present
		let offer = unprotected_attrs.and_then(|attrs| {
			let handshake_attrs = self.convert_to_handshake_attributes(attrs).ok()?;
			let offer_attr =
				crate::transport::handshake::attributes::find(&handshake_attrs, &crate::oids::HANDSHAKE_SECURITY_OFFER)
					.ok()?;

			crate::transport::handshake::attributes::extract_security_offer(offer_attr).ok()
		});

		// Use trait method for negotiation
		self.selected_profile = Some(self.negotiate_profile(offer.as_ref())?);

		Ok(())
	}

	/// Convert Attributes to HandshakeAttribute format.
	fn convert_to_handshake_attributes(&self, attrs: &Attributes) -> Result<Vec<HandshakeAttribute>, HandshakeError> {
		attrs
			.iter()
			.map(|attr| Ok(HandshakeAttribute { attr_type: attr.oid, attr_values: attr.values.clone().into() }))
			.collect()
	}

	/// Get the client certificate, returning an error if not set.
	fn get_client_certificate(&self) -> Result<&Certificate, HandshakeError> {
		self.client_cert
			.as_ref()
			.map(|arc| arc.as_ref())
			.ok_or(HandshakeError::MissingClientCertificate)
	}

	/// Extract the client's verifying key from certificate.
	fn extract_client_verifying_key(&self) -> Result<P::VerifyingKey, HandshakeError> {
		let client_cert = self.get_client_certificate()?;
		let client_public_key = PublicKey::<P::Curve>::from_sec1_bytes(
			client_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		Ok(P::VerifyingKey::from(client_public_key))
	}

	/// Compute the signer identifier from the client's verifying key.
	fn compute_client_signer_identifier(
		&self,
		client_verifying_key: &P::VerifyingKey,
	) -> Result<SignerIdentifier, HandshakeError> {
		Ok(crate::crypto::x509::utils::compute_signer_identifier::<P::Digest, _>(
			client_verifying_key,
		)?)
	}

	/// Verify the signature and content of the SignedData.
	fn verify_client_signature(
		&self,
		signed_data_der: &[u8],
		client_verifying_key: P::VerifyingKey,
		expected_sid: SignerIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		let verifier = EcdsaSignatureVerifier::<P::VerifyingKey, P::Signature, P::Digest>::from_verifying_key_with_sid(
			client_verifying_key,
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

	/// Decrypt the session key from EnvelopedData using KARI.
	///
	/// Performs all steps:
	/// 1. Decode EnvelopedData structure
	/// 2. Extract CEK using KARI decryption (with KeyProvider for ECDH)
	/// 3. Decrypt encrypted content using CEK
	/// 4. Store the session key securely
	async fn decrypt_session_key(&mut self, enveloped_data_der: &[u8]) -> Result<(), HandshakeError> {
		let enveloped_data = EnvelopedData::from_der(enveloped_data_der)?;

		// Extract KARI from recipient infos
		let kari = enveloped_data
			.recip_infos
			.0
			.iter()
			.find_map(|ri| match ri {
				RecipientInfo::Kari(kari) => Some(kari),
				_ => None,
			})
			.ok_or_else(|| HandshakeError::InvalidClientKeyExchange)?;

		// Extract originator public key
		let originator_pub_bytes = match &kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(oipk) => oipk.public_key.raw_bytes(),
			_ => return Err(HandshakeError::InvalidClientKeyExchange),
		};

		let originator_pub = k256::PublicKey::from_sec1_bytes(originator_pub_bytes)?;

		// Perform ECDH using KeyProvider
		let shared_secret_bytes = self.server_key_provider.ecdh(&originator_pub).await?;

		// Derive KEK using HKDF via provider
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let provider = P::default();

		let kdf = provider.as_key_deriver::<HandshakeError, 32>();
		let secret_bytes = Secret::from(shared_secret_bytes);
		let mut kek = secret_bytes.with(|ss| kdf(ss, ukm.as_bytes(), TIGHTBEAM_KARI_KDF_INFO))??;

		// Unwrap CEK
		let wrapped_key = kari.recipient_enc_keys[0].enc_key.as_bytes();
		let unwrapper = provider.as_key_unwrapper_32::<HandshakeError>();
		let cek = unwrapper(wrapped_key, &kek)?;

		// Re-wrap for constant-time validation
		let wrapper = provider.as_key_wrapper_32::<HandshakeError>();
		let rewrapped = wrapper(&cek, &kek)?;
		let valid = rewrapped.as_slice() == wrapped_key;

		// Zeroize KEK
		#[cfg(feature = "zeroize")]
		{
			use zeroize::Zeroize;
			kek.zeroize();
		}

		if !valid {
			return Err(HandshakeError::AesKeyWrap(
				crate::crypto::aead::aes_kw::Error::IntegrityCheckFailed,
			));
		}

		// Decrypt session key from encrypted content
		let cipher = P::AeadCipher::new_from_slice(&cek)
			.map_err(|_| HandshakeError::InvalidKeySize { expected: 32, received: cek.len() })?;
		let session_key_bytes = cipher.decrypt_content(&enveloped_data.encrypted_content)?;

		self.session_key = Some(Secret::from(session_key_bytes));

		Ok(())
	}

	/// Process KeyExchange message (EnvelopedData with KARI containing session key).
	///
	/// # Parameters
	/// - `enveloped_data_der`: DER-encoded EnvelopedData from client
	///
	/// # Security
	/// Session key is stored internally and zeroized on drop. Not returned to prevent
	/// unnecessary copies of key material in memory.
	pub async fn process_key_exchange(&mut self, enveloped_data_der: &[u8]) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Add key exchange to transcript if computing internally
		if self.transcript_hash.is_none() {
			self.transcript_buffer.extend_from_slice(enveloped_data_der);
		}

		// 3. Transition to received state
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		// 4. Decode EnvelopedData to access encrypted content
		let enveloped_data = EnvelopedData::from_der(enveloped_data_der)?;

		// 5. Early alert detection (abort before heavy crypto or negotiation)
		self.check_for_alert(enveloped_data.unprotected_attrs.as_ref())?;

		// 6. Process SecurityOffer and perform profile negotiation
		self.process_security_offer(enveloped_data.unprotected_attrs.as_ref())?;

		// 7. Decrypt and store session key
		self.decrypt_session_key(enveloped_data_der).await?;
		// Transcript implicitly locked for CMS (provided externally). Mark AEAD derivation here
		// as session key material now available.
		self.invariants.derive_aead_once()?;

		Ok(())
	}

	/// Validate prerequisites for building server finished message.
	fn validate_server_finished_prerequisites(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)
	}

	/// Prepare transcript hash and compute digest for signing.
	fn prepare_server_finished_digest(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// Compute transcript hash if not already set
		if self.transcript_hash.is_none() {
			self.transcript_hash = Some(self.compute_transcript_hash());
			// Lock transcript now that it's computed
			self.invariants.lock_transcript()?;
		}

		// Hash the transcript hash
		let content = self.transcript_hash.as_ref().ok_or(HandshakeError::InvalidTranscriptHash)?;
		let mut hasher = P::Digest::new();
		hasher.update(content);
		let digest = hasher.finalize();
		Ok(digest.to_vec())
	}

	/// Sign the finished digest using the server key provider.
	async fn sign_server_finished_digest(&self, digest: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let signature = self.server_key_provider.sign(digest).await?;
		Ok(signature.to_bytes().to_vec())
	}

	/// Build cryptographic components needed for SignedData.
	async fn build_server_finished_crypto_components(
		&self,
	) -> Result<(SignerIdentifier, AlgorithmIdentifierOwned, AlgorithmIdentifierOwned), HandshakeError> {
		let public_key = self.server_key_provider.to_public_key().await?;
		let signer_id = compute_signer_identifier::<P::Digest, _>(&public_key)?;

		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };

		Ok((signer_id, digest_alg, signature_alg))
	}

	/// Build the complete SignedData structure.
	fn build_server_signed_data(
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
		let encap_content_info = EncapsulatedContentInfo {
			econtent_type: crate::oids::DATA,
			econtent: Some(crate::der::Any::new(crate::der::Tag::OctetString, econtent_der.as_slice())?),
		};

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

	/// Finalize server finished by updating transcript and transitioning state.
	fn finalize_server_finished(&mut self, signed_data_der: &[u8]) -> Result<(), HandshakeError> {
		// Add to transcript if computing internally
		if !self.transcript_buffer.is_empty() {
			self.transcript_buffer.extend_from_slice(signed_data_der);
		}

		// Transition state & mark finished sent invariant
		self.state.transition(ServerHandshakeState::ServerFinishedSent)?;
		self.invariants.mark_finished_sent()?;
		Ok(())
	}

	/// Build server Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub async fn build_server_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate state
		self.validate_server_finished_prerequisites()?;

		// 2. Prepare transcript hash and compute digest
		let digest = self.prepare_server_finished_digest()?;

		// 3. Sign the digest
		let signature_bytes = self.sign_server_finished_digest(&digest).await?;

		// 4. Build cryptographic components
		let (signer_id, digest_alg, signature_alg) = self.build_server_finished_crypto_components().await?;

		// 5. Build SignedData structure
		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidTranscriptHash)?;
		let signed_data_der =
			self.build_server_signed_data(transcript_hash, &signature_bytes, signer_id, digest_alg, signature_alg)?;

		// 6. Finalize by updating transcript and state
		self.finalize_server_finished(&signed_data_der)?;

		Ok(signed_data_der)
	}

	/// Process client Finished message (SignedData over transcript hash).
	///
	/// # Parameters
	/// - `signed_data_der`: DER-encoded SignedData from client
	///
	/// # Returns
	/// Verified transcript hash
	pub fn process_client_finished(&mut self, signed_data_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ServerHandshakeState::ServerFinishedSent)?;

		// 2. Add client finished to transcript if computing internally
		if !self.transcript_buffer.is_empty() {
			self.transcript_buffer.extend_from_slice(signed_data_der);
		}

		// 3. Extract cryptographic material
		let client_verifying_key = self.extract_client_verifying_key()?;
		let expected_signer_identifier = self.compute_client_signer_identifier(&client_verifying_key)?;

		// 4. Verify signature and content
		let verified_content =
			self.verify_client_signature(signed_data_der, client_verifying_key, expected_signer_identifier)?;

		// 5. Transition state
		self.state.transition(ServerHandshakeState::ClientFinishedReceived)?;

		Ok(verified_content)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ServerHandshakeState::ClientFinishedReceived)?;

		// 2. Transition to complete (AEAD already derived in finalization stage elsewhere)
		self.state.transition(ServerHandshakeState::Completed)?;

		Ok(())
	}

	/// Get the current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
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

impl<P> HandshakeNegotiation for CmsHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn supported_profiles(&self) -> &[SecurityProfileDesc] {
		&self.supported_profiles
	}
}

impl<P> HandshakeFinalization<P> for CmsHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for CmsHandshakeServer<P> where P: CryptoProvider {}

// ============================================================================
// ServerHandshakeProtocol Implementation
// ============================================================================

impl<P> ServerHandshakeProtocol for CmsHandshakeServer<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: Send + Sync + KeyInit + 'static,
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
					// This is KeyExchange (EnvelopedData) - process and send ServerFinished
					self.process_key_exchange(msg).await?;
					let server_finished = self.build_server_finished().await?;
					Ok(Some(server_finished))
				}
				ServerHandshakeState::ServerFinishedSent => {
					// This is ClientFinished (SignedData) - no response needed
					self.process_client_finished(msg)?;
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
			// 1. Validate state
			if self.state.state() != ServerHandshakeState::ClientFinishedReceived {
				return Err(HandshakeError::InvalidState);
			}

			// 2. Get CEK (session_key) and profile
			let cek = self.session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;

			// 3. Derive final session key as P::AeadCipher using transcript hash as salt
			use crate::transport::handshake::HandshakeFinalization;
			let transcript = self.transcript_hash.as_ref().ok_or(HandshakeError::InvalidTranscriptHash)?;
			let cipher = cek.with(|key_bytes| self.derive_session_aead(key_bytes, transcript))??;

			// 4. Transition to complete
			self.state.transition(ServerHandshakeState::Completed)?;

			// 5. Wrap cipher in RuntimeAead with negotiated OID
			Ok(crate::crypto::aead::RuntimeAead::new(cipher, aead_oid))
		})
	}

	fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	#[cfg(feature = "x509")]
	fn peer_certificate(&self) -> Option<&Certificate> {
		self.validated_client_cert.as_ref().map(|arc| arc.as_ref())
	}

	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc> {
		self.selected_profile
	}
}

/// Type alias for CMS server using secp256k1 curve.
///
/// This is the default curve used in TightBeam and is provided as a
/// convenient alias for the generic `CmsHandshakeServer`.
pub type CmsHandshakeServerSecp256k1 = CmsHandshakeServer<DefaultCryptoProvider>;

#[cfg(test)]
mod tests {
	mod server {
		use super::super::*;
		use crate::cms::cert::IssuerAndSerialNumber;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::crypto::x509::name::Name;
		use crate::crypto::x509::serial_number::SerialNumber;
		use crate::der::Decode;
		use crate::oids::{
			AES_128_GCM, AES_128_WRAP, AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA256, HASH_SHA3_256,
			SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256,
		};
		use crate::random::{generate_nonce, OsRng};
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
		use crate::transport::handshake::builders::{
			TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
		};
		use crate::transport::handshake::tests::*;

		/// Test the full server state flow through a complete handshake.
		///
		/// Verifies that the server correctly transitions through all states:
		/// Init → KeyExchangeReceived → ServerFinishedSent → ClientFinishedReceived → Complete
		#[tokio::test]
		async fn test_server_state_flow() -> Result<(), Box<dyn std::error::Error>> {
			let transcript_hash = [1u8; 32];
			let (mut server, server_public_key) =
				TestCmsServerBuilder::new().with_transcript_hash(transcript_hash).build();

			// Setup client cert for mutual auth
			let client_test_cert = create_test_certificate();
			server.set_client_certificate(client_test_cert.certificate.clone())?;

			// Verify initial state
			assert_eq!(server.state(), ServerHandshakeState::Init);

			// Build and process KeyExchange message
			let key_exchange = build_test_key_exchange(&server_public_key, &[2u8; 32])?;
			server.process_key_exchange(&key_exchange).await?;
			assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
			assert!(server.session_key().is_some());

			// Build server Finished
			let _server_finished = server.build_server_finished().await?;
			assert_eq!(server.state(), ServerHandshakeState::ServerFinishedSent);

			// Build and process client Finished
			let client_finished = build_test_client_finished(&client_test_cert.signing_key, &transcript_hash)?;
			let verified = server.process_client_finished(&client_finished)?;
			assert_eq!(verified, transcript_hash);
			assert_eq!(server.state(), ServerHandshakeState::ClientFinishedReceived);

			// Complete handshake
			server.complete()?;
			assert!(server.is_complete());
			assert_eq!(server.state(), ServerHandshakeState::Completed);

			Ok(())
		}

		/// Test that state transitions are properly enforced.
		///
		/// Verifies that operations fail when called in the wrong state.
		#[tokio::test]
		async fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
			let (mut server, _) = TestCmsServerBuilder::new().build();

			// Cannot build server finished before processing key exchange
			assert!(server.build_server_finished().await.is_err());

			// Cannot process client finished before sending server finished
			assert!(server.process_client_finished(&[]).is_err());

			Ok(())
		}

		/// Test CMS handshake with profile negotiation (dealer's choice mode).
		///
		/// Verifies that when the client doesn't send an explicit offer, the server
		/// selects a profile from its configured list and completes the handshake.
		#[tokio::test]
		async fn test_cms_end_to_end_with_profile_negotiation() -> Result<(), Box<dyn std::error::Error>> {
			let transcript_hash = [1u8; 32];
			let (mut server, server_public_key) =
				TestCmsServerBuilder::new().with_transcript_hash(transcript_hash).build();

			// Configure server with multiple profiles
			let profiles = vec![
				create_aes_gcm_profile(16), // AES-128-GCM
				create_aes_gcm_profile(32), // AES-256-GCM
			];
			server = server.with_supported_profiles(profiles);

			// Setup client certificate for mutual auth
			let client_test_cert = create_test_certificate();
			server.set_client_certificate(client_test_cert.certificate.clone())?;

			// Process KeyExchange (no explicit SecurityOffer from client)
			let key_exchange = build_test_key_exchange(&server_public_key, &[2u8; 32])?;
			server.process_key_exchange(&key_exchange).await?;
			assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
			assert!(server.session_key().is_some());

			// Verify a profile was selected (dealer's choice)
			assert!(server.selected_profile.is_some());
			let selected = server.selected_profile.unwrap();
			assert!(selected.aead.is_some()); // Must have selected an AEAD

			// Complete handshake flow
			let _server_finished = server.build_server_finished().await?;
			assert_eq!(server.state(), ServerHandshakeState::ServerFinishedSent);

			let client_finished = build_test_client_finished(&client_test_cert.signing_key, &transcript_hash)?;
			server.process_client_finished(&client_finished)?;
			assert_eq!(server.state(), ServerHandshakeState::ClientFinishedReceived);

			server.complete()?;
			assert_eq!(server.state(), ServerHandshakeState::Completed);
			assert!(server.is_complete());
			assert!(server.session_key().is_some());

			Ok(())
		}

		// ========================================================================
		// Test Helper Functions
		// ========================================================================

		/// Build a test KeyExchange (EnvelopedData) message.
		fn build_test_key_exchange(
			recipient_public_key: &PublicKey<k256::Secp256k1>,
			session_key: &[u8],
		) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
			let sender_ephemeral = SecretKey::<k256::Secp256k1>::random(&mut OsRng);
			let sender_public = sender_ephemeral.public_key();
			let sender_pub_spki = sender_public.to_public_key_der()?;
			let sender_pub_spki = SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes())?;

			let ukm_bytes = generate_nonce::<64>(None)?;
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
				issuer: Name::default(),
				serial_number: SerialNumber::new(&[0x01])?,
			});

			let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_128_WRAP, parameters: None };

			let kari_builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_ephemeral)
				.with_sender_pub_spki(sender_pub_spki)
				.with_recipient_pub(*recipient_public_key)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			use der::Encode;
			let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = enveloped_builder.build(session_key, None)?;
			Ok(enveloped_data.to_der()?)
		}

		/// Build a test ClientFinished (SignedData) message.
		fn build_test_client_finished(
			signing_key: &Secp256k1SigningKey,
			transcript_hash: &[u8],
		) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
			let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
			let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };

			use der::Encode;
			let builder =
				TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(signing_key, digest_alg, signature_alg)?;

			let signed_data = builder.build(transcript_hash)?;
			Ok(signed_data.to_der()?)
		}

		/// Create a test security profile with the given AEAD key size.
		fn create_aes_gcm_profile(key_size: u16) -> crate::crypto::profiles::SecurityProfileDesc {
			let aead_oid = if key_size == 16 {
				AES_128_GCM
			} else {
				AES_256_GCM
			};
			let key_wrap_oid = if key_size == 16 {
				AES_128_WRAP
			} else {
				AES_256_WRAP
			};

			crate::crypto::profiles::SecurityProfileDesc {
				#[cfg(feature = "digest")]
				digest: HASH_SHA256,
				#[cfg(feature = "aead")]
				aead: Some(aead_oid),
				#[cfg(feature = "aead")]
				aead_key_size: Some(key_size),
				#[cfg(feature = "signature")]
				signature: Some(SIGNER_ECDSA_WITH_SHA256),
				#[cfg(feature = "kdf")]
				kdf: Some(HASH_SHA256), // HKDF-SHA256
				#[cfg(feature = "ecdh")]
				curve: Some(CURVE_SECP256K1),
				key_wrap: Some(key_wrap_oid),
			}
		}
	}
}
