//! CMS-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam handshake protocol using
//! CMS builders and processors.
//!
//! Generic over `P: CryptoProvider` for cryptographic operations.

use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EnvelopedData, OriginatorIdentifierOrKey, RecipientInfo};
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::aead::{Decryptor, KeyInit, SessionKeys};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::secret::{Secret, ToInsecure};
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, PrehashVerifier, SignatureAlgorithmIdentifier, Verifier};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::{compute_signer_identifier, compute_signer_identifier_from_der};
use crate::der::asn1::{OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode};
use crate::oids::{self, DATA};
use crate::spki::AlgorithmIdentifierOwned;
use crate::spki::EncodePublicKey;
use crate::transport::handshake::attributes;
use crate::transport::handshake::common::derive_epoch_materials;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::kari::{derive_kek, key_wrap_key_size, unwrap_and_verify_with_kek};
use crate::transport::handshake::negotiation::{
	authorize_transport, server_mux_settings, DefaultStrengthFloor, MuxSettings, ProfileStrengthPolicy, SecurityAccept,
	TransportAccept, TransportAuthorizer, TransportOffer,
};
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::receipt::{
	certificate_signer_identifier, complete_receipt_artifact, record_receipt_outcome, settle_receipt_ack, sign_receipt,
	SessionObserver, SessionOutcome, SessionReceipt, SessionVerdict, StoredReceipt,
};
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::utils::{compute_transcript_digest, extract_verifying_key_from_cert, validate_state};
use crate::transport::handshake::ServerHandshakeProtocol;
use crate::transport::handshake::{EpochMaterials, HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::Certificate;
use crate::zeroize::Zeroizing;

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
	server_key_provider: Arc<dyn SigningKeyProvider>,
	client_cert: Option<Arc<Certificate>>,
	validated_client_cert: Option<Arc<Certificate>>,
	transcript_hash: Option<[u8; 32]>,
	transcript_buffer: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	supported_profiles: Vec<SecurityProfileDesc>,
	strength_policy: Option<Arc<dyn ProfileStrengthPolicy + Send + Sync>>,
	selected_profile: Option<SecurityProfileDesc>,
	transport_config: Option<TransportOffer>,
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	session_observer: Option<Arc<dyn SessionObserver>>,
	transport_accept: Option<TransportAccept>,
	settlement_challenge: Option<OctetString>,
	session_receipt: Option<SessionReceipt>,
	receipt_artifact: Option<SignedData>,
	stored_receipt: Option<StoredReceipt>,
	epoch_materials: Option<EpochMaterials>,
	mux_settings: Option<MuxSettings>,
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	invariants: HandshakeInvariant,
	_phantom: PhantomData<P>,
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
		server_key_provider: Arc<dyn SigningKeyProvider>,
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
			strength_policy: None, // Defaults to DefaultStrengthFloor
			selected_profile: None,
			transport_config: None,
			transport_authorizer: None,
			session_observer: None,
			transport_accept: None,
			settlement_challenge: None,
			session_receipt: None,
			receipt_artifact: None,
			stored_receipt: None,
			epoch_materials: None,
			mux_settings: None,
			client_validators,
			invariants: { HandshakeInvariant::default() },
			_phantom: PhantomData,
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
	pub fn with_supported_profiles(mut self, profiles: Vec<SecurityProfileDesc>) -> Self {
		self.supported_profiles = profiles;
		self
	}

	/// Override the minimum-strength policy applied during negotiation.
	///
	/// Defaults to `DefaultStrengthFloor` (256-bit AEAD key, >= 256-bit digest).
	/// Pass `NoStrengthFloor` only where weaker profiles must remain negotiable.
	#[must_use]
	pub fn with_strength_policy(mut self, policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		self.strength_policy = Some(policy);
		self
	}

	/// Enable transport multiplexing with the given local advertisement.
	/// Multiplexing activates only when the client also offers it.
	#[must_use]
	pub fn with_transport_config(mut self, config: TransportOffer) -> Self {
		self.transport_config = Some(config);
		self
	}

	/// Override the budget-grant policy consulted between the client's
	/// transport offer and the server's accept. Without an authorizer
	/// the server grants its local configuration ceiling.
	#[must_use]
	pub fn with_transport_authorizer(mut self, authorizer: Arc<dyn TransportAuthorizer>) -> Self {
		self.transport_authorizer = Some(authorizer);
		self
	}

	/// Set the observer that records the [`SessionOutcome`] of every
	/// budget-bearing session, successful or refused.
	#[must_use]
	pub fn with_session_observer(mut self, observer: Arc<dyn SessionObserver>) -> Self {
		self.session_observer = Some(observer);
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

		let cert = Arc::new(cert);
		self.client_cert = Some(Arc::clone(&cert));

		// Store as validated cert (identity is now locked)
		self.validated_client_cert = Some(cert);

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
	fn compute_transcript_hash(&self) -> Result<[u8; 32], HandshakeError> {
		compute_transcript_digest::<P::Digest>(&self.transcript_buffer)
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		validate_state(self.state.state(), expected)
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
			let offer_attr = attributes::find(&handshake_attrs, &oids::HANDSHAKE_SECURITY_OFFER).ok()?;

			attributes::extract_security_offer(offer_attr).ok()
		});

		// Use trait method for negotiation
		self.selected_profile = Some(self.negotiate_profile(offer.as_ref())?);

		Ok(())
	}

	/// Process the client's TransportOffer attribute, if present.
	///
	/// Multiplexing activates only when the client offered it AND it is
	/// locally enabled. Otherwise the connection stays single-flight. The
	/// authorizer (when configured) decides the budget grant.
	async fn process_transport_offer(&mut self, unprotected_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		let offer = unprotected_attrs.and_then(|attrs| {
			let handshake_attrs = self.convert_to_handshake_attributes(attrs).ok()?;
			let offer_attr = attributes::find(&handshake_attrs, &oids::HANDSHAKE_TRANSPORT_OFFER).ok()?;

			attributes::extract_transport_offer(offer_attr).ok()
		});

		let authorized = authorize_transport(
			offer.as_ref(),
			self.transport_config.as_ref(),
			self.transport_authorizer.as_deref(),
		)
		.await?;

		self.transport_accept = authorized.as_ref().map(|authorized| authorized.accept);
		self.settlement_challenge = authorized.and_then(|authorized| authorized.challenge);
		if let (Some(offer), Some(accept)) = (offer.as_ref(), self.transport_accept.as_ref()) {
			self.mux_settings = Some(server_mux_settings(offer, accept));
		}

		Ok(())
	}

	/// Convert Attributes to HandshakeAttribute format.
	fn convert_to_handshake_attributes(
		&self,
		attrs: &Attributes,
	) -> Result<Vec<attributes::HandshakeAttribute>, HandshakeError> {
		attrs
			.iter()
			.map(|attr| {
				// HandshakeAttribute owns its value set; Attributes keeps the source.
				Ok(attributes::HandshakeAttribute { attr_type: attr.oid, attr_values: attr.values.clone().into() })
			})
			.collect()
	}

	/// Get the client certificate, returning an error if not set.
	fn as_client_certificate(&self) -> Result<&Certificate, HandshakeError> {
		self.client_cert
			.as_ref()
			.map(|arc| arc.as_ref())
			.ok_or(HandshakeError::MissingClientCertificate)
	}

	/// Extract the client's verifying key from certificate.
	fn extract_client_verifying_key(&self) -> Result<P::VerifyingKey, HandshakeError> {
		let client_cert = self.as_client_certificate()?;
		let client_public_key = extract_verifying_key_from_cert::<P::Curve>(client_cert)?;
		Ok(P::VerifyingKey::from(client_public_key))
	}

	/// Compute the signer identifier from the client's verifying key.
	fn compute_client_signer_identifier(
		&self,
		client_verifying_key: &P::VerifyingKey,
	) -> Result<SignerIdentifier, HandshakeError> {
		Ok(compute_signer_identifier::<P::Digest, _>(client_verifying_key)?)
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

	/// Decrypt the session key from EnvelopedData and store it securely.
	async fn decrypt_session_key(&mut self, enveloped_data_der: &[u8]) -> Result<(), HandshakeError> {
		let session_key_bytes = self.decrypt_enveloped_content(enveloped_data_der).await?;
		self.session_key = Some(Secret::from(session_key_bytes));

		Ok(())
	}

	/// Decrypt the content of a KARI EnvelopedData addressed to this
	/// server (ECDH via the key provider, KEK unwrap, AEAD open).
	///
	/// Shared by the key exchange and the confidential settlement answer
	/// carried in the client Finished.
	async fn decrypt_enveloped_content(&self, enveloped_data_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let enveloped_data = EnvelopedData::from_der(enveloped_data_der)?;
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

		// Perform ECDH using KeyProvider (takes SEC1 bytes directly);
		// the shared secret arrives already wrapped in SecretSlice.
		let shared_secret = self.server_key_provider.key_agreement(originator_pub_bytes).await?;

		// Derive KEK using HKDF via provider, sized to the negotiated key-wrap algorithm.
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let provider = P::default();

		let key_size = key_wrap_key_size::<P>()?;
		let kek = derive_kek::<P>(&shared_secret, ukm.as_bytes(), TIGHTBEAM_KARI_KDF_INFO, key_size)?;

		// Unwrap CEK. `recipient_enc_keys` is an unauthenticated DER
		// SEQUENCE OF that decodes empty; index only after a length check.
		let wrapped_key = kari
			.recipient_enc_keys
			.first()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.enc_key
			.as_bytes();
		let cek = unwrap_and_verify_with_kek(&provider, kek.as_slice(), wrapped_key)?;

		// Open the encrypted content under the unwrapped CEK
		let cipher = P::AeadCipher::new_from_slice(&cek).map_err(|_| HandshakeError::InvalidKeySize {
			expected: <P::AeadCipher as KeySizeUser>::KeySize::USIZE,
			received: cek.len(),
		})?;

		// Re-box the plaintext. The inner buffer moves, no copy is left behind.
		let content_bytes = cipher.decrypt_content(&enveloped_data.encrypted_content)?;
		Ok(content_bytes.to_insecure()?.into_vec())
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

		// 7. Process TransportOffer and negotiate multiplexing
		self.process_transport_offer(enveloped_data.unprotected_attrs.as_ref()).await?;

		// 8. Decrypt and store session key
		self.decrypt_session_key(enveloped_data_der).await?;

		// 9. Lock transcript and mark AEAD derivation now that session key material is available.
		// For CMS, transcript is locked here (after key exchange processed) rather than during
		// server finished preparation, since session key derivation happens at this point.
		if !self.invariants.transcript_locked {
			self.invariants.lock_transcript()?;
		}
		self.invariants.derive_aead_once()?;

		Ok(())
	}

	/// Validate prerequisites for building server finished message.
	fn validate_server_finished_prerequisites(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)
	}

	/// Prepare transcript hash and compute digest for signing.
	///
	/// The negotiated `SecurityAccept` and `TransportAccept` are appended to
	/// the transcript before hashing so the Finished signature binds both
	/// selections (CWE-345).
	fn prepare_server_finished_digest(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// Compute transcript hash if not already set
		if self.transcript_hash.is_none() {
			if let Some(profile) = self.selected_profile {
				let accept_bytes = attributes::security_accept_transcript_bytes(&SecurityAccept::new(profile))?;
				self.transcript_buffer.extend_from_slice(&accept_bytes);
			}
			if let Some(ref accept) = self.transport_accept {
				let accept_bytes = attributes::transport_accept_transcript_bytes(accept)?;
				self.transcript_buffer.extend_from_slice(&accept_bytes);
			}

			self.transcript_hash = Some(self.compute_transcript_hash()?);
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
		let signature_bytes = self.server_key_provider.sign_prehash(digest).await?;
		Ok(signature_bytes)
	}

	/// Build cryptographic components needed for SignedData.
	async fn build_server_finished_crypto_components(
		&self,
	) -> Result<(SignerIdentifier, AlgorithmIdentifierOwned, AlgorithmIdentifierOwned), HandshakeError> {
		let public_key_bytes = self.server_key_provider.to_public_key_bytes().await?;
		let signer_id = compute_signer_identifier_from_der::<P::Digest>(&public_key_bytes)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };

		Ok((signer_id, digest_alg, signature_alg))
	}

	/// Build the SecurityAccept, TransportAccept, and session receipt
	/// unsigned attributes for the server Finished.
	///
	/// The accepts are advisory like TLS ServerHello extensions
	/// pre-Finished: unauthenticated on the attribute, but tampering
	/// yields a client-side transcript mismatch and the handshake fails
	/// closed. The receipt travels as a server-signed `SignedData`
	/// artifact, third-party verifiable on its own.
	fn build_security_accept_attrs(&self) -> Result<Option<Attributes>, HandshakeError> {
		let mut x509_attrs = Vec::new();

		if let Some(profile) = self.selected_profile {
			let accept_attr = attributes::encode_security_accept(&SecurityAccept::new(profile))?;
			x509_attrs
				.push(Attribute { oid: accept_attr.attr_type, values: SetOfVec::try_from(accept_attr.attr_values)? });
		}
		if let Some(ref accept) = self.transport_accept {
			let accept_attr = attributes::encode_transport_accept(accept)?;
			x509_attrs
				.push(Attribute { oid: accept_attr.attr_type, values: SetOfVec::try_from(accept_attr.attr_values)? });
		}
		if let Some(ref artifact) = self.receipt_artifact {
			let receipt_attr = attributes::encode_session_receipt(artifact)?;
			x509_attrs.push(Attribute {
				oid: receipt_attr.attr_type,
				values: SetOfVec::try_from(receipt_attr.attr_values)?,
			});
		}

		if x509_attrs.is_empty() {
			return Ok(None);
		}

		Ok(Some(Attributes::try_from(x509_attrs)?))
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
			// Same OID lives in SignerInfo and the SignedData digestAlgorithms SET.
			digest_alg: digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: signature_alg,
			signature: OctetString::new(signature_bytes)?,
			unsigned_attrs: self.build_security_accept_attrs()?,
		};

		let octet_string = OctetString::new(transcript_hash)?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = Any::from_der(&econtent_der)?;
		let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent_any) };

		let signed_data = SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![digest_alg].try_into()?,
			encap_content_info,
			certificates: None,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		};

		Ok(signed_data.to_der()?)
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

	/// Build and sign the [`SessionReceipt`] when the accept grants
	/// budgets.
	///
	/// Fail closed: budgets demand a client countersignature,
	/// so a budget-bearing accept without mutual authentication
	/// configured aborts the handshake.
	async fn issue_session_receipt(&mut self) -> Result<(), HandshakeError> {
		let Some(accept) = self.transport_accept.as_ref() else {
			return Ok(());
		};
		let Some(granted) = accept.granted_budgets else {
			return Ok(());
		};

		if self.client_validators.is_none() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidTranscriptHash)?;
		let credit_unit = accept.credit_unit;
		let challenge = self.settlement_challenge.take();
		let (receipt, artifact) = sign_receipt::<P::Digest>(
			transcript_digest,
			granted,
			credit_unit,
			challenge,
			self.server_key_provider.as_ref(),
		)
		.await?;

		self.receipt_artifact = Some(artifact);
		self.session_receipt = Some(receipt);

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

		// 3. Issue the session receipt: the transcript hash pins it to
		// this session, the server signature makes it third-party verifiable
		self.issue_session_receipt().await?;

		// 4. Sign the digest
		let signature_bytes = self.sign_server_finished_digest(&digest).await?;

		// 5. Build cryptographic components
		let (signer_id, digest_alg, signature_alg) = self.build_server_finished_crypto_components().await?;

		// 6. Build SignedData structure
		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidTranscriptHash)?;
		let signed_data_der =
			self.build_server_signed_data(transcript_hash, &signature_bytes, signer_id, digest_alg, signature_alg)?;

		// 7. Finalize by updating transcript and state
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

		// 3. Authenticate a wire-embedded client certificate before use:
		//    set_client_certificate runs the validator chain and enforces
		//    identity immutability across re-handshakes.
		if let Some(cert) = extract_embedded_certificate(signed_data_der)? {
			self.set_client_certificate(cert)?;
		}

		// 4. Extract cryptographic material
		let client_verifying_key = self.extract_client_verifying_key()?;
		let expected_signer_identifier = self.compute_client_signer_identifier(&client_verifying_key)?;

		// 5. Verify signature and content
		let verified_content =
			self.verify_client_signature(signed_data_der, client_verifying_key, expected_signer_identifier)?;

		// 6. Transition state
		self.state.transition(ServerHandshakeState::ClientFinishedReceived)?;

		Ok(verified_content)
	}

	/// Verify the client's receipt countersignature and settle with the
	/// authorizer.
	///
	/// Does nothing when no receipt was issued. Otherwise fails closed:
	/// a missing or invalid countersignature aborts the handshake, and a
	/// settle refusal aborts with the application code. The completed
	/// [`StoredReceipt`] is retained only after both.
	pub async fn process_receipt_ack(&mut self, signed_data_der: &[u8]) -> Result<(), HandshakeError>
	where
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature>,
	{
		// Taken, not cloned: the outcome owns the receipt (and its
		// unbounded ancillary challenge). The fail-closed gate in
		// `complete` keys on the negotiated budgets, not this field.
		let Some(receipt) = self.session_receipt.take() else {
			return Ok(());
		};

		// The artifact's single owner from here on: it either completes
		// into the outcome or travels server-signed as-is.
		let server_artifact = self.receipt_artifact.take().ok_or(HandshakeError::InvalidState)?;

		// The acknowledgement arrives as an EnvelopedData encrypted to
		// this server whose plaintext is the client's receipt
		// `SignerInfo`. Its signed attributes bind the settlement answer,
		// a bearer secret: the plaintext is wiped when the buffer drops.
		let receipt_ack = match extract_receipt_ack_envelope(signed_data_der)? {
			Some(envelope) => {
				let plaintext = Zeroizing::new(self.decrypt_enveloped_content(envelope.as_bytes()).await?);
				Some(SignerInfo::from_der(&plaintext)?)
			}
			None => None,
		};

		let (verdict, ancillary_response) = match receipt_ack.as_ref() {
			None => (SessionVerdict::CountersignatureMissing, None),
			Some(ack) => {
				let client_cert = self.validated_client_cert.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
				let expected_sid = certificate_signer_identifier::<P::Digest>(client_cert)?;
				let public_key = extract_verifying_key_from_cert::<P::Curve>(client_cert)?;
				let verifying_key = P::VerifyingKey::from(public_key);
				settle_receipt_ack::<P::Digest, P::Signature, _>(
					&receipt,
					Some(ack),
					&expected_sid,
					&verifying_key,
					self.transport_authorizer.as_deref(),
				)
				.await?
			}
		};

		// Evidence DER before the move: the raw bytes stay in the
		// outcome even when the SignerInfo folds into the artifact.
		let countersignature = receipt_ack.as_ref().map(SignerInfo::to_der).transpose()?;

		// A verified countersignature completes the artifact; a failed
		// one stays out of it but its DER remains in the outcome as
		// evidence.
		let artifact = match (verdict, receipt_ack) {
			(SessionVerdict::Activated | SessionVerdict::SettlementRejected { .. }, Some(ack)) => {
				complete_receipt_artifact(server_artifact, ack)?
			}
			(_, _) => server_artifact,
		};

		let outcome = SessionOutcome {
			receipt,
			artifact,
			countersignature: countersignature.map(OctetString::new).transpose()?,
			ancillary_response,
			client_certificate: self.validated_client_cert.as_ref().map(Arc::clone),
			verdict,
		};
		self.stored_receipt = Some(record_receipt_outcome(self.session_observer.as_deref(), outcome).await?);

		Ok(())
	}

	/// A budget-bearing accept whose receipt never settled. Keyed on the
	/// durable negotiated budgets: the receipt itself is consumed at
	/// settlement, succeed or fail, so it cannot carry this signal.
	fn receipt_unsettled(&self) -> bool {
		let budget_bearing = self.transport_accept.and_then(|accept| accept.granted_budgets).is_some();
		budget_bearing && self.stored_receipt.is_none()
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ServerHandshakeState::ClientFinishedReceived)?;

		// 2. A budget-bearing session activates only after the receipt
		// settled (fail closed for drivers that skipped or failed
		// process_receipt_ack)
		if self.receipt_unsettled() {
			return Err(HandshakeError::CountersignatureMissing);
		}

		// 3. Transition to complete (AEAD already derived in finalization stage elsewhere)
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

	/// Get the dual-signed session receipt (if the completed handshake
	/// carried budgets).
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}
}

/// Extract the enveloped receipt acknowledgement (EnvelopedData DER
/// encrypted to this server) from a client Finished's SignerInfo
/// unsigned attributes.
///
/// The SignedData is parsed once and duplicate attributes fail closed.
fn extract_receipt_ack_envelope(signed_data_der: &[u8]) -> Result<Option<OctetString>, HandshakeError> {
	let signed_data = SignedData::from_der(signed_data_der)?;
	attributes::find_unsigned_attr(&signed_data, oids::RECEIPT_ACK)?
		.map(|attr| attributes::extract_receipt_ack(&attr))
		.transpose()
}

/// Extract the first X.509 certificate embedded in a Finished message's
/// `certificates` field, if any.
fn extract_embedded_certificate(signed_data_der: &[u8]) -> Result<Option<Certificate>, HandshakeError> {
	use crate::cms::cert::CertificateChoices;

	let signed_data = SignedData::from_der(signed_data_der)?;
	let certificate = signed_data.certificates.as_ref().and_then(|set| {
		set.0.iter().find_map(|choice| match choice {
			// Caller needs an owned cert; the parsed SignedData keeps its copy.
			CertificateChoices::Certificate(cert) => Some(cert.to_owned()),
			CertificateChoices::Other(_) => None,
		})
	});

	Ok(certificate)
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

	fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
		if let Some(policy) = &self.strength_policy {
			return policy.as_ref();
		}

		&DefaultStrengthFloor
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
	P::VerifyingKey:
		From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + PrehashVerifier<P::Signature> + 'static,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::Signature: 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: Send + Sync + KeyInit + 'static,
{
	type Error = HandshakeError;

	fn handle_request<'a, 'b>(&'a mut self, msg: &'b [u8]) -> MaybeSendFuture<'a, Result<Option<Vec<u8>>, Self::Error>>
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
					// This is ClientFinished (SignedData) - no response needed.
					// The receipt countersignature verifies and settles before
					// the session can activate.
					self.process_client_finished(msg)?;
					self.process_receipt_ack(msg).await?;
					Ok(None)
				}
				_ => Err(HandshakeError::InvalidState),
			}
		})
	}

	#[cfg(feature = "aead")]
	fn complete<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<SessionKeys, Self::Error>> {
		Box::pin(async move {
			// 1. Validate state
			if self.state.state() != ServerHandshakeState::ClientFinishedReceived {
				return Err(HandshakeError::InvalidState);
			}

			// 2. A budget-bearing session activates only after the receipt
			// settled (fail closed for drivers that skipped or failed
			// process_receipt_ack)
			if self.receipt_unsettled() {
				return Err(HandshakeError::CountersignatureMissing);
			}

			// 3. Get CEK (session_key) and profile
			let cek = self.session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;

			let transcript = *self.transcript_hash.as_ref().ok_or(HandshakeError::InvalidTranscriptHash)?;
			let directional = cek.with(|key_bytes| self.derive_directional_aead(key_bytes, &transcript))?;
			let ciphers = directional?;

			// 4. Derive the epoch-0 rekey materials alongside the traffic
			// keys, from the same inputs: an in-band renewal later chains
			// from this secret without touching the handshake again. CMS
			// salts key derivation with the transcript hash, so it doubles
			// as the epoch salt here.
			let epoch_derived =
				cek.with(|input_key| derive_epoch_materials::<P>(input_key, &transcript, transcript))?;
			let materials = epoch_derived?;
			self.epoch_materials = Some(materials);

			// 5. Transition to complete
			self.state.transition(ServerHandshakeState::Completed)?;

			// 6. Role-map the directional ciphers with the negotiated OID
			Ok(SessionKeys::for_server(
				ciphers.client_to_server,
				ciphers.server_to_client,
				aead_oid,
			))
		})
	}

	fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}

	fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.mux_settings
	}

	fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	#[cfg(feature = "x509")]
	fn peer_certificate(&self) -> Option<&Certificate> {
		self.validated_client_cert.as_ref().map(|arc| arc.as_ref())
	}

	#[cfg(feature = "aead")]
	fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		self.epoch_materials.take()
	}
}

#[cfg(test)]
mod tests {
	mod server {
		use std::error::Error;

		use super::super::*;
		use crate::cms::cert::IssuerAndSerialNumber;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::crypto::x509::name::Name;
		use crate::crypto::x509::serial_number::SerialNumber;
		use crate::der::{Decode, Encode};
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
		use crate::TightBeamError;

		const TEST_TRANSCRIPT: [u8; 32] = [1u8; 32];
		const TEST_SESSION_KEY: [u8; 32] = [2u8; 32];

		/// Drive Init → Complete for a mutual-auth CMS server handshake.
		async fn complete_handshake(
			server: &mut CmsHandshakeServer<DefaultCryptoProvider>,
			server_public_key: &PublicKey<k256::Secp256k1>,
			client: &TestCertificate,
			transcript_hash: &[u8; 32],
		) -> Result<(), Box<dyn Error>> {
			server.set_client_certificate(client.certificate.to_owned())?;

			let key_exchange = build_test_key_exchange(server_public_key, &TEST_SESSION_KEY)?;
			server.process_key_exchange(&key_exchange).await?;
			assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
			assert!(server.session_key().is_some());

			let _server_finished = server.build_server_finished().await?;
			assert_eq!(server.state(), ServerHandshakeState::ServerFinishedSent);

			let client_finished = build_test_client_finished(&client.signing_key, transcript_hash)?;
			let verified = server.process_client_finished(&client_finished)?;
			assert_eq!(verified, *transcript_hash);
			assert_eq!(server.state(), ServerHandshakeState::ClientFinishedReceived);

			server.complete()?;
			assert!(server.is_complete());
			assert_eq!(server.state(), ServerHandshakeState::Completed);
			Ok(())
		}

		/// Init -> KeyExchangeReceived -> ServerFinishedSent -> ClientFinishedReceived -> Complete
		#[tokio::test]
		async fn test_server_state_flow() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) =
				TestCmsServerBuilder::new().with_transcript_hash(TEST_TRANSCRIPT).build();
			assert_eq!(server.state(), ServerHandshakeState::Init);

			complete_handshake(&mut server, &server_public_key, &create_test_certificate(), &TEST_TRANSCRIPT).await
		}

		#[tokio::test]
		async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
			let (mut server, _) = TestCmsServerBuilder::new().build();
			assert!(server.build_server_finished().await.is_err());
			assert!(server.process_client_finished(&[]).is_err());
			Ok(())
		}

		/// Dealer's choice: no client SecurityOffer; server picks from its list.
		#[tokio::test]
		async fn test_cms_end_to_end_with_profile_negotiation() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) =
				TestCmsServerBuilder::new().with_transcript_hash(TEST_TRANSCRIPT).build();
			server = server.with_supported_profiles(vec![create_aes_gcm_profile(16), create_aes_gcm_profile(32)]);

			complete_handshake(&mut server, &server_public_key, &create_test_certificate(), &TEST_TRANSCRIPT).await?;

			let Some(selected) = server.selected_profile.as_ref() else {
				return Err(TightBeamError::MissingConfiguration.into());
			};
			assert!(selected.aead.is_some());
			assert!(server.session_key().is_some());
			Ok(())
		}

		/// Build a test KeyExchange (EnvelopedData) message.
		fn build_test_key_exchange(
			recipient_public_key: &PublicKey<k256::Secp256k1>,
			session_key: &[u8],
		) -> Result<Vec<u8>, Box<dyn Error>> {
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
			let recipient_pub = *recipient_public_key;
			let kari_builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_ephemeral)
				.with_sender_pub_spki(sender_pub_spki)
				.with_recipient_pub(recipient_pub)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = enveloped_builder.build(session_key, None, None)?;
			Ok(enveloped_data.to_der()?)
		}

		/// Build a test ClientFinished (SignedData) message.
		fn build_test_client_finished(
			signing_key: &Secp256k1SigningKey,
			transcript_hash: &[u8],
		) -> Result<Vec<u8>, Box<dyn Error>> {
			let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
			let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
			let builder =
				TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(signing_key, digest_alg, signature_alg)?;

			let signed_data = builder.build(transcript_hash)?;
			Ok(signed_data.to_der()?)
		}

		/// Create a test security profile with the given AEAD key size.
		fn create_aes_gcm_profile(key_size: u16) -> SecurityProfileDesc {
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

			SecurityProfileDesc {
				digest: Some(HASH_SHA256),
				aead: Some(aead_oid),
				aead_key_size: Some(key_size),
				signature: Some(SIGNER_ECDSA_WITH_SHA256),
				kdf: Some(HASH_SHA256), // HKDF-SHA256
				curve: Some(CURVE_SECP256K1),
				key_wrap: Some(key_wrap_oid),
				kem: None,
			}
		}
	}
}
