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

use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignerIdentifier;
use crate::constants::{TIGHTBEAM_KARI_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO};
use crate::crypto::aead::KeyInit;
use crate::crypto::kdf::KdfProvider;
use crate::crypto::negotiation::select_profile;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::EcdsaSignatureVerifier;
use crate::crypto::x509::policy::CertificateValidation;
use crate::der::oid::AssociatedOid;
use crate::der::Decode;
use crate::spki::EncodePublicKey;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::state::{HandshakeState, ServerStateTransition, StateTransition};
use crate::transport::handshake::utils::aes_gcm_decrypt;
use crate::transport::handshake::{ServerHandshakeKey, ServerHandshakeProtocol};
use crate::x509::Certificate;

/// Server-side CMS handshake orchestrator.
///
/// Generic over `P: CryptoProvider` for cryptographic operations.
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
	state: ServerStateTransition,
	server_key: Arc<dyn ServerHandshakeKey>,
	client_cert: Option<Certificate>,
	validated_client_cert: Option<Certificate>,
	transcript_hash: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	supported_profiles: Vec<SecurityProfileDesc>,
	selected_profile: Option<SecurityProfileDesc>,
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	_phantom: PhantomData<P>,
}

impl<P> CmsHandshakeServer<P>
where
	P: CryptoProvider,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: 'static,
	P::AeadCipher: KeyInit + 'static,
{
	/// Create a new CMS handshake server.
	///
	/// # Parameters
	/// - `server_key`: The server's signing key for authentication (trait object)
	/// - `transcript_hash`: The handshake transcript hash (from previous handshake messages)
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	pub fn new(
		server_key: Arc<dyn ServerHandshakeKey>,
		transcript_hash: Vec<u8>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Self {
		Self {
			state: ServerStateTransition::new(),
			server_key,
			client_cert: None,
			validated_client_cert: None,
			transcript_hash,
			session_key: None,
			supported_profiles: Vec::new(),
			selected_profile: None,
			client_validators,
			_phantom: PhantomData,
		}
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
			if existing_cert != &cert {
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
		self.client_cert = Some(cert.clone());

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

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: HandshakeState) -> Result<(), HandshakeError> {
		if self.state.state() != expected {
			return Err(HandshakeError::InvalidState);
		}
		Ok(())
	}

	/// Get the client certificate, returning an error if not set.
	fn get_client_certificate(&self) -> Result<&Certificate, HandshakeError> {
		self.client_cert.as_ref().ok_or(HandshakeError::MissingClientCertificate)
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
		if verified_content != self.transcript_hash {
			Err(HandshakeError::SignatureVerificationFailed)
		} else {
			Ok(verified_content)
		}
	}

	/// Process KeyExchange message (EnvelopedData with KARI containing session key).
	///
	/// # Parameters
	/// - `enveloped_data_der`: DER-encoded EnvelopedData from client
	///
	/// # Security
	/// Session key is stored internally and zeroized on drop. Not returned to prevent
	/// unnecessary copies of key material in memory.
	pub fn process_key_exchange(&mut self, enveloped_data_der: &[u8]) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(HandshakeState::Init)?;

		// 2. Transition to received state
		self.state.dispatch(HandshakeState::KeyExchangeReceived)?;

		// 3. Decode EnvelopedData to access encrypted content
		let enveloped_data = EnvelopedData::from_der(enveloped_data_der)?;

		// 4. Extract and process SecurityOffer if present (negotiation)
		if let Some(unprotected_attrs) = &enveloped_data.unprotected_attrs {
			// Convert x509_cert::attr::Attributes to HandshakeAttribute
			let handshake_attrs: Result<Vec<_>, HandshakeError> = unprotected_attrs
				.iter()
				.map(|attr| {
					Ok(crate::transport::handshake::attributes::HandshakeAttribute {
						attr_type: attr.oid.clone(),
						attr_values: attr.values.clone().into(),
					})
				})
				.collect();
			let handshake_attrs = handshake_attrs?;

			// Try to find SecurityOffer
			if let Ok(offer_attr) = crate::transport::handshake::attributes::find(
				&handshake_attrs,
				&crate::asn1::transport::HANDSHAKE_SECURITY_OFFER_OID,
			) {
				let offer = crate::transport::handshake::attributes::extract_security_offer(offer_attr)?;

				// Profile negotiation
				if self.supported_profiles.is_empty() {
					return Err(HandshakeError::InvalidState); // Server must configure profiles
				}

				let selected = select_profile(&offer, &self.supported_profiles)?;
				self.selected_profile = Some(selected);
			} else if !self.supported_profiles.is_empty() {
				// No offer from client, use dealer's choice (first profile)
				self.selected_profile = Some(self.supported_profiles[0]);
			}
		} else if !self.supported_profiles.is_empty() {
			// No unprotected attributes at all, use dealer's choice
			self.selected_profile = Some(self.supported_profiles[0]);
		}

		// 5. Decrypt KARI and get CEK (Content Encryption Key)
		let content_encryption_key = self.server_key.decrypt_kari(enveloped_data_der, TIGHTBEAM_KARI_KDF_INFO, 0)?;

		// 6. Decrypt the actual content using the CEK
		let encrypted_content_info = &enveloped_data.encrypted_content;
		let ciphertext_bytes = encrypted_content_info
			.encrypted_content
			.as_ref()
			.ok_or_else(|| HandshakeError::MissingEncryptedContent)?
			.as_bytes();

		// 7. Use the utility function for AES-GCM decryption
		let session_key_bytes = aes_gcm_decrypt(&content_encryption_key, ciphertext_bytes, None)?;

		// 8. Store session key securely
		self.session_key = Some(Secret::from(session_key_bytes));

		Ok(())
	}

	/// Build server Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub fn build_server_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(HandshakeState::KeyExchangeReceived)?;

		// 2. Get algorithm identifiers from the key implementation
		let digest_alg = self.server_key.digest_algorithm();
		let signature_alg = self.server_key.signature_algorithm();

		// 3. Build SignedData
		let signed_data_der =
			self.server_key
				.build_cms_signed_data(&self.transcript_hash, &digest_alg, &signature_alg)?;

		// 4. Transition state
		self.state.dispatch(HandshakeState::ServerFinishedSent)?;

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
		self.validate_expected_state(HandshakeState::ServerFinishedSent)?;

		// 2. Extract cryptographic material
		let client_verifying_key = self.extract_client_verifying_key()?;
		let expected_signer_identifier = self.compute_client_signer_identifier(&client_verifying_key)?;

		// 3. Verify signature and content
		let verified_content =
			self.verify_client_signature(signed_data_der, client_verifying_key, expected_signer_identifier)?;

		// 4. Transition state
		self.state.dispatch(HandshakeState::ClientFinishedReceived)?;

		Ok(verified_content)
	}

	/// Derive the final session key from the CEK using HKDF.
	///
	/// Uses the negotiated profile's key size to derive the correct length key
	/// for the negotiated AEAD cipher. The transcript hash provides session-specific
	/// context for the derivation.
	///
	/// # Parameters
	/// - `cek`: Content Encryption Key (the session_key extracted from EnvelopedData)
	///
	/// # Returns
	/// The derived AEAD cipher ready for use
	fn derive_final_session_key(&self, cek: &[u8]) -> Result<P::AeadCipher, HandshakeError> {
		// Get key size from negotiated profile
		let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
		let key_size = profile.aead_key_size.ok_or(HandshakeError::InvalidState)? as usize;

		// Enforce minimum salt length (16 bytes) for secure key derivation
		if self.transcript_hash.len() < 16 {
			return Err(HandshakeError::InsufficientSaltEntropy { actual: self.transcript_hash.len(), minimum: 16 });
		}

		// Use transcript hash as salt for session-specific key derivation
		let salt = Some(self.transcript_hash.as_slice());

		// Derive key with dynamic size based on negotiated cipher
		// Use provider's KDF with its concrete digest type
		let final_key_bytes = P::Kdf::derive_dynamic_key(cek, TIGHTBEAM_SESSION_KDF_INFO, salt, key_size)?;

		Ok(P::AeadCipher::new_from_slice(&final_key_bytes[..])?)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(HandshakeState::ClientFinishedReceived)?;

		// 2. Transition to complete
		self.state.dispatch(HandshakeState::Complete)?;

		Ok(())
	}

	/// Get the current handshake state.
	pub fn state(&self) -> HandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_complete()
	}

	/// Get the session key (if available).
	///
	/// Returns a reference to the Secret-wrapped session key bytes.
	pub fn session_key(&self) -> Option<&Secret<Vec<u8>>> {
		self.session_key.as_ref()
	}
}

// ============================================================================
// ServerHandshakeProtocol Implementation
// ============================================================================

impl<P> ServerHandshakeProtocol for CmsHandshakeServer<P>
where
	P: CryptoProvider + Send + Sync,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	P::Signature: 'static,
	P::Digest: 'static,
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
				HandshakeState::Init => {
					// This is KeyExchange (EnvelopedData) - process and send ServerFinished
					self.process_key_exchange(msg)?;
					let server_finished = self.build_server_finished()?;
					Ok(Some(server_finished))
				}
				HandshakeState::ServerFinishedSent => {
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
			if self.state.state() != HandshakeState::ClientFinishedReceived {
				return Err(HandshakeError::InvalidState);
			}

			// 2. Get CEK (session_key) and profile
			let cek = self.session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;

			// 3. Derive final session key as P::AeadCipher
			let cipher = cek.with(|key_bytes| self.derive_final_session_key(key_bytes))?;

			// 4. Transition to complete
			self.state.dispatch(HandshakeState::Complete)?;

			// 5. Wrap cipher in RuntimeAead with negotiated OID
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
		use crate::random::{generate_nonce, OsRng};
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
		use crate::transport::handshake::builders::{TightBeamEnvelopedDataBuilder, TightBeamSignedDataBuilder};
		use crate::transport::handshake::tests::*;
		use crate::transport::handshake::TightBeamKariBuilder;

		#[test]
		fn test_server_state_flow() -> Result<(), Box<dyn std::error::Error>> {
			// Given: A CMS server in init state
			let transcript_hash = vec![1u8; 32];
			let (mut server, server_public_key) = TestCmsServerBuilder::new()
				.with_transcript_hash(transcript_hash.clone())
				.build();
			assert_eq!(server.state(), HandshakeState::Init);

			// And: A client certificate for mutual authentication
			let client_test_cert = create_test_certificate();
			server.set_client_certificate(client_test_cert.certificate.clone())?;

			// When: Server processes a valid client key exchange
			let session_key = vec![2u8; 32];

			// Generate ephemeral sender key for KARI

			let sender_ephemeral = SecretKey::<k256::Secp256k1>::random(&mut OsRng);
			let sender_public = sender_ephemeral.public_key();
			let sender_pub_spki = sender_public.to_public_key_der().unwrap();
			let sender_pub_spki = SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes()).unwrap();

			// Create UKM with random bytes
			let ukm_bytes = generate_nonce::<64>(None).unwrap();
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec()).unwrap();

			// Create recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
				issuer: Name::default(),
				serial_number: SerialNumber::new(&[0x01]).unwrap(),
			});

			// Key encryption algorithm
			let oid = crate::asn1::AES_256_WRAP_OID;
			let key_enc_alg = AlgorithmIdentifierOwned { oid, parameters: None };

			let kari_builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_ephemeral)
				.with_sender_pub_spki(sender_pub_spki)
				.with_recipient_pub(server_public_key)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);
			let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let key_exchange = enveloped_builder.build_der(&session_key, None)?;

			// Process KeyExchange
			server.process_key_exchange(&key_exchange)?;
			assert_eq!(server.state(), HandshakeState::KeyExchangeReceived);
			// Verify session key is stored (cannot compare directly - it's wrapped in Secret)
			assert!(server.session_key().is_some());

			// Build server Finished
			let _server_finished = server.build_server_finished()?;
			assert_eq!(server.state(), HandshakeState::ServerFinishedSent);

			// Build client Finished
			let oid = crate::asn1::HASH_SHA3_256_OID;
			let digest_alg = AlgorithmIdentifierOwned { oid, parameters: None };
			let oid = crate::asn1::SIGNER_ECDSA_WITH_SHA3_256_OID;
			let signature_alg = AlgorithmIdentifierOwned { oid, parameters: None };
			let mut client_finished_builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider>::new(
				client_test_cert.signing_key.clone(),
				digest_alg,
				signature_alg,
			)?;
			let client_finished = client_finished_builder.build_der(&transcript_hash)?;

			// Process client Finished
			let verified = server.process_client_finished(&client_finished)?;
			assert_eq!(verified, transcript_hash);
			assert_eq!(server.state(), HandshakeState::ClientFinishedReceived);

			// Complete
			server.complete()?;
			assert!(server.is_complete());
			assert_eq!(server.state(), HandshakeState::Complete);

			Ok(())
		}

		#[test]
		fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
			let server_key = Secp256k1SigningKey::random(&mut OsRng);
			let transcript_hash = vec![1u8; 32];
			let mut server = CmsHandshakeServerSecp256k1::new(Arc::new(server_key), transcript_hash, None);

			// Can't build server finished before processing key exchange
			let result = server.build_server_finished();
			assert!(result.is_err());

			// Can't process client finished before sending server finished
			let result = server.process_client_finished(&[]);
			assert!(result.is_err());

			Ok(())
		}

		/// Test CMS end-to-end handshake with profile negotiation and session key derivation
		#[test]
		fn test_cms_end_to_end_with_profile_negotiation() -> Result<(), Box<dyn std::error::Error>> {
			use crate::crypto::profiles::SecurityProfileDesc;

			// Setup: Create server with profile negotiation support
			let transcript_hash = vec![1u8; 32];
			let (mut server, server_public_key) = TestCmsServerBuilder::new()
				.with_transcript_hash(transcript_hash.clone())
				.build();

			// Configure server with AES-128-GCM and AES-256-GCM profiles
			let aes128_profile = SecurityProfileDesc {
				digest: crate::asn1::HASH_SHA256_OID,
				aead: Some(crate::asn1::AES_128_GCM_OID),
				aead_key_size: Some(16),
				signature: Some(crate::asn1::SIGNER_ECDSA_WITH_SHA256_OID),
				key_wrap: Some(crate::asn1::AES_128_WRAP_OID),
			};

			let aes256_profile = SecurityProfileDesc {
				digest: crate::asn1::HASH_SHA256_OID,
				aead: Some(crate::asn1::AES_256_GCM_OID),
				aead_key_size: Some(32),
				signature: Some(crate::asn1::SIGNER_ECDSA_WITH_SHA256_OID),
				key_wrap: Some(crate::asn1::AES_256_WRAP_OID),
			};

			server = server.with_supported_profiles(vec![aes128_profile, aes256_profile]);

			// Set client certificate for mutual auth
			let client_test_cert = create_test_certificate();
			server.set_client_certificate(client_test_cert.certificate.clone())?;

			// Step 1: Client sends KeyExchange with session key (without explicit offer)
			let session_key = vec![2u8; 32];

			let sender_ephemeral = SecretKey::<k256::Secp256k1>::random(&mut OsRng);
			let sender_public = sender_ephemeral.public_key();
			let sender_pub_spki = sender_public.to_public_key_der().unwrap();
			let sender_pub_spki = SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes()).unwrap();

			let ukm_bytes = generate_nonce::<64>(None).unwrap();
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec()).unwrap();

			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
				issuer: Name::default(),
				serial_number: SerialNumber::new(&[0x01]).unwrap(),
			});

			let oid = crate::asn1::AES_128_WRAP_OID;
			let key_enc_alg = AlgorithmIdentifierOwned { oid, parameters: None };

			let kari_builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_ephemeral)
				.with_sender_pub_spki(sender_pub_spki)
				.with_recipient_pub(server_public_key)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);
			let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let key_exchange = enveloped_builder.build_der(&session_key, None)?;

			// Step 2: Server processes KeyExchange
			server.process_key_exchange(&key_exchange)?;
			assert_eq!(server.state(), HandshakeState::KeyExchangeReceived);
			assert!(server.session_key().is_some());

			// Verify a profile was selected (dealer's choice since no client offer)
			assert!(server.selected_profile.is_some());
			let selected = server.selected_profile.unwrap();
			// Verify it's one of our configured profiles
			assert!(
				selected.aead == Some(crate::asn1::AES_128_GCM_OID)
					|| selected.aead == Some(crate::asn1::AES_256_GCM_OID)
			);

			// Step 3: Server builds ServerFinished
			let _server_finished = server.build_server_finished()?;
			assert_eq!(server.state(), HandshakeState::ServerFinishedSent);

			// Step 4: Client sends ClientFinished
			let oid = crate::asn1::HASH_SHA3_256_OID;
			let digest_alg = AlgorithmIdentifierOwned { oid, parameters: None };
			let oid = crate::asn1::SIGNER_ECDSA_WITH_SHA3_256_OID;
			let signature_alg = AlgorithmIdentifierOwned { oid, parameters: None };
			let mut client_finished_builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider>::new(
				client_test_cert.signing_key.clone(),
				digest_alg,
				signature_alg,
			)?;
			let client_finished = client_finished_builder.build_der(&transcript_hash)?;

			// Step 5: Server processes ClientFinished
			server.process_client_finished(&client_finished)?;
			assert_eq!(server.state(), HandshakeState::ClientFinishedReceived);

			// Step 6: Complete handshake
			server.complete()?;
			assert_eq!(server.state(), HandshakeState::Complete);
			assert!(server.is_complete());

			// Verify session key is available for key derivation
			assert!(server.session_key().is_some());

			Ok(())
		}
	}
}
