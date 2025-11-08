//! CMS-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam handshake protocol using
//! CMS builders and processors.

#![cfg(all(feature = "builder", feature = "aead", feature = "signature"))]

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;

use crate::asn1::AES_256_WRAP_OID;
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::cms::{cert::IssuerAndSerialNumber, signed_data::SignerIdentifier};
use crate::crypto::hash::Digest;
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::crypto::sign::EcdsaSignatureVerifier;
use crate::crypto::sign::SignatureAlgorithmIdentifier;
use crate::crypto::sign::{Keypair, SignatureEncoding, Signer, Verifier};
use crate::crypto::x509::ext::pkix::SubjectKeyIdentifier;
use crate::crypto::x509::validate_certificate_expiry;
use crate::crypto::x509::Certificate;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::Decode;
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::builders::{
	TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::state::{ClientStateTransition, HandshakeState, StateTransition};
use crate::transport::handshake::utils::aes_256_gcm_algorithm;
use crate::transport::handshake::ClientHandshakeProtocol;

/// Client-side CMS handshake orchestrator.
///
/// Generic over curve type `C`, signature type `Sig`, verifying key type `Vk`,
/// signing key type `Sk`, and digest type `D`.
///
/// Manages the complete client handshake flow:
/// 1. Sends KeyExchange (EnvelopedData with KARI)
/// 2. Receives and verifies server Finished (SignedData)
/// 3. Sends client Finished (SignedData)
pub struct CmsHandshakeClient<C, Sig, Vk, Sk, D> {
	state: ClientStateTransition,
	client_key: Sk,
	server_cert: Certificate,
	transcript_hash: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	_phantom: PhantomData<(C, Sig, Vk, D)>,
}

impl<C, Sig, Vk, Sk, D> CmsHandshakeClient<C, Sig, Vk, Sk, D>
where
	C: Curve + CurveArithmetic,
	C::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	PublicKey<C>: EncodePublicKey,
	Sig: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
	Vk: Verifier<Sig> + From<PublicKey<C>> + EncodePublicKey + Send + Sync + 'static,
	Sk: Signer<Sig> + Keypair<VerifyingKey = Vk> + Clone + Send + Sync + 'static,
	D: Digest + AssociatedOid + Send + Sync + 'static,
{
	/// Create a new CMS handshake client.
	///
	/// # Parameters
	/// - `client_key`: The client's signing key for authentication
	/// - `server_cert`: The server's certificate (for key agreement)
	/// - `transcript_hash`: The handshake transcript hash (from previous handshake messages)
	pub fn new(client_key: Sk, server_cert: Certificate, transcript_hash: Vec<u8>) -> Self {
		Self {
			state: ClientStateTransition::new(),
			client_key,
			server_cert,
			transcript_hash,
			session_key: None,
			_phantom: PhantomData,
		}
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: HandshakeState) -> Result<(), HandshakeError> {
		if self.state.state() != expected {
			Err(HandshakeError::InvalidState)
		} else {
			Ok(())
		}
	}

	/// Validate state and server certificate for key exchange.
	fn validate_state_and_certificate(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(HandshakeState::Init)?;

		validate_certificate_expiry(&self.server_cert)?;

		Ok(())
	}

	/// Extract the server's public key from certificate.
	fn extract_server_public_key(&self) -> Result<PublicKey<C>, HandshakeError> {
		Ok(PublicKey::<C>::from_sec1_bytes(
			self.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?)
	}

	/// Create ephemeral keypair for the sender.
	fn create_ephemeral_keypair(&self) -> Result<(SecretKey<C>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let sender_ephemeral = SecretKey::<C>::random(&mut OsRng);
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

	/// Extract the server's verifying key from certificate.
	fn extract_server_verifying_key(&self) -> Result<Vk, HandshakeError> {
		let server_public_key = self.extract_server_public_key()?;
		Ok(Vk::from(server_public_key))
	}

	/// Compute the signer identifier from the server's verifying key.
	fn compute_signer_identifier(&self, server_verifying_key: &Vk) -> Result<SignerIdentifier, HandshakeError> {
		let public_key_der_bytes = server_verifying_key.to_public_key_der()?;

		let mut hasher = D::new();
		Digest::update(&mut hasher, public_key_der_bytes.as_bytes());

		let subject_key_identifier_bytes = Digest::finalize(hasher);
		let subject_key_identifier_octets = OctetString::new(&subject_key_identifier_bytes.as_slice()[..20])?;
		let subject_key_identifier = SubjectKeyIdentifier::from(subject_key_identifier_octets);

		let expected_signer_identifier = SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier);
		Ok(expected_signer_identifier)
	}

	/// Verify the signature and content of the SignedData.
	fn verify_signature(
		&self,
		signed_data_der: &[u8],
		server_verifying_key: Vk,
		expected_sid: SignerIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		let verifier =
			EcdsaSignatureVerifier::<Vk, Sig, D>::from_verifying_key_with_sid(server_verifying_key, expected_sid);
		let processor = TightBeamSignedDataProcessor::new(verifier);

		// Verify content matches our transcript hash
		let digest_oid = D::OID;
		let verified_content = processor.process_der(signed_data_der, &digest_oid)?;
		if verified_content != self.transcript_hash {
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
		self.validate_state_and_certificate()?;

		// 2. Extract cryptographic material
		let server_public_key = self.extract_server_public_key()?;
		let (sender_ephemeral, sender_pub_spki) = self.create_ephemeral_keypair()?;

		// 3. Create UKM (user keying material)
		let ukm_bytes = generate_nonce::<64>(None)?;
		let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

		// 4. Build recipient identifier
		let rid = self.build_recipient_identifier();

		// 5. Key encryption algorithm (ECDH + HKDF + AES wrap)
		let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_256_WRAP_OID, parameters: None };

		// 6. Build KARI (Key Agreement Recipient Info) structure
		let kari_builder = TightBeamKariBuilder::<C>::new()
			.with_sender_priv(sender_ephemeral)
			.with_sender_pub_spki(sender_pub_spki)
			.with_recipient_pub(server_public_key)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		// 7. Create EnvelopedData builder with generic curve type
		let enveloped_builder: TightBeamEnvelopedDataBuilder<C> = TightBeamEnvelopedDataBuilder::new(kari_builder);
		let enveloped_builder = enveloped_builder.with_content_encryption_alg(aes_256_gcm_algorithm());

		// 8. Build and encode
		let enveloped_data_der = enveloped_builder.build_der(&session_key, None)?;

		// 9. Store session key and transition state
		self.session_key = Some(Secret::from(session_key));
		self.state.transition(HandshakeState::KeyExchangeSent)?;

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
		self.validate_expected_state(HandshakeState::KeyExchangeSent)?;

		// 2. Extract cryptographic material
		let server_verifying_key = self.extract_server_verifying_key()?;
		let expected_signer_identifier = self.compute_signer_identifier(&server_verifying_key)?;

		// 3. Verify signature and content
		let verified_content =
			self.verify_signature(signed_data_der, server_verifying_key, expected_signer_identifier)?;

		// 4. Transition state
		self.state.transition(HandshakeState::ServerFinishedReceived)?;

		Ok(verified_content)
	}

	/// Build client Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub fn build_client_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(HandshakeState::ServerFinishedReceived)?;

		// 2. Algorithm identifiers
		let digest_alg = AlgorithmIdentifierOwned { oid: D::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: Sig::ALGORITHM_OID, parameters: None };

		// 3. Build SignedData
		let mut builder =
			TightBeamSignedDataBuilder::<Sig, D>::new(self.client_key.clone(), digest_alg, signature_alg)?;
		let signed_data_der = builder.build_der(&self.transcript_hash)?;

		// 4. Transition state
		self.state.transition(HandshakeState::ClientFinishedSent)?;

		Ok(signed_data_der)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(HandshakeState::ClientFinishedSent)?;

		// 2. Transition to complete
		self.state.transition(HandshakeState::Complete)?;

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
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<C, Sig, Vk, Sk, D> ClientHandshakeProtocol for CmsHandshakeClient<C, Sig, Vk, Sk, D>
where
	C: Curve + CurveArithmetic + Send + Sync,
	C::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	PublicKey<C>: EncodePublicKey,
	Sig: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
	Vk: Verifier<Sig> + From<PublicKey<C>> + EncodePublicKey + Send + Sync + 'static,
	Sk: Signer<Sig> + Keypair<VerifyingKey = Vk> + Clone + Send + Sync + 'static,
	D: Digest + AssociatedOid + Send + Sync + 'static,
{
	type SessionKey = Secret<Vec<u8>>;
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

	fn complete<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>> {
		Box::pin(async move {
			self.complete()?;
			self.session_key.take().ok_or(HandshakeError::InvalidState)
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}
}

/// Type alias for CMS client using secp256k1 curve.
///
/// This is the default curve used in TightBeam and is provided as a
/// convenient alias for the generic `CmsHandshakeClient`.
#[cfg(feature = "secp256k1")]
pub type CmsHandshakeClientSecp256k1 = CmsHandshakeClient<
	crate::crypto::sign::ecdsa::Secp256k1,
	crate::crypto::sign::ecdsa::Secp256k1Signature,
	crate::crypto::sign::ecdsa::Secp256k1VerifyingKey,
	crate::crypto::sign::ecdsa::Secp256k1SigningKey,
	crate::crypto::hash::Sha3_256,
>;

#[cfg(test)]
mod tests {
	mod client {
		use super::super::*;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::der::Decode;
		use crate::transport::handshake::processors::{
			AesGcmContentDecryptor, TightBeamEnvelopedDataProcessor, TightBeamKariRecipient,
		};
		use crate::transport::handshake::tests::*;
		use crate::{HASH_SHA3_256_OID, SIGNER_ECDSA_WITH_SHA3_256_OID};

		#[test]
		fn test_client_state_flow() -> Result<(), Box<dyn std::error::Error>> {
			// Given: A CMS client in init state with a server certificate
			let transcript_hash = vec![1u8; 32];
			let server_test_cert = create_test_certificate();
			let mut client = TestCmsClientBuilder::new()
				.with_server_cert(server_test_cert.certificate.clone())
				.with_transcript_hash(transcript_hash.clone())
				.build();
			assert_eq!(client.state(), HandshakeState::Init);

			// When: Client builds a valid key exchange
			let session_key = vec![2u8; 32];
			let key_exchange = client.build_key_exchange(session_key.clone())?;
			assert_eq!(client.state(), HandshakeState::KeyExchangeSent);
			// Verify session key is stored
			assert!(client.session_key().is_some());

			// Then: Server should be able to decrypt it using the matching private key
			let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(&key_exchange)?;
			let server_secret = SecretKey::from(server_test_cert.signing_key.clone());
			let kari_processor = TightBeamKariRecipient::new(server_secret);
			let content_decryptor = AesGcmContentDecryptor;
			let processor = TightBeamEnvelopedDataProcessor::new(kari_processor, content_decryptor);
			let decrypted = processor.process(&enveloped_data)?;
			assert_eq!(decrypted, session_key);

			// When: Client processes server Finished
			let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256_OID, parameters: None };
			let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None };
			let mut server_finished_builder = TightBeamSignedDataBuilder::<Secp256k1Signature, Sha3_256>::new(
				server_test_cert.signing_key,
				digest_alg,
				signature_alg,
			)?;
			let server_finished = server_finished_builder.build_der(&transcript_hash)?;

			let verified = client.process_server_finished(&server_finished)?;
			assert_eq!(verified, transcript_hash);
			assert_eq!(client.state(), HandshakeState::ServerFinishedReceived);

			// Build client Finished
			let _client_finished = client.build_client_finished()?;
			assert_eq!(client.state(), HandshakeState::ClientFinishedSent);

			// Complete
			client.complete()?;
			assert!(client.is_complete());
			assert_eq!(client.state(), HandshakeState::Complete);

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
}
