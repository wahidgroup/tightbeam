//! CMS-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam handshake protocol using
//! CMS builders and processors.
//!
//! Generic over elliptic curve type to support multiple curves without
//! coupling to secp256k1. The curve type is used only for client certificate
//! verification, while server key operations use the trait abstraction.

#![cfg(all(feature = "builder", feature = "aead", feature = "signature"))]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::marker::PhantomData;

use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignerIdentifier;
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::hash::digest::Digest;
use crate::crypto::hash::Sha3_256;
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::EcdsaSignatureVerifier;
use crate::crypto::sign::{SignatureEncoding, Verifier};
use crate::crypto::x509::ext::pkix::SubjectKeyIdentifier;
use crate::der::asn1::OctetString;
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
/// Generic over elliptic curve type `C` to support multiple curves.
///
/// Manages the complete server handshake flow:
/// 1. Receives and decrypts KeyExchange (EnvelopedData with KARI)
/// 2. Sends server Finished (SignedData)
/// 3. Receives and verifies client Finished (SignedData)
pub struct CmsHandshakeServer<C, Sig, Vk, D>
where
	C: Curve + CurveArithmetic,
	Sig: SignatureEncoding + 'static,
	Vk: Verifier<Sig> + 'static,
	D: Digest + AssociatedOid,
{
	state: ServerStateTransition,
	server_key: Arc<dyn ServerHandshakeKey>,
	client_cert: Option<Certificate>,
	transcript_hash: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	_phantom: PhantomData<(C, Sig, Vk, D)>,
}

impl<C, Sig, Vk, D> CmsHandshakeServer<C, Sig, Vk, D>
where
	C: Curve + CurveArithmetic,
	C::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	Sig: SignatureEncoding,
	Vk: Verifier<Sig> + From<PublicKey<C>> + EncodePublicKey,
	D: Digest + AssociatedOid,
{
	/// Create a new CMS handshake server.
	///
	/// # Parameters
	/// - `server_key`: The server's signing key for authentication (trait object)
	/// - `transcript_hash`: The handshake transcript hash (from previous handshake messages)
	pub fn new(server_key: Arc<dyn ServerHandshakeKey>, transcript_hash: Vec<u8>) -> Self {
		Self {
			state: ServerStateTransition::new(),
			server_key,
			client_cert: None,
			transcript_hash,
			session_key: None,
			_phantom: PhantomData,
		}
	}

	/// Set the client certificate (optional, for mutual authentication).
	pub fn set_client_certificate(&mut self, cert: Certificate) -> Result<(), HandshakeError> {
		// Validate certificate (expiry check)
		crate::crypto::x509::validate_certificate_expiry(&cert)?;

		self.client_cert = Some(cert);
		Ok(())
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
	fn extract_client_verifying_key(&self) -> Result<Vk, HandshakeError> {
		let client_cert = self.get_client_certificate()?;
		let client_public_key = PublicKey::<C>::from_sec1_bytes(
			client_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;
		Ok(Vk::from(client_public_key))
	}

	/// Compute the signer identifier from the client's verifying key.
	fn compute_client_signer_identifier(&self, client_verifying_key: &Vk) -> Result<SignerIdentifier, HandshakeError> {
		let public_key_der_bytes = client_verifying_key.to_public_key_der()?;

		let mut hasher = sha3::Sha3_256::new();
		hasher.update(public_key_der_bytes.as_bytes());

		let subject_key_identifier_bytes = hasher.finalize();
		let subject_key_identifier_octets = OctetString::new(&subject_key_identifier_bytes[..20])?;
		let subject_key_identifier = SubjectKeyIdentifier::from(subject_key_identifier_octets);

		let expected_signer_identifier = SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier);
		Ok(expected_signer_identifier)
	}

	/// Verify the signature and content of the SignedData.
	fn verify_client_signature(
		&self,
		signed_data_der: &[u8],
		client_verifying_key: Vk,
		expected_sid: SignerIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		let verifier = EcdsaSignatureVerifier::<Vk, Sig, Sha3_256>::from_verifying_key_with_sid(
			client_verifying_key,
			expected_sid,
		);
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
		self.state.transition(HandshakeState::KeyExchangeReceived)?;

		// 3. Decode EnvelopedData to access encrypted content
		let enveloped_data = EnvelopedData::from_der(enveloped_data_der)?;

		// 4. Decrypt KARI and get CEK (Content Encryption Key)
		let content_encryption_key = self.server_key.decrypt_kari(enveloped_data_der, TIGHTBEAM_KARI_KDF_INFO, 0)?;

		// 5. Decrypt the actual content using the CEK
		let encrypted_content_info = &enveloped_data.encrypted_content;
		let ciphertext_bytes = encrypted_content_info
			.encrypted_content
			.as_ref()
			.ok_or_else(|| HandshakeError::InvalidEciesMessage("Missing encrypted content".to_string()))?
			.as_bytes();

		// 6. Use the utility function for AES-GCM decryption
		let session_key_bytes = aes_gcm_decrypt(&content_encryption_key, ciphertext_bytes, None)?;

		// 7. Store session key securely
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
		self.state.transition(HandshakeState::ServerFinishedSent)?;

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
		self.state.transition(HandshakeState::ClientFinishedReceived)?;

		Ok(verified_content)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(HandshakeState::ClientFinishedReceived)?;

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
// ServerHandshakeProtocol Implementation
// ============================================================================

impl<C, Sig, Vk, D> ServerHandshakeProtocol for CmsHandshakeServer<C, Sig, Vk, D>
where
	C: Curve + CurveArithmetic,
	C::FieldBytesSize: ModulusSize,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	Sig: SignatureEncoding + Send + Sync,
	Vk: signature::Verifier<Sig> + From<PublicKey<C>> + EncodePublicKey + Send + Sync,
	D: Digest + AssociatedOid + Send + Sync,
{
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

	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>> {
		Box::pin(async move {
			self.complete()?;
			self.session_key.take().ok_or(HandshakeError::InvalidState)
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}
}

/// Type alias for CMS server using secp256k1 curve.
///
/// This is the default curve used in TightBeam and is provided as a
/// convenient alias for the generic `CmsHandshakeServer`.
#[cfg(feature = "secp256k1")]
pub type CmsHandshakeServerSecp256k1 = CmsHandshakeServer<
	crate::crypto::sign::ecdsa::k256::Secp256k1,
	crate::crypto::sign::ecdsa::Secp256k1Signature,
	crate::crypto::sign::ecdsa::Secp256k1VerifyingKey,
	crate::crypto::hash::Sha3_256,
>;

#[cfg(test)]
mod tests {
	mod server {
		use super::super::*;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::crypto::x509::name::Name;
		use crate::crypto::x509::serial_number::SerialNumber;
		use crate::der::Decode;
		use crate::random::{generate_nonce, OsRng};
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
			let sender_pub_spki = crate::spki::SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes()).unwrap();

			// Create UKM with random bytes
			let ukm_bytes = generate_nonce::<64>(None).unwrap();
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec()).unwrap();

			// Create recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: Name::default(),
				serial_number: SerialNumber::new(&[0x01]).unwrap(),
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned { oid: crate::asn1::AES_256_WRAP_OID, parameters: None };

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
			let digest_alg = AlgorithmIdentifierOwned { oid: crate::asn1::HASH_SHA3_256_OID, parameters: None };
			let signature_alg =
				AlgorithmIdentifierOwned { oid: crate::asn1::SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None };
			let mut client_finished_builder = TightBeamSignedDataBuilder::<Secp256k1Signature, Sha3_256>::new(
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
			let mut server = CmsHandshakeServerSecp256k1::new(Arc::new(server_key), transcript_hash);

			// Can't build server finished before processing key exchange
			let result = server.build_server_finished();
			assert!(result.is_err());

			// Can't process client finished before sending server finished
			let result = server.process_client_finished(&[]);
			assert!(result.is_err());

			Ok(())
		}
	}
}
