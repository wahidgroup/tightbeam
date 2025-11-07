//! CMS-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam handshake protocol using
//! CMS builders and processors.

#![cfg(all(feature = "builder", feature = "aead", feature = "signature"))]

use core::marker::PhantomData;

use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, SecretKey};
use crate::crypto::sign::EcdsaSignatureVerifier;
use crate::der::asn1::ObjectIdentifier;
use crate::der::Decode;
use crate::random::OsRng;
use crate::spki::AlgorithmIdentifierOwned;
use crate::spki::EncodePublicKey;
use crate::transport::handshake::builders::{
	TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::state::{ClientStateTransition, HandshakeState, StateTransition};
use crate::transport::handshake::ClientHandshakeProtocol;
use crate::x509::Certificate;

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
	session_key: Option<Vec<u8>>,
	_phantom: PhantomData<(C, Sig, Vk, D)>,
}

impl<C, Sig, Vk, Sk, D> CmsHandshakeClient<C, Sig, Vk, Sk, D>
where
	C: elliptic_curve::Curve + CurveArithmetic,
	C::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
	elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
	elliptic_curve::PublicKey<C>: EncodePublicKey,
	Sig: signature::SignatureEncoding + Send + Sync + 'static,
	Vk: signature::Verifier<Sig> + From<elliptic_curve::PublicKey<C>> + EncodePublicKey + Send + Sync + 'static,
	Sk: signature::Signer<Sig> + signature::Keypair<VerifyingKey = Vk> + Clone + Send + Sync + 'static,
	D: crate::crypto::hash::Digest + der::oid::AssociatedOid + Send + Sync + 'static,
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

	/// Build KeyExchange message (EnvelopedData with KARI containing session key).
	///
	/// # Parameters
	/// - `session_key`: The session key to wrap and send
	///
	/// # Returns
	/// DER-encoded EnvelopedData
	pub fn build_key_exchange(&mut self, session_key: Vec<u8>) -> Result<Vec<u8>, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::Init {
			return Err(HandshakeError::InvalidState);
		}

		// Extract server public key from certificate
		let server_public_key = elliptic_curve::PublicKey::<C>::from_sec1_bytes(
			self.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		let sender_ephemeral = SecretKey::<C>::random(&mut OsRng);
		let sender_public = sender_ephemeral.public_key();
		let sender_pub_spki = sender_public.to_public_key_der().map_err(|e| HandshakeError::SpkiError(e))?;
		let sender_pub_spki = crate::spki::SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes())?;

		// Create UKM (user keying material) - using a simple nonce for now
		let ukm = UserKeyingMaterial::new(vec![0u8; 64])?;

		// Create recipient identifier
		let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
			issuer: self.server_cert.tbs_certificate.issuer.clone(),
			serial_number: self.server_cert.tbs_certificate.serial_number.clone(),
		});

		// Key encryption algorithm (ECDH + HKDF + AES wrap)
		let key_enc_alg = AlgorithmIdentifierOwned {
			oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"), // dhSinglePass-stdDH-sha256kdf-scheme
			parameters: None,
		};

		// Build KARI (Key Agreement Recipient Info) structure
		let kari_builder = TightBeamKariBuilder::<C>::new()
			.with_sender_priv(sender_ephemeral)
			.with_sender_pub_spki(sender_pub_spki)
			.with_recipient_pub(server_public_key)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		// Create EnvelopedData builder with generic curve type
		let enveloped_builder = TightBeamEnvelopedDataBuilder::new(kari_builder)
			.with_content_encryption_alg(crate::transport::handshake::utils::aes_256_gcm_algorithm());

		// Build and encode
		let enveloped_data_der = enveloped_builder.build_der(&session_key, None)?;

		// Store session key and transition state
		self.session_key = Some(session_key);
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
		// Validate state
		if self.state.state() != HandshakeState::KeyExchangeSent {
			return Err(HandshakeError::InvalidState);
		}

		// Extract server verifying key from certificate
		let server_public_key = elliptic_curve::PublicKey::<C>::from_sec1_bytes(
			self.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;
		let server_verifying_key = Vk::from(server_public_key);

		// Compute SignerIdentifier (SKI from DER-encoded public key)
		let public_key_der = server_verifying_key
			.to_public_key_der()
			.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

		let mut hasher = D::new();
		crate::crypto::hash::Digest::update(&mut hasher, public_key_der.as_bytes());
		let skid_bytes = crate::crypto::hash::Digest::finalize(hasher);
		let octet_string = der::asn1::OctetString::new(&skid_bytes.as_slice()[..20])?;
		let expected_sid = cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(
			x509_cert::ext::pkix::SubjectKeyIdentifier::from(octet_string),
		);

		// Create verifier with proper SID checking
		let verifier =
			EcdsaSignatureVerifier::<Vk, Sig, D>::from_verifying_key_with_sid(server_verifying_key, expected_sid);
		let processor = TightBeamSignedDataProcessor::new(verifier);

		// Verify signature
		let digest_oid = D::OID;
		let verified_content = processor.process_der(signed_data_der, &digest_oid)?;

		// Verify content matches our transcript hash
		if verified_content != self.transcript_hash {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		// Transition state
		self.state.transition(HandshakeState::ServerFinishedReceived)?;

		Ok(verified_content)
	}

	/// Build client Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub fn build_client_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::ServerFinishedReceived {
			return Err(HandshakeError::InvalidState);
		}

		// Algorithm identifiers
		let digest_alg = AlgorithmIdentifierOwned { oid: D::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned {
			oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), // ecdsa-with-SHA256 (TODO: make generic)
			parameters: None,
		};

		// Build SignedData
		let mut builder =
			TightBeamSignedDataBuilder::<Sig, D>::new(self.client_key.clone(), digest_alg, signature_alg)?;
		let signed_data_der = builder.build_der(&self.transcript_hash)?;

		// Transition state
		self.state.transition(HandshakeState::ClientFinishedSent)?;
		Ok(signed_data_der)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::ClientFinishedSent {
			return Err(HandshakeError::InvalidState);
		}

		// Transition to complete
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
	pub fn session_key(&self) -> Option<&[u8]> {
		self.session_key.as_deref()
	}
}

// ============================================================================
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<C, Sig, Vk, Sk, D> ClientHandshakeProtocol for CmsHandshakeClient<C, Sig, Vk, Sk, D>
where
	C: elliptic_curve::Curve + CurveArithmetic + Send + Sync,
	C::FieldBytesSize: elliptic_curve::sec1::ModulusSize,
	elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
	elliptic_curve::PublicKey<C>: EncodePublicKey,
	Sig: signature::SignatureEncoding + Send + Sync + 'static,
	Vk: signature::Verifier<Sig> + From<elliptic_curve::PublicKey<C>> + EncodePublicKey + Send + Sync + 'static,
	Sk: signature::Signer<Sig> + signature::Keypair<VerifyingKey = Vk> + Clone + Send + Sync + 'static,
	D: crate::crypto::hash::Digest + der::oid::AssociatedOid + Send + Sync + 'static,
{
	type SessionKey = Vec<u8>;
	type Error = HandshakeError;

	fn start<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a>> {
		Box::pin(async move { self.build_key_exchange(vec![0u8; 32]) })
	}

	fn handle_response<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
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

	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>> {
		Box::pin(async move {
			self.complete()?;
			Ok(self.session_key().ok_or(HandshakeError::InvalidState)?.to_vec())
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
	k256::Secp256k1,
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
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::random::OsRng;
		use crate::spki::EncodePublicKey;
		use crate::transport::handshake::processors::{
			AesGcmContentDecryptor, TightBeamEnvelopedDataProcessor, TightBeamKariRecipient,
		};
		use crate::x509::time::Validity;
		use crate::x509::{name::RdnSequence, TbsCertificate};
		use der::Decode;

		fn create_test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
			let verifying_key = *signing_key.verifying_key();
			let public_key_der = verifying_key.to_public_key_der().unwrap();

			let tbs_cert = TbsCertificate {
				version: crate::x509::Version::V3,
				serial_number: crate::x509::serial_number::SerialNumber::new(&[1]).unwrap(),
				signature: AlgorithmIdentifierOwned {
					oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
					parameters: None,
				},
				issuer: RdnSequence::default(),
				validity: Validity {
					not_before: crate::x509::time::Time::UtcTime(
						crate::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap(),
					),
					not_after: crate::x509::time::Time::UtcTime(
						crate::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(2_000_000_000))
							.unwrap(),
					),
				},
				subject: RdnSequence::default(),
				subject_public_key_info: crate::spki::SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())
					.unwrap(),
				issuer_unique_id: None,
				subject_unique_id: None,
				extensions: None,
			};

			Certificate {
				tbs_certificate: tbs_cert,
				signature_algorithm: AlgorithmIdentifierOwned {
					oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
					parameters: None,
				},
				signature: crate::der::asn1::BitString::new(0, vec![0; 64]).unwrap(),
			}
		}

		#[test]
		fn test_client_state_flow() -> Result<(), Box<dyn std::error::Error>> {
			// Setup
			let client_key = Secp256k1SigningKey::random(&mut OsRng);
			let server_key = Secp256k1SigningKey::random(&mut OsRng);
			let server_cert = create_test_certificate(&server_key);
			let transcript_hash = vec![1u8; 32];

			// Create client
			let mut client = CmsHandshakeClientSecp256k1::new(client_key.clone(), server_cert, transcript_hash.clone());
			assert_eq!(client.state(), HandshakeState::Init);

			// Build KeyExchange
			let session_key = vec![2u8; 32];
			let key_exchange = client.build_key_exchange(session_key.clone())?;
			assert_eq!(client.state(), HandshakeState::KeyExchangeSent);
			assert_eq!(client.session_key(), Some(session_key.as_slice()));

			// Server should be able to decrypt it
			let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(&key_exchange)?;
			let server_secret = SecretKey::from(server_key.clone());
			let kari_processor = TightBeamKariRecipient::new(server_secret, b"tb-kari-v1");
			let content_decryptor = AesGcmContentDecryptor;
			let processor = TightBeamEnvelopedDataProcessor::new(kari_processor, content_decryptor);
			let decrypted = processor.process(&enveloped_data)?;
			assert_eq!(decrypted, session_key);

			// Build server Finished
			let digest_alg = AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8"),
				parameters: None,
			};
			let signature_alg =
				AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), parameters: None };
			let mut server_finished_builder =
				TightBeamSignedDataBuilder::<Secp256k1Signature, Sha3_256>::new(server_key, digest_alg, signature_alg)?;
			let server_finished = server_finished_builder.build_der(&transcript_hash)?;

			// Process server Finished
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
			let client_key = Secp256k1SigningKey::random(&mut OsRng);
			let server_key = Secp256k1SigningKey::random(&mut OsRng);
			let server_cert = create_test_certificate(&server_key);
			let transcript_hash = vec![1u8; 32];
			let mut client = CmsHandshakeClientSecp256k1::new(client_key, server_cert, transcript_hash);

			// Can't process server finished before sending key exchange
			let result = client.process_server_finished(&[]);
			assert!(result.is_err());

			// Can't build client finished before processing server finished
			let result = client.build_client_finished();
			assert!(result.is_err());

			Ok(())
		}
	}
}
