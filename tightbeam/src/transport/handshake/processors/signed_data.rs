//! SignedData processor for TightBeam CMS handshake.
//!
//! Verifies CMS SignedData structures, particularly signatures on handshake
//! messages like the Finished message.

use crate::cms::signed_data::SignedData;
use crate::crypto::sign::SignatureVerifier;
use crate::der::asn1::ObjectIdentifier;
use crate::der::{Decode, Encode};
use crate::transport::handshake::error::HandshakeError;

/// Processor for CMS `SignedData` structures in TightBeam handshake.
///
/// Verifies signatures on content using the provided verifier implementation.
///
/// The processor is algorithm-agnostic and works with any verifier that
/// implements the `SignatureVerifier` trait.
#[cfg(feature = "signature")]
pub struct TightBeamSignedDataProcessor {
	verifier: Box<dyn SignatureVerifier>,
}

#[cfg(feature = "signature")]
impl TightBeamSignedDataProcessor {
	/// Create a new SignedData processor.
	///
	/// # Parameters
	/// - `verifier`: The signature verifier implementation
	pub fn new<V>(verifier: V) -> Self
	where
		V: SignatureVerifier + 'static,
	{
		Self { verifier: Box::new(verifier) }
	}

	/// Process a SignedData structure and verify the signature.
	///
	/// # Parameters
	/// - `signed_data`: The CMS SignedData to verify
	/// - `digest_oid`: Expected digest algorithm OID
	///
	/// # Returns
	/// The verified content on success
	pub fn process(&self, signed_data: &SignedData, digest_oid: &ObjectIdentifier) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate we have exactly one signer
		if signed_data.signer_infos.0.len() != 1 {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		let signer_info = &signed_data.signer_infos.0.as_ref()[0];

		// 2. Validate digest algorithm matches
		if signer_info.digest_alg.oid != *digest_oid {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		// 3. Extract and hash the content
		let content = signed_data
			.encap_content_info
			.econtent
			.as_ref()
			.ok_or(HandshakeError::SignatureVerificationFailed)?;

		// Decode the OCTET STRING from the Any wrapper
		let content_der = content.to_der()?;
		let content_bytes = der::asn1::OctetString::from_der(&content_der)?;

		// 4. Verify the signature
		let signature_bytes = signer_info.signature.as_bytes();
		self.verifier
			.verify_signature(content_bytes.as_bytes(), signature_bytes, &signer_info.sid)?;

		// 5. Return verified content
		Ok(content_bytes.as_bytes().to_vec())
	}

	/// Process DER-encoded SignedData.
	pub fn process_der(
		&self,
		signed_data_der: &[u8],
		digest_oid: &ObjectIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		let signed_data = SignedData::from_der(signed_data_der)?;
		self.process(&signed_data, digest_oid)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(all(feature = "signature", feature = "secp256k1", feature = "sha3"))]
	mod signed_data {
		use super::*;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
		use crate::crypto::sign::EcdsaSignatureVerifier;
		use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
		use crate::transport::handshake::tests::{
			create_ecdsa_sha3_256_signature_alg, create_sha3_256_digest_alg, create_test_signing_key,
		};

		/// Helper function to create a test SignedData builder
		fn create_test_signed_data_builder(
			signing_key: Secp256k1SigningKey,
		) -> Result<TightBeamSignedDataBuilder<DefaultCryptoProvider>, HandshakeError> {
			let digest_alg = create_sha3_256_digest_alg();
			let signature_alg = create_ecdsa_sha3_256_signature_alg();

			TightBeamSignedDataBuilder::<DefaultCryptoProvider>::new(signing_key, digest_alg, signature_alg)
		}

		/// Helper function to create a test signature verifier
		fn create_test_verifier(
			signing_key: &Secp256k1SigningKey,
		) -> Result<
			EcdsaSignatureVerifier<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>,
			crate::error::TightBeamError,
		> {
			EcdsaSignatureVerifier::<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>::from_signing_key(signing_key)
		}

		/// Helper function to create a test processor
		fn create_test_processor(
			signing_key: &Secp256k1SigningKey,
		) -> Result<TightBeamSignedDataProcessor, crate::error::TightBeamError> {
			let verifier = create_test_verifier(signing_key)?;
			Ok(TightBeamSignedDataProcessor::new(verifier))
		}

		#[test]
		fn test_verify_signed_data() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test signing key
			let signing_key = create_test_signing_key();

			// 2. Content to sign
			let content = b"test_content_to_verify";

			// 3. Create SignedData builder and build structure
			let mut builder = create_test_signed_data_builder(signing_key.clone())?;
			let signed_data = builder.build(content)?;

			// 4. Create processor and verify signature
			let processor = create_test_processor(&signing_key)?;
			let verified_content = processor.process(&signed_data, &crate::asn1::HASH_SHA3_256_OID)?;

			// 5. Verify content matches original
			assert_eq!(verified_content, content);

			Ok(())
		}

		#[test]
		fn test_verify_der_encoded() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test signing key
			let signing_key = create_test_signing_key();

			// 2. Content to sign
			let content = b"der_encoded_test";

			// 3. Create SignedData builder and build DER-encoded structure
			let mut builder = create_test_signed_data_builder(signing_key.clone())?;
			let der_bytes = builder.build_der(content)?;

			// 4. Create processor and verify from DER
			let processor = create_test_processor(&signing_key)?;
			let verified_content = processor.process_der(&der_bytes, &crate::asn1::HASH_SHA3_256_OID)?;

			// 5. Verify content matches original
			assert_eq!(verified_content, content);

			Ok(())
		}

		#[test]
		fn test_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create two different signing keys
			let signing_key = create_test_signing_key();
			let wrong_key = create_test_signing_key();

			// 2. Content to sign
			let content = b"test_content";

			// 3. Create SignedData with one key
			let mut builder = create_test_signed_data_builder(signing_key)?;
			let signed_data = builder.build(content)?;

			// 4. Try to verify with wrong key (should fail)
			let processor = create_test_processor(&wrong_key)?;
			let result = processor.process(&signed_data, &crate::asn1::HASH_SHA3_256_OID);

			// 5. Verify that verification fails
			assert!(result.is_err());

			Ok(())
		}

		#[test]
		fn test_wrong_digest_algorithm_fails() -> Result<(), Box<dyn std::error::Error>> {
			// 1. Create test signing key
			let signing_key = create_test_signing_key();

			// 2. Content to sign
			let content = b"test_content";

			// 3. Create SignedData with SHA3-256
			let mut builder = create_test_signed_data_builder(signing_key.clone())?;
			let signed_data = builder.build(content)?;

			// 4. Try to verify with wrong digest OID (SHA-256 instead of SHA3-256)
			let wrong_digest_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"); // SHA-256
			let processor = create_test_processor(&signing_key)?;
			let result = processor.process(&signed_data, &wrong_digest_oid);

			// 5. Verify that verification fails
			assert!(result.is_err());

			Ok(())
		}
	}
}
