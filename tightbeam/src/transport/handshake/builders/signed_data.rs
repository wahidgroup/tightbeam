//! SignedData builder for TightBeam CMS handshake.
//!
//! Creates CMS SignedData structures for authenticating handshake messages,
//! particularly the Finished message that signs the transcript hash.

use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Digest;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::Signer;
use crate::crypto::sign::{Keypair, SignatureEncoding};
use crate::crypto::x509::utils::compute_signer_identifier;
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
use crate::transport::handshake::error::HandshakeError;

/// Builder for CMS `SignedData` structures in TightBeam handshake.
///
/// Signs content (typically a transcript hash) with the sender's private key
/// to provide authentication and non-repudiation.
///
/// The builder is generic over `P: CryptoProvider` which defines the complete
/// cryptographic suite (signature algorithm and digest algorithm).
pub struct TightBeamSignedDataBuilder<P>
where
	P: CryptoProvider,
{
	/// Signer implementing signature creation
	signer: Box<dyn Signer<P::Signature>>,
	/// Digest algorithm for hashing content
	digest_alg: AlgorithmIdentifierOwned,
	/// Signature algorithm identifier
	signature_alg: AlgorithmIdentifierOwned,
	/// Signer identifier (SKID)
	signer_id: SignerIdentifier,
	/// Content type OID (default: id-data)
	content_type: ObjectIdentifier,
	_phantom: core::marker::PhantomData<P>,
}

impl<P> TightBeamSignedDataBuilder<P>
where
	P: CryptoProvider,
	P::Signature: SignatureEncoding,
	P::Digest: Digest + AssociatedOid,
{
	/// Create a new SignedData builder.
	///
	/// # Parameters
	/// - `signer`: The signing key (must implement `Signer<P::Signature>` and `Keypair`)
	/// - `digest_alg`: Algorithm identifier for the digest algorithm
	/// - `signature_alg`: Algorithm identifier for the signature algorithm
	///
	/// # Returns
	/// A new builder instance
	pub fn new<K>(
		signer: K,
		digest_alg: AlgorithmIdentifierOwned,
		signature_alg: AlgorithmIdentifierOwned,
	) -> Result<Self, HandshakeError>
	where
		K: Signer<P::Signature> + Keypair + 'static,
		K::VerifyingKey: EncodePublicKey,
	{
		// Generate SKID from public key
		let verifying_key = signer.verifying_key();
		let signer_id = compute_signer_identifier::<P::Digest, _>(&verifying_key)?;

		Ok(Self {
			signer: Box::new(signer),
			digest_alg,
			signature_alg,
			signer_id,
			content_type: crate::asn1::DATA_OID,
			_phantom: core::marker::PhantomData,
		})
	}

	/// Set the content type OID.
	///
	/// Default is `id-data` (1.2.840.113549.1.7.1).
	pub fn with_content_type(mut self, content_type: ObjectIdentifier) -> Self {
		self.content_type = content_type;
		self
	}

	/// Build a SignedData structure by signing the provided content.
	///
	/// # Parameters
	/// - `content`: The data to sign (typically a transcript hash)
	///
	/// # Returns
	/// A complete CMS SignedData structure with signature
	pub fn build(&mut self, content: &[u8]) -> Result<SignedData, HandshakeError> {
		// 1. Hash the content
		let mut hasher = P::Digest::new();
		hasher.update(content);

		let digest = hasher.finalize();
		let digest_bytes = digest.as_slice();

		// 2. Sign the digest
		let signature = self.signer.try_sign(digest_bytes)?;
		let signature_bytes = signature.to_bytes();

		// 3. Create SignerInfo
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: self.signer_id.clone(),
			digest_alg: self.digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: self.signature_alg.clone(),
			signature: OctetString::new(signature_bytes.as_ref())?,
			unsigned_attrs: None,
		};

		// 4. Create EncapsulatedContentInfo
		let octet_string = OctetString::new(content)?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = der::Any::from_der(&econtent_der)?;

		let encap_content = EncapsulatedContentInfo { econtent_type: self.content_type, econtent: Some(econtent_any) };

		// 5. Build SignedData
		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![self.digest_alg.clone()].try_into()?,
			encap_content_info: encap_content,
			certificates: None,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		})
	}

	/// Build and encode SignedData as DER bytes.
	pub fn build_der(&mut self, content: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let signed_data = self.build(content)?;
		Ok(signed_data.to_der()?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::der::Decode;
	use crate::random::OsRng;

	/// Helper function to create a test signing key
	fn create_test_signing_key() -> Secp256k1SigningKey {
		Secp256k1SigningKey::random(&mut OsRng)
	}

	/// Helper function to create SHA3-256 digest algorithm identifier
	fn create_sha3_256_digest_alg() -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: crate::asn1::HASH_SHA3_256_OID, parameters: None }
	}

	/// Helper function to create ECDSA with SHA256 signature algorithm identifier
	fn create_ecdsa_sha256_signature_alg() -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: crate::asn1::SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None }
	}

	/// Helper function to create a test SignedData builder
	fn create_test_signed_data_builder() -> Result<TightBeamSignedDataBuilder<DefaultCryptoProvider>, HandshakeError> {
		let signing_key = create_test_signing_key();
		let digest_alg = create_sha3_256_digest_alg();
		let signature_alg = create_ecdsa_sha256_signature_alg();

		TightBeamSignedDataBuilder::<DefaultCryptoProvider>::new(signing_key, digest_alg, signature_alg)
	}

	#[test]
	fn test_build_signed_data() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create test builder
		let mut builder = create_test_signed_data_builder()?;

		// 2. Content to sign (e.g., transcript hash)
		let transcript_hash = b"handshake_transcript_hash_placeholder_32bytes";

		// 3. Build SignedData
		let signed_data = builder.build(transcript_hash)?;
		assert_eq!(signed_data.version, CmsVersion::V1);
		assert_eq!(signed_data.digest_algorithms.len(), 1);
		assert_eq!(signed_data.signer_infos.0.len(), 1);
		assert_eq!(signed_data.encap_content_info.econtent_type, crate::asn1::DATA_OID);
		assert!(signed_data.encap_content_info.econtent.is_some());

		// 4. Verify signer info
		let signer_info = &signed_data.signer_infos.0.as_ref()[0];
		assert_eq!(signer_info.version, CmsVersion::V1);

		// 5. Verify signer identifier is SubjectKeyIdentifier
		match signer_info.sid {
			SignerIdentifier::SubjectKeyIdentifier(_) => {}
			_ => unreachable!("SignedData builder should always create SubjectKeyIdentifier"),
		}

		assert!(signer_info.signature.as_bytes().len() > 0);

		Ok(())
	}

	#[test]
	fn test_der_encoding() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create test builder
		let mut builder = create_test_signed_data_builder()?;

		// 2. Content to sign
		let content = b"test_content";

		// 3. Build and encode to DER
		let der_bytes = builder.build_der(content)?;
		assert!(!der_bytes.is_empty());

		// 4. Decode back from DER
		let decoded = SignedData::from_der(&der_bytes)?;
		assert_eq!(decoded.version, CmsVersion::V1);
		assert_eq!(decoded.signer_infos.0.len(), 1);

		Ok(())
	}

	#[test]
	fn test_custom_content_type() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create test builder
		let mut builder = create_test_signed_data_builder()?;

		// 2. Content to sign
		let content = b"custom_content";

		// 3. Custom content type OID
		let custom_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5.6");

		// 4. Configure builder with custom content type
		builder = builder.with_content_type(custom_oid);

		// 5. Build SignedData
		let signed_data = builder.build(content)?;
		assert_eq!(signed_data.encap_content_info.econtent_type, custom_oid);

		Ok(())
	}
}
