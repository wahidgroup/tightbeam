//! SignedData builder for the TightBeam CMS handshake.
//!
//! The builder creates the CMS `SignedData` structures that authenticate
//! handshake messages, such as the Finished message that signs the transcript
//! hash.

use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::crypto::hash::Digest;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::{sign_canonical, Keypair, PrehashSigner, SignatureEncoding};
use crate::crypto::x509::utils::Skid;
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
use crate::transport::handshake::error::HandshakeError;

/// Builder for CMS `SignedData` structures in the TightBeam handshake.
///
/// The builder signs content, typically a transcript hash, with the sender's
/// private key, which gives authentication and non-repudiation.
///
/// - `P` is the [`CryptoProvider`] that names the signature and digest algorithms.
/// - `K` is the concrete signing key type.
pub struct TightBeamSignedDataBuilder<'a, P, K>
where
	P: CryptoProvider,
{
	/// The signing key, borrowed as its concrete type.
	signer: &'a K,
	/// The digest algorithm the SignerInfo names for the content hash.
	digest_alg: AlgorithmIdentifierOwned,
	/// The signature algorithm the SignerInfo names.
	signature_alg: AlgorithmIdentifierOwned,
	/// The signer identifier, which is the subject key identifier (SKID) of
	/// the signer's public key.
	signer_id: SignerIdentifier,
	/// The content type OID, which defaults to `id-data`.
	content_type: ObjectIdentifier,
	_phantom: core::marker::PhantomData<P>,
}

impl<'a, P, K> TightBeamSignedDataBuilder<'a, P, K>
where
	P: CryptoProvider,
	P::Signature: SignatureEncoding,
	P::Digest: Digest + AssociatedOid,
	K: PrehashSigner<P::Signature> + Keypair,
	K::VerifyingKey: EncodePublicKey,
{
	/// Create a builder that signs with `signer` and names `digest_alg` and
	/// `signature_alg` in its SignerInfo.
	///
	/// The signer identifier is the subject key identifier (SKID) of the
	/// signer's public key.
	pub fn new(
		signer: &'a K,
		digest_alg: AlgorithmIdentifierOwned,
		signature_alg: AlgorithmIdentifierOwned,
	) -> Result<Self, HandshakeError> {
		let verifying_key = signer.verifying_key();
		let signer_id = SignerIdentifier::try_from(Skid::of_public_key(verifying_key.to_public_key_der()?))?;

		Ok(Self {
			signer,
			digest_alg,
			signature_alg,
			signer_id,
			content_type: crate::oids::DATA,
			_phantom: core::marker::PhantomData,
		})
	}

	/// Set the content type OID, which defaults to `id-data`
	/// (1.2.840.113549.1.7.1).
	pub fn with_content_type(mut self, content_type: ObjectIdentifier) -> Self {
		self.content_type = content_type;
		self
	}

	/// Build a complete CMS `SignedData` that signs `content`, typically a
	/// transcript hash.
	pub fn build(self, content: impl AsRef<[u8]>) -> Result<SignedData, HandshakeError> {
		let content = content.as_ref();
		// 1. Sign under the canonical convention: the provider digest once,
		//    and ECDSA over the prehash, matching the advertised
		//    signature-algorithm OID.
		let signature = sign_canonical::<P::Digest, P::Signature>(self.signer, content)?;
		let signature_bytes = signature.to_bytes();

		// 2. Create the SignerInfo. The digest algorithm is cloned, because the SignedData names it as well.
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: self.signer_id,
			digest_alg: self.digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: self.signature_alg,
			signature: OctetString::new(signature_bytes.as_ref())?,
			unsigned_attrs: None,
		};

		// 3. Create the EncapsulatedContentInfo over the content as an OCTET STRING.
		let octet_string = OctetString::new(content)?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = der::Any::from_der(&econtent_der)?;
		let econtent = Some(econtent_any);

		let encap_content = EncapsulatedContentInfo { econtent_type: self.content_type, econtent };

		// 4. Build the SignedData, which takes the digest algorithm by move.
		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![self.digest_alg].try_into()?,
			encap_content_info: encap_content,
			certificates: None,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::der::Decode;
	use crate::oids::{DATA, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::random::OsRng;

	/// A fresh secp256k1 signing key for one test.
	fn create_test_signing_key() -> Secp256k1SigningKey {
		Secp256k1SigningKey::random(&mut OsRng)
	}

	/// The SHA3-256 digest algorithm identifier.
	fn create_sha3_256_digest_alg() -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None }
	}

	/// The ECDSA with SHA3-256 signature algorithm identifier.
	fn create_ecdsa_sha256_signature_alg() -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
	}

	/// A `SignedData` builder over `signing_key`, under SHA3-256 and ECDSA with
	/// SHA3-256.
	fn create_test_signed_data_builder<'a>(
		signing_key: &'a Secp256k1SigningKey,
	) -> Result<TightBeamSignedDataBuilder<'a, DefaultCryptoProvider, Secp256k1SigningKey>, HandshakeError> {
		let digest_alg = create_sha3_256_digest_alg();
		let signature_alg = create_ecdsa_sha256_signature_alg();

		TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(signing_key, digest_alg, signature_alg)
	}

	#[test]
	fn test_build_signed_data() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create the test signing key.
		let signing_key = create_test_signing_key();

		// 2. Create the test builder.
		let builder = create_test_signed_data_builder(&signing_key)?;

		// 3. Choose the content to sign, such as a transcript hash.
		let transcript_hash = b"handshake_transcript_hash_placeholder_32bytes";

		// 4. Build the SignedData.
		let signed_data = builder.build(transcript_hash)?;
		assert_eq!(signed_data.version, CmsVersion::V1);
		assert_eq!(signed_data.digest_algorithms.len(), 1);
		assert_eq!(signed_data.signer_infos.0.len(), 1);
		assert_eq!(signed_data.encap_content_info.econtent_type, DATA);
		assert!(signed_data.encap_content_info.econtent.is_some());

		// 5. Verify the signer info.
		let signer_info = &signed_data.signer_infos.0.as_ref()[0];
		assert_eq!(signer_info.version, CmsVersion::V1);

		// 6. Verify that the signer identifier is a SubjectKeyIdentifier.
		match signer_info.sid {
			SignerIdentifier::SubjectKeyIdentifier(_) => {}
			_ => unreachable!("SignedData builder should always create SubjectKeyIdentifier"),
		}

		assert!(!signer_info.signature.as_bytes().is_empty());

		Ok(())
	}

	#[test]
	fn test_der_encoding() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create the test signing key.
		let signing_key = create_test_signing_key();

		// 2. Create the test builder.
		let builder = create_test_signed_data_builder(&signing_key)?;

		// 3. Choose the content to sign.
		let content = b"test_content";

		// 4. Build the SignedData and encode it to DER.
		let built = builder.build(content)?;
		let der_bytes = built.to_der()?;
		assert!(!der_bytes.is_empty());

		// 5. Decode it back from DER.
		let decoded = SignedData::from_der(&der_bytes)?;
		assert_eq!(decoded.version, CmsVersion::V1);
		assert_eq!(decoded.signer_infos.0.len(), 1);

		Ok(())
	}

	#[test]
	fn test_custom_content_type() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create the test signing key.
		let signing_key = create_test_signing_key();

		// 2. Create the test builder.
		let builder = create_test_signed_data_builder(&signing_key)?;

		// 3. Choose the content to sign.
		let content = b"custom_content";

		// 4. Choose a custom content type OID.
		let custom_oid = ObjectIdentifier::new_unwrap("1.2.3.4.5.6");

		// 5. Configure the builder with the custom content type.
		let builder = builder.with_content_type(custom_oid);

		// 6. Build the SignedData.
		let signed_data = builder.build(content)?;
		assert_eq!(signed_data.encap_content_info.econtent_type, custom_oid);

		Ok(())
	}
}
