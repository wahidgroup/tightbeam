#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::signed_data::SignerIdentifier;
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::sign::{verify_canonical, LowSEncoding, PrehashVerifier, SignatureEncoding, SignerInfoExt};
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::Encode;
use crate::error::{ReceivedExpectedError, Result};
use crate::frame::scaffold::TbsScaffold;
use crate::spki::AlgorithmIdentifierOwned;
use crate::version::GatedField;
use crate::x509::ext::pkix::SubjectKeyIdentifier;
use crate::{Frame, SignerInfo, TightBeamError};

impl Frame {
	/// Encode the Frame for signature verification (TBS - to-be-signed).
	///
	/// Excludes `nonrepudiation` without cloning the frame. The borrowing
	/// `TbsScaffold` reuses the derived field encoders, so these bytes
	/// are bit-identical to the DER encoding of the frame with
	/// `nonrepudiation` set to `None`.
	pub fn to_tbs(&self) -> Result<Vec<u8>> {
		let scaffold = TbsScaffold {
			version: &self.version,
			metadata: &self.metadata,
			message: &self.message,
			integrity: self.integrity.as_ref(),
		};

		Ok(scaffold.to_der()?)
	}

	/// Verify the signature of the TightBeam message.
	///
	/// This verifies the signature against the entire TightBeam structure
	/// under the canonical convention. The TBS encoding is hashed once with
	/// `D` and the signature is checked against that prehash.
	///
	/// # Arguments
	/// * `verifier` - The verifier to use for signature verification
	///
	/// # Returns
	/// Ok(()) if the signature is valid
	///
	/// # Errors
	/// Returns an error if:
	/// - The TightBeam doesn't contain a signature
	/// - The SignerInfo advertises a digest other than `D`
	/// - Signature verification fails
	///
	/// # See also
	/// - [`Frame::sign_with_provider`]: the signing counterpart under the same canonical convention
	/// - [`Frame::to_tbs`]: the exact bytes the signature covers
	pub fn verify<S, D>(&self, verifier: &impl PrehashVerifier<S>) -> Result<()>
	where
		S: SignatureEncoding + LowSEncoding,
		D: Digest + AssociatedOid,
	{
		let signature_info = self.nonrepudiation.as_ref().ok_or(TightBeamError::MissingSignature)?;

		// The canonical convention binds the signature to the digest declared
		// in the SignerInfo. A mismatch is algorithm confusion, not merely a
		// bad signature.
		if signature_info.digest_alg.oid != D::OID {
			return Err(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
				signature_info.digest_alg.oid,
				D::OID,
			))));
		}

		let signature_bytes: &[u8] = signature_info.signature.as_bytes();
		let signature = S::try_from(signature_bytes).map_err(|_| TightBeamError::SignatureEncodingError)?;
		let tbs_der = self.to_tbs()?;
		verify_canonical::<D, S>(verifier, &tbs_der, &signature)?;
		Ok(())
	}

	/// Sign the frame with the provided key provider.
	///
	/// This method encodes the frame (without the signature field) and signs
	/// it using the provided key provider. The signature is stored in the
	/// `nonrepudiation` field. It is useful if you require an async
	/// `KeyProvider` and cannot sign the frame synchronously (HSM, KMS, etc.).
	///
	/// # Parameters
	/// - `provider`: A key provider implementing the `KeyProvider` trait
	/// - `digest`: The digest algorithm to use for computing the message digest
	///
	/// On any error the frame is unchanged.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedVersion`] when the frame version predates signatures.
	/// - [`TightBeamError::InvalidAlgorithm`] when `D` is shorter than the 20-byte key identifier.
	/// - Signing errors from the provider.
	///
	/// # See also
	/// - [`Frame::verify`]: the verification counterpart under the same canonical convention
	pub async fn sign_with_provider<D, P>(&mut self, provider: &P) -> Result<()>
	where
		D: Digest + AssociatedOid,
		P: SigningKeyProvider + ?Sized,
	{
		self.ensure_allows(GatedField::Nonrepudiation)?;

		let unsigned_bytes = self.to_tbs()?;

		// The canonical convention hashes the TBS bytes once with `D`,
		// then the provider signs that prehash. The digest algorithm
		// recorded in the SignerInfo below is therefore the digest
		// actually used by the signature.
		let mut tbs_hasher = D::new();
		tbs_hasher.update(&unsigned_bytes);

		let signature_bytes = provider.sign_prehash(&tbs_hasher.finalize()).await?;
		let signature_algorithm = provider.algorithm();

		let public_key_der = provider.to_public_key_bytes().await?;
		let mut hasher = D::new();
		hasher.update(&public_key_der);

		// RFC 5280 s4.2.1.2 method (1): SKID is a 160-bit (20-byte) hash of the
		// public key. Digests shorter than the window are a caller error.
		let skid_digest = hasher.finalize();
		let skid_bytes = skid_digest.as_slice().get(..20).ok_or(TightBeamError::InvalidAlgorithm)?;
		let skid_octets = OctetString::new(skid_bytes)?;
		let skid = SubjectKeyIdentifier::from(skid_octets);
		let sid = SignerIdentifier::SubjectKeyIdentifier(skid);
		let digest_alg = AlgorithmIdentifierOwned { oid: D::OID, parameters: None };

		let signer_info = SignerInfo::from_parts(signature_bytes, signature_algorithm, digest_alg, sid)?;
		self.attach_signer_info(signer_info)
	}

	/// Attach a precomputed [`SignerInfo`] to the frame's `nonrepudiation`
	/// field.
	///
	/// Completes detached / two-phase signing: pair with `Frame::to_tbs` to
	/// sign the canonical to-be-signed bytes with any external backend, then
	/// reattach the result here.
	///
	/// On any error the frame is unchanged.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedVersion`] when the frame version predates signatures.
	pub fn attach_signer_info(&mut self, signer_info: SignerInfo) -> Result<()> {
		self.ensure_allows(GatedField::Nonrepudiation)?;
		self.nonrepudiation = Some(signer_info);

		Ok(())
	}

	/// Attach a precomputed signature from its raw parts.
	///
	/// Convenience over [`Frame::attach_signer_info`] that assembles the
	/// [`SignerInfo`] from the signature bytes and algorithm identifiers.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedVersion`] when the frame version predates signatures.
	/// - Encoding errors when the parts do not form a [`SignerInfo`].
	pub fn attach_signature(
		&mut self,
		signature: impl AsRef<[u8]>,
		signature_algorithm: AlgorithmIdentifierOwned,
		digest_alg: AlgorithmIdentifierOwned,
		sid: SignerIdentifier,
	) -> Result<()> {
		let signer_info = SignerInfo::from_parts(signature, signature_algorithm, digest_alg, sid)?;
		self.attach_signer_info(signer_info)
	}
}

crate::impl_try_from!(Frame, tb => SignerInfo: nonrepudiation, TightBeamError::MissingSignature);

#[cfg(all(test, feature = "builder"))]
mod tests {
	use crate::builder::frame::FrameBuilder;
	use crate::builder::TypeBuilder;
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::crypto::hash::Sha3_256;
	use crate::error::Result;
	use crate::testing::{TestKey, TestMessage, TestSigner};
	use crate::{Frame, TightBeamError, Version};

	fn unsigned_frame(version: Version) -> Result<Frame> {
		let message = TestMessage::sample(None);
		FrameBuilder::from(version)
			.with_id("test-sign")
			.with_order(1696521600)
			.with_message(message)
			.build()
	}

	#[test]
	fn attaching_a_signature_below_v1_is_refused() -> Result<()> {
		let mut frame = unsigned_frame(Version::V0)?;
		let original = frame.clone();
		let result = frame.attach_signer_info(TestSigner::info());
		assert!(matches!(result, Err(TightBeamError::UnsupportedVersion(_))));
		assert_eq!(frame, original);
		Ok(())
	}

	#[cfg(feature = "sha3")]
	mod tbs_encoding {
		use super::*;
		use crate::testing::TestFrame;

		/// Signature validity depends on `to_tbs` staying bit-identical to the
		/// derived DER encoding of a frame with `nonrepudiation` stripped.
		#[test]
		fn tbs_matches_derived_encoding_with_integrity() -> Result<()> {
			let frame = TestFrame::with_integrity();
			let mut unsigned = frame.clone();
			unsigned.nonrepudiation = None;

			assert_eq!(frame.to_tbs()?, crate::encode(&unsigned)?);
			Ok(())
		}

		#[test]
		fn tbs_matches_derived_encoding_without_integrity() -> Result<()> {
			let message = TestMessage::sample(None);
			let frame = compose! { V0: id: "tbs-basic", order: 1u64, message: message }?;
			let mut unsigned = frame.clone();
			unsigned.nonrepudiation = None;

			assert_eq!(frame.to_tbs()?, crate::encode(&unsigned)?);
			Ok(())
		}
	}

	#[cfg(all(feature = "secp256k1", feature = "tokio"))]
	mod sign {
		use super::*;
		use crate::crypto::key::Secp256k1KeyProvider;
		use crate::testing::fixtures::SixteenByteDigest;

		#[tokio::test]
		async fn rejects_digest_shorter_than_skid_window() -> Result<()> {
			let mut frame = unsigned_frame(Version::V1)?;
			let signing_key = TestKey::signing();
			let provider = Secp256k1KeyProvider::from(signing_key);

			let result = frame.sign_with_provider::<SixteenByteDigest, _>(&provider).await;
			assert!(matches!(result, Err(TightBeamError::InvalidAlgorithm)));
			Ok(())
		}

		#[tokio::test]
		async fn test_frame_sign_with_key_provider() -> Result<()> {
			let mut frame = unsigned_frame(Version::V1)?;
			assert!(frame.nonrepudiation.is_none());

			let signing_key = TestKey::signing();
			let provider = Secp256k1KeyProvider::from(signing_key);

			frame.sign_with_provider::<Sha3_256, _>(&provider).await?;
			let Some(signer_info) = frame.nonrepudiation.as_ref() else {
				return Err(TightBeamError::MissingSignatureInfo);
			};
			assert_eq!(signer_info.version, CmsVersion::V1);
			assert!(matches!(signer_info.sid, SignerIdentifier::SubjectKeyIdentifier(_)));

			Ok(())
		}
	}

	#[cfg(feature = "secp256k1")]
	mod detached_sign {
		use super::*;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::crypto::sign::{
			secp256k1_signer_identifier, sign_canonical, SignatureAlgorithmIdentifier, SignerInfoExt,
		};
		use crate::der::oid::AssociatedOid;
		use crate::spki::AlgorithmIdentifierOwned;
		use crate::SignerInfo;

		#[test]
		fn test_attach_signature_roundtrip() -> Result<()> {
			let mut frame = unsigned_frame(Version::V1)?;
			let signing_key = TestKey::signing();

			// External backends must follow the canonical convention.
			// SHA3-256 runs over the TBS bytes, and ECDSA signs that
			// prehash.
			let tbs = frame.to_tbs()?;
			let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(&signing_key, &tbs)?;

			let sig_alg = AlgorithmIdentifierOwned { oid: Secp256k1Signature::ALGORITHM_OID, parameters: None };
			let digest_alg = AlgorithmIdentifierOwned { oid: Sha3_256::OID, parameters: None };
			let sid = secp256k1_signer_identifier(signing_key.verifying_key())?;

			frame.attach_signature(signature.to_bytes(), sig_alg, digest_alg, sid)?;
			assert!(frame.nonrepudiation.is_some());

			frame.verify::<Secp256k1Signature, Sha3_256>(signing_key.verifying_key())?;
			Ok(())
		}

		#[test]
		fn test_attach_signer_info_from_parts() -> Result<()> {
			let mut frame = unsigned_frame(Version::V1)?;
			let signing_key = TestKey::signing();

			let tbs = frame.to_tbs()?;
			let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(&signing_key, &tbs)?;

			let sig_alg = AlgorithmIdentifierOwned { oid: Secp256k1Signature::ALGORITHM_OID, parameters: None };
			let digest_alg = AlgorithmIdentifierOwned { oid: Sha3_256::OID, parameters: None };
			let sid = secp256k1_signer_identifier(signing_key.verifying_key())?;

			let signer_info = SignerInfo::from_parts(signature.to_bytes(), sig_alg, digest_alg, sid)?;
			assert_eq!(signer_info.version, CmsVersion::V1);
			assert!(matches!(signer_info.sid, SignerIdentifier::SubjectKeyIdentifier(_)));

			frame.attach_signer_info(signer_info)?;
			frame.verify::<Secp256k1Signature, Sha3_256>(signing_key.verifying_key())?;
			Ok(())
		}
	}
}
