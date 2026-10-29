use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::crypto::hash::Sha3_256;
use crate::error::Result;
use crate::testing::{TestKey, TestMessage, TestSigner};
use crate::version::GatedField;
use crate::{Frame, TightBeamError, Version};

#[cfg(feature = "secp256k1")]
use crate::crypto::profiles::DefaultCryptoProvider;
#[cfg(feature = "secp256k1")]
use crate::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
#[cfg(feature = "secp256k1")]
use crate::testing::TestCertificate;

fn unsigned_frame(version: Version) -> Result<Frame> {
	let message = TestMessage::sample(None);
	FrameBuilder::from(version)
		.with_id("test-sign")
		.with_order(1696521600)
		.with_message(message)
		.build()
}

/// The certificate of the fixed test key, admitted for signing under the
/// house provider.
#[cfg(feature = "secp256k1")]
fn fixed_signer() -> PeerCertificate<Signing<DefaultCryptoProvider>> {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let signer = PeerCertificate::parse(certificate, KeyPurposes::HOUSE.signer);
	signer.expect("the fixed test certificate is admitted for signing")
}

#[test]
fn attaching_a_signature_below_v1_is_refused() -> Result<()> {
	let mut frame = unsigned_frame(Version::V0)?;
	let original = frame.clone();

	let result = frame.attach_signer_info(TestSigner::info());
	assert!(matches!(
		result,
		Err(TightBeamError::UnsupportedField { field: GatedField::Nonrepudiation, version: Version::V0 })
	));
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
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::crypto::hash::Digest;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::{Signed, SignerError};
	use crate::crypto::x509::{ErasedSigning, PeerCertificate};
	use crate::der::asn1::{ObjectIdentifier, OctetString};
	use crate::der::oid::AssociatedOid;
	use crate::der::{Decode, Encode};
	use crate::error::ReceivedExpectedError;
	use crate::oids::{ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, DATA};
	use crate::oids::{HASH_SHA3_256, HASH_SHA3_512};
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::{TestAttributes, TestCertificate, TestIdentity};
	use crate::x509::ext::pkix::SubjectKeyIdentifier;
	use crate::SignerInfo;

	/// A frame signature names the identity's certificate (RFC 5652 §5.3).
	#[tokio::test]
	async fn a_frame_signature_names_the_identity_certificate() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		let identity = TestIdentity::insecure_fixed();

		frame.sign_with_provider(&identity).await?;

		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		assert_eq!(&signer_info.sid, identity.signer_identifier());
		Ok(())
	}

	/// A frame signature whose digest is not the one its signature algorithm
	/// names is refused (RFC 5753 §2.1.1).
	#[tokio::test]
	async fn a_frame_signature_whose_digest_its_algorithm_does_not_name_is_refused() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_512, parameters: None };
		let mismatched = SignerInfo { digest_alg, ..signer_info.as_ref().clone() };
		let received = Signed::<SignerInfo>::from_der(&mismatched.to_der()?)?;

		frame.attach_signer_info(received)?;

		let refused = frame.verify(&fixed_signer());
		let algorithms = ReceivedExpectedError::from((HASH_SHA3_512, HASH_SHA3_256));
		assert!(matches!(refused, Err(TightBeamError::UnexpectedAlgorithm(received)) if received == algorithms));
		Ok(())
	}

	/// A frame signature names its signer by the certificate's key
	/// identifier, so its `SignerInfo` is version 3 (RFC 5652 §5.3).
	#[tokio::test]
	async fn a_frame_signature_is_version_3_under_a_key_identifier() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		assert_eq!(signer_info.version, CmsVersion::V3);
		assert!(matches!(signer_info.sid, SignerIdentifier::SubjectKeyIdentifier(_)));
		Ok(())
	}

	/// A frame signature's message digest is the digest of the frame's TBS
	/// encoding, the `id-data` content it signs.
	#[tokio::test]
	async fn a_frame_signature_digests_the_tbs_encoding() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		let tbs_digest = Sha3_256::digest(frame.to_tbs()?);
		let expected = OctetString::new(tbs_digest.as_slice())?;
		let value = TestAttributes::value(signer_info, ATTR_MESSAGE_DIGEST);

		let digest = value.decode_as::<OctetString>()?;
		assert_eq!(digest, expected);
		Ok(())
	}

	/// A frame signature protects its digest and signature algorithms with
	/// the RFC 6211 attribute.
	#[tokio::test]
	async fn a_frame_signature_protects_its_algorithms() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		let value = TestAttributes::value(signer_info, ATTR_CMS_ALGORITHM_PROTECTION);
		assert_eq!(value.to_der()?, TestAttributes::ALGORITHM_PROTECTION);
		Ok(())
	}

	/// A signed frame verifies under its signer's key, and the verified
	/// signature is the low-s DER the signer wrote.
	#[tokio::test]
	async fn a_signed_frame_verifies_under_its_signer_key() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let verified = frame.verify(&fixed_signer())?;
		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		assert_eq!(verified.as_bytes(), signer_info.signature.as_bytes());
		Ok(())
	}

	/// A trust store verifies a frame under the certificate its `sid` names,
	/// with the algorithms of its policy.
	#[tokio::test]
	async fn a_signed_frame_verifies_under_its_certificate_and_policy() -> Result<()> {
		let identity = TestIdentity::insecure_fixed();
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&identity).await?;
		frame.verify_under(identity.signing_certificate(), &Secp256k1Policy::default())?;
		Ok(())
	}

	/// A frame checked against another certificate of the same key is
	/// refused by its `sid` (RFC 5652 §5.3).
	#[tokio::test]
	async fn a_frame_checked_against_another_certificate_is_refused() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		frame.sign_with_provider(&TestIdentity::insecure_fixed()).await?;

		let other = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let other = TestCertificate::without_extension(other, SubjectKeyIdentifier::OID);
		let other = PeerCertificate::<ErasedSigning>::parse(other, KeyPurposes::HOUSE.signer)?;

		let refused = frame.verify_under(&other, &Secp256k1Policy::default());
		assert!(matches!(refused, Err(TightBeamError::Signer(SignerError::SignerIdentifier))));
		Ok(())
	}

	/// The builder signs the frame's TBS encoding as `id-data` content.
	#[test]
	fn a_builder_signed_frame_signs_id_data() -> Result<()> {
		let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let frame = FrameBuilder::from(Version::V1)
			.with_id("test-sign")
			.with_order(1696521600)
			.with_message(TestMessage::sample(None))
			.with_signer::<Secp256k1Signature, _>(key)
			.build()?;

		let signer_info = frame.nonrepudiation().ok_or(TightBeamError::MissingSignatureInfo)?;
		let value = TestAttributes::value(signer_info, ATTR_CONTENT_TYPE);

		let oid = value.decode_as::<ObjectIdentifier>()?;
		assert_eq!(oid, DATA);
		Ok(())
	}
}

#[cfg(feature = "secp256k1")]
mod detached_sign {
	use super::*;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::CanonicalSigner;
	use crate::testing::TestCertificate;

	/// An external backend signs the draft's prehash, and the completed
	/// `SignerInfo` attaches and verifies.
	#[test]
	fn a_detached_signature_attaches_and_verifies() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		let signing_key = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&signing_key);
		let draft = frame.signing_draft::<Secp256k1Signature>(&certificate)?;

		let signature: Secp256k1Signature =
			crate::crypto::sign::PrehashSigner::sign_prehash(&signing_key, draft.prehash())?;

		frame.attach_signer_info(draft.complete(signature.to_bytes(), None)?)?;
		frame.verify(&fixed_signer())?;
		Ok(())
	}

	/// A signature over the TBS bytes, with no signed attributes in its
	/// prehash, is not a CMS frame signature, so it fails to verify.
	#[test]
	fn a_signature_over_the_bare_tbs_is_refused() -> Result<()> {
		let mut frame = unsigned_frame(Version::V1)?;
		let signing_key = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&signing_key);
		let draft = frame.signing_draft::<Secp256k1Signature>(&certificate)?;
		let tbs = frame.to_tbs()?;

		let bare: Secp256k1Signature = signing_key.sign_canonical::<Sha3_256>(&tbs)?;
		frame.attach_signer_info(draft.complete(bare.to_bytes(), None)?)?;

		let refused = frame.verify(&fixed_signer());
		assert!(matches!(refused, Err(TightBeamError::SignatureError(_))));
		Ok(())
	}
}
