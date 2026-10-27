//! The CMS signer (RFC 5652 §5).
//!
//! [`CmsSigner`] builds every `SignerInfo` the crate emits, and every
//! `SignedData` that carries one, and verifies every one it reads. Each
//! `SignerInfo` carries signed attributes, so its signature covers the DER of
//! that set (RFC 5652 §5.4):
//!
//! - The content type (RFC 5652 §11.1).
//! - The message digest of the content (RFC 5652 §11.2).
//! - The algorithm protection of RFC 6211, which binds the digest and signature algorithms.
//! - The attributes of the caller's profile, such as the role of a receipt signer.
//!
//! ## Identifier and version
//!
//! The `sid` is the `subjectKeyIdentifier` of the signer's certificate at
//! version 3, or its issuer and serial number at version 1 (RFC 5652 §5.3).
//! A `SignedData` takes the version that RFC 5652 §5.1 gives it.
//!
//! ## Algorithms
//!
//! The signature type names its digest, so a `SignerInfo` carries the digest
//! its signature algorithm names (RFC 5753 §2.1.1). The signer brings every
//! signature value to its canonical form before it attaches it.

use core::borrow::Borrow;

#[cfg(all(not(feature = "std"), any(feature = "transport-cms", feature = "transport-hpke")))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(all(feature = "std", any(feature = "transport-cms", feature = "transport-hpke")))]
use std::sync::Arc;

use crate::cms::cert::CertificateChoices;
use crate::cms::content_info::CmsVersion;
use crate::cms::revocation::{RevocationInfoChoice, RevocationInfoChoices};
use crate::cms::signed_data::{
	CertificateSet, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
	UnsignedAttributes,
};
use crate::crypto::hash::Digest;
use crate::crypto::policy::{CanonicalForm, ProviderPolicy, VerificationPolicy, VerifiedSignature};
use crate::crypto::profiles::SigningProvider;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::PresentedPath;
use crate::crypto::sign::{
	CertifiedKey, PrehashSigner, PrehashVerifier, SignatureAlgorithmIdentifier, SignatureEncoding, SignerError,
};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::{ErasedSigning, PeerCertificate, Signing};
use crate::der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Encode, Sequence, Tag, Tagged};
use crate::error::ReceivedExpectedError;
use crate::frame::{ArrivedCertificates, Signed};
use crate::oids::{ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, DATA};
use crate::spki::{AlgorithmIdentifierOwned, DecodePublicKey, SubjectPublicKeyInfoRef};
use crate::x509::attr::Attribute;
use crate::x509::Certificate;

/// The proof that the signer built a [`Signed`] value.
///
/// Its field is private to this module, so the signer alone holds one.
pub(crate) struct SignerSeal(());

/// `CMSAlgorithmProtection` (RFC 6211 §2). The signer leaves its MAC arm
/// absent.
///
/// ```asn1
/// CMSAlgorithmProtection ::= SEQUENCE {
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
///     macAlgorithm        [2] MessageAuthenticationCodeAlgorithm OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct CmsAlgorithmProtection {
	pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
	#[asn1(
		context_specific = "1",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	pub(crate) signature_algorithm: Option<AlgorithmIdentifierOwned>,
	#[asn1(
		context_specific = "2",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	pub(crate) mac_algorithm: Option<AlgorithmIdentifierOwned>,
}

/// The content one `SignerInfo` signs: its type, its octets, and the signed
/// attributes the caller's profile adds.
#[derive(Clone, Debug)]
pub struct SignedContent<'a> {
	content_type: ObjectIdentifier,
	content: &'a [u8],
	attributes: Vec<Attribute>,
}

impl<'a> SignedContent<'a> {
	/// Content of `content_type`, to which a profile adds its attributes.
	pub fn new(content_type: ObjectIdentifier, content: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		Self { content_type, content: content.as_ref(), attributes: Vec::new() }
	}

	/// Opaque octets of `id-data` (RFC 5652 §4).
	pub fn data(content: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		Self::new(DATA, content)
	}

	/// Add a signed attribute of the caller's profile.
	#[must_use]
	pub fn with_attribute(mut self, attribute: Attribute) -> Self {
		self.attributes.push(attribute);
		self
	}

	/// Add a signed attribute under `oid` whose value SET holds `value`
	/// alone.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- the value SET fails to build.
	pub fn with_single_valued(mut self, oid: ObjectIdentifier, value: Any) -> Result<Self, SignerError> {
		let values = SetOfVec::try_from(vec![value])?;
		self.attributes.push(Attribute { oid, values });
		Ok(self)
	}

	/// The content type the content-type attribute names.
	pub fn content_type(&self) -> ObjectIdentifier {
		self.content_type
	}

	/// The octets the message-digest attribute covers.
	pub fn content(&self) -> &'a [u8] {
		self.content
	}

	/// The signed attributes of this content under the two algorithms.
	///
	/// The set holds the content type, `message_digest`, the algorithm
	/// protection of the two algorithms, and the attributes of the profile,
	/// which move into it. Each OID occurs once (RFC 5652 §11.1, §11.2,
	/// RFC 6211 §2). `SetOfVec` sorts the set into DER order.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- an attribute fails to encode.
	/// - [`SignerError::DuplicateAttribute`] -- a profile attribute repeats an OID of the set.
	fn signed_attributes(
		self,
		message_digest: &[u8],
		digest_algorithm: &AlgorithmIdentifierOwned,
		signature_algorithm: &AlgorithmIdentifierOwned,
	) -> Result<SignedAttributes, SignerError> {
		let protection = CmsAlgorithmProtection {
			digest_algorithm: digest_algorithm.clone(),
			signature_algorithm: Some(signature_algorithm.clone()),
			mac_algorithm: None,
		};

		let content_type = Any::encode_from(&self.content_type)?;
		let digest = Any::encode_from(&OctetString::new(message_digest)?)?;
		let protection = Any::encode_from(&protection)?;

		let required = Self::new(self.content_type, self.content)
			.with_single_valued(ATTR_CONTENT_TYPE, content_type)?
			.with_single_valued(ATTR_MESSAGE_DIGEST, digest)?
			.with_single_valued(ATTR_CMS_ALGORITHM_PROTECTION, protection)?;

		let mut attributes = required.attributes;
		for attribute in self.attributes {
			if attributes.iter().any(|held| held.oid == attribute.oid) {
				return Err(SignerError::DuplicateAttribute(attribute.oid));
			}

			attributes.push(attribute);
		}

		Ok(SignedAttributes::try_from(attributes)?)
	}
}

/// The `SignerInfo` version its `sid` demands (RFC 5652 §5.3).
fn signer_version(sid: &SignerIdentifier) -> CmsVersion {
	match sid {
		SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
		SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
	}
}

/// The `SignedData` version that a certificate of this choice demands
/// (RFC 5652 §5.1).
///
/// `CertificateChoices` decodes an X.509 certificate or an `other` format.
/// An attribute certificate, the version 4 case and one version 3 case of the
/// rule, decodes as neither, so a `SignedData` that holds one fails to decode.
fn certificate_version(choice: &CertificateChoices) -> CmsVersion {
	match choice {
		CertificateChoices::Certificate(_) => CmsVersion::V1,
		CertificateChoices::Other(_) => CmsVersion::V5,
	}
}

/// The `SignedData` version that a revocation entry of this choice demands
/// (RFC 5652 §5.1).
fn crl_version(choice: &RevocationInfoChoice) -> CmsVersion {
	match choice {
		RevocationInfoChoice::Crl(_) => CmsVersion::V1,
		RevocationInfoChoice::Other(_) => CmsVersion::V5,
	}
}

/// The `SignedData` version that RFC 5652 §5.1 gives these parts.
///
/// - 5 for a certificate or a revocation entry of type `other`.
/// - 3 for a version 3 signer or a content other than `id-data`.
/// - 1 otherwise.
fn signed_data_version(
	certificates: Option<&CertificateSet>,
	crls: Option<&RevocationInfoChoices>,
	signer_infos: &SignerInfos,
	content_type: ObjectIdentifier,
) -> CmsVersion {
	let certificate_floor = certificates.iter().flat_map(|set| set.0.iter()).map(certificate_version);
	let crl_floor = crls.iter().flat_map(|set| set.0.iter()).map(crl_version);
	let version_3_signer = signer_infos.0.iter().any(|signer| signer.version == CmsVersion::V3);
	let content_floor = if version_3_signer || content_type != DATA {
		CmsVersion::V3
	} else {
		CmsVersion::V1
	};

	certificate_floor.chain(crl_floor).fold(content_floor, Ord::max)
}

/// Refuse `received` unless it names `expected`.
///
/// # Errors
///
/// - [`SignerError::UnexpectedAlgorithm`] -- the OIDs differ.
fn expect_algorithm(received: &AlgorithmIdentifierOwned, expected: ObjectIdentifier) -> Result<(), SignerError> {
	if received.oid != expected {
		return Err(SignerError::UnexpectedAlgorithm(ReceivedExpectedError::from((
			received.oid,
			expected,
		))));
	}

	Ok(())
}

/// The canonical encoding of a signature value under one signature type.
type Canonicalize = fn(&[u8]) -> Result<Vec<u8>, SignerError>;

/// Parse `encoded` as `S` alone, and return the encoding of its canonical
/// form: for ECDSA, the DER `ECDSA-Sig-Value` with `s` in the low half.
///
/// # Errors
///
/// - [`SignerError::Signature`] -- `encoded` is no `S` encoding, or holds a value out of range.
pub(crate) fn canonical_bytes<S>(encoded: &[u8]) -> Result<Vec<u8>, SignerError>
where
	S: CanonicalForm + SignatureEncoding,
{
	let canonical = S::canonical(encoded)?;
	Ok(canonical.to_vec())
}

/// A function that drafts the `SignerInfo` a `sid` signs over a content
/// under one signature type.
type Draft = fn(SignerIdentifier, SignedContent<'_>) -> Result<SignerInfoDraft, SignerError>;

/// The signature scheme of an identity, as the functions of one
/// [`SigningProvider`]: its draft, the canonical form of each value its key
/// returns, its algorithm, and the policy that verifies its own signatures.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scheme {
	draft: Draft,
	canonicalize: Canonicalize,
	algorithm: ObjectIdentifier,
	policy: &'static dyn VerificationPolicy,
}

impl Scheme {
	/// The scheme of the provider `P`.
	pub(crate) fn of<P>() -> Self
	where
		P: SigningProvider + 'static,
		P::VerifyingKey: DecodePublicKey,
	{
		Self {
			draft: CmsSigner::draft::<P::Signature>,
			canonicalize: canonical_bytes::<P::Signature>,
			algorithm: P::Signature::ALGORITHM_OID,
			policy: &const { ProviderPolicy::<P>::new() },
		}
	}

	/// The OID of the scheme's signature algorithm.
	pub(crate) fn algorithm(self) -> ObjectIdentifier {
		self.algorithm
	}

	/// The policy that verifies a signature of the scheme.
	pub(crate) fn policy(self) -> &'static dyn VerificationPolicy {
		self.policy
	}

	/// Draft the `SignerInfo` that `sid` signs over `content` under this
	/// scheme.
	///
	/// # Errors
	///
	/// - The errors of [`CmsSigner::draft`].
	pub(crate) fn draft(
		self,
		sid: SignerIdentifier,
		content: SignedContent<'_>,
	) -> Result<SignerInfoDraft, SignerError> {
		(self.draft)(sid, content)
	}

	/// The canonical form of `signature` under this scheme.
	///
	/// # Errors
	///
	/// - [`SignerError::Signature`] -- `signature` is no encoding of the scheme's signature type.
	pub(crate) fn canonical(self, signature: &[u8]) -> Result<Vec<u8>, SignerError> {
		(self.canonicalize)(signature)
	}
}

/// A `SignerInfo` complete up to its signature.
///
/// [`Self::prehash`] is what the key signs: the digest of the DER of the
/// signed attributes (RFC 5652 §5.4). [`Self::complete`] attaches the
/// signature in the canonical form of the draft's signature type.
#[derive(Clone, Debug)]
pub struct SignerInfoDraft {
	sid: SignerIdentifier,
	digest_algorithm: AlgorithmIdentifierOwned,
	signature_algorithm: AlgorithmIdentifierOwned,
	signed_attrs: SignedAttributes,
	prehash: Vec<u8>,
	canonicalize: Canonicalize,
}

impl SignerInfoDraft {
	/// The digest the signer's key signs.
	pub fn prehash(&self) -> &[u8] {
		&self.prehash
	}

	/// Attach `signature` and any `unsigned_attrs` of the caller's profile.
	///
	/// The draft parses `signature` as its signature type alone and attaches
	/// the canonical form: for ECDSA, the DER `ECDSA-Sig-Value` (RFC 5753
	/// §2.1.1) with `s` in the low half. A key provider's bytes reach the
	/// `SignerInfo` only in that form.
	///
	/// # Errors
	///
	/// - [`SignerError::Signature`] -- `signature` is not the encoding of the signature type.
	/// - [`SignerError::Encoding`] -- the signature fails to wrap in an OCTET STRING.
	pub fn complete(
		self,
		signature: impl AsRef<[u8]>,
		unsigned_attrs: Option<UnsignedAttributes>,
	) -> Result<Signed<SignerInfo>, SignerError> {
		let Self { sid, digest_algorithm, signature_algorithm, signed_attrs, canonicalize, .. } = self;
		let canonical = canonicalize(signature.as_ref())?;
		let signer_info = SignerInfo {
			version: signer_version(&sid),
			sid,
			digest_alg: digest_algorithm,
			signed_attrs: Some(signed_attrs),
			signature_algorithm,
			signature: OctetString::new(canonical)?,
			unsigned_attrs,
		};

		Ok(Signed::new(signer_info, SignerSeal(())))
	}
}

/// The one builder and verifier of the crate's CMS signatures.
///
/// Every `SignerInfo` carries the content type, the message digest, and the
/// algorithm protection of RFC 6211 as signed attributes. Its `sid` and
/// version follow RFC 5652 §5.3, and a `SignedData` takes the version that
/// RFC 5652 §5.1 gives it.
pub struct CmsSigner;

impl CmsSigner {
	/// Draft the `SignerInfo` that `sid` signs over `content` under the
	/// signature type `S`.
	///
	/// `S` names the signature algorithm and the digest it names (RFC 5753
	/// §2.1.1), so the draft cannot pair the two otherwise.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- an attribute fails to encode.
	/// - [`SignerError::DuplicateAttribute`] -- a profile attribute repeats an OID of the set.
	pub fn draft<S>(sid: SignerIdentifier, content: SignedContent<'_>) -> Result<SignerInfoDraft, SignerError>
	where
		S: CanonicalForm + SignatureEncoding + SignatureAlgorithmIdentifier,
	{
		let digest_algorithm = AlgorithmIdentifierOwned { oid: <S::Digest as AssociatedOid>::OID, parameters: None };
		let signature_algorithm = AlgorithmIdentifierOwned { oid: S::ALGORITHM_OID, parameters: None };
		let message_digest = S::Digest::digest(content.content);
		let signed_attrs = content.signed_attributes(&message_digest, &digest_algorithm, &signature_algorithm)?;
		let prehash = S::Digest::digest(signed_attrs.to_der()?).to_vec();
		let canonicalize: Canonicalize = canonical_bytes::<S>;

		Ok(SignerInfoDraft { sid, digest_algorithm, signature_algorithm, signed_attrs, prehash, canonicalize })
	}

	/// Sign `content` with `key`, a key that signs in place under the
	/// certificate it was paired with.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- an attribute fails to encode.
	/// - [`SignerError::DuplicateAttribute`] -- a profile attribute repeats an OID of the set.
	/// - [`SignerError::Signature`] -- the key refuses the prehash.
	pub fn sign_with<S, K>(key: &CertifiedKey<K>, content: SignedContent<'_>) -> Result<Signed<SignerInfo>, SignerError>
	where
		S: CanonicalForm + SignatureEncoding + SignatureAlgorithmIdentifier,
		K: PrehashSigner<S>,
	{
		let sid = key.signer_identifier().clone();
		let draft = Self::draft::<S>(sid, content)?;
		let signature: S = key.key().sign_prehash(draft.prehash())?;

		draft.complete(signature.to_bytes(), None)
	}

	/// Verify `signer_info` over `content` under `key`.
	///
	/// The check follows RFC 5652 §5.4 and RFC 6211 §3:
	///
	/// 1. The digest and signature algorithms are the pair that `S` names (RFC 5753 §2.1.1).
	/// 2. The version matches the `sid` (RFC 5652 §5.3).
	/// 3. The signed attributes are present and equal the set that `content` requires.
	/// 4. The signature, in its canonical form, verifies over the DER of those attributes.
	///
	/// # Errors
	///
	/// - [`SignerError::UnexpectedAlgorithm`] -- the digest or signature algorithm is another.
	/// - [`SignerError::SignerInfoVersion`] -- the version differs from the one the `sid` demands.
	/// - [`SignerError::SignedAttributes`] -- the signed attributes differ from the required set.
	/// - [`SignerError::DuplicateAttribute`] -- `content` repeats an OID of the set.
	/// - [`SignerError::Encoding`] -- an attribute fails to encode.
	/// - [`SignerError::Signature`] -- the signature is not an `S` encoding, or it fails to verify.
	pub fn verify<S, V>(
		signer_info: &SignerInfo,
		key: &V,
		content: SignedContent<'_>,
	) -> Result<VerifiedSignature, SignerError>
	where
		S: CanonicalForm + SignatureEncoding + SignatureAlgorithmIdentifier,
		V: PrehashVerifier<S> + ?Sized,
	{
		expect_algorithm(&signer_info.digest_alg, <S::Digest as AssociatedOid>::OID)?;
		expect_algorithm(&signer_info.signature_algorithm, S::ALGORITHM_OID)?;

		let message_digest = S::Digest::digest(content.content);
		let signed_attrs = Self::required_attributes(signer_info, content, &message_digest)?;
		let prehash = S::Digest::digest(signed_attrs.to_der()?);

		Ok(VerifiedSignature::verify::<S, V>(
			key,
			prehash,
			signer_info.signature.as_bytes(),
		)?)
	}

	/// Verify that `signer_info` names `signer`, a certificate admitted for
	/// signing under `P`, and verify it over `content` under the key of that
	/// certificate.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- the certificate's key identifier fails to decode.
	/// - [`SignerError::SignerIdentifier`] -- the `sid` names another certificate.
	/// - The errors of [`Self::verify`].
	pub fn verify_signer<P>(
		signer_info: &SignerInfo,
		signer: &PeerCertificate<Signing<P>>,
		content: SignedContent<'_>,
	) -> Result<VerifiedSignature, SignerError>
	where
		P: SigningProvider,
		P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = crate::spki::Error>,
	{
		Self::expect_signer(signer_info, signer.certificate())?;
		Self::verify::<P::Signature, _>(signer_info, &signer.key, content)
	}

	/// Verify the one `SignerInfo` of `signed_data` over `content` under the
	/// key of `signer`, which its `sid` must name.
	///
	/// A handshake message carries exactly one signer, so every handshake
	/// signature verifies here.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- `signed_data` does not have
	///   exactly one signer, or its `sid` names another certificate.
	/// - The errors of [`Self::verify_signer`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn verify_sole_signer<P>(
		signed_data: &SignedData,
		signer: &PeerCertificate<Signing<P>>,
		content: SignedContent<'_>,
	) -> Result<VerifiedSignature, SignerError>
	where
		P: SigningProvider,
		P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = crate::spki::Error>,
	{
		let signer_info = Self::sole_signer(signed_data)?;
		Self::verify_signer::<P>(signer_info, signer, content)
	}

	/// Verify `signer_info` over `content` under `signer`, a certificate
	/// admitted for signing, with the algorithms of `policy`.
	///
	/// The verifier names the algorithms at run time, so the policy digests
	/// the content and verifies the signature by the pair the `SignerInfo`
	/// names, and refuses a pair it does not hold. It reads the key from the
	/// certificate's SPKI at each verify, which is the cost of the erasure.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- the key identifier fails to decode,
	///   or the policy refuses the algorithm pair, the key, or the signature.
	/// - [`SignerError::SignerIdentifier`] -- the `sid` names another certificate.
	/// - [`SignerError::SignerInfoVersion`] -- the version differs from the one the `sid` demands.
	/// - [`SignerError::SignedAttributes`] -- the signed attributes differ from the required set.
	/// - [`SignerError::DuplicateAttribute`] -- `content` repeats an OID of the set.
	/// - [`SignerError::Encoding`] -- an attribute or the public key fails to encode.
	pub fn verify_with_policy(
		signer_info: &SignerInfo,
		signer: &PeerCertificate<ErasedSigning>,
		policy: &dyn VerificationPolicy,
		content: SignedContent<'_>,
	) -> Result<VerifiedSignature, SignerError> {
		let certificate = signer.certificate();
		Self::expect_signer(signer_info, certificate)?;

		let signature_oid = signer_info.signature_algorithm.oid;
		let digest_oid = signer_info.digest_alg.oid;
		let message_digest = policy.digest(&signature_oid, &digest_oid, content.content)?;
		let signed_attrs = Self::required_attributes(signer_info, content, &message_digest)?;
		let message = signed_attrs.to_der()?;
		let public_key_der = certificate.tbs_certificate.subject_public_key_info.to_der()?;
		let signature = signer_info.signature.as_bytes();

		Ok(policy.verify_signature(&signature_oid, &public_key_der, &message, signature)?)
	}

	/// Assemble the `SignedData` that carries `content` and its one signer.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- the content or a SET fails to encode.
	pub fn signed_data(
		content: SignedContent<'_>,
		signer: Signed<SignerInfo>,
		certificates: Option<CertificateSet>,
	) -> Result<Signed<SignedData>, SignerError> {
		let signer = signer.into_inner();
		let digest_algorithms = SetOfVec::try_from(vec![signer.digest_alg.clone()])?;
		let econtent = Any::encode_from(&OctetString::new(content.content)?)?;
		let encap_content_info =
			EncapsulatedContentInfo { econtent_type: content.content_type, econtent: Some(econtent) };
		let signer_infos = SignerInfos(SetOfVec::try_from(vec![signer])?);
		let version = signed_data_version(certificates.as_ref(), None, &signer_infos, content.content_type);

		let signed_data = SignedData {
			version,
			digest_algorithms,
			encap_content_info,
			certificates,
			crls: None,
			signer_infos,
		};
		Ok(Signed::new(signed_data, SignerSeal(())))
	}

	/// The encapsulated content of `signed_data`, of type `content_type`.
	///
	/// The read checks the `SignedData` version against RFC 5652 §5.1 and
	/// each signer's digest algorithm against `digestAlgorithms`.
	///
	/// # Errors
	///
	/// - [`SignerError::SignedDataVersion`] -- the version differs from the RFC 5652 §5.1 rule.
	/// - [`SignerError::DigestAlgorithms`] -- `digestAlgorithms` lacks the digest of a signer.
	/// - [`SignerError::Content`] -- the content is absent, of another type, or no OCTET STRING.
	pub fn content(signed_data: &SignedData, content_type: ObjectIdentifier) -> Result<&[u8], SignerError> {
		let econtent_type = signed_data.encap_content_info.econtent_type;
		let certificates = signed_data.certificates.as_ref();
		let crls = signed_data.crls.as_ref();
		let signer_infos = &signed_data.signer_infos;
		let expected_version = signed_data_version(certificates, crls, signer_infos, econtent_type);
		if signed_data.version != expected_version {
			let versions = ReceivedExpectedError::from((signed_data.version, expected_version));
			return Err(SignerError::SignedDataVersion(versions));
		}

		let digest_algorithms = signed_data.digest_algorithms.as_ref();
		let mut signers = signer_infos.0.iter();
		let declared = signers.all(|signer| digest_algorithms.contains(&signer.digest_alg));
		if !declared {
			return Err(SignerError::DigestAlgorithms);
		}

		if econtent_type != content_type {
			return Err(SignerError::Content);
		}

		let econtent = signed_data.encap_content_info.econtent.as_ref();
		let econtent = econtent.ok_or(SignerError::Content)?;
		if econtent.tag() != Tag::OctetString {
			return Err(SignerError::Content);
		}

		Ok(econtent.value())
	}

	/// The one `SignerInfo` of `signed_data`.
	///
	/// RFC 5652 §5.1 admits any number of signers, and a handshake message
	/// carries exactly one, so every reader of a signer takes it here.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- `signed_data` does not have exactly one signer.
	pub(crate) fn sole_signer(signed_data: &SignedData) -> Result<&SignerInfo, SignerError> {
		match signed_data.signer_infos.0.as_ref() {
			[signer_info] => Ok(signer_info),
			_ => Err(SignerError::SignerIdentifier),
		}
	}

	/// Take the one `SignerInfo` of `signed_data` out of its set, under the
	/// rule and the refusal of [`Self::sole_signer`]. The set is empty after
	/// the call, whatever it returns.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- `signed_data` does not have exactly one signer.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn take_sole_signer(signed_data: &mut SignedData) -> Result<SignerInfo, SignerError> {
		let signers = core::mem::take(&mut signed_data.signer_infos.0).into_vec();
		let [signer_info] = <[SignerInfo; 1]>::try_from(signers).map_err(|_| SignerError::SignerIdentifier)?;
		Ok(signer_info)
	}

	/// The first of `candidates` whose certificate `signer_info` names by its
	/// `sid`, beside what travels with that certificate.
	///
	/// Every reader of a signer's certificate selects through this one scan,
	/// so the decoded set and the received bytes name the same element.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- a certificate's key identifier fails to decode.
	fn first_named<C, T>(
		signer_info: &SignerInfo,
		candidates: impl IntoIterator<Item = (C, T)>,
	) -> Result<Option<(C, T)>, SignerError>
	where
		C: Borrow<Certificate>,
	{
		for (certificate, carried) in candidates {
			if certificate.borrow().is_named_by(&signer_info.sid)? {
				return Ok(Some((certificate, carried)));
			}
		}

		Ok(None)
	}

	/// The certificate of `certificates` that the one signer of `signed_data`
	/// names by its `sid`, wherever it sorts in the SET (RFC 5652 §5.3), or
	/// `None` when the set holds no such certificate.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- `signed_data` does not have exactly one signer.
	/// - [`SignerError::Certificate`] -- a certificate's key identifier fails to decode.
	pub fn signer_certificate(signed_data: &SignedData) -> Result<Option<&Certificate>, SignerError> {
		let signer_info = Self::sole_signer(signed_data)?;
		Self::named_certificate(signed_data, signer_info)
	}

	/// The certificate of the `certificates` of `signed_data` that
	/// `signer_info`, one of its signers, names by its `sid` (RFC 5652 §5.3),
	/// or `None` when the set holds no such certificate.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- a certificate's key identifier fails to decode.
	pub(crate) fn named_certificate<'a>(
		signed_data: &'a SignedData,
		signer_info: &SignerInfo,
	) -> Result<Option<&'a Certificate>, SignerError> {
		let choices = signed_data.certificates.iter().flat_map(|set| set.0.iter());
		let certificates = choices.filter_map(ArrivedCertificates::named);
		let certificates = certificates.map(|certificate| (certificate, ()));

		let named = Self::first_named(signer_info, certificates)?;
		Ok(named.map(|(certificate, ())| certificate))
	}

	/// The certification path the one signer of `signed_data` presents, and
	/// the bytes of its `certificates` field as they arrived in `der`, the
	/// encoding `signed_data` decoded from. It is `None` when the set holds no
	/// certificate the signer names.
	///
	/// - The leaf is the certificate the `sid` names (RFC 5652 §5.3), and
	///   [`PresentedPath::walk`] takes each issuer above it by name.
	/// - Every certificate parses from the bytes it arrived as, so a reader
	///   that binds the field binds the path it keeps, and a decoder that
	///   normalizes an encoding changes no byte the binding covers (CWE-345).
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- `signed_data` does not have exactly one signer.
	/// - [`SignerError::Certificate`] -- the set holds more than
	///   [`MAX_PRESENTED_PATH`](crate::constants::MAX_PRESENTED_PATH)
	///   certificates, which the reader refuses before it walks a path or
	///   checks a signature, a certificate's key identifier fails to decode,
	///   or the walk refuses the path.
	/// - [`SignerError::Encoding`] -- `der` is no SEQUENCE of elements, it
	///   carries a second `certificates` field, or a certificate of the set
	///   arrived in another encoding than its DER.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn signer_path<'a>(
		signed_data: &SignedData,
		der: &'a [u8],
	) -> Result<Option<(PresentedPath, &'a [u8])>, SignerError> {
		let signer_info = Self::sole_signer(signed_data)?;

		// 1. Find the `certificates` field as it arrived, refuse a set past the
		//    cap, and hold each certificate to the bytes it arrived as.
		let Some(arrived) = ArrivedCertificates::read(der)? else {
			return Ok(None);
		};
		PresentedPath::bound(arrived.count())?;
		arrived.admit(signed_data.certificates.as_ref())?;

		// 2. Walk the path of the certificate the `sid` names.
		let choices = signed_data.certificates.iter().flat_map(|set| set.0.iter());
		let certificates = choices.filter_map(ArrivedCertificates::named).cloned().collect();
		let path = Self::path_among(signer_info, certificates)?;
		Ok(path.map(|path| (path, arrived.field())))
	}

	/// Refuse `der`, the encoding of a `SignedData`, when its `certificates`
	/// field arrived with more choices than a path holds, before a typed
	/// decode sorts the set.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- the set holds more than
	///   [`MAX_PRESENTED_PATH`](crate::constants::MAX_PRESENTED_PATH) choices.
	/// - [`SignerError::Encoding`] -- `der` is no SEQUENCE of elements, or it
	///   carries a second `certificates` field.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn bound_presented(der: &(impl AsRef<[u8]> + ?Sized)) -> Result<(), SignerError> {
		let arrived = ArrivedCertificates::read(der)?;
		let count = arrived.as_ref().map_or(0, ArrivedCertificates::count);
		Ok(PresentedPath::bound(count)?)
	}

	/// Take out of the `certificates` of `finished` the certification path
	/// its one signer presents, beside the `SignedData` the set left, or
	/// `None` for the path when the set holds no certificate the signer
	/// names.
	///
	/// A mutual server reads the path a client Finished presents here:
	///
	/// - The leaf is the certificate the `sid` names (RFC 5652 §5.3), and
	///   [`PresentedPath::walk`] takes each issuer above it by name.
	/// - Each certificate moves out of the decoded set, so it parses once.
	/// - The decode of `finished` held each certificate to the bytes it arrived as.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- `finished` does not have exactly one signer.
	/// - [`SignerError::Certificate`] -- the set holds more than
	///   [`MAX_PRESENTED_PATH`](crate::constants::MAX_PRESENTED_PATH)
	///   certificates, which the reader refuses before it walks a path or
	///   checks a signature, a certificate's key identifier fails to decode,
	///   or the walk refuses the path.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn take_signer_path(
		finished: Signed<SignedData>,
	) -> Result<(SignedData, Option<PresentedPath>), SignerError> {
		// 1. Take the set out, and refuse one past the cap before it walks a path or checks a signature.
		let mut signed_data = finished.into_inner();
		let set = signed_data.certificates.take();
		let choices = set.map(|set| set.0.into_vec()).unwrap_or_default();
		let signer_info = Self::sole_signer(&signed_data)?;
		PresentedPath::bound(choices.len())?;

		// 2. Walk the path of the certificate the `sid` names.
		let certificates = choices.into_iter().filter_map(ArrivedCertificates::into_named).collect();
		let path = Self::path_among(signer_info, certificates)?;
		Ok((signed_data, path))
	}

	/// The path of the certificate of `certificates` that `signer_info` names
	/// by its `sid`, under each issuer above it that the rest hold, or `None`
	/// when it names none of them.
	///
	/// The named certificate moves out by its position, and
	/// [`PresentedPath::walk`] takes each issuer by name, so the order of the
	/// rest is free.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- a certificate's key identifier fails
	///   to decode, or the walk refuses the path.
	/// - [`SignerError::SignerIdentifier`] -- the scan names a position outside `certificates`.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn path_among(
		signer_info: &SignerInfo,
		mut certificates: Vec<Certificate>,
	) -> Result<Option<PresentedPath>, SignerError> {
		let candidates = certificates.iter().enumerate().map(|(index, held)| (held, index));
		let Some((_, position)) = Self::first_named(signer_info, candidates)? else {
			return Ok(None);
		};

		let leaf = (position < certificates.len()).then(|| certificates.swap_remove(position));
		let leaf = leaf.ok_or(SignerError::SignerIdentifier)?;
		Ok(Some(PresentedPath::walk(leaf, certificates)?))
	}

	/// Refuse `signer_info` unless its `sid` names `certificate`.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- the certificate's key identifier fails to decode.
	/// - [`SignerError::SignerIdentifier`] -- the `sid` names another certificate.
	fn expect_signer(signer_info: &SignerInfo, certificate: &Certificate) -> Result<(), SignerError> {
		if !certificate.is_named_by(&signer_info.sid)? {
			return Err(SignerError::SignerIdentifier);
		}

		Ok(())
	}

	/// The signed attributes of `signer_info`, once they equal the set that
	/// `content` requires under `message_digest`.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerInfoVersion`] -- the version differs from the one the `sid` demands.
	/// - [`SignerError::SignedAttributes`] -- the signed attributes differ from the required set.
	/// - [`SignerError::Encoding`] -- an attribute fails to encode.
	/// - [`SignerError::DuplicateAttribute`] -- a profile attribute repeats an OID of the set.
	fn required_attributes<'s>(
		signer_info: &'s SignerInfo,
		content: SignedContent<'_>,
		message_digest: &[u8],
	) -> Result<&'s SignedAttributes, SignerError> {
		let expected_version = signer_version(&signer_info.sid);
		if signer_info.version != expected_version {
			let versions = ReceivedExpectedError::from((signer_info.version, expected_version));
			return Err(SignerError::SignerInfoVersion(versions));
		}

		let received = signer_info.signed_attrs.as_ref();
		let received = received.ok_or(SignerError::SignedAttributes)?;
		let digest_algorithm = &signer_info.digest_alg;
		let signature_algorithm = &signer_info.signature_algorithm;
		let required = content.signed_attributes(message_digest, digest_algorithm, signature_algorithm)?;
		if *received != required {
			return Err(SignerError::SignedAttributes);
		}

		Ok(received)
	}
}

impl Signed<SignedData> {
	/// Attach `attribute` to the unsigned attributes of the one `SignerInfo`
	/// of this `SignedData`.
	///
	/// The signature covers the signed attributes alone (RFC 5652 §5.3), so the
	/// value stays the signer's. A server Finished joins the HPKE reply this
	/// way, after the signature it covers exists.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- this `SignedData` does not have exactly one signer.
	/// - [`SignerError::Encoding`] -- a SET refuses the attribute.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn with_unsigned_attribute(self, attribute: Attribute) -> Result<Self, SignerError> {
		let mut signed_data = self.into_inner();
		let mut signer = CmsSigner::take_sole_signer(&mut signed_data)?;

		let mut unsigned_attrs = signer.unsigned_attrs.take().unwrap_or_default();
		unsigned_attrs.insert(attribute)?;
		signer.unsigned_attrs = Some(unsigned_attrs);
		signed_data.signer_infos = SignerInfos(SetOfVec::try_from(vec![signer])?);

		Ok(Signed::new(signed_data, SignerSeal(())))
	}

	/// Add `signer` to this `SignedData` beside the certificate its `sid`
	/// names, and take the version that the joined signers give it (RFC 5652
	/// §5.1). A set that holds the certificate already keeps its one copy.
	///
	/// A receipt countersignature joins the server's `SignedData` this way, so
	/// the artifact carries the certificate of each of its signers.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- a SET of the `SignedData` refuses the insertion.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn with_certified_signer(self, signer: CertifiedSigner) -> Result<Self, SignerError> {
		let mut signed_data = self.into_inner();
		let CertifiedSigner { signer, certificate } = signer;
		let signer = signer.into_inner();

		let digest_present = signed_data.digest_algorithms.as_ref().contains(&signer.digest_alg);
		if !digest_present {
			signed_data.digest_algorithms.insert(signer.digest_alg.clone())?;
		}

		signed_data.signer_infos.0.insert(signer)?;

		// A `CertificateSet` owns each certificate it holds, so a certificate
		// the set lacks joins as its own copy. The client's identity, or the
		// server's record of its peer, keeps a handle for the session, so each
		// join of a session makes a deep clone.
		let set = signed_data.certificates.get_or_insert_with(|| CertificateSet(SetOfVec::new()));
		let mut held_certificates = set.0.iter().filter_map(ArrivedCertificates::named);
		let held = held_certificates.any(|held| *held == *certificate);
		if !held {
			let choice = CertificateChoices::Certificate(Arc::unwrap_or_clone(certificate));
			set.0.insert(choice)?;
		}

		let certificates = signed_data.certificates.as_ref();
		let crls = signed_data.crls.as_ref();
		let content_type = signed_data.encap_content_info.econtent_type;

		signed_data.version = signed_data_version(certificates, crls, &signed_data.signer_infos, content_type);

		Ok(Signed::new(signed_data, SignerSeal(())))
	}
}

/// A `SignerInfo` beside the certificate its `sid` names (RFC 5652 §5.3), the
/// form in which a signer joins a `SignedData` that carries the certificate
/// of each of its signers.
///
/// [`Self::new`] is its one constructor, and it admits only the certificate
/// the `sid` names, so [`Signed::with_certified_signer`] joins each signer
/// beside its own certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct CertifiedSigner {
	/// The `SignerInfo` that joins a `SignedData`.
	signer: Signed<SignerInfo>,
	/// The certificate the `sid` of the signer names.
	certificate: Arc<Certificate>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl CertifiedSigner {
	/// `signer` beside `certificate`, the certificate its `sid` names.
	///
	/// # Errors
	///
	/// - [`SignerError::SignerIdentifier`] -- the `sid` names another certificate.
	/// - [`SignerError::Certificate`] -- the certificate's key identifier fails to decode.
	pub(crate) fn new(signer: Signed<SignerInfo>, certificate: Arc<Certificate>) -> Result<Self, SignerError> {
		CmsSigner::expect_signer(&signer, &certificate)?;
		Ok(Self { signer, certificate })
	}

	/// The signer, which a message also carries apart from the `SignedData`
	/// it joins.
	pub(crate) fn signer(&self) -> &Signed<SignerInfo> {
		&self.signer
	}
}
