//! The test material that the suite builds scenarios from.
//!
//! Each owner type names the material it makes, so a reader who looks for a
//! certificate, a frame, or a key finds one place for it.

use std::sync::Arc;

use crate::asn1::{AlgorithmIdentifier, AlgorithmIdentifierOwned, DigestInfo, Frame, ObjectIdentifier, OctetString};
use crate::der::Sequence;
use crate::oids::HASH_SHA256;
use crate::trace::{IntoEventLabel, TraceCollector};
use crate::Beamable;
use crate::{Message, TightBeamError, Version};

#[cfg(all(test, host_clock))]
use crate::clock::Clock;
#[cfg(host_clock)]
use crate::clock::{ManualClock, UnixMillis};
#[cfg(feature = "aead")]
use aead::*;

#[cfg(feature = "aead")]
mod aead {
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub use crate::crypto::aead::Aes256Gcm;
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub use crate::crypto::aead::{DirectionalCiphers, RuntimeAead};
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub use crate::crypto::key::Aes256GcmKeyProvider;
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub use crate::crypto::profiles::DefaultCryptoProvider;
	pub use crate::runtime::rt;
}

#[cfg(any(
	all(feature = "digest", feature = "sha3"),
	all(feature = "secp256k1", feature = "signature", feature = "x509")
))]
mod hash {
	pub use crate::crypto::hash::Sha3_256;
}

#[cfg(any(
	all(feature = "digest", feature = "sha3"),
	all(feature = "secp256k1", feature = "signature", feature = "x509")
))]
use hash::*;

#[cfg(feature = "x509")]
mod x509_certs {
	pub use crate::cms::cert::CertificateChoices;
	pub use crate::cms::signed_data::CertificateSet;
	pub use crate::x509::Certificate;
}

#[cfg(feature = "x509")]
use x509_certs::*;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod sha3_512_profile {
	pub use crate::crypto::aead::Aes256GcmOid;
	pub use crate::crypto::exchange::Ecdhe;
	pub use crate::crypto::hash::Sha3_512;
	pub use crate::crypto::kdf::HkdfSha3_256;
	pub use crate::crypto::profiles::{
		AeadProvider, Aes256Wrap, CryptoProvider, DigestProvider, KdfProvider, KeyExchangeProvider, KeyWrapProvider,
		SecurityProfile, SigningProvider,
	};
	pub use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use sha3_512_profile::*;

#[cfg(feature = "transport-cms")]
mod cms_server {
	pub use crate::transport::handshake::{CmsIdentityPair, ProvisionedTrust};
}

#[cfg(feature = "transport-cms")]
use cms_server::*;

#[cfg(any(
	feature = "transport-cms",
	all(test, feature = "hpke", feature = "signature", feature = "x509")
))]
mod agreement {
	pub use crate::crypto::cms::KeyAgreementIdentity;
	pub use crate::crypto::hpke::DhKemSecp256k1;
	pub use crate::crypto::key::DiffieHellman;
	pub use crate::crypto::sign::ecdsa::Secp256k1;
}

#[cfg(any(
	feature = "transport-cms",
	all(test, feature = "hpke", feature = "signature", feature = "x509")
))]
use agreement::*;

#[cfg(all(
	any(test, feature = "transport-cms"),
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
mod store {
	pub use crate::crypto::policy::Secp256k1Policy;
	pub use crate::crypto::x509::store::{
		CertificateTrustBuilder, CertificateTrustStore, NoRevocation, RevocationChecker, TrustBuilder,
	};
	pub use crate::crypto::x509::KeyCurves;
}

#[cfg(all(
	any(test, feature = "transport-cms"),
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
use store::*;

#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
mod trust {
	pub use crate::cms::signed_data::SignerIdentifier;
	pub use crate::crypto::policy::VerificationPolicy;
	pub use crate::crypto::x509::error::CertificateValidationError;
	pub use crate::crypto::x509::policy::CertificateValidation;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::crypto::x509::{ErasedSigning, PeerCertificate};
}

#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use trust::*;

/// A message of one text field that the tests encode and send.
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct TestMessage {
	/// The text the message carries.
	pub content: String,
}

impl TestMessage {
	pub fn sample(content: Option<&str>) -> TestMessage {
		TestMessage {
			content: content.map(|c| c.into()).unwrap_or_else(|| "Hello TightBeam!".to_string()),
		}
	}
}

/// A message whose type requires a confidential frame.
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(confidential)]
pub struct ConfidentialNote {
	/// The text the note carries.
	pub content: String,
}

/// A message of numeric profile 1, whose type requires a confidential and
/// non-repudiable frame of version V1 or later.
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile = 1)]
pub struct ConfidentialNonrepudiableNote {
	/// The text the note carries.
	pub content: String,
}

/// A message whose type requires a message integrity digest and a frame
/// integrity digest.
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(message_integrity, frame_integrity)]
pub struct IntegralNote {
	/// The text the note carries.
	pub content: String,
}

/// A message whose type requires a signature. Its DER is the DER of
/// [`TestMessage`].
#[cfg(test)]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(nonrepudiable)]
pub(crate) struct SignedNote {
	/// The text the note carries.
	pub(crate) content: String,
}

/// A message whose type requires a frame of version V2 or later. Its DER is
/// the DER of [`TestMessage`].
#[cfg(test)]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(min_version = "V2")]
pub(crate) struct RecentNote {
	/// The text the note carries.
	pub(crate) content: String,
}

#[cfg(all(feature = "secp256k1", feature = "signature"))]
mod signing {
	pub use k256::ecdsa::SigningKey;
}

#[cfg(all(feature = "secp256k1", feature = "signature"))]
use signing::*;

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
mod cert {
	pub use crate::crypto::key::Secp256k1KeyProvider;
	pub use crate::crypto::sign::ecdsa::Secp256k1Signature;
	pub use crate::crypto::sign::{CanonicalSigner, CertifiedKey, SignatureEncoding, SigningIdentity};
	pub use crate::crypto::x509::utils::Skid;
	pub use crate::crypto::x509::CurvePoints;
	pub use crate::der::asn1::{BitString, Ia5String, PrintableString, SetOfVec, UtcTime};
	pub use crate::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::{Any, Decode, Encode};
	pub use crate::error::Result as TbResult;
	pub use crate::oids::{CURVE_NIST_P256, SIGNER_ECDSA_WITH_SHA3_256};
	pub use crate::spki::SubjectPublicKeyInfoOwned;
	pub use crate::x509::attr::AttributeTypeAndValue;
	pub use crate::x509::ext::pkix::name::GeneralName;
	pub use crate::x509::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
	pub use crate::x509::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
	pub use crate::x509::ext::Extension;
	pub use crate::x509::name::{RdnSequence, RelativeDistinguishedName};
	pub use crate::x509::serial_number::SerialNumber;
	pub use crate::x509::time::{Time, Validity};
	pub use crate::x509::{TbsCertificate, Version as X509Version};
	pub use core::time::Duration;
	pub use elliptic_curve::bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
	pub use elliptic_curve::bigint::{Encoding, U256};
	pub use k256::elliptic_curve::sec1::ToEncodedPoint;
	pub use k256::PublicKey;
}

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
use cert::*;

#[cfg(feature = "colony")]
mod rumor {
	pub use crate::builder::{FrameBuilder, TypeBuilder};
	pub use crate::colony::cluster::VerifiedRumor;
	pub use crate::colony::protocol::GossipRumor;
}

#[cfg(feature = "colony")]
use rumor::*;

#[cfg(feature = "instrument")]
mod instrumented {
	pub use crate::instrumentation::TbInstrumentationConfig;
	pub use crate::trace::TraceConfig;
	pub use crate::urn::Urn;
}

#[cfg(feature = "instrument")]
use instrumented::*;

#[cfg(all(test, feature = "testing-csp"))]
mod csp {
	pub use crate::testing::specs::csp::{Event, Process, ProcessBuilder, State};
	#[cfg(feature = "testing-timing")]
	pub use crate::testing::timing::{TimingConstraint, TimingConstraints, WcetConfig};
}

#[cfg(all(test, feature = "testing-csp"))]
use csp::*;

/// The fixed test validity window, from the epoch through
/// [`TestCertificate::END_OF_VALIDITY`], both as UtcTime.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_validity() -> TbResult<Validity> {
	let not_before = Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(0))?);
	let not_after = Duration::from_secs(TestCertificate::END_OF_VALIDITY);
	let not_after = Time::UtcTime(UtcTime::from_unix_duration(not_after)?);
	let validity = Validity { not_before, not_after };
	Ok(validity)
}

/// Returns the ECDSA-with-SHA3-256 algorithm identifier that the test
/// certificate fixtures use.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_signature_algorithm() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
}

/// Builds the shared body of the URI-SAN fixtures. `name` is both the subject
/// and the issuer (a self-signed shape), and each of `uris` becomes a SAN
/// entry.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_named_with_uri_sans(signing_key: &SigningKey, name: RdnSequence, uris: &[&str]) -> Certificate {
	test_certificate_named(signing_key, name, Some(vec![test_uri_san_extension(uris)]))
}

/// Builds the Subject Alternative Name extension that carries each of `uris`
/// as a URI entry (RFC 5280 §4.2.1.6).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_uri_san_extension(uris: &[&str]) -> Extension {
	let names = uris
		.iter()
		.map(|uri| {
			let uri = Ia5String::new(uri).expect("test URIs are IA5 text");
			GeneralName::UniformResourceIdentifier(uri)
		})
		.collect();

	test_extension(&SubjectAltName(names))
}

/// The SubjectPublicKeyInfo of `key`'s public half.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_public_key(key: &SigningKey) -> SubjectPublicKeyInfoOwned {
	SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).expect("a test key encodes to an SPKI")
}

/// The key identifier extensions of a certificate for `subject_key` that
/// `issuer_key` signs, by RFC 7093 §2 method 1.
///
/// The `subjectKeyIdentifier` is always present (RFC 5280 §4.2.1.2). The
/// `authorityKeyIdentifier` names the issuer's key when another key signs
/// (RFC 5280 §4.2.1.1). Both are non-critical.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_key_identifiers(subject_key: &SigningKey, issuer_key: &SigningKey) -> Vec<Extension> {
	let subject_identifier = Skid::of_public_key(&test_public_key(subject_key));
	let subject_key_identifier =
		SubjectKeyIdentifier::try_from(subject_identifier).expect("a 20-byte identifier wraps in an OctetString");

	let mut extensions = vec![test_noncritical_extension(&subject_key_identifier)];
	if subject_key.verifying_key() == issuer_key.verifying_key() {
		return extensions;
	}

	let issuer_identifier = Skid::of_public_key(&test_public_key(issuer_key));
	let key_identifier = OctetString::new(issuer_identifier.as_bytes().as_slice())
		.expect("a 20-byte identifier wraps in an OctetString");
	let authority = AuthorityKeyIdentifier {
		key_identifier: Some(key_identifier),
		authority_cert_issuer: None,
		authority_cert_serial_number: None,
	};

	extensions.push(test_noncritical_extension(&authority));
	extensions
}

/// The `keyUsage` of an end-entity test certificate: `digitalSignature` and
/// `keyAgreement`, so a verifier admits the certificate for each use (RFC 5280
/// §4.2.1.3, RFC 5480 §3).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_end_entity_key_usage() -> Extension {
	test_extension(&KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement))
}

/// Builds a certificate for `subject_key` under `subject`, signed by
/// `issuer_key` under `issuer`, with a real signature and `serial` as its
/// serial number.
///
/// The key identifier extensions come ahead of `extensions`.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn issue_test_certificate(
	issuer_key: &SigningKey,
	issuer: RdnSequence,
	subject_key: &SigningKey,
	subject: RdnSequence,
	serial: u8,
	extensions: Vec<Extension>,
) -> TbResult<Certificate> {
	let subject_public_key_info = test_public_key(subject_key);
	let algorithm = test_signature_algorithm();
	let mut all_extensions = test_key_identifiers(subject_key, issuer_key);
	all_extensions.extend(extensions);

	let tbs = TbsCertificate {
		version: X509Version::V3,
		serial_number: SerialNumber::new(&[serial])?,
		signature: algorithm.to_owned(),
		issuer,
		validity: test_validity()?,
		subject,
		subject_public_key_info,
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: Some(all_extensions),
	};

	sign_test_certificate(tbs, &algorithm, issuer_key)
}

/// Builds the shared body of the self-signed test certificate fixtures, with
/// an empty subject and issuer, a fixed serial, and caller-chosen extensions.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_with_extensions(signing_key: &SigningKey, extensions: Option<Vec<Extension>>) -> Certificate {
	test_certificate_named(signing_key, RdnSequence::default(), extensions)
}

/// Builds a test certificate that `signing_key` signs, with `name` as both
/// the subject and the issuer, a fixed serial, its key identifier, the
/// end-entity `keyUsage`, and caller-chosen extensions after them.
///
/// Its own key verifies its signature, so it is self-signed
/// (RFC 5280 §3.2), and its own key identifier names its authority
/// (RFC 5280 §4.2.1.1).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_named(
	signing_key: &SigningKey,
	name: RdnSequence,
	extensions: Option<Vec<Extension>>,
) -> Certificate {
	let subject_public_key_info = test_public_key(signing_key);
	let mut all_extensions = test_key_identifiers(signing_key, signing_key);
	all_extensions.push(test_end_entity_key_usage());
	all_extensions.extend(extensions.into_iter().flatten());

	let algorithm = test_signature_algorithm();
	let validity = test_validity().expect("fixed test validity window is valid");
	let serial_number = SerialNumber::new(&[1]).expect("single-byte serial is valid");

	let tbs_certificate = TbsCertificate {
		version: X509Version::V3,
		serial_number,
		signature: algorithm.to_owned(),
		issuer: name.to_owned(),
		validity,
		subject: name,
		subject_public_key_info,
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: Some(all_extensions),
	};

	let signed = sign_test_certificate(tbs_certificate, &algorithm, signing_key);
	signed.expect("the test key signs the certificate")
}

/// Wraps a DER-encodable extension value in a critical `Extension` (RFC 5280
/// §4.2).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_extension<T>(value: &T) -> Extension
where
	T: AssociatedOid + Encode,
{
	let extn_value = OctetString::new(value.to_der().expect("extension value encodes to DER"))
		.expect("DER bytes wrap in an OctetString");
	Extension { extn_id: T::OID, critical: true, extn_value }
}

/// Wraps a DER-encodable extension value in a non-critical `Extension`, the
/// form RFC 5280 §4.2.1.1 and §4.2.1.2 give a key identifier.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_noncritical_extension<T>(value: &T) -> Extension
where
	T: AssociatedOid + Encode,
{
	let extn_value = OctetString::new(value.to_der().expect("extension value encodes to DER"))
		.expect("DER bytes wrap in an OctetString");
	Extension { extn_id: T::OID, critical: false, extn_value }
}

/// A certificate chain in which a root signs an intermediate and the
/// intermediate signs a leaf.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub struct TestCertificateChain {
	/// The self-signed root, a certificate authority that signs the
	/// intermediate.
	pub root: Certificate,
	/// The intermediate certificate authority, which the root signs.
	pub intermediate: Certificate,
	/// The end-entity certificate, which the intermediate signs.
	pub leaf: Certificate,
	/// The key of [`Self::root`], which signs the root and the intermediate.
	pub root_key: SigningKey,
	/// The key of [`Self::intermediate`], which signs the leaf.
	pub intermediate_key: SigningKey,
	/// The key of [`Self::leaf`].
	pub leaf_key: SigningKey,
}

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl TestCertificateChain {
	/// Returns the chain as a shared `[root, intermediate, leaf]` slice for the
	/// handshake.
	pub fn to_arc(&self) -> Arc<[Certificate]> {
		Arc::from([self.root.to_owned(), self.intermediate.to_owned(), self.leaf.to_owned()])
	}
}

/// Builds the single-AVA `CN=<cn>` distinguished name for test certificates.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_cn_name(cn: impl AsRef<str>) -> TbResult<RdnSequence> {
	let cn = cn.as_ref();
	let cn_oid = ObjectIdentifier::new_unwrap("2.5.4.3");
	let cn_str = PrintableString::new(cn)?;
	let attr = AttributeTypeAndValue { oid: cn_oid, value: Any::from(&cn_str) };
	let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![attr])?);

	let name = RdnSequence::from(vec![rdn]);
	Ok(name)
}

/// Signs `tbs` with `key` under the test ECDSA-SHA3-256 algorithm.
///
/// The `signatureValue` is the DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn sign_test_certificate(
	tbs: TbsCertificate,
	algorithm: &AlgorithmIdentifierOwned,
	key: &SigningKey,
) -> TbResult<Certificate> {
	let tbs_der = tbs.to_der()?;
	let signature: Secp256k1Signature = key.sign_canonical::<Sha3_256>(&tbs_der)?;

	let certificate = Certificate {
		tbs_certificate: tbs,
		signature_algorithm: algorithm.to_owned(),
		signature: BitString::new(0, signature.to_vec())?,
	};
	Ok(certificate)
}

/// Generates a `#[test]` function that checks one builder.
///
/// The test builds a `builder_type` from `version`, runs `setup` on it with
/// the message, and passes a copy of the message and the result of `setup` to
/// `assertions`.
///
/// The `message` parameter supports two forms:
///
/// - A direct value: `message: TestMessage::sample(None)`
/// - A closure: `message: || { TestMessage::sample(None) }`
#[macro_export]
macro_rules! test_builder {
	// The closure form is `message: || { ... }`.
	(
		name: $test_name:ident,
		builder_type: $builder_type:ty,
		version: $version:expr,
		message: || $message_body:expr,
		setup: |$builder:ident, $msg:ident| $setup_body:expr,
		assertions: |$msg_result:ident, $frame_result:ident| $assertions_body:expr
	) => {
		$crate::test_builder!(@impl
			$test_name,
			$builder_type,
			$version,
			{ $message_body },
			|$builder, $msg| $setup_body,
			|$msg_result, $frame_result| $assertions_body
		);
	};

	// The direct value form is `message: some_value`.
	(
		name: $test_name:ident,
		builder_type: $builder_type:ty,
		version: $version:expr,
		message: $message:expr,
		setup: |$builder:ident, $msg:ident| $setup_body:expr,
		assertions: |$msg_result:ident, $frame_result:ident| $assertions_body:expr
	) => {
		$crate::test_builder!(@impl
			$test_name,
			$builder_type,
			$version,
			$message,
			|$builder, $msg| $setup_body,
			|$msg_result, $frame_result| $assertions_body
		);
	};

	// The two public forms expand into this internal arm.
	(@impl
		$test_name:ident,
		$builder_type:ty,
		$version:expr,
		$message:expr,
		|$builder:ident, $msg:ident| $setup_body:expr,
		|$msg_result:ident, $frame_result:ident| $assertions_body:expr
	) => {
		#[test]
		fn $test_name() -> $crate::error::Result<()> {
			let $msg = $message;
			let msg_clone = $msg.to_owned();
			let $builder: $builder_type = <$builder_type>::from($version);
			let $frame_result = $setup_body;
			let $msg_result = msg_clone;
			$assertions_body
		}
	};
}

/// Matches a [`Frame`] against an expected value in one of these forms:
///
/// - A `Frame` or an `Arc<Frame>` compares `metadata.id`.
/// - A `Result<Frame, E>` compares `metadata.id` of the `Ok` frame, and an `Err` matches no frame.
/// - Any `T: Message + PartialEq` decodes `T` through [`Frame::decode_message`],
///   which holds a frame whose body arrived in cleartext to the requirements
///   of `T`, and compares. A refused or failed decode matches no frame.
///
/// A scenario grades a match through [`Self::record_match`], and its spec
/// asserts the recorded value with `equals!(true)`.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::{ExpectedMatcher, TestFrame, TestMessage};
///
/// let frame = TestFrame::v0(Some("carried"), None);
///
/// assert!(TestMessage::sample(Some("carried")).matches(&frame));
/// assert!(!TestMessage::sample(Some("other")).matches(&frame));
/// ```
pub trait ExpectedMatcher {
	/// Whether `frame` carries this expected value.
	fn matches(&self, frame: &Frame) -> bool;

	/// Records `label` on `trace`, with the outcome of [`Self::matches`] for
	/// `frame` as its value.
	///
	/// The spec of a scenario asserts the value with `equals!(true)`, so a
	/// frame that does not carry the expected value fails the assertion layer.
	///
	/// # Errors
	///
	/// - The injected error, when the fault model of `trace` injects a fault at `label`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::{ExpectedMatcher, TestFrame, TestMessage};
	/// use tightbeam::trace::{AssertionValue, ConsumedTrace, TraceCollector};
	///
	/// const REPLY: tightbeam::urn::Urn<'static> = tightbeam::urn!("doc", "event:reply/expected");
	///
	/// let trace = TraceCollector::new();
	/// let reply = TestFrame::v0(Some("pong"), None);
	/// TestMessage::sample(Some("pong")).record_match(&trace, REPLY, &reply)?;
	///
	/// let mut consumed = ConsumedTrace::new();
	/// consumed.populate_from_collector(&trace);
	/// let values: Vec<_> = consumed.assertions().iter().map(|assertion| assertion.value.clone()).collect();
	/// assert_eq!(values, [Some(AssertionValue::Bool(true))]);
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	fn record_match(
		&self,
		trace: &TraceCollector,
		label: impl IntoEventLabel,
		frame: &Frame,
	) -> Result<(), TightBeamError>
	where
		Self: Sized,
	{
		let matched = self.matches(frame);
		trace.event_with(label, &[], matched)?.emit();
		Ok(())
	}
}

impl ExpectedMatcher for Frame {
	fn matches(&self, frame: &Frame) -> bool {
		frame.metadata().id() == self.metadata().id()
	}
}

impl ExpectedMatcher for Arc<Frame> {
	fn matches(&self, frame: &Frame) -> bool {
		self.metadata().id() == frame.metadata().id()
	}
}

impl<E> ExpectedMatcher for Result<Frame, E> {
	fn matches(&self, frame: &Frame) -> bool {
		match self {
			Ok(f) => frame.metadata().id() == f.metadata().id(),
			Err(_) => false,
		}
	}
}

impl<T> ExpectedMatcher for T
where
	T: Message + PartialEq,
{
	fn matches(&self, frame: &Frame) -> bool {
		let decoded = frame.decode_message::<T>();
		decoded.is_ok_and(|decoded| decoded == *self)
	}
}

/// Generates an async test that runs its assertions against a live worker.
///
/// The test starts a worker from the value that `setup` returns, passes it to
/// the assertions block, and shuts the worker down afterwards.
#[macro_export]
macro_rules! test_worker {
	(
		name: $test_name:ident,
		setup: || $setup_body:expr,
		assertions: |$worker:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			use $crate::colony::worker::Worker;

			let builder = $setup_body;
			let trace = std::sync::Arc::new($crate::trace::TraceCollector::new());
			let mut worker = <_ as $crate::colony::worker::Worker>::start(builder, trace).await?;

			let result = {
				let $worker = &mut worker;
				$assertions_body.await
			};

			// The shutdown runs before the result returns, so a failed
			// assertion stops the worker too.
			worker.kill().await?;

			result
		}
	};
}

/// The frames in the shapes that the suite sends.
pub struct TestFrame;

impl TestFrame {
	/// The order that the fixed frames of the tests carry:
	/// 2023-10-05T16:00:00Z in Unix seconds.
	pub(crate) const ORDER: u64 = 1_696_521_600;

	/// The message of `frame`, opened with `decryptor` and decoded as `T`.
	///
	/// `inflator` inflates a compressed body. [`rt::block_on`] drives the open,
	/// so a synchronous test reads it on any thread.
	///
	/// # Errors
	///
	/// - The errors of [`Frame::decrypt`].
	#[cfg(feature = "aead")]
	pub fn decrypted<T: Message>(
		frame: Frame,
		decryptor: &(impl crate::crypto::aead::Decryptor + ?Sized),
		inflator: Option<&(dyn crate::core::Inflator + Sync)>,
	) -> crate::error::Result<T> {
		let opened = frame.decrypt::<T>(decryptor, inflator);
		rt::block_on(opened)
	}

	/// A V0 frame of [`TestMessage::sample`] with `content`, under `id` or
	/// `test-message-id`, at the fixed order of the test frames.
	pub fn v0(content: Option<&str>, id: Option<&str>) -> Frame {
		let message = TestMessage::sample(content);
		let id = id.unwrap_or("test-message-id");

		let result = compose! {
			V0: id: id.as_bytes(),
				order: Self::ORDER,
				message: message
		};

		result.expect("Failed to create TightBeam message")
	}

	/// A V1 frame of [`TestMessage::sample`] with `content`, under `id` or
	/// `test-message-id`, at [`Self::ORDER`].
	#[cfg(test)]
	pub(crate) fn v1(content: Option<&str>, id: Option<&str>) -> Frame {
		let message = TestMessage::sample(content);
		let id = id.unwrap_or("test-message-id");
		let built = compose! { V1: id: id, order: Self::ORDER, message: message };
		built.expect("a V1 frame of a sample message builds")
	}

	/// A V1 frame of [`TestMessage::sample`] under `id` at [`Self::ORDER`],
	/// sealed to [`TestKey::insecure_fixed_cipher`].
	#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub(crate) fn sealed(id: impl AsRef<[u8]>) -> Frame {
		TestFrame::sealed_with(TestMessage::sample(None), id)
	}

	/// A V1 frame of `message` under `id` at [`Self::ORDER`], sealed to
	/// [`TestKey::insecure_fixed_cipher`].
	#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub(crate) fn sealed_with<T>(message: T, id: impl AsRef<[u8]>) -> Frame
	where
		T: Message + crate::builder::CheckAeadOid<crate::crypto::aead::Aes256GcmOid>,
	{
		use crate::builder::{FrameBuilder, TypeBuilder};
		use crate::testing::SeededStream;

		let (_, cipher) = TestKey::insecure_fixed_cipher();
		let builder = FrameBuilder::<T>::from(Version::V1).with_message(message).with_id(id);
		let builder = builder.with_order(Self::ORDER).with_encryptor(cipher).with_rng(SeededStream(0));

		let built = builder.build();
		built.expect("a V1 frame seals to the fixed test cipher")
	}

	/// A frame of `version` of [`TestMessage::sample`] under `id` at
	/// [`Self::ORDER`], sealed to [`TestKey::insecure_fixed_cipher`] and
	/// signed by the [`TestIdentity::certified`] key of
	/// [`TestKey::insecure_fixed_signing`].
	#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub(crate) fn sealed_signed(version: Version, id: impl AsRef<[u8]>) -> Frame {
		use crate::builder::{FrameBuilder, TypeBuilder};
		use crate::testing::SeededStream;

		let (_, cipher) = TestKey::insecure_fixed_cipher();
		let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let builder = FrameBuilder::from(version).with_message(TestMessage::sample(None)).with_id(id);
		let builder = builder.with_order(Self::ORDER).with_encryptor(cipher).with_rng(SeededStream(0));

		let built = builder.with_signer::<Secp256k1Signature, _>(signer).build();
		built.expect("the frame version carries a seal and a signature")
	}

	/// Builds a V1 frame that carries a SHA3-256 frame integrity (FI) digest.
	#[cfg(all(feature = "builder", feature = "digest", feature = "sha3"))]
	pub fn with_integrity() -> Frame {
		let message = TestMessage::sample(None);
		compose! {
			V1: id: "fi-frame",
				order: 1u64,
				message: message,
				frame_integrity: type Sha3_256
		}
		.expect("Failed to create frame with frame integrity")
	}

	/// Builds a V2 frame that carries a priority, which V0 and V1 forbid.
	#[cfg(feature = "builder")]
	pub fn prioritized() -> Frame {
		let message = TestMessage::sample(None);
		compose! {
			V2: id: "prioritized",
				order: 1u64,
				message: message,
				priority: crate::MessagePriority::Standard
		}
		.expect("a V2 frame carries a priority")
	}

	/// Returns `frame` decoded again after the first copy of `original` in its
	/// DER becomes `forged`.
	///
	/// A test models a tamper in transit this way, because the frame API holds
	/// each digested or signed field fixed. The two byte strings MUST have one
	/// length, so every DER length octet stays valid.
	pub fn tamper(frame: &Frame, original: impl AsRef<[u8]>, forged: impl AsRef<[u8]>) -> Frame {
		let original = original.as_ref();
		let forged = forged.as_ref();
		assert_eq!(original.len(), forged.len(), "a tamper keeps the DER lengths");

		let mut encoded = crate::der::Encode::to_der(frame).expect("the frame encodes");
		let start = encoded
			.windows(original.len())
			.position(|window| window == original)
			.expect("the frame DER holds the original bytes");

		encoded[start..start + forged.len()].copy_from_slice(forged);

		crate::der::Decode::from_der(&encoded).expect("a same-length rewrite still decodes")
	}

	/// Returns `frame` with its signature's `s` flipped to `n - s`.
	///
	/// ECDSA verifies both values (SEC 1 v2.0 §4.1.4), so a test models a
	/// relay that rewrites a captured signature this way. The flipped
	/// `SignerInfo` enters through the DER decoder, as a received one would.
	#[cfg(all(feature = "secp256k1", feature = "signature"))]
	pub fn with_flipped_s(frame: &Frame) -> Frame {
		use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Signature};
		use crate::crypto::sign::Signed;
		use crate::der::{Decode, Encode};
		use crate::SignerInfo;

		let signed = frame.nonrepudiation().expect("the frame carries a signature");
		let signer_info = signed.as_ref().clone();
		let der = Secp256k1Signature::from_bytes(signer_info.signature.as_bytes()).expect("the signature is DER");
		let scalars = Signature::<Secp256k1>::try_from(der).expect("a DER signature holds two scalars");
		let high = TestKey::high_s_twin(scalars);
		let signature = OctetString::new(high.to_der().as_bytes()).expect("a signature wraps in an OCTET STRING");

		let flipped = SignerInfo { signature, ..signer_info };
		let flipped_der = flipped.to_der().expect("the SignerInfo encodes");
		let decoded = Signed::<SignerInfo>::from_der(&flipped_der).expect("the SignerInfo decodes");

		let mut rewritten = frame.clone();
		rewritten
			.attach_signer_info(decoded)
			.expect("the frame version carries a signature");
		rewritten
	}

	/// `frame` signed by `identity`.
	///
	/// `rt::block_on` drives the signature, so a synchronous test reads it on
	/// any thread.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn signed_by(mut frame: Frame, identity: &SigningIdentity) -> Frame {
		let signing = frame.sign_with_provider(identity);
		crate::runtime::rt::block_on(signing).expect("the frame version carries a signature");
		frame
	}

	/// Returns the DER of `container` with the version of its embedded `frame`
	/// rewritten to `version`.
	///
	/// Every constructor yields a frame whose version admits each field it
	/// carries, so a test that feeds a decoder a version that forbids one of
	/// those fields forges the bytes here.
	pub fn forge_version(container: &impl crate::der::Encode, frame: &Frame, version: Version) -> Vec<u8> {
		let mut encoded = crate::der::Encode::to_der(container).expect("the container encodes");
		let frame_der = crate::der::Encode::to_der(frame).expect("the frame encodes");

		let start = encoded
			.windows(frame_der.len())
			.position(|window| window == frame_der.as_slice())
			.expect("the container embeds the frame DER");

		// A frame opens with its SEQUENCE header, then the `ENUMERATED` tag and
		// length octets of its version.
		let length_octets = match frame_der[1] {
			short if short < 0x80 => 1,
			long => 1 + usize::from(long & 0x7F),
		};

		let version_offset = start + 1 + length_octets + 2;
		encoded[version_offset] = version as u8;
		encoded
	}
}

/// The decoder of NIST P-256 that a test reads a P-256 key under: the range
/// and curve checks of SEC 1 v2.0 §2.3.4 over the field arithmetic of
/// `crypto-bigint`.
///
/// The tree holds the curve arithmetic of secp256k1 alone, so the decoder
/// solves the curve equation y² = x³ - 3x + b of SEC 2 v2.0 §2.4.2 itself. It
/// runs in variable time, which suits a public key alone.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct TestP256Points;

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl TestP256Points {
	/// The prime p of the field of P-256 (SEC 2 v2.0 §2.4.2).
	const PRIME: U256 = U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

	/// The coefficient b of P-256, whose coefficient a is -3.
	const B: U256 = U256::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

	/// The exponent (p + 1) / 4. The prime is 3 modulo 4, so a square α has
	/// the square root α to this power.
	const ROOT: U256 = Self::PRIME.wrapping_add(&U256::ONE).shr_vartime(2);

	/// The Montgomery parameters of the field.
	const FIELD: DynResidueParams<{ U256::LIMBS }> = DynResidueParams::new(&Self::PRIME);

	/// `octets` as an element of the field, or `None` when they are not a
	/// 32-octet integer below p (SEC 1 v2.0 §2.3.6).
	fn element(octets: &[u8]) -> Option<DynResidue<{ U256::LIMBS }>> {
		let octets: [u8; 32] = octets.try_into().ok()?;
		let integer = U256::from_be_bytes(octets);
		(integer < Self::PRIME).then(|| DynResidue::new(&integer, Self::FIELD))
	}

	/// x³ - 3x + b, the square of the y-coordinate of each point whose
	/// x-coordinate is `x`.
	fn right_side(x: &DynResidue<{ U256::LIMBS }>) -> DynResidue<{ U256::LIMBS }> {
		let three = DynResidue::new(&U256::from_u8(3), Self::FIELD);
		let b = DynResidue::new(&Self::B, Self::FIELD);
		x.square().mul(x).sub(&three.mul(x)).add(&b)
	}
}

/// A compressed point is a point when its x-coordinate gives a square, and
/// an uncompressed one when its two coordinates solve the curve equation.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl CurvePoints for TestP256Points {
	fn curve(&self) -> ObjectIdentifier {
		CURVE_NIST_P256
	}

	fn decodes(&self, point: &[u8]) -> bool {
		let Some((form, coordinates)) = point.split_first() else {
			return false;
		};

		match form {
			0x02 | 0x03 => Self::element(coordinates).is_some_and(|x| {
				let square = Self::right_side(&x);
				square.pow(&Self::ROOT).square() == square
			}),
			0x04 => coordinates.split_at_checked(32).is_some_and(|(x, y)| {
				let coordinates = Self::element(x).zip(Self::element(y));
				coordinates.is_some_and(|(x, y)| y.square() == Self::right_side(&x))
			}),
			_ => false,
		}
	}
}

/// The signing and cipher keys with fixed, test-only material.
pub struct TestKey;

impl TestKey {
	/// The P-256 public key of RFC 6979 §A.2.5 in the uncompressed SEC 1 form:
	/// `0x04`, the x-coordinate, then the y-coordinate.
	pub const RFC6979_P256_UNCOMPRESSED: [u8; 65] = [
		0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0,
		0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe,
		0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d,
		0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
	];

	/// The P-256 public key of RFC 6979 §A.2.5 in the compressed SEC 1 form,
	/// whose first octet `0x03` names its odd y.
	pub const RFC6979_P256_COMPRESSED: [u8; 33] = [
		0x03, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0,
		0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
	];

	/// The P-521 public key of RFC 6979 §A.2.7 in the uncompressed SEC 1 form:
	/// `0x04`, then Ux and Uy of 66 octets each, as the RFC prints them.
	pub const RFC6979_P521_UNCOMPRESSED: [u8; 133] = [
		0x04, 0x01, 0x89, 0x45, 0x50, 0xd0, 0x78, 0x59, 0x32, 0xe0, 0x0e, 0xaa, 0x23, 0xb6, 0x94, 0xf2, 0x13, 0xf8,
		0xc3, 0x12, 0x1f, 0x86, 0xdc, 0x97, 0xa0, 0x4e, 0x5a, 0x71, 0x67, 0xdb, 0x4e, 0x5b, 0xcd, 0x37, 0x11, 0x23,
		0xd4, 0x6e, 0x45, 0xdb, 0x6b, 0x5d, 0x53, 0x70, 0xa7, 0xf2, 0x0f, 0xb6, 0x33, 0x15, 0x5d, 0x38, 0xff, 0xa1,
		0x6d, 0x2b, 0xd7, 0x61, 0xdc, 0xac, 0x47, 0x4b, 0x9a, 0x2f, 0x50, 0x23, 0xa4, 0x00, 0x49, 0x31, 0x01, 0xc9,
		0x62, 0xcd, 0x4d, 0x2f, 0xdd, 0xf7, 0x82, 0x28, 0x5e, 0x64, 0x58, 0x41, 0x39, 0xc2, 0xf9, 0x1b, 0x47, 0xf8,
		0x7f, 0xf8, 0x23, 0x54, 0xd6, 0x63, 0x0f, 0x74, 0x6a, 0x28, 0xa0, 0xdb, 0x25, 0x74, 0x1b, 0x5b, 0x34, 0xa8,
		0x28, 0x00, 0x8b, 0x22, 0xac, 0xc2, 0x3f, 0x92, 0x4f, 0xaa, 0xfb, 0xd4, 0xd3, 0x3f, 0x81, 0xea, 0x66, 0x95,
		0x6d, 0xfe, 0xaa, 0x2b, 0xfd, 0xfc, 0xf5,
	];

	/// The P-521 public key of RFC 6979 §A.2.7 in the compressed SEC 1 form,
	/// whose first octet `0x03` names the odd Uy the RFC prints.
	pub const RFC6979_P521_COMPRESSED: [u8; 67] = [
		0x03, 0x01, 0x89, 0x45, 0x50, 0xd0, 0x78, 0x59, 0x32, 0xe0, 0x0e, 0xaa, 0x23, 0xb6, 0x94, 0xf2, 0x13, 0xf8,
		0xc3, 0x12, 0x1f, 0x86, 0xdc, 0x97, 0xa0, 0x4e, 0x5a, 0x71, 0x67, 0xdb, 0x4e, 0x5b, 0xcd, 0x37, 0x11, 0x23,
		0xd4, 0x6e, 0x45, 0xdb, 0x6b, 0x5d, 0x53, 0x70, 0xa7, 0xf2, 0x0f, 0xb6, 0x33, 0x15, 0x5d, 0x38, 0xff, 0xa1,
		0x6d, 0x2b, 0xd7, 0x61, 0xdc, 0xac, 0x47, 0x4b, 0x9a, 0x2f, 0x50, 0x23, 0xa4,
	];

	/// The generator of secp256k1 in the compressed SEC 1 form, as SEC 2 v2.0
	/// §2.4.1 publishes it.
	pub const SEC2_SECP256K1_G_COMPRESSED: [u8; 33] = [
		0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
		0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	];

	/// The generator of secp256k1 in the uncompressed SEC 1 form, as SEC 2
	/// v2.0 §2.4.1 publishes it.
	pub const SEC2_SECP256K1_G_UNCOMPRESSED: [u8; 65] = [
		0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
		0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda,
		0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6,
		0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
	];

	/// The secp256k1 signing key whose secret scalar is thirty-two `seed`
	/// octets.
	///
	/// # Panics
	///
	/// - `seed` is `0x00` or `0xff`, whose octets name no scalar below the group order.
	#[cfg(all(feature = "secp256k1", feature = "signature"))]
	pub(crate) fn fixed(seed: u8) -> SigningKey {
		let scalar = SigningKey::from_bytes(&[seed; 32].into());
		scalar.expect("a seed from 0x01 to 0xfe names a scalar")
	}

	/// Returns the secp256k1 signing key whose secret scalar is thirty-two
	/// `0x01` bytes.
	///
	/// # Security
	///
	/// The scalar is public, so every signature it makes is forgeable by
	/// anyone who reads this file. Production code builds its key with
	/// [`SigningKey::random`](crate::SigningKey::random) from a CSPRNG.
	#[cfg(all(feature = "secp256k1", feature = "signature"))]
	pub fn insecure_fixed_signing() -> SigningKey {
		TestKey::fixed(0x01)
	}

	/// The signing key whose public point is the negation of the point of
	/// `key`, so the two points share an x-coordinate and differ in y.
	#[cfg(all(feature = "secp256k1", feature = "signature"))]
	pub fn negation_of(key: &SigningKey) -> SigningKey {
		let negated = -*key.as_nonzero_scalar();
		SigningKey::from(negated)
	}

	/// The house key provider of `key`, shared.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn provider(key: impl Into<Secp256k1KeyProvider>) -> Arc<Secp256k1KeyProvider> {
		Arc::new(key.into())
	}

	/// The `(r, n - s)` twin of `signature`. ECDSA verifies both (SEC 1 v2.0
	/// §4.1.4), and the twin of a low-s signature is high-s.
	#[cfg(all(feature = "secp256k1", feature = "signature"))]
	pub(crate) fn high_s_twin(
		signature: crate::crypto::sign::ecdsa::Signature<crate::crypto::sign::ecdsa::Secp256k1>,
	) -> crate::crypto::sign::ecdsa::Signature<crate::crypto::sign::ecdsa::Secp256k1> {
		let (r, s) = signature.split_scalars();
		let twin = crate::crypto::sign::ecdsa::Signature::from_scalars(r, -s);
		twin.expect("n - s is a scalar")
	}

	/// Content whose raw `s` under [`Self::insecure_fixed_signing`] lies in
	/// the high half, so a signer that skips the low-s rule fails a test that
	/// signs it.
	#[cfg(test)]
	pub(crate) const HIGH_S_CONTENT: &[u8] = b"cms signer content";

	/// The RFC 7093 §2 method 1 key identifier of the public key of
	/// [`Self::insecure_fixed_signing`]: the leftmost 160 bits of SHA-256 of
	/// the uncompressed point `04 1b84c556..dd078f 70beaf8f..69a8e8d1`. An
	/// independent computation (Python's `hashlib`) gave this value.
	pub const INSECURE_FIXED_KEY_IDENTIFIER: [u8; 20] = [
		0xc0, 0xc5, 0xe0, 0xd9, 0x27, 0xe4, 0xcc, 0xbb, 0x5b, 0xbf, 0x03, 0xd5, 0x0d, 0xae, 0x76, 0xa7, 0x91, 0x14,
		0xa2, 0x96,
	];

	/// Returns record keys of epoch 0 under the house provider, from the
	/// key-encryption keys made of thirty-two `0x00` bytes (client to server)
	/// and thirty-two `0x01` bytes (server to client).
	///
	/// # Security
	///
	/// The keys are public, so no record sealed under them is confidential.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub fn insecure_directional_keys() -> DirectionalCiphers<RuntimeAead> {
		let key = |fill: u8| RuntimeAead::new::<DefaultCryptoProvider>(vec![fill; 32]);
		let client_to_server = key(0x00).expect("32 octets is the key of AES-256 key wrap");
		let server_to_client = key(0x01).expect("32 octets is the key of AES-256 key wrap");
		DirectionalCiphers { client_to_server, server_to_client, epoch: 0 }
	}

	/// Returns the key-encryption key made of thirty-two `0x33` bytes, with
	/// the in-memory key that holds it under the house provider and names it
	/// `tb/test/kek/v1`. A frame sealed to it carries AES-256-GCM content with
	/// its content key wrapped under AES-256 key wrap.
	///
	/// # Security
	///
	/// The key is public, so nothing sealed under it is confidential.
	/// Production code draws its key from a CSPRNG.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub fn insecure_fixed_cipher() -> ([u8; 32], Aes256GcmKeyProvider) {
		let key_bytes = [0x33; 32];
		let cipher = Aes256GcmKeyProvider::new(key_bytes.to_vec(), b"tb/test/kek/v1".to_vec());
		let cipher = cipher.expect("32 octets is the key of AES-256 key wrap");
		(key_bytes, cipher)
	}
}

/// The certificates and chains in the shapes that the trust stores accept or
/// refuse.
pub struct TestCertificate;

impl TestCertificate {
	/// Builds an end-entity certificate of `signing_key` with an empty subject
	/// and issuer. `signing_key` signs it, so its own key verifies its
	/// signature (RFC 5280 §3.2).
	///
	/// It carries its own key identifier and no `authorityKeyIdentifier`,
	/// which a self-signed certificate may omit (RFC 5280 §4.2.1.1).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::policy::{Secp256k1Policy, VerificationPolicy};
	/// use tightbeam::der::Encode;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let tbs = &certificate.tbs_certificate;
	/// let key = tbs.subject_public_key_info.to_der()?;
	/// let message = tbs.to_der()?;
	/// let signature = certificate.signature.raw_bytes();
	///
	/// let algorithm = &certificate.signature_algorithm.oid;
	/// Secp256k1Policy::default().verify_signature(algorithm, &key, &message, signature)?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn self_signed(signing_key: &SigningKey) -> Certificate {
		test_certificate_with_extensions(signing_key, None)
	}

	/// The [`Self::self_signed`] certificate of
	/// [`TestKey::insecure_fixed_signing`].
	///
	/// # Security
	///
	/// The key is public, so every signature it makes is forgeable.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn insecure_fixed() -> Certificate {
		TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
	}

	/// The [`Self::self_signed`] certificate of the negation of
	/// [`TestKey::insecure_fixed_signing`], whose point shares the
	/// x-coordinate of the point of [`Self::insecure_fixed`].
	///
	/// # Security
	///
	/// The key is public, so every signature it makes is forgeable.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn insecure_fixed_negation() -> Certificate {
		let negation = TestKey::negation_of(&TestKey::insecure_fixed_signing());
		TestCertificate::self_signed(&negation)
	}

	/// Builds a [`Self::self_signed`] variant that carries each of `uris` as a
	/// URI Subject Alternative Name entry (RFC 5280 §4.2.1.6).
	///
	/// The subject stays empty, because identity claims such as colony
	/// membership bind to the SAN, not the subject. With an empty subject the
	/// SAN MUST be critical (RFC 5280 §4.2.1.6), which `test_extension`
	/// provides.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_uri_sans(signing_key: &SigningKey, uris: &[&str]) -> Certificate {
		test_certificate_named_with_uri_sans(signing_key, RdnSequence::default(), uris)
	}

	/// Builds a [`Self::with_uri_sans`] variant with a `CN=<cn>` subject and
	/// issuer, for a test whose certificates each need a name of their own.
	///
	/// [`CertificateTrustStore::evaluate`] states how a store selects the
	/// issuer of a certificate.
	///
	/// [`CertificateTrustStore::evaluate`]: crate::crypto::x509::store::CertificateTrustStore#method.evaluate
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_cn_and_uri_sans(signing_key: &SigningKey, cn: impl AsRef<str>, uris: &[&str]) -> Certificate {
		let cn = cn.as_ref();
		let name = test_cn_name(cn).expect("test common names satisfy PrintableString");
		test_certificate_named_with_uri_sans(signing_key, name, uris)
	}

	/// `certificate` with its `subjectKeyIdentifier` extension value written
	/// as `identifier`, which a method other than the crate's may have derived.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_key_identifier(mut certificate: Certificate, identifier: SubjectKeyIdentifier) -> Certificate {
		let value = identifier.to_der().expect("the identifier encodes");
		let extn_value = OctetString::new(value).expect("the identifier wraps");
		let extensions = certificate.tbs_certificate.extensions.get_or_insert_with(Vec::new);
		extensions.retain(|extension| extension.extn_id != SubjectKeyIdentifier::OID);
		extensions.push(Extension { extn_id: SubjectKeyIdentifier::OID, critical: false, extn_value });

		certificate
	}

	/// `certificate` with `serial` as its serial number, and its subject, its
	/// key, and its extensions unchanged.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn with_serial(mut certificate: Certificate, serial: u8) -> Certificate {
		let serial_number = SerialNumber::new(&[serial]).expect("a one-octet serial number encodes");
		certificate.tbs_certificate.serial_number = serial_number;
		certificate
	}

	/// Builds CA issuer extensions: `basicConstraints` (RFC 5280 §4.2.1.9) and
	/// `keyUsage` (§4.2.1.3), as required for certificate-path validation.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn ca_extensions(ca: bool, key_cert_sign: bool, path_len: Option<u8>) -> Vec<Extension> {
		let basic_constraints = BasicConstraints { ca, path_len_constraint: path_len };
		let usage = if key_cert_sign {
			KeyUsages::KeyCertSign
		} else {
			KeyUsages::DigitalSignature
		};

		let key_usage = KeyUsage(usage.into());
		vec![test_extension(&basic_constraints), test_extension(&key_usage)]
	}

	/// Builds a certificate authority `CN=<cn>` that signs its own certificate
	/// and may sign others (RFC 5280 §4.2.1.9 and §4.2.1.3).
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError`] -- the name, the DER encoding, or the signing fails.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn authority(signing_key: &SigningKey, cn: impl AsRef<str>) -> TbResult<Certificate> {
		let name = test_cn_name(cn)?;
		let extensions = TestCertificate::ca_extensions(true, true, None);
		issue_test_certificate(signing_key, name.to_owned(), signing_key, name, 1, extensions)
	}

	/// Builds a leaf `CN=<cn>` that the authority `CN=<issuer_cn>` signs with
	/// `issuer_key`, with each of `uris` as a URI Subject Alternative Name.
	///
	/// A store that holds the authority alone validates this leaf by its chain,
	/// and it resolves no signer for the leaf's key.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError`] -- a name, the DER encoding, or the signing fails.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn issued_with_uri_sans(
		issuer_key: &SigningKey,
		issuer_cn: impl AsRef<str>,
		signing_key: &SigningKey,
		cn: impl AsRef<str>,
		uris: &[&str],
	) -> TbResult<Certificate> {
		let issuer = test_cn_name(issuer_cn)?;
		let subject = test_cn_name(cn)?;
		let extensions = vec![test_end_entity_key_usage(), test_uri_san_extension(uris)];
		issue_test_certificate(issuer_key, issuer, signing_key, subject, 1, extensions)
	}

	/// Builds a leaf `CN=<cn>` with `serial` as its serial number that the
	/// authority `CN=<issuer_cn>` signs with `issuer_key`, whose `keyUsage`
	/// is `key_usage` alone.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError`] -- a name, the DER encoding, or the signing fails.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn issued(
		issuer_key: &SigningKey,
		issuer_cn: impl AsRef<str>,
		signing_key: &SigningKey,
		cn: impl AsRef<str>,
		serial: u8,
		key_usage: KeyUsage,
	) -> TbResult<Certificate> {
		let issuer = test_cn_name(issuer_cn)?;
		let subject = test_cn_name(cn)?;
		let extensions = vec![test_extension(&key_usage)];
		issue_test_certificate(issuer_key, issuer, signing_key, subject, serial, extensions)
	}

	/// `certificate` with `key_usage` as its one `keyUsage` extension, in
	/// place of the one it carried.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_key_usage(certificate: Certificate, key_usage: KeyUsage) -> Certificate {
		let replaced = TestCertificate::without_extension(certificate, KeyUsage::OID);
		TestCertificate::with_extension(replaced, test_extension(&key_usage))
	}

	/// `certificate` with its secp256k1 key in the compressed SEC 1 form,
	/// which names the same point (RFC 5480 §2.2).
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_compressed_key(mut certificate: Certificate) -> Certificate {
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		let point = spki.subject_public_key.as_bytes().expect("the key is whole octets");
		let key = PublicKey::from_sec1_bytes(point).expect("the key is a secp256k1 point");
		let compressed = key.to_encoded_point(true);
		spki.subject_public_key = BitString::from_bytes(compressed.as_bytes()).expect("a point is a BIT STRING");
		certificate
	}

	/// `certificate` with the second-lowest bit of the y-coordinate of its
	/// uncompressed secp256k1 point flipped. The encoding keeps x and the y
	/// parity of the point, and it lies off the curve:
	///
	/// - On the curve, x pairs with y and with p - y alone (SEC 1 v2.0 §2.3.4).
	/// - p - y has the other parity, and the flipped y is neither of the two.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_off_curve_key(mut certificate: Certificate) -> Certificate {
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		let mut point = spki.subject_public_key.raw_bytes().to_vec();
		let low = point.last_mut().expect("the key holds a point");
		*low ^= 0b10;

		spki.subject_public_key = BitString::from_bytes(&point).expect("a point is a BIT STRING");
		certificate
	}

	/// `certificate` with its secp256k1 point in the compact SEC 1 form: the
	/// octet `0x05` before the x-coordinate alone, a form that RFC 5480 §2.2
	/// refuses.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_compact_key(certificate: Certificate) -> Certificate {
		let mut compressed = TestCertificate::with_compressed_key(certificate);
		let spki = &mut compressed.tbs_certificate.subject_public_key_info;
		let point = spki.subject_public_key.raw_bytes();
		let (_, x) = point.split_first().expect("a compressed point names its form");
		let compact = [&[0x05][..], x].concat();

		spki.subject_public_key = BitString::from_bytes(&compact).expect("a point is a BIT STRING");
		compressed
	}

	/// `certificate` with `form` in place of the first octet of its
	/// uncompressed secp256k1 point, such as `0x06` or `0x07` of the hybrid
	/// forms that RFC 5480 §2.2 refuses.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_key_form(mut certificate: Certificate, form: u8) -> Certificate {
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		let point = spki.subject_public_key.raw_bytes();
		let (_, coordinates) = point.split_first().expect("the key holds a point");
		let formed = [&[form][..], coordinates].concat();

		spki.subject_public_key = BitString::from_bytes(&formed).expect("a point is a BIT STRING");
		certificate
	}

	/// `certificate` with its key under the named curve `curve` and the same
	/// point. Its signature then fails to verify, so it serves a reader of keys
	/// alone.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_named_curve(mut certificate: Certificate, curve: ObjectIdentifier) -> Certificate {
		let named_curve = Any::encode_from(&curve).expect("a curve OID encodes");
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		spki.algorithm.parameters = Some(named_curve);
		certificate
	}

	/// `certificate` with `point` as an `id-ecPublicKey` key on the named curve
	/// `curve`, in place of its key. Its signature then fails to verify, so it
	/// serves a reader of keys alone.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_curve_point(mut certificate: Certificate, curve: ObjectIdentifier, point: &[u8]) -> Certificate {
		let named_curve = Any::encode_from(&curve).expect("a curve OID encodes");
		let spki = &mut certificate.tbs_certificate.subject_public_key_info;
		spki.algorithm = AlgorithmIdentifierOwned { oid: ID_EC_PUBLIC_KEY, parameters: Some(named_curve) };
		spki.subject_public_key = BitString::from_bytes(point).expect("a point is a BIT STRING");
		certificate
	}

	/// `certificate` with one non-critical `extendedKeyUsage` that names
	/// `purposes`, in place of the one it carried.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_key_purposes(
		certificate: Certificate,
		purposes: impl IntoIterator<Item = ObjectIdentifier>,
	) -> Certificate {
		let replaced = TestCertificate::without_extension(certificate, ExtendedKeyUsage::OID);
		let purposes = ExtendedKeyUsage(purposes.into_iter().collect());
		TestCertificate::with_extension(replaced, TestCertificate::extension(&purposes, false))
	}

	/// `certificate` with `extension` after the extensions it carries.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_extension(mut certificate: Certificate, extension: Extension) -> Certificate {
		let extensions = certificate.tbs_certificate.extensions.get_or_insert_with(Vec::new);
		extensions.push(extension);
		certificate
	}

	/// `certificate` with every extension of `oid` removed.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn without_extension(mut certificate: Certificate, oid: ObjectIdentifier) -> Certificate {
		let extensions = certificate.tbs_certificate.extensions.get_or_insert_with(Vec::new);
		extensions.retain(|extension| extension.extn_id != oid);
		certificate
	}

	/// `certificate` with no `extensions` field.
	#[cfg(all(test, feature = "x509"))]
	pub(crate) fn without_extensions(mut certificate: Certificate) -> Certificate {
		certificate.tbs_certificate.extensions = None;
		certificate
	}

	/// `certificate` with two non-critical extensions of `oid`, each with an
	/// empty value, after the extensions it carries. RFC 5280 §4.2 refuses the
	/// repeat.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn with_repeated_extension(certificate: Certificate, oid: impl AsRef<str>) -> Certificate {
		let extension = TestCertificate::opaque_extension(oid, false);
		let once = TestCertificate::with_extension(certificate, extension.clone());
		TestCertificate::with_extension(once, extension)
	}

	/// `certificate` with a critical `nameConstraints` extension of an empty
	/// value after the extensions it carries. The crate processes no
	/// `nameConstraints`, so RFC 5280 §4.2 refuses the certificate.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn with_unknown_critical_extension(certificate: Certificate) -> Certificate {
		let extension = TestCertificate::opaque_extension("2.5.29.30", true);
		TestCertificate::with_extension(certificate, extension)
	}

	/// The DER of the SubjectPublicKeyInfo of `certificate`, the form a pin or
	/// a key list names a key in.
	#[cfg(all(test, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub(crate) fn spki_der(certificate: &Certificate) -> Vec<u8> {
		let spki = &certificate.tbs_certificate.subject_public_key_info;
		spki.to_der().expect("a test SubjectPublicKeyInfo encodes")
	}

	/// The extension of `value`, critical when `critical` holds (RFC 5280
	/// §4.2).
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn extension<T>(value: &T, critical: bool) -> Extension
	where
		T: AssociatedOid + Encode,
	{
		let extension = test_extension(value);
		Extension { critical, ..extension }
	}

	/// An extension of `oid` with an empty value, critical when `critical`
	/// holds, for the RFC 5280 §4.2 checks of an unrecognized extension.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn opaque_extension(oid: impl AsRef<str>, critical: bool) -> Extension {
		let extn_id = ObjectIdentifier::new(oid.as_ref()).expect("a test OID parses");
		let extn_value = OctetString::new(Vec::new()).expect("an empty value fits an OCTET STRING");
		Extension { extn_id, critical, extn_value }
	}

	/// `certificate` signed again by `issuer_key` under the test algorithm, so
	/// a test that edits its fields keeps a signature that verifies.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn signed_by(certificate: Certificate, issuer_key: &SigningKey) -> Certificate {
		let Certificate { tbs_certificate, signature_algorithm, .. } = certificate;
		let signed = sign_test_certificate(tbs_certificate, &signature_algorithm, issuer_key);
		signed.expect("the test key signs the certificate")
	}

	/// The `certificates` set of a `SignedData` that holds `certificates`,
	/// which DER sorts (RFC 5652 §5.1).
	#[cfg(feature = "x509")]
	pub fn set_of(certificates: impl IntoIterator<Item = Certificate>) -> CertificateSet {
		let choices: Vec<CertificateChoices> = certificates.into_iter().map(CertificateChoices::Certificate).collect();
		CertificateSet(choices.try_into().expect("distinct certificates are a SET"))
	}

	/// `count` self-signed certificates of distinct fixed keys, each a
	/// stranger to every path.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn strangers(count: u8) -> Vec<Certificate> {
		let stranger = |offset: u8| TestCertificate::self_signed(&TestKey::fixed(offset.saturating_add(16)));
		(0..count).map(stranger).collect()
	}

	/// Two certificates that lead a walk from a certificate `intermediate`
	/// issued back into itself. The first carries the subject of
	/// `intermediate` and names the second as its issuer, and the second names
	/// the first.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn looping_issuers(intermediate: &Certificate) -> [Certificate; 2] {
		let looping = test_cn_name("Looping issuer").expect("a test common name satisfies PrintableString");
		let subject = intermediate.tbs_certificate.subject.to_owned();
		let mut first = TestCertificate::self_signed(&TestKey::fixed(0x60));
		first.tbs_certificate.subject = subject.to_owned();
		first.tbs_certificate.issuer = looping.to_owned();
		let mut second = TestCertificate::self_signed(&TestKey::fixed(0x61));
		second.tbs_certificate.subject = looping;
		second.tbs_certificate.issuer = subject;
		[first, second]
	}

	/// Creates a valid certificate chain in which a root signs an intermediate
	/// and the intermediate signs a leaf.
	///
	/// Each certificate names the subject of its signer as its issuer, and
	/// each carries a valid signature.
	///
	/// # Security
	///
	/// The root, intermediate, and leaf secret scalars are thirty-two `0x01`,
	/// `0x02`, and `0x03` bytes. They are public, so anyone who reads this
	/// file can issue a certificate the chain's root vouches for.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError`] -- the key material, the DER encoding, or the signing fails.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn insecure_fixed_chain() -> TbResult<TestCertificateChain> {
		let root_key = SigningKey::from_bytes(&[1u8; 32].into())?;
		let intermediate_key = SigningKey::from_bytes(&[2u8; 32].into())?;
		let leaf_key = SigningKey::from_bytes(&[3u8; 32].into())?;

		let root_name = test_cn_name("Root")?;
		let inter_name = test_cn_name("Intermediate")?;
		let leaf_name = test_cn_name("Leaf")?;

		let validity = test_validity()?;
		let algorithm = test_signature_algorithm();

		// The root certificate is self-signed.
		let subject_public_key_info = test_public_key(&root_key);
		let mut root_extensions = test_key_identifiers(&root_key, &root_key);
		root_extensions.extend(TestCertificate::ca_extensions(true, true, None));

		let root_tbs = TbsCertificate {
			version: X509Version::V3,
			serial_number: SerialNumber::new(&[1])?,
			signature: algorithm.to_owned(),
			issuer: root_name.to_owned(),
			validity,
			subject: root_name.to_owned(),
			subject_public_key_info,
			issuer_unique_id: None,
			subject_unique_id: None,
			// RFC 5280 §6.1.4(k),(n): the root is a CA permitted to sign
			// certificates.
			extensions: Some(root_extensions),
		};
		let root = sign_test_certificate(root_tbs, &algorithm, &root_key)?;

		// The root signs the intermediate certificate.
		let subject_public_key_info = test_public_key(&intermediate_key);
		let mut intermediate_extensions = test_key_identifiers(&intermediate_key, &root_key);
		intermediate_extensions.extend(TestCertificate::ca_extensions(true, true, None));

		let inter_tbs = TbsCertificate {
			version: X509Version::V3,
			serial_number: SerialNumber::new(&[2])?,
			signature: algorithm.to_owned(),
			issuer: root_name,
			validity,
			subject: inter_name.to_owned(),
			subject_public_key_info,
			issuer_unique_id: None,
			subject_unique_id: None,
			// RFC 5280 §6.1.4(k),(n): the intermediate is a CA permitted to
			// sign certificates.
			extensions: Some(intermediate_extensions),
		};

		let intermediate = sign_test_certificate(inter_tbs, &algorithm, &root_key)?;

		// The intermediate signs the leaf certificate.
		let subject_public_key_info = test_public_key(&leaf_key);
		let mut leaf_extensions = test_key_identifiers(&leaf_key, &intermediate_key);
		leaf_extensions.push(test_end_entity_key_usage());

		let leaf_tbs = TbsCertificate {
			version: X509Version::V3,
			serial_number: SerialNumber::new(&[3])?,
			signature: algorithm.to_owned(),
			issuer: inter_name,
			validity,
			subject: leaf_name,
			subject_public_key_info,
			issuer_unique_id: None,
			subject_unique_id: None,
			extensions: Some(leaf_extensions),
		};
		let leaf = sign_test_certificate(leaf_tbs, &algorithm, &intermediate_key)?;

		Ok(TestCertificateChain { root, intermediate, leaf, root_key, intermediate_key, leaf_key })
	}

	/// Creates an expired test certificate for the validation tests.
	///
	/// It is an ssl.com certificate that expired on August 17, 2019.
	#[cfg(feature = "x509")]
	pub fn expired() -> Certificate {
		crate::pem! {"
			-----BEGIN CERTIFICATE-----
			MIIF1TCCBVugAwIBAgIQdBJ26pggQyU+isEPM912FDAKBggqhkjOPQQDAzByMQsw
			CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
			BgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIEVWIFNTTCBJbnRlcm1l
			ZGlhdGUgQ0EgRUNDIFIyMB4XDTE5MDgxNjIyMzU1N1oXDTE5MDgxNzIyMzU1N1ow
			gcgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3Rv
			bjERMA8GA1UECgwIU1NMIENvcnAxFjAUBgNVBAUTDU5WMjAwODE2MTQyNDMxHzAd
			BgNVBAMMFmV4cGlyZWQtZWNjLWV2LnNzbC5jb20xHTAbBgNVBA8MFFByaXZhdGUg
			T3JnYW5pemF0aW9uMRcwFQYLKwYBBAGCNzwCAQIMBk5ldmFkYTETMBEGCysGAQQB
			gjc8AgEDEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABKFkgNgOHrsYyyJHlGXK
			6C6SupADk+CLOKpMuoIdduURE4k5aXkmQ2yacYNmfqTTgC4oss/c2swxX9KDZdjW
			PYpFXfeCkorzKcX6RDJdUjD/78TiAT7fIyqcNyxuRpr4bqOCA10wggNZMB8GA1Ud
			IwQYMBaAFITu+Hk+CGR2SGQ59bG/iwJeC7wnMH4GCCsGAQUFBwEBBHIwcDBMBggr
			BgEFBQcwAoZAaHR0cDovL3d3dy5zc2wuY29tL3JlcG9zaXRvcnkvU1NMY29tLVN1
			YkNBLUVWLVNTTC1FQ0MtMzg0LVIyLmNydDAgBggrBgEFBQcwAYYUaHR0cDovL29j
			c3BzLnNzbC5jb20wPQYDVR0RBDYwNIIWZXhwaXJlZC1lY2MtZXYuc3NsLmNvbYIa
			d3d3LmV4cGlyZWQtZWNjLWV2LnNzbC5jb20wXwYDVR0gBFgwVjAHBgVngQwBATAN
			BgsqhGgBhvZ3AgUBATA8BgwrBgEEAYKpMAEDAQQwLDAqBggrBgEFBQcCARYeaHR0
			cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5MB0GA1UdJQQWMBQGCCsGAQUFBwMC
			BggrBgEFBQcDATBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8vY3Jscy5zc2wuY29t
			L1NTTGNvbS1TdWJDQS1FVi1TU0wtRUNDLTM4NC1SMi5jcmwwHQYDVR0OBBYEFNK1
			Fhn8lNacFjqY/nVutrEtu8JTMA4GA1UdDwEB/wQEAwIHgDCCAX0GCisGAQQB1nkC
			BAIEggFtBIIBaQFnAHUAdH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFYA
			AAFsnJvm3QAABAMARjBEAiAN3B7UPSzzszy+uYfXAZXKfHp6X8vkFL6FsvDknpv9
			cQIgTcE3kmHDPlQRwhkccghbl/ekwgY8CZHOSYmQcZzAKhoAdgDuS723dc5guuFC
			aR+r4Z5mow9+X7By2IMAxHuJeqj9ywAAAWycm+XxAAAEAwBHMEUCIF8Z0jTHQ0bU
			xRMWFVkPo/Fq8taoiTMF9rAX4/QZtmdNAiEA2kodKU2CXO2WOT257aF0v2gBLh7T
			2f8rrj8MYf4A1soAdgBVgdTCFpA2AUrqC5tXPFPwwOQ4eHAlCBcvo6odBxPTDAAA
			AWycm+ZjAAAEAwBHMEUCIQC/j+yfrh55hcKfaGRBvIOX/Wf+NWy/AUep9UiQaV/0
			oQIgO2WX6jOEyXN9ZtBDTxaspPhIcCIWOXNfn9PkzrEzaWQwCgYIKoZIzj0EAwMD
			aAAwZQIxAIM0MOzr0GX3Zeg3OZCOEKYe/yIXT2FlDMMVAFK0WdHI+lMVwQGacR0A
			+9Cvs7zTlQIwLkVrf3XF+P3afMrGhljvWAqPNHpf/jJsddq0DmSHgITOWCJXfytT
			dLAFZesIxt4p
			-----END CERTIFICATE-----
		"}
		.expect("Failed to parse expired test certificate")
	}

	/// The Unix time, in seconds, at which the fixed test validity window
	/// ends (2033-05-18).
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub const END_OF_VALIDITY: u64 = 2_000_000_000;

	/// A manual clock one second past [`Self::END_OF_VALIDITY`], on which each
	/// certificate of the fixed test validity window is expired.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::clock::Clock;
	/// use tightbeam::testing::TestCertificate;
	///
	/// let clock = TestCertificate::clock_past_validity();
	/// assert!(clock.unix().get() > TestCertificate::END_OF_VALIDITY * 1_000);
	/// ```
	#[cfg(all(host_clock, feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn clock_past_validity() -> Arc<ManualClock> {
		TestClock::past(Self::END_OF_VALIDITY)
	}
}

/// The manual clocks of the tests, each of which moves only when its test
/// advances it.
#[cfg(host_clock)]
pub(crate) struct TestClock;

#[cfg(host_clock)]
impl TestClock {
	/// The Unix time that [`Self::manual`] starts at (2023-11-14), inside the
	/// fixed test validity window.
	#[cfg(test)]
	pub(crate) const START: UnixMillis = UnixMillis::new(1_700_000_000_000);

	/// A manual clock at [`Self::START`].
	#[cfg(test)]
	pub(crate) fn manual() -> Arc<ManualClock> {
		Arc::new(ManualClock::at(Self::START))
	}

	/// `clock` as the erased handle that a store, a gate, or a trace builds
	/// on.
	#[cfg(test)]
	pub(crate) fn erased<C: Clock + 'static>(clock: &Arc<C>) -> Arc<dyn Clock> {
		Arc::clone(clock) as Arc<dyn Clock>
	}

	/// A manual clock one second past the Unix time `seconds`.
	pub(crate) fn past(seconds: u64) -> Arc<ManualClock> {
		let past = core::time::Duration::from_secs(seconds.saturating_add(1));
		Arc::new(ManualClock::at(UnixMillis::new(0).saturating_add(past)))
	}
}

/// The signer material of CMS structures.
///
/// The CMS signer signs fixed placeholder content under the fixed test key,
/// because these tests exercise the encoding of a frame's signature slot.
#[cfg(all(feature = "secp256k1", feature = "signature"))]
pub struct TestSigner;

#[cfg(all(feature = "secp256k1", feature = "signature"))]
impl TestSigner {
	/// A `SignerInfo` that the CMS signer builds over placeholder content.
	pub fn info() -> crate::crypto::sign::Signed<crate::SignerInfo> {
		use crate::crypto::sign::{CmsSigner, SignedContent};

		let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let content = SignedContent::data(b"test signer content");
		CmsSigner::sign_with::<Secp256k1Signature, _>(&key, content).expect("the fixed test key signs")
	}
}

/// The readers of the signed attributes of a `SignerInfo`, which the tests of
/// signed structures share.
#[cfg(feature = "signature")]
pub struct TestAttributes;

#[cfg(feature = "signature")]
impl TestAttributes {
	/// The algorithm protection of `id-sha3-256` beside `ecdsa-with-SHA3-256`
	/// as RFC 6211 §2 writes it under `DEFINITIONS IMPLICIT TAGS`, built by
	/// hand: the `[1]` tag replaces the SEQUENCE tag of the second
	/// AlgorithmIdentifier.
	pub const ALGORITHM_PROTECTION: [u8; 28] = [
		0x30, 0x1a, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0xa1, 0x0b, 0x06,
		0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0a,
	];

	/// The OIDs of the signed attributes of `signer_info`, in DER order.
	pub fn oids(signer_info: &crate::SignerInfo) -> Vec<crate::der::asn1::ObjectIdentifier> {
		let attributes = signer_info.signed_attrs.as_ref().expect("the signer writes signed attributes");
		attributes.iter().map(|attribute| attribute.oid).collect()
	}

	/// The one value of the signed attribute of `signer_info` under `oid`.
	pub fn value(signer_info: &crate::SignerInfo, oid: crate::der::asn1::ObjectIdentifier) -> crate::der::Any {
		let attributes = signer_info.signed_attrs.as_ref().expect("the signer writes signed attributes");
		let mut matching = attributes.iter().filter(|attribute| attribute.oid == oid);
		let attribute = matching.next().expect("the signer writes the attribute");
		let value = attribute.values.iter().next().expect("the attribute holds a value");
		value.clone()
	}

	/// The two content types `envelope` declares: the type of its encrypted
	/// content, and the one value of its content-type attribute.
	#[cfg(all(feature = "aead", feature = "kdf", feature = "ecdh"))]
	pub fn declared_content_types(
		envelope: &crate::asn1::AuthEnvelopedData,
	) -> (crate::der::asn1::ObjectIdentifier, crate::der::asn1::ObjectIdentifier) {
		let attributes = envelope.auth_attrs.as_ref().expect("the envelope authenticates its attributes");
		let content_type = crate::oids::ATTR_CONTENT_TYPE;
		let mut matching = attributes.iter().filter(|attribute| attribute.oid == content_type);
		let attribute = matching.next().expect("the envelope carries a content-type attribute");
		let value = attribute.values.iter().next().expect("the attribute holds a value");
		let named = value.decode_as().expect("the value is an OBJECT IDENTIFIER");
		(envelope.auth_encrypted_content_info.content_type, named)
	}
}

/// The house trust stores of the tests, each under the default secp256k1
/// policy and the house curves.
#[cfg(all(
	any(test, feature = "transport-cms"),
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub(crate) struct TestStore;

#[cfg(all(
	any(test, feature = "transport-cms"),
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
impl TestStore {
	/// The builder of a house store that holds no certificate and consults no
	/// revocation list.
	#[cfg(test)]
	pub(crate) fn empty() -> CertificateTrustBuilder {
		CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
	}

	/// A house store that holds `certificates` and consults no revocation
	/// list.
	#[cfg(test)]
	pub(crate) fn holding(certificates: impl IntoIterator<Item = Certificate>) -> CertificateTrustStore {
		TestStore::revoking(certificates, NoRevocation)
	}

	/// A house store that holds `certificates` and consults `revocation` on
	/// revocation.
	pub(crate) fn revoking(
		certificates: impl IntoIterator<Item = Certificate>,
		revocation: impl RevocationChecker + 'static,
	) -> CertificateTrustStore {
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, revocation);
		let builder = certificates.into_iter().try_fold(builder, TrustBuilder::with_certificate);
		builder.expect("the store takes each test certificate").build()
	}
}

/// A trust that admits every certificate, names one anchor for each, reads
/// no validity period, and verifies each signature under the house policy.
///
/// The house store reads each validity period and walks each path, so a test
/// of a check that runs outside the store holds this double.
#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Debug)]
pub(crate) struct AcceptsEveryCertificate {
	/// The anchor the trust names for every certificate.
	anchor: Arc<Certificate>,
}

#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl AcceptsEveryCertificate {
	/// A trust that names `anchor` for every certificate and resolves no
	/// signer.
	pub(crate) fn under(anchor: impl Into<Arc<Certificate>>) -> Self {
		AcceptsEveryCertificate { anchor: anchor.into() }
	}
}

#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl CertificateValidation for AcceptsEveryCertificate {
	fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
		Ok(())
	}
}

#[cfg(all(test, feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl CertificateTrust for AcceptsEveryCertificate {
	fn is_trusted(&self, _cert: &Certificate) -> bool {
		true
	}

	fn verify_chain(&self, _chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		Ok(Arc::clone(&self.anchor))
	}

	fn trust_anchor(&self, _cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		Ok(Arc::clone(&self.anchor))
	}

	fn find_by_signer_identifier(&self, _sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		None
	}

	fn find_by_public_key(&self, _spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		None
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&const { Secp256k1Policy::new() }
	}
}

/// The two identities of a test CMS server under one test authority: a
/// signing certificate with `digitalSignature` alone, and a key-agreement
/// certificate of the same subject with `keyAgreement` alone, each beside its
/// key.
///
/// A client's store holds the authority, so the store validates both
/// certificates by their chain.
#[cfg(feature = "transport-cms")]
pub struct TestCmsServer {
	/// The authority that issued both certificates.
	pub authority: Certificate,
	/// The key of [`Self::authority`], which issues further certificates
	/// under it.
	pub authority_key: SigningKey,
	/// The certificate whose key signs the server's reply.
	pub signing: Certificate,
	/// The key of [`Self::signing`].
	pub signing_key: SigningKey,
	/// The certificate whose key the CMS opening seals to.
	pub key_agreement: Certificate,
	/// The key of [`Self::key_agreement`].
	pub key_agreement_key: SigningKey,
}

#[cfg(feature = "transport-cms")]
impl TestCmsServer {
	/// A server `CN=<cn>` whose keys derive from `cn`, both certificates
	/// issued by the authority `CN=<cn> authority`, so one name gives one
	/// server.
	pub fn generate(cn: impl AsRef<str>) -> Self {
		let cn = cn.as_ref();
		let signing_key = TestCmsServer::derived_key(cn, "signing");
		let key_agreement_key = TestCmsServer::derived_key(cn, "key agreement");
		TestCmsServer::of(cn, signing_key, key_agreement_key)
	}

	/// A server `CN=<cn>` of `signing_key` and `key_agreement_key`, both
	/// certificates issued by the authority `CN=<cn> authority`.
	///
	/// The authority key is the SHA3-256 digest of the scalar of `signing_key`
	/// followed by the label `authority`, read as a scalar, so equal inputs
	/// give equal servers.
	pub fn of(cn: impl AsRef<str>, signing_key: SigningKey, key_agreement_key: SigningKey) -> Self {
		let cn = cn.as_ref();
		let authority_cn = format!("{cn} authority");
		let authority_key = TestCmsServer::derived_key(signing_key.to_bytes(), "authority");
		let authority = TestCertificate::authority(&authority_key, &authority_cn);
		let authority = authority.expect("a test authority issues itself");

		let signing_usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let signing = TestCertificate::issued(&authority_key, &authority_cn, &signing_key, cn, 2, signing_usage);
		let signing = signing.expect("the authority issues the signing certificate");
		let agreement_usage = KeyUsage(KeyUsages::KeyAgreement.into());
		let key_agreement =
			TestCertificate::issued(&authority_key, &authority_cn, &key_agreement_key, cn, 3, agreement_usage);
		let key_agreement = key_agreement.expect("the authority issues the key-agreement certificate");

		TestCmsServer { authority, authority_key, signing, signing_key, key_agreement, key_agreement_key }
	}

	/// The key whose scalar is the SHA3-256 digest of `input` followed by
	/// `label`.
	fn derived_key(input: impl AsRef<[u8]>, label: impl AsRef<[u8]>) -> SigningKey {
		use crate::crypto::hash::Digest;

		let digest = Sha3_256::new().chain_update(input).chain_update(label).finalize();
		let key = SigningKey::from_bytes(&digest);
		key.expect("a SHA3-256 digest names a scalar below the group order")
	}

	/// A server of fixed keys whose authority issues both certificates to
	/// `subject`, a name of the caller's shape.
	pub fn named(subject: RdnSequence) -> Self {
		let server = TestCmsServer::generate("tightbeam named server");
		let signing = server.issue_signing(&server.signing_key, subject.to_owned(), 2);
		let issuer = server.authority.tbs_certificate.subject.to_owned();
		let usage = vec![test_extension(&KeyUsage(KeyUsages::KeyAgreement.into()))];
		let key = &server.key_agreement_key;
		let key_agreement = issue_test_certificate(&server.authority_key, issuer, key, subject, 3, usage);
		let key_agreement = key_agreement.expect("the authority issues the key-agreement certificate");

		TestCmsServer { signing, key_agreement, ..server }
	}

	/// The signing identity of the server.
	pub fn signing_identity(&self) -> SigningIdentity {
		TestIdentity::presenting(self.signing.to_owned(), &self.signing_key)
	}

	/// The key-agreement identity of the server, whose backend holds
	/// [`Self::key_agreement_key`].
	pub fn key_agreement_identity(&self) -> KeyAgreementIdentity<DhKemSecp256k1> {
		let backend: Arc<dyn DiffieHellman<Secp256k1>> = TestKey::provider(self.key_agreement_key.to_owned());
		let identity = KeyAgreementIdentity::new(self.key_agreement.to_owned(), backend);
		identity.expect("the test key matches its key-agreement certificate")
	}

	/// The server's two identities as the pair a CMS server holds.
	pub fn pair(&self) -> CmsIdentityPair<DhKemSecp256k1> {
		let pair = CmsIdentityPair::new(self.signing_identity(), self.key_agreement_identity());
		pair.expect("the two test certificates name one subject with two keys")
	}

	/// A store that holds the authority of both certificates.
	pub fn store(&self) -> CertificateTrustStore {
		self.store_with(NoRevocation)
	}

	/// A store that holds the authority of both certificates and consults
	/// `checker` on revocation.
	pub fn store_with(&self, checker: impl RevocationChecker + 'static) -> CertificateTrustStore {
		TestStore::revoking([self.authority.to_owned()], checker)
	}

	/// The trust of a client that pins this server's key-agreement
	/// certificate, bare, against [`Self::store`].
	pub fn trust(&self) -> ProvisionedTrust {
		let pinned = Arc::new(self.key_agreement.to_owned());
		let trust = ProvisionedTrust::new(pinned, Arc::new(self.store()));
		trust.expect("the store admits the test key-agreement certificate")
	}

	/// A certificate of the signing key that the authority issues under
	/// `serial`, which differs from [`Self::signing`] in its serial number
	/// alone, so its `subjectKeyIdentifier` names the same key.
	pub fn signing_twin(&self, serial: u8) -> Certificate {
		let subject = self.signing.tbs_certificate.subject.to_owned();
		self.issue_signing(&self.signing_key, subject, serial)
	}

	/// The pair of this server after its authority issues its signing
	/// certificate again to the same subject, beside that certificate. The
	/// reissued certificate holds the key whose scalar is thirty-two `0x07`
	/// octets, and the key-agreement certificate stays the one a client pins.
	pub fn rotated_pair(&self) -> (CmsIdentityPair<DhKemSecp256k1>, Certificate) {
		let key = SigningKey::from_slice(&[0x07; 32]).expect("seven is a secp256k1 scalar");
		let subject = self.signing.tbs_certificate.subject.to_owned();
		let signing = self.issue_signing(&key, subject, 7);

		let identity = TestIdentity::presenting(signing.to_owned(), &key);
		let pair = CmsIdentityPair::new(identity, self.key_agreement_identity());
		let pair = pair.expect("the rotated certificate names the subject of the key-agreement certificate");
		(pair, signing)
	}

	/// This server with both certificates issued again by its authority, each
	/// with an `extendedKeyUsage` that names `purposes`.
	pub fn with_key_purposes(self, purposes: &[ObjectIdentifier]) -> Self {
		let issuer = self.authority.tbs_certificate.subject.to_owned();
		let purposes = TestCertificate::extension(&ExtendedKeyUsage(purposes.to_vec()), false);
		let reissue = |certificate: &Certificate, key: &SigningKey, usage: KeyUsages, serial: u8| {
			let subject = certificate.tbs_certificate.subject.to_owned();
			let extensions = vec![test_extension(&KeyUsage(usage.into())), purposes.to_owned()];
			let issued =
				issue_test_certificate(&self.authority_key, issuer.to_owned(), key, subject, serial, extensions);
			issued.expect("the authority issues a certificate of the purposes")
		};

		let signing = reissue(&self.signing, &self.signing_key, KeyUsages::DigitalSignature, 2);
		let key_agreement = reissue(&self.key_agreement, &self.key_agreement_key, KeyUsages::KeyAgreement, 3);
		TestCmsServer { signing, key_agreement, ..self }
	}

	/// A certificate of `key` the authority issues to `subject` under
	/// `serial`, whose `keyUsage` asserts `digitalSignature` alone.
	pub fn issue_signing(&self, key: &SigningKey, subject: RdnSequence, serial: u8) -> Certificate {
		let issuer = self.authority.tbs_certificate.subject.to_owned();
		let usage = vec![test_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))];
		let issued = issue_test_certificate(&self.authority_key, issuer, key, subject, serial, usage);
		issued.expect("the authority issues a signing certificate")
	}
}

/// The key-agreement holders and recipients of a secp256k1 key under the
/// house KEM.
#[cfg(all(test, feature = "hpke", feature = "signature", feature = "x509"))]
pub(crate) struct TestAgreement;

#[cfg(all(test, feature = "hpke", feature = "signature", feature = "x509"))]
impl TestAgreement {
	/// The key-agreement identity of `key` under its
	/// [`TestCertificate::self_signed`] certificate.
	pub(crate) fn identity(key: &SigningKey) -> KeyAgreementIdentity<DhKemSecp256k1> {
		let identity = KeyAgreementIdentity::new(TestCertificate::self_signed(key), TestAgreement::backend(key));
		identity.expect("the test key matches its certificate")
	}

	/// The bare key of `key` beside the backend of its private half, for a
	/// decryptor that names its recipient by the key alone.
	pub(crate) fn bare(key: &SigningKey) -> crate::crypto::cms::BareKemKey<DhKemSecp256k1> {
		let public = PublicKey::from(key.verifying_key());
		let bare = crate::crypto::cms::BareKemKey::new(public, TestAgreement::backend(key));
		bare.expect("the backend holds the key")
	}

	/// The bare recipient of `key`, named by the key alone, as an encryptor
	/// seals to it.
	pub(crate) fn recipient(key: &SigningKey) -> crate::crypto::cms::KemRecipient<DhKemSecp256k1> {
		use crate::crypto::key::KeyBackend;

		let backend = Secp256k1KeyProvider::from(key.to_owned());
		let spki = backend.to_public_key_bytes().expect("the house backend encodes its key");
		let recipient = crate::crypto::cms::KemRecipient::bare(spki);
		recipient.expect("the key is a secp256k1 key")
	}

	/// The house backend of `key`, as the trait object the house KEM
	/// decapsulates through.
	fn backend(key: &SigningKey) -> Arc<dyn DiffieHellman<Secp256k1>> {
		TestKey::provider(key.to_owned())
	}
}

/// The signing identities, each a certificate beside the key that proves it.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub struct TestIdentity;

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl TestIdentity {
	/// The identity of `key` under the [`TestCertificate::self_signed`]
	/// certificate.
	pub fn of(key: &SigningKey) -> SigningIdentity {
		let certificate = TestCertificate::self_signed(key);
		TestIdentity::presenting(certificate, key)
	}

	/// The identity of `certificate`, whose key is `key`.
	pub fn presenting(certificate: impl Into<Arc<Certificate>>, key: &SigningKey) -> SigningIdentity {
		let provider = TestKey::provider(key.to_owned());
		SigningIdentity::new(certificate, provider).expect("the test key matches its certificate")
	}

	/// The identity of [`TestKey::insecure_fixed_signing`].
	///
	/// # Security
	///
	/// The key is public, so every signature it makes is forgeable.
	pub fn insecure_fixed() -> SigningIdentity {
		TestIdentity::of(&TestKey::insecure_fixed_signing())
	}

	/// `key` beside the [`TestCertificate::self_signed`] certificate, for a
	/// builder that signs in place.
	pub fn certified(key: SigningKey) -> CertifiedKey<SigningKey> {
		let certificate = TestCertificate::self_signed(&key);
		CertifiedKey::new(&certificate, key).expect("the test key matches its certificate")
	}

	/// A signer purpose of an implementor's own, outside the house purposes.
	#[cfg(test)]
	pub(crate) const OWN_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.12");

	/// The identity of [`TestKey::insecure_fixed_signing`] whose certificate
	/// names `purpose` as its one key purpose, or carries no
	/// `extendedKeyUsage` for `None`.
	///
	/// # Security
	///
	/// The key is public, so every signature it makes is forgeable.
	#[cfg(all(test, feature = "colony"))]
	pub(crate) fn naming(purpose: impl Into<Option<ObjectIdentifier>>) -> SigningIdentity {
		let key = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let certificate = match purpose.into() {
			Some(purpose) => TestCertificate::with_key_purposes(certificate, [purpose]),
			None => certificate,
		};

		TestIdentity::presenting(certificate, &key)
	}
}

/// The gossip rumors that the fixed test key signs, as a gateway's
/// verification hands them to admission.
#[cfg(feature = "colony")]
pub struct TestRumor;

#[cfg(feature = "colony")]
impl TestRumor {
	/// The application rumor of `payload`, issued at `order` and signed by
	/// [`TestKey::insecure_fixed_signing`].
	///
	/// # Security
	///
	/// The key is public, so every signature it makes is forgeable.
	pub fn application(order: u64, payload: impl Into<Vec<u8>>) -> Frame {
		let body = GossipRumor::application(payload.into());
		let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let issued = FrameBuilder::from(Version::V1).with_id("rumor").with_order(order);

		let built = issued.with_message(body).with_signer::<Secp256k1Signature, _>(signer).build();
		built.expect("the fixed test key signs a rumor")
	}

	/// `rumor` beside its signature, as its verification under
	/// [`TestIdentity::insecure_fixed`] returns it.
	pub fn verified(rumor: Frame) -> VerifiedRumor {
		let identity = TestIdentity::insecure_fixed();
		let verifying = rumor.verify_under(identity.signing_certificate(), identity.policy());
		let signature = verifying.expect("the fixed test key signed the rumor");

		VerifiedRumor::new(rumor, signature)
	}

	/// The [`Self::application`] rumor of the payload `[1, 2, 3]`, issued at
	/// order 1,000.
	#[cfg(test)]
	pub(crate) fn fixed() -> Frame {
		TestRumor::application(1_000, [1, 2, 3])
	}

	/// The SHA3-256 gossip digest of `rumor`, once its signature verifies
	/// under [`TestIdentity::insecure_fixed`].
	#[cfg(test)]
	pub(crate) fn digest(rumor: &Frame) -> crate::colony::cluster::GossipDigest {
		let verified = TestRumor::verified(rumor.clone());
		verified.gossip_digest::<Sha3_256>().expect("a test rumor frame encodes")
	}
}

/// The traces of the tests of the internal events, and the trail a test
/// reads back from one.
#[cfg(feature = "instrument")]
pub struct TestTrace;

#[cfg(feature = "instrument")]
impl TestTrace {
	/// A trace whose config sets `enable_internal_detail` to `detail` and
	/// keeps every other setting at its default.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events;
	/// use tightbeam::testing::fixtures::TestTrace;
	///
	/// let trace = TestTrace::with_detail(false);
	/// trace.emit(events::GATE_ACCEPT, "Ok");
	///
	/// assert_eq!(TestTrace::trail(&trace, &[events::GATE_ACCEPT]), [events::GATE_ACCEPT]);
	/// ```
	pub fn with_detail(detail: bool) -> TraceCollector {
		let config = TbInstrumentationConfig { enable_internal_detail: detail, ..Default::default() };
		TestTrace::with_config(config)
	}

	/// A trace under the instrumentation settings `config`.
	pub(crate) fn with_config(config: TbInstrumentationConfig) -> TraceCollector {
		TraceCollector::from(TraceConfig::with_instrumentation(config))
	}

	/// A trace whose config sets `enable_payloads`, so each event keeps the
	/// SHA3-256 hash of its payload.
	#[cfg(test)]
	pub(crate) fn with_payloads() -> TraceCollector {
		let config = TbInstrumentationConfig { enable_payloads: true, ..Default::default() };
		TestTrace::with_config(config)
	}

	/// The instrumentation settings that ask for every exploration event:
	/// the enabled sets, the refusals, and the divergences.
	#[cfg(all(test, feature = "testing-fdr"))]
	pub(crate) fn every_flag() -> TbInstrumentationConfig {
		TbInstrumentationConfig {
			sample_enabled_sets: true,
			sample_refusals: true,
			divergence_heuristics: true,
			..Default::default()
		}
	}

	/// A trace that stamps its events with the readings of `clock`.
	#[cfg(test)]
	pub(crate) fn on<C: crate::clock::Clock + 'static>(clock: &Arc<C>) -> TraceCollector {
		TraceCollector::new().with_clock(Arc::clone(clock) as Arc<dyn crate::clock::Clock>)
	}

	/// A trace whose fault model injects the error of `fault` at the records
	/// of `event`, at the rate `bps`.
	#[cfg(all(test, feature = "testing-fault"))]
	pub(crate) fn faulting<E: Into<TightBeamError>>(
		event: impl crate::testing::fault::ProcessEvent,
		fault: impl Fn() -> E + Send + Sync + 'static,
		bps: crate::basis_points::BasisPoints,
	) -> TraceCollector {
		let model = crate::testing::fdr::FaultModel::default().with_event_fault(event, fault, bps);
		TraceCollector::new().with_fault_model(model)
	}

	/// Drains `trace`, and returns its records of `event`, in the order it
	/// recorded them.
	#[cfg(test)]
	pub(crate) fn records(trace: &TraceCollector, event: Urn<'static>) -> Vec<crate::instrumentation::TbEvent> {
		let recorded = trace.drain_events();
		recorded.into_iter().filter(|record| record.urn == event).collect()
	}

	/// Drains `trace`, and returns the label of each of its records of
	/// `event`, in the order it recorded them.
	#[cfg(test)]
	pub(crate) fn labels(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<String>> {
		let records = TestTrace::records(trace, event).into_iter();
		records.map(|record| record.label.map(String::from)).collect()
	}

	/// Drains `trace`, and returns the payload hash of each of its records of
	/// `event`, in the order it recorded them.
	#[cfg(test)]
	pub(crate) fn payloads(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<[u8; 32]>> {
		let records = TestTrace::records(trace, event).into_iter();
		records.map(|record| record.payload_hash).collect()
	}

	/// Drains `trace`, and returns `field` of each event it recorded, in the
	/// order it recorded them.
	#[cfg(test)]
	pub(crate) fn drained<T>(
		trace: &TraceCollector,
		field: impl FnMut(crate::instrumentation::TbEvent) -> T,
	) -> Vec<T> {
		let recorded = trace.drain_events();
		recorded.into_iter().map(field).collect()
	}

	/// Drains `trace`, and returns the URNs among `kept` that it recorded, in
	/// the order it recorded them.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events;
	/// use tightbeam::testing::fixtures::TestTrace;
	///
	/// let trace = TestTrace::with_detail(true);
	/// trace.emit(events::POLICY_EVAL, "policy_eval");
	/// trace.emit(events::GATE_ACCEPT, "Ok");
	///
	/// assert_eq!(TestTrace::trail(&trace, &[events::GATE_ACCEPT]), [events::GATE_ACCEPT]);
	/// ```
	pub fn trail(trace: &TraceCollector, kept: &[Urn<'static>]) -> Vec<Urn<'static>> {
		let recorded = trace.drain_events();
		let urns = recorded.into_iter().map(|event| event.urn);
		urns.filter(|urn| kept.contains(urn)).collect()
	}
}

/// The digest material of CMS structures.
pub struct TestDigest;

impl TestDigest {
	pub fn info() -> DigestInfo {
		let digest = OctetString::new(vec![0u8; 32]).expect("Failed to create OctetString");
		DigestInfo { algorithm: AlgorithmIdentifier { oid: HASH_SHA256, parameters: None }, digest }
	}
}

/// The algorithm identifiers that a test names a CMS or key algorithm by.
#[cfg(test)]
pub(crate) struct TestAlgorithm;

#[cfg(test)]
impl TestAlgorithm {
	/// The identifier of the algorithm `oid`, with its parameters absent.
	pub(crate) fn of(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid, parameters: None }
	}
}

/// The session peers that a test builds a session from.
#[cfg(all(test, feature = "transport", feature = "instrument"))]
pub(crate) struct TestPeer;

#[cfg(all(test, feature = "transport", feature = "instrument"))]
impl TestPeer {
	/// The peer of [`TestCertificate::insecure_fixed`], beside the SHA3-256
	/// hash of the canonical form of its key.
	pub(crate) fn fixed() -> (crate::transport::handshake::SessionPeer, [u8; 32]) {
		use crate::crypto::hash::Digest;

		let certificate = Arc::new(TestCertificate::insecure_fixed());
		let peer = crate::transport::handshake::SessionPeer::try_from(certificate);
		let peer = peer.expect("a test certificate records its peer");
		let key_hash = Sha3_256::digest(peer.key().as_der()).into();
		(peer, key_hash)
	}
}

/// The CMS envelopes in the shapes that the decoders read.
#[cfg(test)]
pub(crate) struct TestEnvelope;

#[cfg(test)]
impl TestEnvelope {
	/// An `AuthEnvelopedData` of `id-data` content under `algorithm`, with no
	/// recipient, no content, no attribute, and sixteen zero octets as its
	/// MAC.
	pub(crate) fn empty_auth_enveloped(algorithm: ObjectIdentifier) -> crate::asn1::AuthEnvelopedData {
		use crate::cms::content_info::CmsVersion;
		use crate::cms::enveloped_data::{EncryptedContentInfo, RecipientInfos};
		use crate::oids::DATA;

		let content_enc_alg = TestAlgorithm::of(algorithm);
		let info = EncryptedContentInfo { content_type: DATA, content_enc_alg, encrypted_content: None };
		let mac = OctetString::new([0u8; 16]).expect("16 octets fit an OCTET STRING");

		crate::asn1::AuthEnvelopedData {
			version: CmsVersion::V0,
			originator_info: None,
			recipient_infos: RecipientInfos::default(),
			auth_encrypted_content_info: info,
			auth_attrs: None,
			mac,
			unauth_attrs: None,
		}
	}

	/// `content` of `content_type` inside a CMS `ContentInfo` (RFC 5652 §3),
	/// the form a CMS parser reads.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn content_info<T>(content_type: ObjectIdentifier, content: &T) -> Vec<u8>
	where
		T: crate::der::EncodeValue + crate::der::Tagged,
	{
		let content = Any::encode_from(content).expect("the content encodes");
		let content_info = crate::asn1::ContentInfo { content_type, content };
		content_info.to_der().expect("the ContentInfo encodes")
	}
}

/// A gate that answers every request with the status it holds.
///
/// Each house gate decides its status from the frame and the session, so a
/// test that needs one status from a gate holds this double.
#[cfg(all(test, feature = "policy"))]
pub(crate) struct TestGate(pub(crate) crate::policy::TransitStatus);

#[cfg(all(test, feature = "policy"))]
impl crate::policy::GatePolicy for TestGate {
	fn evaluate(
		&self,
		_frame: Option<&Frame>,
		_session: &crate::policy::SessionContext,
	) -> crate::policy::TransitStatus {
		self.0
	}
}

/// The two ends of one loopback TCP connection.
#[cfg(test)]
pub(crate) struct TestLoopback;

#[cfg(test)]
impl TestLoopback {
	/// The end that the listener accepted and the end that dialed it, as
	/// tokio streams.
	#[cfg(feature = "tokio")]
	pub(crate) async fn tokio_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
		let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await;
		let listener = bound.expect("a loopback port binds");
		let address = listener.local_addr().expect("a bound listener has an address");
		let dialed = tokio::net::TcpStream::connect(address).await;

		let dialing = dialed.expect("the loopback listener takes the dial");
		let (accepted, _) = listener.accept().await.expect("the dial arrives");
		(accepted, dialing)
	}

	/// The end that the listener accepted and the end that dialed it, as std
	/// streams.
	pub(crate) fn std_pair() -> (std::net::TcpStream, std::net::TcpStream) {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
		let address = listener.local_addr().expect("a bound listener has an address");

		let dialing = std::net::TcpStream::connect(address).expect("the loopback listener takes the dial");
		let (accepted, _) = listener.accept().expect("the dial arrives");
		(accepted, dialing)
	}
}

/// A labelled transition system over named states and events, which
/// [`Self::build`] turns into a [`Process`].
///
/// [`Self::of`] names a process with empty lists, and a struct update sets
/// the lists a test needs.
#[cfg(all(test, feature = "testing-csp"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct TestProcess {
	/// The name of the process.
	pub(crate) name: &'static str,
	/// The state the process starts in.
	pub(crate) initial: &'static str,
	/// The events of the observable alphabet.
	pub(crate) observable: &'static [&'static str],
	/// The events of the hidden alphabet.
	pub(crate) hidden: &'static [&'static str],
	/// Each transition as its source state, its event, and its target state.
	pub(crate) transitions: &'static [(&'static str, &'static str, &'static str)],
	/// The states the process may stop in.
	pub(crate) terminal: &'static [&'static str],
	/// The states the process declares as choice points.
	pub(crate) choice: &'static [&'static str],
}

#[cfg(all(test, feature = "testing-csp"))]
impl TestProcess {
	/// The process `name` that starts in `initial`, with empty alphabets and
	/// no transition, terminal state, or choice point.
	pub(crate) const fn of(name: &'static str, initial: &'static str) -> Self {
		TestProcess {
			name,
			initial,
			observable: &[],
			hidden: &[],
			transitions: &[],
			terminal: &[],
			choice: &[],
		}
	}

	/// The process `Idle`, which offers no event from `S0` and accepts a run
	/// that records none.
	pub(crate) fn idle() -> Process {
		let builder = Process::builder("Idle").initial_state(State("S0")).permits_no_progress();
		builder.build().expect("an idle process names its initial state")
	}

	/// The [`Process`] of this system.
	pub(crate) fn build(self) -> Process {
		let mut builder = Process::builder(self.name).initial_state(State(self.initial));
		for &event in self.observable {
			builder = builder.add_observable(Event(event));
		}
		for &event in self.hidden {
			builder = builder.add_hidden(Event(event));
		}
		for &(from, event, to) in self.transitions {
			builder = builder.add_transition(State(from), Event(event), State(to));
		}
		for &state in self.terminal {
			builder = builder.add_terminal(State(state));
		}
		for &state in self.choice {
			builder = builder.add_choice(State(state));
		}

		builder.build().expect("a test process names its initial state")
	}

	/// The process `name` that takes the events of `events` in turn, through
	/// the states of `states`, to its accepting last state.
	pub(crate) fn chain(name: &'static str, states: &[&'static str], events: &[&'static str]) -> Process {
		let first = states.first().copied().expect("a chain has a first state");
		let last = states.last().copied().expect("a chain has a last state");
		let mut builder = Process::builder(name).initial_state(State(first));
		for ((&from, &to), &event) in states.iter().zip(states.iter().skip(1)).zip(events) {
			builder = builder.add_observable(Event(event));
			builder = builder.add_transition(State(from), Event(event), State(to));
		}

		builder.add_terminal(State(last)).build().expect("a chain of events builds")
	}

	/// The process `name` in which each event of `wcets` takes `s0` to the
	/// terminal `s1`, under a WCET bound of its milliseconds.
	#[cfg(feature = "testing-timing")]
	pub(crate) fn timed(name: &'static str, wcets: &[(&'static str, u64)]) -> Process {
		let mut constraints = TimingConstraints::default();
		let mut builder = Process::builder(name).initial_state(State("s0")).add_terminal(State("s1"));
		for &(event, millis) in wcets {
			let wcet = TimingConstraint::Wcet(WcetConfig::of_millis(millis));
			let added = constraints.add(Event(event), wcet);
			added.expect("each event of a timed process takes one bound");

			let observed = builder.add_observable(Event(event));
			builder = observed.add_transition(State("s0"), Event(event), State("s1"));
		}

		let built = builder.timing_constraints(constraints).build();
		built.expect("a timed process names its initial state")
	}

	/// The process `name` whose `event` takes `from` to each of `targets`,
	/// each an accepting state.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn fan_out(
		name: &'static str,
		from: &'static str,
		event: &'static str,
		targets: &[&'static str],
	) -> Process {
		let built = TestProcess::fanning(name, from, event, targets).build();
		built.expect("a fan of one event builds")
	}

	/// The [`Self::fan_out`] process whose `from` is a declared choice point.
	pub(crate) fn choosing(
		name: &'static str,
		from: &'static str,
		event: &'static str,
		targets: &[&'static str],
	) -> Process {
		let built = TestProcess::fanning(name, from, event, targets).add_choice(State(from)).build();
		built.expect("a choice of one event builds")
	}

	/// The builder of [`Self::fan_out`].
	fn fanning(
		name: &'static str,
		from: &'static str,
		event: &'static str,
		targets: &[&'static str],
	) -> ProcessBuilder {
		let mut builder = Process::builder(name).initial_state(State(from)).add_observable(Event(event));
		for &target in targets {
			builder = builder.add_transition(State(from), Event(event), State(target));
			builder = builder.add_terminal(State(target));
		}

		builder
	}

	/// The process `Spinning`, whose hidden `t` and `u` take `S1` to `S2` and
	/// back after `a`, with the exit `b` at `S2` to the accepting `S3`, so it
	/// can diverge after one event.
	pub(crate) fn spinning() -> Process {
		TestProcess {
			observable: &["a", "b"],
			hidden: &["t", "u"],
			transitions: &[("S0", "a", "S1"), ("S1", "t", "S2"), ("S2", "u", "S1"), ("S2", "b", "S3")],
			terminal: &["S3"],
			..TestProcess::of("Spinning", "S0")
		}
		.build()
	}

	/// The process `Accepting`, which can stop at `Idle`, which also offers
	/// `a`, and at `Done`, which `a` leads to. Its alphabet holds `b` too.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn accepting() -> Process {
		TestProcess {
			observable: &["a", "b"],
			transitions: &[("Idle", "a", "Done")],
			terminal: &["Idle", "Done"],
			..TestProcess::of("Accepting", "Idle")
		}
		.build()
	}

	/// The process `SpinningAfterA`, which takes `a`, then spins on the
	/// hidden `t` at `S1`, so it can diverge after one event.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn spinning_after_a() -> Process {
		TestProcess {
			observable: &["a"],
			hidden: &["t"],
			transitions: &[("S0", "a", "S1"), ("S1", "t", "S1")],
			..TestProcess::of("SpinningAfterA", "S0")
		}
		.build()
	}

	/// The process `EInBothAlphabets`, whose `e`, in the observable and in the
	/// hidden alphabet, takes `S0` to the accepting `S1`.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn e_in_both_alphabets() -> Process {
		TestProcess {
			observable: &["e"],
			hidden: &["e"],
			transitions: &[("S0", "e", "S1")],
			terminal: &["S1"],
			..TestProcess::of("EInBothAlphabets", "S0")
		}
		.build()
	}

	/// The process `test`, which takes `start`, then `process`, to the
	/// accepting `s2`, where `end` returns to `s2`.
	#[cfg(feature = "testing-timing")]
	pub(crate) fn start_process_end() -> Process {
		TestProcess {
			observable: &["start", "process", "end"],
			transitions: &[("s0", "start", "s1"), ("s1", "process", "s2"), ("s2", "end", "s2")],
			terminal: &["s2"],
			..TestProcess::of("test", "s0")
		}
		.build()
	}
}

/// The default profile with SHA3-512 as its digest: AES-256-GCM, ECDSA over
/// secp256k1 with SHA3-256, HKDF-SHA3-256, and AES-256 key wrap.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Sha3_512Profile;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SecurityProfile for Aes256Sha3_512Profile {
	type Digest = Sha3_512;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<k256::Secp256k1>;
	type KeyWrapOid = Aes256Wrap;
}

/// A provider that runs [`Aes256Sha3_512Profile`], so a handshake under it
/// hashes its transcript with SHA3-512.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Sha3_512Provider {
	profile: Aes256Sha3_512Profile,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl DigestProvider for Aes256Sha3_512Provider {
	type Digest = Sha3_512;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl AeadProvider for Aes256Sha3_512Provider {
	type AeadCipher = Aes256Gcm;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl KeyWrapProvider for Aes256Sha3_512Provider {
	type KeyWrap = Aes256Wrap;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SigningProvider for Aes256Sha3_512Provider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl KdfProvider for Aes256Sha3_512Provider {
	type Kdf = HkdfSha3_256;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl KeyExchangeProvider for Aes256Sha3_512Provider {
	type KeyExchange = Ecdhe<k256::Secp256k1>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl CryptoProvider for Aes256Sha3_512Provider {
	type Profile = Aes256Sha3_512Profile;
	type Kem = crate::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// `value` decoded again from its DER.
#[cfg(test)]
pub(crate) fn der_round_trip<T>(value: &T) -> T
where
	T: crate::der::Encode + for<'a> crate::der::Decode<'a>,
{
	let encoded = value.to_der().expect("the value encodes");
	T::from_der(&encoded).expect("what the encoder wrote, the decoder reads")
}

/// Poisons `lock`, as a panic while a holder holds its guard does.
#[cfg(test)]
pub(crate) fn poison<T: ?Sized>(lock: &std::sync::Mutex<T>) {
	let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _held = lock.lock();
		panic!("poison the lock");
	}));
	assert!(panicked.is_err());
	assert!(lock.is_poisoned());
}

/// Poisons `lock`, as a panic while a writer holds its guard does.
#[cfg(all(test, feature = "colony"))]
pub(crate) fn poison_write<T: ?Sized>(lock: &std::sync::RwLock<T>) {
	let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _held = lock.write();
		panic!("poison the lock");
	}));
	assert!(panicked.is_err());
	assert!(lock.is_poisoned());
}

/// `bytes` with the lowest bit of its last octet flipped.
#[cfg(test)]
pub(crate) fn flip_last(bytes: impl AsRef<[u8]>) -> Vec<u8> {
	let mut flipped = bytes.as_ref().to_vec();
	let last = flipped.last_mut().expect("the bytes hold an octet");
	*last ^= 0x01;
	flipped
}

/// The directory `scripts/cms-interop.sh` reads its samples from.
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
const SAMPLE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/cms-samples");

/// The variable that asks a sample test to write its samples.
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
const SAMPLE_VARIABLE: &str = "TIGHTBEAM_CMS_SAMPLES";

/// The key, the `kekid`, and the plaintext an outside CMS reader recovers
/// from one `KEKRecipientInfo` sample, all from fixed test keys.
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
pub(crate) struct KekOpening {
	kek: Vec<u8>,
	key_identifier: Vec<u8>,
	plaintext: Vec<u8>,
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
impl KekOpening {
	/// Collects what opens a seal under `kek`, which `key_identifier` names,
	/// over `plaintext`.
	pub(crate) fn new(
		kek: impl Into<Vec<u8>>,
		key_identifier: impl Into<Vec<u8>>,
		plaintext: impl Into<Vec<u8>>,
	) -> Self {
		Self {
			kek: kek.into(),
			key_identifier: key_identifier.into(),
			plaintext: plaintext.into(),
		}
	}
}

/// `bytes` as lowercase hexadecimal, the form `openssl cms -secretkey`
/// reads.
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Write each of `samples` to [`SAMPLE_DIR`] under its name, what opens each
/// `KEKRecipientInfo` sample of `openings`, and the DER of each of
/// `certificates`, when the environment holds [`SAMPLE_VARIABLE`].
#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
pub(crate) fn write_interop_samples(
	samples: &[(&str, Vec<u8>)],
	openings: &[(&str, &KekOpening)],
	certificates: &[(&str, &Certificate)],
) {
	if std::env::var_os(SAMPLE_VARIABLE).is_none() {
		return;
	}

	let write = |path: String, contents: &[u8]| {
		std::fs::write(path, contents).expect("the sample directory takes the sample");
	};

	std::fs::create_dir_all(SAMPLE_DIR).expect("the sample directory exists or is created");

	for (name, der) in samples {
		write(format!("{SAMPLE_DIR}/{name}.der"), der);
	}
	for (name, opening) in openings {
		write(format!("{SAMPLE_DIR}/{name}.kek"), hex(&opening.kek).as_bytes());
		write(format!("{SAMPLE_DIR}/{name}.kekid"), hex(&opening.key_identifier).as_bytes());
		write(format!("{SAMPLE_DIR}/{name}.plain"), &opening.plaintext);
	}
	for (name, certificate) in certificates {
		let der = certificate.to_der().expect("a test certificate encodes");
		write(format!("{SAMPLE_DIR}/{name}.crt"), &der);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::builder::MetadataBuilder;
	use crate::decode;
	use crate::testing::TestResult;
	use crate::{Metadata, Version};

	#[cfg(all(feature = "builder", feature = "compress"))]
	use crate::cms::signed_data::EncapsulatedContentInfo;
	#[cfg(all(feature = "builder", feature = "compress"))]
	use crate::compress::Compressor;
	#[cfg(all(feature = "builder", feature = "compress"))]
	use crate::error::CompressionResult;
	#[cfg(all(feature = "builder", feature = "compress"))]
	use crate::CompressedData;

	/// A sample message carries the content its caller names.
	#[test]
	#[cfg(feature = "std")]
	fn a_sample_message_carries_the_content_its_caller_names() {
		let message = TestMessage::sample(Some("Test content"));
		assert_eq!(message, TestMessage { content: "Test content".into() });
	}

	/// A V0 test frame carries the id its caller names.
	#[test]
	fn a_test_frame_carries_the_id_its_caller_names() {
		let frame = TestFrame::v0(None, Some("named-id"));
		assert_eq!(frame.metadata().id(), b"named-id");
	}

	/// A value matches the cleartext frame that carries it.
	#[test]
	fn an_expected_message_matches_the_frame_that_carries_it() {
		let frame = TestFrame::v0(Some("carried"), None);
		assert!(TestMessage::sample(Some("carried")).matches(&frame));
	}

	/// A cleartext frame is no carrier of a type that requires
	/// confidentiality, so a value of that type matches no such frame, though
	/// the body decodes as that type.
	#[test]
	fn an_expected_message_matches_no_frame_that_fails_a_requirement_of_its_type() -> TestResult {
		let frame = TestFrame::v0(Some("sealed"), None);
		let expected = ConfidentialNote { content: "sealed".into() };

		let decoded: ConfidentialNote = decode(frame.message())?;
		assert_eq!(decoded, expected);
		assert!(!expected.matches(&frame));
		Ok(())
	}

	/// A body that still needs an inflate is opaque, so a value matches no
	/// compressed frame, though the body holds the encoding of that value.
	#[cfg(all(feature = "builder", feature = "compress"))]
	#[test]
	fn an_expected_message_matches_no_frame_whose_body_needs_an_inflate() -> TestResult {
		let message = TestMessage::sample(Some("stored"));
		let frame = compose! { V0: id: "stored", order: 1u64, message: message, compactness: Stored }?;

		let decoded: TestMessage = decode(frame.message())?;
		let expected = TestMessage::sample(Some("stored"));
		assert_eq!(decoded, expected);
		assert!(!expected.matches(&frame));
		Ok(())
	}

	/// A compressor that keeps the body as it is, so the body of a frame that
	/// names it still decodes as the message type.
	#[cfg(all(feature = "builder", feature = "compress"))]
	struct Stored;

	#[cfg(all(feature = "builder", feature = "compress"))]
	impl Compressor for Stored {
		fn compress(
			&self,
			data: &[u8],
			content_info: Option<EncapsulatedContentInfo>,
		) -> CompressionResult<(Vec<u8>, CompressedData)> {
			use crate::cms::content_info::CmsVersion;
			use crate::oids::DATA;

			let compression_alg = AlgorithmIdentifierOwned { oid: STORED, parameters: None };
			let encap_content_info =
				content_info.unwrap_or(EncapsulatedContentInfo { econtent_type: DATA, econtent: None });
			let compressed = CompressedData { version: CmsVersion::V0, compression_alg, encap_content_info };

			Ok((data.to_vec(), compressed))
		}
	}

	/// The algorithm of [`Stored`], under an arc that names no real codec.
	#[cfg(all(feature = "builder", feature = "compress"))]
	const STORED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.4");

	/// A sealed frame opens through [`TestFrame::decrypted`] inside an async
	/// test, on a thread that a tokio runtime drives.
	#[cfg(all(
		feature = "aes-gcm",
		feature = "signature",
		feature = "kdf",
		feature = "ecdh",
		feature = "tokio"
	))]
	#[tokio::test]
	async fn a_sealed_frame_opens_inside_a_runtime() -> TestResult {
		let frame = TestFrame::sealed("sealed");

		let (_, key) = TestKey::insecure_fixed_cipher();
		let opened = TestFrame::decrypted::<TestMessage>(frame, &key, None)?;
		assert_eq!(opened, TestMessage::sample(None));
		Ok(())
	}

	// A V0 metadata build keeps the id and the order it names, and carries no
	// integrity digest.
	test_builder! {
		name: a_v0_metadata_build_keeps_its_id_and_order,
		builder_type: MetadataBuilder,
		version: Version::V0,
		message: (),
		setup: |builder, _msg| {
			builder
				.with_id("test-id")
				.with_order(TestFrame::ORDER)
				.build()
		},
		assertions: |_msg, result| {
			let metadata: Metadata = result?;
			let built = (metadata.id(), metadata.order(), metadata.integrity());
			assert_eq!(built, (b"test-id".as_slice(), TestFrame::ORDER, None));
			Ok(())
		}
	}
}
