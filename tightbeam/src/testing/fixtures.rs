//! Test material the suite builds scenarios from.
//!
//! Each owner type names the material it makes, so a reader who looks for a
//! certificate, a frame, or a key finds one place for it.

use std::sync::Arc;

use crate::asn1::{AlgorithmIdentifier, AlgorithmIdentifierOwned, DigestInfo, Frame, ObjectIdentifier, OctetString};
use crate::der::Sequence;
use crate::oids::HASH_SHA256;
use crate::Beamable;
use crate::{decode, Message, Version};

#[cfg(host_clock)]
use crate::utils::time::UnixMillis;
#[cfg(feature = "aead")]
use aead::*;

#[cfg(feature = "aead")]
mod aead {
	pub use crate::crypto::aead::{Aes256Gcm, KeyInit};
	pub use crate::crypto::common::Key;
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

#[cfg(all(feature = "std", feature = "digest", feature = "random"))]
mod random_id {
	pub use crate::crypto::hash::Digest;
	pub use crate::random::generate_random_bytes;
}

#[cfg(all(feature = "std", feature = "digest", feature = "random"))]
use random_id::*;

#[cfg(feature = "x509")]
mod x509_certs {
	pub use crate::x509::Certificate;
}

#[cfg(feature = "x509")]
use x509_certs::*;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod sha3_512_profile {
	pub use crate::crypto::aead::Aes256GcmOid;
	pub use crate::crypto::hash::Sha3_512;
	pub use crate::crypto::kdf::HkdfSha3_256;
	pub use crate::crypto::profiles::{
		AeadProvider, Aes256Wrap, CryptoProvider, CurveProvider, DigestProvider, HpkeProvider, KdfProvider,
		KeyWrapProvider, SecurityProfile, SigningProvider,
	};
	pub use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use sha3_512_profile::*;

/// A simple message that the tests encode and send.
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct TestMessage {
	pub content: String,
}

impl TestMessage {
	pub fn sample(content: Option<&str>) -> TestMessage {
		TestMessage {
			content: content.map(|c| c.into()).unwrap_or_else(|| "Hello TightBeam!".to_string()),
		}
	}
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(confidential)]
pub struct ConfidentialNote {
	pub content: String,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile = 1)]
pub struct ConfidentialNonrepudiableNote {
	pub content: String,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(message_integrity, frame_integrity)]
pub struct IntegralNote {
	pub content: String,
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
	pub use crate::der::asn1::{BitString, Ia5String, PrintableString, SetOfVec, UtcTime};
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::{Any, Decode, Encode};
	pub use crate::error::Result as TbResult;
	pub use crate::oids::SIGNER_ECDSA_WITH_SHA3_256;
	pub use crate::spki::SubjectPublicKeyInfoOwned;
	pub use crate::x509::attr::AttributeTypeAndValue;
	pub use crate::x509::ext::pkix::name::GeneralName;
	pub use crate::x509::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
	pub use crate::x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
	pub use crate::x509::ext::Extension;
	pub use crate::x509::name::{RdnSequence, RelativeDistinguishedName};
	pub use crate::x509::serial_number::SerialNumber;
	pub use crate::x509::time::{Time, Validity};
	pub use crate::x509::{TbsCertificate, Version as X509Version};
	pub use core::time::Duration;
}

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
use cert::*;

/// Returns the fixed test validity window, which runs from the epoch through a
/// far-future UtcTime.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_validity() -> TbResult<Validity> {
	let not_before = Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(0))?);
	let not_after = Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(2_000_000_000))?);
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

/// The `keyUsage` of an end-entity test certificate, which signs and opens a
/// KEM's encapsulation as a CMS server does (RFC 5480 §3, RFC 9629 §3).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_end_entity_key_usage() -> Extension {
	test_extension(&KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement))
}

/// Builds a certificate for `subject_key` under `subject`, signed by
/// `issuer_key` under `issuer`, with a real signature.
///
/// The key identifier extensions come first, ahead of `extensions`.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn issue_test_certificate(
	issuer_key: &SigningKey,
	issuer: RdnSequence,
	subject_key: &SigningKey,
	subject: RdnSequence,
	extensions: Vec<Extension>,
) -> TbResult<Certificate> {
	let subject_public_key_info = test_public_key(subject_key);
	let algorithm = test_signature_algorithm();
	let mut all_extensions = test_key_identifiers(subject_key, issuer_key);
	all_extensions.extend(extensions);

	let tbs = TbsCertificate {
		version: X509Version::V3,
		serial_number: SerialNumber::new(&[1])?,
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

/// Builds the shared body of the placeholder-signed test certificate fixtures,
/// with an empty subject and issuer, a fixed serial, and caller-chosen
/// extensions.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_with_extensions(signing_key: &SigningKey, extensions: Option<Vec<Extension>>) -> Certificate {
	test_certificate_named(signing_key, RdnSequence::default(), extensions)
}

/// Builds a placeholder-signed test certificate with `name` as both the subject
/// and the issuer, a fixed serial, its key identifier, and caller-chosen
/// extensions after it.
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
	let signature = BitString::new(0, vec![0; 64]).expect("64-byte placeholder is a valid BitString");

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

	Certificate { tbs_certificate, signature_algorithm: algorithm, signature }
}

/// Wrap a DER-encodable extension value in a critical `Extension` (RFC 5280
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

/// Wrap a DER-encodable extension value in a non-critical `Extension`, the
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
	pub root: Certificate,
	pub intermediate: Certificate,
	pub leaf: Certificate,
	pub root_key: SigningKey,
	pub intermediate_key: SigningKey,
	pub leaf_key: SigningKey,
}

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl TestCertificateChain {
	/// Return the chain as a shared `[root, intermediate, leaf]` slice for the
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

/// Sign `tbs` with `key` under the test ECDSA-SHA3-256 algorithm.
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

/// Generic builder test macro.
///
/// The macro works like `test_case!` for builders. It provides a base
/// builder instance, allows customization, and passes both the input message
/// and the resulting frame to the assertions.
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

	// Internal arm that the two public forms expand into.
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

/// Match a [`Frame`] against an expected value in one of these forms:
///
/// - A `Frame` or an `Arc<Frame>` compares `metadata.id`.
/// - A `Result<Frame, E>` compares `metadata.id` of the `Ok` frame.
/// - Any `T: Beamable + PartialEq` decodes `T` from `frame.message` and compares.
pub trait ExpectedMatcher {
	fn matches(&self, frame: &Frame) -> bool;
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
		if let Ok(decoded) = decode::<T>(frame.message()) {
			decoded == *self
		} else {
			false
		}
	}
}

/// Async test macro with worker setup.
///
/// The macro starts a worker, passes it to the assertions block, and shuts
/// the worker down afterwards.
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
			// assertion still stops the worker.
			worker.kill().await?;

			result
		}
	};
}

/// Frames in the shapes the suite sends.
pub struct TestFrame;

impl TestFrame {
	pub fn v0(content: Option<&str>, id: Option<&str>) -> Frame {
		let message = TestMessage::sample(content);

		#[cfg(host_clock)]
		let order = core::time::Duration::from_millis(UnixMillis::now().get()).as_secs();

		#[cfg(not(host_clock))]
		let order: u64 = 1_700_000_000;

		#[cfg(all(feature = "std", feature = "digest", feature = "random"))]
		let id = id.unwrap_or({
			let mut bytes: [u8; 32] = [0; 32];
			generate_random_bytes(&mut bytes, None).expect("Failed to generate random bytes");

			let hash = Sha3_256::digest(bytes);
			Box::leak(format!("{hash:x}").into_boxed_str())
		});

		#[cfg(not(all(feature = "std", feature = "digest", feature = "random")))]
		let id = id.unwrap_or("test-message-id");

		let result = compose! {
			V0: id: id,
				order: order,
				message: message
		};

		result.expect("Failed to create TightBeam message")
	}

	/// Build a V1 frame carrying a Sha3-256 frame integrity (FI) digest.
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

	/// Build a V2 frame that carries a priority, a field that V0 and V1 forbid.
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
	/// A test models tampering in transit this way, because no method rewrites
	/// a digested or signed field in place. The two byte strings MUST have one
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
	/// `SignerInfo` enters through the DER decoder, as it would off the wire.
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
		let (r, s) = scalars.split_scalars();
		let high = Signature::<Secp256k1>::from_scalars(r, -s).expect("n - s is a scalar");
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

	/// Returns the DER of `container` with the version of its embedded `frame`
	/// rewritten to `version`.
	///
	/// No constructor yields a frame whose version forbids a field it carries.
	/// A test that feeds such a frame to a decoder forges the bytes here.
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

/// Signing and cipher keys with fixed, test-only material.
pub struct TestKey;

impl TestKey {
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
		let secret_bytes = [1u8; 32];
		SigningKey::from_bytes(&secret_bytes.into()).expect("Failed to create signing key")
	}

	/// The RFC 7093 §2 method 1 key identifier of the public key of
	/// [`Self::insecure_fixed_signing`]: the leftmost 160 bits of SHA-256 of
	/// the uncompressed point `04 1b84c556..dd078f 70beaf8f..69a8e8d1`. An
	/// independent computation (Python's `hashlib`) gave this value.
	pub const INSECURE_FIXED_KEY_IDENTIFIER: [u8; 20] = [
		0xc0, 0xc5, 0xe0, 0xd9, 0x27, 0xe4, 0xcc, 0xbb, 0x5b, 0xbf, 0x03, 0xd5, 0x0d, 0xae, 0x76, 0xa7, 0x91, 0x14,
		0xa2, 0x96,
	];

	/// Returns the AES-256-GCM key made of thirty-two `0x33` bytes, with its
	/// cipher.
	///
	/// # Security
	///
	/// The key is public, so nothing sealed under it is confidential.
	/// Production code draws its key from a CSPRNG.
	#[cfg(feature = "aead")]
	pub fn insecure_fixed_cipher() -> (Key<Aes256Gcm>, Aes256Gcm) {
		let key_bytes = [0x33; 32];

		let key = Key::<Aes256Gcm>::from(key_bytes);
		let cipher = Aes256Gcm::new(&key);
		(key, cipher)
	}
}

/// Certificates and chains in the shapes the trust stores accept or refuse.
pub struct TestCertificate;

impl TestCertificate {
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn self_signed(signing_key: &SigningKey) -> Certificate {
		test_certificate_with_extensions(signing_key, None)
	}

	/// Builds a [`Self::self_signed`] variant that carries each of `uris` as a
	/// URI Subject Alternative Name entry (RFC 5280 §4.2.1.6).
	///
	/// The subject stays empty, because identity claims such as colony
	/// membership bind to the SAN and not to the subject. With an empty subject
	/// the SAN MUST be critical (RFC 5280 §4.2.1.6), which `test_extension`
	/// provides.
	#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
	pub fn with_uri_sans(signing_key: &SigningKey, uris: &[&str]) -> Certificate {
		test_certificate_named_with_uri_sans(signing_key, RdnSequence::default(), uris)
	}

	/// Builds a [`Self::with_uri_sans`] variant with a `CN=<cn>` subject and
	/// issuer.
	///
	/// Trust-store issuer selection commits to the first subject-DN match (see
	/// [`CertificateValidation::evaluate`]), so a store that anchors more than
	/// one self-signed identity needs each under a distinct DN. The
	/// empty-subject SAN fixtures all share one DN and would collide.
	///
	/// [`CertificateValidation::evaluate`]: crate::crypto::x509::policy::CertificateValidation::evaluate
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

	/// Build CA issuer extensions: `basicConstraints` (RFC 5280 §4.2.1.9) and
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
		issue_test_certificate(signing_key, name.to_owned(), signing_key, name, extensions)
	}

	/// Builds a leaf `CN=<cn>` that the authority `CN=<issuer_cn>` signs with
	/// `issuer_key`, carrying each of `uris` as a URI Subject Alternative Name.
	///
	/// A store that holds the authority validates this leaf by its chain. It
	/// does not hold the leaf, so it resolves no signer for the leaf's key.
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
		issue_test_certificate(issuer_key, issuer, signing_key, subject, extensions)
	}

	/// Create a valid certificate chain in which a root signs an intermediate
	/// and the intermediate signs a leaf.
	///
	/// Every certificate has proper issuer and subject chaining and a valid
	/// signature.
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

	/// Create an expired test certificate for validation testing.
	///
	/// This certificate from ssl.com expired on August 17, 2019, so it
	/// exercises the expiry validation logic.
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
}

/// Signer material for CMS structures.
///
/// The CMS signer signs fixed placeholder content under the fixed test key,
/// because these tests exercise the encoding of a frame's signature slot.
#[cfg(all(feature = "secp256k1", feature = "signature"))]
pub struct TestSigner;

#[cfg(all(feature = "secp256k1", feature = "signature"))]
impl TestSigner {
	/// A `SignerInfo` the CMS signer built over placeholder content.
	pub fn info() -> crate::crypto::sign::Signed<crate::SignerInfo> {
		use crate::crypto::sign::{CmsSigner, SignedContent};

		let key = TestIdentity::certified(TestKey::insecure_fixed_signing());
		let content = SignedContent::data(b"test signer content");
		CmsSigner::sign_with::<Secp256k1Signature, _>(&key, content).expect("the fixed test key signs")
	}
}

/// Reads on the signed attributes of a `SignerInfo`, which the signed
/// structure tests share.
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
}

/// Signing identities, each a certificate beside the key that proves it.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub struct TestIdentity;

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
impl TestIdentity {
	/// The identity of `key` under the placeholder-signed
	/// [`TestCertificate::self_signed`] certificate.
	pub fn of(key: &SigningKey) -> SigningIdentity {
		let certificate = TestCertificate::self_signed(key);
		TestIdentity::presenting(certificate, key)
	}

	/// The identity of `certificate`, whose key is `key`.
	pub fn presenting(certificate: impl Into<Arc<Certificate>>, key: &SigningKey) -> SigningIdentity {
		let provider = Arc::new(Secp256k1KeyProvider::from(key.clone()));
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

	/// `key` beside the placeholder-signed [`TestCertificate::self_signed`]
	/// certificate, for a builder that signs in place.
	pub fn certified(key: SigningKey) -> CertifiedKey<SigningKey> {
		let certificate = TestCertificate::self_signed(&key);
		CertifiedKey::new(&certificate, key).expect("the test key matches its certificate")
	}
}

/// Digest material for CMS structures.
pub struct TestDigest;

impl TestDigest {
	pub fn info() -> DigestInfo {
		let digest = OctetString::new(vec![0u8; 32]).expect("Failed to create OctetString");
		DigestInfo { algorithm: AlgorithmIdentifier { oid: HASH_SHA256, parameters: None }, digest }
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
	type Curve = k256::Secp256k1;
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
impl CurveProvider for Aes256Sha3_512Provider {
	type Curve = k256::Secp256k1;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl CryptoProvider for Aes256Sha3_512Provider {
	type Profile = Aes256Sha3_512Profile;
	type Kem = crate::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HpkeProvider for Aes256Sha3_512Provider {
	type HpkeSuite = crate::crypto::hpke::HpkeSecp256k1Sha3Aes256Gcm;
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::builder::MetadataBuilder;
	use crate::error::Result as TbResult;
	use crate::{Metadata, Version};

	#[test]
	#[cfg(feature = "std")]
	fn test_create_test_message() -> TbResult<()> {
		let message = TestMessage::sample(Some("Test content"));
		assert_eq!(message.content, "Test content");
		Ok(())
	}

	test_builder! {
		name: test_metadata_builder_basic,
		builder_type: MetadataBuilder,
		version: Version::V0,
		message: (),
		setup: |builder, _msg| {
			builder
				.with_id("test-id")
				.with_order(1696521600)
				.build()
		},
		assertions: |_msg, result| {
			let metadata: Metadata = result?;
			assert_eq!(metadata.id(), b"test-id");
			assert_eq!(metadata.order(), 1696521600);
			assert!(metadata.integrity().is_none());
			Ok(())
		}
	}
}
