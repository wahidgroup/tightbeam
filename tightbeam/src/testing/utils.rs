use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::asn1::{
	AlgorithmIdentifier, AlgorithmIdentifierOwned, DigestInfo, EncryptedContentInfo, Frame, ObjectIdentifier,
	OctetString, SignerInfo,
};
use crate::der::Sequence;
use crate::oids::{COMPRESSION_CONTENT, HASH_SHA256, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
use crate::{decode, Message};

#[cfg(not(feature = "derive"))]
use crate::Version;

#[cfg(feature = "derive")]
use crate::Beamable;

#[cfg(feature = "aead")]
mod aead {
	pub use crate::crypto::aead::{Aes256Gcm, KeyInit};
	pub use crate::crypto::common::Key;
}

#[cfg(feature = "aead")]
use aead::*;

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

/// Simple test message
#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct TestMessage {
	pub content: String,
}

/// Simple test message
#[cfg(not(feature = "derive"))]
#[derive(Clone, Debug, PartialEq, Sequence)]
pub struct TestMessage {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
impl Message for TestMessage {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: Version = Version::V0;
}

#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(confidential)]
pub struct ConfidentialNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
#[derive(Clone, Debug, PartialEq, Sequence)]
pub struct ConfidentialNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
impl Message for ConfidentialNote {
	const MUST_BE_CONFIDENTIAL: bool = true;
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: Version = Version::V0;
}

#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile = 1)]
pub struct ConfidentialNonrepudiableNote {
	pub content: String,
}

#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(message_integrity, frame_integrity)]
pub struct IntegralNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
#[derive(Clone, Debug, PartialEq, Sequence)]
pub struct ConfidentialNonrepudiableNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
impl Message for ConfidentialNonrepudiableNote {
	const MUST_BE_CONFIDENTIAL: bool = true;
	const MUST_BE_NON_REPUDIABLE: bool = true;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: Version = Version::V0;
}

#[cfg(not(feature = "derive"))]
impl Message for IntegralNote {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = true;
	const MUST_HAVE_FRAME_INTEGRITY: bool = true;
	const MIN_VERSION: Version = Version::V0;
}

pub fn create_test_message(content: Option<&str>) -> TestMessage {
	TestMessage {
		content: content.map(|c| c.into()).unwrap_or_else(|| "Hello TightBeam!".to_string()),
	}
}

pub fn create_v0_tightbeam(content: Option<&str>, id: Option<&str>) -> Frame {
	let message = create_test_message(content);

	#[cfg(feature = "std")]
	let order = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("Time went backwards")
		.as_secs();

	#[cfg(not(feature = "std"))]
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

	#[cfg(feature = "derive")]
	let result = compose! {
		V0: id: id,
			order: order,
			message: message
	};

	#[cfg(not(feature = "derive"))]
	let result = Frame::new_v0(id, order, &message);

	result.expect("Failed to create TightBeam message")
}

/// Build a V1 frame carrying a Sha3-256 frame integrity (FI) digest.
#[cfg(all(feature = "builder", feature = "digest", feature = "sha3"))]
pub fn create_frame_with_frame_integrity() -> Frame {
	let message = create_test_message(None);
	compose! {
		V1: id: "fi-frame",
			order: 1u64,
			message: message,
			frame_integrity: type Sha3_256
	}
	.expect("Failed to create frame with frame integrity")
}

#[cfg(all(feature = "secp256k1", feature = "signature"))]
mod signing {
	pub use k256::ecdsa::SigningKey;
}

#[cfg(all(feature = "secp256k1", feature = "signature"))]
use signing::*;

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
mod cert {
	pub use crate::crypto::sign::ecdsa::{Secp256k1, Signature};
	pub use crate::crypto::sign::sign_canonical;
	pub use crate::der::asn1::{BitString, Ia5String, PrintableString, SetOfVec, UtcTime};
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::{Any, Decode, Encode};
	pub use crate::error::Result as TbResult;
	pub use crate::spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
	pub use crate::x509::attr::AttributeTypeAndValue;
	pub use crate::x509::ext::pkix::name::GeneralName;
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

#[cfg(all(feature = "secp256k1", feature = "signature"))]
pub fn create_test_signing_key() -> SigningKey {
	let secret_bytes = [1u8; 32];
	SigningKey::from_bytes(&secret_bytes.into()).expect("Failed to create signing key")
}

/// Fixed test validity window: epoch through a far-future UtcTime.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_validity() -> TbResult<Validity> {
	let not_before = Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(0))?);
	let not_after = Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(2_000_000_000))?);
	let validity = Validity { not_before, not_after };
	Ok(validity)
}

/// ECDSA-with-SHA3-256 algorithm identifier used by the test cert fixtures.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_signature_algorithm() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
}

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub fn create_test_certificate(signing_key: &SigningKey) -> Certificate {
	test_certificate_with_extensions(signing_key, None)
}

/// [`create_test_certificate`] variant carrying each of `uris` as a URI
/// Subject Alternative Name entry (RFC 5280 §4.2.1.6).
///
/// The subject stays empty: identity claims such as colony membership
/// bind to the SAN, never the subject. With an empty subject the SAN
/// MUST be critical (RFC 5280 §4.2.1.6), which `test_extension`
/// already provides.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub fn create_test_certificate_with_uri_sans(signing_key: &SigningKey, uris: &[&str]) -> Certificate {
	test_certificate_named_with_uri_sans(signing_key, RdnSequence::default(), uris)
}

/// [`create_test_certificate_with_uri_sans`] variant with a `CN=<cn>`
/// subject and issuer.
///
/// Trust-store issuer selection commits to the first subject-DN match
/// (see [`CertificateValidation::evaluate`]), so a store anchoring
/// several self-signed identities needs each under a distinct DN. The
/// empty-subject SAN fixtures all share one DN and would collide.
///
/// [`CertificateValidation::evaluate`]: crate::crypto::x509::policy::CertificateValidation::evaluate
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub fn create_test_certificate_with_cn_and_uri_sans(signing_key: &SigningKey, cn: &str, uris: &[&str]) -> Certificate {
	let name = test_cn_name(cn).expect("test common names satisfy PrintableString");
	test_certificate_named_with_uri_sans(signing_key, name, uris)
}

/// Shared body of the URI-SAN fixtures: `name` as both subject and
/// issuer (self-signed shape), each of `uris` as a SAN entry.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_named_with_uri_sans(signing_key: &SigningKey, name: RdnSequence, uris: &[&str]) -> Certificate {
	let names = uris
		.iter()
		.map(|uri| {
			let uri = Ia5String::new(uri).expect("test URIs are IA5 text");
			GeneralName::UniformResourceIdentifier(uri)
		})
		.collect();
	let san = SubjectAltName(names);

	test_certificate_named(signing_key, name, Some(vec![test_extension(&san)]))
}

/// Shared body of the placeholder-signed test certificate fixtures:
/// empty subject and issuer, fixed serial, caller-chosen extensions.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_with_extensions(signing_key: &SigningKey, extensions: Option<Vec<Extension>>) -> Certificate {
	test_certificate_named(signing_key, RdnSequence::default(), extensions)
}

/// Placeholder-signed test certificate with `name` as both subject and
/// issuer, fixed serial, and caller-chosen extensions.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_certificate_named(
	signing_key: &SigningKey,
	name: RdnSequence,
	extensions: Option<Vec<Extension>>,
) -> Certificate {
	let verifying_key = *signing_key.verifying_key();
	let public_key_der = verifying_key
		.to_public_key_der()
		.expect("test verifying key encodes to SPKI DER");
	let subject_public_key_info =
		SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes()).expect("freshly encoded SPKI re-decodes");
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
		extensions,
	};

	Certificate { tbs_certificate, signature_algorithm: algorithm, signature }
}

/// Wrap a DER-encodable extension value in an `Extension` (RFC 5280 §4.2).
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_extension<T>(value: &T) -> Extension
where
	T: AssociatedOid + Encode,
{
	let extn_value = OctetString::new(value.to_der().expect("extension value encodes to DER"))
		.expect("DER bytes wrap in an OctetString");
	Extension { extn_id: T::OID, critical: true, extn_value }
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

/// Digest whose output (16 bytes) is shorter than the 20-byte SKID
/// truncation window.
#[cfg(all(feature = "digest", feature = "sha3"))]
#[derive(Clone, Default)]
pub struct SixteenByteDigest(Sha3_256);

#[cfg(all(feature = "digest", feature = "sha3"))]
mod sixteen_byte_digest {
	use super::SixteenByteDigest;
	use crate::asn1::ObjectIdentifier;
	use crate::der::oid::AssociatedOid;
	use crate::oids::HASH_SHA256;
	use digest::{FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update};

	impl Update for SixteenByteDigest {
		fn update(&mut self, data: &[u8]) {
			Update::update(&mut self.0, data);
		}
	}

	impl OutputSizeUser for SixteenByteDigest {
		type OutputSize = digest::consts::U16;
	}

	impl FixedOutput for SixteenByteDigest {
		fn finalize_into(self, out: &mut Output<Self>) {
			let full = FixedOutput::finalize_fixed(self.0);
			out.copy_from_slice(&full[..16]);
		}
	}

	impl Reset for SixteenByteDigest {
		fn reset(&mut self) {
			Reset::reset(&mut self.0);
		}
	}

	impl FixedOutputReset for SixteenByteDigest {
		fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
			let full = FixedOutputReset::finalize_fixed_reset(&mut self.0);
			out.copy_from_slice(&full[..16]);
		}
	}

	impl HashMarker for SixteenByteDigest {}

	impl AssociatedOid for SixteenByteDigest {
		const OID: ObjectIdentifier = HASH_SHA256;
	}
}

/// A certificate chain with root -> intermediate -> leaf certificates.
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
	/// Shared `[root, intermediate, leaf]` slice for handshake chain plumbing.
	pub fn to_arc(&self) -> Arc<[Certificate]> {
		Arc::from([self.root.to_owned(), self.intermediate.to_owned(), self.leaf.to_owned()])
	}
}

/// Single-AVA `CN=<cn>` distinguished name for test certificates.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn test_cn_name(cn: &str) -> TbResult<RdnSequence> {
	let cn_oid = ObjectIdentifier::new_unwrap("2.5.4.3");
	let cn_str = PrintableString::new(cn)?;
	let attr = AttributeTypeAndValue { oid: cn_oid, value: Any::from(&cn_str) };
	let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![attr])?);

	let name = RdnSequence::from(vec![rdn]);
	Ok(name)
}

/// Sign `tbs` with `key` under the test ECDSA-SHA3-256 algorithm.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
fn sign_test_certificate(
	tbs: TbsCertificate,
	algorithm: &AlgorithmIdentifierOwned,
	key: &SigningKey,
) -> TbResult<Certificate> {
	let tbs_der = tbs.to_der()?;
	let signature: Signature<Secp256k1> = sign_canonical::<Sha3_256, _>(key, &tbs_der)?;

	let certificate = Certificate {
		tbs_certificate: tbs,
		signature_algorithm: algorithm.to_owned(),
		signature: BitString::new(0, signature.to_vec())?,
	};
	Ok(certificate)
}

/// Create a valid certificate chain: root -> intermediate -> leaf.
///
/// All certificates have proper issuer/subject chaining and valid signatures.
///
/// # Errors
///
/// Returns an error if key material, DER encoding, or signing fails.
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub fn create_test_certificate_chain() -> TbResult<TestCertificateChain> {
	let root_key = SigningKey::from_bytes(&[1u8; 32].into())?;
	let intermediate_key = SigningKey::from_bytes(&[2u8; 32].into())?;
	let leaf_key = SigningKey::from_bytes(&[3u8; 32].into())?;

	let root_name = test_cn_name("Root")?;
	let inter_name = test_cn_name("Intermediate")?;
	let leaf_name = test_cn_name("Leaf")?;

	let validity = test_validity()?;
	let algorithm = test_signature_algorithm();

	// Root certificate (self-signed)
	let root_pub_der = root_key.verifying_key().to_public_key_der()?;
	let subject_public_key_info = SubjectPublicKeyInfoOwned::from_der(root_pub_der.as_bytes())?;
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
		// RFC 5280 §6.1.4(k),(n): root is a CA permitted to sign certificates.
		extensions: Some(ca_extensions(true, true, None)),
	};
	let root = sign_test_certificate(root_tbs, &algorithm, &root_key)?;

	// Intermediate certificate (signed by root)
	let inter_pub_der = intermediate_key.verifying_key().to_public_key_der()?;
	let subject_public_key_info = SubjectPublicKeyInfoOwned::from_der(inter_pub_der.as_bytes())?;
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
		// RFC 5280 §6.1.4(k),(n): intermediate is a CA permitted to sign certificates.
		extensions: Some(ca_extensions(true, true, None)),
	};
	let intermediate = sign_test_certificate(inter_tbs, &algorithm, &root_key)?;

	// Leaf certificate (signed by intermediate)
	let leaf_pub_der = leaf_key.verifying_key().to_public_key_der()?;
	let subject_public_key_info = SubjectPublicKeyInfoOwned::from_der(leaf_pub_der.as_bytes())?;
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
		extensions: None,
	};
	let leaf = sign_test_certificate(leaf_tbs, &algorithm, &intermediate_key)?;

	Ok(TestCertificateChain { root, intermediate, leaf, root_key, intermediate_key, leaf_key })
}

#[cfg(feature = "aead")]
pub fn create_test_cipher_key() -> (Key<Aes256Gcm>, Aes256Gcm) {
	let key_bytes = [0x33; 32];
	let key = Key::<Aes256Gcm>::from(key_bytes);
	let cipher = Aes256Gcm::new(&key);
	(key, cipher)
}

/// Create an expired test certificate for validation testing.
///
/// This certificate (from ssl.com) expired on August 17, 2019.
/// Useful for testing certificate expiry validation logic.
#[cfg(feature = "x509")]
pub fn create_expired_test_certificate() -> Certificate {
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

pub fn create_test_hash_info() -> DigestInfo {
	let digest = OctetString::new(vec![0u8; 32]).expect("Failed to create OctetString");
	DigestInfo { algorithm: AlgorithmIdentifier { oid: HASH_SHA256, parameters: None }, digest }
}

/// Create a certificate and key pair that expires soon (within 24 hours).
/// Returns (certificate, signing_key).
///
/// Note: This certificate was generated on 2025-11-09 and expires 2025-11-10.
/// Tests using this will fail after the expiration date.
#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
pub fn create_expiring_test_certificate() -> TbResult<(Certificate, SigningKey)> {
	// Certificate that expires on 2025-11-10 06:35:40 UTC
	let cert = crate::pem! {"
		-----BEGIN CERTIFICATE-----
		MIIBiTCCAS+gAwIBAgIBATALBglghkgBZQMEAwowLTErMCkGA1UEAwwiRXhwaXJp
		bmcgVG9tb3Jyb3cgVGVzdCBDZXJ0aWZpY2F0ZTAeFw0yNTExMDkwNjM1NDBaFw0y
		NTExMTAwNjM1NDBaMC0xKzApBgNVBAMMIkV4cGlyaW5nIFRvbW9ycm93IFRlc3Qg
		Q2VydGlmaWNhdGUwVjAQBgcqhkjOPQIBBgUrgQQACgNCAAQbhMVWexJkQJldPtWq
		ugVl1x4YNGBIGf+cF/Xp1d0Hj3C+r49Yi1QVB/7WpkLFq0Lf34Egp/Y53lEi1Hpp
		qOjRo0IwQDAdBgNVHQ4EFgQUQ65suXrNrzVLgobdsptJLJXpWHAwDwYDVR0TAQH/
		BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCwYJYIZIAWUDBAMKA0cAMEQCIA7h0vvv
		anyhANdtbmk2etj57E5fh1lI3Fg2bePzYq0kAiAL9r2v4pwP8s1uec4FT7HAUYf6
		T4zOUKsmsdnnAwTztg==
		-----END CERTIFICATE-----
	"}?;

	let key_bytes: [u8; 32] = [0x01; 32];
	let signing_key = SigningKey::from_bytes(&key_bytes.into())?;

	Ok((cert, signing_key))
}

/// Historical fixture OID used by `create_test_encryption_info` (not
/// [`crate::oids::AES_256_GCM`], which is a different identifier).
const TEST_CONTENT_ENC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

pub fn create_test_encryption_info() -> EncryptedContentInfo {
	let encrypted_content = OctetString::new(vec![0u8; 12]).expect("12-byte placeholder wraps in an OctetString");
	let content_enc_alg = AlgorithmIdentifier { oid: TEST_CONTENT_ENC_OID, parameters: None };

	EncryptedContentInfo {
		content_type: COMPRESSION_CONTENT,
		content_enc_alg,
		encrypted_content: Some(encrypted_content),
	}
}

pub fn create_test_signer_info() -> SignerInfo {
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::x509::ext::pkix::SubjectKeyIdentifier;

	let version = CmsVersion::V1;
	let skid = OctetString::new([0u8; 20]).expect("20-byte SKID wraps in an OctetString");
	let sid = SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier::from(skid));
	let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
	let signed_attrs = None;
	let signature_algorithm = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
	let signature = OctetString::new([0u8; 64]).expect("64-byte placeholder wraps in an OctetString");
	let unsigned_attrs = None;

	SignerInfo {
		version,
		sid,
		digest_alg,
		signed_attrs,
		signature_algorithm,
		signature,
		unsigned_attrs,
	}
}

/// Generic builder test macro
///
/// Similar to test_case! but specifically designed for testing builders.
/// Automatically provides a base builder instance and allows customization.
/// Passes both the input message and the resulting frame to assertions.
///
/// The `message` parameter supports two forms:
/// - Direct value: `message: create_test_message(None)`
/// - Closure: `message: || { create_test_message(None) }`
#[macro_export]
macro_rules! test_builder {
	// Closure form: message: || { ... }
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

	// Direct value form: message: some_value
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

	// Internal implementation (not exposed to users)
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

// Helper: match a Frame against various "expected" forms.
// - Frame => compare metadata.id
// - Result<Frame, E> => compare metadata.id from Ok(frame)
// - Any T: Beamable + PartialEq => decode T from frame.message and compare
pub trait ExpectedMatcher {
	fn matches(&self, frame: &Frame) -> bool;
}

impl ExpectedMatcher for Frame {
	fn matches(&self, frame: &Frame) -> bool {
		frame.metadata.id == self.metadata.id
	}
}

impl ExpectedMatcher for Arc<Frame> {
	fn matches(&self, frame: &Frame) -> bool {
		self.metadata.id == frame.metadata.id
	}
}

impl<E> ExpectedMatcher for Result<Frame, E> {
	fn matches(&self, frame: &Frame) -> bool {
		match self {
			Ok(f) => frame.metadata.id == f.metadata.id,
			Err(_) => false,
		}
	}
}

impl<T> ExpectedMatcher for T
where
	T: Message + PartialEq,
{
	fn matches(&self, frame: &Frame) -> bool {
		if let Ok(decoded) = decode::<T>(&frame.message) {
			decoded == *self
		} else {
			false
		}
	}
}

/// Async test macro with worker setup
///
/// Automatically starts a worker and passes it to the assertions block for testing.
/// Properly manages worker lifecycle with shutdown.
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

			// Build and start the worker
			let builder = $setup_body;
			let trace = std::sync::Arc::new($crate::trace::TraceCollector::new());
			let mut worker = <_ as $crate::colony::worker::Worker>::start(builder, trace).await?;

			// Run assertions with reference to worker
			let result = {
				let $worker = &mut worker;
				$assertions_body.await
			};

			// Graceful shutdown: close the queue and await run-loop exit
			worker.kill().await?;

			result
		}
	};
}

/// Async test macro with worker setup
///
/// Automatically starts a worker, creates a client, and passes the ready
/// client to the assertions block for testing. Properly manages worker
/// lifecycle.
#[macro_export]
macro_rules! test_servlet {
	// With worker_threads specified
	(
		name: $test_name:ident,
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		setup: || $setup_body:expr,
		assertions: |$client:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Call the setup closure and await the resulting future
			let worker = $setup_body.await?;
			// Get the worker address
			let addr = worker.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			worker.stop();

			result
		}
	};

	// Without worker_threads (defaults to single threaded)
	(
		name: $test_name:ident,
		protocol: $protocol:ident,
		setup: || $setup_body:expr,
		assertions: |$client:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Call the setup closure and await the resulting future
			let worker = ($setup_body).await?;

			// Get the worker address
			let addr = worker.addr();

			// Create client
			let mut $client = $crate::client! {
				async $protocol: connect addr
			}
			.await?;

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			worker.stop();

			result
		}
	};
}

/// Async test macro for hives
///
/// Automatically starts a drone, creates a client, and passes the ready
/// client to the assertions block for testing. Properly manages drone lifecycle.
///
/// Note: Gate observation channels are not yet implemented for hives.
/// The `channels` parameter is reserved for future use.
#[macro_export]
macro_rules! test_drone {
	// With worker_threads and setup callback
	(
		name: $test_name:ident,
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		setup: |$setup_drone:ident| $setup_body:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone = <$drone_type as $crate::colony::servlet::Servlet<()>>::start(
				$crate::trace::TraceCollector::new(),
				$config,
			)
			.await?;

			// Call the setup closure and await the resulting future
			let $setup_drone = drone;
			let drone = $setup_body.await;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for hives)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};

	// Without worker_threads but with setup callback
	(
		name: $test_name:ident,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		setup: |$setup_drone:ident| $setup_body:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone = <$drone_type as $crate::colony::servlet::Servlet<()>>::start(
				::std::sync::Arc::new($crate::trace::TraceCollector::new()),
				$config,
			)
			.await?;

			// Call the setup closure and await the resulting future
			let $setup_drone = drone;
			let drone = $setup_body.await;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for hives)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};

	// Simple variant without setup callback, with worker_threads
	(
		name: $test_name:ident,
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone = <$drone_type as $crate::colony::servlet::Servlet<()>>::start(
				$crate::trace::TraceCollector::new(),
				$config,
			)
			.await?;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for hives)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};

	// Simple variant without setup callback, without worker_threads
	(
		name: $test_name:ident,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone = <$drone_type as $crate::colony::servlet::Servlet<()>>::start(
				$crate::trace::TraceCollector::new(),
				$config,
			)
			.await?;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for hives)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};
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
		let message = create_test_message(Some("Test content"));
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
			assert_eq!(metadata.id, b"test-id");
			assert_eq!(metadata.order, 1696521600);
			assert!(metadata.integrity.is_none());
			Ok(())
		}
	}
}
