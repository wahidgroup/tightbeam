//! Shared test utilities for handshake protocol tests.
//!
//! It holds the fixtures, functions, and data structures that every handshake
//! test module shares, so each setup has one home.
#![allow(unused)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::str::FromStr;
use core::time::Duration;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rand_core::{CryptoRng, RngCore};

use crate::asn1::OctetString;
use crate::cms::cert::CertificateChoices;
use crate::cms::content_info::ContentInfo as ContentInfoValue;
use crate::cms::signed_data::SignedData;
use crate::cms::signed_data::SignerIdentifier;
use crate::constants::{
	TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_ACK_KEY_ID_DOMAIN, TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO,
};
use crate::crypto::aead::{DirectionalCiphers, KeyInit, RecordDirection, RecvCipher, RuntimeAead};
use crate::crypto::cms::{AuthEnvelopedData, Opener};
use crate::crypto::common::KeySizeUser;
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{EcdhSecret, KdfFunction, KdfSalt};
use crate::crypto::key::{KeyBackend, KeyError, Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::policy::Secp256k1Policy;
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider, KdfProvider, Kek, SecurityProfileDesc};
use crate::crypto::secret::SecretSlice;
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use crate::crypto::sign::elliptic_curve::sec1::{CompressedPoint as Sec1CompressedPoint, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::{CanonicalSigner, CmsSigner, Signed, SignedContent, SignedDataExt, SigningIdentity};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
use crate::crypto::x509::store::{
	CertificateTrust, CertificateTrustBuilder, CertificateTrustStore, RevocationChecker, TrustBuilder,
};
use crate::crypto::x509::utils::Skid;
use crate::crypto::x509::{ErasedSigning, KeyPurposes, PeerCertificate};
use crate::der::asn1::BitString;
use crate::der::asn1::GeneralizedTime;
use crate::der::asn1::{Any as AnyValue, ContextSpecificRef, ObjectIdentifier, PrintableString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode, EncodeValue, TagMode, TagNumber, Tagged};
use crate::marker::MaybeSendFuture;
use crate::oids::{AES_256_WRAP, DATA, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256};
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
pub use crate::testing::fixtures::{TestCertificate as CertificateFixtures, TestCertificateChain};
use crate::testing::{TestCmsServer, TestIdentity};
use crate::transport::handshake::flow::ClientFlow;
use crate::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, RunnableProfile, TransportAuthorizer, TransportOffer,
};
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::receipt::{
	ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
};
use crate::transport::handshake::{
	Client, ClientConfig, ClientHello, EstablishedSession, Handshake, HandshakeAttribute, HandshakeError,
	HandshakeMessage, HandshakeSecret, PeerAuthentication, Server, ServerConfig, ServerFlow, ServerHandshake,
	SupportedProfiles,
};
use crate::x509::attr::AttributeTypeAndValue;
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use crate::x509::ext::Extension;
use crate::x509::name::RelativeDistinguishedName;
use crate::x509::serial_number::SerialNumber;
use crate::x509::time::Time;
use crate::x509::time::Validity;
use crate::x509::Certificate;
use crate::x509::{name::RdnSequence, TbsCertificate, Version};
use crate::TightBeamError;
use crate::ZeroizingBytes;

#[cfg(feature = "transport-hpke")]
use crate::transport::handshake::schedule::CompressedPoint;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::{
	Agreement, BaseSecret, HandshakeAgreement, KeyConfirmation, PeerEphemeral, PeerPoint, Sealer, SecretSeal,
};

#[cfg(feature = "transport-hpke")]
mod hpke {
	pub use crate::cms::content_info::ContentInfo;
	pub use crate::crypto::x509::policy::DirectTrustValidator;
	pub use crate::der::asn1::OctetStringRef;
	pub use crate::der::{Any, Tag};
	pub use crate::oids::HANDSHAKE_REPLY_CONTENT;
	pub use crate::transport::handshake::{Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust};
}

#[cfg(feature = "transport-hpke")]
use hpke::*;

#[cfg(feature = "transport-cms")]
mod cms {
	pub use crate::cms::enveloped_data::OriginatorPublicKey;
	pub use crate::constants::TIGHTBEAM_OPENING_UKM_LABEL;
	pub use crate::crypto::cms::KeyAgreementIdentity;
	pub use crate::crypto::hpke::DhKemSecp256k1;
	pub use crate::oids::{HANDSHAKE_OPENING_CONTENT, HANDSHAKE_SERVER_EPHEMERAL, RECEIPT_ACK};
	pub use crate::transport::handshake::attributes::HandshakeAttributes;
	pub use crate::transport::handshake::{
		Cms, CmsClientSettings, CmsIdentityPair, CmsServerSettings, ProvisionedTrust,
	};
}

#[cfg(feature = "transport-cms")]
use crate::transport::handshake::flow::OpeningContent;
#[cfg(feature = "transport-cms")]
use cms::*;

/// The default test profile, the one [`DefaultCryptoProvider`] runs.
pub fn create_default_test_profile() -> SecurityProfileDesc {
	RunnableProfile::<DefaultCryptoProvider>::native().descriptor()
}

/// A test certificate beside its signing key, so every test creates
/// certificates the same way.
#[derive(Debug, Clone)]
pub struct TestCertificate {
	/// The signing key whose public key the certificate carries.
	pub signing_key: Secp256k1SigningKey,
	/// The certificate over the public key of `signing_key`.
	pub certificate: Certificate,
}

/// The two values of the one RDN of [`two_valued_name`]: a CN and an O.
pub fn rdn_values() -> [AttributeTypeAndValue; 2] {
	let value = |oid: &str, text: &str| {
		let text = PrintableString::new(text).expect("the text is printable");
		AttributeTypeAndValue { oid: ObjectIdentifier::new_unwrap(oid), value: AnyValue::from(&text) }
	};
	[value("2.5.4.3", "server"), value("2.5.4.10", "tightbeam")]
}

/// A name of one RDN that holds both [`rdn_values`]. DER sorts the values
/// of the RDN's SET OF, and a decoder restores that order.
pub fn two_valued_name() -> RdnSequence {
	let values = SetOfVec::try_from(rdn_values().to_vec()).expect("two distinct values are a SET");
	RdnSequence::from(vec![RelativeDistinguishedName::from(values)])
}

/// The bytes of `reply` with the two values of [`two_valued_name`] swapped,
/// another encoding of the same certificate value, which DER forbids.
pub fn with_rdn_values_swapped(reply: &HandshakeMessage) -> Vec<u8> {
	let name = two_valued_name();
	let values = name.0.iter().flat_map(|rdn| rdn.0.iter());
	let sorted: Vec<Vec<u8>> = values.map(|value| value.to_der().expect("a value encodes")).collect();
	let encoded = sorted.concat();
	let swapped = sorted.iter().rev().flatten().copied().collect::<Vec<u8>>();
	let carried = reply.der().windows(encoded.len()).position(|window| window == encoded);
	let (head, tail) = reply.der().split_at(carried.expect("the reply carries the RDN"));
	[head, swapped.as_slice(), &tail[encoded.len()..]].concat()
}

/// Create a test certificate with a secp256k1 keypair.
///
/// Every handshake test creates its certificate this way. The certificate
/// uses minimal valid data and a long validity period.
pub fn create_test_certificate() -> TestCertificate {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let certificate = create_test_certificate_inner(&signing_key).expect("Test certificate creation should succeed");
	TestCertificate { signing_key, certificate }
}

/// The identity a test server holds: a signing certificate and a
/// key-agreement certificate of one subject, both issued by one test
/// authority, each beside its key.
///
/// An HPKE server signs with the signing certificate alone, and a CMS server
/// holds both as its pair.
#[derive(Debug, Clone)]
pub struct TestServerIdentity {
	/// The certificate whose key signs the reply, beside that key.
	pub signing: TestCertificate,
	/// The certificate whose key the CMS opening seals to, beside that key.
	pub key_agreement: TestCertificate,
	/// The authority that issued both certificates.
	pub authority: Certificate,
	/// The key of [`Self::authority`].
	pub authority_key: Secp256k1SigningKey,
}

impl TestServerIdentity {
	/// The certificates and keys as the shared test fixture holds them.
	pub fn fixture(&self) -> TestCmsServer {
		TestCmsServer {
			authority: self.authority.to_owned(),
			authority_key: self.authority_key.to_owned(),
			signing: self.signing.certificate.to_owned(),
			signing_key: self.signing.signing_key.to_owned(),
			key_agreement: self.key_agreement.certificate.to_owned(),
			key_agreement_key: self.key_agreement.signing_key.to_owned(),
		}
	}

	/// The key-agreement identity of the server.
	#[cfg(feature = "transport-cms")]
	pub fn key_agreement_identity(&self) -> KeyAgreementIdentity<DhKemSecp256k1> {
		self.fixture().key_agreement_identity()
	}

	/// The pair a CMS server of this identity holds.
	#[cfg(feature = "transport-cms")]
	pub fn pair(&self) -> CmsIdentityPair<DhKemSecp256k1> {
		self.fixture().pair()
	}

	/// The trust of a CMS client that provisions this server.
	#[cfg(feature = "transport-cms")]
	pub fn trust(&self) -> ProvisionedTrust {
		self.fixture().trust()
	}

	/// A store that holds the authority of both certificates.
	pub fn store(&self) -> CertificateTrustStore {
		self.fixture().store()
	}

	/// A store that holds the authority of both certificates and consults
	/// `checker` on revocation.
	pub fn store_with(&self, checker: impl RevocationChecker + 'static) -> CertificateTrustStore {
		self.fixture().store_with(checker)
	}
}

/// A revocation checker that revokes one certificate once [`Self::revoke`]
/// runs, as a store whose verdict on a certificate changes after a trust is
/// built. Each clone shares the one switch.
#[derive(Debug, Clone)]
pub struct LaterRevocation {
	certificate: Arc<Certificate>,
	revoked: Arc<AtomicBool>,
}

impl LaterRevocation {
	/// A checker that will revoke `certificate`.
	pub fn of(certificate: Certificate) -> Self {
		Self { certificate: Arc::new(certificate), revoked: Arc::new(AtomicBool::new(false)) }
	}

	/// Revoke the certificate from here on.
	pub fn revoke(&self) {
		self.revoked.store(true, Ordering::SeqCst);
	}
}

impl RevocationChecker for LaterRevocation {
	fn check(&self, _issuer: &Certificate, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let revoked = self.revoked.load(Ordering::SeqCst) && *cert == *self.certificate;
		match revoked {
			true => Err(CertificateValidationError::CertificateRevoked),
			false => Ok(()),
		}
	}
}

/// Create a test server identity with fresh keys under a fresh authority.
pub fn create_test_server() -> TestServerIdentity {
	TestServerIdentity::from(TestCmsServer::generate("tightbeam test server"))
}

/// A test server whose authority issues both of its certificates to
/// `subject`.
pub fn create_named_test_server(subject: RdnSequence) -> TestServerIdentity {
	TestServerIdentity::from(TestCmsServer::named(subject))
}

/// The certificates and keys of the shared test fixture, as a test server
/// holds them.
impl From<TestCmsServer> for TestServerIdentity {
	fn from(server: TestCmsServer) -> Self {
		let TestCmsServer { authority, authority_key, signing, signing_key, key_agreement, key_agreement_key } = server;
		let signing = TestCertificate { signing_key, certificate: signing };
		let key_agreement = TestCertificate { signing_key: key_agreement_key, certificate: key_agreement };
		TestServerIdentity { signing, key_agreement, authority, authority_key }
	}
}

/// A test server whose signing certificate sits under an intermediate, which
/// the server presents beside it.
///
/// The root of the fixed test chain issued the intermediate, which issued the
/// signing certificate, and the root issued the key-agreement certificate of
/// the same subject. A store that holds the root alone admits both once the
/// reply presents the intermediate.
pub struct ChainedTestServer {
	/// The identity, whose authority is the root of the chain.
	pub identity: TestServerIdentity,
	/// The intermediate that issued the signing certificate.
	pub intermediate: Certificate,
}

impl ChainedTestServer {
	/// The server of the fixed test chain, with a fresh key-agreement key.
	pub fn fixed() -> Self {
		let chain = CertificateFixtures::insecure_fixed_chain().expect("the fixed test chain issues");
		let TestCertificateChain { root, intermediate, leaf, root_key, leaf_key, .. } = chain;
		let key_agreement_key = create_test_signing_key();
		let usage = KeyUsage(KeyUsages::KeyAgreement.into());
		let key_agreement = CertificateFixtures::issued(&root_key, "Root", &key_agreement_key, "Leaf", 4, usage);
		let key_agreement = key_agreement.expect("the root issues the key-agreement certificate");

		let signing = TestCertificate { signing_key: leaf_key, certificate: leaf };
		let key_agreement = TestCertificate { signing_key: key_agreement_key, certificate: key_agreement };
		let identity = TestServerIdentity { signing, key_agreement, authority: root, authority_key: root_key };
		Self { identity, intermediate }
	}

	/// The signing identity of the server, which presents the intermediate.
	pub fn signing_identity(&self) -> SigningIdentity {
		let identity = signing_identity(&self.identity.signing).with_chain([self.intermediate.to_owned()]);
		identity.expect("the intermediate issued the signing certificate")
	}

	/// The intermediate that the root issues again under another serial
	/// number. It has the subject and the key of the intermediate, so it
	/// validates where the intermediate does.
	pub fn intermediate_twin(&self) -> Certificate {
		reissued(&self.intermediate, &self.identity.authority_key, 9)
	}
}

/// The DER of the `certificates` field of a `SignedData` that holds
/// `certificates`, the bytes a handshake transcript binds.
pub fn certificates_field(certificates: impl IntoIterator<Item = Certificate>) -> Vec<u8> {
	let choices: Vec<CertificateChoices> = certificates.into_iter().map(CertificateChoices::Certificate).collect();
	let set = SetOfVec::try_from(choices).expect("distinct certificates are a SET");
	let field = ContextSpecificRef { tag_number: TagNumber::N0, tag_mode: TagMode::Implicit, value: &set };
	field.to_der().expect("the field encodes")
}

/// `certificate` signed again by `issuer_key` under `serial`, with its
/// subject, its key, and its extensions unchanged.
pub fn reissued(certificate: &Certificate, issuer_key: &Secp256k1SigningKey, serial: u8) -> Certificate {
	let mut tbs_certificate = certificate.tbs_certificate.to_owned();
	tbs_certificate.serial_number = SerialNumber::new(&[serial]).expect("a test serial number encodes");
	let message = tbs_certificate.to_der().expect("a test certificate encodes");
	let signature: Secp256k1Signature = issuer_key.sign_canonical::<Sha3_256>(message).expect("the issuer key signs");
	let signature = BitString::from_bytes(signature.as_bytes()).expect("a signature is a BIT STRING");
	let signature_algorithm = certificate.signature_algorithm.to_owned();

	Certificate { tbs_certificate, signature, signature_algorithm }
}

/// `reply` with `certificates` in place of the set it carries. No signature
/// covers the set, so only the transcript tells the two apart.
pub fn with_presented(
	reply: &HandshakeMessage,
	certificates: impl IntoIterator<Item = Certificate>,
) -> HandshakeMessage {
	let signed_data = reply.to_owned().signed().expect("a reply travels in a SignedData");
	let mut signed_data = signed_data.into_value();
	signed_data.certificates = Some(CertificateFixtures::set_of(certificates));
	HandshakeMessage::try_from(signed_data).expect("the reply encodes")
}

/// The certificates `reply` carries, in the order its SET holds them.
pub fn presented_certificates(reply: &HandshakeMessage) -> Vec<Certificate> {
	let signed_data = reply.to_owned().signed().expect("a reply travels in a SignedData");
	let certificates = signed_data.into_value().certificates;
	let choices = certificates.map(|set| set.0.into_vec()).unwrap_or_default();
	let certificate = |choice| match choice {
		CertificateChoices::Certificate(certificate) => Some(certificate),
		CertificateChoices::Other(_) => None,
	};

	choices.into_iter().filter_map(certificate).collect()
}

/// A test certificate whose validity period ended one second after the epoch.
pub fn create_expired_test_certificate() -> TestCertificate {
	let mut expired = create_test_certificate();
	let not_after = GeneralizedTime::from_unix_duration(Duration::from_secs(1));
	let not_after = not_after.expect("one second after the epoch is a time");

	expired.certificate.tbs_certificate.validity.not_after = Time::GeneralTime(not_after);
	expired
}

/// A test certificate of a fresh key whose validity period is the fixed test
/// window, so it is expired on [`CertificateFixtures::clock_past_validity`].
pub fn create_windowed_test_certificate() -> TestCertificate {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let certificate = CertificateFixtures::self_signed(&signing_key);
	TestCertificate { signing_key, certificate }
}

/// A certificate of the key of `identity` that differs from its own
/// certificate in its serial number alone, so its `subjectKeyIdentifier`
/// names the same key.
pub fn same_key_twin(identity: &TestCertificate) -> Certificate {
	let mut twin = identity.certificate.to_owned();
	let serial_number = SerialNumber::new(&[2]).expect("a serial number encodes");

	twin.tbs_certificate.serial_number = serial_number;
	twin
}

/// A test certificate whose issuer and serial number set it apart from every
/// certificate of [`create_test_certificate`], with `serial` as its serial
/// number.
///
/// A test that looks for the issuer and serial number on the wire then finds
/// no match from another certificate of the handshake. Its signature is the
/// zero signature of every test certificate, so no chain validator admits it.
pub fn create_issued_test_certificate(serial: impl AsRef<[u8]>) -> TestCertificate {
	let mut issued = create_test_certificate();
	let issuer = RdnSequence::from_str("CN=tightbeam test issuer").expect("the issuer name parses");
	let serial_number = SerialNumber::new(serial.as_ref()).expect("a test serial number encodes");

	issued.certificate.tbs_certificate.issuer = issuer;
	issued.certificate.tbs_certificate.serial_number = serial_number;
	issued
}

/// Create a self-signed certificate whose public key matches `signing_key`.
///
/// It carries the `subjectKeyIdentifier` of RFC 7093 §2 method 1, as every
/// certificate the crate creates does, so a CMS signer names it by that value.
fn create_test_certificate_inner(signing_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn Error>> {
	let verifying_key = *signing_key.verifying_key();
	let public_key_der = verifying_key.to_public_key_der()?;
	let subject_public_key_info = SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())?;
	let key_identifier = SubjectKeyIdentifier::try_from(Skid::of_public_key(&subject_public_key_info))?;
	let key_identifier = Extension {
		extn_id: SubjectKeyIdentifier::OID,
		critical: false,
		extn_value: OctetString::new(key_identifier.to_der()?)?,
	};

	// The certificate signs a client Finished or an HPKE reply, so its
	// `keyUsage` asserts the signing use alone (RFC 5280 §4.2.1.3).
	let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());
	let extn_value = OctetString::new(key_usage.to_der()?)?;
	let key_usage = Extension { extn_id: KeyUsage::OID, critical: true, extn_value };

	let tbs_cert = TbsCertificate {
		version: Version::V3,
		serial_number: SerialNumber::new(&[1])?,
		signature: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256, parameters: None },
		issuer: RdnSequence::default(),
		validity: Validity {
			not_before: Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(0))?),
			not_after: Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(u32::MAX as u64))?),
		},
		subject: RdnSequence::default(),
		subject_public_key_info,
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: Some(vec![key_identifier, key_usage]),
	};

	Ok(Certificate {
		tbs_certificate: tbs_cert,
		signature_algorithm: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256, parameters: None },
		signature: BitString::new(0, vec![0; 64])?,
	})
}

/// A fresh server ephemeral public key as the compressed SEC 1 point the
/// `ServerHandshake` carries. It discards the private half, so a client that
/// completes against it derives keys nobody else holds.
#[cfg(feature = "transport-hpke")]
pub fn create_test_server_ephemeral() -> Sec1CompressedPoint<Secp256k1> {
	let public_key = SecretKey::random(&mut OsRng).public_key();
	public_key.compressed_point().expect("a secp256k1 point compresses")
}

/// A compressed encoding at the width of secp256k1 whose x-coordinate lies
/// off the curve, so the SEC 1 parser refuses it while its length passes every
/// width check.
///
/// About half of all x-coordinates are off the curve, so the search ends after
/// a few candidates.
pub fn off_curve_point() -> Sec1CompressedPoint<Secp256k1> {
	let mut candidate = Sec1CompressedPoint::<Secp256k1>::default();
	let last = candidate.len() - 1;

	candidate[0] = 0x02;

	for x in 1u8..=u8::MAX {
		candidate[last] = x;
		if PublicKey::<Secp256k1>::from_sec1_bytes(&candidate).is_err() {
			return candidate;
		}
	}

	panic!("no off-curve x-coordinate among 255 small candidates")
}

/// The negation of `key`, which shares its x-coordinate, so ECDH under it
/// yields the secret that `key` yields.
pub fn negated(key: &PublicKey<Secp256k1>) -> PublicKey<Secp256k1> {
	let negated = PublicKey::<Secp256k1>::from_affine(-*key.as_affine());
	negated.expect("the negation of a public key is a public key")
}

/// Replace the key of `certificate` with [`off_curve_point`], so the key
/// parses as no point of the curve.
pub fn put_off_curve_key(certificate: &mut Certificate) {
	let off_curve = BitString::from_bytes(&off_curve_point());
	let off_curve = off_curve.expect("a compressed point is a BIT STRING");
	certificate.tbs_certificate.subject_public_key_info.subject_public_key = off_curve;
}

/// Reports whether `needle` appears anywhere inside `haystack`.
pub fn contains_window(haystack: impl AsRef<[u8]>, needle: impl AsRef<[u8]>) -> bool {
	let needle = needle.as_ref();
	haystack.as_ref().windows(needle.len()).any(|window| window == needle)
}

/// An agreement that yields a chosen secret in place of an ECDH output, so a
/// fixture or an observer runs the production derivation over the value it
/// picked.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
struct FixedAgreement<'a>(&'a EcdhSecret<Secp256k1>);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeAgreement<Secp256k1> for FixedAgreement<'_> {
	fn shared_secret(&self, _peer: &PublicKey<Secp256k1>) -> EcdhSecret<Secp256k1> {
		self.0.duplicate()
	}
}

/// `point` as an admitted peer ephemeral, for a fixture that holds no static
/// key to tell it from.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn admitted(point: &PublicKey<Secp256k1>) -> PeerPoint<Secp256k1> {
	let sec1 = point.to_encoded_point(true);
	let parsed = PeerPoint::parse(sec1.as_bytes());
	parsed.expect("a public key encodes a point")
}

/// The handshake secret of `shared`, followed by `base` when the flow
/// carries one, under `salt`, through the production derivation.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn derive_handshake_secret(
	shared: &EcdhSecret<Secp256k1>,
	base: Option<&BaseSecret>,
	salt: KdfSalt<'_>,
) -> Result<HandshakeSecret, HandshakeError> {
	// The fixed agreement ignores its peer, so any point serves.
	let peer = admitted(&SecretKey::random(&mut OsRng).public_key());
	let agreement = agreement_of(&peer, base);
	agreement.settle(&FixedAgreement(shared), salt)
}

/// The agreement of `peer`, hybrid with `base` as the CMS flow derives, or
/// ephemeral alone as the HPKE flow derives.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn agreement_of<'a>(
	peer: &'a PeerPoint<Secp256k1>,
	base: Option<&'a BaseSecret>,
) -> Agreement<'a, DefaultCryptoProvider> {
	match base {
		Some(base) => Agreement::hybrid(peer, base),
		None => Agreement::ephemeral(peer),
	}
}

/// An ephemeral-ephemeral secret on secp256k1 of 32 `fill` bytes, in place
/// of an ECDH output.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_agreement(fill: u8) -> EcdhSecret<Secp256k1> {
	let octets = SecretSlice::from(vec![fill; 32]);
	EcdhSecret::try_from(octets).expect("32 bytes make a secp256k1 shared secret")
}

/// The salt of the fixture derivations, 32 octets of `0x99`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub const FIXTURE_SALT: &[u8] = &[0x99u8; 32];

/// A handshake secret derived from a fixture ephemeral-ephemeral secret, a
/// fixture base secret of `fill` bytes, and [`FIXTURE_SALT`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_handshake_secret(fill: u8) -> HandshakeSecret {
	let base = BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret");
	let shared = fixture_agreement(0x11);
	let salt = KdfSalt::try_from(FIXTURE_SALT).expect("the fixture salt meets the floor");
	derive_handshake_secret(&shared, Some(&base), salt).expect("fixture inputs derive a handshake secret")
}

/// The salt and the transcript hash of [`fixture_confirmation`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const FIXTURE_CONFIRMED: [u8; 32] = [0x99u8; 32];

/// `output` as the transcript hash digest `D` gave.
pub fn fixture_transcript<D: Digest + AssociatedOid>(output: impl AsRef<[u8]>) -> TranscriptHash {
	let output = digest::Output::<D>::from_exact_iter(output.as_ref().iter().copied());
	let output = output.expect("the output is as wide as the output of `D`");
	let transcript = TranscriptHash::from_output::<D>(output);
	transcript.expect("the output is as wide as a digest output")
}

/// A key-confirmation tag of a fixture handshake secret, which confirms no
/// handshake a test runs.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_confirmation() -> KeyConfirmation {
	let secret = fixture_handshake_secret(0x42);
	let transcript = fixture_transcript::<Sha3_256>(FIXTURE_CONFIRMED);

	let salt = KdfSalt::try_from(FIXTURE_CONFIRMED.as_slice()).expect("the fixture salt meets the floor");
	let derived = secret.confirmation::<DefaultCryptoProvider>(salt, &transcript);
	derived.expect("a fixture secret derives a tag")
}

/// The values a hand-built closing confirms, which a client reads in the reply.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone)]
pub struct Confirming {
	/// The server ephemeral the reply carried.
	pub server_ephemeral: PublicKey<Secp256k1>,
	/// The KDF salt of the handshake.
	pub salt: Vec<u8>,
	/// The hash of the transcript the reply sealed.
	pub transcript_hash: TranscriptHash,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl Confirming {
	/// The key-confirmation tag of a client that drew `ephemeral`, and
	/// `base` when the flow carries one.
	///
	/// The handshake secret comes from the production agreement of `ephemeral`
	/// with the server ephemeral, so an honest hand-built closing confirms the
	/// secret the server derives.
	pub fn tag(&self, base: Option<&BaseSecret>, ephemeral: &SecretKey) -> KeyConfirmation {
		let salt = KdfSalt::try_from(self.salt.as_slice()).expect("the handshake salt meets the floor");
		let secret = self.secret(base, ephemeral);

		let derived = secret.confirmation::<DefaultCryptoProvider>(salt, &self.transcript_hash);
		derived.expect("the handshake secret derives a tag")
	}

	/// The closing sealer of a client that drew `ephemeral`, and `base` when
	/// the flow carries one.
	pub fn closing_sealer(&self, base: Option<&BaseSecret>, ephemeral: &SecretKey) -> Sealer<DefaultCryptoProvider> {
		let salt = KdfSalt::try_from(self.salt.as_slice()).expect("the handshake salt meets the floor");
		let secret = self.secret(base, ephemeral);

		let sealer = secret.sealer::<DefaultCryptoProvider>(SecretSeal::Closing, salt, &self.transcript_hash);
		sealer.expect("the handshake secret derives a closing key")
	}

	/// The handshake secret of the production agreement of `ephemeral` with
	/// the server ephemeral, under `base` when the flow carries one.
	pub fn secret(&self, base: Option<&BaseSecret>, ephemeral: &SecretKey) -> HandshakeSecret {
		let salt = KdfSalt::try_from(self.salt.as_slice()).expect("the handshake salt meets the floor");
		let server_ephemeral = admitted(&self.server_ephemeral);
		let agreement = agreement_of(&server_ephemeral, base);

		let settled = agreement.settle(ephemeral, salt);
		settled.expect("the agreement derives a handshake secret")
	}
}

/// Counts the receipt outcomes a server reports.
#[derive(Default)]
pub struct CountingObserver(AtomicUsize);

impl CountingObserver {
	/// Returns how many outcomes the server reported.
	pub fn outcomes(&self) -> usize {
		self.0.load(Ordering::SeqCst)
	}
}

impl SessionObserver for CountingObserver {
	fn on_outcome<'a>(&'a self, _outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()> {
		Box::pin(async move {
			self.0.fetch_add(1, Ordering::SeqCst);
		})
	}
}

/// Records the receipt artifact of each outcome a server reports.
#[derive(Default)]
pub struct ArtifactObserver(Mutex<Vec<Signed<SignedData>>>);

impl ArtifactObserver {
	/// The artifacts the server reported, in order.
	pub fn artifacts(&self) -> Vec<Signed<SignedData>> {
		let artifacts = self.0.lock().expect("no observer panicked while holding the record");
		artifacts.to_owned()
	}
}

impl SessionObserver for ArtifactObserver {
	fn on_outcome<'a>(&'a self, outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()> {
		Box::pin(async move {
			let mut artifacts = self.0.lock().expect("no observer panicked while holding the record");
			artifacts.push(outcome.artifact.to_owned());
		})
	}
}

/// The plaintext of the record a test session seals under the client's send
/// cipher.
pub const RECORD_PLAINTEXT: &[u8] = b"application record sealed under the traffic key";

/// Seal one record under the client's send cipher, as the DER it travels as.
pub fn sealed_record(client: &EstablishedSession) -> Result<Vec<u8>, TightBeamError> {
	let record = client.keys().send().encrypt_next(RECORD_PLAINTEXT)?;
	Ok(record.to_der()?)
}

/// Open `record`, the DER of one record, as the first client-to-server record
/// of epoch 0 under `key`.
pub fn opened_record(key: RuntimeAead, record: &[u8]) -> Result<SecretSlice<u8>, TightBeamError> {
	let mut arrived = record.to_vec();
	let opened = RecvCipher::new(key, 0, RecordDirection::ClientToServer).open(&mut arrived)?;
	Ok(SecretSlice::from(opened.to_vec()))
}

/// The length of the key-encryption key of a handshake seal.
const OBSERVER_KEK_SIZE: usize = 32;

/// The KDF of the default provider, which the observer runs the base-only
/// derivation through.
type ObserverKdf = <DefaultCryptoProvider as KdfProvider>::Kdf;

/// The outcome of each record attempt an observer makes.
pub type RecordAttempts = Vec<Result<SecretSlice<u8>, TightBeamError>>;

/// The outcome of each attempt an observer makes to open a sealed message.
pub type SealAttempts = Vec<Result<SecretSlice<u8>, HandshakeError>>;

/// A passive observer who recorded one session and later obtained the
/// server's static key.
///
/// It holds the base secret that key recovers when the flow carries one, the
/// protocol salt, and the two ephemeral public keys as the handshake carried
/// them.
///
/// # Candidates
///
/// Each candidate stands in for the ephemeral-ephemeral secret and runs
/// through the production key schedule:
///
/// - the all-zero secret,
/// - the static key's agreement with the client ephemeral,
/// - the static key's agreement with the server ephemeral, and
/// - the x-coordinate of each ephemeral.
///
/// An observer of a flow that carries a base secret also tries the key that
/// the base secret alone derives, which takes no ephemeral-ephemeral input.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct StaticKeyObserver {
	base: Option<BaseSecret>,
	salt: Vec<u8>,
	candidates: Vec<EcdhSecret<Secp256k1>>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl StaticKeyObserver {
	/// Give the observer `static_key`, the `base` it recovered with it when
	/// the flow carries one, the two ephemeral public keys as SEC 1 bytes, and
	/// the protocol `salt`.
	pub fn new(
		static_key: &SecretKey,
		base: Option<&[u8]>,
		client_ephemeral: &[u8],
		server_ephemeral: &[u8],
		salt: impl AsRef<[u8]>,
	) -> Result<Self, Box<dyn Error>> {
		let client_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(client_ephemeral)?;
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(server_ephemeral)?;
		let candidates = vec![
			fixture_agreement(0x00),
			static_key.shared_secret(&client_ephemeral),
			static_key.shared_secret(&server_ephemeral),
			x_coordinate(&client_ephemeral)?,
			x_coordinate(&server_ephemeral)?,
		];

		let base = base.map(|base| SecretSlice::from(base.to_vec()));
		let base = base.map(BaseSecret::try_from).transpose()?;
		Ok(Self { base, salt: salt.as_ref().to_vec(), candidates })
	}

	/// Open `record`, the DER of a recorded client record, under every record
	/// key the observer derives, in both directions, and report each outcome.
	/// Each attempt opens it as a client record, so each reaches the key.
	pub fn record_attempts(&self, record: &[u8]) -> Result<RecordAttempts, Box<dyn Error>> {
		let mut attempts = Vec::new();
		for secret in self.handshake_secrets()? {
			let salt = KdfSalt::try_from(self.salt.as_slice())?;
			let ciphers = DirectionalCiphers::derive::<DefaultCryptoProvider, _>(&secret, salt, 0)?;
			attempts.push(opened_record(ciphers.client_to_server, record));
			attempts.push(opened_record(ciphers.server_to_client, record));
		}

		let Some(base) = &self.base else {
			return Ok(attempts);
		};

		for label in [TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO] {
			attempts.push(opened_record(self.pre_change_key(base, label)?, record));
		}

		Ok(attempts)
	}

	/// Open the closing whose DER is `sealed`, of the transcript
	/// `transcript_hash`, under every closing key the observer derives, and
	/// report each outcome.
	pub async fn closing_attempts(
		&self,
		transcript_hash: &TranscriptHash,
		sealed: impl AsRef<[u8]>,
	) -> Result<SealAttempts, Box<dyn Error>> {
		let sealed = sealed.as_ref();
		let purpose = SecretSeal::Closing;

		// The observer opens the closing as the content type it names, as the
		// server opens it, so each attempt fails at the key alone.
		let envelope = AuthEnvelopedData::from_der(sealed)?;
		let content_type = envelope.auth_encrypted_content_info.content_type;
		let salt = KdfSalt::try_from(self.salt.as_slice())?;
		let mut attempts = Vec::new();

		for secret in self.handshake_secrets()? {
			let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, salt, transcript_hash)?;
			attempts.push(sealer.open(purpose.admit(sealed)?, content_type).await);
		}

		let Some(base) = &self.base else {
			return Ok(attempts);
		};

		let derived = self.pre_change_kek(base, purpose.label())?;
		let kek = Kek::try_from(derived.as_slice())?;
		let key_identifier = [purpose.domain(), transcript_hash.as_bytes()].concat();
		let opener = Opener::Kek { kek, key_identifier: &key_identifier };
		let opened = envelope.open::<DefaultCryptoProvider>(sealed, &opener, content_type).await;

		attempts.push(opened.map_err(|error| purpose.refusal(error)));

		Ok(attempts)
	}

	/// The handshake secret each candidate yields through the production
	/// derivation.
	fn handshake_secrets(&self) -> Result<Vec<HandshakeSecret>, HandshakeError> {
		let salt = KdfSalt::try_from(self.salt.as_slice())?;
		let derive = |shared| derive_handshake_secret(shared, self.base.as_ref(), salt);
		self.candidates.iter().map(derive).collect()
	}

	/// The record key that `base` alone derives under `label`, with no
	/// ephemeral-ephemeral input.
	fn pre_change_key(&self, base: &BaseSecret, label: &[u8]) -> Result<RuntimeAead, Box<dyn Error>> {
		let kek = self.pre_change_kek(base, label)?;
		Ok(RuntimeAead::new::<DefaultCryptoProvider>(kek)?)
	}

	/// The key-encryption key that `base` alone derives under `label`, with
	/// no ephemeral-ephemeral input.
	fn pre_change_kek(&self, base: &BaseSecret, label: &[u8]) -> Result<ZeroizingBytes, HandshakeError> {
		let salt = KdfSalt::try_from(self.salt.as_slice())?;
		let kek = ObserverKdf::derive_dynamic_key(base.as_bytes(), label, Some(salt), OBSERVER_KEK_SIZE)?;
		Ok(kek)
	}
}

/// The x-coordinate of `point` in the place of an ECDH output.
fn x_coordinate(point: &PublicKey<Secp256k1>) -> Result<EcdhSecret<Secp256k1>, Box<dyn Error>> {
	let encoded = point.to_encoded_point(false);
	let x = encoded.x().ok_or("an affine point has an x-coordinate")?;
	Ok(EcdhSecret::try_from(SecretSlice::from(x.to_vec()))?)
}

/// Generate a random secp256k1 signing key for tests.
pub fn create_test_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// Create the SHA3-256 digest algorithm identifier for CMS operations.
pub fn create_sha3_256_digest_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None }
}

/// Create the ECDSA with SHA3-256 signature algorithm identifier for CMS
/// operations.
pub fn create_ecdsa_sha3_256_signature_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
}

/// A `SignedData` over `content` of type `id-data` by a fresh test key.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn create_test_signed_data(content: impl AsRef<[u8]>) -> SignedData {
	let signing_key = TestIdentity::certified(create_test_signing_key());
	let content = content.as_ref();
	let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&signing_key, SignedContent::data(content));
	let signer = signer.expect("the test key signs");

	let signed_data = CmsSigner::signed_data(SignedContent::data(content), signer, None);
	let signed_data = signed_data.expect("the SignedData assembles");
	signed_data.into_inner()
}

/// Create test key pairs for cryptographic operations.
///
/// It returns a tuple of these parts, in order:
///
/// 1. the sender private key,
/// 2. the sender SPKI,
/// 3. the recipient private key, and
/// 4. the recipient public key.
pub fn create_test_keypair() -> (SecretKey, SubjectPublicKeyInfoOwned, SecretKey, PublicKey<Secp256k1>) {
	let sender_key = SecretKey::random(&mut OsRng);
	let sender_pubkey = sender_key.public_key();
	let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey).expect("SPKI creation should succeed");

	let recipient_key = SecretKey::random(&mut OsRng);
	let recipient_pubkey = recipient_key.public_key();

	(sender_key, sender_spki, recipient_key, recipient_pubkey)
}

/// Create the test key encryption algorithm identifier (AES-256 key wrap).
pub fn create_test_key_enc_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None }
}

/// `signing_key` behind the provider trait object that an endpoint
/// configuration takes.
pub fn into_provider(signing_key: Secp256k1SigningKey) -> Arc<dyn SigningKeyProvider> {
	Arc::new(Secp256k1KeyProvider::from(signing_key))
}

/// A key provider that counts the public keys it hands out, over the provider
/// of a test signing key. An HSM or a KMS answers each such call with a round
/// trip, so the count is what a handshake costs it.
#[derive(Debug)]
pub struct CountingProvider {
	inner: Arc<dyn SigningKeyProvider>,
	public_keys: AtomicUsize,
}

impl CountingProvider {
	/// A counter at zero over the provider of `signing_key`.
	pub fn new(signing_key: Secp256k1SigningKey) -> Self {
		Self { inner: into_provider(signing_key), public_keys: AtomicUsize::new(0) }
	}

	/// Returns how many public keys this provider handed out.
	pub fn public_keys(&self) -> usize {
		self.public_keys.load(Ordering::SeqCst)
	}
}

impl KeyBackend for CountingProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.inner.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.public_keys.fetch_add(1, Ordering::SeqCst);
		self.inner.to_public_key_bytes()
	}
}

impl SigningKeyProvider for CountingProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		self.inner.sign_prehash(prehash)
	}
}

/// A key provider that keeps every signature it makes, over the provider of a
/// test signing key, so a test can look for those bytes on the wire.
#[derive(Debug)]
pub struct RecordingProvider {
	inner: Arc<dyn SigningKeyProvider>,
	signatures: Mutex<Vec<Vec<u8>>>,
}

impl RecordingProvider {
	/// A provider over `signing_key` that has made no signature.
	pub fn new(signing_key: Secp256k1SigningKey) -> Self {
		Self { inner: into_provider(signing_key), signatures: Mutex::new(Vec::new()) }
	}

	/// The signature this provider made last, if it made any.
	pub fn last_signature(&self) -> Option<Vec<u8>> {
		let signatures = self.signatures.lock().expect("no signer panicked while holding the record");
		signatures.last().cloned()
	}
}

impl KeyBackend for RecordingProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.inner.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.inner.to_public_key_bytes()
	}
}

impl SigningKeyProvider for RecordingProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signing = self.inner.sign_prehash(prehash);
		Box::pin(async move {
			let signature = signing.await?;
			let mut signatures = self.signatures.lock().expect("no signer panicked while holding the record");
			signatures.push(signature.to_owned());
			Ok(signature)
		})
	}
}

/// Mutual authentication against `validator` alone.
pub fn mutual_with(validator: impl CertificateValidation + 'static) -> PeerAuthentication {
	let validator: Arc<dyn CertificateValidation> = Arc::new(validator);
	PeerAuthentication::Anonymous.and(validator)
}

/// The budgets a budget-bearing test session requests.
pub const TEST_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// The settlement challenge that [`ChallengingAuthorizer`] issues.
pub const TEST_CHALLENGE: &[u8] = b"test settlement challenge";

/// The bearer settlement answer that [`PayingApprover`] gives.
pub const TEST_ANSWER: &[u8] = b"test bearer settlement answer";

/// A budget-bearing transport offer with the test budgets.
pub fn budget_offer() -> TransportOffer {
	TransportOffer::mux(4).with_budgets(TEST_BUDGETS)
}

/// Grants the requested budgets with the test challenge and settles any
/// answer.
pub struct ChallengingAuthorizer;

impl TransportAuthorizer for ChallengingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let challenge = OctetString::new(TEST_CHALLENGE).map_err(|_| AuthorizationRefusal { code: 1 })?;
			Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(challenge) })
		})
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		_response: Option<&'a [u8]>,
		_client: &'a Certificate,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move { Ok(()) })
	}
}

/// Records the offers the server asks it to grant, and grants each as
/// [`ChallengingAuthorizer`] does.
#[derive(Default)]
pub struct RecordingAuthorizer(Mutex<Vec<TransportOffer>>);

impl RecordingAuthorizer {
	/// The offers the server asked this authorizer to grant, in order.
	pub fn offers(&self) -> Vec<TransportOffer> {
		let offers = self.0.lock().expect("no grant panicked while holding the record");
		offers.to_owned()
	}
}

impl TransportAuthorizer for RecordingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		let mut offers = self.0.lock().expect("no grant panicked while holding the record");
		offers.push(offer.to_owned());
		ChallengingAuthorizer.authorize(offer)
	}
}

/// Grants the requested budgets with the test challenge and leaves settlement
/// to the trait default, which refuses a challenged receipt.
pub struct RefusingAuthorizer;

impl TransportAuthorizer for RefusingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		ChallengingAuthorizer.authorize(offer)
	}
}

/// Approves every receipt and answers its challenge with the test answer.
pub struct PayingApprover;

impl ReceiptApprover for PayingApprover {
	fn approve<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
		Box::pin(async move {
			let answer = OctetString::new(TEST_ANSWER).map_err(|_| ApprovalRefusal { code: 1 })?;
			Ok(Some(answer))
		})
	}
}

/// The signing identity of `identity`: its certificate beside the key that
/// proves it.
pub fn signing_identity(identity: &TestCertificate) -> SigningIdentity {
	presenting(identity, into_provider(identity.signing_key.to_owned()))
}

/// The signing identity of `identity`'s certificate, whose key sits behind
/// `key`.
pub fn presenting(identity: &TestCertificate, key: Arc<dyn SigningKeyProvider>) -> SigningIdentity {
	let certificate = identity.certificate.to_owned();
	SigningIdentity::new(certificate, key).expect("the test key matches its certificate")
}

/// The identity of a test client: the certificate of `identity` beside the
/// key that proves it.
pub fn client_identity(identity: &TestCertificate) -> SigningIdentity {
	signing_identity(identity)
}

/// The settings of an HPKE client that admits `server` and presents
/// `identity`, when it holds one.
#[cfg(feature = "transport-hpke")]
pub fn hpke_client_settings(server: &Certificate, identity: Option<SigningIdentity>) -> HpkeClientSettings {
	let validator = DirectTrustValidator::default().with_trust_chain(vec![server.to_owned()]);
	let validator = validator.expect("a test certificate encodes");
	let mut settings = HpkeClientSettings::new(LearnedTrust::new(validator));
	settings.identity = identity;
	settings
}

/// The configuration of an HPKE client that admits `server` and presents
/// `identity`, when it holds one.
#[cfg(feature = "transport-hpke")]
pub fn hpke_client(server: &Certificate, identity: Option<SigningIdentity>) -> TestClientConfig<Hpke> {
	let config = ClientConfig::new(hpke_client_settings(server, identity), KeyPurposes::HOUSE);
	config.expect("a test client identity serves the client role")
}

/// The configuration of an HPKE server that signs with `identity`, demands
/// no client certificate, and runs the default test profile.
#[cfg(feature = "transport-hpke")]
pub fn hpke_server(identity: &TestCertificate) -> TestServerConfig<Hpke> {
	let profiles = SupportedProfiles::from(create_default_test_profile());
	let identity = signing_identity(identity);
	let config = ServerConfig::new(HpkeServerSettings::new(), identity, profiles, KeyPurposes::HOUSE);
	config.expect("a test server identity serves the server role")
}

/// The `ClientHello` that `opening` carries in its `ContentInfo` of type
/// `id-data`.
#[cfg(feature = "transport-hpke")]
pub fn carried_hello(opening: &HandshakeMessage) -> ClientHello {
	let data = opening.to_owned().data().expect("an HPKE opening is a ContentInfo");
	let octets = data.value().content.decode_as::<OctetStringRef<'_>>();
	let octets = octets.expect("the hello travels as an OCTET STRING");
	ClientHello::from_der(octets.as_bytes()).expect("the content is a ClientHello")
}

/// `hello` as the opening an HPKE server reads: a `ContentInfo` of type
/// `id-data` whose OCTET STRING is its DER.
#[cfg(feature = "transport-hpke")]
pub fn hello_opening(hello: &ClientHello) -> HandshakeMessage {
	let hello_der = hello.to_der().expect("a ClientHello encodes");
	let content = Any::new(Tag::OctetString, hello_der).expect("the DER is an OCTET STRING");
	let content_info = ContentInfo { content_type: DATA, content };
	HandshakeMessage::try_from(content_info).expect("the ContentInfo encodes")
}

/// The `SignedData` of an HPKE `reply`.
#[cfg(feature = "transport-hpke")]
pub fn reply_signed_data(reply: &HandshakeMessage) -> SignedData {
	let signed = reply.to_owned().signed().expect("an HPKE reply travels in a SignedData");
	signed.into_value()
}

/// The `ServerHandshake` an HPKE `reply` signs as its content.
#[cfg(feature = "transport-hpke")]
pub fn signed_handshake(reply: &HandshakeMessage) -> ServerHandshake {
	let signed_data = reply_signed_data(reply);
	let content = signed_data.content(HANDSHAKE_REPLY_CONTENT);
	let content = content.expect("an HPKE reply signs a ServerHandshake");
	ServerHandshake::from_der(content).expect("the content is a ServerHandshake")
}

/// The material that an observer who holds the server's static key recovers
/// from a recorded handshake.
pub struct Recovered {
	/// The observer, which holds the static key and everything it opened.
	pub observer: StaticKeyObserver,
	/// The base secret the static key opened, when the flow seals one to it.
	/// The HPKE flow seals nothing to the server, so for HPKE it is `None`.
	pub base: Option<Vec<u8>>,
}

/// A flow the handshake tests run over, and the configurations of its two
/// endpoints.
pub trait TestFlow: ClientFlow<DefaultCryptoProvider> + ServerFlow<DefaultCryptoProvider> {
	/// The attempts [`StaticKeyObserver::record_attempts`] makes on a session
	/// of this flow: five candidates under both directional keys, and the key
	/// from the base secret alone under both directional labels when the flow
	/// carries one.
	const RECORD_ATTEMPTS: usize;

	/// The attempts [`StaticKeyObserver::closing_attempts`] makes on a
	/// closing of this flow: five candidates, and the key from the base
	/// secret alone when the flow carries one.
	const CLOSING_ATTEMPTS: usize;

	/// The configuration of a client that admits `server` and presents
	/// `identity`.
	fn client(server: &TestServerIdentity, identity: &TestCertificate) -> TestClientConfig<Self> {
		Self::client_presenting(server, client_identity(identity))
	}

	/// The configuration of a client that admits `server` and presents
	/// `identity`, whose key may sit behind any provider.
	fn client_presenting(server: &TestServerIdentity, identity: SigningIdentity) -> TestClientConfig<Self>;

	/// The configuration of a server that holds `identity`, demands no client
	/// certificate, and runs the default test profile.
	fn server(identity: &TestServerIdentity) -> TestServerConfig<Self> {
		Self::server_presenting(identity, signing_identity(&identity.signing))
	}

	/// The configuration of a server that holds `identity` and signs under
	/// `signing`, demands no client certificate, and runs the default test
	/// profile.
	fn server_presenting(identity: &TestServerIdentity, signing: SigningIdentity) -> TestServerConfig<Self>;

	/// Open the recorded legs of `run` with the static keys of
	/// `server_identity`, through the same path the server runs.
	async fn recover(run: &Run<Self>, server_identity: &TestServerIdentity) -> Recovered;
}

/// A client configuration under the default provider.
pub type TestClientConfig<F> = ClientConfig<F, DefaultCryptoProvider>;

/// A server configuration under the default provider.
pub type TestServerConfig<F> = ServerConfig<F, DefaultCryptoProvider>;

/// A client handshake under the default provider.
pub type TestClient<F> = Handshake<Client, F, DefaultCryptoProvider>;

/// A server handshake under the default provider.
pub type TestServer<F> = Handshake<Server, F, DefaultCryptoProvider>;

#[cfg(feature = "transport-hpke")]
impl TestFlow for Hpke {
	const RECORD_ATTEMPTS: usize = 10;
	const CLOSING_ATTEMPTS: usize = 5;

	fn client_presenting(server: &TestServerIdentity, identity: SigningIdentity) -> TestClientConfig<Self> {
		hpke_client(&server.signing.certificate, Some(identity))
	}

	fn server_presenting(_identity: &TestServerIdentity, signing: SigningIdentity) -> TestServerConfig<Self> {
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let config = ServerConfig::new(HpkeServerSettings::new(), signing, profiles, KeyPurposes::HOUSE);
		config.expect("a test server identity serves the server role")
	}

	/// The HPKE flow seals nothing to the server, so the static key opens no
	/// leg. The observer holds the two ephemerals as the hello and the reply
	/// carried them in clear.
	async fn recover(run: &Run<Self>, server_identity: &TestServerIdentity) -> Recovered {
		let static_key = SecretKey::from(server_identity.signing.signing_key.to_owned());
		let hello = carried_hello(&run.opening);
		let handshake = signed_handshake(&run.reply);
		let salt = [hello.client_random.as_bytes(), handshake.server_random.as_bytes()].concat();
		let server_ephemeral = handshake.server_ephemeral.as_bytes();
		let client_ephemeral = hello.client_ephemeral.as_bytes();

		let observer = StaticKeyObserver::new(&static_key, None, client_ephemeral, server_ephemeral, salt);
		Recovered { observer: observer.expect("both ephemerals are points on the curve"), base: None }
	}
}

#[cfg(feature = "transport-cms")]
impl TestFlow for Cms {
	const RECORD_ATTEMPTS: usize = 12;
	const CLOSING_ATTEMPTS: usize = 6;

	fn client_presenting(server: &TestServerIdentity, identity: SigningIdentity) -> TestClientConfig<Self> {
		let settings = CmsClientSettings { trust: server.trust(), identity };
		let config = ClientConfig::new(settings, KeyPurposes::HOUSE);
		config.expect("a test client identity serves the client role")
	}

	fn server_presenting(identity: &TestServerIdentity, signing: SigningIdentity) -> TestServerConfig<Self> {
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let pair = CmsIdentityPair::new(signing, identity.key_agreement_identity());
		let pair = pair.expect("the two test certificates name one subject with two keys");
		let config = ServerConfig::new(CmsServerSettings, pair, profiles, KeyPurposes::HOUSE);
		config.expect("a test server pair serves the server role")
	}

	/// The key-agreement key opens the opening, and the observer holds it as
	/// the static key that a recorded session meets later.
	async fn recover(run: &Run<Self>, server_identity: &TestServerIdentity) -> Recovered {
		let opening = run.opening.to_owned().auth_enveloped();
		let opening = opening.expect("a CMS opening is an AuthEnvelopedData");
		let static_key = SecretKey::from(server_identity.key_agreement.signing_key.to_owned());
		let identity = server_identity.key_agreement_identity();
		let opener = Opener::Kem { identity: &identity, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
		let (arrived, opening) = opening.into_parts();
		let opened = opening.open::<DefaultCryptoProvider>(arrived, &opener, HANDSHAKE_OPENING_CONTENT);

		let opened = opened.await;
		let content = opened.expect("the static key opens the opening").to_insecure();
		let content = OpeningContent::from_der(&content).expect("the opening content decodes");
		let base = content.base_secret.as_bytes().to_vec();

		let server_finished = run.reply.to_owned().signed().expect("a CMS reply is a SignedData");
		let server_ephemeral = server_finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL);
		let server_ephemeral = server_ephemeral.expect("the ephemeral attribute is single");
		let server_ephemeral = server_ephemeral.expect("the server Finished carries its ephemeral");
		let server_ephemeral = server_ephemeral.decode::<OriginatorPublicKey>().expect("the ephemeral decodes");
		let server_point = server_ephemeral.public_key.raw_bytes();
		let client_point = content.agreement_key.public_key.raw_bytes();
		let transcript_hash = run.transcript_hash;
		let observer = StaticKeyObserver::new(&static_key, Some(&base), client_point, server_point, transcript_hash);
		let observer = observer.expect("both ephemerals are points on the curve");

		Recovered { observer, base: Some(base) }
	}
}

/// The three messages of one handshake as their senders sent them, with both
/// endpoints after the closing.
pub struct Run<F: TestFlow> {
	/// The opening, as the client sent it.
	pub opening: HandshakeMessage,
	/// The reply, as the server sent it.
	pub reply: HandshakeMessage,
	/// The closing, as the client sent it.
	pub closing: HandshakeMessage,
	/// The transcript hash both sides sealed.
	pub transcript_hash: TranscriptHash,
	/// The client, with its closing sent.
	pub client: TestClient<F>,
	/// The server, with the closing received.
	pub server: TestServer<F>,
}

impl<F: TestFlow> Run<F> {
	/// Every byte the three legs sent.
	pub fn wire_bytes(&self) -> Vec<u8> {
		[self.opening.der(), self.reply.der(), self.closing.der()].concat()
	}
}

/// The recorded legs of a mutual handshake of flow `F` whose client presents
/// `client_identity` and signs through `key`.
pub async fn mutual_run<F: TestFlow>(client_identity: &TestCertificate, key: Arc<dyn SigningKeyProvider>) -> Run<F> {
	let server_identity = create_test_server();
	let presented = presenting(client_identity, key);
	let client = F::client_presenting(&server_identity, presented);

	let mut server = F::server(&server_identity);
	server.peer_authentication = mutual_with(ExpiryValidator::default());
	run(client, server).await
}

/// Drive a client under `client` and a server under `server` through the
/// three legs, and record each message as its sender sends it.
pub async fn run<F: TestFlow>(client: TestClientConfig<F>, server: TestServerConfig<F>) -> Run<F> {
	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let opening = client.start().expect("the client builds its opening");
	let reply = server.reply(opening.to_owned()).await.expect("the server admits the opening");
	let closing = client.respond(reply.to_owned()).await.expect("the client admits the reply");

	server.finish(closing.to_owned()).await.expect("the server admits the closing");

	let transcript_hash = client.transcript_hash().expect("the client sealed its transcript");
	Run { opening, reply, closing, transcript_hash, client, server }
}

/// The identities and the configurations of the two endpoints of one
/// handshake.
pub struct Parties<F: TestFlow> {
	/// The identity the server holds.
	pub server_identity: TestServerIdentity,
	/// The identity the client presents.
	pub client_identity: TestCertificate,
	/// The client configuration, which admits the server.
	pub client: TestClientConfig<F>,
	/// The server configuration.
	pub server: TestServerConfig<F>,
}

/// Two endpoints of flow `F` under `peer_authentication`, where the client
/// admits the server and presents a fresh identity.
pub fn parties<F: TestFlow>(peer_authentication: PeerAuthentication) -> Parties<F> {
	let server_identity = create_test_server();
	let client_identity = create_test_certificate();
	let client = F::client(&server_identity, &client_identity);

	let mut server = F::server(&server_identity);
	server.peer_authentication = peer_authentication;

	Parties { server_identity, client_identity, client, server }
}

/// A fresh client and a fresh server of flow `F` under `peer_authentication`,
/// where the client admits the server and presents a fresh identity.
pub fn pair<F: TestFlow>(peer_authentication: PeerAuthentication) -> (TestClient<F>, TestServer<F>) {
	let Parties { client, server, .. } = parties::<F>(peer_authentication);
	(Handshake::client(client), Handshake::server(server))
}

/// A recorded handshake with both sessions established.
pub struct Established<F: TestFlow> {
	/// The identity the server holds.
	pub server_identity: TestServerIdentity,
	/// The recorded legs, with both endpoints completed.
	pub run: Run<F>,
	/// The session the client established.
	pub client_session: EstablishedSession,
	/// The session the server established.
	pub server_session: EstablishedSession,
}

/// Run a handshake of flow `F` under `peer_authentication` to completion on
/// both sides.
pub async fn established<F: TestFlow>(peer_authentication: PeerAuthentication) -> Established<F> {
	let Parties { server_identity, client, server, .. } = parties::<F>(peer_authentication);
	let mut run = run(client, server).await;
	let client_session = run.client.complete().expect("the client completes");
	let server_session = run.server.complete().expect("the server completes");
	Established { server_identity, run, client_session, server_session }
}

/// The directory `scripts/cms-interop.sh` reads its samples from.
const SAMPLE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/cms-samples");

/// The variable that asks a sample test to write its samples.
const SAMPLE_VARIABLE: &str = "TIGHTBEAM_CMS_SAMPLES";

/// `content` of `content_type` inside a CMS `ContentInfo` (RFC 5652 §3),
/// the form a CMS parser reads.
pub fn content_info<T: EncodeValue + Tagged>(content_type: ObjectIdentifier, content: &T) -> Vec<u8> {
	let content = AnyValue::encode_from(content).expect("the content encodes");
	let content_info = ContentInfoValue { content_type, content };
	content_info.to_der().expect("the ContentInfo encodes")
}

/// The key, the `kekid`, and the plaintext an outside CMS reader recovers
/// from one `KEKRecipientInfo` sample, all from fixed test keys.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct KekOpening {
	kek: Vec<u8>,
	key_identifier: Vec<u8>,
	plaintext: Vec<u8>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl KekOpening {
	/// Collects what opens the seal that `sealer` makes for `purpose` over
	/// `plaintext`, whose frame is the plaintext a reader recovers.
	pub fn of(sealer: &Sealer<DefaultCryptoProvider>, purpose: SecretSeal, plaintext: &[u8]) -> Self {
		let (kek, key_identifier) = sealer.kek_opening();
		let framed = purpose.frame(plaintext).expect("the plaintext fits its frame");
		Self { kek, key_identifier, plaintext: framed.to_vec() }
	}

	/// Collects what opens a seal under `kek`, which `key_identifier` names,
	/// over `plaintext`.
	pub fn new(kek: impl Into<Vec<u8>>, key_identifier: impl Into<Vec<u8>>, plaintext: impl Into<Vec<u8>>) -> Self {
		Self {
			kek: kek.into(),
			key_identifier: key_identifier.into(),
			plaintext: plaintext.into(),
		}
	}
}

/// `bytes` as lowercase hexadecimal, the form `openssl cms -secretkey`
/// reads.
fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Write each of `samples` to [`SAMPLE_DIR`] under its name, what opens each
/// `KEKRecipientInfo` sample of `openings`, and the DER of each of
/// `certificates`, when the environment holds [`SAMPLE_VARIABLE`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn write_interop_samples(
	samples: &[(&str, Vec<u8>)],
	openings: &[(&str, &KekOpening)],
	certificates: &[(&str, &Certificate)],
) -> std::io::Result<()> {
	if std::env::var_os(SAMPLE_VARIABLE).is_none() {
		return Ok(());
	}

	std::fs::create_dir_all(SAMPLE_DIR)?;
	for (name, der) in samples {
		std::fs::write(format!("{SAMPLE_DIR}/{name}.der"), der)?;
	}
	for (name, opening) in openings {
		std::fs::write(format!("{SAMPLE_DIR}/{name}.kek"), hex(&opening.kek))?;
		std::fs::write(format!("{SAMPLE_DIR}/{name}.kekid"), hex(&opening.key_identifier))?;
		std::fs::write(format!("{SAMPLE_DIR}/{name}.plain"), &opening.plaintext)?;
	}
	for (name, certificate) in certificates {
		let der = certificate.to_der().map_err(std::io::Error::other)?;
		std::fs::write(format!("{SAMPLE_DIR}/{name}.crt"), der)?;
	}

	Ok(())
}
