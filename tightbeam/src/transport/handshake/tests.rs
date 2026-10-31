//! Shared test utilities for handshake protocol tests.
//!
//! It holds the fixtures, functions, and data structures that every handshake
//! test module shares, so each setup has one home.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::str::FromStr;
use core::time::Duration;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::asn1::OctetString;
use crate::cms::cert::CertificateChoices;
use crate::cms::signed_data::SignedData;
use crate::cms::signed_data::{CertificateSet, SignerInfo};
use crate::constants::{TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO};
use crate::crypto::aead::{DirectionalCiphers, RecordDirection, RecvCipher, RuntimeAead};
use crate::crypto::cms::{AuthEnvelopedData, Opener};
use crate::crypto::hash::{Digest, Sha3_256, Sha3_512};
use crate::crypto::kdf::{KdfFunction, KdfSalt};
use crate::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use crate::crypto::profiles::{DefaultCryptoProvider, KdfProvider, Kek, SecurityProfileDesc};
use crate::crypto::secret::SecretSlice;
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use crate::crypto::sign::elliptic_curve::sec1::{CompressedPoint as Sec1CompressedPoint, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::{CmsSigner, Signed, SignedContent, SignedDataExt, SignedDataSigners, SigningIdentity};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::policy::{CertificateValidation, RuntimeCertificatePinning};
use crate::crypto::x509::store::RevocationChecker;
use crate::crypto::x509::utils::Skid;
use crate::crypto::x509::{KeyPurposes, PeerCertificate};
use crate::der::asn1::BitString;
use crate::der::asn1::GeneralizedTime;
use crate::der::asn1::{Any as AnyValue, ContextSpecificRef, ObjectIdentifier, PrintableString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode, EncodeValue, TagMode, TagNumber, Tagged};
use crate::marker::MaybeSendFuture;
use crate::oids::{AES_128_GCM, DATA, HASH_SHA3_256, SIGNED_DATA, SIGNER_ECDSA_WITH_SHA256};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
pub use crate::testing::fixtures::{TestCertificate, TestCertificateChain};
use crate::testing::{TestCmsServer, TestIdentity, TestKey};
use crate::transport::handshake::attributes::AttributePayload;
use crate::transport::handshake::flow::ClientFlow;
use crate::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, RunnableProfile, SecurityAccept, TransportAuthorizer,
	TransportOffer,
};
use crate::transport::handshake::primitives::transcript::Transcript;
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::receipt::{
	ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
};
use crate::transport::handshake::{
	Client, ClientConfig, ClientHello, EstablishedSession, Handshake, HandshakeAttribute, HandshakeError,
	HandshakeMessage, HandshakeProvider, HandshakeSecret, PeerAuthentication, Server, ServerConfig, ServerFlow,
	ServerHandshake, SupportedProfiles,
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

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::exchange::{Ecdhe, EcdheShare, KeyShare};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::hpke::DhKemSecp256k1;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::ephemeral::{Distinct, ExchangeSecret, PeerStatics};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::{BaseSecret, FinishedRole, KeyConfirmation, Sealer, SecretSeal};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::wire_der::WireDer;

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
	pub use crate::crypto::cms::{KemRecipient, Recipient};
	pub use crate::crypto::x509::KeyAgreement;
	pub use crate::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY;
	pub use crate::oids::{CURVE_SECP256K1, HANDSHAKE_OPENING_CONTENT, HANDSHAKE_SERVER_EPHEMERAL};
	pub use crate::transport::handshake::attributes::HandshakeAttributes;
	pub use crate::transport::handshake::{Cms, CmsClientSettings, CmsIdentityPair, CmsServerSettings};
}

#[cfg(feature = "transport-cms")]
use crate::transport::handshake::flow::OpeningContent;
#[cfg(feature = "transport-cms")]
use cms::*;

/// The default test profile, the one [`DefaultCryptoProvider`] runs.
pub fn create_default_test_profile() -> SecurityProfileDesc {
	RunnableProfile::<DefaultCryptoProvider>::native().descriptor()
}

/// A descriptor that names an AEAD the default provider does not run.
pub fn foreign_profile() -> SecurityProfileDesc {
	SecurityProfileDesc { aead: Some(AES_128_GCM), ..create_default_test_profile() }
}

/// A test certificate beside its signing key, so every test creates
/// certificates the same way.
#[derive(Debug, Clone)]
pub struct HandshakeCertificate {
	/// The signing key whose public key the certificate carries.
	pub signing_key: Secp256k1SigningKey,
	/// The certificate over the public key of `signing_key`.
	pub certificate: Certificate,
}

impl HandshakeCertificate {
	/// The signing certificate of `server` beside its key.
	pub fn signing_of(server: &TestCmsServer) -> Self {
		let (signing_key, certificate) = (server.signing_key.to_owned(), server.signing.to_owned());
		HandshakeCertificate { signing_key, certificate }
	}

	/// The signing identity of this certificate beside the key that proves
	/// it.
	pub fn signing_identity(&self) -> SigningIdentity {
		TestIdentity::presenting(self.certificate.to_owned(), &self.signing_key)
	}
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

/// Create a test certificate of the fixed secp256k1 key of `seed`.
///
/// Every handshake test creates its certificate this way. The certificate
/// uses minimal valid data and a long validity period. Two seeds give two
/// keys, and one seed gives one certificate.
pub fn create_test_certificate(seed: u8) -> HandshakeCertificate {
	let signing_key = TestKey::fixed(seed);
	let certificate = create_test_certificate_inner(&signing_key).expect("Test certificate creation should succeed");
	HandshakeCertificate { signing_key, certificate }
}

/// A revocation checker that revokes one certificate once [`Self::revoke`]
/// runs, as a store whose verdict on a certificate changes after a trust is
/// built. Each clone shares the one switch. No checker of the crate changes
/// its verdict after a store is built, so no real instance runs this case.
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

/// The test server of the fixed keys of seeds `0xec` (signing) and `0xed`
/// (key agreement), which no other handshake fixture holds.
pub fn create_test_server() -> TestCmsServer {
	TestCmsServer::of("tightbeam test server", TestKey::fixed(0xec), TestKey::fixed(0xed))
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
	pub identity: TestCmsServer,
	/// The intermediate that issued the signing certificate.
	pub intermediate: Certificate,
}

impl ChainedTestServer {
	/// The server of the fixed test chain, with the fixed key-agreement key of
	/// seed `0x04`, which no key of the chain shares.
	pub fn fixed() -> Self {
		let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
		let TestCertificateChain { root, intermediate, leaf, root_key, leaf_key, .. } = chain;
		let key_agreement_key = TestKey::fixed(0x04);
		let usage = KeyUsage(KeyUsages::KeyAgreement.into());
		let key_agreement = TestCertificate::issued(&root_key, "Root", &key_agreement_key, "Leaf", 4, usage);
		let key_agreement = key_agreement.expect("the root issues the key-agreement certificate");

		let identity = TestCmsServer {
			authority: root,
			authority_key: root_key,
			signing: leaf,
			signing_key: leaf_key,
			key_agreement,
			key_agreement_key,
		};
		Self { identity, intermediate }
	}

	/// The signing identity of the server, which presents the intermediate.
	pub fn signing_identity(&self) -> SigningIdentity {
		let identity = self.identity.signing_identity().with_chain([self.intermediate.to_owned()]);
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
	let renumbered = TestCertificate::with_serial(certificate.to_owned(), serial);
	TestCertificate::signed_by(renumbered, issuer_key)
}

/// The projections and edits of a message that the handshake tests read and
/// forge.
impl HandshakeMessage {
	/// The `SignedData` this message carries.
	pub(crate) fn signed_data(&self) -> SignedData {
		let signed = self.to_owned().signed().expect("the message travels in a SignedData");
		signed.into_value()
	}

	/// The `ServerHandshake` an HPKE reply signs as its content.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn signed_handshake(&self) -> ServerHandshake {
		let signed_data = self.signed_data();
		let content = signed_data.content(HANDSHAKE_REPLY_CONTENT);
		let content = content.expect("an HPKE reply signs a ServerHandshake");
		ServerHandshake::from_der(content).expect("the content is a ServerHandshake")
	}

	/// The `ClientHello` an HPKE opening carries in its `ContentInfo` of type
	/// `id-data`.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn carried_hello(&self) -> ClientHello {
		let data = self.to_owned().data().expect("an HPKE opening is a ContentInfo");
		let octets = data.value().content.decode_as::<OctetStringRef<'_>>();
		let octets = octets.expect("the hello travels as an OCTET STRING");
		ClientHello::from_der(octets.as_bytes()).expect("the content is a ClientHello")
	}

	/// This HPKE reply with only its content rewritten by `edit`, as an
	/// on-path party would rewrite it. The signature still covers the content
	/// the server signed.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn with_content(&self, edit: impl FnOnce(&mut ServerHandshake)) -> Self {
		let mut signed_data = self.signed_data();
		let mut handshake = self.signed_handshake();
		edit(&mut handshake);

		let content = handshake.to_der().expect("the content encodes");
		let econtent = Any::new(Tag::OctetString, content).expect("the content is an OCTET STRING");
		signed_data.encap_content_info.econtent = Some(econtent);
		HandshakeMessage::try_from(signed_data).expect("the reply encodes")
	}

	/// This reply with `certificates` in place of the set it carries. No
	/// signature covers the set, so only the transcript tells the two apart.
	pub(crate) fn with_presented(&self, certificates: impl IntoIterator<Item = Certificate>) -> Self {
		let mut signed_data = self.signed_data();
		signed_data.certificates = Some(TestCertificate::set_of(certificates));
		HandshakeMessage::try_from(signed_data).expect("the reply encodes")
	}

	/// The certificates this reply carries, in the order its SET holds them.
	pub(crate) fn presented_certificates(&self) -> Vec<Certificate> {
		let certificates = self.signed_data().certificates;
		let choices = certificates.map(|set| set.0.into_vec()).unwrap_or_default();
		let certificate = |choice| match choice {
			CertificateChoices::Certificate(certificate) => Some(certificate),
			CertificateChoices::Other(_) => None,
		};

		choices.into_iter().filter_map(certificate).collect()
	}

	/// This message with the unsigned attributes of its one signer rewritten
	/// by `edit`.
	pub(crate) fn with_unsigned(&self, edit: impl FnOnce(Vec<Attribute>) -> Vec<Attribute>) -> Self {
		let edited = with_unsigned_attrs(self.signed_data(), edit);
		HandshakeMessage::try_from(edited).expect("the message encodes")
	}

	/// The bytes of this message with the two values of [`two_valued_name`]
	/// swapped, another encoding of the same certificate value, which DER
	/// forbids.
	pub(crate) fn with_rdn_values_swapped(&self) -> Vec<u8> {
		let name = two_valued_name();
		let values = name.0.iter().flat_map(|rdn| rdn.0.iter());
		let sorted: Vec<Vec<u8>> = values.map(|value| value.to_der().expect("a value encodes")).collect();
		let encoded = sorted.concat();
		let swapped = sorted.iter().rev().flatten().copied().collect::<Vec<u8>>();
		let carried = self.der().windows(encoded.len()).position(|window| window == encoded);
		let (head, tail) = self.der().split_at(carried.expect("the message carries the RDN"));
		[head, swapped.as_slice(), &tail[encoded.len()..]].concat()
	}
}

/// A test certificate of the fixed key of `seed` whose validity period ended
/// one second after the epoch.
pub fn create_expired_test_certificate(seed: u8) -> HandshakeCertificate {
	let mut expired = create_test_certificate(seed);
	let not_after = GeneralizedTime::from_unix_duration(Duration::from_secs(1));
	let not_after = not_after.expect("one second after the epoch is a time");

	expired.certificate.tbs_certificate.validity.not_after = Time::GeneralTime(not_after);
	expired
}

/// A test certificate of the fixed key of `seed` whose validity period is the
/// fixed test window, so it is expired on
/// [`TestCertificate::clock_past_validity`].
pub fn create_windowed_test_certificate(seed: u8) -> HandshakeCertificate {
	let signing_key = TestKey::fixed(seed);
	let certificate = TestCertificate::self_signed(&signing_key);
	HandshakeCertificate { signing_key, certificate }
}

/// A certificate of the key of `identity` that differs from its own
/// certificate in its serial number alone, so its `subjectKeyIdentifier`
/// names the same key.
pub fn same_key_twin(identity: &HandshakeCertificate) -> Certificate {
	TestCertificate::with_serial(identity.certificate.to_owned(), 2)
}

/// A test certificate of the fixed key of `seed` whose issuer and serial
/// number set it apart from every certificate of [`create_test_certificate`],
/// with `serial` as its serial number.
///
/// A test that looks for the issuer and serial number on the wire then finds
/// no match from another certificate of the handshake. Its signature is the
/// zero signature of every test certificate, so no chain validator admits it.
pub fn create_issued_test_certificate(seed: u8, serial: impl AsRef<[u8]>) -> HandshakeCertificate {
	let mut issued = create_test_certificate(seed);
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

/// `point` as an admitted server share, for a fixture that holds no static
/// key to tell it from.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn admitted(point: &PublicKey<Secp256k1>) -> Distinct<EcdheShare<Secp256k1>> {
	let parsed = PeerStatics::<Ecdhe<Secp256k1>>::none().server_ephemeral(EcdheShare::from(*point));
	parsed.expect("a fixture holds no static key to compare")
}

/// The secret of the house exchange of `scalar` with `point`, through the
/// production completion.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn exchange_of(scalar: &SecretKey, point: &PublicKey<Secp256k1>) -> ExchangeSecret {
	let completed = admitted(point).complete::<Ecdhe<Secp256k1>>(scalar);
	let completed = completed.expect("the house exchange completes on a point of its curve");
	completed.as_ref().with(|secret| ExchangeSecret::fixture(secret.to_vec()))
}

/// The handshake secret of `shared`, followed by `base` when the flow
/// carries one, under `salt`, through the production derivation.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn derive_handshake_secret(
	shared: &ExchangeSecret,
	base: Option<&BaseSecret>,
	salt: KdfSalt<'_>,
) -> Result<HandshakeSecret, HandshakeError> {
	match base {
		Some(base) => HandshakeSecret::hybrid::<DefaultCryptoProvider>(shared, base, salt),
		None => HandshakeSecret::ephemeral::<DefaultCryptoProvider>(shared, salt),
	}
}

/// An exchange secret of 32 `fill` bytes, in place of the secret of an
/// exchange on secp256k1.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_agreement(fill: u8) -> ExchangeSecret {
	ExchangeSecret::fixture(vec![fill; 32])
}

/// The salt of the fixture derivations, 32 octets of `0x99`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub const FIXTURE_SALT: &[u8] = &[0x99u8; 32];

/// [`FIXTURE_SALT`] as the salt a derivation takes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_salt() -> KdfSalt<'static> {
	KdfSalt::try_from(FIXTURE_SALT).expect("the fixture salt meets the floor")
}

/// A base secret of 32 `fill` bytes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_base_secret(fill: u8) -> BaseSecret {
	BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret")
}

/// A handshake secret derived from a fixture ephemeral-ephemeral secret, a
/// fixture base secret of `fill` bytes, and [`FIXTURE_SALT`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_handshake_secret(fill: u8) -> HandshakeSecret {
	let base = fixture_base_secret(fill);
	let shared = fixture_agreement(0x11);
	derive_handshake_secret(&shared, Some(&base), fixture_salt()).expect("fixture inputs derive a handshake secret")
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

/// The transcript hash of the fixture seals: 32 octets of `0x07` as a
/// SHA3-256 output.
pub fn fixture_transcript_hash() -> TranscriptHash {
	fixture_transcript::<Sha3_256>([0x07; 32])
}

/// A SHA3-256 transcript hash of 32 octets of `0x5a`, which no handshake a
/// test runs seals.
pub fn foreign_transcript_hash() -> TranscriptHash {
	fixture_transcript::<Sha3_256>([0x5a; 32])
}

/// The fixture transcript hash at the SHA3-512 width: 64 octets of `0x07`.
pub fn wide_transcript_hash() -> TranscriptHash {
	fixture_transcript::<Sha3_512>([0x07; 64])
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

/// The sealer of `purpose` that the fixture handshake secret derives under
/// [`FIXTURE_SALT`] and [`fixture_transcript_hash`], so a reader holds its
/// key.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_sealer(purpose: SecretSeal) -> Sealer<DefaultCryptoProvider> {
	let secret = fixture_handshake_secret(0x42);
	let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, fixture_salt(), &fixture_transcript_hash());
	sealer.expect("the fixture secret derives a seal key")
}

/// The key-confirmation attribute that carries `tag`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn finished_attribute(tag: &KeyConfirmation) -> Attribute {
	let attribute = HandshakeAttribute::encode(tag).expect("a tag encodes as an attribute");
	Attribute::try_from(attribute).expect("the attribute encodes")
}

/// The receipt acknowledgement attribute that carries `octets`, as a closing
/// carries it.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn acknowledgement(octets: impl AsRef<[u8]>) -> Attribute {
	let octets = OctetString::new(octets.as_ref()).expect("bytes are an OCTET STRING");
	Attribute::try_from(attribute(&octets)).expect("the acknowledgement is an attribute")
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
		let shared = exchange_of(ephemeral, &self.server_ephemeral);

		let settled = derive_handshake_secret(&shared, base, salt);
		settled.expect("the agreement derives a handshake secret")
	}
}

/// Counts the receipt outcomes a server reports. The application supplies
/// the observer, so the crate ships no real instance to run.
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

/// Records the receipt artifact of each outcome a server reports. The
/// application supplies the observer, so the crate ships no real instance to
/// run.
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
pub fn sealed_record(client: &EstablishedSession) -> Vec<u8> {
	let record = client.keys().send().encrypt_next(RECORD_PLAINTEXT);
	let record = record.expect("an established send cipher seals a record");
	record.to_der().expect("the record encodes")
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
	candidates: Vec<ExchangeSecret>,
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
	) -> Self {
		let client_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(client_ephemeral);
		let client_ephemeral = client_ephemeral.expect("the client ephemeral is a point on the curve");
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(server_ephemeral);
		let server_ephemeral = server_ephemeral.expect("the server ephemeral is a point on the curve");
		let candidates = vec![
			fixture_agreement(0x00),
			exchange_of(static_key, &client_ephemeral),
			exchange_of(static_key, &server_ephemeral),
			x_coordinate(&client_ephemeral),
			x_coordinate(&server_ephemeral),
		];

		let base = base.map(|base| SecretSlice::from(base.to_vec()));
		let base = base.map(BaseSecret::try_from).transpose();
		let base = base.expect("a recovered base secret has the width of a base secret");
		Self { base, salt: salt.as_ref().to_vec(), candidates }
	}

	/// Open `record`, the DER of a recorded client record, under every record
	/// key the observer derives, in both directions, and report each outcome.
	/// Each attempt opens it as a client record, so each reaches the key.
	pub fn record_attempts(&self, record: &[u8]) -> RecordAttempts {
		let mut attempts = Vec::new();
		for secret in self.handshake_secrets() {
			let ciphers = DirectionalCiphers::derive::<DefaultCryptoProvider, _>(&secret, self.salt(), 0);
			let ciphers = ciphers.expect("a handshake secret derives its directional ciphers");
			attempts.push(opened_record(ciphers.client_to_server, record));
			attempts.push(opened_record(ciphers.server_to_client, record));
		}

		let Some(base) = &self.base else {
			return attempts;
		};

		for label in [TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO] {
			attempts.push(opened_record(self.pre_change_key(base, label), record));
		}

		attempts
	}

	/// Open the closing whose DER is `sealed`, of the transcript
	/// `transcript_hash`, under every closing key the observer derives, and
	/// report each outcome.
	pub async fn closing_attempts(&self, transcript_hash: &TranscriptHash, sealed: impl AsRef<[u8]>) -> SealAttempts {
		let sealed = sealed.as_ref();
		let purpose = SecretSeal::Closing;

		// The observer opens the closing as the content type it names, as the
		// server opens it, so each attempt fails at the key alone.
		let envelope = AuthEnvelopedData::from_der(sealed).expect("a recorded closing decodes");
		let content_type = envelope.auth_encrypted_content_info.content_type;
		let mut attempts = Vec::new();

		for secret in self.handshake_secrets() {
			let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, self.salt(), transcript_hash);
			let sealer = sealer.expect("a handshake secret derives a closing key");
			let admitted = purpose.admit(sealed).expect("a recorded closing is admitted for a read");
			attempts.push(sealer.open(admitted, content_type).await);
		}

		let Some(base) = &self.base else {
			return attempts;
		};

		let derived = self.pre_change_kek(base, purpose.label());
		let kek = Kek::try_from(derived.as_slice()).expect("a derived key-encryption key has the width of one");
		let key_identifier = [purpose.domain(), transcript_hash.as_bytes()].concat();
		let opener = Opener::Kek { kek, key_identifier: &key_identifier };
		let opened = envelope.open::<DefaultCryptoProvider>(sealed, &opener, content_type).await;

		attempts.push(opened.map_err(|error| purpose.refusal(error)));

		attempts
	}

	/// The protocol salt as the salt a derivation takes.
	fn salt(&self) -> KdfSalt<'_> {
		KdfSalt::try_from(self.salt.as_slice()).expect("the protocol salt meets the floor")
	}

	/// The handshake secret each candidate yields through the production
	/// derivation.
	fn handshake_secrets(&self) -> Vec<HandshakeSecret> {
		let derive = |shared| derive_handshake_secret(shared, self.base.as_ref(), self.salt());
		let derived: Result<Vec<HandshakeSecret>, HandshakeError> = self.candidates.iter().map(derive).collect();
		derived.expect("each candidate derives a handshake secret")
	}

	/// The record key that `base` alone derives under `label`, with no
	/// ephemeral-ephemeral input.
	fn pre_change_key(&self, base: &BaseSecret, label: &[u8]) -> RuntimeAead {
		let kek = self.pre_change_kek(base, label);
		RuntimeAead::new::<DefaultCryptoProvider>(kek).expect("a derived key-encryption key makes a record key")
	}

	/// The key-encryption key that `base` alone derives under `label`, with
	/// no ephemeral-ephemeral input.
	fn pre_change_kek(&self, base: &BaseSecret, label: &[u8]) -> ZeroizingBytes {
		let kek = ObserverKdf::derive_dynamic_key(base.as_bytes(), label, Some(self.salt()), OBSERVER_KEK_SIZE);
		kek.expect("a base secret derives a key-encryption key")
	}
}

/// The x-coordinate of `point` in the place of the secret of an exchange.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn x_coordinate(point: &PublicKey<Secp256k1>) -> ExchangeSecret {
	let encoded = point.to_encoded_point(false);
	let x = encoded.x().expect("an affine point has an x-coordinate");
	ExchangeSecret::fixture(x.to_vec())
}

/// An ephemeral scalar of the fixed key of `seed`, for a test whose
/// ephemeral needs no fresh draw. Distinct seeds give distinct scalars.
pub fn fixture_ephemeral(seed: u8) -> SecretKey {
	SecretKey::from(TestKey::fixed(seed))
}

/// A `SignedData` over `content` of type `id-data` by the fixed test key of
/// seed `0x0d`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn create_test_signed_data(content: impl AsRef<[u8]>) -> SignedData {
	let signing_key = TestIdentity::certified(TestKey::fixed(0x0d));
	let content = content.as_ref();
	let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&signing_key, SignedContent::data(content));
	let signer = signer.expect("the test key signs");

	let signed_data = CmsSigner::signed_data(SignedContent::data(content), signer, None);
	let signed_data = signed_data.expect("the SignedData assembles");
	signed_data.into_inner()
}

/// A key provider that counts the public keys it hands out, over the provider
/// of a test signing key. An HSM or a KMS answers each such call with a round
/// trip, so the count is what a handshake costs it. No runner attaches an
/// HSM, so this wrapper counts the calls one would answer.
#[derive(Debug)]
pub struct CountingProvider {
	inner: Arc<dyn SigningKeyProvider>,
	public_keys: AtomicUsize,
}

impl CountingProvider {
	/// A counter at zero over the provider of `signing_key`.
	pub fn new(signing_key: Secp256k1SigningKey) -> Self {
		Self { inner: TestKey::provider(signing_key), public_keys: AtomicUsize::new(0) }
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
/// test signing key, so a test can look for those bytes on the wire. No
/// provider of the crate reports the signatures it made, so no real instance
/// runs this case.
#[derive(Debug)]
pub struct RecordingProvider {
	inner: Arc<dyn SigningKeyProvider>,
	signatures: Mutex<Vec<Vec<u8>>>,
}

impl RecordingProvider {
	/// A provider over `signing_key` that has made no signature.
	pub fn new(signing_key: Secp256k1SigningKey) -> Self {
		Self { inner: TestKey::provider(signing_key), signatures: Mutex::new(Vec::new()) }
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

/// The validator that pins `certificate` alone, by its fingerprint.
pub fn pin_of(certificate: &Certificate) -> Arc<dyn CertificateValidation> {
	let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([certificate.to_owned()]);
	Arc::new(pinning.expect("the test certificate has a fingerprint"))
}

/// `signed` with its one signer rewritten by `edit`, as an on-path party
/// would rewrite it.
pub fn with_signer(mut signed: SignedData, edit: impl FnOnce(SignerInfo) -> SignerInfo) -> SignedData {
	let signer = signed.sole_signer().expect("a handshake message has one signer");
	let edited = edit(signer.to_owned());

	signed.signer_infos = vec![edited].try_into().expect("one signer is a SET");
	signed
}

/// `signed` with the unsigned attributes of its one signer rewritten by
/// `edit`. The unsigned attributes sit outside the signature.
pub fn with_unsigned_attrs(signed: SignedData, edit: impl FnOnce(Vec<Attribute>) -> Vec<Attribute>) -> SignedData {
	with_signer(signed, |signer| {
		let carried = signer.unsigned_attrs.to_owned().map(SetOfVec::into_vec).unwrap_or_default();
		let unsigned = Attributes::try_from(edit(carried)).expect("the attributes are a SET");
		SignerInfo { unsigned_attrs: Some(unsigned), ..signer }
	})
}

/// `signed` with `certificates` in place of the set it carries, or with no
/// set when `certificates` is `None`.
pub fn with_certificate_set(mut signed: SignedData, certificates: Option<CertificateSet>) -> SignedData {
	signed.certificates = certificates;
	signed
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
/// answer. The application supplies the authorizer, so the crate ships no real
/// instance to run.
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
/// [`ChallengingAuthorizer`] does. The application supplies the authorizer,
/// so the crate ships no real instance to run.
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
/// to the trait default, which refuses a challenged receipt. The application
/// supplies the authorizer, so the crate ships no real instance to run.
pub struct RefusingAuthorizer;

impl TransportAuthorizer for RefusingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		ChallengingAuthorizer.authorize(offer)
	}
}

/// Approves every receipt and answers its challenge with the test answer. The
/// application supplies the approver, so the crate ships no real instance to
/// run.
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

/// The credit unit of [`fixture_receipt`], in bytes.
pub const FIXTURE_CREDIT_UNIT: u32 = 1024;

/// The receipt that grants `budgets` at [`FIXTURE_CREDIT_UNIT`] over the
/// transcript of [`fixture_transcript_hash`], with `ancillary` as its
/// settlement challenge.
pub fn fixture_receipt(budgets: MuxBudgets, ancillary: Option<&[u8]>) -> SessionReceipt {
	let algorithm = crate::asn1::AlgorithmIdentifier { oid: HASH_SHA3_256, parameters: None };
	let digest = OctetString::new([0x07; 32]).expect("32 octets encode");
	let ancillary = ancillary.map(OctetString::new).transpose().expect("the challenge encodes");

	let transcript_hash = crate::asn1::DigestInfo { algorithm, digest };
	SessionReceipt { transcript_hash, budgets, credit_unit: FIXTURE_CREDIT_UNIT, ancillary }
}

/// The signing identity of `identity`'s certificate, whose key sits behind
/// `key`.
pub fn presenting(identity: &HandshakeCertificate, key: Arc<dyn SigningKeyProvider>) -> SigningIdentity {
	let certificate = identity.certificate.to_owned();
	SigningIdentity::new(certificate, key).expect("the test key matches its certificate")
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
pub fn hpke_server(identity: &HandshakeCertificate) -> TestServerConfig<Hpke> {
	let profiles = SupportedProfiles::from(create_default_test_profile());
	let identity = identity.signing_identity();
	let config = ServerConfig::new(HpkeServerSettings::new(), identity, profiles, KeyPurposes::HOUSE);
	config.expect("a test server identity serves the server role")
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
	fn client(server: &TestCmsServer, identity: &HandshakeCertificate) -> TestClientConfig<Self> {
		Self::client_presenting(server, identity.signing_identity())
	}

	/// The configuration of a client that admits `server` and presents
	/// `identity`, whose key may sit behind any provider.
	fn client_presenting(server: &TestCmsServer, identity: SigningIdentity) -> TestClientConfig<Self>;

	/// The configuration of a server that holds `identity`, demands no client
	/// certificate, and runs the default test profile.
	fn server(identity: &TestCmsServer) -> TestServerConfig<Self> {
		Self::server_presenting(identity, identity.signing_identity())
	}

	/// The configuration of a server that holds `identity` and signs under
	/// `signing`, demands no client certificate, and runs the default test
	/// profile.
	fn server_presenting(identity: &TestCmsServer, signing: SigningIdentity) -> TestServerConfig<Self>;

	/// Open the recorded legs of `run` with the static keys of
	/// `server_identity`, through the same path the server runs.
	async fn recover(run: &Run<Self>, server_identity: &TestCmsServer) -> Recovered;

	/// A reply that the key of `server` signs in answer to `opening`, over the
	/// transcript a client of that opening seals. It selects `accept` when one
	/// is given, carries `server_ephemeral` as the octets of the server share,
	/// and carries no server Finished.
	fn hand_built_reply(
		server: &TestCmsServer,
		opening: &HandshakeMessage,
		accept: Option<SecurityProfileDesc>,
		server_ephemeral: impl AsRef<[u8]>,
	) -> HandshakeMessage;

	/// `reply` with `server_ephemeral` as the octets of the server share it
	/// carries. The signature still covers the share the server signed.
	fn with_server_ephemeral(reply: &HandshakeMessage, server_ephemeral: impl AsRef<[u8]>) -> HandshakeMessage;

	/// `reply` without the accept it carries. The signature still covers the
	/// accept the server signed.
	fn without_accept(reply: &HandshakeMessage) -> HandshakeMessage;

	/// A server under `peer_authentication` that has answered a hand-built
	/// opening of the agreement ephemeral `ephemeral`, so it awaits the
	/// closing.
	async fn awaiting_closing(peer_authentication: PeerAuthentication, ephemeral: SecretKey) -> AwaitingClosing<Self>;

	/// The terms that the server of a handshake under the provider `P` agreed,
	/// once the three legs ran with a client that presents the test certificate
	/// of seed `0xa2`.
	async fn agreed_under<P: HandshakeProvider<Kem = DhKemSecp256k1>>() -> AgreedTerms;
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

	fn client_presenting(server: &TestCmsServer, identity: SigningIdentity) -> TestClientConfig<Self> {
		hpke_client(&server.signing, Some(identity))
	}

	fn server_presenting(_identity: &TestCmsServer, signing: SigningIdentity) -> TestServerConfig<Self> {
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let config = ServerConfig::new(HpkeServerSettings::new(), signing, profiles, KeyPurposes::HOUSE);
		config.expect("a test server identity serves the server role")
	}

	/// The HPKE flow seals nothing to the server, so the static key opens no
	/// leg. The observer holds the two ephemerals as the hello and the reply
	/// carried them in clear.
	async fn recover(run: &Run<Self>, server_identity: &TestCmsServer) -> Recovered {
		let static_key = SecretKey::from(server_identity.signing_key.to_owned());
		let hello = run.opening.carried_hello();
		let handshake = run.reply.signed_handshake();
		let salt = [hello.client_random.as_bytes(), handshake.server_random.as_bytes()].concat();
		let server_ephemeral = handshake.server_ephemeral.as_bytes();
		let client_ephemeral = hello.client_ephemeral.as_bytes();

		let observer = StaticKeyObserver::new(&static_key, None, client_ephemeral, server_ephemeral, salt);
		Recovered { observer, base: None }
	}

	fn hand_built_reply(
		server: &TestCmsServer,
		opening: &HandshakeMessage,
		accept: Option<SecurityProfileDesc>,
		server_ephemeral: impl AsRef<[u8]>,
	) -> HandshakeMessage {
		let signer = HandshakeCertificate::signing_of(server);
		signed_reply(&signer, opening, &reply_content(accept, server_ephemeral))
	}

	/// The share is a field of the signed `ServerHandshake`.
	fn with_server_ephemeral(reply: &HandshakeMessage, server_ephemeral: impl AsRef<[u8]>) -> HandshakeMessage {
		let share = OctetString::new(server_ephemeral.as_ref()).expect("a share is an OCTET STRING");
		reply.with_content(|handshake| handshake.server_ephemeral = share)
	}

	/// The accept is a field of the signed `ServerHandshake`.
	fn without_accept(reply: &HandshakeMessage) -> HandshakeMessage {
		reply.with_content(|handshake| handshake.security_accept = None)
	}

	/// The opening is a hello of [`CLIENT_RANDOM`], and the salt of the
	/// handshake is that random followed by the server random.
	async fn awaiting_closing(peer_authentication: PeerAuthentication, ephemeral: SecretKey) -> AwaitingClosing<Self> {
		let identity = create_test_server();
		let mut config = Self::server(&identity);
		config.peer_authentication = peer_authentication;

		let mut server = Handshake::server(config);
		let reply = server.reply(hello_opening(&hello_of(&ephemeral))).await;
		let reply = reply.expect("the server admits the hello");
		let handshake = reply.signed_handshake();
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(handshake.server_ephemeral.as_bytes());
		let confirming = Confirming {
			server_ephemeral: server_ephemeral.expect("the reply carries a point on the curve"),
			salt: [CLIENT_RANDOM.as_slice(), handshake.server_random.as_bytes()].concat(),
			transcript_hash: server.transcript_hash().expect("the reply sealed the transcript"),
		};

		AwaitingClosing { server, reply, confirming, ephemeral, base: None }
	}

	async fn agreed_under<P: HandshakeProvider<Kem = DhKemSecp256k1>>() -> AgreedTerms {
		let server = create_test_server();
		let identity = Some(create_test_certificate(0xa2).signing_identity());
		let settings = hpke_client_settings(&server.signing, identity);
		let client = ClientConfig::<Self, P>::new(settings, KeyPurposes::HOUSE);
		let profiles = SupportedProfiles::from(RunnableProfile::<P>::native().descriptor());
		let signing = server.signing_identity();
		let config = ServerConfig::<Self, P>::new(HpkeServerSettings::new(), signing, profiles, KeyPurposes::HOUSE);

		let client = client.expect("a test client identity serves the client role");
		agreed_terms(client, config.expect("a test server identity serves the server role")).await
	}
}

#[cfg(feature = "transport-cms")]
impl TestFlow for Cms {
	const RECORD_ATTEMPTS: usize = 12;
	const CLOSING_ATTEMPTS: usize = 6;

	fn client_presenting(server: &TestCmsServer, identity: SigningIdentity) -> TestClientConfig<Self> {
		let settings = CmsClientSettings { trust: server.trust(), identity };
		let config = ClientConfig::new(settings, KeyPurposes::HOUSE);
		config.expect("a test client identity serves the client role")
	}

	fn server_presenting(identity: &TestCmsServer, signing: SigningIdentity) -> TestServerConfig<Self> {
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let pair = CmsIdentityPair::new(signing, identity.key_agreement_identity());
		let pair = pair.expect("the two test certificates name one subject with two keys");
		let config = ServerConfig::new(CmsServerSettings, pair, profiles, KeyPurposes::HOUSE);
		config.expect("a test server pair serves the server role")
	}

	/// The key-agreement key opens the opening, and the observer holds it as
	/// the static key that a recorded session meets later.
	async fn recover(run: &Run<Self>, server_identity: &TestCmsServer) -> Recovered {
		let opening = run.opening.to_owned().auth_enveloped();
		let opening = opening.expect("a CMS opening is an AuthEnvelopedData");
		let static_key = SecretKey::from(server_identity.key_agreement_key.to_owned());
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

		Recovered { observer, base: Some(base) }
	}

	/// The reply is a server Finished, whose transcript binds the accept and
	/// the share as its unsigned attributes carry them.
	fn hand_built_reply(
		server: &TestCmsServer,
		opening: &HandshakeMessage,
		accept: Option<SecurityProfileDesc>,
		server_ephemeral: impl AsRef<[u8]>,
	) -> HandshakeMessage {
		let share = attribute(&originator_holding(server_ephemeral));
		let accept = accept.map(SecurityAccept::new);
		let signer = HandshakeCertificate::signing_of(server);
		let finished = server_finished_selecting(&signer, opening.der(), accept, [share]);
		HandshakeMessage::try_from(finished).expect("a Finished encodes")
	}

	/// The share is an unsigned attribute, which the signed transcript binds.
	fn with_server_ephemeral(reply: &HandshakeMessage, server_ephemeral: impl AsRef<[u8]>) -> HandshakeMessage {
		let share = attribute(&originator_holding(server_ephemeral));
		let share = Attribute::try_from(share).expect("the share is an attribute");
		reply.with_unsigned(|carried| [without_attribute(carried, HANDSHAKE_SERVER_EPHEMERAL), vec![share]].concat())
	}

	/// The accept is an unsigned attribute, which the signed transcript binds.
	fn without_accept(reply: &HandshakeMessage) -> HandshakeMessage {
		reply.with_unsigned(|carried| without_attribute(carried, SecurityAccept::OID))
	}

	/// The opening is that of [`AwaitingClosing::under`], with no offer.
	async fn awaiting_closing(peer_authentication: PeerAuthentication, ephemeral: SecretKey) -> AwaitingClosing<Self> {
		let identity = create_test_server();
		let mut config = Self::server(&identity);
		config.peer_authentication = peer_authentication;

		AwaitingClosing::under(&identity, config, ephemeral, []).await
	}

	async fn agreed_under<P: HandshakeProvider<Kem = DhKemSecp256k1>>() -> AgreedTerms {
		let server = create_test_server();
		let identity = create_test_certificate(0xa2).signing_identity();
		let settings = CmsClientSettings { trust: server.trust(), identity };
		let client = ClientConfig::<Self, P>::new(settings, KeyPurposes::HOUSE);
		let profiles = SupportedProfiles::from(RunnableProfile::<P>::native().descriptor());
		let config = ServerConfig::<Self, P>::new(CmsServerSettings, server.pair(), profiles, KeyPurposes::HOUSE);

		let client = client.expect("a test client identity serves the client role");
		agreed_terms(client, config.expect("a test server pair serves the server role")).await
	}
}

/// A server of flow `F` that has answered a hand-built opening, so it awaits
/// the closing, beside what the client that built the opening holds.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct AwaitingClosing<F: TestFlow> {
	/// The server, with its reply sent.
	pub server: TestServer<F>,
	/// The reply the server sent to the opening.
	pub reply: HandshakeMessage,
	/// What the reply confirms, as the client reads it.
	pub confirming: Confirming,
	/// The agreement ephemeral `R` of the opening.
	pub ephemeral: SecretKey,
	/// The base secret the opening sealed, when the flow carries one.
	pub base: Option<BaseSecret>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<F: TestFlow> AwaitingClosing<F> {
	/// The transcript hash the reply sealed.
	pub fn transcript_hash(&self) -> &TranscriptHash {
		&self.confirming.transcript_hash
	}

	/// The key-confirmation tag of the client that built the opening.
	pub fn tag(&self) -> KeyConfirmation {
		self.confirming.tag(self.base.as_ref(), &self.ephemeral)
	}

	/// The closing sealer of the client that built the opening.
	pub fn closing_sealer(&self) -> Sealer<DefaultCryptoProvider> {
		self.confirming.closing_sealer(self.base.as_ref(), &self.ephemeral)
	}

	/// The closing that carries `finished`, sealed under the closing key of
	/// the client that built the opening, as that client seals it.
	pub fn sealed(&self, finished: &SignedData) -> HandshakeMessage {
		sealed_closing(self.closing_sealer(), finished)
	}

	/// `finished` sealed as [`Self::sealed`] seals it, before it travels as a
	/// closing.
	pub fn sealed_finished(&self, finished: &SignedData) -> AuthEnvelopedData {
		sealed_finished(self.closing_sealer(), finished)
	}

	/// The client Finished of `client` over the transcript the reply sealed,
	/// with the tag of the client that built the opening.
	pub fn finished_of(&self, client: &HandshakeCertificate) -> SignedData {
		build_test_client_finished(client, self.transcript_hash(), &self.tag())
	}

	/// What the server answers to the closing that carries `finished`, sealed
	/// as [`Self::sealed`] seals it.
	pub async fn finish(&mut self, finished: &SignedData) -> Result<(), HandshakeError> {
		let closing = self.sealed(finished);
		self.server.finish(closing).await
	}
}

/// What the server of a handshake agreed, once the three legs ran.
pub struct AgreedTerms {
	/// The hash of the transcript the server sealed.
	pub transcript_hash: TranscriptHash,
	/// The profile the server selected.
	#[cfg(feature = "preview-pqc")]
	pub profile: SecurityProfileDesc,
}

/// Drive a client under `client` and a server under `server` through the
/// three legs, and take the terms the server agreed.
async fn agreed_terms<F, P>(client: ClientConfig<F, P>, server: ServerConfig<F, P>) -> AgreedTerms
where
	F: ClientFlow<P> + ServerFlow<P>,
	P: HandshakeProvider,
{
	let mut client = Handshake::client(client);
	let mut server = Handshake::server(server);
	let opening = client.start().expect("the client builds its opening");
	let reply = server.reply(opening).await.expect("the server admits the opening");
	let closing = client.respond(reply).await.expect("the client admits the reply");

	server.finish(closing).await.expect("the server admits the closing");

	let transcript_hash = server.transcript_hash().expect("the reply sealed the transcript");
	#[cfg(feature = "preview-pqc")]
	let profile = server.selected_profile().expect("the reply selected a profile");
	AgreedTerms {
		transcript_hash,
		#[cfg(feature = "preview-pqc")]
		profile,
	}
}

/// A client of flow `F` that admits `server` and presents the test certificate
/// of seed `0xa1`, beside the reply that a server of `server` sent to its
/// opening.
pub async fn replied<F: TestFlow>(server: &TestCmsServer) -> (TestClient<F>, HandshakeMessage) {
	let mut client = Handshake::client(F::client(server, &create_test_certificate(0xa1)));
	let mut replying = Handshake::server(F::server(server));
	let opening = client.start().expect("a fresh client builds its opening");
	let reply = replying.reply(opening).await.expect("the server admits the opening");
	(client, reply)
}

/// `attributes` without the attributes of `oid`.
pub fn without_attribute(attributes: Vec<Attribute>, oid: ObjectIdentifier) -> Vec<Attribute> {
	attributes.into_iter().filter(|attribute| attribute.oid != oid).collect()
}

/// The attribute that carries `payload`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn attribute<T: AttributePayload + Tagged + EncodeValue>(payload: &T) -> HandshakeAttribute {
	HandshakeAttribute::encode(payload).expect("the payload encodes as an attribute")
}

/// `attributes` as the unsigned attributes of a Finished.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn unsigned_attrs(attributes: Vec<HandshakeAttribute>) -> Attributes {
	let encoded = attributes.into_iter().map(Attribute::try_from);
	let encoded: Result<Vec<_>, _> = encoded.collect();
	Attributes::try_from(encoded.expect("each attribute encodes")).expect("the attributes are a SET")
}

/// A Finished of `role` signed by `key` over `transcript_hash` and
/// `certificate`, built by hand from the CMS signer. It carries no
/// unsigned attribute and no certificate, and its `sid` is the key
/// identifier of `key`, which the test certificate of `key` carries.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn signed_finished(
	role: FinishedRole,
	key: &Secp256k1SigningKey,
	transcript_hash: &TranscriptHash,
	certificate: &Certificate,
) -> SignedData {
	let content = role.content::<Sha3_256>(transcript_hash, certificate);
	let content = content.expect("the Finished content builds");
	let signed = SignedContent::data(&content);
	let key = TestIdentity::certified(key.clone());
	let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&key, signed).expect("the test key signs");

	let finished = CmsSigner::signed_data(SignedContent::data(&content), signer, None);
	let finished = finished.expect("the Finished assembles");
	finished.into_inner()
}

/// A client Finished signed by `client` over `transcript_hash` that embeds
/// its certificate and carries `confirmation`, as a client with an identity
/// builds it before the seal.
///
/// The fixture builds it outside the client flow, so a server that reads it
/// is tested against the message format alone.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn build_test_client_finished(
	client: &HandshakeCertificate,
	transcript_hash: &TranscriptHash,
	confirmation: &KeyConfirmation,
) -> SignedData {
	let signed = signed_finished(FinishedRole::Client, &client.signing_key, transcript_hash, &client.certificate);
	let confirmed = with_unsigned_attrs(signed, |_| vec![finished_attribute(confirmation)]);
	with_certificate_set(confirmed, Some(TestCertificate::set_of([client.certificate.to_owned()])))
}

/// `finished` sealed under `sealer` as the `AuthEnvelopedData` a client
/// sends: content of type `id-signedData` under the closing key.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn sealed_finished(sealer: Sealer<DefaultCryptoProvider>, finished: &SignedData) -> AuthEnvelopedData {
	let finished_der = finished.to_der().expect("the Finished encodes");
	let sealed = sealer.seal(SIGNED_DATA, finished_der);
	sealed.expect("the Finished seals")
}

/// The closing that carries `finished` sealed under `sealer`, as a client
/// seals its Finished.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn sealed_closing(sealer: Sealer<DefaultCryptoProvider>, finished: &SignedData) -> HandshakeMessage {
	let sealed = sealed_finished(sealer, finished);
	HandshakeMessage::try_from(sealed).expect("the closing encodes")
}

/// The client random each hand-built hello carries.
#[cfg(feature = "transport-hpke")]
pub const CLIENT_RANDOM: [u8; 32] = [7u8; 32];

/// A hello that carries [`CLIENT_RANDOM`] and the public half of
/// `ephemeral`, as a client that keeps `ephemeral` builds it.
#[cfg(feature = "transport-hpke")]
pub fn hello_of(ephemeral: &SecretKey) -> ClientHello {
	let client_ephemeral = EcdheShare::from(ephemeral.public_key()).to_octets();
	hello_carrying(client_ephemeral)
}

/// A hello that carries [`CLIENT_RANDOM`] and `client_ephemeral` as its
/// agreement ephemeral.
#[cfg(feature = "transport-hpke")]
pub fn hello_carrying(client_ephemeral: impl AsRef<[u8]>) -> ClientHello {
	ClientHello {
		client_random: OctetString::new(CLIENT_RANDOM).expect("a random is an OCTET STRING"),
		client_ephemeral: OctetString::new(client_ephemeral.as_ref()).expect("a point is an OCTET STRING"),
		security_offer: None,
		transport_offer: None,
	}
}

/// A reply that `server` signs over `handshake` under `content_type`,
/// with its signing certificate and a transcript-hash attribute over
/// `transcript_hash`. It carries no server Finished, so a client that
/// reads it refuses it at the latest where it reads the server Finished.
#[cfg(feature = "transport-hpke")]
pub fn signed_reply_over(
	server: &HandshakeCertificate,
	handshake: &ServerHandshake,
	transcript_hash: &TranscriptHash,
	content_type: ObjectIdentifier,
) -> HandshakeMessage {
	let content = handshake.to_der().expect("the content encodes");
	let attribute = transcript_hash.attribute().expect("the transcript hash is an attribute");
	let signed = SignedContent::new(content_type, &content).with_attribute(attribute);
	let key = TestIdentity::certified(server.signing_key.to_owned());
	let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&key, signed).expect("the test key signs");

	let certificates = TestCertificate::set_of([server.certificate.to_owned()]);
	let content = SignedContent::new(content_type, &content);
	let reply = CmsSigner::signed_data(content, signer, Some(certificates)).expect("the reply assembles");
	HandshakeMessage::try_from(reply.into_inner()).expect("the reply encodes")
}

/// The reply `server` signs over `handshake` in answer to `opening`, over
/// the transcript a client of that opening seals: the hello, the content,
/// and the `certificates` field that holds the signing certificate.
#[cfg(feature = "transport-hpke")]
pub fn signed_reply(
	server: &HandshakeCertificate,
	opening: &HandshakeMessage,
	handshake: &ServerHandshake,
) -> HandshakeMessage {
	signed_reply_under(server, opening, handshake, HANDSHAKE_REPLY_CONTENT)
}

/// The reply of [`signed_reply`], signed under `content_type`.
#[cfg(feature = "transport-hpke")]
pub fn signed_reply_under(
	server: &HandshakeCertificate,
	opening: &HandshakeMessage,
	handshake: &ServerHandshake,
	content_type: ObjectIdentifier,
) -> HandshakeMessage {
	let content = handshake.to_der().expect("the content encodes");
	let certificates = certificates_field([server.certificate.to_owned()]);
	let transcript = [opening.der(), content.as_slice(), certificates.as_slice()].concat();
	let transcript_hash = Transcript::digest::<Sha3_256>(transcript).expect("the transcript hashes");
	signed_reply_over(server, handshake, &transcript_hash, content_type)
}

/// The content of a reply that accepts `profile`, when one is given, and
/// carries `server_ephemeral`.
#[cfg(feature = "transport-hpke")]
pub fn reply_content(profile: Option<SecurityProfileDesc>, server_ephemeral: impl AsRef<[u8]>) -> ServerHandshake {
	let accept = profile.map(|profile| WireDer::new(SecurityAccept::new(profile)).expect("an accept encodes"));
	ServerHandshake {
		server_random: OctetString::new([2u8; 32]).expect("a random is an OCTET STRING"),
		server_ephemeral: OctetString::new(server_ephemeral.as_ref()).expect("a point is an OCTET STRING"),
		security_accept: accept,
		client_cert_required: false,
		transport_accept: None,
	}
}

#[cfg(feature = "transport-hpke")]
impl AwaitingClosing<Hpke> {
	/// The closing that carries `content` of `content_type`, sealed as the
	/// client that built the hello seals it.
	pub fn sealed_as(&self, content_type: ObjectIdentifier, content: Vec<u8>) -> HandshakeMessage {
		let sealed = self.closing_sealer().seal(content_type, content).expect("the closing seals");
		HandshakeMessage::try_from(sealed).expect("the closing encodes")
	}

	/// The anonymous closing that carries `attributes` as its attribute set,
	/// sealed under the closing key that `confirming` derives for the client
	/// that built the hello.
	pub fn anonymous_under(&self, confirming: &Confirming, attributes: Vec<Attribute>) -> HandshakeMessage {
		let attributes = Attributes::try_from(attributes).expect("distinct attributes are a SET");
		let attributes = attributes.to_der().expect("the attribute set encodes");
		let sealer = confirming.closing_sealer(self.base.as_ref(), &self.ephemeral);
		let sealed = sealer.seal(DATA, attributes).expect("the closing seals");
		HandshakeMessage::try_from(sealed).expect("the closing encodes")
	}

	/// What the server answers to the anonymous closing that carries
	/// `attributes`, sealed as the client that built the hello seals it.
	pub async fn finish_anonymous(&mut self, attributes: Vec<Attribute>) -> Result<(), HandshakeError> {
		let closing = self.anonymous_under(&self.confirming, attributes);
		self.server.finish(closing).await
	}
}

/// The originator key of `key`, as the house exchange encodes a share.
#[cfg(feature = "transport-cms")]
pub fn originator_of(key: PublicKey<Secp256k1>) -> OriginatorPublicKey {
	let share = EcdheShare::from(key);
	let encoded = share.to_originator_key();
	encoded.expect("a point encodes as an originator key")
}

/// The originator key of `id-ecPublicKey` on secp256k1 (RFC 5480 §2.2) whose
/// public key is `octets`, which may name no point of the curve.
#[cfg(feature = "transport-cms")]
pub fn originator_holding(octets: impl AsRef<[u8]>) -> OriginatorPublicKey {
	let curve = AnyValue::encode_from(&CURVE_SECP256K1).expect("an OID encodes");
	let algorithm = AlgorithmIdentifierOwned { oid: ID_EC_PUBLIC_KEY, parameters: Some(curve) };
	let public_key = BitString::from_bytes(octets.as_ref()).expect("octets are a BIT STRING");
	OriginatorPublicKey { algorithm, public_key }
}

/// A server Finished signed by `server` over the transcript of `opening`
/// followed by the value of `accept` when one is given, the value of each of
/// `replies` in order, and the `certificates` field of `server`. It carries
/// those attributes and no server Finished MAC.
#[cfg(feature = "transport-cms")]
pub fn server_finished_selecting(
	server: &HandshakeCertificate,
	opening: impl AsRef<[u8]>,
	accept: Option<SecurityAccept>,
	replies: impl IntoIterator<Item = HandshakeAttribute>,
) -> SignedData {
	let attributes: Vec<HandshakeAttribute> = accept.iter().map(attribute).chain(replies).collect();
	let value = |attribute: &HandshakeAttribute| attribute.received_bytes().expect("an attribute value encodes");
	let values: Vec<u8> = attributes.iter().flat_map(value).collect();
	let certificates = certificates_field([server.certificate.to_owned()]);
	let transcript = [opening.as_ref(), &values, &certificates].concat();

	signed_server_finished(server, &transcript, unsigned_attrs(attributes))
}

/// A server Finished signed by `server` over `transcript` that carries
/// `attrs` and the certificate of `server`.
#[cfg(feature = "transport-cms")]
pub fn signed_server_finished(server: &HandshakeCertificate, transcript: &[u8], attrs: Attributes) -> SignedData {
	let transcript_hash = Transcript::digest::<Sha3_256>(transcript).expect("the transcript hashes");
	let signed = signed_finished(FinishedRole::Server, &server.signing_key, &transcript_hash, &server.certificate);
	let signed = with_unsigned_attrs(signed, |_| attrs.into_vec());
	with_certificate_set(signed, Some(TestCertificate::set_of([server.certificate.to_owned()])))
}

/// The opening of [`build_test_opening_of`] whose agreement key is the public
/// half of `ephemeral`, for a fixture that keeps that key to derive the
/// handshake secret.
#[cfg(feature = "transport-cms")]
pub fn build_test_opening_from(
	ephemeral: SecretKey,
	server: &Certificate,
	base: &[u8],
	auth_attrs: impl IntoIterator<Item = HandshakeAttribute>,
) -> AuthEnvelopedData {
	let agreement_key = originator_of(ephemeral.public_key());
	build_test_opening_of(server, base, agreement_key, auth_attrs)
}

/// The opening that seals `base` and `agreement_key` to `server`, as the
/// content of the opening, and authenticates `auth_attrs`.
#[cfg(feature = "transport-cms")]
pub fn build_test_opening_of(
	server: &Certificate,
	base: &[u8],
	agreement_key: OriginatorPublicKey,
	auth_attrs: impl IntoIterator<Item = HandshakeAttribute>,
) -> AuthEnvelopedData {
	let base_secret = OctetString::new(base).expect("bytes are an OCTET STRING");
	let content = OpeningContent { base_secret, agreement_key };
	let content = content.to_der().expect("the content encodes");
	let attributes: Result<Vec<_>, _> = auth_attrs.into_iter().map(Attribute::try_from).collect();
	let attributes = attributes.expect("each handshake attribute is an attribute");
	let recipient = recipient_of(server);
	let recipient = Recipient::Kem { recipient: &recipient, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };

	let sealed = AuthEnvelopedData::seal::<DefaultCryptoProvider>(
		recipient,
		HANDSHAKE_OPENING_CONTENT,
		content,
		attributes,
		None,
	);
	sealed.expect("the opening seals")
}

/// The KEM recipient of `certificate`, admitted for key agreement under
/// the house KEM.
#[cfg(feature = "transport-cms")]
pub fn recipient_of(certificate: &Certificate) -> KemRecipient<DhKemSecp256k1> {
	let purpose = KeyPurposes::HOUSE.server;
	let admitted = PeerCertificate::<KeyAgreement<DhKemSecp256k1>>::parse(certificate.to_owned(), purpose);
	let admitted = admitted.expect("the test certificate is admitted for key agreement");
	KemRecipient::from_certificate(admitted).expect("the test certificate names its recipient")
}

#[cfg(feature = "transport-cms")]
impl AwaitingClosing<Cms> {
	/// A server under `config`, which holds `identity`, that has answered a
	/// hand-built opening of the agreement ephemeral `ephemeral` that
	/// authenticates `offers`.
	///
	/// The opening seals a base secret of `0x02` octets beside `ephemeral`,
	/// and the salt of the handshake is the transcript hash.
	pub async fn under(
		identity: &TestCmsServer,
		config: TestServerConfig<Cms>,
		ephemeral: SecretKey,
		offers: impl IntoIterator<Item = HandshakeAttribute>,
	) -> Self {
		let base = fixture_base_secret(0x02);
		let recipient = &identity.key_agreement;
		let sealed = build_test_opening_from(ephemeral.to_owned(), recipient, base.as_bytes(), offers);
		let opening = HandshakeMessage::try_from(sealed).expect("the opening encodes");
		let mut server = Handshake::server(config);
		let reply = server.reply(opening).await;
		let reply = reply.expect("the server answers the opening");
		let signed = reply.to_owned().signed();
		let signed = signed.expect("a CMS reply is a SignedData");
		let carried = signed.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL);
		let carried = carried.expect("the ephemeral attribute is single");
		let carried = carried.expect("the server Finished carries its ephemeral");
		let originator = carried.decode::<OriginatorPublicKey>().expect("the ephemeral decodes");
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(originator.public_key.raw_bytes());
		let transcript_hash = server.transcript_hash().expect("the reply sealed the transcript");
		let confirming = Confirming {
			server_ephemeral: server_ephemeral.expect("the server ephemeral is a point on the curve"),
			salt: transcript_hash.as_bytes().to_vec(),
			transcript_hash,
		};

		AwaitingClosing { server, reply, confirming, ephemeral, base: Some(base) }
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
pub async fn mutual_run<F: TestFlow>(
	client_identity: &HandshakeCertificate,
	key: Arc<dyn SigningKeyProvider>,
) -> Run<F> {
	let server_identity = create_test_server();
	let presented = presenting(client_identity, key);
	let client = F::client_presenting(&server_identity, presented);

	let mut server = F::server(&server_identity);
	server.peer_authentication = PeerAuthentication::mutual_by_expiry();
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
	pub server_identity: TestCmsServer,
	/// The identity the client presents.
	pub client_identity: HandshakeCertificate,
	/// The client configuration, which admits the server.
	pub client: TestClientConfig<F>,
	/// The server configuration.
	pub server: TestServerConfig<F>,
}

/// Two endpoints of flow `F` under `peer_authentication`, where the client
/// admits the server and presents the test certificate of seed `0xa0`.
pub fn parties<F: TestFlow>(peer_authentication: PeerAuthentication) -> Parties<F> {
	let server_identity = create_test_server();
	let client_identity = create_test_certificate(0xa0);
	let client = F::client(&server_identity, &client_identity);

	let mut server = F::server(&server_identity);
	server.peer_authentication = peer_authentication;

	Parties { server_identity, client_identity, client, server }
}

impl<F: TestFlow> Parties<F> {
	/// The parties with the budget-bearing offer on both sides, where
	/// `approver` answers the receipt for the client and `authorizer` grants
	/// the budgets for the server.
	pub fn budget_bearing(
		mut self,
		approver: Arc<dyn ReceiptApprover>,
		authorizer: Arc<dyn TransportAuthorizer>,
	) -> Self {
		self.client.transport_offer = Some(budget_offer());
		self.client.receipt_approver = Some(approver);
		self.server.transport = Some(budget_offer());
		self.server.transport_authorizer = Some(authorizer);
		self
	}
}

/// Two mutual endpoints of flow `F` with the budget-bearing offer on both
/// sides, where [`PayingApprover`] answers the receipt and `authorizer`
/// grants the budgets.
pub fn budget_bearing<F: TestFlow>(authorizer: impl TransportAuthorizer + 'static) -> Parties<F> {
	parties::<F>(PeerAuthentication::mutual_by_expiry()).budget_bearing(Arc::new(PayingApprover), Arc::new(authorizer))
}

/// A fresh client and a fresh server of flow `F` under `peer_authentication`,
/// where the client admits the server and presents the identity of
/// [`parties`].
pub fn pair<F: TestFlow>(peer_authentication: PeerAuthentication) -> (TestClient<F>, TestServer<F>) {
	let Parties { client, server, .. } = parties::<F>(peer_authentication);
	(Handshake::client(client), Handshake::server(server))
}

/// A recorded handshake with both sessions established.
pub struct Established<F: TestFlow> {
	/// The identity the server holds.
	pub server_identity: TestCmsServer,
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

/// Run each named test body once per flow, as a test of each flow's module.
///
/// Each body is an `async fn` generic over [`TestFlow`] that returns a
/// [`TestResult`](crate::testing::TestResult). The attributes of an entry,
/// such as a `#[cfg(..)]`, go on both of its tests.
macro_rules! over_each_flow {
	($($(#[$attr:meta])* $test:ident),* $(,)?) => {
		#[cfg(feature = "transport-hpke")]
		mod hpke {
			$(
				$(#[$attr])*
				#[tokio::test]
				async fn $test() -> $crate::testing::TestResult {
					super::$test::<$crate::transport::handshake::Hpke>().await
				}
			)*
		}

		#[cfg(feature = "transport-cms")]
		mod cms {
			$(
				$(#[$attr])*
				#[tokio::test]
				async fn $test() -> $crate::testing::TestResult {
					super::$test::<$crate::transport::handshake::Cms>().await
				}
			)*
		}
	};
}

pub(crate) use over_each_flow;
