//! Shared test utilities for handshake protocol tests.
//!
//! The module holds the fixtures, helper functions, and data structures that
//! every handshake test module shares, so each setup has one home.
#![allow(unused)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::str::FromStr;
use core::time::Duration;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rand_core::{CryptoRng, RngCore};

use crate::asn1::OctetString;
use crate::cms::content_info::ContentInfo as ContentInfoValue;
use crate::cms::enveloped_data::EncryptedContentInfo;
use crate::cms::signed_data::SignedData;
use crate::constants::{
	EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_ACK_KEY_ID_DOMAIN, TIGHTBEAM_C2S_KDF_INFO,
	TIGHTBEAM_S2C_KDF_INFO,
};
use crate::crypto::aead::{DecryptContent, DirectionalCiphers, KeyInit};
use crate::crypto::cms::{AuthEnvelopedData, Opener};
use crate::crypto::common::KeySizeUser;
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{EcdhSecret, KdfFunction};
use crate::crypto::key::{KeyError, Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::policy::Secp256k1Policy;
use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider, KdfProvider, SecurityProfileDesc};
use crate::crypto::secret::SecretSlice;
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::{CmsSigner, Signed, SignedContent, SigningIdentity};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
use crate::crypto::x509::utils::Skid;
use crate::der::asn1::BitString;
use crate::der::asn1::GeneralizedTime;
use crate::der::asn1::{Any as AnyValue, ObjectIdentifier};
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode, EncodeValue, Tagged};
use crate::oids::{AES_256_WRAP, DATA, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256};
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::testing::TestIdentity;
use crate::transport::handshake::flow::ClientFlow;
use crate::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, RunnableProfile, TransportAuthorizer, TransportOffer,
};
use crate::transport::handshake::primitives::{KdfSalt, TranscriptHash};
use crate::transport::handshake::receipt::{
	ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
};
use crate::transport::handshake::{
	Client, ClientConfig, ClientHello, EstablishedSession, Handshake, HandshakeAttribute, HandshakeError,
	HandshakeMessage, HandshakeSecret, PeerAuthentication, Server, ServerConfig, ServerFlow, ServerHandshake,
	SupportedProfiles,
};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier};
use crate::x509::ext::Extension;
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
	pub use crate::oids::{HANDSHAKE_OPENING_CONTENT, HANDSHAKE_SERVER_EPHEMERAL, RECEIPT_ACK};
	pub use crate::transport::handshake::attributes::HandshakeAttributes;
	pub use crate::transport::handshake::{
		Cms, CmsClientSettings, CmsServerIdentity, CmsServerSettings, ProvisionedTrust,
	};
}

#[cfg(feature = "transport-cms")]
use crate::transport::handshake::flow::OpeningContent;
#[cfg(feature = "transport-cms")]
use cms::*;

/// Create a default test security profile for handshake tests.
pub fn create_default_test_profile() -> SecurityProfileDesc {
	RunnableProfile::<DefaultCryptoProvider>::native().descriptor()
}

/// Test certificate data, so every test creates certificates the same way.
#[derive(Debug, Clone)]
pub struct TestCertificate {
	/// The signing key whose public key the certificate carries.
	pub signing_key: Secp256k1SigningKey,
	/// The certificate over the public key of `signing_key`.
	pub certificate: Certificate,
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

/// A test certificate whose validity period ended one second after the epoch.
pub fn create_expired_test_certificate() -> TestCertificate {
	let mut expired = create_test_certificate();
	let not_after = GeneralizedTime::from_unix_duration(Duration::from_secs(1));
	let not_after = not_after.expect("one second after the epoch is a time");
	expired.certificate.tbs_certificate.validity.not_after = Time::GeneralTime(not_after);
	expired
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
/// certificate the crate mints does, so a CMS signer names it by that value.
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

	// The certificate signs the server Finished and receives the KEM's
	// encapsulation of the opening (RFC 5480 §3, RFC 9629 §3).
	let key_usage = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyAgreement);
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

/// A fresh server ephemeral public key as the compressed SEC1 point the
/// `ServerHandshake` carries. The private half is discarded, so a client that
/// completes against it derives keys nobody else holds.
#[cfg(feature = "transport-hpke")]
pub fn create_test_server_ephemeral() -> [u8; EC_PUBKEY_COMPRESSED_SIZE] {
	let public_key = SecretKey::random(&mut OsRng).public_key();
	public_key.compressed_point().expect("a compressed secp256k1 point is 33 bytes")
}

/// A 33-byte compressed encoding whose x-coordinate lies off secp256k1, so
/// the SEC1 parser refuses it while its length passes every width check.
///
/// About half of all x-coordinates are off the curve, so the search ends after
/// a few candidates.
pub fn off_curve_point() -> [u8; EC_PUBKEY_COMPRESSED_SIZE] {
	let mut candidate = [0u8; EC_PUBKEY_COMPRESSED_SIZE];
	candidate[0] = 0x02;
	for x in 1u8..=u8::MAX {
		candidate[EC_PUBKEY_COMPRESSED_SIZE - 1] = x;
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
	let off_curve = off_curve.expect("33 bytes are a BIT STRING");
	certificate.tbs_certificate.subject_public_key_info.subject_public_key = off_curve;
}

/// Whether `needle` appears anywhere inside `haystack`.
pub fn contains_window(haystack: impl AsRef<[u8]>, needle: impl AsRef<[u8]>) -> bool {
	let needle = needle.as_ref();
	haystack.as_ref().windows(needle.len()).any(|window| window == needle)
}

/// An agreement that yields a chosen secret in place of an ECDH output, so a
/// fixture or an observer runs the production derivation over the value it
/// picked.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
struct FixedAgreement<'a>(&'a EcdhSecret);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeAgreement<Secp256k1> for FixedAgreement<'_> {
	fn shared_secret(&self, _peer: &PublicKey<Secp256k1>) -> EcdhSecret {
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
	shared: &EcdhSecret,
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

/// A handshake secret derived from a fixture ephemeral-ephemeral secret, a
/// fixture base secret of `fill` bytes, and a fixture salt.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn fixture_handshake_secret(fill: u8) -> HandshakeSecret {
	let base = BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret");
	let shared = EcdhSecret::from([0x11u8; 32]);
	derive_handshake_secret(&shared, Some(&base), KdfSalt::new(&[0x99u8; 32]))
		.expect("fixture inputs derive a handshake secret")
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
	let derived = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&FIXTURE_CONFIRMED), &transcript);
	derived.expect("a fixture secret derives a tag")
}

/// What a hand-built closing confirms, as a client reads it from the reply.
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
		let salt = KdfSalt::new(&self.salt);
		let secret = self.secret(base, ephemeral);

		let derived = secret.confirmation::<DefaultCryptoProvider>(salt, &self.transcript_hash);
		derived.expect("the handshake secret derives a tag")
	}

	/// The closing sealer of a client that drew `ephemeral`, and `base` when
	/// the flow carries one.
	pub fn closing_sealer(&self, base: Option<&BaseSecret>, ephemeral: &SecretKey) -> Sealer<DefaultCryptoProvider> {
		let salt = KdfSalt::new(&self.salt);
		let secret = self.secret(base, ephemeral);
		let sealer = secret.sealer::<DefaultCryptoProvider>(SecretSeal::Closing, salt, &self.transcript_hash);
		sealer.expect("the handshake secret derives a closing key")
	}

	/// The handshake secret of the production agreement of `ephemeral` with
	/// the server ephemeral, under `base` when the flow carries one.
	pub fn secret(&self, base: Option<&BaseSecret>, ephemeral: &SecretKey) -> HandshakeSecret {
		let salt = KdfSalt::new(&self.salt);
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
	/// How many outcomes the server reported.
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

/// Seal one record under the client's send cipher.
pub fn sealed_record(client: &EstablishedSession) -> Result<EncryptedContentInfo, TightBeamError> {
	client.keys().send().encrypt_next(RECORD_PLAINTEXT, None)
}

/// The AEAD of the default provider, which the observer keys with what it
/// derives.
type ObserverCipher = <DefaultCryptoProvider as AeadProvider>::AeadCipher;

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
	candidates: Vec<EcdhSecret>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl StaticKeyObserver {
	/// Give the observer `static_key`, the `base` it recovered with it when
	/// the flow carries one, the two ephemeral public keys as SEC1 bytes, and
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
			EcdhSecret::from([0u8; 32]),
			static_key.shared_secret(&client_ephemeral),
			static_key.shared_secret(&server_ephemeral),
			x_coordinate(&client_ephemeral)?,
			x_coordinate(&server_ephemeral)?,
		];

		let base = base.map(|base| SecretSlice::from(base.to_vec()));
		let base = base.map(BaseSecret::try_from).transpose()?;
		Ok(Self { base, salt: salt.as_ref().to_vec(), candidates })
	}

	/// Open `frame` under every traffic key the observer derives, in both
	/// directions, and report each outcome.
	pub fn record_attempts(&self, frame: &EncryptedContentInfo) -> Result<RecordAttempts, Box<dyn Error>> {
		let mut attempts = Vec::new();
		for secret in self.handshake_secrets()? {
			let ciphers = DirectionalCiphers::derive::<DefaultCryptoProvider, _>(&secret, KdfSalt::new(&self.salt))?;
			attempts.push(ciphers.client_to_server.decrypt_content(frame));
			attempts.push(ciphers.server_to_client.decrypt_content(frame));
		}

		let Some(base) = &self.base else {
			return Ok(attempts);
		};

		for label in [TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO] {
			attempts.push(self.pre_change_cipher(base, label)?.decrypt_content(frame));
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
		let salt = KdfSalt::new(&self.salt);
		let mut attempts = Vec::new();
		for secret in self.handshake_secrets()? {
			let sealer = secret.sealer::<DefaultCryptoProvider>(purpose, salt, transcript_hash)?;
			attempts.push(sealer.open(sealed, content_type).await);
		}

		let Some(base) = &self.base else {
			return Ok(attempts);
		};

		let kek = self.pre_change_kek(base, purpose.label())?;
		let key_identifier = [purpose.domain(), transcript_hash.as_bytes()].concat();
		let opener = Opener::Kek { kek: kek.as_slice(), key_identifier: &key_identifier };
		let opened = envelope.open::<DefaultCryptoProvider>(sealed, &opener, content_type).await;

		attempts.push(opened.map_err(|error| purpose.refusal(error)));

		Ok(attempts)
	}

	/// The handshake secret each candidate yields through the production
	/// derivation.
	fn handshake_secrets(&self) -> Result<Vec<HandshakeSecret>, HandshakeError> {
		let salt = KdfSalt::new(&self.salt);
		let derive = |shared| derive_handshake_secret(shared, self.base.as_ref(), salt);
		self.candidates.iter().map(derive).collect()
	}

	/// The cipher that `base` alone keys under `label`, with no
	/// ephemeral-ephemeral input.
	fn pre_change_cipher(&self, base: &BaseSecret, label: &[u8]) -> Result<ObserverCipher, HandshakeError> {
		let key_size = <ObserverCipher as KeySizeUser>::key_size();
		let key = ObserverKdf::derive_dynamic_key(base.as_bytes(), label, Some(&self.salt), key_size)?;
		Ok(ObserverCipher::new_from_slice(&key)?)
	}

	/// The key-encryption key that `base` alone derives under `label`, with
	/// no ephemeral-ephemeral input.
	fn pre_change_kek(&self, base: &BaseSecret, label: &[u8]) -> Result<ZeroizingBytes, HandshakeError> {
		let kek = ObserverKdf::derive_dynamic_key(base.as_bytes(), label, Some(&self.salt), OBSERVER_KEK_SIZE)?;
		Ok(kek)
	}
}

/// The x-coordinate of `point` in the place of an ECDH output.
fn x_coordinate(point: &PublicKey<Secp256k1>) -> Result<EcdhSecret, Box<dyn Error>> {
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

/// A SignedData over `content` of type `id-data` by a fresh test key.
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
/// The function returns a tuple with these parts, in order:
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

	/// How many public keys this provider handed out.
	pub fn public_keys(&self) -> usize {
		self.public_keys.load(Ordering::SeqCst)
	}
}

impl SigningKeyProvider for CountingProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.inner.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.public_keys.fetch_add(1, Ordering::SeqCst);
		self.inner.to_public_key_bytes()
	}

	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		self.inner.sign_prehash(prehash)
	}

	fn key_agreement(&self, peer_public_key: &[u8]) -> MaybeSendFuture<'_, Result<SecretSlice<u8>, KeyError>> {
		self.inner.key_agreement(peer_public_key)
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

impl SigningKeyProvider for RecordingProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.inner.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.inner.to_public_key_bytes()
	}

	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signing = self.inner.sign_prehash(prehash);
		Box::pin(async move {
			let signature = signing.await?;
			let mut signatures = self.signatures.lock().expect("no signer panicked while holding the record");
			signatures.push(signature.to_owned());
			Ok(signature)
		})
	}

	fn key_agreement(&self, peer_public_key: &[u8]) -> MaybeSendFuture<'_, Result<SecretSlice<u8>, KeyError>> {
		self.inner.key_agreement(peer_public_key)
	}
}

/// Mutual authentication against `validator` alone.
pub fn mutual_with(validator: impl CertificateValidation + 'static) -> PeerAuthentication {
	let validator: Arc<dyn CertificateValidation> = Arc::new(validator);
	PeerAuthentication::mutual([validator])
}

/// The budgets a budget-bearing test session requests.
pub const TEST_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// The settlement challenge a challenging test authorizer issues.
pub const TEST_CHALLENGE: &[u8] = b"test settlement challenge";

/// The bearer settlement answer a paying test approver gives.
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
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move { Ok(()) })
	}
}

/// Records the offers it is asked to grant, and grants each as
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

/// The configuration of an HPKE client that admits `server` and presents
/// `identity`, when it holds one.
#[cfg(feature = "transport-hpke")]
pub fn hpke_client(server: &Certificate, identity: Option<SigningIdentity>) -> TestClientConfig<Hpke> {
	let validator = DirectTrustValidator::default().with_trust_chain(vec![server.to_owned()]);
	let mut settings = HpkeClientSettings::new(LearnedTrust::new(validator));
	settings.identity = identity;
	ClientConfig::new(settings)
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
	let content = CmsSigner::content(&signed_data, HANDSHAKE_REPLY_CONTENT);
	let content = content.expect("an HPKE reply signs a ServerHandshake");
	ServerHandshake::from_der(content).expect("the content is a ServerHandshake")
}

/// What an observer who holds the server's static key recovers from a
/// recorded handshake.
pub struct Recovered {
	/// The observer, holding the static key and everything it opened.
	pub observer: StaticKeyObserver,
	/// The base secret the static key opened, when the flow seals one to it.
	/// The HPKE flow seals nothing to the server, so for HPKE it is `None`.
	pub base: Option<Vec<u8>>,
}

/// A flow the handshake tests run over, with the provisioning of its two
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
	fn client(server: &Certificate, identity: &TestCertificate) -> TestClientConfig<Self> {
		Self::client_presenting(server, client_identity(identity))
	}

	/// The configuration of a client that admits `server` and presents
	/// `identity`, whose key may sit behind any provider.
	fn client_presenting(server: &Certificate, identity: SigningIdentity) -> TestClientConfig<Self>;

	/// The configuration of a server that holds `identity`, demands no client
	/// certificate, and runs the default test profile.
	fn server(identity: &TestCertificate) -> TestServerConfig<Self>;

	/// Open the recorded legs of `run` with the static key of
	/// `server_identity`, through the same path the server runs.
	async fn recover(run: &Run<Self>, server_identity: &TestCertificate) -> Recovered;
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

	fn client_presenting(server: &Certificate, identity: SigningIdentity) -> TestClientConfig<Self> {
		hpke_client(server, Some(identity))
	}

	fn server(identity: &TestCertificate) -> TestServerConfig<Self> {
		let profiles = SupportedProfiles::from(create_default_test_profile());
		ServerConfig::new(HpkeServerSettings::new(), signing_identity(identity), profiles)
	}

	/// The HPKE flow seals nothing to the server, so the static key opens no
	/// leg. The observer holds the two ephemerals as the hello and the reply
	/// carried them in clear.
	async fn recover(run: &Run<Self>, server_identity: &TestCertificate) -> Recovered {
		let static_key = SecretKey::from(server_identity.signing_key.to_owned());
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

	fn client_presenting(server: &Certificate, identity: SigningIdentity) -> TestClientConfig<Self> {
		let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(server.to_owned())
			.expect("the store takes a valid test certificate")
			.build();
		let pinned = CmsServerIdentity::Certificate(Arc::new(server.to_owned()));
		let trust = ProvisionedTrust { identity: pinned, store: Arc::new(store) };
		ClientConfig::new(CmsClientSettings { trust, identity })
	}

	fn server(identity: &TestCertificate) -> TestServerConfig<Self> {
		let profiles = SupportedProfiles::from(create_default_test_profile());
		ServerConfig::new(CmsServerSettings, signing_identity(identity), profiles)
	}

	async fn recover(run: &Run<Self>, server_identity: &TestCertificate) -> Recovered {
		let opening = run.opening.to_owned().auth_enveloped();
		let opening = opening.expect("a CMS opening is an AuthEnvelopedData");
		let static_key = SecretKey::from(server_identity.signing_key.to_owned());
		let identity = signing_identity(server_identity);
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

/// The three messages of one handshake as they were sent, with both endpoints
/// after the closing.
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
	let server_identity = create_test_certificate();
	let presented = presenting(client_identity, key);
	let client = F::client_presenting(&server_identity.certificate, presented);

	let mut server = F::server(&server_identity);
	server.peer_authentication = mutual_with(ExpiryValidator);
	run(client, server).await
}

/// Drive a client under `client` and a server under `server` through the
/// three legs, recording each message as it is sent.
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
	pub server_identity: TestCertificate,
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
	let server_identity = create_test_certificate();
	let client_identity = create_test_certificate();
	let client = F::client(&server_identity.certificate, &client_identity);

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
	pub server_identity: TestCertificate,
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

/// `content` of `content_type` inside a CMS `ContentInfo` (RFC 5652 § 3),
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
	/// What opens the seal `sealer` makes for `purpose` over `plaintext`,
	/// whose frame is the plaintext a reader recovers.
	pub fn of(sealer: &Sealer<DefaultCryptoProvider>, purpose: SecretSeal, plaintext: &[u8]) -> Self {
		let (kek, key_identifier) = sealer.kek_opening();
		let framed = purpose.frame(plaintext).expect("the plaintext fits its frame");
		Self { kek, key_identifier, plaintext: framed.to_vec() }
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
