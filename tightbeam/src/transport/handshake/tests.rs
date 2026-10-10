//! Shared test utilities for handshake protocol tests.
//!
//! The module holds the fixtures, helper functions, and data structures that
//! every handshake test module shares, so each setup has one home.
#![allow(unused)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::time::Duration;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::cert::IssuerAndSerialNumber;
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData};
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::cms::signed_data::SignedData;
use crate::constants::{
	EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_ACK_AAD_DOMAIN, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_C2S_KDF_INFO,
	TIGHTBEAM_S2C_KDF_INFO,
};
use crate::crypto::aead::{Aead, DecryptContent, DirectionalCiphers, KeyInit, Nonce, Payload};
use crate::crypto::common::KeySizeUser;
use crate::crypto::kdf::{EcdhSecret, KdfFunction};
use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::policy::Secp256k1Policy;
use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider, KdfProvider, SecurityProfileDesc};
use crate::crypto::secret::SecretSlice;
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
use crate::der::asn1::BitString;
use crate::der::asn1::GeneralizedTime;
use crate::der::{Decode, Encode};
use crate::oids::{AES_256_WRAP, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256};
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::flow::ClientFlow;
use crate::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, RunnableProfile, TransportAuthorizer, TransportOffer,
};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::receipt::{
	ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
};
#[cfg(feature = "transport-ecies")]
use crate::transport::handshake::schedule::CompressedPoint;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::schedule::{Agreement, BaseSecret, HandshakeAgreement, KeyConfirmation};
#[cfg(feature = "transport-ecies")]
use crate::transport::handshake::TunneledMessage;
use crate::transport::handshake::{
	Client, ClientConfig, ClientHello, ClientKeyExchange, EciesSessionPayload, EstablishedSession, Handshake,
	HandshakeAttribute, HandshakeError, HandshakeKeyManager, HandshakeMessage, HandshakeSecret, PeerAuthentication,
	Server, ServerConfig, ServerFlow, ServerHandshake, SupportedProfiles,
};
use crate::transport::state::ClientIdentity;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::serial_number::SerialNumber;
use crate::x509::time::Time;
use crate::x509::time::Validity;
use crate::x509::Certificate;
use crate::x509::{name::RdnSequence, TbsCertificate, Version};
use crate::TightBeamError;

#[cfg(feature = "transport-ecies")]
mod ecies {
	pub use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
	pub use crate::crypto::aead::Aes256Gcm;
	pub use crate::crypto::ecies::{decrypt, EciesMessageOps, Secp256k1EciesMessage};
	pub use crate::crypto::kdf::HkdfSha3_256;
	pub use crate::crypto::x509::policy::DirectTrustValidator;
	pub use crate::transport::handshake::{Ecies, EciesClientSettings, EciesServerSettings, LearnedTrust};
}

#[cfg(feature = "transport-ecies")]
use ecies::*;

#[cfg(feature = "transport-cms")]
mod cms {
	pub use crate::cms::enveloped_data::{OriginatorIdentifierOrKey, OriginatorPublicKey, RecipientInfo};
	pub use crate::oids::{HANDSHAKE_SERVER_EPHEMERAL, RECEIPT_ACK};
	pub use crate::transport::handshake::attributes::HandshakeAttributes;
	pub use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	pub use crate::transport::handshake::processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};
	pub use crate::transport::handshake::{
		Cms, CmsClientSettings, CmsServerIdentity, CmsServerSettings, ProvisionedTrust,
	};
}

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

/// Create a self-signed certificate whose public key matches `signing_key`.
fn create_test_certificate_inner(signing_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn Error>> {
	let verifying_key = *signing_key.verifying_key();
	let public_key_der = verifying_key.to_public_key_der()?;

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
		subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())?,
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: None,
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
#[cfg(feature = "transport-ecies")]
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

/// Whether `needle` appears anywhere inside `haystack`.
pub fn contains_window(haystack: impl AsRef<[u8]>, needle: impl AsRef<[u8]>) -> bool {
	let needle = needle.as_ref();
	haystack.as_ref().windows(needle.len()).any(|window| window == needle)
}

/// An agreement that yields a chosen secret in place of an ECDH output, so a
/// fixture or an observer runs the production derivation over the value it
/// picked.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
struct FixedAgreement<'a>(&'a EcdhSecret);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeAgreement<Secp256k1> for FixedAgreement<'_> {
	fn shared_secret(&self, _peer: &PublicKey<Secp256k1>) -> Result<EcdhSecret, HandshakeError> {
		Ok(self.0.with(|bytes| EcdhSecret::from(*bytes)))
	}
}

/// The handshake secret of `base` and `shared` under `salt`, through the
/// production derivation.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn derive_handshake_secret(
	base: &BaseSecret,
	shared: &EcdhSecret,
	salt: KdfSalt<'_>,
) -> Result<HandshakeSecret, HandshakeError> {
	// The fixed agreement ignores its peer, so any point serves.
	let peer = SecretKey::random(&mut OsRng).public_key();
	let agreement = Agreement::<DefaultCryptoProvider>::new(base, &peer);
	agreement.settle(&FixedAgreement(shared), salt)
}

/// A handshake secret derived from a fixture base secret of `fill` bytes, a
/// fixture ephemeral-ephemeral secret, and a fixture salt.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn fixture_handshake_secret(fill: u8) -> HandshakeSecret {
	let base = BaseSecret::try_from(SecretSlice::from(vec![fill; 32])).expect("32 bytes make a base secret");
	let shared = EcdhSecret::from([0x11u8; 32]);
	derive_handshake_secret(&base, &shared, KdfSalt::new(&[0x99u8; 32]))
		.expect("fixture inputs derive a handshake secret")
}

/// The salt and the transcript hash of [`fixture_confirmation`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const FIXTURE_CONFIRMED: [u8; 32] = [0x99u8; 32];

/// A key-confirmation tag of a fixture handshake secret, which confirms no
/// handshake a test runs.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn fixture_confirmation() -> KeyConfirmation {
	let secret = fixture_handshake_secret(0x42);
	let derived = secret.confirmation::<DefaultCryptoProvider>(KdfSalt::new(&FIXTURE_CONFIRMED), &FIXTURE_CONFIRMED);
	derived.expect("a fixture secret derives a tag")
}

/// What a hand-built closing confirms, as a client reads it from the reply.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct Confirming {
	/// The server ephemeral the reply carried.
	pub server_ephemeral: PublicKey<Secp256k1>,
	/// The KDF salt of the handshake.
	pub salt: Vec<u8>,
	/// The hash of the transcript the reply sealed.
	pub transcript_hash: [u8; 32],
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl Confirming {
	/// The key-confirmation tag of a client that drew `base` and `ephemeral`.
	///
	/// The handshake secret comes from the production agreement of `ephemeral`
	/// with the server ephemeral, so an honest hand-built closing confirms the
	/// secret the server derives.
	pub fn tag(&self, base: &BaseSecret, ephemeral: &SecretKey) -> KeyConfirmation {
		let salt = KdfSalt::new(&self.salt);
		let agreement = Agreement::<DefaultCryptoProvider>::new(base, &self.server_ephemeral);
		let secret = agreement
			.settle(ephemeral, salt)
			.expect("the agreement derives a handshake secret");

		let derived = secret.confirmation::<DefaultCryptoProvider>(salt, &self.transcript_hash);
		derived.expect("the handshake secret derives a tag")
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

/// The KDF of the default provider, which the observer runs the base-only
/// derivation through.
type ObserverKdf = <DefaultCryptoProvider as KdfProvider>::Kdf;

/// The attempts [`StaticKeyObserver::record_attempts`] makes: five
/// candidates under both directional keys, and the key from the base secret
/// alone under both directional labels.
pub const RECORD_ATTEMPTS: usize = 12;

/// The attempts [`StaticKeyObserver::ack_attempts`] makes: five candidates
/// and the key from the base secret alone.
pub const ACK_ATTEMPTS: usize = 6;

/// The outcome of each record attempt an observer makes.
pub type RecordAttempts = Vec<Result<SecretSlice<u8>, TightBeamError>>;

/// The outcome of each acknowledgement attempt an observer makes.
pub type AckAttempts = Vec<Result<SecretSlice<u8>, HandshakeError>>;

/// A passive observer who recorded one session and later obtained the
/// server's static key.
///
/// It holds the base secret that key recovers, the protocol salt, and the two
/// ephemeral public keys as the handshake carried them.
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
/// The observer also tries the key that the base secret alone derives, which
/// takes no ephemeral-ephemeral input.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct StaticKeyObserver {
	base: BaseSecret,
	salt: Vec<u8>,
	candidates: Vec<EcdhSecret>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl StaticKeyObserver {
	/// Give the observer `static_key`, the `base` it recovered with it, the
	/// two ephemeral public keys as SEC1 bytes, and the protocol `salt`.
	pub fn new(
		static_key: &SecretKey,
		base: impl AsRef<[u8]>,
		client_ephemeral: &[u8],
		server_ephemeral: &[u8],
		salt: impl AsRef<[u8]>,
	) -> Result<Self, Box<dyn Error>> {
		let client_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(client_ephemeral)?;
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(server_ephemeral)?;
		let candidates = vec![
			EcdhSecret::from([0u8; 32]),
			static_key.shared_secret(&client_ephemeral)?,
			static_key.shared_secret(&server_ephemeral)?,
			x_coordinate(&client_ephemeral)?,
			x_coordinate(&server_ephemeral)?,
		];

		let base = BaseSecret::try_from(SecretSlice::from(base.as_ref().to_vec()))?;
		Ok(Self { base, salt: salt.as_ref().to_vec(), candidates })
	}

	/// Open `frame` under every traffic key the observer derives, in both
	/// directions, and report each outcome.
	pub fn record_attempts(&self, frame: &EncryptedContentInfo) -> Result<RecordAttempts, Box<dyn Error>> {
		let mut attempts = Vec::with_capacity(RECORD_ATTEMPTS);
		for secret in self.handshake_secrets()? {
			let ciphers = DirectionalCiphers::derive::<DefaultCryptoProvider, _>(&secret, KdfSalt::new(&self.salt))?;
			attempts.push(ciphers.client_to_server.decrypt_content(frame));
			attempts.push(ciphers.server_to_client.decrypt_content(frame));
		}

		for label in [TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO] {
			attempts.push(self.pre_change_cipher(label)?.decrypt_content(frame));
		}

		Ok(attempts)
	}

	/// Open the sealed acknowledgement `sealed` of the transcript
	/// `transcript_hash` under every acknowledgement key the observer derives,
	/// and report each outcome.
	pub fn ack_attempts(&self, transcript_hash: &[u8; 32], sealed: &[u8]) -> Result<AckAttempts, Box<dyn Error>> {
		let salt = KdfSalt::new(&self.salt);
		let mut attempts = Vec::with_capacity(ACK_ATTEMPTS);
		for secret in self.handshake_secrets()? {
			attempts.push(secret.open_ack::<DefaultCryptoProvider>(salt, transcript_hash, sealed));
		}

		let cipher = self.pre_change_cipher(TIGHTBEAM_ACK_KDF_INFO)?;
		let aad = [TIGHTBEAM_ACK_AAD_DOMAIN, transcript_hash.as_slice()].concat();
		let nonce = Nonce::<ObserverCipher>::default();
		let opened = cipher.decrypt(&nonce, Payload { msg: sealed, aad: &aad });
		attempts.push(opened.map(SecretSlice::from).map_err(HandshakeError::ReceiptAckCipher));
		Ok(attempts)
	}

	/// The handshake secret each candidate yields through the production
	/// derivation.
	fn handshake_secrets(&self) -> Result<Vec<HandshakeSecret>, HandshakeError> {
		let salt = KdfSalt::new(&self.salt);
		let derive = |shared| derive_handshake_secret(&self.base, shared, salt);
		self.candidates.iter().map(derive).collect()
	}

	/// The cipher that the base secret alone keys under `label`, with no
	/// ephemeral-ephemeral input.
	fn pre_change_cipher(&self, label: &[u8]) -> Result<ObserverCipher, HandshakeError> {
		let key_size = <ObserverCipher as KeySizeUser>::key_size();
		let key = ObserverKdf::derive_dynamic_key(self.base.as_bytes(), label, Some(&self.salt), key_size)?;
		Ok(ObserverCipher::new_from_slice(&key)?)
	}
}

/// The x-coordinate of `point` in the place of an ECDH output.
fn x_coordinate(point: &PublicKey<Secp256k1>) -> Result<EcdhSecret, Box<dyn Error>> {
	let encoded = point.to_encoded_point(false);
	let x = encoded.x().ok_or("an affine point has an x-coordinate")?;
	Ok(EcdhSecret::try_from(SecretSlice::from(x.to_vec()))?)
}

/// Create a test ClientHello message with the given client random.
pub fn create_test_client_hello(client_random: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
	let client_hello = ClientHello {
		client_random: OctetString::new(*client_random)?,
		security_offer: None,
		transport_offer: None,
	};
	Ok(client_hello.to_der()?)
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

/// A SignedData over `content` by a fresh test key.
#[cfg(feature = "transport-cms")]
pub fn create_test_signed_data(content: impl AsRef<[u8]>) -> SignedData {
	let signing_key = create_test_signing_key();
	let digest_alg = create_sha3_256_digest_alg();
	let signature_alg = create_ecdsa_sha3_256_signature_alg();
	let builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(&signing_key, digest_alg, signature_alg)
		.expect("the builder accepts a test key");

	builder.build(content).expect("the SignedData signs")
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

/// Create test User Keying Material (UKM) for key agreement.
pub fn create_test_ukm() -> UserKeyingMaterial {
	let ukm_bytes = generate_nonce::<64>(None).expect("UKM generation should succeed");
	UserKeyingMaterial::new(ukm_bytes.to_vec()).expect("UKM creation should succeed")
}

/// Create a test recipient identifier for CMS operations.
pub fn create_test_recipient_id() -> KeyAgreeRecipientIdentifier {
	use x509_cert::name::Name;
	use x509_cert::serial_number::SerialNumber;

	KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
		issuer: Name::default(),
		serial_number: SerialNumber::new(&[0x01]).expect("Serial number creation should succeed"),
	})
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

/// The identity of a test client: the certificate of `identity` beside the
/// key that proves it.
pub fn client_identity(identity: &TestCertificate) -> ClientIdentity<DefaultCryptoProvider> {
	let manager = HandshakeKeyManager::from(identity.signing_key.to_owned());
	ClientIdentity::new(Arc::new(identity.certificate.to_owned()), Arc::new(manager))
}

/// The DER of the `ClientHello` that `opening` tunnels.
#[cfg(feature = "transport-ecies")]
pub fn tunneled_hello(opening: &HandshakeMessage) -> Vec<u8> {
	let tunnel = opening.to_owned().signed().expect("an ECIES opening travels in a SignedData");
	let hello = tunnel.value().tunneled_der().expect("the opening tunnels a ClientHello");
	hello.to_vec()
}

/// `hello` as the opening an ECIES server reads.
#[cfg(feature = "transport-ecies")]
pub fn tunneled_opening(hello: &ClientHello) -> HandshakeMessage {
	let tunnel = SignedData::try_from(hello).expect("a ClientHello tunnels in a SignedData");
	HandshakeMessage::try_from(tunnel).expect("the tunnel encodes")
}

/// The `ServerHandshake` that `reply` tunnels.
#[cfg(feature = "transport-ecies")]
pub fn tunneled_handshake(reply: &HandshakeMessage) -> ServerHandshake {
	let tunnel = reply.to_owned().signed().expect("an ECIES reply travels in a SignedData");
	ServerHandshake::try_from(tunnel.value()).expect("the reply tunnels a ServerHandshake")
}

/// `handshake` as the reply an ECIES client reads.
#[cfg(feature = "transport-ecies")]
pub fn tunneled_reply(handshake: &ServerHandshake) -> HandshakeMessage {
	let tunnel = SignedData::try_from(handshake).expect("a ServerHandshake tunnels in a SignedData");
	HandshakeMessage::try_from(tunnel).expect("the tunnel encodes")
}

/// The `ClientKeyExchange` that `closing` carries.
#[cfg(feature = "transport-ecies")]
pub fn carried_key_exchange(closing: &HandshakeMessage) -> ClientKeyExchange {
	let carrier = closing
		.to_owned()
		.enveloped()
		.expect("an ECIES closing travels in an EnvelopedData");
	ClientKeyExchange::try_from(carrier.value()).expect("the closing carries a ClientKeyExchange")
}

/// `key_exchange` as the closing an ECIES server reads.
#[cfg(feature = "transport-ecies")]
pub fn carried_closing(key_exchange: &ClientKeyExchange) -> HandshakeMessage {
	let carrier = EnvelopedData::try_from(key_exchange).expect("a ClientKeyExchange travels in an EnvelopedData");
	HandshakeMessage::try_from(carrier).expect("the carrier encodes")
}

/// What an observer who holds the server's static key recovers from a
/// recorded handshake.
pub struct Recovered {
	/// The observer, holding the static key and everything it opened.
	pub observer: StaticKeyObserver,
	/// The base secret the static key opened.
	pub base: Vec<u8>,
	/// The sealed receipt acknowledgement, when the closing carried one.
	pub sealed_ack: Option<Vec<u8>>,
}

/// A flow the handshake tests run over, with the provisioning of its two
/// endpoints.
pub trait TestFlow: ClientFlow<DefaultCryptoProvider> + ServerFlow<DefaultCryptoProvider> {
	/// The configuration of a client that admits `server` and presents
	/// `identity`.
	fn client(server: &Certificate, identity: &TestCertificate) -> TestClientConfig<Self>;

	/// The configuration of a server that holds `identity`, demands no client
	/// certificate, and runs the default test profile.
	fn server(identity: &TestCertificate) -> TestServerConfig<Self>;

	/// Open the recorded legs of `run` with the static key of
	/// `server_identity`, through the same path the server runs.
	fn recover(run: &Run<Self>, server_identity: &TestCertificate) -> Recovered;
}

/// A client configuration under the default provider.
pub type TestClientConfig<F> = ClientConfig<F, DefaultCryptoProvider>;

/// A server configuration under the default provider.
pub type TestServerConfig<F> = ServerConfig<F, DefaultCryptoProvider>;

/// A client handshake under the default provider.
pub type TestClient<F> = Handshake<Client, F, DefaultCryptoProvider>;

/// A server handshake under the default provider.
pub type TestServer<F> = Handshake<Server, F, DefaultCryptoProvider>;

#[cfg(feature = "transport-ecies")]
impl TestFlow for Ecies {
	fn client(server: &Certificate, identity: &TestCertificate) -> TestClientConfig<Self> {
		let validator = DirectTrustValidator::default().with_trust_chain(vec![server.to_owned()]);
		let mut settings = EciesClientSettings::new(LearnedTrust::new(validator));
		settings.identity = Some(client_identity(identity));
		ClientConfig::new(settings)
	}

	fn server(identity: &TestCertificate) -> TestServerConfig<Self> {
		let settings = EciesServerSettings::new(Arc::new(identity.certificate.to_owned()));
		let key = into_provider(identity.signing_key.to_owned());
		ServerConfig::new(settings, key, SupportedProfiles::from(create_default_test_profile()))
	}

	fn recover(run: &Run<Self>, server_identity: &TestCertificate) -> Recovered {
		let key_exchange = carried_key_exchange(&run.closing);
		let static_key = SecretKey::from(server_identity.signing_key.to_owned());
		let message = Secp256k1EciesMessage::from_bytes(key_exchange.encrypted_data.as_bytes());
		let message = message.expect("the closing carries an ECIES message");
		let certificate = key_exchange.client_certificate.as_ref();
		let aad = ClientKeyExchange::client_bound_aad(TIGHTBEAM_AAD_DOMAIN_TAG, certificate);
		let aad = aad.expect("the offered certificate encodes");
		let opened = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&static_key, &message, Some(&aad));
		let plaintext = opened.expect("the static key opens the payload").to_insecure();
		let payload = EciesSessionPayload::from_der(&plaintext).expect("the payload decodes");

		let hello = ClientHello::from_der(&tunneled_hello(&run.opening)).expect("the hello decodes");
		let handshake = tunneled_handshake(&run.reply);
		let salt = [hello.client_random.as_bytes(), handshake.server_random.as_bytes()].concat();
		let base = payload.base_key.as_bytes();
		let server_ephemeral = handshake.server_ephemeral.as_bytes();
		let observer = StaticKeyObserver::new(&static_key, base, message.ephemeral_pubkey(), server_ephemeral, salt);

		Recovered {
			observer: observer.expect("both ephemerals are points on the curve"),
			base: base.to_vec(),
			sealed_ack: payload.receipt_ack.map(OctetString::into_bytes),
		}
	}
}

#[cfg(feature = "transport-cms")]
impl TestFlow for Cms {
	fn client(server: &Certificate, identity: &TestCertificate) -> TestClientConfig<Self> {
		let store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(server.to_owned())
			.expect("the store takes a valid test certificate")
			.build();
		let pinned = CmsServerIdentity::Certificate(Arc::new(server.to_owned()));
		let trust = ProvisionedTrust { identity: pinned, store: Arc::new(store) };
		ClientConfig::new(CmsClientSettings { trust, identity: client_identity(identity) })
	}

	fn server(identity: &TestCertificate) -> TestServerConfig<Self> {
		let key = into_provider(identity.signing_key.to_owned());
		ServerConfig::new(CmsServerSettings, key, SupportedProfiles::from(create_default_test_profile()))
	}

	fn recover(run: &Run<Self>, server_identity: &TestCertificate) -> Recovered {
		let key_exchange = run.opening.to_owned().enveloped().expect("a CMS opening is an EnvelopedData");
		let static_key = SecretKey::from(server_identity.signing_key.to_owned());
		let recipient = TightBeamKariRecipient::new(DefaultCryptoProvider::default(), static_key.to_owned());
		let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(recipient);
		let opened = processor.process(key_exchange.value());
		let base = opened.expect("the static key unwraps the base secret").to_insecure().to_vec();

		let server_finished = run.reply.to_owned().signed().expect("a CMS reply is a SignedData");
		let server_ephemeral = server_finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL);
		let server_ephemeral = server_ephemeral.expect("the ephemeral attribute is single");
		let server_ephemeral = server_ephemeral.expect("the server Finished carries its ephemeral");
		let server_ephemeral = server_ephemeral.decode::<OriginatorPublicKey>().expect("the ephemeral decodes");
		let server_point = server_ephemeral.public_key.raw_bytes();
		let client_point = originator_point(key_exchange.value());
		let observer = StaticKeyObserver::new(&static_key, &base, &client_point, server_point, run.transcript_hash);

		let client_finished = run.closing.to_owned().signed().expect("a CMS closing is a SignedData");
		let sealed_ack = client_finished.value().find_unsigned_attr(RECEIPT_ACK);
		let sealed_ack = sealed_ack.expect("the acknowledgement attribute is single");
		let sealed_ack = sealed_ack.map(|attribute| attribute.decode::<OctetString>().expect("it decodes"));

		Recovered {
			observer: observer.expect("both ephemerals are points on the curve"),
			base,
			sealed_ack: sealed_ack.map(OctetString::into_bytes),
		}
	}
}

/// The SEC1 bytes of the client's KARI originator key in `key_exchange`.
#[cfg(feature = "transport-cms")]
pub fn originator_point(key_exchange: &EnvelopedData) -> Vec<u8> {
	let recipient = key_exchange.recip_infos.0.iter().next();
	let Some(RecipientInfo::Kari(kari)) = recipient else {
		panic!("the key exchange carries a KARI");
	};
	let OriginatorIdentifierOrKey::OriginatorKey(originator) = &kari.originator else {
		panic!("the KARI carries an originator key");
	};

	originator.public_key.raw_bytes().to_vec()
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
	pub transcript_hash: [u8; 32],
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

/// A key exchange whose envelope carries two `CLIENT_CERTIFICATE` attributes
/// fails closed instead of admitting the last one, so an injected certificate
/// cannot travel beside the one the client sealed the payload under.
#[cfg(feature = "transport-ecies")]
#[test]
fn a_duplicate_client_certificate_attribute_fails_closed() -> Result<(), Box<dyn Error>> {
	let sealed = create_test_certificate();
	let injected = create_test_certificate();
	let key_exchange = ClientKeyExchange {
		encrypted_data: OctetString::new([0x41u8; 32])?,
		client_certificate: Some(sealed.certificate),
		client_signature: None,
	};

	let mut enveloped = EnvelopedData::try_from(&key_exchange)?;
	let carried = enveloped
		.unprotected_attrs
		.take()
		.ok_or("the key exchange carries its certificate")?;

	let mut attrs = carried.into_vec();
	attrs.push(Attribute::try_from(HandshakeAttribute::encode(&injected.certificate)?)?);

	enveloped.unprotected_attrs = Some(Attributes::try_from(attrs)?);

	let parsed = ClientKeyExchange::try_from(&enveloped);
	assert!(matches!(parsed, Err(HandshakeError::DuplicateAttribute)));
	Ok(())
}
