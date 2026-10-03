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
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::cert::IssuerAndSerialNumber;
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData};
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::constants::{
	EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_ACK_AAD_DOMAIN, TIGHTBEAM_ACK_KDF_INFO, TIGHTBEAM_C2S_KDF_INFO,
	TIGHTBEAM_S2C_KDF_INFO,
};
use crate::crypto::aead::{Aead, DecryptContent, DirectionalCiphers, KeyInit, Nonce, Payload};
use crate::crypto::common::KeySizeUser;
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{EcdhSecret, KdfFunction};
use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::policy::Secp256k1Policy;
use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider, KdfProvider, SecurityProfileDesc};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use crate::der::asn1::BitString;
use crate::der::asn1::GeneralizedTime;
use crate::der::asn1::ObjectIdentifier;
use crate::der::{Decode, Encode};
use crate::oids::{
	AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256,
	SIGNER_ECDSA_WITH_SHA3_512,
};
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, RunnableProfile, SecurityAccept, TransportAuthorizer,
	TransportOffer,
};
#[cfg(feature = "transport-ecies")]
use crate::transport::handshake::orchestrator::CompressedPoint;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::orchestrator::{Agreement, BaseSecret, HandshakeAgreement};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::receipt::{ApprovalRefusal, ReceiptApprover, SessionReceipt};
use crate::transport::handshake::{
	ClientHello, ClientKeyExchange, EstablishedSession, HandshakeAttribute, HandshakeError, HandshakeSecret,
	PeerAuthentication, ServerHandshake,
};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::serial_number::SerialNumber;
use crate::x509::time::Time;
use crate::x509::time::Validity;
use crate::x509::Certificate;
use crate::x509::{name::RdnSequence, TbsCertificate, Version};
use crate::TightBeamError;

#[cfg(feature = "transport-ecies")]
mod ecies {
	pub use crate::crypto::ecies::Secp256k1EciesMessage;
	pub use crate::crypto::x509::policy::DirectTrustValidator;
	pub use crate::transport::handshake::client::EciesHandshakeClient;
	pub use crate::transport::handshake::server::EciesHandshakeServer;
}

#[cfg(feature = "transport-ecies")]
use ecies::*;

#[cfg(feature = "transport-cms")]
mod cms {
	pub use crate::cms::signed_data::SignedData;
	pub use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	pub use crate::transport::handshake::client::CmsHandshakeClient;
	pub use crate::transport::handshake::server::CmsHandshakeServer;
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

/// Create a test certificate with the provided secp256k1 keypair.
///
/// The certificate uses the provided signing key, so its public key matches
/// the private key.
pub fn create_test_certificate_from_key(signing_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn Error>> {
	create_test_certificate_inner(signing_key)
}

/// Create a certificate from a signing key. The public certificate helpers
/// share this body.
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
/// ephemeral public keys as they crossed the wire.
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

/// Compute a test transcript hash from the ClientHello DER, the server
/// random, the server ephemeral, the SPKI bytes, and the security accept DER.
pub fn compute_test_transcript_hash(
	client_hello: impl AsRef<[u8]>,
	server_random: &[u8; 32],
	server_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
	spki_bytes: impl AsRef<[u8]>,
	accept_der: impl AsRef<[u8]>,
) -> [u8; 32] {
	let client_hello = client_hello.as_ref();
	let spki_bytes = spki_bytes.as_ref();
	let accept_der = accept_der.as_ref();
	let fixed = server_random.len() + server_ephemeral.len();
	let mut data = Vec::with_capacity(client_hello.len() + fixed + spki_bytes.len() + accept_der.len());
	data.extend_from_slice(client_hello);
	data.extend_from_slice(server_random);
	data.extend_from_slice(server_ephemeral);
	data.extend_from_slice(spki_bytes);
	data.extend_from_slice(accept_der);

	let digest_arr = Sha3_256::digest(&data);
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&digest_arr);

	digest
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

/// Create a test ServerHandshake message with the given parameters.
pub fn create_test_server_handshake(
	certificate: &Certificate,
	server_random: &[u8; 32],
	server_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
	signature: impl AsRef<[u8]>,
) -> Result<Vec<u8>, Box<dyn Error>> {
	let signature = signature.as_ref();
	let server_handshake = ServerHandshake {
		certificate: certificate.to_owned(),
		server_random: OctetString::new(*server_random)?,
		server_ephemeral: OctetString::new(*server_ephemeral)?,
		signature: OctetString::new(signature)?,
		security_accept: Some(WireDer::new(SecurityAccept::new(create_default_test_profile()))?),
		client_cert_required: false,
		transport_accept: None,
		session_receipt: None,
	};

	Ok(server_handshake.to_der()?)
}

/// Create a test ClientKeyExchange message with the given encrypted data.
pub fn create_test_client_key_exchange(encrypted_data: impl AsRef<[u8]>) -> Result<ClientKeyExchange, Box<dyn Error>> {
	let encrypted_data = encrypted_data.as_ref();
	let client_kex = ClientKeyExchange {
		encrypted_data: OctetString::new(encrypted_data)?,
		#[cfg(feature = "x509")]
		client_certificate: None,
		#[cfg(feature = "x509")]
		client_signature: None,
	};

	Ok(client_kex)
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

/// A SignedData over `content` by a fresh test key, for a step that refuses
/// it by state before reading it.
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

/// Convert a signing key into an `Arc<dyn SigningKeyProvider>`.
///
/// Tests and simple use cases use it to wrap a signing key in a provider
/// trait object.
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

/// Builder for test ECIES handshake servers with default settings.
#[cfg(feature = "transport-ecies")]
pub struct TestEciesServerBuilder {
	key: Option<Secp256k1SigningKey>,
	cert: Option<Certificate>,
	aad_domain: Option<&'static [u8]>,
}

#[cfg(feature = "transport-ecies")]
impl TestEciesServerBuilder {
	/// Create a builder with default settings.
	pub fn new() -> Self {
		Self { key: None, cert: None, aad_domain: None }
	}

	/// Set a specific signing key for the server.
	pub fn with_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.key = Some(key);
		self
	}

	/// Set a specific certificate for the server.
	pub fn with_certificate(mut self, cert: Certificate) -> Self {
		self.cert = Some(cert);
		self
	}

	/// Set the AAD domain tag for ECIES operations.
	pub fn with_aad_domain(mut self, domain: &'static [u8]) -> Self {
		self.aad_domain = Some(domain);
		self
	}

	/// Build the ECIES handshake server.
	pub fn build(self) -> Result<EciesHandshakeServer<DefaultCryptoProvider>, Box<dyn Error>> {
		let test_cert_data = if let Some(cert) = self.cert {
			let key = self.key.unwrap_or_else(|| create_test_certificate().signing_key);
			TestCertificate { signing_key: key, certificate: cert }
		} else {
			self.key
				.map(|key| -> Result<TestCertificate, Box<dyn Error>> {
					let cert = create_test_certificate_from_key(&key)?;
					Ok(TestCertificate { signing_key: key, certificate: cert })
				})
				.transpose()?
				.unwrap_or_else(create_test_certificate)
		};

		let default_profile = create_default_test_profile();
		Ok(EciesHandshakeServer::new(
			into_provider(test_cert_data.signing_key),
			Arc::new(test_cert_data.certificate),
			self.aad_domain,
			PeerAuthentication::Anonymous,
		)
		.with_supported_profiles(vec![default_profile]))
	}
}

#[cfg(feature = "transport-ecies")]
impl Default for TestEciesServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for test ECIES handshake clients with default settings.
#[cfg(feature = "transport-ecies")]
pub struct TestEciesClientBuilder {
	aad_domain: Option<&'static [u8]>,
	trusted_certificate: Option<Certificate>,
}

#[cfg(feature = "transport-ecies")]
impl TestEciesClientBuilder {
	/// Create a builder with default settings.
	pub fn new() -> Self {
		Self { aad_domain: None, trusted_certificate: None }
	}

	/// Set the AAD domain tag for ECIES operations.
	pub fn with_aad_domain(mut self, domain: &'static [u8]) -> Self {
		self.aad_domain = Some(domain);
		self
	}

	/// Trust the given server certificate through a direct-trust validator.
	///
	/// The client fails closed without a validator, so any test that
	/// processes a `ServerHandshake` must pin the server certificate here.
	pub fn with_trusted_certificate(mut self, certificate: Certificate) -> Self {
		self.trusted_certificate = Some(certificate);
		self
	}

	/// Build the ECIES handshake client.
	pub fn build(self) -> EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage> {
		let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(self.aad_domain);
		if let Some(certificate) = self.trusted_certificate {
			let validator = DirectTrustValidator::default().with_trust_chain(vec![certificate]);
			client = client.with_certificate_validator(Arc::new(validator));
		}

		client
	}
}

#[cfg(feature = "transport-ecies")]
impl Default for TestEciesClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for test CMS handshake servers with default settings.
#[cfg(feature = "transport-cms")]
pub struct TestCmsServerBuilder {
	key: Option<Secp256k1SigningKey>,
	peer_authentication: PeerAuthentication,
}

#[cfg(feature = "transport-cms")]
impl TestCmsServerBuilder {
	/// Create a builder with default settings.
	pub fn new() -> Self {
		Self { key: None, peer_authentication: PeerAuthentication::Anonymous }
	}

	/// Set a specific signing key for the server.
	pub fn with_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.key = Some(key);
		self
	}

	/// Set how the server authenticates its client.
	pub fn with_peer_authentication(mut self, peer_authentication: PeerAuthentication) -> Self {
		self.peer_authentication = peer_authentication;
		self
	}

	/// Build the CMS handshake server.
	pub fn build(self) -> (CmsHandshakeServer<DefaultCryptoProvider>, PublicKey<Secp256k1>) {
		let test_key = self.key.unwrap_or_else(|| create_test_certificate().signing_key);
		let verifying_key = *test_key.verifying_key();

		let public_key = PublicKey::<Secp256k1>::from(verifying_key);
		let provider = into_provider(test_key);
		let profiles = vec![create_default_test_profile()];
		let server = CmsHandshakeServer::<DefaultCryptoProvider>::new(provider, self.peer_authentication);
		let server = server.with_supported_profiles(profiles);

		(server, public_key)
	}
}

#[cfg(feature = "transport-cms")]
impl Default for TestCmsServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for test CMS handshake clients with default settings.
#[cfg(feature = "transport-cms")]
pub struct TestCmsClientBuilder {
	client_key: Option<Secp256k1SigningKey>,
	server_cert: Option<Certificate>,
}

#[cfg(feature = "transport-cms")]
impl TestCmsClientBuilder {
	/// Create a builder with default settings.
	pub fn new() -> Self {
		Self { client_key: None, server_cert: None }
	}

	/// Set a specific client signing key.
	pub fn with_client_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.client_key = Some(key);
		self
	}

	/// Set a specific server certificate.
	pub fn with_server_cert(mut self, cert: Certificate) -> Self {
		self.server_cert = Some(cert);
		self
	}

	/// Build the CMS handshake client.
	///
	/// The build attaches a trust store that pins the server certificate,
	/// because the client fails closed without one.
	pub fn build(self) -> Result<CmsHandshakeClient<DefaultCryptoProvider>, Box<dyn Error>> {
		let client_key = self.client_key.unwrap_or_else(|| create_test_certificate().signing_key);
		let server_cert = match self.server_cert {
			Some(cert) => cert,
			None => create_test_certificate_from_key(&create_test_certificate().signing_key)?,
		};

		let trust_store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(server_cert.to_owned())?
			.build();

		let client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			into_provider(client_key),
			Arc::new(server_cert),
		)
		.with_trust_store(Arc::new(trust_store) as Arc<dyn CertificateTrust>);

		Ok(client)
	}
}

#[cfg(feature = "transport-cms")]
impl Default for TestCmsClientBuilder {
	fn default() -> Self {
		Self::new()
	}
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
