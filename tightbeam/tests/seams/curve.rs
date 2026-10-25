//! The handshake and the rekey run here under a curve an outside crate
//! brings: NIST P-256, whose arithmetic the `p256` crate holds.
//!
//! [`P256Provider`] brings these parts of its own:
//!
//! - a signature, ECDSA over P-256 under `ecdsa-with-SHA3-256`, as a [`SigningProvider`],
//! - a signing backend over a P-256 key, as a [`SigningKeyProvider`],
//! - a key-agreement backend that runs the P-256 scalar product, as a [`DiffieHellman`] backend, and
//! - a KEM, DHKEM(P-256, HKDF-SHA256), on a type of its own through the generic helpers of [`DhKem`].
//!
//! The house AEAD, AES-256-GCM, and the house key wrap, AES-256, complete
//! it, beside the house digest and KDF of the default profile.
//!
//! These suites run under it:
//!
//! - the KEM of RFC 9180 Appendix A.3.1, through the outside KEM and the HPKE suite of P-256,
//! - both handshake flows, and the refusal of a secp256k1 point at the width of a compressed P-256 point, and
//! - an in-band renewal of a multiplexed session over TCP.

use core::fmt::{Debug, Formatter};
use std::sync::Arc;

use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{AffinePoint, NistP256, NonZeroScalar, PublicKey, SecretKey};
use rand_core::impls::{next_u32_via_fill, next_u64_via_fill};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use tightbeam::cms::content_info::ContentInfo;
use tightbeam::crypto::aead::{Aes128Gcm, Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::cms::{Encapsulation, EnvelopeError, KeyAgreementIdentity, RecipientKem};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::crypto::hpke::{DhKem, DhKemSuite, HkdfSha256, HpkeMessage, HpkePublicKeyOps, HpkeSecretKeyOps};
use tightbeam::crypto::k256::ecdsa::SigningKey as Secp256k1SigningKey;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::key::{DiffieHellman, KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::profiles::{
	AeadProvider, Aes256Wrap, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, KeyWrapProvider,
	SecurityProfile, SigningProvider,
};
use tightbeam::crypto::secret::{SecretSlice, ToInsecure};
use tightbeam::crypto::sign::{
	CanonicalForm, Error as SignatureError, PrehashSigner, PrehashVerifier, SignatureAlgorithmIdentifier,
	SignatureEncoding, SigningIdentity, Verifier,
};
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::DirectTrustValidator;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::asn1::{ObjectIdentifier, OctetString, OctetStringRef};
use tightbeam::der::{Any, Decode, Encode, Tag};
use tightbeam::oids::{CURVE_NIST_P256, DATA, SIGNER_ECDSA_WITH_SHA3_256};
use tightbeam::random::{CryptoRngCore, OsRng};
use tightbeam::spki::{
	AlgorithmIdentifierOwned, Document, EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoRef,
};
use tightbeam::testing::{unhex, TestCertificate, TestCmsServer, TestKey};
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, ClientHello, Cms, CmsClientSettings, CmsIdentityPair, CmsServerSettings, Handshake,
	HandshakeError, HandshakeMessage, Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust, ProvisionedTrust,
	Server, ServerConfig, SupportedProfiles,
};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::ext::pkix::KeyUsages;
use tightbeam::x509::Certificate;
use tightbeam::ZeroizingBytes;

use super::{run_legs, CONTENT};

/// `id-ecPublicKey` (RFC 5480 §2.1.1), the algorithm of the key the P-256
/// key-agreement backend holds.
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The identifier of the P-256 KEM, under the arc of the outside crate.
const P256_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.3");

/// DHKEM(P-256, HKDF-SHA256) in the HPKE KEM registry (RFC 9180 §7.1).
const KEM_DHKEM_P256_HKDF_SHA256: u16 = 0x0010;

/// RFC 9180 A.3.1: `skEm`, the ephemeral scalar the sender draws.
const RFC_9180_A_3_1_SK_E: &str = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";

/// RFC 9180 A.3.1: `pkEm`, the public half of `skEm`, which is `enc`.
const RFC_9180_A_3_1_PK_E: &str = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac9\
	8536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";

/// RFC 9180 A.3.1: `skRm`, the recipient scalar.
const RFC_9180_A_3_1_SK_R: &str = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";

/// RFC 9180 A.3.1: `pkRm`, the public half of `skRm`.
const RFC_9180_A_3_1_PK_R: &str = "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a82\
	6a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";

/// RFC 9180 A.3.1: the KEM shared secret.
const RFC_9180_A_3_1_SHARED_SECRET: &str = "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8";

/// RFC 9180 A.3.1: the `info` of the key schedule.
const RFC_9180_A_3_1_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";

/// RFC 9180 A.3.1.1: the associated data at sequence number zero.
const RFC_9180_A_3_1_1_AAD_0: &str = "436f756e742d30";

/// RFC 9180 A.3.1.1: the plaintext of every encryption.
const RFC_9180_A_3_1_1_PLAINTEXT: &str = "4265617574792069732074727574682c20747275746820626561757479";

/// RFC 9180 A.3.1.1: the ciphertext at sequence number zero.
const RFC_9180_A_3_1_1_CIPHERTEXT_0: &str =
	"5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434";

/// An ECDSA signature over P-256 under SHA3-256, in DER.
#[derive(Clone, Debug)]
struct P256Signature(DerSignature);

impl TryFrom<&[u8]> for P256Signature {
	type Error = SignatureError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		DerSignature::try_from(bytes).map(Self)
	}
}

impl From<P256Signature> for Box<[u8]> {
	fn from(signature: P256Signature) -> Self {
		signature.0.to_bytes()
	}
}

impl SignatureEncoding for P256Signature {
	type Repr = Box<[u8]>;
}

impl SignatureAlgorithmIdentifier for P256Signature {
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_256;
	type Digest = Sha3_256;
}

/// The canonical form is the DER form with `s` in the low half of the order
/// of P-256, and it brings a high `s` into that half (SEC 1 v2.0 §4.1.4).
impl CanonicalForm for P256Signature {
	fn canonical(encoded: &[u8]) -> Result<Self, SignatureError> {
		let signature = Signature::from_der(encoded)?;
		let low = signature.normalize_s().unwrap_or(signature);
		Ok(Self(low.to_der()))
	}
}

/// The P-256 key that verifies a [`P256Signature`].
#[derive(Clone, Debug, PartialEq)]
struct P256VerifyingKey(VerifyingKey);

impl PrehashVerifier<P256Signature> for P256VerifyingKey {
	fn verify_prehash(&self, prehash: &[u8], signature: &P256Signature) -> Result<(), SignatureError> {
		self.0.verify_prehash(prehash, &signature.0)
	}
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for P256VerifyingKey {
	type Error = SpkiError;

	fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
		VerifyingKey::try_from(spki).map(Self)
	}
}

/// The ECDSA check over the SHA3-256 digest of `message`, as
/// `ecdsa-with-SHA3-256` names it.
impl Verifier<P256Signature> for P256VerifyingKey {
	fn verify(&self, message: &[u8], signature: &P256Signature) -> Result<(), SignatureError> {
		let prehash = Sha3_256::digest(message);
		self.0.verify_prehash(&prehash, &signature.0)
	}
}

/// The key of a point on P-256, as a handshake reads it from a certificate.
impl From<PublicKey> for P256VerifyingKey {
	fn from(key: PublicKey) -> Self {
		Self(VerifyingKey::from(key))
	}
}

/// The point of the key, lent by reference, which a handshake compares an
/// agreement ephemeral with.
impl AsRef<AffinePoint> for P256VerifyingKey {
	fn as_ref(&self) -> &AffinePoint {
		self.0.as_affine()
	}
}

impl EncodePublicKey for P256VerifyingKey {
	fn to_public_key_der(&self) -> tightbeam::spki::Result<Document> {
		self.0.to_public_key_der()
	}
}

/// DHKEM(P-256, HKDF-SHA256), the KEM of RFC 9180 §7.1 that
/// [`KEM_DHKEM_P256_HKDF_SHA256`] names.
type P256DhKem = DhKem<NistP256, HkdfSha256, KEM_DHKEM_P256_HKDF_SHA256>;

/// The HPKE suite of RFC 9180 A.3: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// and AES-128-GCM.
type P256Suite = DhKemSuite<NistP256, HkdfSha256, Aes128Gcm, KEM_DHKEM_P256_HKDF_SHA256>;

/// The P-256 KEM: [`P256DhKem`], named by an identifier of the outside arc.
struct P256Kem;

impl RecipientKem for P256Kem {
	const OID: ObjectIdentifier = P256_KEM;
	const USAGE: KeyUsages = KeyUsages::KeyAgreement;
	type PublicKey = PublicKey;
	type PrivateKey = dyn DiffieHellman<NistP256>;

	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<PublicKey, CertificateValidationError> {
		Ok(PublicKey::try_from(spki)?)
	}

	fn encapsulate(recipient: &PublicKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError> {
		P256DhKem::encap_to(recipient, rng)
	}

	fn decapsulate<'a>(
		key: &'a dyn DiffieHellman<NistP256>,
		recipient: &'a PublicKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>> {
		P256DhKem::decap_through(key, recipient, kemct)
	}
}

/// The profile of [`P256Provider`].
#[derive(Debug, Default, Clone, Copy)]
struct P256Profile;

impl SecurityProfile for P256Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = P256Signature;
	type Kdf = HkdfSha3_256;
	type Curve = NistP256;
	type KeyWrapOid = Aes256Wrap;
}

/// A provider an outside crate defines on P-256: its own signature and KEM,
/// beside the house AEAD, key wrap, digest, and KDF.
#[derive(Debug, Default, Clone, Copy)]
struct P256Provider {
	profile: P256Profile,
}

impl DigestProvider for P256Provider {
	type Digest = Sha3_256;
}

impl AeadProvider for P256Provider {
	type AeadCipher = Aes256Gcm;
}

impl KeyWrapProvider for P256Provider {
	type KeyWrap = Aes256Wrap;
}

impl SigningProvider for P256Provider {
	type Signature = P256Signature;
	type VerifyingKey = P256VerifyingKey;
}

impl KdfProvider for P256Provider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for P256Provider {
	type Curve = NistP256;
}

impl CryptoProvider for P256Provider {
	type Profile = P256Profile;
	type Kem = P256Kem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The signing backend of a P-256 identity: it signs under
/// `ecdsa-with-SHA3-256`.
#[derive(Debug)]
struct P256KeyProvider {
	key: SigningKey,
}

impl KeyBackend for P256KeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.key.verifying_key().to_public_key_der()?.into_vec())
	}
}

impl SigningKeyProvider for P256KeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<DerSignature, SignatureError> = self.key.sign_prehash(prehash);
		let signed = signed.map(|signature| signature.to_vec()).map_err(KeyError::from);
		Box::pin(async move { signed })
	}
}

/// The key-agreement backend of a P-256 identity: it holds a scalar and runs
/// the Diffie-Hellman product itself, so the scalar stays inside it.
struct P256AgreementBackend {
	scalar: NonZeroScalar,
}

/// The public key names the backend, and the scalar stays out of the output.
impl Debug for P256AgreementBackend {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("P256AgreementBackend")
			.field("public_key", &self.public_key())
			.finish_non_exhaustive()
	}
}

impl P256AgreementBackend {
	/// The backend of `scalar`.
	fn of(scalar: NonZeroScalar) -> Self {
		Self { scalar }
	}

	/// The public half of the scalar.
	fn public_key(&self) -> PublicKey {
		PublicKey::from_secret_scalar(&self.scalar)
	}
}

impl KeyBackend for P256AgreementBackend {
	/// `id-ecPublicKey` on P-256, the algorithm of the key the backend holds.
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		let parameters = Any::encode_from(&CURVE_NIST_P256).ok();
		AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key().to_public_key_der()?.into_vec())
	}
}

/// The x-coordinate of the product of the backend's scalar and the peer
/// point (SEC 1 v2.0 §3.3.1).
impl DiffieHellman<NistP256> for P256AgreementBackend {
	fn agree<'a>(&'a self, peer: &'a PublicKey) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
		let product = (peer.to_projective() * *self.scalar).to_affine();
		let agreed = SecretSlice::from(product.x().to_vec());
		Box::pin(async move { Ok(agreed) })
	}
}

/// A random source that draws the scalar a published vector names, so an
/// encapsulation that draws from it draws that scalar.
struct PublishedDraw(Vec<u8>);

impl RngCore for PublishedDraw {
	fn next_u32(&mut self) -> u32 {
		next_u32_via_fill(self)
	}

	fn next_u64(&mut self) -> u64 {
		next_u64_via_fill(self)
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		dest.copy_from_slice(&self.0[..dest.len()]);
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
		self.fill_bytes(dest);
		Ok(())
	}
}

impl CryptoRng for PublishedDraw {}

/// The certificate of the P-256 key `key`, cut from the placeholder-signed
/// house certificate of a fresh secp256k1 key, whose key identifier sets it
/// apart from every other certificate of a test. A trust that pins it
/// compares it whole.
fn certificate_of(key: &PublicKey) -> Certificate {
	let template = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	let point = key.to_encoded_point(false);
	TestCertificate::with_curve_point(template, CURVE_NIST_P256, point.as_bytes())
}

/// The identity under [`P256Provider`] of `certificate` and its `key`.
fn identity_of(certificate: Certificate, key: SigningKey) -> SigningIdentity {
	let provider = Arc::new(P256KeyProvider { key });
	let identity = SigningIdentity::with_provider::<P256Provider>(certificate, provider);
	identity.expect("the P-256 key matches its certificate and its algorithm")
}

/// An identity under [`P256Provider`], of a fresh key.
fn p256_identity() -> SigningIdentity {
	let key = SigningKey::random(&mut OsRng);
	let certificate = certificate_of(&PublicKey::from(key.verifying_key()));
	identity_of(certificate, key)
}

/// A client of the HPKE flow under the P-256 provider.
type P256HpkeClient = Handshake<Client, Hpke, P256Provider>;

/// A server of the HPKE flow under the P-256 provider.
type P256HpkeServer = Handshake<Server, Hpke, P256Provider>;

/// A client that pins the certificate of `server`, beside a server that
/// holds `server`, both under the P-256 provider.
fn hpke_pair(server: SigningIdentity) -> (P256HpkeClient, P256HpkeServer) {
	let pinned = DirectTrustValidator::default().with_trust_chain([server.certificate().to_owned()]);
	let settings = HpkeClientSettings::new(LearnedTrust::new(pinned));
	let client = ClientConfig::<Hpke, P256Provider>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("a P-256 client serves the client role");

	let native = RunnableProfile::<P256Provider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let purposes = KeyPurposes::HOUSE;
	let server_config = ServerConfig::<Hpke, P256Provider>::new(HpkeServerSettings::new(), server, profiles, purposes);
	let server_config = server_config.expect("a P-256 server identity serves the server role");
	(Handshake::client(client), Handshake::server(server_config))
}

/// The hello of `opening`, which carries `point` as its agreement ephemeral
/// `R` in place of the one the client drew.
fn hello_carrying(opening: HandshakeMessage, point: &[u8]) -> Result<HandshakeMessage, Box<dyn std::error::Error>> {
	let content_info = opening.data()?.into_value();
	let octets = content_info.content.decode_as::<OctetStringRef<'_>>()?;
	let hello = ClientHello::from_der(octets.as_bytes())?;

	let hello = ClientHello { client_ephemeral: OctetString::new(point)?, ..hello };
	let content = Any::new(Tag::OctetString, hello.to_der()?)?;
	Ok(HandshakeMessage::try_from(ContentInfo { content_type: DATA, content })?)
}

/// The ephemeral the hello of `opening` carries.
fn carried_ephemeral(opening: HandshakeMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let content_info = opening.data()?.into_value();
	let octets = content_info.content.decode_as::<OctetStringRef<'_>>()?;
	let hello = ClientHello::from_der(octets.as_bytes())?;
	Ok(hello.client_ephemeral.as_bytes().to_vec())
}

/// The P-256 identities of a CMS server, whose certificates a house test
/// authority issued, beside the certificate a client pins and the store that
/// holds the authority.
struct P256CmsServer {
	/// The signing identity and the key-agreement identity the server holds.
	pair: CmsIdentityPair<P256Kem>,
	/// The key-agreement certificate, which a client pins.
	key_agreement: Certificate,
	/// The client's store, which holds the authority of both certificates.
	store: Arc<dyn CertificateTrust>,
}

/// `certificate` of `house` with the P-256 key `key` in place of its own,
/// issued again by the authority of `house`.
fn reissued(house: &TestCmsServer, certificate: &Certificate, key: &PublicKey) -> Certificate {
	let point = key.to_encoded_point(false);
	let moved = TestCertificate::with_curve_point(certificate.to_owned(), CURVE_NIST_P256, point.as_bytes());
	TestCertificate::signed_by(moved, &house.authority_key)
}

/// A CMS server of fresh P-256 keys, whose two certificates name one subject
/// under one house authority.
fn p256_cms_server() -> P256CmsServer {
	let house = TestCmsServer::generate("p256 server");
	let signing_key = SigningKey::random(&mut OsRng);
	let backend = P256AgreementBackend::of(NonZeroScalar::random(&mut OsRng));

	let signing = reissued(&house, &house.signing, &PublicKey::from(signing_key.verifying_key()));
	let key_agreement = reissued(&house, &house.key_agreement, &backend.public_key());
	let backend: Arc<dyn DiffieHellman<NistP256>> = Arc::new(backend);
	let agreement = KeyAgreementIdentity::<P256Kem>::new(key_agreement.to_owned(), backend);
	let agreement = agreement.expect("the P-256 backend holds the key of its certificate");
	let pair = CmsIdentityPair::new(identity_of(signing, signing_key), agreement);
	let pair = pair.expect("the two certificates name one subject with two keys");

	P256CmsServer { pair, key_agreement, store: Arc::new(house.store()) }
}

/// A client of `server` that pins its key-agreement certificate and presents
/// a P-256 identity, beside the server, both under the P-256 provider.
fn cms_pair(server: P256CmsServer) -> (Handshake<Client, Cms, P256Provider>, Handshake<Server, Cms, P256Provider>) {
	let trust = ProvisionedTrust::new(Arc::new(server.key_agreement), server.store);
	let trust = trust.expect("the store admits the P-256 key-agreement certificate");
	let settings = CmsClientSettings { trust, identity: p256_identity() };
	let client = ClientConfig::<Cms, P256Provider>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("a P-256 client serves the client role");

	let native = RunnableProfile::<P256Provider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let purposes = KeyPurposes::HOUSE;
	let server_config = ServerConfig::<Cms, P256Provider>::new(CmsServerSettings, server.pair, profiles, purposes);
	let server_config = server_config.expect("a P-256 server pair serves the server role");
	(Handshake::client(client), Handshake::server(server_config))
}

/// The outside KEM encapsulates to the recipient key of RFC 9180 A.3.1 as
/// the vector does: `enc` is `pkEm` of the scalar it draws, and the shared
/// secret is the published one.
#[test]
fn the_p256_kem_encapsulates_as_rfc_9180_a_3_1() -> Result<(), Box<dyn std::error::Error>> {
	let recipient = PublicKey::from_sec1_bytes(&unhex(RFC_9180_A_3_1_PK_R))?;
	let mut draw = PublishedDraw(unhex(RFC_9180_A_3_1_SK_E));

	let encapsulation = P256Kem::encapsulate(&recipient, &mut draw)?;
	let encapsulated = (encapsulation.shared_secret.to_vec(), encapsulation.kemct);
	let published = (unhex(RFC_9180_A_3_1_SHARED_SECRET), unhex(RFC_9180_A_3_1_PK_E));
	assert_eq!(encapsulated, published);
	Ok(())
}

/// The outside KEM decapsulates `enc` of RFC 9180 A.3.1 through the backend
/// of the recipient scalar to the published shared secret.
#[tokio::test]
async fn the_p256_kem_decapsulates_rfc_9180_a_3_1() -> Result<(), Box<dyn std::error::Error>> {
	let scalar = NonZeroScalar::try_from(unhex(RFC_9180_A_3_1_SK_R).as_slice())?;
	let backend = P256AgreementBackend::of(scalar);
	let recipient = backend.public_key();

	let shared = P256Kem::decapsulate(&backend, &recipient, &unhex(RFC_9180_A_3_1_PK_E)).await?;
	assert_eq!(shared.as_slice(), unhex(RFC_9180_A_3_1_SHARED_SECRET).as_slice());
	Ok(())
}

/// The HPKE suite of P-256 seals the plaintext of RFC 9180 A.3.1.1 at
/// sequence number zero to `enc` and the published ciphertext.
#[test]
fn the_p256_hpke_suite_seals_as_rfc_9180_a_3_1_1() -> Result<(), Box<dyn std::error::Error>> {
	let recipient = PublicKey::from_sec1_bytes(&unhex(RFC_9180_A_3_1_PK_R))?;
	let mut published_draw = PublishedDraw(unhex(RFC_9180_A_3_1_SK_E));
	let draw: &mut dyn CryptoRngCore = &mut published_draw;
	let info = unhex(RFC_9180_A_3_1_INFO);
	let aad = unhex(RFC_9180_A_3_1_1_AAD_0);

	let sealed = recipient.seal::<P256Suite>(info, aad, unhex(RFC_9180_A_3_1_1_PLAINTEXT), Some(draw))?;
	let published = [unhex(RFC_9180_A_3_1_PK_E), unhex(RFC_9180_A_3_1_1_CIPHERTEXT_0)].concat();
	assert_eq!(sealed.to_bytes(), published);
	Ok(())
}

/// The HPKE suite of P-256 opens `enc` and the ciphertext of RFC 9180
/// A.3.1.1 at sequence number zero under the recipient scalar.
#[test]
fn the_p256_hpke_suite_opens_rfc_9180_a_3_1_1() -> Result<(), Box<dyn std::error::Error>> {
	let recipient = SecretKey::from_slice(&unhex(RFC_9180_A_3_1_SK_R))?;
	let wire = [unhex(RFC_9180_A_3_1_PK_E), unhex(RFC_9180_A_3_1_1_CIPHERTEXT_0)].concat();
	let message = HpkeMessage::<P256Suite>::from_bytes(wire)?;

	let opened = recipient.open(&message, unhex(RFC_9180_A_3_1_INFO), unhex(RFC_9180_A_3_1_1_AAD_0))?;
	assert_eq!(opened.to_insecure().as_slice(), unhex(RFC_9180_A_3_1_1_PLAINTEXT).as_slice());
	Ok(())
}

/// The HPKE flow runs under the P-256 provider, and the client's first
/// record opens under the server's session keys.
#[tokio::test]
async fn a_p256_provider_runs_the_hpke_flow() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = hpke_pair(p256_identity());
	run_legs(&mut client, &mut server).await;

	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let mut record = client_session.keys().send().encrypt_next(CONTENT)?.to_der()?;
	let opened = server_session.keys().recv().open(&mut record)?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The hello of a P-256 client carries `R` as a point of P-256 in the
/// compressed form, so `R` has the width of that form on P-256.
#[test]
fn a_p256_hello_carries_a_compressed_p256_point() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, _server) = hpke_pair(p256_identity());
	let ephemeral = carried_ephemeral(client.start()?)?;

	let point = PublicKey::from_sec1_bytes(&ephemeral)?;
	assert_eq!(ephemeral, point.to_encoded_point(true).as_bytes());
	Ok(())
}

/// The generator of secp256k1 in its compressed form (SEC 2 v2.0 §2.4.1)
/// has the width of a compressed P-256 point, and its x-coordinate is no
/// x-coordinate of P-256, so a P-256 server refuses the hello that carries
/// it as `R`.
#[tokio::test]
async fn a_p256_server_refuses_a_secp256k1_point() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = hpke_pair(p256_identity());
	let hello = hello_carrying(client.start()?, &TestKey::SEC2_SECP256K1_G_COMPRESSED)?;

	let refused = server.reply(hello).await;
	assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
	Ok(())
}

/// The CMS flow runs under the P-256 provider, with a key-agreement backend
/// on P-256 behind the outside KEM, and the client's first record opens
/// under the server's session keys.
#[tokio::test]
async fn a_p256_provider_runs_the_cms_flow() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = cms_pair(p256_cms_server());
	run_legs(&mut client, &mut server).await;

	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let mut record = client_session.keys().send().encrypt_next(CONTENT)?.to_der()?;
	let opened = server_session.keys().recv().open(&mut record)?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// A session of a client and a server under the P-256 provider, each a
/// multiplexed plane over a loopback socket, whose budgets bring a renewal
/// at the fifth single-chunk emit.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
mod renewal {
	use core::time::Duration;
	use std::sync::Arc;

	use tightbeam::crypto::policy::Secp256k1Policy;
	use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
	use tightbeam::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	use tightbeam::policy::TransitStatus;
	use tightbeam::prelude::TightBeamSocketAddr;
	use tightbeam::testing::TestFrame;
	use tightbeam::transport::client::{ClientBuilder, ConnectionBuilder};
	use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
	use tightbeam::transport::multiplex::{MuxAcceptor, MuxConnector, MuxDispatch, MuxHandle, MuxRole, SpawnedMux};
	use tightbeam::transport::tcp::r#async::{TokioListener, TokioStream};
	use tightbeam::transport::{EncryptedProtocol, ResponsePackage, TransportEncryptionConfig, TransportResult};
	use tightbeam::Frame;
	use tokio::net::TcpStream;
	use tokio::task::JoinHandle;

	use super::{p256_identity, P256Provider};
	use crate::common::poll::poll_until;

	/// The budgets under which the fifth single-chunk emit of a client tips
	/// its budget into the drain reserve, with one chunk of 1 KiB a stream.
	const RENEWAL_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 10, server_to_client: 4096 };

	/// The emits of the client, past the one that brings the renewal.
	const EMITS: usize = 8;

	/// The reads of a receipt, one every 5 ms for 2 s, before the wait for a
	/// renewal fails.
	const RENEWAL_POLLS: u32 = 400;

	/// The dispatch of the server: it echoes each unary frame.
	struct EchoDispatch;

	impl MuxDispatch for EchoDispatch {
		async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
			Ok(ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame))))
		}
	}

	/// The client end of a renewing session, with the tasks that keep both
	/// ends running.
	struct RenewingSession {
		handle: MuxHandle,
		_tasks: [JoinHandle<()>; 2],
		_serving: JoinHandle<TransportResult<()>>,
	}

	/// The offer of both ends: one peer-initiated stream, a chunk of 1 KiB,
	/// and [`RENEWAL_BUDGETS`].
	fn renewing_offer() -> TransportOffer {
		let offer = TransportOffer::mux(1).with_chunk_payload_size(1024);
		offer.with_budgets(RENEWAL_BUDGETS)
	}

	/// A client and a server under the P-256 provider that pin each other,
	/// each assembled as a multiplexed plane with its rekey context, while the
	/// server serves [`EchoDispatch`].
	async fn renewing_session() -> Result<RenewingSession, Box<dyn std::error::Error>> {
		let server_identity = p256_identity();
		let client_identity = p256_identity();
		let server_certificate = server_identity.certificate().to_owned();
		let pinned = DirectTrustValidator::default().with_trust_chain([client_identity.certificate().to_owned()]);
		let validators: [Arc<dyn CertificateValidation>; 1] = [Arc::new(pinned)];

		let config = TransportEncryptionConfig::<P256Provider>::new(server_identity).with_client_validators(validators);
		let bind = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
		let (listener, addr) = TokioListener::<P256Provider>::bind_with(bind, config).await?;
		let accepting = tokio::spawn(async move {
			let (transport, _) = listener.accept().await?;
			let mut transport = transport.with_mux_offer(Some(renewing_offer()));
			MuxAcceptor::negotiate_mux(&mut transport).await?;
			transport.into_mux(MuxRole::Server)
		});

		let store = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(server_certificate)?;
		let builder = ClientBuilder::<TokioListener<P256Provider>>::builder().with_trust_store(Arc::new(store.build()));
		let builder = builder.with_client_identity(client_identity);
		let stream = TcpStream::connect(*addr).await?;
		let client = builder.adopt(TokioStream::from(stream))?.into_transport();
		let mut client = client.with_mux_offer(Some(renewing_offer()));
		MuxConnector::complete_client_handshake(&mut client).await?;

		let SpawnedMux { handle, reader_task: client_reader, .. } = client.into_mux(MuxRole::Client)?.spawn();
		let server = accepting.await??;
		let SpawnedMux { responder, reader_task: server_reader, .. } = server.spawn();
		let serving = tokio::spawn(responder.serve_with(EchoDispatch));
		Ok(RenewingSession { handle, _tasks: [client_reader, server_reader], _serving: serving })
	}

	/// Emit [`EMITS`] frames on `handle`, each on a stream of its own.
	async fn emit_series(handle: &MuxHandle) -> TransportResult<()> {
		for index in 0..EMITS {
			let label = format!("p256-renewal-{index}");
			let frame = TestFrame::v0(Some(label.as_str()), None);
			handle.emit_on_stream(&frame).await?;
		}

		Ok(())
	}

	/// A session under the P-256 provider renews its epoch in band, so the
	/// client holds an epoch receipt other than the receipt of its handshake.
	#[tokio::test]
	async fn a_p256_session_renews_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let session = renewing_session().await?;
		let handshake_receipt = session.handle.session_receipt();
		emit_series(&session.handle).await?;

		let interval = Duration::from_millis(5);
		let rotated = || session.handle.session_receipt() != handshake_receipt;
		let renewed = poll_until(RENEWAL_POLLS, interval, rotated).await;
		assert!(renewed);
		Ok(())
	}
}
