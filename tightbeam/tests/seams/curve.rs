//! The handshake and the rekey run here under a curve an outside crate
//! brings: NIST P-256, whose arithmetic the `p256` crate holds.
//!
//! [`P256Provider`] brings these parts of its own:
//!
//! - a signature, ECDSA over P-256 under `ecdsa-with-SHA3-256`, as a [`SigningProvider`],
//! - a signing backend over a P-256 key, as a [`SigningKeyProvider`],
//! - a key-agreement backend, an [`AgreementBackend`] on P-256, as a [`DiffieHellman`] backend, and
//! - a KEM, DHKEM(P-256, HKDF-SHA256), as an [`OutsideKem`] over the generic helpers of [`DhKem`].
//!
//! The house AEAD, AES-256-GCM, and the house key wrap, AES-256, complete
//! it, beside the house digest and KDF of the default profile.
//!
//! These suites run under it:
//!
//! - the KEM of RFC 9180 Appendix A.3.1, through the outside KEM and the HPKE suite of P-256,
//! - both handshake flows, and the refusal of a secp256k1 point at the width of a compressed P-256 point,
//! - an in-band renewal of a multiplexed session over TCP, and
//! - a handshake and one exchange over the blocking TCP transport.
//!
//! [`p384`] and [`p521`] bring the same parts on P-384 and on P-521.

use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;
use std::sync::Arc;

use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve;
use p256::elliptic_curve::group::Curve as _;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{AffinePoint, NistP256, PublicKey};
use rand_core::impls::{next_u32_via_fill, next_u64_via_fill};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use tightbeam::cms::content_info::ContentInfo;
use tightbeam::crypto::aead::{Aes128Gcm, Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::cms::{Encapsulation, EnvelopeError, KeyAgreementIdentity, RecipientKem};
use tightbeam::crypto::common::typenum::Unsigned;
use tightbeam::crypto::common::{BlockSizeUser, OutputSizeUser};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::crypto::hkdf::{InvalidLength, SimpleHkdf};
use tightbeam::crypto::hpke::{
	DhKem, DhKemSuite, HkdfSha256, HpkeKdf, HpkeMessage, HpkePublicKeyOps, HpkeSecretKeyOps, HpkeSuite,
};
use tightbeam::crypto::k256::ecdsa::SigningKey as Secp256k1SigningKey;
use tightbeam::crypto::kdf::{HkdfSha3_256, KdfError};
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
use tightbeam::der::oid::AssociatedOid;
use tightbeam::der::{Any, Decode, Encode, Tag};
use tightbeam::marker::MaybeSendFuture;
use tightbeam::oids::{CURVE_NIST_P256, DATA, SIGNER_ECDSA_WITH_SHA3_256};
use tightbeam::random::{CryptoRngCore, OsRng};
use tightbeam::spki::{
	AlgorithmIdentifierOwned, Document, EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoRef,
};
use tightbeam::testing::{unhex, TestCertificate, TestCmsServer, TestKey};
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, ClientFlow, ClientHello, Cms, CmsClientSettings, CmsIdentityPair, CmsServerSettings,
	Handshake, HandshakeCurve, HandshakeError, HandshakeMessage, HandshakeProvider, Hpke, HpkeClientSettings,
	HpkeServerSettings, LearnedTrust, ProvisionedTrust, Server, ServerConfig, ServerFlow, SupportedProfiles,
};
use tightbeam::x509::ext::pkix::KeyUsages;
use tightbeam::x509::Certificate;
use tightbeam::zeroize::Zeroizing;
use tightbeam::ZeroizingBytes;

use super::{run_legs, CONTENT};

mod p384;
mod p521;

/// `id-ecPublicKey` (RFC 5480 §2.1.1), the algorithm of the key each outside
/// key-agreement backend holds.
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// DHKEM(P-256, HKDF-SHA256) in the HPKE KEM registry (RFC 9180 §7.1).
const KEM_DHKEM_P256_HKDF_SHA256: u16 = 0x0010;

/// RFC 9180 A.3.1 and A.6.1: the `info` of the key schedule of every
/// base-mode vector.
const RFC_9180_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";

/// RFC 9180 A.3.1.1 and A.6.1.1: the associated data at sequence number zero.
const RFC_9180_AAD_0: &str = "436f756e742d30";

/// RFC 9180 A.3.1.1 and A.6.1.1: the plaintext of every encryption.
const RFC_9180_PLAINTEXT: &str = "4265617574792069732074727574682c20747275746820626561757479";

/// One base-mode vector of a DHKEM and of its HPKE suite, under the `info`,
/// the associated data, and the plaintext of RFC 9180 Appendix A.
struct KemVector {
	/// `skEm`, the ephemeral scalar the sender draws.
	sk_e: &'static str,
	/// `pkEm`, the public half of `skEm`, which is `enc`.
	pk_e: &'static str,
	/// `skRm`, the recipient scalar.
	sk_r: &'static str,
	/// `pkRm`, the public half of `skRm`.
	pk_r: &'static str,
	/// The KEM shared secret.
	shared_secret: &'static str,
	/// The ciphertext at sequence number zero.
	ciphertext: &'static str,
}

/// RFC 9180 A.3.1 and A.3.1.1.
const RFC_9180_A_3_1: KemVector = KemVector {
	sk_e: "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
	pk_e: "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac9\
		8536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
	sk_r: "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
	pk_r: "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a82\
		6a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
	shared_secret: "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
	ciphertext: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
};

impl KemVector {
	/// The shared secret and `enc` of the vector.
	fn encapsulation(&self) -> (Vec<u8>, Vec<u8>) {
		(unhex(self.shared_secret), unhex(self.pk_e))
	}

	/// The message of the vector: `enc`, then the ciphertext.
	fn message(&self) -> Vec<u8> {
		[unhex(self.pk_e), unhex(self.ciphertext)].concat()
	}

	/// The shared secret and `enc` of the outside KEM `K` on the curve `C`,
	/// which encapsulates to `pkRm` and draws `skEm`.
	fn encapsulated_by<C, K>(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>>
	where
		C: HandshakeCurve,
		K: RecipientKem<PublicKey = elliptic_curve::PublicKey<C>>,
	{
		let recipient = elliptic_curve::PublicKey::<C>::from_sec1_bytes(&unhex(self.pk_r))?;
		let mut draw = PublishedDraw(unhex(self.sk_e));

		let encapsulation = K::encapsulate(&recipient, &mut draw)?;
		Ok((encapsulation.shared_secret.to_vec(), encapsulation.kemct))
	}

	/// The shared secret of the outside KEM `K` on the curve `C`, which
	/// decapsulates `enc` through an [`AgreementBackend`] of `skRm`.
	async fn decapsulated_by<C, K>(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>
	where
		C: HandshakeCurve,
		K: RecipientKem<PublicKey = elliptic_curve::PublicKey<C>, PrivateKey = dyn DiffieHellman<C>>,
	{
		let scalar = elliptic_curve::NonZeroScalar::<C>::try_from(unhex(self.sk_r).as_slice())?;
		let backend = AgreementBackend::of(scalar);
		let recipient = backend.public_key();

		let shared = K::decapsulate(&backend, &recipient, &unhex(self.pk_e)).await?;
		Ok(shared.to_vec())
	}

	/// The message that the HPKE suite `S` seals to `pkRm` at sequence number
	/// zero under the ephemeral `skEm`: `enc`, then the ciphertext.
	fn sealed_by<S: HpkeSuite>(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		let recipient = elliptic_curve::PublicKey::<S::Curve>::from_sec1_bytes(&unhex(self.pk_r))?;
		let mut published_draw = PublishedDraw(unhex(self.sk_e));
		let draw: &mut dyn CryptoRngCore = &mut published_draw;
		let info = unhex(RFC_9180_INFO);
		let aad = unhex(RFC_9180_AAD_0);

		let sealed = recipient.seal::<S>(info, aad, unhex(RFC_9180_PLAINTEXT), Some(draw))?;
		Ok(sealed.to_bytes())
	}

	/// The plaintext that the HPKE suite `S` opens from the message of the
	/// vector, at sequence number zero under `skRm`.
	fn opened_by<S: HpkeSuite>(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
		let recipient = elliptic_curve::SecretKey::<S::Curve>::from_slice(&unhex(self.sk_r))?;
		let message = HpkeMessage::<S>::from_bytes(self.message())?;

		let opened = recipient.open(&message, unhex(RFC_9180_INFO), unhex(RFC_9180_AAD_0))?;
		Ok(opened.to_insecure().to_vec())
	}
}

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

/// HKDF over the digest `D`, the KDF `KDF_ID` of RFC 9180 §7.2, as the
/// outside crate writes it. `Nh` is the output size of `D`.
struct OutsideHkdf<D, const KDF_ID: u16>(PhantomData<D>);

impl<D, const KDF_ID: u16> HpkeKdf for OutsideHkdf<D, KDF_ID>
where
	D: Digest + BlockSizeUser + Clone,
{
	const KDF_ID: u16 = KDF_ID;
	const EXTRACT_SIZE: usize = <<D as OutputSizeUser>::OutputSize as Unsigned>::USIZE;

	fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
		let (prk, _) = SimpleHkdf::<D>::extract(Some(salt), ikm);
		Zeroizing::new(prk.to_vec())
	}

	fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<ZeroizingBytes, KdfError> {
		let keyed = SimpleHkdf::<D>::from_prk(prk).map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
		let mut okm = Zeroizing::new(vec![0u8; len]);
		keyed.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;
		Ok(okm)
	}
}

/// The identifier the outside crate gives its KEM on a curve, under the arc
/// of the outside crate.
trait OutsideKemOid {
	/// The identifier of the KEM on this curve.
	const KEM: ObjectIdentifier;
}

/// The P-256 KEM of the outside arc.
impl OutsideKemOid for NistP256 {
	const KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.3");
}

/// A KEM an outside crate writes: DHKEM `KEM_ID` on the curve `C` under the
/// KDF `K`, through the generic helpers of [`DhKem`], and named by the
/// identifier that [`OutsideKemOid`] gives `C`.
struct OutsideKem<C, K, const KEM_ID: u16>(PhantomData<(C, K)>);

impl<C, K, const KEM_ID: u16> RecipientKem for OutsideKem<C, K, KEM_ID>
where
	C: HandshakeCurve + OutsideKemOid,
	K: HpkeKdf,
{
	const OID: ObjectIdentifier = C::KEM;
	const USAGE: KeyUsages = KeyUsages::KeyAgreement;
	type PublicKey = elliptic_curve::PublicKey<C>;
	type PrivateKey = dyn DiffieHellman<C>;

	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self::PublicKey, CertificateValidationError> {
		Ok(elliptic_curve::PublicKey::try_from(spki)?)
	}

	fn encapsulate(recipient: &Self::PublicKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError> {
		DhKem::<C, K, KEM_ID>::encap_to(recipient, rng)
	}

	fn decapsulate<'a>(
		key: &'a dyn DiffieHellman<C>,
		recipient: &'a Self::PublicKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>> {
		DhKem::<C, K, KEM_ID>::decap_through(key, recipient, kemct)
	}
}

/// DHKEM(P-256, HKDF-SHA256), the KEM of RFC 9180 §7.1 that
/// [`KEM_DHKEM_P256_HKDF_SHA256`] names.
type P256Kem = OutsideKem<NistP256, HkdfSha256, KEM_DHKEM_P256_HKDF_SHA256>;

/// The HPKE suite of RFC 9180 A.3: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// and AES-128-GCM.
type P256Suite = DhKemSuite<NistP256, HkdfSha256, Aes128Gcm, KEM_DHKEM_P256_HKDF_SHA256>;

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

/// The key-agreement backend of an identity on the curve `C`: it holds a
/// scalar and runs the Diffie-Hellman product itself, so the scalar stays
/// inside it.
struct AgreementBackend<C: HandshakeCurve> {
	scalar: elliptic_curve::NonZeroScalar<C>,
}

/// The public key names the backend, and the scalar stays out of the output.
impl<C: HandshakeCurve> Debug for AgreementBackend<C> {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("AgreementBackend")
			.field("public_key", &self.public_key())
			.finish_non_exhaustive()
	}
}

impl<C: HandshakeCurve> AgreementBackend<C> {
	/// The backend of `scalar`.
	fn of(scalar: elliptic_curve::NonZeroScalar<C>) -> Self {
		Self { scalar }
	}

	/// The backend of a fresh scalar.
	fn random() -> Self {
		Self::of(elliptic_curve::NonZeroScalar::random(&mut OsRng))
	}

	/// The public half of the scalar.
	fn public_key(&self) -> elliptic_curve::PublicKey<C> {
		elliptic_curve::PublicKey::from_secret_scalar(&self.scalar)
	}
}

impl<C: HandshakeCurve> KeyBackend for AgreementBackend<C> {
	/// `id-ecPublicKey` on `C`, the algorithm of the key the backend holds.
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		let parameters = Any::encode_from(&C::OID).ok();
		AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key().to_public_key_der()?.into_vec())
	}
}

/// The x-coordinate of the product of the backend's scalar and the peer
/// point, as wide as the field of `C` (SEC 1 v2.0 §3.3.1).
impl<C: HandshakeCurve> DiffieHellman<C> for AgreementBackend<C> {
	fn agree<'a>(
		&'a self,
		peer: &'a elliptic_curve::PublicKey<C>,
	) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
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

/// The certificate of the point `point` on the curve `curve`, cut from the
/// self-signed house certificate of a fresh secp256k1 key, whose key
/// identifier sets it apart from every other certificate of a test. A trust
/// that pins it compares it whole.
fn certificate_of(curve: ObjectIdentifier, point: &[u8]) -> Certificate {
	let template = TestCertificate::self_signed(&Secp256k1SigningKey::random(&mut OsRng));
	TestCertificate::with_curve_point(template, curve, point)
}

/// The identity under the provider `P` of `certificate` and `key`, the
/// signing backend that holds its key.
fn identity_of<P>(certificate: Certificate, key: Arc<dyn SigningKeyProvider>) -> SigningIdentity
where
	P: HandshakeProvider<VerifyingKey: PartialEq>,
{
	let identity = SigningIdentity::with_provider::<P>(certificate, key);
	identity.expect("the outside key matches its certificate and its algorithm")
}

/// An identity under [`P256Provider`], of a fresh key.
fn p256_identity() -> SigningIdentity {
	let key = SigningKey::random(&mut OsRng);
	let point = PublicKey::from(key.verifying_key()).to_encoded_point(false);
	let certificate = certificate_of(CURVE_NIST_P256, point.as_bytes());
	identity_of::<P256Provider>(certificate, Arc::new(P256KeyProvider { key }))
}

/// A client that pins the certificate of `server`, beside a server that
/// holds `server`, both under the provider `P`.
fn hpke_pair<P: HandshakeProvider>(
	server: SigningIdentity,
) -> (Handshake<Client, Hpke, P>, Handshake<Server, Hpke, P>) {
	let pinned = DirectTrustValidator::default().with_trust_chain([server.certificate().to_owned()]);
	let pinned = pinned.expect("an outside certificate encodes");
	let settings = HpkeClientSettings::new(LearnedTrust::new(pinned));
	let client = ClientConfig::<Hpke, P>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("an outside client serves the client role");

	let native = RunnableProfile::<P>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let purposes = KeyPurposes::HOUSE;
	let server_config = ServerConfig::<Hpke, P>::new(HpkeServerSettings::new(), server, profiles, purposes);
	let server_config = server_config.expect("an outside server identity serves the server role");
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

/// The ephemeral `R` that the hello of an HPKE client under `P` carries,
/// beside the compressed form of the point it decodes to on the curve of `P`.
fn carried_point<P: HandshakeProvider>(
	server: SigningIdentity,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
	let (mut client, _server) = hpke_pair::<P>(server);
	let ephemeral = carried_ephemeral(client.start()?)?;

	let point = elliptic_curve::PublicKey::<P::Curve>::from_sec1_bytes(&ephemeral)?;
	let compressed = point.to_encoded_point(true).as_bytes().to_vec();
	Ok((ephemeral, compressed))
}

/// The identities of a CMS server under the outside KEM `K`, whose
/// certificates a house test authority issued, beside the certificate a client
/// pins and the store that holds the authority.
struct OutsideCmsServer<K: RecipientKem> {
	/// The signing identity and the key-agreement identity the server holds.
	pair: CmsIdentityPair<K>,
	/// The key-agreement certificate, which a client pins.
	key_agreement: Certificate,
	/// The client's store, which holds the authority of both certificates.
	store: Arc<dyn CertificateTrust>,
}

impl<K: RecipientKem> OutsideCmsServer<K> {
	/// The server of `house` that signs as `signing` and agrees through
	/// `backend`, the holder of the key of `key_agreement`.
	fn of(
		house: &TestCmsServer,
		signing: SigningIdentity,
		key_agreement: Certificate,
		backend: Arc<K::PrivateKey>,
	) -> Self {
		let agreement = KeyAgreementIdentity::<K>::new(key_agreement.to_owned(), backend);
		let agreement = agreement.expect("the outside backend holds the key of its certificate");
		let pair = CmsIdentityPair::new(signing, agreement);
		let pair = pair.expect("the two certificates name one subject with two keys");

		Self { pair, key_agreement, store: Arc::new(house.store()) }
	}
}

/// `certificate` of `house` with the point `point` on the curve `curve` in
/// place of its key, issued again by the authority of `house`.
fn reissued(house: &TestCmsServer, certificate: &Certificate, curve: ObjectIdentifier, point: &[u8]) -> Certificate {
	let moved = TestCertificate::with_curve_point(certificate.to_owned(), curve, point);
	TestCertificate::signed_by(moved, &house.authority_key)
}

/// A CMS server under `P` named `name`, whose signing backend `signer` holds
/// the point `signing_point` and whose key-agreement backend is an
/// [`AgreementBackend`] of a fresh scalar. Its two certificates name one
/// subject under one house authority.
fn outside_cms_server<P>(
	name: &str,
	signer: Arc<dyn SigningKeyProvider>,
	signing_point: &[u8],
) -> OutsideCmsServer<P::Kem>
where
	P: HandshakeProvider<VerifyingKey: PartialEq, Kem: RecipientKem<PrivateKey = dyn DiffieHellman<P::Curve>>>,
{
	let house = TestCmsServer::generate(name);
	let backend = AgreementBackend::<P::Curve>::random();
	let curve = <P::Curve as AssociatedOid>::OID;

	let agreement_point = backend.public_key().to_encoded_point(false);
	let signing = reissued(&house, &house.signing, curve, signing_point);
	let key_agreement = reissued(&house, &house.key_agreement, curve, agreement_point.as_bytes());
	let signing = identity_of::<P>(signing, signer);
	let backend: Arc<dyn DiffieHellman<P::Curve>> = Arc::new(backend);
	OutsideCmsServer::of(&house, signing, key_agreement, backend)
}

/// A CMS server of fresh P-256 keys.
fn p256_cms_server() -> OutsideCmsServer<P256Kem> {
	let key = SigningKey::random(&mut OsRng);
	let point = PublicKey::from(key.verifying_key()).to_encoded_point(false);
	outside_cms_server::<P256Provider>("p256 server", Arc::new(P256KeyProvider { key }), point.as_bytes())
}

/// A client of `server` that pins its key-agreement certificate and presents
/// `identity`, beside the server, both under the provider `P`.
fn cms_pair<P: HandshakeProvider>(
	server: OutsideCmsServer<P::Kem>,
	identity: SigningIdentity,
) -> (Handshake<Client, Cms, P>, Handshake<Server, Cms, P>) {
	let trust = ProvisionedTrust::new(Arc::new(server.key_agreement), server.store);
	let trust = trust.expect("the store admits the outside key-agreement certificate");
	let settings = CmsClientSettings { trust, identity };
	let client = ClientConfig::<Cms, P>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("an outside client serves the client role");

	let native = RunnableProfile::<P>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let purposes = KeyPurposes::HOUSE;
	let server_config = ServerConfig::<Cms, P>::new(CmsServerSettings, server.pair, profiles, purposes);
	let server_config = server_config.expect("an outside server pair serves the server role");
	(Handshake::client(client), Handshake::server(server_config))
}

/// The first record the client of `pair` seals once the three legs run, as
/// the server of `pair` opens it under its session keys.
async fn first_record_opened<P, F>(
	pair: (Handshake<Client, F, P>, Handshake<Server, F, P>),
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
	P: HandshakeProvider,
	F: ClientFlow<P> + ServerFlow<P>,
{
	let (mut client, mut server) = pair;
	run_legs(&mut client, &mut server).await;

	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let mut record = client_session.keys().send().encrypt_next(CONTENT)?.to_der()?;
	let opened = server_session.into_keys().recv_mut().open(&mut record)?;
	Ok(opened.to_vec())
}

/// The outside KEM encapsulates to the recipient key of RFC 9180 A.3.1 as
/// the vector does: `enc` is `pkEm` of the scalar it draws, and the shared
/// secret is the published one.
#[test]
fn the_p256_kem_encapsulates_as_rfc_9180_a_3_1() -> Result<(), Box<dyn std::error::Error>> {
	let encapsulated = RFC_9180_A_3_1.encapsulated_by::<NistP256, P256Kem>()?;
	assert_eq!(encapsulated, RFC_9180_A_3_1.encapsulation());
	Ok(())
}

/// The outside KEM decapsulates `enc` of RFC 9180 A.3.1 through the backend
/// of the recipient scalar to the published shared secret.
#[tokio::test]
async fn the_p256_kem_decapsulates_rfc_9180_a_3_1() -> Result<(), Box<dyn std::error::Error>> {
	let shared = RFC_9180_A_3_1.decapsulated_by::<NistP256, P256Kem>().await?;
	assert_eq!(shared, unhex(RFC_9180_A_3_1.shared_secret));
	Ok(())
}

/// The HPKE suite of P-256 seals the plaintext of RFC 9180 A.3.1.1 at
/// sequence number zero to `enc` and the published ciphertext.
#[test]
fn the_p256_hpke_suite_seals_as_rfc_9180_a_3_1_1() -> Result<(), Box<dyn std::error::Error>> {
	let sealed = RFC_9180_A_3_1.sealed_by::<P256Suite>()?;
	assert_eq!(sealed, RFC_9180_A_3_1.message());
	Ok(())
}

/// The HPKE suite of P-256 opens `enc` and the ciphertext of RFC 9180
/// A.3.1.1 at sequence number zero under the recipient scalar.
#[test]
fn the_p256_hpke_suite_opens_rfc_9180_a_3_1_1() -> Result<(), Box<dyn std::error::Error>> {
	let opened = RFC_9180_A_3_1.opened_by::<P256Suite>()?;
	assert_eq!(opened, unhex(RFC_9180_PLAINTEXT));
	Ok(())
}

/// The HPKE flow runs under the P-256 provider, and the client's first
/// record opens under the server's session keys.
#[tokio::test]
async fn a_p256_provider_runs_the_hpke_flow() -> Result<(), Box<dyn std::error::Error>> {
	let opened = first_record_opened(hpke_pair::<P256Provider>(p256_identity())).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The hello of a P-256 client carries `R` as a point of P-256 in the
/// compressed form, so `R` has the width of that form on P-256.
#[test]
fn a_p256_hello_carries_a_compressed_p256_point() -> Result<(), Box<dyn std::error::Error>> {
	let (carried, compressed) = carried_point::<P256Provider>(p256_identity())?;
	assert_eq!(carried, compressed);
	Ok(())
}

/// The generator of secp256k1 in its compressed form (SEC 2 v2.0 §2.4.1)
/// has the width of a compressed P-256 point, and its x-coordinate is no
/// x-coordinate of P-256, so a P-256 server refuses the hello that carries
/// it as `R`.
#[tokio::test]
async fn a_p256_server_refuses_a_secp256k1_point() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = hpke_pair::<P256Provider>(p256_identity());
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
	let opened = first_record_opened(cms_pair::<P256Provider>(p256_cms_server(), p256_identity())).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// A session of a client and a server under an outside provider, each a
/// multiplexed plane over a loopback socket, whose budgets bring a renewal
/// at the fifth single-chunk emit.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
mod renewal {
	use core::time::Duration;
	use std::sync::Arc;

	use tightbeam::crypto::policy::Secp256k1Policy;
	use tightbeam::crypto::sign::SigningIdentity;
	use tightbeam::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
	use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
	use tightbeam::crypto::x509::KeyCurves;
	use tightbeam::policy::TransitStatus;
	use tightbeam::prelude::TightBeamSocketAddr;
	use tightbeam::testing::TestFrame;
	use tightbeam::transport::client::{ClientBuilder, ConnectionBuilder};
	use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
	use tightbeam::transport::handshake::HandshakeProvider;
	use tightbeam::transport::multiplex::{
		MuxAcceptor, MuxConnector, MuxDispatch, MuxDrivers, MuxHandle, MuxRole, SpawnedMux,
	};
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

	/// The client end of a session that renews its epoch, with the drivers
	/// and the task that run both ends.
	struct RenewingSession {
		handle: MuxHandle,
		_drivers: [MuxDrivers; 2],
		_serving: JoinHandle<TransportResult<()>>,
	}

	/// The offer of both ends: one peer-initiated stream, a chunk of 1 KiB,
	/// and [`RENEWAL_BUDGETS`].
	fn renewing_offer() -> TransportOffer {
		let offer = TransportOffer::mux(1).with_chunk_payload_size(1024);
		offer.with_budgets(RENEWAL_BUDGETS)
	}

	/// A client and a server under the provider `P` that pin each other, each
	/// with an identity of `identity`, and each assembled as a multiplexed
	/// plane with its rekey context, while the server serves [`EchoDispatch`].
	async fn renewing_session<P: HandshakeProvider>(
		identity: fn() -> SigningIdentity,
	) -> Result<RenewingSession, Box<dyn std::error::Error>> {
		let server_identity = identity();
		let client_identity = identity();
		let server_certificate = server_identity.certificate().to_owned();
		let pinned = DirectTrustValidator::default().with_trust_chain([client_identity.certificate().to_owned()])?;
		let validators: [Arc<dyn CertificateValidation>; 1] = [Arc::new(pinned)];

		let config = TransportEncryptionConfig::<P>::new(server_identity).with_client_validators(validators);
		let bind = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
		let (listener, addr) = TokioListener::<P>::bind_with(bind, config).await?;
		let accepting = tokio::spawn(async move {
			let (transport, _) = listener.accept().await?;
			let mut transport = transport.with_mux_offer(Some(renewing_offer()));
			MuxAcceptor::negotiate_mux(&mut transport).await?;
			transport.into_mux(MuxRole::Server)
		});

		let store = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let store = store.with_certificate(server_certificate)?;
		let builder = ClientBuilder::<TokioListener<P>>::builder().with_trust_store(Arc::new(store.build()));
		let builder = builder.with_client_identity(client_identity);
		let stream = TcpStream::connect(*addr).await?;
		let client = builder.adopt(TokioStream::from(stream))?.into_transport();
		let mut client = client.with_mux_offer(Some(renewing_offer()));
		MuxConnector::complete_client_handshake(&mut client).await?;

		let SpawnedMux { handle, drivers: client_drivers, .. } = client.into_mux(MuxRole::Client)?.spawn();
		let server = accepting.await??;
		let SpawnedMux { responder, drivers: server_drivers, .. } = server.spawn();
		let serving = tokio::spawn(responder.serve_with(EchoDispatch));
		Ok(RenewingSession { handle, _drivers: [client_drivers, server_drivers], _serving: serving })
	}

	/// Emits [`EMITS`] frames on `handle`, each on a stream of its own.
	async fn emit_series(handle: &MuxHandle) -> TransportResult<()> {
		for index in 0..EMITS {
			let label = format!("renewal-{index}");
			let frame = TestFrame::v0(Some(label.as_str()), None);
			handle.emit_on_stream(&frame).await?;
		}

		Ok(())
	}

	/// Whether a session under the provider `P`, with identities of
	/// `identity`, renews its epoch in band: the client holds an epoch receipt
	/// other than the receipt of its handshake within [`RENEWAL_POLLS`] reads.
	pub(super) async fn renews_its_epoch<P: HandshakeProvider>(
		identity: fn() -> SigningIdentity,
	) -> Result<bool, Box<dyn std::error::Error>> {
		let session = renewing_session::<P>(identity).await?;
		let handshake_receipt = session.handle.session_receipt();
		emit_series(&session.handle).await?;

		let interval = Duration::from_millis(5);
		let rotated = || session.handle.session_receipt() != handshake_receipt;
		Ok(poll_until(RENEWAL_POLLS, interval, rotated).await)
	}

	/// A session under the P-256 provider renews its epoch in band, so the
	/// client holds an epoch receipt other than the receipt of its handshake.
	#[tokio::test]
	async fn a_p256_session_renews_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
		let renewed = renews_its_epoch::<P256Provider>(p256_identity).await?;
		assert!(renewed);
		Ok(())
	}
}

/// A client and a server under the P-256 provider run a handshake and one
/// exchange over the blocking TCP transport.
#[cfg(feature = "tcp")]
mod blocking {
	use super::{p256_identity, P256Provider};
	use crate::seams::blocking::blocking_exchange;

	/// A blocking client and server under the P-256 provider complete their
	/// handshake, so the client holds the certificate of the server, and a
	/// frame the client emits comes back to it.
	#[tokio::test]
	async fn a_p256_provider_runs_the_blocking_transport() -> Result<(), Box<dyn std::error::Error>> {
		let exchange = blocking_exchange::<P256Provider>(p256_identity(), "p256-blocking").await?;
		assert_eq!(exchange.received, exchange.sent);
		Ok(())
	}
}

/// `cert!` issues a certificate under the signature type that its
/// `signature:` key names.
mod certificate {
	use core::time::Duration;

	use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
	use p256::ecdsa::{DerSignature, Signature, SigningKey};
	use tightbeam::crypto::hash::{Digest, Sha3_256};
	use tightbeam::crypto::sign::Sha3Signer;
	use tightbeam::der::Encode;
	use tightbeam::oids::SIGNER_ECDSA_WITH_SHA3_256;
	use tightbeam::random::OsRng;
	use tightbeam::spki::SubjectPublicKeyInfoOwned;

	/// `cert!` signs a root certificate under the P-256 signature type of its
	/// `signature:` key, so the P-256 key verifies it under
	/// `ecdsa-with-SHA3-256`.
	#[test]
	fn cert_issues_a_p256_certificate_under_a_p256_signature_type() -> Result<(), Box<dyn std::error::Error>> {
		let key = SigningKey::random(&mut OsRng);
		let signer = Sha3Signer::from(&key);
		let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;

		let certificate = tightbeam::cert!(
			profile: Root,
			subject: "CN=P-256 Root",
			serial: 1u32,
			duration: Duration::from_secs(3600),
			signer: &signer,
			subject_public_key: spki,
			signature: DerSignature
		)?;

		let prehash = Sha3_256::digest(certificate.tbs_certificate.to_der()?);
		let signature = Signature::from_der(certificate.signature.raw_bytes())?;
		let verified = key.verifying_key().verify_prehash(&prehash, &signature).is_ok();
		let algorithm = certificate.signature_algorithm.oid;
		assert_eq!((algorithm, verified), (SIGNER_ECDSA_WITH_SHA3_256, true));
		Ok(())
	}
}
