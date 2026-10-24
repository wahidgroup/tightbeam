//! The seams an outside crate fills, each built here as such a crate must
//! build it, through the public API of tightbeam alone.
//!
//! The parts the outside crate writes itself:
//!
//! - a signature, ECDSA over secp256k1 under `ecdsa-with-SHA3-512`, whose
//!   canonical form refuses a high `s`, as a [`SigningProvider`],
//! - a KDF, HKDF over SHA3-512 under an identifier of its own arc, as a [`KdfProvider`],
//! - a KEM, the DHKEM over secp256k1 under a KEM identifier of its own, through [`RecipientKem`],
//! - a signing backend, as a [`SigningKeyProvider`],
//! - a key-agreement backend that runs its own scalar product, as a [`DiffieHellman`] backend,
//! - an AEAD, AES-128-GCM under a cipher type of its own, as a [`ContentEncryption`], and
//! - a key wrap that brings `wrap` and `unwrap` alone, as a [`KeyWrapAlgorithm`].
//!
//! The outside provider selects one house type through [`KeyWrapProvider`]:
//! the AES-128 key wrap.
//!
//! The suites that run under it:
//!
//! - [`hpke`] and [`cms`] run both handshakes, under a provider that names no HPKE suite.
//! - [`kem`] brings a KEM whose private-key operation is not Diffie-Hellman.
//! - [`curves`] brings the decoder of a curve, which refuses its off-curve encodings at each reader of keys.

#[cfg(feature = "transport-cms")]
mod cms;
mod curves;
mod frames;
#[cfg(feature = "transport-hpke")]
mod hpke;
mod kem;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
mod mux;
mod servlet;
mod trust;

use std::sync::Arc;

use tightbeam::asn1::GcmParameters;
use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::aead::{
	AeadAlgorithm, AeadCore, AeadInPlace, Aes128Gcm, Aes128GcmOid, Error as AeadError, Key, KeyInit, KeySizeUser,
	Nonce, Tag,
};
use tightbeam::crypto::cms::{
	AuthEnvelopedData, ContentEncryption, Encapsulation, EnvelopeError, KemRecipient, KeyAgreementIdentity, Opener,
	Recipient, RecipientKem,
};
use tightbeam::crypto::common::typenum::U32;
use tightbeam::crypto::hash::{Digest, Sha3_512};
use tightbeam::crypto::hpke::{DhKem, HkdfSha256};
use tightbeam::crypto::k256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use tightbeam::crypto::k256::elliptic_curve::point::AffineCoordinates;
use tightbeam::crypto::k256::{AffinePoint, NonZeroScalar, PublicKey, Secp256k1};
use tightbeam::crypto::kdf::{Hkdf, KdfError, KdfFunction};
use tightbeam::crypto::key::{DiffieHellman, KeyBackend, KeyError, Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::policy::ProviderPolicy;
use tightbeam::crypto::profiles::{
	AeadProvider, Aes128Wrap, Aes256Wrap, CryptoProvider, CurveProvider, DefaultCryptoProvider, DigestProvider,
	KdfProvider, KeyWrapAlgorithm, KeyWrapProvider, SecurityProfile, SigningProvider,
};
use tightbeam::crypto::secret::{SecretSlice, ToInsecure};
use tightbeam::crypto::sign::{
	CanonicalForm, CmsSigner, Error as SignatureError, PrehashSigner, PrehashVerifier, SignatureAlgorithmIdentifier,
	SignatureEncoding, SignedContent, SignerError, SigningIdentity, Verifier,
};
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::{KeyAgreement, KeyPurposes, PeerCertificate};
use tightbeam::der::asn1::{ObjectIdentifier, OctetString};
use tightbeam::der::oid::AssociatedOid;
use tightbeam::der::{Any, Encode};
use tightbeam::error::ReceivedExpectedError;
use tightbeam::oids::{
	AES_128_GCM, AES_128_WRAP, CURVE_SECP256K1, DATA, SIGNER_ECDSA_WITH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_512,
};
use tightbeam::random::{CryptoRngCore, OsRng};
use tightbeam::spki::{AlgorithmIdentifierOwned, Document, EncodePublicKey, SubjectPublicKeyInfoRef};
use tightbeam::testing::{unhex, EnvelopeRecipient, SeededStream, TestCertificate, TestMessage};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::ext::pkix::KeyUsages;
use tightbeam::x509::Certificate;
use tightbeam::zeroize::Zeroizing;
use tightbeam::{Version, ZeroizingBytes};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::negotiation::{NoStrengthFloor, ProfilePolicy};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::{Client, ClientFlow, Handshake, Server, ServerFlow};

/// The identifier of the outside KEM, under an arc of its own.
const OUTSIDE_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");

/// The identifier of the outside KDF, under the same arc.
const OUTSIDE_KDF: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.2");

/// `id-ecPublicKey` (RFC 5480 §2.1.1), the algorithm of the key the outside
/// key-agreement backend holds.
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The HPKE KEM identifier of the outside KEM, which its `suite_id` carries
/// in place of the registered `0x0016`.
const OUTSIDE_KEM_ID: u16 = 0xFE16;

/// The recipient key of the outside KEM's known answer.
const KNOWN_RECIPIENT_KEY: [u8; 32] = [0x2a; 32];

/// The `encryptedKey` of an outside KEM seal to [`KNOWN_RECIPIENT_KEY`] from
/// `SeededStream(0)`, computed with Python's `cryptography`: DHKEM(secp256k1,
/// HKDF-SHA256) under KEM identifier `0xFE16` (RFC 9180 §4.1), HKDF-SHA3-512
/// over the `CMSORIforKEMOtherInfo` for a 16-octet KEK, and AES-128 key wrap
/// of the content key `0x01` × 16.
const OUTSIDE_WRAPPED_KEY: &str = "c6c821278412285c30a481017736f88a21e472784d8b3180";

/// The content every envelope here seals.
const CONTENT: &[u8] = b"sealed under an outside provider";

/// The purpose label of the outside opening.
const UKM_LABEL: &[u8] = b"tb/test/outside/ukm/v1";

/// An ECDSA signature over secp256k1 under SHA3-512, in DER.
///
/// SHA3-512 stands in for SHA-256, whose type in this build names no OID, and
/// differs from the house digest.
#[derive(Clone, Debug)]
struct OutsideSignature(DerSignature);

impl TryFrom<&[u8]> for OutsideSignature {
	type Error = SignatureError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		DerSignature::try_from(bytes).map(Self)
	}
}

impl From<OutsideSignature> for Box<[u8]> {
	fn from(signature: OutsideSignature) -> Self {
		signature.0.to_bytes()
	}
}

impl SignatureEncoding for OutsideSignature {
	type Repr = Box<[u8]>;
}

impl SignatureAlgorithmIdentifier for OutsideSignature {
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_512;
	type Digest = Sha3_512;
}

/// The DER form with a low `s`. It refuses a high `s`, which the house form
/// normalizes.
impl CanonicalForm for OutsideSignature {
	fn canonical(encoded: &[u8]) -> Result<Self, SignatureError> {
		let signature = Signature::from_der(encoded)?;
		let low = signature.normalize_s().is_none();
		low.then(|| Self(signature.to_der())).ok_or_else(SignatureError::new)
	}
}

/// The secp256k1 key that verifies a [`OutsideSignature`].
#[derive(Clone, Debug, PartialEq)]
struct OutsideVerifyingKey(VerifyingKey);

impl PrehashVerifier<OutsideSignature> for OutsideVerifyingKey {
	fn verify_prehash(&self, prehash: &[u8], signature: &OutsideSignature) -> Result<(), SignatureError> {
		self.0.verify_prehash(prehash, &signature.0)
	}
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for OutsideVerifyingKey {
	type Error = tightbeam::spki::Error;

	fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
		VerifyingKey::try_from(spki).map(Self)
	}
}

/// The ECDSA check over the SHA3-512 digest of `message`, as
/// `ecdsa-with-SHA3-512` names it.
impl Verifier<OutsideSignature> for OutsideVerifyingKey {
	fn verify(&self, message: &[u8], signature: &OutsideSignature) -> Result<(), SignatureError> {
		let prehash = Sha3_512::digest(message);
		self.0.verify_prehash(&prehash, &signature.0)
	}
}

/// The key of a point on secp256k1, as a handshake reads it from a
/// certificate.
impl From<PublicKey> for OutsideVerifyingKey {
	fn from(key: PublicKey) -> Self {
		Self(VerifyingKey::from(key))
	}
}

/// The point of the key, lent by reference, which a handshake compares an
/// agreement ephemeral with.
impl AsRef<AffinePoint> for OutsideVerifyingKey {
	fn as_ref(&self) -> &AffinePoint {
		self.0.as_affine()
	}
}

impl EncodePublicKey for OutsideVerifyingKey {
	fn to_public_key_der(&self) -> tightbeam::spki::Result<Document> {
		self.0.to_public_key_der()
	}
}

/// HKDF over SHA3-512 under an identifier of the outside arc, apart from the
/// house HKDF-SHA3-256.
struct OutsideKdf;

impl AssociatedOid for OutsideKdf {
	const OID: ObjectIdentifier = OUTSIDE_KDF;
}

impl KdfFunction for OutsideKdf {
	fn derive_dynamic_key(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
		key_size: usize,
	) -> Result<ZeroizingBytes, KdfError> {
		let mut key = Zeroizing::new(vec![0u8; key_size]);
		let expanded = Hkdf::<Sha3_512>::new(salt, ikm).expand(info, key.as_mut_slice());
		expanded.map_err(KdfError::DerivationFailed)?;
		Ok(key)
	}
}

/// The DHKEM over secp256k1 under HKDF-SHA256 and [`OUTSIDE_KEM_ID`], so its
/// shared secret differs from that of the house KEM.
type OutsideDhKem = DhKem<Secp256k1, HkdfSha256, OUTSIDE_KEM_ID>;

/// The outside KEM: [`OutsideDhKem`], named by an identifier of its own arc.
struct OutsideKem;

impl RecipientKem for OutsideKem {
	const OID: ObjectIdentifier = OUTSIDE_KEM;
	const USAGE: KeyUsages = KeyUsages::KeyAgreement;
	type PublicKey = PublicKey;
	type PrivateKey = dyn DiffieHellman<Secp256k1>;

	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<PublicKey, CertificateValidationError> {
		Ok(PublicKey::try_from(spki)?)
	}

	fn encapsulate(recipient: &PublicKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError> {
		OutsideDhKem::encap_to(recipient, rng)
	}

	fn decapsulate<'a>(
		key: &'a dyn DiffieHellman<Secp256k1>,
		recipient: &'a PublicKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>> {
		OutsideDhKem::decap_through(key, recipient, kemct)
	}
}

/// The profile of [`OutsideProvider`].
#[derive(Debug, Default, Clone, Copy)]
struct OutsideProfile;

impl SecurityProfile for OutsideProfile {
	type Digest = Sha3_512;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = OutsideSignature;
	type Kdf = OutsideKdf;
	type Curve = Secp256k1;
	type KeyWrapOid = Aes128Wrap;
}

/// AES-128-GCM as an outside crate brings it: a cipher type of its own over
/// the house cipher, with its own [`ContentEncryption`] under
/// `GCMParameters`. It seals and opens in place through the house cipher, so
/// a refused buffer stays as it was.
struct OutsideGcm(Aes128Gcm);

impl KeySizeUser for OutsideGcm {
	type KeySize = <Aes128Gcm as KeySizeUser>::KeySize;
}

impl KeyInit for OutsideGcm {
	fn new(key: &Key<Self>) -> Self {
		Self(Aes128Gcm::new(key))
	}
}

impl AeadCore for OutsideGcm {
	type NonceSize = <Aes128Gcm as AeadCore>::NonceSize;
	type TagSize = <Aes128Gcm as AeadCore>::TagSize;
	type CiphertextOverhead = <Aes128Gcm as AeadCore>::CiphertextOverhead;
}

impl AeadInPlace for OutsideGcm {
	fn encrypt_in_place_detached(
		&self,
		nonce: &Nonce<Self>,
		associated_data: &[u8],
		buffer: &mut [u8],
	) -> Result<Tag<Self>, AeadError> {
		self.0.encrypt_in_place_detached(nonce, associated_data, buffer)
	}

	fn decrypt_in_place_detached(
		&self,
		nonce: &Nonce<Self>,
		associated_data: &[u8],
		buffer: &mut [u8],
		tag: &Tag<Self>,
	) -> Result<(), AeadError> {
		self.0.decrypt_in_place_detached(nonce, associated_data, buffer, tag)
	}
}

impl AeadAlgorithm for OutsideGcm {
	type Oid = Aes128GcmOid;
}

/// The `GCMParameters` of RFC 5084 §3.2, with the 16-octet tag of the cipher.
impl ContentEncryption for OutsideGcm {
	fn parameters(nonce: &Nonce<Self>) -> Result<Any, EnvelopeError> {
		let parameters = GcmParameters { aes_nonce: OctetString::new(nonce.as_slice())?, aes_icv_len: 16 };
		Ok(Any::encode_from(&parameters)?)
	}

	fn nonce(parameters: Option<&Any>) -> Result<Nonce<Self>, EnvelopeError> {
		let parameters = parameters.ok_or(EnvelopeError::ContentEncryptionAlgorithm)?;
		let parameters = parameters.decode_as::<GcmParameters>();
		let parameters = parameters.map_err(|_| EnvelopeError::ContentEncryptionAlgorithm)?;
		if parameters.aes_icv_len != 16 {
			return Err(EnvelopeError::TagLength((usize::from(parameters.aes_icv_len), 16).into()));
		}

		let nonce = parameters.aes_nonce.as_bytes().iter().copied();
		Nonce::<Self>::from_exact_iter(nonce).ok_or(EnvelopeError::ContentEncryptionAlgorithm)
	}
}

/// A key wrap an outside crate brings with `wrap` and `unwrap` alone, over
/// the house AES-256 key wrap, so the provided `unwrap_into` serves it.
struct OutsideWrap;

impl KeyWrapAlgorithm for OutsideWrap {
	type Oid = Aes256Wrap;
	type KekSize = U32;

	fn wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>, KeyError> {
		Aes256Wrap::wrap(kek, key)
	}

	fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<ZeroizingBytes, KeyError> {
		Aes256Wrap::unwrap(kek, wrapped)
	}
}

/// The RFC 3394 §4.3 key-encryption key, `000102...1f`.
const RFC_3394_KEK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// The RFC 3394 §4.3 key data, `00112233...ff`.
const RFC_3394_KEY_DATA: &str = "00112233445566778899aabbccddeeff";

/// The RFC 3394 §4.3 ciphertext: the key data under the KEK.
const RFC_3394_4_3: &str = "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7";

/// The provided `unwrap_into` of an outside wrap copies the key its
/// `unwrap` returns into the caller's buffer.
#[test]
fn an_outside_wrap_unwraps_into_a_buffer_of_its_key_size() -> Result<(), KeyError> {
	let mut key = [0u8; 16];
	OutsideWrap::unwrap_into(&unhex(RFC_3394_KEK), &unhex(RFC_3394_4_3), &mut key)?;
	assert_eq!(key.as_slice(), unhex(RFC_3394_KEY_DATA).as_slice());
	Ok(())
}

/// The provided `unwrap_into` refuses a buffer of another size than the key.
#[test]
fn an_outside_wrap_refuses_a_buffer_of_another_size() {
	let mut key = [0u8; 32];
	let refused = OutsideWrap::unwrap_into(&unhex(RFC_3394_KEK), &unhex(RFC_3394_4_3), &mut key);
	let expected = ReceivedExpectedError { received: 32, expected: 16 };
	assert!(matches!(refused, Err(KeyError::WrapLength(found)) if found == expected));
}

/// A provider an outside crate defines: its own signature, KDF, KEM, and
/// AEAD cipher, beside the house AES-128 key wrap.
#[derive(Debug, Default, Clone, Copy)]
struct OutsideProvider {
	profile: OutsideProfile,
}

impl DigestProvider for OutsideProvider {
	type Digest = Sha3_512;
}

impl AeadProvider for OutsideProvider {
	type AeadCipher = OutsideGcm;
}

impl KeyWrapProvider for OutsideProvider {
	type KeyWrap = Aes128Wrap;
}

impl SigningProvider for OutsideProvider {
	type Signature = OutsideSignature;
	type VerifyingKey = OutsideVerifyingKey;
}

impl KdfProvider for OutsideProvider {
	type Kdf = OutsideKdf;
}

impl CurveProvider for OutsideProvider {
	type Curve = Secp256k1;
}

impl CryptoProvider for OutsideProvider {
	type Profile = OutsideProfile;
	type Kem = OutsideKem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The signing backend of an outside identity: it signs under
/// `ecdsa-with-SHA3-512`.
#[derive(Debug)]
struct OutsideKeyProvider {
	key: SigningKey,
}

impl KeyBackend for OutsideKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_512, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.key.verifying_key().to_public_key_der()?.into_vec())
	}
}

impl SigningKeyProvider for OutsideKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<DerSignature, SignatureError> = self.key.sign_prehash(prehash);
		let signed = signed.map(|signature| signature.to_vec()).map_err(KeyError::from);
		Box::pin(async move { signed })
	}
}

impl OutsideKeyProvider {
	/// The outside key provider of `key`.
	fn of(key: SigningKey) -> Self {
		Self { key }
	}
}

/// The key-agreement backend of an outside identity: it holds a secp256k1
/// scalar and runs the Diffie-Hellman product itself, so the scalar stays
/// inside the backend.
struct OutsideAgreementBackend {
	scalar: NonZeroScalar,
}

/// The public key names the backend, and the scalar stays out of the output.
impl core::fmt::Debug for OutsideAgreementBackend {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("OutsideAgreementBackend")
			.field("public_key", &self.public_key())
			.finish_non_exhaustive()
	}
}

impl OutsideAgreementBackend {
	/// The outside key-agreement backend of the scalar of `key`.
	fn of(key: &SigningKey) -> Self {
		Self { scalar: *key.as_nonzero_scalar() }
	}

	/// The public half of the scalar.
	fn public_key(&self) -> PublicKey {
		PublicKey::from_secret_scalar(&self.scalar)
	}
}

impl KeyBackend for OutsideAgreementBackend {
	/// `id-ecPublicKey` on secp256k1, the algorithm of the key the backend
	/// holds.
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		let parameters = Any::encode_from(&CURVE_SECP256K1).ok();
		AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key().to_public_key_der()?.into_vec())
	}
}

/// The x-coordinate of the product of the backend's scalar and the peer
/// point (SEC 1 v2.0 §3.3.1).
impl DiffieHellman<Secp256k1> for OutsideAgreementBackend {
	fn agree<'a>(&'a self, peer: &'a PublicKey) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
		let product = (peer.to_projective() * *self.scalar).to_affine();
		let agreed = SecretSlice::from(product.x().to_vec());
		Box::pin(async move { Ok(agreed) })
	}
}

/// An outside key provider whose signatures carry the high `s`, `n - s`, of
/// the low-`s` signature its key computes.
#[derive(Debug)]
struct HighSKeyProvider(OutsideKeyProvider);

impl KeyBackend for HighSKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.0.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.0.to_public_key_bytes()
	}
}

impl SigningKeyProvider for HighSKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<Signature, SignatureError> = self.0.key.sign_prehash(prehash);
		let high = signed.and_then(|low| Signature::from_scalars(low.r(), -*low.s()));
		let high = high.map(|signature| signature.to_der().to_vec()).map_err(KeyError::from);
		Box::pin(async move { high })
	}
}

/// The identity under [`OutsideProvider`] of `certificate` and its `key`.
pub(crate) fn outside_identity_of(certificate: Certificate, key: SigningKey) -> SigningIdentity {
	let provider = Arc::new(OutsideKeyProvider::of(key));
	let identity = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider);
	identity.expect("the outside key matches its certificate and its algorithm")
}

/// An identity under [`OutsideProvider`], of a fresh key.
fn outside_identity() -> SigningIdentity {
	let key = SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::self_signed(&key);
	outside_identity_of(certificate, key)
}

/// The key-agreement identity under [`OutsideKem`] of `certificate` and its
/// key `key`, behind an [`OutsideAgreementBackend`].
fn outside_agreement_identity_of(certificate: Certificate, key: &SigningKey) -> KeyAgreementIdentity<OutsideKem> {
	let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(OutsideAgreementBackend::of(key));
	let identity = KeyAgreementIdentity::new(certificate, backend);
	identity.expect("the outside backend holds the key of its certificate")
}

/// A key-agreement identity under [`OutsideKem`], of a fresh key, whose
/// certificate asserts `keyAgreement`.
fn outside_agreement_identity() -> KeyAgreementIdentity<OutsideKem> {
	let key = SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::self_signed(&key);
	outside_agreement_identity_of(certificate, &key)
}

/// The recipient under [`OutsideKem`] of `certificate`, admitted for key
/// agreement.
fn outside_recipient(certificate: Certificate) -> KemRecipient<OutsideKem> {
	let admitted = PeerCertificate::<KeyAgreement<OutsideKem>>::parse(certificate, KeyPurposes::HOUSE.server);
	let admitted = admitted.expect("the certificate asserts keyAgreement on a secp256k1 key");
	KemRecipient::from_certificate(admitted).expect("the certificate names its recipient")
}

/// The policy of both endpoints of a handshake under [`OutsideProvider`].
/// The outside profile runs AES-128-GCM, below the default floor of 256-bit
/// keys, so both endpoints opt out of the floor.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn outside_policy() -> ProfilePolicy<OutsideProvider> {
	ProfilePolicy::with_floor(Arc::new(NoStrengthFloor))
}

/// Run the three legs of `client` and `server` of flow `F` under
/// [`OutsideProvider`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
async fn run_legs<F>(
	client: &mut Handshake<Client, F, OutsideProvider>,
	server: &mut Handshake<Server, F, OutsideProvider>,
) where
	F: ClientFlow<OutsideProvider> + ServerFlow<OutsideProvider>,
{
	let opening = client.start().expect("the outside client opens");
	let reply = server.reply(opening).await.expect("the outside server replies");
	let closing = client.respond(reply).await.expect("the outside client closes");
	server.finish(closing).await.expect("the outside server admits the closing");
}

/// [`CONTENT`] sealed under [`OutsideProvider`] to `recipient`.
fn outside_sealed(recipient: Recipient<'_, OutsideKem>) -> AuthEnvelopedData {
	let sealed = AuthEnvelopedData::seal::<OutsideProvider>(recipient, DATA, CONTENT, [], None);
	sealed.expect("the content seals under the outside provider")
}

/// An identity under the outside provider signs a content, and the policy of
/// that provider verifies the signature.
#[tokio::test]
async fn an_outside_identity_signs_under_its_own_algorithm() -> Result<(), Box<dyn std::error::Error>> {
	let identity = outside_identity();
	let content = SignedContent::data(CONTENT);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;

	let policy = ProviderPolicy::<OutsideProvider>::default();
	CmsSigner::verify_with_policy(&signer_info, identity.signing_certificate(), &policy, content)?;
	Ok(())
}

/// A key that declares another algorithm pairs with no outside identity.
#[test]
fn with_provider_refuses_a_key_of_another_algorithm() {
	let key = SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(Secp256k1KeyProvider::from(key));

	let refused = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider);
	assert!(matches!(refused, Err(SignerError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA3_256));
}

/// A frame the outside identity signs verifies under the identity's own
/// policy, the check a gateway runs on a rumor it originates.
#[tokio::test]
async fn an_outside_identity_verifies_its_own_signature() -> Result<(), Box<dyn std::error::Error>> {
	let identity = outside_identity();
	let builder = FrameBuilder::from(Version::V2).with_id(b"outside-rumor").with_order(1696521600);
	let mut frame = builder.with_message(TestMessage::sample(None)).build()?;
	frame.sign_with_provider(&identity).await?;

	frame.verify_under(identity.signing_certificate(), identity.policy())?;
	Ok(())
}

/// A seal to the outside key-agreement identity under a `KEMRecipientInfo`
/// opens under the outside provider, through the outside backend's own
/// Diffie-Hellman product.
#[tokio::test]
async fn an_outside_provider_opens_its_kem_seal() -> Result<(), Box<dyn std::error::Error>> {
	let identity = outside_agreement_identity();
	let sealed = outside_sealed(Recipient::Kem { recipient: identity.recipient(), ukm_label: UKM_LABEL });

	let opener = Opener::Kem { identity: &identity, ukm_label: UKM_LABEL };
	let arrived = sealed.to_der()?;
	let opened = sealed.open::<OutsideProvider>(arrived, &opener, DATA).await?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The pairing constructor refuses an outside backend that holds another key
/// than the certificate it is paired with.
#[test]
fn a_key_agreement_identity_refuses_an_outside_backend_of_another_key() {
	let certificate = TestCertificate::self_signed(&SigningKey::random(&mut OsRng));
	let other = SigningKey::random(&mut OsRng);
	let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(OutsideAgreementBackend::of(&other));

	let refused = KeyAgreementIdentity::<OutsideKem>::new(certificate, backend);
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// The key-agreement use refuses a point in the compact form before the
/// outside KEM reads the key, though the parse of that KEM decodes the form
/// (RFC 5480 §2.2).
#[test]
fn the_key_agreement_use_refuses_a_compact_point_for_an_outside_kem() -> Result<(), Box<dyn std::error::Error>> {
	let key = SigningKey::from_bytes(&KNOWN_RECIPIENT_KEY.into())?;
	let compact = TestCertificate::with_compact_key(TestCertificate::self_signed(&key));

	let refused = PeerCertificate::<KeyAgreement<OutsideKem>>::parse(compact, KeyPurposes::HOUSE.server);
	assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	Ok(())
}

/// A seal under a 16-octet KEK, the key size of AES-128 key wrap, opens under
/// the outside provider.
#[tokio::test]
async fn an_outside_provider_opens_its_kek_seal() -> Result<(), Box<dyn std::error::Error>> {
	let kek = [0x24u8; 16];
	let sealed = outside_sealed(Recipient::Kek { kek: &kek, key_identifier: b"outside" });

	let opener = Opener::Kek { kek: &kek, key_identifier: b"outside" };
	let arrived = sealed.to_der()?;
	let opened = sealed.open::<OutsideProvider>(arrived, &opener, DATA).await?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The outside seal names the algorithms of the outside provider:
/// AES-128-GCM, the outside KEM and KDF, and AES-128 key wrap.
#[test]
fn an_outside_seal_names_its_algorithms() {
	let identity = outside_agreement_identity();
	let sealed = outside_sealed(Recipient::Kem { recipient: identity.recipient(), ukm_label: UKM_LABEL });
	let kem = sealed.kem_recipient();

	let cipher = sealed.auth_encrypted_content_info.content_enc_alg.oid;
	let named = (cipher, kem.kem.oid, kem.kdf.oid, kem.wrap.oid);
	assert_eq!(named, (AES_128_GCM, OUTSIDE_KEM, OUTSIDE_KDF, AES_128_WRAP));
}

/// An outside KEM seal wraps its content key under the KEK that the outside
/// KEM and the outside KDF derive. The seal draws the ephemeral scalar
/// `0x03` × 32 and the `ukm` random `0x04` × 32.
#[test]
fn an_outside_kem_seal_wraps_under_the_outside_derivation() -> Result<(), Box<dyn std::error::Error>> {
	let key = SigningKey::from_bytes(&KNOWN_RECIPIENT_KEY.into())?;
	let recipient = outside_recipient(TestCertificate::self_signed(&key));
	let recipient = Recipient::Kem { recipient: &recipient, ukm_label: UKM_LABEL };
	let mut rng = SeededStream(0);
	let sealed = AuthEnvelopedData::seal::<OutsideProvider>(recipient, DATA, CONTENT, [], Some(&mut rng))?;

	let kem = sealed.kem_recipient();
	assert_eq!(kem.encrypted_key.as_bytes(), unhex(OUTSIDE_WRAPPED_KEY).as_slice());
	Ok(())
}

/// An outside identity refuses the high `s` its key returns, which the house
/// form would normalize.
#[tokio::test]
async fn an_outside_identity_refuses_a_high_s() -> Result<(), Box<dyn std::error::Error>> {
	let key = SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(HighSKeyProvider(OutsideKeyProvider::of(key)));
	let identity = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider)?;

	let refused = identity.sign_prehash(&[0x5a; 64]).await;
	assert!(matches!(refused, Err(SignerError::Signature(_))));
	Ok(())
}

/// The house provider refuses an outside seal, whose cipher is not its own.
#[tokio::test]
async fn the_house_provider_refuses_an_outside_seal() -> Result<(), Box<dyn std::error::Error>> {
	let kek = [0x24u8; 16];
	let sealed = outside_sealed(Recipient::Kek { kek: &kek, key_identifier: b"outside" });

	let opener = Opener::Kek { kek: &kek, key_identifier: b"outside" };
	let arrived = sealed.to_der()?;
	let refused = sealed.open::<DefaultCryptoProvider>(arrived, &opener, DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentEncryptionAlgorithm)));
	Ok(())
}
