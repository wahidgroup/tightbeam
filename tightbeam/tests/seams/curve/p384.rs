//! The handshake and the rekey run here under NIST P-384, whose arithmetic
//! the `p384` crate holds and whose field is 48 bytes wide.
//!
//! [`P384Provider`] brings these parts of its own:
//!
//! - a signature, ECDSA over P-384 under `ecdsa-with-SHA3-512`, as a [`SigningProvider`],
//! - a signing backend over a P-384 key, as a [`SigningKeyProvider`],
//! - a key-agreement backend, an [`AgreementBackend`] on P-384, as a [`DiffieHellman`] backend,
//! - HKDF-SHA384, the KDF of RFC 9180 §7.2 that DHKEM(P-384) names, as an [`HpkeKdf`], and
//! - a KEM, DHKEM(P-384, HKDF-SHA384), as an [`OutsideKem`] over the generic helpers of [`DhKem`].
//!
//! The house digest SHA3-512, the house AEAD AES-256-GCM, the house key wrap
//! AES-256, and the house KDF HKDF-SHA3-256 complete it.
//!
//! These suites run under it:
//!
//! - a known answer of DHKEM(P-384, HKDF-SHA384) and of its HPKE suite under AES-256-GCM,
//! - both handshake flows, and
//! - an in-band renewal of a multiplexed session over TCP.
//!
//! [`AgreementBackend`]: super::AgreementBackend
//! [`DhKem`]: tightbeam::crypto::hpke::DhKem
//! [`DiffieHellman`]: tightbeam::crypto::key::DiffieHellman
//! [`HpkeKdf`]: tightbeam::crypto::hpke::HpkeKdf

use std::sync::Arc;

use p384::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{AffinePoint, NistP384, PublicKey};
use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::hash::{Digest, Sha3_512};
use tightbeam::crypto::hpke::DhKemSuite;
use tightbeam::crypto::k256::sha2::Sha384;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::profiles::{
	AeadProvider, Aes256Wrap, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, KeyWrapProvider,
	SecurityProfile, SigningProvider,
};
use tightbeam::crypto::sign::{
	CanonicalForm, Error as SignatureError, PrehashSigner, PrehashVerifier, SignatureAlgorithmIdentifier,
	SignatureEncoding, SigningIdentity, Verifier,
};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::oids::{CURVE_NIST_P384, SIGNER_ECDSA_WITH_SHA3_512};
use tightbeam::random::OsRng;
use tightbeam::spki::{
	AlgorithmIdentifierOwned, Document, EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoRef,
};
use tightbeam::testing::unhex;
use tightbeam::utils::marker::MaybeSendFuture;

use super::{
	carried_point, certificate_of, cms_pair, first_record_opened, hpke_pair, identity_of, outside_cms_server,
	KemVector, OutsideCmsServer, OutsideHkdf, OutsideKem, OutsideKemOid, CONTENT, RFC_9180_PLAINTEXT,
};

/// DHKEM(P-384, HKDF-SHA384) in the HPKE KEM registry (RFC 9180 §7.1).
const KEM_DHKEM_P384_HKDF_SHA384: u16 = 0x0011;

/// HKDF-SHA384 in the HPKE KDF registry (RFC 9180 §7.2).
const KDF_HKDF_SHA384: u16 = 0x0002;

/// The known answer of DHKEM(P-384, HKDF-SHA384) and of its HPKE suite under
/// AES-256-GCM.
///
/// The NIST-curve vectors of RFC 9180 cover P-256 and P-521, so the known
/// answer of P-384 comes from an independent DHKEM and HPKE (Python's
/// `cryptography`, `hmac`, and `hashlib`) that reproduces RFC 9180 A.6.1:
///
/// - `skEm` is `SHA-384("tb/test/p384/ephemeral") mod n`, with `n` the order of P-384.
/// - `skRm` is `SHA-384("tb/test/p384/recipient") mod n`.
/// - The `info`, the associated data, and the plaintext are those of the A.6.1 vectors.
/// - `enc` is 97 octets, and the shared secret, `Nsecret`, is 48.
const KNOWN_ANSWER: KemVector = KemVector {
	sk_e: "a7373290734df5d94c389036fe89c4bf00b6f3ebc33ed0646cd6e7478e6cd3405a1831121d1190dc45bbf66503427de8",
	pk_e: "049aef583acdad40d5af01828397c9a98e0866e92ed0c723cfb4462cb06ec56e1e09c4b50a62547c3ac74d95\
		fefab739bdd5d5aa6abfbb74bd8bfad43dd56a5d5c20ab7c7dc2a4dec8b168856c0275b8f413e93a88324e5ebae1f472a272877ab4",
	sk_r: "f4efce81a5f55b400ece86bb9cae8ad33d05481bd23d7cb46028dc1bc8d8a14f92b1d9cf8e23d6f56a00759e8ddb4a10",
	pk_r: "043adf69a3e6c441178c7c29d1f9ce6e2abb66f945d894d142a0d4c60f8e8cfe9f074d6cfb0f7e4034e03481\
		e733db2135a14673b1f6ef2d17b1f15cc6b99c786f3b7af33730edd3d6944b612dd7d7c2a8b24112edc15fc518650bc5084b6e930d",
	shared_secret: "759d134787545a56a077cd65978923883c0f21b3a0eb4d53\
		cd198f05ad6b34042aced4a108227067ada5fe88fdc98423",
	ciphertext: "35c1fcaa2895b46338d605f56b1522d5fc602bd13de0550e20095aaac8a626e0ab248615c8f2e24f82d404041a",
};

/// An ECDSA signature over P-384 under SHA3-512, in DER. SHA3-512 meets the
/// 192-bit strength of the curve (FIPS 186-5 §6.4.1).
#[derive(Clone, Debug)]
struct P384Signature(DerSignature);

impl TryFrom<&[u8]> for P384Signature {
	type Error = SignatureError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		DerSignature::try_from(bytes).map(Self)
	}
}

impl From<P384Signature> for Box<[u8]> {
	fn from(signature: P384Signature) -> Self {
		signature.0.to_bytes()
	}
}

impl SignatureEncoding for P384Signature {
	type Repr = Box<[u8]>;
}

impl SignatureAlgorithmIdentifier for P384Signature {
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_512;
	type Digest = Sha3_512;
}

/// The canonical form is the DER form with `s` in the low half of the order
/// of P-384, and it brings a high `s` into that half (SEC 1 v2.0 §4.1.4).
impl CanonicalForm for P384Signature {
	fn canonical(encoded: &[u8]) -> Result<Self, SignatureError> {
		let signature = Signature::from_der(encoded)?;
		let low = signature.normalize_s().unwrap_or(signature);
		Ok(Self(low.to_der()))
	}
}

/// The P-384 key that verifies a [`P384Signature`].
#[derive(Clone, Debug, PartialEq)]
struct P384VerifyingKey(VerifyingKey);

impl PrehashVerifier<P384Signature> for P384VerifyingKey {
	fn verify_prehash(&self, prehash: &[u8], signature: &P384Signature) -> Result<(), SignatureError> {
		self.0.verify_prehash(prehash, &signature.0)
	}
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for P384VerifyingKey {
	type Error = SpkiError;

	fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
		VerifyingKey::try_from(spki).map(Self)
	}
}

/// The ECDSA check over the SHA3-512 digest of `message`, as
/// `ecdsa-with-SHA3-512` names it.
impl Verifier<P384Signature> for P384VerifyingKey {
	fn verify(&self, message: &[u8], signature: &P384Signature) -> Result<(), SignatureError> {
		let prehash = Sha3_512::digest(message);
		self.0.verify_prehash(&prehash, &signature.0)
	}
}

/// The key of a point on P-384, as a handshake reads it from a certificate.
impl From<PublicKey> for P384VerifyingKey {
	fn from(key: PublicKey) -> Self {
		Self(VerifyingKey::from(key))
	}
}

/// The point of the key, lent by reference, which a handshake compares an
/// agreement ephemeral with.
impl AsRef<AffinePoint> for P384VerifyingKey {
	fn as_ref(&self) -> &AffinePoint {
		self.0.as_affine()
	}
}

impl EncodePublicKey for P384VerifyingKey {
	fn to_public_key_der(&self) -> tightbeam::spki::Result<Document> {
		self.0.to_public_key_der()
	}
}

/// HKDF-SHA384, the KDF `0x0002` of RFC 9180 §7.2, which DHKEM(P-384)
/// derives its shared secret with. `Nh` is 48.
type HkdfSha384 = OutsideHkdf<Sha384, KDF_HKDF_SHA384>;

/// The P-384 KEM of the outside arc.
impl OutsideKemOid for NistP384 {
	const KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.4");
}

/// DHKEM(P-384, HKDF-SHA384), the KEM of RFC 9180 §7.1 that
/// [`KEM_DHKEM_P384_HKDF_SHA384`] names.
type P384Kem = OutsideKem<NistP384, HkdfSha384, KEM_DHKEM_P384_HKDF_SHA384>;

/// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, and AES-256-GCM.
type P384Suite = DhKemSuite<NistP384, HkdfSha384, Aes256Gcm, KEM_DHKEM_P384_HKDF_SHA384>;

/// The profile of [`P384Provider`].
#[derive(Debug, Default, Clone, Copy)]
struct P384Profile;

impl SecurityProfile for P384Profile {
	type Digest = Sha3_512;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = P384Signature;
	type Kdf = HkdfSha3_256;
	type Curve = NistP384;
	type KeyWrapOid = Aes256Wrap;
}

/// A provider an outside crate defines on P-384: its own signature and KEM,
/// beside the house digest, AEAD, key wrap, and KDF.
#[derive(Debug, Default, Clone, Copy)]
struct P384Provider {
	profile: P384Profile,
}

impl DigestProvider for P384Provider {
	type Digest = Sha3_512;
}

impl AeadProvider for P384Provider {
	type AeadCipher = Aes256Gcm;
}

impl KeyWrapProvider for P384Provider {
	type KeyWrap = Aes256Wrap;
}

impl SigningProvider for P384Provider {
	type Signature = P384Signature;
	type VerifyingKey = P384VerifyingKey;
}

impl KdfProvider for P384Provider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for P384Provider {
	type Curve = NistP384;
}

impl CryptoProvider for P384Provider {
	type Profile = P384Profile;
	type Kem = P384Kem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The signing backend of a P-384 identity: it signs under
/// `ecdsa-with-SHA3-512`.
#[derive(Debug)]
struct P384KeyProvider {
	key: SigningKey,
}

impl KeyBackend for P384KeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_512, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.key.verifying_key().to_public_key_der()?.into_vec())
	}
}

impl SigningKeyProvider for P384KeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<DerSignature, SignatureError> = self.key.sign_prehash(prehash);
		let signed = signed.map(|signature| signature.to_vec()).map_err(KeyError::from);
		Box::pin(async move { signed })
	}
}

/// An identity under [`P384Provider`], of a fresh key.
fn p384_identity() -> SigningIdentity {
	let key = SigningKey::random(&mut OsRng);
	let point = PublicKey::from(key.verifying_key()).to_encoded_point(false);
	let certificate = certificate_of(CURVE_NIST_P384, point.as_bytes());
	identity_of::<P384Provider>(certificate, Arc::new(P384KeyProvider { key }))
}

/// A CMS server of fresh P-384 keys.
fn p384_cms_server() -> OutsideCmsServer<P384Kem> {
	let key = SigningKey::random(&mut OsRng);
	let point = PublicKey::from(key.verifying_key()).to_encoded_point(false);
	outside_cms_server::<P384Provider>("p384 server", Arc::new(P384KeyProvider { key }), point.as_bytes())
}

/// The outside KEM encapsulates to the recipient key of the known answer as
/// the known answer does: `enc` is the 97-octet `pkEm` of the scalar it
/// draws, and the shared secret is the 48-octet one.
#[test]
fn the_p384_kem_encapsulates_its_known_answer() -> Result<(), Box<dyn std::error::Error>> {
	let encapsulated = KNOWN_ANSWER.encapsulated_by::<NistP384, P384Kem>()?;
	assert_eq!(encapsulated, KNOWN_ANSWER.encapsulation());
	Ok(())
}

/// The outside KEM decapsulates `enc` of the known answer through the
/// backend of the recipient scalar, whose agreement is 48 octets, to the
/// known shared secret.
#[tokio::test]
async fn the_p384_kem_decapsulates_its_known_answer() -> Result<(), Box<dyn std::error::Error>> {
	let shared = KNOWN_ANSWER.decapsulated_by::<NistP384, P384Kem>().await?;
	assert_eq!(shared, unhex(KNOWN_ANSWER.shared_secret));
	Ok(())
}

/// The HPKE suite of P-384 seals the plaintext at sequence number zero to
/// `enc` and the known ciphertext.
#[test]
fn the_p384_hpke_suite_seals_its_known_answer() -> Result<(), Box<dyn std::error::Error>> {
	let sealed = KNOWN_ANSWER.sealed_by::<P384Suite>()?;
	assert_eq!(sealed, KNOWN_ANSWER.message());
	Ok(())
}

/// The HPKE suite of P-384 parses the 97-octet `enc` of the known answer and
/// opens its ciphertext under the recipient scalar.
#[test]
fn the_p384_hpke_suite_opens_its_known_answer() -> Result<(), Box<dyn std::error::Error>> {
	let opened = KNOWN_ANSWER.opened_by::<P384Suite>()?;
	assert_eq!(opened, unhex(RFC_9180_PLAINTEXT));
	Ok(())
}

/// The HPKE flow runs under the P-384 provider, and the client's first
/// record opens under the server's session keys.
#[tokio::test]
async fn a_p384_provider_runs_the_hpke_flow() -> Result<(), Box<dyn std::error::Error>> {
	let opened = first_record_opened(hpke_pair::<P384Provider>(p384_identity())).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The hello of a P-384 client carries `R` as a point of P-384 in the
/// compressed form, 49 octets.
#[test]
fn a_p384_hello_carries_a_compressed_p384_point() -> Result<(), Box<dyn std::error::Error>> {
	let (carried, compressed) = carried_point::<P384Provider>(p384_identity())?;
	assert_eq!(carried, compressed);
	Ok(())
}

/// The CMS flow runs under the P-384 provider, with a key-agreement backend
/// on P-384 behind the outside KEM, and the client's first record opens
/// under the server's session keys.
#[tokio::test]
async fn a_p384_provider_runs_the_cms_flow() -> Result<(), Box<dyn std::error::Error>> {
	let opened = first_record_opened(cms_pair::<P384Provider>(p384_cms_server(), p384_identity())).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// A session under the P-384 provider renews its epoch in band, so the
/// client holds an epoch receipt other than the receipt of its handshake.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn a_p384_session_renews_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
	let renewed = super::renewal::renews_its_epoch::<P384Provider>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}
