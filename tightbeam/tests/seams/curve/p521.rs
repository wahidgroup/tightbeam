//! The handshake and the rekey run here under NIST P-521, whose arithmetic
//! the `p521` crate holds and whose field is 66 bytes wide.
//!
//! [`P521Provider`] brings these parts of its own:
//!
//! - a signature, ECDSA over P-521 under `ecdsa-with-SHA3-512`, as a [`SigningProvider`],
//! - a signing backend over a P-521 key, as a [`SigningKeyProvider`],
//! - a key-agreement backend, an [`AgreementBackend`] on P-521, as a [`DiffieHellman`] backend,
//! - HKDF-SHA512, the KDF of RFC 9180 §7.2 that DHKEM(P-521) names, as an [`HpkeKdf`], and
//! - a KEM, DHKEM(P-521, HKDF-SHA512), as an [`OutsideKem`] over the generic helpers of [`DhKem`].
//!
//! The house digest SHA3-512, the house AEAD AES-256-GCM, the house key wrap
//! AES-256, and the house KDF HKDF-SHA3-256 complete it.
//!
//! These suites run under it:
//!
//! - RFC 9180 Appendix A.6.1, through the outside KEM and the HPKE suite of P-521,
//! - both handshake flows, and
//! - an in-band renewal of a multiplexed session over TCP.
//!
//! [`AgreementBackend`]: super::AgreementBackend
//! [`DhKem`]: tightbeam::crypto::hpke::DhKem
//! [`DiffieHellman`]: tightbeam::crypto::key::DiffieHellman
//! [`HpkeKdf`]: tightbeam::crypto::hpke::HpkeKdf

use core::fmt::{Debug, Formatter};
use std::sync::Arc;

use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;
use p521::ecdsa::{Signature, SigningKey, VerifyingKey};
use p521::elliptic_curve::sec1::ToEncodedPoint;
use p521::{NistP521, PublicKey};
use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::exchange::Ecdhe;
use tightbeam::crypto::hash::{Digest, Sha3_512};
use tightbeam::crypto::hpke::DhKemSuite;
use tightbeam::crypto::k256::sha2::Sha512;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::profiles::{
	AeadProvider, Aes256Wrap, CryptoProvider, DigestProvider, KdfProvider, KeyExchangeProvider, KeyWrapProvider,
	SecurityProfile, SecurityProfileDesc, SigningProvider,
};
use tightbeam::crypto::sign::{
	CanonicalForm, Error as SignatureError, PrehashVerifier, SignatureAlgorithmIdentifier, SignatureEncoding,
	SigningIdentity, Verifier,
};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::Encode;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::oids::{CURVE_NIST_P521, SIGNER_ECDSA_WITH_SHA3_512};
use tightbeam::random::OsRng;
use tightbeam::spki::{
	AlgorithmIdentifierOwned, Document, EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoRef,
};
use tightbeam::testing::unhex;

use super::{
	carried_point, certificate_of, cms_pair, first_record_opened, hpke_pair, identity_of, outside_cms_server,
	AgreementBackend, KemVector, OutsideCmsServer, OutsideHkdf, OutsideKem, OutsideKemOid, CONTENT, RFC_9180_PLAINTEXT,
};

/// DHKEM(P-521, HKDF-SHA512) in the HPKE KEM registry (RFC 9180 §7.1).
const KEM_DHKEM_P521_HKDF_SHA512: u16 = 0x0012;

/// HKDF-SHA512 in the HPKE KDF registry (RFC 9180 §7.2).
const KDF_HKDF_SHA512: u16 = 0x0003;

/// RFC 9180 A.6.1 and A.6.1.1: `enc` is 133 octets, and the shared secret,
/// `Nsecret`, is 64.
const RFC_9180_A_6_1: KemVector = KemVector {
	sk_e: "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8\
		569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b",
	pk_e: "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900a\
		aeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ec\
		e2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0\
		692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29\
		b0",
	sk_r: "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c27196\
		a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b2462847",
	pk_r: "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba0f\
		7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580e6\
		61012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b\
		57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec\
		64",
	shared_secret: "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336fe\
		f33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818",
	ciphertext: "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200a\
		afcc6d80ea4c795a7c5b841a",
};

/// An ECDSA signature over P-521 under SHA3-512.
#[derive(Clone, Debug)]
struct P521Signature(Signature);

/// The DER form, which [`CanonicalForm`] reads.
impl TryFrom<&[u8]> for P521Signature {
	type Error = SignatureError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Signature::from_der(bytes).map(Self)
	}
}

/// The DER form of the signature.
impl From<P521Signature> for Box<[u8]> {
	fn from(signature: P521Signature) -> Self {
		signature.0.to_der().to_bytes()
	}
}

impl SignatureEncoding for P521Signature {
	type Repr = Box<[u8]>;
}

impl SignatureAlgorithmIdentifier for P521Signature {
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_512;
	type Digest = Sha3_512;
}

/// The canonical form is the DER form with `s` in the low half of the order
/// of P-521, and it brings a high `s` into that half (SEC 1 v2.0 §4.1.4).
impl CanonicalForm for P521Signature {
	fn canonical(encoded: &[u8]) -> Result<Self, SignatureError> {
		let signature = Signature::from_der(encoded)?;
		let low = signature.normalize_s().unwrap_or(signature);
		Ok(Self(low))
	}
}

/// The P-521 key that verifies a [`P521Signature`], held as its point.
#[derive(Clone, Debug, PartialEq)]
struct P521VerifyingKey(PublicKey);

impl PrehashVerifier<P521Signature> for P521VerifyingKey {
	fn verify_prehash(&self, prehash: &[u8], signature: &P521Signature) -> Result<(), SignatureError> {
		let verifier = VerifyingKey::from_affine(*self.0.as_affine())?;
		verifier.verify_prehash(prehash, &signature.0)
	}
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for P521VerifyingKey {
	type Error = SpkiError;

	fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
		PublicKey::try_from(spki).map(Self)
	}
}

/// The ECDSA check over the SHA3-512 digest of `message`, as
/// `ecdsa-with-SHA3-512` names it.
impl Verifier<P521Signature> for P521VerifyingKey {
	fn verify(&self, message: &[u8], signature: &P521Signature) -> Result<(), SignatureError> {
		let prehash = Sha3_512::digest(message);
		self.verify_prehash(&prehash, signature)
	}
}

impl EncodePublicKey for P521VerifyingKey {
	fn to_public_key_der(&self) -> tightbeam::spki::Result<Document> {
		self.0.to_public_key_der()
	}
}

/// HKDF-SHA512, the KDF `0x0003` of RFC 9180 §7.2, which DHKEM(P-521)
/// derives its shared secret with. `Nh` is 64.
type HkdfSha512 = OutsideHkdf<Sha512, KDF_HKDF_SHA512>;

/// The P-521 KEM of the outside arc.
impl OutsideKemOid for NistP521 {
	const KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.5");
}

/// DHKEM(P-521, HKDF-SHA512), the KEM of RFC 9180 §7.1 that
/// [`KEM_DHKEM_P521_HKDF_SHA512`] names.
type P521Kem = OutsideKem<NistP521, HkdfSha512, KEM_DHKEM_P521_HKDF_SHA512>;

/// The HPKE suite of RFC 9180 A.6: DHKEM(P-521, HKDF-SHA512), HKDF-SHA512,
/// and AES-256-GCM.
type P521Suite = DhKemSuite<NistP521, HkdfSha512, Aes256Gcm, KEM_DHKEM_P521_HKDF_SHA512>;

/// The profile of [`P521Provider`].
#[derive(Debug, Default, Clone, Copy)]
struct P521Profile;

impl SecurityProfile for P521Profile {
	type Digest = Sha3_512;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = P521Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<NistP521>;
	type KeyWrapOid = Aes256Wrap;
}

/// A provider an outside crate defines on P-521: its own signature and KEM,
/// beside the house digest, AEAD, key wrap, and KDF.
#[derive(Debug, Default, Clone, Copy)]
struct P521Provider {
	profile: P521Profile,
}

impl DigestProvider for P521Provider {
	type Digest = Sha3_512;
}

impl AeadProvider for P521Provider {
	type AeadCipher = Aes256Gcm;
}

impl KeyWrapProvider for P521Provider {
	type KeyWrap = Aes256Wrap;
}

impl SigningProvider for P521Provider {
	type Signature = P521Signature;
	type VerifyingKey = P521VerifyingKey;
}

impl KdfProvider for P521Provider {
	type Kdf = HkdfSha3_256;
}

impl KeyExchangeProvider for P521Provider {
	type KeyExchange = Ecdhe<NistP521>;
}

impl CryptoProvider for P521Provider {
	type Profile = P521Profile;
	type Kem = P521Kem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The signing backend of a P-521 identity: it signs under
/// `ecdsa-with-SHA3-512`, with a nonce from the OS random source.
struct P521KeyProvider {
	key: SigningKey,
}

/// The public key names the backend, and the scalar stays out of the output.
impl Debug for P521KeyProvider {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("P521KeyProvider")
			.field("public_key", &self.public_key())
			.finish_non_exhaustive()
	}
}

impl P521KeyProvider {
	/// The public half of the key.
	fn public_key(&self) -> PublicKey {
		PublicKey::from_secret_scalar(self.key.as_nonzero_scalar())
	}
}

impl KeyBackend for P521KeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_512, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key().to_public_key_der()?.into_vec())
	}
}

impl SigningKeyProvider for P521KeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<Signature, SignatureError> = self.key.sign_prehash_with_rng(&mut OsRng, prehash);
		let signed = signed.map(|signature| signature.to_der().to_vec()).map_err(KeyError::from);
		Box::pin(async move { signed })
	}
}

/// An identity under [`P521Provider`], of a fresh key.
fn p521_identity() -> SigningIdentity {
	let backend = P521KeyProvider { key: SigningKey::random(&mut OsRng) };
	let point = backend.public_key().to_encoded_point(false);
	let certificate = certificate_of(CURVE_NIST_P521, point.as_bytes());
	identity_of::<P521Provider>(certificate, Arc::new(backend))
}

/// A CMS server of fresh P-521 keys.
fn p521_cms_server() -> OutsideCmsServer<P521Kem> {
	let signer = P521KeyProvider { key: SigningKey::random(&mut OsRng) };
	let point = signer.public_key().to_encoded_point(false);
	let backend = AgreementBackend::random();
	outside_cms_server::<P521Provider, _>("p521 server", Arc::new(signer), CURVE_NIST_P521, point.as_bytes(), backend)
}

/// The outside KEM encapsulates to the recipient key of RFC 9180 A.6.1 as
/// the vector does: `enc` is the 133-octet `pkEm` of the scalar it draws,
/// and the shared secret is the 64-octet one it publishes.
#[test]
fn the_p521_kem_encapsulates_as_rfc_9180_a_6_1() -> Result<(), Box<dyn std::error::Error>> {
	let encapsulated = RFC_9180_A_6_1.encapsulated_by::<NistP521, P521Kem>()?;
	assert_eq!(encapsulated, RFC_9180_A_6_1.encapsulation());
	Ok(())
}

/// The outside KEM decapsulates `enc` of RFC 9180 A.6.1 through the backend
/// of the recipient scalar, whose agreement is 66 octets, to the published
/// shared secret.
#[tokio::test]
async fn the_p521_kem_decapsulates_rfc_9180_a_6_1() -> Result<(), Box<dyn std::error::Error>> {
	let shared = RFC_9180_A_6_1.decapsulated_by::<NistP521, P521Kem>().await?;
	assert_eq!(shared, unhex(RFC_9180_A_6_1.shared_secret));
	Ok(())
}

/// The HPKE suite of P-521 seals the plaintext of RFC 9180 A.6.1.1 at
/// sequence number zero to `enc` and the published ciphertext.
#[test]
fn the_p521_hpke_suite_seals_as_rfc_9180_a_6_1_1() -> Result<(), Box<dyn std::error::Error>> {
	let sealed = RFC_9180_A_6_1.sealed_by::<P521Suite>()?;
	assert_eq!(sealed, RFC_9180_A_6_1.message());
	Ok(())
}

/// The HPKE suite of P-521 parses the 133-octet `enc` of RFC 9180 A.6.1.1
/// and opens its ciphertext at sequence number zero under the recipient
/// scalar.
#[test]
fn the_p521_hpke_suite_opens_rfc_9180_a_6_1_1() -> Result<(), Box<dyn std::error::Error>> {
	let opened = RFC_9180_A_6_1.opened_by::<P521Suite>()?;
	assert_eq!(opened, unhex(RFC_9180_PLAINTEXT));
	Ok(())
}

/// The HPKE flow runs under the P-521 provider, and the client's first
/// record opens under the server's session keys.
#[tokio::test]
async fn a_p521_provider_runs_the_hpke_flow() -> Result<(), Box<dyn std::error::Error>> {
	let opened = first_record_opened(hpke_pair::<P521Provider>(p521_identity())).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The hello of a P-521 client carries `R` as a point of P-521 in the
/// compressed form, 67 octets.
#[test]
fn a_p521_hello_carries_a_compressed_p521_point() -> Result<(), Box<dyn std::error::Error>> {
	let (carried, compressed) = carried_point::<P521Provider, _>(p521_identity())?;
	assert_eq!(carried, compressed);
	Ok(())
}

/// The CMS flow runs under the P-521 provider, with a key-agreement backend
/// on P-521 behind the outside KEM, and the client's first record opens
/// under the server's session keys.
#[tokio::test]
async fn a_p521_provider_runs_the_cms_flow() -> Result<(), Box<dyn std::error::Error>> {
	let opened = first_record_opened(cms_pair::<P521Provider>(p521_cms_server(), p521_identity())).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// A session under the P-521 provider renews its epoch in band, so the
/// client holds an epoch receipt other than the receipt of its handshake.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn a_p521_session_renews_its_epoch() -> Result<(), Box<dyn std::error::Error>> {
	let renewed = super::renewal::renews_its_epoch::<P521Provider>(p521_identity).await?;
	assert!(renewed);
	Ok(())
}

/// The DER of the descriptor of [`P521Profile`].
const P521_DESCRIPTOR: &str = "304ca00b060960864801650304020aa10b060960864801650304012ea20b060960864801650304030ca3\
	0d060b2a864886f70d0109100321a40706052b81040023a50b060960864801650304012d";

/// The descriptor of [`P521Profile`] encodes as [`P521_DESCRIPTOR`].
#[test]
fn the_p521_descriptor_encodes_as_its_known_der() -> Result<(), Box<dyn std::error::Error>> {
	let der = SecurityProfileDesc::from(&P521Profile).to_der()?;
	assert_eq!(der, unhex(P521_DESCRIPTOR));
	Ok(())
}
