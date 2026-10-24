//! HPKE (Hybrid Public Key Encryption), the base mode of [RFC 9180][rfc9180].
//!
//! A sender seals a message to a recipient's public key, and the holder of the
//! private key opens it. This module implements the single-shot API of
//! [RFC 9180 §6.1][rfc9180-6.1] over a DH-based KEM ([§4.1][rfc9180-4.1]).
//!
//! # Suite
//!
//! An [`HpkeSuite`] names the three algorithms of [RFC 9180 §7][rfc9180-7]:
//!
//! - The KEM is a DHKEM on a curve with a 32-byte field, with a KDF of its own.
//! - The KDF runs the key schedule.
//! - The AEAD seals the message.
//!
//! [`HpkeSecp256k1Sha256Aes256Gcm`] is the house suite, the registered one:
//! DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM. A suite is a
//! type parameter, so an implementor brings its own suite to every operation.
//!
//! # Operations
//!
//! **Seal** ([`HpkePublicKeyOps::seal`]), with `pkR` the recipient public key:
//!
//! 1. Draw an ephemeral key pair `(skE, pkE)`, which serves this one message.
//! 2. Compute `dh = DH(skE, pkR)`, and set `enc` to `pkE` in uncompressed SEC1 form.
//! 3. Derive `shared_secret = ExtractAndExpand(dh, enc || pkR)` under the KDF of the KEM.
//! 4. Derive `key` and `base_nonce` from `shared_secret` and `info` under the KDF of the suite.
//! 5. Seal `ct = AEAD.Seal(key, base_nonce, aad, pt)`.
//! 6. Output `enc || ct`.
//!
//! **Open** ([`HpkeSecretKeyOps::open`]) computes `dh = DH(skR, pkE)`, runs
//! steps 3 and 4, and opens `ct` with `AEAD.Open`. [`EcdhSecret::open`] starts
//! from a `dh` that a key provider computed.
//!
//! Every derivation is labeled with `"HPKE-v1"` and a `suite_id`
//! ([RFC 9180 §4][rfc9180-4]). The KEM binds its own identifier, and the key
//! schedule binds all three, so two suites derive unrelated keys from one `dh`.
//!
//! # Identifiers
//!
//! [RFC 9180 §7][rfc9180-7] gives each KEM, KDF, and AEAD a 16-bit identifier
//! from an [IANA registry][iana-hpke].
//!
//! - Every identifier of the house suite is registered: KEM `0x0016`, KDF `0x0001`, and AEAD `0x0002`.
//! - The identifiers enter the labels of every derivation, so another value derives other keys.
//! - The KEM `0x0016` is DHKEM(secp256k1, HKDF-SHA256)
//!   ([draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby]): `Nsecret` is 32, and
//!   `Nenc`, `Npk`, and `Nsk` are 65, 65, and 32.
//! - [`DhKemSecp256k1`] is that registered KEM under [`HkdfSha256`], as a KEM
//!   alone. A CMS `KEMRecipientInfo` derives its key from its shared secret.
//!
//! ## Frames
//!
//! [`HpkeEncryptor`] and [`HpkeDecryptor`] seal and open a frame to a
//! recipient key as an `AuthEnvelopedData` with a `KEMRecipientInfo`
//! (RFC 9629), under the KEM, the KDF, the key wrap, and the AEAD of a
//! provider.
//!
//! # Sources
//!
//! - [RFC 9180][rfc9180]: Hybrid Public Key Encryption.
//! - [RFC 5869][rfc5869]: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//! - [draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby]: a secp256k1-based DHKEM for HPKE.
//! - [IANA HPKE registry][iana-hpke]: the KEM, KDF, and AEAD identifiers.
//!
//! [rfc9180]: https://datatracker.ietf.org/doc/html/rfc9180
//! [rfc9180-4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
//! [rfc9180-4.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
//! [rfc9180-6.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-6.1
//! [rfc9180-7]: https://datatracker.ietf.org/doc/html/rfc9180#section-7
//! [rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
//! [wahby]: https://datatracker.ietf.org/doc/html/draft-wahby-cfrg-hpke-kem-secp256k1-01
//! [iana-hpke]: https://www.iana.org/assignments/hpke/hpke.xhtml

use core::marker::PhantomData;

#[cfg(all(not(feature = "std"), feature = "x509", feature = "signature", feature = "ecdh"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "x509", feature = "signature", feature = "ecdh"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", feature = "x509", feature = "signature", feature = "ecdh"))]
use std::sync::Arc;

use crate::constants::EC_PUBKEY_UNCOMPRESSED_SIZE;
use crate::crypto::aead::{Aead, AeadCore, Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Payload};
use crate::crypto::common::typenum::{Unsigned, U32};
use crate::crypto::common::KeySizeUser;
use crate::crypto::hkdf::InvalidLength;
use crate::crypto::k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use crate::crypto::k256::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::crypto::k256::sha2::Sha256;
use crate::crypto::k256::Secp256k1;
use crate::crypto::kdf::{EcdhSecret, KdfError, ZeroizingHkdf};
use crate::crypto::secret::{Secret, SecretSlice};
use crate::random::{CryptoRngCore, OsRng, RngWrapper};
use crate::zeroize::{Zeroize, Zeroizing};
use crate::Errorizable;
use crate::ZeroizingBytes;

#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::asn1::{AuthEnvelopedData, ObjectIdentifier};
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::constants::TIGHTBEAM_FRAME_UKM_LABEL;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::aead::{AeadAlgorithm, CheckedContent, Decryptor, Encryptor};
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::cms::{
	ContentEncryption, Encapsulation, EnvelopeError, KemKeyHolder, KemRecipient, Opener, Recipient, RecipientKem,
};
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::key::DiffieHellman;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::profiles::CryptoProvider;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::x509::ext::pkix::KeyUsages;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::crypto::x509::EllipticCurvePoint;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::der::oid::AssociatedOid;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::oids::{DATA, DHKEM_SECP256K1};
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::spki::SubjectPublicKeyInfoRef;
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
use crate::utils::marker::MaybeSendFuture;

/// The label every HPKE derivation leads with ([RFC 9180 §4][rfc9180-4]).
///
/// [rfc9180-4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
const VERSION_LABEL: &[u8] = b"HPKE-v1";

/// `mode_base`, the mode of a context with no pre-shared key and no sender
/// key ([RFC 9180 §5][rfc9180-5], Table 1).
///
/// [rfc9180-5]: https://datatracker.ietf.org/doc/html/rfc9180#section-5
const MODE_BASE: u8 = 0x00;

/// AES-128-GCM in the HPKE AEAD registry ([RFC 9180 §7.3][rfc9180-7.3]).
///
/// [rfc9180-7.3]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.3
pub const AEAD_AES_128_GCM: u16 = 0x0001;

/// AES-256-GCM in the HPKE AEAD registry ([RFC 9180 §7.3][rfc9180-7.3]).
///
/// [rfc9180-7.3]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.3
pub const AEAD_AES_256_GCM: u16 = 0x0002;

/// DHKEM(secp256k1, HKDF-SHA256) in the HPKE KEM registry
/// ([draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby]).
///
/// [wahby]: https://datatracker.ietf.org/doc/html/draft-wahby-cfrg-hpke-kem-secp256k1-01
pub const KEM_DHKEM_SECP256K1_HKDF_SHA256: u16 = 0x0016;

/// HKDF-SHA256 in the HPKE KDF registry ([RFC 9180 §7.2][rfc9180-7.2]).
///
/// [rfc9180-7.2]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.2
pub const KDF_HKDF_SHA256: u16 = 0x0001;

/// A two-stage key derivation function of an HPKE suite
/// ([RFC 9180 §4][rfc9180-4]).
///
/// The contract of an implementation is to wipe each copy of the key
/// material it holds, once a derivation ends, as
/// [`KdfFunction`](crate::crypto::kdf::KdfFunction) states.
///
/// [rfc9180-4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
pub trait HpkeKdf {
	/// The identifier of this KDF in the HPKE KDF registry.
	const KDF_ID: u16;

	/// `Nh`, the size in bytes of an [`Self::extract`] output.
	const EXTRACT_SIZE: usize;

	/// `Extract(salt, ikm)`: a pseudorandom key of `Nh` bytes.
	fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes;

	/// `Expand(prk, info, L)`: `len` bytes of output keying material.
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] -- `prk` is shorter than `Nh`, or `len` is past the KDF's bound.
	fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError>;
}

/// HKDF-SHA256 ([RFC 5869][rfc5869]), the KDF of the registered DHKEM on
/// secp256k1.
///
/// The pseudorandom key, each output block, and each input that the hash
/// buffers wipe on drop. The SHA-256 core of `sha2` 0.10.9 holds its
/// chaining state in plain words with private fields, so that state drops as
/// it is.
///
/// [rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
pub struct HkdfSha256;

impl HpkeKdf for HkdfSha256 {
	const KDF_ID: u16 = KDF_HKDF_SHA256;

	const EXTRACT_SIZE: usize = 32;

	fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
		let prk = ZeroizingHkdf::<Sha256>::extract(salt, ikm);
		Zeroizing::new(prk.as_slice().to_vec())
	}

	fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
		let keyed = ZeroizingHkdf::<Sha256>::from_prk(prk);
		let keyed = keyed.map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
		let mut okm = Zeroizing::new(vec![0u8; len]);
		keyed.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;
		Ok(okm)
	}
}

/// An AEAD of an HPKE suite and its identifier
/// ([RFC 9180 §7.3][rfc9180-7.3]).
///
/// The cipher type is the one home of the identifier, so a suite that seals
/// with this cipher labels its derivations with this value.
///
/// [rfc9180-7.3]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.3
pub trait HpkeAead: Aead + KeyInit {
	/// The identifier of this AEAD in the HPKE AEAD registry.
	const AEAD_ID: u16;
}

impl HpkeAead for Aes128Gcm {
	const AEAD_ID: u16 = AEAD_AES_128_GCM;
}

impl HpkeAead for Aes256Gcm {
	const AEAD_ID: u16 = AEAD_AES_256_GCM;
}

/// An HPKE ciphersuite: a DHKEM, a KDF, and an AEAD
/// ([RFC 9180 §7][rfc9180-7]).
///
/// The three identifiers come from the algorithm types and enter every key
/// schedule, so a suite is the type both peers MUST agree on for a message to
/// open.
///
/// [rfc9180-7]: https://datatracker.ietf.org/doc/html/rfc9180#section-7
pub trait HpkeSuite {
	/// The curve of the DHKEM. Its field is 32 bytes wide, so a DH output is
	/// 32 bytes and an encapsulated key is 65.
	type Curve: Curve<FieldBytesSize = U32>
		+ CurveArithmetic<AffinePoint: FromEncodedPoint<Self::Curve> + ToEncodedPoint<Self::Curve>>;

	/// The KDF of the DHKEM, which derives the KEM shared secret. `Nsecret`
	/// is its `Nh`.
	type KemKdf: HpkeKdf;

	/// The identifier of the DHKEM in the HPKE KEM registry
	/// ([RFC 9180 §7.1][rfc9180-7.1]).
	///
	/// [rfc9180-7.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1
	const KEM_ID: u16;

	/// The KDF of the key schedule.
	type Kdf: HpkeKdf;

	/// The AEAD that seals the message.
	type Aead: HpkeAead;
}

/// The suite of the DHKEM `KEM_ID` on curve `C` under KDF `K`, the same KDF
/// for the key schedule, and AEAD `A`.
pub struct DhKemSuite<C, K, A, const KEM_ID: u16>(PhantomData<(C, K, A)>);

impl<C, K, A, const KEM_ID: u16> HpkeSuite for DhKemSuite<C, K, A, KEM_ID>
where
	C: Curve<FieldBytesSize = U32> + CurveArithmetic,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	K: HpkeKdf,
	A: HpkeAead,
{
	type Curve = C;
	type KemKdf = K;
	type Kdf = K;
	type Aead = A;

	const KEM_ID: u16 = KEM_ID;
}

/// DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM: the
/// registered suite (KEM `0x0016`, KDF `0x0001`, AEAD `0x0002`), and the house
/// one.
pub type HpkeSecp256k1Sha256Aes256Gcm = DhKemSuite<Secp256k1, HkdfSha256, Aes256Gcm, KEM_DHKEM_SECP256K1_HKDF_SHA256>;

/// An error from an HPKE operation.
#[derive(Errorizable, Debug, Clone)]
pub enum HpkeError {
	/// The message has an invalid format or length.
	#[error("Invalid HPKE message format")]
	InvalidCiphertext,

	/// The public key bytes fail to decode.
	#[error("Invalid HPKE public key: {0}")]
	InvalidPublicKey(crate::crypto::k256::elliptic_curve::Error),

	/// The secret key bytes fail to decode.
	#[error("Invalid HPKE secret key: {0}")]
	InvalidSecretKey(crate::crypto::k256::elliptic_curve::Error),

	/// The AEAD failed to seal.
	#[error("HPKE seal failed: {0}")]
	EncryptionFailed(crate::crypto::aead::Error),

	/// The AEAD failed to open or to verify the tag.
	#[error("HPKE open failed: {0}")]
	DecryptionFailed(crate::crypto::aead::Error),

	/// A KDF refused a derivation, or the AEAD refused the derived key.
	#[error("HPKE key derivation failed: {0}")]
	Kdf(KdfError),
}

crate::impl_from!(KdfError => HpkeError::Kdf);

/// The result of an HPKE operation.
pub type Result<T> = core::result::Result<T, HpkeError>;

/// The labeled derivations of one scope ([RFC 9180 §4][rfc9180-4]).
///
/// Each derivation binds the `suite_id` of its scope, so the KEM and the key
/// schedule of one suite are separated from each other and from every other
/// suite.
///
/// [rfc9180-4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
struct Labeled<K> {
	suite_id: Vec<u8>,
	kdf: PhantomData<K>,
}

impl<K: HpkeKdf> Labeled<K> {
	/// The scope of the DHKEM `kem_id` that derives with `K`, whose
	/// `suite_id` is `"KEM" || I2OSP(kem_id, 2)`
	/// ([RFC 9180 §4.1][rfc9180-4.1]).
	///
	/// [rfc9180-4.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
	fn kem(kem_id: u16) -> Self {
		let kem_id = kem_id.to_be_bytes();
		let suite_id = [b"KEM".as_slice(), &kem_id].concat();
		Self { suite_id, kdf: PhantomData }
	}

	/// The scope of the key schedule of suite `S`, whose `suite_id` is
	/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`
	/// ([RFC 9180 §5.1][rfc9180-5.1]).
	///
	/// [rfc9180-5.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-5.1
	fn schedule<S>() -> Self
	where
		S: HpkeSuite<Kdf = K>,
	{
		let kem_id = S::KEM_ID.to_be_bytes();
		let kdf_id = K::KDF_ID.to_be_bytes();
		let aead_id = <S::Aead as HpkeAead>::AEAD_ID.to_be_bytes();
		let suite_id = [b"HPKE".as_slice(), &kem_id, &kdf_id, &aead_id].concat();
		Self { suite_id, kdf: PhantomData }
	}

	/// `LabeledExtract(salt, label, ikm)`.
	fn extract(&self, salt: &[u8], label: &[u8], ikm: &[u8]) -> ZeroizingBytes {
		let labeled_ikm = Zeroizing::new([VERSION_LABEL, &self.suite_id, label, ikm].concat());
		K::extract(salt, &labeled_ikm)
	}

	/// `LabeledExpand(prk, label, info, L)`.
	fn expand(&self, prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Result<ZeroizingBytes> {
		let length = u16::try_from(len).map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
		let length = length.to_be_bytes();
		let labeled_info = [length.as_slice(), VERSION_LABEL, &self.suite_id, label, info].concat();
		let okm = K::expand(prk, &labeled_info, len)?;

		// The length is the geometry of the cipher or of the KEM, so a KDF
		// that returns another length fails here rather than at the cipher.
		if okm.len() != len {
			return Err(HpkeError::Kdf(KdfError::DerivationFailed(InvalidLength)));
		}

		Ok(okm)
	}
}

/// The key and the base nonce of a base-mode context
/// ([RFC 9180 §5.1][rfc9180-5.1]).
///
/// A single-shot context seals one message at sequence number zero, so its
/// nonce is the base nonce ([RFC 9180 §5.2][rfc9180-5.2]).
///
/// [rfc9180-5.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-5.1
/// [rfc9180-5.2]: https://datatracker.ietf.org/doc/html/rfc9180#section-5.2
struct KeySchedule<S> {
	key: ZeroizingBytes,
	base_nonce: ZeroizingBytes,
	suite: PhantomData<S>,
}

impl<S: HpkeSuite> KeySchedule<S> {
	/// `KeySchedule(mode_base, shared_secret, info, psk, psk_id)` with the
	/// default, empty `psk` and `psk_id`.
	fn derive(shared_secret: &[u8], info: &[u8]) -> Result<Self> {
		let labeled = Labeled::<S::Kdf>::schedule::<S>();
		let key_size = <S::Aead as KeySizeUser>::KeySize::USIZE;
		let nonce_size = <S::Aead as AeadCore>::NonceSize::USIZE;

		let psk_id_hash = labeled.extract(b"", b"psk_id_hash", b"");
		let info_hash = labeled.extract(b"", b"info_hash", info);
		let context = [[MODE_BASE].as_slice(), &psk_id_hash, &info_hash].concat();

		let secret = labeled.extract(shared_secret, b"secret", b"");
		let key = labeled.expand(&secret, b"key", &context, key_size)?;
		let base_nonce = labeled.expand(&secret, b"base_nonce", &context, nonce_size)?;
		Ok(Self { key, base_nonce, suite: PhantomData })
	}

	/// The AEAD of the suite under the derived key.
	fn cipher(&self) -> Result<S::Aead> {
		let refused = HpkeError::Kdf(KdfError::DerivationFailed(InvalidLength));
		S::Aead::new_from_slice(&self.key).map_err(|_| refused)
	}

	/// `AEAD.Seal(key, base_nonce, aad, pt)`.
	fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
		let cipher = self.cipher()?;
		let nonce = Nonce::<S::Aead>::from_slice(&self.base_nonce);
		let payload = Payload { msg: plaintext, aad };
		cipher.encrypt(nonce, payload).map_err(HpkeError::EncryptionFailed)
	}

	/// `AEAD.Open(key, base_nonce, aad, ct)`.
	fn open(&self, aad: &[u8], ciphertext: &[u8]) -> Result<SecretSlice<u8>> {
		let cipher = self.cipher()?;
		let nonce = Nonce::<S::Aead>::from_slice(&self.base_nonce);
		let payload = Payload { msg: ciphertext, aad };
		let plaintext = cipher.decrypt(nonce, payload).map_err(HpkeError::DecryptionFailed)?;
		Ok(Secret::from(plaintext))
	}
}

/// A sealed HPKE message of suite `S`: the encapsulated key `enc` and the
/// ciphertext `ct`.
///
/// The encoding is `enc || ct`:
///
/// - `enc` is the sender's ephemeral public key in uncompressed SEC1 form, 65 bytes.
/// - `ct` ends with the AEAD tag.
///
/// [`Self::from_bytes`] admits a point on the curve and a ciphertext that
/// carries a tag ([RFC 9180 §7.1.4][rfc9180-7.1.4]), so every DH that follows
/// runs on a validated key.
///
/// [rfc9180-7.1.4]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.4
pub struct HpkeMessage<S: HpkeSuite> {
	/// The encapsulated key, which is the sender's ephemeral public key.
	encapsulated_key: PublicKey<S::Curve>,
	/// The ciphertext and its authentication tag.
	ciphertext: Vec<u8>,
}

impl<S: HpkeSuite> HpkeMessage<S> {
	/// Parse a message from its encoding, `enc || ct`.
	///
	/// # Errors
	///
	/// - [`HpkeError::InvalidCiphertext`] -- `bytes` is shorter than an encapsulated key and an AEAD tag.
	/// - [`HpkeError::InvalidPublicKey`] -- `enc` fails SEC1 decoding, or it is off the curve.
	pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		let bytes = bytes.as_ref();
		let tag_size = <S::Aead as AeadCore>::TagSize::USIZE;
		let split = bytes.split_first_chunk::<EC_PUBKEY_UNCOMPRESSED_SIZE>();
		let (enc, ciphertext) = split.ok_or(HpkeError::InvalidCiphertext)?;
		if ciphertext.len() < tag_size {
			return Err(HpkeError::InvalidCiphertext);
		}

		let parsed = PublicKey::<S::Curve>::from_sec1_bytes(enc);
		let encapsulated_key = parsed.map_err(HpkeError::InvalidPublicKey)?;
		Ok(Self { encapsulated_key, ciphertext: ciphertext.to_vec() })
	}

	/// Encode the message as `enc || ct`.
	pub fn to_bytes(&self) -> Vec<u8> {
		let enc = self.encapsulated_key.to_encoded_point(false);
		[enc.as_bytes(), &self.ciphertext].concat()
	}

	/// The encapsulated key `enc`, which is the sender's ephemeral public key.
	///
	/// A caller that runs the `DH(skR, pkE)` step behind a key provider hands
	/// this key to the provider and opens the message with
	/// [`EcdhSecret::open`].
	pub fn encapsulated_key(&self) -> &PublicKey<S::Curve> {
		&self.encapsulated_key
	}

	/// The ciphertext `ct`, which ends with the AEAD tag.
	pub fn ciphertext(&self) -> &[u8] {
		&self.ciphertext
	}

	/// Seal `plaintext` to `recipient` under `ephemeral` (`Encap`, then
	/// `Seal` at sequence number zero).
	///
	/// The ephemeral is taken by value and dropped here, so it serves this one
	/// message ([RFC 9180 §9.2.3][rfc9180-9.2.3]). The nonce of a single-shot
	/// context is fixed by the key schedule, so a second message under one
	/// ephemeral would repeat it.
	///
	/// [rfc9180-9.2.3]: https://datatracker.ietf.org/doc/html/rfc9180#section-9.2.3
	fn sealed(
		ephemeral: SecretKey<S::Curve>,
		recipient: &PublicKey<S::Curve>,
		info: &[u8],
		aad: &[u8],
		plaintext: &[u8],
	) -> Result<Self> {
		let encapsulated_key = ephemeral.public_key();
		let dh = EcdhSecret::agree(&ephemeral, recipient);
		let shared_secret = dh.kem_shared_secret::<S::Curve, S::KemKdf>(S::KEM_ID, &encapsulated_key, recipient)?;

		let schedule = KeySchedule::<S>::derive(&shared_secret, info)?;
		let ciphertext = schedule.seal(aad, plaintext)?;
		Ok(Self { encapsulated_key, ciphertext })
	}
}

/// HPKE sealing to a recipient public key.
pub trait HpkePublicKeyOps {
	/// The curve of this key.
	type Curve;

	/// Seal `plaintext` to this key under a fresh ephemeral (`SealBase`,
	/// [RFC 9180 §6.1][rfc9180-6.1]).
	///
	/// - `info`: application context that the key schedule binds.
	/// - `aad`: associated data that the AEAD authenticates and leaves in the clear.
	/// - `rng`: the cryptographically secure RNG that draws the ephemeral. `None` uses [`OsRng`].
	///
	/// The ephemeral fixes the key and the nonce, so an RNG that repeats its
	/// stream repeats both.
	///
	/// # Errors
	///
	/// - [`HpkeError::Kdf`] -- a KDF refused a derivation, or the AEAD refused the derived key.
	/// - [`HpkeError::EncryptionFailed`] -- the AEAD refused the plaintext.
	///
	/// [rfc9180-6.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-6.1
	fn seal<S>(
		&self,
		info: impl AsRef<[u8]>,
		aad: impl AsRef<[u8]>,
		plaintext: impl AsRef<[u8]>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<HpkeMessage<S>>
	where
		S: HpkeSuite<Curve = Self::Curve>;
}

impl<C> HpkePublicKeyOps for PublicKey<C>
where
	C: Curve<FieldBytesSize = U32> + CurveArithmetic,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	type Curve = C;

	fn seal<S>(
		&self,
		info: impl AsRef<[u8]>,
		aad: impl AsRef<[u8]>,
		plaintext: impl AsRef<[u8]>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<HpkeMessage<S>>
	where
		S: HpkeSuite<Curve = C>,
	{
		let mut os_rng = OsRng;
		let source = rng.unwrap_or(&mut os_rng);
		let ephemeral = SecretKey::<C>::random(&mut RngWrapper(source));
		HpkeMessage::sealed(ephemeral, self, info.as_ref(), aad.as_ref(), plaintext.as_ref())
	}
}

/// HPKE opening with the recipient secret key.
pub trait HpkeSecretKeyOps {
	/// The curve of this key.
	type Curve;

	/// Open `message` with this key as the recipient (`OpenBase`,
	/// [RFC 9180 §6.1][rfc9180-6.1]).
	///
	/// `info` and `aad` MUST equal the values the sender sealed under.
	///
	/// # Errors
	///
	/// - The errors of [`EcdhSecret::open`].
	///
	/// [rfc9180-6.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-6.1
	fn open<S>(
		&self,
		message: &HpkeMessage<S>,
		info: impl AsRef<[u8]>,
		aad: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>>
	where
		S: HpkeSuite<Curve = Self::Curve>;
}

impl<C> HpkeSecretKeyOps for SecretKey<C>
where
	C: Curve<FieldBytesSize = U32> + CurveArithmetic,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	type Curve = C;

	fn open<S>(
		&self,
		message: &HpkeMessage<S>,
		info: impl AsRef<[u8]>,
		aad: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>>
	where
		S: HpkeSuite<Curve = C>,
	{
		let dh = EcdhSecret::agree(self, message.encapsulated_key());
		dh.open(&self.public_key(), message, info, aad)
	}
}

impl EcdhSecret {
	/// The KEM shared secret of this DH output, which is
	/// `ExtractAndExpand(dh, kem_context)` with `kem_context = enc || pkRm`
	/// ([RFC 9180 §4.1][rfc9180-4.1]).
	///
	/// The context binds the encapsulated key and the recipient key, so a
	/// message opens under the one recipient key it was sealed to.
	///
	/// [rfc9180-4.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
	fn kem_shared_secret<C, K>(
		self,
		kem_id: u16,
		encapsulated_key: &PublicKey<C>,
		recipient: &PublicKey<C>,
	) -> Result<ZeroizingBytes>
	where
		C: Curve<FieldBytesSize = U32> + CurveArithmetic,
		AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
		K: HpkeKdf,
	{
		let labeled = Labeled::<K>::kem(kem_id);
		let enc = encapsulated_key.to_encoded_point(false);
		let recipient = recipient.to_encoded_point(false);
		let kem_context = [enc.as_bytes(), recipient.as_bytes()].concat();

		let eae_prk = self.with(|dh| labeled.extract(b"", b"eae_prk", dh));
		labeled.expand(&eae_prk, b"shared_secret", &kem_context, K::EXTRACT_SIZE)
	}

	/// Open an HPKE `message` with this precomputed `DH(skR, pkE)` output.
	///
	/// This splits the DH step out of [`HpkeSecretKeyOps::open`], so the
	/// recipient private key can live behind an external boundary such as an
	/// HSM, a KMS, or a secure enclave. The caller runs three steps:
	///
	/// 1. Parse the message with [`HpkeMessage::from_bytes`], which validates `pkE`.
	/// 2. Obtain the DH output of [`HpkeMessage::encapsulated_key`] out of band,
	///    for example from `DiffieHellman::agree` of a key backend.
	/// 3. Open the message here.
	///
	/// - `recipient`: the public key the message was sealed to, which the KEM context binds.
	///
	/// # Errors
	///
	/// - [`HpkeError::Kdf`] -- a KDF refused a derivation, or the AEAD refused the derived key.
	/// - [`HpkeError::DecryptionFailed`] -- the AEAD refused the ciphertext.
	pub fn open<S>(
		self,
		recipient: &PublicKey<S::Curve>,
		message: &HpkeMessage<S>,
		info: impl AsRef<[u8]>,
		aad: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>>
	where
		S: HpkeSuite,
	{
		let encapsulated_key = message.encapsulated_key();
		let shared_secret = self.kem_shared_secret::<S::Curve, S::KemKdf>(S::KEM_ID, encapsulated_key, recipient)?;
		let schedule = KeySchedule::<S>::derive(&shared_secret, info.as_ref())?;
		schedule.open(aad.as_ref(), message.ciphertext())
	}
}

/// The DHKEM of [RFC 9180 §4.1][rfc9180-4.1] on curve `C` under the KDF `K`
/// and the HPKE KEM identifier `KEM_ID`, which its `suite_id` carries, as a
/// KEM alone: `Encap` and `Decap`.
///
/// A CMS `KEMRecipientInfo` names its KEM by itself and derives its own key
/// from the shared secret ([RFC 9629 §5][rfc9629-5]), so it takes the shared
/// secret this type yields.
///
/// [rfc9180-4.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
/// [rfc9629-5]: https://datatracker.ietf.org/doc/html/rfc9629#section-5
pub struct DhKem<C, K, const KEM_ID: u16>(PhantomData<(C, K)>);

/// DHKEM(secp256k1, HKDF-SHA256), the registered KEM `0x0016`.
pub type DhKemSecp256k1 = DhKem<Secp256k1, HkdfSha256, KEM_DHKEM_SECP256K1_HKDF_SHA256>;

impl<C, K, const KEM_ID: u16> DhKem<C, K, KEM_ID>
where
	C: Curve<FieldBytesSize = U32> + CurveArithmetic,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	K: HpkeKdf,
{
	/// The identifier of the DHKEM in the HPKE KEM registry, which its
	/// labeled derivations bind ([RFC 9180 §4.1][rfc9180-4.1]).
	///
	/// [rfc9180-4.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
	pub const KEM_ID: u16 = KEM_ID;

	/// `Encap(pkR)`: draw a fresh ephemeral, and return the shared secret
	/// beside `enc`, the public half of that ephemeral.
	///
	/// `rng` draws the ephemeral, and `None` draws it from the OS source. The
	/// ephemeral drops here, so it serves one encapsulation.
	///
	/// # Errors
	///
	/// - [`HpkeError::Kdf`] -- the KDF refused a derivation.
	pub fn encap(
		recipient: &PublicKey<C>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<(ZeroizingBytes, PublicKey<C>)> {
		let mut os_rng = OsRng;
		let source = rng.unwrap_or(&mut os_rng);
		let ephemeral = SecretKey::<C>::random(&mut RngWrapper(source));
		Self::encap_with(ephemeral, recipient)
	}

	/// `Encap(pkR)` under `ephemeral`, which serves this one encapsulation.
	fn encap_with(ephemeral: SecretKey<C>, recipient: &PublicKey<C>) -> Result<(ZeroizingBytes, PublicKey<C>)> {
		let encapsulated_key = ephemeral.public_key();
		let dh = EcdhSecret::agree(&ephemeral, recipient);
		let shared_secret = dh.kem_shared_secret::<C, K>(KEM_ID, &encapsulated_key, recipient)?;
		Ok((shared_secret, encapsulated_key))
	}

	/// `Decap(enc, skR)` from `dh`, the `DH(skR, pkE)` output that the holder
	/// of the recipient key computed, so the key can stay behind a provider.
	///
	/// `recipient` is the public key `encapsulated_key` was sealed to, which
	/// the KEM context binds.
	///
	/// # Errors
	///
	/// - [`HpkeError::Kdf`] -- the KDF refused a derivation.
	pub fn decap(dh: EcdhSecret, encapsulated_key: &PublicKey<C>, recipient: &PublicKey<C>) -> Result<ZeroizingBytes> {
		dh.kem_shared_secret::<C, K>(KEM_ID, encapsulated_key, recipient)
	}
}

/// The DHKEM on the curve `C` under the KDF `K` and `KEM_ID`, to a parsed
/// recipient key and through the backend that holds its private half. The
/// house [`RecipientKem`] runs on these, and a KEM under another identifier
/// can too.
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
impl<C, K, const KEM_ID: u16> DhKem<C, K, KEM_ID>
where
	C: Curve<FieldBytesSize = U32> + CurveArithmetic,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	K: HpkeKdf,
{
	/// `Encap(pkR)` to `recipient`, with `enc` in uncompressed SEC1 form as
	/// the `kemct`.
	///
	/// `C`, `K`, and `KEM_ID` together name one KEM, so an implementor pairs a
	/// `KEM_ID` with the KDF its registration names, as `0x0016` names
	/// HKDF-SHA256.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Kem`] -- the KEM failed a derivation.
	pub fn encap_to(
		recipient: &PublicKey<C>,
		rng: &mut dyn CryptoRngCore,
	) -> core::result::Result<Encapsulation, EnvelopeError> {
		let (shared_secret, encapsulated_key) = Self::encap(recipient, Some(rng))?;
		let kemct = encapsulated_key.to_encoded_point(false).as_bytes().to_vec();
		Ok(Encapsulation { shared_secret, kemct })
	}

	/// `Decap(kemct, skR)` through `key`, the backend that holds the private
	/// half of `recipient`. This parses the point first, and then the backend
	/// runs `DH(skR, pkE)`.
	///
	/// `C`, `K`, and `KEM_ID` together name one KEM, so an implementor pairs a
	/// `KEM_ID` with the KDF its registration names, as `0x0016` names
	/// HKDF-SHA256.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::KemPoint`] -- `kemct` is no uncompressed point on `C`.
	/// - [`EnvelopeError::Key`] -- the backend failed the agreement.
	/// - [`EnvelopeError::Kdf`] -- the agreement is not 32 octets.
	/// - [`EnvelopeError::Kem`] -- the KEM failed a derivation.
	pub fn decap_through<'a>(
		key: &'a (impl DiffieHellman<C> + ?Sized),
		recipient: &'a PublicKey<C>,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, core::result::Result<ZeroizingBytes, EnvelopeError>> {
		Box::pin(async move {
			let encapsulated_key = Self::encapsulated_key(kemct)?;
			let agreed = key.agree(&encapsulated_key).await?;
			let dh = EcdhSecret::try_from(agreed)?;
			Ok(Self::decap(dh, &encapsulated_key, recipient)?)
		})
	}

	/// `kemct` as DHKEM's `enc`: the uncompressed SEC1 form of a point on `C`,
	/// 65 octets (RFC 9180 §7.1.1, draft-wahby-cfrg-hpke-kem-secp256k1 §3.1).
	///
	/// # Errors
	///
	/// - [`EnvelopeError::KemPoint`] -- `kemct` is another form or no point on `C`.
	fn encapsulated_key(kemct: &[u8]) -> core::result::Result<PublicKey<C>, EnvelopeError> {
		let uncompressed = kemct.len() == EC_PUBKEY_UNCOMPRESSED_SIZE && kemct.first() == Some(&0x04);
		if !uncompressed {
			return Err(EnvelopeError::KemPoint);
		}

		let point = PublicKey::from_sec1_bytes(kemct);
		point.map_err(|_| EnvelopeError::KemPoint)
	}
}

/// DHKEM(secp256k1, HKDF-SHA256), the KEM `0x0016` that
/// [`DHKEM_SECP256K1`] names: the house KEM. Its recipient key is a point on
/// secp256k1, and its backend runs the Diffie-Hellman agreement.
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
impl RecipientKem for DhKemSecp256k1 {
	const OID: ObjectIdentifier = DHKEM_SECP256K1;
	const USAGE: KeyUsages = KeyUsages::KeyAgreement;
	type PublicKey = PublicKey<Secp256k1>;
	type PrivateKey = dyn DiffieHellman<Secp256k1>;

	/// The `id-ecPublicKey` SPKI on secp256k1 (RFC 5480 §2.1.1), whose point
	/// is compressed or uncompressed (§2.2) and on the curve.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::SpkiError`] -- the SPKI names another
	///   algorithm or curve, its point is in another form, or it holds no
	///   point.
	fn public_key(
		spki: SubjectPublicKeyInfoRef<'_>,
	) -> core::result::Result<PublicKey<Secp256k1>, CertificateValidationError> {
		spki.require_point_form()?;
		Ok(PublicKey::<Secp256k1>::try_from(spki)?)
	}

	/// # Errors
	///
	/// - The errors of [`DhKem::encap_to`].
	fn encapsulate(
		recipient: &PublicKey<Secp256k1>,
		rng: &mut dyn CryptoRngCore,
	) -> core::result::Result<Encapsulation, EnvelopeError> {
		Self::encap_to(recipient, rng)
	}

	/// # Errors
	///
	/// - The errors of [`DhKem::decap_through`].
	fn decapsulate<'a>(
		key: &'a dyn DiffieHellman<Secp256k1>,
		recipient: &'a PublicKey<Secp256k1>,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, core::result::Result<ZeroizingBytes, EnvelopeError>> {
		Self::decap_through(key, recipient, kemct)
	}
}

impl core::convert::TryFrom<SecretSlice<u8>> for crate::crypto::k256::SecretKey {
	type Error = HpkeError;

	/// # Errors
	///
	/// - [`HpkeError::InvalidSecretKey`] -- the bytes are no scalar of the curve.
	fn try_from(bytes: SecretSlice<u8>) -> Result<Self> {
		let parsed = bytes.with(|raw| crate::crypto::k256::SecretKey::from_slice(raw));
		parsed.map_err(HpkeError::InvalidSecretKey)
	}
}

impl From<&crate::crypto::k256::SecretKey> for SecretSlice<u8> {
	fn from(secret_key: &crate::crypto::k256::SecretKey) -> Self {
		// The scalar leaves the key as a plain array, so this wipes it once the
		// wiping buffer holds its copy (CWE-226).
		let mut scalar = secret_key.to_bytes();
		let bytes = Secret::from(scalar.to_vec());
		scalar.as_mut_slice().zeroize();
		bytes
	}
}

/// Seals a frame to a recipient key as an `AuthEnvelopedData` with one
/// `KEMRecipientInfo` (RFC 9629 §3), under the KEM of the provider `P`.
///
/// - Every algorithm comes from `P`: its KEM, its KDF, its key wrap, and its AEAD.
/// - It implements [`Encryptor`] under the AEAD of `P`.
/// - [`FrameBuilder::with_encryptor`] therefore admits it for a frame of `P`'s profile.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::crypto::aead::{DecryptContent, Encryptor};
/// use tightbeam::crypto::cms::{BareKemKey, KemRecipient};
/// use tightbeam::crypto::hpke::{HpkeDecryptor, HpkeEncryptor};
/// use tightbeam::crypto::k256::{PublicKey, Secp256k1};
/// use tightbeam::crypto::key::{DiffieHellman, KeyBackend, Secp256k1KeyProvider};
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::der::Encode;
/// use tightbeam::random::OsRng;
/// use tightbeam::SigningKey;
///
/// let signing_key = SigningKey::random(&mut OsRng);
/// let public = PublicKey::from(signing_key.verifying_key());
/// let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(Secp256k1KeyProvider::from(signing_key));
/// let recipient = KemRecipient::bare(backend.to_public_key_bytes()?)?;
///
/// let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
/// let mut sealed = encryptor.encrypt_content(b"hello".to_vec(), None, None)?;
/// let mut content = sealed.take_content()?;
/// let arrived = sealed.to_der()?;
///
/// let decryptor = HpkeDecryptor::<DefaultCryptoProvider>::new(BareKemKey::new(public, backend)?);
/// let runtime = tokio::runtime::Builder::new_current_thread().build()?;
/// runtime.block_on(decryptor.decrypt_content(&sealed, &arrived, &mut content))?;
/// assert_eq!(&content[..], b"hello");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
///
/// [`FrameBuilder::with_encryptor`]: crate::builder::FrameBuilder::with_encryptor
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
pub struct HpkeEncryptor<P: CryptoProvider> {
	recipient: KemRecipient<P::Kem>,
}

#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
impl<P: CryptoProvider> HpkeEncryptor<P> {
	/// Create an encryptor that seals to `recipient`, the recipient key and
	/// the `rid` that names it.
	pub fn new(recipient: KemRecipient<P::Kem>) -> Self {
		Self { recipient }
	}
}

/// The `ukm` of the seal is the frame purpose label followed by 32 octets that
/// the seal draws. The decryptor admits a `ukm` of that form alone.
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
impl<P> Encryptor<<P::AeadCipher as AeadAlgorithm>::Oid> for HpkeEncryptor<P>
where
	P: CryptoProvider<AeadCipher: ContentEncryption>,
{
	fn encrypt_content(
		&self,
		content: impl Into<Vec<u8>>,
		content_type: Option<ObjectIdentifier>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> crate::error::Result<AuthEnvelopedData> {
		let recipient = Recipient::Kem { recipient: &self.recipient, ukm_label: TIGHTBEAM_FRAME_UKM_LABEL };
		let content_type = content_type.unwrap_or(DATA);
		Ok(AuthEnvelopedData::seal::<P>(recipient, content_type, content, [], rng)?)
	}
}

/// Opens a frame sealed to a recipient key, through the
/// [`KemKeyHolder`] that pairs the key with the backend of its private half:
/// a [`KeyAgreementIdentity`](crate::crypto::cms::KeyAgreementIdentity) or a
/// [`BareKemKey`](crate::crypto::cms::BareKemKey).
///
/// It implements [`Decryptor`], and the key stays behind the backend, which
/// runs the KEM's private-key operation.
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
pub struct HpkeDecryptor<P: CryptoProvider> {
	holder: Arc<dyn KemKeyHolder<P::Kem>>,
}

#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
impl<P: CryptoProvider> HpkeDecryptor<P> {
	/// Create a decryptor that opens through `holder`.
	pub fn new(holder: impl KemKeyHolder<P::Kem> + 'static) -> Self {
		Self { holder: Arc::new(holder) }
	}
}

/// The decryptor admits a `ukm` of the frame purpose label followed by 32
/// octets, and the content type that the envelope's attributes authenticate.
#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
impl<P> Decryptor for HpkeDecryptor<P>
where
	P: CryptoProvider<AeadCipher: ContentEncryption>,
{
	fn algorithm_oid(&self) -> ObjectIdentifier {
		<<P::AeadCipher as AeadAlgorithm>::Oid as AssociatedOid>::OID
	}

	fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, crate::error::Result<()>> {
		Box::pin(async move {
			let opener = Opener::Kem { identity: &*self.holder, ukm_label: TIGHTBEAM_FRAME_UKM_LABEL };
			content.open::<P>(&opener).await
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::aead::Key;
	use crate::crypto::common::typenum::U48;
	use crate::crypto::k256::sha2::Sha512;
	use crate::crypto::secret::ToInsecure;
	use crate::testing::{unhex, SeededStream};
	use aead::{AeadInPlace, Tag};

	/// The house suite.
	type Suite = HpkeSecp256k1Sha256Aes256Gcm;

	const INFO: &[u8] = b"tb/hpke/test";

	/// HKDF-SHA512, the KDF `0x0003` of RFC 9180 Table 3, which two of the
	/// Appendix A suites derive with.
	struct HkdfSha512;

	impl HpkeKdf for HkdfSha512 {
		const KDF_ID: u16 = 0x0003;
		const EXTRACT_SIZE: usize = 64;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			let prk = ZeroizingHkdf::<Sha512>::extract(salt, ikm);
			Zeroizing::new(prk.as_slice().to_vec())
		}

		fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			let keyed = ZeroizingHkdf::<Sha512>::from_prk(prk);
			let keyed = keyed.map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
			let mut okm = Zeroizing::new(vec![0u8; len]);
			keyed.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;
			Ok(okm)
		}
	}

	/// DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	type RegisteredAes128 = DhKemSuite<Secp256k1, HkdfSha256, Aes128Gcm, KEM_DHKEM_SECP256K1_HKDF_SHA256>;

	/// DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
	type RegisteredAes256 = DhKemSuite<Secp256k1, HkdfSha256, Aes256Gcm, KEM_DHKEM_SECP256K1_HKDF_SHA256>;

	/// HKDF-SHA256 under another KEM identifier, and `LEN_SHIFT` bytes away
	/// from a 12-byte request, as a relabeled or a faulty provider KDF is.
	struct AlteredKdf<const KEM_SHIFT: u16, const LEN_SHIFT: i8>;

	impl<const KEM_SHIFT: u16, const LEN_SHIFT: i8> HpkeKdf for AlteredKdf<KEM_SHIFT, LEN_SHIFT> {
		const KDF_ID: u16 = KDF_HKDF_SHA256;
		const EXTRACT_SIZE: usize = 32;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			HkdfSha256::extract(salt, ikm)
		}

		fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			let shift = isize::from(LEN_SHIFT) * isize::from(len == 12);
			HkdfSha256::expand(prk, info, len.saturating_add_signed(shift))
		}
	}

	/// The algorithms of [`Suite`] under another KEM identifier.
	type Relabeled = DhKemSuite<Secp256k1, HkdfSha256, Aes256Gcm, { KEM_DHKEM_SECP256K1_HKDF_SHA256 + 1 }>;

	/// A KDF with no bound on its output, so the two-byte length frame of
	/// `LabeledExpand` is the one refusal a long request meets.
	struct UnboundedKdf;

	impl HpkeKdf for UnboundedKdf {
		const KDF_ID: u16 = 0xFFFD;
		const EXTRACT_SIZE: usize = 32;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			HkdfSha256::extract(salt, ikm)
		}

		fn expand(_prk: &[u8], _info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			Ok(Zeroizing::new(vec![0u8; len]))
		}
	}

	/// One base-mode vector: the keys of both sides, the `info`, and what the
	/// KEM and the key schedule derive from them.
	struct Vector {
		info: &'static str,
		ephemeral_secret: &'static str,
		ephemeral_public: &'static str,
		recipient_secret: &'static str,
		recipient_public: &'static str,
		shared_secret: &'static str,
		key: &'static str,
		base_nonce: &'static str,
	}

	/// draft-wahby-cfrg-hpke-kem-secp256k1-01, B.1.1, the first vector.
	const AES_128_GCM_VECTOR: Vector = Vector {
		info: "17adde3164d65a90d077fd9a0fdba665152c3336",
		ephemeral_secret: "30fbc0d41cd01885333211ff53b9ed29bcbdccc3ff13625a82db61a7bb8eae19",
		ephemeral_public: "04591775168f328a2adbcb887acd287d55a1025d7d2b15e1937278a5efd1d48b\
			19c00cf07559320e6d278a71c9e58bae5d9ab041d7905c66291f4d08459c946e18",
		recipient_secret: "a795c287c132154a8b96dc81dc8b4e2f02bbbad78dab0567b59db1d1540751f6",
		recipient_public: "043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845d\
			af49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab",
		shared_secret: "7eabf4bab973fc9cc8b3bb2fdaa4d7f154309c31d11214cc48b4a8f3d65236f7",
		key: "c508c44d920152fb8dd597c8edce4cd1",
		base_nonce: "4ac4413d13c5713d6c76fad2",
	};

	/// draft-wahby-cfrg-hpke-kem-secp256k1-01, B.2.1, the first vector.
	const AES_256_GCM_VECTOR: Vector = Vector {
		info: "b546c00cece2e2ff0815eb0f8124fb9028c66e80",
		ephemeral_secret: "8979ee752423d020085c75cce1644959f819464a4c1c4e9a28ce4dd482991c1c",
		ephemeral_public: "040de7712da136d40779452a32e70ec834fa092ee8e3f26450786c6cd51396e8\
			596c958065594d30432e812fc7a53a10d7fce2ce9bf52ccce72cbad4c79d3b17f6",
		recipient_secret: "024be5fda9036a2d81f8c634193b5ce83e65bfc4373ae8b7a960fea8770d1f8f",
		recipient_public: "040986ec455812ddd870414c2753f75dadaefda155bc7bd18c4ab6ff3dd61b2e\
			a3bee4ab2a0160b8e330757fc6d81d88ece7051bd9a07fa7e5368ea579e2e6c0e6",
		shared_secret: "ad889cd7b11e8881252f8f12539be9f5e36d2b95c96c875fb0e449c711e8bc0d",
		key: "da2f3e53e24306c97331e92f564b6c207246e9ab4dea07a472401702d0af5c53",
		base_nonce: "d4d0dcfeeb6767d808f319e4",
	};

	/// The associated data and the plaintext of the sealed known answers.
	const KNOWN_AAD: &[u8] = b"tb/hpke/test/aad";
	const KNOWN_PLAINTEXT: &[u8] = b"known answer";

	/// What [`AES_256_GCM_VECTOR`] seals [`KNOWN_PLAINTEXT`] to under
	/// [`KNOWN_AAD`], from an independent implementation of RFC 9180 that
	/// reproduced both published vectors, and an independent AES-GCM.
	const REGISTERED_CIPHERTEXT: &str = "e0080fb223a2a45fe65407abafefade00abf2e6b11b7428df396d117";

	impl Vector {
		/// The ephemeral secret key of the sender.
		fn ephemeral(&self) -> SecretKey<Secp256k1> {
			let scalar = unhex(self.ephemeral_secret);
			SecretKey::<Secp256k1>::from_slice(&scalar).expect("the vector holds a scalar")
		}

		/// The secret key of the recipient.
		fn recipient(&self) -> SecretKey<Secp256k1> {
			let scalar = unhex(self.recipient_secret);
			SecretKey::<Secp256k1>::from_slice(&scalar).expect("the vector holds a scalar")
		}

		/// The public key of the recipient, as the vector encodes it.
		fn recipient_public(&self) -> PublicKey<Secp256k1> {
			let point = unhex(self.recipient_public);
			PublicKey::<Secp256k1>::from_sec1_bytes(&point).expect("the vector holds a point")
		}

		/// The encapsulated key, as the vector encodes it.
		fn encapsulated_key(&self) -> PublicKey<Secp256k1> {
			let point = unhex(self.ephemeral_public);
			PublicKey::<Secp256k1>::from_sec1_bytes(&point).expect("the vector holds a point")
		}

		/// The message this vector seals [`KNOWN_PLAINTEXT`] to under suite
		/// `S`, through the production seal with the vector's ephemeral.
		fn sealed<S>(&self) -> Result<HpkeMessage<S>>
		where
			S: HpkeSuite<Curve = Secp256k1>,
		{
			let info = unhex(self.info);
			HpkeMessage::sealed(self.ephemeral(), &self.recipient_public(), &info, KNOWN_AAD, KNOWN_PLAINTEXT)
		}

		/// What the registered DHKEM yields to the sender of this vector under
		/// its ephemeral: the shared secret and the encapsulated key.
		fn encapsulated(&self) -> Result<(Vec<u8>, PublicKey<Secp256k1>)> {
			let encapsulated = DhKemSecp256k1::encap_with(self.ephemeral(), &self.recipient_public());
			let (shared_secret, encapsulated_key) = encapsulated?;
			Ok((shared_secret.to_vec(), encapsulated_key))
		}

		/// What the registered DHKEM yields to the recipient of this vector,
		/// from the DH output of its secret key and the encapsulated key.
		fn decapsulated(&self) -> Result<Vec<u8>> {
			let recipient = self.recipient();
			let encapsulated_key = self.encapsulated_key();
			let dh = EcdhSecret::agree(&recipient, &encapsulated_key);
			let shared_secret = DhKemSecp256k1::decap(dh, &encapsulated_key, &recipient.public_key())?;
			Ok(shared_secret.to_vec())
		}

		/// The shared secret and the encapsulated key this vector publishes.
		fn published_encapsulation(&self) -> (Vec<u8>, PublicKey<Secp256k1>) {
			(unhex(self.shared_secret), self.encapsulated_key())
		}
	}

	/// What one side derives for a vector.
	#[derive(Debug, PartialEq)]
	struct Derived {
		shared_secret: Vec<u8>,
		key: Vec<u8>,
		base_nonce: Vec<u8>,
	}

	impl Derived {
		/// What `vector` publishes.
		fn published(vector: &Vector) -> Self {
			Self {
				shared_secret: unhex(vector.shared_secret),
				key: unhex(vector.key),
				base_nonce: unhex(vector.base_nonce),
			}
		}

		/// What the sender of `vector` derives under suite `S`, from its
		/// ephemeral secret and the recipient public key.
		fn by_sender<S>(vector: &Vector) -> Result<Self>
		where
			S: HpkeSuite<Curve = Secp256k1>,
		{
			let ephemeral = vector.ephemeral();
			let recipient = vector.recipient_public();
			let dh = EcdhSecret::agree(&ephemeral, &recipient);
			Self::from_dh::<S>(dh, &ephemeral.public_key(), &recipient, vector)
		}

		/// What the recipient of `vector` derives under suite `S`, from its
		/// secret key and the encapsulated key.
		fn by_recipient<S>(vector: &Vector) -> Result<Self>
		where
			S: HpkeSuite<Curve = Secp256k1>,
		{
			let recipient = vector.recipient();
			let encapsulated_key = vector.encapsulated_key();
			let dh = EcdhSecret::agree(&recipient, &encapsulated_key);
			Self::from_dh::<S>(dh, &encapsulated_key, &recipient.public_key(), vector)
		}

		fn from_dh<S>(
			dh: EcdhSecret,
			encapsulated_key: &PublicKey<Secp256k1>,
			recipient: &PublicKey<Secp256k1>,
			vector: &Vector,
		) -> Result<Self>
		where
			S: HpkeSuite<Curve = Secp256k1>,
		{
			let shared_secret = dh.kem_shared_secret::<Secp256k1, S::KemKdf>(S::KEM_ID, encapsulated_key, recipient)?;
			let schedule = KeySchedule::<S>::derive(&shared_secret, &unhex(vector.info))?;
			Ok(Self {
				shared_secret: shared_secret.to_vec(),
				key: schedule.key.to_vec(),
				base_nonce: schedule.base_nonce.to_vec(),
			})
		}
	}

	#[test]
	fn the_sender_matches_the_published_vector_under_aes_128_gcm() -> Result<()> {
		let derived = Derived::by_sender::<RegisteredAes128>(&AES_128_GCM_VECTOR)?;
		assert_eq!(derived, Derived::published(&AES_128_GCM_VECTOR));
		Ok(())
	}

	#[test]
	fn the_sender_matches_the_published_vector_under_aes_256_gcm() -> Result<()> {
		let derived = Derived::by_sender::<RegisteredAes256>(&AES_256_GCM_VECTOR)?;
		assert_eq!(derived, Derived::published(&AES_256_GCM_VECTOR));
		Ok(())
	}

	#[test]
	fn the_recipient_matches_the_published_vectors() -> Result<()> {
		let with_aes_128 = Derived::by_recipient::<RegisteredAes128>(&AES_128_GCM_VECTOR)?;
		let with_aes_256 = Derived::by_recipient::<RegisteredAes256>(&AES_256_GCM_VECTOR)?;
		assert_eq!(with_aes_128, Derived::published(&AES_128_GCM_VECTOR));
		assert_eq!(with_aes_256, Derived::published(&AES_256_GCM_VECTOR));
		Ok(())
	}

	/// The KEM alone, under the ephemeral of the B.1.1 vector, yields the
	/// shared secret and the encapsulated key that vector publishes.
	#[test]
	fn the_dhkem_encapsulates_to_the_published_b_1_1_vector() -> Result<()> {
		let encapsulated = AES_128_GCM_VECTOR.encapsulated()?;
		assert_eq!(encapsulated, AES_128_GCM_VECTOR.published_encapsulation());
		Ok(())
	}

	/// The KEM alone, under the ephemeral of the B.2.1 vector, yields the
	/// shared secret and the encapsulated key that vector publishes.
	#[test]
	fn the_dhkem_encapsulates_to_the_published_b_2_1_vector() -> Result<()> {
		let encapsulated = AES_256_GCM_VECTOR.encapsulated()?;
		assert_eq!(encapsulated, AES_256_GCM_VECTOR.published_encapsulation());
		Ok(())
	}

	/// The KEM alone, from the DH output of the recipient key and the
	/// encapsulated key of the B.1.1 vector, yields its shared secret.
	#[test]
	fn the_dhkem_decapsulates_the_published_b_1_1_vector() -> Result<()> {
		let decapsulated = AES_128_GCM_VECTOR.decapsulated()?;
		assert_eq!(decapsulated, unhex(AES_128_GCM_VECTOR.shared_secret));
		Ok(())
	}

	/// The KEM alone, from the DH output of the recipient key and the
	/// encapsulated key of the B.2.1 vector, yields its shared secret.
	#[test]
	fn the_dhkem_decapsulates_the_published_b_2_1_vector() -> Result<()> {
		let decapsulated = AES_256_GCM_VECTOR.decapsulated()?;
		assert_eq!(decapsulated, unhex(AES_256_GCM_VECTOR.shared_secret));
		Ok(())
	}

	/// The KEM carries the identifier the registry assigns it.
	#[test]
	fn the_registered_dhkem_carries_its_registry_identifiers() {
		assert_eq!(DhKemSecp256k1::KEM_ID, 0x0016);
		assert_eq!(<HkdfSha256 as HpkeKdf>::KDF_ID, 0x0001);
	}

	/// The house suite is the registered one, so it runs under the three
	/// identifiers the registry assigns: KEM `0x0016`, KDF `0x0001`, and AEAD
	/// `0x0002`.
	#[test]
	fn the_house_suite_carries_the_registered_identifiers() {
		assert_eq!(<Suite as HpkeSuite>::KEM_ID, 0x0016);
		assert_eq!(<<Suite as HpkeSuite>::Kdf as HpkeKdf>::KDF_ID, 0x0001);
		assert_eq!(<<Suite as HpkeSuite>::Aead as HpkeAead>::AEAD_ID, 0x0002);
	}

	/// The sealed bytes are the encapsulated key the vector publishes and the
	/// ciphertext an independent AES-GCM produces under the derived key and
	/// nonce, so the cipher is keyed and nonced as the schedule derived.
	#[test]
	fn a_sealed_message_matches_its_known_answer() -> Result<()> {
		let registered = AES_256_GCM_VECTOR.sealed::<RegisteredAes256>()?.to_bytes();
		let enc = unhex(AES_256_GCM_VECTOR.ephemeral_public);
		assert_eq!(registered, [enc.as_slice(), &unhex(REGISTERED_CIPHERTEXT)].concat());
		Ok(())
	}

	#[test]
	fn the_recipient_opens_the_known_answer() -> Result<()> {
		let enc = unhex(AES_256_GCM_VECTOR.ephemeral_public);
		let wire = [enc.as_slice(), &unhex(REGISTERED_CIPHERTEXT)].concat();
		let message = HpkeMessage::<Suite>::from_bytes(wire)?;

		let opened = AES_256_GCM_VECTOR
			.recipient()
			.open(&message, unhex(AES_256_GCM_VECTOR.info), KNOWN_AAD)?;
		assert_eq!(&opened.to_insecure()[..], KNOWN_PLAINTEXT);
		Ok(())
	}

	/// A KEM of RFC 9180 Table 2, by its identifier `ID` and its KDF `K`.
	///
	/// The key schedule reads the identifier of a KEM and the shared secret
	/// it produced, and the Appendix A vectors publish both. Their KEMs run
	/// on X25519, P-256, and P-521, so this type stands in for the curve.
	struct KemOf<const ID: u16, K>(PhantomData<K>);

	impl<const ID: u16, K: HpkeKdf> HpkeKdf for KemOf<ID, K> {
		const KDF_ID: u16 = K::KDF_ID;
		const EXTRACT_SIZE: usize = K::EXTRACT_SIZE;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			K::extract(salt, ikm)
		}

		fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			K::expand(prk, info, len)
		}
	}

	/// The suite of an Appendix A vector: the KEM `ID` over `KemK`, the KDF
	/// `K`, and the AEAD `A`.
	struct RfcSuite<const ID: u16, KemK, K, A>(PhantomData<(KemK, K, A)>);

	impl<const ID: u16, KemK: HpkeKdf, K: HpkeKdf, A: HpkeAead> HpkeSuite for RfcSuite<ID, KemK, K, A> {
		type Curve = Secp256k1;
		type KemKdf = KemOf<ID, KemK>;
		type Kdf = K;
		type Aead = A;

		const KEM_ID: u16 = ID;
	}

	/// RFC 9180 A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	type RfcA1 = RfcSuite<0x0020, HkdfSha256, HkdfSha256, Aes128Gcm>;

	/// RFC 9180 A.3: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	type RfcA3 = RfcSuite<0x0010, HkdfSha256, HkdfSha256, Aes128Gcm>;

	/// RFC 9180 A.4: DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM.
	type RfcA4 = RfcSuite<0x0010, HkdfSha256, HkdfSha512, Aes128Gcm>;

	/// RFC 9180 A.6: DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM.
	type RfcA6 = RfcSuite<0x0012, HkdfSha512, HkdfSha512, Aes256Gcm>;

	/// The `info` of every base-mode vector of RFC 9180 Appendix A.
	const RFC_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";

	/// The plaintext of every encryption of Appendix A.
	const RFC_PLAINTEXT: &str = "4265617574792069732074727574682c20747275746820626561757479";

	/// The associated data of every encryption at sequence number zero.
	const RFC_AAD: &str = "436f756e742d30";

	/// One base-mode vector of RFC 9180 Appendix A, from the KEM shared secret
	/// on: what the key schedule derives, and the ciphertext at sequence
	/// number zero.
	struct ScheduleVector {
		shared_secret: &'static str,
		key: &'static str,
		base_nonce: &'static str,
		ciphertext: &'static str,
	}

	/// RFC 9180 A.1.1 and A.1.1.1.
	const RFC_A_1_1: ScheduleVector = ScheduleVector {
		shared_secret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		key: "4531685d41d65f03dc48f6b8302c05b0",
		base_nonce: "56d890e5accaaf011cff4b7d",
		ciphertext: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
	};

	/// RFC 9180 A.3.1 and A.3.1.1.
	const RFC_A_3_1: ScheduleVector = ScheduleVector {
		shared_secret: "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8",
		key: "868c066ef58aae6dc589b6cfdd18f97e",
		base_nonce: "4e0bc5018beba4bf004cca59",
		ciphertext: "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434",
	};

	/// RFC 9180 A.4.1 and A.4.1.1.
	const RFC_A_4_1: ScheduleVector = ScheduleVector {
		shared_secret: "02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd",
		key: "090ca96e5f8aa02b69fac360da50ddf9",
		base_nonce: "9c995e621bf9a20c5ca45546",
		ciphertext: "d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba",
	};

	/// RFC 9180 A.6.1 and A.6.1.1.
	const RFC_A_6_1: ScheduleVector = ScheduleVector {
		shared_secret: "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336\
			fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818",
		key: "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70",
		base_nonce: "55ff7a7d739c69f44b25447b",
		ciphertext: "170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b200aafcc6d80ea4c795a7c5b841a",
	};

	/// What the two contexts of a [`ScheduleVector`] derive and compute.
	#[derive(Debug, PartialEq)]
	struct Scheduled {
		key: Vec<u8>,
		base_nonce: Vec<u8>,
		ciphertext: Vec<u8>,
		plaintext: Vec<u8>,
	}

	impl Scheduled {
		/// What `vector` publishes.
		fn published(vector: &ScheduleVector) -> Self {
			Self {
				key: unhex(vector.key),
				base_nonce: unhex(vector.base_nonce),
				ciphertext: unhex(vector.ciphertext),
				plaintext: unhex(RFC_PLAINTEXT),
			}
		}

		/// What suite `S` makes of the shared secret of `vector`. The sender
		/// context seals the plaintext, and the recipient context opens the
		/// published ciphertext.
		fn by_suite<S: HpkeSuite>(vector: &ScheduleVector) -> Result<Self> {
			let shared_secret = unhex(vector.shared_secret);
			let info = unhex(RFC_INFO);
			let aad = unhex(RFC_AAD);
			let sender = KeySchedule::<S>::derive(&shared_secret, &info)?;
			let recipient = KeySchedule::<S>::derive(&shared_secret, &info)?;

			let ciphertext = sender.seal(&aad, &unhex(RFC_PLAINTEXT))?;
			let plaintext = recipient.open(&aad, &unhex(vector.ciphertext))?;
			Ok(Self {
				key: sender.key.to_vec(),
				base_nonce: sender.base_nonce.to_vec(),
				ciphertext,
				plaintext: plaintext.to_insecure().to_vec(),
			})
		}
	}

	#[test]
	fn the_key_schedule_and_the_seal_match_rfc_9180_a_1() -> Result<()> {
		let scheduled = Scheduled::by_suite::<RfcA1>(&RFC_A_1_1)?;
		assert_eq!(scheduled, Scheduled::published(&RFC_A_1_1));
		Ok(())
	}

	#[test]
	fn the_key_schedule_and_the_seal_match_rfc_9180_a_3() -> Result<()> {
		let scheduled = Scheduled::by_suite::<RfcA3>(&RFC_A_3_1)?;
		assert_eq!(scheduled, Scheduled::published(&RFC_A_3_1));
		Ok(())
	}

	/// The KDF of the key schedule differs from the KDF of the KEM here.
	#[test]
	fn the_key_schedule_and_the_seal_match_rfc_9180_a_4() -> Result<()> {
		let scheduled = Scheduled::by_suite::<RfcA4>(&RFC_A_4_1)?;
		assert_eq!(scheduled, Scheduled::published(&RFC_A_4_1));
		Ok(())
	}

	/// The shared secret is 64 bytes wide here, and the key is 32.
	#[test]
	fn the_key_schedule_and_the_seal_match_rfc_9180_a_6() -> Result<()> {
		let scheduled = Scheduled::by_suite::<RfcA6>(&RFC_A_6_1)?;
		assert_eq!(scheduled, Scheduled::published(&RFC_A_6_1));
		Ok(())
	}

	/// One HKDF-SHA256 vector of RFC 5869 Appendix A.
	struct HkdfVector {
		ikm: &'static str,
		salt: &'static str,
		info: &'static str,
		length: usize,
		prk: &'static str,
		okm: &'static str,
	}

	/// RFC 5869 A.1, the basic test case.
	const RFC_5869_A_1: HkdfVector = HkdfVector {
		ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt: "000102030405060708090a0b0c",
		info: "f0f1f2f3f4f5f6f7f8f9",
		length: 42,
		prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
		okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
	};

	/// RFC 5869 A.2, longer inputs and outputs.
	const RFC_5869_A_2: HkdfVector = HkdfVector {
		ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
			202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
			808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
			d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		length: 82,
		prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
		okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
			59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
	};

	/// RFC 5869 A.3, a zero-length salt and info.
	const RFC_5869_A_3: HkdfVector = HkdfVector {
		ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		salt: "",
		info: "",
		length: 42,
		prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
		okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
	};

	impl HkdfVector {
		/// What [`HkdfSha256`] derives from this vector: the PRK and the OKM.
		fn derived(&self) -> core::result::Result<(Vec<u8>, Vec<u8>), KdfError> {
			let prk = HkdfSha256::extract(&unhex(self.salt), &unhex(self.ikm));
			let okm = HkdfSha256::expand(&prk, &unhex(self.info), self.length)?;
			Ok((prk.to_vec(), okm.to_vec()))
		}

		/// The PRK and the OKM this vector publishes.
		fn published(&self) -> (Vec<u8>, Vec<u8>) {
			(unhex(self.prk), unhex(self.okm))
		}
	}

	#[test]
	fn hkdf_sha256_matches_rfc_5869_a_1() -> core::result::Result<(), KdfError> {
		let derived = RFC_5869_A_1.derived()?;
		assert_eq!(derived, RFC_5869_A_1.published());
		Ok(())
	}

	#[test]
	fn hkdf_sha256_matches_rfc_5869_a_2() -> core::result::Result<(), KdfError> {
		let derived = RFC_5869_A_2.derived()?;
		assert_eq!(derived, RFC_5869_A_2.published());
		Ok(())
	}

	#[test]
	fn hkdf_sha256_matches_rfc_5869_a_3() -> core::result::Result<(), KdfError> {
		let derived = RFC_5869_A_3.derived()?;
		assert_eq!(derived, RFC_5869_A_3.published());
		Ok(())
	}

	fn keypair() -> (SecretKey<Secp256k1>, PublicKey<Secp256k1>) {
		let secret = SecretKey::<Secp256k1>::random(&mut OsRng);
		let public = secret.public_key();
		(secret, public)
	}

	fn roundtrip(plaintext: impl AsRef<[u8]>, aad: impl AsRef<[u8]>) -> Result<()> {
		let plaintext = plaintext.as_ref();
		let (secret, public) = keypair();
		let sealed = public.seal::<Suite>(INFO, &aad, plaintext, None)?;

		let opened = secret.open(&sealed, INFO, &aad)?;
		assert_eq!(plaintext, &opened.to_insecure()[..]);
		Ok(())
	}

	#[test]
	fn a_sealed_message_opens_to_its_plaintext() -> Result<()> {
		roundtrip(b"Hello, HPKE!", b"")?;
		roundtrip(b"Secret message", b"authenticated data")?;
		roundtrip(b"", b"")?;
		roundtrip([0x5Au8; 4096], b"")?;
		roundtrip(b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC", b"version:1|timestamp:12345")?;
		Ok(())
	}

	#[test]
	fn a_message_opens_under_its_aad_alone() -> Result<()> {
		let (secret, public) = keypair();
		let sealed = public.seal::<Suite>(INFO, b"authenticated data", b"Secret message", None)?;

		let opened = secret.open(&sealed, INFO, b"authenticated data")?;
		assert_eq!(&opened.to_insecure()[..], b"Secret message");
		assert!(secret.open(&sealed, INFO, b"wrong data").is_err());
		assert!(secret.open(&sealed, INFO, b"").is_err());
		Ok(())
	}

	/// The key schedule binds `info`, so a message opens under the context it
	/// was sealed in.
	#[test]
	fn a_message_opens_under_its_info_alone() -> Result<()> {
		let (secret, public) = keypair();
		let sealed = public.seal::<Suite>(INFO, b"", b"Secret message", None)?;

		assert!(secret.open(&sealed, INFO, b"").is_ok());
		assert!(secret.open(&sealed, b"another context", b"").is_err());
		assert!(secret.open(&sealed, b"", b"").is_err());
		Ok(())
	}

	/// The labels bind the identifiers, so the same algorithms under another
	/// KEM identifier derive another key.
	#[test]
	fn a_message_opens_under_its_suite_alone() -> Result<()> {
		let (secret, public) = keypair();
		let sealed = public.seal::<Suite>(INFO, b"", b"Secret message", None)?;
		let relabeled = HpkeMessage::<Relabeled>::from_bytes(sealed.to_bytes())?;

		let opened = secret.open(&relabeled, INFO, b"");
		assert!(matches!(opened, Err(HpkeError::DecryptionFailed(_))));
		Ok(())
	}

	#[test]
	fn another_recipient_fails_to_open() -> Result<()> {
		let (_, public) = keypair();
		let (other_secret, _) = keypair();
		let sealed = public.seal::<Suite>(INFO, b"", b"Sensitive data", None)?;

		let opened = other_secret.open(&sealed, INFO, b"");
		assert!(matches!(opened, Err(HpkeError::DecryptionFailed(_))));
		Ok(())
	}

	/// The KEM context binds the recipient key, so the right DH output opens
	/// the message under that key alone.
	#[test]
	fn a_dh_output_opens_under_its_recipient_key_alone() -> Result<()> {
		let (secret, public) = keypair();
		let (_, other_public) = keypair();
		let sealed = public.seal::<Suite>(INFO, b"", b"Sensitive data", None)?;
		let ephemeral = sealed.encapsulated_key();

		let opened = EcdhSecret::agree(&secret, ephemeral).open(&public, &sealed, INFO, b"")?;
		let rebound = EcdhSecret::agree(&secret, ephemeral).open(&other_public, &sealed, INFO, b"");
		assert_eq!(&opened.to_insecure()[..], b"Sensitive data");
		assert!(matches!(rebound, Err(HpkeError::DecryptionFailed(_))));
		Ok(())
	}

	/// What a recipient reads from a sealed message after `tamper` changed its
	/// encoding.
	fn opened_after(tamper: fn(&mut Vec<u8>)) -> Result<SecretSlice<u8>> {
		let (secret, public) = keypair();
		let mut wire = public.seal::<Suite>(INFO, b"", b"Sensitive data", None)?.to_bytes();
		tamper(&mut wire);

		let message = HpkeMessage::<Suite>::from_bytes(wire)?;
		secret.open(&message, INFO, b"")
	}

	#[test]
	fn a_tampered_message_fails_to_open() -> Result<()> {
		let untouched = opened_after(|_| ())?;
		let last_byte_flipped = opened_after(|wire| wire[EC_PUBKEY_UNCOMPRESSED_SIZE + 29] ^= 0xFF);
		let first_byte_flipped = opened_after(|wire| wire[EC_PUBKEY_UNCOMPRESSED_SIZE] ^= 0xFF);
		let one_byte_short = opened_after(|wire| wire.truncate(EC_PUBKEY_UNCOMPRESSED_SIZE + 29));
		let key_tag_flipped = opened_after(|wire| wire[0] ^= 0xFF);

		assert_eq!(&untouched.to_insecure()[..], b"Sensitive data");
		assert!(matches!(last_byte_flipped, Err(HpkeError::DecryptionFailed(_))));
		assert!(matches!(first_byte_flipped, Err(HpkeError::DecryptionFailed(_))));
		assert!(matches!(one_byte_short, Err(HpkeError::DecryptionFailed(_))));
		assert!(matches!(key_tag_flipped, Err(HpkeError::InvalidPublicKey(_))));
		Ok(())
	}

	/// The encoding of a message under `enc`, with a ciphertext of `tag`
	/// bytes and no more.
	fn wire_of(enc: impl AsRef<[u8]>, tag: usize) -> Vec<u8> {
		[enc.as_ref(), &vec![0xEEu8; tag]].concat()
	}

	/// The parse refuses a message that cannot carry an encapsulated key and
	/// a tag, ahead of any DH.
	#[test]
	fn a_message_too_short_for_a_key_and_a_tag_is_refused() -> Result<()> {
		let enc = unhex(AES_256_GCM_VECTOR.ephemeral_public);

		let short_key = HpkeMessage::<Suite>::from_bytes(&enc[..EC_PUBKEY_UNCOMPRESSED_SIZE - 1]);
		let short_tag = HpkeMessage::<Suite>::from_bytes(wire_of(&enc, 15));
		let bare_tag = HpkeMessage::<Suite>::from_bytes(wire_of(&enc, 16))?;
		assert!(matches!(short_key, Err(HpkeError::InvalidCiphertext)));
		assert!(matches!(short_tag, Err(HpkeError::InvalidCiphertext)));
		assert_eq!(bare_tag.ciphertext(), &[0xEE; 16]);
		Ok(())
	}

	/// The parse validates the encapsulated key, so it refuses a point off the
	/// curve and a compressed encoding at the uncompressed width.
	#[test]
	fn an_encapsulated_key_that_is_no_point_is_refused() {
		let mut off_curve = unhex(AES_256_GCM_VECTOR.ephemeral_public);
		off_curve[EC_PUBKEY_UNCOMPRESSED_SIZE - 1] ^= 0x01;
		let mut compressed_tag = unhex(AES_256_GCM_VECTOR.ephemeral_public);
		compressed_tag[0] = 0x02;

		let off_curve = HpkeMessage::<Suite>::from_bytes(wire_of(off_curve, 16));
		let compressed_tag = HpkeMessage::<Suite>::from_bytes(wire_of(compressed_tag, 16));
		assert!(matches!(off_curve, Err(HpkeError::InvalidPublicKey(_))));
		assert!(matches!(compressed_tag, Err(HpkeError::InvalidPublicKey(_))));
	}

	#[test]
	fn a_message_survives_its_encoding() -> Result<()> {
		let (secret, public) = keypair();
		let sealed = public.seal::<Suite>(INFO, b"", b"Test serialization", None)?;
		let parsed = HpkeMessage::<Suite>::from_bytes(sealed.to_bytes())?;

		let opened = secret.open(&parsed, INFO, b"")?;
		assert_eq!(parsed.encapsulated_key(), sealed.encapsulated_key());
		assert_eq!(parsed.ciphertext().len(), b"Test serialization".len() + 16);
		assert_eq!(&opened.to_insecure()[..], b"Test serialization");
		Ok(())
	}

	#[test]
	fn a_secret_key_survives_its_byte_form() -> Result<()> {
		let (secret, public) = keypair();
		let secret_bytes: SecretSlice<u8> = (&secret).into();

		let restored = crate::crypto::k256::SecretKey::try_from(secret_bytes)?;
		let zero = crate::crypto::k256::SecretKey::try_from(Secret::from(vec![0x00u8; 32]));
		assert_eq!(restored.public_key(), public);
		assert!(matches!(zero, Err(HpkeError::InvalidSecretKey(_))));
		Ok(())
	}

	/// AES-256-GCM behind a 48-byte key, wider than one 32-byte KDF block.
	struct WideKeyCipher(Aes256Gcm);

	impl KeySizeUser for WideKeyCipher {
		type KeySize = U48;
	}

	impl KeyInit for WideKeyCipher {
		fn new(key: &Key<Self>) -> Self {
			let (inner_key, _) = key.split_at(32);
			Self(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(inner_key)))
		}
	}

	impl AeadCore for WideKeyCipher {
		type NonceSize = <Aes256Gcm as AeadCore>::NonceSize;
		type TagSize = <Aes256Gcm as AeadCore>::TagSize;
		type CiphertextOverhead = <Aes256Gcm as AeadCore>::CiphertextOverhead;
	}

	impl AeadInPlace for WideKeyCipher {
		fn encrypt_in_place_detached(
			&self,
			nonce: &Nonce<Self>,
			associated_data: &[u8],
			buffer: &mut [u8],
		) -> aead::Result<Tag<Self>> {
			self.0.encrypt_in_place_detached(nonce, associated_data, buffer)
		}

		fn decrypt_in_place_detached(
			&self,
			nonce: &Nonce<Self>,
			associated_data: &[u8],
			buffer: &mut [u8],
			tag: &Tag<Self>,
		) -> aead::Result<()> {
			self.0.decrypt_in_place_detached(nonce, associated_data, buffer, tag)
		}
	}

	impl HpkeAead for WideKeyCipher {
		const AEAD_ID: u16 = 0xFFFE;
	}

	/// A cipher whose key is wider than one KDF block keys and round-trips,
	/// because the key is derived at the cipher's own size.
	#[test]
	fn a_key_wider_than_32_bytes_round_trips() -> Result<()> {
		type Wide = DhKemSuite<Secp256k1, HkdfSha256, WideKeyCipher, KEM_DHKEM_SECP256K1_HKDF_SHA256>;
		let (secret, public) = keypair();
		let sealed = public.seal::<Wide>(INFO, b"", b"wide", None)?;

		let opened = secret.open(&sealed, INFO, b"")?;
		assert_eq!(&opened.to_insecure()[..], b"wide");
		Ok(())
	}

	/// A KDF that answers another length than the one asked fails the
	/// derivation on either side of it, so the cipher runs on its own geometry
	/// alone.
	#[test]
	fn a_kdf_output_of_another_length_is_refused() {
		type Overlong = DhKemSuite<Secp256k1, AlteredKdf<0, 1>, Aes256Gcm, KEM_DHKEM_SECP256K1_HKDF_SHA256>;
		type Short = DhKemSuite<Secp256k1, AlteredKdf<0, -1>, Aes256Gcm, KEM_DHKEM_SECP256K1_HKDF_SHA256>;
		let (_, public) = keypair();

		let overlong = public.seal::<Overlong>(INFO, b"", b"plaintext", None);
		let short = public.seal::<Short>(INFO, b"", b"plaintext", None);
		assert!(matches!(overlong, Err(HpkeError::Kdf(_))));
		assert!(matches!(short, Err(HpkeError::Kdf(_))));
	}

	/// `LabeledExpand` frames its length in two bytes, so it refuses a longer
	/// request ahead of the KDF. The KDF here answers any length, because
	/// HKDF-SHA256 refuses past 8,160 bytes on its own and would hide the
	/// frame.
	#[test]
	fn a_labeled_expand_past_two_length_bytes_is_refused() {
		type Unbounded = DhKemSuite<Secp256k1, UnboundedKdf, Aes256Gcm, 0xFFFD>;
		let labeled = Labeled::<UnboundedKdf>::schedule::<Unbounded>();
		let prk = [0x11u8; 32];

		let widest = labeled.expand(&prk, b"key", b"", usize::from(u16::MAX));
		let past_the_frame = labeled.expand(&prk, b"key", b"", usize::from(u16::MAX) + 1);
		assert!(widest.is_ok());
		assert!(matches!(past_the_frame, Err(HpkeError::Kdf(_))));
	}

	/// Seal a fixed plaintext to `public` with the ephemeral drawn from
	/// `stream`.
	fn sealed_from(public: &PublicKey<Secp256k1>, mut stream: SeededStream) -> Result<Vec<u8>> {
		let sealed = public.seal::<Suite>(INFO, b"", b"seeded", Some(&mut stream))?;
		Ok(sealed.to_bytes())
	}

	/// The ephemeral key comes from the caller's RNG and the nonce from the
	/// key schedule, so two streams of one seed seal one plaintext to the same
	/// bytes.
	#[test]
	fn seal_draws_from_the_callers_rng() -> Result<()> {
		let (_, public) = keypair();

		let first = sealed_from(&public, SeededStream(0))?;
		let second = sealed_from(&public, SeededStream(0))?;
		let other_seed = sealed_from(&public, SeededStream(7))?;
		assert_eq!(first, second);
		assert_ne!(first, other_seed);
		Ok(())
	}

	/// The frame KEM recipients of the house provider.
	#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh"))]
	mod frames {
		use super::*;
		use crate::cms::enveloped_data::RecipientInfo;
		use crate::crypto::aead::{DecryptContent, Encryptor};
		use crate::crypto::cms::{BareKemKey, KemRecipientInfo, KeyAgreementIdentity};
		use crate::crypto::key::{DiffieHellman, KeyBackend, Secp256k1KeyProvider};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::der::{Decode, Encode};
		use crate::oids::{AES_256_GCM, AES_256_WRAP, HKDF_SHA3_256, ORI_KEM};
		use crate::testing::{TestAttributes, TestCertificate};
		use crate::ZeroizingBytes;

		type House = DefaultCryptoProvider;

		/// The frame purpose label `tb/frame/ukm/v1`, the 15 octets every frame
		/// `ukm` leads with.
		const FRAME_UKM_LABEL: &[u8] = b"tb/frame/ukm/v1";

		const FRAMED: &[u8] = b"framed content";

		/// The `id-signedData` content type, `1.2.840.113549.1.7.2`
		/// (RFC 5652 §5.1), a type other than the default.
		const ID_SIGNED_DATA: crate::der::asn1::ObjectIdentifier =
			crate::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

		/// A fresh secp256k1 key, its public point, and its house backend.
		fn key_with_backend() -> (PublicKey<Secp256k1>, Arc<dyn DiffieHellman<Secp256k1>>) {
			let key = Secp256k1SigningKey::random(&mut OsRng);
			let public = PublicKey::from(key.verifying_key());
			(public, Arc::new(Secp256k1KeyProvider::from(key)))
		}

		/// The bare recipient of `backend`'s key, from its SPKI.
		fn bare_recipient(backend: &Arc<dyn DiffieHellman<Secp256k1>>) -> KemRecipient<DhKemSecp256k1> {
			let spki = backend.to_public_key_bytes().expect("the backend encodes its key");
			KemRecipient::bare(spki).expect("the key is a secp256k1 key")
		}

		/// [`FRAMED`] sealed to `recipient` by the house frame encryptor,
		/// beside the DER it arrives as.
		fn sealed_to(recipient: KemRecipient<DhKemSecp256k1>) -> (AuthEnvelopedData, Vec<u8>) {
			let encryptor = HpkeEncryptor::<House>::new(recipient);
			let sealed = encryptor.encrypt_content(FRAMED, None, None).expect("the frame seals");
			let arrived = sealed.to_der().expect("the frame encodes");
			(sealed, arrived)
		}

		/// `sealed` as a frame carries it: the envelope with its content
		/// detached, beside the content.
		fn detached(mut sealed: AuthEnvelopedData) -> (AuthEnvelopedData, ZeroizingBytes) {
			let content = sealed.take_content().expect("the seal carries its content");
			(sealed, content)
		}

		/// The `KEMRecipientInfo` of `sealed`.
		fn kem_recipient_of(sealed: &AuthEnvelopedData) -> KemRecipientInfo {
			let recipient = sealed.recipient_infos.0.as_slice().first().cloned();
			let other = match recipient {
				Some(RecipientInfo::Ori(other)) if other.ori_type == ORI_KEM => Some(other),
				_ => None,
			};

			let other = other.expect("a frame seal carries one id-ori-kem recipient");
			other.ori_value.decode_as().expect("the value is a KEMRecipientInfo")
		}

		#[tokio::test]
		async fn a_frame_sealed_to_a_bare_key_opens_through_its_bare_kem_key() -> crate::error::Result<()> {
			let (public, backend) = key_with_backend();
			let (sealed, arrived) = sealed_to(bare_recipient(&backend));
			let (envelope, mut content) = detached(sealed);

			let decryptor = HpkeDecryptor::<House>::new(BareKemKey::new(public, backend)?);
			decryptor.decrypt_content(&envelope, &arrived, &mut content).await?;
			assert_eq!(&content[..], FRAMED);
			Ok(())
		}

		#[tokio::test]
		async fn a_frame_sealed_to_a_certificate_key_opens_through_its_identity() -> crate::error::Result<()> {
			let key = Secp256k1SigningKey::random(&mut OsRng);
			let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(Secp256k1KeyProvider::from(key.to_owned()));
			let identity = KeyAgreementIdentity::<DhKemSecp256k1>::new(TestCertificate::self_signed(&key), backend)?;
			let (sealed, arrived) = sealed_to(identity.recipient().clone());
			let (envelope, mut content) = detached(sealed);

			let decryptor = HpkeDecryptor::<House>::new(identity);
			decryptor.decrypt_content(&envelope, &arrived, &mut content).await?;
			assert_eq!(&content[..], FRAMED);
			Ok(())
		}

		#[tokio::test]
		async fn a_frame_whose_rid_names_another_key_is_refused() -> crate::error::Result<()> {
			let (_, sealed_backend) = key_with_backend();
			let (public, backend) = key_with_backend();
			let (sealed, arrived) = sealed_to(bare_recipient(&sealed_backend));
			let (envelope, mut content) = detached(sealed);

			let decryptor = HpkeDecryptor::<House>::new(BareKemKey::new(public, backend)?);
			let refused = decryptor.decrypt_content(&envelope, &arrived, &mut content).await;
			assert!(matches!(
				refused,
				Err(crate::TightBeamError::EnvelopeError(EnvelopeError::RecipientIdentifier))
			));
			Ok(())
		}

		/// A KEM seal of another purpose carries another `ukm`, so the frame
		/// decryptor refuses it.
		#[tokio::test]
		async fn a_kem_seal_of_another_purpose_does_not_open_as_a_frame() -> crate::error::Result<()> {
			let (public, backend) = key_with_backend();
			let recipient = bare_recipient(&backend);
			let opening = Recipient::Kem { recipient: &recipient, ukm_label: b"tb/handshake/opening/ukm/v1" };
			let sealed = AuthEnvelopedData::seal::<House>(opening, DATA, FRAMED, [], None)?;
			let arrived = sealed.to_der()?;
			let (envelope, mut content) = detached(sealed);

			let decryptor = HpkeDecryptor::<House>::new(BareKemKey::new(public, backend)?);
			let refused = decryptor.decrypt_content(&envelope, &arrived, &mut content).await;
			assert!(matches!(refused, Err(crate::TightBeamError::EnvelopeError(EnvelopeError::Ukm))));
			Ok(())
		}

		/// The frame seal runs every algorithm of the house provider and names
		/// each by its registered identifier.
		#[test]
		fn a_frame_seal_names_the_algorithms_of_its_provider() {
			let (_, backend) = key_with_backend();
			let (sealed, _) = sealed_to(bare_recipient(&backend));

			let recipient = kem_recipient_of(&sealed);
			assert_eq!(recipient.kem.oid, DHKEM_SECP256K1);
			assert_eq!(recipient.kdf.oid, HKDF_SHA3_256);
			assert_eq!(recipient.wrap.oid, AES_256_WRAP);
			assert_eq!(sealed.auth_encrypted_content_info.content_enc_alg.oid, AES_256_GCM);
		}

		/// The `ukm` of a frame seal is the frame purpose label, then the 32
		/// octets the seal draws.
		#[test]
		fn a_frame_seal_leads_its_ukm_with_the_frame_label() -> crate::error::Result<()> {
			let (_, backend) = key_with_backend();
			let (sealed, _) = sealed_to(bare_recipient(&backend));

			let ukm = kem_recipient_of(&sealed).ukm.ok_or(EnvelopeError::Ukm)?;
			let (label, random) = ukm.as_bytes().split_at(FRAME_UKM_LABEL.len());
			assert_eq!(label, FRAME_UKM_LABEL);
			assert_eq!(random.len(), 32);
			Ok(())
		}

		/// A frame sealed as another content type declares that type, in its
		/// content type and in its content-type attribute.
		#[test]
		fn a_frame_seal_declares_the_content_type_it_is_given() -> crate::error::Result<()> {
			let (_, backend) = key_with_backend();
			let encryptor = HpkeEncryptor::<House>::new(bare_recipient(&backend));
			let sealed = encryptor.encrypt_content(FRAMED, Some(ID_SIGNED_DATA), None)?;

			let declared = TestAttributes::declared_content_types(&sealed);
			assert_eq!(declared, (ID_SIGNED_DATA, ID_SIGNED_DATA));
			Ok(())
		}

		/// A frame sealed as another content type opens as that type, the type
		/// its attributes authenticate.
		#[tokio::test]
		async fn a_frame_of_another_content_type_opens_as_that_type() -> crate::error::Result<()> {
			let (public, backend) = key_with_backend();
			let encryptor = HpkeEncryptor::<House>::new(bare_recipient(&backend));
			let sealed = encryptor.encrypt_content(FRAMED, Some(ID_SIGNED_DATA), None)?;
			let arrived = sealed.to_der()?;
			let (envelope, mut content) = detached(sealed);

			let decryptor = HpkeDecryptor::<House>::new(BareKemKey::new(public, backend)?);
			decryptor.decrypt_content(&envelope, &arrived, &mut content).await?;
			assert_eq!(&content[..], FRAMED);
			Ok(())
		}

		/// Each frame seal draws its own ephemeral, so two seals to one
		/// recipient carry two `kemct` values.
		#[test]
		fn each_frame_seal_encapsulates_afresh() {
			let (_, backend) = key_with_backend();
			let recipient = bare_recipient(&backend);
			let (first, _) = sealed_to(recipient.clone());
			let (second, _) = sealed_to(recipient);

			assert_ne!(kem_recipient_of(&first).kemct, kem_recipient_of(&second).kemct);
		}

		/// A frame decodes back from the DER its seal encodes.
		#[test]
		fn a_frame_seal_decodes_back_from_its_encoding() -> crate::error::Result<()> {
			let (_, backend) = key_with_backend();
			let (sealed, arrived) = sealed_to(bare_recipient(&backend));
			assert_eq!(AuthEnvelopedData::from_der(&arrived)?, sealed);
			Ok(())
		}
	}
}
