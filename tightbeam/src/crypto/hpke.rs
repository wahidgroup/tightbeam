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
//! [`HpkeSecp256k1Sha3Aes256Gcm`] is the suite of the default provider:
//! DHKEM(secp256k1, HKDF-SHA3-256), HKDF-SHA3-256, and AES-256-GCM.
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
//! - The two AEAD values are registered.
//! - [`KEM_DHKEM_SECP256K1_HKDF_SHA3_256`] and [`KDF_HKDF_SHA3_256`] are this
//!   crate's own, because the registry holds no value for HKDF-SHA3-256 or for
//!   a DHKEM that derives with it.
//! - Both enter the labels of every derivation, so another value derives other keys.
//! - The KEM takes its sizes from DHKEM(secp256k1, HKDF-SHA256), the registered
//!   KEM `0x0016` ([draft-wahby-cfrg-hpke-kem-secp256k1-01][wahby]): `Nsecret`
//!   is 32, and `Nenc`, `Npk`, and `Nsk` are 65, 65, and 32.
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

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::constants::EC_PUBKEY_UNCOMPRESSED_SIZE;
use crate::crypto::aead::{Aead, AeadCore, Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Payload};
use crate::crypto::common::typenum::{Unsigned, U32};
use crate::crypto::common::KeySizeUser;
use crate::crypto::hash::Sha3_256;
use crate::crypto::hkdf::{Hkdf, InvalidLength};
use crate::crypto::k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use crate::crypto::k256::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey};
use crate::crypto::k256::Secp256k1;
use crate::crypto::kdf::{EcdhSecret, HkdfSha3_256, KdfError};
use crate::crypto::secret::{Secret, SecretSlice};
use crate::random::{CryptoRngCore, OsRng, RngWrapper};
use crate::zeroize::{Zeroize, Zeroizing};
use crate::Errorizable;
use crate::ZeroizingBytes;

#[cfg(feature = "x509")]
use crate::asn1::ObjectIdentifier;
#[cfg(feature = "x509")]
use crate::constants::TIGHTBEAM_HPKE_FRAME_INFO;
#[cfg(feature = "x509")]
use crate::der::oid::AssociatedOid;

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

/// DHKEM(secp256k1, HKDF-SHA3-256), under this crate's own KEM identifier.
///
/// The IANA registry holds no value for this KEM, and it has no range for
/// private use. This value sits in the unassigned range.
pub const KEM_DHKEM_SECP256K1_HKDF_SHA3_256: u16 = 0xFF16;

/// HKDF-SHA3-256, under this crate's own KDF identifier.
///
/// The IANA registry holds no value for this KDF, and it has no range for
/// private use. This value sits in the unassigned range.
pub const KDF_HKDF_SHA3_256: u16 = 0xFF01;

/// A two-stage key derivation function of an HPKE suite
/// ([RFC 9180 §4][rfc9180-4]).
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

impl HpkeKdf for HkdfSha3_256 {
	const KDF_ID: u16 = KDF_HKDF_SHA3_256;

	const EXTRACT_SIZE: usize = 32;

	fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
		let (mut extracted, _) = Hkdf::<Sha3_256>::extract(Some(salt), ikm);
		let prk = Zeroizing::new(extracted.to_vec());
		extracted.as_mut_slice().zeroize();
		prk
	}

	fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
		let keyed = Hkdf::<Sha3_256>::from_prk(prk).map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
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

/// A KDF that a DHKEM on curve `C` derives with, and the identifier of that
/// DHKEM ([RFC 9180 §7.1][rfc9180-7.1]).
///
/// A DHKEM is named by its curve and its KDF, so the pair is the one home of
/// the KEM identifier.
///
/// [rfc9180-7.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1
pub trait DhKemKdf<C>: HpkeKdf {
	/// The identifier of the DHKEM in the HPKE KEM registry.
	const KEM_ID: u16;
}

impl DhKemKdf<Secp256k1> for HkdfSha3_256 {
	const KEM_ID: u16 = KEM_DHKEM_SECP256K1_HKDF_SHA3_256;
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
	type KemKdf: DhKemKdf<Self::Curve>;

	/// The KDF of the key schedule.
	type Kdf: HpkeKdf;

	/// The AEAD that seals the message.
	type Aead: HpkeAead;
}

/// The suite of a DHKEM on curve `C` under KDF `K`, the same KDF for the key
/// schedule, and AEAD `A`.
pub struct DhKemSuite<C, K, A>(PhantomData<(C, K, A)>);

impl<C, K, A> HpkeSuite for DhKemSuite<C, K, A>
where
	C: Curve<FieldBytesSize = U32> + CurveArithmetic,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	K: DhKemKdf<C>,
	A: HpkeAead,
{
	type Curve = C;
	type KemKdf = K;
	type Kdf = K;
	type Aead = A;
}

/// DHKEM(secp256k1, HKDF-SHA3-256), HKDF-SHA3-256, and AES-256-GCM.
///
/// The KEM and KDF identifiers of this suite are this crate's own. See
/// [`KEM_DHKEM_SECP256K1_HKDF_SHA3_256`] and [`KDF_HKDF_SHA3_256`].
pub type HpkeSecp256k1Sha3Aes256Gcm = DhKemSuite<Secp256k1, HkdfSha3_256, Aes256Gcm>;

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
	/// The scope of the DHKEM of suite `S`, whose `suite_id` is
	/// `"KEM" || I2OSP(kem_id, 2)` ([RFC 9180 §4.1][rfc9180-4.1]).
	///
	/// [rfc9180-4.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-4.1
	fn kem<S>() -> Self
	where
		S: HpkeSuite<KemKdf = K>,
		K: DhKemKdf<S::Curve>,
	{
		let kem_id = K::KEM_ID.to_be_bytes();
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
		let kem_id = <S::KemKdf as DhKemKdf<S::Curve>>::KEM_ID.to_be_bytes();
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
	/// message and nothing else ([RFC 9180 §9.2.3][rfc9180-9.2.3]). The nonce
	/// of a single-shot context is fixed by the key schedule, so a second
	/// message under one ephemeral would repeat it.
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
		let shared_secret = dh.kem_shared_secret::<S>(&encapsulated_key, recipient)?;

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
	/// - `rng`: the cryptographically secure RNG that draws the ephemeral. `None` uses `OsRng`.
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
	/// - The [`EcdhSecret::open`] set.
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
	fn kem_shared_secret<S>(
		self,
		encapsulated_key: &PublicKey<S::Curve>,
		recipient: &PublicKey<S::Curve>,
	) -> Result<ZeroizingBytes>
	where
		S: HpkeSuite,
	{
		let labeled = Labeled::<S::KemKdf>::kem::<S>();
		let enc = encapsulated_key.to_encoded_point(false);
		let recipient = recipient.to_encoded_point(false);
		let kem_context = [enc.as_bytes(), recipient.as_bytes()].concat();

		let eae_prk = self.with(|dh| labeled.extract(b"", b"eae_prk", dh));
		labeled.expand(&eae_prk, b"shared_secret", &kem_context, S::KemKdf::EXTRACT_SIZE)
	}

	/// Open an HPKE `message` with this precomputed `DH(skR, pkE)` output.
	///
	/// This splits the DH step out of [`HpkeSecretKeyOps::open`], so the
	/// recipient private key can live behind an external boundary such as an
	/// HSM, a KMS, or a secure enclave. The caller runs three steps:
	///
	/// 1. Parse the message with [`HpkeMessage::from_bytes`], which validates `pkE`.
	/// 2. Obtain the DH output of [`HpkeMessage::encapsulated_key`] out of band,
	///    for example from `SigningKeyProvider::key_agreement`.
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
		let shared_secret = self.kem_shared_secret::<S>(message.encapsulated_key(), recipient)?;
		let schedule = KeySchedule::<S>::derive(&shared_secret, info.as_ref())?;
		schedule.open(aad.as_ref(), message.ciphertext())
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
		// The scalar leaves the key as a plain array, so it is wiped once the
		// wiping buffer holds its copy (CWE-226).
		let mut scalar = secret_key.to_bytes();
		let bytes = Secret::from(scalar.to_vec());
		scalar.as_mut_slice().zeroize();
		bytes
	}
}

#[cfg(feature = "x509")]
crate::define_oid_wrapper!(
	/// The OID of [`HpkeSecp256k1Sha3Aes256Gcm`] in base mode.
	HpkeSecp256k1Sha3Aes256GcmOid,
	crate::oids::HPKE_SECP256K1_SHA3_256_AES_256_GCM
);

/// Seals messages to a recipient's secp256k1 public key with HPKE.
///
/// It implements [`Encryptor`](crate::crypto::aead::Encryptor), so
/// [`FrameBuilder::with_encryptor`] accepts it for asymmetric message
/// encryption.
///
/// # Example
///
/// ```
/// use tightbeam::crypto::aead::{DecryptContent, Encryptor};
/// use tightbeam::crypto::hpke::{HpkeDecryptor, HpkeEncryptor};
/// use tightbeam::crypto::k256::SecretKey;
/// use tightbeam::crypto::secret::ToInsecure;
/// use tightbeam::random::OsRng;
///
/// let recipient = SecretKey::random(&mut OsRng);
/// let encryptor = HpkeEncryptor::new(recipient.public_key());
/// let info = encryptor.encrypt_content(b"hello", [], None)?;
///
/// let decryptor = HpkeDecryptor::new(recipient);
/// let plaintext = decryptor.decrypt_content(&info)?.to_insecure();
/// assert_eq!(&plaintext[..], b"hello");
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
///
/// [`FrameBuilder::with_encryptor`]: crate::builder::FrameBuilder::with_encryptor
#[cfg(feature = "x509")]
pub struct HpkeEncryptor {
	recipient_pubkey: PublicKey<Secp256k1>,
}

#[cfg(feature = "x509")]
impl HpkeEncryptor {
	/// Create an HPKE encryptor for `recipient_pubkey`.
	pub fn new(recipient_pubkey: impl Into<PublicKey<Secp256k1>>) -> Self {
		Self { recipient_pubkey: recipient_pubkey.into() }
	}

	/// Create an encryptor from SEC1-encoded public key bytes.
	///
	/// # Errors
	///
	/// - [`HpkeError::InvalidPublicKey`] -- `bytes` fails SEC1 decoding, or it is off the curve.
	pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		let parsed = PublicKey::<Secp256k1>::from_sec1_bytes(bytes.as_ref());
		let pubkey = parsed.map_err(HpkeError::InvalidPublicKey)?;
		Ok(Self::new(pubkey))
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Encryptor<HpkeSecp256k1Sha3Aes256GcmOid> for HpkeEncryptor {
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		_nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> crate::error::Result<crate::EncryptedContentInfo> {
		let recipient = &self.recipient_pubkey;
		let sealed = recipient.seal::<HpkeSecp256k1Sha3Aes256Gcm>(TIGHTBEAM_HPKE_FRAME_INFO, b"", data, None)?;

		// The encrypted content holds the full HPKE message, which is the
		// encapsulated key followed by the ciphertext.
		let encrypted_bytes = sealed.to_bytes();
		let content_type = content_type.unwrap_or(crate::oids::DATA);

		// The algorithm carries no nonce parameter and `_nonce` goes unread,
		// because the key schedule derives the nonce.
		let oid = HpkeSecp256k1Sha3Aes256GcmOid::OID;
		let content_enc_alg = crate::AlgorithmIdentifier { oid, parameters: None };
		let encrypted_content = Some(crate::der::asn1::OctetString::new(encrypted_bytes)?);

		Ok(crate::EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
	}
}

/// Opens HPKE messages with the recipient's secp256k1 secret key.
///
/// It implements [`Decryptor`](crate::crypto::aead::Decryptor), so a frame
/// decrypts with it through [`Frame::decrypt`](crate::Frame::decrypt).
///
/// See [`HpkeEncryptor`] for a round trip.
#[cfg(feature = "x509")]
pub struct HpkeDecryptor {
	secret_key: SecretKey<Secp256k1>,
}

#[cfg(feature = "x509")]
impl HpkeDecryptor {
	/// Create an HPKE decryptor that holds `secret_key`.
	pub fn new(secret_key: impl Into<SecretKey<Secp256k1>>) -> Self {
		Self { secret_key: secret_key.into() }
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Decryptor for HpkeDecryptor {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		HpkeSecp256k1Sha3Aes256GcmOid::OID
	}

	fn open(&self, content: crate::crypto::aead::CheckedContent<'_>) -> crate::error::Result<SecretSlice<u8>> {
		let encrypted_bytes = content
			.info()
			.encrypted_content
			.as_ref()
			.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
			.as_bytes();

		let message = HpkeMessage::<HpkeSecp256k1Sha3Aes256Gcm>::from_bytes(encrypted_bytes)?;
		Ok(self.secret_key.open(&message, TIGHTBEAM_HPKE_FRAME_INFO, b"")?)
	}
}

/// HPKE decryptor driven by a precomputed `DH(skR, pkE)` output.
///
/// It pairs with [`HpkeMessage::encapsulated_key`] and an async key-agreement
/// backend (`SigningKeyProvider::key_agreement`) so the recipient private key
/// can stay inside an HSM, a KMS, or a secure enclave. It opens the suite that
/// [`HpkeSecp256k1Sha3Aes256GcmOid`] names.
#[cfg(feature = "x509")]
pub struct HpkeSharedSecretDecryptor {
	shared_secret: EcdhSecret,
	recipient_pubkey: PublicKey<Secp256k1>,
}

#[cfg(feature = "x509")]
impl HpkeSharedSecretDecryptor {
	/// Build a decryptor from a precomputed DH output and the public key of
	/// the recipient that computed it.
	pub fn new(shared_secret: EcdhSecret, recipient_pubkey: impl Into<PublicKey<Secp256k1>>) -> Self {
		Self { shared_secret, recipient_pubkey: recipient_pubkey.into() }
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Decryptor for HpkeSharedSecretDecryptor {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		HpkeSecp256k1Sha3Aes256GcmOid::OID
	}

	fn open(&self, content: crate::crypto::aead::CheckedContent<'_>) -> crate::error::Result<SecretSlice<u8>> {
		let encrypted_bytes = content
			.info()
			.encrypted_content
			.as_ref()
			.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
			.as_bytes();

		let message = HpkeMessage::<HpkeSecp256k1Sha3Aes256Gcm>::from_bytes(encrypted_bytes)?;
		let shared_secret = self.shared_secret.duplicate();
		let recipient = &self.recipient_pubkey;
		Ok(shared_secret.open(recipient, &message, TIGHTBEAM_HPKE_FRAME_INFO, b"")?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::aead::Key;
	use crate::crypto::common::typenum::U48;
	use crate::crypto::k256::sha2::{Sha256, Sha512};
	use crate::crypto::secret::ToInsecure;
	use aead::{AeadInPlace, Tag};
	use rand_core::{CryptoRng, RngCore};

	/// The suite of the default provider.
	type Suite = HpkeSecp256k1Sha3Aes256Gcm;

	const INFO: &[u8] = b"tb/hpke/test";

	/// HKDF-SHA256, the KDF of the registered DHKEM on secp256k1. The
	/// published vectors of that KEM check the construction, and the SHA3-256
	/// suite runs the same code under another hash.
	struct HkdfSha256;

	impl HpkeKdf for HkdfSha256 {
		const KDF_ID: u16 = 0x0001;
		const EXTRACT_SIZE: usize = 32;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
			Zeroizing::new(prk.to_vec())
		}

		fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			let keyed = Hkdf::<Sha256>::from_prk(prk).map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
			let mut okm = Zeroizing::new(vec![0u8; len]);
			keyed.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;
			Ok(okm)
		}
	}

	impl DhKemKdf<Secp256k1> for HkdfSha256 {
		const KEM_ID: u16 = 0x0016;
	}

	/// HKDF-SHA512, the KDF `0x0003` of RFC 9180 Table 3, which two of the
	/// Appendix A suites derive with.
	struct HkdfSha512;

	impl HpkeKdf for HkdfSha512 {
		const KDF_ID: u16 = 0x0003;
		const EXTRACT_SIZE: usize = 64;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
			Zeroizing::new(prk.to_vec())
		}

		fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			let keyed = Hkdf::<Sha512>::from_prk(prk).map_err(|_| KdfError::DerivationFailed(InvalidLength))?;
			let mut okm = Zeroizing::new(vec![0u8; len]);
			keyed.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;
			Ok(okm)
		}
	}

	/// DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	type RegisteredAes128 = DhKemSuite<Secp256k1, HkdfSha256, Aes128Gcm>;

	/// DHKEM(secp256k1, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
	type RegisteredAes256 = DhKemSuite<Secp256k1, HkdfSha256, Aes256Gcm>;

	/// HKDF-SHA3-256 under another KEM identifier, and `LEN_SHIFT` bytes away
	/// from a 12-byte request, as a relabeled or a faulty provider KDF is.
	struct AlteredKdf<const KEM_SHIFT: u16, const LEN_SHIFT: i8>;

	impl<const KEM_SHIFT: u16, const LEN_SHIFT: i8> HpkeKdf for AlteredKdf<KEM_SHIFT, LEN_SHIFT> {
		const KDF_ID: u16 = KDF_HKDF_SHA3_256;
		const EXTRACT_SIZE: usize = 32;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			HkdfSha3_256::extract(salt, ikm)
		}

		fn expand(prk: &[u8], info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			let shift = isize::from(LEN_SHIFT) * isize::from(len == 12);
			HkdfSha3_256::expand(prk, info, len.saturating_add_signed(shift))
		}
	}

	impl<const KEM_SHIFT: u16, const LEN_SHIFT: i8> DhKemKdf<Secp256k1> for AlteredKdf<KEM_SHIFT, LEN_SHIFT> {
		const KEM_ID: u16 = KEM_DHKEM_SECP256K1_HKDF_SHA3_256 + KEM_SHIFT;
	}

	/// The algorithms of [`Suite`] under another KEM identifier.
	type Relabeled = DhKemSuite<Secp256k1, AlteredKdf<1, 0>, Aes256Gcm>;

	/// A KDF with no bound on its output, so the two-byte length frame of
	/// `LabeledExpand` is the one refusal a long request meets.
	struct UnboundedKdf;

	impl HpkeKdf for UnboundedKdf {
		const KDF_ID: u16 = 0xFFFD;
		const EXTRACT_SIZE: usize = 32;

		fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
			HkdfSha3_256::extract(salt, ikm)
		}

		fn expand(_prk: &[u8], _info: &[u8], len: usize) -> core::result::Result<ZeroizingBytes, KdfError> {
			Ok(Zeroizing::new(vec![0u8; len]))
		}
	}

	impl DhKemKdf<Secp256k1> for UnboundedKdf {
		const KEM_ID: u16 = 0xFFFD;
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

	/// The keys and the `info` of [`AES_256_GCM_VECTOR`] under [`Suite`]. An
	/// independent implementation of RFC 9180 over HKDF-SHA3-256 computed the
	/// three derived values, after it reproduced both published vectors.
	const SHA3_SUITE_VECTOR: Vector = Vector {
		shared_secret: "928f056b2e9e4ffc60c202f140bccc2c8ca2b532ddd7ab04aaa289163311ab11",
		key: "a7b027a95f1670f92223d499bd37b3b82f9979436a6e341e5536b4b236c81d2b",
		base_nonce: "28a60f79b7e449790ab1cf16",
		..AES_256_GCM_VECTOR
	};

	/// The associated data and the plaintext of the sealed known answers.
	const KNOWN_AAD: &[u8] = b"tb/hpke/test/aad";
	const KNOWN_PLAINTEXT: &[u8] = b"known answer";

	/// What [`AES_256_GCM_VECTOR`] seals [`KNOWN_PLAINTEXT`] to under
	/// [`KNOWN_AAD`], from the same independent implementation and an
	/// independent AES-GCM.
	const REGISTERED_CIPHERTEXT: &str = "e0080fb223a2a45fe65407abafefade00abf2e6b11b7428df396d117";

	/// What [`SHA3_SUITE_VECTOR`] seals [`KNOWN_PLAINTEXT`] to under
	/// [`KNOWN_AAD`], from the same source.
	const SHA3_SUITE_CIPHERTEXT: &str = "f742fee844fad9743f6d2fece69bb3e0ed60cc352d4dc544216993f6";

	/// The bytes a hex string names.
	fn unhex(hex: &str) -> Vec<u8> {
		let digits = hex.as_bytes().chunks(2);
		let bytes = digits.map(|pair| {
			let pair = core::str::from_utf8(pair).expect("a vector is ASCII");
			u8::from_str_radix(pair, 16).expect("a vector is hex")
		});
		bytes.collect()
	}

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
			let shared_secret = dh.kem_shared_secret::<S>(encapsulated_key, recipient)?;
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

	/// The SHA3-256 suite derives what an independent implementation derives
	/// under the same identifiers, so the hash and the crate's two
	/// identifiers are the whole difference from the registered suite.
	#[test]
	fn the_sha3_suite_matches_its_known_answer() -> Result<()> {
		let by_sender = Derived::by_sender::<Suite>(&SHA3_SUITE_VECTOR)?;
		let by_recipient = Derived::by_recipient::<Suite>(&SHA3_SUITE_VECTOR)?;
		assert_eq!(by_sender, Derived::published(&SHA3_SUITE_VECTOR));
		assert_eq!(by_recipient, Derived::published(&SHA3_SUITE_VECTOR));
		Ok(())
	}

	/// The sealed bytes are the encapsulated key the vector publishes and the
	/// ciphertext an independent AES-GCM produces under the derived key and
	/// nonce, so the cipher is keyed and nonced as the schedule derived.
	#[test]
	fn a_sealed_message_matches_its_known_answer() -> Result<()> {
		let registered = AES_256_GCM_VECTOR.sealed::<RegisteredAes256>()?.to_bytes();
		let sha3 = SHA3_SUITE_VECTOR.sealed::<Suite>()?.to_bytes();

		let enc = unhex(AES_256_GCM_VECTOR.ephemeral_public);
		assert_eq!(registered, [enc.as_slice(), &unhex(REGISTERED_CIPHERTEXT)].concat());
		assert_eq!(sha3, [enc.as_slice(), &unhex(SHA3_SUITE_CIPHERTEXT)].concat());
		Ok(())
	}

	#[test]
	fn the_recipient_opens_the_known_answer() -> Result<()> {
		let enc = unhex(SHA3_SUITE_VECTOR.ephemeral_public);
		let wire = [enc.as_slice(), &unhex(SHA3_SUITE_CIPHERTEXT)].concat();
		let message = HpkeMessage::<Suite>::from_bytes(wire)?;

		let opened = SHA3_SUITE_VECTOR
			.recipient()
			.open(&message, unhex(SHA3_SUITE_VECTOR.info), KNOWN_AAD)?;
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

	impl<const ID: u16, K: HpkeKdf> DhKemKdf<Secp256k1> for KemOf<ID, K> {
		const KEM_ID: u16 = ID;
	}

	/// The suite of an Appendix A vector: the KEM `ID` over `KemK`, the KDF
	/// `K`, and the AEAD `A`.
	struct RfcSuite<const ID: u16, KemK, K, A>(PhantomData<(KemK, K, A)>);

	impl<const ID: u16, KemK: HpkeKdf, K: HpkeKdf, A: HpkeAead> HpkeSuite for RfcSuite<ID, KemK, K, A> {
		type Curve = Secp256k1;
		type KemKdf = KemOf<ID, KemK>;
		type Kdf = K;
		type Aead = A;
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

	/// A message that cannot carry an encapsulated key and a tag is refused
	/// at the parse, ahead of any DH.
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

	/// The parse validates the encapsulated key, so a point off the curve and
	/// a compressed encoding at the uncompressed width are both refused.
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
		type Wide = DhKemSuite<Secp256k1, HkdfSha3_256, WideKeyCipher>;
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
		type Overlong = DhKemSuite<Secp256k1, AlteredKdf<0, 1>, Aes256Gcm>;
		type Short = DhKemSuite<Secp256k1, AlteredKdf<0, -1>, Aes256Gcm>;
		let (_, public) = keypair();

		let overlong = public.seal::<Overlong>(INFO, b"", b"plaintext", None);
		let short = public.seal::<Short>(INFO, b"", b"plaintext", None);
		assert!(matches!(overlong, Err(HpkeError::Kdf(_))));
		assert!(matches!(short, Err(HpkeError::Kdf(_))));
	}

	/// `LabeledExpand` frames its length in two bytes, so a longer request is
	/// refused ahead of the KDF. The KDF here answers any length, because
	/// HKDF-SHA3-256 refuses past 8,160 bytes on its own and would hide the
	/// frame.
	#[test]
	fn a_labeled_expand_past_two_length_bytes_is_refused() {
		type Unbounded = DhKemSuite<Secp256k1, UnboundedKdf, Aes256Gcm>;
		let labeled = Labeled::<UnboundedKdf>::schedule::<Unbounded>();
		let prk = [0x11u8; 32];

		let widest = labeled.expand(&prk, b"key", b"", usize::from(u16::MAX));
		let past_the_frame = labeled.expand(&prk, b"key", b"", usize::from(u16::MAX) + 1);
		assert!(widest.is_ok());
		assert!(matches!(past_the_frame, Err(HpkeError::Kdf(_))));
	}

	/// A byte stream that repeats from its seed. The OS source answers fresh
	/// bytes on every draw, so a test of whose RNG `seal` reads needs this
	/// double.
	struct SeededStream(u8);

	impl RngCore for SeededStream {
		fn next_u32(&mut self) -> u32 {
			rand_core::impls::next_u32_via_fill(self)
		}

		fn next_u64(&mut self) -> u64 {
			rand_core::impls::next_u64_via_fill(self)
		}

		fn fill_bytes(&mut self, dest: &mut [u8]) {
			self.0 = self.0.wrapping_add(1);
			dest.fill(self.0);
		}

		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
			self.fill_bytes(dest);
			Ok(())
		}
	}

	impl CryptoRng for SeededStream {}

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

	/// The frame adapters seal and open under the frame context and stamp the
	/// suite OID, so a message sealed under another `info` stays closed to
	/// them.
	#[cfg(feature = "x509")]
	#[test]
	fn the_frame_adapters_round_trip_under_the_frame_context() -> crate::error::Result<()> {
		use crate::crypto::aead::{DecryptContent, Encryptor};
		use crate::oids::HPKE_SECP256K1_SHA3_256_AES_256_GCM;

		let (secret, public) = keypair();
		let encryptor = HpkeEncryptor::from_bytes(public.to_encoded_point(true))?;
		let malformed = HpkeEncryptor::from_bytes([0xFFu8; 33]);
		let decryptor = HpkeDecryptor::new(secret);
		let mut info = encryptor.encrypt_content(b"framed", [], None)?;

		let opened = decryptor.decrypt_content(&info)?.to_insecure();
		let foreign = public.seal::<Suite>(INFO, b"", b"framed", None)?.to_bytes();
		info.encrypted_content = Some(crate::der::asn1::OctetString::new(foreign)?);
		assert_eq!(&opened[..], b"framed");
		assert_eq!(info.content_enc_alg.oid, HPKE_SECP256K1_SHA3_256_AES_256_GCM);
		assert!(matches!(malformed, Err(HpkeError::InvalidPublicKey(_))));
		assert!(decryptor.decrypt_content(&info).is_err());
		Ok(())
	}

	/// Open an HPKE payload with the recipient private key held behind a
	/// `SigningKeyProvider`: the `DH(skR, pkE)` step runs via `key_agreement`,
	/// then the shared-secret decryptor opens it through the standard
	/// `Decryptor`.
	#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh", feature = "tokio"))]
	#[tokio::test]
	async fn shared_secret_decryptor_via_provider() -> crate::error::Result<()> {
		use crate::crypto::aead::{DecryptContent, Encryptor};
		use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;

		let plaintext = b"hsm-backed hpke decryption";
		let (secret, public) = keypair();
		let info = HpkeEncryptor::new(public).encrypt_content(plaintext, [], None)?;
		let wire = info.encrypted_content.as_ref().ok_or(HpkeError::InvalidCiphertext)?.as_bytes();

		let message = HpkeMessage::<Suite>::from_bytes(wire)?;
		let enc = message.encapsulated_key().to_encoded_point(false);
		let provider = Secp256k1KeyProvider::from(Secp256k1SigningKey::from(secret));
		let shared = provider.key_agreement(enc.as_bytes()).await?;

		let decryptor = HpkeSharedSecretDecryptor::new(EcdhSecret::try_from(shared)?, public);
		let opened = decryptor.decrypt_content(&info)?.to_insecure();
		assert_eq!(&opened[..], plaintext);
		Ok(())
	}
}
