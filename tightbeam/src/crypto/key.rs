//! Pluggable key backends for tightbeam transport encryption.
//!
//! A backend may hold its keys in memory, in an HSM, in a KMS, or in an
//! enclave. Each private-key operation is a trait of its own, so the compiler
//! refuses a backend where another operation belongs:
//!
//! - [`KeyBackend`] states what every private-key backend states about
//!   itself: its algorithm and its public key.
//! - [`SigningKeyProvider`] signs a prehash.
//! - [`DiffieHellman`] runs the agreement that a DHKEM decapsulation asks of its key holder.
//!
//! A concrete implementation such as [`EcdsaKeyProvider`] writes the encodings
//! of its algorithm: the DER of its public key and of its signature.

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::fmt::Debug;

#[cfg(all(not(feature = "std"), any(feature = "signature", feature = "aead")))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "aead")]
use core::future::Future;
#[cfg(feature = "aead")]
use core::pin::Pin;
#[cfg(all(feature = "std", any(feature = "signature", feature = "aead")))]
use std::sync::Arc;

use crate::Errorizable;

#[cfg(feature = "signature")]
use crate::marker::{MaybeSend, MaybeSendFuture, MaybeSync};

#[cfg(feature = "signature")]
mod signing {
	pub use crate::crypto::sign::ecdsa::der::{MaxOverhead, MaxSize, Signature as DerSignature};
	pub use crate::crypto::sign::ecdsa::{
		DigestPrimitive, Secp256k1, SignPrimitive, SignatureSize, SigningKey, VerifyPrimitive,
	};
	pub use crate::crypto::sign::elliptic_curve::generic_array::{ArrayLength, GenericArray};
	pub use crate::crypto::sign::elliptic_curve::ops::{Invert, Reduce};
	pub use crate::crypto::sign::elliptic_curve::point::PointCompression;
	pub use crate::crypto::sign::elliptic_curve::scalar::Scalar;
	pub use crate::crypto::sign::elliptic_curve::sec1::ModulusSize;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::subtle::CtOption;
	pub use crate::crypto::sign::elliptic_curve::{
		AffinePoint, CurveArithmetic, Error as EllipticCurveError, FieldBytesSize, PrimeCurve,
	};
	pub use crate::crypto::sign::{
		Error as SignatureError, Keypair, PrehashSigner, SignatureAlgorithmIdentifier, SignatureEncoding,
	};

	#[cfg(feature = "ecdh")]
	pub use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
	#[cfg(feature = "ecdh")]
	pub use crate::crypto::sign::elliptic_curve::PublicKey;
}

#[cfg(feature = "signature")]
use signing::*;

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
mod encryption {
	pub use crate::asn1::{AuthEnvelopedData, ObjectIdentifier};
	pub use crate::crypto::aead::{AeadAlgorithm, CheckedContent, Decryptor, Encryptor};
	pub use crate::crypto::cms::ContentEncryption;
	pub(crate) use crate::crypto::cms::OwnedKek;
	pub use crate::crypto::profiles::{CryptoProvider, KeyWrapAlgorithm};
	pub use crate::oids::DATA;
	pub use crate::random::CryptoRngCore;
	pub use crate::TightBeamError;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use encryption::*;

#[cfg(any(feature = "signature", feature = "aead"))]
mod common {
	pub use crate::crypto::common::typenum::Unsigned;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::spki::AlgorithmIdentifierOwned;

	#[cfg(feature = "signature")]
	pub use crate::spki::EncodePublicKey;
}

#[cfg(any(feature = "signature", feature = "aead"))]
use common::*;

#[cfg(any(all(feature = "signature", feature = "ecdh"), feature = "aead"))]
use crate::crypto::secret::SecretSlice;

#[cfg(all(feature = "kem", feature = "hpke", feature = "signature"))]
use crate::crypto::hpke::DhKemSecp256k1Enc;
#[cfg(all(feature = "kem", feature = "hpke", feature = "signature"))]
use crate::crypto::kdf::EcdhSecret;
#[cfg(all(feature = "kem", feature = "hpke", feature = "signature"))]
use kem::{Decapsulator, Error as KemError, SharedSecret};

/// Errors from key provider operations.
#[derive(Errorizable, Debug)]
pub enum KeyError {
	/// SPKI encoding or decoding failed.
	#[error("SPKI error: {0}")]
	SpkiError(crate::spki::Error),

	/// An elliptic curve operation failed.
	#[cfg(feature = "signature")]
	#[error("Elliptic curve error: {0}")]
	EllipticCurveError(EllipticCurveError),

	/// A signature or ECDSA operation failed, for example on invalid key bytes.
	#[cfg(feature = "signature")]
	#[error("Signature error: {0}")]
	SignatureError(SignatureError),

	/// A key-encryption key of another size than the key of its wrap
	/// ([`KeyWrapAlgorithm::KekSize`]).
	///
	/// [`KeyWrapAlgorithm::KekSize`]: crate::crypto::profiles::KeyWrapAlgorithm::KekSize
	#[cfg(feature = "aead")]
	#[error("Key-encryption key length mismatch: {0}")]
	KekLength(crate::error::ReceivedExpectedError<usize, usize>),

	/// A length a key wrap refuses: a key shorter than the wrap's minimum or
	/// not a whole number of 64-bit blocks (RFC 3394 § 2), or a buffer of
	/// another size than the unwrapped key.
	#[cfg(feature = "aead")]
	#[error("Key wrap length mismatch: {0}")]
	WrapLength(crate::error::ReceivedExpectedError<usize, usize>),

	/// An AES key wrap or unwrap failed. On unwrap it marks a failed integrity
	/// check (RFC 3394 § 2.2.2), so the wrapped key was altered or another KEK
	/// wrapped it.
	#[cfg(feature = "aead")]
	#[error("AES key wrap operation failed: {0}")]
	WrapFailed(crate::crypto::aead::aes_kw::Error),

	/// The signing key material has the wrong length for the curve.
	#[cfg(feature = "signature")]
	#[error("Signing key length mismatch: {0}")]
	KeyLengthError(crate::error::ReceivedExpectedError<usize, usize>),
}

crate::impl_from!(crate::spki::Error => KeyError::SpkiError);
crate::impl_from!(#[cfg(feature = "signature")] EllipticCurveError => KeyError::EllipticCurveError);
crate::impl_from!(#[cfg(feature = "signature")] SignatureError => KeyError::SignatureError);

/// A signing key given as raw bytes or as a key provider.
///
/// [`SigningKeySpec::Bytes`] suits configuration in a const context, such as a
/// `const` item, and [`SigningKeySpec::Provider`] holds a backend built at run
/// time.
#[cfg(feature = "signature")]
#[derive(Clone)]
pub enum SigningKeySpec {
	/// Raw key bytes, such as a 32-byte secp256k1 scalar.
	Bytes(&'static [u8]),

	/// A key provider instance, such as an HSM or KMS backend.
	Provider(Arc<dyn SigningKeyProvider>),
}

// A `SigningKeySpec::Bytes` holds a raw signing key, so its `Debug` prints the
// variant and the byte length only (CWE-532).
#[cfg(feature = "signature")]
impl Debug for SigningKeySpec {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Bytes(bytes) => f.debug_struct("SigningKeySpec::Bytes").field("len", &bytes.len()).finish(),
			Self::Provider(_) => f.write_str("SigningKeySpec::Provider(..)"),
		}
	}
}

#[cfg(feature = "signature")]
impl SigningKeySpec {
	/// Convert this key specification to a key provider for the ECDSA curve
	/// `C`.
	///
	/// - [`SigningKeySpec::Bytes`] builds an ECDSA signing key from the raw
	///   bytes and wraps it in an [`EcdsaKeyProvider`].
	/// - [`SigningKeySpec::Provider`] returns a clone of the provider handle it holds.
	///
	/// # Type Parameters
	///
	/// - `C`: the elliptic curve type, such as `k256::Secp256k1`.
	///
	/// # Errors
	///
	/// - [`KeyError::KeyLengthError`] -- the bytes are not the curve's field size.
	/// - [`KeyError::SignatureError`] -- the bytes are not a valid signing key.
	pub fn to_provider<C>(&self) -> Result<Arc<dyn SigningKeyProvider>, KeyError>
	where
		C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
		Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
		SignatureSize<C>: ArrayLength<u8>,
		MaxSize<C>: ArrayLength<u8>,
		<FieldBytesSize<C> as core::ops::Add>::Output: core::ops::Add<MaxOverhead> + ArrayLength<u8>,
		FieldBytesSize<C>: ModulusSize,
		AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
		SigningKey<C>: PrehashSigner<DerSignature<C>> + Keypair + Send + Sync + Debug + 'static,
		<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
		DerSignature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync + 'static,
	{
		match self {
			SigningKeySpec::Bytes(bytes) => {
				let expected = FieldBytesSize::<C>::USIZE;
				if bytes.len() != expected {
					return Err(KeyError::KeyLengthError((bytes.len(), expected).into()));
				}

				let field_bytes = GenericArray::from_slice(bytes);
				let signing_key = SigningKey::<C>::from_bytes(field_bytes)?;
				Ok(Arc::new(EcdsaKeyProvider::from(signing_key)))
			}
			SigningKeySpec::Provider(provider) => Ok(Arc::clone(provider)),
		}
	}
}

/// What every private-key backend states about itself, shared by the
/// signing and the key-agreement backends.
///
/// An implementation keeps its private key inside its boundary, so a Hardware
/// Security Module (HSM), a Key Management Service (KMS), or a secure enclave
/// can hold it. The operation the key performs is a trait of its own that
/// names this one as its supertrait, such as [`SigningKeyProvider`].
///
/// # Threading
///
/// The trait requires `Send` and `Sync` on every target except `wasm32`, where
/// the single-threaded executor lets JavaScript-backed providers (WebAuthn,
/// wallets, remote KMS bridges) implement it.
#[cfg(feature = "signature")]
pub trait KeyBackend: MaybeSend + MaybeSync + Debug {
	/// Returns the algorithm identifier for this key.
	fn algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Returns the public key as a DER SubjectPublicKeyInfo.
	///
	/// The read of the public key is synchronous, unlike a private-key
	/// operation, so an identity checks it against its certificate when the
	/// identity is built. A remote backend fetches it once, when the backend
	/// is built.
	///
	/// # Errors
	///
	/// - [`KeyError`] -- the backend fails to encode the public key.
	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError>;
}

/// A shared backend is a backend, so one handle serves every endpoint that
/// holds the same key.
#[cfg(feature = "signature")]
impl<T: KeyBackend + ?Sized> KeyBackend for Arc<T> {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		T::algorithm(self)
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		T::to_public_key_bytes(self)
	}
}

/// A backend whose private key signs.
///
/// The signature is async, so a remote backend fits the same API, and the
/// byte encoding admits any signature algorithm. The compiler refuses a
/// `dyn SigningKeyProvider` where a `dyn DiffieHellman` belongs, and
/// `CmsIdentityPair::new` refuses one key in both, so a backend of both,
/// such as [`EcdsaKeyProvider`], serves one identity per key.
#[cfg(feature = "signature")]
pub trait SigningKeyProvider: KeyBackend {
	/// Signs a precomputed digest (prehash) with this provider's private key.
	///
	/// The canonical tightbeam convention hashes content exactly once (see
	/// [`sign_canonical`]). Providers MUST sign the given prehash directly, so
	/// the produced signature matches the advertised signature-algorithm OID
	/// whatever the backend.
	///
	/// - `prehash`: the digest of the content to sign.
	/// - An ECDSA result MUST be the DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3).
	/// - Its `s` MUST lie in the low half of the curve order.
	///
	/// # Errors
	///
	/// - [`KeyError`] -- the backend fails to sign `prehash`.
	///
	/// [`sign_canonical`]: crate::crypto::sign::CanonicalSigner::sign_canonical
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>>;
}

/// A shared provider is a provider, so one handle serves every endpoint that
/// signs with the same key.
#[cfg(feature = "signature")]
impl<T: SigningKeyProvider + ?Sized> SigningKeyProvider for Arc<T> {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		T::sign_prehash(self, prehash)
	}
}

/// The one operation a DHKEM asks of the holder of its recipient key: the
/// Diffie-Hellman agreement on the curve `C` (RFC 9180 §4.1).
///
/// The house [`EcdsaKeyProvider`] implements it, and a KMS implements it and
/// keeps the scalar inside its boundary. The result is a [`SecretSlice`], so
/// the shared secret zeroizes on drop (CWE-212).
#[cfg(all(feature = "signature", feature = "ecdh"))]
pub trait DiffieHellman<C: CurveArithmetic>: KeyBackend {
	/// The x-coordinate of the product of this backend's scalar and `peer`.
	///
	/// # Errors
	///
	/// - [`KeyError`] -- the backend fails the agreement.
	fn agree<'a>(&'a self, peer: &'a PublicKey<C>) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>>;
}

/// A shared backend agrees as the backend it shares.
#[cfg(all(feature = "signature", feature = "ecdh"))]
impl<C: CurveArithmetic, T: DiffieHellman<C> + ?Sized> DiffieHellman<C> for Arc<T> {
	fn agree<'a>(&'a self, peer: &'a PublicKey<C>) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
		T::agree(self, peer)
	}
}

/// An ECDSA key provider that signs, and runs ECDH key agreement under the
/// `ecdh` feature.
///
/// It wraps an ECDSA signing key on any curve `C`. It is the recommended
/// provider for the TightBeam transport handshakes.
///
/// # Type Parameters
///
/// - `C`: the elliptic curve type, such as `k256::Secp256k1` or `p256::NistP256`.
#[cfg(all(feature = "signature", feature = "secp256k1"))]
pub struct EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	signing_key: SigningKey<C>,
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> From<SigningKey<C>> for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn from(signing_key: SigningKey<C>) -> Self {
		EcdsaKeyProvider { signing_key }
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> Debug for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("EcdsaKeyProvider")
			.field("curve", &core::any::type_name::<C>())
			.finish_non_exhaustive()
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> KeyBackend for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
	SignatureSize<C>: ArrayLength<u8>,
	MaxSize<C>: ArrayLength<u8>,
	<FieldBytesSize<C> as core::ops::Add>::Output: core::ops::Add<MaxOverhead> + ArrayLength<u8>,
	FieldBytesSize<C>: ModulusSize,
	AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
	SigningKey<C>: PrehashSigner<DerSignature<C>> + Keypair + Send + Sync + Debug,
	<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
	DerSignature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync,
{
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: DerSignature::<C>::ALGORITHM_OID, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		let encoded = self.signing_key.verifying_key().to_public_key_der()?;
		Ok(encoded.into_vec())
	}
}

#[cfg(all(feature = "signature", feature = "secp256k1"))]
impl<C> SigningKeyProvider for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
	SignatureSize<C>: ArrayLength<u8>,
	MaxSize<C>: ArrayLength<u8>,
	<FieldBytesSize<C> as core::ops::Add>::Output: core::ops::Add<MaxOverhead> + ArrayLength<u8>,
	FieldBytesSize<C>: ModulusSize,
	AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
	SigningKey<C>: PrehashSigner<DerSignature<C>> + Keypair + Send + Sync + Debug,
	<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
	DerSignature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync,
{
	/// The ECDSA signer of the curve returns `s` in the low half of the order,
	/// and the result is its DER encoding.
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let result = self
			.signing_key
			.sign_prehash(prehash)
			.map(|signature: DerSignature<C>| signature.to_vec())
			.map_err(KeyError::from);

		Box::pin(async move { result })
	}
}

/// The agreement runs before the future is built, so no copy of the scalar
/// lives across an await, and a cancelled agreement leaves none behind
/// (CWE-226).
#[cfg(all(feature = "signature", feature = "secp256k1", feature = "ecdh"))]
impl<C> DiffieHellman<C> for EcdsaKeyProvider<C>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression + AssociatedOid + Send + Sync + 'static,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C> + Reduce<C::Uint>,
	SignatureSize<C>: ArrayLength<u8>,
	MaxSize<C>: ArrayLength<u8>,
	<FieldBytesSize<C> as core::ops::Add>::Output: core::ops::Add<MaxOverhead> + ArrayLength<u8>,
	FieldBytesSize<C>: ModulusSize,
	AffinePoint<C>: VerifyPrimitive<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
	SigningKey<C>: PrehashSigner<DerSignature<C>> + Keypair + Send + Sync + Debug,
	<SigningKey<C> as Keypair>::VerifyingKey: EncodePublicKey,
	DerSignature<C>: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync,
{
	fn agree<'a>(&'a self, peer: &'a PublicKey<C>) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
		let shared_secret = diffie_hellman(self.signing_key.as_nonzero_scalar(), peer.as_affine());
		let agreed = SecretSlice::from(shared_secret.raw_secret_bytes().to_vec());
		Box::pin(async move { Ok(agreed) })
	}
}

/// The ECDSA key provider on secp256k1, which also runs ECDH under the `ecdh`
/// feature.
#[cfg(feature = "signature")]
pub type Secp256k1KeyProvider = EcdsaKeyProvider<Secp256k1>;

/// `Decap(enc, skR)` of DHKEM(secp256k1, HKDF-SHA256) under the RustCrypto
/// `kem` traits, with this key as `skR` (RFC 9180 §4.1).
///
/// The agreement runs on the point that [`DhKemSecp256k1Enc`] admitted, so the
/// key never multiplies a point off the curve.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hpke::DhKemSecp256k1;
/// use tightbeam::crypto::kem::{Decapsulator, Encapsulator};
/// use tightbeam::crypto::key::Secp256k1KeyProvider;
/// use tightbeam::crypto::k256::PublicKey;
/// use tightbeam::random::OsRng;
/// use tightbeam::SigningKey;
///
/// let signing_key = SigningKey::random(&mut OsRng);
/// let recipient = PublicKey::from(signing_key.verifying_key());
/// let key = Secp256k1KeyProvider::from(signing_key);
///
/// let (encapsulated_key, sent) = DhKemSecp256k1::default().try_encap(&mut OsRng, &recipient)?;
/// let received = key.try_decap(&encapsulated_key)?;
/// assert_eq!(received.as_bytes(), sent.as_bytes());
/// # Ok::<(), tightbeam::crypto::kem::Error>(())
/// ```
#[cfg(all(feature = "kem", feature = "hpke", feature = "signature"))]
impl Decapsulator<DhKemSecp256k1Enc> for Secp256k1KeyProvider {
	/// # Errors
	///
	/// - [`KemError`] -- the KDF refuses a derivation.
	fn try_decap(&self, encapped_key: &DhKemSecp256k1Enc) -> Result<SharedSecret<DhKemSecp256k1Enc>, KemError> {
		let agreed = diffie_hellman(self.signing_key.as_nonzero_scalar(), encapped_key.public_key().as_affine());
		let recipient = PublicKey::from(self.signing_key.verifying_key());
		encapped_key.decapsulate(EcdhSecret::from(agreed), &recipient)
	}
}

/// A pluggable backend for a key-encryption key (KEK), the key a
/// `KEKRecipientInfo` names (RFC 5652 §6.2.3).
///
/// An implementation encrypts and decrypts a content-encryption key under its
/// KEK and keeps the KEK inside its boundary, so a Hardware Security Module
/// (HSM), a Key Management Service (KMS), or a secure enclave can hold it.
///
/// # Security Properties
///
/// - **Key encapsulation**: the KEK stays inside the provider boundary.
/// - **Uniform interface**: in-memory and remote backends use identical APIs.
/// - **Async by default**: encryption and decryption are async, so a remote backend fits the same API.
/// - **Algorithm agnostic**: the backend names its own key-encryption algorithm.
#[cfg(feature = "aead")]
pub trait EncryptingKeyProvider: Send + Sync + Debug {
	/// Returns the key-encryption algorithm of this key, which the
	/// `keyEncryptionAlgorithm` of a `KEKRecipientInfo` names.
	fn algorithm(&self) -> AlgorithmIdentifierOwned;

	/// Returns the identifier that names this key, the
	/// `kekid.keyIdentifier` of every `KEKRecipientInfo` under it.
	fn key_identifier(&self) -> &[u8];

	/// Encrypts the content-encryption key `content_key` under this key.
	///
	/// The result is the `encryptedKey` of a `KEKRecipientInfo`.
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `content_key` is no length the algorithm wraps.
	/// - [`KeyError::WrapFailed`] -- the algorithm refused the key.
	fn encrypt(&self, content_key: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>>;

	/// Decrypts `encrypted_key`, the `encryptedKey` of a `KEKRecipientInfo`
	/// under this key.
	///
	/// The result is the content-encryption key, which wipes when it drops.
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `encrypted_key` is no length the algorithm unwraps.
	/// - [`KeyError::WrapFailed`] -- `encrypted_key` fails the integrity check of the algorithm.
	fn decrypt(
		&self,
		encrypted_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>>;

	/// Decrypts `encrypted_key`, the `encryptedKey` of a `KEKRecipientInfo`
	/// under this key, into `content_key`, which takes the content-encryption
	/// key whole, so a caller decrypts it onto its own stack.
	///
	/// The default decrypts through [`Self::decrypt`] and copies the key into
	/// `content_key`, and the copy [`Self::decrypt`] returns wipes as it drops.
	/// A provider that can write into the caller's buffer overrides it.
	///
	/// # Errors
	///
	/// - The [`Self::decrypt`] set.
	/// - [`KeyError::WrapLength`] -- `content_key` is another size than the decrypted key.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::key::{Aes256GcmKeyProvider, EncryptingKeyProvider, KeyError};
	/// use tightbeam::zeroize::Zeroizing;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
	/// # runtime.block_on(async {
	/// // A fixed key-encryption key serves an example alone. A real holder
	/// // keeps a key of its own.
	/// let holder = Aes256GcmKeyProvider::new(vec![0x5A; 32], b"example-kek".to_vec())?;
	/// let wrapped = holder.encrypt(&[0xC3; 32]).await?;
	///
	/// // The content key lands in the caller's buffer, which wipes where it
	/// // drops.
	/// let mut content_key = Zeroizing::new([0u8; 32]);
	/// holder.decrypt_into(&wrapped, &mut *content_key).await?;
	/// assert_eq!(*content_key, [0xC3; 32]);
	/// # Ok::<(), KeyError>(())
	/// # })?;
	/// # Ok(())
	/// # }
	/// ```
	fn decrypt_into<'a>(
		&'a self,
		encrypted_key: &'a [u8],
		content_key: &'a mut [u8],
	) -> Pin<Box<dyn Future<Output = Result<(), KeyError>> + Send + 'a>> {
		Box::pin(async move {
			let decrypted = self.decrypt(encrypted_key).await?;
			decrypted.with(|key| {
				if key.len() != content_key.len() {
					return Err(KeyError::WrapLength((content_key.len(), key.len()).into()));
				}

				content_key.iter_mut().zip(key.iter()).for_each(|(slot, octet)| *slot = *octet);
				Ok(())
			})
		})
	}
}

/// A shared provider is a provider, as for [`SigningKeyProvider`].
#[cfg(feature = "aead")]
impl<T: EncryptingKeyProvider + ?Sized> EncryptingKeyProvider for Arc<T> {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		T::algorithm(self)
	}

	fn key_identifier(&self) -> &[u8] {
		T::key_identifier(self)
	}

	fn encrypt(&self, content_key: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		T::encrypt(self, content_key)
	}

	fn decrypt(
		&self,
		encrypted_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
		T::decrypt(self, encrypted_key)
	}

	fn decrypt_into<'a>(
		&'a self,
		encrypted_key: &'a [u8],
		content_key: &'a mut [u8],
	) -> Pin<Box<dyn Future<Output = Result<(), KeyError>> + Send + 'a>> {
		T::decrypt_into(self, encrypted_key, content_key)
	}
}

/// An in-memory key-encryption key under the key wrap of the provider `P`,
/// named by its key identifier.
///
/// - It is the reference [`EncryptingKeyProvider`], for an application that holds its KEK in memory.
/// - It stores the KEK in memory, in a buffer that wipes when it drops.
/// - It seals and opens a frame as an [`Encryptor`] and a [`Decryptor`], under one `KEKRecipientInfo`.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
pub struct InMemoryEncryptingKeyProvider<P: CryptoProvider> {
	kek: OwnedKek<P::KeyWrap>,
	key_identifier: Vec<u8>,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl<P: CryptoProvider> InMemoryEncryptingKeyProvider<P> {
	/// Hold `kek`, a key of the size of the key wrap of `P`, named by
	/// `key_identifier`.
	///
	/// # Errors
	///
	/// - [`KeyError::KekLength`] -- `kek` is another size than the wrap's key.
	pub fn new(kek: impl Into<crate::ZeroizingBytes>, key_identifier: impl Into<Vec<u8>>) -> Result<Self, KeyError> {
		let bytes = kek.into();
		let kek = OwnedKek::try_from(bytes.as_slice())?;
		let key_identifier = key_identifier.into();
		Ok(Self { kek, key_identifier })
	}
}

/// The key identifier and the algorithm name the key, and the KEK stays out
/// of the output.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl<P: CryptoProvider> Debug for InMemoryEncryptingKeyProvider<P> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("InMemoryEncryptingKeyProvider")
			.field("algorithm", &<<P::KeyWrap as KeyWrapAlgorithm>::Oid as AssociatedOid>::OID)
			.field("key_identifier", &self.key_identifier)
			.finish_non_exhaustive()
	}
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl<P: CryptoProvider> EncryptingKeyProvider for InMemoryEncryptingKeyProvider<P> {
	/// The key wrap of `P`, with parameters absent (RFC 3565 §2.3.2).
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		let oid = <<P::KeyWrap as KeyWrapAlgorithm>::Oid as AssociatedOid>::OID;
		AlgorithmIdentifierOwned { oid, parameters: None }
	}

	fn key_identifier(&self) -> &[u8] {
		&self.key_identifier
	}

	fn encrypt(&self, content_key: &[u8]) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, KeyError>> + Send + '_>> {
		let kek = self.kek.kek();
		let wrapped = P::KeyWrap::wrap(&kek, content_key);
		Box::pin(async move { wrapped })
	}

	fn decrypt(
		&self,
		encrypted_key: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<SecretSlice<u8>, KeyError>> + Send + '_>> {
		let kek = self.kek.kek();
		let unwrapped = P::KeyWrap::unwrap(&kek, encrypted_key);
		let content_key = unwrapped.map(|mut key| SecretSlice::from(core::mem::take(&mut *key)));
		Box::pin(async move { content_key })
	}

	/// The key wrap of `P` unwraps straight into `content_key`, the caller's
	/// buffer.
	fn decrypt_into<'a>(
		&'a self,
		encrypted_key: &'a [u8],
		content_key: &'a mut [u8],
	) -> Pin<Box<dyn Future<Output = Result<(), KeyError>> + Send + 'a>> {
		let kek = self.kek.kek();
		let unwrapped = P::KeyWrap::unwrap_into(&kek, encrypted_key, content_key);
		Box::pin(async move { unwrapped })
	}
}

/// A frame seals to this key as an `AuthEnvelopedData` with one
/// `KEKRecipientInfo`, under every algorithm of `P`.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl<P> Encryptor<<P::AeadCipher as AeadAlgorithm>::Oid> for InMemoryEncryptingKeyProvider<P>
where
	P: CryptoProvider<AeadCipher: ContentEncryption>,
{
	fn encrypt_content(
		&self,
		content: impl Into<Vec<u8>>,
		content_type: Option<ObjectIdentifier>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<AuthEnvelopedData, TightBeamError> {
		let content_type = content_type.unwrap_or(DATA);
		let kek = self.kek.kek();
		let sealed = AuthEnvelopedData::seal_kek::<P>(&kek, &self.key_identifier, content_type, content, [], rng);
		Ok(sealed?)
	}
}

/// A frame opens under this key when its `kekid` names it, and the content
/// type is the one the envelope's attributes authenticate.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl<P> Decryptor for InMemoryEncryptingKeyProvider<P>
where
	P: CryptoProvider<AeadCipher: ContentEncryption>,
{
	fn algorithm_oid(&self) -> ObjectIdentifier {
		<<P::AeadCipher as AeadAlgorithm>::Oid as AssociatedOid>::OID
	}

	fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, Result<(), TightBeamError>> {
		let kek = self.kek.kek();
		let opened = content.open_kek::<P>(&kek, &self.key_identifier);
		Box::pin(core::future::ready(opened))
	}
}

/// The in-memory key-encryption key of [`DefaultCryptoProvider`], whose
/// frames seal under AES-256-GCM with the content key wrapped under AES-256
/// key wrap.
///
/// [`DefaultCryptoProvider`]: crate::crypto::profiles::DefaultCryptoProvider
#[cfg(all(
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh",
	feature = "aes-gcm"
))]
pub type Aes256GcmKeyProvider = InMemoryEncryptingKeyProvider<crate::crypto::profiles::DefaultCryptoProvider>;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::PrehashVerifier;
	use crate::runtime::rt;
	use crate::testing::{TestKey, TestResult};

	/// The SHA3-256 digest of the content every signing test signs.
	fn digest() -> Vec<u8> {
		Sha3_256::digest(TestKey::HIGH_S_CONTENT).to_vec()
	}

	/// The house provider of the fixed test key.
	fn provider() -> Secp256k1KeyProvider {
		Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing())
	}

	/// The length of the SPKI that `provider` presents.
	fn spki_len_of(provider: &impl KeyBackend) -> usize {
		let spki = provider.to_public_key_bytes().expect("the house provider encodes its key");
		spki.len()
	}

	/// The signature that `provider` makes over [`digest`], parsed from its
	/// DER.
	fn signature_of(provider: &impl SigningKeyProvider) -> Secp256k1Signature {
		let der = rt::block_on(provider.sign_prehash(&digest())).expect("the house provider signs");
		Secp256k1Signature::from_bytes(&der).expect("the house provider signs in DER")
	}

	/// The secret that the house provider of [`TestKey::fixed`] `own` agrees
	/// with the point of [`TestKey::fixed`] `peer`.
	#[cfg(feature = "ecdh")]
	fn agreed(own: u8, peer: u8) -> Vec<u8> {
		let provider = Secp256k1KeyProvider::from(TestKey::fixed(own));
		let peer = PublicKey::from(TestKey::fixed(peer).verifying_key());
		let agreed = rt::block_on(provider.agree(&peer)).expect("the house provider agrees on a curve point");
		agreed.to_insecure().to_vec()
	}

	// The house provider presents its key as a DER SPKI of 88 octets, the
	// size of a secp256k1 SPKI, owned, shared, or shared as a trait object.
	crate::tb_cases! {
		fn a_provider_presents_an_spki_of_88_octets(len: usize) {
			assert_eq!(len, 88);
		}
		cases {
			owned => spki_len_of(&provider()),
			shared => spki_len_of(&Arc::new(provider())),
			shared_as_a_trait_object => spki_len_of(&(Arc::new(provider()) as Arc<dyn SigningKeyProvider>)),
		}
	}

	// The house provider signs a prehash that its key verifies, owned,
	// shared, or shared as a trait object.
	crate::tb_cases! {
		fn a_provider_signs_verifiably(signature: Secp256k1Signature) {
			let verifying_key = *TestKey::insecure_fixed_signing().verifying_key();
			let verified = verifying_key.verify_prehash(&digest(), &signature);
			assert!(matches!(verified, Ok(())));
		}
		cases {
			owned => signature_of(&provider()),
			shared => signature_of(&Arc::new(provider())),
			shared_as_a_trait_object => signature_of(&(Arc::new(provider()) as Arc<dyn SigningKeyProvider>)),
		}
	}

	/// The provider signs with `s` in the low half of the curve order, so its
	/// DER value is the canonical form a verifier keys on. The raw `s` of this
	/// key over this content lies in the high half, by an independent RFC
	/// 6979 computation, so the test fails for a provider that skips the rule.
	#[test]
	fn the_provider_signs_low_s() -> TestResult {
		let signature = signature_of(&provider());
		let scalars = crate::crypto::sign::ecdsa::Signature::<Secp256k1>::try_from(signature)?;
		assert!(scalars.normalize_s().is_none());
		Ok(())
	}

	/// Both sides of an agreement compute the same shared secret.
	#[cfg(feature = "ecdh")]
	#[test]
	fn both_providers_agree_on_one_secret() {
		let initiator = agreed(0x11, 0x22);
		let responder = agreed(0x22, 0x11);
		assert_eq!(initiator, responder);
	}

	/// A secp256k1 shared secret is 32 bytes, the width of the field.
	#[cfg(feature = "ecdh")]
	#[test]
	fn an_agreed_secret_is_as_wide_as_the_field() {
		let secret = agreed(0x11, 0x22);
		assert_eq!(secret.len(), 32);
	}

	/// The house provider names the algorithm of the signatures it makes.
	#[test]
	fn a_provider_names_the_algorithm_of_its_signatures() {
		let algorithm = provider().algorithm();
		assert_eq!(algorithm.oid, Secp256k1Signature::ALGORITHM_OID);
	}

	/// Short key material reaches a typed refusal ahead of the
	/// fixed-size conversion's assert.
	#[test]
	fn short_signing_key_bytes_are_refused() {
		let spec = SigningKeySpec::Bytes(&[0u8; 5]);
		let refused = spec.to_provider::<crate::crypto::sign::ecdsa::k256::Secp256k1>();
		assert!(matches!(refused, Err(KeyError::KeyLengthError(sizes)) if (sizes.received, sizes.expected) == (5, 32)));
	}

	/// The `Debug` of a raw key spec prints its length only, so a caller that
	/// logs its configuration keeps the signing key out of the log (CWE-532).
	#[test]
	fn signing_key_spec_debug_omits_the_key_bytes() {
		let spec = SigningKeySpec::Bytes(&[0xABu8; 32]);
		let rendered = format!("{spec:?}");
		assert!(!rendered.contains("171"));
		assert!(rendered.contains("32"));
	}

	/// The house in-memory provider, which wraps a content key under the key
	/// it holds.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	mod house_wrap {
		use core::convert::identity;

		use super::*;
		use crate::testing::fixtures::flip_last;
		use crate::testing::unhex;
		use crate::testing::vectors::rfc3394::RFC_3394_4_6;

		/// The content key the house provider wraps in its `decrypt_into`
		/// tests.
		const CONTENT_KEY: [u8; 32] = [0xC3u8; 32];

		/// The house provider of the fixed test key-encryption key.
		fn house() -> Aes256GcmKeyProvider {
			let (_kek, holder) = TestKey::insecure_fixed_cipher();
			holder
		}

		/// The house provider of the RFC 3394 §4.6 key-encryption key.
		fn rfc_3394_holder() -> Aes256GcmKeyProvider {
			let holder = Aes256GcmKeyProvider::new(unhex(RFC_3394_4_6.kek), b"tb/test/kek/v1".to_vec());
			holder.expect("the RFC 3394 §4.6 KEK is the size of the house wrap's key")
		}

		/// [`CONTENT_KEY`] as `holder` wraps it.
		fn wrapped_by(holder: &impl EncryptingKeyProvider) -> Vec<u8> {
			let wrapped = rt::block_on(holder.encrypt(&CONTENT_KEY));
			wrapped.expect("the house wrap takes a 32-octet key")
		}

		/// The refusal of `holder` to unwrap its own wrap of [`CONTENT_KEY`],
		/// after `alter`, into a buffer of 16 octets.
		fn short_unwrap(holder: &impl EncryptingKeyProvider, alter: fn(Vec<u8>) -> Vec<u8>) -> Option<KeyError> {
			let wrapped = alter(wrapped_by(holder));
			let mut short = [0u8; 16];
			rt::block_on(holder.decrypt_into(&wrapped, &mut short)).err()
		}

		/// The house provider wraps under the key it holds as RFC 3394 §4.6
		/// wraps 256 bits of key data under a 256-bit KEK.
		#[test]
		fn the_house_provider_wraps_as_rfc_3394_4_6() -> TestResult {
			let key_data = unhex(RFC_3394_4_6.key_data);
			let wrapped = rt::block_on(rfc_3394_holder().encrypt(&key_data))?;
			assert_eq!(wrapped, unhex(RFC_3394_4_6.ciphertext));
			Ok(())
		}

		/// The house provider unwraps under the key it holds as RFC 3394 §4.6
		/// unwraps 256 bits of key data under a 256-bit KEK.
		#[test]
		fn the_house_provider_unwraps_rfc_3394_4_6() -> TestResult {
			let wrapped = unhex(RFC_3394_4_6.ciphertext);
			let mut key = [0u8; 32];

			rt::block_on(rfc_3394_holder().decrypt_into(&wrapped, &mut key))?;

			assert_eq!(key.as_slice(), unhex(RFC_3394_4_6.key_data).as_slice());
			Ok(())
		}

		/// The house provider unwraps into the caller's buffer the content key
		/// it wrapped.
		#[test]
		fn the_house_provider_decrypts_into_the_callers_buffer() -> TestResult {
			let holder = house();
			let wrapped = wrapped_by(&holder);
			let mut content_key = [0u8; 32];

			rt::block_on(holder.decrypt_into(&wrapped, &mut content_key))?;

			assert_eq!(content_key, CONTENT_KEY);
			Ok(())
		}

		// The house provider hands the caller's buffer to the key wrap itself,
		// so the wrap refuses a buffer of another size and names the 32 octets
		// a wrapped key of 40 octets holds (RFC 3394 §2.2.2). It checks the
		// size before it unwraps, so a wrapped key whose integrity check fails
		// (RFC 3394 §2.2.3) meets the same refusal, through a shared house
		// provider too.
		crate::tb_cases! {
			fn the_house_provider_checks_the_buffer_before_it_unwraps(refused: Option<KeyError>) {
				assert!(matches!(
					refused,
					Some(KeyError::WrapLength(sizes)) if (sizes.received, sizes.expected) == (16, 32)
				));
			}
			cases {
				an_intact_wrap => short_unwrap(&house(), identity),
				a_failed_wrap => short_unwrap(&house(), flip_last),
				a_failed_wrap_of_a_shared_provider => short_unwrap(&Arc::new(house()), flip_last),
			}
		}
	}
}
