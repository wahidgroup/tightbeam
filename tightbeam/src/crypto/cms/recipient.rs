//! The two sides of a content key: the [`Recipient`] a sender wraps it for,
//! and the [`Opener`] a reader unwraps it with, each under the algorithms of
//! a [`CryptoProvider`].
//!
//! A KEM recipient is one [`KemRecipient`]: the recipient key beside the
//! `rid` that names it. A sender builds one from a certificate admitted for
//! key agreement, or from a bare key with [`KemRecipient::bare`]. An opener
//! holds one inside a [`KemKeyHolder`], a [`KeyAgreementIdentity`] or a
//! [`BareKemKey`], which pairs it with the backend of its private key.

#[cfg(all(not(feature = "std"), feature = "kem"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use core::fmt;

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{OtherRecipientInfo, RecipientIdentifier, RecipientInfo, RecipientInfos};
use crate::crypto::cms::kek;
use crate::crypto::cms::{CmsOriForKemOtherInfo, EnvelopeError, KemRecipientInfo};
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::kdf::KdfFunction;
use crate::crypto::key::KeyBackend;
use crate::crypto::profiles::{CryptoProvider, Kek, KeyWrapAlgorithm};
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::ext::pkix::KeyUsages;
use crate::crypto::x509::ext::pkix::SubjectKeyIdentifier;
use crate::crypto::x509::utils::{CertificateExt, Skid};
use crate::crypto::x509::{KeyAgreement, PeerCertificate};
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode};
use crate::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::oids::ORI_KEM;
use crate::random::CryptoRngCore;
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use crate::x509::Certificate;
use crate::ZeroizingBytes;

#[cfg(feature = "kem")]
use core::marker::PhantomData;

#[cfg(feature = "kem")]
use crate::crypto::profiles::KemProvider;
#[cfg(feature = "kem")]
use crate::random::RngWrapper;
#[cfg(feature = "kem")]
use crate::zeroize::Zeroizing;
#[cfg(feature = "kem")]
use kem::generic_array::GenericArray;
#[cfg(feature = "kem")]
use kem::{Decapsulator, EncappedKey, Encapsulator};

/// The length in octets of the random octets that follow the purpose label
/// in a `ukm`.
pub(super) const UKM_RANDOM_SIZE: usize = 32;

/// The output of `Encap(pkR)` (RFC 9180 §4): the shared secret, and the
/// `kemct` that carries it to the holder of the private key.
pub struct Encapsulation {
	/// The shared secret the key-encryption key derives from.
	pub shared_secret: ZeroizingBytes,
	/// The KEM ciphertext a `KEMRecipientInfo` carries (RFC 9629 §3).
	pub kemct: Vec<u8>,
}

/// The KEM of a `KEMRecipientInfo` (RFC 9629 §3), with its own key types
/// and the one private-key operation its `Decap` needs.
///
/// A [`CryptoProvider`] names its KEM, and an implementor brings its own KEM
/// as an implementation of this trait on its own type:
///
/// - A DHKEM names [`DiffieHellman`](crate::crypto::key::DiffieHellman) as its private key.
/// - A KEM such as ML-KEM names a decapsulation trait of its own.
pub trait RecipientKem {
	/// The identifier the `kem` field names, with parameters absent.
	const OID: ObjectIdentifier;

	/// The `keyUsage` bit the KEM's certificate profile asserts on a
	/// recipient certificate: `keyAgreement` for a DHKEM over an
	/// `id-ecPublicKey` key (RFC 5480 §3), and `keyEncipherment` for ML-KEM
	/// (RFC 9935 §5, RFC 9629 §3).
	const USAGE: KeyUsages;

	/// The recipient's public key, parsed once from a SubjectPublicKeyInfo.
	/// [`KeyAgreementIdentity::new`] and [`BareKemKey::new`] compare it with
	/// the public half of a backend.
	type PublicKey: Clone + PartialEq + Send + Sync + 'static;

	/// The private-key operation `Decap` runs through, as a trait object a
	/// key backend implements.
	type PrivateKey: ?Sized + KeyBackend;

	/// Parse `spki` as a recipient key of this KEM.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- `spki` names another algorithm, or holds no key of this KEM.
	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self::PublicKey, CertificateValidationError>;

	/// `Encap(pkR)` to `recipient`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError`] -- a derivation failed.
	fn encapsulate(recipient: &Self::PublicKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError>;

	/// `Decap(kemct, skR)` through `key`, the backend that holds the private
	/// half of `recipient`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError`] -- `kemct` is no ciphertext of the KEM, or the backend or a derivation failed.
	fn decapsulate<'a>(
		key: &'a Self::PrivateKey,
		recipient: &'a Self::PublicKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>>;
}

/// The KEM of the [`KemProvider`] role of `P` as the KEM of a
/// `KEMRecipientInfo` (RFC 9629 §3), so a KEM of the RustCrypto `kem` traits
/// seals and opens envelopes.
///
/// A provider names `ProviderKem<Self>` as its [`CryptoProvider::Kem`], and
/// its envelopes, its frames, and its handshake then run the KEM of its role:
///
/// - The `kem` field names the identifier of [`KemProvider::Kem`].
/// - A recipient certificate asserts [`KemProvider::USAGE`], the usage of the certificate profile of the KEM.
/// - The recipient key parses from a SubjectPublicKeyInfo.
/// - The private key of a recipient is the [`KemProvider::DecapsulationKey`] of `P`, a [`KeyBackend`].
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::cms::{ProviderKem, RecipientKem};
/// use tightbeam::crypto::k256::PublicKey;
/// use tightbeam::crypto::key::Secp256k1KeyProvider;
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::random::OsRng;
/// use tightbeam::SigningKey;
///
/// // The house role runs DHKEM(secp256k1, HKDF-SHA256).
/// type HouseKem = ProviderKem<DefaultCryptoProvider>;
///
/// let signing_key = SigningKey::random(&mut OsRng);
/// let recipient = PublicKey::from(signing_key.verifying_key());
/// let key = Secp256k1KeyProvider::from(signing_key);
///
/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
/// # runtime.block_on(async {
/// let sent = HouseKem::encapsulate(&recipient, &mut OsRng)?;
/// let received = HouseKem::decapsulate(&key, &recipient, &sent.kemct).await?;
/// assert_eq!(received, sent.shared_secret);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[cfg(feature = "kem")]
pub struct ProviderKem<P>(PhantomData<P>);

#[cfg(feature = "kem")]
impl<P> RecipientKem for ProviderKem<P>
where
	P: KemProvider,
	P::Kem: AssociatedOid,
	P::DecapsulationKey: KeyBackend + 'static,
	<P::EncappedKey as EncappedKey>::RecipientPublicKey: Clone
		+ PartialEq
		+ Send
		+ Sync
		+ 'static
		+ for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = crate::spki::Error>,
{
	const OID: ObjectIdentifier = <P::Kem as AssociatedOid>::OID;
	const USAGE: KeyUsages = P::USAGE;
	type PublicKey = <P::EncappedKey as EncappedKey>::RecipientPublicKey;
	type PrivateKey = P::DecapsulationKey;

	/// # Errors
	///
	/// - [`CertificateValidationError::SpkiError`] -- `spki` holds no key of the KEM.
	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self::PublicKey, CertificateValidationError> {
		Ok(Self::PublicKey::try_from(spki)?)
	}

	/// `Encap(pkR)` by the default value of [`KemProvider::Kem`], with the
	/// encapsulated key as the `kemct`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::KemRefused`] -- the KEM refused the encapsulation.
	fn encapsulate(recipient: &Self::PublicKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError> {
		let encapsulated = P::Kem::default().try_encap(&mut RngWrapper(rng), recipient);
		let (encapsulated_key, shared_secret) = encapsulated.map_err(|_| EnvelopeError::KemRefused)?;
		let shared_secret = Zeroizing::new(shared_secret.as_bytes().to_vec());
		let kemct = encapsulated_key.as_ref().to_vec();

		Ok(Encapsulation { shared_secret, kemct })
	}

	/// `Decap(kemct, skR)` by `key`. The decapsulation runs before the future
	/// is built, so no copy of the shared secret lives across an await.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::KemRefused`] -- `kemct` is no encapsulated key of the
	///   KEM, or the KEM refused the decapsulation.
	fn decapsulate<'a>(
		key: &'a P::DecapsulationKey,
		_recipient: &'a Self::PublicKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>> {
		let decapsulated = Self::decapsulate_now(key, kemct);
		Box::pin(async move { decapsulated })
	}
}

#[cfg(feature = "kem")]
impl<P: KemProvider> ProviderKem<P> {
	/// `Decap(kemct, skR)` by `key`, at once.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::KemRefused`] -- `kemct` is no encapsulated key of the
	///   KEM, or the KEM refused the decapsulation.
	fn decapsulate_now(key: &P::DecapsulationKey, kemct: &[u8]) -> Result<ZeroizingBytes, EnvelopeError> {
		let encoding = GenericArray::from_exact_iter(kemct.iter().copied()).ok_or(EnvelopeError::KemRefused)?;
		let encapsulated_key = P::EncappedKey::from_bytes(&encoding).map_err(|_| EnvelopeError::KemRefused)?;
		let shared_secret = key.try_decap(&encapsulated_key).map_err(|_| EnvelopeError::KemRefused)?;

		Ok(Zeroizing::new(shared_secret.as_bytes().to_vec()))
	}
}

/// A recipient's public key beside its `rid`: the one form a sender seals to
/// and an opener compares against.
pub struct KemRecipient<K: RecipientKem> {
	/// The recipient key the sender encapsulates to.
	key: K::PublicKey,
	/// The identifier the `rid` of a `KEMRecipientInfo` carries.
	rid: RecipientIdentifier,
}

impl<K: RecipientKem> KemRecipient<K> {
	/// The recipient of `certificate`, whose key the use admitted, named by
	/// its `subjectKeyIdentifier` or by its issuer and serial number
	/// (RFC 9629 §3).
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Certificate`] -- the key identifier or the serial number fails to decode.
	pub fn from_certificate(certificate: PeerCertificate<KeyAgreement<K>>) -> Result<Self, EnvelopeError> {
		let rid = certificate.certificate().recipient_identifier()?;
		Ok(Self { key: certificate.key, rid })
	}

	/// The recipient of a bare key, from the DER of its SubjectPublicKeyInfo,
	/// named by the RFC 7093 §2 method 1 identifier of the key as the
	/// `subjectKeyIdentifier` form of the `rid`.
	///
	/// The identifier hashes the key as `spki` encodes it, so a recipient
	/// publishes the SubjectPublicKeyInfo its backend emits, and the
	/// [`BareKemKey`] of its decryptor then names the same `rid`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- `spki` is no DER SubjectPublicKeyInfo.
	/// - [`EnvelopeError::Certificate`] -- the key is no key of `K`.
	pub fn bare(spki: impl AsRef<[u8]>) -> Result<Self, EnvelopeError> {
		let spki = spki.as_ref();
		let key = K::public_key(SubjectPublicKeyInfoRef::from_der(spki)?)?;
		Self::named(key, spki)
	}

	/// `key`, named by the RFC 7093 §2 method 1 identifier of the key `spki`,
	/// its SubjectPublicKeyInfo, encodes.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- `spki` is no DER SubjectPublicKeyInfo.
	fn named(key: K::PublicKey, spki: &[u8]) -> Result<Self, EnvelopeError> {
		let owned = SubjectPublicKeyInfoOwned::from_der(spki)?;
		let identifier = SubjectKeyIdentifier::try_from(Skid::of_public_key(&owned))?;
		let rid = RecipientIdentifier::SubjectKeyIdentifier(identifier);
		Ok(Self { key, rid })
	}
}

impl<K: RecipientKem> Clone for KemRecipient<K> {
	fn clone(&self) -> Self {
		Self { key: self.key.clone(), rid: self.rid.clone() }
	}
}

/// The `rid` names the recipient, and the key stays out of the output.
impl<K: RecipientKem> fmt::Debug for KemRecipient<K> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("KemRecipient").field("rid", &self.rid).finish_non_exhaustive()
	}
}

/// A key-agreement certificate beside the backend that holds its private
/// key, under the KEM `K`.
///
/// [`Self::new`] checks the certificate, its key, and the backend against
/// each other once, so the key that decapsulates is the key the `rid` names.
/// Every clone shares the one checked value.
pub struct KeyAgreementIdentity<K: RecipientKem> {
	parts: Arc<IdentityParts<K>>,
}

/// What a [`KeyAgreementIdentity`] holds, checked against each other once.
struct IdentityParts<K: RecipientKem> {
	/// The key-agreement certificate.
	certificate: Arc<Certificate>,
	/// The backend of the certificate's private key.
	key: Arc<K::PrivateKey>,
	/// The certificate's key and its `rid`.
	recipient: KemRecipient<K>,
}

impl<K: RecipientKem> KeyAgreementIdentity<K> {
	/// Pair `certificate` with `key`, the backend of its private key.
	///
	/// This admits the certificate for key agreement under `K` first, so its
	/// `keyUsage` asserts [`RecipientKem::USAGE`] and its SPKI is a key of
	/// `K`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Certificate`] -- the certificate is refused for key
	///   agreement under `K`, or the backend's key is no key of `K`.
	/// - [`EnvelopeError::Key`] -- the backend fails to return its public key.
	/// - [`EnvelopeError::Encoding`] -- the backend's key is no DER SubjectPublicKeyInfo.
	/// - [`EnvelopeError::KeyMismatch`] -- the backend's key differs from the certificate's key.
	pub fn new(certificate: impl Into<Arc<Certificate>>, key: Arc<K::PrivateKey>) -> Result<Self, EnvelopeError> {
		let certificate = certificate.into();
		let admitted = PeerCertificate::<KeyAgreement<K>>::own(Arc::clone(&certificate))?;
		let recipient = KemRecipient::from_certificate(admitted)?;
		checked_pair::<K>(&recipient.key, &key)?;

		Ok(Self { parts: Arc::new(IdentityParts { certificate, key, recipient }) })
	}

	/// The key-agreement certificate this identity holds.
	pub fn certificate(&self) -> &Certificate {
		&self.parts.certificate
	}

	/// The recipient this identity answers for: the certificate's key and
	/// its `rid`.
	pub fn recipient(&self) -> &KemRecipient<K> {
		&self.parts.recipient
	}
}

/// A clone shares the one checked value.
impl<K: RecipientKem> Clone for KeyAgreementIdentity<K> {
	fn clone(&self) -> Self {
		Self { parts: Arc::clone(&self.parts) }
	}
}

/// The subject and the `rid` name the identity, and the backend stays out
/// of the output.
impl<K: RecipientKem> fmt::Debug for KeyAgreementIdentity<K> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("KeyAgreementIdentity")
			.field("subject", &self.certificate().tbs_certificate.subject)
			.field("rid", &self.recipient().rid)
			.finish_non_exhaustive()
	}
}

/// The recipient key and the private key that answers for it, lent to an
/// opener as the one pair a constructor checked.
///
/// [`KeyAgreementIdentity::new`] and [`BareKemKey::new`] are the two
/// constructors, and each compares the backend's public half with the
/// recipient key, so the trait is sealed.
pub trait KemKeyHolder<K: RecipientKem>: sealed::Sealed + MaybeSend + MaybeSync {
	/// The recipient key and the `rid` that names it.
	fn recipient(&self) -> &KemRecipient<K>;

	/// The backend that runs the KEM's private-key operation for the
	/// recipient key.
	fn key(&self) -> &K::PrivateKey;
}

mod sealed {
	/// The seal of [`KemKeyHolder`](super::KemKeyHolder), implemented by its
	/// two holders alone.
	pub trait Sealed {}
}

impl<K: RecipientKem> sealed::Sealed for KeyAgreementIdentity<K> {}

impl<K: RecipientKem> KemKeyHolder<K> for KeyAgreementIdentity<K> {
	fn recipient(&self) -> &KemRecipient<K> {
		&self.parts.recipient
	}

	fn key(&self) -> &K::PrivateKey {
		&self.parts.key
	}
}

/// A bare recipient key beside the backend of its private key, for a frame
/// decryptor that names its recipient by the key alone. The `rid` is the
/// RFC 7093 §2 method 1 identifier of the key, as [`KemRecipient::bare`]
/// names it.
pub struct BareKemKey<K: RecipientKem> {
	/// The backend of the private key.
	key: Arc<K::PrivateKey>,
	/// The public key and its `rid`.
	recipient: KemRecipient<K>,
}

impl<K: RecipientKem> BareKemKey<K> {
	/// Pair `public` with `key`, the backend of its private half.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Key`] -- the backend fails to return its public key.
	/// - [`EnvelopeError::Encoding`] -- the backend's key is no DER SubjectPublicKeyInfo.
	/// - [`EnvelopeError::Certificate`] -- the backend's key is no key of `K`.
	/// - [`EnvelopeError::KeyMismatch`] -- the backend's key differs from `public`.
	pub fn new(public: K::PublicKey, key: Arc<K::PrivateKey>) -> Result<Self, EnvelopeError> {
		let spki = checked_pair::<K>(&public, &key)?;
		let recipient = KemRecipient::named(public, &spki)?;

		Ok(Self { key, recipient })
	}
}

impl<K: RecipientKem> sealed::Sealed for BareKemKey<K> {}

impl<K: RecipientKem> KemKeyHolder<K> for BareKemKey<K> {
	fn recipient(&self) -> &KemRecipient<K> {
		&self.recipient
	}

	fn key(&self) -> &K::PrivateKey {
		&self.key
	}
}

/// The SubjectPublicKeyInfo the backend `key` emits, once the key it holds
/// is `public`, compared as keys of `K`. Both holders of a pair run this one
/// check.
///
/// # Errors
///
/// - [`EnvelopeError::Key`] -- the backend fails to return its public key.
/// - [`EnvelopeError::Encoding`] -- the backend's key is no DER SubjectPublicKeyInfo.
/// - [`EnvelopeError::Certificate`] -- the backend's key is no key of `K`.
/// - [`EnvelopeError::KeyMismatch`] -- the backend's key differs from `public`.
fn checked_pair<K: RecipientKem>(public: &K::PublicKey, key: &K::PrivateKey) -> Result<Vec<u8>, EnvelopeError> {
	let spki = key.to_public_key_bytes()?;
	let backend = K::public_key(SubjectPublicKeyInfoRef::from_der(&spki)?)?;
	if backend != *public {
		return Err(EnvelopeError::KeyMismatch);
	}

	Ok(spki)
}

/// A clone shares the backend.
impl<K: RecipientKem> Clone for BareKemKey<K> {
	fn clone(&self) -> Self {
		Self { key: Arc::clone(&self.key), recipient: self.recipient.clone() }
	}
}

/// The `rid` names the key, and the backend stays out of the output.
impl<K: RecipientKem> fmt::Debug for BareKemKey<K> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BareKemKey")
			.field("rid", &self.recipient.rid)
			.finish_non_exhaustive()
	}
}

/// The KEM of every `KEMRecipientInfo` under `P`, with parameters absent.
fn kem_algorithm<P: CryptoProvider>() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: <P::Kem as RecipientKem>::OID, parameters: None }
}

/// The KDF of every `KEMRecipientInfo` under `P`, the profile's KDF, with
/// parameters absent (RFC 9688 §5.1).
fn kdf_algorithm<P: CryptoProvider>() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: <P::Kdf as AssociatedOid>::OID, parameters: None }
}

/// The recipient a sender wraps the content key for, under the algorithms of
/// the provider `P` that seals.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::cms::enveloped_data::RecipientInfo;
/// use tightbeam::crypto::cms::{AuthEnvelopedData, KemRecipient, Recipient};
/// use tightbeam::crypto::k256::Secp256k1;
/// use tightbeam::crypto::key::{DiffieHellman, KeyBackend, Secp256k1KeyProvider};
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::oids::DATA;
/// use tightbeam::random::OsRng;
/// use tightbeam::SigningKey;
///
/// // The bare key of a recipient, which the seal encapsulates to.
/// let signing_key = SigningKey::random(&mut OsRng);
/// let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(Secp256k1KeyProvider::from(signing_key));
/// let key = KemRecipient::bare(backend.to_public_key_bytes()?)?;
/// let ukm_label: &[u8] = b"example/v1";
/// let recipient: Recipient<'_, DefaultCryptoProvider> = Recipient::Kem { recipient: &key, ukm_label };
///
/// // A KEM recipient travels as an `ori` of type `id-ori-kem`.
/// let sealed = AuthEnvelopedData::seal(recipient, DATA, b"content".to_vec(), [], None)?;
/// assert!(matches!(sealed.recipient_infos.0.as_slice(), [RecipientInfo::Ori(_)]));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub enum Recipient<'a, P: CryptoProvider> {
	/// The holder of the private half of `recipient`, through a
	/// `KEMRecipientInfo` (RFC 9629 §3) under the KEM of `P`. The `rid` is
	/// the recipient's, and the `ukm` is `ukm_label` followed by 32 octets
	/// this seal draws.
	Kem {
		/// The key the seal encapsulates to, beside the `rid` that names it.
		recipient: &'a KemRecipient<P::Kem>,
		/// The purpose label that leads the `ukm`.
		ukm_label: &'a [u8],
	},
	/// The holder of `kek`, through a `KEKRecipientInfo` (RFC 5652 §6.2.3)
	/// whose `kekid.keyIdentifier` is `key_identifier`.
	Kek {
		/// The key-encryption key both ends hold, of the size of `P`'s wrap.
		kek: Kek<'a, P::KeyWrap>,
		/// The identifier that names `kek`.
		key_identifier: &'a [u8],
	},
}

impl<P: CryptoProvider> Recipient<'_, P> {
	/// Wrap `content_key` for this recipient under the wrap of `P`, as its
	/// `RecipientInfo`.
	///
	/// # Errors
	///
	/// - The errors of [`Self::wrap_kem`], for a `Kem` recipient.
	/// - [`EnvelopeError::Key`] -- the key wrap refused the content key.
	/// - [`EnvelopeError::Encoding`] -- the identifier fails to encode.
	pub(super) fn wrap(&self, content_key: &[u8], rng: &mut dyn CryptoRngCore) -> Result<RecipientInfo, EnvelopeError> {
		match self {
			Self::Kem { recipient, ukm_label } => Self::wrap_kem(recipient, ukm_label, content_key, rng),
			Self::Kek { kek, key_identifier } => kek.recipient_info(key_identifier, content_key),
		}
	}

	/// Wrap `content_key` to the key of `recipient` as a `KEMRecipientInfo`
	/// in an `ori` of type `id-ori-kem`, under the KEM and the KDF of `P`.
	///
	/// # Errors
	///
	/// - The errors of [`RecipientKem::encapsulate`] for the provider's KEM.
	/// - [`EnvelopeError::Random`] -- the random source failed.
	/// - [`EnvelopeError::Kdf`] -- the KDF refused the key-encryption key.
	/// - [`EnvelopeError::Key`] -- `KeyError::KekLength` for a key-encryption
	///   key of another length than the wrap's, or the refusal of the key wrap
	///   for the content key.
	/// - [`EnvelopeError::Encoding`] -- a structure fails to encode.
	fn wrap_kem(
		recipient: &KemRecipient<P::Kem>,
		ukm_label: &[u8],
		content_key: &[u8],
		rng: &mut dyn CryptoRngCore,
	) -> Result<RecipientInfo, EnvelopeError> {
		// 1. Encapsulate to the recipient key under the provider's KEM, and
		//    draw the random octets of the ukm.
		let Encapsulation { shared_secret, kemct } = P::Kem::encapsulate(&recipient.key, rng)?;
		let mut random = [0u8; UKM_RANDOM_SIZE];
		rng.try_fill_bytes(&mut random).map_err(|_| EnvelopeError::Random)?;
		let ukm = OctetString::new([ukm_label, random.as_slice()].concat())?;

		// 2. Derive the key-encryption key from the shared secret alone, and
		//    wrap the content key under it (RFC 9629 §5, §7).
		let kek_length = <<P::KeyWrap as KeyWrapAlgorithm>::KekSize as Unsigned>::U16;
		let wrap = kek::wrap_algorithm::<P::KeyWrap>();
		let other_info = CmsOriForKemOtherInfo { wrap: wrap.clone(), kek_length, ukm: Some(ukm.clone()) };
		let derived = other_info.derive_kek::<P::Kdf>(&shared_secret)?;
		let kek = Kek::<P::KeyWrap>::try_from(derived.as_slice())?;
		let encrypted_key = OctetString::new(P::KeyWrap::wrap(&kek, content_key)?)?;

		// 3. Carry the KEM ciphertext, under the `rid` that names the recipient.
		let kem = KemRecipientInfo {
			version: CmsVersion::V0,
			rid: recipient.rid.clone(),
			kem: kem_algorithm::<P>(),
			kemct: OctetString::new(kemct)?,
			kdf: kdf_algorithm::<P>(),
			kek_length,
			ukm: Some(ukm),
			wrap,
			encrypted_key,
		};

		let ori_value = Any::encode_from(&kem)?;
		Ok(RecipientInfo::Ori(OtherRecipientInfo { ori_type: ORI_KEM, ori_value }))
	}
}

/// What a reader unwraps the content key with, under the algorithms of the
/// provider `P` that opens.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::cms::{AuthEnvelopedData, EnvelopeError, Opener, Recipient};
/// use tightbeam::crypto::profiles::{DefaultCryptoProvider, Kek};
/// use tightbeam::der::Encode;
/// use tightbeam::oids::DATA;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
/// # runtime.block_on(async {
/// // A fixed key serves an example alone. Both ends hold the same KEK.
/// let key = [0x5au8; 32];
/// let kek = Kek::try_from(key.as_slice())?;
/// let key_identifier: &[u8] = b"example-kek";
/// let recipient: Recipient<'_, DefaultCryptoProvider> = Recipient::Kek { kek, key_identifier };
/// let sealed = AuthEnvelopedData::seal(recipient, DATA, b"content".to_vec(), [], None)?;
/// let arrived = sealed.to_der()?;
///
/// // An opener admits the recipient that names its own key alone.
/// let key_identifier: &[u8] = b"another-kek";
/// let opener: Opener<'_, DefaultCryptoProvider> = Opener::Kek { kek, key_identifier };
/// let refused = sealed.open(arrived, &opener, DATA).await;
/// assert!(matches!(refused, Err(EnvelopeError::KeyIdentifier)));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok(())
/// # }
/// ```
pub enum Opener<'a, P: CryptoProvider> {
	/// The holder of the key of a `KEMRecipientInfo`, which admits a `ukm` of
	/// `ukm_label` followed by 32 octets alone.
	Kem {
		/// The identity or bare key whose recipient key the sender
		/// encapsulated to. Its backend runs the decapsulation.
		identity: &'a dyn KemKeyHolder<P::Kem>,
		/// The purpose label the `ukm` must lead with.
		ukm_label: &'a [u8],
	},
	/// The holder of `kek`, which admits a `KEKRecipientInfo` whose
	/// `kekid.keyIdentifier` is `key_identifier` alone.
	Kek {
		/// The key-encryption key both ends hold, of the size of `P`'s wrap.
		kek: Kek<'a, P::KeyWrap>,
		/// The identifier that names `kek`.
		key_identifier: &'a [u8],
	},
}

impl<P: CryptoProvider> Opener<'_, P> {
	/// Unwrap the content key from `recipient_infos` into `content_key`, which
	/// takes it whole, under the algorithms of `P`. They must hold one
	/// recipient of this opener's kind.
	///
	/// This is the one decision on the kind of a `RecipientInfo`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::RecipientKind`] -- another number of recipients, or a recipient of another kind.
	/// - The errors of [`Self::unwrap_kem`], for a `Kem` opener.
	/// - The errors of [`Kek::unwrap_named`], for a `Kek` opener.
	/// - [`EnvelopeError::Encoding`] -- the `KEMRecipientInfo` fails to decode.
	pub(super) async fn unwrap(
		&self,
		recipient_infos: &RecipientInfos,
		content_key: &mut [u8],
	) -> Result<(), EnvelopeError> {
		match self {
			Self::Kem { identity, ukm_label } => {
				let RecipientInfo::Ori(other) = kek::sole(recipient_infos)? else {
					return Err(EnvelopeError::RecipientKind);
				};
				if other.ori_type != ORI_KEM {
					return Err(EnvelopeError::RecipientKind);
				}

				let kem = other.ori_value.decode_as::<KemRecipientInfo>()?;
				Self::unwrap_kem(*identity, ukm_label, &kem, content_key).await
			}
			Self::Kek { kek, key_identifier } => kek.unwrap_named(key_identifier, recipient_infos, content_key),
		}
	}

	/// Unwrap the content key of `kem` into `content_key` through the backend
	/// of `identity` under the KEM, the KDF, and the wrap of `P`.
	///
	/// This checks every field before the backend runs, so a refused
	/// recipient costs the backend no operation.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::RecipientVersion`] -- the version is not 0.
	/// - [`EnvelopeError::RecipientIdentifier`] -- the `rid` names another recipient than the identity's.
	/// - [`EnvelopeError::RecipientAlgorithm`] -- the KEM, the KDF, or the wrap
	///   is another than the provider's.
	/// - [`EnvelopeError::KekLength`] -- `kekLength` is another than the wrap's.
	/// - [`EnvelopeError::Ukm`] -- the `ukm` is absent or names another purpose.
	/// - The errors of [`RecipientKem::decapsulate`] for the provider's KEM.
	/// - [`EnvelopeError::Encoding`] -- the `CMSORIforKEMOtherInfo` fails to encode.
	/// - [`EnvelopeError::Kdf`] -- the KDF refused the key-encryption key.
	/// - [`EnvelopeError::Key`] -- `KeyError::KekLength`, for a key-encryption
	///   key of another length than the wrap's.
	/// - [`EnvelopeError::KeyUnwrap`] -- the wrapped content key fails its integrity check.
	async fn unwrap_kem(
		identity: &dyn KemKeyHolder<P::Kem>,
		ukm_label: &[u8],
		kem: &KemRecipientInfo,
		content_key: &mut [u8],
	) -> Result<(), EnvelopeError> {
		// 1. Hold every field to the provider's algorithms before the backend runs.
		let recipient = identity.recipient();
		if kem.version != CmsVersion::V0 {
			return Err(EnvelopeError::RecipientVersion((kem.version, CmsVersion::V0).into()));
		}
		if kem.rid != recipient.rid {
			return Err(EnvelopeError::RecipientIdentifier);
		}

		let wrap = kek::wrap_algorithm::<P::KeyWrap>();
		let named = kem.kem == kem_algorithm::<P>() && kem.kdf == kdf_algorithm::<P>();
		if !named || kem.wrap != wrap {
			return Err(EnvelopeError::RecipientAlgorithm);
		}

		let kek_length = <<P::KeyWrap as KeyWrapAlgorithm>::KekSize as Unsigned>::U16;
		if kem.kek_length != kek_length {
			return Err(EnvelopeError::KekLength(
				(usize::from(kem.kek_length), usize::from(kek_length)).into(),
			));
		}

		let ukm = kem.ukm.as_ref().filter(|ukm| ukm_admits(ukm_label, ukm.as_bytes()));
		let ukm = ukm.ok_or(EnvelopeError::Ukm)?;

		// 2. Decapsulate through the backend under the provider's KEM.
		let shared_secret = P::Kem::decapsulate(identity.key(), &recipient.key, kem.kemct.as_bytes()).await?;

		// 3. Derive the key-encryption key from the shared secret alone, and unwrap the content key under it.
		let other_info = CmsOriForKemOtherInfo { wrap, kek_length, ukm: Some(ukm.clone()) };
		let derived = other_info.derive_kek::<P::Kdf>(&shared_secret)?;
		let kek = Kek::<P::KeyWrap>::try_from(derived.as_slice())?;
		kek.unwrap_content_key(kem.encrypted_key.as_bytes(), content_key)
	}
}

impl CmsOriForKemOtherInfo {
	/// The key-encryption key `shared_secret` derives under this info: the
	/// KDF `K` with an empty salt and `DER(self)` as `info`, for `kekLength`
	/// octets (RFC 9629 §5, RFC 9688 §5.1).
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Encoding`] -- the info fails to encode.
	/// - [`EnvelopeError::Kdf`] -- the KDF refused the length.
	pub(super) fn derive_kek<K: KdfFunction>(&self, shared_secret: &[u8]) -> Result<ZeroizingBytes, EnvelopeError> {
		let info: Vec<u8> = self.to_der()?;
		let kek_size = usize::from(self.kek_length);
		Ok(K::derive_dynamic_key(shared_secret, &info, None, kek_size)?)
	}
}

/// Whether `ukm` is `label` followed by [`UKM_RANDOM_SIZE`] octets.
fn ukm_admits(label: &[u8], ukm: &[u8]) -> bool {
	ukm.strip_prefix(label).is_some_and(|random| random.len() == UKM_RANDOM_SIZE)
}
