//! The two sides of a content key: the [`Recipient`] a sender wraps it for,
//! and the [`Opener`] a reader unwraps it with, each under the algorithms of
//! a [`CryptoProvider`].

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{KekIdentifier, KekRecipientInfo, OtherRecipientInfo, RecipientInfo, RecipientInfos};
use crate::crypto::cms::{CmsOriForKemOtherInfo, EnvelopeError, KemRecipientInfo};
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::{CryptoProvider, KeyWrapAlgorithm};
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::ext::pkix::KeyUsages;
use crate::crypto::x509::utils::{recipient_identifier_of, CertificateExt};
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Encode};
use crate::oids::ORI_KEM;
use crate::random::CryptoRngCore;
use crate::spki::AlgorithmIdentifierOwned;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::ZeroizingBytes;

/// The length in octets of the random octets that follow the purpose label
/// in a `ukm`.
pub(super) const UKM_RANDOM_SIZE: usize = 32;

/// A content key, wiped where it drops.
pub(super) type ContentKey = ZeroizingBytes;

/// The output of `Encap(pkR)` (RFC 9180 §4): the shared secret, and the
/// `kemct` that carries it to the holder of the private key.
pub struct Encapsulation {
	/// The shared secret the key-encryption key derives from.
	pub shared_secret: ZeroizingBytes,
	/// The KEM ciphertext a `KEMRecipientInfo` carries (RFC 9629 §3).
	pub kemct: Vec<u8>,
}

/// The KEM of a `KEMRecipientInfo` (RFC 9629 §3): its identifier, its
/// `Encap` to the key of a certificate, and its `Decap` through the key
/// provider of an identity.
///
/// A [`CryptoProvider`] names its KEM, so an implementor brings its own KEM
/// with an implementation of this trait on its own type.
pub trait RecipientKem {
	/// The identifier the `kem` field names, with parameters absent.
	const OID: ObjectIdentifier;

	/// `Encap(pkR)` to the key of `certificate`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError`] -- the certificate holds no key of the KEM, or a derivation failed.
	fn encapsulate(certificate: &Certificate, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError>;

	/// `Decap(kemct, skR)` through the key provider of `identity`, whose
	/// certificate the sender encapsulated to.
	///
	/// # Errors
	///
	/// - [`EnvelopeError`] -- `kemct` is no ciphertext of the KEM, or the provider or a derivation failed.
	fn decapsulate<'a>(
		identity: &'a SigningIdentity,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>>;
}

/// The wrap of every recipient under `P`, the provider's key wrap, with
/// parameters absent (RFC 3565 §2.3.2).
fn wrap_algorithm<P: CryptoProvider>() -> AlgorithmIdentifierOwned {
	let oid = <<P::KeyWrap as KeyWrapAlgorithm>::Oid as AssociatedOid>::OID;
	AlgorithmIdentifierOwned { oid, parameters: None }
}

/// Wrap `content_key` under `kek` with the provider's key wrap.
///
/// # Errors
///
/// - [`EnvelopeError::Key`] -- the wrap refused `kek` or the content key.
pub(super) fn wrap_key<P: CryptoProvider>(kek: &[u8], content_key: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
	Ok(P::KeyWrap::wrap(kek, content_key)?)
}

/// Unwrap `wrapped` under `kek` with the provider's key wrap.
///
/// # Errors
///
/// - [`EnvelopeError::KeyUnwrap`] -- `wrapped` fails the integrity check, or a length.
pub(super) fn unwrap_key<P: CryptoProvider>(kek: &[u8], wrapped: &[u8]) -> Result<ContentKey, EnvelopeError> {
	// A length or an integrity failure both leave the key wrapped, which is
	// the one refusal of RFC 3394 §2.2.3.
	P::KeyWrap::unwrap(kek, wrapped).map_err(|_| EnvelopeError::KeyUnwrap)
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

/// The recipient a sender wraps the content key for.
pub enum Recipient<'a> {
	/// The holder of the key of `certificate`, through a `KEMRecipientInfo`
	/// (RFC 9629 §3) under the provider's KEM. The `rid` names the
	/// certificate, and the `ukm` is `ukm_label` followed by 32 octets this
	/// seal draws.
	Kem {
		/// The certificate whose key the seal encapsulates to.
		certificate: &'a Certificate,
		/// The purpose label that leads the `ukm`.
		ukm_label: &'a [u8],
	},
	/// The holder of `kek`, through a `KEKRecipientInfo` (RFC 5652 §6.2.3)
	/// whose `kekid.keyIdentifier` is `key_identifier`.
	Kek {
		/// The key-encryption key both ends hold, of the size of the wrap.
		kek: &'a [u8],
		/// The identifier that names `kek`.
		key_identifier: &'a [u8],
	},
}

impl Recipient<'_> {
	/// Wrap `content_key` for this recipient under the wrap of `P`, as its
	/// `RecipientInfo`.
	///
	/// # Errors
	///
	/// - The [`Self::wrap_kem`] set, for a `Kem` recipient.
	/// - [`EnvelopeError::Key`] -- the key wrap refused `kek` or the content key.
	/// - [`EnvelopeError::Encoding`] -- the identifier fails to encode.
	pub(super) fn wrap<P: CryptoProvider>(
		&self,
		content_key: &ContentKey,
		rng: &mut dyn CryptoRngCore,
	) -> Result<RecipientInfo, EnvelopeError> {
		match self {
			Self::Kem { certificate, ukm_label } => Self::wrap_kem::<P>(certificate, ukm_label, content_key, rng),
			Self::Kek { kek, key_identifier } => {
				let kek_identifier = OctetString::new(*key_identifier)?;
				let kek_id = KekIdentifier { kek_identifier, date: None, other: None };
				let encrypted_key = OctetString::new(wrap_key::<P>(kek, content_key)?)?;
				let version = CmsVersion::V4;
				let key_enc_alg = wrap_algorithm::<P>();

				let kek = KekRecipientInfo { version, kek_id, key_enc_alg, encrypted_key };
				Ok(RecipientInfo::Kekri(kek))
			}
		}
	}

	/// Wrap `content_key` to the key of `certificate` as a `KEMRecipientInfo`
	/// in an `ori` of type `id-ori-kem`, under the KEM and the KDF of `P`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Certificate`] -- the certificate does not permit key
	///   agreement, or fails to name its key.
	/// - The [`RecipientKem::encapsulate`] set of the provider's KEM.
	/// - [`EnvelopeError::Random`] -- the random source failed.
	/// - [`EnvelopeError::Kdf`] -- the KDF refused the key-encryption key.
	/// - [`EnvelopeError::Key`] -- the key wrap refused the content key.
	/// - [`EnvelopeError::Encoding`] -- a structure fails to encode.
	fn wrap_kem<P: CryptoProvider>(
		certificate: &Certificate,
		ukm_label: &[u8],
		content_key: &ContentKey,
		rng: &mut dyn CryptoRngCore,
	) -> Result<RecipientInfo, EnvelopeError> {
		// 1. Name the recipient by its certificate, whose `keyUsage` must permit key agreement.
		certificate.require_key_usage(KeyUsages::KeyAgreement)?;
		let rid = certificate.recipient_identifier()?;

		// 2. Encapsulate to the key under the provider's KEM, and draw the random octets of the ukm.
		let Encapsulation { shared_secret, kemct } = P::Kem::encapsulate(certificate, rng)?;
		let mut random = [0u8; UKM_RANDOM_SIZE];
		rng.try_fill_bytes(&mut random).map_err(|_| EnvelopeError::Random)?;
		let ukm = OctetString::new([ukm_label, random.as_slice()].concat())?;

		// 3. Derive the key-encryption key from the shared secret alone, and
		//    wrap the content key under it (RFC 9629 §5, §7).
		let kek_length = <<P::KeyWrap as KeyWrapAlgorithm>::KekSize as Unsigned>::U16;
		let other_info = CmsOriForKemOtherInfo { wrap: wrap_algorithm::<P>(), kek_length, ukm: Some(ukm.clone()) };
		let kek = other_info.derive_kek::<P::Kdf>(&shared_secret)?;
		let encrypted_key = OctetString::new(wrap_key::<P>(&kek, content_key)?)?;

		// 4. Carry the KEM ciphertext.
		let kem = KemRecipientInfo {
			version: CmsVersion::V0,
			rid,
			kem: kem_algorithm::<P>(),
			kemct: OctetString::new(kemct)?,
			kdf: kdf_algorithm::<P>(),
			kek_length,
			ukm: Some(ukm),
			wrap: wrap_algorithm::<P>(),
			encrypted_key,
		};

		let ori_value = Any::encode_from(&kem)?;
		Ok(RecipientInfo::Ori(OtherRecipientInfo { ori_type: ORI_KEM, ori_value }))
	}
}

/// What a reader unwraps the content key with.
pub enum Opener<'a> {
	/// The holder of the key of a `KEMRecipientInfo`, which admits a `ukm` of
	/// `ukm_label` followed by 32 octets alone.
	Kem {
		/// The identity whose certificate the sender encapsulated to. Its key
		/// provider runs the decapsulation.
		identity: &'a SigningIdentity,
		/// The purpose label the `ukm` must lead with.
		ukm_label: &'a [u8],
	},
	/// The holder of `kek`, which admits a `KEKRecipientInfo` whose
	/// `kekid.keyIdentifier` is `key_identifier` alone.
	Kek {
		/// The key-encryption key both ends hold, of the size of the wrap.
		kek: &'a [u8],
		/// The identifier that names `kek`.
		key_identifier: &'a [u8],
	},
}

impl Opener<'_> {
	/// Unwrap the content key from `recipient_infos` under the algorithms of
	/// `P`. They must hold one recipient of this opener's kind.
	///
	/// This is the one decision on the kind of a `RecipientInfo`.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::RecipientKind`] -- another number of recipients, or a recipient of another kind.
	/// - The [`Self::unwrap_kem`] set, for a `Kem` opener.
	/// - The [`Self::unwrap_kek`] set, for a `Kek` opener.
	/// - [`EnvelopeError::Encoding`] -- the `KEMRecipientInfo` fails to decode.
	pub(super) async fn unwrap<P: CryptoProvider>(
		&self,
		recipient_infos: &RecipientInfos,
	) -> Result<ContentKey, EnvelopeError> {
		let [recipient] = recipient_infos.0.as_slice() else {
			return Err(EnvelopeError::RecipientKind);
		};

		match (self, recipient) {
			(Self::Kem { identity, ukm_label }, RecipientInfo::Ori(other)) if other.ori_type == ORI_KEM => {
				let kem = other.ori_value.decode_as::<KemRecipientInfo>()?;
				Self::unwrap_kem::<P>(identity, ukm_label, &kem).await
			}
			(Self::Kek { kek, key_identifier }, RecipientInfo::Kekri(kek_info)) => {
				Self::unwrap_kek::<P>(kek, key_identifier, kek_info)
			}
			_ => Err(EnvelopeError::RecipientKind),
		}
	}

	/// Unwrap the content key of `kem` through the key provider of `identity`
	/// under the KEM, the KDF, and the wrap of `P`.
	///
	/// Every field is checked before the provider runs, so a refused
	/// recipient costs the provider no operation.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::RecipientVersion`] -- the version is not 0.
	/// - [`EnvelopeError::RecipientIdentifier`] -- the `rid` names another certificate.
	/// - [`EnvelopeError::Certificate`] -- the identity's certificate does not permit key agreement.
	/// - [`EnvelopeError::RecipientAlgorithm`] -- the KEM, the KDF, or the wrap
	///   is another than the provider's.
	/// - [`EnvelopeError::KekLength`] -- `kekLength` is another than the wrap's.
	/// - [`EnvelopeError::Ukm`] -- the `ukm` is absent or names another purpose.
	/// - The [`RecipientKem::decapsulate`] set of the provider's KEM.
	/// - [`EnvelopeError::Kdf`] -- the KDF refused the key-encryption key.
	/// - [`EnvelopeError::KeyUnwrap`] -- the wrapped content key fails its integrity check.
	async fn unwrap_kem<P: CryptoProvider>(
		identity: &SigningIdentity,
		ukm_label: &[u8],
		kem: &KemRecipientInfo,
	) -> Result<ContentKey, EnvelopeError> {
		// 1. Hold every field to the provider's algorithms before the provider runs.
		if kem.version != CmsVersion::V0 {
			return Err(EnvelopeError::RecipientVersion((kem.version, CmsVersion::V0).into()));
		}
		if kem.rid != recipient_identifier_of(identity.signer_identifier()) {
			return Err(EnvelopeError::RecipientIdentifier);
		}
		identity.certificate().require_key_usage(KeyUsages::KeyAgreement)?;

		let named = kem.kem == kem_algorithm::<P>() && kem.kdf == kdf_algorithm::<P>();
		if !named || kem.wrap != wrap_algorithm::<P>() {
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

		// 2. Decapsulate through the key provider under the provider's KEM.
		let shared_secret = P::Kem::decapsulate(identity, kem.kemct.as_bytes()).await?;

		// 3. Derive the key-encryption key from the shared secret alone, and
		//    unwrap the content key under it.
		let wrap = wrap_algorithm::<P>();
		let other_info = CmsOriForKemOtherInfo { wrap, kek_length, ukm: Some(ukm.clone()) };
		let kek = other_info.derive_kek::<P::Kdf>(&shared_secret)?;
		unwrap_key::<P>(&kek, kem.encrypted_key.as_bytes())
	}

	/// Unwrap the content key of `kek_info` under `kek` and the wrap of the
	/// provider.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::RecipientVersion`] -- the version is not 4.
	/// - [`EnvelopeError::KeyIdentifier`] -- the `kekid` names another key.
	/// - [`EnvelopeError::RecipientAlgorithm`] -- the key wrap is another than the provider's.
	/// - [`EnvelopeError::KeyUnwrap`] -- the wrapped content key fails its integrity check.
	fn unwrap_kek<P: CryptoProvider>(
		kek: &[u8],
		key_identifier: &[u8],
		kek_info: &KekRecipientInfo,
	) -> Result<ContentKey, EnvelopeError> {
		if kek_info.version != CmsVersion::V4 {
			return Err(EnvelopeError::RecipientVersion((kek_info.version, CmsVersion::V4).into()));
		}

		let kek_id = &kek_info.kek_id;
		let bare = kek_id.date.is_none() && kek_id.other.is_none();
		let named = kek_id.kek_identifier.as_bytes() == key_identifier && bare;
		if !named {
			return Err(EnvelopeError::KeyIdentifier);
		}
		if kek_info.key_enc_alg != wrap_algorithm::<P>() {
			return Err(EnvelopeError::RecipientAlgorithm);
		}

		unwrap_key::<P>(kek, kek_info.encrypted_key.as_bytes())
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
	ukm.len() == label.len() + UKM_RANDOM_SIZE && ukm.starts_with(label)
}
