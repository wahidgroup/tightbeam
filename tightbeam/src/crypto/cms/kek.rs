//! The `KEKRecipientInfo` of an envelope (RFC 5652 §6.2.3): the recipient
//! that wraps the content key under a key-encryption key (KEK) both ends
//! hold, under the key wrap of a provider.
//!
//! [`Kek`] holds an in-memory KEK, checked against the size of its wrap once
//! where it is made. The record keys of a session and the in-memory frame key
//! hold one each.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::marker::PhantomData;
use core::ops::Deref;

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{KekIdentifier, KekRecipientInfo, RecipientInfo, RecipientInfos};
use crate::crypto::aead::Key;
use crate::crypto::cms::EnvelopeError;
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::key::KeyError;
use crate::crypto::profiles::KeyWrapAlgorithm;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::spki::AlgorithmIdentifierOwned;
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

/// A content key of the cipher `A`, on the stack and wiped where it drops.
pub(super) type ContentKey<A> = Zeroizing<Key<A>>;

/// A key-encryption key of the size of the key wrap `W`, wiped where it
/// drops.
///
/// [`Self::new`] is the one size check, so every wrap and unwrap under it
/// receives a key of its size.
pub(crate) struct Kek<W> {
	bytes: ZeroizingBytes,
	wrap: PhantomData<fn() -> W>,
}

impl<W: KeyWrapAlgorithm> Kek<W> {
	/// Hold `bytes` as a key-encryption key of `W`.
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `bytes` is another size than the key of `W`.
	pub(crate) fn new(bytes: impl Into<ZeroizingBytes>) -> Result<Self, KeyError> {
		let bytes = bytes.into();
		let expected = <W::KekSize as Unsigned>::USIZE;
		if bytes.len() != expected {
			return Err(KeyError::WrapLength((bytes.len(), expected).into()));
		}

		Ok(Self { bytes, wrap: PhantomData })
	}
}

/// The wrap reads the key as the octets it takes.
impl<W> Deref for Kek<W> {
	type Target = [u8];

	fn deref(&self) -> &[u8] {
		&self.bytes
	}
}

/// The key-encryption algorithm of the wrap `W`, with parameters absent (RFC
/// 3565 §2.3.2).
pub(super) fn wrap_algorithm<W: KeyWrapAlgorithm>() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: <W::Oid as AssociatedOid>::OID, parameters: None }
}

/// Wrap `content_key` under `kek` with `W`, as the `KEKRecipientInfo` that
/// `key_identifier` names.
///
/// # Errors
///
/// - [`EnvelopeError::Key`] -- the wrap refused `kek` or the content key.
/// - [`EnvelopeError::Encoding`] -- the identifier or the encrypted key fails to encode.
pub(super) fn wrap_kek<W: KeyWrapAlgorithm>(
	kek: &[u8],
	key_identifier: &[u8],
	content_key: &[u8],
) -> Result<RecipientInfo, EnvelopeError> {
	let encrypted_key = W::wrap(kek, content_key)?;
	kek_info(key_identifier, wrap_algorithm::<W>(), encrypted_key)
}

/// Unwrap the content key of the one `KEKRecipientInfo` of `recipient_infos`
/// into `content_key`, under `kek` and the wrap `W`, once it names the key
/// `key_identifier` names.
///
/// # Errors
///
/// - The [`named_kek`] set, under the key-encryption algorithm of `W`.
/// - [`EnvelopeError::KeyUnwrap`] -- the wrapped content key fails its integrity check, or is another size.
pub(super) fn unwrap_kek<W: KeyWrapAlgorithm>(
	kek: &[u8],
	key_identifier: &[u8],
	recipient_infos: &RecipientInfos,
	content_key: &mut [u8],
) -> Result<(), EnvelopeError> {
	let encrypted_key = named_kek(recipient_infos, key_identifier, &wrap_algorithm::<W>())?;
	unwrap_key::<W>(kek, encrypted_key, content_key)
}

/// Unwrap `wrapped` under `kek` with the wrap `W` into `content_key`, which
/// takes the key whole.
///
/// # Errors
///
/// - [`EnvelopeError::KeyUnwrap`] -- `wrapped` fails the integrity check, or a length.
pub(super) fn unwrap_key<W: KeyWrapAlgorithm>(
	kek: &[u8],
	wrapped: &[u8],
	content_key: &mut [u8],
) -> Result<(), EnvelopeError> {
	// A length or an integrity failure both leave the key wrapped, which is
	// the one refusal of RFC 3394 §2.2.3.
	W::unwrap_into(kek, wrapped, content_key).map_err(|_| EnvelopeError::KeyUnwrap)
}

/// The `KEKRecipientInfo` (RFC 5652 §6.2.3, version 4) of a content key
/// that `key_enc_alg` encrypted to `encrypted_key` under the key
/// `key_identifier` names.
///
/// # Errors
///
/// - [`EnvelopeError::Encoding`] -- the identifier or the encrypted key fails to encode.
pub(super) fn kek_info(
	key_identifier: &[u8],
	key_enc_alg: AlgorithmIdentifierOwned,
	encrypted_key: Vec<u8>,
) -> Result<RecipientInfo, EnvelopeError> {
	let kek_identifier = OctetString::new(key_identifier)?;
	let kek_id = KekIdentifier { kek_identifier, date: None, other: None };
	let encrypted_key = OctetString::new(encrypted_key)?;
	let version = CmsVersion::V4;

	let kek = KekRecipientInfo { version, kek_id, key_enc_alg, encrypted_key };
	Ok(RecipientInfo::Kekri(kek))
}

/// The encrypted content key of the one `KEKRecipientInfo` of
/// `recipient_infos`, once it names the key `key_identifier` names under the
/// key-encryption algorithm `key_enc_alg`.
///
/// # Errors
///
/// - [`EnvelopeError::RecipientKind`] -- another number of recipients, or a recipient of another kind.
/// - [`EnvelopeError::RecipientVersion`] -- the version is not 4.
/// - [`EnvelopeError::KeyIdentifier`] -- the `kekid` names another key.
/// - [`EnvelopeError::RecipientAlgorithm`] -- the key-encryption algorithm is another than `key_enc_alg`.
pub(super) fn named_kek<'r>(
	recipient_infos: &'r RecipientInfos,
	key_identifier: &[u8],
	key_enc_alg: &AlgorithmIdentifierOwned,
) -> Result<&'r [u8], EnvelopeError> {
	let RecipientInfo::Kekri(kek_info) = sole(recipient_infos)? else {
		return Err(EnvelopeError::RecipientKind);
	};
	if kek_info.version != CmsVersion::V4 {
		return Err(EnvelopeError::RecipientVersion((kek_info.version, CmsVersion::V4).into()));
	}

	let kek_id = &kek_info.kek_id;
	let bare = kek_id.date.is_none() && kek_id.other.is_none();
	let named = kek_id.kek_identifier.as_bytes() == key_identifier && bare;
	if !named {
		return Err(EnvelopeError::KeyIdentifier);
	}
	if kek_info.key_enc_alg != *key_enc_alg {
		return Err(EnvelopeError::RecipientAlgorithm);
	}

	Ok(kek_info.encrypted_key.as_bytes())
}

/// The one recipient of `recipient_infos`.
///
/// # Errors
///
/// - [`EnvelopeError::RecipientKind`] -- another number of recipients than one.
pub(super) fn sole(recipient_infos: &RecipientInfos) -> Result<&RecipientInfo, EnvelopeError> {
	let [recipient] = recipient_infos.0.as_slice() else {
		return Err(EnvelopeError::RecipientKind);
	};

	Ok(recipient)
}
