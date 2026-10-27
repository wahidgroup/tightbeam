//! The `KEKRecipientInfo` of an envelope (RFC 5652 §6.2.3): the recipient
//! that wraps the content key under a key-encryption key (KEK) both ends
//! hold, under the key wrap of a provider.
//!
//! [`OwnedKek`] holds an in-memory KEK, which passed the one length check of
//! [`Kek`] where it is made. The record keys of a session, the in-memory
//! frame key, and the handshake sealer hold one each.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{KekIdentifier, KekRecipientInfo, RecipientInfo, RecipientInfos};
use crate::crypto::aead::Key;
use crate::crypto::cms::EnvelopeError;
use crate::crypto::common::generic_array::GenericArray;
use crate::crypto::key::KeyError;
use crate::crypto::profiles::{Kek, KeyWrapAlgorithm};
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::spki::AlgorithmIdentifierOwned;
use crate::zeroize::Zeroizing;

/// A content key of the cipher `A`, on the stack and wiped where it drops.
pub(super) type ContentKey<A> = Zeroizing<Key<A>>;

/// A key-encryption key of the size of the key wrap `W`, held on the heap and
/// wiped where it drops.
///
/// [`TryFrom`] on a slice copies a key that passed the one length check of
/// [`Kek`], and [`Self::kek`] lends it to each wrap and unwrap under `W`.
pub(crate) struct OwnedKek<W: KeyWrapAlgorithm> {
	/// The key on the heap, so a move of the holder moves a pointer alone.
	key: Box<Zeroizing<GenericArray<u8, W::KekSize>>>,
}

impl<W: KeyWrapAlgorithm> OwnedKek<W> {
	/// The key, lent to a wrap or an unwrap under `W`.
	pub(crate) fn kek(&self) -> Kek<'_, W> {
		Kek::from(&**self.key)
	}
}

/// The one length check of [`Kek`], then one copy of the key.
impl<W: KeyWrapAlgorithm> TryFrom<&[u8]> for OwnedKek<W> {
	type Error = KeyError;

	/// Hold a copy of the key that `key` holds.
	///
	/// # Errors
	///
	/// - [`KeyError::KekLength`] -- `key` is another length than [`KeyWrapAlgorithm::KekSize`].
	fn try_from(key: &[u8]) -> Result<Self, KeyError> {
		let kek = Kek::<W>::try_from(key)?;

		// The buffer is on the heap before the key is copied into it.
		let mut key = Box::new(Zeroizing::new(GenericArray::default()));
		key.iter_mut().zip(kek.as_array()).for_each(|(slot, octet)| *slot = *octet);
		Ok(Self { key })
	}
}

/// The key-encryption algorithm of the wrap `W`, with parameters absent (RFC
/// 3565 §2.3.2).
pub(super) fn wrap_algorithm<W: KeyWrapAlgorithm>() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: <W::Oid as AssociatedOid>::OID, parameters: None }
}

/// The behavior of a key-encryption key in a `KEKRecipientInfo`.
impl<W: KeyWrapAlgorithm> Kek<'_, W> {
	/// Wrap `content_key` under this key with `W`, as the `KEKRecipientInfo`
	/// that `key_identifier` names.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::Key`] -- the wrap refused the content key.
	/// - [`EnvelopeError::Encoding`] -- the identifier or the encrypted key fails to encode.
	pub(super) fn recipient_info(
		&self,
		key_identifier: &[u8],
		content_key: &[u8],
	) -> Result<RecipientInfo, EnvelopeError> {
		let encrypted_key = W::wrap(self, content_key)?;
		kek_info(key_identifier, wrap_algorithm::<W>(), encrypted_key)
	}

	/// Unwrap the content key of the one `KEKRecipientInfo` of
	/// `recipient_infos` into `content_key`, under this key and the wrap `W`,
	/// once it names the key `key_identifier` names.
	///
	/// # Errors
	///
	/// - The errors of [`named_kek`], under the key-encryption algorithm of `W`.
	/// - [`EnvelopeError::KeyUnwrap`] -- the wrapped content key fails its
	///   integrity check, or is another size.
	pub(super) fn unwrap_named(
		&self,
		key_identifier: &[u8],
		recipient_infos: &RecipientInfos,
		content_key: &mut [u8],
	) -> Result<(), EnvelopeError> {
		let encrypted_key = named_kek(recipient_infos, key_identifier, &wrap_algorithm::<W>())?;
		self.unwrap_content_key(encrypted_key, content_key)
	}

	/// Unwrap `wrapped` under this key with the wrap `W` into `content_key`,
	/// which takes the key whole.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::KeyUnwrap`] -- `wrapped` fails the integrity check, or a length.
	pub(super) fn unwrap_content_key(&self, wrapped: &[u8], content_key: &mut [u8]) -> Result<(), EnvelopeError> {
		// A length or an integrity failure both leave the key wrapped, which is
		// the one refusal of RFC 3394 §2.2.3.
		W::unwrap_into(self, wrapped, content_key).map_err(|_| EnvelopeError::KeyUnwrap)
	}
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
/// - [`EnvelopeError::KeyIdentifier`] -- the `kekid` names another key, or carries a `date` or an `other`.
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
