#[cfg(feature = "aead")]
#[inline]
pub(crate) fn key_from_slice(bytes: &[u8]) -> crate::crypto::aead::Key<crate::crypto::aead::Aes256Gcm> {
	debug_assert_eq!(bytes.len(), 32);
	let mut array = [0u8; 32];
	array.copy_from_slice(bytes);
	array.into()
}

#[cfg(feature = "aead")]
#[inline]
pub(crate) fn nonce_from_slice<A: crate::crypto::aead::Aead>(bytes: &[u8]) -> crate::crypto::aead::Nonce<A> {
	let len = core::mem::size_of::<crate::crypto::aead::Nonce<A>>();
	debug_assert_eq!(bytes.len(), len);
	let mut array = aead::Nonce::<A>::default();
	let array_slice: &mut [u8] = array.as_mut();
	array_slice.copy_from_slice(bytes);
	array
}
