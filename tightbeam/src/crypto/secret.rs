//! Secret handling for Tightbeam.
//!
//! [`Secret`] is a minimal secret wrapper with these properties:
//!
//! - Ownership is strict.
//! - [`Secret::with`] gives borrowed access, and [`ToInsecure::to_insecure`]
//!   gives owned access through a wiping buffer.
//! - The inner value zeroizes on drop, over its whole allocation.
#![forbid(unsafe_code)]

use core::str::FromStr;
use core::{any, fmt};

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A secret wrapper that zeroizes its inner value on drop.
///
/// The value lives in a [`Zeroizing`] buffer for its whole life, so no state
/// exists in which the secret is missing and every accessor is total. The
/// type does not implement Clone or Copy, which keeps ownership strict.
pub struct Secret<S: Zeroize>(Zeroizing<S>);

impl<S: Zeroize> Secret<S> {
	/// Borrow the inner secret immutably for the duration of `f`, so a caller
	/// can inspect it without an owned copy.
	pub fn with<R>(&self, f: impl FnOnce(&S) -> R) -> R {
		f(&self.0)
	}

	/// Move the value into a frame body, which wipes it when the frame drops.
	///
	/// The allocation moves, so no copy is made. The exit is crate-private, so
	/// every owner that receives a secret this way wipes it.
	pub(crate) fn release(mut self) -> S
	where
		S: Default,
	{
		core::mem::take(&mut *self.0)
	}
}

impl<S: Zeroize> ZeroizeOnDrop for Secret<S> {}

impl<S: Zeroize> fmt::Debug for Secret<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Secret<{}>([REDACTED])", any::type_name::<S>())
	}
}

/// Wrap an owned value. A `Vec` keeps its allocation, so no copy of the
/// secret is made on the way in, and the wipe on drop covers the whole
/// capacity.
impl<S: Zeroize> From<S> for Secret<S> {
	fn from(src: S) -> Self {
		Self(Zeroizing::new(src))
	}
}

/// Secret byte or element buffer.
pub type SecretSlice<T> = Secret<Vec<T>>;

/// Secret string.
pub type SecretString = Secret<String>;

impl From<&str> for SecretString {
	fn from(s: &str) -> Self {
		Secret::from(String::from(s))
	}
}

impl FromStr for SecretString {
	type Err = core::convert::Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(SecretString::from(s))
	}
}

/// Move a secret out of its [`Secret`] wrapper, consuming the wrapper.
///
/// The value still holds key material, so it comes back in a [`Zeroizing`]
/// buffer that wipes when it drops. [`Zeroizing`] dereferences to the value,
/// so a caller reads, encodes, and sends it as it would the raw form. A copy
/// that outlives the buffer, such as one an FFI boundary demands, is an
/// explicit copy out of it.
pub trait ToInsecure {
	/// The wiping buffer that carries the exposed secret.
	type Raw: ZeroizeOnDrop;

	/// Take the secret out of its wrapper.
	fn to_insecure(self) -> Self::Raw;
}

impl<S: Zeroize> ToInsecure for Secret<S> {
	type Raw = Zeroizing<S>;

	fn to_insecure(self) -> Self::Raw {
		self.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_secret_string_from_str() -> Result<(), core::convert::Infallible> {
		let s = SecretString::from_str("test")?;
		assert_eq!(s.to_insecure().as_str(), "test");
		Ok(())
	}

	#[test]
	fn test_to_insecure_sized() {
		let s: Secret<[u8; 2]> = Secret::from([1u8, 2u8]);
		let raw = s.to_insecure();
		assert_eq!(*raw, [1, 2]);
	}

	#[test]
	fn test_to_insecure_buffers() {
		let s: SecretString = SecretString::from("abc");
		assert_eq!(s.to_insecure().as_str(), "abc");

		let s2: SecretSlice<u8> = Vec::from([9u8, 8u8, 7u8]).into();
		assert_eq!(s2.to_insecure().as_slice(), &[9, 8, 7]);
	}

	/// Wrapping a buffer keeps its allocation, so the bytes that arrived are
	/// the bytes that get wiped, spare capacity included.
	#[test]
	fn wrapping_a_buffer_keeps_its_allocation() {
		let mut plaintext = Vec::with_capacity(64);
		plaintext.extend_from_slice(&[0xA5; 48]);

		let address = plaintext.as_ptr();
		let secret = SecretSlice::from(plaintext);
		assert_eq!(secret.with(|bytes| bytes.as_ptr()), address);
		assert_eq!(secret.with(Vec::capacity), 64);
	}

	/// Releasing moves the allocation out without a copy.
	#[test]
	fn releasing_a_buffer_moves_its_allocation() {
		let plaintext = vec![0x5Au8; 32];
		let address = plaintext.as_ptr();

		let released = SecretSlice::from(plaintext).release();
		assert_eq!(released.as_ptr(), address);
	}

	/// A type whose values wipe when they drop.
	fn assert_wipes_on_drop<T: ZeroizeOnDrop>() {}

	// An exposed secret still owns key material, so the value it hands back
	// wipes when it drops.
	#[test]
	fn an_exposed_secret_wipes_on_drop() {
		assert_wipes_on_drop::<<Secret<[u8; 2]> as ToInsecure>::Raw>();
		assert_wipes_on_drop::<<SecretSlice<u8> as ToInsecure>::Raw>();
		assert_wipes_on_drop::<<SecretString as ToInsecure>::Raw>();
	}

	#[test]
	fn test_with_immutable_access() {
		let s: SecretString = SecretString::from("abcdef");
		assert_eq!(s.with(String::len), 6);
		assert_eq!(s.to_insecure().as_str(), "abcdef");
	}
}
