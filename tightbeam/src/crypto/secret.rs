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
/// The value lives in a [`Zeroizing`] buffer for its whole life, so the
/// secret is present in every state and every accessor is total. The type
/// implements neither `Clone` nor `Copy`, which keeps ownership strict.
pub struct Secret<S: Zeroize>(Zeroizing<S>);

impl<S: Zeroize> Secret<S> {
	/// Borrow the inner secret immutably for the duration of `f`, so a caller
	/// can inspect it without an owned copy.
	pub fn with<R>(&self, f: impl FnOnce(&S) -> R) -> R {
		f(&self.0)
	}
}

impl<S: Zeroize> ZeroizeOnDrop for Secret<S> {}

impl<S: Zeroize> fmt::Debug for Secret<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Secret<{}>([REDACTED])", any::type_name::<S>())
	}
}

/// Wraps an owned value. A `Vec` keeps its allocation, so wrapping copies
/// no secret bytes, and the wipe on drop covers the whole capacity.
impl<S: Zeroize> From<S> for Secret<S> {
	fn from(src: S) -> Self {
		Self(Zeroizing::new(src))
	}
}

/// Adopts a value that already lives in a wiping buffer, so a secret copied
/// into a [`Zeroizing`] array reaches its wrapper without a plain copy on the
/// way (CWE-226).
impl<S: Zeroize> From<Zeroizing<S>> for Secret<S> {
	fn from(src: Zeroizing<S>) -> Self {
		Self(src)
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
	use crate::testing::TestResult;

	/// A secret string parses from a `str` and holds the text it parsed.
	#[test]
	fn a_secret_string_parses_from_a_str() -> TestResult {
		let secret = SecretString::from_str("test")?;
		assert_eq!(secret.to_insecure().as_str(), "test");
		Ok(())
	}

	/// An exposed sized secret hands back the value it wrapped.
	#[test]
	fn an_exposed_sized_secret_hands_back_its_value() {
		let secret: Secret<[u8; 2]> = Secret::from([1u8, 2u8]);
		let raw = secret.to_insecure();
		assert_eq!(*raw, [1, 2]);
	}

	/// An exposed secret string hands back the text it wrapped.
	#[test]
	fn an_exposed_secret_string_hands_back_its_text() {
		let secret = SecretString::from("abc");
		assert_eq!(secret.to_insecure().as_str(), "abc");
	}

	/// An exposed secret slice hands back the octets it wrapped.
	#[test]
	fn an_exposed_secret_slice_hands_back_its_octets() {
		let secret: SecretSlice<u8> = Vec::from([9u8, 8u8, 7u8]).into();
		assert_eq!(secret.to_insecure().as_slice(), &[9, 8, 7]);
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

	/// Compiles only for a type whose values wipe when they drop.
	fn assert_wipes_on_drop<T: ZeroizeOnDrop>() {}

	/// An exposed secret still owns key material, so the value it hands back
	/// wipes when it drops.
	#[test]
	fn an_exposed_secret_wipes_on_drop() {
		assert_wipes_on_drop::<<Secret<[u8; 2]> as ToInsecure>::Raw>();
		assert_wipes_on_drop::<<SecretSlice<u8> as ToInsecure>::Raw>();
		assert_wipes_on_drop::<<SecretString as ToInsecure>::Raw>();
	}

	/// `with` lends the wrapped value to its closure.
	#[test]
	fn a_secret_lends_its_value_to_a_closure() {
		let secret = SecretString::from("abcdef");
		assert_eq!(secret.with(String::len), 6);
	}

	/// A loan through `with` leaves the wrapped value in place.
	#[test]
	fn a_lent_secret_keeps_its_value() {
		let secret = SecretString::from("abcdef");
		secret.with(String::len);
		assert_eq!(secret.to_insecure().as_str(), "abcdef");
	}
}
