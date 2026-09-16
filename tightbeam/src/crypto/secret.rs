//! Secret handling utilities for Tightbeam
//!
//! A minimal secret wrapper providing:
//! - Strict ownership (no Clone/Copy)
//! - Borrowed access through [`Secret::with`], and owned access through
//!   [`ToInsecure::to_insecure`], which hands back a wiping buffer
//! - Zeroize on drop for the inner value
//! - Blanket `From<T>` for ergonomic construction
#![forbid(unsafe_code)]

use core::str::FromStr;
use core::{any, fmt};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

use crate::der::{self, Decode, Encode, FixedTag};
use crate::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use crate::Errorizable;

/// Error returned by [`Secret`] accessors when the wrapped value is
/// unavailable, e.g. already consumed via [`ToInsecure::to_insecure`] or
/// never present.
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
	/// Secret value is unavailable (already consumed or never set).
	#[error("Secret value is unavailable")]
	Unavailable,
}

/// A secret wrapper that zeroizes its inner value on drop.
///
/// This type owns the inner secret (boxed for possible DST support) and
/// does not implement Clone/Copy to preserve strict ownership semantics.
pub struct Secret<S: Zeroize + ?Sized> {
	inner: Option<Box<S>>,
}

impl<S: Zeroize + ?Sized> Secret<S> {
	/// Construct from a pre-boxed secret value.
	pub fn new(boxed: Box<S>) -> Self {
		Self { inner: Some(boxed) }
	}

	/// Ephemeral immutable access to the inner secret via a closure to allow
	/// for secure introspection.
	pub fn with<R>(&self, f: impl FnOnce(&S) -> R) -> Result<R, SecretError> {
		match self.inner.as_ref() {
			Some(inner) => Ok(f(inner.as_ref())),
			None => Err(SecretError::Unavailable),
		}
	}
}

impl<S: Zeroize + ?Sized> Zeroize for Secret<S> {
	fn zeroize(&mut self) {
		if let Some(inner) = self.inner.as_mut() {
			inner.as_mut().zeroize();
		}
	}
}

impl<S: Zeroize + ?Sized> Drop for Secret<S> {
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl<S: Zeroize + ?Sized> ZeroizeOnDrop for Secret<S> {}

impl<S: Zeroize + ?Sized> fmt::Debug for Secret<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Secret<{}>([REDACTED])", any::type_name::<S>())
	}
}

/// Blanket conversion from owning values into `Secret<T>`.
impl<S> From<S> for Secret<S>
where
	S: Zeroize + Encode + for<'a> Decode<'a>,
{
	fn from(src: S) -> Self {
		Secret { inner: Some(Box::new(src)) }
	}
}

/// Conversion from boxed values into `Secret<T>`.
impl<S: Zeroize + ?Sized> From<Box<S>> for Secret<S> {
	fn from(b: Box<S>) -> Self {
		Secret::new(b)
	}
}

impl<S> FixedTag for Secret<S>
where
	S: Zeroize + FixedTag + ?Sized,
{
	const TAG: der::Tag = S::TAG;
}

/// Secret slice alias (owns `Box<[T]>`)
pub type SecretSlice<T> = Secret<[T]>;

impl<T> From<Vec<T>> for SecretSlice<T>
where
	T: Zeroize,
	[T]: Zeroize,
{
	fn from(v: Vec<T>) -> Self {
		Secret::from(v.into_boxed_slice())
	}
}

impl<T> SecretSlice<T>
where
	T: Zeroize,
	[T]: Zeroize,
{
	/// Take ownership of the buffer, moving the allocation.
	///
	/// [`ToInsecure::to_insecure`] hands back a wiping buffer that cannot
	/// release what it holds, so a caller who must own the bytes copies them
	/// out of it. This moves the allocation instead and transfers the duty to
	/// wipe it. Reach for it only where the copy is the thing being avoided.
	///
	/// # Errors
	///
	/// - [`SecretError::Unavailable`] when the secret was already taken.
	pub fn into_boxed_slice(mut self) -> Result<Box<[T]>, SecretError> {
		self.inner.take().ok_or(SecretError::Unavailable)
	}
}

/// Secret string alias (owns `Box<str>`)
pub type SecretString = Secret<str>;

impl From<String> for SecretString {
	fn from(s: String) -> Self {
		Secret::from(s.into_boxed_str())
	}
}

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
///
/// - For sized inner types `S`, `to_insecure()` returns `Zeroizing<S>`.
/// - For dynamically sized inner types like `[T]` and `str`, it returns a
///   `Zeroizing<Box<[T]>>` or `Zeroizing<Box<str>>`.
pub trait ToInsecure {
	/// The wiping buffer that carries the exposed secret.
	type Raw: ZeroizeOnDrop;

	/// Take the secret out of its wrapper.
	///
	/// # Errors
	///
	/// - [`SecretError::Unavailable`] when the secret was already taken.
	fn to_insecure(self) -> Result<Self::Raw, SecretError>;
}

impl<S: Zeroize> ToInsecure for Secret<S> {
	type Raw = Zeroizing<S>;

	fn to_insecure(self) -> Result<Self::Raw, SecretError> {
		let mut this = self;
		match this.inner.take() {
			Some(inner_box) => Ok(Zeroizing::new(*inner_box)),
			None => Err(SecretError::Unavailable),
		}
	}
}

impl<T> ToInsecure for Secret<[T]>
where
	T: Zeroize,
	[T]: Zeroize,
{
	type Raw = Zeroizing<Box<[T]>>;

	fn to_insecure(self) -> Result<Self::Raw, SecretError> {
		let mut this = self;
		match this.inner.take() {
			Some(inner) => Ok(Zeroizing::new(inner)),
			None => Err(SecretError::Unavailable),
		}
	}
}

impl ToInsecure for Secret<str> {
	type Raw = Zeroizing<Box<str>>;

	fn to_insecure(self) -> Result<Self::Raw, SecretError> {
		let mut this = self;
		match this.inner.take() {
			Some(inner) => Ok(Zeroizing::new(inner)),
			None => Err(SecretError::Unavailable),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_secret_string_from_str() -> Result<(), Box<dyn std::error::Error>> {
		let s = SecretString::from_str("test")?;
		assert_eq!(&**s.to_insecure()?, "test");
		Ok(())
	}

	#[test]
	fn test_to_insecure_sized() -> Result<(), Box<dyn std::error::Error>> {
		let s: Secret<[u8; 2]> = Secret::from([1u8, 2u8]);
		let raw = s.to_insecure()?;
		assert_eq!(*raw, [1, 2]);
		Ok(())
	}

	#[test]
	fn test_to_insecure_dsts() -> Result<(), Box<dyn std::error::Error>> {
		let s: SecretString = SecretString::from("abc");
		let raw = s.to_insecure()?;
		assert_eq!(&**raw, "abc");

		let s2: SecretSlice<u8> = Vec::from([9u8, 8u8, 7u8]).into();
		let raw2 = s2.to_insecure()?;
		assert_eq!(&**raw2, &[9, 8, 7]);
		Ok(())
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
	fn test_with_immutable_access() -> Result<(), Box<dyn std::error::Error>> {
		let s: SecretString = SecretString::from("abcdef");
		let len = s.with(|inner| inner.len())?;
		assert_eq!(len, 6);

		let raw = s.to_insecure()?;
		assert_eq!(&**raw, "abcdef");
		Ok(())
	}
}
