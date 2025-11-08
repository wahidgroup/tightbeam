//! Secret handling utilities for Tightbeam
#![forbid(unsafe_code)]
//!
//! A minimal secret wrapper providing:
//! - Strict ownership (no Clone/Copy)
//! - Explicit access via ExposeSecret/ExposeSecretMut
//! - Zeroize on drop for the inner value
//! - Blanket From<T> for ergonomic construction

use core::convert::Infallible;
use core::str::FromStr;
use core::{any, fmt};

use crate::der::{self, Decode, Encode, FixedTag};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

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
	pub fn with<R>(&self, f: impl FnOnce(&S) -> R) -> R {
		let inner = self.inner.as_ref().expect("secret moved");
		f(inner.as_ref())
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

/// Blanket conversion from owning values into Secret<T>.
impl<S> From<S> for Secret<S>
where
	S: Zeroize + Encode + for<'a> Decode<'a>,
{
	fn from(src: S) -> Self {
		Secret { inner: Some(Box::new(src)) }
	}
}

/// Conversion from boxed values into Secret<T>.
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

/// Secret slice alias (owns Box<[T]>)
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

/// Secret string alias (owns Box<str>)
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
	type Err = Infallible;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(SecretString::from(s))
	}
}

/// Convert a Secret into its raw underlying type (consumes the Secret).
///
/// - For sized inner types `S`, `to_insecure()` returns `S` by value.
/// - For dynamically sized inner types like `[T]` and `str`, it returns a
///   `Box<[T]>` or `Box<str>`.
pub trait ToInsecure {
	type Raw;
	fn to_insecure(self) -> Self::Raw;
}

impl<S: Zeroize> ToInsecure for Secret<S> {
	type Raw = S;
	fn to_insecure(self) -> S {
		let mut this = self;
		let inner_box = this.inner.take().expect("secret moved");
		*inner_box
	}
}

impl<T> ToInsecure for Secret<[T]>
where
	T: Zeroize,
	[T]: Zeroize,
{
	type Raw = Box<[T]>;

	fn to_insecure(self) -> Box<[T]> {
		let mut this = self;
		this.inner.take().expect("secret moved")
	}
}

impl ToInsecure for Secret<str> {
	type Raw = Box<str>;

	fn to_insecure(self) -> Box<str> {
		let mut this = self;
		this.inner.take().expect("secret moved")
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_secret_string_from_str() {
		let s = SecretString::from_str("test").unwrap();
		assert_eq!(s.to_insecure(), "test".into());
	}

	#[test]
	fn test_to_insecure_sized() {
		let s: Secret<[u8; 2]> = Secret::from([1u8, 2u8]);
		let raw = s.to_insecure();
		assert_eq!(raw, [1, 2]);
	}

	#[test]
	fn test_to_insecure_dsts() {
		let s: SecretString = SecretString::from("abc");
		let raw: Box<str> = s.to_insecure();
		assert_eq!(&*raw, "abc");

		let s2: SecretSlice<u8> = Vec::from([9u8, 8u8, 7u8]).into();
		let raw2: Box<[u8]> = s2.to_insecure();
		assert_eq!(&*raw2, &[9, 8, 7]);
	}

	#[test]
	fn test_with_immutable_access() {
		let s: SecretString = SecretString::from("abcdef");
		let len = s.with(|inner| inner.len());
		assert_eq!(len, 6);

		let raw = s.to_insecure();
		assert_eq!(&*raw, "abcdef");
	}
}
