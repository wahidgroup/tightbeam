//! RFC 8141 compliant URN (Uniform Resource Name) implementation
//!
//! See: `<https://datatracker.ietf.org/doc/html/rfc8141>`
//!
//! Provides zero-copy URN construction with declarative specification support
//! for validation and hierarchical NSS (Namespace-Specific String) structure.
//!
//! # RFC 8141 Format
//!
//! ```text
//! urn:<NID>:<NSS>
//! ```
//!
//! Note:
//! The optional r-component, q-component, and f-component extensions from RFC
//! 8141 are not included in this basic implementation.
//!
//! Where:
//! - **NID**: Namespace Identifier (2-32 chars, alphanumeric+hyphen, starts with letter)
//! - **NSS**: Namespace-Specific String (structure defined by namespace spec)
//!
//! # Examples
//!
//! ```rust
//! use tightbeam::utils::urn::{Urn, UrnBuilder, UrnValidationError};
//! use tightbeam::builder::TypeBuilder;
//!
//! fn main() -> Result<(), UrnValidationError> {
//!     // Build a URN with direct NSS
//!     let urn = UrnBuilder::new()
//!         .with_nid("tightbeam")
//!         .with_nss("instrumentation:trace:123")
//!         .build()?;
//!
//!     assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:trace:123");
//!
//!     // Build a URN from components (sorted by key)
//!     let urn = UrnBuilder::new()
//!         .with_nid("tightbeam")
//!         .set("category", "instrumentation")
//!         .set("resource.type", "trace")
//!         .set("resource.id", "123")
//!         .build()?;
//!
//!     // Components sorted: "category", "resource.id", "resource.type"
//!     assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:123:trace");
//!
//!     // Build a URN with a spec (recommended pattern)
//!     use tightbeam::utils::urn::specs::tightbeam::TightbeamUrnSpec;
//!     let urn = UrnBuilder::from(TightbeamUrnSpec)
//!         .set("category", "instrumentation")
//!         .set("resource_type", "trace")
//!         .set("resource_id", "abc-123")
//!         .build()?;
//!
//!     assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:trace/abc-123");
//!     Ok(())
//! }
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String};

#[cfg(feature = "std")]
use std::borrow::Cow;

use core::fmt;

#[macro_use]
mod macros;

pub mod builders;
pub mod error;
pub mod spec;
#[cfg(test)]
pub mod specs;

pub use builders::{UrnBuilder, UrnSpecBuilder};
pub use error::UrnValidationError;
pub use spec::{UrnComponents, UrnSpec};

use crate::der::{Decode, DecodeValue, EncodeValue, Tag, Tagged};

/// RFC 8141 compliant URN structure
///
/// Uses `Cow<'a, str>` for zero-copy string handling.
///
/// DER serialization: Encoded as a UTF8String containing the full URN representation "urn:nid:nss".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urn<'a> {
	/// Namespace Identifier (2-32 chars, alphanumeric+hyphen, starts with letter)
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.1>`
	pub nid: Cow<'a, str>,

	/// Namespace-Specific String (structure defined by namespace)
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.2>`
	pub nss: Cow<'a, str>,
}

impl<'a> Urn<'a> {
	/// Create an unchecked URN from static strings
	///
	/// This can be used in const contexts to define constant URNs.
	/// No validation is performed - use `verify::<Spec>()` at runtime
	/// to validate against a spec.
	///
	/// # Example
	///
	/// ```rust
	/// # use tightbeam::utils::urn::Urn;
	/// const EXAMPLE_URN: Urn<'static> = Urn::new("example", "test:resource");
	/// ```
	#[inline]
	pub const fn new(nid: &'static str, nss: &'static str) -> Urn<'static> {
		Urn { nid: Cow::Borrowed(nid), nss: Cow::Borrowed(nss) }
	}

	/// Verify this URN against a spec
	///
	/// Validates that:
	/// - The NID matches the spec's NID
	/// - The NID format is valid (RFC 8141 compliant)
	/// - The NSS structure conforms to the spec's requirements
	pub fn verify<S: UrnSpec>(&self) -> Result<(), UrnValidationError> {
		// Check NID matches spec
		if self.nid.as_ref() != S::NID {
			return Err(UrnValidationError::NidMismatch);
		}

		// Validate NID format
		Self::validate_nid(self.nid.as_ref())?;

		// Create a builder with this URN's data for spec validation
		let builder = UrnBuilder::default().with_nid(self.nid.as_ref()).with_nss(self.nss.as_ref());

		// Validate using the spec with UrnComponents trait
		S::validate(&builder as &dyn UrnComponents)
	}

	/// Validate that the NID conforms to RFC 8141 Section 2.3.1
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.1>`
	///
	/// NID must be 2-32 characters, alphanumeric plus hyphens, starting with a letter.
	/// This implements the formal-namespace-identifier production from RFC 8141.
	pub fn validate_nid(nid: &str) -> Result<(), UrnValidationError> {
		let len = nid.len();
		if !(2..=32).contains(&len) {
			return Err(UrnValidationError::InvalidNidLength);
		}

		let mut chars = nid.chars();
		if let Some(first) = chars.next() {
			if !first.is_ascii_alphabetic() {
				return Err(UrnValidationError::InvalidNidStart);
			}
		}

		for ch in chars {
			if !ch.is_ascii_alphanumeric() && ch != '-' {
				return Err(UrnValidationError::InvalidNidCharacters);
			}
		}

		Ok(())
	}

	/// Convert the URN to an owned version with 'static lifetime
	///
	/// This converts borrowed strings to owned strings, allowing the URN
	/// to outlive its original data sources. This is similar to `Cow::into_owned()`.
	#[inline]
	pub fn into_owned(self) -> Urn<'static> {
		Urn { nid: Cow::Owned(self.nid.into_owned()), nss: Cow::Owned(self.nss.into_owned()) }
	}
}

impl<'a> fmt::Display for Urn<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "urn:{}:{}", self.nid, self.nss)
	}
}

// DER serialization: Urn is encoded as a UTF8String containing "urn:nid:nss"
impl<'a> Tagged for Urn<'a> {
	fn tag(&self) -> Tag {
		Tag::Utf8String
	}
}

impl<'a> EncodeValue for Urn<'a> {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		let urn_str = format!("urn:{}:{}", self.nid, self.nss);
		urn_str.value_len()
	}

	fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		let urn_str = format!("urn:{}:{}", self.nid, self.nss);
		urn_str.encode_value(encoder)
	}
}

impl<'a> DecodeValue<'a> for Urn<'a> {
	fn decode_value<R: crate::der::Reader<'a>>(
		reader: &mut R,
		_header: crate::der::Header,
	) -> crate::der::Result<Self> {
		let utf8_str = String::decode_value(reader, _header)?;
		let urn_str = utf8_str.as_str();

		// Parse "urn:nid:nss" format
		if !urn_str.starts_with("urn:") {
			return Err(crate::der::ErrorKind::Value { tag: Tag::Utf8String }.into());
		}

		let rest = &urn_str[4..]; // Skip "urn:"
		let colon_pos = rest
			.find(':')
			.ok_or_else(|| crate::der::ErrorKind::Value { tag: Tag::Utf8String })?;

		let nid = &rest[..colon_pos];
		let nss = &rest[colon_pos + 1..];

		Ok(Urn { nid: Cow::Owned(nid.to_string()), nss: Cow::Owned(nss.to_string()) })
	}
}

impl<'a> Decode<'a> for Urn<'a> {
	fn decode<R: crate::der::Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		let header = reader.peek_header()?;
		Self::decode_value(reader, header)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_urn_nid_validation() {
		// Valid NIDs
		let valid_cases: &[&str] = &["ab", "tightbeam", "isbn", "a123", "my-namespace"];
		for nid in valid_cases {
			assert!(Urn::validate_nid(nid).is_ok());
		}

		// Invalid NIDs - too short
		assert!(Urn::validate_nid("a").is_err());

		// Invalid NIDs - too long
		let too_long = "a".repeat(33);
		assert!(Urn::validate_nid(&too_long).is_err());

		// Invalid NIDs - doesn't start with letter
		let invalid_start: &[&str] = &["1abc", "-abc"];
		for nid in invalid_start {
			assert!(Urn::validate_nid(nid).is_err());
		}

		// Invalid NIDs - invalid characters
		let invalid_chars: &[&str] = &["ab_cd", "ab.cd"];
		for nid in invalid_chars {
			assert!(Urn::validate_nid(nid).is_err());
		}
	}

	#[test]
	fn test_urn_to_owned() {
		// (nid, nss)
		let test_cases: &[(&str, &str)] = &[
			("tightbeam", "test:resource"),
			("example", "path/to/resource"),
			("test", "simple"),
		];

		for (nid, nss) in test_cases {
			let urn = Urn { nid: Cow::Borrowed(*nid), nss: Cow::Borrowed(*nss) };
			let owned_urn = urn.into_owned();
			assert!(matches!(owned_urn.nid, Cow::Owned(_)));
			assert!(matches!(owned_urn.nss, Cow::Owned(_)));
			assert_eq!(owned_urn.nid, *nid);
			assert_eq!(owned_urn.nss, *nss);
		}
	}
}
