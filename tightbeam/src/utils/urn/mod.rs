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
//!
//! fn main() -> Result<(), UrnValidationError> {
//!     // Build a URN with direct NSS
//!     let urn = UrnBuilder::default()
//!         .with_nid("tightbeam")
//!         .with_nss("instrumentation:trace:123")
//!         .build()?;
//!
//!     assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:trace:123");
//!
//!     // Build a URN from components (sorted by key)
//!     let urn = UrnBuilder::default()
//!         .with_nid("tightbeam")
//!         .set("category", "instrumentation")
//!         .set("resource.type", "trace")
//!         .set("resource.id", "123")
//!         .build()?;
//!
//!     // Components sorted: "category", "resource.id", "resource.type"
//!     assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:123:trace");
//!
//!     Ok(())
//! }
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{
	borrow::Cow,
	string::{String, ToString},
};
#[cfg(feature = "std")]
use std::borrow::Cow;

use core::fmt;
use core::str::FromStr;

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

use crate::der::{DecodeValue, EncodeValue, FixedTag, Tag};

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

	/// Validate that the NID conforms to RFC 8141 § 2.3.1
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

// Parsing always produces owned data: the input string may not outlive
// the URN, so both components are copied into `'static` Cows.
impl FromStr for Urn<'static> {
	type Err = UrnValidationError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let rest = s.strip_prefix("urn:").ok_or(UrnValidationError::InvalidUrnSyntax)?;
		let (nid, nss) = rest.split_once(':').ok_or(UrnValidationError::InvalidUrnSyntax)?;
		Self::validate_nid(nid)?;

		// RFC 8141 §2 requires at least one NSS character: "urn:nid:"
		// names nothing and would collide with every empty-NSS parse.
		if nss.is_empty() {
			return Err(UrnValidationError::InvalidUrnSyntax);
		}

		Ok(Urn { nid: Cow::Owned(nid.to_string()), nss: Cow::Owned(nss.to_string()) })
	}
}

// DER serialization: Urn is encoded as a UTF8String containing "urn:nid:nss"
impl<'a> FixedTag for Urn<'a> {
	const TAG: Tag = Tag::Utf8String;
}

impl<'a> EncodeValue for Urn<'a> {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		// "urn:" (4) + nid + ":" (1) + nss
		let total_len = 4 + self.nid.len() + 1 + self.nss.len();
		crate::der::Length::try_from(total_len)
	}

	fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		// Manually write "urn:nid:nss" without format!() for no_std compatibility
		encoder.write(b"urn:")?;
		encoder.write(self.nid.as_bytes())?;
		encoder.write(b":")?;
		encoder.write(self.nss.as_bytes())?;
		Ok(())
	}
}

// Decoding always produces owned data, so the decoded URN is `'static`
// regardless of the reader's lifetime. This is what lets derived
// `Sequence` types carry `Urn<'static>` fields directly.
impl<'a> DecodeValue<'a> for Urn<'static> {
	fn decode_value<R: crate::der::Reader<'a>>(
		reader: &mut R,
		_header: crate::der::Header,
	) -> crate::der::Result<Self> {
		let tag = Tag::Utf8String;
		let utf8_str = String::decode_value(reader, _header)?;
		utf8_str.parse().map_err(|_| crate::der::ErrorKind::Value { tag }.into())
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
	fn test_urn_from_str_round_trips_display() -> Result<(), UrnValidationError> {
		// (input, nid, nss)
		let cases: &[(&str, &str, &str)] = &[
			("urn:tightbeam:servlet:prod:ping", "tightbeam", "servlet:prod:ping"),
			(
				"urn:test:event:cluster/peer-advertised",
				"test",
				"event:cluster/peer-advertised",
			),
			("urn:my-ns:a", "my-ns", "a"),
		];

		for (input, nid, nss) in cases {
			let urn: Urn<'static> = input.parse()?;
			assert_eq!(urn.nid, *nid);
			assert_eq!(urn.nss, *nss);
			assert_eq!(urn.to_string(), *input);
		}

		Ok(())
	}

	#[test]
	fn test_urn_from_str_rejects_malformed() {
		let cases: &[&str] = &["", "urn:", "urn:onlynid", "urn:nid:", "no-prefix:nid:nss", "urn:1bad:nss"];
		for input in cases {
			assert!(input.parse::<Urn<'static>>().is_err());
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
