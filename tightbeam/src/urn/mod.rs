//! An RFC 8141 URN (Uniform Resource Name).
//!
//! The format follows `<https://datatracker.ietf.org/doc/html/rfc8141>`.
//!
//! It provides zero-copy URN construction, and a declarative specification
//! validates the hierarchical NSS (Namespace-Specific String) structure.
//!
//! # RFC 8141 Format
//!
//! ```text
//! urn:<NID>:<NSS>
//! ```
//!
//! The two parts are:
//! - **NID**: the Namespace Identifier, 2 to 32 ASCII letters, digits, or
//!   hyphens, with a letter first and a letter or digit last.
//! - **NSS**: the Namespace-Specific String, whose structure the namespace specification defines.
//!
//! The implementation covers the NID and the NSS. The optional r-component,
//! q-component, and f-component of RFC 8141 are out of its scope.
//!
//! # Examples
//!
//! ```rust
//! use tightbeam::urn::{Urn, UrnBuilder, UrnValidationError};
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

/// An RFC 8141 URN.
///
/// The parts are `Cow<'a, str>`, so a URN borrows its input without a copy.
///
/// The DER encoding is a UTF8String that holds the full form,
/// "urn:nid:nss".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urn<'a> {
	/// The Namespace Identifier, 2 to 32 ASCII letters, digits, or hyphens
	/// with a letter first and a letter or digit last.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.1>`
	nid: Cow<'a, str>,

	/// The Namespace-Specific String, whose structure the namespace defines.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.2>`
	nss: Cow<'a, str>,
}

impl<'a> Urn<'a> {
	/// Builds a URN from static parts and skips every check.
	///
	/// It exists for [`urn!`](crate::urn!), which validates both parts in a
	/// `const` block before it calls this function, and it has to be `pub`
	/// because the macro expands in downstream crates. Write `urn!` instead.
	#[doc(hidden)]
	pub const fn new_unchecked(nid: &'static str, nss: &'static str) -> Urn<'static> {
		Urn { nid: Cow::Borrowed(nid), nss: Cow::Borrowed(nss) }
	}

	/// Builds a URN from parts known only at run time.
	///
	/// [`urn!`](crate::urn!) is the compile-time path for literals. This one
	/// applies the same rules to values a caller assembles.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidNidLength`] -- `nid` is shorter than 2 or longer than 32 characters.
	/// - [`UrnValidationError::InvalidNidStart`] -- the first character of `nid` is no letter.
	/// - [`UrnValidationError::InvalidNidCharacters`] -- a character of `nid`
	///   is no letter, digit, or hyphen, or `nid` ends with a hyphen.
	/// - [`UrnValidationError::RequiredFieldMissing`] -- `nss` is empty.
	pub fn from_parts(nid: impl AsRef<str>, nss: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let nid = Cow::Owned(String::from(nid.as_ref()));
		let nss = Cow::Owned(String::from(nss.as_ref()));
		Urn::checked(nid, nss)
	}

	/// The Namespace Identifier.
	pub fn nid(&self) -> &str {
		&self.nid
	}

	/// The Namespace-Specific String.
	pub fn nss(&self) -> &str {
		&self.nss
	}

	/// Verifies this URN against the spec `S`.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::NidMismatch`] -- the NID differs from `S::NID`.
	/// - The errors of [`Urn::validate_nid`] -- the NID has an invalid format.
	/// - The errors of [`UrnSpec::validate`] -- the NSS structure breaks the spec's requirements.
	pub fn verify<S: UrnSpec>(&self) -> Result<(), UrnValidationError> {
		if self.nid.as_ref() != S::NID {
			return Err(UrnValidationError::NidMismatch);
		}

		Self::validate_nid(self.nid.as_ref())?;

		// The spec reads the URN's parts through a builder's `UrnComponents`.
		let builder = UrnBuilder::default().with_nid(self.nid.as_ref()).with_nss(self.nss.as_ref());

		S::validate(&builder as &dyn UrnComponents)
	}

	/// Validates the NID against RFC 8141 § 2.1.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.1>`
	///
	/// The NID production of RFC 8141 § 2 is
	/// `(alphanum) 0*30(ldh) (alphanum)`, so a valid NID meets these rules:
	///
	/// - It holds 2 to 32 ASCII letters, digits, and hyphens.
	/// - Its last character is a letter or a digit.
	/// - Its first character is a letter. The RFC also admits a digit, so this rule is the house's own.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidNidLength`] -- `nid` is shorter than 2 or longer than 32 characters.
	/// - [`UrnValidationError::InvalidNidStart`] -- the first character of `nid` is no letter.
	/// - [`UrnValidationError::InvalidNidCharacters`] -- a character of `nid`
	///   is no letter, digit, or hyphen, or `nid` ends with a hyphen.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// assert_eq!(Urn::validate_nid("my-namespace"), Ok(()));
	/// assert_eq!(Urn::validate_nid("namespace-"), Err(UrnValidationError::InvalidNidCharacters));
	/// ```
	pub const fn validate_nid(nid: &str) -> Result<(), UrnValidationError> {
		// The check walks bytes, because a `const fn` cannot call `str::chars`.
		// The production is ASCII, so bytes and characters agree here.
		let bytes = nid.as_bytes();
		if bytes.len() < 2 || bytes.len() > 32 {
			return Err(UrnValidationError::InvalidNidLength);
		}

		let [first, middle @ .., last] = bytes else {
			return Err(UrnValidationError::InvalidNidLength);
		};
		if !first.is_ascii_alphabetic() {
			return Err(UrnValidationError::InvalidNidStart);
		}
		if !last.is_ascii_alphanumeric() {
			return Err(UrnValidationError::InvalidNidCharacters);
		}

		let mut remaining = middle;
		while let [byte, after @ ..] = remaining {
			if !byte.is_ascii_alphanumeric() && *byte != b'-' {
				return Err(UrnValidationError::InvalidNidCharacters);
			}

			remaining = after;
		}

		Ok(())
	}

	/// Validates a Namespace-Specific String.
	///
	/// RFC 8141 § 2 requires at least one NSS character: `urn:nid:` names
	/// nothing, and an empty NSS would collide with every other empty one.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::RequiredFieldMissing`] -- `nss` is empty.
	pub const fn validate_nss(nss: &str) -> Result<(), UrnValidationError> {
		if nss.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("nss"));
		}

		Ok(())
	}

	/// The one runtime path that assembles a `Urn`.
	///
	/// [`urn!`](crate::urn!) checks literals in const context. Every other
	/// constructor, the parser and the builder included, comes through here,
	/// so every URN built at run time passes the same checks.
	pub(super) fn checked(nid: Cow<'a, str>, nss: Cow<'a, str>) -> Result<Urn<'a>, UrnValidationError> {
		Self::validate_nid(&nid)?;
		Self::validate_nss(&nss)?;

		Ok(Urn { nid, nss })
	}

	/// Converts the URN into an owned version with the `'static` lifetime.
	///
	/// The borrowed strings become owned strings, so the URN can outlive the
	/// data it borrowed, as with `Cow::into_owned()`.
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

// The parser always returns owned data. The URN can outlive the input
// string, so the parser copies both components into `'static` Cows.
impl FromStr for Urn<'static> {
	type Err = UrnValidationError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let rest = s.strip_prefix("urn:").ok_or(UrnValidationError::InvalidUrnSyntax)?;
		let (nid, nss) = rest.split_once(':').ok_or(UrnValidationError::InvalidUrnSyntax)?;
		Urn::checked(Cow::Owned(nid.to_string()), Cow::Owned(nss.to_string()))
	}
}

impl<'a> FixedTag for Urn<'a> {
	const TAG: Tag = Tag::Utf8String;
}

impl<'a> EncodeValue for Urn<'a> {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		// "urn:" (4) + nid + ":" (1) + nss
		let separators = crate::der::Length::new(5);
		(separators + self.nid.len())? + self.nss.len()
	}

	fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		// The writes put out "urn:nid:nss" part by part, without `format!()`,
		// for no_std compatibility.
		encoder.write(b"urn:")?;
		encoder.write(self.nid.as_bytes())?;
		encoder.write(b":")?;
		encoder.write(self.nss.as_bytes())?;
		Ok(())
	}
}

// The decoder always returns owned data, so the decoded URN is `'static`
// for any lifetime of the reader, and a derived `Sequence` type can carry a
// `Urn<'static>` field directly.
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

	/// Each NID beside the outcome of the NID production of RFC 8141 § 2,
	/// `(alphanum) 0*30(ldh) (alphanum)`, and of the house rule of a letter
	/// first.
	const NID_CASES: [(&str, Result<(), UrnValidationError>); 15] = [
		// The two `alphanum` ends alone give the shortest NID.
		("ab", Ok(())),
		("a", Err(UrnValidationError::InvalidNidLength)),
		("", Err(UrnValidationError::InvalidNidLength)),
		// Two ends and 30 `ldh` give the longest NID.
		("a123456789012345678901234567890b", Ok(())),
		("a1234567890123456789012345678901b", Err(UrnValidationError::InvalidNidLength)),
		// An `ldh` is a letter, a digit, or a hyphen, and hyphens may repeat.
		("my-namespace", Ok(())),
		("a--b", Ok(())),
		("a_b", Err(UrnValidationError::InvalidNidCharacters)),
		("a.b", Err(UrnValidationError::InvalidNidCharacters)),
		("a\u{e9}b", Err(UrnValidationError::InvalidNidCharacters)),
		// The last character is an `alphanum`.
		("a9", Ok(())),
		("ab-", Err(UrnValidationError::InvalidNidCharacters)),
		// The first character is an `alphanum`, of either case.
		("Ab", Ok(())),
		("-ab", Err(UrnValidationError::InvalidNidStart)),
		// The house rule refuses the digit first that the RFC admits.
		("1ab", Err(UrnValidationError::InvalidNidStart)),
	];

	#[test]
	fn validate_nid_follows_the_rfc_8141_production() {
		let outcomes = NID_CASES.map(|(nid, _)| (nid, Urn::validate_nid(nid)));

		assert_eq!(outcomes, NID_CASES);
	}

	// Each case is (input, nid, nss).
	crate::tb_cases! {
		fn test_urn_from_str_round_trips_display((input, nid, nss): (&str, &str, &str))
			-> Result<(), UrnValidationError>
		{
			let urn: Urn<'static> = input.parse()?;
			assert_eq!(urn.nid, nid);
			assert_eq!(urn.nss, nss);
			assert_eq!(urn.to_string(), input);
			Ok(())
		}
		cases {
			servlet => ("urn:tightbeam:servlet:prod:ping", "tightbeam", "servlet:prod:ping"),
			event => ("urn:test:event:cluster/peer-advertised", "test", "event:cluster/peer-advertised"),
			hyphenated_nid => ("urn:my-ns:a", "my-ns", "a"),
		}
	}

	crate::tb_cases! {
		fn test_urn_from_str_rejects_malformed(input: &str) {
			assert!(input.parse::<Urn<'static>>().is_err());
		}
		cases {
			empty => "",
			scheme_alone => "urn:",
			nid_alone => "urn:onlynid",
			empty_nss => "urn:nid:",
			no_scheme => "no-prefix:nid:nss",
			digit_first_nid => "urn:1bad:nss",
		}
	}

	// Each case is (nid, nss).
	crate::tb_cases! {
		fn test_urn_to_owned((nid, nss): (&str, &str)) {
			let urn = Urn { nid: Cow::Borrowed(nid), nss: Cow::Borrowed(nss) };
			let owned_urn = urn.into_owned();
			assert!(matches!(owned_urn.nid, Cow::Owned(_)));
			assert!(matches!(owned_urn.nss, Cow::Owned(_)));
			assert_eq!(owned_urn.nid, nid);
			assert_eq!(owned_urn.nss, nss);
		}
		cases {
			tightbeam => ("tightbeam", "test:resource"),
			path => ("example", "path/to/resource"),
			simple => ("test", "simple"),
		}
	}
}
