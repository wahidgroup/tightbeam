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
//! urn:<NID>:<NSS>[?+<r-component>][?=<q-component>][#<f-component>]
//! ```
//!
//! The parts are:
//! - **NID**: the Namespace Identifier, 2 to 32 ASCII letters, digits, or
//!   hyphens, with a letter or a digit at each end.
//! - **NSS**: the Namespace-Specific String, a run of the `pchar` of RFC 3986 § 3.3 and `/`.
//!   The namespace specification defines its structure.
//! - **The optional components**: the r-component, the q-component, and the f-component of RFC 8141 § 2.3.
//!
//! The scheme `urn` and the NID compare in any case. Two URNs are equal when
//! RFC 8141 § 3.1 makes them URN-equivalent.
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
use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::borrow::Cow;

use core::fmt;
use core::hash::{Hash, Hasher};
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
/// - Equality and the hash follow URN-equivalence (RFC 8141 § 3.1). Both
///   read one normalized form: `urn:`, the NID in lower case, `:`, and the NSS
///   with the hex digits of each percent-encoded triplet in upper case. The
///   optional components take no part.
/// - The display form and the DER encoding are the parsed text, "urn:nid:nss" with its optional components.
///
/// # Examples
///
/// ```
/// use tightbeam::urn::{Urn, UrnValidationError};
///
/// let lower: Urn<'static> = "urn:example:a123,z456".parse()?;
/// let upper: Urn<'static> = "URN:EXAMPLE:a123,z456#789".parse()?;
///
/// assert_eq!(lower, upper);
/// assert_eq!(upper.to_string(), "urn:EXAMPLE:a123,z456#789");
/// # Ok::<(), UrnValidationError>(())
/// ```
#[derive(Debug, Clone)]
pub struct Urn<'a> {
	/// The Namespace Identifier.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.1>`
	nid: Cow<'a, str>,

	/// The Namespace-Specific String.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.2>`
	nss: Cow<'a, str>,

	/// The optional components, when the URN carries one. The box keeps a URN
	/// without them at the size of its two parts and one pointer.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.3>`
	optional: Option<Box<OptionalComponents<'a>>>,
}

impl<'a> Urn<'a> {
	/// Builds a URN from static parts and skips every check.
	///
	/// It serves [`urn!`](crate::urn!), which validates both parts in a `const`
	/// block first, and it is `pub` because the macro expands in downstream
	/// crates. Write `urn!` instead.
	#[doc(hidden)]
	pub const fn new_unchecked(nid: &'static str, nss: &'static str) -> Urn<'static> {
		Urn { nid: Cow::Borrowed(nid), nss: Cow::Borrowed(nss), optional: None }
	}

	/// Builds a URN from parts known only at run time.
	///
	/// [`urn!`](crate::urn!) is the compile-time path for literals. This one
	/// applies the same rules to values a caller assembles.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidNidLength`] -- `nid` is shorter than 2 or longer than 32 characters.
	/// - [`UrnValidationError::InvalidNidStart`] -- the first character of `nid` is no letter or digit.
	/// - [`UrnValidationError::InvalidNidCharacters`] -- a character of `nid`
	///   is no letter, digit, or hyphen, or `nid` ends with a hyphen.
	/// - [`UrnValidationError::RequiredFieldMissing`] -- `nss` is empty.
	/// - [`UrnValidationError::InvalidNssCharacters`] -- `nss` breaks the NSS production of RFC 8141 § 2.
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

	/// The r-component, the text after `?+`, when the URN carries one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// let urn: Urn<'static> = "urn:example:a123,z456?+abc".parse()?;
	///
	/// assert_eq!(urn.r_component(), Some("abc"));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn r_component(&self) -> Option<&str> {
		self.optional.as_ref()?.r_component.as_deref()
	}

	/// The q-component, the text after `?=`, when the URN carries one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// let urn: Urn<'static> = "urn:example:a123,z456?=xyz".parse()?;
	///
	/// assert_eq!(urn.q_component(), Some("xyz"));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn q_component(&self) -> Option<&str> {
		self.optional.as_ref()?.q_component.as_deref()
	}

	/// The f-component, the text after `#`, when the URN carries one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// let urn: Urn<'static> = "urn:example:a123,z456#789".parse()?;
	///
	/// assert_eq!(urn.f_component(), Some("789"));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn f_component(&self) -> Option<&str> {
		self.optional.as_ref()?.f_component.as_deref()
	}

	/// Verifies this URN against the spec `S`.
	///
	/// The spec reads the NSS into its components, transforms them, validates
	/// them, and builds the NSS from them again, as [`UrnBuilder::build`] does
	/// under `S`. A URN passes when that NSS is its own, so `verify` admits
	/// each URN that `S` builds, and refuses a form of it that `S` writes
	/// another way. The NID compares with `S::NID` in any case.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::NidMismatch`] -- the NID differs from `S::NID`.
	/// - The errors of [`Urn::validate_nid`] -- the NID has an invalid format.
	/// - The errors of [`UrnSpec::components`] -- the NSS does not follow the grammar of `S`.
	/// - The errors of [`UrnSpec::validate`] -- the NSS structure breaks the spec's requirements.
	/// - The errors of [`UrnSpec::build_nss`] -- the components build no NSS.
	/// - [`UrnValidationError::NssMismatch`] -- `S` builds another NSS from the components.
	pub fn verify<S: UrnSpec>(&self) -> Result<(), UrnValidationError> {
		if !self.nid.eq_ignore_ascii_case(S::NID) {
			return Err(UrnValidationError::NidMismatch);
		}

		Self::validate_nid(self.nid.as_ref())?;

		// 1. Read the NSS with the grammar of the spec, then run the steps that
		//    the builder runs under it.
		let mut components = S::components(self.nss.as_ref())?;
		S::transform(&mut components);
		S::validate(&components)?;

		// 2. Refuse a parse, or a form of the NSS, that the spec builds
		//    otherwise.
		let rebuilt = S::build_nss(&components)?;
		if rebuilt.as_ref() != self.nss.as_ref() {
			return Err(UrnValidationError::NssMismatch);
		}

		Ok(())
	}

	/// Validates the NID against RFC 8141 § 2.1.
	/// See: `<https://datatracker.ietf.org/doc/html/rfc8141#section-2.1>`
	///
	/// The NID production of RFC 8141 § 2 is
	/// `(alphanum) 0*30(ldh) (alphanum)`, so a valid NID meets these rules:
	///
	/// - It holds 2 to 32 ASCII letters, digits, and hyphens.
	/// - Its first character and its last character are each a letter or a digit.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidNidLength`] -- `nid` is shorter than 2 or longer than 32 characters.
	/// - [`UrnValidationError::InvalidNidStart`] -- the first character of `nid` is no letter or digit.
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
		if !first.is_ascii_alphanumeric() {
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

	/// Validates a Namespace-Specific String against the NSS production of
	/// RFC 8141 § 2, `pchar *(pchar / "/")`, over the `pchar` of RFC 3986
	/// § 3.3.
	///
	/// An NSS holds at least one character: `urn:nid:` names nothing, and an
	/// empty NSS would collide with every other empty one. Each `%` starts a
	/// percent-encoded triplet of two hex digits.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::RequiredFieldMissing`] -- `nss` is empty.
	/// - [`UrnValidationError::InvalidNssCharacters`] -- `nss` starts with a
	///   `/`, holds a character outside `pchar` and `/`, or holds a `%` that
	///   two hex digits do not follow.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// assert_eq!(Urn::validate_nss("a123%2Cz456/foo"), Ok(()));
	/// assert_eq!(Urn::validate_nss("a?b"), Err(UrnValidationError::InvalidNssCharacters));
	/// ```
	pub const fn validate_nss(nss: &str) -> Result<(), UrnValidationError> {
		if nss.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("nss"));
		}
		if !Production::Nss.admits(nss) {
			return Err(UrnValidationError::InvalidNssCharacters);
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

		Ok(Urn { nid, nss, optional: None })
	}

	/// The URN that `text` writes in the grammar of RFC 8141 § 2, borrowed
	/// from `text`.
	///
	/// The scheme `urn` reads in any case. The NSS runs to the first `?` or
	/// `#`, and the optional components follow it.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidUrnSyntax`] -- `text` has no `urn:`
	///   scheme or no `:` after the NID, or an optional component breaks its
	///   production.
	/// - The errors of [`Self::checked`] -- the NID or the NSS breaks its production.
	fn parse(text: &'a str) -> Result<Urn<'a>, UrnValidationError> {
		let (scheme, name) = text.split_at_checked(4).ok_or(UrnValidationError::InvalidUrnSyntax)?;
		if !scheme.eq_ignore_ascii_case("urn:") {
			return Err(UrnValidationError::InvalidUrnSyntax);
		}

		let (nid, rest) = name.split_once(':').ok_or(UrnValidationError::InvalidUrnSyntax)?;
		let nss_end = rest.find(['?', '#']).unwrap_or(rest.len());
		let (nss, tail) = rest.split_at_checked(nss_end).ok_or(UrnValidationError::InvalidUrnSyntax)?;

		let urn = Urn::checked(Cow::Borrowed(nid), Cow::Borrowed(nss))?;
		let optional = OptionalComponents::parse(tail)?;
		Ok(Urn { optional, ..urn })
	}

	/// The octets of the normalized form of this URN under RFC 8141 § 3.1:
	/// `urn:`, the NID in lower case, `:`, and the NSS with the hex digits of
	/// each percent-encoded triplet in upper case.
	///
	/// The optional components take no part, as URN-equivalence reads none.
	/// Equality, the hash, and the colony route keys all read this form, so
	/// two URN-equivalent URNs give one key.
	pub(crate) fn normalized(&self) -> impl Iterator<Item = u8> + '_ {
		let scheme = b"urn:".iter().copied();
		let nid = self.nid.bytes().map(|byte| byte.to_ascii_lowercase());
		let nss = NssText::segment(&self.nss).normalized();

		scheme.chain(nid).chain([b':']).chain(nss)
	}

	/// Converts the URN into an owned `'static` one that can outlive the data
	/// it borrowed, as `Cow::into_owned()` does.
	#[inline]
	pub fn into_owned(self) -> Urn<'static> {
		let nid = Cow::Owned(self.nid.into_owned());
		let nss = Cow::Owned(self.nss.into_owned());
		let optional = self.optional.map(|optional| Box::new(optional.into_owned()));
		Urn { nid, nss, optional }
	}

	/// Each optional component beside the delimiter that introduces it, in
	/// the order of RFC 8141 § 2.
	fn delimited_components(&self) -> impl Iterator<Item = (&'static str, &str)> {
		self.optional.iter().flat_map(|optional| optional.delimited())
	}
}

/// The upper-case hex digits of a percent-encoded triplet, by value.
#[cfg(feature = "colony")]
const HEX_DIGITS: [u8; 16] = *b"0123456789ABCDEF";

/// The text of a Namespace-Specific String, or of one segment of it, in
/// which each `%` starts a percent-encoded triplet (RFC 3986 § 2.1).
///
/// - Two texts are equal under the case normalization of RFC 8141 § 3.1: the
///   hex digits of each triplet compare in any case, and each other character
///   compares by octet.
/// - [`NssText::decoded`] gives the octets that the text writes.
///
/// # Examples
///
/// ```
/// use tightbeam::urn::{NssText, UrnValidationError};
///
/// let locator = NssText::new("%5b::1%5D:9000")?;
///
/// assert_eq!(locator, NssText::new("%5B::1%5d:9000")?);
/// assert_eq!(locator.decoded().as_ref(), b"[::1]:9000");
/// # Ok::<(), UrnValidationError>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct NssText<'a>(&'a str);

impl<'a> NssText<'a> {
	/// The NSS text `text`, checked against the NSS production of RFC 8141
	/// § 2, as [`Urn::validate_nss`] checks it.
	///
	/// # Errors
	///
	/// - The errors of [`Urn::validate_nss`] -- `text` breaks the NSS production.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{NssText, UrnValidationError};
	///
	/// assert_eq!(NssText::new("a%2Cb")?.as_str(), "a%2Cb");
	/// assert_eq!(NssText::new("a%2").err(), Some(UrnValidationError::InvalidNssCharacters));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn new(text: &'a str) -> Result<Self, UrnValidationError> {
		Urn::validate_nss(text)?;
		Ok(Self(text))
	}

	/// A segment of the NSS of a URN that this crate parsed or built, whose
	/// triplets each hold two hex digits.
	pub(crate) const fn segment(text: &'a str) -> Self {
		Self(text)
	}

	/// The text as the URN writes it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{NssText, UrnValidationError};
	///
	/// assert_eq!(NssText::new("%5B::1%5D:9000")?.as_str(), "%5B::1%5D:9000");
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	#[must_use]
	pub const fn as_str(&self) -> &'a str {
		self.0
	}

	/// The octets that the text writes: each percent-encoded triplet becomes
	/// the octet it encodes, and each other character stays as it is.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{NssText, UrnValidationError};
	///
	/// let locator = NssText::new("h%C3%B4te:1")?;
	/// assert_eq!(locator.decoded().as_ref(), "h\u{f4}te:1".as_bytes());
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	#[must_use]
	pub fn decoded(&self) -> Cow<'a, [u8]> {
		let text = self.0;
		if !text.contains('%') {
			return Cow::Borrowed(text.as_bytes());
		}

		let mut decoded = Vec::with_capacity(text.len());
		let mut remaining = text.as_bytes();
		while let [byte, after @ ..] = remaining {
			let triplet = match (*byte, after) {
				(b'%', [high, low, rest @ ..]) => Some((*high, *low, rest)),
				_ => None,
			};
			let value = triplet.and_then(|(high, low, rest)| Some((Production::hex_pair(high, low)?, rest)));

			remaining = match value {
				Some((value, rest)) => {
					decoded.push(value);
					rest
				}
				None => {
					decoded.push(*byte);
					after
				}
			};
		}

		Cow::Owned(decoded)
	}

	/// The NSS text that writes `text`, which [`Self::decoded`] reads back.
	///
	/// - Each `%`, and each byte outside the `pchar` of RFC 3986 § 3.3 and `/`,
	///   becomes its triplet in upper-case hex digits (RFC 3986 § 2.1).
	/// - Each other byte stays as it is.
	/// - The colony writes an address into a URN through it, so an IPv6 literal
	///   such as `[::1]:9000` meets the NSS production.
	#[cfg(feature = "colony")]
	pub(crate) fn encode(text: &str) -> Cow<'_, str> {
		let kept = |byte: &u8| *byte != b'%' && (*byte == b'/' || Production::is_pchar(*byte));
		if text.bytes().all(|byte| kept(&byte)) {
			return Cow::Borrowed(text);
		}

		let encoded = text.bytes().flat_map(|byte| {
			if kept(&byte) {
				return [Some(byte), None, None];
			}

			let high = HEX_DIGITS.get(usize::from(byte.div_euclid(16))).copied();
			let low = HEX_DIGITS.get(usize::from(byte.rem_euclid(16))).copied();
			[Some(b'%'), high, low]
		});

		Cow::Owned(encoded.flatten().map(char::from).collect())
	}

	/// The octets of the text under the case normalization of RFC 8141 § 3.1,
	/// which writes each hex digit of a percent-encoded triplet in upper case.
	fn normalized(self) -> impl Iterator<Item = u8> + 'a {
		self.0.bytes().scan(0u8, |hex_digits_left, byte| {
			let in_triplet = *hex_digits_left > 0;
			*hex_digits_left = match byte {
				b'%' => 2,
				_ => hex_digits_left.saturating_sub(1),
			};

			let normalized = in_triplet.then(|| byte.to_ascii_uppercase());
			Some(normalized.unwrap_or(byte))
		})
	}
}

impl PartialEq for NssText<'_> {
	/// Compares the two texts under the case normalization of RFC 8141 § 3.1.
	fn eq(&self, other: &Self) -> bool {
		self.normalized().eq(other.normalized())
	}
}

impl Eq for NssText<'_> {}

impl Hash for NssText<'_> {
	/// Hashes the octets that [`PartialEq`] compares, and an end marker that
	/// no NSS octet takes.
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.normalized().for_each(|byte| state.write_u8(byte));
		state.write_u8(0xff);
	}
}

/// The optional components of a URN (RFC 8141 § 2.3), which follow its NSS.
#[derive(Debug, Clone, Default)]
struct OptionalComponents<'a> {
	/// The r-component, after `?+`.
	r_component: Option<Cow<'a, str>>,
	/// The q-component, after `?=`.
	q_component: Option<Cow<'a, str>>,
	/// The f-component, after `#`.
	f_component: Option<Cow<'a, str>>,
}

impl<'a> OptionalComponents<'a> {
	/// The optional components that `tail`, the text after the NSS of a URN,
	/// writes, or `None` when `tail` is empty.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidUrnSyntax`] -- `tail` starts with a `?`
	///   that no `+` or `=` follows, or a component breaks its production.
	fn parse(tail: &'a str) -> Result<Option<Box<Self>>, UrnValidationError> {
		if tail.is_empty() {
			return Ok(None);
		}

		// 1. The f-component runs from the first `#` to the end, because no
		//    other component admits a `#`.
		let (rq_components, f_component) = match tail.split_once('#') {
			Some((rq_components, f_component)) => (rq_components, Some(f_component)),
			None => (tail, None),
		};

		// 2. The first `?=` ends the r-component and starts the q-component
		//    (RFC 8141 § 2.3.1).
		let (r_part, q_component) = match rq_components.split_once("?=") {
			Some((r_part, q_component)) => (r_part, Some(q_component)),
			None => (rq_components, None),
		};
		let r_component = match r_part {
			"" => None,
			r_part => Some(r_part.strip_prefix("?+").ok_or(UrnValidationError::InvalidUrnSyntax)?),
		};

		// 3. Each component meets its production.
		let mut rq_texts = [r_component, q_component].into_iter().flatten();
		let rq_admitted = rq_texts.all(|text| Production::Component.admits(text));
		let f_admitted = f_component.is_none_or(|text| Production::Fragment.admits(text));
		let admitted = rq_admitted && f_admitted;
		if !admitted {
			return Err(UrnValidationError::InvalidUrnSyntax);
		}

		let components = Self {
			r_component: r_component.map(Cow::Borrowed),
			q_component: q_component.map(Cow::Borrowed),
			f_component: f_component.map(Cow::Borrowed),
		};
		Ok(Some(Box::new(components)))
	}

	/// These components, owning their text.
	fn into_owned(self) -> OptionalComponents<'static> {
		let owned = |component: Option<Cow<'a, str>>| component.map(|text| Cow::Owned(text.into_owned()));
		OptionalComponents {
			r_component: owned(self.r_component),
			q_component: owned(self.q_component),
			f_component: owned(self.f_component),
		}
	}

	/// Each present component beside the delimiter that introduces it, in
	/// the order of RFC 8141 § 2.
	fn delimited(&self) -> impl Iterator<Item = (&'static str, &str)> {
		let r_component = ("?+", self.r_component.as_deref());
		let q_component = ("?=", self.q_component.as_deref());
		let f_component = ("#", self.f_component.as_deref());

		let delimited = [r_component, q_component, f_component].into_iter();
		delimited.filter_map(|(delimiter, component)| Some((delimiter, component?)))
	}
}

/// A production of RFC 8141 § 2 over the `pchar` of RFC 3986 § 3.3.
#[derive(Clone, Copy)]
enum Production {
	/// `NSS = pchar *(pchar / "/")`
	Nss,
	/// The r-component and the q-component: `pchar *(pchar / "/" / "?")`
	Component,
	/// The f-component of RFC 3986 § 3.5: `*(pchar / "/" / "?")`
	Fragment,
}

impl Production {
	/// Whether `text` meets this production. A `%` starts a percent-encoded
	/// triplet of two hex digits, in either case.
	const fn admits(self, text: &str) -> bool {
		let bytes = text.as_bytes();
		let leads = match (self, bytes) {
			(Self::Fragment, _) => true,
			(_, [first, ..]) => *first != b'/' && *first != b'?',
			(_, []) => false,
		};
		if !leads {
			return false;
		}

		let question_mark = !matches!(self, Self::Nss);
		let mut remaining = bytes;
		while let [byte, after @ ..] = remaining {
			remaining = match (*byte, after) {
				(b'%', [high, low, rest @ ..]) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => rest,
				(b'/', _) => after,
				(b'?', _) if question_mark => after,
				(byte, _) if Self::is_pchar(byte) => after,
				_ => return false,
			};
		}

		true
	}

	/// Whether `byte` is a `pchar` of RFC 3986 § 3.3 by itself: an
	/// `unreserved` or a `sub-delims` character, `:`, or `@`.
	const fn is_pchar(byte: u8) -> bool {
		let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
		let sub_delims = matches!(byte, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';');
		let sub_delims = sub_delims || byte == b'=';
		unreserved || sub_delims || byte == b':' || byte == b'@'
	}

	/// The byte that the hex digits `high` and `low` write, in either case,
	/// or `None` when either is no hex digit.
	fn hex_pair(high: u8, low: u8) -> Option<u8> {
		let digit = |digit: u8| u8::try_from(char::from(digit).to_digit(16)?).ok();
		digit(high)?.checked_mul(16)?.checked_add(digit(low)?)
	}
}

impl PartialEq for Urn<'_> {
	/// URN-equivalence (RFC 8141 § 3.1): the two normalized forms are equal.
	fn eq(&self, other: &Self) -> bool {
		self.normalized().eq(other.normalized())
	}
}

impl Eq for Urn<'_> {}

impl Hash for Urn<'_> {
	/// Hashes the normalized form that [`PartialEq`] compares, so
	/// URN-equivalent URNs hash alike, and an end marker that no octet of the
	/// form takes.
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.normalized().for_each(|byte| state.write_u8(byte));
		state.write_u8(0xff);
	}
}

impl<'a> fmt::Display for Urn<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "urn:{}:{}", self.nid, self.nss)?;
		for (delimiter, component) in self.delimited_components() {
			write!(f, "{delimiter}{component}")?;
		}

		Ok(())
	}
}

// The parser copies each part into a `'static` Cow, so the URN can outlive
// the input string.
impl FromStr for Urn<'static> {
	type Err = UrnValidationError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Urn::parse(s).map(Urn::into_owned)
	}
}

impl<'a> FixedTag for Urn<'a> {
	const TAG: Tag = Tag::Utf8String;
}

impl<'a> EncodeValue for Urn<'a> {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		// "urn:" (4) + nid + ":" (1) + nss, then each delimited component
		let separators = crate::der::Length::new(5);
		let mut len = ((separators + self.nid.len())? + self.nss.len())?;
		for (delimiter, component) in self.delimited_components() {
			len = ((len + delimiter.len())? + component.len())?;
		}

		Ok(len)
	}

	fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		// The writes put out "urn:nid:nss" part by part, without `format!()`,
		// for no_std compatibility.
		encoder.write(b"urn:")?;
		encoder.write(self.nid.as_bytes())?;
		encoder.write(b":")?;
		encoder.write(self.nss.as_bytes())?;
		for (delimiter, component) in self.delimited_components() {
			encoder.write(delimiter.as_bytes())?;
			encoder.write(component.as_bytes())?;
		}

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
	/// `(alphanum) 0*30(ldh) (alphanum)`.
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
		// The first character is an `alphanum`: a letter of either case, or a
		// digit.
		("Ab", Ok(())),
		("1ab", Ok(())),
		("-ab", Err(UrnValidationError::InvalidNidStart)),
	];

	#[test]
	fn validate_nid_follows_the_rfc_8141_production() {
		let outcomes = NID_CASES.map(|(nid, _)| (nid, Urn::validate_nid(nid)));
		assert_eq!(outcomes, NID_CASES);
	}

	/// The example URNs of RFC 8141 § 3.2, by group. Each URN of a group is
	/// URN-equivalent to each other URN of its group, and to no URN of another
	/// group.
	const RFC_8141_EXAMPLES: [&[&str]; 8] = [
		// The scheme and the NID compare in any case, and the r-, q-, and
		// f-components take no part.
		&[
			"urn:example:a123,z456",
			"URN:example:a123,z456",
			"urn:EXAMPLE:a123,z456",
			"urn:example:a123,z456?+abc",
			"urn:example:a123,z456?=xyz",
			"urn:example:a123,z456#789",
		],
		// A `/` and the text after it are part of the NSS.
		&["urn:example:a123,z456/foo"],
		&["urn:example:a123,z456/bar"],
		&["urn:example:a123,z456/baz"],
		// The hex digits of a percent-encoded triplet compare in any case, and
		// the triplet stays encoded.
		&["urn:example:a123%2Cz456", "URN:EXAMPLE:a123%2cz456"],
		// Each other character of the NSS compares by case.
		&["urn:example:A123,z456"],
		&["urn:example:a123,Z456"],
		// A Cyrillic letter differs from the Latin letter it looks like.
		&["urn:example:%D0%B0123,z456"],
	];

	/// Each example URN of RFC 8141 § 3.2 beside the index of its group.
	fn parsed_rfc_8141_examples() -> Result<Vec<(usize, Urn<'static>)>, UrnValidationError> {
		let grouped = RFC_8141_EXAMPLES.iter().enumerate();
		let examples = grouped.flat_map(|(group, urns)| urns.iter().map(move |urn| (group, urn)));
		examples.map(|(group, urn)| Ok((group, urn.parse()?))).collect()
	}

	/// Two example URNs of RFC 8141 § 3.2 are equal when the RFC places them
	/// in one group.
	#[test]
	fn the_rfc_8141_examples_compare_by_urn_equivalence() -> Result<(), UrnValidationError> {
		let examples = parsed_rfc_8141_examples()?;

		let pairs = examples
			.iter()
			.flat_map(|first| examples.iter().map(move |second| (first, second)));
		let wrong = pairs.filter(|((group, urn), (other_group, other))| (urn == other) != (group == other_group));
		let wrong: Vec<_> = wrong
			.map(|((_, urn), (_, other))| (urn.to_string(), other.to_string()))
			.collect();

		assert_eq!(wrong, Vec::<(String, String)>::new());
		Ok(())
	}

	/// Equal example URNs of RFC 8141 § 3.2 hash alike, so a set of them
	/// holds one URN per group.
	#[test]
	fn the_rfc_8141_examples_hash_by_urn_equivalence() -> Result<(), UrnValidationError> {
		let examples = parsed_rfc_8141_examples()?;

		let distinct: std::collections::HashSet<Urn<'static>> = examples.into_iter().map(|(_, urn)| urn).collect();

		assert_eq!(distinct.len(), RFC_8141_EXAMPLES.len());
		Ok(())
	}

	// Each case is (a text, another text, whether RFC 8141 § 3.1 makes the two
	// equal).
	crate::tb_cases! {
		fn nss_text_compares_under_the_case_normalization_of_rfc_8141((first, second, equal): (&str, &str, bool))
			-> Result<(), UrnValidationError>
		{
			assert_eq!(NssText::new(first)? == NssText::new(second)?, equal);
			Ok(())
		}
		cases {
			hex_digits_in_either_case => ("a%2cb", "a%2Cb", true),
			a_letter_by_case => ("a%2Cb", "A%2Cb", false),
			a_letter_after_a_triplet_by_case => ("%2Cb", "%2CB", false),
			a_triplet_and_the_letter_it_encodes => ("%41", "A", false),
		}
	}

	/// Each example URN of RFC 8141 § 3.2 writes its own text, with the scheme
	/// in lower case.
	#[test]
	fn the_rfc_8141_examples_display_with_a_lower_case_scheme() -> Result<(), UrnValidationError> {
		let examples = parsed_rfc_8141_examples()?;

		let written: Vec<String> = examples.iter().map(|(_, urn)| urn.to_string()).collect();

		let texts = RFC_8141_EXAMPLES.iter().flat_map(|urns| urns.iter());
		let expected: Vec<String> = texts.map(|text| format!("urn:{}", text.get(4..).unwrap_or_default())).collect();
		assert_eq!(written, expected);
		Ok(())
	}

	// Each case is (input, the refusal of RFC 8141 § 2).
	crate::tb_cases! {
		fn a_urn_outside_the_rfc_8141_grammar_is_refused((input, refusal): (&str, UrnValidationError)) {
			assert_eq!(input.parse::<Urn<'static>>(), Err(refusal));
		}
		cases {
			space_in_the_nss => ("urn:example:a b", UrnValidationError::InvalidNssCharacters),
			bracket_in_the_nss => ("urn:example:a[1]", UrnValidationError::InvalidNssCharacters),
			non_ascii_in_the_nss => ("urn:example:a\u{e9}b", UrnValidationError::InvalidNssCharacters),
			short_triplet => ("urn:example:a%2", UrnValidationError::InvalidNssCharacters),
			triplet_of_no_hex_digits => ("urn:example:a%zz", UrnValidationError::InvalidNssCharacters),
			nss_that_starts_with_a_slash => ("urn:example:/a", UrnValidationError::InvalidNssCharacters),
			question_mark_alone => ("urn:example:a?b", UrnValidationError::InvalidUrnSyntax),
			empty_r_component => ("urn:example:a?+", UrnValidationError::InvalidUrnSyntax),
			empty_q_component => ("urn:example:a?=", UrnValidationError::InvalidUrnSyntax),
			r_component_that_starts_with_a_slash => ("urn:example:a?+/r", UrnValidationError::InvalidUrnSyntax),
			second_hash => ("urn:example:a#b#c", UrnValidationError::InvalidUrnSyntax),
			space_in_a_component => ("urn:example:a?=b c", UrnValidationError::InvalidUrnSyntax),
		}
	}

	crate::urn_spec! {
		/// A spec of one required field, `urn:probe:<kind>`.
		ProbeSpec,
		nid: "probe",
		nss_structure {
			kind: { values: ["a", "b"] }
		}
	}

	/// A spec verifies the URN it built itself, so `verify` reads the
	/// components the NSS carries.
	#[test]
	fn urn_verify_admits_the_urn_its_own_spec_built() -> Result<(), UrnValidationError> {
		let urn = UrnBuilder::from(ProbeSpec).set("kind", "a").build()?;
		urn.verify::<ProbeSpec>()
	}

	/// A spec of a custom format verifies the URN it built, through the
	/// literals of its format.
	#[test]
	fn urn_verify_admits_a_urn_of_a_custom_format() -> Result<(), UrnValidationError> {
		let urn: Urn<'static> = "urn:tightbeam:instrumentation:trace/abc-123".parse()?;
		urn.verify::<specs::TightbeamUrnSpec>()
	}

	/// The spec lowercases a resource type, so it builds another NSS from the
	/// components of an uppercase one, and `verify` refuses it.
	#[test]
	fn urn_verify_refuses_a_form_its_spec_writes_another_way() -> Result<(), UrnValidationError> {
		let urn: Urn<'static> = "urn:tightbeam:instrumentation:TRACE/abc-123".parse()?;
		assert_eq!(urn.verify::<specs::TightbeamUrnSpec>(), Err(UrnValidationError::NssMismatch));
		Ok(())
	}

	/// The format of the spec places a `/` before the resource id, so it
	/// refuses an NSS without one.
	#[test]
	fn urn_verify_refuses_an_nss_without_a_literal_of_its_format() -> Result<(), UrnValidationError> {
		let urn: Urn<'static> = "urn:tightbeam:instrumentation:trace".parse()?;
		assert_eq!(urn.verify::<specs::TightbeamUrnSpec>(), Err(UrnValidationError::NssMismatch));
		Ok(())
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
			digit_first_nid => ("urn:1ab:x", "1ab", "x"),
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
			hyphen_first_nid => "urn:-bad:nss",
		}
	}

	// Each case is (nid, nss).
	crate::tb_cases! {
		fn test_urn_to_owned((nid, nss): (&str, &str)) {
			let urn = Urn { nid: Cow::Borrowed(nid), nss: Cow::Borrowed(nss), optional: None };
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

	/// A URN with each optional component writes the same DER text it
	/// parsed, and decodes with each component in its place.
	#[test]
	fn a_urn_with_its_optional_components_survives_a_der_round_trip() -> Result<(), Box<dyn core::error::Error>> {
		use crate::der::{Decode, Encode};

		let urn: Urn<'static> = "urn:example:a123,z456?+r/1?=q?2#f/3?".parse()?;

		let decoded = Urn::from_der(&urn.to_der()?)?;

		let components = (decoded.r_component(), decoded.q_component(), decoded.f_component());
		assert_eq!(components, (Some("r/1"), Some("q?2"), Some("f/3?")));
		assert_eq!(decoded.to_string(), "urn:example:a123,z456?+r/1?=q?2#f/3?");
		Ok(())
	}

	/// A spec verifies a URN whose NID differs from its own in case alone,
	/// because the NID compares in any case.
	#[test]
	fn urn_verify_compares_the_nid_in_any_case() -> Result<(), UrnValidationError> {
		let urn: Urn<'static> = "urn:PROBE:a".parse()?;
		urn.verify::<ProbeSpec>()
	}

	// Each case is (an address, the NSS text that the colony writes of it).
	#[cfg(feature = "colony")]
	crate::tb_cases! {
		fn an_address_percent_encodes_into_the_nss_and_back((address, encoded): (&str, &str))
			-> Result<(), UrnValidationError>
		{
			let written = NssText::encode(address);

			let text = NssText::new(&written)?;
			assert_eq!(written, encoded);
			assert_eq!(text.decoded().as_ref(), address.as_bytes());
			Ok(())
		}
		cases {
			ipv4 => ("10.0.0.5:9100", "10.0.0.5:9100"),
			ipv6 => ("[::1]:9000", "%5B::1%5D:9000"),
			scoped_ipv6 => ("[fe80::1%eth0]:9000", "%5Bfe80::1%25eth0%5D:9000"),
			path => ("unix/tmp/a b", "unix/tmp/a%20b"),
			non_ascii => ("h\u{f4}te:1", "h%C3%B4te:1"),
		}
	}
}
