//! URN specification trait

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;

#[cfg(feature = "std")]
use std::borrow::Cow;

use super::error::ValidationError;
use super::UrnBuilder;

/// Trait defining a URN namespace specification
///
/// Implementors define validation rules, transformations, and NSS structure
/// for a specific URN namespace according to RFC 8141.
pub trait UrnSpec {
	/// Namespace Identifier (NID)
	///
	/// Must be 2-32 characters, alphanumeric plus hyphens, starting with a letter.
	/// Examples: "tightbeam", "isbn", "uuid"
	const NID: &'static str;

	/// Validate a partially constructed URN builder
	///
	/// Checks that all required fields are present and satisfy constraints.
	fn validate(builder: &UrnBuilder) -> Result<(), ValidationError>;

	/// Transform builder (apply defaults, normalizations)
	///
	/// Called before validation to allow specs to apply transformations like
	/// upper-casing, default values, etc.
	fn transform(builder: UrnBuilder) -> UrnBuilder {
		builder
	}

	/// Build NSS string from structured components
	///
	/// Constructs the Namespace-Specific String from the builder's components
	/// according to the spec's defined structure.
	fn build_nss(builder: &UrnBuilder) -> Result<Cow<'static, str>, ValidationError>;
}
