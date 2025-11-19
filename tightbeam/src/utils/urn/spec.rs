//! URN specification trait

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;

#[cfg(feature = "std")]
use std::borrow::Cow;

use super::error::UrnValidationError;

/// Trait for providing access to URN components
///
/// This abstraction allows `UrnSpec` to work with any type that provides
/// component access, not just `UrnBuilder`. Provides both read and write
/// capabilities for validation and transformation.
pub trait UrnComponents<'a> {
	/// Get a component value by key
	fn get_component(&self, key: &'static str) -> Option<&Cow<'a, str>>;

	/// Set a component value by key (for transformation)
	fn set_component(&mut self, key: &'static str, value: Cow<'a, str>);

	/// Remove a component by key (for transformation)
	fn remove_component(&mut self, key: &'static str) -> Option<Cow<'a, str>>;

	/// Iterate over all components (immutable)
	///
	/// Returns a boxed iterator for dyn-compatibility. Implementations should
	/// minimize allocation overhead where possible.
	#[cfg(feature = "std")]
	fn iter(&self) -> Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_>;

	/// Iterate over all components (immutable) - alloc version
	#[cfg(not(feature = "std"))]
	fn iter(&self) -> alloc::boxed::Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_>;

	/// Iterate over all components (mutable)
	///
	/// Returns a boxed iterator for dyn-compatibility. Implementations should
	/// minimize allocation overhead where possible.
	#[cfg(feature = "std")]
	fn iter_mut(&mut self) -> Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_>;

	/// Iterate over all components (mutable) - alloc version
	#[cfg(not(feature = "std"))]
	fn iter_mut(&mut self) -> alloc::boxed::Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_>;
}

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

	/// Transform components (apply defaults, normalizations)
	///
	/// Called before validation to allow specs to apply transformations like
	/// upper-casing, default values, etc. via the UrnComponents trait interface.
	fn transform<'a>(components: &mut dyn UrnComponents<'a>) {
		// Default no-op - specs can override to mutate components
		let _ = components;
	}

	/// Validate components
	///
	/// Checks that all required fields are present and satisfy constraints.
	fn validate<'a>(components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError>;

	/// Build NSS string from structured components
	///
	/// Constructs the Namespace-Specific String from the components
	/// according to the spec's defined structure.
	fn build_nss<'a>(components: &dyn UrnComponents<'a>) -> Result<Cow<'static, str>, UrnValidationError>;
}
