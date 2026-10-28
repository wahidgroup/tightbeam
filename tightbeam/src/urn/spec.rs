//! URN specification trait

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
#[cfg(feature = "std")]
use std::borrow::Cow;

use super::error::UrnValidationError;

/// Read and write access to URN components.
///
/// `UrnSpec` validates and transforms components through it, so a spec works
/// with any type that holds components, not only `UrnBuilder`.
pub trait UrnComponents<'a> {
	/// Get a component value by key
	fn get_component(&self, key: &'static str) -> Option<&Cow<'a, str>>;

	/// Set a component value by key (for transformation)
	fn set_component(&mut self, key: &'static str, value: Cow<'a, str>);

	/// Remove a component by key (for transformation)
	fn remove_component(&mut self, key: &'static str) -> Option<Cow<'a, str>>;

	/// Iterate over all components (immutable).
	///
	/// The iterator is boxed so the trait stays dyn-compatible. An
	/// implementation should allocate as little as it can.
	#[cfg(feature = "std")]
	fn iter(&self) -> Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_>;

	/// Iterate over all components (immutable), under `alloc` alone.
	#[cfg(not(feature = "std"))]
	fn iter(&self) -> alloc::boxed::Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_>;

	/// Iterate over all components (mutable).
	///
	/// The iterator is boxed so the trait stays dyn-compatible. An
	/// implementation should allocate as little as it can.
	#[cfg(feature = "std")]
	fn iter_mut(&mut self) -> Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_>;

	/// Iterate over all components (mutable), under `alloc` alone.
	#[cfg(not(feature = "std"))]
	fn iter_mut(&mut self) -> alloc::boxed::Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_>;
}

/// The specification of a URN namespace.
///
/// An implementor defines the validation rules, transformations, and NSS
/// structure of one URN namespace, by RFC 8141.
pub trait UrnSpec {
	/// The Namespace Identifier (NID), such as "tightbeam", "isbn", or "uuid".
	///
	/// It holds 2 to 32 ASCII letters, digits, and hyphens. It starts with a
	/// letter and ends with a letter or a digit
	/// ([`Urn::validate_nid`](crate::urn::Urn::validate_nid)).
	const NID: &'static str;

	/// The components this spec reads an NSS into, borrowed from the NSS.
	///
	/// A spec of [`urn_spec!`](crate::urn_spec!) reads its NSS into a
	/// [`UrnBuilder`](crate::urn::UrnBuilder), and a spec written by hand
	/// names a type of its own.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{UrnBuilder, UrnSpec, UrnValidationError};
	///
	/// tightbeam::urn_spec! {
	///     /// The spec of `urn:example:<id>`, for an id of `one` or `two`.
	///     ExampleSpec,
	///     nid: "example",
	///     nss_structure {
	///         id: { values: ["one", "two"] }
	///     }
	/// }
	///
	/// let components: <ExampleSpec as UrnSpec>::Components<'_> = ExampleSpec::components("one")?;
	/// let _: UrnBuilder<'_> = components;
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	type Components<'a>: UrnComponents<'a>;

	/// Read `nss` into the components this spec builds it from, each borrowed
	/// from `nss`.
	///
	/// [`Urn::verify`](crate::urn::Urn::verify) reads a URN through it, then
	/// transforms, validates, and builds the NSS from the components again, so
	/// the grammar of the spec decides each URN it admits.
	///
	/// # Errors
	///
	/// - [`UrnValidationError`] -- `nss` does not follow the grammar of this spec.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{UrnComponents, UrnSpec, UrnValidationError};
	///
	/// tightbeam::urn_spec! {
	///     /// The spec of `urn:example:<id>`, for an id of `one` or `two`.
	///     ExampleSpec,
	///     nid: "example",
	///     nss_structure {
	///         id: { values: ["one", "two"] }
	///     }
	/// }
	///
	/// let components = ExampleSpec::components("one")?;
	/// assert_eq!(components.get_component("id").map(|id| id.as_ref()), Some("one"));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	fn components<'a>(nss: &'a str) -> Result<Self::Components<'a>, UrnValidationError>;

	/// Transform components before validation, such as to upper-case a value
	/// or to set a default.
	fn transform<'a>(components: &mut dyn UrnComponents<'a>) {
		// The default leaves the components as they are.
		let _ = components;
	}

	/// Validate components: every required field is present and meets its
	/// constraints.
	fn validate<'a>(components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError>;

	/// Build the Namespace-Specific String from the components, by the
	/// structure of the spec.
	fn build_nss<'a>(components: &dyn UrnComponents<'a>) -> Result<Cow<'static, str>, UrnValidationError>;
}
