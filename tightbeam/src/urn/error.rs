//! The error type of URN validation and construction.

use crate::urn::builders::spec::Pattern;

use crate::Errorizable;

/// An error that URN validation or construction reports.
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum UrnValidationError {
	/// A required field is missing.
	#[error("Required field missing: {0}")]
	RequiredFieldMissing(&'static str),

	/// A field has an invalid format.
	#[error("Invalid format for field '{field}': expected pattern {pattern:?}")]
	InvalidFormat { field: &'static str, pattern: Option<Pattern> },

	/// A forbidden field is present.
	#[error("Forbidden field present: {0}")]
	ForbiddenFieldPresent(&'static str),

	/// The NID does not match the NID of the spec.
	#[error("NID does not match spec")]
	NidMismatch,

	/// The realm segment does not match the realm of the namespace.
	#[error("Realm does not match namespace")]
	RealmMismatch,

	/// The NID is not 2-32 characters long.
	#[error("Invalid NID length: must be 2-32 characters")]
	InvalidNidLength,

	/// The NID starts with a character other than a letter.
	#[error("Invalid NID: must start with a letter")]
	InvalidNidStart,

	/// The NID holds a character other than a letter, a digit, or a hyphen,
	/// or it ends with a hyphen.
	#[error("Invalid NID characters: must be alphanumeric or hyphens, and end with an alphanumeric")]
	InvalidNidCharacters,

	/// The string is not of the form `urn:<nid>:<nss>`.
	#[error("Invalid URN syntax: expected urn:<nid>:<nss>")]
	InvalidUrnSyntax,

	/// A [`UrnBuilder`] holds both a direct NSS and a spec, so no one mode
	/// builds its NSS.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{UrnBuilder, UrnValidationError};
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
	/// let built = UrnBuilder::from(ExampleSpec).set("id", "one").with_nss("one").build();
	///
	/// assert_eq!(built, Err(UrnValidationError::ConflictingNssModes));
	/// ```
	///
	/// [`UrnBuilder`]: crate::urn::UrnBuilder
	#[error("The builder holds both a direct NSS and a spec")]
	ConflictingNssModes,
}
