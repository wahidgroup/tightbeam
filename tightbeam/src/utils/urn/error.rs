//! URN validation error types

use crate::utils::urn::builders::spec::Pattern;

use crate::Errorizable;

/// Errors that can occur during URN validation and construction
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum UrnValidationError {
	/// A required field is missing
	#[error("Required field missing: {0}")]
	RequiredFieldMissing(&'static str),

	/// A field has an invalid format
	#[error("Invalid format for field '{field}': expected pattern {pattern:?}")]
	InvalidFormat { field: &'static str, pattern: Option<Pattern> },

	/// A forbidden field is present
	#[error("Forbidden field present: {0}")]
	ForbiddenFieldPresent(&'static str),

	/// NID does not match the spec's expected NID
	#[error("NID does not match spec")]
	NidMismatch,

	/// Realm segment does not match the namespace's realm
	#[error("Realm does not match namespace")]
	RealmMismatch,

	/// NID length is invalid (must be 2-32 characters)
	#[error("Invalid NID length: must be 2-32 characters")]
	InvalidNidLength,

	/// NID must start with a letter
	#[error("Invalid NID: must start with a letter")]
	InvalidNidStart,

	/// NID contains invalid characters (must be alphanumeric and hyphens only)
	#[error("Invalid NID characters: must be alphanumeric and hyphens only")]
	InvalidNidCharacters,

	/// String is not of the form `urn:<nid>:<nss>`
	#[error("Invalid URN syntax: expected urn:<nid>:<nss>")]
	InvalidUrnSyntax,
}
