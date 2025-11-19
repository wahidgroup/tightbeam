//! URN validation error types

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "derive")]
use crate::Errorizable;

#[cfg(not(feature = "derive"))]
use core::fmt;

use crate::utils::urn::builders::spec::Pattern;

/// Errors that can occur during URN validation and construction
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrnValidationError {
	/// A required field is missing
	#[cfg_attr(feature = "derive", error("Required field missing: {0}"))]
	RequiredFieldMissing(&'static str),

	/// A field has an invalid format
	#[cfg_attr(
		feature = "derive",
		error("Invalid format for field '{field}': expected pattern {pattern:?}")
	)]
	InvalidFormat { field: &'static str, pattern: Option<Pattern> },

	/// A forbidden field is present
	#[cfg_attr(feature = "derive", error("Forbidden field present: {0}"))]
	ForbiddenFieldPresent(&'static str),

	/// NID does not match the spec's expected NID
	#[cfg_attr(feature = "derive", error("NID does not match spec"))]
	NidMismatch,

	/// NID length is invalid (must be 2-32 characters)
	#[cfg_attr(feature = "derive", error("Invalid NID length: must be 2-32 characters"))]
	InvalidNidLength,

	/// NID must start with a letter
	#[cfg_attr(feature = "derive", error("Invalid NID: must start with a letter"))]
	InvalidNidStart,

	/// NID contains invalid characters (must be alphanumeric and hyphens only)
	#[cfg_attr(
		feature = "derive",
		error("Invalid NID characters: must be alphanumeric and hyphens only")
	)]
	InvalidNidCharacters,
}

#[cfg(not(feature = "derive"))]
impl fmt::Display for UrnValidationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::RequiredFieldMissing(field) => write!(f, "Required field missing: {field}"),
			Self::InvalidFormat { field, pattern } => {
				if let Some(p) = pattern {
					write!(f, "Invalid format for field '{field}': expected pattern {}", p.pattern_str())
				} else {
					write!(f, "Invalid format for field '{field}'")
				}
			}
			Self::ForbiddenFieldPresent(field) => write!(f, "Forbidden field present: {field}"),
			Self::NidMismatch => write!(f, "NID does not match spec"),
			Self::InvalidNidLength => write!(f, "Invalid NID length: must be 2-32 characters"),
			Self::InvalidNidStart => write!(f, "Invalid NID: must start with a letter"),
			Self::InvalidNidCharacters => {
				write!(f, "Invalid NID characters: must be alphanumeric and hyphens only")
			}
		}
	}
}

#[cfg(all(feature = "std", not(feature = "derive")))]
impl std::error::Error for UrnValidationError {}
