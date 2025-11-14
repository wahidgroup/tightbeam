//! URN validation error types

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::String;

use core::fmt;

/// Errors that can occur during URN validation and construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
	/// A required field is missing
	RequiredFieldMissing(&'static str),

	/// A field has an invalid format
	InvalidFormat {
		field: &'static str,
		pattern: &'static str,
	},

	/// Cross-field validation rule violated
	CrossFieldViolation(&'static str),

	/// A forbidden field is present
	ForbiddenFieldPresent(&'static str),

	/// Invalid Namespace Identifier (NID)
	InvalidNid(&'static str),
}

impl fmt::Display for ValidationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::RequiredFieldMissing(field) => write!(f, "Required field missing: {}", field),
			Self::InvalidFormat { field, pattern } => {
				write!(f, "Invalid format for field '{}': expected pattern {}", field, pattern)
			}
			Self::CrossFieldViolation(msg) => write!(f, "Cross-field validation failed: {}", msg),
			Self::ForbiddenFieldPresent(field) => write!(f, "Forbidden field present: {}", field),
			Self::InvalidNid(msg) => write!(f, "Invalid NID: {}", msg),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}

