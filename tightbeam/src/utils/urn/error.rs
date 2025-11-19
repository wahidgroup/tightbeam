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
		error("Invalid format for field '{field}': expected pattern {pattern}")
	)]
	InvalidFormat { field: &'static str, pattern: &'static str },

	/// Cross-field validation rule violated
	#[cfg_attr(feature = "derive", error("Cross-field validation failed: {0}"))]
	CrossFieldViolation(&'static str),

	/// A forbidden field is present
	#[cfg_attr(feature = "derive", error("Forbidden field present: {0}"))]
	ForbiddenFieldPresent(&'static str),

	/// Invalid Namespace Identifier (NID)
	#[cfg_attr(feature = "derive", error("Invalid NID: {0}"))]
	InvalidNid(&'static str),
}

#[cfg(not(feature = "derive"))]
impl fmt::Display for UrnValidationError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::RequiredFieldMissing(field) => write!(f, "Required field missing: {field}"),
			Self::InvalidFormat { field, pattern } => {
				write!(f, "Invalid format for field '{field}': expected pattern {pattern}")
			}
			Self::CrossFieldViolation(msg) => write!(f, "Cross-field validation failed: {msg}"),
			Self::ForbiddenFieldPresent(field) => write!(f, "Forbidden field present: {field}"),
			Self::InvalidNid(msg) => write!(f, "Invalid NID: {msg}"),
		}
	}
}

#[cfg(all(feature = "std", not(feature = "derive")))]
impl std::error::Error for UrnValidationError {}
