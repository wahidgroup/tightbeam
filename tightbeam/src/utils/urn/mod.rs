//! RFC 8141 compliant URN (Uniform Resource Name) implementation
//!
//! Provides zero-copy URN construction with declarative specification support
//! for validation and hierarchical NSS (Namespace-Specific String) structure.
//!
//! # RFC 8141 Format
//!
//! ```text
//! urn:<NID>:<NSS>
//! ```
//!
//! Where:
//! - **NID**: Namespace Identifier (2-32 chars, alphanumeric+hyphen, starts with letter)
//! - **NSS**: Namespace-Specific String (structure defined by namespace spec)
//!
//! # Examples
//!
//! ```rust
//! use tightbeam::utils::urn::{Urn, UrnBuilder, ValidationError};
//!
//! fn main() -> Result<(), ValidationError> {
//!     // Build a URN manually
//!     let urn = UrnBuilder::new()
//!         .nid("tightbeam")
//!         .set("category", "instrumentation")
//!         .set("resource.type", "trace")
//!         .set("resource.id", "123")
//!         .build_with(|builder| {
//!             let category = builder
//!                 .get("category")
//!                 .ok_or(ValidationError::RequiredFieldMissing("category"))?;
//!             let res_type = builder
//!                 .get("resource.type")
//!                 .ok_or(ValidationError::RequiredFieldMissing("resource.type"))?;
//!             let res_id = builder
//!                 .get("resource.id")
//!                 .ok_or(ValidationError::RequiredFieldMissing("resource.id"))?;
//!             Ok(format!("{}:{}:{}", category, res_type, res_id).into())
//!         })?;
//!
//!     assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:trace:123");
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as Map;
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "std")]
use std::borrow::Cow;
#[cfg(feature = "std")]
use std::collections::HashMap as Map;

use core::fmt;

pub mod error;
pub mod spec;

pub use error::ValidationError;
pub use spec::UrnSpec;

/// RFC 8141 compliant URN structure
///
/// Uses `Cow<'a, str>` for zero-copy string handling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Urn<'a> {
	/// Namespace Identifier (2-32 chars, alphanumeric+hyphen, starts with letter)
	pub nid: Cow<'a, str>,

	/// Namespace-Specific String (structure defined by namespace)
	pub nss: Cow<'a, str>,
}

impl<'a> Urn<'a> {
	/// Create a new URN builder
	#[inline]
	pub fn builder() -> UrnBuilder<'a> {
		UrnBuilder::new()
	}

	/// Create a URN from a spec type
	///
	/// Returns a pre-configured builder for the given spec.
	#[inline]
	pub fn from<S: UrnSpec>(_spec: S) -> UrnBuilder<'a> {
		let mut builder = UrnBuilder::new();
		builder.nid = Some(Cow::Borrowed(S::NID));
		builder
	}

	/// Convert the URN to an owned version with 'static lifetime
	#[inline]
	pub fn into_owned(self) -> Urn<'static> {
		Urn {
			nid: Cow::Owned(self.nid.into_owned()),
			nss: Cow::Owned(self.nss.into_owned()),
		}
	}

	/// Validate that the NID conforms to RFC 8141
	///
	/// NID must be 2-32 characters, alphanumeric plus hyphens, starting with a letter.
	pub fn validate_nid(nid: &str) -> Result<(), ValidationError> {
		let len = nid.len();
		if len < 2 || len > 32 {
			return Err(ValidationError::InvalidNid("NID must be 2-32 characters"));
		}

		let mut chars = nid.chars();
		if let Some(first) = chars.next() {
			if !first.is_ascii_alphabetic() {
				return Err(ValidationError::InvalidNid("NID must start with a letter"));
			}
		}

		for ch in chars {
			if !ch.is_ascii_alphanumeric() && ch != '-' {
				return Err(ValidationError::InvalidNid(
					"NID must contain only alphanumeric characters and hyphens",
				));
			}
		}

		Ok(())
	}
}

impl<'a> fmt::Display for Urn<'a> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "urn:{}:{}", self.nid, self.nss)
	}
}

/// Builder for constructing URNs with validation
#[derive(Debug, Default)]
pub struct UrnBuilder<'a> {
	/// Namespace Identifier
	pub(crate) nid: Option<Cow<'a, str>>,

	/// Hierarchical components for NSS construction
	pub(crate) components: Map<&'static str, Cow<'a, str>>,
}

impl<'a> UrnBuilder<'a> {
	/// Create a new URN builder
	#[inline]
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the Namespace Identifier (NID)
	#[inline]
	pub fn nid(mut self, nid: impl Into<Cow<'a, str>>) -> Self {
		self.nid = Some(nid.into());
		self
	}

	/// Set a component value by key
	///
	/// Keys can be hierarchical using dot notation (e.g., "resource.type", "resource.id")
	#[inline]
	pub fn set(mut self, key: &'static str, value: impl Into<Cow<'a, str>>) -> Self {
		self.components.insert(key, value.into());
		self
	}

	/// Get a component value by key
	#[inline]
	pub fn get(&self, key: &'static str) -> Option<&Cow<'a, str>> {
		self.components.get(key)
	}

	/// Build the URN with a custom NSS builder function
	///
	/// This is a lower-level method for when you're not using a spec.
	pub fn build_with<F>(self, nss_builder: F) -> Result<Urn<'a>, ValidationError>
	where
		F: FnOnce(&Self) -> Result<Cow<'a, str>, ValidationError>,
	{
		// Validate NID format first (before consuming self)
		let nid_ref = self.nid.as_ref().ok_or(ValidationError::RequiredFieldMissing("nid"))?;
		Urn::validate_nid(nid_ref)?;

		// Build NSS (while self is still intact)
		let nss = nss_builder(&self)?;

		// Now consume self to extract nid
		let nid = self.nid.unwrap(); // Safe: we validated it exists above

		Ok(Urn { nid, nss })
	}

	/// Build the URN using a spec's validation and NSS construction
	pub fn build_with_spec<S: UrnSpec>(self) -> Result<Urn<'a>, ValidationError> {
		// Apply spec transformations
		let builder = S::transform(self);

		// Validate
		S::validate(&builder)?;

		// Validate NID format before building NSS
		let nid_ref = builder.nid.as_ref().ok_or(ValidationError::RequiredFieldMissing("nid"))?;
		Urn::validate_nid(nid_ref)?;

		// Build NSS (while builder is still intact)
		let nss = S::build_nss(&builder)?;

		// Now consume builder to extract nid
		let nid = builder.nid.unwrap(); // Safe: we validated it exists above

		Ok(Urn { nid, nss })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_urn_nid_validation() {
		// Valid NIDs
		assert!(Urn::validate_nid("ab").is_ok());
		assert!(Urn::validate_nid("tightbeam").is_ok());
		assert!(Urn::validate_nid("isbn").is_ok());
		assert!(Urn::validate_nid("a123").is_ok());
		assert!(Urn::validate_nid("my-namespace").is_ok());

		// Invalid NIDs - too short
		assert!(Urn::validate_nid("a").is_err());

		// Invalid NIDs - too long
		assert!(Urn::validate_nid("a".repeat(33).as_str()).is_err());

		// Invalid NIDs - doesn't start with letter
		assert!(Urn::validate_nid("1abc").is_err());
		assert!(Urn::validate_nid("-abc").is_err());

		// Invalid NIDs - invalid characters
		assert!(Urn::validate_nid("ab_cd").is_err());
		assert!(Urn::validate_nid("ab.cd").is_err());
	}

	#[test]
	fn test_urn_builder_basic() {
		let urn = UrnBuilder::new()
			.nid("tightbeam")
			.build_with(|_| Ok("test:resource".into()))
			.unwrap();

		assert_eq!(urn.nid, "tightbeam");
		assert_eq!(urn.nss, "test:resource");
		assert_eq!(urn.to_string(), "urn:tightbeam:test:resource");
	}

	#[test]
	fn test_urn_builder_with_components() {
		let urn = UrnBuilder::new()
			.nid("example")
			.set("type", "book")
			.set("id", "123")
			.build_with(|builder| {
				let type_val = builder.get("type").ok_or(ValidationError::RequiredFieldMissing("type"))?;
				let id_val = builder.get("id").ok_or(ValidationError::RequiredFieldMissing("id"))?;
				Ok(format!("{}:{}", type_val, id_val).into())
			})
			.unwrap();

		assert_eq!(urn.to_string(), "urn:example:book:123");
	}

	#[test]
	fn test_urn_builder_missing_nid() {
		let result = UrnBuilder::new().build_with(|_| Ok("test".into()));

		assert!(matches!(result, Err(ValidationError::RequiredFieldMissing("nid"))));
	}

	#[test]
	fn test_urn_into_owned() {
		let borrowed_nid = "tightbeam";
		let borrowed_nss = "test:resource";

		let urn = Urn {
			nid: Cow::Borrowed(borrowed_nid),
			nss: Cow::Borrowed(borrowed_nss),
		};

		let owned_urn = urn.into_owned();

		assert!(matches!(owned_urn.nid, Cow::Owned(_)));
		assert!(matches!(owned_urn.nss, Cow::Owned(_)));
		assert_eq!(owned_urn.nid, "tightbeam");
		assert_eq!(owned_urn.nss, "test:resource");
	}
}

