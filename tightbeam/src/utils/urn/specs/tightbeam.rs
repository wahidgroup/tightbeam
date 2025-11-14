//! Tightbeam URN specifications
//!
//! Defines URN specs for tightbeam namespaces like instrumentation, testing, etc.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::borrow::Cow;

use crate::utils::urn::{UrnBuilder, UrnSpec, ValidationError};

/// TightbeamInstrumentation URN specification
///
/// Format: `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`
///
/// # Examples
///
/// ```
/// use tightbeam::utils::urn::{Urn, UrnBuilder};
/// use tightbeam::utils::urn::specs::TightbeamInstrumentation;
///
/// let urn = Urn::from(TightbeamInstrumentation)
///     .category("instrumentation")
///     .resource_type("trace")
///     .resource_id("abc-123")
///     .build_with_spec::<TightbeamInstrumentation>()?;
///
/// assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:trace/abc-123");
/// # Ok::<(), tightbeam::utils::urn::ValidationError>(())
/// ```
pub struct TightbeamInstrumentation;

impl UrnSpec for TightbeamInstrumentation {
	const NID: &'static str = "tightbeam";

	fn validate(builder: &UrnBuilder) -> Result<(), ValidationError> {
		// Validate category field
		match builder.get("category") {
			None => return Err(ValidationError::RequiredFieldMissing("category")),
			Some(v) if v.as_ref() != "instrumentation" => {
				return Err(ValidationError::InvalidFormat {
					field: "category",
					pattern: "const(\"instrumentation\")",
				});
			}
			_ => {}
		}

		// Validate resource_type field
		match builder.get("resource_type") {
			None => return Err(ValidationError::RequiredFieldMissing("resource_type")),
			Some(v) => {
				let valid = matches!(v.as_ref(), "trace" | "event" | "seed" | "verdict");
				if !valid {
					return Err(ValidationError::InvalidFormat {
						field: "resource_type",
						pattern: "oneof(\"trace\", \"event\", \"seed\", \"verdict\")",
					});
				}
			}
		}

		// Validate resource_id field
		if builder.get("resource_id").is_none() {
			return Err(ValidationError::RequiredFieldMissing("resource_id"));
		}

		// Additional validation: resource_id should be alphanumeric with hyphens
		if let Some(id) = builder.get("resource_id") {
			let valid = id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
			if !valid {
				return Err(ValidationError::InvalidFormat {
					field: "resource_id",
					pattern: "^[a-z0-9-]+$",
				});
			}
		}

		Ok(())
	}

	fn build_nss(builder: &UrnBuilder) -> Result<Cow<'static, str>, ValidationError> {
		let category = builder
			.get("category")
			.ok_or(ValidationError::RequiredFieldMissing("category"))?;
		let resource_type = builder
			.get("resource_type")
			.ok_or(ValidationError::RequiredFieldMissing("resource_type"))?;
		let resource_id = builder
			.get("resource_id")
			.ok_or(ValidationError::RequiredFieldMissing("resource_id"))?;

		// Format: category:resource_type/resource_id
		let nss = format!("{}:{}/{}", category, resource_type, resource_id);

		Ok(Cow::Owned(nss))
	}
}

// Generate builder methods for TightbeamInstrumentation fields
impl<'a> UrnBuilder<'a> {
	/// Set the category field (must be "instrumentation" for TightbeamInstrumentation)
	#[inline]
	pub fn category(self, value: impl Into<Cow<'a, str>>) -> Self {
		self.set("category", value)
	}

	/// Set the resource type (trace, event, seed, or verdict)
	#[inline]
	pub fn resource_type(self, value: impl Into<Cow<'a, str>>) -> Self {
		self.set("resource_type", value)
	}

	/// Set the resource ID (alphanumeric with hyphens)
	#[inline]
	pub fn resource_id(self, value: impl Into<Cow<'a, str>>) -> Self {
		self.set("resource_id", value)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::urn::Urn;

	#[test]
	fn test_tightbeam_instrumentation_valid() {
		let urn = Urn::from(TightbeamInstrumentation)
			.category("instrumentation")
			.resource_type("trace")
			.resource_id("abc-123")
			.build_with_spec::<TightbeamInstrumentation>()
			.unwrap();

		assert_eq!(urn.nid, "tightbeam");
		assert_eq!(urn.nss, "instrumentation:trace/abc-123");
		assert_eq!(urn.to_string(), "urn:tightbeam:instrumentation:trace/abc-123");
	}

	#[test]
	fn test_tightbeam_instrumentation_all_resource_types() {
		for resource_type in &["trace", "event", "seed", "verdict"] {
			let urn = Urn::from(TightbeamInstrumentation)
				.category("instrumentation")
				.resource_type(*resource_type)
				.resource_id("test-123")
				.build_with_spec::<TightbeamInstrumentation>()
				.unwrap();

			assert_eq!(urn.to_string(), format!("urn:tightbeam:instrumentation:{}/test-123", resource_type));
		}
	}

	#[test]
	fn test_tightbeam_instrumentation_missing_category() {
		let result = Urn::from(TightbeamInstrumentation)
			.resource_type("trace")
			.resource_id("123")
			.build_with_spec::<TightbeamInstrumentation>();

		assert!(matches!(result, Err(ValidationError::RequiredFieldMissing("category"))));
	}

	#[test]
	fn test_tightbeam_instrumentation_invalid_category() {
		let result = Urn::from(TightbeamInstrumentation)
			.category("testing")
			.resource_type("trace")
			.resource_id("123")
			.build_with_spec::<TightbeamInstrumentation>();

		assert!(matches!(result, Err(ValidationError::InvalidFormat { field: "category", .. })));
	}

	#[test]
	fn test_tightbeam_instrumentation_invalid_resource_type() {
		let result = Urn::from(TightbeamInstrumentation)
			.category("instrumentation")
			.resource_type("invalid")
			.resource_id("123")
			.build_with_spec::<TightbeamInstrumentation>();

		assert!(matches!(result, Err(ValidationError::InvalidFormat { field: "resource_type", .. })));
	}

	#[test]
	fn test_tightbeam_instrumentation_invalid_resource_id() {
		let result = Urn::from(TightbeamInstrumentation)
			.category("instrumentation")
			.resource_type("trace")
			.resource_id("invalid_chars!")
			.build_with_spec::<TightbeamInstrumentation>();

		assert!(matches!(result, Err(ValidationError::InvalidFormat { field: "resource_id", .. })));
	}

	#[test]
	fn test_tightbeam_instrumentation_zero_copy() {
		let category = "instrumentation";
		let resource_type = "trace";
		let resource_id = "abc-123";

		let urn = Urn::from(TightbeamInstrumentation)
			.category(category)
			.resource_type(resource_type)
			.resource_id(resource_id)
			.build_with_spec::<TightbeamInstrumentation>()
			.unwrap();

		// NID should be borrowed
		assert!(matches!(urn.nid, Cow::Borrowed(_)));
		assert_eq!(urn.nid, "tightbeam");
	}
}

