//! Tightbeam URN specifications
//!
//! Defines URN specs for tightbeam namespaces like instrumentation, testing, etc.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::utils::urn::builders::spec::Pattern;
use crate::utils::urn::UrnValidationError;

#[cfg(not(feature = "derive"))]
use crate::utils::urn::{UrnBuilder, UrnSpec};

#[cfg(feature = "derive")]
crate::urn_spec! {
	/// TightbeamInstrumentation URN specification
	///
	/// Format: `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`
	pub TightbeamInstrumentation,
	nid: "tightbeam",
	nss_structure {
		category: { value: "instrumentation", sep: ":" },
		resource_type: { values: ["trace", "event", "seed", "verdict"], sep: "/" },
		resource_id: { pattern: Pattern::AlphaNumericHyphen }
	},
	nss_format: "{}:{}/{}"
}

#[cfg(not(feature = "derive"))]
/// TightbeamInstrumentation URN specification
///
/// Format: `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`
pub struct TightbeamInstrumentation;

#[cfg(not(feature = "derive"))]
impl UrnSpec for TightbeamInstrumentation {
	const NID: &'static str = "tightbeam";

	fn validate(builder: &UrnBuilder) -> Result<(), UrnValidationError> {
		// Validate category: required and must equal "instrumentation"
		let category = builder
			.get("category")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("category"))?;
		if category.as_ref() != "instrumentation" {
			return Err(UrnValidationError::InvalidFormat { field: "category", pattern: "const(\"instrumentation\")" });
		}

		// Validate resource_type: required and must be one of ["trace", "event", "seed", "verdict"]
		let resource_type = builder
			.get("resource_type")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_type"))?;
		let valid_types = &["trace", "event", "seed", "verdict"];
		if !valid_types.iter().any(|&t| resource_type.as_ref() == t) {
			return Err(UrnValidationError::InvalidFormat { field: "resource_type", pattern: "oneof(...)" });
		}

		// Validate resource_id: required and must match AlphaNumericHyphen pattern
		let resource_id = builder
			.get("resource_id")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_id"))?;
		if !Pattern::AlphaNumericHyphen.matches(resource_id.as_ref()) {
			return Err(UrnValidationError::InvalidFormat {
				field: "resource_id",
				pattern: Pattern::AlphaNumericHyphen.pattern_str(),
			});
		}

		Ok(())
	}

	fn build_nss(builder: &UrnBuilder) -> Result<Cow<'static, str>, UrnValidationError> {
		let category = builder
			.get("category")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("category"))?;
		let resource_type = builder
			.get("resource_type")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_type"))?;
		let resource_id = builder
			.get("resource_id")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_id"))?;

		let mut result = "{}:{}/{}".to_string();
		if let Some(pos) = result.find("{}") {
			result.replace_range(pos..pos + 2, category.as_ref());
		}
		if let Some(pos) = result.find("{}") {
			result.replace_range(pos..pos + 2, resource_type.as_ref());
		}
		if let Some(pos) = result.find("{}") {
			result.replace_range(pos..pos + 2, resource_id.as_ref());
		}

		Ok(result.into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::builder::TypeBuilder;
	use crate::utils::urn::{Urn, UrnBuilder};

	#[cfg(feature = "testing")]
	use crate::{exactly, tb_assert_spec, tb_scenario};

	// Helper to build a URN with the spec
	fn build_urn<'a>(
		category: Option<&'a str>,
		resource_type: Option<&'a str>,
		resource_id: Option<&'a str>,
	) -> Result<Urn<'a>, UrnValidationError> {
		let mut builder = UrnBuilder::from(TightbeamInstrumentation);
		if let Some(cat) = category {
			builder = builder.set("category", cat);
		}
		if let Some(rt) = resource_type {
			builder = builder.set("resource_type", rt);
		}
		if let Some(rid) = resource_id {
			builder = builder.set("resource_id", rid);
		}

		builder.build()
	}

	#[test]
	fn test_tightbeam_instrumentation_valid() -> Result<(), UrnValidationError> {
		// (category, resource_type, resource_id, expected_nss, expected_urn_string)
		let test_cases: &[(&str, &str, &str, &str, &str)] = &[
			(
				"instrumentation",
				"trace",
				"abc-123",
				"instrumentation:trace/abc-123",
				"urn:tightbeam:instrumentation:trace/abc-123",
			),
			(
				"instrumentation",
				"event",
				"test-456",
				"instrumentation:event/test-456",
				"urn:tightbeam:instrumentation:event/test-456",
			),
			(
				"instrumentation",
				"seed",
				"xyz-789",
				"instrumentation:seed/xyz-789",
				"urn:tightbeam:instrumentation:seed/xyz-789",
			),
			(
				"instrumentation",
				"verdict",
				"result-1",
				"instrumentation:verdict/result-1",
				"urn:tightbeam:instrumentation:verdict/result-1",
			),
		];

		for (category, resource_type, resource_id, expected_nss, expected_urn) in test_cases {
			let urn = build_urn(Some(category), Some(resource_type), Some(resource_id))?;
			assert_eq!(urn.nid, "tightbeam");
			assert_eq!(urn.nss, *expected_nss);
			assert_eq!(urn.to_string(), *expected_urn);
		}
		Ok(())
	}

	#[test]
	fn test_tightbeam_instrumentation_all_resource_types() -> Result<(), UrnValidationError> {
		let resource_types = &["trace", "event", "seed", "verdict"];
		let resource_id = "test-123";
		for resource_type in resource_types {
			let urn = build_urn(Some("instrumentation"), Some(resource_type), Some(resource_id))?;
			assert_eq!(
				urn.to_string(),
				format!("urn:tightbeam:instrumentation:{resource_type}/{resource_id}")
			);
		}
		Ok(())
	}

	#[test]
	fn test_tightbeam_instrumentation_missing_fields() {
		// (category, resource_type, resource_id, expected_error_field)
		type MissingFieldsTestCase<'a> = (Option<&'a str>, Option<&'a str>, Option<&'a str>, &'a str);
		let test_cases: &[MissingFieldsTestCase] = &[
			(None, Some("trace"), Some("123"), "category"),
			(Some("instrumentation"), None, Some("123"), "resource_type"),
			(Some("instrumentation"), Some("trace"), None, "resource_id"),
		];

		for (category, resource_type, resource_id, expected_field) in test_cases {
			let result = build_urn(*category, *resource_type, *resource_id);
			assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing(field)) if field == *expected_field));
		}
	}

	#[test]
	fn test_tightbeam_instrumentation_invalid_field_values() {
		// (category, resource_type, resource_id, error_type)
		let test_cases: &[(&str, &str, &str, &str)] = &[
			("testing", "trace", "123", "category"),
			("invalid", "trace", "123", "category"),
			("instrumentation", "invalid", "123", "resource_type"),
			("instrumentation", "unknown", "123", "resource_type"),
			("instrumentation", "trace", "invalid_chars!", "resource_id"),
			("instrumentation", "trace", "space here", "resource_id"),
			("instrumentation", "trace", "underscore_here", "resource_id"),
		];

		for (category, resource_type, resource_id, expected_field) in test_cases {
			let result = build_urn(Some(*category), Some(*resource_type), Some(*resource_id));
			assert!(matches!(result, Err(UrnValidationError::InvalidFormat { field, .. }) if field == *expected_field));
		}
	}

	#[cfg(feature = "testing")]
	tb_assert_spec! {
		pub TightbeamUrnSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("urn_string", exactly!(1), equals!("urn:tightbeam:instrumentation:trace/abc-123"))
			]
		}
	}

	#[cfg(feature = "testing")]
	tb_scenario! {
		name: test_tightbeam_urn_with_spec,
		spec: TightbeamUrnSpec,
		environment Bare {
			exec: |trace| {
				let urn = UrnBuilder::from(TightbeamInstrumentation)
					.set("category", "instrumentation")
					.set("resource_type", "trace")
					.set("resource_id", "abc-123")
					.build()?;

				trace.event_with("urn_string", &[], urn.to_string());

				Ok(())
			}
		}
	}
}
