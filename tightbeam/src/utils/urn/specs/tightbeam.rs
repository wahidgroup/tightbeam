//! Tightbeam URN specifications
//!
//! Defines URN specs for tightbeam namespaces like instrumentation, testing, etc.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

#[cfg(all(feature = "std", not(feature = "derive")))]
use std::borrow::Cow;

use crate::utils::urn::builders::spec::Pattern;
use crate::utils::urn::UrnValidationError;

#[cfg(not(feature = "derive"))]
use crate::utils::urn::spec::UrnSpec;
#[cfg(not(feature = "derive"))]
use crate::utils::urn::UrnComponents;

#[cfg(feature = "derive")]
crate::urn_spec! {
	/// TightbeamUrnSpec URN specification
	///
	/// Format: `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`
	pub TightbeamUrnSpec,
	nid: "tightbeam",
	nss_structure {
		category: { value: "instrumentation", sep: ":" },
		resource_type: { values: ["trace", "event", "seed", "verdict"], sep: "/" },
		resource_id: { pattern: Pattern::AlphaNumericHyphen }
	},
	nss_format: "{}:{}/{}",
	transform: |components| {
		// Normalize resource_type to lowercase
		for (key, value) in components.iter_mut() {
			if key == "resource_type" {
				*value = value.to_lowercase().into();
			}
		}
	}
}

#[cfg(not(feature = "derive"))]
/// TightbeamUrnSpec URN specification
///
/// Format: `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`
pub struct TightbeamUrnSpec;

#[cfg(not(feature = "derive"))]
impl UrnSpec for TightbeamUrnSpec {
	const NID: &'static str = "tightbeam";

	fn transform<'a>(components: &mut dyn UrnComponents<'a>) {
		// Normalize resource_type to lowercase
		for (key, value) in components.iter_mut() {
			if key == "resource_type" {
				*value = value.to_lowercase().into();
			}
		}
	}

	fn validate<'a>(components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError> {
		// Validate category: required and must equal "instrumentation"
		let category = components
			.get_component("category")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("category"))?;
		if category.as_ref() != "instrumentation" {
			return Err(UrnValidationError::InvalidFormat { field: "category", pattern: None });
		}

		// Validate resource_type: required and must be one of ["trace", "event", "seed", "verdict"]
		let resource_type = components
			.get_component("resource_type")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_type"))?;
		let valid_types = &["trace", "event", "seed", "verdict"];
		if !valid_types.iter().any(|&t| resource_type.as_ref() == t) {
			return Err(UrnValidationError::InvalidFormat { field: "resource_type", pattern: None });
		}

		// Validate resource_id: required and must match AlphaNumericHyphen pattern
		let resource_id = components
			.get_component("resource_id")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_id"))?;
		if !Pattern::AlphaNumericHyphen.matches(resource_id.as_ref()) {
			return Err(UrnValidationError::InvalidFormat {
				field: "resource_id",
				pattern: Some(Pattern::AlphaNumericHyphen),
			});
		}

		Ok(())
	}

	fn build_nss<'a>(components: &dyn UrnComponents<'a>) -> Result<Cow<'static, str>, UrnValidationError> {
		let category = components
			.get_component("category")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("category"))?;
		let resource_type = components
			.get_component("resource_type")
			.ok_or_else(|| UrnValidationError::RequiredFieldMissing("resource_type"))?;
		let resource_id = components
			.get_component("resource_id")
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
	use crate::utils::urn::UrnBuilder;

	#[cfg(feature = "testing")]
	use crate::{exactly, tb_assert_spec, tb_scenario};

	// Macro to reduce repetition in tightbeam URN tests
	macro_rules! build_tightbeam_urn {
		(values: [$($k:literal = $v:literal),+], nss: $expected_nss:literal, urn: $expected_urn:literal) => {{
			let urn = UrnBuilder::from(TightbeamUrnSpec)
				$(.set($k, $v))+
				.build()?;
			assert_eq!(urn.nid, "tightbeam");
			assert_eq!(urn.nss, $expected_nss);
			assert_eq!(urn.to_string(), $expected_urn);
		}};
	}

	macro_rules! missing_field {
		(values: [$($k:literal = $v:literal),*], field: $expected:literal) => {{
			let mut builder = UrnBuilder::from(TightbeamUrnSpec);
			$(builder = builder.set($k, $v);)*
			let result = builder.build();
			assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing(field)) if field == $expected));
		}};
	}

	macro_rules! invalid_field {
		(values: [$($k:literal = $v:literal),+], field: $expected:literal) => {{
			let result = UrnBuilder::from(TightbeamUrnSpec)
				$(.set($k, $v))+
				.build();
			assert!(matches!(result, Err(UrnValidationError::InvalidFormat { field, .. }) if field == $expected));
		}};
	}

	#[test]
	fn test_tightbeam_instrumentation_valid() -> Result<(), UrnValidationError> {
		build_tightbeam_urn!(
			values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "abc-123"],
			nss: "instrumentation:trace/abc-123",
			urn: "urn:tightbeam:instrumentation:trace/abc-123"
		);

		build_tightbeam_urn!(
			values: ["category" = "instrumentation", "resource_type" = "event", "resource_id" = "test-456"],
			nss: "instrumentation:event/test-456",
			urn: "urn:tightbeam:instrumentation:event/test-456"
		);

		build_tightbeam_urn!(
			values: ["category" = "instrumentation", "resource_type" = "seed", "resource_id" = "xyz-789"],
			nss: "instrumentation:seed/xyz-789",
			urn: "urn:tightbeam:instrumentation:seed/xyz-789"
		);

		build_tightbeam_urn!(
			values: ["category" = "instrumentation", "resource_type" = "verdict", "resource_id" = "result-1"],
			nss: "instrumentation:verdict/result-1",
			urn: "urn:tightbeam:instrumentation:verdict/result-1"
		);

		Ok(())
	}

	#[test]
	fn test_tightbeam_instrumentation_all_resource_types() -> Result<(), UrnValidationError> {
		let resource_types = &["trace", "event", "seed", "verdict"];
		let resource_id = "test-123";
		for resource_type in resource_types {
			let urn = UrnBuilder::from(TightbeamUrnSpec)
				.set("category", "instrumentation")
				.set("resource_type", *resource_type)
				.set("resource_id", resource_id)
				.build()?;
			assert_eq!(
				urn.to_string(),
				format!("urn:tightbeam:instrumentation:{resource_type}/{resource_id}")
			);
		}
		Ok(())
	}

	#[test]
	fn test_tightbeam_instrumentation_missing_fields() {
		missing_field!(values: ["resource_type" = "trace", "resource_id" = "123"], field: "category");
		missing_field!(values: ["category" = "instrumentation", "resource_id" = "123"], field: "resource_type");
		missing_field!(values: ["category" = "instrumentation", "resource_type" = "trace"], field: "resource_id");
	}

	#[test]
	fn test_tightbeam_instrumentation_invalid_field_values() {
		// Constraint violations
		invalid_field!(values: ["category" = "testing", "resource_type" = "trace", "resource_id" = "123"], field: "category");
		invalid_field!(values: ["category" = "invalid", "resource_type" = "trace", "resource_id" = "123"], field: "category");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "invalid", "resource_id" = "123"], field: "resource_type");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "unknown", "resource_id" = "123"], field: "resource_type");

		// Pattern violations
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "invalid_chars!"], field: "resource_id");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "space here"], field: "resource_id");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "underscore_here"], field: "resource_id");
	}

	#[test]
	fn test_tightbeam_instrumentation_transform_lowercase() -> Result<(), UrnValidationError> {
		// Test that uppercase resource_type gets normalized to lowercase
		let test_cases: &[(&str, &str)] =
			&[("TRACE", "trace"), ("Event", "event"), ("SEED", "seed"), ("VeRdIcT", "verdict")];

		for (input, expected) in test_cases {
			let urn = UrnBuilder::from(TightbeamUrnSpec)
				.set("category", "instrumentation")
				.set("resource_type", *input)
				.set("resource_id", "test-123")
				.build()?;
			assert_eq!(urn.to_string(), format!("urn:tightbeam:instrumentation:{expected}/test-123"));
		}
		Ok(())
	}

	#[cfg(feature = "testing")]
	tb_assert_spec! {
		pub TightbeamUrnSpecSpec,
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
		spec: TightbeamUrnSpecSpec,
		environment Bare {
			exec: |trace| {
				let urn = UrnBuilder::from(TightbeamUrnSpec)
					.set("category", "instrumentation")
					.set("resource_type", "trace")
					.set("resource_id", "abc-123")
					.build()?;

				trace.event_with("urn_string", &[], urn.to_string())?;

				Ok(())
			}
		}
	}
}
