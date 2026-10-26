//! The URN specification of the `tightbeam` namespace.
//!
//! [`TightbeamUrnSpec`] validates the instrumentation URNs of the namespace,
//! such as `urn:tightbeam:instrumentation:trace/<id>`.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::urn::builders::spec::Pattern;
use crate::urn::UrnValidationError;

crate::urn_spec! {
	/// The URN specification of the tightbeam instrumentation namespace.
	///
	/// Its format is
	/// `urn:tightbeam:instrumentation:<resource_type>/<resource_id>`.
	pub TightbeamUrnSpec,
	nid: "tightbeam",
	nss_structure {
		category: { value: "instrumentation", sep: ":" },
		resource_type: { values: ["trace", "event", "seed", "verdict"], sep: "/" },
		resource_id: { pattern: Pattern::AlphaNumericHyphen }
	},
	nss_format: "{}:{}/{}",
	transform: |components| {
		// The transform lowercases a resource type to meet the `values` list.
		for (key, value) in components.iter_mut() {
			if key == "resource_type" {
				*value = value.to_lowercase().into();
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::urn::UrnBuilder;

	// This macro builds the URN of one case and checks its NID, NSS, and text.
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

	// Each resource type that the spec admits renders into the URN.
	crate::tb_cases! {
		fn test_tightbeam_instrumentation_all_resource_types(
			(resource_type, expected): (&str, &str)
		) -> Result<(), UrnValidationError> {
			let urn = UrnBuilder::from(TightbeamUrnSpec)
				.set("category", "instrumentation")
				.set("resource_type", resource_type)
				.set("resource_id", "test-123")
				.build()?;

			assert_eq!(urn.to_string(), expected);
			Ok(())
		}
		cases {
			trace => ("trace", "urn:tightbeam:instrumentation:trace/test-123"),
			event => ("event", "urn:tightbeam:instrumentation:event/test-123"),
			seed => ("seed", "urn:tightbeam:instrumentation:seed/test-123"),
			verdict => ("verdict", "urn:tightbeam:instrumentation:verdict/test-123"),
		}
	}

	#[test]
	fn test_tightbeam_instrumentation_missing_fields() {
		missing_field!(values: ["resource_type" = "trace", "resource_id" = "123"], field: "category");
		missing_field!(values: ["category" = "instrumentation", "resource_id" = "123"], field: "resource_type");
		missing_field!(values: ["category" = "instrumentation", "resource_type" = "trace"], field: "resource_id");
	}

	#[test]
	fn test_tightbeam_instrumentation_invalid_field_values() {
		// A value outside the const or the listed values fails its constraint.
		invalid_field!(values: ["category" = "testing", "resource_type" = "trace", "resource_id" = "123"], field: "category");
		invalid_field!(values: ["category" = "invalid", "resource_type" = "trace", "resource_id" = "123"], field: "category");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "invalid", "resource_id" = "123"], field: "resource_type");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "unknown", "resource_id" = "123"], field: "resource_type");

		// A value with a character outside the pattern fails it.
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "invalid_chars!"], field: "resource_id");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "space here"], field: "resource_id");
		invalid_field!(values: ["category" = "instrumentation", "resource_type" = "trace", "resource_id" = "underscore_here"], field: "resource_id");
	}

	// The spec normalizes a resource type in any case to lowercase.
	crate::tb_cases! {
		fn test_tightbeam_instrumentation_transform_lowercase(
			(input, expected): (&str, &str)
		) -> Result<(), UrnValidationError> {
			let urn = UrnBuilder::from(TightbeamUrnSpec)
				.set("category", "instrumentation")
				.set("resource_type", input)
				.set("resource_id", "test-123")
				.build()?;

			assert_eq!(urn.to_string(), expected);
			Ok(())
		}
		cases {
			trace_upper => ("TRACE", "urn:tightbeam:instrumentation:trace/test-123"),
			event_title => ("Event", "urn:tightbeam:instrumentation:event/test-123"),
			seed_upper => ("SEED", "urn:tightbeam:instrumentation:seed/test-123"),
			verdict_mixed => ("VeRdIcT", "urn:tightbeam:instrumentation:verdict/test-123"),
		}
	}
}
