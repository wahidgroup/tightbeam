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
	use crate::testing::TestResult;
	use crate::urn::UrnBuilder;

	use super::*;

	// Each case is a resource type and a resource id of the `instrumentation`
	// category, beside the NSS the spec builds of them. The last four cases
	// write a resource type in upper or mixed letters, which the spec
	// lowercases.
	crate::tb_cases! {
		fn the_tightbeam_spec_builds_an_instrumentation_urn(
			(resource_type, resource_id, nss): (&str, &str, &str)
		) -> TestResult {
			let category = ("category", "instrumentation");
			let components = [category, ("resource_type", resource_type), ("resource_id", resource_id)];

			let urn = UrnBuilder::from(TightbeamUrnSpec).holding(&components).build()?;
			assert_eq!((urn.nid.as_ref(), urn.nss.as_ref()), ("tightbeam", nss));
			Ok(())
		}
		cases {
			trace => ("trace", "abc-123", "instrumentation:trace/abc-123"),
			event => ("event", "test-456", "instrumentation:event/test-456"),
			seed => ("seed", "xyz-789", "instrumentation:seed/xyz-789"),
			verdict => ("verdict", "result-1", "instrumentation:verdict/result-1"),
			trace_of_test_123 => ("trace", "test-123", "instrumentation:trace/test-123"),
			event_of_test_123 => ("event", "test-123", "instrumentation:event/test-123"),
			seed_of_test_123 => ("seed", "test-123", "instrumentation:seed/test-123"),
			verdict_of_test_123 => ("verdict", "test-123", "instrumentation:verdict/test-123"),
			trace_in_upper_case => ("TRACE", "test-123", "instrumentation:trace/test-123"),
			event_in_title_case => ("Event", "test-123", "instrumentation:event/test-123"),
			seed_in_upper_case => ("SEED", "test-123", "instrumentation:seed/test-123"),
			verdict_in_mixed_case => ("VeRdIcT", "test-123", "instrumentation:verdict/test-123"),
		}
	}

	// Each case is the components of a builder of the spec, beside the refusal
	// that names the field they leave out or break. A const or a list of
	// values names no pattern, and the pattern of `resource_id` names itself.
	crate::tb_cases! {
		fn the_tightbeam_spec_names_the_field_it_refuses(
			(components, refusal): (&'static [(&'static str, &'static str)], UrnValidationError)
		) {
			let built = UrnBuilder::from(TightbeamUrnSpec).holding(components).build();
			assert_eq!(built, Err(refusal));
		}
		cases {
			missing_category => (
				&[("resource_type", "trace"), ("resource_id", "123")],
				UrnValidationError::RequiredFieldMissing("category"),
			),
			missing_resource_type => (
				&[("category", "instrumentation"), ("resource_id", "123")],
				UrnValidationError::RequiredFieldMissing("resource_type"),
			),
			missing_resource_id => (
				&[("category", "instrumentation"), ("resource_type", "trace")],
				UrnValidationError::RequiredFieldMissing("resource_id"),
			),
			testing_category => (
				&[("category", "testing"), ("resource_type", "trace"), ("resource_id", "123")],
				UrnValidationError::InvalidFormat { field: "category", pattern: None },
			),
			invalid_category => (
				&[("category", "invalid"), ("resource_type", "trace"), ("resource_id", "123")],
				UrnValidationError::InvalidFormat { field: "category", pattern: None },
			),
			invalid_resource_type => (
				&[("category", "instrumentation"), ("resource_type", "invalid"), ("resource_id", "123")],
				UrnValidationError::InvalidFormat { field: "resource_type", pattern: None },
			),
			unknown_resource_type => (
				&[("category", "instrumentation"), ("resource_type", "unknown"), ("resource_id", "123")],
				UrnValidationError::InvalidFormat { field: "resource_type", pattern: None },
			),
			bang_in_the_id => (
				&[("category", "instrumentation"), ("resource_type", "trace"), ("resource_id", "invalid_chars!")],
				UrnValidationError::InvalidFormat { field: "resource_id", pattern: Some(Pattern::AlphaNumericHyphen) },
			),
			space_in_the_id => (
				&[("category", "instrumentation"), ("resource_type", "trace"), ("resource_id", "space here")],
				UrnValidationError::InvalidFormat { field: "resource_id", pattern: Some(Pattern::AlphaNumericHyphen) },
			),
			underscore_in_the_id => (
				&[("category", "instrumentation"), ("resource_type", "trace"), ("resource_id", "underscore_here")],
				UrnValidationError::InvalidFormat { field: "resource_id", pattern: Some(Pattern::AlphaNumericHyphen) },
			),
		}
	}
}
