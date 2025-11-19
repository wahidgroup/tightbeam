//! URN builder for constructing URNs with validation

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{borrow::Cow, boxed::Box, collections::HashMap};

use crate::builder::TypeBuilder;
use crate::utils::urn::{Urn, UrnComponents, UrnSpec, UrnValidationError};

/// Spec builder function type
type SpecBuilderFn<'a> = dyn FnOnce(&mut UrnBuilder<'a>) -> Result<Cow<'static, str>, UrnValidationError> + 'a;

/// Builder for constructing URNs with validation
#[derive(Default)]
pub struct UrnBuilder<'a> {
	/// Namespace Identifier
	pub(crate) nid: Option<Cow<'a, str>>,

	/// Hierarchical components for NSS construction
	pub(crate) components: HashMap<&'static str, Cow<'a, str>>,

	/// NSS building mode - either direct NSS or spec-based
	nss_mode: NssMode<'a>,
}

/// NSS construction mode - mutually exclusive
#[derive(Default)]
enum NssMode<'a> {
	/// Not yet set
	#[default]
	Unset,
	/// Direct NSS string provided via `with_nss()`
	Direct(Cow<'a, str>),
	/// Spec-based building via `with_spec()` - stores the building closure
	Spec(Box<SpecBuilderFn<'a>>),
}

impl<'a> UrnBuilder<'a> {
	/// Get a component value by key
	#[inline]
	pub fn get(&self, key: &'static str) -> Option<&Cow<'a, str>> {
		self.components.get(key)
	}
}

impl<'a> UrnComponents<'a> for UrnBuilder<'a> {
	fn get_component(&self, key: &'static str) -> Option<&Cow<'a, str>> {
		self.get(key)
	}

	fn set_component(&mut self, key: &'static str, value: Cow<'a, str>) {
		self.components.insert(key, value);
	}

	fn remove_component(&mut self, key: &'static str) -> Option<Cow<'a, str>> {
		self.components.remove(key)
	}

	#[cfg(feature = "std")]
	#[inline]
	fn iter(&self) -> Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_> {
		Box::new(self.components.iter().map(|(k, v)| (*k, v)))
	}

	#[cfg(not(feature = "std"))]
	#[inline]
	fn iter(&self) -> Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_> {
		Box::new(self.components.iter().map(|(k, v)| (*k, v)))
	}

	#[cfg(feature = "std")]
	#[inline]
	fn iter_mut(&mut self) -> Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_> {
		Box::new(self.components.iter_mut().map(|(k, v)| (*k, v)))
	}

	#[cfg(not(feature = "std"))]
	#[inline]
	fn iter_mut(&mut self) -> Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_> {
		Box::new(self.components.iter_mut().map(|(k, v)| (*k, v)))
	}
}

impl<'a> UrnBuilder<'a> {
	/// Set a component value by key
	///
	/// Keys can be hierarchical using dot notation (e.g., "resource.type")
	#[inline]
	pub fn set(mut self, key: &'static str, value: impl Into<Cow<'a, str>>) -> Self {
		self.components.insert(key, value.into());
		self
	}

	/// Set the Namespace Identifier (NID)
	#[inline]
	pub fn with_nid(mut self, nid: impl Into<Cow<'a, str>>) -> Self {
		self.nid = Some(nid.into());
		self
	}

	/// Set the NSS directly
	///
	/// This method cannot be used together with `with_spec()`. If both are
	/// called, `build()` will return an error.
	pub fn with_nss(mut self, nss: impl Into<Cow<'a, str>>) -> Self {
		self.nss_mode = NssMode::Direct(nss.into());
		self
	}

	/// Configure the builder to use a spec for validation and NSS construction
	///
	/// This method cannot be used together with `with_nss()`. If both are called,
	/// `build()` will return an error.
	pub fn with_spec<S: UrnSpec>(mut self) -> Self {
		// Capture the spec's building logic in a closure
		let spec_builder = move |builder: &mut UrnBuilder<'a>| -> Result<Cow<'static, str>, UrnValidationError> {
			// Transform: spec mutates components via UrnComponents trait
			S::transform(builder as &mut dyn UrnComponents<'a>);
			// Validate using UrnComponents trait
			S::validate(builder as &dyn UrnComponents<'a>)?;
			// Build NSS using UrnComponents trait
			S::build_nss(builder as &dyn UrnComponents<'a>)
		};

		self.nss_mode = NssMode::Spec(Box::new(spec_builder));
		self
	}
}

impl<'a, S: UrnSpec> From<S> for UrnBuilder<'a> {
	/// Create a URN builder from a spec type
	///
	/// Pre-configures the builder with the spec's NID (Namespace Identifier)
	/// and applies the spec's validation and NSS building logic. The builder
	/// is ready to use - no need to call `with_spec::<S>()` separately.
	#[inline]
	fn from(_: S) -> Self {
		let mut builder = UrnBuilder::default().with_spec::<S>();
		builder.nid = Some(Cow::Borrowed(S::NID));
		builder
	}
}

impl<'a> TypeBuilder<Urn<'a>> for UrnBuilder<'a> {
	type Error = UrnValidationError;

	/// Build the URN using the configured NSS mode
	///
	/// The NSS can be provided via:
	/// - `with_nss()`: Direct NSS string
	/// - `with_spec()`: Spec-based validation and construction
	/// - Default: Constructed from components in lexicographic key order
	///
	/// `with_nss()` and `with_spec()` are mutually exclusive. If neither is called,
	/// the NSS is constructed from components.
	///
	/// # RFC 8141 Compliance
	///
	/// This method produces a URN in the format `urn:<NID>:<NSS>` where:
	/// - NID is validated to be 2-32 characters, alphanumeric plus hyphens, starting with a letter
	/// - NSS is constructed according to the selected mode
	///
	/// # Errors
	/// Returns an error if:
	/// - NID is missing
	/// - NID format is invalid (not RFC 8141 compliant)
	/// - Both `with_nss()` and `with_spec()` were called (mutually exclusive)
	/// - NSS cannot be constructed (empty components when using default mode)
	fn build(mut self) -> Result<Urn<'a>, UrnValidationError> {
		// Validate NID format first
		let nid_ref = self.nid.as_ref().ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;

		Urn::validate_nid(nid_ref)?;

		// Handle Spec case FIRST while self is still intact
		if matches!(self.nss_mode, NssMode::Spec(_)) {
			// Extract the closure by replacing with Unset
			let builder_fn = match core::mem::replace(&mut self.nss_mode, NssMode::Unset) {
				NssMode::Spec(f) => f,
				_ => unreachable!(),
			};

			let nss = builder_fn(&mut self)?;
			let nid = self.nid.ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;
			return Ok(Urn { nid, nss });
		}

		// For other modes, extract fields and build NSS
		let nss_mode = self.nss_mode;
		let components = self.components;
		let nid = self.nid;

		let nss = match nss_mode {
			NssMode::Unset => {
				// Collect and sort keys for deterministic ordering (important for HashMap)
				let mut keys: Vec<&'static str> = components.keys().copied().collect();
				keys.sort();

				let mut nss_parts = Vec::new();
				for key in keys {
					if let Some(value) = components.get(key) {
						nss_parts.push(value.as_ref());
					}
				}

				if nss_parts.is_empty() {
					return Err(UrnValidationError::RequiredFieldMissing("nss components"));
				}

				nss_parts.join(":").into()
			}
			NssMode::Direct(nss) => nss,
			NssMode::Spec(_) => unreachable!("Spec case handled above"),
		};

		let nid = nid.ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;
		Ok(Urn { nid, nss })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::builder::TypeBuilder;
	use crate::utils::urn::builders::spec::Pattern;

	#[cfg(feature = "derive")]
	crate::urn_spec! {
		/// Test URN spec for testing URN builder functionality
		TestUrnSpec,
		nid: "test",
		nss_structure {
			category: { value: "instrumentation", sep: ":" },
			type: { values: ["trace", "event", "seed", "verdict"], sep: "/" },
			id: { pattern: Pattern::AlphaNumericHyphen }
		},
		nss_format: "{}:{}/{}"
	}

	#[cfg(not(feature = "derive"))]
	use crate::utils::urn::{UrnComponents, UrnSpec, UrnSpecBuilder};

	#[cfg(not(feature = "derive"))]
	struct TestUrnSpec;

	#[cfg(not(feature = "derive"))]
	impl TestUrnSpec {
		fn spec_builder() -> UrnSpecBuilder {
			UrnSpecBuilder::from("test")
				.field_required("category")
				.field_const("category", "instrumentation")
				.field_nss_separator("category", ":")
				.field_required("type")
				.field_oneof("type", &["trace", "event", "seed", "verdict"])
				.field_nss_separator("type", "/")
				.field_required("id")
				.field_pattern("id", Pattern::AlphaNumericHyphen)
				.nss_format("{}:{}/{}")
		}
	}

	#[cfg(not(feature = "derive"))]
	impl UrnSpec for TestUrnSpec {
		const NID: &'static str = "test";

		fn validate<'a>(components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError> {
			Self::spec_builder().validate(components)
		}

		fn build_nss<'a>(components: &dyn UrnComponents<'a>) -> Result<Cow<'static, str>, UrnValidationError> {
			let nss = Self::spec_builder().build_nss(components)?;
			Ok(nss.into())
		}
	}

	#[test]
	fn test_urn_builder_with_nss() -> Result<(), UrnValidationError> {
		// (nid, nss, expected_urn_string)
		let test_cases: &[(&str, &str, &str)] = &[
			("tightbeam", "test:resource", "urn:tightbeam:test:resource"),
			("example", "path/to/resource", "urn:example:path/to/resource"),
			("test", "simple", "urn:test:simple"),
		];

		for (nid, nss, expected) in test_cases {
			let urn = UrnBuilder::default().with_nid(*nid).with_nss(*nss).build()?;
			assert_eq!(urn.nid, *nid);
			assert_eq!(urn.nss, *nss);
			assert_eq!(urn.to_string(), *expected);
		}

		Ok(())
	}

	#[test]
	fn test_urn_builder_with_components() -> Result<(), UrnValidationError> {
		// (nid, components, expected_urn_string)
		// Components are sorted by key in lexicographic order
		type ComponentsTestCase<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
		let test_cases: &[ComponentsTestCase] = &[
			("example", &[("type", "book"), ("id", "123")], "urn:example:123:book"),
			("test", &[("a", "1"), ("b", "2"), ("c", "3")], "urn:test:1:2:3"),
			("ns", &[("z", "last"), ("a", "first")], "urn:ns:first:last"),
		];

		for (nid, components, expected) in test_cases {
			let mut builder = UrnBuilder::default().with_nid(*nid);
			for (key, value) in *components {
				builder = builder.set(key, *value);
			}

			let urn = builder.build()?;
			assert_eq!(urn.nid, *nid);
			assert_eq!(urn.to_string(), *expected);
		}

		Ok(())
	}

	#[test]
	fn test_urn_builder_missing_nid() {
		let test_cases: &[&str] = &["test", "resource:path", ""];
		for nss in test_cases {
			let result = UrnBuilder::default().with_nss(*nss).build();
			assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing(_))));
		}
	}

	#[test]
	fn test_urn_builder_with_spec() -> Result<(), UrnValidationError> {
		// Macro to reduce repetition in spec-based builder tests
		macro_rules! build_with_spec {
			(values: [$($k:literal = $v:literal),+], nss: $expected_nss:literal, urn: $expected_urn:literal) => {{
				let urn = UrnBuilder::from(TestUrnSpec)
					$(.set($k, $v))+
					.build()?;
				assert_eq!(urn.nid, TestUrnSpec::NID);
				assert_eq!(urn.nss, $expected_nss);
				assert_eq!(urn.to_string(), $expected_urn);
			}};
		}

		// Test all resource types with valid data
		build_with_spec!(
			values: ["category" = "instrumentation", "type" = "trace", "id" = "abc-123"],
			nss: "instrumentation:trace/abc-123",
			urn: "urn:test:instrumentation:trace/abc-123"
		);

		build_with_spec!(
			values: ["category" = "instrumentation", "type" = "event", "id" = "test-456"],
			nss: "instrumentation:event/test-456",
			urn: "urn:test:instrumentation:event/test-456"
		);

		build_with_spec!(
			values: ["category" = "instrumentation", "type" = "seed", "id" = "xyz-789"],
			nss: "instrumentation:seed/xyz-789",
			urn: "urn:test:instrumentation:seed/xyz-789"
		);

		build_with_spec!(
			values: ["category" = "instrumentation", "type" = "verdict", "id" = "result-1"],
			nss: "instrumentation:verdict/result-1",
			urn: "urn:test:instrumentation:verdict/result-1"
		);

		Ok(())
	}

	#[test]
	fn test_urn_builder_with_spec_missing_fields() {
		// Macro to test missing required fields
		macro_rules! missing_field {
			(values: [$($k:literal = $v:literal),*], field: $expected:literal) => {{
				let mut builder = UrnBuilder::from(TestUrnSpec);
				$(builder = builder.set($k, $v);)*
				let result = builder.build();
				assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing(field)) if field == $expected));
			}};
		}

		// Test each required field being missing
		missing_field!(values: ["type" = "trace", "id" = "123"], field: "category");
		missing_field!(values: ["category" = "instrumentation", "id" = "123"], field: "type");
		missing_field!(values: ["category" = "instrumentation", "type" = "trace"], field: "id");
	}

	#[test]
	fn test_urn_builder_with_spec_invalid_fields() {
		// Macro to test invalid field values
		macro_rules! invalid_field {
			(values: [$($k:literal = $v:literal),+], field: $expected:literal) => {{
				let result = UrnBuilder::from(TestUrnSpec)
					$(.set($k, $v))+
					.build();
				assert!(matches!(result, Err(UrnValidationError::InvalidFormat { field, .. }) if field == $expected));
			}};
		}

		// Test constraint violations
		invalid_field!(values: ["category" = "invalid", "type" = "trace", "id" = "123"], field: "category");
		invalid_field!(values: ["category" = "instrumentation", "type" = "invalid", "id" = "123"], field: "type");

		// Test pattern violations
		invalid_field!(values: ["category" = "instrumentation", "type" = "trace", "id" = "invalid_chars!"], field: "id");
		invalid_field!(values: ["category" = "instrumentation", "type" = "trace", "id" = "space here"], field: "id");
		invalid_field!(values: ["category" = "instrumentation", "type" = "trace", "id" = "underscore_here"], field: "id");
	}

	#[test]
	fn test_urn_builder_empty_components() {
		let test_cases: &[&str] = &["tightbeam", "test", "example"];
		for nid in test_cases {
			let result = UrnBuilder::default().with_nid(*nid).build();
			assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing(_))));
		}
	}
}
