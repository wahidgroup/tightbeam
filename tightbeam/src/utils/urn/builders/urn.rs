//! URN builder for constructing URNs with validation

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::borrow::Cow;

#[cfg(feature = "std")]
use std::{borrow::Cow, collections::HashMap};

use crate::builder::TypeBuilder;
use crate::utils::urn::{Urn, UrnSpec, UrnValidationError};

/// Spec builder function type
type SpecBuilderFn<'a> = dyn FnOnce(&UrnBuilder<'a>) -> Result<Cow<'static, str>, UrnValidationError> + 'a;

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
	/// Create a new URN builder
	#[inline]
	pub fn new() -> Self {
		Self::default()
	}

	/// Get a component value by key
	#[inline]
	pub fn get(&self, key: &'static str) -> Option<&Cow<'a, str>> {
		self.components.get(key)
	}

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
		let spec_builder = move |builder: &UrnBuilder<'a>| -> Result<Cow<'static, str>, UrnValidationError> {
			// Apply spec transformations (need to clone to avoid consuming)
			let mut transformed = UrnBuilder {
				nid: builder.nid.clone(),
				components: builder.components.clone(),
				nss_mode: NssMode::Unset,
			};
			transformed = S::transform(transformed);

			// Validate
			S::validate(&transformed)?;
			// Build NSS
			S::build_nss(&transformed)
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
		let mut builder = UrnBuilder::new().with_spec::<S>();
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
	/// The optional r-component, q-component, and f-component extensions from RFC 8141
	/// are not included in this basic implementation.
	///
	/// # Errors
	/// Returns an error if:
	/// - NID is missing
	/// - NID format is invalid (not RFC 8141 compliant)
	/// - Both `with_nss()` and `with_spec()` were called (mutually exclusive)
	/// - NSS cannot be constructed (empty components when using default mode)
	fn build(self) -> Result<Urn<'a>, UrnValidationError> {
		// Validate NID format first (before consuming self)
		let nid_ref = self.nid.as_ref().ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;
		Urn::validate_nid(nid_ref)?;

		// Extract nss_mode before consuming self
		let nss_mode = self.nss_mode;
		let components = self.components;

		// Build NSS according to mode
		let nss = match nss_mode {
			NssMode::Unset => {
				// Default: build from components in lexicographic order
				#[cfg(not(feature = "std"))]
				use alloc::vec::Vec;

				#[cfg(feature = "std")]
				use std::vec::Vec;

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
			NssMode::Spec(builder_fn) => {
				// Build using spec - create a temporary builder reference for the closure
				let builder_ref =
					UrnBuilder { nid: self.nid.clone(), components: components.clone(), nss_mode: NssMode::Unset };
				let nss_static = builder_fn(&builder_ref)?;
				// Convert Cow<'static, str> to Cow<'a, str>
				match nss_static {
					Cow::Borrowed(s) => Cow::Borrowed(s),
					Cow::Owned(s) => Cow::Owned(s),
				}
			}
		};

		// Now consume self to extract nid
		let nid = self.nid.ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;
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
	use crate::utils::urn::{UrnSpec, UrnSpecBuilder};

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

		fn validate(builder: &UrnBuilder) -> Result<(), UrnValidationError> {
			Self::spec_builder().validate(builder)
		}

		fn build_nss(builder: &UrnBuilder) -> Result<Cow<'static, str>, UrnValidationError> {
			let nss = Self::spec_builder().build_nss(builder)?;
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
			let urn = UrnBuilder::new().with_nid(*nid).with_nss(*nss).build()?;
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
			let mut builder = UrnBuilder::new().with_nid(*nid);
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
			let result = UrnBuilder::new().with_nss(*nss).build();
			assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing("nid"))));
		}
	}

	#[test]
	fn test_urn_builder_with_spec() -> Result<(), UrnValidationError> {
		// (category, type, id, expected_nss, expected_urn_string)
		let test_cases: &[(&str, &str, &str, &str, &str)] = &[
			(
				"instrumentation",
				"trace",
				"abc-123",
				"instrumentation:trace/abc-123",
				"urn:test:instrumentation:trace/abc-123",
			),
			(
				"instrumentation",
				"event",
				"test-456",
				"instrumentation:event/test-456",
				"urn:test:instrumentation:event/test-456",
			),
			(
				"instrumentation",
				"seed",
				"xyz-789",
				"instrumentation:seed/xyz-789",
				"urn:test:instrumentation:seed/xyz-789",
			),
			(
				"instrumentation",
				"verdict",
				"result-1",
				"instrumentation:verdict/result-1",
				"urn:test:instrumentation:verdict/result-1",
			),
		];

		for (category, type_val, id, expected_nss, expected_urn) in test_cases {
			let urn = UrnBuilder::from(TestUrnSpec)
				.set("category", *category)
				.set("type", *type_val)
				.set("id", *id)
				.build()?;

			assert_eq!(urn.nid, TestUrnSpec::NID);
			assert_eq!(urn.nss, *expected_nss);
			assert_eq!(urn.to_string(), *expected_urn);
		}

		Ok(())
	}

	#[test]
	fn test_urn_builder_with_spec_missing_fields() {
		// (category, type, id, expected_error_field)
		type MissingFieldsTestCase<'a> = (Option<&'a str>, Option<&'a str>, Option<&'a str>, &'a str);
		let test_cases: &[MissingFieldsTestCase] = &[
			(None, Some("trace"), Some("123"), "category"),
			(Some("instrumentation"), None, Some("123"), "type"),
			(Some("instrumentation"), Some("trace"), None, "id"),
		];

		for (category, type_val, id, expected_field) in test_cases {
			let mut builder = UrnBuilder::from(TestUrnSpec);
			if let Some(cat) = *category {
				builder = builder.set("category", cat);
			}
			if let Some(t) = *type_val {
				builder = builder.set("type", t);
			}
			if let Some(i) = *id {
				builder = builder.set("id", i);
			}

			let result = builder.build();
			assert!(matches!(result, Err(UrnValidationError::RequiredFieldMissing(field)) if field == *expected_field));
		}
	}

	#[test]
	fn test_urn_builder_with_spec_invalid_fields() {
		// (category, type, id, error_type)
		let test_cases: &[(&str, &str, &str, &str)] = &[
			("invalid", "trace", "123", "category"),
			("instrumentation", "invalid", "123", "type"),
			("instrumentation", "trace", "invalid_chars!", "id"),
			("instrumentation", "trace", "space here", "id"),
			("instrumentation", "trace", "underscore_here", "id"),
		];

		for (category, type_val, id, expected_field) in test_cases {
			let result = UrnBuilder::from(TestUrnSpec)
				.set("category", *category)
				.set("type", *type_val)
				.set("id", *id)
				.build();

			assert!(matches!(result, Err(UrnValidationError::InvalidFormat { field, .. }) if field == *expected_field));
		}
	}

	#[test]
	fn test_urn_builder_empty_components() {
		let test_cases: &[&str] = &["tightbeam", "test", "example"];
		for nid in test_cases {
			let result = UrnBuilder::new().with_nid(*nid).build();
			assert!(matches!(
				result,
				Err(UrnValidationError::RequiredFieldMissing("nss components"))
			));
		}
	}
}
