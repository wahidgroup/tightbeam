//! UrnSpecBuilder for programmatic URN specification construction

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::borrow::Cow;

use crate::utils::urn::{UrnComponents, UrnValidationError};

/// Validation pattern for field values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
	/// Alphabetic characters only: `[a-zA-Z]+`
	Alpha,
	/// Numeric characters only: `[0-9]+`
	Numeric,
	/// Alphanumeric characters: `[a-zA-Z0-9]+`
	AlphaNumeric,
	/// Alphanumeric characters with hyphens: `[a-z0-9-]+`
	AlphaNumericHyphen,
}

impl Pattern {
	/// Check if a value matches this pattern
	pub fn matches(&self, value: &str) -> bool {
		match self {
			Pattern::Alpha => value.chars().all(|c| c.is_ascii_alphabetic()),
			Pattern::Numeric => value.chars().all(|c| c.is_ascii_digit()),
			Pattern::AlphaNumeric => value.chars().all(|c| c.is_ascii_alphanumeric()),
			Pattern::AlphaNumericHyphen => value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
		}
	}

	/// Get the regex pattern string for error messages
	pub fn pattern_str(&self) -> &'static str {
		match self {
			Pattern::Alpha => "^[a-zA-Z]+$",
			Pattern::Numeric => "^[0-9]+$",
			Pattern::AlphaNumeric => "^[a-zA-Z0-9]+$",
			Pattern::AlphaNumericHyphen => "^[a-z0-9-]+$",
		}
	}
}

/// Validation constraint for a field
#[derive(Debug, Clone)]
pub enum Constraint {
	/// Field must equal a constant value
	Const(&'static str),
	/// Field must be one of the given values
	OneOf(Cow<'static, [&'static str]>),
}

impl Constraint {
	/// Check if a value matches this constraint
	pub fn matches(&self, value: &str) -> bool {
		match self {
			Constraint::Const(expected) => value == *expected,
			Constraint::OneOf(options) => options.contains(&value),
		}
	}

	/// Get the constraint pattern string for error messages
	pub fn pattern_str(&self) -> &'static str {
		match self {
			Constraint::Const(_) => "const(\"value\")",
			Constraint::OneOf(_) => "oneof(...)",
		}
	}
}

/// Configuration for a single field in a URN specification
#[derive(Debug, Clone)]
pub struct FieldConfig {
	/// Field name
	pub name: &'static str,
	/// Whether the field is required
	pub required: bool,
	/// Validation constraints
	pub constraints: Vec<Constraint>,
	/// Validation pattern (separate from constraints)
	pub pattern: Option<Pattern>,
	/// NSS separator before this field (e.g., ":" or "/")
	pub nss_separator: Option<&'static str>,
}

impl FieldConfig {
	fn new(name: &'static str, required: bool) -> Self {
		Self { name, required, constraints: Vec::new(), pattern: None, nss_separator: None }
	}
}

/// NSS formatting configuration
#[derive(Debug, Clone)]
pub enum NssFormat {
	/// Simple join with separator
	Join(&'static str),
	/// Custom format string with {} placeholders in field order
	Custom(String),
}

/// Builder for constructing URN specifications programmatically
#[derive(Debug, Clone)]
pub struct UrnSpecBuilder {
	/// Namespace Identifier
	nid: &'static str,
	/// Field configurations in order
	fields: Vec<FieldConfig>,
	/// NSS format configuration
	nss_format: NssFormat,
}

impl UrnSpecBuilder {
	/// Get or create a field configuration, returning its index
	fn get_or_create_field_index(&mut self, name: &'static str, required: bool) -> usize {
		if let Some(index) = self.fields.iter().position(|f| f.name == name) {
			self.fields[index].required = required;
			index
		} else {
			self.fields.push(FieldConfig::new(name, required));
			self.fields.len() - 1
		}
	}

	/// Add a required field
	pub fn field_required(mut self, name: &'static str) -> Self {
		self.get_or_create_field_index(name, true);
		self
	}

	/// Add an optional field
	pub fn field_optional(mut self, name: &'static str) -> Self {
		self.get_or_create_field_index(name, false);
		self
	}

	/// Add a const constraint to the specified field
	pub fn field_const(mut self, name: &'static str, value: &'static str) -> Self {
		let index = self.get_or_create_field_index(name, true);
		self.fields[index].constraints.push(Constraint::Const(value));
		self
	}

	/// Add a oneof constraint to the specified field
	pub fn field_oneof(mut self, name: &'static str, options: &'static [&'static str]) -> Self {
		let index = self.get_or_create_field_index(name, true);
		self.fields[index].constraints.push(Constraint::OneOf(Cow::Borrowed(options)));
		self
	}

	/// Set pattern for the specified field
	pub fn field_pattern(mut self, name: &'static str, pattern: Pattern) -> Self {
		let index = self.get_or_create_field_index(name, true);
		self.fields[index].pattern = Some(pattern);
		self
	}

	/// Set NSS separator for the specified field
	pub fn field_nss_separator(mut self, name: &'static str, separator: &'static str) -> Self {
		if let Some(field) = self.fields.iter_mut().find(|f| f.name == name) {
			field.nss_separator = Some(separator);
		}

		self
	}

	/// Set custom NSS format string (e.g., "{}:{}/{}")
	pub fn nss_format(mut self, format: &str) -> Self {
		self.nss_format = NssFormat::Custom(format.to_string());
		self
	}

	/// Validate components using this spec's configuration
	pub fn validate<'a>(&self, components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError> {
		for field in &self.fields {
			// Check required
			if field.required && components.get_component(field.name).is_none() {
				return Err(UrnValidationError::RequiredFieldMissing(field.name));
			}

			// Check constraints and pattern if value exists
			if let Some(value) = components.get_component(field.name) {
				let value_str = value.as_ref();

				// Check constraints
				for constraint in &field.constraints {
					if !constraint.matches(value_str) {
						return Err(UrnValidationError::InvalidFormat { field: field.name, pattern: None });
					}
				}

				// Check pattern
				if let Some(pattern) = field.pattern {
					if !pattern.matches(value_str) {
						return Err(UrnValidationError::InvalidFormat { field: field.name, pattern: Some(pattern) });
					}
				}
			}
		}

		Ok(())
	}

	/// Build NSS from components using this spec's configuration
	pub fn build_nss<'a>(&self, components: &dyn UrnComponents<'a>) -> Result<String, UrnValidationError> {
		match &self.nss_format {
			NssFormat::Join(default_separator) => {
				let mut nss_parts = Vec::new();
				for field in &self.fields {
					if let Some(value) = components.get_component(field.name) {
						// Add separator before value (except for first field)
						if !nss_parts.is_empty() {
							// Use field-specific separator if set, otherwise default
							let separator = field.nss_separator.unwrap_or(default_separator);
							nss_parts.push(separator);
						}

						nss_parts.push(value.as_ref());
					}
				}

				if nss_parts.is_empty() {
					return Err(UrnValidationError::RequiredFieldMissing("nss components"));
				}

				Ok(nss_parts.join(""))
			}
			NssFormat::Custom(format_str) => {
				// Extract field values in order for required fields
				let mut field_values = Vec::new();
				for field in &self.fields {
					if field.required {
						let value = components
							.get_component(field.name)
							.ok_or(UrnValidationError::RequiredFieldMissing(field.name))?;
						field_values.push(value.as_ref());
					} else if let Some(value) = components.get_component(field.name) {
						field_values.push(value.as_ref());
					}
				}

				// Count placeholders in format string
				let placeholder_count = format_str.matches("{}").count();
				if placeholder_count != field_values.len() {
					return Err(UrnValidationError::RequiredFieldMissing("nss components"));
				}

				// Build NSS using format string - replace placeholders one at a time
				let mut result = format_str.to_string();
				for value in field_values {
					if let Some(pos) = result.find("{}") {
						result.replace_range(pos..pos + 2, value);
					}
				}

				let nss = result;

				Ok(nss)
			}
		}
	}

	/// Get the NID for this spec
	pub fn nid(&self) -> &'static str {
		self.nid
	}

	/// Get field configurations
	pub fn fields(&self) -> &[FieldConfig] {
		&self.fields
	}
}

impl From<&'static str> for UrnSpecBuilder {
	fn from(nid: &'static str) -> Self {
		Self { nid, fields: Vec::new(), nss_format: NssFormat::Join(":") }
	}
}

#[cfg(test)]
mod tests {
	use crate::utils::urn::UrnBuilder;

	use super::*;

	#[test]
	fn test_pattern_matches() {
		let test_cases: &[(Pattern, &[&str], &[&str])] = &[
			(
				Pattern::Alpha,
				&["abc", "XYZ", "Hello", "WORLD"],
				&["abc123", "123", "abc-xyz", "a1b", "space here"],
			),
			(Pattern::Numeric, &["123", "0", "999", "42"], &["abc", "12a", "1-2", "12.5"]),
			(
				Pattern::AlphaNumeric,
				&["abc123", "XYZ999", "Hello42", "WORLD0", "abc", "123"],
				&["abc-xyz", "space here", "12.5", "a_b"],
			),
			(
				Pattern::AlphaNumericHyphen,
				&["abc-123", "xyz-y", "test-case", "kebab-case-id", "abc", "123"],
				&["abc_xyz", "space here", "12.5"],
			),
		];

		for (pattern, valid_values, invalid_values) in test_cases {
			for value in *valid_values {
				assert!(pattern.matches(value), "Pattern {pattern:?} should match '{value}'");
			}
			for value in *invalid_values {
				assert!(!pattern.matches(value), "Pattern {pattern:?} should not match '{value}'");
			}
		}
	}

	#[test]
	fn test_pattern_str() {
		// Data-driven: test all Pattern variants
		let test_cases: &[(Pattern, &str)] = &[
			(Pattern::Alpha, "^[a-zA-Z]+$"),
			(Pattern::Numeric, "^[0-9]+$"),
			(Pattern::AlphaNumeric, "^[a-zA-Z0-9]+$"),
			(Pattern::AlphaNumericHyphen, "^[a-z0-9-]+$"),
		];

		for (pattern, expected) in test_cases {
			assert_eq!(
				pattern.pattern_str(),
				*expected,
				"Pattern {pattern:?} should have pattern_str '{expected}'"
			);
		}
	}

	#[test]
	fn test_constraint_matches() {
		let const_test_cases: &[(&str, &[&str], &[&str])] =
			&[("expected", &["expected"], &["unexpected", "Expected", "EXPECTED", ""])];

		for (const_value, valid_values, invalid_values) in const_test_cases {
			let constraint = Constraint::Const(const_value);
			for value in *valid_values {
				assert!(constraint.matches(value), "Const({const_value:?}) should match '{value}'");
			}
			for value in *invalid_values {
				assert!(!constraint.matches(value), "Const({const_value:?}) should not match '{value}'");
			}
		}

		// OneOf constraint test cases: (options, valid_values, invalid_values)
		let oneof_test_cases: &[(&[&str], &[&str], &[&str])] = &[
			(
				&["option1", "option2", "option3"],
				&["option1", "option2", "option3"],
				&["option4", "Option1", "OPTION1", ""],
			),
			(&["a", "b", "c"], &["a", "b", "c"], &["d", "A", "ab", ""]),
		];

		for (options, valid_values, invalid_values) in oneof_test_cases {
			let constraint = Constraint::OneOf(Cow::Borrowed(*options));
			for value in *valid_values {
				assert!(constraint.matches(value), "OneOf({options:?}) should match '{value}'");
			}
			for value in *invalid_values {
				assert!(!constraint.matches(value), "OneOf({options:?}) should not match '{value}'");
			}
		}

		// Verify we test all Constraint variants
		let tested_const = !const_test_cases.is_empty();
		let tested_oneof = !oneof_test_cases.is_empty();
		assert!(tested_const, "Const variant must be tested");
		assert!(tested_oneof, "OneOf variant must be tested");
	}

	#[test]
	fn test_constraint_pattern_str() {
		assert_eq!(Constraint::Const("value").pattern_str(), "const(\"value\")");
		assert_eq!(Constraint::OneOf(Cow::Borrowed(&["a", "b"])).pattern_str(), "oneof(...)");
	}

	#[test]
	fn test_urn_spec_builder_validation() {
		// Macro to reduce repetition in validation tests
		macro_rules! validate_pass {
			(spec: [$($spec_op:ident($($arg:expr),*)),+], values: [$($k:literal = $v:literal),*]) => {{
				let spec = UrnSpecBuilder::from("test")$(.$spec_op($($arg),*))+;
				let builder = UrnBuilder::default()$(.set($k, $v))*;
				assert!(spec.validate(&builder).is_ok());
			}};
		}

		macro_rules! validate_fail_missing {
			(spec: [$($spec_op:ident($($arg:expr),*)),+], values: [$($k:literal = $v:literal),*], field: $expected:literal) => {{
				let spec = UrnSpecBuilder::from("test")$(.$spec_op($($arg),*))+;
				let builder = UrnBuilder::default()$(.set($k, $v))*;
				assert!(matches!(
					spec.validate(&builder),
					Err(UrnValidationError::RequiredFieldMissing(field)) if field == $expected
				));
			}};
		}

		macro_rules! validate_fail_format {
			(spec: [$($spec_op:ident($($arg:expr),*)),+], values: [$($k:literal = $v:literal),*], field: $expected:literal) => {{
				let spec = UrnSpecBuilder::from("test")$(.$spec_op($($arg),*))+;
				let builder = UrnBuilder::default()$(.set($k, $v))*;
				assert!(matches!(
					spec.validate(&builder),
					Err(UrnValidationError::InvalidFormat { field, .. }) if field == $expected
				));
			}};
		}

		// Required field missing
		validate_fail_missing!(
			spec: [field_required("field1"), field_pattern("field1", Pattern::Alpha)],
			values: [],
			field: "field1"
		);

		// Optional field passes when missing
		validate_pass!(spec: [field_optional("field1")], values: []);

		// Pattern validation - valid
		validate_pass!(
			spec: [field_required("field1"), field_pattern("field1", Pattern::Alpha)],
			values: ["field1" = "abc"]
		);

		// Pattern validation - invalid
		validate_fail_format!(
			spec: [field_required("field1"), field_pattern("field1", Pattern::Alpha)],
			values: ["field1" = "abc123"],
			field: "field1"
		);

		// Const constraint - valid
		validate_pass!(
			spec: [field_required("field1"), field_const("field1", "expected")],
			values: ["field1" = "expected"]
		);

		// Const constraint - invalid
		validate_fail_format!(
			spec: [field_required("field1"), field_const("field1", "expected")],
			values: ["field1" = "unexpected"],
			field: "field1"
		);

		// OneOf constraint - valid
		validate_pass!(
			spec: [field_required("field1"), field_oneof("field1", &["a", "b", "c"])],
			values: ["field1" = "b"]
		);

		// OneOf constraint - invalid
		validate_fail_format!(
			spec: [field_required("field1"), field_oneof("field1", &["a", "b", "c"])],
			values: ["field1" = "d"],
			field: "field1"
		);
	}

	#[test]
	fn test_urn_spec_builder_build_nss() -> Result<(), UrnValidationError> {
		// Macro to reduce repetition in NSS building tests
		macro_rules! build_nss_pass {
			(spec: [$($spec_op:ident($($arg:expr),*)),+], values: [$($k:literal = $v:literal),+], expected: $exp:literal) => {{
				let spec = UrnSpecBuilder::from("test")$(.$spec_op($($arg),*))+;
				let builder = UrnBuilder::default()$(.set($k, $v))+;
				assert_eq!(spec.build_nss(&builder)?, $exp);
			}};
		}

		macro_rules! build_nss_fail {
			(spec: [$($spec_op:ident($($arg:expr),*)),*], values: [$($k:literal = $v:literal),*], error: $err_msg:literal) => {{
				#![allow(unused_mut)]
				let mut spec = UrnSpecBuilder::from("test");
				$(spec = spec.$spec_op($($arg),*);)*
				let mut builder = UrnBuilder::default();
				$(builder = builder.set($k, $v);)*
				assert!(matches!(
					spec.build_nss(&builder),
					Err(UrnValidationError::RequiredFieldMissing(msg)) if msg == $err_msg
				));
			}};
		}

		// Join format (default)
		build_nss_pass!(
			spec: [
				field_required("field1"),
				field_required("field2"),
				field_nss_separator("field2", "/"),
				field_optional("field3")
			],
			values: ["field1" = "value1", "field2" = "value2"],
			expected: "value1/value2"
		);

		// Custom format
		build_nss_pass!(
			spec: [
				field_required("field1"),
				field_required("field2"),
				field_optional("field3"),
				nss_format("{}:{}/{}")
			],
			values: ["field1" = "value1", "field2" = "value2", "field3" = "value3"],
			expected: "value1:value2/value3"
		);

		// Empty NSS
		build_nss_fail!(
			spec: [],
			values: [],
			error: "nss components"
		);

		// Format mismatch
		build_nss_fail!(
			spec: [field_required("field1"), field_required("field2"), nss_format("{}")],
			values: ["field1" = "value1", "field2" = "value2"],
			error: "nss components"
		);

		Ok(())
	}

	#[test]
	fn test_urn_spec_builder_field_operations() {
		let spec = UrnSpecBuilder::from("test")
			.field_required("field1")
			.field_optional("field2")
			.field_const("field1", "const_value")
			.field_oneof("field2", &["opt1", "opt2"])
			.field_pattern("field1", Pattern::Alpha)
			.field_nss_separator("field1", ":")
			.field_nss_separator("field2", "/");

		assert_eq!(spec.nid(), "test");
		assert_eq!(spec.fields().len(), 2);
		assert_eq!(spec.fields()[0].name, "field1");
		assert!(spec.fields()[0].required);
		assert_eq!(spec.fields()[0].constraints.len(), 1);
		assert_eq!(spec.fields()[0].pattern, Some(Pattern::Alpha));
		assert_eq!(spec.fields()[0].nss_separator, Some(":"));
		assert_eq!(spec.fields()[1].name, "field2");
		// field_oneof() sets field to required
		assert!(spec.fields()[1].required);
		assert_eq!(spec.fields()[1].constraints.len(), 1);
		assert_eq!(spec.fields()[1].nss_separator, Some("/"));
	}
}
