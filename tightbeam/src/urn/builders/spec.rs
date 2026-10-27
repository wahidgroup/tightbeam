//! The `UrnSpecBuilder`, which builds a URN specification programmatically.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
	borrow::Cow,
	string::{String, ToString},
	vec::Vec,
};
#[cfg(feature = "std")]
use std::borrow::Cow;

use crate::urn::{UrnComponents, UrnValidationError};

/// A validation pattern for a field value.
///
/// Each pattern admits a non-empty run of one ASCII character class:
///
/// - A field value fills one part of the NSS, and an empty part names nothing, so an empty value fails.
/// - The NSS grammar of RFC 8141 § 2 admits letters of both cases, so a class that holds letters holds both.
///
/// # Sources
///
/// - RFC 8141, Uniform Resource Names (URNs), § 2, April 2017:
///   <https://www.rfc-editor.org/rfc/rfc8141#section-2>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
	/// One or more ASCII letters, as `[a-zA-Z]+`.
	Alpha,
	/// One or more ASCII digits, as `[0-9]+`.
	Numeric,
	/// One or more ASCII letters and digits, as `[a-zA-Z0-9]+`.
	AlphaNumeric,
	/// One or more ASCII letters, digits, and hyphens, as `[a-zA-Z0-9-]+`.
	AlphaNumericHyphen,
}

impl Pattern {
	/// Whether `value` is non-empty and every character of it is in the class
	/// of this pattern.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::builders::spec::Pattern;
	///
	/// assert!(Pattern::AlphaNumericHyphen.matches("Trace-7"));
	/// assert!(!Pattern::AlphaNumericHyphen.matches(""));
	/// ```
	pub fn matches(&self, value: impl AsRef<str>) -> bool {
		let value = value.as_ref();
		let in_class = value.chars().all(|c| self.admits(c));
		!value.is_empty() && in_class
	}

	/// Whether `c` is in the character class of this pattern.
	fn admits(&self, c: char) -> bool {
		match self {
			Pattern::Alpha => c.is_ascii_alphabetic(),
			Pattern::Numeric => c.is_ascii_digit(),
			Pattern::AlphaNumeric => c.is_ascii_alphanumeric(),
			Pattern::AlphaNumericHyphen => c.is_ascii_alphanumeric() || c == '-',
		}
	}

	/// The regex that states the rule of [`Pattern::matches`], for error
	/// messages.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::builders::spec::Pattern;
	///
	/// assert_eq!(Pattern::AlphaNumericHyphen.pattern_str(), "^[a-zA-Z0-9-]+$");
	/// ```
	pub fn pattern_str(&self) -> &'static str {
		match self {
			Pattern::Alpha => "^[a-zA-Z]+$",
			Pattern::Numeric => "^[0-9]+$",
			Pattern::AlphaNumeric => "^[a-zA-Z0-9]+$",
			Pattern::AlphaNumericHyphen => "^[a-zA-Z0-9-]+$",
		}
	}
}

/// A validation constraint for a field.
#[derive(Debug, Clone)]
pub enum Constraint {
	/// The field must equal a constant value.
	Const(&'static str),
	/// The field must be one of the given values.
	OneOf(Cow<'static, [&'static str]>),
}

impl Constraint {
	/// Whether `value` meets this constraint.
	pub fn matches(&self, value: impl AsRef<str>) -> bool {
		let value = value.as_ref();
		match self {
			Constraint::Const(expected) => value == *expected,
			Constraint::OneOf(options) => options.contains(&value),
		}
	}

	/// The constraint pattern string for error messages.
	pub fn pattern_str(&self) -> &'static str {
		match self {
			Constraint::Const(_) => "const(\"value\")",
			Constraint::OneOf(_) => "oneof(...)",
		}
	}
}

/// The configuration of one field in a URN specification.
#[derive(Debug, Clone)]
pub struct FieldConfig {
	/// The name of the field.
	pub name: &'static str,
	/// Whether the field is required.
	pub required: bool,
	/// The validation constraints that the value must meet.
	pub constraints: Vec<Constraint>,
	/// The validation pattern, checked apart from the constraints.
	pub pattern: Option<Pattern>,
	/// The NSS separator that goes before this field, such as ":" or "/".
	pub nss_separator: Option<&'static str>,
}

impl FieldConfig {
	fn new(name: &'static str, required: bool) -> Self {
		Self { name, required, constraints: Vec::new(), pattern: None, nss_separator: None }
	}
}

/// The format that builds the NSS from the field values.
#[derive(Debug, Clone)]
pub enum NssFormat {
	/// The field values joined by this default separator.
	Join(&'static str),
	/// A format string whose `{}` placeholders take the field values in order.
	Custom(String),
}

/// A builder that constructs a URN specification programmatically.
#[derive(Debug, Clone)]
pub struct UrnSpecBuilder {
	/// The Namespace Identifier.
	nid: &'static str,
	/// The field configurations, in order.
	fields: Vec<FieldConfig>,
	/// The format that joins the field values into the NSS.
	nss_format: NssFormat,
}

impl UrnSpecBuilder {
	/// Sets whether the field named `name` is required, creates the field when
	/// it is absent, and applies `edit` to it.
	fn edit_field(&mut self, name: &'static str, required: bool, edit: impl FnOnce(&mut FieldConfig)) {
		let existing = self.fields.iter_mut().find(|f| f.name == name);
		match existing {
			Some(field) => {
				field.required = required;
				edit(field);
			}
			None => {
				let mut field = FieldConfig::new(name, required);
				edit(&mut field);
				self.fields.push(field);
			}
		}
	}

	/// Adds a required field named `name`, or makes an existing one required.
	pub fn field_required(mut self, name: &'static str) -> Self {
		self.edit_field(name, true, |_| {});
		self
	}

	/// Adds an optional field named `name`, or makes an existing one optional.
	pub fn field_optional(mut self, name: &'static str) -> Self {
		self.edit_field(name, false, |_| {});
		self
	}

	/// Adds a const constraint to the field named `name`, which also makes it
	/// required.
	pub fn field_const(mut self, name: &'static str, value: &'static str) -> Self {
		self.edit_field(name, true, |field| field.constraints.push(Constraint::Const(value)));
		self
	}

	/// Adds a oneof constraint to the field named `name`, which also makes it
	/// required.
	pub fn field_oneof(mut self, name: &'static str, options: &'static [&'static str]) -> Self {
		let constraint = Constraint::OneOf(Cow::Borrowed(options));
		self.edit_field(name, true, |field| field.constraints.push(constraint));
		self
	}

	/// Sets the pattern of the field named `name`, which also makes it
	/// required.
	pub fn field_pattern(mut self, name: &'static str, pattern: Pattern) -> Self {
		self.edit_field(name, true, |field| field.pattern = Some(pattern));
		self
	}

	/// Sets the NSS separator of the field named `name`, when that field
	/// exists.
	pub fn field_nss_separator(mut self, name: &'static str, separator: &'static str) -> Self {
		if let Some(field) = self.fields.iter_mut().find(|f| f.name == name) {
			field.nss_separator = Some(separator);
		}

		self
	}

	/// Sets a custom NSS format string, such as "{}:{}/{}".
	pub fn nss_format(mut self, format: impl AsRef<str>) -> Self {
		self.nss_format = NssFormat::Custom(format.as_ref().to_string());
		self
	}

	/// Validates `components` against this spec.
	pub fn validate<'a>(&self, components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError> {
		for field in &self.fields {
			if field.required && components.get_component(field.name).is_none() {
				return Err(UrnValidationError::RequiredFieldMissing(field.name));
			}

			if let Some(value) = components.get_component(field.name) {
				let value_str = value.as_ref();

				for constraint in &field.constraints {
					if !constraint.matches(value_str) {
						return Err(UrnValidationError::InvalidFormat { field: field.name, pattern: None });
					}
				}

				if let Some(pattern) = field.pattern {
					if !pattern.matches(value_str) {
						return Err(UrnValidationError::InvalidFormat { field: field.name, pattern: Some(pattern) });
					}
				}
			}
		}

		Ok(())
	}

	/// Builds the NSS from `components` with this spec's format.
	pub fn build_nss<'a>(&self, components: &dyn UrnComponents<'a>) -> Result<String, UrnValidationError> {
		match &self.nss_format {
			NssFormat::Join(default_separator) => {
				let mut nss_parts = Vec::new();
				for field in &self.fields {
					if let Some(value) = components.get_component(field.name) {
						// Each value after the first one present takes a
						// separator before it.
						if !nss_parts.is_empty() {
							// The field's own separator wins over the default.
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
				// Each required field and each present optional field gives a
				// value, in field order.
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

				// Each placeholder takes exactly one value.
				let placeholder_count = format_str.matches("{}").count();
				if placeholder_count != field_values.len() {
					return Err(UrnValidationError::RequiredFieldMissing("nss components"));
				}

				// The check above gives each placeholder one value, so each
				// value fills the gap between two parts of the format, and one
				// buffer sized up front holds the whole NSS.
				let values_len = field_values.iter().map(|value| value.len()).fold(0, usize::saturating_add);
				let mut nss = String::with_capacity(format_str.len().saturating_add(values_len));
				let mut parts = format_str.split("{}");
				nss.push_str(parts.next().unwrap_or_default());
				for (value, part) in field_values.into_iter().zip(parts) {
					nss.push_str(value);
					nss.push_str(part);
				}

				Ok(nss)
			}
		}
	}

	/// The NID of this spec.
	pub fn nid(&self) -> &'static str {
		self.nid
	}

	/// The field configurations, in order.
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
	use crate::urn::UrnBuilder;

	use super::*;

	/// The values of `valid` that `admits` refuses, beside the values of
	/// `invalid` that it admits, so one case reports every value it misreads.
	fn misread<'v>(
		admits: impl Fn(&str) -> bool,
		valid: &[&'v str],
		invalid: &[&'v str],
	) -> (Vec<&'v str>, Vec<&'v str>) {
		let refused = valid.iter().copied().filter(|value| !admits(value)).collect();
		let admitted = invalid.iter().copied().filter(|value| admits(value)).collect();
		(refused, admitted)
	}

	/// One pattern, the values it admits, and the values it refuses.
	type PatternCase = (Pattern, &'static [&'static str], &'static [&'static str]);

	crate::tb_cases! {
		fn test_pattern_matches((pattern, valid, invalid): PatternCase) {
			let misses = misread(|value| pattern.matches(value), valid, invalid);

			assert_eq!(misses, (Vec::new(), Vec::new()), "Pattern {pattern:?} misreads these values");
		}
		cases {
			alpha => (
				Pattern::Alpha,
				&["abc", "XYZ", "Hello", "WORLD"],
				&["abc123", "123", "abc-xyz", "a1b", "space here"],
			),
			numeric => (Pattern::Numeric, &["123", "0", "999", "42"], &["abc", "12a", "1-2", "12.5"]),
			alpha_numeric => (
				Pattern::AlphaNumeric,
				&["abc123", "XYZ999", "Hello42", "WORLD0", "abc", "123"],
				&["abc-xyz", "space here", "12.5", "a_b"],
			),
			alpha_numeric_hyphen => (
				Pattern::AlphaNumericHyphen,
				&["abc-123", "xyz-y", "test-case", "kebab-case-id", "abc", "123"],
				&["abc_xyz", "space here", "12.5"],
			),
		}
	}

	// One case for each `Pattern` variant.
	crate::tb_cases! {
		fn test_pattern_str((pattern, expected): (Pattern, &str)) {
			assert_eq!(pattern.pattern_str(), expected, "Pattern {pattern:?} should have pattern_str '{expected}'");
		}
		cases {
			alpha => (Pattern::Alpha, "^[a-zA-Z]+$"),
			numeric => (Pattern::Numeric, "^[0-9]+$"),
			alpha_numeric => (Pattern::AlphaNumeric, "^[a-zA-Z0-9]+$"),
			alpha_numeric_hyphen => (Pattern::AlphaNumericHyphen, "^[a-zA-Z0-9-]+$"),
		}
	}

	/// Values that fall on each side of every class edge, the empty value
	/// among them.
	const PROBES: [&str; 11] = ["", "a", "Z", "7", "-", "aZ7", "aZ7-", "a_b", "a b", "1.5", "\u{e9}"];

	/// The regex form that `pattern_str` writes, `^[class]q$`, read as the
	/// rule it states.
	struct BracketRegex {
		/// The inclusive character ranges of the class, a lone character as a
		/// range of one.
		ranges: Vec<(char, char)>,
		/// The least length the quantifier admits, 1 for `+` and 0 for `*`.
		min_len: usize,
	}

	impl BracketRegex {
		/// Reads `regex`, which must have the `^[class]q$` form.
		fn parse(regex: &str) -> Self {
			let body = regex
				.strip_prefix("^[")
				.and_then(|rest| rest.strip_suffix('$'))
				.expect("a `^[class]q$` regex");
			let (class, quantifier) = body.split_once(']').expect("a closed class");
			let class: Vec<char> = class.chars().collect();
			let min_len = match quantifier {
				"+" => 1,
				"*" => 0,
				other => panic!("the quantifier {other:?} is neither `+` nor `*`"),
			};

			Self { ranges: Self::ranges(&class), min_len }
		}

		/// The ranges of a class body such as `a-zA-Z0-9-`, where a hyphen
		/// between two characters makes a range.
		fn ranges(class: &[char]) -> Vec<(char, char)> {
			match class {
				[] => Vec::new(),
				[low, '-', high, rest @ ..] => [vec![(*low, *high)], Self::ranges(rest)].concat(),
				[single, rest @ ..] => [vec![(*single, *single)], Self::ranges(rest)].concat(),
			}
		}

		/// Whether the regex admits `value`.
		fn admits(&self, value: &str) -> bool {
			let in_class = |c: char| self.ranges.iter().any(|&(low, high)| (low..=high).contains(&c));
			value.chars().count() >= self.min_len && value.chars().all(in_class)
		}
	}

	/// The probes on which `pattern.matches` and the regex of
	/// `pattern.pattern_str` disagree.
	fn disagreements(pattern: Pattern) -> Vec<&'static str> {
		let regex = BracketRegex::parse(pattern.pattern_str());
		PROBES
			.into_iter()
			.filter(|probe| pattern.matches(probe) != regex.admits(probe))
			.collect()
	}

	#[test]
	fn alpha_matches_the_rule_of_its_pattern_str() {
		let disagreements = disagreements(Pattern::Alpha);

		assert_eq!(disagreements, Vec::<&str>::new());
	}

	#[test]
	fn numeric_matches_the_rule_of_its_pattern_str() {
		let disagreements = disagreements(Pattern::Numeric);

		assert_eq!(disagreements, Vec::<&str>::new());
	}

	#[test]
	fn alpha_numeric_matches_the_rule_of_its_pattern_str() {
		let disagreements = disagreements(Pattern::AlphaNumeric);

		assert_eq!(disagreements, Vec::<&str>::new());
	}

	#[test]
	fn alpha_numeric_hyphen_matches_the_rule_of_its_pattern_str() {
		let disagreements = disagreements(Pattern::AlphaNumericHyphen);

		assert_eq!(disagreements, Vec::<&str>::new());
	}

	// The cases cover both `Constraint` variants. Each is the constraint,
	// the values it admits, and the values it refuses.
	crate::tb_cases! {
		fn test_constraint_matches((constraint, valid, invalid): (Constraint, &[&str], &[&str])) {
			let misses = misread(|value| constraint.matches(value), valid, invalid);

			assert_eq!(misses, (Vec::new(), Vec::new()), "{constraint:?} misreads these values");
		}
		cases {
			const_value => (
				Constraint::Const("expected"),
				&["expected"],
				&["unexpected", "Expected", "EXPECTED", ""],
			),
			one_of_options => (
				Constraint::OneOf(Cow::Borrowed(&["option1", "option2", "option3"])),
				&["option1", "option2", "option3"],
				&["option4", "Option1", "OPTION1", ""],
			),
			one_of_letters => (
				Constraint::OneOf(Cow::Borrowed(&["a", "b", "c"])),
				&["a", "b", "c"],
				&["d", "A", "ab", ""],
			),
		}
	}

	#[test]
	fn test_constraint_pattern_str() {
		assert_eq!(Constraint::Const("value").pattern_str(), "const(\"value\")");
		assert_eq!(Constraint::OneOf(Cow::Borrowed(&["a", "b"])).pattern_str(), "oneof(...)");
	}

	/// A later `field_optional` makes a required field optional, so a URN
	/// without the field validates.
	#[test]
	fn a_field_made_optional_after_required_may_be_absent() -> Result<(), UrnValidationError> {
		let spec = UrnSpecBuilder::from("test").field_required("field1").field_optional("field1");
		let builder = UrnBuilder::default();

		spec.validate(&builder)
	}

	#[test]
	fn test_urn_spec_builder_validation() {
		// These macros build the spec and the components of each case.
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

		// A missing required field fails.
		validate_fail_missing!(
			spec: [field_required("field1"), field_pattern("field1", Pattern::Alpha)],
			values: [],
			field: "field1"
		);

		// A missing optional field passes.
		validate_pass!(spec: [field_optional("field1")], values: []);

		// A value that fits the pattern passes.
		validate_pass!(
			spec: [field_required("field1"), field_pattern("field1", Pattern::Alpha)],
			values: ["field1" = "abc"]
		);

		// A value outside the pattern fails.
		validate_fail_format!(
			spec: [field_required("field1"), field_pattern("field1", Pattern::Alpha)],
			values: ["field1" = "abc123"],
			field: "field1"
		);

		// A value equal to the const passes.
		validate_pass!(
			spec: [field_required("field1"), field_const("field1", "expected")],
			values: ["field1" = "expected"]
		);

		// Another value fails the const.
		validate_fail_format!(
			spec: [field_required("field1"), field_const("field1", "expected")],
			values: ["field1" = "unexpected"],
			field: "field1"
		);

		// A listed value passes the oneof.
		validate_pass!(
			spec: [field_required("field1"), field_oneof("field1", &["a", "b", "c"])],
			values: ["field1" = "b"]
		);

		// An unlisted value fails the oneof.
		validate_fail_format!(
			spec: [field_required("field1"), field_oneof("field1", &["a", "b", "c"])],
			values: ["field1" = "d"],
			field: "field1"
		);
	}

	#[test]
	fn test_urn_spec_builder_build_nss() -> Result<(), UrnValidationError> {
		// These macros build the spec and the components of each NSS case.
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

		// The default join format applies a field's own separator.
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

		// A custom format places each value at its placeholder.
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

		// A spec with no field fails to build an NSS.
		build_nss_fail!(
			spec: [],
			values: [],
			error: "nss components"
		);

		// A format with fewer placeholders than values fails.
		build_nss_fail!(
			spec: [field_required("field1"), field_required("field2"), nss_format("{}")],
			values: ["field1" = "value1", "field2" = "value2"],
			error: "nss components"
		);

		Ok(())
	}

	/// A literal ahead of the first placeholder leads the NSS.
	#[test]
	fn a_custom_format_keeps_its_leading_literal() -> Result<(), UrnValidationError> {
		let spec = UrnSpecBuilder::from("test").field_required("field1").nss_format("lead-{}");
		let builder = UrnBuilder::default().set("field1", "value1");

		assert_eq!(spec.build_nss(&builder)?, "lead-value1");
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
		// `field_oneof` makes the field required.
		assert!(spec.fields()[1].required);
		assert_eq!(spec.fields()[1].constraints.len(), 1);
		assert_eq!(spec.fields()[1].nss_separator, Some("/"));
	}
}
