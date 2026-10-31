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

use crate::urn::{UrnBuilder, UrnComponents, UrnValidationError};

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

	/// Reads `nss` back into the components [`Self::build_nss`] builds it
	/// from, each borrowed from `nss`.
	///
	/// It reads the grammar that [`Self::build_nss`] writes, over the same
	/// fields and format:
	///
	/// - A join format splits `nss` at the separator of each field after the first.
	/// - A custom format reads each value up to the literal after its placeholder.
	/// - Each field in order takes the next value, and a required field always takes it.
	/// - An optional field takes the next value when a value remains for each
	///   later required field and, under a join format, when its own separator
	///   comes before the value.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::RequiredFieldMissing`] -- `nss` holds no value for a required field.
	/// - [`UrnValidationError::NssMismatch`] -- `nss` holds a value that no
	///   field takes, a value after a separator that is not its field's, or no
	///   literal of the custom format where the format places it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{UrnComponents, UrnSpecBuilder, UrnValidationError};
	///
	/// let spec = UrnSpecBuilder::from("example").field_required("kind").field_required("id");
	/// let spec = spec.field_nss_separator("id", "/");
	/// let components = spec.parse_nss("trace/abc-123")?;
	///
	/// assert_eq!(components.get_component("kind").map(|kind| kind.as_ref()), Some("trace"));
	/// assert_eq!(components.get_component("id").map(|id| id.as_ref()), Some("abc-123"));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn parse_nss<'a>(&self, nss: &'a str) -> Result<UrnBuilder<'a>, UrnValidationError> {
		match &self.nss_format {
			NssFormat::Join(default_separator) => {
				let values = self.joined_values(default_separator, nss);
				self.components_of(values, Some(*default_separator))
			}
			NssFormat::Custom(format) => {
				let values = Self::placeholder_values(format, nss)?;
				self.components_of(values, None)
			}
		}
	}

	/// The values of `nss`, which the join format of `default_separator`
	/// built, each beside the separator before it, in order.
	fn joined_values<'a>(&self, default_separator: &'static str, nss: &'a str) -> Vec<NssValue<'a>> {
		let mut values = Vec::new();
		let mut before = None;
		let mut start = 0usize;
		for (at, _) in nss.char_indices() {
			if at < start {
				continue;
			}

			let tail = nss.get(at..).unwrap_or_default();
			let Some(separator) = self.separator_at(default_separator, tail) else {
				continue;
			};

			// Each index is a character boundary of `nss`, and so is the end
			// of a separator that starts at one.
			let value = nss.get(start..at).unwrap_or_default();
			values.push(NssValue { separator: before, value });
			before = Some(separator);
			start = at.saturating_add(separator.len());
		}

		let last = nss.get(start..).unwrap_or_default();
		values.push(NssValue { separator: before, value: last });
		values
	}

	/// The longest separator that `tail` starts with, among the separators of
	/// the fields after the first under the join format of `default_separator`.
	///
	/// The separator of a field goes between it and the value before it, so
	/// the separators of the fields after the first split the NSS, and the
	/// longest of two that start at one place splits it there.
	fn separator_at(&self, default_separator: &'static str, tail: &str) -> Option<&'static str> {
		let later_fields = self.fields.iter().skip(1);
		let separators = later_fields.map(|field| field.nss_separator.unwrap_or(default_separator));
		let starting = separators.filter(|separator| !separator.is_empty() && tail.starts_with(*separator));
		starting.max_by_key(|separator| separator.len())
	}

	/// The values of `nss` at the placeholders of `format`, in order.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::NssMismatch`] -- `nss` lacks a literal of `format` where the format places it.
	fn placeholder_values<'a>(format: &str, nss: &'a str) -> Result<Vec<NssValue<'a>>, UrnValidationError> {
		let mut literals = format.split("{}");
		let lead = literals.next().unwrap_or_default();
		let mut rest = nss.strip_prefix(lead).ok_or(UrnValidationError::NssMismatch)?;

		// The last literal closes the NSS, and each other one ends the value
		// before it where it first occurs.
		let mut literals = literals.peekable();
		let mut values = Vec::new();
		while let Some(literal) = literals.next() {
			let is_last = literals.peek().is_none();
			let split = if is_last {
				rest.strip_suffix(literal).map(|value| (value, ""))
			} else {
				rest.split_once(literal)
			};

			let (value, after) = split.ok_or(UrnValidationError::NssMismatch)?;
			values.push(NssValue { separator: None, value });
			rest = after;
		}

		// A format of literals alone matches the NSS equal to it.
		if !rest.is_empty() {
			return Err(UrnValidationError::NssMismatch);
		}

		Ok(values)
	}

	/// The components that `values`, read from an NSS in order, give the
	/// fields of this spec, as [`Self::parse_nss`] states. `default_separator`
	/// is the separator of a join format, or `None` for a custom format.
	///
	/// # Errors
	///
	/// - The errors of [`Self::parse_nss`].
	fn components_of<'a>(
		&self,
		values: Vec<NssValue<'a>>,
		default_separator: Option<&'static str>,
	) -> Result<UrnBuilder<'a>, UrnValidationError> {
		let mut remaining = values.len();
		let mut later_required = self.fields.iter().filter(|field| field.required).count();
		let mut values = values.into_iter().peekable();

		let mut components = UrnBuilder::default().with_nid(self.nid);
		for field in &self.fields {
			if field.required {
				later_required = later_required.saturating_sub(1);
			}

			let separator = default_separator.map(|default| field.nss_separator.unwrap_or(default));
			let fits = values.peek().is_some_and(|value| value.follows(separator));
			let takes = field.required || (fits && remaining > later_required);
			if !takes {
				continue;
			}

			let value = values.next().ok_or(UrnValidationError::RequiredFieldMissing(field.name))?;
			if !value.follows(separator) {
				return Err(UrnValidationError::NssMismatch);
			}

			components.set_component(field.name, Cow::Borrowed(value.value));
			remaining = remaining.saturating_sub(1);
		}

		if values.next().is_some() {
			return Err(UrnValidationError::NssMismatch);
		}

		Ok(components)
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

/// One value of an NSS as it arrived, beside the separator before it.
struct NssValue<'a> {
	/// The separator before the value under a join format, or `None` for the
	/// first value and for each value of a custom format.
	separator: Option<&'static str>,
	/// The value, borrowed from the NSS.
	value: &'a str,
}

impl NssValue<'_> {
	/// Whether this value fills a field that `separator` goes before, or that
	/// a custom format places when `separator` is `None`.
	///
	/// The first value of a join and every value of a custom format fill any
	/// field, and each later value of a join fills a field of its separator.
	fn follows(&self, separator: Option<&str>) -> bool {
		match self.separator {
			None => true,
			Some(before) => separator == Some(before),
		}
	}
}

impl From<&'static str> for UrnSpecBuilder {
	fn from(nid: &'static str) -> Self {
		Self { nid, fields: Vec::new(), nss_format: NssFormat::Join(":") }
	}
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeMap;

	use crate::testing::TestResult;

	use super::*;

	/// The options that the oneof constraint of the cases lists.
	const OPTIONS: &[&str] = &["option1", "option2", "option3"];

	/// The letters that the oneof constraint of the cases lists.
	const LETTERS: &[&str] = &["a", "b", "c"];

	// Each case is a pattern and a value, beside whether the pattern admits
	// the value.
	crate::tb_cases! {
		fn a_pattern_judges_a_value_by_its_class((pattern, value, admitted): (Pattern, &str, bool)) {
			assert_eq!(pattern.matches(value), admitted);
		}
		cases {
			alpha_admits_abc => (Pattern::Alpha, "abc", true),
			alpha_admits_upper_xyz => (Pattern::Alpha, "XYZ", true),
			alpha_admits_hello => (Pattern::Alpha, "Hello", true),
			alpha_admits_upper_world => (Pattern::Alpha, "WORLD", true),
			alpha_refuses_abc123 => (Pattern::Alpha, "abc123", false),
			alpha_refuses_123 => (Pattern::Alpha, "123", false),
			alpha_refuses_abc_hyphen_xyz => (Pattern::Alpha, "abc-xyz", false),
			alpha_refuses_a1b => (Pattern::Alpha, "a1b", false),
			alpha_refuses_a_space => (Pattern::Alpha, "space here", false),
			numeric_admits_123 => (Pattern::Numeric, "123", true),
			numeric_admits_0 => (Pattern::Numeric, "0", true),
			numeric_admits_999 => (Pattern::Numeric, "999", true),
			numeric_admits_42 => (Pattern::Numeric, "42", true),
			numeric_refuses_abc => (Pattern::Numeric, "abc", false),
			numeric_refuses_12a => (Pattern::Numeric, "12a", false),
			numeric_refuses_1_hyphen_2 => (Pattern::Numeric, "1-2", false),
			numeric_refuses_12_dot_5 => (Pattern::Numeric, "12.5", false),
			alpha_numeric_admits_abc123 => (Pattern::AlphaNumeric, "abc123", true),
			alpha_numeric_admits_upper_xyz999 => (Pattern::AlphaNumeric, "XYZ999", true),
			alpha_numeric_admits_hello42 => (Pattern::AlphaNumeric, "Hello42", true),
			alpha_numeric_admits_upper_world0 => (Pattern::AlphaNumeric, "WORLD0", true),
			alpha_numeric_admits_abc => (Pattern::AlphaNumeric, "abc", true),
			alpha_numeric_admits_123 => (Pattern::AlphaNumeric, "123", true),
			alpha_numeric_refuses_abc_hyphen_xyz => (Pattern::AlphaNumeric, "abc-xyz", false),
			alpha_numeric_refuses_a_space => (Pattern::AlphaNumeric, "space here", false),
			alpha_numeric_refuses_12_dot_5 => (Pattern::AlphaNumeric, "12.5", false),
			alpha_numeric_refuses_a_underscore_b => (Pattern::AlphaNumeric, "a_b", false),
			alpha_numeric_hyphen_admits_abc_hyphen_123 => (Pattern::AlphaNumericHyphen, "abc-123", true),
			alpha_numeric_hyphen_admits_xyz_hyphen_y => (Pattern::AlphaNumericHyphen, "xyz-y", true),
			alpha_numeric_hyphen_admits_test_case => (Pattern::AlphaNumericHyphen, "test-case", true),
			alpha_numeric_hyphen_admits_kebab_case_id => (Pattern::AlphaNumericHyphen, "kebab-case-id", true),
			alpha_numeric_hyphen_admits_abc => (Pattern::AlphaNumericHyphen, "abc", true),
			alpha_numeric_hyphen_admits_123 => (Pattern::AlphaNumericHyphen, "123", true),
			alpha_numeric_hyphen_refuses_abc_underscore_xyz => (Pattern::AlphaNumericHyphen, "abc_xyz", false),
			alpha_numeric_hyphen_refuses_a_space => (Pattern::AlphaNumericHyphen, "space here", false),
			alpha_numeric_hyphen_refuses_12_dot_5 => (Pattern::AlphaNumericHyphen, "12.5", false),
		}
	}

	// One case for each `Pattern` variant, beside the regex of its class.
	crate::tb_cases! {
		fn pattern_str_writes_the_regex_of_its_class((pattern, regex): (Pattern, &str)) {
			assert_eq!(pattern.pattern_str(), regex);
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

	// One case for each `Pattern` variant. Each case compares two oracles,
	// `matches` and the regex of `pattern_str`, over every probe.
	crate::tb_cases! {
		fn a_pattern_matches_the_rule_of_its_pattern_str(pattern: Pattern) {
			let disagreements = disagreements(pattern);
			assert_eq!(disagreements, Vec::<&str>::new());
		}
		cases {
			alpha => Pattern::Alpha,
			numeric => Pattern::Numeric,
			alpha_numeric => Pattern::AlphaNumeric,
			alpha_numeric_hyphen => Pattern::AlphaNumericHyphen,
		}
	}

	// The cases cover both `Constraint` variants. Each is a constraint and a
	// value, beside whether the constraint admits the value.
	crate::tb_cases! {
		fn a_constraint_judges_a_value_by_its_values((constraint, value, admitted): (Constraint, &str, bool)) {
			assert_eq!(constraint.matches(value), admitted);
		}
		cases {
			const_admits_its_value => (Constraint::Const("expected"), "expected", true),
			const_refuses_another_value => (Constraint::Const("expected"), "unexpected", false),
			const_refuses_its_value_in_title_case => (Constraint::Const("expected"), "Expected", false),
			const_refuses_its_value_in_upper_case => (Constraint::Const("expected"), "EXPECTED", false),
			const_refuses_the_empty_value => (Constraint::Const("expected"), "", false),
			options_admit_option1 => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "option1", true),
			options_admit_option2 => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "option2", true),
			options_admit_option3 => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "option3", true),
			options_refuse_option4 => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "option4", false),
			options_refuse_an_option_in_title_case => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "Option1", false),
			options_refuse_an_option_in_upper_case => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "OPTION1", false),
			options_refuse_the_empty_value => (Constraint::OneOf(Cow::Borrowed(OPTIONS)), "", false),
			letters_admit_a => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "a", true),
			letters_admit_b => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "b", true),
			letters_admit_c => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "c", true),
			letters_refuse_d => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "d", false),
			letters_refuse_an_upper_case_letter => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "A", false),
			letters_refuse_two_letters => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "ab", false),
			letters_refuse_the_empty_value => (Constraint::OneOf(Cow::Borrowed(LETTERS)), "", false),
		}
	}

	// One case for each `Constraint` variant, beside the pattern string it
	// writes.
	crate::tb_cases! {
		fn a_constraint_writes_its_pattern_str((constraint, written): (Constraint, &str)) {
			assert_eq!(constraint.pattern_str(), written);
		}
		cases {
			const_value => (Constraint::Const("value"), "const(\"value\")"),
			one_of => (Constraint::OneOf(Cow::Borrowed(&["a", "b"])), "oneof(...)"),
		}
	}

	/// Returns a spec of one required field under the alpha pattern.
	fn alpha_spec() -> UrnSpecBuilder {
		UrnSpecBuilder::from("test")
			.field_required("field1")
			.field_pattern("field1", Pattern::Alpha)
	}

	/// Returns a spec of one required field whose value is the const
	/// `expected`.
	fn const_spec() -> UrnSpecBuilder {
		UrnSpecBuilder::from("test")
			.field_required("field1")
			.field_const("field1", "expected")
	}

	/// Returns a spec of one required field whose value is one of
	/// [`LETTERS`].
	fn oneof_spec() -> UrnSpecBuilder {
		UrnSpecBuilder::from("test")
			.field_required("field1")
			.field_oneof("field1", LETTERS)
	}

	/// A spec and the components of a URN, beside the outcome that a call of
	/// the spec gives on them.
	type SpecCase<T> = (fn() -> UrnSpecBuilder, &'static [(&'static str, &'static str)], T);

	// Each case is a spec and the components of a URN, beside the verdict of
	// `validate`. A constraint names no pattern, and a pattern names itself.
	crate::tb_cases! {
		fn a_spec_validates_the_components_of_a_urn(
			(spec, components, verdict): SpecCase<Result<(), UrnValidationError>>
		) {
			let validated = spec().validate(&UrnBuilder::default().holding(components));

			assert_eq!(validated, verdict);
		}
		cases {
			admits_an_absent_optional_field => (|| UrnSpecBuilder::from("test").field_optional("field1"), &[], Ok(())),
			/// A later `field_optional` makes a required field optional, so a
			/// URN without the field validates.
			admits_an_absent_field_made_optional_after_required => (
				|| UrnSpecBuilder::from("test").field_required("field1").field_optional("field1"),
				&[],
				Ok(()),
			),
			refuses_an_absent_required_field => (
				alpha_spec,
				&[],
				Err(UrnValidationError::RequiredFieldMissing("field1")),
			),
			admits_a_value_of_its_pattern => (alpha_spec, &[("field1", "abc")], Ok(())),
			refuses_a_value_outside_its_pattern => (
				alpha_spec,
				&[("field1", "abc123")],
				Err(UrnValidationError::InvalidFormat { field: "field1", pattern: Some(Pattern::Alpha) }),
			),
			admits_its_const_value => (const_spec, &[("field1", "expected")], Ok(())),
			refuses_another_value_than_its_const => (
				const_spec,
				&[("field1", "unexpected")],
				Err(UrnValidationError::InvalidFormat { field: "field1", pattern: None }),
			),
			admits_one_of_its_values => (oneof_spec, &[("field1", "b")], Ok(())),
			refuses_a_value_outside_its_values => (
				oneof_spec,
				&[("field1", "d")],
				Err(UrnValidationError::InvalidFormat { field: "field1", pattern: None }),
			),
		}
	}

	// Each case is a spec and the components of a URN, beside the NSS that
	// `build_nss` writes of them or its refusal. A spec refuses components
	// that fill no place of its format, or more places than the format has,
	// and names the NSS components.
	crate::tb_cases! {
		fn build_nss_writes_the_format_of_its_spec(
			(spec, components, nss): SpecCase<Result<String, UrnValidationError>>
		) {
			let built = spec().build_nss(&UrnBuilder::default().holding(components));
			assert_eq!(built, nss);
		}
		cases {
			/// The default join format applies the separator of each field.
			a_join_with_a_separator_of_its_field => (
				|| {
					let spec = UrnSpecBuilder::from("test").field_required("field1").field_required("field2");
					spec.field_nss_separator("field2", "/").field_optional("field3")
				},
				&[("field1", "value1"), ("field2", "value2")],
				Ok("value1/value2".into()),
			),
			/// A custom format places each value at its placeholder.
			a_custom_format => (
				|| {
					let spec = UrnSpecBuilder::from("test").field_required("field1").field_required("field2");
					spec.field_optional("field3").nss_format("{}:{}/{}")
				},
				&[("field1", "value1"), ("field2", "value2"), ("field3", "value3")],
				Ok("value1:value2/value3".into()),
			),
			/// A literal ahead of the first placeholder leads the NSS.
			a_custom_format_with_a_leading_literal => (
				|| UrnSpecBuilder::from("test").field_required("field1").nss_format("lead-{}"),
				&[("field1", "value1")],
				Ok("lead-value1".into()),
			),
			no_field => (
				|| UrnSpecBuilder::from("test"),
				&[],
				Err(UrnValidationError::RequiredFieldMissing("nss components")),
			),
			fewer_placeholders_than_values => (
				|| UrnSpecBuilder::from("test").field_required("field1").field_required("field2").nss_format("{}"),
				&[("field1", "value1"), ("field2", "value2")],
				Err(UrnValidationError::RequiredFieldMissing("nss components")),
			),
		}
	}

	/// A join spec of a required field, a required field after `/`, and an
	/// optional field.
	fn join_spec() -> UrnSpecBuilder {
		let spec = UrnSpecBuilder::from("test").field_required("kind").field_required("id");
		spec.field_nss_separator("id", "/").field_optional("tag")
	}

	/// Returns a join spec of the two required fields `a` and `b`.
	fn ab_spec() -> UrnSpecBuilder {
		UrnSpecBuilder::from("test").field_required("a").field_required("b")
	}

	/// Returns each component that `components` holds, by key.
	fn components_of<'b>(components: &'b UrnBuilder<'_>) -> BTreeMap<&'static str, &'b str> {
		components.iter().map(|(key, value)| (key, value.as_ref())).collect()
	}

	// Each case is a spec and an NSS, beside the components that `parse_nss`
	// reads back from it. A field the NSS leaves no value for is absent.
	crate::tb_cases! {
		fn parse_nss_reads_back_its_components(
			(spec, nss, expected): (fn() -> UrnSpecBuilder, &str, BTreeMap<&str, &str>)
		) -> TestResult {
			let components = spec().parse_nss(nss)?;
			assert_eq!(components_of(&components), expected);
			Ok(())
		}
		cases {
			a_join => (join_spec, "trace/abc-123", BTreeMap::from([("kind", "trace"), ("id", "abc-123")])),
			a_custom_format => (
				|| ab_spec().field_optional("c").nss_format("{}:{}/{}"),
				"value1:value2/value3",
				BTreeMap::from([("a", "value1"), ("b", "value2"), ("c", "value3")]),
			),
			/// An optional field before a required one leaves it the one value.
			an_optional_field_before_a_required_one => (
				|| UrnSpecBuilder::from("test").field_optional("region").field_required("host"),
				"h1",
				BTreeMap::from([("host", "h1")]),
			),
			/// Of two optional fields beside one spare value, the first in
			/// field order takes it.
			two_optional_fields_and_one_spare_value => (
				|| {
					let spec = UrnSpecBuilder::from("test").field_optional("region").field_optional("zone");
					spec.field_required("host")
				},
				"eu:h1",
				BTreeMap::from([("region", "eu"), ("host", "h1")]),
			),
			/// An optional field takes no value that follows the separator of
			/// another field.
			an_optional_field_beside_another_fields_separator => (
				|| {
					let spec = UrnSpecBuilder::from("test").field_required("kind").field_optional("tag");
					let spec = spec.field_nss_separator("tag", ".").field_required("id");
					spec.field_nss_separator("id", "/")
				},
				"trace/abc",
				BTreeMap::from([("kind", "trace"), ("id", "abc")]),
			),
		}
	}

	// Each case is a spec and an NSS, beside the refusal of `parse_nss`.
	crate::tb_cases! {
		fn parse_nss_refuses_an_nss_outside_its_spec(
			(spec, nss, refusal): (fn() -> UrnSpecBuilder, &str, UrnValidationError)
		) {
			let parsed = spec().parse_nss(nss);
			assert_eq!(parsed.err(), Some(refusal));
		}
		cases {
			a_value_that_no_field_takes => (ab_spec, "x:y:z", UrnValidationError::NssMismatch),
			a_value_short_of_a_required_field => (ab_spec, "x", UrnValidationError::RequiredFieldMissing("b")),
			no_literal_of_its_custom_format => (
				|| ab_spec().nss_format("{}/{}"),
				"x:y",
				UrnValidationError::NssMismatch,
			),
		}
	}

	/// Returns a spec of `field1` and `field2`, each with every setting that a
	/// call makes.
	fn operated_spec() -> UrnSpecBuilder {
		UrnSpecBuilder::from("test")
			.field_required("field1")
			.field_optional("field2")
			.field_const("field1", "const_value")
			.field_oneof("field2", &["opt1", "opt2"])
			.field_pattern("field1", Pattern::Alpha)
			.field_nss_separator("field1", ":")
			.field_nss_separator("field2", "/")
	}

	/// Returns the field of `spec` that `name` names.
	fn field_named<'s>(spec: &'s UrnSpecBuilder, name: &str) -> &'s FieldConfig {
		let found = spec.fields().iter().find(|field| field.name == name);
		found.expect("the spec declares the field")
	}

	/// Returns the names of the fields of `spec`, in order.
	fn field_names(spec: &UrnSpecBuilder) -> Vec<&'static str> {
		spec.fields().iter().map(|field| field.name).collect()
	}

	/// A spec keeps the NID it was built from.
	#[test]
	fn a_spec_keeps_its_nid() {
		let spec = operated_spec();
		assert_eq!(spec.nid(), "test");
	}

	/// A spec keeps one field per name, in the order of their declarations.
	#[test]
	fn a_spec_keeps_its_fields_in_declaration_order() {
		let spec = operated_spec();
		assert_eq!(field_names(&spec), ["field1", "field2"]);
	}

	/// Whether a field is required, beside its pattern and its separator.
	type Settings = (bool, Option<Pattern>, Option<&'static str>);

	/// A check that reads the constraints of one field.
	type ConstraintCheck = fn(&[Constraint]) -> bool;

	// Each case is a field of the operated spec, beside its constraint and
	// whether it is required, its pattern, and its separator.
	crate::tb_cases! {
		fn a_field_keeps_the_settings_its_calls_made(
			(name, constraint_is, settings): (&str, ConstraintCheck, Settings)
		) {
			let spec = operated_spec();
			let field = field_named(&spec, name);
			assert!(constraint_is(&field.constraints));
			assert_eq!((field.required, field.pattern, field.nss_separator), settings);
		}
		cases {
			field1 => (
				"field1",
				|constraints| matches!(constraints, [Constraint::Const("const_value")]),
				(true, Some(Pattern::Alpha), Some(":")),
			),
			/// `field_oneof` makes the optional `field2` required.
			field2 => (
				"field2",
				|constraints| {
					matches!(constraints, [Constraint::OneOf(options)] if options.as_ref() == ["opt1", "opt2"])
				},
				(true, None, Some("/")),
			),
		}
	}
}
