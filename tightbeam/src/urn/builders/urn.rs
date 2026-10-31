//! The URN builder, which validates each URN it constructs.

use crate::urn::{Urn, UrnComponents, UrnSpec, UrnValidationError};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, boxed::Box, collections::BTreeMap as HashMap, vec::Vec};
#[cfg(feature = "std")]
use std::{borrow::Cow, boxed::Box, collections::HashMap};

#[cfg(feature = "builder")]
use crate::builder::TypeBuilder;

/// The closure that builds the NSS of a spec on a builder.
type SpecBuilderFn<'a> = dyn FnOnce(&mut UrnBuilder<'a>) -> Result<Cow<'static, str>, UrnValidationError> + 'a;

/// A builder that constructs URNs and validates them.
#[derive(Default)]
pub struct UrnBuilder<'a> {
	/// The Namespace Identifier (NID) of the URN.
	pub(crate) nid: Option<Cow<'a, str>>,

	/// The hierarchical components that the NSS is constructed from.
	pub(crate) components: HashMap<&'static str, Cow<'a, str>>,

	/// The mode that builds the NSS, from a direct NSS or from a spec.
	nss_mode: NssMode<'a>,
}

/// The one mode of NSS construction that a builder holds.
#[derive(Default)]
enum NssMode<'a> {
	/// The caller set no mode, so the NSS comes from the components.
	#[default]
	Unset,
	/// The NSS string that `with_nss()` provides.
	Direct(Cow<'a, str>),
	/// The building closure that `with_spec()` stores.
	Spec(Box<SpecBuilderFn<'a>>),
	/// The caller set both a direct NSS and a spec, which `build()` refuses.
	Conflicting,
}

impl<'a> NssMode<'a> {
	/// Returns the mode after a `with_nss()` call that sets `nss`.
	///
	/// A later direct NSS replaces an earlier one, and a direct NSS beside a
	/// spec is a conflict.
	fn direct(self, nss: Cow<'a, str>) -> Self {
		match self {
			Self::Unset | Self::Direct(_) => Self::Direct(nss),
			Self::Spec(_) | Self::Conflicting => Self::Conflicting,
		}
	}

	/// Returns the mode after a `with_spec()` call that stores `spec`.
	///
	/// A later spec replaces an earlier one, and a spec beside a direct NSS
	/// is a conflict.
	fn spec(self, spec: Box<SpecBuilderFn<'a>>) -> Self {
		match self {
			Self::Unset | Self::Spec(_) => Self::Spec(spec),
			Self::Direct(_) | Self::Conflicting => Self::Conflicting,
		}
	}
}

impl<'a> UrnBuilder<'a> {
	/// Returns the component value of `key`.
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
	/// Sets the component value of `key`.
	///
	/// A key can be hierarchical in dot notation, such as `"resource.type"`.
	#[inline]
	pub fn set(mut self, key: &'static str, value: impl Into<Cow<'a, str>>) -> Self {
		self.components.insert(key, value.into());
		self
	}

	/// Sets the Namespace Identifier (NID).
	#[inline]
	pub fn with_nid(mut self, nid: impl Into<Cow<'a, str>>) -> Self {
		self.nid = Some(nid.into());
		self
	}

	/// Sets the NSS directly.
	///
	/// A later call replaces the NSS of an earlier one. A builder that also
	/// holds a spec, from `with_spec()` or from [`UrnBuilder::from`], refuses
	/// to build.
	pub fn with_nss(mut self, nss: impl Into<Cow<'a, str>>) -> Self {
		let mode = core::mem::take(&mut self.nss_mode);
		self.nss_mode = mode.direct(nss.into());
		self
	}

	/// Configures a spec for the validation and the NSS construction.
	///
	/// A later call replaces the spec of an earlier one. A builder that also
	/// holds a direct NSS from `with_nss()` refuses to build.
	pub fn with_spec<S: UrnSpec>(mut self) -> Self {
		// The closure defers the work of the spec to `build()`.
		let spec_builder = move |builder: &mut UrnBuilder<'a>| -> Result<Cow<'static, str>, UrnValidationError> {
			// The spec transforms the components before it validates them.
			S::transform(builder as &mut dyn UrnComponents<'a>);
			S::validate(builder as &dyn UrnComponents<'a>)?;
			S::build_nss(builder as &dyn UrnComponents<'a>)
		};

		let mode = core::mem::take(&mut self.nss_mode);
		self.nss_mode = mode.spec(Box::new(spec_builder));
		self
	}
}

impl<'a, S: UrnSpec> From<S> for UrnBuilder<'a> {
	/// Creates a URN builder from a spec type.
	///
	/// The builder takes the NID of the spec and applies `with_spec::<S>()`
	/// itself, so it is ready to use.
	#[inline]
	fn from(_: S) -> Self {
		let mut builder = UrnBuilder::default().with_spec::<S>();
		builder.nid = Some(Cow::Borrowed(S::NID));
		builder
	}
}

impl<'a> UrnBuilder<'a> {
	/// Builds the URN with the configured NSS mode.
	///
	/// The NSS comes from one of three modes:
	/// - `with_nss()` provides the NSS string directly.
	/// - `with_spec()` validates the components and constructs the NSS from them.
	/// - With neither call, the default joins the components in lexicographic key order.
	///
	/// A builder that holds both `with_nss()` and `with_spec()` refuses to
	/// build.
	///
	/// # RFC 8141 Compliance
	///
	/// The URN has the format `urn:<NID>:<NSS>`, where:
	/// - The NID has 2-32 characters of letters, digits, and hyphens, and
	///   starts and ends with a letter or digit.
	/// - The selected mode constructs the NSS, a run of the `pchar` of RFC 3986 § 3.3 and `/`.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::RequiredFieldMissing`] -- the NID is missing,
	///   the NSS is empty, or the default mode has no components.
	/// - [`UrnValidationError::InvalidNidLength`] -- the NID is not 2-32 characters long.
	/// - [`UrnValidationError::InvalidNidStart`] -- the NID starts with a
	///   character other than a letter or a digit.
	/// - [`UrnValidationError::InvalidNidCharacters`] -- the NID holds a
	///   character other than a letter, a digit, or a hyphen, or it ends with a
	///   hyphen.
	/// - [`UrnValidationError::InvalidNssCharacters`] -- the NSS breaks the NSS production of RFC 8141 § 2.
	/// - [`UrnValidationError::ConflictingNssModes`] -- the builder holds both a direct NSS and a spec.
	/// - Any error of the spec's `validate` or `build_nss`, in the `with_spec()` mode.
	pub fn build(mut self) -> Result<Urn<'a>, UrnValidationError> {
		// A spec's own validation runs before assembly and may compare the NID,
		// so the builder reports a malformed NID first, with its own error.
		let nid_ref = self.nid.as_ref().ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;
		Urn::validate_nid(nid_ref)?;

		// The mode moves out first, so the spec closure can borrow the
		// builder.
		let nss = match core::mem::replace(&mut self.nss_mode, NssMode::Unset) {
			NssMode::Spec(builder_fn) => builder_fn(&mut self)?,
			NssMode::Direct(nss) => nss,
			NssMode::Conflicting => return Err(UrnValidationError::ConflictingNssModes),
			NssMode::Unset => {
				// A `HashMap` iterates in no fixed order, so the sorted keys
				// make the NSS deterministic.
				let mut keys: Vec<&'static str> = self.components.keys().copied().collect();
				keys.sort();

				let mut nss_parts = Vec::new();
				for key in keys {
					if let Some(value) = self.components.get(key) {
						nss_parts.push(value.as_ref());
					}
				}

				if nss_parts.is_empty() {
					return Err(UrnValidationError::RequiredFieldMissing("nss components"));
				}

				nss_parts.join(":").into()
			}
		};

		let nid = self.nid.ok_or(UrnValidationError::RequiredFieldMissing("nid"))?;
		Urn::checked(nid, nss)
	}
}

#[cfg(feature = "builder")]
impl<'a> TypeBuilder<Urn<'a>> for UrnBuilder<'a> {
	type Error = UrnValidationError;

	fn build(self) -> Result<Urn<'a>, Self::Error> {
		UrnBuilder::build(self)
	}
}

#[cfg(test)]
impl<'a> UrnBuilder<'a> {
	/// This builder with each of `components`, a key beside its value, set in
	/// their order.
	pub(crate) fn holding<'c>(self, components: impl IntoIterator<Item = &'c (&'static str, &'a str)>) -> Self
	where
		'a: 'c,
	{
		let components = components.into_iter();
		components.fold(self, |builder, &(key, value)| builder.set(key, value))
	}
}

#[cfg(test)]
mod tests {
	use crate::testing::TestResult;
	use crate::urn::builders::spec::Pattern;

	use super::*;

	crate::urn_spec! {
		/// The URN spec that the builder tests use.
		TestUrnSpec,
		nid: "test",
		nss_structure {
			category: { value: "instrumentation", sep: ":" },
			type: { values: ["trace", "event", "seed", "verdict"], sep: "/" },
			id: { pattern: Pattern::AlphaNumericHyphen }
		},
		nss_format: "{}:{}/{}"
	}

	/// A builder of the [`TestUrnSpec`] NID that holds components the spec
	/// accepts, and no NSS mode.
	fn component_builder() -> UrnBuilder<'static> {
		let components = [("category", "instrumentation"), ("type", "trace"), ("id", "abc-123")];
		UrnBuilder::default().with_nid(TestUrnSpec::NID).holding(&components)
	}

	// Each case is a NID and a direct NSS, which the URN carries as the
	// builder was given them.
	crate::tb_cases! {
		fn a_builder_carries_the_nid_and_nss_it_is_given((nid, nss): (&str, &str)) -> TestResult {
			let urn = UrnBuilder::default().with_nid(nid).with_nss(nss).build()?;
			assert_eq!((urn.nid.as_ref(), urn.nss.as_ref()), (nid, nss));
			Ok(())
		}
		cases {
			colon_path => ("tightbeam", "test:resource"),
			slash_path => ("example", "path/to/resource"),
			simple => ("test", "simple"),
		}
	}

	// The builder joins the components in the lexicographic order of their
	// keys. Each case is a NID and its components, beside the NSS they join
	// into.
	crate::tb_cases! {
		fn a_builder_joins_its_components_in_key_order(
			(nid, components, nss): (&str, &'static [(&'static str, &'static str)], &str)
		) -> TestResult {
			let urn = UrnBuilder::default().with_nid(nid).holding(components).build()?;
			assert_eq!((urn.nid.as_ref(), urn.nss.as_ref()), (nid, nss));
			Ok(())
		}
		cases {
			two_keys => ("example", &[("type", "book"), ("id", "123")], "123:book"),
			sorted_keys => ("test", &[("a", "1"), ("b", "2"), ("c", "3")], "1:2:3"),
			reversed_keys => ("ns", &[("z", "last"), ("a", "first")], "first:last"),
		}
	}

	// Each case is the components of a builder of [`TestUrnSpec`], beside the
	// NSS that the spec writes of them.
	crate::tb_cases! {
		fn a_spec_builder_writes_its_nss((components, nss): (&'static [(&'static str, &'static str)], &str))
			-> TestResult
		{
			let urn = UrnBuilder::from(TestUrnSpec).holding(components).build()?;
			assert_eq!((urn.nid.as_ref(), urn.nss.as_ref()), ("test", nss));
			Ok(())
		}
		cases {
			trace => (
				&[("category", "instrumentation"), ("type", "trace"), ("id", "abc-123")],
				"instrumentation:trace/abc-123",
			),
			event => (
				&[("category", "instrumentation"), ("type", "event"), ("id", "test-456")],
				"instrumentation:event/test-456",
			),
			seed => (
				&[("category", "instrumentation"), ("type", "seed"), ("id", "xyz-789")],
				"instrumentation:seed/xyz-789",
			),
			verdict => (
				&[("category", "instrumentation"), ("type", "verdict"), ("id", "result-1")],
				"instrumentation:verdict/result-1",
			),
		}
	}

	// Each case is the components of a builder of [`TestUrnSpec`], beside the
	// refusal that names the field they leave out or break. A constraint names
	// no pattern, and the pattern of `id` names itself.
	crate::tb_cases! {
		fn a_spec_builder_names_the_field_it_refuses(
			(components, refusal): (&'static [(&'static str, &'static str)], UrnValidationError)
		) {
			let built = UrnBuilder::from(TestUrnSpec).holding(components).build();
			assert_eq!(built, Err(refusal));
		}
		cases {
			missing_category => (
				&[("type", "trace"), ("id", "123")],
				UrnValidationError::RequiredFieldMissing("category"),
			),
			missing_type => (
				&[("category", "instrumentation"), ("id", "123")],
				UrnValidationError::RequiredFieldMissing("type"),
			),
			missing_id => (
				&[("category", "instrumentation"), ("type", "trace")],
				UrnValidationError::RequiredFieldMissing("id"),
			),
			category_outside_its_value => (
				&[("category", "invalid"), ("type", "trace"), ("id", "123")],
				UrnValidationError::InvalidFormat { field: "category", pattern: None },
			),
			type_outside_its_values => (
				&[("category", "instrumentation"), ("type", "invalid"), ("id", "123")],
				UrnValidationError::InvalidFormat { field: "type", pattern: None },
			),
			bang_in_the_id => (
				&[("category", "instrumentation"), ("type", "trace"), ("id", "invalid_chars!")],
				UrnValidationError::InvalidFormat { field: "id", pattern: Some(Pattern::AlphaNumericHyphen) },
			),
			space_in_the_id => (
				&[("category", "instrumentation"), ("type", "trace"), ("id", "space here")],
				UrnValidationError::InvalidFormat { field: "id", pattern: Some(Pattern::AlphaNumericHyphen) },
			),
			underscore_in_the_id => (
				&[("category", "instrumentation"), ("type", "trace"), ("id", "underscore_here")],
				UrnValidationError::InvalidFormat { field: "id", pattern: Some(Pattern::AlphaNumericHyphen) },
			),
		}
	}

	// Each case is a builder that refuses to build, beside its refusal.
	crate::tb_cases! {
		fn a_builder_refuses_to_build((builder, refusal): (fn() -> UrnBuilder<'static>, UrnValidationError)) {
			let built = builder().build();
			assert_eq!(built, Err(refusal));
		}
		cases {
			no_nid_beside_a_simple_nss => (
				|| UrnBuilder::default().with_nss("test"),
				UrnValidationError::RequiredFieldMissing("nid"),
			),
			no_nid_beside_a_path_nss => (
				|| UrnBuilder::default().with_nss("resource:path"),
				UrnValidationError::RequiredFieldMissing("nid"),
			),
			no_nid_beside_an_empty_nss => (
				|| UrnBuilder::default().with_nss(""),
				UrnValidationError::RequiredFieldMissing("nid"),
			),
			no_component_under_tightbeam => (
				|| UrnBuilder::default().with_nid("tightbeam"),
				UrnValidationError::RequiredFieldMissing("nss components"),
			),
			no_component_under_test => (
				|| UrnBuilder::default().with_nid("test"),
				UrnValidationError::RequiredFieldMissing("nss components"),
			),
			no_component_under_example => (
				|| UrnBuilder::default().with_nid("example"),
				UrnValidationError::RequiredFieldMissing("nss components"),
			),
			/// The builder assembles its `Urn` through the one checked
			/// constructor, so it refuses an empty NSS as the constructors do.
			a_direct_empty_nss => (
				|| UrnBuilder::default().with_nid("test").with_nss(""),
				UrnValidationError::RequiredFieldMissing("nss"),
			),
			/// One empty component joins into an empty NSS.
			one_empty_component => (
				|| UrnBuilder::default().with_nid("test").set("only", ""),
				UrnValidationError::RequiredFieldMissing("nss"),
			),
			/// The builder names a malformed NID before it checks the NSS.
			a_malformed_nid_before_an_empty_nss => (
				|| UrnBuilder::default().with_nid("-bad").with_nss(""),
				UrnValidationError::InvalidNidStart,
			),
			/// A builder that holds both a direct NSS and a spec refuses to
			/// build, whichever of the two calls came first.
			a_spec_then_an_nss => (
				|| component_builder().with_spec::<TestUrnSpec>().with_nss("direct"),
				UrnValidationError::ConflictingNssModes,
			),
			/// The same conflict, with the NSS first.
			an_nss_then_a_spec => (
				|| component_builder().with_nss("direct").with_spec::<TestUrnSpec>(),
				UrnValidationError::ConflictingNssModes,
			),
		}
	}
}
