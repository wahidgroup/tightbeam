//! An outside crate writes a [`UrnSpec`] by hand here: [`KindAndName`] names
//! [`Parts`], a [`UrnComponents`] type of its own, and reads an NSS into it,
//! so [`Urn::verify`] reads each URN through the grammar of the spec.
//!
//! [`TwoOptional`], a spec of `urn_spec!` with two optional fields, verifies
//! each URN it builds through the parse of the house builder.

use std::borrow::Cow;

use tightbeam::urn::builders::spec::Pattern;
use tightbeam::urn::{Urn, UrnBuilder, UrnComponents, UrnSpec, UrnValidationError};

/// The spec of `urn:outside:<kind>/<name>`, for a kind of `servlet` or
/// `worker`.
struct KindAndName;

/// The two parts of an NSS of [`KindAndName`], each borrowed from it.
struct Parts<'a> {
	kind: Option<Cow<'a, str>>,
	name: Option<Cow<'a, str>>,
}

impl<'a> Parts<'a> {
	/// The slot of the part that `key` names, or `None` for a key the spec
	/// does not name.
	fn slot(&mut self, key: &'static str) -> Option<&mut Option<Cow<'a, str>>> {
		match key {
			"kind" => Some(&mut self.kind),
			"name" => Some(&mut self.name),
			_ => None,
		}
	}
}

impl<'a> UrnComponents<'a> for Parts<'a> {
	fn get_component(&self, key: &'static str) -> Option<&Cow<'a, str>> {
		match key {
			"kind" => self.kind.as_ref(),
			"name" => self.name.as_ref(),
			_ => None,
		}
	}

	fn set_component(&mut self, key: &'static str, value: Cow<'a, str>) {
		if let Some(slot) = self.slot(key) {
			*slot = Some(value);
		}
	}

	fn remove_component(&mut self, key: &'static str) -> Option<Cow<'a, str>> {
		self.slot(key).and_then(Option::take)
	}

	fn iter(&self) -> Box<dyn Iterator<Item = (&'static str, &Cow<'a, str>)> + '_> {
		let kind = self.kind.iter().map(|kind| ("kind", kind));
		let name = self.name.iter().map(|name| ("name", name));
		Box::new(kind.chain(name))
	}

	fn iter_mut(&mut self) -> Box<dyn Iterator<Item = (&'static str, &mut Cow<'a, str>)> + '_> {
		let kind = self.kind.iter_mut().map(|kind| ("kind", kind));
		let name = self.name.iter_mut().map(|name| ("name", name));
		Box::new(kind.chain(name))
	}
}

impl UrnSpec for KindAndName {
	const NID: &'static str = "outside";

	type Components<'a> = Parts<'a>;

	fn components<'a>(nss: &'a str) -> Result<Parts<'a>, UrnValidationError> {
		let (kind, name) = nss.split_once('/').ok_or(UrnValidationError::RequiredFieldMissing("name"))?;
		Ok(Parts { kind: Some(Cow::Borrowed(kind)), name: Some(Cow::Borrowed(name)) })
	}

	fn validate<'a>(components: &dyn UrnComponents<'a>) -> Result<(), UrnValidationError> {
		let (kind, name) = KindAndName::parts_of(components)?;
		if !matches!(kind, "servlet" | "worker") {
			return Err(UrnValidationError::InvalidFormat { field: "kind", pattern: None });
		}

		let pattern = Pattern::AlphaNumericHyphen;
		if !pattern.matches(name) {
			return Err(UrnValidationError::InvalidFormat { field: "name", pattern: Some(pattern) });
		}

		Ok(())
	}

	fn build_nss<'a>(components: &dyn UrnComponents<'a>) -> Result<Cow<'static, str>, UrnValidationError> {
		let (kind, name) = KindAndName::parts_of(components)?;
		Ok(Cow::Owned(format!("{kind}/{name}")))
	}
}

impl KindAndName {
	/// The kind and the name that `components` hold.
	fn parts_of<'c>(components: &'c dyn UrnComponents<'_>) -> Result<(&'c str, &'c str), UrnValidationError> {
		let kind = components.get_component("kind");
		let kind = kind.ok_or(UrnValidationError::RequiredFieldMissing("kind"))?;
		let name = components.get_component("name");
		let name = name.ok_or(UrnValidationError::RequiredFieldMissing("name"))?;
		Ok((kind.as_ref(), name.as_ref()))
	}
}

/// The outside spec verifies the URN its own grammar builds.
#[test]
fn an_outside_spec_verifies_the_urn_it_builds() -> Result<(), UrnValidationError> {
	let builder = UrnBuilder::from(KindAndName).set("kind", "servlet");
	let urn = builder.set("name", "ping").build()?;
	urn.verify::<KindAndName>()
}

/// The outside spec reads no name from an NSS without a `/`, so `verify`
/// refuses it with the error the spec names.
#[test]
fn an_outside_spec_refuses_a_urn_its_grammar_reads_no_name_from() -> Result<(), UrnValidationError> {
	let urn = Urn::from_parts("outside", "servlet")?;
	let refused = urn.verify::<KindAndName>();
	assert_eq!(refused, Err(UrnValidationError::RequiredFieldMissing("name")));
	Ok(())
}

tightbeam::urn_spec! {
	/// The spec of `urn:optional:[<region>:][<zone>:]<host>`.
	TwoOptional,
	nid: "optional",
	nss_structure {
		region: { required: false },
		zone: { required: false },
		host: { pattern: Pattern::AlphaNumericHyphen }
	}
}

/// A URN that names both optional fields verifies under the spec that built
/// it.
#[test]
fn a_spec_of_two_optional_fields_verifies_a_urn_of_both() -> Result<(), UrnValidationError> {
	let builder = UrnBuilder::from(TwoOptional).set("region", "eu").set("zone", "a");
	let urn = builder.set("host", "h1").build()?;
	urn.verify::<TwoOptional>()
}

/// A URN that names one optional field verifies under the spec that built
/// it, whichever field the parse gives its value to.
#[test]
fn a_spec_of_two_optional_fields_verifies_a_urn_of_one() -> Result<(), UrnValidationError> {
	let urn = UrnBuilder::from(TwoOptional).set("zone", "a").set("host", "h1").build()?;
	urn.verify::<TwoOptional>()
}
