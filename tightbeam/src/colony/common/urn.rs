//! Colony resource naming: URN vocabulary, minting, and validation.
//!
//! Every colony resource is named by an RFC 8141 URN with a fixed
//! positional grammar (the ARN model: typed segments, empty allowed,
//! grammar validated before the resource is looked up):
//!
//! ```text
//! urn:{nid}:{realm}:{resource-type}:{resource-id}
//!      │      │          │              │
//!      │      │          │              └ name; `/` separates an instance tail
//!      │      │          └ fixed vocabulary: servlet | hive | colony
//!      │      └ deployment segment, MAY be empty
//!      └ naming authority, default "tightbeam"
//! ```
//!
//! Examples:
//!
//! ```text
//! urn:tightbeam:prod-us:servlet:beam                 servlet type
//! urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100   servlet instance
//! urn:tightbeam:prod-us:hive:10.0.0.5:9000           hive identity
//! urn:tightbeam:prod-us:colony:main                  colony membership
//! urn:acme::servlet:beam                             custom authority, no realm
//! ```
//!
//! A [`ColonyNamespace`] is the minting and validation authority for one
//! deployment. Gateways validate inbound URNs against their own
//! namespace, so segments sharing a network cannot cross-register or
//! cross-route: wrong authority, wrong realm, or malformed grammar is
//! refused at the boundary.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
	borrow::Cow,
	format,
	string::{String, ToString},
	vec::Vec,
};
#[cfg(feature = "std")]
use std::borrow::Cow;

use crate::utils::urn::{Urn, UrnValidationError};

/// Default naming authority for colony resources.
pub const COLONY_NID: &str = "tightbeam";

const SERVLET_SEGMENT: &str = "servlet";
const HIVE_SEGMENT: &str = "hive";
const COLONY_SEGMENT: &str = "colony";

/// Naming scope for a colony deployment: authority (NID) plus an
/// optional realm segment. All resource URNs for the deployment are
/// minted from and validated against one namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColonyNamespace {
	nid: Cow<'static, str>,
	realm: Cow<'static, str>,
}

impl Default for ColonyNamespace {
	fn default() -> Self {
		Self { nid: Cow::Borrowed(COLONY_NID), realm: Cow::Borrowed("") }
	}
}

/// A validated colony resource, borrowed from the URN it was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColonyResource<'a> {
	/// A servlet type, optionally narrowed to one instance.
	Servlet {
		/// Servlet type name.
		name: &'a str,
		/// Instance tail (the locator after `/`), when present.
		instance: Option<&'a str>,
	},
	/// A hive identity.
	Hive {
		/// The registration locator the identity was minted from.
		addr: &'a str,
	},
	/// A colony membership identity, carried in a certificate's URI
	/// Subject Alternative Name (RFC 5280 §4.2.1.6).
	Colony {
		/// Colony name.
		name: &'a str,
	},
}

impl ColonyNamespace {
	/// Build a namespace with a custom authority and realm.
	///
	/// The NID is validated against RFC 8141 § 2.3.1. The realm must not
	/// contain `:` (it is one positional segment of the grammar) or `/`
	/// (the first `/` in a canonical URN marks the instance tail).
	pub fn new(
		nid: impl Into<Cow<'static, str>>,
		realm: impl Into<Cow<'static, str>>,
	) -> Result<Self, UrnValidationError> {
		let nid = nid.into();
		let realm = realm.into();

		Urn::validate_nid(nid.as_ref())?;
		if realm.contains(':') || realm.contains('/') {
			return Err(UrnValidationError::InvalidFormat { field: "realm", pattern: None });
		}

		Ok(Self { nid, realm })
	}

	/// Mint the URN naming a servlet type.
	///
	/// A name containing `/` or `:` is refused: a `/` would parse back
	/// as an instance tail and a `:` as an extra positional segment, so
	/// [`ColonyNamespace::validate`] would reinterpret the minted URN as
	/// naming a different resource. An empty name is refused for the
	/// same reason validation refuses an empty `resource-id`.
	pub fn servlet(&self, name: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let name = name.as_ref();
		Self::validate_single_segment_name(name)?;

		Ok(self.mint(SERVLET_SEGMENT, name))
	}

	/// Mint the URN naming a colony.
	///
	/// A colony URN travels in a certificate's URI Subject Alternative
	/// Name (RFC 5280 §4.2.1.6) and asserts colony membership for
	/// gossip and peer federation. The refusal rules match
	/// [`ColonyNamespace::servlet`]: a name with `/` or `:` would
	/// reparse as a different resource, and an empty name cannot name
	/// anything.
	pub fn colony(&self, name: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let name = name.as_ref();
		Self::validate_single_segment_name(name)?;

		Ok(self.mint(COLONY_SEGMENT, name))
	}

	/// Refuse a `resource-id` that is empty or carries a grammar
	/// delimiter, so a minted URN always validates back as the same
	/// resource.
	fn validate_single_segment_name(name: &str) -> Result<(), UrnValidationError> {
		if name.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
		}
		if name.contains('/') || name.contains(':') {
			return Err(UrnValidationError::InvalidFormat { field: "resource-id", pattern: None });
		}

		Ok(())
	}

	/// Mint the URN identifying a hive by its registration locator.
	///
	/// An empty locator is refused: it cannot name anything and
	/// validation refuses an empty `resource-id`. `:` and `/` are
	/// allowed because locators carry them (`host:port`, URL paths) and
	/// the hive `resource-id` is the whole remaining tail.
	pub fn hive(&self, addr: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let addr = addr.as_ref();
		if addr.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
		}

		Ok(self.mint(HIVE_SEGMENT, addr))
	}

	fn mint(&self, resource_type: &str, id: &str) -> Urn<'static> {
		Urn {
			nid: Cow::Owned(String::from(self.nid.as_ref())),
			nss: Cow::Owned(format!("{}:{}:{}", self.realm, resource_type, id)),
		}
	}

	/// Validate a URN against this namespace and parse its resource.
	///
	/// Grammar is checked before any registry is consulted: authority
	/// mismatch, realm mismatch, unknown resource type, and missing
	/// segments are each refused with a distinct error.
	///
	/// All comparisons are exact and case-sensitive. This is stricter
	/// than RFC 8141 § 3.1, which makes NID equivalence case-insensitive;
	/// exact matching keeps registry keys derived from canonical bytes
	/// valid without case folding anywhere.
	pub fn validate<'a>(&self, urn: &'a Urn<'a>) -> Result<ColonyResource<'a>, UrnValidationError> {
		if urn.nid.as_ref() != self.nid.as_ref() {
			return Err(UrnValidationError::NidMismatch);
		}

		let (realm, rest) = urn
			.nss
			.split_once(':')
			.ok_or(UrnValidationError::RequiredFieldMissing("resource-type"))?;
		if realm != self.realm.as_ref() {
			return Err(UrnValidationError::RealmMismatch);
		}

		let (resource_type, id) = rest
			.split_once(':')
			.ok_or(UrnValidationError::RequiredFieldMissing("resource-id"))?;
		if id.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
		}

		match resource_type {
			SERVLET_SEGMENT => {
				let (name, instance) = match id.split_once('/') {
					Some((name, instance)) => (name, Some(instance)),
					None => (id, None),
				};
				if name.is_empty() {
					return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
				}
				if instance == Some("") {
					return Err(UrnValidationError::RequiredFieldMissing("instance"));
				}

				Ok(ColonyResource::Servlet { name, instance })
			}
			HIVE_SEGMENT => Ok(ColonyResource::Hive { addr: id }),
			// A colony name is one segment: a `/` or extra `:` cannot
			// come from `colony`, so such an id names nothing mintable.
			COLONY_SEGMENT => {
				Self::validate_single_segment_name(id)?;
				Ok(ColonyResource::Colony { name: id })
			}
			_ => Err(UrnValidationError::InvalidFormat { field: "resource-type", pattern: None }),
		}
	}
}

/// Mint the instance URN under a servlet type: the type's URN with a
/// `/{addr}` tail. Authority and realm are inherited from the type, so
/// no namespace handle is needed.
pub fn servlet_instance(servlet_type: &Urn<'_>, addr: impl AsRef<str>) -> Urn<'static> {
	Urn {
		nid: Cow::Owned(String::from(servlet_type.nid.as_ref())),
		nss: Cow::Owned(format!("{}/{}", servlet_type.nss, addr.as_ref())),
	}
}

/// Whether `urn` is a bare servlet type in `namespace` (no instance tail)
#[must_use]
pub fn is_bare_servlet_type(namespace: &ColonyNamespace, urn: &Urn<'_>) -> bool {
	matches!(namespace.validate(urn), Ok(ColonyResource::Servlet { instance: None, .. }))
}

/// Canonical bytes of a URN: its display form (`urn:nid:nss`).
///
/// Registries key by this form so lookups agree across processes
/// regardless of how the URN was built.
pub fn canonical_bytes(urn: &Urn<'_>) -> Vec<u8> {
	urn.to_string().into_bytes()
}

/// Canonical bytes of a URN with any instance tail stripped: the type
/// key an instance belongs to. NID, realm, and servlet name cannot
/// contain `/`, so the first `/` in the canonical form always marks the
/// start of the instance tail.
pub fn type_canonical_bytes(urn: &Urn<'_>) -> Vec<u8> {
	let mut canonical = urn.to_string();
	if let Some(tail) = canonical.find('/') {
		canonical.truncate(tail);
	}

	canonical.into_bytes()
}

/// Byte prefix matching every instance key under a servlet type: the
/// type's canonical bytes plus the tail delimiter. The delimiter keeps
/// one type's prefix from matching another type's keys (`beam` never
/// matches `beam2/...`).
pub fn type_prefix_bytes(servlet_type: &Urn<'_>) -> Vec<u8> {
	let mut prefix = type_canonical_bytes(servlet_type);
	prefix.push(b'/');
	prefix
}

#[cfg(test)]
mod tests {
	use super::*;

	fn prod() -> ColonyNamespace {
		ColonyNamespace::new("tightbeam", "prod-us").unwrap_or_default()
	}

	fn servlet(namespace: &ColonyNamespace, name: &str) -> Urn<'static> {
		namespace.servlet(name).expect("test names satisfy the mint grammar")
	}

	fn hive(namespace: &ColonyNamespace, addr: &str) -> Urn<'static> {
		namespace.hive(addr).expect("test locators satisfy the mint grammar")
	}

	fn colony(namespace: &ColonyNamespace, name: &str) -> Urn<'static> {
		namespace.colony(name).expect("test names satisfy the mint grammar")
	}

	#[test]
	fn minted_urns_round_trip_through_validate() {
		let prod = prod();
		let bare = ColonyNamespace::default();
		let cases = [
			(
				&prod,
				servlet(&prod, "beam"),
				"urn:tightbeam:prod-us:servlet:beam",
				ColonyResource::Servlet { name: "beam", instance: None },
			),
			(
				&prod,
				servlet_instance(&servlet(&prod, "beam"), "10.0.0.5:9100"),
				"urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100",
				ColonyResource::Servlet { name: "beam", instance: Some("10.0.0.5:9100") },
			),
			(
				&prod,
				hive(&prod, "10.0.0.5:9000"),
				"urn:tightbeam:prod-us:hive:10.0.0.5:9000",
				ColonyResource::Hive { addr: "10.0.0.5:9000" },
			),
			(
				&prod,
				colony(&prod, "main"),
				"urn:tightbeam:prod-us:colony:main",
				ColonyResource::Colony { name: "main" },
			),
			(
				&bare,
				servlet(&bare, "beam"),
				"urn:tightbeam::servlet:beam",
				ColonyResource::Servlet { name: "beam", instance: None },
			),
			(
				&bare,
				colony(&bare, "main"),
				"urn:tightbeam::colony:main",
				ColonyResource::Colony { name: "main" },
			),
		];
		for (namespace, urn, display, resource) in cases {
			assert_eq!(urn.to_string(), display);
			assert_eq!(namespace.validate(&urn), Ok(resource));
		}
	}

	#[test]
	fn foreign_or_malformed_urns_are_refused() {
		let namespace = prod();
		let cases = [
			(Urn::new("acme", "prod-us:servlet:beam"), UrnValidationError::NidMismatch),
			(Urn::new("tightbeam", "staging:servlet:beam"), UrnValidationError::RealmMismatch),
			(
				Urn::new("tightbeam", "prod-us:queue:beam"),
				UrnValidationError::InvalidFormat { field: "resource-type", pattern: None },
			),
			(
				Urn::new("tightbeam", "prod-us"),
				UrnValidationError::RequiredFieldMissing("resource-type"),
			),
			(
				Urn::new("tightbeam", "prod-us:servlet:"),
				UrnValidationError::RequiredFieldMissing("resource-id"),
			),
			(
				servlet_instance(&servlet(&namespace, "beam"), ""),
				UrnValidationError::RequiredFieldMissing("instance"),
			),
			(
				Urn::new("tightbeam", "prod-us:colony:main/tail"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			(
				Urn::new("tightbeam", "prod-us:colony:main:extra"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
		];
		for (urn, error) in cases {
			assert_eq!(namespace.validate(&urn), Err(error));
		}
	}

	#[test]
	fn invalid_namespace_parts_are_refused_at_construction() {
		let cases = [
			(
				"tightbeam",
				"prod:us",
				UrnValidationError::InvalidFormat { field: "realm", pattern: None },
			),
			(
				"tightbeam",
				"prod/us",
				UrnValidationError::InvalidFormat { field: "realm", pattern: None },
			),
			("9bad", "", UrnValidationError::InvalidNidStart),
		];
		for (nid, realm, error) in cases {
			assert_eq!(ColonyNamespace::new(nid, realm).err(), Some(error));
		}
	}

	#[test]
	fn type_canonical_bytes_strips_instance_tail() {
		let namespace = prod();
		let servlet_type = servlet(&namespace, "beam");
		let instance = servlet_instance(&servlet_type, "10.0.0.5:9100");

		assert_eq!(type_canonical_bytes(&instance), canonical_bytes(&servlet_type));
		assert_eq!(type_canonical_bytes(&servlet_type), canonical_bytes(&servlet_type));
	}

	#[test]
	fn type_prefix_bounds_instance_keys_to_one_type() {
		let namespace = prod();
		let beam = servlet(&namespace, "beam");
		let beam_instance = canonical_bytes(&servlet_instance(&beam, "10.0.0.5:9100"));
		let beam2_instance = canonical_bytes(&servlet_instance(&servlet(&namespace, "beam2"), "10.0.0.5:9200"));

		let prefix = type_prefix_bytes(&beam);
		assert!(beam_instance.starts_with(&prefix));
		assert!(!beam2_instance.starts_with(&prefix));
	}

	#[test]
	fn delimiter_and_empty_names_are_refused_at_mint() {
		let namespace = prod();
		let cases = [
			(namespace.servlet(""), UrnValidationError::RequiredFieldMissing("resource-id")),
			(
				namespace.servlet("beam/10.0.0.5"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			(
				namespace.servlet("beam:extra"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			(namespace.hive(""), UrnValidationError::RequiredFieldMissing("resource-id")),
			(namespace.colony(""), UrnValidationError::RequiredFieldMissing("resource-id")),
			(
				namespace.colony("main/tail"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			(
				namespace.colony("main:extra"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
		];
		for (minted, error) in cases {
			assert_eq!(minted.err(), Some(error));
		}
	}
}
