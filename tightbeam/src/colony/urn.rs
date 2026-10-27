//! The URN vocabulary of colony resources, with its minting and validation.
//!
//! An RFC 8141 URN names each colony resource, in a fixed positional
//! grammar of typed segments after the ARN model:
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
//! deployment. A gateway validates each inbound URN against its own
//! namespace, so a segment registers and routes inside its own authority
//! and realm.

use std::borrow::Cow;

use crate::colony::protocol::ServletInfo;
use crate::urn::{Urn, UrnValidationError};
use crate::TightBeamError;

/// The default naming authority for colony resources.
pub const COLONY_NID: &str = "tightbeam";

const SERVLET_SEGMENT: &str = "servlet";
const HIVE_SEGMENT: &str = "hive";
const COLONY_SEGMENT: &str = "colony";

/// The naming scope of a colony deployment: an authority (NID) and an
/// optional realm segment. One namespace mints and validates every resource
/// URN of the deployment.
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

/// A validated colony resource, which borrows from its source URN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColonyResource<'a> {
	/// A servlet type, optionally narrowed to one instance.
	Servlet {
		/// The name of the servlet type.
		name: &'a str,
		/// The instance tail (the locator after `/`), when present.
		instance: Option<&'a str>,
	},
	/// A hive identity.
	Hive {
		/// The registration locator that [`ColonyNamespace::hive`] mints the
		/// identity from.
		addr: &'a str,
	},
	/// A colony membership identity, carried in a certificate's URI
	/// Subject Alternative Name (RFC 5280 §4.2.1.6).
	Colony {
		/// The name of the colony.
		name: &'a str,
	},
}

impl ColonyNamespace {
	/// Builds a namespace with a custom authority and realm.
	///
	/// # Errors
	///
	/// - The errors of [`Urn::validate_nid`] -- the NID breaks RFC 8141 § 2.1.
	/// - [`UrnValidationError::InvalidFormat`] -- the realm contains `:`, which
	///   would split its one positional segment of the grammar, or `/`, which
	///   marks the instance tail in a canonical URN.
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

	/// Mints the URN that names a servlet type.
	///
	/// The function refuses a name with a `/` or a `:`, because a `/` would
	/// parse back as an instance tail and a `:` as an extra positional segment,
	/// so [`ColonyNamespace::validate`] would read the minted URN as a
	/// different resource. It refuses an empty name for the same reason that
	/// validation refuses an empty `resource-id`.
	pub fn servlet(&self, name: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let name = name.as_ref();
		Self::validate_single_segment_name(name)?;

		self.mint(SERVLET_SEGMENT, name)
	}

	/// Mints the URN that names a colony.
	///
	/// A colony URN travels in a certificate's URI Subject Alternative
	/// Name (RFC 5280 §4.2.1.6) and asserts colony membership for
	/// gossip and peer federation. The refusal rules match
	/// [`ColonyNamespace::servlet`]: a name with `/` or `:` would
	/// reparse as a different resource, and a name carries at least one
	/// character.
	pub fn colony(&self, name: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let name = name.as_ref();
		Self::validate_single_segment_name(name)?;

		self.mint(COLONY_SEGMENT, name)
	}

	/// Refuses a `resource-id` that is empty or carries a grammar
	/// delimiter, so a minted URN always validates back as the same
	/// resource.
	fn validate_single_segment_name(name: impl AsRef<str>) -> Result<(), UrnValidationError> {
		let name = name.as_ref();
		if name.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
		}
		if name.contains('/') || name.contains(':') {
			return Err(UrnValidationError::InvalidFormat { field: "resource-id", pattern: None });
		}

		Ok(())
	}

	/// Mints the URN that identifies a hive by its registration locator.
	///
	/// The function refuses an empty locator, because validation requires a
	/// nonempty `resource-id`. A locator may carry `:` and `/` (`host:port`,
	/// URL paths), because the hive `resource-id` is the whole tail after the
	/// resource type.
	pub fn hive(&self, addr: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let addr = addr.as_ref();
		if addr.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
		}

		self.mint(HIVE_SEGMENT, addr)
	}

	/// Mints the hive URN for a locator carried as bytes.
	///
	/// It returns [`None`] when the bytes are not UTF-8 or [`Self::hive`]
	/// refuses the locator. Wire and configuration both hand the locator over
	/// as bytes, so both reach the URN through one decode.
	pub(crate) fn hive_from_bytes(&self, addr: impl AsRef<[u8]>) -> Option<Urn<'static>> {
		let addr = addr.as_ref();
		let addr = core::str::from_utf8(addr).ok()?;
		self.hive(addr).ok()
	}

	/// Whether every URN in `types` is a bare servlet type in this namespace.
	///
	/// A peer advertises the types it serves, so one foreign or instance
	/// URN in the list refuses the whole advertisement.
	pub(crate) fn all_bare_servlet_types(&self, types: impl AsRef<[Urn<'static>]>) -> bool {
		let types = types.as_ref();
		types.iter().all(|urn| self.is_bare_servlet_type(urn))
	}

	/// Whether the instance locator inside `info.servlet_id` equals the
	/// address advertised alongside it.
	///
	/// A servlet that advertises one address under the identity of another
	/// redirects that identity's traffic (CWE-639), so the two MUST agree.
	pub(crate) fn locator_matches(&self, info: &ServletInfo) -> bool {
		match self.validate(&info.servlet_id) {
			Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => {
				locator.as_bytes() == info.address.as_slice()
			}
			_ => false,
		}
	}

	/// Mints `urn:{nid}:{realm}:{resource_type}:{id}` under this namespace.
	///
	/// # Errors
	///
	/// - The errors of [`Urn::from_parts`]. A namespace from its own
	///   constructor never causes one, but no type carries that proof for the
	///   parts of the namespace.
	fn mint(&self, resource_type: impl AsRef<str>, id: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let resource_type = resource_type.as_ref();
		let id = id.as_ref();
		let nss = format!("{}:{}:{}", self.realm, resource_type, id);
		Urn::from_parts(self.nid.as_ref(), nss)
	}

	/// Validates a URN against this namespace and parses its resource.
	///
	/// The grammar check runs before any registry lookup. Every comparison is
	/// exact and case-sensitive, which is stricter than RFC 8141 § 3.1 (NID
	/// equivalence there is case-insensitive), so registry keys derived from
	/// canonical bytes stay valid with no case folding anywhere.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::NidMismatch`] -- the authority differs from this namespace's NID.
	/// - [`UrnValidationError::RealmMismatch`] -- the realm differs from this namespace's realm.
	/// - [`UrnValidationError::RequiredFieldMissing`] -- the resource type or
	///   the resource id is absent, or the resource id, the servlet name, or
	///   the instance tail after a `/` is empty.
	/// - [`UrnValidationError::InvalidFormat`] -- the resource type is outside
	///   the vocabulary, or a colony name carries `/` or `:`.
	pub fn validate<'a>(&self, urn: &'a Urn<'a>) -> Result<ColonyResource<'a>, UrnValidationError> {
		if urn.nid() != self.nid.as_ref() {
			return Err(UrnValidationError::NidMismatch);
		}

		let (realm, rest) = urn
			.nss()
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
			// A colony name is one segment, so an id with a `/` or an extra `:`
			// names something outside the mintable grammar.
			COLONY_SEGMENT => {
				Self::validate_single_segment_name(id)?;
				Ok(ColonyResource::Colony { name: id })
			}
			_ => Err(UrnValidationError::InvalidFormat { field: "resource-type", pattern: None }),
		}
	}
}

impl Urn<'_> {
	/// Mints the instance URN under a servlet type: the type's URN with a
	/// `/{addr}` tail. The instance inherits the authority and realm of the
	/// type, so the call needs no namespace handle.
	///
	/// # Errors
	///
	/// - The errors of [`Urn::from_parts`]. Every checked constructor meets
	///   its rules, so only a URN that `Urn::new_unchecked` builds outside
	///   [`urn!`](crate::urn!) can see one.
	pub fn servlet_instance(&self, addr: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let nss = format!("{}/{}", self.nss(), addr.as_ref());
		Urn::from_parts(self.nid(), nss)
	}

	/// Mints the instance URN under a servlet type from a locator carried as
	/// bytes, which become the `resource-id` tail.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UrnValidationError`] -- `addr_bytes` is not UTF-8
	///   ([`UrnValidationError::InvalidFormat`]), or
	///   [`Self::servlet_instance`] refuses the URN.
	pub fn instance_urn(&self, addr_bytes: impl AsRef<[u8]>) -> Result<Urn<'static>, TightBeamError> {
		let addr = core::str::from_utf8(addr_bytes.as_ref()).map_err(|_| {
			TightBeamError::UrnValidationError(UrnValidationError::InvalidFormat {
				field: "resource-id",
				pattern: None,
			})
		})?;

		Ok(self.servlet_instance(addr)?)
	}

	/// The canonical bytes of a URN: its display form (`urn:nid:nss`).
	///
	/// Registries key by this form, so lookups agree across processes for a
	/// URN from any constructor.
	pub fn canonical_bytes(&self) -> Vec<u8> {
		self.to_string().into_bytes()
	}

	/// The canonical bytes with any instance tail cut off, which form the type
	/// key of an instance. The NID, the realm, and the servlet name exclude
	/// `/`, so the first `/` in the canonical form always marks the tail.
	pub fn type_canonical_bytes(&self) -> Vec<u8> {
		let mut canonical = self.to_string();
		if let Some(tail) = canonical.find('/') {
			canonical.truncate(tail);
		}

		canonical.into_bytes()
	}

	/// The byte prefix of every instance key under a servlet type: the type's
	/// canonical bytes and the tail delimiter. The delimiter keeps the prefix
	/// of one type off the keys of another, so `beam` matches `beam/...` alone
	/// and `beam2/...` stays with its own type.
	pub fn type_prefix_bytes(&self) -> Vec<u8> {
		let mut prefix = self.type_canonical_bytes();
		prefix.push(b'/');
		prefix
	}
}

/// A URN proven to be a bare servlet type in one namespace.
///
/// Route selection keys on the canonical bytes this carries, so it cannot
/// run on an instance locator or a foreign realm. The namespace check runs
/// once, where [`ColonyNamespace::servlet_type_key`] mints the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServletTypeKey(Vec<u8>);

impl ServletTypeKey {
	/// The registry's route key for this type.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Builds a key from bytes that a registry fixture holds.
	///
	/// Production mints every key through
	/// [`ColonyNamespace::servlet_type_key`], which proves that the URN is a
	/// bare servlet type in this colony. Registry fixtures test the map and
	/// skip the parse, so they name their rows directly.
	#[cfg(test)]
	pub(crate) fn from_route_bytes(bytes: impl Into<Vec<u8>>) -> Self {
		Self(bytes.into())
	}
}

impl AsRef<[u8]> for ServletTypeKey {
	fn as_ref(&self) -> &[u8] {
		self.as_bytes()
	}
}

impl ColonyNamespace {
	/// The route key for `urn`, when it is a bare servlet type here.
	///
	/// It returns [`None`] for an instance locator, a foreign authority, or
	/// another realm, none of which name a routable servlet type.
	#[must_use]
	pub fn servlet_type_key(&self, urn: &Urn<'_>) -> Option<ServletTypeKey> {
		match self.validate(urn) {
			Ok(ColonyResource::Servlet { instance: None, .. }) => Some(ServletTypeKey(urn.canonical_bytes())),
			_ => None,
		}
	}

	/// Whether `urn` is a bare servlet type in this namespace (no tail).
	///
	/// [`ColonyNamespace::servlet_type_key`] answers the same question and
	/// also returns the route key, so a caller that uses the key calls that
	/// function instead.
	#[must_use]
	pub(crate) fn is_bare_servlet_type(&self, urn: &Urn<'_>) -> bool {
		self.servlet_type_key(urn).is_some()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn prod() -> ColonyNamespace {
		ColonyNamespace::new("tightbeam", "prod-us").unwrap_or_default()
	}

	fn servlet(namespace: &ColonyNamespace, name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let name = name.as_ref();
		namespace.servlet(name).expect("test names satisfy the mint grammar")
	}

	/// An instance of the servlet type `beam` whose locator is empty.
	fn empty_instance() -> Urn<'static> {
		servlet(&prod(), "beam")
			.servlet_instance("")
			.expect("a servlet type URN yields an instance URN")
	}

	/// An instance locator in this namespace, which names a servlet but is
	/// not a bare type.
	fn instance_of(bare: &Urn<'static>) -> Urn<'static> {
		bare.servlet_instance("10.0.0.5:9100")
			.expect("a servlet type URN yields an instance URN")
	}

	/// The same servlet name in another realm.
	fn foreign_servlet() -> Urn<'static> {
		let other = ColonyNamespace::new("tightbeam", "staging-eu").expect("the fixture realm is valid");
		servlet(&other, "beam")
	}

	#[test]
	fn a_bare_servlet_type_yields_its_route_key() {
		let prod = prod();
		let bare = servlet(&prod, "beam");
		let key = prod.servlet_type_key(&bare);
		assert_eq!(key.map(|key| key.as_bytes().to_vec()), Some(bare.canonical_bytes()));
	}

	#[test]
	fn an_instance_locator_yields_no_route_key() {
		let prod = prod();
		let instance = instance_of(&servlet(&prod, "beam"));
		assert!(prod.servlet_type_key(&instance).is_none());
	}

	#[test]
	fn a_foreign_realm_yields_no_route_key() {
		let prod = prod();
		assert!(prod.servlet_type_key(&foreign_servlet()).is_none());
	}

	fn hive(namespace: &ColonyNamespace, addr: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let addr = addr.as_ref();
		namespace.hive(addr).expect("test locators satisfy the mint grammar")
	}

	fn colony(namespace: &ColonyNamespace, name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let name = name.as_ref();
		namespace.colony(name).expect("test names satisfy the mint grammar")
	}

	/// One minted URN: the namespace that validates it, the URN, its display
	/// form, and the resource it names.
	type MintedCase = (ColonyNamespace, Urn<'static>, &'static str, ColonyResource<'static>);

	crate::tb_cases! {
		fn minted_urns_round_trip_through_validate((namespace, urn, display, resource): MintedCase) {
			assert_eq!(urn.to_string(), display);
			assert_eq!(namespace.validate(&urn), Ok(resource));
		}
		cases {
			servlet_type => (
				prod(),
				servlet(&prod(), "beam"),
				"urn:tightbeam:prod-us:servlet:beam",
				ColonyResource::Servlet { name: "beam", instance: None },
			),
			servlet_instance => (
				prod(),
				instance_of(&servlet(&prod(), "beam")),
				"urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100",
				ColonyResource::Servlet { name: "beam", instance: Some("10.0.0.5:9100") },
			),
			hive => (
				prod(),
				hive(&prod(), "10.0.0.5:9000"),
				"urn:tightbeam:prod-us:hive:10.0.0.5:9000",
				ColonyResource::Hive { addr: "10.0.0.5:9000" },
			),
			colony => (
				prod(),
				colony(&prod(), "main"),
				"urn:tightbeam:prod-us:colony:main",
				ColonyResource::Colony { name: "main" },
			),
			bare_servlet => (
				ColonyNamespace::default(),
				servlet(&ColonyNamespace::default(), "beam"),
				"urn:tightbeam::servlet:beam",
				ColonyResource::Servlet { name: "beam", instance: None },
			),
			bare_colony => (
				ColonyNamespace::default(),
				colony(&ColonyNamespace::default(), "main"),
				"urn:tightbeam::colony:main",
				ColonyResource::Colony { name: "main" },
			),
		}
	}

	crate::tb_cases! {
		fn foreign_or_malformed_urns_are_refused((urn, error): (Urn<'static>, UrnValidationError)) {
			assert_eq!(prod().validate(&urn), Err(error));
		}
		cases {
			foreign_nid => (crate::urn!("acme", "prod-us:servlet:beam"), UrnValidationError::NidMismatch),
			foreign_realm => (crate::urn!("tightbeam", "staging:servlet:beam"), UrnValidationError::RealmMismatch),
			unknown_resource_type => (
				crate::urn!("tightbeam", "prod-us:queue:beam"),
				UrnValidationError::InvalidFormat { field: "resource-type", pattern: None },
			),
			realm_alone => (
				crate::urn!("tightbeam", "prod-us"),
				UrnValidationError::RequiredFieldMissing("resource-type"),
			),
			empty_resource_id => (
				crate::urn!("tightbeam", "prod-us:servlet:"),
				UrnValidationError::RequiredFieldMissing("resource-id"),
			),
			empty_instance => (empty_instance(), UrnValidationError::RequiredFieldMissing("instance")),
			colony_with_instance => (
				crate::urn!("tightbeam", "prod-us:colony:main/tail"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			colony_with_extra_segment => (
				crate::urn!("tightbeam", "prod-us:colony:main:extra"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
		}
	}

	crate::tb_cases! {
		fn invalid_namespace_parts_are_refused_at_construction((nid, realm, error): (&str, &str, UrnValidationError)) {
			assert_eq!(ColonyNamespace::new(nid, realm).err(), Some(error));
		}
		cases {
			realm_with_colon => (
				"tightbeam",
				"prod:us",
				UrnValidationError::InvalidFormat { field: "realm", pattern: None },
			),
			realm_with_slash => (
				"tightbeam",
				"prod/us",
				UrnValidationError::InvalidFormat { field: "realm", pattern: None },
			),
			digit_first_nid => ("9bad", "", UrnValidationError::InvalidNidStart),
		}
	}

	#[test]
	fn type_canonical_bytes_strips_instance_tail() {
		let namespace = prod();
		let servlet_type = servlet(&namespace, "beam");
		let instance = servlet_type
			.servlet_instance("10.0.0.5:9100")
			.expect("a servlet type URN yields an instance URN");

		assert_eq!(instance.type_canonical_bytes(), servlet_type.canonical_bytes());
		assert_eq!(servlet_type.type_canonical_bytes(), servlet_type.canonical_bytes());
	}

	#[test]
	fn type_prefix_bounds_instance_keys_to_one_type() {
		let namespace = prod();
		let beam = servlet(&namespace, "beam");
		let beam_instance = beam
			.servlet_instance("10.0.0.5:9100")
			.expect("a servlet type URN yields an instance URN")
			.canonical_bytes();
		let beam2_instance = servlet(&namespace, "beam2")
			.servlet_instance("10.0.0.5:9200")
			.expect("a servlet type URN yields an instance URN")
			.canonical_bytes();

		let prefix = beam.type_prefix_bytes();
		assert!(beam_instance.starts_with(&prefix));
		assert!(!beam2_instance.starts_with(&prefix));
	}

	/// The outcome of one mint, and the refusal it must be.
	type MintCase = (Result<Urn<'static>, UrnValidationError>, UrnValidationError);

	crate::tb_cases! {
		fn delimiter_and_empty_names_are_refused_at_mint((minted, error): MintCase) {
			assert_eq!(minted.err(), Some(error));
		}
		cases {
			empty_servlet => (prod().servlet(""), UrnValidationError::RequiredFieldMissing("resource-id")),
			servlet_with_instance => (
				prod().servlet("beam/10.0.0.5"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			servlet_with_extra_segment => (
				prod().servlet("beam:extra"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			empty_hive => (prod().hive(""), UrnValidationError::RequiredFieldMissing("resource-id")),
			empty_colony => (prod().colony(""), UrnValidationError::RequiredFieldMissing("resource-id")),
			colony_with_instance => (
				prod().colony("main/tail"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
			colony_with_extra_segment => (
				prod().colony("main:extra"),
				UrnValidationError::InvalidFormat { field: "resource-id", pattern: None },
			),
		}
	}
}
