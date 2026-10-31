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
//! urn:tightbeam:prod-us:hive:%5B::1%5D:9000          hive at an IPv6 literal
//! urn:tightbeam:prod-us:colony:main                  colony membership
//! urn:acme::servlet:beam                             custom authority, no realm
//! ```
//!
//! A [`ColonyNamespace`] is the minting and validation authority for one
//! deployment. A gateway validates each inbound URN against its own
//! namespace, so a segment registers and routes inside its own authority
//! and realm.
//!
//! - A colony URN carries no r-, q-, or f-component, because the grammar defines none.
//! - Names compare by URN-equivalence (RFC 8141 § 3.1): the scheme and the
//!   NID in any case, and the hex digits of each percent-encoded triplet in
//!   any case.
//! - Each registry key is the normalized form of its URN, so two
//!   URN-equivalent names key one resource.

use std::borrow::Cow;

use crate::colony::protocol::ServletInfo;
use crate::urn::{NssText, Urn, UrnValidationError};
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
		/// The instance tail after `/`, when present: the locator, with each
		/// byte outside the NSS production of RFC 8141 percent-encoded.
		/// [`NssText::decoded`] gives its address.
		instance: Option<NssText<'a>>,
	},
	/// A hive identity.
	Hive {
		/// The registration locator that [`ColonyNamespace::hive`] mints the
		/// identity from, with each byte outside the NSS production of RFC
		/// 8141 percent-encoded. [`NssText::decoded`] gives its address.
		addr: NssText<'a>,
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
	/// Every URN that the namespace mints opens its NSS with the realm, so the
	/// namespace admits only a realm under which each valid name mints.
	///
	/// # Errors
	///
	/// - The errors of [`Urn::validate_nid`] -- the NID breaks RFC 8141 § 2.1.
	/// - [`UrnValidationError::InvalidFormat`] -- the realm contains `:`, which
	///   would split its one positional segment of the grammar, or `/`, which
	///   marks the instance tail in a canonical URN.
	/// - [`UrnValidationError::InvalidNssCharacters`] -- the realm holds a
	///   character outside the `pchar` of RFC 3986 § 3.3, or a `%` that two hex
	///   digits do not follow, so it breaks the NSS production of RFC 8141 § 2.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::urn::ColonyNamespace;
	/// use tightbeam::urn::UrnValidationError;
	///
	/// let namespace = ColonyNamespace::new("acme", "prod%20us")?;
	/// assert_eq!(namespace.servlet("beam")?.to_string(), "urn:acme:prod%20us:servlet:beam");
	///
	/// let refused = ColonyNamespace::new("acme", "prod us");
	/// assert_eq!(refused, Err(UrnValidationError::InvalidNssCharacters));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn new(
		nid: impl Into<Cow<'static, str>>,
		realm: impl Into<Cow<'static, str>>,
	) -> Result<Self, UrnValidationError> {
		let nid = nid.into();
		let realm = realm.into();

		Urn::validate_nid(nid.as_ref())?;
		Self::validate_realm(realm.as_ref())?;

		Ok(Self { nid, realm })
	}

	/// Refuses a realm that cannot open the NSS of a minted URN.
	///
	/// A mint writes the realm and then a `:`, so the realm is valid when that
	/// text meets the NSS production. The `:` also keeps an empty realm valid.
	fn validate_realm(realm: &str) -> Result<(), UrnValidationError> {
		if realm.contains([':', '/']) {
			return Err(UrnValidationError::InvalidFormat { field: "realm", pattern: None });
		}

		let nss_head = format!("{realm}:");
		Urn::validate_nss(&nss_head)
	}

	/// The namespace that `urn` names: its NID, and the realm segment that
	/// opens its NSS.
	///
	/// It returns [`None`] when the NSS holds no `:` to end a realm, or when
	/// [`Self::new`] refuses the parts, because no namespace then exists.
	pub(crate) fn of(urn: &Urn<'_>) -> Option<Self> {
		let (realm, _) = urn.nss().split_once(':')?;
		Self::new(urn.nid().to_owned(), realm.to_owned()).ok()
	}

	/// Mints the URN that names a servlet type.
	///
	/// The function refuses a name with a `/` or a `:`, because a `/` would
	/// parse back as an instance tail and a `:` as an extra positional segment,
	/// so [`ColonyNamespace::validate`] would read the minted URN as a
	/// different resource. It refuses an empty name for the same reason that
	/// validation refuses an empty `resource-id`.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::RequiredFieldMissing`] -- `name` is empty.
	/// - [`UrnValidationError::InvalidFormat`] -- `name` holds a `/` or a `:`.
	/// - [`UrnValidationError::InvalidNssCharacters`] -- `name` holds a
	///   character outside the `pchar` of RFC 3986 § 3.3, or a `%` that two hex
	///   digits do not follow.
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
	///
	/// # Errors
	///
	/// - The errors of [`ColonyNamespace::servlet`], for the same `name`.
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
	/// resource type. Each byte of it outside the NSS production of RFC 8141,
	/// such as a bracket of an IPv6 literal, is percent-encoded.
	pub fn hive(&self, addr: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let addr = addr.as_ref();
		if addr.is_empty() {
			return Err(UrnValidationError::RequiredFieldMissing("resource-id"));
		}

		self.mint(HIVE_SEGMENT, NssText::encode(addr))
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

	/// Whether the instance locator inside `info.servlet_id`, percent-decoded,
	/// equals the address advertised alongside it.
	///
	/// A servlet that advertises one address under the identity of another
	/// redirects that identity's traffic (CWE-639), so the two MUST agree.
	pub(crate) fn locator_matches(&self, info: &ServletInfo) -> bool {
		match self.validate(&info.servlet_id) {
			Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => {
				locator.decoded().as_ref() == info.address.as_slice()
			}
			_ => false,
		}
	}

	/// Mints `urn:{nid}:{realm}:{resource_type}:{id}` under this namespace.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::InvalidNssCharacters`] -- `id` breaks the NSS
	///   production. The NID and the realm cause no error, because
	///   [`Self::new`] refuses each one that would.
	fn mint(&self, resource_type: impl AsRef<str>, id: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let resource_type = resource_type.as_ref();
		let id = id.as_ref();
		let nss = format!("{}:{}:{}", self.realm, resource_type, id);
		Urn::from_parts(self.nid.as_ref(), nss)
	}

	/// Validates a URN against this namespace and parses its resource.
	///
	/// - The grammar check runs before any registry lookup.
	/// - The NID compares in any case, and the realm compares octet by octet,
	///   with the hex digits of each triplet in any case (RFC 8141 § 3.1).
	/// - Each registry key is the normalized form that [`Urn::canonical_bytes`]
	///   writes, so every name this method admits keys its resource alike.
	///
	/// # Errors
	///
	/// - [`UrnValidationError::ForbiddenFieldPresent`] -- the URN carries an
	///   r-, q-, or f-component, which the colony grammar does not define.
	/// - [`UrnValidationError::NidMismatch`] -- the authority differs from this namespace's NID.
	/// - [`UrnValidationError::RealmMismatch`] -- the realm differs from this namespace's realm.
	/// - [`UrnValidationError::RequiredFieldMissing`] -- the resource type or
	///   the resource id is absent, or the resource id, the servlet name, or
	///   the instance tail after a `/` is empty.
	/// - [`UrnValidationError::InvalidFormat`] -- the resource type is outside
	///   the vocabulary, or a colony name carries `/` or `:`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::urn::{ColonyNamespace, ColonyResource};
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// let namespace = ColonyNamespace::new("acme", "prod")?;
	///
	/// let hive: Urn<'static> = "urn:ACME:prod:hive:%5b::1%5d:9000".parse()?;
	/// let resource = namespace.validate(&hive)?;
	/// assert!(matches!(resource, ColonyResource::Hive { addr } if addr.decoded().as_ref() == b"[::1]:9000"));
	///
	/// let queried: Urn<'static> = "urn:acme:prod:servlet:beam?=x".parse()?;
	/// let refused = namespace.validate(&queried);
	/// assert_eq!(refused, Err(UrnValidationError::ForbiddenFieldPresent("q-component")));
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn validate<'a>(&self, urn: &'a Urn<'a>) -> Result<ColonyResource<'a>, UrnValidationError> {
		Self::refuse_optional_components(urn)?;
		if !urn.nid().eq_ignore_ascii_case(&self.nid) {
			return Err(UrnValidationError::NidMismatch);
		}

		let (realm, rest) = urn
			.nss()
			.split_once(':')
			.ok_or(UrnValidationError::RequiredFieldMissing("resource-type"))?;
		if NssText::segment(realm) != NssText::segment(&self.realm) {
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

				let instance = instance.map(NssText::segment);
				Ok(ColonyResource::Servlet { name, instance })
			}
			HIVE_SEGMENT => Ok(ColonyResource::Hive { addr: NssText::segment(id) }),
			// A colony name is one segment, so an id with a `/` or an extra `:`
			// names something outside the mintable grammar.
			COLONY_SEGMENT => {
				Self::validate_single_segment_name(id)?;
				Ok(ColonyResource::Colony { name: id })
			}
			_ => Err(UrnValidationError::InvalidFormat { field: "resource-type", pattern: None }),
		}
	}

	/// Refuses a URN that carries an optional component, and names the first
	/// one in the order of RFC 8141 § 2.
	fn refuse_optional_components(urn: &Urn<'_>) -> Result<(), UrnValidationError> {
		let components = [
			("r-component", urn.r_component()),
			("q-component", urn.q_component()),
			("f-component", urn.f_component()),
		];
		let carried = components.into_iter().find(|(_, component)| component.is_some());
		match carried {
			Some((name, _)) => Err(UrnValidationError::ForbiddenFieldPresent(name)),
			None => Ok(()),
		}
	}
}

impl Urn<'_> {
	/// Mints the instance URN under a servlet type: the type's URN with a
	/// `/{addr}` tail. The instance inherits the authority and realm of the
	/// type, so the call needs no namespace handle. Each byte of `addr`
	/// outside the NSS production of RFC 8141, such as a bracket of an IPv6
	/// literal, is percent-encoded.
	///
	/// # Errors
	///
	/// - The errors of [`Urn::from_parts`]. Every checked constructor meets
	///   its rules, so only a URN that `Urn::new_unchecked` builds outside
	///   [`urn!`](crate::urn!) can see one.
	pub fn servlet_instance(&self, addr: impl AsRef<str>) -> Result<Urn<'static>, UrnValidationError> {
		let nss = format!("{}/{}", self.nss(), NssText::encode(addr.as_ref()));
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

	/// The canonical bytes of a URN: its normalized form under RFC 8141 § 3.1,
	/// which equality and the hash read.
	///
	/// - The form is `urn:`, the NID in lower case, `:`, and the NSS with the
	///   hex digits of each percent-encoded triplet in upper case.
	/// - The optional components take no part in it.
	/// - Registries key by this form, so two URN-equivalent URNs key one entry in any process.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::urn::{Urn, UrnValidationError};
	///
	/// let urn: Urn<'static> = "URN:TightBeam::servlet:be%2aam?=x".parse()?;
	/// assert_eq!(urn.canonical_bytes(), b"urn:tightbeam::servlet:be%2Aam");
	/// # Ok::<(), UrnValidationError>(())
	/// ```
	pub fn canonical_bytes(&self) -> Vec<u8> {
		self.normalized().collect()
	}

	/// The canonical bytes with any instance tail cut off, which form the type
	/// key of an instance. The NID, the realm, and the servlet name exclude
	/// `/`, and the canonical form holds no optional component, so the first
	/// `/` in it always marks the tail.
	pub fn type_canonical_bytes(&self) -> Vec<u8> {
		let mut canonical = self.canonical_bytes();
		if let Some(tail) = canonical.iter().position(|byte| *byte == b'/') {
			canonical.truncate(tail);
		}

		canonical
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
/// Route selection keys on the canonical bytes this carries, so it runs on
/// a bare servlet type of the namespace alone. The namespace check runs where
/// [`ColonyNamespace::servlet_type_key`] mints the key, and a gateway mints
/// the key of its gossip ingress at start, under the namespace it serves.
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
impl ColonyNamespace {
	/// The servlet type `name` in the default namespace.
	pub(crate) fn servlet_fixture(name: impl AsRef<str>) -> Urn<'static> {
		let minted = ColonyNamespace::default().servlet(name);
		minted.expect("a fixture name satisfies the mint grammar")
	}

	/// The instance of the servlet type `name` at `locator`, in the default
	/// namespace.
	pub(crate) fn instance_fixture(name: impl AsRef<str>, locator: impl AsRef<str>) -> Urn<'static> {
		let minted = ColonyNamespace::servlet_fixture(name).servlet_instance(locator);
		minted.expect("a fixture locator satisfies the mint grammar")
	}

	/// The hive at `locator` in the default namespace.
	pub(crate) fn hive_fixture(locator: impl AsRef<str>) -> Urn<'static> {
		let minted = ColonyNamespace::default().hive(locator);
		minted.expect("a fixture locator satisfies the mint grammar")
	}

	/// The colony `name` in the default namespace.
	pub(crate) fn colony_fixture(name: impl AsRef<str>) -> Urn<'static> {
		let minted = ColonyNamespace::default().colony(name);
		minted.expect("a fixture name satisfies the mint grammar")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::TestResult;

	/// The namespace of the realm `prod-us`.
	fn prod() -> ColonyNamespace {
		ColonyNamespace::new("tightbeam", "prod-us").expect("the fixture realm is valid")
	}

	/// A namespace whose realm holds a percent-encoded space.
	fn encoded() -> ColonyNamespace {
		ColonyNamespace::new("tightbeam", "prod%20us").expect("the fixture realm is valid")
	}

	fn servlet(namespace: &ColonyNamespace, name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		let name = name.as_ref();
		namespace.servlet(name).expect("test names satisfy the mint grammar")
	}

	/// An instance of the servlet type `beam` whose locator is empty.
	fn empty_instance() -> Urn<'static> {
		instance_at(&servlet(&prod(), "beam"), "")
	}

	/// The instance of `bare` at `locator`, which names a servlet but is not a
	/// bare type.
	fn instance_at(bare: &Urn<'static>, locator: &str) -> Urn<'static> {
		let instance = bare.servlet_instance(locator);
		instance.expect("a servlet type URN yields an instance URN")
	}

	/// The same servlet name in another realm.
	fn foreign_servlet() -> Urn<'static> {
		let other = ColonyNamespace::new("tightbeam", "staging-eu").expect("the fixture realm is valid");
		servlet(&other, "beam")
	}

	// A bare servlet type of the namespace mints its canonical form as its
	// route key, and an instance locator or a foreign realm mints none.
	crate::tb_cases! {
		fn only_a_bare_servlet_type_mints_a_route_key((urn, key): (Urn<'static>, Option<&[u8]>)) {
			let minted = prod().servlet_type_key(&urn);

			assert_eq!(minted.as_ref().map(ServletTypeKey::as_bytes), key);
		}
		cases {
			bare => (servlet(&prod(), "beam"), Some(b"urn:tightbeam:prod-us:servlet:beam".as_slice())),
			instance_locator => (instance_at(&servlet(&prod(), "beam"), "10.0.0.5:9100"), None),
			foreign_realm => (foreign_servlet(), None),
		}
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

	// Each minted URN displays in its canonical form and validates as the
	// resource it names.
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
				instance_at(&servlet(&prod(), "beam"), "10.0.0.5:9100"),
				"urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100",
				ColonyResource::Servlet { name: "beam", instance: Some(NssText::segment("10.0.0.5:9100")) },
			),
			hive => (
				prod(),
				hive(&prod(), "10.0.0.5:9000"),
				"urn:tightbeam:prod-us:hive:10.0.0.5:9000",
				ColonyResource::Hive { addr: NssText::segment("10.0.0.5:9000") },
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
			encoded_realm => (
				encoded(),
				servlet(&encoded(), "beam"),
				"urn:tightbeam:prod%20us:servlet:beam",
				ColonyResource::Servlet { name: "beam", instance: None },
			),
		}
	}

	// The namespace refuses a URN of another authority or realm, and each URN
	// outside its grammar.
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

	// A namespace refuses a realm or an authority outside its grammar at
	// construction.
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
			hyphen_first_nid => ("-bad", "", UrnValidationError::InvalidNidStart),
			realm_outside_pchar => ("tightbeam", "prod us", UrnValidationError::InvalidNssCharacters),
			realm_with_a_short_triplet => ("tightbeam", "prod%2", UrnValidationError::InvalidNssCharacters),
		}
	}

	// Each case is a URN that RFC 8141 § 3.1 makes URN-equivalent to the
	// servlet type `be%2Aam` of `prod-us`.
	crate::tb_cases! {
		fn equivalent_servlet_types_mint_one_route_key(text: &str) -> TestResult {
			let urn: Urn<'static> = text.parse()?;
			let key = prod().servlet_type_key(&urn).map(|key| key.as_bytes().to_vec());
			assert_eq!(key, Some(b"urn:tightbeam:prod-us:servlet:be%2Aam".to_vec()));
			Ok(())
		}
		cases {
			as_minted => "urn:tightbeam:prod-us:servlet:be%2Aam",
			scheme_in_upper_case => "URN:tightbeam:prod-us:servlet:be%2Aam",
			nid_in_upper_case => "urn:TightBeam:prod-us:servlet:be%2Aam",
			hex_digits_in_lower_case => "urn:tightbeam:prod-us:servlet:be%2aam",
		}
	}

	// Each case is a colony URN that carries an optional component, beside
	// the component the refusal names.
	crate::tb_cases! {
		fn a_colony_urn_with_an_optional_component_is_refused((text, component): (&str, &'static str)) -> TestResult {
			let urn: Urn<'static> = text.parse()?;
			assert_eq!(prod().validate(&urn), Err(UrnValidationError::ForbiddenFieldPresent(component)));
			Ok(())
		}
		cases {
			servlet_r_component => ("urn:tightbeam:prod-us:servlet:beam?+r", "r-component"),
			servlet_q_component => ("urn:tightbeam:prod-us:servlet:beam?=a/b", "q-component"),
			servlet_f_component => ("urn:tightbeam:prod-us:servlet:beam#f", "f-component"),
			instance_q_component => ("urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100?=q", "q-component"),
			hive_r_component => ("urn:tightbeam:prod-us:hive:10.0.0.5:9000?+r", "r-component"),
			colony_f_component => ("urn:tightbeam:prod-us:colony:main#f", "f-component"),
		}
	}

	/// A realm compares as the rest of the NSS does, with the hex digits of
	/// each percent-encoded triplet in any case (RFC 8141 § 3.1).
	#[test]
	fn a_realm_compares_the_hex_digits_of_its_triplets_in_any_case() -> TestResult {
		let namespace = ColonyNamespace::new("tightbeam", "prod%2Cus")?;
		let urn: Urn<'static> = "urn:tightbeam:prod%2cus:servlet:beam".parse()?;
		let servlet = ColonyResource::Servlet { name: "beam", instance: None };
		assert_eq!(namespace.validate(&urn), Ok(servlet));
		Ok(())
	}

	// A URN's canonical bytes spell its scheme and its NID in lower case, the
	// hex digits of each triplet in upper case, and no optional component, and
	// its type canonical bytes spell its bare type the same way.
	crate::tb_cases! {
		fn the_canonical_bytes_are_the_normalized_form(
			(text, canonical, type_canonical): (&str, &str, &str)
		) -> TestResult {
			let urn: Urn<'static> = text.parse()?;
			let written = (urn.canonical_bytes(), urn.type_canonical_bytes());
			assert_eq!(written, (canonical.as_bytes().to_vec(), type_canonical.as_bytes().to_vec()));
			Ok(())
		}
		cases {
			as_minted => (
				"urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100",
				"urn:tightbeam:prod-us:servlet:beam/10.0.0.5:9100",
				"urn:tightbeam:prod-us:servlet:beam",
			),
			nid_and_hex_digits => (
				"URN:TightBeam:prod-us:servlet:be%2aam/%5b::1%5d:9000",
				"urn:tightbeam:prod-us:servlet:be%2Aam/%5B::1%5D:9000",
				"urn:tightbeam:prod-us:servlet:be%2Aam",
			),
			optional_components => (
				"urn:tightbeam:prod-us:servlet:ping?=a/b#f",
				"urn:tightbeam:prod-us:servlet:ping",
				"urn:tightbeam:prod-us:servlet:ping",
			),
		}
	}

	// The type canonical bytes of a servlet URN are the canonical bytes of
	// its bare type, with or without an instance tail.
	crate::tb_cases! {
		fn type_canonical_bytes_name_the_bare_type(urn: Urn<'static>) {
			let written = urn.type_canonical_bytes();
			assert_eq!(written, b"urn:tightbeam:prod-us:servlet:beam");
		}
		cases {
			of_an_instance => instance_at(&servlet(&prod(), "beam"), "10.0.0.5:9100"),
			of_a_bare_type => servlet(&prod(), "beam"),
		}
	}

	// The type prefix of `beam` starts the key of each `beam` instance, and
	// the key of no instance of a type whose name extends `beam`.
	crate::tb_cases! {
		fn the_type_prefix_bounds_instance_keys_to_one_type((instance, inside): (Urn<'static>, bool)) {
			let prefix = servlet(&prod(), "beam").type_prefix_bytes();
			assert_eq!(instance.canonical_bytes().starts_with(&prefix), inside);
		}
		cases {
			an_instance_of_the_type => (instance_at(&servlet(&prod(), "beam"), "10.0.0.5:9100"), true),
			an_instance_of_a_longer_name => (instance_at(&servlet(&prod(), "beam2"), "10.0.0.5:9200"), false),
		}
	}

	/// The outcome of one mint, and the refusal it must be.
	type MintCase = (Result<Urn<'static>, UrnValidationError>, UrnValidationError);

	// A mint refuses a name outside the mint grammar.
	crate::tb_cases! {
		fn names_outside_the_mint_grammar_are_refused_at_mint((minted, error): MintCase) {
			assert_eq!(minted.err(), Some(error));
		}
		cases {
			servlet_outside_pchar => (prod().servlet("be am"), UrnValidationError::InvalidNssCharacters),
			colony_outside_pchar => (prod().colony("ma in"), UrnValidationError::InvalidNssCharacters),
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
