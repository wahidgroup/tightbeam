//! The peer plane of a cluster gateway: hop budgets, peer-advertisement
//! admission, relay trails, and the flood a gateway gossips in.

use std::sync::Arc;

use super::runtime::VerifiedControlFrame;
use super::{
	AdmittedDial, ClusterConfig, DialTarget, Party, PeerConfig, PeerHint, PheromoneConfig, RelayRoute, RouteKind,
	ServletEntry, SharedId,
};
use crate::colony::protocol::IssuedAt;
use crate::colony::protocol::{ClusterWorkRequest, PeerAdvertisement};
use crate::colony::urn::ColonyNamespace;
use crate::colony::urn::ColonyResource;
use crate::constants::{DEFAULT_HOP_BUDGET, MAX_ADVERTISED_TYPES};
use crate::crypto::hash::Digest;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::utils::{CertificateExt, Fingerprint};
use crate::crypto::x509::Certificate;
use crate::policy::TransitStatus;
use crate::transport::multiplex::StreamRoute;
use crate::urn::Urn;
use crate::utils::time::UnixMillis;
use crate::x509::ext::pkix::name::GeneralName;
use crate::x509::ext::pkix::SubjectAltName;

/// The forwards that a work request or a routed stream open has left to spend.
///
/// The gateway parses the raw wire count once at its boundary through
/// [`HopBudget::from_wire`], clamped to [`PeerConfig::max_hops`]. Every later
/// rule reads the clamped value, so the operator's cap bounds the forwards a
/// peer can spend (CWE-770).
///
/// [`PeerConfig::max_hops`]: super::PeerConfig::max_hops
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopBudget {
	/// The forwards this gateway has left to spend, under the operator's cap.
	remaining: u8,
	/// Whether the sender already spent part of the budget.
	relayed: bool,
}

/// The hop budget octet as a peer sent it, before the local clamp.
///
/// The octet tells an origin request from a relayed one, so it is a type
/// apart from the operator's cap that clamps it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireHopBudget(u8);

impl WireHopBudget {
	/// The budget octet a peer sent.
	#[must_use]
	pub const fn new(hops: u8) -> Self {
		Self(hops)
	}

	/// The octet, for the clamp that consumes it.
	#[must_use]
	pub const fn get(self) -> u8 {
		self.0
	}
}

impl HopBudget {
	/// Clamps a wire budget to the operator's cap.
	///
	/// An origin request, which carries the sentinel budget, takes the local
	/// cap. The wire value decides whether a peer already relayed the request,
	/// so it arrives as its own type that a call site cannot swap with the cap
	/// (CWE-639).
	#[must_use]
	pub fn from_wire(wire: WireHopBudget, max_hops: u8) -> Self {
		let hops = wire.get();
		Self { remaining: hops.min(max_hops), relayed: hops != DEFAULT_HOP_BUDGET }
	}

	/// Spends one forward and stops at zero.
	#[must_use]
	pub fn spend(self) -> Self {
		Self { remaining: self.remaining.saturating_sub(1), relayed: self.relayed }
	}

	/// Whether a peer already spent part of this budget.
	///
	/// An origin request carries the sentinel, so anything below it reached
	/// this gateway through at least one relay. The export boundary reads
	/// this to tell a direct caller from a relayed one.
	///
	/// # Wire count
	///
	/// [`Self::from_wire`] reads it from the wire count before the clamp,
	/// because a cap below the sentinel would make every origin request look
	/// relayed.
	#[must_use]
	pub fn is_relayed(&self) -> bool {
		self.relayed
	}

	/// Whether the budget affords the forwards that a route of `kind` spends.
	///
	/// - A local route spends no forward.
	/// - A peer route spends one forward.
	/// - A relay trail spends one forward at the relay before it reaches the owner, so it needs two.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::{HopBudget, RouteKind, WireHopBudget};
	///
	/// let budget = HopBudget::from_wire(WireHopBudget::new(1), 4);
	/// assert!(budget.affords(RouteKind::Peer));
	/// assert!(!budget.affords(RouteKind::PeerRelay));
	/// ```
	#[must_use]
	pub fn affords(&self, kind: RouteKind) -> bool {
		match kind {
			RouteKind::Local => true,
			RouteKind::Peer => self.remaining > 0,
			RouteKind::PeerRelay => self.remaining >= 2,
		}
	}

	/// Whether the budget affords a forward to a peer gateway, as
	/// [`Self::affords`] decides for [`RouteKind::Peer`].
	#[must_use]
	pub fn allows_forward(&self) -> bool {
		self.affords(RouteKind::Peer)
	}

	/// Whether the budget affords the two forwards a relay trail needs, as
	/// [`Self::affords`] decides for [`RouteKind::PeerRelay`].
	#[must_use]
	pub fn allows_relay_trail(&self) -> bool {
		self.affords(RouteKind::PeerRelay)
	}

	/// The count this budget puts back on the wire.
	#[must_use]
	pub fn wire(&self) -> u8 {
		self.remaining
	}

	/// The relayed stream route of one peer hop out of this budget.
	///
	/// The route reaches the same `target` with one forward spent, so a relay
	/// pays for every route it stamps (CWE-834).
	#[must_use]
	pub(crate) fn relayed_route(self, target: &Urn<'static>) -> StreamRoute {
		StreamRoute::relayed_to(target.clone(), self.spend().wire())
	}

	/// The relayed work envelope of one peer hop out of this budget.
	///
	/// Unary work spends its hop here, as a routed stream spends it in
	/// [`Self::relayed_route`]. `payload` is the client's encoded frame and
	/// travels opaque, so a relay hop forwards the bytes it received.
	#[must_use]
	pub(crate) fn relayed_work(self, servlet_type: Urn<'static>, payload: impl Into<Vec<u8>>) -> ClusterWorkRequest {
		let payload: Vec<u8> = payload.into();
		ClusterWorkRequest { servlet_type, payload, hops_remaining: self.spend().wire() }
	}

	/// A budget under a cap of the sentinel [`DEFAULT_HOP_BUDGET`], so the wire
	/// count a test picks passes unclamped.
	#[cfg(test)]
	pub(crate) fn for_test(wire: u8) -> Self {
		Self::from_wire(WireHopBudget::new(wire), DEFAULT_HOP_BUDGET)
	}
}

/// A peer advertisement that passed signer resolution and the wire checks.
///
/// The registry receives this type only after those checks, so the signer
/// identity and the claimed dial address each arrive in their own field.
pub struct AdmittedPeerAd {
	/// The fingerprint of the signer certificate, which keys the slate.
	pub(super) peer_hive_id: SharedId,
	/// The claimed gateway socket, parsed and admitted once. Every slate entry
	/// dials it, so a score lookup and a stored route agree on one socket. The
	/// discovery hint carries it as the proof that the dial policy admitted it.
	pub(super) dial: AdmittedDial,
	/// The peer-routed entries, keyed by `peer_hive_id NUL type`.
	pub(super) slate: Vec<ServletEntry>,
	/// The issue order of the signed advertisement frame. Reconciliation
	/// refuses an order older than the newest applied (CWE-294).
	pub(super) order: UnixMillis,
}

/// The fallback trails of one admitted advertisement through one relay.
///
/// The slate reconciles under the composite `origin NUL relay` bucket
/// (`ServletRegistry::reconcile_relay_trail`), so a trail outlives a new direct
/// slate from the origin. An empty direct advertisement removes it with the
/// direct routes. It also leaves when the relay it dials is evicted, and the
/// stale-trail prune drops an idle trail.
pub struct RelayTrail {
	/// The composite `origin NUL relay` bucket this slate reconciles under.
	pub(super) bucket: SharedId,
	/// The origin whose types the trails reach, and the owner of every
	/// route in the bucket.
	pub(super) origin: SharedId,
	/// The relay-routed entries, keyed by `bucket NUL type`.
	pub(super) slate: Vec<ServletEntry>,
	/// The issue order of the advertisement that the trails derive from.
	pub(super) order: UnixMillis,
}

impl AdmittedPeerAd {
	/// Admits a wire advertisement, or fails closed with a refusal status.
	///
	/// The checks run in this order:
	///
	/// 1. The signer MUST resolve on the peer plane, and the slate keys by its
	///    name under [`TrustPlanes::peer_identity`], whatever `gateway_addr` it
	///    claims.
	/// 2. This gateway MUST be in a flood, and the signer MUST be a member of it.
	/// 3. [`PeerConfig::admit_claim`] MUST admit the claimed address, and the
	///    advertised types MUST be bare servlet types within the type cap.
	///
	/// Caps and local-route conflicts are registry policy under
	/// [`super::ServletRegistry::reconcile_peer_slate`].
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- a check above refuses the advertisement.
	///
	/// [`TrustPlanes::peer_identity`]: super::TrustPlanes::peer_identity
	pub(crate) fn admit(
		verified: &VerifiedControlFrame<'_>,
		ad: &PeerAdvertisement,
		conf: &ClusterConfig,
	) -> Result<Self, TransitStatus> {
		if !matches!(verified.party(), Party::Peer) {
			return Err(TransitStatus::PermissionDenied);
		}

		let frame = verified.frame();
		// The control-frame parse resolved the signer certificate and its slate
		// key, so the membership gate and the slate both read that parse.
		let signer_cert = verified.signer_cert();
		let peer_hive_id = verified.fingerprint().into_shared();

		// Federation is a colony operation, so this gateway and the advertiser
		// must both carry a valid colony URN SAN. A certificate without one
		// serves general transport and work, and grants no membership.
		let Some(flood) = conf.flood() else {
			return Err(TransitStatus::PermissionDenied);
		};
		flood.member(signer_cert)?;

		let dial = peer_advertisement_wire_ok(&ad.gateway_addr, &ad.advertised_types, &conf.namespace, &conf.peer)?;

		// Routes carry the admitted socket itself, so a later lookup by
		// address finds them whatever the peer wrote on the wire.
		let slate = conf.pheromone.peer_slate(&peer_hive_id, dial, &ad.advertised_types);

		Ok(Self { peer_hive_id, dial, slate, order: frame.issued_at() })
	}

	/// The relay trails through `relay_id`, the gateway that relayed this
	/// advertisement: one trail per advertised type, each to `relay_dial`, the
	/// relay's admitted gateway socket. It is `None` when the relay is the
	/// origin itself or the slate is empty.
	///
	/// # Failover
	///
	/// The route registry then holds two trails per type: the direct trail to
	/// the origin and a relay trail through the relaying peer. Pheromone
	/// feedback can fail over to the relay when the origin is unreachable.
	#[must_use]
	pub fn relay_trail(
		&self,
		relay_id: &SharedId,
		relay_dial: AdmittedDial,
		pheromone: &PheromoneConfig,
	) -> Option<RelayTrail> {
		if relay_id.as_ref() == self.peer_hive_id.as_ref() {
			return None;
		}
		if self.slate.is_empty() {
			return None;
		}

		// The trails dial one relay socket, so they share one rendering of it.
		let bucket = ServletEntry::relay_bucket(&self.peer_hive_id, relay_id);
		let target = DialTarget::of_claimed(relay_dial);
		let PheromoneConfig { initial_pheromone, abandonment_limit, .. } = *pheromone;
		let slate: Vec<ServletEntry> = self
			.slate
			.iter()
			.map(|entry| {
				let route = RelayRoute {
					origin_id: Arc::clone(&self.peer_hive_id),
					relay_id: Arc::clone(relay_id),
					servlet_type: Arc::clone(entry.servlet_type()),
					dial: relay_dial,
				};
				ServletEntry::peer_relay_sharing(route, &target, initial_pheromone, abandonment_limit)
			})
			.collect();

		Some(RelayTrail { bucket, origin: Arc::clone(&self.peer_hive_id), slate, order: self.order })
	}

	/// The discovery hint of this admitted advertisement: the verified
	/// signer's admitted dial address and its certificate fingerprint.
	///
	/// The hint owns its fields, because it outlives this advertisement in the
	/// peer table. Every admitted advertiser is a flood member, so each yields
	/// a hint.
	///
	/// # Unproven address
	///
	/// The advertiser dialed this gateway, so nothing proves the claimed
	/// address dials back yet. The peer table holds the hint in `new` until
	/// this gateway's own probe proves membership, the way the Bitcoin
	/// address manager holds a self-announced address.
	#[must_use]
	pub fn discovery_hint(&self) -> PeerHint {
		PeerHint { dial: self.dial, peer_id: Some(self.peer_hive_id.to_vec()) }
	}
}

/// Runs the wire-level advertisement checks, outside the registry lock.
fn peer_advertisement_wire_ok(
	gateway_addr: impl AsRef<[u8]>,
	types: impl AsRef<[Urn<'static>]>,
	namespace: &ColonyNamespace,
	peer: &PeerConfig,
) -> Result<AdmittedDial, TransitStatus> {
	let gateway_addr = gateway_addr.as_ref();
	let types = types.as_ref();
	// The dial policy is the whole check on the claimed address, so the
	// admitted value is both the proof and what the caller keeps.
	let dial = peer.admit_claim(gateway_addr).map_err(|_| TransitStatus::PermissionDenied)?;

	let types_valid = namespace.all_bare_servlet_types(types);
	let within_type_cap = types.len() <= MAX_ADVERTISED_TYPES;
	if types_valid && within_type_cap {
		Ok(dial)
	} else {
		Err(TransitStatus::PermissionDenied)
	}
}

/// The flood this gateway gossips in: the scope a rumor, a reconcile round,
/// a repair, and a peer exchange travel inside.
///
/// [`ClusterConfig::flood`] builds one.
///
/// # Scope
///
/// The flood is the namespace. A member is a gateway whose key the peer trust
/// store holds, with a certificate there that carries a colony URN of this
/// namespace, whichever colony it names. Every inbound gossip frame and
/// outbound gossip dial asks [`Self::member`], the one home of that rule.
///
/// - Colonies are the parties, and the flood is the state they share. Work
///   federation admits the same set, so one rule decides both planes.
/// - The peer trust store is the share set. A gateway receives rumors only
///   from origins it trusts, so different trust stores divide one namespace
///   into subnets.
/// - A trusted certificate with no colony URN of the namespace is outside every flood.
/// - Each question reads the store, so a change at run time takes effect at once.
/// - A certificate authority in the store admits no gateway, because the
///   store must hold the certificate of each key that signs a frame.
/// - A gateway with no peer plane dials its peers on the hive pool, so its
///   hive trust store is the list ([`ClusterTlsConfig::peer_dial_trust`]).
///
/// [`ClusterTlsConfig::peer_dial_trust`]: super::ClusterTlsConfig::peer_dial_trust
#[derive(Debug, Clone, Copy)]
pub(crate) struct Flood<'a> {
	namespace: &'a ColonyNamespace,
	/// The store this gateway dials its peers under, which is the list of
	/// parties. With no store the flood has no member.
	peer_trust: Option<&'a dyn CertificateTrust>,
}

/// The proof that a certificate belongs to a [`Flood`].
///
/// [`Flood::member`] is the only constructor, so a value of this type means
/// the membership rule ran on a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FloodMember(());

impl<'a> Flood<'a> {
	/// The flood of a member gateway under `namespace`, with `peer_trust` as
	/// its list of parties.
	fn new(namespace: &'a ColonyNamespace, peer_trust: Option<&'a dyn CertificateTrust>) -> Self {
		Self { namespace, peer_trust }
	}

	/// Decides whether the gateway that holds `cert` belongs to this flood.
	///
	/// The rule reads the certificate the store holds for the key of `cert`.
	///
	/// - With a peer plane, a frame signature verifies against that same
	///   certificate, so this gateway sends a rumor only to a gateway whose
	///   signed frames it admits (CWE-668).
	/// - With no peer plane the gateway publishes only: it sends on its hive
	///   trust store and admits no peer frame.
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- the certificate is outside the flood.
	pub(crate) fn member(&self, cert: &Certificate) -> Result<FloodMember, TransitStatus> {
		let enrolled = self.peer_trust.and_then(|trust| trust.enrolled_certificate(cert));
		let colony = enrolled.and_then(|enrolled| self.namespace.cert_colony_urn(enrolled));
		if colony.is_none() {
			return Err(TransitStatus::PermissionDenied);
		}

		Ok(FloodMember(()))
	}
}

impl ClusterConfig {
	/// The flood this gateway gossips in.
	///
	/// It returns `None` for a gateway whose certificate carries no colony
	/// URN, which gossips nothing. The constructor of [`Flood`] is private to
	/// this file, so a flood exists only where this method builds one.
	#[must_use]
	pub(crate) fn flood(&self) -> Option<Flood<'_>> {
		self.colony_urn.as_ref()?;

		Some(Flood::new(&self.namespace, self.tls.peer_dial_trust()))
	}

	/// The proof that the gateway which presented `answer` in a handshake
	/// belongs to this gateway's flood, or `None` when [`Flood::member`]
	/// refuses it or this gateway is in no flood.
	///
	/// A gossip dial sends only on this proof, and an advertisement's
	/// connection stays pooled only on it.
	#[must_use]
	pub(crate) fn flood_member(&self, answer: &Certificate) -> Option<FloodMember> {
		let flood = self.flood()?;
		flood.member(answer).ok()
	}
}

impl ColonyNamespace {
	/// The colony URN a certificate asserts, when exactly one is present.
	///
	/// Membership binds to the URI SAN (RFC 5280 §4.2.1.6) alone. It skips
	/// non-URI SANs and URIs that fail colony validation in this namespace.
	///
	/// It returns `None` in each case below, so an ambiguous identity fails
	/// closed (CWE-706):
	///
	/// - The extension is absent or malformed.
	/// - No entry validates.
	/// - More than one distinct colony URN is present.
	#[must_use]
	pub fn cert_colony_urn(&self, cert: &Certificate) -> Option<Urn<'static>> {
		let mut colony: Option<Urn<'static>> = None;

		let san: SubjectAltName = cert.extension().ok()??;
		for entry in &san.0 {
			let GeneralName::UniformResourceIdentifier(uri) = entry else {
				continue;
			};
			let Ok(urn) = uri.as_str().parse::<Urn<'static>>() else {
				continue;
			};
			if !matches!(self.validate(&urn), Ok(ColonyResource::Colony { .. })) {
				continue;
			}

			match colony.as_ref() {
				Some(existing) if *existing == urn => {}
				Some(_) => return None,
				None => colony = Some(urn),
			}
		}

		colony
	}
}

/// The peer identity of a certificate.
pub(crate) trait ColonyCertificate {
	/// Returns the stable peer key, the certificate's fingerprint under `D`.
	///
	/// Slates and misbehavior scores key on the fingerprint of the certificate
	/// that [`TrustPlanes::peer_identity`] resolves, so a peer keeps one
	/// identity across every `gateway_addr` it advertises. A certificate with
	/// no fingerprint gives `None`, so an unidentifiable peer fails closed.
	///
	/// [`TrustPlanes::peer_identity`]: super::TrustPlanes::peer_identity
	fn fingerprint_id<D: Digest>(&self) -> Option<SharedId>;
}

impl ColonyCertificate for Certificate {
	fn fingerprint_id<D: Digest>(&self) -> Option<SharedId> {
		let fingerprint = Fingerprint::<D>::from_certificate(self).ok()?;
		Some(Arc::from(fingerprint.as_slice()))
	}
}

#[cfg(test)]
mod tests {
	use super::super::RouteKind;
	use super::*;
	use crate::colony::cluster::{ColonyDigest, PeerAddress};
	use crate::testing::{unhex, TestCertificate, TestKey};
	use crate::transport::tcp::r#async::TokioListener;

	/// The SHA3-256 digest of the DER of the fixed test certificate, computed
	/// with Python's `hashlib.sha3_256`.
	const HOUSE_GATEWAY_ID: &str = "ec636319b64960969b307426b727616ab7692df941b0a96b52a9c13f1f077b4c";

	/// A gateway under the house provider goes by the SHA3-256 fingerprint of
	/// its certificate, the digest its protocol's provider names.
	#[test]
	fn a_house_gateway_goes_by_its_sha3_256_fingerprint() {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let id = certificate.fingerprint_id::<ColonyDigest<TokioListener>>();
		assert_eq!(id.as_deref(), Some(unhex(HOUSE_GATEWAY_ID).as_slice()));
	}

	// A budget of one forward reaches a local servlet and a peer gateway, and a
	// relay trail needs the second forward that the relay spends.
	crate::tb_cases! {
		fn a_budget_of_one_affords_a_peer_route_and_not_a_relay_trail(
			(kind, afforded): (RouteKind, bool)
		) -> Result<(), Box<dyn core::error::Error>> {
			let budget = HopBudget::for_test(1);
			assert_eq!(budget.affords(kind), afforded);
			Ok(())
		}
		cases {
			a_local_route => (RouteKind::Local, true),
			a_peer_route => (RouteKind::Peer, true),
			a_relay_trail => (RouteKind::PeerRelay, false),
		}
	}

	/// A colony URN under another naming authority.
	fn foreign_colony() -> Urn<'static> {
		let foreign = ColonyNamespace::new("acme", "").unwrap_or_default();
		foreign.colony("main").expect("static colony name")
	}

	fn nestmate_ns() -> ColonyNamespace {
		ColonyNamespace::default()
	}

	fn ping_type() -> Urn<'static> {
		nestmate_ns().servlet("ping").expect("static servlet name")
	}

	/// A parsed dial address, which every fixture spelling names.
	fn address(spelling: &str) -> PeerAddress {
		PeerAddress::fixture(spelling)
	}

	/// One socket spelled two ways is one entry, so an address that passes the
	/// hint gate also passes the advertisement gate. An ad that spells its
	/// socket verbosely installs routes under the canonical key, so a later
	/// score or eviction lookup by that address finds them.
	#[test]
	fn an_ad_spelling_its_socket_verbosely_routes_under_the_canonical_key() {
		let verbose = address("[0:0:0:0:0:0:0:1]:9000");
		let canonical = address("[::1]:9000");
		assert_eq!(verbose.route_bytes(), canonical.route_bytes());
		assert_eq!(verbose.route_bytes().as_ref(), b"[::1]:9000");
	}

	#[test]
	fn advertised_types_accept_bare_reject_instance() {
		let ns = nestmate_ns();
		let bare = ping_type();
		assert!(ns.all_bare_servlet_types(core::slice::from_ref(&bare)));

		let instance = bare
			.servlet_instance("127.0.0.1:1")
			.expect("a servlet type URN yields an instance URN");
		assert!(!ns.all_bare_servlet_types(&[instance]));
	}

	/// The pheromone settings the slate tests read: the shipped defaults, so a
	/// changed default shows up in these tests.
	fn test_pheromone() -> PheromoneConfig {
		PheromoneConfig::default()
	}

	#[test]
	fn build_peer_slate_keys_by_hive_and_sets_dial() {
		let hive: SharedId = Arc::from([1u8; 32].as_slice());
		let slate = test_pheromone().peer_slate(&hive, AdmittedDial::fixture("127.0.0.1:9000"), &[ping_type()]);
		assert_eq!(slate.len(), 1);
		assert_eq!(slate[0].route_kind(), RouteKind::Peer);
		assert_eq!(slate[0].dial_target().as_bytes(), b"127.0.0.1:9000");
		assert_eq!(slate[0].owner_id().as_ref(), hive.as_ref());
		assert_eq!(slate[0].route_key()[0], 1);
		assert_eq!(slate[0].route_key()[32], 0);
	}

	fn admitted_ad(origin: &SharedId, dial: impl AsRef<str>, types: impl AsRef<[Urn<'static>]>) -> AdmittedPeerAd {
		let dial = AdmittedDial::fixture(dial);
		let types = types.as_ref();
		let slate = test_pheromone().peer_slate(origin, dial, types);
		AdmittedPeerAd { peer_hive_id: Arc::clone(origin), dial, slate, order: UnixMillis::new(0) }
	}

	#[test]
	fn discovery_hint_names_the_advertiser() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let ad = admitted_ad(&origin, "127.0.0.1:9000", &[ping_type()]);

		let hint = ad.discovery_hint();
		assert_eq!(hint.dial, AdmittedDial::fixture("127.0.0.1:9000"));
		assert_eq!(hint.peer_id.as_deref(), Some(origin.as_ref()));
	}

	/// The fixture socket at which peers dial the relay gateway.
	fn relay_dial() -> AdmittedDial {
		AdmittedDial::fixture("127.0.0.1:9001")
	}

	fn some_trail(trail: Option<RelayTrail>) -> RelayTrail {
		trail.expect("relay trail for a distinct relay with a live slate")
	}

	#[test]
	fn relay_trail_none_for_self_relay() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let ad = admitted_ad(&origin, "127.0.0.1:9000", &[ping_type()]);
		let trail = ad.relay_trail(&origin, relay_dial(), &PheromoneConfig::default());
		assert!(trail.is_none());
	}

	#[test]
	fn relay_trail_none_for_empty_slate() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let relay: SharedId = Arc::from([2u8; 32].as_slice());
		let ad = admitted_ad(&origin, "127.0.0.1:9000", &[]);
		let trail = ad.relay_trail(&relay, relay_dial(), &PheromoneConfig::default());
		assert!(trail.is_none());
	}

	#[test]
	fn relay_trail_buckets_by_origin_and_relay() {
		let origin: SharedId = Arc::from([1u8; 32].as_slice());
		let relay: SharedId = Arc::from([2u8; 32].as_slice());
		let ad = admitted_ad(&origin, "127.0.0.1:9000", &[ping_type()]);
		let trail = some_trail(ad.relay_trail(&relay, relay_dial(), &PheromoneConfig::default()));

		let expected_bucket: Vec<u8> = [origin.as_ref(), &[0u8], relay.as_ref()].concat();
		assert_eq!(trail.bucket.as_ref(), expected_bucket.as_slice());
		assert_eq!(trail.slate.len(), 1);
		assert_eq!(trail.slate[0].route_kind(), RouteKind::PeerRelay);
		assert_eq!(trail.slate[0].bucket().as_ref(), expected_bucket.as_slice());
		assert_eq!(trail.slate[0].owner_id().as_ref(), origin.as_ref());
		assert_eq!(trail.slate[0].relay_id().map(|id| id.as_ref()), Some(relay.as_ref()));
		assert_eq!(trail.slate[0].dial_target().as_bytes(), b"127.0.0.1:9001");
	}

	#[test]
	fn peer_advertisement_wire_ok_refuses_bad_dial() {
		let ns = nestmate_ns();
		let status = peer_advertisement_wire_ok(b"", &[ping_type()], &ns, &PeerConfig::default());
		assert_eq!(status, Err(TransitStatus::PermissionDenied));
	}

	#[test]
	fn peer_advertisement_wire_ok_refuses_allowlist_miss() {
		let ns = nestmate_ns();
		let allow = PeerConfig::allowing(["10.0.0.1:9000"]);
		let status = peer_advertisement_wire_ok(b"127.0.0.1:9000", &[ping_type()], &ns, &allow);
		assert_eq!(status, Err(TransitStatus::PermissionDenied));
	}

	mod colony_urn {
		use super::*;
		use crate::testing::fixtures::{TestCertificate, TestKey};

		fn main_colony() -> Urn<'static> {
			nestmate_ns().colony("main").expect("static colony name")
		}

		fn other_colony() -> Urn<'static> {
			nestmate_ns().colony("other").expect("static colony name")
		}

		#[test]
		fn cert_colony_urn_extracts_a_valid_san() {
			let key = TestKey::insecure_fixed_signing();
			let cert = TestCertificate::with_uri_sans(&key, &[&main_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_ignores_non_colony_entries() {
			let key = TestKey::insecure_fixed_signing();
			let servlet = ping_type().to_string();
			let cert =
				TestCertificate::with_uri_sans(&key, &[&servlet, "https://example.test", &main_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_tolerates_duplicate_identical_entries() {
			let key = TestKey::insecure_fixed_signing();
			let urn = main_colony().to_string();
			let cert = TestCertificate::with_uri_sans(&key, &[&urn, &urn]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), Some(main_colony()));
		}

		#[test]
		fn cert_colony_urn_fails_closed_on_ambiguity() {
			let key = TestKey::insecure_fixed_signing();
			let cert = TestCertificate::with_uri_sans(&key, &[&main_colony().to_string(), &other_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), None);
		}

		#[test]
		fn cert_colony_urn_is_none_without_san() {
			let key = TestKey::insecure_fixed_signing();
			let cert = TestCertificate::self_signed(&key);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), None);
		}

		#[test]
		fn cert_colony_urn_is_none_for_foreign_namespace() {
			let key = TestKey::insecure_fixed_signing();
			let cert = TestCertificate::with_uri_sans(&key, &[&foreign_colony().to_string()]);
			assert_eq!(nestmate_ns().cert_colony_urn(&cert), None);
		}
	}

	mod flood {
		use super::*;
		use crate::crypto::policy::Secp256k1Policy;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::crypto::x509::store::{CertificateTrustBuilder, CertificateTrustStore, NoRevocation, TrustBuilder};
		use crate::crypto::x509::KeyCurves;
		use crate::tb_cases;
		use crate::testing::fixtures::{TestCertificate, TestKey};

		/// The colony URN of `name` in the test namespace.
		fn colony(name: &str) -> String {
			let urn = nestmate_ns().colony(name).expect("static colony name");
			urn.to_string()
		}

		/// What [`Flood::member`] answers.
		type Answer = Result<FloodMember, TransitStatus>;

		/// The answer the flood of the test namespace gives a certificate that
		/// carries `sans`.
		fn membership(sans: &[String]) -> Answer {
			let sans: Vec<&str> = sans.iter().map(String::as_str).collect();
			let key = TestKey::insecure_fixed_signing();
			let cert = TestCertificate::with_uri_sans(&key, &sans);

			let ns = nestmate_ns();
			let store = store_holding(&cert);
			let flood = Flood::new(&ns, Some(&store));

			flood.member(&cert)
		}

		/// A peer trust store that holds `cert` alone.
		fn store_holding(cert: &Certificate) -> CertificateTrustStore {
			let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
			let builder = builder.with_certificate(cert.clone());
			builder.expect("the test certificate satisfies the trust builder").build()
		}

		/// A certificate of colony "main" under a key no fixture store holds.
		fn unenrolled_member_cert() -> Certificate {
			let key = Secp256k1SigningKey::from_bytes(&[2u8; 32].into()).expect("the fixture scalar is a valid key");
			TestCertificate::with_cn_and_uri_sans(&key, "Unenrolled", &[&colony("main")])
		}

		// The certificate names a colony of the namespace, and the store holds
		// another key.
		#[test]
		fn a_key_the_store_does_not_hold_is_outside_the_flood() {
			let key = TestKey::insecure_fixed_signing();
			let enrolled = TestCertificate::with_uri_sans(&key, &[&colony("main")]);

			let ns = nestmate_ns();
			let store = store_holding(&enrolled);
			let flood = Flood::new(&ns, Some(&store));
			assert_eq!(flood.member(&unenrolled_member_cert()), OUTSIDE);
		}

		#[test]
		fn a_flood_with_no_peer_trust_has_no_member() {
			let ns = nestmate_ns();
			let flood = Flood::new(&ns, None);
			assert_eq!(flood.member(&unenrolled_member_cert()), OUTSIDE);
		}

		const MEMBER: Answer = Ok(FloodMember(()));
		const OUTSIDE: Answer = Err(TransitStatus::PermissionDenied);

		tb_cases! {
			fn the_flood_decides_membership_from_the_certificate((sans, answer): (Vec<String>, Answer)) {
				assert_eq!(membership(&sans), answer);
			}
			cases {
				one_colony => (vec![colony("main")], MEMBER),
				another_colony => (vec![colony("other")], MEMBER),
				no_colony => (vec![], OUTSIDE),
				another_namespace => (vec![foreign_colony().to_string()], OUTSIDE),
				two_colonies => (vec![colony("main"), colony("other")], OUTSIDE),
			}
		}
	}
}
