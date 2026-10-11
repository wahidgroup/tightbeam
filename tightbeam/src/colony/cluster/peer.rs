//! Peer-advertisement admission for the cluster gateway.

use std::sync::Arc;

use super::runtime::VerifiedControlFrame;
use super::{
	AdmittedDial, ClusterConfig, Party, PeerConfig, PeerHint, PheromoneConfig, RelayRoute, ServletEntry, SharedId,
};
use crate::colony::common::ColonyResource;
use crate::colony::common::IssuedAt;
use crate::colony::common::{ClusterWorkRequest, ColonyNamespace, PeerAdvertisement};
use crate::constants::{DEFAULT_HOP_BUDGET, MAX_ADVERTISED_TYPES};
use crate::crypto::hash::Sha3_256;
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustStore};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::Certificate;
use crate::policy::TransitStatus;
use crate::transport::multiplex::StreamRoute;
use crate::utils::time::UnixMillis;
use crate::utils::urn::Urn;
use crate::x509::ext::pkix::name::GeneralName;
use crate::x509::ext::pkix::SubjectAltName;

/// Forwards a work request or routed stream open may still spend.
///
/// The wire carries a raw count, so the budget is parsed once at the
/// gateway boundary through [`HopBudget::from_wire`], which clamps it to
/// the operator's [`PeerConfig::max_hops`]. Every downstream rule reads
/// this value rather than the raw octet, so the operator's cap bounds the
/// forwards a peer can spend (CWE-770).
///
/// [`PeerConfig::max_hops`]: super::PeerConfig::max_hops
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopBudget {
	/// Forwards this gateway may still spend, under the operator's cap.
	remaining: u8,
	/// Whether the sender already spent part of the budget.
	relayed: bool,
}

/// The hop budget octet as a peer sent it, before the local clamp.
///
/// The wire octet separates an origin request from a relayed one, so it is
/// a distinct type from the operator's cap that clamps it.
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
	/// An origin request carries the sentinel budget, so the clamp also
	/// stamps the origin with the local cap. The wire value decides
	/// whether a peer already relayed the request, so it arrives as its
	/// own type rather than as one of two bare octets a call site could
	/// exchange (CWE-639).
	#[must_use]
	pub fn from_wire(wire: WireHopBudget, max_hops: u8) -> Self {
		let hops = wire.get();

		Self { remaining: hops.min(max_hops), relayed: hops != DEFAULT_HOP_BUDGET }
	}

	/// Spends one forward, saturating at zero.
	#[must_use]
	pub fn spend(self) -> Self {
		Self { remaining: self.remaining.saturating_sub(1), relayed: self.relayed }
	}

	/// Whether a peer already spent part of this budget.
	///
	/// An origin request arrives carrying the sentinel, so anything below it
	/// reached this gateway through at least one relay. The export boundary
	/// reads this to tell a direct caller from a relayed one.
	///
	/// # Wire count
	///
	/// The answer is read from the wire count before the cap clamps it, because
	/// a cap below the sentinel would otherwise make every origin request look
	/// relayed.
	#[must_use]
	pub fn is_relayed(&self) -> bool {
		self.relayed
	}

	/// Whether the budget affords a forward to a peer gateway.
	#[must_use]
	pub fn allows_forward(&self) -> bool {
		self.remaining > 0
	}

	/// Whether the budget affords the two forwards a relay trail needs.
	///
	/// A relay trail spends one hop at the relay before the owner is
	/// reached, so only a budget of two or more can select it.
	#[must_use]
	pub fn allows_relay_trail(&self) -> bool {
		self.remaining >= 2
	}

	/// The count this budget puts back on the wire.
	#[must_use]
	pub fn wire(&self) -> u8 {
		self.remaining
	}

	/// Relayed stream route for one peer hop out of this budget.
	///
	/// The route reaches the same `target` with one forward spent. Building
	/// it through the budget spends the hop, so a relay pays for every route
	/// it stamps (CWE-834).
	#[must_use]
	pub(crate) fn relayed_route(self, target: &Urn<'static>) -> StreamRoute {
		StreamRoute::relayed_to(target.clone(), self.spend().wire())
	}

	/// Relayed work envelope for one peer hop out of this budget.
	///
	/// Unary work spends its hop here, as a routed stream spends it in
	/// [`Self::relayed_route`]. `payload` is already the client's encoded frame
	/// and travels opaquely, so a relay hop forwards the bytes it received.
	#[must_use]
	pub(crate) fn relayed_work(self, servlet_type: Urn<'static>, payload: impl Into<Vec<u8>>) -> ClusterWorkRequest {
		let payload: Vec<u8> = payload.into();
		ClusterWorkRequest { servlet_type, payload, hops_remaining: self.spend().wire() }
	}

	/// A budget clamped to the default cap, for tests that pick a wire count.
	#[cfg(test)]
	pub(crate) fn for_test(wire: u8) -> Self {
		Self::from_wire(WireHopBudget::new(wire), DEFAULT_HOP_BUDGET)
	}
}

/// Peer advertisement that passed signer resolution and wire checks.
///
/// The registry receives this type only after those checks, so the signer
/// identity and the claimed dial address each arrive in their own field.
pub struct AdmittedPeerAd {
	/// Fingerprint of the signer certificate, which keys the slate.
	pub(super) peer_hive_id: SharedId,
	/// Claimed gateway socket every slate entry dials, parsed and admitted
	/// once.
	///
	/// The slate entries carry this same value, so a scoring lookup and a
	/// stored route agree on one socket, and the discovery hint carries the
	/// proof the dial policy admitted it.
	pub(super) dial: AdmittedDial,
	/// Peer-routed entries keyed by `peer_hive_id NUL type`.
	pub(super) slate: Vec<ServletEntry>,
	/// Issue order of the signed advertisement frame. Reconciliation
	/// refuses an order older than the newest applied (CWE-294).
	pub(super) order: UnixMillis,
}

/// Fallback trails for one admitted advertisement through one relay.
///
/// The slate reconciles under the composite `origin NUL relay` bucket,
/// so a relay trail outlives a replacement of the origin's direct slate. An
/// empty direct advertisement removes it with the direct routes. A trail also
/// leaves when the relay it dials is evicted, and an idle trail decays away by
/// staleness pruning.
pub struct RelayTrail {
	/// The composite `origin NUL relay` bucket this slate reconciles under.
	pub(super) bucket: SharedId,
	/// The origin whose types the trails reach, and the owner of every
	/// route in the bucket.
	pub(super) origin: SharedId,
	/// Relay-routed entries keyed by `bucket NUL type`.
	pub(super) slate: Vec<ServletEntry>,
	/// Issue order of the advertisement the trails derive from.
	pub(super) order: UnixMillis,
}

impl AdmittedPeerAd {
	/// Admits a wire advertisement, failing closed with a refusal status.
	///
	/// The checks run in this order:
	///
	/// 1. The signer MUST resolve on the peer plane, and the slate keys by its
	///    certificate fingerprint rather than the claimed `gateway_addr`.
	/// 2. This gateway MUST be in a flood, and the signer MUST be a member of it.
	/// 3. [`PeerConfig::admit_claim`] MUST admit the claimed address, and the
	///    advertised types MUST be bare servlet types within the type cap.
	///
	/// Caps and local-route conflicts are registry policy under
	/// [`super::ServletRegistry::reconcile_peer_slate`].
	pub(crate) fn admit(
		verified: &VerifiedControlFrame<'_>,
		ad: &PeerAdvertisement,
		conf: &ClusterConfig,
	) -> Result<Self, TransitStatus> {
		if !matches!(verified.party(), Party::Peer) {
			return Err(TransitStatus::PermissionDenied);
		}

		let frame = verified.frame();
		// The control-frame parse already resolved the signer certificate
		// and keyed its slate, so the membership gate reads that
		// certificate and the slate key comes from that parse.
		let signer_cert = verified.signer_cert();
		let peer_hive_id = verified.fingerprint().into_shared();

		// Federation is a colony operation, so both this gateway and the
		// advertising peer must carry a valid colony URN SAN. A certificate
		// without one still serves general transport and work, but it grants
		// no membership.
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

	/// Relay trails through `relay_id`, the gateway that relayed this
	/// advertisement, with one trail per advertised type dialing
	/// `relay_dial`, the relay's own admitted gateway socket.
	///
	/// Returns `None` when the relay is the origin itself or the slate is
	/// empty.
	///
	/// # Failover
	///
	/// Routing then holds two trails per type: the direct trail dialing
	/// the origin, and a relay trail through the relaying peer.
	/// Pheromone feedback can therefore fail over to the relay when
	/// the origin is unreachable.
	///
	/// # Bucket
	///
	/// The trails reconcile under their own `origin NUL relay` bucket
	/// (`ServletRegistry::reconcile_relay_trail`), so a replacement of the
	/// origin's direct slate leaves the fallback in place. An empty direct
	/// advertisement removes both.
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

		let bucket = ServletEntry::relay_bucket(&self.peer_hive_id, relay_id);
		let slate: Vec<ServletEntry> = self
			.slate
			.iter()
			.map(|entry| {
				ServletEntry::peer_relay(
					RelayRoute {
						origin_id: Arc::clone(&self.peer_hive_id),
						relay_id: Arc::clone(relay_id),
						servlet_type: Arc::clone(entry.servlet_type()),
						dial: relay_dial,
					},
					pheromone.initial_pheromone,
					pheromone.abandonment_limit,
				)
			})
			.collect();

		Some(RelayTrail { bucket, origin: Arc::clone(&self.peer_hive_id), slate, order: self.order })
	}

	/// Discovery hint from this admitted advertisement: the verified
	/// signer's admitted dial address plus its certificate fingerprint.
	///
	/// The hint owns its fields because it outlives this borrowed
	/// advertisement inside the peer table. Every admitted advertiser is a
	/// flood member, so every one yields a hint.
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

/// Wire-level advertisement checks, which run without the registry lock.
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
/// [`ClusterConfig::flood`] builds one, and only for a gateway whose own
/// certificate carries a colony URN.
///
/// # Scope
///
/// The flood is the namespace. A member is a gateway whose key the peer trust
/// store holds, and whose certificate in that store carries a colony URN of
/// this namespace, whichever colony it names. This type is the one home for
/// that rule. Every inbound gossip frame and every outbound gossip dial asks
/// [`Self::member`], so the rule is written once.
///
/// - Colonies are the parties, and the flood is the state they share. Work
///   federation admits the same set, so one rule decides both planes.
/// - The peer trust store is the share set. A gateway receives the rumors of
///   the origins it trusts and of no other, so trust stores that differ
///   divide one namespace into subnets.
/// - A trusted certificate with no colony URN of the namespace is outside every flood.
/// - Each question reads the store, so a change to it while the gateway runs takes effect at once.
/// - A certificate authority in the store admits no gateway, because the
///   store must hold the certificate of each key that signs a frame.
/// - A gateway with no peer plane dials its peers on the hive pool, so its
///   hive trust store is the list (`ClusterTlsConfig::peer_dial_trust`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Flood<'a> {
	namespace: &'a ColonyNamespace,
	/// The store this gateway dials its peers under, which is the list of
	/// parties. With no store the flood has no member.
	peer_trust: Option<&'a dyn CertificateTrust>,
}

/// Proof that a certificate belongs to a [`Flood`].
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
	///   certificate, so a rumor is sent only where signed frames are admitted
	///   (CWE-668).
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
	/// this file, so a flood exists only for a gateway this method takes.
	#[must_use]
	pub(crate) fn flood(&self) -> Option<Flood<'_>> {
		self.colony_urn.as_ref()?;

		Some(Flood::new(&self.namespace, self.tls.peer_dial_trust()))
	}
}

impl ColonyNamespace {
	/// Colony URN a certificate asserts, when exactly one is present.
	///
	/// Membership binds to the URI SAN (RFC 5280 §4.2.1.6) rather than the
	/// Subject DN. Non-URI SANs and URIs that fail colony validation in this
	/// namespace are ignored.
	///
	/// The answer is `None` in each case below, so an ambiguous identity
	/// fails closed (CWE-706):
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

/// Peer identity derived from a certificate.
pub(crate) trait ColonyCertificate {
	/// Stable peer key derived from the certificate itself.
	///
	/// Slates and misbehavior scoring key on this fingerprint, so one peer
	/// keeps one identity across every `gateway_addr` it advertises. The
	/// answer is `None` when the trust store yields no fingerprint, so an
	/// unidentifiable peer fails closed.
	fn fingerprint_id(&self) -> Option<SharedId>;
}

impl ColonyCertificate for Certificate {
	fn fingerprint_id(&self) -> Option<SharedId> {
		let fingerprint = CertificateTrustStore::to_fingerprint::<Sha3_256>(self).ok()?;
		Some(Arc::from(fingerprint.as_slice()))
	}
}

#[cfg(test)]
mod tests {
	use super::super::RouteKind;
	use super::*;
	use crate::colony::cluster::PeerAddress;

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
	/// hint gate also passes the advertisement gate.
	/// An ad spelling its socket verbosely installs routes under the
	/// canonical key, so a later scoring or eviction lookup by that address
	/// finds them.
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

	/// Pheromone settings the slate tests read: the shipped defaults, so a
	/// changed default shows up here rather than silently diverging.
	fn test_pheromone() -> PheromoneConfig {
		PheromoneConfig::default()
	}

	#[test]
	fn build_peer_slate_keys_by_hive_and_sets_dial() {
		let hive: SharedId = Arc::from([1u8; 32].as_slice());
		let slate = test_pheromone().peer_slate(&hive, AdmittedDial::fixture("127.0.0.1:9000"), &[ping_type()]);
		assert_eq!(slate.len(), 1);
		assert_eq!(slate[0].route_kind(), RouteKind::Peer);
		assert_eq!(slate[0].dial_target().route_bytes().as_ref(), b"127.0.0.1:9000");
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

	/// The fixture socket a relaying gateway is dialed at.
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
		assert_eq!(trail.slate[0].dial_target().route_bytes().as_ref(), b"127.0.0.1:9001");
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
		use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
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
			let builder = CertificateTrustBuilder::from(Secp256k1Policy).with_certificate(cert.clone());
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
