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
use crate::crypto::x509::store::CertificateTrustStore;
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
/// this value rather than the raw octet, so a peer cannot spend more
/// forwards than the operator allows (CWE-770).
///
/// [`PeerConfig::max_hops`]: super::PeerConfig::max_hops
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopBudget {
	/// Forwards this gateway may still spend, under the operator's cap.
	remaining: u8,
	/// Whether the sender had already spent part of the budget.
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
	/// reached, so a shorter budget could never select it.
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
	/// it through the budget spends the hop, so a relay cannot stamp a route
	/// it did not pay for (CWE-834).
	#[must_use]
	pub(crate) fn relayed_route(self, target: &Urn<'static>) -> StreamRoute {
		StreamRoute::relayed_to(target.clone(), self.spend().wire())
	}

	/// Relayed work envelope for one peer hop out of this budget.
	///
	/// The unary twin of [`Self::relayed_route`]. `payload` is already the
	/// client's encoded frame and travels opaquely, so a relay hop
	/// re-encodes nothing.
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
/// The registry receives this type only after those checks, so signer
/// identity cannot be transposed with the claimed dial address.
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
/// so relay trails live and die independently of the origin's direct
/// slate. The origin's next direct advertisement cannot evict them.
/// A dead relay decays away by staleness pruning.
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
	/// - The signer MUST resolve on the peer plane, and the slate keys by its
	///   certificate fingerprint rather than the claimed `gateway_addr`.
	/// - The local and the peer certificate MUST both carry a colony URN SAN.
	/// - [`PeerConfig::admit_claim`] MUST admit the claimed address, and the
	///   advertised types MUST be bare servlet types within the type cap.
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
		{
			let local_member = conf.colony_urn().is_some();
			let peer_member = conf.namespace.cert_colony_urn(signer_cert).is_some();
			if !(local_member && peer_member) {
				return Err(TransitStatus::PermissionDenied);
			}
		}

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
	/// (`ServletRegistry::reconcile_relay_trail`), so the origin's direct
	/// slate lifecycle never evicts the fallback.
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
	/// advertisement inside the peer table.
	///
	/// # Unproven address
	///
	/// The advertiser dialed this gateway, so nothing proves the claimed
	/// address dials back yet. The peer table holds the hint in `new` until
	/// this gateway's own probe passes the colony gate, the way the Bitcoin
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
	/// keeps one identity across every `gateway_addr` it advertises.
	/// `None` when the trust store yields no fingerprint, so an
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

	/// One socket spelled two ways is one entry, so a peer cannot pass the
	/// hint gate and fail the advertisement gate with the same address.
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

		fn foreign_colony() -> Urn<'static> {
			let foreign = ColonyNamespace::new("acme", "").unwrap_or_default();
			foreign.colony("main").expect("static colony name")
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
}
