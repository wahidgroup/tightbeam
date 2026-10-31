//! The peer plane of a cluster gateway: hop budgets, peer-advertisement
//! admission, relay trails, and the flood a gateway gossips in.

use std::sync::Arc;

use super::runtime::VerifiedControlFrame;
use super::{
	AdmittedDial, ClusterConfig, DialTarget, Party, PeerConfig, PeerHint, PheromoneConfig, RelayRoute, RouteKind,
	ServletEntry, SharedId,
};
use crate::clock::UnixMillis;
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

#[cfg(test)]
impl AdmittedPeerAd {
	/// The advertisement of `peer` at the fixture socket `dial` that carries
	/// `slate` and was issued at `order`.
	pub(crate) fn fixture(
		peer: impl AsRef<[u8]>,
		dial: impl AsRef<str>,
		slate: impl IntoIterator<Item = ServletEntry>,
		order: u64,
	) -> Self {
		let peer_hive_id = SharedId::from(peer.as_ref());
		let (dial, slate) = (AdmittedDial::fixture(dial), slate.into_iter().collect());
		AdmittedPeerAd { peer_hive_id, dial, slate, order: UnixMillis::new(order) }
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
	use crate::colony::protocol::ClusterRequest;
	use crate::constants::DEFAULT_MAX_HOPS;
	use crate::tb_cases;
	use crate::testing::fixtures::TestStore;
	use crate::testing::{unhex, TestCertificate, TestKey, TestResult};
	use crate::transport::tcp::r#async::TokioListener;
	use crate::{decode, encode};

	/// The SHA3-256 digest of the DER of the fixed test certificate, computed
	/// with Python's `hashlib.sha3_256`.
	const HOUSE_GATEWAY_ID: &str = "ec636319b64960969b307426b727616ab7692df941b0a96b52a9c13f1f077b4c";

	/// A gateway under the house provider goes by the SHA3-256 fingerprint of
	/// its certificate, the digest its protocol's provider names.
	#[test]
	fn a_house_gateway_goes_by_its_sha3_256_fingerprint() {
		let certificate = TestCertificate::insecure_fixed();
		let id = certificate.fingerprint_id::<ColonyDigest<TokioListener>>();
		assert_eq!(id.as_deref(), Some(unhex(HOUSE_GATEWAY_ID).as_slice()));
	}

	// A budget of one forward reaches a local servlet and a peer gateway, and a
	// relay trail needs the second forward that the relay spends.
	tb_cases! {
		fn a_budget_of_one_affords_a_peer_route_and_not_a_relay_trail((kind, afforded): (RouteKind, bool)) {
			let budget = HopBudget::for_test(1);
			assert_eq!(budget.affords(kind), afforded);
		}
		cases {
			a_local_route => (RouteKind::Local, true),
			a_peer_route => (RouteKind::Peer, true),
			a_relay_trail => (RouteKind::PeerRelay, false),
		}
	}

	/// The budget that the wire count `wire` grants under the hop cap
	/// `policy`.
	fn budget(wire: u8, policy: u8) -> HopBudget {
		HopBudget::from_wire(WireHopBudget::new(wire), policy)
	}

	/// The servlet type `ping` of the default namespace.
	fn ping_type() -> Urn<'static> {
		ColonyNamespace::servlet_fixture("ping")
	}

	// A relayed work request stamps the budget the gateway has left after its
	// own forward, and a spent budget stays at zero.
	tb_cases! {
		fn relayed_work_stamps_the_spent_budget((budget, remaining): (HopBudget, u8)) {
			let work = budget.relayed_work(ping_type(), vec![1]);
			assert_eq!(work.hops_remaining, remaining);
		}
		cases {
			decremented => (HopBudget::for_test(2), 1),
			saturated_at_zero => (HopBudget::for_test(0), 0),
		}
	}

	/// A relayed work envelope carries the decremented budget on the wire, so
	/// a skipped decrement in `HopBudget::relayed_work` fails here even when
	/// an integration clamp masks it.
	#[test]
	fn relayed_envelope_carries_the_decremented_budget_on_the_wire() -> TestResult {
		let relayed = HopBudget::for_test(2).relayed_work(ping_type(), vec![7]);
		let envelope = encode(&ClusterRequest::Work(relayed))?;

		let decoded = decode::<ClusterRequest>(&envelope)?;
		assert!(matches!(decoded, ClusterRequest::Work(work) if work.hops_remaining == 1));
		Ok(())
	}

	// A missing decrement in `HopBudget::relayed_route` fails here even when
	// integration topologies mask it with a clamp. The mux handle tests pin
	// the stamp of the route on the Open.
	tb_cases! {
		fn relayed_route_stamps_the_spent_budget((budget, remaining): (HopBudget, u8)) {
			let route = budget.relayed_route(&ColonyNamespace::servlet_fixture("stream-echo"));
			assert_eq!(route.hops_remaining(), remaining);
		}
		cases {
			decremented => (HopBudget::for_test(2), 1),
			saturated_at_zero => (HopBudget::for_test(0), 0),
		}
	}

	/// A relayed route keeps the target of the stream it carries.
	#[test]
	fn relayed_route_keeps_the_target() {
		let target = ColonyNamespace::servlet_fixture("stream-echo");
		let route = HopBudget::for_test(2).relayed_route(&target);
		assert_eq!(route.target(), Some(&target));
	}

	// A budget clamps the origin sentinel to the hop cap of its gateway, keeps
	// a relayed count below that cap, and spends to zero under a cap of zero.
	tb_cases! {
		fn hop_budget_wire_clamps_to_policy((wire, policy, clamped): (u8, u8, u8)) {
			assert_eq!(budget(wire, policy).wire(), clamped);
		}
		cases {
			origin_sentinel => (DEFAULT_HOP_BUDGET, 1, 1),
			relayed_below_policy => (1, 3, 1),
			zero_policy => (DEFAULT_HOP_BUDGET, 0, 0),
		}
	}

	/// A hop cap of zero disables forwarding.
	#[test]
	fn a_zero_policy_disables_forwarding() {
		assert!(!budget(DEFAULT_HOP_BUDGET, 0).allows_forward());
	}

	// An origin request carries the sentinel, so a count below it reached
	// this gateway through a relay. The relayed fact reads the wire count,
	// because the clamped count under a cap below the origin sentinel would
	// mark every direct caller relayed and refuse it at the export boundary.
	tb_cases! {
		fn a_budget_reads_as_relayed_by_its_wire_count((wire, policy, relayed): (u8, u8, bool)) {
			assert_eq!(budget(wire, policy).is_relayed(), relayed);
		}
		cases {
			origin => (DEFAULT_HOP_BUDGET, DEFAULT_HOP_BUDGET, false),
			clamped_origin => (DEFAULT_HOP_BUDGET, DEFAULT_MAX_HOPS, false),
			below_the_sentinel => (2, 4, true),
		}
	}

	// A relay trail spends one hop at the relay, so a shorter budget could
	// never select it.
	tb_cases! {
		fn a_relay_trail_needs_two_forwards((wire, allowed): (u8, bool)) {
			assert_eq!(budget(wire, 4).allows_relay_trail(), allowed);
		}
		cases {
			one_forward => (1, false),
			two_forwards => (2, true),
		}
	}

	/// The colony URN of `name` in the default namespace.
	fn colony(name: &str) -> Urn<'static> {
		ColonyNamespace::colony_fixture(name)
	}

	/// A colony URN under another naming authority.
	fn foreign_colony() -> Urn<'static> {
		let foreign = ColonyNamespace::new("acme", "").expect("the fixture authority is valid");
		foreign.colony("main").expect("static colony name")
	}

	/// The certificate of the fixed test key that carries each of `sans` as a
	/// URI Subject Alternative Name.
	fn certificate_naming(sans: &[String]) -> Certificate {
		let sans: Vec<&str> = sans.iter().map(String::as_str).collect();
		TestCertificate::with_uri_sans(&TestKey::insecure_fixed_signing(), &sans)
	}

	/// The hive id of 32 octets of `fill`.
	fn hive_id(fill: u8) -> SharedId {
		Arc::from([fill; 32].as_slice())
	}

	/// One socket spelled two ways is one entry, so an address that passes the
	/// hint gate also passes the advertisement gate. An ad that spells its
	/// socket verbosely installs routes under the canonical key, so a later
	/// score or eviction lookup by that address finds them.
	#[test]
	fn an_ad_spelling_its_socket_verbosely_routes_under_the_canonical_key() {
		let verbose = PeerAddress::fixture("[0:0:0:0:0:0:0:1]:9000");
		let canonical = PeerAddress::fixture("[::1]:9000");
		assert_eq!(verbose.route_bytes(), canonical.route_bytes());
		assert_eq!(verbose.route_bytes().as_ref(), b"[::1]:9000");
	}

	// An advertisement names bare servlet types alone, so a list that holds
	// an instance locator refuses as a whole.
	tb_cases! {
		fn advertised_types_admit_bare_types_alone((types, admitted): (Vec<Urn<'static>>, bool)) {
			assert_eq!(ColonyNamespace::default().all_bare_servlet_types(&types), admitted);
		}
		cases {
			bare => (vec![ping_type()], true),
			instance => (vec![ColonyNamespace::instance_fixture("ping", "127.0.0.1:1")], false),
		}
	}

	/// The slate of an advertisement of `types` by the hive `origin`, which
	/// peers dial at the fixture socket `127.0.0.1:9000`.
	fn slate_of(origin: &SharedId, types: &[Urn<'static>]) -> Vec<ServletEntry> {
		PheromoneConfig::default().peer_slate(origin, AdmittedDial::fixture("127.0.0.1:9000"), types)
	}

	/// The one route of `slate`.
	fn sole(slate: &[ServletEntry]) -> &ServletEntry {
		let [route] = slate else { panic!("the slate holds one route") };
		route
	}

	/// A peer slate holds one peer route per type, owned by the hive and keyed
	/// by the hive, a separator octet, and the type.
	#[test]
	fn a_peer_slate_keys_each_route_by_its_hive_and_type() {
		let slate = slate_of(&hive_id(1), &[ping_type()]);
		let route = sole(&slate);

		let key = [[1u8; 32].as_slice(), &[0], b"urn:tightbeam::servlet:ping"].concat();
		let read = (route.route_kind(), route.owner_id().as_ref(), route.route_key().as_ref());
		assert_eq!(read, (RouteKind::Peer, [1u8; 32].as_slice(), key.as_slice()));
	}

	/// Each route of a peer slate dials the socket its advertisement claims.
	#[test]
	fn a_peer_slate_dials_the_advertised_socket() {
		let slate = slate_of(&hive_id(1), &[ping_type()]);
		assert_eq!(sole(&slate).dial_target().as_bytes(), b"127.0.0.1:9000");
	}

	/// The advertisement of `types` by the hive `origin` at the fixture socket
	/// `127.0.0.1:9000`, issued at order zero.
	fn ad_of(origin: &SharedId, types: &[Urn<'static>]) -> AdmittedPeerAd {
		AdmittedPeerAd::fixture(origin, "127.0.0.1:9000", slate_of(origin, types), 0)
	}

	/// The discovery hint of an advertisement names the socket and the hive
	/// of its advertiser.
	#[test]
	fn discovery_hint_names_the_advertiser() {
		let ad = ad_of(&hive_id(1), &[ping_type()]);
		let hint = ad.discovery_hint();

		let read = (hint.dial, hint.peer_id);
		assert_eq!(read, (AdmittedDial::fixture("127.0.0.1:9000"), Some([1u8; 32].to_vec())));
	}

	/// The fixture socket at which peers dial the relay gateway.
	fn relay_dial() -> AdmittedDial {
		AdmittedDial::fixture("127.0.0.1:9001")
	}

	/// The trail of `trail`, which a distinct relay of a live slate leaves.
	fn some_trail(trail: Option<RelayTrail>) -> RelayTrail {
		trail.expect("relay trail for a distinct relay with a live slate")
	}

	// A hive that relays its own advertisement, or an advertisement with an
	// empty slate, leaves no relay trail.
	tb_cases! {
		fn relay_trail_none_for((relay, types): (SharedId, Vec<Urn<'static>>)) {
			let ad = ad_of(&hive_id(1), &types);
			let trail = ad.relay_trail(&relay, relay_dial(), &PheromoneConfig::default());
			assert!(trail.is_none());
		}
		cases {
			self_relay => (hive_id(1), vec![ping_type()]),
			empty_slate => (hive_id(2), Vec::new()),
		}
	}

	/// A relay trail buckets each route under the origin, a separator octet,
	/// and the relay, owns it by the origin, and dials the relay.
	#[test]
	fn relay_trail_buckets_by_origin_and_relay() {
		let (origin, relay) = (hive_id(1), hive_id(2));
		let ad = ad_of(&origin, &[ping_type()]);
		let trail = some_trail(ad.relay_trail(&relay, relay_dial(), &PheromoneConfig::default()));

		let expected_bucket: Vec<u8> = [origin.as_ref(), &[0u8], relay.as_ref()].concat();
		let route = sole(&trail.slate);
		assert_eq!(trail.bucket.as_ref(), expected_bucket.as_slice());
		assert_eq!(route.route_kind(), RouteKind::PeerRelay);
		assert_eq!(route.bucket().as_ref(), expected_bucket.as_slice());
		assert_eq!(route.owner_id().as_ref(), origin.as_ref());
		assert_eq!(route.relay_id().map(|id| id.as_ref()), Some(relay.as_ref()));
		assert_eq!(route.dial_target().as_bytes(), b"127.0.0.1:9001");
	}

	// The wire checks refuse an advertisement whose dial names no socket, and
	// one whose dial the allowlist leaves out.
	tb_cases! {
		fn peer_advertisement_wire_ok_refuses((dial, config): (&[u8], PeerConfig)) {
			let status = peer_advertisement_wire_ok(dial, &[ping_type()], &ColonyNamespace::default(), &config);
			assert_eq!(status, Err(TransitStatus::PermissionDenied));
		}
		cases {
			bad_dial => (b"", PeerConfig::default()),
			allowlist_miss => (b"127.0.0.1:9000", PeerConfig::allowing(["10.0.0.1:9000"])),
		}
	}

	mod colony_urn {
		use super::*;

		// A certificate names its colony by its one URI SAN of a colony of the
		// namespace. It skips other entries and collapses identical ones, and
		// it names none for two colonies, no SAN, or another namespace.
		tb_cases! {
			fn cert_colony_urn((certificate, named): (Certificate, Option<Urn<'static>>)) {
				assert_eq!(ColonyNamespace::default().cert_colony_urn(&certificate), named);
			}
			cases {
				extracts_a_valid_san => (certificate_naming(&[colony("main").to_string()]), Some(colony("main"))),
				ignores_non_colony_entries => (
					certificate_naming(&[
						ping_type().to_string(),
						String::from("https://example.test"),
						colony("main").to_string(),
					]),
					Some(colony("main")),
				),
				tolerates_duplicate_identical_entries => (
					certificate_naming(&[colony("main").to_string(), colony("main").to_string()]),
					Some(colony("main")),
				),
				fails_closed_on_ambiguity => (
					certificate_naming(&[colony("main").to_string(), colony("other").to_string()]),
					None,
				),
				is_none_without_san => (TestCertificate::insecure_fixed(), None),
				is_none_for_foreign_namespace => (certificate_naming(&[foreign_colony().to_string()]), None),
			}
		}
	}

	mod flood {
		use super::*;
		use crate::crypto::x509::store::CertificateTrustStore;

		/// What [`Flood::member`] answers.
		type Answer = Result<FloodMember, TransitStatus>;

		/// The answer the flood of the default namespace gives a certificate
		/// that carries `sans`, under a peer store that holds it.
		fn membership(sans: &[String]) -> Answer {
			let cert = certificate_naming(sans);
			let store = TestStore::holding([cert.clone()]);
			let ns = ColonyNamespace::default();

			let flood = Flood::new(&ns, Some(&store));
			flood.member(&cert)
		}

		/// A certificate of colony "main" under a key no fixture store holds.
		fn unenrolled_member_cert() -> Certificate {
			TestCertificate::with_cn_and_uri_sans(&TestKey::fixed(0x02), "Unenrolled", &[&colony("main").to_string()])
		}

		// The certificate names a colony of the namespace, and the peer store
		// holds another key or the flood has no peer store.
		tb_cases! {
			fn an_unenrolled_member_is_outside_the_flood(store: Option<CertificateTrustStore>) {
				let ns = ColonyNamespace::default();
				let flood = Flood::new(&ns, store.as_ref().map(|store| store as &dyn CertificateTrust));

				assert_eq!(flood.member(&unenrolled_member_cert()), OUTSIDE);
			}
			cases {
				a_store_of_another_key => Some(TestStore::holding([certificate_naming(&[colony("main").to_string()])])),
				no_peer_trust => None,
			}
		}

		const MEMBER: Answer = Ok(FloodMember(()));
		const OUTSIDE: Answer = Err(TransitStatus::PermissionDenied);

		// An enrolled certificate of one colony of the namespace is a member,
		// and one of no colony, of another namespace, or of two colonies is
		// outside the flood.
		tb_cases! {
			fn the_flood_decides_membership_from_the_certificate((sans, answer): (Vec<String>, Answer)) {
				assert_eq!(membership(&sans), answer);
			}
			cases {
				one_colony => (vec![colony("main").to_string()], MEMBER),
				another_colony => (vec![colony("other").to_string()], MEMBER),
				no_colony => (vec![], OUTSIDE),
				another_namespace => (vec![foreign_colony().to_string()], OUTSIDE),
				two_colonies => (vec![colony("main").to_string(), colony("other").to_string()], OUTSIDE),
			}
		}
	}
}
