use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::colony::cluster::SharedId;
use crate::colony::common::MAX_PHEROMONE;
use crate::utils::BasisPoints;

/// How the load balancer reaches an entry.
///
/// `Local` resolves to a servlet this gateway owns. `Peer` resolves to
/// a peer gateway that owns the servlet, reached by forwarding.
/// `PeerRelay` resolves to a relaying peer gateway that must forward
/// once more to reach the owner, so selection requires a relay budget
/// of at least two. All kinds share the same pheromone scoring tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteKind {
	#[default]
	Local,
	Peer,
	PeerRelay,
}

impl RouteKind {
	/// Whether the request leaves this gateway for a peer gateway.
	#[must_use]
	pub fn is_peer(self) -> bool {
		matches!(self, Self::Peer | Self::PeerRelay)
	}
}

/// A servlet instance tracked with pheromone score and trial count.
///
/// Fields are private so the route-key discipline holds by
/// construction:
///
/// - [`ServletEntry::local`] keys by the servlet address it dials.
/// - [`ServletEntry::peer`] keys by `peer_id NUL servlet_type`.
/// - [`ServletEntry::peer_relay`] keys by `origin NUL relay NUL type`.
#[derive(Debug)]
pub struct ServletEntry {
	/// Registry map key and pheromone trail identity.
	route_key: SharedId,
	servlet_type: SharedId,
	/// Reconcile bucket: the hive-index key one slate replaces atomically.
	/// Local entries bucket by hive, peer entries by origin, relay
	/// entries by the composite `origin NUL relay`.
	bucket: SharedId,
	/// Owning identity: local hive address, or the certificate
	/// fingerprint of the origin gateway that advertised the type.
	owner_id: SharedId,
	/// Certificate fingerprint of the relaying gateway this entry
	/// dials, when the route is a relay trail.
	relay_id: Option<SharedId>,
	/// Socket dialed when forwarding. Local entries use `route_key`.
	dial_addr: SharedId,
	route_kind: RouteKind,
	pheromone: AtomicU64,
	last_reinforced: Instant,
	trial_count: AtomicU32,
	abandonment_limit: u32,
	/// When this entry was last built by a reconcile, for staleness
	/// pruning. Never preserved across replacement, because a refresh
	/// must advance it.
	installed_at: Instant,
}

/// Operator view of one learned peer route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouteInfo {
	/// Canonical servlet type bytes.
	pub servlet_type: SharedId,
	/// Claimed peer gateway dial address.
	pub dial_addr: SharedId,
	/// Advertising peer identity certificate fingerprint.
	pub peer_id: SharedId,
}

/// Identity fields one peer-routed constructor hands to [`ServletEntry::peer_kind`].
struct PeerIdentity {
	bucket: SharedId,
	owner_id: SharedId,
	relay_id: Option<SharedId>,
	route_kind: RouteKind,
}

impl ServletEntry {
	/// Creates a local servlet reachable at `address`, owned by `hive_id`.
	pub fn local(
		address: SharedId,
		servlet_type: SharedId,
		hive_id: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		Self {
			route_key: Arc::clone(&address),
			servlet_type,
			bucket: Arc::clone(&hive_id),
			owner_id: hive_id,
			relay_id: None,
			dial_addr: address,
			route_kind: RouteKind::Local,
			pheromone: AtomicU64::new(initial_pheromone),
			last_reinforced: Instant::now(),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
			installed_at: Instant::now(),
		}
	}

	/// Creates a peer route whose key is `peer_id NUL servlet_type`.
	pub fn peer(
		peer_id: SharedId,
		servlet_type: SharedId,
		dial_addr: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let identity = PeerIdentity {
			bucket: Arc::clone(&peer_id),
			owner_id: peer_id,
			relay_id: None,
			route_kind: RouteKind::Peer,
		};

		Self::peer_kind(identity, servlet_type, dial_addr, initial_pheromone, abandonment_limit)
	}

	/// Creates a relay trail for `origin_id`'s type, dialing the
	/// relaying gateway `relay_id` instead of the origin.
	///
	/// The entry buckets under the composite [`Self::relay_bucket`], so
	/// the key is `origin NUL relay NUL servlet_type`. That key is
	/// distinct from the direct `origin NUL servlet_type` trail, so
	/// the two score independently. Reconciling under its own bucket
	/// means the origin's direct slate lifecycle never evicts the
	/// fallback.
	/// Forwarding through this trail spends a hop at the relay, so
	/// selection requires a budget that lets the relay forward once
	/// more.
	pub fn peer_relay(
		origin_id: SharedId,
		relay_id: SharedId,
		servlet_type: SharedId,
		dial_addr: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let identity = PeerIdentity {
			bucket: Self::relay_bucket(&origin_id, &relay_id),
			owner_id: origin_id,
			relay_id: Some(relay_id),
			route_kind: RouteKind::PeerRelay,
		};

		Self::peer_kind(identity, servlet_type, dial_addr, initial_pheromone, abandonment_limit)
	}

	/// Composite `origin NUL relay` reconcile bucket for relay trails.
	///
	/// One construction shared by entry keys and slate reconciliation,
	/// so the two can never drift apart.
	#[must_use]
	pub fn relay_bucket(origin_id: &[u8], relay_id: &[u8]) -> SharedId {
		let mut bucket = Vec::with_capacity(origin_id.len() + 1 + relay_id.len());
		bucket.extend_from_slice(origin_id);
		bucket.push(0);
		bucket.extend_from_slice(relay_id);

		Arc::from(bucket.as_slice())
	}

	/// One key discipline for both peer-routed kinds: `bucket NUL type`.
	fn peer_kind(
		identity: PeerIdentity,
		servlet_type: SharedId,
		dial_addr: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let PeerIdentity { bucket, owner_id, relay_id, route_kind } = identity;
		let mut route_key = Vec::with_capacity(bucket.len() + 1 + servlet_type.len());
		route_key.extend_from_slice(&bucket);
		route_key.push(0);
		route_key.extend_from_slice(&servlet_type);

		Self {
			route_key: Arc::from(route_key.as_slice()),
			servlet_type,
			bucket,
			owner_id,
			relay_id,
			dial_addr,
			route_kind,
			pheromone: AtomicU64::new(initial_pheromone),
			last_reinforced: Instant::now(),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
			installed_at: Instant::now(),
		}
	}

	/// Creates a local entry. This is an alias of [`Self::local`].
	pub fn new(
		address: SharedId,
		servlet_type: SharedId,
		hive_id: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		Self::local(address, servlet_type, hive_id, initial_pheromone, abandonment_limit)
	}

	/// Registry map key and pheromone trail identity.
	#[must_use]
	pub fn route_key(&self) -> &SharedId {
		&self.route_key
	}

	/// Socket address dialed when forwarding through this entry.
	#[must_use]
	pub fn dial_target(&self) -> &SharedId {
		&self.dial_addr
	}

	/// Owning identity: local hive address, or the certificate
	/// fingerprint of the origin gateway that advertised the type.
	#[must_use]
	pub fn owner_id(&self) -> &SharedId {
		&self.owner_id
	}

	/// Reconcile bucket this entry lives under in the hive index.
	#[must_use]
	pub fn bucket(&self) -> &SharedId {
		&self.bucket
	}

	/// Certificate fingerprint of the relaying gateway this entry
	/// dials. `None` for local and direct peer routes.
	#[must_use]
	pub fn relay_id(&self) -> Option<&SharedId> {
		self.relay_id.as_ref()
	}

	/// When the last reconcile built this entry, for staleness pruning.
	pub(super) fn installed_at(&self) -> Instant {
		self.installed_at
	}

	/// Servlet type key bytes used for type-index lookup.
	#[must_use]
	pub fn servlet_type(&self) -> &SharedId {
		&self.servlet_type
	}

	/// Whether this entry is local or peer-routed.
	#[must_use]
	pub fn route_kind(&self) -> RouteKind {
		self.route_kind
	}

	/// Consecutive failures accumulated toward abandonment.
	#[must_use]
	pub fn trial_count(&self) -> u32 {
		self.trial_count.load(Ordering::Relaxed)
	}

	/// Operator view of peer route fields, when this entry is peer-routed.
	///
	/// `peer_id` is the advertising origin for relay trails too. The
	/// relay hop stays on [`ServletEntry::relay_id`].
	#[must_use]
	pub fn peer_route_info(&self) -> Option<PeerRouteInfo> {
		match self.route_kind {
			RouteKind::Local => None,
			RouteKind::Peer | RouteKind::PeerRelay => Some(PeerRouteInfo {
				// Shared identity bytes: Arc clone only.
				servlet_type: Arc::clone(&self.servlet_type),
				dial_addr: Arc::clone(&self.dial_addr),
				peer_id: Arc::clone(&self.owner_id),
			}),
		}
	}

	/// True when consecutive failures reached the abandonment limit.
	#[must_use]
	pub fn is_abandoned(&self) -> bool {
		self.trial_count.load(Ordering::Relaxed) >= self.abandonment_limit
	}

	/// True when the entry remains selectable for routing.
	#[must_use]
	pub fn is_live(&self) -> bool {
		!self.is_abandoned()
	}

	/// Current pheromone level used by weighted selection.
	#[must_use]
	pub fn pheromone_level(&self) -> u64 {
		self.pheromone.load(Ordering::Relaxed)
	}

	/// Raise pheromone after a successful request and clear the failure streak.
	///
	/// One `fetch_update` keeps concurrent evaporation from discarding the
	/// reinforcement.
	pub fn reinforce(&self, quality: u64) {
		let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			Some(current.saturating_add(quality).min(MAX_PHEROMONE))
		});
		self.trial_count.store(0, Ordering::Relaxed);
	}

	/// Count one failure toward abandonment.
	pub fn weaken(&self) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
	}

	/// Count one failure and optionally subtract pheromone.
	pub fn weaken_with_penalty(&self, penalty: u64) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
		if penalty > 0 {
			let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				Some(current.saturating_sub(penalty))
			});
		}
	}

	/// Decay pheromone by `rate` basis points.
	pub fn evaporate(&self, rate: BasisPoints) {
		let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			let decay = current.saturating_mul(rate.get() as u64) / 10000;
			Some(current.saturating_sub(decay))
		});
	}

	/// Carries pheromone and trial state across a peer-route replacement.
	///
	/// `installed_at` is deliberately not carried: a replacement is a
	/// fresh reconcile, and staleness pruning must see it as one.
	pub(super) fn preserve_peer_trail_from(&mut self, prev: &Self) {
		let both_peer = self.route_kind.is_peer() && prev.route_kind.is_peer();
		if !both_peer {
			return;
		}

		self.pheromone = AtomicU64::new(prev.pheromone.load(Ordering::Relaxed));
		self.trial_count = AtomicU32::new(prev.trial_count.load(Ordering::Relaxed));
		self.last_reinforced = prev.last_reinforced;
	}
}

impl Clone for ServletEntry {
	fn clone(&self) -> Self {
		Self {
			route_key: Arc::clone(&self.route_key),
			servlet_type: Arc::clone(&self.servlet_type),
			bucket: Arc::clone(&self.bucket),
			owner_id: Arc::clone(&self.owner_id),
			relay_id: self.relay_id.as_ref().map(Arc::clone),
			dial_addr: Arc::clone(&self.dial_addr),
			route_kind: self.route_kind,
			pheromone: AtomicU64::new(self.pheromone.load(Ordering::Relaxed)),
			last_reinforced: self.last_reinforced,
			trial_count: AtomicU32::new(self.trial_count.load(Ordering::Relaxed)),
			abandonment_limit: self.abandonment_limit,
			installed_at: self.installed_at,
		}
	}
}
