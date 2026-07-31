use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::colony::cluster::SharedId;
use crate::colony::common::MAX_PHEROMONE;
use crate::utils::BasisPoints;

/// How the load balancer reaches an entry.
///
/// `Local` resolves to a servlet this gateway owns. `Peer` resolves to
/// a peer gateway that owns the servlet, reached by forwarding. Both
/// share the same pheromone scoring tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteKind {
	#[default]
	Local,
	Peer,
}

/// A servlet instance tracked with pheromone score and trial count.
///
/// Fields are private so the route-key discipline holds by construction:
/// [`ServletEntry::local`] keys by the servlet address it dials, while
/// [`ServletEntry::peer`] keys by `peer_id NUL servlet_type` and dials
/// the claimed gateway socket.
#[derive(Debug)]
pub struct ServletEntry {
	/// Registry map key and pheromone trail identity.
	route_key: SharedId,
	servlet_type: SharedId,
	/// Local hive address, or advertising peer certificate fingerprint.
	owner_id: SharedId,
	/// Socket dialed when forwarding. Local entries use `route_key`.
	dial_addr: SharedId,
	route_kind: RouteKind,
	pheromone: AtomicU64,
	last_reinforced: Instant,
	trial_count: AtomicU32,
	abandonment_limit: u32,
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
			owner_id: hive_id,
			dial_addr: address,
			route_kind: RouteKind::Local,
			pheromone: AtomicU64::new(initial_pheromone),
			last_reinforced: Instant::now(),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
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
		let mut route_key = Vec::with_capacity(peer_id.len() + 1 + servlet_type.len());
		route_key.extend_from_slice(&peer_id);
		route_key.push(0);
		route_key.extend_from_slice(&servlet_type);

		Self {
			route_key: Arc::from(route_key.as_slice()),
			servlet_type,
			owner_id: peer_id,
			dial_addr,
			route_kind: RouteKind::Peer,
			pheromone: AtomicU64::new(initial_pheromone),
			last_reinforced: Instant::now(),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
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

	/// Local hive address, or advertising peer certificate fingerprint.
	#[must_use]
	pub fn owner_id(&self) -> &SharedId {
		&self.owner_id
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
	#[must_use]
	pub fn peer_route_info(&self) -> Option<PeerRouteInfo> {
		match self.route_kind {
			RouteKind::Local => None,
			RouteKind::Peer => Some(PeerRouteInfo {
				// Shared identity bytes: Arc clone only.
				servlet_type: Arc::clone(&self.servlet_type),
				dial_addr: Arc::clone(&self.dial_addr),
				peer_id: Arc::clone(&self.owner_id),
			}),
		}
	}

	/// True when consecutive failures reached the abandonment limit.
	pub fn is_abandoned(&self) -> bool {
		self.trial_count.load(Ordering::Relaxed) >= self.abandonment_limit
	}

	/// True when the entry remains selectable for routing.
	pub fn is_live(&self) -> bool {
		!self.is_abandoned()
	}

	/// Current pheromone level used by weighted selection.
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

	pub(super) fn preserve_peer_trail_from(&mut self, prev: &Self) {
		let both_peer = self.route_kind == RouteKind::Peer && prev.route_kind == RouteKind::Peer;
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
			owner_id: Arc::clone(&self.owner_id),
			dial_addr: Arc::clone(&self.dial_addr),
			route_kind: self.route_kind,
			pheromone: AtomicU64::new(self.pheromone.load(Ordering::Relaxed)),
			last_reinforced: self.last_reinforced,
			trial_count: AtomicU32::new(self.trial_count.load(Ordering::Relaxed)),
			abandonment_limit: self.abandonment_limit,
		}
	}
}
