//! Servlet route registry with pheromone scoring and trial-based abandonment.
//!
//! - Pheromone rises on successful work and decays on a timer.
//! - Trial count rises on failure; entries abandon past a limit.
//! - Local hive routes and peer-learned routes share the same scoring tables.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use super::error::ClusterError;
use super::peer::AdmittedPeerAd;
use super::SharedId;
use crate::colony::common::MAX_PHEROMONE;
use crate::constants::{MAX_PEER_GATEWAYS, MAX_PEER_ROUTES};
use crate::utils::BasisPoints;

// ============================================================================
// Configuration
// ============================================================================

/// Default pheromone configuration constants
pub const DEFAULT_EVAPORATION_RATE_BPS: u16 = 1000; // 10% per interval
pub const DEFAULT_EVAPORATION_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_INITIAL_PHEROMONE: u64 = 5000; // 50% of max
pub const DEFAULT_ABANDONMENT_LIMIT: u32 = 5;

/// Configuration for pheromone-based servlet tracking
#[derive(Debug, Clone)]
pub struct PheromoneConfig {
	/// Decay rate per evaporation cycle in basis points (1000 = 10%)
	pub evaporation_rate: BasisPoints,
	/// How often to run evaporation
	pub evaporation_interval: Duration,
	/// Starting pheromone level for new entries
	pub initial_pheromone: u64,
	/// Max consecutive failures before abandonment
	pub abandonment_limit: u32,
	/// Pheromone boost on successful request (default: 500 = 5% boost)
	pub reinforcement_boost: u64,
	/// Pheromone penalty on failed request (default: 0, only trial_count incremented)
	pub weakening_penalty: u64,
}

/// Default reinforcement boost (500 = 5% pheromone increase on success)
pub const DEFAULT_REINFORCEMENT_BOOST: u64 = 500;
/// Default weakening penalty (0 = only increment trial count on failure)
pub const DEFAULT_WEAKENING_PENALTY: u64 = 0;

impl Default for PheromoneConfig {
	fn default() -> Self {
		Self {
			evaporation_rate: BasisPoints::new(DEFAULT_EVAPORATION_RATE_BPS),
			evaporation_interval: Duration::from_secs(DEFAULT_EVAPORATION_INTERVAL_SECS),
			initial_pheromone: DEFAULT_INITIAL_PHEROMONE,
			abandonment_limit: DEFAULT_ABANDONMENT_LIMIT,
			reinforcement_boost: DEFAULT_REINFORCEMENT_BOOST,
			weakening_penalty: DEFAULT_WEAKENING_PENALTY,
		}
	}
}

/// Storage caps for peer-learned routes (CWE-770)
///
/// A named pair so gateway and route limits cannot be transposed at a
/// callsite: two adjacent `usize` arguments would swap silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCaps {
	/// Max distinct peer gateways holding installed slates
	pub max_gateways: usize,
	/// Max total stored peer routes across all gateways
	pub max_routes: usize,
}

impl Default for PeerCaps {
	fn default() -> Self {
		Self { max_gateways: MAX_PEER_GATEWAYS, max_routes: MAX_PEER_ROUTES }
	}
}

// ============================================================================
// Servlet Entry
// ============================================================================

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
	/// Registry map key and pheromone trail identity
	route_key: SharedId,
	servlet_type: SharedId,
	/// Local hive address, or advertising peer's cert fingerprint
	owner_id: SharedId,
	/// Socket dialed when forwarding (`route_key` for Local entries)
	dial_addr: SharedId,
	route_kind: RouteKind,
	pheromone: AtomicU64,
	last_reinforced: Instant,
	trial_count: AtomicU32,
	abandonment_limit: u32,
}

/// Operator view of one learned peer route
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouteInfo {
	/// Canonical servlet type bytes
	pub servlet_type: Vec<u8>,
	/// Claimed peer gateway dial address
	pub dial_addr: Vec<u8>,
	/// Advertising peer identity (cert fingerprint)
	pub peer_id: Vec<u8>,
}

impl ServletEntry {
	/// Local servlet reachable at `address`, owned by `hive_id`
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

	/// Peer route: map key is `peer_id NUL servlet_type`, dial is `dial_addr`
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

	/// Create a local entry (alias of [`Self::local`])
	pub fn new(
		address: SharedId,
		servlet_type: SharedId,
		hive_id: SharedId,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		Self::local(address, servlet_type, hive_id, initial_pheromone, abandonment_limit)
	}

	/// Registry map key and pheromone trail identity
	#[must_use]
	pub fn route_key(&self) -> &SharedId {
		&self.route_key
	}

	/// Socket address dialed when forwarding through this entry
	#[must_use]
	pub fn dial_target(&self) -> &SharedId {
		&self.dial_addr
	}

	/// Local hive address, or peer cert fingerprint for [`RouteKind::Peer`]
	#[must_use]
	pub fn owner_id(&self) -> &SharedId {
		&self.owner_id
	}

	/// Servlet type key bytes
	#[must_use]
	pub fn servlet_type(&self) -> &SharedId {
		&self.servlet_type
	}

	/// Whether this entry is local or peer-routed
	#[must_use]
	pub fn route_kind(&self) -> RouteKind {
		self.route_kind
	}

	/// Consecutive failure count toward abandonment
	#[must_use]
	pub fn trial_count(&self) -> u32 {
		self.trial_count.load(Ordering::Relaxed)
	}

	/// Operator view when this entry is a peer route
	#[must_use]
	pub fn peer_route_info(&self) -> Option<PeerRouteInfo> {
		match self.route_kind {
			RouteKind::Local => None,
			RouteKind::Peer => Some(PeerRouteInfo {
				servlet_type: self.servlet_type.to_vec(),
				dial_addr: self.dial_addr.to_vec(),
				peer_id: self.owner_id.to_vec(),
			}),
		}
	}

	/// Check if this entry should be abandoned (too many failures)
	pub fn is_abandoned(&self) -> bool {
		self.trial_count.load(Ordering::Relaxed) >= self.abandonment_limit
	}

	/// Whether the entry is selectable for routing (not abandoned)
	pub fn is_live(&self) -> bool {
		!self.is_abandoned()
	}

	/// Get current pheromone level
	pub fn pheromone_level(&self) -> u64 {
		self.pheromone.load(Ordering::Relaxed)
	}

	/// Reinforce pheromone on success
	///
	/// Quality is added directly to pheromone, capped at MAX_PHEROMONE.
	/// Read-modify-write is a single `fetch_update` so a concurrent
	/// evaporation cycle cannot silently drop the reinforcement.
	pub fn reinforce(&self, quality: u64) {
		let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			Some(current.saturating_add(quality).min(MAX_PHEROMONE))
		});

		// Reset trial count on success
		self.trial_count.store(0, Ordering::Relaxed);
	}

	/// Weaken entry on failure (increment trial count)
	pub fn weaken(&self) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
	}

	/// Weaken entry with pheromone penalty on failure
	///
	/// Increments trial count and applies optional pheromone penalty.
	pub fn weaken_with_penalty(&self, penalty: u64) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
		if penalty > 0 {
			let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				Some(current.saturating_sub(penalty))
			});
		}
	}

	/// Apply evaporation decay
	///
	/// Rate is in basis points (1000 = 10% decay)
	pub fn evaporate(&self, rate: BasisPoints) {
		let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			let decay = current.saturating_mul(rate.get() as u64) / 10000;
			Some(current.saturating_sub(decay))
		});
	}

	/// Copy trail metrics from `prev` onto this Peer entry (Peer-on-Peer only)
	fn preserve_peer_trail_from(&mut self, prev: &Self) {
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

// ============================================================================
// Servlet Registry
// ============================================================================

/// Registry of servlet entries with pheromone-based routing.
///
/// Tracks servlet instances across hives and peer gateways. Reinforcement
/// and evaporation steer selection; trial limits abandon dead routes.
pub struct ServletRegistry {
	/// Map of servlet address -> entry
	entries: RwLock<HashMap<SharedId, ServletEntry>>,
	/// Reverse index: servlet_type -> Vec<address>
	type_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Reverse index: hive_id -> Vec<address>
	hive_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Serializes slate accept and reconciliation: conflict/cap checks and
	/// install span several lock acquisitions and must not interleave.
	/// Local installs hold it too, so a local route cannot land between a
	/// peer ad's conflict probe and its install.
	reconcile_gate: Mutex<()>,
	/// Configuration
	config: PheromoneConfig,
}

impl ServletRegistry {
	/// Create a new registry with the given configuration
	pub fn new(config: PheromoneConfig) -> Self {
		Self {
			entries: RwLock::new(HashMap::new()),
			type_index: RwLock::new(HashMap::new()),
			hive_index: RwLock::new(HashMap::new()),
			reconcile_gate: Mutex::new(()),
			config,
		}
	}

	/// Add a servlet entry
	///
	/// Re-registering an address replaces the previous entry and retires
	/// its index rows first: otherwise a reconnecting hive accumulates
	/// duplicate addresses in the type/hive indices, multiplying its
	/// load-balancer selection weight.
	///
	/// Peer-on-Peer replacement at the same route key keeps the prior
	/// pheromone and trial state so advertise beats do not reset trails.
	pub fn add(&self, entry: ServletEntry) -> Result<(), ClusterError> {
		let addr = Arc::clone(entry.route_key());
		let servlet_type = Arc::clone(entry.servlet_type());
		let hive_id = Arc::clone(entry.owner_id());

		let previous = {
			let mut entries = self.entries.write()?;
			let mut entry = entry;
			if let Some(prev) = entries.get(addr.as_ref()) {
				entry.preserve_peer_trail_from(prev);
			}

			let addr = Arc::clone(&addr);
			entries.insert(addr, entry)
		};

		if let Some(ref prev) = previous {
			self.remove_index_rows(prev, &addr)?;
		}

		// Add to type index
		{
			let mut type_idx = self.type_index.write()?;
			let addr = Arc::clone(&addr);
			type_idx.entry(servlet_type).or_default().push(addr);
		}

		// Add to hive index
		{
			let mut hive_idx = self.hive_index.write()?;
			hive_idx.entry(hive_id).or_default().push(addr);
		}

		Ok(())
	}

	/// Remove the type/hive index rows recorded for `entry` under `address`
	fn remove_index_rows(&self, entry: &ServletEntry, address: &[u8]) -> Result<(), ClusterError> {
		{
			let mut type_idx = self.type_index.write()?;
			if let Some(addrs) = type_idx.get_mut(entry.servlet_type()) {
				addrs.retain(|a| a.as_ref() != address);
				if addrs.is_empty() {
					type_idx.remove(entry.servlet_type());
				}
			}
		}

		{
			let mut hive_idx = self.hive_index.write()?;
			if let Some(addrs) = hive_idx.get_mut(entry.owner_id()) {
				addrs.retain(|a| a.as_ref() != address);
				if addrs.is_empty() {
					hive_idx.remove(entry.owner_id());
				}
			}
		}

		Ok(())
	}

	/// Add entries for all servlet types from a hive
	///
	/// Creates one entry per servlet type, using hive address as servlet address
	/// (servlet-level addresses can be added later via direct registration).
	/// Holds `reconcile_gate` so the local install cannot interleave with a
	/// peer conflict probe in [`Self::reconcile_peer_slate`].
	pub fn add_entries_from_hive(
		&self,
		hive_id: &SharedId,
		hive_address: &SharedId,
		servlet_types: &[SharedId],
	) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;
		for servlet_type in servlet_types {
			let entry = ServletEntry::new(
				Arc::clone(hive_address),
				Arc::clone(servlet_type),
				Arc::clone(hive_id),
				self.config.initial_pheromone,
				self.config.abandonment_limit,
			);
			self.add(entry)?;
		}
		Ok(())
	}

	/// Remove a servlet entry by address
	pub fn remove(&self, address: &[u8]) -> Result<Option<ServletEntry>, ClusterError> {
		let entry = {
			let mut entries = self.entries.write()?;
			entries.remove(address)
		};

		if let Some(ref e) = entry {
			self.remove_index_rows(e, address)?;
		}

		Ok(entry)
	}

	/// Replace one hive's slate with `entries`, all-or-nothing.
	///
	/// Installs the new entries first, then prunes the hive's addresses
	/// absent from the new slate: remove-then-add would drop every route
	/// before the first add. Any mid-flight failure rolls back to the
	/// prior slate, so a caller never observes a mixed one. Every entry
	/// must carry `hive_id` as its hive, or the prune misses it.
	///
	/// Serialized by `reconcile_gate`: a local slate that lands between
	/// [`Self::reconcile_peer_slate`]'s conflict probe and its install
	/// would be replaced by peer rows the probe was meant to refuse.
	pub fn reconcile_by_hive(&self, hive_id: &[u8], entries: Vec<ServletEntry>) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;
		self.reconcile_slate(hive_id, entries)
	}

	/// Ungated reconcile body; callers hold `reconcile_gate`
	fn reconcile_slate(&self, hive_id: &[u8], entries: Vec<ServletEntry>) -> Result<(), ClusterError> {
		let prior: Vec<ServletEntry> = {
			let addresses: Vec<SharedId> = {
				let hive_idx = self.hive_index.read()?;
				hive_idx.get(hive_id).cloned().unwrap_or_default()
			};
			let map = self.entries.read()?;
			addresses.iter().filter_map(|addr| map.get(addr.as_ref()).cloned()).collect()
		};

		let mut fresh: Vec<SharedId> = Vec::with_capacity(entries.len());
		for entry in entries {
			let addr = Arc::clone(entry.route_key());
			if let Err(err) = self.add(entry) {
				self.restore_slate(&fresh, &prior);
				return Err(err);
			}

			fresh.push(addr);
		}

		let stale: Vec<SharedId> = {
			let hive_idx = self.hive_index.read()?;
			hive_idx
				.get(hive_id)
				.cloned()
				.unwrap_or_default()
				.into_iter()
				.filter(|addr| !fresh.iter().any(|kept| kept.as_ref() == addr.as_ref()))
				.collect()
		};

		for addr in &stale {
			if let Err(err) = self.remove(addr) {
				self.restore_slate(&fresh, &prior);
				return Err(err);
			}
		}

		Ok(())
	}

	/// Best-effort rollback for a failed reconcile: retire the fresh
	/// installs, then re-add the prior slate (covering entries the fresh
	/// installs displaced and any already-pruned stale routes).
	fn restore_slate(&self, fresh: &[SharedId], prior: &[ServletEntry]) {
		for addr in fresh {
			let _ = self.remove(addr);
		}
		for entry in prior {
			let _ = self.add(entry.clone());
		}
	}

	/// Accept an admitted peer slate under one install lock (conflict + caps + reconcile)
	///
	/// Taking [`AdmittedPeerAd`] makes unvalidated slates unrepresentable:
	/// wire checks and signer keying already ran at construction. This
	/// method owns registry policy so concurrent ads cannot pass caps then
	/// both install. Fail-closed: internal errors propagate and the caller
	/// refuses the advertisement.
	pub fn reconcile_peer_slate(&self, ad: AdmittedPeerAd, caps: PeerCaps) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;

		if self.peer_key_conflicts_local(&ad.peer_hive_id)? || self.peer_dial_conflicts_local(&ad.dial_addr)? {
			return Err(ClusterError::PeerSlateConflict);
		}

		if self.peer_slate_exceeds_caps(&ad.peer_hive_id, ad.slate.len(), caps.max_gateways, caps.max_routes)? {
			return Err(ClusterError::PeerCapExceeded);
		}

		self.reconcile_slate(&ad.peer_hive_id, ad.slate)
	}

	/// Remove all entries belonging to a hive
	pub fn remove_by_hive(&self, hive_id: &[u8]) -> Result<Vec<ServletEntry>, ClusterError> {
		let addresses: Vec<SharedId> = {
			let hive_idx = self.hive_index.read()?;
			hive_idx.get(hive_id).cloned().unwrap_or_default()
		};

		let mut removed = Vec::with_capacity(addresses.len());
		for addr in &addresses {
			if let Some(entry) = self.remove(addr)? {
				removed.push(entry);
			}
		}

		Ok(removed)
	}

	/// Apply a batch of servlet address adds/removes for one hive.
	///
	/// Atomic: either every change lands or the registry is unchanged.
	/// Rejects adds/removes that reference another hive's routes.
	/// Holds `reconcile_gate` so the local install cannot interleave with a
	/// peer conflict probe in [`Self::reconcile_peer_slate`].
	pub fn apply_address_update(
		&self,
		hive_id: &[u8],
		added: Vec<ServletEntry>,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;
		for entry in &added {
			if entry.owner_id().as_ref() != hive_id {
				return Err(ClusterError::ServletNotOwned);
			}
		}

		{
			let entries = self.entries.read()?;
			for addr in removed {
				if let Some(entry) = entries.get(*addr) {
					if entry.owner_id().as_ref() != hive_id {
						return Err(ClusterError::ServletNotOwned);
					}
				}
			}
		}

		let mut applied_addrs: Vec<SharedId> = Vec::with_capacity(added.len());
		for entry in added {
			let addr = Arc::clone(entry.route_key());
			if let Err(err) = self.add(entry) {
				for applied in &applied_addrs {
					let _ = self.remove(applied);
				}

				return Err(err);
			}

			applied_addrs.push(addr);
		}

		let mut removed_entries: Vec<ServletEntry> = Vec::with_capacity(removed.len());
		for addr in removed {
			match self.remove(addr) {
				Ok(Some(entry)) => removed_entries.push(entry),
				Ok(None) => {
					for entry in removed_entries {
						let _ = self.add(entry);
					}
					for applied in &applied_addrs {
						let _ = self.remove(applied);
					}

					return Err(ClusterError::ServletNotFound);
				}
				Err(err) => {
					for entry in removed_entries {
						let _ = self.add(entry);
					}
					for applied in &applied_addrs {
						let _ = self.remove(applied);
					}

					return Err(err);
				}
			}
		}

		Ok(())
	}

	/// Get entries for a servlet type (for load balancing)
	pub fn entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<ServletEntry>, ClusterError> {
		let addresses: Vec<SharedId> = {
			let type_idx = self.type_index.read()?;
			type_idx.get(servlet_type).cloned().unwrap_or_default()
		};

		let entries = self.entries.read()?;
		let result: Vec<ServletEntry> = addresses
			.iter()
			.filter_map(|addr| entries.get(addr.as_ref()).cloned())
			.filter(|e| e.is_live())
			.collect();

		Ok(result)
	}

	/// Live entries for a servlet type owned by this gateway's own hives
	///
	/// Used when inbound work is already forwarded: the loop guard serves
	/// local routes only and never re-forwards to a peer.
	pub fn local_entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<ServletEntry>, ClusterError> {
		let entries = self.entries_for_type(servlet_type)?;
		let local = entries
			.into_iter()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.collect();

		Ok(local)
	}

	/// Distinct servlet types owned by this gateway's own hives, sorted
	///
	/// Route truth for the advertise beat: unlike the hive registry's
	/// registration-time servlet index, this sees address updates and
	/// eviction.
	pub fn local_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		let entries = self.entries.read()?;
		let mut types: Vec<SharedId> = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.filter(|entry| entry.is_live())
			.map(|entry| Arc::clone(entry.servlet_type()))
			.collect();

		types.sort_unstable();
		types.dedup();

		Ok(types)
	}

	/// Whether a peer slate keyed by `hive_id` would touch local routes
	///
	/// Peer installs replace only prior Peer state. A local servlet at the
	/// same address key, or a local hive owning the same hive-index key,
	/// means the advertisement would clobber routes another trust plane
	/// installed, so the caller refuses it.
	fn peer_key_conflicts_local(&self, hive_id: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let address_taken = entries.get(hive_id).is_some_and(|entry| entry.route_kind() == RouteKind::Local);
		if address_taken {
			return Ok(true);
		}

		let hive_idx = self.hive_index.read()?;
		let Some(addresses) = hive_idx.get(hive_id) else {
			return Ok(false);
		};

		let hive_taken = addresses.iter().any(|addr| {
			entries
				.get(addr.as_ref())
				.is_some_and(|entry| entry.route_kind() == RouteKind::Local)
		});

		Ok(hive_taken)
	}

	/// Whether a peer dial address collides with a local servlet address
	///
	/// An unverified claimed gateway that matches a local servlet would
	/// let forwarded work reflect into the hive trust plane (CWE-918).
	fn peer_dial_conflicts_local(&self, dial_addr: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let conflict = entries
			.values()
			.any(|entry| entry.route_kind() == RouteKind::Local && entry.route_key().as_ref() == dial_addr);

		Ok(conflict)
	}

	/// Whether installing `new_slate_len` routes for `hive_id` exceeds peer caps
	///
	/// Counts every stored Peer route and distinct Peer gateway, replacing
	/// this hive's prior slate size so a re-advertise does not double-count.
	/// Abandoned entries count too: they hold registry storage until pruned,
	/// so excluding them would let stored routes exceed the cap.
	fn peer_slate_exceeds_caps(
		&self,
		hive_id: &[u8],
		new_slate_len: usize,
		max_gateways: usize,
		max_routes: usize,
	) -> Result<bool, ClusterError> {
		if new_slate_len == 0 {
			return Ok(false);
		}

		let entries = self.entries.read()?;
		let mut peer_total = 0usize;
		let mut prior_for_hive = 0usize;
		let mut gateways: HashSet<&[u8]> = HashSet::new();
		for entry in entries.values().filter(|entry| entry.route_kind() == RouteKind::Peer) {
			peer_total += 1;

			let owner = entry.owner_id().as_ref();
			gateways.insert(owner);

			if owner == hive_id {
				prior_for_hive += 1;
			}
		}

		let routes_after = peer_total.saturating_sub(prior_for_hive).saturating_add(new_slate_len);
		if routes_after > max_routes {
			return Ok(true);
		}

		let gateways_after = gateways.len().saturating_add(usize::from(!gateways.contains(hive_id)));
		Ok(gateways_after > max_gateways)
	}

	/// Live entries reached through a peer gateway (`RouteKind::Peer`)
	///
	/// Abandoned trails are excluded: an isolated peer nest is
	/// unreachable, so it is neither advertised nor re-flooded.
	pub fn peer_entries(&self) -> Result<Vec<ServletEntry>, ClusterError> {
		let entries = self.entries.read()?;
		let result = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.filter(|entry| entry.is_live())
			.cloned()
			.collect();

		Ok(result)
	}

	/// Reinforce pheromone for a servlet on success
	pub fn reinforce(&self, address: &[u8], quality: u64) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		if let Some(entry) = entries.get(address) {
			entry.reinforce(quality);
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Weaken a servlet on failure (increment trial count)
	pub fn weaken(&self, address: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		if let Some(entry) = entries.get(address) {
			entry.weaken();
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Weaken a servlet with pheromone penalty on failure
	pub fn weaken_with_penalty(&self, address: &[u8], penalty: u64) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		if let Some(entry) = entries.get(address) {
			entry.weaken_with_penalty(penalty);
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Weaken every live Peer route advertised by one peer identity
	///
	/// Misbehavior scoring for the gossip plane: a peer that relays
	/// invalid gossip is weakened across all of its `peer_id NUL type`
	/// trails, since the misbehavior is the peer's, not one route's.
	/// Returns the number of entries weakened.
	pub fn weaken_peer(&self, peer_id: &[u8]) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		let weakened = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.filter(|entry| entry.is_live())
			.filter(|entry| entry.owner_id().as_ref() == peer_id)
			.map(ServletEntry::weaken)
			.count();

		Ok(weakened)
	}

	/// Weaken every live Peer route dialed through one gateway address
	///
	/// Misbehavior scoring for anti-entropy, where the peer is known by
	/// the address this gateway reconciles with rather than by a signer
	/// fingerprint: reconciliation replies are unsigned, and the peer
	/// pool's pinned trust authenticates the endpoint at that address.
	/// Returns the number of entries weakened.
	pub fn weaken_peer_by_dial(&self, dial_addr: &[u8]) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		let weakened = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.filter(|entry| entry.is_live())
			.filter(|entry| entry.dial_target().as_ref() == dial_addr)
			.map(ServletEntry::weaken)
			.count();

		Ok(weakened)
	}

	/// Apply evaporation to all entries
	pub fn evaporate(&self) -> Result<(), ClusterError> {
		let entries = self.entries.read()?;
		let rate = self.config.evaporation_rate;
		for entry in entries.values() {
			entry.evaporate(rate);
		}
		Ok(())
	}

	/// Remove all abandoned entries (trial_count >= abandonment_limit)
	pub fn remove_abandoned(&self) -> Result<usize, ClusterError> {
		let abandoned: Vec<SharedId> = {
			let entries = self.entries.read()?;
			entries
				.iter()
				.filter(|(_, e)| e.is_abandoned())
				.map(|(addr, _)| Arc::clone(addr))
				.collect()
		};

		let count = abandoned.len();
		for addr in &abandoned {
			self.remove(addr)?;
		}

		Ok(count)
	}

	/// Get configuration
	pub fn config(&self) -> &PheromoneConfig {
		&self.config
	}

	/// Count of tracked servlets
	pub fn len(&self) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		Ok(entries.len())
	}

	/// Check if registry is empty
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		Ok(self.len()? == 0)
	}
}

impl Default for ServletRegistry {
	fn default() -> Self {
		Self::new(PheromoneConfig::default())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// =========================================================================
	// Test Helpers
	// =========================================================================

	/// Create a test entry with specified pheromone and abandonment limit
	fn test_entry(pheromone: u64, abandonment_limit: u32) -> ServletEntry {
		ServletEntry::new(
			Arc::from(b"addr".as_slice()),
			Arc::from(b"type".as_slice()),
			Arc::from(b"hive".as_slice()),
			pheromone,
			abandonment_limit,
		)
	}

	/// Create a named test entry for registry tests
	fn named_entry(addr: &[u8], servlet_type: &[u8], hive: &[u8]) -> ServletEntry {
		ServletEntry::new(
			Arc::from(addr),
			Arc::from(servlet_type),
			Arc::from(hive),
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	/// Create a named test entry routed through a peer gateway
	fn peer_entry(servlet_type: &[u8], peer_id: &[u8]) -> ServletEntry {
		ServletEntry::peer(
			Arc::from(peer_id),
			Arc::from(servlet_type),
			Arc::from(b"127.0.0.1:9000".as_slice()),
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	fn peer_entry_dial(servlet_type: &[u8], peer_id: &[u8], dial: &[u8]) -> ServletEntry {
		ServletEntry::peer(
			Arc::from(peer_id),
			Arc::from(servlet_type),
			Arc::from(dial),
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	// =========================================================================
	// ServletEntry Tests - Data-Driven
	// =========================================================================

	/// Test cases: (initial_pheromone, reinforce_amount, expected_result)
	const REINFORCE_CASES: &[(u64, u64, u64)] = &[
		(5000, 1000, 6000),                  // normal add
		(9500, 1000, MAX_PHEROMONE),         // caps at max
		(0, 500, 500),                       // from zero
		(MAX_PHEROMONE, 100, MAX_PHEROMONE), // already at max
	];

	#[test]
	fn entry_reinforce_pheromone() {
		for &(initial, amount, expected) in REINFORCE_CASES {
			let entry = test_entry(initial, 5);
			entry.reinforce(amount);
			assert_eq!(entry.pheromone_level(), expected);
		}
	}

	/// Test cases: (initial_pheromone, decay_rate_bps, expected_result)
	const EVAPORATE_CASES: &[(u64, u16, u64)] = &[
		(10000, 1000, 9000), // 10% decay
		(5000, 2000, 4000),  // 20% decay
		(100, 5000, 50),     // 50% decay
		(0, 1000, 0),        // already zero
	];

	#[test]
	fn entry_evaporate_pheromone() {
		for &(initial, rate, expected) in EVAPORATE_CASES {
			let entry = test_entry(initial, 5);
			entry.evaporate(BasisPoints::new(rate));
			assert_eq!(entry.pheromone_level(), expected);
		}
	}

	#[test]
	fn entry_weaken_increments_trials() {
		let entry = test_entry(5000, 5);
		for expected in 1..=3 {
			entry.weaken();
			assert_eq!(entry.trial_count(), expected);
		}
	}

	#[test]
	fn entry_abandoned_after_limit() {
		let limit = 3;
		let entry = test_entry(5000, limit);

		// Not abandoned until reaching limit
		for _ in 0..limit {
			assert!(!entry.is_abandoned());
			entry.weaken();
		}
		assert!(entry.is_abandoned());
	}

	#[test]
	fn entry_reinforce_resets_trials() {
		let entry = test_entry(5000, 5);
		entry.weaken();
		entry.weaken();
		assert_eq!(entry.trial_count(), 2);

		entry.reinforce(100);
		assert_eq!(entry.trial_count(), 0);
	}

	// =========================================================================
	// ServletRegistry Tests
	// =========================================================================

	#[test]
	fn entry_route_kind_defaults_local() {
		let entry = named_entry(b"addr1", b"calculator", b"hive1");
		assert_eq!(entry.route_kind(), RouteKind::Local);
	}

	#[test]
	fn entry_local_dials_own_address() {
		let entry = named_entry(b"addr1", b"calculator", b"hive1");
		assert_eq!(entry.dial_target().as_ref(), entry.route_key().as_ref());
	}

	#[test]
	fn entry_peer_dials_gateway_not_route_key() {
		let entry = peer_entry(b"calc", b"fp");
		assert_eq!(entry.dial_target().as_ref(), b"127.0.0.1:9000");
		assert_ne!(entry.dial_target().as_ref(), entry.route_key().as_ref());
		assert_eq!(entry.route_key()[0], b'f');
		assert_eq!(entry.route_key()[2], 0);
	}

	#[test]
	fn peer_entries_filters_by_route_kind() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"local", b"calc", b"hive1")).ok();

		let empty = registry.peer_entries().ok().unwrap_or_default();
		assert!(empty.is_empty());

		let peer = peer_entry(b"calc", b"peer-colony");
		let route_key = Arc::clone(peer.route_key());
		registry.add(peer).ok();

		let peers = registry.peer_entries().ok().unwrap_or_default();
		assert_eq!(peers.len(), 1);
		assert_eq!(peers[0].route_key().as_ref(), route_key.as_ref());
	}

	#[test]
	fn peer_entries_excludes_abandoned() {
		let limit = 2;
		let config = PheromoneConfig { abandonment_limit: limit, ..Default::default() };
		let registry = ServletRegistry::new(config);

		let peer = ServletEntry::peer(
			Arc::from(b"peer-colony".as_slice()),
			Arc::from(b"calc".as_slice()),
			Arc::from(b"127.0.0.1:9000".as_slice()),
			DEFAULT_INITIAL_PHEROMONE,
			limit,
		);

		let route_key = Arc::clone(peer.route_key());
		registry.add(peer).ok();

		for _ in 0..limit {
			registry.weaken(&route_key).ok();
		}

		let peers = registry.peer_entries().ok().unwrap_or_default();
		assert!(peers.is_empty());
	}

	#[test]
	fn local_entries_for_type_excludes_peer_routes() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"local", b"calc", b"hive1")).ok();
		registry.add(peer_entry(b"calc", b"peer-colony")).ok();

		let local = registry.local_entries_for_type(b"calc").ok().unwrap_or_default();
		assert_eq!(local.len(), 1);
		assert_eq!(local[0].route_key().as_ref(), b"local");
	}

	#[test]
	fn local_entries_for_type_empty_when_only_peer_routes() {
		let registry = ServletRegistry::default();
		registry.add(peer_entry(b"calc", b"peer-colony")).ok();

		let local = registry.local_entries_for_type(b"calc").ok().unwrap_or_default();
		assert!(local.is_empty());
	}

	// Non-empty slates install before they prune, so a serialized
	// registry is never observably empty once seeded. An empty sighting
	// or a final count other than one proves interleaved reconciles
	// pruned each other's fresh installs.
	#[test]
	fn reconcile_by_hive_serializes_concurrent_slates() {
		use core::sync::atomic::{AtomicBool, Ordering};

		let registry = ServletRegistry::default();
		registry.reconcile_by_hive(b"gw", vec![peer_entry(b"urn:t:a", b"gw")]).ok();

		let saw_empty = AtomicBool::new(false);
		std::thread::scope(|scope| {
			scope.spawn(|| {
				for _ in 0..2000 {
					let slate = vec![peer_entry(b"urn:t:a", b"gw")];
					registry.reconcile_by_hive(b"gw", slate).ok();
				}
			});
			scope.spawn(|| {
				for _ in 0..2000 {
					let slate = vec![peer_entry(b"urn:t:b", b"gw")];
					registry.reconcile_by_hive(b"gw", slate).ok();
				}
			});
			scope.spawn(|| {
				for _ in 0..20000 {
					let empty = registry.peer_entries().ok().unwrap_or_default().is_empty();
					saw_empty.fetch_or(empty, Ordering::Relaxed);
				}
			});
		});

		assert!(!saw_empty.load(Ordering::Relaxed));
		assert_eq!(registry.peer_entries().ok().unwrap_or_default().len(), 1);
	}

	#[test]
	fn local_servlets_dedups_and_excludes_peer_routes() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"a1", b"calc", b"hive1")).ok();
		registry.add(named_entry(b"a2", b"calc", b"hive1")).ok();
		registry.add(named_entry(b"a3", b"echo", b"hive1")).ok();
		registry.add(peer_entry(b"urn:t:x", b"gw")).ok();

		let types = registry.local_servlets().ok().unwrap_or_default();
		assert_eq!(types.len(), 2);
	}

	#[test]
	fn local_servlets_tracks_adds_and_removes() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"a1", b"calc", b"hive1")).ok();
		registry.add(named_entry(b"a2", b"echo", b"hive1")).ok();
		registry.remove(b"a2").ok();

		let types = registry.local_servlets().ok().unwrap_or_default();
		assert_eq!(types.len(), 1);
		assert_eq!(types[0].as_ref(), b"calc");
	}

	#[test]
	fn reconcile_by_hive_installs_multi_type_slate() {
		let registry = ServletRegistry::default();
		let slate = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

		registry.reconcile_by_hive(b"gw", slate).ok();

		let peers = registry.peer_entries().ok().unwrap_or_default();
		assert_eq!(peers.len(), 2);
	}

	#[test]
	fn reconcile_by_hive_prunes_stale_routes() {
		let registry = ServletRegistry::default();
		let full = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

		registry.reconcile_by_hive(b"gw", full).ok();
		let shrunk = vec![peer_entry(b"urn:t:a", b"gw")];
		registry.reconcile_by_hive(b"gw", shrunk).ok();

		let peers = registry.peer_entries().ok().unwrap_or_default();
		assert_eq!(peers.len(), 1);
		assert_eq!(peers[0].servlet_type().as_ref(), b"urn:t:a");
	}

	#[test]
	fn reconcile_by_hive_leaves_other_hives_untouched() {
		let registry = ServletRegistry::default();
		let peer = peer_entry(b"urn:t:a", b"gw");
		registry.add(named_entry(b"local", b"urn:t:a", b"hive1")).ok();
		registry.reconcile_by_hive(b"gw", vec![peer]).ok();
		registry.reconcile_by_hive(b"gw", vec![]).ok();

		let locals = registry.local_entries_for_type(b"urn:t:a").ok().unwrap_or_default();
		assert_eq!(locals.len(), 1);
		assert!(registry.peer_entries().ok().unwrap_or_default().is_empty());
	}

	#[test]
	fn reconcile_by_hive_preserves_peer_trail_state() {
		let registry = ServletRegistry::default();
		let first = peer_entry(b"urn:t:a", b"fp");
		let route = Arc::clone(first.route_key());
		registry.reconcile_by_hive(b"fp", vec![first]).ok();
		registry.reinforce(&route, 1_000).ok();
		registry.weaken(&route).ok();

		let before = registry.entries_for_type(b"urn:t:a").ok().unwrap_or_default();
		let pheromone_before = before[0].pheromone_level();
		let trials_before = before[0].trial_count();

		registry
			.reconcile_by_hive(b"fp", vec![peer_entry_dial(b"urn:t:a", b"fp", b"127.0.0.1:9001")])
			.ok();

		let after = registry.entries_for_type(b"urn:t:a").ok().unwrap_or_default();
		assert_eq!(after[0].pheromone_level(), pheromone_before);
		assert_eq!(after[0].trial_count(), trials_before);
		assert_eq!(after[0].dial_target().as_ref(), b"127.0.0.1:9001");
	}

	#[test]
	fn peer_dial_conflicts_with_local_servlet_address() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"127.0.0.1:9000", b"calc", b"hive1")).ok();
		assert_eq!(registry.peer_dial_conflicts_local(b"127.0.0.1:9000").ok(), Some(true));
		assert_eq!(registry.peer_dial_conflicts_local(b"127.0.0.1:9001").ok(), Some(false));
	}

	#[test]
	fn peer_slate_exceeds_caps_counts_gateways_and_routes() {
		let registry = ServletRegistry::default();
		registry.reconcile_by_hive(b"fp1", vec![peer_entry(b"a", b"fp1")]).ok();
		registry.reconcile_by_hive(b"fp2", vec![peer_entry(b"a", b"fp2")]).ok();

		assert_eq!(registry.peer_slate_exceeds_caps(b"fp3", 1, 2, 1024).ok(), Some(true));
		assert_eq!(registry.peer_slate_exceeds_caps(b"fp1", 1, 2, 1024).ok(), Some(false));
		// fp1 prior=1, fp2=1; slate of 5 => routes_after=6 > max 5
		assert_eq!(registry.peer_slate_exceeds_caps(b"fp1", 5, 64, 5).ok(), Some(true));
		assert_eq!(registry.peer_slate_exceeds_caps(b"fp1", 0, 1, 1).ok(), Some(false));
	}

	fn admitted(hive: &[u8], dial: &[u8], slate: Vec<ServletEntry>) -> AdmittedPeerAd {
		AdmittedPeerAd { peer_hive_id: Arc::from(hive), dial_addr: Arc::from(dial), slate }
	}

	#[test]
	fn reconcile_peer_slate_refuses_over_gateway_cap() {
		let registry = ServletRegistry::default();
		let caps = PeerCaps { max_gateways: 1, ..Default::default() };
		let first_ad = admitted(b"fp1", b"127.0.0.1:9000", vec![peer_entry(b"a", b"fp1")]);
		let first = registry.reconcile_peer_slate(first_ad, caps);
		assert!(matches!(first, Ok(())));

		let second_ad = admitted(b"fp2", b"127.0.0.1:9001", vec![peer_entry(b"a", b"fp2")]);
		let second = registry.reconcile_peer_slate(second_ad, caps);
		assert!(matches!(second, Err(ClusterError::PeerCapExceeded)));
		assert_eq!(registry.peer_entries().ok().unwrap_or_default().len(), 1);
	}

	// A local slate and a peer ad race for the same hive-index key. Both
	// paths hold the reconcile gate, so the ad either sees the local rows
	// and refuses, or completes first and its rows are then replaced. A
	// missing local route at the end proves a local install landed inside
	// the ad's probe-to-install window and was clobbered by peer rows.
	#[test]
	fn reconcile_peer_slate_excludes_concurrent_local_install() {
		for _ in 0..500 {
			let registry = ServletRegistry::default();
			std::thread::scope(|scope| {
				scope.spawn(|| {
					let slate = vec![named_entry(b"gw", b"calc", b"gw")];
					registry.reconcile_by_hive(b"gw", slate).ok();
				});
				scope.spawn(|| {
					let ad = admitted(b"gw", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"gw")]);
					registry.reconcile_peer_slate(ad, PeerCaps::default()).ok();
				});
			});

			let locals = registry.local_entries_for_type(b"calc").ok().unwrap_or_default();
			assert_eq!(locals.len(), 1);
		}
	}

	#[test]
	fn peer_key_conflicts_only_with_local_routes() {
		// (seeded entry, probe key, expected conflict)
		let cases: &[(ServletEntry, &[u8], bool)] = &[
			(named_entry(b"gw", b"calc", b"hive1"), b"gw", true),
			(named_entry(b"addr1", b"calc", b"gw"), b"gw", true),
			(peer_entry(b"calc", b"gw"), b"gw", false),
			(peer_entry(b"calc", b"gw"), b"unseen", false),
		];

		for (entry, probe, expected) in cases {
			let registry = ServletRegistry::default();
			registry.add(entry.clone()).ok();

			assert_eq!(registry.peer_key_conflicts_local(probe).ok(), Some(*expected));
		}
	}

	#[test]
	fn registry_add_and_lookup() {
		let registry = ServletRegistry::default();
		let entry = named_entry(b"addr1", b"calculator", b"hive1");
		registry.add(entry).ok();

		let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
		assert_eq!(found.len(), 1);
		assert_eq!(found[0].route_key().as_ref(), b"addr1");
	}

	fn seed_reregistered_registry() -> ServletRegistry {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"addr1", b"calculator", b"hive1")).ok();
		registry.add(named_entry(b"addr1", b"calculator", b"hive1")).ok();
		registry
	}

	#[test]
	fn registry_reregistration_does_not_duplicate_indices() {
		let registry = seed_reregistered_registry();

		let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
		assert_eq!(found.len(), 1);
		assert!(matches!(registry.len().ok(), Some(1)));
	}

	#[test]
	fn registry_reregistration_moves_entry_across_types() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"addr1", b"calculator", b"hive1")).ok();
		registry.add(named_entry(b"addr1", b"auth", b"hive2")).ok();

		let calculator = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
		let auth = registry.entries_for_type(b"auth").ok().unwrap_or_default();
		assert!(calculator.is_empty());
		assert_eq!(auth.len(), 1);

		// Old hive index rows retired alongside the type rows
		let removed = registry.remove_by_hive(b"hive1").ok().unwrap_or_default();
		assert!(removed.is_empty());
	}

	#[test]
	fn registry_remove_after_reregistration_clears_entry() {
		let registry = seed_reregistered_registry();
		registry.remove(b"addr1").ok();

		let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
		assert!(found.is_empty());
	}

	#[test]
	fn registry_remove_abandoned_prunes_entries() {
		let limit = 2;
		let config = PheromoneConfig { abandonment_limit: limit, ..Default::default() };
		let registry = ServletRegistry::new(config);

		let entry = test_entry(5000, limit);
		registry.add(entry).ok();

		// Weaken to abandonment
		for _ in 0..limit {
			registry.weaken(b"addr").ok();
		}

		assert!(matches!(registry.remove_abandoned().ok(), Some(1)));
		assert!(matches!(registry.len().ok(), Some(0)));
	}

	#[test]
	fn weaken_peer_targets_all_routes_of_one_peer() -> Result<(), ClusterError> {
		let registry = ServletRegistry::default();
		registry.add(peer_entry(b"urn:t:a", b"fp-a"))?;
		registry.add(peer_entry(b"urn:t:b", b"fp-a"))?;
		registry.add(peer_entry(b"urn:t:a", b"fp-b"))?;

		let weakened = registry.weaken_peer(b"fp-a")?;

		assert_eq!(weakened, 2);
		Ok(())
	}

	#[test]
	fn weaken_peer_skips_local_routes() -> Result<(), ClusterError> {
		let registry = ServletRegistry::default();
		registry.add(named_entry(b"addr", b"urn:t:a", b"hive-a"))?;

		let weakened = registry.weaken_peer(b"hive-a")?;

		assert_eq!(weakened, 0);
		Ok(())
	}

	/// Create a peer-routed test entry with a specific abandonment limit
	fn peer_entry_limit(servlet_type: &[u8], peer_id: &[u8], limit: u32) -> ServletEntry {
		ServletEntry::peer(
			Arc::from(peer_id),
			Arc::from(servlet_type),
			Arc::from(b"127.0.0.1:9000".as_slice()),
			DEFAULT_INITIAL_PHEROMONE,
			limit,
		)
	}

	#[test]
	fn weaken_peer_abandons_after_limit_leaving_others_live() -> Result<(), ClusterError> {
		let limit = 2;
		let registry = ServletRegistry::default();
		registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", limit))?;
		registry.add(peer_entry_limit(b"urn:t:a", b"fp-b", limit))?;

		for _ in 0..limit {
			registry.weaken_peer(b"fp-a")?;
		}

		let live = registry.peer_entries()?;
		assert_eq!(live.len(), 1);
		assert_eq!(live[0].owner_id().as_ref(), b"fp-b");
		Ok(())
	}

	#[test]
	fn weaken_peer_skips_already_abandoned_routes() -> Result<(), ClusterError> {
		let limit = 2;
		let registry = ServletRegistry::default();
		registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", limit))?;

		for _ in 0..limit {
			registry.weaken_peer(b"fp-a")?;
		}

		let weakened = registry.weaken_peer(b"fp-a")?;
		assert_eq!(weakened, 0);
		Ok(())
	}

	#[test]
	fn weaken_peer_by_dial_targets_matching_gateway() -> Result<(), ClusterError> {
		let registry = ServletRegistry::default();
		registry.add(peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"))?;
		registry.add(peer_entry_dial(b"urn:t:b", b"fp-a", b"127.0.0.1:9100"))?;
		registry.add(peer_entry_dial(b"urn:t:a", b"fp-b", b"127.0.0.1:9200"))?;

		let weakened = registry.weaken_peer_by_dial(b"127.0.0.1:9100")?;

		assert_eq!(weakened, 2);
		Ok(())
	}

	#[test]
	fn weaken_peer_by_dial_ignores_unknown_gateway() -> Result<(), ClusterError> {
		let registry = ServletRegistry::default();
		registry.add(peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"))?;

		let weakened = registry.weaken_peer_by_dial(b"127.0.0.1:9999")?;

		assert_eq!(weakened, 0);
		Ok(())
	}

	struct ApplyAddressUpdateCase {
		seed: (&'static [u8], &'static [u8], &'static [u8]),
		caller_hive: &'static [u8],
		add: Option<(&'static [u8], &'static [u8], &'static [u8])>,
		remove: &'static [&'static [u8]],
		expect_ok: bool,
		expected_addrs: &'static [&'static [u8]],
	}

	fn apply_address_update_cases() -> Vec<ApplyAddressUpdateCase> {
		const VICTIM: &[&[u8]] = &[b"victim"];
		const OLD: &[&[u8]] = &[b"old"];
		const NEW: &[&[u8]] = &[b"new"];
		const MISSING: &[&[u8]] = &[b"ghost"];

		vec![
			ApplyAddressUpdateCase {
				seed: (b"victim", b"calc", b"hive-a"),
				caller_hive: b"hive-b",
				add: Some((b"poison", b"calc", b"hive-b")),
				remove: VICTIM,
				expect_ok: false,
				expected_addrs: VICTIM,
			},
			ApplyAddressUpdateCase {
				seed: (b"old", b"calc", b"hive-a"),
				caller_hive: b"hive-a",
				add: Some((b"new", b"calc", b"hive-a")),
				remove: OLD,
				expect_ok: true,
				expected_addrs: NEW,
			},
			// A remove naming an absent locator must refuse: Ok(None) must
			// not report success while the seeded route stays routed.
			ApplyAddressUpdateCase {
				seed: (b"victim", b"calc", b"hive-a"),
				caller_hive: b"hive-a",
				add: None,
				remove: MISSING,
				expect_ok: false,
				expected_addrs: VICTIM,
			},
		]
	}

	#[test]
	fn apply_address_update_ownership_and_atomicity() {
		for case in apply_address_update_cases() {
			let registry = ServletRegistry::default();
			registry.add(named_entry(case.seed.0, case.seed.1, case.seed.2)).ok();

			let added = case.add.map(|(a, t, h)| named_entry(a, t, h)).into_iter().collect();
			let result = registry.apply_address_update(case.caller_hive, added, case.remove);
			assert_eq!(result.is_ok(), case.expect_ok);

			let found = registry.entries_for_type(b"calc").ok().unwrap_or_default();
			assert_eq!(found.len(), case.expected_addrs.len());
			for (entry, addr) in found.iter().zip(case.expected_addrs.iter()) {
				assert_eq!(entry.route_key().as_ref(), *addr);
			}
		}
	}
}
