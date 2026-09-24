//! Servlet route registry with pheromone scoring and trial-based abandonment.
//!
//! - Pheromone rises on successful work and decays on a timer.
//! - Trial count rises on failure, and entries abandon past a limit.
//! - Local hive routes and peer-learned routes share the same scoring tables.

mod config;
mod entry;
mod index;
mod select;

#[cfg(test)]
mod tests;

use crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
use crate::utils::time::{Clock, MonotonicInstant, UnixMillis};
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

pub(super) use super::error::ClusterError;
pub(super) use super::SharedId;

pub(crate) use config::HiveSlate;
pub use config::{
	PeerCaps, PheromoneConfig, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS,
	DEFAULT_EVAPORATION_RATE_BPS, DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};
pub use entry::{DialTarget, LocalRoute, PeerRoute, PeerRouteInfo, RelayRoute, RouteKind, ServletEntry};

use entry::Owner;

/// One route as the registry holds it: the entry and when it was placed.
///
/// The install instant belongs to the placement, not to the entry, so an
/// entry outside the map has none and an entry inside always has one. A
/// replacement is a fresh placement and ages from it.
struct Installed {
	entry: Arc<ServletEntry>,
	at: MonotonicInstant,
}

/// One owner's claim on one route key, for the removal arm.
///
/// Both fields are byte slices, so a positional pair could be transposed
/// and the decider would look an owner up as a key, find nothing, and
/// admit the removal. Named fields make the question unmistakable
/// (CWE-639).
struct RouteClaim<'a> {
	/// The identity that must hold the route.
	owner: Owner<'a>,
	/// The route key the owner claims.
	key: &'a [u8],
}

/// The bucket one slate replaces and the identity every route in it must
/// belong to.
///
/// A slate swap removes what the bucket held before, so the sweep is an
/// ownership question too: a bucket whose bytes another owner's routes
/// landed under is not this owner's to clear (CWE-639).
#[derive(Clone, Copy)]
struct Bucket<'a> {
	/// The hive-index key the slate reconciles under.
	id: &'a [u8],
	/// The identity that owns every route in the bucket.
	owner: Owner<'a>,
}

/// Servlet entries and the two reverse indexes derived from them.
///
/// A route key appears in `entries` and in exactly the index rows its
/// entry declares. One lock covers all three, so a slate swap is atomic
/// and a reader sees index rows naming entries the map still holds
/// (CWE-362).
#[derive(Default)]
pub(super) struct Routes {
	entries: HashMap<SharedId, Installed>,
	by_type: HashMap<SharedId, Vec<SharedId>>,
	by_bucket: HashMap<SharedId, Vec<SharedId>>,
	ad_orders: HashMap<SharedId, UnixMillis>,
}

impl Routes {
	/// Whether `entry` may be placed at its key.
	///
	/// This is the one decider for route ownership. `entry` is admitted when
	/// its key is free or already held by its owner, and when its endpoint is
	/// free or dialed by that owner alone (CWE-639). Peers may share an
	/// endpoint, because a relay trail dials the relay's own gateway.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- a local route's key or socket
	///   belongs to another owner.
	/// - [`ClusterError::PeerSlateConflict`] -- a peer route's key or socket
	///   belongs to another owner.
	fn admits(&self, entry: &ServletEntry) -> Result<(), ClusterError> {
		let owner = entry.owner();
		let key_held_by_other = self.owner_of(entry.route_key()).is_some_and(|held| !held.same(owner));
		if key_held_by_other {
			return Err(Self::refusal(owner));
		}

		let dial = entry.dial_target();
		let dialed_by_other = self.values().any(|held| {
			let both_peers = held.owner().is_peer() && owner.is_peer();
			!both_peers && !held.owner().same(owner) && held.dial_target().same_endpoint(dial)
		});
		if dialed_by_other {
			return Err(Self::refusal(owner));
		}

		Ok(())
	}

	/// Whether `claim.owner` holds the route at `claim.key`.
	///
	/// This is the removal side of [`Self::admits`]: the route must exist and
	/// must belong to the claimant.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotFound`] -- nothing is routed at the key.
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds a route a hive claims.
	/// - [`ClusterError::PeerSlateConflict`] -- another owner holds a route a peer claims.
	fn held_by(&self, claim: RouteClaim<'_>) -> Result<(), ClusterError> {
		let held = self.owner_of(claim.key).ok_or(ClusterError::ServletNotFound)?;
		if held.same(claim.owner) {
			Ok(())
		} else {
			Err(Self::refusal(claim.owner))
		}
	}

	/// The owner of whatever is routed at `key`.
	fn owner_of(&self, key: impl AsRef<[u8]>) -> Option<Owner<'_>> {
		let key = key.as_ref();
		self.entries.get(key).map(|installed| installed.entry.owner())
	}

	/// The refusal a claim by `owner` answers with, named for the plane the
	/// claim came from.
	fn refusal(owner: Owner<'_>) -> ClusterError {
		if owner.is_peer() {
			ClusterError::PeerSlateConflict
		} else {
			ClusterError::ServletNotOwned
		}
	}

	/// Stores `entry`, replacing a route its owner already holds at its key.
	///
	/// A replaced peer route keeps its pheromone and trial state, so a
	/// re-advertisement leaves a route's earned standing in place.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds the key or socket.
	/// - [`ClusterError::PeerSlateConflict`] -- another owner holds a peer route's key or socket.
	#[cfg(test)]
	pub(super) fn insert(&mut self, entry: ServletEntry, now: MonotonicInstant) -> Result<(), ClusterError> {
		self.admits(&entry)?;
		self.place(entry, now);
		Ok(())
	}

	/// Stores an entry [`Self::admits`] already admitted, installed at `now`
	/// on the registry's clock.
	fn place(&mut self, mut entry: ServletEntry, now: MonotonicInstant) {
		let address = Arc::clone(entry.route_key());
		if let Some(previous) = self.entries.get(address.as_ref()) {
			entry.preserve_peer_trail_from(&previous.entry);
		}

		self.unindex(address.as_ref());

		let servlet_type = Arc::clone(entry.servlet_type());
		let bucket = Arc::clone(entry.bucket());
		self.by_type.entry(servlet_type).or_default().push(Arc::clone(&address));
		self.by_bucket.entry(bucket).or_default().push(Arc::clone(&address));
		self.entries.insert(address, Installed { entry: Arc::new(entry), at: now });
	}

	pub(super) fn remove(&mut self, address: impl AsRef<[u8]>) -> Option<Arc<ServletEntry>> {
		let address = address.as_ref();
		let installed = self.entries.remove(address)?;
		self.drop_index_rows(&installed.entry, address);
		Some(installed.entry)
	}

	/// Drops the index rows of whatever currently sits at `address`.
	fn unindex(&mut self, address: impl AsRef<[u8]>) {
		let address = address.as_ref();
		let Some(previous) = self.entries.get(address).map(|installed| Arc::clone(&installed.entry)) else {
			return;
		};

		self.drop_index_rows(&previous, address);
	}

	fn drop_index_rows(&mut self, entry: &ServletEntry, address: impl AsRef<[u8]>) {
		let address = address.as_ref();
		Self::retire(&mut self.by_type, entry.servlet_type(), address);
		Self::retire(&mut self.by_bucket, entry.bucket(), address);
	}

	fn retire(index: &mut HashMap<SharedId, Vec<SharedId>>, key: &SharedId, address: impl AsRef<[u8]>) {
		let address = address.as_ref();
		let Some(addresses) = index.get_mut(key) else {
			return;
		};

		addresses.retain(|candidate| candidate.as_ref() != address);
		if addresses.is_empty() {
			index.remove(key);
		}
	}

	/// Replaces `bucket`'s slate in one step.
	///
	/// Every entry is admitted and every route the swap would remove is
	/// checked against `bucket.owner` before any map moves, so a refusal
	/// leaves the bucket as it was. The new entries land before the
	/// departed ones leave, so no reader observes the bucket empty mid-swap.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds a key or
	///   socket a local slate claims, or a route under the bucket.
	/// - [`ClusterError::PeerSlateConflict`] -- another owner holds a key or
	///   socket a peer slate claims.
	fn reconcile(
		&mut self,
		bucket: Bucket<'_>,
		slate: impl IntoIterator<Item = ServletEntry>,
		now: MonotonicInstant,
	) -> Result<(), ClusterError> {
		let slate: Vec<ServletEntry> = slate.into_iter().collect();
		for entry in &slate {
			self.admits(entry)?;
		}

		// The sweep below removes what the bucket held, so every route in
		// it must be this owner's to remove.
		for address in self.addresses_in_bucket(bucket.id) {
			self.held_by(RouteClaim { owner: bucket.owner, key: address.as_ref() })?;
		}

		let mut fresh: Vec<SharedId> = Vec::with_capacity(slate.len());
		for entry in slate {
			fresh.push(Arc::clone(entry.route_key()));
			self.place(entry, now);
		}

		let stale: Vec<SharedId> = self
			.addresses_in_bucket(bucket.id)
			.iter()
			.filter(|address| !fresh.iter().any(|kept| kept.as_ref() == address.as_ref()))
			.map(Arc::clone)
			.collect();

		for address in &stale {
			self.remove(address.as_ref());
		}

		Ok(())
	}

	/// Removes every route in `bucket` that `bucket.owner` holds.
	///
	/// A retiring owner takes its own routes with it and nothing else, so a
	/// route another owner landed under the same bucket bytes stays.
	fn remove_owned(&mut self, bucket: Bucket<'_>) -> Vec<Arc<ServletEntry>> {
		let owned: Vec<SharedId> = self
			.addresses_in_bucket(bucket.id)
			.iter()
			.filter(|address| self.owner_of(address.as_ref()).is_some_and(|held| held.same(bucket.owner)))
			.map(Arc::clone)
			.collect();

		owned.iter().filter_map(|address| self.remove(address.as_ref())).collect()
	}

	pub(super) fn get(&self, address: impl AsRef<[u8]>) -> Option<&Arc<ServletEntry>> {
		let address = address.as_ref();
		self.entries.get(address).map(|installed| &installed.entry)
	}

	pub(super) fn values(&self) -> impl Iterator<Item = &Arc<ServletEntry>> {
		self.entries.values().map(|installed| &installed.entry)
	}

	/// Route keys serving `servlet_type`, borrowed from the index.
	pub(super) fn addresses_for_type(&self, servlet_type: impl AsRef<[u8]>) -> &[SharedId] {
		let servlet_type = servlet_type.as_ref();
		self.by_type.get(servlet_type).map_or(&[], Vec::as_slice)
	}

	/// Route keys in `bucket`, borrowed from the index.
	pub(super) fn addresses_in_bucket(&self, bucket: impl AsRef<[u8]>) -> &[SharedId] {
		let bucket = bucket.as_ref();
		self.by_bucket.get(bucket).map_or(&[], Vec::as_slice)
	}

	/// Whether admitting `new_slate_len` routes for `bucket` would pass one
	/// of the caps `caps` sets for its kind.
	fn slate_exceeds_caps(&self, bucket: impl AsRef<[u8]>, new_slate_len: usize, caps: KindCaps) -> bool {
		let KindCaps { kind: count_kind, max_identities, max_routes } = caps;
		let bucket = bucket.as_ref();
		if new_slate_len == 0 {
			return false;
		}

		let mut kind_total = 0usize;
		let mut prior_for_bucket = 0usize;
		let mut identities = HashSet::new();
		for entry in self.values().filter(|entry| entry.route_kind() == count_kind) {
			kind_total += 1;

			let entry_bucket = entry.bucket().as_ref();
			identities.insert(entry_bucket);
			if entry_bucket == bucket {
				prior_for_bucket += 1;
			}
		}

		let routes_after = kind_total.saturating_sub(prior_for_bucket).saturating_add(new_slate_len);
		if routes_after > max_routes {
			return true;
		}

		let identity_is_new = !identities.contains(bucket);
		identities.len().saturating_add(usize::from(identity_is_new)) > max_identities
	}

	/// Admits one advertisement under the guard the caller already holds.
	///
	/// The checks and writes run in this order:
	///
	/// - A slate older than the bucket's last applied order is refused.
	/// - A slate that would pass the kind's caps is refused.
	/// - [`Self::reconcile`] asks the one decider about every key, socket, and swept route.
	/// - An emptied direct slate also withdraws the relay trails learned from it.
	/// - The ledger records the order the slate applied at.
	///
	/// Every step reads and writes under that one guard, so concurrent
	/// advertisements for one bucket apply in a single order and the ledger
	/// always names the slate installed (CWE-294, CWE-367).
	fn admit_peer_ad(
		&mut self,
		bucket: Bucket<'_>,
		slate: impl IntoIterator<Item = ServletEntry>,
		caps: KindCaps,
		order: UnixMillis,
		tombstone: Tombstone,
		now: MonotonicInstant,
	) -> Result<(), ClusterError> {
		let slate: Vec<ServletEntry> = slate.into_iter().collect();
		if self.ad_orders.get(bucket.id).is_some_and(|&applied| order < applied) {
			return Err(ClusterError::StalePeerAd);
		}
		if self.slate_exceeds_caps(bucket.id, slate.len(), caps) {
			return Err(ClusterError::PeerCapExceeded);
		}

		let clearing = slate.is_empty();

		self.reconcile(bucket, slate, now)?;

		// A withdrawn direct slate withdraws the relay fallbacks learned
		// from it, in the same step that withdraws the direct routes.
		if clearing && caps.kind == RouteKind::Peer {
			self.remove_relay_trails_for_origin(bucket.id);
		}

		self.record_ad_order(Arc::from(bucket.id), order, tombstone);

		Ok(())
	}

	/// Drops the relay trails installed more than `max_age` before `now`.
	///
	/// The filter and the removal run under the one guard the caller holds,
	/// so a trail that a reconcile refreshes is judged on its refreshed age.
	pub(super) fn prune_stale_relay_trails(&mut self, now: MonotonicInstant, max_age: Duration) -> usize {
		let stale: Vec<SharedId> = self
			.entries
			.values()
			.filter(|installed| installed.entry.route_kind() == RouteKind::PeerRelay)
			.filter(|installed| now.saturating_duration_since(installed.at) > max_age)
			.map(|installed| Arc::clone(installed.entry.route_key()))
			.collect();

		for route_key in &stale {
			self.remove(route_key.as_ref());
		}

		stale.len()
	}

	/// Drops every relay trail learned for one origin identity.
	pub(super) fn remove_relay_trails_for_origin(&mut self, origin_id: impl AsRef<[u8]>) -> usize {
		let origin_id = origin_id.as_ref();
		let stale: Vec<SharedId> = self
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::PeerRelay)
			.filter(|entry| entry.owner_id().as_ref() == origin_id)
			.map(|entry| Arc::clone(entry.route_key()))
			.collect();

		for route_key in &stale {
			self.remove(route_key.as_ref());
		}

		stale.len()
	}

	/// Records the order this bucket last applied at.
	///
	/// A row lives as long as its bucket holds entries. Once the bucket
	/// empties, the row survives one freshness window as a tombstone, so a
	/// replayed older advertisement still loses to the withdrawal it would
	/// otherwise undo (CWE-294).
	fn record_ad_order(&mut self, bucket: SharedId, order: UnixMillis, tombstone: Tombstone) {
		self.ad_orders.insert(bucket, order);

		// The closure borrows `by_bucket` apart from `ad_orders`, so the ledger
		// prunes against the live index without copying its keys.
		let Tombstone { window, now } = tombstone;
		let by_bucket = &self.by_bucket;
		self.ad_orders
			.retain(|bucket, applied| by_bucket.contains_key(bucket) || now.saturating_since(*applied) <= window);
	}

	/// Returns the number of rows the order ledger holds.
	#[cfg(test)]
	pub(super) fn ad_order_rows(&self) -> usize {
		self.ad_orders.len()
	}

	/// Applies one hive's additions and removals in a single step.
	///
	/// Every entry is checked before any map moves, so a refusal leaves the
	/// registry as it was and the caller needs no compensating undo. The
	/// slate names its hive, so every added route is that hive's by
	/// construction and only the registry's own ownership question remains.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- an address belongs to another owner.
	/// - [`ClusterError::ServletNotFound`] -- a removal names an absent address.
	pub(super) fn apply_address_update(
		&mut self,
		added: HiveSlate,
		removed: &[&[u8]],
		now: MonotonicInstant,
	) -> Result<(), ClusterError> {
		let (hive_id, added) = added.into_parts();
		let owner = Owner::hive(hive_id.as_ref());
		for entry in &added {
			self.admits(entry)?;
		}
		for address in removed {
			self.held_by(RouteClaim { owner, key: address })?;
		}

		for entry in added {
			self.place(entry, now);
		}
		for address in removed {
			self.remove(address);
		}

		Ok(())
	}
}

/// The peer-routed kind a slate installs and the two storage caps it spends.
///
/// The fields are named so a caller cannot hand the identity cap to the
/// route slot or the reverse (CWE-770).
#[derive(Clone, Copy, Debug)]
struct KindCaps {
	/// The kind whose routes the caps count.
	kind: RouteKind,
	/// The most distinct buckets this kind may hold.
	max_identities: usize,
	/// The most routes this kind may hold across every bucket.
	max_routes: usize,
}

/// When an emptied bucket's order row may be dropped: once `window` has
/// passed since it applied, as of `now`.
///
/// The two travel together so an admission cannot pair a window with an
/// instant from another clock.
#[derive(Clone, Copy, Debug)]
pub(super) struct Tombstone {
	/// How long the row survives after its bucket empties.
	pub(super) window: Duration,
	/// The instant the admission happens at.
	pub(super) now: UnixMillis,
}

/// Registry of servlet entries with pheromone-based routing.
///
/// The registry tracks servlet instances across hives and peer gateways.
/// Reinforcement and evaporation steer selection, and trial limits abandon
/// dead routes.
pub struct ServletRegistry {
	/// Entries and the two reverse indexes derived from them.
	pub(super) routes: RwLock<Routes>,
	/// How long a dead bucket's order tombstone survives.
	pub(super) ad_tombstone_window: Duration,
	/// The clock that tombstones, route installs, and relay-trail age are
	/// measured on.
	pub(super) clock: Arc<dyn Clock>,
	/// Scoring and lifecycle configuration.
	pub(super) config: PheromoneConfig,
}

impl ServletRegistry {
	/// Creates a registry that scores on `config` and measures tombstones,
	/// route installs, and relay-trail age on `clock`.
	///
	/// The clock is the gateway's own, so a registry cannot age its rows on
	/// a clock the gateway beside it does not read.
	pub fn new(config: PheromoneConfig, clock: Arc<dyn Clock>) -> Self {
		Self {
			routes: RwLock::new(Routes::default()),
			ad_tombstone_window: Duration::from_millis(DEFAULT_COMMAND_FRESHNESS_WINDOW_MS),
			clock,
			config,
		}
	}

	/// The tombstone bound for an advertisement admitted now.
	pub(super) fn tombstone(&self) -> Tombstone {
		Tombstone { window: self.ad_tombstone_window, now: self.clock.unix() }
	}

	/// Sets the advertisement tombstone window, normally the gateway's
	/// signed-control freshness window, so the two replay bounds stay
	/// aligned.
	#[must_use]
	pub fn with_ad_tombstone_window(mut self, window: Duration) -> Self {
		self.ad_tombstone_window = window;
		self
	}
}
