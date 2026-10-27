//! Servlet route registry with pheromone scores and trial-based abandonment.
//!
//! - Pheromone rises on successful work and decays on a timer.
//! - Each failure raises the trial count, and the registry abandons an entry at the limit.
//! - Local hive routes and peer-learned routes share the same score tables.

mod config;
mod entry;
mod index;
mod select;

#[cfg(test)]
mod tests;

use core::num::NonZeroUsize;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::colony::cluster::PeerAddress;
use crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
use crate::utils::time::{Clock, MonotonicInstant, UnixMillis};

use entry::Owner;
pub(crate) use entry::RoutePlane;

pub(super) use super::error::ClusterError;
pub(super) use super::SharedId;
pub(crate) use config::HiveSlate;
pub use config::{
	PeerCaps, PheromoneConfig, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS,
	DEFAULT_EVAPORATION_RATE_BPS, DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};
pub use entry::{DialTarget, PeerRoute, PeerRouteInfo, RelayRoute, RouteKind, ServletEntry};
pub use select::Weakened;

/// One route as the registry holds it: the entry and its install instant.
///
/// The install instant belongs to the placement, so an entry has one exactly
/// while the map holds it. A replacement is a fresh placement and ages from
/// it.
struct Installed {
	entry: Arc<ServletEntry>,
	at: MonotonicInstant,
}

/// One owner's claim on one route key, for the removal arm.
///
/// The owner carries its plane and the key is plain bytes, so the named
/// fields state the question in one direction: does this owner hold this
/// key (CWE-639).
struct RouteClaim<'a> {
	/// The identity that must hold the route.
	owner: Owner<'a>,
	/// The route key the owner claims.
	key: &'a [u8],
}

/// The bucket one slate replaces and the identity every route in it must
/// belong to.
///
/// A slate swap removes what the bucket held, so the sweep asks about
/// ownership too. A bucket where another owner's routes landed is not this
/// owner's to clear (CWE-639).
#[derive(Clone, Copy)]
struct Bucket<'a> {
	/// The hive-index key the slate reconciles under.
	id: &'a [u8],
	/// The identity that owns every route in the bucket.
	owner: Owner<'a>,
}

/// Servlet entries, the two reverse indexes derived from them, and the
/// advertisement order ledger.
///
/// A route key appears in `entries` and in exactly the index rows its entry
/// declares. One lock covers them all, so a slate swap is atomic and a reader
/// sees index rows that name only entries the map holds (CWE-362).
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
	/// It is the one decider for route ownership. It admits `entry` when its
	/// key is free or its owner holds it, and its endpoint is free or that
	/// owner alone dials it (CWE-639). Peers may share an endpoint, because a
	/// relay trail dials the relay's own gateway.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- a local route's key or socket belongs to another owner.
	/// - [`ClusterError::PeerSlateConflict`] -- a peer route's key or socket belongs to another owner.
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

	/// Stores `entry` at its key, in place of any route its owner holds there.
	///
	/// A replaced peer route keeps its pheromone and trial state, so a
	/// re-advertisement keeps the score a route earned.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds a local route's key or socket.
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

	/// Drops the index rows of whatever sits at `address`.
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
	/// The swap admits every entry and checks every route it would remove
	/// against `bucket.owner` before any map moves, so a refusal leaves the
	/// bucket unchanged. New entries land before departed ones leave, so the
	/// bucket stays populated.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds a key or
	///   socket a local slate claims, or a route under a hive's bucket.
	/// - [`ClusterError::PeerSlateConflict`] -- another owner holds a key or
	///   socket a peer slate claims, or a route under a peer's bucket.
	fn reconcile(
		&mut self,
		bucket: Bucket<'_>,
		slate: impl IntoIterator<Item = ServletEntry>,
		now: MonotonicInstant,
	) -> Result<SlateChange, ClusterError> {
		let slate: Vec<ServletEntry> = slate.into_iter().collect();
		for entry in &slate {
			self.admits(entry)?;
		}

		// The sweep below removes what the bucket held, so every route in
		// it must be this owner's to remove.
		let held = self.addresses_in_bucket(bucket.id);
		for address in held {
			self.held_by(RouteClaim { owner: bucket.owner, key: address.as_ref() })?;
		}

		let mut change = SlateChange { held: held.len(), installed: 0, withdrawn: 0 };
		let mut fresh: Vec<SharedId> = Vec::with_capacity(slate.len());
		for entry in slate {
			let key = Arc::clone(entry.route_key());
			let is_new = self.get(key.as_ref()).is_none();

			change.installed = change.installed.saturating_add(usize::from(is_new));

			fresh.push(key);
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

		change.withdrawn = stale.len();

		Ok(change)
	}

	/// Removes every route in `bucket` that `bucket.owner` holds.
	///
	/// An owner that retires takes only its own routes with it, so a route
	/// another owner landed under the same bucket bytes stays.
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

	/// The route keys that serve `servlet_type`, borrowed from the index.
	pub(super) fn addresses_for_type(&self, servlet_type: impl AsRef<[u8]>) -> &[SharedId] {
		let servlet_type = servlet_type.as_ref();
		self.by_type.get(servlet_type).map_or(&[], Vec::as_slice)
	}

	/// The route keys in `bucket`, borrowed from the index.
	pub(super) fn addresses_in_bucket(&self, bucket: impl AsRef<[u8]>) -> &[SharedId] {
		let bucket = bucket.as_ref();
		self.by_bucket.get(bucket).map_or(&[], Vec::as_slice)
	}

	/// Whether a slate of `new_slate_len` routes for `bucket` would pass one
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
			kind_total = kind_total.saturating_add(1);

			let entry_bucket = entry.bucket().as_ref();
			identities.insert(entry_bucket);
			if entry_bucket == bucket {
				prior_for_bucket = prior_for_bucket.saturating_add(1);
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
	/// 1. It refuses a slate older than the bucket's last applied order.
	/// 2. It refuses a slate that would pass the kind's caps.
	/// 3. [`Self::reconcile`] asks the one decider about every key, socket, and swept route.
	/// 4. An emptied direct slate also withdraws, and counts, the relay trails learned from it.
	/// 5. The ledger records the order the slate applied at.
	///
	/// Every step runs under that guard, so concurrent advertisements for one
	/// bucket apply in one order, and the ledger names the installed slate
	/// (CWE-294, CWE-367).
	///
	/// # Errors
	///
	/// - [`ClusterError::StalePeerAd`] -- the slate is older than the bucket's last applied order.
	/// - [`ClusterError::PeerCapExceeded`] -- the slate would pass one of the kind's caps.
	/// - [`ClusterError::PeerSlateConflict`] -- another owner holds a key, a socket, or a swept route.
	fn admit_peer_ad(
		&mut self,
		bucket: Bucket<'_>,
		slate: impl IntoIterator<Item = ServletEntry>,
		caps: KindCaps,
		order: UnixMillis,
		tombstone: Tombstone,
		now: MonotonicInstant,
	) -> Result<SlateChange, ClusterError> {
		let slate: Vec<ServletEntry> = slate.into_iter().collect();
		if self.ad_orders.get(bucket.id).is_some_and(|&applied| order < applied) {
			return Err(ClusterError::StalePeerAd);
		}
		if self.slate_exceeds_caps(bucket.id, slate.len(), caps) {
			return Err(ClusterError::PeerCapExceeded);
		}

		let clearing = slate.is_empty();
		let mut change = self.reconcile(bucket, slate, now)?;

		// A withdrawn direct slate withdraws the relay fallbacks learned
		// from it, in the same step that withdraws the direct routes.
		if clearing && caps.kind == RouteKind::Peer {
			let trails = self.remove_relay_trails_for_origin(bucket.id);
			change.withdrawn = change.withdrawn.saturating_add(trails);
		}

		self.record_ad_order(Arc::from(bucket.id), order, tombstone);

		Ok(change)
	}

	/// Drops the relay trails installed more than `max_age` before `now`.
	///
	/// The filter and the removal run under the caller's guard, so the filter
	/// reads the age a reconcile refreshed.
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

	/// Drops every peer route that dials `gateway`, and returns how many it
	/// dropped.
	///
	/// - A relay trail through the socket dials it, so it leaves with the direct routes.
	/// - A fallback trail to the same origin through another relay dials that relay, so it stays.
	pub(super) fn remove_peer_routes_dialing(&mut self, gateway: PeerAddress) -> usize {
		let dials_gateway = |entry: &&Arc<ServletEntry>| entry.is_peer_route_to(gateway);
		let dialing: Vec<Arc<ServletEntry>> = self.values().filter(dials_gateway).map(Arc::clone).collect();
		for entry in &dialing {
			self.remove(entry.route_key().as_ref());
		}

		dialing.len()
	}

	/// Records the order this bucket last applied at.
	///
	/// A row lives as long as its bucket holds entries. Once the bucket
	/// empties, the row survives one freshness window as a tombstone, so a
	/// replayed older advertisement cannot undo the withdrawal (CWE-294).
	fn record_ad_order(&mut self, bucket: SharedId, order: UnixMillis, tombstone: Tombstone) {
		self.ad_orders.insert(bucket, order);

		// The closure borrows `by_bucket` apart from `ad_orders`, so the ledger
		// prunes against the live index and reads its keys in place.
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
	/// It checks every entry before any map moves, so a refusal leaves the
	/// registry unchanged and needs no undo. The slate names its hive, so every
	/// added route is that hive's, and only the registry's ownership check
	/// remains.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds an added or
	///   removed address, or dials the endpoint an added address names.
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

		// Removals run first, so a locator the update both removes and adds,
		// as a restart that reuses its listen address does, stays routed.
		for address in removed {
			self.remove(address);
		}
		for entry in added {
			self.place(entry, now);
		}

		Ok(())
	}
}

/// The peer-routed kind a slate installs and the two storage caps it spends.
///
/// The fields are named so the identity cap and the route cap each land in
/// their own slot (CWE-770).
#[derive(Clone, Copy, Debug)]
struct KindCaps {
	/// The kind whose routes the caps count.
	kind: RouteKind,
	/// The most distinct buckets this kind may hold.
	max_identities: usize,
	/// The most routes this kind may hold across every bucket.
	max_routes: usize,
}

/// When the registry may drop an emptied bucket's order row: once `window`
/// has passed since it applied, as of `now`.
///
/// They travel together, so an admission pairs the window with an instant
/// from the clock that measures it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Tombstone {
	/// How long the row survives after its bucket empties.
	pub(super) window: Duration,
	/// The instant the admission happens at.
	pub(super) now: UnixMillis,
}

/// What one slate swap changed in its bucket.
///
/// A refresh of a route the bucket held is neither an install nor a
/// withdrawal, so each count names a change of routes alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SlateChange {
	/// The count of routes the bucket held before the swap.
	held: usize,
	/// The count of routes the swap placed at a key that held no route.
	installed: usize,
	/// The count of routes the swap removed, with the relay trails that an
	/// emptied direct slate withdraws.
	withdrawn: usize,
}

impl SlateChange {
	/// The count of new routes, or [`None`] when the swap installed none.
	#[must_use]
	pub(crate) fn installed(&self) -> Option<NonZeroUsize> {
		NonZeroUsize::new(self.installed)
	}

	/// The count of routes withdrawn, or [`None`] when the swap withdrew
	/// none.
	#[must_use]
	pub(crate) fn withdrawn(&self) -> Option<NonZeroUsize> {
		NonZeroUsize::new(self.withdrawn)
	}

	/// Whether the swap placed routes in a bucket that held none, so the
	/// bucket's trail is new.
	#[must_use]
	pub(crate) fn opens_bucket(&self) -> bool {
		self.held == 0 && self.installed > 0
	}
}

/// A registry of servlet entries with pheromone-based routing.
///
/// It tracks servlet instances across hives and peer gateways.
pub struct ServletRegistry {
	/// The entries, the two reverse indexes, and the order ledger.
	pub(super) routes: RwLock<Routes>,
	/// How long a dead bucket's order tombstone survives.
	pub(super) ad_tombstone_window: Duration,
	/// The clock that measures tombstones, route installs, and relay-trail age.
	pub(super) clock: Arc<dyn Clock>,
	/// The pheromone score and lifecycle configuration.
	pub(super) config: PheromoneConfig,
}

impl ServletRegistry {
	/// Creates a registry that scores on `config` and measures tombstones,
	/// route installs, and relay-trail age on `clock`.
	///
	/// The gateway passes its own clock, so the registry ages its rows on the
	/// clock the gateway reads.
	pub fn new(config: PheromoneConfig, clock: Arc<dyn Clock>) -> Self {
		Self {
			routes: RwLock::new(Routes::default()),
			ad_tombstone_window: Duration::from_millis(DEFAULT_COMMAND_FRESHNESS_WINDOW_MS),
			clock,
			config,
		}
	}

	/// The tombstone bound for an advertisement admitted at this clock reading.
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

#[cfg(test)]
impl ServletRegistry {
	/// Poisons the route lock, as a thread that panicked under the guard
	/// leaves it.
	pub(crate) fn poison_routes(&self) {
		let poisoner = || {
			let _held = self.routes.write();
			panic!("a thread panicked under the route lock");
		};

		// The panic is the point, so the joined result carries nothing to read.
		let _panicked = std::thread::scope(|scope| scope.spawn(poisoner).join());
	}
}
