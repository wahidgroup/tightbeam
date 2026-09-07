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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::colony::common::current_timestamp_ms;
use crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;

pub(super) use super::error::ClusterError;
pub(super) use super::SharedId;

pub use config::{
	PeerCaps, PheromoneConfig, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS,
	DEFAULT_EVAPORATION_RATE_BPS, DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};
pub use entry::{PeerRouteInfo, RouteKind, ServletEntry};

/// Servlet entries and the two reverse indexes derived from them.
///
/// A route key appears in `entries` and in exactly the index rows its
/// entry declares. One lock covers all three, so a slate swap is atomic
/// and a reader sees index rows naming entries the map still holds
/// (CWE-362).
#[derive(Default)]
pub(super) struct Routes {
	entries: HashMap<SharedId, Arc<ServletEntry>>,
	by_type: HashMap<SharedId, Vec<SharedId>>,
	by_bucket: HashMap<SharedId, Vec<SharedId>>,
	ad_orders: HashMap<SharedId, u64>,
}

impl Routes {
	/// Stores `entry`, replacing any route already at its key.
	///
	/// A replaced peer route keeps its pheromone and trial state, so a
	/// re-advertisement leaves a route's earned standing in place.
	pub(super) fn insert(&mut self, mut entry: ServletEntry) {
		let address = Arc::clone(entry.route_key());
		if let Some(previous) = self.entries.get(address.as_ref()) {
			entry.preserve_peer_trail_from(previous);
		}

		self.unindex(address.as_ref());

		let servlet_type = Arc::clone(entry.servlet_type());
		let bucket = Arc::clone(entry.bucket());
		self.by_type.entry(servlet_type).or_default().push(Arc::clone(&address));
		self.by_bucket.entry(bucket).or_default().push(Arc::clone(&address));
		self.entries.insert(address, Arc::new(entry));
	}

	pub(super) fn remove(&mut self, address: &[u8]) -> Option<Arc<ServletEntry>> {
		let entry = self.entries.remove(address)?;
		self.drop_index_rows(&entry, address);
		Some(entry)
	}

	/// Drops the index rows of whatever currently sits at `address`.
	fn unindex(&mut self, address: &[u8]) {
		let Some(previous) = self.entries.get(address).map(Arc::clone) else {
			return;
		};

		self.drop_index_rows(&previous, address);
	}

	fn drop_index_rows(&mut self, entry: &ServletEntry, address: &[u8]) {
		Self::retire(&mut self.by_type, entry.servlet_type(), address);
		Self::retire(&mut self.by_bucket, entry.bucket(), address);
	}

	fn retire(index: &mut HashMap<SharedId, Vec<SharedId>>, key: &SharedId, address: &[u8]) {
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
	/// The new entries land before the departed ones leave, so no reader
	/// observes the bucket empty mid-swap and no rollback is required.
	pub(super) fn reconcile(&mut self, bucket: &[u8], slate: Vec<ServletEntry>) {
		let mut fresh: Vec<SharedId> = Vec::with_capacity(slate.len());
		for entry in slate {
			fresh.push(Arc::clone(entry.route_key()));
			self.insert(entry);
		}

		let stale: Vec<SharedId> = self
			.by_bucket
			.get(bucket)
			.map(|addresses| {
				addresses
					.iter()
					.filter(|address| !fresh.iter().any(|kept| kept.as_ref() == address.as_ref()))
					.map(Arc::clone)
					.collect()
			})
			.unwrap_or_default();

		for address in &stale {
			self.remove(address.as_ref());
		}
	}

	pub(super) fn get(&self, address: &[u8]) -> Option<&Arc<ServletEntry>> {
		self.entries.get(address)
	}

	pub(super) fn values(&self) -> impl Iterator<Item = &Arc<ServletEntry>> {
		self.entries.values()
	}

	/// Route keys serving `servlet_type`, borrowed from the index.
	pub(super) fn addresses_for_type(&self, servlet_type: &[u8]) -> &[SharedId] {
		self.by_type.get(servlet_type).map_or(&[], Vec::as_slice)
	}

	/// Route keys in `bucket`, borrowed from the index.
	pub(super) fn addresses_in_bucket(&self, bucket: &[u8]) -> &[SharedId] {
		self.by_bucket.get(bucket).map_or(&[], Vec::as_slice)
	}

	/// Whether a local route already claims `hive_id` as its key or bucket.
	pub(super) fn peer_key_conflicts_local(&self, hive_id: &[u8]) -> bool {
		if self.get(hive_id).is_some_and(|entry| entry.route_kind() == RouteKind::Local) {
			return true;
		}

		self.addresses_in_bucket(hive_id).iter().any(|address| {
			self.get(address.as_ref())
				.is_some_and(|entry| entry.route_kind() == RouteKind::Local)
		})
	}

	/// Whether a local route already dials `dial_addr`.
	pub(super) fn peer_dial_conflicts_local(&self, dial_addr: &[u8]) -> bool {
		self.values()
			.any(|entry| entry.route_kind() == RouteKind::Local && entry.route_key().as_ref() == dial_addr)
	}

	/// Whether admitting `new_slate_len` routes for `bucket` would pass a cap.
	pub(super) fn slate_exceeds_caps(
		&self,
		bucket: &[u8],
		new_slate_len: usize,
		count_kind: RouteKind,
		max_identities: usize,
		max_routes: usize,
	) -> bool {
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

	/// Admits one advertisement: freshness, conflicts, caps, the swap, and
	/// the order it applied at.
	///
	/// Every step reads and writes under the guard the caller already
	/// holds, so concurrent advertisements for one bucket apply in a
	/// single order and the ledger always names the slate installed
	/// (CWE-294, CWE-367).
	#[allow(clippy::too_many_arguments)]
	pub(super) fn admit_peer_ad(
		&mut self,
		bucket: &SharedId,
		dial_addr: Option<&[u8]>,
		slate: Vec<ServletEntry>,
		count_kind: RouteKind,
		max_identities: usize,
		max_routes: usize,
		order: u64,
		tombstone_window_ms: u64,
	) -> Result<(), ClusterError> {
		if self.ad_orders.get(bucket.as_ref()).is_some_and(|&applied| order < applied) {
			return Err(ClusterError::StalePeerAd);
		}
		if self.peer_key_conflicts_local(bucket.as_ref()) {
			return Err(ClusterError::PeerSlateConflict);
		}
		if dial_addr.is_some_and(|addr| self.peer_dial_conflicts_local(addr)) {
			return Err(ClusterError::PeerSlateConflict);
		}
		if self.slate_exceeds_caps(bucket.as_ref(), slate.len(), count_kind, max_identities, max_routes) {
			return Err(ClusterError::PeerCapExceeded);
		}

		let clearing = slate.is_empty();

		self.reconcile(bucket.as_ref(), slate);

		// A withdrawn direct slate withdraws the relay fallbacks learned
		// from it, in the same step that withdraws the direct routes.
		if clearing && count_kind == RouteKind::Peer {
			self.remove_relay_trails_for_origin(bucket.as_ref());
		}

		self.record_ad_order(Arc::clone(bucket), order, tombstone_window_ms);

		Ok(())
	}

	/// Drops every relay trail learned for one origin identity.
	pub(super) fn remove_relay_trails_for_origin(&mut self, origin_id: &[u8]) -> usize {
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
	fn record_ad_order(&mut self, bucket: SharedId, order: u64, tombstone_window_ms: u64) {
		self.ad_orders.insert(bucket, order);

		// Disjoint field borrows: the ledger prunes against the live index
		// without copying its keys.
		let now = current_timestamp_ms();
		let by_bucket = &self.by_bucket;
		self.ad_orders.retain(|bucket, applied| {
			by_bucket.contains_key(bucket) || now.saturating_sub(*applied) <= tombstone_window_ms
		});
	}

	/// Rows the order ledger holds.
	#[cfg(test)]
	pub(super) fn ad_order_rows(&self) -> usize {
		self.ad_orders.len()
	}

	/// Applies one hive's additions and removals in a single step.
	///
	/// Every entry is checked before any map moves, so a refusal leaves the
	/// registry as it was and the caller needs no compensating undo.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- an address belongs to another hive.
	/// - [`ClusterError::ServletNotFound`] -- a removal names an absent address.
	pub(super) fn apply_address_update(
		&mut self,
		hive_id: &[u8],
		added: Vec<ServletEntry>,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		for entry in &added {
			if entry.owner_id().as_ref() != hive_id {
				return Err(ClusterError::ServletNotOwned);
			}
		}
		for address in removed {
			match self.get(address) {
				Some(entry) if entry.owner_id().as_ref() == hive_id => {}
				Some(_) => return Err(ClusterError::ServletNotOwned),
				None => return Err(ClusterError::ServletNotFound),
			}
		}

		for entry in added {
			self.insert(entry);
		}
		for address in removed {
			self.remove(address);
		}

		Ok(())
	}
}

/// Registry of servlet entries with pheromone-based routing.
///
/// Tracks servlet instances across hives and peer gateways.
/// Reinforcement and evaporation steer selection, and trial limits
/// abandon dead routes.
pub struct ServletRegistry {
	/// Entries and the two reverse indexes derived from them.
	pub(super) routes: RwLock<Routes>,
	/// Milliseconds a dead bucket's order tombstone survives.
	pub(super) ad_tombstone_window_ms: u64,
	/// Scoring and lifecycle configuration.
	pub(super) config: PheromoneConfig,
}

impl ServletRegistry {
	/// Creates a registry with the supplied pheromone configuration.
	pub fn new(config: PheromoneConfig) -> Self {
		Self {
			routes: RwLock::new(Routes::default()),
			ad_tombstone_window_ms: DEFAULT_COMMAND_FRESHNESS_WINDOW_MS,
			config,
		}
	}

	/// Sets the advertisement tombstone window, normally the gateway's
	/// signed-control freshness window, so the two replay bounds stay
	/// aligned.
	#[must_use]
	pub fn with_ad_tombstone_window_ms(mut self, window_ms: u64) -> Self {
		self.ad_tombstone_window_ms = window_ms;
		self
	}
}

impl Default for ServletRegistry {
	fn default() -> Self {
		Self::new(PheromoneConfig::default())
	}
}
