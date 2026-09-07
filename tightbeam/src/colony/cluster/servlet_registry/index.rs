use std::sync::Arc;

use super::{ClusterError, PeerCaps, RouteKind, ServletEntry, ServletRegistry, SharedId};
use crate::colony::cluster::peer::{AdmittedPeerAd, RelayTrail};
use crate::colony::common::current_timestamp_ms;

impl ServletRegistry {
	/// Adds a servlet entry.
	///
	/// Re-registering an address retires its index rows first. Peer route
	/// replacement preserves its pheromone and trial state.
	pub fn add(&self, entry: ServletEntry) -> Result<(), ClusterError> {
		self.routes.write()?.insert(entry);

		Ok(())
	}

	/// Adds entries for every servlet type declared by one hive.
	pub fn add_entries_from_hive(
		&self,
		hive_id: &SharedId,
		hive_address: &SharedId,
		servlet_types: &[SharedId],
	) -> Result<(), ClusterError> {
		let mut routes = self.routes.write()?;
		for servlet_type in servlet_types {
			routes.insert(ServletEntry::new(
				Arc::clone(hive_address),
				Arc::clone(servlet_type),
				Arc::clone(hive_id),
				self.config.initial_pheromone,
				self.config.abandonment_limit,
			));
		}

		Ok(())
	}

	/// Removes a servlet entry by address.
	pub fn remove(&self, address: &[u8]) -> Result<Option<Arc<ServletEntry>>, ClusterError> {
		Ok(self.routes.write()?.remove(address))
	}

	/// Replaces one hive slate atomically.
	pub fn reconcile_by_hive(&self, hive_id: &[u8], entries: Vec<ServletEntry>) -> Result<(), ClusterError> {
		self.reconcile_slate(hive_id, entries)
	}

	fn reconcile_slate(&self, hive_id: &[u8], entries: Vec<ServletEntry>) -> Result<(), ClusterError> {
		self.routes.write()?.reconcile(hive_id, entries);

		Ok(())
	}

	/// Reconciles an admitted peer slate after stale, conflict, and cap
	/// checks.
	///
	/// The registry refuses an advertisement older than the newest one
	/// applied for the origin, so a replayed ad inside the freshness
	/// window leaves the fresher slate in place (CWE-294). An
	/// empty slate clears the origin's relay trails with its direct routes:
	/// a fallback lasts as long as a claim it was learned from.
	pub fn reconcile_peer_slate(&self, ad: AdmittedPeerAd, caps: PeerCaps) -> Result<(), ClusterError> {
		let AdmittedPeerAd { peer_hive_id, dial_addr, slate, order } = ad;

		self.refuse_stale_ad(&peer_hive_id, order)?;

		let clearing = slate.is_empty();

		self.routes.write()?.admit_peer_slate(
			&peer_hive_id,
			Some(&dial_addr),
			slate,
			RouteKind::Peer,
			caps.max_gateways,
			caps.max_routes,
		)?;

		if clearing {
			self.remove_relay_trails_for_origin(&peer_hive_id)?;
		}

		self.record_ad_order(peer_hive_id, order)
	}

	/// Replaces one relay-trail slate atomically under its own bucket.
	///
	/// The bucket is `origin NUL relay`, so an origin's direct slate and its
	/// relay fallback reconcile independently.
	///
	/// Relay buckets spend the separate budget in
	/// [`PeerCaps::max_relay_buckets`] and [`PeerCaps::max_relay_routes`],
	/// which bounds what a member relaying many origins can claim and leaves
	/// direct-gateway admission its own headroom (CWE-770).
	///
	/// The relay dial address comes from this registry's recorded value for
	/// the relay, which the direct reconcile's dial-conflict probe has
	/// already gated. Each bucket refuses stale advertisements on its own
	/// order ledger, as direct slates do (CWE-294).
	pub fn reconcile_relay_trail(&self, trail: RelayTrail, caps: PeerCaps) -> Result<(), ClusterError> {
		let RelayTrail { bucket, slate, order } = trail;

		self.refuse_stale_ad(&bucket, order)?;

		self.routes.write()?.admit_peer_slate(
			&bucket,
			None,
			slate,
			RouteKind::PeerRelay,
			caps.max_relay_buckets,
			caps.max_relay_routes,
		)?;
		self.record_ad_order(bucket, order)
	}

	/// Refuses an advertisement older than the newest applied for `bucket`.
	fn refuse_stale_ad(&self, bucket: &[u8], order: u64) -> Result<(), ClusterError> {
		let ledger = self.ad_orders.lock()?;
		if ledger.get(bucket).is_some_and(|&applied| order < applied) {
			return Err(ClusterError::StalePeerAd);
		}

		Ok(())
	}

	/// Records the applied advertisement order.
	///
	/// A row lives as long as its bucket holds entries. Once the bucket
	/// empties, the row survives one freshness window as a tombstone, so a
	/// replayed older advertisement still loses to the withdrawal it would
	/// otherwise undo (CWE-294).
	///
	/// Orders are frame-issue timestamps, so past that window the freshness
	/// gate refuses the replay on its own. Expired tombstones prune here,
	/// which bounds the ledger to the peer caps plus the window.
	fn record_ad_order(&self, bucket: SharedId, order: u64) -> Result<(), ClusterError> {
		let mut ledger = self.ad_orders.lock()?;
		ledger.insert(bucket, order);

		let routes = self.routes.read()?;
		let now = current_timestamp_ms();
		ledger.retain(|bucket, applied| {
			routes.holds_bucket(bucket.as_ref()) || now.saturating_sub(*applied) <= self.ad_tombstone_window_ms
		});

		Ok(())
	}

	/// Removes every relay trail learned for one origin identity.
	pub fn remove_relay_trails_for_origin(&self, origin_id: &[u8]) -> Result<usize, ClusterError> {
		let mut routes = self.routes.write()?;
		let stale: Vec<SharedId> = routes
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::PeerRelay)
			.filter(|entry| entry.owner_id().as_ref() == origin_id)
			.map(|entry| Arc::clone(entry.route_key()))
			.collect();

		for route_key in &stale {
			routes.remove(route_key.as_ref());
		}

		Ok(stale.len())
	}

	/// Removes every entry belonging to a hive.
	pub fn remove_by_hive(&self, hive_id: &[u8]) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let mut routes = self.routes.write()?;
		let addresses = routes.addresses_in_bucket(hive_id).to_vec();

		let mut removed = Vec::with_capacity(addresses.len());
		for address in &addresses {
			if let Some(entry) = routes.remove(address.as_ref()) {
				removed.push(entry);
			}
		}

		Ok(removed)
	}

	/// Applies a batch of servlet address additions and removals for one hive.
	pub fn apply_address_update(
		&self,
		hive_id: &[u8],
		added: Vec<ServletEntry>,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		self.routes.write()?.apply_address_update(hive_id, added, removed)
	}
}
