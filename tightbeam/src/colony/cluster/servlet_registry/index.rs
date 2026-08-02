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
		let addr = Arc::clone(entry.route_key());
		let servlet_type = Arc::clone(entry.servlet_type());
		let bucket = Arc::clone(entry.bucket());

		let previous = {
			let mut entries = self.entries.write()?;
			let mut entry = entry;
			if let Some(prev) = entries.get(addr.as_ref()) {
				entry.preserve_peer_trail_from(prev);
			}

			let stored_entry = Arc::new(entry);
			entries.insert(Arc::clone(&addr), stored_entry)
		};

		if let Some(previous) = previous.as_deref() {
			self.remove_index_rows(previous, &addr)?;
		}

		{
			let mut type_idx = self.type_index.write()?;
			type_idx.entry(servlet_type).or_default().push(Arc::clone(&addr));
		}

		{
			let mut hive_idx = self.hive_index.write()?;
			hive_idx.entry(bucket).or_default().push(addr);
		}

		Ok(())
	}

	fn remove_index_rows(&self, entry: &ServletEntry, address: &[u8]) -> Result<(), ClusterError> {
		{
			let mut type_idx = self.type_index.write()?;
			if let Some(addrs) = type_idx.get_mut(entry.servlet_type()) {
				addrs.retain(|addr| addr.as_ref() != address);
				if addrs.is_empty() {
					type_idx.remove(entry.servlet_type());
				}
			}
		}

		{
			let mut hive_idx = self.hive_index.write()?;
			if let Some(addrs) = hive_idx.get_mut(entry.bucket()) {
				addrs.retain(|addr| addr.as_ref() != address);
				if addrs.is_empty() {
					hive_idx.remove(entry.bucket());
				}
			}
		}

		Ok(())
	}

	/// Adds entries for every servlet type declared by one hive.
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

	/// Removes a servlet entry by address.
	pub fn remove(&self, address: &[u8]) -> Result<Option<Arc<ServletEntry>>, ClusterError> {
		let entry = {
			let mut entries = self.entries.write()?;
			entries.remove(address)
		};

		if let Some(entry) = entry.as_deref() {
			self.remove_index_rows(entry, address)?;
		}

		Ok(entry)
	}

	/// Replaces one hive slate atomically.
	pub fn reconcile_by_hive(&self, hive_id: &[u8], entries: Vec<ServletEntry>) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;
		self.reconcile_slate(hive_id, entries)
	}

	fn reconcile_slate(&self, hive_id: &[u8], entries: Vec<ServletEntry>) -> Result<(), ClusterError> {
		let prior: Vec<Arc<ServletEntry>> = {
			let addresses = {
				let hive_idx = self.hive_index.read()?;
				hive_idx.get(hive_id).cloned().unwrap_or_default()
			};

			let map = self.entries.read()?;
			addresses
				.iter()
				.filter_map(|address| map.get(address.as_ref()).map(Arc::clone))
				.collect()
		};

		let mut fresh = Vec::with_capacity(entries.len());
		for entry in entries {
			let addr = Arc::clone(entry.route_key());
			if let Err(error) = self.add(entry) {
				self.restore_slate(&fresh, &prior);

				return Err(error);
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
				.filter(|address| !fresh.iter().any(|kept| kept.as_ref() == address.as_ref()))
				.collect()
		};

		for addr in &stale {
			if let Err(error) = self.remove(addr) {
				self.restore_slate(&fresh, &prior);
				return Err(error);
			}
		}

		Ok(())
	}

	fn restore_slate(&self, fresh: &[SharedId], prior: &[Arc<ServletEntry>]) {
		for address in fresh {
			let _ = self.remove(address);
		}
		for entry in prior {
			let entry = ServletEntry::clone(entry);
			let _ = self.add(entry);
		}
	}

	/// Reconciles an admitted peer slate after stale, conflict, and cap
	/// checks.
	///
	/// The registry refuses an advertisement older than the newest one
	/// applied for the origin. A replayed ad inside the freshness
	/// window therefore cannot regress a fresher slate (CWE-294). An
	/// empty slate clears the origin's relay trails with its direct routes:
	/// a fallback MUST NOT outlive every claim it was learned from.
	pub fn reconcile_peer_slate(&self, ad: AdmittedPeerAd, caps: PeerCaps) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;
		let AdmittedPeerAd { peer_hive_id, dial_addr, slate, order } = ad;

		self.refuse_stale_ad(&peer_hive_id, order)?;

		if self.peer_key_conflicts_local(&peer_hive_id)? || self.peer_dial_conflicts_local(&dial_addr)? {
			return Err(ClusterError::PeerSlateConflict);
		}
		if self.slate_exceeds_caps(&peer_hive_id, slate.len(), RouteKind::Peer, caps.max_gateways, caps.max_routes)? {
			return Err(ClusterError::PeerCapExceeded);
		}

		let clearing = slate.is_empty();

		self.reconcile_slate(&peer_hive_id, slate)?;

		if clearing {
			self.remove_relay_trails_for_origin(&peer_hive_id)?;
		}

		self.record_ad_order(peer_hive_id, order)
	}

	/// Replaces one relay-trail slate atomically under its own bucket.
	///
	/// The bucket is `origin NUL relay`, so an origin's direct slate
	/// reconcile never evicts its relay fallback and vice versa.
	/// Relay buckets spend their own cap budget
	/// ([`PeerCaps::max_relay_buckets`], [`PeerCaps::max_relay_routes`]),
	/// so a member relaying many origins can neither inflate the
	/// registry nor starve direct-gateway admission (CWE-770). The
	/// relay dial address is this registry's own recorded value for
	/// the relay, never a wire claim. The direct reconcile's
	/// dial-conflict probe has therefore already gated it. Stale
	/// advertisements are refused per bucket, exactly like direct
	/// slates (CWE-294).
	pub fn reconcile_relay_trail(&self, trail: RelayTrail, caps: PeerCaps) -> Result<(), ClusterError> {
		let _gate = self.reconcile_gate.lock()?;
		let RelayTrail { bucket, slate, order } = trail;

		self.refuse_stale_ad(&bucket, order)?;

		if self.peer_key_conflicts_local(&bucket)? {
			return Err(ClusterError::PeerSlateConflict);
		}
		if self.slate_exceeds_caps(
			&bucket,
			slate.len(),
			RouteKind::PeerRelay,
			caps.max_relay_buckets,
			caps.max_relay_routes,
		)? {
			return Err(ClusterError::PeerCapExceeded);
		}

		self.reconcile_slate(&bucket, slate)?;
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
	/// A row whose bucket still holds entries lives with the bucket. A
	/// dead bucket's row persists as a tombstone for one freshness
	/// window, so a replayed older advertisement cannot undo a
	/// withdrawal (CWE-294). Orders are frame-issue timestamps, so an
	/// expired tombstone guards nothing the freshness gate does not
	/// already refuse. Expired tombstones prune here, which keeps the
	/// ledger bounded.
	fn record_ad_order(&self, bucket: SharedId, order: u64) -> Result<(), ClusterError> {
		let mut ledger = self.ad_orders.lock()?;
		ledger.insert(bucket, order);

		let hive_idx = self.hive_index.read()?;
		let now = current_timestamp_ms();
		ledger.retain(|bucket, applied| {
			hive_idx.contains_key(bucket.as_ref()) || now.saturating_sub(*applied) <= self.ad_tombstone_window_ms
		});

		Ok(())
	}

	/// Removes every relay trail learned for one origin identity.
	pub fn remove_relay_trails_for_origin(&self, origin_id: &[u8]) -> Result<usize, ClusterError> {
		let stale: Vec<SharedId> = {
			let entries = self.entries.read()?;
			entries
				.values()
				.filter(|entry| entry.route_kind() == RouteKind::PeerRelay)
				.filter(|entry| entry.owner_id().as_ref() == origin_id)
				.map(|entry| Arc::clone(entry.route_key()))
				.collect()
		};

		for route_key in &stale {
			self.remove(route_key)?;
		}

		Ok(stale.len())
	}

	/// Removes every entry belonging to a hive.
	pub fn remove_by_hive(&self, hive_id: &[u8]) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let addresses = {
			let hive_idx = self.hive_index.read()?;
			hive_idx.get(hive_id).cloned().unwrap_or_default()
		};

		let mut removed = Vec::with_capacity(addresses.len());
		for address in &addresses {
			if let Some(entry) = self.remove(address)? {
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
		let _gate = self.reconcile_gate.lock()?;
		for entry in &added {
			if entry.owner_id().as_ref() != hive_id {
				return Err(ClusterError::ServletNotOwned);
			}
		}

		{
			let entries = self.entries.read()?;
			for address in removed {
				if let Some(entry) = entries.get(*address) {
					if entry.owner_id().as_ref() != hive_id {
						return Err(ClusterError::ServletNotOwned);
					}
				}
			}
		}

		let mut applied_addrs: Vec<SharedId> = Vec::with_capacity(added.len());
		for entry in added {
			let addr = Arc::clone(entry.route_key());
			if let Err(error) = self.add(entry) {
				for applied in &applied_addrs {
					let _ = self.remove(applied);
				}
				return Err(error);
			}
			applied_addrs.push(addr);
		}

		let mut removed_entries = Vec::with_capacity(removed.len());
		for address in removed {
			match self.remove(address) {
				Ok(Some(entry)) => removed_entries.push(entry),
				Ok(None) => {
					self.restore_removed_and_fresh(removed_entries, &applied_addrs);
					return Err(ClusterError::ServletNotFound);
				}
				Err(error) => {
					self.restore_removed_and_fresh(removed_entries, &applied_addrs);
					return Err(error);
				}
			}
		}

		Ok(())
	}

	fn restore_removed_and_fresh(&self, removed_entries: Vec<Arc<ServletEntry>>, applied_addrs: &[SharedId]) {
		for entry in removed_entries {
			let entry = ServletEntry::clone(&entry);
			let _ = self.add(entry);
		}
		for address in applied_addrs {
			let _ = self.remove(address);
		}
	}
}
