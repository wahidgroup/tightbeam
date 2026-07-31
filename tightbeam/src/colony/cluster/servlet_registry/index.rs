use std::sync::Arc;

use super::{ClusterError, PeerCaps, ServletEntry, ServletRegistry, SharedId};
use crate::colony::cluster::peer::AdmittedPeerAd;

impl ServletRegistry {
	/// Adds a servlet entry.
	///
	/// Re-registering an address retires its index rows first. Peer route
	/// replacement preserves its pheromone and trial state.
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
			hive_idx.entry(hive_id).or_default().push(addr);
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
			if let Some(addrs) = hive_idx.get_mut(entry.owner_id()) {
				addrs.retain(|addr| addr.as_ref() != address);
				if addrs.is_empty() {
					hive_idx.remove(entry.owner_id());
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

	/// Reconciles an admitted peer slate after conflict and cap checks.
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
