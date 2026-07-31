use std::collections::HashSet;
use std::sync::Arc;

use super::{ClusterError, PheromoneConfig, RouteKind, ServletEntry, ServletRegistry, SharedId};

impl ServletRegistry {
	/// Live entries for a servlet type, shared by Arc (no entry deep copy).
	pub fn entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let addresses = {
			let type_idx = self.type_index.read()?;
			type_idx.get(servlet_type).cloned().unwrap_or_default()
		};

		let entries = self.entries.read()?;
		let result = addresses
			.iter()
			.filter_map(|address| entries.get(address.as_ref()).map(Arc::clone))
			.filter(|entry| entry.is_live())
			.collect();

		Ok(result)
	}

	/// Live local entries for a servlet type.
	pub fn local_entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let entries = self.entries_for_type(servlet_type)?;
		let local = entries
			.into_iter()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.collect();

		Ok(local)
	}

	/// Distinct live servlet types owned by this gateway.
	pub fn local_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		let entries = self.entries.read()?;
		let mut types = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.filter(|entry| entry.is_live())
			.map(|entry| Arc::clone(entry.servlet_type()))
			.collect::<Vec<_>>();

		types.sort_unstable();
		types.dedup();

		Ok(types)
	}

	pub(super) fn peer_key_conflicts_local(&self, hive_id: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let address_taken = entries.get(hive_id).is_some_and(|entry| entry.route_kind() == RouteKind::Local);
		if address_taken {
			return Ok(true);
		}

		let hive_idx = self.hive_index.read()?;
		let Some(addresses) = hive_idx.get(hive_id) else {
			return Ok(false);
		};

		let hive_taken = addresses.iter().any(|address| {
			entries
				.get(address.as_ref())
				.is_some_and(|entry| entry.route_kind() == RouteKind::Local)
		});

		Ok(hive_taken)
	}

	pub(super) fn peer_dial_conflicts_local(&self, dial_addr: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let conflict = entries
			.values()
			.any(|entry| entry.route_kind() == RouteKind::Local && entry.route_key().as_ref() == dial_addr);

		Ok(conflict)
	}

	pub(super) fn peer_slate_exceeds_caps(
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
		let mut gateways = HashSet::new();
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

		let gateway_is_new = !gateways.contains(hive_id);
		let gateways_after = gateways.len().saturating_add(usize::from(gateway_is_new));
		Ok(gateways_after > max_gateways)
	}

	/// Live routes reached through peer gateways.
	pub fn peer_entries(&self) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let entries = self.entries.read()?;
		let result = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.filter(|entry| entry.is_live())
			.map(Arc::clone)
			.collect();

		Ok(result)
	}

	/// Reinforce pheromone for one servlet after success.
	pub fn reinforce(&self, address: &[u8], quality: u64) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let result = if let Some(entry) = entries.get(address) {
			entry.reinforce(quality);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Count one failure for the servlet at `address`.
	pub fn weaken(&self, address: &[u8]) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let result = if let Some(entry) = entries.get(address) {
			entry.weaken();
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Count one failure and apply a pheromone penalty.
	pub fn weaken_with_penalty(&self, address: &[u8], penalty: u64) -> Result<bool, ClusterError> {
		let entries = self.entries.read()?;
		let result = if let Some(entry) = entries.get(address) {
			entry.weaken_with_penalty(penalty);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Weaken every live route advertised by a peer identity.
	pub fn weaken_peer(&self, peer_id: &[u8]) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		let weakened = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.filter(|entry| entry.is_live())
			.filter(|entry| entry.owner_id().as_ref() == peer_id)
			.map(|entry| entry.weaken())
			.count();

		Ok(weakened)
	}

	/// Weaken every live peer route that dials `dial_addr`.
	pub fn weaken_peer_by_dial(&self, dial_addr: &[u8]) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		let weakened = entries
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Peer)
			.filter(|entry| entry.is_live())
			.filter(|entry| entry.dial_target().as_ref() == dial_addr)
			.map(|entry| entry.weaken())
			.count();

		Ok(weakened)
	}

	/// Evaporate pheromone on every tracked entry.
	pub fn evaporate(&self) -> Result<(), ClusterError> {
		let entries = self.entries.read()?;
		let rate = self.config.evaporation_rate;
		for entry in entries.values() {
			entry.evaporate(rate);
		}

		Ok(())
	}

	/// Drop every entry that reached its abandonment limit.
	pub fn remove_abandoned(&self) -> Result<usize, ClusterError> {
		let abandoned = {
			let entries = self.entries.read()?;
			entries
				.iter()
				.filter(|(_, entry)| entry.is_abandoned())
				.map(|(address, _)| Arc::clone(address))
				.collect::<Vec<_>>()
		};

		let count = abandoned.len();
		for address in &abandoned {
			self.remove(address)?;
		}

		Ok(count)
	}

	/// Pheromone scoring and lifecycle configuration.
	pub fn config(&self) -> &PheromoneConfig {
		&self.config
	}

	/// Number of tracked servlet routes.
	pub fn len(&self) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		Ok(entries.len())
	}

	/// True when the registry holds no entries.
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		let is_empty = self.len()? == 0;
		Ok(is_empty)
	}
}
