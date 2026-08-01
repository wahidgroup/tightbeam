use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

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

	/// Whether reconciling `new_slate_len` routes under `bucket` would
	/// exceed the caps for its route kind (CWE-770).
	///
	/// `count_kind` scopes both counts, so direct slates and relay
	/// trails spend separate budgets. `max_identities` bounds distinct
	/// buckets of that kind (direct gateways, or `(origin, relay)`
	/// relay buckets). `max_routes` bounds that kind's total stored
	/// routes.
	pub(super) fn slate_exceeds_caps(
		&self,
		bucket: &[u8],
		new_slate_len: usize,
		count_kind: RouteKind,
		max_identities: usize,
		max_routes: usize,
	) -> Result<bool, ClusterError> {
		if new_slate_len == 0 {
			return Ok(false);
		}

		let entries = self.entries.read()?;
		let mut kind_total = 0usize;
		let mut prior_for_bucket = 0usize;
		let mut identities = HashSet::new();
		for entry in entries.values().filter(|entry| entry.route_kind() == count_kind) {
			kind_total += 1;

			let entry_bucket = entry.bucket().as_ref();
			identities.insert(entry_bucket);
			if entry_bucket == bucket {
				prior_for_bucket += 1;
			}
		}

		let routes_after = kind_total.saturating_sub(prior_for_bucket).saturating_add(new_slate_len);
		if routes_after > max_routes {
			return Ok(true);
		}

		let identity_is_new = !identities.contains(bucket);
		let identities_after = identities.len().saturating_add(usize::from(identity_is_new));
		Ok(identities_after > max_identities)
	}

	/// Live routes reached through peer gateways, relay trails included.
	pub fn peer_entries(&self) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let entries = self.entries.read()?;
		let result = entries
			.values()
			.filter(|entry| entry.route_kind().is_peer())
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

	/// Weaken every live route attributed to a peer identity: direct
	/// routes it advertised, relay trails learned for it, and relay
	/// trails that forward through it.
	pub fn weaken_peer(&self, peer_id: &[u8]) -> Result<usize, ClusterError> {
		let attributed = |entry: &ServletEntry| {
			entry.owner_id().as_ref() == peer_id || entry.relay_id().is_some_and(|relay| relay.as_ref() == peer_id)
		};

		let entries = self.entries.read()?;
		let weakened = entries
			.values()
			.filter(|entry| entry.route_kind().is_peer())
			.filter(|entry| entry.is_live())
			.filter(|entry| attributed(entry))
			.map(|entry| entry.weaken())
			.count();

		Ok(weakened)
	}

	/// Weaken every live peer route that dials `dial_addr`, relay
	/// trails included: a misbehaving gateway weakens every trail
	/// through it.
	pub fn weaken_peer_by_dial(&self, dial_addr: &[u8]) -> Result<usize, ClusterError> {
		let entries = self.entries.read()?;
		let weakened = entries
			.values()
			.filter(|entry| entry.route_kind().is_peer())
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

	/// Drop relay trails whose last reconcile is older than `max_age`.
	///
	/// A relay trail refreshes only when a relayed advertisement rumor
	/// reconciles its bucket, so a trail past `max_age` lost its refresh
	/// path. Selection alone cannot retire it: a trail that is never picked
	/// never accrues trials, so age is the lifecycle bound (CWE-772).
	///
	/// # Sources
	///
	/// - CWE-772, missing release of resource after effective lifetime:
	///   <https://cwe.mitre.org/data/definitions/772.html>
	pub fn prune_stale_relay_trails(&self, max_age: Duration) -> Result<usize, ClusterError> {
		let now = Instant::now();
		let stale = {
			let entries = self.entries.read()?;
			entries
				.values()
				.filter(|entry| entry.route_kind() == RouteKind::PeerRelay)
				.filter(|entry| now.duration_since(entry.installed_at()) > max_age)
				.map(|entry| Arc::clone(entry.route_key()))
				.collect::<Vec<_>>()
		};

		let count = stale.len();
		for route_key in &stale {
			self.remove(route_key)?;
		}

		Ok(count)
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
