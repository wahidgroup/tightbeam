use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use super::{ClusterError, PheromoneConfig, RouteKind, ServletEntry, ServletRegistry, SharedId};

impl ServletRegistry {
	/// Live routes for a servlet type, shared by Arc (no entry deep copy).
	pub fn entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let routes = self.routes.read()?;
		let addresses = routes.addresses_for_type(servlet_type);
		let result = addresses
			.iter()
			.filter_map(|address| routes.get(address.as_ref()).map(Arc::clone))
			.filter(|entry| entry.is_live())
			.collect();

		Ok(result)
	}

	/// Live local routes for a servlet type.
	pub fn local_entries_for_type(&self, servlet_type: &[u8]) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let routes = self.entries_for_type(servlet_type)?;
		let local = routes
			.into_iter()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.collect();

		Ok(local)
	}

	/// Distinct live servlet types owned by this gateway.
	pub fn local_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		let routes = self.routes.read()?;
		let mut types = routes
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.filter(|entry| entry.is_live())
			.map(|entry| Arc::clone(entry.servlet_type()))
			.collect::<Vec<_>>();

		types.sort_unstable();
		types.dedup();

		Ok(types)
	}

	/// Live routes reached through peer gateways, relay trails included.
	pub fn peer_entries(&self) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let routes = self.routes.read()?;
		let result = routes
			.values()
			.filter(|entry| entry.route_kind().is_peer())
			.filter(|entry| entry.is_live())
			.map(Arc::clone)
			.collect();

		Ok(result)
	}

	/// Reinforce pheromone for one servlet after success.
	pub fn reinforce(&self, address: &[u8], quality: u64) -> Result<bool, ClusterError> {
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.reinforce(quality);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Count one failure for the servlet at `address`.
	pub fn weaken(&self, address: &[u8]) -> Result<bool, ClusterError> {
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.weaken();
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Count one failure and apply a pheromone penalty.
	pub fn weaken_with_penalty(&self, address: &[u8], penalty: u64) -> Result<bool, ClusterError> {
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
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

		let routes = self.routes.read()?;
		let weakened = routes
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
		let routes = self.routes.read()?;
		let weakened = routes
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
		let routes = self.routes.read()?;
		let rate = self.config.evaporation_rate;
		for entry in routes.values() {
			entry.evaporate(rate);
		}

		Ok(())
	}

	/// Drop relay trails whose last reconcile is older than `max_age`.
	///
	/// A relay trail refreshes only when a relayed advertisement rumor
	/// reconciles its bucket, so a trail past `max_age` lost its refresh
	/// path. An unpicked trail accrues no trials, so age is the lifecycle
	/// bound that retires it (CWE-772).
	///
	/// # Sources
	///
	/// - CWE-772, missing release of resource after effective lifetime:
	///   <https://cwe.mitre.org/data/definitions/772.html>
	pub fn prune_stale_relay_trails(&self, max_age: Duration) -> Result<usize, ClusterError> {
		let now = Instant::now();
		let stale = {
			let routes = self.routes.read()?;
			routes
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
		let mut routes = self.routes.write()?;
		let abandoned: Vec<SharedId> = routes
			.values()
			.filter(|entry| entry.is_abandoned())
			.map(|entry| Arc::clone(entry.route_key()))
			.collect();

		let count = abandoned.len();
		for address in &abandoned {
			routes.remove(address.as_ref());
		}

		Ok(count)
	}

	/// Pheromone scoring and lifecycle configuration.
	pub fn config(&self) -> &PheromoneConfig {
		&self.config
	}

	/// Number of tracked servlet routes.
	pub fn len(&self) -> Result<usize, ClusterError> {
		let routes = self.routes.read()?;
		Ok(routes.values().count())
	}

	/// True when the registry holds no routes.
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		let is_empty = self.len()? == 0;
		Ok(is_empty)
	}
}
