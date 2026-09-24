use core::time::Duration;
use std::sync::Arc;

use super::{ClusterError, PheromoneConfig, RouteKind, ServletEntry, ServletRegistry, SharedId};
use crate::colony::common::ServletTypeKey;

impl ServletRegistry {
	/// Returns the live routes for a servlet type as shared [`Arc`] handles,
	/// so the call deep-copies no entry.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn entries_for_type(&self, servlet_type: &ServletTypeKey) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let servlet_type = servlet_type.as_ref();
		let routes = self.routes.read()?;
		let addresses = routes.addresses_for_type(servlet_type);
		let result = addresses
			.iter()
			.filter_map(|address| routes.get(address.as_ref()).map(Arc::clone))
			.filter(|entry| entry.is_live())
			.collect();

		Ok(result)
	}

	/// Returns the live local routes for a servlet type.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn local_entries_for_type(
		&self,
		servlet_type: &ServletTypeKey,
	) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let routes = self.entries_for_type(servlet_type)?;
		let local = routes
			.into_iter()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.collect();

		Ok(local)
	}

	/// Returns the distinct live servlet types this gateway owns, sorted.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
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

	/// Returns the live routes reached through peer gateways, relay trails
	/// included.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
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

	/// Reinforces the pheromone of the servlet at `address` after a success,
	/// and reports whether a route sits at `address`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn reinforce(&self, address: impl AsRef<[u8]>, quality: u64) -> Result<bool, ClusterError> {
		let address = address.as_ref();
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.reinforce(quality);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Counts one failure for the servlet at `address`, and reports whether a
	/// route sits at `address`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn weaken(&self, address: impl AsRef<[u8]>) -> Result<bool, ClusterError> {
		let address = address.as_ref();
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.weaken();
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Counts one failure and applies a pheromone penalty to the servlet at
	/// `address`, and reports whether a route sits at `address`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn weaken_with_penalty(&self, address: impl AsRef<[u8]>, penalty: u64) -> Result<bool, ClusterError> {
		let address = address.as_ref();
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.weaken_with_penalty(penalty);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Weakens every live route attributed to a peer identity and returns how
	/// many it weakened.
	///
	/// A route is attributed to the peer when it is one of these:
	///
	/// - A direct route the peer advertised.
	/// - A relay trail learned for the peer.
	/// - A relay trail that forwards through the peer.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn weaken_peer(&self, peer_id: impl AsRef<[u8]>) -> Result<usize, ClusterError> {
		let peer_id = peer_id.as_ref();
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

	/// Weakens every live peer route that dials `dial_addr`, relay trails
	/// included, and returns how many it weakened. A misbehaving gateway
	/// therefore weakens every trail through it.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn weaken_peer_by_dial(&self, dial_addr: impl AsRef<[u8]>) -> Result<usize, ClusterError> {
		let dial_addr = dial_addr.as_ref();
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

	/// Evaporates pheromone on every tracked entry at the configured rate.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn evaporate(&self) -> Result<(), ClusterError> {
		let routes = self.routes.read()?;
		let rate = self.config.evaporation_rate;
		for entry in routes.values() {
			entry.evaporate(rate);
		}

		Ok(())
	}

	/// Drops the relay trails whose last reconcile is older than `max_age`.
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
	pub(in crate::colony::cluster) fn prune_stale_relay_trails(
		&self,
		max_age: Duration,
	) -> Result<usize, ClusterError> {
		let now = self.clock.monotonic();
		Ok(self.routes.write()?.prune_stale_relay_trails(now, max_age))
	}

	/// Drops every entry that reached its abandonment limit and returns how
	/// many it dropped.
	pub(in crate::colony::cluster) fn remove_abandoned(&self) -> Result<usize, ClusterError> {
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

	/// Returns the pheromone scoring and lifecycle configuration.
	pub fn config(&self) -> &PheromoneConfig {
		&self.config
	}

	/// Returns the number of tracked servlet routes.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn len(&self) -> Result<usize, ClusterError> {
		let routes = self.routes.read()?;
		Ok(routes.values().count())
	}

	/// Whether the registry holds no routes.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		let is_empty = self.len()? == 0;
		Ok(is_empty)
	}
}
