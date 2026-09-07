use core::time::Duration;
use std::sync::Arc;

use crate::colony::cluster::registry::SharedId;
use crate::colony::cluster::servlet_registry::entry::ServletEntry;
use crate::colony::common::ServletInfo;
use crate::constants::{MAX_PEER_GATEWAYS, MAX_PEER_ROUTES, MAX_RELAY_BUCKETS, MAX_RELAY_ROUTES};
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;

/// Default decay per evaporation cycle in basis points (1000 = 10%).
pub const DEFAULT_EVAPORATION_RATE_BPS: u16 = 1000;
/// Default seconds between evaporation cycles.
pub const DEFAULT_EVAPORATION_INTERVAL_SECS: u64 = 30;
/// Default starting pheromone level for a new entry.
pub const DEFAULT_INITIAL_PHEROMONE: u64 = 5000;
/// Default consecutive failures before a route abandons.
pub const DEFAULT_ABANDONMENT_LIMIT: u32 = 5;
/// Default reinforcement boost (500 = 5% pheromone increase on success).
pub const DEFAULT_REINFORCEMENT_BOOST: u64 = 500;
/// Default weakening penalty (0 = only increment trial count on failure).
pub const DEFAULT_WEAKENING_PENALTY: u64 = 0;

/// Configuration for pheromone-based servlet tracking.
#[derive(Debug, Clone)]
pub struct PheromoneConfig {
	/// Decay rate per evaporation cycle in basis points (1000 = 10%).
	pub evaporation_rate: BasisPoints,
	/// The interval between evaporation cycles.
	pub evaporation_interval: Duration,
	/// Starting pheromone level for new entries.
	pub initial_pheromone: u64,
	/// Maximum consecutive failures before abandonment.
	pub abandonment_limit: u32,
	/// Pheromone boost on a successful request.
	pub reinforcement_boost: u64,
	/// Pheromone penalty on a failed request.
	pub weakening_penalty: u64,
}

impl PheromoneConfig {
	/// Route entries for one hive's advertised servlets.
	///
	/// Every entry starts on this colony's pheromone level and abandonment
	/// limit, so a freshly registered route competes on the same terms as
	/// the routes already in the registry.
	pub(crate) fn servlet_slate(&self, servlets: &[ServletInfo], hive_addr: &SharedId) -> Vec<ServletEntry> {
		servlets
			.iter()
			.map(|info| {
				ServletEntry::new(
					Arc::from(info.address.as_slice()),
					Arc::from(info.servlet_id.type_canonical_bytes().as_slice()),
					Arc::clone(hive_addr),
					self.initial_pheromone,
					self.abandonment_limit,
				)
			})
			.collect()
	}

	/// Peer-routed slate keyed by `peer_hive_id` NUL type.
	///
	/// `dial` is the claimed gateway socket stored on every entry, so every
	/// type this peer advertises resolves to the one gateway that owns it.
	pub(crate) fn peer_slate(
		&self,
		peer_hive_id: &SharedId,
		dial: SharedId,
		types: &[Urn<'static>],
	) -> Vec<ServletEntry> {
		types
			.iter()
			.map(|urn| {
				ServletEntry::peer(
					Arc::clone(peer_hive_id),
					Arc::from(urn.type_canonical_bytes().as_slice()),
					Arc::clone(&dial),
					self.initial_pheromone,
					self.abandonment_limit,
				)
			})
			.collect()
	}
}

impl Default for PheromoneConfig {
	fn default() -> Self {
		Self {
			evaporation_rate: BasisPoints::new(DEFAULT_EVAPORATION_RATE_BPS),
			evaporation_interval: Duration::from_secs(DEFAULT_EVAPORATION_INTERVAL_SECS),
			initial_pheromone: DEFAULT_INITIAL_PHEROMONE,
			abandonment_limit: DEFAULT_ABANDONMENT_LIMIT,
			reinforcement_boost: DEFAULT_REINFORCEMENT_BOOST,
			weakening_penalty: DEFAULT_WEAKENING_PENALTY,
		}
	}
}

/// Storage caps for peer-learned routes (CWE-770).
///
/// Named fields prevent callers from silently transposing adjacent
/// limits. Direct slates and relay trails hold separate budgets so
/// relay fan-in can never starve direct-gateway admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCaps {
	/// Maximum distinct peer gateways holding installed direct slates.
	pub max_gateways: usize,
	/// Maximum stored direct peer routes across all gateways.
	pub max_routes: usize,
	/// Maximum distinct `(origin, relay)` buckets holding relay trails.
	pub max_relay_buckets: usize,
	/// Maximum stored relay-trail routes across all buckets.
	pub max_relay_routes: usize,
}

impl Default for PeerCaps {
	fn default() -> Self {
		Self {
			max_gateways: MAX_PEER_GATEWAYS,
			max_routes: MAX_PEER_ROUTES,
			max_relay_buckets: MAX_RELAY_BUCKETS,
			max_relay_routes: MAX_RELAY_ROUTES,
		}
	}
}
