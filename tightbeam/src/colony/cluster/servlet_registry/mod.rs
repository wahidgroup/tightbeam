//! Servlet route registry with pheromone scoring and trial-based abandonment.
//!
//! - Pheromone rises on successful work and decays on a timer.
//! - Trial count rises on failure; entries abandon past a limit.
//! - Local hive routes and peer-learned routes share the same scoring tables.

mod config;
mod entry;
mod index;
mod select;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

pub(super) use super::error::ClusterError;
pub(super) use super::SharedId;

pub use config::{
	PeerCaps, PheromoneConfig, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS,
	DEFAULT_EVAPORATION_RATE_BPS, DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};
pub use entry::{PeerRouteInfo, RouteKind, ServletEntry};

/// Registry of servlet entries with pheromone-based routing.
///
/// Tracks servlet instances across hives and peer gateways. Reinforcement
/// and evaporation steer selection; trial limits abandon dead routes.
pub struct ServletRegistry {
	/// Each route key owns one shared entry for zero-copy read queries.
	pub(super) entries: RwLock<HashMap<SharedId, Arc<ServletEntry>>>,
	/// Reverse index from servlet type to route keys.
	pub(super) type_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Reverse index from hive identity to route keys.
	pub(super) hive_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Serializes multi-lock reconciliation and local installation.
	pub(super) reconcile_gate: Mutex<()>,
	/// Scoring and lifecycle configuration.
	pub(super) config: PheromoneConfig,
}

impl ServletRegistry {
	/// Creates a registry with the supplied pheromone configuration.
	pub fn new(config: PheromoneConfig) -> Self {
		Self {
			entries: RwLock::new(HashMap::new()),
			type_index: RwLock::new(HashMap::new()),
			hive_index: RwLock::new(HashMap::new()),
			reconcile_gate: Mutex::new(()),
			config,
		}
	}
}

impl Default for ServletRegistry {
	fn default() -> Self {
		Self::new(PheromoneConfig::default())
	}
}
