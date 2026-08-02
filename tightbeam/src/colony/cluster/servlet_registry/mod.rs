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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;

pub(super) use super::error::ClusterError;
pub(super) use super::SharedId;

pub use config::{
	PeerCaps, PheromoneConfig, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS,
	DEFAULT_EVAPORATION_RATE_BPS, DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};
pub use entry::{PeerRouteInfo, RouteKind, ServletEntry};

/// Registry of servlet entries with pheromone-based routing.
///
/// Tracks servlet instances across hives and peer gateways.
/// Reinforcement and evaporation steer selection, and trial limits
/// abandon dead routes.
pub struct ServletRegistry {
	/// Each route key owns one shared entry for zero-copy read queries.
	pub(super) entries: RwLock<HashMap<SharedId, Arc<ServletEntry>>>,
	/// Reverse index from servlet type to route keys.
	pub(super) type_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Reverse index from reconcile bucket to route keys.
	pub(super) hive_index: RwLock<HashMap<SharedId, Vec<SharedId>>>,
	/// Serializes multi-lock reconciliation and local installation.
	pub(super) reconcile_gate: Mutex<()>,
	/// Newest advertisement order applied per peer bucket, so a
	/// replayed older advertisement cannot regress a fresher slate
	/// (CWE-294). A row whose bucket died persists as a tombstone for
	/// one freshness window, so a withdrawal cannot be undone by a
	/// replay inside the window. Expired tombstones prune on the next
	/// record, which bounds the ledger by the peer caps plus the window.
	pub(super) ad_orders: Mutex<HashMap<SharedId, u64>>,
	/// Milliseconds a dead bucket's order tombstone survives. Past the
	/// window, the signed-control freshness gate refuses the replayed
	/// frame itself, so the tombstone carries no further value.
	pub(super) ad_tombstone_window_ms: u64,
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
			ad_orders: Mutex::new(HashMap::new()),
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
