use core::num::NonZeroU32;
use core::time::Duration;
use std::sync::Arc;

use super::ClusterError;
use crate::basis_points::BasisPoints;
use crate::colony::cluster::registry::SharedId;
use crate::colony::cluster::servlet_registry::entry::{DialTarget, LocalRoute, PeerRoute, ServletEntry};
use crate::colony::cluster::{AdmittedDial, ClusterConfig};
use crate::colony::protocol::ServletInfo;
use crate::constants::{MAX_PEER_GATEWAYS, MAX_PEER_ROUTES, MAX_RELAY_BUCKETS, MAX_RELAY_ROUTES};
use crate::urn::Urn;

/// The default decay per evaporation cycle, in basis points (1000 = 10%).
pub const DEFAULT_EVAPORATION_RATE_BPS: u16 = 1000;
/// The default number of seconds between evaporation cycles.
pub const DEFAULT_EVAPORATION_INTERVAL_SECS: u64 = 30;
/// The default initial pheromone level of a new entry.
pub const DEFAULT_INITIAL_PHEROMONE: u64 = 5000;
/// The default count of consecutive failures that abandons a route.
///
/// The compiler evaluates its value, so a limit of zero fails to compile.
pub const DEFAULT_ABANDONMENT_LIMIT: NonZeroU32 = match NonZeroU32::new(5) {
	Some(limit) => limit,
	None => panic!("the default abandonment limit takes one failure or more"),
};
/// The default pheromone boost on a success (500 = 5% of the pheromone cap).
pub const DEFAULT_REINFORCEMENT_BOOST: u64 = 500;
/// The default weakening penalty. At 0, a failure only counts as a trial.
pub const DEFAULT_WEAKENING_PENALTY: u64 = 0;

/// The pheromone and abandonment settings of servlet routes.
#[derive(Debug, Clone)]
pub struct PheromoneConfig {
	/// The decay rate per evaporation cycle, in basis points (1000 = 10%).
	pub evaporation_rate: BasisPoints,
	/// The interval between evaporation cycles.
	pub evaporation_interval: Duration,
	/// The initial pheromone level of a new entry.
	pub initial_pheromone: u64,
	/// The count of consecutive failures that abandons an entry. It is at
	/// least one, so every entry is live at its creation.
	pub abandonment_limit: NonZeroU32,
	/// The pheromone boost on a successful request.
	pub reinforcement_boost: u64,
	/// The pheromone penalty on a failed request.
	pub weakening_penalty: u64,
}

/// The local routes one hive registered, every one owned by that hive.
///
/// [`ClusterConfig::servlet_slate`] is the one constructor. It stamps
/// `hive_id` on each entry and admits only a locator that names its own
/// address, so each entry names that hive as owner and dials the address its
/// identity claims (CWE-639).
pub(crate) struct HiveSlate {
	hive_id: SharedId,
	entries: Vec<ServletEntry>,
}

impl HiveSlate {
	/// The hive every route in this slate belongs to.
	pub(crate) fn hive_id(&self) -> &SharedId {
		&self.hive_id
	}

	/// Splits the slate into the hive and its routes for the registry that
	/// installs them.
	pub(super) fn into_parts(self) -> (SharedId, Vec<ServletEntry>) {
		(self.hive_id, self.entries)
	}

	/// A slate of already built entries, for tests that seed a registry
	/// with routes the fixtures name directly.
	#[cfg(test)]
	pub(super) fn of(hive_id: impl AsRef<[u8]>, entries: impl IntoIterator<Item = ServletEntry>) -> Self {
		let hive_id = hive_id.as_ref();
		Self { hive_id: Arc::from(hive_id), entries: entries.into_iter().collect() }
	}
}

impl ClusterConfig {
	/// Builds the route entries for one hive's advertised servlets.
	///
	/// - Each instance URN locator MUST equal the address advertised beside it (CWE-639).
	/// - Each entry answers under the signer advertised beside it (CWE-346).
	/// - Each entry starts on this colony's pheromone level and abandonment limit.
	///
	/// The locator rule stops a servlet that advertises one address under
	/// another's identity from redirecting that identity's traffic.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- a servlet URN names no servlet
	///   instance of this namespace, or its locator names another address than
	///   the one beside it.
	pub(crate) fn servlet_slate(
		&self,
		servlets: impl AsRef<[ServletInfo]>,
		hive_addr: &SharedId,
	) -> Result<HiveSlate, ClusterError> {
		let servlets = servlets.as_ref();
		let mut entries = Vec::with_capacity(servlets.len());
		for info in servlets {
			if !self.namespace.locator_matches(info) {
				return Err(ClusterError::InvalidAddress(info.address.clone()));
			}

			let route = LocalRoute {
				address: Arc::from(info.address.as_slice()),
				servlet_type: Arc::from(info.servlet_id.type_canonical_bytes().as_slice()),
				hive_id: Arc::clone(hive_addr),
				signer: info.signer.clone(),
			};

			let PheromoneConfig { initial_pheromone, abandonment_limit, .. } = self.pheromone;
			let entry = ServletEntry::local(route, initial_pheromone, abandonment_limit);
			entries.push(entry);
		}

		Ok(HiveSlate { hive_id: Arc::clone(hive_addr), entries })
	}
}

impl PheromoneConfig {
	/// Builds the peer-routed slate, each entry keyed by
	/// `peer_hive_id NUL type`.
	///
	/// Every entry stores `dial`, the admitted gateway socket, so each type
	/// this peer advertises resolves to the gateway that owns it. The entries
	/// share one rendering of that socket.
	pub(crate) fn peer_slate(
		&self,
		peer_hive_id: &SharedId,
		dial: AdmittedDial,
		types: impl AsRef<[Urn<'static>]>,
	) -> Vec<ServletEntry> {
		let types = types.as_ref();
		let target = DialTarget::of_claimed(dial);
		types
			.iter()
			.map(|urn| {
				let route = PeerRoute {
					peer_id: Arc::clone(peer_hive_id),
					servlet_type: Arc::from(urn.type_canonical_bytes().as_slice()),
					dial,
				};
				ServletEntry::peer_sharing(route, &target, self.initial_pheromone, self.abandonment_limit)
			})
			.collect()
	}
}

impl Default for PheromoneConfig {
	fn default() -> Self {
		Self {
			evaporation_rate: crate::bps!(DEFAULT_EVAPORATION_RATE_BPS),
			evaporation_interval: Duration::from_secs(DEFAULT_EVAPORATION_INTERVAL_SECS),
			initial_pheromone: DEFAULT_INITIAL_PHEROMONE,
			abandonment_limit: DEFAULT_ABANDONMENT_LIMIT,
			reinforcement_boost: DEFAULT_REINFORCEMENT_BOOST,
			weakening_penalty: DEFAULT_WEAKENING_PENALTY,
		}
	}
}

/// The storage caps of peer-learned routes (CWE-770).
///
/// The fields are named, so a caller cannot transpose two adjacent limits
/// unseen. Direct slates and relay trails hold separate budgets, so
/// direct-gateway admission keeps its headroom under relay fan-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCaps {
	/// The maximum count of peer gateways that hold an installed direct slate.
	pub max_gateways: usize,
	/// The maximum count of direct peer routes stored across all gateways.
	pub max_routes: usize,
	/// The maximum count of `(origin, relay)` buckets that hold relay trails.
	pub max_relay_buckets: usize,
	/// The maximum count of relay-trail routes stored across all buckets.
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
