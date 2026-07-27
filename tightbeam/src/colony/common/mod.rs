//! Common types shared across colony modules
//!
//! Contains load balancing strategies, message routing, and scaling configuration
//! used by both cluster and hive components.

pub mod messages;
pub mod scaling;

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{SPLITMIX64_GAMMA, SPLITMIX64_MIX_1, SPLITMIX64_MIX_2};
use crate::utils::BasisPoints;

pub use messages::*;
pub use scaling::*;

// ============================================================================
// Load Balancing
// ============================================================================

/// Metrics for a servlet instance used in load balancing decisions
#[derive(Debug, Clone)]
pub struct InstanceMetrics {
	/// Unique instance identifier (e.g., "worker_servlet_127.0.0.1:8080")
	pub servlet_id: Vec<u8>,
	/// Current utilization in basis points (0-10000)
	pub utilization: BasisPoints,
	/// Number of active/in-flight requests
	pub active_requests: u32,
}

/// Load balancing strategy for selecting servlet instances
///
/// Implementations determine how to distribute work across multiple
/// instances of the same servlet type.
pub trait LoadBalancer: Send + Sync + Default + Clone {
	/// Select an instance index from candidates
	///
	/// # Arguments
	/// * `candidates` - Slice of instance metrics to choose from
	///
	/// # Returns
	/// Index into `candidates` of the selected instance, or None if no suitable instance
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize>;
}

/// Select instance with lowest utilization
///
/// Simple and effective for most workloads. May cause thundering herd
/// under high concurrency as all routers converge on the same instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeastLoaded;

impl LoadBalancer for LeastLoaded {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		candidates
			.iter()
			.enumerate()
			.min_by_key(|(_, m)| m.utilization.get())
			.map(|(i, _)| i)
	}
}

/// Power of Two Choices (P2C) load balancer
///
/// Picks two distinct uniformly-random candidates per call and selects the
/// one with lower utilization (Mitzenmacher, "The Power of Two Choices in
/// Randomized Load Balancing", IEEE TPDS 12(10), 2001). The random probe
/// pair spreads concurrent routers across the pool instead of converging on
/// the single least-loaded instance.
///
/// Randomness comes from per-balancer SplitMix64 state advanced atomically
/// on every call, so selections within the same instant still draw fresh pairs.
#[derive(Debug, Clone)]
pub struct PowerOfTwoChoices {
	rng: Arc<AtomicU64>,
}

/// Gamma-stepped sequence so each balancer starts on a distinct SplitMix64
/// stream even when constructed within the same millisecond.
static P2C_SEED_SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl Default for PowerOfTwoChoices {
	fn default() -> Self {
		let sequence = P2C_SEED_SEQUENCE.fetch_add(SPLITMIX64_GAMMA, Ordering::Relaxed);
		Self { rng: Arc::new(AtomicU64::new(sequence ^ current_timestamp_ms())) }
	}
}

/// Advance SplitMix64 state atomically and return the mixed output
///
/// Reference implementation: Vigna, `splitmix64.c` (2015); see
/// [`SPLITMIX64_GAMMA`]. The single `fetch_add` claims a unique state value
/// per call, so concurrent callers never observe the same draw.
fn splitmix64_next(state: &AtomicU64) -> u64 {
	let mut z = state
		.fetch_add(SPLITMIX64_GAMMA, Ordering::Relaxed)
		.wrapping_add(SPLITMIX64_GAMMA);

	z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_MIX_1);
	z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_MIX_2);
	z ^ (z >> 31)
}

impl LoadBalancer for PowerOfTwoChoices {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates.len() {
			0 => None,
			1 => Some(0),
			2 => {
				// Exactly 2: probing "two random" is probing both
				if candidates[0].utilization <= candidates[1].utilization {
					Some(0)
				} else {
					Some(1)
				}
			}
			n => {
				// One draw yields 64 bits; the halves index a uniformly
				// distinct pair: second is drawn from [0, n-1) and shifted
				// past first, so (first, second) covers all ordered pairs.
				let draw = splitmix64_next(&self.rng);
				let first = ((draw >> 32) as usize) % n;
				let offset = ((draw & u64::from(u32::MAX)) as usize) % (n - 1);
				let second = offset + usize::from(offset >= first);

				if candidates[first].utilization <= candidates[second].utilization {
					Some(first)
				} else {
					Some(second)
				}
			}
		}
	}
}

/// Round-robin load balancer
///
/// Distributes requests evenly across all instances regardless of load.
/// Simple and predictable but doesn't account for varying request costs.
#[derive(Debug, Clone, Default)]
pub struct RoundRobin {
	counter: Arc<AtomicU64>,
}

impl LoadBalancer for RoundRobin {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		Some((count as usize) % candidates.len())
	}
}

// ============================================================================
// Scoring Policy
// ============================================================================

/// Converts raw entry data into a selection score for load balancing
///
/// ScoringPolicy transforms pheromone and utilization data into a unified
/// score that any LoadBalancer can use. The score semantics match utilization:
/// lower values are preferred by LeastLoaded.
///
/// This separation allows bio-inspired algorithms (ACO/ABC) to work with
/// any load balancing strategy.
pub trait ScoringPolicy: Send + Sync {
	/// Compute a selection score from pheromone and utilization
	///
	/// # Arguments
	/// * `pheromone` - Pheromone level (0-10000, higher = more successful)
	/// * `utilization` - Current load in basis points (0-10000, higher = busier)
	///
	/// # Returns
	/// Score in basis points (lower = preferred by LeastLoaded-style balancers)
	fn score(&self, pheromone: u64, utilization: BasisPoints) -> BasisPoints;
}

/// Pheromone-first scoring: high pheromone = low score = preferred
///
/// Ignores utilization and focuses purely on historical success.
/// Good for environments where past performance predicts future success.
#[derive(Debug, Clone, Copy, Default)]
pub struct PheromoneScoring;

impl ScoringPolicy for PheromoneScoring {
	fn score(&self, pheromone: u64, _utilization: BasisPoints) -> BasisPoints {
		// Invert: MAX - pheromone so LeastLoaded picks highest pheromone
		let inverted = 10000u64.saturating_sub(pheromone);
		BasisPoints::new_saturating(inverted as u16)
	}
}

/// Utilization-first scoring (existing behavior)
///
/// Ignores pheromone and uses only current load.
/// Good for predictable, homogeneous workloads.
#[derive(Debug, Clone, Copy, Default)]
pub struct UtilizationScoring;

impl ScoringPolicy for UtilizationScoring {
	fn score(&self, _pheromone: u64, utilization: BasisPoints) -> BasisPoints {
		utilization
	}
}

/// Combined scoring: weighted blend of pheromone and utilization
///
/// Balances historical success with current load for adaptive routing.
#[derive(Debug, Clone, Copy)]
pub struct CombinedScoring {
	/// Weight for pheromone component (0-10000 basis points)
	pub pheromone_weight: u16,
}

impl Default for CombinedScoring {
	fn default() -> Self {
		Self { pheromone_weight: 5000 } // 50/50 blend
	}
}

impl ScoringPolicy for CombinedScoring {
	fn score(&self, pheromone: u64, utilization: BasisPoints) -> BasisPoints {
		let pheromone_score = 10000u64.saturating_sub(pheromone);
		let util_score = utilization.get() as u64;

		let pw = self.pheromone_weight as u64;
		let uw = 10000u64.saturating_sub(pw);

		// Weighted average
		let combined = (pheromone_score * pw + util_score * uw) / 10000;
		BasisPoints::new_saturating(combined as u16)
	}
}

// ============================================================================
// Message Routing
// ============================================================================

/// Type validator function signature for message routing
pub type MessageValidator = fn(&[u8]) -> bool;

/// Message routing strategy for type-based dispatch
///
/// Implementations determine how to match incoming messages to servlet types.
pub trait MessageRouter: Send + Sync + Default + Clone {
	/// Attempt to route a message to a servlet type
	///
	/// # Arguments
	/// * `message` - Raw message bytes to route
	/// * `registered_types` - Slice of (type_name, validator) pairs
	///
	/// # Returns
	/// The servlet type name if matched, None otherwise
	fn route<'a>(&self, message: &[u8], registered_types: &'a [(&'static [u8], MessageValidator)]) -> Option<&'a [u8]>;
}

/// Routes by attempting decode against each registered type's validator
///
/// Tries validators in registration order; first match wins.
#[derive(Debug, Clone, Copy, Default)]
pub struct TypeBasedRouter;

impl MessageRouter for TypeBasedRouter {
	fn route<'a>(&self, message: &[u8], registered_types: &'a [(&'static [u8], MessageValidator)]) -> Option<&'a [u8]> {
		registered_types
			.iter()
			.find(|(_, validator)| validator(message))
			.map(|(name, _)| *name)
	}
}

// ============================================================================
// Timestamp Helper
// ============================================================================

/// Get current timestamp in milliseconds since UNIX epoch
///
/// Always backed by the system clock: `colony` implies `std`, so no
/// fallback stub exists.
pub fn current_timestamp_ms() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

// ============================================================================
// Utilization Aggregation
// ============================================================================

/// Mean utilization across all servlet instances of a hive
///
/// `total_utilization` is the sum of per-instance basis points and
/// `instance_count` the number of instances summed. A hive with zero
/// instances reports [`BasisPoints::MAX`]: it cannot absorb work, so
/// backpressure and heartbeats must signal saturation (per-type scaling
/// still sees the zero count and spawns).
pub fn aggregate_utilization(total_utilization: u64, instance_count: usize) -> BasisPoints {
	match instance_count {
		0 => BasisPoints::MAX,
		n => BasisPoints::new_saturating((total_utilization / n as u64) as u16),
	}
}

// ============================================================================
// Control-Plane Reply Frames
// ============================================================================

/// Build a V0 response frame echoing a request id
///
/// Single implementation behind the `hive!` and `cluster!` `@reply`
/// macro arms.
pub fn reply_frame<M: crate::Message>(
	id: impl AsRef<[u8]>,
	message: M,
) -> Result<Option<crate::Frame>, crate::TightBeamError> {
	use crate::builder::TypeBuilder;

	let frame = crate::utils::compose(crate::Version::V0)
		.with_id(id)
		.with_order(0)
		.with_message(message)
		.build()?;

	Ok(Some(frame))
}

/// Build a V2 response frame with an explicit priority
///
/// Used for heartbeat replies, which carry `NetworkControl` priority so
/// monitoring stays distinguishable from work traffic.
pub fn reply_frame_with_priority<M: crate::Message>(
	id: impl AsRef<[u8]>,
	priority: crate::MessagePriority,
	message: M,
) -> Result<Option<crate::Frame>, crate::TightBeamError> {
	use crate::builder::TypeBuilder;

	let frame = crate::utils::compose(crate::Version::V2)
		.with_id(id)
		.with_order(0)
		.with_priority(priority)
		.with_message(message)
		.build()?;

	Ok(Some(frame))
}

#[cfg(test)]
mod tests {
	use std::collections::HashSet;

	use super::{InstanceMetrics, LoadBalancer, PowerOfTwoChoices};
	use crate::utils::BasisPoints;

	fn candidates(count: usize) -> Vec<InstanceMetrics> {
		(0..count)
			.map(|index| InstanceMetrics {
				servlet_id: vec![index as u8],
				utilization: BasisPoints::new(5000),
				active_requests: 0,
			})
			.collect()
	}

	#[test]
	fn p2c_returns_none_for_empty_pool() {
		let balancer = PowerOfTwoChoices::default();
		assert_eq!(balancer.select(&[]), None);
	}

	#[test]
	fn p2c_returns_sole_candidate() {
		let balancer = PowerOfTwoChoices::default();
		assert_eq!(balancer.select(&candidates(1)), Some(0));
	}

	#[test]
	fn p2c_picks_least_loaded_of_two() {
		let balancer = PowerOfTwoChoices::default();
		let mut pool = candidates(2);
		pool[1].utilization = BasisPoints::new(100);

		assert_eq!(balancer.select(&pool), Some(1));
	}

	#[test]
	fn p2c_covers_all_indices_under_uniform_load() {
		let balancer = PowerOfTwoChoices::default();
		let pool = candidates(8);

		let seen: HashSet<usize> = (0..4096).filter_map(|_| balancer.select(&pool)).collect();
		assert_eq!(seen.len(), pool.len());
	}

	#[test]
	fn p2c_escapes_loaded_leading_pair() {
		let balancer = PowerOfTwoChoices::default();
		let mut pool = candidates(4);
		pool[0].utilization = BasisPoints::MAX;
		pool[1].utilization = BasisPoints::MAX;

		let seen: HashSet<usize> = (0..4096).filter_map(|_| balancer.select(&pool)).collect();
		assert!(seen.contains(&2));
		assert!(seen.contains(&3));
	}

	#[test]
	fn p2c_balancers_draw_distinct_streams() {
		let first = PowerOfTwoChoices::default();
		let second = PowerOfTwoChoices::default();
		let pool = candidates(64);

		let first_picks: Vec<Option<usize>> = (0..16).map(|_| first.select(&pool)).collect();
		let second_picks: Vec<Option<usize>> = (0..16).map(|_| second.select(&pool)).collect();
		assert_ne!(first_picks, second_picks);
	}

	/// Cases: (total_utilization, instance_count, expected_bps)
	const AGGREGATE_CASES: &[(u64, usize, u16)] = &[
		(0, 0, 10000),     // no instances -> saturated, route elsewhere
		(0, 4, 0),         // all idle
		(20000, 4, 5000),  // uniform mean
		(10000, 2, 5000),  // one loaded type + one idle type
		(40000, 4, 10000), // fully loaded
	];

	#[test]
	fn aggregate_utilization_means_across_all_instances() {
		for &(total, count, expected) in AGGREGATE_CASES {
			assert_eq!(super::aggregate_utilization(total, count).get(), expected);
		}
	}
}
