//! Common types shared across colony modules
//!
//! Contains load balancing strategies, message routing, and scaling configuration
//! used by both cluster and hive components.

pub mod messages;
pub mod scaling;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::constants::LCG_MULTIPLIER;
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
/// Picks two random candidates and selects the one with lower utilization.
/// Better than pure least-loaded under high concurrency as it avoids
/// thundering herd while still achieving good balance.
///
/// Used by Envoy, gRPC, and other modern load balancers.
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerOfTwoChoices;

impl LoadBalancer for PowerOfTwoChoices {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates.len() {
			0 => None,
			1 => Some(0),
			2 => {
				// Exactly 2: pick least loaded
				if candidates[0].utilization <= candidates[1].utilization {
					Some(0)
				} else {
					Some(1)
				}
			}
			n => {
				// Pick 2 random indices using simple LCG for no_std compatibility
				let seed = current_timestamp_ms();
				let i1 = (seed as usize) % n;
				let i2 = ((seed.wrapping_mul(LCG_MULTIPLIER).wrapping_add(1)) as usize) % n;
				// Ensure different indices
				let i2 = if i1 == i2 {
					(i2 + 1) % n
				} else {
					i2
				};

				// Select least loaded of the two
				if candidates[i1].utilization <= candidates[i2].utilization {
					Some(i1)
				} else {
					Some(i2)
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
		BasisPoints::new(inverted as u16)
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
		BasisPoints::new(combined as u16)
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
#[cfg(feature = "std")]
pub fn current_timestamp_ms() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

/// Timestamp stub for no_std environments
///
/// Embedded systems should provide their own time source.
#[cfg(not(feature = "std"))]
pub fn current_timestamp_ms() -> u64 {
	0 // Embedded systems need external time source
}
