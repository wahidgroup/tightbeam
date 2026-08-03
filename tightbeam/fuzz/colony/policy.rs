//! Mutable [`GatePolicy`] and deterministic load balancers for AFL.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tightbeam::colony::common::{InstanceMetrics, LoadBalancer};
use tightbeam::policy::{GatePolicy, SessionContext, TransitStatus};
use tightbeam::Frame;

/// Shared pre-decode gate that the oracle can arm or disarm.
pub(crate) struct DynamicPolicyGate {
	reject: AtomicBool,
}

impl DynamicPolicyGate {
	pub fn new() -> Arc<Self> {
		Arc::new(Self { reject: AtomicBool::new(false) })
	}

	pub fn set_reject(&self, reject: bool) {
		self.reject.store(reject, Ordering::Relaxed);
	}

	pub fn is_rejecting(&self) -> bool {
		self.reject.load(Ordering::Relaxed)
	}
}

impl GatePolicy for DynamicPolicyGate {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		if self.is_rejecting() {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
}

/// Round-robin without wall-clock seeding (stable AFL coverage).
pub(crate) struct StableRoundRobin {
	counter: AtomicU64,
}

impl StableRoundRobin {
	pub fn new() -> Self {
		Self { counter: AtomicU64::new(0) }
	}
}

impl LoadBalancer for StableRoundRobin {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % candidates.len();
		Some(idx)
	}
}

/// Pins the first pick to a preferred route key so decoy failover is deterministic.
pub(crate) struct DecoyFirstBalancer {
	/// Route key the balancer prefers first so decoy failover stays deterministic.
	pub preferred: Arc<Mutex<Option<Vec<u8>>>>,
}

impl LoadBalancer for DecoyFirstBalancer {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		let Ok(preferred) = self.preferred.lock() else {
			return Some(0);
		};

		preferred
			.as_ref()
			.and_then(|key| candidates.iter().position(|candidate| candidate.instance_key == *key))
			.or(Some(0))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn decoy_first_empty_candidates_returns_none() {
		let balancer = DecoyFirstBalancer { preferred: Arc::new(Mutex::new(None)) };
		assert!(balancer.select(&[]).is_none());
	}
}
