//! Scaling configuration and decision types
//!
//! Types for auto-scaling servlet instances based on utilization metrics.

use core::time::Duration;

use crate::utils::BasisPoints;

/// Default scale-up cooldown (30 seconds)
const DEFAULT_SCALE_UP_COOLDOWN: Duration = Duration::from_secs(30);
/// Default scale-down cooldown (60 seconds)
const DEFAULT_SCALE_DOWN_COOLDOWN: Duration = Duration::from_secs(60);

/// Per-servlet-type scaling configuration
#[derive(Debug, Clone, Copy)]
pub struct ServletScaleConf {
	/// Minimum instances to maintain (default: 1)
	pub min_instances: usize,
	/// Maximum instances allowed (default: 10)
	pub max_instances: usize,
	/// Scale-up threshold in basis points (default: 8000 = 80%)
	pub scale_up_threshold: BasisPoints,
	/// Scale-down threshold in basis points (default: 2000 = 20%)
	pub scale_down_threshold: BasisPoints,
	/// Cooldown after scale-up before next scale-up (default: 30s)
	///
	/// Prevents rapid scaling up during load spikes. After spawning
	/// an instance, this duration must elapse before another scale-up.
	pub scale_up_cooldown: Duration,
	/// Cooldown after scale-down before next scale-down (default: 60s)
	///
	/// Prevents oscillation by requiring more stable low utilization
	/// before removing additional instances. Longer than scale-up cooldown
	/// to avoid thrashing during variable load.
	pub scale_down_cooldown: Duration,
}

impl Default for ServletScaleConf {
	fn default() -> Self {
		Self {
			min_instances: 1,
			max_instances: 10,
			scale_up_threshold: BasisPoints::new(8000),
			scale_down_threshold: BasisPoints::new(2000),
			scale_up_cooldown: DEFAULT_SCALE_UP_COOLDOWN,
			scale_down_cooldown: DEFAULT_SCALE_DOWN_COOLDOWN,
		}
	}
}

/// Input message to the scaling worker
#[derive(Debug, Clone)]
pub struct ScalingMetrics {
	/// Servlet type being evaluated
	pub servlet_type: Vec<u8>,
	/// Current utilization in basis points (0-10000)
	pub utilization: BasisPoints,
	/// Current instance count
	pub current_instances: usize,
	/// Scaling configuration for this type
	pub config: ServletScaleConf,
}

/// Output decision from the scaling worker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalingDecision {
	/// No action needed
	Hold,
	/// Spawn one additional instance
	ScaleUp,
	/// Stop one idle instance
	ScaleDown,
}

impl ScalingDecision {
	/// Evaluate scaling metrics and return a decision
	///
	/// This is the core scaling logic that determines whether to scale up,
	/// scale down, or hold steady based on current utilization and bounds.
	#[must_use]
	pub fn evaluate(metrics: &ScalingMetrics) -> Self {
		let utilization = metrics.utilization.get();
		let up_threshold = metrics.config.scale_up_threshold.get();
		let down_threshold = metrics.config.scale_down_threshold.get();
		if utilization > up_threshold && metrics.current_instances < metrics.config.max_instances {
			ScalingDecision::ScaleUp
		} else if utilization < down_threshold && metrics.current_instances > metrics.config.min_instances {
			ScalingDecision::ScaleDown
		} else {
			ScalingDecision::Hold
		}
	}
}
