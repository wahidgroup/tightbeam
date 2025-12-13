//! Scaling configuration and decision types
//!
//! Types for auto-scaling servlet instances based on utilization metrics.

use crate::utils::BasisPoints;

/// Per-servlet-type scaling configuration
#[derive(Debug, Clone)]
pub struct ServletScaleConf {
	/// Minimum instances to maintain (default: 1)
	pub min_instances: usize,
	/// Maximum instances allowed (default: 10)
	pub max_instances: usize,
	/// Scale-up threshold in basis points (default: 8000 = 80%)
	pub scale_up_threshold: BasisPoints,
	/// Scale-down threshold in basis points (default: 2000 = 20%)
	pub scale_down_threshold: BasisPoints,
}

impl Default for ServletScaleConf {
	fn default() -> Self {
		Self {
			min_instances: 1,
			max_instances: 10,
			scale_up_threshold: BasisPoints::new(8000),
			scale_down_threshold: BasisPoints::new(2000),
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
