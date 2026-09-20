//! Scaling configuration and decision types
//!
//! Types for auto-scaling servlet instances based on utilization metrics.

use core::time::Duration;

use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::Errorizable;

/// Default scale-up cooldown (30 seconds)
const DEFAULT_SCALE_UP_COOLDOWN: Duration = Duration::from_secs(30);
/// Default scale-down cooldown (60 seconds)
const DEFAULT_SCALE_DOWN_COOLDOWN: Duration = Duration::from_secs(60);

/// Why a scaling configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Errorizable)]
pub enum ScaleConfigRefusal {
	/// The instance bounds name an empty or inverted range.
	#[error("instance bounds must satisfy 1 <= min <= max")]
	InstanceBounds,
	/// The thresholds overlap, so one utilization reading both scales up
	/// and scales down.
	#[error("scale-down threshold must sit below the scale-up threshold")]
	OverlappingThresholds,
}

/// Per-servlet-type scaling configuration.
///
/// The fields are read-only because their legal combinations are not
/// independent: bounds that exclude every instance count, and thresholds
/// that overlap, describe a scaler that oscillates. [`Self::new`] is the
/// one place those pairs are checked, so a config that exists is one the
/// scaler can act on.
#[derive(Debug, Clone, Copy)]
pub struct ServletScaleConfig {
	min_instances: usize,
	max_instances: usize,
	scale_up_threshold: BasisPoints,
	scale_down_threshold: BasisPoints,
	scale_up_cooldown: Duration,
	scale_down_cooldown: Duration,
}

impl ServletScaleConfig {
	/// Scaling thresholds for one servlet type.
	///
	/// Cooldowns keep their defaults: 30 seconds after a scale-up, 60
	/// after a scale-down. Set them with [`Self::with_cooldowns`].
	///
	/// The bounds and the thresholds stay positional, unlike the cooldowns
	/// [`ScaleCooldowns`] carries: transposing either pair here is refused
	/// below, so the mistake is loud. A swapped cooldown pair is not.
	///
	/// # Errors
	///
	/// - [`ScaleConfigRefusal::InstanceBounds`] -- the bounds name an empty or inverted range.
	/// - [`ScaleConfigRefusal::OverlappingThresholds`] -- a single
	///   utilization reading would both scale up and scale down.
	pub const fn new(
		min_instances: usize,
		max_instances: usize,
		scale_up_threshold: BasisPoints,
		scale_down_threshold: BasisPoints,
	) -> Result<Self, ScaleConfigRefusal> {
		if min_instances == 0 || min_instances > max_instances {
			return Err(ScaleConfigRefusal::InstanceBounds);
		}
		if scale_down_threshold.get() >= scale_up_threshold.get() {
			return Err(ScaleConfigRefusal::OverlappingThresholds);
		}

		Ok(Self {
			min_instances,
			max_instances,
			scale_up_threshold,
			scale_down_threshold,
			scale_up_cooldown: DEFAULT_SCALE_UP_COOLDOWN,
			scale_down_cooldown: DEFAULT_SCALE_DOWN_COOLDOWN,
		})
	}

	/// Replace the cooldowns that follow each scaling action.
	///
	/// The pair is named rather than positional, because two adjacent
	/// durations a caller can swap is a swap nothing would catch.
	#[must_use]
	pub fn with_cooldowns(mut self, cooldowns: ScaleCooldowns) -> Self {
		self.scale_up_cooldown = cooldowns.after_scale_up;
		self.scale_down_cooldown = cooldowns.after_scale_down;
		self
	}

	/// Fewest instances the scaler leaves running.
	#[must_use]
	pub fn min_instances(&self) -> usize {
		self.min_instances
	}

	/// Most instances the scaler spawns.
	#[must_use]
	pub fn max_instances(&self) -> usize {
		self.max_instances
	}

	/// Utilization above which one more instance is spawned.
	#[must_use]
	pub fn scale_up_threshold(&self) -> BasisPoints {
		self.scale_up_threshold
	}

	/// Utilization below which one idle instance is stopped.
	#[must_use]
	pub fn scale_down_threshold(&self) -> BasisPoints {
		self.scale_down_threshold
	}

	/// Wait after a scale-up before the next one.
	#[must_use]
	pub fn scale_up_cooldown(&self) -> Duration {
		self.scale_up_cooldown
	}

	/// Wait after a scale-down before the next one.
	#[must_use]
	pub fn scale_down_cooldown(&self) -> Duration {
		self.scale_down_cooldown
	}
}

/// The wait after each scaling action before the next one of its kind.
///
/// The scale-down wait is normally the longer of the two, because removing
/// an instance under variable load is what thrashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleCooldowns {
	/// Wait after a scale-up before the next scale-up.
	pub after_scale_up: Duration,
	/// Wait after a scale-down before the next scale-down.
	pub after_scale_down: Duration,
}

impl Default for ScaleCooldowns {
	fn default() -> Self {
		Self {
			after_scale_up: DEFAULT_SCALE_UP_COOLDOWN,
			after_scale_down: DEFAULT_SCALE_DOWN_COOLDOWN,
		}
	}
}

impl ServletScaleConfig {
	/// The bounds and thresholds a servlet scales on when none are set.
	///
	/// Built through [`Self::new`] in a const block, so a default that
	/// stopped satisfying the pair checks would fail to compile rather
	/// than ship as a second, unchecked home for these values.
	pub const DEFAULT: Self = match Self::new(1, 10, crate::bps!(8000), crate::bps!(2000)) {
		Ok(config) => config,
		Err(_) => panic!("the default scale config must satisfy its own checks"),
	};
}

impl Default for ServletScaleConfig {
	fn default() -> Self {
		Self::DEFAULT
	}
}

/// Input message to the scaling worker
#[derive(Debug, Clone)]
pub struct ScalingMetrics {
	/// Type URN of the servlet being evaluated
	pub servlet_type: Urn<'static>,
	/// Current utilization in basis points (0-10000)
	pub utilization: BasisPoints,
	/// Current instance count
	pub current_instances: usize,
	/// Scaling configuration for this type
	pub config: ServletScaleConfig,
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

impl ScalingMetrics {
	/// Whether this reading calls for scaling up, down, or holding.
	///
	/// The decision reads nothing but these metrics, so it lives on them.
	#[must_use]
	pub fn decide(&self) -> ScalingDecision {
		let utilization = self.utilization.get();
		let up_threshold = self.config.scale_up_threshold().get();
		let down_threshold = self.config.scale_down_threshold().get();
		if utilization > up_threshold && self.current_instances < self.config.max_instances() {
			ScalingDecision::ScaleUp
		} else if utilization < down_threshold && self.current_instances > self.config.min_instances() {
			ScalingDecision::ScaleDown
		} else {
			ScalingDecision::Hold
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_inverted_instance_range_is_refused() {
		let refusal = ServletScaleConfig::new(4, 2, crate::bps!(8000), crate::bps!(2000));
		assert!(matches!(refusal, Err(ScaleConfigRefusal::InstanceBounds)));
	}

	#[test]
	fn a_floor_of_zero_instances_is_refused() {
		let refusal = ServletScaleConfig::new(0, 2, crate::bps!(8000), crate::bps!(2000));
		assert!(matches!(refusal, Err(ScaleConfigRefusal::InstanceBounds)));
	}

	#[test]
	fn overlapping_thresholds_are_refused() {
		let refusal = ServletScaleConfig::new(1, 4, crate::bps!(2000), crate::bps!(8000));
		assert!(matches!(refusal, Err(ScaleConfigRefusal::OverlappingThresholds)));
	}

	/// The refusal is `down >= up`, so equal thresholds are the boundary
	/// case: one utilization reading would both scale up and scale down.
	#[test]
	fn equal_thresholds_are_refused() {
		let refusal = ServletScaleConfig::new(1, 4, crate::bps!(5000), crate::bps!(5000));
		assert!(matches!(refusal, Err(ScaleConfigRefusal::OverlappingThresholds)));
	}

	/// The bound is `min > max`, so a range of exactly one instance is
	/// admitted: a servlet that never scales is a legal configuration.
	#[test]
	fn a_single_instance_range_is_admitted() -> Result<(), ScaleConfigRefusal> {
		let config = ServletScaleConfig::new(2, 2, crate::bps!(8000), crate::bps!(2000))?;
		assert_eq!(config.min_instances(), 2);
		assert_eq!(config.max_instances(), 2);
		Ok(())
	}

	/// Cooldowns arrive as a named pair, so the two durations cannot be
	/// swapped at the call site.
	#[test]
	fn cooldowns_land_where_they_are_named() -> Result<(), ScaleConfigRefusal> {
		let config =
			ServletScaleConfig::new(1, 4, crate::bps!(8000), crate::bps!(2000))?.with_cooldowns(ScaleCooldowns {
				after_scale_up: Duration::from_secs(5),
				after_scale_down: Duration::from_secs(90),
			});

		assert_eq!(config.scale_up_cooldown(), Duration::from_secs(5));
		assert_eq!(config.scale_down_cooldown(), Duration::from_secs(90));
		Ok(())
	}

	#[test]
	fn a_separated_pair_of_thresholds_is_admitted() -> Result<(), ScaleConfigRefusal> {
		let config = ServletScaleConfig::new(1, 4, crate::bps!(8000), crate::bps!(2000))?;
		assert_eq!(config.min_instances(), 1);
		assert_eq!(config.max_instances(), 4);
		Ok(())
	}
}
