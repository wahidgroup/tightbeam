//! Scaling configuration and decision types.
//!
//! A hive scales the instances of each servlet type on these utilization
//! metrics.

use core::time::Duration;

use crate::urn::Urn;
use crate::utils::BasisPoints;
use crate::Errorizable;

/// The default wait after a scale-up, 30 seconds.
const DEFAULT_SCALE_UP_COOLDOWN: Duration = Duration::from_secs(30);
/// The default wait after a scale-down, 60 seconds.
const DEFAULT_SCALE_DOWN_COOLDOWN: Duration = Duration::from_secs(60);

/// The reason [`ServletScaleConfig::new`] refuses a scaling configuration.
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

/// The scaling configuration of one servlet type.
///
/// The fields are read-only, because their legal values depend on each
/// other. Bounds that exclude every instance count leave the scaler no count
/// to hold, and thresholds that overlap make it oscillate. [`Self::new`]
/// checks those pairs in one place, so a config that exists is one the
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
	/// Builds the scaling configuration of one servlet type.
	///
	/// Cooldowns keep their defaults: 30 seconds after a scale-up, 60
	/// after a scale-down. Set them with [`Self::with_cooldowns`].
	///
	/// The bounds and the thresholds stay positional, because a transposed
	/// pair fails the checks below and the mistake is loud.
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
	/// [`ScaleCooldowns`] names the pair, because a swap of two positional
	/// durations passes every check.
	#[must_use]
	pub fn with_cooldowns(mut self, cooldowns: ScaleCooldowns) -> Self {
		self.scale_up_cooldown = cooldowns.after_scale_up;
		self.scale_down_cooldown = cooldowns.after_scale_down;
		self
	}

	/// The fewest instances the scaler leaves running.
	#[must_use]
	pub fn min_instances(&self) -> usize {
		self.min_instances
	}

	/// The most instances the scaler spawns.
	#[must_use]
	pub fn max_instances(&self) -> usize {
		self.max_instances
	}

	/// Whether a type that holds `current` instances admits one more, which
	/// [`Self::max_instances`] bounds.
	///
	/// The scaler and the hive's instance set both read it, so a spawn from
	/// either path stops at the same bound (CWE-770).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::hive::ServletScaleConfig;
	///
	/// let config = ServletScaleConfig::new(1, 2, tightbeam::bps!(8000), tightbeam::bps!(2000))?;
	/// assert!(config.admits_instance(1));
	/// assert!(!config.admits_instance(2));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub const fn admits_instance(&self, current: usize) -> bool {
		current < self.max_instances
	}

	/// Whether a type that holds `current` instances spares one, which
	/// [`Self::min_instances`] bounds.
	///
	/// The scaler and the hive's instance set both read it, so a stop from
	/// either path stops at the same floor.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::hive::ServletScaleConfig;
	///
	/// let config = ServletScaleConfig::new(1, 2, tightbeam::bps!(8000), tightbeam::bps!(2000))?;
	/// assert!(config.spares_instance(2));
	/// assert!(!config.spares_instance(1));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub const fn spares_instance(&self, current: usize) -> bool {
		current > self.min_instances
	}

	/// The utilization above which the scaler spawns one more instance.
	#[must_use]
	pub fn scale_up_threshold(&self) -> BasisPoints {
		self.scale_up_threshold
	}

	/// The utilization below which the scaler stops one idle instance.
	#[must_use]
	pub fn scale_down_threshold(&self) -> BasisPoints {
		self.scale_down_threshold
	}

	/// The wait after a scale-up before the next one.
	#[must_use]
	pub fn scale_up_cooldown(&self) -> Duration {
		self.scale_up_cooldown
	}

	/// The wait after a scale-down before the next one.
	#[must_use]
	pub fn scale_down_cooldown(&self) -> Duration {
		self.scale_down_cooldown
	}
}

/// The wait after each scaling action before the next one of its kind.
///
/// The scale-down wait is normally the longer of the two, because the
/// removal of an instance under variable load is what thrashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleCooldowns {
	/// The wait after a scale-up before the next scale-up.
	pub after_scale_up: Duration,
	/// The wait after a scale-down before the next scale-down.
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
	/// It holds 1 to 10 instances, spawns one more above 80% utilization, and
	/// stops an idle one below 20%.
	///
	/// It builds through [`Self::new`] in a const, so a default that fails
	/// the pair checks fails to compile, and the values have no unchecked
	/// second home.
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

/// One reading of a servlet type that the hive scaling loop decides on.
#[derive(Debug, Clone)]
pub struct ScalingMetrics {
	/// The type URN of the servlet under evaluation.
	pub servlet_type: Urn<'static>,
	/// The current utilization in basis points, from 0 to 10000.
	pub utilization: BasisPoints,
	/// The current instance count of the type.
	pub current_instances: usize,
	/// The scaling configuration of this type.
	pub config: ServletScaleConfig,
}

/// The decision [`ScalingMetrics::decide`] returns for one servlet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalingDecision {
	/// Keep the current instance count.
	Hold,
	/// Spawn one more instance.
	ScaleUp,
	/// Stop one idle instance.
	ScaleDown,
}

impl ScalingMetrics {
	/// Decides whether this reading calls for a scale-up, a scale-down, or a
	/// hold.
	///
	/// The decision reads these metrics alone, so it lives on them.
	#[must_use]
	pub fn decide(&self) -> ScalingDecision {
		let utilization = self.utilization.get();
		let up_threshold = self.config.scale_up_threshold().get();
		let down_threshold = self.config.scale_down_threshold().get();
		if utilization > up_threshold && self.config.admits_instance(self.current_instances) {
			ScalingDecision::ScaleUp
		} else if utilization < down_threshold && self.config.spares_instance(self.current_instances) {
			ScalingDecision::ScaleDown
		} else {
			ScalingDecision::Hold
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tb_cases;

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

	/// The bound is `min > max`, so a range that holds one instance count is
	/// admitted: a servlet with a fixed instance count is a legal
	/// configuration.
	#[test]
	fn a_single_instance_range_is_admitted() -> Result<(), ScaleConfigRefusal> {
		let config = ServletScaleConfig::new(2, 2, crate::bps!(8000), crate::bps!(2000))?;
		assert_eq!(config.min_instances(), 2);
		assert_eq!(config.max_instances(), 2);
		Ok(())
	}

	/// Cooldowns arrive as a named pair, so each duration lands on the
	/// cooldown that the call site names.
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

	/// A reading of `utilization` basis points over `current_instances` of a
	/// type bounded to one to two instances.
	fn reading(utilization: BasisPoints, current_instances: usize) -> ScalingMetrics {
		let servlet_type = crate::urn!("tightbeam", "servlet:echo");
		let config = ServletScaleConfig::new(1, 2, crate::bps!(8000), crate::bps!(2000));
		let config = config.expect("one to two instances is a legal range");
		ScalingMetrics { servlet_type, utilization, current_instances, config }
	}

	/// A reading's load and instance count, and the decision it calls for.
	type DecisionRow = (BasisPoints, usize, ScalingDecision);

	// A loaded type scales up below its bound and holds at it, and an idle
	// type scales down above its floor and holds at it.
	tb_cases! {
		fn a_scale_stops_at_the_instance_bounds((utilization, current, expected): DecisionRow) {
			assert_eq!(reading(utilization, current).decide(), expected);
		}
		cases {
			loaded_below_the_bound_scales_up => (crate::bps!(9000), 1, ScalingDecision::ScaleUp),
			loaded_at_the_bound_holds => (crate::bps!(9000), 2, ScalingDecision::Hold),
			idle_above_the_floor_scales_down => (crate::bps!(1000), 2, ScalingDecision::ScaleDown),
			idle_at_the_floor_holds => (crate::bps!(1000), 1, ScalingDecision::Hold),
		}
	}
}
