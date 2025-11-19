//! Configuration types for FDR refinement checking
//!
//! This module contains the core configuration structures and result types
//! used by the FDR exploration engine.

use std::collections::HashSet;

use crate::builder::TypeBuilder;
use crate::testing::error::TestingError;
use crate::testing::specs::csp::{Event, Process, State};

/// CSP trace: sequence of observable events
pub type Trace = Vec<Event>;

/// Refusal set: events refused in stable state
pub type RefusalSet = HashSet<Event>;

/// Failure: (trace, refusal_set)
pub type Failure = (Trace, RefusalSet);

/// Acceptance set: events accepted after trace
pub type AcceptanceSet = HashSet<Event>;

/// Scheduler model type
/// Panics if used when `testing-fault` feature is not enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerModel {
	/// Cooperative scheduling (yield-based)
	Cooperative,
	/// Preemptive scheduling (time-sliced)
	Preemptive,
}

/// Fault injection strategy
/// Panics if used when `testing-fault` feature is not enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionStrategy {
	/// Deterministic fault injection (seed-based)
	Deterministic,
	/// Random fault injection
	Random,
}

/// Fault type for injection
/// Panics if used when `testing-fault` feature is not enabled
#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
	/// Network packet drop
	NetworkDrop { probability: f64 },
	/// Message corruption
	MessageCorruption { probability: f64 },
	/// Node crash
	NodeCrash { probability: f64 },
}

/// Fault model configuration
/// Panics if used when `testing-fault` feature is not enabled
#[derive(Debug, Clone)]
pub struct FaultModel {
	/// List of faults to inject
	pub faults: Vec<Fault>,
	/// Injection strategy
	pub injection_strategy: InjectionStrategy,
}

/// Builder for creating `FaultModel` instances with auto-prefixed fault syntax.
///
/// Allows users to write `NetworkDrop { probability: 0.1 }` instead of
/// `Fault::NetworkDrop { probability: 0.1 }` for better ergonomics.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Default, Clone)]
pub struct FaultModelBuilder {
	faults: Vec<Fault>,
	injection_strategy: Option<InjectionStrategy>,
}

#[cfg(feature = "testing-fault")]
impl FaultModelBuilder {
	/// Add a [multiple] network drop fault (auto-prefixes `Fault::`).
	pub fn with_network_drop(mut self, probability: f64) -> Self {
		self.faults.push(Fault::NetworkDrop { probability });
		self
	}

	/// Add a [multiple] message corruption fault (auto-prefixes `Fault::`).
	pub fn with_message_corruption(mut self, probability: f64) -> Self {
		self.faults.push(Fault::MessageCorruption { probability });
		self
	}

	/// Add a [multiple] node crash fault (auto-prefixes `Fault::`).
	pub fn with_node_crash(mut self, probability: f64) -> Self {
		self.faults.push(Fault::NodeCrash { probability });
		self
	}

	/// Add a [multiple] fault directly (for advanced use cases).
	///
	/// This method allows adding a `Fault` enum variant directly if needed.
	pub fn with_fault(mut self, fault: Fault) -> Self {
		self.faults.push(fault);
		self
	}

	/// Set the injection strategy.
	pub fn with_strategy(mut self, strategy: InjectionStrategy) -> Self {
		self.injection_strategy = Some(strategy);
		self
	}
}

#[cfg(feature = "testing-fault")]
impl TypeBuilder<FaultModel> for FaultModelBuilder {
	type Error = TestingError;

	fn build(self) -> Result<FaultModel, Self::Error> {
		let injection_strategy = self.injection_strategy.unwrap_or(InjectionStrategy::Deterministic);
		Ok(FaultModel { faults: self.faults, injection_strategy })
	}
}

/// FMEA configuration (automatic analysis only)
/// Panics if used when `testing-fmea` feature is not enabled
#[derive(Debug, Clone)]
pub struct FmeaConfig {
	/// Enable automatic FMEA analysis
	pub enabled: bool,
}

/// FDR configuration for refinement checking and multi-seed exploration
///
/// Supports two modes:
/// 1. Single-process exploration: Verify properties of one process
/// 2. Refinement checking: Verify Spec ⊑ Impl (traces/failures/divergences)
#[derive(Debug, Clone)]
pub struct FdrConfig {
	/// Number of exploration seeds (different scheduling)
	pub seeds: u32,

	/// Maximum trace depth before cutoff
	pub max_depth: usize,

	/// Maximum consecutive τ-transitions before divergence detection
	pub max_internal_run: usize,

	/// Per-seed timeout in milliseconds
	pub timeout_ms: u64,

	/// Additional processes for refinement checking
	/// If provided, check: specs[0] ⊑ main_process
	pub specs: Vec<Process>,

	/// Stop refinement checking on first violation (fast-fail mode)
	/// When true (default), returns immediately after finding first counter-example
	/// When false, checks all specs and collects all violations
	pub fail_fast: bool,

	/// Expect FDR refinement to fail (for negative tests)
	/// When true, the test passes if refinement fails (proving the trace violates the spec)
	/// When false (default), the test fails if refinement fails
	pub expect_failure: bool,

	/// Number of schedulers (m) - for resource constraint modeling
	/// When m < n (process_count), some traces become impossible
	/// Optional: set to Some(_) to enable scheduler modeling, None to disable.
	/// When set, both scheduler_count and process_count must be Some(_).
	#[cfg(feature = "testing-fault")]
	pub scheduler_count: Option<u32>,

	/// Number of concurrent processes (n) - for resource constraint modeling
	/// Optional: set to Some(_) to enable scheduler modeling, None to disable.
	/// When set, both scheduler_count and process_count must be Some(_).
	#[cfg(feature = "testing-fault")]
	pub process_count: Option<u32>,

	/// Scheduler model type (Cooperative or Preemptive)
	/// Panics if set to Some(_) when `testing-fault` feature is not enabled
	pub scheduler_model: Option<SchedulerModel>,

	/// Fault injection model
	/// Panics if set to Some(_) when `testing-fault` feature is not enabled
	pub fault_model: Option<FaultModel>,

	/// FMEA analysis configuration
	/// Panics if set to Some(_) when `testing-fmea` feature is not enabled
	pub fmea: Option<FmeaConfig>,
}

impl Default for FdrConfig {
	fn default() -> Self {
		Self {
			seeds: 64,
			max_depth: 128,
			max_internal_run: 32,
			timeout_ms: 5000,
			specs: Vec::new(),
			fail_fast: true,
			expect_failure: false,
			#[cfg(feature = "testing-fault")]
			scheduler_count: None,
			#[cfg(feature = "testing-fault")]
			process_count: None,
			#[cfg(feature = "testing-fault")]
			scheduler_model: None,
			#[cfg(feature = "testing-fault")]
			fault_model: None,
			#[cfg(feature = "testing-fmea")]
			fmea: None,
		}
	}
}

impl FdrConfig {
	/// Validate scheduler model constraints with detailed error messages.
	///
	/// Checks:
	/// - scheduler_count and process_count must both be Some(_) or both be None
	/// - If set, scheduler_count must be <= process_count
	/// - If set, scheduler_count and process_count must be > 0
	///
	/// Returns `Ok(())` if validation passes, or a `TestingError` if validation fails.
	#[cfg(feature = "testing-fault")]
	pub fn validate_scheduler_model(&self) -> Result<(), TestingError> {
		match (self.scheduler_count, self.process_count) {
			(None, None) => Ok(()), // Scheduler modeling disabled - valid
			(Some(_), None) | (None, Some(_)) => Err(TestingError::InvalidFdrConfig(
				"scheduler_count and process_count must both be set or both be None. \
					Resource constraint modeling requires both values."
					.to_string(),
			)),
			(Some(scheduler_count), Some(process_count)) => {
				if scheduler_count > process_count {
					return Err(TestingError::InvalidFdrConfig(format!(
						"scheduler_count ({scheduler_count}) cannot exceed process_count ({process_count}). \
						When m > n, all processes can run simultaneously, making \
						resource constraint modeling meaningless."
					)));
				}
				if scheduler_count == 0 {
					return Err(TestingError::InvalidFdrConfig(format!(
						"scheduler_count must be > 0. Got {scheduler_count}."
					)));
				}
				if process_count == 0 {
					return Err(TestingError::InvalidFdrConfig(format!(
						"process_count must be > 0. Got {process_count}."
					)));
				}
				Ok(())
			}
		}
	}

	/// Validate all constraints (scheduler model).
	///
	/// This is a convenience method that calls `validate_scheduler_model()`.
	#[cfg(feature = "testing-fault")]
	pub fn validate(&self) -> Result<(), TestingError> {
		self.validate_scheduler_model()
	}

	/// Validate all constraints (no-op when testing-fault is not enabled).
	#[cfg(not(feature = "testing-fault"))]
	pub fn validate(&self) -> Result<(), TestingError> {
		Ok(())
	}
}

/// Validate probability is in range [0.0, 1.0] at compile time
/// Helper macro for validating probabilities (must be used in const context)
#[cfg(feature = "testing-fault")]
#[doc(hidden)]
#[macro_export]
macro_rules! __validate_probability {
	($p:expr) => {{
		// Compile-time assertion: probability must be in [0.0, 1.0]
		const _: () = assert!($p >= 0.0 && $p <= 1.0, "Probability must be in range [0.0, 1.0]");
		$p
	}};
}

/// FDR verification verdict
///
/// Captures verification results from multi-seed exploration and refinement checking:
/// - Single-process properties: determinism, deadlock, divergence
/// - Refinement checking: Spec ⊑ Impl (traces, failures, divergences)
#[derive(Debug, Clone)]
pub struct FdrVerdict {
	/// Overall pass/fail status
	pub passed: bool,

	/// Divergence freedom: no infinite τ-loops detected
	pub divergence_free: bool,

	/// Deadlock freedom: no unexpected STOP states
	pub deadlock_free: bool,

	/// Determinism: no witnesses to nondeterminism found
	pub is_deterministic: bool,

	/// Trace refinement: traces(Impl) ⊆ traces(Spec)
	/// Only meaningful when specs provided in FdrConfig
	pub trace_refines: bool,

	/// Failures refinement: failures(Impl) ⊆ failures(Spec)
	/// Only meaningful when specs provided in FdrConfig
	pub failures_refines: bool,

	/// Divergence refinement: divergences(Impl) ⊆ divergences(Spec)
	/// Only meaningful when specs provided in FdrConfig
	pub divergence_refines: bool,

	/// Witness to trace refinement violation: trace in Impl but not in Spec
	pub trace_refinement_witness: Option<Trace>,

	/// Witness to failures refinement violation: (trace, refusal) in Impl but not in Spec
	pub failures_refinement_witness: Option<Failure>,

	/// Witness to divergence refinement violation: divergent trace in Impl but not in Spec
	pub divergence_refinement_witness: Option<Trace>,

	/// Witness to nondeterminism: (seed, trace, event) where different seeds diverge
	pub determinism_witness: Option<(u64, Trace, Event)>,

	/// Witness to divergence: (seed, τ-loop sequence) if found
	pub divergence_witness: Option<(u64, Vec<Event>)>,

	/// Witness to deadlock: (seed, trace, state) if found
	pub deadlock_witness: Option<(u64, Trace, State)>,

	/// Traces explored across all seeds
	pub traces_explored: usize,

	/// Distinct states visited
	pub states_visited: usize,

	/// Number of seeds successfully completed
	pub seeds_completed: u32,

	/// Seed that caused failure, if any
	pub failing_seed: Option<u64>,
}

impl Default for FdrVerdict {
	fn default() -> Self {
		Self {
			passed: true,
			divergence_free: true,
			deadlock_free: true,
			is_deterministic: true,
			trace_refines: true,
			failures_refines: true,
			divergence_refines: true,
			trace_refinement_witness: None,
			failures_refinement_witness: None,
			divergence_refinement_witness: None,
			determinism_witness: None,
			divergence_witness: None,
			deadlock_witness: None,
			traces_explored: 0,
			states_visited: 0,
			seeds_completed: 0,
			failing_seed: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::TransitionRelation;

	#[test]
	fn default_configuration() {
		let config = FdrConfig::default();
		assert_eq!(config.seeds, 64);
		assert_eq!(config.max_depth, 128);
		assert_eq!(config.max_internal_run, 32);
		assert_eq!(config.timeout_ms, 5000);
		assert!(config.specs.is_empty());
		assert!(config.fail_fast);
	}

	#[test]
	fn dual_mode_support() {
		// Mode 1: Single-process exploration
		let config_exploration = FdrConfig::default();
		assert!(config_exploration.specs.is_empty());

		// Mode 2: Refinement checking
		let spec = Process {
			name: "Spec",
			description: Some("Test spec"),
			initial: State("S0"),
			states: vec![State("S0")].into_iter().collect(),
			observable: HashSet::new(),
			hidden: HashSet::new(),
			choice: HashSet::new(),
			terminal: vec![State("S0")].into_iter().collect(),
			transitions: TransitionRelation::new(),
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-timing")]
			timed_transitions: None,
		};

		let config_refinement = FdrConfig { specs: vec![spec], ..FdrConfig::default() };
		assert!(!config_refinement.specs.is_empty());
	}

	// Tests for FdrVerdict
	mod verdict {
		use super::*;

		#[test]
		fn default_values() {
			let verdict = FdrVerdict::default();

			assert!(verdict.passed);
			assert!(verdict.divergence_free);
			assert!(verdict.deadlock_free);
			assert!(verdict.is_deterministic);
			assert!(verdict.trace_refines);
			assert!(verdict.failures_refines);

			assert!(verdict.determinism_witness.is_none());
			assert!(verdict.divergence_witness.is_none());
			assert!(verdict.deadlock_witness.is_none());
			assert!(verdict.trace_refinement_witness.is_none());
			assert!(verdict.failures_refinement_witness.is_none());

			assert_eq!(verdict.traces_explored, 0);
			assert_eq!(verdict.states_visited, 0);
			assert_eq!(verdict.seeds_completed, 0);
			assert!(verdict.failing_seed.is_none());
		}

		#[test]
		fn refinement_witness_tracking() {
			let mut verdict = FdrVerdict::default();

			// Trace refinement violation
			let bad_trace = vec![Event("unexpected")];
			verdict.trace_refines = false;
			verdict.trace_refinement_witness = Some(bad_trace.clone());
			verdict.passed = false;
			assert!(!verdict.trace_refines);
			assert_eq!(verdict.trace_refinement_witness, Some(bad_trace));

			// Failures refinement violation
			let bad_failure_trace = vec![Event("a"), Event("b")];
			let bad_refusal: HashSet<Event> = vec![Event("c")].into_iter().collect();
			verdict.failures_refines = false;
			verdict.failures_refinement_witness = Some((bad_failure_trace.clone(), bad_refusal.clone()));
			assert!(!verdict.failures_refines);
			assert_eq!(verdict.failures_refinement_witness, Some((bad_failure_trace, bad_refusal)));
		}

		#[test]
		fn trace_refinement_structure() {
			// Spec ⊑_T Impl: traces(Impl) ⊆ traces(Spec)
			let verdict = FdrVerdict::default();
			assert!(verdict.trace_refines);
			assert!(verdict.trace_refinement_witness.is_none());
		}

		#[test]
		fn failures_refinement_structure() {
			// Spec ⊑_F Impl: failures(Impl) ⊆ failures(Spec)
			let verdict = FdrVerdict::default();
			assert!(verdict.failures_refines);
			assert!(verdict.failures_refinement_witness.is_none());
		}
	}

	// Tests for FaultModelBuilder
	#[cfg(feature = "testing-fault")]
	mod builder {
		use super::*;

		#[test]
		fn fault_model_builder_single_fault() -> Result<(), TestingError> {
			let model = FaultModelBuilder::default().with_network_drop(0.1).build()?;
			assert_eq!(model.faults.len(), 1);

			match &model.faults[0] {
				Fault::NetworkDrop { probability } => assert_eq!(probability, &0.1),
				_ => return Err(TestingError::InvalidFaultModel),
			}
			assert_eq!(model.injection_strategy, InjectionStrategy::Deterministic);
			Ok(())
		}

		#[test]
		fn fault_model_builder_multiple_faults() -> Result<(), TestingError> {
			let model = FaultModelBuilder::default()
				.with_network_drop(0.1)
				.with_message_corruption(0.05)
				.with_node_crash(0.01)
				.build()?;

			assert_eq!(model.faults.len(), 3);
			match &model.faults[0] {
				Fault::NetworkDrop { probability } => assert_eq!(probability, &0.1),
				_ => return Err(TestingError::InvalidFaultModel),
			}
			match &model.faults[1] {
				Fault::MessageCorruption { probability } => assert_eq!(probability, &0.05),
				_ => return Err(TestingError::InvalidFaultModel),
			}
			match &model.faults[2] {
				Fault::NodeCrash { probability } => assert_eq!(probability, &0.01),
				_ => return Err(TestingError::InvalidFaultModel),
			}
			Ok(())
		}

		#[test]
		fn fault_model_builder_with_strategy() -> Result<(), TestingError> {
			let model = FaultModelBuilder::default()
				.with_network_drop(0.1)
				.with_strategy(InjectionStrategy::Random)
				.build()?;
			assert_eq!(model.injection_strategy, InjectionStrategy::Random);
			Ok(())
		}

		#[test]
		fn fault_model_builder_add_fault_directly() -> Result<(), TestingError> {
			let fault = Fault::NetworkDrop { probability: 0.2 };
			let model = FaultModelBuilder::default().with_fault(fault).build()?;
			assert_eq!(model.faults.len(), 1);
			Ok(())
		}
	}

	// Tests for scheduler model validation
	#[cfg(feature = "testing-fault")]
	mod validation {
		use super::*;

		/// Helper to assert validation error is InvalidFdrConfig variant
		fn assert_validation_error(result: Result<(), TestingError>) -> Result<(), TestingError> {
			match result {
				Ok(()) => Err(TestingError::InvalidFdrConfig(String::new())),
				Err(TestingError::InvalidFdrConfig(_)) => Ok(()),
				Err(e) => Err(e),
			}
		}

		#[test]
		fn scheduler_validation_valid_config() -> Result<(), TestingError> {
			let config = FdrConfig {
				scheduler_count: Some(2),
				process_count: Some(5),
				scheduler_model: Some(SchedulerModel::Cooperative),
				..FdrConfig::default()
			};

			config.validate_scheduler_model()?;
			Ok(())
		}

		#[test]
		fn scheduler_validation_scheduler_exceeds_process_count() -> Result<(), TestingError> {
			let config = FdrConfig { scheduler_count: Some(5), process_count: Some(2), ..FdrConfig::default() };
			assert_validation_error(config.validate_scheduler_model())
		}

		#[test]
		fn scheduler_validation_zero_scheduler_count() -> Result<(), TestingError> {
			let config = FdrConfig { scheduler_count: Some(0), process_count: Some(5), ..FdrConfig::default() };
			assert_validation_error(config.validate_scheduler_model())
		}

		#[test]
		fn scheduler_validation_zero_process_count() -> Result<(), TestingError> {
			let config = FdrConfig { scheduler_count: Some(2), process_count: Some(0), ..FdrConfig::default() };
			assert_validation_error(config.validate_scheduler_model())
		}

		#[test]
		fn scheduler_validation_equal_counts() -> Result<(), TestingError> {
			let config = FdrConfig { scheduler_count: Some(3), process_count: Some(3), ..FdrConfig::default() };
			config.validate_scheduler_model()?;
			Ok(())
		}

		#[test]
		fn scheduler_validation_default_values() -> Result<(), TestingError> {
			let config = FdrConfig::default();
			config.validate_scheduler_model()?;
			Ok(())
		}

		#[test]
		fn scheduler_validation_only_scheduler_count_set() -> Result<(), TestingError> {
			let config = FdrConfig { scheduler_count: Some(2), process_count: None, ..FdrConfig::default() };
			assert_validation_error(config.validate_scheduler_model())
		}

		#[test]
		fn scheduler_validation_only_process_count_set() -> Result<(), TestingError> {
			let config = FdrConfig { scheduler_count: None, process_count: Some(5), ..FdrConfig::default() };
			assert_validation_error(config.validate_scheduler_model())
		}
	}
}
