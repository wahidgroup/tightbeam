//! Configuration types for FDR refinement checking.
//!
//! The module holds the configuration structures and the result types that
//! the FDR exploration engine uses.

#[cfg(feature = "testing-fault")]
use std::{borrow::Cow, collections::HashMap, sync::Arc};

use crate::testing::error::TestingError;
use crate::testing::specs::csp::Process;

#[cfg(feature = "testing-fault")]
use crate::testing::fault::{ProcessEvent, ProcessState};
#[cfg(feature = "testing-fault")]
use crate::testing::fdr::SeededRng;
#[cfg(feature = "testing-fmea")]
use crate::testing::fmea::FmeaConfig;
#[cfg(feature = "testing-fault")]
use crate::{constants::DEFAULT_FAULT_SEED, error::TightBeamError, testing::error::FdrConfigError, utils::BasisPoints};

/// The scheduling model of the processes in an FDR exploration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerModel {
	/// Cooperative scheduling, where each process yields.
	Cooperative,
	/// Preemptive scheduling, where the scheduler slices time.
	Preemptive,
}

/// The strategy that decides when an injection point injects its fault, at
/// runtime and in FDR exploration.
///
/// - **Deterministic**: counter-based injection, so runs repeat for DO-178C and IEC 61508.
/// - **Random**: a seeded RNG for statistical coverage, where a repeated seed injects the same faults.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionStrategy {
	/// Deterministic fault injection, which counts the records of each event,
	/// so its injections are predictable and repeat from run to run.
	Deterministic,
	/// Random fault injection from a seeded RNG, which injects by probability
	/// and repeats under the same seed.
	Random,
}

#[cfg(feature = "testing-fault")]
impl InjectionStrategy {
	/// The draw state of this strategy at its start, with the generator of
	/// the random strategy at `seed`.
	fn draw(self, seed: u64) -> StrategyDraw {
		match self {
			Self::Deterministic => StrategyDraw::Counted(HashMap::new()),
			Self::Random => StrategyDraw::Seeded(SeededRng::new(seed)),
		}
	}
}

/// The draw state of an injection strategy, which decides whether an
/// injection point injects at a record of its event.
#[cfg(feature = "testing-fault")]
#[derive(Debug)]
pub(crate) enum StrategyDraw {
	/// The deterministic strategy, with the count of the records of each
	/// label.
	Counted(HashMap<Cow<'static, str>, u32>),
	/// The random strategy, with its generator, seeded from the model as FDR
	/// exploration seeds its own.
	Seeded(SeededRng),
}

#[cfg(feature = "testing-fault")]
impl StrategyDraw {
	/// Whether `injection` fires at this record of `label`.
	///
	/// - The count spreads the injections over the records of each label, so
	///   runs repeat for DO-178C and IEC 61508: 3000 bps (30%) injects on
	///   records 4, 7, and 10 of 10.
	/// - The generator draws as FDR exploration does.
	///
	/// The label stays the `Cow` that the count keys, as the check that calls
	/// this states.
	#[allow(clippy::ptr_arg)]
	pub(crate) fn injects(&mut self, label: &Cow<'static, str>, injection: &FaultInjection) -> bool {
		let probability = u64::from(injection.probability_bps.get());
		match self {
			Self::Counted(calls) => {
				let count = calls.entry(Cow::clone(label)).or_insert(0);
				*count = count.saturating_add(1);
				u64::from(*count) * probability % 10000 < probability
			}
			Self::Seeded(rng) => injection.should_inject(rng.get_next()),
		}
	}
}

/// The place of an injection point: an event in one process state, or an
/// event in every state.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum InjectionKey<'a> {
	/// An event of FDR exploration in the state that `state` names as
	/// `Process.State`.
	State { state: Cow<'a, str>, event: Cow<'a, str> },
	/// A runtime record of an event, in every process state.
	Event(Cow<'a, str>),
}

/// The configuration of one fault injection point.
#[cfg(feature = "testing-fault")]
#[derive(Clone)]
pub(crate) struct FaultInjection {
	pub(crate) error_factory: Arc<dyn Fn() -> TightBeamError + Send + Sync>,
	/// The injection probability in basis points (0 to 10000, where 10000 is
	/// 100%), which the `BasisPoints` type validates at compile time.
	pub(crate) probability_bps: BasisPoints,
}

#[cfg(feature = "testing-fault")]
impl FaultInjection {
	/// Whether the fault fires for the draw `rng_value`, read in basis points
	/// as `rng_value` modulo 10,000.
	pub(crate) fn should_inject(&self, rng_value: u64) -> bool {
		rng_value % 10000 < u64::from(self.probability_bps.get())
	}
}

#[cfg(feature = "testing-fault")]
impl core::fmt::Debug for FaultInjection {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("FaultInjection")
			.field("probability_bps", &self.probability_bps)
			.finish_non_exhaustive()
	}
}

/// The fault model configuration, a `HashMap` of injection points for O(1)
/// lookups. Each point keys on a process state and an event, or on an event in
/// every state. The model needs the `testing-fault` feature.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::{FaultModel, InjectionStrategy};
/// use tightbeam::trace::TraceCollector;
/// use tightbeam::urn::Urn;
/// use tightbeam::TightBeamError;
///
/// const SEND: Urn<'static> = tightbeam::urn!("test", "event:example/send");
///
/// // The builders set the strategy, the seed, and each injection point.
/// let fault = || TightBeamError::ChannelClosed;
/// let model = FaultModel::from(InjectionStrategy::Random).with_seed(7);
/// let model = model.with_event_fault(SEND, fault, tightbeam::bps!(10000));
/// let trace = TraceCollector::new().with_fault_model(model);
/// assert!(matches!(trace.event(SEND), Err(TightBeamError::ChannelClosed)));
/// ```
#[cfg(feature = "testing-fault")]
#[derive(Clone)]
pub struct FaultModel {
	/// The injection points, each at its place.
	injection_points: HashMap<InjectionKey<'static>, FaultInjection>,
	/// The strategy that decides whether a point injects at a record.
	injection_strategy: InjectionStrategy,
	/// The seed of the random strategy's generator, so its injections repeat
	/// for DO-178C and IEC 61508.
	seed: u64,
}

#[cfg(feature = "testing-fault")]
impl core::fmt::Debug for FaultModel {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("FaultModel")
			.field("injection_points", &format!("{} points", self.injection_points.len()))
			.field("injection_strategy", &self.injection_strategy)
			.finish()
	}
}

#[cfg(feature = "testing-fault")]
impl Default for FaultModel {
	fn default() -> Self {
		Self {
			injection_points: HashMap::new(),
			injection_strategy: InjectionStrategy::Deterministic,
			seed: DEFAULT_FAULT_SEED,
		}
	}
}

#[cfg(feature = "testing-fault")]
impl From<InjectionStrategy> for FaultModel {
	fn from(injection_strategy: InjectionStrategy) -> Self {
		Self { injection_points: HashMap::new(), injection_strategy, seed: DEFAULT_FAULT_SEED }
	}
}

#[cfg(feature = "testing-fault")]
impl FaultModel {
	/// Inject a fault at a process state and an event, typed through the
	/// `ProcessState` and `ProcessEvent` traits.
	///
	/// The fault fires at that (process state, event) pair with the probability
	/// `probability_bps` in basis points (0 to 10000, where 10000 is 100%).
	///
	/// The traits validate the pair at compile time when the enums come from
	/// the `tb_process_spec!` macro.
	pub fn with_fault<S, E, F, Err>(self, state: S, event: E, error_fn: F, probability_bps: BasisPoints) -> Self
	where
		S: ProcessState,
		E: ProcessEvent,
		F: Fn() -> Err + Send + Sync + 'static,
		Err: Into<TightBeamError>,
	{
		let key = InjectionKey::State { state: state.full_key(), event: event.event_label() };
		self.with_point(key, error_fn, probability_bps)
	}

	/// Inject a fault at each runtime record of `event`, in every process
	/// state, with the probability `probability_bps` in basis points.
	///
	/// A collector injects the fault once [`TraceCollector::with_fault_model`]
	/// installs the model, and its [`TraceCollector::event`] then returns the
	/// error of `error_fn`.
	///
	/// [`TraceCollector::with_fault_model`]: crate::trace::TraceCollector::with_fault_model
	/// [`TraceCollector::event`]: crate::trace::TraceCollector::event
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::FaultModel;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::urn::Urn;
	/// use tightbeam::TightBeamError;
	///
	/// const SPAWN: Urn<'static> = tightbeam::urn!("test", "event:example/spawn");
	///
	/// // Every record of the event fails.
	/// let fault = || TightBeamError::MissingResponse;
	/// let model = FaultModel::default().with_event_fault(SPAWN, fault, tightbeam::bps!(10000));
	/// let trace = TraceCollector::new().with_fault_model(model);
	/// assert!(matches!(trace.event(SPAWN), Err(TightBeamError::MissingResponse)));
	/// ```
	pub fn with_event_fault<E, F, Err>(self, event: E, error_fn: F, probability_bps: BasisPoints) -> Self
	where
		E: ProcessEvent,
		F: Fn() -> Err + Send + Sync + 'static,
		Err: Into<TightBeamError>,
	{
		let key = InjectionKey::Event(event.event_label());
		self.with_point(key, error_fn, probability_bps)
	}

	/// Insert the injection point at `key`, whose error `error_fn` builds.
	fn with_point<F, Err>(mut self, key: InjectionKey<'static>, error_fn: F, probability_bps: BasisPoints) -> Self
	where
		F: Fn() -> Err + Send + Sync + 'static,
		Err: Into<TightBeamError>,
	{
		let injection = FaultInjection { error_factory: Arc::new(move || error_fn().into()), probability_bps };
		self.injection_points.insert(key, injection);
		self
	}

	/// The injection point of a runtime record of the event `label`, as
	/// [`Self::with_event_fault`] keys it.
	///
	/// The lookup key borrows `label`, so the point borrows it too.
	pub(crate) fn runtime_injection<'a>(&'a self, label: &'a str) -> Option<&'a FaultInjection> {
		let key = InjectionKey::Event(Cow::Borrowed(label));
		self.injection_points.get(&key)
	}

	/// The injection point of the event `event` in the process state `state`,
	/// named `Process.State`, as [`Self::with_fault`] keys it.
	///
	/// The lookup key borrows both names, so the point borrows them too.
	pub(crate) fn state_injection<'a>(&'a self, state: &'a str, event: &'a str) -> Option<&'a FaultInjection> {
		let key = InjectionKey::State { state: Cow::Borrowed(state), event: Cow::Borrowed(event) };
		self.injection_points.get(&key)
	}

	/// The draw state of the model's strategy at its start, with the
	/// generator of the random strategy at the model's seed.
	pub(crate) fn strategy_draw(&self) -> StrategyDraw {
		self.injection_strategy.draw(self.seed)
	}

	/// Set the seed of the random strategy's generator, so a run repeats.
	pub fn with_seed(mut self, seed: u64) -> Self {
		self.seed = seed;
		self
	}
}

/// The FDR configuration for refinement checking and multi-seed exploration.
///
/// The configuration supports two modes:
/// 1. Single-process exploration: verify the properties of one process.
/// 2. Refinement checking: verify Spec ⊑ Impl (traces, failures, divergences).
#[derive(Debug, Clone)]
pub struct FdrConfig {
	/// The number of exploration seeds, each of which runs another schedule.
	pub seeds: u32,

	/// The maximum trace depth, where exploration cuts a trace off.
	pub max_depth: usize,

	/// The maximum run of consecutive τ-transitions, past which exploration
	/// detects a divergence.
	pub max_internal_run: usize,

	/// The timeout of each seed, in milliseconds.
	pub timeout_ms: u64,

	/// The additional processes for refinement checking. When the list holds a
	/// process, exploration checks specs\[0\] ⊑ main_process.
	pub specs: Vec<Process>,

	/// Whether refinement checks stop at the first violation (fast-fail mode).
	/// When true (the default), the check returns at the first counter-example.
	/// When false, it checks every spec and collects every violation.
	pub fail_fast: bool,

	/// The number of schedulers (m), for resource constraint modeling. When m
	/// is below n (`process_count`), some traces become impossible. `Some(_)`
	/// turns scheduler modeling on, and `None` turns it off. When set, both
	/// `scheduler_count` and `process_count` must be `Some(_)`.
	#[cfg(feature = "testing-fault")]
	pub scheduler_count: Option<u32>,

	/// The number of concurrent processes (n), for resource constraint
	/// modeling. `Some(_)` turns scheduler modeling on, and `None` turns it
	/// off. When set, both `scheduler_count` and `process_count` must be
	/// `Some(_)`.
	#[cfg(feature = "testing-fault")]
	pub process_count: Option<u32>,

	/// The scheduler model, cooperative or preemptive.
	pub scheduler_model: Option<SchedulerModel>,

	/// The fault injection model. When set, it turns on CSP state-driven fault
	/// injection during FDR exploration.
	#[cfg(feature = "testing-fault")]
	pub fault_model: Option<FaultModel>,

	/// The configuration of the FMEA, the failure mode and effects analysis.
	#[cfg(feature = "testing-fmea")]
	pub fmea_config: Option<FmeaConfig>,
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
			scheduler_model: None,
			#[cfg(feature = "testing-fault")]
			scheduler_count: None,
			#[cfg(feature = "testing-fault")]
			process_count: None,
			#[cfg(feature = "testing-fault")]
			fault_model: None,
			#[cfg(feature = "testing-fmea")]
			fmea_config: None,
		}
	}
}

impl FdrConfig {
	/// Validate the constraints of the scheduler model, with a detailed error
	/// message for each.
	///
	/// It checks these rules:
	/// - `scheduler_count` and `process_count` must both be `Some(_)` or both be `None`.
	/// - When set, `scheduler_count` must not exceed `process_count`.
	/// - When set, `scheduler_count` and `process_count` must each be above 0.
	///
	/// ## Returns
	/// - `Ok(())` when every check passes.
	/// - `Err(TestingError)` when a check fails.
	#[cfg(feature = "testing-fault")]
	pub fn validate_scheduler_model(&self) -> Result<(), TestingError> {
		match (self.scheduler_count, self.process_count) {
			(None, None) => Ok(()), // Scheduler modeling is off and valid.
			(Some(_), None) | (None, Some(_)) => Err(TestingError::InvalidFdrConfig(FdrConfigError {
				field: "scheduler_count/process_count",
				reason: "both must be set or both be None for resource constraint modeling",
			})),
			(Some(scheduler_count), Some(process_count)) => {
				if scheduler_count > process_count {
					return Err(TestingError::InvalidFdrConfig(FdrConfigError {
						field: "scheduler_count",
						reason: "cannot exceed process_count (would make resource modeling meaningless)",
					}));
				}
				if scheduler_count == 0 {
					return Err(TestingError::InvalidFdrConfig(FdrConfigError {
						field: "scheduler_count",
						reason: "must be > 0",
					}));
				}
				if process_count == 0 {
					return Err(TestingError::InvalidFdrConfig(FdrConfigError {
						field: "process_count",
						reason: "must be > 0",
					}));
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

	/// Validate all constraints. Every configuration passes when the
	/// `testing-fault` feature is off.
	#[cfg(not(feature = "testing-fault"))]
	pub fn validate(&self) -> Result<(), TestingError> {
		Ok(())
	}
}

/// The record of a fault that FDR exploration injected.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, PartialEq)]
pub struct InjectedFaultRecord {
	/// The CSP state of the injection, as `process.state`.
	pub csp_state: String,
	/// The label of the event at which the fault fired.
	pub event_label: String,
	/// The message of the injected error.
	pub error_message: String,
	/// The injection probability of the point, in basis points.
	pub probability_bps: u16,
}

#[cfg(test)]
mod tests {
	use std::collections::HashSet;

	use super::*;
	use crate::testing::specs::csp::{Observation, State, TransitionRelation};

	// These unit tests cover `FaultModel`.

	#[cfg(feature = "testing-fault")]
	mod fault_model {
		use super::*;

		#[derive(Debug, Clone, Copy)]
		struct TestError;

		impl core::fmt::Display for TestError {
			fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
				write!(f, "test error")
			}
		}

		impl From<TestError> for TightBeamError {
			fn from(e: TestError) -> Self {
				TightBeamError::InjectedFault(Box::new(e))
			}
		}

		#[derive(Debug, Clone, Copy)]
		struct TestState;

		impl ProcessState for TestState {
			fn process_name(&self) -> &'static str {
				"TestProcess"
			}
			fn state_name(&self) -> &'static str {
				"TestState"
			}
		}

		#[derive(Debug, Clone, Copy)]
		struct TestEvent;

		impl ProcessEvent for TestEvent {
			fn event_label(&self) -> Cow<'static, str> {
				Cow::Borrowed("test_event")
			}
		}

		#[derive(Debug, Clone, Copy)]
		struct AnotherState;

		impl ProcessState for AnotherState {
			fn process_name(&self) -> &'static str {
				"TestProcess"
			}
			fn state_name(&self) -> &'static str {
				"AnotherState"
			}
		}

		#[derive(Debug, Clone, Copy)]
		struct AnotherEvent;

		impl ProcessEvent for AnotherEvent {
			fn event_label(&self) -> Cow<'static, str> {
				Cow::Borrowed("another_event")
			}
		}

		/// Look up the injection registered under a `Process.State` key and
		/// event label.
		fn injection<'a>(model: &'a FaultModel, state: &'static str, event: &'static str) -> &'a FaultInjection {
			model
				.state_injection(state, event)
				.expect("fault registered for the requested state and event")
		}

		#[test]
		fn default_initializes_empty() {
			let model = FaultModel::default();
			assert_eq!(model.injection_points.len(), 0);
			assert_eq!(model.injection_strategy, InjectionStrategy::Deterministic);
		}

		#[test]
		fn from_strategy_sets_strategy() {
			let model = FaultModel::from(InjectionStrategy::Random);
			assert_eq!(model.injection_strategy, InjectionStrategy::Random);
		}

		#[test]
		fn with_fault_adds_typed_injection() {
			let model = FaultModel::default().with_fault(TestState, TestEvent, || TestError, crate::bps!(5000));
			assert_eq!(model.injection_points.len(), 1);

			let injection = injection(&model, "TestProcess.TestState", "test_event");
			assert_eq!(injection.probability_bps, crate::bps!(5000));
		}

		#[test]
		fn with_fault_io_error() {
			let model = FaultModel::default().with_fault(
				TestState,
				TestEvent,
				|| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test"),
				crate::bps!(100),
			);

			let error = (injection(&model, "TestProcess.TestState", "test_event").error_factory)();
			assert!(matches!(error, TightBeamError::IoError(_)));
		}

		#[test]
		fn hashmap_provides_o1_lookup() {
			let model = FaultModel::default()
				.with_fault(TestState, TestEvent, || TestError, crate::bps!(1000))
				.with_fault(TestState, AnotherEvent, || TestError, crate::bps!(2000))
				.with_fault(AnotherState, TestEvent, || TestError, crate::bps!(3000));
			assert_eq!(model.injection_points.len(), 3);

			assert_eq!(
				injection(&model, "TestProcess.TestState", "test_event").probability_bps,
				crate::bps!(1000)
			);
			assert_eq!(
				injection(&model, "TestProcess.TestState", "another_event").probability_bps,
				crate::bps!(2000)
			);
			assert_eq!(
				injection(&model, "TestProcess.AnotherState", "test_event").probability_bps,
				crate::bps!(3000)
			);
		}

		#[test]
		fn should_inject_probability_0_percent() {
			let model = FaultModel::default().with_fault(TestState, TestEvent, || TestError, crate::bps!(0));
			let injection = injection(&model, "TestProcess.TestState", "test_event");
			assert!(!injection.should_inject(0));
			assert!(!injection.should_inject(9999));
		}

		#[test]
		fn should_inject_probability_100_percent() {
			let model = FaultModel::default().with_fault(TestState, TestEvent, || TestError, crate::bps!(10000));
			let injection = injection(&model, "TestProcess.TestState", "test_event");
			assert!(injection.should_inject(0));
			assert!(injection.should_inject(9999));
		}

		#[test]
		fn should_inject_probability_50_percent() {
			let model = FaultModel::default().with_fault(TestState, TestEvent, || TestError, crate::bps!(5000));
			let injection = injection(&model, "TestProcess.TestState", "test_event");
			assert!(injection.should_inject(0));
			assert!(injection.should_inject(4999));
			assert!(!injection.should_inject(5000));
			assert!(!injection.should_inject(9999));
		}

		#[test]
		fn clone_preserves_injection_points() {
			let model1 = FaultModel::default().with_fault(TestState, TestEvent, || TestError, crate::bps!(5000));
			let model2 = model1.clone();
			assert_eq!(model2.injection_points.len(), 1);
			assert_eq!(model2.injection_strategy, InjectionStrategy::Deterministic);
		}
	}

	// These tests cover `FdrConfig`.

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
			observation: Observation::Model,
			requires_progress: true,
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
			#[cfg(feature = "testing-schedulability")]
			schedulability_periods: None,
		};

		let config_refinement = FdrConfig { specs: vec![spec], ..FdrConfig::default() };
		assert!(!config_refinement.specs.is_empty());
	}
}
