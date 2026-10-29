//! The configuration and result types of FDR refinement checking.

use std::borrow::Cow;

#[cfg(feature = "testing-fault")]
use core::num::NonZeroU32;
#[cfg(feature = "testing-fault")]
use std::{collections::HashMap, sync::Arc};

use crate::testing::error::FdrConfigError;
use crate::testing::specs::csp::Process;

#[cfg(feature = "testing-fault")]
use crate::testing::fault::{ProcessEvent, ProcessState};
#[cfg(feature = "testing-fault")]
use crate::testing::fdr::SeededRng;
#[cfg(feature = "testing-fmea")]
use crate::testing::fmea::FmeaConfig;
#[cfg(feature = "testing-fault")]
use crate::testing::specs::csp::{Event, Observation, State};
#[cfg(feature = "testing-fault")]
use crate::{basis_points::BasisPoints, constants::DEFAULT_FAULT_SEED, error::TightBeamError};

/// The scheduling model of the processes in an FDR exploration.
///
/// A component process takes an edge when it holds one of the schedulers, or
/// when a scheduler is free and it takes one. An edge of more than one
/// component, a shared event, needs one of its components to hold or take a
/// scheduler. The model decides when a component yields its scheduler:
///
/// - A component with no edge at its state is blocked, and it yields under either model.
/// - Under `Cooperative`, a component also yields when it takes a shared
///   event, and it keeps its scheduler across every other event.
/// - Under `Preemptive`, every component yields after each event, so a
///   preemptive constraint removes no untimed trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerModel {
	/// Cooperative scheduling, where a process runs until it blocks or takes a
	/// shared event.
	Cooperative,
	/// Preemptive scheduling, where the scheduler can switch processes after
	/// each event.
	Preemptive,
}

/// The two counts of a resource-constraint model: m schedulers that run n
/// processes.
///
/// The fields are named, so a call site cannot swap the two counts.
/// [`SchedulerConstraint::new`] checks the pair.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerCounts {
	/// The number of schedulers (m).
	pub schedulers: NonZeroU32,
	/// The number of concurrent processes (n).
	pub processes: NonZeroU32,
}

/// A resource-constraint model: m schedulers that run n processes under a
/// scheduling model, with m at most n.
///
/// With m below n, some traces of the processes become impossible (Pedersen
/// and Chalmers, SBMF 2024). The fields are private, so [`Self::new`] is the
/// one construction, and every constraint holds its bound.
///
/// - A run reads the constraint as [`FdrConfig::scheduler`] states.
/// - The n processes are the component processes that the parallel
///   compositions of the process under verification number.
/// - The [`SchedulerModel`] decides when each one yields its scheduler.
///
/// # Examples
///
/// ```
/// use core::num::NonZeroU32;
///
/// use tightbeam::testing::fdr::{FdrConfig, SchedulerConstraint, SchedulerCounts, SchedulerModel};
///
/// let counts = SchedulerCounts { schedulers: NonZeroU32::MIN, processes: NonZeroU32::try_from(3)? };
/// let constraint = SchedulerConstraint::new(SchedulerModel::Cooperative, counts)?;
/// let config = FdrConfig { scheduler: Some(constraint), ..FdrConfig::default() };
///
/// let processes = config.scheduler.map(|constraint| constraint.processes().get());
/// assert_eq!(processes, Some(3));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConstraint {
	/// How the schedulers run the processes.
	model: SchedulerModel,
	/// The schedulers and the processes, with the schedulers at most the
	/// processes.
	counts: SchedulerCounts,
}

#[cfg(feature = "testing-fault")]
impl SchedulerConstraint {
	/// A constraint of `counts.schedulers` schedulers that run
	/// `counts.processes` processes under `model`.
	///
	/// # Errors
	///
	/// - [`FdrConfigError`] -- `counts.schedulers` exceeds `counts.processes`, so a scheduler has no process.
	pub fn new(model: SchedulerModel, counts: SchedulerCounts) -> Result<Self, FdrConfigError> {
		if counts.schedulers > counts.processes {
			return Err(FdrConfigError { field: "schedulers", reason: "cannot exceed processes" });
		}

		Ok(Self { model, counts })
	}

	/// How the schedulers run the processes.
	pub fn model(&self) -> SchedulerModel {
		self.model
	}

	/// The number of schedulers (m).
	pub fn schedulers(&self) -> NonZeroU32 {
		self.counts.schedulers
	}

	/// The number of concurrent processes (n).
	pub fn processes(&self) -> NonZeroU32 {
		self.counts.processes
	}
}

/// The strategy that decides when an injection point injects its fault, at
/// runtime and in FDR exploration.
///
/// - **Deterministic**: counter-based injection, so runs repeat for DO-178C and IEC 61508.
/// - **Random**: a seeded RNG for statistical coverage, where a repeated seed injects the same faults.
///
/// Each walk of FDR exploration starts the strategy again. The count of the
/// deterministic strategy starts at zero, and the generator of the random
/// strategy starts at the seed of the model XOR the exploration seed of the
/// walk.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionStrategy {
	/// Deterministic fault injection, which counts the records of each event,
	/// so its injections repeat from run to run.
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
	/// The random strategy, with its generator.
	Seeded(SeededRng),
}

#[cfg(feature = "testing-fault")]
impl StrategyDraw {
	/// Whether `injection` fires at this record of `label`.
	///
	/// - The count spreads the injections over the records of each label, so
	///   runs repeat for DO-178C and IEC 61508: 3000 bps (30%) injects on
	///   records 4, 7, and 10 of 10.
	/// - The generator draws one value per record and reads it through
	///   [`FaultInjection::should_inject`].
	///
	/// `label` stays the `Cow` the count keys on, so a static label clones as a
	/// pointer copy, as `TraceCollector::check_runtime_fault_injection` states.
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
	/// 100%), a range `BasisPoints` holds by construction.
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
	/// Injects a fault at a process state and an event, typed through the
	/// `ProcessState` and `ProcessEvent` traits.
	///
	/// The fault fires at that pair with the probability `probability_bps`, in
	/// basis points (0 to 10000, where 10000 is 100%). The traits validate the
	/// pair at compile time when the enums come from `tb_process_spec!`.
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

	/// Injects a fault at each runtime record of `event`, in every process
	/// state, with the probability `probability_bps` in basis points.
	///
	/// Once [`TraceCollector::with_fault_model`] installs the model, the
	/// collector's [`TraceCollector::event`] returns the error of `error_fn`.
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

	/// Inserts the injection point at `key`, whose error `error_fn` builds.
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
	pub(crate) fn runtime_injection<'a>(&'a self, label: &'a str) -> Option<&'a FaultInjection> {
		let key = InjectionKey::Event(Cow::Borrowed(label));
		self.injection_points.get(&key)
	}

	/// The injection point of the event `event` in the process state `state`,
	/// named `Process.State`, as [`Self::with_fault`] keys it.
	pub(crate) fn state_injection<'a>(&'a self, state: &'a str, event: &'a str) -> Option<&'a FaultInjection> {
		let key = InjectionKey::State { state: Cow::Borrowed(state), event: Cow::Borrowed(event) };
		self.injection_points.get(&key)
	}

	/// The draw state of the model's strategy at its start, with the
	/// generator of the random strategy at the model's seed.
	pub(crate) fn strategy_draw(&self) -> StrategyDraw {
		self.injection_strategy.draw(self.seed)
	}

	/// The draw state of the model's strategy at the start of the FDR walk of
	/// `walk_seed`, with the generator of the random strategy at the model's
	/// seed XOR `walk_seed`.
	///
	/// Each walk draws on its own, so the walks run in any order, and a
	/// repeated model seed repeats the injections of each walk.
	fn walk_draw(&self, walk_seed: u64) -> StrategyDraw {
		let seed = self.seed ^ walk_seed;
		self.injection_strategy.draw(seed)
	}

	/// Sets the seed of the random strategy's generator, so a run repeats at
	/// runtime and in each walk of FDR exploration.
	pub fn with_seed(mut self, seed: u64) -> Self {
		self.seed = seed;
		self
	}
}

/// The fault model of one walk of FDR exploration, beside the draw state of
/// its injection strategy.
///
/// [`Self::new`] starts the strategy for the walk, so a walk injects the same
/// faults on each run.
#[cfg(feature = "testing-fault")]
pub(crate) struct WalkFaults<'a> {
	/// The model whose state injection points [`Self::draw`] reads.
	model: &'a FaultModel,
	/// The draw state of the model's strategy in this walk.
	strategy: StrategyDraw,
}

#[cfg(feature = "testing-fault")]
impl<'a> WalkFaults<'a> {
	/// Creates the faults of `model` in the walk of `walk_seed`, with the
	/// strategy at its start.
	pub(crate) fn new(model: &'a FaultModel, walk_seed: u64) -> Self {
		let strategy = model.walk_draw(walk_seed);
		Self { model, strategy }
	}

	/// Draws the fault that the model injects at this visit of `event` in
	/// `state` of `process`, or `None`.
	///
	/// - The strategy counts the visits of each event that reach an injection
	///   point, as it counts the runtime records of an event.
	/// - A state of a scheduled process keys on the state it runs, so a point at
	///   a state of the process fires under a scheduler constraint.
	pub(crate) fn draw(&mut self, process: &Process, state: State, event: &Event) -> Option<InjectedFaultRecord> {
		// The `Process.State` lookup key costs one allocation. The Cow-keyed
		// map borrows it, so the lookup reads the fault-injection table in
		// place.
		let base = process.components.base_of(state);
		let state_key = format!("{}.{}", process.name(), base.0);
		let model = self.model;
		let injection = model.state_injection(&state_key, event.0)?;
		let label = Cow::Borrowed(event.0);
		if !self.strategy.injects(&label, injection) {
			return None;
		}

		let probability_bps = injection.probability_bps.get();
		let error = (injection.error_factory)();
		let record = InjectedFaultRecord {
			csp_state: state_key,
			event_label: event.0.to_string(),
			error_message: error.to_string(),
			probability_bps,
		};
		Some(record)
	}
}

/// The FDR configuration for refinement checking and multi-seed exploration.
///
/// It supports two modes:
/// 1. Single-process exploration: verify the properties of one process.
/// 2. Refinement checking: verify Spec ⊑ Impl (traces, failures, divergences).
#[derive(Debug, Clone)]
pub struct FdrConfig {
	/// The number of exploration seeds, each of which runs another schedule.
	pub seeds: u32,

	/// The longest trace, in observable events, that exploration and the
	/// refinement checks follow before they cut it off.
	pub max_depth: usize,

	/// The most hidden events exploration takes in one run. A longer run is a
	/// divergence, and so is a hidden run of any length that reaches a cycle of
	/// hidden events.
	pub max_internal_run: usize,

	/// The time budget, in milliseconds, of each search that the refinement
	/// checker runs: the trace, failure, and divergence searches of a process,
	/// and the search of a spec for the traces of the implementation. A search
	/// that spends it stops with an incomplete answer, and a check it cuts
	/// short decides [`Decision::Unknown`].
	///
	/// [`Decision::Unknown`]: crate::testing::fdr::Decision::Unknown
	pub timeout_ms: u64,

	/// The specification processes for refinement checking. The explorer
	/// checks spec ⊑ subject for each one.
	pub specs: Vec<Process>,

	/// Whether each refinement pass returns at its first counterexample
	/// (fast-fail mode, the default). When false, a pass checks every spec, and
	/// the verdict keeps the witness of the last violation.
	pub fail_fast: bool,

	/// The resource-constraint model of the run, m schedulers that run n
	/// processes, when the run states one.
	///
	/// The walk of each explored process and the subject of each refinement
	/// check run under it. A recorded trace ran under its own schedule, so it
	/// stays as it is. A run whose process composes other than n processes, or
	/// holds a timed transition, returns an [`FdrConfigError`].
	#[cfg(feature = "testing-fault")]
	pub scheduler: Option<SchedulerConstraint>,

	/// The fault injection model, which turns on CSP state-driven fault
	/// injection in FDR exploration.
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
			#[cfg(feature = "testing-fault")]
			scheduler: None,
			#[cfg(feature = "testing-fault")]
			fault_model: None,
			#[cfg(feature = "testing-fmea")]
			fmea_config: None,
		}
	}
}

impl FdrConfig {
	/// Whether a run of this configuration refines the subject against
	/// specs, which a configuration that names a spec does.
	pub(crate) fn refines_against_specs(&self) -> bool {
		!self.specs.is_empty()
	}

	/// The process that a walk explores, or a refinement check grades, for
	/// `process`: the process that the scheduler constraint lets it run, or
	/// `process` itself with no constraint or for a recorded trace.
	///
	/// # Errors
	///
	/// - [`FdrConfigError`] -- the constraint does not fit `process`, as
	///   `SchedulerConstraint::schedule` states.
	#[cfg(feature = "testing-fault")]
	pub(crate) fn scheduled<'p>(&self, process: &'p Process) -> Result<Cow<'p, Process>, FdrConfigError> {
		let recorded = process.observation() == Observation::RecordedTrace;
		let Some(constraint) = self.scheduler.as_ref().filter(|_| !recorded) else {
			return Ok(Cow::Borrowed(process));
		};

		let scheduled = constraint.schedule(process)?;
		Ok(Cow::Owned(scheduled))
	}

	/// The process that a walk explores, or a refinement check grades, for
	/// `process`, which is `process` itself in a build with no scheduler
	/// constraint.
	#[cfg(not(feature = "testing-fault"))]
	pub(crate) fn scheduled<'p>(&self, process: &'p Process) -> Result<Cow<'p, Process>, FdrConfigError> {
		Ok(Cow::Borrowed(process))
	}

	/// The exploration that a run of this configuration performs.
	///
	/// - A configuration with no spec explores the state space, with a fault model or without one.
	/// - Specs with a fault model run each spec under the faults.
	/// - Specs with no fault model run the refinement checks.
	pub(crate) fn mode(&self) -> ExplorationMode {
		if !self.refines_against_specs() {
			return ExplorationMode::StateSpace;
		}

		#[cfg(feature = "testing-fault")]
		if self.fault_model.is_some() {
			return ExplorationMode::UnderFaults;
		}

		ExplorationMode::Refinement
	}
}

/// The exploration that a run of an [`FdrConfig`] performs, which its specs
/// and its fault model select ([`FdrConfig::mode`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExplorationMode {
	/// Each spec runs under the faults of the fault model.
	#[cfg(feature = "testing-fault")]
	UnderFaults,
	/// The subject refines against each spec.
	Refinement,
	/// The subject runs over every seed, with no spec.
	StateSpace,
}

/// The record of a fault that FDR exploration injected.
#[cfg(feature = "testing-fault")]
#[derive(Debug, Clone, PartialEq)]
pub struct InjectedFaultRecord {
	/// The CSP state of the injection, as `Process.State`.
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
	use crate::testing::specs::csp::{Components, Observation, State, TransitionRelation};

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

		/// Looks up the injection registered under a `Process.State` key and
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

	/// A spec of one state, which is its initial state and a terminal one.
	fn one_state_spec() -> Process {
		Process {
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
			components: Components::default(),
		}
	}

	#[test]
	fn dual_mode_support() {
		// Mode 1: Single-process exploration
		let config_exploration = FdrConfig::default();
		assert!(config_exploration.specs.is_empty());

		// Mode 2: Refinement checking
		let spec = one_state_spec();

		let config_refinement = FdrConfig { specs: vec![spec], ..FdrConfig::default() };
		assert!(!config_refinement.specs.is_empty());
	}

	/// A configuration that names no spec explores the state space.
	#[test]
	fn a_config_with_no_spec_explores_the_state_space() {
		assert_eq!(FdrConfig::default().mode(), ExplorationMode::StateSpace);
	}

	/// A configuration that names a spec and no fault model runs the refinement
	/// checks.
	#[test]
	fn a_config_with_a_spec_runs_the_refinement_checks() {
		let config = FdrConfig { specs: vec![one_state_spec()], ..FdrConfig::default() };

		assert_eq!(config.mode(), ExplorationMode::Refinement);
	}

	/// A configuration that names a spec and a fault model runs each spec under
	/// the faults.
	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_config_with_a_spec_and_a_fault_model_runs_each_spec_under_faults() {
		let fault_model = Some(FaultModel::default());
		let config = FdrConfig { specs: vec![one_state_spec()], fault_model, ..FdrConfig::default() };

		assert_eq!(config.mode(), ExplorationMode::UnderFaults);
	}

	/// A fault model with no spec explores the state space, because only a
	/// spec runs under the faults.
	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_config_with_a_fault_model_and_no_spec_explores_the_state_space() {
		let config = FdrConfig { fault_model: Some(FaultModel::default()), ..FdrConfig::default() };

		assert_eq!(config.mode(), ExplorationMode::StateSpace);
	}

	#[cfg(feature = "testing-fault")]
	#[test]
	fn an_fdr_config_cannot_hold_more_schedulers_than_processes() -> Result<(), Box<dyn core::error::Error>> {
		let counts = SchedulerCounts { schedulers: NonZeroU32::try_from(3)?, processes: NonZeroU32::try_from(2)? };
		let refused = SchedulerConstraint::new(SchedulerModel::Cooperative, counts);
		assert!(matches!(refused, Err(FdrConfigError { field: "schedulers", .. })));
		Ok(())
	}
}
