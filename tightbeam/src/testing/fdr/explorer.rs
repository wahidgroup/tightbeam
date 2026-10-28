//! The traits of the FDR explorer and the types that they exchange.
//!
//! Each trait is one subsystem, which an outside crate can replace:
//! - [`ExplorationCore`] explores the seeds of a process and keeps their results.
//! - [`RefinementChecker`] runs the trace, failures, and divergence refinement checks.
//! - [`MemoizationCache`] keeps the computed sets of a process for the refinement checker.

use core::ops::Range;
use std::collections::HashSet;

#[cfg(feature = "testing-timing")]
use core::time::Duration;
#[cfg(feature = "testing-timing")]
use std::collections::HashMap;

use super::config::FdrConfig;
use super::verdict::{Failure, Trace};
use crate::testing::specs::csp::{Event, Process, SearchStructure, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::InjectedFaultRecord;

/// The exploration engine of the FDR explorer.
///
/// An engine traverses the state space of its process one seed at a time,
/// finds the deadlocks and divergences that each seed reaches, and keeps the
/// results.
pub trait ExplorationCore {
	/// The engine that [`Self::for_process`] builds for a process that lives
	/// for `'p`.
	type ForProcess<'p>: ExplorationCore;

	/// The engine of `process` under the configuration of this engine, before
	/// its first seed.
	///
	/// [`FdrExplorer`](super::FdrExplorer) runs each spec of a fault run on
	/// the engine `for_process` builds, so every exploration of a run goes
	/// through the kind of engine that the explorer holds.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let subject = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	/// let spec = Process::builder("Idle").initial_state(State("I0")).add_terminal(State("I0")).build()?;
	///
	/// let engine = DefaultExplorationEngine::new(&subject, Arc::new(FdrConfig::default()));
	/// let mut spec_engine = engine.for_process(&spec);
	/// spec_engine.explore_seeds(0..1);
	/// assert_eq!(spec_engine.visited_states().len(), 1);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn for_process<'p>(&self, process: &'p Process) -> Self::ForProcess<'p>;

	/// The process under exploration.
	fn process(&self) -> &Process;

	/// The FDR configuration of the exploration.
	fn config(&self) -> &FdrConfig;

	/// Explores the schedule of `seed` and returns its result.
	fn explore_seed(&mut self, seed: u64) -> SeedResult;

	/// Explores the schedule of each seed in `seeds`, records each result, and
	/// returns each seed with its result, in the order of the seeds.
	///
	/// - The explorer runs every seed of a process through it and reads the results it returns.
	/// - The default calls [`Self::explore_seed`], then [`Self::add_seed_result`], once per seed.
	/// - The results it returns are the last entries of [`Self::seed_results`].
	/// - [`DefaultExplorationEngine`](super::DefaultExplorationEngine)
	///   overrides it to run the seeds in parallel in a build with `rayon`.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let mut engine = DefaultExplorationEngine::new(&process, Arc::new(FdrConfig::default()));
	/// let results = engine.explore_seeds(0..4);
	/// let seeds: Vec<u64> = results.iter().map(|(seed, _result)| *seed).collect();
	/// assert_eq!(seeds, [0, 1, 2, 3]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn explore_seeds(&mut self, seeds: Range<u64>) -> &[(u64, SeedResult)] {
		let start = self.seed_results().len();
		for seed in seeds {
			let result = self.explore_seed(seed);
			self.add_seed_result(seed, result);
		}

		let recorded = self.seed_results();
		recorded.get(start..).unwrap_or_default()
	}

	/// The traces that the recorded seeds explored.
	fn traces(&self) -> Vec<Trace>;

	/// The states that exploration visited.
	///
	/// When `FdrExplorer` explores its subject, it counts this set as
	/// `FdrVerdict::states_visited`, and the exploration events of
	/// `FdrExplorer::explore_into` cover each of its states.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let mut engine = DefaultExplorationEngine::new(&process, Arc::new(FdrConfig::default()));
	/// engine.explore_seeds(0..1);
	/// assert_eq!(engine.visited_states().len(), 2);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn visited_states(&self) -> &HashSet<State>;

	/// The number of seed results that the engine holds, the length of
	/// [`Self::seed_results`], up to [`u32::MAX`].
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let mut engine = DefaultExplorationEngine::new(&process, Arc::new(FdrConfig::default()));
	/// engine.explore_seeds(0..3);
	/// assert_eq!(engine.seeds_completed(), 3);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn seeds_completed(&self) -> u32 {
		let held = self.seed_results().len();
		u32::try_from(held).unwrap_or(u32::MAX)
	}

	/// Records `result`, the result of `seed`, as the last entry of
	/// [`Self::seed_results`].
	fn add_seed_result(&mut self, seed: u64, result: SeedResult);

	/// Each seed with the result the engine recorded for it, in record order.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let mut engine = DefaultExplorationEngine::new(&process, Arc::new(FdrConfig::default()));
	/// engine.explore_seeds(0..2);
	/// engine.explore_seeds(2..3);
	/// let seeds: Vec<u64> = engine.seed_results().iter().map(|(seed, _result)| *seed).collect();
	/// assert_eq!(seeds, [0, 1, 2]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn seed_results(&self) -> &[(u64, SeedResult)];

	/// The number of exploration branches that timed exploration dropped for a
	/// failed WCET, deadline, or path WCET constraint.
	fn timing_pruned(&self) -> usize {
		0
	}

	/// The refusal set that a failure of `process` records at `state`, or
	/// `None` at an unstable state.
	///
	/// The default reads [`Process::failure_refusals`], the one home of the
	/// rule. The walk of
	/// [`DefaultExplorationEngine`](super::DefaultExplorationEngine) records
	/// each failure of a seed through it.
	///
	/// # Examples
	///
	/// ```
	/// use std::collections::HashSet;
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let engine = DefaultExplorationEngine::new(&process, Arc::new(FdrConfig::default()));
	/// let refused = engine.compute_refusals(&process, State("S1"));
	/// assert_eq!(refused, Some(HashSet::from([Event("send")])));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn compute_refusals(&self, process: &Process, state: State) -> Option<HashSet<Event>> {
		process.failure_refusals(state)
	}
}

/// The outcome of one refinement check.
#[derive(Debug, Clone, PartialEq)]
pub enum RefinementOutcome<W> {
	/// Refinement holds for everything the check explored. When `complete` is
	/// false, the claim holds only within the bounds.
	Holds {
		/// Whether the check computed each of its sets in full, before a
		/// timeout or a resource limit.
		complete: bool,
	},
	/// Refinement fails, and the witness is the trace or failure at fault.
	Violated(W),
	/// A timeout or a resource limit stopped the check before it decided the
	/// relation.
	Inconclusive,
}

/// The refinement checker of the FDR explorer.
///
/// A checker runs the three refinement checks:
/// - Trace refinement: traces(Impl) ⊆ traces(Spec)
/// - Failures refinement: failures(Impl) ⊆ failures(Spec)
/// - Divergence refinement: divergences(Impl) ⊆ divergences(Spec)
pub trait RefinementChecker {
	/// The most traces that one trace computation holds before it stops
	/// early, which bounds the exponential trace set of a large spec.
	const MAX_TRACES: usize = 5000;

	/// The largest breadth-first queue that a search holds before it stops
	/// early, which bounds its memory on a large state space.
	const MAX_QUEUE_SIZE: usize = 10000;

	/// The most visited states that a search holds before it stops early,
	/// which bounds its memory use.
	const MAX_VISITED: usize = 20000;

	/// Checks trace refinement, traces(impl_process) ⊆ traces(spec).
	fn check_trace_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace>;

	/// Checks failures refinement, failures(impl_process) ⊆ failures(spec).
	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Failure>;

	/// Checks divergence refinement, divergences(impl_process) ⊆
	/// divergences(spec).
	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace>;

	/// Computes every trace of `process` up to `max_depth`.
	///
	/// The `bool` is true when the trace set is complete up to `max_depth`,
	/// and false when a timeout or a resource limit cut the search short.
	fn compute_traces(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool);

	/// Computes every failure of `process` up to `max_depth`.
	///
	/// The `bool` is true when the failure set is complete up to
	/// `max_depth`, and false when a timeout or a resource limit cut the
	/// search short.
	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> (Vec<Failure>, bool);

	/// Computes each trace of `process`, up to `max_depth` events, after which
	/// a state that the process reaches can diverge.
	///
	/// The `bool` is true when the set is complete up to `max_depth`, and false
	/// when a timeout or a resource limit cut the search short.
	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool);

	/// The refusal set that a failure of `process` records at `state`, or
	/// `None` at an unstable state.
	///
	/// The default reads [`Process::failure_refusals`], the one home of the
	/// rule, so an outside checker applies the same rule as the house checker.
	///
	/// # Examples
	///
	/// ```
	/// use std::cell::RefCell;
	/// use std::collections::HashSet;
	/// use std::rc::Rc;
	/// use std::sync::Arc;
	///
	/// use tightbeam::testing::fdr::{DefaultCache, DefaultRefinementChecker, FdrConfig, RefinementChecker};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_observable(Event("stop"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let cache = Rc::new(RefCell::new(DefaultCache::new()));
	/// let checker = DefaultRefinementChecker::new(&process, Arc::new(FdrConfig::default()), cache);
	/// let refused = checker.compute_refusals(&process, State("S0"));
	/// assert_eq!(refused, Some(HashSet::from([Event("stop")])));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn compute_refusals(&self, process: &Process, state: State) -> Option<HashSet<Event>> {
		process.failure_refusals(state)
	}
}

/// A memoization cache of the trace, failure, and divergence sets.
///
/// The refinement checker computes each set of a process once per depth bound
/// and reads it from the cache for each later check. Each entry keys on a
/// [`CacheKey`], the structure of a process and the depth bound of its search.
pub trait MemoizationCache {
	/// The cached traces under `key`, and whether the set is complete, or
	/// `None` when the cache holds none.
	fn get_cached_traces(&self, key: &CacheKey) -> Option<(Vec<Trace>, bool)>;

	/// Stores the traces under `key`, and whether the set is `complete`.
	fn cache_traces(&mut self, key: CacheKey, traces: impl IntoIterator<Item = Trace>, complete: bool);

	/// The cached failures under `key`, and whether the set is complete, or
	/// `None` when the cache holds none.
	fn get_cached_failures(&self, key: &CacheKey) -> Option<(Vec<Failure>, bool)>;

	/// Stores the failures under `key`, and whether the set is `complete`.
	fn cache_failures(&mut self, key: CacheKey, failures: impl IntoIterator<Item = Failure>, complete: bool);

	/// The cached divergences under `key`, and whether the set is complete, or
	/// `None` when the cache holds none.
	fn get_cached_divergences(&self, key: &CacheKey) -> Option<(Vec<Trace>, bool)>;

	/// Stores the divergences under `key`, and whether the set is `complete`.
	fn cache_divergences(&mut self, key: CacheKey, divergences: impl IntoIterator<Item = Trace>, complete: bool);
}

/// The key of one memoized set: the structure of a process and the depth
/// bound, in observable events, of the search that computed the set.
///
/// - The structure is the initial state and, each in sorted order, the
///   states, the accepting states, the choice points, the two alphabets, and
///   the transitions.
/// - Two keys are equal only when both parts are equal, so a set of one depth
///   never answers a search at another, and a hash collision never serves the
///   set of another process.
/// - The name stays out of the key, because the algebra operators (`hide`,
///   `rename`) give one name to processes of different structure.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::fdr::CacheKey;
/// use tightbeam::testing::specs::csp::{Event, Process, State};
///
/// let process = Process::builder("Send")
///     .initial_state(State("S0"))
///     .add_observable(Event("send"))
///     .add_transition(State("S0"), Event("send"), State("S1"))
///     .add_terminal(State("S1"))
///     .build()?;
///
/// assert_eq!(CacheKey::new(&process, 8), CacheKey::new(&process, 8));
/// assert_ne!(CacheKey::new(&process, 8), CacheKey::new(&process, 16));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
	/// The structure of the process that the search read.
	structure: SearchStructure,
	/// The depth bound of the search.
	max_depth: usize,
}

impl CacheKey {
	/// The key of a set of `process` that a search to `max_depth` observable
	/// events computes.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::CacheKey;
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let named = |name| {
	///     Process::builder(name)
	///         .initial_state(State("S0"))
	///         .add_observable(Event("send"))
	///         .add_transition(State("S0"), Event("send"), State("S1"))
	///         .add_terminal(State("S1"))
	///         .build()
	/// };
	///
	/// assert_eq!(CacheKey::new(&named("Send")?, 8), CacheKey::new(&named("Post")?, 8));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new(process: &Process, max_depth: usize) -> Self {
		let structure = process.search_structure();
		Self { structure, max_depth }
	}
}

/// The result of one seed of exploration.
///
/// With `testing-fault`, every variant carries the records of the faults that
/// the seed injected, so the recovery counters can attribute a failure to a
/// fault, as `FdrVerdict::error_recovery_failed` states.
#[derive(Debug, Clone)]
pub enum SeedResult {
	/// The seed explored to its end, with its longest trace, the failures it
	/// collected, and the faults it injected.
	#[cfg(feature = "testing-fault")]
	Success(Trace, Vec<Failure>, Vec<InjectedFaultRecord>),
	/// The seed explored to its end, with its longest trace and the failures
	/// it collected.
	#[cfg(not(feature = "testing-fault"))]
	Success(Trace, Vec<Failure>),
	/// The seed diverged at a state, with the trace that reached the state,
	/// the state, the hidden events of the run that diverges from it, and the
	/// faults the seed injected.
	#[cfg(feature = "testing-fault")]
	Divergence(Trace, State, Vec<Event>, Vec<InjectedFaultRecord>),
	/// The seed diverged at a state, with the trace that reached the state,
	/// the state, and the hidden events of the run that diverges from it.
	#[cfg(not(feature = "testing-fault"))]
	Divergence(Trace, State, Vec<Event>),
	/// The seed deadlocked, an unexpected STOP, with the trace that reached the
	/// state, the state, and the faults the seed injected.
	#[cfg(feature = "testing-fault")]
	Deadlock(Trace, State, Vec<InjectedFaultRecord>),
	/// The seed deadlocked, an unexpected STOP, with the trace that reached the
	/// state and the state.
	#[cfg(not(feature = "testing-fault"))]
	Deadlock(Trace, State),
}

impl SeedResult {
	/// The state where this seed diverged, paired with the hidden events of the
	/// run that diverges from it.
	pub(crate) fn divergence(&self) -> Option<(State, &[Event])> {
		match self {
			#[cfg(feature = "testing-fault")]
			Self::Divergence(_trace, state, run, _faults) => Some((*state, run)),
			#[cfg(not(feature = "testing-fault"))]
			Self::Divergence(_trace, state, run) => Some((*state, run)),
			_ => None,
		}
	}

	/// Whether this seed ran to its end with neither a divergence nor a
	/// deadlock.
	#[cfg(feature = "testing-fault")]
	pub(crate) fn succeeded(&self) -> bool {
		matches!(self, Self::Success(..))
	}
}

/// The state of one branch of a seed's exploration, which the seed's queue
/// holds.
///
/// Its fields are private, so the record methods keep `internal_run` within
/// the hidden events of the branch, and the readers lend each part.
#[derive(Debug, Clone)]
pub struct ExplorationState {
	/// The process state that the branch reached.
	process_state: State,

	/// The observable events of the branch so far.
	trace: Trace,

	/// The length of the current run of hidden (τ) events, which an observable
	/// event resets.
	internal_run: usize,

	/// Every state that the branch passed through, from the initial state.
	state_path: Vec<State>,

	/// Every hidden event that the branch took, across its runs.
	hidden_events: Vec<Event>,

	/// The elapsed time of the branch, the sum of the worst-case execution
	/// time (WCET) of each observable event.
	#[cfg(feature = "testing-timing")]
	elapsed_time: Duration,

	/// Each observable event of the branch, with the elapsed time after it.
	#[cfg(feature = "testing-timing")]
	event_times: Vec<(Event, Duration)>,

	/// The value of each clock of timed CSP, by clock name.
	#[cfg(feature = "testing-timing")]
	clock_values: HashMap<String, Duration>,
}

impl ExplorationState {
	/// The exploration state at the start of a seed, at `process_state`.
	pub fn initial(process_state: State) -> Self {
		Self {
			process_state,
			trace: Vec::new(),
			internal_run: 0,
			state_path: vec![process_state],
			hidden_events: Vec::new(),
			#[cfg(feature = "testing-timing")]
			elapsed_time: Duration::ZERO,
			#[cfg(feature = "testing-timing")]
			event_times: Vec::new(),
			#[cfg(feature = "testing-timing")]
			clock_values: HashMap::new(),
		}
	}

	/// A copy of this state for a new branch.
	pub fn branch(&self) -> Self {
		self.clone()
	}

	/// The process state that the branch reached.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert_eq!(branch.process_state(), State("S2"));
	/// ```
	pub fn process_state(&self) -> State {
		self.process_state
	}

	/// The observable events of the branch so far.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert_eq!(branch.trace(), [Event("send")]);
	/// ```
	pub fn trace(&self) -> &[Event] {
		&self.trace
	}

	/// Every state that the branch passed through, from the initial state.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert_eq!(branch.state_path(), [State("S0"), State("S1"), State("S2")]);
	/// ```
	pub fn state_path(&self) -> &[State] {
		&self.state_path
	}

	/// Every hidden event that the branch took, across its runs.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert_eq!(branch.hidden_events(), [Event("tau")]);
	/// ```
	pub fn hidden_events(&self) -> &[Event] {
		&self.hidden_events
	}

	/// The elapsed time of the branch, the sum of the worst-case execution
	/// time (WCET) of each observable event.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert_eq!(branch.elapsed_time(), core::time::Duration::ZERO);
	/// ```
	#[cfg(feature = "testing-timing")]
	pub fn elapsed_time(&self) -> Duration {
		self.elapsed_time
	}

	/// Each observable event of the branch, with the elapsed time after it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert!(branch.event_times().is_empty());
	/// ```
	#[cfg(feature = "testing-timing")]
	pub fn event_times(&self) -> &[(Event, Duration)] {
		&self.event_times
	}

	/// The value of each clock of timed CSP, by clock name.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::ExplorationState;
	/// use tightbeam::testing::specs::csp::{Event, State};
	///
	/// let mut branch = ExplorationState::initial(State("S0"));
	/// branch.record_hidden(Event("tau"), State("S1"));
	/// branch.record_observable(Event("send"), State("S2"));
	///
	/// assert!(branch.clock_values().is_empty());
	/// ```
	#[cfg(feature = "testing-timing")]
	pub fn clock_values(&self) -> &HashMap<String, Duration> {
		&self.clock_values
	}

	/// Takes the observable `event` to `next_state`, which ends the current
	/// run of hidden events.
	pub fn record_observable(&mut self, event: Event, next_state: State) {
		self.trace.push(event);
		self.process_state = next_state;
		self.state_path.push(next_state);
		self.internal_run = 0;
		#[cfg(feature = "testing-timing")]
		{
			// The caller adds the WCET of the event through `update_timing`.
		}
	}

	/// Takes the hidden (τ) `event` to `next_state`, which extends the current
	/// run of hidden events.
	pub fn record_hidden(&mut self, event: Event, next_state: State) {
		self.hidden_events.push(event);
		self.process_state = next_state;
		self.state_path.push(next_state);
		self.internal_run += 1;
		#[cfg(feature = "testing-timing")]
		{
			// A hidden event takes zero time, so the timing stays as it is.
		}
	}

	/// The hidden events of the current run, which the last observable event
	/// started. A divergence past `max_internal_run` reports this run.
	pub fn current_run(&self) -> &[Event] {
		let start = self.hidden_events.len().saturating_sub(self.internal_run);
		self.hidden_events.get(start..).unwrap_or_default()
	}

	/// Adds `wcet`, the WCET of the observable `event`, to the elapsed time,
	/// and records the event at the new elapsed time.
	#[cfg(feature = "testing-timing")]
	pub fn update_timing(&mut self, event: &Event, wcet: Duration) {
		self.elapsed_time += wcet;
		self.event_times.push((*event, self.elapsed_time));
	}

	/// Advances every clock by `elapsed`, up to the largest duration.
	#[cfg(feature = "testing-timing")]
	pub fn update_clocks(&mut self, elapsed: Duration) {
		for clock_value in self.clock_values.values_mut() {
			*clock_value = clock_value.saturating_add(elapsed);
		}
	}

	/// Sets each clock in `clock_names` to zero.
	#[cfg(feature = "testing-timing")]
	pub fn reset_clocks(&mut self, clock_names: impl AsRef<[String]>) {
		let clock_names = clock_names.as_ref();
		for name in clock_names {
			self.clock_values.insert(name.clone(), Duration::ZERO);
		}
	}
}

/// A seeded random number generator, which makes the choices of one seed, so
/// each seed repeats its schedule.
#[derive(Debug, Clone)]
pub struct SeededRng {
	state: u64,
}

impl SeededRng {
	/// A generator that starts from `seed`.
	pub fn new(seed: u64) -> Self {
		Self { state: seed.wrapping_add(1) }
	}

	/// The next pseudo-random number of the linear congruential generator.
	pub fn get_next(&mut self) -> u64 {
		// The multiplier and the increment are Knuth's MMIX LCG constants, and
		// `crate::constants` cites Numerical Recipes § 7.1.4 for them.
		self.state = self
			.state
			.wrapping_mul(crate::constants::LCG_MULTIPLIER)
			.wrapping_add(crate::constants::LCG_INCREMENT);
		self.state
	}

	/// An item of `items` that the next draw picks, or `None` when `items` is
	/// empty.
	///
	/// The pick reads the high 32 bits of the draw. The low bits of an LCG
	/// with a power-of-two modulus repeat with a short period, and the lowest
	/// bit alternates, so a pick from the low bits alternates between two
	/// items whatever the seed.
	///
	/// # Sources
	///
	/// - Knuth, *The Art of Computer Programming*, Vol. 2 (3rd Ed., 1997), § 3.2.1.1 "Choice of modulus"
	pub fn choose<'a, T>(&mut self, items: &'a (impl AsRef<[T]> + ?Sized)) -> Option<&'a T> {
		let items = items.as_ref();
		if items.is_empty() {
			None
		} else {
			let high_bits = self.get_next() >> 32;
			let index = usize::try_from(high_bits).ok()?.checked_rem(items.len())?;
			items.get(index)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// These tests cover `SeededRng`.
	mod seeded_rng {
		use super::*;

		#[test]
		fn deterministic_sequences() {
			let mut rng1 = SeededRng::new(42);
			let mut rng2 = SeededRng::new(42);

			let first: Vec<_> = (0..10).map(|_| rng1.get_next()).collect();
			let second: Vec<_> = (0..10).map(|_| rng2.get_next()).collect();
			assert_eq!(first, second);
		}

		#[test]
		fn different_seeds_produce_different_sequences() {
			let mut rng1 = SeededRng::new(42);
			let mut rng2 = SeededRng::new(43);

			let same_count = (0..10).filter(|_| rng1.get_next() == rng2.get_next()).count();
			assert!(same_count < 10, "All values should not be identical");
		}

		#[test]
		fn choose_from_items() {
			let mut rng = SeededRng::new(42);
			let items = vec![1, 2, 3, 4, 5];

			assert!(rng.choose(&items).is_some());
			assert!(rng.choose(&Vec::<i32>::new()).is_none());
		}

		#[test]
		fn a_two_way_choice_can_pick_one_item_twice() -> Result<(), Box<dyn core::error::Error>> {
			let mut rng = SeededRng::new(7);
			let sides = [0, 1];

			let first = rng.choose(&sides);
			let second = rng.choose(&sides);

			assert_eq!(first, second, "the high bits of seed 7 pick one side twice");
			Ok(())
		}
	}

	// These tests cover `ExplorationState`.
	mod exploration_state {
		use super::*;
		use crate::testing::specs::csp::{Event, State};

		#[test]
		fn initial_state() {
			let state = State("Start");
			let exp_state = ExplorationState::initial(state);
			assert_eq!(exp_state.process_state, state);
			assert!(exp_state.trace.is_empty());
			assert_eq!(exp_state.internal_run, 0);
			assert_eq!(exp_state.state_path.len(), 1);
			assert!(exp_state.hidden_events.is_empty());
		}

		#[test]
		fn record_observable_event() {
			let (state1, state2) = (State("S1"), State("S2"));
			let event = Event("evt");

			let mut exp_state = ExplorationState::initial(state1);
			exp_state.record_observable(event, state2);
			assert_eq!(exp_state.process_state, state2);
			assert_eq!(exp_state.trace, vec![event]);
			assert_eq!(exp_state.internal_run, 0); // An observable event ends the run.
			assert_eq!(exp_state.state_path.len(), 2);
		}

		#[test]
		fn record_hidden_event() {
			let (state1, state2) = (State("S1"), State("S2"));
			let event = Event("tau");

			let mut exp_state = ExplorationState::initial(state1);
			exp_state.record_hidden(event, state2);
			assert_eq!(exp_state.process_state, state2);
			assert!(exp_state.trace.is_empty()); // The trace holds observable events alone.
			assert_eq!(exp_state.internal_run, 1); // The hidden event extends the run.
			assert_eq!(exp_state.hidden_events, vec![event]);
			assert_eq!(exp_state.state_path.len(), 2);
		}

		#[test]
		fn an_observable_event_starts_a_new_hidden_run() {
			let (state1, state2) = (State("S1"), State("S2"));
			let (tau, evt, tick) = (Event("tau"), Event("evt"), Event("tick"));

			let mut exp_state = ExplorationState::initial(state1);
			exp_state.record_hidden(tau, state2);
			exp_state.record_observable(evt, state1);
			exp_state.record_hidden(tick, state2);

			assert_eq!(exp_state.current_run(), [tick]);
			assert_eq!(exp_state.hidden_events, vec![tau, tick]);
		}

		#[test]
		fn divergence_detection_via_internal_run_counter() {
			let state = State("S1");
			let tau = Event("tau");
			let mut exp_state = ExplorationState::initial(state);

			// A τ-loop takes the same hidden event 35 times, past the default
			// `max_internal_run` of 32.
			for _ in 0..35 {
				exp_state.record_hidden(tau, state);
			}

			assert!(exp_state.internal_run > 32);
			assert_eq!(exp_state.hidden_events.len(), 35);
			assert!(exp_state.trace.is_empty()); // The observable trace stays empty.
		}

		#[cfg(feature = "testing-timing")]
		#[test]
		fn update_timing() {
			let state = State("S1");
			let event = Event("evt");
			let mut exp_state = ExplorationState::initial(state);

			exp_state.record_observable(event, state);
			exp_state.update_timing(&event, Duration::from_millis(10));
			assert_eq!(exp_state.elapsed_time, Duration::from_millis(10));
			assert_eq!(exp_state.event_times.len(), 1);
			assert_eq!(exp_state.event_times[0].0, event);
			assert_eq!(exp_state.event_times[0].1, Duration::from_millis(10));

			// A second event adds its WCET to the elapsed time of the first.
			let event2 = Event("evt2");
			exp_state.record_observable(event2, state);
			exp_state.update_timing(&event2, Duration::from_millis(5));
			assert_eq!(exp_state.elapsed_time, Duration::from_millis(15));
			assert_eq!(exp_state.event_times.len(), 2);
			assert_eq!(exp_state.event_times[1].0, event2);
			assert_eq!(exp_state.event_times[1].1, Duration::from_millis(15));
		}
	}

	// These tests cover `CacheKey`.
	#[cfg(feature = "testing-timing")]
	mod cache_key {
		use super::*;
		use crate::testing::specs::csp::ProcessBuildError;

		#[test]
		fn a_timed_transition_is_part_of_the_key() -> Result<(), ProcessBuildError> {
			let without = Process::builder("Keyed")
				.initial_state(State("S0"))
				.add_state(State("S1"))
				.add_observable(Event("arm"))
				.build()?;
			let with = Process::builder("Keyed")
				.initial_state(State("S0"))
				.add_observable(Event("arm"))
				.add_timed_transition(State("S0"), Event("arm"), State("S1"), None, Vec::new())
				.build()?;

			assert_ne!(CacheKey::new(&without, 8), CacheKey::new(&with, 8));
			Ok(())
		}
	}
}
