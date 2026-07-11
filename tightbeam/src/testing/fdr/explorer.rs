//! Trait-based architecture for FDR exploration
//!
//! This module defines the core traits that separate concerns in the FDR exploration engine:
//! - `ExplorationCore`: Core exploration logic and state management
//! - `RefinementChecker`: Refinement checking algorithms (trace, failures, divergence)
//! - `MemoizationCache`: Caching layer for expensive computations

use std::collections::HashSet;

#[cfg(feature = "testing-timing")]
use core::time::Duration;
#[cfg(feature = "testing-timing")]
use std::collections::HashMap;

use super::config::{Failure, FdrConfig, Trace};
use crate::testing::specs::csp::{Event, Process, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::InjectedFaultRecord;

/// Core exploration functionality
///
/// Handles the fundamental exploration mechanics: state space traversal,
/// seed management, determinism checking, and basic property verification.
pub trait ExplorationCore {
	/// Get the process being explored
	fn process(&self) -> &Process;

	/// Get the current configuration
	fn config(&self) -> &FdrConfig;

	/// Explore a single seed and return the result
	fn explore_seed(&mut self, seed: u64) -> SeedResult;

	/// Get traces explored so far
	fn traces(&self) -> Vec<Trace>;

	/// Get failures collected so far
	fn failures(&self) -> Vec<Failure>;

	/// Get statistics about exploration
	fn states_visited(&self) -> usize;

	/// Get number of seeds completed
	fn seeds_completed(&self) -> u32;

	/// Accumulate timing-pruned branch count (for parallel aggregation)
	fn add_timing_pruned(&mut self, _count: usize) {}

	/// Add a seed result (for use when aggregating parallel results)
	fn add_seed_result(&mut self, seed: u64, result: SeedResult);

	/// Update visited states (for use when aggregating parallel results)
	fn update_visited_states(&mut self, visited: &HashSet<State>);

	/// Number of exploration branches pruned for timing violations
	///
	/// Timed exploration drops branches whose WCET/deadline constraints fail.
	fn timing_pruned(&self) -> usize {
		0
	}

	/// Compute refusal set at a given state
	///
	/// Refusal set = all observable events minus enabled observable events.
	/// Hidden events (τ-transitions) are filtered out as they cannot be refused.
	/// Reference: Roscoe (1998, 2010)
	fn compute_refusals(&self, process: &Process, state: State) -> HashSet<Event> {
		use std::collections::HashSet;
		// Only consider observable events (filter out hidden τ-transitions)
		let enabled_events: HashSet<Event> = process
			.enabled(state)
			.iter()
			.filter_map(|action| {
				if !process.hidden.contains(&action.event) {
					Some(action.event)
				} else {
					None
				}
			})
			.collect();

		// Refusal set = all observable events minus enabled observable events
		process
			.observable
			.iter()
			.filter(|&event| !enabled_events.contains(event))
			.cloned()
			.collect()
	}
}

/// Outcome of a single refinement check
#[derive(Debug, Clone, PartialEq)]
pub enum RefinementOutcome<W> {
	/// Refinement holds for everything explored. `complete` is false when
	/// resource bounds truncated the explored set (bounded-verification
	/// claim only).
	Holds {
		/// Whether the underlying trace/failure sets were computed without
		/// hitting resource limits
		complete: bool,
	},
	/// Refinement violated; witness is the offending trace/failure
	Violated(W),
	/// Timeout or resource limits prevented deciding the relation
	Inconclusive,
}

/// Refinement checking algorithms
///
/// Implements the three main refinement checks:
/// - Trace refinement: traces(Impl) ⊆ traces(Spec)
/// - Failures refinement: failures(Impl) ⊆ failures(Spec)
/// - Divergence refinement: divergences(Impl) ⊆ divergences(Spec)
pub trait RefinementChecker {
	/// Maximum number of traces to compute before early termination
	/// Prevents exponential explosion for large specs
	const MAX_TRACES: usize = 5000;

	/// Maximum queue size in BFS exploration before early termination
	/// Prevents memory exhaustion for large state spaces
	const MAX_QUEUE_SIZE: usize = 10000;

	/// Maximum visited states before early termination
	/// Prevents excessive memory usage during exploration
	const MAX_VISITED: usize = 20000;

	/// Check trace refinement: traces(impl_process) ⊆ traces(spec_process)
	fn check_trace_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace>;

	/// Check failures refinement: failures(impl_process) ⊆ failures(spec_process)
	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Failure>;

	/// Check divergence refinement: divergences(impl_process) ⊆ divergences(spec_process)
	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace>;

	/// Compute all traces of a process up to max_depth
	///
	/// The `bool` is true when the trace set is complete up to `max_depth`
	/// (no timeout or resource limit truncated the exploration).
	fn compute_traces(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool);

	/// Compute all failures of a process up to max_depth
	///
	/// The `bool` is true when the failure set is complete up to
	/// `max_depth` (no resource limit truncated the exploration).
	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> (Vec<Failure>, bool);

	/// Compute all divergences of a process up to max_depth
	///
	/// The `bool` is true when the divergence set is complete up to
	/// `max_depth`.
	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool);

	/// Compute refusal set at a given state
	fn compute_refusals(&self, process: &Process, state: State) -> HashSet<Event>;
}

/// Memoization cache for expensive computations
///
/// Caches results of trace/failure/divergence computations to avoid
/// redundant work when checking multiple refinements.
///
/// Keys are structural digests ([`Process::structure_digest`]), not
/// process names: algebra operators (`hide`, `rename`) produce constant
/// names for structurally different results, so name keys collide and
/// silently serve wrong verdicts.
pub trait MemoizationCache {
	/// Get cached traces for a process structure, or None if not cached
	fn get_cached_traces(&self, structure: u64) -> Option<(Vec<Trace>, bool)>;

	/// Cache traces for a process structure
	fn cache_traces(&mut self, structure: u64, traces: Vec<Trace>, complete: bool);

	/// Get cached failures for a process structure, or None if not cached
	fn get_cached_failures(&self, structure: u64) -> Option<(Vec<Failure>, bool)>;

	/// Cache failures for a process structure
	fn cache_failures(&mut self, structure: u64, failures: Vec<Failure>, complete: bool);

	/// Get cached divergences for a process structure, or None if not cached
	fn get_cached_divergences(&self, structure: u64) -> Option<(Vec<Trace>, bool)>;

	/// Cache divergences for a process structure
	fn cache_divergences(&mut self, structure: u64, divergences: Vec<Trace>, complete: bool);
}

/// Result of exploring a single seed
///
/// With `testing-fault`, every variant carries the fault records injected
/// during the seed so recovery statistics can attribute failures after a
/// fault (see `FdrVerdict::error_recovery_failed`).
#[derive(Debug, Clone)]
pub enum SeedResult {
	/// Exploration completed successfully
	#[cfg(feature = "testing-fault")]
	Success(Trace, Vec<Failure>, Vec<InjectedFaultRecord>),
	#[cfg(not(feature = "testing-fault"))]
	Success(Trace, Vec<Failure>),
	/// Divergence detected (τ-loop)
	#[cfg(feature = "testing-fault")]
	Divergence(Trace, Vec<Event>, Vec<InjectedFaultRecord>),
	#[cfg(not(feature = "testing-fault"))]
	Divergence(Trace, Vec<Event>),
	/// Deadlock detected (unexpected STOP)
	#[cfg(feature = "testing-fault")]
	Deadlock(Trace, State, Vec<InjectedFaultRecord>),
	#[cfg(not(feature = "testing-fault"))]
	Deadlock(Trace, State),
}

/// Exploration state during BFS traversal
#[derive(Debug, Clone)]
pub struct ExplorationState {
	/// Current process state
	pub process_state: State,

	/// Trace so far (observable events only)
	pub trace: Trace,

	/// Consecutive τ-transitions counter
	pub internal_run: usize,

	/// Path through state space (for divergence witness)
	pub state_path: Vec<State>,

	/// Hidden events executed (for divergence witness)
	pub hidden_events: Vec<Event>,

	/// Cumulative elapsed time (worst-case using WCET)
	#[cfg(feature = "testing-timing")]
	pub elapsed_time: Duration,

	/// Event timestamps: (event, cumulative_time_when_event_occurred)
	#[cfg(feature = "testing-timing")]
	pub event_times: Vec<(Event, Duration)>,

	/// Clock values (for timed CSP)
	#[cfg(feature = "testing-timing")]
	pub clock_values: HashMap<String, Duration>,
}

impl ExplorationState {
	/// Create initial exploration state
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

	/// Clone state for branch exploration
	pub fn branch(&self) -> Self {
		self.clone()
	}

	/// Record observable event
	pub fn record_observable(&mut self, event: Event, next_state: State) {
		self.trace.push(event);
		self.process_state = next_state;
		self.state_path.push(next_state);
		self.internal_run = 0; // Reset τ counter
		#[cfg(feature = "testing-timing")]
		{
			// Timing will be updated by caller after WCET lookup
		}
	}

	/// Record hidden (τ) event
	pub fn record_hidden(&mut self, event: Event, next_state: State) {
		self.hidden_events.push(event);
		self.process_state = next_state;
		self.state_path.push(next_state);
		self.internal_run += 1;
		#[cfg(feature = "testing-timing")]
		{
			// Hidden events don't contribute to timing (or use zero time)
		}
	}

	/// Update timing after recording an observable event
	/// Called after WCET lookup to add event time
	#[cfg(feature = "testing-timing")]
	pub fn update_timing(&mut self, event: &Event, wcet: Duration) {
		self.elapsed_time += wcet;
		self.event_times.push((*event, self.elapsed_time));
	}

	/// Advance all clocks by elapsed time
	#[cfg(feature = "testing-timing")]
	pub fn update_clocks(&mut self, elapsed: Duration) {
		for clock_value in self.clock_values.values_mut() {
			*clock_value = clock_value.saturating_add(elapsed);
		}
	}

	/// Reset specific clocks to zero
	#[cfg(feature = "testing-timing")]
	pub fn reset_clocks(&mut self, clock_names: &[String]) {
		for name in clock_names {
			self.clock_values.insert(name.clone(), Duration::ZERO);
		}
	}
}

/// Seeded RNG for deterministic choice selection at nondeterministic points
#[derive(Debug, Clone)]
pub struct SeededRng {
	state: u64,
}

impl SeededRng {
	/// Create new seeded RNG
	pub fn new(seed: u64) -> Self {
		Self { state: seed.wrapping_add(1) }
	}

	/// Generate next pseudo-random number (LCG algorithm)
	pub fn get_next(&mut self) -> u64 {
		// Linear Congruential Generator constants from Numerical Recipes
		self.state = self
			.state
			.wrapping_mul(crate::constants::LCG_MULTIPLIER)
			.wrapping_add(crate::constants::LCG_INCREMENT);
		self.state
	}

	/// Choose an item from slice using current RNG state
	pub fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
		if items.is_empty() {
			None
		} else {
			let index = (self.get_next() as usize) % items.len();
			Some(&items[index])
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Tests for SeededRng
	mod seeded_rng {
		use super::*;

		#[test]
		fn deterministic_sequences() {
			let mut rng1 = SeededRng::new(42);
			let mut rng2 = SeededRng::new(42);
			for _ in 0..10 {
				assert_eq!(rng1.get_next(), rng2.get_next());
			}
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
	}

	// Tests for ExplorationState
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
			assert_eq!(exp_state.internal_run, 0); // Reset after observable
			assert_eq!(exp_state.state_path.len(), 2);
		}

		#[test]
		fn record_hidden_event() {
			let (state1, state2) = (State("S1"), State("S2"));
			let event = Event("tau");

			let mut exp_state = ExplorationState::initial(state1);
			exp_state.record_hidden(event, state2);
			assert_eq!(exp_state.process_state, state2);
			assert!(exp_state.trace.is_empty()); // Hidden events don't go in trace
			assert_eq!(exp_state.internal_run, 1); // Incremented
			assert_eq!(exp_state.hidden_events, vec![event]);
			assert_eq!(exp_state.state_path.len(), 2);
		}

		#[test]
		fn divergence_detection_via_internal_run_counter() {
			let state = State("S1");
			let tau = Event("tau");
			let mut exp_state = ExplorationState::initial(state);

			// Simulate τ-loop: many hidden transitions
			for _ in 0..35 {
				exp_state.record_hidden(tau, state);
			}

			assert!(exp_state.internal_run > 32);
			assert_eq!(exp_state.hidden_events.len(), 35);
			assert!(exp_state.trace.is_empty()); // Observable trace stays empty
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

			// Add another event
			let event2 = Event("evt2");
			exp_state.record_observable(event2, state);
			exp_state.update_timing(&event2, Duration::from_millis(5));
			assert_eq!(exp_state.elapsed_time, Duration::from_millis(15));
			assert_eq!(exp_state.event_times.len(), 2);
			assert_eq!(exp_state.event_times[1].0, event2);
			assert_eq!(exp_state.event_times[1].1, Duration::from_millis(15));
		}
	}
}
