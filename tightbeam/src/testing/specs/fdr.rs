//! Layer 3: FDR/Refinement checking
//!
//! This module provides bounded refinement checking following CSP theory:
//! - Trace refinement (⊑T): traces(Impl) ⊆ traces(Spec)
//! - Failures refinement (⊑F): failures(Impl) ⊆ failures(Spec)
//! - Divergence detection: no infinite τ-loops
//! - Multi-seed exploration: different scheduler interleaving
//! - CSPM export for FDR4 integration
//!
//! Based on:
//! - Hoare (1985): Communicating Sequential Processes
//! - Roscoe (2010): Understanding Concurrent Systems
//! - Pedersen & Chalmers (2024): Verifying Cooperatively Scheduled Runtimes
//!
//! Feature gated: requires `testing-fdr`

use std::collections::{HashSet, VecDeque};
use std::io::Write;

use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionLabel, AssertionPhase};
use crate::testing::specs::csp::{Event, Process, State};
use crate::testing::trace::ConsumedTrace;

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
}

impl Default for FdrConfig {
	fn default() -> Self {
		Self {
			seeds: 64,
			max_depth: 128,
			max_internal_run: 32,
			timeout_ms: 5000,
			specs: Vec::new(),
		}
	}
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
	pub trace_refinement_witness: Option<Vec<Event>>,

	/// Witness to failures refinement violation: (trace, refusal) in Impl but not in Spec
	pub failures_refinement_witness: Option<(Vec<Event>, HashSet<Event>)>,

	/// Witness to divergence refinement violation: divergent trace in Impl but not in Spec
	pub divergence_refinement_witness: Option<Vec<Event>>,

	/// Witness to nondeterminism: (seed, trace, event) where different seeds diverge
	pub determinism_witness: Option<(u64, Vec<Event>, Event)>,

	/// Witness to divergence: (seed, τ-loop sequence) if found
	pub divergence_witness: Option<(u64, Vec<Event>)>,

	/// Witness to deadlock: (seed, trace, state) if found
	pub deadlock_witness: Option<(u64, Vec<Event>, State)>,

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

/// CSP trace: sequence of observable events
pub type Trace = Vec<Event>;

/// Refusal set: events refused in stable state
pub type RefusalSet = HashSet<Event>;

/// Failure: (trace, refusal_set)
pub type Failure = (Trace, RefusalSet);

/// Acceptance set: events accepted after trace
pub type AcceptanceSet = HashSet<Event>;

/// Seeded RNG for deterministic choice selection at nondeterministic points
struct SeededRng {
	state: u64,
}

impl SeededRng {
	/// Create new seeded RNG
	fn new(seed: u64) -> Self {
		Self { state: seed.wrapping_add(1) }
	}

	/// Generate next pseudo-random number (LCG algorithm)
	fn next(&mut self) -> u64 {
		// Linear Congruential Generator constants from Numerical Recipes
		const A: u64 = 6364136223846793005;
		const C: u64 = 1442695040888963407;
		self.state = self.state.wrapping_mul(A).wrapping_add(C);
		self.state
	}

	/// Choose an item from slice using current RNG state
	fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
		if items.is_empty() {
			None
		} else {
			let index = (self.next() as usize) % items.len();
			Some(&items[index])
		}
	}
}

/// Result of exploring a single seed
enum SeedResult {
	/// Exploration completed successfully
	Success(Trace),
	/// Divergence detected (τ-loop)
	Divergence(Trace, Vec<Event>),
	/// Deadlock detected (unexpected STOP)
	Deadlock(Trace, State),
}

/// FDR exploration state
#[derive(Debug, Clone)]
struct ExplorationState {
	/// Current process state
	process_state: State,

	/// Trace so far (observable events only)
	trace: Trace,

	/// Consecutive τ-transitions counter
	internal_run: usize,

	/// Path through state space (for divergence witness)
	state_path: Vec<State>,

	/// Hidden events executed (for divergence witness)
	hidden_events: Vec<Event>,
}

impl ExplorationState {
	/// Create initial exploration state
	fn initial(process_state: State) -> Self {
		Self {
			process_state,
			trace: Vec::new(),
			internal_run: 0,
			state_path: vec![process_state],
			hidden_events: Vec::new(),
		}
	}

	/// Clone state for branch exploration
	fn branch(&self) -> Self {
		self.clone()
	}

	/// Record observable event
	fn record_observable(&mut self, event: Event, next_state: State) {
		self.trace.push(event);
		self.process_state = next_state;
		self.state_path.push(next_state);
		self.internal_run = 0; // Reset τ counter
	}

	/// Record hidden (τ) event
	fn record_hidden(&mut self, event: Event, next_state: State) {
		self.hidden_events.push(event.clone());
		self.process_state = next_state;
		self.state_path.push(next_state);
		self.internal_run += 1;
	}
}

/// FDR exploration engine
pub struct FdrExplorer<'a> {
	/// Process being verified
	process: &'a Process,

	/// Configuration
	config: FdrConfig,

	/// Results per seed
	seed_results: Vec<(u64, SeedResult)>,

	/// States visited (for statistics)
	visited_states: HashSet<State>,

	/// Verdict accumulator
	verdict: FdrVerdict,
}

impl<'a> FdrExplorer<'a> {
	/// Create new FDR explorer
	pub fn new(process: &'a Process, config: FdrConfig) -> Self {
		Self {
			process,
			config,
			seed_results: Vec::new(),
			visited_states: HashSet::new(),
			verdict: FdrVerdict::default(),
		}
	}

	/// Run multi-seed exploration
	pub fn explore(&mut self) -> FdrVerdict {
		// Mode 1: Refinement checking (when specs provided)
		if !self.config.specs.is_empty() {
			self.check_refinement();
			return self.verdict.clone();
		}

		// Mode 2: Single-process multi-seed exploration
		for seed in 0..self.config.seeds {
			let result = self.explore_seed(seed as u64);
			self.seed_results.push((seed as u64, result));
			self.verdict.seeds_completed += 1;
		}

		self.verdict.traces_explored = self.seed_results.len();
		self.verdict.states_visited = self.visited_states.len();

		// Check determinism across all seeds
		self.check_determinism();

		// Update overall verdict
		self.verdict.passed = self.verdict.divergence_free
			&& self.verdict.deadlock_free
			&& (self.verdict.is_deterministic || self.verdict.determinism_witness.is_none());

		self.verdict.clone()
	}

	/// Explore single seed (different scheduling)
	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		let mut rng = SeededRng::new(seed);
		let mut queue = VecDeque::new();

		// Initial exploration state
		let initial = ExplorationState::initial(self.process.initial);
		queue.push_back(initial);

		// Track best result for this seed
		let mut longest_trace = Vec::new();
		while let Some(state) = queue.pop_front() {
			// Track visited states
			self.visited_states.insert(state.process_state);

			// Depth cutoff
			if state.trace.len() >= self.config.max_depth {
				if state.trace.len() > longest_trace.len() {
					longest_trace = state.trace.clone();
				}

				continue;
			}

			// Divergence detection
			if state.internal_run > self.config.max_internal_run {
				return SeedResult::Divergence(state.trace.clone(), state.hidden_events.clone());
			}

			// Terminal state: record trace and mark success
			if self.process.is_terminal(state.process_state) {
				if state.trace.len() > longest_trace.len() {
					longest_trace = state.trace.clone();
				}

				continue;
			}

			// Get enabled actions
			let actions = self.process.enabled(state.process_state);
			if actions.is_empty() {
				// Deadlock: no enabled actions in non-terminal state
				return SeedResult::Deadlock(state.trace.clone(), state.process_state);
			}

			// Select action using seeded RNG at choice points
			let action = if self.process.choice.contains(&state.process_state) {
				// Nondeterministic choice point: use RNG to select
				rng.choose(&actions).expect("actions not empty")
			} else if actions.len() == 1 {
				// Deterministic: only one choice
				&actions[0]
			} else {
				// Multiple actions but not marked as choice state: use RNG anyway
				rng.choose(&actions).expect("actions not empty")
			};

			// Execute transition
			let next_states = self.process.step(state.process_state, &action.event);
			for next_state in next_states {
				let mut next_exploration = state.branch();
				if self.process.hidden.contains(&action.event) {
					// Hidden (τ) transition
					next_exploration.record_hidden(action.event.clone(), next_state);
				} else {
					// Observable transition
					next_exploration.record_observable(action.event.clone(), next_state);
				}

				queue.push_back(next_exploration);
			}
		}

		// Return success with longest trace found
		SeedResult::Success(longest_trace)
	}

	/// Check for witnesses to nondeterminism
	fn check_determinism(&mut self) {
		let mut traces_by_seed: Vec<(u64, &Trace)> = Vec::new();

		// Collect successful traces
		for (seed, result) in &self.seed_results {
			match result {
				SeedResult::Success(trace) => {
					traces_by_seed.push((*seed, trace));
				}
				SeedResult::Divergence(_trace, hidden) => {
					// Divergence violation
					self.verdict.divergence_free = false;
					self.verdict.passed = false;
					self.verdict.divergence_witness = Some((*seed, hidden.clone()));
					self.verdict.failing_seed = Some(*seed);
				}
				SeedResult::Deadlock(trace, state) => {
					// Deadlock violation
					self.verdict.deadlock_free = false;
					self.verdict.passed = false;
					self.verdict.deadlock_witness = Some((*seed, trace.clone(), *state));
					self.verdict.failing_seed = Some(*seed);
				}
			}
		}

		// Check if all successful traces are identical
		if traces_by_seed.len() > 1 {
			let first_trace = traces_by_seed[0].1;
			for (seed, trace) in &traces_by_seed[1..] {
				if trace != &first_trace {
					// Found nondeterminism
					self.verdict.is_deterministic = false;
					// Find first diverging event
					for (i, event) in first_trace.iter().enumerate() {
						if i >= trace.len() || &trace[i] != event {
							let witness_event = if i < trace.len() {
								trace[i].clone()
							} else {
								event.clone()
							};
							self.verdict.determinism_witness = Some((*seed, trace.to_vec(), witness_event));
							break;
						}
					}
					break;
				}
			}
		}
	}

	/// Get traces explored (for compatibility)
	pub fn traces(&self) -> Vec<Trace> {
		self.seed_results
			.iter()
			.filter_map(|(_, result)| match result {
				SeedResult::Success(trace) => Some(trace.clone()),
				_ => None,
			})
			.collect()
	}

	/// Get failures collected (for compatibility)
	pub fn failures(&self) -> Vec<Failure> {
		// Compute failures from successful traces
		let mut failures = Vec::new();
		for (_, result) in &self.seed_results {
			if let SeedResult::Success(trace) = result {
				// Empty refusal set for now (would need state tracking)
				failures.push((trace.clone(), HashSet::new()));
			}
		}
		failures
	}

	/// Compute all possible traces of a process up to max_depth
	///
	/// Uses BFS to exhaustively explore all reachable traces.
	/// Returns set of traces for efficient subset checking.
	///
	/// ## Algorithm
	/// 1. Start from initial state with empty trace
	/// 2. For each state, explore all enabled observable events
	/// 3. Handle τ-transitions automatically (hidden events)
	/// 4. Record trace at each state (including empty trace at initial)
	/// 5. Stop at terminal states or depth limit
	///
	/// ## Notes
	/// - Only observable events appear in traces
	/// - τ-transitions are taken automatically without appearing in trace
	/// - Empty trace ⟨⟩ is always included (initial state)
	fn compute_traces(&self, process: &Process, max_depth: usize) -> HashSet<Trace> {
		let mut traces = HashSet::new();
		let mut queue = VecDeque::new();

		// Initial state: empty trace
		queue.push_back((process.initial, Vec::new(), 0usize));
		traces.insert(Vec::new()); // ⟨⟩ is always a valid trace

		while let Some((state, trace, depth)) = queue.pop_front() {
			// Depth cutoff
			if depth >= max_depth {
				continue;
			}

			// Terminal state: trace is recorded
			if process.is_terminal(state) {
				continue;
			}

			// Get enabled actions
			let actions = process.enabled(state);

			for action in actions {
				// Get next states for this action
				let next_states = process.step(state, &action.event);

				for next_state in next_states {
					if process.hidden.contains(&action.event) {
						// τ-transition: don't extend trace, just explore new state
						queue.push_back((next_state, trace.clone(), depth));
					} else {
						// Observable event: extend trace
						let mut new_trace = trace.clone();
						new_trace.push(action.event.clone());
						traces.insert(new_trace.clone());
						queue.push_back((next_state, new_trace, depth + 1));
					}
				}
			}
		}

		traces
	}

	/// Check trace refinement: traces(impl_process) ⊆ traces(spec_process)
	///
	/// Returns (passed, counter_example):
	/// - (true, None): Refinement holds
	/// - (false, Some(trace)): Refinement fails, trace is witness in Impl but not in Spec
	///
	/// ## CSP Theory
	/// Spec ⊑_T Impl means: every trace of Impl is also a trace of Spec
	/// - Spec describes permitted behaviors
	/// - Impl must not exhibit behaviors outside Spec
	///
	/// ## Example
	/// ```text
	/// Spec: STOP  (traces = {⟨⟩})
	/// Impl: a → STOP  (traces = {⟨⟩, ⟨a⟩})
	/// Result: Fails, witness = ⟨a⟩ (Impl can do 'a', Spec cannot)
	/// ```
	fn check_trace_refinement(&self, spec: &Process, impl_process: &Process) -> (bool, Option<Trace>) {
		// Compute all traces for both processes
		let spec_traces = self.compute_traces(spec, self.config.max_depth);
		let impl_traces = self.compute_traces(impl_process, self.config.max_depth);

		// Check: impl_traces ⊆ spec_traces
		for impl_trace in &impl_traces {
			if !spec_traces.contains(impl_trace) {
				// Found counter-example: trace in Impl but not in Spec
				return (false, Some(impl_trace.clone()));
			}
		}

		// All impl traces are in spec traces
		(true, None)
	}

	/// Compute refusal set at a given state
	///
	/// Returns the set of events that can be refused (are not enabled) at this state.
	/// A process in state `s` can refuse event `a` if `a` is not in the alphabet or
	/// if there is no transition from `s` on `a`.
	///
	/// ## Algorithm
	/// 1. Get all observable events in the alphabet
	/// 2. For each event, check if it's enabled at the state
	/// 3. If not enabled, add to refusal set
	///
	/// ## Note
	/// This computes the minimal refusal set. A process can also refuse any
	/// superset of this set, but we only need to track maximal refusals for
	/// refinement checking.
	fn compute_refusals(&self, process: &Process, state: State) -> RefusalSet {
		let mut refusals = RefusalSet::new();

		// For each observable event in the alphabet
		for event in &process.observable {
			// Check if this event is enabled at the current state
			let enabled = process.enabled(state).iter().any(|action| &action.event == event);

			if !enabled {
				// Event not enabled → can be refused
				refusals.insert(event.clone());
			}
		}

		refusals
	}

	/// Compute all failures of a process up to max_depth
	///
	/// A failure is a pair (trace, refusal_set) where:
	/// - `trace` is a sequence of observable events leading to a stable state
	/// - `refusal_set` is a set of events that can be refused at that state
	///
	/// Uses BFS to explore all reachable states and compute refusal sets.
	///
	/// ## Algorithm
	/// 1. Start from initial state with empty trace
	/// 2. For each reachable state, compute refusal set
	/// 3. Record failure (trace, refusal_set)
	/// 4. Explore transitions to build longer traces
	/// 5. Handle τ-transitions (don't extend trace)
	///
	/// ## Notes
	/// - Empty trace with initial state refusals always included
	/// - Only stable states (after resolving τ-transitions) have meaningful refusals
	/// - For simplicity, we compute refusals at all states
	/// - Returns Vec instead of HashSet (refusal sets aren't hashable)
	fn compute_failures(&self, process: &Process, max_depth: usize) -> Vec<Failure> {
		let mut failures = Vec::new();
		let mut queue = VecDeque::new();
		let mut visited = HashSet::new();

		// Initial state: empty trace with initial refusals
		queue.push_back((process.initial, Vec::new(), 0usize));

		while let Some((state, trace, depth)) = queue.pop_front() {
			// Track visited (state, trace) pairs to avoid duplicates
			let visit_key = (state, trace.clone());
			if visited.contains(&visit_key) {
				continue;
			}
			visited.insert(visit_key);

			// Compute refusal set at this state
			let refusals = self.compute_refusals(process, state);

			// Check if we already have this failure (avoid duplicates)
			let failure = (trace.clone(), refusals);
			if !failures.contains(&failure) {
				failures.push(failure);
			}

			// Depth cutoff
			if depth >= max_depth {
				continue;
			}

			// Terminal state: no more transitions
			if process.is_terminal(state) {
				continue;
			}

			// Get enabled actions
			let actions = process.enabled(state);

			for action in actions {
				// Get next states for this action
				let next_states = process.step(state, &action.event);

				for next_state in next_states {
					if process.hidden.contains(&action.event) {
						// τ-transition: don't extend trace, just explore new state
						queue.push_back((next_state, trace.clone(), depth));
					} else {
						// Observable event: extend trace
						let mut new_trace = trace.clone();
						new_trace.push(action.event.clone());
						queue.push_back((next_state, new_trace, depth + 1));
					}
				}
			}
		}

		failures
	}

	/// Check failures refinement: failures(impl_process) ⊆ failures(spec_process)
	///
	/// Returns (passed, counter_example):
	/// - (true, None): Refinement holds
	/// - (false, Some((trace, refusal))): Refinement fails, (trace, refusal) is in Impl but not in Spec
	///
	/// ## CSP Theory
	/// Spec ⊑_F Impl means: every failure of Impl is also a failure of Spec
	/// - Failures capture both what a process does and what it refuses
	/// - More powerful than trace refinement (catches internal choice vs external choice)
	///
	/// ## Example
	/// ```text
	/// Spec: a → STOP □ b → STOP  (external choice)
	/// Impl: a → STOP ⊓ b → STOP  (internal choice)
	///
	/// Trace refinement: PASSES (same traces)
	/// Failures refinement: FAILS
	///   - Impl after ⟨⟩ can refuse {a}: (⟨⟩, {a}) ∈ failures(Impl)
	///   - Spec after ⟨⟩ cannot refuse {a}: (⟨⟩, {a}) ∉ failures(Spec)
	///   - Witness: (⟨⟩, {a})
	/// ```
	fn check_failures_refinement(&self, spec: &Process, impl_process: &Process) -> (bool, Option<Failure>) {
		// Compute all failures for both processes
		let spec_failures = self.compute_failures(spec, self.config.max_depth);
		let impl_failures = self.compute_failures(impl_process, self.config.max_depth);

		// Check: impl_failures ⊆ spec_failures
		for impl_failure in &impl_failures {
			if !spec_failures.contains(impl_failure) {
				// Found counter-example: failure in Impl but not in Spec
				return (false, Some(impl_failure.clone()));
			}
		}

		// All impl failures are in spec failures
		(true, None)
	}

	/// Compute all divergences of a process up to max_depth
	///
	/// A divergence is a trace that leads to a state from which an infinite
	/// sequence of τ-transitions is possible (an infinite internal loop).
	///
	/// Uses BFS to explore states, detecting τ-cycles. When exploring τ-transitions,
	/// if we revisit a (state, trace) we've seen in the current τ-run, we've found a cycle.
	///
	/// ## Algorithm
	/// 1. Start from initial state with empty trace
	/// 2. Explore transitions using BFS
	/// 3. Track states seen during current τ-run
	/// 4. If we see same (state, trace) twice in a τ-run, it's a divergence
	/// 5. Reset τ-run tracking on observable events
	///
	/// ## CSP Theory
	/// Divergences = traces that lead to states with infinite τ-loops
	/// - Spec: a → τ → b → STOP (no divergence)
	/// - Impl: a → τ → τ → τ → ... (diverges after ⟨a⟩)
	///
	/// Returns set of traces after which divergence is possible.
	fn compute_divergences(&self, process: &Process, max_depth: usize) -> HashSet<Trace> {
		let mut divergences = HashSet::new();
		let mut queue = VecDeque::new();

		// (state, trace, tau_states_seen) where tau_states_seen tracks states in current τ-run
		// Start with initial state already in tau_states_seen
		let mut initial_tau_seen = HashSet::new();
		initial_tau_seen.insert((process.initial, Vec::new()));
		queue.push_back((process.initial, Vec::new(), initial_tau_seen));

		// Track visited (state, trace) globally to avoid redundant work
		// BUT: Don't mark as visited if we found a divergence, since other paths might also diverge
		let mut global_visited = HashSet::new();

		while let Some((state, trace, tau_states_seen)) = queue.pop_front() {
			// Depth cutoff
			if trace.len() >= max_depth {
				continue;
			}

			// Skip if we've already fully explored this (state, trace) and found no divergence
			let key = (state, trace.clone());
			if global_visited.contains(&key) {
				continue;
			}

			// Explore all enabled actions
			for action in process.enabled(state) {
				// Get next states from transition
				let next_states = process.step(state, &action.event);

				for next_state in next_states {
					if process.hidden.contains(&action.event) {
						// Hidden (τ) transition: check for cycle
						let next_key = (next_state, trace.clone());

						if tau_states_seen.contains(&next_key) {
							// Found τ-cycle! This trace diverges
							divergences.insert(trace.clone());
							// Don't mark as visited - we found divergence
							// Continue to next action
							continue;
						}

						// Add to τ-run tracking and continue
						let mut new_tau_seen = tau_states_seen.clone();
						new_tau_seen.insert(next_key.clone());
						queue.push_back((next_state, trace.clone(), new_tau_seen));
					} else {
						// Observable event: extend trace, reset τ-tracking
						let mut new_trace = trace.clone();
						new_trace.push(action.event.clone());
						let mut new_tau_seen = HashSet::new();
						new_tau_seen.insert((next_state, new_trace.clone()));
						queue.push_back((next_state, new_trace, new_tau_seen));
					}
				}
			}

			// Only mark as visited after exploring all actions (and no divergence found from here)
			global_visited.insert(key.clone());
		}

		divergences
	}

	/// Check divergence refinement: divergences(impl_process) ⊆ divergences(spec_process)
	///
	/// Returns (passed, counter_example):
	/// - (true, None): Refinement holds
	/// - (false, Some(trace)): Refinement fails, trace diverges in Impl but not in Spec
	///
	/// ## CSP Theory
	/// Spec ⊑_D Impl means: Impl cannot diverge where Spec doesn't
	/// - Spec describes permitted divergent behaviors
	/// - Impl must not introduce new divergences
	///
	/// ## Example
	/// ```text
	/// Spec: a → STOP  (no divergence)
	/// Impl: a → (τ → τ → τ → ...) (diverges after ⟨a⟩)
	/// Result: Fails, witness = ⟨a⟩ (Impl diverges, Spec doesn't)
	/// ```
	fn check_divergence_refinement(&self, spec: &Process, impl_process: &Process) -> (bool, Option<Trace>) {
		// Compute all divergences for both processes
		let spec_divergences = self.compute_divergences(spec, self.config.max_depth);
		let impl_divergences = self.compute_divergences(impl_process, self.config.max_depth);
		for impl_div in &impl_divergences {
			if !spec_divergences.contains(impl_div) {
				// Found counter-example: trace diverges in Impl but not in Spec
				return (false, Some(impl_div.clone()));
			}
		}

		// All impl divergences are in spec divergences
		(true, None)
	}

	/// Run refinement checking mode
	///
	/// When `config.specs` is non-empty, checks:
	/// - For each spec in specs: spec ⊑ process
	///
	/// Updates verdict with refinement results and witnesses.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		// Check trace refinement for each spec
		for spec in &self.config.specs {
			let (passed, witness) = self.check_trace_refinement(spec, self.process);
			if !passed {
				self.verdict.trace_refines = false;
				self.verdict.passed = false;
				self.verdict.trace_refinement_witness = witness;
				return; // Stop at first violation
			}
		}

		// Check failures refinement for each spec
		for spec in &self.config.specs {
			let (passed, witness) = self.check_failures_refinement(spec, self.process);
			if !passed {
				self.verdict.failures_refines = false;
				self.verdict.passed = false;
				self.verdict.failures_refinement_witness = witness;
				return; // Stop at first violation
			}
		}

		// Check divergence refinement for each spec
		for spec in &self.config.specs {
			let (passed, witness) = self.check_divergence_refinement(spec, self.process);
			if !passed {
				self.verdict.divergence_refines = false;
				self.verdict.passed = false;
				self.verdict.divergence_refinement_witness = witness;
				return; // Stop at first violation
			}
		}

		// All refinement checks passed
		self.verdict.passed = true;
	}
}

/// CSPM (CSP Machine-readable) export
pub struct CspmExporter<'a> {
	process: &'a Process,
}

impl<'a> CspmExporter<'a> {
	pub fn new(process: &'a Process) -> Self {
		Self { process }
	}

	/// Export process to CSPM format for FDR4
	pub fn export<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writeln!(writer, "-- Generated by tightbeam testing framework")?;
		writeln!(writer, "-- Process: {}", self.process.name)?;

		if let Some(desc) = self.process.description {
			writeln!(writer, "-- Description: {desc}")?;
		}

		writeln!(writer)?;

		// Observable alphabet
		writeln!(writer, "-- Observable alphabet (Σ)")?;
		writeln!(writer, "datatype Observable = ")?;
		let mut obs_iter = self.process.observable.iter();
		if let Some(first) = obs_iter.next() {
			write!(writer, "  {}", first.0)?;
			for event in obs_iter {
				write!(writer, " | {}", event.0)?;
			}
			writeln!(writer)?;
		}
		writeln!(writer)?;

		// Hidden alphabet
		if !self.process.hidden.is_empty() {
			writeln!(writer, "-- Hidden alphabet (τ)")?;
			writeln!(writer, "datatype Hidden = ")?;
			let mut hid_iter = self.process.hidden.iter();
			if let Some(first) = hid_iter.next() {
				write!(writer, "  {}", first.0)?;
				for event in hid_iter {
					write!(writer, " | {}", event.0)?;
				}
				writeln!(writer)?;
			}
			writeln!(writer)?;
		}

		// States
		writeln!(writer, "-- States")?;
		writeln!(writer, "datatype States = ")?;
		let mut state_iter = self.process.states.iter();
		if let Some(first) = state_iter.next() {
			write!(writer, "  {}", first.0)?;
			for state in state_iter {
				write!(writer, " | {}", state.0)?;
			}
			writeln!(writer)?;
		}
		writeln!(writer)?;

		// Process definition (simplified LTS representation)
		writeln!(writer, "-- Process: {}", self.process.name)?;
		writeln!(writer, "channel obs : Observable")?;
		writeln!(writer, "channel hid : Hidden")?;
		writeln!(writer)?;

		// Generate process per state
		for state in &self.process.states {
			write!(writer, "{}Process = ", state.0)?;

			if self.process.is_terminal(*state) {
				writeln!(writer, "SKIP")?;
			} else {
				// Get enabled actions
				let enabled = self.process.enabled(*state);

				if enabled.is_empty() {
					writeln!(writer, "STOP")?;
				} else {
					let mut first = true;
					for action in enabled {
						if !first {
							write!(writer, " [] ")?;
						}
						first = false;

						let next_states = self.process.step(*state, &action.event);
						let next = next_states.first().unwrap(); // Take first for simplicity

						if action.is_observable() {
							write!(writer, "obs.{} -> {}Process", action.event.0, next.0)?;
						} else {
							write!(writer, "hid.{} -> {}Process", action.event.0, next.0)?;
						}
					}
					writeln!(writer)?;
				}
			}
			writeln!(writer)?;
		}

		// Main process
		writeln!(
			writer,
			"{} = {}Process \\ {{| hid |}}",
			self.process.name, self.process.initial.0
		)?;

		Ok(())
	}
}

/// Extension trait for ConsumedTrace with FDR analysis
pub trait FdrTraceExt {
	/// Check if CSP trace is valid
	fn csp_valid(&self) -> bool;

	/// Check if terminated in valid terminal state
	fn terminated_in_valid_state(&self) -> bool;

	/// Get acceptance set after current trace
	fn acceptance_at(&self, state_label: &str) -> Option<AcceptanceSet>;

	/// Check if process can refuse event after state
	fn can_refuse_after(&self, state_label: &str, event_label: &str) -> bool;

	/// Count assertion by label (convenience)
	fn assertion_count(&self, label: &str) -> usize;

	/// Project trace to observable events only
	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String>;

	/// Project trace to hidden events only
	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String>;

	/// Export trace as CSPM
	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

impl FdrTraceExt for ConsumedTrace {
	fn csp_valid(&self) -> bool {
		// Trace is valid if:
		// 1. No transport errors occurred
		// 2. Gate decision was reached (Accept or Reject)
		// 3. If accepted, handler executed (evidenced by assertions)
		if self.error.is_some() {
			return false;
		}

		// Must have a gate decision (part of the protocol)
		if self.gate_decision.is_none() {
			return false;
		}

		// If gate accepted, we expect handler evidence (assertions or response)
		if matches!(self.gate_decision, Some(TransitStatus::Accepted)) {
			if self.assertions.is_empty() && self.response.is_none() {
				return false; // Handler should have done something
			}
		}

		true
	}

	fn terminated_in_valid_state(&self) -> bool {
		// Check if execution completed successfully in a terminal state:
		// 1. No errors
		// 2. Gate decision reached
		// 3. For accepted requests: response generated or terminal assertions present
		if self.error.is_some() {
			return false;
		}

		match self.gate_decision {
			Some(TransitStatus::Accepted) => {
				// Accepted path: should have response or handler-end assertions
				self.response.is_some() || self.assertions.iter().any(|a| a.phase == AssertionPhase::HandlerEnd)
			}
			Some(TransitStatus::Busy)
			| Some(TransitStatus::Unauthorized)
			| Some(TransitStatus::Forbidden)
			| Some(TransitStatus::Timeout) => {
				// Rejection paths are terminal by definition
				true
			}
			Some(TransitStatus::Request) | None => false, // No decision = incomplete execution
		}
	}

	fn acceptance_at(&self, state_label: &str) -> Option<AcceptanceSet> {
		// Compute acceptance set based on trace structure at given state
		// State labels in ConsumedTrace context:
		// - "initial": before gate
		// - "gate_accept": after gate accepts
		// - "handler": during handler execution
		// - "terminal": after response/rejection
		let mut acceptance = AcceptanceSet::new();

		match state_label {
			"initial" => {
				// At initial state, we can accept request frame
				acceptance.insert(Event("request"));
			}
			"gate_accept" => {
				// After gate accepts, handler can process
				acceptance.insert(Event("handler_enter"));
			}
			"handler" => {
				// During handler, can do internal operations or exit
				acceptance.insert(Event("handler_exit"));
				acceptance.insert(Event("response"));
			}
			"gate_reject" => {
				// Rejection is terminal, no further events
			}
			"terminal" => {
				// Terminal state accepts nothing
			}
			_ => {
				// Unknown state label
				return None;
			}
		}

		Some(acceptance)
	}

	fn can_refuse_after(&self, state_label: &str, event_label: &str) -> bool {
		// Event can be refused if it's not in the acceptance set at that state
		if let Some(acceptance) = self.acceptance_at(state_label) {
			// Check if the event label matches any in the acceptance set
			!acceptance.iter().any(|e| e.0 == event_label)
		} else {
			// Unknown state: conservatively assume can refuse
			true
		}
	}

	fn assertion_count(&self, label: &str) -> usize {
		self.assertions
			.iter()
			.filter(|a| matches!(&a.label, AssertionLabel::Custom(l) if *l == label))
			.count()
	}

	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String> {
		use crate::instrumentation::TbEventKind;

		self.instrument_events
			.iter()
			.filter(|e| {
				matches!(
					e.kind,
					TbEventKind::GateAccept
						| TbEventKind::GateReject
						| TbEventKind::RequestRecv
						| TbEventKind::ResponseSend
						| TbEventKind::AssertLabel
				)
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String> {
		use crate::instrumentation::TbEventKind;

		self.instrument_events
			.iter()
			.filter(|e| {
				matches!(
					e.kind,
					TbEventKind::HandlerEnter
						| TbEventKind::HandlerExit
						| TbEventKind::CryptoStep
						| TbEventKind::CompressStep
						| TbEventKind::RouteStep
						| TbEventKind::PolicyEval
						| TbEventKind::ProcessHidden
				)
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writeln!(writer, "-- Execution trace")?;
		writeln!(writer, "Trace = <")?;

		#[cfg(feature = "instrument")]
		{
			let observable = self.project_to_observable();
			for (idx, event) in observable.iter().enumerate() {
				if idx > 0 {
					write!(writer, ", ")?;
				}
				write!(writer, "{event}")?;
			}
		}

		writeln!(writer, ">")?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::TransitionRelation;

	// ===== Test Fixtures =====

	/// Create a simple linear process: S0 --a--> S1
	pub fn linear_process(name: &'static str, terminal_s1: bool) -> Process {
		let mut transitions = TransitionRelation::new();
		transitions.add(State("S0"), Event("a"), State("S1"));

		Process {
			name,
			description: Some("Linear test process"),
			initial: State("S0"),
			states: vec![State("S0"), State("S1")].into_iter().collect(),
			observable: vec![Event("a")].into_iter().collect(),
			hidden: HashSet::new(),
			choice: HashSet::new(),
			terminal: if terminal_s1 {
				vec![State("S1")].into_iter().collect()
			} else {
				HashSet::new()
			},
			transitions,
		}
	}

	/// Create a nondeterministic choice process: S0 --a--> {S1, S2}
	pub fn choice_process(name: &'static str) -> Process {
		let mut transitions = TransitionRelation::new();
		transitions.add(State("S0"), Event("a"), State("S1"));
		transitions.add(State("S0"), Event("a"), State("S2"));

		Process {
			name,
			description: Some("Nondeterministic choice process"),
			initial: State("S0"),
			states: vec![State("S0"), State("S1"), State("S2")].into_iter().collect(),
			observable: vec![Event("a")].into_iter().collect(),
			hidden: HashSet::new(),
			choice: vec![State("S0")].into_iter().collect(),
			terminal: vec![State("S1"), State("S2")].into_iter().collect(),
			transitions,
		}
	}

	/// Create a process with hidden transitions for divergence testing
	#[allow(dead_code)]
	pub fn tau_loop_process(name: &'static str) -> Process {
		let mut transitions = TransitionRelation::new();
		transitions.add(State("S0"), Event("tau"), State("S0")); // Self-loop

		Process {
			name,
			description: Some("Process with τ-loop"),
			initial: State("S0"),
			states: vec![State("S0")].into_iter().collect(),
			observable: HashSet::new(),
			hidden: vec![Event("tau")].into_iter().collect(),
			choice: HashSet::new(),
			terminal: HashSet::new(),
			transitions,
		}
	}

	/// Standard test configuration
	pub fn test_config(seeds: u32) -> FdrConfig {
		FdrConfig { seeds, max_depth: 10, max_internal_run: 32, timeout_ms: 1000, specs: Vec::new() }
	}

	/// Build STOP process (no transitions, traces = {⟨⟩})
	pub fn stop_process() -> Process {
		Process {
			name: "STOP",
			description: Some("Process that does nothing"),
			initial: State("S0"),
			states: vec![State("S0")].into_iter().collect(),
			observable: HashSet::new(),
			hidden: HashSet::new(),
			choice: HashSet::new(),
			terminal: vec![State("S0")].into_iter().collect(),
			transitions: TransitionRelation::new(),
		}
	}

	/// Build a → STOP (traces = {⟨⟩, ⟨a⟩})
	pub fn a_then_stop() -> Process {
		let mut transitions = TransitionRelation::new();
		transitions.add(State("S0"), Event("a"), State("S1"));

		Process {
			name: "a_then_STOP",
			description: Some("Do 'a' then stop"),
			initial: State("S0"),
			states: vec![State("S0"), State("S1")].into_iter().collect(),
			observable: vec![Event("a")].into_iter().collect(),
			hidden: HashSet::new(),
			choice: HashSet::new(),
			terminal: vec![State("S1")].into_iter().collect(),
			transitions,
		}
	}

	// Tests for SeededRng
	mod seeded_rng {
		use super::*;

		#[test]
		fn deterministic_sequences() {
			let mut rng1 = SeededRng::new(42);
			let mut rng2 = SeededRng::new(42);

			for _ in 0..10 {
				assert_eq!(rng1.next(), rng2.next());
			}
		}

		#[test]
		fn different_seeds_produce_different_sequences() {
			let mut rng1 = SeededRng::new(42);
			let mut rng2 = SeededRng::new(43);

			let same_count = (0..10).filter(|_| rng1.next() == rng2.next()).count();
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
	}

	// Tests for ExplorationState
	mod exploration_state {
		use super::*;

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
			exp_state.record_observable(event.clone(), state2);
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
			exp_state.record_hidden(event.clone(), state2);
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
				exp_state.record_hidden(tau.clone(), state);
			}

			assert!(exp_state.internal_run > 32);
			assert_eq!(exp_state.hidden_events.len(), 35);
			assert!(exp_state.trace.is_empty()); // Observable trace stays empty
		}
	}

	// Tests for FdrConfig
	mod config {
		use super::*;

		#[test]
		fn default_configuration() {
			let config = FdrConfig::default();
			assert_eq!(config.seeds, 64);
			assert_eq!(config.max_depth, 128);
			assert_eq!(config.max_internal_run, 32);
			assert_eq!(config.timeout_ms, 5000);
			assert!(config.specs.is_empty());
		}

		#[test]
		fn dual_mode_support() {
			// Mode 1: Single-process exploration
			let config_exploration = FdrConfig::default();
			assert!(config_exploration.specs.is_empty());

			// Mode 2: Refinement checking
			let spec = linear_process("Spec", true);
			let config_refinement = FdrConfig { specs: vec![spec], ..FdrConfig::default() };
			assert!(!config_refinement.specs.is_empty());
		}
	}

	// Tests for FDR exploration behavior aligned
	mod formal_alignment {
		use super::*;

		#[test]
		fn deadlock_detection() {
			let process = linear_process("DeadlockProcess", false);
			let config = test_config(1);
			let mut explorer = FdrExplorer::new(&process, config);

			let verdict = explorer.explore();
			assert!(!verdict.deadlock_free, "Should detect deadlock at S1");
			assert!(!verdict.passed);
			assert!(verdict.deadlock_witness.is_some());
		}

		#[test]
		fn determinism_witness_generation() {
			let process = choice_process("NondeterministicProcess");
			let config = test_config(10);
			let mut explorer = FdrExplorer::new(&process, config);

			// May find nondeterminism depending on RNG
			let verdict = explorer.explore();
			if !verdict.is_deterministic {
				assert!(verdict.determinism_witness.is_some());
				let (seed, trace, event) = verdict.determinism_witness.unwrap();
				assert!(seed < 10);
				assert!(!trace.is_empty() || event == Event("a"));
			}
		}

		#[test]
		fn multi_seed_scheduler_simulation() {
			let process = choice_process("ChoiceProcess");
			let config = test_config(5);

			let mut explorer = FdrExplorer::new(&process, config);
			let verdict = explorer.explore();
			assert_eq!(verdict.seeds_completed, 5);
			assert_eq!(verdict.traces_explored, 5);
			assert!(verdict.states_visited > 0);
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

	// Tests for CSPM export
	mod export {
		use super::*;

		#[test]
		fn export_format_alignment() {
			let mut transitions = TransitionRelation::new();
			transitions.add(State("S0"), Event("a"), State("S1"));

			let process = Process {
				name: "SimpleProcess",
				description: Some("Test process for CSPM export"),
				initial: State("S0"),
				states: vec![State("S0"), State("S1")].into_iter().collect(),
				observable: vec![Event("a")].into_iter().collect(),
				hidden: vec![Event("tau")].into_iter().collect(),
				choice: HashSet::new(),
				terminal: vec![State("S1")].into_iter().collect(),
				transitions,
			};

			let exporter = CspmExporter::new(&process);
			let mut output = Vec::new();
			exporter.export(&mut output).unwrap();

			let cspm = String::from_utf8(output).unwrap();

			// Verify essential CSPM elements
			let required_elements = [
				"SimpleProcess",
				"Observable",
				"a",
				"Hidden",
				"tau",
				"States",
				"S0",
				"S1",
				"\\", // Hiding operator
			];

			for element in &required_elements {
				assert!(cspm.contains(element), "CSPM output missing required element: {}", element);
			}
		}
	}

	/// Generic test framework for refinement checking
	/// Tests the same scenarios across trace, failures, and divergence refinement
	mod refinement_tests {
		use super::*;

		/// Test case definition
		struct RefinementTestCase {
			name: &'static str,
			spec_builder: fn() -> Process,
			impl_builder: fn() -> Process,
			expected_pass: bool,
			check_trace: bool,
			check_failures: bool,
			check_divergence: bool,
			trace_witness: Option<&'static [Event]>,
			failures_witness_check: Option<fn(&FdrVerdict) -> bool>,
		}

		/// Run a test case for all refinement types
		fn run_refinement_test_case(test_case: &RefinementTestCase) {
			let spec = (test_case.spec_builder)();
			let impl_proc = (test_case.impl_builder)();

			let config = FdrConfig { specs: vec![spec], ..Default::default() };
			let mut explorer = FdrExplorer::new(&impl_proc, config);
			let verdict = explorer.explore();

			assert_eq!(
				verdict.passed, test_case.expected_pass,
				"Test case '{}' failed: expected pass={}, got pass={}",
				test_case.name, test_case.expected_pass, verdict.passed
			);

			if test_case.check_trace {
				assert_eq!(
					verdict.trace_refines, test_case.expected_pass,
					"Test case '{}' trace refinement: expected {}, got {}",
					test_case.name, test_case.expected_pass, verdict.trace_refines
				);
			}

			if test_case.check_failures {
				assert_eq!(
					verdict.failures_refines, test_case.expected_pass,
					"Test case '{}' failures refinement: expected {}, got {}",
					test_case.name, test_case.expected_pass, verdict.failures_refines
				);
			}

			if test_case.check_divergence {
				assert_eq!(
					verdict.divergence_refines, test_case.expected_pass,
					"Test case '{}' divergence refinement: expected {}, got {}",
					test_case.name, test_case.expected_pass, verdict.divergence_refines
				);
			}

			if let Some(expected_witness) = test_case.trace_witness {
				assert_eq!(
					verdict.trace_refinement_witness.as_ref(),
					Some(&expected_witness.to_vec()),
					"Test case '{}' trace witness mismatch",
					test_case.name
				);
			}

			if let Some(witness_check) = test_case.failures_witness_check {
				assert!(
					witness_check(&verdict),
					"Test case '{}' failures witness check failed",
					test_case.name
				);
			}
		}

		/// Test cases that apply to all refinement types
		const COMMON_TEST_CASES: &[RefinementTestCase] = &[
			RefinementTestCase {
				name: "identical_processes",
				spec_builder: a_then_stop,
				impl_builder: a_then_stop,
				expected_pass: true,
				check_trace: true,
				check_failures: true,
				check_divergence: true,
				trace_witness: None,
				failures_witness_check: None,
			},
			RefinementTestCase {
				name: "stop_processes",
				spec_builder: stop_process,
				impl_builder: stop_process,
				expected_pass: true,
				check_trace: true,
				check_failures: true,
				check_divergence: true,
				trace_witness: None,
				failures_witness_check: None,
			},
			RefinementTestCase {
				name: "impl_does_more_than_spec",
				spec_builder: stop_process,
				impl_builder: a_then_stop,
				expected_pass: false,
				check_trace: true,
				check_failures: false, // Failures refinement also fails, but we stop at trace
				check_divergence: false,
				trace_witness: Some(&[Event("a")]),
				failures_witness_check: None,
			},
			RefinementTestCase {
				name: "spec_does_more_impl_subset",
				spec_builder: a_then_stop,
				impl_builder: stop_process,
				expected_pass: true,
				check_trace: true,
				check_failures: true,
				check_divergence: true,
				trace_witness: None,
				failures_witness_check: None,
			},
		];

		/// Generate tests for all common cases
		macro_rules! generate_common_tests {
			($module_name:ident) => {
				mod $module_name {
					use super::*;

					#[test]
					fn identical_processes() {
						run_refinement_test_case(&COMMON_TEST_CASES[0]);
					}

					#[test]
					fn stop_processes() {
						run_refinement_test_case(&COMMON_TEST_CASES[1]);
					}

					#[test]
					fn impl_does_more_than_spec() {
						run_refinement_test_case(&COMMON_TEST_CASES[2]);
					}

					#[test]
					fn spec_does_more_impl_subset() {
						run_refinement_test_case(&COMMON_TEST_CASES[3]);
					}
				}
			};
		}

		generate_common_tests!(trace_refinement);
		generate_common_tests!(failures_refinement);
		generate_common_tests!(divergence_refinement);
	}

	// Tests for FdrTraceExt
	mod trace_ext {
		use super::*;

		fn make_trace(status: TransitStatus, with_response: bool, with_assertion: bool) -> ConsumedTrace {
			let mut trace = ConsumedTrace::default();
			trace.gate_decision = Some(status);
			if with_response {
				trace.response = Some(
					crate::compose! {
						V0: id: "test",
							order: 1,
							message: crate::testing::utils::create_test_message(None)
					}
					.expect("compose frame"),
				);
			}
			if with_assertion {
				trace.assertions.push(crate::testing::assertions::Assertion::new(
					0,
					AssertionPhase::HandlerStart,
					AssertionLabel::Custom("test"),
					None,
				));
			}
			trace
		}

		#[test]
		fn csp_valid_with_response() {
			assert!(make_trace(TransitStatus::Accepted, true, false).csp_valid());
		}

		#[test]
		fn csp_valid_with_assertion() {
			assert!(make_trace(TransitStatus::Accepted, false, true).csp_valid());
		}

		#[test]
		fn csp_invalid_with_error() {
			let mut trace = make_trace(TransitStatus::Accepted, false, false);
			trace.error = Some(crate::transport::error::TransportError::Timeout);
			assert!(!trace.csp_valid());
		}

		#[test]
		fn csp_invalid_incomplete() {
			assert!(!ConsumedTrace::default().csp_valid());
		}

		#[test]
		fn terminated_with_response() {
			assert!(make_trace(TransitStatus::Accepted, true, false).terminated_in_valid_state());
		}

		#[test]
		fn terminated_with_handler_end() {
			let mut trace = make_trace(TransitStatus::Accepted, false, false);
			trace.assertions.push(crate::testing::assertions::Assertion::new(
				0,
				AssertionPhase::HandlerEnd,
				AssertionLabel::Custom("end"),
				None,
			));
			assert!(trace.terminated_in_valid_state());
		}

		#[test]
		fn terminated_with_rejection() {
			assert!(make_trace(TransitStatus::Busy, false, false).terminated_in_valid_state());
		}

		#[test]
		fn acceptance_at_states() {
			let trace = ConsumedTrace::default();

			let initial = trace.acceptance_at("initial").expect("initial");
			assert!(initial.contains(&Event("request")));

			let handler = trace.acceptance_at("handler").expect("handler");
			assert!(handler.contains(&Event("handler_exit")));
			assert!(handler.contains(&Event("response")));

			let terminal = trace.acceptance_at("terminal").expect("terminal");
			assert!(terminal.is_empty());
		}

		#[test]
		fn refusal_checks() {
			let trace = ConsumedTrace::default();
			assert!(trace.can_refuse_after("terminal", "any_event"));
			assert!(!trace.can_refuse_after("initial", "request"));
		}

		#[test]
		fn assertion_counting() {
			let mut trace = ConsumedTrace::default();
			for (seq, label) in [(0, "foo"), (1, "bar"), (2, "foo")] {
				trace.assertions.push(crate::testing::assertions::Assertion::new(
					seq,
					AssertionPhase::Gate,
					AssertionLabel::Custom(label),
					None,
				));
			}

			assert_eq!(trace.assertion_count("foo"), 2);
			assert_eq!(trace.assertion_count("bar"), 1);
			assert_eq!(trace.assertion_count("baz"), 0);
		}
	}
}
