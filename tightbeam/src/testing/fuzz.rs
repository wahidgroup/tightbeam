//! Fuzzing support utilities
//!
//! Provides helpers for fuzzing tightbeam components with AFL.rs or other fuzzers.
//! Key feature: CSP-guided fuzzing using `CspOracle` for intelligent state exploration.

#![cfg(all(feature = "std", feature = "testing-csp"))]

use crate::testing::specs::csp::{Event, Process, State};
use std::collections::HashSet;

/// CSP state oracle for guided fuzzing
///
/// Tracks execution through a CSP process state machine, providing:
/// - Valid next events at each state
/// - State exploration coverage metrics
/// - State hashing for IJON-guided fuzzing
#[derive(Debug, Clone)]
pub struct CspOracle {
	process: Process,
	current_state: State,
	visited_states: HashSet<State>,
	visited_transitions: HashSet<(State, Event)>,
	trace: Vec<Event>,
}

impl CspOracle {
	/// Create a new CSP oracle from a process specification
	pub fn new(process: Process) -> Self {
		let initial = process.initial;
		let mut visited_states = HashSet::new();
		visited_states.insert(initial);

		Self {
			process,
			current_state: initial,
			visited_states,
			visited_transitions: HashSet::new(),
			trace: Vec::new(),
		}
	}

	/// Get the current state
	pub fn current_state(&self) -> State {
		self.current_state
	}

	/// Get all visited states
	pub fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	/// Get all visited transitions
	pub fn visited_transitions(&self) -> &HashSet<(State, Event)> {
		&self.visited_transitions
	}

	/// Get the execution trace
	pub fn trace(&self) -> &[Event] {
		&self.trace
	}

	/// Check if current state is terminal
	pub fn is_terminal(&self) -> bool {
		self.process.is_terminal(self.current_state)
	}

	/// Get list of valid events from current state
	///
	/// Returns only observable events that can be taken from the current state.
	/// Returns empty if in terminal state.
	pub fn valid_events(&self) -> Vec<Event> {
		if self.is_terminal() {
			return Vec::new();
		}

		self.process
			.enabled(self.current_state)
			.iter()
			.filter(|a| a.is_observable())
			.map(|a| a.event.clone())
			.collect()
	}

	/// Attempt to take a transition with the given event
	///
	/// Returns `true` if transition succeeded, `false` if event not enabled.
	/// Updates current state and tracking metrics on success.
	pub fn step(&mut self, event: &Event) -> bool {
		let next_states = self.process.step(self.current_state, event);

		if next_states.is_empty() {
			return false;
		}

		// Record transition
		self.visited_transitions.insert((self.current_state, event.clone()));
		self.trace.push(event.clone());

		// Take first state (deterministic or first choice)
		self.current_state = next_states[0];
		self.visited_states.insert(self.current_state);

		true
	}

	/// Reset oracle to initial state
	pub fn reset(&mut self) {
		let initial = self.process.initial;
		self.current_state = initial;
		self.visited_states.clear();
		self.visited_states.insert(initial);
		self.visited_transitions.clear();
		self.trace.clear();
	}

	/// Get hash of current state for IJON tracking
	///
	/// Returns a stable hash that can be used with `afl::ijon_set!()` to guide
	/// AFL toward unexplored states.
	pub fn track_state(&self) -> u32 {
		use std::collections::hash_map::DefaultHasher;
		use std::hash::{Hash, Hasher};

		let mut hasher = DefaultHasher::new();
		self.current_state.hash(&mut hasher);
		hasher.finish() as u32
	}

	/// Get coverage score for IJON maximization
	///
	/// Returns combined metric of state and transition coverage.
	/// Upper 32 bits: number of visited states
	/// Lower 32 bits: number of visited transitions
	///
	/// Use with `afl::ijon_max!()` to guide AFL toward maximum coverage.
	pub fn coverage_score(&self) -> u64 {
		((self.visited_states.len() as u64) << 32) | (self.visited_transitions.len() as u64)
	}

	/// Get state space coverage percentage
	pub fn state_coverage(&self) -> f64 {
		let total_states = self.process.states.len();
		if total_states == 0 {
			return 0.0;
		}
		(self.visited_states.len() as f64) / (total_states as f64) * 100.0
	}

	/// Get transition coverage statistics
	pub fn transition_coverage(&self) -> (usize, usize) {
		// Count total possible transitions
		let mut total_transitions = 0;
		for state in &self.process.states {
			for event in self.process.observable.iter().chain(&self.process.hidden) {
				if self.process.transitions.targets(*state, event).is_some() {
					total_transitions += 1;
				}
			}
		}

		(self.visited_transitions.len(), total_transitions)
	}

	/// Run oracle-guided fuzzing from arbitrary byte input
	///
	/// Interprets input bytes as choices for which events to take at each state.
	/// This is the core fuzzing harness for AFL.rs integration.
	///
	/// Returns `Ok(())` if execution reaches terminal state, `Err` otherwise.
	///
	/// # Example
	///
	/// ```ignore
	/// // In AFL.rs fuzz target:
	/// afl::fuzz!(|data: &[u8]| {
	///     let proc = MyProcess::process();
	///     let mut oracle = CspOracle::new(proc);
	///
	///     if oracle.fuzz_from_bytes(data).is_ok() {
	///         // Track coverage for IJON
	///         afl::ijon_max!("coverage", oracle.coverage_score());
	///     }
	/// });
	/// ```
	pub fn fuzz_from_bytes(&mut self, input: &[u8]) -> Result<(), &'static str> {
		self.reset();
		let mut byte_idx = 0;

		while !self.is_terminal() && byte_idx < input.len() {
			let valid = self.valid_events();
			if valid.is_empty() {
				return Err("deadlock: no valid events");
			}

			// Use input byte to choose which event to take
			let choice = (input[byte_idx] as usize) % valid.len();
			let event = &valid[choice];

			if !self.step(event) {
				return Err("oracle rejected valid event");
			}

			byte_idx += 1;
		}

		if self.is_terminal() {
			Ok(())
		} else {
			Err("input exhausted before terminal state")
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn oracle_tracks_state_transitions() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("go")
			.add_observable("stop")
			.add_transition(State("S0"), "go", State("S1"))
			.add_transition(State("S1"), "stop", State("S2"))
			.add_terminal(State("S2"))
			.build()
			.unwrap();

		let mut oracle = CspOracle::new(proc);

		// Initial state
		assert_eq!(oracle.current_state(), State("S0"));
		assert_eq!(oracle.visited_states().len(), 1);
		assert!(!oracle.is_terminal());

		// Valid events at S0
		let valid = oracle.valid_events();
		assert_eq!(valid.len(), 1);
		assert_eq!(valid[0].0, "go");

		// Take transition
		assert!(oracle.step(&Event("go")));
		assert_eq!(oracle.current_state(), State("S1"));
		assert_eq!(oracle.visited_states().len(), 2);
		assert_eq!(oracle.visited_transitions().len(), 1);
		assert_eq!(oracle.trace().len(), 1);

		// Take second transition
		assert!(oracle.step(&Event("stop")));
		assert_eq!(oracle.current_state(), State("S2"));
		assert!(oracle.is_terminal());
		assert_eq!(oracle.valid_events().len(), 0);
	}

	#[test]
	fn oracle_rejects_invalid_events() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("valid")
			.add_transition(State("S0"), "valid", State("S1"))
			.add_terminal(State("S1"))
			.build()
			.unwrap();

		let mut oracle = CspOracle::new(proc);

		// Invalid event should fail
		assert!(!oracle.step(&Event("invalid")));
		assert_eq!(oracle.current_state(), State("S0"));
		assert_eq!(oracle.visited_transitions().len(), 0);
	}

	#[test]
	fn oracle_reset() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("go")
			.add_transition(State("S0"), "go", State("S1"))
			.add_terminal(State("S1"))
			.build()
			.unwrap();

		let mut oracle = CspOracle::new(proc);

		// Take transition
		oracle.step(&Event("go"));
		assert_eq!(oracle.current_state(), State("S1"));

		// Reset
		oracle.reset();
		assert_eq!(oracle.current_state(), State("S0"));
		assert_eq!(oracle.visited_states().len(), 1);
		assert_eq!(oracle.visited_transitions().len(), 0);
		assert_eq!(oracle.trace().len(), 0);
	}

	#[test]
	fn oracle_coverage_metrics() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("a")
			.add_observable("b")
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S1"), "b", State("S2"))
			.add_terminal(State("S2"))
			.build()
			.unwrap();

		let mut oracle = CspOracle::new(proc);

		// Initial coverage
		let coverage = oracle.state_coverage();
		assert!((coverage - 33.33).abs() < 0.1); // 1/3 states

		// After one transition
		oracle.step(&Event("a"));
		let coverage = oracle.state_coverage();
		assert!((coverage - 66.66).abs() < 0.1); // 2/3 states

		// After second transition
		oracle.step(&Event("b"));
		let coverage = oracle.state_coverage();
		assert!((coverage - 100.0).abs() < 0.1); // 3/3 states

		// Transition coverage
		let (visited, _total) = oracle.transition_coverage();
		assert_eq!(visited, 2);
	}

	#[test]
	fn oracle_track_state_is_stable() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("go")
			.add_transition(State("S0"), "go", State("S1"))
			.add_terminal(State("S1"))
			.build()
			.unwrap();

		// Same state should produce same hash
		let oracle1 = CspOracle::new(proc.clone());
		let oracle2 = CspOracle::new(proc);
		assert_eq!(oracle1.track_state(), oracle2.track_state());
	}

	#[test]
	fn oracle_coverage_score_increases() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("go")
			.add_transition(State("S0"), "go", State("S1"))
			.add_terminal(State("S1"))
			.build()
			.unwrap();

		let mut oracle = CspOracle::new(proc);
		let score1 = oracle.coverage_score();

		oracle.step(&Event("go"));

		// Score should increase after visiting new state/transition
		let score2 = oracle.coverage_score();
		assert!(score2 > score1);
	}

	#[test]
	fn oracle_with_choice_points() {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("choice")
			.add_transition(State("S0"), "choice", State("S1"))
			.add_transition(State("S0"), "choice", State("S2"))
			.add_choice(State("S0"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()
			.unwrap();

		let mut oracle = CspOracle::new(proc);

		// Should provide valid event
		let valid = oracle.valid_events();
		assert_eq!(valid.len(), 1);
		assert_eq!(valid[0].0, "choice");

		// Step should succeed (takes first choice)
		assert!(oracle.step(&Event("choice")));
		assert_eq!(oracle.current_state(), State("S1"));
	}

	mod scenario {
		use crate::testing::assertions::AssertionPhase;

		// Define assertion spec for runtime validation
		crate::tb_assert_spec! {
			pub FuzzGuidedSpec,
			V(1,0,0): {
				mode: Accept,
				gate: Accepted,
				assertions: [
					(HandlerStart, "start", crate::exactly!(1)),
					(HandlerStart, "action_a", crate::at_least!(0)),
					(HandlerStart, "action_b", crate::at_least!(0)),
					(HandlerStart, "done", crate::exactly!(1))
				]
			},
		}

		// Define CSP process to guide fuzzing
		crate::tb_process_spec! {
			pub struct FuzzGuidedProc;
			events {
				observable { "start", "action_a", "action_b", "done" }
				hidden { }
			}
			states {
				S0 => { "start" => S1 },
				S1 => { "action_a" => S1, "action_b" => S1, "done" => S2 }
			}
			terminal { S2 }
		}

		// Define fuzz specification - generates random byte sequences
		crate::tb_fuzz_spec! {
			pub FuzzRandomInputs,
			test_cases: 50,
			input_length: 4, 8,
			seed: 0x12345678,
			print_stats: true
		}

		// Demonstrates: fuzz: generates iterations, CSP validates traces
		crate::tb_scenario! {
			name: fuzz_test_random_inputs,
			spec: FuzzGuidedSpec,
			csp: FuzzGuidedProc,
			fuzz: FuzzRandomInputs,
			environment Bare {
				exec: |trace| {
					// Always start
					trace.assert(AssertionPhase::HandlerStart, "start");

					// Use fuzz input to guide which actions to take
					while trace.fuzz_has_bytes(1)? {
						let choice = trace.fuzz_u8()? % 3;
						match choice {
							0 => trace.assert(AssertionPhase::HandlerStart, "action_a"),
							1 => trace.assert(AssertionPhase::HandlerStart, "action_b"),
							_ => break,
						}
					}

					// Always end
					trace.assert(AssertionPhase::HandlerStart, "done");
					Ok(())
				}
			}
		}
	}
}
