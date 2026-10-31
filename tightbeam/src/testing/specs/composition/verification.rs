//! Verification checks for composed CSP processes.
//!
//! Each check walks the process and returns an error of its own:
//! - [`DeadlockChecker`] finds a reachable state that enables no action and is not terminal.
//! - [`LivelockChecker`] finds a reachable state that can diverge.
//! - [`DeterminismChecker`] finds a hidden action, or a state where one event leads to more than one state.

use std::collections::{HashSet, VecDeque};

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{Event, Process, State};

/// The deadlock check for a CSP process.
pub struct DeadlockChecker;

impl DeadlockChecker {
	/// Checks that each state the process reaches enables an action or is
	/// terminal.
	///
	/// A deadlock is a state that meets both conditions:
	/// 1. It enables no action.
	/// 2. It is not a terminal state.
	///
	/// # Errors
	///
	/// - [`DeadlockError`] -- a reachable state is a deadlock, and the error
	///   names the first one the search finds.
	pub fn check(process: &Process) -> Result<(), DeadlockError> {
		// The search is breadth-first, so the first deadlock it finds is one
		// that the fewest steps reach.
		let mut visited = HashSet::new();
		let mut queue = VecDeque::new();

		queue.push_back(process.initial);
		visited.insert(process.initial);

		while let Some(state) = queue.pop_front() {
			let enabled = process.enabled(state);
			if enabled.is_empty() && !process.terminal.contains(&state) {
				return Err(DeadlockError { state });
			}

			for action in enabled {
				let successors = process.step(state, &action.event);
				for successor in successors {
					if visited.insert(successor) {
						queue.push_back(successor);
					}
				}
			}
		}

		Ok(())
	}
}

/// The error of [`DeadlockChecker::check`], which names a deadlocked state.
#[derive(Debug, Clone)]
pub struct DeadlockError {
	/// The reachable state that enables no action and is not terminal.
	pub state: State,
}

impl std::fmt::Display for DeadlockError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Deadlock detected at state {}", self.state)
	}
}

impl std::error::Error for DeadlockError {}

/// The livelock check for a CSP process.
pub struct LivelockChecker;

impl LivelockChecker {
	/// Checks that each state the process reaches is free of divergence.
	///
	/// A livelock is a reachable state from which a run of hidden events
	/// reaches a cycle of hidden events. A cycle with an observable exit is a
	/// livelock too, because the run can stay on the cycle.
	///
	/// [`Process::divergent_states`] decides each state, and the check reads
	/// that answer at each state that the process reaches.
	///
	/// # Errors
	///
	/// - [`LivelockError`] -- a reachable state can diverge, and the error holds the cycle of its witness.
	pub fn check(process: &Process) -> Result<(), LivelockError> {
		let divergent = process.divergent_states();
		let mut visited = HashSet::from([process.initial]);
		let mut queue = VecDeque::from([process.initial]);

		while let Some(state) = queue.pop_front() {
			if let Some(cycle) = divergent.cycle(state) {
				return Err(LivelockError { cycle });
			}

			for action in process.enabled(state) {
				let successors = process.step(state, &action.event);
				let unvisited = successors.into_iter().filter(|successor| visited.insert(*successor));
				queue.extend(unvisited);
			}
		}

		Ok(())
	}
}

/// The error of [`LivelockChecker::check`], which holds the cycle of a
/// witness.
#[derive(Debug, Clone)]
pub struct LivelockError {
	/// The states of the cycle of hidden events, in the order the run passes
	/// them.
	pub cycle: Vec<State>,
}

impl std::fmt::Display for LivelockError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Livelock detected in cycle: {:?}", self.cycle)
	}
}

impl std::error::Error for LivelockError {}

/// The determinism check for a CSP process.
pub struct DeterminismChecker;

impl DeterminismChecker {
	/// Checks that the process is structurally deterministic, by the rule of
	/// [`Process::determinism_witness`]: no state enables a hidden action, and
	/// each event of each state leads to one state at most.
	///
	/// # Errors
	///
	/// - [`NonDeterminismError`] -- the process has a witness, which the error names with its targets.
	pub fn check(process: &Process) -> Result<(), NonDeterminismError> {
		let Some((state, event)) = process.determinism_witness() else {
			return Ok(());
		};

		let mut targets = process.step(state, &event);
		targets.sort_unstable();
		targets.dedup();

		Err(NonDeterminismError { state, event, targets })
	}
}

/// The error of [`DeterminismChecker::check`], which names a state, an event,
/// and the states the event leads to.
#[derive(Debug, Clone)]
pub struct NonDeterminismError {
	/// The state of the witness.
	pub state: State,
	/// The hidden event, or the event that leads to more than one state.
	pub event: Event,
	/// Every state that the event leads to from `state`, sorted by name.
	pub targets: Vec<State>,
}

impl std::fmt::Display for NonDeterminismError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Non-determinism at state {}: event {} is hidden or branches, and leads to {:?}",
			self.state, self.event, self.targets
		)
	}
}

impl std::error::Error for NonDeterminismError {}

/// A deadlock becomes [`CompositionError::DeadlockDetected`] at the same state.
impl From<DeadlockError> for CompositionError {
	fn from(e: DeadlockError) -> Self {
		CompositionError::DeadlockDetected { state: e.state }
	}
}

impl From<LivelockError> for CompositionError {
	fn from(e: LivelockError) -> Self {
		CompositionError::LivelockDetected { cycle: e.cycle }
	}
}

impl From<NonDeterminismError> for CompositionError {
	fn from(e: NonDeterminismError) -> Self {
		CompositionError::NonDeterminismDetected { state: e.state, events: vec![e.event] }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::fixtures::TestProcess;

	/// One property check over a process, as whether the process passes it.
	type Check = fn(&Process) -> bool;

	/// A process in which `a` takes `s0` to `s1`, which is not terminal and
	/// enables nothing.
	fn stuck_after_a() -> Process {
		TestProcess {
			observable: &["a"],
			transitions: &[("s0", "a", "s1")],
			..TestProcess::of("Deadlock", "s0")
		}
		.build()
	}

	/// A process in which `a` takes `s0` to the terminal `s1`.
	fn a_once() -> Process {
		TestProcess::chain("Det", &["s0", "s1"], &["a"])
	}

	/// A process where `x` and `y` each lead from every state of `a` to `l`
	/// to the four states `t0` to `t3`.
	fn nondeterministic_everywhere() -> Process {
		let sources = ["f", "c", "a", "e", "b", "d", "l", "h", "k", "g", "j", "i"];
		let targets = ["t2", "t0", "t3", "t1"];
		let mut builder = Process::builder("Everywhere")
			.initial_state(State("a"))
			.add_observable(Event("y"))
			.add_observable(Event("x"));

		for from in sources {
			for event in ["y", "x"] {
				for to in targets {
					builder = builder.add_transition(State(from), Event(event), State(to));
				}
			}
		}

		builder.build().expect("a process with an initial state builds")
	}

	/// A deadlock names the first state that enables nothing and is not
	/// terminal.
	#[test]
	fn a_state_that_enables_nothing_and_is_not_terminal_is_a_deadlock() {
		let process = stuck_after_a();
		let checked = DeadlockChecker::check(&process);
		assert_eq!(checked.err().map(|error| error.state), Some(State("s1")));
	}

	// Each check passes a chain that ends in a terminal state.
	crate::tb_cases! {
		fn a_chain_to_a_terminal_state_passes_the_check(check: Check) {
			let process = a_once();
			let passed = check(&process);
			assert!(passed);
		}

		cases {
			of_deadlock => |process| DeadlockChecker::check(process).is_ok(),
			of_determinism => |process| DeterminismChecker::check(process).is_ok(),
			of_livelock => |process| LivelockChecker::check(process).is_ok(),
		}
	}

	/// The witness of nondeterminism names the first state and event by name,
	/// with the targets sorted.
	#[test]
	fn the_witness_names_the_first_state_and_event_by_name_with_sorted_targets() {
		let process = nondeterministic_everywhere();
		let checked = DeterminismChecker::check(&process);

		let witness = checked.err().map(|error| (error.state, error.event, error.targets));
		let targets = vec![State("t0"), State("t1"), State("t2"), State("t3")];
		assert_eq!(witness, Some((State("a"), Event("x"), targets)));
	}

	/// A hidden cycle with an observable exit is a livelock, and the error
	/// names the states of the cycle.
	#[test]
	fn a_hidden_cycle_with_an_observable_exit_is_a_livelock() {
		let process = TestProcess::spinning();
		let checked = LivelockChecker::check(&process);

		let cycle = checked.err().map(|error| error.cycle);
		let spin = vec![State("S1"), State("S2")];
		assert_eq!(cycle, Some(spin));
	}
}
