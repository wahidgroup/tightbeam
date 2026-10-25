//! Verification checks for composed CSP processes.
//!
//! Each check walks the process and returns an error of its own:
//! - [`DeadlockChecker`] finds a reachable state that enables no action and is not terminal.
//! - [`LivelockChecker`] finds a reachable state that can diverge.
//! - [`DeterminismChecker`] finds a state where one event leads to more than one state.

use std::collections::{HashMap, HashSet, VecDeque};

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
	/// Checks that each event of each state leads to one state at most.
	///
	/// A process is nondeterministic when one of its states has an event that
	/// leads to more than one state. The check reads every state of the
	/// process, reachable or not.
	///
	/// # Errors
	///
	/// - [`NonDeterminismError`] -- a state has an event that leads to more
	///   than one state, and the error names one such pair.
	pub fn check(process: &Process) -> Result<(), NonDeterminismError> {
		for state in &process.states {
			let event_targets: HashMap<Event, HashSet<State>> =
				process.enabled(*state).into_iter().fold(HashMap::new(), |mut acc, action| {
					let targets = process.step(*state, &action.event);
					acc.entry(action.event).or_insert_with(HashSet::new).extend(targets);
					acc
				});

			if let Some((event, targets)) = event_targets.into_iter().find(|(_, targets)| targets.len() > 1) {
				return Err(NonDeterminismError { state: *state, event, targets: targets.into_iter().collect() });
			}
		}

		Ok(())
	}
}

/// The error of [`DeterminismChecker::check`], which names a state, an event,
/// and the states the event leads to.
#[derive(Debug, Clone)]
pub struct NonDeterminismError {
	/// The state where the event leads to more than one state.
	pub state: State,
	/// The event that leads to more than one state.
	pub event: Event,
	/// Every state that the event leads to from `state`.
	pub targets: Vec<State>,
}

impl std::fmt::Display for NonDeterminismError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Non-determinism at state {}: event {} leads to {} states: {:?}",
			self.state,
			self.event,
			self.targets.len(),
			self.targets
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
	use crate::testing::specs::csp::{Event, Process, ProcessBuildError, State};

	fn deadlock_process() -> Process {
		Process::builder("Deadlock")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_observable(Event("a"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.build()
			.expect("Failed to build process")
	}

	fn non_deadlock_process() -> Process {
		Process::builder("NonDeadlock")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_observable(Event("a"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.add_terminal(State("s1"))
			.build()
			.expect("Failed to build process")
	}

	fn deterministic_process() -> Process {
		Process::builder("Det")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_observable(Event("a"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.add_terminal(State("s1"))
			.build()
			.expect("Failed to build process")
	}

	#[test]
	fn test_deadlock_detection_finds_deadlock() {
		let p = deadlock_process();
		let result = DeadlockChecker::check(&p);
		assert!(result.is_err());
	}

	#[test]
	fn test_deadlock_detection_no_deadlock() {
		let p = non_deadlock_process();
		let result = DeadlockChecker::check(&p);
		assert!(result.is_ok());
	}

	#[test]
	fn test_determinism_check_deterministic() {
		let p = deterministic_process();
		let result = DeterminismChecker::check(&p);
		assert!(result.is_ok());
	}

	#[test]
	fn test_livelock_detection_no_livelock() {
		let p = deterministic_process();
		let result = LivelockChecker::check(&p);
		assert!(result.is_ok());
	}

	/// A process whose hidden `t` and `u` take `s1` to `s2` and back, with the
	/// observable exit `b` at `s2`.
	fn spinning() -> Result<Process, ProcessBuildError> {
		Process::builder("Spinning")
			.initial_state(State("s0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.add_transition(State("s1"), Event("t"), State("s2"))
			.add_transition(State("s2"), Event("u"), State("s1"))
			.add_transition(State("s2"), Event("b"), State("s3"))
			.add_terminal(State("s3"))
			.build()
	}

	#[test]
	fn a_hidden_cycle_with_an_observable_exit_is_a_livelock() -> Result<(), ProcessBuildError> {
		let process = spinning()?;

		let checked = LivelockChecker::check(&process);

		let cycle = checked.err().map(|error| error.cycle);
		let spin = vec![State("s1"), State("s2")];
		assert_eq!(cycle, Some(spin), "the run of `t` and `u` can go on forever");
		Ok(())
	}
}
