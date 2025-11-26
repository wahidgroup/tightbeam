//! CSP Verification Algorithms
//!
//! Implements verification algorithms for composed processes:
//! - Deadlock detection
//! - Livelock detection
//! - Determinism checking
//! - Refinement verification

use std::collections::{HashMap, HashSet, VecDeque};

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{Event, Process, State};

/// Deadlock checker for CSP processes
pub struct DeadlockChecker;

impl DeadlockChecker {
	/// Check if process is deadlock-free
	///
	/// A deadlock is a state with:
	/// 1. No enabled transitions
	/// 2. Not in terminal set
	///
	/// Returns the first deadlock state found, or Ok(()) if deadlock-free.
	pub fn check(process: &Process) -> Result<(), DeadlockError> {
		// BFS to explore all reachable states
		let mut visited = HashSet::new();
		let mut queue = VecDeque::new();

		queue.push_back(process.initial);
		visited.insert(process.initial);

		while let Some(state) = queue.pop_front() {
			// Check if this is a deadlock: no transitions and not terminal
			let enabled = process.enabled(state);
			if enabled.is_empty() && !process.terminal.contains(&state) {
				return Err(DeadlockError { state });
			}

			// Explore successors
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

/// Deadlock error
#[derive(Debug, Clone)]
pub struct DeadlockError {
	pub state: State,
}

impl std::fmt::Display for DeadlockError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Deadlock detected at state {}", self.state)
	}
}

impl std::error::Error for DeadlockError {}

/// Livelock checker for CSP processes
pub struct LivelockChecker;

impl LivelockChecker {
	/// Check if process is livelock-free
	///
	/// A livelock is a cycle reachable only via hidden (τ) events.
	/// Uses Tarjan's SCC algorithm to detect strongly connected components
	/// in the hidden event graph.
	pub fn check(process: &Process) -> Result<(), LivelockError> {
		// Build graph of hidden transitions only
		let hidden_graph: HashMap<State, HashSet<State>> = process
			.states
			.iter()
			.map(|state| {
				let hidden_successors = process
					.enabled(*state)
					.into_iter()
					.filter(|action| process.hidden.contains(&action.event))
					.flat_map(|action| process.step(*state, &action.event))
					.collect();
				(*state, hidden_successors)
			})
			.collect();

		// Find SCCs using Tarjan's algorithm
		let sccs = Self::tarjan_scc(&hidden_graph, process.initial);

		// Check if any SCC has size > 1 and is reachable only via hidden events
		sccs.into_iter()
			.find(|scc| scc.len() > 1 && Self::is_hidden_cycle(scc, &hidden_graph, process))
			.map_or(Ok(()), |scc| Err(LivelockError { cycle: scc }))
	}

	/// Tarjan's SCC algorithm
	fn tarjan_scc(graph: &HashMap<State, HashSet<State>>, initial: State) -> Vec<Vec<State>> {
		let mut index = 0;
		let mut stack = Vec::new();
		let mut indices: HashMap<State, usize> = HashMap::new();
		let mut low_links: HashMap<State, usize> = HashMap::new();
		let mut on_stack: HashSet<State> = HashSet::new();
		let mut sccs = Vec::new();

		#[allow(clippy::too_many_arguments)]
		fn strong_connect(
			v: State,
			graph: &HashMap<State, HashSet<State>>,
			index: &mut usize,
			stack: &mut Vec<State>,
			indices: &mut HashMap<State, usize>,
			low_links: &mut HashMap<State, usize>,
			on_stack: &mut HashSet<State>,
			sccs: &mut Vec<Vec<State>>,
		) {
			indices.insert(v, *index);
			low_links.insert(v, *index);
			*index += 1;
			stack.push(v);
			on_stack.insert(v);

			if let Some(successors) = graph.get(&v) {
				for &w in successors {
					if !indices.contains_key(&w) {
						strong_connect(w, graph, index, stack, indices, low_links, on_stack, sccs);
						let w_low_link = *low_links.get(&w).unwrap_or(&usize::MAX);
						let v_low_link = *low_links.get(&v).unwrap_or(&usize::MAX);
						low_links.insert(v, v_low_link.min(w_low_link));
					} else if on_stack.contains(&w) {
						let w_index = *indices.get(&w).unwrap_or(&usize::MAX);
						let v_low_link = *low_links.get(&v).unwrap_or(&usize::MAX);
						low_links.insert(v, v_low_link.min(w_index));
					}
				}
			}

			if low_links.get(&v) == indices.get(&v) {
				let mut scc = Vec::new();
				loop {
					let w = stack.pop().expect("Stack underflow in Tarjan");
					on_stack.remove(&w);
					scc.push(w);
					if w == v {
						break;
					}
				}
				sccs.push(scc);
			}
		}

		// Run for all states reachable from initial
		let mut to_visit: HashSet<State> = HashSet::new();
		let mut visited = HashSet::new();
		to_visit.insert(initial);

		while let Some(&state) = to_visit.iter().next() {
			to_visit.remove(&state);
			if visited.insert(state) {
				if let Some(successors) = graph.get(&state) {
					for &successor in successors {
						if !visited.contains(&successor) {
							to_visit.insert(successor);
						}
					}
				}

				if !indices.contains_key(&state) {
					strong_connect(
						state,
						graph,
						&mut index,
						&mut stack,
						&mut indices,
						&mut low_links,
						&mut on_stack,
						&mut sccs,
					);
				}
			}
		}

		sccs
	}

	/// Check if SCC forms a hidden cycle (livelock)
	fn is_hidden_cycle(scc: &[State], _hidden_graph: &HashMap<State, HashSet<State>>, process: &Process) -> bool {
		// If cycle has any observable events that lead out of SCC, it's not a livelock
		!scc.iter().any(|&state| {
			process
				.enabled(state)
				.into_iter()
				.filter(|action| process.observable.contains(&action.event))
				.any(|action| {
					process
						.step(state, &action.event)
						.into_iter()
						.any(|target| !scc.contains(&target))
				})
		})
	}
}

/// Livelock error
#[derive(Debug, Clone)]
pub struct LivelockError {
	pub cycle: Vec<State>,
}

impl std::fmt::Display for LivelockError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Livelock detected in cycle: {:?}", self.cycle)
	}
}

impl std::error::Error for LivelockError {}

/// Determinism checker for CSP processes
pub struct DeterminismChecker;

impl DeterminismChecker {
	/// Check if process is deterministic
	///
	/// A process is non-deterministic if any state has the same event
	/// leading to multiple different target states.
	pub fn check(process: &Process) -> Result<(), NonDeterminismError> {
		for state in &process.states {
			// Group transitions by event and check for multiple targets
			let event_targets: HashMap<Event, HashSet<State>> =
				process.enabled(*state).into_iter().fold(HashMap::new(), |mut acc, action| {
					let targets = process.step(*state, &action.event);
					acc.entry(action.event).or_insert_with(HashSet::new).extend(targets);
					acc
				});

			// Find first non-deterministic event
			if let Some((event, targets)) = event_targets.into_iter().find(|(_, targets)| targets.len() > 1) {
				return Err(NonDeterminismError { state: *state, event, targets: targets.into_iter().collect() });
			}
		}

		Ok(())
	}
}

/// Non-determinism error
#[derive(Debug, Clone)]
pub struct NonDeterminismError {
	pub state: State,
	pub event: Event,
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

/// Convert verification errors to CompositionError
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
	use crate::testing::specs::csp::{Process, State};

	fn deadlock_process() -> Process {
		Process::builder("Deadlock")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_observable("a")
			.add_transition(State("s0"), "a", State("s1"))
			.build()
			.expect("Failed to build process")
	}

	fn non_deadlock_process() -> Process {
		Process::builder("NonDeadlock")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_observable("a")
			.add_transition(State("s0"), "a", State("s1"))
			.add_terminal(State("s1"))
			.build()
			.expect("Failed to build process")
	}

	fn deterministic_process() -> Process {
		Process::builder("Det")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_observable("a")
			.add_transition(State("s0"), "a", State("s1"))
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
}
