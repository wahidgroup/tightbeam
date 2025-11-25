//! CSP Process Algebra Operations
//!
//! Implements core process algebra operations from CSP theory:
//! - Hiding (P \ A)
//! - Renaming (P [[ old <- new ]])
//! - Sequential composition (P ; Q)
//! - External choice (P [] Q)
//! - Internal choice (P |~| Q)

use std::collections::{HashMap, HashSet};

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{Event, Process, State};

impl Process {
	/// Hiding: P \ A
	///
	/// Make events in A hidden (internal τ-transitions).
	/// Observable events become hidden events.
	///
	/// ## Effect
	/// - Events in A are removed from observable alphabet
	/// - Events in A are added to hidden alphabet
	/// - State space and transitions remain unchanged
	pub fn hide(&self, hidden_events: HashSet<Event>) -> Result<Process, CompositionError> {
		let name = Box::leak(format!("({} \\ A)", self.name).into_boxed_str());
		let builder = self
			.states
			.iter()
			.fold(Process::builder(name).initial_state(self.initial), |b, state| {
				b.add_state(*state)
			});

		let builder = self.terminal.iter().fold(builder, |b, state| b.add_terminal(*state));
		let builder = self
			.observable
			.iter()
			.filter(|e| !hidden_events.contains(e))
			.fold(builder, |b, event| b.add_observable(event.0));

		let builder = self
			.observable
			.iter()
			.filter(|e| hidden_events.contains(e))
			.fold(builder, |b, event| b.add_hidden(event.0));

		let builder = self.hidden.iter().fold(builder, |b, event| b.add_hidden(event.0));
		let builder = self
			.states
			.iter()
			.flat_map(|state| {
				self.enabled(*state).into_iter().flat_map(move |action| {
					self.step(*state, &action.event)
						.into_iter()
						.map(move |target| (*state, action.event, target))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// Renaming: P [[ old <- new ]]
	///
	/// Rename events according to the mapping.
	/// All occurrences of old events are replaced with new events.
	///
	/// ## Parameters
	/// - `mapping`: HashMap from old event to new event
	pub fn rename(&self, mapping: HashMap<Event, Event>) -> Result<Process, CompositionError> {
		let name = Box::leak(format!("({} [[r]])", self.name).into_boxed_str());
		let builder = self
			.states
			.iter()
			.fold(Process::builder(name).initial_state(self.initial), |b, state| {
				b.add_state(*state)
			});

		let builder = self.terminal.iter().fold(builder, |b, state| b.add_terminal(*state));
		let observable_events: Vec<Event> = self
			.observable
			.iter()
			.map(|event| *mapping.get(event).unwrap_or(event))
			.collect();

		let builder = observable_events
			.into_iter()
			.fold(builder, |b, event| b.add_observable(event.0));

		let hidden_events: Vec<Event> = self.hidden.iter().map(|event| *mapping.get(event).unwrap_or(event)).collect();
		let builder = hidden_events.into_iter().fold(builder, |b, event| b.add_hidden(event.0));

		let mut transitions = Vec::new();
		for state in &self.states {
			for action in self.enabled(*state) {
				let new_event = *mapping.get(&action.event).unwrap_or(&action.event);
				for target in self.step(*state, &action.event) {
					transitions.push((*state, new_event, target));
				}
			}
		}

		let builder = transitions
			.into_iter()
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// Sequential composition: P ; Q
	///
	/// When P terminates (reaches a terminal state), start Q.
	/// Terminal states of P are connected to initial state of Q.
	///
	/// ## State Space
	/// S = S_P ∪ S_Q (union, but P terminal states connect to Q initial)
	///
	/// ## Transitions
	/// - All P transitions remain
	/// - All Q transitions remain
	/// - P terminal states have τ-transition to Q initial state
	pub fn sequential(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = Box::leak(format!("({} ; {})", p.name, q.name).into_boxed_str());
		let builder = p
			.states
			.iter()
			.fold(Process::builder(name).initial_state(p.initial), |b, state| b.add_state(*state));

		let builder = q
			.states
			.iter()
			.fold(builder, |b, state| b.add_state(State::sequential(state, "Q")));

		let builder = p
			.observable
			.iter()
			.chain(&q.observable)
			.fold(builder, |b, event| b.add_observable(event.0));

		let builder = p.hidden.iter().chain(&q.hidden).fold(builder, |b, event| b.add_hidden(event.0));
		let builder = p
			.states
			.iter()
			.flat_map(|state| {
				p.enabled(*state).into_iter().flat_map(move |action| {
					p.step(*state, &action.event)
						.into_iter()
						.map(move |target| (*state, action.event, target))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		let builder = q
			.states
			.iter()
			.flat_map(|state| {
				let renamed_state = State::sequential(state, "Q");
				q.enabled(*state).into_iter().flat_map(move |action| {
					q.step(*state, &action.event)
						.into_iter()
						.map(move |target| (renamed_state, action.event, State::sequential(&target, "Q")))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		let q_initial_renamed = State::sequential(&q.initial, "Q");
		let builder = p.terminal.iter().fold(builder.add_hidden("tau_seq"), |b, p_terminal| {
			b.add_transition(*p_terminal, "tau_seq", q_initial_renamed)
		});

		let builder = q
			.terminal
			.iter()
			.fold(builder, |b, q_terminal| b.add_terminal(State::sequential(q_terminal, "Q")));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// External choice: P [] Q
	///
	/// Environment determines which process runs.
	/// The first observable event determines the choice.
	///
	/// ## State Space
	/// Initial state offers both P and Q initial states
	/// After first event, committed to one process
	pub fn external_choice(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let choice_initial = State("ExternalChoice_Initial");
		let name = Box::leak(format!("({} [] {})", p.name, q.name).into_boxed_str());

		let builder = p.states.iter().fold(
			Process::builder(name).initial_state(choice_initial).add_state(choice_initial),
			|b, state| b.add_state(State::prefixed(state, "P")),
		);

		let builder = q
			.states
			.iter()
			.fold(builder, |b, state| b.add_state(State::prefixed(state, "Q")));

		let builder = p
			.observable
			.iter()
			.chain(&q.observable)
			.fold(builder, |b, event| b.add_observable(event.0));

		let builder = p.hidden.iter().chain(&q.hidden).fold(builder, |b, event| b.add_hidden(event.0));
		let builder = p
			.enabled(p.initial)
			.into_iter()
			.flat_map(|action| {
				p.step(p.initial, &action.event)
					.into_iter()
					.map(move |target| (action.event, State::prefixed(&target, "P")))
			})
			.fold(builder, |b, (event, target)| b.add_transition(choice_initial, event.0, target));

		let builder = q
			.enabled(q.initial)
			.into_iter()
			.flat_map(|action| {
				q.step(q.initial, &action.event)
					.into_iter()
					.map(move |target| (action.event, State::prefixed(&target, "Q")))
			})
			.fold(builder, |b, (event, target)| b.add_transition(choice_initial, event.0, target));

		let builder = p
			.states
			.iter()
			.flat_map(|state| {
				let prefixed_state = State::prefixed(state, "P");
				p.enabled(*state).into_iter().flat_map(move |action| {
					p.step(*state, &action.event)
						.into_iter()
						.map(move |target| (prefixed_state, action.event, State::prefixed(&target, "P")))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		let builder = q
			.states
			.iter()
			.flat_map(|state| {
				let prefixed_state = State::prefixed(state, "Q");
				q.enabled(*state).into_iter().flat_map(move |action| {
					q.step(*state, &action.event)
						.into_iter()
						.map(move |target| (prefixed_state, action.event, State::prefixed(&target, "Q")))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		let builder = p
			.terminal
			.iter()
			.fold(builder, |b, p_terminal| b.add_terminal(State::prefixed(p_terminal, "P")));

		let builder = q
			.terminal
			.iter()
			.fold(builder, |b, q_terminal| b.add_terminal(State::prefixed(q_terminal, "Q")));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// Internal choice: P |~| Q
	///
	/// Process non-deterministically chooses P or Q.
	/// From initial state, there are two τ-transitions to P and Q initial states.
	pub fn internal_choice(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let choice_initial = State("InternalChoice_Initial");
		let name = Box::leak(format!("({} |~| {})", p.name, q.name).into_boxed_str());
		let builder = p.states.iter().fold(
			Process::builder(name)
				.initial_state(choice_initial)
				.add_state(choice_initial)
				.add_hidden("tau_choice_p")
				.add_hidden("tau_choice_q"),
			|b, state| b.add_state(State::prefixed(state, "P")),
		);

		let builder = q
			.states
			.iter()
			.fold(builder, |b, state| b.add_state(State::prefixed(state, "Q")));

		let builder = p
			.observable
			.iter()
			.chain(&q.observable)
			.fold(builder, |b, event| b.add_observable(event.0));

		let builder = p.hidden.iter().chain(&q.hidden).fold(builder, |b, event| b.add_hidden(event.0));
		let p_prefixed_initial = State::prefixed(&p.initial, "P");
		let q_prefixed_initial = State::prefixed(&q.initial, "Q");
		let builder = builder
			.add_transition(choice_initial, "tau_choice_p", p_prefixed_initial)
			.add_transition(choice_initial, "tau_choice_q", q_prefixed_initial)
			.add_choice(choice_initial);

		let builder = p
			.states
			.iter()
			.flat_map(|state| {
				let prefixed_state = State::prefixed(state, "P");
				p.enabled(*state).into_iter().flat_map(move |action| {
					p.step(*state, &action.event)
						.into_iter()
						.map(move |target| (prefixed_state, action.event, State::prefixed(&target, "P")))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		let builder = q
			.states
			.iter()
			.flat_map(|state| {
				let prefixed_state = State::prefixed(state, "Q");
				q.enabled(*state).into_iter().flat_map(move |action| {
					q.step(*state, &action.event)
						.into_iter()
						.map(move |target| (prefixed_state, action.event, State::prefixed(&target, "Q")))
				})
			})
			.fold(builder, |b, (state, event, target)| b.add_transition(state, event.0, target));

		let builder = p
			.terminal
			.iter()
			.fold(builder, |b, p_terminal| b.add_terminal(State::prefixed(p_terminal, "P")));

		let builder = q
			.terminal
			.iter()
			.fold(builder, |b, q_terminal| b.add_terminal(State::prefixed(q_terminal, "Q")));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}
}

impl State {
	/// Create a state with sequential composition prefix
	pub fn sequential(s: &State, prefix: &str) -> State {
		let name = Box::leak(format!("{}_{}", prefix, s.0).into_boxed_str());
		State(name)
	}

	/// Create a state with a prefix (for choice operators)
	pub fn prefixed(s: &State, prefix: &str) -> State {
		let name = Box::leak(format!("{}_{}", prefix, s.0).into_boxed_str());
		State(name)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::{Event, Process, State};

	fn simple_process() -> Process {
		Process::builder("P")
			.initial_state(State("s0"))
			.add_state(State("s0"))
			.add_state(State("s1"))
			.add_state(State("s2"))
			.add_observable("a")
			.add_observable("b")
			.add_transition(State("s0"), "a", State("s1"))
			.add_transition(State("s1"), "b", State("s2"))
			.add_terminal(State("s2"))
			.build()
			.expect("Failed to build process")
	}

	#[test]
	fn test_hiding_basic() {
		let p = simple_process();
		let hidden_events = [Event("a")].iter().copied().collect();

		let result = p.hide(hidden_events).expect("Hide failed");
		assert!(result.hidden.contains(&Event("a")));
		assert!(!result.observable.contains(&Event("a")));
		assert!(result.observable.contains(&Event("b")));
	}

	#[test]
	fn test_renaming_basic() {
		let p = simple_process();
		let mut mapping = HashMap::new();
		mapping.insert(Event("a"), Event("x"));

		let result = p.rename(mapping).expect("Rename failed");
		assert!(result.observable.contains(&Event("x")));
		assert!(!result.observable.contains(&Event("a")));
	}

	#[test]
	fn test_sequential_basic() {
		let p = simple_process();
		let q = simple_process();

		let result = Process::sequential(&p, &q).expect("Sequential failed");
		assert!(result.name.contains(";"));
		assert!(result.states.len() >= p.states.len() + q.states.len());
	}

	#[test]
	fn test_external_choice_basic() {
		let p = simple_process();
		let q = simple_process();

		let result = Process::external_choice(&p, &q).expect("External choice failed");
		assert!(result.name.contains("[]"));
		assert!(result.states.len() >= 3);
	}

	#[test]
	fn test_internal_choice_basic() {
		let p = simple_process();
		let q = simple_process();

		let result = Process::internal_choice(&p, &q).expect("Internal choice failed");
		assert!(result.name.contains("|~|"));
		assert!(result.states.len() >= 3);
	}
}
