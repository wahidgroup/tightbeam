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
use crate::testing::specs::csp::{intern, Event, Process, ProcessBuilder, State};

/// Add both operands' alphabets to the builder, preserving the
/// observable/hidden classification
fn union_alphabets(builder: ProcessBuilder, p: &Process, q: &Process) -> ProcessBuilder {
	let builder = p
		.observable
		.iter()
		.chain(&q.observable)
		.fold(builder, |b, event| b.add_observable(event.0));

	p.hidden.iter().chain(&q.hidden).fold(builder, |b, event| b.add_hidden(event.0))
}

/// Copy every state of `process` into the builder through `map_state`
fn copy_states<S>(builder: ProcessBuilder, process: &Process, map_state: S) -> ProcessBuilder
where
	S: Fn(&State) -> State,
{
	process.states.iter().fold(builder, |b, state| b.add_state(map_state(state)))
}

/// Copy every terminal state of `process` into the builder through `map_state`
fn copy_terminals<S>(builder: ProcessBuilder, process: &Process, map_state: S) -> ProcessBuilder
where
	S: Fn(&State) -> State,
{
	process
		.terminal
		.iter()
		.fold(builder, |b, state| b.add_terminal(map_state(state)))
}

/// Copy every transition of `process` into the builder, mapping states
/// through `map_state` and events through `map_event`
fn copy_transitions<S, E>(builder: ProcessBuilder, process: &Process, map_state: S, map_event: E) -> ProcessBuilder
where
	S: Fn(&State) -> State,
	E: Fn(Event) -> Event,
{
	let map_state = &map_state;
	let map_event = &map_event;

	process
		.states
		.iter()
		.flat_map(move |state| {
			process.enabled(*state).into_iter().flat_map(move |action| {
				process
					.step(*state, &action.event)
					.into_iter()
					.map(move |target| (map_state(state), map_event(action.event), map_state(&target)))
			})
		})
		.fold(builder, |b, (from, event, to)| b.add_transition(from, event.0, to))
}

/// Prefixed copies of both operands: states, alphabets, transitions, and
/// terminals of `p` under `P_` and `q` under `Q_`. Shared scaffold of the
/// choice operators, which differ only in how their initial state wires
/// into the copies.
fn prefixed_operands(builder: ProcessBuilder, p: &Process, q: &Process) -> ProcessBuilder {
	let builder = copy_states(builder, p, |state| State::prefixed(state, "P"));
	let builder = copy_states(builder, q, |state| State::prefixed(state, "Q"));
	let builder = union_alphabets(builder, p, q);
	let builder = copy_transitions(builder, p, |state| State::prefixed(state, "P"), |event| event);
	let builder = copy_transitions(builder, q, |state| State::prefixed(state, "Q"), |event| event);
	let builder = copy_terminals(builder, p, |state| State::prefixed(state, "P"));

	copy_terminals(builder, q, |state| State::prefixed(state, "Q"))
}

/// Copy the transitions leaving `process`'s initial state so they originate
/// from `from` instead, targeting the prefixed copies (external choice's
/// first-event commitment)
fn fan_out_initial(builder: ProcessBuilder, process: &Process, from: State, prefix: &str) -> ProcessBuilder {
	process
		.enabled(process.initial)
		.into_iter()
		.flat_map(|action| {
			process
				.step(process.initial, &action.event)
				.into_iter()
				.map(move |target| (action.event, State::prefixed(&target, prefix)))
		})
		.fold(builder, |b, (event, target)| b.add_transition(from, event.0, target))
}

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
		let name = intern(format!("({} \\ A)", self.name));
		let builder = copy_states(Process::builder(name).initial_state(self.initial), self, |state| *state);
		let builder = copy_terminals(builder, self, |state| *state);
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
		let builder = copy_transitions(builder, self, |state| *state, |event| event);

		Ok(builder.build()?)
	}

	/// Renaming: P [[ old <- new ]]
	///
	/// Rename events according to the mapping.
	/// All occurrences of old events are replaced with new events.
	///
	/// ## Parameters
	/// - `mapping`: HashMap from old event to new event
	pub fn rename(&self, mapping: HashMap<Event, Event>) -> Result<Process, CompositionError> {
		let name = intern(format!("({} [[r]])", self.name));
		let builder = copy_states(Process::builder(name).initial_state(self.initial), self, |state| *state);
		let builder = copy_terminals(builder, self, |state| *state);
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
		let builder = copy_transitions(builder, self, |state| *state, |event| *mapping.get(&event).unwrap_or(&event));

		Ok(builder.build()?)
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
		let name = intern(format!("({} ; {})", p.name, q.name));
		let builder = copy_states(Process::builder(name).initial_state(p.initial), p, |state| *state);
		let builder = copy_states(builder, q, |state| State::prefixed(state, "Q"));
		let builder = union_alphabets(builder, p, q);
		let builder = copy_transitions(builder, p, |state| *state, |event| event);
		let builder = copy_transitions(builder, q, |state| State::prefixed(state, "Q"), |event| event);

		let q_initial_renamed = State::prefixed(&q.initial, "Q");
		let builder = p.terminal.iter().fold(builder.add_hidden("tau_seq"), |b, p_terminal| {
			b.add_transition(*p_terminal, "tau_seq", q_initial_renamed)
		});

		let builder = copy_terminals(builder, q, |state| State::prefixed(state, "Q"));

		Ok(builder.build()?)
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
		let name = intern(format!("({} [] {})", p.name, q.name));
		let builder = Process::builder(name).initial_state(choice_initial).add_state(choice_initial);
		let builder = prefixed_operands(builder, p, q);
		let builder = fan_out_initial(builder, p, choice_initial, "P");
		let builder = fan_out_initial(builder, q, choice_initial, "Q");

		Ok(builder.build()?)
	}

	/// Internal choice: P |~| Q
	///
	/// Process non-deterministically chooses P or Q.
	/// From initial state, there are two τ-transitions to P and Q initial states.
	pub fn internal_choice(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let choice_initial = State("InternalChoice_Initial");
		let name = intern(format!("({} |~| {})", p.name, q.name));
		let builder = Process::builder(name)
			.initial_state(choice_initial)
			.add_state(choice_initial)
			.add_hidden("tau_choice_p")
			.add_hidden("tau_choice_q");

		let builder = prefixed_operands(builder, p, q);
		let builder = builder
			.add_transition(choice_initial, "tau_choice_p", State::prefixed(&p.initial, "P"))
			.add_transition(choice_initial, "tau_choice_q", State::prefixed(&q.initial, "Q"))
			.add_choice(choice_initial);

		Ok(builder.build()?)
	}
}

impl State {
	/// Create a renamed copy of a state under an operand prefix, used by the
	/// composition operators to keep operand state spaces disjoint
	pub fn prefixed(s: &State, prefix: &str) -> State {
		State(intern(format!("{}_{}", prefix, s.0)))
	}
}

#[cfg(test)]
mod tests {
	use std::borrow::Cow;

	use super::*;
	use crate::testing::assertions::{Assertion, AssertionLabel};
	use crate::testing::specs::csp::{Event, Process, State};
	use crate::trace::ConsumedTrace;

	fn trace_of(labels: &[&'static str]) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		for (seq, label) in labels.iter().enumerate() {
			trace.assertions.push(Assertion::new(
				seq,
				AssertionLabel::Custom(Cow::Borrowed(label)),
				Vec::new(),
				None,
			));
		}
		trace
	}

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
	fn test_hiding_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let hidden_events = [Event("a")].iter().copied().collect();

		let result = p.hide(hidden_events)?;
		assert!(result.hidden.contains(&Event("a")));
		assert!(!result.observable.contains(&Event("a")));
		assert!(result.observable.contains(&Event("b")));

		Ok(())
	}

	#[test]
	fn test_renaming_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let mut mapping = HashMap::new();
		mapping.insert(Event("a"), Event("x"));

		let result = p.rename(mapping)?;
		assert!(result.observable.contains(&Event("x")));
		assert!(!result.observable.contains(&Event("a")));

		Ok(())
	}

	#[test]
	fn test_sequential_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let q = simple_process();

		let result = Process::sequential(&p, &q)?;
		assert!(result.name.contains(";"));
		assert!(result.states.len() >= p.states.len() + q.states.len());

		Ok(())
	}

	#[test]
	fn test_external_choice_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let q = simple_process();

		let result = Process::external_choice(&p, &q)?;
		assert!(result.name.contains("[]"));
		assert!(result.states.len() >= 3);

		Ok(())
	}

	#[test]
	fn test_internal_choice_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let q = simple_process();

		let result = Process::internal_choice(&p, &q)?;
		assert!(result.name.contains("|~|"));
		assert!(result.states.len() >= 3);

		Ok(())
	}

	#[test]
	fn internal_choice_trace_validates_through_tau() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let q = simple_process();
		let composed = Process::internal_choice(&p, &q)?;

		let result = composed.validate_trace(&trace_of(&["a", "b"]));
		assert!(result.valid);

		Ok(())
	}

	#[test]
	fn sequential_trace_validates_across_tau_bridge() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process();
		let q = simple_process();
		let composed = Process::sequential(&p, &q)?;

		let result = composed.validate_trace(&trace_of(&["a", "b", "a", "b"]));
		assert!(result.valid);

		Ok(())
	}
}
