//! CSP process algebra operations.
//!
//! This module implements these operators of CSP theory on [`Process`]:
//! - Hiding: `P \ A`.
//! - Renaming: `P [[ old <- new ]]`.
//! - Sequential composition: `P ; Q`.
//! - External choice: `P [] Q`.
//! - Internal choice: `P |~| Q`.

use std::collections::{HashMap, HashSet};

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{intern, Event, Process, ProcessBuilder, State};

impl ProcessBuilder {
	/// Add the alphabets of both operands, and keep each event in its
	/// observable or hidden alphabet.
	fn union_alphabets(self, p: &Process, q: &Process) -> Self {
		let builder = p
			.observable
			.iter()
			.chain(&q.observable)
			.fold(self, |b, event| b.add_observable(event));

		p.hidden.iter().chain(&q.hidden).fold(builder, |b, event| b.add_hidden(event))
	}

	/// Copy every state of `process` through `map_state`.
	fn copy_states<S>(self, process: &Process, map_state: S) -> Self
	where
		S: Fn(&State) -> State,
	{
		process.states.iter().fold(self, |b, state| b.add_state(map_state(state)))
	}

	/// Copy every terminal state of `process` through `map_state`.
	fn copy_terminals<S>(self, process: &Process, map_state: S) -> Self
	where
		S: Fn(&State) -> State,
	{
		process.terminal.iter().fold(self, |b, state| b.add_terminal(map_state(state)))
	}

	/// Copy every transition of `process`, with each state mapped through
	/// `map_state` and each event through `map_event`.
	///
	/// A timed transition keeps its guard and its clock resets.
	fn copy_transitions<S, E>(self, process: &Process, map_state: S, map_event: E) -> Self
	where
		S: Fn(&State) -> State,
		E: Fn(Event) -> Event,
	{
		let enabled = process.states.iter().map(|state| (*state, process.enabled(*state)));
		let offered = enabled.flat_map(|(state, actions)| actions.into_iter().map(move |action| (state, action.event)));

		offered.fold(self, |builder, (state, event)| {
			let copy = (map_state(&state), map_event(event));
			builder.copy_edges(process, (state, event), copy, &map_state)
		})
	}

	/// Copy the edges of `process` that `event` labels at `state`, as edges
	/// that `as_event` labels at `from`, with each target mapped through
	/// `map_target`.
	///
	/// A timed edge keeps its guard and its clock resets.
	fn copy_edges<T>(
		self,
		process: &Process,
		(state, event): (State, Event),
		(from, as_event): (State, Event),
		map_target: T,
	) -> Self
	where
		T: Fn(&State) -> State,
	{
		let untimed = process.transitions.targets(state, &event).unwrap_or_default().iter();
		let builder = untimed.fold(self, |b, target| b.add_transition(from, as_event, map_target(target)));

		#[cfg(feature = "testing-timing")]
		let builder = process.timed_edges(state, &event).iter().fold(builder, |b, edge| {
			let resets = edge.reset_clocks.iter().cloned();
			b.add_timed_transition(from, as_event, map_target(&edge.to), edge.guard.clone(), resets)
		});

		builder
	}

	/// Add prefixed copies of both operands: the states, alphabets,
	/// transitions, and terminals of `p` under `P_` and of `q` under `Q_`.
	/// Both choice operators build on these copies, and they differ only in
	/// how their initial state connects to them.
	fn prefixed_operands(self, p: &Process, q: &Process) -> Self {
		self.copy_states(p, |state| State::prefixed(state, "P"))
			.copy_states(q, |state| State::prefixed(state, "Q"))
			.union_alphabets(p, q)
			.copy_transitions(p, |state| State::prefixed(state, "P"), |event| event)
			.copy_transitions(q, |state| State::prefixed(state, "Q"), |event| event)
			.copy_terminals(p, |state| State::prefixed(state, "P"))
			.copy_terminals(q, |state| State::prefixed(state, "Q"))
	}

	/// Copy the transitions that leave the initial state of `process` so that
	/// they start at `from` and reach the prefixed copies. An external choice
	/// commits on its first event through these copies.
	///
	/// A timed transition keeps its guard and its clock resets.
	fn fan_out_initial(self, process: &Process, from: State, prefix: impl AsRef<str>) -> Self {
		let prefix = prefix.as_ref();
		let initial = process.initial;
		let prefixed = |target: &State| State::prefixed(target, prefix);
		process.enabled(initial).into_iter().fold(self, |builder, action| {
			let fanned = (from, action.event);
			builder.copy_edges(process, (initial, action.event), fanned, prefixed)
		})
	}
}

impl Process {
	/// Hiding: `P \ A`, where `A` is `hidden_events`.
	///
	/// The observable events of `A` become hidden, so their transitions are
	/// internal τ transitions.
	///
	/// ## Effect
	/// - The observable alphabet loses the events of `A`.
	/// - The hidden alphabet gains the observable events of `A`.
	/// - The state space and the transitions stay the same.
	pub fn hide(&self, hidden_events: HashSet<Event>) -> Result<Process, CompositionError> {
		let name = intern(format!("({} \\ A)", self.name));
		let builder = Process::builder(name)
			.initial_state(self.initial)
			.copy_states(self, |state| *state);

		let builder = builder.copy_terminals(self, |state| *state);
		let builder = self
			.observable
			.iter()
			.filter(|e| !hidden_events.contains(e))
			.fold(builder, |b, event| b.add_observable(event));
		let builder = self
			.observable
			.iter()
			.filter(|e| hidden_events.contains(e))
			.fold(builder, |b, event| b.add_hidden(event));

		let builder = self.hidden.iter().fold(builder, |b, event| b.add_hidden(event));
		let builder = builder.copy_transitions(self, |state| *state, |event| event);
		Ok(builder.build()?)
	}

	/// Renaming: `P [[ old <- new ]]`.
	///
	/// Rename events according to `mapping`. Every occurrence of an old event,
	/// in both alphabets and in every transition, becomes its new event.
	///
	/// ## Parameters
	/// - `mapping`: the new event for each old event.
	pub fn rename(&self, mapping: HashMap<Event, Event>) -> Result<Process, CompositionError> {
		let name = intern(format!("({} [[r]])", self.name));
		let builder = Process::builder(name)
			.initial_state(self.initial)
			.copy_states(self, |state| *state);
		let builder = builder.copy_terminals(self, |state| *state);
		let observable_events: Vec<Event> = self
			.observable
			.iter()
			.map(|event| *mapping.get(event).unwrap_or(event))
			.collect();

		let builder = observable_events.into_iter().fold(builder, |b, event| b.add_observable(event));
		let hidden_events: Vec<Event> = self.hidden.iter().map(|event| *mapping.get(event).unwrap_or(event)).collect();
		let builder = hidden_events.into_iter().fold(builder, |b, event| b.add_hidden(event));
		let builder = builder.copy_transitions(self, |state| *state, |event| *mapping.get(&event).unwrap_or(&event));
		Ok(builder.build()?)
	}

	/// Sequential composition: `P ; Q`.
	///
	/// When `P` reaches a terminal state, `Q` starts, so the terminal states of
	/// `P` connect to the initial state of `Q`.
	///
	/// ## State Space
	/// `S = S_P ∪ S_Q`, where the states of `Q` carry the prefix `Q_`. Only the
	/// terminal states of `Q` stay terminal.
	///
	/// ## Transitions
	/// - Every transition of `P` remains.
	/// - Every transition of `Q` remains.
	/// - Each terminal state of `P` has a τ transition, `tau_seq`, to the initial state of `Q`.
	pub fn sequential(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = intern(format!("({} ; {})", p.name, q.name));
		let builder = Process::builder(name).initial_state(p.initial).copy_states(p, |state| *state);
		let builder = builder.copy_states(q, |state| State::prefixed(state, "Q"));
		let builder = builder.union_alphabets(p, q);
		let builder = builder.copy_transitions(p, |state| *state, |event| event);
		let builder = builder.copy_transitions(q, |state| State::prefixed(state, "Q"), |event| event);

		let q_initial_renamed = State::prefixed(&q.initial, "Q");
		let builder = p.terminal.iter().fold(builder.add_hidden(Event("tau_seq")), |b, p_terminal| {
			b.add_transition(*p_terminal, Event("tau_seq"), q_initial_renamed)
		});

		let builder = builder.copy_terminals(q, |state| State::prefixed(state, "Q"));
		Ok(builder.build()?)
	}

	/// External choice: `P [] Q`.
	///
	/// The first event decides which process runs. An observable first event
	/// is the environment's choice, and a hidden first event of either operand
	/// also commits the choice.
	///
	/// ## State Space
	/// The initial state offers the first events of both `P` and `Q`. After
	/// the first event, the process is committed to one operand.
	pub fn external_choice(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let choice_initial = State("ExternalChoice_Initial");
		let name = intern(format!("({} [] {})", p.name, q.name));
		let builder = Process::builder(name).initial_state(choice_initial).add_state(choice_initial);
		let builder = builder.prefixed_operands(p, q);
		let builder = builder.fan_out_initial(p, choice_initial, "P");
		let builder = builder.fan_out_initial(q, choice_initial, "Q");

		Ok(builder.build()?)
	}

	/// Internal choice: `P |~| Q`.
	///
	/// The process chooses `P` or `Q` nondeterministically. Two τ transitions,
	/// `tau_choice_p` and `tau_choice_q`, lead from the initial state to the
	/// initial states of `P` and `Q`.
	pub fn internal_choice(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let choice_initial = State("InternalChoice_Initial");
		let name = intern(format!("({} |~| {})", p.name, q.name));
		let builder = Process::builder(name)
			.initial_state(choice_initial)
			.add_state(choice_initial)
			.add_hidden(Event("tau_choice_p"))
			.add_hidden(Event("tau_choice_q"));

		let builder = builder.prefixed_operands(p, q);
		let builder = builder
			.add_transition(choice_initial, Event("tau_choice_p"), State::prefixed(&p.initial, "P"))
			.add_transition(choice_initial, Event("tau_choice_q"), State::prefixed(&q.initial, "Q"))
			.add_choice(choice_initial);

		Ok(builder.build()?)
	}
}

impl State {
	/// Create a renamed copy of a state under an operand prefix. The
	/// composition operators use it to keep the state spaces of their operands
	/// disjoint.
	pub fn prefixed(s: &State, prefix: impl AsRef<str>) -> State {
		let prefix = prefix.as_ref();
		State(intern(format!("{}_{}", prefix, s.0)))
	}
}

#[cfg(test)]
mod tests {
	use std::borrow::Cow;

	#[cfg(feature = "testing-timing")]
	use core::time::Duration;

	use super::*;
	use crate::testing::assertions::{Assertion, AssertionLabel};
	use crate::testing::specs::csp::{Event, Process, State};
	use crate::trace::ConsumedTrace;

	#[cfg(feature = "testing-timing")]
	use crate::testing::specs::csp::ProcessBuildError;
	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::TimingGuard;

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
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.add_transition(State("s1"), Event("b"), State("s2"))
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

	/// A process in which `a` takes `s0` to the terminal `s1` where the
	/// clocks satisfy `guard`.
	#[cfg(feature = "testing-timing")]
	fn guarded_process(guard: TimingGuard) -> Result<Process, ProcessBuildError> {
		Process::builder("G")
			.initial_state(State("s0"))
			.add_observable(Event("a"))
			.add_timed_transition(State("s0"), Event("a"), State("s1"), Some(guard), Vec::new())
			.add_terminal(State("s1"))
			.build()
	}

	/// The guards of the timed edges that `a` labels at `state`.
	#[cfg(feature = "testing-timing")]
	fn guards_of(process: &Process, state: State) -> Vec<Option<TimingGuard>> {
		let edges = process.timed_edges(state, &Event("a"));
		edges.iter().map(|edge| edge.guard.clone()).collect()
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn hiding_keeps_the_guard_of_a_timed_transition() -> Result<(), Box<dyn core::error::Error>> {
		let bound = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		let guarded = guarded_process(bound.clone())?;

		let copy = guarded.hide(HashSet::new())?;

		assert_eq!(guards_of(&copy, State("s0")), [Some(bound)]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn an_external_choice_keeps_the_guard_of_a_first_event() -> Result<(), Box<dyn core::error::Error>> {
		let bound = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		let guarded = guarded_process(bound.clone())?;

		let choice = Process::external_choice(&guarded, &simple_process())?;

		assert_eq!(guards_of(&choice, State("ExternalChoice_Initial")), [Some(bound)]);
		Ok(())
	}
}
