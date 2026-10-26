//! CSP process algebra operations.
//!
//! This module implements these operators of CSP theory on [`Process`]:
//! - Hiding: `P \ A`.
//! - Renaming: `P [[ old <- new ]]`.
//! - Sequential composition: `P ; Q`.
//! - External choice: `P [] Q`.
//! - Internal choice: `P |~| Q`.

use std::collections::{HashMap, HashSet};

#[cfg(feature = "testing-schedulability")]
use core::time::Duration;

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{intern, Event, Process, ProcessBuilder, State};

#[cfg(feature = "testing-schedulability")]
use crate::testing::schedulability::SchedulerType;
#[cfg(feature = "testing-timing")]
use crate::testing::specs::csp::Alphabet;

impl ProcessBuilder {
	/// Adds the alphabets of both operands, and keeps each event in its
	/// observable or hidden alphabet.
	fn union_alphabets(self, p: &Process, q: &Process) -> Self {
		let builder = p
			.observable
			.iter()
			.chain(&q.observable)
			.fold(self, |b, event| b.add_observable(event));

		p.hidden.iter().chain(&q.hidden).fold(builder, |b, event| b.add_hidden(event))
	}

	/// Copies every state of `process` through `map_state`.
	fn copy_states<S>(self, process: &Process, map_state: S) -> Self
	where
		S: Fn(&State) -> State,
	{
		process.states.iter().fold(self, |b, state| b.add_state(map_state(state)))
	}

	/// Copies every terminal state of `process` through `map_state`.
	fn copy_terminals<S>(self, process: &Process, map_state: S) -> Self
	where
		S: Fn(&State) -> State,
	{
		process.terminal.iter().fold(self, |b, state| b.add_terminal(map_state(state)))
	}

	/// Copies every choice point of `process` through `map_state`.
	fn copy_choices<S>(self, process: &Process, map_state: S) -> Self
	where
		S: Fn(&State) -> State,
	{
		process.choice.iter().fold(self, |b, state| b.add_choice(map_state(state)))
	}

	/// Copies every transition of `process`, with each state mapped through
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

	/// Copies the edges of `process` that `event` labels at `state`, as edges
	/// that `as_event` labels at `from`, with each target mapped through
	/// `map_target`.
	///
	/// A timed edge keeps its guard and its clock resets, and the copy
	/// declares each clock that the edge names.
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
			let declared = edge.clocks().fold(b, |declared, clock| declared.clock(clock));
			let resets = edge.reset_clocks.iter().cloned();
			declared.add_timed_transition(from, as_event, map_target(&edge.to), edge.guard.clone(), resets)
		});

		builder
	}

	/// Adds prefixed copies of both operands: the states, alphabets,
	/// transitions, terminals, and choice points of `p` under `P_` and of `q`
	/// under `Q_`. Both choice operators build on these copies, and they
	/// differ only in how their initial state connects to them.
	fn prefixed_operands(self, p: &Process, q: &Process) -> Self {
		self.copy_states(p, |state| State::prefixed(state, "P"))
			.copy_states(q, |state| State::prefixed(state, "Q"))
			.union_alphabets(p, q)
			.copy_transitions(p, |state| State::prefixed(state, "P"), |event| event)
			.copy_transitions(q, |state| State::prefixed(state, "Q"), |event| event)
			.copy_terminals(p, |state| State::prefixed(state, "P"))
			.copy_terminals(q, |state| State::prefixed(state, "Q"))
			.copy_choices(p, |state| State::prefixed(state, "P"))
			.copy_choices(q, |state| State::prefixed(state, "Q"))
	}

	/// Adds the open state of an external choice that pairs `p_state` of `p`
	/// with `q_state` of `q`, and its edges.
	///
	/// - A hidden event of either operand moves that operand alone, and the choice stays open.
	/// - An observable event of either operand commits the choice to the prefixed copy of that operand.
	/// - The open state is accepting when either of its two states is.
	/// - It is a choice point when one of its states is, or when both operands offer one event there.
	///
	/// A timed edge keeps its guard and its clock resets.
	fn open_choice(self, (p, p_state): (&Process, State), (q, q_state): (&Process, State)) -> Self {
		let from = State::open_choice(p_state, q_state);
		let p_actions = p.enabled(p_state);
		let q_actions = q.enabled(q_state);
		let q_events: HashSet<Event> = q_actions.iter().map(|action| action.event).collect();
		let shared = p_actions.iter().any(|action| q_events.contains(&action.event));
		let accepting = p.is_terminal(p_state) || q.is_terminal(q_state);
		let choice = shared || p.is_choice(p_state) || q.is_choice(q_state);

		let builder = p_actions.iter().fold(self.add_state(from), |builder, action| {
			let edge = (p_state, action.event);
			let label = (from, action.event);
			if action.is_hidden() {
				builder.copy_edges(p, edge, label, |target| State::open_choice(*target, q_state))
			} else {
				builder.copy_edges(p, edge, label, |target| State::prefixed(target, "P"))
			}
		});

		let builder = q_actions.iter().fold(builder, |builder, action| {
			let edge = (q_state, action.event);
			let label = (from, action.event);
			if action.is_hidden() {
				builder.copy_edges(q, edge, label, |target| State::open_choice(p_state, *target))
			} else {
				builder.copy_edges(q, edge, label, |target| State::prefixed(target, "Q"))
			}
		});

		let builder = if accepting {
			builder.add_terminal(from)
		} else {
			builder
		};
		if choice {
			builder.add_choice(from)
		} else {
			builder
		}
	}

	/// Sets the timing of `p` and of `q` together: their timing constraints
	/// and their schedulability periods.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	#[cfg(feature = "testing-timing")]
	pub(super) fn timing_of_both(self, p: &Process, q: &Process) -> Result<Self, CompositionError> {
		let conflict = |event| CompositionError::ConflictingTiming { event };
		let constraints = match (&p.timing_constraints, &q.timing_constraints) {
			(Some(mine), Some(theirs)) => Some(mine.union(theirs).map_err(conflict)?),
			(mine, theirs) => mine.as_ref().or(theirs.as_ref()).cloned(),
		};

		let builder = match constraints {
			Some(constraints) => self.timing_constraints(constraints),
			None => self,
		};

		#[cfg(feature = "testing-schedulability")]
		let builder = builder.schedule_of_both(p, q)?;

		Ok(builder)
	}

	/// Sets the timing of `process` with each event mapped through `rename`.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `rename` merges two events whose timing differs.
	#[cfg(feature = "testing-timing")]
	fn renamed_timing<R>(self, process: &Process, rename: R) -> Result<Self, CompositionError>
	where
		R: Fn(Event) -> Event + Copy,
	{
		let conflict = |event| CompositionError::ConflictingTiming { event };
		let held = process.timing_constraints.as_ref();
		let renamed = held.map(|constraints| constraints.renamed(rename));
		let constraints = renamed.transpose().map_err(conflict)?;

		let builder = match constraints {
			Some(constraints) => self.timing_constraints(constraints),
			None => self,
		};

		#[cfg(feature = "testing-schedulability")]
		let builder = builder.renamed_schedule(process, rename)?;

		Ok(builder)
	}

	/// Sets the schedule of `p` and of `q` together.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` give one event periods that differ.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	#[cfg(feature = "testing-schedulability")]
	fn schedule_of_both(self, p: &Process, q: &Process) -> Result<Self, CompositionError> {
		let schedule = match (Schedule::of(p), Schedule::of(q)) {
			(Some(mine), Some(theirs)) => mine.joined(&theirs)?,
			(Some(only), None) | (None, Some(only)) => only,
			(None, None) => return Ok(self),
		};

		Ok(self.with_schedulability_periods(schedule.scheduler, schedule.periods))
	}

	/// Sets the schedule of `process` with each event mapped through `rename`.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `rename` maps two events with periods that differ to one.
	#[cfg(feature = "testing-schedulability")]
	fn renamed_schedule<R>(self, process: &Process, rename: R) -> Result<Self, CompositionError>
	where
		R: Fn(Event) -> Event,
	{
		let Some(schedule) = Schedule::of(process) else {
			return Ok(self);
		};

		let renamed = schedule.renamed(rename)?;
		Ok(self.with_schedulability_periods(renamed.scheduler, renamed.periods))
	}
}

/// The scheduler of a process and the period of each event it schedules.
#[cfg(feature = "testing-schedulability")]
struct Schedule {
	/// The scheduler that the analysis assumes.
	scheduler: SchedulerType,
	/// The period of each scheduled event.
	periods: HashMap<Event, Duration>,
}

#[cfg(feature = "testing-schedulability")]
impl Schedule {
	/// The schedule of `process`, when it declares one.
	fn of(process: &Process) -> Option<Self> {
		let (scheduler, periods) = process.schedulability_periods.as_ref()?;
		Some(Self { scheduler: *scheduler, periods: periods.clone() })
	}

	/// This schedule and `other` together.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- the two give one event periods that differ.
	/// - [`CompositionError::ConflictingScheduler`] -- the two name different schedulers.
	fn joined(mut self, other: &Self) -> Result<Self, CompositionError> {
		if self.scheduler != other.scheduler {
			return Err(CompositionError::ConflictingScheduler);
		}

		for (event, period) in other.in_event_order() {
			self.admit(event, period)?;
		}

		Ok(self)
	}

	/// This schedule with each event mapped through `rename`.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `rename` maps two events with periods that differ to one.
	fn renamed<R>(&self, rename: R) -> Result<Self, CompositionError>
	where
		R: Fn(Event) -> Event,
	{
		let mut renamed = Self { scheduler: self.scheduler, periods: HashMap::new() };
		for (event, period) in self.in_event_order() {
			renamed.admit(rename(event), period)?;
		}

		Ok(renamed)
	}

	/// The periods of this schedule, sorted by event name, so a conflict
	/// names the same event on every run.
	fn in_event_order(&self) -> Vec<(Event, Duration)> {
		let mut entries: Vec<(Event, Duration)> =
			self.periods.iter().map(|(event, period)| (*event, *period)).collect();
		entries.sort_unstable();
		entries
	}

	/// Adds `period` for `event`, or keeps the period held when the two are
	/// equal.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- this schedule holds another period for `event`.
	fn admit(&mut self, event: Event, period: Duration) -> Result<(), CompositionError> {
		match self.periods.get(&event) {
			Some(held) if *held == period => Ok(()),
			Some(_) => Err(CompositionError::ConflictingTiming { event }),
			None => {
				self.periods.insert(event, period);
				Ok(())
			}
		}
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
	/// - The state space, the transitions, and the timing stay the same.
	pub fn hide(&self, hidden_events: HashSet<Event>) -> Process {
		let moved: HashSet<Event> = self.observable.intersection(&hidden_events).copied().collect();
		let mut hidden = self.clone();
		hidden.name = intern(format!("({} \\ A)", self.name));
		hidden.observable.retain(|event| !moved.contains(event));
		hidden.hidden.extend(&moved);

		// A timed edge records the alphabet of its event, so the edges of a
		// moved event record the hidden alphabet.
		#[cfg(feature = "testing-timing")]
		{
			let edges = hidden.timed_transitions.iter_mut().flat_map(HashMap::values_mut).flatten();
			let moved_edges = edges.filter(|edge| moved.contains(&edge.action.event));
			moved_edges.for_each(|edge| edge.action.alphabet = Alphabet::Hidden);
		}

		hidden
	}

	/// Renaming: `P [[ old <- new ]]`.
	///
	/// The method renames events through `mapping`. Every occurrence of an old
	/// event, in both alphabets and in every transition, becomes its new event.
	///
	/// ## Parameters
	/// - `mapping`: the new event for each old event.
	///
	/// The timing constraints and the schedulability periods follow their
	/// events. A mapping may take two events to one, and their timing then
	/// becomes one when it agrees.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `mapping` merges two events whose timing differs.
	pub fn rename(&self, mapping: HashMap<Event, Event>) -> Result<Process, CompositionError> {
		let name = intern(format!("({} [[r]])", self.name));
		let rename_event = |event: Event| *mapping.get(&event).unwrap_or(&event);
		let builder = Process::builder(name)
			.initial_state(self.initial)
			.copy_states(self, |state| *state);
		let builder = builder.copy_terminals(self, |state| *state);
		let builder = builder.copy_choices(self, |state| *state);
		let observable_events: Vec<Event> = self.observable.iter().map(|event| rename_event(*event)).collect();

		let builder = observable_events.into_iter().fold(builder, |b, event| b.add_observable(event));
		let hidden_events: Vec<Event> = self.hidden.iter().map(|event| rename_event(*event)).collect();
		let builder = hidden_events.into_iter().fold(builder, |b, event| b.add_hidden(event));
		let builder = builder.copy_transitions(self, |state| *state, rename_event);
		#[cfg(feature = "testing-timing")]
		let builder = builder.renamed_timing(self, rename_event)?;
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
	///
	/// The composition holds the timing constraints and the schedulability
	/// periods of both operands.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn sequential(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = intern(format!("({} ; {})", p.name, q.name));
		let builder = Process::builder(name).initial_state(p.initial).copy_states(p, |state| *state);
		let builder = builder.copy_states(q, |state| State::prefixed(state, "Q"));
		let builder = builder.union_alphabets(p, q);
		let builder = builder.copy_transitions(p, |state| *state, |event| event);
		let builder = builder.copy_transitions(q, |state| State::prefixed(state, "Q"), |event| event);
		let builder = builder.copy_choices(p, |state| *state);
		let builder = builder.copy_choices(q, |state| State::prefixed(state, "Q"));

		let q_initial_renamed = State::prefixed(&q.initial, "Q");
		let builder = p.terminal.iter().fold(builder.add_hidden(Event("tau_seq")), |b, p_terminal| {
			b.add_transition(*p_terminal, Event("tau_seq"), q_initial_renamed)
		});

		let builder = builder.copy_terminals(q, |state| State::prefixed(state, "Q"));
		#[cfg(feature = "testing-timing")]
		let builder = builder.timing_of_both(p, q)?;
		Ok(builder.build()?)
	}

	/// External choice: `P [] Q`.
	///
	/// The environment chooses with the first observable event. A hidden event
	/// of either operand moves that operand alone, and the choice stays open,
	/// as the firing rules of external choice state (A.W. Roscoe, *The Theory
	/// and Practice of Concurrency*, 2005 revision).
	///
	/// ## State Space
	/// - An open state pairs two states that `P` and `Q` reach by hidden events alone.
	/// - The initial state is the open state of the two initial states.
	/// - The first observable event commits the process to the prefixed copy of its operand.
	///
	/// The composition holds the timing constraints and the schedulability
	/// periods of both operands.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn external_choice(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = intern(format!("({} [] {})", p.name, q.name));
		let initial = State::open_choice(p.initial, q.initial);
		let builder = Process::builder(name).initial_state(initial).prefixed_operands(p, q);

		let p_open = p.tau_closure([p.initial]);
		let q_open = q.tau_closure([q.initial]);
		let pairs = p_open
			.iter()
			.flat_map(|p_state| q_open.iter().map(move |q_state| (*p_state, *q_state)));
		let builder = pairs.fold(builder, |builder, (p_state, q_state)| {
			builder.open_choice((p, p_state), (q, q_state))
		});

		#[cfg(feature = "testing-timing")]
		let builder = builder.timing_of_both(p, q)?;

		Ok(builder.build()?)
	}

	/// Internal choice: `P |~| Q`.
	///
	/// The process chooses `P` or `Q` nondeterministically. Two τ transitions,
	/// `tau_choice_p` and `tau_choice_q`, lead from the initial state to the
	/// initial states of `P` and `Q`.
	///
	/// The composition holds the timing constraints and the schedulability
	/// periods of both operands.
	///
	/// # Errors
	///
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
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

		#[cfg(feature = "testing-timing")]
		let builder = builder.timing_of_both(p, q)?;

		Ok(builder.build()?)
	}
}

impl State {
	/// Creates a renamed copy of a state under an operand prefix. The
	/// composition operators use it to keep the state spaces of their operands
	/// disjoint.
	pub fn prefixed(s: &State, prefix: impl AsRef<str>) -> State {
		let prefix = prefix.as_ref();
		State(intern(format!("{}_{}", prefix, s.0)))
	}

	/// The open state of an external choice that pairs `p_state` with
	/// `q_state`, named `ExternalChoice_(p,q)`.
	fn open_choice(p_state: State, q_state: State) -> State {
		let pair = State::product(p_state, q_state);
		State::prefixed(&pair, "ExternalChoice")
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
	use crate::builder::TypeBuilder;
	#[cfg(feature = "testing-timing")]
	use crate::testing::specs::csp::ProcessBuildError;
	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::{TimingConstraint, TimingConstraints, TimingGuard, WcetConfigBuilder};

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

		let result = p.hide(hidden_events);
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
			.clock(guard.clock())
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

		let copy = guarded.hide(HashSet::new());

		assert_eq!(guards_of(&copy, State("s0")), [Some(bound)]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn an_external_choice_keeps_the_guard_of_a_first_event() -> Result<(), Box<dyn core::error::Error>> {
		let bound = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		let guarded = guarded_process(bound.clone())?;

		let choice = Process::external_choice(&guarded, &simple_process())?;

		assert_eq!(guards_of(&choice, choice.initial), [Some(bound)]);
		Ok(())
	}

	/// A process in which `a` takes `s0` to `s1` through the hidden `t`, and
	/// `s1` to the terminal `s2`.
	fn hidden_start() -> Process {
		Process::builder("H")
			.initial_state(State("s0"))
			.add_observable(Event("a"))
			.add_hidden(Event("t"))
			.add_transition(State("s0"), Event("t"), State("s1"))
			.add_transition(State("s1"), Event("a"), State("s2"))
			.add_terminal(State("s2"))
			.build()
			.expect("a process with an initial state builds")
	}

	/// A process in which `c` takes `q0` to the terminal `q1`.
	fn c_once() -> Process {
		Process::builder("C")
			.initial_state(State("q0"))
			.add_observable(Event("c"))
			.add_transition(State("q0"), Event("c"), State("q1"))
			.add_terminal(State("q1"))
			.build()
			.expect("a process with an initial state builds")
	}

	/// A process in which `a` takes `s0` to `s1` or to `s2`, and `s0` is a
	/// declared choice point.
	fn branching() -> Process {
		Process::builder("B")
			.initial_state(State("s0"))
			.add_observable(Event("a"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.add_transition(State("s0"), Event("a"), State("s2"))
			.add_choice(State("s0"))
			.add_terminal(State("s1"))
			.add_terminal(State("s2"))
			.build()
			.expect("a process with an initial state builds")
	}

	/// A process in which each event of `wcets` takes `s0` to the terminal
	/// `s1`, and the WCET of each is its milliseconds.
	#[cfg(feature = "testing-timing")]
	fn timed(name: &'static str, wcets: &[(&'static str, u64)]) -> Process {
		let mut constraints = TimingConstraints::default();
		let builder = Process::builder(name).initial_state(State("s0")).add_terminal(State("s1"));
		let builder = wcets.iter().fold(builder, |builder, &(event, millis)| {
			let duration = Duration::from_millis(millis);
			let wcet = WcetConfigBuilder::default()
				.with_duration(duration)
				.build()
				.expect("a WCET with a duration builds");
			constraints.add(Event(event), TimingConstraint::Wcet(wcet));
			builder
				.add_observable(Event(event))
				.add_transition(State("s0"), Event(event), State("s1"))
		});

		builder
			.timing_constraints(constraints)
			.build()
			.expect("a process with an initial state builds")
	}

	/// Whether `process` holds a timing constraint on `event`.
	#[cfg(feature = "testing-timing")]
	fn constrains(process: &Process, event: &'static str) -> bool {
		let constraints = process.timing_constraints.as_ref();
		constraints.is_some_and(|constraints| constraints.has_constraint(&Event(event)))
	}

	/// A process in which `a` takes `s0` to the terminal `s1`, with a period
	/// of `millis` on `a` under `scheduler`.
	#[cfg(feature = "testing-schedulability")]
	fn scheduled(scheduler: SchedulerType, millis: u64) -> Process {
		let periods = HashMap::from([(Event("a"), Duration::from_millis(millis))]);
		Process::builder("S")
			.initial_state(State("s0"))
			.add_observable(Event("a"))
			.add_transition(State("s0"), Event("a"), State("s1"))
			.add_terminal(State("s1"))
			.with_schedulability_periods(scheduler, periods)
			.build()
			.expect("a process with an initial state builds")
	}

	#[test]
	fn a_hidden_first_move_keeps_the_choice_open() -> Result<(), Box<dyn core::error::Error>> {
		let choice = Process::external_choice(&hidden_start(), &c_once())?;

		let after_hidden = choice.step(choice.initial, &Event("t"));
		let offered: Vec<HashSet<Event>> = after_hidden.iter().map(|state| choice.offers(*state)).collect();
		assert_eq!(offered, [HashSet::from([Event("a"), Event("c")])]);
		Ok(())
	}

	#[test]
	fn an_observable_first_event_commits_the_choice() -> Result<(), Box<dyn core::error::Error>> {
		let choice = Process::external_choice(&simple_process(), &c_once())?;

		let after_a = choice.step(choice.initial, &Event("a"));
		let offered: Vec<HashSet<Event>> = after_a.iter().map(|state| choice.offers(*state)).collect();
		assert_eq!(offered, [HashSet::from([Event("b")])]);
		Ok(())
	}

	#[test]
	fn a_first_event_of_both_operands_makes_a_choice_point() -> Result<(), Box<dyn core::error::Error>> {
		let choice = Process::external_choice(&simple_process(), &simple_process())?;
		assert!(choice.is_choice(choice.initial));
		Ok(())
	}

	#[test]
	fn renaming_keeps_a_choice_point() -> Result<(), Box<dyn core::error::Error>> {
		let renamed = branching().rename(HashMap::from([(Event("a"), Event("x"))]))?;
		assert!(renamed.is_choice(State("s0")));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_sequential_composition_declares_the_clocks_it_copies() -> Result<(), Box<dyn core::error::Error>> {
		let bound = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		let guarded = guarded_process(bound.clone())?;

		let composed = Process::sequential(&guarded, &simple_process())?;
		assert_eq!(guards_of(&composed, State("s0")), [Some(bound)]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn hiding_keeps_the_timing_constraints() -> Result<(), Box<dyn core::error::Error>> {
		let process = timed("T", &[("a", 10)]);
		let copy = process.hide(HashSet::from([Event("a")]));
		assert!(constrains(&copy, "a"));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn renaming_moves_a_constraint_to_the_new_event() -> Result<(), Box<dyn core::error::Error>> {
		let process = timed("T", &[("a", 10)]);
		let renamed = process.rename(HashMap::from([(Event("a"), Event("x"))]))?;
		assert!(constrains(&renamed, "x"));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn renaming_two_differently_constrained_events_to_one_is_refused() -> Result<(), Box<dyn core::error::Error>> {
		let process = timed("T", &[("a", 10), ("b", 20)]);
		let mapping = HashMap::from([(Event("a"), Event("x")), (Event("b"), Event("x"))]);

		let refused = process.rename(mapping);
		assert!(matches!(
			refused,
			Err(CompositionError::ConflictingTiming { event: Event("x") })
		));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_sequential_composition_holds_the_timing_of_both() -> Result<(), Box<dyn core::error::Error>> {
		let composed = Process::sequential(&timed("P", &[("a", 10)]), &timed("Q", &[("b", 20)]))?;
		assert_eq!([constrains(&composed, "a"), constrains(&composed, "b")], [true, true]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn an_external_choice_holds_the_timing_of_both() -> Result<(), Box<dyn core::error::Error>> {
		let composed = Process::external_choice(&timed("P", &[("a", 10)]), &timed("Q", &[("b", 20)]))?;
		assert_eq!([constrains(&composed, "a"), constrains(&composed, "b")], [true, true]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn an_internal_choice_holds_the_timing_of_both() -> Result<(), Box<dyn core::error::Error>> {
		let composed = Process::internal_choice(&timed("P", &[("a", 10)]), &timed("Q", &[("b", 20)]))?;
		assert_eq!([constrains(&composed, "a"), constrains(&composed, "b")], [true, true]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_composition_keeps_one_copy_of_an_agreeing_constraint() -> Result<(), Box<dyn core::error::Error>> {
		let process = timed("P", &[("a", 10)]);
		let composed = Process::sequential(&process, &process)?;
		assert!(constrains(&composed, "a"));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_composition_refuses_constraints_that_do_not_agree() -> Result<(), Box<dyn core::error::Error>> {
		let refused = Process::sequential(&timed("P", &[("a", 10)]), &timed("Q", &[("a", 20)]));
		assert!(matches!(
			refused,
			Err(CompositionError::ConflictingTiming { event: Event("a") })
		));
		Ok(())
	}

	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn hiding_keeps_the_schedulability_periods() -> Result<(), Box<dyn core::error::Error>> {
		let process = scheduled(SchedulerType::RateMonotonic, 50);
		let copy = process.hide(HashSet::new());
		assert_eq!(copy.schedulability_periods, process.schedulability_periods);
		Ok(())
	}

	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn a_composition_refuses_two_schedulers() -> Result<(), Box<dyn core::error::Error>> {
		let rate_monotonic = scheduled(SchedulerType::RateMonotonic, 50);
		let deadline_first = scheduled(SchedulerType::EarliestDeadlineFirst, 50);

		let refused = Process::internal_choice(&rate_monotonic, &deadline_first);
		assert!(matches!(refused, Err(CompositionError::ConflictingScheduler)));
		Ok(())
	}

	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn a_composition_refuses_two_periods_for_one_event() -> Result<(), Box<dyn core::error::Error>> {
		let fast = scheduled(SchedulerType::RateMonotonic, 50);
		let slow = scheduled(SchedulerType::RateMonotonic, 100);

		let refused = Process::internal_choice(&fast, &slow);
		assert!(matches!(
			refused,
			Err(CompositionError::ConflictingTiming { event: Event("a") })
		));
		Ok(())
	}
}
