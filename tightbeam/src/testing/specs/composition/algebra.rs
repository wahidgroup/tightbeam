//! CSP process algebra operations.
//!
//! It implements these CSP operators on [`Process`]:
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
	/// - A timed edge keeps its guard and its clock resets, and the copy
	///   declares each clock that the edge names.
	/// - Each copy keeps the components that move on its edge, and the copy
	///   holds as many components as `process`.
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
		let movers = |target: State| process.components.moving((state, event, target), 0);
		let builder = self.components(process.components.count());

		let untimed = process.transitions.targets(state, &event).unwrap_or_default().iter();
		let builder = untimed.fold(builder, |b, target| {
			let to = map_target(target);
			let added = b.add_transition(from, as_event, to);
			added.add_movers((from, as_event, to), movers(*target))
		});

		#[cfg(feature = "testing-timing")]
		let builder = process.timed_edges(state, &event).iter().fold(builder, |b, edge| {
			let declared = edge.clocks().fold(b, |declared, clock| declared.clock(clock));
			let resets = edge.reset_clocks.iter().cloned();
			let to = map_target(&edge.to);
			let copied = declared.add_timed_transition(from, as_event, to, edge.guard.clone(), resets);
			copied.add_movers((from, as_event, to), movers(edge.to))
		});

		builder
	}

	/// Adds prefixed copies of both operands: the states, alphabets,
	/// transitions, terminals, and choice points of `p` under `P_` and of `q`
	/// under `Q_`. Both choice operators build on these copies and differ only
	/// in how their initial state connects to them.
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

	/// Adds `period` for `event`, or keeps the held one when the two are equal.
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
	/// Every occurrence of an old event of `mapping`, in both alphabets and in
	/// every transition, becomes its new event.
	///
	/// ## Parameters
	/// - `mapping`: the new event for each old event.
	///
	/// The timing constraints and the schedulability periods follow their
	/// events. When a mapping takes two events to one, their timing merges if
	/// it agrees.
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
	/// When `P` reaches a terminal state, `Q` starts.
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
	/// by the firing rules of external choice (A.W. Roscoe, *The Theory and
	/// Practice of Concurrency*, 2005 revision).
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
	/// Creates a renamed copy of a state under an operand prefix, so the
	/// composition operators keep the state spaces of their operands disjoint.
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
	use super::*;
	use crate::testing::fixtures::TestProcess;
	use crate::testing::specs::lts::CspValidationResult;
	use crate::testing::TestResult;
	use crate::trace::ConsumedTrace;

	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::TimingGuard;

	/// One composition operator over two processes.
	type Compose = fn(&Process, &Process) -> Result<Process, CompositionError>;

	/// One operator over a single process.
	#[cfg(feature = "testing-timing")]
	type Transform = fn(&Process) -> Result<Process, CompositionError>;

	/// A process `P` in which `a` takes `s0` to `s1`, and `b` takes `s1` to
	/// the terminal `s2`.
	fn simple_process() -> Process {
		TestProcess::chain("P", &["s0", "s1", "s2"], &["a", "b"])
	}

	/// The composition of two copies of [`simple_process`] under `compose`.
	fn composed(compose: Compose) -> Process {
		let built = compose(&simple_process(), &simple_process());
		built.expect("two copies of one untimed process compose")
	}

	/// The states of `names`.
	fn states_named(names: &[&'static str]) -> HashSet<State> {
		names.iter().copied().map(State).collect()
	}

	/// A process in which `a` takes `s0` to `s1` through the hidden `t`, and
	/// `s1` to the terminal `s2`.
	fn hidden_start() -> Process {
		TestProcess {
			observable: &["a"],
			hidden: &["t"],
			transitions: &[("s0", "t", "s1"), ("s1", "a", "s2")],
			terminal: &["s2"],
			..TestProcess::of("H", "s0")
		}
		.build()
	}

	/// A process in which `c` takes `q0` to the terminal `q1`.
	fn c_once() -> Process {
		TestProcess::chain("C", &["q0", "q1"], &["c"])
	}

	/// A process in which `a` takes `s0` to the terminal `s1` where the
	/// clocks satisfy `guard`.
	#[cfg(feature = "testing-timing")]
	fn guarded_process(guard: TimingGuard) -> Process {
		Process::builder("G")
			.initial_state(State("s0"))
			.clock(guard.clock())
			.add_observable(Event("a"))
			.add_timed_transition(State("s0"), Event("a"), State("s1"), Some(guard), Vec::new())
			.add_terminal(State("s1"))
			.build()
			.expect("a guard on a declared clock builds")
	}

	/// The guards of the timed edges that `a` labels at `state`.
	#[cfg(feature = "testing-timing")]
	fn guards_of(process: &Process, state: State) -> Vec<Option<TimingGuard>> {
		let edges = process.timed_edges(state, &Event("a"));
		edges.iter().map(|edge| edge.guard.clone()).collect()
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

	/// Hiding moves an event from the observable to the hidden alphabet.
	#[test]
	fn hiding_moves_an_event_to_the_hidden_alphabet() {
		let process = simple_process();
		let hidden = process.hide(HashSet::from([Event("a")]));

		let alphabets = (hidden.observable, hidden.hidden);
		assert_eq!(alphabets, (HashSet::from([Event("b")]), HashSet::from([Event("a")])));
	}

	/// Renaming replaces an event of the observable alphabet with its new
	/// name.
	#[test]
	fn renaming_replaces_an_event_of_the_alphabet() -> TestResult {
		let process = simple_process();
		let renamed = process.rename(HashMap::from([(Event("a"), Event("x"))]))?;
		assert_eq!(renamed.observable, HashSet::from([Event("x"), Event("b")]));
		Ok(())
	}

	// Each operator names its composition in CSP notation, over the states of
	// both operands and the states it adds.
	crate::tb_cases! {
		fn an_operator_names_its_composition((compose, name, states): (Compose, &str, HashSet<State>)) {
			let process = composed(compose);
			assert_eq!((process.name, process.states), (name, states));
		}

		cases {
			sequential => (
				Process::sequential,
				"(P ; P)",
				states_named(&["s0", "s1", "s2", "Q_s0", "Q_s1", "Q_s2"]),
			),
			external_choice => (
				Process::external_choice,
				"(P [] P)",
				states_named(&["ExternalChoice_(s0,s0)", "P_s0", "P_s1", "P_s2", "Q_s0", "Q_s1", "Q_s2"]),
			),
			internal_choice => (
				Process::internal_choice,
				"(P |~| P)",
				states_named(&["InternalChoice_Initial", "P_s0", "P_s1", "P_s2", "Q_s0", "Q_s1", "Q_s2"]),
			),
		}
	}

	// A composition takes its hidden step silently, so a trace of the events
	// of its operands validates.
	crate::tb_cases! {
		fn a_trace_validates_across_the_hidden_step_of((compose, trace): (Compose, ConsumedTrace)) {
			let process = composed(compose);
			let result = process.validate_trace(&trace);
			assert_eq!(result, CspValidationResult { valid: true, violations: Vec::new() });
		}

		cases {
			an_internal_choice => (Process::internal_choice, ConsumedTrace::recording([Event("a"), Event("b")])),
			a_sequential_composition => (
				Process::sequential,
				ConsumedTrace::recording([Event("a"), Event("b"), Event("a"), Event("b")]),
			),
		}
	}

	// Each operator keeps the guard of the first event of an operand, so the
	// copy also declares the clock that the guard reads.
	#[cfg(feature = "testing-timing")]
	crate::tb_cases! {
		fn the_guard_of_a_first_event_survives(transform: Transform) -> TestResult {
			let guarded = guarded_process(TimingGuard::clk_within(5));
			let copy = transform(&guarded)?;
			assert_eq!(guards_of(&copy, copy.initial), [Some(TimingGuard::clk_within(5))]);
			Ok(())
		}

		cases {
			hiding => |guarded| Ok(guarded.hide(HashSet::new())),
			an_external_choice => |guarded| Process::external_choice(guarded, &simple_process()),
			a_sequential_composition => |guarded| Process::sequential(guarded, &simple_process()),
		}
	}

	// The first move of an external choice keeps the choice open when it is
	// hidden, and commits the choice when it is observable.
	crate::tb_cases! {
		fn an_external_choice_after_one_move((left, first, offered): (Process, &str, HashSet<Event>)) -> TestResult {
			let choice = Process::external_choice(&left, &c_once())?;

			let after = choice.step(choice.initial, &Event(first));
			let offers: Vec<HashSet<Event>> = after.iter().map(|state| choice.offers(*state)).collect();
			assert_eq!(offers, [offered]);
			Ok(())
		}

		cases {
			that_is_hidden_stays_open => (hidden_start(), "t", HashSet::from([Event("a"), Event("c")])),
			on_an_observable_event_commits => (simple_process(), "a", HashSet::from([Event("b")])),
		}
	}

	/// An external choice whose operands share a first event is a choice
	/// point at its initial state.
	#[test]
	fn a_first_event_of_both_operands_makes_a_choice_point() {
		let choice = composed(Process::external_choice);
		assert!(choice.is_choice(choice.initial));
	}

	/// Renaming keeps a declared choice point.
	#[test]
	fn renaming_keeps_a_choice_point() -> TestResult {
		let branching = TestProcess::choosing("B", "s0", "a", &["s1", "s2"]);
		let renamed = branching.rename(HashMap::from([(Event("a"), Event("x"))]))?;
		assert!(renamed.is_choice(State("s0")));
		Ok(())
	}

	// Hiding and renaming keep the timing constraint of an event, under its
	// new name where the operator renames it.
	#[cfg(feature = "testing-timing")]
	crate::tb_cases! {
		fn the_constraint_of_an_event_survives((transform, event): (Transform, &'static str)) -> TestResult {
			let process = TestProcess::timed("T", &[("a", 10)]);
			let copy = transform(&process)?;
			assert!(constrains(&copy, event));
			Ok(())
		}

		cases {
			hiding => (|process| Ok(process.hide(HashSet::from([Event("a")]))), "a"),
			renaming => (|process| process.rename(HashMap::from([(Event("a"), Event("x"))])), "x"),
		}
	}

	/// Renaming two events that hold different constraints to one name is
	/// refused.
	#[cfg(feature = "testing-timing")]
	#[test]
	fn renaming_two_differently_constrained_events_to_one_is_refused() {
		let process = TestProcess::timed("T", &[("a", 10), ("b", 20)]);
		let mapping = HashMap::from([(Event("a"), Event("x")), (Event("b"), Event("x"))]);

		let refused = process.rename(mapping);
		assert!(matches!(
			refused,
			Err(CompositionError::ConflictingTiming { event: Event("x") })
		));
	}

	// Each operator holds the timing constraints of both operands.
	#[cfg(feature = "testing-timing")]
	crate::tb_cases! {
		fn the_timing_of_both_operands_survives(compose: Compose) -> TestResult {
			let composed = compose(&TestProcess::timed("P", &[("a", 10)]), &TestProcess::timed("Q", &[("b", 20)]))?;
			assert_eq!([constrains(&composed, "a"), constrains(&composed, "b")], [true, true]);
			Ok(())
		}

		cases {
			a_sequential_composition => Process::sequential,
			an_external_choice => Process::external_choice,
			an_internal_choice => Process::internal_choice,
		}
	}

	/// A composition of two operands that agree on a constraint keeps one
	/// copy of it.
	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_composition_keeps_one_copy_of_an_agreeing_constraint() -> TestResult {
		let process = TestProcess::timed("P", &[("a", 10)]);
		let composed = Process::sequential(&process, &process)?;
		assert!(constrains(&composed, "a"));
		Ok(())
	}

	/// A composition refuses two constraints on one event that disagree.
	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_composition_refuses_constraints_that_do_not_agree() {
		let (first, second) = (TestProcess::timed("P", &[("a", 10)]), TestProcess::timed("Q", &[("a", 20)]));
		let refused = Process::sequential(&first, &second);
		assert!(matches!(
			refused,
			Err(CompositionError::ConflictingTiming { event: Event("a") })
		));
	}

	/// Hiding keeps the schedulability periods.
	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn hiding_keeps_the_schedulability_periods() {
		let process = scheduled(SchedulerType::RateMonotonic, 50);
		let copy = process.hide(HashSet::new());
		assert_eq!(copy.schedulability_periods, process.schedulability_periods);
	}

	/// A composition refuses two operands that name different schedulers.
	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn a_composition_refuses_two_schedulers() {
		let rate_monotonic = scheduled(SchedulerType::RateMonotonic, 50);
		let deadline_first = scheduled(SchedulerType::EarliestDeadlineFirst, 50);

		let refused = Process::internal_choice(&rate_monotonic, &deadline_first);
		assert!(matches!(refused, Err(CompositionError::ConflictingScheduler)));
	}

	/// A composition refuses two periods for one event.
	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn a_composition_refuses_two_periods_for_one_event() {
		let fast = scheduled(SchedulerType::RateMonotonic, 50);
		let slow = scheduled(SchedulerType::RateMonotonic, 100);

		let refused = Process::internal_choice(&fast, &slow);
		assert!(matches!(
			refused,
			Err(CompositionError::ConflictingTiming { event: Event("a") })
		));
	}
}
