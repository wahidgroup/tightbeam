//! Layer 2: CSP (Communicating Sequential Processes).
//!
//! It implements CSP process algebra for tightbeam testing, after Hoare's
//! theory:
//!
//! - Processes communicate through events (message passing).
//! - Observable events are visible, and hidden events (τ) are internal.
//! - A nondeterministic choice lets one event lead to more than one state.
//! - A labeled transition system (LTS) represents the behavior of a process.
//!
//! It requires the `testing-csp` feature.
//!
//! # Sources
//!
//! - C.A.R. Hoare, "Communicating Sequential Processes" (1978):
//!   <https://www.cs.cmu.edu/~crary/819-f09/Hoare78.pdf>

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock, PoisonError};

#[cfg(feature = "testing-timing")]
use core::time::Duration;

use crate::der::{Decode, DecodeValue, EncodeValue, Tag, Tagged};
use crate::der::{Header, Length, Reader, Writer};
use crate::testing::assertions::AssertionLabel;
use crate::testing::specs::composition::CompositionError;
use crate::trace::ConsumedTrace;
use crate::urn::Urn;
use crate::Errorizable;

#[cfg(feature = "testing-schedulability")]
use crate::testing::schedulability::{SchedulabilityError, SchedulerType, TaskSet};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::{TimedTransition, TimingConstraints, TimingGuard};

pub use super::lts::{Action, Alphabet, CspValidationResult, CspViolation, Event, State};

/// The intern pool for CSP state and event names built at runtime.
///
/// The engine keys [`State`] and [`Event`] on `&'static str` so both stay
/// `Copy`. A name built at runtime (a product state, a decoded event, or an
/// owned assertion label) must become `'static`. The pool deduplicates the
/// names, so each distinct name leaks once (CWE-401).
static INTERN_POOL: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();

/// Promotes a runtime string to `&'static str` through [`INTERN_POOL`].
pub(crate) fn intern<S>(name: S) -> &'static str
where
	S: AsRef<str> + Into<String>,
{
	let pool = INTERN_POOL.get_or_init(|| Mutex::new(HashSet::new()));
	let mut pool = pool.lock().unwrap_or_else(PoisonError::into_inner);
	if let Some(existing) = pool.get(name.as_ref()) {
		return existing;
	}

	let leaked: &'static str = Box::leak(name.into().into_boxed_str());
	pool.insert(leaked);

	leaked
}

impl From<Urn<'_>> for Event {
	fn from(urn: Urn<'_>) -> Self {
		Event(intern(urn.to_string()))
	}
}

impl From<&Urn<'_>> for Event {
	fn from(urn: &Urn<'_>) -> Self {
		Event(intern(urn.to_string()))
	}
}

// An `Event` encodes as a DER UTF8String. The decoder interns the decoded
// name, because `Event` holds a `&'static str`.
impl Tagged for Event {
	fn tag(&self) -> Tag {
		Tag::Utf8String
	}
}

impl EncodeValue for Event {
	fn value_len(&self) -> crate::der::Result<Length> {
		let s: String = self.0.to_string();
		s.value_len()
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		let s: String = self.0.to_string();
		s.encode_value(encoder)
	}
}

impl<'a> DecodeValue<'a> for Event {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> crate::der::Result<Self> {
		let s = String::decode_value(reader, header)?;
		Ok(Event(intern(s)))
	}
}

impl<'a> Decode<'a> for Event {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		let header = reader.peek_header()?;
		Self::decode_value(reader, header)
	}
}

/// A CSP transition: an event that takes one state to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
	/// The state the transition leaves.
	pub from: State,
	/// The action that labels the transition.
	pub action: Action,
	/// The state the transition enters.
	pub to: State,
}

/// The transition relation, from a state and an event to its target states.
///
/// More than one target for a state and an event is nondeterminism.
#[derive(Debug, Clone)]
pub struct TransitionRelation {
	/// The target states of each source state and event.
	transitions: HashMap<(State, Event), Vec<State>>,
}

impl TransitionRelation {
	pub fn new() -> Self {
		Self { transitions: HashMap::new() }
	}

	/// Adds a transition that takes `from` to `to` on `event`.
	pub fn add(&mut self, from: State, event: Event, to: State) {
		self.transitions.entry((from, event)).or_default().push(to);
	}

	/// Every state that `event` takes `from` to.
	pub fn targets(&self, from: State, event: &Event) -> Option<&[State]> {
		self.transitions.get(&(from, *event)).map(|v| v.as_slice())
	}

	/// Whether `event` takes `from` to more than one state.
	pub fn is_nondeterministic(&self, from: State, event: &Event) -> bool {
		self.transitions.get(&(from, *event)).map(|v| v.len() > 1).unwrap_or(false)
	}

	/// Iterates over every `((from, event), targets)` entry.
	pub fn iter(&self) -> impl Iterator<Item = (&(State, Event), &Vec<State>)> {
		self.transitions.iter()
	}

	/// Keeps the transitions of each event that `keep` accepts.
	pub(crate) fn retain<K>(&mut self, keep: K)
	where
		K: Fn(&Event) -> bool,
	{
		self.transitions.retain(|(_, event), _| keep(event));
	}
}

impl Default for TransitionRelation {
	fn default() -> Self {
		Self::new()
	}
}

/// What a process is evidence of.
///
/// The stable failures and failures-divergences models need the subject's
/// refusals, and only a specification states them.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Observation {
	/// A process written as a specification.
	#[default]
	Model,

	/// One execution recorded as a sequence of events.
	RecordedTrace,
}

impl Observation {
	/// Whether refusals are known, so `[F=` and `[FD=` are defined.
	pub fn carries_refusals(self) -> bool {
		matches!(self, Self::Model)
	}
}

/// A CSP process, held as a labeled transition system (LTS).
///
/// The LTS has these parts:
/// - An observable alphabet of external events.
/// - A hidden alphabet of internal τ events.
/// - A transition relation.
/// - The nondeterministic choice points.
/// - The timing constraints for real-time verification, when the process has them.
///
/// It is `#[non_exhaustive]`, because [`ProcessBuilder`] alone establishes the
/// invariants between the fields.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Process {
	/// The human-readable name of the process.
	pub name: &'static str,

	/// What this process is evidence of, as the code that builds it sets it.
	pub observation: Observation,

	/// Whether a run that records no event in this alphabet is a violation.
	///
	/// A trace that takes no transition satisfies every process, so the
	/// check would hold whatever the run did. A process requires progress,
	/// unless [`ProcessBuilder::permits_no_progress`] lifts the rule for a
	/// process that models a run with no event.
	pub requires_progress: bool,

	/// The state the process starts in.
	pub initial: State,

	/// Every state of the process.
	pub states: HashSet<State>,

	/// The terminal (accepting) states. One with no enabled action is a STOP.
	pub terminal: HashSet<State>,

	/// The nondeterministic choice points, where one event may lead to more
	/// than one state.
	pub choice: HashSet<State>,

	/// The observable alphabet (Σ) of external events.
	pub observable: HashSet<Event>,

	/// The hidden alphabet (τ) of internal events.
	pub hidden: HashSet<Event>,

	/// The transition relation of the untimed transitions.
	pub transitions: TransitionRelation,

	/// The description of the process, when its spec gives one.
	pub description: Option<&'static str>,

	/// The timing constraints that real-time verification checks.
	#[cfg(feature = "testing-timing")]
	pub timing_constraints: Option<TimingConstraints>,

	/// The timed transitions, keyed by the source state and the event.
	///
	/// Each one is an edge of the process. Its guard decides when FDR
	/// exploration takes it.
	#[cfg(feature = "testing-timing")]
	pub timed_transitions: Option<HashMap<(State, Event), Vec<TimedTransition>>>,

	/// The scheduler and the period of each event for schedulability analysis.
	/// [`Self::generate_task_set`] combines them with the timing constraints
	/// into a [`TaskSet`].
	#[cfg(feature = "testing-schedulability")]
	pub schedulability_periods: Option<(SchedulerType, HashMap<Event, Duration>)>,
}

/// The parts of a process that a search of its traces, failures, and
/// divergences reads ([`Process::search_structure`]).
///
/// - Each part is in sorted order, so two processes with equal parts have equal structures.
/// - The name stays out, because the algebra operators (`hide`, `rename`) give
///   one name to processes of different structure.
/// - A guard and its resets stay out, because the search takes a timed edge
///   whatever the clocks read, as [`Process::step`] reads it.
#[cfg(feature = "testing-fdr")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SearchStructure {
	/// The state the search starts from.
	initial: State,
	/// Every state of the process.
	states: Vec<State>,
	/// The accepting states, where a run can terminate.
	terminal: Vec<State>,
	/// The declared nondeterministic choice points.
	choice: Vec<State>,
	/// The events of the observable alphabet (Σ).
	observable: Vec<Event>,
	/// The events of the hidden alphabet (τ).
	hidden: Vec<Event>,
	/// Each transition, untimed or timed, as its source, its event, and its
	/// target.
	transitions: Vec<(State, Event, State)>,
}

/// An edge that the clocks allow, and the clocks it resets.
#[cfg(all(feature = "testing-timing", any(test, feature = "testing-fdr")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Successor<'a> {
	/// The state the edge leads to.
	pub(crate) to: State,

	/// The clocks that the edge resets when a run takes it.
	pub(crate) resets: &'a [String],
}

impl Process {
	/// Creates a [`ProcessBuilder`] for a process named `name`.
	pub fn builder(name: &'static str) -> ProcessBuilder {
		ProcessBuilder::new(name)
	}

	/// Returns the observable alphabet (Σ).
	pub fn observable_alphabet(&self) -> &HashSet<Event> {
		&self.observable
	}

	/// Returns the hidden alphabet (τ).
	pub fn hidden_alphabet(&self) -> &HashSet<Event> {
		&self.hidden
	}

	/// The projection of `trace` onto this process's observable alphabet.
	///
	/// `traces(P \ X) = { s ↾ (Σ ∖ X) | s ∈ traces(P) }`. A recording also
	/// holds the steps this process models internally, so the refinement check
	/// projects it before the comparison. The projection holds in the traces
	/// model only, because hiding is not sound in `F` or `FD`.
	pub fn project(&self, trace: impl AsRef<[Event]>) -> Vec<Event> {
		let trace = trace.as_ref();
		trace.iter().filter(|event| self.observable.contains(event)).copied().collect()
	}

	/// The events `other` makes observable that this process models in
	/// neither alphabet, sorted by name.
	///
	/// This process neither permits nor forbids them, so they count as model
	/// coverage and not as a violation.
	#[cfg(any(test, feature = "testing-fdr"))]
	pub(crate) fn unmodelled(&self, other: &Self) -> Vec<Event> {
		let mut found: Vec<Event> = other
			.observable
			.iter()
			.filter(|event| !self.observable.contains(event) && !self.hidden.contains(event))
			.copied()
			.collect();
		found.sort_unstable();
		found
	}

	/// The states that `event` takes `state` to.
	///
	/// A timed transition takes `state` to its target whatever the clocks read.
	pub fn step(&self, state: State, event: &Event) -> Vec<State> {
		let untimed = self.transitions.targets(state, event).unwrap_or_default();

		#[cfg(feature = "testing-timing")]
		let timed = self.timed_edges(state, event).iter().map(|edge| edge.to);
		#[cfg(not(feature = "testing-timing"))]
		let timed = core::iter::empty();

		untimed.iter().copied().chain(timed).collect()
	}

	/// Returns the actions that `state` enables.
	///
	/// The actions are sorted by event name, observable before hidden on a
	/// name collision, so violation reports and byte-driven exploration are
	/// reproducible whatever the `HashSet` iteration order.
	///
	/// A timed transition enables its event whatever the clocks read.
	pub fn enabled(&self, state: State) -> Vec<Action> {
		let mut actions = Vec::new();

		for event in &self.observable {
			if self.has_edge(state, event) {
				actions.push(Action { event: *event, alphabet: Alphabet::Observable });
			}
		}

		for event in &self.hidden {
			if self.has_edge(state, event) {
				actions.push(Action { event: *event, alphabet: Alphabet::Hidden });
			}
		}

		actions.sort_by(|a, b| a.event.0.cmp(b.event.0).then_with(|| a.is_hidden().cmp(&b.is_hidden())));
		actions
	}

	/// The first state and event that refute structural determinism, or
	/// `None` when the process is structurally deterministic.
	///
	/// A process with no hidden action and no `(state, event)` pair of more
	/// than one target state is deterministic in CSP (Roscoe 2010, §10.5).
	/// External choice is deterministic, so it names no witness.
	///
	/// - The walk reads every state of the process, reachable or not.
	/// - It reads the states in name order and the actions of each state in
	///   the order of [`Self::enabled`], so each run names the same witness.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Settles")
	///     .initial_state(State("S0"))
	///     .add_hidden(Event("tau"))
	///     .add_transition(State("S0"), Event("tau"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// assert_eq!(process.determinism_witness(), Some((State("S0"), Event("tau"))));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn determinism_witness(&self) -> Option<(State, Event)> {
		let mut states: Vec<State> = self.states.iter().copied().collect();
		states.sort_unstable();
		for state in states {
			for action in self.enabled(state) {
				let mut targets = self.step(state, &action.event);
				targets.sort_unstable();
				targets.dedup();

				if action.is_hidden() || targets.len() > 1 {
					return Some((state, action.event));
				}
			}
		}

		None
	}

	/// Whether `event` takes `state` to a state, whatever the clocks read.
	fn has_edge(&self, state: State, event: &Event) -> bool {
		#[cfg(feature = "testing-timing")]
		let timed = !self.timed_edges(state, event).is_empty();
		#[cfg(not(feature = "testing-timing"))]
		let timed = false;

		timed || self.transitions.targets(state, event).is_some()
	}

	/// The timed transitions that `event` labels at `state`.
	#[cfg(feature = "testing-timing")]
	pub(crate) fn timed_edges(&self, state: State, event: &Event) -> &[TimedTransition] {
		let table = self.timed_transitions.as_ref();
		let edges = table.and_then(|table| table.get(&(state, *event)));
		edges.map(Vec::as_slice).unwrap_or_default()
	}

	/// Whether this process holds a timed transition.
	#[cfg(feature = "testing-timing")]
	pub(crate) fn has_timed_transitions(&self) -> bool {
		self.timed_transitions.as_ref().is_some_and(|table| !table.is_empty())
	}

	/// The clock readings when a run starts: each clock that a guard or a
	/// reset of this process names reads zero.
	///
	/// A run of a timed automaton starts with every clock at zero (R. Alur and
	/// D.L. Dill, "A theory of timed automata", Theoretical Computer Science
	/// 126, 1994), and a reset sets a clock back to zero.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::timing::TimingGuard;
	///
	/// let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
	/// let process = Process::builder("Guarded")
	///     .initial_state(State("S0"))
	///     .clock("clk")
	///     .add_observable(Event("arm"))
	///     .add_timed_transition(State("S0"), Event("arm"), State("S1"), Some(guard), Vec::new())
	///     .build()?;
	///
	/// assert_eq!(process.initial_clocks().get("clk"), Some(&Duration::ZERO));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[cfg(feature = "testing-timing")]
	pub fn initial_clocks(&self) -> HashMap<String, Duration> {
		let edges = self.timed_transitions.iter().flat_map(HashMap::values).flatten();
		let named = edges.flat_map(TimedTransition::clocks);
		named.map(|clock| (clock.to_string(), Duration::ZERO)).collect()
	}

	/// The edges that `event` takes from `state` while the clocks read
	/// `clocks`.
	///
	/// An untimed edge is always a successor, and it resets no clock. A timed
	/// edge is a successor when `clocks` satisfy its guard, and it resets the
	/// clocks it names.
	#[cfg(all(feature = "testing-timing", any(test, feature = "testing-fdr")))]
	pub(crate) fn successors<'a>(
		&'a self,
		state: State,
		event: &Event,
		clocks: &'a HashMap<String, Duration>,
	) -> impl Iterator<Item = Successor<'a>> + 'a {
		let untimed = self.transitions.targets(state, event).unwrap_or_default();
		let untimed = untimed.iter().map(|to| Successor { to: *to, resets: &[] });
		let edges = self.timed_edges(state, event);
		let allowed = edges.iter().filter(move |edge| edge.guard_satisfied(clocks));
		let timed = allowed.map(|edge| Successor { to: edge.to, resets: &edge.reset_clocks });

		untimed.chain(timed)
	}

	/// The actions of `state` that have a successor while the clocks read
	/// `clocks`.
	///
	/// A state whose every action a guard refuses offers no action, so FDR
	/// exploration finds a deadlock there.
	#[cfg(all(feature = "testing-timing", feature = "testing-fdr"))]
	pub(crate) fn enabled_under(&self, state: State, clocks: &HashMap<String, Duration>) -> Vec<Action> {
		let mut actions = self.enabled(state);
		actions.retain(|action| self.successors(state, &action.event, clocks).next().is_some());
		actions
	}

	/// Whether `state` is a terminal (accepting) state.
	pub fn is_terminal(&self, state: State) -> bool {
		self.terminal.contains(&state)
	}

	/// Whether `state` is a declared nondeterministic choice point.
	pub fn is_choice(&self, state: State) -> bool {
		self.choice.contains(&state)
	}

	/// Whether `state` is stable: it enables no hidden action.
	///
	/// It checks each event of the hidden alphabet for an edge from `state`,
	/// as the hidden actions of [`Self::enabled`] do, with no allocation.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Settle")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("done"))
	///     .add_hidden(Event("settle"))
	///     .add_transition(State("S0"), Event("settle"), State("S1"))
	///     .add_transition(State("S1"), Event("done"), State("S2"))
	///     .add_terminal(State("S2"))
	///     .build()?;
	///
	/// assert!(!process.is_stable(State("S0")));
	/// assert!(process.is_stable(State("S1")));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn is_stable(&self, state: State) -> bool {
		let has_step = |event: &Event| self.has_edge(state, event);
		!self.hidden.iter().any(has_step)
	}

	/// The observable events that `state` offers: the events of the observable
	/// actions of [`Self::enabled`].
	///
	/// # Examples
	///
	/// ```
	/// use std::collections::HashSet;
	///
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Choose")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("a"))
	///     .add_observable(Event("b"))
	///     .add_hidden(Event("t"))
	///     .add_transition(State("S0"), Event("a"), State("S1"))
	///     .add_transition(State("S0"), Event("t"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// assert_eq!(process.offers(State("S0")), HashSet::from([Event("a")]));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn offers(&self, state: State) -> HashSet<Event> {
		let enabled_actions = self.enabled(state);
		let observable = enabled_actions.into_iter().filter(Action::is_observable);
		observable.map(|action| action.event).collect()
	}

	/// The refusal set that the failures model records at `state`.
	///
	/// - At an accepting state, where the process can terminate, the set is every observable event.
	/// - At another stable state, the set is each observable event that `state` does not offer.
	/// - At an unstable state, the answer is `None`, as the state can take a hidden action before it refuses.
	///
	/// A process that can terminate after a trace `s` has the failure `(s, Σ)`,
	/// because it can refuse every event but its termination (axiom F4 of A.W.
	/// Roscoe, *The Theory and Practice of Concurrency*, 2005 revision,
	/// §8.3.1, which the stable failures model of §8.4 keeps).
	///
	/// # Examples
	///
	/// ```
	/// use std::collections::HashSet;
	///
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Accepting")
	///     .initial_state(State("Idle"))
	///     .add_observable(Event("a"))
	///     .add_observable(Event("b"))
	///     .add_hidden(Event("t"))
	///     .add_transition(State("Idle"), Event("a"), State("Busy"))
	///     .add_transition(State("Busy"), Event("b"), State("Wait"))
	///     .add_transition(State("Wait"), Event("t"), State("Idle"))
	///     .add_terminal(State("Idle"))
	///     .build()?;
	///
	/// let every_event = HashSet::from([Event("a"), Event("b")]);
	/// assert_eq!(process.failure_refusals(State("Idle")), Some(every_event));
	/// assert_eq!(process.failure_refusals(State("Busy")), Some(HashSet::from([Event("a")])));
	/// assert_eq!(process.failure_refusals(State("Wait")), None);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn failure_refusals(&self, state: State) -> Option<HashSet<Event>> {
		if self.is_terminal(state) {
			return Some(self.observable.clone());
		}
		if !self.is_stable(state) {
			return None;
		}

		let offers = self.offers(state);
		let refused = self.observable.difference(&offers).copied().collect();
		Some(refused)
	}

	/// The states of this process that can diverge.
	///
	/// A state diverges when a run of hidden events from it reaches a cycle of
	/// hidden events, so the process can perform hidden events forever after
	/// the trace that led to it (A.W. Roscoe, *The Theory and Practice of
	/// Concurrency*, 2005 revision, §8.3.1). One pass over the graph of hidden
	/// steps computes the answer:
	///
	/// 1. Tarjan's algorithm, with a stack of its own, finds the strongly connected components.
	/// 2. A state with a hidden step inside its own component lies on a cycle of hidden events.
	/// 3. A search back along the hidden steps marks each state that reaches such a state.
	///
	/// - On a finite process the answer is exact, needs no bound on the run, and holds under any event names.
	/// - A timed hidden transition is a step whatever the clocks read, as [`Self::step`] reads it.
	/// - A process with no hidden event computes the answer with no allocation.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Lasso")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("b"))
	///     .add_hidden(Event("p"))
	///     .add_hidden(Event("t"))
	///     .add_hidden(Event("u"))
	///     .add_transition(State("S0"), Event("p"), State("S1"))
	///     .add_transition(State("S1"), Event("t"), State("S2"))
	///     .add_transition(State("S2"), Event("u"), State("S1"))
	///     .add_transition(State("S2"), Event("b"), State("S3"))
	///     .add_terminal(State("S3"))
	///     .build()?;
	///
	/// let divergent = process.divergent_states();
	/// assert_eq!(divergent.witness(State("S0")), Some(vec![Event("p"), Event("t"), Event("u")]));
	/// assert!(!divergent.contains(State("S3")));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn divergent_states(&self) -> DivergentStates {
		if self.hidden.is_empty() {
			return DivergentStates::default();
		}

		let graph = HiddenGraph::of(self);
		graph.divergent_states()
	}

	/// Builds the [`TaskSet`] of the timing constraints and the schedulability
	/// periods, or `Ok(None)` for a process with no schedulability block.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::EmptyTaskSet`] -- the process declares periods and no timing constraints.
	/// - [`SchedulabilityError::MissingPeriod`] -- a WCET constraint names an event that has no period.
	#[cfg(feature = "testing-schedulability")]
	pub fn generate_task_set(&self) -> Result<Option<TaskSet>, SchedulabilityError> {
		let Some((scheduler, periods)) = &self.schedulability_periods else {
			return Ok(None);
		};
		let Some(timing) = &self.timing_constraints else {
			return Err(SchedulabilityError::EmptyTaskSet);
		};

		let task_set = timing.to_task_set(periods, *scheduler)?;
		Ok(Some(task_set))
	}
}

#[cfg(feature = "testing-fdr")]
impl Process {
	/// The structure of this process that a search of its traces, failures,
	/// and divergences reads.
	///
	/// Two processes with equal structures have the same sets at each depth
	/// bound, so the memoization cache of the refinement check keys on it.
	pub(crate) fn search_structure(&self) -> SearchStructure {
		/// The members of `set`, sorted.
		fn sorted<T: Copy + Ord>(set: &HashSet<T>) -> Vec<T> {
			let mut members: Vec<T> = set.iter().copied().collect();
			members.sort_unstable();
			members
		}

		let untimed = self.transitions.iter();
		let untimed = untimed.flat_map(|((from, event), targets)| targets.iter().map(move |to| (*from, *event, *to)));

		#[cfg(feature = "testing-timing")]
		let timed = self.timed_transitions.iter().flatten();
		#[cfg(feature = "testing-timing")]
		let timed = timed.flat_map(|((from, event), edges)| edges.iter().map(move |edge| (*from, *event, edge.to)));
		#[cfg(not(feature = "testing-timing"))]
		let timed = core::iter::empty();

		let mut transitions: Vec<(State, Event, State)> = untimed.chain(timed).collect();
		transitions.sort_unstable();

		SearchStructure {
			initial: self.initial,
			states: sorted(&self.states),
			terminal: sorted(&self.terminal),
			choice: sorted(&self.choice),
			observable: sorted(&self.observable),
			hidden: sorted(&self.hidden),
			transitions,
		}
	}
}

/// The states of a process that can diverge ([`Process::divergent_states`]).
///
/// Each divergent state holds one hidden step to a divergent state, toward or
/// along a cycle of hidden events. A run of these steps stays among the
/// divergent states, so it reaches a state it passed. That run is the witness
/// of the divergence.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::specs::csp::{Event, Process, State};
///
/// let process = Process::builder("Spin")
///     .initial_state(State("S0"))
///     .add_observable(Event("a"))
///     .add_hidden(Event("t"))
///     .add_transition(State("S0"), Event("a"), State("S1"))
///     .add_transition(State("S1"), Event("t"), State("S1"))
///     .build()?;
///
/// let divergent = process.divergent_states();
/// assert!(divergent.contains(State("S1")));
/// assert_eq!(divergent.witness(State("S0")), None);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DivergentStates {
	/// The hidden step that each divergent state takes in its witness, as the
	/// event and the state it reaches.
	steps: HashMap<State, (Event, State)>,
}

impl DivergentStates {
	/// Whether `state` can diverge.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Spin")
	///     .initial_state(State("S0"))
	///     .add_hidden(Event("t"))
	///     .add_transition(State("S0"), Event("t"), State("S0"))
	///     .build()?;
	///
	/// assert!(process.divergent_states().contains(State("S0")));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn contains(&self, state: State) -> bool {
		self.steps.contains_key(&state)
	}

	/// The witness that `state` can diverge, or `None` when it cannot.
	///
	/// The witness holds the hidden events of a run from `state` to a cycle of
	/// hidden events and once around it. A state that cannot diverge answers
	/// with no allocation.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Spin")
	///     .initial_state(State("S0"))
	///     .add_hidden(Event("t"))
	///     .add_hidden(Event("u"))
	///     .add_transition(State("S0"), Event("t"), State("S1"))
	///     .add_transition(State("S1"), Event("u"), State("S0"))
	///     .build()?;
	///
	/// let witness = process.divergent_states().witness(State("S1"));
	/// assert_eq!(witness, Some(vec![Event("u"), Event("t")]));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn witness(&self, state: State) -> Option<Vec<Event>> {
		let walk = self.walk(state)?;
		Some(walk.events)
	}

	/// The states of the cycle that the witness of `state` goes around, in the
	/// order the run passes them, or `None` when `state` cannot diverge.
	pub(crate) fn cycle(&self, state: State) -> Option<Vec<State>> {
		let Walk { mut passed, repeated, .. } = self.walk(state)?;
		let start = passed.iter().position(|passed| *passed == repeated)?;
		Some(passed.split_off(start))
	}

	/// The run of the witness of `state`, up to the first state it passes a
	/// second time.
	fn walk(&self, state: State) -> Option<Walk> {
		let mut step = self.steps.get(&state)?;
		let mut walk = Walk { events: Vec::new(), passed: vec![state], repeated: state };
		loop {
			let (event, to) = *step;
			walk.events.push(event);
			if walk.passed.contains(&to) {
				walk.repeated = to;
				return Some(walk);
			}

			// Each divergent state steps to a divergent state, so `to` holds a
			// step of its own.
			walk.passed.push(to);
			step = self.steps.get(&to)?;
		}
	}
}

/// A run along the witness steps of [`DivergentStates`].
struct Walk {
	/// The hidden events of the run, in order.
	events: Vec<Event>,
	/// The states the run passed, from its start, in order.
	passed: Vec<State>,
	/// The state that the run passed a second time, where it ends.
	repeated: State,
}

/// The hidden steps of a process, over the indices of its states.
struct HiddenGraph {
	/// Each state of the process, sorted by name, then each state that a
	/// hidden step reaches outside that set.
	states: Vec<State>,
	/// The hidden steps of each state in `states`, as the event and the index
	/// of the state it reaches, in the order of [`Process::enabled`] and
	/// [`Process::step`].
	steps: Vec<Vec<(Event, usize)>>,
}

impl HiddenGraph {
	/// The hidden steps of `process`.
	fn of(process: &Process) -> Self {
		let mut states: Vec<State> = process.states.iter().copied().collect();
		states.sort_unstable();

		let mut index: HashMap<State, usize> = states.iter().copied().zip(0..).collect();
		let mut graph = Self { states, steps: Vec::new() };

		while let Some(&state) = graph.states.get(graph.steps.len()) {
			let mut steps = Vec::new();
			let enabled_actions = process.enabled(state);
			for action in enabled_actions.into_iter().filter(Action::is_hidden) {
				for to in process.step(state, &action.event) {
					let at = graph.index_of(&mut index, to);
					steps.push((action.event, at));
				}
			}

			graph.steps.push(steps);
		}

		graph
	}

	/// The index of `state` in `states`, which `state` joins at first visit.
	fn index_of(&mut self, index: &mut HashMap<State, usize>, state: State) -> usize {
		let next = self.states.len();
		let at = *index.entry(state).or_insert(next);
		if at == next {
			self.states.push(state);
		}

		at
	}

	/// The states that can diverge, each with the hidden step of its witness.
	fn divergent_states(&self) -> DivergentStates {
		let components = self.components();
		let mut chosen: Vec<Option<(Event, usize)>> = vec![None; self.states.len()];
		let mut found = VecDeque::new();

		// 1. A state with a hidden step inside its own component lies on a
		// cycle, and that step keeps its run on the cycle.
		for (from, steps) in self.steps.iter().enumerate() {
			let component = components.get(from).copied().flatten();
			let inside = |to: usize| component.is_some() && components.get(to).copied().flatten() == component;
			let cycle_step = steps.iter().find(|(_event, to)| inside(*to));
			if let (Some(step), Some(slot)) = (cycle_step, chosen.get_mut(from)) {
				*slot = Some(*step);
				found.push_back(from);
			}
		}

		// 2. A search back along the hidden steps gives each state that
		// reaches a cycle its first step toward the nearest one.
		let entering = self.entering();
		while let Some(to) = found.pop_front() {
			for &(from, event) in entering.get(to).into_iter().flatten() {
				let Some(slot) = chosen.get_mut(from) else {
					continue;
				};

				if slot.is_none() {
					*slot = Some((event, to));
					found.push_back(from);
				}
			}
		}

		// 3. Each chosen step trades the indices of its states for their names.
		let indexed = chosen.into_iter().enumerate();
		let named = indexed.filter_map(|(from, step)| self.named(from, step?));
		DivergentStates { steps: named.collect() }
	}

	/// The hidden steps that enter each state, as the index of the state they
	/// leave and the event.
	fn entering(&self) -> Vec<Vec<(usize, Event)>> {
		let mut entering = vec![Vec::new(); self.states.len()];
		for (from, steps) in self.steps.iter().enumerate() {
			for &(event, to) in steps {
				if let Some(into) = entering.get_mut(to) {
					into.push((from, event));
				}
			}
		}

		entering
	}

	/// The step `(event, to)` from the state at `from`, with each state by
	/// its name.
	fn named(&self, from: usize, (event, to): (Event, usize)) -> Option<(State, (Event, State))> {
		let from = self.states.get(from)?;
		let to = self.states.get(to)?;
		Some((*from, (event, *to)))
	}

	/// The strongly connected component of each state, numbered in the order
	/// that Tarjan's algorithm closes them.
	fn components(&self) -> Vec<Option<usize>> {
		let count = self.states.len();
		let mut search = Tarjan::new(count);
		for root in 0..count {
			search.search_from(self, root);
		}

		search.components
	}
}

/// Tarjan's search for the strongly connected components of a [`HiddenGraph`].
///
/// The depth-first search keeps each state it descends into, with its next
/// step to try, on a stack of its own, so the call stack keeps one depth
/// however long a run of hidden steps grows.
struct Tarjan {
	/// The order in which the search reached each state, once it has.
	order: Vec<Option<usize>>,
	/// The lowest order that each state reaches through the states on `open`.
	low: Vec<usize>,
	/// The reached states whose component is open, in the order reached.
	open: Vec<usize>,
	/// Whether each state is on `open`.
	on_open: Vec<bool>,
	/// The component of each state, once its component closes.
	components: Vec<Option<usize>>,
	/// The count of the states the search reached.
	reached: usize,
	/// The count of the components the search closed.
	closed: usize,
}

impl Tarjan {
	/// A search over `count` states that has reached none.
	fn new(count: usize) -> Self {
		Self {
			order: vec![None; count],
			low: vec![0; count],
			open: Vec::new(),
			on_open: vec![false; count],
			components: vec![None; count],
			reached: 0,
			closed: 0,
		}
	}

	/// Searches the states that `root` reaches, unless an earlier search
	/// reached `root`.
	fn search_from(&mut self, graph: &HiddenGraph, root: usize) {
		if self.order.get(root).copied().flatten().is_some() {
			return;
		}

		self.reach(root);

		let mut calls = vec![(root, 0usize)];
		while let Some(&(state, next)) = calls.last() {
			let step = graph.steps.get(state).and_then(|steps| steps.get(next));
			let Some(&(_event, to)) = step else {
				calls.pop();
				let parent = calls.last().map(|&(parent, _next)| parent);
				self.finish(state, parent);
				continue;
			};

			if let Some((_state, next)) = calls.last_mut() {
				*next = next.saturating_add(1);
			}

			match self.order.get(to).copied().flatten() {
				None => {
					self.reach(to);
					calls.push((to, 0));
				}
				Some(order) if self.is_open(to) => self.lower(state, order),
				Some(_) => {}
			}
		}
	}

	/// Gives `state` the next order, and opens it.
	fn reach(&mut self, state: usize) {
		let reached = self.reached;
		if let Some(order) = self.order.get_mut(state) {
			*order = Some(reached);
		}
		if let Some(low) = self.low.get_mut(state) {
			*low = reached;
		}
		if let Some(on_open) = self.on_open.get_mut(state) {
			*on_open = true;
		}

		self.open.push(state);
		self.reached = reached.saturating_add(1);
	}

	/// Whether `state` is on `open`.
	fn is_open(&self, state: usize) -> bool {
		self.on_open.get(state).copied().unwrap_or(false)
	}

	/// Lowers the low order of `state` to `order`, when `order` is lower.
	fn lower(&mut self, state: usize, order: usize) {
		if let Some(low) = self.low.get_mut(state) {
			*low = order.min(*low);
		}
	}

	/// Leaves `state` once the search tried each of its steps.
	///
	/// The parent of `state` takes its low order. A state whose low order is
	/// its own order is the root of a component, which closes over the states
	/// above it on `open`.
	fn finish(&mut self, state: usize, parent: Option<usize>) {
		let Some(low) = self.low.get(state).copied() else {
			return;
		};
		if let Some(parent) = parent {
			self.lower(parent, low);
		}

		let order = self.order.get(state).copied().flatten();
		if order != Some(low) {
			return;
		}

		while let Some(member) = self.open.pop() {
			if let Some(on_open) = self.on_open.get_mut(member) {
				*on_open = false;
			}
			if let Some(component) = self.components.get_mut(member) {
				*component = Some(self.closed);
			}
			if member == state {
				break;
			}
		}

		self.closed = self.closed.saturating_add(1);
	}
}

/// A CSP process specification that checks a recorded trace.
///
/// When a scenario builds its configuration, it builds the process of its spec
/// once ([`Self::to_process_cow`]) and checks the claims of the spec once
/// ([`Self::verify_claims`]). Each grade then checks the trace of the run
/// against that one process.
pub trait ProcessSpec {
	/// Checks `trace` against `process`, the process that
	/// [`Self::to_process_cow`] built for this spec, and returns each
	/// violation.
	///
	/// The default checks `trace` against `process` alone. A spec that checks
	/// a trace by rules of its own overrides it.
	fn validate_trace(&self, process: &Process, trace: &ConsumedTrace) -> CspValidationResult {
		process.validate_trace(trace)
	}

	/// Returns the [`Process`] of this spec, which the trace check and FDR
	/// exploration walk.
	///
	/// The result is a `Cow` because a process comes from one of two sources:
	/// - A [`Process`] lends itself as a borrowed process.
	/// - A spec type, such as a [`CompositionSpec`] ZST, builds an owned process.
	///
	/// # Errors
	///
	/// - The [`CompositionError`] of a process that does not build, such as an alphabet outside its operands.
	///
	/// [`CompositionSpec`]: super::composition::CompositionSpec
	fn to_process_cow(&self) -> Result<Cow<'_, Process>, CompositionError>;

	/// Checks the properties that this spec claims of its process.
	///
	/// The default holds, as for a spec with no claim. A [`CompositionSpec`]
	/// checks the claims of its `properties:` block and of each operand
	/// ([`CompositionSpec::verify_properties`]).
	///
	/// # Errors
	///
	/// - The [`CompositionError`] of a claim that the process breaks.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, ProcessSpec, State};
	///
	/// let ping = Process::builder("Ping")
	///     .initial_state(State("idle"))
	///     .add_observable(Event("ping"))
	///     .add_transition(State("idle"), Event("ping"), State("done"))
	///     .add_terminal(State("done"))
	///     .build()?;
	///
	/// assert!(ping.verify_claims().is_ok());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`CompositionSpec`]: super::composition::CompositionSpec
	/// [`CompositionSpec::verify_properties`]: super::composition::CompositionSpec::verify_properties
	fn verify_claims(&self) -> Result<(), CompositionError> {
		Ok(())
	}
}

impl Process {
	/// Validates a consumed trace against this CSP process.
	///
	/// - A trace is a sequence over the observable alphabet, so the check
	///   matches each event there after a τ-closure takes the τ transitions
	///   silently. An event that only a hidden action enables is a
	///   [`CspViolation::EventNotEnabled`].
	/// - The check tracks the candidate states as a set, so it follows every
	///   branch of a nondeterministic choice at once.
	/// - More than one target is legal only at a state that
	///   [`ProcessBuilder::add_choice`] registers. Elsewhere it is a
	///   [`CspViolation::NondeterministicChoice`].
	pub fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult {
		let mut violations = Vec::new();
		let mut current_states = vec![self.initial];

		// The filter projects the trace onto this process's alphabet by exact
		// URN identity, as Hoare's restriction `tr ↾ A` does. A label outside
		// the alphabet falls outside this specification, so the check drops it.
		let events: Vec<Event> = trace
			.assertions
			.iter()
			.filter_map(|assertion| {
				let AssertionLabel::Custom(recorded) = &assertion.label;
				let recorded = recorded.as_ref();
				self.observable
					.iter()
					.chain(self.hidden.iter())
					.find(|event| recorded == event.0)
					.copied()
			})
			.collect();

		for event in &events {
			let closure = self.tau_closure(&current_states);
			let action = Action { event: *event, alphabet: Alphabet::Observable };

			// The run has terminated when every candidate is a STOP, a terminal
			// state with no enabled action. An accepting state that enables an
			// action stays live, as in a cyclic `terminal { Idle }` model.
			if closure
				.iter()
				.all(|state| self.is_terminal(*state) && self.enabled(*state).is_empty())
			{
				if let Some(terminal_state) = closure.first().copied() {
					violations.push(CspViolation::AfterTermination { event: *event, terminal_state });
				}

				continue;
			}

			let mut seen = HashSet::new();
			let mut next_states = Vec::new();
			for state in closure.iter().filter(|state| self.enabled(**state).contains(&action)) {
				let targets = self.step(*state, event);

				if targets.len() > 1 && !self.is_choice(*state) {
					violations.push(CspViolation::NondeterministicChoice {
						event: *event,
						state: *state,
						next_states: targets.clone(),
					});
				}

				for target in targets {
					if seen.insert(target) {
						next_states.push(target);
					}
				}
			}

			if next_states.is_empty() {
				let state = closure.first().copied().unwrap_or(self.initial);
				violations.push(CspViolation::EventNotEnabled {
					event: *event,
					state,
					enabled: self.enabled_from_set(&closure),
				});

				continue;
			}

			current_states = next_states;
		}

		if self.requires_progress && events.is_empty() {
			violations.push(CspViolation::NoProgress { initial: self.initial });
		}

		CspValidationResult { valid: violations.is_empty(), violations }
	}

	/// Every state that hidden (τ) transitions alone reach from `states`, with
	/// the input states included. A worklist walks them, so a deep chain costs
	/// no stack.
	pub(crate) fn tau_closure(&self, states: impl AsRef<[State]>) -> Vec<State> {
		let states = states.as_ref();
		let mut closure: Vec<State> = states.to_vec();
		let mut seen: HashSet<State> = states.iter().copied().collect();
		let mut idx = 0;
		while let Some(state) = closure.get(idx).copied() {
			idx += 1;

			for hidden_action in self.enabled(state).iter().filter(|action| action.is_hidden()) {
				for target in self.step(state, &hidden_action.event) {
					if seen.insert(target) {
						closure.push(target);
					}
				}
			}
		}

		closure
	}

	/// The union of the actions that `states` enable, deduplicated and sorted
	/// so violation reports are reproducible.
	fn enabled_from_set(&self, states: impl AsRef<[State]>) -> Vec<Action> {
		let states = states.as_ref();
		let mut actions: Vec<Action> = Vec::new();
		for state in states {
			for action in self.enabled(*state) {
				if !actions.contains(&action) {
					actions.push(action);
				}
			}
		}

		actions.sort_by(|a, b| a.event.0.cmp(b.event.0).then_with(|| a.is_hidden().cmp(&b.is_hidden())));
		actions
	}
}

impl ProcessSpec for Process {
	fn to_process_cow(&self) -> Result<Cow<'_, Process>, CompositionError> {
		Ok(Cow::Borrowed(self))
	}
}

/// An error that a [`Process`] does not build with.
///
/// [`ProcessBuilder::build`] returns the structural ones. The process of a
/// [`tb_process_spec!`](crate::tb_process_spec!) also returns the timing
/// ones, for a `timing` block whose bounds disagree or whose deadline does
/// not build.
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum ProcessBuildError {
	/// No call to [`ProcessBuilder::initial_state`] set the initial state.
	#[error("initial state not set")]
	MissingInitialState,

	/// A guard or a reset names a clock that no call to
	/// [`ProcessBuilder::clock`] declares.
	#[error("the clock {clock} is not declared")]
	UndeclaredClock {
		/// The name of the undeclared clock.
		clock: String,
	},

	/// A process spec states two timing bounds for `event` that do not agree.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::testing::specs::csp::{Event, ProcessBuildError};
	/// use tightbeam::urn::Urn;
	/// use tightbeam::{tb_process_spec, wcet};
	///
	/// const STEP: Urn<'static> = tightbeam::urn!("doc", "event:bound/step");
	///
	/// tb_process_spec! {
	///     pub BoundTwice,
	///     events {
	///         observable { STEP }
	///         hidden { }
	///     }
	///     states {
	///         S0 => { STEP => S1 }
	///     }
	///     terminal { S1 }
	///     timing {
	///         wcet: {
	///             STEP => wcet!(Duration::from_millis(5)),
	///             STEP => wcet!(Duration::from_millis(9))
	///         }
	///     }
	/// }
	///
	/// let refused = BoundTwice::process();
	/// assert_eq!(refused.err(), Some(ProcessBuildError::ConflictingTiming { event: Event::from(STEP) }));
	/// ```
	#[cfg(feature = "testing-timing")]
	#[error("the spec states two timing bounds for the event {event} that do not agree")]
	ConflictingTiming {
		/// The event of the two bounds.
		event: Event,
	},

	/// A process spec states a deadline from `start` to `end` that does not
	/// build, because its minimum slack exceeds its duration.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, ProcessBuildError};
	///
	/// let refused = ProcessBuildError::InvalidDeadline { start: Event("open"), end: Event("close") };
	/// let message = "the deadline from open to close does not build, as its slack exceeds its duration";
	/// assert_eq!(refused.to_string(), message);
	/// ```
	#[cfg(feature = "testing-timing")]
	#[error("the deadline from {start} to {end} does not build, as its slack exceeds its duration")]
	InvalidDeadline {
		/// The event that starts the deadline.
		start: Event,
		/// The event that ends the deadline.
		end: Event,
	},
}

/// The builder of a CSP [`Process`].
#[derive(Debug)]
pub struct ProcessBuilder {
	name: &'static str,
	initial: Option<State>,
	states: HashSet<State>,
	terminal: HashSet<State>,
	choice: HashSet<State>,
	observable: HashSet<Event>,
	hidden: HashSet<Event>,
	transitions: TransitionRelation,
	description: Option<&'static str>,
	requires_progress: bool,
	#[cfg(feature = "testing-timing")]
	timing_constraints: Option<TimingConstraints>,
	#[cfg(feature = "testing-timing")]
	timed_transitions: Option<HashMap<(State, Event), Vec<TimedTransition>>>,
	#[cfg(feature = "testing-timing")]
	clocks: HashSet<String>,
	#[cfg(feature = "testing-schedulability")]
	schedulability_periods: Option<(SchedulerType, HashMap<Event, Duration>)>,
}

impl ProcessBuilder {
	pub fn new(name: &'static str) -> Self {
		Self {
			name,
			initial: None,
			states: HashSet::new(),
			terminal: HashSet::new(),
			choice: HashSet::new(),
			observable: HashSet::new(),
			hidden: HashSet::new(),
			transitions: TransitionRelation::new(),
			description: None,
			requires_progress: true,
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-timing")]
			timed_transitions: None,
			#[cfg(feature = "testing-timing")]
			clocks: HashSet::new(),
			#[cfg(feature = "testing-schedulability")]
			schedulability_periods: None,
		}
	}

	/// Accepts a run that records no event in this process's alphabet.
	///
	/// Use it only for a process whose modelled behavior is to do nothing.
	/// Every other process rejects such a run ([`Process::requires_progress`]).
	pub fn permits_no_progress(mut self) -> Self {
		self.requires_progress = false;
		self
	}

	pub fn initial_state(mut self, state: State) -> Self {
		self.initial = Some(state);
		self.states.insert(state);
		self
	}

	pub fn add_state(mut self, state: State) -> Self {
		self.states.insert(state);
		self
	}

	pub fn add_terminal(mut self, state: State) -> Self {
		self.states.insert(state);
		self.terminal.insert(state);
		self
	}

	pub fn add_choice(mut self, state: State) -> Self {
		self.choice.insert(state);
		self
	}

	pub fn add_observable(mut self, event: impl Into<Event>) -> Self {
		self.observable.insert(event.into());
		self
	}

	pub fn add_hidden(mut self, event: impl Into<Event>) -> Self {
		self.hidden.insert(event.into());
		self
	}

	pub fn add_transition(mut self, from: State, event: impl Into<Event>, to: State) -> Self {
		self.states.insert(from);
		self.states.insert(to);
		self.transitions.add(from, event.into(), to);
		self
	}

	pub fn description(mut self, desc: &'static str) -> Self {
		self.description = Some(desc);
		self
	}

	#[cfg(feature = "testing-timing")]
	pub fn timing_constraints(mut self, constraints: TimingConstraints) -> Self {
		self.timing_constraints = Some(constraints);
		self
	}

	/// Declares the clock `name`, which a guard or a reset of this process may
	/// name.
	///
	/// [`Self::build`] refuses a guard or a reset that names a clock with no
	/// declaration, so a misspelt clock name fails the build. A run starts
	/// each clock at zero ([`Process::initial_clocks`]).
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::timing::TimingGuard;
	///
	/// let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
	/// let process = Process::builder("Guarded")
	///     .initial_state(State("S0"))
	///     .clock("clk")
	///     .add_observable(Event("arm"))
	///     .add_timed_transition(State("S0"), Event("arm"), State("S1"), Some(guard), Vec::new())
	///     .build()?;
	///
	/// assert_eq!(process.initial_clocks().len(), 1);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[cfg(feature = "testing-timing")]
	pub fn clock(mut self, name: impl Into<String>) -> Self {
		self.clocks.insert(name.into());
		self
	}

	/// Adds a transition that `guard` enables, and that resets `reset_clocks`
	/// when a run takes it.
	///
	/// Where the guard binds depends on the check:
	///
	/// - [`Process::enabled`] and [`Process::step`] offer `event` at `from` whatever the clocks read.
	/// - The CSP trace check and the refinement checks ignore the clocks and accept the event at any time.
	/// - FDR exploration takes the transition only when the clocks satisfy the guard.
	/// - Exploration starts each clock at zero ([`Process::initial_clocks`]).
	///
	/// Each clock that `guard` or `reset_clocks` names needs a [`Self::clock`]
	/// declaration, or [`Self::build`] refuses the process.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::timing::TimingGuard;
	///
	/// let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
	/// let process = Process::builder("Guarded")
	///     .initial_state(State("S0"))
	///     .clock("clk")
	///     .add_observable(Event("arm"))
	///     .add_timed_transition(State("S0"), Event("arm"), State("S1"), Some(guard), ["clk".to_string()])
	///     .build()?;
	///
	/// assert_eq!(process.step(State("S0"), &Event("arm")), [State("S1")]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[cfg(feature = "testing-timing")]
	pub fn add_timed_transition(
		mut self,
		from: State,
		event: impl Into<Event>,
		to: State,
		guard: Option<TimingGuard>,
		reset_clocks: impl IntoIterator<Item = String>,
	) -> Self {
		let event = event.into();
		let reset_clocks: Vec<String> = reset_clocks.into_iter().collect();
		self = self.add_state(from).add_state(to);
		if self.timed_transitions.is_none() {
			self.timed_transitions = Some(HashMap::new());
		}

		if let Some(ref mut transitions) = self.timed_transitions {
			let key = (from, event);
			let action = Action {
				event,
				alphabet: if self.observable.contains(&event) {
					Alphabet::Observable
				} else {
					Alphabet::Hidden
				},
			};

			let timed_trans = TimedTransition::new(from, action, to).with_reset_clocks(reset_clocks);
			let timed_trans = if let Some(g) = guard {
				timed_trans.with_guard(g)
			} else {
				timed_trans
			};

			transitions.entry(key).or_insert_with(Vec::new).push(timed_trans);
		}
		self
	}

	#[cfg(feature = "testing-schedulability")]
	pub fn with_schedulability_periods(
		mut self,
		scheduler: crate::testing::schedulability::SchedulerType,
		periods: HashMap<Event, core::time::Duration>,
	) -> Self {
		self.schedulability_periods = Some((scheduler, periods));
		self
	}

	pub fn build(self) -> Result<Process, ProcessBuildError> {
		let initial = self.initial.ok_or(ProcessBuildError::MissingInitialState)?;
		#[cfg(feature = "testing-timing")]
		if let Some(clock) = self.undeclared_clock() {
			return Err(ProcessBuildError::UndeclaredClock { clock: clock.to_string() });
		}

		Ok(Process {
			name: self.name,
			observation: Observation::Model,
			requires_progress: self.requires_progress,
			initial,
			states: self.states,
			terminal: self.terminal,
			choice: self.choice,
			observable: self.observable,
			hidden: self.hidden,
			transitions: self.transitions,
			description: self.description,
			#[cfg(feature = "testing-timing")]
			timing_constraints: self.timing_constraints,
			#[cfg(feature = "testing-timing")]
			timed_transitions: self.timed_transitions,
			#[cfg(feature = "testing-schedulability")]
			schedulability_periods: self.schedulability_periods,
		})
	}

	/// The first clock, in name order, that a timed transition names and no
	/// call to [`Self::clock`] declares.
	#[cfg(feature = "testing-timing")]
	fn undeclared_clock(&self) -> Option<&str> {
		let edges = self.timed_transitions.iter().flat_map(HashMap::values).flatten();
		let named = edges.flat_map(TimedTransition::clocks);

		named.filter(|clock| !self.clocks.contains(*clock)).min()
	}
}

#[cfg(test)]
mod tests {
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use core::sync::atomic::{AtomicBool, Ordering};
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use std::sync::Arc;

	use super::*;
	use crate::testing::assertions::Assertion;
	use crate::testing::{ScenarioConfig, SetupEnv};
	use crate::urn::Urn;
	use crate::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::servlet;
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::testing::TestMessage;
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::testing::{ClientEnv, TestHooks};
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::transport::tcp::r#async::TokioListener;
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::transport::tcp::TightBeamSocketAddr;
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::transport::{EndpointConfig, MessageEmitter, Protocol};

	#[cfg(feature = "testing-timing")]
	const ARM: Urn<'static> = crate::urn!("test", "event:csp/arm");

	/// A spec that models `start` and `send` as observable and `prepare` as
	/// hidden, and leaves every other event out of both alphabets.
	fn alphabet_spec() -> Result<Process, ProcessBuildError> {
		Process::builder("AlphabetSpec")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_observable(Event("send"))
			.add_hidden(Event("prepare"))
			.add_transition(State("S0"), Event("start"), State("S1"))
			.add_transition(State("S1"), Event("prepare"), State("S2"))
			.add_transition(State("S2"), Event("send"), State("S3"))
			.add_terminal(State("S3"))
			.build()
	}

	#[test]
	fn project_keeps_only_what_the_spec_observes() -> Result<(), ProcessBuildError> {
		let spec = alphabet_spec()?;
		let recorded = [Event("start"), Event("prepare"), Event("audit"), Event("send")];
		let projected = spec.project(recorded);
		assert_eq!(projected, vec![Event("start"), Event("send")]);
		Ok(())
	}

	#[test]
	fn unmodelled_names_what_the_spec_leaves_out_of_both_alphabets() -> Result<(), ProcessBuildError> {
		let spec = alphabet_spec()?;
		let subject = Process::builder("Subject")
			.initial_state(State("T0"))
			.add_observable(Event("start"))
			.add_observable(Event("prepare"))
			.add_observable(Event("audit"))
			.add_transition(State("T0"), Event("start"), State("T1"))
			.add_terminal(State("T1"))
			.build()?;

		let outside = spec.unmodelled(&subject);
		assert_eq!(outside, vec![Event("audit")], "`prepare` is modelled, as the spec's own τ");
		Ok(())
	}

	#[test]
	fn builder_creates_valid_process() -> Result<(), Box<dyn core::error::Error>> {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_observable(Event("send"))
			.add_hidden(Event("prepare"))
			.add_transition(State("S0"), Event("start"), State("S1"))
			.add_transition(State("S1"), Event("prepare"), State("S2"))
			.add_transition(State("S2"), Event("send"), State("S3"))
			.add_terminal(State("S3"))
			.description("Simple test process")
			.build()?;

		assert_eq!(proc.name, "TestProc");
		assert_eq!(proc.initial, State("S0"));
		assert_eq!(proc.observable.len(), 2);
		assert_eq!(proc.hidden.len(), 1);
		assert!(proc.is_terminal(State("S3")));
		Ok(())
	}

	#[test]
	fn step_executes_transitions() -> Result<(), Box<dyn core::error::Error>> {
		let proc = Process::builder("StepTest")
			.initial_state(State("S0"))
			.add_observable(Event("go"))
			.add_transition(State("S0"), Event("go"), State("S1"))
			.add_terminal(State("S1"))
			.build()?;

		let targets = proc.step(State("S0"), &Event("go"));
		assert_eq!(targets.len(), 1);
		assert_eq!(targets[0], State("S1"));

		let no_targets = proc.step(State("S0"), &Event("missing"));
		assert_eq!(no_targets.len(), 0);
		Ok(())
	}

	#[test]
	fn enabled_returns_possible_actions() -> Result<(), Box<dyn core::error::Error>> {
		let proc = Process::builder("EnabledTest")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("tau"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S0"), Event("tau"), State("S2"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()?;

		let enabled = proc.enabled(State("S0"));
		assert_eq!(enabled.len(), 2);

		let events: Vec<&str> = enabled.iter().map(|a| a.event.0).collect();
		assert!(events.contains(&"a"));
		assert!(events.contains(&"tau"));
		Ok(())
	}

	#[test]
	fn nondeterministic_choice() -> Result<(), Box<dyn core::error::Error>> {
		let proc = Process::builder("ChoiceTest")
			.initial_state(State("S0"))
			.add_observable(Event("choice"))
			.add_transition(State("S0"), Event("choice"), State("S1"))
			.add_transition(State("S0"), Event("choice"), State("S2"))
			.add_choice(State("S0"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()?;

		let targets = proc.step(State("S0"), &Event("choice"));
		assert_eq!(targets.len(), 2);
		assert!(targets.contains(&State("S1")));
		assert!(targets.contains(&State("S2")));

		assert!(proc.is_choice(State("S0")));
		Ok(())
	}

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

	fn branching_process(declared_choice: bool) -> Result<Process, ProcessBuildError> {
		let builder = Process::builder("Branching")
			.initial_state(State("S0"))
			.add_observable(Event("go"))
			.add_observable(Event("x"))
			.add_observable(Event("y"))
			.add_transition(State("S0"), Event("go"), State("S1"))
			.add_transition(State("S0"), Event("go"), State("S2"))
			.add_transition(State("S1"), Event("x"), State("T"))
			.add_transition(State("S2"), Event("y"), State("T"))
			.add_terminal(State("T"));

		if declared_choice {
			builder.add_choice(State("S0")).build()
		} else {
			builder.build()
		}
	}

	#[test]
	fn declared_choice_validates_both_branches() -> Result<(), ProcessBuildError> {
		let proc = branching_process(true)?;
		let via_first = proc.validate_trace(&trace_of(&["go", "x"]));
		let via_second = proc.validate_trace(&trace_of(&["go", "y"]));
		assert!(via_first.valid);
		assert!(via_second.valid);
		Ok(())
	}

	#[test]
	fn tau_transitions_traversed_silently() -> Result<(), ProcessBuildError> {
		let proc = Process::builder("TauBridge")
			.initial_state(State("S0"))
			.add_hidden(Event("tau"))
			.add_observable(Event("a"))
			.add_transition(State("S0"), Event("tau"), State("S1"))
			.add_transition(State("S1"), Event("a"), State("T"))
			.add_terminal(State("T"))
			.build()?;

		let result = proc.validate_trace(&trace_of(&["a"]));
		assert!(result.valid);
		Ok(())
	}

	#[test]
	fn tau_chain_traversed_across_multiple_hidden_steps() -> Result<(), ProcessBuildError> {
		let proc = Process::builder("TauChain")
			.initial_state(State("S0"))
			.add_hidden(Event("tau_1"))
			.add_hidden(Event("tau_2"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("tau_1"), State("S2"))
			.add_transition(State("S2"), Event("tau_2"), State("S3"))
			.add_transition(State("S3"), Event("b"), State("T"))
			.add_terminal(State("T"))
			.build()?;

		let result = proc.validate_trace(&trace_of(&["a", "b"]));
		assert!(result.valid);
		Ok(())
	}

	#[test]
	fn undeclared_nondeterminism_is_flagged() -> Result<(), ProcessBuildError> {
		let proc = branching_process(false)?;
		let result = proc.validate_trace(&trace_of(&["go", "x"]));
		assert!(!result.valid);
		assert!(result
			.violations
			.iter()
			.any(|v| matches!(v, CspViolation::NondeterministicChoice { .. })));

		Ok(())
	}

	#[test]
	fn hidden_only_event_in_trace_is_not_enabled() -> Result<(), ProcessBuildError> {
		let proc = Process::builder("HiddenOnly")
			.initial_state(State("S0"))
			.add_hidden(Event("tau"))
			.add_transition(State("S0"), Event("tau"), State("S1"))
			.add_terminal(State("S1"))
			.build()?;

		let result = proc.validate_trace(&trace_of(&["tau"]));
		assert!(!result.valid);
		assert!(result
			.violations
			.iter()
			.any(|v| matches!(v, CspViolation::EventNotEnabled { .. })));
		Ok(())
	}

	#[test]
	fn intern_deduplicates_across_calls() {
		let first = intern(String::from("intern_dedupe_probe"));
		let second = intern("intern_dedupe_probe");
		assert_eq!(first.as_ptr(), second.as_ptr());
	}

	#[test]
	fn enabled_is_sorted_by_event_name() -> Result<(), ProcessBuildError> {
		let proc = Process::builder("Sorted")
			.initial_state(State("S0"))
			.add_observable(Event("b"))
			.add_observable(Event("a"))
			.add_hidden(Event("c"))
			.add_transition(State("S0"), Event("b"), State("S1"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S0"), Event("c"), State("S1"))
			.add_terminal(State("S1"))
			.build()?;

		let names: Vec<&str> = proc.enabled(State("S0")).iter().map(|a| a.event.0).collect();
		assert_eq!(names, vec!["a", "b", "c"]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_timed_transition_adds_its_states() -> Result<(), ProcessBuildError> {
		let process = Process::builder("States")
			.initial_state(State("S0"))
			.add_timed_transition(State("S1"), Event("arm"), State("S2"), None, Vec::new())
			.build()?;
		assert_eq!(process.states, HashSet::from([State("S0"), State("S1"), State("S2")]));
		Ok(())
	}

	/// A process that declares the clock `declared`, in which `arm` takes
	/// `S0` to `S1` while `clk` reads at most 5 ms, and `fire` takes `S1`
	/// back to `S0` and resets the clock `reset`.
	#[cfg(feature = "testing-timing")]
	fn clocked(declared: &str, reset: &str) -> Result<Process, ProcessBuildError> {
		let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		Process::builder("Clocked")
			.initial_state(State("S0"))
			.clock(declared)
			.add_observable(Event("arm"))
			.add_observable(Event("fire"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), Some(guard), Vec::new())
			.add_timed_transition(State("S1"), Event("fire"), State("S0"), None, [reset.to_string()])
			.build()
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guard_on_an_undeclared_clock_is_refused() -> Result<(), Box<dyn core::error::Error>> {
		let refused = clocked("other", "other");
		assert_eq!(
			refused.err(),
			Some(ProcessBuildError::UndeclaredClock { clock: "clk".to_string() })
		);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_misspelt_reset_is_refused() -> Result<(), Box<dyn core::error::Error>> {
		let refused = clocked("clk", "clck");
		assert_eq!(
			refused.err(),
			Some(ProcessBuildError::UndeclaredClock { clock: "clck".to_string() })
		);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn every_clock_that_a_process_names_starts_at_zero() -> Result<(), Box<dyn core::error::Error>> {
		let process = clocked("clk", "clk")?;
		let clocks = process.initial_clocks();
		assert_eq!(clocks, HashMap::from([("clk".to_string(), Duration::ZERO)]));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_timed_transition_takes_an_event_in_any_form() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("Urn")
			.initial_state(State("S0"))
			.add_observable(ARM)
			.add_timed_transition(State("S0"), ARM, State("S1"), None, Vec::new())
			.build()?;
		assert_eq!(process.step(State("S0"), &Event::from(ARM)), [State("S1")]);
		Ok(())
	}

	#[test]
	fn handshake_process_example() -> Result<(), Box<dyn core::error::Error>> {
		// A CSP handshake that sends either directly or through a queue.
		let proc = Process::builder("Handshake")
			.initial_state(State("S0"))
			// Σ holds the four events an observer sees.
			.add_observable(Event("start"))
			.add_observable(Event("send"))
			.add_observable(Event("ack"))
			.add_observable(Event("fail"))
			// τ holds the four internal steps.
			.add_hidden(Event("serialize"))
			.add_hidden(Event("encrypt"))
			.add_hidden(Event("queue"))
			.add_hidden(Event("dispatch"))
			// S1 branches to a direct send (S1s) or a queued send (S1q).
			.add_transition(State("S0"), Event("start"), State("S1"))
			.add_transition(State("S1"), Event("serialize"), State("S1s"))
			.add_transition(State("S1"), Event("queue"), State("S1q"))
			.add_transition(State("S1s"), Event("encrypt"), State("S1e"))
			.add_transition(State("S1e"), Event("send"), State("S2"))
			.add_transition(State("S1q"), Event("dispatch"), State("S1d"))
			.add_transition(State("S1d"), Event("send"), State("S2"))
			.add_transition(State("S2"), Event("ack"), State("S3"))
			.add_transition(State("S2"), Event("fail"), State("S3f"))
			// S3 is the success STOP, and S3f is the failure STOP.
			.add_terminal(State("S3"))
			.add_terminal(State("S3f"))
			// S1 is a declared choice point, so both branches are legal.
			.add_choice(State("S1"))
			.description("Queued or direct send")
			.build()?;

		assert_eq!(proc.initial, State("S0"));

		assert!(proc.is_choice(State("S1")));
		let s1_enabled = proc.enabled(State("S1"));
		assert_eq!(s1_enabled.len(), 2); // S1 enables serialize and queue.

		assert_eq!(proc.observable_alphabet().len(), 4);
		assert!(proc.observable_alphabet().contains(&Event("start")));
		assert!(proc.observable_alphabet().contains(&Event("send")));
		assert!(proc.observable_alphabet().contains(&Event("ack")));
		assert!(proc.observable_alphabet().contains(&Event("fail")));

		assert_eq!(proc.hidden_alphabet().len(), 4);

		assert!(proc.is_terminal(State("S3")));
		assert!(proc.is_terminal(State("S3f")));

		Ok(())
	}

	// `tb_process_spec!` builds the handshake process, and each numbered step
	// checks one part of the LTS it yields.
	#[test]
	fn test_csp_process_spec_structure() -> Result<(), ProcessBuildError> {
		tb_process_spec! {
			pub ComprehensiveHandshake,
			events {
				observable { Event("start"), Event("send"), Event("ack"), Event("fail") }
				hidden { Event("serialize"), Event("encrypt"), Event("queue"), Event("dispatch") }
			}
			states {
				S0  => { Event("start") => S1 },
				S1  => { Event("serialize") => S1s, Event("queue") => S1q },
				S1s => { Event("encrypt") => S1e },
				S1e => { Event("send") => S2 },
				S1q => { Event("dispatch") => S1d },
				S1d => { Event("send") => S2 },
				S2  => { Event("ack") => S3, Event("fail") => S3f },
				S3  => {},
				S3f => {}
			}
			terminal { S3, S3f }
			choice { S1 }
			annotations { description: "Comprehensive handshake with queued or direct send" }
		}

		let proc = ComprehensiveHandshake::process()?;

		// 1. The name, the description, and the initial state.
		assert_eq!(proc.name, "ComprehensiveHandshake");
		assert_eq!(proc.description, Some("Comprehensive handshake with queued or direct send"));
		assert_eq!(proc.initial, State("S0"));

		// 2. The state space.
		assert_eq!(proc.states.len(), 9); // S0, S1, S1s, S1e, S1q, S1d, S2, S3, S3f
		assert!(proc.states.contains(&State("S0")));
		assert!(proc.states.contains(&State("S1")));
		assert!(proc.states.contains(&State("S1s")));
		assert!(proc.states.contains(&State("S1e")));
		assert!(proc.states.contains(&State("S1q")));
		assert!(proc.states.contains(&State("S1d")));
		assert!(proc.states.contains(&State("S2")));
		assert!(proc.states.contains(&State("S3")));
		assert!(proc.states.contains(&State("S3f")));

		// 3. The observable alphabet (Σ).
		assert_eq!(proc.observable_alphabet().len(), 4);
		assert!(proc.observable_alphabet().contains(&Event("start")));
		assert!(proc.observable_alphabet().contains(&Event("send")));
		assert!(proc.observable_alphabet().contains(&Event("ack")));
		assert!(proc.observable_alphabet().contains(&Event("fail")));

		// 4. The hidden alphabet (τ).
		assert_eq!(proc.hidden_alphabet().len(), 4);
		assert!(proc.hidden_alphabet().contains(&Event("serialize")));
		assert!(proc.hidden_alphabet().contains(&Event("encrypt")));
		assert!(proc.hidden_alphabet().contains(&Event("queue")));
		assert!(proc.hidden_alphabet().contains(&Event("dispatch")));

		// 5. The terminal states (STOP).
		assert_eq!(proc.terminal.len(), 2);
		assert!(proc.is_terminal(State("S3"))); // S3 is the success STOP.
		assert!(proc.is_terminal(State("S3f"))); // S3f is the failure STOP.

		// 6. The nondeterministic choice points (⊓).
		assert_eq!(proc.choice.len(), 1);
		assert!(proc.is_choice(State("S1"))); // S1 chooses serialize or queue.

		// 7. The observable transitions of the transition relation.
		let s0_start = proc.step(State("S0"), &Event("start"));
		assert_eq!(s0_start.len(), 1);
		assert_eq!(s0_start[0], State("S1"));

		let s1e_send = proc.step(State("S1e"), &Event("send"));
		assert_eq!(s1e_send.len(), 1);
		assert_eq!(s1e_send[0], State("S2"));

		let s1d_send = proc.step(State("S1d"), &Event("send"));
		assert_eq!(s1d_send.len(), 1);
		assert_eq!(s1d_send[0], State("S2"));

		let s2_ack = proc.step(State("S2"), &Event("ack"));
		assert_eq!(s2_ack.len(), 1);
		assert_eq!(s2_ack[0], State("S3"));

		let s2_fail = proc.step(State("S2"), &Event("fail"));
		assert_eq!(s2_fail.len(), 1);
		assert_eq!(s2_fail[0], State("S3f"));

		// 8. The hidden (τ) transitions of the transition relation.
		let s1_serialize = proc.step(State("S1"), &Event("serialize"));
		assert_eq!(s1_serialize.len(), 1);
		assert_eq!(s1_serialize[0], State("S1s"));

		let s1_queue = proc.step(State("S1"), &Event("queue"));
		assert_eq!(s1_queue.len(), 1);
		assert_eq!(s1_queue[0], State("S1q"));

		let s1s_encrypt = proc.step(State("S1s"), &Event("encrypt"));
		assert_eq!(s1s_encrypt.len(), 1);
		assert_eq!(s1s_encrypt[0], State("S1e"));

		let s1q_dispatch = proc.step(State("S1q"), &Event("dispatch"));
		assert_eq!(s1q_dispatch.len(), 1);
		assert_eq!(s1q_dispatch[0], State("S1d"));

		// 9. The enabled actions at each state.
		// S0 enables only the observable `start`.
		let s0_enabled = proc.enabled(State("S0"));
		assert_eq!(s0_enabled.len(), 1);
		assert!(s0_enabled.iter().any(|a| a.event.0 == "start" && a.is_observable()));

		// S1 offers a nondeterministic choice of hidden `serialize` or `queue`.
		let s1_enabled = proc.enabled(State("S1"));
		assert_eq!(s1_enabled.len(), 2);
		assert!(s1_enabled.iter().any(|a| a.event.0 == "serialize" && a.is_hidden()));
		assert!(s1_enabled.iter().any(|a| a.event.0 == "queue" && a.is_hidden()));

		// S2 enables the observable `ack` and `fail`, one for each outcome.
		let s2_enabled = proc.enabled(State("S2"));
		assert_eq!(s2_enabled.len(), 2);
		assert!(s2_enabled.iter().any(|a| a.event.0 == "ack" && a.is_observable()));
		assert!(s2_enabled.iter().any(|a| a.event.0 == "fail" && a.is_observable()));

		// S3 is terminal and enables no action.
		let s3_enabled = proc.enabled(State("S3"));
		assert_eq!(s3_enabled.len(), 0);

		// 10. A trace along the direct success path.
		let mut current = proc.initial;

		current = proc.step(current, &Event("start"))[0];
		assert_eq!(current, State("S1"));
		assert!(proc.is_choice(current));

		current = proc.step(current, &Event("serialize"))[0];
		assert_eq!(current, State("S1s"));

		current = proc.step(current, &Event("encrypt"))[0];
		assert_eq!(current, State("S1e"));

		current = proc.step(current, &Event("send"))[0];
		assert_eq!(current, State("S2"));

		current = proc.step(current, &Event("ack"))[0];
		assert_eq!(current, State("S3"));
		assert!(proc.is_terminal(current));

		// 11. A trace along the queued success path.
		let mut current = proc.initial;

		current = proc.step(current, &Event("start"))[0];
		assert_eq!(current, State("S1"));

		current = proc.step(current, &Event("queue"))[0];
		assert_eq!(current, State("S1q"));

		current = proc.step(current, &Event("dispatch"))[0];
		assert_eq!(current, State("S1d"));

		current = proc.step(current, &Event("send"))[0];
		assert_eq!(current, State("S2"));

		current = proc.step(current, &Event("ack"))[0];
		assert_eq!(current, State("S3"));
		assert!(proc.is_terminal(current));

		// 12. A trace along the failure path.
		let mut current = proc.initial;

		current = proc.step(current, &Event("start"))[0];

		current = proc.step(current, &Event("serialize"))[0];

		current = proc.step(current, &Event("encrypt"))[0];

		current = proc.step(current, &Event("send"))[0];

		current = proc.step(current, &Event("fail"))[0];
		assert_eq!(current, State("S3f"));
		assert!(proc.is_terminal(current));

		// 13. An invalid transition yields no successor states.
		assert_eq!(proc.step(State("S0"), &Event("send")).len(), 0);
		assert_eq!(proc.step(State("S1"), &Event("ack")).len(), 0);
		assert_eq!(proc.step(State("S3"), &Event("start")).len(), 0); // S3 is terminal.

		// 14. Each event classifies as observable or hidden.
		for action in proc.enabled(State("S0")) {
			if action.event.0 == "start" {
				assert!(action.is_observable());
				assert!(!action.is_hidden());
				assert_eq!(action.alphabet, Alphabet::Observable);
			}
		}
		for action in proc.enabled(State("S1")) {
			if action.event.0 == "serialize" || action.event.0 == "queue" {
				assert!(action.is_hidden());
				assert!(!action.is_observable());
				assert_eq!(action.alphabet, Alphabet::Hidden);
			}
		}

		Ok(())
	}

	const STEP1: Urn<'static> = crate::urn!("test", "event:csp/step1");
	const STEP2: Urn<'static> = crate::urn!("test", "event:csp/step2");

	// The scenario runs the flow in the Bare environment and checks the trace
	// against both specs.
	tb_assert_spec! {
		pub SimpleBareFlowSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(STEP1, exactly!(1)),
				(STEP2, exactly!(1))
			]
		},
	}

	tb_process_spec! {
		pub SimpleBareFlowProc,
		events {
			observable { STEP1, STEP2 }
			hidden { }
		}
		states {
			S0 => { STEP1 => S1 },
			S1 => { STEP2 => S2 }
		}
		terminal { S2 }
	}

	tb_scenario! {
		name: test_csp_with_bare_environment,
		config: ScenarioConfig::builder()
			.with_spec(SimpleBareFlowSpec::latest())
			.with_csp(SimpleBareFlowProc)
			.build(),
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				trace.event(STEP1)?;
				trace.event(STEP2)?;
				Ok(())
			}
		}
	}

	const RECEIVED: Urn<'static> = crate::urn!("test", "event:csp/received");
	const RESPONDED: Urn<'static> = crate::urn!("test", "event:csp/responded");

	// The assertion spec counts the events that the run must record.
	tb_assert_spec! {
		pub ClientServerFlowSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(RECEIVED, exactly!(2)),
				(RESPONDED, exactly!(2))
			]
		},
	}

	// The CSP process models the client and server events of one
	// request-response flow.
	tb_process_spec! {
		pub ClientServerFlowProc,
		events {
			observable { RECEIVED, RESPONDED }
			hidden { }
		}
		states {
			S0 => { RESPONDED => S1 },
			S1 => { RECEIVED => S2 },
			S2 => { RESPONDED => S3 },
			S3 => { RECEIVED => S4 }
		}
		terminal { S4 }
		annotations { description: "Client-server request-response with 2 client + 2 server assertions" }
	}

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	static HOOK_CALLED: AtomicBool = AtomicBool::new(false);

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	crate::tb_scenario! {
		name: test_csp_process_with_assert_spec_integration,
		config: ScenarioConfig::builder()
			.with_spec(ClientServerFlowSpec::latest())
			.with_csp(ClientServerFlowProc)
			.with_hooks(TestHooks::on_pass(|_context| {
					HOOK_CALLED.store(true, Ordering::SeqCst);
				}).with_on_fail(|_context, violations| {
					panic!("Test should not fail! Violations: {violations}")
				}))
			.build(),
		environment ServiceClient {
			worker_threads: 2,
			server: |SetupEnv { trace, .. }| async move {
				let bind_addr = TightBeamSocketAddr(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
				let (listener, addr) = <TokioListener as Protocol>::bind_cleartext(bind_addr).await?;

				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace.share(),
					handle: |frame, trace| async move {
						// The server records both events of the request.
						trace.event(RECEIVED)?;
						trace.event(RESPONDED)?;
						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |ClientEnv { trace, addr, .. }| async move {
				let stream = <TokioListener as Protocol>::connect(addr).await?;
				let mut client = <TokioListener as Protocol>::create_transport(stream, EndpointConfig::cleartext());

				// The client records its first event before it sends.
				trace.event(RESPONDED)?;

				let test_message = TestMessage::sample(None);
				let test_frame = compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				// The client records its second event after the reply arrives.
				trace.event(RECEIVED)?;

				Ok(())
			}
		}
	}

	// The servlet scenario below starts this servlet.
	#[cfg(all(feature = "testing-csp", feature = "tcp", feature = "tokio"))]
	servlet! {
		pub TestServletForScenario<crate::testing::fixtures::TestMessage, EnvConfig = ()>,
		protocol: TokioListener,
		handle: |_msg, frame, ctx| async move {
			let trace = ctx.trace();
			// The server records both events of the request.
			trace.event(RECEIVED)?;
			trace.event(RESPONDED)?;
			Ok(Some(frame))
		}
	}

	// The scenario serves the flow from the servlet in the ServiceClient
	// environment.
	#[cfg(all(feature = "testing-csp", feature = "tcp", feature = "tokio"))]
	tb_scenario! {
		name: test_servlet_environment_integration,
		config: ScenarioConfig::builder()
			.with_spec(ClientServerFlowSpec::latest())
			.with_csp(ClientServerFlowProc)
			.build(),
		environment ServiceClient {
			worker_threads: 1,
			server: |SetupEnv { trace, .. }| async move {
				let servlet = TestServletForScenario::start(Arc::new(trace), crate::colony::servlet::ServletConfig::cleartext()).await?;
				let addr = servlet.addr().to_owned();
				let server_handle = tokio::spawn(servlet.join());

				Ok((server_handle, addr))
			},
			client: |ClientEnv { trace, addr, .. }| async move {
				let stream = <TokioListener as Protocol>::connect(addr).await?;
				let mut client = <TokioListener as Protocol>::create_transport(stream, EndpointConfig::cleartext());

				// The client records its first event before it sends.
				trace.event(RESPONDED)?;

				let test_message = TestMessage::sample(None);
				let test_frame = compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				// The client records its second event after the reply arrives.
				trace.event(RECEIVED)?;

				Ok(())
			}
		}
	}
}
