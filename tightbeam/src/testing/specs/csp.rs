//! Layer 2: CSP (Communicating Sequential Processes).
//!
//! This module implements CSP-style process algebra for tightbeam testing. It
//! follows Hoare's theory:
//!
//! - Processes communicate through events (message passing).
//! - Observable events are visible, and hidden events (τ) are internal.
//! - A nondeterministic choice lets one event lead to more than one state.
//! - A labeled transition system (LTS) represents the behavior of a process.
//!
//! The module requires the `testing-csp` feature.
//!
//! # Sources
//!
//! - C.A.R. Hoare, "Communicating Sequential Processes" (1978):
//!   <https://www.cs.cmu.edu/~crary/819-f09/Hoare78.pdf>

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock, PoisonError};

#[cfg(any(
	feature = "testing-schedulability",
	all(feature = "testing-timing", any(test, feature = "testing-fdr"))
))]
use core::time::Duration;

use crate::der::{Decode, DecodeValue, EncodeValue, Tag, Tagged};
use crate::der::{Header, Length, Reader, Writer};
use crate::testing::assertions::AssertionLabel;
use crate::trace::ConsumedTrace;
use crate::urn::Urn;

#[cfg(feature = "testing-schedulability")]
use crate::testing::schedulability::{SchedulabilityError, SchedulerType, TaskSet};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::{TimedTransition, TimingConstraints, TimingGuard};
use crate::Errorizable;

pub use super::lts::{Action, Alphabet, CspValidationResult, CspViolation, Event, State};

/// The intern pool for CSP state and event names built at runtime.
///
/// The engine keys [`State`] and [`Event`] on `&'static str` so both stay
/// `Copy`. A name built at runtime (a product state, a decoded event, or an
/// owned assertion label) must therefore become `'static`. The pool
/// deduplicates the names, so each distinct name leaks once (CWE-401).
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
/// A state and event may have more than one target, which is nondeterminism.
#[derive(Debug, Clone)]
pub struct TransitionRelation {
	/// Target states for each source state and event.
	transitions: HashMap<(State, Event), Vec<State>>,
}

impl TransitionRelation {
	pub fn new() -> Self {
		Self { transitions: HashMap::new() }
	}

	/// Add a transition that takes `from` to `to` on `event`.
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

	/// Iterate over every `((from, event), targets)` entry.
	pub fn iter(&self) -> impl Iterator<Item = (&(State, Event), &Vec<State>)> {
		self.transitions.iter()
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
/// The type is `#[non_exhaustive]` because [`ProcessBuilder`] is the only
/// construction that establishes the invariants between the fields.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Process {
	/// The human-readable name of the process.
	pub name: &'static str,

	/// What this process is evidence of. The code that builds it sets it.
	pub observation: Observation,

	/// Whether a run that records no event in this alphabet is a violation.
	///
	/// A trace that takes no transition satisfies every process, so the
	/// check would hold whatever the run did. Processes require progress
	/// unless a scenario states that doing nothing is the behavior it models.
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

	/// The timed transitions, keyed by source state and event.
	///
	/// Each one is an edge of the process. Its guard decides where FDR
	/// exploration takes it.
	#[cfg(feature = "testing-timing")]
	pub timed_transitions: Option<HashMap<(State, Event), Vec<TimedTransition>>>,

	/// The scheduler and the period of each event for schedulability analysis.
	/// [`Self::generate_task_set`] combines them with the timing constraints
	/// into a [`TaskSet`].
	#[cfg(feature = "testing-schedulability")]
	pub schedulability_periods: Option<(SchedulerType, HashMap<Event, Duration>)>,
}

/// An edge that the clocks allow, and the clocks it resets.
#[cfg(all(feature = "testing-timing", any(test, feature = "testing-fdr")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Successor<'a> {
	/// The state the edge leads to.
	pub(crate) to: State,

	/// The clocks that the edge resets when it is taken.
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

	/// `trace` restricted to this process's observable alphabet.
	///
	/// `traces(P \ X) = { s ↾ (Σ ∖ X) | s ∈ traces(P) }`. A recording also
	/// holds the steps this process models internally, so it is projected
	/// before it is compared. Traces model only: hiding is not sound in `F`
	/// or `FD`.
	pub fn project(&self, trace: impl AsRef<[Event]>) -> Vec<Event> {
		let trace = trace.as_ref();
		trace.iter().filter(|event| self.observable.contains(event)).copied().collect()
	}

	/// The events `other` makes observable that this process models in
	/// neither alphabet, sorted by name.
	///
	/// This process neither permits nor forbids them, so they are model
	/// coverage rather than a violation.
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
	/// A timed transition takes `state` to its target whatever the clocks
	/// read.
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

	/// The edges that `event` takes from `state` while the clocks read
	/// `clocks`.
	///
	/// An untimed edge is always a successor, and it resets no clock. A timed
	/// edge is a successor where `clocks` satisfy its guard, and it resets the
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

	/// A digest of the LTS structure: the initial state, the sorted states,
	/// the terminals, the choice points, the alphabets, and the triples of the
	/// untimed and the timed transitions.
	///
	/// - Two processes share a digest if and only if they have identical
	///   structure, so the digest is a sound memoization key where `name` is
	///   not. Algebra operators such as `hide` and `rename` give the same name
	///   to structurally different results.
	/// - The digest is stable only within one program run, because the
	///   `DefaultHasher` seeds vary across runs. Do not persist it.
	pub fn structure_digest(&self) -> u64 {
		use core::hash::{Hash, Hasher};
		use std::collections::hash_map::DefaultHasher;

		fn sorted_names<'a, I>(items: I) -> Vec<&'a str>
		where
			I: Iterator<Item = &'a str>,
		{
			let mut names: Vec<&str> = items.collect();
			names.sort_unstable();
			names
		}

		let mut hasher = DefaultHasher::new();
		self.initial.0.hash(&mut hasher);

		sorted_names(self.states.iter().map(|s| s.0)).hash(&mut hasher);
		sorted_names(self.terminal.iter().map(|s| s.0)).hash(&mut hasher);
		sorted_names(self.choice.iter().map(|s| s.0)).hash(&mut hasher);
		sorted_names(self.observable.iter().map(|e| e.0)).hash(&mut hasher);
		sorted_names(self.hidden.iter().map(|e| e.0)).hash(&mut hasher);

		let untimed = self.transitions.iter();
		let untimed = untimed.flat_map(|(key, targets)| targets.iter().map(move |to| (key, *to)));

		#[cfg(feature = "testing-timing")]
		let timed = self.timed_transitions.iter().flatten();
		#[cfg(feature = "testing-timing")]
		let timed = timed.flat_map(|(key, edges)| edges.iter().map(move |edge| (key, edge.to)));
		#[cfg(not(feature = "testing-timing"))]
		let timed = core::iter::empty();

		let edges = untimed.chain(timed);
		let mut triples: Vec<(&str, &str, &str)> = edges.map(|((from, event), to)| (from.0, event.0, to.0)).collect();
		triples.sort_unstable();
		triples.hash(&mut hasher);

		hasher.finish()
	}

	/// Builds the [`TaskSet`] of the timing constraints and the schedulability
	/// periods.
	///
	/// A process that declares no schedulability block has no task set, so
	/// the call returns `Ok(None)`.
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

/// A CSP process specification that a trace can be validated against.
pub trait ProcessSpec {
	/// Validate a trace against this process specification.
	fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult;

	/// Returns the [`Process`] that FDR exploration walks.
	///
	/// The result is a `Cow` because a process comes from one of two sources:
	/// - A [`Process`] lends itself as a borrowed process.
	/// - A [`CompositionSpec`](super::composition::CompositionSpec) ZST builds an owned process.
	fn to_process_cow(&self) -> Cow<'_, Process>;
}

impl Process {
	/// Validate a consumed trace against this CSP process.
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

		// Project the trace onto this process's alphabet by exact URN
		// identity, as Hoare's restriction `tr ↾ A` does. A label outside the
		// alphabet falls outside this specification, so the check drops it.
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

			// The run has terminated when every candidate is a true STOP, a
			// terminal state with no enabled action. An accepting state that
			// still offers a transition (a cyclic `terminal { Idle }` model)
			// stays live.
			if closure
				.iter()
				.all(|state| self.is_terminal(*state) && self.enabled(*state).is_empty())
			{
				if let Some(terminal_state) = closure.first().copied() {
					violations.push(CspViolation::AfterTermination { event: *event, terminal_state });
				}

				continue;
			}

			// Step on the observable event from each candidate that enables it.
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
	fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult {
		self.validate_trace(trace)
	}

	fn to_process_cow(&self) -> Cow<'_, Process> {
		Cow::Borrowed(self)
	}
}

/// An error from building a [`Process`] with a [`ProcessBuilder`].
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBuildError {
	/// No call to [`ProcessBuilder::initial_state`] set the initial state.
	#[error("initial state not set")]
	MissingInitialState,
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
			#[cfg(feature = "testing-schedulability")]
			schedulability_periods: None,
		}
	}

	/// Accepts a run that records no event in this process's alphabet.
	///
	/// Use it only for a process whose modelled behavior is to do nothing.
	/// Every other process rejects such a run, because a trace that takes no
	/// transition satisfies every process.
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

	/// Add a transition that `guard` enables, and that resets `reset_clocks`
	/// when it is taken.
	///
	/// Where the guard binds depends on the check:
	///
	/// - [`Process::enabled`] and [`Process::step`] offer `event` at `from` whatever the clocks read.
	/// - The CSP trace check and the refinement checks ignore the clocks and accept the event at any time.
	/// - FDR exploration takes the transition only where the clocks satisfy the guard.
	/// - Exploration starts each clock unset, and a guard on an unset clock does not hold.
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
		event: Event,
		to: State,
		guard: Option<TimingGuard>,
		reset_clocks: impl IntoIterator<Item = String>,
	) -> Self {
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
}

#[cfg(test)]
mod tests {
	use core::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;

	use super::*;
	use crate::testing::assertions::Assertion;
	use crate::testing::TestMessage;
	use crate::testing::{ClientEnv, ScenarioConfig, SetupEnv, TestHooks};
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::EndpointConfig;
	use crate::transport::MessageEmitter;
	use crate::transport::Protocol;
	use crate::urn::Urn;

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::{exactly, servlet, tb_assert_spec, tb_process_spec, tb_scenario};

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
	fn the_structure_digest_covers_a_timed_transition() -> Result<(), ProcessBuildError> {
		let without = Process::builder("Digest")
			.initial_state(State("S0"))
			.add_state(State("S1"))
			.add_observable(Event("arm"))
			.build()?;
		let with = Process::builder("Digest")
			.initial_state(State("S0"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), None, Vec::new())
			.build()?;

		assert_ne!(without.structure_digest(), with.structure_digest());
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
			// S3 is the success STOP and S3f the failure STOP.
			.add_terminal(State("S3"))
			.add_terminal(State("S3f"))
			// S1 is a declared choice point, so both branches are legal.
			.add_choice(State("S1"))
			.description("Queued or direct send")
			.build()?;

		assert_eq!(proc.initial, State("S0"));

		assert!(proc.is_choice(State("S1")));
		let s1_enabled = proc.enabled(State("S1"));
		assert_eq!(s1_enabled.len(), 2); // serialize, queue

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
	fn test_csp_process_spec_structure() {
		// The process is a model of the handshake state machine.
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

		let proc = ComprehensiveHandshake::process();

		// 1. Basic process properties.
		assert_eq!(proc.name, "ComprehensiveHandshake");
		assert_eq!(proc.description, Some("Comprehensive handshake with queued or direct send"));
		assert_eq!(proc.initial, State("S0"));

		// 2. State space.
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

		// 3. Observable alphabet (Σ).
		assert_eq!(proc.observable_alphabet().len(), 4);
		assert!(proc.observable_alphabet().contains(&Event("start")));
		assert!(proc.observable_alphabet().contains(&Event("send")));
		assert!(proc.observable_alphabet().contains(&Event("ack")));
		assert!(proc.observable_alphabet().contains(&Event("fail")));

		// 4. Hidden alphabet (τ).
		assert_eq!(proc.hidden_alphabet().len(), 4);
		assert!(proc.hidden_alphabet().contains(&Event("serialize")));
		assert!(proc.hidden_alphabet().contains(&Event("encrypt")));
		assert!(proc.hidden_alphabet().contains(&Event("queue")));
		assert!(proc.hidden_alphabet().contains(&Event("dispatch")));

		// 5. Terminal states (STOP).
		assert_eq!(proc.terminal.len(), 2);
		assert!(proc.is_terminal(State("S3"))); // Success terminal
		assert!(proc.is_terminal(State("S3f"))); // Failure terminal

		// 6. Nondeterministic choice points (□).
		assert_eq!(proc.choice.len(), 1);
		assert!(proc.is_choice(State("S1"))); // S1 chooses serialize or queue

		// 7. Transition relation: observable transitions.
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

		// 8. Transition relation: hidden (τ) transitions.
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

		// 9. Enabled actions at each state.
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

		// 10. Trace execution: success path (direct).
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

		// 11. Trace execution: success path (queued).
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

		// 12. Trace execution: failure path.
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
		assert_eq!(proc.step(State("S3"), &Event("start")).len(), 0); // Terminal has no transitions

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
				let server_handle = tokio::spawn(async move {
					let _ = servlet.join().await;
				});

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
