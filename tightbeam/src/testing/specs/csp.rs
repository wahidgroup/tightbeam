//! Layer 2: CSP (Communicating Sequential Processes)
//!
//! Implementation of CSP-style process algebra for tightbeam testing.
//!
//! Based on Hoare's Communicating Sequential Processes theory:
//! - Processes communicate through events (message passing)
//! - Observable events are visible; hidden events (τ) are internal
//! - Nondeterministic choice allows multiple possible behaviors
//! - Labeled Transition Systems (LTS) represent process behavior
//!
//! Reference: C.A.R. Hoare, "Communicating Sequential Processes" (1978)
//! <https://www.cs.cmu.edu/~crary/819-f09/Hoare78.pdf>
//!
//! Feature gated: requires `testing-csp`

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Mutex, OnceLock, PoisonError};

#[cfg(feature = "testing-schedulability")]
use core::time::Duration;

use crate::der::{Decode, DecodeValue, EncodeValue, Tag, Tagged};
use crate::der::{Header, Length, Reader, Writer};
use crate::testing::assertions::AssertionLabel;
use crate::trace::ConsumedTrace;

#[cfg(feature = "testing-schedulability")]
use crate::testing::schedulability::{SchedulabilityError, SchedulerType, TaskSet};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::{TimedTransition, TimingConstraints, TimingGuard};

/// Intern pool for CSP state/event names constructed at runtime.
///
/// The engine keys [`State`]/[`Event`] on `&'static str` for `Copy`
/// ergonomics, so runtime-built names (product states, decoded events,
/// owned assertion labels) must be promoted to `'static`. Interning
/// deduplicates before leaking (CWE-401).
static INTERN_POOL: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();

/// Promote a runtime string to `&'static str` via the intern pool.
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

/// Process state in the LTS
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct State(pub &'static str);

impl fmt::Display for State {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// CSP event identifier
///
/// Represents a named event in a CSP process specification. Also used by
/// timing verification to identify events with timing constraints (WCET,
/// deadlines, jitter) and in violation reports.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Event(pub &'static str);

impl fmt::Display for Event {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

// Manual ASN.1 encoding/decoding for Event
// Encodes &'static str as UTF8String, decodes as String (which can be
// converted to Event via From<String>)
impl Tagged for Event {
	fn tag(&self) -> Tag {
		Tag::Utf8String
	}
}

impl EncodeValue for Event {
	fn value_len(&self) -> crate::der::Result<Length> {
		// Convert &'static str to String for encoding
		let s: String = self.0.to_string();
		s.value_len()
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		// Convert &'static str to String for encoding
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

/// CSP alphabet: observable vs hidden (τ/tau)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alphabet {
	/// Observable external event
	Observable,
	/// Hidden internal event (τ/tau)
	Hidden,
}

/// CSP action: event with alphabet classification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Action {
	pub event: Event,
	pub alphabet: Alphabet,
}

impl Action {
	pub fn observable(label: &'static str) -> Self {
		Self { event: Event(label), alphabet: Alphabet::Observable }
	}

	pub fn hidden(label: &'static str) -> Self {
		Self { event: Event(label), alphabet: Alphabet::Hidden }
	}

	pub fn is_observable(&self) -> bool {
		matches!(self.alphabet, Alphabet::Observable)
	}

	pub fn is_hidden(&self) -> bool {
		matches!(self.alphabet, Alphabet::Hidden)
	}
}

/// CSP transition: state --\[event\]--> state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
	pub from: State,
	pub action: Action,
	pub to: State,
}

/// Transition relation mapping (state, event) -> target state(s)
/// Supports nondeterminism (multiple targets per state+event)
#[derive(Debug, Clone)]
pub struct TransitionRelation {
	/// Maps (from_state, event) -> Vec<to_state>
	transitions: HashMap<(State, Event), Vec<State>>,
}

impl TransitionRelation {
	pub fn new() -> Self {
		Self { transitions: HashMap::new() }
	}

	/// Add transition: from --\[event\]--> to
	pub fn add(&mut self, from: State, event: Event, to: State) {
		self.transitions.entry((from, event)).or_default().push(to);
	}

	/// Get all target states: from --\[event\]--> ?
	pub fn targets(&self, from: State, event: &Event) -> Option<&[State]> {
		self.transitions.get(&(from, *event)).map(|v| v.as_slice())
	}

	/// Check if nondeterministic: from --\[event\]--> {s1, s2, ...}
	pub fn is_nondeterministic(&self, from: State, event: &Event) -> bool {
		self.transitions.get(&(from, *event)).map(|v| v.len() > 1).unwrap_or(false)
	}

	/// Iterate over all `((from, event), targets)` entries.
	pub fn iter(&self) -> impl Iterator<Item = (&(State, Event), &Vec<State>)> {
		self.transitions.iter()
	}
}

impl Default for TransitionRelation {
	fn default() -> Self {
		Self::new()
	}
}

/// CSP Process (Labeled Transition System)
///
/// Represents a process as an LTS with:
/// - Observable alphabet (external events)
/// - Hidden alphabet (internal τ events)
/// - Transition relation
/// - Nondeterministic choice points
/// - Timing constraints (optional, for real-time verification)
#[derive(Debug, Clone)]
pub struct Process {
	/// Human-readable name
	pub name: &'static str,

	/// Initial state
	pub initial: State,

	/// All states
	pub states: HashSet<State>,

	/// Terminal states (STOP)
	pub terminal: HashSet<State>,

	/// Nondeterministic choice points
	pub choice: HashSet<State>,

	/// Observable alphabet (Σ)
	pub observable: HashSet<Event>,

	/// Hidden alphabet (τ)
	pub hidden: HashSet<Event>,

	/// Transition relation
	pub transitions: TransitionRelation,

	/// Optional description
	pub description: Option<&'static str>,

	/// Timing constraints for real-time verification
	#[cfg(feature = "testing-timing")]
	pub timing_constraints: Option<TimingConstraints>,

	/// Optional timed transitions with timing guards
	#[cfg(feature = "testing-timing")]
	pub timed_transitions: Option<HashMap<(State, Event), Vec<TimedTransition>>>,

	/// Period mapping for schedulability analysis
	/// Combined with timing_constraints to form TaskSet
	#[cfg(feature = "testing-schedulability")]
	pub schedulability_periods: Option<(SchedulerType, HashMap<Event, Duration>)>,
}

impl Process {
	/// Create new Process builder
	pub fn builder(name: &'static str) -> ProcessBuilder {
		ProcessBuilder::new(name)
	}

	/// Get observable alphabet
	pub fn observable_alphabet(&self) -> &HashSet<Event> {
		&self.observable
	}

	/// Get hidden alphabet
	pub fn hidden_alphabet(&self) -> &HashSet<Event> {
		&self.hidden
	}

	/// Execute transition: s --\[e\]--> ?
	pub fn step(&self, state: State, event: &Event) -> Vec<State> {
		self.transitions.targets(state, event).map(|v| v.to_vec()).unwrap_or_default()
	}

	/// Get enabled actions from state
	///
	/// Sorted by event name (observable before hidden on a name collision)
	/// so violation reports and byte-driven exploration are reproducible
	/// regardless of `HashSet` iteration order.
	pub fn enabled(&self, state: State) -> Vec<Action> {
		let mut actions = Vec::new();

		// Observable actions
		for event in &self.observable {
			if self.transitions.targets(state, event).is_some() {
				actions.push(Action { event: *event, alphabet: Alphabet::Observable });
			}
		}

		// Hidden actions
		for event in &self.hidden {
			if self.transitions.targets(state, event).is_some() {
				actions.push(Action { event: *event, alphabet: Alphabet::Hidden });
			}
		}

		actions.sort_by(|a, b| a.event.0.cmp(b.event.0).then_with(|| a.is_hidden().cmp(&b.is_hidden())));
		actions
	}

	/// Check if state is terminal (STOP)
	pub fn is_terminal(&self, state: State) -> bool {
		self.terminal.contains(&state)
	}

	/// Check if state is nondeterministic choice point
	pub fn is_choice(&self, state: State) -> bool {
		self.choice.contains(&state)
	}

	/// Structural digest over the LTS: initial state, sorted states,
	/// terminals, choice points, alphabets, and transition triples.
	///
	/// Two processes share a digest iff they have identical structure, so
	/// it is a sound memoization key where `name` is not (algebra
	/// operators such as `hide`/`rename` produce constant names for
	/// structurally different results).
	///
	/// The digest is only stable within one program run (`DefaultHasher`
	/// seeds vary across runs); do not persist it.
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

		let mut triples: Vec<(&str, &str, &str)> = self
			.transitions
			.iter()
			.flat_map(|((from, event), targets)| targets.iter().map(move |to| (from.0, event.0, to.0)))
			.collect();
		triples.sort_unstable();
		triples.hash(&mut hasher);

		hasher.finish()
	}

	/// Generate TaskSet from timing constraints and schedulability periods
	#[cfg(feature = "testing-schedulability")]
	pub fn generate_task_set(&self) -> Result<Option<TaskSet>, SchedulabilityError> {
		if let (Some(timing), Some((scheduler, periods))) = (&self.timing_constraints, &self.schedulability_periods) {
			Ok(Some(timing.to_task_set(periods, *scheduler)?))
		} else {
			Ok(None)
		}
	}
}

/// Trait for CSP process specifications that can be validated against traces
pub trait ProcessSpec {
	/// Validate a trace against this process specification
	fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult;

	/// Get the underlying Process for FDR exploration
	///
	/// Returns `Cow<Process>` to support both:
	/// - Borrowed: For `Process` itself
	/// - Owned: For CompositionSpec ZSTs that construct the process
	fn to_process_cow(&self) -> Cow<'_, Process>;
}

/// Result of CSP process validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspValidationResult {
	/// Whether the trace is valid
	pub valid: bool,
	/// Violations found during validation
	pub violations: Vec<CspViolation>,
}

/// Violation types for CSP validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspViolation {
	/// Event occurred that was not enabled in current state
	EventNotEnabled { event: Event, state: State, enabled: Vec<Action> },
	/// Multiple states reachable (nondeterministic choice not resolved)
	NondeterministicChoice { event: Event, state: State, next_states: Vec<State> },
	/// Trace continued after reaching terminal state
	AfterTermination { event: Event, terminal_state: State },
	/// No states reachable from transition (deadlock)
	Deadlock { event: Event, state: State },
}

impl std::fmt::Display for CspViolation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			CspViolation::EventNotEnabled { event, state, enabled } => {
				write!(
					f,
					"Event {event:?} not enabled in state {state:?}. Enabled actions: {enabled:?}"
				)
			}
			CspViolation::NondeterministicChoice { event, state, next_states } => {
				write!(
					f,
					"Nondeterministic choice at state {state:?} with event {event:?}. Possible next states: {next_states:?}"
				)
			}
			CspViolation::AfterTermination { event, terminal_state } => {
				write!(f, "Event {event:?} occurred after terminal state {terminal_state:?}")
			}
			CspViolation::Deadlock { event, state } => {
				write!(f, "Deadlock: Event {event:?} led to no reachable states from {state:?}")
			}
		}
	}
}

impl Process {
	/// Validate a consumed trace against this CSP process
	///
	/// # Trace contract
	///
	/// Traces are sequences of observable events: every assertion label is
	/// matched against the observable alphabet only. Hidden (τ) events are
	/// internal to the process and never appear in a consumed trace
	/// (Roscoe: behaviors are recorded "by an observer who cannot see the
	/// internal action τ"). Per the operational semantics, τ transitions
	/// happen silently: before matching each observable event the validator
	/// expands the candidate states by τ-closure, so processes with hidden
	/// steps on the path (e.g. `sequential`'s `tau_seq` bridge or
	/// `internal_choice`'s `tau_choice_*`) validate correctly. An event
	/// that is only enabled as hidden is reported as
	/// [`CspViolation::EventNotEnabled`].
	///
	/// # Nondeterminism
	///
	/// The validator tracks the *set* of states the process may occupy
	/// (subset construction), so all branches of a nondeterministic choice
	/// are followed simultaneously. Multiple targets for a `(state, event)`
	/// pair are legal at states registered via
	/// [`ProcessBuilder::add_choice`]; multiple targets at an *undeclared*
	/// state are reported as [`CspViolation::NondeterministicChoice`].
	pub fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult {
		let mut violations = Vec::new();
		let mut current_states = vec![self.initial];

		// Map assertion labels onto this process's alphabet. Supports the
		// same URN shorthand as Layer 1 (`"foo"` matches
		// `urn:…:event/foo`). Out-of-alphabet labels are ignored.
		let events: Vec<Event> = trace
			.assertions
			.iter()
			.filter_map(|assertion| {
				let AssertionLabel::Custom(recorded) = &assertion.label;
				let recorded = recorded.as_ref();
				self.observable
					.iter()
					.chain(self.hidden.iter())
					.find(|event| recorded == event.0 || recorded.ends_with(&["/", event.0].concat()))
					.copied()
			})
			.collect();

		for event in &events {
			let closure = self.tau_closure(&current_states);
			let action = Action { event: *event, alphabet: Alphabet::Observable };

			// Termination check: every candidate is a true STOP - terminal
			// with no enabled actions. Accepting states that still offer
			// transitions (cyclic `terminal { Idle }` models) stay live.
			if closure
				.iter()
				.all(|state| self.is_terminal(*state) && self.enabled(*state).is_empty())
			{
				if let Some(terminal_state) = closure.first().copied() {
					violations.push(CspViolation::AfterTermination { event: *event, terminal_state });
				}

				continue;
			}

			// Step on the observable event from every candidate state
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

		CspValidationResult { valid: violations.is_empty(), violations }
	}

	/// All states reachable from `states` via hidden (τ) transitions only,
	/// including the input states. Worklist traversal, no recursion.
	pub(crate) fn tau_closure(&self, states: &[State]) -> Vec<State> {
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

	/// Union of enabled actions across a state set, deduplicated and sorted
	/// for reproducible violation reports
	fn enabled_from_set(&self, states: &[State]) -> Vec<Action> {
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

/// Error building a [`Process`] from a [`ProcessBuilder`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBuildError {
	/// [`ProcessBuilder::initial_state`] was never called
	MissingInitialState,
}

impl fmt::Display for ProcessBuildError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::MissingInitialState => write!(f, "initial state not set"),
		}
	}
}

impl core::error::Error for ProcessBuildError {}

/// Builder for CSP Process
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
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-timing")]
			timed_transitions: None,
			#[cfg(feature = "testing-schedulability")]
			schedulability_periods: None,
		}
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

	pub fn add_observable(mut self, event: &'static str) -> Self {
		self.observable.insert(Event(event));
		self
	}

	pub fn add_hidden(mut self, event: &'static str) -> Self {
		self.hidden.insert(Event(event));
		self
	}

	pub fn add_transition(mut self, from: State, event: &'static str, to: State) -> Self {
		self.states.insert(from);
		self.states.insert(to);
		self.transitions.add(from, Event(event), to);
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

	#[cfg(feature = "testing-timing")]
	pub fn add_timed_transition(
		mut self,
		from: State,
		event: Event,
		to: State,
		guard: Option<TimingGuard>,
		reset_clocks: Vec<String>,
	) -> Self {
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
	use crate::testing::create_test_message;
	use crate::testing::{ClientEnv, ScenarioConf, SetupEnv, TestHooks};
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::MessageEmitter;
	use crate::transport::Protocol;

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::{exactly, servlet, tb_assert_spec, tb_process_spec, tb_scenario};

	#[test]
	fn builder_creates_valid_process() -> Result<(), Box<dyn core::error::Error>> {
		let proc = Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("start")
			.add_observable("send")
			.add_hidden("prepare")
			.add_transition(State("S0"), "start", State("S1"))
			.add_transition(State("S1"), "prepare", State("S2"))
			.add_transition(State("S2"), "send", State("S3"))
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
			.add_observable("go")
			.add_transition(State("S0"), "go", State("S1"))
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
			.add_observable("a")
			.add_observable("b")
			.add_hidden("tau")
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S0"), "tau", State("S2"))
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
			.add_observable("choice")
			.add_transition(State("S0"), "choice", State("S1"))
			.add_transition(State("S0"), "choice", State("S2"))
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
			.add_observable("go")
			.add_observable("x")
			.add_observable("y")
			.add_transition(State("S0"), "go", State("S1"))
			.add_transition(State("S0"), "go", State("S2"))
			.add_transition(State("S1"), "x", State("T"))
			.add_transition(State("S2"), "y", State("T"))
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
			.add_hidden("tau")
			.add_observable("a")
			.add_transition(State("S0"), "tau", State("S1"))
			.add_transition(State("S1"), "a", State("T"))
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
			.add_hidden("tau_1")
			.add_hidden("tau_2")
			.add_observable("a")
			.add_observable("b")
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S1"), "tau_1", State("S2"))
			.add_transition(State("S2"), "tau_2", State("S3"))
			.add_transition(State("S3"), "b", State("T"))
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
			.add_hidden("tau")
			.add_transition(State("S0"), "tau", State("S1"))
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
			.add_observable("b")
			.add_observable("a")
			.add_hidden("c")
			.add_transition(State("S0"), "b", State("S1"))
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S0"), "c", State("S1"))
			.add_terminal(State("S1"))
			.build()?;

		let names: Vec<&str> = proc.enabled(State("S0")).iter().map(|a| a.event.0).collect();
		assert_eq!(names, vec!["a", "b", "c"]);

		Ok(())
	}

	#[test]
	fn handshake_process_example() -> Result<(), Box<dyn core::error::Error>> {
		// CSP handshake with queued or direct send
		let proc = Process::builder("Handshake")
			.initial_state(State("S0"))
			// Observable alphabet
			.add_observable("start")
			.add_observable("send")
			.add_observable("ack")
			.add_observable("fail")
			// Hidden alphabet (τ)
			.add_hidden("serialize")
			.add_hidden("encrypt")
			.add_hidden("queue")
			.add_hidden("dispatch")
			// Transitions
			.add_transition(State("S0"), "start", State("S1"))
			.add_transition(State("S1"), "serialize", State("S1s"))
			.add_transition(State("S1"), "queue", State("S1q"))
			.add_transition(State("S1s"), "encrypt", State("S1e"))
			.add_transition(State("S1e"), "send", State("S2"))
			.add_transition(State("S1q"), "dispatch", State("S1d"))
			.add_transition(State("S1d"), "send", State("S2"))
			.add_transition(State("S2"), "ack", State("S3"))
			.add_transition(State("S2"), "fail", State("S3f"))
			// Terminal states (STOP)
			.add_terminal(State("S3"))
			.add_terminal(State("S3f"))
			// Nondeterministic choice
			.add_choice(State("S1"))
			.description("Queued or direct send")
			.build()?;

		// Verify initial state
		assert_eq!(proc.initial, State("S0"));

		// Verify nondeterministic choice at S1
		assert!(proc.is_choice(State("S1")));
		let s1_enabled = proc.enabled(State("S1"));
		assert_eq!(s1_enabled.len(), 2); // serialize, queue

		// Verify observable alphabet
		assert_eq!(proc.observable_alphabet().len(), 4);
		assert!(proc.observable_alphabet().contains(&Event("start")));
		assert!(proc.observable_alphabet().contains(&Event("send")));
		assert!(proc.observable_alphabet().contains(&Event("ack")));
		assert!(proc.observable_alphabet().contains(&Event("fail")));

		// Verify hidden alphabet
		assert_eq!(proc.hidden_alphabet().len(), 4);

		// Verify terminal states
		assert!(proc.is_terminal(State("S3")));
		assert!(proc.is_terminal(State("S3f")));

		Ok(())
	}

	// Test CSP process spec integration with assert spec and ServiceClient environment
	#[test]
	fn test_csp_process_spec_structure() {
		// Define CSP process using tb_process_spec! macro
		// This models the theoretical state machine behavior
		tb_process_spec! {
			pub ComprehensiveHandshake,
			events {
				observable { "start", "send", "ack", "fail" }
				hidden { "serialize", "encrypt", "queue", "dispatch" }
			}
			states {
				S0  => { "start" => S1 },
				S1  => { "serialize" => S1s, "queue" => S1q },
				S1s => { "encrypt" => S1e },
				S1e => { "send" => S2 },
				S1q => { "dispatch" => S1d },
				S1d => { "send" => S2 },
				S2  => { "ack" => S3, "fail" => S3f },
				S3  => {},
				S3f => {}
			}
			terminal { S3, S3f }
			choice { S1 }
			annotations { description: "Comprehensive handshake with queued or direct send" }
		}

		let proc = ComprehensiveHandshake::process();

		// ===== Test 1: Basic process properties =====
		assert_eq!(proc.name, "ComprehensiveHandshake");
		assert_eq!(proc.description, Some("Comprehensive handshake with queued or direct send"));
		assert_eq!(proc.initial, State("S0"));

		// ===== Test 2: State space =====
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

		// ===== Test 3: Observable alphabet (Σ) =====
		assert_eq!(proc.observable_alphabet().len(), 4);
		assert!(proc.observable_alphabet().contains(&Event("start")));
		assert!(proc.observable_alphabet().contains(&Event("send")));
		assert!(proc.observable_alphabet().contains(&Event("ack")));
		assert!(proc.observable_alphabet().contains(&Event("fail")));

		// ===== Test 4: Hidden alphabet (τ) =====
		assert_eq!(proc.hidden_alphabet().len(), 4);
		assert!(proc.hidden_alphabet().contains(&Event("serialize")));
		assert!(proc.hidden_alphabet().contains(&Event("encrypt")));
		assert!(proc.hidden_alphabet().contains(&Event("queue")));
		assert!(proc.hidden_alphabet().contains(&Event("dispatch")));

		// ===== Test 5: Terminal states (STOP) =====
		assert_eq!(proc.terminal.len(), 2);
		assert!(proc.is_terminal(State("S3"))); // Success terminal
		assert!(proc.is_terminal(State("S3f"))); // Failure terminal

		// ===== Test 6: Nondeterministic choice points (□) =====
		assert_eq!(proc.choice.len(), 1);
		assert!(proc.is_choice(State("S1"))); // S1 has choice: serialize OR queue

		// ===== Test 7: Transition relation - observable transitions =====
		// S0 --[start]--> S1
		let s0_start = proc.step(State("S0"), &Event("start"));
		assert_eq!(s0_start.len(), 1);
		assert_eq!(s0_start[0], State("S1"));

		// S1e --[send]--> S2
		let s1e_send = proc.step(State("S1e"), &Event("send"));
		assert_eq!(s1e_send.len(), 1);
		assert_eq!(s1e_send[0], State("S2"));

		// S1d --[send]--> S2
		let s1d_send = proc.step(State("S1d"), &Event("send"));
		assert_eq!(s1d_send.len(), 1);
		assert_eq!(s1d_send[0], State("S2"));

		// S2 --[ack]--> S3
		let s2_ack = proc.step(State("S2"), &Event("ack"));
		assert_eq!(s2_ack.len(), 1);
		assert_eq!(s2_ack[0], State("S3"));

		// S2 --[fail]--> S3f
		let s2_fail = proc.step(State("S2"), &Event("fail"));
		assert_eq!(s2_fail.len(), 1);
		assert_eq!(s2_fail[0], State("S3f"));

		// ===== Test 8: Transition relation - hidden (τ) transitions =====
		// S1 --[serialize]--> S1s (hidden)
		let s1_serialize = proc.step(State("S1"), &Event("serialize"));
		assert_eq!(s1_serialize.len(), 1);
		assert_eq!(s1_serialize[0], State("S1s"));

		// S1 --[queue]--> S1q (hidden, nondeterministic choice)
		let s1_queue = proc.step(State("S1"), &Event("queue"));
		assert_eq!(s1_queue.len(), 1);
		assert_eq!(s1_queue[0], State("S1q"));

		// S1s --[encrypt]--> S1e (hidden)
		let s1s_encrypt = proc.step(State("S1s"), &Event("encrypt"));
		assert_eq!(s1s_encrypt.len(), 1);
		assert_eq!(s1s_encrypt[0], State("S1e"));

		// S1q --[dispatch]--> S1d (hidden)
		let s1q_dispatch = proc.step(State("S1q"), &Event("dispatch"));
		assert_eq!(s1q_dispatch.len(), 1);
		assert_eq!(s1q_dispatch[0], State("S1d"));

		// ===== Test 9: Enabled actions at each state =====
		// S0: only "start" observable
		let s0_enabled = proc.enabled(State("S0"));
		assert_eq!(s0_enabled.len(), 1);
		assert!(s0_enabled.iter().any(|a| a.event.0 == "start" && a.is_observable()));

		// S1: "serialize" and "queue" hidden (nondeterministic)
		let s1_enabled = proc.enabled(State("S1"));
		assert_eq!(s1_enabled.len(), 2);
		assert!(s1_enabled.iter().any(|a| a.event.0 == "serialize" && a.is_hidden()));
		assert!(s1_enabled.iter().any(|a| a.event.0 == "queue" && a.is_hidden()));

		// S2: "ack" and "fail" observable (nondeterministic outcome)
		let s2_enabled = proc.enabled(State("S2"));
		assert_eq!(s2_enabled.len(), 2);
		assert!(s2_enabled.iter().any(|a| a.event.0 == "ack" && a.is_observable()));
		assert!(s2_enabled.iter().any(|a| a.event.0 == "fail" && a.is_observable()));

		// S3: terminal, no enabled actions
		let s3_enabled = proc.enabled(State("S3"));
		assert_eq!(s3_enabled.len(), 0);

		// ===== Test 10: Trace execution - success path (direct) =====
		let mut current = proc.initial;

		// S0 --[start]--> S1
		current = proc.step(current, &Event("start"))[0];
		assert_eq!(current, State("S1"));
		assert!(proc.is_choice(current)); // Choice point

		// S1 --[serialize]--> S1s (direct path)
		current = proc.step(current, &Event("serialize"))[0];
		assert_eq!(current, State("S1s"));

		// S1s --[encrypt]--> S1e
		current = proc.step(current, &Event("encrypt"))[0];
		assert_eq!(current, State("S1e"));

		// S1e --[send]--> S2
		current = proc.step(current, &Event("send"))[0];
		assert_eq!(current, State("S2"));

		// S2 --[ack]--> S3
		current = proc.step(current, &Event("ack"))[0];
		assert_eq!(current, State("S3"));
		assert!(proc.is_terminal(current)); // Terminal state

		// ===== Test 11: Trace execution - success path (queued) =====
		let mut current = proc.initial;

		// S0 --[start]--> S1
		current = proc.step(current, &Event("start"))[0];
		assert_eq!(current, State("S1"));

		// S1 --[queue]--> S1q (queued path)
		current = proc.step(current, &Event("queue"))[0];
		assert_eq!(current, State("S1q"));

		// S1q --[dispatch]--> S1d
		current = proc.step(current, &Event("dispatch"))[0];
		assert_eq!(current, State("S1d"));

		// S1d --[send]--> S2
		current = proc.step(current, &Event("send"))[0];
		assert_eq!(current, State("S2"));

		// S2 --[ack]--> S3
		current = proc.step(current, &Event("ack"))[0];
		assert_eq!(current, State("S3"));
		assert!(proc.is_terminal(current));

		// ===== Test 12: Trace execution - failure path =====
		let mut current = proc.initial;

		// S0 --[start]--> S1
		current = proc.step(current, &Event("start"))[0];

		// S1 --[serialize]--> S1s
		current = proc.step(current, &Event("serialize"))[0];

		// S1s --[encrypt]--> S1e
		current = proc.step(current, &Event("encrypt"))[0];

		// S1e --[send]--> S2
		current = proc.step(current, &Event("send"))[0];

		// S2 --[fail]--> S3f (failure terminal)
		current = proc.step(current, &Event("fail"))[0];
		assert_eq!(current, State("S3f"));
		assert!(proc.is_terminal(current)); // Terminal state

		// ===== Test 13: Invalid transitions return empty =====
		assert_eq!(proc.step(State("S0"), &Event("send")).len(), 0);
		assert_eq!(proc.step(State("S1"), &Event("ack")).len(), 0);
		assert_eq!(proc.step(State("S3"), &Event("start")).len(), 0); // Terminal has no transitions

		// ===== Test 14: Observable vs Hidden classification =====
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

	// Integration test with tb_scenario! for Bare environment
	tb_assert_spec! {
		pub SimpleBareFlowSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Ok,
			assertions: [
				("step1", exactly!(1)),
				("step2", exactly!(1))
			]
		},
	}

	tb_process_spec! {
		pub SimpleBareFlowProc,
		events {
			observable { "step1", "step2" }
			hidden { }
		}
		states {
			S0 => { "step1" => S1 },
			S1 => { "step2" => S2 }
		}
		terminal { S2 }
	}

	tb_scenario! {
		name: test_csp_with_bare_environment,
		config: ScenarioConf::builder()
			.with_spec(SimpleBareFlowSpec::latest())
			.with_csp(SimpleBareFlowProc)
			.build(),
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				trace.event("step1")?;
				trace.event("step2")?;
				Ok(())
			}
		}
	}

	// Define the assertion spec (what to validate at runtime)
	tb_assert_spec! {
		pub ClientServerFlowSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Ok,
			assertions: [
				(Received, exactly!(2)),
				(Responded, exactly!(2))
			]
		},
	}

	// Define the CSP process spec (theoretical state machine model)
	// Models the client-server request-response flow with assertions
	tb_process_spec! {
		pub ClientServerFlowProc,
		events {
			observable { "Received", "Responded" }
			hidden { }
		}
		states {
			S0 => { "Responded" => S1 },
			S1 => { "Received" => S2 },
			S2 => { "Responded" => S3 },
			S3 => { "Received" => S4 }
		}
		terminal { S4 }
		annotations { description: "Client-server request-response with 2 client + 2 server assertions" }
	}

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	static HOOK_CALLED: AtomicBool = AtomicBool::new(false);

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	crate::tb_scenario! {
		name: test_csp_process_with_assert_spec_integration,
		config: ScenarioConf::builder()
			.with_spec(ClientServerFlowSpec::latest())
			.with_csp(ClientServerFlowProc)
			.with_hooks(TestHooks {
				on_pass: Some(std::sync::Arc::new(|_result| {
					// Hook called - assertions already validated by spec
					HOOK_CALLED.store(true, Ordering::SeqCst);
					Ok(())
				})),
				on_fail: Some(std::sync::Arc::new(|_result, violation| {
					panic!("Test should not fail! Violation: {violation:?}")
				})),
			})
			.build(),
		environment ServiceClient {
			worker_threads: 2,
			server: |SetupEnv { trace, .. }| async move {
				let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
				let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;

				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace.share(),
					handle: |frame, trace| async move {
						// Server-side assertions
						trace.event(ClientServerFlowSpec::Received)?;
						trace.event(ClientServerFlowSpec::Responded)?;
						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |ClientEnv { trace, addr, .. }| async move {
				let stream = <TokioListener as Protocol>::connect(addr).await?;
				let mut client = <TokioListener as Protocol>::create_transport(stream);

				// Client-side assertion before sending
				trace.event(ClientServerFlowSpec::Responded)?;

				let test_message = create_test_message(None);
				let test_frame = compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.event(ClientServerFlowSpec::Received)?;

				Ok(())
			}
		}
	}

	// Define servlet at module scope for testing
	#[cfg(all(feature = "testing-csp", feature = "tcp", feature = "tokio"))]
	servlet! {
		pub TestServletForScenario<crate::testing::utils::TestMessage, EnvConfig = ()>,
		protocol: TokioListener,
		handle: |_msg, frame, ctx| async move {
			let trace = ctx.trace();
			// Server-side assertions
			trace.event(ClientServerFlowSpec::Received)?;
			trace.event(ClientServerFlowSpec::Responded)?;
			Ok(Some(frame))
		}
	}

	// Test using the new Servlet environment
	#[cfg(all(feature = "testing-csp", feature = "tcp", feature = "tokio"))]
	tb_scenario! {
		name: test_servlet_environment_integration,
		config: ScenarioConf::builder()
			.with_spec(ClientServerFlowSpec::latest())
			.with_csp(ClientServerFlowProc)
			.build(),
		environment ServiceClient {
			worker_threads: 1,
			server: |SetupEnv { trace, .. }| async move {
				let servlet = TestServletForScenario::start(Arc::new(trace), None).await?;
				let addr = servlet.addr();
				let server_handle = tokio::spawn(async move {
					let _ = servlet.join().await;
				});
				Ok((server_handle, addr))
			},
			client: |ClientEnv { trace, addr, .. }| async move {
				let stream = <TokioListener as Protocol>::connect(addr).await?;
				let mut client = <TokioListener as Protocol>::create_transport(stream);

				// Client-side assertion before sending
				trace.event(ClientServerFlowSpec::Responded)?;

				let test_message = create_test_message(None);
				let test_frame = compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.event(ClientServerFlowSpec::Received)?;

				Ok(())
			}
		}
	}
}
