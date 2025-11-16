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
//! https://www.cs.cmu.edu/~crary/819-f09/Hoare78.pdf
//!
//! Feature gated: requires `testing-csp`

use std::collections::{HashMap, HashSet};
use std::fmt;
/// Process state in the LTS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct State(pub &'static str);

impl fmt::Display for State {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// CSP event
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Event(pub &'static str);

impl fmt::Display for Event {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
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

/// CSP transition: state --[event]--> state
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

	/// Add transition: from --[event]--> to
	pub fn add(&mut self, from: State, event: Event, to: State) {
		self.transitions.entry((from, event)).or_default().push(to);
	}

	/// Get all target states: from --[event]--> ?
	pub fn targets(&self, from: State, event: &Event) -> Option<&[State]> {
		self.transitions.get(&(from, event.clone())).map(|v| v.as_slice())
	}

	/// Check if nondeterministic: from --[event]--> {s1, s2, ...}
	pub fn is_nondeterministic(&self, from: State, event: &Event) -> bool {
		self.transitions
			.get(&(from, event.clone()))
			.map(|v| v.len() > 1)
			.unwrap_or(false)
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
	pub timing_constraints: Option<crate::testing::timing::TimingConstraints>,
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

	/// Execute transition: s --[e]--> ?
	pub fn step(&self, state: State, event: &Event) -> Vec<State> {
		self.transitions.targets(state, event).map(|v| v.to_vec()).unwrap_or_default()
	}

	/// Get enabled actions from state
	pub fn enabled(&self, state: State) -> Vec<Action> {
		let mut actions = Vec::new();

		// Observable actions
		for event in &self.observable {
			if self.transitions.targets(state, event).is_some() {
				actions.push(Action { event: event.clone(), alphabet: Alphabet::Observable });
			}
		}

		// Hidden actions
		for event in &self.hidden {
			if self.transitions.targets(state, event).is_some() {
				actions.push(Action { event: event.clone(), alphabet: Alphabet::Hidden });
			}
		}

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
}

/// Trait for CSP process specifications that can be validated against traces
pub trait ProcessSpec {
	/// Validate a trace against this process specification
	fn validate_trace(&self, trace: &crate::testing::trace::ConsumedTrace) -> CspValidationResult;
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
	pub fn validate_trace(&self, trace: &crate::testing::trace::ConsumedTrace) -> CspValidationResult {
		let mut violations = Vec::new();
		let mut current_state = self.initial;

		// Map assertion labels to events
		for assertion in &trace.assertions {
			// Extract event from assertion label
			let event_name = match &assertion.label {
				crate::testing::assertions::AssertionLabel::Custom(s) => *s,
			};

			let event = Event(event_name);
			let action = Action::observable(event_name);

			// Check if in terminal state
			if self.is_terminal(current_state) {
				violations.push(CspViolation::AfterTermination { event: event.clone(), terminal_state: current_state });
				continue;
			}

			// Check if event is enabled
			let enabled = self.enabled(current_state);
			if !enabled.contains(&action) {
				violations.push(CspViolation::EventNotEnabled {
					event: event.clone(),
					state: current_state,
					enabled: enabled.clone(),
				});
				continue;
			}

			// Perform transition
			let next_states = self.step(current_state, &event);

			if next_states.is_empty() {
				violations.push(CspViolation::Deadlock { event: event.clone(), state: current_state });
				continue;
			}

			if next_states.len() > 1 {
				violations.push(CspViolation::NondeterministicChoice {
					event: event.clone(),
					state: current_state,
					next_states: next_states.clone(),
				});
			}

			// Take first state for continuation (deterministic or first choice)
			current_state = next_states[0];
		}

		CspValidationResult { valid: violations.is_empty(), violations }
	}
}

impl ProcessSpec for Process {
	fn validate_trace(&self, trace: &crate::testing::trace::ConsumedTrace) -> CspValidationResult {
		self.validate_trace(trace)
	}
}

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
	timing_constraints: Option<crate::testing::timing::TimingConstraints>,
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
	pub fn timing_constraints(mut self, constraints: crate::testing::timing::TimingConstraints) -> Self {
		self.timing_constraints = Some(constraints);
		self
	}

	pub fn build(self) -> Result<Process, &'static str> {
		let initial = self.initial.ok_or("Initial state not set")?;

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
		})
	}
}

#[cfg(test)]
mod tests {
	use core::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::testing::create_test_message;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::MessageEmitter;
	use crate::transport::Protocol;

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	use crate::servlet;

	#[test]
	fn builder_creates_valid_process() {
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
			.build()
			.expect("Failed to build process");

		assert_eq!(proc.name, "TestProc");
		assert_eq!(proc.initial, State("S0"));
		assert_eq!(proc.observable.len(), 2);
		assert_eq!(proc.hidden.len(), 1);
		assert!(proc.is_terminal(State("S3")));
	}

	#[test]
	fn step_executes_transitions() {
		let proc = Process::builder("StepTest")
			.initial_state(State("S0"))
			.add_observable("go")
			.add_transition(State("S0"), "go", State("S1"))
			.add_terminal(State("S1"))
			.build()
			.unwrap();

		let targets = proc.step(State("S0"), &Event("go"));
		assert_eq!(targets.len(), 1);
		assert_eq!(targets[0], State("S1"));

		let no_targets = proc.step(State("S0"), &Event("missing"));
		assert_eq!(no_targets.len(), 0);
	}

	#[test]
	fn enabled_returns_possible_actions() {
		let proc = Process::builder("EnabledTest")
			.initial_state(State("S0"))
			.add_observable("a")
			.add_observable("b")
			.add_hidden("tau")
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S0"), "tau", State("S2"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()
			.unwrap();

		let enabled = proc.enabled(State("S0"));
		assert_eq!(enabled.len(), 2);

		let events: Vec<&str> = enabled.iter().map(|a| a.event.0).collect();
		assert!(events.contains(&"a"));
		assert!(events.contains(&"tau"));
	}

	#[test]
	fn nondeterministic_choice() {
		let proc = Process::builder("ChoiceTest")
			.initial_state(State("S0"))
			.add_observable("choice")
			.add_transition(State("S0"), "choice", State("S1"))
			.add_transition(State("S0"), "choice", State("S2"))
			.add_choice(State("S0"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()
			.unwrap();

		let targets = proc.step(State("S0"), &Event("choice"));
		assert_eq!(targets.len(), 2);
		assert!(targets.contains(&State("S1")));
		assert!(targets.contains(&State("S2")));

		assert!(proc.is_choice(State("S0")));
	}

	#[test]
	fn handshake_process_example() {
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
			.build()
			.unwrap();

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
	}

	// Test CSP process spec integration with assert spec and ServiceClient environment
	#[test]
	fn test_csp_process_spec_structure() {
		// Define CSP process using tb_process_spec! macro
		// This models the theoretical state machine behavior
		crate::tb_process_spec! {
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
	crate::tb_assert_spec! {
		pub SimpleBareFlowSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("step1", crate::exactly!(1)),
				("step2", crate::exactly!(1))
			]
		},
	}

	crate::tb_process_spec! {
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

	crate::tb_scenario! {
		name: test_csp_with_bare_environment,
		spec: SimpleBareFlowSpec,
		csp: SimpleBareFlowProc,
		environment Bare {
			exec: |trace| {
				trace.assert("step1", &[]);
				trace.assert("step2", &[]);
				Ok(())
			}
		}
	}

	// Define the assertion spec (what to validate at runtime)
	crate::tb_assert_spec! {
		pub ClientServerFlowSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", crate::exactly!(2)),
				("Responded", crate::exactly!(2))
			]
		},
	}

	// Define the CSP process spec (theoretical state machine model)
	// Models the client-server request-response flow with assertions
	crate::tb_process_spec! {
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
		spec: ClientServerFlowSpec,
		csp: ClientServerFlowProc,
		environment ServiceClient {
			worker_threads: 2,
			server: |trace| async move {
				let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
				let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;

				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace,
					handle: |frame, trace| async move {
						// Server-side assertions
						trace.assert("Received", &[]);
						trace.assert("Responded", &[]);
						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |trace, mut client| async move {
				// Client-side assertion before sending
				trace.assert("Responded", &[]);

				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.assert("Received", &[]);

				Ok(())
			}
		},
		hooks {
			on_pass: |_trace| {
				// Hook called - assertions already validated by spec
				HOOK_CALLED.store(true, Ordering::SeqCst);
			},
			on_fail: |_trace, violations| {
				panic!("Test should not fail! Violations: {violations:?}");
			}
		}
	}

	// Define servlet at module scope for testing
	#[cfg(all(feature = "testing-csp", feature = "tcp", feature = "tokio"))]
	servlet! {
		pub TestServletForScenario<()>,
		protocol: TokioListener,
		handle: |frame, trace| async move {
			// Server-side assertions
			trace.assert("Received", &[]);
			trace.assert("Responded", &[]);
			Ok(Some(frame))
		}
	}

	// Test using the new Servlet environment
	#[cfg(all(feature = "testing-csp", feature = "tcp", feature = "tokio"))]
	crate::tb_scenario! {
		name: test_servlet_environment_integration,
		spec: ClientServerFlowSpec,
		csp: ClientServerFlowProc,
		environment ServiceClient {
			worker_threads: 1,
			server: |trace| async move {
				let servlet = TestServletForScenario::start(trace).await?;
				let addr = servlet.addr();
				let server_handle = tokio::spawn(async move {
					let _ = servlet.join().await;
				});
				Ok((server_handle, addr))
			},
			client: |trace, mut client| async move {
				// Client-side assertion before sending
				trace.assert("Responded", &[]);

				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.assert("Received", &[]);

				Ok(())
			}
		}
	}
}
