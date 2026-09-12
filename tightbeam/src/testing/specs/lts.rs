//! Labelled transition system vocabulary and the Layer 2 result
//!
//! A CSP process is a labelled transition system over named states and
//! named events, so those names and the verdict a validation produces are
//! plain data, and they live here in a module that every feature selection
//! compiles. The engine that walks a transition relation lives in
//! [`super::csp`] behind `testing-csp`.
//!
//! # Contents
//!
//! - [`State`] and [`Event`] name the two coordinates of a transition.
//! - [`Alphabet`] and [`Action`] classify an event as observable or hidden.
//! - [`CspValidationResult`] and [`CspViolation`] carry what Layer 2 decided.

use std::borrow::Cow;
use std::fmt;

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
///
/// Event identity is the full URN rendering (`urn:<nid>:<nss>`): spec
/// surfaces convert from [`Urn`](crate::utils::urn::Urn) so alphabets never
/// collide across NIDs.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Event(pub &'static str);

impl fmt::Display for Event {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl From<&Event> for Event {
	fn from(event: &Event) -> Self {
		*event
	}
}

// CSP event identity is already the full URN rendering, so replaying a
// process event into a trace preserves URN-keyed labels.
impl crate::trace::IntoEventLabel for Event {
	fn into_label(self) -> Cow<'static, str> {
		Cow::Borrowed(self.0)
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
