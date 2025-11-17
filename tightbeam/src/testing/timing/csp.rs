//! Timed CSP semantics
//!
//! Provides timing guards and clock variables for timed CSP processes.
//! Enables formal verification with timing constraints integrated into
//! CSP process semantics.

use core::time::Duration;

use crate::testing::specs::csp::{Action, State};

/// Clock variable for timed automata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClockVariable {
	/// Clock name
	pub name: String,
	/// Initial clock value
	pub initial_value: u64,
}

/// Timing guard condition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimingGuard {
	/// Clock less than duration: x < d
	ClockLessThan(String, Duration),
	/// Clock less than or equal: x <= d
	ClockLessEqual(String, Duration),
	/// Clock greater than: x > d
	ClockGreaterThan(String, Duration),
	/// Clock greater than or equal: x >= d
	ClockGreaterEqual(String, Duration),
	/// Clock equals: x == d
	ClockEquals(String, Duration),
	/// Clock in range: d1 <= x <= d2
	ClockInRange(String, Duration, Duration),
}

/// Timed transition with optional timing guard and clock resets
#[derive(Debug, Clone)]
pub struct TimedTransition {
	/// Source state
	pub from: State,
	/// Action (event + alphabet)
	pub action: Action,
	/// Target state
	pub to: State,
	/// Optional timing guard (transition only enabled if guard satisfied)
	/// If None, transition is always enabled (backward compatible)
	pub guard: Option<TimingGuard>,
	/// Clocks to reset on this transition
	pub reset_clocks: Vec<String>,
}

impl TimedTransition {
	/// Create new timed transition
	pub fn new(from: State, action: Action, to: State) -> Self {
		Self { from, action, to, guard: None, reset_clocks: Vec::new() }
	}

	/// Add timing guard to transition
	pub fn with_guard(mut self, guard: TimingGuard) -> Self {
		self.guard = Some(guard);
		self
	}

	/// Add clock resets to transition
	pub fn with_reset_clocks(mut self, clocks: Vec<String>) -> Self {
		self.reset_clocks = clocks;
		self
	}
}
