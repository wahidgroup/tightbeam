//! Timed CSP semantics.
//!
//! This module holds the clock variables, timing guards, and timed
//! transitions of a timed CSP process, so a formal check can apply timing
//! constraints inside the process semantics.

use core::time::Duration;

use std::collections::HashMap;

use crate::testing::specs::csp::{Action, State};

/// A named clock of a timed automaton.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClockVariable {
	/// The name that timing guards and clock resets use for this clock.
	pub name: String,
	/// The value of the clock when it starts.
	pub initial_value: u64,
}

/// A condition on one clock that must hold for a timed transition to be
/// enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimingGuard {
	/// The clock reads less than the duration: `x < d`.
	ClockLessThan(String, Duration),
	/// The clock reads at most the duration: `x <= d`.
	ClockLessEqual(String, Duration),
	/// The clock reads more than the duration: `x > d`.
	ClockGreaterThan(String, Duration),
	/// The clock reads at least the duration: `x >= d`.
	ClockGreaterEqual(String, Duration),
	/// The clock reads the duration exactly: `x == d`.
	ClockEquals(String, Duration),
	/// The clock reads a value in the closed range: `d1 <= x <= d2`.
	ClockInRange(String, Duration, Duration),
}

impl TimingGuard {
	/// The name of the clock that this guard reads.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::testing::timing::TimingGuard;
	///
	/// let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
	/// assert_eq!(guard.clock(), "clk");
	/// ```
	pub fn clock(&self) -> &str {
		match self {
			TimingGuard::ClockLessThan(name, _)
			| TimingGuard::ClockLessEqual(name, _)
			| TimingGuard::ClockGreaterThan(name, _)
			| TimingGuard::ClockGreaterEqual(name, _)
			| TimingGuard::ClockEquals(name, _)
			| TimingGuard::ClockInRange(name, _, _) => name,
		}
	}

	/// Whether this guard holds for `clock_values`.
	///
	/// A clock the guard names but the map omits leaves the guard
	/// unsatisfied, so an unstarted clock never enables a transition.
	pub fn satisfied_by(&self, clock_values: &HashMap<String, Duration>) -> bool {
		match self {
			TimingGuard::ClockLessThan(name, duration) => clock_values.get(name).is_some_and(|v| *v < *duration),
			TimingGuard::ClockLessEqual(name, duration) => clock_values.get(name).is_some_and(|v| *v <= *duration),
			TimingGuard::ClockGreaterThan(name, duration) => clock_values.get(name).is_some_and(|v| *v > *duration),
			TimingGuard::ClockGreaterEqual(name, duration) => clock_values.get(name).is_some_and(|v| *v >= *duration),
			TimingGuard::ClockEquals(name, duration) => clock_values.get(name).is_some_and(|v| *v == *duration),
			TimingGuard::ClockInRange(name, d1, d2) => clock_values.get(name).is_some_and(|v| *v >= *d1 && *v <= *d2),
		}
	}
}

/// A CSP transition that may carry a timing guard and the clocks it resets.
#[derive(Debug, Clone)]
pub struct TimedTransition {
	/// The state the transition leaves.
	pub from: State,
	/// The action of the transition, which is an event and its alphabet.
	pub action: Action,
	/// The state the transition enters.
	pub to: State,
	/// The guard that must hold for the transition to be enabled. With
	/// `None`, the transition is always enabled.
	pub guard: Option<TimingGuard>,
	/// The clocks that this transition resets when it fires.
	pub reset_clocks: Vec<String>,
}

impl TimedTransition {
	/// Creates an unguarded transition with an empty reset list.
	pub fn new(from: State, action: Action, to: State) -> Self {
		Self { from, action, to, guard: None, reset_clocks: Vec::new() }
	}

	/// Sets the timing guard of this transition.
	pub fn with_guard(mut self, guard: TimingGuard) -> Self {
		self.guard = Some(guard);
		self
	}

	/// Sets the clocks this transition resets, and replaces any earlier list.
	pub fn with_reset_clocks(mut self, clocks: impl IntoIterator<Item = String>) -> Self {
		let clocks: Vec<String> = clocks.into_iter().collect();
		self.reset_clocks = clocks;
		self
	}

	/// The clocks that this transition names: the clock of its guard, then
	/// each clock it resets.
	pub(crate) fn clocks(&self) -> impl Iterator<Item = &str> {
		let guarded = self.guard.iter().map(TimingGuard::clock);
		let reset = self.reset_clocks.iter().map(String::as_str);

		guarded.chain(reset)
	}

	/// Whether this transition is enabled at `clock_values`.
	///
	/// A transition with no guard is always enabled.
	pub fn guard_satisfied(&self, clock_values: &HashMap<String, Duration>) -> bool {
		self.guard.as_ref().is_none_or(|guard| guard.satisfied_by(clock_values))
	}
}
