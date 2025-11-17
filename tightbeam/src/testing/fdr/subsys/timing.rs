//! Timing constraint checking during FDR exploration
//!
//! This module provides functions to check timing constraints during CSP
//! exploration, allowing early pruning of traces that violate timing
//! requirements.

use core::time::Duration;

use std::collections::HashMap;

use crate::testing::fdr::config::Trace;
use crate::testing::specs::csp::Event;
use crate::testing::timing::{TimedTransition, TimingConstraint, TimingConstraints, TimingGuard};

/// Check if current trace violates any timing constraints
///
/// Returns `true` if any timing constraint is violated, `false` otherwise.
/// This allows pruning of violating traces during exploration.
pub fn check_timing_violations(
	trace: &Trace,
	elapsed_time: Duration,
	event_times: &[(Event, Duration)],
	constraints: &TimingConstraints,
) -> bool {
	// Check deadline constraints
	if check_deadline_violations(event_times, constraints) {
		return true;
	}

	// Check path WCET constraints
	if check_path_wcet_violations(trace, elapsed_time, constraints) {
		return true;
	}

	false
}

/// Check if a specific event's WCET violates its constraint
///
/// This is called during exploration after looking up the WCET for an event.
/// It checks if the WCET value exceeds the constraint for that event.
pub fn check_event_wcet_violation(event: &Event, event_wcet: Duration, constraints: &TimingConstraints) -> bool {
	check_wcet_violations(event, event_wcet, constraints)
}

/// Check if any WCET constraint is violated
///
/// A WCET violation occurs if the WCET for an event exceeds its constraint.
/// During exploration, we use WCET as worst-case time, so we check if the
/// WCET value itself exceeds the constraint.
fn check_wcet_violations(event: &Event, event_wcet: Duration, constraints: &TimingConstraints) -> bool {
	// Check if the WCET for this event exceeds its constraint
	if let Some(TimingConstraint::Wcet(wcet_config)) = constraints.get(event) {
		// The event_wcet is the WCET value we looked up for this event
		// Check if it exceeds the constraint
		if event_wcet > wcet_config.duration {
			return true;
		}
	}

	false
}

/// Check if any deadline constraint is violated
///
/// A deadline violation occurs if the time between start_event and end_event
/// exceeds the deadline duration.
fn check_deadline_violations(event_times: &[(Event, Duration)], constraints: &TimingConstraints) -> bool {
	for deadline in constraints.deadlines() {
		// Find start_event and end_event in event_times
		let mut start_time: Option<Duration> = None;
		let mut end_time: Option<Duration> = None;
		for (event, time) in event_times {
			if *event == deadline.start_event {
				start_time = Some(*time);
			}
			if *event == deadline.end_event {
				end_time = Some(*time);
			}
		}

		// If both events found, check deadline
		if let (Some(start), Some(end)) = (start_time, end_time) {
			let latency = end - start;
			if latency > deadline.duration {
				return true;
			}
		}
	}

	false
}

/// Check if any path WCET constraint is violated
///
/// A path WCET violation occurs if the cumulative WCET along a matching path
/// exceeds the path WCET limit.
fn check_path_wcet_violations(trace: &Trace, elapsed_time: Duration, constraints: &TimingConstraints) -> bool {
	for path_wcet in constraints.path_wcets() {
		// Check if current trace matches the path pattern
		if matches_path_pattern(trace, &path_wcet.path) {
			// If path matches and elapsed time exceeds limit, violation
			if elapsed_time > path_wcet.max_duration {
				return true;
			}
		}
	}

	false
}

/// Check if trace matches a path pattern (exact match)
fn matches_path_pattern(trace: &Trace, pattern: &[Event]) -> bool {
	if trace.len() != pattern.len() {
		return false;
	}

	trace.iter().zip(pattern.iter()).all(|(a, b)| a == b)
}

/// Evaluate a timing guard against current clock values
///
/// Returns `true` if the guard is satisfied, `false` otherwise.
/// If the clock is not found in clock_values, returns `false` (guard not satisfied).
#[cfg(feature = "testing-timing")]
pub fn evaluate_timing_guard(guard: &TimingGuard, clock_values: &HashMap<String, Duration>) -> bool {
	match guard {
		TimingGuard::ClockLessThan(name, duration) => {
			clock_values.get(name).map_or(false, |v| *v < *duration)
		}
		TimingGuard::ClockLessEqual(name, duration) => {
			clock_values.get(name).map_or(false, |v| *v <= *duration)
		}
		TimingGuard::ClockGreaterThan(name, duration) => {
			clock_values.get(name).map_or(false, |v| *v > *duration)
		}
		TimingGuard::ClockGreaterEqual(name, duration) => {
			clock_values.get(name).map_or(false, |v| *v >= *duration)
		}
		TimingGuard::ClockEquals(name, duration) => {
			clock_values.get(name).map_or(false, |v| *v == *duration)
		}
		TimingGuard::ClockInRange(name, d1, d2) => {
			clock_values.get(name).map_or(false, |v| *v >= *d1 && *v <= *d2)
		}
	}
}

/// Check if a timed transition's guard is satisfied
///
/// Returns `true` if:
/// - The transition has no guard (backward compatible)
/// - The transition has a guard and it is satisfied
///
/// Returns `false` if the guard exists and is not satisfied.
#[cfg(feature = "testing-timing")]
pub fn check_timed_transition_guard(
	transition: &TimedTransition,
	clock_values: &HashMap<String, Duration>,
) -> bool {
	// If no guard, transition is always enabled (backward compatible)
	if let Some(ref guard) = transition.guard {
		evaluate_timing_guard(guard, clock_values)
	} else {
		true
	}
}

#[cfg(test)]
#[cfg(feature = "testing-timing")]
mod tests {
	use super::*;
	use crate::builder::TypeBuilder;
	use crate::testing::error::TestingError;
	use crate::testing::timing::{Deadline, DeadlineBuilder, PathWcet, WcetConfigBuilder};

	/// Helper to create deadline constraint
	fn create_deadline_constraint(ms: u64, start: &'static str, end: &'static str) -> Result<Deadline, TestingError> {
		DeadlineBuilder::default()
			.with_duration(Duration::from_millis(ms))
			.with_start_event(Event(start))
			.with_end_event(Event(end))
			.build()
	}

	/// Test case for timing violation checking
	struct TimingViolationTestCase {
		trace_events: &'static [&'static str],
		elapsed_time_ms: u64,
		event_times_ms: &'static [(&'static str, u64)],
		has_deadline: bool,
		deadline_ms: u64,
		has_path_wcet: bool,
		path_wcet_ms: u64,
		expected_violation: bool,
	}

	const TIMING_VIOLATION_TEST_CASES: &[TimingViolationTestCase] = &[
		TimingViolationTestCase {
			// No violations: deadline satisfied
			trace_events: &["start", "end"],
			elapsed_time_ms: 50,
			event_times_ms: &[("start", 0), ("end", 50)],
			has_deadline: true,
			deadline_ms: 100,
			has_path_wcet: false,
			path_wcet_ms: 0,
			expected_violation: false,
		},
		TimingViolationTestCase {
			// Deadline violation: latency exceeds deadline
			trace_events: &["start", "end"],
			elapsed_time_ms: 150,
			event_times_ms: &[("start", 0), ("end", 150)],
			has_deadline: true,
			deadline_ms: 100,
			has_path_wcet: false,
			path_wcet_ms: 0,
			expected_violation: true,
		},
		TimingViolationTestCase {
			// Path WCET violation: elapsed time exceeds path WCET
			trace_events: &["start", "process", "end"],
			elapsed_time_ms: 150,
			event_times_ms: &[("start", 50), ("process", 100), ("end", 150)],
			has_deadline: false,
			deadline_ms: 0,
			has_path_wcet: true,
			path_wcet_ms: 100,
			expected_violation: true,
		},
		TimingViolationTestCase {
			// No violations: all constraints satisfied
			trace_events: &["start", "process", "end"],
			elapsed_time_ms: 50,
			event_times_ms: &[("start", 0), ("process", 30), ("end", 50)],
			has_deadline: true,
			deadline_ms: 100,
			has_path_wcet: true,
			path_wcet_ms: 100,
			expected_violation: false,
		},
	];

	/// Run timing violation test case
	fn run_timing_violation_test_case(case: &TimingViolationTestCase) -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let trace: Trace = case.trace_events.iter().map(|s| Event(s)).collect();
		let elapsed_time = Duration::from_millis(case.elapsed_time_ms);
		let event_times: Vec<(Event, Duration)> = case
			.event_times_ms
			.iter()
			.map(|(s, ms)| (Event(s), Duration::from_millis(*ms)))
			.collect();

		// Note: WCET violations are checked per-event during exploration,
		// not in this aggregate check. This test focuses on deadline and path WCET.

		if case.has_deadline {
			let deadline = create_deadline_constraint(case.deadline_ms, "start", "end")?;
			constraints.add_deadline(deadline);
		}

		if case.has_path_wcet {
			let path_wcet = PathWcet::new(
				vec![Event("start"), Event("process"), Event("end")],
				Duration::from_millis(case.path_wcet_ms),
			);
			constraints.add_path_wcet(path_wcet);
		}

		let has_violation = check_timing_violations(&trace, elapsed_time, &event_times, &constraints);
		assert_eq!(has_violation, case.expected_violation);

		Ok(())
	}

	#[test]
	fn test_timing_violations() -> Result<(), TestingError> {
		for case in TIMING_VIOLATION_TEST_CASES {
			run_timing_violation_test_case(case)?;
		}
		Ok(())
	}

	#[test]
	fn test_no_constraints() {
		let constraints = TimingConstraints::default();
		let trace: Trace = vec![Event("process")];
		let elapsed_time = Duration::from_millis(100);
		let event_times = vec![];

		let has_violation = check_timing_violations(&trace, elapsed_time, &event_times, &constraints);
		assert!(!has_violation);
	}

	#[test]
	fn test_event_wcet_violation() {
		let mut constraints = TimingConstraints::default();
		let wcet_config = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(100))
			.build()
			.unwrap();
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		// WCET within constraint: no violation
		assert!(!check_event_wcet_violation(
			&Event("process"),
			Duration::from_millis(50),
			&constraints
		));
		assert!(!check_event_wcet_violation(
			&Event("process"),
			Duration::from_millis(100),
			&constraints
		));

		// WCET exceeds constraint: violation
		assert!(check_event_wcet_violation(
			&Event("process"),
			Duration::from_millis(150),
			&constraints
		));

		// Event without constraint: no violation
		assert!(!check_event_wcet_violation(
			&Event("other"),
			Duration::from_millis(1000),
			&constraints
		));
	}
}
