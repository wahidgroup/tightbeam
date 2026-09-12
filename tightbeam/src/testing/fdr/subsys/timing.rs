//! Timing constraint checking during FDR exploration
//!
//! This module provides functions to check timing constraints during CSP
//! exploration, allowing early pruning of traces that violate timing
//! requirements.

use core::time::Duration;

use std::collections::HashMap;

use crate::testing::fdr::verdict::Trace;
use crate::testing::specs::csp::Event;
use crate::testing::timing::{TimedTransition, TimingConstraint, TimingConstraints, TimingGuard};

impl TimingConstraints {
	/// Whether the current trace violates any timing constraint.
	///
	/// The exploration prunes on `true`, so a violating trace is cut before
	/// its successors are generated.
	pub fn violated_by(&self, trace: &Trace, elapsed_time: Duration, event_times: &[(Event, Duration)]) -> bool {
		self.deadline_violated(event_times) || self.path_wcet_violated(trace, elapsed_time)
	}

	/// Whether `event_wcet` exceeds the WCET constraint on `event`.
	///
	/// The exploration uses WCET as the worst-case time, so the looked-up
	/// value is compared against the constraint directly.
	pub fn wcet_violated(&self, event: &Event, event_wcet: Duration) -> bool {
		let Some(TimingConstraint::Wcet(wcet_config)) = self.get(event) else {
			return false;
		};

		event_wcet > wcet_config.duration
	}

	/// Whether the time between any deadline's start and end event exceeds
	/// that deadline's duration.
	///
	/// A deadline whose two events are not both in `event_times` has not
	/// been exercised yet, so it cannot be violated.
	fn deadline_violated(&self, event_times: &[(Event, Duration)]) -> bool {
		self.deadlines().iter().any(|deadline| {
			let start = event_times
				.iter()
				.find(|(event, _)| *event == deadline.start_event)
				.map(|(_, time)| *time);
			let end = event_times
				.iter()
				.find(|(event, _)| *event == deadline.end_event)
				.map(|(_, time)| *time);

			matches!((start, end), (Some(start), Some(end)) if end - start > deadline.duration)
		})
	}

	/// Whether the cumulative WCET along a matching path exceeds its limit.
	///
	/// A path matches only on an exact event sequence, so a longer or
	/// shorter trace leaves that path's limit unspent.
	fn path_wcet_violated(&self, trace: &Trace, elapsed_time: Duration) -> bool {
		self.path_wcets().iter().any(|path_wcet| {
			let matched =
				trace.len() == path_wcet.path.len() && trace.iter().zip(path_wcet.path.iter()).all(|(a, b)| a == b);

			matched && elapsed_time > path_wcet.max_duration
		})
	}
}

#[cfg(feature = "testing-timing")]
impl TimingGuard {
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

#[cfg(feature = "testing-timing")]
impl TimedTransition {
	/// Whether this transition is enabled at `clock_values`.
	///
	/// A transition with no guard is always enabled.
	pub fn guard_satisfied(&self, clock_values: &HashMap<String, Duration>) -> bool {
		self.guard.as_ref().is_none_or(|guard| guard.satisfied_by(clock_values))
	}
}

#[cfg(feature = "testing-schedulability")]
impl crate::testing::specs::csp::Process {
	/// Whether this process's task set fails schedulability analysis.
	///
	/// A process with no schedulability configuration has no task set to
	/// analyse, so it reports no violation.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError`](crate::testing::schedulability::SchedulabilityError)
	///   from task-set generation or the analysis itself.
	pub fn schedulability_violated(&self) -> Result<bool, crate::testing::schedulability::SchedulabilityError> {
		use crate::testing::schedulability::SchedulerType;

		let Some(task_set) = self.generate_task_set()? else {
			return Ok(false);
		};

		let result = match task_set.scheduler {
			SchedulerType::RateMonotonic => task_set.is_rm_schedulable()?,
			SchedulerType::EarliestDeadlineFirst => task_set.is_edf_schedulable()?,
		};

		Ok(!result.is_schedulable)
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
		let duration = Duration::from_millis(ms);
		let start_event = Event(start);
		let end_event = Event(end);

		DeadlineBuilder::default()
			.with_duration(duration)
			.with_start_event(start_event)
			.with_end_event(end_event)
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

		let has_violation = constraints.violated_by(&trace, elapsed_time, &event_times);
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

		let has_violation = constraints.violated_by(&trace, elapsed_time, &event_times);
		assert!(!has_violation);
	}

	#[test]
	fn test_event_wcet_violation() -> Result<(), Box<dyn core::error::Error>> {
		let mut constraints = TimingConstraints::default();
		let duration = Duration::from_millis(100);
		let wcet_config = WcetConfigBuilder::default().with_duration(duration).build()?;
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		// WCET within constraint: no violation
		assert!(!constraints.wcet_violated(&Event("process"), Duration::from_millis(50)));
		assert!(!constraints.wcet_violated(&Event("process"), Duration::from_millis(100)));

		// WCET exceeds constraint: violation
		assert!(constraints.wcet_violated(&Event("process"), Duration::from_millis(150)));

		// Event without constraint: no violation
		assert!(!constraints.wcet_violated(&Event("other"), Duration::from_millis(1000)));

		Ok(())
	}
}
