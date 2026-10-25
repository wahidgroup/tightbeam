//! The timing checks of FDR exploration.
//!
//! The module adds checks to [`TimingConstraints`] that FDR exploration calls
//! on each branch, so exploration prunes a trace that violates a timing
//! constraint before the trace grows.

use core::time::Duration;

use crate::testing::fdr::verdict::Trace;
use crate::testing::specs::csp::Event;
use crate::testing::timing::{TimingConstraint, TimingConstraints};

impl TimingConstraints {
	/// Whether `trace` violates a deadline or a path WCET constraint.
	///
	/// Exploration prunes on `true`, so it cuts a violating trace before it
	/// generates the successors.
	pub fn violated_by(
		&self,
		trace: &Trace,
		elapsed_time: Duration,
		event_times: impl AsRef<[(Event, Duration)]>,
	) -> bool {
		let event_times = event_times.as_ref();
		self.deadline_violated(event_times) || self.path_wcet_violated(trace, elapsed_time)
	}

	/// Whether `event_wcet` exceeds the WCET constraint on `event`.
	///
	/// Exploration takes the WCET as the time of the event, so it compares the
	/// value that `wcet_of` looks up against the constraint.
	pub fn wcet_violated(&self, event: &Event, event_wcet: Duration) -> bool {
		let Some(TimingConstraint::Wcet(wcet_config)) = self.get(event) else {
			return false;
		};

		event_wcet > wcet_config.duration
	}

	/// The WCET that `event` adds to the elapsed time of a path.
	///
	/// An event with no WCET constraint, or with a jitter or a deadline
	/// constraint, adds [`Duration::ZERO`].
	pub(crate) fn wcet_of(&self, event: &Event) -> Duration {
		let Some(TimingConstraint::Wcet(wcet_config)) = self.get(event) else {
			return Duration::ZERO;
		};

		wcet_config.duration
	}

	/// Whether the time from the start event to the end event of a deadline
	/// exceeds its duration.
	///
	/// A deadline holds while `event_times` lacks one of its two events.
	fn deadline_violated(&self, event_times: impl AsRef<[(Event, Duration)]>) -> bool {
		let event_times = event_times.as_ref();
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
	/// A path matches only a trace of its exact event sequence, so its limit
	/// binds that trace alone.
	fn path_wcet_violated(&self, trace: &Trace, elapsed_time: Duration) -> bool {
		self.path_wcets().iter().any(|path_wcet| {
			let matched =
				trace.len() == path_wcet.path.len() && trace.iter().zip(path_wcet.path.iter()).all(|(a, b)| a == b);

			matched && elapsed_time > path_wcet.max_duration
		})
	}
}

#[cfg(feature = "testing-schedulability")]
impl crate::testing::specs::csp::Process {
	/// Whether the task set of this process fails schedulability analysis.
	///
	/// A process with no schedulability configuration has no task set to
	/// analyse, so it reports no violation.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError`](crate::testing::schedulability::SchedulabilityError) --
	///   task-set generation or the analysis fails.
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

	/// A deadline of `ms` milliseconds from `start` to `end`.
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

	/// One case of the timing violation table.
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
			// The deadline holds.
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
			// The latency exceeds the deadline.
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
			// The elapsed time exceeds the path WCET.
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
			// The deadline and the path WCET both hold.
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

	/// Runs one case of the table and checks its verdict.
	fn run_timing_violation_test_case(case: &TimingViolationTestCase) -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let trace: Trace = case.trace_events.iter().map(|s| Event(s)).collect();
		let elapsed_time = Duration::from_millis(case.elapsed_time_ms);
		let event_times: Vec<(Event, Duration)> = case
			.event_times_ms
			.iter()
			.map(|(s, ms)| (Event(s), Duration::from_millis(*ms)))
			.collect();

		// Exploration checks each event against its WCET apart from this
		// aggregate check, so the table covers the deadline and the path WCET.

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

		// A WCET at or under the constraint holds.
		assert!(!constraints.wcet_violated(&Event("process"), Duration::from_millis(50)));
		assert!(!constraints.wcet_violated(&Event("process"), Duration::from_millis(100)));

		// A WCET over the constraint is a violation.
		assert!(constraints.wcet_violated(&Event("process"), Duration::from_millis(150)));

		// An event with no constraint holds at any WCET.
		assert!(!constraints.wcet_violated(&Event("other"), Duration::from_millis(1000)));

		Ok(())
	}

	#[test]
	fn an_event_adds_the_wcet_its_constraint_names() -> Result<(), Box<dyn core::error::Error>> {
		let mut constraints = TimingConstraints::default();
		let duration = Duration::from_millis(100);
		let wcet_config = WcetConfigBuilder::default().with_duration(duration).build()?;
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		assert_eq!(constraints.wcet_of(&Event("process")), duration);
		Ok(())
	}
}
