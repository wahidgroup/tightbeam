//! The timing checks of FDR exploration.
//!
//! The module adds checks to [`TimingConstraints`] that FDR exploration calls
//! on each branch, so exploration prunes a trace that violates a timing
//! constraint before the trace grows. It adds to [`Process`] the divergence of
//! a state at the clocks of a branch, which a guard can block.

use core::time::Duration;
use std::collections::{BTreeSet, HashMap, HashSet};

use crate::testing::fdr::verdict::Trace;
use crate::testing::specs::csp::{Action, Event, Process, State};
use crate::testing::timing::{TimingConstraint, TimingConstraints};

#[cfg(feature = "testing-schedulability")]
use crate::testing::schedulability::SchedulabilityError;

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

/// A point of a run of hidden events: a state, and the clocks that the run
/// has reset on its way there.
type RunPoint = (State, BTreeSet<String>);

impl Process {
	/// The hidden events of a run from `state` that never ends while the
	/// clocks read `clocks`, or `None` when no such run exists.
	///
	/// - A hidden event takes no time, so the clocks change along a run only
	///   where an edge resets them, and each guard reads them at its edge.
	/// - The run takes the hidden actions in the order of [`Process::enabled`],
	///   and it ends at the first point that it reaches a second time, so its
	///   last event closes a cycle.
	///
	/// A guard can block an edge that [`Process::divergent_states`] counts,
	/// so a state that it marks can answer `None` here.
	pub(crate) fn divergence_under(&self, state: State, clocks: &HashMap<String, Duration>) -> Option<Vec<Event>> {
		let start: RunPoint = (state, BTreeSet::new());
		let mut stack = vec![(start.clone(), self.hidden_steps(&start, clocks))];
		let mut on_path = HashSet::from([start]);
		let mut finished = HashSet::new();
		let mut events = Vec::new();

		while let Some((_point, pending)) = stack.last_mut() {
			// 1. A point whose every step is explored closes no cycle.
			let Some((event, next)) = pending.pop() else {
				if let Some((done, _pending)) = stack.pop() {
					on_path.remove(&done);
					finished.insert(done);
				}

				events.truncate(stack.len().saturating_sub(1));
				continue;
			};

			// 2. A step back to a point on the path closes the cycle of the run.
			if on_path.contains(&next) {
				events.push(event);
				return Some(events);
			}

			// 3. A step to a point that closes no cycle adds nothing to the run.
			if finished.contains(&next) {
				continue;
			}

			// 4. Any other step extends the run.
			events.push(event);
			let steps = self.hidden_steps(&next, clocks);
			on_path.insert(next.clone());
			stack.push((next, steps));
		}

		None
	}

	/// The hidden steps from `point` while the clocks read `clocks` with the
	/// resets of `point`, in reverse order, so a stack pops the first one
	/// first.
	fn hidden_steps(&self, point: &RunPoint, clocks: &HashMap<String, Duration>) -> Vec<(Event, RunPoint)> {
		let (from, reset) = point;
		let mut at = clocks.clone();
		for name in reset {
			at.insert(name.clone(), Duration::ZERO);
		}

		let mut steps = Vec::new();
		let hidden = self.enabled(*from).into_iter().filter(Action::is_hidden);
		for action in hidden {
			for successor in self.successors(*from, &action.event, &at) {
				let mut resets = reset.clone();
				resets.extend(successor.resets.iter().cloned());
				steps.push((action.event, (successor.to, resets)));
			}
		}

		steps.reverse();
		steps
	}
}

#[cfg(feature = "testing-schedulability")]
impl Process {
	/// Whether the task set of this process fails schedulability analysis,
	/// or `None` when the process declares no schedulability block, so no
	/// analysis runs.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError`] -- task-set generation or the analysis fails.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// assert_eq!(process.schedulability_violated()?, None);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn schedulability_violated(&self) -> Result<Option<bool>, SchedulabilityError> {
		use crate::testing::schedulability::SchedulerType;

		let Some(task_set) = self.generate_task_set()? else {
			return Ok(None);
		};

		let result = match task_set.scheduler {
			SchedulerType::RateMonotonic => task_set.is_rm_schedulable()?,
			SchedulerType::EarliestDeadlineFirst => task_set.is_edf_schedulable()?,
		};

		Ok(Some(!result.is_schedulable))
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
		deadline_ms: Option<u64>,
		path_wcet_ms: Option<u64>,
		expected_violation: bool,
	}

	impl TimingViolationTestCase {
		/// Whether the constraints of the case reject its trace.
		fn violated(&self) -> bool {
			let mut constraints = TimingConstraints::default();
			let trace: Trace = self.trace_events.iter().map(|s| Event(s)).collect();
			let elapsed_time = Duration::from_millis(self.elapsed_time_ms);
			let event_times: Vec<(Event, Duration)> = self
				.event_times_ms
				.iter()
				.map(|(s, ms)| (Event(s), Duration::from_millis(*ms)))
				.collect();

			if let Some(deadline_ms) = self.deadline_ms {
				let deadline = create_deadline_constraint(deadline_ms, "start", "end").expect("the deadline builds");
				constraints.add_deadline(deadline);
			}

			if let Some(path_wcet_ms) = self.path_wcet_ms {
				let path = vec![Event("start"), Event("process"), Event("end")];
				let path_wcet = PathWcet::new(path, Duration::from_millis(path_wcet_ms));
				constraints.add_path_wcet(path_wcet);
			}

			constraints.violated_by(&trace, elapsed_time, &event_times)
		}
	}

	// Exploration charges each event its WCET apart from this aggregate check,
	// so the table covers the deadline and the path WCET.
	crate::tb_cases! {
		fn timing_violation(case: TimingViolationTestCase) {
			let violated = case.violated();
			assert_eq!(violated, case.expected_violation);
		}

		cases {
			within_the_deadline => TimingViolationTestCase {
				trace_events: &["start", "end"],
				elapsed_time_ms: 50,
				event_times_ms: &[("start", 0), ("end", 50)],
				deadline_ms: Some(100),
				path_wcet_ms: None,
				expected_violation: false,
			},
			past_the_deadline => TimingViolationTestCase {
				trace_events: &["start", "end"],
				elapsed_time_ms: 150,
				event_times_ms: &[("start", 0), ("end", 150)],
				deadline_ms: Some(100),
				path_wcet_ms: None,
				expected_violation: true,
			},
			past_the_path_wcet => TimingViolationTestCase {
				trace_events: &["start", "process", "end"],
				elapsed_time_ms: 150,
				event_times_ms: &[("start", 50), ("process", 100), ("end", 150)],
				deadline_ms: None,
				path_wcet_ms: Some(100),
				expected_violation: true,
			},
			within_the_deadline_and_the_path_wcet => TimingViolationTestCase {
				trace_events: &["start", "process", "end"],
				elapsed_time_ms: 50,
				event_times_ms: &[("start", 0), ("process", 30), ("end", 50)],
				deadline_ms: Some(100),
				path_wcet_ms: Some(100),
				expected_violation: false,
			},
		}
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
	fn an_event_adds_the_wcet_its_constraint_names() -> Result<(), Box<dyn core::error::Error>> {
		let mut constraints = TimingConstraints::default();
		let duration = Duration::from_millis(100);
		let wcet_config = WcetConfigBuilder::default().with_duration(duration).build()?;
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		assert_eq!(constraints.wcet_of(&Event("process")), duration);
		Ok(())
	}
}
