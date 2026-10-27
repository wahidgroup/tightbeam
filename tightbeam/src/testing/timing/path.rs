//! The path WCET analysis of a trace.
//!
//! The analysis is compositional. It checks that the sum of the execution
//! times along each bounded execution path stays within the bound of that path.

use std::time::Duration;

use super::saturating_nanos;
use super::verification::Samples;
use crate::testing::specs::csp::{Event, Process};
use crate::trace::ConsumedTrace;

/// An execution path that a trace shows, with its timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPath {
	/// The events of the path, in order.
	pub events: Vec<Event>,
	/// The duration of each event in nanoseconds, or `None` for an event with
	/// no measure.
	pub durations: Vec<Option<u64>>,
	/// The total duration of the path: the sum of the measured durations, in
	/// nanoseconds, saturated at `u64::MAX`.
	pub total_duration: u64,
}

/// A path WCET constraint.
///
/// It bounds the total duration of one sequence of events. The verification
/// compares the sum of the event durations along the path with the bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWcet {
	/// The events of the path, which a run matches in order.
	pub path: Vec<Event>,
	/// The longest total duration that the path allows.
	pub max_duration: Duration,
}

impl ExecutionPath {
	/// Builds the execution path of `events` and their `durations`.
	pub fn new(events: impl IntoIterator<Item = Event>, durations: impl IntoIterator<Item = Option<u64>>) -> Self {
		let events: Vec<Event> = events.into_iter().collect();
		let durations: Vec<Option<u64>> = durations.into_iter().collect();
		let total_duration = Self::sum_of(&durations);
		Self { events, durations, total_duration }
	}

	/// The first `len` events of this path, with the sum of their durations
	/// in nanoseconds, or `None` when the path holds fewer events.
	pub(crate) fn prefix(&self, len: usize) -> Option<(&[Event], u64)> {
		let events = self.events.get(..len)?;
		let durations = self.durations.iter().take(len);

		Some((events, Self::sum_of(durations)))
	}

	/// The sum of the measured `durations`, saturated at `u64::MAX`.
	fn sum_of<'a>(durations: impl IntoIterator<Item = &'a Option<u64>>) -> u64 {
		durations.into_iter().filter_map(|&d| d).fold(0, u64::saturating_add)
	}

	/// Whether `pattern` matches this path.
	///
	/// A pattern matches the first events of this path in order, as a prefix
	/// or as the whole path. An empty pattern matches no path.
	pub fn matches_pattern(&self, pattern: impl AsRef<[Event]>) -> bool {
		let pattern = pattern.as_ref();
		if pattern.is_empty() {
			return false;
		}
		if pattern.len() > self.events.len() {
			return false;
		}

		// The first events of the path match the pattern by name.
		self.events
			.iter()
			.take(pattern.len())
			.zip(pattern.iter())
			.all(|(a, b)| a.0 == b.0)
	}

	/// The duration of the first run of `event` on this path, or `None` when
	/// the path lacks the event or the run has no measure.
	pub fn duration_for_event(&self, event: &Event) -> Option<u64> {
		self.events
			.iter()
			.position(|e| e == event)
			.and_then(|idx| self.durations.get(idx).copied().flatten())
	}
}

impl PathWcet {
	/// Builds the path WCET constraint that bounds `path` by `max_duration`.
	pub fn new(path: impl IntoIterator<Item = Event>, max_duration: Duration) -> Self {
		let path: Vec<Event> = path.into_iter().collect();
		Self { path, max_duration }
	}

	/// The bound of the path in nanoseconds, saturated at `u64::MAX`.
	pub fn max_duration_ns(&self) -> u64 {
		saturating_nanos(self.max_duration)
	}

	/// The duration `duration_ns` of a run of the events `run`, when the run
	/// takes this path exactly and exceeds its maximum, or `None` when it
	/// holds the bound.
	pub(crate) fn excess(&self, run: &[Event], duration_ns: u64) -> Option<u64> {
		let on_path = run == self.path.as_slice();
		let over_budget = duration_ns > self.max_duration_ns();
		(on_path && over_budget).then_some(duration_ns)
	}
}

impl ConsumedTrace {
	/// The execution paths that this trace takes through `process`.
	///
	/// A path is a walk that `process` admits over the runs of its own events,
	/// in trace order. A run is any record of an event but a deadline marker,
	/// and it takes the walk to the first state its event reaches. The events
	/// of `process` decide where a path breaks:
	///
	/// - The walk skips a run of an event outside the alphabet of `process`.
	/// - A run that the current state does not enable ends the path and opens the next one.
	/// - The next path starts at the initial state, and the walk skips a run that it does not enable.
	pub fn execution_paths(&self, process: &Process) -> Vec<ExecutionPath> {
		let mut paths = Vec::new();
		let mut events = Vec::new();
		let mut durations = Vec::new();
		let mut state = process.initial;

		#[cfg(feature = "instrument")]
		let records = self.instrument_events.iter();
		#[cfg(not(feature = "instrument"))]
		let records = core::iter::empty::<&crate::instrumentation::TbEvent>();

		for record in records {
			let Some(event) = Samples::run_of(record, process) else {
				continue;
			};

			let mut next = process.step(state, &event).first().copied();
			if next.is_none() {
				if !events.is_empty() {
					let path = ExecutionPath::new(core::mem::take(&mut events), core::mem::take(&mut durations));
					paths.push(path);
				}

				state = process.initial;
				next = process.step(state, &event).first().copied();
			}
			let Some(next) = next else {
				continue;
			};

			events.push(event);
			durations.push(record.duration_ns);
			state = next;
		}

		if !events.is_empty() {
			paths.push(ExecutionPath::new(events, durations));
		}

		paths
	}
}

#[cfg(test)]
mod tests {
	use std::borrow::Cow;

	use super::*;
	use crate::instrumentation::{events, TbEvent};
	use crate::testing::specs::csp::{Process, ProcessBuildError, State};
	use crate::urn::Urn;

	#[test]
	fn test_execution_path_new() {
		let events = vec![Event("start"), Event("process"), Event("end")];
		let durations = vec![Some(10_000_000), Some(20_000_000), Some(5_000_000)];
		let path = ExecutionPath::new(events.clone(), durations.clone());
		assert_eq!(path.events, events);
		assert_eq!(path.durations, durations);
		assert_eq!(path.total_duration, 35_000_000);
	}

	#[test]
	fn test_execution_path_matches_pattern() {
		let events = vec![Event("start"), Event("process"), Event("end")];
		let durations = vec![Some(10_000_000), Some(20_000_000), Some(5_000_000)];
		let path = ExecutionPath::new(events, durations);
		// The whole path matches.
		assert!(path.matches_pattern([Event("start"), Event("process"), Event("end")]));
		// A prefix matches.
		assert!(path.matches_pattern([Event("start"), Event("process")]));
		// A pattern with another event fails to match.
		assert!(!path.matches_pattern([Event("start"), Event("wrong")]));
		// A pattern longer than the path fails to match.
		assert!(!path.matches_pattern([Event("start"), Event("process"), Event("end"), Event("extra")]));
	}

	#[test]
	fn test_path_wcet_new() {
		let path = vec![Event("start"), Event("process"), Event("end")];
		let max_duration = Duration::from_millis(50);
		let path_wcet = PathWcet::new(path.clone(), max_duration);
		assert_eq!(path_wcet.path, path);
		assert_eq!(path_wcet.max_duration, max_duration);
		assert_eq!(path_wcet.max_duration_ns(), 50_000_000);
	}

	#[test]
	fn a_path_total_saturates_at_the_largest_duration() -> Result<(), Box<dyn core::error::Error>> {
		let events = [Event("start"), Event("end")];
		let path = ExecutionPath::new(events, [Some(u64::MAX), Some(1)]);
		assert_eq!(path.total_duration, u64::MAX);
		Ok(())
	}

	/// A process that takes `start`, then `process`, then `end`.
	fn create_test_process() -> Result<Process, ProcessBuildError> {
		Process::builder("test")
			.initial_state(State("s0"))
			.add_terminal(State("s2"))
			.add_observable(Event("start"))
			.add_observable(Event("process"))
			.add_observable(Event("end"))
			.add_transition(State("s0"), Event("start"), State("s1"))
			.add_transition(State("s1"), Event("process"), State("s2"))
			.add_transition(State("s2"), Event("end"), State("s2"))
			.build()
	}

	/// A trace of one `TIMING_WCET` run for each label and duration of
	/// `events`, numbered from 1.
	fn create_trace_with_timing_events(events: &[(&str, u64)]) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			use crate::instrumentation::events;

			trace.instrument_events = events
				.iter()
				.enumerate()
				.map(|(idx, (label, duration_ns))| TbEvent {
					seq: idx as u32 + 1,
					urn: events::TIMING_WCET,
					label: Some(label.to_string().into()),
					payload_hash: None,
					duration_ns: Some(*duration_ns),
					timestamp_ns: None,
					flags: 0,
					extras: None,
				})
				.collect();
		}

		trace
	}

	/// A trace of `records`, each a kind, a label, and a value. A deadline
	/// marker carries its value as a timestamp, and every other record
	/// carries it as a duration.
	fn trace_of(records: &[(Urn<'static>, &'static str, u64)]) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			use crate::instrumentation::events;

			trace.instrument_events = records
				.iter()
				.enumerate()
				.map(|(seq, (urn, label, value))| {
					let is_marker = *urn == events::TIMING_DEADLINE;
					TbEvent {
						seq: seq as u32,
						urn: urn.clone(),
						label: Some(Cow::Borrowed(*label)),
						payload_hash: None,
						duration_ns: (!is_marker).then_some(*value),
						timestamp_ns: is_marker.then_some(*value),
						flags: 0,
						extras: None,
					}
				})
				.collect();
		}

		trace
	}

	/// The path of the `start`, `process`, and `end` runs of 10, 20, and 5 ms.
	fn start_process_end() -> ExecutionPath {
		let events = [Event("start"), Event("process"), Event("end")];
		ExecutionPath::new(events, [Some(10_000_000), Some(20_000_000), Some(5_000_000)])
	}

	#[test]
	fn a_run_outside_the_alphabet_leaves_the_path_whole() -> Result<(), ProcessBuildError> {
		let process = create_test_process()?;
		let trace = trace_of(&[
			(events::TIMING_WCET, "start", 10_000_000),
			(events::TIMING_WCET, "other", 1_000_000),
			(events::TIMING_WCET, "process", 20_000_000),
			(events::TIMING_WCET, "end", 5_000_000),
		]);

		let paths = trace.execution_paths(&process);
		assert_eq!(paths, [start_process_end()]);
		Ok(())
	}

	#[test]
	fn a_deadline_marker_lies_on_no_path() -> Result<(), ProcessBuildError> {
		let process = create_test_process()?;
		let trace = trace_of(&[
			(events::TIMING_WCET, "start", 10_000_000),
			(events::TIMING_DEADLINE, "process", 15_000_000),
			(events::TIMING_WCET, "process", 20_000_000),
			(events::TIMING_WCET, "end", 5_000_000),
		]);

		let paths = trace.execution_paths(&process);
		assert_eq!(paths, [start_process_end()]);
		Ok(())
	}

	#[test]
	fn test_extract_paths_simple() -> Result<(), ProcessBuildError> {
		let process = create_test_process()?;
		let events = vec![("start", 10_000_000), ("process", 20_000_000), ("end", 5_000_000)];
		let trace = create_trace_with_timing_events(&events);

		// The trace yields one path that holds all three events.
		let paths = trace.execution_paths(&process);
		assert_eq!(paths.len(), 1);
		assert_eq!(paths[0].events.len(), 3);
		assert_eq!(paths[0].total_duration, 35_000_000);
		Ok(())
	}
}
