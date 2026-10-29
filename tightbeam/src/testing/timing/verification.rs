//! The timing verification of a trace against its timing constraints.

use std::collections::HashMap;

use crate::der::Sequence;
use crate::instrumentation::{events, TbEvent};
use crate::testing::error::TestingError;
use crate::testing::specs::csp::{Event, Process};
use crate::trace::ConsumedTrace;

use super::constraints::{TimingConstraint, TimingConstraints};
use super::deadline::Deadline;
use super::violations::{DeadlineMiss, JitterViolation, PathWcetViolation, TimingSlackViolation, TimingViolation};

/// The DER-encodable result of a timing verification.
#[derive(Debug, Default, Clone, PartialEq, Eq, Sequence)]
pub struct TimingVerificationResult {
	/// Whether the trace meets every timing constraint.
	pub passed: bool,
	/// The WCET violations in the trace.
	pub wcet_violations: Vec<TimingViolation>,
	/// The deadline misses in the trace.
	pub deadline_misses: Vec<DeadlineMiss>,
	/// The jitter violations in the trace.
	pub jitter_violations: Vec<JitterViolation>,
	/// The slack violations in the trace.
	pub slack_violations: Vec<TimingSlackViolation>,
	/// The path WCET violations in the trace.
	pub path_wcet_violations: Vec<PathWcetViolation>,
}

/// The timing events of a trace, grouped by the label of their event.
type EventsByLabel<'a> = HashMap<&'a str, Vec<&'a TbEvent>>;

/// The samples of one event that a verification pass reads: each record that
/// the pass selects, with its measure in nanoseconds, in trace order.
pub(super) struct Samples {
	/// The sequence number of each sample.
	seqs: Vec<u64>,
	/// The measure of each sample, in the order of `seqs`.
	measures: Vec<u64>,
}

impl Samples {
	/// The runs of `event` in `events_by_label`, each with its duration.
	///
	/// A run is every record of the event but a deadline marker, whatever
	/// kind the collector files it under: `TIMING_WCET` for a timed event,
	/// `ASSERT_PAYLOAD` for an event with a value, `ASSERT_LABEL` for an
	/// event with no timing, or the kind of an explicit emit.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a run carries no duration.
	fn runs(event: Event, events_by_label: &EventsByLabel<'_>) -> Result<Self, TestingError> {
		let duration_of = |ev: &TbEvent| ev.duration_ns;

		Self::of(event, events_by_label, Self::is_run, duration_of)
	}

	/// Whether `record` is a run of its event, as [`Self::runs`] selects it.
	fn is_run(record: &TbEvent) -> bool {
		record.urn != events::TIMING_DEADLINE
	}

	/// The event of `process` that `record` is a run of, or `None` when the
	/// record is a deadline marker, carries no label, or names an event
	/// outside the alphabet of `process`.
	pub(super) fn run_of(record: &TbEvent, process: &Process) -> Option<Event> {
		let label = record.label.as_deref().filter(|_| Self::is_run(record))?;
		let mut alphabet = process.observable.iter().chain(&process.hidden);

		alphabet.find(|event| event.0 == label).copied()
	}

	/// The deadline markers of `event` in `events_by_label`, each at its
	/// timestamp.
	///
	/// A marker is a `TIMING_DEADLINE` event, a point in time. A run carries
	/// a span length, so it is no marker.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a marker carries no timestamp.
	fn markers(event: Event, events_by_label: &EventsByLabel<'_>) -> Result<Self, TestingError> {
		let is_marker = |ev: &TbEvent| ev.urn == events::TIMING_DEADLINE;
		let time_of = |ev: &TbEvent| ev.timestamp_ns;

		Self::of(event, events_by_label, is_marker, time_of)
	}

	/// The records of `event` in `events_by_label` that `selects` admits,
	/// each with the measure that `measure` reads from it.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a selected record carries no measure.
	fn of(
		event: Event,
		events_by_label: &EventsByLabel<'_>,
		selects: impl Fn(&TbEvent) -> bool,
		measure: impl Fn(&TbEvent) -> Option<u64>,
	) -> Result<Self, TestingError> {
		let records = events_by_label.get(event.0).map(Vec::as_slice).unwrap_or_default();
		let selected = records.iter().filter(|record| selects(record));
		let measured = selected.map(|record| {
			let unmeasured = || TestingError::TimingSampleUnmeasured { event, seq: record.seq };
			measure(record)
				.map(|measure_ns| (record.seq, measure_ns))
				.ok_or_else(unmeasured)
		});

		let measured: Vec<(u64, u64)> = measured.collect::<Result<_, _>>()?;
		let (seqs, measures) = measured.into_iter().unzip();

		Ok(Self { seqs, measures })
	}

	/// The sequence number of a longest sample, or `None` for an empty set.
	fn longest_seq(&self) -> Option<u64> {
		let longest = self.seqs.iter().zip(&self.measures).max_by_key(|(_, measure_ns)| **measure_ns);
		longest.map(|(seq, _)| *seq)
	}

	/// Each sample as its sequence number and its measure.
	fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
		self.seqs.iter().copied().zip(self.measures.iter().copied())
	}
}

impl TimingConstraints {
	/// Verifies `trace` against the timing constraints of this collection.
	///
	/// The check reads the observed durations and times from the
	/// instrumentation events of the trace, and each constraint decides on
	/// its own samples.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingRecordIncomplete`] -- `trace` holds fewer events than its run emitted.
	/// - [`TestingError::TimingSampleUnmeasured`] -- a record of a constrained event carries no measure.
	/// - [`TestingError::DeadlineUnterminated`] -- a deadline start marker has no end marker after it.
	/// - [`TestingError::WcetAnalysisFailed`] -- the analyzer of a WCET percentile fails on its samples.
	/// - [`TestingError::WcetPercentileMissing`] -- the analyzer of a WCET percentile gives no value for it.
	/// - [`TestingError::JitterCalculationFailed`] -- the calculator of a jitter bound fails on its samples.
	pub fn verify(&self, trace: &ConsumedTrace) -> Result<TimingVerificationResult, TestingError> {
		self.verify_with_process(trace, None)
	}

	/// Verifies `trace` against the timing constraints of this collection,
	/// with the CSP `process` when one is given.
	///
	/// A process adds the path WCET constraints to the check. Without one, the
	/// check covers the event constraints alone: WCET, deadlines, and jitter.
	///
	/// # Errors
	///
	/// - The errors of [`Self::verify`].
	pub fn verify_with_process(
		&self,
		trace: &ConsumedTrace,
		process: Option<&Process>,
	) -> Result<TimingVerificationResult, TestingError> {
		// A truncated record can lack the sample that breaks a bound.
		if !trace.is_complete() {
			return Err(TestingError::TimingRecordIncomplete);
		}

		let mut result = TimingVerificationResult { passed: true, ..Default::default() };
		let records = Self::records_of(trace);
		let events_by_label = Self::group_events_by_label(&records);

		self.verify_wcet_constraints(&events_by_label, &mut result)?;
		self.verify_deadline_constraints(&events_by_label, &mut result)?;
		self.verify_jitter_constraints(&events_by_label, &mut result)?;

		if let Some(process) = process {
			self.verify_path_wcet_constraints(trace, &records, process, &mut result)?;
		}

		Ok(result)
	}

	/// The instrumentation events of `trace`, each a record that a bound of
	/// its event can read.
	fn records_of(trace: &ConsumedTrace) -> Vec<&TbEvent> {
		#[cfg(feature = "instrument")]
		{
			trace.instrument_events().iter().collect()
		}
		#[cfg(not(feature = "instrument"))]
		{
			Vec::new()
		}
	}

	/// Groups `events` by label, and skips an event with no label.
	fn group_events_by_label<'a>(events: &[&'a TbEvent]) -> EventsByLabel<'a> {
		let mut grouped: EventsByLabel<'a> = HashMap::new();
		for event in events.iter().copied() {
			if let Some(label) = event.label.as_deref() {
				grouped.entry(label).or_default().push(event);
			}
		}

		grouped
	}

	/// Verifies each WCET constraint against the runs of its event, and
	/// records a violation that names the measure past the bound.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a run carries no duration.
	/// - The errors of a bound that [`TimingConstraint::excess`] cannot check.
	fn verify_wcet_constraints(
		&self,
		events_by_label: &EventsByLabel<'_>,
		result: &mut TimingVerificationResult,
	) -> Result<(), TestingError> {
		for (event, constraint) in &self.constraints {
			let TimingConstraint::Wcet(_) = constraint else {
				continue;
			};

			let samples = Samples::runs(*event, events_by_label)?;
			// An event that never ran holds its bound.
			let Some(longest_seq) = samples.longest_seq() else {
				continue;
			};
			let Some(observed_ns) = constraint.excess(*event, &samples.measures)? else {
				continue;
			};

			result.passed = false;
			result.wcet_violations.push(TimingViolation {
				event: *event,
				wcet_ns: constraint.bound_ns(),
				observed_ns,
				seq: longest_seq,
			});
		}

		Ok(())
	}

	/// Verifies each deadline constraint against the windows of its start and
	/// end markers. A window opens at a start marker and closes at the first
	/// end marker after it.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a marker carries no timestamp.
	/// - [`TestingError::DeadlineUnterminated`] -- a start marker has no end marker after it.
	fn verify_deadline_constraints(
		&self,
		events_by_label: &EventsByLabel<'_>,
		result: &mut TimingVerificationResult,
	) -> Result<(), TestingError> {
		for deadline in self.deadlines() {
			let starts = Samples::markers(deadline.start_event, events_by_label)?;
			let ends = Samples::markers(deadline.end_event, events_by_label)?;

			for (start_seq, start_ns) in starts.iter() {
				let end = ends.iter().find(|(_, end_ns)| *end_ns > start_ns);
				let unterminated = || TestingError::DeadlineUnterminated {
					start: deadline.start_event,
					end: deadline.end_event,
					seq: start_seq,
				};

				let (end_seq, end_ns) = end.ok_or_else(unterminated)?;
				let window = Window { start_seq, end_seq, latency_ns: end_ns.saturating_sub(start_ns) };

				window.record_against(deadline, result);
			}
		}

		Ok(())
	}

	/// Verifies each jitter constraint against the runs of its event, and
	/// records a violation that names the jitter past the bound.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a run carries no duration.
	/// - [`TestingError::JitterCalculationFailed`] -- the calculator of a bound fails on its samples.
	fn verify_jitter_constraints(
		&self,
		events_by_label: &EventsByLabel<'_>,
		result: &mut TimingVerificationResult,
	) -> Result<(), TestingError> {
		for (event, constraint) in &self.constraints {
			let TimingConstraint::Jitter(..) = constraint else {
				continue;
			};

			let samples = Samples::runs(*event, events_by_label)?;
			let Some(observed_jitter_ns) = constraint.excess(*event, &samples.measures)? else {
				continue;
			};

			result.passed = false;
			result.jitter_violations.push(JitterViolation {
				event: *event,
				max_jitter_ns: constraint.bound_ns(),
				observed_jitter_ns,
				seqs: samples.seqs,
			});
		}

		Ok(())
	}

	/// Verifies each path WCET constraint against the execution paths of
	/// `trace` through `process`.
	///
	/// # Errors
	///
	/// - [`TestingError::TimingSampleUnmeasured`] -- a run of an event of `process` carries no duration.
	fn verify_path_wcet_constraints(
		&self,
		trace: &ConsumedTrace,
		records: &[&TbEvent],
		process: &Process,
		result: &mut TimingVerificationResult,
	) -> Result<(), TestingError> {
		if self.path_wcets().is_empty() {
			return Ok(());
		}

		// An execution path sums the durations of the runs of the events of
		// `process`, so a run with no duration would count as zero.
		let unmeasured = records.iter().find_map(|ev| {
			let event = Samples::run_of(ev, process)?;
			ev.duration_ns.is_none().then_some((event, ev.seq))
		});
		if let Some((event, seq)) = unmeasured {
			return Err(TestingError::TimingSampleUnmeasured { event, seq });
		}

		let execution_paths = trace.execution_paths(process);
		for path_wcet in self.path_wcets() {
			let max_duration_ns = path_wcet.max_duration_ns();
			for exec_path in &execution_paths {
				// A path bound reads the run of its own events at the start of
				// an execution path.
				let Some((run, run_ns)) = exec_path.prefix(path_wcet.path.len()) else {
					continue;
				};
				if let Some(observed_path_duration_ns) = path_wcet.excess(run, run_ns) {
					result.passed = false;
					result.path_wcet_violations.push(PathWcetViolation {
						path: run.to_vec(),
						max_path_duration_ns: max_duration_ns,
						observed_path_duration_ns,
						seqs: {
							// The sequence numbers of the trace events
							// whose label lies on the path.
							#[cfg(feature = "instrument")]
							{
								trace
									.instrument_events()
									.iter()
									.filter(|ev| {
										ev.label.as_ref().map(|l| run.iter().any(|e| e.0 == &**l)) == Some(true)
									})
									.map(|ev| ev.seq)
									.collect()
							}
							#[cfg(not(feature = "instrument"))]
							{
								Vec::new()
							}
						},
					});
				}
			}
		}

		Ok(())
	}
}

/// A deadline window: a start marker and the first end marker after it.
struct Window {
	/// The sequence number of the start marker.
	start_seq: u64,
	/// The sequence number of the end marker.
	end_seq: u64,
	/// The time from the start marker to the end marker, in nanoseconds.
	latency_ns: u64,
}

impl Window {
	/// Records the miss and the slack shortfall of this window against
	/// `deadline`, as the deadline decides each.
	fn record_against(&self, deadline: &Deadline, result: &mut TimingVerificationResult) {
		let deadline_ns = deadline.duration_ns();

		if let Some(observed_ns) = deadline.excess(self.latency_ns) {
			result.passed = false;
			result.deadline_misses.push(DeadlineMiss {
				start_event: deadline.start_event,
				end_event: deadline.end_event,
				deadline_ns,
				observed_ns,
				start_seq: self.start_seq,
				end_seq: self.end_seq,
			});
		}

		let shortfall = deadline.min_slack_ns().zip(deadline.slack_shortfall(self.latency_ns));
		if let Some((required_slack_ns, observed_slack_ns)) = shortfall {
			result.passed = false;
			result.slack_violations.push(TimingSlackViolation {
				start_event: deadline.start_event,
				end_event: deadline.end_event,
				required_slack_ns,
				observed_slack_ns,
				deadline_ns,
				observed_latency_ns: self.latency_ns,
				start_seq: self.start_seq,
				end_seq: self.end_seq,
			});
		}
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;
	use std::time::Duration;

	use super::*;
	use crate::builder::TypeBuilder;
	use crate::instrumentation::events;
	use crate::instrumentation::TbInstrumentationConfig;
	use crate::testing::specs::csp::{Process, ProcessBuildError, State};
	use crate::testing::timing::{DeadlineBuilder, PathWcet, WcetConfig, WcetConfigBuilder};
	use crate::testing::timing::{
		DefaultStatisticalAnalyzer, JitterCalculator, Percentile, StatisticalAnalyzer, StatisticalMeasures,
		VarianceJitter,
	};
	use crate::trace::{TraceCollector, TraceConfig};
	use crate::urn::Urn;
	use crate::TightBeamError;

	// The case types of the table-driven tests.

	/// One case of the WCET constraint table.
	struct WcetTestCase {
		constraint_ms: u64,
		events: Vec<(Urn<'static>, &'static str, u64)>, // (event_urn, label, value_ns)
		expected_passed: bool,
		expected_violations: usize,
	}

	/// One case of the deadline constraint table.
	struct DeadlineTestCase {
		deadline_ms: u64,
		start_event: &'static str,
		end_event: &'static str,
		min_slack_ms: Option<u64>,
		events: Vec<(Urn<'static>, &'static str, u64)>, // (event_urn, label, value_ns)
		expected_passed: bool,
		expected_deadline_misses: usize,
		expected_slack_violations: usize,
	}

	/// One case of the jitter constraint table.
	struct JitterTestCase {
		max_jitter_ms: u64,
		event_label: &'static str,
		events: Vec<(Urn<'static>, &'static str, u64)>, // (event_urn, label, value_ns)
		expected_passed: bool,
		expected_violations: usize,
	}

	// The functions that build the timing events, traces, and verdicts.

	/// Creates a timing event. A deadline marker carries `value_ns` as a
	/// timestamp, and every other timing URN carries it as a duration. The
	/// collector of [`trace_with_events`] numbers it by its place.
	fn timing_event(event_urn: Urn<'static>, label: impl AsRef<str>, value_ns: u64) -> TbEvent {
		let label = label.as_ref();
		let is_deadline = event_urn == events::TIMING_DEADLINE;
		TbEvent {
			seq: 0,
			urn: event_urn,
			label: Some(label.to_string().into()),
			payload_hash: None,
			duration_ns: if is_deadline {
				None
			} else {
				Some(value_ns)
			},
			timestamp_ns: if is_deadline {
				Some(value_ns)
			} else {
				None
			},
			flags: 0,
			extras: None,
		}
	}

	/// The trace that a collector records of `events`, one record of each in
	/// order, so each record takes its place as its sequence number. A record
	/// keeps the duration or the timestamp that its event carries.
	fn trace_with_events(events: impl IntoIterator<Item = TbEvent>) -> ConsumedTrace {
		recorded(true, |collector| {
			for event in events {
				let label = event.label.unwrap_or_default();
				match (event.duration_ns, event.timestamp_ns) {
					(Some(span_ns), _) => collector.emit_with_timing(event.urn, label, Duration::from_nanos(span_ns)),
					(None, Some(at_ns)) => collector.emit_with_timestamp(event.urn, label, Duration::from_nanos(at_ns)),
					(None, None) => collector.emit(event.urn, label),
				}
			}

			Ok(())
		})
	}

	/// Creates an empty trace.
	fn empty_trace() -> ConsumedTrace {
		ConsumedTrace::new()
	}

	/// Builds the timing events of a case, in order.
	fn build_events(events: &[(Urn<'static>, &'static str, u64)]) -> Vec<TbEvent> {
		events
			.iter()
			.map(|(event_urn, label, value_ns)| timing_event(event_urn.clone(), label, *value_ns))
			.collect()
	}

	/// Verifies the events of a case against the constraints that `setup` adds.
	fn verify_constraints<F>(
		setup: F,
		events: &[(Urn<'static>, &'static str, u64)],
	) -> Result<TimingVerificationResult, TestingError>
	where
		F: FnOnce(&mut TimingConstraints) -> Result<(), TestingError>,
	{
		let mut constraints = TimingConstraints::default();
		setup(&mut constraints)?;

		let trace = trace_with_events(build_events(events));
		constraints.verify(&trace)
	}

	impl WcetTestCase {
		/// The verdict of a WCET bound of `constraint_ms` on `process` over the
		/// events of the case.
		fn verified(&self) -> Result<TimingVerificationResult, TestingError> {
			verify_constraints(
				|constraints| {
					let duration = Duration::from_millis(self.constraint_ms);
					let wcet_config = WcetConfigBuilder::default().with_duration(duration).build()?;
					constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config))?;
					Ok(())
				},
				&self.events,
			)
		}
	}

	impl DeadlineTestCase {
		/// The verdict of the deadline of the case over its events.
		fn verified(&self) -> Result<TimingVerificationResult, TestingError> {
			verify_constraints(
				|constraints| {
					let duration = Duration::from_millis(self.deadline_ms);
					let start_event = Event(self.start_event);
					let end_event = Event(self.end_event);
					let mut builder = DeadlineBuilder::default()
						.with_duration(duration)
						.with_start_event(start_event)
						.with_end_event(end_event);

					if let Some(slack_ms) = self.min_slack_ms {
						let min_slack = Duration::from_millis(slack_ms);
						builder = builder.with_min_slack(min_slack);
					}

					constraints.add_deadline(builder.build()?);
					Ok(())
				},
				&self.events,
			)
		}
	}

	impl JitterTestCase {
		/// The verdict of the jitter bound of the case over its events.
		fn verified(&self) -> Result<TimingVerificationResult, TestingError> {
			verify_constraints(
				|constraints| {
					let dur = Duration::from_millis(self.max_jitter_ms);
					constraints.add(Event(self.event_label), TimingConstraint::Jitter(dur, None))?;
					Ok(())
				},
				&self.events,
			)
		}
	}

	// The table-driven tests of each constraint kind.

	// A WCET bound of 100 ms on `process` holds for each sample at or under
	// it, and a timing event of another kind is no WCET sample.
	crate::tb_cases! {
		fn wcet_constraint(case: WcetTestCase) -> Result<(), TestingError> {
			let result = case.verified()?;

			assert_eq!(result.passed, case.expected_passed);
			assert_eq!(result.wcet_violations.len(), case.expected_violations);
			Ok(())
		}

		cases {
			within_the_bound => WcetTestCase {
				constraint_ms: 100,
				events: vec![(events::TIMING_WCET, "process", 50_000_000)],
				expected_passed: true,
				expected_violations: 0,
			},
			past_the_bound => WcetTestCase {
				constraint_ms: 100,
				events: vec![(events::TIMING_WCET, "process", 150_000_000)],
				expected_passed: false,
				expected_violations: 1,
			},
			one_sample_past_the_bound => WcetTestCase {
				constraint_ms: 100,
				events: vec![
					(events::TIMING_WCET, "process", 50_000_000),
					(events::TIMING_WCET, "process", 150_000_000),
					(events::TIMING_WCET, "process", 80_000_000),
				],
				expected_passed: false,
				expected_violations: 1,
			},
			no_sample => WcetTestCase { constraint_ms: 100, events: Vec::new(), expected_passed: true, expected_violations: 0 },
			at_the_bound => WcetTestCase {
				constraint_ms: 100,
				events: vec![(events::TIMING_WCET, "process", 100_000_000)],
				expected_passed: true,
				expected_violations: 0,
			},
			a_deadline_event => WcetTestCase {
				constraint_ms: 100,
				events: vec![(events::TIMING_DEADLINE, "process", 150_000_000)],
				expected_passed: true,
				expected_violations: 0,
			},
		}
	}

	// A deadline of 100 ms from `start` to `end` counts each window past it,
	// and a minimum slack counts each window that ends too close to it.
	crate::tb_cases! {
		fn deadline_constraint(case: DeadlineTestCase) -> Result<(), TestingError> {
			let result = case.verified()?;

			assert_eq!(result.passed, case.expected_passed);
			assert_eq!(result.deadline_misses.len(), case.expected_deadline_misses);
			assert_eq!(result.slack_violations.len(), case.expected_slack_violations);
			Ok(())
		}

		cases {
			end_within_the_deadline => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: None,
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 50_000_000),
				],
				expected_passed: true,
				expected_deadline_misses: 0,
				expected_slack_violations: 0,
			},
			end_past_the_deadline => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: None,
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 150_000_000),
				],
				expected_passed: false,
				expected_deadline_misses: 1,
				expected_slack_violations: 0,
			},
			second_window_past_the_deadline => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: None,
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 50_000_000),
					(events::TIMING_DEADLINE, "start", 200_000_000),
					(events::TIMING_DEADLINE, "end", 350_000_000),
				],
				expected_passed: false,
				expected_deadline_misses: 1,
				expected_slack_violations: 0,
			},
			end_with_no_start => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: None,
				events: vec![(events::TIMING_DEADLINE, "end", 50_000_000)],
				expected_passed: true,
				expected_deadline_misses: 0,
				expected_slack_violations: 0,
			},
			end_at_the_deadline => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: None,
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 100_000_000),
				],
				expected_passed: true,
				expected_deadline_misses: 0,
				expected_slack_violations: 0,
			},
			slack_kept => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: Some(20),
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 50_000_000),
				],
				expected_passed: true,
				expected_deadline_misses: 0,
				expected_slack_violations: 0,
			},
			slack_short => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: Some(20),
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 85_000_000),
				],
				expected_passed: false,
				expected_deadline_misses: 0,
				expected_slack_violations: 1,
			},
			past_the_deadline_and_short_of_slack => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: Some(20),
				events: vec![
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 150_000_000),
				],
				expected_passed: false,
				expected_deadline_misses: 1,
				expected_slack_violations: 1,
			},
		}
	}

	// A jitter bound of 50 ms on `process` counts a spread of samples past it,
	// and one sample has no spread.
	crate::tb_cases! {
		fn jitter_constraint(case: JitterTestCase) -> Result<(), TestingError> {
			let result = case.verified()?;

			assert_eq!(result.passed, case.expected_passed);
			assert_eq!(result.jitter_violations.len(), case.expected_violations);
			Ok(())
		}

		cases {
			spread_within_the_bound => JitterTestCase {
				max_jitter_ms: 50,
				event_label: "process",
				events: vec![
					(events::TIMING_JITTER, "process", 10_000_000),
					(events::TIMING_JITTER, "process", 12_000_000),
					(events::TIMING_JITTER, "process", 11_000_000),
				],
				expected_passed: true,
				expected_violations: 0,
			},
			spread_past_the_bound => JitterTestCase {
				max_jitter_ms: 50,
				event_label: "process",
				events: vec![
					(events::TIMING_JITTER, "process", 10_000_000),
					(events::TIMING_JITTER, "process", 70_000_000),
					(events::TIMING_JITTER, "process", 15_000_000),
				],
				expected_passed: false,
				expected_violations: 1,
			},
			one_sample => JitterTestCase {
				max_jitter_ms: 50,
				event_label: "process",
				events: vec![(events::TIMING_JITTER, "process", 10_000_000)],
				expected_passed: true,
				expected_violations: 0,
			},
		}
	}

	// The tests of a record that cannot decide a bound: a sample with no
	// measure, a truncated record, and a deadline that never ends.

	/// `record` with its duration and its timestamp cleared, as a sink that
	/// records no durations files it.
	fn unmeasured(mut record: TbEvent) -> TbEvent {
		record.duration_ns = None;
		record.timestamp_ns = None;
		record
	}

	/// The constraints of a 100 ms WCET bound on `process`.
	fn wcet_on_process() -> TimingConstraints {
		let wcet = create_wcet_config(100).expect("a WCET with a duration builds");
		let mut constraints = TimingConstraints::default();
		let added = constraints.add(Event("process"), TimingConstraint::Wcet(wcet));
		added.expect("the first constraint on an event is admitted");

		constraints
	}

	/// A measured record of `other`, an event that no constraint names, which
	/// takes sequence number 0 ahead of the record that a test refuses.
	fn a_record_of_another_event() -> TbEvent {
		timing_event(events::TIMING_WCET, "other", 10_000_000)
	}

	#[test]
	fn an_unmeasured_wcet_sample_is_an_error() -> Result<(), TestingError> {
		let constraints = wcet_on_process();
		let sample = unmeasured(timing_event(events::TIMING_WCET, "process", 500_000_000));
		let trace = trace_with_events(vec![a_record_of_another_event(), sample]);

		let verified = constraints.verify(&trace);
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 1 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	#[test]
	fn an_unmeasured_jitter_sample_is_an_error() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		constraints.add(Event("process"), TimingConstraint::Jitter(Duration::from_millis(5), None))?;
		let trace = trace_with_events(vec![
			unmeasured(timing_event(events::TIMING_JITTER, "process", 10_000_000)),
			unmeasured(timing_event(events::TIMING_JITTER, "process", 90_000_000)),
		]);

		let verified = constraints.verify(&trace);

		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 0 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	#[test]
	fn a_deadline_marker_with_no_time_is_an_error() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		constraints.add_deadline(create_deadline(100, "start", "end")?);

		let trace = trace_with_events(vec![
			a_record_of_another_event(),
			unmeasured(timing_event(events::TIMING_DEADLINE, "start", 0)),
			timing_event(events::TIMING_DEADLINE, "end", 50_000_000),
		]);

		let verified = constraints.verify(&trace);
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("start"), seq: 1 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	#[test]
	fn an_incomplete_record_is_an_error() -> Result<(), TestingError> {
		let constraints = wcet_on_process();
		let mut trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "process", 50_000_000),
			timing_event(events::TIMING_WCET, "process", 60_000_000),
		]);
		trace.mark_truncated();

		let verified = constraints.verify(&trace);
		assert!(matches!(verified, Err(TestingError::TimingRecordIncomplete)), "{verified:?}");
		Ok(())
	}

	#[test]
	fn a_deadline_start_with_no_end_is_an_error() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		constraints.add_deadline(create_deadline(100, "start", "end")?);

		let start = timing_event(events::TIMING_DEADLINE, "start", 1_000_000);
		let trace = trace_with_events(vec![a_record_of_another_event(), start]);
		let verified = constraints.verify(&trace);

		let unterminated = matches!(
			verified,
			Err(TestingError::DeadlineUnterminated { start: Event("start"), end: Event("end"), seq: 1 })
		);
		assert!(unterminated, "{verified:?}");
		Ok(())
	}

	// The tests of a run that the collector files under a kind other than
	// `TIMING_WCET`: an event with a value, and an event with no timing.

	/// The empty tag list that each run with a value carries.
	const NO_TAGS: &[&str] = &[];

	/// The trace of the runs that `run` records on a collector, which keeps
	/// their durations only when `record_durations` holds.
	fn recorded(
		record_durations: bool,
		run: impl FnOnce(&TraceCollector) -> Result<(), TightBeamError>,
	) -> ConsumedTrace {
		let config = TbInstrumentationConfig { record_durations, ..Default::default() };
		let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));
		run(&collector).expect("the collector records each run");

		let mut trace = ConsumedTrace::new();
		trace.populate_from_collector(&collector);
		trace
	}

	/// A trace that holds a run of `process` with a value for each duration
	/// in `durations_ms`, which the collector files under `ASSERT_PAYLOAD`.
	fn valued_runs(record_durations: bool, durations_ms: &'static [u64]) -> ConsumedTrace {
		recorded(record_durations, |collector| {
			for (value, duration_ms) in durations_ms.iter().enumerate() {
				let run = collector.event_with(Event("process"), NO_TAGS, value as u64)?;
				run.with_timing(Duration::from_millis(*duration_ms)).emit();
			}
			Ok(())
		})
	}

	/// The constraints of a 5 ms jitter bound on `process`.
	fn jitter_on_process() -> TimingConstraints {
		let mut constraints = TimingConstraints::default();
		let jitter = TimingConstraint::Jitter(Duration::from_millis(5), None);
		let added = constraints.add(Event("process"), jitter);
		added.expect("the first constraint on an event is admitted");

		constraints
	}

	#[test]
	fn a_timed_run_with_a_value_is_a_wcet_sample() -> Result<(), TestingError> {
		let constraints = wcet_on_process();
		let trace = valued_runs(true, &[150]);

		let result = constraints.verify(&trace)?;
		let violation =
			TimingViolation { event: Event("process"), wcet_ns: 100_000_000, observed_ns: 150_000_000, seq: 0 };
		assert_eq!(result.wcet_violations, [violation]);
		Ok(())
	}

	#[test]
	fn an_unmeasured_run_with_a_value_is_an_error_under_a_wcet_bound() -> Result<(), TestingError> {
		let constraints = wcet_on_process();
		let trace = valued_runs(false, &[150]);

		let verified = constraints.verify(&trace);
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 0 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	#[test]
	fn an_unmeasured_run_with_a_value_is_an_error_under_a_jitter_bound() -> Result<(), TestingError> {
		let constraints = jitter_on_process();
		let trace = valued_runs(false, &[10, 90]);

		let verified = constraints.verify(&trace);
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 0 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	#[test]
	fn an_untimed_run_of_a_bounded_event_is_an_error() -> Result<(), TestingError> {
		let constraints = wcet_on_process();
		let trace = recorded(true, |collector| {
			collector.event(Event("process"))?.emit();
			Ok(())
		});

		let verified = constraints.verify(&trace);
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 0 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	// The tests of WCET, jitter, and deadline constraints together.

	/// Creates a WCET configuration of `ms` milliseconds.
	fn create_wcet_config(ms: u64) -> Result<WcetConfig, TestingError> {
		let duration = Duration::from_millis(ms);
		WcetConfigBuilder::default().with_duration(duration).build()
	}

	/// Creates a deadline of `ms` milliseconds from `start` to `end`.
	fn create_deadline(ms: u64, start: &'static str, end: &'static str) -> Result<Deadline, TestingError> {
		let duration = Duration::from_millis(ms);
		let start_event = Event(start);
		let end_event = Event(end);

		DeadlineBuilder::default()
			.with_duration(duration)
			.with_start_event(start_event)
			.with_end_event(end_event)
			.build()
	}

	/// Adds a 100 ms WCET bound on `process`, a 50 ms jitter bound on
	/// `request`, and a 200 ms deadline from `start` to `end`.
	fn setup_combined_constraints(constraints: &mut TimingConstraints) -> Result<(), TestingError> {
		constraints.add(Event("process"), TimingConstraint::Wcet(create_wcet_config(100)?))?;
		constraints.add(Event("request"), TimingConstraint::Jitter(Duration::from_millis(50), None))?;
		constraints.add_deadline(create_deadline(200, "start", "end")?);
		Ok(())
	}

	#[test]
	fn test_combined_constraints_all_passed() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		setup_combined_constraints(&mut constraints)?;

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "process", 50_000_000),
			timing_event(events::TIMING_JITTER, "request", 10_000_000),
			timing_event(events::TIMING_JITTER, "request", 12_000_000),
			timing_event(events::TIMING_DEADLINE, "start", 0),
			timing_event(events::TIMING_DEADLINE, "end", 100_000_000),
		]);

		let result = constraints.verify(&trace)?;
		assert!(result.passed);
		assert!(result.wcet_violations.is_empty());
		assert!(result.jitter_violations.is_empty());
		assert!(result.deadline_misses.is_empty());
		Ok(())
	}

	#[test]
	fn test_combined_constraints_multiple_violations() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		setup_combined_constraints(&mut constraints)?;

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "process", 150_000_000), // WCET violation
			timing_event(events::TIMING_JITTER, "request", 10_000_000),
			timing_event(events::TIMING_JITTER, "request", 70_000_000), // Jitter violation
			timing_event(events::TIMING_DEADLINE, "start", 0),
			timing_event(events::TIMING_DEADLINE, "end", 250_000_000), // Deadline violation
		]);

		let result = constraints.verify(&trace)?;
		assert!(!result.passed);
		assert_eq!(result.wcet_violations.len(), 1);
		assert_eq!(result.jitter_violations.len(), 1);
		assert_eq!(result.deadline_misses.len(), 1);
		Ok(())
	}

	// The edge cases: no constraint, no event, and a custom jitter calculator.

	#[test]
	fn test_empty_constraints() -> Result<(), TestingError> {
		let constraints = TimingConstraints::default();
		let event = timing_event(events::TIMING_WCET, "process", 50_000_000);
		let trace = trace_with_events(vec![event]);

		let result = constraints.verify(&trace)?;
		assert!(result.passed);
		Ok(())
	}

	#[test]
	fn test_empty_trace() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		constraints.add(Event("process"), TimingConstraint::Wcet(create_wcet_config(100)?))?;

		let trace = empty_trace();
		let result = constraints.verify(&trace)?;
		assert!(result.passed); // An event that never ran holds its bound.
		Ok(())
	}

	#[test]
	fn test_jitter_with_custom_calculator() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let dur = Duration::from_millis(100);
		let calc = Arc::new(VarianceJitter);
		constraints.add(Event("process"), TimingConstraint::Jitter(dur, Some(calc)))?;

		// The durations [10ms, 20ms, 15ms] feed the variance-based jitter.
		let trace = trace_with_events(vec![
			timing_event(events::TIMING_JITTER, "process", 10_000_000),
			timing_event(events::TIMING_JITTER, "process", 20_000_000),
			timing_event(events::TIMING_JITTER, "process", 15_000_000),
		]);

		// The result depends on the variance calculation, so the test checks
		// that the verification returns and reports at most one violation.
		let result = constraints.verify(&trace)?;
		assert!(result.jitter_violations.len() <= 1);
		Ok(())
	}

	// The tests of a constraint that its analyzer or calculator cannot check.
	// The house analyzer and calculators accept each sample set the verifier
	// passes, so each failure comes from an outside implementation.

	/// An outside analyzer whose analysis fails on every sample set.
	#[derive(Debug)]
	struct FailingAnalyzer;

	impl StatisticalAnalyzer for FailingAnalyzer {
		fn analyze(&self, _durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError> {
			Err(TightBeamError::InvalidMetadata)
		}
	}

	/// An outside analyzer that gives the median alone.
	#[derive(Debug)]
	struct MedianAnalyzer;

	impl StatisticalAnalyzer for MedianAnalyzer {
		fn analyze(&self, durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError> {
			let mut measures = DefaultStatisticalAnalyzer.analyze(durations)?;
			measures.percentiles.retain(|value| value.percentile == Percentile::P50);
			Ok(measures)
		}
	}

	/// An outside jitter calculator whose calculation fails on any sample set.
	#[derive(Debug)]
	struct FailingCalculator;

	impl JitterCalculator for FailingCalculator {
		fn calculate(&self, _durations: &[u64]) -> Result<u64, TightBeamError> {
			Err(TightBeamError::InvalidMetadata)
		}
	}

	/// The constraints of a P99 WCET bound of 100 ms on `process`, under
	/// `analyzer`.
	fn p99_wcet_under(analyzer: impl StatisticalAnalyzer + 'static) -> TimingConstraints {
		let wcet = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(100))
			.with_percentile(Percentile::P99)
			.with_analyzer(analyzer)
			.build()
			.expect("a WCET with a duration and a percentile builds");
		let mut constraints = TimingConstraints::default();
		let added = constraints.add(Event("process"), TimingConstraint::Wcet(wcet));
		added.expect("the first constraint on an event is admitted");
		constraints
	}

	#[test]
	fn a_failed_wcet_analysis_is_an_error() -> Result<(), TestingError> {
		let constraints = p99_wcet_under(FailingAnalyzer);
		let trace = trace_with_events(vec![timing_event(events::TIMING_WCET, "process", 50_000_000)]);

		let verified = constraints.verify(&trace);
		let failed = matches!(verified, Err(TestingError::WcetAnalysisFailed { event: Event("process"), .. }));
		assert!(failed, "{verified:?}");
		Ok(())
	}

	#[test]
	fn a_wcet_analysis_with_no_value_for_the_percentile_is_an_error() -> Result<(), TestingError> {
		let constraints = p99_wcet_under(MedianAnalyzer);
		let trace = trace_with_events(vec![timing_event(events::TIMING_WCET, "process", 50_000_000)]);

		let verified = constraints.verify(&trace);
		let missing = matches!(
			verified,
			Err(TestingError::WcetPercentileMissing { event: Event("process"), percentile: Percentile::P99 })
		);
		assert!(missing, "{verified:?}");
		Ok(())
	}

	#[test]
	fn a_failed_jitter_calculation_is_an_error() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let max_jitter = Duration::from_millis(50);
		let calculator: Arc<dyn JitterCalculator> = Arc::new(FailingCalculator);
		constraints.add(Event("process"), TimingConstraint::Jitter(max_jitter, Some(calculator)))?;

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_JITTER, "process", 10_000_000),
			timing_event(events::TIMING_JITTER, "process", 12_000_000),
		]);

		let verified = constraints.verify(&trace);
		let failed = matches!(
			verified,
			Err(TestingError::JitterCalculationFailed { event: Event("process"), .. })
		);
		assert!(failed, "{verified:?}");
		Ok(())
	}

	/// An outside analyzer whose percentiles are twice those of
	/// [`DefaultStatisticalAnalyzer`], like a model that extrapolates past the
	/// samples.
	#[derive(Debug)]
	struct DoublingAnalyzer;

	impl StatisticalAnalyzer for DoublingAnalyzer {
		fn analyze(&self, durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError> {
			let mut measures = DefaultStatisticalAnalyzer.analyze(durations)?;
			for value in &mut measures.percentiles {
				value.value = value.value.saturating_mul(2);
			}
			Ok(measures)
		}
	}

	// The P99 of one 80 ms sample under the doubling model is 160 ms, past
	// the 100 ms bound, so the result fails with that measure.
	#[test]
	fn an_exceeded_percentile_fails_the_result_with_its_measure() -> Result<(), TestingError> {
		let constraints = p99_wcet_under(DoublingAnalyzer);
		let trace = trace_with_events(vec![timing_event(events::TIMING_WCET, "process", 80_000_000)]);

		let result = constraints.verify(&trace)?;
		let violation =
			TimingViolation { event: Event("process"), wcet_ns: 100_000_000, observed_ns: 160_000_000, seq: 0 };
		assert!(!result.passed);
		assert_eq!(result.wcet_violations, [violation]);
		Ok(())
	}

	// The tests of path WCET constraints.

	/// Creates a test process that takes `start`, then `process`, then `end`.
	fn create_path_test_process() -> Result<Process, ProcessBuildError> {
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

	/// Creates a path WCET constraint of `max_duration_ms` on the path of
	/// `start`, `process`, and `end`.
	fn create_test_path_wcet(max_duration_ms: u64) -> PathWcet {
		PathWcet::new(
			vec![Event("start"), Event("process"), Event("end")],
			Duration::from_millis(max_duration_ms),
		)
	}

	/// One case of the path WCET table.
	struct PathWcetTestCase {
		start_duration_ns: u64,
		process_duration_ns: u64,
		end_duration_ns: u64,
		max_duration_ms: u64,
		expected_passed: bool,
		/// The observed and the maximum path duration of each violation, in
		/// nanoseconds.
		expected_violations: &'static [(u64, u64)],
	}

	impl PathWcetTestCase {
		/// The verdict of a path WCET bound of `max_duration_ms` over the
		/// `start`, `process`, and `end` samples of the case.
		fn verified(&self) -> Result<TimingVerificationResult, Box<dyn core::error::Error>> {
			let process = create_path_test_process()?;
			let mut constraints = TimingConstraints::default();
			constraints.add_path_wcet(create_test_path_wcet(self.max_duration_ms));

			let trace = trace_with_events(vec![
				timing_event(events::TIMING_WCET, "start", self.start_duration_ns),
				timing_event(events::TIMING_WCET, "process", self.process_duration_ns),
				timing_event(events::TIMING_WCET, "end", self.end_duration_ns),
			]);

			let result = constraints.verify_with_process(&trace, Some(&process))?;
			Ok(result)
		}
	}

	// A path bound of 50 ms holds for the sum of the three samples of the path.
	crate::tb_cases! {
		fn path_wcet_constraint(case: PathWcetTestCase) -> Result<(), Box<dyn core::error::Error>> {
			let result = case.verified()?;

			let violations: Vec<(u64, u64)> = result
				.path_wcet_violations
				.iter()
				.map(|violation| (violation.observed_path_duration_ns, violation.max_path_duration_ns))
				.collect();
			assert_eq!(result.passed, case.expected_passed);
			assert_eq!(violations, case.expected_violations);
			Ok(())
		}

		cases {
			// Total: 10ms + 20ms + 5ms = 35ms < 50ms (pass)
			within_the_bound => PathWcetTestCase {
				start_duration_ns: 10_000_000,
				process_duration_ns: 20_000_000,
				end_duration_ns: 5_000_000,
				max_duration_ms: 50,
				expected_passed: true,
				expected_violations: &[],
			},
			// Total: 10ms + 30ms + 15ms = 55ms > 50ms (violation)
			past_the_bound => PathWcetTestCase {
				start_duration_ns: 10_000_000,
				process_duration_ns: 30_000_000,
				end_duration_ns: 15_000_000,
				max_duration_ms: 50,
				expected_passed: false,
				expected_violations: &[(55_000_000, 50_000_000)],
			},
		}
	}

	#[test]
	fn an_unmeasured_path_sample_is_an_error() -> Result<(), Box<dyn core::error::Error>> {
		let process = create_path_test_process()?;
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000),
			unmeasured(timing_event(events::TIMING_WCET, "process", 60_000_000)),
			timing_event(events::TIMING_WCET, "end", 5_000_000),
		]);

		let verified = constraints.verify_with_process(&trace, Some(&process));
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 1 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	// The bound on `start` then `process` reads those two runs, 30 ms in
	// all, and not the `end` run that the execution path holds after them.
	#[test]
	fn a_path_bound_reads_the_duration_of_its_own_events() -> Result<(), Box<dyn core::error::Error>> {
		let process = create_path_test_process()?;
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(PathWcet::new([Event("start"), Event("process")], Duration::from_millis(50)));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000),
			timing_event(events::TIMING_WCET, "process", 20_000_000),
			timing_event(events::TIMING_WCET, "end", 30_000_000),
		]);

		let result = constraints.verify_with_process(&trace, Some(&process))?;
		assert!(result.passed, "{result:?}");
		Ok(())
	}

	/// The durations of the path WCET violations of `result`, in nanoseconds.
	fn observed_path_durations(result: &TimingVerificationResult) -> Vec<u64> {
		let violations = result.path_wcet_violations.iter();
		violations.map(|violation| violation.observed_path_duration_ns).collect()
	}

	// The run of `process` carries a value, so the collector files it under
	// `ASSERT_PAYLOAD`. The path holds it: 10 + 60 + 5 = 75 ms.
	#[test]
	fn a_run_with_a_value_lies_on_its_path() -> Result<(), Box<dyn core::error::Error>> {
		let process = create_path_test_process()?;
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = recorded(true, |collector| {
			collector.event(Event("start"))?.with_timing(Duration::from_millis(10)).emit();
			let valued = collector.event_with(Event("process"), NO_TAGS, 7u64)?;
			valued.with_timing(Duration::from_millis(60)).emit();
			collector.event(Event("end"))?.with_timing(Duration::from_millis(5)).emit();
			Ok(())
		});

		let result = constraints.verify_with_process(&trace, Some(&process))?;
		assert_eq!(observed_path_durations(&result), [75_000_000]);
		Ok(())
	}

	#[test]
	fn an_unmeasured_run_with_a_value_on_a_path_is_an_error() -> Result<(), Box<dyn core::error::Error>> {
		let process = create_path_test_process()?;
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000),
			unmeasured(timing_event(events::ASSERT_PAYLOAD, "process", 60_000_000)),
			timing_event(events::TIMING_WCET, "end", 5_000_000),
		]);

		let verified = constraints.verify_with_process(&trace, Some(&process));
		let refused = matches!(
			verified,
			Err(TestingError::TimingSampleUnmeasured { event: Event("process"), seq: 1 })
		);
		assert!(refused, "{verified:?}");
		Ok(())
	}

	// The `start` of the second run is not enabled where the first run ends,
	// so it starts the second path, which takes 30 + 30 + 30 = 90 ms.
	#[test]
	fn a_run_that_breaks_a_path_starts_the_next() -> Result<(), Box<dyn core::error::Error>> {
		let process = create_path_test_process()?;
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000),
			timing_event(events::TIMING_WCET, "process", 10_000_000),
			timing_event(events::TIMING_WCET, "end", 10_000_000),
			timing_event(events::TIMING_WCET, "start", 30_000_000),
			timing_event(events::TIMING_WCET, "process", 30_000_000),
			timing_event(events::TIMING_WCET, "end", 30_000_000),
		]);

		let result = constraints.verify_with_process(&trace, Some(&process))?;
		assert_eq!(observed_path_durations(&result), [90_000_000]);
		Ok(())
	}

	#[test]
	fn test_path_wcet_no_process() -> Result<(), TestingError> {
		// A verification without a process leaves the path WCET constraints
		// unchecked.
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000),
			timing_event(events::TIMING_WCET, "process", 30_000_000),
			timing_event(events::TIMING_WCET, "end", 15_000_000),
		]);

		let result = constraints.verify(&trace)?;
		assert!(result.passed);
		assert!(result.path_wcet_violations.is_empty());
		Ok(())
	}
}
