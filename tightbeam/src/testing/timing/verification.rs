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
	use crate::instrumentation::TbInstrumentationConfig;
	use crate::testing::fixtures::{TestProcess, TestTrace};
	use crate::testing::timing::{
		DeadlineBuilder, DefaultStatisticalAnalyzer, JitterCalculator, PathWcet, Percentile, StatisticalAnalyzer,
		StatisticalMeasures, VarianceJitter, WcetConfig, WcetConfigBuilder,
	};
	use crate::testing::TestResult;
	use crate::trace::TraceCollector;
	use crate::urn::Urn;
	use crate::TightBeamError;

	/// One timed record of a trace: its kind, its label, and its measure in
	/// nanoseconds.
	type Timed = (Urn<'static>, &'static str, u64);

	/// What a check of a trace returns.
	type Verified = Result<TimingVerificationResult, TestingError>;

	// The constraints that the tests check.

	/// The constraints that hold `constraint` on `process` alone.
	fn on_process(constraint: TimingConstraint) -> TimingConstraints {
		let mut constraints = TimingConstraints::default();
		let added = constraints.add(Event("process"), constraint);
		added.expect("the first constraint on an event is admitted");

		constraints
	}

	/// The constraints of a 100 ms WCET bound on `process`.
	fn wcet_on_process() -> TimingConstraints {
		on_process(TimingConstraint::Wcet(WcetConfig::of_millis(100)))
	}

	/// The constraints of a jitter bound of `millis` milliseconds on
	/// `process`, under `calculator`, or under the house calculator for
	/// `None`.
	fn jitter_on_process(millis: u64, calculator: Option<Arc<dyn JitterCalculator>>) -> TimingConstraints {
		on_process(TimingConstraint::Jitter(Duration::from_millis(millis), calculator))
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
		on_process(TimingConstraint::Wcet(wcet))
	}

	/// The constraints that hold `deadline` alone.
	fn with_deadline(deadline: Deadline) -> TimingConstraints {
		let mut constraints = TimingConstraints::default();
		constraints.add_deadline(deadline);
		constraints
	}

	/// The deadline of 100 ms from `start` to `end`, built with a minimum
	/// slack of `slack_ms` milliseconds when it is `Some`.
	fn hundred_ms_deadline(slack_ms: Option<u64>) -> Deadline {
		let builder = DeadlineBuilder::default().with_duration(Duration::from_millis(100));
		let builder = builder.with_start_event(Event("start")).with_end_event(Event("end"));
		let builder = match slack_ms {
			Some(millis) => builder.with_min_slack(Duration::from_millis(millis)),
			None => builder,
		};

		builder.build().expect("a slack within its duration builds")
	}

	/// The constraints of a path bound of `millis` milliseconds on the path of
	/// `start`, `process`, and `end`.
	fn path_within(millis: u64) -> TimingConstraints {
		let path = [Event("start"), Event("process"), Event("end")];
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(PathWcet::new(path, Duration::from_millis(millis)));

		constraints
	}

	/// The constraints of a 100 ms WCET bound on `process`, a 50 ms jitter
	/// bound on `request`, and a 200 ms deadline from `start` to `end`.
	fn combined() -> TimingConstraints {
		let mut constraints = with_deadline(Deadline::of_millis(200, "start", "end"));
		let wcet = constraints.add(Event("process"), TimingConstraint::Wcet(WcetConfig::of_millis(100)));
		wcet.expect("the first constraint on an event is admitted");

		let jitter = constraints.add(Event("request"), TimingConstraint::Jitter(Duration::from_millis(50), None));
		jitter.expect("the first constraint on an event is admitted");

		constraints
	}

	/// The result of a check that finds each bound kept.
	fn kept() -> TimingVerificationResult {
		TimingVerificationResult { passed: true, ..Default::default() }
	}

	// The traces that the tests check.

	/// The empty tag list that each run with a value carries.
	const NO_TAGS: &[&str] = &[];

	/// The trace of the runs that `run` records on a collector, which keeps
	/// their durations only when `record_durations` holds.
	fn recorded(
		record_durations: bool,
		run: impl FnOnce(&TraceCollector) -> Result<(), TightBeamError>,
	) -> ConsumedTrace {
		let config = TbInstrumentationConfig { record_durations, ..Default::default() };
		let collector = TestTrace::with_config(config);
		run(&collector).expect("the collector records each run");
		ConsumedTrace::drained_from(&collector)
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

	/// A trace that holds one run of `process` with no timing.
	fn an_untimed_run() -> ConsumedTrace {
		recorded(true, |collector| {
			collector.event(Event("process"))?.emit();
			Ok(())
		})
	}

	/// A trace of two measured runs of `process` whose sink dropped records.
	fn a_truncated_record() -> ConsumedTrace {
		let mut trace = ConsumedTrace::timed(&[
			(events::TIMING_WCET, "process", 50_000_000),
			(events::TIMING_WCET, "process", 60_000_000),
		]);
		trace.mark_truncated();
		trace
	}

	/// A trace of the `start`, `process`, and `end` runs of 10, 60, and 5 ms,
	/// in which the run of `process` carries a value, so the collector files
	/// it under `ASSERT_PAYLOAD`.
	fn a_valued_run_on_the_path() -> ConsumedTrace {
		recorded(true, |collector| {
			collector.event(Event("start"))?.with_timing(Duration::from_millis(10)).emit();
			let valued = collector.event_with(Event("process"), NO_TAGS, 7u64)?;
			valued.with_timing(Duration::from_millis(60)).emit();
			collector.event(Event("end"))?.with_timing(Duration::from_millis(5)).emit();
			Ok(())
		})
	}

	// The doubles of the checks that an outside analyzer or calculator fails.

	/// An outside analyzer whose analysis fails on every sample set. The house
	/// analyzer accepts each sample set that the check passes it, so a failed
	/// analysis needs an outside one.
	#[derive(Debug)]
	struct FailingAnalyzer;

	impl StatisticalAnalyzer for FailingAnalyzer {
		fn analyze(&self, _durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError> {
			Err(TightBeamError::InvalidMetadata)
		}
	}

	/// An outside analyzer that gives the median alone. The house analyzer
	/// gives every percentile, so a missing percentile needs an outside one.
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
	/// The house calculators accept each sample set that the check passes
	/// them, so a failed calculation needs an outside one.
	#[derive(Debug)]
	struct FailingCalculator;

	impl JitterCalculator for FailingCalculator {
		fn calculate(&self, _durations: &[u64]) -> Result<u64, TightBeamError> {
			Err(TightBeamError::InvalidMetadata)
		}
	}

	/// An outside analyzer whose percentiles are twice those of
	/// [`DefaultStatisticalAnalyzer`], like a model that extrapolates past the
	/// samples. The house analyzer reads a percentile from the samples, so a
	/// measure past every sample needs an outside one.
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

	// The table-driven tests of each constraint kind.

	// A WCET bound of 100 ms on `process` holds for each sample at or under
	// it, and a timing event of another kind is no WCET sample.
	crate::tb_cases! {
		fn wcet_constraint((records, passed, violations): (&[Timed], bool, usize)) -> TestResult {
			let trace = ConsumedTrace::timed(records);
			let result = wcet_on_process().verify(&trace)?;
			assert_eq!((result.passed, result.wcet_violations.len()), (passed, violations));
			Ok(())
		}

		cases {
			within_the_bound => (&[(events::TIMING_WCET, "process", 50_000_000)], true, 0),
			past_the_bound => (&[(events::TIMING_WCET, "process", 150_000_000)], false, 1),
			one_sample_past_the_bound => (
				&[
					(events::TIMING_WCET, "process", 50_000_000),
					(events::TIMING_WCET, "process", 150_000_000),
					(events::TIMING_WCET, "process", 80_000_000),
				],
				false,
				1,
			),
			no_sample => (&[], true, 0),
			at_the_bound => (&[(events::TIMING_WCET, "process", 100_000_000)], true, 0),
			a_deadline_event => (&[(events::TIMING_DEADLINE, "process", 150_000_000)], true, 0),
		}
	}

	/// One case of the deadline table.
	struct DeadlineCase<'a> {
		/// The minimum slack of the deadline in milliseconds, if any.
		min_slack_ms: Option<u64>,
		/// The deadline markers of the trace.
		records: &'a [Timed],
		/// Whether the trace keeps the deadline.
		passed: bool,
		/// The count of the windows that pass the deadline.
		misses: usize,
		/// The count of the windows that end too close to the deadline.
		slack_violations: usize,
	}

	// A deadline of 100 ms from `start` to `end` counts each window past it,
	// and a minimum slack counts each window that ends too close to it.
	crate::tb_cases! {
		fn deadline_constraint(case: DeadlineCase<'_>) -> TestResult {
			let constraints = with_deadline(hundred_ms_deadline(case.min_slack_ms));
			let trace = ConsumedTrace::timed(case.records);

			let result = constraints.verify(&trace)?;
			let verdict = (result.passed, result.deadline_misses.len(), result.slack_violations.len());
			assert_eq!(verdict, (case.passed, case.misses, case.slack_violations));
			Ok(())
		}

		cases {
			end_within_the_deadline => DeadlineCase {
				min_slack_ms: None,
				records: &[(events::TIMING_DEADLINE, "start", 0), (events::TIMING_DEADLINE, "end", 50_000_000)],
				passed: true,
				misses: 0,
				slack_violations: 0,
			},
			end_past_the_deadline => DeadlineCase {
				min_slack_ms: None,
				records: &[(events::TIMING_DEADLINE, "start", 0), (events::TIMING_DEADLINE, "end", 150_000_000)],
				passed: false,
				misses: 1,
				slack_violations: 0,
			},
			second_window_past_the_deadline => DeadlineCase {
				min_slack_ms: None,
				records: &[
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 50_000_000),
					(events::TIMING_DEADLINE, "start", 200_000_000),
					(events::TIMING_DEADLINE, "end", 350_000_000),
				],
				passed: false,
				misses: 1,
				slack_violations: 0,
			},
			end_with_no_start => DeadlineCase {
				min_slack_ms: None,
				records: &[(events::TIMING_DEADLINE, "end", 50_000_000)],
				passed: true,
				misses: 0,
				slack_violations: 0,
			},
			end_at_the_deadline => DeadlineCase {
				min_slack_ms: None,
				records: &[(events::TIMING_DEADLINE, "start", 0), (events::TIMING_DEADLINE, "end", 100_000_000)],
				passed: true,
				misses: 0,
				slack_violations: 0,
			},
			slack_kept => DeadlineCase {
				min_slack_ms: Some(20),
				records: &[(events::TIMING_DEADLINE, "start", 0), (events::TIMING_DEADLINE, "end", 50_000_000)],
				passed: true,
				misses: 0,
				slack_violations: 0,
			},
			slack_short => DeadlineCase {
				min_slack_ms: Some(20),
				records: &[(events::TIMING_DEADLINE, "start", 0), (events::TIMING_DEADLINE, "end", 85_000_000)],
				passed: false,
				misses: 0,
				slack_violations: 1,
			},
			past_the_deadline_and_short_of_slack => DeadlineCase {
				min_slack_ms: Some(20),
				records: &[(events::TIMING_DEADLINE, "start", 0), (events::TIMING_DEADLINE, "end", 150_000_000)],
				passed: false,
				misses: 1,
				slack_violations: 1,
			},
		}
	}

	// A jitter bound of 50 ms on `process` counts a spread of samples past it,
	// and one sample has no spread.
	crate::tb_cases! {
		fn jitter_constraint((records, passed, violations): (&[Timed], bool, usize)) -> TestResult {
			let trace = ConsumedTrace::timed(records);

			let result = jitter_on_process(50, None).verify(&trace)?;
			assert_eq!((result.passed, result.jitter_violations.len()), (passed, violations));
			Ok(())
		}

		cases {
			spread_within_the_bound => (
				&[
					(events::TIMING_JITTER, "process", 10_000_000),
					(events::TIMING_JITTER, "process", 12_000_000),
					(events::TIMING_JITTER, "process", 11_000_000),
				],
				true,
				0,
			),
			spread_past_the_bound => (
				&[
					(events::TIMING_JITTER, "process", 10_000_000),
					(events::TIMING_JITTER, "process", 70_000_000),
					(events::TIMING_JITTER, "process", 15_000_000),
				],
				false,
				1,
			),
			one_sample => (&[(events::TIMING_JITTER, "process", 10_000_000)], true, 0),
		}
	}

	/// One check of a trace against its constraints.
	struct Check {
		/// The constraints of the check.
		constraints: fn() -> TimingConstraints,
		/// The process whose paths the check reads, or `None` for a check of
		/// the event bounds alone.
		process: Option<Process>,
		/// The trace of the check.
		trace: fn() -> ConsumedTrace,
	}

	// A check refuses a sample with no measure, and names its event and its
	// sequence number. A run of an event with a value and a run with no
	// timing are samples of the bounds on that event.
	crate::tb_cases! {
		fn an_unmeasured_sample_is_an_error((check, (event, seq)): (Check, (&str, u64))) {
			let constraints = (check.constraints)();
			let trace = (check.trace)();

			let verified = constraints.verify_with_process(&trace, check.process.as_ref());
			let refused = (Event(event), seq);
			assert!(matches!(
				verified,
				Err(TestingError::TimingSampleUnmeasured { event: unmeasured, seq: at }) if (unmeasured, at) == refused
			));
		}

		cases {
			under_a_wcet_bound => (
				Check {
					constraints: wcet_on_process,
					process: None,
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_WCET, "other", Some(10_000_000)),
							(events::TIMING_WCET, "process", None),
						])
					},
				},
				("process", 1),
			),
			under_a_jitter_bound => (
				Check {
					constraints: || jitter_on_process(5, None),
					process: None,
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_JITTER, "process", None),
							(events::TIMING_JITTER, "process", None),
						])
					},
				},
				("process", 0),
			),
			of_a_deadline_marker => (
				Check {
					constraints: || with_deadline(Deadline::of_millis(100, "start", "end")),
					process: None,
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_WCET, "other", Some(10_000_000)),
							(events::TIMING_DEADLINE, "start", None),
							(events::TIMING_DEADLINE, "end", Some(50_000_000)),
						])
					},
				},
				("start", 1),
			),
			of_a_run_with_a_value_under_a_wcet_bound => (
				Check { constraints: wcet_on_process, process: None, trace: || valued_runs(false, &[150]) },
				("process", 0),
			),
			of_a_run_with_a_value_under_a_jitter_bound => (
				Check {
					constraints: || jitter_on_process(5, None),
					process: None,
					trace: || valued_runs(false, &[10, 90]),
				},
				("process", 0),
			),
			of_an_untimed_run_of_a_bounded_event => (
				Check { constraints: wcet_on_process, process: None, trace: an_untimed_run },
				("process", 0),
			),
			on_a_path => (
				Check {
					constraints: || path_within(50),
					process: Some(TestProcess::start_process_end()),
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_WCET, "start", Some(10_000_000)),
							(events::TIMING_WCET, "process", None),
							(events::TIMING_WCET, "end", Some(5_000_000)),
						])
					},
				},
				("process", 1),
			),
			of_a_run_with_a_value_on_a_path => (
				Check {
					constraints: || path_within(50),
					process: Some(TestProcess::start_process_end()),
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_WCET, "start", Some(10_000_000)),
							(events::ASSERT_PAYLOAD, "process", None),
							(events::TIMING_WCET, "end", Some(5_000_000)),
						])
					},
				},
				("process", 1),
			),
		}
	}

	// A check refuses a truncated record, a deadline that never ends, and a
	// bound whose outside analyzer or calculator fails.
	crate::tb_cases! {
		fn the_check_refuses((check, refused): (Check, fn(&Verified) -> bool)) {
			let constraints = (check.constraints)();
			let trace = (check.trace)();

			let verified = constraints.verify_with_process(&trace, check.process.as_ref());
			assert!(refused(&verified));
		}

		cases {
			an_incomplete_record => (
				Check { constraints: wcet_on_process, process: None, trace: a_truncated_record },
				|verified| matches!(verified, Err(TestingError::TimingRecordIncomplete)),
			),
			a_deadline_start_with_no_end => (
				Check {
					constraints: || with_deadline(Deadline::of_millis(100, "start", "end")),
					process: None,
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_WCET, "other", 10_000_000),
							(events::TIMING_DEADLINE, "start", 1_000_000),
						])
					},
				},
				|verified| {
					matches!(
						verified,
						Err(TestingError::DeadlineUnterminated { start: Event("start"), end: Event("end"), seq: 1 })
					)
				},
			),
			a_failed_wcet_analysis => (
				Check {
					constraints: || p99_wcet_under(FailingAnalyzer),
					process: None,
					trace: || ConsumedTrace::timed(&[(events::TIMING_WCET, "process", 50_000_000)]),
				},
				|verified| {
					matches!(
						verified,
						Err(TestingError::WcetAnalysisFailed { event: Event("process"), cause })
							if matches!(**cause, TightBeamError::InvalidMetadata)
					)
				},
			),
			a_wcet_analysis_with_no_value_for_the_percentile => (
				Check {
					constraints: || p99_wcet_under(MedianAnalyzer),
					process: None,
					trace: || ConsumedTrace::timed(&[(events::TIMING_WCET, "process", 50_000_000)]),
				},
				|verified| {
					matches!(
						verified,
						Err(TestingError::WcetPercentileMissing {
							event: Event("process"),
							percentile: Percentile::P99,
						})
					)
				},
			),
			a_failed_jitter_calculation => (
				Check {
					constraints: || jitter_on_process(50, Some(Arc::new(FailingCalculator))),
					process: None,
					trace: || {
						ConsumedTrace::timed(&[
							(events::TIMING_JITTER, "process", 10_000_000),
							(events::TIMING_JITTER, "process", 12_000_000),
						])
					},
				},
				|verified| {
					matches!(
						verified,
						Err(TestingError::JitterCalculationFailed { event: Event("process"), cause })
							if matches!(**cause, TightBeamError::InvalidMetadata)
					)
				},
			),
		}
	}

	/// A timed run of `process` with a value is a sample of the WCET bound on
	/// `process`.
	#[test]
	fn a_timed_run_with_a_value_is_a_wcet_sample() -> TestResult {
		let trace = valued_runs(true, &[150]);
		let result = wcet_on_process().verify(&trace)?;
		let violation =
			TimingViolation { event: Event("process"), wcet_ns: 100_000_000, observed_ns: 150_000_000, seq: 0 };

		let failed = TimingVerificationResult { passed: false, wcet_violations: vec![violation], ..kept() };
		assert_eq!(result, failed);
		Ok(())
	}

	// A WCET bound on `process`, a jitter bound on `request`, and a deadline
	// from `start` to `end` each read their own records of one trace.
	crate::tb_cases! {
		fn three_kinds_of_bound_check_one_trace((records, result): (&[Timed], TimingVerificationResult)) -> TestResult {
			let trace = ConsumedTrace::timed(records);
			let verified = combined().verify(&trace)?;
			assert_eq!(verified, result);
			Ok(())
		}

		cases {
			within_each_bound => (
				&[
					(events::TIMING_WCET, "process", 50_000_000),
					(events::TIMING_JITTER, "request", 10_000_000),
					(events::TIMING_JITTER, "request", 12_000_000),
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 100_000_000),
				],
				kept(),
			),
			/// The run of `process` takes 150 ms, the house calculator spreads
			/// the runs of `request` over 60 ms, and `end` comes 250 ms after
			/// `start`.
			past_each_bound => (
				&[
					(events::TIMING_WCET, "process", 150_000_000),
					(events::TIMING_JITTER, "request", 10_000_000),
					(events::TIMING_JITTER, "request", 70_000_000),
					(events::TIMING_DEADLINE, "start", 0),
					(events::TIMING_DEADLINE, "end", 250_000_000),
				],
				TimingVerificationResult {
					passed: false,
					wcet_violations: vec![TimingViolation {
						event: Event("process"),
						wcet_ns: 100_000_000,
						observed_ns: 150_000_000,
						seq: 0,
					}],
					jitter_violations: vec![JitterViolation {
						event: Event("request"),
						max_jitter_ns: 50_000_000,
						observed_jitter_ns: 60_000_000,
						seqs: vec![1, 2],
					}],
					deadline_misses: vec![DeadlineMiss {
						start_event: Event("start"),
						end_event: Event("end"),
						deadline_ns: 200_000_000,
						observed_ns: 250_000_000,
						start_seq: 3,
						end_seq: 4,
					}],
					..kept()
				},
			),
		}
	}

	// A check with nothing to bound keeps each bound: no constraint, no sample
	// of the bounded event, and a path bound with no process to read the path
	// from.
	crate::tb_cases! {
		fn a_check_with_nothing_to_bound_passes(
			(constraints, records): (fn() -> TimingConstraints, &[Timed])
		) -> TestResult {
			let trace = ConsumedTrace::timed(records);
			let result = constraints().verify(&trace)?;
			assert_eq!(result, kept());
			Ok(())
		}

		cases {
			no_constraint => (TimingConstraints::default, &[(events::TIMING_WCET, "process", 50_000_000)]),
			no_sample => (wcet_on_process, &[]),
			a_path_bound_with_no_process => (
				|| path_within(50),
				&[
					(events::TIMING_WCET, "start", 10_000_000),
					(events::TIMING_WCET, "process", 30_000_000),
					(events::TIMING_WCET, "end", 15_000_000),
				],
			),
		}
	}

	/// A custom calculator measures the jitter of a bound. The variance of 10,
	/// 20, and 15 ms about their mean of 15 ms is (25 + 25 + 0) / 3 ms², which
	/// is 16,666,666,666,666 ns² in whole units, past the bound of
	/// 100,000,000.
	#[test]
	fn a_custom_calculator_measures_the_jitter_of_a_bound() -> TestResult {
		let constraints = jitter_on_process(100, Some(Arc::new(VarianceJitter)));
		let trace = ConsumedTrace::timed(&[
			(events::TIMING_JITTER, "process", 10_000_000),
			(events::TIMING_JITTER, "process", 20_000_000),
			(events::TIMING_JITTER, "process", 15_000_000),
		]);

		let result = constraints.verify(&trace)?;
		let violation = JitterViolation {
			event: Event("process"),
			max_jitter_ns: 100_000_000,
			observed_jitter_ns: 16_666_666_666_666,
			seqs: vec![0, 1, 2],
		};
		assert_eq!(result.jitter_violations, [violation]);
		Ok(())
	}

	/// An exceeded percentile fails the result with its measure. The P99 of
	/// one 80 ms sample under the doubling model is 160 ms, past the 100 ms
	/// bound.
	#[test]
	fn an_exceeded_percentile_fails_the_result_with_its_measure() -> TestResult {
		let constraints = p99_wcet_under(DoublingAnalyzer);
		let trace = ConsumedTrace::timed(&[(events::TIMING_WCET, "process", 80_000_000)]);
		let result = constraints.verify(&trace)?;
		let violation =
			TimingViolation { event: Event("process"), wcet_ns: 100_000_000, observed_ns: 160_000_000, seq: 0 };

		let failed = TimingVerificationResult { passed: false, wcet_violations: vec![violation], ..kept() };
		assert_eq!(result, failed);
		Ok(())
	}

	// The tests of path WCET constraints.

	// A path bound of 50 ms holds for the sum of the three samples of the path.
	crate::tb_cases! {
		fn path_wcet_constraint((records, result): (&[Timed], TimingVerificationResult)) -> TestResult {
			let process = TestProcess::start_process_end();
			let trace = ConsumedTrace::timed(records);

			let verified = path_within(50).verify_with_process(&trace, Some(&process))?;
			assert_eq!(verified, result);
			Ok(())
		}

		cases {
			// Total: 10ms + 20ms + 5ms = 35ms < 50ms (pass)
			within_the_bound => (
				&[
					(events::TIMING_WCET, "start", 10_000_000),
					(events::TIMING_WCET, "process", 20_000_000),
					(events::TIMING_WCET, "end", 5_000_000),
				],
				kept(),
			),
			// Total: 10ms + 30ms + 15ms = 55ms > 50ms (violation)
			past_the_bound => (
				&[
					(events::TIMING_WCET, "start", 10_000_000),
					(events::TIMING_WCET, "process", 30_000_000),
					(events::TIMING_WCET, "end", 15_000_000),
				],
				TimingVerificationResult {
					passed: false,
					path_wcet_violations: vec![PathWcetViolation {
						path: vec![Event("start"), Event("process"), Event("end")],
						max_path_duration_ns: 50_000_000,
						observed_path_duration_ns: 55_000_000,
						seqs: vec![0, 1, 2],
					}],
					..kept()
				},
			),
		}
	}

	/// A path bound reads the duration of its own events. The bound on
	/// `start` then `process` reads those two runs, 30 ms in all, and not the
	/// `end` run that the execution path holds after them.
	#[test]
	fn a_path_bound_reads_the_duration_of_its_own_events() -> TestResult {
		let process = TestProcess::start_process_end();
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(PathWcet::new([Event("start"), Event("process")], Duration::from_millis(50)));
		let trace = ConsumedTrace::timed(&[
			(events::TIMING_WCET, "start", 10_000_000),
			(events::TIMING_WCET, "process", 20_000_000),
			(events::TIMING_WCET, "end", 30_000_000),
		]);

		let result = constraints.verify_with_process(&trace, Some(&process))?;
		assert_eq!(result, kept());
		Ok(())
	}

	// A path bound of 50 ms measures the path of each run of `start`,
	// `process`, and `end`: 10 + 60 + 5 = 75 ms with a run of `process` that
	// carries a value, and 30 + 30 + 30 = 90 ms for a second run whose `start`
	// the end of the first run does not enable, so it starts the next path.
	crate::tb_cases! {
		fn a_path_bound_measures_the_path_of_each_run(
			(trace, durations): (fn() -> ConsumedTrace, &[u64])
		) -> TestResult {
			let process = TestProcess::start_process_end();
			let result = path_within(50).verify_with_process(&trace(), Some(&process))?;

			let violations = result.path_wcet_violations.iter();
			let observed: Vec<u64> = violations.map(|violation| violation.observed_path_duration_ns).collect();
			assert_eq!(observed, durations);
			Ok(())
		}

		cases {
			with_a_run_that_carries_a_value => (a_valued_run_on_the_path, &[75_000_000]),
			after_a_run_that_breaks_the_path => (
				|| {
					ConsumedTrace::timed(&[
						(events::TIMING_WCET, "start", 10_000_000),
						(events::TIMING_WCET, "process", 10_000_000),
						(events::TIMING_WCET, "end", 10_000_000),
						(events::TIMING_WCET, "start", 30_000_000),
						(events::TIMING_WCET, "process", 30_000_000),
						(events::TIMING_WCET, "end", 30_000_000),
					])
				},
				&[90_000_000],
			),
		}
	}
}
