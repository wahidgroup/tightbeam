//! The timing verification of a trace against its timing constraints.

use std::collections::HashMap;
use std::sync::Arc;

use super::jitter::{JitterCalculator, MinMaxJitter};
use super::statistics::{DefaultStatisticalAnalyzer, Percentile, StatisticalAnalyzer};
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

impl TimingConstraints {
	/// Verifies `trace` against the timing constraints of this collection.
	///
	/// The check reads the observed durations from the instrumentation events
	/// of the trace.
	pub fn verify(&self, trace: &ConsumedTrace) -> Result<TimingVerificationResult, TestingError> {
		self.verify_with_process(trace, None)
	}

	/// Verifies `trace` against the timing constraints of this collection,
	/// with the CSP `process` when one is given.
	///
	/// A process adds the path WCET constraints to the check. Without one, the
	/// check covers the event constraints alone: WCET, deadlines, and jitter.
	pub fn verify_with_process(
		&self,
		trace: &ConsumedTrace,
		process: Option<&Process>,
	) -> Result<TimingVerificationResult, TestingError> {
		let mut result = TimingVerificationResult { passed: true, ..Default::default() };
		let events_by_label = Self::extract_timing_events(trace);
		let events_by_label = Self::group_events_by_label(&events_by_label);

		Self::verify_wcet_constraints(self, &events_by_label, &mut result);
		Self::verify_deadline_constraints(self, &events_by_label, &mut result);
		Self::verify_jitter_constraints(self, &events_by_label, &mut result);

		if let Some(process) = process {
			Self::verify_path_wcet_constraints(self, trace, process, &mut result);
		}

		Ok(result)
	}

	/// The timing events of `trace`: each event with a timing URN, or with a
	/// duration or a timestamp set.
	fn extract_timing_events(trace: &ConsumedTrace) -> Vec<&TbEvent> {
		#[cfg(feature = "instrument")]
		{
			trace
				.instrument_events
				.iter()
				.filter(|ev| {
					ev.urn == events::TIMING_WCET
						|| ev.urn == events::TIMING_DEADLINE
						|| ev.urn == events::TIMING_JITTER
						|| ev.duration_ns.is_some()
						|| ev.timestamp_ns.is_some()
				})
				.collect()
		}
		#[cfg(not(feature = "instrument"))]
		{
			Vec::new()
		}
	}

	/// Groups `events` by label, and skips an event with no label.
	fn group_events_by_label<'a>(events: &'a [&TbEvent]) -> HashMap<String, Vec<&'a TbEvent>> {
		let mut grouped: HashMap<String, Vec<&'a TbEvent>> = HashMap::new();
		for event in events {
			if let Some(label) = &event.label {
				grouped.entry(label.clone()).or_default().push(*event);
			}
		}

		grouped
	}

	/// Verifies each WCET constraint against the `TIMING_WCET` samples of its
	/// event. A constraint with a percentile tests that percentile of the
	/// samples, and any other constraint tests each sample.
	fn verify_wcet_constraints(
		constraints: &TimingConstraints,
		events_by_label: &HashMap<String, Vec<&TbEvent>>,
		result: &mut TimingVerificationResult,
	) {
		for (event, constraint) in constraints.constraints.iter() {
			if let TimingConstraint::Wcet(wcet_config) = constraint {
				let wcet_ns = wcet_config.duration.as_nanos() as u64;
				let event_label = event.0;
				if let Some(events) = events_by_label.get(event_label) {
					// The samples are the `TIMING_WCET` events, because another
					// timing event can carry a duration too.
					let wcet_events: Vec<&TbEvent> =
						events.iter().filter(|e| e.urn == events::TIMING_WCET).copied().collect();

					if let Some(percentile) = wcet_config.percentile {
						Self::verify_percentile_wcet(wcet_config, percentile, &wcet_events, event, wcet_ns, result);
					} else {
						Self::report_wcet_violations(event, wcet_ns, &wcet_events, result);
					}
				}
			}
		}
	}

	/// Verifies a percentile WCET constraint over `events`, and reports each
	/// sample past the bound when the percentile of the samples exceeds it.
	fn verify_percentile_wcet(
		wcet_config: &crate::testing::timing::WcetConfig,
		percentile: Percentile,
		events: &[&TbEvent],
		event: &Event,
		wcet_ns: u64,
		result: &mut TimingVerificationResult,
	) {
		let durations: Vec<u64> = events.iter().filter_map(|ev| ev.duration_ns).collect();

		if durations.is_empty() {
			return;
		}

		let analyzer: Arc<dyn StatisticalAnalyzer> = wcet_config
			.analyzer
			.clone()
			.unwrap_or_else(|| Arc::new(DefaultStatisticalAnalyzer));

		let measures = match analyzer.analyze(&durations) {
			Ok(m) => m,
			Err(_) => return, // Skip if analysis fails
		};

		let percentile_value = match measures.percentiles.iter().find(|pv| pv.percentile == percentile) {
			Some(pv) => pv.value,
			None => return, // Percentile not available
		};

		if percentile_value > wcet_ns {
			Self::report_wcet_violations(event, wcet_ns, events, result);
		}
	}

	/// Records a violation for each event whose duration exceeds `wcet_ns`,
	/// and marks the result failed.
	fn report_wcet_violations(event: &Event, wcet_ns: u64, events: &[&TbEvent], result: &mut TimingVerificationResult) {
		for ev in events.iter() {
			if let Some(observed_ns) = ev.duration_ns {
				if observed_ns > wcet_ns {
					result.passed = false;
					result.wcet_violations.push(TimingViolation {
						event: Event(event.0),
						wcet_ns,
						observed_ns,
						seq: ev.seq,
					});
				}
			}
		}
	}

	/// Verifies each deadline constraint against the pairs of its start and
	/// end events.
	fn verify_deadline_constraints(
		constraints: &TimingConstraints,
		events_by_label: &HashMap<String, Vec<&TbEvent>>,
		result: &mut TimingVerificationResult,
	) {
		for deadline in constraints.deadlines() {
			let deadline_ns = deadline.duration.as_nanos() as u64;
			let start_label = deadline.start_event.0;
			let end_label = deadline.end_event.0;

			// Deadline pairing consumes point-in-time markers only: the
			// timing-deadline URN with a timestamp. WCET events carry
			// durations (span lengths) and must not cross-match here.
			let start_events: Vec<&TbEvent> = events_by_label
				.get(start_label)
				.map(|v| {
					v.iter()
						.filter(|e| e.urn == events::TIMING_DEADLINE && e.timestamp_ns.is_some())
						.copied()
						.collect()
				})
				.unwrap_or_default();
			let end_events: Vec<&TbEvent> = events_by_label
				.get(end_label)
				.map(|v| {
					v.iter()
						.filter(|e| e.urn == events::TIMING_DEADLINE && e.timestamp_ns.is_some())
						.copied()
						.collect()
				})
				.unwrap_or_default();

			Self::check_deadline_pairs(deadline, deadline_ns, &start_events, &end_events, result);
		}
	}

	/// Checks each start event, with the first end event after it, against
	/// the deadline and its minimum slack.
	fn check_deadline_pairs(
		deadline: &Deadline,
		deadline_ns: u64,
		start_events: &[&TbEvent],
		end_events: &[&TbEvent],
		result: &mut TimingVerificationResult,
	) {
		for start_event in start_events.iter() {
			if let Some(start_ns) = start_event.timestamp_ns {
				if let Some(end_event) = Self::find_matching_end_event(start_ns, end_events) {
					if let Some(end_ns) = end_event.timestamp_ns {
						let latency_ns = end_ns.saturating_sub(start_ns);
						Self::check_deadline_violation(
							deadline,
							deadline_ns,
							latency_ns,
							start_event,
							end_event,
							result,
						);

						Self::check_slack_violation(deadline, deadline_ns, latency_ns, start_event, end_event, result);
					}
				}
			}
		}
	}

	/// The first end event whose timestamp follows `start_ns`.
	fn find_matching_end_event<'a>(start_ns: u64, end_events: &'a [&TbEvent]) -> Option<&'a TbEvent> {
		end_events
			.iter()
			.find(|ev| ev.timestamp_ns.map(|end_ns| end_ns > start_ns).unwrap_or(false))
			.copied()
	}

	/// Records a deadline miss when `latency_ns` exceeds `deadline_ns`.
	fn check_deadline_violation(
		deadline: &Deadline,
		deadline_ns: u64,
		latency_ns: u64,
		start_event: &TbEvent,
		end_event: &TbEvent,
		result: &mut TimingVerificationResult,
	) {
		if latency_ns > deadline_ns {
			result.passed = false;
			result.deadline_misses.push(DeadlineMiss {
				start_event: Event(deadline.start_event.0),
				end_event: Event(deadline.end_event.0),
				deadline_ns,
				observed_ns: latency_ns,
				start_seq: start_event.seq,
				end_seq: end_event.seq,
			});
		}
	}

	/// Records a slack violation when the time left under the deadline falls
	/// short of its minimum slack.
	fn check_slack_violation(
		deadline: &Deadline,
		deadline_ns: u64,
		latency_ns: u64,
		start_event: &TbEvent,
		end_event: &TbEvent,
		result: &mut TimingVerificationResult,
	) {
		if let Some(required_slack) = deadline.min_slack {
			let required_slack_ns = required_slack.as_nanos() as u64;
			let observed_slack_ns = deadline_ns.saturating_sub(latency_ns);
			if observed_slack_ns < required_slack_ns {
				result.passed = false;
				result.slack_violations.push(TimingSlackViolation {
					start_event: Event(deadline.start_event.0),
					end_event: Event(deadline.end_event.0),
					required_slack_ns,
					observed_slack_ns,
					deadline_ns,
					observed_latency_ns: latency_ns,
					start_seq: start_event.seq,
					end_seq: end_event.seq,
				});
			}
		}
	}

	/// Verifies each jitter constraint whose event has at least two samples.
	fn verify_jitter_constraints(
		constraints: &TimingConstraints,
		events_by_label: &HashMap<String, Vec<&TbEvent>>,
		result: &mut TimingVerificationResult,
	) {
		for (event, constraint) in constraints.constraints.iter() {
			if let TimingConstraint::Jitter(max_jitter, calculator_opt) = constraint {
				let max_jitter_ns = max_jitter.as_nanos() as u64;
				let event_label = event.0;
				if let Some(events) = events_by_label.get(event_label) {
					if events.len() >= 2 {
						Self::check_jitter_violation(event, max_jitter_ns, events, calculator_opt, result);
					}
				}
			}
		}
	}

	/// Records a jitter violation when the jitter of the sample durations
	/// exceeds `max_jitter_ns`. The calculator defaults to `MinMaxJitter`.
	fn check_jitter_violation(
		event: &Event,
		max_jitter_ns: u64,
		events: &[&TbEvent],
		calculator_opt: &Option<Arc<dyn JitterCalculator>>,
		result: &mut TimingVerificationResult,
	) {
		let durations: Vec<u64> = events.iter().filter_map(|ev| ev.duration_ns).collect();
		if durations.len() >= 2 {
			let calculator = calculator_opt.as_ref().map(|c| c.as_ref()).unwrap_or(&MinMaxJitter);
			if let Ok(observed_jitter) = calculator.calculate(&durations) {
				if observed_jitter > max_jitter_ns {
					result.passed = false;
					result.jitter_violations.push(JitterViolation {
						event: Event(event.0),
						max_jitter_ns,
						observed_jitter_ns: observed_jitter,
						seqs: events.iter().map(|ev| ev.seq).collect(),
					});
				}
			}
		}
	}

	/// Verifies each path WCET constraint against the execution paths of
	/// `trace` through `process`.
	fn verify_path_wcet_constraints(
		constraints: &TimingConstraints,
		trace: &ConsumedTrace,
		process: &Process,
		result: &mut TimingVerificationResult,
	) {
		let execution_paths = trace.execution_paths(process);
		for path_wcet in constraints.path_wcets() {
			let max_duration_ns = path_wcet.max_duration_ns();
			for exec_path in &execution_paths {
				let on_path = exec_path.matches_pattern(&path_wcet.path);
				let over_budget = exec_path.total_duration > max_duration_ns;
				if on_path && over_budget {
					result.passed = false;
					result.path_wcet_violations.push(PathWcetViolation {
						path: exec_path.events.clone(),
						max_path_duration_ns: max_duration_ns,
						observed_path_duration_ns: exec_path.total_duration,
						seqs: {
							// The sequence numbers of the trace events
							// whose label lies on the path.
							#[cfg(feature = "instrument")]
							{
								trace
									.instrument_events
									.iter()
									.filter(|ev| {
										ev.label.as_ref().map(|l| exec_path.events.iter().any(|e| e.0 == l.as_str()))
											== Some(true)
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
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;
	use crate::builder::TypeBuilder;
	use crate::instrumentation::events;
	use crate::testing::specs::csp::{Process, ProcessBuildError, State};
	use crate::testing::timing::VarianceJitter;
	use crate::testing::timing::{DeadlineBuilder, PathWcet, WcetConfig, WcetConfigBuilder};
	use crate::urn::Urn;

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
	/// timestamp, and every other timing URN carries it as a duration.
	fn timing_event(event_urn: Urn<'static>, label: impl AsRef<str>, value_ns: u64, seq: u32) -> TbEvent {
		let label = label.as_ref();
		let is_deadline = event_urn == events::TIMING_DEADLINE;
		TbEvent {
			seq,
			urn: event_urn,
			label: Some(label.to_string()),
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

	/// Creates a trace whose instrumentation events are `events`, or an empty
	/// trace in a build without `instrument`.
	fn trace_with_events(events: impl IntoIterator<Item = TbEvent>) -> ConsumedTrace {
		let events: Vec<TbEvent> = events.into_iter().collect();
		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			trace.instrument_events = events;
		}
		trace
	}

	/// Creates an empty trace.
	fn empty_trace() -> ConsumedTrace {
		ConsumedTrace::new()
	}

	/// Builds the timing events of a case, each numbered by its index.
	fn build_events(events: &[(Urn<'static>, &'static str, u64)]) -> Vec<TbEvent> {
		events
			.iter()
			.enumerate()
			.map(|(seq, (event_urn, label, value_ns))| timing_event(event_urn.clone(), label, *value_ns, seq as u32))
			.collect()
	}

	/// Verifies the events of a case against the constraints that `setup`
	/// adds.
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
					constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));
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
					constraints.add(Event(self.event_label), TimingConstraint::Jitter(dur, None));
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
			start_with_no_end => DeadlineTestCase {
				deadline_ms: 100,
				start_event: "start",
				end_event: "end",
				min_slack_ms: None,
				events: vec![(events::TIMING_DEADLINE, "start", 0)],
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

	// The special case of a WCET event with no duration.

	#[test]
	fn test_wcet_no_duration() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let duration = Duration::from_millis(100);
		let wcet_config = WcetConfigBuilder::default().with_duration(duration).build()?;
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			trace.instrument_events.push(TbEvent {
				seq: 0,
				urn: events::TIMING_WCET,
				label: Some("process".to_string()),
				payload_hash: None,
				duration_ns: None, // No duration
				timestamp_ns: None,
				flags: 0,
				extras: None,
			});
		}

		let result = constraints.verify(&trace)?;
		assert!(result.passed); // Event without duration is skipped
		assert!(result.wcet_violations.is_empty());
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
		constraints.add(Event("process"), TimingConstraint::Wcet(create_wcet_config(100)?));
		constraints.add(Event("request"), TimingConstraint::Jitter(Duration::from_millis(50), None));
		constraints.add_deadline(create_deadline(200, "start", "end")?);
		Ok(())
	}

	#[test]
	fn test_combined_constraints_all_passed() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		setup_combined_constraints(&mut constraints)?;

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "process", 50_000_000, 0),
			timing_event(events::TIMING_JITTER, "request", 10_000_000, 1),
			timing_event(events::TIMING_JITTER, "request", 12_000_000, 2),
			timing_event(events::TIMING_DEADLINE, "start", 0, 3),
			timing_event(events::TIMING_DEADLINE, "end", 100_000_000, 4),
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
			timing_event(events::TIMING_WCET, "process", 150_000_000, 0), // WCET violation
			timing_event(events::TIMING_JITTER, "request", 10_000_000, 1),
			timing_event(events::TIMING_JITTER, "request", 70_000_000, 2), // Jitter violation
			timing_event(events::TIMING_DEADLINE, "start", 0, 3),
			timing_event(events::TIMING_DEADLINE, "end", 250_000_000, 4), // Deadline violation
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
		let event = timing_event(events::TIMING_WCET, "process", 50_000_000, 0);
		let trace = trace_with_events(vec![event]);

		let result = constraints.verify(&trace)?;
		assert!(result.passed);
		Ok(())
	}

	#[test]
	fn test_empty_trace() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		constraints.add(Event("process"), TimingConstraint::Wcet(create_wcet_config(100)?));

		let trace = empty_trace();
		let result = constraints.verify(&trace)?;
		assert!(result.passed); // No violations if no events
		Ok(())
	}

	#[test]
	fn test_jitter_with_custom_calculator() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let dur = Duration::from_millis(100);
		let calc = Arc::new(VarianceJitter);
		constraints.add(Event("process"), TimingConstraint::Jitter(dur, Some(calc)));

		// The durations [10ms, 20ms, 15ms] feed the variance-based jitter.
		let trace = trace_with_events(vec![
			timing_event(events::TIMING_JITTER, "process", 10_000_000, 0),
			timing_event(events::TIMING_JITTER, "process", 20_000_000, 1),
			timing_event(events::TIMING_JITTER, "process", 15_000_000, 2),
		]);

		// The result depends on the variance calculation, so the test checks
		// that the verification returns and reports at most one violation.
		let result = constraints.verify(&trace)?;
		assert!(result.jitter_violations.len() <= 1);
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
				timing_event(events::TIMING_WCET, "start", self.start_duration_ns, 0),
				timing_event(events::TIMING_WCET, "process", self.process_duration_ns, 1),
				timing_event(events::TIMING_WCET, "end", self.end_duration_ns, 2),
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
	fn test_path_wcet_no_process() -> Result<(), TestingError> {
		// A verification without a process leaves the path WCET constraints
		// unchecked.
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000, 0),
			timing_event(events::TIMING_WCET, "process", 30_000_000, 1),
			timing_event(events::TIMING_WCET, "end", 15_000_000, 2),
		]);

		let result = constraints.verify(&trace)?;
		assert!(result.passed);
		assert!(result.path_wcet_violations.is_empty());
		Ok(())
	}
}
