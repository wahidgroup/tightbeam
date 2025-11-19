//! Timing verification logic

use std::collections::HashMap;
use std::sync::Arc;

use super::constraints::{TimingConstraint, TimingConstraints};
use super::deadline::Deadline;
use super::path::extract_paths;
use super::violations::{DeadlineMiss, JitterViolation, PathWcetViolation, TimingSlackViolation, TimingViolation};
use crate::der::Sequence;
use crate::instrumentation::{events, TbEvent};
use crate::testing::error::TestingError;
use crate::testing::specs::csp::{Event, Process};
use crate::trace::ConsumedTrace;
use crate::utils::jitter::{JitterCalculator, MinMaxJitter};
use crate::utils::statistics::{DefaultStatisticalAnalyzer, Percentile, StatisticalAnalyzer};

/// Timing verification result
#[derive(Debug, Default, Clone, PartialEq, Eq, Sequence)]
pub struct TimingVerificationResult {
	/// Whether all timing constraints were satisfied
	pub passed: bool,
	/// WCET violations found
	pub wcet_violations: Vec<TimingViolation>,
	/// Deadline misses found
	pub deadline_misses: Vec<DeadlineMiss>,
	/// Jitter violations found
	pub jitter_violations: Vec<JitterViolation>,
	/// Slack violations found
	pub slack_violations: Vec<TimingSlackViolation>,
	/// Path WCET violations found
	pub path_wcet_violations: Vec<PathWcetViolation>,
}

impl TimingConstraints {
	/// Verify timing constraints against trace
	///
	/// Checks observed durations from instrumentation events against timing
	/// constraints defined in this collection.
	pub fn verify(&self, trace: &ConsumedTrace) -> Result<TimingVerificationResult, TestingError> {
		self.verify_with_process(trace, None)
	}

	/// Verify timing constraints against trace with optional CSP process
	///
	/// If a process is provided, path-based WCET constraints are also verified.
	/// Otherwise, only event-based constraints (WCET, deadlines, jitter) are checked.
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

		// Verify path-based WCET if process is provided
		if let Some(process) = process {
			Self::verify_path_wcet_constraints(self, trace, process, &mut result);
		}

		Ok(result)
	}

	/// Extract timing events from trace
	/// Looks for events with duration_ns set (timing information)
	fn extract_timing_events(trace: &ConsumedTrace) -> Vec<&TbEvent> {
		#[cfg(feature = "instrument")]
		{
			trace
				.instrument_events
				.iter()
				.filter(|ev| {
					// Include events with timing URNs or any event with duration_ns set
					ev.urn == events::TIMING_WCET
						|| ev.urn == events::TIMING_DEADLINE
						|| ev.urn == events::TIMING_JITTER
						|| ev.duration_ns.is_some()
				})
				.collect()
		}
		#[cfg(not(feature = "instrument"))]
		{
			Vec::new()
		}
	}

	/// Group events by label for efficient lookup
	fn group_events_by_label<'a>(events: &'a [&TbEvent]) -> HashMap<String, Vec<&'a TbEvent>> {
		let mut grouped: HashMap<String, Vec<&'a TbEvent>> = HashMap::new();
		for event in events {
			if let Some(label) = &event.label {
				grouped.entry(label.clone()).or_default().push(*event);
			}
		}

		grouped
	}

	/// Verify WCET constraints
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
					// Filter for timing-wcet URN only
					// Events with duration but different URNs
					let wcet_events: Vec<&TbEvent> =
						events.iter().filter(|e| e.urn == events::TIMING_WCET).copied().collect();

					// If percentile is specified, use statistical analysis
					if let Some(percentile) = wcet_config.percentile {
						Self::verify_percentile_wcet(wcet_config, percentile, &wcet_events, event, wcet_ns, result);
					} else {
						// Standard max-based WCET verification
						Self::report_wcet_violations(event, wcet_ns, &wcet_events, result);
					}
				}
			}
		}
	}

	/// Verify percentile-based WCET constraints
	fn verify_percentile_wcet(
		wcet_config: &crate::testing::timing::WcetConfig,
		percentile: Percentile,
		events: &[&TbEvent],
		event: &Event,
		wcet_ns: u64,
		result: &mut TimingVerificationResult,
	) {
		// Extract durations from events
		let durations: Vec<u64> = events.iter().filter_map(|ev| ev.duration_ns).collect();

		if durations.is_empty() {
			return;
		}

		// Use configured analyzer or default
		let analyzer: Arc<dyn StatisticalAnalyzer> = wcet_config
			.analyzer
			.clone()
			.unwrap_or_else(|| Arc::new(DefaultStatisticalAnalyzer));

		// Perform statistical analysis
		let measures = match analyzer.analyze(&durations) {
			Ok(m) => m,
			Err(_) => return, // Skip if analysis fails
		};

		// Get percentile value
		let percentile_value = match measures.percentiles.iter().find(|pv| pv.percentile == percentile) {
			Some(pv) => pv.value,
			None => return, // Percentile not available
		};

		// Check if percentile value exceeds WCET
		if percentile_value > wcet_ns {
			// Report violation for all events that exceeded WCET
			Self::report_wcet_violations(event, wcet_ns, events, result);
		}
	}

	/// Report WCET violations for events that exceed the WCET threshold
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

	/// Verify deadline constraints (explicit start/end event pairs)
	fn verify_deadline_constraints(
		constraints: &TimingConstraints,
		events_by_label: &HashMap<String, Vec<&TbEvent>>,
		result: &mut TimingVerificationResult,
	) {
		for deadline in constraints.deadlines() {
			let deadline_ns = deadline.duration.as_nanos() as u64;
			let start_label = deadline.start_event.0;
			let end_label = deadline.end_event.0;

			// Filter for timing-deadline URN or any event with duration_ns
			let start_events: Vec<&TbEvent> = events_by_label
				.get(start_label)
				.map(|v| {
					v.iter()
						.filter(|e| e.urn == events::TIMING_DEADLINE || e.duration_ns.is_some())
						.copied()
						.collect()
				})
				.unwrap_or_default();
			let end_events: Vec<&TbEvent> = events_by_label
				.get(end_label)
				.map(|v| {
					v.iter()
						.filter(|e| e.urn == events::TIMING_DEADLINE || e.duration_ns.is_some())
						.copied()
						.collect()
				})
				.unwrap_or_default();

			Self::check_deadline_pairs(deadline, deadline_ns, &start_events, &end_events, result);
		}
	}

	/// Check deadline pairs and slack constraints
	fn check_deadline_pairs(
		deadline: &Deadline,
		deadline_ns: u64,
		start_events: &[&TbEvent],
		end_events: &[&TbEvent],
		result: &mut TimingVerificationResult,
	) {
		for start_event in start_events.iter() {
			if let Some(start_ns) = start_event.duration_ns {
				if let Some(end_event) = Self::find_matching_end_event(start_ns, end_events) {
					if let Some(end_ns) = end_event.duration_ns {
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

	/// Find the next end event after a start event
	fn find_matching_end_event<'a>(start_ns: u64, end_events: &'a [&TbEvent]) -> Option<&'a TbEvent> {
		end_events
			.iter()
			.find(|ev| ev.duration_ns.map(|end_ns| end_ns > start_ns).unwrap_or(false))
			.copied()
	}

	/// Check if deadline was violated
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

	/// Check if slack constraint was violated
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

	/// Verify jitter constraints
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

	/// Check if jitter constraint was violated
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

	/// Verify path-based WCET constraints
	fn verify_path_wcet_constraints(
		constraints: &TimingConstraints,
		trace: &ConsumedTrace,
		process: &Process,
		result: &mut TimingVerificationResult,
	) {
		// Extract execution paths from trace
		// For each path-based WCET constraint
		let execution_paths = extract_paths(trace, process);
		for path_wcet in constraints.path_wcets() {
			// Find matching execution paths
			let max_duration_ns = path_wcet.max_duration_ns();
			for exec_path in &execution_paths {
				if exec_path.matches_pattern(&path_wcet.path) {
					// Check if path duration exceeds constraint
					if exec_path.total_duration > max_duration_ns {
						result.passed = false;
						result.path_wcet_violations.push(PathWcetViolation {
							path: exec_path.events.clone(),
							max_path_duration_ns: max_duration_ns,
							observed_path_duration_ns: exec_path.total_duration,
							seqs: {
								// Extract sequence numbers from trace events
								#[cfg(feature = "instrument")]
								{
									trace
										.instrument_events
										.iter()
										.filter(|ev| {
											ev.label
												.as_ref()
												.map(|l| exec_path.events.iter().any(|e| e.0 == l.as_str()))
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
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;
	use crate::builder::TypeBuilder;
	use crate::instrumentation::events;
	use crate::testing::specs::csp::{Process, State};
	use crate::testing::timing::{DeadlineBuilder, PathWcet, WcetConfig, WcetConfigBuilder};
	use crate::utils::jitter::VarianceJitter;
	use crate::utils::urn::Urn;

	// ========================================================================
	// Test Case Data Structures
	// ========================================================================

	/// Test case for WCET constraint verification
	struct WcetTestCase {
		constraint_ms: u64,
		events: &'static [(Urn<'static>, &'static str, u64)], // (event_urn, label, duration_ns)
		expected_passed: bool,
		expected_violations: usize,
	}

	/// Test case for deadline constraint verification
	struct DeadlineTestCase {
		deadline_ms: u64,
		start_event: &'static str,
		end_event: &'static str,
		min_slack_ms: Option<u64>,
		events: &'static [(Urn<'static>, &'static str, u64)], // (event_urn, label, duration_ns)
		expected_passed: bool,
		expected_deadline_misses: usize,
		expected_slack_violations: usize,
	}

	/// Test case for jitter constraint verification
	struct JitterTestCase {
		max_jitter_ms: u64,
		event_label: &'static str,
		events: &'static [(Urn<'static>, &'static str, u64)], // (event_urn, label, duration_ns)
		expected_passed: bool,
		expected_violations: usize,
	}

	// ========================================================================
	// Test Case Data
	// ========================================================================

	const WCET_TEST_CASES: &[WcetTestCase] = &[
		WcetTestCase {
			constraint_ms: 100,
			events: &[(events::TIMING_WCET, "process", 50_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
		WcetTestCase {
			constraint_ms: 100,
			events: &[(events::TIMING_WCET, "process", 150_000_000)],
			expected_passed: false,
			expected_violations: 1,
		},
		WcetTestCase {
			constraint_ms: 100,
			events: &[
				(events::TIMING_WCET, "process", 50_000_000),
				(events::TIMING_WCET, "process", 150_000_000),
				(events::TIMING_WCET, "process", 80_000_000),
			],
			expected_passed: false,
			expected_violations: 1,
		},
		WcetTestCase { constraint_ms: 100, events: &[], expected_passed: true, expected_violations: 0 },
		WcetTestCase {
			constraint_ms: 100,
			events: &[(events::TIMING_WCET, "process", 100_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
		WcetTestCase {
			constraint_ms: 100,
			events: &[(events::TIMING_DEADLINE, "process", 150_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
	];

	const DEADLINE_TEST_CASES: &[DeadlineTestCase] = &[
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 50_000_000),
			],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 150_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 1,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 50_000_000),
				(events::TIMING_DEADLINE, "start", 200_000_000),
				(events::TIMING_DEADLINE, "end", 350_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 1,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[(events::TIMING_DEADLINE, "end", 50_000_000)],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[(events::TIMING_DEADLINE, "start", 0)],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 100_000_000),
			],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: Some(20),
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 50_000_000),
			],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: Some(20),
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 85_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 0,
			expected_slack_violations: 1,
		},
		DeadlineTestCase {
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: Some(20),
			events: &[
				(events::TIMING_DEADLINE, "start", 0),
				(events::TIMING_DEADLINE, "end", 150_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 1,
			expected_slack_violations: 1,
		},
	];

	const JITTER_TEST_CASES: &[JitterTestCase] = &[
		JitterTestCase {
			max_jitter_ms: 50,
			event_label: "process",
			events: &[
				(events::TIMING_JITTER, "process", 10_000_000),
				(events::TIMING_JITTER, "process", 12_000_000),
				(events::TIMING_JITTER, "process", 11_000_000),
			],
			expected_passed: true,
			expected_violations: 0,
		},
		JitterTestCase {
			max_jitter_ms: 50,
			event_label: "process",
			events: &[
				(events::TIMING_JITTER, "process", 10_000_000),
				(events::TIMING_JITTER, "process", 70_000_000),
				(events::TIMING_JITTER, "process", 15_000_000),
			],
			expected_passed: false,
			expected_violations: 1,
		},
		JitterTestCase {
			max_jitter_ms: 50,
			event_label: "process",
			events: &[(events::TIMING_JITTER, "process", 10_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
	];

	// ========================================================================
	// Test Helpers
	// ========================================================================

	/// Create a timing event with duration
	fn timing_event(event_urn: Urn<'static>, label: &str, duration_ns: u64, seq: u32) -> TbEvent {
		TbEvent {
			seq,
			urn: event_urn,
			label: Some(label.to_string()),
			payload_hash: None,
			duration_ns: Some(duration_ns),
			flags: 0,
			extras: None,
		}
	}

	/// Create a trace with timing events
	fn trace_with_events(events: Vec<TbEvent>) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			trace.instrument_events = events;
		}
		trace
	}

	/// Create empty trace
	fn empty_trace() -> ConsumedTrace {
		ConsumedTrace::new()
	}

	/// Build events from test case data
	fn build_events(events: &'static [(Urn<'static>, &'static str, u64)]) -> Vec<TbEvent> {
		events
			.iter()
			.enumerate()
			.map(|(seq, (event_urn, label, duration_ns))| TbEvent {
				seq: seq as u32,
				urn: event_urn.clone(),
				label: Some(label.to_string()),
				payload_hash: None,
				duration_ns: Some(*duration_ns),
				flags: 0,
				extras: None,
			})
			.collect()
	}

	/// Common verification pattern: setup constraints, create trace, verify, assert
	fn verify_constraints<F>(
		setup: F,
		events: &'static [(Urn<'static>, &'static str, u64)],
	) -> Result<TimingVerificationResult, TestingError>
	where
		F: FnOnce(&mut TimingConstraints) -> Result<(), TestingError>,
	{
		let mut constraints = TimingConstraints::default();
		setup(&mut constraints)?;

		let trace = trace_with_events(build_events(events));
		constraints.verify(&trace)
	}

	/// Run WCET test case
	fn run_wcet_test_case(case: &WcetTestCase) -> Result<(), TestingError> {
		let result = verify_constraints(
			|constraints| {
				let wcet_config = WcetConfigBuilder::default()
					.with_duration(Duration::from_millis(case.constraint_ms))
					.build()?;
				constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));
				Ok(())
			},
			case.events,
		)?;

		if result.passed != case.expected_passed {
			eprintln!("WCET Test Case Failed:");
			eprintln!("  constraint_ms: {}", case.constraint_ms);
			eprintln!(
				"  events: {:?}",
				case.events
					.iter()
					.map(|(urn, label, dur)| (urn, label, dur))
					.collect::<Vec<_>>()
			);
			eprintln!("  expected_passed: {}", case.expected_passed);
			eprintln!("  actual_passed: {}", result.passed);
			eprintln!("  wcet_violations: {}", result.wcet_violations.len());
		}
		assert_eq!(result.passed, case.expected_passed);
		assert_eq!(result.wcet_violations.len(), case.expected_violations);
		Ok(())
	}

	/// Run deadline test case
	fn run_deadline_test_case(case: &DeadlineTestCase) -> Result<(), TestingError> {
		let result = verify_constraints(
			|constraints| {
				let mut builder = DeadlineBuilder::default()
					.with_duration(Duration::from_millis(case.deadline_ms))
					.with_start_event(Event(case.start_event))
					.with_end_event(Event(case.end_event));

				if let Some(slack_ms) = case.min_slack_ms {
					builder = builder.with_min_slack(Duration::from_millis(slack_ms));
				}

				constraints.add_deadline(builder.build()?);
				Ok(())
			},
			case.events,
		)?;

		assert_eq!(result.passed, case.expected_passed);
		assert_eq!(result.deadline_misses.len(), case.expected_deadline_misses);
		assert_eq!(result.slack_violations.len(), case.expected_slack_violations);
		Ok(())
	}

	/// Run jitter test case
	fn run_jitter_test_case(case: &JitterTestCase) -> Result<(), TestingError> {
		let result = verify_constraints(
			|constraints| {
				let dur = Duration::from_millis(case.max_jitter_ms);
				constraints.add(Event(case.event_label), TimingConstraint::Jitter(dur, None));
				Ok(())
			},
			case.events,
		)?;

		assert_eq!(result.passed, case.expected_passed);
		assert_eq!(result.jitter_violations.len(), case.expected_violations);
		Ok(())
	}

	// ========================================================================
	// Data-Driven Tests
	// ========================================================================

	#[test]
	fn test_wcet_constraints() -> Result<(), TestingError> {
		for case in WCET_TEST_CASES {
			run_wcet_test_case(case)?;
		}
		Ok(())
	}

	#[test]
	fn test_deadline_constraints() -> Result<(), TestingError> {
		for case in DEADLINE_TEST_CASES {
			run_deadline_test_case(case)?;
		}
		Ok(())
	}

	#[test]
	fn test_jitter_constraints() -> Result<(), TestingError> {
		for case in JITTER_TEST_CASES {
			run_jitter_test_case(case)?;
		}
		Ok(())
	}

	// ========================================================================
	// Special Cases
	// ========================================================================

	#[test]
	fn test_wcet_no_duration() -> Result<(), TestingError> {
		let mut constraints = TimingConstraints::default();
		let wcet_config = WcetConfigBuilder::default().with_duration(Duration::from_millis(100)).build()?;
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
				flags: 0,
				extras: None,
			});
		}

		let result = constraints.verify(&trace)?;
		assert!(result.passed); // Event without duration is skipped
		assert!(result.wcet_violations.is_empty());
		Ok(())
	}

	// ========================================================================
	// Combined Constraint Tests
	// ========================================================================

	/// Helper to create WCET config
	fn create_wcet_config(ms: u64) -> Result<WcetConfig, TestingError> {
		WcetConfigBuilder::default().with_duration(Duration::from_millis(ms)).build()
	}

	/// Helper to create deadline
	fn create_deadline(ms: u64, start: &'static str, end: &'static str) -> Result<Deadline, TestingError> {
		DeadlineBuilder::default()
			.with_duration(Duration::from_millis(ms))
			.with_start_event(Event(start))
			.with_end_event(Event(end))
			.build()
	}

	/// Setup combined constraints (WCET, jitter, deadline)
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

	// ========================================================================
	// Edge Cases
	// ========================================================================

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

		// Durations: [10ms, 20ms, 15ms] - variance-based jitter
		let trace = trace_with_events(vec![
			timing_event(events::TIMING_JITTER, "process", 10_000_000, 0),
			timing_event(events::TIMING_JITTER, "process", 20_000_000, 1),
			timing_event(events::TIMING_JITTER, "process", 15_000_000, 2),
		]);

		// Result depends on variance calculation - just verify it doesn't panic
		let result = constraints.verify(&trace)?;
		assert!(result.jitter_violations.len() <= 1);
		Ok(())
	}

	// ========================================================================
	// Path-Based WCET Tests
	// ========================================================================

	/// Helper to create a simple test process: start -> process -> end
	fn create_path_test_process() -> Result<Process, &'static str> {
		Process::builder("test")
			.initial_state(State("s0"))
			.add_terminal(State("s2"))
			.add_observable("start")
			.add_observable("process")
			.add_observable("end")
			.add_transition(State("s0"), "start", State("s1"))
			.add_transition(State("s1"), "process", State("s2"))
			.add_transition(State("s2"), "end", State("s2"))
			.build()
	}

	/// Helper to create path WCET constraint for test path
	fn create_test_path_wcet(max_duration_ms: u64) -> PathWcet {
		PathWcet::new(
			vec![Event("start"), Event("process"), Event("end")],
			Duration::from_millis(max_duration_ms),
		)
	}

	/// Path WCET test case
	struct PathWcetTestCase {
		start_duration_ns: u64,
		process_duration_ns: u64,
		end_duration_ns: u64,
		max_duration_ms: u64,
		expected_passed: bool,
		expected_violations: usize,
		expected_observed_ns: Option<u64>,
	}

	const PATH_WCET_TEST_CASES: &[PathWcetTestCase] = &[
		PathWcetTestCase {
			// Total: 10ms + 20ms + 5ms = 35ms < 50ms (pass)
			start_duration_ns: 10_000_000,
			process_duration_ns: 20_000_000,
			end_duration_ns: 5_000_000,
			max_duration_ms: 50,
			expected_passed: true,
			expected_violations: 0,
			expected_observed_ns: None,
		},
		PathWcetTestCase {
			// Total: 10ms + 30ms + 15ms = 55ms > 50ms (violation)
			start_duration_ns: 10_000_000,
			process_duration_ns: 30_000_000,
			end_duration_ns: 15_000_000,
			max_duration_ms: 50,
			expected_passed: false,
			expected_violations: 1,
			expected_observed_ns: Some(55_000_000),
		},
	];

	/// Run path WCET test case
	fn run_path_wcet_test_case(case: &PathWcetTestCase) -> Result<(), Box<dyn core::error::Error>> {
		let process = create_path_test_process()?;
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(case.max_duration_ms));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", case.start_duration_ns, 0),
			timing_event(events::TIMING_WCET, "process", case.process_duration_ns, 1),
			timing_event(events::TIMING_WCET, "end", case.end_duration_ns, 2),
		]);

		let result = constraints.verify_with_process(&trace, Some(&process))?;
		assert_eq!(result.passed, case.expected_passed);
		assert_eq!(result.path_wcet_violations.len(), case.expected_violations);

		if let Some(expected_observed_ns) = case.expected_observed_ns {
			assert_eq!(result.path_wcet_violations[0].observed_path_duration_ns, expected_observed_ns);
			assert_eq!(
				result.path_wcet_violations[0].max_path_duration_ns,
				case.max_duration_ms * 1_000_000
			);
		}
		Ok(())
	}

	#[test]
	fn test_path_wcet_constraints() -> Result<(), Box<dyn core::error::Error>> {
		for case in PATH_WCET_TEST_CASES {
			run_path_wcet_test_case(case)?;
		}
		Ok(())
	}

	#[test]
	fn test_path_wcet_no_process() -> Result<(), TestingError> {
		// Path-based WCET should not be verified if no process is provided
		let mut constraints = TimingConstraints::default();
		constraints.add_path_wcet(create_test_path_wcet(50));

		let trace = trace_with_events(vec![
			timing_event(events::TIMING_WCET, "start", 10_000_000, 0),
			timing_event(events::TIMING_WCET, "process", 30_000_000, 1),
			timing_event(events::TIMING_WCET, "end", 15_000_000, 2),
		]);

		// Without process, path WCET is not checked
		let result = constraints.verify(&trace)?;
		assert!(result.passed);
		assert!(result.path_wcet_violations.is_empty());
		Ok(())
	}
}
