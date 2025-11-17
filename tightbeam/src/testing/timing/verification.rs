//! Timing verification logic

use std::collections::HashMap;
use std::sync::Arc;

use super::constraints::{TimingConstraint, TimingConstraints};
use super::deadline::Deadline;
use super::violations::{DeadlineMiss, JitterViolation, TimingSlackViolation, TimingViolation};
use crate::der::Sequence;
use crate::instrumentation::{TbEvent, TbEventKind};
use crate::testing::error::TestingError;
use crate::testing::specs::csp::Event;
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
}

impl TimingConstraints {
	/// Verify timing constraints against trace
	///
	/// Checks observed durations from instrumentation events against timing
	/// constraints defined in this collection.
	pub fn verify(&self, trace: &ConsumedTrace) -> Result<TimingVerificationResult, TestingError> {
		let mut result = TimingVerificationResult { passed: true, ..Default::default() };
		let events_by_label = Self::extract_timing_events(trace);
		let events_by_label = Self::group_events_by_label(&events_by_label);

		Self::verify_wcet_constraints(self, &events_by_label, &mut result);
		Self::verify_deadline_constraints(self, &events_by_label, &mut result);
		Self::verify_jitter_constraints(self, &events_by_label, &mut result);

		Ok(result)
	}

	/// Extract timing events from trace
	fn extract_timing_events(trace: &ConsumedTrace) -> Vec<&TbEvent> {
		#[cfg(feature = "instrument")]
		{
			trace
				.instrument_events
				.iter()
				.filter(|ev| {
					matches!(
						ev.kind,
						TbEventKind::TimingWcet | TbEventKind::TimingDeadline | TbEventKind::TimingJitter
					)
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
					let wcet_events: Vec<&TbEvent> =
						events.iter().filter(|e| e.kind == TbEventKind::TimingWcet).copied().collect();

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

			let start_events: Vec<&TbEvent> = events_by_label
				.get(start_label)
				.map(|v| v.iter().filter(|e| e.kind == TbEventKind::TimingDeadline).copied().collect())
				.unwrap_or_default();
			let end_events: Vec<&TbEvent> = events_by_label
				.get(end_label)
				.map(|v| v.iter().filter(|e| e.kind == TbEventKind::TimingDeadline).copied().collect())
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
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use super::*;
	use crate::builder::TypeBuilder;
	use crate::testing::timing::{DeadlineBuilder, WcetConfigBuilder};
	use crate::utils::jitter::VarianceJitter;

	// ========================================================================
	// Test Case Data Structures
	// ========================================================================

	/// Test case for WCET constraint verification
	struct WcetTestCase {
		name: &'static str,
		constraint_ms: u64,
		events: &'static [(TbEventKind, &'static str, u64)], // (kind, label, duration_ns)
		expected_passed: bool,
		expected_violations: usize,
	}

	/// Test case for deadline constraint verification
	struct DeadlineTestCase {
		name: &'static str,
		deadline_ms: u64,
		start_event: &'static str,
		end_event: &'static str,
		min_slack_ms: Option<u64>,
		events: &'static [(TbEventKind, &'static str, u64)], // (kind, label, duration_ns)
		expected_passed: bool,
		expected_deadline_misses: usize,
		expected_slack_violations: usize,
	}

	/// Test case for jitter constraint verification
	struct JitterTestCase {
		name: &'static str,
		max_jitter_ms: u64,
		event_label: &'static str,
		events: &'static [(TbEventKind, &'static str, u64)], // (kind, label, duration_ns)
		expected_passed: bool,
		expected_violations: usize,
	}

	// ========================================================================
	// Test Case Data
	// ========================================================================

	const WCET_TEST_CASES: &[WcetTestCase] = &[
		WcetTestCase {
			name: "passed",
			constraint_ms: 100,
			events: &[(TbEventKind::TimingWcet, "process", 50_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
		WcetTestCase {
			name: "violated",
			constraint_ms: 100,
			events: &[(TbEventKind::TimingWcet, "process", 150_000_000)],
			expected_passed: false,
			expected_violations: 1,
		},
		WcetTestCase {
			name: "multiple_events",
			constraint_ms: 100,
			events: &[
				(TbEventKind::TimingWcet, "process", 50_000_000),
				(TbEventKind::TimingWcet, "process", 150_000_000),
				(TbEventKind::TimingWcet, "process", 80_000_000),
			],
			expected_passed: false,
			expected_violations: 1,
		},
		WcetTestCase {
			name: "missing_event",
			constraint_ms: 100,
			events: &[],
			expected_passed: true,
			expected_violations: 0,
		},
		WcetTestCase {
			name: "exact_boundary",
			constraint_ms: 100,
			events: &[(TbEventKind::TimingWcet, "process", 100_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
		WcetTestCase {
			name: "wrong_event_kind",
			constraint_ms: 100,
			events: &[(TbEventKind::TimingDeadline, "process", 150_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
	];

	const DEADLINE_TEST_CASES: &[DeadlineTestCase] = &[
		DeadlineTestCase {
			name: "passed",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 50_000_000),
			],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "violated",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 150_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 1,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "multiple_pairs",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 50_000_000),
				(TbEventKind::TimingDeadline, "start", 200_000_000),
				(TbEventKind::TimingDeadline, "end", 350_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 1,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "missing_start",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[(TbEventKind::TimingDeadline, "end", 50_000_000)],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "missing_end",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[(TbEventKind::TimingDeadline, "start", 0)],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "exact_boundary",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: None,
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 100_000_000),
			],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "slack_passed",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: Some(20),
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 50_000_000),
			],
			expected_passed: true,
			expected_deadline_misses: 0,
			expected_slack_violations: 0,
		},
		DeadlineTestCase {
			name: "slack_violated",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: Some(20),
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 85_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 0,
			expected_slack_violations: 1,
		},
		DeadlineTestCase {
			name: "slack_with_deadline_violation",
			deadline_ms: 100,
			start_event: "start",
			end_event: "end",
			min_slack_ms: Some(20),
			events: &[
				(TbEventKind::TimingDeadline, "start", 0),
				(TbEventKind::TimingDeadline, "end", 150_000_000),
			],
			expected_passed: false,
			expected_deadline_misses: 1,
			expected_slack_violations: 1,
		},
	];

	const JITTER_TEST_CASES: &[JitterTestCase] = &[
		JitterTestCase {
			name: "passed",
			max_jitter_ms: 50,
			event_label: "process",
			events: &[
				(TbEventKind::TimingJitter, "process", 10_000_000),
				(TbEventKind::TimingJitter, "process", 12_000_000),
				(TbEventKind::TimingJitter, "process", 11_000_000),
			],
			expected_passed: true,
			expected_violations: 0,
		},
		JitterTestCase {
			name: "violated",
			max_jitter_ms: 50,
			event_label: "process",
			events: &[
				(TbEventKind::TimingJitter, "process", 10_000_000),
				(TbEventKind::TimingJitter, "process", 70_000_000),
				(TbEventKind::TimingJitter, "process", 15_000_000),
			],
			expected_passed: false,
			expected_violations: 1,
		},
		JitterTestCase {
			name: "insufficient_events",
			max_jitter_ms: 50,
			event_label: "process",
			events: &[(TbEventKind::TimingJitter, "process", 10_000_000)],
			expected_passed: true,
			expected_violations: 0,
		},
	];

	// ========================================================================
	// Test Helpers
	// ========================================================================

	/// Create a timing event with duration
	fn timing_event(kind: TbEventKind, label: &str, duration_ns: u64, seq: u32) -> TbEvent {
		TbEvent {
			seq,
			kind,
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
	fn build_events(events: &'static [(TbEventKind, &'static str, u64)]) -> Vec<TbEvent> {
		events
			.iter()
			.enumerate()
			.map(|(seq, (kind, label, duration_ns))| timing_event(*kind, label, *duration_ns, seq as u32))
			.collect()
	}

	/// Run WCET test case
	fn run_wcet_test_case(case: &WcetTestCase) {
		let mut constraints = TimingConstraints::new();
		let wcet_config = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(case.constraint_ms))
			.build()
			.unwrap();
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		let events = build_events(case.events);
		let trace = trace_with_events(events);

		let result = constraints.verify(&trace).unwrap();
		assert_eq!(result.passed, case.expected_passed, "Test case: {}", case.name);
		assert_eq!(
			result.wcet_violations.len(),
			case.expected_violations,
			"Test case: {} - expected {} violations, got {}",
			case.name,
			case.expected_violations,
			result.wcet_violations.len()
		);
	}

	/// Run deadline test case
	fn run_deadline_test_case(case: &DeadlineTestCase) {
		let mut constraints = TimingConstraints::new();
		let mut builder = DeadlineBuilder::default()
			.with_duration(Duration::from_millis(case.deadline_ms))
			.with_start_event(Event(case.start_event))
			.with_end_event(Event(case.end_event));

		if let Some(slack_ms) = case.min_slack_ms {
			builder = builder.with_min_slack(Duration::from_millis(slack_ms));
		}

		let deadline = builder.build().unwrap();
		constraints.add_deadline(deadline);

		let events = build_events(case.events);
		let trace = trace_with_events(events);

		let result = constraints.verify(&trace).unwrap();
		assert_eq!(result.passed, case.expected_passed, "Test case: {}", case.name);
		assert_eq!(
			result.deadline_misses.len(),
			case.expected_deadline_misses,
			"Test case: {} - expected {} deadline misses, got {}",
			case.name,
			case.expected_deadline_misses,
			result.deadline_misses.len()
		);
		assert_eq!(
			result.slack_violations.len(),
			case.expected_slack_violations,
			"Test case: {} - expected {} slack violations, got {}",
			case.name,
			case.expected_slack_violations,
			result.slack_violations.len()
		);
	}

	/// Run jitter test case
	fn run_jitter_test_case(case: &JitterTestCase) {
		let mut constraints = TimingConstraints::new();
		let dur = Duration::from_millis(case.max_jitter_ms);
		constraints.add(Event(case.event_label), TimingConstraint::Jitter(dur, None));

		let events = build_events(case.events);
		let trace = trace_with_events(events);

		let result = constraints.verify(&trace).unwrap();
		assert_eq!(result.passed, case.expected_passed, "Test case: {}", case.name);
		assert_eq!(
			result.jitter_violations.len(),
			case.expected_violations,
			"Test case: {} - expected {} violations, got {}",
			case.name,
			case.expected_violations,
			result.jitter_violations.len()
		);
	}

	// ========================================================================
	// Data-Driven Tests
	// ========================================================================

	#[test]
	fn test_wcet_constraints() {
		for case in WCET_TEST_CASES {
			run_wcet_test_case(case);
		}
	}

	#[test]
	fn test_deadline_constraints() {
		for case in DEADLINE_TEST_CASES {
			run_deadline_test_case(case);
		}
	}

	#[test]
	fn test_jitter_constraints() {
		for case in JITTER_TEST_CASES {
			run_jitter_test_case(case);
		}
	}

	// ============================================================================
	// Special Cases (not easily data-driven)
	// ============================================================================

	#[test]
	fn test_wcet_no_duration() {
		let mut constraints = TimingConstraints::new();
		let wcet_config = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(100))
			.build()
			.unwrap();
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			trace.instrument_events.push(TbEvent {
				seq: 0,
				kind: TbEventKind::TimingWcet,
				label: Some("process".to_string()),
				payload_hash: None,
				duration_ns: None, // No duration
				flags: 0,
				extras: None,
			});
		}

		let result = constraints.verify(&trace).unwrap();
		assert!(result.passed); // Event without duration is skipped
		assert!(result.wcet_violations.is_empty());
	}

	// ========================================================================
	// Combined Constraint Tests
	// ========================================================================

	#[test]
	fn test_combined_constraints_all_passed() {
		let mut constraints = TimingConstraints::new();
		let wcet_config = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(100))
			.build()
			.unwrap();
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));
		constraints.add(Event("request"), TimingConstraint::Jitter(Duration::from_millis(50), None));
		let deadline = DeadlineBuilder::default()
			.with_duration(Duration::from_millis(200))
			.with_start_event(Event("start"))
			.with_end_event(Event("end"))
			.build()
			.unwrap();
		constraints.add_deadline(deadline);

		let trace = trace_with_events(vec![
			timing_event(TbEventKind::TimingWcet, "process", 50_000_000, 0),
			timing_event(TbEventKind::TimingJitter, "request", 10_000_000, 1),
			timing_event(TbEventKind::TimingJitter, "request", 12_000_000, 2),
			timing_event(TbEventKind::TimingDeadline, "start", 0, 3),
			timing_event(TbEventKind::TimingDeadline, "end", 100_000_000, 4),
		]);

		let result = constraints.verify(&trace).unwrap();
		assert!(result.passed);
		assert!(result.wcet_violations.is_empty());
		assert!(result.jitter_violations.is_empty());
		assert!(result.deadline_misses.is_empty());
	}

	#[test]
	fn test_combined_constraints_multiple_violations() {
		let mut constraints = TimingConstraints::new();
		let wcet_config = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(100))
			.build()
			.unwrap();
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));
		constraints.add(Event("request"), TimingConstraint::Jitter(Duration::from_millis(50), None));
		let deadline = DeadlineBuilder::default()
			.with_duration(Duration::from_millis(200))
			.with_start_event(Event("start"))
			.with_end_event(Event("end"))
			.build()
			.unwrap();
		constraints.add_deadline(deadline);

		let trace = trace_with_events(vec![
			timing_event(TbEventKind::TimingWcet, "process", 150_000_000, 0), // WCET violation
			timing_event(TbEventKind::TimingJitter, "request", 10_000_000, 1),
			timing_event(TbEventKind::TimingJitter, "request", 70_000_000, 2), // Jitter violation
			timing_event(TbEventKind::TimingDeadline, "start", 0, 3),
			timing_event(TbEventKind::TimingDeadline, "end", 250_000_000, 4), // Deadline violation
		]);

		let result = constraints.verify(&trace).unwrap();
		assert!(!result.passed);
		assert_eq!(result.wcet_violations.len(), 1);
		assert_eq!(result.jitter_violations.len(), 1);
		assert_eq!(result.deadline_misses.len(), 1);
	}

	// ========================================================================
	// Edge Cases
	// ========================================================================

	#[test]
	fn test_empty_constraints() {
		let constraints = TimingConstraints::new();
		let trace = trace_with_events(vec![timing_event(TbEventKind::TimingWcet, "process", 50_000_000, 0)]);

		let result = constraints.verify(&trace).unwrap();
		assert!(result.passed);
	}

	#[test]
	fn test_empty_trace() {
		let mut constraints = TimingConstraints::new();
		let wcet_config = WcetConfigBuilder::default()
			.with_duration(Duration::from_millis(100))
			.build()
			.unwrap();
		constraints.add(Event("process"), TimingConstraint::Wcet(wcet_config));

		let trace = empty_trace();
		let result = constraints.verify(&trace).unwrap();
		assert!(result.passed); // No violations if no events
	}

	#[test]
	fn test_jitter_with_custom_calculator() {
		let mut constraints = TimingConstraints::new();
		let dur = Duration::from_millis(100);
		let calc = Arc::new(VarianceJitter);
		constraints.add(Event("process"), TimingConstraint::Jitter(dur, Some(calc)));

		// Durations: [10ms, 20ms, 15ms] - variance-based jitter
		let trace = trace_with_events(vec![
			timing_event(TbEventKind::TimingJitter, "process", 10_000_000, 0),
			timing_event(TbEventKind::TimingJitter, "process", 20_000_000, 1),
			timing_event(TbEventKind::TimingJitter, "process", 15_000_000, 2),
		]);

		// Result depends on variance calculation - just verify it doesn't panic
		let result = constraints.verify(&trace).unwrap();
		assert!(result.jitter_violations.len() <= 1);
	}
}
