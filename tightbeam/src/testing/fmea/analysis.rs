//! FMEA analysis functions
//!
//! Provides automatic calculation of:
//! - Severity (from CSP criticality analysis)
//! - Occurrence (from probability basis points)
//! - Detection (from error recovery statistics)

use crate::testing::fdr::{FdrVerdict, InjectedFaultRecord};
use crate::testing::fmea::SeverityScale;
use crate::testing::specs::csp::Process;
use std::collections::{HashSet, VecDeque};

/// Calculate severity based on CSP criticality analysis
///
/// Uses reachability analysis to determine severity:
/// - Deadlock (no transitions, not terminal) = Catastrophic
/// - Cannot reach terminal states = Hazardous
/// - Significantly restricts state space = Major
/// - Minor state restriction = Minor
pub fn calculate_severity(fault: &InjectedFaultRecord, process: &Process, scale: SeverityScale) -> u8 {
	// Find the state where the fault occurs
	let fault_state = process.states.iter().find(|s| s.0 == fault.csp_state.as_str()).copied();
	let Some(fault_state) = fault_state else {
		// Unknown state = medium severity (uncertain impact)
		return scale.mid_value();
	};

	// BFS to explore reachable states from fault point
	let mut visited = HashSet::new();
	let mut queue = VecDeque::new();
	queue.push_back(fault_state);
	visited.insert(fault_state);

	let mut has_deadlock = false;
	let mut can_reach_terminal = false;
	while let Some(current_state) = queue.pop_front() {
		// Check if terminal
		if process.is_terminal(current_state) {
			can_reach_terminal = true;
			continue;
		}

		// Check for deadlock
		let enabled = process.enabled(current_state);
		if enabled.is_empty() {
			has_deadlock = true;
			continue;
		}

		// Explore successors
		for action in enabled {
			let successors = process.step(current_state, &action.event);
			for next_state in successors {
				if visited.insert(next_state) {
					queue.push_back(next_state);
				}
			}
		}
	}

	// Calculate severity based on criticality
	let total_states = process.states.len();
	let reachable_count = visited.len();
	let restriction_ratio = (reachable_count as f64) / (total_states as f64);

	match scale {
		SeverityScale::MilStd1629 => {
			// MIL-STD-1629: 1-10 scale
			if has_deadlock {
				10 // Catastrophic: System completely stops
			} else if !can_reach_terminal && !process.terminal.is_empty() {
				9 // Critical: Cannot complete normal operation
			} else if restriction_ratio < 0.5 {
				7 // Severe: More than half of states unreachable
			} else if restriction_ratio < 0.8 {
				5 // Moderate: Significant state restriction
			} else {
				3 // Minor: Limited impact
			}
		}
		SeverityScale::Iso26262 => {
			// ISO 26262: 1-4 scale (catastrophic, hazardous, major, minor)
			if has_deadlock || (!can_reach_terminal && !process.terminal.is_empty()) {
				4 // Catastrophic: Complete system failure or cannot reach safe terminal
			} else if restriction_ratio < 0.5 {
				3 // Hazardous: Severely restricted functionality
			} else if restriction_ratio < 0.8 {
				2 // Major: Noticeable degradation
			} else {
				1 // Minor: Limited impact
			}
		}
	}
}

/// Convert occurrence probability (basis points) to FMEA scale
pub fn convert_occurrence(probability_bps: u16, scale: SeverityScale) -> u16 {
	let normalized = match scale {
		SeverityScale::MilStd1629 => probability_bps / 1000, // 0-10000 -> 0-10
		SeverityScale::Iso26262 => probability_bps / 2500,   // 0-10000 -> 0-4
	};

	(normalized + 1).min(scale.max_value())
}

/// Calculate detection rating from error recovery statistics
pub fn calculate_detection(verdict: &FdrVerdict, scale: SeverityScale) -> u8 {
	let total = verdict.error_recovery_successful + verdict.error_recovery_failed;

	if total == 0 {
		return scale.mid_value();
	}

	let success_rate = (verdict.error_recovery_successful as f64) / (total as f64);
	let inverted = 1.0 - success_rate;
	let max = scale.max_value() as f64;

	((inverted * (max - 1.0)) + 1.0) as u8
}

impl SeverityScale {
	/// Maximum value for this scale
	pub(crate) const fn max_value(&self) -> u16 {
		match self {
			Self::MilStd1629 => 10,
			Self::Iso26262 => 4,
		}
	}

	/// Mid-range value for this scale
	pub(crate) const fn mid_value(&self) -> u8 {
		match self {
			Self::MilStd1629 => 5,
			Self::Iso26262 => 2,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::{Process, State};

	fn create_fault(state: &str) -> InjectedFaultRecord {
		InjectedFaultRecord {
			csp_state: state.to_string(),
			event_label: "test_event".to_string(),
			error_message: "Test fault".to_string(),
			probability_bps: 5000,
		}
	}

	fn assert_severity_both_scales(
		fault: &InjectedFaultRecord,
		process: &Process,
		expected_mil: u8,
		expected_iso: u8,
		context: &str,
	) {
		let severity_mil = calculate_severity(fault, process, SeverityScale::MilStd1629);
		let severity_iso = calculate_severity(fault, process, SeverityScale::Iso26262);
		assert_eq!(severity_mil, expected_mil, "{} (MIL-STD-1629 1-10 scale)", context);
		assert_eq!(severity_iso, expected_iso, "{} (ISO 26262 1-4 scale)", context);
	}

	macro_rules! process_spec {
		(
			$name:expr,
			initial: $initial:expr,
			terminals: [$($terminal:expr),* $(,)?],
			transitions: [$(($from:expr, $event:expr, $to:expr)),* $(,)?]
		) => {{
			let mut builder = Process::builder($name).initial_state(State($initial));

			let mut observables = std::collections::HashSet::new();
			$(
				observables.insert($event);
			)*

			for observable in observables {
				builder = builder.add_observable(observable);
			}

			$(
				builder = builder.add_terminal(State($terminal));
			)*

			$(
				builder = builder.add_transition(State($from), $event, State($to));
			)*

			builder.build().unwrap()
		}};
	}

	#[test]
	fn test_severity_deadlock_catastrophic() {
		let process = process_spec!(
			"DeadlockProcess",
			initial: "Init",
			terminals: [],
			transitions: [("Init", "start", "Blocked")]
		);
		assert_severity_both_scales(
			&create_fault("Init"),
			&process,
			10,
			4,
			"Deadlock (no transitions, not terminal) is catastrophic",
		);
	}

	#[test]
	fn test_severity_cannot_reach_terminal() {
		let process = process_spec!(
			"NoTerminalProcess",
			initial: "Init",
			terminals: ["Success"],
			transitions: [
				("Init", "start", "Loop"),
				("Loop", "loop_back", "Loop")
			]
		);
		assert_severity_both_scales(
			&create_fault("Init"),
			&process,
			9,
			4,
			"Cannot reach terminal state is critical/catastrophic",
		);
	}

	#[test]
	fn test_severity_severe_restriction() {
		let process = process_spec!(
			"RestrictedProcess",
			initial: "Init",
			terminals: ["Done"],
			transitions: [
				("Init", "to_a", "A"),
				("A", "done", "Done"),
				("Init", "to_b", "B"),
				("B", "to_c", "C"),
				("C", "to_d", "D"),
				("D", "done", "Done")
			]
		);
		assert_severity_both_scales(&create_fault("A"), &process, 7, 3, "Severe restriction (<50% states reachable)");
	}

	#[test]
	fn test_severity_moderate_restriction() {
		let process = process_spec!(
			"ModerateProcess",
			initial: "Init",
			terminals: ["Done"],
			transitions: [
				("Init", "to_a", "A"),
				("Init", "to_alt", "Alt"),
				("A", "to_b", "B"),
				("B", "done", "Done"),
				("Alt", "done", "Done")
			]
		);
		assert_severity_both_scales(
			&create_fault("A"),
			&process,
			5,
			2,
			"Moderate restriction (50-80% states reachable)",
		);
	}

	#[test]
	fn test_severity_minor_impact() {
		let process = process_spec!(
			"MinorProcess",
			initial: "S1",
			terminals: [],
			transitions: [
				("S1", "event", "S2"),
				("S2", "event", "S1")
			]
		);
		assert_severity_both_scales(&create_fault("S1"), &process, 3, 1, "Minor impact (all states reachable)");
	}

	#[test]
	fn test_severity_unknown_state() {
		let process = Process::builder("SimpleProcess")
			.add_observable("event")
			.initial_state(State("Known"))
			.build()
			.unwrap();

		assert_severity_both_scales(&create_fault("UnknownState"), &process, 5, 2, "Unknown state returns mid-value");
	}

	#[test]
	fn test_convert_occurrence_boundaries() {
		let test_cases = [
			(0, SeverityScale::MilStd1629, 1),
			(5000, SeverityScale::MilStd1629, 6),
			(10000, SeverityScale::MilStd1629, 10),
			(0, SeverityScale::Iso26262, 1),
			(5000, SeverityScale::Iso26262, 3),
			(10000, SeverityScale::Iso26262, 4),
		];

		for (bps, scale, expected) in test_cases {
			assert_eq!(
				convert_occurrence(bps, scale),
				expected,
				"Occurrence for {} bps with {:?}",
				bps,
				scale
			);
		}
	}

	#[test]
	fn test_detection_ratings() {
		struct DetectionTestCase {
			success: usize,
			failed: usize,
			scale: SeverityScale,
			expected: u8,
			description: &'static str,
		}

		let test_cases = [
			DetectionTestCase {
				success: 10,
				failed: 0,
				scale: SeverityScale::MilStd1629,
				expected: 1,
				description: "All recoveries successful (easily detected)",
			},
			DetectionTestCase {
				success: 0,
				failed: 10,
				scale: SeverityScale::MilStd1629,
				expected: 10,
				description: "All recoveries failed (undetectable)",
			},
			DetectionTestCase {
				success: 5,
				failed: 5,
				scale: SeverityScale::MilStd1629,
				expected: 5,
				description: "50/50 recovery rate (moderate detection)",
			},
		];

		for case in &test_cases {
			let verdict = FdrVerdict {
				error_recovery_successful: case.success,
				error_recovery_failed: case.failed,
				..Default::default()
			};
			assert_eq!(calculate_detection(&verdict, case.scale), case.expected, "{}", case.description);
		}
	}
}
