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

impl InjectedFaultRecord {
	/// Severity of this fault, from CSP criticality analysis.
	///
	/// Reachability from the fault state decides the rating:
	/// - Deadlock (no transitions, not terminal) is catastrophic.
	/// - No reachable terminal state is hazardous.
	/// - A large state-space restriction is major.
	/// - A small restriction is minor.
	pub fn severity(&self, process: &Process, scale: SeverityScale) -> u8 {
		// Production fault records key states as "process.state". bare state names
		// are accepted for records built directly against a process.
		let state_name = self
			.csp_state
			.strip_prefix(process.name)
			.and_then(|rest| rest.strip_prefix('.'))
			.unwrap_or(self.csp_state.as_str());

		// Find the state where the fault occurs
		let fault_state = process.states.iter().find(|s| s.0 == state_name).copied();
		let Some(fault_state) = fault_state else {
			// Unknown state = medium severity (uncertain impact)
			return scale.mid_value();
		};

		// BFS to explore reachable states from fault point
		let mut visited = HashSet::new();
		visited.insert(fault_state);

		let mut queue = VecDeque::new();
		queue.push_back(fault_state);

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
}

impl FdrVerdict {
	/// Detection rating from this run's error-recovery statistics.
	///
	/// A run with no recovery attempts has nothing to rate, so it reports
	/// the scale's midpoint.
	pub fn detection(&self, scale: SeverityScale) -> u8 {
		let total = self.error_recovery_successful + self.error_recovery_failed;
		if total == 0 {
			return scale.mid_value();
		}

		let success_rate = (self.error_recovery_successful as f64) / (total as f64);
		let inverted = 1.0 - success_rate;
		let max = scale.max_value() as f64;

		((inverted * (max - 1.0)) + 1.0) as u8
	}
}

impl SeverityScale {
	/// Occurrence rating for a probability in basis points.
	pub fn occurrence(&self, probability_bps: u16) -> u16 {
		let normalized = match self {
			Self::MilStd1629 => probability_bps / 1000, // 0-10000 -> 0-10
			Self::Iso26262 => probability_bps / 2500,   // 0-10000 -> 0-4
		};

		(normalized + 1).min(self.max_value())
	}

	/// Wire discriminant for this scale.
	pub(crate) fn wire_code(&self) -> u8 {
		match self {
			Self::MilStd1629 => 0,
			Self::Iso26262 => 1,
		}
	}
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
	use crate::testing::specs::csp::{Event, Process, State};

	fn create_fault(state: &str) -> InjectedFaultRecord {
		InjectedFaultRecord {
			csp_state: state.to_string(),
			event_label: "test_event".to_string(),
			error_message: "Test fault".to_string(),
			probability_bps: 5000,
		}
	}

	fn assert_severity_both_scales(fault: &InjectedFaultRecord, process: &Process, expected_mil: u8, expected_iso: u8) {
		let severity_mil = fault.severity(process, SeverityScale::MilStd1629);
		let severity_iso = fault.severity(process, SeverityScale::Iso26262);
		assert_eq!(severity_mil, expected_mil);
		assert_eq!(severity_iso, expected_iso);
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
				observables.insert(Event($event));
			)*

			for observable in observables {
				builder = builder.add_observable(observable);
			}

			$(
				builder = builder.add_terminal(State($terminal));
			)*

			$(
				builder = builder.add_transition(State($from), Event($event), State($to));
			)*

			builder.build().expect("fixture state machine builds")
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
		assert_severity_both_scales(&create_fault("DeadlockProcess.Init"), &process, 10, 4);
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
		assert_severity_both_scales(&create_fault("NoTerminalProcess.Init"), &process, 9, 4);
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
		assert_severity_both_scales(&create_fault("RestrictedProcess.A"), &process, 7, 3);
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
		assert_severity_both_scales(&create_fault("ModerateProcess.A"), &process, 5, 2);
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
		assert_severity_both_scales(&create_fault("MinorProcess.S1"), &process, 3, 1);
	}

	#[test]
	fn test_severity_bare_state_name_accepted() {
		let process = process_spec!(
			"BareProcess",
			initial: "Init",
			terminals: [],
			transitions: [("Init", "start", "Blocked")]
		);
		assert_severity_both_scales(&create_fault("Init"), &process, 10, 4);
	}

	#[test]
	fn test_severity_unknown_state() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("SimpleProcess")
			.add_observable(Event("event"))
			.initial_state(State("Known"))
			.build()?;

		assert_severity_both_scales(&create_fault("SimpleProcess.UnknownState"), &process, 5, 2);

		Ok(())
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
			assert_eq!(scale.occurrence(bps), expected);
		}
	}

	#[test]
	fn test_detection_ratings() {
		// (recoveries successful, recoveries failed, scale, expected rating)
		let test_cases = [
			(10, 0, SeverityScale::MilStd1629, 1),
			(0, 10, SeverityScale::MilStd1629, 10),
			(5, 5, SeverityScale::MilStd1629, 5),
		];

		for (success, failed, scale, expected) in test_cases {
			let verdict = FdrVerdict {
				error_recovery_successful: success,
				error_recovery_failed: failed,
				..Default::default()
			};
			assert_eq!(verdict.detection(scale), expected);
		}
	}
}
