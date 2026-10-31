//! The FMEA ratings of a fault and of a run.
//!
//! The module computes three ratings automatically:
//! - The severity, from the CSP criticality analysis.
//! - The occurrence, from the probability in basis points.
//! - The detection, from the error-recovery statistics.

use crate::testing::fdr::{FdrVerdict, InjectedFaultRecord};
use crate::testing::fmea::SeverityScale;
use crate::testing::specs::csp::{Process, State};
use std::collections::{HashSet, VecDeque};

impl InjectedFaultRecord {
	/// The site of this fault among `processes`: the first process that holds
	/// the state this record names, with that state.
	///
	/// A record names its state as `Process.State`. A key that starts with the
	/// name of a process and a dot names the state after the dot. Any other
	/// key names the state of that full name, so a bare state name reads as a
	/// state of each process.
	pub(crate) fn site_in<'p>(&self, processes: &[&'p Process]) -> Option<(&'p Process, State)> {
		processes.iter().find_map(|process| {
			let after_process = self.csp_state.strip_prefix(process.name);
			let qualified = after_process.and_then(|rest| rest.strip_prefix('.'));
			let state_name = qualified.unwrap_or(self.csp_state.as_str());
			let state = process.states.iter().find(|state| state.0 == state_name).copied()?;

			Some((*process, state))
		})
	}

	/// The severity of this fault, from the CSP criticality analysis.
	///
	/// Reachability from the fault state decides the rating. The cases run from
	/// the most severe, and ISO 26262 rates the first two alike:
	/// - A deadlock, which is a reachable non-terminal state with no enabled event.
	/// - Terminal states that the fault state cannot reach.
	/// - A reach of less than half of the states, which is a large restriction.
	/// - A reach of less than 80 percent of the states.
	/// - Any other reach, which is a small restriction.
	pub fn severity(&self, process: &Process, scale: SeverityScale) -> u8 {
		self.severity_in(&[process], scale)
	}

	/// The severity of this fault at its site among `processes`, by the rule
	/// of [`Self::severity`].
	pub(crate) fn severity_in(&self, processes: &[&Process], scale: SeverityScale) -> u8 {
		let Some((process, fault_state)) = self.site_in(processes) else {
			// An unknown state has an uncertain impact, so it rates mid-scale.
			return scale.mid_value();
		};

		// A breadth-first search collects the states the fault state reaches.
		let mut visited = HashSet::new();
		visited.insert(fault_state);

		let mut queue = VecDeque::new();
		queue.push_back(fault_state);

		let mut has_deadlock = false;
		let mut can_reach_terminal = false;
		while let Some(current_state) = queue.pop_front() {
			if process.is_terminal(current_state) {
				can_reach_terminal = true;
				continue;
			}

			// A non-terminal state with no enabled event is a deadlock.
			let enabled = process.enabled(current_state);
			if enabled.is_empty() {
				has_deadlock = true;
				continue;
			}

			for action in enabled {
				let successors = process.step(current_state, &action.event);
				for next_state in successors {
					if visited.insert(next_state) {
						queue.push_back(next_state);
					}
				}
			}
		}

		// The restriction ratio is the reached share of the states.
		let total_states = process.states.len();
		let reachable_count = visited.len();
		let restriction_ratio = (reachable_count as f64) / (total_states as f64);

		match scale {
			SeverityScale::MilStd1629 => {
				// MIL-STD-1629 rates on a scale of 1 to 10.
				if has_deadlock {
					10 // Catastrophic: the system stops completely.
				} else if !can_reach_terminal && !process.terminal.is_empty() {
					9 // Critical: normal operation cannot complete.
				} else if restriction_ratio < 0.5 {
					7 // Severe: more than half of the states are unreachable.
				} else if restriction_ratio < 0.8 {
					5 // Moderate: over a fifth of the states are unreachable.
				} else {
					3 // Minor: the impact is limited.
				}
			}
			SeverityScale::Iso26262 => {
				// ISO 26262 rates on a scale of 1 to 4: catastrophic,
				// hazardous, major, and minor.
				if has_deadlock || (!can_reach_terminal && !process.terminal.is_empty()) {
					4 // Catastrophic: the system fails or cannot end safely.
				} else if restriction_ratio < 0.5 {
					3 // Hazardous: the functionality is severely restricted.
				} else if restriction_ratio < 0.8 {
					2 // Major: the degradation is noticeable.
				} else {
					1 // Minor: the impact is limited.
				}
			}
		}
	}
}

impl FdrVerdict {
	/// The detection rating of this run, from its error-recovery statistics.
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
			Self::MilStd1629 => probability_bps / 1000, // 0-10000 maps to 0-10.
			Self::Iso26262 => probability_bps / 2500,   // 0-10000 maps to 0-4.
		};

		(normalized + 1).min(self.max_value())
	}

	/// The wire discriminant of this scale.
	pub(crate) fn wire_code(&self) -> u8 {
		match self {
			Self::MilStd1629 => 0,
			Self::Iso26262 => 1,
		}
	}
	/// The maximum value of this scale.
	pub(crate) const fn max_value(&self) -> u16 {
		match self {
			Self::MilStd1629 => 10,
			Self::Iso26262 => 4,
		}
	}

	/// The mid-range value of this scale.
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
	use crate::testing::fixtures::TestProcess;
	use crate::testing::fmea::DEADLOCK;

	/// A process whose `start` takes `Init` to the loop at `Loop`, so no run
	/// reaches its terminal `Success`.
	const NO_TERMINAL: TestProcess = TestProcess {
		observable: &["start", "loop_back"],
		transitions: &[("Init", "start", "Loop"), ("Loop", "loop_back", "Loop")],
		terminal: &["Success"],
		..TestProcess::of("NoTerminalProcess", "Init")
	};

	/// A process of six states, where `A` reaches `A` and the terminal `Done`
	/// alone.
	const RESTRICTED: TestProcess = TestProcess {
		observable: &["to_a", "done", "to_b", "to_c", "to_d"],
		transitions: &[
			("Init", "to_a", "A"),
			("A", "done", "Done"),
			("Init", "to_b", "B"),
			("B", "to_c", "C"),
			("C", "to_d", "D"),
			("D", "done", "Done"),
		],
		terminal: &["Done"],
		..TestProcess::of("RestrictedProcess", "Init")
	};

	/// A process of five states, where `A` reaches `A`, `B`, and the terminal
	/// `Done`.
	const MODERATE: TestProcess = TestProcess {
		observable: &["to_a", "to_alt", "to_b", "done"],
		transitions: &[
			("Init", "to_a", "A"),
			("Init", "to_alt", "Alt"),
			("A", "to_b", "B"),
			("B", "done", "Done"),
			("Alt", "done", "Done"),
		],
		terminal: &["Done"],
		..TestProcess::of("ModerateProcess", "Init")
	};

	/// A process whose `event` takes `S1` to `S2` and back, with no terminal
	/// state.
	const MINOR: TestProcess = TestProcess {
		observable: &["event"],
		transitions: &[("S1", "event", "S2"), ("S2", "event", "S1")],
		..TestProcess::of("MinorProcess", "S1")
	};

	// A fault rates its severity on both scales from what its state reaches:
	// a deadlock, no terminal state, under half the states, under four fifths
	// of them, or the rest. A fault at a state the process lacks rates
	// mid-scale.
	crate::tb_cases! {
		fn a_fault_rates_its_severity((process, state, ratings): (Process, &str, (u8, u8))) {
			let fault = InjectedFaultRecord::at(state, "test_event");

			let mil = fault.severity(&process, SeverityScale::MilStd1629);
			let iso = fault.severity(&process, SeverityScale::Iso26262);
			assert_eq!((mil, iso), ratings);
		}

		cases {
			at_a_state_that_reaches_a_deadlock => (DEADLOCK.build(), "DeadlockProcess.Init", (10, 4)),
			at_a_state_that_cannot_reach_a_terminal_state => (NO_TERMINAL.build(), "NoTerminalProcess.Init", (9, 4)),
			at_a_state_that_reaches_under_half_the_states => (RESTRICTED.build(), "RestrictedProcess.A", (7, 3)),
			at_a_state_that_reaches_under_four_fifths_of_the_states => (MODERATE.build(), "ModerateProcess.A", (5, 2)),
			at_a_state_that_reaches_every_state => (MINOR.build(), "MinorProcess.S1", (3, 1)),
			at_a_bare_state_name => (TestProcess { name: "BareProcess", ..DEADLOCK }.build(), "Init", (10, 4)),
			at_mid_scale_for_a_state_the_process_lacks => (
				TestProcess { observable: &["event"], ..TestProcess::of("SimpleProcess", "Known") }.build(),
				"SimpleProcess.UnknownState",
				(5, 2),
			),
		}
	}

	// The occurrence rating maps a probability in basis points onto the scale.
	// Each row is (basis points, scale, expected occurrence rating).
	crate::tb_cases! {
		fn occurrence_boundary((bps, scale, expected): (u16, SeverityScale, u16)) {
			assert_eq!(scale.occurrence(bps), expected);
		}

		cases {
			mil_std_1629_at_zero => (0, SeverityScale::MilStd1629, 1),
			mil_std_1629_at_half => (5000, SeverityScale::MilStd1629, 6),
			mil_std_1629_at_full => (10000, SeverityScale::MilStd1629, 10),
			iso_26262_at_zero => (0, SeverityScale::Iso26262, 1),
			iso_26262_at_half => (5000, SeverityScale::Iso26262, 3),
			iso_26262_at_full => (10000, SeverityScale::Iso26262, 4),
		}
	}

	// The detection rating falls as the share of successful recoveries rises.
	// Each row is (recoveries successful, recoveries failed, scale, expected
	// detection rating).
	crate::tb_cases! {
		fn detection_rating((success, failed, scale, expected): (usize, usize, SeverityScale, u8)) {
			let verdict = FdrVerdict {
				error_recovery_successful: success,
				error_recovery_failed: failed,
				..Default::default()
			};
			assert_eq!(verdict.detection(scale), expected);
		}

		cases {
			every_recovery_succeeds => (10, 0, SeverityScale::MilStd1629, 1),
			every_recovery_fails => (0, 10, SeverityScale::MilStd1629, 10),
			half_the_recoveries_succeed => (5, 5, SeverityScale::MilStd1629, 5),
		}
	}
}
