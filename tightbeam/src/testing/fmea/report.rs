//! FMEA report types and generation

use std::collections::{HashSet, VecDeque};

use crate::testing::fdr::{FdrVerdict, InjectedFaultRecord};
use crate::testing::specs::csp::Process;
use crate::TightBeamError;

/// Severity scale for FMEA analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeverityScale {
	/// MIL-STD-1629 scale (1-10)
	#[default]
	MilStd1629,
	/// ISO 26262 automotive scale (1-4: catastrophic, hazardous, major, minor)
	Iso26262,
}

/// FMEA configuration
#[derive(Debug, Clone)]
pub struct FmeaConfig {
	/// The scale of the severity, occurrence, and detection ratings.
	pub severity_scale: SeverityScale,
	/// The RPN above which a failure mode is critical, 100 by default.
	pub rpn_critical_threshold: u32,
	/// Whether an FDR run that injects a fault puts the report in its verdict.
	pub auto_generate: bool,
}

impl Default for FmeaConfig {
	fn default() -> Self {
		Self {
			severity_scale: SeverityScale::MilStd1629,
			rpn_critical_threshold: 100,
			auto_generate: true,
		}
	}
}

/// Individual failure mode entry
#[derive(Debug, Clone, PartialEq)]
pub struct FailureMode {
	/// The component that fails, which a generated report names by the CSP
	/// state of the fault, as `Process.State`.
	pub component: String,
	/// The failure, which a generated report names by the event label of the
	/// fault.
	pub failure: String,
	/// The effects that the CSP reachability of the fault state finds.
	pub effects: Vec<String>,
	/// The severity rating, from the CSP reachability of the fault state.
	pub severity: u8,
	/// The occurrence rating, from the injection probability in basis points.
	pub occurrence: u16,
	/// The detection rating, from the error-recovery statistics of the run.
	pub detection: u8,
	/// The risk priority number, severity × occurrence × detection.
	pub rpn: u32,
}

impl FailureMode {
	/// Create new failure mode with calculated RPN
	pub fn new(
		component: impl Into<String>,
		failure: impl Into<String>,
		effects: impl IntoIterator<Item = String>,
		severity: u8,
		occurrence: u16,
		detection: u8,
	) -> Self {
		let component: String = component.into();
		let failure: String = failure.into();
		let effects: Vec<String> = effects.into_iter().collect();
		let rpn = (severity as u32) * (occurrence as u32) * (detection as u32);
		Self { component, failure, effects, severity, occurrence, detection, rpn }
	}
}

/// FMEA report
#[derive(Debug, Clone, PartialEq)]
pub struct FmeaReport {
	/// The failure modes, one per injection point that fired in a generated
	/// report.
	pub failure_modes: Vec<FailureMode>,
	/// The scale of every rating in the report.
	pub severity_scale: SeverityScale,
	/// The aggregate risk priority, the sum of the RPN of every failure mode.
	pub total_rpn: u32,
	/// The index in `failure_modes` of each failure mode whose RPN exceeds the
	/// critical threshold.
	pub critical_failures: Vec<usize>,
}

impl FmeaReport {
	/// Create new FMEA report with calculated totals
	pub fn new(
		failure_modes: impl IntoIterator<Item = FailureMode>,
		severity_scale: SeverityScale,
		rpn_threshold: u32,
	) -> Self {
		let failure_modes: Vec<FailureMode> = failure_modes.into_iter().collect();
		let total_rpn: u32 = failure_modes.iter().map(|fm| fm.rpn).sum();
		let critical_failures: Vec<usize> = failure_modes
			.iter()
			.enumerate()
			.filter_map(|(idx, fm)| {
				if fm.rpn > rpn_threshold {
					Some(idx)
				} else {
					None
				}
			})
			.collect();

		Self { failure_modes, severity_scale, total_rpn, critical_failures }
	}
}

impl FdrVerdict {
	/// FMEA report over the faults this run injected.
	///
	/// - Each injection point that fired is one failure mode, however many seeds it fired in.
	/// - The fault of a point rates at its state in the first of `processes` that holds that state.
	/// - A fault whose state no process holds rates as a fault in an unknown state.
	/// - A run that injected nothing has no failure modes, so the report is the
	///   empty one at the configured scale.
	///
	/// # Errors
	///
	/// The first failure-mode analysis that fails.
	pub fn fmea_report<'p>(
		&self,
		processes: impl IntoIterator<Item = &'p Process>,
		config: Option<FmeaConfig>,
	) -> Result<FmeaReport, TightBeamError> {
		let config = config.unwrap_or_default();
		let processes: Vec<&Process> = processes.into_iter().collect();
		let failure_modes: Result<Vec<_>, _> = self
			.fault_points()
			.map(|fault| fault.failure_mode(&processes, self, &config))
			.collect();

		Ok(FmeaReport::new(
			failure_modes?,
			config.severity_scale,
			config.rpn_critical_threshold,
		))
	}

	/// The first record of each injection point among the faults this run
	/// injected, in the order of injection.
	///
	/// The records of one point name its state, its event, and its
	/// probability, and the verdict rates the detection of the whole run, so
	/// each record of the point gives the one failure mode of the point.
	fn fault_points(&self) -> impl Iterator<Item = &InjectedFaultRecord> {
		let mut seen = HashSet::new();
		self.faults_injected.iter().filter(move |fault| seen.insert(fault.point()))
	}
}

impl InjectedFaultRecord {
	/// The injection point of this fault, as its state and its event.
	fn point(&self) -> (&str, &str) {
		(&self.csp_state, &self.event_label)
	}

	/// Failure-mode entry for this fault: severity, occurrence, detection,
	/// and the effects reachability analysis found.
	///
	/// # Errors
	///
	/// Whatever [`FailureMode::new`] reports.
	fn failure_mode(
		&self,
		processes: &[&Process],
		verdict: &FdrVerdict,
		config: &FmeaConfig,
	) -> Result<FailureMode, TightBeamError> {
		Ok(FailureMode::new(
			self.csp_state.clone(),
			self.event_label.clone(),
			self.effects(processes),
			self.severity_in(processes, config.severity_scale),
			config.severity_scale.occurrence(self.probability_bps),
			verdict.detection(config.severity_scale),
		))
	}

	/// Effects of this fault at its site among `processes`, via CSP
	/// reachability analysis.
	fn effects(&self, processes: &[&Process]) -> Vec<String> {
		let mut effects = Vec::new();

		// Find the state where the fault occurs
		let Some((process, fault_state)) = self.site_in(processes) else {
			effects.push(format!("Fault occurs in unknown state: {}", self.csp_state));
			return effects;
		};

		// BFS to explore reachable states from fault point
		let mut visited = HashSet::new();
		let mut queue = VecDeque::new();
		queue.push_back(fault_state);
		visited.insert(fault_state);

		let mut reachable_terminals = Vec::new();
		let mut potential_deadlocks = Vec::new();
		while let Some(current_state) = queue.pop_front() {
			// Check if terminal
			if process.is_terminal(current_state) {
				reachable_terminals.push(current_state.0);
				continue;
			}

			// Get enabled transitions
			// A non-terminal state with no enabled transition can deadlock.
			let enabled = process.enabled(current_state);
			if enabled.is_empty() {
				potential_deadlocks.push(current_state.0);
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

		// Generate effect descriptions
		if !reachable_terminals.is_empty() {
			effects.push(format!("Can reach terminal state(s): {}", reachable_terminals.join(", ")));
		}
		if !potential_deadlocks.is_empty() {
			effects.push(format!("Potential deadlock in state(s): {}", potential_deadlocks.join(", ")));
		}

		// If fault leads to reduced state space
		let total_states = process.states.len();
		let reachable_count = visited.len();
		if reachable_count < total_states {
			effects.push(format!(
				"Restricts reachable states to {} of {} total states",
				reachable_count, total_states
			));
		}

		// Default if no specific effects identified
		if effects.is_empty() {
			effects.push(format!("Fault during {} may cause state transition failure", self.event_label));
		}

		effects
	}
}

#[cfg(test)]
impl InjectedFaultRecord {
	/// A fault of `event` at `state`, which a run injects at a probability of
	/// 5,000 basis points.
	pub(crate) fn at(state: impl AsRef<str>, event: impl AsRef<str>) -> Self {
		InjectedFaultRecord {
			csp_state: state.as_ref().to_string(),
			event_label: event.as_ref().to_string(),
			error_message: "Test fault".to_string(),
			probability_bps: 5000,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::fdr::{FaultModel, FdrConfig};
	use crate::testing::fixtures::TestProcess;
	use crate::testing::fmea::DEADLOCK;
	use crate::urn::Urn;

	const SEND: Urn<'static> = crate::urn!("test", "event:fmea-report/send");
	const ACK: Urn<'static> = crate::urn!("test", "event:fmea-report/ack");

	// A link that sends and then takes an acknowledgement, the process that
	// the generated report reads.
	crate::tb_process_spec! {
		pub Link,
		events { observable { SEND, ACK } hidden { } }
		states {
			Ready => { SEND => Sent },
			Sent => { ACK => Done }
		}
		terminal { Done }
	}

	// The fault of the generated report fires in `Ready`, so the call lists
	// that state alone.
	crate::tb_gen_process_types!(Link, Ready);

	/// A process whose `start` takes `Init` to `Running`, and whose `finish`
	/// takes `Running` to the terminal `Success`.
	const FINISHING: TestProcess = TestProcess {
		observable: &["start", "finish"],
		transitions: &[("Init", "start", "Running"), ("Running", "finish", "Success")],
		terminal: &["Success"],
		..TestProcess::of("TestProcess", "Init")
	};

	/// A process of four states in a line from `Init` to `C`, which is not
	/// terminal and offers no event.
	const RESTRICTED: TestProcess = TestProcess {
		observable: &["to_a", "to_b", "to_c"],
		transitions: &[("Init", "to_a", "A"), ("A", "to_b", "B"), ("B", "to_c", "C")],
		..TestProcess::of("RestrictedProcess", "Init")
	};

	/// A process whose three states lie on one cycle, with no terminal state.
	const CYCLE: TestProcess = TestProcess {
		observable: &["event1", "event2"],
		transitions: &[("S1", "event1", "S2"), ("S2", "event2", "S3"), ("S3", "event1", "S1")],
		..TestProcess::of("NormalProcess", "S1")
	};

	/// The report of two failure modes of RPN 2,400 and 240, past a critical
	/// threshold of 1,000.
	fn two_modes() -> FmeaReport {
		let modes = [
			FailureMode::new("S1", "e1", Vec::new(), 8, 50, 6),
			FailureMode::new("S2", "e2", Vec::new(), 4, 20, 3),
		];

		FmeaReport::new(modes, SeverityScale::MilStd1629, 1000)
	}

	/// The failure modes of the report that a run of `seeds` seeds generates,
	/// where every send in `Ready` fails.
	fn generated_modes(seeds: u32) -> Vec<FailureMode> {
		let fault = || TightBeamError::ChannelClosed;
		let event = link::Event(SEND);
		let fault_model = FaultModel::default().with_fault(link::States::Ready, event, fault, crate::bps!(10000));
		let link = Link::process().expect("the link spec builds");
		let config = FdrConfig {
			seeds,
			specs: vec![link.clone()],
			fault_model: Some(fault_model),
			fmea_config: Some(FmeaConfig::default()),
			..FdrConfig::default()
		};

		let verdict = link.verdict_under(config);
		verdict.fmea_report.map(|report| report.failure_modes).unwrap_or_default()
	}

	// These tests cover the defaults and the RPN arithmetic.

	/// A report rates on the MIL-STD-1629 scale by default.
	#[test]
	fn the_default_severity_scale_is_mil_std_1629() {
		assert_eq!(SeverityScale::default(), SeverityScale::MilStd1629);
	}

	/// The default config generates a report on the MIL-STD-1629 scale, with
	/// a critical RPN of 100.
	#[test]
	fn the_default_config_generates_a_mil_std_1629_report_with_a_critical_rpn_of_100() {
		let config = FmeaConfig::default();
		let settings = (config.severity_scale, config.rpn_critical_threshold, config.auto_generate);
		assert_eq!(settings, (SeverityScale::MilStd1629, 100, true));
	}

	/// The RPN of a failure mode is the product of its severity, occurrence,
	/// and detection ratings.
	#[test]
	fn a_failure_mode_rates_its_rpn_as_the_product_of_its_ratings() {
		let mode = FailureMode::new("Test.State", "event", ["Effect".to_string()], 8, 50, 6);
		assert_eq!(mode.rpn, 2_400);
	}

	/// The total RPN of a report is the sum of the RPN of its modes.
	#[test]
	fn a_report_sums_the_rpn_of_its_modes() {
		let report = two_modes();
		assert_eq!(report.total_rpn, 2_640);
	}

	/// A report flags each mode whose RPN passes its critical threshold, by
	/// its place in the report.
	#[test]
	fn a_report_flags_each_mode_past_its_critical_threshold() {
		let report = two_modes();
		assert_eq!(report.critical_failures, [0]);
	}

	// The CSP reachability analysis names each effect that the state of a fault
	// reaches: a terminal state, a deadlock, and a restricted reach. A fault at
	// a state the process lacks names that state, and a fault with no other
	// effect names a transition failure.
	crate::tb_cases! {
		fn a_fault_has_the_effects((process, state, event, effects): (Process, &str, &str, &[&str])) {
			let fault = InjectedFaultRecord::at(state, event);
			let found = fault.effects(&[&process]);
			assert_eq!(found, effects);
		}

		cases {
			of_a_reachable_terminal_state => (
				FINISHING.build(),
				"TestProcess.Init",
				"start",
				&["Can reach terminal state(s): Success"],
			),
			of_a_reachable_deadlock => (
				DEADLOCK.build(),
				"DeadlockProcess.Init",
				"start",
				&["Potential deadlock in state(s): Blocked"],
			),
			of_a_deadlock_and_a_restricted_reach => (
				RESTRICTED.build(),
				"RestrictedProcess.A",
				"to_b",
				&["Potential deadlock in state(s): C", "Restricts reachable states to 3 of 4 total states"],
			),
			of_an_unknown_state => (
				TestProcess { observable: &["event"], ..TestProcess::of("SimpleProcess", "Known") }.build(),
				"SimpleProcess.UnknownState",
				"event",
				&["Fault occurs in unknown state: SimpleProcess.UnknownState"],
			),
			of_a_transition_failure_where_no_other_effect_holds => (
				CYCLE.build(),
				"NormalProcess.S1",
				"event1",
				&["Fault during event1 may cause state transition failure"],
			),
		}
	}

	/// A generated report traces the effects of a fault from the state where
	/// it fires.
	#[test]
	fn a_generated_report_traces_the_effects_from_the_fault_state() {
		let modes = generated_modes(1);
		let effects: Vec<Vec<String>> = modes.into_iter().map(|mode| mode.effects).collect();
		assert_eq!(effects, [["Can reach terminal state(s): Done"]]);
	}

	/// A fault point that injects on every seed of a run is one failure mode
	/// of its report.
	#[test]
	fn a_fault_point_that_injects_on_every_seed_is_one_failure_mode() {
		let modes = generated_modes(4);
		assert_eq!(modes.len(), 1);
	}
}
