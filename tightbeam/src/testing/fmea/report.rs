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
	/// The failure modes, one per injected fault in a generated report.
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
	/// Each fault rates at the state it names in the first of `processes` that
	/// holds that state. A fault whose state no process holds rates as a fault
	/// in an unknown state. A run that injected nothing has no failure modes,
	/// so the report is the empty one at the configured scale.
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
			.faults_injected
			.iter()
			.map(|fault| fault.failure_mode(&processes, self, &config))
			.collect();

		Ok(FmeaReport::new(
			failure_modes?,
			config.severity_scale,
			config.rpn_critical_threshold,
		))
	}
}

impl InjectedFaultRecord {
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
mod tests {
	use super::*;
	use crate::testing::fdr::{DefaultFdrExplorer, FaultModel, FdrConfig};
	use crate::testing::specs::csp::{Event, Process, State};
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

	// Test fixtures and helpers
	fn create_fault(state: impl AsRef<str>, event: impl AsRef<str>) -> InjectedFaultRecord {
		let state = state.as_ref();
		let event = event.as_ref();
		InjectedFaultRecord {
			csp_state: state.to_string(),
			event_label: event.to_string(),
			error_message: "Test fault".to_string(),
			probability_bps: 5000,
		}
	}

	fn assert_effect_contains(effects: impl AsRef<[String]>, expected: impl AsRef<str>, context: impl AsRef<str>) {
		let effects = effects.as_ref();
		let expected = expected.as_ref();
		let context = context.as_ref();
		assert!(!effects.is_empty(), "{}: Should identify effects", context);
		assert!(
			effects.iter().any(|e| e.contains(expected)),
			"{}: Expected '{}' in effects: {:?}",
			context,
			expected,
			effects
		);
	}

	// Configuration and type tests
	#[test]
	fn test_severity_scale_default() {
		assert_eq!(SeverityScale::default(), SeverityScale::MilStd1629);
	}

	#[test]
	fn test_fmea_config_default() {
		let config = FmeaConfig::default();
		assert_eq!(config.severity_scale, SeverityScale::MilStd1629);
		assert_eq!(config.rpn_critical_threshold, 100);
		assert!(config.auto_generate);
	}

	#[test]
	fn test_failure_mode_rpn_calculation() {
		let fm = FailureMode::new(
			"Test.State".to_string(),
			"event".to_string(),
			vec!["Effect".to_string()],
			8,
			50,
			6,
		);
		assert_eq!(fm.rpn, 8 * 50 * 6);
	}

	#[test]
	fn test_fmea_report_critical_identification() {
		let modes = vec![
			FailureMode::new("S1".to_string(), "e1".to_string(), vec![], 8, 50, 6),
			FailureMode::new("S2".to_string(), "e2".to_string(), vec![], 4, 20, 3),
		];

		let report = FmeaReport::new(modes, SeverityScale::MilStd1629, 1000);
		assert_eq!(report.total_rpn, 2400 + 240);
		assert_eq!(report.critical_failures, vec![0]);
	}

	// CSP reachability analysis tests
	#[test]
	fn test_analyze_effects_terminal_state_reachable() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("TestProcess")
			.add_observable(Event("start"))
			.add_observable(Event("finish"))
			.initial_state(State("Init"))
			.add_terminal(State("Success"))
			.add_transition(State("Init"), Event("start"), State("Running"))
			.add_transition(State("Running"), Event("finish"), State("Success"))
			.build()?;

		let effects = create_fault("TestProcess.Init", "start").effects(&[&process]);
		assert_effect_contains(&effects, "terminal state", "Terminal state detection");
		Ok(())
	}

	#[test]
	fn test_analyze_effects_deadlock_detection() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("DeadlockProcess")
			.add_observable(Event("start"))
			.initial_state(State("Init"))
			.add_transition(State("Init"), Event("start"), State("Blocked"))
			.build()?;

		let effects = create_fault("DeadlockProcess.Init", "start").effects(&[&process]);
		assert_effect_contains(&effects, "deadlock", "Deadlock detection");
		Ok(())
	}

	#[test]
	fn test_analyze_effects_state_space_restriction() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("RestrictedProcess")
			.add_observable(Event("to_a"))
			.add_observable(Event("to_b"))
			.add_observable(Event("to_c"))
			.initial_state(State("Init"))
			.add_transition(State("Init"), Event("to_a"), State("A"))
			.add_transition(State("A"), Event("to_b"), State("B"))
			.add_transition(State("B"), Event("to_c"), State("C"))
			.build()?;

		let effects = create_fault("RestrictedProcess.A", "to_b").effects(&[&process]);
		assert_effect_contains(&effects, "Restricts reachable states", "State space restriction");

		Ok(())
	}

	#[test]
	fn test_analyze_effects_unknown_state() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("SimpleProcess")
			.add_observable(Event("event"))
			.initial_state(State("Known"))
			.build()?;

		let effects = create_fault("SimpleProcess.UnknownState", "event").effects(&[&process]);
		assert_eq!(effects.len(), 1);
		assert!(effects[0].contains("unknown state"));
		Ok(())
	}

	#[test]
	fn test_analyze_effects_default_message() -> Result<(), Box<dyn core::error::Error>> {
		let process = Process::builder("NormalProcess")
			.add_observable(Event("event1"))
			.add_observable(Event("event2"))
			.initial_state(State("S1"))
			.add_transition(State("S1"), Event("event1"), State("S2"))
			.add_transition(State("S2"), Event("event2"), State("S3"))
			.add_transition(State("S3"), Event("event1"), State("S1"))
			.build()?;

		let effects = create_fault("NormalProcess.S1", "event1").effects(&[&process]);
		assert_effect_contains(&effects, "state transition failure", "Default message");
		Ok(())
	}

	#[test]
	fn a_generated_report_traces_the_effects_from_the_fault_state() -> Result<(), Box<dyn core::error::Error>> {
		let fault = || TightBeamError::ChannelClosed;
		let event = link::Event(SEND);
		let fault_model = FaultModel::default().with_fault(link::States::Ready, event, fault, crate::bps!(10000));
		let config = FdrConfig {
			seeds: 1,
			specs: vec![Link::process()?],
			fault_model: Some(fault_model),
			fmea_config: Some(FmeaConfig::default()),
			..FdrConfig::default()
		};

		let process = Link::process()?;
		let verdict = DefaultFdrExplorer::with_defaults(&process, config).explore()?;
		let modes = verdict.fmea_report.map(|report| report.failure_modes).unwrap_or_default();

		let effects: Vec<Vec<String>> = modes.into_iter().map(|mode| mode.effects).collect();
		assert_eq!(effects, [["Can reach terminal state(s): Done"]]);
		Ok(())
	}
}
