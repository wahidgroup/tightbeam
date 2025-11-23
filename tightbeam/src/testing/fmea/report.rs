//! FMEA report types and generation

use std::collections::{HashSet, VecDeque};

use crate::testing::fdr::{FdrVerdict, InjectedFaultRecord};
use crate::testing::fmea::analysis::{calculate_detection, calculate_severity, convert_occurrence};
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
	pub severity_scale: SeverityScale,
	pub rpn_critical_threshold: u32,
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
	pub component: String,
	pub failure: String,
	pub effects: Vec<String>,
	pub severity: u8,
	pub occurrence: u16,
	pub detection: u8,
	pub rpn: u32,
}

impl FailureMode {
	/// Create new failure mode with calculated RPN
	pub fn new(
		component: String,
		failure: String,
		effects: Vec<String>,
		severity: u8,
		occurrence: u16,
		detection: u8,
	) -> Self {
		let rpn = (severity as u32) * (occurrence as u32) * (detection as u32);
		Self { component, failure, effects, severity, occurrence, detection, rpn }
	}
}

/// FMEA report
#[derive(Debug, Clone, PartialEq)]
pub struct FmeaReport {
	pub failure_modes: Vec<FailureMode>,
	pub severity_scale: SeverityScale,
	pub total_rpn: u32,
	pub critical_failures: Vec<usize>,
}

impl FmeaReport {
	/// Create new FMEA report with calculated totals
	pub fn new(failure_modes: Vec<FailureMode>, severity_scale: SeverityScale, rpn_threshold: u32) -> Self {
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

/// Generate FMEA report from FDR verdict
pub fn generate_fmea_report(
	verdict: &FdrVerdict,
	process: &Process,
	config: Option<FmeaConfig>,
) -> Result<FmeaReport, TightBeamError> {
	let config = config.unwrap_or_default();

	if verdict.faults_injected.is_empty() {
		return Ok(FmeaReport::new(
			Vec::new(),
			config.severity_scale,
			config.rpn_critical_threshold,
		));
	}

	let failure_modes: Result<Vec<_>, _> = verdict
		.faults_injected
		.iter()
		.map(|fault| analyze_fault(fault, process, verdict, &config))
		.collect();

	Ok(FmeaReport::new(
		failure_modes?,
		config.severity_scale,
		config.rpn_critical_threshold,
	))
}

/// Analyze individual fault to create failure mode entry
fn analyze_fault(
	fault: &InjectedFaultRecord,
	process: &Process,
	verdict: &FdrVerdict,
	config: &FmeaConfig,
) -> Result<FailureMode, TightBeamError> {
	let severity = calculate_severity(fault, process, config.severity_scale);
	let occurrence = convert_occurrence(fault.probability_bps, config.severity_scale);
	let detection = calculate_detection(verdict, config.severity_scale);
	let effects = analyze_effects(fault, process);

	Ok(FailureMode::new(
		fault.csp_state.clone(),
		fault.event_label.clone(),
		effects,
		severity,
		occurrence,
		detection,
	))
}

/// Analyze effects via CSP reachability analysis
fn analyze_effects(fault: &InjectedFaultRecord, process: &Process) -> Vec<String> {
	let mut effects = Vec::new();

	// Find the state where the fault occurs
	let fault_state = process.states.iter().find(|s| s.0 == fault.csp_state.as_str()).copied();
	let Some(fault_state) = fault_state else {
		effects.push(format!("Fault occurs in unknown state: {}", fault.csp_state));
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
		// Check for potential deadlock (no enabled transitions, not terminal)
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
		effects.push(format!("Fault during {} may cause state transition failure", fault.event_label));
	}

	effects
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::{Process, State};

	// Test fixtures and helpers
	fn create_fault(state: &str, event: &str) -> InjectedFaultRecord {
		InjectedFaultRecord {
			csp_state: state.to_string(),
			event_label: event.to_string(),
			error_message: "Test fault".to_string(),
			probability_bps: 5000,
		}
	}

	fn assert_effect_contains(effects: &[String], expected: &str, context: &str) {
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
	fn test_analyze_effects_terminal_state_reachable() {
		let process = Process::builder("TestProcess")
			.add_observable("start")
			.add_observable("finish")
			.initial_state(State("Init"))
			.add_terminal(State("Success"))
			.add_transition(State("Init"), "start", State("Running"))
			.add_transition(State("Running"), "finish", State("Success"))
			.build()
			.unwrap();

		let effects = analyze_effects(&create_fault("Init", "start"), &process);
		assert_effect_contains(&effects, "terminal state", "Terminal state detection");
	}

	#[test]
	fn test_analyze_effects_deadlock_detection() {
		let process = Process::builder("DeadlockProcess")
			.add_observable("start")
			.initial_state(State("Init"))
			.add_transition(State("Init"), "start", State("Blocked"))
			.build()
			.unwrap();

		let effects = analyze_effects(&create_fault("Init", "start"), &process);
		assert_effect_contains(&effects, "deadlock", "Deadlock detection");
	}

	#[test]
	fn test_analyze_effects_state_space_restriction() {
		let process = Process::builder("RestrictedProcess")
			.add_observable("to_a")
			.add_observable("to_b")
			.add_observable("to_c")
			.initial_state(State("Init"))
			.add_transition(State("Init"), "to_a", State("A"))
			.add_transition(State("A"), "to_b", State("B"))
			.add_transition(State("B"), "to_c", State("C"))
			.build()
			.unwrap();

		let effects = analyze_effects(&create_fault("A", "to_b"), &process);
		assert_effect_contains(&effects, "Restricts reachable states", "State space restriction");
	}

	#[test]
	fn test_analyze_effects_unknown_state() {
		let process = Process::builder("SimpleProcess")
			.add_observable("event")
			.initial_state(State("Known"))
			.build()
			.unwrap();

		let effects = analyze_effects(&create_fault("UnknownState", "event"), &process);
		assert_eq!(effects.len(), 1);
		assert!(effects[0].contains("unknown state"));
	}

	#[test]
	fn test_analyze_effects_default_message() {
		let process = Process::builder("NormalProcess")
			.add_observable("event1")
			.add_observable("event2")
			.initial_state(State("S1"))
			.add_transition(State("S1"), "event1", State("S2"))
			.add_transition(State("S2"), "event2", State("S3"))
			.add_transition(State("S3"), "event1", State("S1"))
			.build()
			.unwrap();

		let effects = analyze_effects(&create_fault("S1", "event1"), &process);
		assert_effect_contains(&effects, "state transition failure", "Default message");
	}
}
