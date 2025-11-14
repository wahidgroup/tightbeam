//! Extension Trait for ConsumedTrace with FDR Analysis
//!
//! Provides CSP-specific analysis capabilities for execution traces.
#![cfg(feature = "std")]

use std::io::Write;

use std::collections::HashSet;

use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionLabel, AssertionPhase};
use crate::testing::fdr::config::AcceptanceSet;
use crate::testing::specs::csp::{Event, Process, State, TransitionRelation};
use crate::testing::trace::ConsumedTrace;

/// State labels used in FDR trace analysis
mod state_labels {
	pub const INITIAL: &str = "initial";
	pub const GATE_ACCEPT: &str = "gate_accept";
	pub const HANDLER: &str = "handler";
	pub const GATE_REJECT: &str = "gate_reject";
	pub const TERMINAL: &str = "terminal";
}

/// Extension trait for ConsumedTrace with FDR analysis
pub trait FdrTraceExt {
	/// Check if CSP trace is valid
	fn csp_valid(&self) -> bool;

	/// Check if terminated in valid terminal state
	fn terminated_in_valid_state(&self) -> bool;

	/// Get acceptance set after current trace
	fn acceptance_at(&self, state_label: &str) -> Option<AcceptanceSet>;

	/// Check if process can refuse event after state
	fn can_refuse_after(&self, state_label: &str, event_label: &str) -> bool;

	/// Count assertion by label (convenience)
	fn assertion_count(&self, label: &str) -> usize;

	/// Project trace to observable events only
	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String>;

	/// Project trace to hidden events only
	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String>;

	/// Export trace as CSPM
	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()>;

	/// Convert ConsumedTrace to CSP Process for FDR refinement checking
	fn to_process(&self) -> Process;
}

impl FdrTraceExt for ConsumedTrace {
	fn csp_valid(&self) -> bool {
		// Trace is valid if:
		// 1. No transport errors occurred
		// 2. Gate decision was reached (Accept or Reject)
		// 3. If accepted, handler executed (evidenced by assertions)
		if self.error.is_some() {
			return false;
		}

		// Must have a gate decision (part of the protocol)
		if self.gate_decision.is_none() {
			return false;
		}

		// If gate accepted, we expect handler evidence (assertions or response)
		if matches!(self.gate_decision, Some(TransitStatus::Accepted)) {
			if self.assertions.is_empty() && self.response.is_none() {
				return false; // Handler should have done something
			}
		}

		true
	}

	fn terminated_in_valid_state(&self) -> bool {
		// Check if execution completed successfully in a terminal state:
		// 1. No errors
		// 2. Gate decision reached
		// 3. For accepted requests: response generated or terminal assertions present
		if self.error.is_some() {
			return false;
		}

		match self.gate_decision {
			Some(TransitStatus::Accepted) => {
				// Accepted path: should have response or handler-end assertions
				self.response.is_some() || self.assertions.iter().any(|a| a.phase == AssertionPhase::HandlerEnd)
			}
			Some(TransitStatus::Busy)
			| Some(TransitStatus::Unauthorized)
			| Some(TransitStatus::Forbidden)
			| Some(TransitStatus::Timeout) => {
				// Rejection paths are terminal by definition
				true
			}
			Some(TransitStatus::Request) | None => false, // No decision = incomplete execution
		}
	}

	fn acceptance_at(&self, state_label: &str) -> Option<AcceptanceSet> {
		// Compute acceptance set based on trace structure at given state
		// State labels in ConsumedTrace context:
		// - "initial": before gate
		// - "gate_accept": after gate accepts
		// - "handler": during handler execution
		// - "terminal": after response/rejection
		use state_labels::*;

		let mut acceptance = AcceptanceSet::new();

		match state_label {
			INITIAL => {
				// At initial state, we can accept request frame
				acceptance.insert(Event("request"));
			}
			GATE_ACCEPT => {
				// After gate accepts, handler can process
				acceptance.insert(Event("handler_enter"));
			}
			HANDLER => {
				// During handler, can do internal operations or exit
				acceptance.insert(Event("handler_exit"));
				acceptance.insert(Event("response"));
			}
			GATE_REJECT | TERMINAL => {
				// Rejection/terminal states accept nothing
			}
			_ => {
				// Unknown state label
				return None;
			}
		}

		Some(acceptance)
	}

	fn can_refuse_after(&self, state_label: &str, event_label: &str) -> bool {
		// Event can be refused if it's not in the acceptance set at that state
		if let Some(acceptance) = self.acceptance_at(state_label) {
			// Check if the event label matches any in the acceptance set
			!acceptance.iter().any(|e| e.0 == event_label)
		} else {
			// Unknown state: conservatively assume can refuse
			true
		}
	}

	fn assertion_count(&self, label: &str) -> usize {
		self.assertions
			.iter()
			.filter(|a| matches!(&a.label, AssertionLabel::Custom(l) if *l == label))
			.count()
	}

	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String> {
		use crate::instrumentation::TbEventKind;

		self.instrument_events
			.iter()
			.filter(|e| {
				matches!(
					e.kind,
					TbEventKind::GateAccept
						| TbEventKind::GateReject
						| TbEventKind::RequestRecv
						| TbEventKind::ResponseSend
						| TbEventKind::AssertLabel
				)
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String> {
		use crate::instrumentation::TbEventKind;

		self.instrument_events
			.iter()
			.filter(|e| {
				matches!(
					e.kind,
					TbEventKind::HandlerEnter
						| TbEventKind::HandlerExit
						| TbEventKind::CryptoStep
						| TbEventKind::CompressStep
						| TbEventKind::RouteStep
						| TbEventKind::PolicyEval
						| TbEventKind::ProcessHidden
				)
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writeln!(writer, "-- Execution trace")?;
		writeln!(writer, "Trace = <")?;

		#[cfg(feature = "instrument")]
		{
			let observable = self.project_to_observable();
			for (idx, event) in observable.iter().enumerate() {
				if idx > 0 {
					write!(writer, ", ")?;
				}
				write!(writer, "{event}")?;
			}
		}

		writeln!(writer, ">")?;
		Ok(())
	}

	/// Convert ConsumedTrace to CSP Process for FDR refinement checking
	///
	/// Creates a linear process model representing the execution trace:
	/// - States correspond to execution stages (initial, gate_accept, handler, terminal)
	/// - Observable events are derived from assertion labels
	/// - Hidden events represent internal operations
	fn to_process(&self) -> Process {
		use state_labels::*;

		let mut states = HashSet::new();
		let mut terminal = HashSet::new();
		let mut observable = HashSet::new();
		let mut hidden = HashSet::new();
		let mut transitions = TransitionRelation::new();

		// Define states based on execution stages
		let s_initial = State(INITIAL);
		let s_gate_accept = State(GATE_ACCEPT);
		let s_handler = State(HANDLER);
		let s_gate_reject = State(GATE_REJECT);
		let s_terminal = State(TERMINAL);

		states.insert(s_initial.clone());
		states.insert(s_gate_accept.clone());
		states.insert(s_handler.clone());
		states.insert(s_gate_reject.clone());
		states.insert(s_terminal.clone());

		// Terminal state is always terminal
		terminal.insert(s_terminal.clone());

		// Build transitions based on trace execution path
		match self.gate_decision {
			Some(TransitStatus::Accepted) => {
				// Path: initial -> gate_accept -> handler -> terminal
				let request_event = Event("request");
				observable.insert(request_event.clone());
				transitions.add(s_initial.clone(), request_event, s_gate_accept.clone());

				let handler_enter_event = Event("handler_enter");
				hidden.insert(handler_enter_event.clone());
				transitions.add(s_gate_accept.clone(), handler_enter_event, s_handler.clone());

				// Add transitions for each assertion as observable event
				for assertion in &self.assertions {
					if let AssertionLabel::Custom(label) = &assertion.label {
						let event = Event(*label);
						observable.insert(event.clone());
						transitions.add(s_handler.clone(), event, s_handler.clone());
					}
				}

				// Handler exit -> terminal
				let handler_exit_event = Event("handler_exit");
				hidden.insert(handler_exit_event.clone());
				transitions.add(s_handler.clone(), handler_exit_event, s_terminal.clone());

				// Response event if present
				if self.response.is_some() {
					let response_event = Event("response");
					observable.insert(response_event.clone());
					transitions.add(s_handler.clone(), response_event, s_terminal.clone());
				}
			}
			Some(_) => {
				// Rejection path: initial -> gate_reject -> terminal
				let request_event = Event("request");
				observable.insert(request_event.clone());
				transitions.add(s_initial.clone(), request_event, s_gate_reject.clone());
				transitions.add(s_gate_reject.clone(), Event("reject"), s_terminal.clone());
				observable.insert(Event("reject"));
			}
			None => {
				// No gate decision - just initial state, no transitions
			}
		}

		Process {
			name: "TraceProcess",
			initial: s_initial,
			states,
			terminal,
			choice: HashSet::new(), // No nondeterminism in a single trace
			observable,
			hidden,
			transitions,
			description: Some("Process derived from ConsumedTrace"),
		}
	}
}

impl ConsumedTrace {
	/// Convert this trace to a CSP Process for FDR refinement checking
	pub fn to_process(&self) -> Process {
		<Self as FdrTraceExt>::to_process(self)
	}
}
