//! Extension Trait for ConsumedTrace with FDR Analysis
//!
//! Provides FDR-specific analysis capabilities for execution traces.
//! This module is FDR-specific: trace-to-process conversion is used for refinement checking
//! (comparing trace_process ⊑ spec_process), not for general CSP validation.

use std::collections::HashSet;
use std::io::Write;

use crate::policy::TransitStatus;
use crate::testing::assertions::AssertionLabel;
use crate::testing::fdr::config::AcceptanceSet;
use crate::testing::specs::csp::{Event, Process, State, TransitionRelation};
use crate::trace::ConsumedTrace;

/// State labels used in FDR trace analysis
pub const INITIAL: &str = "initial";
pub const GATE_ACCEPT: &str = "gate_accept";
pub const HANDLER: &str = "handler";
pub const GATE_REJECT: &str = "gate_reject";
pub const TERMINAL: &str = "terminal";

/// Mode for converting trace to CSP process (FDR-specific)
///
/// Controls which events are included when converting a `ConsumedTrace` to a
/// `Process` for FDR refinement checking. This is distinct from
/// `InstrumentationMode` which controls runtime capture; this controls
/// post-processing selection.
///
/// Note: Requires `enable_internal_detail: true` in
/// `InstrumentationMode::Custom` to capture hidden events for
/// `FullInstrumentation` mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceProcessMode {
	/// Only include assertion events (default, backward compatible)
	AssertionsOnly,
	/// Include assertions + observable instrumentation events
	///
	/// Observable events: GateAccept, GateReject, RequestRecv, ResponseSend, AssertLabel
	/// Useful when your CSP spec models the full protocol flow including gate decisions
	#[cfg(feature = "instrument")]
	WithObservableInstrumentation,
	/// Include all events: assertions + observable + hidden instrumentation
	///
	/// Hidden events: HandlerEnter, HandlerExit, CryptoStep, CompressStep, RouteStep, PolicyEval
	/// Requires `enable_internal_detail: true` in instrumentation config
	#[cfg(feature = "instrument")]
	FullInstrumentation,
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
	///
	/// Creates a linear process model representing the execution trace. This is used for
	/// refinement checking: `trace_process ⊑ spec_process`.
	///
	/// By default, only includes assertion events. Use `to_process_with_mode()` to include
	/// instrumentation events (requires `instrument` feature).
	fn to_process(&self) -> Process {
		self.to_process_with_mode(TraceProcessMode::AssertionsOnly)
	}

	/// Convert ConsumedTrace to CSP Process with specified event inclusion mode
	///
	/// See `TraceProcessMode` for available modes. Note that `FullInstrumentation` requires
	/// `enable_internal_detail: true` in the instrumentation configuration.
	fn to_process_with_mode(&self, mode: TraceProcessMode) -> Process;
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
		if matches!(self.gate_decision, Some(TransitStatus::Accepted))
			&& self.assertions.is_empty()
			&& self.response.is_none()
		{
			return false; // Handler should have done something
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
				// Accepted path: should have response or assertions (indicating handler execution)
				self.response.is_some() || !self.assertions.is_empty()
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
	/// Creates a linear process model representing the execution trace.
	/// Creates a strictly linear, acyclic chain to avoid infinite BFS exploration.
	/// The trace process represents a single execution path.
	fn to_process_with_mode(&self, mode: TraceProcessMode) -> Process {
		let mut states = HashSet::new();
		let mut terminal = HashSet::new();
		let mut observable = HashSet::new();
		let mut hidden = HashSet::new();
		let mut transitions = TransitionRelation::new();

		let s_initial = State(INITIAL);
		let s_terminal = State(TERMINAL);

		states.insert(s_initial);
		states.insert(s_terminal);
		terminal.insert(s_terminal);

		// Collect events based on mode
		#[derive(Clone)]
		enum TraceEvent {
			Assertion {
				seq: usize,
				label: &'static str,
			},
			#[cfg(feature = "instrument")]
			ObservableInstrumentation {
				seq: u32,
				label: String,
			},
			#[cfg(feature = "instrument")]
			HiddenInstrumentation {
				seq: u32,
				label: String,
			},
		}

		let mut events: Vec<TraceEvent> = Vec::new();

		// Always include assertions
		for assertion in &self.assertions {
			let AssertionLabel::Custom(label) = &assertion.label;
			events.push(TraceEvent::Assertion { seq: assertion.seq, label });
		}

		// Include instrumentation events based on mode
		#[cfg(feature = "instrument")]
		{
			use crate::instrumentation::TbEventKind;

			match mode {
				TraceProcessMode::AssertionsOnly => {
					// No instrumentation events
				}
				TraceProcessMode::WithObservableInstrumentation | TraceProcessMode::FullInstrumentation => {
					// Include observable instrumentation events
					for event in &self.instrument_events {
						if matches!(
							event.kind,
							TbEventKind::GateAccept
								| TbEventKind::GateReject
								| TbEventKind::RequestRecv
								| TbEventKind::ResponseSend
								| TbEventKind::AssertLabel
						) {
							if let Some(label) = &event.label {
								events.push(TraceEvent::ObservableInstrumentation {
									seq: event.seq,
									label: label.clone(),
								});
							}
						}
					}
				}
			}

			if matches!(mode, TraceProcessMode::FullInstrumentation) {
				// Include hidden instrumentation events
				for event in &self.instrument_events {
					if matches!(
						event.kind,
						TbEventKind::HandlerEnter
							| TbEventKind::HandlerExit
							| TbEventKind::CryptoStep
							| TbEventKind::CompressStep
							| TbEventKind::RouteStep
							| TbEventKind::PolicyEval
							| TbEventKind::ProcessHidden
					) {
						if let Some(label) = &event.label {
							events.push(TraceEvent::HiddenInstrumentation { seq: event.seq, label: label.clone() });
						}
					}
				}
			}
		}

		// Sort events by sequence number to preserve execution order
		events.sort_by(|a, b| {
			let seq_a = match a {
				TraceEvent::Assertion { seq, .. } => *seq as u64,
				#[cfg(feature = "instrument")]
				TraceEvent::ObservableInstrumentation { seq, .. } | TraceEvent::HiddenInstrumentation { seq, .. } => *seq as u64,
			};
			let seq_b = match b {
				TraceEvent::Assertion { seq, .. } => *seq as u64,
				#[cfg(feature = "instrument")]
				TraceEvent::ObservableInstrumentation { seq, .. } | TraceEvent::HiddenInstrumentation { seq, .. } => *seq as u64,
			};
			seq_a.cmp(&seq_b)
		});

		// Build transitions from sorted events
		if !events.is_empty() {
			let mut from_state = s_initial;
			for (idx, event) in events.iter().enumerate() {
				let (event, is_hidden) = match event {
					TraceEvent::Assertion { label, .. } => (Event(label), false),
					#[cfg(feature = "instrument")]
					TraceEvent::ObservableInstrumentation { label, .. } => {
						let static_label: &'static str = Box::leak(label.clone().into_boxed_str());
						(Event(static_label), false)
					}
					#[cfg(feature = "instrument")]
					TraceEvent::HiddenInstrumentation { label, .. } => {
						let static_label: &'static str = Box::leak(label.clone().into_boxed_str());
						(Event(static_label), true)
					}
				};

				// Add to appropriate alphabet
				if is_hidden {
					hidden.insert(event.clone());
				} else {
					observable.insert(event.clone());
				}

				// Add transition: last event goes to terminal, others use intermediate states
				let to_state = if idx == events.len() - 1 {
					s_terminal
				} else {
					let state_name: &'static str = Box::leak(format!("trace_state_{idx}").into_boxed_str());
					let to_state = State(state_name);
					states.insert(to_state);
					to_state
				};

				transitions.add(from_state, event, to_state);
				from_state = to_state;
			}
		}

		// If no events, the process is just initial -> terminal with no events
		// This represents SKIP/STOP - a process that can do nothing

		let description = match mode {
			TraceProcessMode::AssertionsOnly => "Process derived from ConsumedTrace (assertion events only)",
			#[cfg(feature = "instrument")]
			TraceProcessMode::WithObservableInstrumentation => {
				"Process derived from ConsumedTrace (assertions + observable instrumentation)"
			}
			#[cfg(feature = "instrument")]
			TraceProcessMode::FullInstrumentation => {
				"Process derived from ConsumedTrace (all events including hidden instrumentation)"
			}
		};

		Process {
			name: "TraceProcess",
			initial: s_initial,
			states,
			terminal,
			choice: HashSet::new(), // No nondeterminism in a single trace
			observable,
			hidden,
			transitions,
			description: Some(description),
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-timing")]
			timed_transitions: None,
		}
	}
}

// Convenience implementation on ConsumedTrace for FDR refinement checking
impl ConsumedTrace {
	/// Convert this trace to a CSP Process for FDR refinement checking
	///
	/// This is a convenience wrapper around `FdrTraceExt::to_process()`.
	/// See `FdrTraceExt` trait for details.
	pub fn to_process(&self) -> Process {
		<Self as FdrTraceExt>::to_process(self)
	}

	/// Convert this trace to a CSP Process with specified event inclusion mode
	///
	/// This is a convenience wrapper around `FdrTraceExt::to_process_with_mode()`.
	/// See `FdrTraceExt` trait for details.
	pub fn to_process_with_mode(&self, mode: TraceProcessMode) -> Process {
		<Self as FdrTraceExt>::to_process_with_mode(self, mode)
	}
}
