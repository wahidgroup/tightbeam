//! Execution trace capture and representation
//!
//! This module defines the `ConsumedTrace` structure that represents
//! a fully drained CBVOC execution. The trace captures all channel
//! events, phase transitions, and outcome state.

#[cfg(feature = "std")]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "std"))]
use alloc::sync::{Arc, Mutex};

use crate::policy::TransitStatus;
use crate::testing::assertions::{Assertion, AssertionLabel, AssertionPhase, AssertionValue};
use crate::transport::error::TransportError;
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::{TbEvent, TbEventKind};

/// Unified trace collector for assertions and instrumentation events.
///
/// This type replaces the separate AssertionCollector pattern, unifying
/// both assertions and instrumentation events into a single explicitly-passed
/// collector. This ensures async-safety and provides a consistent API for
/// trace collection.
#[derive(Clone)]
pub struct TraceCollector {
	assertions: Arc<Mutex<Vec<Assertion>>>,
	#[cfg(feature = "instrument")]
	events: Arc<Mutex<Vec<TbEvent>>>,
	#[cfg(feature = "testing-fuzz")]
	pub oracle: Option<crate::testing::fuzz::FuzzContext>,
}

impl TraceCollector {
	/// Create a new empty trace collector
	pub fn new() -> Self {
		Self {
			assertions: Arc::new(Mutex::new(Vec::new())),
			#[cfg(feature = "instrument")]
			events: Arc::new(Mutex::new(Vec::new())),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
		}
	}

	/// Create a trace collector with fuzz oracle (CSP-guided fuzzing)
	#[cfg(feature = "testing-fuzz")]
	pub fn with_fuzz_oracle(input: Vec<u8>, process: crate::testing::specs::csp::Process) -> Self {
		Self {
			assertions: Arc::new(Mutex::new(Vec::new())),
			#[cfg(feature = "instrument")]
			events: Arc::new(Mutex::new(Vec::new())),
			oracle: Some(crate::testing::fuzz::FuzzContext::new(input, process)),
		}
	}

	/// Get the fuzz oracle, panicking if not configured
	#[cfg(feature = "testing-fuzz")]
	pub fn oracle(&self) -> &crate::testing::fuzz::FuzzContext {
		self.oracle
			.as_ref()
			.expect("Oracle not configured - did you provide csp: parameter in tb_scenario!?")
	}

	/// Record an assertion
	pub fn assert(&self, phase: AssertionPhase, label: &str) {
		self.assert_with_payload(phase, label, None);
	}

	/// Record an assertion without caring about phase (convenience for FDR/CSP scenarios)
	///
	/// This is a convenience method for scenarios where the lifecycle phase doesn't matter,
	/// such as FDR refinement checking or CSP process modeling. It uses `AssertionPhase::Any`
	/// which matches any phase during validation.
	///
	/// ## Automatic CSP Stepping
	/// When a CSP oracle is configured (via `with_fuzz_oracle`), this method automatically
	/// attempts to step the CSP state machine if the event label matches a CSP event.
	/// Common mappings:
	/// - `"move_sent"` → `"move_request"`
	/// - `"move_validated"` → `"move_valid"`
	/// - `"move_rejected"` → `"move_invalid"`
	/// - `"game_ended"` → `"game_over"`
	///
	/// If automatic stepping fails (event not enabled or no mapping), the trace event
	/// is still recorded. Use `oracle().step_event()` for manual CSP stepping.
	pub fn event(&self, label: &str) {
		self.assert(AssertionPhase::Any, label);

		// Automatically step CSP oracle if configured and event matches CSP event
		#[cfg(feature = "testing-fuzz")]
		if let Some(ref oracle) = self.oracle {
			// Try to map trace event label to CSP event
			// Only map known trace events to CSP events (using static string literals)
			let csp_event_label: Option<&'static str> = match label {
				"move_sent" => Some("move_request"),
				"move_validated" => Some("move_valid"),
				"move_rejected" => Some("move_invalid"),
				"game_ended" => Some("game_over"),
				// Note: "move_response" should be stepped manually after receiving response
				// "server_move" is not a CSP event (it's a trace event for coverage)
				// For unknown events, skip automatic stepping (use step_event() manually)
				_ => None,
			};

			if let Some(csp_label) = csp_event_label {
				use crate::testing::specs::csp::Event;
				let event = Event(csp_label);
				// Try to step CSP - ignore errors (event might not be enabled or not match)
				let _ = oracle.step_event(&event);
			}
		}
	}

	/// Record an assertion with a value for equality checking
	pub fn assert_value<V: Into<AssertionValue>>(&self, phase: AssertionPhase, label: &str, value: V) {
		let seq = self.assertions.lock().map(|a| a.len()).unwrap_or(0);
		let assertion_value = value.into();

		// Emit instrumentation event when instrument feature is enabled
		#[cfg(feature = "instrument")]
		{
			// For value assertions, we emit as AssertPayload since there's a value
			let value_str = match &assertion_value {
				AssertionValue::String(s) => s.clone(),
				AssertionValue::Bool(b) => b.to_string(),
				AssertionValue::U8(n) => n.to_string(),
				AssertionValue::U32(n) => n.to_string(),
				AssertionValue::U64(n) => n.to_string(),
				AssertionValue::I32(n) => n.to_string(),
				AssertionValue::I64(n) => n.to_string(),
				AssertionValue::F64(n) => n.to_string(),
				AssertionValue::None => "none".to_string(),
			};
			self.emit_with_payload(TbEventKind::AssertPayload, label, Some(value_str.as_bytes()));
		}

		// Convert label to 'static lifetime for storage
		let static_label: &'static str = Box::leak(label.to_string().into_boxed_str());

		let assertion = Assertion::with_value(seq, phase, AssertionLabel::Custom(static_label), None, assertion_value);
		if let Ok(mut assertions) = self.assertions.lock() {
			assertions.push(assertion);
		}
	}
	/// Record an assertion with payload
	pub fn assert_with_payload(&self, phase: AssertionPhase, label: &str, payload: Option<&[u8]>) {
		use sha3::{Digest, Sha3_256};

		let seq = self.assertions.lock().map(|a| a.len()).unwrap_or(0);
		let payload_hash = payload.map(|p| {
			let mut hasher = Sha3_256::new();
			hasher.update(p);
			let out = hasher.finalize();
			let mut arr = [0u8; 32];
			arr.copy_from_slice(&out);
			arr
		});

		// Convert label to 'static lifetime for storage
		// This is fine for test scenarios where we don't expect unbounded label creation
		let static_label: &'static str = Box::leak(label.to_string().into_boxed_str());

		let assertion = Assertion::new(seq, phase, AssertionLabel::Custom(static_label), payload_hash);
		if let Ok(mut assertions) = self.assertions.lock() {
			assertions.push(assertion);
		}

		// Emit instrumentation event when instrument feature is enabled
		#[cfg(feature = "instrument")]
		{
			let event_kind = if payload.is_some() {
				TbEventKind::AssertPayload
			} else {
				TbEventKind::AssertLabel
			};
			self.emit_with_payload(event_kind, label, payload);
		}
	}
	/// Emit an instrumentation event
	#[cfg(feature = "instrument")]
	pub fn emit(&self, kind: TbEventKind, label: &str) {
		self.emit_with_payload(kind, label, None);
	}

	/// Emit an instrumentation event with payload
	#[cfg(feature = "instrument")]
	pub fn emit_with_payload(&self, kind: TbEventKind, label: &str, payload: Option<&[u8]>) {
		let seq = crate::instrumentation::active::next_seq();
		let event = TbEvent {
			seq,
			kind,
			label: Some(label.to_string()),
			payload_hash: payload.map(|p| {
				use sha3::{Digest, Sha3_256};
				let mut hasher = Sha3_256::new();
				hasher.update(p);
				let out = hasher.finalize();
				let mut arr = [0u8; 32];
				arr.copy_from_slice(&out);
				arr
			}),
			duration_ns: None,
			flags: 0,
			extras: None,
		};

		if let Ok(mut events) = self.events.lock() {
			events.push(event.clone());
		}

		// Also emit to the active instrumentation system
		let _ = crate::instrumentation::active::emit(kind, Some(label), payload, None, 0, None);
	}

	/// Drain assertions into a vector
	pub fn drain_assertions(&self) -> Vec<Assertion> {
		if let Ok(mut assertions) = self.assertions.lock() {
			assertions.drain(..).collect()
		} else {
			Vec::new()
		}
	}

	/// Drain events into a vector
	#[cfg(feature = "instrument")]
	pub fn drain_events(&self) -> Vec<TbEvent> {
		if let Ok(mut events) = self.events.lock() {
			events.drain(..).collect()
		} else {
			Vec::new()
		}
	}
}

impl Default for TraceCollector {
	fn default() -> Self {
		Self::new()
	}
}

/// Consumed execution trace after await completion.
///
/// Represents the complete deterministic execution sequence captured
/// via CBVOC observation channels. Post-await, the container receives
/// this trace for spec verification and custom assertions.
#[derive(Debug, Default)]
pub struct ConsumedTrace {
	/// Phase events captured via instrumentation (if enabled)
	#[cfg(feature = "instrument")]
	pub instrument_events: Vec<TbEvent>,

	/// Handler assertions relayed via `tx` channel
	pub assertions: Vec<Assertion>,

	/// Gate decision (Accepted/Rejected/etc.)
	pub gate_decision: Option<TransitStatus>,

	/// Frame that triggered gate acceptance (if accepted)
	pub accepted_frame: Option<Frame>,

	/// Frame that triggered gate rejection (if rejected)
	pub rejected_frame: Option<Frame>,

	/// Response frame (if handler produced one)
	pub response: Option<Frame>,

	/// Transport error (if emission failed)
	pub error: Option<TransportError>,
}

impl ConsumedTrace {
	pub fn new() -> Self {
		Self {
			#[cfg(feature = "instrument")]
			instrument_events: Vec::new(),
			assertions: Vec::new(),
			gate_decision: None,
			accepted_frame: None,
			rejected_frame: None,
			response: None,
			error: None,
		}
	}

	/// Populate trace from TraceCollector
	pub fn populate_from_collector(&mut self, collector: &TraceCollector) {
		self.assertions.extend(collector.drain_assertions());
		#[cfg(feature = "instrument")]
		{
			self.instrument_events.extend(collector.drain_events());
		}
	}

	/// Determine execution mode based on trace outcome
	pub fn execution_mode(&self) -> ExecutionMode {
		if self.error.is_some() {
			ExecutionMode::Error
		} else if matches!(self.gate_decision, Some(TransitStatus::Accepted)) {
			ExecutionMode::Accept
		} else if self.gate_decision.is_some() {
			ExecutionMode::Reject
		} else {
			ExecutionMode::Error // No gate decision = protocol violation
		}
	}

	/// Check if response was produced
	pub fn has_response(&self) -> bool {
		self.response.is_some()
	}

	/// Count assertions matching phase and label
	pub fn count_assertions(
		&self,
		phase: crate::testing::assertions::AssertionPhase,
		label: &crate::testing::assertions::AssertionLabel,
	) -> usize {
		self.assertions.iter().filter(|a| a.phase == phase && &a.label == label).count()
	}

	#[cfg(feature = "instrument")]
	pub fn count_event_kind(&self, kind: TbEventKind) -> usize {
		self.instrument_events.iter().filter(|e| e.kind == kind).count()
	}
}

/// Execution mode classification for specs
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
	/// Gate accepts, handler runs, may produce response
	Accept,
	/// Gate rejects, handler never runs
	Reject,
	/// Transport error occurred
	Error,
}

impl ExecutionMode {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Accept => "accept",
			Self::Reject => "reject",
			Self::Error => "error",
		}
	}
}
