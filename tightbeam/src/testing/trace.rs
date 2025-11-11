//! Execution trace capture and representation
//!
//! This module defines the `ConsumedTrace` structure that represents
//! a fully drained CBVOC execution. The trace captures all channel
//! events, phase transitions, and outcome state.

use crate::policy::TransitStatus;
use crate::testing::assertions::Assertion;
use crate::transport::error::TransportError;
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::{TbEvent, TbEventKind};

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

	/// Drain any thread-local recorded assertions (via `tb_assert!`) into this trace.
	/// Safe to call multiple times; subsequent calls after first will be no-ops
	/// because the underlying buffer is cleared on drain.
	pub fn drain_recorded_assertions(&mut self) {
		let drained = crate::testing::assertions::drain_assertions();
		if !drained.is_empty() {
			self.assertions.extend(drained);
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
