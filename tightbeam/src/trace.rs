#![allow(unexpected_cfgs)]

#[cfg(feature = "std")]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "std"))]
use alloc::sync::{Arc, Mutex};

use crate::policy::TransitStatus;
use crate::testing::assertions::{Assertion, AssertionLabel, AssertionValue};
use crate::transport::error::TransportError;
use crate::Frame;

use sha3::{Digest, Sha3_256};

#[cfg(feature = "instrument")]
use crate::instrumentation::{TbEvent, TbEventKind};

#[derive(Clone)]
pub struct TraceCollector {
	state: Arc<TraceState>,
}

struct TraceState {
	assertions: Mutex<Vec<Assertion>>,
	#[cfg(feature = "instrument")]
	events: Mutex<Vec<TbEvent>>,
	#[cfg(feature = "testing-fuzz")]
	oracle: Option<crate::testing::fuzz::FuzzContext>,
}

impl TraceState {
	fn new() -> Self {
		Self {
			assertions: Mutex::new(Vec::new()),
			#[cfg(feature = "instrument")]
			events: Mutex::new(Vec::new()),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
		}
	}

	#[cfg(fuzzing)]
	#[cfg(feature = "testing-fuzz")]
	fn with_oracle(input: Vec<u8>, process: crate::testing::specs::csp::Process) -> Self {
		Self {
			assertions: Mutex::new(Vec::new()),
			#[cfg(feature = "instrument")]
			events: Mutex::new(Vec::new()),
			oracle: Some(crate::testing::fuzz::FuzzContext::new(input, process)),
		}
	}
}

impl TraceCollector {
	/// Create a new empty trace collector
	pub fn new() -> Self {
		Self { state: Arc::new(TraceState::new()) }
	}

	/// Create a trace collector with fuzz oracle (CSP-guided fuzzing)
	#[cfg(fuzzing)]
	#[cfg(feature = "testing-fuzz")]
	pub fn with_fuzz_oracle(input: Vec<u8>, process: crate::testing::specs::csp::Process) -> Self {
		Self { state: Arc::new(TraceState::with_oracle(input, process)) }
	}

	/// Get the fuzz oracle, panicking if not configured
	#[cfg(fuzzing)]
	#[cfg(feature = "testing-fuzz")]
	pub fn oracle(&self) -> &crate::testing::fuzz::FuzzContext {
		self.state
			.oracle
			.as_ref()
			.expect("Oracle not configured - did you provide csp: parameter in tb_scenario!?")
	}

	/// Record an event with no tags or value.
	pub fn event(&self, label: impl AsRef<str>) {
		self.event_with(label.as_ref(), &[], ());
	}

	/// Record an event with explicit tags and optional value.
	pub fn event_with<V>(&self, label: &str, tags: &[&'static str], value: V)
	where
		V: Into<EventValue>,
	{
		let seq = self.state.assertions.lock().map(|a| a.len()).unwrap_or(0);
		let static_label: &'static str = leak_label(label);
		let event_value = value.into();
		let assertion = match event_value {
			EventValue::None => {
				#[cfg(feature = "instrument")]
				self.emit_with_payload(TbEventKind::AssertLabel, label, None);

				Assertion::new(seq, AssertionLabel::Custom(static_label), tags.to_vec(), None)
			}
			EventValue::Value(assertion_value) => {
				#[cfg(feature = "instrument")]
				{
					let value_str = format_assertion_value(&assertion_value);
					self.emit_with_payload(TbEventKind::AssertPayload, label, Some(value_str.as_bytes()));
				}

				Assertion::with_value(seq, AssertionLabel::Custom(static_label), tags.to_vec(), None, assertion_value)
			}
		};

		if let Ok(mut assertions) = self.state.assertions.lock() {
			assertions.push(assertion);
		}

		#[cfg(feature = "testing-fuzz")]
		self.dispatch_csp_event(label);
	}

	#[cfg(feature = "testing-fuzz")]
	fn dispatch_csp_event(&self, label: &str) {
		if let Some(ref oracle) = self.state.oracle {
			if let Some(csp_label) = Self::map_csp_label(label) {
				use crate::testing::specs::csp::Event;
				let event = Event(csp_label);
				let _ = oracle.step_event(&event);
			}
		}
	}

	#[cfg(feature = "testing-fuzz")]
	fn map_csp_label(label: &str) -> Option<&'static str> {
		match label {
			"client_move_sent" => Some("move_request"),
			"client_move_validated" => Some("move_valid"),
			"client_move_rejected" => Some("move_invalid"),
			"client_game_ended" => Some("game_over"),
			_ => None,
		}
	}

	#[cfg(feature = "instrument")]
	pub fn emit(&self, kind: TbEventKind, label: impl AsRef<str>) {
		self.emit_with_payload(kind, label.as_ref(), None);
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_payload(&self, kind: TbEventKind, label: impl AsRef<str>, payload: Option<&[u8]>) {
		let label = label.as_ref();
		let seq = crate::instrumentation::active::next_seq();
		let event = TbEvent {
			seq,
			kind,
			label: Some(label.to_string()),
			payload_hash: payload.map(hash_payload),
			duration_ns: None,
			flags: 0,
			extras: None,
		};

		if let Ok(mut events) = self.state.events.lock() {
			events.push(event.clone());
		}

		let _ = crate::instrumentation::active::emit(kind, Some(label), payload, None, 0, None);
	}

	/// Drain assertions into a vector
	pub fn drain_assertions(&self) -> Vec<Assertion> {
		if let Ok(mut assertions) = self.state.assertions.lock() {
			assertions.drain(..).collect()
		} else {
			Vec::new()
		}
	}

	/// Drain events into a vector
	#[cfg(feature = "instrument")]
	pub fn drain_events(&self) -> Vec<TbEvent> {
		if let Ok(mut events) = self.state.events.lock() {
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

fn leak_label(label: &str) -> &'static str {
	Box::leak(label.to_string().into_boxed_str())
}

fn hash_payload(payload: &[u8]) -> [u8; 32] {
	let mut hasher = Sha3_256::new();
	hasher.update(payload);
	let out = hasher.finalize();

	let mut arr = [0u8; 32];
	arr.copy_from_slice(&out);
	arr
}

#[cfg(feature = "instrument")]
fn format_assertion_value(value: &AssertionValue) -> String {
	match value {
		AssertionValue::String(s) => s.clone(),
		AssertionValue::Bool(b) => b.to_string(),
		AssertionValue::U8(n) => n.to_string(),
		AssertionValue::U32(n) => n.to_string(),
		AssertionValue::U64(n) => n.to_string(),
		AssertionValue::I32(n) => n.to_string(),
		AssertionValue::I64(n) => n.to_string(),
		AssertionValue::F64(n) => n.to_string(),
		AssertionValue::MessagePriority(p) => format!("{p:?}"),
		AssertionValue::Version(v) => format!("{v:?}"),
		AssertionValue::Some(inner) => format!("Some({inner:?})"),
		AssertionValue::IsNone => "none".to_string(),
		AssertionValue::IsSome => "some".to_string(),
		AssertionValue::RatioActual(n, d) => format!("{n}/{d}"),
		AssertionValue::RatioLimit(n, d) => format!("≤{n}/{d}"),
	}
}

/// Consumed execution trace after await completion.
#[derive(Debug, Default)]
pub struct ConsumedTrace {
	#[cfg(feature = "instrument")]
	pub instrument_events: Vec<TbEvent>,
	pub assertions: Vec<Assertion>,
	pub gate_decision: Option<TransitStatus>,
	pub accepted_frame: Option<Frame>,
	pub rejected_frame: Option<Frame>,
	pub response: Option<Frame>,
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
			ExecutionMode::Error
		}
	}

	pub fn has_response(&self) -> bool {
		self.response.is_some()
	}

	pub fn count_assertions(
		&self,
		label: &crate::testing::assertions::AssertionLabel,
		tags: Option<&[&'static str]>,
	) -> usize {
		self.assertions
			.iter()
			.filter(|a| {
				&a.label == label
					&& if let Some(filter_tags) = tags {
						filter_tags.iter().all(|tag| a.tags.contains(tag))
					} else {
						true
					}
			})
			.count()
	}

	#[cfg(feature = "instrument")]
	pub fn count_event_kind(&self, kind: TbEventKind) -> usize {
		self.instrument_events.iter().filter(|e| e.kind == kind).count()
	}
}

#[derive(Debug, Clone)]
pub enum EventValue {
	None,
	Value(AssertionValue),
}

impl From<()> for EventValue {
	fn from(_: ()) -> Self {
		Self::None
	}
}

impl<T> From<T> for EventValue
where
	AssertionValue: From<T>,
{
	fn from(value: T) -> Self {
		Self::Value(AssertionValue::from(value))
	}
}

/// Execution mode classification for specs
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
	Accept,
	Reject,
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

#[cfg(test)]
mod tests {
	use crate::{exactly, tb_assert_spec, tb_scenario};

	tb_assert_spec! {
		pub TraceCollectorSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("alpha", exactly!(1)),
				("beta", exactly!(1)),
			]
		}
	}

	tb_scenario! {
		name: trace_collector_records_shared_state,
		spec: TraceCollectorSpec,
		environment Bare {
			exec: |trace| {
				let other = trace.clone();
				trace.event("alpha");
				other.event("beta");
				Ok(())
			}
		}
	}
}
