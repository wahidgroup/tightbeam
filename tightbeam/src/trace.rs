#![allow(unexpected_cfgs)]

use core::cell::Cell;
use core::time::Duration;

#[cfg(feature = "std")]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "std"))]
use alloc::sync::{Arc, Mutex};

use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::TransitStatus;
use crate::testing::assertions::{Assertion, AssertionLabel, AssertionValue};
use crate::transport::error::TransportError;
use crate::utils::urn::Urn;
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::{events, TbEvent, TbInstrumentationConfig};

/// Configuration for trace collection
#[derive(Clone, Debug, Default)]
pub struct TraceConfig {
	#[cfg(feature = "instrument")]
	pub instrumentation: Option<TbInstrumentationConfig>,
}

impl TraceConfig {
	#[cfg(feature = "instrument")]
	pub fn with_instrumentation(config: TbInstrumentationConfig) -> Self {
		Self { instrumentation: Some(config) }
	}

	#[cfg(feature = "instrument")]
	pub fn instrumentation(&self) -> TbInstrumentationConfig {
		self.instrumentation.unwrap_or_default()
	}
}

#[cfg(feature = "instrument")]
impl From<TbInstrumentationConfig> for TraceConfig {
	fn from(config: TbInstrumentationConfig) -> Self {
		Self { instrumentation: Some(config) }
	}
}

/// Builder for constructing and emitting trace events
///
/// Allows optional chaining of timing and payload information.
/// Example:
/// ```rust
/// trace.event("process")
///     .with_timing(Duration::from_millis(5))
///     .with_payload(data)
///     .emit();
/// ```
pub struct EventBuilder<'a> {
	collector: &'a TraceCollector,
	label: String,
	tags: Vec<&'static str>,
	value: Option<EventValue>,
	#[cfg(feature = "instrument")]
	duration_ns: Option<u64>,
	#[cfg(feature = "instrument")]
	payload: Option<&'a [u8]>,
	emitted: Cell<bool>,
}

impl<'a> EventBuilder<'a> {
	fn new(collector: &'a TraceCollector, label: String, tags: Vec<&'static str>, value: Option<EventValue>) -> Self {
		Self {
			collector,
			label,
			tags,
			value,
			#[cfg(feature = "instrument")]
			duration_ns: None,
			#[cfg(feature = "instrument")]
			payload: None,
			emitted: Cell::new(false),
		}
	}

	/// Add timing information to the event
	#[cfg(feature = "instrument")]
	pub fn with_timing(mut self, duration: Duration) -> Self {
		self.duration_ns = Some(duration.as_nanos() as u64);
		self
	}

	#[cfg(not(feature = "instrument"))]
	pub fn with_timing(self, _duration: Duration) -> Self {
		self
	}

	/// Add payload data to the event
	#[cfg(feature = "instrument")]
	pub fn with_payload(mut self, payload: &'a [u8]) -> Self {
		self.payload = Some(payload);
		self
	}

	#[cfg(not(feature = "instrument"))]
	pub fn with_payload(self, _payload: &'a [u8]) -> Self {
		self
	}

	/// Emit the event (both assertion and instrumentation if enabled)
	/// This is automatically called when the builder is dropped.
	pub fn emit(self) {
		self.emit_internal();
	}

	fn emit_internal(&self) {
		fn leak_label(label: &str) -> &'static str {
			Box::leak(label.to_string().into_boxed_str())
		}

		// Check if already emitted
		if self.emitted.get() {
			return;
		}

		self.emitted.set(true);

		let seq = self.collector.state.assertions.lock().map(|a| a.len()).unwrap_or(0);
		let static_label: &'static str = leak_label(&self.label);
		let assertion = match &self.value {
			Some(EventValue::None) | None => {
				#[cfg(feature = "instrument")]
				{
					// Use TIMING_WCET URN if duration is specified, otherwise ASSERT_LABEL
					let urn = if self.duration_ns.is_some() {
						events::TIMING_WCET
					} else {
						events::ASSERT_LABEL
					};

					self.collector
						.emit_internal(urn, Some(&self.label), self.payload, self.duration_ns);
				}
				Assertion::new(seq, AssertionLabel::Custom(static_label), self.tags.clone(), None)
			}
			Some(EventValue::Value(assertion_value)) => {
				#[cfg(feature = "instrument")]
				{
					let value_str = format_assertion_value(assertion_value);
					self.collector.emit_internal(
						events::ASSERT_PAYLOAD,
						Some(&self.label),
						Some(value_str.as_bytes()),
						self.duration_ns,
					);
				}
				Assertion::with_value(
					seq,
					AssertionLabel::Custom(static_label),
					self.tags.clone(),
					None,
					assertion_value.clone(),
				)
			}
		};

		if let Ok(mut assertions) = self.collector.state.assertions.lock() {
			assertions.push(assertion);
		}

		#[cfg(feature = "testing-fuzz")]
		self.collector.dispatch_csp_event(&self.label);
	}
}

impl<'a> Drop for EventBuilder<'a> {
	fn drop(&mut self) {
		self.emit_internal();
	}
}

#[derive(Clone)]
pub struct TraceCollector {
	state: Arc<TraceState>,
}

struct TraceState {
	assertions: Mutex<Vec<Assertion>>,
	#[cfg(feature = "instrument")]
	events: Mutex<Vec<TbEvent>>,
	#[cfg(feature = "instrument")]
	config: TbInstrumentationConfig,
	#[cfg(feature = "instrument")]
	seq: Mutex<u32>,
	#[cfg(feature = "testing-fuzz")]
	oracle: Option<crate::testing::fuzz::FuzzContext>,
}

impl TraceState {
	fn new() -> Self {
		Self {
			assertions: Mutex::new(Vec::new()),
			#[cfg(feature = "instrument")]
			events: Mutex::new(Vec::new()),
			#[cfg(feature = "instrument")]
			config: TbInstrumentationConfig::default(),
			#[cfg(feature = "instrument")]
			seq: Mutex::new(0),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
		}
	}

	#[cfg(feature = "instrument")]
	fn with_config(config: TbInstrumentationConfig) -> Self {
		Self {
			assertions: Mutex::new(Vec::new()),
			events: Mutex::new(Vec::new()),
			config,
			seq: Mutex::new(0),
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
			#[cfg(feature = "instrument")]
			config: TbInstrumentationConfig::default(),
			#[cfg(feature = "instrument")]
			seq: Mutex::new(0),
			oracle: Some(crate::testing::fuzz::FuzzContext::new(input, process)),
		}
	}
}

impl TraceCollector {
	/// Create a new empty trace collector with default config
	pub fn new() -> Self {
		Self { state: Arc::new(TraceState::new()) }
	}

	#[cfg(feature = "instrument")]
	fn with_config(config: TbInstrumentationConfig) -> Self {
		Self { state: Arc::new(TraceState::with_config(config)) }
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
	/// Returns an EventBuilder for optional chaining.
	pub fn event(&self, label: impl AsRef<str>) -> EventBuilder<'_> {
		EventBuilder::new(self, label.as_ref().to_string(), Vec::new(), None)
	}

	/// Record an event with explicit tags and optional value.
	/// Returns an EventBuilder for optional chaining.
	pub fn event_with<V>(&self, label: &str, tags: &[&'static str], value: V) -> EventBuilder<'_>
	where
		V: Into<EventValue>,
	{
		EventBuilder::new(self, label.to_string(), tags.to_vec(), Some(value.into()))
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
	fn next_seq(&self) -> u32 {
		if let Ok(mut seq) = self.state.seq.lock() {
			let current = *seq;
			*seq += 1;
			current
		} else {
			0
		}
	}

	#[cfg(feature = "instrument")]
	fn emit_internal(&self, urn: Urn<'static>, label: Option<&str>, payload: Option<&[u8]>, duration_ns: Option<u64>) {
		let cfg = self.state.config;
		let seq = self.next_seq();

		// Check overflow
		if let Ok(events) = self.state.events.lock() {
			if (events.len() as u32) >= cfg.max_events {
				return;
			}
		}

		let payload_hash = if cfg.enable_payloads {
			payload.map(hash_payload)
		} else {
			None
		};

		let event = TbEvent {
			seq,
			urn,
			label: label.map(|l| l.to_string()),
			payload_hash,
			duration_ns: if cfg.record_durations {
				duration_ns
			} else {
				None
			},
			flags: 0,
			extras: None,
		};

		if let Ok(mut events) = self.state.events.lock() {
			events.push(event);
		}
	}

	#[cfg(feature = "instrument")]
	pub fn emit(&self, event_urn: Urn<'static>, label: impl AsRef<str>) {
		self.emit_with_payload(event_urn, label.as_ref(), None);
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_payload(&self, event_urn: Urn<'static>, label: impl AsRef<str>, payload: Option<&[u8]>) {
		self.emit_internal(event_urn, Some(label.as_ref()), payload, None);
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_timing(&self, event_urn: Urn<'static>, label: impl AsRef<str>, duration: Duration) {
		self.emit_internal(event_urn, Some(label.as_ref()), None, Some(duration.as_nanos() as u64));
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

impl From<TraceConfig> for TraceCollector {
	fn from(config: TraceConfig) -> Self {
		#[cfg(feature = "instrument")]
		{
			Self::with_config(config.instrumentation())
		}
		#[cfg(not(feature = "instrument"))]
		{
			Self::new()
		}
	}
}

impl Default for TraceCollector {
	fn default() -> Self {
		Self::new()
	}
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

	pub fn count_assertions(&self, label: &AssertionLabel, tags: Option<&[&'static str]>) -> usize {
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
	pub fn count_event_urn(&self, event_urn: Urn<'static>) -> usize {
		self.instrument_events.iter().filter(|e| e.urn == event_urn).count()
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
