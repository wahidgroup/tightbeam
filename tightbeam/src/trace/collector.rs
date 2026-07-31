#![allow(unexpected_cfgs)]

use core::cell::Cell;
use core::time::Duration;

use std::borrow::Cow;
use std::sync::Arc;
#[cfg(all(feature = "instrument", not(target_family = "wasm")))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use core::fmt;
#[cfg(feature = "testing-fault")]
use std::collections::HashMap;
#[cfg(any(test, feature = "testing", feature = "instrument", feature = "testing-fault"))]
use std::sync::Mutex;

use crate::trace::{AssertionValue, TraceConfigBuilder};
use crate::utils::urn::Urn;

#[cfg(feature = "testing-fault")]
use crate::constants::DEFAULT_FAULT_SEED;
#[cfg(feature = "instrument")]
use crate::crypto::hash::{Digest, Sha3_256};
#[cfg(feature = "instrument")]
use crate::instrumentation::{events, BoundedMemorySink, EventSink, TbEvent, TbInstrumentationConfig};
#[cfg(all(feature = "policy", any(test, feature = "testing")))]
use crate::policy::TransitStatus;
#[cfg(feature = "testing-fault")]
use crate::testing::fdr::FaultModel;
#[cfg(feature = "testing-fault")]
use crate::testing::fdr::InjectionStrategy;
#[cfg(feature = "logging")]
use crate::trace::logging::LogRecord;
#[cfg(any(test, feature = "testing"))]
use crate::trace::{Assertion, AssertionLabel};
#[cfg(all(feature = "transport", any(test, feature = "testing")))]
use crate::transport::error::TransportError;
#[cfg(any(test, feature = "testing"))]
use crate::Frame;

/// Trait for converting types into event labels.
///
/// Event identity is a URN: only URN forms convert. Raw strings are
/// rejected at compile time so every emitted label resolves to an entry
/// in a URN inventory (crate: [`crate::instrumentation::events`]).
pub trait IntoEventLabel {
	fn into_label(self) -> Cow<'static, str>;
}

impl IntoEventLabel for Urn<'_> {
	fn into_label(self) -> Cow<'static, str> {
		Cow::Owned(self.to_string())
	}
}

impl IntoEventLabel for &Urn<'_> {
	fn into_label(self) -> Cow<'static, str> {
		Cow::Owned(self.to_string())
	}
}

/// Configuration for trace collection
#[derive(Default)]
pub struct TraceConfig {
	#[cfg(feature = "instrument")]
	pub instrumentation: Option<TbInstrumentationConfig>,
	/// Event retention/export sink. `None` uses the default bounded
	/// in-memory buffer ([`BoundedMemorySink`]) sized by
	/// `instrumentation.max_events`.
	#[cfg(feature = "instrument")]
	pub sink: Option<Arc<dyn EventSink>>,
	#[cfg(feature = "logging")]
	pub logger: Option<super::logging::LoggerConfig>,
}

impl fmt::Debug for TraceConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut s = f.debug_struct("TraceConfig");
		#[cfg(feature = "instrument")]
		s.field("instrumentation", &self.instrumentation);
		#[cfg(feature = "instrument")]
		s.field("sink", &self.sink.as_ref().map(|_| "<dyn EventSink>"));
		#[cfg(feature = "logging")]
		s.field("logger", &self.logger);
		s.finish()
	}
}

impl TraceConfig {
	pub fn builder() -> TraceConfigBuilder {
		TraceConfigBuilder::default()
	}

	#[cfg(feature = "instrument")]
	pub fn with_instrumentation(config: TbInstrumentationConfig) -> Self {
		Self {
			instrumentation: Some(config),
			sink: None,
			#[cfg(feature = "logging")]
			logger: None,
		}
	}

	#[cfg(feature = "instrument")]
	pub fn instrumentation(&self) -> TbInstrumentationConfig {
		self.instrumentation.unwrap_or_default()
	}
}

#[cfg(feature = "instrument")]
impl From<TbInstrumentationConfig> for TraceConfig {
	fn from(config: TbInstrumentationConfig) -> Self {
		Self {
			instrumentation: Some(config),
			sink: None,
			#[cfg(feature = "logging")]
			logger: None,
		}
	}
}

/// Builder for constructing and emitting trace events
///
/// Allows optional chaining of timing and payload information.
/// Example:
/// ```rust
/// # use core::time::Duration;
/// # use tightbeam::error::TightBeamError;
/// # use tightbeam::trace::{TraceCollector, EventValue};
/// # use tightbeam::utils::urn::Urn;
/// # const ROUTE_STEP: Urn<'static> = Urn::new("tightbeam", "event:route/step");
/// # fn example() -> Result<(), TightBeamError> {
/// # let trace = TraceCollector::default();
/// trace.event(ROUTE_STEP)?
///     .with_timing(Duration::from_millis(5))
///     .with_payload(b"payload")
///     .emit();
/// # Ok(())
/// # }
/// ```
pub struct EventBuilder<'a> {
	collector: &'a TraceCollector,
	label: Cow<'static, str>,
	tags: Option<Cow<'static, [&'static str]>>,
	value: Option<EventValue>,
	#[cfg(feature = "instrument")]
	duration_ns: Option<u64>,
	#[cfg(feature = "instrument")]
	payload: Option<&'a [u8]>,
	#[cfg(feature = "logging")]
	log_level: Option<super::logging::LogLevel>,
	emitted: Cell<bool>,
}

impl<'a> EventBuilder<'a> {
	fn new(
		collector: &'a TraceCollector,
		label: Cow<'static, str>,
		tags: Option<Cow<'static, [&'static str]>>,
		value: Option<EventValue>,
	) -> Self {
		Self {
			collector,
			label,
			tags,
			value,
			#[cfg(feature = "instrument")]
			duration_ns: None,
			#[cfg(feature = "instrument")]
			payload: None,
			#[cfg(feature = "logging")]
			log_level: None,
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

	/// Set log level for this event
	///
	/// When a log level is set, the event will be emitted to the configured
	/// log backend (if any) in addition to trace events.
	#[cfg(feature = "logging")]
	pub fn with_log_level(mut self, level: super::logging::LogLevel) -> Self {
		self.log_level = Some(level);
		self
	}

	#[cfg(not(feature = "logging"))]
	pub fn with_log_level(self, _level: ()) -> Self {
		self
	}

	/// Emit the event (both assertion and instrumentation if enabled)
	/// This is automatically called when the builder is dropped.
	pub fn emit(mut self) {
		self.emit_internal();
	}

	fn emit_internal(&mut self) {
		// Check if already emitted
		if self.emitted.get() {
			return;
		}

		self.emitted.set(true);

		// Emit to log backend if configured and log level is set (before moving label)
		#[cfg(feature = "logging")]
		if let Some(logger_config) = &self.collector.state.logger_config {
			// Use explicit log level, or fall back to default from config
			let effective_level = self.log_level.or(logger_config.default_level);
			if let Some(level) = effective_level {
				if logger_config.filter.should_log(level, None) {
					let label_str = match &self.label {
						Cow::Borrowed(s) => *s,
						Cow::Owned(s) => s.as_str(),
					};

					let record = LogRecord {
						level,
						timestamp: self.duration_ns,
						component: None, // TODO: Extract from tags
						message: label_str,
						metadata: None, // TODO: Extract from value
					};

					// Ignore logging errors (don't fail trace collection)
					let _ = logger_config.backend.emit(&record);
				}
			}
		}

		let label = core::mem::take(&mut self.label);
		let value = self.value.take();

		#[cfg(feature = "instrument")]
		match &value {
			Some(EventValue::None) | None => {
				// Use TIMING_WCET URN if duration is specified, otherwise ASSERT_LABEL
				let urn = if self.duration_ns.is_some() {
					events::TIMING_WCET
				} else {
					events::ASSERT_LABEL
				};

				self.collector
					.emit_internal(urn, Some(&label), self.payload, self.duration_ns, None);
			}
			Some(EventValue::Value(assertion_value)) => {
				let value_str = format_assertion_value(assertion_value);
				self.collector.emit_internal(
					events::ASSERT_PAYLOAD,
					Some(&label),
					Some(value_str.as_bytes()),
					self.duration_ns,
					None,
				);
			}
		}

		#[cfg(feature = "testing-fuzz")]
		self.collector.dispatch_csp_event(&label);

		#[cfg(any(test, feature = "testing"))]
		{
			let seq = self.collector.state.assertions.lock().map(|a| a.len()).unwrap_or(0);
			let tags = self.tags.take().map(|t| t.into_owned()).unwrap_or_default();
			let assertion = match value {
				Some(EventValue::None) | None => Assertion::new(seq, AssertionLabel::Custom(label), tags, None),
				Some(EventValue::Value(assertion_value)) => {
					Assertion::with_value(seq, AssertionLabel::Custom(label), tags, None, assertion_value)
				}
			};

			if let Ok(mut assertions) = self.collector.state.assertions.lock() {
				assertions.push(assertion);
			}
		}

		#[cfg(not(any(test, feature = "testing")))]
		let _ = (label, value, self.tags.take(), self.collector);
	}
}

impl<'a> Drop for EventBuilder<'a> {
	fn drop(&mut self) {
		self.emit_internal();
	}
}

#[derive(Debug)]
pub struct TraceCollector {
	state: Arc<TraceState>,
}

/// Debug-opaque handle around the configured event sink.
#[cfg(feature = "instrument")]
struct SinkHandle(Arc<dyn EventSink>);

#[cfg(feature = "instrument")]
impl fmt::Debug for SinkHandle {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("<dyn EventSink>")
	}
}

#[cfg(feature = "instrument")]
impl Default for SinkHandle {
	fn default() -> Self {
		Self(Arc::new(BoundedMemorySink::default()))
	}
}

/// Monotonic trace clock: event timestamps count nanoseconds since the
/// collector's construction. The construction time origin is recorded once
/// (`TRACE_CLOCK_ORIGIN`) so absolute times are reconstructible without a
/// per-event syscall.
///
/// `wasm` targets have no monotonic `Instant`; there the clock is inert
/// and events carry no timestamps.
#[cfg(feature = "instrument")]
#[derive(Debug)]
struct TraceClock {
	#[cfg(not(target_family = "wasm"))]
	origin: Instant,
	#[cfg(not(target_family = "wasm"))]
	origin_unix_ns: u128,
	origin_recorded: core::sync::atomic::AtomicBool,
}

#[cfg(feature = "instrument")]
impl Default for TraceClock {
	fn default() -> Self {
		Self {
			#[cfg(not(target_family = "wasm"))]
			origin: Instant::now(),
			// A wall clock before the epoch reads as origin zero rather
			// than failing collector construction.
			#[cfg(not(target_family = "wasm"))]
			origin_unix_ns: SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map(|since| since.as_nanos())
				.unwrap_or_default(),
			origin_recorded: core::sync::atomic::AtomicBool::new(false),
		}
	}
}

#[cfg(feature = "instrument")]
impl TraceClock {
	fn now_ns(&self) -> Option<u64> {
		#[cfg(not(target_family = "wasm"))]
		{
			Some(self.origin.elapsed().as_nanos() as u64)
		}
		#[cfg(target_family = "wasm")]
		{
			None
		}
	}
}

#[derive(Debug)]
struct TraceState {
	#[cfg(any(test, feature = "testing"))]
	assertions: Mutex<Vec<Assertion>>,
	/// Owns event retention: the default is a bounded in-memory buffer
	/// ([`BoundedMemorySink`]); consumers may inject their own via
	/// [`TraceConfig::sink`]
	#[cfg(feature = "instrument")]
	sink: SinkHandle,
	#[cfg(feature = "instrument")]
	config: TbInstrumentationConfig,
	#[cfg(feature = "instrument")]
	seq: Mutex<u32>,
	#[cfg(feature = "instrument")]
	clock: TraceClock,
	#[cfg(feature = "testing-fuzz")]
	oracle: Option<crate::testing::fuzz::FuzzContext>,
	#[cfg(feature = "testing-fault")]
	runtime_fault_model: Option<FaultModel>,
	#[cfg(feature = "testing-fault")]
	fault_rng_state: Mutex<u64>, // For Random strategy (seeded RNG)
	#[cfg(feature = "testing-fault")]
	fault_call_counters: Mutex<HashMap<Cow<'static, str>, u32>>, // For Deterministic strategy
	#[cfg(feature = "logging")]
	logger_config: Option<super::logging::LoggerConfig>,
}

impl Default for TraceState {
	fn default() -> Self {
		Self {
			#[cfg(any(test, feature = "testing"))]
			assertions: Mutex::new(Vec::new()),
			#[cfg(feature = "instrument")]
			sink: SinkHandle::default(),
			#[cfg(feature = "instrument")]
			config: TbInstrumentationConfig::default(),
			#[cfg(feature = "instrument")]
			seq: Mutex::new(0),
			#[cfg(feature = "instrument")]
			clock: TraceClock::default(),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
			#[cfg(feature = "testing-fault")]
			runtime_fault_model: None,
			#[cfg(feature = "testing-fault")]
			fault_rng_state: Mutex::new(DEFAULT_FAULT_SEED),
			#[cfg(feature = "testing-fault")]
			fault_call_counters: Mutex::new(HashMap::new()),
			#[cfg(feature = "logging")]
			logger_config: None,
		}
	}
}

impl TraceState {
	#[cfg(feature = "instrument")]
	fn with_config(config: TbInstrumentationConfig, sink: Option<Arc<dyn EventSink>>) -> Self {
		let sink = SinkHandle(sink.unwrap_or_else(|| Arc::new(BoundedMemorySink::new(config.max_events))));

		Self {
			#[cfg(any(test, feature = "testing"))]
			assertions: Mutex::new(Vec::new()),
			sink,
			config,
			seq: Mutex::new(0),
			clock: TraceClock::default(),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
			#[cfg(feature = "testing-fault")]
			runtime_fault_model: None,
			#[cfg(feature = "testing-fault")]
			fault_rng_state: Mutex::new(DEFAULT_FAULT_SEED),
			#[cfg(feature = "testing-fault")]
			fault_call_counters: Mutex::new(HashMap::new()),
			#[cfg(feature = "logging")]
			logger_config: None,
		}
	}

	#[cfg(feature = "testing-fuzz")]
	fn with_oracle(input: Vec<u8>, process: crate::testing::specs::csp::Process) -> Self {
		Self {
			// The testing-fuzz feature implies testing, so the field exists here
			assertions: Mutex::new(Vec::new()),
			#[cfg(feature = "instrument")]
			sink: SinkHandle::default(),
			#[cfg(feature = "instrument")]
			config: TbInstrumentationConfig::default(),
			#[cfg(feature = "instrument")]
			seq: Mutex::new(0),
			#[cfg(feature = "instrument")]
			clock: TraceClock::default(),
			oracle: Some(crate::testing::fuzz::FuzzContext::new(input, process)),
			#[cfg(feature = "testing-fault")]
			runtime_fault_model: None,
			#[cfg(feature = "testing-fault")]
			fault_rng_state: Mutex::new(DEFAULT_FAULT_SEED),
			#[cfg(feature = "testing-fault")]
			fault_call_counters: Mutex::new(HashMap::new()),
			#[cfg(feature = "logging")]
			logger_config: None,
		}
	}
}

impl Default for TraceCollector {
	fn default() -> Self {
		Self { state: Arc::new(TraceState::default()) }
	}
}

impl TraceCollector {
	/// Create a new empty trace collector with default config
	pub fn new() -> Self {
		Self::default()
	}

	/// Create an additional handle that observes and records the same state.
	pub fn share(&self) -> Self {
		Self { state: Arc::clone(&self.state) }
	}

	#[cfg(feature = "instrument")]
	fn with_config(config: TbInstrumentationConfig, sink: Option<Arc<dyn EventSink>>) -> Self {
		Self { state: Arc::new(TraceState::with_config(config, sink)) }
	}

	/// Configure logging backend for this trace collector
	///
	/// Events can emit to the log backend by calling `.with_log_level()`.
	/// If the logger config has a default level, it applies to all events
	/// without an explicit log level.
	#[cfg(feature = "logging")]
	pub fn with_logger(mut self, config: super::logging::LoggerConfig) -> Self {
		if let Some(state) = Arc::get_mut(&mut self.state) {
			state.logger_config = Some(config);
		}
		self
	}

	/// Create a trace collector with fuzz oracle (CSP-guided fuzzing)
	#[cfg(feature = "testing-fuzz")]
	pub fn with_fuzz_oracle(input: Vec<u8>, process: crate::testing::specs::csp::Process) -> Self {
		Self { state: Arc::new(TraceState::with_oracle(input, process)) }
	}

	/// Get the fuzz oracle
	///
	/// # Panics
	///
	/// Panics when no oracle is configured. This accessor exists for
	/// `tb_scenario!`-generated fuzz harnesses (feature `testing-fuzz`),
	/// where a missing `csp:` parameter is a harness construction bug that
	/// must abort the fuzz run rather than continue unguided.
	// Test-harness surface: the documented abort is the contract, so the
	// zero-panic deny is waived for this accessor alone.
	#[allow(clippy::expect_used)]
	#[cfg(feature = "testing-fuzz")]
	pub fn oracle(&self) -> &crate::testing::fuzz::FuzzContext {
		self.state
			.oracle
			.as_ref()
			.expect("Oracle not configured - did you provide csp: parameter in tb_scenario!?")
	}

	/// Check for runtime fault injection (certification-grade)
	///
	/// # Returns
	/// - Ok(()) if no fault should be injected
	/// - Err if a fault is injected.
	///
	/// # Why `&Cow<'static, str>` instead of `&str`
	///
	/// This violates clippy's ptr_arg lint but is necessary for zero-copy:
	/// - We must store the label in a HashMap<Cow<'static, str>, u32> for
	///   fault injection counters
	/// - `Cow::clone()` on `Cow::Borrowed` is zero-cost (just copies the pointer)
	/// - Taking `&str` would force `Cow::Borrowed(label)` construction
	/// - This maintains zero-allocation for static labels while supporting dynamic ones
	#[allow(clippy::ptr_arg)]
	#[cfg(feature = "testing-fault")]
	fn check_runtime_fault_injection(&self, label_cow: &Cow<'static, str>) -> Result<(), crate::TightBeamError> {
		if let Some(ref fault_config) = self.state.runtime_fault_model {
			let key = (Cow::Borrowed("*"), Cow::Borrowed(label_cow.as_ref()));
			if let Some(fault_injection) = fault_config.injection_points.get(&key) {
				let should_inject = match fault_config.injection_strategy {
					InjectionStrategy::Deterministic => {
						// Counter-based injection for DO-178C/IEC 61508 reproducibility
						// Clone Cow: zero-cost for static strings, one alloc for dynamic
						let mut counters = self.state.fault_call_counters.lock()?;
						let count = counters.entry(Cow::clone(label_cow)).or_insert(0);
						*count += 1;

						// Inject based on probability: e.g., 3000 bps (30%) = inject on calls 3,6,9 out of 10
						(*count * fault_injection.probability_bps.get() as u32) % 10000
							< fault_injection.probability_bps.get() as u32
					}
					InjectionStrategy::Random => {
						// Seeded RNG for statistical coverage (like FDR)
						let mut rng_state = self.state.fault_rng_state.lock()?;
						if *rng_state == 0 {
							*rng_state = fault_config.seed.wrapping_add(1);
						}
						// LCG algorithm (same as FDR's SeededRng)
						*rng_state = rng_state
							.wrapping_mul(crate::constants::LCG_MULTIPLIER)
							.wrapping_add(crate::constants::LCG_INCREMENT);
						let rng_value = (*rng_state % 10000) as u16;
						rng_value < fault_injection.probability_bps.get()
					}
				};

				if should_inject {
					return Err((fault_injection.error_factory)());
				}
			}
		}
		Ok(())
	}

	/// Record an event with no tags or value.
	///
	/// # Returns
	/// - Ok(EventBuilder) for optional chaining
	/// - Err if a fault is injected.
	pub fn event(&self, label: impl IntoEventLabel) -> Result<EventBuilder<'_>, crate::TightBeamError> {
		let label_cow = label.into_label();

		#[cfg(feature = "testing-fault")]
		self.check_runtime_fault_injection(&label_cow)?;

		Ok(EventBuilder::new(self, label_cow, None, None))
	}

	/// Record an event with explicit tags and optional value.
	///
	/// # Returns
	/// - Ok(EventBuilder) for optional chaining
	/// - Err if a fault is injected.
	///
	/// # Zero-allocation option
	/// Pass a static slice to avoid allocation:
	///
	/// ```ignore
	/// const TAGS: &[&str] = &["critical", "network"];
	/// trace.event_with(events::ROUTE_STEP, TAGS, value)?
	/// ```
	pub fn event_with<V>(
		&self,
		label: impl IntoEventLabel,
		tags: impl Into<Cow<'static, [&'static str]>>,
		value: V,
	) -> Result<EventBuilder<'_>, crate::TightBeamError>
	where
		V: Into<EventValue>,
	{
		let label_cow = label.into_label();

		#[cfg(feature = "testing-fault")]
		self.check_runtime_fault_injection(&label_cow)?;

		Ok(EventBuilder::new(self, label_cow, Some(tags.into()), Some(value.into())))
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
	fn emit_internal(
		&self,
		urn: Urn<'static>,
		label: Option<&str>,
		payload: Option<&[u8]>,
		duration_ns: Option<u64>,
		timestamp_ns: Option<u64>,
	) {
		let cfg = self.state.config;

		let payload_hash = if cfg.enable_payloads {
			payload.map(hash_payload)
		} else {
			None
		};

		// The sink owns retention: events dropped by a bounded sink still
		// consume a sequence number, so gaps in `seq` reveal exactly where
		// truncation occurred.
		self.state.sink.0.emit(TbEvent {
			seq: self.next_seq(),
			urn,
			label: label.map(|l| l.to_string()),
			payload_hash,
			duration_ns: if cfg.record_durations {
				duration_ns
			} else {
				None
			},
			timestamp_ns,
			flags: 0,
			extras: None,
		});
	}

	#[cfg(feature = "instrument")]
	pub fn emit(&self, event_urn: Urn<'static>, label: impl AsRef<str>) {
		self.emit_with_payload(event_urn, label.as_ref(), None);
	}

	/// Record the trace clock's time origin once per collector, so
	/// relative `timestamp_ns` values reconstruct to absolute times.
	#[cfg(feature = "instrument")]
	fn record_clock_origin(&self) {
		use core::sync::atomic::Ordering;

		if self.state.clock.origin_recorded.swap(true, Ordering::Relaxed) {
			return;
		}

		#[cfg(not(target_family = "wasm"))]
		self.emit_internal(
			crate::instrumentation::events::TRACE_CLOCK_ORIGIN,
			Some(&self.state.clock.origin_unix_ns.to_string()),
			None,
			None,
			Some(0),
		);
	}

	/// Dual-write a production control-plane event: the URN into the
	/// instrument log, plus the same URN as assertion label for spec
	/// assertions and CSP alphabets when the testing layer observes the
	/// trace.
	#[cfg(feature = "instrument")]
	pub fn emit_event(&self, event: Urn<'static>) {
		#[cfg(feature = "testing")]
		{
			if let Ok(builder) = self.event(&event) {
				builder.emit()
			}
		}

		self.record_clock_origin();
		self.emit_internal(event, None, None, None, self.state.clock.now_ns());
	}

	/// Dual-write a production control-plane event carrying evidence: the
	/// label records why (e.g. the refusing status) and the payload
	/// records who (e.g. the peer's SPKI DER) as its SHA3-256 hash when
	/// payload capture is enabled.
	#[cfg(feature = "instrument")]
	pub fn emit_event_with_evidence(&self, event: Urn<'static>, label: &str, payload: Option<&[u8]>) {
		#[cfg(feature = "testing")]
		{
			if let Ok(builder) = self.event(&event) {
				builder.emit()
			}
		}

		self.record_clock_origin();
		self.emit_internal(event, Some(label), payload, None, self.state.clock.now_ns());
	}

	/// Dual-write a production control-plane event carrying a
	/// spec-assertable value: the label records why (e.g. the GoAway
	/// reason name) and the value carries its wire code for `equals!`
	/// assertions.
	#[cfg(feature = "instrument")]
	pub fn emit_event_with_value<V>(&self, event: Urn<'static>, label: &str, value: V)
	where
		V: Into<EventValue>,
	{
		#[cfg(feature = "testing")]
		{
			if let Ok(builder) = self.event_with(&event, &[], value) {
				builder.emit()
			}
		}
		#[cfg(not(feature = "testing"))]
		let _ = value;

		self.record_clock_origin();
		self.emit_internal(event, Some(label), None, None, self.state.clock.now_ns());
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_payload(&self, event_urn: Urn<'static>, label: impl AsRef<str>, payload: Option<&[u8]>) {
		self.emit_internal(event_urn, Some(label.as_ref()), payload, None, None);
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_timing(&self, event_urn: Urn<'static>, label: impl AsRef<str>, duration: Duration) {
		self.emit_internal(event_urn, Some(label.as_ref()), None, Some(duration.as_nanos() as u64), None);
	}

	/// Emit an event stamped with a point-in-time instant (relative to the
	/// trace clock origin), e.g. deadline start/end markers. Durations and
	/// timestamps are distinct `TbEvent` fields: a duration is a span length,
	/// a timestamp is when the event occurred.
	#[cfg(feature = "instrument")]
	pub fn emit_with_timestamp(&self, event_urn: Urn<'static>, label: impl AsRef<str>, timestamp: Duration) {
		self.emit_internal(event_urn, Some(label.as_ref()), None, None, Some(timestamp.as_nanos() as u64));
	}

	/// Drain assertions into a vector
	#[cfg(any(test, feature = "testing"))]
	pub fn drain_assertions(&self) -> Vec<Assertion> {
		if let Ok(mut assertions) = self.state.assertions.lock() {
			assertions.drain(..).collect()
		} else {
			Vec::new()
		}
	}

	/// Drain retained events from the configured sink
	#[cfg(feature = "instrument")]
	pub fn drain_events(&self) -> Vec<TbEvent> {
		self.state.sink.0.drain()
	}

	/// Whether the configured sink dropped any event (sticky)
	///
	/// Feed this into
	/// [`EvidenceArtifact::finalize`](crate::instrumentation::EvidenceArtifact::finalize)
	/// so evidence
	/// built from a truncated trace reports `overflow = true`.
	#[cfg(feature = "instrument")]
	pub fn overflowed(&self) -> bool {
		self.state.sink.0.overflowed()
	}
}

impl From<TraceConfig> for TraceCollector {
	fn from(config: TraceConfig) -> Self {
		#[cfg(any(feature = "instrument", feature = "logging"))]
		{
			let mut collector = Self::default();

			#[cfg(feature = "instrument")]
			if config.instrumentation.is_some() || config.sink.is_some() {
				collector = Self::with_config(config.instrumentation.unwrap_or_default(), config.sink);
			}

			#[cfg(feature = "logging")]
			if let Some(logger) = config.logger {
				collector = collector.with_logger(logger);
			}

			collector
		}

		#[cfg(not(any(feature = "instrument", feature = "logging")))]
		{
			let _ = config;
			Self::default()
		}
	}
}

#[cfg(feature = "instrument")]
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
		AssertionValue::String(s) => s.to_string(),
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
		#[cfg(feature = "policy")]
		AssertionValue::TransitStatus(status) => format!("{status:?}"),
	}
}

/// Consumed execution trace after await completion.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct ConsumedTrace {
	pub assertions: Vec<Assertion>,
	pub accepted_frame: Option<Frame>,
	pub rejected_frame: Option<Frame>,
	pub response: Option<Frame>,

	#[cfg(feature = "instrument")]
	pub instrument_events: Vec<TbEvent>,
	#[cfg(feature = "policy")]
	pub gate_decision: Option<TransitStatus>,
	#[cfg(feature = "transport")]
	pub error: Option<TransportError>,
}

#[cfg(any(test, feature = "testing"))]
impl ConsumedTrace {
	pub fn new() -> Self {
		Self {
			assertions: Vec::new(),
			accepted_frame: None,
			rejected_frame: None,
			response: None,
			#[cfg(feature = "instrument")]
			instrument_events: Vec::new(),
			#[cfg(feature = "policy")]
			gate_decision: None,
			#[cfg(feature = "transport")]
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
		#[cfg(feature = "transport")]
		if self.error.is_some() {
			return ExecutionMode::Error;
		}
		#[cfg(feature = "policy")]
		{
			if matches!(self.gate_decision, Some(TransitStatus::Ok)) {
				return ExecutionMode::Accept;
			}
			if self.gate_decision.is_some() {
				return ExecutionMode::Reject;
			}

			ExecutionMode::Error
		}
		#[cfg(not(feature = "policy"))]
		ExecutionMode::Accept
	}

	pub fn has_response(&self) -> bool {
		self.response.is_some()
	}

	pub fn count_assertions(&self, label: &AssertionLabel, tags: Option<&[&'static str]>) -> usize {
		self.assertions
			.iter()
			.filter(|a| {
				// Use matches() for tightbeam URN shorthand support
				a.label.matches(label)
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
#[cfg(any(test, feature = "testing"))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
	Accept,
	Reject,
	Error,
}

#[cfg(any(test, feature = "testing"))]
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
	use crate::utils::urn::Urn;
	use crate::{exactly, tb_assert_spec, tb_scenario, testing::SetupEnv};

	const ALPHA: Urn<'static> = Urn::new("test", "event:collector/alpha");
	const BETA: Urn<'static> = Urn::new("test", "event:collector/beta");

	tb_assert_spec! {
		pub TraceCollectorSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Ok,
			assertions: [
				(ALPHA, exactly!(1)),
				(BETA, exactly!(1)),
			]
		}
	}

	tb_scenario! {
		name: trace_collector_records_shared_state,
		spec: TraceCollectorSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				trace.event(ALPHA)?;
				trace.event(BETA)?;
				Ok(())
			}
		}
	}

	#[cfg(feature = "instrument")]
	mod overflow {
		use crate::instrumentation::{events, TbInstrumentationConfig};
		use crate::trace::{TraceCollector, TraceConfig};

		fn collector_with_max_events(max_events: u32) -> TraceCollector {
			let config = TbInstrumentationConfig { max_events, ..Default::default() };
			TraceCollector::from(TraceConfig::with_instrumentation(config))
		}

		#[test]
		fn events_within_bound_do_not_overflow() {
			let collector = collector_with_max_events(2);

			collector.emit(events::START, "first");
			collector.emit(events::END, "second");

			assert!(!collector.overflowed());
			assert_eq!(collector.drain_events().len(), 2);
		}

		#[test]
		fn events_past_bound_are_dropped_and_flagged() {
			let collector = collector_with_max_events(2);

			collector.emit(events::START, "first");
			collector.emit(events::END, "second");
			collector.emit(events::END, "third");

			assert!(collector.overflowed());
			assert_eq!(collector.drain_events().len(), 2);
		}
	}

	#[cfg(feature = "instrument")]
	mod sink {
		use std::sync::{Arc, Mutex};

		use crate::instrumentation::{events, EventSink, TbEvent, TbInstrumentationConfig};
		use crate::trace::{TraceCollector, TraceConfig};

		/// Loss-free sink: retains every event with no cap.
		#[derive(Default)]
		struct UnboundedSink {
			events: Mutex<Vec<TbEvent>>,
		}

		impl EventSink for UnboundedSink {
			fn emit(&self, event: TbEvent) {
				if let Ok(mut events) = self.events.lock() {
					events.push(event);
				}
			}

			fn drain(&self) -> Vec<TbEvent> {
				if let Ok(mut events) = self.events.lock() {
					events.drain(..).collect()
				} else {
					Vec::new()
				}
			}

			fn overflowed(&self) -> bool {
				false
			}
		}

		#[test]
		fn consumer_sink_replaces_bounded_buffer() {
			let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
			let collector = TraceCollector::from(
				TraceConfig::builder()
					.with_instrumentation(config)
					.with_sink(Arc::new(UnboundedSink::default()))
					.build(),
			);

			collector.emit(events::START, "first");
			collector.emit(events::END, "second");
			collector.emit(events::END, "third");

			assert!(!collector.overflowed());
			assert_eq!(collector.drain_events().len(), 3);
		}

		#[test]
		fn sink_without_instrumentation_config_still_receives_events() {
			let collector =
				TraceCollector::from(TraceConfig::builder().with_sink(Arc::new(UnboundedSink::default())).build());

			collector.emit(events::START, "only");

			assert_eq!(collector.drain_events().len(), 1);
		}

		#[test]
		fn sink_events_carry_contiguous_seq() {
			let collector =
				TraceCollector::from(TraceConfig::builder().with_sink(Arc::new(UnboundedSink::default())).build());

			collector.emit(events::START, "first");
			collector.emit(events::END, "second");

			let seqs: Vec<u32> = collector.drain_events().iter().map(|e| e.seq).collect();
			assert_eq!(seqs, vec![0, 1]);
		}
	}
}
