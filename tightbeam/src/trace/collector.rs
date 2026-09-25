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
#[cfg(any(test, feature = "testing"))]
use std::sync::PoisonError;

use crate::trace::{AssertionValue, TraceConfigBuilder};
use crate::utils::urn::Urn;

#[cfg(feature = "testing-fault")]
use crate::constants::DEFAULT_FAULT_SEED;
#[cfg(feature = "instrument")]
use crate::crypto::hash::{Digest, Sha3_256};
#[cfg(any(test, feature = "testing"))]
use crate::error::TightBeamError;
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
#[cfg(any(test, feature = "testing"))]
use crate::Frame;

/// Converts a type into an event label.
///
/// Event identity is a URN, so only URN forms implement this trait. A raw
/// string fails to compile, so every emitted label resolves to an entry in a
/// URN inventory such as [`crate::instrumentation::events`].
pub trait IntoEventLabel {
	/// Renders the URN as the label text.
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

/// Configuration for trace collection.
#[derive(Default)]
pub struct TraceConfig {
	/// Instrumentation settings. `None` uses the default settings.
	#[cfg(feature = "instrument")]
	pub instrumentation: Option<TbInstrumentationConfig>,
	/// Event retention and export sink. `None` uses the default bounded
	/// in-memory buffer ([`BoundedMemorySink`]) sized by
	/// `instrumentation.max_events`.
	#[cfg(feature = "instrument")]
	pub sink: Option<Arc<dyn EventSink>>,
	/// Log backend configuration. `None` leaves events off the log backend.
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

/// Builder that constructs and emits one trace event.
///
/// Timing and payload information chain on optionally.
///
/// # Examples
///
/// ```rust
/// # use core::time::Duration;
/// # use tightbeam::error::TightBeamError;
/// # use tightbeam::trace::{TraceCollector, EventValue};
/// # use tightbeam::utils::urn::Urn;
/// # const ROUTE_STEP: Urn<'static> = tightbeam::urn!("tightbeam", "event:route/step");
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
	#[cfg(any(feature = "instrument", feature = "logging"))]
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
			#[cfg(any(feature = "instrument", feature = "logging"))]
			duration_ns: None,
			#[cfg(feature = "instrument")]
			payload: None,
			#[cfg(feature = "logging")]
			log_level: None,
			emitted: Cell::new(false),
		}
	}

	/// Adds timing information to the event.
	#[cfg(any(feature = "instrument", feature = "logging"))]
	pub fn with_timing(mut self, duration: Duration) -> Self {
		self.duration_ns = Some(duration.as_nanos() as u64);
		self
	}

	#[cfg(not(any(feature = "instrument", feature = "logging")))]
	pub fn with_timing(self, _duration: Duration) -> Self {
		self
	}

	/// Adds payload data to the event.
	#[cfg(feature = "instrument")]
	pub fn with_payload(mut self, payload: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		let payload = payload.as_ref();
		self.payload = Some(payload);
		self
	}

	#[cfg(not(feature = "instrument"))]
	pub fn with_payload(self, _payload: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		self
	}

	/// Sets the log level for this event.
	///
	/// With a log level set, the event also goes to the configured log
	/// backend, when one is configured.
	#[cfg(feature = "logging")]
	pub fn with_log_level(mut self, level: super::logging::LogLevel) -> Self {
		self.log_level = Some(level);
		self
	}

	#[cfg(not(feature = "logging"))]
	pub fn with_log_level(self, _level: ()) -> Self {
		self
	}

	/// Emits the event to the assertion log and to instrumentation, when each
	/// is enabled. Dropping the builder emits the event too.
	pub fn emit(mut self) {
		self.emit_internal();
	}

	fn emit_internal(&mut self) {
		// An event emits once, whether through `emit` or through drop.
		if self.emitted.get() {
			return;
		}

		self.emitted.set(true);

		// The log backend reads the label before the label moves out below.
		#[cfg(feature = "logging")]
		if let Some(logger_config) = &self.collector.state.logger_config {
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

					// The trace is the evidence and the log is a convenience,
					// so a backend that refuses a record must not stop the
					// event from being collected. Nothing above this reads a
					// logging outcome.
					let _unlogged = logger_config.backend.emit(&record);
				}
			}
		}

		let label = core::mem::take(&mut self.label);
		let value = self.value.take();

		#[cfg(feature = "instrument")]
		match &value {
			Some(EventValue::None) | None => {
				let urn = if self.duration_ns.is_some() {
					events::TIMING_WCET
				} else {
					events::ASSERT_LABEL
				};

				self.collector
					.emit_internal(urn, Some(&label), self.payload, self.duration_ns, None);
			}
			Some(EventValue::Value(assertion_value)) => {
				let value_str = assertion_value.render();
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

/// Collects the trace events and assertions of one run.
///
/// Every handle [`TraceCollector::share`] makes records into the same state.
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

/// Monotonic trace clock whose event timestamps count nanoseconds since the
/// collector's construction. The construction time origin is recorded once
/// (`TRACE_CLOCK_ORIGIN`), so absolute times are reconstructible without a
/// per-event syscall.
///
/// `wasm` targets have no monotonic `Instant`, so there the clock is inert
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
			// A system clock set before the epoch reads as origin zero, so
			// collector construction still succeeds.
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
	/// The sink owns event retention. The default is a bounded in-memory
	/// buffer ([`BoundedMemorySink`]), and consumers may inject their own
	/// through [`TraceConfig::sink`].
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
	fault_rng_state: Mutex<u64>, // The seeded RNG state for the random strategy.
	#[cfg(feature = "testing-fault")]
	fault_call_counters: Mutex<HashMap<Cow<'static, str>, u32>>, // The per-label call counters for the deterministic strategy.
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
	fn with_oracle(input: impl Into<Vec<u8>>, process: crate::testing::specs::csp::Process) -> Self {
		let input: Vec<u8> = input.into();
		Self {
			// The testing-fuzz feature implies testing, so the field exists
			// here.
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
	/// Creates a new, empty trace collector with the default config.
	pub fn new() -> Self {
		Self::default()
	}

	/// Creates an additional handle that observes and records the same
	/// state.
	pub fn share(&self) -> Self {
		Self { state: Arc::clone(&self.state) }
	}

	#[cfg(feature = "instrument")]
	fn with_config(config: TbInstrumentationConfig, sink: Option<Arc<dyn EventSink>>) -> Self {
		Self { state: Arc::new(TraceState::with_config(config, sink)) }
	}

	/// Configures the logging backend for this trace collector.
	///
	/// An event reaches the log backend through `.with_log_level()`. When the
	/// logger config has a default level, that level applies to every event
	/// without an explicit one.
	///
	/// The config applies only while this handle is the sole owner of its
	/// state, so call this before [`TraceCollector::share`].
	#[cfg(feature = "logging")]
	pub fn with_logger(mut self, config: super::logging::LoggerConfig) -> Self {
		if let Some(state) = Arc::get_mut(&mut self.state) {
			state.logger_config = Some(config);
		}
		self
	}

	/// Creates a trace collector with a fuzz oracle for CSP-guided fuzzing.
	#[cfg(feature = "testing-fuzz")]
	pub fn with_fuzz_oracle(input: impl Into<Vec<u8>>, process: crate::testing::specs::csp::Process) -> Self {
		let input: Vec<u8> = input.into();
		Self { state: Arc::new(TraceState::with_oracle(input, process)) }
	}

	/// The fuzz oracle, when this collector was built with one.
	///
	/// [`TraceCollector::with_fuzz_oracle`] is the only constructor that
	/// installs one, and [`TraceCollector::share`] carries it, so every
	/// handle a scenario receives answers the same way its collector does.
	/// Every other collector returns [`None`].
	///
	/// A fuzz harness wants the oracle itself rather than an `Option`, and
	/// a missing one is a harness construction bug it should abort on.
	/// `OracleAccess::oracle`, in the test-support surface, is that
	/// accessor. This one is the total answer the library owes a caller
	/// that is not a harness.
	#[cfg(feature = "testing-fuzz")]
	pub fn try_oracle(&self) -> Option<&crate::testing::fuzz::FuzzContext> {
		self.state.oracle.as_ref()
	}

	/// Checks whether the runtime fault model injects a fault at
	/// `label_cow`.
	///
	/// # Errors
	///
	/// - The injection point's error, when the model injects a fault.
	/// - A lock error, when a fault-state lock is poisoned.
	///
	/// # Why `&Cow<'static, str>` instead of `&str`
	///
	/// The parameter trips clippy's `ptr_arg` lint, and the lint is allowed
	/// because the zero-copy counters need the `Cow` itself:
	///
	/// - The fault injection counters key a `HashMap<Cow<'static, str>, u32>` by the label.
	/// - `Cow::clone()` on `Cow::Borrowed` costs nothing, because it copies the pointer.
	/// - Taking `&str` would force a `Cow::Borrowed(label)` construction.
	/// - Static labels stay allocation-free, and dynamic labels still work.
	#[allow(clippy::ptr_arg)]
	#[cfg(feature = "testing-fault")]
	fn check_runtime_fault_injection(&self, label_cow: &Cow<'static, str>) -> Result<(), crate::TightBeamError> {
		if let Some(ref fault_config) = self.state.runtime_fault_model {
			let key = (Cow::Borrowed("*"), Cow::Borrowed(label_cow.as_ref()));
			if let Some(fault_injection) = fault_config.injection_points.get(&key) {
				let should_inject = match fault_config.injection_strategy {
					InjectionStrategy::Deterministic => {
						// Counter-based injection keeps runs reproducible
						// for DO-178C and IEC 61508. Cloning the `Cow` costs
						// nothing for a static label and one allocation for
						// a dynamic one.
						let mut counters = self.state.fault_call_counters.lock()?;
						let count = counters.entry(Cow::clone(label_cow)).or_insert(0);
						*count += 1;

						// The count spreads injections by probability. For
						// example, 3000 bps (30%) injects on calls 4, 7, and
						// 10 out of 10.
						(*count * fault_injection.probability_bps.get() as u32) % 10000
							< fault_injection.probability_bps.get() as u32
					}
					InjectionStrategy::Random => {
						// A seeded RNG gives statistical coverage, as FDR
						// does.
						let mut rng_state = self.state.fault_rng_state.lock()?;
						if *rng_state == 0 {
							*rng_state = fault_config.seed.wrapping_add(1);
						}
						// The LCG step matches FDR's `SeededRng`.
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

	/// Records an event with no tags or value, and returns an
	/// [`EventBuilder`] for optional chaining.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `label`.
	pub fn event(&self, label: impl IntoEventLabel) -> Result<EventBuilder<'_>, crate::TightBeamError> {
		let label_cow = label.into_label();

		#[cfg(feature = "testing-fault")]
		self.check_runtime_fault_injection(&label_cow)?;

		Ok(EventBuilder::new(self, label_cow, None, None))
	}

	/// Records an event with explicit tags and an optional value, and returns
	/// an [`EventBuilder`] for optional chaining.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `label`.
	///
	/// # Zero-allocation option
	///
	/// A static slice of tags avoids an allocation:
	///
	/// ```rust
	/// # use tightbeam::error::TightBeamError;
	/// # use tightbeam::trace::TraceCollector;
	/// # use tightbeam::utils::urn::Urn;
	/// # const ROUTE_STEP: Urn<'static> = tightbeam::urn!("tightbeam", "event:route/step");
	/// # fn main() -> Result<(), TightBeamError> {
	/// # let trace = TraceCollector::default();
	/// const TAGS: &[&str] = &["critical", "network"];
	/// trace.event_with(ROUTE_STEP, TAGS, 3u64)?.emit();
	/// # Ok(())
	/// # }
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

	/// Steps the fuzz CSP oracle live when the recorded label is in the
	/// alphabet.
	///
	/// - Labels are full URN renderings, and their identity matches
	///   [`crate::testing::specs::csp::Event`] through the shared intern pool,
	///   so structure-aware and simple harnesses both step without alias
	///   tables.
	/// - The step result is discarded, because a label that is disabled or
	///   outside the process alphabet fails the step, and end-of-run CSP
	///   validation owns hard acceptance.
	#[cfg(feature = "testing-fuzz")]
	fn dispatch_csp_event(&self, label: impl AsRef<str>) {
		let label = label.as_ref();
		let Some(oracle) = self.state.oracle.as_ref() else {
			return;
		};

		use crate::testing::specs::csp::{intern, Event};

		let event = Event(intern(label));
		let _ = oracle.step_event(&event);
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

	/// Records the trace clock's time origin once per collector, so
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

	/// Dual-writes a production control-plane event. The URN goes into the
	/// instrument log, and the same URN becomes the assertion label for spec
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

	/// Dual-writes a production control-plane event that carries evidence.
	/// The label records why, such as the refusing status. The payload
	/// records who, such as the peer's SPKI DER, as its SHA3-256 hash when
	/// payload capture is enabled.
	///
	/// `label` accepts any type that converts via [`AsRef<str>`].
	#[cfg(feature = "instrument")]
	pub fn emit_event_with_evidence(&self, event: Urn<'static>, label: impl AsRef<str>, payload: Option<&[u8]>) {
		let label = label.as_ref();
		#[cfg(feature = "testing")]
		{
			if let Ok(builder) = self.event(&event) {
				builder.emit()
			}
		}

		self.record_clock_origin();
		self.emit_internal(event, Some(label), payload, None, self.state.clock.now_ns());
	}

	/// Dual-writes a production control-plane event that carries a
	/// spec-assertable value. The label records why, such as the GoAway
	/// reason name, and the value carries its wire code for `equals!`
	/// assertions.
	///
	/// `label` accepts any type that converts via [`AsRef<str>`].
	#[cfg(feature = "instrument")]
	pub fn emit_event_with_value<V>(&self, event: Urn<'static>, label: impl AsRef<str>, value: V)
	where
		V: Into<EventValue>,
	{
		let label = label.as_ref();
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

	/// Emits an event stamped with a point-in-time instant relative to the
	/// trace clock origin, such as a deadline start or end marker.
	///
	/// Durations and timestamps are distinct `TbEvent` fields. A duration is
	/// a span length, and a timestamp is when the event occurred.
	#[cfg(feature = "instrument")]
	pub fn emit_with_timestamp(&self, event_urn: Urn<'static>, label: impl AsRef<str>, timestamp: Duration) {
		self.emit_internal(event_urn, Some(label.as_ref()), None, None, Some(timestamp.as_nanos() as u64));
	}

	/// How many recorded events carry `label`, read without draining them.
	///
	/// A test waiting on a background task polls this, so the wait ends on
	/// the event it expects rather than on elapsed time. Recording only
	/// appends, so a poisoned lock holds a whole list and is read as is.
	#[cfg(any(test, feature = "testing"))]
	pub fn recorded(&self, label: impl IntoEventLabel) -> usize {
		let label = AssertionLabel::Custom(label.into_label());
		let assertions = self.state.assertions.lock().unwrap_or_else(PoisonError::into_inner);
		assertions.iter().filter(|assertion| assertion.label.matches(&label)).count()
	}

	/// Drains the recorded assertions into a vector.
	#[cfg(any(test, feature = "testing"))]
	pub fn drain_assertions(&self) -> Vec<Assertion> {
		if let Ok(mut assertions) = self.state.assertions.lock() {
			assertions.drain(..).collect()
		} else {
			Vec::new()
		}
	}

	/// Drains the retained events from the configured sink.
	#[cfg(feature = "instrument")]
	pub fn drain_events(&self) -> Vec<TbEvent> {
		self.state.sink.0.drain()
	}

	/// Whether the configured sink dropped any event. The flag is sticky.
	///
	/// Feed this into
	/// [`crate::instrumentation::EvidenceArtifact::finalize`], so evidence
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
fn hash_payload(payload: impl AsRef<[u8]>) -> [u8; 32] {
	let payload = payload.as_ref();
	let mut hasher = Sha3_256::new();
	hasher.update(payload);
	let out = hasher.finalize();

	let mut arr = [0u8; 32];
	arr.copy_from_slice(&out);
	arr
}

/// The execution trace a scenario consumes once the awaited run completes.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct ConsumedTrace {
	/// The assertions the run recorded.
	pub assertions: Vec<Assertion>,
	/// The frame the run accepted, when it recorded one.
	pub accepted_frame: Option<Frame>,
	/// The frame the run rejected, when it recorded one.
	pub rejected_frame: Option<Frame>,
	/// The response frame the run produced, if any.
	pub response: Option<Frame>,

	/// The instrumentation events the run emitted.
	#[cfg(feature = "instrument")]
	pub instrument_events: Vec<TbEvent>,
	/// The gate's decision, when the run passed through a gate.
	#[cfg(feature = "policy")]
	pub gate_decision: Option<TransitStatus>,
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
		}
	}

	/// Moves the collector's assertions and events into this trace.
	pub fn populate_from_collector(&mut self, collector: &TraceCollector) {
		self.assertions.extend(collector.drain_assertions());
		#[cfg(feature = "instrument")]
		{
			self.instrument_events.extend(collector.drain_events());
		}
	}

	pub fn has_response(&self) -> bool {
		self.response.is_some()
	}

	pub fn count_assertions(&self, label: &AssertionLabel, tags: Option<&[&'static str]>) -> usize {
		self.assertions
			.iter()
			.filter(|a| {
				// `matches` accepts the tightbeam URN shorthand, which
				// plain equality would miss.
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

/// The value an event carries into its assertion.
#[derive(Debug, Clone)]
pub enum EventValue {
	/// The event carries no value.
	None,
	/// The event carries an assertable value.
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

/// How a recorded run ended, as specs classify it.
#[cfg(any(test, feature = "testing"))]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
	/// The body returned and no gate decision refused the run.
	Accept,
	/// A gate decision other than `Ok` refused the run.
	Reject,
	/// The body returned an error.
	Error,
}

#[cfg(any(test, feature = "testing"))]
impl ExecutionMode {
	/// What the run did, read from the body's own result and the trace.
	///
	/// An error is what the body returned, and a rejection is a gate decision
	/// other than `Ok`. A run with no gate decision took no gate, so it reads
	/// as accepted.
	#[cfg_attr(not(feature = "policy"), expect(unused_variables))]
	pub fn of(execution: &Result<(), TightBeamError>, trace: &ConsumedTrace) -> Self {
		if execution.is_err() {
			return Self::Error;
		}

		#[cfg(feature = "policy")]
		if matches!(trace.gate_decision, Some(status) if status != TransitStatus::Ok) {
			return Self::Reject;
		}

		Self::Accept
	}

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

	const ALPHA: Urn<'static> = crate::urn!("test", "event:collector/alpha");
	const BETA: Urn<'static> = crate::urn!("test", "event:collector/beta");

	/// A collector built without `csp:` has no oracle, and reading one
	/// reports that rather than ending the process.
	#[test]
	#[cfg(feature = "testing-fuzz")]
	fn a_collector_without_an_oracle_reports_its_absence() {
		let collector = super::TraceCollector::default();

		assert!(collector.try_oracle().is_none());
	}

	/// Every handle a scenario receives answers the way its collector does.
	/// A `share` that dropped the oracle would disarm every fuzz harness
	/// silently, because the harness reads the shared handle, not the one
	/// the macro built.
	#[test]
	#[cfg(feature = "testing-fuzz")]
	fn a_collector_built_with_an_oracle_hands_it_to_every_share(
	) -> Result<(), crate::testing::specs::csp::ProcessBuildError> {
		use crate::testing::specs::csp::{Event, Process, State};

		let process = Process::builder("ShareSpec")
			.initial_state(State("S0"))
			.add_observable(Event("step"))
			.add_transition(State("S0"), Event("step"), State("S1"))
			.add_terminal(State("S1"))
			.build()?;

		let collector = super::TraceCollector::with_fuzz_oracle(Vec::new(), process);

		assert!(collector.try_oracle().is_some());
		assert!(collector.share().try_oracle().is_some());
		Ok(())
	}

	tb_assert_spec! {
		pub TraceCollectorSpec,
		V(1,0,0): {
			mode: Accept,
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
		use std::sync::Mutex;

		use crate::instrumentation::{events, EventSink, TbEvent, TbInstrumentationConfig};
		use crate::trace::{TraceCollector, TraceConfig};

		/// A loss-free sink that retains every event with no cap.
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
					.with_sink(UnboundedSink::default())
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
			let collector = TraceCollector::from(TraceConfig::builder().with_sink(UnboundedSink::default()).build());

			collector.emit(events::START, "only");

			assert_eq!(collector.drain_events().len(), 1);
		}

		#[test]
		fn sink_events_carry_contiguous_seq() {
			let collector = TraceCollector::from(TraceConfig::builder().with_sink(UnboundedSink::default()).build());

			collector.emit(events::START, "first");
			collector.emit(events::END, "second");

			let seqs: Vec<u32> = collector.drain_events().iter().map(|e| e.seq).collect();
			assert_eq!(seqs, vec![0, 1]);
		}
	}
}
