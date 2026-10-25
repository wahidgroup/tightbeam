use core::cell::Cell;
use core::time::Duration;

use std::borrow::Cow;
use std::sync::Arc;
#[cfg(feature = "instrument")]
use std::sync::{Once, RwLock};

use core::fmt;
#[cfg(any(test, feature = "testing", feature = "instrument", feature = "testing-fault"))]
use std::sync::Mutex;
#[cfg(feature = "testing-fault")]
use std::sync::OnceLock;
#[cfg(any(test, feature = "testing", feature = "instrument"))]
use std::sync::PoisonError;

use crate::trace::{AssertionValue, TraceConfigBuilder};
use crate::urn::Urn;

#[cfg(feature = "instrument")]
use crate::crypto::hash::{Digest, Sha3_256};
#[cfg(any(test, feature = "testing"))]
use crate::error::TightBeamError;
#[cfg(feature = "instrument")]
use crate::instrumentation::{events, BoundedMemorySink, EventSink, TbEvent, TbInstrumentationConfig};
#[cfg(all(feature = "policy", any(test, feature = "testing")))]
use crate::policy::TransitStatus;
#[cfg(feature = "testing-fault")]
use crate::testing::fdr::{FaultModel, StrategyDraw};
#[cfg(feature = "logging")]
use crate::trace::logging::LogRecord;
#[cfg(any(test, feature = "testing"))]
use crate::trace::{Assertion, AssertionLabel};
#[cfg(all(feature = "instrument", host_clock))]
use crate::utils::time::SystemClock;
#[cfg(feature = "instrument")]
use crate::utils::time::{Clock, MonotonicInstant, UnixMillis};
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

/// An internal event: a step inside the request path, which a trace records
/// when its config sets [`enable_internal_detail`].
///
/// The set is closed, so [`TraceCollector::emit_internal_event`], the one
/// reader of the flag, gates these events alone. Each variant maps to its URN
/// in [`events`] and to its label, the name the event taxonomy gives the step.
///
/// [`enable_internal_detail`]: crate::instrumentation::TbInstrumentationConfig::enable_internal_detail
// The emit sites sit in the transport, the mux, and the servlet, and `colony`
// turns on all of them. A build without `colony` leaves out some sites, and a
// build without `instrument` reads the labels alone, so some variants and the
// reader have no caller there.
#[cfg(any(feature = "instrument", feature = "testing-fdr"))]
#[cfg_attr(not(all(feature = "colony", feature = "instrument")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InternalEvent {
	/// The entry into the application handler of an admitted call.
	HandlerEnter,
	/// The exit from the application handler of an admitted call.
	HandlerExit,
	/// A frame body that a servlet decrypted for typed delivery.
	CryptoStep,
	/// A cleartext frame body that a servlet inflated for typed delivery.
	CompressStep,
	/// A peer stream that the mux responder routed to the method of its kind.
	RouteStep,
	/// A collector gate that evaluated one inbound call.
	PolicyEval,
}

// As on `InternalEvent`, a build without `colony` or `instrument` leaves out
// some callers.
#[cfg(any(feature = "instrument", feature = "testing-fdr"))]
#[cfg_attr(not(all(feature = "colony", feature = "instrument")), allow(dead_code))]
impl InternalEvent {
	/// Every internal event, which [`Self::of`] reads as the closed set.
	#[cfg(all(feature = "instrument", feature = "testing-fdr"))]
	const ALL: [Self; 6] = [
		Self::HandlerEnter,
		Self::HandlerExit,
		Self::CryptoStep,
		Self::CompressStep,
		Self::RouteStep,
		Self::PolicyEval,
	];

	/// The internal event that `urn` names, or [`None`] when `urn` names an
	/// event outside the set.
	///
	/// The trace analysis of FDR reads it to project a trace onto its hidden
	/// steps, so an event that the flag gates is a hidden step there too.
	#[cfg(all(feature = "instrument", feature = "testing-fdr"))]
	pub(crate) fn of(urn: &Urn<'_>) -> Option<Self> {
		Self::ALL.into_iter().find(|event| event.urn() == *urn)
	}

	/// The URN of this event in the inventory.
	#[cfg(feature = "instrument")]
	fn urn(self) -> Urn<'static> {
		match self {
			Self::HandlerEnter => events::HANDLER_ENTER,
			Self::HandlerExit => events::HANDLER_EXIT,
			Self::CryptoStep => events::CRYPTO_STEP,
			Self::CompressStep => events::COMPRESS_STEP,
			Self::RouteStep => events::ROUTE_STEP,
			Self::PolicyEval => events::POLICY_EVAL,
		}
	}

	/// The label of this event, which the trace analysis of FDR reads as the
	/// name of a hidden step and offers in its acceptance sets.
	pub(crate) const fn label(self) -> &'static str {
		match self {
			Self::HandlerEnter => "handler_enter",
			Self::HandlerExit => "handler_exit",
			Self::CryptoStep => "crypto_step",
			Self::CompressStep => "compress_step",
			Self::RouteStep => "route_step",
			Self::PolicyEval => "policy_eval",
		}
	}
}

/// Configuration for trace collection.
#[derive(Default)]
pub struct TraceConfig {
	/// The instrumentation settings. `None` uses the default settings.
	#[cfg(feature = "instrument")]
	pub instrumentation: Option<TbInstrumentationConfig>,
	/// The sink that retains and exports events. `None` uses the default
	/// bounded in-memory buffer ([`BoundedMemorySink`]) sized by
	/// `instrumentation.max_events`.
	#[cfg(feature = "instrument")]
	pub sink: Option<Arc<dyn EventSink>>,
	/// The log backend configuration. `None` leaves events off the log backend.
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

/// A builder that constructs and emits one trace event.
///
/// The timing and the payload are optional calls that chain onto the builder.
/// `V` is the value the event carries: `()` for an event from
/// [`TraceCollector::event`], and [`EventValue`] for one from
/// [`TraceCollector::event_with`].
///
/// # Examples
///
/// ```rust
/// # use core::time::Duration;
/// # use tightbeam::error::TightBeamError;
/// # use tightbeam::trace::{TraceCollector, EventValue};
/// # use tightbeam::urn::Urn;
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
pub struct EventBuilder<'a, V: Into<EventValue> = ()> {
	collector: &'a TraceCollector,
	label: Cow<'static, str>,
	tags: Option<Cow<'static, [&'static str]>>,
	value: Option<V>,
	#[cfg(any(feature = "instrument", feature = "logging"))]
	duration_ns: Option<u64>,
	#[cfg(feature = "instrument")]
	payload: Option<&'a [u8]>,
	#[cfg(feature = "logging")]
	log_level: Option<super::logging::LogLevel>,
	emitted: Cell<bool>,
}

impl<'a, V: Into<EventValue>> EventBuilder<'a, V> {
	fn new(
		collector: &'a TraceCollector,
		label: Cow<'static, str>,
		tags: Option<Cow<'static, [&'static str]>>,
		value: Option<V>,
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

	/// Sets the log level for this event.
	///
	/// With a log level set, the event also goes to the log backend, when the
	/// collector has one and its filter admits the level.
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
	/// is enabled. The builder also emits the event on drop.
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
					// so the event reaches the trace even when the backend
					// refuses the log record. The outcome of the log write
					// stops here, because `emit` and the drop return `()`.
					let _unlogged = logger_config.backend.emit(&record);
				}
			}
		}

		let label = core::mem::take(&mut self.label);
		let value: Option<EventValue> = self.value.take().map(Into::into);

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
				// An event with a value takes no payload, so the rendered
				// value fills the one payload of the record.
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

impl<'a> EventBuilder<'a> {
	/// Adds payload data to the event.
	///
	/// Only an event with no value takes a payload, because the instrument
	/// record holds one payload, and an event with a value fills it with the
	/// rendered value.
	///
	/// # Examples
	///
	/// ```compile_fail
	/// # use tightbeam::error::TightBeamError;
	/// # use tightbeam::trace::TraceCollector;
	/// # use tightbeam::urn::Urn;
	/// # const ROUTE_STEP: Urn<'static> = tightbeam::urn!("tightbeam", "event:route/step");
	/// # fn example() -> Result<(), TightBeamError> {
	/// # let trace = TraceCollector::default();
	/// trace.event_with(ROUTE_STEP, &[], 3u64)?.with_payload(b"payload").emit();
	/// # Ok(())
	/// # }
	/// ```
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
}

impl<'a, V: Into<EventValue>> Drop for EventBuilder<'a, V> {
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

/// A Debug-opaque handle around the configured event sink.
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

/// A clock beside the readings it gave when a collector adopted it, and
/// whether an event recorded them.
#[cfg(feature = "instrument")]
#[derive(Debug)]
struct TraceOrigin {
	/// The clock each event offset reads.
	clock: Arc<dyn Clock>,
	/// The monotonic reading each offset counts from.
	monotonic: MonotonicInstant,
	/// The Unix time of the same instant, in milliseconds.
	unix: UnixMillis,
	/// Completes once the first event on this origin has recorded it, and
	/// holds each other event on the origin until then.
	recorded: Once,
}

#[cfg(feature = "instrument")]
impl TraceOrigin {
	/// The origin that `clock` reads now, which the first event on it records.
	fn of(clock: Arc<dyn Clock>) -> Self {
		let monotonic = clock.monotonic();
		let unix = clock.unix();
		Self { clock, monotonic, unix, recorded: Once::new() }
	}

	/// The nanoseconds on the clock since the origin, saturated to the range of
	/// a `u64`.
	fn offset_ns(&self) -> u64 {
		let since = self.clock.monotonic().saturating_duration_since(self.monotonic);
		u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
	}

	/// The origin as Unix-epoch nanoseconds, at the millisecond precision of
	/// the clock.
	fn unix_ns(&self) -> u128 {
		u128::from(self.unix.get()).saturating_mul(1_000_000)
	}
}

/// The trace clock, whose event timestamps count nanoseconds on the clock a
/// collector adopted since the origin it took from that clock. The collector
/// records each origin once ([`TRACE_CLOCK_ORIGIN`]), before the first event
/// that counts from it, so one Unix reading per origin gives the absolute time
/// of every event.
///
/// - A collector adopts [`SystemClock`] where the host has one, and
///   [`TraceCollector::with_clock`] adopts another.
/// - A build with no host clock stamps its events once a clock is adopted.
///
/// [`TRACE_CLOCK_ORIGIN`]: events::TRACE_CLOCK_ORIGIN
#[cfg(feature = "instrument")]
#[derive(Debug)]
struct TraceClock {
	/// The adopted clock with its origin.
	origin: RwLock<Option<TraceOrigin>>,
}

#[cfg(feature = "instrument")]
impl Default for TraceClock {
	fn default() -> Self {
		#[cfg(host_clock)]
		let origin = Some(TraceOrigin::of(Arc::new(SystemClock)));
		#[cfg(not(host_clock))]
		let origin = None;
		Self { origin: RwLock::new(origin) }
	}
}

#[cfg(feature = "instrument")]
impl TraceClock {
	/// The clock that this trace clock adopted, if any.
	#[cfg(feature = "testing-fdr")]
	fn clock(&self) -> Option<Arc<dyn Clock>> {
		let guard = self.origin.read().unwrap_or_else(PoisonError::into_inner);
		guard.as_ref().map(|origin| Arc::clone(&origin.clock))
	}

	/// Adopt `clock` with a new origin, which the next event records.
	///
	/// A write under the lock replaces the origin whole, so a poisoned lock
	/// takes the new origin too.
	fn adopt(&self, clock: Arc<dyn Clock>) {
		let origin = TraceOrigin::of(clock);
		let mut slot = self.origin.write().unwrap_or_else(PoisonError::into_inner);
		*slot = Some(origin);
	}

	/// Stamp one event on the adopted clock under one read guard.
	///
	/// - `record` receives the origin as Unix-epoch nanoseconds when the event is the first on it.
	/// - `emit` then receives the nanoseconds on the clock since the origin, or `None` with no clock adopted.
	///
	/// An adoption takes the write lock, so it lands before the origin record
	/// or after the event. Each other event on the origin waits for its
	/// record, so every event counts from an origin the trace recorded before
	/// it.
	fn stamp(&self, record: impl FnOnce(u128), emit: impl FnOnce(Option<u64>)) {
		let guard = self.origin.read().unwrap_or_else(PoisonError::into_inner);
		let Some(origin) = guard.as_ref() else {
			emit(None);
			return;
		};

		// A record that panicked leaves the origin unrecorded, so the next
		// event on it records it.
		origin.recorded.call_once_force(|_| record(origin.unix_ns()));
		emit(Some(origin.offset_ns()));
	}
}

/// The runtime fault model of a collector, beside the draw state of its
/// injection strategy.
///
/// [`Self::new`] starts the strategy from its initial state, so one model
/// injects the same faults on each run.
#[cfg(feature = "testing-fault")]
#[derive(Debug)]
struct RuntimeFaults {
	/// The model whose runtime injection points [`Self::draw`] reads.
	model: FaultModel,
	/// The draw state of the model's strategy.
	strategy: StrategyDraw,
}

#[cfg(feature = "testing-fault")]
impl RuntimeFaults {
	/// Creates the faults of `model`, with its strategy at its start.
	fn new(model: FaultModel) -> Self {
		let strategy = model.strategy_draw();
		Self { model, strategy }
	}

	/// Draws the fault the model injects at this record of `label`, or `None`.
	///
	/// The label stays the `Cow` that the count keys, as
	/// [`TraceCollector::check_runtime_fault_injection`] states.
	#[allow(clippy::ptr_arg)]
	fn draw(&mut self, label: &Cow<'static, str>) -> Option<crate::TightBeamError> {
		let injection = self.model.runtime_injection(label)?;
		let inject = self.strategy.injects(label, injection);

		inject.then(|| (injection.error_factory)())
	}
}

/// The faults of the default model, whose set of injection points is empty.
#[cfg(feature = "testing-fault")]
impl Default for RuntimeFaults {
	fn default() -> Self {
		Self::new(FaultModel::default())
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
	/// The runtime fault model with the draw state of its strategy. The slot
	/// is empty until [`TraceCollector::with_fault_model`] installs a model,
	/// and an event reads an empty slot with one atomic load.
	#[cfg(feature = "testing-fault")]
	runtime_faults: OnceLock<Mutex<RuntimeFaults>>,
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
			runtime_faults: OnceLock::new(),
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
			runtime_faults: OnceLock::new(),
			#[cfg(feature = "logging")]
			logger_config: None,
		}
	}

	#[cfg(feature = "testing-fuzz")]
	fn with_oracle(oracle: crate::testing::fuzz::FuzzContext) -> Self {
		Self {
			// The `testing-fuzz` feature implies `testing`, so the field exists
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
			oracle: Some(oracle),
			#[cfg(feature = "testing-fault")]
			runtime_faults: OnceLock::new(),
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

/// The exploration events that the instrumentation settings of a trace ask
/// FDR exploration to record. [`TraceCollector::exploration_asks`] copies
/// these three flags out of the settings.
#[cfg(all(feature = "instrument", feature = "testing-fdr"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExplorationAsks {
	/// Whether each visited state records the observable events it offers, as
	/// [`TbInstrumentationConfig::sample_enabled_sets`] asks.
	pub(crate) enabled_sets: bool,
	/// Whether each visited stable or accepting state records its refusal set,
	/// as [`TbInstrumentationConfig::sample_refusals`] asks.
	pub(crate) refusals: bool,
	/// Whether each state where a seed diverged records the run of the
	/// divergence, as [`TbInstrumentationConfig::divergence_heuristics`] asks.
	pub(crate) divergences: bool,
}

impl TraceCollector {
	/// Creates an empty trace collector with the default config.
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

	/// The exploration events that the instrumentation settings of this
	/// collector ask for.
	#[cfg(all(feature = "instrument", feature = "testing-fdr"))]
	pub(crate) fn exploration_asks(&self) -> ExplorationAsks {
		let settings = &self.state.config;
		ExplorationAsks {
			enabled_sets: settings.sample_enabled_sets,
			refusals: settings.sample_refusals,
			divergences: settings.divergence_heuristics,
		}
	}

	/// A collector with a state and a default sink of its own, under the
	/// instrumentation settings and the clock of this one.
	#[cfg(all(feature = "instrument", feature = "testing-fdr"))]
	pub(crate) fn sibling(&self) -> Self {
		let sibling = Self::with_config(self.state.config, None);
		let clock = self.state.clock.clock();
		if let Some(clock) = clock {
			sibling.state.clock.adopt(clock);
		}

		sibling
	}

	/// A collector with a state of its own, which a build without
	/// `instrument` gives the default settings.
	#[cfg(all(not(feature = "instrument"), feature = "testing-fdr"))]
	pub(crate) fn sibling(&self) -> Self {
		Self::default()
	}

	/// Configures the log backend of this trace collector.
	///
	/// An event reaches the log backend through
	/// [`EventBuilder::with_log_level`]. When the logger config has a default
	/// level, that level applies to every event without an explicit one.
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

	/// Adopts `clock` as the clock this collector stamps its events on, with
	/// an origin it reads from `clock` now.
	///
	/// - Every handle that shares the state reads the clock.
	/// - The next event records the origin as
	///   [`TRACE_CLOCK_ORIGIN`](events::TRACE_CLOCK_ORIGIN), in Unix-epoch
	///   nanoseconds at the millisecond precision of the clock.
	/// - The `timestamp_ns` of each event counts nanoseconds on the clock from the origin.
	/// - [`Default`] adopts [`SystemClock`] where the host has one.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::utils::time::{Clock, SystemClock};
	///
	/// const POOL_DIAL: tightbeam::urn::Urn<'static> = tightbeam::urn!("tightbeam", "event:pool/dial");
	///
	/// let clock: Arc<dyn Clock> = Arc::new(SystemClock);
	/// let trace = TraceCollector::new().with_clock(clock);
	/// trace.emit_event(POOL_DIAL)?;
	///
	/// // The event carries its timestamp on the clock.
	/// let events = trace.drain_events();
	/// let dial = events.iter().find(|event| event.urn == POOL_DIAL);
	/// assert!(dial.is_some_and(|event| event.timestamp_ns.is_some()));
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	#[cfg(feature = "instrument")]
	pub fn with_clock(self, clock: Arc<dyn Clock>) -> Self {
		self.state.clock.adopt(clock);
		self
	}

	/// Creates a trace collector that steps `oracle` live as it records each
	/// event.
	#[cfg(feature = "testing-fuzz")]
	pub(crate) fn with_fuzz_context(oracle: crate::testing::fuzz::FuzzContext) -> Self {
		Self { state: Arc::new(TraceState::with_oracle(oracle)) }
	}

	/// Installs `model` as the runtime fault model of the state this
	/// collector shares, so [`Self::event`] and [`Self::event_with`] inject
	/// the faults that [`FaultModel::with_event_fault`] keys.
	///
	/// - Every handle that shares the state injects by the model.
	/// - The model starts its strategy with the count of each label at zero and the generator at its seed.
	/// - A model installed later replaces this one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::FaultModel;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::urn::Urn;
	/// use tightbeam::TightBeamError;
	///
	/// const SEND: Urn<'static> = tightbeam::urn!("test", "event:example/send");
	///
	/// // At 5000 bps (50%), the deterministic strategy injects on the second
	/// // record of two.
	/// let fault = || TightBeamError::ChannelClosed;
	/// let model = FaultModel::default().with_event_fault(SEND, fault, tightbeam::bps!(5000));
	/// let trace = TraceCollector::new().with_fault_model(model);
	/// assert!(trace.event(SEND).is_ok());
	/// assert!(matches!(trace.event(SEND), Err(TightBeamError::ChannelClosed)));
	/// ```
	#[cfg(feature = "testing-fault")]
	pub fn with_fault_model(self, model: FaultModel) -> Self {
		let faults = RuntimeFaults::new(model);

		// The slot holds a model from the first install on, and each install
		// replaces it under the lock. A panic under the lock leaves a whole
		// model, and the install replaces it whole, so a poisoned lock takes
		// the new model too.
		let slot = self.state.runtime_faults.get_or_init(Mutex::default);
		let mut installed = slot.lock().unwrap_or_else(PoisonError::into_inner);
		*installed = faults;
		drop(installed);
		self
	}

	/// Checks whether the runtime fault model injects a fault at
	/// `label_cow`.
	///
	/// # Errors
	///
	/// - The injection point's error, when the model injects a fault.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	///
	/// # Why `&Cow<'static, str>` instead of `&str`
	///
	/// The parameter trips clippy's `ptr_arg` lint, and the lint is allowed
	/// because the zero-copy counters need the `Cow` itself:
	///
	/// - The fault injection counters key a `HashMap<Cow<'static, str>, u32>` by the label.
	/// - `Cow::clone()` on `Cow::Borrowed` copies only the pointer.
	/// - A `&str` parameter would force a `Cow::Borrowed(label)` construction.
	/// - Static labels stay allocation-free, and dynamic labels still work.
	#[allow(clippy::ptr_arg)]
	#[cfg(feature = "testing-fault")]
	fn check_runtime_fault_injection(&self, label_cow: &Cow<'static, str>) -> Result<(), crate::TightBeamError> {
		let Some(slot) = self.state.runtime_faults.get() else {
			return Ok(());
		};

		let mut faults = slot.lock()?;
		let fault = faults.draw(label_cow);
		fault.map_or(Ok(()), Err)
	}

	/// Records an event with no tags or value, and returns an
	/// [`EventBuilder`] that chains the optional calls.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `label`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	pub fn event(&self, label: impl IntoEventLabel) -> Result<EventBuilder<'_>, crate::TightBeamError> {
		let label_cow = label.into_label();

		#[cfg(feature = "testing-fault")]
		self.check_runtime_fault_injection(&label_cow)?;

		Ok(EventBuilder::new(self, label_cow, None, None))
	}

	/// Records an event with explicit tags and an optional value, and returns
	/// an [`EventBuilder`] that chains the optional calls.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `label`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	///
	/// # Zero-allocation option
	///
	/// A static slice of tags avoids an allocation:
	///
	/// ```rust
	/// # use tightbeam::error::TightBeamError;
	/// # use tightbeam::trace::TraceCollector;
	/// # use tightbeam::urn::Urn;
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
	) -> Result<EventBuilder<'_, EventValue>, crate::TightBeamError>
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
	///   so structure-aware and simple harnesses both step on the label as
	///   rendered.
	/// - The dispatch discards the step result, because a label that is
	///   disabled or outside the process alphabet fails the step, and
	///   end-of-run CSP validation owns hard acceptance.
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
			*seq = current.wrapping_add(1);
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
		// The sink owns retention: events dropped by a bounded sink still
		// consume a sequence number, so gaps in `seq` reveal where truncation
		// occurred. This method asks the sink before it builds the event, so an
		// event that the sink drops costs no allocation.
		let seq = self.next_seq();
		let sink = &self.state.sink.0;
		if !sink.retains() {
			return;
		}

		let cfg = self.state.config;

		let payload_hash = if cfg.enable_payloads {
			payload.map(hash_payload)
		} else {
			None
		};

		sink.emit(TbEvent {
			seq,
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

	/// Emits `urn` stamped on the adopted clock. The first event on an origin
	/// records that origin first, so relative `timestamp_ns` values
	/// reconstruct to absolute times.
	#[cfg(feature = "instrument")]
	fn emit_stamped(&self, urn: Urn<'static>, label: Option<&str>, payload: Option<&[u8]>) {
		let record = |origin_unix_ns: u128| {
			let origin = origin_unix_ns.to_string();
			self.emit_internal(events::TRACE_CLOCK_ORIGIN, Some(&origin), None, None, Some(0));
		};
		let emit = |timestamp_ns| self.emit_internal(urn, label, payload, None, timestamp_ns);
		self.state.clock.stamp(record, emit);
	}

	/// Dual-writes a production control-plane event. The URN goes into the
	/// instrument log, and under the `testing` feature the same URN becomes
	/// the assertion label for spec assertions and CSP alphabets.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	///
	/// # Examples
	///
	/// ```rust
	/// # use tightbeam::trace::TraceCollector;
	/// # const POOL_DIAL: tightbeam::urn::Urn<'static> = tightbeam::urn!("tightbeam", "event:pool/dial");
	/// let trace = TraceCollector::default();
	/// trace.emit_event(POOL_DIAL)?;
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	#[cfg(feature = "instrument")]
	pub fn emit_event(&self, event: Urn<'static>) -> Result<(), crate::TightBeamError> {
		#[cfg(feature = "testing")]
		self.event(&event)?.emit();

		self.emit_stamped(event, None, None);
		Ok(())
	}

	/// Dual-writes a production control-plane event that carries evidence.
	/// The label records why, such as the refusal status. The payload
	/// records who, such as the peer's SPKI DER, as its SHA3-256 hash when
	/// payload capture is enabled.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	///
	/// # Examples
	///
	/// ```rust
	/// # use tightbeam::trace::TraceCollector;
	/// # const GATE_REJECT: tightbeam::urn::Urn<'static> = tightbeam::urn!("tightbeam", "event:gate/reject");
	/// let trace = TraceCollector::default();
	/// trace.emit_event_with_evidence(GATE_REJECT, "PermissionDenied", Some(b"peer key"))?;
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	#[cfg(feature = "instrument")]
	pub fn emit_event_with_evidence(
		&self,
		event: Urn<'static>,
		label: impl AsRef<str>,
		payload: Option<&[u8]>,
	) -> Result<(), crate::TightBeamError> {
		self.emit_event_with_value_and_evidence(event, label, (), payload)
	}

	/// Dual-writes a production control-plane event that carries a
	/// spec-assertable value. The label records why, such as the GoAway
	/// reason name, and the value carries its wire code for `equals!`
	/// assertions.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	///
	/// # Examples
	///
	/// ```rust
	/// # use tightbeam::trace::TraceCollector;
	/// # const GOAWAY_SENT: tightbeam::urn::Urn<'static> = tightbeam::urn!("tightbeam", "event:mux/goaway");
	/// let trace = TraceCollector::default();
	/// trace.emit_event_with_value(GOAWAY_SENT, "Shutdown", 0u32)?;
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	#[cfg(feature = "instrument")]
	pub fn emit_event_with_value<V>(
		&self,
		event: Urn<'static>,
		label: impl AsRef<str>,
		value: V,
	) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
	{
		self.emit_event_with_value_and_evidence(event, label, value, None)
	}

	/// Dual-writes `event`, an internal event, when the config of this trace
	/// sets [`enable_internal_detail`].
	///
	/// This method is the one reader of the flag. With the flag off it returns
	/// at its first branch, before any allocation, so an emit site costs that
	/// branch alone. With the flag on, the event carries its label and the
	/// trace clock stamp, as [`Self::emit_event_with_evidence`] writes it.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	///
	/// [`enable_internal_detail`]: TbInstrumentationConfig::enable_internal_detail
	// As on `InternalEvent`, a build without `colony` leaves out some callers.
	#[cfg(feature = "instrument")]
	#[cfg_attr(not(feature = "colony"), allow(dead_code))]
	#[inline]
	pub(crate) fn emit_internal_event(&self, event: InternalEvent) -> Result<(), crate::TightBeamError> {
		if !self.state.config.enable_internal_detail {
			return Ok(());
		}

		self.emit_event_with_evidence(event.urn(), event.label(), None)
	}

	/// Dual-writes a production control-plane event that carries a
	/// spec-assertable value and evidence. The value reaches the assertion
	/// for `equals!` checks. The label records why, and the payload records
	/// who, as its SHA3-256 hash when payload capture is enabled.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	/// - [`crate::TightBeamError::LockPoisoned`] -- the fault-state lock is poisoned.
	#[cfg(any(feature = "instrument", feature = "colony"))]
	pub(crate) fn emit_event_with_value_and_evidence<V>(
		&self,
		event: Urn<'static>,
		label: impl AsRef<str>,
		value: V,
		payload: Option<&[u8]>,
	) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
	{
		let label = label.as_ref();
		#[cfg(feature = "testing")]
		self.event_with(&event, &[], value)?.emit();
		#[cfg(not(feature = "testing"))]
		let _ = value;

		#[cfg(feature = "instrument")]
		self.emit_stamped(event, Some(label), payload);
		#[cfg(not(feature = "instrument"))]
		let _ = (event, label, payload);

		Ok(())
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
	/// Durations and timestamps are distinct fields of [`TbEvent`]. A duration
	/// is a span length, and a timestamp is when the event occurred.
	#[cfg(feature = "instrument")]
	pub fn emit_with_timestamp(&self, event_urn: Urn<'static>, label: impl AsRef<str>, timestamp: Duration) {
		self.emit_internal(event_urn, Some(label.as_ref()), None, None, Some(timestamp.as_nanos() as u64));
	}

	/// Counts the recorded events that carry `label`, and leaves them recorded.
	///
	/// A test that waits on a background task polls this, so the wait ends on
	/// the event it expects rather than on elapsed time. An event record only
	/// appends to the list, so a poisoned lock holds a whole list, and the
	/// count reads it as is.
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

	/// Reports whether the configured sink dropped any event, as a sticky flag.
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
	/// Whether the sink of a collector that this trace drained dropped events,
	/// so [`Self::instrument_events`] holds a truncated record.
	#[cfg(feature = "instrument")]
	pub overflowed: bool,
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
			#[cfg(feature = "instrument")]
			overflowed: false,
			#[cfg(feature = "policy")]
			gate_decision: None,
		}
	}

	/// Moves the collector's assertions and events into this trace.
	///
	/// The overflow latch of the collector's sink comes along, so a trace that
	/// drained a truncated record says so in [`Self::overflowed`].
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::{events, TbInstrumentationConfig};
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
	///
	/// let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
	/// let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	///
	/// let mut consumed = ConsumedTrace::new();
	/// consumed.populate_from_collector(&collector);
	///
	/// assert!(consumed.overflowed);
	/// ```
	pub fn populate_from_collector(&mut self, collector: &TraceCollector) {
		self.assertions.extend(collector.drain_assertions());
		#[cfg(feature = "instrument")]
		{
			self.instrument_events.extend(collector.drain_events());
			self.overflowed |= collector.overflowed();
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

/// The way a recorded run ended, as specs classify it.
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
	/// Reads what the run did from the body's own result and the trace.
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
	use crate::urn::Urn;
	use crate::{exactly, tb_assert_spec, tb_scenario, testing::SetupEnv};

	const ALPHA: Urn<'static> = crate::urn!("test", "event:collector/alpha");
	const BETA: Urn<'static> = crate::urn!("test", "event:collector/beta");

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

	#[cfg(feature = "testing-fault")]
	mod faults {
		use super::{ALPHA, BETA};
		use crate::testing::fdr::{FaultModel, InjectionStrategy};
		use crate::trace::TraceCollector;
		use crate::TightBeamError;

		/// The seed of the random strategy in these tests.
		const SEED: u64 = 7;

		/// The records at which the random strategy injects at 5000 bps from
		/// [`SEED`], computed outside the crate from the generator's LCG.
		const SEED_DRAWS: [bool; 32] = [
			true, true, true, true, false, false, true, true, true, false, true, true, true, true, false, true, false,
			false, false, true, false, true, true, false, false, true, false, true, true, false, true, false,
		];

		/// The error each fault of these tests injects.
		fn closed() -> TightBeamError {
			TightBeamError::ChannelClosed
		}

		/// A model installed through one handle injects at every handle that
		/// shares its state.
		#[test]
		fn a_model_installed_through_one_handle_injects_at_its_shares() -> Result<(), TightBeamError> {
			let collector = TraceCollector::new();
			let shared = collector.share();
			let model = FaultModel::default().with_event_fault(ALPHA, closed, crate::bps!(10000));
			let _collector = collector.with_fault_model(model);

			assert!(matches!(shared.event(ALPHA), Err(TightBeamError::ChannelClosed)));
			Ok(())
		}

		/// At 5000 bps the deterministic strategy injects on the second record
		/// of each label, and it counts each label apart.
		#[test]
		fn the_deterministic_strategy_counts_each_label_apart() -> Result<(), TightBeamError> {
			let model = FaultModel::default().with_event_fault(ALPHA, closed, crate::bps!(5000));
			let model = model.with_event_fault(BETA, closed, crate::bps!(5000));
			let collector = TraceCollector::new().with_fault_model(model);

			collector.event(ALPHA)?;
			collector.event(BETA)?;
			assert!(matches!(collector.event(ALPHA), Err(TightBeamError::ChannelClosed)));
			assert!(matches!(collector.event(BETA), Err(TightBeamError::ChannelClosed)));
			Ok(())
		}

		/// A model installed later replaces the model the state holds.
		#[test]
		fn a_model_installed_later_replaces_the_first() -> Result<(), TightBeamError> {
			let first = FaultModel::default().with_event_fault(ALPHA, closed, crate::bps!(10000));
			let second = FaultModel::default().with_event_fault(BETA, closed, crate::bps!(10000));
			let collector = TraceCollector::new().with_fault_model(first).with_fault_model(second);

			collector.event(ALPHA)?;
			assert!(matches!(collector.event(BETA), Err(TightBeamError::ChannelClosed)));
			Ok(())
		}

		/// A collector that injects a fault at every record of [`ALPHA`].
		fn faulting_at_alpha() -> TraceCollector {
			let model = FaultModel::default().with_event_fault(ALPHA, closed, crate::bps!(10000));
			TraceCollector::new().with_fault_model(model)
		}

		/// A dual-write emit returns the fault injected at its event, so its
		/// caller fails.
		#[cfg(feature = "instrument")]
		#[test]
		fn an_emit_returns_the_fault_injected_at_its_event() {
			let refused = faulting_at_alpha().emit_event(ALPHA);
			assert!(matches!(refused, Err(TightBeamError::ChannelClosed)));
		}

		/// An emit with evidence returns the fault injected at its event.
		#[cfg(feature = "instrument")]
		#[test]
		fn an_emit_with_evidence_returns_the_fault_injected_at_its_event() {
			let refused = faulting_at_alpha().emit_event_with_evidence(ALPHA, "refused", None);
			assert!(matches!(refused, Err(TightBeamError::ChannelClosed)));
		}

		/// An emit with a value returns the fault injected at its event.
		#[cfg(feature = "instrument")]
		#[test]
		fn an_emit_with_a_value_returns_the_fault_injected_at_its_event() {
			let refused = faulting_at_alpha().emit_event_with_value(ALPHA, "refused", 7u32);
			assert!(matches!(refused, Err(TightBeamError::ChannelClosed)));
		}

		/// The random strategy draws as the FDR generator of the model's seed,
		/// so the seed decides each fault.
		#[test]
		fn the_random_strategy_draws_from_the_seed_of_the_model() -> Result<(), TightBeamError> {
			let model = FaultModel::from(InjectionStrategy::Random).with_seed(SEED);
			let model = model.with_event_fault(ALPHA, closed, crate::bps!(5000));
			let collector = TraceCollector::new().with_fault_model(model);

			let drawn: Vec<bool> = (0..32).map(|_| collector.event(ALPHA).is_err()).collect();
			assert_eq!(drawn, SEED_DRAWS);
			Ok(())
		}
	}

	#[cfg(feature = "instrument")]
	mod overflow {
		use crate::instrumentation::{events, TbInstrumentationConfig};
		use crate::trace::{ConsumedTrace, TraceCollector, TraceConfig};

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

		/// An event that a full sink drops still takes its sequence number, so
		/// the gap marks where the sink cut the record.
		#[test]
		fn a_dropped_event_still_takes_its_sequence_number() {
			let collector = collector_with_max_events(1);
			collector.emit(events::START, "kept");
			collector.emit(events::END, "dropped");
			let before = collector.drain_events();
			collector.emit(events::END, "after the drain");

			let after = collector.drain_events();
			let seqs = [before, after].map(|kept| kept.iter().map(|event| event.seq).collect::<Vec<u32>>());
			assert_eq!(seqs, [vec![0], vec![2]]);
		}

		/// A consumed trace carries the overflow latch of the collector it
		/// drained, so a truncated record says so.
		#[test]
		fn a_consumed_trace_carries_the_overflow_latch_of_its_collector() {
			let latched = [1, 2].map(|max_events| {
				let collector = collector_with_max_events(max_events);
				collector.emit(events::START, "first");
				collector.emit(events::END, "second");

				let mut consumed = ConsumedTrace::new();
				consumed.populate_from_collector(&collector);
				consumed.overflowed
			});
			assert_eq!(latched, [true, false]);
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

	/// The trace clock reads the clock its collector adopts.
	#[cfg(feature = "instrument")]
	mod clock {
		use core::time::Duration;
		use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

		use super::super::TraceState;
		use crate::instrumentation::{events, EventSink, TbEvent};
		use crate::trace::{TraceCollector, TraceConfig};
		use crate::utils::time::{Clock, ManualClock};
		use crate::TightBeamError;

		/// A manual clock an hour past its start, so its readings differ from
		/// those of the system clock.
		fn advanced_clock() -> Arc<ManualClock> {
			let clock = Arc::new(ManualClock::default());
			clock.advance(Duration::from_secs(3600));
			clock
		}

		/// Notes, as each event stamped on the trace clock lands in its sink,
		/// whether a collector could adopt a clock at that moment.
		#[derive(Default)]
		struct AdoptionProbe {
			/// The state whose trace clock an adoption would take.
			state: OnceLock<Weak<TraceState>>,
			/// One answer for each event, in the order the events landed.
			adoptable: Mutex<Vec<bool>>,
		}

		impl AdoptionProbe {
			/// Note whether the write lock that an adoption takes is free now.
			fn note(&self) {
				let state = self.state.get().and_then(Weak::upgrade);
				let state = state.expect("the probe watches a live collector");
				let attempt = state.clock.origin.try_write();
				let free = attempt.is_ok();
				drop(attempt);

				let mut adoptable = self.adoptable.lock().unwrap_or_else(PoisonError::into_inner);
				adoptable.push(free);
			}

			/// The answers noted so far.
			fn noted(&self) -> Vec<bool> {
				let adoptable = self.adoptable.lock().unwrap_or_else(PoisonError::into_inner);
				adoptable.clone()
			}
		}

		/// The sink of a probed collector, which notes each event it receives
		/// that carries a timestamp.
		struct ProbingSink(Arc<AdoptionProbe>);

		impl EventSink for ProbingSink {
			fn emit(&self, event: TbEvent) {
				if event.timestamp_ns.is_some() {
					self.0.note();
				}
			}

			fn drain(&self) -> Vec<TbEvent> {
				Vec::new()
			}

			fn overflowed(&self) -> bool {
				false
			}
		}

		/// A collector on an advanced clock whose sink notes for `probe`.
		fn probed_collector(probe: &Arc<AdoptionProbe>) -> TraceCollector {
			let sink = ProbingSink(Arc::clone(probe));
			let config = TraceConfig::builder().with_sink(sink).build();
			let trace = TraceCollector::from(config).with_clock(advanced_clock() as Arc<dyn Clock>);
			let watched = probe.state.set(Arc::downgrade(&trace.state));
			watched.expect("a probe watches one collector");
			trace
		}

		/// A collector records as its origin the reading of the clock it
		/// adopts, in Unix-epoch nanoseconds at the clock's millisecond
		/// precision.
		#[test]
		fn a_collector_stamps_its_origin_at_the_reading_of_its_clock() -> Result<(), TightBeamError> {
			let clock = advanced_clock();
			let expected = (u128::from(clock.unix().get()) * 1_000_000).to_string();
			let trace = TraceCollector::new().with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
			trace.emit_event(events::START)?;

			let recorded = trace.drain_events();
			let origin = recorded.iter().find(|event| event.urn == events::TRACE_CLOCK_ORIGIN);
			let label = origin.and_then(|event| event.label.as_deref());
			assert_eq!(label, Some(expected.as_str()));
			Ok(())
		}

		/// The timestamp of an event is the span the adopted clock moved since
		/// the origin.
		#[test]
		fn an_event_stamps_the_span_its_clock_moved() -> Result<(), TightBeamError> {
			let clock = advanced_clock();
			let trace = TraceCollector::new().with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
			clock.advance(Duration::from_secs(5));
			trace.emit_event(events::START)?;

			let recorded = trace.drain_events();
			let event = recorded.iter().find(|event| event.urn == events::START);
			let stamp = event.and_then(|event| event.timestamp_ns);
			assert_eq!(stamp, Some(5_000_000_000));
			Ok(())
		}

		/// A collector records each origin it adopts once, before the first
		/// event that counts from it.
		#[test]
		fn each_adopted_origin_is_recorded_before_its_events() -> Result<(), TightBeamError> {
			let trace = TraceCollector::new().with_clock(advanced_clock() as Arc<dyn Clock>);
			trace.emit_event(events::START)?;
			trace.emit_event(events::START)?;
			let trace = trace.with_clock(advanced_clock() as Arc<dyn Clock>);
			trace.emit_event(events::END)?;

			let recorded = trace.drain_events();
			let stamped = recorded.iter().filter(|event| event.timestamp_ns.is_some());
			let urns: Vec<_> = stamped.map(|event| &event.urn).collect();
			let origin = &events::TRACE_CLOCK_ORIGIN;
			assert_eq!(urns, [origin, &events::START, &events::START, origin, &events::END]);
			Ok(())
		}

		/// An event and the record of its origin land under one read guard of
		/// the trace clock, so an adoption on another handle lands before the
		/// record or after the event.
		#[test]
		fn an_event_and_its_origin_record_land_before_an_adoption() -> Result<(), TightBeamError> {
			let probe = Arc::new(AdoptionProbe::default());
			let trace = probed_collector(&probe);
			trace.emit_event(events::START)?;

			let adoptable = probe.noted();
			assert_eq!(adoptable, [false, false]);
			Ok(())
		}
	}

	/// The payload of an event reaches its instrument record.
	#[cfg(feature = "instrument")]
	mod payload {
		use super::ALPHA;
		use crate::crypto::hash::{Digest, Sha3_256};
		use crate::instrumentation::TbInstrumentationConfig;
		use crate::trace::{TraceCollector, TraceConfig};
		use crate::TightBeamError;

		/// An event with no value records the SHA3-256 hash of its payload.
		#[test]
		fn an_event_records_the_hash_of_its_payload() -> Result<(), TightBeamError> {
			let config = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
			let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));
			collector.event(ALPHA)?.with_payload(b"evidence").emit();

			let expected: [u8; 32] = Sha3_256::digest(b"evidence").into();
			let recorded = collector.drain_events();
			let evidence: Vec<Option<[u8; 32]>> = recorded.iter().map(|event| event.payload_hash).collect();
			assert_eq!(evidence, [Some(expected)]);
			Ok(())
		}
	}

	/// The flag of the trace config gates each internal event.
	#[cfg(feature = "instrument")]
	mod internal {
		use super::super::InternalEvent;
		use crate::instrumentation::events;
		use crate::testing::fixtures::TestTrace;
		use crate::urn::Urn;
		use crate::TightBeamError;

		/// The URN and the label of each event that one handler entry records
		/// under a trace whose config sets `enable_internal_detail` to
		/// `detail`.
		fn recorded_entries(detail: bool) -> Result<Vec<(Urn<'static>, Option<String>)>, TightBeamError> {
			let trace = TestTrace::with_detail(detail);
			trace.emit_internal_event(InternalEvent::HandlerEnter)?;

			let recorded = trace.drain_events();
			let entries = recorded.into_iter().filter(|event| event.urn == events::HANDLER_ENTER);
			Ok(entries.map(|event| (event.urn, event.label)).collect())
		}

		/// An internal event records its URN and its label when the trace
		/// config sets the detail flag, and nothing when it clears the flag.
		#[test]
		fn an_internal_event_records_under_the_detail_flag_alone() -> Result<(), TightBeamError> {
			let entry = (events::HANDLER_ENTER, Some("handler_enter".to_owned()));
			assert_eq!([recorded_entries(true)?, recorded_entries(false)?], [vec![entry], vec![]]);
			Ok(())
		}

		/// The URN of each internal event names that event, and the URN of an
		/// event outside the set names none.
		#[cfg(feature = "testing-fdr")]
		#[test]
		fn the_urn_of_an_event_names_it_in_the_internal_set() {
			let urns = [
				events::HANDLER_ENTER,
				events::HANDLER_EXIT,
				events::CRYPTO_STEP,
				events::COMPRESS_STEP,
				events::ROUTE_STEP,
				events::POLICY_EVAL,
				events::GATE_ACCEPT,
			];
			let expected = [
				Some(InternalEvent::HandlerEnter),
				Some(InternalEvent::HandlerExit),
				Some(InternalEvent::CryptoStep),
				Some(InternalEvent::CompressStep),
				Some(InternalEvent::RouteStep),
				Some(InternalEvent::PolicyEval),
				None,
			];
			assert_eq!(urns.map(|urn| InternalEvent::of(&urn)), expected);
		}
	}
}
