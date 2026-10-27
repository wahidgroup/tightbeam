use core::cell::Cell;
#[cfg(feature = "instrument")]
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use std::borrow::Cow;
use std::sync::Arc;
#[cfg(feature = "instrument")]
use std::sync::{Once, RwLock};

use core::fmt;
#[cfg(any(test, feature = "testing", feature = "testing-fault"))]
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
use crate::trace::{Assertion, AssertionLabel, Presence};
#[cfg(all(feature = "instrument", host_clock))]
use crate::utils::time::SystemClock;
#[cfg(all(feature = "logging", not(feature = "instrument")))]
use crate::utils::time::UnixMillis;
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

/// The configuration of trace collection.
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
	/// Whether the builder writes the instrument record of its event. A
	/// dual-write stamps that record itself, so its builder writes the
	/// assertion alone.
	#[cfg(feature = "instrument")]
	instrumented: bool,
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
			#[cfg(feature = "instrument")]
			instrumented: true,
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
						timestamp: self.collector.log_timestamp(),
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

		// A testing build asserts the label after the record, so the record
		// takes a copy of the label there. Any other build moves the label into
		// the record.
		#[cfg(all(feature = "instrument", any(test, feature = "testing")))]
		let record_label = || Some(label.clone());
		#[cfg(all(feature = "instrument", not(any(test, feature = "testing"))))]
		let record_label = move || Some(label);

		#[cfg(feature = "instrument")]
		if self.instrumented {
			match &value {
				Some(EventValue::None) | None => {
					let urn = if self.duration_ns.is_some() {
						events::TIMING_WCET
					} else {
						events::ASSERT_LABEL
					};

					let payload = self.payload;
					self.collector
						.emit_internal(urn, record_label, || payload, self.duration_ns, None);
				}
				Some(EventValue::Value(assertion_value)) => {
					// An event with a value takes no payload, so the rendered
					// value fills the one payload of the record.
					let rendered = || Some(assertion_value.render());
					self.collector.emit_internal(
						events::ASSERT_PAYLOAD,
						record_label,
						rendered,
						self.duration_ns,
						None,
					);
				}
			}
		}

		#[cfg(feature = "testing-fuzz")]
		self.collector.dispatch_csp_event(&label);

		#[cfg(any(test, feature = "testing"))]
		{
			// One lock gives the assertion its sequence number and its place
			// in the list. A record only appends, so a poisoned lock holds a
			// whole list, and the record reads through the poison.
			let mut assertions = self.collector.state.assertions.lock().unwrap_or_else(PoisonError::into_inner);
			let seq = assertions.len();
			let tags = self.tags.take().map(|t| t.into_owned()).unwrap_or_default();
			let assertion = match value {
				Some(EventValue::None) | None => Assertion::new(seq, AssertionLabel::Custom(label), tags, None),
				Some(EventValue::Value(assertion_value)) => {
					Assertion::with_value(seq, AssertionLabel::Custom(label), tags, None, assertion_value)
				}
			};

			assertions.push(assertion);
		}

		#[cfg(not(any(test, feature = "testing")))]
		let _ = (value, self.tags.take(), self.collector);
		#[cfg(not(any(test, feature = "testing", feature = "instrument")))]
		let _ = label;
	}
}

impl<'a> EventBuilder<'a> {
	/// Adds payload data to the event.
	///
	/// Only an event with no value takes a payload. The instrument record holds
	/// one payload, and an event with a value fills it with the rendered value.
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

#[cfg(all(feature = "instrument", feature = "colony"))]
impl SinkHandle {
	/// The sink of a connection trace: the named one, or a bounded buffer.
	fn sibling(&self, max_events: u32) -> Self {
		let named = self.0.sibling();
		Self(named.unwrap_or_else(|| Arc::new(BoundedMemorySink::new(max_events))))
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
	/// The origin that `clock` reads at the call, which its first event
	/// records.
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

/// The trace clock: each event timestamp counts nanoseconds since the origin
/// that the adopted clock gave. The collector records each origin once
/// ([`TRACE_CLOCK_ORIGIN`]), before the first event that counts from it, so
/// one Unix reading per origin gives the absolute time of every event.
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
	#[cfg(any(feature = "testing-fdr", feature = "colony"))]
	fn clock(&self) -> Option<Arc<dyn Clock>> {
		let guard = self.origin.read().unwrap_or_else(PoisonError::into_inner);
		guard.as_ref().map(|origin| Arc::clone(&origin.clock))
	}

	/// The Unix time on the adopted clock, or `None` with no clock adopted.
	#[cfg(feature = "logging")]
	fn unix_now(&self) -> Option<UnixMillis> {
		let guard = self.origin.read().unwrap_or_else(PoisonError::into_inner);
		guard.as_ref().map(|origin| origin.clock.unix())
	}

	/// A trace clock on the clock of this one, with an origin of its own.
	#[cfg(any(feature = "testing-fdr", feature = "colony"))]
	fn split(&self) -> Self {
		let origin = self.clock().map(TraceOrigin::of);
		Self { origin: RwLock::new(origin) }
	}

	/// Adopts `clock` with a new origin, which the next event records.
	///
	/// A write under the lock replaces the origin whole, so a poisoned lock
	/// takes the new origin too.
	fn adopt(&self, clock: Arc<dyn Clock>) {
		let origin = TraceOrigin::of(clock);
		let mut slot = self.origin.write().unwrap_or_else(PoisonError::into_inner);
		*slot = Some(origin);
	}

	/// Stamps one event on the adopted clock under one read guard.
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
	/// The label stays the `Cow` that the count keys
	/// ([`TraceCollector::check_runtime_fault_injection`]).
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

#[derive(Debug, Default)]
struct TraceState {
	/// The assertions of the run. A connection trace shares the log, so a
	/// scenario spec reads each record of its run.
	#[cfg(any(test, feature = "testing"))]
	assertions: Arc<Mutex<Vec<Assertion>>>,
	/// The frames of the exchanges that a scenario reported. Each frame slot
	/// keeps the first frame that an exchange gives it, as it arrives.
	#[cfg(any(test, feature = "testing"))]
	exchanges: Mutex<ExchangeRecord>,
	/// The sink owns event retention. The default is a bounded in-memory
	/// buffer ([`BoundedMemorySink`]), and consumers may inject their own
	/// through [`TraceConfig::sink`].
	#[cfg(feature = "instrument")]
	sink: SinkHandle,
	#[cfg(feature = "instrument")]
	config: TbInstrumentationConfig,
	/// The sequence number of the next event. One atomic add gives each event
	/// its own number.
	#[cfg(feature = "instrument")]
	seq: AtomicU32,
	#[cfg(feature = "instrument")]
	clock: TraceClock,
	#[cfg(feature = "testing-fuzz")]
	oracle: Option<crate::testing::fuzz::FuzzContext>,
	/// The runtime fault model with the draw state of its strategy. The slot
	/// is empty until [`TraceCollector::with_fault_model`] installs a model,
	/// and an event reads an empty slot with one atomic load.
	///
	/// A connection trace shares the slot of the trace it splits from.
	#[cfg(feature = "testing-fault")]
	runtime_faults: Arc<OnceLock<Mutex<RuntimeFaults>>>,
	/// The log backend of the state. A connection trace shares it.
	#[cfg(feature = "logging")]
	logger_config: Option<Arc<super::logging::LoggerConfig>>,
}

impl TraceState {
	#[cfg(feature = "instrument")]
	fn with_config(config: TbInstrumentationConfig, sink: Option<Arc<dyn EventSink>>) -> Self {
		let sink = SinkHandle(sink.unwrap_or_else(|| Arc::new(BoundedMemorySink::new(config.max_events))));

		Self {
			#[cfg(any(test, feature = "testing"))]
			assertions: Arc::default(),
			#[cfg(any(test, feature = "testing"))]
			exchanges: Mutex::default(),
			sink,
			config,
			seq: AtomicU32::new(0),
			clock: TraceClock::default(),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
			#[cfg(feature = "testing-fault")]
			runtime_faults: Arc::default(),
			#[cfg(feature = "logging")]
			logger_config: None,
		}
	}

	/// A state for the connections of a plane that this state audits.
	///
	/// It shares the logger, the fault slot, and the assertion log. Its sink is
	/// the one that [`EventSink::sibling`] names.
	#[cfg(feature = "colony")]
	fn for_connections(&self) -> Self {
		Self {
			#[cfg(any(test, feature = "testing"))]
			assertions: Arc::clone(&self.assertions),
			#[cfg(any(test, feature = "testing"))]
			exchanges: Mutex::default(),
			#[cfg(feature = "instrument")]
			sink: self.sink.sibling(self.config.max_events),
			#[cfg(feature = "instrument")]
			config: self.config,
			#[cfg(feature = "instrument")]
			seq: AtomicU32::new(0),
			#[cfg(feature = "instrument")]
			clock: self.clock.split(),
			#[cfg(feature = "testing-fuzz")]
			oracle: None,
			#[cfg(feature = "testing-fault")]
			runtime_faults: Arc::clone(&self.runtime_faults),
			#[cfg(feature = "logging")]
			logger_config: self.logger_config.as_ref().map(Arc::clone),
		}
	}

	#[cfg(feature = "testing-fuzz")]
	fn with_oracle(oracle: crate::testing::fuzz::FuzzContext) -> Self {
		Self {
			// The `testing-fuzz` feature implies `testing`, so the fields exist
			// here.
			assertions: Arc::default(),
			exchanges: Mutex::default(),
			#[cfg(feature = "instrument")]
			sink: SinkHandle::default(),
			#[cfg(feature = "instrument")]
			config: TbInstrumentationConfig::default(),
			#[cfg(feature = "instrument")]
			seq: AtomicU32::new(0),
			#[cfg(feature = "instrument")]
			clock: TraceClock::default(),
			oracle: Some(oracle),
			#[cfg(feature = "testing-fault")]
			runtime_faults: Arc::default(),
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

	/// Creates another handle that records into the same state.
	pub fn share(&self) -> Self {
		Self { state: Arc::clone(&self.state) }
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

	/// The Unix time in milliseconds that a log record of this collector
	/// carries: the reading of the adopted clock, or of the host clock in a
	/// build with no trace clock.
	#[cfg(feature = "logging")]
	fn log_timestamp(&self) -> Option<u64> {
		#[cfg(feature = "instrument")]
		let now = self.state.clock.unix_now();
		#[cfg(all(not(feature = "instrument"), host_clock))]
		let now = Some(UnixMillis::now());
		#[cfg(all(not(feature = "instrument"), not(host_clock)))]
		let now: Option<UnixMillis> = None;

		now.map(UnixMillis::get)
	}

	/// A collector with a state and a default sink of its own, under the
	/// instrumentation settings and the clock of this one.
	#[cfg(all(feature = "instrument", feature = "testing-fdr"))]
	pub(crate) fn sibling(&self) -> Self {
		let mut state = TraceState::with_config(self.state.config, None);
		state.clock = self.state.clock.split();

		Self { state: Arc::new(state) }
	}

	/// A collector with a state of its own, which a build without
	/// `instrument` gives the default settings.
	#[cfg(all(not(feature = "instrument"), feature = "testing-fdr"))]
	pub(crate) fn sibling(&self) -> Self {
		Self::default()
	}

	/// A collector for the connections of a plane that this trace audits.
	///
	/// It shares the logger, the fault slot, the assertions, and the clock of
	/// this trace. Its sink is the one that [`EventSink::sibling`] names.
	#[cfg(feature = "colony")]
	pub(crate) fn connections(&self) -> Self {
		Self { state: Arc::new(self.state.for_connections()) }
	}

	/// Configures the log backend of this trace collector.
	///
	/// [`EventBuilder::with_log_level`] sends an event to the log backend. A
	/// default level of the logger config applies to every other event.
	///
	/// Only the sole owner of the state can set the config, so call this
	/// before [`TraceCollector::share`].
	///
	/// # Errors
	///
	/// - [`TraceStateShared`] -- another handle shares the state of this
	///   collector. The call drops the config and this handle.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::trace::{LogFilter, LogLevel, LoggerConfig, StdoutBackend};
	/// use tightbeam::trace::{TraceCollector, TraceStateShared};
	///
	/// let config = || LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Error));
	/// let trace = TraceCollector::new().with_logger(config())?;
	/// let _shared = trace.share();
	///
	/// assert!(matches!(trace.with_logger(config()), Err(TraceStateShared)));
	/// # Ok::<(), TraceStateShared>(())
	/// ```
	#[cfg(feature = "logging")]
	pub fn with_logger(mut self, config: super::logging::LoggerConfig) -> Result<Self, TraceStateShared> {
		let Some(state) = Arc::get_mut(&mut self.state) else {
			return Err(TraceStateShared);
		};

		state.logger_config = Some(Arc::new(config));
		Ok(self)
	}

	/// Adopts `clock` as the clock this collector stamps its events on, with
	/// an origin it reads from `clock` at the call.
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
	/// - Every handle that shares the state injects by the model, and so does each connection trace of it.
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

		// The first install fills the slot, and each install replaces the model
		// whole under the lock. A panic under the lock leaves a whole model, so
		// a poisoned lock takes the new model too.
		let slot = self.state.runtime_faults.get_or_init(Mutex::default);
		let mut installed = slot.lock().unwrap_or_else(PoisonError::into_inner);
		*installed = faults;
		drop(installed);
		self
	}

	/// Checks whether the runtime fault model injects a fault at `label_cow`.
	///
	/// # Errors
	///
	/// - The injection point's error, when the model injects a fault.
	///
	/// # Why `&Cow<'static, str>` instead of `&str`
	///
	/// The parameter trips clippy's `ptr_arg` lint, and the lint is allowed
	/// because the zero-copy counters need the `Cow` itself:
	///
	/// - The fault injection counters key a `HashMap<Cow<'static, str>, u32>` by the label.
	/// - `Cow::clone()` on `Cow::Borrowed` copies only the pointer.
	/// - A `&str` parameter would force a `Cow::Borrowed(label)` construction.
	/// - Static labels stay allocation-free, and dynamic labels work too.
	#[allow(clippy::ptr_arg)]
	#[cfg(feature = "testing-fault")]
	fn check_runtime_fault_injection(&self, label_cow: &Cow<'static, str>) -> Result<(), crate::TightBeamError> {
		let Some(slot) = self.state.runtime_faults.get() else {
			return Ok(());
		};

		// A panic under the lock leaves a whole model, as `with_fault_model`
		// states, so the draw reads through a poisoned lock.
		let mut faults = slot.lock().unwrap_or_else(PoisonError::into_inner);
		let fault = faults.draw(label_cow);
		fault.map_or(Ok(()), Err)
	}

	/// Records an event with no tags or value, and returns an
	/// [`EventBuilder`] that chains the optional calls.
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
	/// an [`EventBuilder`] that chains the optional calls.
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

	/// Records `event` with `value` as the assertion of a dual-write, as
	/// [`Self::event_with`] records it with no tags.
	///
	/// The dual-write stamps the one instrument record of `event` on the
	/// trace clock, so the assertion builder writes none.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(all(feature = "testing", any(feature = "instrument", feature = "colony")))]
	fn assert_dual_write<V>(&self, event: &Urn<'static>, value: V) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
	{
		#[cfg_attr(not(feature = "instrument"), expect(unused_mut))]
		let mut builder = self.event_with(event, &[], value)?;
		#[cfg(feature = "instrument")]
		{
			builder.instrumented = false;
		}

		builder.emit();
		Ok(())
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

	/// Takes the sequence number of the next event, which wraps past
	/// `u32::MAX`. Each event needs a number of its own and no order against
	/// other memory, so the add is `Relaxed`.
	#[cfg(feature = "instrument")]
	fn next_seq(&self) -> u32 {
		self.state.seq.fetch_add(1, Ordering::Relaxed)
	}

	/// Writes one event to the sink. `label` renders its label, and runs only
	/// when the sink retains the event. `evidence` renders its payload, and
	/// runs only when the sink retains the event and the config keeps
	/// payloads. A dropped event renders nothing.
	#[cfg(feature = "instrument")]
	fn emit_internal<E: AsRef<[u8]>>(
		&self,
		urn: Urn<'static>,
		label: impl FnOnce() -> Option<Cow<'static, str>>,
		evidence: impl FnOnce() -> Option<E>,
		duration_ns: Option<u64>,
		timestamp_ns: Option<u64>,
	) {
		self.write_record(urn, label, evidence, duration_ns, timestamp_ns, 0);
	}

	/// Writes one event to the sink with `flags`, as [`Self::emit_internal`]
	/// writes one with every flag clear. The event API sets
	/// [`TbEvent::FROM_EVENT_API`] through it, in every build.
	#[cfg(feature = "instrument")]
	fn write_record<E: AsRef<[u8]>>(
		&self,
		urn: Urn<'static>,
		label: impl FnOnce() -> Option<Cow<'static, str>>,
		evidence: impl FnOnce() -> Option<E>,
		duration_ns: Option<u64>,
		timestamp_ns: Option<u64>,
		flags: u32,
	) {
		// The sink owns retention. An event that a bounded sink drops takes a
		// sequence number too, so gaps in `seq` show where truncation
		// occurred. The write asks the sink before it builds the event, so a
		// dropped event costs no allocation.
		let seq = self.next_seq();
		let sink = &self.state.sink.0;
		if !sink.retains() {
			return;
		}

		let cfg = self.state.config;
		let label = label();

		let payload_hash = if cfg.enable_payloads {
			evidence().map(hash_payload)
		} else {
			None
		};

		sink.emit(TbEvent {
			seq,
			urn,
			label,
			payload_hash,
			duration_ns: if cfg.record_durations {
				duration_ns
			} else {
				None
			},
			timestamp_ns,
			flags,
			extras: None,
		});
	}

	#[cfg(feature = "instrument")]
	pub fn emit(&self, event_urn: Urn<'static>, label: impl Into<Cow<'static, str>>) {
		self.emit_with_payload(event_urn, label, None);
	}

	/// Emits `urn` stamped on the adopted clock, with `label` and `evidence`
	/// rendered as [`Self::write_record`] renders them.
	///
	/// - The first event on an origin records that origin first, so relative
	///   `timestamp_ns` values reconstruct to absolute times.
	/// - The event API is the one caller, so the record of `urn` carries [`TbEvent::FROM_EVENT_API`].
	/// - The origin record has every flag clear.
	#[cfg(feature = "instrument")]
	fn emit_stamped<E: AsRef<[u8]>>(
		&self,
		urn: Urn<'static>,
		label: impl FnOnce() -> Option<Cow<'static, str>>,
		evidence: impl FnOnce() -> Option<E>,
	) {
		let record = |origin_unix_ns: u128| {
			let origin = || Some(Cow::Owned(origin_unix_ns.to_string()));
			self.emit_internal(events::TRACE_CLOCK_ORIGIN, origin, no_evidence, None, Some(0));
		};
		let emit = |timestamp_ns| self.write_record(urn, label, evidence, None, timestamp_ns, TbEvent::FROM_EVENT_API);
		self.state.clock.stamp(record, emit);
	}

	/// Dual-writes a production control-plane event. The URN goes into the
	/// instrument log, and under the `testing` feature the same URN becomes
	/// the assertion label for spec assertions and CSP alphabets.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
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
		self.assert_dual_write(&event, ())?;

		self.emit_stamped(event, || None, no_evidence);
		Ok(())
	}

	/// Dual-writes `event` with no label or value, and with the payload that
	/// `evidence` renders. The trace runs `evidence` only when its sink retains
	/// the event and its config keeps payloads.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(all(feature = "instrument", feature = "tokio"))]
	pub(crate) fn emit_event_with_rendered_evidence<E: AsRef<[u8]>>(
		&self,
		event: Urn<'static>,
		evidence: impl FnOnce() -> Option<E>,
	) -> Result<(), crate::TightBeamError> {
		#[cfg(feature = "testing")]
		self.assert_dual_write(&event, ())?;

		self.emit_stamped(event, || None, evidence);
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
		label: impl Into<Cow<'static, str>>,
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
		label: impl Into<Cow<'static, str>>,
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
	/// It is the one reader of the flag. With the flag off, it returns at its
	/// first branch, before any allocation, so an emit site costs that branch
	/// alone. With the flag on, the event carries its label and the trace clock
	/// stamp ([`Self::emit_event_with_evidence`]).
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
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
	#[cfg(any(feature = "instrument", feature = "colony"))]
	pub(crate) fn emit_event_with_value_and_evidence<V>(
		&self,
		event: Urn<'static>,
		label: impl Into<Cow<'static, str>>,
		value: V,
		payload: Option<&[u8]>,
	) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
	{
		self.emit_event_with_value_and_rendered_evidence(event, label, value, || payload)
	}

	/// Dual-writes `event` with `value` and the payload that `evidence`
	/// renders, as [`Self::emit_event_with_value_and_evidence`] writes a
	/// payload in hand.
	///
	/// The trace runs `evidence` only when its sink retains the event and its
	/// config keeps payloads, so a dropped payload renders nothing.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(any(feature = "instrument", feature = "colony"))]
	pub(crate) fn emit_event_with_value_and_rendered_evidence<V, E>(
		&self,
		event: Urn<'static>,
		label: impl Into<Cow<'static, str>>,
		value: V,
		evidence: impl FnOnce() -> Option<E>,
	) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
		E: AsRef<[u8]>,
	{
		self.emit_rendered_event(event, || label, value, evidence)
	}

	/// Dual-writes `event` with `value`, and with the label that `label`
	/// renders, as [`Self::emit_event_with_value`] writes a label in hand.
	///
	/// The trace runs `label` only when its sink retains the event, so a
	/// dropped record renders no label.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	// The audit of a refused handshake is the one emit site, so a build with no
	// handshake protocol leaves out the caller.
	#[cfg(feature = "instrument")]
	#[cfg_attr(
		not(any(feature = "transport-cms", feature = "transport-hpke")),
		allow(dead_code)
	)]
	pub(crate) fn emit_event_with_value_and_rendered_label<V, L>(
		&self,
		event: Urn<'static>,
		label: impl FnOnce() -> L,
		value: V,
	) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
		L: Into<Cow<'static, str>>,
	{
		self.emit_rendered_event(event, label, value, no_evidence)
	}

	/// Dual-writes `event` with `value`, the label that `label` renders, and
	/// the payload that `evidence` renders.
	///
	/// The trace runs `label` only when its sink retains the event, and runs
	/// `evidence` only when its sink retains the event and its config keeps
	/// payloads.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(any(feature = "instrument", feature = "colony"))]
	pub(crate) fn emit_rendered_event<V, L, E>(
		&self,
		event: Urn<'static>,
		label: impl FnOnce() -> L,
		value: V,
		evidence: impl FnOnce() -> Option<E>,
	) -> Result<(), crate::TightBeamError>
	where
		V: Into<EventValue>,
		L: Into<Cow<'static, str>>,
		E: AsRef<[u8]>,
	{
		#[cfg(feature = "testing")]
		self.assert_dual_write(&event, value)?;
		#[cfg(not(feature = "testing"))]
		let _ = value;

		#[cfg(feature = "instrument")]
		self.emit_stamped(event, || Some(label().into()), evidence);
		#[cfg(not(feature = "instrument"))]
		let _ = (event, label, evidence);

		Ok(())
	}

	/// Dual-writes `event`, a colony event that carries no label, no value,
	/// and no payload, through [`Self::emit_event_with_value_and_evidence`].
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(feature = "colony")]
	pub(crate) fn emit_marker(&self, event: Urn<'static>) -> Result<(), crate::TightBeamError> {
		self.emit_event_with_value_and_evidence(event, "", (), None)
	}

	/// Dual-writes `event`, a colony event with no label and no value whose
	/// payload records who, through
	/// [`Self::emit_event_with_value_and_rendered_evidence`]. The trace runs
	/// `evidence` only when its sink retains the event and its config keeps
	/// payloads.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(feature = "colony")]
	pub(crate) fn emit_marker_with_evidence<E: AsRef<[u8]>>(
		&self,
		event: Urn<'static>,
		evidence: impl FnOnce() -> Option<E>,
	) -> Result<(), crate::TightBeamError> {
		self.emit_event_with_value_and_rendered_evidence(event, "", (), evidence)
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_payload(
		&self,
		event_urn: Urn<'static>,
		label: impl Into<Cow<'static, str>>,
		payload: Option<&[u8]>,
	) {
		self.emit_internal(event_urn, || Some(label.into()), || payload, None, None);
	}

	#[cfg(feature = "instrument")]
	pub fn emit_with_timing(&self, event_urn: Urn<'static>, label: impl Into<Cow<'static, str>>, duration: Duration) {
		self.emit_internal(
			event_urn,
			|| Some(label.into()),
			no_evidence,
			Some(duration.as_nanos() as u64),
			None,
		);
	}

	/// Emits an event stamped with a point-in-time instant relative to the
	/// trace clock origin, such as a deadline start or end marker.
	///
	/// Durations and timestamps are distinct fields of [`TbEvent`]. A duration
	/// is a span length, and a timestamp is when the event occurred.
	#[cfg(feature = "instrument")]
	pub fn emit_with_timestamp(
		&self,
		event_urn: Urn<'static>,
		label: impl Into<Cow<'static, str>>,
		timestamp: Duration,
	) {
		self.emit_internal(
			event_urn,
			|| Some(label.into()),
			no_evidence,
			None,
			Some(timestamp.as_nanos() as u64),
		);
	}

	/// Counts the recorded events that carry `label`, and leaves them recorded.
	///
	/// A test that waits on a background task polls this, so the wait ends on
	/// the event it expects and not on elapsed time. A record only appends to
	/// the list, so a poisoned lock holds a whole list, which the count reads.
	#[cfg(any(test, feature = "testing"))]
	pub fn recorded(&self, label: impl IntoEventLabel) -> usize {
		let label = AssertionLabel::Custom(label.into_label());
		let assertions = self.state.assertions.lock().unwrap_or_else(PoisonError::into_inner);
		assertions.iter().filter(|assertion| assertion.label.matches(&label)).count()
	}

	/// Records how the peer of the run answered one request.
	///
	/// The record keeps the first frame of each slot
	/// ([`ConsumedTrace::record_accepted`]), so the collector drops the frames
	/// of a later exchange as it arrives.
	/// [`ConsumedTrace::populate_from_collector`] moves the record into the
	/// trace.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::{ConsumedTrace, Exchange, TraceCollector};
	///
	/// let response = TestFrame::v0(None, Some("response"));
	/// let collector = TraceCollector::new();
	/// let request = TestFrame::v0(None, Some("request"));
	/// collector.record_exchange(Exchange::Accepted { request, response: Some(Box::new(response.clone())) });
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.populate_from_collector(&collector);
	///
	/// assert_eq!(trace.response(), Some(&response));
	/// ```
	#[cfg(any(test, feature = "testing"))]
	pub fn record_exchange(&self, exchange: Exchange) {
		// A record fills empty slots alone, so a poisoned lock holds a whole
		// record.
		let mut record = self.state.exchanges.lock().unwrap_or_else(PoisonError::into_inner);
		record.record(exchange);
	}

	/// Drains the recorded assertions into a vector.
	///
	/// A record only appends to the list, so a poisoned lock holds a whole
	/// list, and the drain takes it as is.
	#[cfg(any(test, feature = "testing"))]
	pub fn drain_assertions(&self) -> Vec<Assertion> {
		let mut assertions = self.state.assertions.lock().unwrap_or_else(PoisonError::into_inner);
		core::mem::take(&mut *assertions)
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

	/// The count of the events that this collector has sequenced, the ones its
	/// sink dropped included.
	///
	/// [`ConsumedTrace::populate_from_collector`] compares it with the events
	/// that it drains. The read needs no order against other memory, so it is
	/// `Relaxed`.
	#[cfg(all(feature = "instrument", any(test, feature = "testing")))]
	fn sequenced(&self) -> u32 {
		self.state.seq.load(Ordering::Relaxed)
	}
}

impl From<TraceConfig> for TraceCollector {
	fn from(config: TraceConfig) -> Self {
		#[cfg(any(feature = "instrument", feature = "logging"))]
		{
			let mut state = TraceState::default();

			#[cfg(feature = "instrument")]
			if config.instrumentation.is_some() || config.sink.is_some() {
				state = TraceState::with_config(config.instrumentation.unwrap_or_default(), config.sink);
			}

			// The conversion is the sole owner of the state, so the state takes
			// the logger config in place.
			#[cfg(feature = "logging")]
			if let Some(logger) = config.logger {
				state.logger_config = Some(Arc::new(logger));
			}

			Self { state: Arc::new(state) }
		}

		#[cfg(not(any(feature = "instrument", feature = "logging")))]
		{
			let _ = config;
			Self::default()
		}
	}
}

/// The render of an event that carries no evidence.
#[cfg(feature = "instrument")]
fn no_evidence() -> Option<&'static [u8]> {
	None
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

/// How the peer of a scenario answered one request, as the client saw it.
///
/// The client closure of a scenario records it with
/// [`TraceCollector::record_exchange`], and the spec reads the frames from the
/// [`ConsumedTrace`]. A `response:` constraint decides on the response that the
/// client received, and refuses a run that records no exchange.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::TestFrame;
/// use tightbeam::trace::{ConsumedTrace, Exchange, TraceCollector};
///
/// let request = TestFrame::v0(None, Some("request"));
/// let response = TestFrame::v0(None, Some("response"));
/// let collector = TraceCollector::new();
/// let answered = Some(Box::new(response.clone()));
/// collector.record_exchange(Exchange::Accepted { request: request.clone(), response: answered });
///
/// let mut trace = ConsumedTrace::new();
/// trace.populate_from_collector(&collector);
///
/// assert_eq!(trace.accepted_frame(), Some(&request));
/// assert_eq!(trace.response(), Some(&response));
/// ```
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug, PartialEq)]
pub enum Exchange {
	/// The peer accepted `request`.
	Accepted {
		/// The request that the peer accepted.
		request: Frame,
		/// The response of the peer, or `None` when it answered with no frame.
		///
		/// The box keeps the two variants near one size.
		response: Option<Box<Frame>>,
	},
	/// The peer refused `request`.
	Rejected {
		/// The request that the peer refused.
		request: Frame,
	},
}

/// The frames that the exchanges of one run report.
///
/// Each frame slot keeps the first frame that an exchange gives it, so a later
/// exchange leaves every filled slot as it is. A response comes only with an
/// accepted request, so a record that holds a response holds that request.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
struct ExchangeRecord {
	/// The first request that the peer accepted.
	accepted: Option<Frame>,
	/// The first request that the peer refused.
	rejected: Option<Frame>,
	/// The first response that the client received.
	response: Option<Frame>,
}

#[cfg(any(test, feature = "testing"))]
impl ExchangeRecord {
	/// Puts `frame` in `slot` when the slot holds no frame.
	fn keep_first(slot: &mut Option<Frame>, frame: Option<Frame>) {
		if slot.is_none() {
			*slot = frame;
		}
	}

	/// Records that the peer accepted `request` and answered with `response`.
	fn accept(&mut self, request: Frame, response: Option<Frame>) {
		Self::keep_first(&mut self.accepted, Some(request));
		Self::keep_first(&mut self.response, response);
	}

	/// Records that the peer refused `request`.
	fn reject(&mut self, request: Frame) {
		Self::keep_first(&mut self.rejected, Some(request));
	}

	/// Records the frames of `exchange` in the slot of its kind.
	fn record(&mut self, exchange: Exchange) {
		match exchange {
			Exchange::Accepted { request, response } => self.accept(request, response.map(|frame| *frame)),
			Exchange::Rejected { request } => self.reject(request),
		}
	}

	/// Takes the frames of `later`, a record of exchanges that arrived after
	/// the exchanges of this one.
	fn merge(&mut self, later: Self) {
		Self::keep_first(&mut self.accepted, later.accepted);
		Self::keep_first(&mut self.rejected, later.rejected);
		Self::keep_first(&mut self.response, later.response);
	}

	/// Whether the client received a response, or `None` when no exchange
	/// reported how the peer answered.
	fn response_presence(&self) -> Option<Presence> {
		let reported = self.accepted.is_some() || self.rejected.is_some();
		reported.then(|| Presence::of_option(&self.response))
	}
}

/// The refusal of a count over an instrumentation record that misses events
/// of its run.
///
/// [`ConsumedTrace::count_event_urn`] returns it when
/// [`ConsumedTrace::is_complete`] reads `false`, because a count over a
/// record that lacks events is a lower bound and decides no exact count.
///
/// # Examples
///
/// ```
/// use tightbeam::instrumentation::{events, TbInstrumentationConfig};
/// use tightbeam::trace::{ConsumedTrace, EventRecordTruncated, TraceCollector, TraceConfig};
///
/// let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
/// let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));
/// collector.emit(events::GATE_ACCEPT, "Ok");
/// collector.emit(events::GATE_ACCEPT, "Ok");
///
/// let mut trace = ConsumedTrace::new();
/// trace.populate_from_collector(&collector);
///
/// assert_eq!(trace.count_event_urn(events::GATE_ACCEPT), Err(EventRecordTruncated));
/// ```
#[cfg(all(feature = "instrument", any(test, feature = "testing")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRecordTruncated;

#[cfg(all(feature = "instrument", any(test, feature = "testing")))]
impl fmt::Display for EventRecordTruncated {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("the instrumentation record misses events of its run, so it decides no count")
	}
}

#[cfg(all(feature = "instrument", any(test, feature = "testing")))]
impl core::error::Error for EventRecordTruncated {}

/// The refusal of [`TraceCollector::with_logger`] on a collector whose state
/// another handle shares ([`TraceCollector::share`]).
///
/// The logger config sits in the state that every handle reads, and only the
/// sole owner of that state can set it.
///
/// # Examples
///
/// ```
/// use tightbeam::trace::{LogFilter, LogLevel, LoggerConfig, StdoutBackend};
/// use tightbeam::trace::{TraceCollector, TraceStateShared};
///
/// let trace = TraceCollector::new();
/// let _shared = trace.share();
/// let config = LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Error));
///
/// assert!(matches!(trace.with_logger(config), Err(TraceStateShared)));
/// ```
#[cfg(feature = "logging")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceStateShared;

#[cfg(feature = "logging")]
impl fmt::Display for TraceStateShared {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("another handle shares the trace state, so the state takes no logger config")
	}
}

#[cfg(feature = "logging")]
impl core::error::Error for TraceStateShared {}

/// The execution trace a scenario consumes once the awaited run completes.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct ConsumedTrace {
	/// The assertions the run recorded.
	pub assertions: Vec<Assertion>,
	/// The frames of the exchanges that the run reported, which
	/// [`Self::record_accepted`] and [`Self::record_rejected`] fill.
	exchanges: ExchangeRecord,

	/// The instrumentation events the run emitted.
	#[cfg(feature = "instrument")]
	pub instrument_events: Vec<TbEvent>,
	/// Whether the record of a collector that this trace drained misses
	/// events, which [`Self::is_complete`] reads.
	#[cfg(feature = "instrument")]
	truncated: bool,
	/// The gate's decision, when the run passed through a gate.
	#[cfg(feature = "policy")]
	pub gate_decision: Option<TransitStatus>,
}

#[cfg(any(test, feature = "testing"))]
impl ConsumedTrace {
	pub fn new() -> Self {
		Self {
			assertions: Vec::new(),
			exchanges: ExchangeRecord::default(),
			#[cfg(feature = "instrument")]
			instrument_events: Vec::new(),
			#[cfg(feature = "instrument")]
			truncated: false,
			#[cfg(feature = "policy")]
			gate_decision: None,
		}
	}

	/// Moves the collector's assertions, exchanges, and events into this trace.
	///
	/// The trace reads as incomplete ([`Self::is_complete`]) when the drained
	/// record misses an event that the collector sequenced:
	///
	/// - The sink dropped the event.
	/// - The sink forwards each event and keeps none.
	/// - A reader drained the collector first, a second drain of one collector included.
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
	/// assert!(!consumed.is_complete());
	/// ```
	pub fn populate_from_collector(&mut self, collector: &TraceCollector) {
		self.assertions.extend(collector.drain_assertions());

		let exchanges = core::mem::take(&mut *collector.state.exchanges.lock().unwrap_or_else(PoisonError::into_inner));
		self.exchanges.merge(exchanges);

		#[cfg(feature = "instrument")]
		{
			// The count reads before the drain, and only the drained events
			// numbered below it count, so the comparison covers the same
			// events whatever another task sequences during the drain.
			let sequenced = collector.sequenced();
			let drained = collector.drain_events();
			let held = drained.iter().filter(|event| event.seq < sequenced).count();
			let whole = u32::try_from(held) == Ok(sequenced) && !collector.overflowed();

			self.truncated |= !whole;
			self.instrument_events.extend(drained);
		}
	}

	/// Records that the peer of the run accepted `request` and answered with
	/// `response`, or with no frame when `response` is `None`.
	///
	/// Each frame slot keeps the first frame that an exchange gives it, so the
	/// response of a run with more than one exchange is the first response
	/// that arrived.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// let (first, second) = (TestFrame::v0(None, Some("first")), TestFrame::v0(None, Some("second")));
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.record_accepted(first.clone(), Some(first.clone()));
	/// trace.record_accepted(second.clone(), Some(second));
	///
	/// assert_eq!(trace.response(), Some(&first));
	/// ```
	pub fn record_accepted(&mut self, request: Frame, response: Option<Frame>) {
		self.exchanges.accept(request, response);
	}

	/// Records that the peer of the run refused `request`.
	///
	/// The slot keeps the first refused request, as
	/// [`Self::record_accepted`] keeps the first of its frames.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::{ConsumedTrace, Presence};
	///
	/// let request = TestFrame::v0(None, Some("request"));
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.record_rejected(request.clone());
	///
	/// assert_eq!(trace.rejected_frame(), Some(&request));
	/// assert_eq!(trace.response_presence(), Some(Presence::Absent));
	/// ```
	pub fn record_rejected(&mut self, request: Frame) {
		self.exchanges.reject(request);
	}

	/// The first request that the peer of the run accepted, when the run
	/// reported one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// let request = TestFrame::v0(None, Some("request"));
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.record_accepted(request.clone(), None);
	///
	/// assert_eq!(trace.accepted_frame(), Some(&request));
	/// ```
	pub fn accepted_frame(&self) -> Option<&Frame> {
		self.exchanges.accepted.as_ref()
	}

	/// The first request that the peer of the run refused, when the run
	/// reported one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// assert_eq!(ConsumedTrace::new().rejected_frame(), None);
	/// ```
	pub fn rejected_frame(&self) -> Option<&Frame> {
		self.exchanges.rejected.as_ref()
	}

	/// The first response that the client of the run received, when the run
	/// reported one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// let (request, response) = (TestFrame::v0(None, Some("request")), TestFrame::v0(None, Some("response")));
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.record_accepted(request, Some(response.clone()));
	///
	/// assert_eq!(trace.response(), Some(&response));
	/// ```
	pub fn response(&self) -> Option<&Frame> {
		self.exchanges.response.as_ref()
	}

	/// Whether the client of the run received a response, or `None` when the
	/// run reported no exchange.
	///
	/// Such a run holds no evidence of how the peer answered, which either
	/// [`Presence::Present`] or [`Presence::Absent`] would claim.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::{ConsumedTrace, Presence};
	///
	/// let mut trace = ConsumedTrace::new();
	/// assert_eq!(trace.response_presence(), None);
	///
	/// trace.record_accepted(TestFrame::v0(None, Some("request")), None);
	/// assert_eq!(trace.response_presence(), Some(Presence::Absent));
	/// ```
	pub fn response_presence(&self) -> Option<Presence> {
		self.exchanges.response_presence()
	}

	pub fn has_response(&self) -> bool {
		self.exchanges.response.is_some()
	}

	/// Whether the instrumentation record of this trace holds every event of
	/// its run.
	///
	/// The record is complete when the sink of each drained collector dropped
	/// no event (by its drop latch), and the trace drained every event that the
	/// collector sequenced. A build without `instrument` holds an empty record,
	/// which is complete.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::{events, EventSink, TbEvent};
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
	///
	/// // A sink that forwards each event and keeps none.
	/// struct Forwarding;
	///
	/// impl EventSink for Forwarding {
	///     fn emit(&self, _event: TbEvent) {}
	///
	///     fn drain(&self) -> Vec<TbEvent> {
	///         Vec::new()
	///     }
	///
	///     fn overflowed(&self) -> bool {
	///         false
	///     }
	/// }
	///
	/// let collector = TraceCollector::from(TraceConfig::builder().with_sink(Forwarding).build());
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.populate_from_collector(&collector);
	///
	/// assert!(!trace.is_complete());
	/// ```
	pub fn is_complete(&self) -> bool {
		#[cfg(feature = "instrument")]
		{
			!self.truncated
		}

		#[cfg(not(feature = "instrument"))]
		{
			true
		}
	}

	/// Marks the trace as one whose sink dropped events, so a test of a
	/// reader can refuse an incomplete record without a dropping sink.
	#[cfg(all(test, feature = "testing-timing"))]
	pub(crate) fn mark_truncated(&mut self) {
		self.truncated = true;
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

	/// The count of the instrumentation events of `event_urn` in this trace.
	///
	/// # Errors
	///
	/// - [`EventRecordTruncated`] -- the record misses events ([`Self::is_complete`]).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::{events, TbInstrumentationConfig};
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
	///
	/// let collector = TraceCollector::from(TraceConfig::with_instrumentation(TbInstrumentationConfig::default()));
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.populate_from_collector(&collector);
	///
	/// assert_eq!(trace.count_event_urn(events::GATE_ACCEPT), Ok(1));
	/// ```
	#[cfg(feature = "instrument")]
	pub fn count_event_urn(&self, event_urn: Urn<'static>) -> Result<usize, EventRecordTruncated> {
		if !self.is_complete() {
			return Err(EventRecordTruncated);
		}

		Ok(self.instrument_events.iter().filter(|e| e.urn == event_urn).count())
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
	/// A run with no gate decision took no gate, so it reads as accepted.
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

	/// The render of the evidence of an event, which the trace runs only when
	/// it keeps the payload.
	#[cfg(feature = "instrument")]
	mod evidence {
		use core::cell::Cell;

		use super::ALPHA;
		use crate::instrumentation::TbInstrumentationConfig;
		use crate::trace::{TraceCollector, TraceConfig};
		use crate::TightBeamError;

		// A trace whose config keeps payloads renders the evidence of an emit,
		// and a trace whose config drops them renders nothing.
		crate::tb_cases! {
			fn an_emit_renders_its_evidence_when_the_trace_keeps_payloads((enable_payloads, rendered): (bool, bool))
				-> Result<(), TightBeamError>
			{
				let config = TbInstrumentationConfig { enable_payloads, ..TbInstrumentationConfig::default() };
				let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
				let ran = Cell::new(false);
				let evidence = || {
					ran.set(true);
					Some(b"evidence")
				};

				trace.emit_event_with_value_and_rendered_evidence(ALPHA, "label", (), evidence)?;
				assert_eq!(ran.get(), rendered);
				Ok(())
			}
			cases {
				kept => (true, true),
				dropped => (false, false),
			}
		}
	}

	mod poison {
		use std::panic::{catch_unwind, AssertUnwindSafe};

		use super::ALPHA;
		use crate::trace::TraceCollector;
		use crate::TightBeamError;

		/// Poisons the assertions lock of `collector`, as a panic while a
		/// record holds the lock would.
		fn poison_assertions(collector: &TraceCollector) {
			let panicked = catch_unwind(AssertUnwindSafe(|| {
				let _held = collector.state.assertions.lock();
				panic!("poison the assertions lock");
			}));

			assert!(panicked.is_err());
			assert!(collector.state.assertions.is_poisoned());
		}

		/// Each write leaves the assertion list whole, so an event that records
		/// after a panic poisoned the lock drains too.
		#[test]
		fn an_event_recorded_after_a_poisoning_panic_drains() -> Result<(), TightBeamError> {
			let collector = TraceCollector::new();
			poison_assertions(&collector);

			collector.event(ALPHA)?.emit();
			assert_eq!(collector.drain_assertions().len(), 1);
			Ok(())
		}
	}

	#[cfg(feature = "testing-fault")]
	mod faults {
		use std::panic::{catch_unwind, AssertUnwindSafe};

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

		/// An error factory that panics, so the draw that calls it panics while
		/// it holds the fault-state lock.
		fn panicking() -> TightBeamError {
			panic!("the error factory panics under the fault-state lock")
		}

		/// Poisons the fault-state lock of `collector`, as a draw whose error
		/// factory panics under the lock does.
		fn poison_fault_state(collector: &TraceCollector) {
			let model = FaultModel::default().with_event_fault(ALPHA, panicking, crate::bps!(10000));
			let faulting = collector.share().with_fault_model(model);

			let panicked = catch_unwind(AssertUnwindSafe(|| faulting.event(ALPHA)));
			assert!(panicked.is_err());
			assert!(collector.state.runtime_faults.get().is_some_and(|faults| faults.is_poisoned()));
		}

		/// A panic under the fault-state lock leaves a whole model, so a model
		/// installed after it injects at its own label.
		#[test]
		fn a_model_installed_after_a_panic_under_the_lock_injects() {
			let collector = TraceCollector::new();
			poison_fault_state(&collector);

			let model = FaultModel::default().with_event_fault(BETA, closed, crate::bps!(10000));
			let collector = collector.with_fault_model(model);
			assert!(matches!(collector.event(BETA), Err(TightBeamError::ChannelClosed)));
		}

		/// A collector that injects a fault at every record of [`ALPHA`].
		#[cfg(feature = "instrument")]
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

		/// An event that a full sink drops takes its sequence number too, so
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

		/// The trace that drains `collector`.
		fn consumed(collector: &TraceCollector) -> ConsumedTrace {
			let mut consumed = ConsumedTrace::new();
			consumed.populate_from_collector(collector);
			consumed
		}

		#[test]
		fn a_trace_that_drains_every_event_of_its_run_is_complete() -> Result<(), Box<dyn core::error::Error>> {
			let collector = collector_with_max_events(2);
			collector.emit(events::START, "first");
			collector.emit(events::END, "second");

			assert!(consumed(&collector).is_complete());
			Ok(())
		}

		#[test]
		fn a_trace_whose_sink_dropped_an_event_is_incomplete() -> Result<(), Box<dyn core::error::Error>> {
			let collector = collector_with_max_events(1);
			collector.emit(events::START, "first");
			collector.emit(events::END, "second");

			assert!(!consumed(&collector).is_complete());
			Ok(())
		}

		/// A reader that drained the collector first leaves the drop latch
		/// clear, and the sequence count shows the events that the trace lacks.
		#[test]
		fn a_trace_that_drains_after_another_reader_is_incomplete() -> Result<(), Box<dyn core::error::Error>> {
			let collector = collector_with_max_events(2);
			collector.emit(events::START, "taken");

			let _taken = collector.drain_events();
			collector.emit(events::END, "left");

			let trace = consumed(&collector);
			assert!(!collector.overflowed(), "no sink dropped an event");
			assert!(!trace.is_complete());
			Ok(())
		}

		#[test]
		fn a_truncated_trace_counts_no_event() -> Result<(), Box<dyn core::error::Error>> {
			let collector = collector_with_max_events(1);
			collector.emit(events::START, "first");
			collector.emit(events::END, "second");

			let counted = consumed(&collector).count_event_urn(events::START);
			assert_eq!(counted, Err(crate::trace::EventRecordTruncated));
			Ok(())
		}
	}

	#[cfg(feature = "instrument")]
	mod sink {
		use std::sync::Mutex;

		use crate::instrumentation::{events, EventSink, TbEvent, TbInstrumentationConfig};
		use crate::trace::{ConsumedTrace, TraceCollector, TraceConfig};

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

		/// A sink that forwards each event and keeps none, or keeps each event
		/// and reports a drop.
		struct Lossy {
			/// Whether the sink keeps each event it receives.
			keeps: bool,
			/// The events that the sink keeps.
			kept: UnboundedSink,
		}

		impl EventSink for Lossy {
			fn emit(&self, event: TbEvent) {
				if self.keeps {
					self.kept.emit(event);
				}
			}

			fn drain(&self) -> Vec<TbEvent> {
				self.kept.drain()
			}

			fn overflowed(&self) -> bool {
				self.keeps
			}
		}

		/// The trace that drains a collector over `sink` after one event.
		fn consumed_over(sink: Lossy) -> ConsumedTrace {
			let collector = TraceCollector::from(TraceConfig::builder().with_sink(sink).build());
			collector.emit(events::START, "only");

			let mut consumed = ConsumedTrace::new();
			consumed.populate_from_collector(&collector);
			consumed
		}

		#[test]
		fn a_trace_over_a_sink_that_keeps_no_event_is_incomplete() -> Result<(), Box<dyn core::error::Error>> {
			let trace = consumed_over(Lossy { keeps: false, kept: UnboundedSink::default() });
			assert!(!trace.is_complete());
			Ok(())
		}

		/// The drop latch of a sink that a collector shares decides as the
		/// sequence count does, so a sink that reports a drop leaves the trace
		/// incomplete with every event of its collector drained.
		#[test]
		fn a_trace_over_a_sink_that_reports_a_drop_is_incomplete() -> Result<(), Box<dyn core::error::Error>> {
			let trace = consumed_over(Lossy { keeps: true, kept: UnboundedSink::default() });
			assert!(!trace.is_complete());
			Ok(())
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
			/// Notes whether an adoption's write lock is free at this moment.
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
		use std::borrow::Cow;

		use super::super::InternalEvent;
		use crate::instrumentation::events;
		use crate::testing::fixtures::TestTrace;
		use crate::urn::Urn;
		use crate::TightBeamError;

		/// The URN and the label of one record.
		type Entry = (Urn<'static>, Option<Cow<'static, str>>);

		/// The URN and the label of each event that one handler entry records
		/// under a trace whose config sets `enable_internal_detail` to
		/// `detail`.
		fn recorded_entries(detail: bool) -> Result<Vec<Entry>, TightBeamError> {
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
			let entry = (events::HANDLER_ENTER, Some(Cow::Borrowed("handler_enter")));
			assert_eq!([recorded_entries(true)?, recorded_entries(false)?], [vec![entry], vec![]]);
			Ok(())
		}

		/// The record of an internal event borrows the static label of the
		/// event, so the record copies no label.
		#[test]
		fn the_record_of_an_internal_event_borrows_its_label() -> Result<(), TightBeamError> {
			let recorded = recorded_entries(true)?;
			let borrowed: Vec<bool> = recorded
				.iter()
				.map(|(_, label)| matches!(label, Some(Cow::Borrowed(_))))
				.collect();
			assert_eq!(borrowed, [true]);
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

	/// The sink records that one event takes.
	#[cfg(feature = "instrument")]
	mod records {
		use std::sync::Arc;

		use super::ALPHA;
		use crate::instrumentation::events;
		use crate::trace::TraceCollector;
		use crate::urn::Urn;
		use crate::utils::time::{Clock, ManualClock};
		use crate::TightBeamError;

		/// A dual-write takes one sink record of its own, after the record of
		/// the clock origin, whether or not the build asserts it.
		#[test]
		fn a_dual_write_takes_one_sink_record() -> Result<(), TightBeamError> {
			let trace = TraceCollector::new().with_clock(Arc::new(ManualClock::default()) as Arc<dyn Clock>);
			trace.emit_event_with_evidence(ALPHA, "refused", None)?;

			let recorded = trace.drain_events();
			let urns: Vec<Urn<'static>> = recorded.into_iter().map(|event| event.urn).collect();
			assert_eq!(urns, [events::TRACE_CLOCK_ORIGIN, ALPHA]);
			Ok(())
		}
	}

	/// The record that an event hands to the log backend.
	#[cfg(all(feature = "instrument", feature = "logging"))]
	mod log_records {
		use core::time::Duration;
		use std::sync::{Arc, Mutex};

		use super::ALPHA;
		use crate::trace::{LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig, TraceCollector};
		use crate::utils::time::{Clock, ManualClock};

		/// A backend that keeps the timestamp of each record it receives.
		struct Stamps(Arc<Mutex<Vec<Option<u64>>>>);

		impl LogBackend for Stamps {
			fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
				if let Ok(mut stamps) = self.0.lock() {
					stamps.push(record.timestamp);
				}
				Ok(())
			}

			fn accepts(&self, _level: LogLevel) -> bool {
				true
			}
		}

		/// A timed event logs the Unix time of the trace clock in
		/// milliseconds, not the duration it measured.
		#[test]
		fn a_timed_event_logs_the_unix_time_of_the_trace_clock() -> Result<(), Box<dyn core::error::Error>> {
			let clock = Arc::new(ManualClock::default());
			let stamps = Arc::new(Mutex::new(Vec::new()));
			let filter = LogFilter::new(LogLevel::Debug);
			let config = LoggerConfig::new(Stamps(Arc::clone(&stamps)), filter).with_default_level(LogLevel::Info);
			let trace = TraceCollector::new()
				.with_clock(Arc::clone(&clock) as Arc<dyn Clock>)
				.with_logger(config)?;

			trace.event(ALPHA)?.with_timing(Duration::from_millis(5)).emit();

			let logged = stamps.lock().map_err(|_| "the stamp lock is poisoned")?.clone();
			assert_eq!(logged, [Some(clock.unix().get())]);
			Ok(())
		}
	}

	/// The label that each emit path writes into its record.
	#[cfg(feature = "instrument")]
	mod labels {
		use core::cell::Cell;
		use core::time::Duration;
		use std::borrow::Cow;

		use super::ALPHA;
		use crate::instrumentation::TbInstrumentationConfig;
		use crate::trace::{TraceCollector, TraceConfig};
		use crate::TightBeamError;

		/// The static label that each emit path writes.
		const LABEL: &str = "refused";

		/// One emit path, which writes `LABEL` at `ALPHA` in a trace.
		type Emit = fn(&TraceCollector) -> Result<(), TightBeamError>;

		// The record that a trace keeps of a static label borrows the label on
		// every emit path, so the record copies no label.
		crate::tb_cases! {
			fn the_record_of_a_static_label_borrows_it(emit: Emit) -> Result<(), TightBeamError> {
				let trace = TraceCollector::new();
				emit(&trace)?;

				let recorded = trace.drain_events();
				let labels = recorded.into_iter().filter(|event| event.urn == ALPHA).map(|event| event.label);
				let borrowed: Vec<bool> = labels.map(|label| matches!(label, Some(Cow::Borrowed(LABEL)))).collect();
				assert_eq!(borrowed, [true]);
				Ok(())
			}
			cases {
				emit => |trace| {
					trace.emit(ALPHA, LABEL);
					Ok(())
				},
				emit_with_payload => |trace| {
					trace.emit_with_payload(ALPHA, LABEL, None);
					Ok(())
				},
				emit_with_timing => |trace| {
					trace.emit_with_timing(ALPHA, LABEL, Duration::from_millis(5));
					Ok(())
				},
				emit_with_timestamp => |trace| {
					trace.emit_with_timestamp(ALPHA, LABEL, Duration::from_millis(5));
					Ok(())
				},
				emit_event_with_evidence => |trace| trace.emit_event_with_evidence(ALPHA, LABEL, None),
				emit_event_with_value => |trace| trace.emit_event_with_value(ALPHA, LABEL, 7u32),
				emit_event_with_value_and_evidence => |trace| {
					trace.emit_event_with_value_and_evidence(ALPHA, LABEL, (), None)
				},
				emit_event_with_value_and_rendered_evidence => |trace| {
					trace.emit_event_with_value_and_rendered_evidence(ALPHA, LABEL, (), || Some(b"evidence"))
				},
				emit_event_with_value_and_rendered_label => |trace| {
					trace.emit_event_with_value_and_rendered_label(ALPHA, || LABEL, ())
				},
			}
		}

		// A trace renders the label of an emit when its sink keeps the record,
		// and renders nothing when its sink drops the record.
		crate::tb_cases! {
			fn an_emit_renders_its_label_when_the_sink_keeps_the_record((max_events, rendered): (u32, bool))
				-> Result<(), TightBeamError>
			{
				let config = TbInstrumentationConfig { max_events, ..TbInstrumentationConfig::default() };
				let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
				let ran = Cell::new(false);
				let label = || {
					ran.set(true);
					LABEL
				};

				trace.emit_event_with_value_and_rendered_label(ALPHA, label, ())?;
				assert_eq!(ran.get(), rendered);
				Ok(())
			}
			cases {
				kept => (u32::MAX, true),
				dropped => (0, false),
			}
		}
	}

	/// The state that a connection trace shares with the trace it splits from.
	#[cfg(feature = "colony")]
	mod connections {
		use super::ALPHA;
		use crate::trace::TraceCollector;
		use crate::TightBeamError;

		/// A model installed after the split injects on the connection trace.
		#[cfg(feature = "testing-fault")]
		#[test]
		fn a_connection_trace_injects_the_faults_of_its_parent() -> Result<(), TightBeamError> {
			use crate::testing::fdr::FaultModel;

			let parent = TraceCollector::new();
			let connections = parent.connections();
			let closed = || TightBeamError::ChannelClosed;
			let model = FaultModel::default().with_event_fault(ALPHA, closed, crate::bps!(10000));
			let _faulted = parent.with_fault_model(model);

			assert!(matches!(connections.event(ALPHA), Err(TightBeamError::ChannelClosed)));
			Ok(())
		}

		/// A connection trace logs its events through the logger of its parent.
		#[cfg(feature = "logging")]
		#[test]
		fn a_connection_trace_logs_through_the_logger_of_its_parent() -> Result<(), Box<dyn core::error::Error>> {
			use core::sync::atomic::{AtomicUsize, Ordering};
			use std::sync::Arc;

			use crate::trace::{LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig};

			/// A backend that counts the records it receives.
			struct Counting(Arc<AtomicUsize>);

			impl LogBackend for Counting {
				fn emit(&self, _record: &LogRecord) -> Result<(), LogError> {
					self.0.fetch_add(1, Ordering::SeqCst);
					Ok(())
				}

				fn accepts(&self, _level: LogLevel) -> bool {
					true
				}
			}

			let logged = Arc::new(AtomicUsize::new(0));
			let filter = LogFilter::new(LogLevel::Debug);
			let config = LoggerConfig::new(Counting(Arc::clone(&logged)), filter).with_default_level(LogLevel::Info);
			let parent = TraceCollector::new().with_logger(config)?;

			parent.connections().event(ALPHA)?.emit();

			assert_eq!(logged.load(Ordering::SeqCst), 1);
			Ok(())
		}

		/// A connection trace records into the sink its parent's sink names.
		#[cfg(feature = "instrument")]
		#[test]
		fn a_connection_trace_records_into_the_sink_its_parent_names() -> Result<(), TightBeamError> {
			use std::sync::Arc;

			use crate::instrumentation::{BoundedMemorySink, EventSink, TbEvent};
			use crate::trace::TraceConfig;

			/// A sink that forwards each event to a shared destination.
			struct Forwarding(Arc<BoundedMemorySink>);

			impl EventSink for Forwarding {
				fn emit(&self, event: TbEvent) {
					self.0.emit(event);
				}

				fn drain(&self) -> Vec<TbEvent> {
					Vec::new()
				}

				fn overflowed(&self) -> bool {
					self.0.overflowed()
				}

				fn sibling(&self) -> Option<Arc<dyn EventSink>> {
					Some(Arc::clone(&self.0) as Arc<dyn EventSink>)
				}
			}

			let destination = Arc::new(BoundedMemorySink::default());
			let config = TraceConfig::builder().with_sink(Forwarding(Arc::clone(&destination))).build();
			let parent = TraceCollector::from(config);

			parent.connections().emit_event(ALPHA)?;

			let forwarded = destination.drain().into_iter().filter(|event| event.urn == ALPHA).count();
			assert_eq!(forwarded, 1);
			Ok(())
		}
	}
}
