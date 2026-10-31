//! The logging subsystem, with RFC 5424 severity levels.
//!
//! A [`LogBackend`], injected at runtime, writes the records to an output
//! target, such as stdout, a file, or a SIEM.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write};

use crate::standards::rfc::rfc5424::SyslogSeverity;
use crate::Errorizable;

/// The severity of a log record: the RFC 5424 severity set, as syslog
/// numbers it.
///
/// A lower value is a higher severity. [`SyslogSeverity`] declares the set,
/// with its names and its numeric parse, and this alias names it.
///
/// # Examples
///
/// ```
/// use tightbeam::trace::LogLevel;
///
/// assert!(LogLevel::Warning < LogLevel::Informational);
/// assert_eq!(LogLevel::Informational.to_string(), "INFORMATIONAL");
/// ```
pub type LogLevel = SyslogSeverity;

/// One log event, as a [`LogBackend`] receives it.
#[derive(Debug, Clone)]
pub struct LogRecord<'a> {
	/// The severity level.
	pub level: LogLevel,
	/// The Unix timestamp in milliseconds, when the record has one.
	pub timestamp: Option<u64>,
	/// The component or module name, when the record names one.
	pub component: Option<&'a str>,
	/// The log message.
	pub message: &'a str,
	/// The key-value metadata pairs, when the record has any.
	pub metadata: Option<&'a [(&'a str, &'a str)]>,
}

/// The errors of a logging operation.
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
	/// An I/O operation failed.
	#[error("I/O error")]
	IoError,
	/// The log buffer is full.
	#[error("buffer full")]
	BufferFull,
	/// The backend is unavailable.
	#[error("backend unavailable")]
	BackendUnavailable,
}

/// A logging backend, which writes log records to its output target.
pub trait LogBackend: Send + Sync {
	/// Emit a log record.
	///
	/// # Errors
	///
	/// - [`LogError`] -- the backend cannot emit the record.
	fn emit(&self, record: &LogRecord) -> Result<(), LogError>;

	/// Whether this backend accepts records at `level`, by its own criteria.
	///
	/// A trace reads it before it hands a record to the backend, so the
	/// backend receives each record that the filter of the trace admits and
	/// that it accepts.
	fn accepts(&self, level: LogLevel) -> bool;

	/// Flush the buffered records of an async backend. The default flushes
	/// nothing.
	///
	/// A trace calls it on [`TraceCollector::flush_log`], and once more when
	/// the last handle of the trace drops.
	///
	/// [`TraceCollector::flush_log`]: crate::trace::TraceCollector::flush_log
	///
	/// # Errors
	///
	/// - [`LogError`] -- the flush fails.
	fn flush(&self) -> Result<(), LogError> {
		Ok(())
	}
}

/// The filter that decides which log records emit: a global minimum level,
/// with overrides per component.
#[derive(Debug, Clone)]
pub struct LogFilter {
	/// The global minimum log level.
	min_level: LogLevel,
	/// The log level overrides per component.
	component_overrides: HashMap<Cow<'static, str>, LogLevel>,
}

impl Default for LogFilter {
	fn default() -> Self {
		Self { min_level: LogLevel::Informational, component_overrides: HashMap::new() }
	}
}

impl LogFilter {
	/// Create a filter whose minimum level is `min_level`.
	pub fn new(min_level: LogLevel) -> Self {
		Self { min_level, component_overrides: HashMap::new() }
	}

	/// Override the log level of `component`, such as Debug for "security"
	/// while every other component stays at Info.
	pub fn with_component(mut self, component: impl Into<Cow<'static, str>>, level: LogLevel) -> Self {
		self.component_overrides.insert(component.into(), level);
		self
	}

	/// Whether a record at `level` from `component` emits: the override of
	/// `component` sets the threshold, or the minimum level does.
	pub fn should_log(&self, level: LogLevel, component: Option<&str>) -> bool {
		let threshold = if let Some(comp) = component {
			self.component_overrides.get(comp).copied().unwrap_or(self.min_level)
		} else {
			self.min_level
		};

		level <= threshold
	}
}

/// The logger configuration: a backend, a filter, and an optional default
/// level.
pub struct LoggerConfig {
	/// The backend that writes the records.
	pub backend: Box<dyn LogBackend>,
	/// The filter that decides which records emit.
	pub filter: LogFilter,
	/// The level of an event that names no level.
	pub default_level: Option<LogLevel>,
}

impl core::fmt::Debug for LoggerConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("LoggerConfig")
			.field("backend", &"<dyn LogBackend>")
			.field("filter", &self.filter)
			.field("default_level", &self.default_level)
			.finish()
	}
}

impl LoggerConfig {
	/// Create a logger config from its backend and its filter.
	pub fn new(backend: impl LogBackend + 'static, filter: LogFilter) -> Self {
		let backend: Box<dyn LogBackend> = Box::new(backend);
		Self { backend, filter, default_level: None }
	}

	/// Set the level of an event that names no level.
	pub fn with_default_level(mut self, level: LogLevel) -> Self {
		self.default_level = Some(level);
		self
	}

	/// The level that a record of `requested` level and of `component` logs
	/// at, or `None` when this logger writes no record of it.
	///
	/// A request with no level takes the default level. The record logs when
	/// [`LogFilter::should_log`] admits the level and [`LogBackend::accepts`]
	/// of the backend takes it.
	fn admit(&self, requested: Option<LogLevel>, component: Option<&str>) -> Option<LogLevel> {
		let level = requested.or(self.default_level)?;
		let admitted = self.filter.should_log(level, component) && self.backend.accepts(level);
		admitted.then_some(level)
	}
}

/// The logger of a trace, which each handle of the trace and each connection
/// trace of it share.
///
/// The last of them to drop flushes the backend, so a backend that buffers
/// its records writes them out when the trace ends.
#[derive(Debug)]
pub(crate) struct TraceLogger {
	/// The backend, the filter, and the default level of the trace.
	config: LoggerConfig,
}

impl TraceLogger {
	/// Writes the record of `message` to the backend, when this logger admits
	/// the `requested` level for `component`, as [`LoggerConfig::admit`]
	/// decides.
	///
	/// The record takes the admitted level, and `timestamp` runs only for a
	/// record that the logger admits.
	///
	/// # Errors
	///
	/// - The error of [`LogBackend::emit`], when the backend refuses the record.
	pub(crate) fn log(
		&self,
		requested: Option<LogLevel>,
		component: Option<&str>,
		message: &str,
		timestamp: impl FnOnce() -> Option<u64>,
	) -> Result<(), LogError> {
		let Some(level) = self.config.admit(requested, component) else {
			return Ok(());
		};

		let record = LogRecord { level, timestamp: timestamp(), component, message, metadata: None };
		self.config.backend.emit(&record)
	}

	/// Flushes the backend, so a backend that buffers its records writes them
	/// out.
	///
	/// # Errors
	///
	/// - The error of [`LogBackend::flush`].
	pub(crate) fn flush(&self) -> Result<(), LogError> {
		self.config.backend.flush()
	}
}

impl From<LoggerConfig> for TraceLogger {
	fn from(config: LoggerConfig) -> Self {
		Self { config }
	}
}

impl Drop for TraceLogger {
	// A drop has no caller to take the error of the flush, so the error stops
	// here. `TraceCollector::flush_log` returns it to a caller that asks.
	fn drop(&mut self) {
		let _unflushed = self.flush();
	}
}

/// A backend that writes the records to standard output.
#[derive(Debug, Clone, Copy)]
pub struct StdoutBackend;

impl Default for StdoutBackend {
	fn default() -> Self {
		Self
	}
}

impl StdoutBackend {
	/// Writes `record` to `out`: one line for the record, and one line for
	/// each metadata pair.
	///
	/// # Errors
	///
	/// - [`LogError::IoError`] -- a write to `out` fails, such as on a pipe whose reader closed.
	fn write_record(out: &mut impl Write, record: &LogRecord) -> Result<(), LogError> {
		let component = record.component.unwrap_or("app");
		let timestamp = record.timestamp.map(|ts| format!("[{}] ", ts)).unwrap_or_default();

		// `LogError` is `Copy`, so the variant alone names the failure.
		let refused = |_: io::Error| LogError::IoError;
		let line = writeln!(out, "{timestamp}[{}] {component}: {}", record.level, record.message);
		line.map_err(refused)?;

		if let Some(metadata) = record.metadata {
			for (key, value) in metadata {
				writeln!(out, "  {key}: {value}").map_err(refused)?;
			}
		}

		Ok(())
	}
}

impl LogBackend for StdoutBackend {
	/// Writes `record` to the locked stdout, so the lines of one record stay
	/// together.
	///
	/// # Errors
	///
	/// - [`LogError::IoError`] -- the write to stdout fails, such as on a pipe whose reader closed.
	fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
		let mut out = io::stdout().lock();
		Self::write_record(&mut out, record)
	}

	fn accepts(&self, _level: LogLevel) -> bool {
		true
	}
}

/// A backend that fans each record out to every inner backend that accepts its
/// level, so one record can reach stdout, a file, and a SIEM at once.
pub struct MultiplexBackend {
	backends: Vec<Box<dyn LogBackend>>,
}

impl MultiplexBackend {
	/// Create a backend that fans each record out to `backends`.
	pub fn new(backends: Vec<Box<dyn LogBackend>>) -> Self {
		Self { backends }
	}
}

impl LogBackend for MultiplexBackend {
	fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
		for backend in &self.backends {
			if backend.accepts(record.level) {
				backend.emit(record)?;
			}
		}
		Ok(())
	}

	fn accepts(&self, level: LogLevel) -> bool {
		self.backends.iter().any(|b| b.accepts(level))
	}

	fn flush(&self) -> Result<(), LogError> {
		for backend in &self.backends {
			backend.flush()?;
		}
		Ok(())
	}
}

/// The log backend of the owner tests of the logger and the trace.
#[cfg(test)]
pub(crate) mod fixtures {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::{Arc, Mutex, PoisonError};

	use super::{LogBackend, LogError, LogLevel, LogRecord};

	/// The level, the message, and the component of a captured record.
	pub(crate) type Captured = (LogLevel, String, Option<String>);

	/// One record as a [`CaptureBackend`] keeps it: its fields, and the
	/// timestamp it carries.
	type Kept = (Captured, Option<u64>);

	/// A real in-process [`LogBackend`] that keeps in memory each record it
	/// receives, so a test reads back the records that crossed the backend
	/// seam.
	///
	/// - It accepts the level it holds and each more severe level, and [`Default`] accepts every level.
	/// - It counts the flushes it runs.
	/// - Its clones share one list of records and one count of flushes, so a
	///   test keeps a clone and hands the backend to a logger.
	#[derive(Clone)]
	pub(crate) struct CaptureBackend {
		/// The least severe level that the backend accepts.
		accepts_up_to: LogLevel,
		/// The fields of each record, beside the timestamp it carries.
		records: Arc<Mutex<Vec<Kept>>>,
		/// The count of the flushes the backend ran.
		flushes: Arc<AtomicUsize>,
	}

	impl Default for CaptureBackend {
		fn default() -> Self {
			Self::accepting(LogLevel::Debug)
		}
	}

	impl CaptureBackend {
		/// A backend that accepts the records of `level` and of each more
		/// severe level.
		pub(crate) fn accepting(level: LogLevel) -> Self {
			Self { accepts_up_to: level, records: Arc::default(), flushes: Arc::default() }
		}

		/// The level, the message, and the component of each record this
		/// backend received, in order.
		pub(crate) fn records(&self) -> Vec<Captured> {
			let records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
			records.iter().map(|(captured, _)| captured.clone()).collect()
		}

		/// The timestamp of each record this backend received, in order.
		#[cfg(feature = "instrument")]
		pub(crate) fn timestamps(&self) -> Vec<Option<u64>> {
			let records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
			records.iter().map(|(_, timestamp)| *timestamp).collect()
		}

		/// The count of the flushes this backend ran.
		pub(crate) fn flushes(&self) -> usize {
			self.flushes.load(Ordering::Relaxed)
		}
	}

	// Each push adds one whole record, so a poisoned lock holds a whole list.
	impl LogBackend for CaptureBackend {
		fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
			let captured = (record.level, record.message.to_string(), record.component.map(String::from));
			let mut records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
			records.push((captured, record.timestamp));
			Ok(())
		}

		fn accepts(&self, level: LogLevel) -> bool {
			level <= self.accepts_up_to
		}

		fn flush(&self) -> Result<(), LogError> {
			self.flushes.fetch_add(1, Ordering::Relaxed);
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::fixtures::CaptureBackend;
	use super::*;
	use crate::testing::TestResult;
	use crate::trace::{TraceCollector, TraceStateShared};
	use crate::urn::Urn;

	const TEST1: Urn<'static> = crate::urn!("test", "event:log/test1");
	const TEST2: Urn<'static> = crate::urn!("test", "event:log/test2");
	const NO_LOG: Urn<'static> = crate::urn!("test", "event:log/no-log");
	const SHOULD_LOG: Urn<'static> = crate::urn!("test", "event:log/should-log");
	const EMERGENCY: Urn<'static> = crate::urn!("test", "event:log/emergency");
	const ERROR: Urn<'static> = crate::urn!("test", "event:log/error");
	const WARNING: Urn<'static> = crate::urn!("test", "event:log/warning");
	const NOTICE: Urn<'static> = crate::urn!("test", "event:log/notice");
	const INFO: Urn<'static> = crate::urn!("test", "event:log/info");
	const DEBUG: Urn<'static> = crate::urn!("test", "event:log/debug");
	const TEST: Urn<'static> = crate::urn!("test", "event:log/test");

	/// A fresh trace that logs through `config`.
	fn logging_through(config: LoggerConfig) -> TraceCollector {
		let trace = TraceCollector::default().with_logger(config);
		trace.expect("a fresh trace owns its state alone")
	}

	// A more severe level orders before each less severe one, as RFC 5424
	// numbers the severities.
	crate::tb_cases! {
		fn a_more_severe_level_orders_first((more, less): (LogLevel, LogLevel)) {
			assert!(more < less);
		}
		cases {
			emergency_before_alert => (LogLevel::Emergency, LogLevel::Alert),
			alert_before_critical => (LogLevel::Alert, LogLevel::Critical),
			critical_before_error => (LogLevel::Critical, LogLevel::Error),
			error_before_warning => (LogLevel::Error, LogLevel::Warning),
			warning_before_notice => (LogLevel::Warning, LogLevel::Notice),
			notice_before_informational => (LogLevel::Notice, LogLevel::Informational),
			informational_before_debug => (LogLevel::Informational, LogLevel::Debug),
		}
	}

	// A level displays its RFC 5424 name in upper case.
	crate::tb_cases! {
		fn a_log_level_displays_its_name((level, name): (LogLevel, &str)) {
			assert_eq!(level.to_string(), name);
		}
		cases {
			emergency => (LogLevel::Emergency, "EMERGENCY"),
			error => (LogLevel::Error, "ERROR"),
			debug => (LogLevel::Debug, "DEBUG"),
		}
	}

	// A filter admits a record of its own level and of each more severe
	// level, and refuses each less severe one.
	crate::tb_cases! {
		fn a_global_filter_admits_its_level_and_each_more_severe((level, admitted): (LogLevel, bool)) {
			assert_eq!(LogFilter::new(LogLevel::Warning).should_log(level, None), admitted);
		}
		cases {
			emergency => (LogLevel::Emergency, true),
			error => (LogLevel::Error, true),
			warning => (LogLevel::Warning, true),
			notice => (LogLevel::Notice, false),
			informational => (LogLevel::Informational, false),
			debug => (LogLevel::Debug, false),
		}
	}

	// An override sets the level of its own component, and each other
	// component keeps the global level.
	crate::tb_cases! {
		fn a_component_override_sets_the_level_of_its_component(
			(level, component, admitted): (LogLevel, &str, bool)
		) {
			let filter = LogFilter::new(LogLevel::Warning).with_component("security", LogLevel::Debug);
			assert_eq!(filter.should_log(level, Some(component)), admitted);
		}
		cases {
			database_informational => (LogLevel::Informational, "database", false),
			database_error => (LogLevel::Error, "database", true),
			security_debug => (LogLevel::Debug, "security", true),
			security_informational => (LogLevel::Informational, "security", true),
		}
	}

	/// An event that names no level logs at the default level of the logger,
	/// and an event that names a level logs at that level.
	#[test]
	fn an_event_without_a_level_logs_at_the_default_level() -> TestResult {
		let backend = CaptureBackend::default();
		let config = LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug));
		let trace = logging_through(config.with_default_level(LogLevel::Informational));
		trace.event(TEST1)?.emit();
		trace.event(TEST2)?.with_log_level(LogLevel::Error).emit();

		let logged = [
			(LogLevel::Informational, TEST1.to_string(), None),
			(LogLevel::Error, TEST2.to_string(), None),
		];
		assert_eq!(backend.records(), logged);
		Ok(())
	}

	/// A logger with no default level logs the events that name a level alone.
	#[test]
	fn an_event_without_a_level_logs_nothing_without_a_default() -> TestResult {
		let backend = CaptureBackend::default();
		let trace = logging_through(LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug)));
		trace.event(NO_LOG)?.emit();
		trace.event(SHOULD_LOG)?.with_log_level(LogLevel::Warning).emit();
		assert_eq!(backend.records(), [(LogLevel::Warning, SHOULD_LOG.to_string(), None)]);
		Ok(())
	}

	/// A logger hands its backend the records at the level of its filter and
	/// at each more severe level.
	#[test]
	fn a_logger_drops_records_below_its_filter_level() -> TestResult {
		let backend = CaptureBackend::default();
		let trace = logging_through(LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Warning)));
		trace.event(EMERGENCY)?.with_log_level(LogLevel::Emergency).emit();
		trace.event(ERROR)?.with_log_level(LogLevel::Error).emit();
		trace.event(WARNING)?.with_log_level(LogLevel::Warning).emit();
		trace.event(NOTICE)?.with_log_level(LogLevel::Notice).emit();
		trace.event(INFO)?.with_log_level(LogLevel::Informational).emit();
		trace.event(DEBUG)?.with_log_level(LogLevel::Debug).emit();

		let logged = [
			(LogLevel::Emergency, EMERGENCY.to_string(), None),
			(LogLevel::Error, ERROR.to_string(), None),
			(LogLevel::Warning, WARNING.to_string(), None),
		];
		assert_eq!(backend.records(), logged);
		Ok(())
	}

	/// A multiplex backend hands each record to every backend it holds.
	#[test]
	fn a_multiplex_backend_hands_each_record_to_every_backend() -> TestResult {
		let (first, second) = (CaptureBackend::default(), CaptureBackend::default());
		let multiplex = MultiplexBackend::new(vec![Box::new(first.clone()), Box::new(second.clone())]);
		let trace = logging_through(LoggerConfig::new(multiplex, LogFilter::new(LogLevel::Debug)));
		trace.event(TEST)?.with_log_level(LogLevel::Informational).emit();

		let logged = || vec![(LogLevel::Informational, TEST.to_string(), None)];
		assert_eq!([first.records(), second.records()], [logged(), logged()]);
		Ok(())
	}

	/// A component override admits a debug record of its component, which the
	/// global level refuses.
	#[test]
	fn a_component_override_admits_a_debug_record_of_that_component() -> TestResult {
		let backend = CaptureBackend::default();
		let filter = LogFilter::new(LogLevel::Informational).with_component("security", LogLevel::Debug);
		let trace = logging_through(LoggerConfig::new(backend.clone(), filter));

		let security_event = trace.event(DEBUG)?.with_component("security");
		security_event.with_log_level(LogLevel::Debug).emit();

		let security = Some("security".to_string());
		assert_eq!(backend.records(), [(LogLevel::Debug, DEBUG.to_string(), security)]);
		Ok(())
	}

	/// The writer is a pipe whose reader closed, which refuses a write with
	/// `BrokenPipe`, as stdout does when the reader of its pipe exits.
	#[test]
	fn a_failed_stdout_write_returns_io_error() -> TestResult {
		let (reader, mut writer) = std::io::pipe()?;
		drop(reader);
		let record = LogRecord {
			level: LogLevel::Informational,
			timestamp: None,
			component: None,
			message: "closed",
			metadata: None,
		};

		let written = StdoutBackend::write_record(&mut writer, &record);
		assert_eq!(written, Err(LogError::IoError));
		Ok(())
	}

	/// A collector whose state another handle shares refuses a logger config,
	/// which only the sole owner of the state can set.
	#[test]
	fn a_shared_collector_refuses_a_logger_config() {
		let trace = TraceCollector::default();
		let _shared = trace.share();

		let config = LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Debug));
		assert!(matches!(trace.with_logger(config), Err(TraceStateShared { .. })));
	}

	/// The refusal of a shared collector holds the collector, which still
	/// records into the shared state.
	#[test]
	fn a_refused_logger_hands_the_collector_back() -> TestResult {
		let trace = TraceCollector::default();
		let shared = trace.share();
		let config = LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Debug));

		let refused = trace.with_logger(config).err().ok_or("a shared state refuses the config")?;
		refused.into_collector().event(TEST)?.emit();

		assert_eq!(shared.recorded(TEST), 1);
		Ok(())
	}

	/// The trace reads `accepts` of its backend, so a record that the filter
	/// admits and the backend refuses reaches no backend.
	#[test]
	fn a_record_that_its_backend_refuses_reaches_no_backend() -> TestResult {
		let backend = CaptureBackend::accepting(LogLevel::Warning);
		let trace = logging_through(LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug)));
		trace.event(ERROR)?.with_log_level(LogLevel::Error).emit();
		trace.event(DEBUG)?.with_log_level(LogLevel::Debug).emit();
		assert_eq!(backend.records(), [(LogLevel::Error, ERROR.to_string(), None)]);
		Ok(())
	}

	/// The backend of a trace flushes once, when the last handle that shares
	/// the trace drops.
	#[test]
	fn the_last_handle_of_a_trace_flushes_its_backend() {
		let backend = CaptureBackend::default();
		let trace = logging_through(LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug)));
		let shared = trace.share();

		drop(trace);
		let after_the_first = backend.flushes();
		drop(shared);

		assert_eq!([after_the_first, backend.flushes()], [0, 1]);
	}

	/// A backend whose flush fails, as a SIEM backend does when its endpoint
	/// is gone.
	///
	/// The house backends flush in process with no failure of their own, so a
	/// test of a failed flush holds this double.
	struct Unflushable;

	impl LogBackend for Unflushable {
		fn emit(&self, _record: &LogRecord) -> Result<(), LogError> {
			Ok(())
		}

		fn accepts(&self, _level: LogLevel) -> bool {
			true
		}

		fn flush(&self) -> Result<(), LogError> {
			Err(LogError::BackendUnavailable)
		}
	}

	// `flush_log` flushes the backend of the trace, and returns the result of
	// the flush to its caller.
	crate::tb_cases! {
		fn flush_log_returns_the_result_of_the_backend_flush((config, expected): (LoggerConfig, Result<(), LogError>)) {
			let trace = logging_through(config);
			let flushed = trace.flush_log();
			assert_eq!(flushed, expected);
		}
		cases {
			/// A backend whose flush fails hands its error to the caller.
			a_failed_flush => (
				LoggerConfig::new(Unflushable, LogFilter::new(LogLevel::Debug)),
				Err(LogError::BackendUnavailable),
			),
			/// The stdout backend keeps the default flush, which flushes
			/// nothing and succeeds.
			the_default_flush => (LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Debug)), Ok(())),
		}
	}

	// A fresh collector records each event its caller emits, whichever
	// constructor builds it.
	crate::tb_cases! {
		fn a_fresh_collector_records_an_event(fresh: fn() -> TraceCollector) -> TestResult {
			let trace = fresh();
			trace.event(TEST)?.emit();
			assert_eq!(trace.recorded(TEST), 1);
			Ok(())
		}
		cases {
			default => TraceCollector::default,
			new => TraceCollector::new,
		}
	}
}
