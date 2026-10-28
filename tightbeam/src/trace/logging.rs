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
	fn accepts(&self, level: LogLevel) -> bool;

	/// Flush the buffered records of an async backend. The default flushes
	/// nothing.
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
	/// A request with no level takes the default level, and
	/// [`LogFilter::should_log`] decides the rest.
	pub(crate) fn admit(&self, requested: Option<LogLevel>, component: Option<&str>) -> Option<LogLevel> {
		let level = requested.or(self.default_level)?;
		let admitted = self.filter.should_log(level, component);
		admitted.then_some(level)
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

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
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

	#[test]
	fn test_log_level_ordering() {
		assert!(LogLevel::Emergency < LogLevel::Alert);
		assert!(LogLevel::Alert < LogLevel::Critical);
		assert!(LogLevel::Critical < LogLevel::Error);
		assert!(LogLevel::Error < LogLevel::Warning);
		assert!(LogLevel::Warning < LogLevel::Notice);
		assert!(LogLevel::Notice < LogLevel::Informational);
		assert!(LogLevel::Informational < LogLevel::Debug);
	}

	#[test]
	fn test_log_level_display() {
		assert_eq!(format!("{}", LogLevel::Emergency), "EMERGENCY");
		assert_eq!(format!("{}", LogLevel::Error), "ERROR");
		assert_eq!(format!("{}", LogLevel::Debug), "DEBUG");
	}

	#[test]
	fn test_log_filter_global_level() {
		let filter = LogFilter::new(LogLevel::Warning);
		assert!(filter.should_log(LogLevel::Emergency, None));
		assert!(filter.should_log(LogLevel::Error, None));
		assert!(filter.should_log(LogLevel::Warning, None));
		assert!(!filter.should_log(LogLevel::Notice, None));
		assert!(!filter.should_log(LogLevel::Informational, None));
		assert!(!filter.should_log(LogLevel::Debug, None));
	}

	#[test]
	fn test_log_filter_component_override() {
		let filter = LogFilter::new(LogLevel::Warning).with_component("security", LogLevel::Debug);
		assert!(!filter.should_log(LogLevel::Informational, Some("database")));
		assert!(filter.should_log(LogLevel::Error, Some("database")));
		assert!(filter.should_log(LogLevel::Debug, Some("security")));
		assert!(filter.should_log(LogLevel::Informational, Some("security")));
	}

	// A spy backend: it records the emitted output in a shared `Vec` for the
	// tests to assert on.
	#[derive(Debug, Clone)]
	struct CaptureBackend {
		captured: Arc<std::sync::Mutex<Vec<Captured>>>,
	}

	/// The level, the message, and the component of a captured record.
	type Captured = (LogLevel, String, Option<String>);

	impl CaptureBackend {
		fn with_captured(captured: Arc<std::sync::Mutex<Vec<Captured>>>) -> Self {
			Self { captured }
		}
	}

	impl LogBackend for CaptureBackend {
		fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
			let component = record.component.map(String::from);
			let entry = (record.level, record.message.to_string(), component);
			self.captured.lock().map_err(|_| LogError::BackendUnavailable)?.push(entry);
			Ok(())
		}

		fn accepts(&self, _level: LogLevel) -> bool {
			true
		}
	}

	#[test]
	fn test_logger_config_default_level() -> Result<(), Box<dyn core::error::Error>> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = {
			let captured = Arc::clone(&captured);
			CaptureBackend::with_captured(captured)
		};
		let config =
			LoggerConfig::new(backend, LogFilter::new(LogLevel::Debug)).with_default_level(LogLevel::Informational);
		let trace = TraceCollector::default().with_logger(config)?;

		trace.event(TEST1)?.emit();
		trace.event(TEST2)?.with_log_level(LogLevel::Error).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records.len(), 2);
		assert_eq!(records[0].0, LogLevel::Informational);
		assert_eq!(records[0].1, TEST1.to_string());
		assert_eq!(records[1].0, LogLevel::Error);
		assert_eq!(records[1].1, TEST2.to_string());

		Ok(())
	}

	#[test]
	fn test_logger_config_no_default_level() -> Result<(), Box<dyn core::error::Error>> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = {
			let captured = Arc::clone(&captured);
			CaptureBackend::with_captured(captured)
		};

		let config = LoggerConfig::new(backend, LogFilter::new(LogLevel::Debug));
		let trace = TraceCollector::default().with_logger(config)?;

		trace.event(NO_LOG)?.emit();
		trace.event(SHOULD_LOG)?.with_log_level(LogLevel::Warning).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records.len(), 1);
		assert_eq!(records[0].0, LogLevel::Warning);
		assert_eq!(records[0].1, SHOULD_LOG.to_string());

		Ok(())
	}

	#[test]
	fn test_log_filter_with_logger() -> Result<(), Box<dyn core::error::Error>> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = {
			let captured = Arc::clone(&captured);
			CaptureBackend::with_captured(captured)
		};

		let config = LoggerConfig::new(backend, LogFilter::new(LogLevel::Warning));
		let trace = TraceCollector::default().with_logger(config)?;
		trace.event(EMERGENCY)?.with_log_level(LogLevel::Emergency).emit();
		trace.event(ERROR)?.with_log_level(LogLevel::Error).emit();
		trace.event(WARNING)?.with_log_level(LogLevel::Warning).emit();
		trace.event(NOTICE)?.with_log_level(LogLevel::Notice).emit();
		trace.event(INFO)?.with_log_level(LogLevel::Informational).emit();
		trace.event(DEBUG)?.with_log_level(LogLevel::Debug).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records.len(), 3);
		assert_eq!(records[0].1, EMERGENCY.to_string());
		assert_eq!(records[1].1, ERROR.to_string());
		assert_eq!(records[2].1, WARNING.to_string());

		Ok(())
	}

	#[test]
	fn test_multiplex_backend() -> Result<(), Box<dyn core::error::Error>> {
		let captured1 = Arc::new(std::sync::Mutex::new(Vec::new()));
		let captured2 = Arc::new(std::sync::Mutex::new(Vec::new()));

		let backend1 = {
			let captured = Arc::clone(&captured1);
			CaptureBackend::with_captured(captured)
		};
		let backend2 = {
			let captured = Arc::clone(&captured2);
			CaptureBackend::with_captured(captured)
		};

		let multiplex = MultiplexBackend::new(vec![Box::new(backend1), Box::new(backend2)]);
		let config = LoggerConfig::new(multiplex, LogFilter::new(LogLevel::Debug));
		let trace = TraceCollector::default().with_logger(config)?;

		trace.event(TEST)?.with_log_level(LogLevel::Informational).emit();

		let records1 = captured1.lock().ok().map(|r| r.clone()).unwrap_or_default();
		let records2 = captured2.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records1.len(), 1);
		assert_eq!(records2.len(), 1);
		assert_eq!(records1[0].1, TEST.to_string());
		assert_eq!(records2[0].1, TEST.to_string());

		Ok(())
	}

	#[test]
	fn a_component_override_admits_a_debug_record_of_that_component() -> Result<(), Box<dyn core::error::Error>> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = CaptureBackend::with_captured(Arc::clone(&captured));
		let filter = LogFilter::new(LogLevel::Informational).with_component("security", LogLevel::Debug);
		let trace = TraceCollector::default().with_logger(LoggerConfig::new(backend, filter))?;

		let security_event = trace.event(DEBUG)?.with_component("security");
		security_event.with_log_level(LogLevel::Debug).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		let security = Some("security".to_string());
		assert_eq!(records, [(LogLevel::Debug, DEBUG.to_string(), security)]);
		Ok(())
	}

	/// The writer is a pipe whose reader closed, which refuses a write with
	/// `BrokenPipe`, as stdout does when the reader of its pipe exits.
	#[test]
	fn a_failed_stdout_write_returns_io_error() -> Result<(), Box<dyn core::error::Error>> {
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
	fn a_shared_collector_refuses_a_logger_config() -> Result<(), Box<dyn core::error::Error>> {
		let trace = TraceCollector::default();
		let _shared = trace.share();

		let config = LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Debug));
		assert!(matches!(trace.with_logger(config), Err(TraceStateShared { .. })));
		Ok(())
	}

	/// The refusal of a shared collector holds the collector, which still
	/// records into the shared state.
	#[test]
	fn a_refused_logger_hands_the_collector_back() -> Result<(), Box<dyn core::error::Error>> {
		let trace = TraceCollector::default();
		let shared = trace.share();
		let config = LoggerConfig::new(StdoutBackend, LogFilter::new(LogLevel::Debug));

		let refused = trace.with_logger(config).err().ok_or("a shared state refuses the config")?;
		refused.into_collector().event(TEST)?.emit();

		assert_eq!(shared.recorded(TEST), 1);
		Ok(())
	}

	#[test]
	fn test_trace_collector_default() -> Result<(), crate::TightBeamError> {
		let trace = TraceCollector::default();
		trace.event(TEST)?.emit();
		Ok(())
	}

	#[test]
	fn test_trace_collector_new() -> Result<(), crate::TightBeamError> {
		let trace = TraceCollector::new();
		trace.event(TEST)?.emit();
		Ok(())
	}
}
