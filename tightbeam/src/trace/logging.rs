//! Logging subsystem with RFC 5424 severity levels
//!
//! Provides trait-based logging backends with runtime injection for flexible
//! output targets (stdout, file, SIEM, etc.) while maintaining no_std compatibility
//! for core traits.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, collections::BTreeMap as HashMap, vec::Vec};
#[cfg(feature = "std")]
use std::{borrow::Cow, collections::HashMap};

use core::fmt;

/// RFC 5424 Severity Levels
///
/// Maps to syslog severity levels where lower numeric values indicate
/// higher severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LogLevel {
	/// System is unusable
	Emergency = 0,
	/// Action must be taken immediately
	Alert = 1,
	/// Critical conditions
	Critical = 2,
	/// Error conditions
	Error = 3,
	/// Warning conditions
	Warning = 4,
	/// Normal but significant condition
	Notice = 5,
	/// Informational messages
	Info = 6,
	/// Debug-level messages
	Debug = 7,
}

impl fmt::Display for LogLevel {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			LogLevel::Emergency => write!(f, "EMERGENCY"),
			LogLevel::Alert => write!(f, "ALERT"),
			LogLevel::Critical => write!(f, "CRITICAL"),
			LogLevel::Error => write!(f, "ERROR"),
			LogLevel::Warning => write!(f, "WARNING"),
			LogLevel::Notice => write!(f, "NOTICE"),
			LogLevel::Info => write!(f, "INFO"),
			LogLevel::Debug => write!(f, "DEBUG"),
		}
	}
}

/// Log record containing all information about a log event
#[derive(Debug, Clone)]
pub struct LogRecord<'a> {
	/// Severity level
	pub level: LogLevel,
	/// Unix timestamp in milliseconds (optional)
	pub timestamp: Option<u64>,
	/// Component or module name (optional)
	pub component: Option<&'a str>,
	/// Log message
	pub message: &'a str,
	/// Key-value metadata pairs (optional)
	pub metadata: Option<&'a [(&'a str, &'a str)]>,
}

/// Errors that can occur during logging operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogError {
	/// I/O error occurred
	IoError,
	/// Log buffer is full
	BufferFull,
	/// Backend is unavailable
	BackendUnavailable,
}

impl fmt::Display for LogError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			LogError::IoError => write!(f, "I/O error"),
			LogError::BufferFull => write!(f, "buffer full"),
			LogError::BackendUnavailable => write!(f, "backend unavailable"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for LogError {}

/// Trait for logging backends
///
/// Implementations can output logs to various targets (stdout, files, SIEM systems, etc.)
pub trait LogBackend: Send + Sync {
	/// Emit a log record
	///
	/// # Errors
	///
	/// Returns `LogError` if the backend cannot emit the log record
	fn emit(&self, record: &LogRecord) -> Result<(), LogError>;

	/// Check if this backend accepts logs at the given level
	///
	/// This allows backends to filter based on their own criteria
	fn accepts(&self, level: LogLevel) -> bool;

	/// Flush any buffered logs (optional, for async backends)
	///
	/// # Errors
	///
	/// Returns `LogError` if flushing fails
	fn flush(&self) -> Result<(), LogError> {
		Ok(())
	}
}

/// Filter for controlling which log records are emitted
///
/// Supports a global minimum level plus per-component overrides
#[derive(Debug, Clone)]
pub struct LogFilter {
	/// Minimum log level (global default)
	min_level: LogLevel,
	/// Per-component log level overrides
	component_overrides: HashMap<Cow<'static, str>, LogLevel>,
}

impl Default for LogFilter {
	fn default() -> Self {
		Self { min_level: LogLevel::Info, component_overrides: HashMap::new() }
	}
}

impl LogFilter {
	/// Create a new filter with the specified minimum level
	pub fn new(min_level: LogLevel) -> Self {
		Self { min_level, component_overrides: HashMap::new() }
	}

	/// Add a component-specific log level override
	///
	/// This allows fine-grained control, e.g., enabling Debug logs for
	/// "security" while keeping Info for everything else.
	pub fn with_component(mut self, component: impl Into<Cow<'static, str>>, level: LogLevel) -> Self {
		self.component_overrides.insert(component.into(), level);
		self
	}

	/// Check if a log record should be emitted based on level and component
	pub fn should_log(&self, level: LogLevel, component: Option<&str>) -> bool {
		let threshold = if let Some(comp) = component {
			self.component_overrides.get(comp).copied().unwrap_or(self.min_level)
		} else {
			self.min_level
		};

		level <= threshold
	}
}

/// Configuration for logging subsystem
///
/// Encapsulates backend, filter, and optional default log level
pub struct LoggerConfig {
	/// Log backend for output
	pub backend: Box<dyn LogBackend>,
	/// Filter for controlling which logs are emitted
	pub filter: LogFilter,
	/// Default log level to apply to events without explicit level
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
	/// Create logger config with required fields
	pub fn new(backend: Box<dyn LogBackend>, filter: LogFilter) -> Self {
		Self { backend, filter, default_level: None }
	}

	/// Set default log level for all events
	pub fn with_default_level(mut self, level: LogLevel) -> Self {
		self.default_level = Some(level);
		self
	}
}

/// Standard output logging backend
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy)]
pub struct StdoutBackend;

#[cfg(feature = "std")]
impl Default for StdoutBackend {
	fn default() -> Self {
		Self
	}
}

#[cfg(feature = "std")]
impl LogBackend for StdoutBackend {
	fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
		let component = record.component.unwrap_or("app");
		let timestamp = record.timestamp.map(|ts| format!("[{}] ", ts)).unwrap_or_default();

		println!("{}[{}] {}: {}", timestamp, record.level, component, record.message);

		if let Some(metadata) = record.metadata {
			for (key, value) in metadata {
				println!("  {}: {}", key, value);
			}
		}

		Ok(())
	}

	fn accepts(&self, _level: LogLevel) -> bool {
		true
	}
}

/// Multiplex backend that fans out to multiple backends
///
/// Emits log records to all configured backends, allowing simultaneous
/// logging to multiple destinations (e.g., stdout + file + SIEM)
pub struct MultiplexBackend {
	backends: Vec<Box<dyn LogBackend>>,
}

impl MultiplexBackend {
	/// Create a new multiplex backend with the given backends
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
	use crate::trace::TraceCollector;

	#[test]
	fn test_log_level_ordering() {
		assert!(LogLevel::Emergency < LogLevel::Alert);
		assert!(LogLevel::Alert < LogLevel::Critical);
		assert!(LogLevel::Critical < LogLevel::Error);
		assert!(LogLevel::Error < LogLevel::Warning);
		assert!(LogLevel::Warning < LogLevel::Notice);
		assert!(LogLevel::Notice < LogLevel::Info);
		assert!(LogLevel::Info < LogLevel::Debug);
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
		assert!(!filter.should_log(LogLevel::Info, None));
		assert!(!filter.should_log(LogLevel::Debug, None));
	}

	#[test]
	fn test_log_filter_component_override() {
		let filter = LogFilter::new(LogLevel::Warning).with_component("security", LogLevel::Debug);
		assert!(!filter.should_log(LogLevel::Info, Some("database")));
		assert!(filter.should_log(LogLevel::Error, Some("database")));
		assert!(filter.should_log(LogLevel::Debug, Some("security")));
		assert!(filter.should_log(LogLevel::Info, Some("security")));
	}

	// Mock backend for testing - uses Arc internally to share captured records
	#[derive(Debug, Clone)]
	struct MockBackend {
		captured: Arc<std::sync::Mutex<Vec<(LogLevel, String)>>>,
	}

	impl MockBackend {
		fn with_captured(captured: Arc<std::sync::Mutex<Vec<(LogLevel, String)>>>) -> Self {
			Self { captured }
		}
	}

	impl LogBackend for MockBackend {
		fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
			self.captured
				.lock()
				.map_err(|_| LogError::BackendUnavailable)?
				.push((record.level, record.message.to_string()));
			Ok(())
		}

		fn accepts(&self, _level: LogLevel) -> bool {
			true
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_logger_config_default_level() -> Result<(), crate::TightBeamError> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = MockBackend::with_captured(Arc::clone(&captured));
		let config =
			LoggerConfig::new(Box::new(backend), LogFilter::new(LogLevel::Debug)).with_default_level(LogLevel::Info);
		let trace = TraceCollector::default().with_logger(config);

		trace.event("test1")?.emit();
		trace.event("test2")?.with_log_level(LogLevel::Error).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records.len(), 2);
		assert_eq!(records[0].0, LogLevel::Info);
		assert_eq!(records[0].1, "test1");
		assert_eq!(records[1].0, LogLevel::Error);
		assert_eq!(records[1].1, "test2");

		Ok(())
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_logger_config_no_default_level() -> Result<(), crate::TightBeamError> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = MockBackend::with_captured(Arc::clone(&captured));
		let config = LoggerConfig::new(Box::new(backend), LogFilter::new(LogLevel::Debug));
		let trace = TraceCollector::default().with_logger(config);

		trace.event("no_log")?.emit();
		trace.event("should_log")?.with_log_level(LogLevel::Warning).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records.len(), 1);
		assert_eq!(records[0].0, LogLevel::Warning);
		assert_eq!(records[0].1, "should_log");

		Ok(())
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_log_filter_with_logger() -> Result<(), crate::TightBeamError> {
		let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
		let backend = MockBackend::with_captured(Arc::clone(&captured));
		let config = LoggerConfig::new(Box::new(backend), LogFilter::new(LogLevel::Warning));
		let trace = TraceCollector::default().with_logger(config);

		trace.event("emergency")?.with_log_level(LogLevel::Emergency).emit();
		trace.event("error")?.with_log_level(LogLevel::Error).emit();
		trace.event("warning")?.with_log_level(LogLevel::Warning).emit();
		trace.event("notice")?.with_log_level(LogLevel::Notice).emit();
		trace.event("info")?.with_log_level(LogLevel::Info).emit();
		trace.event("debug")?.with_log_level(LogLevel::Debug).emit();

		let records = captured.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records.len(), 3);
		assert_eq!(records[0].1, "emergency");
		assert_eq!(records[1].1, "error");
		assert_eq!(records[2].1, "warning");

		Ok(())
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_multiplex_backend() -> Result<(), crate::TightBeamError> {
		let captured1 = Arc::new(std::sync::Mutex::new(Vec::new()));
		let captured2 = Arc::new(std::sync::Mutex::new(Vec::new()));

		let backend1 = MockBackend::with_captured(Arc::clone(&captured1));
		let backend2 = MockBackend::with_captured(Arc::clone(&captured2));

		let multiplex = MultiplexBackend::new(vec![Box::new(backend1), Box::new(backend2)]);

		let config = LoggerConfig::new(Box::new(multiplex), LogFilter::new(LogLevel::Debug));
		let trace = TraceCollector::default().with_logger(config);

		trace.event("test")?.with_log_level(LogLevel::Info).emit();

		let records1 = captured1.lock().ok().map(|r| r.clone()).unwrap_or_default();
		let records2 = captured2.lock().ok().map(|r| r.clone()).unwrap_or_default();
		assert_eq!(records1.len(), 1);
		assert_eq!(records2.len(), 1);
		assert_eq!(records1[0].1, "test");
		assert_eq!(records2[0].1, "test");

		Ok(())
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_trace_collector_default() -> Result<(), crate::TightBeamError> {
		let trace = TraceCollector::default();
		trace.event("test")?.emit();
		Ok(())
	}

	#[cfg(feature = "std")]
	#[test]
	fn test_trace_collector_new() -> Result<(), crate::TightBeamError> {
		let trace = TraceCollector::new();
		trace.event("test")?.emit();
		Ok(())
	}
}
