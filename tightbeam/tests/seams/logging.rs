//! An outside crate writes its own [`LogBackend`], and a trace hands that
//! backend each record that its filter admits and the backend accepts. The
//! trace flushes the backend on [`TraceCollector::flush_log`] and when its last
//! handle drops.
//!
//! The backend reaches the trace through [`TraceCollector::with_logger`] on a
//! built collector, and through [`TraceConfig::with_logger`] on the
//! configuration of a new one.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tightbeam::trace::{
	LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig, TraceCollector, TraceConfig,
};
use tightbeam::urn::Urn;

/// The event of a record that the filter admits.
const SENT: Urn<'static> = tightbeam::urn!("outside", "event:logging/sent");
/// The event of a record below the level of the filter.
const SKIPPED: Urn<'static> = tightbeam::urn!("outside", "event:logging/skipped");

/// The level and the message of each record that a [`Keeping`] backend
/// received, in order.
type Kept = Arc<Mutex<Vec<(LogLevel, String)>>>;

/// A backend that keeps the level and the message of each record it
/// receives, and accepts every level.
struct Keeping(Kept);

impl LogBackend for Keeping {
	fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
		let mut kept = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		kept.push((record.level, record.message.to_string()));
		Ok(())
	}

	fn accepts(&self, _level: LogLevel) -> bool {
		true
	}
}

/// A logger config over a [`Keeping`] backend that writes into `kept`, whose
/// filter admits `Warning` and the levels above it.
fn keeping_config(kept: &Kept) -> LoggerConfig {
	LoggerConfig::new(Keeping(Arc::clone(kept)), LogFilter::new(LogLevel::Warning))
}

/// The records that `trace` handed its backend for one event at `Error` and
/// one at `Debug`.
fn records_of(trace: &TraceCollector, kept: &Kept) -> Vec<(LogLevel, String)> {
	let sent = trace.event(SENT).expect("the trace injects no fault");
	sent.with_log_level(LogLevel::Error).emit();
	let skipped = trace.event(SKIPPED).expect("the trace injects no fault");
	skipped.with_log_level(LogLevel::Debug).emit();

	let kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
	kept.clone()
}

#[test]
fn an_outside_backend_receives_each_record_its_filter_admits() -> Result<(), Box<dyn std::error::Error>> {
	let kept = Kept::default();
	let trace = TraceCollector::new().with_logger(keeping_config(&kept))?;

	let records = records_of(&trace, &kept);

	assert_eq!(records, [(LogLevel::Error, SENT.to_string())]);
	Ok(())
}

#[test]
fn a_trace_config_hands_its_outside_backend_to_the_collector() {
	let kept = Kept::default();
	let trace = TraceCollector::from(TraceConfig::default().with_logger(keeping_config(&kept)));

	let records = records_of(&trace, &kept);

	assert_eq!(records, [(LogLevel::Error, SENT.to_string())]);
}

/// A backend that accepts the records of `Error` and each more severe level,
/// keeps the message of each record it receives, and counts its flushes.
#[derive(Clone, Default)]
struct Selective {
	messages: Arc<Mutex<Vec<String>>>,
	flushes: Arc<AtomicUsize>,
}

impl Selective {
	/// The messages of the records this backend received, in order.
	fn messages(&self) -> Vec<String> {
		let messages = self.messages.lock().unwrap_or_else(PoisonError::into_inner);
		messages.clone()
	}

	/// The count of the flushes this backend ran.
	fn flushes(&self) -> usize {
		self.flushes.load(Ordering::Relaxed)
	}
}

impl LogBackend for Selective {
	fn emit(&self, record: &LogRecord) -> Result<(), LogError> {
		let mut messages = self.messages.lock().unwrap_or_else(PoisonError::into_inner);
		messages.push(record.message.to_string());
		Ok(())
	}

	fn accepts(&self, level: LogLevel) -> bool {
		level <= LogLevel::Error
	}

	fn flush(&self) -> Result<(), LogError> {
		self.flushes.fetch_add(1, Ordering::Relaxed);
		Ok(())
	}
}

/// The trace reads `accepts` of an outside backend, so a record that the
/// filter admits and the backend refuses reaches no backend.
#[test]
fn an_outside_backend_receives_each_record_it_accepts() -> Result<(), Box<dyn std::error::Error>> {
	let backend = Selective::default();
	let config = LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug));
	let trace = TraceCollector::new().with_logger(config)?;

	trace.event(SENT)?.with_log_level(LogLevel::Error).emit();
	trace.event(SKIPPED)?.with_log_level(LogLevel::Warning).emit();

	assert_eq!(backend.messages(), [SENT.to_string()]);
	Ok(())
}

/// `flush_log` flushes an outside backend while the trace is live.
#[test]
fn flush_log_flushes_an_outside_backend() -> Result<(), Box<dyn std::error::Error>> {
	let backend = Selective::default();
	let config = LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug));
	let trace = TraceCollector::new().with_logger(config)?;

	trace.flush_log()?;

	assert_eq!(backend.flushes(), 1);
	Ok(())
}

/// The last handle of a trace flushes an outside backend when it drops.
#[test]
fn the_last_handle_of_a_trace_flushes_its_outside_backend() -> Result<(), Box<dyn std::error::Error>> {
	let backend = Selective::default();
	let config = LoggerConfig::new(backend.clone(), LogFilter::new(LogLevel::Debug));
	let trace = TraceCollector::new().with_logger(config)?;

	drop(trace);

	assert_eq!(backend.flushes(), 1);
	Ok(())
}
