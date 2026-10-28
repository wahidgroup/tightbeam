//! An outside crate writes its own [`LogBackend`], and a trace hands each
//! record that its filter admits to that backend.
//!
//! The backend reaches the trace through [`TraceCollector::with_logger`] on a
//! built collector, and through [`TraceConfig::with_logger`] on the
//! configuration of a new one.

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
