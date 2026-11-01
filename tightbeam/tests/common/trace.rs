//! The trace helpers that the instrumented suites share.
//!
//! [`instrumented_trace`] builds a trace under one instrumentation config, and
//! the readers drain the records of one event from a trace.

use tightbeam::instrumentation::{TbEvent, TbInstrumentationConfig};
use tightbeam::trace::{TraceCollector, TraceConfig};
use tightbeam::urn::Urn;

/// A trace under `config`, whose default sink keeps at most
/// `config.max_events` events.
pub fn instrumented_trace(config: TbInstrumentationConfig) -> TraceCollector {
	TraceCollector::from(TraceConfig::with_instrumentation(config))
}

/// Drains `trace`, and returns its records of `event` in the order the trace
/// filed them.
pub fn records_of(trace: &TraceCollector, event: Urn<'static>) -> impl Iterator<Item = TbEvent> {
	let recorded = trace.drain_events().into_iter();
	recorded.filter(move |record| record.urn == event)
}

/// Drains `trace`, and returns the label of each record of `event`, in the
/// order the trace filed them.
pub fn recorded_labels(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<String>> {
	let records = records_of(trace, event);
	records.map(|record| record.label.as_deref().map(String::from)).collect()
}
