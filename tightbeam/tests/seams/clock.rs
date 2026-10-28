//! An outside crate writes its own [`Clock`], and a trace that adopts it
//! through [`TraceCollector::with_clock`] stamps each event on its readings.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;

use tightbeam::instrumentation::events::TRACE_CLOCK_ORIGIN;
use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::utils::time::{Clock, MonotonicInstant, UnixMillis};

/// The event that each test stamps.
const SEND: Urn<'static> = tightbeam::urn!("outside", "event:clock/send");

/// The Unix time of the origin of a [`SteppedClock`], in milliseconds.
const ORIGIN_MS: u64 = 1_700_000_000_000;

/// A clock that its test steps by hand. It reads the span that it was
/// stepped through, from a fixed Unix origin and from the monotonic reading
/// it took at its construction, and a sleep steps it.
#[derive(Debug)]
struct SteppedClock {
	/// The monotonic reading of the origin.
	monotonic_start: MonotonicInstant,
	/// The span the clock was stepped through, in nanoseconds.
	elapsed_ns: AtomicU64,
}

impl SteppedClock {
	/// A clock at its origin.
	fn new() -> Self {
		let monotonic_start = MonotonicInstant::from_std(std::time::Instant::now());
		Self { monotonic_start, elapsed_ns: AtomicU64::new(0) }
	}

	/// Steps the clock forward by `span`.
	fn step(&self, span: Duration) {
		let span_ns = u64::try_from(span.as_nanos()).unwrap_or(u64::MAX);
		self.elapsed_ns.fetch_add(span_ns, Ordering::SeqCst);
	}

	/// The span the clock was stepped through.
	fn elapsed(&self) -> Duration {
		Duration::from_nanos(self.elapsed_ns.load(Ordering::SeqCst))
	}
}

impl Clock for SteppedClock {
	fn unix(&self) -> UnixMillis {
		UnixMillis::new(ORIGIN_MS).saturating_add(self.elapsed())
	}

	fn monotonic(&self) -> MonotonicInstant {
		let start = self.monotonic_start;
		start.checked_add(self.elapsed()).unwrap_or(start)
	}

	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		self.step(span);
		Box::pin(core::future::ready(()))
	}
}

/// A trace on a fresh [`SteppedClock`], beside the clock.
fn stepped_trace() -> (TraceCollector, Arc<SteppedClock>) {
	let clock = Arc::new(SteppedClock::new());
	let trace = TraceCollector::new().with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
	(trace, clock)
}

#[test]
fn a_trace_on_an_outside_clock_records_its_origin() -> Result<(), Box<dyn std::error::Error>> {
	let (trace, _clock) = stepped_trace();

	trace.emit_event(SEND)?;

	let recorded = trace.drain_events();
	let origin = recorded.iter().find(|event| event.urn == TRACE_CLOCK_ORIGIN);
	let label = origin.and_then(|event| event.label.as_deref());
	assert_eq!(label, Some("1700000000000000000"));
	Ok(())
}

#[test]
fn a_trace_on_an_outside_clock_stamps_the_span_it_stepped() -> Result<(), Box<dyn std::error::Error>> {
	let (trace, clock) = stepped_trace();
	clock.step(Duration::from_millis(7));

	trace.emit_event(SEND)?;

	let recorded = trace.drain_events();
	let sent = recorded.iter().find(|event| event.urn == SEND);
	assert_eq!(sent.and_then(|event| event.timestamp_ns), Some(7_000_000));
	Ok(())
}
