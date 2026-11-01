//! The trace helpers of the colony suite.
//!
//! The constructors build a trace that keeps the payload digest of each event
//! or that bounds its store. [`payload_digests`] reads those digests back, and
//! [`signer_digest`] and [`session_digest`] state the digest that a colony
//! record carries. [`TraceWaiter`] wakes a test on the events of a trace and
//! of each trace that splits from it.

use std::sync::Arc;

use tokio::sync::watch;

use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::crypto::x509::utils::Fingerprint;
use tightbeam::crypto::x509::{CanonicalKey, Certificate};
use tightbeam::instrumentation::{BoundedMemorySink, EventSink, TbEvent, TbInstrumentationConfig};
use tightbeam::trace::{TraceCollector, TraceConfig};
use tightbeam::urn::Urn;

use crate::common::poll::HANG_GUARD;
use crate::common::trace::{instrumented_trace, records_of};

/// A trace that keeps the digest of each event's payload.
pub fn payload_trace() -> TraceCollector {
	let config = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
	instrumented_trace(config)
}

/// A trace whose sink keeps at most `max_events` events, and latches its
/// overflow past them.
pub fn bounded_trace(max_events: u32) -> TraceCollector {
	let config = TbInstrumentationConfig { max_events, ..TbInstrumentationConfig::default() };
	instrumented_trace(config)
}

/// Drains `trace`, and returns the payload digest of each record of `event`,
/// in the order the trace filed them.
pub fn payload_digests(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<[u8; 32]>> {
	let records = records_of(trace, event);
	records.map(|record| record.payload_hash).collect()
}

/// The payload digest of a record that names the signer of `certificate`:
/// the digest of its fingerprint under the colony digest.
pub fn signer_digest(certificate: &Certificate) -> [u8; 32] {
	let fingerprint = Fingerprint::<Sha3_256>::from_certificate(certificate);
	let fingerprint = fingerprint.expect("a fixture certificate encodes");
	Sha3_256::digest(fingerprint.as_slice()).into()
}

/// The payload digest of a record that names the peer of a session by its
/// `certificate`: the SHA3-256 digest of the canonical DER of its key.
pub fn session_digest(certificate: &Certificate) -> [u8; 32] {
	let spki = &certificate.tbs_certificate.subject_public_key_info;
	let key = CanonicalKey::of(spki).expect("a fixture certificate holds a key of a house curve");
	Sha3_256::digest(key.as_der()).into()
}

/// An [`EventSink`] that keeps the events of its trace, and counts each event
/// for the test that waits on it.
///
/// An outside crate writes it on the public sink seam, which the colony suites
/// prove. A trace that splits from its trace gets a sibling, and a sibling
/// keeps its events in a bounded store of its own, so a drain reads one trace
/// alone. Every sibling counts into one shared record, which wakes each wait.
#[derive(Clone)]
pub struct TraceWaiter {
	/// The bound of the store of each sibling.
	max_events: u32,
	/// The events of this trace, which a drain of the trace reads.
	kept: Arc<BoundedMemorySink>,
	/// The URN of each event that any sibling received, in arrival order.
	seen: watch::Sender<Vec<Urn<'static>>>,
}

impl TraceWaiter {
	/// A trace whose store keeps at most the default count of events of an
	/// instrumentation config, beside the waiter of its sink.
	pub fn trace() -> (TraceCollector, Self) {
		let max_events = TbInstrumentationConfig::default().max_events;
		let waiter = Self::sharing(max_events, watch::Sender::default());
		let config = TraceConfig::default().with_sink(waiter.clone());
		(TraceCollector::from(config), waiter)
	}

	/// The count of the events whose URN is `event`, on this trace and on each
	/// trace that split from it.
	///
	/// A house event carries its own URN to the sink. An assertion that
	/// [`TraceCollector::event`] records carries `ASSERT_LABEL` in its place.
	pub fn count(&self, event: Urn<'static>) -> usize {
		Self::counted(&self.seen.borrow(), &event)
	}

	/// Waits until `count` events carry the URN `event`, and answers whether
	/// they arrived within [`HANG_GUARD`].
	pub async fn until(&self, event: Urn<'static>, count: usize) -> bool {
		let mut seen = self.seen.subscribe();
		let arrived = seen.wait_for(|seen| Self::counted(seen, &event) >= count);
		let waited = tokio::time::timeout(HANG_GUARD, arrived).await;
		matches!(waited, Ok(Ok(_)))
	}

	/// A waiter with an empty store of `max_events` events that counts into
	/// `seen`.
	fn sharing(max_events: u32, seen: watch::Sender<Vec<Urn<'static>>>) -> Self {
		let kept = Arc::new(BoundedMemorySink::new(max_events));
		Self { max_events, kept, seen }
	}

	/// The count of the URNs in `seen` that equal `event`.
	fn counted(seen: &[Urn<'static>], event: &Urn<'static>) -> usize {
		seen.iter().filter(|urn| *urn == event).count()
	}
}

// The sink keeps the default `retains`, so the record counts each event, the
// ones past the bound of the store included.
impl EventSink for TraceWaiter {
	// The store keeps the event before the record wakes a wait, so a wait that
	// drains the trace finds the event.
	fn emit(&self, event: TbEvent) {
		let urn = event.urn.clone();
		self.kept.emit(event);
		self.seen.send_modify(|seen| seen.push(urn));
	}

	fn drain(&self) -> Vec<TbEvent> {
		self.kept.drain()
	}

	fn overflowed(&self) -> bool {
		self.kept.overflowed()
	}

	fn sibling(&self) -> Option<Arc<dyn EventSink>> {
		let sibling = Self::sharing(self.max_events, self.seen.clone());
		Some(Arc::new(sibling))
	}
}
