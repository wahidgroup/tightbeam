//! Incremental stream bodies and the reader-side forwarders that feed them.
//!
//! A [`StreamBody`] is the consumer half of streaming dispatch. A
//! [`ForwardedStream`] is the reader-side ledger that feeds it.

use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::Stream;

use super::handle::CancelOnDrop;
use super::shared::OpenSlot;
use super::sink::RequestSink;
use crate::der::Decode;
use crate::transport::{TransportError, TransportResult};
use crate::Frame;

/// Chunk-level event the reader forwards to a [`StreamBody`].
pub enum BodyEvent {
	/// One body chunk, in wire order.
	Chunk(Vec<u8>),
	/// Clean `last`-flagged end of the body.
	End,
	/// The stream resolved without a clean end, through a non-Ok trailer, a
	/// cancel, or a drain.
	Failed(TransportError),
}

/// Consumption report from a [`StreamBody`] back to the reader.
///
/// The reader uses [`consumed`](Self::consumed) as its input to credit
/// replenishment.
pub struct DrainNote {
	/// Stream whose body drained the chunks.
	pub stream_id: u32,
	/// Absolute count of chunks the handler has drained. Like every ledger
	/// position in the credit design, it is monotonic and idempotent.
	pub consumed: u64,
}

/// Incremental stream body, which carries one of two streams:
///
/// - A peer request under [`MuxResponder::serve_streaming`] or [`MuxResponder::serve_duplex`].
/// - The streamed reply of a duplex stream opened locally with [`MuxHandle::open_duplex`].
///
/// Chunks arrive in wire order as the peer sends them. Consuming a chunk
/// reports drain progress to the reader, which replenishes the peer's stream
/// credit through the connection's [`CreditGrantor`]. A slow consumer
/// therefore parks the sender.
///
/// # Drop
///
/// - Dropping a handler-side request body discards the remaining chunks. The
///   responder still owes the terminal record.
/// - Dropping a duplex reply body before its terminal event cancels the
///   stream, which releases the cap slot on both endpoints.
///
/// [`MuxResponder::serve_streaming`]: super::responder::MuxResponder::serve_streaming
/// [`MuxResponder::serve_duplex`]: super::responder::MuxResponder::serve_duplex
/// [`MuxHandle::open_duplex`]: super::handle::MuxHandle::open_duplex
/// [`CreditGrantor`]: super::flow::CreditGrantor
pub struct StreamBody {
	/// The stream's identity. A peer-initiated body holds it from birth, and a
	/// locally-opened duplex reply receives it at the first push.
	slot: Arc<OpenSlot>,
	events: mpsc::Receiver<BodyEvent>,
	drained: mpsc::Sender<DrainNote>,
	/// Whether the drain channel still owes the reader the current
	/// `consumed` count. Notes carry absolute counts, so the count at send
	/// time stands in for every count the channel refused before it.
	unreported: bool,
	consumed: u64,
	finished: bool,
	/// Armed only on locally-initiated duplex replies: abandoning the reply
	/// must reclaim the stream like abandoning a response future does.
	guard: Option<CancelOnDrop>,
}

impl StreamBody {
	/// Assemble a body and the forwarder that feeds it, for one streaming
	/// request.
	///
	/// Channel capacity covers the grant window plus the `End` marker. The
	/// reader clamps streaming grants to `consumed + window`, so a conforming
	/// peer always fits in the channel.
	pub(crate) fn pair(slot: Arc<OpenSlot>, window: u64, drained: mpsc::Sender<DrainNote>) -> (Self, ForwardedStream) {
		let capacity = usize::try_from(window).unwrap_or(usize::MAX).saturating_add(1);
		let (events, receiver) = mpsc::channel(capacity);

		let body = Self {
			slot,
			events: receiver,
			drained,
			unreported: false,
			consumed: 0,
			finished: false,
			guard: None,
		};
		let forwarder = ForwardedStream { events, received: 0, limit: window, window };
		(body, forwarder)
	}

	/// Feed every chunk of this body into `sink`, then close the sink so
	/// its stream ends.
	///
	/// Consuming each chunk replenishes the peer's credit, so a slow
	/// downstream parks the upstream (end-to-end backpressure).
	///
	/// # Errors
	///
	/// Returns the first read or push failure and leaves the sink unclosed.
	pub(crate) async fn drain_into(mut self, mut sink: RequestSink) -> TransportResult<()> {
		while let Some(chunk) = self.chunk().await? {
			sink.push(&chunk).await?;
		}

		sink.close().await
	}

	/// Arm the drop guard: dropping this body before its terminal
	/// event cancels the stream on both endpoints.
	pub fn arm_guard(&mut self, guard: CancelOnDrop) {
		self.guard = Some(guard);
	}

	/// Wait for the next body chunk, or `Ok(None)` once the peer's `last`
	/// chunk has been consumed.
	///
	/// The terminal state is sticky. After `Ok(None)` or an error, every later
	/// call returns `Ok(None)`.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the stream died before its `last` chunk.
	/// - The trailer's [`TransitStatus`](crate::policy::TransitStatus) mapped
	///   to its transport error, on a duplex reply that ended non-Ok.
	pub async fn chunk(&mut self) -> TransportResult<Option<Vec<u8>>> {
		poll_fn(|cx| self.poll_chunk(cx)).await
	}

	/// Collect the remaining chunks into one buffer, consuming the
	/// body. Drain reports flow per chunk exactly as with
	/// [`chunk`](Self::chunk), so credit replenishment is identical.
	///
	/// # Errors
	///
	/// The same set as [`chunk`](Self::chunk).
	pub async fn into_bytes(mut self) -> TransportResult<Vec<u8>> {
		let mut bytes = Vec::new();
		while let Some(chunk) = self.chunk().await? {
			bytes.extend_from_slice(&chunk);
		}

		Ok(bytes)
	}

	/// Collect the remaining chunks and decode them as one DER
	/// [`Frame`], consuming the body.
	///
	/// # Errors
	///
	/// - The [`chunk`](Self::chunk) set, while the body drains.
	/// - [`TransportError::DerError`] -- the collected bytes are not a DER frame.
	pub async fn into_frame(self) -> TransportResult<Frame> {
		let bytes = self.into_bytes().await?;
		Frame::from_der(&bytes).map_err(TransportError::DerError)
	}

	/// Poll core shared by [`chunk`](Self::chunk) and the [`Stream`] impl.
	fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<TransportResult<Option<Vec<u8>>>> {
		if self.finished {
			return Poll::Ready(Ok(None));
		}

		// A report the channel refused earlier goes first, so a reader that
		// resumed learns of the consumption before this poll adds to it.
		self.flush_drain_note(cx);

		match Pin::new(&mut self.events).poll_next(cx) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(Some(BodyEvent::Chunk(chunk))) => {
				self.consumed = self.consumed.saturating_add(1);
				self.unreported = true;
				self.flush_drain_note(cx);
				Poll::Ready(Ok(Some(chunk)))
			}
			Poll::Ready(Some(BodyEvent::End)) => {
				self.finish();
				Poll::Ready(Ok(None))
			}
			Poll::Ready(Some(BodyEvent::Failed(err))) => {
				self.finish();
				Poll::Ready(Err(err))
			}
			Poll::Ready(None) => {
				self.finish();
				Poll::Ready(Err(TransportError::ConnectionClosed))
			}
		}
	}

	/// Report the current consumption count to the reader once the channel
	/// admits it.
	///
	/// A full channel keeps the count owed and parks this body's waker on the
	/// channel, so the report leaves as soon as the reader drains a slot. A
	/// closed channel means the reader is gone, and the closed events channel
	/// surfaces that on the next poll, so the count has no one left to reach.
	fn flush_drain_note(&mut self, cx: &mut Context<'_>) {
		if !self.unreported {
			return;
		}

		// A chunk implies the stream opened, so the slot is assigned.
		let Some(stream_id) = self.slot.get() else {
			return;
		};

		match self.drained.poll_ready(cx) {
			Poll::Pending => {}
			Poll::Ready(Err(_)) => self.unreported = false,
			Poll::Ready(Ok(())) => {
				self.unreported = false;
				let note = DrainNote { stream_id, consumed: self.consumed };
				// A start refused right after a ready poll means the receiver
				// closed in between, which the next events poll reports.
				let _ = self.drained.start_send(note);
			}
		}
	}

	/// Mark the body terminal and disarm its drop guard, because a resolved
	/// stream has nothing left to cancel.
	fn finish(&mut self) {
		self.finished = true;
		if let Some(guard) = &mut self.guard {
			guard.disarm();
		}
	}
}

/// Chunk-at-a-time [`Stream`] view of the body.
///
/// `Ok` items are body chunks, and a single `Err` item surfaces the terminal
/// failure. The stream fuses to `None` after that item and after the clean
/// end, which matches the sticky terminal state of [`StreamBody::chunk`]. The
/// view admits `TryStreamExt` combinators such as `try_next` and `try_fold`.
impl Stream for StreamBody {
	type Item = TransportResult<Vec<u8>>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		match self.poll_chunk(cx) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(Ok(Some(chunk))) => Poll::Ready(Some(Ok(chunk))),
			Poll::Ready(Ok(None)) => Poll::Ready(None),
			Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
		}
	}
}

/// Reader-side ledger of a streaming request, which forwards chunks into the
/// body channel instead of a reassembly buffer.
pub struct ForwardedStream {
	events: mpsc::Sender<BodyEvent>,
	/// Count of chunks accepted so far.
	received: u64,
	/// Absolute cumulative chunk limit granted to the sender.
	limit: u64,
	/// Grant ceiling above the consumed watermark. The body channel absorbs
	/// at most this many undrained chunks.
	window: u64,
}

impl ForwardedStream {
	/// Current `(limit, window)` pair for grant arithmetic.
	pub fn limits(&self) -> (u64, u64) {
		(self.limit, self.window)
	}

	/// Raise the granted limit.
	///
	/// Grants are absolute and monotonic, so a stale lower value is ignored.
	///
	/// # Sources
	///
	/// - RFC 9113 § 6.9.1, the flow-control window:
	///   <https://datatracker.ietf.org/doc/html/rfc9113#section-6.9.1>
	pub fn raise_limit(&mut self, limit: u64) {
		self.limit = self.limit.max(limit);
	}

	/// Account one arriving chunk against the granted limit, returning `false`
	/// when the chunk would pass the limit.
	pub fn accept_chunk(&mut self) -> bool {
		if self.received >= self.limit {
			return false;
		}

		self.received = self.received.saturating_add(1);

		true
	}

	/// Forward a body event, returning `false` on failure.
	///
	/// Grants are clamped to channel capacity, so a full channel is
	/// unreachable for a conforming peer and overflow reports as a failure
	/// like a disconnect. A dropped body closes the channel, which is also a
	/// failure because consumed credit stays consumed.
	pub fn forward(&mut self, event: BodyEvent) -> bool {
		self.events.try_send(event).is_ok()
	}

	/// Account and forward one payload chunk, returning `false` on a credit
	/// overrun or an overflowing channel.
	///
	/// An empty payload, such as a bare trailer or an empty body, consumes its
	/// credit and forwards no chunk event. The consumer therefore sees data or
	/// the end, and no phantom empty chunk.
	pub fn accept_and_forward(&mut self, payload: impl AsRef<[u8]>) -> bool {
		let payload = payload.as_ref();
		if !self.accept_chunk() {
			return false;
		}
		if payload.is_empty() {
			return true;
		}

		self.forward(BodyEvent::Chunk(payload.to_vec()))
	}

	/// Whether the consuming body has been dropped (refused at the
	/// cap or abandoned by its handler).
	pub fn severed(&self) -> bool {
		self.events.is_closed()
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;

	use super::super::testing::{body_fixture, noop_cx, poll_now, FlagWake};
	use super::*;
	use crate::der::Encode;
	use crate::testing::TestFrame;

	#[test]
	fn test_stream_body_yields_chunks_and_reports_drain() {
		let (mut body, mut forwarder, mut notes) = body_fixture(7, 4);
		assert!(forwarder.accept_chunk());
		assert!(forwarder.forward(BodyEvent::Chunk(vec![1, 2])));
		assert!(forwarder.forward(BodyEvent::End));

		let first = body.poll_chunk_now();
		assert!(matches!(first, Poll::Ready(Ok(Some(chunk))) if chunk == [1, 2]));
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
		// The terminal state is sticky.
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));

		let note = notes.try_recv();
		assert!(matches!(note, Ok(DrainNote { stream_id: 7, consumed: 1 })));
		// The End marker consumes no credit and reports no drain.
		assert!(notes.try_recv().is_err());
	}

	#[test]
	fn test_drain_notes_coalesce_while_the_reader_stalls_and_flush_on_resume() {
		let (mut body, mut forwarder, mut notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Chunk(vec![1])));
		assert!(forwarder.forward(BodyEvent::Chunk(vec![2])));
		assert!(forwarder.forward(BodyEvent::Chunk(vec![3])));

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Ready(Ok(Some(chunk))) if chunk == [1]));
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Ready(Ok(Some(chunk))) if chunk == [2]));
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Ready(Ok(Some(chunk))) if chunk == [3]));

		// The stalled reader holds exactly the body's one slot.
		assert!(!flag.woken());
		assert!(matches!(notes.try_recv(), Ok(DrainNote { stream_id: 7, consumed: 1 })));
		assert!(notes.try_recv().is_err());

		// Draining the slot wakes the body, whose next poll reports its
		// current count ahead of waiting on chunks.
		assert!(flag.woken());
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Pending));
		assert!(matches!(notes.try_recv(), Ok(DrainNote { stream_id: 7, consumed: 3 })));
		assert!(notes.try_recv().is_err());
	}

	#[test]
	fn test_stream_body_surfaces_severed_stream() {
		let (mut body, forwarder, _notes) = body_fixture(7, 4);
		drop(forwarder);

		let severed = body.poll_chunk_now();
		assert!(matches!(severed, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	#[test]
	fn test_stream_body_surfaces_failed_terminal() {
		let (mut body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Failed(TransportError::Draining)));

		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Err(TransportError::Draining))));
		// The terminal state is sticky.
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
	}

	#[test]
	fn test_forwarded_stream_enforces_granted_limit() {
		let (_body, mut forwarder, _notes) = body_fixture(7, 1);
		assert!(forwarder.accept_chunk());
		assert!(!forwarder.accept_chunk());
	}

	// A dropped body closes the channel, so forward must report failure.
	// Treating Closed like success would keep credit draining.
	#[test]
	fn test_forward_reports_failure_when_body_dropped() {
		let (body, mut forwarder, _notes) = body_fixture(7, 4);
		drop(body);
		assert!(!forwarder.forward(BodyEvent::Chunk(vec![1])));
	}

	#[test]
	fn test_stream_body_stream_impl_yields_then_fuses() {
		let (mut body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Chunk(vec![1, 2])));
		assert!(forwarder.forward(BodyEvent::End));

		let mut cx = noop_cx();
		let first = Pin::new(&mut body).poll_next(&mut cx);
		assert!(matches!(first, Poll::Ready(Some(Ok(chunk))) if chunk == [1, 2]));
		assert!(matches!(Pin::new(&mut body).poll_next(&mut cx), Poll::Ready(None)));
		assert!(matches!(Pin::new(&mut body).poll_next(&mut cx), Poll::Ready(None)));
	}

	// A terminal failure surfaces as one Err item, and then the stream fuses.
	#[test]
	fn test_stream_body_stream_impl_surfaces_failure_once() {
		let (mut body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Failed(TransportError::Draining)));

		let mut cx = noop_cx();
		let first = Pin::new(&mut body).poll_next(&mut cx);
		assert!(matches!(first, Poll::Ready(Some(Err(TransportError::Draining)))));
		assert!(matches!(Pin::new(&mut body).poll_next(&mut cx), Poll::Ready(None)));
	}

	#[test]
	fn test_into_bytes_concatenates_chunks() {
		let (body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Chunk(vec![1, 2])));
		assert!(forwarder.forward(BodyEvent::Chunk(vec![3])));
		assert!(forwarder.forward(BodyEvent::End));

		let bytes = poll_now(body.into_bytes());
		assert!(matches!(bytes, Poll::Ready(Ok(bytes)) if bytes == [1, 2, 3]));
	}

	#[test]
	fn test_into_frame_decodes_collected_chunks() -> TransportResult<()> {
		let frame = TestFrame::v0(Some("collected"), None);
		let payload = frame.to_der()?;
		let middle = payload.len() / 2;

		let (body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Chunk(payload[..middle].to_vec())));
		assert!(forwarder.forward(BodyEvent::Chunk(payload[middle..].to_vec())));
		assert!(forwarder.forward(BodyEvent::End));

		let decoded = poll_now(body.into_frame());
		assert!(matches!(decoded, Poll::Ready(Ok(decoded)) if decoded == frame));

		Ok(())
	}

	#[test]
	fn test_into_frame_maps_garbage_to_der_error() {
		let (body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Chunk(vec![0xFF, 0xFF])));
		assert!(forwarder.forward(BodyEvent::End));

		let decoded = poll_now(body.into_frame());
		assert!(matches!(decoded, Poll::Ready(Err(TransportError::DerError(_)))));
	}

	// An empty payload such as a bare trailer consumes credit and forwards no
	// chunk event, so the consumer sees no phantom empty chunk.
	#[test]
	fn test_forwarded_stream_skips_empty_payload_events() {
		let (mut body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.accept_and_forward([]));
		assert!(forwarder.forward(BodyEvent::End));
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
		assert!(matches!(forwarder.limits(), (4, 4)));
	}
}
