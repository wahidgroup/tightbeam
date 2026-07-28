//! Incremental stream bodies: the consumer half of streaming dispatch
//! and the reader-side forwarders that feed them.

use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::Stream;

use super::handle::CancelOnDrop;
use super::shared::OpenSlot;
use crate::der::Decode;
use crate::transport::{TransportError, TransportResult};
use crate::Frame;

/// Chunk-level event the reader forwards to a [`StreamBody`].
pub(super) enum BodyEvent {
	Chunk(Vec<u8>),
	/// Clean `last`-flagged end of the body.
	End,
	/// The stream resolved without a clean end: non-Ok trailer,
	/// cancel, or drain.
	Failed(TransportError),
}

/// Consumption report from a [`StreamBody`] back to the reader:
/// `consumed` is the absolute chunk count the handler has drained,
/// the reader's input to credit replenishment. Monotonic and
/// idempotent like every ledger position in the credit design.
pub(super) struct DrainNote {
	pub(super) stream_id: u32,
	pub(super) consumed: u64,
}

/// Incremental stream body: a peer request under
/// [`MuxResponder::serve_streaming`](super::responder::MuxResponder::serve_streaming) /
/// [`serve_duplex`](super::responder::MuxResponder::serve_duplex),
/// or the streamed reply of a locally-opened duplex stream
/// ([`MuxHandle::open_duplex`](super::handle::MuxHandle::open_duplex)).
///
/// Chunks arrive in wire order as the peer sends them. Consuming a chunk
/// reports drain progress to the reader, which replenishes the peer's stream
/// credit through the connection's [`CreditGrantor`](super::flow::CreditGrantor).
/// A slow consumer therefore parks the sender.
///
/// Dropping a handler-side request body discards the remaining
/// chunks (the responder still owes the terminal record). Dropping
/// a duplex reply body before its terminal event cancels the
/// stream, releasing the cap slot on both endpoints.
pub struct StreamBody {
	/// The stream's identity: assigned from birth on peer-initiated
	/// bodies, assigned at first push on locally-opened duplex replies
	slot: Arc<OpenSlot>,
	events: mpsc::Receiver<BodyEvent>,
	drained: mpsc::UnboundedSender<DrainNote>,
	consumed: u64,
	finished: bool,
	/// Armed only on locally-initiated duplex replies: abandoning the reply
	/// must reclaim the stream like abandoning a response future does.
	guard: Option<CancelOnDrop>,
}

impl StreamBody {
	/// Arm the drop guard: dropping this body before its terminal
	/// event cancels the stream on both endpoints.
	pub(super) fn arm_guard(&mut self, guard: CancelOnDrop) {
		self.guard = Some(guard);
	}

	/// Next body chunk, `Ok(None)` once the peer's `last` chunk has
	/// been consumed.
	///
	/// The terminal state is sticky: after `Ok(None)` or an error,
	/// every later call returns `Ok(None)`.
	///
	/// # Errors
	/// - `ConnectionClosed`: the stream died before its `last` chunk
	/// - The trailer's [`TransitStatus`](crate::policy::TransitStatus)
	///   mapped to its transport error, on a duplex reply that ended non-Ok
	pub async fn chunk(&mut self) -> TransportResult<Option<Vec<u8>>> {
		poll_fn(|cx| self.poll_chunk(cx)).await
	}

	/// Collect the remaining chunks into one buffer, consuming the
	/// body. Drain reports flow per chunk exactly as with
	/// [`chunk`](Self::chunk), so credit replenishment is identical.
	///
	/// # Errors
	/// Same set as [`chunk`](Self::chunk).
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
	/// - [`chunk`](Self::chunk)'s set, while draining
	/// - `DerError`: the collected bytes are not a DER frame
	pub async fn into_frame(self) -> TransportResult<Frame> {
		let bytes = self.into_bytes().await?;
		Frame::from_der(&bytes).map_err(TransportError::DerError)
	}

	/// Poll core shared by [`chunk`](Self::chunk) and the [`Stream`] impl.
	fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<TransportResult<Option<Vec<u8>>>> {
		if self.finished {
			return Poll::Ready(Ok(None));
		}

		match Pin::new(&mut self.events).poll_next(cx) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(Some(BodyEvent::Chunk(chunk))) => {
				self.consumed = self.consumed.saturating_add(1);
				// A chunk implies the stream opened, so the slot is
				// assigned. A dropped reader means the connection is
				// going down; the next poll surfaces the closure.
				if let Some(stream_id) = self.slot.get() {
					let _ = self.drained.unbounded_send(DrainNote { stream_id, consumed: self.consumed });
				}
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

	/// Mark the body terminal and stand its drop guard down: a
	/// resolved stream has nothing left to cancel.
	fn finish(&mut self) {
		self.finished = true;
		if let Some(guard) = &mut self.guard {
			guard.disarm();
		}
	}
}

/// Chunk-at-a-time [`Stream`] view: `Ok` items are body chunks, a
/// single `Err` item surfaces the terminal failure, and the stream
/// fuses to `None` afterwards (and after the clean end), matching
/// [`StreamBody::chunk`]'s sticky terminal state. Enables
/// `TryStreamExt` combinators (`try_next`, `try_fold`, ...).
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

/// Assemble a body/forwarder pair for one streaming request.
///
/// Channel capacity covers the grant window plus the `End` marker:
/// the reader clamps streaming grants to `consumed + window`, so a
/// conforming peer can never overrun the channel.
pub(super) fn stream_body(
	slot: Arc<OpenSlot>,
	window: u64,
	drained: mpsc::UnboundedSender<DrainNote>,
) -> (StreamBody, ForwardedStream) {
	let capacity = usize::try_from(window).unwrap_or(usize::MAX).saturating_add(1);
	let (events, receiver) = mpsc::channel(capacity);

	let body = StreamBody { slot, events: receiver, drained, consumed: 0, finished: false, guard: None };
	let forwarder = ForwardedStream { events, received: 0, limit: window, window };
	(body, forwarder)
}

/// Reader-side ledger of a streaming request: chunks forward into
/// the body channel instead of a reassembly buffer.
pub(super) struct ForwardedStream {
	events: mpsc::Sender<BodyEvent>,
	/// Chunks accepted so far
	received: u64,
	/// Absolute cumulative chunk limit granted to the sender
	limit: u64,
	/// Grant ceiling above the consumed watermark: the body channel
	/// absorbs at most this many undrained chunks
	window: u64,
}

impl ForwardedStream {
	/// Current `(limit, window)` pair for grant arithmetic.
	pub(super) fn limits(&self) -> (u64, u64) {
		(self.limit, self.window)
	}

	/// Raise the granted limit. Grants are absolute and monotonic
	/// ([RFC 9113 § 6.9.1](https://datatracker.ietf.org/doc/html/rfc9113#section-6.9.1)
	/// analog), so a stale lower value is ignored.
	pub(super) fn raise_limit(&mut self, limit: u64) {
		self.limit = self.limit.max(limit);
	}

	/// Account one arriving chunk against the granted limit.
	pub(super) fn accept_chunk(&mut self) -> bool {
		if self.received >= self.limit {
			return false;
		}

		self.received = self.received.saturating_add(1);

		true
	}

	/// Forward a body event. A full channel is unreachable for a
	/// conforming peer (grants are clamped to channel capacity), so
	/// overflow reports as a failure like a disconnect. A dropped
	/// (Closed) body is also failure: consumed credit stays consumed.
	pub(super) fn forward(&mut self, event: BodyEvent) -> bool {
		self.events.try_send(event).is_ok()
	}

	/// Account and forward one payload chunk: `false` on a credit
	/// overrun or an overflowing channel. Empty payloads (bare
	/// trailers, empty bodies) consume their credit but forward no
	/// chunk event: the consumer sees data or the end, never a
	/// phantom empty chunk.
	pub(super) fn accept_and_forward(&mut self, payload: &[u8]) -> bool {
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
	pub(super) fn severed(&self) -> bool {
		self.events.is_closed()
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;

	use super::super::testing::{body_fixture, noop_cx, poll_chunk, poll_now};
	use super::*;
	use crate::der::Encode;
	use crate::testing::create_v0_tightbeam;

	#[test]
	fn test_stream_body_yields_chunks_and_reports_drain() {
		let (mut body, mut forwarder, mut notes) = body_fixture(7, 4);
		assert!(forwarder.accept_chunk());
		assert!(forwarder.forward(BodyEvent::Chunk(vec![1, 2])));
		assert!(forwarder.forward(BodyEvent::End));

		let first = poll_chunk(&mut body);
		assert!(matches!(first, Poll::Ready(Ok(Some(chunk))) if chunk == [1, 2]));
		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Ok(None))));
		// Terminal state is sticky
		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Ok(None))));

		let note = notes.try_recv();
		assert!(matches!(note, Ok(DrainNote { stream_id: 7, consumed: 1 })));
		// The End marker consumes no credit and reports no drain
		assert!(notes.try_recv().is_err());
	}

	#[test]
	fn test_stream_body_surfaces_severed_stream() {
		let (mut body, forwarder, _notes) = body_fixture(7, 4);
		drop(forwarder);

		let severed = poll_chunk(&mut body);
		assert!(matches!(severed, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	#[test]
	fn test_stream_body_surfaces_failed_terminal() {
		let (mut body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.forward(BodyEvent::Failed(TransportError::Draining)));

		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Err(TransportError::Draining))));
		// Terminal state is sticky
		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Ok(None))));
	}

	#[test]
	fn test_forwarded_stream_enforces_granted_limit() {
		let (_body, mut forwarder, _notes) = body_fixture(7, 1);
		assert!(forwarder.accept_chunk());
		assert!(!forwarder.accept_chunk());
	}

	// A dropped body closes the channel: forward must report failure,
	// not treat Closed like success (credit would keep draining).
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

	// A terminal failure surfaces as one Err item, then the stream
	// fuses.
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
		let frame = create_v0_tightbeam(Some("collected"), None);
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

	// Empty payloads (bare trailers) consume credit but forward no
	// chunk event: the consumer never sees a phantom empty chunk.
	#[test]
	fn test_forwarded_stream_skips_empty_payload_events() {
		let (mut body, mut forwarder, _notes) = body_fixture(7, 4);
		assert!(forwarder.accept_and_forward(&[]));
		assert!(forwarder.forward(BodyEvent::End));

		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Ok(None))));
		assert!(matches!(forwarder.limits(), (4, 4)));
	}
}
