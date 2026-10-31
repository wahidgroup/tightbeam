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
use super::reassembly::{Reassembly, ReassemblyBudget};
use super::shared::OpenSlot;
use crate::der::Decode;
use crate::transport::{TransportError, TransportResult};
use crate::Frame;

#[cfg(doc)]
use crate::constants::MAX_MUX_REASSEMBLY_BYTES;
#[cfg(doc)]
use crate::transport::TransportFailure;

#[cfg(feature = "colony")]
use super::sink::RequestSink;

/// A chunk-level event that the reader forwards to a [`StreamBody`].
pub enum BodyEvent {
	/// One body chunk, in wire order.
	Chunk(Vec<u8>),
	/// The clean, `last`-flagged end of the body.
	End,
	/// The stream resolved without a clean end, through a non-Ok trailer, a
	/// cancel, or a drain.
	Failed(TransportError),
}

/// A consumption report from a [`StreamBody`] back to the reader.
///
/// The reader uses [`consumed`](Self::consumed) as its input to credit
/// replenishment.
pub struct DrainNote {
	/// The stream whose body drained the chunks.
	pub stream_id: u32,
	/// The absolute count of chunks that the handler has drained. Like every
	/// ledger position in the credit design, it is monotonic and idempotent.
	pub consumed: u64,
}

/// An incremental stream body, which carries one of two streams:
///
/// - A peer request under [`MuxResponder::serve_streaming`] or [`MuxResponder::serve_duplex`].
/// - The streamed reply of a duplex stream opened locally with [`MuxHandle::open_duplex`].
///
/// Chunks arrive in wire order as the peer sends them. Each consumed chunk
/// reports drain progress to the reader, which replenishes the peer's stream
/// credit through the connection's [`CreditGrantor`]. A slow consumer
/// therefore parks the sender.
///
/// # Drop
///
/// - A handler-side request body that drops discards its remaining chunks.
///   The responder still owes the terminal record.
/// - A duplex reply body that drops before its terminal event cancels the
///   stream, which releases the cap slot on both endpoints.
///
/// [`MuxResponder::serve_streaming`]: super::responder::MuxResponder::serve_streaming
/// [`MuxResponder::serve_duplex`]: super::responder::MuxResponder::serve_duplex
/// [`MuxHandle::open_duplex`]: super::handle::MuxHandle::open_duplex
/// [`CreditGrantor`]: crate::transport::multiplex::CreditGrantor
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
	/// The drop guard, armed on a locally-initiated duplex reply alone, because
	/// an abandoned reply must reclaim its stream as an abandoned response
	/// future does.
	guard: Option<CancelOnDrop>,
	/// The reassembly budget of the connection, which a collect of the body
	/// charges as the unary reassembly of the reader does.
	budget: Arc<ReassemblyBudget>,
}

impl StreamBody {
	/// Assembles a body and the forwarder that feeds it, for one streaming
	/// request.
	///
	/// The channel capacity covers the grant window plus the `End` marker. The
	/// reader clamps streaming grants to `consumed + window`, so a conforming
	/// peer always fits in the channel. A collect of the body charges
	/// `budget`, the reassembly budget of the connection.
	pub(crate) fn pair(
		slot: Arc<OpenSlot>,
		window: u64,
		drained: mpsc::Sender<DrainNote>,
		budget: Arc<ReassemblyBudget>,
	) -> (Self, ForwardedStream) {
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
			budget,
		};
		let forwarder = ForwardedStream { events, received: 0, limit: window, window };
		(body, forwarder)
	}

	/// Feeds every chunk of this body into `sink`, then closes the sink so
	/// its stream ends.
	///
	/// Each consumed chunk replenishes the peer's credit, so a slow
	/// downstream parks the upstream (end-to-end backpressure).
	///
	/// # Errors
	///
	/// - The first read or push failure, which leaves the sink unclosed.
	#[cfg(feature = "colony")]
	pub(crate) async fn drain_into(mut self, mut sink: RequestSink) -> TransportResult<()> {
		while let Some(chunk) = self.chunk().await? {
			sink.push(&chunk).await?;
		}

		sink.close().await
	}

	/// Arms the drop guard, so a drop of this body before its terminal event
	/// cancels the stream on both endpoints.
	pub fn arm_guard(&mut self, guard: CancelOnDrop) {
		self.guard = Some(guard);
	}

	/// Waits for the next body chunk, and answers `Ok(None)` once this body
	/// consumed the peer's `last` chunk.
	///
	/// The terminal state is sticky. After `Ok(None)` or an error, every later
	/// call returns `Ok(None)`.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the stream died before its `last` chunk.
	/// - [`TransportError::Draining`] -- a GoAway ended the stream before the peer served it.
	/// - `OperationFailed(Cancelled)` -- its own sink or the peer cancelled the stream.
	/// - The trailer's [`TransitStatus`](crate::policy::TransitStatus) mapped
	///   to its transport error, on a duplex reply that ended non-Ok.
	pub async fn chunk(&mut self) -> TransportResult<Option<Vec<u8>>> {
		poll_fn(|cx| self.poll_chunk(cx)).await
	}

	/// Collects the remaining chunks into one buffer and consumes the body.
	/// Drain reports flow per chunk exactly as with [`chunk`](Self::chunk), so
	/// credit replenishment is identical.
	///
	/// The chunks reassemble under the bounds of a unary reassembly, so a peer
	/// stream reassembles to one bound on either path (CWE-770).
	///
	/// # Errors
	///
	/// - The errors of [`chunk`](Self::chunk).
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the chunks pass
	///   [`MAX_MUX_REASSEMBLY_BYTES`], or the reassembly budget of the
	///   connection.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::policy::TransitStatus;
	/// use tightbeam::transport::multiplex::StreamBody;
	/// use tightbeam::transport::{ResponsePackage, TransportError, TransportFailure, TransportResult};
	///
	/// /// Answer a streamed upload once its body is whole. A body past the
	/// /// reassembly ceiling is the peer's to shrink, so it reads
	/// /// `ResourceExhausted`.
	/// async fn upload(body: StreamBody) -> TransportResult<ResponsePackage> {
	///     match body.into_bytes().await {
	///         Ok(_bytes) => Ok(ResponsePackage::new(TransitStatus::Ok, None)),
	///         Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)) => {
	///             Ok(ResponsePackage::new(TransitStatus::ResourceExhausted, None))
	///         }
	///         Err(other) => Err(other),
	///     }
	/// }
	/// ```
	pub async fn into_bytes(mut self) -> TransportResult<Vec<u8>> {
		let mut collected = Reassembly::new(Arc::clone(&self.budget));
		while let Some(chunk) = self.chunk().await? {
			collected.append(chunk)?;
		}

		Ok(collected.into_bytes())
	}

	/// Collects the remaining chunks, decodes them as one DER [`Frame`], and
	/// consumes the body.
	///
	/// # Errors
	///
	/// - The errors of [`chunk`](Self::chunk), while the body drains.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the chunks pass
	///   [`MAX_MUX_REASSEMBLY_BYTES`], or the reassembly budget of the
	///   connection.
	/// - [`TransportError::DerError`] -- the collected bytes are not a DER frame.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::policy::TransitStatus;
	/// use tightbeam::transport::multiplex::StreamBody;
	/// use tightbeam::transport::{ResponsePackage, TransportResult};
	///
	/// /// Echo the frame a peer streamed, once its chunks are whole.
	/// async fn echo(body: StreamBody) -> TransportResult<ResponsePackage> {
	///     let frame = body.into_frame().await?;
	///     Ok(ResponsePackage::new(TransitStatus::Ok, Some(frame)))
	/// }
	/// ```
	pub async fn into_frame(self) -> TransportResult<Frame> {
		let bytes = self.into_bytes().await?;
		Frame::from_der(&bytes).map_err(TransportError::DerError)
	}

	/// The poll core that [`chunk`](Self::chunk) and the [`Stream`] impl share.
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

	/// Reports the current consumption count to the reader once the channel
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

	/// Marks the body terminal and disarms its drop guard, because a resolved
	/// stream has nothing left to cancel.
	fn finish(&mut self) {
		self.finished = true;
		if let Some(guard) = &mut self.guard {
			guard.disarm();
		}
	}
}

/// A chunk-at-a-time [`Stream`] view of the body.
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

/// The reader-side ledger of a streaming request, which forwards chunks into
/// the body channel in place of a reassembly buffer.
pub struct ForwardedStream {
	events: mpsc::Sender<BodyEvent>,
	/// The count of chunks accepted so far.
	received: u64,
	/// The absolute cumulative chunk limit granted to the sender.
	limit: u64,
	/// The grant ceiling above the consumed watermark. The body channel absorbs
	/// at most this many undrained chunks.
	window: u64,
}

impl ForwardedStream {
	/// The current `(limit, window)` pair of the grant arithmetic.
	pub fn limits(&self) -> (u64, u64) {
		(self.limit, self.window)
	}

	/// Raises the granted limit.
	///
	/// Grants are absolute and monotonic, so the call ignores a stale lower
	/// value.
	///
	/// # Sources
	///
	/// - RFC 9113 § 6.9.1, the flow-control window:
	///   <https://datatracker.ietf.org/doc/html/rfc9113#section-6.9.1>
	pub fn raise_limit(&mut self, limit: u64) {
		self.limit = self.limit.max(limit);
	}

	/// Accounts one arriving chunk against the granted limit, and returns
	/// `false` when the chunk would pass the limit.
	pub fn accept_chunk(&mut self) -> bool {
		if self.received >= self.limit {
			return false;
		}

		self.received = self.received.saturating_add(1);

		true
	}

	/// Forwards a body event, and returns `false` on a failure.
	///
	/// The reader clamps grants to the channel capacity, so a full channel is
	/// unreachable for a conforming peer, and an overflow reports as a failure
	/// like a disconnect. A dropped body closes the channel, which is also a
	/// failure because consumed credit stays consumed.
	pub fn forward(&mut self, event: BodyEvent) -> bool {
		self.events.try_send(event).is_ok()
	}

	/// Accounts and forwards one payload chunk, and returns `false` on a credit
	/// overrun or a full channel.
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

	/// Whether the body that consumes this stream dropped, refused at the cap
	/// or abandoned by its handler.
	pub fn severed(&self) -> bool {
		self.events.is_closed()
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;

	use super::super::fixtures::{noop_cx, poll_now, FlagWake};
	use super::*;
	use crate::constants::MAX_MUX_REASSEMBLY_BYTES;
	use crate::der::Encode;
	use crate::testing::{TestFrame, TestResult};
	use crate::transport::TransportFailure;

	/// The length of each chunk of the bodies that meet the reassembly
	/// ceiling.
	const CEILING_CHUNK_LEN: usize = 64 * 1024;

	/// The chunks of [`CEILING_CHUNK_LEN`] octets that fill the reassembly
	/// ceiling exactly.
	const CEILING_CHUNKS: usize = MAX_MUX_REASSEMBLY_BYTES / CEILING_CHUNK_LEN;

	/// A body of stream 7 with a window of four chunks whose forwarder carried
	/// `events`, beside that forwarder and the drain notes of the body.
	fn body_carrying(
		events: impl IntoIterator<Item = BodyEvent>,
	) -> (StreamBody, ForwardedStream, mpsc::Receiver<DrainNote>) {
		let (body, mut forwarder, notes) = StreamBody::fixture(7, 4);
		let carried = events.into_iter().all(|event| forwarder.forward(event));
		assert!(carried);

		(body, forwarder, notes)
	}

	/// A body whose forwarder carried `count` chunks of [`CEILING_CHUNK_LEN`]
	/// octets and then its end, beside the drain notes it reports.
	fn forwarded_body(count: usize) -> (StreamBody, mpsc::Receiver<DrainNote>) {
		let window = u64::try_from(count).expect("a chunk count fits u64");
		let (body, mut forwarder, notes) = StreamBody::fixture(7, window);
		let chunk = vec![0xAB; CEILING_CHUNK_LEN];

		let forwarded = (0..count).all(|_| forwarder.accept_and_forward(&chunk));
		let ended = forwarder.forward(BodyEvent::End);
		assert!(forwarded && ended);

		(body, notes)
	}

	/// A body over `budget` whose forwarder carried two chunks of 100 octets
	/// and then its end.
	fn two_chunk_body(budget: Arc<ReassemblyBudget>) -> StreamBody {
		let (body, mut forwarder, _notes) = StreamBody::budgeted_fixture(7, 4, budget);

		let forwarded = (0..2).all(|_| forwarder.accept_and_forward([0xAB; 100]));
		let ended = forwarder.forward(BodyEvent::End);
		assert!(forwarded && ended);

		body
	}

	/// A body yields its chunks, ends for good, and reports one drain per
	/// chunk, and the end marker consumes no credit.
	#[test]
	fn a_body_yields_its_chunks_and_reports_each_drain() {
		let (mut body, mut forwarder, mut notes) = StreamBody::fixture(7, 4);
		assert!(forwarder.accept_chunk());
		assert!(forwarder.forward(BodyEvent::Chunk(vec![1, 2])));
		assert!(forwarder.forward(BodyEvent::End));

		let first = body.poll_chunk_now();
		assert!(matches!(first, Poll::Ready(Ok(Some(chunk))) if chunk == [1, 2]));
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
		// The terminal state is sticky.
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
		assert!(matches!(notes.try_recv(), Ok(DrainNote { stream_id: 7, consumed: 1 })));
		// The End marker consumes no credit and reports no drain.
		assert!(notes.try_recv().is_err());
	}

	/// The drain notes of a body coalesce while the reader stalls, and the
	/// drained slot flushes them when the reader resumes.
	#[test]
	fn drain_notes_coalesce_while_the_reader_stalls_and_flush_on_resume() {
		let (mut body, _forwarder, mut notes) =
			body_carrying([BodyEvent::Chunk(vec![1]), BodyEvent::Chunk(vec![2]), BodyEvent::Chunk(vec![3])]);

		let parked = FlagWake::parked();
		let mut cx = parked.cx();
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Ready(Ok(Some(chunk))) if chunk == [1]));
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Ready(Ok(Some(chunk))) if chunk == [2]));
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Ready(Ok(Some(chunk))) if chunk == [3]));

		// The stalled reader holds exactly the body's one slot.
		assert!(!parked.woken());
		assert!(matches!(notes.try_recv(), Ok(DrainNote { stream_id: 7, consumed: 1 })));
		assert!(notes.try_recv().is_err());

		// The drained slot wakes the body, whose next poll reports its current
		// count before it waits on chunks.
		assert!(parked.woken());
		assert!(matches!(body.poll_chunk(&mut cx), Poll::Pending));
		assert!(matches!(notes.try_recv(), Ok(DrainNote { stream_id: 7, consumed: 3 })));
		assert!(notes.try_recv().is_err());
	}

	/// A body whose forwarder dropped ends as a closed connection.
	#[test]
	fn a_body_surfaces_a_severed_stream() {
		let (mut body, forwarder, _notes) = StreamBody::fixture(7, 4);
		drop(forwarder);

		let severed = body.poll_chunk_now();
		assert!(matches!(severed, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	/// A body surfaces a failed terminal once, and then ends for good.
	#[test]
	fn a_body_surfaces_a_failed_terminal() {
		let (mut body, _forwarder, _notes) = body_carrying([BodyEvent::Failed(TransportError::Draining)]);

		let failed = body.poll_chunk_now();
		assert!(matches!(failed, Poll::Ready(Err(TransportError::Draining))));
		// The terminal state is sticky.
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
	}

	/// A forwarder accepts no chunk past the limit it granted.
	#[test]
	fn a_forwarder_enforces_its_granted_limit() {
		let (_body, mut forwarder, _notes) = StreamBody::fixture(7, 1);

		let first = forwarder.accept_chunk();
		assert!(first);
		assert!(!forwarder.accept_chunk());
	}

	/// A dropped body closes the channel, so forward must report failure. A
	/// forward that treated `Closed` as a success would keep credit draining.
	#[test]
	fn a_forward_fails_once_the_body_dropped() {
		let (body, mut forwarder, _notes) = StreamBody::fixture(7, 4);
		drop(body);

		let forwarded = forwarder.forward(BodyEvent::Chunk(vec![1]));
		assert!(!forwarded);
	}

	/// The first item a body stream yields, which a row tests.
	type FirstItem = Poll<Option<TransportResult<Vec<u8>>>>;

	// A body stream yields its first item, a chunk or a terminal failure,
	// and then fuses.
	crate::tb_cases! {
		fn a_body_stream_yields_its_item_and_then_fuses(
			(events, yielded): (Vec<BodyEvent>, fn(&FirstItem) -> bool)
		) {
			let (mut body, _forwarder, _notes) = body_carrying(events);
			let mut cx = noop_cx();

			let first = Pin::new(&mut body).poll_next(&mut cx);
			assert!(yielded(&first));
			assert!(matches!(Pin::new(&mut body).poll_next(&mut cx), Poll::Ready(None)));
			assert!(matches!(Pin::new(&mut body).poll_next(&mut cx), Poll::Ready(None)));
		}
		cases {
			a_chunk_then_the_end => (
				vec![BodyEvent::Chunk(vec![1, 2]), BodyEvent::End],
				|first| matches!(first, Poll::Ready(Some(Ok(chunk))) if chunk == &[1, 2]),
			),
			a_failure => (
				vec![BodyEvent::Failed(TransportError::Draining)],
				|first| matches!(first, Poll::Ready(Some(Err(TransportError::Draining)))),
			),
		}
	}

	/// A body collects its chunks into one buffer in order.
	#[test]
	fn a_body_concatenates_its_chunks() {
		let (body, _forwarder, _notes) =
			body_carrying([BodyEvent::Chunk(vec![1, 2]), BodyEvent::Chunk(vec![3]), BodyEvent::End]);

		let bytes = poll_now(body.into_bytes());
		assert!(matches!(bytes, Poll::Ready(Ok(bytes)) if bytes == [1, 2, 3]));
	}

	/// A body decodes the frame its chunks carry together.
	#[test]
	fn a_body_decodes_the_frame_its_chunks_carry() -> TestResult {
		let frame = TestFrame::v0(Some("collected"), None);
		let payload = frame.to_der()?;
		let middle = payload.len() / 2;
		let (body, _forwarder, _notes) = body_carrying([
			BodyEvent::Chunk(payload[..middle].to_vec()),
			BodyEvent::Chunk(payload[middle..].to_vec()),
			BodyEvent::End,
		]);

		let decoded = poll_now(body.into_frame());
		assert!(matches!(decoded, Poll::Ready(Ok(decoded)) if decoded == frame));

		Ok(())
	}

	/// A body that meets the reassembly ceiling exactly is collected whole.
	#[test]
	fn a_body_at_the_reassembly_ceiling_is_collected() {
		let (body, _notes) = forwarded_body(CEILING_CHUNKS);

		let collected = poll_now(body.into_bytes());
		assert!(matches!(collected, Poll::Ready(Ok(bytes)) if bytes.len() == MAX_MUX_REASSEMBLY_BYTES));
	}

	// A body past a bound of its collect is refused as oversize: a peer stream
	// reassembles to the bound of a unary reassembly, so one chunk past it
	// refuses the body, and a body charges the reassembly budget of its
	// connection as it collects, so a body inside its own ceiling is refused
	// past the budget.
	crate::tb_cases! {
		fn a_body_past_a_bound_of_its_collect_is_refused(body: StreamBody) {
			let collected = poll_now(body.into_bytes());
			assert!(matches!(
				collected,
				Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)))
			));
		}
		cases {
			the_reassembly_ceiling => forwarded_body(CEILING_CHUNKS + 1).0,
			the_connection_budget => two_chunk_body(Arc::new(ReassemblyBudget::with_ceiling(128))),
		}
	}

	/// A body whose chunks decode to no frame reports the decode error.
	#[test]
	fn a_body_of_garbage_reports_a_der_error() {
		let (body, _forwarder, _notes) = body_carrying([BodyEvent::Chunk(vec![0xFF, 0xFF]), BodyEvent::End]);

		let decoded = poll_now(body.into_frame());
		assert!(matches!(decoded, Poll::Ready(Err(TransportError::DerError(_)))));
	}

	/// An empty payload such as a bare trailer consumes credit and forwards
	/// no chunk event, so the consumer sees no phantom empty chunk.
	#[test]
	fn a_forwarder_skips_an_empty_payload() {
		let (mut body, mut forwarder, _notes) = StreamBody::fixture(7, 4);
		assert!(forwarder.accept_and_forward([]));
		assert!(forwarder.forward(BodyEvent::End));

		let ended = body.poll_chunk_now();
		assert!(matches!(ended, Poll::Ready(Ok(None))));
		assert_eq!(forwarder.limits(), (4, 4));
	}
}
