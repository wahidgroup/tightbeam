//! The producer sinks, which share one budget-metering rule. A `RequestSink`
//! streams request chunks on the client side, and a `ReplySink` streams reply
//! chunks on the responder side of a duplex stream.

use super::link::MuxLink;
use super::shared::{BudgetStanding, OpenRequest, StreamReservation};
use crate::transport::envelopes::{MuxDataPackage, MuxStreamKind, TransportEnvelope};
use crate::transport::TransportResult;
use crate::urn::Urn;

/// Wire state of a streamed request. It holds a cap slot until the first
/// record goes out, and the assigned stream ID afterwards.
enum SinkStream {
	/// The stream waits for its first record. The reservation holds the cap
	/// slot until the stream opens or an end of the connection resolves it.
	Reserved(StreamReservation),
	Opened(u32),
}

/// Producer half of a streamed request. It pushes chunks on a
/// locally-initiated stream and closes the stream with the `last` flag on the
/// final chunk.
///
/// - Pushes reach the wire eagerly, so a duplex conversation can await reply chunks between pushes.
/// - [`close_with`](RequestSink::close_with) flags a known final chunk `last` and spends no extra record.
///
/// See [`crate::transport::multiplex::MuxHandle::open_stream`] and
/// [`crate::transport::multiplex::MuxHandle::open_duplex`].
pub struct RequestSink {
	stream: SinkStream,
	kind: MuxStreamKind,
	link: MuxLink,
	closed: bool,
	/// Grpc-style route stamped on the stream's Open, consumed when
	/// the first chunk opens the stream.
	target: Option<Urn<'static>>,
	/// Relay budget stamped beside the route on the stream's Open.
	hops_remaining: u8,
}

impl RequestSink {
	/// Sink over a reserved (unopened) stream. `target` and `hops_remaining`
	/// stamp the stream's Open with a grpc-style route.
	pub(crate) fn new(
		reservation: StreamReservation,
		kind: MuxStreamKind,
		link: MuxLink,
		target: Option<Urn<'static>>,
		hops_remaining: u8,
	) -> Self {
		Self {
			stream: SinkStream::Reserved(reservation),
			kind,
			link,
			closed: false,
			target,
			hops_remaining,
		}
	}

	/// Stream one request chunk to the peer, split to the peer's advertised
	/// receive size. An empty push returns `Ok` at once.
	///
	/// - Chunks go out eagerly, so a chunk-for-chunk duplex conversation can await replies between pushes.
	/// - The body still ends only at [`close`](Self::close) or
	///   [`close_with`](Self::close_with), so a unary response cannot resolve
	///   before the close.
	///
	/// # Errors
	///
	/// - `OperationFailed(Cancelled)` -- the stream resolved underneath the sink.
	/// - `OperationFailed(BudgetExhausted)` -- the budget cannot carry the chunk.
	/// - `ConnectionClosed` -- a driver of the connection ended.
	/// - `Draining` -- a GoAway ended admission before the first chunk opened the stream.
	pub async fn push(&mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		if payload.is_empty() {
			return Ok(());
		}

		self.send_payload(payload, false).await
	}

	/// Complete the request body with an empty `last`-flagged record.
	/// A sink closed without any push sends it as the stream's open
	/// (an empty request body).
	///
	/// When the call site knows the final chunk, prefer
	/// [`close_with`](Self::close_with): it flags the chunk itself
	/// and spends no extra record.
	///
	/// # Errors
	///
	/// - The errors of [`push`](Self::push).
	pub async fn close(mut self) -> TransportResult<()> {
		// The empty trailer is still one credit-gated record.
		if let SinkStream::Opened(stream_id) = self.stream {
			self.link.shared().add_send_records(stream_id, 1);
		}

		// The sink counts as closed only once the trailer reached
		// the writer queue: a failed or abandoned close still owes
		// the stream a cancel, which Drop settles.
		self.send_chunk(&[], true, 1).await?;
		self.closed = true;

		Ok(())
	}

	/// Stream the final request chunk with the `last` flag set, which
	/// completes the body in one step. An empty payload degrades to
	/// [`close`](Self::close).
	///
	/// # Errors
	///
	/// - The errors of [`push`](Self::push).
	pub async fn close_with(mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		if payload.is_empty() {
			return self.close().await;
		}

		// As in `close`, the sink counts as closed only once the flagged
		// chunk reached the writer queue, so a failure keeps the cancel of
		// Drop armed.
		self.send_payload(payload, true).await?;
		self.closed = true;

		Ok(())
	}

	/// Meter and send one payload, split to the peer's advertised
	/// receive size. The final wire chunk carries the `last` flag when
	/// this payload closes the body.
	async fn send_payload(&mut self, payload: impl AsRef<[u8]>, closes: bool) -> TransportResult<()> {
		let payload = payload.as_ref();
		let credits = self.link.shared().credits_for(payload.len());
		let standing = self.link.shared().admit_debit(credits, false).await?;

		// The open seeds the ledger with the payload's records. An
		// already-open stream extends it push by push.
		let records = self.link.shared().records_for(payload.len());
		if let SinkStream::Opened(stream_id) = self.stream {
			self.link.shared().add_send_records(stream_id, records);
		}

		let chunk_size = self.link.shared().send_chunk_size.get();
		let mut chunks = payload.chunks(chunk_size).peekable();
		while let Some(chunk) = chunks.next() {
			let last = closes && chunks.peek().is_none();
			self.send_chunk(chunk, last, records).await?;
		}

		if matches!(standing, BudgetStanding::Exhausting) {
			self.link.renew_or_drain().await?;
		}

		Ok(())
	}

	/// Send one wire record. The first chunk travels as the stream's
	/// `Open` through the atomic open, and every later chunk as `Data`.
	async fn send_chunk(&mut self, chunk: impl AsRef<[u8]>, last: bool, records: u64) -> TransportResult<()> {
		let chunk = chunk.as_ref();
		match &mut self.stream {
			SinkStream::Reserved(reservation) => {
				let mut request = OpenRequest {
					kind: self.kind,
					last,
					payload: chunk,
					records,
					target: self.target.take(),
					hops_remaining: self.hops_remaining,
				};

				let opened = self.link.send_open_envelope(reservation, &mut request).await;
				match opened {
					Ok(stream_id) => {
						self.stream = SinkStream::Opened(stream_id);
						Ok(())
					}
					Err(err) => {
						// A failed open leaves the sink reserved: hand back the
						// route the open did not consume. A retried first chunk
						// then still stamps it.
						self.target = request.target;
						Err(err)
					}
				}
			}
			SinkStream::Opened(stream_id) => {
				let stream_id = *stream_id;
				let envelope = TransportEnvelope::from(MuxDataPackage::new(stream_id, last, chunk)?);
				self.link.send_data_envelope(stream_id, envelope).await
			}
		}
	}
}

impl Drop for RequestSink {
	fn drop(&mut self) {
		if self.closed {
			return;
		}

		// For an unopened sink, the drop of the reservation cancels the
		// stream, unless an end of the connection resolved it first.
		if let SinkStream::Opened(stream_id) = self.stream {
			self.link.enqueue_stream_cancel(stream_id);
		}
	}
}

/// Producer half of a duplex stream. It pushes reply chunks on a
/// peer-initiated stream ahead of the closing trailer
/// (see [`crate::transport::multiplex::MuxResponder::serve_duplex`]).
///
/// Every push debits the session budget and parks on the peer's
/// stream credit as a reassembled response does.
pub struct ReplySink {
	stream_id: u32,
	link: MuxLink,
}

impl ReplySink {
	pub(crate) fn new(stream_id: u32, link: MuxLink) -> Self {
		// Streamed replies learn their length push by push.
		link.shared().register_send_stream(stream_id, 0);

		Self { stream_id, link }
	}

	/// Stream one reply chunk to the peer, split to the peer's advertised
	/// receive size. An empty push returns `Ok` at once.
	///
	/// # Errors
	///
	/// - `OperationFailed(Cancelled)` -- the peer cancelled the stream.
	/// - `ConnectionClosed` -- a driver of the connection ended.
	/// - `OperationFailed(BudgetExhausted)` -- the session budget cannot carry the chunk.
	pub async fn push(&mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		if payload.is_empty() {
			return Ok(());
		}

		let chunk_size = self.link.shared().send_chunk_size.get();
		// Reply pushes draw on the reserve like reassembled
		// responses, because owed traffic must flush through a drain.
		let credits = self.link.shared().credits_for(payload.len());
		let standing = self.link.shared().admit_debit(credits, true).await?;
		if matches!(standing, BudgetStanding::Exhausting) {
			self.link.drain_budget(credits).await?;
		}

		let records = self.link.shared().records_for(payload.len());
		self.link.shared().add_send_records(self.stream_id, records);

		for chunk in payload.chunks(chunk_size) {
			let envelope = TransportEnvelope::from(MuxDataPackage::new(self.stream_id, false, chunk)?);
			self.link.send_data_envelope(self.stream_id, envelope).await?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;
	use std::sync::Arc;

	use futures::channel::{mpsc, oneshot};

	use super::super::fixtures::{next_mux, poll_now, FIXTURE_PEER_CAP};
	use super::super::outbound::Outbound;
	use super::super::shared::{MuxShared, StreamOutcome};
	use super::*;
	use crate::constants::DEFAULT_HOP_BUDGET;
	use crate::transport::envelopes::{CancelReason, MuxEnvelope};
	use crate::transport::multiplex::{MuxRole, MuxSettings};
	use crate::transport::TransportError;

	/// Reserved (unopened) request sink on a fresh client with the
	/// given route, plus the outbound queue's receiving end and the
	/// response receiver.
	fn routed_sink_fixture(
		target: Option<Urn<'static>>,
	) -> (
		Arc<MuxShared>,
		RequestSink,
		mpsc::Receiver<Outbound>,
		oneshot::Receiver<StreamOutcome>,
	) {
		let shared = MuxShared::fixture(MuxRole::Client, &MuxSettings::symmetric(FIXTURE_PEER_CAP));
		let (link, sent, _notes) = MuxLink::over(Arc::clone(&shared), 8);
		let (sender, receiver) = oneshot::channel();
		let reservation = shared.reserve_stream_slot(sender).expect("fresh connection has stream slots");
		let sink = RequestSink::new(reservation, MuxStreamKind::Streaming, link, target, DEFAULT_HOP_BUDGET);

		(shared, sink, sent, receiver)
	}

	/// Unrouted variant of [`routed_sink_fixture`].
	fn sink_fixture() -> (
		Arc<MuxShared>,
		RequestSink,
		mpsc::Receiver<Outbound>,
		oneshot::Receiver<StreamOutcome>,
	) {
		routed_sink_fixture(None)
	}

	/// Pushes reach the wire eagerly. The bare close carries the `last` flag
	/// on an empty trailer record: push/push/close must travel as
	/// Open(!last), Data(!last), Data(last, empty).
	#[test]
	fn a_sink_pushes_eagerly_and_closes_with_an_empty_trailer() {
		let (_shared, mut sink, mut sent, _outcome) = sink_fixture();
		assert!(matches!(poll_now(sink.push([1u8, 1])), Poll::Ready(Ok(()))));
		assert!(matches!(
			next_mux(&mut sent),
			Some(MuxEnvelope::Open(package)) if !package.last() && package.payload() == [1u8, 1]
		));
		assert!(matches!(poll_now(sink.push([2u8, 2])), Poll::Ready(Ok(()))));
		assert!(matches!(
			next_mux(&mut sent),
			Some(MuxEnvelope::Data(package)) if !package.last() && package.payload() == [2u8, 2]
		));
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			next_mux(&mut sent),
			Some(MuxEnvelope::Data(package)) if package.last() && package.payload().is_empty()
		));
	}

	/// A known final chunk carries the `last` flag itself: no empty trailer
	/// follows it.
	#[test]
	fn a_close_with_a_final_chunk_flags_that_chunk() {
		let (_shared, mut sink, mut sent, _outcome) = sink_fixture();
		assert!(matches!(poll_now(sink.push([1u8, 1])), Poll::Ready(Ok(()))));

		let closed = poll_now(sink.close_with([2u8, 2]));
		assert!(matches!(closed, Poll::Ready(Ok(()))));
		assert!(matches!(
			next_mux(&mut sent),
			Some(MuxEnvelope::Open(package)) if !package.last() && package.payload() == [1u8, 1]
		));
		assert!(matches!(
			next_mux(&mut sent),
			Some(MuxEnvelope::Data(package)) if package.last() && package.payload() == [2u8, 2]
		));
		assert!(sent.try_recv().is_err());
	}

	/// An opened sink abandoned without close still owes the peer a cancel:
	/// its Open is on the wire.
	#[test]
	fn a_sink_dropped_after_its_open_cancels_the_stream() {
		let (_shared, mut sink, mut sent, mut receiver) = sink_fixture();
		assert!(matches!(poll_now(sink.push([1u8])), Poll::Ready(Ok(()))));
		assert!(matches!(next_mux(&mut sent), Some(MuxEnvelope::Open(_))));

		drop(sink);

		assert!(matches!(
			receiver.try_recv(),
			Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))
		));
		assert!(matches!(next_mux(&mut sent), Some(MuxEnvelope::Cancel(package)) if package.stream_id() == 1));
	}

	/// A sink dropped before any push never reached the wire: the
	/// reservation resolves the caller locally and releases the cap slot
	/// without a wire cancel.
	#[test]
	fn a_sink_dropped_before_its_open_releases_its_reservation_silently() {
		let (shared, sink, mut sent, mut receiver) = sink_fixture();

		drop(sink);

		assert!(matches!(
			receiver.try_recv(),
			Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))
		));
		assert!(sent.try_recv().is_err());
		assert!(shared.has_stream_headroom());
	}

	// A close that fails to reach the wire still owes the peer a cancel: Drop
	// must tear the stream down (resolving the caller's outcome), not treat
	// the failed close as complete. The flagged-final-chunk close keeps the
	// same contract.
	crate::tb_cases! {
		fn a_failed_close_still_cancels_the_stream(close: fn(RequestSink) -> Poll<TransportResult<()>>) {
			let (_shared, mut sink, sent, mut receiver) = sink_fixture();
			assert!(matches!(poll_now(sink.push([1u8])), Poll::Ready(Ok(()))));
			drop(sent);

			let closed = close(sink);
			assert!(matches!(closed, Poll::Ready(Err(TransportError::ConnectionClosed))));
			assert!(matches!(receiver.try_recv(), Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));
		}
		cases {
			close => |sink| poll_now(sink.close()),
			close_with_a_final_chunk => |sink| poll_now(sink.close_with([2u8, 2])),
		}
	}

	/// A failed open keeps the route on the sink, so a retried first chunk
	/// still opens routed.
	#[test]
	fn a_failed_open_keeps_the_route() {
		let target = crate::urn!("tb", "servlet:ledger");
		let (_shared, mut sink, sent, _outcome) = routed_sink_fixture(Some(target.clone()));
		drop(sent);

		let pushed = poll_now(sink.push([1u8]));
		assert!(matches!(pushed, Poll::Ready(Err(TransportError::ConnectionClosed))));
		assert_eq!(sink.target, Some(target));
	}

	/// An empty request body still travels: close without a push sends the
	/// stream's Open with the last flag and no payload.
	#[test]
	fn a_close_without_a_push_sends_an_empty_last_open() {
		let (_shared, sink, mut sent, _outcome) = sink_fixture();
		let closed = poll_now(sink.close());
		assert!(matches!(closed, Poll::Ready(Ok(()))));
		assert!(matches!(
			next_mux(&mut sent),
			Some(MuxEnvelope::Open(package)) if package.last() && package.payload().is_empty()
		));
	}
}
