//! Producer sinks: streamed request chunks (client side) and
//! streamed reply chunks (duplex responder side), sharing one
//! budget-metering rule.

use core::future::poll_fn;
use std::sync::Arc;

use futures::channel::mpsc;

use super::body::ForwardedStream;
use super::flow::{chunk_records, payload_credits};
use super::outbound::Outbound;
use super::shared::{enqueue_stream_cancel, BudgetStanding, MuxShared, OpenRequest, StreamReservation};
use super::writer::{drain_with_reason, renew_or_drain};
use crate::transport::envelopes::{GoAwayReason, MuxDataPackage, MuxStreamKind, TransportEnvelope};
use crate::transport::{TransportError, TransportResult};
use crate::utils::urn::Urn;

/// Send one credit-gated data chunk: reserve a writer-queue slot,
/// then take the stream credit and enqueue in one critical section
/// (see [`MuxShared::poll_send_enqueue`]). Fails once the stream's
/// ledger is gone (cancelled, resolved, or connection failure).
pub(super) async fn send_data_envelope(
	shared: &MuxShared,
	outbound: &mut mpsc::Sender<Outbound>,
	stream_id: u32,
	envelope: TransportEnvelope,
) -> TransportResult<()> {
	let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
	if ready.is_err() {
		return Err(TransportError::ConnectionClosed);
	}

	let mut slot = Some(envelope);
	poll_fn(|cx| shared.poll_send_enqueue(stream_id, outbound, &mut slot, cx)).await
}

/// Send a stream's Open record through the atomic open (see
/// [`MuxShared::poll_open_enqueue`]): reserve a writer-queue slot,
/// then assign the stream ID and enqueue in one critical section so
/// Opens hit the wire in ID order.
pub(super) async fn send_open_envelope(
	shared: &MuxShared,
	outbound: &mut mpsc::Sender<Outbound>,
	reservation: &mut StreamReservation,
	request: &mut OpenRequest<'_>,
) -> TransportResult<u32> {
	let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
	if ready.is_err() {
		return Err(TransportError::ConnectionClosed);
	}

	poll_fn(|cx| shared.poll_open_enqueue(reservation, request, outbound, cx)).await
}

/// Meter one pushed payload: debit the session budget and account
/// the payload's records on the stream's sender ledger. The one
/// budget rule both streaming sinks share.
async fn debit_push(
	shared: &MuxShared,
	stream_id: u32,
	payload_len: usize,
	reserved: bool,
) -> TransportResult<BudgetStanding> {
	let credits = payload_credits(payload_len, shared.send_chunk_size, shared.credit_unit);
	let standing = shared.admit_debit(credits, reserved).await?;
	shared.add_send_records(stream_id, chunk_records(payload_len, shared.send_chunk_size));

	Ok(standing)
}

/// Wire state of a streamed request: a held cap slot until the
/// first record goes out, the assigned stream ID afterwards.
enum SinkStream {
	/// No Open sent yet: the reservation holds the cap slot and the
	/// forwarder (duplex only) waits for the assigned ID.
	Reserved {
		reservation: StreamReservation,
		duplex: Option<ForwardedStream>,
	},
	Opened(u32),
}

/// Producer half of a streamed request: pushes chunks on a
/// locally-initiated stream, closed by flagging the final chunk
/// `last` (see [`crate::transport::multiplex::MuxHandle::open_stream`] and [`crate::transport::multiplex::MuxHandle::open_duplex`]).
///
/// Pushes reach the wire eagerly, so a duplex conversation can await
/// reply chunks between pushes. [`close_with`](RequestSink::close_with)
/// carries a known final chunk on the `last` record for free.
pub struct RequestSink {
	stream: SinkStream,
	kind: MuxStreamKind,
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	closed: bool,
	/// Grpc-style route stamped on the stream's Open, consumed when
	/// the first chunk opens the stream.
	target: Option<Urn<'static>>,
	/// Relay budget stamped beside the route on the stream's Open.
	hops_remaining: u8,
}

impl RequestSink {
	/// Sink over a reserved (unopened) stream. `duplex` carries the
	/// reply forwarder to register once the ID exists. `target` and
	/// `hops_remaining` stamp the stream's Open with a grpc-style route.
	pub(super) fn new(
		reservation: StreamReservation,
		kind: MuxStreamKind,
		shared: Arc<MuxShared>,
		outbound: mpsc::Sender<Outbound>,
		duplex: Option<ForwardedStream>,
		target: Option<Urn<'static>>,
		hops_remaining: u8,
	) -> Self {
		Self {
			stream: SinkStream::Reserved { reservation, duplex },
			kind,
			shared,
			outbound,
			closed: false,
			target,
			hops_remaining,
		}
	}

	/// Stream one request chunk to the peer, splitting to the peer's
	/// advertised receive size. Empty pushes send nothing.
	///
	/// Chunks go out eagerly: on a duplex stream, awaiting reply
	/// chunks between pushes (a chunk-for-chunk conversation) is
	/// sound. The body still ends only at [`close`](Self::close) /
	/// [`close_with`](Self::close_with), so a unary response cannot
	/// resolve before the close.
	///
	/// # Errors
	/// - `OperationFailed(Cancelled)`: the stream resolved underneath the sink
	/// - `OperationFailed(BudgetExhausted)`: the budget cannot carry the chunk
	/// - `ConnectionClosed`: writer driver gone
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
	/// When the final chunk is known at the call site, prefer
	/// [`close_with`](Self::close_with): it flags the chunk itself
	/// and spends no extra record.
	///
	/// # Errors
	/// Same set as [`push`](Self::push).
	pub async fn close(mut self) -> TransportResult<()> {
		// The empty trailer is still one credit-gated record
		if let SinkStream::Opened(stream_id) = self.stream {
			self.shared.add_send_records(stream_id, 1);
		}

		// The sink counts as closed only once the trailer reached
		// the writer queue: a failed or abandoned close still owes
		// the stream a cancel, which Drop settles.
		self.send_chunk(&[], true, 1).await?;
		self.closed = true;

		Ok(())
	}

	/// Stream the final request chunk with the `last` flag set,
	/// completing the body in one step. An empty payload degrades to
	/// [`close`](Self::close).
	///
	/// # Errors
	/// Same set as [`push`](Self::push).
	pub async fn close_with(mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		if payload.is_empty() {
			return self.close().await;
		}

		// Closed only after the flagged chunk reached the writer
		// queue (see close): failure keeps Drop's cancel armed.
		self.send_payload(payload, true).await?;
		self.closed = true;

		Ok(())
	}

	/// Meter and send one payload, split to the peer's advertised
	/// receive size, flagging the final wire chunk `last` when this
	/// payload closes the body.
	async fn send_payload(&mut self, payload: &[u8], closes: bool) -> TransportResult<()> {
		let credits = payload_credits(payload.len(), self.shared.send_chunk_size, self.shared.credit_unit);
		let standing = self.shared.admit_debit(credits, false).await?;

		// The open seeds the ledger with the payload's records. An
		// already-open stream extends it push by push.
		let records = chunk_records(payload.len(), self.shared.send_chunk_size);
		if let SinkStream::Opened(stream_id) = self.stream {
			self.shared.add_send_records(stream_id, records);
		}

		let chunk_size = self.shared.send_chunk_size;
		let mut chunks = payload.chunks(chunk_size).peekable();
		while let Some(chunk) = chunks.next() {
			let last = closes && chunks.peek().is_none();
			self.send_chunk(chunk, last, records).await?;
		}

		if matches!(standing, BudgetStanding::Exhausting) {
			renew_or_drain(&self.shared, &self.outbound).await?;
		}

		Ok(())
	}

	/// One wire record: the first chunk travels as the stream's
	/// `Open` through the atomic open, every later chunk as `Data`.
	async fn send_chunk(&mut self, chunk: &[u8], last: bool, records: u64) -> TransportResult<()> {
		match &mut self.stream {
			SinkStream::Reserved { reservation, duplex } => {
				let mut request = OpenRequest {
					kind: self.kind,
					last,
					payload: chunk,
					records,
					duplex: duplex.take(),
					target: self.target.take(),
					hops_remaining: self.hops_remaining,
				};

				let opened = send_open_envelope(&self.shared, &mut self.outbound, reservation, &mut request).await;
				match opened {
					Ok(stream_id) => {
						self.stream = SinkStream::Opened(stream_id);
						Ok(())
					}
					Err(err) => {
						// A failed open leaves the sink reserved: hand back
						// whatever the open did not consume. A retried
						// first chunk then still stamps the route and
						// registers the reply forwarder.
						self.target = request.target;
						*duplex = request.duplex;
						Err(err)
					}
				}
			}
			SinkStream::Opened(stream_id) => {
				let stream_id = *stream_id;
				let envelope = TransportEnvelope::from(MuxDataPackage::new(stream_id, last, chunk)?);
				send_data_envelope(&self.shared, &mut self.outbound, stream_id, envelope).await
			}
		}
	}
}

impl Drop for RequestSink {
	fn drop(&mut self) {
		if self.closed {
			return;
		}

		// Unopened: the reservation's own drop releases the cap slot
		// and resolves the caller locally.
		if let SinkStream::Opened(stream_id) = self.stream {
			enqueue_stream_cancel(&self.shared, &self.outbound, stream_id);
		}
	}
}

/// Producer half of a duplex stream: pushes reply chunks on a
/// peer-initiated stream ahead of the closing trailer
/// (see [`crate::transport::multiplex::MuxResponder::serve_duplex`]).
///
/// Every push debits the session budget and parks on the peer's
/// stream credit exactly like a reassembled response.
pub struct ReplySink {
	stream_id: u32,
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
}

impl ReplySink {
	pub(super) fn new(stream_id: u32, shared: Arc<MuxShared>, outbound: mpsc::Sender<Outbound>) -> Self {
		// Streamed replies learn their length push by push
		shared.register_send_stream(stream_id, 0);

		Self { stream_id, shared, outbound }
	}

	/// Stream one reply chunk to the peer, splitting to the peer's
	/// advertised receive size. Empty pushes send nothing.
	///
	/// # Errors
	/// - `OperationFailed(Cancelled)`: peer cancelled the stream
	/// - `ConnectionClosed`: writer driver gone
	/// - `OperationFailed(BudgetExhausted)`: the session budget
	///   cannot carry the chunk
	pub async fn push(&mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		if payload.is_empty() {
			return Ok(());
		}

		let chunk_size = self.shared.send_chunk_size;
		// Reply pushes draw on the reserve like reassembled
		// responses: owed traffic must flush through a drain
		let standing = debit_push(&self.shared, self.stream_id, payload.len(), true).await?;
		if matches!(standing, BudgetStanding::Exhausting) {
			drain_with_reason(&self.shared, &self.outbound, GoAwayReason::BudgetExhausted).await?;
		}

		for chunk in payload.chunks(chunk_size) {
			let envelope = TransportEnvelope::from(MuxDataPackage::new(self.stream_id, false, chunk)?);
			send_data_envelope(&self.shared, &mut self.outbound, self.stream_id, envelope).await?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;

	use futures::channel::oneshot;

	use super::super::shared::StreamOutcome;
	use super::super::testing::{client_shared, poll_now};
	use super::*;
	use crate::constants::DEFAULT_HOP_BUDGET;
	use crate::transport::envelopes::{CancelReason, MuxEnvelope};

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
		let shared = client_shared();
		let (outbound, sent) = mpsc::channel(8);
		let (sender, receiver) = oneshot::channel();
		let reservation = shared.reserve_stream_slot(sender).expect("fresh connection has stream slots");

		let sink = RequestSink::new(
			reservation,
			MuxStreamKind::Streaming,
			Arc::clone(&shared),
			outbound,
			None,
			target,
			DEFAULT_HOP_BUDGET,
		);
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

	// Pushes reach the wire eagerly. The bare close carries the
	// `last` flag on an empty trailer record: push/push/close must
	// travel as Open(!last), Data(!last), Data(last, empty).
	#[test]
	fn test_request_sink_pushes_eagerly_and_closes_with_empty_trailer() {
		let (_shared, mut sink, mut sent, _outcome) = sink_fixture();

		assert!(matches!(poll_now(sink.push([1u8, 1])), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if !package.last() && package.payload() == [1u8, 1]
		));

		assert!(matches!(poll_now(sink.push([2u8, 2])), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Data(package))))
				if !package.last() && package.payload() == [2u8, 2]
		));

		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Data(package))))
				if package.last() && package.payload().is_empty()
		));
	}

	// A known final chunk carries the `last` flag itself: no empty
	// trailer follows it.
	#[test]
	fn test_request_sink_close_with_flags_final_chunk() {
		let (_shared, mut sink, mut sent, _outcome) = sink_fixture();

		assert!(matches!(poll_now(sink.push([1u8, 1])), Poll::Ready(Ok(()))));
		assert!(matches!(poll_now(sink.close_with([2u8, 2])), Poll::Ready(Ok(()))));

		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if !package.last() && package.payload() == [1u8, 1]
		));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Data(package))))
				if package.last() && package.payload() == [2u8, 2]
		));
		assert!(sent.try_recv().is_err());
	}

	// An opened sink abandoned without close still owes the peer a
	// cancel: its Open is on the wire.
	#[test]
	fn test_request_sink_drop_after_open_cancels_stream() {
		let (_shared, mut sink, mut sent, mut receiver) = sink_fixture();

		let pushed = poll_now(sink.push([1u8]));
		assert!(matches!(pushed, Poll::Ready(Ok(()))));

		let open = sent.try_recv();
		assert!(matches!(
			open,
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(_))))
		));

		drop(sink);

		let outcome = receiver.try_recv();
		assert!(matches!(outcome, Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));

		let cancel = sent.try_recv();
		assert!(matches!(
			cancel,
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Cancel(package))))
				if package.stream_id() == 1
		));
	}

	// A sink dropped before any push never reached the wire: the
	// reservation resolves the caller locally and releases the cap
	// slot without a wire cancel.
	#[test]
	fn test_request_sink_drop_unopened_releases_reservation_silently() {
		let (shared, sink, mut sent, mut receiver) = sink_fixture();

		drop(sink);

		let outcome = receiver.try_recv();
		assert!(matches!(outcome, Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));
		assert!(sent.try_recv().is_err());
		assert!(shared.has_stream_headroom());
	}

	// A close that fails to reach the wire still owes the peer a
	// cancel: Drop must tear the stream down (resolving the caller's
	// outcome), not treat the failed close as complete.
	#[test]
	fn test_request_sink_failed_close_still_cancels_stream() {
		let (_shared, mut sink, sent, mut receiver) = sink_fixture();

		let pushed = poll_now(sink.push([1u8]));
		assert!(matches!(pushed, Poll::Ready(Ok(()))));
		drop(sent);

		let closed = poll_now(sink.close());
		assert!(matches!(closed, Poll::Ready(Err(TransportError::ConnectionClosed))));

		let outcome = receiver.try_recv();
		assert!(matches!(outcome, Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));
	}

	// Same contract for the flagged-final-chunk close.
	#[test]
	fn test_request_sink_failed_close_with_still_cancels_stream() {
		let (_shared, mut sink, sent, mut receiver) = sink_fixture();

		let pushed = poll_now(sink.push([1u8]));
		assert!(matches!(pushed, Poll::Ready(Ok(()))));

		drop(sent);

		let closed = poll_now(sink.close_with([2u8, 2]));
		assert!(matches!(closed, Poll::Ready(Err(TransportError::ConnectionClosed))));

		let outcome = receiver.try_recv();
		assert!(matches!(outcome, Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));
	}

	// A failed open must not strip the route: the target stays on
	// the sink so a retried first chunk still opens routed.
	#[test]
	fn test_request_sink_failed_open_keeps_route() {
		let (_shared, mut sink, sent, _outcome) = routed_sink_fixture(Some(Urn::new("tb", "servlet:ledger")));

		drop(sent);

		let pushed = poll_now(sink.push([1u8]));
		assert!(matches!(pushed, Poll::Ready(Err(TransportError::ConnectionClosed))));
		assert!(sink.target.is_some());
	}

	// An empty request body still travels: close without a push
	// sends the stream's Open with the last flag and no payload.
	#[test]
	fn test_request_sink_close_without_push_sends_empty_last_open() {
		let (_shared, sink, mut sent, _outcome) = sink_fixture();
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if package.last() && package.payload().is_empty()
		));
	}
}
