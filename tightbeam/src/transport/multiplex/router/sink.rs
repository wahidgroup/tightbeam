//! Producer sinks: streamed request chunks (client side) and
//! streamed reply chunks (duplex responder side), sharing one
//! budget-metering rule.

use core::future::poll_fn;
use std::sync::Arc;

use futures::channel::mpsc;

use super::flow::{chunk_records, payload_credits};
use super::outbound::Outbound;
use super::shared::{enqueue_stream_cancel, BudgetStanding, MuxShared};
use super::writer::{drain_with_reason, renew_or_drain};
use crate::transport::envelopes::{GoAwayReason, MuxDataPackage, MuxOpenPackage, MuxStreamKind, TransportEnvelope};
use crate::transport::{TransportError, TransportResult};

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

/// Producer half of a streamed request: pushes chunks on a
/// locally-initiated stream, closed by flagging the final chunk
/// `last` (see [`MuxHandle::open_stream`] and [`MuxHandle::open_duplex`]).
///
/// Pushes reach the wire eagerly, so a duplex conversation can await
/// reply chunks between pushes. [`close_with`](RequestSink::close_with)
/// carries a known final chunk on the `last` record for free;
/// [`close`](RequestSink::close) spends one extra empty record when the
/// end is only known after the fact. Dropping the sink without closing
/// cancels the stream.
pub struct RequestSink {
	stream_id: u32,
	kind: MuxStreamKind,
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	opened: bool,
	closed: bool,
}

impl RequestSink {
	pub(super) fn new(
		stream_id: u32,
		kind: MuxStreamKind,
		shared: Arc<MuxShared>,
		outbound: mpsc::Sender<Outbound>,
	) -> Self {
		Self { stream_id, kind, shared, outbound, opened: false, closed: false }
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
		self.closed = true;
		// The empty trailer is still one credit-gated record
		self.shared.add_send_records(self.stream_id, 1);
		self.send_chunk(&[], true).await
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

		self.closed = true;
		self.send_payload(payload, true).await
	}

	/// Meter and send one payload, split to the peer's advertised
	/// receive size, flagging the final wire chunk `last` when this
	/// payload closes the body.
	async fn send_payload(&mut self, payload: &[u8], closes: bool) -> TransportResult<()> {
		let standing = debit_push(&self.shared, self.stream_id, payload.len(), false).await?;

		let chunk_size = self.shared.send_chunk_size;
		let mut chunks = payload.chunks(chunk_size).peekable();
		while let Some(chunk) = chunks.next() {
			let last = closes && chunks.peek().is_none();
			self.send_chunk(chunk, last).await?;
		}

		if matches!(standing, BudgetStanding::Exhausting) {
			renew_or_drain(&self.shared, &self.outbound).await?;
		}

		Ok(())
	}

	/// One wire record: the first chunk travels as the stream's
	/// `Open`, every later chunk as `Data`.
	async fn send_chunk(&mut self, chunk: &[u8], last: bool) -> TransportResult<()> {
		let envelope = if self.opened {
			TransportEnvelope::from(MuxDataPackage::new(self.stream_id, last, chunk)?)
		} else {
			TransportEnvelope::from(MuxOpenPackage::new(self.stream_id, last, self.kind, chunk)?)
		};

		self.opened = true;

		send_data_envelope(&self.shared, &mut self.outbound, self.stream_id, envelope).await
	}
}

impl Drop for RequestSink {
	fn drop(&mut self) {
		if self.closed {
			return;
		}

		enqueue_stream_cancel(&self.shared, &self.outbound, self.stream_id);
	}
}

/// Producer half of a duplex stream: pushes reply chunks on a
/// peer-initiated stream ahead of the closing trailer
/// (see [`MuxResponder::serve_duplex`]).
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
	/// advertised receive size. Empty pushes send nothing (the wire
	/// carries no empty data records).
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
	use crate::transport::envelopes::{CancelReason, MuxEnvelope};

	/// Registered request sink on stream 1 of a fresh client, with
	/// the outbound queue's receiving end.
	fn sink_fixture() -> (Arc<MuxShared>, RequestSink, mpsc::Receiver<Outbound>) {
		let shared = client_shared();
		let (outbound, sent) = mpsc::channel(8);

		shared.register_send_stream(1, 0);

		let sink = RequestSink::new(1, MuxStreamKind::Streaming, Arc::clone(&shared), outbound);
		(shared, sink, sent)
	}

	// Pushes reach the wire eagerly; the bare close carries the
	// `last` flag on an empty trailer record: push/push/close must
	// travel as Open(!last), Data(!last), Data(last, empty).
	#[test]
	fn test_request_sink_pushes_eagerly_and_closes_with_empty_trailer() {
		let (_shared, mut sink, mut sent) = sink_fixture();

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

	// A known final chunk rides the `last` record itself: no empty
	// trailer follows it.
	#[test]
	fn test_request_sink_close_with_flags_final_chunk() {
		let (_shared, mut sink, mut sent) = sink_fixture();

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

	#[test]
	fn test_request_sink_drop_cancels_stream() {
		let shared = client_shared();
		let (outbound, mut sent) = mpsc::channel(8);
		let (sender, mut receiver) = oneshot::channel();
		let stream_id = shared.allocate(sender).expect("fresh connection has stream slots");

		shared.register_send_stream(stream_id, 0);

		drop(RequestSink::new(
			stream_id,
			MuxStreamKind::Streaming,
			Arc::clone(&shared),
			outbound,
		));

		let outcome = receiver.try_recv();
		assert!(matches!(outcome, Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Cancel(package))))
				if package.stream_id() == stream_id
		));
	}

	// An empty request body still travels: close without a push
	// sends the stream's Open with the last flag and no payload.
	#[test]
	fn test_request_sink_close_without_push_sends_empty_last_open() {
		let (_shared, sink, mut sent) = sink_fixture();

		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if package.last() && package.payload().is_empty()
		));
	}
}
