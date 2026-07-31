//! Client handle: stream emission, streaming opens, pings, and the
//! drop guards that reclaim abandoned in-flight work.

use core::future::Future;
use std::sync::Arc;

use futures::channel::{mpsc, oneshot};
use futures::SinkExt;

use super::body::{stream_body, DrainNote, StreamBody};
use super::flow::{chunk_records, payload_credits};
use super::outbound::{outbound_handle, Outbound};
use super::shared::{
	cancel_error, enqueue_stream_cancel, BudgetStanding, MuxShared, OpenRequest, OpenSlot, StreamOutcome,
	StreamReservation,
};
use super::sink::{send_data_envelope, send_open_envelope, RequestSink};
use super::writer::{drain_with_reason, renew_or_drain};
use crate::der::Encode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{
	GoAwayReason, MuxDataPackage, MuxPingPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::error::TransportFailure;
use crate::transport::multiplex::{MultiplexedProtocol, StreamingProtocol};
use crate::transport::{TransportError, TransportResult};
use crate::utils::marker::MaybeSend;
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::StoredReceipt;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "transport-policy")]
use crate::transport::GateAudit;

/// Cancels the stream if the owning emit future is dropped before its
/// response arrives: frees the cap slot and notifies the peer (best-effort,
/// [RFC 9113 § 6.4](https://datatracker.ietf.org/doc/html/rfc9113#section-6.4)).
///
/// The stream's ID is read through its [`OpenSlot`] at drop time: a
/// guard dropped before the Open ever went out stands down on its
/// own (nothing on the wire, the reservation releases the cap slot).
pub(super) struct CancelOnDrop {
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	slot: Arc<OpenSlot>,
	armed: bool,
}

impl CancelOnDrop {
	/// Armed guard over a stream identified by `slot`.
	fn new(shared: &Arc<MuxShared>, outbound: &mpsc::Sender<Outbound>, slot: Arc<OpenSlot>) -> Self {
		Self {
			shared: Arc::clone(shared),
			outbound: outbound_handle(outbound),
			slot,
			armed: true,
		}
	}

	pub(super) fn disarm(&mut self) {
		self.armed = false;
	}
}

impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}

		if let Some(stream_id) = self.slot.get() {
			enqueue_stream_cancel(&self.shared, &self.outbound, stream_id);
		}
	}
}

/// Forgets the pending ping if the owning ping future is dropped
/// before its ack arrives. A later ack resolves nothing (discarded
/// like a stale response), so no peer notification is needed.
struct ForgetPingOnDrop {
	shared: Arc<MuxShared>,
	opaque: u64,
	armed: bool,
}

impl ForgetPingOnDrop {
	fn disarm(&mut self) {
		self.armed = false;
	}
}

impl Drop for ForgetPingOnDrop {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}

		self.shared.remove_pending_ping(self.opaque);
	}
}

/// Prefer moving the frame out of the Arc; deep-copy only when the
/// inbound path still holds a shared reference (dual ownership).
fn unwrap_frame(frame: Arc<Frame>) -> Frame {
	Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone())
}

fn resolve_response(response: ResponsePackage) -> TransportResult<Option<Frame>> {
	match response.status() {
		TransitStatus::Ok => Ok(response.message.map(unwrap_frame)),
		status => Err(TransportError::from(status)),
	}
}

/// Map a pending stream's delivered outcome (or its dropped slot)
/// to the caller-facing result.
fn resolve_outcome(outcome: Result<StreamOutcome, oneshot::Canceled>) -> TransportResult<Option<Frame>> {
	match outcome {
		Ok(StreamOutcome::Response(response)) => resolve_response(response),
		Ok(StreamOutcome::Cancelled(reason)) => Err(cancel_error(reason)),
		Ok(StreamOutcome::Draining) => Err(TransportError::Draining),
		Err(_) => Err(TransportError::ConnectionClosed),
	}
}

/// Cloneable client handle for a multiplexed connection.
///
/// Shares pending-stream state and the outbound queue across clones
/// (`Arc` + channel refcount bumps only). Does not drive I/O: spawn
/// [`crate::transport::multiplex::MuxReaderDriver`] and [`crate::transport::multiplex::MuxWriterDriver`] on the caller's executor.
/// See [`MuxHandle::emit_on_stream`] and [`MuxHandle::ping`].
#[derive(Clone)]
pub struct MuxHandle {
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	/// Consumption reports from duplex reply bodies back to the
	/// reader's credit replenishment
	drain_feedback: mpsc::UnboundedSender<DrainNote>,
}

// Audit source for gate verdicts on the mux plane: the responder
// gates requests through `gate_inbound`, which records the
// verdict into this connection's collector.
#[cfg(feature = "transport-policy")]
impl GateAudit for MuxHandle {
	#[cfg(feature = "instrument")]
	fn audit_trace(&self) -> Option<&TraceCollector> {
		self.shared.trace.as_ref()
	}
}

impl MuxHandle {
	/// Assemble a handle over the connection's shared state and
	/// queues (refcount bumps only, no data copies).
	pub(super) fn new(
		shared: Arc<MuxShared>,
		outbound: mpsc::Sender<Outbound>,
		drain_feedback: mpsc::UnboundedSender<DrainNote>,
	) -> Self {
		Self { shared, outbound, drain_feedback }
	}

	/// Send a request on a freshly allocated stream and await its
	/// response. Frames beyond the peer's advertised chunk size are
	/// segmented into `Open(first) Data(...)* Data(last)`, each chunk
	/// gated by the peer's stream credit.
	///
	/// Dropping the returned future before it resolves cancels the
	/// stream: the pending entry is removed, the cap slot freed, and a
	/// best-effort [`crate::transport::envelopes::MuxCancelPackage`] sent. Per-stream timeouts
	/// compose by wrapping this future in the caller's timer.
	///
	/// # Errors
	/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
	/// - `OperationFailed(BudgetExhausted)`: the outbound budget cannot cover frame
	/// - `OperationFailed(ResourceExhausted)`: the peer refused the stream
	/// - `Draining`: GoAway sent or received. No new streams
	/// - `ConnectionClosed`: connection failed before the response
	pub async fn emit_on_stream(&self, frame: &Frame) -> TransportResult<Option<Frame>> {
		// Encode before reserving so an encoding failure never burns
		// a cap slot or queues work for a stream the peer never saw.
		let payload = frame.to_der()?;
		let credits = payload_credits(payload.len(), self.shared.send_chunk_size, self.shared.credit_unit);

		let (sender, receiver) = oneshot::channel();
		// The reservation holds the cap slot until the Open goes out
		// and releases it if this future is dropped waiting out a
		// renewal: no ID exists yet, so nothing needs cancelling
		let mut reservation = self.shared.reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		let standing = self.shared.admit_debit(credits, false).await?;

		let total = chunk_records(payload.len(), self.shared.send_chunk_size);
		let mut guard = CancelOnDrop::new(&self.shared, &self.outbound, Arc::clone(&slot));

		match self.send_request_chunks(&mut reservation, &payload, total).await {
			Ok(()) => {}
			// Ledger removed mid-send: the stream resolved underneath
			// the sender and the outcome channel carries the truth
			Err(TransportError::OperationFailed(TransportFailure::Cancelled)) => {}
			Err(err) => return Err(err),
		}

		if matches!(standing, BudgetStanding::Exhausting) {
			renew_or_drain(&self.shared, &self.outbound).await?;
		}

		let outcome = receiver.await;

		guard.disarm();
		if let Some(stream_id) = slot.get() {
			self.shared.finish_send_stream(stream_id);
		}

		resolve_outcome(outcome)
	}

	/// Open a streaming request: push chunks through the returned
	/// [`RequestSink`], then await the returned response future.
	///
	/// Every push debits the session budget and parks on the peer's
	/// stream credit exactly like [`emit_on_stream`](Self::emit_on_stream)
	/// chunks. Streamed requests are metered and paid, not a side
	/// channel. Dropping the sink before [`RequestSink::close`], or
	/// the response future before it resolves, cancels the stream.
	///
	/// # Errors
	/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
	/// - `Draining`: GoAway sent or received. No new streams
	pub fn open_stream(
		&self,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		let (sender, receiver) = oneshot::channel();
		let reservation = self.shared.reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		let sink = RequestSink::new(
			reservation,
			MuxStreamKind::Streaming,
			Arc::clone(&self.shared),
			outbound_handle(&self.outbound),
			None,
		);

		let shared = Arc::clone(&self.shared);
		let outbound = outbound_handle(&self.outbound);
		let response = async move {
			let mut guard = CancelOnDrop::new(&shared, &outbound, Arc::clone(&slot));
			let outcome = receiver.await;

			guard.disarm();
			if let Some(stream_id) = slot.get() {
				shared.finish_send_stream(stream_id);
			}

			resolve_outcome(outcome)
		};

		Ok((sink, response))
	}

	/// Open a duplex stream: push request chunks through the
	/// returned [`RequestSink`] while consuming the streamed reply
	/// from the returned [`StreamBody`] - both directions flow
	/// concurrently on one stream.
	///
	/// Pushes reach the wire eagerly (see [`RequestSink::push`]), so
	/// a push-one-await-one conversation with the handler is sound.
	/// The reply's pace stays the handler's choice: only its trailer
	/// is guaranteed, so an exchange that must not park awaits reply
	/// chunks it knows the handler sends.
	///
	/// The reply ends with the responder's trailer: `Ok(None)` on an
	/// Ok status, otherwise the status mapped to its transport error.
	/// Consuming reply chunks replenishes the peer's stream credit,
	/// so a slow reader parks the responder (end-to-end backpressure).
	/// Dropping the sink before [`RequestSink::close`], or the reply
	/// body before its terminal event, cancels the stream.
	///
	/// # Errors
	/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
	/// - `Draining`: GoAway sent or received. No new streams
	pub fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)> {
		let (sender, receiver) = oneshot::channel();
		let reservation = self.shared.reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		// The reply travels through the body, not the outcome slot:
		// the pending entry only holds the stream's cap slot
		drop(receiver);

		// The forwarder rides the reservation into the sink and
		// registers under the assigned ID at first push, before the
		// Open can reach the peer
		let (mut body, forwarder) =
			stream_body(Arc::clone(&slot), self.shared.initial_recv_credit, self.drain_feedback.clone());

		// An abandoned reply must reclaim its cap slot: without the
		// guard, a closed-sink duplex stream has no cancel path and
		// the slot stays pinned until the peer's trailer
		body.arm_guard(CancelOnDrop::new(&self.shared, &self.outbound, slot));

		let sink = RequestSink::new(
			reservation,
			MuxStreamKind::Duplex,
			Arc::clone(&self.shared),
			outbound_handle(&self.outbound),
			Some(forwarder),
		);
		Ok((sink, body))
	}

	/// Segment a request payload into the initiator grammar, one
	/// credit-gated chunk per record. The first chunk travels through
	/// the atomic open (assigning the stream ID and seeding the
	/// ledger with `total` records), the rest as `Data`.
	async fn send_request_chunks(
		&self,
		reservation: &mut StreamReservation,
		payload: &[u8],
		total: u64,
	) -> TransportResult<()> {
		let chunk_size = self.shared.send_chunk_size;
		let mut outbound = outbound_handle(&self.outbound);
		let mut chunks = payload.chunks(chunk_size);
		let mut sent: u64 = 0;
		let first = chunks.next().unwrap_or(&[]);

		sent += 1;
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: sent == total,
			payload: first,
			records: total,
			duplex: None,
		};

		let stream_id = send_open_envelope(&self.shared, &mut outbound, reservation, &mut request).await?;
		for chunk in chunks {
			sent += 1;

			let data = MuxDataPackage::new(stream_id, sent == total, chunk)?;
			let data_envelope = TransportEnvelope::from(data);
			send_data_envelope(&self.shared, &mut outbound, stream_id, data_envelope).await?;
		}

		Ok(())
	}

	/// Whether a new locally-initiated stream would be admitted now: cap
	/// headroom, live ID space, and no GoAway either way.
	///
	/// Advisory: a concurrent emit can take the last slot after this
	/// returns, so callers still handle `StreamsExhausted`.
	pub fn has_stream_headroom(&self) -> bool {
		self.shared.has_stream_headroom()
	}

	/// Whether any locally-initiated stream is still awaiting its response.
	///
	/// Callers with a clock use this to pin a connection as active while
	/// streams are in flight (see pool `last_used` stamping).
	pub fn has_pending_streams(&self) -> bool {
		self.shared.has_pending_streams()
	}

	/// Reason carried by the peer's GoAway, or `None` while the
	/// connection is live or was shut down locally.
	///
	/// Reconnect policies branch on this: `Shutdown` invites an
	/// immediate reconnect, `EnhanceYourCalm` calls for backoff, and
	/// `ProtocolError` points at a bug rather than a transient fault.
	pub fn goaway_reason(&self) -> Option<GoAwayReason> {
		self.shared.goaway_reason()
	}

	/// Current epoch's dual-signed session receipt, rotated in
	/// place by each completed in-band renewal. `None` on sessions
	/// without receipt-bearing rekey materials.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
		self.shared.session_receipt()
	}

	/// Resolve once a locally-initiated stream would be admitted:
	/// cap headroom, live ID space, and no GoAway either way.
	///
	/// Replaces polling [`MuxHandle::has_stream_headroom`] in a loop.
	/// Advisory like the getter: a concurrent emit can take the slot
	/// between wake and use, so callers still handle `StreamsExhausted`.
	///
	/// # Errors
	/// - `Draining`: GoAway sent or received, or stream IDs exhausted.
	pub fn wait_for_stream_slot(&self) -> impl Future<Output = TransportResult<()>> + MaybeSend {
		self.shared.stream_slot()
	}

	/// Connection-level liveness probe
	/// ([RFC 9113 § 6.7](https://datatracker.ietf.org/doc/html/rfc9113#section-6.7)):
	/// resolves when the peer's ack arrives.
	///
	/// No stream is allocated and the peer's application handler never runs,
	/// so this doubles as an idle keepalive for links whose carrier cannot
	/// ping itself.
	///
	/// # Errors
	/// - `Draining`: GoAway sent or received. The connection is ending
	/// - `ConnectionClosed`: connection failed before the ack
	pub async fn ping(&self) -> TransportResult<()> {
		let (sender, receiver) = oneshot::channel();
		let opaque = self.shared.allocate_ping(sender)?;
		let shared = Arc::clone(&self.shared);
		let mut guard = ForgetPingOnDrop { shared, opaque, armed: true };

		let probe = MuxPingPackage::new(false, opaque);
		let mut outbound = outbound_handle(&self.outbound);
		outbound
			.send(Outbound::Envelope(probe.into()))
			.await
			.map_err(|_| TransportError::ConnectionClosed)?;

		let outcome = receiver.await;

		guard.disarm();

		outcome.map_err(|_| TransportError::ConnectionClosed)?;

		Ok(())
	}

	/// Gracefully shut the connection down
	/// ([RFC 9113 § 6.8](https://datatracker.ietf.org/doc/html/rfc9113#section-6.8)):
	/// sends GoAway, halts the allocator, awaits pending-table drain, then
	/// closes the writer driver.
	///
	/// A drain deadline composes by wrapping this future in the
	/// caller's timer.
	pub async fn shutdown(&self) -> TransportResult<()> {
		self.shutdown_with(GoAwayReason::Shutdown).await
	}

	/// As [`shutdown`](Self::shutdown), advertising `reason` in the
	/// GoAway. Application-defined codes live at or above
	/// [`MUX_APPLICATION_CODE_FLOOR`](crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR).
	pub async fn shutdown_with(&self, reason: GoAwayReason) -> TransportResult<()> {
		drain_with_reason(&self.shared, &self.outbound, reason).await?;

		self.shared.drain_pending().await;

		let mut outbound = outbound_handle(&self.outbound);
		let _ = outbound.send(Outbound::Close).await;
		Ok(())
	}
}

impl MultiplexedProtocol for MuxHandle {
	fn max_concurrent_streams(&self) -> u32 {
		self.shared.local_cap
	}

	fn emit_on_stream(&self, frame: &Frame) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend {
		MuxHandle::emit_on_stream(self, frame)
	}
}

impl StreamingProtocol for MuxHandle {
	fn open_stream(
		&self,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		MuxHandle::open_stream(self)
	}

	fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)> {
		MuxHandle::open_duplex(self)
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;

	use super::super::body::BodyEvent;
	use super::super::testing::{client_shared, poll_chunk, poll_now};
	use super::*;
	use crate::transport::envelopes::MuxEnvelope;

	fn duplex_handle() -> (MuxHandle, mpsc::Receiver<Outbound>) {
		let (outbound, sent) = mpsc::channel(8);
		let (drain_feedback, _) = mpsc::unbounded();
		let handle = MuxHandle { shared: client_shared(), outbound, drain_feedback };

		(handle, sent)
	}

	// Abandoning a duplex reply after the sink closed must reclaim
	// the stream: without the body's drop guard the cap slot and
	// the duplex forwarder stay pinned until the peer's trailer.
	#[test]
	fn test_stream_body_drop_cancels_abandoned_duplex_reply() {
		let (handle, mut sent) = duplex_handle();
		let (sink, body) = handle.open_duplex().expect("fresh connection has stream slots");
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));

		drop(body);

		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(_))))
		));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Cancel(package))))
				if package.stream_id() == 1
		));
		assert!(handle.shared.take_duplex(1).is_none());
		assert!(!handle.shared.is_pending(1));
	}

	// A resolved reply disarms the guard: dropping the body after
	// its terminal event sends no cancel.
	#[test]
	fn test_stream_body_terminal_disarms_drop_cancel() {
		let (handle, mut sent) = duplex_handle();
		let (sink, mut body) = handle.open_duplex().expect("fresh connection has stream slots");
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));

		let mut forwarder = handle.shared.take_duplex(1).expect("open_duplex registered the forwarder");
		let _ = handle.shared.remove_pending(1);
		assert!(forwarder.forward(BodyEvent::End));
		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Ok(None))));

		drop(body);

		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(_))))
		));
		assert!(sent.try_recv().is_err());
	}
}
