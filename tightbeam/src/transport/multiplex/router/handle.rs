//! Client handle: stream emission, streaming opens, pings, and the
//! drop guards that reclaim abandoned in-flight work.

use core::future::Future;
use std::sync::Arc;

use futures::channel::{mpsc, oneshot};
use futures::SinkExt;

use super::body::{DrainNote, StreamBody};
use super::flow::{chunk_records, payload_credits};
use super::link::MuxLink;
use super::outbound::Outbound;
use super::shared::{BudgetStanding, MuxShared, OpenRequest, OpenSlot, StreamOutcome, StreamReservation};
use super::sink::RequestSink;
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::Encode;
use crate::transport::envelopes::{GoAwayReason, MuxDataPackage, MuxPingPackage, MuxStreamKind, TransportEnvelope};
use crate::transport::error::TransportFailure;
use crate::transport::multiplex::{MultiplexedProtocol, StreamRoute, StreamingProtocol};
use crate::transport::{TransportError, TransportResult};
use crate::utils::marker::MaybeSend;
use crate::utils::urn::Urn;
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
pub struct CancelOnDrop {
	link: MuxLink,
	slot: Arc<OpenSlot>,
	armed: bool,
}

impl CancelOnDrop {
	/// Armed guard over a stream identified by `slot`.
	fn new(link: &MuxLink, slot: Arc<OpenSlot>) -> Self {
		Self { link: link.clone(), slot, armed: true }
	}

	pub fn disarm(&mut self) {
		self.armed = false;
	}
}

impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}

		if let Some(stream_id) = self.slot.get() {
			self.link.enqueue_stream_cancel(stream_id);
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

/// Cloneable client handle for a multiplexed connection.
///
/// Shares pending-stream state and the outbound queue across clones
/// (`Arc` + channel refcount bumps only). Does not drive I/O: spawn
/// [`crate::transport::multiplex::MuxReaderDriver`] and [`crate::transport::multiplex::MuxWriterDriver`] on the caller's executor.
/// See [`MuxHandle::emit_on_stream`] and [`MuxHandle::ping`].
#[derive(Clone)]
pub struct MuxHandle {
	link: MuxLink,
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
		self.link.shared().trace.as_ref()
	}
}

impl MuxHandle {
	/// Assemble a handle over the connection's shared state and
	/// queues (refcount bumps only, no data copies).
	pub(crate) fn new(link: MuxLink, drain_feedback: mpsc::UnboundedSender<DrainNote>) -> Self {
		Self { link, drain_feedback }
	}

	/// Send a request on a freshly allocated stream and await its
	/// response. Frames beyond the peer's advertised chunk size are
	/// segmented into `Open(first) Data(...)* Data(last)`, each chunk
	/// gated by the peer's stream credit.
	///
	/// Dropping the returned future before it resolves cancels the
	/// stream: the pending entry is removed, the cap slot freed, and a
	/// best-effort [`crate::transport::envelopes::MuxCancelPackage`] sent.
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
		let credits = payload_credits(
			payload.len(),
			self.link.shared().send_chunk_size,
			self.link.shared().credit_unit,
		);

		let (sender, receiver) = oneshot::channel();
		// The reservation holds the cap slot until the Open goes out
		// and releases it if this future is dropped waiting out a
		// renewal: no ID exists yet, so nothing needs cancelling
		let mut reservation = self.link.shared().reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		let standing = self.link.shared().admit_debit(credits, false).await?;

		let total = chunk_records(payload.len(), self.link.shared().send_chunk_size);
		let mut guard = CancelOnDrop::new(&self.link, Arc::clone(&slot));

		match self.send_request_chunks(&mut reservation, &payload, total).await {
			Ok(()) => {}
			// Ledger removed mid-send: the stream resolved underneath
			// the sender and the outcome channel carries the truth
			Err(TransportError::OperationFailed(TransportFailure::Cancelled)) => {}
			Err(err) => return Err(err),
		}

		if matches!(standing, BudgetStanding::Exhausting) {
			self.link.renew_or_drain().await?;
		}

		let outcome = receiver.await;

		guard.disarm();

		if let Some(stream_id) = slot.get() {
			self.link.shared().finish_send_stream(stream_id);
		}

		outcome.map_or(Err(TransportError::ConnectionClosed), StreamOutcome::resolve)
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
		self.open_stream_with_route(StreamRoute::local())
	}

	/// Open a streaming request to a servlet type, so a gateway
	/// responder can dispatch or splice the stream by that target.
	///
	/// The target names a servlet type, exactly as `HiveContext::call`
	/// does: the caller says what work it wants, never a specific
	/// instance. A `Urn<'static>` const passes with no allocation.
	/// Otherwise identical to [`open_stream`](Self::open_stream).
	///
	/// # Errors
	/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
	/// - `Draining`: GoAway sent or received. No new streams
	pub fn open_stream_to(
		&self,
		target: impl Into<Urn<'static>>,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		self.open_stream_with_route(StreamRoute::to(target.into()))
	}

	/// Open a streaming request carrying a fully-formed [`StreamRoute`].
	///
	/// Shared open core behind [`open_stream`](Self::open_stream) and
	/// [`open_stream_to`](Self::open_stream_to). It is the
	/// crate-internal entry a gateway uses to re-emit a client stream
	/// to a peer with [`StreamRoute::relayed_to`]. The route parts
	/// stay on the sink until its first chunk emits the Open.
	pub(crate) fn open_stream_with_route(
		&self,
		route: StreamRoute,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		let (target, hops_remaining) = route.into_parts();
		let (sender, receiver) = oneshot::channel();
		let reservation = self.link.shared().reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		let sink = RequestSink::new(
			reservation,
			MuxStreamKind::Streaming,
			self.link.clone(),
			None,
			target,
			hops_remaining,
		);

		let link = self.link.clone();
		let response = async move {
			let mut guard = CancelOnDrop::new(&link, Arc::clone(&slot));
			let outcome = receiver.await;

			guard.disarm();

			if let Some(stream_id) = slot.get() {
				link.shared().finish_send_stream(stream_id);
			}

			outcome.map_or(Err(TransportError::ConnectionClosed), StreamOutcome::resolve)
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
		self.open_duplex_with_route(StreamRoute::local())
	}

	/// Open a duplex stream to a servlet type, so a gateway responder
	/// can dispatch or splice both directions by that target.
	///
	/// The target names a servlet type, exactly as `HiveContext::call`
	/// does: the caller says what work it wants, never a specific
	/// instance. A `Urn<'static>` const passes with no allocation.
	/// Otherwise identical to [`open_duplex`](Self::open_duplex).
	///
	/// # Errors
	/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
	/// - `Draining`: GoAway sent or received. No new streams
	pub fn open_duplex_to(&self, target: impl Into<Urn<'static>>) -> TransportResult<(RequestSink, StreamBody)> {
		self.open_duplex_with_route(StreamRoute::to(target.into()))
	}

	/// Open a duplex stream carrying a fully-formed [`StreamRoute`].
	///
	/// Shared open core behind [`open_duplex`](Self::open_duplex) and
	/// [`open_duplex_to`](Self::open_duplex_to). It is the
	/// crate-internal entry a gateway uses to re-emit a client duplex
	/// stream to a peer with [`StreamRoute::relayed_to`]. The route
	/// parts stay on the sink until its first chunk emits the Open.
	pub(crate) fn open_duplex_with_route(&self, route: StreamRoute) -> TransportResult<(RequestSink, StreamBody)> {
		let (target, hops_remaining) = route.into_parts();
		let (sender, receiver) = oneshot::channel();
		let reservation = self.link.shared().reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		// The reply travels through the body, not the outcome slot:
		// the pending entry only holds the stream's cap slot
		drop(receiver);

		// The forwarder follows the reservation into the sink and
		// registers under the assigned ID at first push, before the
		// Open can reach the peer.
		let (mut body, forwarder) = StreamBody::pair(
			Arc::clone(&slot),
			self.link.shared().initial_recv_credit,
			self.drain_feedback.clone(),
		);

		// An abandoned reply must reclaim its cap slot: without the
		// guard, a closed-sink duplex stream has no cancel path and
		// the slot stays pinned until the peer's trailer
		body.arm_guard(CancelOnDrop::new(&self.link, slot));

		let sink = RequestSink::new(
			reservation,
			MuxStreamKind::Duplex,
			self.link.clone(),
			Some(forwarder),
			target,
			hops_remaining,
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
		let chunk_size = self.link.shared().send_chunk_size;
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
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
		};

		let stream_id = self.link.send_open_envelope(reservation, &mut request).await?;
		for chunk in chunks {
			sent += 1;

			let data = MuxDataPackage::new(stream_id, sent == total, chunk)?;
			let data_envelope = TransportEnvelope::from(data);
			self.link.send_data_envelope(stream_id, data_envelope).await?;
		}

		Ok(())
	}

	/// Whether a new locally-initiated stream would be admitted now: cap
	/// headroom, live ID space, and no GoAway either way.
	///
	/// Advisory: a concurrent emit can take the last slot after this
	/// returns, so callers still handle `StreamsExhausted`.
	pub fn has_stream_headroom(&self) -> bool {
		self.link.shared().has_stream_headroom()
	}

	/// Whether any locally-initiated stream is still awaiting its response.
	///
	/// Callers with a clock use this to pin a connection as active while
	/// streams are in flight (see pool `last_used` stamping).
	pub fn has_pending_streams(&self) -> bool {
		self.link.shared().has_pending_streams()
	}

	/// Reason carried by the peer's GoAway, or `None` while the
	/// connection is live or was shut down locally.
	///
	/// Reconnect policies branch on this: `Shutdown` invites an
	/// immediate reconnect, `EnhanceYourCalm` calls for backoff, and
	/// `ProtocolError` points at a bug rather than a transient fault.
	pub fn goaway_reason(&self) -> Option<GoAwayReason> {
		self.link.shared().goaway_reason()
	}

	/// Current epoch's dual-signed session receipt, rotated in
	/// place by each completed in-band renewal. `None` on sessions
	/// without receipt-bearing rekey materials.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
		self.link.shared().session_receipt()
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
		self.link.shared().stream_slot()
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
		let opaque = self.link.shared().allocate_ping(sender)?;
		let shared = Arc::clone(self.link.shared());
		let mut guard = ForgetPingOnDrop { shared, opaque, armed: true };

		let probe = MuxPingPackage::new(false, opaque);
		let mut outbound = self.link.sender();
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
		self.link.announce_goaway(reason).await?;
		self.link.shared().drain_pending().await;

		let mut outbound = self.link.sender();
		let _ = outbound.send(Outbound::Close).await;
		Ok(())
	}
}

impl MultiplexedProtocol for MuxHandle {
	fn max_concurrent_streams(&self) -> u32 {
		self.link.shared().local_cap
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
	use super::super::testing::{client_shared, poll_now};
	use super::*;
	use crate::transport::envelopes::MuxEnvelope;
	use crate::utils::urn::Urn;

	fn duplex_handle() -> (MuxHandle, mpsc::Receiver<Outbound>) {
		let (outbound, sent) = mpsc::channel(8);
		let (drain_feedback, _) = mpsc::unbounded();
		let handle = MuxHandle { link: MuxLink::new(client_shared(), outbound), drain_feedback };
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
		assert!(handle.link.shared().take_duplex(1).is_none());
		assert!(!handle.link.shared().is_pending(1));
	}

	// open_stream_to stamps the grpc-style route on the stream's
	// Open record so a gateway responder can dispatch or splice by
	// target. The origin open carries the default relay budget.
	#[test]
	fn test_open_stream_to_stamps_route_on_open() -> TransportResult<()> {
		let (handle, mut sent) = duplex_handle();
		let target = Urn::new("tb", "servlet:ledger");
		let (sink, _response) = handle.open_stream_to(target.clone())?;
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if package.target() == Some(&target) && package.hops_remaining() == DEFAULT_HOP_BUDGET
		));

		Ok(())
	}

	// An explicit spent budget on the Open is served locally and
	// never re-forwarded by a peer gateway.
	#[test]
	fn test_open_stream_with_relayed_route_stamps_budget() -> TransportResult<()> {
		let (handle, mut sent) = duplex_handle();
		let target = Urn::new("tb", "servlet:ledger");
		let (sink, _response) = handle.open_stream_with_route(StreamRoute::from_parts(Some(target.clone()), 0))?;
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if package.target() == Some(&target) && package.hops_remaining() == 0
		));

		Ok(())
	}

	// The unrouted open path carries no route: open_stream emits an
	// Open with no target and the default relay budget.
	#[test]
	fn test_open_stream_local_open_has_no_route() -> TransportResult<()> {
		let (handle, mut sent) = duplex_handle();
		let (sink, _response) = handle.open_stream()?;
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));
		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(package))))
				if package.target().is_none() && package.hops_remaining() == DEFAULT_HOP_BUDGET
		));

		Ok(())
	}

	// A resolved reply disarms the guard: dropping the body after
	// its terminal event sends no cancel.
	#[test]
	fn test_stream_body_terminal_disarms_drop_cancel() {
		let (handle, mut sent) = duplex_handle();
		let (sink, mut body) = handle.open_duplex().expect("fresh connection has stream slots");
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));

		let mut forwarder = handle
			.link
			.shared()
			.take_duplex(1)
			.expect("open_duplex registered the forwarder");

		let _ = handle.link.shared().remove_pending(1);
		assert!(forwarder.forward(BodyEvent::End));
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));

		drop(body);

		assert!(matches!(
			sent.try_recv(),
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Open(_))))
		));
		assert!(sent.try_recv().is_err());
	}
}
