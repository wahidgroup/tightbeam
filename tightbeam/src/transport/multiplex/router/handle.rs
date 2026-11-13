//! The client handle emits streams, opens streaming requests, pings the peer,
//! and owns the drop guards that reclaim abandoned in-flight work.

use core::future::Future;
use core::pin::pin;
use std::sync::Arc;

use futures::channel::oneshot;
use futures::SinkExt;

use super::body::StreamBody;
use super::link::MuxLink;
use super::outbound::Outbound;
use super::shared::{BudgetStanding, MuxShared, OpenRequest, OpenSlot, StreamOutcome, StreamReservation};
use super::sink::RequestSink;
use crate::clock::Lapse;
use crate::constants::DEFAULT_HOP_BUDGET;
use crate::der::Encode;
use crate::marker::MaybeSend;
use crate::transport::envelopes::{
	CancelReason, GoAwayReason, MuxDataPackage, MuxPingPackage, MuxStreamKind, TransportEnvelope,
};
use crate::transport::error::TransportFailure;
use crate::transport::multiplex::{MultiplexedProtocol, StreamRoute, StreamingProtocol};
use crate::transport::GateAudit;
use crate::transport::{TransportError, TransportResult};
use crate::urn::Urn;
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(pooled_mux)]
use core::future::poll_fn;

/// Cancels the stream if the owning emit future is dropped before its response
/// arrives. The cancel frees the cap slot and notifies the peer, best-effort
/// ([RFC 9113 § 6.4][rfc9113-6.4]).
///
/// The guard reads the stream's ID through its [`OpenSlot`] at drop time. A
/// guard dropped before the Open went out stands down on its own, because
/// nothing is on the wire and the reservation releases the cap slot.
///
/// The cancel carries [`CancelReason::Cancelled`], or
/// [`CancelReason::Timeout`] once a deadline that passed ends the wait of the
/// stream ([`Self::fail`]).
///
/// [rfc9113-6.4]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.4
pub struct CancelOnDrop {
	link: MuxLink,
	slot: Arc<OpenSlot>,
	armed: bool,
	/// The reason of the cancel that the drop sends.
	reason: CancelReason,
}

impl CancelOnDrop {
	/// Returns an armed guard over the stream that `slot` identifies.
	fn new(link: &MuxLink, slot: Arc<OpenSlot>) -> Self {
		Self { link: link.clone(), slot, armed: true, reason: CancelReason::Cancelled }
	}

	pub fn disarm(&mut self) {
		self.armed = false;
	}

	/// Takes `failure`, which ends the wait of the stream, and returns it. A
	/// deadline that passed sets the reason of the drop cancel to `Timeout`.
	fn fail(&mut self, failure: TransportError) -> TransportError {
		if matches!(failure, TransportError::OperationFailed(TransportFailure::DeadlineExceeded)) {
			self.reason = CancelReason::Timeout;
		}

		failure
	}
}

impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}

		if let Some(stream_id) = self.slot.get() {
			self.link.enqueue_stream_cancel(stream_id, self.reason);
		}
	}
}

/// Forgets the pending ping if the owning ping future is dropped
/// before its ack arrives. A later ack finds no pending entry and
/// resolves nothing, as a stale response does, so the peer needs no
/// notification.
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
/// Clones share the pending-stream state and the outbound queue, at the cost of
/// `Arc` and channel refcount bumps only. The drivers own the I/O, so the
/// caller spawns [`MuxReaderDriver`] and [`MuxWriterDriver`] on its executor.
/// See [`MuxHandle::emit_on_stream`] and [`MuxHandle::ping`].
///
/// # Ended connection
///
/// - Once either driver has ended, every call that would wait on the peer returns `ConnectionClosed`.
/// - That outranks `Draining`, so a connection that took a GoAway and then ended reports the end.
///
/// [`MuxReaderDriver`]: crate::transport::multiplex::MuxReaderDriver
/// [`MuxWriterDriver`]: crate::transport::multiplex::MuxWriterDriver
#[derive(Clone)]
pub struct MuxHandle {
	link: MuxLink,
}

/// When a keepalive probes its link.
#[derive(Clone, Copy)]
enum Probing {
	/// Once per interval, for as long as the link lasts.
	Always,
	/// Once per interval while a locally-initiated stream is open, and at once
	/// when the next one opens, so an idle connection ends at its read
	/// deadline.
	#[cfg(pooled_mux)]
	WhileStreams,
}

impl Probing {
	/// Waits until this policy wants the next probe on the connection of
	/// `shared`.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the connection failed while the policy waited for a stream.
	#[cfg_attr(not(pooled_mux), expect(unused_variables))]
	async fn ready(self, shared: &MuxShared) -> TransportResult<()> {
		match self {
			Self::Always => Ok(()),
			#[cfg(pooled_mux)]
			Self::WhileStreams => poll_fn(|cx| shared.poll_stream_opened(cx)).await,
		}
	}
}

// The handle is the audit source for gate verdicts on the mux plane. The
// responder gates requests through `gate_inbound`, which records the verdict
// into this connection's collector.
impl GateAudit for MuxHandle {
	#[cfg(feature = "instrument")]
	fn audit_trace(&self) -> Option<&TraceCollector> {
		self.link.shared().trace.as_ref()
	}
}

impl MuxHandle {
	/// Assemble a handle over the connection's shared state and queues.
	pub(crate) fn new(link: MuxLink) -> Self {
		Self { link }
	}

	/// Send a request on a freshly allocated stream and await its response.
	///
	/// The call segments a frame beyond the peer's advertised chunk size into
	/// `Open(first) Data(...)* Data(last)`, and the peer's stream credit gates
	/// each chunk. The send of each chunk waits for credit within the read
	/// deadline of the link, and the response comes within that deadline,
	/// counted from the end of the request.
	///
	/// # Cancellation
	///
	/// Dropping the returned future before it resolves cancels the stream. The
	/// cancel removes the pending entry, frees the cap slot, and sends a
	/// best-effort [`crate::transport::envelopes::MuxCancelPackage`] under
	/// [`CancelReason::Cancelled`]. A send or a response that the deadline cuts
	/// off cancels the stream the same way, under [`CancelReason::Timeout`].
	///
	/// # Errors
	///
	/// - `OperationFailed(StreamsExhausted)` -- the local-initiated cap is exhausted.
	/// - `OperationFailed(BudgetExhausted)` -- the outbound budget cannot cover the frame.
	/// - `OperationFailed(ResourceExhausted)` -- the peer refused the stream.
	/// - `OperationFailed(DeadlineExceeded)` -- the peer granted no credit for
	///   a chunk, or sent no response, within the read deadline of the link.
	/// - `OperationFailed(FailedPrecondition)` -- the polling thread has no
	///   timer for the clock of the link, and a chunk or the response waits.
	/// - `Draining` -- a GoAway was sent or received, so the connection opens no new streams.
	/// - `ConnectionClosed` -- the connection failed, before this call or before the response.
	pub async fn emit_on_stream(&self, frame: &Frame) -> TransportResult<Option<Frame>> {
		// Encode before reserving so an encoding failure never burns
		// a cap slot or queues work for a stream the peer never saw.
		let payload = frame.to_der()?;
		let credits = self.link.shared().credits_for(payload.len());

		let (sender, receiver) = oneshot::channel();
		// The reservation holds the cap slot until the Open goes out, and
		// releases it if this future is dropped while it waits out a renewal.
		// No ID exists yet, so nothing needs cancelling.
		let mut reservation = self.link.shared().reserve_stream_slot(sender)?;
		let slot = reservation.slot();

		let standing = self.link.shared().admit_debit(credits, false).await?;

		let total = self.link.shared().records_for(payload.len());
		let mut guard = CancelOnDrop::new(&self.link, Arc::clone(&slot));

		match self.send_request_chunks(&mut reservation, &payload, total).await {
			Ok(()) => {}
			// A send that finds its ledger gone means the stream resolved
			// underneath the sender, so the outcome channel carries the result.
			Err(TransportError::OperationFailed(TransportFailure::Cancelled)) => {}
			Err(err) => return Err(guard.fail(err)),
		}

		if matches!(standing, BudgetStanding::Exhausting) {
			self.link.renew_or_drain().await?;
		}

		// A response that the deadline cuts off leaves the guard armed, so its
		// drop cancels the stream with `Timeout`.
		let outcome = self.link.pulse().bound(receiver).await.map_err(|err| guard.fail(err))?;

		guard.disarm();

		if let Some(stream_id) = slot.get() {
			self.link.shared().finish_send_stream(stream_id);
		}

		outcome.map_or(Err(TransportError::ConnectionClosed), StreamOutcome::resolve)
	}

	/// Open a streaming request: push chunks through the returned
	/// [`RequestSink`], then await the returned response future.
	///
	/// - Every push debits the session budget and parks on the peer's stream
	///   credit exactly like [`emit_on_stream`](Self::emit_on_stream) chunks,
	///   so a streamed request is metered and paid like a unary one.
	/// - The response comes within the read deadline of the link, counted from
	///   [`RequestSink::close`], as the response of `emit_on_stream` does. A
	///   response that comes before the close needs no bound.
	/// - Dropping the sink before [`RequestSink::close`], or the response
	///   future before it resolves, cancels the stream.
	/// - A connection that fails or drains before the first push resolves the
	///   response future with `ConnectionClosed` or `Draining`.
	///
	/// The response future fails with `OperationFailed(DeadlineExceeded)` once
	/// the deadline passes, and the stream ends with a
	/// [`CancelReason::Timeout`] cancel. It fails with
	/// `OperationFailed(FailedPrecondition)` when the polling thread has no
	/// timer for the clock of the link and the response waits.
	///
	/// # Errors
	///
	/// - `OperationFailed(StreamsExhausted)` -- the local-initiated cap is exhausted.
	/// - `Draining` -- a GoAway was sent or received, so the connection opens no new streams.
	/// - `ConnectionClosed` -- the connection has failed, so nothing would answer the stream.
	pub fn open_stream(
		&self,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		self.open_stream_with_route(StreamRoute::local())
	}

	/// Open a streaming request to a servlet type, so a gateway
	/// responder can dispatch or splice the stream by that target.
	///
	/// The target names a servlet type, exactly as `HiveContext::call` does, so
	/// the caller says what work it wants and not which instance does it. A
	/// `Urn<'static>` const passes with no allocation. The call is otherwise
	/// identical to [`open_stream`](Self::open_stream).
	///
	/// # Errors
	///
	/// - `OperationFailed(StreamsExhausted)` -- the local-initiated cap is exhausted.
	/// - `Draining` -- a GoAway was sent or received, so the connection opens no new streams.
	/// - `ConnectionClosed` -- the connection has failed, so nothing would answer the stream.
	pub fn open_stream_to(
		&self,
		target: impl Into<Urn<'static>>,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		self.open_stream_with_route(StreamRoute::to(target.into()))
	}

	/// Open a streaming request carrying a fully-formed [`StreamRoute`].
	///
	/// - [`open_stream`](Self::open_stream) and [`open_stream_to`](Self::open_stream_to) share this core.
	/// - A gateway re-emits a client stream to a peer through it, with [`StreamRoute::relayed_to`].
	///
	/// The route parts stay on the sink until its first chunk emits the Open.
	pub(crate) fn open_stream_with_route(
		&self,
		route: StreamRoute,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		let (target, hops_remaining) = route.into_parts();
		let (sender, receiver) = oneshot::channel();
		let (end_signal, ended) = oneshot::channel();
		let reservation = self.link.shared().reserve_stream_slot(sender)?;
		let slot = reservation.slot();
		let sink = RequestSink::streaming(reservation, self.link.clone(), target, hops_remaining, end_signal);

		let link = self.link.clone();
		let pulse = self.link.pulse().clone();
		// The guard arms before the first poll, so a response future that drops
		// unpolled cancels its stream as well.
		let mut guard = CancelOnDrop::new(&link, Arc::clone(&slot));
		let response = async move {
			// A response that the deadline cuts off leaves the guard armed, so
			// its drop cancels the stream with `Timeout`.
			let outcome = pulse.reply_after(ended, receiver).await.map_err(|err| guard.fail(err))?;

			guard.disarm();

			if let Some(stream_id) = slot.get() {
				link.shared().finish_send_stream(stream_id);
			}

			outcome.map_or(Err(TransportError::ConnectionClosed), StreamOutcome::resolve)
		};

		Ok((sink, response))
	}

	/// Open a duplex stream: push request chunks through the returned
	/// [`RequestSink`] while consuming the streamed reply from the returned
	/// [`StreamBody`]. Both directions flow concurrently on one stream.
	///
	/// # Pacing
	///
	/// - Pushes reach the wire eagerly (see [`RequestSink::push`]), so a
	///   push-one-await-one conversation with the handler is sound.
	/// - The reply's pace stays the handler's choice. Only its trailer is
	///   guaranteed, so an exchange that must not park awaits reply chunks
	///   that it knows the handler sends.
	/// - Consuming reply chunks replenishes the peer's stream credit, so a
	///   slow reader parks the responder (end-to-end backpressure).
	///
	/// # Ending
	///
	/// The reply ends with the responder's trailer: `Ok(None)` on an Ok status,
	/// otherwise the status mapped to its transport error. Dropping the sink
	/// before [`RequestSink::close`], or the reply body before its terminal
	/// event, cancels the stream. A connection that fails or drains before the
	/// first push ends the body with `ConnectionClosed` or `Draining`.
	///
	/// # Errors
	///
	/// - `OperationFailed(StreamsExhausted)` -- the local-initiated cap is exhausted.
	/// - `Draining` -- a GoAway was sent or received, so the connection opens no new streams.
	/// - `ConnectionClosed` -- the connection has failed, so nothing would answer the stream.
	pub fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)> {
		self.open_duplex_with_route(StreamRoute::local())
	}

	/// Open a duplex stream to a servlet type, so a gateway responder
	/// can dispatch or splice both directions by that target.
	///
	/// The target names a servlet type, exactly as `HiveContext::call` does,
	/// so the caller says what work it wants and not which instance does it.
	/// A `Urn<'static>` const passes with no allocation. The call is otherwise
	/// identical to [`open_duplex`](Self::open_duplex).
	///
	/// # Errors
	///
	/// - `OperationFailed(StreamsExhausted)` -- the local-initiated cap is exhausted.
	/// - `Draining` -- a GoAway was sent or received, so the connection opens no new streams.
	/// - `ConnectionClosed` -- the connection has failed, so nothing would answer the stream.
	pub fn open_duplex_to(&self, target: impl Into<Urn<'static>>) -> TransportResult<(RequestSink, StreamBody)> {
		self.open_duplex_with_route(StreamRoute::to(target.into()))
	}

	/// Open a duplex stream carrying a fully-formed [`StreamRoute`].
	///
	/// - [`open_duplex`](Self::open_duplex) and [`open_duplex_to`](Self::open_duplex_to) share this core.
	/// - A gateway re-emits a client duplex stream to a peer through it, with [`StreamRoute::relayed_to`].
	///
	/// The route parts stay on the sink until its first chunk emits the Open.
	pub(crate) fn open_duplex_with_route(&self, route: StreamRoute) -> TransportResult<(RequestSink, StreamBody)> {
		let (target, hops_remaining) = route.into_parts();
		// The reply forwarder waits with the reservation in the pending table,
		// where a failed or draining connection reaches it. It registers under
		// the assigned ID at first push, before the Open can reach the peer.
		let drained = self.link.drain_feedback();
		let (reservation, mut body) = self.link.shared().reserve_duplex_slot(drained)?;
		let slot = reservation.slot();

		// An abandoned reply must reclaim its cap slot. Without the guard, a
		// closed-sink duplex stream has no cancel path, and the slot stays
		// pinned until the peer's trailer.
		body.arm_guard(CancelOnDrop::new(&self.link, slot));

		let sink = RequestSink::duplex(reservation, self.link.clone(), target, hops_remaining);
		Ok((sink, body))
	}

	/// Segment a request payload into the initiator grammar, one credit-gated
	/// chunk per record. The first chunk travels through the atomic open, which
	/// assigns the stream ID and seeds the ledger with `total` records, and the
	/// rest travel as `Data`.
	async fn send_request_chunks(
		&self,
		reservation: &mut StreamReservation,
		payload: impl AsRef<[u8]>,
		total: u64,
	) -> TransportResult<()> {
		let payload = payload.as_ref();
		let chunk_size = self.link.shared().send_chunk_size.get();
		let mut chunks = payload.chunks(chunk_size);
		let mut sent: u64 = 0;
		let first = chunks.next().unwrap_or(&[]);

		sent = sent.saturating_add(1);
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: sent == total,
			payload: first,
			records: total,
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
		};

		let stream_id = self.link.send_open_envelope(reservation, &mut request).await?;
		for chunk in chunks {
			sent = sent.saturating_add(1);

			let data = MuxDataPackage::new(stream_id, sent == total, chunk)?;
			let data_envelope = TransportEnvelope::from(data);
			self.link.send_data_envelope(stream_id, data_envelope).await?;
		}

		Ok(())
	}

	/// Returns whether a new locally-initiated stream would be admitted now,
	/// which needs cap headroom, live ID space, a connection that has not
	/// failed, and no GoAway in either direction.
	///
	/// The answer is advisory. A concurrent emit can take the last slot after
	/// this returns, so callers still handle `StreamsExhausted`.
	pub fn has_stream_headroom(&self) -> bool {
		self.link.shared().has_stream_headroom()
	}

	/// Returns whether any locally-initiated stream is still awaiting its
	/// response.
	///
	/// Callers with a clock use this to pin a connection as active while
	/// streams are in flight (see pool `last_used` stamping).
	pub fn has_pending_streams(&self) -> bool {
		self.link.shared().has_pending_streams()
	}

	/// Returns the reason carried by the peer's GoAway, or `None` while the
	/// connection is live or was shut down locally.
	///
	/// Reconnect policies branch on this: `Shutdown` invites an immediate
	/// reconnect, `EnhanceYourCalm` calls for backoff, and `ProtocolError`
	/// points at a bug rather than a transient fault.
	pub fn goaway_reason(&self) -> Option<GoAwayReason> {
		self.link.shared().goaway_reason()
	}

	/// Returns the current epoch's dual-signed session receipt, which each
	/// completed in-band renewal rotates in place. The answer is `None` on a
	/// session without receipt-bearing rekey materials.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
		self.link.shared().session_receipt()
	}

	/// Resolve once a locally-initiated stream would be admitted, on the
	/// conditions [`MuxHandle::has_stream_headroom`] names.
	///
	/// A caller awaits this in place of a polling loop over that getter. The
	/// answer is advisory like the getter, because a concurrent emit can take
	/// the slot between wake and use, so callers still handle
	/// `StreamsExhausted`.
	///
	/// # Errors
	///
	/// - `Draining` -- a GoAway was sent or received, or the stream IDs are exhausted.
	/// - `ConnectionClosed` -- the connection has failed.
	pub fn wait_for_stream_slot(&self) -> impl Future<Output = TransportResult<()>> + MaybeSend {
		self.link.shared().stream_slot()
	}

	/// Probe connection-level liveness ([RFC 9113 § 6.7][rfc9113-6.7]). The
	/// future resolves when the peer's ack arrives.
	///
	/// The probe stays off the stream table and the peer's application handler,
	/// so it doubles as an idle keepalive for links whose carrier cannot ping
	/// itself.
	///
	/// # Errors
	///
	/// - `Draining` -- a GoAway was sent or received, so the connection is ending.
	/// - `ConnectionClosed` -- the connection failed, before this call or before the ack.
	///
	/// [rfc9113-6.7]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.7
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

	/// Ping the peer once per interval so an idle link stays inside the read
	/// deadline of both ends. The future runs until a [`ping`](Self::ping)
	/// fails, and resolves to the error of that ping, or at once to
	/// `FailedPrecondition` on a clock that cannot race a probe.
	///
	/// Run it on a task of its own, on a clone of the handle.
	///
	/// # Timing
	///
	/// [`KEEPALIVE_PROBES_PER_DEADLINE`] intervals fill one [`operation_timeout`]
	/// of the read half, timed on the clock of the write half.
	///
	/// - The future sends the first probe at once, and each later probe one interval after the one before it.
	/// - A probe waits at most one interval for its ack. At the next tick the
	///   future forgets an unanswered probe and sends the next one.
	/// - Each probe counts as a read on the peer, and each ack as a read on
	///   this end. One end that runs this therefore keeps both ends alive while
	///   the interval is shorter than the read deadline of the peer.
	/// - This end stays inside its read deadline through one lost ack in a row,
	///   when the future starts under one interval after the last read and each
	///   ack that arrives takes under one interval.
	///
	/// # Errors
	///
	/// - [`TransportError::Draining`] -- a probe met a GoAway that went out or came in.
	/// - [`TransportError::ConnectionClosed`] -- the link closed before a probe
	///   or while a probe waited for its ack, as when a drain ends.
	/// - The injected error, when the runtime fault model injects a fault at
	///   the drain event of a refused probe.
	/// - [`TransportError::OperationFailed`] with `FailedPrecondition` -- the
	///   clock of the link cannot race a probe on the polling thread
	///   ([`Clock::timing`]). The house clock races on a thread that runs a
	///   tokio runtime with its time driver.
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(feature = "tokio")]
	/// # {
	/// use tightbeam::transport::multiplex::MuxHandle;
	/// use tightbeam::transport::TransportError;
	///
	/// /// Keep the link of `handle` alive on a task of its own.
	/// fn keep_alive_on_a_task(handle: &MuxHandle) -> tokio::task::JoinHandle<TransportError> {
	///     tokio::spawn(handle.clone().keep_alive())
	/// }
	/// # }
	/// ```
	///
	/// [`operation_timeout`]: crate::transport::TransportLimits::operation_timeout
	/// [`KEEPALIVE_PROBES_PER_DEADLINE`]: crate::constants::KEEPALIVE_PROBES_PER_DEADLINE
	/// [`Clock::timing`]: crate::clock::Clock::timing
	#[must_use]
	pub async fn keep_alive(self) -> TransportError {
		self.probe(Probing::Always).await
	}

	/// Keep the link alive as [`keep_alive`](Self::keep_alive) does, while a
	/// locally-initiated stream is open. The future sends no probe while the
	/// connection holds no stream, so an idle connection ends at its read
	/// deadline, and it probes at once when the next stream opens.
	///
	/// # Errors
	///
	/// - The errors of [`keep_alive`](Self::keep_alive).
	/// - [`TransportError::ConnectionClosed`] -- the connection failed while the future waited for a stream.
	#[cfg(pooled_mux)]
	pub(crate) async fn keep_streams_alive(self) -> TransportError {
		self.probe(Probing::WhileStreams).await
	}

	/// Probes the link once per interval while `probing` wants a probe, until
	/// a probe fails.
	async fn probe(self, probing: Probing) -> TransportError {
		let pulse = self.link.pulse().clone();
		let Some(mut timer) = pulse.racing_timer() else {
			return TransportError::OperationFailed(TransportFailure::FailedPrecondition);
		};

		let interval = pulse.interval();
		loop {
			if let Err(ended) = probing.ready(self.link.shared()).await {
				return ended;
			}

			let sent = pulse.now();
			match timer.within(interval, pin!(self.ping())).await {
				Ok(Err(refusal)) => return refusal,
				Ok(Ok(())) => {}
				Err(Lapse::Passed) => continue,
				Err(lapse @ Lapse::NoTimer) => return lapse.into(),
			}

			let waited = pulse.now().saturating_duration_since(sent);
			timer.sleep(interval.saturating_sub(waited)).await;
		}
	}

	/// Gracefully shut the connection down ([RFC 9113 § 6.8][rfc9113-6.8]). The
	/// call sends GoAway, halts the allocator, awaits the pending-table drain,
	/// then closes the writer driver.
	///
	/// A drain deadline composes by wrapping this future in the caller's timer.
	///
	/// [rfc9113-6.8]: https://datatracker.ietf.org/doc/html/rfc9113#section-6.8
	pub async fn shutdown(&self) -> TransportResult<()> {
		self.shutdown_with(GoAwayReason::Shutdown).await
	}

	/// Shut down as [`shutdown`](Self::shutdown) does, and advertise `reason`
	/// in the GoAway. Application-defined codes live at or above
	/// [`MUX_APPLICATION_CODE_FLOOR`].
	///
	/// [`MUX_APPLICATION_CODE_FLOOR`]: crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR
	pub async fn shutdown_with(&self, reason: GoAwayReason) -> TransportResult<()> {
		self.link.announce_goaway(reason).await?;
		self.link.shared().drain_pending().await;

		self.close().await;
		Ok(())
	}

	/// Closes the writer driver once it writes every envelope queued before
	/// the call, so a GoAway that a responder queued reaches the peer ahead of
	/// the close.
	pub(crate) async fn close(&self) {
		let mut outbound = self.link.sender();
		// A writer that already ended with the connection has closed the
		// queue, which is the outcome Close asks for.
		let _ = outbound.send(Outbound::Close).await;
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
	use core::time::Duration;

	use futures::channel::mpsc;

	use super::super::body::{BodyEvent, DrainNote};
	use super::super::fixtures::{next_mux, poll_now, FIXTURE_PEER_CAP};
	use super::super::link::Pulse;
	use super::*;
	use crate::clock::{Clock, SystemClock};
	use crate::constants::DEFAULT_OPERATION_TIMEOUT;
	use crate::testing::TestResult;
	use crate::transport::envelopes::MuxEnvelope;
	use crate::transport::multiplex::{MuxRole, MuxSettings};
	use crate::transport::{EnvelopeSink, EnvelopeSource};

	#[cfg(feature = "tokio")]
	use super::super::fixtures::drained;
	#[cfg(feature = "tokio")]
	use crate::constants::MIN_MUX_CHUNK_SIZE;
	#[cfg(feature = "tokio")]
	use crate::testing::TestFrame;

	/// A client handle over a fresh link, beside the receiver of its outbound
	/// queue and the receiver of its drain notes.
	fn duplex_handle() -> (MuxHandle, mpsc::Receiver<Outbound>, mpsc::Receiver<DrainNote>) {
		let shared = MuxShared::fixture(MuxRole::Client, &MuxSettings::symmetric(FIXTURE_PEER_CAP));
		let (link, sent, notes) = MuxLink::over(shared, 8);
		(MuxHandle { link }, sent, notes)
	}

	/// Receives the peer's GoAway above stream 0 on `shared`, whose trace
	/// injects no fault.
	fn receive_goaway(shared: &MuxShared) {
		let received = shared.fail_pending_above(0, GoAwayReason::Shutdown);
		received.expect("a state with no fault model records the GoAway");
	}

	mod keepalive {
		use core::future::pending;

		use super::super::super::fixtures::{drained, poll_times};
		use super::*;
		use crate::clock::{BlockingClock, ManualClock};
		use crate::transport::{CheckedLimits, TransportLimits};

		/// The opaque of the first ping a fresh link sends.
		const FIRST_PROBE: u64 = 0;

		/// Both halves of a link that reads `clock` under `limits`. A read on
		/// it waits forever.
		struct PacedHalves {
			clock: Arc<ManualClock>,
			limits: CheckedLimits,
		}

		impl PacedHalves {
			/// Both halves on `clock`, whose operation timeout is `deadline`.
			fn under(clock: &Arc<ManualClock>, deadline: Duration) -> Self {
				let limits = TransportLimits { operation_timeout: deadline, ..TransportLimits::default() };
				let limits = limits.checked().expect("a deadline above zero agrees with the defaults");

				Self { clock: Arc::clone(clock), limits }
			}
		}

		impl EnvelopeSource for PacedHalves {
			async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
				pending().await
			}

			fn limits(&self) -> CheckedLimits {
				self.limits
			}
		}

		impl EnvelopeSink for PacedHalves {
			async fn write_envelope(&mut self, _envelope: TransportEnvelope) -> TransportResult<()> {
				Ok(())
			}

			fn remaining_records(&self) -> u64 {
				u64::MAX
			}

			fn clock(&self) -> Arc<dyn Clock> {
				Arc::clone(&self.clock) as Arc<dyn Clock>
			}
		}

		/// A client handle paced by a link on `clock` with a nine-second
		/// deadline, beside the receiver of its outbound queue.
		fn paced_handle(clock: &Arc<ManualClock>) -> (MuxHandle, mpsc::Receiver<Outbound>) {
			let shared = MuxShared::fixture(MuxRole::Client, &MuxSettings::symmetric(FIXTURE_PEER_CAP));

			let (link, sent, _notes) = MuxLink::over(shared, 8);
			let halves = PacedHalves::under(clock, Duration::from_secs(9));
			(MuxHandle::new(link.with_pulse(Pulse::of(&halves, &halves))), sent)
		}

		/// A deadline of fewer nanoseconds than the probes per deadline has no
		/// whole share, so the pace keeps the whole deadline in place of a zero
		/// pace.
		#[test]
		fn a_deadline_with_no_whole_third_paces_at_the_whole_deadline() {
			let halves = PacedHalves::under(&Arc::new(ManualClock::default()), Duration::from_nanos(2));
			let pulse = Pulse::of(&halves, &halves);
			assert_eq!(pulse.interval(), Duration::from_nanos(2));
		}

		#[test]
		fn a_keepalive_paces_its_probes_at_a_third_of_the_read_deadline() {
			let clock = Arc::new(ManualClock::default());
			let (handle, mut sent) = paced_handle(&clock);
			let mut keepalive = Box::pin(handle.keep_alive());

			poll_times(&mut keepalive, 2);
			assert_eq!(drained(&mut sent).len(), 1);

			clock.advance(Duration::from_millis(2_999));
			poll_times(&mut keepalive, 1);
			assert!(drained(&mut sent).is_empty());

			clock.advance(Duration::from_millis(1));
			poll_times(&mut keepalive, 2);
			assert_eq!(drained(&mut sent).len(), 1);
		}

		/// A peer past its ack cap drops the ack, so the probe gives way to the
		/// next one at the next tick.
		#[test]
		fn a_keepalive_probes_again_after_an_unanswered_probe() {
			let clock = Arc::new(ManualClock::default());
			let (handle, mut sent) = paced_handle(&clock);
			let mut keepalive = Box::pin(handle.keep_alive());

			poll_times(&mut keepalive, 2);
			assert_eq!(drained(&mut sent).len(), 1);

			clock.advance(Duration::from_secs(3));
			poll_times(&mut keepalive, 2);
			assert_eq!(drained(&mut sent).len(), 1);
		}

		/// `ForgetPingOnDrop` is the one bound on the pending pings of a peer
		/// that never acks, so a replaced probe leaves the table.
		#[test]
		fn a_replaced_probe_leaves_the_pending_table() {
			let clock = Arc::new(ManualClock::default());
			let (handle, _sent) = paced_handle(&clock);
			let mut keepalive = Box::pin(handle.clone().keep_alive());

			poll_times(&mut keepalive, 2);
			clock.advance(Duration::from_secs(3));
			poll_times(&mut keepalive, 2);

			assert!(!handle.link.shared().takes_ping(FIRST_PROBE));
		}

		/// An ack ends the wait of its probe alone, so the next probe leaves at
		/// the next tick.
		#[test]
		fn a_keepalive_holds_its_pace_after_an_ack() {
			let clock = Arc::new(ManualClock::default());
			let (handle, mut sent) = paced_handle(&clock);
			let mut keepalive = Box::pin(handle.clone().keep_alive());

			poll_times(&mut keepalive, 2);
			clock.advance(Duration::from_secs(1));
			handle.link.shared().resolve_ping(FIRST_PROBE);
			poll_times(&mut keepalive, 2);
			assert_eq!(drained(&mut sent).len(), 1);

			clock.advance(Duration::from_secs(2));
			poll_times(&mut keepalive, 2);
			assert_eq!(drained(&mut sent).len(), 1);
		}

		#[test]
		fn a_keepalive_ends_with_its_connection() {
			let clock = Arc::new(ManualClock::default());
			let (handle, _sent) = paced_handle(&clock);
			let mut keepalive = Box::pin(handle.clone().keep_alive());

			poll_times(&mut keepalive, 1);
			handle.link.shared().fail_all_pending();
			clock.advance(Duration::from_secs(3));

			let ended = poll_now(&mut keepalive);
			assert!(matches!(ended, Poll::Ready(TransportError::ConnectionClosed)));
		}

		/// A GoAway refuses the next probe, so the keepalive ends with the
		/// drain.
		#[test]
		fn a_keepalive_ends_at_a_goaway() {
			let clock = Arc::new(ManualClock::default());
			let (handle, _sent) = paced_handle(&clock);
			let mut keepalive = Box::pin(handle.clone().keep_alive());

			poll_times(&mut keepalive, 1);
			receive_goaway(handle.link.shared());
			clock.advance(Duration::from_secs(3));

			assert!(matches!(poll_now(&mut keepalive), Poll::Ready(TransportError::Draining)));
		}

		// A clock that cannot race a probe on the polling thread makes the
		// keepalive refuse at once, before its first probe: the system clock
		// on a thread outside any tokio runtime, and a clock that parks.
		crate::tb_cases! {
			fn a_keepalive_with_no_timer_refuses_before_its_first_probe(clock: Arc<dyn Clock>) {
				let (handle, mut sent, _notes) = duplex_handle();
				let pulse = Pulse::paced(clock, DEFAULT_OPERATION_TIMEOUT);
				let handle = MuxHandle::new(handle.link.with_pulse(pulse));
				let mut keepalive = Box::pin(handle.keep_alive());

				let ended = poll_now(&mut keepalive);
				let refused = matches!(
					ended,
					Poll::Ready(TransportError::OperationFailed(TransportFailure::FailedPrecondition))
				);
				assert!(refused);
				assert!(drained(&mut sent).is_empty());
			}
			cases {
				system_clock_outside_a_runtime => Arc::new(SystemClock),
				clock_that_parks => Arc::new(BlockingClock::default()),
			}
		}
	}

	/// Abandoning a duplex reply after the sink closed must reclaim the
	/// stream: without the body's drop guard the cap slot and the duplex
	/// forwarder stay pinned until the peer's trailer.
	#[test]
	fn a_dropped_body_cancels_its_abandoned_duplex_reply() -> TestResult {
		let (handle, mut sent, _notes) = duplex_handle();
		let (sink, body) = handle.open_duplex()?;
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));

		drop(body);

		assert!(matches!(next_mux(&mut sent), Some(MuxEnvelope::Open(_))));
		assert!(matches!(next_mux(&mut sent), Some(MuxEnvelope::Cancel(package)) if package.stream_id() == 1));
		assert!(handle.link.shared().take_duplex(1).is_none());
		assert!(!handle.link.shared().is_pending(1));
		Ok(())
	}

	/// An open, the target its Open record names, and the relay budget it
	/// stamps.
	type RouteCase = (fn(&MuxHandle) -> TransportResult<RequestSink>, Option<Urn<'static>>, u8);

	// An open stamps its route on the Open record of its stream: a routed
	// open names its target so a gateway responder can dispatch or splice by
	// it, an explicit spent budget reaches the Open so a peer gateway serves
	// the stream locally and never forwards it again, and the unrouted open
	// carries no target. An origin open carries the default relay budget.
	crate::tb_cases! {
		fn an_open_stamps_its_route_on_the_open_record((open, target, hops): RouteCase) -> TestResult {
			let (handle, mut sent, _notes) = duplex_handle();
			let sink = open(&handle)?;

			let closed = poll_now(sink.close());
			assert!(matches!(closed, Poll::Ready(Ok(()))));
			assert!(matches!(
				next_mux(&mut sent),
				Some(MuxEnvelope::Open(package))
					if package.target() == target.as_ref() && package.hops_remaining() == hops
			));
			Ok(())
		}
		cases {
			to_a_target => (
				|handle| handle.open_stream_to(crate::urn!("tb", "servlet:ledger")).map(|(sink, _response)| sink),
				Some(crate::urn!("tb", "servlet:ledger")),
				DEFAULT_HOP_BUDGET,
			),
			with_a_spent_relay_budget => (
				|handle| {
					let route = StreamRoute::from_parts(Some(crate::urn!("tb", "servlet:ledger")), 0);
					handle.open_stream_with_route(route).map(|(sink, _response)| sink)
				},
				Some(crate::urn!("tb", "servlet:ledger")),
				0,
			),
			local => (|handle| handle.open_stream().map(|(sink, _response)| sink), None, DEFAULT_HOP_BUDGET),
		}
	}

	/// A failed connection refuses the first push, and the body has ended
	/// with it.
	#[test]
	fn a_duplex_body_ends_when_its_open_meets_a_failed_connection() -> TestResult {
		let (handle, _sent, _notes) = duplex_handle();
		let (mut sink, mut body) = handle.open_duplex()?;
		handle.link.shared().fail_all_pending();

		let pushed = poll_now(sink.push([1u8]));
		assert!(matches!(pushed, Poll::Ready(Err(TransportError::ConnectionClosed))));
		assert!(matches!(
			body.poll_chunk_now(),
			Poll::Ready(Err(TransportError::ConnectionClosed))
		));
		Ok(())
	}

	/// The body reports what it drained under its stream ID, and it learns
	/// that ID from the slot it shares with the reservation.
	#[test]
	fn a_duplex_body_reports_drains_under_the_opened_id() -> TestResult {
		let (handle, _sent, mut notes) = duplex_handle();
		let (mut sink, mut body) = handle.open_duplex()?;
		assert!(matches!(poll_now(sink.push([1u8])), Poll::Ready(Ok(()))));

		let mut forwarder = handle.link.shared().take_duplex(1).ok_or("the open registered the forwarder")?;
		assert!(forwarder.accept_and_forward([7u8]));

		let chunk = body.poll_chunk_now();
		assert!(matches!(chunk, Poll::Ready(Ok(Some(_)))));
		assert!(matches!(notes.try_recv(), Ok(note) if note.stream_id == 1 && note.consumed == 1));
		Ok(())
	}

	/// An end of a link and the test of the error it ends an unopened stream
	/// with.
	type LinkEndCase = (fn(&MuxShared), fn(&TransportError) -> bool);

	// A stream that is reserved and not yet opened ends with its link, even
	// while its sink is alive and has pushed nothing: a failed connection
	// ends it as closed, and a GoAway in either direction ends admission, so
	// it ends as draining.
	crate::tb_cases! {
		fn an_unopened_response_ends_with_its_link((end, ended_as): LinkEndCase) -> TestResult {
			let (handle, _sent, _notes) = duplex_handle();
			let (_sink, response) = handle.open_stream()?;
			end(handle.link.shared());

			let ended = poll_now(response);
			assert!(matches!(&ended, Poll::Ready(Err(error)) if ended_as(error)));
			Ok(())
		}
		cases {
			on_a_connection_failure => (
				MuxShared::fail_all_pending,
				|error| matches!(error, TransportError::ConnectionClosed),
			),
			on_a_local_shutdown => (
				|shared| {
					shared.begin_shutdown();
				},
				|error| matches!(error, TransportError::Draining),
			),
		}
	}

	// An unopened duplex body ends with its link as an unopened response
	// does.
	crate::tb_cases! {
		fn an_unopened_duplex_body_ends_with_its_link((end, ended_as): LinkEndCase) -> TestResult {
			let (handle, _sent, _notes) = duplex_handle();
			let (_sink, mut body) = handle.open_duplex()?;
			end(handle.link.shared());

			let ended = body.poll_chunk_now();
			assert!(matches!(&ended, Poll::Ready(Err(error)) if ended_as(error)));
			Ok(())
		}
		cases {
			on_a_connection_failure => (
				MuxShared::fail_all_pending,
				|error| matches!(error, TransportError::ConnectionClosed),
			),
			on_a_peer_goaway => (receive_goaway, |error| matches!(error, TransportError::Draining)),
		}
	}

	/// A sink dropped before its first push cancels a stream that never
	/// opened, and its body reads that as a cancel on a connection that still
	/// runs.
	#[test]
	fn an_unopened_duplex_body_ends_cancelled_when_its_sink_drops() -> TestResult {
		let (handle, _sent, _notes) = duplex_handle();
		let (sink, mut body) = handle.open_duplex()?;
		drop(sink);

		assert!(matches!(
			body.poll_chunk_now(),
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)))
		));
		Ok(())
	}

	/// A resolved reply disarms the guard: dropping the body after its
	/// terminal event sends no cancel.
	#[test]
	fn a_terminal_body_disarms_its_drop_cancel() -> TestResult {
		let (handle, mut sent, _notes) = duplex_handle();
		let (sink, mut body) = handle.open_duplex()?;
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));

		let shared = handle.link.shared();
		let mut forwarder = shared.take_duplex(1).ok_or("open_duplex registered the forwarder")?;
		// The reply ledger entry is dropped so the terminal event alone, and
		// no pending reply, decides what the drop guard sees.
		let _ = shared.remove_pending(1);
		assert!(forwarder.forward(BodyEvent::End));
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));

		drop(body);

		assert!(matches!(next_mux(&mut sent), Some(MuxEnvelope::Open(_))));
		assert!(sent.try_recv().is_err());
		Ok(())
	}

	/// A response future that drops before its first poll cancels its stream,
	/// so the stream leaves the pending table.
	#[test]
	fn an_unpolled_response_cancels_its_stream_when_it_drops() -> TestResult {
		let (handle, _sent, _notes) = duplex_handle();
		let (mut sink, response) = handle.open_stream()?;
		assert!(matches!(poll_now(sink.push(b"open")), Poll::Ready(Ok(()))));

		drop(response);

		assert!(!handle.link.shared().is_pending(1));
		Ok(())
	}

	/// Whether `outcome` refused its wait for a clock with no timer on the
	/// polling thread.
	#[cfg(feature = "tokio")]
	fn refused_for_no_timer<T>(outcome: &Poll<TransportResult<T>>) -> bool {
		let Poll::Ready(Err(TransportError::OperationFailed(failure))) = outcome else {
			return false;
		};

		*failure == TransportFailure::FailedPrecondition
	}

	/// A client handle on a link whose clock has no timer on a thread outside
	/// any tokio runtime, beside the receiver of its outbound queue.
	#[cfg(feature = "tokio")]
	fn timerless_handle() -> (MuxHandle, mpsc::Receiver<Outbound>) {
		let (handle, sent, _notes) = duplex_handle();
		let pulse = Pulse::paced(Arc::new(SystemClock), DEFAULT_OPERATION_TIMEOUT);
		(MuxHandle::new(handle.link.with_pulse(pulse)), sent)
	}

	/// The reply wait of an emit refuses on a clock with no timer for the
	/// polling thread, as each bound of the transport does.
	#[cfg(feature = "tokio")]
	#[test]
	fn an_emit_reply_wait_with_no_timer_refuses() {
		let (handle, _sent) = timerless_handle();
		let frame = TestFrame::v0(None, None);

		let emitted = poll_now(handle.emit_on_stream(&frame));
		assert!(refused_for_no_timer(&emitted));
	}

	/// The reply wait of a streamed request refuses on such a clock once the
	/// request closes.
	#[cfg(feature = "tokio")]
	#[test]
	fn a_streamed_reply_wait_with_no_timer_refuses_after_the_close() -> TestResult {
		let (handle, _sent) = timerless_handle();
		let (sink, response) = handle.open_stream()?;
		assert!(matches!(poll_now(sink.close()), Poll::Ready(Ok(()))));

		let answered = poll_now(response);
		assert!(refused_for_no_timer(&answered));
		Ok(())
	}

	/// A client handle on `settings` under a nine-second read deadline on the
	/// tokio clock, beside the receiver of its outbound queue.
	#[cfg(feature = "tokio")]
	fn paced_handle(settings: &MuxSettings) -> (MuxHandle, mpsc::Receiver<Outbound>) {
		let shared = MuxShared::fixture(MuxRole::Client, settings);
		let (link, sent, _notes) = MuxLink::over(shared, 8);
		let pulse = Pulse::paced(Arc::new(SystemClock), Duration::from_secs(9));
		(MuxHandle::new(link.with_pulse(pulse)), sent)
	}

	/// The reason of the cancel of stream 1 among the commands on `sent`.
	#[cfg(feature = "tokio")]
	fn cancel_reason(sent: &mut mpsc::Receiver<Outbound>) -> Option<CancelReason> {
		drained(sent)
			.into_iter()
			.filter_map(Outbound::into_mux)
			.find_map(|envelope| match envelope {
				MuxEnvelope::Cancel(cancel) if cancel.stream_id() == 1 => Some(cancel.reason()),
				_ => None,
			})
	}

	/// An emit whose response misses the read deadline cancels its stream
	/// with `Timeout`.
	#[cfg(feature = "tokio")]
	#[tokio::test(start_paused = true)]
	async fn an_emit_past_its_reply_deadline_cancels_with_timeout() {
		let (handle, mut sent) = paced_handle(&MuxSettings::symmetric(FIXTURE_PEER_CAP));
		// The emit fails with `DeadlineExceeded`, and the test reads the
		// cancel that it leaves on the queue.
		let _lapsed = handle.emit_on_stream(&TestFrame::v0(None, None)).await;
		assert_eq!(cancel_reason(&mut sent), Some(CancelReason::Timeout));
	}

	/// An emit whose chunk waits on credit past the read deadline cancels its
	/// stream with `Timeout`.
	#[cfg(feature = "tokio")]
	#[tokio::test(start_paused = true)]
	async fn an_emit_past_its_credit_deadline_cancels_with_timeout() {
		let settings = MuxSettings::symmetric(FIXTURE_PEER_CAP)
			.with_chunk_size(MIN_MUX_CHUNK_SIZE)
			.with_initial_credit(1);

		let (handle, mut sent) = paced_handle(&settings);
		let label = "w".repeat(2 * MIN_MUX_CHUNK_SIZE as usize);

		// The emit fails with `DeadlineExceeded`, and the test reads the
		// cancel that it leaves on the queue.
		let _lapsed = handle.emit_on_stream(&TestFrame::v0(Some(&label), None)).await;

		assert_eq!(cancel_reason(&mut sent), Some(CancelReason::Timeout));
	}

	/// A streamed request whose response misses the read deadline after the
	/// close cancels its stream with `Timeout`.
	#[cfg(feature = "tokio")]
	#[tokio::test(start_paused = true)]
	async fn a_streamed_reply_past_its_deadline_cancels_with_timeout() -> TestResult {
		let (handle, mut sent) = paced_handle(&MuxSettings::symmetric(FIXTURE_PEER_CAP));
		let (sink, response) = handle.open_stream()?;
		sink.close().await?;

		// The response fails with `DeadlineExceeded`, and the test reads the
		// cancel that it leaves on the queue.
		let _lapsed = response.await;

		assert_eq!(cancel_reason(&mut sent), Some(CancelReason::Timeout));
		Ok(())
	}
}
