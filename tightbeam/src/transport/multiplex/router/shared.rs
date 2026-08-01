//! Connection-wide shared state: stream allocation, sender-side flow
//! control, budgets, GoAway drain, and rekey phase tracking.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use core::task::{Context, Poll, Waker};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures::channel::{mpsc, oneshot};

use super::body::{BodyEvent, ForwardedStream};
use super::flow::cap_as_usize;
use super::outbound::{outbound_handle, Outbound};
use crate::transport::envelopes::{
	CancelReason, GoAwayReason, MuxCancelPackage, MuxOpenPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::error::TransportFailure;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::multiplex::MuxRole;
use crate::transport::{TransportError, TransportResult};
use crate::utils::urn::Urn;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::StoredReceipt;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;

fn wake_all(wakers: &mut Vec<Waker>) {
	for waker in wakers.drain(..) {
		waker.wake();
	}
}

/// Register `cx`'s waker. Waker clone is a refcount bump, not a data copy.
pub(super) fn park_waker(waiters: &mut Vec<Waker>, cx: &Context<'_>) {
	waiters.push(cx.waker().clone());
}

/// Identity of a locally-initiated stream whose ID is assigned at
/// first send (atomic open): vacant until the Open record enqueues,
/// the assigned ID afterwards. Stream IDs start at 1 (client) or 2
/// (server), so zero unambiguously means "not opened yet".
///
/// Shared between the parts that outlive the open (sinks, response
/// futures, reply bodies, cancel guards) so each can act on the real
/// ID once it exists and stand down when it never did.
pub(super) struct OpenSlot(AtomicU32);

impl OpenSlot {
	const VACANT: u32 = 0;

	fn vacant() -> Arc<Self> {
		Arc::new(Self(AtomicU32::new(Self::VACANT)))
	}

	/// Slot for a stream whose ID is already known (peer-initiated
	/// bodies, replies): assigned from birth.
	pub(super) fn assigned(stream_id: u32) -> Arc<Self> {
		Arc::new(Self(AtomicU32::new(stream_id)))
	}

	fn assign(&self, stream_id: u32) {
		self.0.store(stream_id, AtomicOrdering::Release);
	}

	pub(super) fn get(&self) -> Option<u32> {
		match self.0.load(AtomicOrdering::Acquire) {
			Self::VACANT => None,
			stream_id => Some(stream_id),
		}
	}
}

/// A cap slot held for a stream that has not sent its Open record
/// yet. The stream ID is assigned inside [`MuxShared::poll_open_enqueue`],
/// in the same critical section that enqueues the Open, so Opens hit
/// the wire in strictly increasing ID order
/// ([RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1))
/// no matter how initiations interleave.
///
/// Dropping an unopened reservation releases the cap slot and resolves the
/// response future as locally cancelled. Once opened, the pending table owns
/// the stream's lifecycle and the drop is a no-op.
pub(super) struct StreamReservation {
	shared: Arc<MuxShared>,
	sender: Option<oneshot::Sender<StreamOutcome>>,
	slot: Arc<OpenSlot>,
}

impl StreamReservation {
	/// Handle to the stream's late-assigned identity (refcount bump).
	pub(super) fn slot(&self) -> Arc<OpenSlot> {
		Arc::clone(&self.slot)
	}
}

impl Drop for StreamReservation {
	fn drop(&mut self) {
		let Some(sender) = self.sender.take() else {
			return;
		};

		let _ = sender.send(StreamOutcome::Cancelled(CancelReason::Cancelled));
		let mut state = self.shared.lock();
		state.reserved = state.reserved.saturating_sub(1);
		state.wake_slot_waiters();
	}
}

/// One stream's Open record, handed to
/// [`MuxShared::poll_open_enqueue`]. `records` seeds the sender
/// ledger (the payload's chunk count, or the whole message's for a
/// unary emit); `duplex` carries the reply forwarder to register
/// under the assigned ID before the Open can reach the peer.
pub(super) struct OpenRequest<'a> {
	pub(super) kind: MuxStreamKind,
	pub(super) last: bool,
	pub(super) payload: &'a [u8],
	pub(super) records: u64,
	pub(super) duplex: Option<ForwardedStream>,
	/// Grpc-style route stamped on the Open record, or `None` for an
	/// unrouted local open.
	pub(super) target: Option<Urn<'static>>,
	/// Loop guard stamped beside the route: a forwarded open is
	/// served locally and never re-forwarded.
	pub(super) forwarded: bool,
}

/// Outcome delivered to a pending stream's oneshot slot.
pub(super) enum StreamOutcome {
	/// Correlated response arrived
	Response(ResponsePackage),
	/// Peer cancelled or refused the stream
	Cancelled(CancelReason),
	/// Peer sent GoAway with `last_stream_id` below this stream
	Draining,
}

pub(super) fn cancel_error(reason: CancelReason) -> TransportError {
	match reason {
		CancelReason::Cancelled => TransportError::OperationFailed(TransportFailure::Cancelled),
		CancelReason::Timeout => TransportError::OperationFailed(TransportFailure::DeadlineExceeded),
		CancelReason::Rejected => TransportError::OperationFailed(TransportFailure::ResourceExhausted),
		// An app-coded cancel is still a cancel. The code itself
		// carries no transport-failure mapping of its own
		CancelReason::Application(_) => TransportError::OperationFailed(TransportFailure::Cancelled),
	}
}

/// Resolve a locally-initiated stream as cancelled and notify the
/// peer: the local teardown shared by every abandoned send path
/// (drop guards, abandoned sinks, explicit close).
///
/// The wire cancel travels on a fresh sender clone, whose guaranteed
/// slot (channel capacity = buffer + senders) admits it even when the
/// queue is otherwise full. The only unreachable case is a
/// disconnected queue, where the writer - and the connection - are
/// already gone.
pub(super) fn enqueue_stream_cancel(shared: &MuxShared, outbound: &mpsc::Sender<Outbound>, stream_id: u32) {
	if let Some(mut forwarder) = shared.take_duplex(stream_id) {
		let _ = forwarder.forward(BodyEvent::Failed(cancel_error(CancelReason::Cancelled)));
	}
	if let Some(sender) = shared.remove_pending(stream_id) {
		let _ = sender.send(StreamOutcome::Cancelled(CancelReason::Cancelled));
		let package = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
		let _ = outbound_handle(outbound).try_send(Outbound::Envelope(package.into()));
	}
}

/// Client-side renewal state (key-switch boundaries). Server
/// endpoints and sessions without rekey materials stay `Idle` forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RekeyPhase {
	/// No renewal in flight
	Idle,
	/// `RekeyRequest` written; awaiting the server's response
	AwaitingResponse,
	/// Response verified; new c2s admissions park while owed chunks
	/// flush ahead of the `RekeyAck`
	FlushingAck,
	/// `RekeyAck` written (send cipher switched); c2s parked until
	/// `RekeyDone` activates the fresh epoch budget
	AwaitingDone,
}

/// Disposition of an incoming peer-initiated stream.
pub(super) enum PeerStream {
	Accept,
	/// GoAway already sent and the stream is newer than its
	/// `last_stream_id`. Refuse without processing.
	RejectDraining,
}

/// Sender-side flow-control ledger for one stream direction (QUIC
/// MAX_STREAM_DATA,
/// [RFC 9000 § 4.1](https://datatracker.ietf.org/doc/html/rfc9000#section-4.1)).
/// Requests and responses on the same stream never collide here: an
/// endpoint sends request chunks only on IDs it allocated and response
/// chunks only on IDs the peer allocated.
struct SendStream {
	/// Chunks already permitted onto the outbound queue
	sent: u64,
	/// Absolute cumulative chunk limit granted by the peer
	limit: u64,
	/// Registered chunks not yet permitted (drain accounting)
	unsent: u64,
	/// Wakers parked until the peer raises the limit
	credit_wakers: Vec<Waker>,
}

/// Outcome of an outbound session-budget debit.
pub(super) enum BudgetStanding {
	/// Spendable credits remain, or the session is unmetered
	Healthy,
	/// The balance fell to the drain reserve: trigger the
	/// [`GoAwayReason::BudgetExhausted`] drain
	Exhausting,
}

struct MuxState {
	/// Next locally-initiated stream ID. `None` once the ID space is
	/// exhausted (strictly monotonic, never reuses, never allocates 0)
	next_stream_id: Option<u32>,
	/// Highest peer-initiated stream ID seen (0 = none yet)
	last_peer_stream_id: u32,
	/// Open locally-initiated streams awaiting their response.
	/// Together with `reserved` this is the cap-relevant
	/// open-stream count
	pending: BTreeMap<u32, oneshot::Sender<StreamOutcome>>,
	/// Cap slots held by initiations that have not sent their Open
	/// record yet (see [`StreamReservation`]): IDs are assigned at
	/// first send so Opens hit the wire in ID order
	reserved: usize,
	/// Next correlation value for a locally-initiated ping
	next_ping_opaque: u64,
	/// Local pings awaiting their ack, keyed by correlation value
	pending_pings: BTreeMap<u64, oneshot::Sender<()>>,
	/// Sender-side per-stream flow-control ledgers
	send_streams: HashMap<u32, SendStream>,
	/// Credits left in the outbound session budget. `None` = unmetered
	send_budget: Option<u64>,
	/// Chunks registered by producers but not yet permitted, across
	/// all streams. Added to the writer's drain headroom so owed
	/// chunks always fit inside the remaining records
	unsent_chunks: u64,
	/// `last_stream_id` advertised in our GoAway, once sent
	goaway_sent: Option<u32>,
	/// `last_stream_id` received in the peer's GoAway
	goaway_received: Option<u32>,
	/// Reason carried by the peer's GoAway, once received. Local
	/// shutdown leaves this empty: the caller already knows why
	goaway_reason: Option<GoAwayReason>,
	/// Wakers parked on pending-table drain (shutdown)
	drain_wakers: Vec<Waker>,
	/// Wakers parked on stream-slot headroom (cap full)
	slot_wakers: Vec<Waker>,
	/// In-band renewal state. Only a client with rekey materials
	/// ever leaves `Idle`
	rekey: RekeyPhase,
	/// Renewal in flight with send records down to the drain
	/// headroom: data chunks park until the fresh cipher installs
	rekey_hard_floor: bool,
	/// Whether this endpoint can open renewals (client role with
	/// rekey materials attached)
	rekey_client: bool,
	/// Wakers parked on renewal transitions: admissions waiting out
	/// a renewal, chunks on the hard floor, and the writer waiting
	/// for owed chunks to quiesce ahead of the `RekeyAck`
	rekey_wakers: Vec<Waker>,
}

impl MuxState {
	fn wake_drain_waiters(&mut self) {
		wake_all(&mut self.drain_wakers);
	}

	fn wake_slot_waiters(&mut self) {
		wake_all(&mut self.slot_wakers);
	}

	pub(super) fn wake_rekey_waiters(&mut self) {
		wake_all(&mut self.rekey_wakers);
	}

	/// A GoAway in either direction puts the connection in drain.
	pub(super) fn is_draining(&self) -> bool {
		self.goaway_sent.is_some() || self.goaway_received.is_some()
	}

	/// Cap-relevant open-stream count: streams awaiting their
	/// response plus reservations that have not opened yet.
	fn open_load(&self) -> usize {
		self.pending.len().saturating_add(self.reserved)
	}

	fn reject_if_draining(&self) -> TransportResult<()> {
		if self.is_draining() {
			return Err(TransportError::Draining);
		}

		Ok(())
	}
}

pub(super) struct MuxShared {
	pub(super) role: MuxRole,
	state: Mutex<MuxState>,
	pub(super) local_cap: u32,
	/// Largest chunk payload this endpoint may send (peer-advertised)
	pub(super) send_chunk_size: usize,
	/// Bytes per session-budget credit (negotiated, both directions)
	pub(super) credit_unit: u32,
	/// Initial per-stream chunk limit for outbound data
	/// (peer-advertised)
	initial_send_credit: u64,
	/// Initial per-stream chunk limit granted to the peer (local
	/// receive window; duplex reply bodies size from it)
	pub(super) initial_recv_credit: u64,
	/// Connection collector inherited from the split halves;
	/// control-plane events land here
	/// (see [`crate::instrumentation::events`]).
	#[cfg(feature = "instrument")]
	pub(super) trace: Option<TraceCollector>,
	/// Reply forwarders for locally-initiated duplex streams,
	/// registered by
	/// [`MuxHandle::open_duplex`](super::handle::MuxHandle::open_duplex)
	/// and driven by the reader (response chunks forward instead of
	/// reassembling).
	///
	/// Forwarder registries partition by initiator: this map holds
	/// only locally-initiated stream IDs, the reader's
	/// `peer_bodies` only peer-initiated ones. Every teardown path
	/// (cancel, GoAway, connection failure) must clear its side of
	/// both registries.
	duplex_recv: Mutex<HashMap<u32, ForwardedStream>>,
	/// Credits reserved so owed traffic can flush during a budget
	/// drain. See [`MuxSettings::send_budget_reserve`]
	budget_drain_headroom: u64,
	/// Negotiated outbound budget, restored at each epoch boundary
	/// (credit-match invariant: epoch receipt budgets equal the
	/// initial terms)
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	initial_send_budget: Option<u64>,
	/// Current epoch's dual-signed receipt; renewal rotates it
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	session_receipt: Mutex<Option<Arc<StoredReceipt>>>,
}

impl MuxShared {
	pub(super) fn new(role: MuxRole, settings: &MuxSettings) -> Self {
		Self {
			role,
			local_cap: settings.local_initiated_cap,
			send_chunk_size: cap_as_usize(settings.send_chunk_size).max(1),
			credit_unit: settings.credit_unit.max(1),
			initial_send_credit: settings.initial_send_credit.max(1),
			initial_recv_credit: settings.initial_recv_credit.max(1),
			duplex_recv: Mutex::new(HashMap::new()),
			budget_drain_headroom: settings.send_budget_reserve(),
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			initial_send_budget: settings.send_budget,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			session_receipt: Mutex::new(None),
			#[cfg(feature = "instrument")]
			trace: None,
			state: Mutex::new(MuxState {
				next_stream_id: Some(role.first_local_stream_id()),
				last_peer_stream_id: 0,
				pending: BTreeMap::new(),
				reserved: 0,
				next_ping_opaque: 0,
				pending_pings: BTreeMap::new(),
				send_streams: HashMap::new(),
				send_budget: settings.send_budget,
				unsent_chunks: 0,
				goaway_sent: None,
				goaway_received: None,
				goaway_reason: None,
				drain_wakers: Vec::new(),
				slot_wakers: Vec::new(),
				rekey: RekeyPhase::Idle,
				rekey_hard_floor: false,
				rekey_client: false,
				rekey_wakers: Vec::new(),
			}),
		}
	}

	fn lock(&self) -> MutexGuard<'_, MuxState> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Future resolving once a locally-initiated stream would be
	/// admitted (refcount bump).
	pub(super) fn stream_slot(self: &Arc<Self>) -> StreamSlot {
		StreamSlot { shared: Arc::clone(self) }
	}

	/// Future resolving once the pending table drains (refcount bump).
	pub(super) fn drain_pending(self: &Arc<Self>) -> DrainPending {
		DrainPending { shared: Arc::clone(self) }
	}

	fn duplex_lock(&self) -> MutexGuard<'_, HashMap<u32, ForwardedStream>> {
		self.duplex_recv.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Register the reply forwarder for a locally-initiated duplex
	/// stream.
	pub(super) fn insert_duplex(&self, stream_id: u32, forwarder: ForwardedStream) {
		self.duplex_lock().insert(stream_id, forwarder);
	}

	/// Detach a duplex reply forwarder (stream resolving).
	pub(super) fn take_duplex(&self, stream_id: u32) -> Option<ForwardedStream> {
		self.duplex_lock().remove(&stream_id)
	}

	/// Forward one reply chunk into a duplex body. `None` when the
	/// stream is not duplex; `Some(false)` on a credit overrun.
	pub(super) fn forward_duplex_chunk(&self, stream_id: u32, payload: &[u8]) -> Option<bool> {
		let mut map = self.duplex_lock();
		let stream = map.get_mut(&stream_id)?;
		let accepted = stream.accept_and_forward(payload);

		Some(accepted)
	}

	/// Granted limit and window of a duplex reply body, when live.
	pub(super) fn duplex_limits(&self, stream_id: u32) -> Option<(u64, u64)> {
		let map = self.duplex_lock();
		let stream = map.get(&stream_id)?;

		Some(stream.limits())
	}

	/// Raise a duplex reply body's granted limit.
	pub(super) fn set_duplex_limit(&self, stream_id: u32, limit: u64) {
		if let Some(stream) = self.duplex_lock().get_mut(&stream_id) {
			stream.raise_limit(limit);
		}
	}

	/// Fail duplex replies the peer's GoAway disowned (streams above
	/// its high-water mark will never be answered).
	pub(super) fn fail_duplex_above(&self, last_stream_id: u32) {
		let mut map = self.duplex_lock();
		map.retain(|stream_id, stream| {
			if *stream_id <= last_stream_id {
				return true;
			}
			let _ = stream.forward(BodyEvent::Failed(TransportError::Draining));

			false
		});
	}

	/// Drop every duplex reply forwarder on connection failure; the
	/// bodies observe the closed channel.
	fn fail_all_duplex(&self) {
		self.duplex_lock().clear();
	}

	/// Drop a stream's sender ledger under the lock: return its
	/// unflushed chunks to the drain accounting and wake any parked
	/// producer so it observes the removal.
	fn drop_send_stream(state: &mut MuxState, stream_id: u32) {
		if let Some(stream) = state.send_streams.remove(&stream_id) {
			state.unsent_chunks = state.unsent_chunks.saturating_sub(stream.unsent);
			for waker in stream.credit_wakers {
				waker.wake();
			}
			Self::wake_on_quiesce(state);
		}
	}

	/// Wake the writer once owed chunks quiesce while it holds a
	/// `RekeyAck` back (the ack trails every old-epoch chunk).
	fn wake_on_quiesce(state: &mut MuxState) {
		if state.unsent_chunks == 0 && state.rekey == RekeyPhase::FlushingAck {
			state.wake_rekey_waiters();
		}
	}

	/// Register the sender-side ledger for a stream about to carry
	/// `chunks` outbound chunk records.
	pub(super) fn register_send_stream(&self, stream_id: u32, chunks: u64) {
		let mut state = self.lock();
		state.unsent_chunks = state.unsent_chunks.saturating_add(chunks);
		state.send_streams.insert(
			stream_id,
			SendStream {
				sent: 0,
				limit: self.initial_send_credit,
				unsent: chunks,
				credit_wakers: Vec::new(),
			},
		);
	}

	/// Drop a stream's sender ledger outside the pending-table paths
	/// (response streams, abandoned sends).
	pub(super) fn finish_send_stream(&self, stream_id: u32) {
		let mut state = self.lock();
		Self::drop_send_stream(&mut state, stream_id);
	}

	/// Extend a registered sender ledger by `chunks` outbound
	/// records: streamed replies learn their length one push at a
	/// time. A missing ledger means the stream already resolved
	/// (cancel or failure); the send path reports that itself.
	pub(super) fn add_send_records(&self, stream_id: u32, chunks: u64) {
		let mut state = self.lock();
		let Some(stream) = state.send_streams.get_mut(&stream_id) else {
			return;
		};
		stream.unsent = stream.unsent.saturating_add(chunks);
		state.unsent_chunks = state.unsent_chunks.saturating_add(chunks);
	}

	/// Consume one unit of stream credit under the lock, or park.
	/// Fails once the ledger is gone: the stream resolved underneath
	/// the sender (cancel, response, or connection failure) and the
	/// outcome channel has the truth.
	fn take_chunk_credit(state: &mut MuxState, stream_id: u32, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let Some(stream) = state.send_streams.get_mut(&stream_id) else {
			return Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)));
		};
		if stream.sent >= stream.limit {
			park_waker(&mut stream.credit_wakers, cx);
			return Poll::Pending;
		}

		stream.sent = stream.sent.saturating_add(1);
		stream.unsent = stream.unsent.saturating_sub(1);
		state.unsent_chunks = state.unsent_chunks.saturating_sub(1);
		Self::wake_on_quiesce(state);

		Poll::Ready(Ok(()))
	}

	/// Resolve once the peer's grant admits the stream's next chunk,
	/// consuming one unit of credit.
	#[cfg(test)]
	pub(super) fn poll_send_chunk(&self, stream_id: u32, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let mut state = self.lock();
		Self::take_chunk_credit(&mut state, stream_id, cx)
	}

	/// Consume one unit of stream credit and enqueue the chunk's
	/// envelope in one critical section, so no data envelope can
	/// slip into the queue behind a rekey `RekeyAck` boundary
	/// (strict park). The caller MUST have reserved queue
	/// capacity via `poll_ready` on `outbound` first.
	///
	/// Chunks additionally park on the rekey hard floor: send
	/// records at the drain headroom with a renewal in flight are
	/// reserved for control and the exchange legs.
	pub(super) fn poll_send_enqueue(
		&self,
		stream_id: u32,
		outbound: &mut mpsc::Sender<Outbound>,
		envelope: &mut Option<TransportEnvelope>,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<()>> {
		let mut state = self.lock();
		if state.rekey_hard_floor {
			park_waker(&mut state.rekey_wakers, cx);
			return Poll::Pending;
		}

		match Self::take_chunk_credit(&mut state, stream_id, cx) {
			Poll::Ready(Ok(())) => {}
			other => return other,
		}

		let Some(envelope) = envelope.take() else {
			return Poll::Ready(Err(TransportError::ConnectionClosed));
		};
		let enqueued = outbound
			.start_send(Outbound::Envelope(envelope))
			.map_err(|_| TransportError::ConnectionClosed);

		Poll::Ready(enqueued)
	}

	/// Apply a peer credit grant (idempotent, monotonic: only a limit
	/// above the current one changes anything). Grants for unknown
	/// streams are discarded: a grant racing stream completion is
	/// benign.
	pub(super) fn apply_credit_grant(&self, stream_id: u32, limit: u64) {
		let mut state = self.lock();
		let Some(stream) = state.send_streams.get_mut(&stream_id) else {
			return;
		};
		if limit <= stream.limit {
			return;
		}

		stream.limit = limit;
		for waker in stream.credit_wakers.drain(..) {
			waker.wake();
		}
	}

	/// Debit `credits` from the budget in `state`.
	///
	/// `reserved` spends into the drain reserve. Non-reserved debits
	/// fail fast once the spendable balance above the reserve cannot
	/// cover them, keeping the reserve intact for the drain.
	fn debit_budget(
		state: &mut MuxState,
		headroom: u64,
		credits: u64,
		reserved: bool,
	) -> TransportResult<BudgetStanding> {
		let Some(balance) = state.send_budget else {
			return Ok(BudgetStanding::Healthy);
		};

		let spendable = if reserved {
			balance
		} else {
			balance.saturating_sub(headroom)
		};
		if credits > spendable {
			return Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted));
		}

		let remaining = balance.saturating_sub(credits);
		state.send_budget = Some(remaining);

		if remaining <= headroom {
			return Ok(BudgetStanding::Exhausting);
		}

		Ok(BudgetStanding::Healthy)
	}

	/// Debit `credits` from the outbound session budget (test seam
	/// over [`Self::debit_budget`]; production paths wait out
	/// renewals via [`Self::admit_debit`]).
	#[cfg(test)]
	pub(super) fn debit_send_budget(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
		let mut state = self.lock();
		Self::debit_budget(&mut state, self.budget_drain_headroom, credits, reserved)
	}

	/// Debit the outbound session budget once no renewal is in flight.
	///
	/// Client admissions park across a renewal so every debit
	/// belongs unambiguously to one epoch: budgets reset at
	/// `RekeyDone` and a debit issued mid-renewal could otherwise
	/// straddle the boundary. Draining connections skip
	/// the park: the renewal is dead and owed traffic must flush.
	pub(super) fn poll_admit_debit(
		&self,
		credits: u64,
		reserved: bool,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<BudgetStanding>> {
		let mut state = self.lock();
		let draining = state.is_draining();
		if state.rekey_client && state.rekey != RekeyPhase::Idle && !draining {
			park_waker(&mut state.rekey_wakers, cx);
			return Poll::Pending;
		}

		Poll::Ready(Self::debit_budget(&mut state, self.budget_drain_headroom, credits, reserved))
	}

	/// Debit the outbound budget, waiting out any in-flight renewal.
	pub(super) async fn admit_debit(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
		poll_fn(|cx| self.poll_admit_debit(credits, reserved, cx)).await
	}

	/// Chunks registered but not yet flushed, across all streams.
	pub(super) fn unsent_chunks(&self) -> u64 {
		self.lock().unsent_chunks
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn rekey_phase(&self) -> RekeyPhase {
		self.lock().rekey
	}

	/// Whether this endpoint may open a renewal right now: client
	/// role with rekey materials, no renewal in flight, no GoAway.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn renewal_ready(&self) -> bool {
		let state = self.lock();
		let draining = state.is_draining();

		state.rekey_client && state.rekey == RekeyPhase::Idle && !draining
	}

	/// Mark this endpoint as holding the client half of a rekey
	/// exchange: renewal triggers and admission gating activate.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn mark_rekey_client(&self) {
		self.lock().rekey_client = true;
	}

	/// Transition `Idle` to `AwaitingResponse` exactly once: `open`
	/// runs under the state lock, so concurrent triggers collapse to
	/// a single opened renewal, and an `open` failure leaves the
	/// phase untouched. `None` when a renewal is already in flight,
	/// the connection is draining, or `open` declined.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn enter_renewal<T>(&self, open: impl FnOnce() -> Option<T>) -> Option<T> {
		let mut state = self.lock();
		if state.rekey != RekeyPhase::Idle || state.is_draining() {
			return None;
		}

		let request = open()?;
		state.rekey = RekeyPhase::AwaitingResponse;

		Some(request)
	}

	/// Whether owed c2s chunks have quiesced (nothing registered but
	/// unflushed). Parks `cx` on the rekey waker set otherwise, so the
	/// caller re-polls when the last owed chunk flushes.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn poll_chunks_quiesced(&self, cx: &Context<'_>) -> bool {
		let mut state = self.lock();
		if state.unsent_chunks == 0 {
			return true;
		}

		park_waker(&mut state.rekey_wakers, cx);
		false
	}

	/// Park new c2s admissions while owed chunks flush ahead of the
	/// `RekeyAck` (client, on a verified `RekeyResponse`).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn begin_ack_flush(&self) {
		let mut state = self.lock();
		state.rekey = RekeyPhase::FlushingAck;
		// Owed chunks may already be quiescent: give the writer its
		// wake now rather than waiting for a ledger transition
		Self::wake_on_quiesce(&mut state);
	}

	/// Send cipher active after Ack; lifts the hard-floor park.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn mark_ack_written(&self) {
		let mut state = self.lock();
		state.rekey = RekeyPhase::AwaitingDone;
		state.rekey_hard_floor = false;
		state.wake_rekey_waiters();
	}

	/// Close the renewal (fresh epoch active, or the attempt died):
	/// admissions resume, hard floor lifts, parked tasks wake.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn finish_renewal(&self) {
		let mut state = self.lock();
		state.rekey = RekeyPhase::Idle;
		state.rekey_hard_floor = false;
		state.wake_rekey_waiters();
	}

	/// Park data chunks: send records are down to the drain
	/// headroom while a renewal is in flight, and what remains is
	/// reserved for control and the exchange legs.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn park_hard_floor(&self) {
		self.lock().rekey_hard_floor = true;
	}

	/// Restore the outbound budget to the negotiated terms at the
	/// `RekeyDone` boundary (credit-match invariant keeps the epoch
	/// receipt's terms equal to the initial ones).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn reset_send_budget(&self) {
		self.lock().send_budget = self.initial_send_budget;
	}

	/// Publish the completed epoch receipt to handle accessors.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn rotate_receipt(&self, receipt: StoredReceipt) {
		let mut slot = self.session_receipt.lock().unwrap_or_else(PoisonError::into_inner);
		*slot = Some(Arc::new(receipt));
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
		let slot = self.session_receipt.lock().unwrap_or_else(PoisonError::into_inner);
		slot.as_ref().map(Arc::clone)
	}

	/// Dual-write a control-plane event: core kind URN into the
	/// instrument log, plus the stable label for spec assertions and
	/// CSP alphabets.
	#[cfg(feature = "instrument")]
	pub(super) fn emit_event(&self, event: Urn<'static>) {
		let Some(trace) = self.trace.as_ref() else {
			return;
		};

		trace.emit_event(event);
	}

	/// Record a GoAway control event: the reason name labels why and
	/// its wire code rides as the assertable value.
	#[cfg(feature = "instrument")]
	pub(super) fn emit_goaway_event(&self, event: Urn<'static>, reason: GoAwayReason) {
		let Some(trace) = self.trace.as_ref() else {
			return;
		};

		trace.emit_event_with_value(event, reason.as_str(), u32::from(reason));
	}

	fn reject_admission(&self) -> TransportResult<()> {
		match self.lock().reject_if_draining() {
			Ok(()) => Ok(()),
			Err(err) => {
				#[cfg(feature = "instrument")]
				self.emit_event(events::MUX_EMIT_DRAINING);

				Err(err)
			}
		}
	}

	/// Reserve a cap slot for a locally-initiated stream without
	/// assigning its ID: the ID is assigned when the Open record
	/// enqueues (see [`Self::poll_open_enqueue`]), so it always
	/// matches wire order. Admission (draining, cap, ID space) is
	/// checked here, at the caller-visible initiation point.
	pub(super) fn reserve_stream_slot(
		self: &Arc<Self>,
		sender: oneshot::Sender<StreamOutcome>,
	) -> TransportResult<StreamReservation> {
		self.reject_admission()?;
		let mut state = self.lock();
		if state.next_stream_id.is_none() {
			return Err(TransportError::Draining);
		}
		if state.open_load() >= cap_as_usize(self.local_cap) {
			drop(state);

			#[cfg(feature = "instrument")]
			self.emit_event(events::MUX_STREAMS_EXHAUSTED);

			return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
		}

		state.reserved = state.reserved.saturating_add(1);
		drop(state);

		Ok(StreamReservation { shared: Arc::clone(self), sender: Some(sender), slot: OpenSlot::vacant() })
	}

	/// Atomic open: assign the next stream ID and enqueue the
	/// stream's Open record in one critical section, so Opens hit
	/// the wire in strictly increasing ID order no matter how
	/// concurrent initiations interleave. The caller MUST have
	/// reserved queue capacity via `poll_ready` on `outbound` first.
	///
	/// Every precondition (rekey hard floor) is checked before the
	/// ID is consumed, so a `Pending` never burns an ID or a wire
	/// slot. The fresh ledger's initial credit is at least one, so
	/// the Open's own credit debit can never park after assignment.
	pub(super) fn poll_open_enqueue(
		&self,
		reservation: &mut StreamReservation,
		request: &mut OpenRequest<'_>,
		outbound: &mut mpsc::Sender<Outbound>,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<u32>> {
		let mut state = self.lock();
		if state.rekey_hard_floor {
			park_waker(&mut state.rekey_wakers, cx);
			return Poll::Pending;
		}

		let Some(stream_id) = state.next_stream_id else {
			return Poll::Ready(Err(TransportError::Draining));
		};
		let Some(sender) = reservation.sender.take() else {
			// Unreachable by construction: a reservation opens once.
			return Poll::Ready(Err(TransportError::InvalidState));
		};

		state.next_stream_id = stream_id.checked_add(2);
		state.reserved = state.reserved.saturating_sub(1);
		state.pending.insert(stream_id, sender);
		reservation.slot.assign(stream_id);

		// Seed the ledger, then take the Open's own credit: the
		// initial grant floor of one admits it without parking.
		state.unsent_chunks = state.unsent_chunks.saturating_add(request.records);
		state.send_streams.insert(
			stream_id,
			SendStream {
				sent: 0,
				limit: self.initial_send_credit,
				unsent: request.records,
				credit_wakers: Vec::new(),
			},
		);
		if let Poll::Ready(Err(err)) = Self::take_chunk_credit(&mut state, stream_id, cx) {
			return Poll::Ready(Err(err));
		}

		// Registered before the Open can reach the peer, so a reply
		// chunk always finds its forwarder.
		if let Some(forwarder) = request.duplex.take() {
			self.insert_duplex(stream_id, forwarder);
		}

		let package = match MuxOpenPackage::new(stream_id, request.last, request.kind, request.payload) {
			Ok(package) => package.with_route(request.target.take(), request.forwarded),
			Err(err) => return Poll::Ready(Err(TransportError::DerError(err))),
		};
		let enqueued = outbound
			.start_send(Outbound::Envelope(package.into()))
			.map_err(|_| TransportError::ConnectionClosed);

		Poll::Ready(enqueued.map(|()| stream_id))
	}

	pub(super) fn remove_pending(&self, stream_id: u32) -> Option<oneshot::Sender<StreamOutcome>> {
		let mut state = self.lock();
		let entry = state.pending.remove(&stream_id);
		if entry.is_some() {
			// The stream is over: releasing its sender ledger wakes a
			// producer still parked on credit so it stops sending
			Self::drop_send_stream(&mut state, stream_id);
			state.wake_drain_waiters();
			state.wake_slot_waiters();
		}

		entry
	}

	/// Resolve a pending stream. Unknown IDs are silently discarded
	/// (tolerates cancel/response races on the connection).
	pub(super) fn resolve(&self, stream_id: u32, outcome: StreamOutcome) {
		if let Some(sender) = self.remove_pending(stream_id) {
			let _ = sender.send(outcome);
		}
	}

	/// Register a locally-initiated ping and return its correlation
	/// value. Refused while draining: a peer that honors the GoAway
	/// contract reserves its remaining records for owed stream
	/// traffic and never acks (see [`MuxSettings::drain_reserve_records`]).
	pub(super) fn allocate_ping(&self, sender: oneshot::Sender<()>) -> TransportResult<u64> {
		self.reject_admission()?;
		let mut state = self.lock();

		let opaque = state.next_ping_opaque;
		state.next_ping_opaque = opaque.wrapping_add(1);
		state.pending_pings.insert(opaque, sender);

		Ok(opaque)
	}

	/// Resolve a pending ping. Unknown correlation values are silently
	/// discarded (stale ack racing a dropped ping future is benign).
	pub(super) fn resolve_ping(&self, opaque: u64) {
		if let Some(sender) = self.lock().pending_pings.remove(&opaque) {
			let _ = sender.send(());
		}
	}

	pub(super) fn remove_pending_ping(&self, opaque: u64) {
		self.lock().pending_pings.remove(&opaque);
	}

	pub(super) fn shutdown_begun(&self) -> bool {
		self.lock().goaway_sent.is_some()
	}

	/// Drop every pending slot on connection failure. Receivers observe
	/// cancellation. Producers parked on credit observe ledger removal.
	/// Any in-flight renewal is dead: parked admissions resume to
	/// meet the failure instead of waiting for a `RekeyDone` that
	/// will never arrive.
	pub(super) fn fail_all_pending(&self) {
		self.fail_all_duplex();

		let mut state = self.lock();
		state.pending.clear();
		state.pending_pings.clear();

		for (_, stream) in state.send_streams.drain() {
			for waker in stream.credit_wakers {
				waker.wake();
			}
		}

		state.unsent_chunks = 0;
		state.rekey = RekeyPhase::Idle;
		state.rekey_hard_floor = false;
		state.wake_drain_waiters();
		state.wake_slot_waiters();
		state.wake_rekey_waiters();
	}

	/// Resolve pending streams above `last_stream_id` as draining
	/// (peer GoAway: it will never process them). Records the peer's
	/// reason for [`MuxShared::goaway_reason`].
	pub(super) fn fail_pending_above(&self, last_stream_id: u32, reason: GoAwayReason) {
		{
			let mut state = self.lock();

			state.goaway_received = Some(last_stream_id);
			state.goaway_reason = Some(reason);

			if let Some(first_dropped) = last_stream_id.checked_add(1) {
				for (_, sender) in state.pending.split_off(&first_dropped) {
					let _ = sender.send(StreamOutcome::Draining);
				}
			}

			state.wake_drain_waiters();
			state.wake_slot_waiters();
			state.wake_rekey_waiters();
		}

		#[cfg(feature = "instrument")]
		self.emit_goaway_event(events::MUX_GOAWAY_RECV, reason);
	}

	/// Halt the allocator and record the GoAway watermark.
	/// `last_stream_id` to advertise, or `None` if already shutting down.
	pub(super) fn begin_shutdown(&self) -> Option<u32> {
		let mut state = self.lock();
		if state.goaway_sent.is_some() {
			return None;
		}

		state.goaway_sent = Some(state.last_peer_stream_id);
		state.wake_slot_waiters();
		state.wake_rekey_waiters();
		Some(state.last_peer_stream_id)
	}

	/// Validate and record an incoming peer-initiated stream ID
	/// ([RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1):
	/// odd/even role match, nonzero, strictly increasing).
	pub(super) fn register_peer_stream(&self, stream_id: u32) -> TransportResult<PeerStream> {
		let mut state = self.lock();
		if !self.role.peer().initiates(stream_id) || stream_id <= state.last_peer_stream_id {
			return Err(TransportError::InvalidMessage);
		}

		state.last_peer_stream_id = stream_id;

		if let Some(last) = state.goaway_sent {
			if stream_id > last {
				return Ok(PeerStream::RejectDraining);
			}
		}

		Ok(PeerStream::Accept)
	}

	pub(super) fn last_peer_stream_id(&self) -> u32 {
		self.lock().last_peer_stream_id
	}

	pub(super) fn has_stream_headroom(&self) -> bool {
		let state = self.lock();
		let under_cap = state.open_load() < cap_as_usize(self.local_cap);
		let id_space_live = state.next_stream_id.is_some();
		let no_goaway = state.goaway_sent.is_none() && state.goaway_received.is_none();

		no_goaway && id_space_live && under_cap
	}

	pub(super) fn has_pending_streams(&self) -> bool {
		let state = self.lock();
		!state.pending.is_empty() || state.reserved > 0
	}

	pub(super) fn is_pending(&self, stream_id: u32) -> bool {
		self.lock().pending.contains_key(&stream_id)
	}

	pub(super) fn goaway_reason(&self) -> Option<GoAwayReason> {
		self.lock().goaway_reason
	}

	/// Resolve once a locally-initiated stream would be admitted, or
	/// fail with `Draining` once no stream will ever be admitted again.
	pub(super) fn poll_stream_slot(&self, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let mut state = self.lock();

		let goaway = state.is_draining();
		let id_space_dead = state.next_stream_id.is_none();
		if goaway || id_space_dead {
			return Poll::Ready(Err(TransportError::Draining));
		}

		if state.open_load() < cap_as_usize(self.local_cap) {
			return Poll::Ready(Ok(()));
		}

		park_waker(&mut state.slot_wakers, cx);

		Poll::Pending
	}
}

/// Resolves once a locally-initiated stream would be admitted. Fails
/// with `Draining` once no stream will ever be admitted again.
pub(super) struct StreamSlot {
	shared: Arc<MuxShared>,
}

impl Future for StreamSlot {
	type Output = TransportResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		self.shared.poll_stream_slot(cx)
	}
}

/// Resolves once the pending table drains (all in-flight local streams
/// completed, cancelled, or failed).
pub(super) struct DrainPending {
	shared: Arc<MuxShared>,
}

impl Future for DrainPending {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
		let mut state = self.shared.lock();
		if state.pending.is_empty() {
			return Poll::Ready(());
		}

		park_waker(&mut state.drain_wakers, cx);

		Poll::Pending
	}
}

#[cfg(test)]
mod tests {
	use super::super::body::stream_body;
	use super::super::testing::{noop_cx, poll_chunk};
	use super::*;

	use crate::transport::envelopes::MuxEnvelope;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	use crate::transport::envelopes::MuxPingPackage;

	fn shared(role: MuxRole, local_cap: u32) -> Arc<MuxShared> {
		Arc::new(MuxShared::new(role, &MuxSettings::symmetric(local_cap)))
	}

	fn shared_with_settings(role: MuxRole, settings: MuxSettings) -> Arc<MuxShared> {
		Arc::new(MuxShared::new(role, &settings))
	}

	fn slot() -> oneshot::Sender<StreamOutcome> {
		oneshot::channel().0
	}

	fn ping_slot() -> oneshot::Sender<()> {
		oneshot::channel().0
	}

	/// Open one stream through the production path: reserve, then
	/// atomically assign its ID and enqueue its Open record.
	fn open_one(shared: &Arc<MuxShared>) -> TransportResult<u32> {
		let mut reservation = shared.reserve_stream_slot(slot())?;
		let (mut outbound, _wire) = mpsc::channel(4);
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: true,
			payload: &[],
			records: 1,
			duplex: None,
			target: None,
			forwarded: false,
		};

		let mut cx = noop_cx();
		match shared.poll_open_enqueue(&mut reservation, &mut request, &mut outbound, &mut cx) {
			Poll::Ready(result) => result,
			Poll::Pending => Err(TransportError::ConnectionClosed),
		}
	}

	fn allocate_ids(shared: &Arc<MuxShared>, ids: &[u32]) {
		for &id in ids {
			assert!(matches!(open_one(shared), Ok(got) if got == id));
		}
	}

	fn allocate_ping_ids(shared: &MuxShared, ids: &[u64]) {
		for &id in ids {
			assert!(matches!(shared.allocate_ping(ping_slot()), Ok(got) if got == id));
		}
	}

	fn poll_slot(shared: &MuxShared) -> Poll<TransportResult<()>> {
		let mut cx = noop_cx();
		shared.poll_stream_slot(&mut cx)
	}

	fn assert_slot_poll(shared: &MuxShared, expect: SlotExpect) {
		let polled = poll_slot(shared);
		match expect {
			SlotExpect::ReadyOk => assert!(matches!(polled, Poll::Ready(Ok(())))),
			SlotExpect::Pending => assert!(matches!(polled, Poll::Pending)),
			SlotExpect::Draining => {
				assert!(matches!(polled, Poll::Ready(Err(TransportError::Draining))))
			}
		}
	}

	enum HeadroomSetup {
		Fresh { cap: u32 },
		AtCap { cap: u32 },
		LocalShutdown { cap: u32 },
	}

	fn prepare_headroom(setup: HeadroomSetup) -> Arc<MuxShared> {
		match setup {
			HeadroomSetup::Fresh { cap } => shared(MuxRole::Client, cap),
			HeadroomSetup::AtCap { cap } => {
				let shared = shared(MuxRole::Client, cap);
				allocate_ids(&shared, &[1]);
				shared
			}
			HeadroomSetup::LocalShutdown { cap } => {
				let shared = shared(MuxRole::Client, cap);
				shared.begin_shutdown();
				shared
			}
		}
	}

	enum GoAwaySetup {
		Live,
		PeerEnhanceYourCalm,
		LocalShutdown,
	}

	fn prepare_goaway(setup: GoAwaySetup) -> Arc<MuxShared> {
		let shared = shared(MuxRole::Client, 2);
		match setup {
			GoAwaySetup::Live => {}
			GoAwaySetup::PeerEnhanceYourCalm => {
				shared.fail_pending_above(0, GoAwayReason::EnhanceYourCalm);
			}
			GoAwaySetup::LocalShutdown => {
				shared.begin_shutdown();
			}
		}
		shared
	}

	enum SlotSetup {
		ReadyWithHeadroom,
		PendingAtCap,
		DrainingLocal,
		DrainingPeer,
	}

	enum SlotExpect {
		ReadyOk,
		Pending,
		Draining,
	}

	fn prepare_slot(setup: SlotSetup) -> Arc<MuxShared> {
		let shared = shared(MuxRole::Client, 1);
		match setup {
			SlotSetup::ReadyWithHeadroom => {}
			SlotSetup::PendingAtCap => allocate_ids(&shared, &[1]),
			SlotSetup::DrainingLocal => {
				shared.begin_shutdown();
			}
			SlotSetup::DrainingPeer => {
				shared.fail_pending_above(0, GoAwayReason::Shutdown);
			}
		}
		shared
	}

	fn assert_cancel_maps(reason: CancelReason, failure: TransportFailure) {
		let error = cancel_error(reason);
		assert!(matches!(
			error,
			TransportError::OperationFailed(got) if got == failure
		));
	}

	#[test]
	fn test_cancel_reason_error_mapping() {
		for (reason, failure) in [
			(CancelReason::Rejected, TransportFailure::ResourceExhausted),
			(CancelReason::Timeout, TransportFailure::DeadlineExceeded),
			(CancelReason::Cancelled, TransportFailure::Cancelled),
			(CancelReason::Application(0x1000), TransportFailure::Cancelled),
		] {
			assert_cancel_maps(reason, failure);
		}
	}

	/// Waker that records delivery, for slot-waiter wake assertions.
	#[derive(Default)]
	struct FlagWake {
		woken: core::sync::atomic::AtomicBool,
	}

	impl FlagWake {
		fn pair() -> (Arc<Self>, Waker) {
			let flag = Arc::new(Self::default());
			let waker = futures::task::waker(Arc::clone(&flag));

			(flag, waker)
		}

		fn woken(&self) -> bool {
			self.woken.load(core::sync::atomic::Ordering::SeqCst)
		}
	}

	impl futures::task::ArcWake for FlagWake {
		fn wake_by_ref(arc_self: &Arc<Self>) {
			arc_self.woken.store(true, core::sync::atomic::Ordering::SeqCst);
		}
	}

	#[test]
	fn test_role_allocates_monotonic_ids() {
		for (role, ids) in [(MuxRole::Client, &[1u32, 3, 5][..]), (MuxRole::Server, &[2u32, 4][..])] {
			let shared = shared(role, 8);
			allocate_ids(&shared, ids);
		}
	}

	#[test]
	fn test_cap_exhaustion_reports_busy() {
		let shared = shared(MuxRole::Client, 2);
		allocate_ids(&shared, &[1, 3]);
		assert!(matches!(
			open_one(&shared),
			Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted))
		));
	}

	#[test]
	fn test_completed_stream_frees_cap_slot() {
		let shared = shared(MuxRole::Client, 1);
		allocate_ids(&shared, &[1]);
		assert!(shared.remove_pending(1).is_some());
		allocate_ids(&shared, &[3]);
	}

	// The heart of the atomic open: whichever initiation sends its
	// Open first takes the lower ID, regardless of reservation
	// order, so Opens hit the wire in strictly increasing ID order.
	#[test]
	fn test_ids_follow_open_order_not_reservation_order() {
		let shared = shared(MuxRole::Client, 4);
		let early = shared.reserve_stream_slot(slot()).expect("fresh connection has headroom");

		assert!(matches!(open_one(&shared), Ok(1)));

		drop(early);
		assert!(matches!(open_one(&shared), Ok(3)));
	}

	#[test]
	fn test_reservation_holds_cap_slot_until_dropped() {
		let shared = shared(MuxRole::Client, 1);
		let held = shared.reserve_stream_slot(slot()).expect("fresh connection has headroom");

		assert!(matches!(
			open_one(&shared),
			Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted))
		));

		drop(held);
		assert!(matches!(open_one(&shared), Ok(1)));
	}

	// An open parked on the rekey hard floor consumes nothing: the
	// same reservation opens once the floor lifts.
	#[test]
	fn test_open_parked_on_rekey_floor_keeps_reservation() {
		let shared = shared(MuxRole::Client, 4);
		let mut reservation = shared.reserve_stream_slot(slot()).expect("fresh connection has headroom");
		let (mut outbound, _wire) = mpsc::channel(4);
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: true,
			payload: &[],
			records: 1,
			duplex: None,
			target: None,
			forwarded: false,
		};

		let mut cx = noop_cx();

		shared.lock().rekey_hard_floor = true;

		let parked = shared.poll_open_enqueue(&mut reservation, &mut request, &mut outbound, &mut cx);
		assert!(matches!(parked, Poll::Pending));

		shared.lock().rekey_hard_floor = false;

		let opened = shared.poll_open_enqueue(&mut reservation, &mut request, &mut outbound, &mut cx);
		assert!(matches!(opened, Poll::Ready(Ok(1))));
	}

	#[test]
	fn test_allocation_halts_after_shutdown() {
		let shared = shared(MuxRole::Client, 8);
		assert!(matches!(shared.begin_shutdown(), Some(0)));
		assert!(matches!(open_one(&shared), Err(TransportError::Draining)));
		assert!(shared.begin_shutdown().is_none());
	}

	#[test]
	fn test_allocation_halts_after_peer_goaway() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_pending_above(0, GoAwayReason::Shutdown);
		assert!(matches!(open_one(&shared), Err(TransportError::Draining)));
	}

	#[test]
	fn test_id_space_exhaustion_reports_draining() {
		let shared = shared(MuxRole::Client, 8);
		shared.lock().next_stream_id = Some(u32::MAX);
		allocate_ids(&shared, &[u32::MAX]);
		assert!(matches!(open_one(&shared), Err(TransportError::Draining)));
	}

	#[test]
	fn test_peer_stream_rejects_invalid_ids() {
		let server = shared(MuxRole::Server, 8);
		for id in [0u32, 2] {
			assert!(matches!(server.register_peer_stream(id), Err(TransportError::InvalidMessage)));
		}
	}

	#[test]
	fn test_peer_stream_rejects_non_increasing() {
		let server = shared(MuxRole::Server, 8);
		assert!(matches!(server.register_peer_stream(5), Ok(PeerStream::Accept)));
		assert!(matches!(server.register_peer_stream(3), Err(TransportError::InvalidMessage)));
		assert!(matches!(server.register_peer_stream(5), Err(TransportError::InvalidMessage)));
		assert!(matches!(server.register_peer_stream(7), Ok(PeerStream::Accept)));
	}

	#[test]
	fn test_peer_stream_above_goaway_watermark_refused() {
		let server = shared(MuxRole::Server, 8);
		assert!(matches!(server.register_peer_stream(1), Ok(PeerStream::Accept)));
		assert!(matches!(server.begin_shutdown(), Some(1)));
		assert!(matches!(server.register_peer_stream(3), Ok(PeerStream::RejectDraining)));
	}

	#[test]
	fn test_goaway_fails_pending_above_watermark_only() {
		let shared = shared(MuxRole::Client, 8);
		let (sender_low, mut receiver_low) = oneshot::channel();
		let (sender_high, mut receiver_high) = oneshot::channel();

		shared.lock().pending.insert(1, sender_low);
		shared.lock().pending.insert(3, sender_high);

		shared.fail_pending_above(1, GoAwayReason::Shutdown);

		assert!(matches!(receiver_low.try_recv(), Ok(None)));
		assert!(matches!(receiver_high.try_recv(), Ok(Some(StreamOutcome::Draining))));
	}

	#[test]
	fn test_ping_allocates_monotonic_opaque() {
		let shared = shared(MuxRole::Client, 8);
		allocate_ping_ids(&shared, &[0, 1, 2]);
	}

	#[test]
	fn test_ping_ack_resolves_pending() {
		let shared = shared(MuxRole::Client, 8);
		let (sender, mut receiver) = oneshot::channel();
		assert!(matches!(shared.allocate_ping(sender), Ok(0)));

		shared.resolve_ping(0);
		assert!(matches!(receiver.try_recv(), Ok(Some(()))));
	}

	#[test]
	fn test_stale_ping_ack_discarded() {
		let shared = shared(MuxRole::Client, 8);
		let (sender, mut receiver) = oneshot::channel();
		assert!(matches!(shared.allocate_ping(sender), Ok(0)));

		shared.remove_pending_ping(0);
		shared.resolve_ping(0);
		assert!(receiver.try_recv().is_err());
	}

	#[test]
	fn test_ping_refused_while_draining() {
		let shared = shared(MuxRole::Client, 8);
		shared.begin_shutdown();
		assert!(matches!(shared.allocate_ping(ping_slot()), Err(TransportError::Draining)));
	}

	#[test]
	fn test_connection_failure_fails_pending_pings() {
		let shared = shared(MuxRole::Client, 8);
		let (sender, mut receiver) = oneshot::channel();
		assert!(matches!(shared.allocate_ping(sender), Ok(0)));

		shared.fail_all_pending();
		assert!(receiver.try_recv().is_err());
	}

	#[test]
	fn test_stream_headroom() {
		for (setup, expect) in [
			(HeadroomSetup::Fresh { cap: 2 }, true),
			(HeadroomSetup::AtCap { cap: 1 }, false),
			(HeadroomSetup::LocalShutdown { cap: 2 }, false),
		] {
			let shared = prepare_headroom(setup);
			assert_eq!(shared.has_stream_headroom(), expect);
		}
	}

	#[test]
	fn test_pending_streams_track_in_flight() {
		let shared = shared(MuxRole::Client, 8);
		assert!(!shared.has_pending_streams());

		allocate_ids(&shared, &[1]);

		assert!(shared.has_pending_streams());
		assert!(shared.remove_pending(1).is_some());
		assert!(!shared.has_pending_streams());
	}

	// A reserved slot (open_stream before first push) must pin the
	// connection against idle prune the same way a pending ID does.
	#[test]
	fn test_reserved_slot_counts_as_pending() {
		let shared = shared(MuxRole::Client, 8);
		assert!(!shared.has_pending_streams());

		let reservation = shared.reserve_stream_slot(slot());
		assert!(reservation.is_ok());
		assert!(shared.has_pending_streams());

		drop(reservation);
		assert!(!shared.has_pending_streams());
	}

	#[test]
	fn test_goaway_reason_from_peer_only() {
		for (setup, expected) in [
			(GoAwaySetup::Live, None),
			(GoAwaySetup::PeerEnhanceYourCalm, Some(GoAwayReason::EnhanceYourCalm)),
			(GoAwaySetup::LocalShutdown, None),
		] {
			let shared = prepare_goaway(setup);
			assert_eq!(shared.goaway_reason(), expected);
		}
	}

	#[test]
	fn test_stream_slot_poll_outcomes() {
		for (setup, expect) in [
			(SlotSetup::ReadyWithHeadroom, SlotExpect::ReadyOk),
			(SlotSetup::PendingAtCap, SlotExpect::Pending),
			(SlotSetup::DrainingLocal, SlotExpect::Draining),
			(SlotSetup::DrainingPeer, SlotExpect::Draining),
		] {
			let shared = prepare_slot(setup);
			assert_slot_poll(&shared, expect);
		}
	}

	#[test]
	fn test_stream_slot_wakes_when_slot_frees() {
		let shared = shared(MuxRole::Client, 1);
		allocate_ids(&shared, &[1]);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Pending));

		assert!(shared.remove_pending(1).is_some());

		assert!(flag.woken());
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Ready(Ok(()))));
	}

	#[test]
	fn test_stream_slot_wakes_on_shutdown() {
		let shared = shared(MuxRole::Client, 1);
		allocate_ids(&shared, &[1]);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Pending));

		shared.begin_shutdown();

		assert!(flag.woken());
		assert!(matches!(
			shared.poll_stream_slot(&mut cx),
			Poll::Ready(Err(TransportError::Draining))
		));
	}

	fn metered_settings(initial_send_credit: u64, send_budget: Option<u64>) -> MuxSettings {
		let mut settings = MuxSettings::symmetric(4);
		settings.initial_send_credit = initial_send_credit;
		settings.send_budget = send_budget;
		settings
	}

	/// Caps 1/1, chunk 1024, unit 1024: drain headroom is 5 records
	/// priced at 1 credit each.
	fn budget_settings(send_budget: u64) -> MuxSettings {
		let mut settings = MuxSettings::symmetric(1);
		settings.send_chunk_size = 1024;
		settings.credit_unit = 1024;
		settings.send_budget = Some(send_budget);
		settings
	}

	#[test]
	fn test_send_chunk_parks_at_limit_and_resumes_on_grant() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(1, None));
		shared.register_send_stream(1, 2);

		let mut cx = noop_cx();
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Ready(Ok(()))));

		let (flag, waker) = FlagWake::pair();
		let mut parked_cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_send_chunk(1, &mut parked_cx), Poll::Pending));

		shared.apply_credit_grant(1, 2);
		assert!(flag.woken());
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Ready(Ok(()))));
	}

	#[test]
	fn test_send_chunk_fails_after_ledger_drop() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(1, None));
		shared.register_send_stream(1, 1);
		shared.finish_send_stream(1);

		let mut cx = noop_cx();
		assert!(matches!(
			shared.poll_send_chunk(1, &mut cx),
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)))
		));
	}

	#[test]
	fn test_credit_grants_are_monotonic() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(2, None));
		shared.register_send_stream(1, 4);
		// A grant at or below the current limit changes nothing
		shared.apply_credit_grant(1, 1);

		let mut cx = noop_cx();
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Ready(Ok(()))));
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Ready(Ok(()))));
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Pending));
	}

	#[test]
	fn test_unsent_chunks_track_flush_and_drop() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(8, None));
		shared.register_send_stream(1, 3);
		shared.register_send_stream(3, 2);
		assert_eq!(shared.unsent_chunks(), 5);

		let mut cx = noop_cx();
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Ready(Ok(()))));
		assert_eq!(shared.unsent_chunks(), 4);

		shared.finish_send_stream(1);
		assert_eq!(shared.unsent_chunks(), 2);

		shared.finish_send_stream(3);
		assert_eq!(shared.unsent_chunks(), 0);
	}

	#[test]
	fn test_budget_debit_fail_fast_and_reserve() {
		let shared = shared_with_settings(MuxRole::Client, budget_settings(10));

		// 10 credits, 5 reserved: 4 spend cleanly
		assert!(matches!(shared.debit_send_budget(4, false), Ok(BudgetStanding::Healthy)));
		// 6 credits left, 1 spendable: 6 must fail fast, not park
		assert!(matches!(
			shared.debit_send_budget(6, false),
			Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted))
		));
		// The last spendable credit tips the balance into the reserve
		assert!(matches!(shared.debit_send_budget(1, false), Ok(BudgetStanding::Exhausting)));
		// Owed (reserved) traffic keeps flowing inside the reserve
		assert!(matches!(shared.debit_send_budget(5, true), Ok(BudgetStanding::Exhausting)));
		// Even the reserve refuses an overdraft
		assert!(matches!(
			shared.debit_send_budget(1, true),
			Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted))
		));
	}

	#[test]
	fn test_unmetered_budget_never_exhausts() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(1, None));
		assert!(matches!(shared.debit_send_budget(u64::MAX, false), Ok(BudgetStanding::Healthy)));
	}

	/// Put a client-side shared state into an in-flight renewal.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn begin_client_renewal(shared: &MuxShared) {
		let mut state = shared.lock();
		state.rekey_client = true;
		state.rekey = RekeyPhase::AwaitingResponse;
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_admissions_park_across_renewal_and_resume() {
		let shared = shared_with_settings(MuxRole::Client, budget_settings(10));
		begin_client_renewal(&shared);

		let (flag, waker) = FlagWake::pair();
		let mut parked_cx = Context::from_waker(&waker);
		let parked = shared.poll_admit_debit(1, false, &mut parked_cx);
		assert!(matches!(parked, Poll::Pending));

		shared.finish_renewal();
		assert!(flag.woken());

		let mut cx = noop_cx();
		let admitted = shared.poll_admit_debit(1, false, &mut cx);
		assert!(matches!(admitted, Poll::Ready(Ok(BudgetStanding::Healthy))));
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_hard_floor_parks_chunks_until_ack_writes() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(2, None));
		shared.register_send_stream(1, 1);
		begin_client_renewal(&shared);
		shared.park_hard_floor();

		let (mut outbound, _outbound_rx) = mpsc::channel(4);
		let ping = MuxPingPackage::new(false, 0);
		let mut slot = Some(TransportEnvelope::from(ping));
		let (flag, waker) = FlagWake::pair();
		let mut parked_cx = Context::from_waker(&waker);
		let parked = shared.poll_send_enqueue(1, &mut outbound, &mut slot, &mut parked_cx);
		assert!(matches!(parked, Poll::Pending));

		shared.mark_ack_written();
		assert!(flag.woken());

		let mut cx = noop_cx();
		let enqueued = shared.poll_send_enqueue(1, &mut outbound, &mut slot, &mut cx);
		assert!(matches!(enqueued, Poll::Ready(Ok(()))));
	}

	// A wire cancel enqueued while the queue is saturated still
	// travels: the teardown clone's guaranteed slot (channel capacity
	// = buffer + senders) admits it past a full buffer.
	#[test]
	fn test_stream_cancel_survives_saturated_queue() {
		let shared = shared(MuxRole::Client, 2);
		allocate_ids(&shared, &[1]);

		let (outbound, mut wire) = mpsc::channel(0);
		let mut filler = outbound_handle(&outbound);
		while filler.try_send(Outbound::Close).is_ok() {}

		enqueue_stream_cancel(&shared, &outbound, 1);

		let mut saw_cancel = false;
		while let Ok(command) = wire.try_recv() {
			if matches!(
				&command,
				Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Cancel(package)))
					if package.stream_id() == 1
			) {
				saw_cancel = true;
			}
		}
		assert!(saw_cancel);
	}

	// A peer GoAway disowns duplex replies above its watermark:
	// those bodies fail with Draining, the rest stay live.
	#[test]
	fn test_fail_duplex_above_fails_disowned_replies() {
		let shared = shared(MuxRole::Client, 4);
		let (feedback, _notes) = mpsc::unbounded();
		let (mut kept, below) = stream_body(OpenSlot::assigned(1), 4, feedback.clone());
		let (mut disowned, above) = stream_body(OpenSlot::assigned(3), 4, feedback);
		shared.insert_duplex(1, below);
		shared.insert_duplex(3, above);

		shared.fail_duplex_above(1);

		assert!(matches!(poll_chunk(&mut kept), Poll::Pending));
		assert!(matches!(poll_chunk(&mut disowned), Poll::Ready(Err(TransportError::Draining))));
		assert!(shared.take_duplex(1).is_some());
		assert!(shared.take_duplex(3).is_none());
	}
}
