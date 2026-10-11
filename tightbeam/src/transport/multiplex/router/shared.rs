//! Connection-wide shared state: stream allocation, sender-side flow
//! control, budgets, GoAway drain, and rekey phase tracking.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use core::task::{Context, Poll, Waker};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures::channel::{mpsc, oneshot};

use super::body::{BodyEvent, DrainNote, ForwardedStream, StreamBody};
use super::flow::{cap_as_usize, ChunkSize};
use super::outbound::Outbound;
use super::pending::{PendingReplies, ReservationKey};
use crate::transport::envelopes::{
	CancelReason, GoAwayReason, MuxOpenPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::error::TransportFailure;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::multiplex::MuxRole;
use crate::transport::{TransportError, TransportResult};
use crate::urn::Urn;
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::StoredReceipt;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;

/// Wake every parked waker and empty the set.
fn wake_all(wakers: &mut Vec<Waker>) {
	for waker in wakers.drain(..) {
		waker.wake();
	}
}

/// Register `cx`'s waker. The waker clone bumps a refcount and copies no data.
pub fn park_waker(waiters: &mut Vec<Waker>, cx: &Context<'_>) {
	waiters.push(cx.waker().clone());
}

/// Identity of a locally-initiated stream whose ID is assigned at first send
/// (atomic open).
///
/// - It is vacant until the Open record enqueues, and holds the assigned ID
///   afterwards. Stream IDs start at 1 (client) or 2 (server), so zero
///   unambiguously means "not opened yet".
/// - The parts that outlive the open (sinks, response futures, reply bodies,
///   cancel guards) share it, so each can act on the real ID once it exists and
///   stand down when the open was refused.
pub struct OpenSlot(AtomicU32);

impl OpenSlot {
	const VACANT: u32 = 0;

	fn vacant() -> Arc<Self> {
		Arc::new(Self(AtomicU32::new(Self::VACANT)))
	}

	/// Slot for a stream whose ID is already known, such as a peer-initiated
	/// body or a reply. It is assigned from birth.
	pub fn assigned(stream_id: u32) -> Arc<Self> {
		Arc::new(Self(AtomicU32::new(stream_id)))
	}

	fn assign(&self, stream_id: u32) {
		self.0.store(stream_id, AtomicOrdering::Release);
	}

	/// The assigned stream ID, or `None` while the slot is vacant.
	pub fn get(&self) -> Option<u32> {
		match self.0.load(AtomicOrdering::Acquire) {
			Self::VACANT => None,
			stream_id => Some(stream_id),
		}
	}
}

/// A cap slot held for a stream that has not sent its Open record yet.
///
/// The stream ID is assigned inside [`MuxShared::poll_open_enqueue`], in the
/// same critical section that enqueues the Open. Opens therefore reach the
/// peer in strictly increasing ID order ([RFC 9113 § 5.1.1][rfc9113-5.1.1]),
/// however the initiations interleave.
///
/// The pending table holds the stream from its reservation on.
///
/// # Drop
///
/// - An unopened reservation cancels its stream: the cap slot goes back, and the caller reads a cancel.
/// - A reservation that a failure or a GoAway resolved first has nothing left to give back.
/// - An opened reservation leaves its stream in place, where the stream answers to its ID.
///
/// [rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
pub struct StreamReservation {
	shared: Arc<MuxShared>,
	/// The stream's place in the pending table, until it opens.
	key: Option<ReservationKey>,
	slot: Arc<OpenSlot>,
}

impl StreamReservation {
	/// Clone a handle to the stream's late-assigned identity. The clone bumps a
	/// refcount.
	pub fn slot(&self) -> Arc<OpenSlot> {
		Arc::clone(&self.slot)
	}

	/// Open the stream through the atomic open of
	/// [`MuxShared::poll_open_enqueue`], on the connection that reserved it.
	///
	/// The reservation names its own connection, so a caller cannot open it on
	/// another one, where its key would name another stream.
	///
	/// # Errors
	///
	/// - The [`MuxShared::poll_open_enqueue`] set.
	pub fn poll_open(
		&mut self,
		request: &mut OpenRequest<'_>,
		outbound: &mut mpsc::Sender<Outbound>,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<u32>> {
		// The clone bumps a refcount and leaves the reservation free to give
		// up its key.
		let shared = Arc::clone(&self.shared);
		shared.poll_open_enqueue(self, request, outbound, cx)
	}
}

impl Drop for StreamReservation {
	fn drop(&mut self) {
		let Some(key) = self.key.take() else {
			return;
		};

		let mut state = self.shared.lock();
		// An end of the connection that resolved the stream first also freed
		// its cap slot and woke the waiters.
		if state.pending.cancel(key) {
			state.wake_slot_waiters();
		}
	}
}

/// One stream's Open record, handed to [`MuxShared::poll_open_enqueue`].
pub struct OpenRequest<'a> {
	/// Whether the Open carries a unary, streaming, or duplex request.
	pub kind: MuxStreamKind,
	/// Whether this Open closes the send half in the same record.
	pub last: bool,
	/// Chunk bytes carried with the Open record.
	pub payload: &'a [u8],
	/// Records this Open seeds the sender ledger with: the payload's chunk
	/// count, or the whole message's count for a unary emit.
	pub records: u64,
	/// Grpc-style route stamped on the Open record, or `None` for an
	/// unrouted local open.
	pub target: Option<Urn<'static>>,
	/// Relay budget stamped beside the route, which is the number of gateway
	/// forwards the stream may still spend. A `0` open is served locally, so
	/// its forward budget stays spent.
	pub hops_remaining: u8,
}

/// Outcome delivered to a pending stream's oneshot slot.
pub enum StreamOutcome {
	/// A correlated response arrived.
	Response(ResponsePackage),
	/// The peer cancelled or refused the stream.
	Cancelled(CancelReason),
	/// A GoAway ended the stream: the peer's, with a `last_stream_id` below
	/// it, or one in either direction before it opened.
	Draining,
}

impl StreamOutcome {
	/// The caller-facing result of one pending stream.
	///
	/// # Errors
	///
	/// - The error for the response's own status -- the responder refused.
	/// - [`TransportError::Draining`] -- a GoAway ended the stream before the peer served it.
	/// - [`CancelReason::cancel_error`] -- the peer cancelled.
	pub(crate) fn resolve(self) -> TransportResult<Option<Frame>> {
		match self {
			Self::Response(response) => response.resolve(),
			Self::Cancelled(reason) => Err(reason.cancel_error()),
			Self::Draining => Err(TransportError::Draining),
		}
	}
}

/// Client-side renewal state across the key-switch boundaries. A server
/// endpoint and a session without rekey materials stay `Idle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyPhase {
	/// No renewal is in flight.
	Idle,
	/// `RekeyRequest` is written, and the server's response is awaited.
	AwaitingResponse,
	/// The response verified. New c2s admissions park while owed
	/// chunks flush ahead of the `RekeyAck`.
	FlushingAck,
	/// `RekeyAck` is written and the send cipher switched. C2s stays
	/// parked until `RekeyDone` activates the fresh epoch budget.
	AwaitingDone,
}

/// Disposition of an incoming peer-initiated stream.
pub enum PeerStream {
	/// Accept and process the stream.
	Accept,
	/// This endpoint already sent GoAway, and the stream is newer than its
	/// `last_stream_id`. Refuse the stream without processing it.
	RejectDraining,
}

/// Sender-side flow-control ledger for one stream direction, after QUIC
/// MAX_STREAM_DATA ([RFC 9000 § 4.1][rfc9000-4.1]).
///
/// Requests and responses on the same stream stay distinct here. An endpoint
/// sends request chunks only on IDs it allocated, and response chunks only on
/// IDs the peer allocated.
///
/// [rfc9000-4.1]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
struct SendStream {
	/// Chunks already permitted onto the outbound queue.
	sent: u64,
	/// Absolute cumulative chunk limit the peer granted.
	limit: u64,
	/// Registered chunks not yet permitted, for drain accounting.
	unsent: u64,
	/// Wakers parked until the peer raises the limit.
	credit_wakers: Vec<Waker>,
}

/// Outcome of an outbound session-budget debit.
pub enum BudgetStanding {
	/// Spendable credits remain, or the session is unmetered.
	Healthy,
	/// The balance fell to the drain reserve, so trigger the
	/// [`GoAwayReason::BudgetExhausted`] drain.
	Exhausting,
}

/// Mutable connection state behind the [`MuxShared`] lock.
struct MuxState {
	/// Next locally-initiated stream ID, or `None` once the ID space is
	/// exhausted. IDs are strictly monotonic over the nonzero values.
	next_stream_id: Option<u32>,
	/// Highest peer-initiated stream ID seen, or 0 before the first.
	last_peer_stream_id: u32,
	/// Reserved streams, open streams, and pings that still await their answer.
	/// It decides admission and owns the cap-relevant open-stream count (see
	/// [`StreamReservation`]).
	pending: PendingReplies,
	/// Next correlation value for a locally-initiated ping.
	next_ping_opaque: u64,
	/// Sender-side per-stream flow-control ledgers.
	send_streams: HashMap<u32, SendStream>,
	/// Credits left in the outbound session budget. `None` means the
	/// session is unmetered.
	send_budget: Option<u64>,
	/// Chunks registered by producers but not yet permitted, across all
	/// streams. The writer adds them to its drain headroom, so owed chunks
	/// always fit inside the remaining records.
	unsent_chunks: u64,
	/// `last_stream_id` this endpoint advertised in its GoAway, once sent.
	goaway_sent: Option<u32>,
	/// `last_stream_id` received in the peer's GoAway.
	goaway_received: Option<u32>,
	/// Reason carried by the peer's GoAway, once received. Local shutdown
	/// leaves this empty, because the caller already knows why.
	goaway_reason: Option<GoAwayReason>,
	/// Wakers parked until the pending table drains at shutdown.
	drain_wakers: Vec<Waker>,
	/// Wakers parked until a stream slot frees while the cap is full.
	slot_wakers: Vec<Waker>,
	/// In-band renewal state. Only a client with rekey materials ever
	/// leaves `Idle`.
	rekey: RekeyPhase,
	/// `true` while a renewal is in flight with send records down to the
	/// drain headroom, so data chunks park until the fresh cipher installs.
	rekey_hard_floor: bool,
	/// Whether this endpoint can open renewals, which takes the client role
	/// with rekey materials attached.
	rekey_client: bool,
	/// Wakers parked on renewal transitions: admissions that wait out a
	/// renewal, chunks on the hard floor, and the writer that waits for owed
	/// chunks to quiesce ahead of the `RekeyAck`.
	rekey_wakers: Vec<Waker>,
}

impl MuxState {
	/// Wake every task parked until the pending table drains.
	fn wake_drain_waiters(&mut self) {
		wake_all(&mut self.drain_wakers);
	}

	/// Wake every task parked until a stream slot frees.
	fn wake_slot_waiters(&mut self) {
		wake_all(&mut self.slot_wakers);
	}

	/// Wake every task parked on a renewal transition.
	pub fn wake_rekey_waiters(&mut self) {
		wake_all(&mut self.rekey_wakers);
	}

	/// The ID a new locally-initiated stream would take, while one may
	/// still be admitted.
	///
	/// An exhausted ID space ends admission as a GoAway does, so it joins
	/// [`PendingReplies::refusal`] here and a caller receives the ID it can
	/// use straight away.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway ended admission, or the ID space is exhausted.
	fn admissible_stream_id(&self) -> TransportResult<u32> {
		if let Some(refusal) = self.pending.refusal() {
			return Err(refusal);
		}

		self.next_stream_id.ok_or(TransportError::Draining)
	}
}

/// Connection-wide mux state that the drivers and the stream handles share
/// through an `Arc`.
pub struct MuxShared {
	/// Whether this endpoint initiates or accepts streams.
	pub role: MuxRole,
	state: Mutex<MuxState>,
	/// Concurrent streams this endpoint may initiate, as the peer advertised.
	pub local_cap: u32,
	/// Largest chunk payload this endpoint may send, as the peer advertised.
	pub send_chunk_size: ChunkSize,
	/// Bytes per session-budget credit, negotiated for both directions.
	pub credit_unit: u32,
	/// Initial per-stream chunk limit for outbound data, as the peer
	/// advertised.
	initial_send_credit: u64,
	/// Initial per-stream chunk limit granted to the peer. It is the local
	/// receive window, which duplex reply bodies size from.
	pub initial_recv_credit: u64,
	/// Connection collector inherited from the split halves. Control-plane
	/// events land here (see [`crate::instrumentation::events`]).
	#[cfg(feature = "instrument")]
	pub trace: Option<TraceCollector>,
	/// Reply forwarders for open locally-initiated duplex streams. The atomic
	/// open registers each one under its stream ID, and the reader drives it,
	/// forwarding response chunks as they arrive instead of reassembling them.
	/// A forwarder waits in the pending table until its stream opens.
	///
	/// # Partition
	///
	/// Forwarder registries partition by initiator. This map holds only
	/// locally-initiated stream IDs, and the reader's `peer_bodies` holds only
	/// peer-initiated ones. Every teardown path (cancel, GoAway, connection
	/// failure) must clear its side of both registries, and the pending table
	/// for a stream that has not opened.
	duplex_recv: Mutex<HashMap<u32, ForwardedStream>>,
	/// Credits reserved so owed traffic can flush during a budget drain. See
	/// [`MuxSettings::send_budget_reserve`].
	budget_drain_headroom: u64,
	/// Negotiated outbound budget, restored at each epoch boundary. The
	/// credit-match invariant keeps the epoch receipt budgets equal to the
	/// initial terms.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	initial_send_budget: Option<u64>,
	/// Current epoch's dual-signed receipt. Renewal rotates it.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	session_receipt: Mutex<Option<Arc<StoredReceipt>>>,
}

impl MuxShared {
	/// Shared state for `role` under the negotiated `settings`, with no
	/// stream open.
	pub fn new(role: MuxRole, settings: &MuxSettings) -> Self {
		Self {
			role,
			local_cap: settings.local_initiated_cap,
			send_chunk_size: ChunkSize::new(cap_as_usize(settings.send_chunk_size)),
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
				pending: PendingReplies::default(),
				next_ping_opaque: 0,
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

	/// Lock the connection state, recovering the guard from a poisoned lock.
	fn lock(&self) -> MutexGuard<'_, MuxState> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Session-budget credits an outbound payload debits at the peer's
	/// receive chunk size and the negotiated credit unit.
	pub fn credits_for(&self, payload_len: usize) -> u64 {
		self.send_chunk_size.credits(payload_len, self.credit_unit)
	}

	/// Chunk records an outbound payload occupies at the peer's receive chunk
	/// size.
	pub fn records_for(&self, payload_len: usize) -> u64 {
		self.send_chunk_size.records(payload_len)
	}

	/// Future that resolves once a locally-initiated stream would be
	/// admitted. Creating it is a refcount bump.
	pub fn stream_slot(self: &Arc<Self>) -> StreamSlot {
		StreamSlot { shared: Arc::clone(self) }
	}

	/// Future that resolves once the pending table drains. Creating it is a
	/// refcount bump.
	pub fn drain_pending(self: &Arc<Self>) -> DrainPending {
		DrainPending { shared: Arc::clone(self) }
	}

	/// Lock the duplex reply registry, recovering the guard from a poisoned
	/// lock.
	fn duplex_lock(&self) -> MutexGuard<'_, HashMap<u32, ForwardedStream>> {
		self.duplex_recv.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Register the reply forwarder for a locally-initiated duplex
	/// stream. The caller holds the state lock and the table admitted the
	/// stream, which is what keeps a forwarder off a failed connection.
	fn insert_duplex(&self, stream_id: u32, forwarder: ForwardedStream) {
		self.duplex_lock().insert(stream_id, forwarder);
	}

	/// Detach a duplex reply forwarder while its stream resolves.
	pub fn take_duplex(&self, stream_id: u32) -> Option<ForwardedStream> {
		self.duplex_lock().remove(&stream_id)
	}

	/// Forward one reply chunk into a duplex body.
	///
	/// It returns `None` when the stream is not duplex, and `Some(false)` on a
	/// credit overrun.
	pub fn forward_duplex_chunk(&self, stream_id: u32, payload: impl AsRef<[u8]>) -> Option<bool> {
		let payload = payload.as_ref();
		let mut map = self.duplex_lock();
		let stream = map.get_mut(&stream_id)?;

		let accepted = stream.accept_and_forward(payload);
		Some(accepted)
	}

	/// Granted limit and window of a duplex reply body, when live.
	pub fn duplex_limits(&self, stream_id: u32) -> Option<(u64, u64)> {
		let map = self.duplex_lock();
		let stream = map.get(&stream_id)?;

		Some(stream.limits())
	}

	/// Raise a duplex reply body's granted limit.
	pub fn set_duplex_limit(&self, stream_id: u32, limit: u64) {
		if let Some(stream) = self.duplex_lock().get_mut(&stream_id) {
			stream.raise_limit(limit);
		}
	}

	/// Fail duplex replies the peer's GoAway disowned. Streams above its
	/// high-water mark stay unanswered.
	pub fn fail_duplex_above(&self, last_stream_id: u32) {
		let mut map = self.duplex_lock();
		map.retain(|stream_id, stream| {
			if *stream_id <= last_stream_id {
				return true;
			}

			// A reply body already dropped has no reader for the failure,
			// and the GoAway disowned the stream either way.
			let _ = stream.forward(BodyEvent::Failed(TransportError::Draining));
			false
		});
	}

	/// Drop every duplex reply forwarder on connection failure, so the bodies
	/// observe the closed channel.
	fn fail_all_duplex(&self) {
		self.duplex_lock().clear();
	}

	/// Drop a stream's sender ledger under the lock. Its unflushed chunks
	/// return to the drain accounting, and any parked producer wakes to
	/// observe the removal.
	fn drop_send_stream(state: &mut MuxState, stream_id: u32) {
		if let Some(stream) = state.send_streams.remove(&stream_id) {
			state.unsent_chunks = state.unsent_chunks.saturating_sub(stream.unsent);
			for waker in stream.credit_wakers {
				waker.wake();
			}

			Self::wake_on_quiesce(state);
		}
	}

	/// Move the rekey phase from `from` to `to`, and report whether the move
	/// happened.
	///
	/// The precondition and the write live together, so the phase advances
	/// only from `from` to `to` and the rekey sequence stays ordered.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn advance_rekey(state: &mut MuxState, from: RekeyPhase, to: RekeyPhase) -> bool {
		if state.rekey != from {
			return false;
		}

		state.rekey = to;
		true
	}

	/// Wake the writer once owed chunks quiesce while it holds a `RekeyAck`
	/// back, because the ack trails every old-epoch chunk.
	fn wake_on_quiesce(state: &mut MuxState) {
		if state.unsent_chunks == 0 && state.rekey == RekeyPhase::FlushingAck {
			state.wake_rekey_waiters();
		}
	}

	/// Register the sender-side ledger for a stream about to carry
	/// `chunks` outbound chunk records.
	pub fn register_send_stream(&self, stream_id: u32, chunks: u64) {
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

	/// Drop a stream's sender ledger outside the pending-table paths, such as
	/// for response streams and abandoned sends.
	pub fn finish_send_stream(&self, stream_id: u32) {
		let mut state = self.lock();
		Self::drop_send_stream(&mut state, stream_id);
	}

	/// Extend a registered sender ledger by `chunks` outbound records.
	///
	/// Streamed replies learn their length one push at a time. A missing
	/// ledger means the stream already resolved through a cancel or a
	/// failure, and the send path reports that itself.
	pub fn add_send_records(&self, stream_id: u32, chunks: u64) {
		let mut state = self.lock();
		let Some(stream) = state.send_streams.get_mut(&stream_id) else {
			return;
		};
		stream.unsent = stream.unsent.saturating_add(chunks);
		state.unsent_chunks = state.unsent_chunks.saturating_add(chunks);
	}

	/// Consume one unit of stream credit under the lock, or park.
	///
	/// # Errors
	///
	/// - [`TransportFailure::Cancelled`] -- the ledger is gone. The stream
	///   resolved underneath the sender through a cancel, a response, or a
	///   connection failure, and the outcome channel has the truth.
	/// - [`TransportError::ConnectionClosed`] -- the ledger is at its limit and
	///   the connection has failed. No grant can arrive, so a reply whose
	///   ledger registered after the failure sweep would park for good.
	fn take_chunk_credit(state: &mut MuxState, stream_id: u32, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let Some(stream) = state.send_streams.get_mut(&stream_id) else {
			return Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)));
		};
		if stream.sent >= stream.limit {
			if state.pending.is_closed() {
				return Poll::Ready(Err(TransportError::ConnectionClosed));
			}

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
	pub fn poll_send_chunk(&self, stream_id: u32, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let mut state = self.lock();
		Self::take_chunk_credit(&mut state, stream_id, cx)
	}

	/// Consume one unit of stream credit and enqueue the chunk's envelope in
	/// one critical section, so no data envelope can slip into the queue behind
	/// a rekey `RekeyAck` boundary (strict park).
	///
	/// The caller MUST have reserved queue capacity through `poll_ready` on
	/// `outbound` first.
	///
	/// # Rekey floor
	///
	/// Chunks also park on the rekey hard floor, because send records at the
	/// drain headroom with a renewal in flight are reserved for control and the
	/// exchange legs.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::Cancelled`] -- the stream's ledger is gone.
	/// - [`TransportError::ConnectionClosed`] -- the envelope slot is empty, or
	///   a driver of the connection ended.
	pub fn poll_send_enqueue(
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

	/// Apply a peer credit grant.
	///
	/// The grant is idempotent and monotonic, so only a limit above the
	/// current one changes anything. A grant for an unknown stream is
	/// discarded, because a grant that races stream completion is benign.
	pub fn apply_credit_grant(&self, stream_id: u32, limit: u64) {
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
	/// `reserved` spends into the drain reserve. A non-reserved debit fails
	/// fast once the spendable balance above the reserve falls short, which
	/// keeps the reserve intact for the drain.
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

	/// Debit `credits` from the outbound session budget through
	/// [`Self::debit_budget`], for tests. Production paths wait out renewals
	/// through [`Self::admit_debit`].
	#[cfg(test)]
	pub fn debit_send_budget(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
		let mut state = self.lock();
		Self::debit_budget(&mut state, self.budget_drain_headroom, credits, reserved)
	}

	/// Debit the outbound session budget once no renewal is in flight.
	///
	/// Client admissions park across a renewal so every debit belongs to one
	/// epoch. Budgets reset at `RekeyDone`, and a debit issued mid-renewal
	/// could otherwise straddle the boundary. A draining connection skips the
	/// park, because the renewal is dead and owed traffic must flush.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with [`TransportFailure::BudgetExhausted`] -- the
	///   budget cannot carry `credits`.
	pub fn poll_admit_debit(
		&self,
		credits: u64,
		reserved: bool,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<BudgetStanding>> {
		let mut state = self.lock();
		let draining = state.pending.is_draining();
		if state.rekey_client && state.rekey != RekeyPhase::Idle && !draining {
			park_waker(&mut state.rekey_wakers, cx);
			return Poll::Pending;
		}

		Poll::Ready(Self::debit_budget(&mut state, self.budget_drain_headroom, credits, reserved))
	}

	/// Debit the outbound budget, waiting out any in-flight renewal.
	///
	/// # Errors
	///
	/// - The [`poll_admit_debit`](Self::poll_admit_debit) set.
	pub async fn admit_debit(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
		poll_fn(|cx| self.poll_admit_debit(credits, reserved, cx)).await
	}

	/// Chunks registered but not yet flushed, across all streams.
	pub fn unsent_chunks(&self) -> u64 {
		self.lock().unsent_chunks
	}

	/// The current renewal phase, read by the writer's renewal deadline.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	pub fn rekey_phase(&self) -> RekeyPhase {
		self.lock().rekey
	}

	/// Whether this endpoint may open a renewal now. That takes the client
	/// role with rekey materials, an `Idle` phase, and a connection that still
	/// admits work.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn renewal_ready(&self) -> bool {
		let state = self.lock();
		let admits = state.pending.refusal().is_none();
		state.rekey_client && state.rekey == RekeyPhase::Idle && admits
	}

	/// Mark this endpoint as the client half of a rekey exchange, which
	/// activates renewal triggers and admission gating.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn mark_rekey_client(&self) {
		self.lock().rekey_client = true;
	}

	/// Transition `Idle` to `AwaitingResponse` exactly once.
	///
	/// `open` runs under the state lock, so concurrent triggers collapse to a
	/// single opened renewal, and an `open` failure leaves the phase
	/// untouched. It returns `None` when a renewal is already in flight, the
	/// connection admits no work, or `open` declined.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn enter_renewal<T>(&self, open: impl FnOnce() -> Option<T>) -> Option<T> {
		let mut state = self.lock();
		if state.rekey != RekeyPhase::Idle || state.pending.refusal().is_some() {
			return None;
		}

		let request = open()?;
		Self::advance_rekey(&mut state, RekeyPhase::Idle, RekeyPhase::AwaitingResponse);
		Some(request)
	}

	/// Whether owed c2s chunks have quiesced, which means the registered
	/// count and the flushed count agree. Otherwise it parks `cx` on the
	/// rekey waker set, so the caller re-polls when the last owed chunk
	/// flushes.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn poll_chunks_quiesced(&self, cx: &Context<'_>) -> bool {
		let mut state = self.lock();
		if state.unsent_chunks == 0 {
			return true;
		}

		park_waker(&mut state.rekey_wakers, cx);
		false
	}

	/// Admit a `RekeyResponse` (client), parking new c2s admissions while
	/// owed chunks flush ahead of the `RekeyAck`.
	///
	/// The phase check and the move are one step under the lock, so a
	/// response that arrives out of order moves nothing and admits nothing.
	/// It returns whether the response was admitted.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn admit_rekey_response(&self) -> bool {
		let mut state = self.lock();
		if !Self::advance_rekey(&mut state, RekeyPhase::AwaitingResponse, RekeyPhase::FlushingAck) {
			return false;
		}

		// Owed chunks may already be quiescent, so give the writer its wake
		// now, ahead of the next ledger transition.
		Self::wake_on_quiesce(&mut state);
		true
	}

	/// Record that the writer wrote the `RekeyAck` (client). The send cipher is
	/// active after the Ack, which lifts the hard-floor park.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn mark_ack_written(&self) {
		let mut state = self.lock();
		if !Self::advance_rekey(&mut state, RekeyPhase::FlushingAck, RekeyPhase::AwaitingDone) {
			return;
		}

		state.rekey_hard_floor = false;
		state.wake_rekey_waiters();
	}

	/// Close a renewal that completed (client, on `RekeyDone`), and report
	/// whether the renewal closed.
	///
	/// - The phase check, the send budget reset, and the receipt rotation all
	///   happen under the lock, before any parked admission wakes, so an
	///   admission that debits the new epoch also reads its receipt.
	/// - A `RekeyDone` that arrives before the `RekeyAck` was written closes nothing.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn complete_renewal(&self, receipt: StoredReceipt) -> bool {
		let mut state = self.lock();
		if !Self::advance_rekey(&mut state, RekeyPhase::AwaitingDone, RekeyPhase::Idle) {
			return false;
		}

		state.send_budget = self.initial_send_budget;

		// No path holds the receipt slot while it takes this lock, so taking
		// the slot here keeps the lock order.
		self.rotate_receipt(receipt);
		Self::release_renewal(&mut state);
		true
	}

	/// Abandon the renewal from any phase after the attempt died or was
	/// refused. Admissions resume, the hard floor lifts, and parked tasks wake.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn finish_renewal(&self) {
		let mut state = self.lock();
		Self::abandon_renewal(&mut state);
	}

	/// Return the renewal to `Idle` from any phase. Apart from a completed
	/// renewal, this is the only write of `Idle`.
	fn abandon_renewal(state: &mut MuxState) {
		state.rekey = RekeyPhase::Idle;
		Self::release_renewal(state);
	}

	/// Lift the hard floor and wake everything parked on the renewal.
	fn release_renewal(state: &mut MuxState) {
		state.rekey_hard_floor = false;
		state.wake_rekey_waiters();
	}

	/// Park data chunks, because send records are down to the drain headroom
	/// while a renewal is in flight, and what remains is reserved for control
	/// and the exchange legs.
	///
	/// # Phase check
	///
	/// The phase check and the park are one step under the lock. Only a
	/// renewal in flight can lift the floor, so a floor set after the reader
	/// closed the renewal would park data until the connection died. With the
	/// phase `Idle` this writes nothing and returns `false`, and the caller
	/// falls through to the drain decision.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn park_hard_floor(&self) -> bool {
		let mut state = self.lock();
		if state.rekey == RekeyPhase::Idle {
			return false;
		}

		state.rekey_hard_floor = true;
		true
	}

	/// Restore the outbound budget to the negotiated terms at the `RekeyDone`
	/// boundary. The credit-match invariant keeps the epoch receipt's terms
	/// equal to the initial ones.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn reset_send_budget(&self) {
		self.lock().send_budget = self.initial_send_budget;
	}

	/// Publish the completed epoch receipt to handle accessors.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn rotate_receipt(&self, receipt: StoredReceipt) {
		let mut slot = self.session_receipt.lock().unwrap_or_else(PoisonError::into_inner);
		*slot = Some(Arc::new(receipt));
	}

	/// The current epoch's dual-signed receipt, once a handshake or a renewal
	/// published one.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
		let slot = self.session_receipt.lock().unwrap_or_else(PoisonError::into_inner);
		slot.as_ref().map(Arc::clone)
	}

	/// Meter one pushed payload. The call debits the session budget and
	/// accounts the payload's records on the stream's sender ledger, which is
	/// the one budget rule both streaming sinks share.
	///
	/// # Errors
	///
	/// - The refusal from [`Self::admit_debit`] -- the budget cannot carry the payload.
	pub(crate) async fn debit_push(
		&self,
		stream_id: u32,
		payload_len: usize,
		reserved: bool,
	) -> TransportResult<BudgetStanding> {
		let credits = self.credits_for(payload_len);
		let standing = self.admit_debit(credits, reserved).await?;
		self.add_send_records(stream_id, self.records_for(payload_len));
		Ok(standing)
	}

	/// Record a responder answering [`TransitStatus::Internal`] from a
	/// local inconsistency, so the peer-observed status has a local
	/// investigation trail.
	pub(crate) fn note_internal_error(&self) {
		#[cfg(feature = "instrument")]
		self.emit_event(events::MUX_INTERNAL_ERROR);
	}

	/// Trace an admission refusal that a drain caused.
	///
	/// `MUX_EMIT_DRAINING` names a drain, so it is emitted for
	/// [`TransportError::Draining`] alone.
	#[cfg(feature = "instrument")]
	fn trace_refusal(&self, refusal: &TransportError) {
		if matches!(refusal, TransportError::Draining) {
			self.emit_event(events::MUX_EMIT_DRAINING);
		}
	}

	/// Write a control-plane event twice: the core kind URN into the
	/// instrument log, and the stable label for spec assertions and CSP
	/// alphabets.
	#[cfg(feature = "instrument")]
	pub fn emit_event(&self, event: Urn<'static>) {
		let Some(trace) = self.trace.as_ref() else {
			return;
		};

		trace.emit_event(event);
	}

	/// Record a GoAway control event. The reason name labels why, and its
	/// code is the assertable value.
	#[cfg(feature = "instrument")]
	pub fn emit_goaway_event(&self, event: Urn<'static>, reason: GoAwayReason) {
		let Some(trace) = self.trace.as_ref() else {
			return;
		};

		trace.emit_event_with_value(event, reason.as_str(), u32::from(reason));
	}

	/// Reserve a cap slot for a locally-initiated stream without assigning its
	/// ID.
	///
	/// The ID is assigned when the Open record enqueues (see
	/// [`Self::poll_open_enqueue`]), so it always matches the send order.
	/// Admission (running drivers, draining, cap, ID space) is checked here, at
	/// the caller-visible initiation point.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway ended admission, or the ID space is exhausted.
	/// - [`TransportError::OperationFailed`] with [`TransportFailure::StreamsExhausted`] -- the
	///   open load is at the local cap.
	pub fn reserve_stream_slot(
		self: &Arc<Self>,
		sender: oneshot::Sender<StreamOutcome>,
	) -> TransportResult<StreamReservation> {
		self.reserve_slot(sender, None, OpenSlot::vacant())
	}

	/// Reserve a cap slot for a duplex stream, with the body that its reply
	/// streams into.
	///
	/// The reply forwarder waits with the reservation in the pending table and
	/// registers under the assigned ID when the Open record enqueues. A
	/// connection that fails or drains before then ends the body.
	///
	/// # Errors
	///
	/// - The [`reserve_stream_slot`](Self::reserve_stream_slot) set.
	pub fn reserve_duplex_slot(
		self: &Arc<Self>,
		drained: mpsc::Sender<DrainNote>,
	) -> TransportResult<(StreamReservation, StreamBody)> {
		let slot = OpenSlot::vacant();
		let (body, reply) = StreamBody::pair(Arc::clone(&slot), self.initial_recv_credit, drained);
		// The reply travels through the body, so the outcome has no reader and
		// the pending entry holds the cap slot and the forwarder alone.
		let (outcome, _) = oneshot::channel();
		let reservation = self.reserve_slot(outcome, Some(reply), slot)?;

		Ok((reservation, body))
	}

	/// Admit one reservation, with the reply forwarder of a duplex.
	///
	/// # Errors
	///
	/// - The [`reserve_stream_slot`](Self::reserve_stream_slot) set.
	fn reserve_slot(
		self: &Arc<Self>,
		outcome: oneshot::Sender<StreamOutcome>,
		reply: Option<ForwardedStream>,
		slot: Arc<OpenSlot>,
	) -> TransportResult<StreamReservation> {
		let mut state = self.lock();
		if let Err(refusal) = state.admissible_stream_id() {
			drop(state);

			#[cfg(feature = "instrument")]
			self.trace_refusal(&refusal);

			return Err(refusal);
		}
		if state.pending.open_load() >= cap_as_usize(self.local_cap) {
			drop(state);

			#[cfg(feature = "instrument")]
			self.emit_event(events::MUX_STREAMS_EXHAUSTED);

			return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
		}

		let key = state.pending.reserve(outcome, reply)?;
		drop(state);

		Ok(StreamReservation { shared: Arc::clone(self), key: Some(key), slot })
	}

	/// Atomic open: assign the next stream ID and enqueue the stream's Open
	/// record in one critical section. Opens therefore reach the peer in
	/// strictly increasing ID order, however concurrent initiations
	/// interleave.
	///
	/// The caller MUST have reserved queue capacity through `poll_ready` on
	/// `outbound` first.
	///
	/// # Preconditions
	///
	/// Every precondition, such as the rekey hard floor, is checked before
	/// the ID is consumed, so a `Pending` leaves the ID and the queue slot
	/// free. The fresh ledger's initial credit is at least one, so the Open's
	/// own credit debit proceeds straight after assignment.
	///
	/// # Errors
	///
	/// - [`TransportError::Draining`] -- admission ended after the reservation.
	/// - [`TransportError::InvalidState`] -- the reservation already opened.
	/// - [`TransportError::DerError`] -- the Open record does not encode.
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	fn poll_open_enqueue(
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

		let stream_id = match state.admissible_stream_id() {
			Ok(stream_id) => stream_id,
			Err(refusal) => return Poll::Ready(Err(refusal)),
		};
		// The record is built before anything registers, so an Open that does
		// not encode leaves the reservation whole.
		let package = match MuxOpenPackage::new(stream_id, request.last, request.kind, request.payload) {
			Ok(package) => package,
			Err(err) => return Poll::Ready(Err(TransportError::DerError(err))),
		};
		let Some(key) = reservation.key.take() else {
			// Unreachable by construction: a reservation opens once.
			return Poll::Ready(Err(TransportError::InvalidState));
		};

		let reply = match state.pending.open(key, stream_id) {
			Ok(reply) => reply,
			// Unreachable by construction: the decider read this table under
			// the same lock, and it refuses after each end that resolves a
			// reservation.
			Err(refusal) => return Poll::Ready(Err(refusal)),
		};

		state.next_stream_id = stream_id.checked_add(2);
		reservation.slot.assign(stream_id);
		// Seed the ledger, then take the Open's own credit. The initial grant
		// floor of one admits it without parking.
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

		// The forwarder registers before the Open can reach the peer, so a
		// reply chunk always finds it.
		if let Some(forwarder) = reply {
			self.insert_duplex(stream_id, forwarder);
		}

		let package = package.with_route(request.target.take(), request.hops_remaining);
		let enqueued = outbound
			.start_send(Outbound::Envelope(package.into()))
			.map_err(|_| TransportError::ConnectionClosed);
		if enqueued.is_err() {
			// The Open never left, so nothing may stay registered to wait on
			// it. Each dropped sender ends its half of the stream.
			Self::drop_send_stream(&mut state, stream_id);
			drop(state.pending.take_stream(stream_id));
			drop(self.take_duplex(stream_id));
		}

		Poll::Ready(enqueued.map(|()| stream_id))
	}

	/// Detach a pending stream's outcome sender and release its sender
	/// ledger, or return `None` for an unknown ID.
	pub fn remove_pending(&self, stream_id: u32) -> Option<oneshot::Sender<StreamOutcome>> {
		let mut state = self.lock();
		let entry = state.pending.take_stream(stream_id);
		if entry.is_some() {
			// The stream is over, so releasing its sender ledger wakes a
			// producer still parked on credit and it stops sending.
			Self::drop_send_stream(&mut state, stream_id);
			state.wake_drain_waiters();
			state.wake_slot_waiters();
		}

		entry
	}

	/// Resolve a pending stream. An unknown ID is silently discarded, which
	/// tolerates a cancel racing a response on the connection.
	pub fn resolve(&self, stream_id: u32, outcome: StreamOutcome) {
		if let Some(sender) = self.remove_pending(stream_id) {
			// A dropped receiver is an initiator that cancelled, the same race
			// an unknown ID is.
			let _ = sender.send(outcome);
		}
	}

	/// Register a locally-initiated ping and return its correlation value.
	///
	/// The ping is refused while draining, because a peer that honors the
	/// GoAway contract reserves its remaining records for owed stream traffic
	/// (see [`MuxSettings::drain_reserve_records`]).
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway went out or came in.
	pub fn allocate_ping(&self, sender: oneshot::Sender<()>) -> TransportResult<u64> {
		let mut state = self.lock();
		if let Some(refusal) = state.pending.refusal() {
			drop(state);

			#[cfg(feature = "instrument")]
			self.trace_refusal(&refusal);

			return Err(refusal);
		}

		let opaque = state.next_ping_opaque;
		state.pending.admit_ping(opaque, sender)?;
		state.next_ping_opaque = opaque.wrapping_add(1);

		Ok(opaque)
	}

	/// Resolve a pending ping. An unknown correlation value is silently
	/// discarded, because a stale ack that races a dropped ping future is
	/// benign.
	pub fn resolve_ping(&self, opaque: u64) {
		if let Some(sender) = self.lock().pending.take_ping(opaque) {
			// A dropped receiver is a ping future already gone, and its late
			// ack is as benign as a stale one.
			let _ = sender.send(());
		}
	}

	/// Forget a pending ping without resolving it.
	pub fn remove_pending_ping(&self, opaque: u64) {
		self.lock().pending.forget_ping(opaque);
	}

	/// Whether this endpoint already sent its GoAway.
	pub fn shutdown_begun(&self) -> bool {
		self.lock().goaway_sent.is_some()
	}

	/// Drop every pending slot on connection failure.
	///
	/// - Receivers observe cancellation.
	/// - Producers parked on credit observe the ledger removal.
	/// - Any in-flight renewal is dead, so parked admissions resume to meet the
	///   failure instead of waiting for a `RekeyDone` the peer abandoned.
	/// - Admission ends for good under the lock that clears the tables, so no
	///   stream or ping registers after the sweep and waits on a driver that
	///   is gone.
	pub fn fail_all_pending(&self) {
		let mut state = self.lock();
		state.pending.close();
		// An Open registers its reply forwarder under this lock, after the
		// table admits it. The registry therefore empties here, behind the
		// close, and no forwarder lands between the two.
		self.fail_all_duplex();

		for (_, stream) in state.send_streams.drain() {
			for waker in stream.credit_wakers {
				waker.wake();
			}
		}

		state.unsent_chunks = 0;
		Self::abandon_renewal(&mut state);
		state.wake_drain_waiters();
		state.wake_slot_waiters();
	}

	/// Resolve pending streams above `last_stream_id` as draining, because
	/// the peer's GoAway stopped their processing. A stream still reserved
	/// resolves the same way, because a GoAway ends admission. It records the
	/// peer's reason for [`MuxShared::goaway_reason`].
	pub fn fail_pending_above(&self, last_stream_id: u32, reason: GoAwayReason) {
		{
			let mut state = self.lock();
			state.goaway_received = Some(last_stream_id);
			state.goaway_reason = Some(reason);

			if let Some(first_dropped) = last_stream_id.checked_add(1) {
				for (stream_id, sender) in state.pending.take_streams_from(first_dropped) {
					// A dropped receiver is an initiator that gave up before
					// the GoAway, which leaves nothing to resolve.
					let _ = sender.send(StreamOutcome::Draining);
					// The peer grants no credit for a stream it disowned, so
					// the ledger goes and a producer parked on it wakes.
					Self::drop_send_stream(&mut state, stream_id);
				}
			}

			state.pending.drain();
			state.wake_drain_waiters();
			state.wake_slot_waiters();
			state.wake_rekey_waiters();
		}

		#[cfg(feature = "instrument")]
		self.emit_goaway_event(events::MUX_GOAWAY_RECV, reason);
	}

	/// Halt the allocator and record the GoAway watermark. A stream still
	/// reserved resolves as draining, because a GoAway ends admission.
	///
	/// It returns the `last_stream_id` to advertise, or `None` when shutdown
	/// already began.
	pub fn begin_shutdown(&self) -> Option<u32> {
		let mut state = self.lock();
		if state.goaway_sent.is_some() {
			return None;
		}

		state.goaway_sent = Some(state.last_peer_stream_id);
		state.pending.drain();
		state.wake_slot_waiters();
		state.wake_rekey_waiters();

		Some(state.last_peer_stream_id)
	}

	/// Validate and record an incoming peer-initiated stream ID per
	/// [RFC 9113 § 5.1.1][rfc9113-5.1.1].
	///
	/// - The ID is odd or even to match the peer's role.
	/// - The ID is nonzero.
	/// - The ID is strictly greater than every earlier peer-initiated ID.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the ID breaks one of the rules above.
	///
	/// [rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
	pub fn register_peer_stream(&self, stream_id: u32) -> TransportResult<PeerStream> {
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

	/// Highest peer-initiated stream ID seen, or 0 before the first.
	pub fn last_peer_stream_id(&self) -> u32 {
		self.lock().last_peer_stream_id
	}

	/// Whether a new locally-initiated stream fits now: both drivers still
	/// run, no GoAway in either direction, a live ID space, and an open load
	/// under the cap.
	pub fn has_stream_headroom(&self) -> bool {
		let state = self.lock();

		let under_cap = state.pending.open_load() < cap_as_usize(self.local_cap);
		let admits = state.admissible_stream_id().is_ok();
		admits && under_cap
	}

	/// Whether any locally-initiated stream is pending or reserved.
	pub fn has_pending_streams(&self) -> bool {
		let state = self.lock();
		state.pending.open_load() > 0
	}

	/// Whether `stream_id` is awaiting its response.
	pub fn is_pending(&self, stream_id: u32) -> bool {
		self.lock().pending.holds_stream(stream_id)
	}

	/// Reason carried by the peer's GoAway, once received.
	pub fn goaway_reason(&self) -> Option<GoAwayReason> {
		self.lock().goaway_reason
	}

	/// Resolve once a locally-initiated stream would be admitted.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- admission has ended for good.
	pub fn poll_stream_slot(&self, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let mut state = self.lock();
		if let Err(refusal) = state.admissible_stream_id() {
			return Poll::Ready(Err(refusal));
		}
		if state.pending.open_load() < cap_as_usize(self.local_cap) {
			return Poll::Ready(Ok(()));
		}

		park_waker(&mut state.slot_wakers, cx);

		Poll::Pending
	}
}

/// Future that resolves once a locally-initiated stream would be admitted,
/// or fails once admission has ended for good.
pub struct StreamSlot {
	shared: Arc<MuxShared>,
}

impl Future for StreamSlot {
	type Output = TransportResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		self.shared.poll_stream_slot(cx)
	}
}

/// Future that resolves once the pending table drains, which means every
/// in-flight local stream completed, was cancelled, or failed.
pub struct DrainPending {
	shared: Arc<MuxShared>,
}

impl Future for DrainPending {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
		let mut state = self.shared.lock();
		if state.pending.stream_count() == 0 {
			return Poll::Ready(());
		}

		park_waker(&mut state.drain_wakers, cx);

		Poll::Pending
	}
}

impl CancelReason {
	/// The transport error a caller observes for this cancel reason.
	pub fn cancel_error(&self) -> TransportError {
		match self {
			CancelReason::Cancelled => TransportError::OperationFailed(TransportFailure::Cancelled),
			CancelReason::Timeout => TransportError::OperationFailed(TransportFailure::DeadlineExceeded),
			CancelReason::Rejected => TransportError::OperationFailed(TransportFailure::ResourceExhausted),
			// An app-coded cancel is still a cancel, and the code maps to no
			// transport failure of its own.
			CancelReason::Application(_) => TransportError::OperationFailed(TransportFailure::Cancelled),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::super::link::MuxLink;
	use super::super::testing::{noop_cx, FlagWake};
	use super::*;

	use crate::constants::DEFAULT_HOP_BUDGET;
	use crate::transport::envelopes::MuxEnvelope;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	use crate::transport::envelopes::MuxPingPackage;

	fn shared(role: MuxRole, local_cap: u32) -> Arc<MuxShared> {
		Arc::new(MuxShared::new(role, &MuxSettings::symmetric(local_cap)))
	}

	fn shared_with_settings(role: MuxRole, settings: MuxSettings) -> Arc<MuxShared> {
		Arc::new(MuxShared::new(role, &settings))
	}

	/// Put `outcome` in the pending table as the open stream `stream_id`.
	fn hold_pending(shared: &MuxShared, stream_id: u32, outcome: oneshot::Sender<StreamOutcome>) {
		let mut state = shared.lock();
		let key = state.pending.reserve(outcome, None).expect("the reader runs");
		state.pending.open(key, stream_id).expect("the reservation is fresh");
	}

	fn slot() -> oneshot::Sender<StreamOutcome> {
		oneshot::channel().0
	}

	fn ping_slot() -> oneshot::Sender<()> {
		oneshot::channel().0
	}

	/// Open one stream through the production path. It reserves a slot, then
	/// atomically assigns the ID and enqueues the Open record.
	fn open_one(shared: &Arc<MuxShared>) -> TransportResult<u32> {
		let mut reservation = shared.reserve_stream_slot(slot())?;
		let (mut outbound, _wire) = mpsc::channel(4);
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: true,
			payload: &[],
			records: 1,
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
		};

		let mut cx = noop_cx();
		match shared.poll_open_enqueue(&mut reservation, &mut request, &mut outbound, &mut cx) {
			Poll::Ready(result) => result,
			Poll::Pending => Err(TransportError::ConnectionClosed),
		}
	}

	fn allocate_ids(shared: &Arc<MuxShared>, ids: impl AsRef<[u32]>) {
		let ids = ids.as_ref();
		for &id in ids {
			assert!(matches!(open_one(shared), Ok(got) if got == id));
		}
	}

	fn allocate_ping_ids(shared: &MuxShared, ids: impl AsRef<[u64]>) {
		let ids = ids.as_ref();
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
				allocate_ids(&shared, [1]);
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
			SlotSetup::PendingAtCap => allocate_ids(&shared, [1]),
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
		let error = reason.cancel_error();
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
		allocate_ids(&shared, [1, 3]);
		assert!(matches!(
			open_one(&shared),
			Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted))
		));
	}

	#[test]
	fn test_completed_stream_frees_cap_slot() {
		let shared = shared(MuxRole::Client, 1);
		allocate_ids(&shared, [1]);
		assert!(shared.remove_pending(1).is_some());
		allocate_ids(&shared, [3]);
	}

	// The atomic open gives the lower ID to whichever initiation sends its
	// Open first, whatever the reservation order, so Opens reach the peer in
	// strictly increasing ID order.
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

	// An open parked on the rekey hard floor holds its reservation, so the
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
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
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
		allocate_ids(&shared, [u32::MAX]);
		assert!(matches!(open_one(&shared), Err(TransportError::Draining)));
	}

	/// A GoAway that lands between reservation and enqueue stops the Open.
	///
	/// The reservation succeeds while admission is open, so this is the
	/// window the enqueue itself has to close (CWE-362).
	#[test]
	fn test_goaway_after_reservation_refuses_the_open() {
		let shared = shared(MuxRole::Client, 8);
		let mut reservation = shared.reserve_stream_slot(slot()).expect("admission is open");

		shared.fail_pending_above(0, GoAwayReason::Shutdown);

		let (mut outbound, _wire) = mpsc::channel(4);
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: true,
			payload: &[],
			records: 1,
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
		};

		let mut cx = noop_cx();
		let enqueued = shared.poll_open_enqueue(&mut reservation, &mut request, &mut outbound, &mut cx);
		assert!(matches!(enqueued, Poll::Ready(Err(TransportError::Draining))));
	}

	#[test]
	fn test_goaway_refuses_a_new_ping() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_pending_above(0, GoAwayReason::Shutdown);

		let (sender, _receiver) = oneshot::channel();
		assert!(matches!(shared.allocate_ping(sender), Err(TransportError::Draining)));
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

		hold_pending(&shared, 1, sender_low);
		hold_pending(&shared, 3, sender_high);
		shared.fail_pending_above(1, GoAwayReason::Shutdown);

		assert!(matches!(receiver_low.try_recv(), Ok(None)));
		assert!(matches!(receiver_high.try_recv(), Ok(Some(StreamOutcome::Draining))));
	}

	#[test]
	fn test_ping_allocates_monotonic_opaque() {
		let shared = shared(MuxRole::Client, 8);
		allocate_ping_ids(&shared, [0, 1, 2]);
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

	// The reader has ended, so no ack can arrive for a ping registered now.
	#[test]
	fn test_ping_refused_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_all_pending();
		assert!(matches!(
			shared.allocate_ping(ping_slot()),
			Err(TransportError::ConnectionClosed)
		));
	}

	/// A failure that lands between reservation and enqueue stops the Open.
	///
	/// The reservation succeeds while the reader runs, so this is the window
	/// the enqueue itself has to close (CWE-362).
	#[test]
	fn test_failure_after_reservation_refuses_the_open() {
		let shared = shared(MuxRole::Client, 8);
		let mut reservation = shared.reserve_stream_slot(slot()).expect("admission is open");

		shared.fail_all_pending();

		let (mut outbound, _wire) = mpsc::channel(4);
		let mut request = OpenRequest {
			kind: MuxStreamKind::Unary,
			last: true,
			payload: &[],
			records: 1,
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
		};

		let mut cx = noop_cx();
		let enqueued = shared.poll_open_enqueue(&mut reservation, &mut request, &mut outbound, &mut cx);
		assert!(matches!(enqueued, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	#[test]
	fn test_no_stream_headroom_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_all_pending();
		assert!(!shared.has_stream_headroom());
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_no_renewal_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.mark_rekey_client();
		shared.fail_all_pending();
		assert!(!shared.renewal_ready());
	}

	// The sweep returns the phase to `Idle`, so the phase alone would let a
	// renewal open on a connection that cannot answer it.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_renewal_not_entered_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_all_pending();
		assert!(shared.enter_renewal(|| Some(())).is_none());
	}

	#[test]
	fn test_reservation_refused_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_all_pending();

		let reserved = shared.reserve_stream_slot(slot());
		assert!(matches!(reserved, Err(TransportError::ConnectionClosed)));
	}

	#[test]
	fn test_stream_slot_refused_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.fail_all_pending();
		assert!(matches!(poll_slot(&shared), Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	#[test]
	fn test_stream_slot_wakes_on_connection_failure() {
		let shared = shared(MuxRole::Client, 1);
		allocate_ids(&shared, [1]);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Pending));

		shared.fail_all_pending();

		assert!(flag.woken());
		let woken = shared.poll_stream_slot(&mut cx);
		assert!(matches!(woken, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	// A graceful shutdown ends with the reader, and the later fact wins: the
	// drain could still finish, and a failed connection cannot.
	#[test]
	fn test_connection_failure_outranks_a_drain() {
		let shared = shared(MuxRole::Client, 8);
		shared.begin_shutdown();
		shared.fail_all_pending();

		let pinged = shared.allocate_ping(ping_slot());
		assert!(matches!(pinged, Err(TransportError::ConnectionClosed)));
	}

	/// Count the `MUX_EMIT_DRAINING` events one refused ping leaves, on a
	/// connection that `end` has brought to its end.
	#[cfg(feature = "instrument")]
	fn drain_events_of_a_refused_ping(end: impl FnOnce(&MuxShared)) -> usize {
		let trace = TraceCollector::new();
		let mut shared = MuxShared::new(MuxRole::Client, &MuxSettings::symmetric(8));
		shared.trace = Some(trace.share());
		end(&shared);

		let refused = shared.allocate_ping(ping_slot());
		refused.expect_err("an ended connection refuses a ping");

		let traced = trace.drain_events();
		traced.iter().filter(|event| event.urn == events::MUX_EMIT_DRAINING).count()
	}

	#[cfg(feature = "instrument")]
	#[test]
	fn test_drain_refusal_traces_a_drain() {
		let drains = drain_events_of_a_refused_ping(|shared| {
			shared.begin_shutdown();
		});
		assert_eq!(drains, 1);
	}

	// The event names a drain, and a failed connection is none.
	#[cfg(feature = "instrument")]
	#[test]
	fn test_connection_failure_refusal_traces_no_drain() {
		let drains = drain_events_of_a_refused_ping(MuxShared::fail_all_pending);
		assert_eq!(drains, 0);
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

		allocate_ids(&shared, [1]);

		assert!(shared.has_pending_streams());
		assert!(shared.remove_pending(1).is_some());
		assert!(!shared.has_pending_streams());
	}

	// A reserved slot (open_stream before the first push) must pin the
	// connection against the idle prune the same way a pending ID does.
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
		allocate_ids(&shared, [1]);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Pending));
		assert!(shared.remove_pending(1).is_some());

		assert!(flag.woken());
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Ready(Ok(()))));
	}

	// A reserved stream holds a cap slot before it has an ID, so each
	// question about room counts it.
	#[test]
	fn test_reserved_slot_counts_against_headroom() {
		let shared = shared(MuxRole::Client, 1);
		let _held = shared.reserve_stream_slot(slot()).expect("fresh connection has headroom");
		assert!(!shared.has_stream_headroom());
		assert!(matches!(poll_slot(&shared), Poll::Pending));
	}

	#[test]
	fn test_stream_slot_wakes_when_a_reservation_drops() {
		let shared = shared(MuxRole::Client, 1);
		let held = shared.reserve_stream_slot(slot()).expect("fresh connection has headroom");

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Pending));

		drop(held);

		assert!(flag.woken());
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Ready(Ok(()))));
	}

	#[test]
	fn test_stream_slot_wakes_on_shutdown() {
		let shared = shared(MuxRole::Client, 1);
		allocate_ids(&shared, [1]);

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

	/// Caps 1/1, chunk 1024, and unit 1024 give a drain headroom of 5 records
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

	// Only the reader applies a grant, so a ledger registered after it ended
	// has nothing to wait for at its limit.
	#[test]
	fn test_send_chunk_fails_at_limit_after_connection_failure() {
		let shared = shared_with_settings(MuxRole::Server, metered_settings(1, None));
		shared.fail_all_pending();
		shared.register_send_stream(2, 2);

		let mut cx = noop_cx();
		assert!(matches!(shared.poll_send_chunk(2, &mut cx), Poll::Ready(Ok(()))));
		let at_limit = shared.poll_send_chunk(2, &mut cx);
		assert!(matches!(at_limit, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	// The peer grants no credit for a stream its GoAway disowned, so a
	// producer parked on that stream has to wake with the sweep.
	#[test]
	fn test_goaway_wakes_a_producer_parked_above_the_watermark() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(1, None));
		allocate_ids(&shared, [1]);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Pending));

		shared.fail_pending_above(0, GoAwayReason::Shutdown);

		assert!(flag.woken());

		let resumed = shared.poll_send_chunk(1, &mut cx);
		assert!(matches!(
			resumed,
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)))
		));
	}

	// An Open that the writer queue refuses never left, so nothing may stay
	// registered to wait on it: no stream, no ledger, and no reply forwarder.
	#[test]
	fn test_open_that_does_not_enqueue_registers_nothing() {
		let shared = shared(MuxRole::Client, 8);
		let (drained, _notes) = mpsc::channel(1);
		let (mut reservation, mut body) = shared.reserve_duplex_slot(drained).expect("admission is open");
		let (mut outbound, wire) = mpsc::channel(4);
		drop(wire);

		let mut request = OpenRequest {
			kind: MuxStreamKind::Duplex,
			last: true,
			payload: &[],
			records: 1,
			target: None,
			hops_remaining: DEFAULT_HOP_BUDGET,
		};

		let mut cx = noop_cx();
		let enqueued = reservation.poll_open(&mut request, &mut outbound, &mut cx);
		assert!(matches!(enqueued, Poll::Ready(Err(TransportError::ConnectionClosed))));
		assert!(!shared.has_pending_streams());

		let ledger = shared.poll_send_chunk(1, &mut cx);
		assert!(matches!(
			ledger,
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)))
		));

		let ended = body.poll_chunk_now();
		assert!(matches!(ended, Poll::Ready(Err(TransportError::ConnectionClosed))));
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
		// A grant at or below the current limit leaves the limit as it is.
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

		// Of 10 credits, 5 are reserved, so 4 spend cleanly.
		assert!(matches!(shared.debit_send_budget(4, false), Ok(BudgetStanding::Healthy)));
		// With 6 credits left and 1 spendable, a debit of 6 must fail fast
		// instead of parking.
		assert!(matches!(
			shared.debit_send_budget(6, false),
			Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted))
		));
		// The last spendable credit tips the balance into the reserve.
		assert!(matches!(shared.debit_send_budget(1, false), Ok(BudgetStanding::Exhausting)));
		// Owed (reserved) traffic keeps flowing inside the reserve.
		assert!(matches!(shared.debit_send_budget(5, true), Ok(BudgetStanding::Exhausting)));
		// The reserve also refuses an overdraft.
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

	/// A waker that records whether the epoch receipt had rotated when it
	/// woke.
	struct ReceiptWitness {
		shared: Arc<MuxShared>,
		rotated: core::sync::atomic::AtomicBool,
	}

	impl futures::task::ArcWake for ReceiptWitness {
		fn wake_by_ref(arc_self: &Arc<Self>) {
			let rotated = arc_self.shared.session_receipt().is_some();
			arc_self.rotated.store(rotated, core::sync::atomic::Ordering::SeqCst);
		}
	}

	/// An admission released by a completed renewal debits the new epoch, so
	/// it must find the new epoch's receipt already in place when it wakes.
	#[tokio::test]
	async fn test_a_released_admission_reads_the_new_epoch_receipt(
	) -> Result<(), crate::transport::handshake::HandshakeError> {
		use crate::transport::rekey::tests::{rekey_pair, run_exchange};

		let (mut client, mut server) = rekey_pair()?;
		let (client_install, _) = run_exchange(&mut client, &mut server).await?;

		let shared = shared_with_settings(MuxRole::Client, budget_settings(10));
		begin_client_renewal(&shared);
		assert!(shared.admit_rekey_response());

		shared.mark_ack_written();

		let witness = Arc::new(ReceiptWitness { shared: Arc::clone(&shared), rotated: Default::default() });
		let waker = futures::task::waker(Arc::clone(&witness));
		let parked = shared.poll_admit_debit(1, false, &mut Context::from_waker(&waker));
		assert!(matches!(parked, Poll::Pending));

		assert!(shared.complete_renewal(client_install.receipt));
		assert!(witness.rotated.load(core::sync::atomic::Ordering::SeqCst));
		Ok(())
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_hard_floor_parks_chunks_until_ack_writes() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(2, None));
		shared.register_send_stream(1, 1);
		begin_client_renewal(&shared);
		assert!(shared.park_hard_floor());

		let (mut outbound, _outbound_rx) = mpsc::channel(4);
		let ping = MuxPingPackage::new(false, 0);
		let mut slot = Some(TransportEnvelope::from(ping));
		let (flag, waker) = FlagWake::pair();
		let mut parked_cx = Context::from_waker(&waker);
		let parked = shared.poll_send_enqueue(1, &mut outbound, &mut slot, &mut parked_cx);
		assert!(matches!(parked, Poll::Pending));

		// The renewal reaches the Ack write through the flush phase, the same
		// order the reader and writer drive it in.
		assert!(shared.admit_rekey_response());
		shared.mark_ack_written();
		assert!(flag.woken());

		let mut cx = noop_cx();
		let enqueued = shared.poll_send_enqueue(1, &mut outbound, &mut slot, &mut cx);
		assert!(matches!(enqueued, Poll::Ready(Ok(()))));
	}

	/// The writer observes a renewal in flight, then parks the floor, and the
	/// reader can close that renewal between the two steps. Only a phase
	/// change lifts a parked floor, so the park decides under the phase lock:
	/// with the renewal gone it writes nothing and chunks keep flowing.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_park_hard_floor_refuses_once_the_renewal_closed() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(2, None));
		shared.register_send_stream(1, 1);
		begin_client_renewal(&shared);

		// The reader abandons the renewal after the writer saw it in flight.
		shared.finish_renewal();

		assert!(!shared.park_hard_floor());

		let (mut outbound, _outbound_rx) = mpsc::channel(4);
		let ping = MuxPingPackage::new(false, 0);
		let mut slot = Some(TransportEnvelope::from(ping));
		let mut cx = noop_cx();

		let enqueued = shared.poll_send_enqueue(1, &mut outbound, &mut slot, &mut cx);
		assert!(matches!(enqueued, Poll::Ready(Ok(()))));
	}

	// A cancel enqueued while the queue is saturated still travels, because
	// the teardown clone's guaranteed slot admits it past a full buffer. The
	// channel capacity is the buffer plus the senders.
	#[test]
	fn test_stream_cancel_survives_saturated_queue() {
		let shared = shared(MuxRole::Client, 2);
		allocate_ids(&shared, [1]);

		let (outbound, mut wire) = mpsc::channel(0);
		let mut filler = outbound.clone();
		while filler.try_send(Outbound::Close).is_ok() {}

		let (link, _) = MuxLink::new(shared, outbound);
		link.enqueue_stream_cancel(1);

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

	// A peer GoAway disowns duplex replies above its watermark, so those
	// bodies fail with Draining and the rest stay live.
	#[test]
	fn test_fail_duplex_above_fails_disowned_replies() {
		let shared = shared(MuxRole::Client, 4);
		let (feedback, _notes) = mpsc::channel(0);
		let (mut kept, below) = StreamBody::pair(OpenSlot::assigned(1), 4, feedback.clone());
		let (mut disowned, above) = StreamBody::pair(OpenSlot::assigned(3), 4, feedback);

		shared.insert_duplex(1, below);
		shared.insert_duplex(3, above);
		shared.fail_duplex_above(1);

		assert!(matches!(kept.poll_chunk_now(), Poll::Pending));
		assert!(matches!(disowned.poll_chunk_now(), Poll::Ready(Err(TransportError::Draining))));
		assert!(shared.take_duplex(1).is_some());
		assert!(shared.take_duplex(3).is_none());
	}
}
