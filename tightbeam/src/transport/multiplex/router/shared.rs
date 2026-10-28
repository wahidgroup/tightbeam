//! The connection-wide state that the drivers and the stream handles share:
//! stream allocation, sender-side flow control, budgets, the GoAway drain,
//! and the rekey phase.

use core::future::{poll_fn, Future};
use core::num::NonZeroU32;
use core::pin::Pin;
#[cfg(not(all(test, tightbeam_loom)))]
use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use core::task::{Context, Poll, Waker};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use futures::channel::{mpsc, oneshot};
#[cfg(all(test, tightbeam_loom))]
use loom::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

use super::body::{BodyEvent, DrainNote, ForwardedStream, StreamBody};
use super::flow::{cap_as_usize, ChunkSize};
use super::outbound::Outbound;
use super::pending::{PendingReplies, ReservationKey};
use super::reassembly::ReassemblyBudget;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{
	CancelReason, GoAwayReason, MuxOpenPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::error::TransportFailure;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::multiplex::MuxRole;
use crate::transport::{TransportError, TransportResult};
use crate::urn::Urn;
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::StoredReceipt;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::{InternalEvent, TraceCollector};

/// Wakes every parked waker and empties the set.
fn wake_all(wakers: &mut Vec<Waker>) {
	for waker in wakers.drain(..) {
		waker.wake();
	}
}

/// Registers the waker of `cx`. The clone only raises a reference count.
pub fn park_waker(waiters: &mut Vec<Waker>, cx: &Context<'_>) {
	waiters.push(cx.waker().clone());
}

/// The identity of a locally-initiated stream, whose ID the atomic open
/// assigns at the first send.
///
/// - It is vacant until the Open record enqueues, then holds the assigned ID.
///   Stream IDs start at 1 (client) or 2 (server), so zero means "not opened
///   yet".
/// - The parts that outlive the open (sinks, response futures, reply bodies,
///   cancel guards) share it, so each acts on the real ID once it exists and
///   stands down when the connection refuses the open.
pub struct OpenSlot(AtomicU32);

impl OpenSlot {
	const VACANT: u32 = 0;

	fn vacant() -> Arc<Self> {
		Arc::new(Self(AtomicU32::new(Self::VACANT)))
	}

	/// Returns a slot for a stream whose ID is already known, such as a
	/// peer-initiated body or a reply, so the slot starts assigned.
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

/// A cap slot held for a stream until it sends its Open record.
///
/// [`MuxShared::poll_open_enqueue`] assigns the stream ID in the critical
/// section that enqueues the Open, so Opens reach the peer in strictly
/// increasing ID order ([RFC 9113 § 5.1.1][rfc9113-5.1.1]), however the
/// initiations interleave. The pending table holds the stream from its
/// reservation on.
///
/// # Drop
///
/// - An unopened reservation cancels its stream: the cap slot goes back, and the caller reads a cancel.
/// - A reservation that a failure or a GoAway resolved first finds its slot freed and its waiters woken.
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
	/// Clones a handle to the stream's late-assigned identity. The clone only
	/// raises a reference count.
	pub fn slot(&self) -> Arc<OpenSlot> {
		Arc::clone(&self.slot)
	}

	/// Opens the stream through the atomic open of
	/// [`MuxShared::poll_open_enqueue`], on the connection that reserved it.
	///
	/// The reservation names its own connection, so the open always runs
	/// there. On another connection, its key would name another stream.
	///
	/// # Errors
	///
	/// - The errors of [`MuxShared::poll_open_enqueue`].
	pub fn poll_open(
		&mut self,
		request: &mut OpenRequest<'_>,
		outbound: &mut mpsc::Sender<Outbound>,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<u32>> {
		// The clone raises a reference count and leaves the reservation free
		// to give up its key.
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
	/// The chunk bytes that the Open record carries.
	pub payload: &'a [u8],
	/// The record count that this Open seeds the sender ledger with: the
	/// payload's chunk count, or the whole message's count for a unary emit.
	pub records: u64,
	/// The grpc-style route stamped on the Open record, or `None` for an
	/// unrouted local open.
	pub target: Option<Urn<'static>>,
	/// The relay budget stamped beside the route: the number of gateway
	/// forwards the stream has left. A gateway that holds an open at `0` serves
	/// it locally and forwards nothing.
	pub hops_remaining: u8,
}

/// The outcome delivered to a pending stream's oneshot slot.
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
	/// The result that the caller reads for one pending stream.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the response carries a status other than `Ok`, so the responder refused.
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

/// The client-side renewal state across the key-switch boundaries. A server
/// endpoint and a session without rekey materials stay `Idle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyPhase {
	/// No renewal is in flight.
	Idle,
	/// The client wrote `RekeyRequest` and awaits the server's response.
	AwaitingResponse,
	/// The client verified the response. Admissions of c2s traffic stay
	/// parked while owed chunks flush ahead of the `RekeyAck`.
	FlushingAck,
	/// The client wrote `RekeyAck` and switched the send cipher. Admissions of
	/// c2s traffic stay parked until `RekeyDone` activates the fresh epoch
	/// budget.
	AwaitingDone,
}

/// The disposition of a stream that the peer initiates.
pub enum PeerStream {
	/// The endpoint accepts and processes the stream.
	Accept,
	/// This endpoint already sent its GoAway, and the stream is newer than its
	/// `last_stream_id`, so the endpoint refuses it before any work on it.
	RejectDraining,
}

/// The sender-side flow-control ledger for one stream direction, after QUIC
/// MAX_STREAM_DATA ([RFC 9000 § 4.1][rfc9000-4.1]).
///
/// Requests and responses on the same stream stay distinct here. An endpoint
/// sends request chunks only on IDs it allocated, and response chunks only on
/// IDs the peer allocated.
///
/// [rfc9000-4.1]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
struct SendStream {
	/// The count of chunks already permitted onto the outbound queue.
	sent: u64,
	/// The absolute cumulative chunk limit that the peer granted.
	limit: u64,
	/// The count of registered chunks that wait for a permit, which the drain
	/// accounting reads.
	unsent: u64,
	/// The wakers parked until the peer raises the limit.
	credit_wakers: Vec<Waker>,
}

/// The outcome of an outbound session-budget debit.
pub enum BudgetStanding {
	/// Spendable credits remain, or the session is unmetered.
	Healthy,
	/// The balance fell to the drain reserve, so the caller renews in band or
	/// starts the [`GoAwayReason::BudgetExhausted`] drain.
	Exhausting,
}

/// The mutable connection state behind the [`MuxShared`] lock.
struct MuxState {
	/// The next locally-initiated stream ID, or `None` once the ID space is
	/// exhausted. IDs are strictly monotonic over the nonzero values.
	next_stream_id: Option<u32>,
	/// The highest peer-initiated stream ID seen, or 0 before the first.
	last_peer_stream_id: u32,
	/// The reserved streams, open streams, and pings that await their
	/// answer. It decides admission and owns the cap-relevant open-stream
	/// count (see [`StreamReservation`]).
	pending: PendingReplies,
	/// The next correlation value for a locally-initiated ping.
	next_ping_opaque: u64,
	/// The sender-side flow-control ledgers, one per stream.
	send_streams: HashMap<u32, SendStream>,
	/// The credits left in the outbound session budget, or `None` for an
	/// unmetered session.
	send_budget: Option<u64>,
	/// The chunks producers registered that wait for a permit, across all
	/// streams. The writer adds them to its drain headroom, so owed chunks
	/// always fit inside the records left.
	unsent_chunks: u64,
	/// The `last_stream_id` this endpoint advertised in its GoAway, once sent.
	goaway_sent: Option<u32>,
	/// The `last_stream_id` received in the peer's GoAway.
	goaway_received: Option<u32>,
	/// The reason that the peer's GoAway carries, once received. A local
	/// shutdown leaves this empty, because the caller already knows why.
	goaway_reason: Option<GoAwayReason>,
	/// The wakers parked until the pending table drains at shutdown.
	drain_wakers: Vec<Waker>,
	/// The wakers parked until a stream slot frees while the cap is full.
	slot_wakers: Vec<Waker>,
	/// The in-band renewal state. Only a client with rekey materials ever
	/// leaves `Idle`.
	rekey: RekeyPhase,
	/// `true` while a renewal is in flight with send records down to the
	/// drain headroom, so data chunks park until the fresh cipher installs.
	rekey_hard_floor: bool,
	/// Whether this endpoint opens renewals: rekey materials are attached in
	/// a role that opens them. [`MuxShared::mark_rekey_attached`] derives it
	/// from the role, so the readers read one value.
	opens_renewals: bool,
	/// The wakers parked on renewal transitions: admissions that wait out a
	/// renewal, chunks on the hard floor, and the writer that waits for owed
	/// chunks to quiesce ahead of the `RekeyAck`.
	rekey_wakers: Vec<Waker>,
}

impl MuxState {
	/// Wakes every task parked until the pending table drains.
	fn wake_drain_waiters(&mut self) {
		wake_all(&mut self.drain_wakers);
	}

	/// Wakes every task parked until a stream slot frees.
	fn wake_slot_waiters(&mut self) {
		wake_all(&mut self.slot_wakers);
	}

	/// Wakes every task parked on a renewal transition.
	pub fn wake_rekey_waiters(&mut self) {
		wake_all(&mut self.rekey_wakers);
	}

	/// The ID a new locally-initiated stream would take, while the connection
	/// admits one.
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

	/// Whether a renewal may open in this state: the phase is
	/// [`RekeyPhase::Idle`], and the connection admits work.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn admits_renewal(&self) -> bool {
		self.rekey == RekeyPhase::Idle && self.pending.refusal().is_none()
	}
}

/// The connection-wide mux state that the drivers and the stream handles
/// share through an `Arc`.
pub struct MuxShared {
	/// The handshake role of this endpoint, which fixes whether its stream
	/// IDs are odd or even. [`Self::new`] sets it once.
	role: MuxRole,
	state: Mutex<MuxState>,
	/// The number of concurrent streams this endpoint may initiate, as the
	/// peer advertised.
	pub local_cap: u32,
	/// The largest chunk payload this endpoint may send, as the peer
	/// advertised.
	pub send_chunk_size: ChunkSize,
	/// The bytes per session-budget credit, negotiated for both directions.
	pub credit_unit: NonZeroU32,
	/// The initial per-stream chunk limit for outbound data, as the peer
	/// advertised.
	initial_send_credit: u64,
	/// The initial per-stream chunk limit granted to the peer. It is the
	/// local receive window, which duplex reply bodies size from.
	pub initial_recv_credit: u64,
	/// The connection collector inherited from the split halves.
	/// Control-plane events land here (see [`crate::instrumentation::events`]).
	#[cfg(feature = "instrument")]
	pub trace: Option<TraceCollector>,
	/// The reply forwarders for open locally-initiated duplex streams. The
	/// atomic open registers each one under its stream ID, and the reader
	/// drives it to forward each response chunk as it arrives, in place of a
	/// reassembly. A forwarder waits in the pending table until its stream
	/// opens.
	///
	/// # Partition
	///
	/// Forwarder registries partition by initiator. This map holds only
	/// locally-initiated stream IDs, and the reader's `peer_bodies` holds only
	/// peer-initiated ones. Every teardown path (cancel, GoAway, connection
	/// failure) must clear its side of both registries, and the pending table
	/// for a stream that has not opened.
	duplex_recv: Mutex<HashMap<u32, ForwardedStream>>,
	/// The reassembly ceiling that every peer stream on this connection
	/// shares: the unary reassembly of the reader, and the collect of each
	/// stream body.
	reassembly_budget: Arc<ReassemblyBudget>,
	/// The credits reserved so owed traffic can flush during a budget drain.
	/// See [`MuxSettings::send_budget_reserve`].
	budget_drain_headroom: u64,
	/// The negotiated outbound budget, restored at each epoch boundary. The
	/// credit-match invariant keeps the epoch receipt budgets equal to the
	/// initial terms.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	initial_send_budget: Option<u64>,
	/// The dual-signed receipt of the current epoch. A renewal rotates it.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	session_receipt: Mutex<Option<Arc<StoredReceipt>>>,
}

impl MuxShared {
	/// Returns the shared state for `role` under the negotiated `settings`,
	/// with no stream open.
	pub fn new(role: MuxRole, settings: &MuxSettings) -> Self {
		Self {
			role,
			local_cap: settings.local_initiated_cap(),
			send_chunk_size: ChunkSize::new(cap_as_usize(settings.send_chunk_size())),
			credit_unit: settings.credit_unit(),
			initial_send_credit: settings.initial_send_credit(),
			initial_recv_credit: settings.initial_recv_credit(),
			duplex_recv: Mutex::new(HashMap::new()),
			reassembly_budget: Arc::new(ReassemblyBudget::default()),
			budget_drain_headroom: settings.send_budget_reserve(),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			initial_send_budget: settings.send_budget(),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			session_receipt: Mutex::new(None),
			#[cfg(feature = "instrument")]
			trace: None,
			state: Mutex::new(MuxState {
				next_stream_id: Some(role.first_local_stream_id()),
				last_peer_stream_id: 0,
				pending: PendingReplies::default(),
				next_ping_opaque: 0,
				send_streams: HashMap::new(),
				send_budget: settings.send_budget(),
				unsent_chunks: 0,
				goaway_sent: None,
				goaway_received: None,
				goaway_reason: None,
				drain_wakers: Vec::new(),
				slot_wakers: Vec::new(),
				rekey: RekeyPhase::Idle,
				rekey_hard_floor: false,
				opens_renewals: false,
				rekey_wakers: Vec::new(),
			}),
		}
	}

	/// The handshake role of this endpoint, which fixes whether its stream
	/// IDs are odd or even.
	pub fn role(&self) -> MuxRole {
		self.role
	}

	/// The reassembly budget of this connection, which every peer stream
	/// charges.
	pub(crate) fn reassembly_budget(&self) -> Arc<ReassemblyBudget> {
		Arc::clone(&self.reassembly_budget)
	}

	/// Locks the connection state, and recovers the guard from a poisoned lock.
	fn lock(&self) -> MutexGuard<'_, MuxState> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// The session-budget credits that an outbound payload debits at the
	/// peer's receive chunk size and the negotiated credit unit.
	pub fn credits_for(&self, payload_len: usize) -> u64 {
		self.send_chunk_size.credits(payload_len, self.credit_unit)
	}

	/// The chunk records that an outbound payload occupies at the peer's
	/// receive chunk size.
	pub fn records_for(&self, payload_len: usize) -> u64 {
		self.send_chunk_size.records(payload_len)
	}

	/// A future that resolves once the connection would admit a
	/// locally-initiated stream. Its creation only raises a reference count.
	pub fn stream_slot(self: &Arc<Self>) -> StreamSlot {
		StreamSlot { shared: Arc::clone(self) }
	}

	/// A future that resolves once the pending table drains. Its creation
	/// only raises a reference count.
	pub fn drain_pending(self: &Arc<Self>) -> DrainPending {
		DrainPending { shared: Arc::clone(self) }
	}

	/// Locks the duplex reply registry, and recovers the guard from a poisoned
	/// lock.
	fn duplex_lock(&self) -> MutexGuard<'_, HashMap<u32, ForwardedStream>> {
		self.duplex_recv.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Registers the reply forwarder for a locally-initiated duplex stream. The
	/// caller holds the state lock, and the table admitted the stream, so no
	/// forwarder lands on a failed connection.
	fn insert_duplex(&self, stream_id: u32, forwarder: ForwardedStream) {
		self.duplex_lock().insert(stream_id, forwarder);
	}

	/// Detaches a duplex reply forwarder while its stream resolves.
	pub fn take_duplex(&self, stream_id: u32) -> Option<ForwardedStream> {
		self.duplex_lock().remove(&stream_id)
	}

	/// Forwards one reply chunk into a duplex body. It returns `None` when the
	/// registry holds no forwarder for the stream, and `Some(false)` on a
	/// credit overrun or a body channel that refuses the chunk.
	pub fn forward_duplex_chunk(&self, stream_id: u32, payload: impl AsRef<[u8]>) -> Option<bool> {
		let payload = payload.as_ref();
		let mut map = self.duplex_lock();
		let stream = map.get_mut(&stream_id)?;

		let accepted = stream.accept_and_forward(payload);
		Some(accepted)
	}

	/// The granted limit and the window of a duplex reply body, while its
	/// forwarder is registered.
	pub fn duplex_limits(&self, stream_id: u32) -> Option<(u64, u64)> {
		let map = self.duplex_lock();
		let stream = map.get(&stream_id)?;

		Some(stream.limits())
	}

	/// Raises a duplex reply body's granted limit.
	pub fn set_duplex_limit(&self, stream_id: u32, limit: u64) {
		if let Some(stream) = self.duplex_lock().get_mut(&stream_id) {
			stream.raise_limit(limit);
		}
	}

	/// Fails the duplex replies that the peer's GoAway disowned: the streams
	/// above its high-water mark, which the peer leaves unanswered.
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

	/// Drops every duplex reply forwarder on connection failure, so the bodies
	/// observe the closed channel.
	fn fail_all_duplex(&self) {
		self.duplex_lock().clear();
	}

	/// Drops a stream's sender ledger under the lock. Its unflushed chunks
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

	/// Moves the rekey phase from `from` to `to`, and reports whether the move
	/// happened.
	///
	/// The precondition and the write live together, so the phase moves only
	/// from `from` and the rekey sequence stays ordered.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn advance_rekey(state: &mut MuxState, from: RekeyPhase, to: RekeyPhase) -> bool {
		if state.rekey != from {
			return false;
		}

		state.rekey = to;
		true
	}

	/// Wakes the writer once owed chunks quiesce while it holds a `RekeyAck`
	/// back, because the ack trails every old-epoch chunk.
	fn wake_on_quiesce(state: &mut MuxState) {
		if state.unsent_chunks == 0 && state.rekey == RekeyPhase::FlushingAck {
			state.wake_rekey_waiters();
		}
	}

	/// Registers the sender-side ledger for a stream about to carry
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

	/// Drops a stream's sender ledger outside the pending-table paths, such as
	/// for response streams and abandoned sends.
	pub fn finish_send_stream(&self, stream_id: u32) {
		let mut state = self.lock();
		Self::drop_send_stream(&mut state, stream_id);
	}

	/// Extends a registered sender ledger by `chunks` outbound records.
	///
	/// Streamed replies learn their length one push at a time. When the
	/// ledger is gone, the stream already resolved through a cancel or a
	/// failure, and the send path reports that itself.
	pub fn add_send_records(&self, stream_id: u32, chunks: u64) {
		let mut state = self.lock();
		let Some(stream) = state.send_streams.get_mut(&stream_id) else {
			return;
		};
		stream.unsent = stream.unsent.saturating_add(chunks);
		state.unsent_chunks = state.unsent_chunks.saturating_add(chunks);
	}

	/// Consumes one unit of stream credit under the lock, or parks.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::Cancelled`] -- the ledger is gone. The stream
	///   resolved underneath the sender through a cancel, a response, or a
	///   connection failure, and the outcome channel carries the real outcome.
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

	/// Resolves once the peer's grant admits the stream's next chunk, and
	/// consumes one unit of credit.
	#[cfg(test)]
	pub fn poll_send_chunk(&self, stream_id: u32, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		let mut state = self.lock();
		Self::take_chunk_credit(&mut state, stream_id, cx)
	}

	/// Consumes one unit of stream credit and enqueues the chunk's envelope in
	/// one critical section, so each data envelope that passes the floor check
	/// enters the queue ahead of a rekey `RekeyAck` boundary (strict park).
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

	/// Applies a peer credit grant.
	///
	/// The grant is idempotent and monotonic, so only a limit above the
	/// current one changes anything. It discards a grant for an unknown stream,
	/// because a grant that races stream completion is benign.
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

	/// Debits `credits` from the budget in `state`.
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

	/// Debits `credits` from the outbound session budget through
	/// [`Self::debit_budget`], for tests. Production paths wait out renewals
	/// through [`Self::admit_debit`].
	#[cfg(test)]
	pub fn debit_send_budget(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
		let mut state = self.lock();
		Self::debit_budget(&mut state, self.budget_drain_headroom, credits, reserved)
	}

	/// Debits the outbound session budget between renewals.
	///
	/// Client admissions park across a renewal so every debit belongs to one
	/// epoch. Budgets reset at `RekeyDone`, and a debit issued mid-renewal
	/// could otherwise straddle the boundary. A draining connection skips the
	/// park, because the renewal is dead and owed traffic must flush.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::BudgetExhausted`] -- the budget cannot carry
	///   `credits`.
	pub fn poll_admit_debit(
		&self,
		credits: u64,
		reserved: bool,
		cx: &mut Context<'_>,
	) -> Poll<TransportResult<BudgetStanding>> {
		let mut state = self.lock();
		let draining = state.pending.is_draining();
		let renewing = state.opens_renewals && state.rekey != RekeyPhase::Idle;
		if renewing && !draining {
			park_waker(&mut state.rekey_wakers, cx);
			return Poll::Pending;
		}

		Poll::Ready(Self::debit_budget(&mut state, self.budget_drain_headroom, credits, reserved))
	}

	/// Debits the outbound budget, and waits out any renewal in flight.
	///
	/// This is the one admission of emits, pushes, and responses, so the
	/// connection's trail records each debit that the budget refuses here, as
	/// `MUX_BUDGET_REFUSED`.
	///
	/// # Errors
	///
	/// - The errors of [`poll_admit_debit`](Self::poll_admit_debit).
	/// - The injected error, when the runtime fault model injects a fault at
	///   the record of a refusal, in place of the refusal.
	pub async fn admit_debit(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
		let admitted = poll_fn(|cx| self.poll_admit_debit(credits, reserved, cx)).await;

		#[cfg(feature = "instrument")]
		if let Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)) = admitted {
			self.trace_budget_refusal(credits, reserved)?;
		}

		admitted
	}

	/// Traces a debit of `credits` that the outbound budget refused, as
	/// `MUX_BUDGET_REFUSED`. The label names whether the debit could spend
	/// the drain reserve, and the credits it asked for are the value.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the trace.
	#[cfg(feature = "instrument")]
	fn trace_budget_refusal(&self, credits: u64, reserved: bool) -> TransportResult<()> {
		let Some(trace) = self.trace.as_ref() else {
			return Ok(());
		};

		let debit = if reserved {
			"reserved"
		} else {
			"unreserved"
		};
		Ok(trace.emit_event_with_value(events::MUX_BUDGET_REFUSED, debit, credits)?)
	}

	/// Returns `credits` to the outbound budget, for a debit whose payload
	/// stays unsent.
	///
	/// The balance caps at the terms of the epoch, so a refund that lands
	/// after a renewal restored the budget stops at those terms.
	pub(crate) fn refund_budget(&self, credits: u64) {
		let mut state = self.lock();
		let Some(balance) = state.send_budget else {
			return;
		};

		let refunded = balance.saturating_add(credits);
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		let refunded = self.initial_send_budget.map_or(refunded, |terms| refunded.min(terms));
		state.send_budget = Some(refunded);
	}

	/// The credits left in the outbound budget, or `None` when the session is
	/// unmetered.
	#[cfg(test)]
	pub(crate) fn send_budget(&self) -> Option<u64> {
		self.lock().send_budget
	}

	/// The chunks that producers registered and that wait for a permit, across
	/// all streams.
	pub fn unsent_chunks(&self) -> u64 {
		self.lock().unsent_chunks
	}

	/// The current renewal phase, which the writer's renewal deadline reads.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	pub fn rekey_phase(&self) -> RekeyPhase {
		self.lock().rekey
	}

	/// Whether this endpoint may open a renewal at this instant. It requires
	/// the client role with rekey materials, an `Idle` phase, and a connection
	/// that admits work.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn renewal_ready(&self) -> bool {
		let state = self.lock();
		state.opens_renewals && state.admits_renewal()
	}

	/// Marks rekey materials attached, which in a role that opens renewals
	/// activates the renewal triggers and the admission gate.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn mark_rekey_attached(&self) {
		self.lock().opens_renewals = self.role.opens_renewals();
	}

	/// Transitions `Idle` to `AwaitingResponse` exactly once.
	///
	/// `open` runs under the state lock, so concurrent triggers collapse to a
	/// single opened renewal, and an `open` failure leaves the phase
	/// untouched. It returns `None` when a renewal is already in flight, the
	/// connection admits no work, or `open` declined.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn enter_renewal<T>(&self, open: impl FnOnce() -> Option<T>) -> Option<T> {
		let mut state = self.lock();
		if !state.admits_renewal() {
			return None;
		}

		let request = open()?;
		Self::advance_rekey(&mut state, RekeyPhase::Idle, RekeyPhase::AwaitingResponse);
		Some(request)
	}

	/// Whether owed c2s chunks have quiesced: the registered and flushed counts
	/// agree. Otherwise it parks `cx` on the rekey waker set, so the caller
	/// re-polls when the last owed chunk flushes.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn poll_chunks_quiesced(&self, cx: &Context<'_>) -> bool {
		let mut state = self.lock();
		if state.unsent_chunks == 0 {
			return true;
		}

		park_waker(&mut state.rekey_wakers, cx);
		false
	}

	/// Admits a `RekeyResponse` (client) and enters
	/// [`RekeyPhase::FlushingAck`], where c2s admissions stay parked while owed
	/// chunks flush ahead of the `RekeyAck`.
	///
	/// The phase check and the move are one step under the lock, so a
	/// response that arrives out of order leaves the phase as it is. It
	/// returns whether it admitted the response.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn admit_rekey_response(&self) -> bool {
		let mut state = self.lock();
		if !Self::advance_rekey(&mut state, RekeyPhase::AwaitingResponse, RekeyPhase::FlushingAck) {
			return false;
		}

		// Owed chunks may already be quiescent, so give the writer its wake
		// here, ahead of the next ledger transition.
		Self::wake_on_quiesce(&mut state);
		true
	}

	/// Records that the writer wrote the `RekeyAck` (client). The send cipher
	/// is active after the Ack, which lifts the hard-floor park.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn mark_ack_written(&self) {
		let mut state = self.lock();
		if !Self::advance_rekey(&mut state, RekeyPhase::FlushingAck, RekeyPhase::AwaitingDone) {
			return;
		}

		state.rekey_hard_floor = false;
		state.wake_rekey_waiters();
	}

	/// Closes a renewal that completed (client, on `RekeyDone`), and reports
	/// whether the renewal closed.
	///
	/// - The phase check, the send budget reset, and the receipt rotation all
	///   happen under the lock, before any parked admission wakes, so an
	///   admission that debits the new epoch also reads its receipt.
	/// - A `RekeyDone` that arrives before the writer wrote the `RekeyAck` leaves the phase as it is.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn complete_renewal(&self, receipt: StoredReceipt) -> bool {
		let mut state = self.lock();
		if !Self::advance_rekey(&mut state, RekeyPhase::AwaitingDone, RekeyPhase::Idle) {
			return false;
		}

		state.send_budget = self.initial_send_budget;

		// The receipt slot is always the inner lock, so the rotation here
		// keeps the lock order.
		self.rotate_receipt(receipt);
		Self::release_renewal(&mut state);
		true
	}

	/// Abandons the renewal from any phase after the attempt dies or meets a
	/// refusal. Admissions resume, the hard floor lifts, and parked tasks wake.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn finish_renewal(&self) {
		let mut state = self.lock();
		Self::abandon_renewal(&mut state);
	}

	/// Returns the renewal to `Idle` from any phase. Apart from a completed
	/// renewal, this is the only write of `Idle`.
	fn abandon_renewal(state: &mut MuxState) {
		state.rekey = RekeyPhase::Idle;
		Self::release_renewal(state);
	}

	/// Lifts the hard floor and wakes everything parked on the renewal.
	fn release_renewal(state: &mut MuxState) {
		state.rekey_hard_floor = false;
		state.wake_rekey_waiters();
	}

	/// Parks data chunks, because send records are down to the drain headroom
	/// while a renewal is in flight, and what remains is reserved for control
	/// and the exchange legs.
	///
	/// # Phase check
	///
	/// The phase check and the park are one step under the lock. Only a
	/// renewal in flight can lift the floor, so a floor set after the reader
	/// closed the renewal would park data until the connection died. With the
	/// phase `Idle` it leaves the floor down and returns `false`, and the
	/// caller falls through to the drain decision.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn park_hard_floor(&self) -> bool {
		let mut state = self.lock();
		if state.rekey == RekeyPhase::Idle {
			return false;
		}

		state.rekey_hard_floor = true;
		true
	}

	/// Restores the outbound budget to the negotiated terms at the `RekeyDone`
	/// boundary. The credit-match invariant keeps the epoch receipt's terms
	/// equal to the initial ones.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn reset_send_budget(&self) {
		self.lock().send_budget = self.initial_send_budget;
	}

	/// Publishes the completed epoch receipt to the handle accessors.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn rotate_receipt(&self, receipt: impl Into<Arc<StoredReceipt>>) {
		let mut slot = self.session_receipt.lock().unwrap_or_else(PoisonError::into_inner);
		*slot = Some(receipt.into());
	}

	/// The current epoch's dual-signed receipt, once a handshake or a renewal
	/// published one.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
		let slot = self.session_receipt.lock().unwrap_or_else(PoisonError::into_inner);
		slot.as_ref().map(Arc::clone)
	}

	/// Records that a responder answered a stream with a fault of this
	/// endpoint: [`TransitStatus::Internal`] from a local inconsistency, or the
	/// status of a dispatch method that failed. The peer-observed status then
	/// has a local investigation trail.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	///
	/// [`TransitStatus::Internal`]: crate::policy::TransitStatus::Internal
	pub(crate) fn note_internal_error(&self) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		self.emit_event(events::MUX_INTERNAL_ERROR)?;
		Ok(())
	}

	/// Records that the responder refused a peer stream with `status`, as
	/// `MUX_STREAM_REFUSED`. The status names why, and it is the value a spec
	/// asserts.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	pub(crate) fn note_stream_refused(&self, status: TransitStatus) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		if let Some(trace) = self.trace.as_ref() {
			trace.emit_event_with_value(events::MUX_STREAM_REFUSED, status.as_str(), status)?;
		}

		#[cfg(not(feature = "instrument"))]
		let _ = status;

		Ok(())
	}

	/// Records that the responder routed one peer stream to the dispatch method
	/// of its kind, as the internal event `ROUTE_STEP`.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	pub(crate) fn note_route_step(&self) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		if let Some(trace) = self.trace.as_ref() {
			trace.emit_internal_event(InternalEvent::RouteStep)?;
		}

		Ok(())
	}

	/// Traces an admission refusal that a drain caused.
	///
	/// `MUX_EMIT_DRAINING` names a drain, so it fires for
	/// [`TransportError::Draining`] alone.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the trace.
	#[cfg(feature = "instrument")]
	fn trace_refusal(&self, refusal: &TransportError) -> TransportResult<()> {
		if matches!(refusal, TransportError::Draining) {
			self.emit_event(events::MUX_EMIT_DRAINING)?;
		}
		Ok(())
	}

	/// Writes a control-plane event twice: the core kind URN into the
	/// instrument log, and the stable label for spec assertions and CSP
	/// alphabets.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(feature = "instrument")]
	pub fn emit_event(&self, event: Urn<'static>) -> TransportResult<()> {
		let Some(trace) = self.trace.as_ref() else {
			return Ok(());
		};

		Ok(trace.emit_event(event)?)
	}

	/// Records a GoAway control event. The reason name labels why, and its
	/// code is the assertable value.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at `event`.
	#[cfg(feature = "instrument")]
	pub fn emit_goaway_event(&self, event: Urn<'static>, reason: GoAwayReason) -> TransportResult<()> {
		let Some(trace) = self.trace.as_ref() else {
			return Ok(());
		};

		Ok(trace.emit_event_with_value(event, reason.as_str(), u32::from(reason))?)
	}

	/// Reserves a cap slot for a locally-initiated stream, whose ID the open
	/// assigns later.
	///
	/// [`Self::poll_open_enqueue`] assigns the ID when the Open record
	/// enqueues, so it always matches the send order. This call checks
	/// admission (live drivers, the drain, the cap, the ID space) at the
	/// caller-visible initiation point.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway ended admission, or the ID space is exhausted.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::StreamsExhausted`] -- the open load is at the
	///   local cap.
	/// - The injected error, when the runtime fault model injects a fault at the event of the refusal.
	pub fn reserve_stream_slot(
		self: &Arc<Self>,
		sender: oneshot::Sender<StreamOutcome>,
	) -> TransportResult<StreamReservation> {
		self.reserve_slot(sender, None, OpenSlot::vacant())
	}

	/// Reserves a cap slot for a duplex stream, with the body that its reply
	/// streams into.
	///
	/// The reply forwarder waits with the reservation in the pending table and
	/// registers under the assigned ID when the Open record enqueues. A
	/// connection that fails or drains before then ends the body.
	///
	/// # Errors
	///
	/// - The errors of [`reserve_stream_slot`](Self::reserve_stream_slot).
	pub fn reserve_duplex_slot(
		self: &Arc<Self>,
		drained: mpsc::Sender<DrainNote>,
	) -> TransportResult<(StreamReservation, StreamBody)> {
		let slot = OpenSlot::vacant();
		let budget = self.reassembly_budget();
		let (body, reply) = StreamBody::pair(Arc::clone(&slot), self.initial_recv_credit, drained, budget);
		// The reply travels through the body, so the outcome has no reader and
		// the pending entry holds the cap slot and the forwarder alone.
		let (outcome, _) = oneshot::channel();
		let reservation = self.reserve_slot(outcome, Some(reply), slot)?;

		Ok((reservation, body))
	}

	/// Admits one reservation, with the reply forwarder of a duplex.
	///
	/// # Errors
	///
	/// - The errors of [`reserve_stream_slot`](Self::reserve_stream_slot).
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
			self.trace_refusal(&refusal)?;

			return Err(refusal);
		}
		if state.pending.open_load() >= cap_as_usize(self.local_cap) {
			drop(state);

			#[cfg(feature = "instrument")]
			self.emit_event(events::MUX_STREAMS_EXHAUSTED)?;

			return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
		}

		let key = state.pending.reserve(outcome, reply)?;
		drop(state);

		Ok(StreamReservation { shared: Arc::clone(self), key: Some(key), slot })
	}

	/// The atomic open: it assigns the next stream ID and enqueues the stream's
	/// Open record in one critical section, so Opens reach the peer in strictly
	/// increasing ID order, however concurrent initiations interleave.
	///
	/// The caller MUST have reserved queue capacity through `poll_ready` on
	/// `outbound` first.
	///
	/// # Preconditions
	///
	/// It checks every precondition, such as the rekey hard floor, before it
	/// consumes the ID, so a `Pending` leaves the ID and the queue slot free.
	/// The fresh ledger's initial credit is at least one, so the Open's own
	/// credit debit proceeds at once.
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
		// This builds the record before anything registers, so an Open that
		// does not encode leaves the reservation whole.
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
		// Seed the ledger, then take the Open's own credit, which the initial
		// grant floor of one admits at once.
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
			// The Open stayed off the queue, so each registration that waits
			// on it drops here, and each dropped sender ends its half of the
			// stream.
			Self::drop_send_stream(&mut state, stream_id);
			drop(state.pending.take_stream(stream_id));
			drop(self.take_duplex(stream_id));
		}

		Poll::Ready(enqueued.map(|()| stream_id))
	}

	/// Detaches a pending stream's outcome sender and releases its sender
	/// ledger, or returns `None` for an unknown ID.
	pub fn remove_pending(&self, stream_id: u32) -> Option<oneshot::Sender<StreamOutcome>> {
		let mut state = self.lock();
		let entry = state.pending.take_stream(stream_id);
		if entry.is_some() {
			// The stream is over, so the release of its sender ledger wakes a
			// producer parked on credit, and that producer stops.
			Self::drop_send_stream(&mut state, stream_id);
			state.wake_drain_waiters();
			state.wake_slot_waiters();
		}

		entry
	}

	/// Resolves a pending stream. It discards an unknown ID silently, because
	/// a cancel can race a response on the connection.
	pub fn resolve(&self, stream_id: u32, outcome: StreamOutcome) {
		if let Some(sender) = self.remove_pending(stream_id) {
			// A dropped receiver is an initiator that cancelled, the same race
			// an unknown ID is.
			let _ = sender.send(outcome);
		}
	}

	/// Registers a locally-initiated ping and returns its correlation value.
	///
	/// It refuses the ping while the connection drains, because a peer that
	/// honors the GoAway contract reserves the records it has left for owed
	/// stream traffic (see [`MuxSettings::drain_reserve_records`]).
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway went out or came in.
	/// - The injected error, when the runtime fault model injects a fault at the event of the refusal.
	pub fn allocate_ping(&self, sender: oneshot::Sender<()>) -> TransportResult<u64> {
		let mut state = self.lock();
		if let Some(refusal) = state.pending.refusal() {
			drop(state);

			#[cfg(feature = "instrument")]
			self.trace_refusal(&refusal)?;

			return Err(refusal);
		}

		let opaque = state.next_ping_opaque;
		state.pending.admit_ping(opaque, sender)?;
		state.next_ping_opaque = opaque.wrapping_add(1);

		Ok(opaque)
	}

	/// Resolves a pending ping. It discards an unknown correlation value
	/// silently, because a stale ack that races a dropped ping future is
	/// benign.
	pub fn resolve_ping(&self, opaque: u64) {
		if let Some(sender) = self.lock().pending.take_ping(opaque) {
			// A dropped receiver is a ping future already gone, and its late
			// ack is as benign as a stale one.
			let _ = sender.send(());
		}
	}

	/// Forgets a pending ping, and drops its sender unresolved.
	pub fn remove_pending_ping(&self, opaque: u64) {
		self.lock().pending.forget_ping(opaque);
	}

	/// Whether this endpoint already sent its GoAway.
	pub fn shutdown_begun(&self) -> bool {
		self.lock().goaway_sent.is_some()
	}

	/// Drops every pending slot on connection failure.
	///
	/// - Receivers observe cancellation.
	/// - Producers parked on credit observe the ledger removal.
	/// - Any renewal in flight is dead, and the peer abandoned its `RekeyDone`,
	///   so parked admissions resume and meet the failure.
	/// - Admission ends for good under the lock that clears the tables, so a
	///   stream or ping after the sweep fails at once with
	///   [`TransportError::ConnectionClosed`], because its driver is gone.
	pub fn fail_all_pending(&self) {
		let mut state = self.lock();
		state.pending.close();
		// An Open registers its reply forwarder under this lock, after the
		// table admits it, so the clear here, behind the close, catches every
		// forwarder the table admitted.
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

	/// Resolves pending streams above `last_stream_id` as draining, because the
	/// peer's GoAway disowned them. A stream that holds only a reservation
	/// resolves the same way, because a GoAway ends admission. It records the
	/// peer's reason for [`MuxShared::goaway_reason`].
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at
	///   the event of the GoAway, after every stream above `last_stream_id`
	///   resolved.
	pub fn fail_pending_above(&self, last_stream_id: u32, reason: GoAwayReason) -> TransportResult<()> {
		{
			let mut state = self.lock();
			state.goaway_received = Some(last_stream_id);
			state.goaway_reason = Some(reason);

			if let Some(first_dropped) = last_stream_id.checked_add(1) {
				for (stream_id, sender) in state.pending.take_streams_from(first_dropped) {
					// A dropped receiver is an initiator that gave up before
					// the GoAway, which leaves nothing to resolve.
					let _ = sender.send(StreamOutcome::Draining);
					// The peer's credit for a stream it disowned has ended, so
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
		self.emit_goaway_event(events::MUX_GOAWAY_RECV, reason)?;
		Ok(())
	}

	/// Halts the allocator and records the GoAway watermark. A stream that
	/// holds only a reservation resolves as draining, because a GoAway ends
	/// admission.
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

	/// Validates and records the ID of a stream that the peer initiates, per
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

	/// The highest peer-initiated stream ID seen, or 0 before the first.
	pub fn last_peer_stream_id(&self) -> u32 {
		self.lock().last_peer_stream_id
	}

	/// Whether a new locally-initiated stream fits at this instant. It fits
	/// while both drivers run, before a GoAway in either direction, with a live
	/// ID space, and with an open load under the cap.
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

	/// Whether `stream_id` awaits its response.
	pub fn is_pending(&self, stream_id: u32) -> bool {
		self.lock().pending.holds_stream(stream_id)
	}

	/// The reason that the peer's GoAway carried, once received.
	pub fn goaway_reason(&self) -> Option<GoAwayReason> {
		self.lock().goaway_reason
	}

	/// Resolves once the connection would admit a locally-initiated stream.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway ended admission, or the ID space is exhausted.
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

/// A future that resolves once the connection would admit a locally-initiated
/// stream, or fails once admission has ended for good.
pub struct StreamSlot {
	shared: Arc<MuxShared>,
}

impl Future for StreamSlot {
	type Output = TransportResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
		self.shared.poll_stream_slot(cx)
	}
}

/// A future that resolves once the pending table drains: every in-flight local
/// stream completed, failed, or met a cancel.
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
			// An app-coded cancel counts as a cancel, so it maps to `Cancelled`
			// whatever its code.
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

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::transport::envelopes::MuxPingPackage;

	#[cfg(feature = "instrument")]
	use super::super::testing::poll_now;
	#[cfg(feature = "instrument")]
	use crate::trace::AssertionValue;

	fn shared(role: MuxRole, local_cap: u32) -> Arc<MuxShared> {
		Arc::new(MuxShared::new(role, &MuxSettings::symmetric(local_cap)))
	}

	fn shared_with_settings(role: MuxRole, settings: MuxSettings) -> Arc<MuxShared> {
		Arc::new(MuxShared::new(role, &settings))
	}

	/// Receives the peer's GoAway of `reason` above `last_stream_id` on
	/// `shared`, whose trace injects no fault.
	fn receive_goaway(shared: &MuxShared, last_stream_id: u32, reason: GoAwayReason) {
		let received = shared.fail_pending_above(last_stream_id, reason);
		received.expect("a state with no fault model records the GoAway");
	}

	/// Puts `outcome` in the pending table as the open stream `stream_id`.
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

	/// Opens one stream through the production path. It reserves a slot, then
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

	/// Opens `count` streams on `shared`, and returns the ID of each in the
	/// order it opened.
	fn open_streams(shared: &Arc<MuxShared>, count: usize) -> Vec<u32> {
		(0..count)
			.map(|_| open_one(shared).expect("a test stream opens under the cap"))
			.collect()
	}

	/// Allocates `count` pings on `shared`, and returns the correlation value
	/// of each, in the order of allocation.
	fn allocate_pings(shared: &MuxShared, count: usize) -> Vec<u64> {
		(0..count)
			.map(|_| shared.allocate_ping(ping_slot()).expect("a test ping allocates on a live link"))
			.collect()
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
				open_streams(&shared, 1);
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
				receive_goaway(&shared, 0, GoAwayReason::EnhanceYourCalm);
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
			SlotSetup::PendingAtCap => {
				open_streams(&shared, 1);
			}
			SlotSetup::DrainingLocal => {
				shared.begin_shutdown();
			}
			SlotSetup::DrainingPeer => {
				receive_goaway(&shared, 0, GoAwayReason::Shutdown);
			}
		}
		shared
	}

	crate::tb_cases! {
		fn test_cancel_reason_error_mapping((reason, failure): (CancelReason, TransportFailure)) {
			let error = reason.cancel_error();
			assert!(matches!(
				error,
				TransportError::OperationFailed(got) if got == failure
			));
		}
		cases {
			rejected => (CancelReason::Rejected, TransportFailure::ResourceExhausted),
			timeout => (CancelReason::Timeout, TransportFailure::DeadlineExceeded),
			cancelled => (CancelReason::Cancelled, TransportFailure::Cancelled),
			application => (CancelReason::Application(0x1000), TransportFailure::Cancelled),
		}
	}

	crate::tb_cases! {
		fn test_role_allocates_monotonic_ids((role, ids): (MuxRole, &[u32])) {
			let shared = shared(role, 8);
			assert_eq!(open_streams(&shared, ids.len()), ids);
		}
		cases {
			client => (MuxRole::Client, &[1, 3, 5]),
			server => (MuxRole::Server, &[2, 4]),
		}
	}

	#[test]
	fn test_cap_exhaustion_reports_busy() {
		let shared = shared(MuxRole::Client, 2);
		open_streams(&shared, 2);
		assert!(matches!(
			open_one(&shared),
			Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted))
		));
	}

	#[test]
	fn test_completed_stream_frees_cap_slot() {
		let shared = shared(MuxRole::Client, 1);
		open_streams(&shared, 1);
		assert!(shared.remove_pending(1).is_some());
		assert_eq!(open_streams(&shared, 1), [3]);
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
		receive_goaway(&shared, 0, GoAwayReason::Shutdown);
		assert!(matches!(open_one(&shared), Err(TransportError::Draining)));
	}

	#[test]
	fn test_id_space_exhaustion_reports_draining() {
		let shared = shared(MuxRole::Client, 8);
		shared.lock().next_stream_id = Some(u32::MAX);
		open_streams(&shared, 1);
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

		receive_goaway(&shared, 0, GoAwayReason::Shutdown);

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
		receive_goaway(&shared, 0, GoAwayReason::Shutdown);

		let (sender, _receiver) = oneshot::channel();
		assert!(matches!(shared.allocate_ping(sender), Err(TransportError::Draining)));
	}

	// A peer of a server opens odd IDs alone, and ID 0 is reserved.
	crate::tb_cases! {
		fn test_peer_stream_rejects_invalid_ids(id: u32) {
			let server = shared(MuxRole::Server, 8);
			assert!(matches!(server.register_peer_stream(id), Err(TransportError::InvalidMessage)));
		}
		cases {
			reserved_zero => 0,
			the_server_parity => 2,
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
		receive_goaway(&shared, 1, GoAwayReason::Shutdown);

		assert!(matches!(receiver_low.try_recv(), Ok(None)));
		assert!(matches!(receiver_high.try_recv(), Ok(Some(StreamOutcome::Draining))));
	}

	#[test]
	fn test_ping_allocates_monotonic_opaque() {
		let shared = shared(MuxRole::Client, 8);
		assert_eq!(allocate_pings(&shared, 3), [0, 1, 2]);
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

	// The reader has ended, so no ack can arrive for a ping registered later.
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

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn test_no_renewal_after_connection_failure() {
		let shared = shared(MuxRole::Client, 8);
		shared.mark_rekey_attached();
		shared.fail_all_pending();
		assert!(!shared.renewal_ready());
	}

	// A server holds its rekey materials to answer renewals, so its budget
	// reserve takes the GoAway drain.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn test_renewal_readiness_takes_the_client_role() {
		let shared = shared(MuxRole::Server, 8);
		shared.mark_rekey_attached();
		assert!(!shared.renewal_ready());
	}

	// The sweep returns the phase to `Idle`, so the phase alone would let a
	// renewal open on a connection that cannot answer it.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
		open_streams(&shared, 1);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_stream_slot(&mut cx), Poll::Pending));

		shared.fail_all_pending();

		assert!(flag.woken());
		let woken = shared.poll_stream_slot(&mut cx);
		assert!(matches!(woken, Poll::Ready(Err(TransportError::ConnectionClosed))));
	}

	// An orderly shutdown ends with the reader, and the later fact wins: the
	// drain could finish, and a failed connection cannot.
	#[test]
	fn test_connection_failure_outranks_a_drain() {
		let shared = shared(MuxRole::Client, 8);
		shared.begin_shutdown();
		shared.fail_all_pending();

		let pinged = shared.allocate_ping(ping_slot());
		assert!(matches!(pinged, Err(TransportError::ConnectionClosed)));
	}

	/// Counts the `MUX_EMIT_DRAINING` events one refused ping leaves, on a
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

	crate::tb_cases! {
		fn test_stream_headroom((setup, expect): (HeadroomSetup, bool)) {
			let shared = prepare_headroom(setup);
			assert_eq!(shared.has_stream_headroom(), expect);
		}
		cases {
			fresh => (HeadroomSetup::Fresh { cap: 2 }, true),
			at_cap => (HeadroomSetup::AtCap { cap: 1 }, false),
			local_shutdown => (HeadroomSetup::LocalShutdown { cap: 2 }, false),
		}
	}

	#[test]
	fn test_pending_streams_track_in_flight() {
		let shared = shared(MuxRole::Client, 8);
		assert!(!shared.has_pending_streams());

		open_streams(&shared, 1);

		assert!(shared.has_pending_streams());
		assert!(shared.remove_pending(1).is_some());
		assert!(!shared.has_pending_streams());
	}

	// A reserved slot (`open_stream` before the first push) must pin the
	// connection against the idle prune as a pending ID does.
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

	crate::tb_cases! {
		fn test_goaway_reason_from_peer_only((setup, expected): (GoAwaySetup, Option<GoAwayReason>)) {
			let shared = prepare_goaway(setup);
			assert_eq!(shared.goaway_reason(), expected);
		}
		cases {
			live => (GoAwaySetup::Live, None),
			peer_enhance_your_calm => (GoAwaySetup::PeerEnhanceYourCalm, Some(GoAwayReason::EnhanceYourCalm)),
			local_shutdown => (GoAwaySetup::LocalShutdown, None),
		}
	}

	crate::tb_cases! {
		fn test_stream_slot_poll_outcomes((setup, expect): (SlotSetup, SlotExpect)) {
			let shared = prepare_slot(setup);
			assert_slot_poll(&shared, expect);
		}
		cases {
			ready_with_headroom => (SlotSetup::ReadyWithHeadroom, SlotExpect::ReadyOk),
			pending_at_cap => (SlotSetup::PendingAtCap, SlotExpect::Pending),
			draining_local => (SlotSetup::DrainingLocal, SlotExpect::Draining),
			draining_peer => (SlotSetup::DrainingPeer, SlotExpect::Draining),
		}
	}

	#[test]
	fn test_stream_slot_wakes_when_slot_frees() {
		let shared = shared(MuxRole::Client, 1);
		open_streams(&shared, 1);

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
		open_streams(&shared, 1);

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
		let settings = MuxSettings::symmetric(4).with_initial_credit(initial_send_credit);
		settings.with_send_budget(send_budget)
	}

	/// Caps of 1 and 1, a chunk of 1024, and the default unit of 1024 give a
	/// drain headroom of 5 records at 1 credit each.
	fn budget_settings(send_budget: u64) -> MuxSettings {
		let settings = MuxSettings::symmetric(1).with_chunk_size(1024);
		settings.with_send_budget(Some(send_budget))
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

	// The peer's credit for a stream its GoAway disowned has ended, so a
	// producer parked on that stream has to wake with the sweep.
	#[test]
	fn test_goaway_wakes_a_producer_parked_above_the_watermark() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(1, None));
		open_streams(&shared, 1);

		let (flag, waker) = FlagWake::pair();
		let mut cx = Context::from_waker(&waker);
		assert!(matches!(shared.poll_send_chunk(1, &mut cx), Poll::Pending));

		receive_goaway(&shared, 0, GoAwayReason::Shutdown);

		assert!(flag.woken());

		let resumed = shared.poll_send_chunk(1, &mut cx);
		assert!(matches!(
			resumed,
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)))
		));
	}

	// An Open that the writer queue refuses stays off the queue, so the
	// stream, the ledger, and the reply forwarder that wait on it all drop.
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

		// Of 10 credits, 5 are reserved, so a debit of 4 stays `Healthy`.
		assert!(matches!(shared.debit_send_budget(4, false), Ok(BudgetStanding::Healthy)));
		// With 6 credits left and 1 spendable, a debit of 6 must fail fast
		// in place of a park.
		assert!(matches!(
			shared.debit_send_budget(6, false),
			Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted))
		));
		// The last spendable credit tips the balance into the reserve.
		assert!(matches!(shared.debit_send_budget(1, false), Ok(BudgetStanding::Exhausting)));
		// Owed (reserved) traffic spends inside the reserve.
		assert!(matches!(shared.debit_send_budget(5, true), Ok(BudgetStanding::Exhausting)));
		// The reserve also refuses an overdraft.
		assert!(matches!(
			shared.debit_send_budget(1, true),
			Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted))
		));
	}

	/// What an admission of a debit of `credits` past a budget of 10 credits
	/// leaves: whether the budget refused it as exhausted, and the labels and
	/// the values of its refusal records.
	#[cfg(feature = "instrument")]
	fn refusal_records(credits: u64, reserved: bool) -> (bool, Vec<Option<String>>, Vec<Option<AssertionValue>>) {
		let trace = TraceCollector::new();
		let mut shared = MuxShared::new(MuxRole::Client, &budget_settings(10));
		shared.trace = Some(trace.share());

		let refused = poll_now(shared.admit_debit(credits, reserved));
		let exhausted = matches!(
			refused,
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)))
		);

		let records = trace.drain_events();
		let labels = records
			.into_iter()
			.filter(|record| record.urn == events::MUX_BUDGET_REFUSED)
			.map(|record| record.label.map(String::from))
			.collect();
		let values = trace.drain_assertions().into_iter().map(|record| record.value).collect();
		(exhausted, labels, values)
	}

	// The refusal of a debit names whether the debit could spend the drain
	// reserve, and carries the credits it asked for as its value.
	#[cfg(feature = "instrument")]
	crate::tb_cases! {
		fn a_refused_debit_records_its_refusal((reserved, label): (bool, &str)) {
			let expected = (true, vec![Some(label.to_owned())], vec![Some(AssertionValue::from(11u64))]);
			assert_eq!(refusal_records(11, reserved), expected);
		}
		cases {
			unreserved => (false, "unreserved"),
			reserved => (true, "reserved"),
		}
	}

	/// A refund that lands after a renewal restored the budget stops at the
	/// terms of the epoch.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_refund_after_a_renewal_stays_within_the_terms() -> TransportResult<()> {
		let shared = shared_with_settings(MuxRole::Client, budget_settings(10));
		shared.debit_send_budget(4, false)?;
		shared.reset_send_budget();

		shared.refund_budget(4);
		assert_eq!(shared.send_budget(), Some(10));
		Ok(())
	}

	#[test]
	fn test_unmetered_budget_never_exhausts() {
		let shared = shared_with_settings(MuxRole::Client, metered_settings(1, None));
		assert!(matches!(shared.debit_send_budget(u64::MAX, false), Ok(BudgetStanding::Healthy)));
	}

	/// Puts a client-side shared state into an in-flight renewal.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn begin_client_renewal(shared: &MuxShared) {
		shared.mark_rekey_attached();
		let mut state = shared.lock();
		state.rekey = RekeyPhase::AwaitingResponse;
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
	/// change lifts a parked floor, so the park decides under the state lock:
	/// with the renewal gone it leaves the floor down and chunks pass.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

	// A cancel enqueued while the queue is saturated travels, because the
	// teardown clone's guaranteed slot admits it past a full buffer. The
	// channel capacity is the buffer plus the senders.
	#[test]
	fn test_stream_cancel_survives_saturated_queue() {
		let shared = shared(MuxRole::Client, 2);
		open_streams(&shared, 1);

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
		let budget = shared.reassembly_budget();
		let (mut kept, below) = StreamBody::pair(OpenSlot::assigned(1), 4, feedback.clone(), Arc::clone(&budget));
		let (mut disowned, above) = StreamBody::pair(OpenSlot::assigned(3), 4, feedback, budget);

		shared.insert_duplex(1, below);
		shared.insert_duplex(3, above);
		shared.fail_duplex_above(1);

		assert!(matches!(kept.poll_chunk_now(), Poll::Pending));
		assert!(matches!(disowned.poll_chunk_now(), Poll::Ready(Err(TransportError::Draining))));
		assert!(shared.take_duplex(1).is_some());
		assert!(shared.take_duplex(3).is_none());
	}
}

/// The loom model of the open slot, which the first send assigns while the
/// handles that share the slot read it.
#[cfg(all(test, tightbeam_loom))]
mod loom_models {
	use loom::thread::{self, JoinHandle};

	use super::*;

	/// The stream ID the model assigns.
	const STREAM_ID: u32 = 3;

	/// Assigns `stream_id` to `slot` on a new thread.
	fn spawn_assign(slot: &Arc<OpenSlot>, stream_id: u32) -> JoinHandle<()> {
		let slot = Arc::clone(slot);

		thread::spawn(move || slot.assign(stream_id))
	}

	/// Waits for `handle`.
	fn joined(handle: JoinHandle<()>) {
		handle.join().expect("the model thread finishes");
	}

	/// A read that races the assignment sees a vacant slot or the assigned ID,
	/// and a read after the assignment sees the ID.
	#[test]
	fn a_read_racing_the_assignment_sees_vacant_or_the_id() {
		loom::model(|| {
			let slot = OpenSlot::vacant();
			let assigning = spawn_assign(&slot, STREAM_ID);
			let raced = slot.get();
			joined(assigning);

			assert!(matches!(raced, None | Some(STREAM_ID)));
			assert_eq!(slot.get(), Some(STREAM_ID));
		});
	}
}
