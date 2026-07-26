//! HTTP/2-style multiplexing: concurrent request/response streams over a
//! single connection.
//!
//! A [`MuxTransport`] is built from split envelope halves plus
//! [`MuxSettings`]. Encrypted halves come from
//! [`TcpTransport::into_split`](crate::transport::TcpTransport::into_split)
//! with handshake-negotiated settings. Cleartext halves come from
//! [`TcpTransport::into_split_cleartext`](crate::transport::TcpTransport::into_split_cleartext)
//! with out-of-band symmetric settings and NO confidentiality, integrity,
//! replay, or deletion protection. It decomposes into four parts:
//!
//! - [`MuxWriterDriver`]: single serialization point. Drains an outbound
//!   queue and writes each envelope through the send half.
//! - [`MuxReaderDriver`]: reads envelopes off the read half, routes
//!   responses to their pending streams and requests to the responder.
//! - [`MuxHandle`]: cloneable client handle. [`MuxHandle::emit_on_stream`]
//!   allocates a stream, sends the request, and awaits the correlated
//!   response. [`MuxHandle::ping`] probes connection liveness without
//!   touching a stream or the peer's handler.
//! - [`MuxResponder`]: serves peer-initiated streams with a caller-supplied
//!   handler, enforcing the advertised concurrency cap.
//!
//! Stream ID rules follow [RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1)/[§ 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2): odd IDs are
//! client-initiated, even IDs server-initiated, ID 0 is reserved and never
//! allocated, and each endpoint allocates strictly monotonically. Per-stream
//! timeouts compose externally: wrap the emit future in a timeout and the
//! drop guard cancels the stream on expiry.

use core::future::Future;

#[cfg(feature = "transport-policy")]
use crate::policy::GatePolicy;
use crate::transport::handshake::negotiation::{MuxSettings, TransportOffer};
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;
use crate::Frame;

/// Stream identifier within one multiplexed connection.
///
/// Odd IDs are client-initiated, even IDs server-initiated, and ID 0 is
/// reserved ([RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

impl StreamId {
	/// Wrap a raw stream ID.
	pub const fn new(id: u32) -> Self {
		Self(id)
	}

	/// Raw numeric ID carried on the wire.
	pub const fn value(&self) -> u32 {
		self.0
	}

	/// Client-initiated streams use odd IDs.
	pub const fn is_client_initiated(&self) -> bool {
		self.0 % 2 == 1
	}

	/// Server-initiated streams use even IDs (including the reserved ID 0).
	pub const fn is_server_initiated(&self) -> bool {
		self.0.is_multiple_of(2)
	}
}

/// Stream state for multiplexed transports
///
/// Streams in `Open`, `HalfClosedLocal`, or `HalfClosedRemote` count toward
/// the peer-advertised concurrency cap. `Idle` and `Closed` do not
/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
	/// Stream is idle (not yet used)
	Idle,
	/// Stream is open and active
	Open,
	/// Stream is half-closed (local side closed)
	HalfClosedLocal,
	/// Stream is half-closed (remote side closed)
	HalfClosedRemote,
	/// Stream is fully closed
	Closed,
}

/// Endpoint role on a multiplexed connection, fixing odd/even stream IDs:
/// clients allocate odd IDs, servers even IDs (HTTP/2 convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRole {
	/// Handshake initiator. Allocates odd stream IDs
	Client,
	/// Handshake responder. Allocates even stream IDs
	Server,
}

impl MuxRole {
	const fn first_local_stream_id(self) -> u32 {
		match self {
			MuxRole::Client => 1,
			MuxRole::Server => 2,
		}
	}

	/// Whether this role is the initiator of `stream_id` (ID 0 belongs to
	/// no role).
	const fn initiates(self, stream_id: u32) -> bool {
		match self {
			MuxRole::Client => !stream_id.is_multiple_of(2),
			MuxRole::Server => stream_id != 0 && stream_id.is_multiple_of(2),
		}
	}

	const fn peer(self) -> MuxRole {
		match self {
			MuxRole::Client => MuxRole::Server,
			MuxRole::Server => MuxRole::Client,
		}
	}
}

/// Concurrent request/response streams over one connection.
///
/// Cap, allocate, and cancel contracts match [`MuxHandle`]; this trait
/// exists so the pool and other callers stay generic over the concrete
/// handle type.
pub trait MultiplexedProtocol {
	/// Peer-advertised cap on concurrent locally-initiated streams
	/// (HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` analog).
	fn max_concurrent_streams(&self) -> u32;

	/// Allocate a stream, send `frame`, await the correlated response.
	///
	/// Dropping the future before it resolves cancels the stream and frees
	/// its concurrency slot.
	fn emit_on_stream(&self, frame: &Frame) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend;

	/// Best-effort cancel of a locally-initiated in-flight stream: frees
	/// the slot and notifies the peer without blocking.
	fn close_stream(&self, stream_id: StreamId);
}

/// Mux capability advertisement, bound into the handshake transcript.
///
/// Implemented only by transports that can attach the mux plane after
/// negotiation (split envelope halves plus spawned drivers): advertising
/// anywhere else would negotiate a capability the endpoint cannot honor.
pub trait MuxCapable: Sized {
	/// Set the local mux advertisement. `None` advertises nothing.
	fn with_mux_offer(self, offer: Option<TransportOffer>) -> Self;

	/// Negotiated multiplexing settings from a completed handshake.
	/// `None` means the connection is single-flight.
	fn negotiated_mux(&self) -> Option<MuxSettings>;
}

/// Client-side mux connection setup.
///
/// Abstracts the concrete transport so the connection pool stays generic
/// over [`Protocol`](crate::transport::Protocol).
pub trait MuxConnector: MuxCapable {
	/// Envelope read half after splitting.
	type EnvelopeReader: EnvelopeSource + Send + 'static;
	/// Envelope write half after splitting.
	type EnvelopeWriter: EnvelopeSink + Send + 'static;

	/// Drive the client handshake to completion. Does nothing on transports
	/// without encryption material, which then never negotiate mux.
	fn complete_client_handshake(&mut self) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Split into envelope halves for the mux drivers.
	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)>;
}

/// Collector gate plus envelope halves of a consumed [`MuxAcceptor`].
#[cfg(feature = "transport-policy")]
pub type GatedHalves<T> = (
	Box<dyn GatePolicy>,
	(<T as MuxAcceptor>::EnvelopeReader, <T as MuxAcceptor>::EnvelopeWriter),
);

/// Server-side counterpart of [`MuxConnector`]: negotiate multiplexing
/// while accepting, then hand the connection to the mux plane.
#[cfg(feature = "transport-policy")]
pub trait MuxAcceptor: MuxCapable {
	/// Envelope read half after splitting.
	type EnvelopeReader: EnvelopeSource + Send + 'static;
	/// Envelope write half after splitting.
	type EnvelopeWriter: EnvelopeSink + Send + 'static;

	/// Drive the server-side handshake to completion and report the
	/// negotiated multiplexing settings. `Ok(None)` means the connection
	/// MUST be served single-flight.
	fn negotiate_mux(&mut self) -> impl Future<Output = TransportResult<Option<MuxSettings>>> + MaybeSend;

	/// Consume the transport into its collector gate plus envelope halves.
	/// Consuming means no placeholder gate ever sits inside a live
	/// collector: the gate moves to the mux responder, the transport
	/// ceases to exist.
	fn into_gated_halves(self) -> TransportResult<GatedHalves<Self>>;
}

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
mod router {
	use core::future::{poll_fn, Future};
	use core::pin::Pin;
	use core::task::{Context, Poll, Waker};
	use std::collections::{BTreeMap, HashMap, VecDeque};
	use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

	use futures::channel::{mpsc, oneshot};
	use futures::future::{select, AbortHandle, Abortable, Aborted, Either};
	use futures::stream::FuturesUnordered;
	use futures::{pin_mut, SinkExt, Stream, StreamExt};

	use super::{MultiplexedProtocol, MuxRole, StreamId};
	use crate::constants::{DEFAULT_MUX_CANCEL_BUDGET, DEFAULT_MUX_STREAM_CREDIT};
	use crate::der::{Decode, Encode};
	use crate::policy::TransitStatus;
	use crate::transport::envelopes::{
		CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxCreditPackage, MuxDataPackage, MuxEndPackage,
		MuxEnvelope, MuxOpenPackage, MuxPingPackage, ResponsePackage, TransportEnvelope,
	};
	use crate::transport::error::TransportFailure;
	use crate::transport::handshake::negotiation::MuxSettings;
	use crate::transport::io::{EnvelopeSink, EnvelopeSource};
	use crate::transport::{TransportError, TransportResult};
	use crate::utils::marker::MaybeSend;
	use crate::Frame;

	fn cap_as_usize(cap: u32) -> usize {
		usize::try_from(cap).unwrap_or(usize::MAX)
	}

	/// Ping acks the reader buffers while the writer queue is full.
	/// Probes beyond this backlog draw no ack, so a ping flood against a
	/// saturated connection extracts nothing (CVE-2019-9512).
	const MAX_PENDING_PING_ACKS: usize = 4;

	fn wake_all(wakers: &mut Vec<Waker>) {
		for waker in wakers.drain(..) {
			waker.wake();
		}
	}

	fn len_as_u64(len: usize) -> u64 {
		u64::try_from(len).unwrap_or(u64::MAX)
	}

	/// Chunk records a payload occupies at `chunk_size` bytes per chunk.
	/// An empty payload travels inline in its trailer and occupies none.
	fn chunk_records(payload_len: usize, chunk_size: usize) -> u64 {
		len_as_u64(payload_len).div_ceil(len_as_u64(chunk_size.max(1)))
	}

	/// Session-budget credits a payload debits: `ceil(len / credit_unit)`
	/// summed per chunk, so the sender's whole-frame debit equals the sum
	/// of the receiver's per-chunk debits.
	fn payload_credits(payload_len: usize, chunk_size: usize, credit_unit: u32) -> u64 {
		let chunk_size = len_as_u64(chunk_size.max(1));
		let unit = u64::from(credit_unit.max(1));
		let len = len_as_u64(payload_len);

		let full_chunks = len / chunk_size;
		let remainder = len % chunk_size;
		let per_full_chunk = chunk_size.div_ceil(unit);

		full_chunks
			.saturating_mul(per_full_chunk)
			.saturating_add(remainder.div_ceil(unit))
	}

	/// Static records the writer must reserve so a graceful drain can finish
	/// after the GoAway fires
	/// ([RFC 8446 § 5.5](https://datatracker.ietf.org/doc/html/rfc8446#section-5.5) analog).
	///
	/// At the moment the limit check trips, the connection can still owe:
	/// - envelopes already queued outbound, at most the channel capacity of
	///   `local_cap + peer_cap`
	/// - response trailers to in-flight peer streams, at most `peer_cap`
	/// - drop-guard cancels for pending local streams, at most `local_cap`
	/// - the GoAway itself, exactly 1
	///
	/// Total: `2 * (local_cap + peer_cap) + 1`. Chunked frames add a
	/// dynamic term on top: every registered-but-unflushed chunk is one
	/// more owed record, tracked live in [`MuxState::unsent_chunks`] and
	/// added by the writer at each limit check. A hostile peer that keeps
	/// opening streams after the GoAway draws refusal cancels beyond any
	/// bound and only exhausts the cipher of its own dying connection.
	fn drain_headroom(settings: &MuxSettings) -> u64 {
		u64::from(settings.local_initiated_cap)
			.saturating_add(u64::from(settings.peer_initiated_cap))
			.saturating_mul(2)
			.saturating_add(1)
	}

	/// Credits reserved out of the outbound session budget so owed traffic
	/// can flush during a budget drain: the static record headroom priced at
	/// the worst-case per-chunk debit.
	fn budget_drain_headroom(settings: &MuxSettings) -> u64 {
		let chunk_size = cap_as_usize(settings.send_chunk_size);
		let per_chunk = payload_credits(chunk_size, chunk_size, settings.credit_unit);
		drain_headroom(settings).saturating_mul(per_chunk)
	}

	/// Outcome delivered to a pending stream's oneshot slot.
	enum StreamOutcome {
		/// Correlated response arrived
		Response(ResponsePackage),
		/// Peer cancelled or refused the stream
		Cancelled(CancelReason),
		/// Peer sent GoAway with `last_stream_id` below this stream
		Draining,
	}

	enum Outbound {
		Envelope(TransportEnvelope),
		Close,
	}

	/// Exclusive outbound handle for `SinkExt::send` / `try_send`.
	/// `mpsc::Sender` is Arc-backed; this is a refcount bump.
	fn outbound_handle(outbound: &mpsc::Sender<Outbound>) -> mpsc::Sender<Outbound> {
		outbound.clone()
	}

	/// Register `cx`'s waker. Waker clone is a refcount bump, not a data copy.
	fn park_waker(waiters: &mut Vec<Waker>, cx: &Context<'_>) {
		waiters.push(cx.waker().clone());
	}

	/// Peer-initiated event routed from the reader to the responder.
	enum InboundEvent {
		Request(u32, Arc<Frame>),
		Cancel(u32),
	}

	/// Disposition of an incoming peer-initiated stream.
	enum PeerStream {
		Accept,
		/// GoAway already sent and the stream is newer than its
		/// `last_stream_id`. Refuse without processing.
		RejectDraining,
	}

	/// Sender-side flow-control ledger for one stream direction (QUIC
	/// MAX_STREAM_DATA analog,
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
	enum BudgetStanding {
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
		/// Open locally-initiated streams awaiting their response. The map
		/// size is the cap-relevant open-stream count
		pending: BTreeMap<u32, oneshot::Sender<StreamOutcome>>,
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
	}

	impl MuxState {
		fn wake_drain_waiters(&mut self) {
			wake_all(&mut self.drain_wakers);
		}

		fn wake_slot_waiters(&mut self) {
			wake_all(&mut self.slot_wakers);
		}

		fn reject_if_draining(&self) -> TransportResult<()> {
			if self.goaway_sent.is_some() || self.goaway_received.is_some() {
				return Err(TransportError::Draining);
			}

			Ok(())
		}
	}

	struct MuxShared {
		role: MuxRole,
		local_cap: u32,
		/// Largest chunk payload this endpoint may send (peer-advertised)
		send_chunk_size: usize,
		/// Bytes per session-budget credit (negotiated, both directions)
		credit_unit: u32,
		/// Initial per-stream chunk limit for outbound data
		/// (peer-advertised)
		initial_send_credit: u64,
		/// Credits reserved so owed traffic can flush during a budget
		/// drain. See [`budget_drain_headroom`]
		budget_drain_headroom: u64,
		state: Mutex<MuxState>,
	}

	impl MuxShared {
		fn new(role: MuxRole, settings: &MuxSettings) -> Self {
			Self {
				role,
				local_cap: settings.local_initiated_cap,
				send_chunk_size: cap_as_usize(settings.send_chunk_size).max(1),
				credit_unit: settings.credit_unit.max(1),
				initial_send_credit: settings.initial_send_credit.max(1),
				budget_drain_headroom: budget_drain_headroom(settings),
				state: Mutex::new(MuxState {
					next_stream_id: Some(role.first_local_stream_id()),
					last_peer_stream_id: 0,
					pending: BTreeMap::new(),
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
				}),
			}
		}

		fn lock(&self) -> MutexGuard<'_, MuxState> {
			self.state.lock().unwrap_or_else(PoisonError::into_inner)
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
			}
		}

		/// Register the sender-side ledger for a stream about to carry
		/// `chunks` outbound chunk records.
		fn register_send_stream(&self, stream_id: u32, chunks: u64) {
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
		fn finish_send_stream(&self, stream_id: u32) {
			let mut state = self.lock();
			Self::drop_send_stream(&mut state, stream_id);
		}

		/// Resolve once the peer's grant admits the stream's next chunk,
		/// consuming one unit of credit. Fails once the ledger is gone:
		/// the stream resolved underneath the sender (cancel, response,
		/// or connection failure) and the outcome channel has the truth.
		fn poll_send_chunk(&self, stream_id: u32, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
			let mut state = self.lock();
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

			Poll::Ready(Ok(()))
		}

		/// Apply a peer credit grant (idempotent, monotonic: only a limit
		/// above the current one changes anything). Grants for unknown
		/// streams are discarded: a grant racing stream completion is
		/// benign.
		fn apply_credit_grant(&self, stream_id: u32, limit: u64) {
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

		/// Debit `credits` from the outbound session budget.
		///
		/// `reserved` spends into the drain reserve. Non-reserved debits
		/// fail fast once the spendable balance above the reserve cannot
		/// cover them, keeping the reserve intact for the drain.
		fn debit_send_budget(&self, credits: u64, reserved: bool) -> TransportResult<BudgetStanding> {
			let mut state = self.lock();
			let Some(balance) = state.send_budget else {
				return Ok(BudgetStanding::Healthy);
			};

			let spendable = if reserved {
				balance
			} else {
				balance.saturating_sub(self.budget_drain_headroom)
			};
			if credits > spendable {
				return Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted));
			}

			let remaining = balance.saturating_sub(credits);
			state.send_budget = Some(remaining);

			if remaining <= self.budget_drain_headroom {
				return Ok(BudgetStanding::Exhausting);
			}

			Ok(BudgetStanding::Healthy)
		}

		/// Chunks registered but not yet flushed, across all streams.
		fn unsent_chunks(&self) -> u64 {
			self.lock().unsent_chunks
		}

		/// Allocate the next stream ID and register its response slot.
		fn allocate(&self, sender: oneshot::Sender<StreamOutcome>) -> TransportResult<u32> {
			let mut state = self.lock();
			state.reject_if_draining()?;
			if state.pending.len() >= cap_as_usize(self.local_cap) {
				return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
			}

			let stream_id = state.next_stream_id.ok_or(TransportError::Draining)?;
			state.next_stream_id = stream_id.checked_add(2);
			state.pending.insert(stream_id, sender);

			Ok(stream_id)
		}

		fn remove_pending(&self, stream_id: u32) -> Option<oneshot::Sender<StreamOutcome>> {
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
		fn resolve(&self, stream_id: u32, outcome: StreamOutcome) {
			if let Some(sender) = self.remove_pending(stream_id) {
				let _ = sender.send(outcome);
			}
		}

		/// Register a locally-initiated ping and return its correlation
		/// value. Refused while draining: a peer that honors the GoAway
		/// contract reserves its remaining records for owed stream
		/// traffic and never acks (see [`drain_headroom`]).
		fn allocate_ping(&self, sender: oneshot::Sender<()>) -> TransportResult<u64> {
			let mut state = self.lock();
			state.reject_if_draining()?;

			let opaque = state.next_ping_opaque;
			state.next_ping_opaque = opaque.wrapping_add(1);
			state.pending_pings.insert(opaque, sender);

			Ok(opaque)
		}

		/// Resolve a pending ping. Unknown correlation values are silently
		/// discarded (stale ack racing a dropped ping future is benign).
		fn resolve_ping(&self, opaque: u64) {
			if let Some(sender) = self.lock().pending_pings.remove(&opaque) {
				let _ = sender.send(());
			}
		}

		fn remove_pending_ping(&self, opaque: u64) {
			self.lock().pending_pings.remove(&opaque);
		}

		fn shutdown_begun(&self) -> bool {
			self.lock().goaway_sent.is_some()
		}

		/// Drop every pending slot on connection failure. Receivers observe
		/// cancellation. Producers parked on credit observe ledger removal.
		fn fail_all_pending(&self) {
			let mut state = self.lock();
			state.pending.clear();
			state.pending_pings.clear();

			for (_, stream) in state.send_streams.drain() {
				for waker in stream.credit_wakers {
					waker.wake();
				}
			}

			state.unsent_chunks = 0;
			state.wake_drain_waiters();
			state.wake_slot_waiters();
		}

		/// Resolve pending streams above `last_stream_id` as draining
		/// (peer GoAway: it will never process them). Records the peer's
		/// reason for [`MuxShared::goaway_reason`].
		fn fail_pending_above(&self, last_stream_id: u32, reason: GoAwayReason) {
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
		}

		/// Halt the allocator and record the GoAway watermark. Returns the
		/// `last_stream_id` to advertise, or `None` if already shutting down.
		fn begin_shutdown(&self) -> Option<u32> {
			let mut state = self.lock();
			if state.goaway_sent.is_some() {
				return None;
			}

			state.goaway_sent = Some(state.last_peer_stream_id);
			state.wake_slot_waiters();
			Some(state.last_peer_stream_id)
		}

		/// Validate and record an incoming peer-initiated stream ID
		/// ([RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1):
		/// odd/even role match, nonzero, strictly increasing).
		fn register_peer_stream(&self, stream_id: u32) -> TransportResult<PeerStream> {
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

		fn last_peer_stream_id(&self) -> u32 {
			self.lock().last_peer_stream_id
		}

		fn has_stream_headroom(&self) -> bool {
			let state = self.lock();
			let under_cap = state.pending.len() < cap_as_usize(self.local_cap);
			let id_space_live = state.next_stream_id.is_some();
			let no_goaway = state.goaway_sent.is_none() && state.goaway_received.is_none();

			no_goaway && id_space_live && under_cap
		}

		fn has_pending_streams(&self) -> bool {
			!self.lock().pending.is_empty()
		}

		fn is_pending(&self, stream_id: u32) -> bool {
			self.lock().pending.contains_key(&stream_id)
		}

		fn goaway_reason(&self) -> Option<GoAwayReason> {
			self.lock().goaway_reason
		}

		/// Resolve once a locally-initiated stream would be admitted, or
		/// fail with `Draining` once no stream will ever be admitted again.
		fn poll_stream_slot(&self, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
			let mut state = self.lock();

			let goaway = state.goaway_sent.is_some() || state.goaway_received.is_some();
			let id_space_dead = state.next_stream_id.is_none();
			if goaway || id_space_dead {
				return Poll::Ready(Err(TransportError::Draining));
			}

			if state.pending.len() < cap_as_usize(self.local_cap) {
				return Poll::Ready(Ok(()));
			}

			park_waker(&mut state.slot_wakers, cx);

			Poll::Pending
		}
	}

	/// Resolves once a locally-initiated stream would be admitted. Fails
	/// with `Draining` once no stream will ever be admitted again.
	struct StreamSlot {
		shared: Arc<MuxShared>,
	}

	impl Future for StreamSlot {
		type Output = TransportResult<()>;

		fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
			self.shared.poll_stream_slot(cx)
		}
	}

	/// Resolves once the peer's grant admits the stream's next chunk,
	/// consuming one unit of stream credit. Fails once the stream's
	/// ledger is gone (cancelled, resolved, or connection failure).
	struct SendPermit<'a> {
		shared: &'a MuxShared,
		stream_id: u32,
	}

	impl Future for SendPermit<'_> {
		type Output = TransportResult<()>;

		fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<TransportResult<()>> {
			self.shared.poll_send_chunk(self.stream_id, cx)
		}
	}

	/// Receiver-side stream credit policy: decides when to raise a
	/// stream's absolute cumulative chunk limit (QUIC MAX_STREAM_DATA analog,
	/// [RFC 9000 § 4.1](https://datatracker.ietf.org/doc/html/rfc9000#section-4.1)).
	///
	/// The receiver's granted limit bounds per-stream reassembly memory
	/// at `limit * chunk size`. Withholding grants applies backpressure
	/// to the sender, which parks until the limit rises.
	///
	/// Every grant travels as one `MuxCredit` envelope. It is a control-plane
	/// AEAD record outside the session budget, so implementations
	/// SHOULD batch grants rather than raise the limit per chunk, or a
	/// long transfer spends the cipher's record limit on control traffic.
	pub trait CreditGrantor: Send + Sync {
		/// New absolute chunk limit for a stream that has accepted
		/// `received` chunks under `limit`, or `None` to leave the limit
		/// unchanged. Values at or below `limit` are discarded (grants
		/// are monotonic).
		fn replenish(&self, stream_id: StreamId, received: u64, limit: u64) -> Option<u64>;
	}

	/// Default grantor: replenishes a fixed chunk window in batches,
	/// bounding per-stream reassembly memory at `window * chunk size`
	/// while letting frames of any length flow.
	///
	/// Grants fire only once remaining credit falls to the half-window
	/// low-water mark, then top the limit back up to a full window ahead
	/// of arrival. One `MuxCredit` record therefore covers about half a
	/// window of data chunks, keeping control-plane AEAD record
	/// consumption at `O(chunks / window)`.
	pub struct BufferedGrantor {
		window: u64,
	}

	impl BufferedGrantor {
		/// Grantor keeping `window` chunks (at least one) of credit open.
		pub fn new(window: u64) -> Self {
			Self { window: window.max(1) }
		}
	}

	impl Default for BufferedGrantor {
		fn default() -> Self {
			Self::new(DEFAULT_MUX_STREAM_CREDIT)
		}
	}

	impl CreditGrantor for BufferedGrantor {
		fn replenish(&self, _stream_id: StreamId, received: u64, limit: u64) -> Option<u64> {
			let remaining = limit.saturating_sub(received);
			let low_water = (self.window / 2).max(1);
			if remaining > low_water {
				return None;
			}

			let target = received.saturating_add(self.window);
			if target > limit {
				return Some(target);
			}

			None
		}
	}

	/// Halt the allocator and build the GoAway, once per connection.
	/// `None` when shutdown already began.
	fn goaway_package(shared: &MuxShared, reason: GoAwayReason) -> Option<GoAwayPackage> {
		let last_peer = shared.begin_shutdown()?;
		Some(GoAwayPackage::new(last_peer, reason))
	}

	/// Queue a GoAway with `reason` and halt the allocator, exactly once
	/// per connection. Shared by graceful shutdown and the budget drain.
	async fn drain_with_reason(
		shared: &MuxShared,
		outbound: &mpsc::Sender<Outbound>,
		reason: GoAwayReason,
	) -> TransportResult<()> {
		let Some(package) = goaway_package(shared, reason) else {
			return Ok(());
		};

		let mut outbound = outbound_handle(outbound);
		outbound
			.send(Outbound::Envelope(package.into()))
			.await
			.map_err(|_| TransportError::ConnectionClosed)?;

		Ok(())
	}

	/// Resolves once the pending table drains (all in-flight local streams
	/// completed, cancelled, or failed).
	struct DrainPending {
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

	/// Cancels the stream if the owning emit future is dropped before its
	/// response arrives: frees the cap slot and notifies the peer (best-effort,
	/// [RFC 9113 § 6.4](https://datatracker.ietf.org/doc/html/rfc9113#section-6.4)
	/// analog).
	struct CancelOnDrop {
		shared: Arc<MuxShared>,
		outbound: mpsc::Sender<Outbound>,
		stream_id: u32,
		armed: bool,
	}

	impl CancelOnDrop {
		fn disarm(&mut self) {
			self.armed = false;
		}
	}

	fn enqueue_stream_cancel(shared: &MuxShared, outbound: &mpsc::Sender<Outbound>, stream_id: u32) {
		if shared.remove_pending(stream_id).is_some() {
			let package = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
			let _ = outbound_handle(outbound).try_send(Outbound::Envelope(package.into()));
		}
	}

	impl Drop for CancelOnDrop {
		fn drop(&mut self) {
			if !self.armed {
				return;
			}

			enqueue_stream_cancel(&self.shared, &self.outbound, self.stream_id);
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

	fn cancel_error(reason: CancelReason) -> TransportError {
		match reason {
			CancelReason::Cancelled => TransportError::OperationFailed(TransportFailure::Cancelled),
			CancelReason::Timeout => TransportError::OperationFailed(TransportFailure::DeadlineExceeded),
			CancelReason::Rejected => TransportError::OperationFailed(TransportFailure::ResourceExhausted),
			// An app-coded cancel is still a cancel. The code itself
			// carries no transport-failure mapping of its own
			CancelReason::Application(_) => TransportError::OperationFailed(TransportFailure::Cancelled),
		}
	}

	fn resolve_response(response: ResponsePackage) -> TransportResult<Option<Frame>> {
		match response.status() {
			TransitStatus::Ok => Ok(response.message.map(unwrap_frame)),
			status => Err(TransportError::from(status)),
		}
	}

	/// Cloneable client handle for a multiplexed connection.
	///
	/// Shares pending-stream state and the outbound queue across clones
	/// (`Arc` + channel refcount bumps only). Does not drive I/O: spawn
	/// [`MuxReaderDriver`] and [`MuxWriterDriver`] on the caller's executor.
	/// See [`MuxHandle::emit_on_stream`] and [`MuxHandle::ping`].
	#[derive(Clone)]
	pub struct MuxHandle {
		shared: Arc<MuxShared>,
		outbound: mpsc::Sender<Outbound>,
	}

	impl MuxHandle {
		/// Send a request on a freshly allocated stream and await its
		/// response. Frames beyond the peer's advertised chunk size are
		/// segmented into `Open(first) Data(...)* Data(last)`, each chunk
		/// gated by the peer's stream credit.
		///
		/// Dropping the returned future before it resolves cancels the
		/// stream: the pending entry is removed, the cap slot freed, and a
		/// best-effort [`MuxCancelPackage`] sent. Per-stream timeouts
		/// compose by wrapping this future in the caller's timer.
		///
		/// # Errors
		/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
		/// - `OperationFailed(BudgetExhausted)`: the outbound budget cannot cover frame
		/// - `OperationFailed(ResourceExhausted)`: the peer refused the stream
		/// - `Draining`: GoAway sent or received. No new streams
		/// - `ConnectionClosed`: connection failed before the response
		pub async fn emit_on_stream(&self, frame: &Frame) -> TransportResult<Option<Frame>> {
			// Encode before allocating so an encoding failure never burns
			// a stream ID or queues a cancel for a stream the peer never saw.
			let payload = frame.to_der()?;
			let credits = payload_credits(payload.len(), self.shared.send_chunk_size, self.shared.credit_unit);

			let (sender, receiver) = oneshot::channel();
			let stream_id = self.shared.allocate(sender)?;
			let standing = match self.shared.debit_send_budget(credits, false) {
				Ok(standing) => standing,
				Err(err) => {
					self.shared.remove_pending(stream_id);
					return Err(err);
				}
			};

			let chunk_records = chunk_records(payload.len(), self.shared.send_chunk_size);
			self.shared.register_send_stream(stream_id, chunk_records);

			let mut guard = CancelOnDrop {
				shared: Arc::clone(&self.shared),
				outbound: outbound_handle(&self.outbound),
				stream_id,
				armed: true,
			};

			match self.send_request_chunks(stream_id, &payload, chunk_records).await {
				Ok(()) => {}
				// Ledger removed mid-send: the stream resolved underneath
				// the sender and the outcome channel carries the truth
				Err(TransportError::OperationFailed(TransportFailure::Cancelled)) => {}
				Err(err) => return Err(err),
			}

			if matches!(standing, BudgetStanding::Exhausting) {
				drain_with_reason(&self.shared, &self.outbound, GoAwayReason::BudgetExhausted).await?;
			}

			let outcome = receiver.await;

			guard.disarm();
			self.shared.finish_send_stream(stream_id);

			match outcome {
				Ok(StreamOutcome::Response(response)) => resolve_response(response),
				Ok(StreamOutcome::Cancelled(reason)) => Err(cancel_error(reason)),
				Ok(StreamOutcome::Draining) => Err(TransportError::Draining),
				Err(_) => Err(TransportError::ConnectionClosed),
			}
		}

		/// Segment a request payload into the initiator grammar, one
		/// credit-gated chunk per record. `total` is the registered
		/// chunk count: sender and ledger share one figure by
		/// construction.
		async fn send_request_chunks(&self, stream_id: u32, payload: &[u8], total: u64) -> TransportResult<()> {
			let chunk_size = self.shared.send_chunk_size;
			let mut outbound = outbound_handle(&self.outbound);
			let mut chunks = payload.chunks(chunk_size);
			let mut sent: u64 = 0;

			let first = chunks.next().unwrap_or(&[]);
			SendPermit { shared: &self.shared, stream_id }.await?;

			sent += 1;
			let open = MuxOpenPackage::new(stream_id, sent == total, first)?;
			outbound
				.send(Outbound::Envelope(open.into()))
				.await
				.map_err(|_| TransportError::ConnectionClosed)?;

			for chunk in chunks {
				SendPermit { shared: &self.shared, stream_id }.await?;
				sent += 1;
				let data = MuxDataPackage::new(stream_id, sent == total, chunk)?;
				outbound
					.send(Outbound::Envelope(data.into()))
					.await
					.map_err(|_| TransportError::ConnectionClosed)?;
			}

			Ok(())
		}

		/// Cancel a locally-initiated in-flight stream (best-effort).
		pub fn close_stream(&self, stream_id: StreamId) {
			enqueue_stream_cancel(&self.shared, &self.outbound, stream_id.value());
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

		/// Resolve once a locally-initiated stream would be admitted:
		/// cap headroom, live ID space, and no GoAway either way.
		///
		/// Replaces polling [`MuxHandle::has_stream_headroom`] in a loop.
		/// Advisory like the getter: a concurrent emit can take the slot
		/// between wake and use, so callers still handle
		/// `StreamsExhausted`.
		///
		/// # Errors
		/// - `Draining`: GoAway sent or received, or stream IDs exhausted.
		pub fn wait_for_stream_slot(&self) -> impl Future<Output = TransportResult<()>> + MaybeSend {
			StreamSlot { shared: Arc::clone(&self.shared) }
		}

		/// Connection-level liveness probe
		/// ([RFC 9113 § 6.7](https://datatracker.ietf.org/doc/html/rfc9113#section-6.7)
		/// analog): resolves when the peer's ack arrives.
		///
		/// No stream is allocated and the peer's application handler never
		/// runs, so this doubles as an idle keepalive for links whose
		/// carrier cannot ping itself.
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
		/// ([RFC 9113 § 6.8](https://datatracker.ietf.org/doc/html/rfc9113#section-6.8)
		/// analog): sends GoAway, halts the allocator, awaits pending-table
		/// drain, then closes the writer driver.
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

			DrainPending { shared: Arc::clone(&self.shared) }.await;

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

		fn close_stream(&self, stream_id: StreamId) {
			MuxHandle::close_stream(self, stream_id);
		}
	}

	/// Writer driver: single serialization point for the connection.
	///
	/// Drains the outbound queue and writes each envelope through the
	/// [`EnvelopeSink`] (encrypting or cleartext). Spawn
	/// [`MuxWriterDriver::drive`] on the caller's executor.
	pub struct MuxWriterDriver<W>
	where
		W: EnvelopeSink,
	{
		writer: W,
		commands: mpsc::Receiver<Outbound>,
		shared: Arc<MuxShared>,
		/// Records reserved for draining before the send cipher halts.
		/// See [`drain_headroom`] for the bound derivation.
		drain_headroom: u64,
	}

	impl<W> MuxWriterDriver<W>
	where
		W: EnvelopeSink,
	{
		/// Run the driver until shutdown or write failure.
		pub async fn drive(mut self) -> TransportResult<()> {
			while let Some(command) = self.commands.next().await {
				match command {
					Outbound::Envelope(envelope) => {
						self.writer.write_envelope(envelope).await?;
						self.enforce_rekey_limit().await?;
					}
					Outbound::Close => break,
				}
			}

			Ok(())
		}

		/// [RFC 8446 § 5.5](https://datatracker.ietf.org/doc/html/rfc8446#section-5.5)
		/// analog: when the send cipher nears its record limit, drain the
		/// connection via GoAway while enough records remain to answer
		/// in-flight peer streams and flush every registered-but-unsent chunk.
		/// The caller then reestablishes the session for fresh keys.
		async fn enforce_rekey_limit(&mut self) -> TransportResult<()> {
			let headroom = self.drain_headroom.saturating_add(self.shared.unsent_chunks());
			if self.writer.remaining_records() > headroom {
				return Ok(());
			}

			// Bypass the command queue: at the record ceiling the queue
			// may already be full of owed stream traffic.
			if let Some(package) = goaway_package(&self.shared, GoAwayReason::Shutdown) {
				self.writer.write_envelope(package.into()).await?;
			}

			Ok(())
		}
	}

	/// Receiver-side reassembly state for one inbound stream direction.
	struct RecvStream {
		/// Chunks concatenated in arrival order (the AEAD channel already
		/// proves order and completeness)
		buffer: Vec<u8>,
		/// Chunks accepted so far
		received: u64,
		/// Absolute cumulative chunk limit granted to the sender
		limit: u64,
	}

	impl RecvStream {
		fn new(limit: u64) -> Self {
			Self { buffer: Vec::new(), received: 0, limit }
		}

		/// Account one accepted chunk against the granted limit and
		/// buffer it. `false` means the sender overran its credit.
		fn accept_chunk(&mut self, payload: &[u8]) -> bool {
			self.received = self.received.saturating_add(1);
			if self.received > self.limit {
				return false;
			}

			self.buffer.extend_from_slice(payload);

			true
		}
	}

	/// Reader driver: routes inbound envelopes off the read half.
	///
	/// Responses resolve their pending stream (unknown IDs silently
	/// discarded: cancel/response races are benign). Requests flow to the
	/// [`MuxResponder`]. Chunked payloads reassemble here, bounded by the
	/// credit this endpoint granted. The [`CreditGrantor`] decides when to
	/// raise a stream's limit. Protocol violations answer with a GoAway
	/// and fail the driver. Spawn [`MuxReaderDriver::drive`] on the
	/// caller's executor.
	pub struct MuxReaderDriver<R>
	where
		R: EnvelopeSource,
	{
		reader: R,
		shared: Arc<MuxShared>,
		inbound: mpsc::Sender<InboundEvent>,
		outbound: mpsc::Sender<Outbound>,
		grantor: Arc<dyn CreditGrantor>,
		/// Concurrent peer-initiated streams accepted (locally advertised).
		/// Bounds `peer_reassembly` so partial opens cannot hold state
		/// beyond the cap
		/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)
		/// stream accounting analog).
		peer_cap: u32,
		/// Largest chunk payload accepted inbound (locally advertised)
		recv_chunk_size: usize,
		/// Initial chunk limit granted to each inbound stream direction
		initial_recv_credit: u64,
		/// Credits the peer may still spend inbound. `None` = unmetered
		recv_budget: Option<u64>,
		/// Reassembly of peer-initiated request streams
		peer_reassembly: HashMap<u32, RecvStream>,
		/// Reassembly of responses to locally-initiated streams
		local_reassembly: HashMap<u32, RecvStream>,
		/// Control envelopes buffered while the writer queue is full so
		/// the read loop never parks
		/// ([RFC 9113 § 5.2.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2)).
		/// Bounded: grants coalesce per stream, ping acks are capped
		pending_control: VecDeque<TransportEnvelope>,
	}

	/// Drain buffered control into the writer queue. Cancellation-safe:
	/// an envelope leaves the buffer only after its slot is reserved.
	async fn flush_control(
		outbound: &mut mpsc::Sender<Outbound>,
		pending: &mut VecDeque<TransportEnvelope>,
	) -> TransportResult<()> {
		while !pending.is_empty() {
			let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
			if ready.is_err() {
				return Err(TransportError::ConnectionClosed);
			}

			let Some(envelope) = pending.pop_front() else {
				return Ok(());
			};

			outbound
				.start_send(Outbound::Envelope(envelope))
				.map_err(|_| TransportError::ConnectionClosed)?;
		}

		Ok(())
	}

	/// Whether `envelope` is a buffered credit grant for `stream_id`.
	fn is_credit_grant_for(envelope: &TransportEnvelope, stream_id: u32) -> bool {
		matches!(
			envelope,
			TransportEnvelope::Mux(MuxEnvelope::Credit(package)) if package.stream_id() == stream_id
		)
	}

	/// Whether `envelope` is a buffered ping ack.
	fn is_ping_ack(envelope: &TransportEnvelope) -> bool {
		matches!(envelope, TransportEnvelope::Mux(MuxEnvelope::Ping(_)))
	}

	impl<R> MuxReaderDriver<R>
	where
		R: EnvelopeSource,
	{
		/// Run the driver until the connection ends. Pending streams observe
		/// the failure.
		pub async fn drive(mut self) -> TransportResult<()> {
			let result = self.route_envelopes().await;

			self.shared.fail_all_pending();

			result
		}

		/// Route inbound envelopes to their pending streams or handlers.
		async fn route_envelopes(&mut self) -> TransportResult<()> {
			loop {
				let envelope = self.next_envelope().await?;
				let TransportEnvelope::Mux(mux) = envelope else {
					return Err(self.protocol_violation());
				};
				match mux {
					MuxEnvelope::End(package) => self.route_end(package)?,
					MuxEnvelope::Open(package) => self.route_open(package).await?,
					MuxEnvelope::Data(package) => self.route_data(package).await?,
					MuxEnvelope::Credit(package) => {
						self.shared.apply_credit_grant(package.stream_id(), package.limit());
					}
					MuxEnvelope::Cancel(package) => self.route_cancel(package).await?,
					MuxEnvelope::Ping(package) => self.route_ping(package)?,
					MuxEnvelope::GoAway(package) => {
						self.shared.fail_pending_above(package.last_stream_id(), package.reason());
						// Responses to streams the peer will never answer
						// are no longer coming: drop their partial buffers
						self.local_reassembly.retain(|id, _| self.shared.is_pending(*id));
					}
				}
			}
		}

		/// Enforce the advertised chunk ceiling and debit the inbound
		/// session budget for one chunk. Both overruns are protocol
		/// violations: the sender knows the ceiling and its own grant.
		fn charge_inbound_chunk(&mut self, payload: &[u8]) -> TransportResult<()> {
			if payload.len() > self.recv_chunk_size {
				return Err(self.protocol_violation());
			}
			let Some(balance) = self.recv_budget else {
				return Ok(());
			};

			let credits = payload_credits(payload.len(), self.recv_chunk_size, self.shared.credit_unit);
			if credits > balance {
				return Err(self.protocol_violation());
			}

			self.recv_budget = Some(balance - credits);

			Ok(())
		}

		/// Read the next envelope, flushing buffered control as the
		/// writer queue drains. The read never parks behind the flush.
		async fn next_envelope(&mut self) -> TransportResult<TransportEnvelope> {
			if self.pending_control.is_empty() {
				return self.reader.read_envelope().await;
			}

			let read = self.reader.read_envelope();
			let flush = flush_control(&mut self.outbound, &mut self.pending_control);
			pin_mut!(read, flush);

			match select(read, flush).await {
				Either::Left((envelope, _)) => envelope,
				Either::Right((flushed, read)) => {
					flushed?;
					read.await
				}
			}
		}

		/// Hand a control envelope to the writer, buffering on a full
		/// queue instead of parking the read loop.
		fn queue_control(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
			if !self.pending_control.is_empty() {
				self.pending_control.push_back(envelope);
				return Ok(());
			}

			match self.outbound.try_send(Outbound::Envelope(envelope)) {
				Ok(()) => Ok(()),
				Err(refused) if refused.is_full() => {
					if let Outbound::Envelope(envelope) = refused.into_inner() {
						self.pending_control.push_back(envelope);
					}
					Ok(())
				}
				Err(_) => Err(TransportError::ConnectionClosed),
			}
		}

		/// Queue a credit grant, superseding any buffered grant for the
		/// same stream: `Credit` is an absolute limit, only the newest matters.
		fn queue_credit(&mut self, stream_id: u32, new_limit: u64) -> TransportResult<()> {
			self.pending_control
				.retain(|envelope| !is_credit_grant_for(envelope, stream_id));
			self.queue_control(MuxCreditPackage::new(stream_id, new_limit).into())
		}

		/// Queue a ping ack; probes beyond [`MAX_PENDING_PING_ACKS`] draw no ack.
		fn queue_ping_ack(&mut self, package: MuxPingPackage) -> TransportResult<()> {
			let buffered_acks = self.pending_control.iter().filter(|envelope| is_ping_ack(envelope)).count();
			if buffered_acks >= MAX_PENDING_PING_ACKS {
				return Ok(());
			}

			self.queue_control(package.into())
		}

		/// Consult the grantor and queue a credit grant when it raises
		/// the stream's limit.
		fn maybe_grant(&mut self, stream_id: u32, stream: &mut RecvStream) -> TransportResult<()> {
			let granted = self.grantor.replenish(StreamId::new(stream_id), stream.received, stream.limit);
			let Some(new_limit) = granted else {
				return Ok(());
			};
			if new_limit <= stream.limit {
				return Ok(());
			}

			stream.limit = new_limit;

			self.queue_credit(stream_id, new_limit)
		}

		/// Decode a reassembled stream payload into its message frame.
		///
		/// Empty payload = message-less trailer. Version validation happens
		/// here rather than at the io layer because chunked payloads only
		/// become a frame after reassembly.
		fn decode_stream_frame(&mut self, payload: &[u8]) -> TransportResult<Option<Frame>> {
			if payload.is_empty() {
				return Ok(None);
			}

			let frame = match Frame::from_der(payload) {
				Ok(frame) => frame,
				Err(_) => return Err(self.protocol_violation()),
			};
			if !frame.validate_version_compatibility() {
				return Err(self.protocol_violation());
			}

			Ok(Some(frame))
		}

		fn route_end(&mut self, package: MuxEndPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			if !self.shared.role.initiates(stream_id) {
				return Err(self.protocol_violation());
			}

			// The sender debited its ledgers for this record whether or
			// not the stream is still pending, so account it either way
			if !package.payload().is_empty() {
				self.charge_inbound_chunk(package.payload())?;
			}

			// Resolve before decoding: stale ends are discarded without
			// inspecting their payload, and non-Ok trailers never
			// contribute a frame, so garbage bytes on either cannot tear
			// down the connection.
			let Some(sender) = self.shared.remove_pending(stream_id) else {
				self.local_reassembly.remove(&stream_id);
				return Ok(());
			};

			let mut stream = self
				.local_reassembly
				.remove(&stream_id)
				.unwrap_or_else(|| RecvStream::new(self.initial_recv_credit));
			if !package.payload().is_empty() && !stream.accept_chunk(package.payload()) {
				return Err(self.protocol_violation());
			}

			let message = match package.status() {
				TransitStatus::Ok => self.decode_stream_frame(&stream.buffer)?,
				_ => None,
			};

			let response = ResponsePackage::new(package.status(), message);
			let _ = sender.send(StreamOutcome::Response(response));
			Ok(())
		}

		async fn route_open(&mut self, package: MuxOpenPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();

			match self.shared.register_peer_stream(stream_id) {
				Ok(PeerStream::Accept) => self.accept_peer_open(stream_id, package).await,
				Ok(PeerStream::RejectDraining) => self.reject_draining_open(stream_id, package),
				Err(_) => Err(self.protocol_violation()),
			}
		}

		/// Accept a peer open: dispatch whole-frame opens, otherwise park
		/// the first chunk under the peer-initiated reassembly cap.
		async fn accept_peer_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
			self.charge_inbound_chunk(package.payload())?;
			if package.last() {
				// Whole frame in one chunk: the credit floor of one admits
				// it without touching reassembly
				return self.dispatch_request(stream_id, package.payload()).await;
			}

			// A conforming sender keeps its in-flight opens under the cap
			// it was advertised, so one more partial stream is a
			// violation, not backpressure
			if self.peer_reassembly.len() >= cap_as_usize(self.peer_cap) {
				return Err(self.protocol_violation());
			}

			let stream = RecvStream::new(self.initial_recv_credit);
			let stream = self.park_reassembly(stream_id, stream, package.payload())?;
			self.peer_reassembly.insert(stream_id, stream);

			Ok(())
		}

		/// Refuse an open past our GoAway watermark. The chunk still
		/// crossed the wire under the sender's ledgers, so debit inbound.
		fn reject_draining_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
			self.charge_inbound_chunk(package.payload())?;
			self.refuse_stream(stream_id);

			Ok(())
		}

		async fn route_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			// The chunker never emits an empty chunk: empty payloads travel
			// only in trailers
			if package.payload().is_empty() {
				return Err(self.protocol_violation());
			}
			if self.shared.role.peer().initiates(stream_id) {
				return self.route_request_data(package).await;
			}
			if self.shared.role.initiates(stream_id) {
				return self.route_response_data(package).await;
			}

			Err(self.protocol_violation())
		}

		/// Append `payload` into `stream` or fail closed on credit overrun.
		fn accept_chunk_or_violate(&mut self, mut stream: RecvStream, payload: &[u8]) -> TransportResult<RecvStream> {
			if !stream.accept_chunk(payload) {
				return Err(self.protocol_violation());
			}

			Ok(stream)
		}

		/// Accept a non-final chunk and raise credit when the grantor asks.
		/// Caller parks the returned stream in the right reassembly map.
		fn park_reassembly(
			&mut self,
			stream_id: u32,
			stream: RecvStream,
			payload: &[u8],
		) -> TransportResult<RecvStream> {
			let mut stream = self.accept_chunk_or_violate(stream, payload)?;
			self.maybe_grant(stream_id, &mut stream)?;

			Ok(stream)
		}

		/// Continuation chunk of a peer-initiated request.
		async fn route_request_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			self.charge_inbound_chunk(package.payload())?;

			let Some(stream) = self.peer_reassembly.remove(&stream_id) else {
				// A refused or cancelled stream still flushing chunks it
				// had credit for. Anything beyond the high-water mark
				// never opened
				if stream_id <= self.shared.last_peer_stream_id() {
					return Ok(());
				}

				return Err(self.protocol_violation());
			};

			if package.last() {
				// Final chunk: dispatch without a credit raise — the stream
				// is leaving reassembly
				let stream = self.accept_chunk_or_violate(stream, package.payload())?;
				return self.dispatch_request(stream_id, &stream.buffer).await;
			}

			let stream = self.park_reassembly(stream_id, stream, package.payload())?;
			self.peer_reassembly.insert(stream_id, stream);

			Ok(())
		}

		/// Continuation chunk of a response to a locally-initiated stream.
		/// The responder grammar terminates with `End`, never `Data(last)`.
		async fn route_response_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			self.charge_inbound_chunk(package.payload())?;

			if package.last() {
				return Err(self.protocol_violation());
			}

			// Stale flush of a stream this endpoint already resolved
			if !self.shared.is_pending(stream_id) {
				self.local_reassembly.remove(&stream_id);
				return Ok(());
			}

			let stream = self
				.local_reassembly
				.remove(&stream_id)
				.unwrap_or_else(|| RecvStream::new(self.initial_recv_credit));
			let stream = self.park_reassembly(stream_id, stream, package.payload())?;
			self.local_reassembly.insert(stream_id, stream);

			Ok(())
		}

		/// Decode a fully reassembled request and hand it to the responder.
		async fn dispatch_request(&mut self, stream_id: u32, payload: &[u8]) -> TransportResult<()> {
			let frame = match self.decode_stream_frame(payload)? {
				Some(frame) => frame,
				// A request stream must carry a message
				None => return Err(self.protocol_violation()),
			};

			let event = InboundEvent::Request(stream_id, Arc::new(frame));
			if self.inbound.send(event).await.is_err() {
				// No responder is serving this connection
				self.refuse_stream(stream_id);
			}

			Ok(())
		}

		async fn route_cancel(&mut self, package: MuxCancelPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			if self.shared.role.initiates(stream_id) {
				// Peer cancelled/refused a stream we initiated
				self.local_reassembly.remove(&stream_id);
				self.shared.resolve(stream_id, StreamOutcome::Cancelled(package.reason()));
				return Ok(());
			}
			if self.shared.role.peer().initiates(stream_id) {
				// Peer withdrew its own request: drop any partial
				// reassembly, release the response ledger, abort the handler
				self.peer_reassembly.remove(&stream_id);
				self.shared.finish_send_stream(stream_id);

				let _ = self.inbound.send(InboundEvent::Cancel(stream_id)).await;
				return Ok(());
			}

			Err(self.protocol_violation())
		}

		/// Answer a peer probe with its ack. Terminates here: pings never
		/// reach the responder or the application handler.
		fn route_ping(&mut self, package: MuxPingPackage) -> TransportResult<()> {
			if package.ack() {
				self.shared.resolve_ping(package.opaque());
				return Ok(());
			}

			// After our GoAway the writer's remaining records are reserved
			// for owed stream traffic (see `drain_headroom`), so peer
			// probes draw no acks. Combined with the capped ack backlog
			// this bounds what a ping flood can extract (CVE-2019-9512).
			if self.shared.shutdown_begun() {
				return Ok(());
			}

			self.queue_ping_ack(MuxPingPackage::new(true, package.opaque()))
		}

		fn refuse_stream(&mut self, stream_id: u32) {
			let package = MuxCancelPackage::new(stream_id, CancelReason::Rejected);
			let _ = self.outbound.try_send(Outbound::Envelope(package.into()));
		}

		fn protocol_violation(&mut self) -> TransportError {
			let package = GoAwayPackage::new(self.shared.last_peer_stream_id(), GoAwayReason::ProtocolError);
			let _ = self.outbound.try_send(Outbound::Envelope(package.into()));

			TransportError::InvalidMessage
		}
	}

	/// Event multiplexer for the responder loop: handler completions take
	/// priority over new inbound work.
	enum ResponderEvent {
		Request(u32, Arc<Frame>),
		Cancelled(u32),
		Finished(u32, TransportResult<()>),
		Aborted,
		Closed,
	}

	async fn next_responder_event<Fut>(
		inbound: &mut mpsc::Receiver<InboundEvent>,
		tasks: &mut FuturesUnordered<Abortable<Fut>>,
		inbound_open: bool,
	) -> ResponderEvent
	where
		Fut: Future<Output = (u32, TransportResult<()>)>,
	{
		poll_fn(|cx| {
			if let Poll::Ready(Some(completion)) = Pin::new(&mut *tasks).poll_next(cx) {
				let event = match completion {
					Ok((stream_id, result)) => ResponderEvent::Finished(stream_id, result),
					Err(Aborted) => ResponderEvent::Aborted,
				};

				return Poll::Ready(event);
			}
			if inbound_open {
				match Pin::new(&mut *inbound).poll_next(cx) {
					Poll::Ready(Some(InboundEvent::Request(stream_id, frame))) => {
						return Poll::Ready(ResponderEvent::Request(stream_id, frame));
					}
					Poll::Ready(Some(InboundEvent::Cancel(stream_id))) => {
						return Poll::Ready(ResponderEvent::Cancelled(stream_id));
					}
					Poll::Ready(None) => return Poll::Ready(ResponderEvent::Closed),
					Poll::Pending => {}
				}
			}

			Poll::Pending
		})
		.await
	}

	/// Send a response on a peer-initiated stream, chunking when it
	/// exceeds the peer's advertised receive size: full chunks travel as
	/// `Data(last = false)` and the final chunk travels inline in the `End`
	/// trailer (responder grammar). Every payload-bearing record is gated
	/// by the peer's stream credit. A response the session budget cannot
	/// carry degrades to a payload-free `ResourceExhausted` refusal.
	async fn send_response(
		shared: &MuxShared,
		outbound: &mpsc::Sender<Outbound>,
		stream_id: u32,
		response: ResponsePackage,
	) -> TransportResult<()> {
		let mut status = response.status();
		let mut payload = match response.message() {
			Some(frame) => frame.as_ref().to_der()?,
			None => Vec::new(),
		};

		let credits = payload_credits(payload.len(), shared.send_chunk_size, shared.credit_unit);
		match shared.debit_send_budget(credits, true) {
			Ok(BudgetStanding::Healthy) => {}
			Ok(BudgetStanding::Exhausting) => {
				drain_with_reason(shared, outbound, GoAwayReason::BudgetExhausted).await?;
			}
			// Even the drain reserve cannot carry the payload: refuse
			// the stream for free instead of tearing the connection
			Err(_) => {
				status = TransitStatus::ResourceExhausted;
				payload = Vec::new();
			}
		}

		let mut outbound = outbound_handle(outbound);
		if payload.is_empty() {
			let package = MuxEndPackage::new(stream_id, status, payload)?;
			return outbound
				.send(Outbound::Envelope(package.into()))
				.await
				.map_err(|_| TransportError::ConnectionClosed);
		}

		let chunk_size = shared.send_chunk_size;
		let total = chunk_records(payload.len(), chunk_size);
		shared.register_send_stream(stream_id, total);

		let mut sent: u64 = 0;
		for chunk in payload.chunks(chunk_size) {
			match (SendPermit { shared, stream_id }).await {
				Ok(()) => {}
				// Ledger removed mid-send: the peer cancelled the stream
				// and the receiver will discard what already went out
				Err(_) => return Ok(()),
			}

			sent += 1;

			let envelope = if sent == total {
				TransportEnvelope::from(MuxEndPackage::new(stream_id, status, chunk)?)
			} else {
				TransportEnvelope::from(MuxDataPackage::new(stream_id, false, chunk)?)
			};
			if outbound.send(Outbound::Envelope(envelope)).await.is_err() {
				shared.finish_send_stream(stream_id);
				return Err(TransportError::ConnectionClosed);
			}
		}

		shared.finish_send_stream(stream_id);

		Ok(())
	}

	/// Serves peer-initiated streams with a caller-supplied handler.
	///
	/// Handlers for distinct streams run concurrently, and each stream's
	/// response is sent from its own task, so neither a slow handler nor
	/// a credit-parked response blocks other streams. Cap exhaustion answers
	/// with [`TransitStatus::ResourceExhausted`]. A peer cancel aborts the
	/// in-flight handler (or its response send) and sends no response.
	///
	/// Cancels of in-flight handlers draw on a per-connection budget
	/// (CVE-2023-44487 "Rapid Reset" hardening): a peer that opens streams
	/// only to cancel them exhausts the budget and is told to go away.
	pub struct MuxResponder {
		inbound: mpsc::Receiver<InboundEvent>,
		outbound: mpsc::Sender<Outbound>,
		shared: Arc<MuxShared>,
		peer_cap: u32,
		cancel_budget: u32,
	}

	impl MuxResponder {
		/// Run the responder until the connection ends.
		///
		/// # Errors
		/// - `ConnectionClosed`: writer driver gone
		/// - `OperationFailed(PolicyRejection)`: peer exhausted the cancel
		///   budget. A [`GoAwayReason::EnhanceYourCalm`] was sent
		pub async fn serve<H, Fut>(mut self, handler: H) -> TransportResult<()>
		where
			H: Fn(Arc<Frame>) -> Fut,
			Fut: Future<Output = ResponsePackage> + MaybeSend,
		{
			let mut in_flight: HashMap<u32, AbortHandle> = HashMap::new();
			let mut tasks = FuturesUnordered::new();
			let mut inbound_open = true;
			let mut last_stream_id = 0;

			loop {
				if !inbound_open && tasks.is_empty() {
					return Ok(());
				}

				match next_responder_event(&mut self.inbound, &mut tasks, inbound_open).await {
					ResponderEvent::Closed => inbound_open = false,
					ResponderEvent::Aborted => {}
					ResponderEvent::Cancelled(stream_id) => {
						if let Some(handle) = in_flight.remove(&stream_id) {
							handle.abort();

							if self.cancel_budget == 0 {
								return Err(self.refuse_cancel_abuse(last_stream_id).await);
							}

							self.cancel_budget -= 1;
						}
					}
					ResponderEvent::Request(stream_id, frame) => {
						last_stream_id = stream_id;

						if in_flight.len() >= cap_as_usize(self.peer_cap) {
							let refusal = ResponsePackage::new(TransitStatus::ResourceExhausted, None);
							send_response(&self.shared, &self.outbound, stream_id, refusal).await?;
							continue;
						}

						let (handle, registration) = AbortHandle::new_pair();

						in_flight.insert(stream_id, handle);

						let work = handler(frame);
						let shared = Arc::clone(&self.shared);
						let outbound = outbound_handle(&self.outbound);
						let task = async move {
							let response = work.await;
							let result = send_response(&shared, &outbound, stream_id, response).await;

							(stream_id, result)
						};
						tasks.push(Abortable::new(task, registration));
					}
					ResponderEvent::Finished(stream_id, result) => {
						in_flight.remove(&stream_id);
						result?;
					}
				}
			}
		}

		/// CVE-2023-44487 hardening: too many cancels of in-flight
		/// handlers ends the connection with a best-effort GoAway.
		async fn refuse_cancel_abuse(&mut self, last_stream_id: u32) -> TransportError {
			let package = GoAwayPackage::new(last_stream_id, GoAwayReason::EnhanceYourCalm);
			let _ = self.outbound.send(Outbound::Envelope(package.into())).await;

			TransportError::OperationFailed(TransportFailure::PolicyRejection)
		}
	}

	/// Multiplexed transport assembled from split envelope halves and
	/// [`MuxSettings`].
	pub struct MuxTransport<R, W>
	where
		R: EnvelopeSource,
		W: EnvelopeSink,
	{
		handle: MuxHandle,
		reader: MuxReaderDriver<R>,
		writer: MuxWriterDriver<W>,
		responder: MuxResponder,
	}

	impl<R, W> MuxTransport<R, W>
	where
		R: EnvelopeSource,
		W: EnvelopeSink,
	{
		/// Assemble a multiplexed transport over split halves.
		///
		/// `role` fixes odd/even stream IDs and MUST match the endpoint's
		/// connection role (initiator = client). On encrypted halves,
		/// `settings` MUST come from
		/// [`negotiated_mux`](crate::transport::TcpTransport::negotiated_mux).
		/// A peer that never negotiated multiplexing rejects every muxed
		/// envelope as invalid. On cleartext halves there is no
		/// negotiation: both endpoints MUST agree on the same settings out
		/// of band ([`MuxSettings::symmetric`]).
		pub fn new(reader: R, writer: W, role: MuxRole, settings: MuxSettings) -> Self {
			let outbound_capacity =
				cap_as_usize(settings.local_initiated_cap.saturating_add(settings.peer_initiated_cap)).max(1);
			let inbound_capacity = cap_as_usize(settings.peer_initiated_cap).max(1);
			let (outbound_sender, outbound_receiver) = mpsc::channel(outbound_capacity);
			let (inbound_sender, inbound_receiver) = mpsc::channel(inbound_capacity);

			let shared = Arc::new(MuxShared::new(role, &settings));
			let drain_headroom = drain_headroom(&settings);

			Self {
				handle: MuxHandle { shared: Arc::clone(&shared), outbound: outbound_handle(&outbound_sender) },
				reader: MuxReaderDriver {
					reader,
					shared: Arc::clone(&shared),
					inbound: inbound_sender,
					outbound: outbound_handle(&outbound_sender),
					grantor: Arc::new(BufferedGrantor::default()),
					peer_cap: settings.peer_initiated_cap,
					recv_chunk_size: cap_as_usize(settings.recv_chunk_size).max(1),
					initial_recv_credit: settings.initial_recv_credit.max(1),
					recv_budget: settings.recv_budget,
					peer_reassembly: HashMap::new(),
					local_reassembly: HashMap::new(),
					pending_control: VecDeque::new(),
				},
				writer: MuxWriterDriver {
					writer,
					commands: outbound_receiver,
					shared: Arc::clone(&shared),
					drain_headroom,
				},
				responder: MuxResponder {
					inbound: inbound_receiver,
					outbound: outbound_sender,
					shared,
					peer_cap: settings.peer_initiated_cap,
					cancel_budget: DEFAULT_MUX_CANCEL_BUDGET,
				},
			}
		}

		/// Override the peer cancel budget (CVE-2023-44487 hardening).
		pub fn with_cancel_budget(mut self, budget: u32) -> Self {
			self.responder.cancel_budget = budget;
			self
		}

		/// Override the receiver-side stream credit policy (default:
		/// [`BufferedGrantor`] with a
		/// [`DEFAULT_MUX_STREAM_CREDIT`]-chunk window).
		#[must_use]
		pub fn with_credit_grantor(mut self, grantor: Arc<dyn CreditGrantor>) -> Self {
			self.reader.grantor = grantor;
			self
		}

		/// Clone the client handle without decomposing the transport
		/// (`Arc` + channel refcount bumps).
		pub fn handle(&self) -> MuxHandle {
			self.handle.clone()
		}

		/// Decompose into the handle, the two drivers to spawn, and
		/// the responder.
		pub fn into_parts(self) -> (MuxHandle, MuxReaderDriver<R>, MuxWriterDriver<W>, MuxResponder) {
			(self.handle, self.reader, self.writer, self.responder)
		}
	}

	#[cfg(test)]
	mod tests {
		use core::future::pending;
		use core::sync::atomic::{AtomicUsize, Ordering};
		use std::collections::VecDeque;

		use super::*;

		fn shared(role: MuxRole, local_cap: u32) -> MuxShared {
			MuxShared::new(role, &MuxSettings::symmetric(local_cap))
		}

		fn shared_with_settings(role: MuxRole, settings: MuxSettings) -> MuxShared {
			MuxShared::new(role, &settings)
		}

		fn slot() -> oneshot::Sender<StreamOutcome> {
			oneshot::channel().0
		}

		fn ping_slot() -> oneshot::Sender<()> {
			oneshot::channel().0
		}

		fn noop_cx() -> Context<'static> {
			Context::from_waker(futures::task::noop_waker_ref())
		}

		fn allocate_ids(shared: &MuxShared, ids: &[u32]) {
			for &id in ids {
				assert!(matches!(shared.allocate(slot()), Ok(got) if got == id));
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

		fn assert_cancel_maps(reason: CancelReason, failure: TransportFailure) {
			let error = cancel_error(reason);
			assert!(matches!(
				error,
				TransportError::OperationFailed(got) if got == failure
			));
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

		fn prepare_headroom(setup: HeadroomSetup) -> MuxShared {
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

		fn prepare_goaway(setup: GoAwaySetup) -> MuxShared {
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

		fn prepare_slot(setup: SlotSetup) -> MuxShared {
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
				shared.allocate(slot()),
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

		#[test]
		fn test_allocation_halts_after_shutdown() {
			let shared = shared(MuxRole::Client, 8);
			assert!(matches!(shared.begin_shutdown(), Some(0)));
			assert!(matches!(shared.allocate(slot()), Err(TransportError::Draining)));
			assert!(shared.begin_shutdown().is_none());
		}

		#[test]
		fn test_allocation_halts_after_peer_goaway() {
			let shared = shared(MuxRole::Client, 8);
			shared.fail_pending_above(0, GoAwayReason::Shutdown);
			assert!(matches!(shared.allocate(slot()), Err(TransportError::Draining)));
		}

		#[test]
		fn test_id_space_exhaustion_reports_draining() {
			let shared = shared(MuxRole::Client, 8);
			shared.lock().next_stream_id = Some(u32::MAX);
			allocate_ids(&shared, &[u32::MAX]);
			assert!(matches!(shared.allocate(slot()), Err(TransportError::Draining)));
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
		fn test_drain_headroom_covers_queue_responses_cancels_goaway() {
			let settings = MuxSettings { local_initiated_cap: 3, peer_initiated_cap: 5, ..MuxSettings::symmetric(1) };
			assert_eq!(drain_headroom(&settings), 17);
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
		fn test_chunk_records_boundaries() {
			for (len, chunk, expect) in [
				(0usize, 1024usize, 0u64),
				(1, 1024, 1),
				(1023, 1024, 1),
				(1024, 1024, 1),
				(2048, 1024, 2),
				(2049, 1024, 3),
			] {
				assert_eq!(chunk_records(len, chunk), expect);
			}
		}

		#[test]
		fn test_payload_credits_match_per_chunk_sum() {
			for (len, chunk, unit, expect) in [
				(0usize, 1024usize, 1000u32, 0u64),
				(100, 1024, 1000, 1),
				(1024, 1024, 1024, 1),
				(2048, 1024, 512, 4),
				// Sender's whole-frame debit equals the receiver's
				// per-chunk sum, not the naive whole-frame ceil (3)
				(2500, 1024, 1000, 5),
			] {
				assert_eq!(payload_credits(len, chunk, unit), expect);
			}
		}

		#[test]
		fn test_budget_drain_headroom_prices_records() {
			assert_eq!(budget_drain_headroom(&budget_settings(0)), 5);

			let mut coarse = budget_settings(0);
			coarse.credit_unit = 512;
			assert_eq!(budget_drain_headroom(&coarse), 10);
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

		#[test]
		fn test_buffered_grantor_batches_at_low_water() {
			let grantor = BufferedGrantor::new(4);
			// Above the half-window low-water mark: no grant
			assert_eq!(grantor.replenish(StreamId::new(1), 0, 4), None);
			assert_eq!(grantor.replenish(StreamId::new(1), 1, 4), None);
			assert_eq!(grantor.replenish(StreamId::new(1), 3, 8), None);
			// At the low-water mark: top back up to a full window ahead
			assert_eq!(grantor.replenish(StreamId::new(1), 2, 4), Some(6));
			assert_eq!(grantor.replenish(StreamId::new(1), 6, 8), Some(10));
		}

		#[test]
		fn test_buffered_grantor_single_chunk_window() {
			let grantor = BufferedGrantor::new(1);
			// A grant to limit itself would not raise it: stay silent
			assert_eq!(grantor.replenish(StreamId::new(1), 3, 4), None);
			// Fully consumed: open the next chunk
			assert_eq!(grantor.replenish(StreamId::new(1), 4, 4), Some(5));
		}

		#[test]
		fn test_recv_stream_enforces_granted_limit() {
			let mut stream = RecvStream::new(2);
			assert!(stream.accept_chunk(b"ab"));
			assert!(stream.accept_chunk(b"cd"));
			assert!(!stream.accept_chunk(b"ef"));
			assert_eq!(stream.buffer.as_slice(), b"abcd");
		}

		/// Source scripted with a fixed sequence, then pending forever.
		struct ScriptedSource {
			envelopes: VecDeque<TransportEnvelope>,
			delivered: Arc<AtomicUsize>,
		}

		impl EnvelopeSource for ScriptedSource {
			fn read_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend {
				let next = self.envelopes.pop_front();
				let delivered = Arc::clone(&self.delivered);
				async move {
					match next {
						Some(envelope) => {
							delivered.fetch_add(1, Ordering::SeqCst);
							Ok(envelope)
						}
						None => pending().await,
					}
				}
			}
		}

		/// Grantor that raises the limit on every consultation.
		struct AlwaysGrant;

		impl CreditGrantor for AlwaysGrant {
			fn replenish(&self, _stream_id: StreamId, received: u64, limit: u64) -> Option<u64> {
				Some(limit.max(received).saturating_add(1))
			}
		}

		struct ReaderFixture {
			driver: MuxReaderDriver<ScriptedSource>,
			outbound: mpsc::Receiver<Outbound>,
			/// Held open so the driver never sees a closed inbound channel.
			_inbound: mpsc::Receiver<InboundEvent>,
			delivered: Arc<AtomicUsize>,
		}

		/// Reader driver over a scripted source whose outbound queue is
		/// already full (single slot taken by a filler envelope).
		fn reader_with_full_queue(envelopes: Vec<TransportEnvelope>) -> ReaderFixture {
			let settings = MuxSettings::symmetric(4);
			let (mut outbound_sender, outbound_receiver) = mpsc::channel(0);
			let (inbound_sender, inbound_receiver) = mpsc::channel(4);
			let delivered = Arc::new(AtomicUsize::new(0));

			let filler = MuxPingPackage::new(false, u64::MAX);
			assert!(outbound_sender.try_send(Outbound::Envelope(filler.into())).is_ok());
			assert!(outbound_sender
				.try_send(Outbound::Envelope(MuxPingPackage::new(false, 0).into()))
				.is_err());

			let driver = MuxReaderDriver {
				reader: ScriptedSource { envelopes: envelopes.into(), delivered: Arc::clone(&delivered) },
				shared: Arc::new(MuxShared::new(MuxRole::Server, &settings)),
				inbound: inbound_sender,
				outbound: outbound_sender,
				grantor: Arc::new(AlwaysGrant),
				peer_cap: settings.peer_initiated_cap,
				recv_chunk_size: cap_as_usize(settings.recv_chunk_size).max(1),
				initial_recv_credit: settings.initial_recv_credit.max(1),
				recv_budget: None,
				peer_reassembly: HashMap::new(),
				local_reassembly: HashMap::new(),
				pending_control: VecDeque::new(),
			};

			ReaderFixture { driver, outbound: outbound_receiver, _inbound: inbound_receiver, delivered }
		}

		fn poll_times<F>(future: &mut Pin<Box<F>>, times: usize)
		where
			F: Future,
		{
			let mut cx = noop_cx();
			for _ in 0..times {
				let _ = future.as_mut().poll(&mut cx);
			}
		}

		// The h2 deadlock lesson ([RFC 9113 § 5.2.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2)): a full outbound
		// queue must never park the read loop, or two mutually parked
		// endpoints deadlock. Credit grants and ping acks buffer locally
		// instead.
		#[test]
		fn test_reader_reads_while_outbound_queue_full() {
			let open = MuxOpenPackage::new(1, false, vec![0u8; 4]).unwrap();
			let probe = MuxPingPackage::new(false, 7);
			let fixture = reader_with_full_queue(vec![open.into(), probe.into()]);
			let delivered = Arc::clone(&fixture.delivered);

			let mut driver = Box::pin(fixture.driver.drive());
			poll_times(&mut driver, 8);

			assert_eq!(delivered.load(Ordering::SeqCst), 2);
		}

		#[test]
		fn test_buffered_control_flushes_as_capacity_returns() {
			let open = MuxOpenPackage::new(1, false, vec![0u8; 4]).unwrap();
			let probe = MuxPingPackage::new(false, 7);
			let mut fixture = reader_with_full_queue(vec![open.into(), probe.into()]);

			let mut driver = Box::pin(fixture.driver.drive());
			poll_times(&mut driver, 4);

			let filler = fixture.outbound.try_recv();
			assert!(matches!(
				filler,
				Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(_))))
			));

			poll_times(&mut driver, 4);

			let grant = fixture.outbound.try_recv();
			assert!(matches!(
				grant,
				Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package))))
					if package.stream_id() == 1
			));

			poll_times(&mut driver, 4);

			let ack = fixture.outbound.try_recv();
			assert!(matches!(
				ack,
				Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(package))))
					if package.ack() && package.opaque() == 7
			));
		}

		#[test]
		fn test_buffered_credit_grants_coalesce_per_stream() {
			let mut fixture = reader_with_full_queue(Vec::new());
			fixture.driver.queue_credit(1, 2).unwrap();
			fixture.driver.queue_credit(3, 2).unwrap();
			fixture.driver.queue_credit(1, 4).unwrap();

			let buffered: Vec<_> = fixture.driver.pending_control.iter().collect();
			assert_eq!(buffered.len(), 2);
			assert!(is_credit_grant_for(buffered[0], 3));
			assert!(matches!(
				buffered[1],
				TransportEnvelope::Mux(MuxEnvelope::Credit(package))
					if package.stream_id() == 1 && package.limit() == 4
			));
		}

		#[test]
		fn test_ping_ack_backlog_is_capped() {
			let mut fixture = reader_with_full_queue(Vec::new());
			for opaque in 0..8 {
				fixture.driver.queue_ping_ack(MuxPingPackage::new(true, opaque)).unwrap();
			}

			let buffered_acks = fixture
				.driver
				.pending_control
				.iter()
				.filter(|envelope| is_ping_ack(envelope))
				.count();
			assert_eq!(buffered_acks, MAX_PENDING_PING_ACKS);
		}
	}
}

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
pub use router::{
	BufferedGrantor, CreditGrantor, MuxHandle, MuxReaderDriver, MuxResponder, MuxTransport, MuxWriterDriver,
};

pub use super::envelopes::GoAwayReason;
