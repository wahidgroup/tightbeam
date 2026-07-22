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
//! Stream ID rules follow RFC 9113 § 5.1.1/5.1.2: odd IDs are
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

/// Stream identifier for multiplexed protocols
///
/// Uniquely identifies a logical stream within a single physical connection.
/// Similar to HTTP/2 stream IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

impl StreamId {
	/// Create a new stream ID
	pub const fn new(id: u32) -> Self {
		Self(id)
	}

	/// Get the underlying ID value
	pub const fn value(&self) -> u32 {
		self.0
	}

	/// Check if this is a client-initiated stream (odd ID)
	pub const fn is_client_initiated(&self) -> bool {
		self.0 % 2 == 1
	}

	/// Check if this is a server-initiated stream (even ID)
	pub const fn is_server_initiated(&self) -> bool {
		self.0.is_multiple_of(2)
	}
}

/// Stream state for multiplexed transports
///
/// Streams in `Open`, `HalfClosedLocal`, or `HalfClosedRemote` count toward
/// the peer-advertised concurrency cap. `Idle` and `Closed` do not
/// (RFC 9113 § 5.1.2).
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

/// Protocol multiplexing (multiple concurrent requests on one connection)
///
/// Implementations provide HTTP/2-style stream multiplexing over a single
/// physical connection, enabling concurrent request/response pairs without
/// head-of-line blocking.
pub trait MultiplexedProtocol {
	/// Negotiated cap on concurrent locally-initiated streams
	///
	/// Similar to HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS. The peer
	/// advertised this value during the handshake.
	fn max_concurrent_streams(&self) -> u32;

	/// Send a request on a freshly allocated stream and await its response
	///
	/// Allocates the next stream ID (odd or even per role), registers the
	/// pending response slot, and resolves when the correlated response
	/// arrives. Dropping the returned future before it resolves cancels the
	/// stream and frees its concurrency slot.
	fn emit_on_stream(&self, frame: &Frame) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend;

	/// Cancel a locally-initiated in-flight stream
	///
	/// Best-effort: removes the pending entry, frees the concurrency slot,
	/// and notifies the peer without blocking. Never panics.
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
	use core::time::Duration;
	use std::collections::{BTreeMap, HashMap};
	use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
	use std::time::Instant;

	use futures::channel::{mpsc, oneshot};
	use futures::future::{AbortHandle, Abortable, Aborted};
	use futures::stream::FuturesUnordered;
	use futures::{SinkExt, Stream, StreamExt};

	use super::{MultiplexedProtocol, MuxRole, StreamId};
	use crate::constants::DEFAULT_MUX_CANCEL_BUDGET;
	use crate::der::{Decode, Encode};
	use crate::policy::TransitStatus;
	use crate::transport::envelopes::{
		CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxEndPackage, MuxEnvelope, MuxOpenPackage,
		MuxPingPackage, ResponsePackage, TransportEnvelope,
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

	/// Records the writer must reserve so a graceful rekey drain can finish
	/// after the GoAway fires (RFC 8446 § 5.5 analog).
	///
	/// At the moment the limit check trips, the connection can still owe:
	/// - envelopes already queued outbound, at most the channel capacity of
	///   `local_cap + peer_cap`
	/// - responses to in-flight peer streams, at most `peer_cap`
	/// - drop-guard cancels for pending local streams, at most `local_cap`
	/// - the GoAway itself, exactly 1
	///
	/// Total: `2 * (local_cap + peer_cap) + 1`. A hostile peer that keeps
	/// opening streams after the GoAway draws refusal cancels beyond any
	/// bound and only exhausts the cipher of its own dying connection.
	fn drain_headroom(settings: &MuxSettings) -> u64 {
		u64::from(settings.local_initiated_cap)
			.saturating_add(u64::from(settings.peer_initiated_cap))
			.saturating_mul(2)
			.saturating_add(1)
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
		/// When the last stream opened in either direction. Pings do not
		/// count: keepalive probes must not defeat idle reclamation
		last_activity: Instant,
		/// `last_stream_id` advertised in our GoAway, once sent
		goaway_sent: Option<u32>,
		/// `last_stream_id` received in the peer's GoAway
		goaway_received: Option<u32>,
		/// Wakers parked on pending-table drain (shutdown)
		drain_wakers: Vec<Waker>,
	}

	impl MuxState {
		fn wake_drain_waiters(&mut self) {
			for waker in self.drain_wakers.drain(..) {
				waker.wake();
			}
		}
	}

	struct MuxShared {
		role: MuxRole,
		local_cap: u32,
		state: Mutex<MuxState>,
	}

	impl MuxShared {
		fn lock(&self) -> MutexGuard<'_, MuxState> {
			self.state.lock().unwrap_or_else(PoisonError::into_inner)
		}

		/// Allocate the next stream ID and register its response slot.
		fn allocate(&self, sender: oneshot::Sender<StreamOutcome>) -> TransportResult<u32> {
			let mut state = self.lock();
			if state.goaway_sent.is_some() || state.goaway_received.is_some() {
				return Err(TransportError::Draining);
			}
			if state.pending.len() >= cap_as_usize(self.local_cap) {
				return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
			}

			let stream_id = state.next_stream_id.ok_or(TransportError::Draining)?;
			state.next_stream_id = stream_id.checked_add(2);
			state.pending.insert(stream_id, sender);
			state.last_activity = Instant::now();

			Ok(stream_id)
		}

		fn remove_pending(&self, stream_id: u32) -> Option<oneshot::Sender<StreamOutcome>> {
			let mut state = self.lock();
			let entry = state.pending.remove(&stream_id);
			if entry.is_some() {
				state.wake_drain_waiters();
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
			if state.goaway_sent.is_some() || state.goaway_received.is_some() {
				return Err(TransportError::Draining);
			}

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
		/// cancellation.
		fn fail_all_pending(&self) {
			let mut state = self.lock();
			state.pending.clear();
			state.pending_pings.clear();
			state.wake_drain_waiters();
		}

		/// Resolve pending streams above `last_stream_id` as draining
		/// (peer GoAway: it will never process them).
		fn fail_pending_above(&self, last_stream_id: u32) {
			let mut state = self.lock();
			state.goaway_received = Some(last_stream_id);
			if let Some(first_dropped) = last_stream_id.checked_add(1) {
				for (_, sender) in state.pending.split_off(&first_dropped) {
					let _ = sender.send(StreamOutcome::Draining);
				}
			}

			state.wake_drain_waiters();
		}

		/// Halt the allocator and record the GoAway watermark. Returns the
		/// `last_stream_id` to advertise, or `None` if already shutting down.
		fn begin_shutdown(&self) -> Option<u32> {
			let mut state = self.lock();
			if state.goaway_sent.is_some() {
				return None;
			}

			state.goaway_sent = Some(state.last_peer_stream_id);
			Some(state.last_peer_stream_id)
		}

		/// Validate and record an incoming peer-initiated stream ID
		/// (RFC 9113 § 5.1.1: odd/even role match, nonzero, strictly increasing).
		fn register_peer_stream(&self, stream_id: u32) -> TransportResult<PeerStream> {
			let mut state = self.lock();
			if !self.role.peer().initiates(stream_id) || stream_id <= state.last_peer_stream_id {
				return Err(TransportError::InvalidMessage);
			}

			state.last_peer_stream_id = stream_id;
			state.last_activity = Instant::now();

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

		/// Time since the last stream opened, or zero while any
		/// locally-initiated stream is still in flight.
		fn idle_for(&self, now: Instant) -> Duration {
			let state = self.lock();
			if !state.pending.is_empty() {
				return Duration::ZERO;
			}

			now.duration_since(state.last_activity)
		}
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

			state.drain_wakers.push(cx.waker().clone());

			Poll::Pending
		}
	}

	/// Cancels the stream if the owning emit future is dropped before its
	/// response arrives: frees the cap slot and notifies the peer
	/// (best-effort, RFC 9113 § 6.4 analog).
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
			let _ = outbound.clone().try_send(Outbound::Envelope(package.into()));
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

	fn unwrap_frame(frame: Arc<Frame>) -> Frame {
		Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone())
	}

	fn cancel_error(reason: CancelReason) -> TransportError {
		match reason {
			CancelReason::Cancelled => TransportError::OperationFailed(TransportFailure::PolicyRejection),
			CancelReason::Timeout => TransportError::OperationFailed(TransportFailure::Timeout),
			CancelReason::Rejected => TransportError::OperationFailed(TransportFailure::Busy),
			// Application codes carry no transport-failure mapping of their own
			CancelReason::Application(_) => TransportError::OperationFailed(TransportFailure::PolicyRejection),
		}
	}

	fn resolve_response(response: ResponsePackage) -> TransportResult<Option<Frame>> {
		match response.status() {
			TransitStatus::Accepted => Ok(response.message.map(unwrap_frame)),
			status => Err(TransportError::from(status)),
		}
	}

	/// Cloneable client handle for a multiplexed connection.
	#[derive(Clone)]
	pub struct MuxHandle {
		shared: Arc<MuxShared>,
		outbound: mpsc::Sender<Outbound>,
	}

	impl MuxHandle {
		/// Send a request on a freshly allocated stream and await its
		/// response.
		///
		/// Dropping the returned future before it resolves cancels the
		/// stream: the pending entry is removed, the cap slot freed, and a
		/// best-effort [`MuxCancelPackage`] sent. Per-stream timeouts
		/// compose by wrapping this future in the caller's timer.
		///
		/// # Errors
		/// - `OperationFailed(StreamsExhausted)`: local-initiated cap exhausted
		/// - `OperationFailed(Busy)`: the peer refused the stream
		/// - `Draining`: GoAway sent or received. No new streams
		/// - `ConnectionClosed`: connection failed before the response
		pub async fn emit_on_stream(&self, frame: &Frame) -> TransportResult<Option<Frame>> {
			// Encode before allocating so an encoding failure never burns
			// a stream ID or queues a cancel for a stream the peer never saw.
			let payload = frame.to_der()?;
			let (sender, receiver) = oneshot::channel();
			let stream_id = self.shared.allocate(sender)?;
			let mut guard = CancelOnDrop {
				shared: Arc::clone(&self.shared),
				outbound: self.outbound.clone(),
				stream_id,
				armed: true,
			};

			let request = MuxOpenPackage::new(stream_id, true, payload)?;
			let mut outbound = self.outbound.clone();
			outbound
				.send(Outbound::Envelope(request.into()))
				.await
				.map_err(|_| TransportError::ConnectionClosed)?;

			let outcome = receiver.await;

			guard.disarm();

			match outcome {
				Ok(StreamOutcome::Response(response)) => resolve_response(response),
				Ok(StreamOutcome::Cancelled(reason)) => Err(cancel_error(reason)),
				Ok(StreamOutcome::Draining) => Err(TransportError::Draining),
				Err(_) => Err(TransportError::ConnectionClosed),
			}
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

		/// Time since the last stream opened in either direction, or zero
		/// while any locally-initiated stream is still in flight.
		///
		/// Pings deliberately do not count as activity: keepalive probes
		/// must not defeat idle reclamation.
		pub fn idle_for(&self, now: Instant) -> Duration {
			self.shared.idle_for(now)
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
			let mut outbound = self.outbound.clone();
			outbound
				.send(Outbound::Envelope(probe.into()))
				.await
				.map_err(|_| TransportError::ConnectionClosed)?;

			let outcome = receiver.await;

			guard.disarm();

			outcome.map_err(|_| TransportError::ConnectionClosed)?;

			Ok(())
		}

		/// Gracefully shut the connection down (RFC 9113 § 6.8 analog): sends
		/// GoAway, halts the allocator, awaits pending-table drain, then
		/// closes the writer driver.
		///
		/// A drain deadline composes by wrapping this future in the
		/// caller's timer.
		pub async fn shutdown(&self) -> TransportResult<()> {
			if let Some(last_peer) = self.shared.begin_shutdown() {
				let package = GoAwayPackage::new(last_peer, GoAwayReason::Shutdown);
				let mut outbound = self.outbound.clone();
				outbound
					.send(Outbound::Envelope(package.into()))
					.await
					.map_err(|_| TransportError::ConnectionClosed)?;
			}

			DrainPending { shared: Arc::clone(&self.shared) }.await;

			let mut outbound = self.outbound.clone();
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

		/// RFC 8446 § 5.5 analog: when the send cipher nears its
		/// record limit, drain the connection via GoAway while enough
		/// records remain to answer in-flight peer streams. The caller
		/// then reestablishes the session for fresh keys.
		async fn enforce_rekey_limit(&mut self) -> TransportResult<()> {
			if self.writer.remaining_records() > self.drain_headroom {
				return Ok(());
			}
			if let Some(last_peer) = self.shared.begin_shutdown() {
				let package = GoAwayPackage::new(last_peer, GoAwayReason::Shutdown);
				self.writer.write_envelope(package.into()).await?;
			}

			Ok(())
		}
	}

	/// Reader driver: routes inbound envelopes off the read half.
	///
	/// Responses resolve their pending stream (unknown IDs silently
	/// discarded: cancel/response races are benign). Requests flow to the
	/// [`MuxResponder`]. Protocol violations answer with a GoAway and fail
	/// the driver. Spawn [`MuxReaderDriver::drive`] on the caller's executor.
	pub struct MuxReaderDriver<R>
	where
		R: EnvelopeSource,
	{
		reader: R,
		shared: Arc<MuxShared>,
		inbound: mpsc::Sender<InboundEvent>,
		outbound: mpsc::Sender<Outbound>,
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
				let envelope = self.reader.read_envelope().await?;
				let TransportEnvelope::Mux(mux) = envelope else {
					return Err(self.protocol_violation());
				};
				match mux {
					MuxEnvelope::End(package) => self.route_end(package)?,
					MuxEnvelope::Open(package) => self.route_open(package).await?,
					MuxEnvelope::Cancel(package) => self.route_cancel(package).await?,
					MuxEnvelope::Ping(package) => self.route_ping(package).await?,
					MuxEnvelope::GoAway(package) => self.shared.fail_pending_above(package.last_stream_id()),
					// The handshake never negotiates chunking, so no
					// conforming peer sends continuation chunks or
					// credit grants
					MuxEnvelope::Data(_) | MuxEnvelope::Credit(_) => return Err(self.protocol_violation()),
				}
			}
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

			// Resolve before decoding: stale ends are discarded without
			// inspecting their payload, and non-Accepted trailers never
			// contribute a frame, so garbage bytes on either cannot tear
			// down the connection.
			let Some(sender) = self.shared.remove_pending(stream_id) else {
				return Ok(());
			};

			let message = match package.status() {
				TransitStatus::Accepted => self.decode_stream_frame(package.payload())?,
				_ => None,
			};

			let response = ResponsePackage::new(package.status(), message);
			let _ = sender.send(StreamOutcome::Response(response));
			Ok(())
		}

		async fn route_open(&mut self, package: MuxOpenPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			// The handshake never negotiates chunking, so every
			// conforming open carries its whole frame as the last chunk
			if !package.last() {
				return Err(self.protocol_violation());
			}

			match self.shared.register_peer_stream(stream_id) {
				Ok(PeerStream::Accept) => {
					let frame = match self.decode_stream_frame(package.payload())? {
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
				Ok(PeerStream::RejectDraining) => {
					self.refuse_stream(stream_id);
					Ok(())
				}
				Err(_) => Err(self.protocol_violation()),
			}
		}

		async fn route_cancel(&mut self, package: MuxCancelPackage) -> TransportResult<()> {
			let stream_id = package.stream_id();
			if self.shared.role.initiates(stream_id) {
				// Peer cancelled/refused a stream we initiated
				self.shared.resolve(stream_id, StreamOutcome::Cancelled(package.reason()));
				return Ok(());
			}
			if self.shared.role.peer().initiates(stream_id) {
				// Peer withdrew its own request. Abort the handler
				let _ = self.inbound.send(InboundEvent::Cancel(stream_id)).await;
				return Ok(());
			}

			Err(self.protocol_violation())
		}

		/// Answer a peer probe with its ack. Terminates here: pings never
		/// reach the responder or the application handler.
		async fn route_ping(&mut self, package: MuxPingPackage) -> TransportResult<()> {
			if package.ack() {
				self.shared.resolve_ping(package.opaque());
				return Ok(());
			}

			// After our GoAway the writer's remaining records are reserved
			// for owed stream traffic (see `drain_headroom`), so peer
			// probes draw no acks. Combined with the bounded outbound
			// queue's backpressure this caps what a ping flood can extract
			// (CVE-2019-9512 hardening).
			if self.shared.shutdown_begun() {
				return Ok(());
			}

			let ack = MuxPingPackage::new(true, package.opaque());
			self.outbound
				.send(Outbound::Envelope(ack.into()))
				.await
				.map_err(|_| TransportError::ConnectionClosed)?;

			Ok(())
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
		Finished(u32, ResponsePackage),
		Aborted,
		Closed,
	}

	async fn next_responder_event<Fut>(
		inbound: &mut mpsc::Receiver<InboundEvent>,
		tasks: &mut FuturesUnordered<Abortable<Fut>>,
		inbound_open: bool,
	) -> ResponderEvent
	where
		Fut: Future<Output = (u32, ResponsePackage)>,
	{
		poll_fn(|cx| {
			if let Poll::Ready(Some(completion)) = Pin::new(&mut *tasks).poll_next(cx) {
				let event = match completion {
					Ok((stream_id, response)) => ResponderEvent::Finished(stream_id, response),
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

	/// Serves peer-initiated streams with a caller-supplied handler.
	///
	/// Handlers for distinct streams run concurrently (no head-of-line
	/// blocking). Cap exhaustion answers with [`TransitStatus::Busy`]. A
	/// peer cancel aborts the in-flight handler and sends no response.
	///
	/// Cancels of in-flight handlers draw on a per-connection budget
	/// (CVE-2023-44487 "Rapid Reset" hardening): a peer that opens streams
	/// only to cancel them exhausts the budget and is told to go away.
	pub struct MuxResponder {
		inbound: mpsc::Receiver<InboundEvent>,
		outbound: mpsc::Sender<Outbound>,
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
							self.respond(stream_id, ResponsePackage::new(TransitStatus::Busy, None)).await?;
							continue;
						}

						let (handle, registration) = AbortHandle::new_pair();

						in_flight.insert(stream_id, handle);

						let work = handler(frame);
						tasks.push(Abortable::new(async move { (stream_id, work.await) }, registration));
					}
					ResponderEvent::Finished(stream_id, response) => {
						in_flight.remove(&stream_id);
						self.respond(stream_id, response).await?;
					}
				}
			}
		}

		async fn respond(&mut self, stream_id: u32, response: ResponsePackage) -> TransportResult<()> {
			let payload = match response.message() {
				Some(frame) => frame.as_ref().to_der()?,
				None => Vec::new(),
			};
			let package = MuxEndPackage::new(stream_id, response.status(), payload)?;

			self.outbound
				.send(Outbound::Envelope(package.into()))
				.await
				.map_err(|_| TransportError::ConnectionClosed)
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

			let shared = Arc::new(MuxShared {
				role,
				local_cap: settings.local_initiated_cap,
				state: Mutex::new(MuxState {
					next_stream_id: Some(role.first_local_stream_id()),
					last_peer_stream_id: 0,
					pending: BTreeMap::new(),
					next_ping_opaque: 0,
					pending_pings: BTreeMap::new(),
					last_activity: Instant::now(),
					goaway_sent: None,
					goaway_received: None,
					drain_wakers: Vec::new(),
				}),
			});

			let drain_headroom = drain_headroom(&settings);

			Self {
				handle: MuxHandle { shared: Arc::clone(&shared), outbound: outbound_sender.clone() },
				reader: MuxReaderDriver {
					reader,
					shared: Arc::clone(&shared),
					inbound: inbound_sender,
					outbound: outbound_sender.clone(),
				},
				writer: MuxWriterDriver { writer, commands: outbound_receiver, shared, drain_headroom },
				responder: MuxResponder {
					inbound: inbound_receiver,
					outbound: outbound_sender,
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

		/// Clone the client handle without decomposing the transport.
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
		use super::*;

		fn test_shared(role: MuxRole, local_cap: u32) -> MuxShared {
			MuxShared {
				role,
				local_cap,
				state: Mutex::new(MuxState {
					next_stream_id: Some(role.first_local_stream_id()),
					last_peer_stream_id: 0,
					pending: BTreeMap::new(),
					next_ping_opaque: 0,
					pending_pings: BTreeMap::new(),
					last_activity: Instant::now(),
					goaway_sent: None,
					goaway_received: None,
					drain_wakers: Vec::new(),
				}),
			}
		}

		fn slot() -> oneshot::Sender<StreamOutcome> {
			oneshot::channel().0
		}

		#[test]
		fn test_client_allocates_odd_monotonic() {
			let shared = test_shared(MuxRole::Client, 8);
			assert!(matches!(shared.allocate(slot()), Ok(1)));
			assert!(matches!(shared.allocate(slot()), Ok(3)));
			assert!(matches!(shared.allocate(slot()), Ok(5)));
		}

		#[test]
		fn test_server_allocates_even_monotonic_never_zero() {
			let shared = test_shared(MuxRole::Server, 8);
			assert!(matches!(shared.allocate(slot()), Ok(2)));
			assert!(matches!(shared.allocate(slot()), Ok(4)));
		}

		#[test]
		fn test_cap_exhaustion_reports_busy() {
			let shared = test_shared(MuxRole::Client, 2);
			assert!(matches!(shared.allocate(slot()), Ok(1)));
			assert!(matches!(shared.allocate(slot()), Ok(3)));
			assert!(matches!(
				shared.allocate(slot()),
				Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted))
			));
		}

		#[test]
		fn test_completed_stream_frees_cap_slot() {
			let shared = test_shared(MuxRole::Client, 1);
			assert!(matches!(shared.allocate(slot()), Ok(1)));
			assert!(shared.remove_pending(1).is_some());
			assert!(matches!(shared.allocate(slot()), Ok(3)));
		}

		#[test]
		fn test_allocation_halts_after_shutdown() {
			let shared = test_shared(MuxRole::Client, 8);
			assert!(matches!(shared.begin_shutdown(), Some(0)));
			assert!(matches!(shared.allocate(slot()), Err(TransportError::Draining)));
			assert!(shared.begin_shutdown().is_none());
		}

		#[test]
		fn test_allocation_halts_after_peer_goaway() {
			let shared = test_shared(MuxRole::Client, 8);
			shared.fail_pending_above(0);
			assert!(matches!(shared.allocate(slot()), Err(TransportError::Draining)));
		}

		#[test]
		fn test_id_space_exhaustion_reports_draining() {
			let shared = test_shared(MuxRole::Client, 8);
			shared.lock().next_stream_id = Some(u32::MAX);
			assert!(matches!(shared.allocate(slot()), Ok(u32::MAX)));
			assert!(matches!(shared.allocate(slot()), Err(TransportError::Draining)));
		}

		#[test]
		fn test_peer_stream_rejects_zero_and_wrong_parity() {
			let server = test_shared(MuxRole::Server, 8);
			assert!(matches!(server.register_peer_stream(0), Err(TransportError::InvalidMessage)));
			assert!(matches!(server.register_peer_stream(2), Err(TransportError::InvalidMessage)));
			assert!(matches!(server.register_peer_stream(1), Ok(PeerStream::Accept)));
		}

		#[test]
		fn test_peer_stream_rejects_non_increasing() {
			let server = test_shared(MuxRole::Server, 8);
			assert!(matches!(server.register_peer_stream(5), Ok(PeerStream::Accept)));
			assert!(matches!(server.register_peer_stream(3), Err(TransportError::InvalidMessage)));
			assert!(matches!(server.register_peer_stream(5), Err(TransportError::InvalidMessage)));
			assert!(matches!(server.register_peer_stream(7), Ok(PeerStream::Accept)));
		}

		#[test]
		fn test_peer_stream_above_goaway_watermark_refused() {
			let server = test_shared(MuxRole::Server, 8);
			assert!(matches!(server.register_peer_stream(1), Ok(PeerStream::Accept)));
			assert!(matches!(server.begin_shutdown(), Some(1)));
			assert!(matches!(server.register_peer_stream(3), Ok(PeerStream::RejectDraining)));
		}

		#[test]
		fn test_goaway_fails_pending_above_watermark_only() {
			let shared = test_shared(MuxRole::Client, 8);
			let (sender_low, mut receiver_low) = oneshot::channel();
			let (sender_high, mut receiver_high) = oneshot::channel();

			shared.lock().pending.insert(1, sender_low);
			shared.lock().pending.insert(3, sender_high);

			shared.fail_pending_above(1);

			assert!(matches!(receiver_low.try_recv(), Ok(None)));
			assert!(matches!(receiver_high.try_recv(), Ok(Some(StreamOutcome::Draining))));
		}

		#[test]
		fn test_drain_headroom_covers_queue_responses_cancels_goaway() {
			let settings = MuxSettings { local_initiated_cap: 3, peer_initiated_cap: 5 };
			assert_eq!(drain_headroom(&settings), 17);
		}

		fn ping_slot() -> oneshot::Sender<()> {
			oneshot::channel().0
		}

		#[test]
		fn test_ping_allocates_monotonic_opaque() {
			let shared = test_shared(MuxRole::Client, 8);
			assert!(matches!(shared.allocate_ping(ping_slot()), Ok(0)));
			assert!(matches!(shared.allocate_ping(ping_slot()), Ok(1)));
			assert!(matches!(shared.allocate_ping(ping_slot()), Ok(2)));
		}

		#[test]
		fn test_ping_ack_resolves_pending() {
			let shared = test_shared(MuxRole::Client, 8);
			let (sender, mut receiver) = oneshot::channel();
			assert!(matches!(shared.allocate_ping(sender), Ok(0)));

			shared.resolve_ping(0);
			assert!(matches!(receiver.try_recv(), Ok(Some(()))));
		}

		#[test]
		fn test_stale_ping_ack_discarded() {
			let shared = test_shared(MuxRole::Client, 8);
			let (sender, mut receiver) = oneshot::channel();
			assert!(matches!(shared.allocate_ping(sender), Ok(0)));

			shared.remove_pending_ping(0);
			shared.resolve_ping(0);
			assert!(receiver.try_recv().is_err());
		}

		#[test]
		fn test_ping_refused_while_draining() {
			let shared = test_shared(MuxRole::Client, 8);
			shared.begin_shutdown();
			assert!(matches!(shared.allocate_ping(ping_slot()), Err(TransportError::Draining)));
		}

		#[test]
		fn test_connection_failure_fails_pending_pings() {
			let shared = test_shared(MuxRole::Client, 8);
			let (sender, mut receiver) = oneshot::channel();
			assert!(matches!(shared.allocate_ping(sender), Ok(0)));

			shared.fail_all_pending();
			assert!(receiver.try_recv().is_err());
		}

		#[test]
		fn test_headroom_present_on_fresh_connection() {
			let shared = test_shared(MuxRole::Client, 2);
			assert!(shared.has_stream_headroom());
		}

		#[test]
		fn test_headroom_gone_at_cap() {
			let shared = test_shared(MuxRole::Client, 1);
			assert!(matches!(shared.allocate(slot()), Ok(1)));
			assert!(!shared.has_stream_headroom());
		}

		#[test]
		fn test_headroom_gone_while_draining() {
			let shared = test_shared(MuxRole::Client, 2);
			shared.begin_shutdown();
			assert!(!shared.has_stream_headroom());
		}

		#[test]
		fn test_idle_zero_while_stream_in_flight() {
			let shared = test_shared(MuxRole::Client, 8);
			assert!(matches!(shared.allocate(slot()), Ok(1)));

			let later = Instant::now() + Duration::from_secs(60);
			assert_eq!(shared.idle_for(later), Duration::ZERO);
		}

		#[test]
		fn test_idle_grows_after_streams_resolve() {
			let shared = test_shared(MuxRole::Client, 8);
			assert!(matches!(shared.allocate(slot()), Ok(1)));
			assert!(shared.remove_pending(1).is_some());

			let later = Instant::now() + Duration::from_secs(60);
			assert!(shared.idle_for(later) >= Duration::from_secs(60));
		}

		#[test]
		fn test_new_stream_resets_idle_measure() {
			let shared = test_shared(MuxRole::Client, 8);
			shared.lock().last_activity = Instant::now() - Duration::from_secs(60);

			assert!(matches!(shared.allocate(slot()), Ok(1)));
			assert!(shared.remove_pending(1).is_some());
			assert!(shared.idle_for(Instant::now()) < Duration::from_secs(60));
		}

		#[test]
		fn test_peer_stream_resets_idle_measure() {
			let server = test_shared(MuxRole::Server, 8);
			server.lock().last_activity = Instant::now() - Duration::from_secs(60);

			assert!(matches!(server.register_peer_stream(1), Ok(PeerStream::Accept)));
			assert!(server.idle_for(Instant::now()) < Duration::from_secs(60));
		}

		#[test]
		fn test_cancel_reason_error_mapping() {
			assert!(matches!(
				cancel_error(CancelReason::Rejected),
				TransportError::OperationFailed(TransportFailure::Busy)
			));
			assert!(matches!(
				cancel_error(CancelReason::Timeout),
				TransportError::OperationFailed(TransportFailure::Timeout)
			));
			assert!(matches!(
				cancel_error(CancelReason::Cancelled),
				TransportError::OperationFailed(TransportFailure::PolicyRejection)
			));
			assert!(matches!(
				cancel_error(CancelReason::Application(0x1000)),
				TransportError::OperationFailed(TransportFailure::PolicyRejection)
			));
		}
	}
}

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
pub use router::{MuxHandle, MuxReaderDriver, MuxResponder, MuxTransport, MuxWriterDriver};
