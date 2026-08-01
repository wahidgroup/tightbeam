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
//! Streaming layers over the same wire: [`MuxHandle::open_stream`] and
//! [`MuxHandle::open_duplex`] push request chunks through a [`RequestSink`].
//! Each initiating call stamps its interaction kind on the stream's Open
//! record ([`MuxStreamKind`](crate::transport::envelopes::MuxStreamKind)),
//! and [`MuxResponder::serve_with`] routes every peer stream to the matching
//! [`MuxDispatch`] method.
//!
//! Stream ID rules follow:
//! - [RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1)
//! - [RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)
//! - Odd IDs are client-initiated, even IDs server-initiated
//! - ID 0 is reserved and never allocated
//! - Each endpoint allocates strictly monotonically
//!
//! Per-stream timeouts compose externally: wrap the emit future in a timeout
//! and the drop guard cancels the stream on expiry.

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
mod router;

use core::future::Future;
use std::sync::Arc;

use crate::transport::handshake::negotiation::{MuxSettings, TransportOffer};
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;
use crate::Frame;

#[cfg(feature = "x509")]
use crate::x509::Certificate;

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
use crate::constants::DEFAULT_HOP_BUDGET;
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
use crate::utils::urn::Urn;

/// Converts a caller-owned or already-shared mux offer into a shared handle.
///
/// Accept loops and pools store [`Arc<TransportOffer>`] so each connection
/// bumps a refcount instead of deep-copying authorization octets.
pub trait IntoMuxOffer {
	/// Shared offer for transport storage, or `None` to advertise nothing.
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>>;
}

impl IntoMuxOffer for Option<TransportOffer> {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		self.map(Arc::new)
	}
}

impl IntoMuxOffer for Option<Arc<TransportOffer>> {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		self
	}
}

impl IntoMuxOffer for TransportOffer {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		Some(Arc::new(self))
	}
}

impl IntoMuxOffer for Arc<TransportOffer> {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		Some(self)
	}
}

impl IntoMuxOffer for &Arc<TransportOffer> {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		// Share one advertisement across accept/dial sites.
		Some(Arc::clone(self))
	}
}

impl IntoMuxOffer for Option<&Arc<TransportOffer>> {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		self.map(Arc::clone)
	}
}

#[cfg(feature = "transport-policy")]
use crate::policy::GatePolicy;
#[cfg(feature = "transport-policy")]
use crate::policy::SessionContext;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::rekey::RekeyDriver;

#[cfg(all(feature = "x509", feature = "tokio"))]
pub use router::SpawnedMux;
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
pub use router::{
	BufferedGrantor, CreditGrantor, MuxDispatch, MuxHandle, MuxReaderDriver, MuxResponder, MuxTransport,
	MuxWriterDriver, ReplySink, RequestSink, StreamBody,
};

/// Grpc-style route carried on a stream's Open record.
///
/// The route selects the responder's dispatch target (a servlet [`Urn`],
/// the stream analog of an HTTP `:path`) and carries the relay budget.
/// The default route reproduces an unrouted local open, so the routed
/// and unrouted open paths share one wire shape.
///
/// Initiators stamp a route through the typed `open_stream_to` /
/// `open_duplex_to` entry points, which name a servlet type the same way
/// `HiveContext::call` does. A served handler reads the route it received
/// through [`CallContext`](crate::transport::serve::CallContext).
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRoute {
	target: Option<Urn<'static>>,
	hops_remaining: u8,
}

/// The default route: unrouted, with the origin relay budget so it
/// stays DER-omitted on the wire like a pre-route open.
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
impl Default for StreamRoute {
	fn default() -> Self {
		Self { target: None, hops_remaining: DEFAULT_HOP_BUDGET }
	}
}

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
impl StreamRoute {
	/// Unrouted local stream: the responder dispatches by its own
	/// resolved address. Identical on the wire to a pre-route open.
	pub(crate) fn local() -> Self {
		Self::default()
	}

	/// Route to a servlet type with the origin sentinel budget, which
	/// defers the hop cap to the first gateway's `max_hops` policy. A
	/// gateway reads the target to dispatch locally or splice to a
	/// peer.
	pub(crate) fn to(target: Urn<'static>) -> Self {
		Self { target: Some(target), hops_remaining: DEFAULT_HOP_BUDGET }
	}

	/// Route to a servlet type with an explicit remaining relay
	/// budget. A gateway stamps this when it re-emits a client stream
	/// to a peer gateway with the budget decremented. A `0` budget is
	/// served locally and never re-forwarded.
	pub(crate) fn relayed_to(target: Urn<'static>, hops_remaining: u8) -> Self {
		Self { target: Some(target), hops_remaining }
	}

	/// Reconstruct a route from the parts carried on a received Open.
	pub(crate) fn from_parts(target: Option<Urn<'static>>, hops_remaining: u8) -> Self {
		Self { target, hops_remaining }
	}

	/// Split into the target and relay budget stamped on the Open.
	pub(crate) fn into_parts(self) -> (Option<Urn<'static>>, u8) {
		(self.target, self.hops_remaining)
	}

	/// Grpc-style dispatch target, or `None` for an unrouted stream
	/// whose responder address is already resolved.
	pub fn target(&self) -> Option<&Urn<'static>> {
		self.target.as_ref()
	}

	/// Relay budget left on this open: the number of gateway forwards
	/// the stream may still spend. A `0` stream is served locally and
	/// never re-forwarded.
	pub fn hops_remaining(&self) -> u8 {
		self.hops_remaining
	}
}

/// Stream identifier within one multiplexed connection.
///
/// Odd IDs are client-initiated, even IDs are server-initiated, and ID 0 is reserved
/// ([RFC 9113 § 5.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u32);

impl StreamId {
	/// Build from the wire-encoded stream identifier.
	pub const fn new(id: u32) -> Self {
		Self(id)
	}

	/// Wire-encoded identifier for framing and role checks.
	pub const fn value(&self) -> u32 {
		self.0
	}

	/// True when this id is odd (client-allocated).
	pub const fn is_client_initiated(&self) -> bool {
		self.0 % 2 == 1
	}

	/// True when this id is even (server-allocated), including reserved id 0.
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
	/// The id is unused and does not count toward the concurrency cap.
	Idle,
	/// Both sides may send. The stream counts toward the concurrency
	/// cap.
	Open,
	/// Local send is closed. The stream still counts toward the
	/// concurrency cap.
	HalfClosedLocal,
	/// Remote send is closed. The stream still counts toward the
	/// concurrency cap.
	HalfClosedRemote,
	/// The stream is fully closed and does not count toward the
	/// concurrency cap.
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
/// Cap and cancel contracts match [`MuxHandle`]. This trait exists so
/// the pool and other callers stay generic over the concrete handle
/// type. Cancellation is by drop: abandoning the emit future cancels
/// its stream, so no ID-keyed cancel surface exists.
pub trait MultiplexedProtocol {
	/// Peer-advertised cap on concurrent locally-initiated streams
	/// (HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`).
	fn max_concurrent_streams(&self) -> u32;

	/// Open a stream, send `frame`, await the correlated response.
	///
	/// Dropping the future before it resolves cancels the stream and frees
	/// its concurrency slot.
	fn emit_on_stream(&self, frame: &Frame) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend;
}

/// Mux capability advertisement, bound into the handshake transcript.
///
/// Implemented only by transports that can attach the mux plane after
/// negotiation (split envelope halves plus spawned drivers): advertising
/// anywhere else would negotiate a capability the endpoint cannot honor.
pub trait MuxCapable: Sized {
	/// Local mux advertisement. `None` advertises nothing.
	///
	/// Callers that already hold a shared offer pass `Some(Arc::clone(&offer))`.
	/// Owned offers convert at the boundary via [`IntoMuxOffer`] on inherent
	/// transport helpers.
	fn with_mux_offer(self, offer: Option<Arc<TransportOffer>>) -> Self;

	/// Negotiated multiplexing settings from a completed handshake.
	/// `None` means the connection is single-flight.
	fn negotiated_mux(&self) -> Option<MuxSettings>;
}

/// In-band rekey wiring harvested from a completed receipt-bearing
/// handshake: the role-fixed exchange half plus the epoch-0 dual-signed
/// receipt it rotates (unmetered sessions carry none and keep the
/// GoAway drain). Opaque: built by the transport, consumed by
/// [`MuxTransport::with_rekey`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct MuxRekeyContext {
	pub(crate) driver: RekeyDriver,
	pub(crate) receipt: StoredReceipt,
}

/// Client-side mux connection setup.
///
/// Abstracts the concrete transport so the connection pool stays generic
/// over [`Protocol`](crate::transport::Protocol).
pub trait MuxConnector: MuxCapable {
	/// Envelope read half after splitting.
	type EnvelopeReader: EnvelopeSource + MaybeSend + 'static;
	/// Envelope write half after splitting.
	type EnvelopeWriter: EnvelopeSink + MaybeSend + 'static;

	/// Drive the client handshake to completion. Does nothing on transports
	/// without encryption material, which then never negotiate mux.
	fn complete_client_handshake(&mut self) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Detach the client half of the in-band rekey wiring from a completed
	/// handshake. `Ok(None)` on sessions without a receipt-bearing epoch.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		Ok(None)
	}

	/// Validated peer certificate pinned by a completed client handshake.
	///
	/// [`MuxConnector::into_envelope_halves`] consumes the transport, so
	/// the connection pool reads peer identity here first and shares it
	/// with every lease. A transport without encryption material answers
	/// `None`, and identity-gating callers MUST fail closed on `None`.
	#[cfg(feature = "x509")]
	fn handshake_peer_certificate(&self) -> Option<Arc<Certificate>>;

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
pub trait MuxAcceptor: MuxCapable {
	/// Envelope read half after splitting.
	type EnvelopeReader: EnvelopeSource + MaybeSend + 'static;
	/// Envelope write half after splitting.
	type EnvelopeWriter: EnvelopeSink + MaybeSend + 'static;

	/// Drive the server-side handshake to completion and report the
	/// negotiated multiplexing settings. `Ok(None)` means the connection
	/// MUST be served single-flight.
	fn negotiate_mux(&mut self) -> impl Future<Output = TransportResult<Option<MuxSettings>>> + MaybeSend;

	/// Detach the server half of the in-band rekey wiring from a
	/// completed handshake. `Ok(None)` on sessions without a
	/// receipt-bearing epoch.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		Ok(None)
	}

	/// Authenticated peer context of the completed handshake,
	/// snapshotted before the transport splits. Empty by default.
	#[cfg(feature = "transport-policy")]
	fn session_context(&self) -> SessionContext {
		SessionContext::default()
	}

	/// Consume the transport into its collector gate plus envelope halves.
	/// Consuming means no placeholder gate ever sits inside a live
	/// collector: the gate moves to the mux responder, the transport
	/// ceases to exist.
	#[cfg(feature = "transport-policy")]
	fn into_gated_halves(self) -> TransportResult<GatedHalves<Self>>;

	/// Consume the transport into raw envelope halves for the mux
	/// drivers, without the policy plane.
	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)>;
}

/// Streaming extension of [`MultiplexedProtocol`]: chunked request
/// bodies and duplex replies over individual mux streams.
///
/// Segregated from the base trait so unary callers never see streaming
/// machinery, and because the concrete sink/body types live in the
/// router plane.
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
pub trait StreamingProtocol: MultiplexedProtocol {
	/// Open a streamed request: push chunks through the sink, then await
	/// the unary response. Dropping either side cancels the stream.
	fn open_stream(
		&self,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)>;

	/// Open a duplex stream: push request chunks through the sink while
	/// the peer's reply arrives incrementally through the body.
	fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)>;
}
