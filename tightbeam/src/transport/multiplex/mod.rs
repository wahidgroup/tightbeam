//! HTTP/2-style multiplexing, which runs concurrent request/response streams
//! over a single connection.
//!
//! A [`MuxTransport`] is built from [`MuxSettings`] and from the halves that
//! [`TcpTransport::into_split`](crate::transport::TcpTransport::into_split)
//! yields. An encrypted session negotiates the settings. A transport named
//! cleartext takes them out of band, and it has NO confidentiality, integrity,
//! replay, or deletion protection.
//!
//! # Parts
//!
//! - [`MuxWriterDriver`] is the single serialization point. It drains an
//!   outbound queue and writes each envelope through the send half.
//! - [`MuxReaderDriver`] reads envelopes off the read half, and routes
//!   responses to their pending streams and requests to the responder.
//! - [`MuxHandle`] is the cloneable client handle.
//!   [`MuxHandle::emit_on_stream`] allocates a stream, sends the request, and
//!   awaits the correlated response. [`MuxHandle::ping`] probes connection
//!   liveness without touching a stream or the peer's handler.
//! - [`MuxResponder`] serves peer-initiated streams with a caller-supplied
//!   handler, and enforces the advertised concurrency cap.
//!
//! # Streaming
//!
//! Streaming layers over the same connection:
//!
//! - [`MuxHandle::open_stream`] and [`MuxHandle::open_duplex`] push request chunks through a [`RequestSink`].
//! - Each initiating call stamps its interaction kind on the stream's Open
//!   record ([`MuxStreamKind`](crate::transport::envelopes::MuxStreamKind)).
//! - [`MuxResponder::serve_with`] routes every peer stream to the matching [`MuxDispatch`] method.
//!
//! # Stream IDs
//!
//! Stream ID rules follow [RFC 9113 § 5.1.1][rfc9113-5.1.1] and
//! [RFC 9113 § 5.1.2][rfc9113-5.1.2]:
//!
//! - Odd IDs are client-initiated, and even IDs are server-initiated.
//! - ID 0 is reserved and never allocated.
//! - Each endpoint allocates strictly monotonically.
//!
//! Per-stream timeouts compose externally. Wrap the emit future in a timeout,
//! and the drop guard cancels the stream on expiry.
//!
//! [rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
//! [rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
mod router;
#[cfg(pooled_mux)]
mod service;

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
use crate::transport::handshake::receipt::{ReceiptSigner, StoredReceipt};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::{HandshakeProvider, HandshakeVerifyingKey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::rekey::{ClientRekey, RekeyDriver, RekeyMaterials, ServerRekey};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::state::EncryptedProtocolState;
#[cfg(pooled_mux)]
use service::GatedService;

#[cfg(all(feature = "x509", feature = "tokio"))]
pub use router::SpawnedMux;
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
pub use router::{
	BufferedGrantor, CreditGrantor, MuxDispatch, MuxHandle, MuxReaderDriver, MuxResponder, MuxTransport,
	MuxWriterDriver, ReplySink, RequestSink, StreamBody,
};
#[cfg(pooled_mux)]
pub use service::{CallContext, MuxService};

/// Grpc-style route carried on a stream's Open record.
///
/// The route selects the responder's dispatch target and carries the relay
/// budget. The target is a servlet [`Urn`], which serves a stream as `:path`
/// serves an HTTP request.
///
/// - Initiators stamp a route through the typed `open_stream_to` and
///   `open_duplex_to` entry points, which name a servlet type URN the same way
///   a unary routed call names its target.
/// - A served handler reads the route it received through [`CallContext`].
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRoute {
	target: Option<Urn<'static>>,
	hops_remaining: u8,
}

/// The default route is unrouted and carries the origin relay budget, so DER
/// omits both fields. An open stamped with it encodes the same as an unrouted
/// local open, so the routed and unrouted open paths share one wire shape.
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
impl Default for StreamRoute {
	fn default() -> Self {
		Self { target: None, hops_remaining: DEFAULT_HOP_BUDGET }
	}
}

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
impl StreamRoute {
	/// The route of an unrouted local stream, which the responder dispatches by
	/// its own resolved address. DER omits both route fields from the Open.
	pub(crate) fn local() -> Self {
		Self::default()
	}

	/// Route to a servlet type with the origin sentinel budget, which defers
	/// the hop cap to the first gateway's `max_hops` policy.
	///
	/// A gateway reads the target to dispatch locally or splice to a peer. A
	/// caller that needs no raw [`StreamRoute`] should prefer one of these:
	///
	/// - [`PooledClient::open_stream_to`](crate::transport::PooledClient::open_stream_to)
	/// - [`PooledClient::open_duplex_to`](crate::transport::PooledClient::open_duplex_to)
	pub fn to(target: Urn<'static>) -> Self {
		Self { target: Some(target), hops_remaining: DEFAULT_HOP_BUDGET }
	}

	/// Route to a servlet type with an explicit remaining relay budget.
	///
	/// A gateway stamps this route when it re-emits a client stream to a peer
	/// gateway with the budget decremented. A `0` budget is served locally and
	/// never re-forwarded. An origin open uses [`Self::to`].
	#[cfg(feature = "colony")]
	pub fn relayed_to(target: Urn<'static>, hops_remaining: u8) -> Self {
		// The sentinel encodes an origin open. A relayed route must stay
		// below it so hop-budget accounting treats the open as already relayed.
		Self { target: Some(target), hops_remaining: hops_remaining.min(DEFAULT_HOP_BUDGET - 1) }
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

	/// Relay budget left on this open, which is the number of gateway forwards
	/// the stream may still spend. A `0` stream is served locally and never
	/// re-forwarded.
	pub fn hops_remaining(&self) -> u8 {
		self.hops_remaining
	}
}

/// Stream identifier within one multiplexed connection.
///
/// Odd IDs are client-initiated, even IDs are server-initiated, and ID 0 is
/// reserved ([RFC 9113 § 5.1.1][rfc9113-5.1.1]).
///
/// [rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
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

/// Stream state for multiplexed transports.
///
/// Streams in `Open`, `HalfClosedLocal`, or `HalfClosedRemote` count toward
/// the peer-advertised concurrency cap, and `Idle` and `Closed` streams do not
/// ([RFC 9113 § 5.1.2][rfc9113-5.1.2]).
///
/// [rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
	/// The id is unused and does not count toward the concurrency cap.
	Idle,
	/// Both sides may send. The stream counts toward the concurrency cap.
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

/// Endpoint role on a multiplexed connection, which fixes whether its stream
/// IDs are odd or even. A client allocates odd IDs and a server allocates even
/// IDs, by the HTTP/2 convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRole {
	/// The handshake initiator, which allocates odd stream IDs.
	Client,
	/// The handshake responder, which allocates even stream IDs.
	Server,
}

#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
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
/// Cap and cancel contracts match [`MuxHandle`]. This trait exists so the pool
/// and other callers stay generic over the concrete handle type. Cancellation
/// is by drop. Abandoning the emit future cancels its stream, and that drop is
/// the only cancel surface.
pub trait MultiplexedProtocol {
	/// Peer-advertised cap on concurrent locally-initiated streams
	/// (HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`).
	fn max_concurrent_streams(&self) -> u32;

	/// Open a stream, send `frame`, and await the correlated response.
	///
	/// Dropping the future before it resolves cancels the stream and frees
	/// its concurrency slot.
	fn emit_on_stream(&self, frame: &Frame) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend;
}

/// Mux capability advertisement, bound into the handshake transcript.
///
/// Only a transport that can attach the mux plane after negotiation implements
/// this trait. The plane takes split envelope halves and spawned drivers, so
/// an advertisement from any other transport would negotiate a capability the
/// endpoint cannot honor.
pub trait MuxCapable: Sized {
	/// Set the local mux advertisement, where `None` advertises nothing.
	///
	/// A caller that already holds a shared offer passes
	/// `Some(Arc::clone(&offer))`. An owned offer converts at the boundary
	/// through [`IntoMuxOffer`] on the inherent transport helpers.
	fn with_mux_offer(self, offer: Option<Arc<TransportOffer>>) -> Self;

	/// Negotiated multiplexing settings from a completed handshake.
	/// `None` means the connection is single-flight.
	fn negotiated_mux(&self) -> Option<MuxSettings>;
}

/// In-band rekey context taken from a completed receipt-bearing handshake.
///
/// It holds the role-fixed exchange half and the epoch-0 dual-signed receipt
/// that the exchange rotates. An unmetered session carries no receipt, so it
/// has no context and keeps the GoAway drain. The type is opaque, so the
/// transport builds it and [`MuxTransport::with_rekey`] consumes it.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub struct MuxRekeyContext {
	pub(crate) driver: RekeyDriver,
	pub(crate) receipt: StoredReceipt,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl MuxRekeyContext {
	/// Harvest the in-band rekey context from a completed receipt-bearing
	/// handshake.
	///
	/// [`MuxTransport::with_rekey`] consumes the result. The constructor is
	/// crate-internal, so the transport's [`MuxConnector::take_rekey`] or
	/// [`MuxAcceptor::take_rekey`] always fixes the endpoint role.
	///
	/// # Returns
	///
	/// - `Ok(Some(..))` at most once per handshake, because the call detaches the retained epoch materials.
	/// - `Ok(None)` when no handshake completed, when the endpoint has no key
	///   manager, or when the session carries no dual-signed receipt, no
	///   retained peer identity, or no epoch materials.
	///
	/// # Errors
	///
	/// - [`TransportError::HandshakeError`] -- the peer key or the signer identifier fails to extract.
	///
	/// [`TransportError::HandshakeError`]: crate::transport::error::TransportError::HandshakeError
	/// [`MuxTransport::with_rekey`]: crate::transport::multiplex::MuxTransport::with_rekey
	/// [`MuxConnector::take_rekey`]: crate::transport::multiplex::MuxConnector::take_rekey
	/// [`MuxAcceptor::take_rekey`]: crate::transport::multiplex::MuxAcceptor::take_rekey
	#[cfg(feature = "x509")]
	pub(crate) fn detach<T, P>(state: &mut T, role: MuxRole) -> TransportResult<Option<Self>>
	where
		T: EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let Some(stored) = state.session_state().receipt().cloned() else {
			return Ok(None);
		};
		let Some(provider) = state
			.encryption()
			.key_manager
			.as_ref()
			.map(|manager| manager.signing_provider())
		else {
			return Ok(None);
		};

		let Some(peer_certificate) = state.session_state().peer_certificate_arc() else {
			return Ok(None);
		};

		let peer_static = peer_certificate.verifying_key::<P::Curve>()?;
		let peer_sid = peer_certificate.signer_identifier::<P::Digest>()?;

		// The materials detach last, so a session refused above keeps them.
		let Some(epoch) = state.session_state_mut().take_epoch_materials() else {
			return Ok(None);
		};

		let reference_receipt = stored.receipt().clone();
		let materials = RekeyMaterials::<P>::new(epoch, reference_receipt, provider, peer_static, peer_sid);

		let driver = match role {
			MuxRole::Client => {
				let approver = state.encryption().receipt_approver.as_ref().map(Arc::clone);
				let exchange = ClientRekey::new(materials, approver);
				RekeyDriver::client(exchange)
			}
			MuxRole::Server => {
				let exchange = ServerRekey::new(
					materials,
					state.encryption().transport_authorizer.as_ref().map(Arc::clone),
					state.encryption().session_observer.as_ref().map(Arc::clone),
					Some(peer_certificate),
				);
				RekeyDriver::server(exchange)
			}
		};

		Ok(Some(Self { driver, receipt: stored }))
	}
}

/// Client-side mux connection setup.
///
/// The trait abstracts the concrete transport, so the connection pool stays
/// generic over [`Protocol`](crate::transport::Protocol).
pub trait MuxConnector: MuxCapable {
	/// Envelope read half after splitting.
	type EnvelopeReader: EnvelopeSource + MaybeSend + 'static;
	/// Envelope write half after splitting.
	type EnvelopeWriter: EnvelopeSink + MaybeSend + 'static;

	/// Drive the client handshake to completion.
	///
	/// The call does nothing on a transport without encryption material, which
	/// then never negotiates mux.
	fn complete_client_handshake(&mut self) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Detach the client half of the in-band rekey context from a completed
	/// handshake. The result is `Ok(None)` for a session without a
	/// receipt-bearing epoch.
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

/// Server-side counterpart of [`MuxConnector`], which negotiates multiplexing
/// while accepting and then hands the connection to the mux plane.
pub trait MuxAcceptor: MuxCapable {
	/// Envelope read half after splitting.
	type EnvelopeReader: EnvelopeSource + MaybeSend + 'static;
	/// Envelope write half after splitting.
	type EnvelopeWriter: EnvelopeSink + MaybeSend + 'static;

	/// Drive the server-side handshake to completion and report the
	/// negotiated multiplexing settings. `Ok(None)` means the connection
	/// MUST be served single-flight.
	fn negotiate_mux(&mut self) -> impl Future<Output = TransportResult<Option<MuxSettings>>> + MaybeSend;

	/// Detach the server half of the in-band rekey context from a completed
	/// handshake. The result is `Ok(None)` for a session without a
	/// receipt-bearing epoch.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		Ok(None)
	}

	/// Authenticated peer context of the completed handshake, snapshotted
	/// before the transport splits. The default is empty.
	#[cfg(feature = "transport-policy")]
	fn session_context(&self) -> SessionContext {
		SessionContext::default()
	}

	/// Consume the transport into its collector gate plus envelope halves.
	///
	/// The gate moves to the mux responder and the transport ceases to exist,
	/// so a live collector holds its real gate and never a placeholder.
	#[cfg(feature = "transport-policy")]
	fn into_gated_halves(self) -> TransportResult<GatedHalves<Self>>;

	/// Consume the transport into its raw envelope halves alone, for the mux
	/// drivers.
	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)>;

	/// Serve a mux-negotiated connection until it ends.
	///
	/// The call consumes the transport into gated halves, spawns both drivers,
	/// and runs the responder with `service` routed by each stream's kind:
	///
	/// - Unary frames pass the transport's collector gate before reaching [`MuxService::unary`].
	/// - Streaming and duplex streams evaluate the same gate with no request frame (`None`) first.
	/// - Service failures close their stream with the failure's mapped status.
	///
	/// # Arguments
	///
	/// - `cancel_budget` overrides the CVE-2023-44487 cancel-abuse default when it is set.
	///
	/// # Errors
	///
	/// - `InvalidState` or `OperationFailed(EncryptorUnavailable)` -- no handshake completed.
	/// - The terminal responder failures of [`MuxResponder::serve_with`].
	#[cfg(pooled_mux)]
	fn serve<S: MuxService>(
		mut self,
		settings: MuxSettings,
		service: S,
		cancel_budget: Option<u32>,
	) -> impl Future<Output = TransportResult<()>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			let rekey = self.take_rekey()?;
			let snapshot = self.session_context();
			let (gate, (reader, writer)) = self.into_gated_halves()?;
			let mux = MuxTransport::new(reader, writer, MuxRole::Server, settings);
			let SpawnedMux { handle, responder, reader_task: _reader_task } = mux.spawn_with(cancel_budget, rekey);

			responder.serve_with(GatedService::new(service, gate, snapshot, handle)).await
		}
	}
}

/// Streaming extension of [`MultiplexedProtocol`], which adds chunked request
/// bodies and duplex replies over individual mux streams.
///
/// The extension is a separate trait because the concrete sink and body types
/// live in the router plane, and so that a unary caller depends on the base
/// trait alone.
#[cfg(all(feature = "x509", any(feature = "tokio", feature = "async-transport")))]
pub trait StreamingProtocol: MultiplexedProtocol {
	/// Open a streamed request. The caller pushes chunks through the sink and
	/// then awaits the unary response. Dropping either side cancels the stream.
	fn open_stream(
		&self,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)>;

	/// Open a duplex stream. The caller pushes request chunks through the sink
	/// while the peer's reply arrives incrementally through the body.
	fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)>;
}

#[cfg(all(test, feature = "colony"))]
mod tests {
	use super::*;

	#[test]
	fn relayed_to_sentinel_clamps_to_relayed_route() {
		let sentinel = StreamRoute::relayed_to(crate::urn!("fuzz", "servlet:test/ping"), DEFAULT_HOP_BUDGET);
		assert_eq!(sentinel.hops_remaining(), DEFAULT_HOP_BUDGET - 1);

		let below = StreamRoute::relayed_to(crate::urn!("fuzz", "servlet:test/ping"), 1);
		assert_eq!(below.hops_remaining(), 1);
	}
}
