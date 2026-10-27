//! HTTP/2-style multiplexing: concurrent request/response streams over one
//! connection.
//!
//! A [`MuxTransport`] takes [`MuxSettings`] and the halves that
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
//!   liveness off the stream table and outside the peer's handler.
//! - [`MuxResponder`] serves peer-initiated streams with a caller-supplied
//!   handler, and enforces the advertised concurrency cap.
//!
//! # Streaming
//!
//! Streaming layers over the same connection:
//!
//! - [`MuxHandle::open_stream`] and [`MuxHandle::open_duplex`] push request chunks through a [`RequestSink`].
//! - Each call that opens a stream stamps its interaction kind on the stream's
//!   Open record ([`MuxStreamKind`]).
//! - [`MuxResponder::serve_with`] routes every peer stream to the [`MuxDispatch`] method of its kind.
//!
//! # Stream IDs
//!
//! Stream ID rules follow [RFC 9113 § 5.1.1][rfc9113-5.1.1] and
//! [RFC 9113 § 5.1.2][rfc9113-5.1.2]:
//!
//! - Odd IDs are client-initiated, and even IDs are server-initiated.
//! - ID 0 is reserved, and no endpoint allocates it.
//! - Each endpoint allocates strictly monotonically.
//!
//! Per-stream timeouts compose externally. Wrap the emit future in a timeout,
//! and the drop guard cancels the stream on expiry.
//!
//! [rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
//! [rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2
//! [`MuxStreamKind`]: crate::transport::envelopes::MuxStreamKind

#[cfg(any(feature = "tokio", feature = "async-transport"))]
mod router;
#[cfg(pooled_mux)]
mod service;

use core::future::Future;
use std::sync::Arc;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
use futures::future::ready;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub use router::{
	BufferedGrantor, MuxHandle, MuxReaderDriver, MuxResponder, MuxTransport, MuxWriterDriver, ReplySink, RequestSink,
	StreamBody,
};
#[cfg(feature = "tokio")]
pub use router::{MuxDrivers, SpawnedMux};
#[cfg(pooled_mux)]
pub use service::{CallContext, MuxService};

use crate::policy::GatePolicy;
use crate::policy::SessionContext;
use crate::transport::handshake::negotiation::{MuxSettings, TransportOffer};
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;
use crate::x509::Certificate;
use crate::Frame;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::constants::DEFAULT_HOP_BUDGET;
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::policy::TransitStatus;
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::transport::envelopes::ResponsePackage;
#[cfg(mux_rekey)]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(mux_rekey)]
use crate::transport::handshake::HandshakeProvider;
#[cfg(mux_rekey)]
use crate::transport::rekey::{RekeyDriver, Renewal};
#[cfg(mux_rekey)]
use crate::transport::state::{EncryptedProtocolState, Endpoint};
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::transport::TransportError;
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::urn::Urn;
#[cfg(pooled_mux)]
use service::GatedService;

/// Converts a caller-owned or already-shared mux offer into a shared handle.
///
/// Accept loops and pools store [`Arc<TransportOffer>`], so each connection
/// clones the `Arc` instead of a deep copy of the authorization octets.
pub trait IntoMuxOffer {
	/// Returns the shared offer for transport storage, or `None` to advertise
	/// nothing.
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
		// The clone shares one advertisement across accept and dial sites.
		Some(Arc::clone(self))
	}
}

impl IntoMuxOffer for Option<&Arc<TransportOffer>> {
	fn into_mux_offer(self) -> Option<Arc<TransportOffer>> {
		self.map(Arc::clone)
	}
}

/// The gRPC-style route that the Open record of a stream carries.
///
/// The route selects the responder's dispatch target and carries the relay
/// budget. The target is a servlet [`Urn`], which names the handler of a
/// stream as `:path` names the target of an HTTP request.
///
/// - Initiators stamp a route through [`MuxHandle::open_stream_to`] and
///   [`MuxHandle::open_duplex_to`], which name a servlet type URN as a unary
///   routed call names its target.
/// - A served handler reads the route it received through [`CallContext`].
#[cfg(any(feature = "tokio", feature = "async-transport"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRoute {
	target: Option<Urn<'static>>,
	hops_remaining: u8,
}

/// The default route is unrouted and carries the origin relay budget, so DER
/// omits both fields. An open stamped with it encodes the same as an unrouted
/// local open, so the routed and unrouted open paths share one wire shape.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl Default for StreamRoute {
	fn default() -> Self {
		Self { target: None, hops_remaining: DEFAULT_HOP_BUDGET }
	}
}

#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl StreamRoute {
	/// The route of an unrouted local stream, which the responder dispatches by
	/// its own resolved address. DER omits both route fields from the Open.
	pub(crate) fn local() -> Self {
		Self::default()
	}

	/// Builds a route to a servlet type with the origin sentinel budget, which
	/// defers the hop cap to the first gateway's `max_hops` policy.
	///
	/// A gateway reads the target to dispatch locally or splice to a peer. A
	/// caller that needs no raw [`StreamRoute`] should prefer one of these:
	///
	/// - [`PooledClient::open_stream_to`](crate::transport::PooledClient::open_stream_to)
	/// - [`PooledClient::open_duplex_to`](crate::transport::PooledClient::open_duplex_to)
	pub fn to(target: Urn<'static>) -> Self {
		Self { target: Some(target), hops_remaining: DEFAULT_HOP_BUDGET }
	}

	/// Builds a route to a servlet type with a given remaining relay budget.
	///
	/// A gateway stamps this route when it re-emits a client stream to a peer
	/// gateway with the budget decremented. An origin open uses [`Self::to`].
	#[cfg(feature = "colony")]
	pub fn relayed_to(target: Urn<'static>, hops_remaining: u8) -> Self {
		// The sentinel encodes an origin open. A relayed route must stay
		// below it so hop-budget accounting treats the open as already relayed.
		Self { target: Some(target), hops_remaining: hops_remaining.min(DEFAULT_HOP_BUDGET - 1) }
	}

	/// Reconstructs a route from the parts that a received Open carries.
	pub(crate) fn from_parts(target: Option<Urn<'static>>, hops_remaining: u8) -> Self {
		Self { target, hops_remaining }
	}

	/// Splits the route into the target and the relay budget stamped on the
	/// Open.
	pub(crate) fn into_parts(self) -> (Option<Urn<'static>>, u8) {
		(self.target, self.hops_remaining)
	}

	/// Returns the gRPC-style dispatch target, or `None` for an unrouted stream
	/// whose responder address is already resolved.
	pub fn target(&self) -> Option<&Urn<'static>> {
		self.target.as_ref()
	}

	/// Returns the relay budget left on this open: the gateway forwards the
	/// stream has left. A gateway serves a stream at `0` locally, so its relay
	/// ends there.
	pub fn hops_remaining(&self) -> u8 {
		self.hops_remaining
	}
}

/// The stream identifier within one multiplexed connection.
///
/// Odd IDs are client-initiated, even IDs are server-initiated, and ID 0 is
/// reserved ([RFC 9113 § 5.1.1][rfc9113-5.1.1]).
///
/// [rfc9113-5.1.1]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u32);

impl StreamId {
	/// Builds a stream ID from its wire-encoded value.
	pub const fn new(id: u32) -> Self {
		Self(id)
	}

	/// Returns the wire-encoded identifier for framing and role checks.
	pub const fn value(&self) -> u32 {
		self.0
	}

	/// Returns `true` when this ID is odd (client-allocated).
	pub const fn is_client_initiated(&self) -> bool {
		self.0 % 2 == 1
	}

	/// Returns `true` when this ID is even, which covers the server-allocated
	/// IDs and the reserved ID 0.
	pub const fn is_server_initiated(&self) -> bool {
		self.0.is_multiple_of(2)
	}
}

/// The state of a stream on a multiplexed transport.
///
/// Streams in `Open`, `HalfClosedLocal`, or `HalfClosedRemote` count toward
/// the peer-advertised concurrency cap, and `Idle` and `Closed` streams are
/// exempt from it ([RFC 9113 § 5.1.2][rfc9113-5.1.2]).
///
/// [rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
	/// The ID is unused.
	Idle,
	/// Both sides may send.
	Open,
	/// The local side has closed its send half.
	HalfClosedLocal,
	/// The remote side has closed its send half.
	HalfClosedRemote,
	/// The stream is fully closed.
	Closed,
}

/// The endpoint role on a multiplexed connection, which fixes the parity of
/// its stream IDs by the HTTP/2 convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRole {
	/// The handshake initiator, which allocates odd stream IDs.
	Client,
	/// The handshake responder, which allocates even stream IDs.
	Server,
}

#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl MuxRole {
	const fn first_local_stream_id(self) -> u32 {
		match self {
			MuxRole::Client => 1,
			MuxRole::Server => 2,
		}
	}

	/// Whether this role is the initiator of `stream_id`. Both roles answer
	/// `false` for the reserved ID 0.
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

	/// Whether this role holds its key-switch marker until the data chunks it
	/// owes under the old key quiesce. The client's `RekeyAck` trails every
	/// such chunk, and the server's `RekeyDone` writes at once.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	const fn holds_key_switch(self) -> bool {
		match self {
			MuxRole::Client => true,
			MuxRole::Server => false,
		}
	}

	/// Whether this role opens renewals and parks its admissions across each
	/// one. The client opens every exchange, and the server answers it.
	const fn opens_renewals(self) -> bool {
		match self {
			MuxRole::Client => true,
			MuxRole::Server => false,
		}
	}
}

#[cfg(mux_rekey)]
impl MuxRole {
	/// Returns what this role renews under on `endpoint`: the identity it
	/// presented in the handshake and the hooks of its half of the rekey
	/// exchange, or `None` when the endpoint holds no identity of this role.
	fn renewal<P: HandshakeProvider>(self, endpoint: &Endpoint<'_, P>) -> Option<Renewal<P>> {
		match self {
			MuxRole::Client => endpoint.client_renewal(),
			MuxRole::Server => endpoint.server_renewal(),
		}
	}
}

/// A protocol that runs concurrent request/response streams over one
/// connection.
///
/// It lets a caller stay generic over the handle type, under the cap and
/// cancel contracts of [`MuxHandle`]. The one cancel surface is a drop of the
/// emit future.
pub trait MultiplexedProtocol {
	/// Returns the peer-advertised cap on concurrent locally-initiated streams
	/// (HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS`).
	fn max_concurrent_streams(&self) -> u32;

	/// Opens a stream, sends `frame`, and awaits the correlated response.
	///
	/// A drop of the future before it resolves cancels the stream and frees
	/// its concurrency slot.
	fn emit_on_stream(&self, frame: &Frame) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend;
}

/// The mux capability advertisement, which the handshake binds into its
/// transcript.
///
/// Only a transport that can attach the mux plane after negotiation implements
/// this trait. The plane takes split envelope halves and spawned drivers, so
/// an advertisement from any other transport would negotiate a capability the
/// endpoint cannot honor.
pub trait MuxCapable: Sized {
	/// Sets the local mux advertisement, where `None` advertises nothing.
	///
	/// A caller that holds a shared offer passes `Some(Arc::clone(&offer))`.
	/// An owned offer converts at the boundary through [`IntoMuxOffer`] on the
	/// inherent transport methods.
	fn with_mux_offer(self, offer: Option<Arc<TransportOffer>>) -> Self;

	/// Returns the negotiated multiplexing settings of a completed handshake.
	/// `None` means the connection is single-flight.
	fn negotiated_mux(&self) -> Option<MuxSettings>;
}

/// The in-band rekey context of a completed receipt-bearing handshake.
///
/// With an async runtime, it holds the role-fixed exchange half and the epoch-0
/// dual-signed receipt that the exchange rotates. An unmetered session carries
/// no receipt, so it has no context and keeps the GoAway drain. The type is
/// opaque, so the transport builds it, and [`MuxTransport::with_rekey`]
/// assembles a mux transport in the role of its half.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct MuxRekeyContext {
	#[cfg(mux_rekey)]
	pub(crate) driver: RekeyDriver,
	#[cfg(mux_rekey)]
	pub(crate) receipt: Arc<StoredReceipt>,
	/// Makes the type uninhabited in a build without an async runtime,
	/// because a rekey runs only in a mux driver and a mux driver runs only on
	/// that runtime.
	#[cfg(not(mux_rekey))]
	_unbuilt: core::convert::Infallible,
}

#[cfg(mux_rekey)]
impl MuxRekeyContext {
	/// Harvests the in-band rekey context from a completed receipt-bearing
	/// handshake.
	///
	/// [`MuxTransport::with_rekey`] consumes the result. The constructor is
	/// crate-internal, so the transport's [`MuxConnector::take_rekey`] or
	/// [`MuxAcceptor::take_rekey`] always fixes the endpoint role.
	///
	/// # Returns
	///
	/// - `Ok(Some(..))` at most once per handshake, because the call detaches the retained epoch materials.
	/// - `Ok(None)` when no handshake completed, when the endpoint holds no
	///   signing identity for its role, or when the session carries no
	///   dual-signed receipt, no retained peer identity, or no epoch materials.
	///
	/// # Errors
	///
	/// - [`TransportError::HandshakeError`] -- the signing use or the purpose
	///   of the peer's role refuses the peer's certificate.
	///
	/// [`TransportError::HandshakeError`]: crate::transport::error::TransportError::HandshakeError
	/// [`MuxTransport::with_rekey`]: crate::transport::multiplex::MuxTransport::with_rekey
	/// [`MuxConnector::take_rekey`]: crate::transport::multiplex::MuxConnector::take_rekey
	/// [`MuxAcceptor::take_rekey`]: crate::transport::multiplex::MuxAcceptor::take_rekey
	pub(crate) fn detach<T, P>(state: &mut T, role: MuxRole) -> TransportResult<Option<Self>>
	where
		T: EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		// Each role renews under the identity it presented in the handshake,
		// against a peer of the other role.
		let renewed = state.session_state_mut().renew(|endpoint| role.renewal(endpoint))?;
		Ok(renewed.map(|(driver, receipt)| Self { driver, receipt }))
	}
}

// The mux role is a type of this module, so the role of a rekey half sits
// here and `multiplex` alone depends on `rekey`.
#[cfg(mux_rekey)]
impl RekeyDriver {
	/// Returns the mux role of this half, which is also the role of the
	/// transport that assembles with it.
	const fn role(&self) -> MuxRole {
		match self {
			RekeyDriver::Client(_) => MuxRole::Client,
			RekeyDriver::Server(_) => MuxRole::Server,
		}
	}
}

/// The mux role of every [`MuxConnector`], the handshake initiator. Its rekey
/// detaches for this role, and its transport assembles in it.
#[cfg(mux_rekey)]
pub(crate) const CONNECTOR_ROLE: MuxRole = MuxRole::Client;

/// The mux role of every [`MuxAcceptor`], the handshake responder. Its rekey
/// detaches for this role, and its transport assembles in it.
#[cfg(mux_rekey)]
pub(crate) const ACCEPTOR_ROLE: MuxRole = MuxRole::Server;

/// The client-side setup of a mux connection.
///
/// The trait abstracts the concrete transport, so the connection pool stays
/// generic over [`Protocol`](crate::transport::Protocol).
pub trait MuxConnector: MuxCapable {
	/// The envelope read half that the split yields.
	type EnvelopeReader: EnvelopeSource + MaybeSend + 'static;
	/// The envelope write half that the split yields.
	type EnvelopeWriter: EnvelopeSink + MaybeSend + 'static;

	/// Drives the client handshake to completion.
	///
	/// On a transport without encryption material, the call returns `Ok(())`
	/// at once, and [`MuxCapable::negotiated_mux`] stays `None`.
	fn complete_client_handshake(&mut self) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Detaches the client half of the in-band rekey context from a completed
	/// handshake. The result is `Ok(None)` for a session without a
	/// receipt-bearing epoch.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		Ok(None)
	}

	/// Returns the validated peer certificate that a completed client
	/// handshake pinned.
	///
	/// [`MuxConnector::into_envelope_halves`] consumes the transport, so
	/// the connection pool reads peer identity here first and shares it
	/// with every lease. A transport without encryption material answers
	/// `None`, and a caller that gates on identity MUST fail closed on `None`.
	fn handshake_peer_certificate(&self) -> Option<Arc<Certificate>>;

	/// Splits the transport into envelope halves for the mux drivers.
	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)>;
}

/// The collector gate and the envelope halves of a consumed [`MuxAcceptor`].
pub type GatedHalves<T> = (
	Box<dyn GatePolicy>,
	(<T as MuxAcceptor>::EnvelopeReader, <T as MuxAcceptor>::EnvelopeWriter),
);

/// The server-side counterpart of [`MuxConnector`], which negotiates
/// multiplexing during the accept and then hands the connection to the mux
/// plane.
pub trait MuxAcceptor: MuxCapable {
	/// The envelope read half that the split yields.
	type EnvelopeReader: EnvelopeSource + MaybeSend + 'static;
	/// The envelope write half that the split yields.
	type EnvelopeWriter: EnvelopeSink + MaybeSend + 'static;

	/// Drives the server-side handshake to completion and reports the
	/// negotiated multiplexing settings. `Ok(None)` means the caller MUST
	/// serve the connection single-flight.
	fn negotiate_mux(&mut self) -> impl Future<Output = TransportResult<Option<MuxSettings>>> + MaybeSend;

	/// Detaches the server half of the in-band rekey context from a completed
	/// handshake. The result is `Ok(None)` for a session without a
	/// receipt-bearing epoch.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		Ok(None)
	}

	/// Returns the authenticated peer context of the completed handshake, which
	/// the transport snapshots before it splits. The default is empty.
	fn session_context(&self) -> SessionContext {
		SessionContext::default()
	}

	/// Consumes the transport into its collector gate and its envelope halves.
	///
	/// The gate moves to the mux responder and the transport ceases to exist,
	/// so a live collector always holds its real gate.
	fn into_gated_halves(self) -> TransportResult<GatedHalves<Self>>;

	/// Consumes the transport into its raw envelope halves alone, for the mux
	/// drivers.
	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)>;

	/// Serves a mux-negotiated connection until it ends.
	///
	/// The call consumes the transport into gated halves, spawns both drivers,
	/// and runs the responder with `service` routed by each stream's kind:
	///
	/// - Unary frames pass the transport's collector gate before they reach [`MuxService::unary`].
	/// - Streaming and duplex streams evaluate the same gate with no request frame (`None`) first.
	/// - A handler that fails with an error of its own closes its stream with
	///   the failure's mapped status, which the trail records as
	///   `HANDLER_FAILED`.
	/// - A [`MuxService`] default refuses its kind, which answers
	///   `Unimplemented` and the trail records as `MUX_STREAM_REFUSED`.
	/// - A fault the trace injects at the verdict of the gate, or at the entry
	///   of a handler, closes its stream as `Internal`.
	///
	/// The drivers live as long as the call, so a call that its owner drops
	/// ends the connection at once. A call that ends closes the writer behind
	/// the envelopes the responder queued, a GoAway among them.
	///
	/// # Arguments
	///
	/// - `cancel_budget` overrides the CVE-2023-44487 cancel-abuse default when it is set.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the session is provisioned for
	///   encryption and its handshake has not completed, so
	///   [`MuxAcceptor::into_gated_halves`] cannot split the transport.
	/// - [`TransportError::HandshakeError`] -- the signing use or the purpose
	///   of the peer's role refuses the peer's certificate, so
	///   [`MuxAcceptor::take_rekey`] cannot detach the rekey context.
	/// - [`TransportError`] -- the terminal responder failures of [`MuxResponder::serve_with`].
	///
	/// # Examples
	///
	/// ```no_run
	/// use tightbeam::transport::multiplex::{MuxAcceptor, MuxService};
	/// use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
	/// use tightbeam::transport::TransportResult;
	///
	/// /// Refuses every interaction through the defaults of the trait.
	/// struct Closed;
	///
	/// impl MuxService for Closed {}
	///
	/// /// Serve one accepted connection under the multiplexing it negotiated.
	/// async fn serve(mut transport: TcpTransport<TokioStream>) -> TransportResult<()> {
	///     let Some(settings) = transport.negotiate_mux().await? else {
	///         return Ok(());
	///     };
	///
	///     transport.serve(settings, Closed, None).await
	/// }
	/// ```
	///
	/// [`TransportError`]: crate::transport::error::TransportError
	/// [`TransportError::InvalidState`]: crate::transport::error::TransportError::InvalidState
	/// [`TransportError::HandshakeError`]: crate::transport::error::TransportError::HandshakeError
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
			let mux = MuxTransport::assemble(reader, writer, ACCEPTOR_ROLE, settings, rekey);
			let SpawnedMux { handle, responder, drivers } = mux.spawn_with(cancel_budget);
			let closer = handle.clone();

			let served = responder.serve_with(GatedService::new(service, gate, snapshot, handle)).await;
			closer.close().await;
			drivers.finish().await;
			served
		}
	}
}

/// The streaming extension of [`MultiplexedProtocol`], which adds chunked
/// request bodies and duplex replies over individual mux streams.
///
/// It is a separate trait because the sink and body types live in the router
/// plane, and so a unary caller needs the base trait alone.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait StreamingProtocol: MultiplexedProtocol {
	/// Opens a streamed request. The caller pushes chunks through the sink and
	/// then awaits the unary response. A drop of either side cancels the
	/// stream.
	fn open_stream(
		&self,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)>;

	/// Opens a duplex stream. The caller pushes request chunks through the sink
	/// while the peer's reply arrives incrementally through the body.
	fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)>;
}

/// The receiver-side stream credit policy, which decides when to raise a
/// stream's absolute cumulative chunk limit (QUIC MAX_STREAM_DATA,
/// [RFC 9000 § 4.1][rfc9000-4.1]).
///
/// The receiver's granted limit bounds per-stream reassembly memory
/// at `limit * chunk size`. A receiver that withholds grants applies
/// backpressure to the sender, which parks until the limit rises.
///
/// # Batching
///
/// Every grant travels as one `MuxCredit` envelope, a control-plane AEAD record
/// outside the session budget. Implementations SHOULD batch grants, because a
/// grant per chunk makes a long transfer spend the cipher's record limit on
/// control traffic.
///
/// [rfc9000-4.1]: https://datatracker.ietf.org/doc/html/rfc9000#section-4.1
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait CreditGrantor: Send + Sync {
	/// Returns the new absolute chunk limit for a stream that has accepted
	/// `received` chunks under `limit`, or `None` to leave the limit
	/// unchanged. The reader discards a value at or below `limit`.
	fn replenish(&self, stream_id: StreamId, received: u64, limit: u64) -> Option<u64>;
}

/// The kind-routed handler set for the peer streams of one connection.
///
/// The initiator stamps the kind of each stream on its Open record
/// ([`MuxStreamKind`]), and the responder routes the stream to the method here
/// that matches the kind.
///
/// # A refused kind
///
/// Every default fails with [`TransportError::NotServed`], so a kind outside
/// the dispatch refuses its own stream and the connection continues to serve.
/// The responder answers the stream [`TransitStatus::Unimplemented`] and
/// records the refusal as `MUX_STREAM_REFUSED`. A method that returns
/// `NotServed` of its own refuses its kind in the same way.
///
/// # A failed stream
///
/// Each method answers its own stream, and any other `Err` refuses that
/// stream alone. The responder answers it with the status of the error,
/// records `MUX_INTERNAL_ERROR`, and continues to serve the other streams of
/// the connection:
///
/// - [`TransportError::OperationFailed`] keeps the status its failure
///   carries, apart from `Unavailable`, which reads `Unknown`.
/// - Any other error reads [`TransitStatus::Internal`].
///
/// A method that answers a refusal with a status of its own returns it in
/// `Ok`.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::policy::TransitStatus;
/// use tightbeam::transport::multiplex::{MuxDispatch, StreamBody, StreamRoute};
/// use tightbeam::transport::{ResponsePackage, TransportError, TransportFailure, TransportResult};
/// use tightbeam::Frame;
///
/// /// Echoes each unary frame and each streamed frame, and refuses duplex
/// /// streams by the default.
/// struct Echo;
///
/// impl MuxDispatch for Echo {
///     async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
///         Ok(ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame))))
///     }
///
///     /// A body past the reassembly ceiling is the peer's to shrink, so it
///     /// reads `ResourceExhausted`. Any other failure refuses the stream
///     /// with the status of its error.
///     async fn streaming(&self, body: StreamBody, _route: StreamRoute) -> TransportResult<ResponsePackage> {
///         match body.into_frame().await {
///             Ok(frame) => Ok(ResponsePackage::new(TransitStatus::Ok, Some(frame))),
///             Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)) => {
///                 Ok(ResponsePackage::new(TransitStatus::ResourceExhausted, None))
///             }
///             Err(other) => Err(other),
///         }
///     }
/// }
/// ```
///
/// [`MuxStreamKind`]: crate::transport::envelopes::MuxStreamKind
/// [`TransportError::NotServed`]: crate::transport::error::TransportError::NotServed
/// [`TransportError::OperationFailed`]: crate::transport::error::TransportError::OperationFailed
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait MuxDispatch {
	/// Answers one unary request with its terminal response.
	///
	/// # Errors
	///
	/// - Any error, which refuses this stream alone with the status the trait doc names.
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		// The default refuses the kind, so the frame goes unread.
		let _ = frame;
		ready(Err(TransportError::NotServed))
	}

	/// Consumes a streamed request body and answers with the terminal response.
	///
	/// Each chunk the handler consumes replenishes the peer's stream credit, so
	/// a slow handler parks the sender with end-to-end backpressure. `route`
	/// carries the gRPC-style dispatch target that the initiator stamped on
	/// the Open.
	///
	/// # Errors
	///
	/// - Any error, which refuses this stream alone with the status the trait doc names.
	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		// The default refuses the kind, so the body and route go unread.
		let _ = (body, route);
		ready(Err(TransportError::NotServed))
	}

	/// Consumes request chunks and pushes reply chunks at the same time, in
	/// full duplex on one stream.
	///
	/// The returned status closes the stream as its `End` trailer. `route`
	/// carries the gRPC-style dispatch target that the initiator stamped on
	/// the Open.
	///
	/// # Errors
	///
	/// - Any error, which closes this stream alone with the status the trait doc names.
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		// The default refuses the kind, so body, reply, and route go unread.
		let _ = (body, reply, route);
		ready(Err(TransportError::NotServed))
	}
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
