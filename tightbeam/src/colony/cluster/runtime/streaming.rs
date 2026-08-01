//! Streaming and duplex splice: route a client stream by its target
//! `Urn` to a local servlet or a peer gateway, then relay the bodies
//! and reply.
//!
//! The gateway is a `MuxService`: a streamed or duplex open carries a
//! grpc-style route the same way unary work carries `servlet_type`.
//! Selection reuses [`select_route`], so streaming and unary share one
//! pheromone-weighted routing decision. A `Local` route dials the
//! servlet on the hive plane; a `Peer` route re-emits the stream to the
//! peer gateway on the peer plane with [`StreamRoute::forwarded_to`],
//! so the peer serves it locally and never re-forwards (one-hop guard).

use core::hash::Hash;
use core::str::{self, FromStr};
use std::sync::Arc;

use futures::future::try_join;

use crate::colony::cluster::runtime::bounds::{ClusterPool, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::work::{select_route, work_trail_ok, work_trail_weaken, RouteChoice};
use crate::colony::cluster::RouteKind;
use crate::colony::common::{canonical_bytes, is_bare_servlet_type};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::instrumentation::events::CLUSTER_WORK_FORWARDED;
use crate::policy::TransitStatus;
use crate::transport::error::TransportError;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxConnector, ReplySink, RequestSink, StreamBody, StreamRoute};
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{
	EncryptedProtocol, PersistentConnection, PooledClient, Protocol, TransportResult, X509ClientConfig,
};
use crate::utils::urn::Urn;
use crate::{Frame, TightBeamError};

/// The dialing plan a splice follows once a route is chosen: which
/// pool and socket to open on, the route to stamp on that open, and
/// the pheromone key to reinforce or weaken by the outcome.
struct SplicePlan<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	dial_addr: Arc<[u8]>,
	route: StreamRoute,
	route_key: Arc<[u8]>,
	is_peer: bool,
}

/// Refuse a stream with a terminal transit status. The mux responder
/// maps the failure onto the stream's `End` trailer.
fn refuse(status: TransitStatus) -> TightBeamError {
	TransportError::from(status).into()
}

/// Choose a route for `target` and turn it into a dialing plan.
///
/// Refuses a non-bare or foreign-realm target with `PermissionDenied`
/// and an unroutable target (no live trail, or a peer target with no
/// peer plane configured) with `Unavailable`, before any dial.
fn plan_splice<P: Protocol>(
	target: &Urn<'static>,
	forwarded: bool,
	ctx: &GatewayRuntimeCtx<P>,
) -> Result<SplicePlan<P>, TransitStatus> {
	if !is_bare_servlet_type(&ctx.config.namespace, target) {
		return Err(TransitStatus::PermissionDenied);
	}

	let type_key = canonical_bytes(target);
	let RouteChoice { route_key, dial_addr, route_kind } =
		select_route(&ctx.servlet_registry, &ctx.config, &type_key, forwarded).ok_or(TransitStatus::Unavailable)?;

	match route_kind {
		RouteKind::Local => Ok(SplicePlan {
			pool: Arc::clone(&ctx.pool),
			dial_addr,
			route: StreamRoute::local(),
			route_key,
			is_peer: false,
		}),
		RouteKind::Peer => {
			let peer_pool = ctx.peer_pool.as_ref().ok_or(TransitStatus::Unavailable)?;
			Ok(SplicePlan {
				pool: Arc::clone(peer_pool),
				dial_addr,
				route: StreamRoute::forwarded_to(target.clone()),
				route_key,
				is_peer: true,
			})
		}
	}
}

/// Feed every chunk of `body` into `sink`, then close the sink so its
/// stream ends. Consuming each chunk replenishes the peer's credit,
/// so a slow downstream parks the upstream (end-to-end backpressure).
async fn drain_into(mut body: StreamBody, mut sink: RequestSink) -> TransportResult<()> {
	while let Some(chunk) = body.chunk().await? {
		sink.push(&chunk).await?;
	}

	sink.close().await
}

/// Reinforce or weaken the chosen trail by the splice outcome, the
/// same feedback unary work applies. A peer splice that answered also
/// fires [`CLUSTER_WORK_FORWARDED`].
fn record_outcome<P: Protocol>(succeeded: bool, plan: &SplicePlan<P>, ctx: &GatewayRuntimeCtx<P>) {
	if !succeeded {
		work_trail_weaken(&ctx.servlet_registry, &plan.route_key, &ctx.config, &ctx.trace);
		return;
	}

	if plan.is_peer {
		let _ = ctx.trace.event(CLUSTER_WORK_FORWARDED);
	}
	work_trail_ok(&ctx.servlet_registry, &plan.route_key, &ctx.config, &ctx.trace);
}

/// Parse a stored dial socket into the protocol address, refusing an
/// address the transport cannot parse as `Unavailable`.
fn dial_address<P: Protocol>(dial_addr: &[u8]) -> Result<P::Address, TightBeamError>
where
	P::Address: FromStr,
{
	let parsed = str::from_utf8(dial_addr).ok().and_then(|text| text.parse::<P::Address>().ok());
	parsed.ok_or_else(|| refuse(TransitStatus::Unavailable))
}

/// Dial the plan's socket on the plan's pool: the shared connect step
/// of both splices. A failed dial refuses as `Unavailable`.
async fn dial_route<P>(plan: &SplicePlan<P>) -> Result<PooledClient<P, DefaultCryptoProvider>, TightBeamError>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	let dial_addr = dial_address::<P>(&plan.dial_addr)?;
	plan.pool
		.connect(dial_addr)
		.await
		.map_err(|_| refuse(TransitStatus::Unavailable))
}

/// Splice a streamed request: relay the client body to the route, then
/// answer with the route's unary reply.
///
/// Returns the servlet's reply frame verbatim; unlike unary work, no
/// `ClusterWorkResponse` envelope wraps it, since the stream reply is
/// the servlet's own frame end to end.
///
/// # Errors
/// - `PermissionDenied`: non-bare or foreign-realm target
/// - `Unavailable`: no live trail, no peer plane, or dial failure
/// - the route's own terminal status on a stream failure
pub(crate) async fn splice_streaming<P>(
	body: StreamBody,
	target: Urn<'static>,
	forwarded: bool,
	ctx: GatewayRuntimeCtx<P>,
) -> Result<Option<Frame>, TightBeamError>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	let plan = plan_splice(&target, forwarded, &ctx).map_err(refuse)?;

	let reply = async {
		let client = dial_route(&plan).await?;
		let (sink, response) = client.open_stream_with_route(plan.route.clone())?;
		drain_into(body, sink).await?;
		let reply = response.await?;
		Ok(reply)
	}
	.await;

	record_outcome(reply.is_ok(), &plan, &ctx);

	reply
}

/// Splice a duplex stream: relay the client body to the route while
/// relaying the route's reply chunks back, both directions concurrent.
///
/// Dropping the handler (a client cancel aborts it) drops the peer
/// sink and body, whose [`CancelOnDrop`] guards cancel the peer stream,
/// so a cancel propagates across the splice.
///
/// [`CancelOnDrop`]: crate::transport::multiplex::MuxHandle
///
/// # Errors
/// - `PermissionDenied`: non-bare or foreign-realm target
/// - `Unavailable`: no live trail, no peer plane, or dial failure
/// - the route's own terminal status on a stream failure
pub(crate) async fn splice_duplex<P>(
	body: StreamBody,
	mut reply: ReplySink,
	target: Urn<'static>,
	forwarded: bool,
	ctx: GatewayRuntimeCtx<P>,
) -> Result<(), TightBeamError>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	let plan = plan_splice(&target, forwarded, &ctx).map_err(refuse)?;

	let spliced = async {
		let client = dial_route(&plan).await?;
		let (peer_sink, mut peer_body) = client.open_duplex_with_route(plan.route.clone())?;

		let upstream = drain_into(body, peer_sink);
		let downstream = async {
			while let Some(chunk) = peer_body.chunk().await? {
				reply.push(&chunk).await?;
			}
			Ok::<(), TransportError>(())
		};

		try_join(upstream, downstream).await.map(|_| ()).map_err(TightBeamError::from)
	}
	.await;

	record_outcome(spliced.is_ok(), &plan, &ctx);

	spliced
}
