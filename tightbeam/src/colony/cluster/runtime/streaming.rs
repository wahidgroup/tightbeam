//! Streaming and duplex splice: route a client stream by its target
//! `Urn` to a local servlet or a peer gateway, then relay the bodies
//! and reply.
//!
//! The gateway is a `MuxService`: a streamed or duplex open carries a
//! grpc-style route the same way unary work carries `servlet_type`.
//! Selection reuses [`select_route`], so streaming and unary share one
//! pheromone-weighted routing decision. A `Local` route dials the
//! servlet on the hive plane. A `Peer` route re-emits the stream to the
//! peer gateway on the peer plane with [`StreamRoute::relayed_to`] and
//! the relay budget decremented. A spent budget is therefore served
//! locally and never re-forwarded.

use core::hash::Hash;
use core::str::{self, FromStr};
use std::sync::Arc;

use futures::future::try_join;

use crate::colony::cluster::runtime::bounds::{ClusterPool, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::work::{
	hop_budget, select_route, spend_hop, work_trail_ok, work_trail_weaken, RouteChoice,
};
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

/// The dialing plan a splice follows once a route is chosen.
///
/// - `pool` and `dial_addr` name the socket to open on.
/// - `route` is stamped on that open.
/// - `route_key` is the pheromone key the outcome reinforces or
///   weakens.
struct SplicePlan<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	dial_addr: Arc<[u8]>,
	route: StreamRoute,
	route_key: Arc<[u8]>,
	is_peer: bool,
}

/// Refuse a stream with a terminal transit status. The mux responder
/// maps the failure onto the stream's `End` trailer.
pub(super) fn refuse(status: TransitStatus) -> TightBeamError {
	TransportError::from(status).into()
}

/// Relayed stream route for a peer hop: same target, with one forward
/// spent from the budget. The streaming twin of the unary
/// `relayed_work`.
fn relayed_route(target: &Urn<'static>, effective: u8) -> StreamRoute {
	StreamRoute::relayed_to(target.clone(), spend_hop(effective))
}

/// Choose a route for `target` and turn it into a dialing plan.
///
/// The inbound relay budget is clamped to the gateway's `max_hops`
/// policy before selection, and a peer re-emit spends one hop.
/// `exclude` removes one just-failed route key so a bounded retry
/// picks the next-best trail. Before any dial, a non-bare or
/// foreign-realm target refuses with `PermissionDenied`. An unroutable
/// target (no live trail, or a peer target with no peer plane
/// configured) refuses with `Unavailable`.
fn plan_splice<P: Protocol>(
	target: &Urn<'static>,
	hops_remaining: u8,
	exclude: Option<&[u8]>,
	ctx: &GatewayRuntimeCtx<P>,
) -> Result<SplicePlan<P>, TransitStatus> {
	if !is_bare_servlet_type(&ctx.config.namespace, target) {
		return Err(TransitStatus::PermissionDenied);
	}

	let type_key = canonical_bytes(target);
	let effective = hop_budget(ctx.config.peer.max_hops, hops_remaining);
	let RouteChoice { route_key, dial_addr, route_kind } =
		select_route(&ctx.servlet_registry, &ctx.config, &type_key, effective, exclude)
			.ok_or(TransitStatus::Unavailable)?;

	match route_kind {
		RouteKind::Local => Ok(SplicePlan {
			pool: Arc::clone(&ctx.pool),
			dial_addr,
			route: StreamRoute::local(),
			route_key,
			is_peer: false,
		}),
		RouteKind::Peer | RouteKind::PeerRelay => {
			let peer_pool = ctx.peer_pool.as_ref().ok_or(TransitStatus::Unavailable)?;
			Ok(SplicePlan {
				pool: Arc::clone(peer_pool),
				dial_addr,
				route: relayed_route(target, effective),
				route_key,
				is_peer: true,
			})
		}
	}
}

/// Feed every chunk of `body` into `sink`, then close the sink so its
/// stream ends. Consuming each chunk replenishes the peer's credit.
/// A slow downstream therefore parks the upstream (end-to-end backpressure).
async fn drain_into(mut body: StreamBody, mut sink: RequestSink) -> TransportResult<()> {
	while let Some(chunk) = body.chunk().await? {
		sink.push(&chunk).await?;
	}

	sink.close().await
}

/// Reinforce or weaken the chosen trail by the splice outcome, the
/// same feedback unary work applies. A peer splice that answered also
/// fires [`CLUSTER_WORK_FORWARDED`].
fn record_outcome<P: Protocol>(succeeded: bool, route_key: &Arc<[u8]>, is_peer: bool, ctx: &GatewayRuntimeCtx<P>) {
	if !succeeded {
		work_trail_weaken(&ctx.servlet_registry, route_key, &ctx.config, &ctx.trace);
		return;
	}

	if is_peer {
		let _ = ctx.trace.event(CLUSTER_WORK_FORWARDED);
	}
	work_trail_ok(&ctx.servlet_registry, route_key, &ctx.config, &ctx.trace);
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

/// Plan and dial the splice route, with one bounded retry on a failed
/// dial. The failed trail weakens immediately, and the next-best
/// trail, excluding the failed route key, gets a single chance.
/// Retrying at the dial step is safe because no body chunk has been
/// consumed yet.
async fn connect_splice<P>(
	target: &Urn<'static>,
	hops_remaining: u8,
	ctx: &GatewayRuntimeCtx<P>,
) -> Result<(SplicePlan<P>, PooledClient<P, DefaultCryptoProvider>), TightBeamError>
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
	let plan = plan_splice(target, hops_remaining, None, ctx).map_err(refuse)?;
	let dial_error = match dial_route(&plan).await {
		Ok(client) => {
			return Ok((plan, client));
		}
		Err(error) => error,
	};

	work_trail_weaken(&ctx.servlet_registry, &plan.route_key, &ctx.config, &ctx.trace);

	// No alternative trail: surface the original dial failure.
	let Ok(retry_plan) = plan_splice(target, hops_remaining, Some(&plan.route_key), ctx) else {
		return Err(dial_error);
	};

	match dial_route(&retry_plan).await {
		Ok(client) => Ok((retry_plan, client)),
		Err(error) => {
			work_trail_weaken(&ctx.servlet_registry, &retry_plan.route_key, &ctx.config, &ctx.trace);
			Err(error)
		}
	}
}

/// Splice a streamed request: relay the client body to the route, then
/// answer with the route's unary reply.
///
/// Returns the servlet's reply frame unchanged. Unlike unary work, no
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
	hops_remaining: u8,
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
	let (plan, client) = connect_splice(&target, hops_remaining, &ctx).await?;
	// The route moves into the Open; only the key and the peer flag
	// outlive it for the outcome feedback.
	let SplicePlan { route, route_key, is_peer, .. } = plan;

	let reply = async {
		let (sink, response) = client.open_stream_with_route(route)?;

		drain_into(body, sink).await?;

		let reply = response.await?;
		Ok(reply)
	}
	.await;

	record_outcome(reply.is_ok(), &route_key, is_peer, &ctx);

	reply
}

/// Splice a duplex stream: relay the client body to the route while
/// relaying the route's reply chunks back, both directions concurrent.
///
/// Dropping the handler drops the peer sink and body, and a client
/// cancel aborts the handler. Their [`CancelOnDrop`] guards then
/// cancel the peer stream, so a cancel propagates across the splice.
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
	hops_remaining: u8,
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
	let (plan, client) = connect_splice(&target, hops_remaining, &ctx).await?;
	// The route moves into the Open; only the key and the peer flag
	// outlive it for the outcome feedback.
	let SplicePlan { route, route_key, is_peer, .. } = plan;

	let spliced = async {
		let (peer_sink, mut peer_body) = client.open_duplex_with_route(route)?;

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

	record_outcome(spliced.is_ok(), &route_key, is_peer, &ctx);

	spliced
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::ColonyNamespace;

	fn stream_type() -> Urn<'static> {
		ColonyNamespace::default()
			.servlet("stream-echo")
			.expect("test names satisfy the mint grammar")
	}

	// Pins the stream-path budget: dropping the decrement in
	// `relayed_route` fails here even when integration topologies mask
	// it with a clamp. The route-to-Open stamping is pinned by the mux
	// handle tests.
	#[test]
	fn relayed_route_stamps_a_decremented_budget() {
		let route = relayed_route(&stream_type(), 2);
		assert_eq!(route.hops_remaining(), 1);
	}

	#[test]
	fn relayed_route_saturates_a_spent_budget_at_zero() {
		let route = relayed_route(&stream_type(), 0);
		assert_eq!(route.hops_remaining(), 0);
	}

	#[test]
	fn relayed_route_keeps_the_target() {
		let route = relayed_route(&stream_type(), 2);
		assert_eq!(route.target(), Some(&stream_type()));
	}
}
