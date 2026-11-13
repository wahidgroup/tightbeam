//! A streaming or duplex splice routes a client stream by its target [`Urn`] to
//! a local servlet or a peer gateway, then relays the bodies and the reply.
//!
//! The gateway is a [`MuxService`]: a streamed or duplex open carries a
//! gRPC-style route as unary work carries `servlet_type`. Route selection
//! reuses [`ServletRegistry::select_route`], so streaming and unary share one
//! pheromone-weighted decision.
//!
//! - A `Local` route dials the servlet on the hive plane.
//! - A `Peer` route re-emits the stream to the peer gateway on the peer plane
//!   with [`StreamRoute::relayed_to`] and the relay budget decremented.
//!
//! So a stream whose budget is spent reaches a local servlet only.
//!
//! [`ServletRegistry::select_route`]: crate::colony::cluster::ServletRegistry::select_route
//! [`MuxService`]: crate::transport::multiplex::MuxService

use core::future::Future;
use core::pin::pin;
use std::sync::Arc;

use futures::future::{select, Either};

use crate::colony::cluster::runtime::bounds::{ColonyDialProtocol, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::{HivePlane, PeerPlane};
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::runtime::work::RouteChoice;
use crate::colony::cluster::HopBudget;
use crate::instrumentation::events::CLUSTER_WORK_FORWARDED;
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::multiplex::{RelayFailure, ReplySink, StreamBody, StreamRoute};
use crate::transport::PooledClient;
use crate::urn::Urn;
use crate::{Frame, TightBeamError};

/// The failure of a splice, by the side that caused it.
enum SpliceFailure {
	/// The route failed the stream: its terminal status, a refused chunk, or
	/// the end of its link.
	Route(TightBeamError),
	/// The caller left before the route answered: its body failed, or its
	/// reply refused a chunk.
	Caller(TightBeamError),
}

impl SpliceFailure {
	/// The failure of the route, from `error`.
	fn route(error: impl Into<TightBeamError>) -> Self {
		Self::Route(error.into())
	}

	/// The failure of the caller, from `error`.
	fn caller(error: impl Into<TightBeamError>) -> Self {
		Self::Caller(error.into())
	}

	/// The status that this failure scores against the route, or `None` for a
	/// caller that left, which says nothing of the route.
	fn route_status(&self) -> Option<TransitStatus> {
		match self {
			Self::Route(error) => Some(error.failure_status()),
			Self::Caller(_) => None,
		}
	}
}

/// The body of a relay is the caller's, and its sink is the route's.
impl From<RelayFailure> for SpliceFailure {
	fn from(failure: RelayFailure) -> Self {
		match failure {
			RelayFailure::Source(error) => Self::caller(error),
			RelayFailure::Sink(error) => Self::route(error),
		}
	}
}

/// The caller of a splice hears its failure, whichever side caused it.
impl From<SpliceFailure> for TightBeamError {
	fn from(failure: SpliceFailure) -> Self {
		match failure {
			SpliceFailure::Route(error) | SpliceFailure::Caller(error) => error,
		}
	}
}

/// The two legs of one splice: the relay of the caller's body to the route,
/// and the answer of the route.
struct SpliceLegs<R, A> {
	relay: R,
	answer: A,
}

impl<R, A, T> SpliceLegs<R, A>
where
	R: Future<Output = Result<(), RelayFailure>>,
	A: Future<Output = Result<T, SpliceFailure>>,
{
	/// Runs both legs at once, until the answer of the route decides the
	/// splice.
	///
	/// - A relay that delivers the whole body, or that meets a stream the route
	///   resolved, leaves the end to the answer.
	/// - A failed relay ends the splice at once, and the drop of both legs cancels the stream of the route.
	/// - An answer that comes first ends the splice, and the rest of the body stays unread.
	async fn settle(self) -> Result<T, SpliceFailure> {
		let Self { relay, answer } = self;
		match select(pin!(relay), pin!(answer)).await {
			Either::Left((Ok(()), answer)) => answer.await,
			Either::Left((Err(failure), _)) => Err(failure.into()),
			Either::Right((answered, _)) => answered,
		}
	}
}

/// The dial plan a splice follows once the registry selects its route.
///
/// - `choice` names the endpoint to open on and the pheromone key the outcome reinforces or weakens.
/// - `route` is the stream route that open carries.
struct SplicePlan {
	choice: RouteChoice,
	route: StreamRoute,
}

impl SplicePlan {
	/// Dial this plan's route, on `hive` for a local route and on `peers` for
	/// a peer route, the connect step both splices share. A failed dial refuses
	/// as `Unavailable`, as does a hop that another party answers, which the
	/// plane records.
	async fn dial<P: ColonyDialProtocol>(
		&self,
		hive: &HivePlane<P>,
		peers: &PeerPlane<P>,
	) -> Result<PooledClient<P>, TransitStatus> {
		let hop = self.choice.hop(hive, peers);
		hop.connect().await.map_err(|_| TransitStatus::Unavailable)
	}
}

impl<P: ColonyDialProtocol> GatewayRuntimeCtx<P> {
	/// Choose a route for `target` and turn it into a dial plan, or the
	/// status that refuses the splice before any dial.
	///
	/// `budget` is the clamp the stream gate already applied, and a peer
	/// re-emit spends one hop from it. `exclude` removes the route key of a
	/// failed dial, so a bounded retry picks the next-best trail.
	///
	/// - [`TransitStatus::PermissionDenied`] -- the target is not bare, or it names a foreign realm.
	/// - [`TransitStatus::Unavailable`] -- no live trail exists.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- `trace` refused the event of a refusal.
	fn plan_splice(
		&self,
		target: &Urn<'static>,
		budget: HopBudget,
		exclude: Option<&[u8]>,
		trace: &TraceCollector,
	) -> Result<Result<SplicePlan, TransitStatus>, TightBeamError> {
		let Some(type_key) = self.config.namespace.servlet_type_key(target) else {
			let status = self.refuse_work(TransitStatus::PermissionDenied, trace)?;
			return Ok(Err(status));
		};

		let selected = self.servlet_registry.select_route(&self.config, &type_key, budget, exclude);
		let Some(choice) = selected else {
			self.record_no_trail(exclude, trace)?;

			return Ok(Err(TransitStatus::Unavailable));
		};

		let route = choice.plane.stream_route(target, budget);
		Ok(Ok(SplicePlan { choice, route }))
	}

	/// Plan and dial the splice route, with one retry on a failed dial. The
	/// failed trail weakens at once, and the next-best other trail gets one
	/// chance. A retry at the dial step is safe, because the splice reads the
	/// body only after a dial succeeds.
	async fn connect_splice(
		&self,
		target: &Urn<'static>,
		budget: HopBudget,
		trace: &TraceCollector,
	) -> Result<(SplicePlan, PooledClient<P>), TightBeamError> {
		let plan = self.plan_splice(target, budget, None, trace)?.map_err(TransitStatus::refusal)?;
		let dial_status = match plan.dial(&self.hive_plane, &self.peer_plane).await {
			Ok(client) => {
				return Ok((plan, client));
			}
			Err(status) => status,
		};

		let registry = &self.servlet_registry;
		registry.work_trail_weaken(&plan.choice.route_key, dial_status, &self.config, trace)?;

		// With no alternative trail, the caller gets the original dial failure.
		let Ok(retry_plan) = self.plan_splice(target, budget, Some(&plan.choice.route_key), trace)? else {
			return Err(dial_status.refusal());
		};

		match retry_plan.dial(&self.hive_plane, &self.peer_plane).await {
			Ok(client) => Ok((retry_plan, client)),
			Err(status) => {
				registry.work_trail_weaken(&retry_plan.choice.route_key, status, &self.config, trace)?;
				Err(status.refusal())
			}
		}
	}

	/// Reinforce or weaken the chosen trail by the splice outcome, the
	/// same feedback unary work applies. Each record goes on `trace`.
	///
	/// - A splice that the route failed weakens the trail by the status of that failure.
	/// - A splice that its caller left scores nothing.
	/// - A peer splice that answered also fires [`CLUSTER_WORK_FORWARDED`].
	fn record_outcome<T>(
		&self,
		spliced: &Result<T, SpliceFailure>,
		route_key: &Arc<[u8]>,
		is_peer: bool,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		let registry = &self.servlet_registry;
		if let Err(failure) = spliced {
			let Some(status) = failure.route_status() else {
				return Ok(());
			};

			return registry.work_trail_weaken(route_key, status, &self.config, trace);
		}

		if is_peer {
			trace.emit_marker(CLUSTER_WORK_FORWARDED)?;
		}

		registry.work_trail_ok(route_key, &self.config, trace)
	}

	/// Splice a streamed request: relay the client body to the route, and
	/// answer with the route's unary reply.
	///
	/// Returns the servlet's reply frame unchanged, because the stream reply is
	/// the servlet's own frame end to end. Unary work wraps its reply in a
	/// `ClusterWorkResponse` envelope. A reply that comes before the body
	/// ends, such as an early refusal, ends the splice.
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- the target is not bare, or it names a foreign realm.
	/// - [`TransitStatus::Unavailable`] -- no live trail exists, the dial
	///   failed, or another gateway answered.
	/// - [`TightBeamError`] -- the stream failed, under the route's own terminal status, or the caller left.
	pub(crate) async fn splice_streaming(
		self,
		body: StreamBody,
		target: Urn<'static>,
		budget: HopBudget,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		let trace = audit.unproven();
		let (plan, client) = self.connect_splice(&target, budget, trace).await?;
		// The route moves into the Open, so only the key and the peer flag
		// outlive it for the outcome feedback.
		let is_peer = plan.choice.is_peer();
		let SplicePlan { route, choice } = plan;
		let route_key = choice.route_key;
		let spliced = async {
			let (sink, response) = client.open_stream_with_route(route).map_err(SpliceFailure::route)?;
			let answer = async { response.await.map_err(SpliceFailure::route) };

			SpliceLegs { relay: body.drain_into(sink), answer }.settle().await
		}
		.await;

		self.record_outcome(&spliced, &route_key, is_peer, trace)?;

		spliced.map_err(TightBeamError::from)
	}

	/// Splice a duplex stream: relay the client body to the route and the
	/// route's reply chunks back, with both directions concurrent.
	///
	/// - The end of the route's reply ends the splice, so the route's status reaches the client.
	/// - A dropped handler drops the peer sink and the body, and a client
	///   cancel aborts the handler. The peer sink's drop and the cancel guard
	///   of the peer [`StreamBody`] then cancel the peer stream, so a cancel
	///   propagates across the splice.
	///
	/// [`StreamBody`]: crate::transport::multiplex::StreamBody
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- the target is not bare, or it names a foreign realm.
	/// - [`TransitStatus::Unavailable`] -- no live trail exists, the dial
	///   failed, or another gateway answered.
	/// - [`TightBeamError`] -- the stream failed, under the route's own terminal status, or the caller left.
	pub(crate) async fn splice_duplex(
		self,
		body: StreamBody,
		mut reply: ReplySink,
		target: Urn<'static>,
		budget: HopBudget,
		audit: &RequestAudit,
	) -> Result<(), TightBeamError> {
		let trace = audit.unproven();
		let (plan, client) = self.connect_splice(&target, budget, trace).await?;
		// The route moves into the Open, so only the key and the peer flag
		// outlive it for the outcome feedback.
		let is_peer = plan.choice.is_peer();
		let SplicePlan { route, choice } = plan;
		let route_key = choice.route_key;
		let spliced = async {
			let (peer_sink, mut peer_body) = client.open_duplex_with_route(route).map_err(SpliceFailure::route)?;
			let answer = async {
				while let Some(chunk) = peer_body.chunk().await.map_err(SpliceFailure::route)? {
					reply.push(&chunk).await.map_err(SpliceFailure::caller)?;
				}

				Ok(())
			};

			SpliceLegs { relay: body.drain_into(peer_sink), answer }.settle().await
		}
		.await;

		self.record_outcome(&spliced, &route_key, is_peer, trace)?;

		spliced.map_err(TightBeamError::from)
	}
}

#[cfg(test)]
mod tests {
	use core::future::{pending, ready};

	use futures::FutureExt;

	use super::*;
	use crate::colony::cluster::runtime::bounds::fixtures::Audited;
	use crate::colony::cluster::{ClusterConfig, ServletEntry};
	use crate::colony::urn::ColonyNamespace;
	use crate::testing::TestResult;
	use crate::transport::TransportError;

	fn stream_type() -> Urn<'static> {
		ColonyNamespace::servlet_fixture("stream-echo")
	}

	/// A gateway with no peer pool dials its peers on its hive pool, so a peer
	/// route plans a relayed splice and refuses nothing before the dial.
	#[test]
	fn a_peer_route_on_a_gateway_with_no_peer_pool_hops_on_the_hive_pool() -> TestResult {
		let audited = Audited::of(ClusterConfig::fixture());
		let route = ServletEntry::peer_fixture(stream_type().canonical_bytes(), b"first", "192.0.2.1:9001");

		audited.gateway.servlet_registry.add(route)?;

		let budget = HopBudget::for_test(2);
		let planned = audited.gateway.plan_splice(&stream_type(), budget, None, &audited.trace)?;

		let route = planned.map(|plan| plan.route);
		let read = route.as_ref().map(|route| (route.hops_remaining(), route.target()));
		assert_eq!(read, Ok((1, Some(&stream_type()))));
		Ok(())
	}

	/// The failure of a route that closed its link.
	fn route_closed() -> SpliceFailure {
		SpliceFailure::route(TransportError::ConnectionClosed)
	}

	/// A relay that ends clean leaves the end of the splice to the answer of
	/// the route.
	#[test]
	fn a_clean_relay_leaves_the_end_to_the_answer() {
		let legs = SpliceLegs { relay: ready(Ok(())), answer: ready(Err::<(), _>(route_closed())) };

		let settled = legs.settle().now_or_never();
		assert!(matches!(settled, Some(Err(SpliceFailure::Route(_)))));
	}

	/// A relay that fails at its body ends the splice at once, as a failure
	/// of the caller.
	#[test]
	fn a_failed_body_ends_the_splice_as_the_callers_failure() {
		let relay = ready(Err(RelayFailure::Source(TransportError::ConnectionClosed)));
		let legs = SpliceLegs { relay, answer: pending::<Result<(), SpliceFailure>>() };

		let settled = legs.settle().now_or_never();
		assert!(matches!(settled, Some(Err(SpliceFailure::Caller(_)))));
	}

	/// A relay that fails at its sink ends the splice at once, as a failure
	/// of the route.
	#[test]
	fn a_failed_sink_ends_the_splice_as_the_routes_failure() {
		let relay = ready(Err(RelayFailure::Sink(TransportError::ConnectionClosed)));
		let legs = SpliceLegs { relay, answer: pending::<Result<(), SpliceFailure>>() };

		let settled = legs.settle().now_or_never();
		assert!(matches!(settled, Some(Err(SpliceFailure::Route(_)))));
	}

	/// An answer that comes first ends the splice while the relay still waits
	/// on the body.
	#[test]
	fn an_answer_ends_the_splice_while_the_relay_waits() {
		let legs = SpliceLegs {
			relay: pending::<Result<(), RelayFailure>>(),
			answer: ready(Ok::<_, SpliceFailure>(7)),
		};

		let settled = legs.settle().now_or_never();
		assert!(matches!(settled, Some(Ok(7))));
	}
}
