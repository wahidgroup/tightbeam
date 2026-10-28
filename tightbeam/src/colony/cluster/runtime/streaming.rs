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

use std::sync::Arc;

use futures::future::try_join;

use crate::colony::cluster::runtime::bounds::{ColonyDialProtocol, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::{HivePlane, PeerPlane};
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::runtime::work::RouteChoice;
use crate::colony::cluster::HopBudget;
use crate::instrumentation::events::CLUSTER_WORK_FORWARDED;
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::error::TransportError;
use crate::transport::multiplex::{ReplySink, StreamBody, StreamRoute};
use crate::transport::PooledClient;
use crate::urn::Urn;
use crate::{Frame, TightBeamError};

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
	/// same feedback unary work applies. `failure` is the status of a splice
	/// that failed, and a peer splice that answered also fires
	/// [`CLUSTER_WORK_FORWARDED`]. Each record goes on `trace`.
	fn record_outcome(
		&self,
		failure: Option<TransitStatus>,
		route_key: &Arc<[u8]>,
		is_peer: bool,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		let registry = &self.servlet_registry;
		if let Some(status) = failure {
			return registry.work_trail_weaken(route_key, status, &self.config, trace);
		}

		if is_peer {
			trace.emit_marker(CLUSTER_WORK_FORWARDED)?;
		}

		registry.work_trail_ok(route_key, &self.config, trace)
	}

	/// Splice a streamed request: relay the client body to the route, then
	/// answer with the route's unary reply.
	///
	/// Returns the servlet's reply frame unchanged, because the stream reply is
	/// the servlet's own frame end to end. Unary work wraps its reply in a
	/// `ClusterWorkResponse` envelope.
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- the target is not bare, or it names a foreign realm.
	/// - [`TransitStatus::Unavailable`] -- no live trail exists, the dial
	///   failed, or another gateway answered.
	/// - [`TightBeamError`] -- the stream failed, under the route's own terminal status.
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
		let reply = async {
			let (sink, response) = client.open_stream_with_route(route)?;

			body.drain_into(sink).await?;

			let reply = response.await?;
			Ok(reply)
		}
		.await;

		let failure = reply.as_ref().err().map(TightBeamError::failure_status);
		self.record_outcome(failure, &route_key, is_peer, trace)?;

		reply
	}

	/// Splice a duplex stream: relay the client body to the route and the
	/// route's reply chunks back, with both directions concurrent.
	///
	/// A dropped handler drops the peer sink and the body, and a client
	/// cancel aborts the handler. The peer sink's drop and the cancel guard of
	/// the peer [`StreamBody`] then cancel the peer stream, so a cancel
	/// propagates across the splice.
	///
	/// [`StreamBody`]: crate::transport::multiplex::StreamBody
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- the target is not bare, or it names a foreign realm.
	/// - [`TransitStatus::Unavailable`] -- no live trail exists, the dial
	///   failed, or another gateway answered.
	/// - [`TightBeamError`] -- the stream failed, under the route's own terminal status.
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
			let (peer_sink, mut peer_body) = client.open_duplex_with_route(route)?;
			let upstream = body.drain_into(peer_sink);
			let downstream = async {
				while let Some(chunk) = peer_body.chunk().await? {
					reply.push(&chunk).await?;
				}

				Ok::<(), TransportError>(())
			};

			try_join(upstream, downstream).await.map(|_| ()).map_err(TightBeamError::from)
		}
		.await;

		let failure = spliced.as_ref().err().map(TightBeamError::failure_status);
		self.record_outcome(failure, &route_key, is_peer, trace)?;

		spliced
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::{
		AdmittedDial, CertificateSpec, ClusterConfig, ClusterTlsConfig, PeerRoute, ServletEntry,
		DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE,
	};
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::testing::{TestCertificate, TestKey};
	use crate::transport::TokioListener;

	fn stream_type() -> Urn<'static> {
		ColonyNamespace::default()
			.servlet("stream-echo")
			.expect("test names satisfy the mint grammar")
	}

	// A missing decrement in `HopBudget::relayed_route` fails here even when
	// integration topologies mask it with a clamp. The mux handle tests pin
	// the stamp of the route on the Open.
	#[test]
	fn relayed_route_stamps_a_decremented_budget() {
		let route = HopBudget::for_test(2).relayed_route(&stream_type());
		assert_eq!(route.hops_remaining(), 1);
	}

	#[test]
	fn relayed_route_saturates_a_spent_budget_at_zero() {
		let route = HopBudget::for_test(0).relayed_route(&stream_type());
		assert_eq!(route.hops_remaining(), 0);
	}

	#[test]
	fn relayed_route_keeps_the_target() {
		let route = HopBudget::for_test(2).relayed_route(&stream_type());
		assert_eq!(route.target(), Some(&stream_type()));
	}

	/// The route of [`stream_type`] through the peer gateway `first`.
	fn peer_route() -> ServletEntry {
		let servlet_type = stream_type().canonical_bytes();
		let route = PeerRoute {
			peer_id: Arc::from(b"first".as_slice()),
			servlet_type: Arc::from(servlet_type.as_slice()),
			dial: AdmittedDial::fixture("192.0.2.1:9001"),
		};

		ServletEntry::peer(route, DEFAULT_INITIAL_PHEROMONE, DEFAULT_ABANDONMENT_LIMIT)
	}

	/// The request context of a gateway that configures no peer trust, so it
	/// holds no peer pool.
	fn gateway_with_no_peer_pool(trace: &Arc<TraceCollector>) -> GatewayRuntimeCtx<TokioListener> {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let spec = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let config = ClusterConfig::new(tls.expect("the fixture certificate decodes"));

		GatewayRuntimeCtx::for_test(config, trace, &Arc::new(TraceCollector::new()))
	}

	// A gateway with no peer pool dials its peers on its hive pool, so a peer
	// route plans a relayed splice and refuses nothing before the dial.
	#[test]
	fn a_peer_route_on_a_gateway_with_no_peer_pool_hops_on_the_hive_pool() -> Result<(), Box<dyn core::error::Error>> {
		let trace = Arc::new(TraceCollector::new());
		let gateway = gateway_with_no_peer_pool(&trace);
		gateway.servlet_registry.add(peer_route())?;

		let planned = gateway.plan_splice(&stream_type(), HopBudget::for_test(2), None, &trace)?;

		let route = planned.map(|plan| plan.route);
		let read = route.as_ref().map(|route| (route.hops_remaining(), route.target()));
		assert_eq!(read, Ok((1, Some(&stream_type()))));
		Ok(())
	}
}
