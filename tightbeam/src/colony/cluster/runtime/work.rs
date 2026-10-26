//! Work routing selects a route, forwards the payload, and updates the
//! pheromone scores.

use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::{ColonyDialProtocol, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::{HivePlane, Hop, PeerPlane};
use crate::colony::cluster::servlet_registry::RoutePlane;
use crate::colony::cluster::{
	ClusterConfig, ClusterError, DialTarget, HopBudget, RouteKind, ServletEntry, ServletRegistry,
};
use crate::colony::protocol::{ClusterRequest, ClusterWorkRequest, ClusterWorkResponse, ReplyForm};
use crate::colony::urn::ServletTypeKey;
use crate::decode;
use crate::encode;
use crate::instrumentation::events::{
	CLUSTER_WORK_FAILED, CLUSTER_WORK_FORWARDED, CLUSTER_WORK_REFUSED, CLUSTER_WORK_ROUTED, CLUSTER_WORK_UNAVAILABLE,
};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::multiplex::StreamRoute;
use crate::transport::Protocol;
use crate::urn::Urn;
use crate::{Frame, TightBeamError};

/// A route the load balancer chose for a servlet type.
///
/// - `route_key` is the pheromone key to reinforce or weaken.
/// - `dial` is the endpoint to dial.
/// - `plane` is the plane the route dials on, with the gateway a peer route names.
pub(crate) struct RouteChoice {
	pub(crate) route_key: Arc<[u8]>,
	pub(crate) dial: DialTarget,
	pub(crate) plane: RoutePlane,
}

impl RouteChoice {
	/// The choice that forwards through `entry`.
	pub(crate) fn of(entry: &ServletEntry) -> Self {
		Self {
			route_key: Arc::clone(entry.route_key()),
			dial: entry.dial_target().clone(),
			plane: entry.plane(),
		}
	}

	/// Whether the route forwards to a peer gateway.
	pub(crate) fn is_peer(&self) -> bool {
		self.plane.is_peer()
	}

	/// The hop this route dials, on the plane [`RoutePlane::hop`] names.
	///
	/// # Errors
	///
	/// - [`ClusterError::ConnectFailed`] -- a peer route meets a gateway with no
	///   peer plane, as in [`RoutePlane::hop`].
	pub(crate) fn hop<'p, P: Protocol>(
		&'p self,
		hive: &'p HivePlane<P>,
		peers: Option<&'p PeerPlane<P>>,
	) -> Result<Hop<'p, P>, ClusterError> {
		let dial = self.dial.clone();
		self.plane.hop(dial, hive, peers)
	}
}

impl RoutePlane {
	/// Whether this plane forwards to a peer gateway.
	pub(crate) fn is_peer(&self) -> bool {
		matches!(self, Self::Peer { .. })
	}

	/// The hop that dials `dial` on this plane: on `hive` bound to the signer
	/// a servlet's registration names, or on `peers` bound to the gateway a
	/// peer route names.
	///
	/// # Errors
	///
	/// - [`ClusterError::ConnectFailed`] -- a peer route meets a gateway with no peer plane.
	pub(crate) fn hop<'p, P: Protocol>(
		&'p self,
		dial: DialTarget,
		hive: &'p HivePlane<P>,
		peers: Option<&'p PeerPlane<P>>,
	) -> Result<Hop<'p, P>, ClusterError> {
		match self {
			Self::Hive { signer } => Ok(hive.servlet(dial, Arc::clone(signer))),
			Self::Peer { gateway_id } => {
				let peers = peers.ok_or(ClusterError::ConnectFailed)?;
				Ok(peers.hop(dial, gateway_id))
			}
		}
	}

	/// Delivers one forward on `hop`, a hop of this plane, and returns the
	/// bytes that answered it.
	///
	/// - A local servlet receives the client's frame on the hive trust plane:
	///   the frame `frame_cache` holds, or the decode of `payload`.
	/// - A peer gateway receives `payload` as a Work envelope with `budget`
	///   decremented, on the peer trust plane.
	async fn deliver<P: ColonyDialProtocol>(
		&self,
		hop: Hop<'_, P>,
		servlet_type: &Urn<'static>,
		payload: Vec<u8>,
		budget: HopBudget,
		frame_cache: &mut Option<Frame>,
	) -> Result<Vec<u8>, ClusterError> {
		match self {
			Self::Hive { .. } => {
				let frame = match frame_cache.take() {
					Some(frame) => frame,
					None => decode(&payload)?,
				};
				hop.deliver_frame(frame).await
			}
			Self::Peer { .. } => {
				let work = budget.relayed_work(servlet_type.clone(), payload);
				let envelope = encode(&ClusterRequest::Work(work))?;
				hop.deliver_envelope(envelope).await
			}
		}
	}

	/// Classifies one forward this plane answered with `response_payload`.
	fn classify(&self, response_payload: Vec<u8>) -> ForwardOutcome {
		match self {
			Self::Hive { .. } => ForwardOutcome::Local(response_payload),
			Self::Peer { .. } => match decode::<ClusterWorkResponse>(&response_payload) {
				Ok(peer_response) => ForwardOutcome::Peer(peer_response),
				Err(_) => ForwardOutcome::PeerGarbled,
			},
		}
	}

	/// The route a splice on this plane stamps on its open: local on the hive
	/// plane, and relayed to `target` with `budget` decremented on the peer
	/// plane.
	///
	/// # Errors
	///
	/// - [`TransitStatus::Unavailable`] -- a peer route meets a gateway with no peer plane.
	pub(crate) fn stream_route<P: Protocol>(
		&self,
		target: &Urn<'static>,
		budget: HopBudget,
		peers: Option<&PeerPlane<P>>,
	) -> Result<StreamRoute, TransitStatus> {
		match self {
			Self::Hive { .. } => Ok(StreamRoute::local()),
			Self::Peer { .. } if peers.is_none() => Err(TransitStatus::Unavailable),
			Self::Peer { .. } => Ok(budget.relayed_route(target)),
		}
	}
}

/// The decoded outcome of one answered forward.
///
/// The response buffer moves in and decodes exactly once, so the
/// failover check and the settle share one parse.
enum ForwardOutcome {
	/// A local servlet answered. The bytes are its encoded reply frame.
	Local(Vec<u8>),
	/// A peer gateway answered with a decoded work response.
	Peer(ClusterWorkResponse),
	/// A peer gateway answered with bytes that do not decode.
	PeerGarbled,
}

impl ForwardOutcome {
	/// Whether the answer proves that the frame never ran, so a retry on
	/// another route runs it at most once.
	///
	/// - A peer's [`TransitStatus::Unavailable`] proves it, because a gateway
	///   answers that status only for a frame it proved undelivered
	///   ([`ClusterError::forward_status`]).
	/// - A garbled reply follows a delivered frame, so it proves nothing.
	/// - Every other refusal relays unchanged, so the caller keeps its retryability contract.
	fn proves_undelivered(&self) -> bool {
		match self {
			Self::Local(_) | Self::PeerGarbled => false,
			Self::Peer(peer_response) => peer_response.status == TransitStatus::Unavailable,
		}
	}

	/// The status this forward settles with.
	///
	/// - A local servlet's reply is `Ok`.
	/// - A peer gateway's answer carries its own status.
	/// - A garbled reply is `Unknown`: the peer read the frame before it
	///   garbled the reply, so the frame may have run, and the caller hears
	///   that its outcome is unknown.
	fn status(&self) -> TransitStatus {
		match self {
			Self::Local(_) => TransitStatus::Ok,
			Self::Peer(peer_response) => peer_response.status,
			Self::PeerGarbled => TransitStatus::Unknown,
		}
	}
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Records a work request or a stream splice that the gateway refuses
	/// with `status` before it selects a route, and returns that status.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault the `testing-fault` feature injects.
	pub(crate) fn refuse_work(&self, status: TransitStatus) -> Result<TransitStatus, TightBeamError> {
		let trace = &self.trace;
		trace.emit_event_with_value_and_evidence(CLUSTER_WORK_REFUSED, status.as_str(), status, None)?;
		Ok(status)
	}

	/// Records a work request or a stream splice whose servlet type has no
	/// live trail at its first route selection.
	///
	/// - `retry_of` is the route key that a failed first selection excludes, or `None` for the first one.
	/// - The event fires for the first selection alone, because a retry that
	///   finds no second trail already traced its failure on the trail it
	///   weakened.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault the `testing-fault` feature injects.
	pub(crate) fn record_no_trail(&self, retry_of: Option<&[u8]>) -> Result<(), TightBeamError> {
		if retry_of.is_some() {
			return Ok(());
		}

		self.trace.emit_marker(CLUSTER_WORK_UNAVAILABLE)
	}

	/// Weakens the trail that failed and answers the caller with `status`.
	fn work_trail_fail(
		&self,
		route_key: &Arc<[u8]>,
		frame: &Frame,
		status: TransitStatus,
	) -> Result<Option<Frame>, TightBeamError> {
		let registry = &self.servlet_registry;
		registry.work_trail_weaken(route_key, status, &self.config, &self.trace)?;
		ReplyForm::Plain.reply(frame.metadata().id(), ClusterWorkResponse::err(status))
	}
}

impl<P: ColonyDialProtocol> GatewayRuntimeCtx<P> {
	/// Forwards along one selected route, as the client's frame to a local
	/// servlet or as a budget-decremented Work envelope to a peer gateway.
	///
	/// `frame_cache` holds the frame the admission check already decoded from
	/// `payload`. A local forward consumes it, so the admission decode is the
	/// only parse on the first local attempt. A bounded retry that lands on a
	/// second local route decodes again from its retained payload copy.
	async fn forward_attempt(
		&self,
		choice: &RouteChoice,
		servlet_type: &Urn<'static>,
		payload: impl Into<Vec<u8>>,
		budget: HopBudget,
		frame_cache: &mut Option<Frame>,
	) -> Result<Vec<u8>, ClusterError> {
		let payload: Vec<u8> = payload.into();
		let hop = choice.hop(&self.hive_plane, self.peer_plane.as_ref())?;

		choice.plane.deliver(hop, servlet_type, payload, budget, frame_cache).await
	}

	/// Settles an answered forward: it reinforces or weakens the trail and
	/// replies to the caller with one envelope.
	fn settle_forward(
		&self,
		frame: &Frame,
		choice: &RouteChoice,
		outcome: ForwardOutcome,
	) -> Result<Option<Frame>, TightBeamError> {
		let status = outcome.status();
		match outcome {
			ForwardOutcome::Local(response_payload) => {
				self.servlet_registry
					.work_trail_ok(&choice.route_key, &self.config, &self.trace)?;
				ReplyForm::Plain.reply(frame.metadata().id(), ClusterWorkResponse::ok(response_payload))
			}
			ForwardOutcome::Peer(peer_response) => {
				// The gateway relays the peer's own envelope, so the client
				// sees one envelope end to end.
				let trace = &self.trace;
				trace.emit_marker(CLUSTER_WORK_FORWARDED)?;

				let registry = &self.servlet_registry;
				if status == TransitStatus::Ok {
					registry.work_trail_ok(&choice.route_key, &self.config, &self.trace)?;
				} else {
					registry.work_trail_weaken(&choice.route_key, status, &self.config, &self.trace)?;
				}

				ReplyForm::Plain.reply(frame.metadata().id(), peer_response)
			}
			ForwardOutcome::PeerGarbled => self.work_trail_fail(&choice.route_key, frame, status),
		}
	}

	/// Routes one work request to a local servlet or a peer gateway.
	///
	/// `budget` is the parse the export gate already performed on this
	/// request's wire count, so the routing rules and the gate read one
	/// clamp of one octet.
	pub(crate) async fn handle_work(
		self,
		frame: Frame,
		request: ClusterWorkRequest,
		budget: HopBudget,
	) -> Result<Option<Frame>, TightBeamError> {
		// A work target must be a servlet URN in this gateway's
		// namespace. The gateway refuses foreign authorities and realms
		// before it consults the registry.
		let Some(type_key) = self.config.namespace.servlet_type_key(&request.servlet_type) else {
			let status = self.refuse_work(TransitStatus::PermissionDenied)?;
			let refusal = ClusterWorkResponse::err(status);
			return ReplyForm::Plain.reply(frame.metadata().id(), refusal);
		};

		// The payload must decode as the client's end-to-end frame. Other bytes
		// are a permanent caller fault, refused before route selection, so one
		// malformed request never weakens a healthy trail, burns the failover
		// retry, or misreports as a retryable infrastructure fault.
		let client_frame: Frame = match decode(&request.payload) {
			Ok(client_frame) => client_frame,
			Err(_) => {
				let status = self.refuse_work(TransitStatus::InvalidArgument)?;
				let refusal = ClusterWorkResponse::err(status);
				return ReplyForm::Plain.reply(frame.metadata().id(), refusal);
			}
		};

		let mut frame_cache = Some(client_frame);
		let servlet_type = request.servlet_type;
		let mut attempt_payload = request.payload;
		let mut excluded: Option<Arc<[u8]>> = None;

		// At most two selections run: the pheromone-chosen trail and, after
		// an outcome that proves the frame never ran, one bounded retry on
		// the next-best trail, with the failed route key excluded.
		loop {
			let choice = match self
				.servlet_registry
				.select_route(&self.config, &type_key, budget, excluded.as_deref())
			{
				Some(choice) => choice,
				None => {
					self.record_no_trail(excluded.as_deref())?;

					let refusal = ClusterWorkResponse::err(TransitStatus::Unavailable);
					return ReplyForm::Plain.reply(frame.metadata().id(), refusal);
				}
			};

			// The forward consumes its payload buffer into the emitted
			// frame, so the loop retains a copy while a retry is open.
			let retry_payload = if excluded.is_none() {
				Some(attempt_payload.clone())
			} else {
				None
			};

			let forward_result = self
				.forward_attempt(&choice, &servlet_type, attempt_payload, budget, &mut frame_cache)
				.await;

			// The outcome feeds the pheromone scores, which steer future
			// selection toward instances that answer and away from ones
			// that fail.
			match forward_result {
				Ok(response_payload) => {
					let outcome = choice.plane.classify(response_payload);

					// A live peer that cannot serve the type takes the same
					// bounded failover as a fault before the write, so the
					// trail weakens and the next-best one gets the retry.
					if outcome.proves_undelivered() && excluded.is_none() {
						if let Some(retry) = retry_payload {
							let status = outcome.status();
							let registry = &self.servlet_registry;
							registry.work_trail_weaken(&choice.route_key, status, &self.config, &self.trace)?;

							excluded = Some(choice.route_key);
							attempt_payload = retry;
							continue;
						}
					}

					return self.settle_forward(&frame, &choice, outcome);
				}
				Err(error) => {
					let status = error.forward_status();

					// A trail that proved the frame never ran weakens at once,
					// and a frame that may have run goes back to the caller as
					// a failure, so it runs at most once.
					if error.proves_undelivered() && excluded.is_none() {
						if let Some(retry) = retry_payload {
							let registry = &self.servlet_registry;
							registry.work_trail_weaken(&choice.route_key, status, &self.config, &self.trace)?;
							excluded = Some(choice.route_key);
							attempt_payload = retry;
							continue;
						}
					}

					return self.work_trail_fail(&choice.route_key, &frame, status);
				}
			}
		}
	}
}

impl ServletRegistry {
	/// Selects one route for `type_key` over its live pheromone trails.
	///
	/// The relay budget bounds which trail kinds are eligible:
	///
	/// - `hops_remaining == 0` selects `Local` only.
	/// - A live budget selects `Local` and `Peer`, so pheromone prefers
	///   nearby nests and can also fail over across the colony.
	/// - A relay trail spends one hop at the relay before the owner is reached,
	///   so it selects only when the budget affords at least two forwards.
	///
	/// `exclude` removes the route key of the failed attempt, so a bounded
	/// retry picks the next-best trail. `None` means no entry serves the type,
	/// the balancer declined, or the route registry is poisoned. The caller
	/// answers each case as [`TransitStatus::Unavailable`].
	pub(crate) fn select_route(
		&self,
		config: &ClusterConfig,
		type_key: &ServletTypeKey,
		budget: HopBudget,
		exclude: Option<&[u8]>,
	) -> Option<RouteChoice> {
		let servlet_registry = self;
		let entries = if budget.allows_forward() {
			servlet_registry.entries_for_type(type_key)
		} else {
			servlet_registry.local_entries_for_type(type_key)
		};
		let entries = match entries {
			Ok(entries) => entries,
			Err(_) => return None,
		};

		let entries: Vec<_> = entries
			.into_iter()
			.filter(|entry| entry.route_kind() != RouteKind::PeerRelay || budget.allows_relay_trail())
			.filter(|entry| match exclude {
				Some(failed) => entry.route_key().as_ref() != failed,
				None => true,
			})
			.collect();
		if entries.is_empty() {
			return None;
		}

		// An out-of-range balancer answer degrades to `Unavailable` instead of
		// a panic on the request path (see [`ClusterConfig::pick_instance`]).
		let selected_entry = config.pick_instance(&entries)?;
		Some(RouteChoice::of(selected_entry))
	}

	/// Reinforces a trail that answered, and records the routing event.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the routing event, the fault
	///   the `testing-fault` feature injects.
	pub(crate) fn work_trail_ok(
		&self,
		route_key: &Arc<[u8]>,
		config: &ClusterConfig,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		// A score is feedback on a request that already holds its answer, so
		// a registry fault leaves the trail unscored and the reply stands.
		let _ = self.reinforce(route_key, config.pheromone.reinforcement_boost);
		trace.emit_marker(CLUSTER_WORK_ROUTED)?;
		Ok(())
	}

	/// Weakens a trail that failed with `status`, and records the failure
	/// event.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the failure event, the fault
	///   the `testing-fault` feature injects.
	pub(crate) fn work_trail_weaken(
		&self,
		route_key: &Arc<[u8]>,
		status: TransitStatus,
		config: &ClusterConfig,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		// A score is feedback on a request that already holds its answer, so
		// a registry fault leaves the trail unscored and the reply stands.
		let _ = self.weaken_with_penalty(route_key, config.pheromone.weakening_penalty);
		trace.emit_event_with_value_and_evidence(CLUSTER_WORK_FAILED, status.as_str(), status, None)?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::peer::WireHopBudget;
	use crate::colony::cluster::{
		AdmittedDial, PeerRoute, RelayRoute, ServletEntry, SharedId, DEFAULT_ABANDONMENT_LIMIT,
		DEFAULT_INITIAL_PHEROMONE,
	};
	use crate::colony::cluster::{InstanceMetrics, LoadBalancer};
	use crate::colony::protocol::ServletInfo;
	use crate::colony::urn::ColonyNamespace;
	use crate::constants::{DEFAULT_HOP_BUDGET, DEFAULT_MAX_HOPS};

	use crate::colony::cluster::{CertificateSpec, ClusterTlsConfig, PheromoneConfig};
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::testing::{TestCertificate, TestKey};
	use crate::transport::TokioListener;
	use crate::utils::time::ManualClock;

	/// A registry on a clock only the test moves.
	fn registry() -> ServletRegistry {
		ServletRegistry::new(PheromoneConfig::default(), Arc::new(ManualClock::default()))
	}

	fn ping_type() -> Urn<'static> {
		ColonyNamespace::default()
			.servlet("ping")
			.expect("test names satisfy the mint grammar")
	}

	/// The route key for the fixture servlet type, created as production
	/// creates it.
	fn ping_key() -> ServletTypeKey {
		ColonyNamespace::default()
			.servlet_type_key(&ping_type())
			.expect("the fixture type is bare in the default namespace")
	}

	fn peer_entry(peer: impl AsRef<[u8]>, dial: impl AsRef<str>) -> ServletEntry {
		let peer = peer.as_ref();
		let servlet_type = ping_type().canonical_bytes();
		ServletEntry::peer(
			PeerRoute {
				peer_id: Arc::from(peer),
				servlet_type: Arc::from(servlet_type.as_slice()),
				dial: AdmittedDial::fixture(dial),
			},
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	fn relay_entry(origin: impl AsRef<[u8]>, relay: impl AsRef<[u8]>, dial: impl AsRef<str>) -> ServletEntry {
		let origin = origin.as_ref();
		let relay = relay.as_ref();
		let servlet_type = ping_type().canonical_bytes();
		ServletEntry::peer_relay(
			RelayRoute {
				origin_id: Arc::from(origin),
				relay_id: Arc::from(relay),
				servlet_type: Arc::from(servlet_type.as_slice()),
				dial: AdmittedDial::fixture(dial),
			},
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	fn encoded_work_response(response: &ClusterWorkResponse) -> Vec<u8> {
		encode(response).expect("test responses satisfy the codec")
	}

	/// The plane of a local route, bound to the fixture servlet's signer.
	fn local_plane() -> RoutePlane {
		RoutePlane::Hive { signer: Arc::new(ServletInfo::fixture_signer()) }
	}

	/// The plane of a direct peer route.
	fn peer_plane() -> RoutePlane {
		peer_entry(b"first", "192.0.2.1:9001").plane()
	}

	/// The plane of a relay trail, which names its relay.
	fn relay_plane() -> RoutePlane {
		relay_entry(b"origin", b"relay", "192.0.2.3:9001").plane()
	}

	#[test]
	fn forward_outcome_local_reply_never_fails_over() {
		let outcome = local_plane().classify(b"pong".to_vec());
		assert!(!outcome.proves_undelivered());
		assert!(matches!(outcome, ForwardOutcome::Local(payload) if payload == b"pong"));
	}

	#[test]
	fn forward_outcome_peer_unavailable_reply_fails_over() {
		let bytes = encoded_work_response(&ClusterWorkResponse::err(TransitStatus::Unavailable));
		assert!(peer_plane().classify(bytes).proves_undelivered());
	}

	#[test]
	fn forward_outcome_relay_unavailable_reply_fails_over() {
		let bytes = encoded_work_response(&ClusterWorkResponse::err(TransitStatus::Unavailable));
		assert!(relay_plane().classify(bytes).proves_undelivered());
	}

	#[test]
	fn forward_outcome_peer_ok_reply_settles() {
		let bytes = encoded_work_response(&ClusterWorkResponse::ok(b"pong".to_vec()));
		assert!(!peer_plane().classify(bytes).proves_undelivered());
	}

	#[test]
	fn forward_outcome_peer_refusal_relays_unchanged() {
		let bytes = encoded_work_response(&ClusterWorkResponse::err(TransitStatus::PermissionDenied));
		assert!(!peer_plane().classify(bytes).proves_undelivered());
	}

	// A garbled reply follows a frame the peer read, so it proves nothing, and
	// the frame stays with its first route.
	#[test]
	fn forward_outcome_garbled_peer_reply_never_fails_over() {
		let outcome = peer_plane().classify(b"not-a-response".to_vec());
		assert!(matches!(outcome, ForwardOutcome::PeerGarbled));
		assert!(!outcome.proves_undelivered());
	}

	fn test_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		ClusterConfig::new(
			ClusterTlsConfig::new(
				CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key))),
				Arc::new(Secp256k1KeyProvider::from(key)),
			)
			.expect("the test certificate must decode"),
		)
	}

	#[test]
	fn relayed_work_stamps_a_decremented_budget() {
		let work = HopBudget::for_test(2).relayed_work(ping_type(), vec![1]);
		assert_eq!(work.hops_remaining, 1);
	}

	#[test]
	fn relayed_work_saturates_a_spent_budget_at_zero() {
		let work = HopBudget::for_test(0).relayed_work(ping_type(), vec![1]);
		assert_eq!(work.hops_remaining, 0);
	}

	// This test pins the on-wire budget. If `HopBudget::relayed_work` skips
	// its decrement, this test fails even when integration topologies mask
	// it with a clamp.
	#[test]
	fn relayed_envelope_carries_the_decremented_budget_on_the_wire() -> Result<(), TightBeamError> {
		let relayed = HopBudget::for_test(2).relayed_work(ping_type(), vec![7]);
		let envelope = encode(&ClusterRequest::Work(relayed))?;

		let decoded = decode::<ClusterRequest>(&envelope)?;
		assert!(matches!(decoded, ClusterRequest::Work(work) if work.hops_remaining == 1));
		Ok(())
	}

	/// A balancer double that answers with an out-of-range index.
	struct RogueBalancer;

	impl LoadBalancer for RogueBalancer {
		fn select(&self, _candidates: &[InstanceMetrics]) -> Option<usize> {
			Some(usize::MAX)
		}
	}

	/// A balancer double that always picks the first candidate.
	struct FirstBalancer;

	impl LoadBalancer for FirstBalancer {
		fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
			candidates.first().map(|_| 0)
		}
	}

	fn config_balancing_with(balancer: Arc<dyn LoadBalancer>) -> ClusterConfig {
		let mut config = test_config();
		config.load_balancer = balancer;
		config
	}

	#[test]
	fn a_draw_refuses_an_out_of_range_index() {
		let entries = vec![Arc::new(peer_entry(b"first", "192.0.2.1:9001"))];
		let config = config_balancing_with(Arc::new(RogueBalancer));
		assert!(config.pick_instance(&entries).is_none());
	}

	// A local splice opens a local route on the hive plane.
	#[test]
	fn a_local_splice_opens_a_local_route() {
		let route = local_plane().stream_route::<TokioListener>(&ping_type(), HopBudget::for_test(2), None);
		assert_eq!(route, Ok(StreamRoute::local()));
	}

	// A peer splice needs the peer plane to dial its gateway, so with none
	// configured it refuses as unavailable before any dial.
	#[test]
	fn a_peer_splice_with_no_peer_plane_is_unavailable() {
		let route = peer_plane().stream_route::<TokioListener>(&ping_type(), HopBudget::for_test(2), None);
		assert_eq!(route, Err(TransitStatus::Unavailable));
	}

	#[test]
	fn a_draw_returns_the_selected_entry() {
		let entries = vec![Arc::new(peer_entry(b"first", "192.0.2.1:9001"))];
		let config = config_balancing_with(Arc::new(FirstBalancer));
		let picked = config.pick_instance(&entries);
		assert!(matches!(picked, Some(entry) if entry.dial_target().as_bytes() == b"192.0.2.1:9001"));
	}

	#[test]
	fn hop_budget_clamps_the_origin_sentinel_to_policy() {
		assert_eq!(HopBudget::from_wire(WireHopBudget::new(DEFAULT_HOP_BUDGET), 1).wire(), 1);
	}

	#[test]
	fn hop_budget_honors_a_relayed_value_below_policy() {
		assert_eq!(HopBudget::from_wire(WireHopBudget::new(1), 3).wire(), 1);
	}

	#[test]
	fn hop_budget_zero_policy_disables_forwarding() {
		let budget = HopBudget::from_wire(WireHopBudget::new(DEFAULT_HOP_BUDGET), 0);
		assert_eq!(budget.wire(), 0);
		assert!(!budget.allows_forward());
	}

	/// An origin request carries the sentinel, so anything below it
	/// reached this gateway through a relay.
	#[test]
	fn an_origin_budget_reads_as_direct() {
		assert!(!HopBudget::from_wire(WireHopBudget::new(DEFAULT_HOP_BUDGET), DEFAULT_HOP_BUDGET).is_relayed());
		assert!(HopBudget::from_wire(WireHopBudget::new(2), 4).is_relayed());
	}

	// The relayed fact reads the wire count, because the clamped count under a
	// cap below the origin sentinel would mark every direct caller relayed and
	// refuse it at the export boundary.
	#[test]
	fn a_clamped_origin_budget_still_reads_as_direct() {
		assert!(!HopBudget::from_wire(WireHopBudget::new(DEFAULT_HOP_BUDGET), DEFAULT_MAX_HOPS).is_relayed());
	}

	/// A relay trail spends one hop at the relay, so a shorter budget
	/// could never select it.
	#[test]
	fn a_relay_trail_needs_two_forwards() {
		assert!(!HopBudget::from_wire(WireHopBudget::new(1), 4).allows_relay_trail());
		assert!(HopBudget::from_wire(WireHopBudget::new(2), 4).allows_relay_trail());
	}

	#[test]
	fn select_route_withholds_relay_trails_below_two_hops() -> Result<(), ClusterError> {
		let config = test_config();
		let registry = registry();
		registry.add(relay_entry(b"origin", b"relay", "192.0.2.3:9001"))?;

		let type_key = ping_key();
		let below = registry.select_route(&config, &type_key, HopBudget::for_test(1), None);
		let at_gate = registry.select_route(&config, &type_key, HopBudget::for_test(2), None);
		assert!(below.is_none());

		let relay = RoutePlane::Peer { gateway_id: SharedId::from(b"relay".as_slice()) };
		assert_eq!(at_gate.map(|choice| choice.plane), Some(relay));
		Ok(())
	}

	#[test]
	fn select_route_excludes_the_failed_route_key() -> Result<(), ClusterError> {
		let config = test_config();
		let registry = registry();
		registry.add(peer_entry(b"first", "192.0.2.1:9001"))?;
		registry.add(peer_entry(b"second", "192.0.2.2:9001"))?;

		let type_key = ping_key();
		let failed = registry
			.select_route(&config, &type_key, HopBudget::for_test(1), None)
			.map(|choice| choice.route_key);

		let failed = failed.as_deref();
		let retry = registry.select_route(&config, &type_key, HopBudget::for_test(1), failed);
		assert!(matches!((failed, &retry), (Some(first), Some(next)) if next.route_key.as_ref() != first));
		Ok(())
	}
}
