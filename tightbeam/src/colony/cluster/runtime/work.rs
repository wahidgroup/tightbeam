//! Work routing selects a route, forwards the payload, and updates the
//! pheromone scores.

use core::hash::Hash;
use core::str::FromStr;
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::GatewayRuntimeCtx;
use crate::colony::cluster::runtime::hop::Hop;
use crate::colony::cluster::{ClusterConfig, ClusterError, ClusterWorkResponse, HopBudget, RouteKind, ServletRegistry};
use crate::colony::common::{canonical_bytes, is_bare_servlet_type, reply_frame, ClusterRequest, ClusterWorkRequest};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::decode;
use crate::encode;
use crate::instrumentation::events::{
	CLUSTER_WORK_FAILED, CLUSTER_WORK_FORWARDED, CLUSTER_WORK_REFUSED, CLUSTER_WORK_ROUTED, CLUSTER_WORK_UNAVAILABLE,
};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::error::TransportError;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::utils::urn::Urn;
use crate::{Frame, TightBeamError};

/// A route the load balancer chose for a servlet type.
///
/// - `route_key` is the pheromone key to reinforce or weaken.
/// - `dial_addr` is the socket to dial.
/// - `route_kind` picks the dial plane: hive for local, peer
///   otherwise.
pub(crate) struct RouteChoice {
	pub(crate) route_key: Arc<[u8]>,
	pub(crate) dial_addr: Arc<[u8]>,
	pub(crate) route_kind: RouteKind,
}

fn work_trail_fail(
	servlet_registry: &ServletRegistry,
	route_key: &Arc<[u8]>,
	config: &ClusterConfig,
	trace: &TraceCollector,
	frame: &Frame,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	servlet_registry.work_trail_weaken(route_key, config, trace)?;
	reply_frame(&frame.metadata.id, ClusterWorkResponse::err(status))
}

/// Builds the relayed work envelope for a peer hop. It carries the same
/// type and client frame bytes, with one forward spent from the budget.
///
/// The struct is constructed literally because the payload is already
/// the client's encoded frame and travels opaquely. No re-encode
/// happens at relay hops.
fn relayed_work(servlet_type: Urn<'static>, payload: Vec<u8>, budget: HopBudget) -> ClusterWorkRequest {
	ClusterWorkRequest { servlet_type, payload, hops_remaining: budget.spend().wire() }
}

/// Decoded outcome of one answered forward.
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
	/// Classify one answered forward by route kind.
	fn classify(route_kind: RouteKind, response_payload: Vec<u8>) -> Self {
		match route_kind {
			RouteKind::Local => Self::Local(response_payload),
			RouteKind::Peer | RouteKind::PeerRelay => match decode::<ClusterWorkResponse>(&response_payload) {
				Ok(peer_response) => Self::Peer(peer_response),
				Err(_) => Self::PeerGarbled,
			},
		}
	}

	/// `true` when a live route reported it cannot serve the type.
	///
	/// This is the same failover class as a transport fault mapped to
	/// [`TransitStatus::Unavailable`]. The trail is useless for this
	/// type right now, and a garbled peer reply proves nothing better.
	/// Every other refusal relays unchanged so the caller keeps its
	/// retryability contract.
	fn is_unavailable(&self) -> bool {
		match self {
			Self::Local(_) => false,
			Self::Peer(peer_response) => peer_response.status == TransitStatus::Unavailable,
			Self::PeerGarbled => true,
		}
	}
}

/// Transit status a failed forward relays to the caller.
///
/// A servlet refusal relays unchanged so the caller keeps its
/// retryability contract. Everything else degrades to `Unavailable`.
fn forward_failure_status(error: ClusterError) -> TransitStatus {
	match error {
		ClusterError::Transport(TransportError::OperationFailed(failure)) => {
			TransitStatus::try_from(failure).unwrap_or(TransitStatus::Unavailable)
		}
		_ => TransitStatus::Unavailable,
	}
}

impl<P> GatewayRuntimeCtx<P>
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
	/// Forward along one selected route. A local servlet receives the client's
	/// frame. A peer gateway receives a budget-decremented Work envelope.
	///
	/// `frame_cache` holds the frame the admission check already decoded from
	/// `payload`. A local forward consumes it, so the admission decode is the
	/// only parse on the first local attempt. A bounded retry that lands on a
	/// second local route decodes again from its retained payload copy.
	async fn forward_attempt(
		&self,
		choice: &RouteChoice,
		servlet_type: &Urn<'static>,
		payload: Vec<u8>,
		budget: HopBudget,
		frame_cache: &mut Option<Frame>,
	) -> Result<Vec<u8>, ClusterError> {
		let dial_addr = Arc::clone(&choice.dial_addr);

		// Local hops deliver the client's frame on the hive
		// trust plane. Peer hops re-enter the peer gateway as Work with
		// the budget decremented, on the peer trust plane.
		match choice.route_kind {
			RouteKind::Local => {
				let frame = match frame_cache.take() {
					Some(frame) => frame,
					None => decode(&payload)?,
				};
				Hop::new(&self.pool, dial_addr).deliver_frame(frame).await
			}
			RouteKind::Peer | RouteKind::PeerRelay => match self.peer_pool.as_ref() {
				Some(peer_pool) => {
					let work = relayed_work(servlet_type.clone(), payload, budget);
					let envelope = encode(&ClusterRequest::Work(work))?;
					Hop::new(peer_pool, dial_addr).deliver_envelope(envelope).await
				}
				None => Err(ClusterError::ConnectFailed),
			},
		}
	}

	/// Settle an answered forward. This reinforces or weakens the trail and
	/// replies to the caller with one envelope.
	fn settle_forward(
		&self,
		frame: &Frame,
		choice: &RouteChoice,
		outcome: ForwardOutcome,
	) -> Result<Option<Frame>, TightBeamError> {
		match outcome {
			ForwardOutcome::Local(response_payload) => {
				self.servlet_registry
					.work_trail_ok(&choice.route_key, &self.config, &self.trace)?;
				reply_frame(&frame.metadata.id, ClusterWorkResponse::ok(response_payload))
			}
			ForwardOutcome::Peer(peer_response) => {
				// Relay the peer's own envelope so the client sees one
				// envelope end to end.
				self.trace.event(CLUSTER_WORK_FORWARDED)?;

				if peer_response.status == TransitStatus::Ok {
					self.servlet_registry
						.work_trail_ok(&choice.route_key, &self.config, &self.trace)?;
				} else {
					self.servlet_registry
						.work_trail_weaken(&choice.route_key, &self.config, &self.trace)?;
				}

				reply_frame(&frame.metadata.id, peer_response)
			}
			ForwardOutcome::PeerGarbled => work_trail_fail(
				&self.servlet_registry,
				&choice.route_key,
				&self.config,
				&self.trace,
				frame,
				TransitStatus::Unavailable,
			),
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
		// namespace. Foreign authorities and realms are refused
		// before the registry is consulted.
		if !is_bare_servlet_type(&self.config.namespace, &request.servlet_type) {
			self.trace.event(CLUSTER_WORK_REFUSED)?;
			return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::PermissionDenied));
		}

		// The payload must decode as the client's end-to-end frame. Bytes
		// that do not are a permanent caller fault, refused before route
		// selection so one malformed request can never weaken a healthy
		// pheromone trail, burn the bounded failover retry, or misreport
		// as a retryable infrastructure fault. The decoded frame is kept
		// for the first local forward, which re-emits it as-is.
		let client_frame: Frame = match decode(&request.payload) {
			Ok(client_frame) => client_frame,
			Err(_) => {
				self.trace.event(CLUSTER_WORK_REFUSED)?;
				return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::InvalidArgument));
			}
		};

		let mut frame_cache = Some(client_frame);
		let type_key = canonical_bytes(&request.servlet_type);
		let servlet_type = request.servlet_type;
		let mut attempt_payload = request.payload;
		let mut excluded: Option<Arc<[u8]>> = None;

		// At most two selections run: the pheromone-chosen trail and, after
		// an Unavailable outcome, one bounded retry on the next-best trail
		// excluding the failed route key.
		loop {
			let choice = match self
				.servlet_registry
				.select_route(&self.config, &type_key, budget, excluded.as_deref())
			{
				Some(choice) => choice,
				None => {
					// The unavailable event marks a type with no live trail
					// at all. An exhausted retry already traced its failure
					// on the weakened trail.
					if excluded.is_none() {
						self.trace.event(CLUSTER_WORK_UNAVAILABLE)?;
					}
					return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::Unavailable));
				}
			};

			// The forward consumes its payload buffer into the emitted
			// frame, so a copy is retained while a retry is still open.
			let retry_payload = if excluded.is_none() {
				Some(attempt_payload.clone())
			} else {
				None
			};

			let forward_result = self
				.forward_attempt(&choice, &servlet_type, attempt_payload, budget, &mut frame_cache)
				.await;

			// The outcome feeds the pheromone scores, steering future
			// selection toward instances that answer and away from ones
			// that fail.
			match forward_result {
				Ok(response_payload) => {
					let outcome = ForwardOutcome::classify(choice.route_kind, response_payload);

					// A live peer that reports it cannot serve the type
					// joins the same bounded failover as a transport
					// fault. Weaken the trail and retry the next-best one.
					if outcome.is_unavailable() && excluded.is_none() {
						if let Some(retry) = retry_payload {
							self.servlet_registry
								.work_trail_weaken(&choice.route_key, &self.config, &self.trace)?;

							excluded = Some(choice.route_key);
							attempt_payload = retry;
							continue;
						}
					}

					return self.settle_forward(&frame, &choice, outcome);
				}
				Err(error) => {
					let status = forward_failure_status(error);

					// Fast failover. An unavailable trail weakens now and
					// the next-best trail gets the single retry.
					if status == TransitStatus::Unavailable && excluded.is_none() {
						if let Some(retry) = retry_payload {
							self.servlet_registry
								.work_trail_weaken(&choice.route_key, &self.config, &self.trace)?;
							excluded = Some(choice.route_key);
							attempt_payload = retry;
							continue;
						}
					}

					return work_trail_fail(
						&self.servlet_registry,
						&choice.route_key,
						&self.config,
						&self.trace,
						&frame,
						status,
					);
				}
			}
		}
	}
}

impl ServletRegistry {
	/// Select one route for `type_key` over its live pheromone trails.
	///
	/// The relay budget bounds which trail kinds are eligible:
	///
	/// - `hops_remaining == 0` selects `Local` only.
	/// - A live budget selects `Local` and `Peer`, so pheromone prefers
	///   nearby nests while still failing over across the colony.
	/// - A relay trail spends one hop at the relay before the owner is reached,
	///   so it selects only when the budget affords at least two forwards.
	///
	/// `exclude` removes one just-failed route key so a bounded retry picks the
	/// next-best trail. `None` means no entry serves the type or the balancer
	/// declined, which the caller answers as [`TransitStatus::Unavailable`].
	pub(crate) fn select_route(
		&self,
		config: &ClusterConfig,
		type_key: &[u8],
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

		// An out-of-range balancer answer degrades to `Unavailable`
		// instead of panicking the request path (see [`ClusterConfig::pick_instance`]).
		let selected_entry = config.pick_instance(&entries)?;
		Some(RouteChoice {
			route_key: Arc::clone(selected_entry.route_key()),
			dial_addr: Arc::clone(selected_entry.dial_target()),
			route_kind: selected_entry.route_kind(),
		})
	}

	/// Reinforce a trail that answered, and record the routing event.
	///
	/// # Errors
	///
	/// - Propagates the trace fault the `testing-fault` feature injects.
	pub(crate) fn work_trail_ok(
		&self,
		route_key: &Arc<[u8]>,
		config: &ClusterConfig,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		// Scoring is feedback on a request that already holds its answer, so
		// a registry fault leaves the trail unscored and the reply stands.
		let _ = self.reinforce(route_key, config.pheromone.reinforcement_boost);
		trace.event(CLUSTER_WORK_ROUTED)?;

		Ok(())
	}

	/// Weaken a trail that failed, and record the failure event.
	///
	/// # Errors
	///
	/// - Propagates the trace fault the `testing-fault` feature injects.
	pub(crate) fn work_trail_weaken(
		&self,
		route_key: &Arc<[u8]>,
		config: &ClusterConfig,
		trace: &TraceCollector,
	) -> Result<(), TightBeamError> {
		// Scoring is feedback on a request that already holds its answer, so
		// a registry fault leaves the trail unscored and the reply stands.
		let _ = self.weaken_with_penalty(route_key, config.pheromone.weakening_penalty);
		trace.event(CLUSTER_WORK_FAILED)?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::cluster::{ServletEntry, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE};
	use crate::colony::common::{ColonyNamespace, InstanceMetrics, LoadBalancer};
	use crate::constants::{DEFAULT_HOP_BUDGET, DEFAULT_MAX_HOPS};

	use crate::colony::cluster::{CertificateSpec, ClusterTlsConfig};
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::testing::create_test_signing_key;

	fn ping_type() -> Urn<'static> {
		ColonyNamespace::default()
			.servlet("ping")
			.expect("test names satisfy the mint grammar")
	}

	fn peer_entry(peer: &[u8], dial: &[u8]) -> ServletEntry {
		ServletEntry::peer(
			Arc::from(peer),
			Arc::from(canonical_bytes(&ping_type()).as_slice()),
			Arc::from(dial),
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	fn relay_entry(origin: &[u8], relay: &[u8], dial: &[u8]) -> ServletEntry {
		ServletEntry::peer_relay(
			Arc::from(origin),
			Arc::from(relay),
			Arc::from(canonical_bytes(&ping_type()).as_slice()),
			Arc::from(dial),
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		)
	}

	fn encoded_work_response(response: &ClusterWorkResponse) -> Vec<u8> {
		encode(response).expect("test responses satisfy the codec")
	}

	#[test]
	fn forward_outcome_local_reply_never_fails_over() {
		let outcome = ForwardOutcome::classify(RouteKind::Local, b"pong".to_vec());
		assert!(!outcome.is_unavailable());
		assert!(matches!(outcome, ForwardOutcome::Local(payload) if payload == b"pong"));
	}

	#[test]
	fn forward_outcome_peer_unavailable_reply_fails_over() {
		let bytes = encoded_work_response(&ClusterWorkResponse::err(TransitStatus::Unavailable));
		assert!(ForwardOutcome::classify(RouteKind::Peer, bytes).is_unavailable());
	}

	#[test]
	fn forward_outcome_relay_unavailable_reply_fails_over() {
		let bytes = encoded_work_response(&ClusterWorkResponse::err(TransitStatus::Unavailable));
		assert!(ForwardOutcome::classify(RouteKind::PeerRelay, bytes).is_unavailable());
	}

	#[test]
	fn forward_outcome_peer_ok_reply_settles() {
		let bytes = encoded_work_response(&ClusterWorkResponse::ok(b"pong".to_vec()));
		assert!(!ForwardOutcome::classify(RouteKind::Peer, bytes).is_unavailable());
	}

	#[test]
	fn forward_outcome_peer_refusal_relays_unchanged() {
		let bytes = encoded_work_response(&ClusterWorkResponse::err(TransitStatus::PermissionDenied));
		assert!(!ForwardOutcome::classify(RouteKind::Peer, bytes).is_unavailable());
	}

	#[test]
	fn forward_outcome_garbled_peer_reply_fails_over() {
		let outcome = ForwardOutcome::classify(RouteKind::Peer, b"not-a-response".to_vec());
		assert!(matches!(outcome, ForwardOutcome::PeerGarbled));
		assert!(outcome.is_unavailable());
	}

	fn test_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = create_test_signing_key();
		ClusterConfig::new(ClusterTlsConfig {
			certificate: CertificateSpec::Der(&[]),
			key: Arc::new(Secp256k1KeyProvider::from(key)),
			validators: Vec::new(),
			client_validators: Vec::new(),
			hive_trust: None,
			peer_trust: None,
		})
	}

	#[test]
	fn relayed_work_stamps_a_decremented_budget() {
		let work = relayed_work(ping_type(), vec![1], HopBudget::for_test(2));
		assert_eq!(work.hops_remaining, 1);
	}

	#[test]
	fn relayed_work_saturates_a_spent_budget_at_zero() {
		let work = relayed_work(ping_type(), vec![1], HopBudget::for_test(0));
		assert_eq!(work.hops_remaining, 0);
	}

	// Pins the on-wire budget. Dropping the decrement in `relayed_work`
	// fails here even when integration topologies mask it with a clamp.
	#[test]
	fn relayed_envelope_carries_the_decremented_budget_on_the_wire() -> Result<(), TightBeamError> {
		let envelope = encode(&ClusterRequest::Work(relayed_work(
			ping_type(),
			vec![7],
			HopBudget::for_test(2),
		)))?;

		let decoded = decode::<ClusterRequest>(&envelope)?;
		assert!(matches!(decoded, ClusterRequest::Work(work) if work.hops_remaining == 1));
		Ok(())
	}

	/// Balancer double that answers with an out-of-range index.
	struct RogueBalancer;

	impl LoadBalancer for RogueBalancer {
		fn select(&self, _candidates: &[InstanceMetrics]) -> Option<usize> {
			Some(usize::MAX)
		}
	}

	/// Balancer double that always picks the first candidate.
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
		let entries = vec![Arc::new(peer_entry(b"first", b"first:1"))];
		let config = config_balancing_with(Arc::new(RogueBalancer));
		assert!(config.pick_instance(&entries).is_none());
	}

	#[test]
	fn a_draw_returns_the_selected_entry() {
		let entries = vec![Arc::new(peer_entry(b"first", b"first:1"))];
		let config = config_balancing_with(Arc::new(FirstBalancer));
		let picked = config.pick_instance(&entries);
		assert!(matches!(picked, Some(entry) if entry.dial_target().as_ref() == b"first:1"));
	}

	#[test]
	fn hop_budget_clamps_the_origin_sentinel_to_policy() {
		assert_eq!(HopBudget::from_wire(DEFAULT_HOP_BUDGET, 1).wire(), 1);
	}

	#[test]
	fn hop_budget_honors_a_relayed_value_below_policy() {
		assert_eq!(HopBudget::from_wire(1, 3).wire(), 1);
	}

	#[test]
	fn hop_budget_zero_policy_disables_forwarding() {
		let budget = HopBudget::from_wire(DEFAULT_HOP_BUDGET, 0);
		assert_eq!(budget.wire(), 0);
		assert!(!budget.allows_forward());
	}

	/// An origin request carries the sentinel, so anything below it
	/// reached this gateway through a relay.
	#[test]
	fn an_origin_budget_reads_as_direct() {
		assert!(!HopBudget::from_wire(DEFAULT_HOP_BUDGET, DEFAULT_HOP_BUDGET).is_relayed());
		assert!(HopBudget::from_wire(2, 4).is_relayed());
	}

	// The relayed fact comes from the wire count, not the clamped one.
	// A cap below the origin sentinel would otherwise mark every direct
	// caller relayed and refuse it at the export boundary.
	#[test]
	fn a_clamped_origin_budget_still_reads_as_direct() {
		assert!(!HopBudget::from_wire(DEFAULT_HOP_BUDGET, DEFAULT_MAX_HOPS).is_relayed());
	}

	/// A relay trail spends one hop at the relay, so a shorter budget
	/// could never select it.
	#[test]
	fn a_relay_trail_needs_two_forwards() {
		assert!(!HopBudget::from_wire(1, 4).allows_relay_trail());
		assert!(HopBudget::from_wire(2, 4).allows_relay_trail());
	}

	#[test]
	fn select_route_withholds_relay_trails_below_two_hops() -> Result<(), ClusterError> {
		let config = test_config();
		let registry = ServletRegistry::default();
		registry.add(relay_entry(b"origin", b"relay", b"relay:1"))?;

		let type_key = canonical_bytes(&ping_type());
		let below = registry.select_route(&config, &type_key, HopBudget::for_test(1), None);
		let at_gate = registry.select_route(&config, &type_key, HopBudget::for_test(2), None);
		assert!(below.is_none());
		assert!(matches!(at_gate, Some(choice) if choice.route_kind == RouteKind::PeerRelay));
		Ok(())
	}

	#[test]
	fn select_route_excludes_the_failed_route_key() -> Result<(), ClusterError> {
		let config = test_config();
		let registry = ServletRegistry::default();
		registry.add(peer_entry(b"first", b"first:1"))?;
		registry.add(peer_entry(b"second", b"second:1"))?;

		let type_key = canonical_bytes(&ping_type());
		let failed = registry
			.select_route(&config, &type_key, HopBudget::for_test(1), None)
			.map(|choice| choice.route_key);

		let failed = failed.as_deref();
		let retry = registry.select_route(&config, &type_key, HopBudget::for_test(1), failed);
		assert!(matches!((failed, &retry), (Some(first), Some(next)) if next.route_key.as_ref() != first));
		Ok(())
	}
}
