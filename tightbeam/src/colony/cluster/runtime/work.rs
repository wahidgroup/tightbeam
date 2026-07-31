//! Work routing: select a route, forward payload, update pheromone scores.

use core::hash::Hash;
use core::mem;
use core::str::{self, FromStr};
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::ClusterPool;
use crate::colony::cluster::{ClusterConfig, ClusterError, ClusterWorkResponse, RouteKind, ServletRegistry};
use crate::colony::common::{
	canonical_bytes, is_bare_servlet_type, reply_frame, ClusterRequest, ClusterWorkRequest, InstanceMetrics,
};
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
use crate::{Frame, Metadata, TightBeamError, Version};

fn work_trail_ok(
	servlet_registry: &ServletRegistry,
	route_key: &Arc<[u8]>,
	config: &ClusterConfig,
	trace: &TraceCollector,
) {
	let _ = servlet_registry.reinforce(route_key, config.pheromone.reinforcement_boost);
	let _ = trace.event(CLUSTER_WORK_ROUTED);
}

fn work_trail_weaken(
	servlet_registry: &ServletRegistry,
	route_key: &Arc<[u8]>,
	config: &ClusterConfig,
	trace: &TraceCollector,
) {
	let _ = servlet_registry.weaken_with_penalty(route_key, config.pheromone.weakening_penalty);
	let _ = trace.event(CLUSTER_WORK_FAILED);
}

fn work_trail_fail(
	servlet_registry: &ServletRegistry,
	route_key: &Arc<[u8]>,
	config: &ClusterConfig,
	trace: &TraceCollector,
	frame: &Frame,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	work_trail_weaken(servlet_registry, route_key, config, trace);
	reply_frame(&frame.metadata.id, ClusterWorkResponse::err(status))
}

pub(crate) async fn forward_work<P>(
	pool: &Arc<ClusterPool<P>>,
	addr: Arc<[u8]>,
	payload: Vec<u8>,
) -> Result<Vec<u8>, ClusterError>
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
	let addr_str = str::from_utf8(&addr).map_err(|_| ClusterError::InvalidAddress(addr.to_vec()))?;
	let parsed_addr: P::Address = addr_str.parse().map_err(|_| ClusterError::InvalidAddress(addr.to_vec()))?;

	let mut metadata = Metadata::default();
	metadata.id = b"work-forward".to_vec();

	let frame = Frame {
		version: Version::V0,
		metadata,
		message: payload,
		integrity: None,
		nonrepudiation: None,
	};

	let mut client = pool.connect(parsed_addr).await.map_err(|_| ClusterError::ConnectFailed)?;

	let mut response = match client.emit(frame, None).await {
		Ok(Some(r)) => r,
		Ok(None) => {
			return Err(ClusterError::NoResponse);
		}
		Err(e) => {
			return Err(ClusterError::from(e));
		}
	};

	let message = mem::take(&mut response.message);
	Ok(message)
}

pub(crate) async fn handle_work<P>(
	frame: Frame,
	request: ClusterWorkRequest,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	peer_pool: Option<Arc<ClusterPool<P>>>,
	trace: Arc<TraceCollector>,
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
	// A work target must be a servlet URN in this gateway's
	// namespace; foreign authorities and realms are refused
	// before the registry is consulted.
	if !is_bare_servlet_type(&config.namespace, &request.servlet_type) {
		trace.event(CLUSTER_WORK_REFUSED)?;
		return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::PermissionDenied));
	}

	let type_key = canonical_bytes(&request.servlet_type);
	let forwarded = request.forwarded;
	let servlet_type = request.servlet_type;
	let payload = request.payload;

	// One-hop loop guard: already-forwarded work selects Local only.
	// Origin work selects Local and Peer so pheromone can prefer
	// nearby nests while still failing over across the colony.
	let entries = if forwarded {
		servlet_registry.local_entries_for_type(&type_key)
	} else {
		servlet_registry.entries_for_type(&type_key)
	};
	let entries = match entries {
		Ok(e) if !e.is_empty() => e,
		_ => {
			trace.event(CLUSTER_WORK_UNAVAILABLE)?;
			return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::Unavailable));
		}
	};

	let metrics: Vec<InstanceMetrics> = entries
		.iter()
		.map(|e| InstanceMetrics { instance_key: e.route_key().to_vec(), pheromone: e.pheromone_level() })
		.collect();

	let selected_idx = match config.load_balancer.select(&metrics) {
		Some(idx) => idx,
		None => {
			trace.event(CLUSTER_WORK_UNAVAILABLE)?;
			return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::Unavailable));
		}
	};

	let selected_entry = &entries[selected_idx];
	let route_key = Arc::clone(selected_entry.route_key());
	let dial_addr = Arc::clone(selected_entry.dial_target());
	let route_kind = selected_entry.route_kind();

	// Local hops carry bare app payload on the hive trust plane.
	// Peer hops re-enter the peer gateway as Work{forwarded:true}
	// on the peer trust plane.
	let forward_result = match route_kind {
		RouteKind::Local => forward_work(&pool, dial_addr, payload).await,
		RouteKind::Peer => match peer_pool.as_ref() {
			Some(peer_pool) => {
				let work = ClusterWorkRequest::new(servlet_type, payload).into_forwarded();
				match encode(&ClusterRequest::Work(work)) {
					Ok(envelope) => forward_work(peer_pool, dial_addr, envelope).await,
					Err(error) => Err(ClusterError::from(error)),
				}
			}
			None => Err(ClusterError::ConnectFailed),
		},
	};

	// Pheromone feedback: the outcome steers future selection
	// toward instances that answer and away from ones that fail
	match forward_result {
		Ok(response_payload) => match route_kind {
			RouteKind::Local => {
				work_trail_ok(&servlet_registry, &route_key, &config, &trace);
				reply_frame(&frame.metadata.id, ClusterWorkResponse::ok(response_payload))
			}
			RouteKind::Peer => {
				// Peer gateways reply with ClusterWorkResponse; decode
				// and relay so the client sees one envelope.
				match decode::<ClusterWorkResponse>(&response_payload) {
					Ok(peer_response) => {
						trace.event(CLUSTER_WORK_FORWARDED)?;

						if peer_response.status == TransitStatus::Ok {
							work_trail_ok(&servlet_registry, &route_key, &config, &trace);
						} else {
							work_trail_weaken(&servlet_registry, &route_key, &config, &trace);
						}

						reply_frame(&frame.metadata.id, peer_response)
					}
					Err(_) => work_trail_fail(
						&servlet_registry,
						&route_key,
						&config,
						&trace,
						&frame,
						TransitStatus::Unavailable,
					),
				}
			}
		},
		Err(error) => {
			// A servlet refusal relays verbatim so the caller keeps
			// its retryability contract.
			let status = match error {
				ClusterError::Transport(TransportError::OperationFailed(failure)) => {
					TransitStatus::try_from(failure).unwrap_or(TransitStatus::Unavailable)
				}
				_ => TransitStatus::Unavailable,
			};
			work_trail_fail(&servlet_registry, &route_key, &config, &trace, &frame, status)
		}
	}
}
