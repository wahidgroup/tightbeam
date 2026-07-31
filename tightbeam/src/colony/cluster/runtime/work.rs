//! Work routing: select a route, forward payload, update pheromone scores.

use crate::crypto::profiles::DefaultCryptoProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::ClusterPool;
use crate::colony::cluster::{ClusterConfig, ClusterError, ServletRegistry};
use crate::colony::common::reply_frame;
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

fn work_trail_ok(
	servlet_registry: &ServletRegistry,
	route_key: &Arc<[u8]>,
	config: &ClusterConfig,
	trace: &TraceCollector,
) {
	let _ = servlet_registry.reinforce(route_key, config.pheromone.reinforcement_boost);
	let _ = trace.event(crate::instrumentation::events::CLUSTER_WORK_ROUTED);
}

fn work_trail_weaken(
	servlet_registry: &ServletRegistry,
	route_key: &Arc<[u8]>,
	config: &ClusterConfig,
	trace: &TraceCollector,
) {
	let _ = servlet_registry.weaken_with_penalty(route_key, config.pheromone.weakening_penalty);
	let _ = trace.event(crate::instrumentation::events::CLUSTER_WORK_FAILED);
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
	reply_frame(
		&frame.metadata.id,
		crate::colony::cluster::ClusterWorkResponse::err(status),
	)
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
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ crate::transport::state::EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	let addr_str =
		core::str::from_utf8(&addr).map_err(|_| crate::colony::cluster::ClusterError::InvalidAddress(addr.to_vec()))?;
	let parsed_addr: P::Address = addr_str
		.parse()
		.map_err(|_| crate::colony::cluster::ClusterError::InvalidAddress(addr.to_vec()))?;

	let mut metadata = crate::Metadata::default();
	metadata.id = b"work-forward".to_vec();

	let frame = crate::Frame {
		version: crate::Version::V0,
		metadata,
		message: payload,
		integrity: None,
		nonrepudiation: None,
	};

	let mut client = pool
		.connect(parsed_addr)
		.await
		.map_err(|_| crate::colony::cluster::ClusterError::ConnectFailed)?;

	let mut response = match client.emit(frame, None).await {
		Ok(Some(r)) => r,
		Ok(None) => {
			return Err(crate::colony::cluster::ClusterError::NoResponse);
		}
		Err(e) => {
			return Err(crate::colony::cluster::ClusterError::from(e));
		}
	};

	Ok::<_, crate::colony::cluster::ClusterError>(core::mem::take(&mut response.message))
}

pub(crate) async fn handle_work<P>(
	frame: Frame,
	request: crate::colony::common::ClusterWorkRequest,
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
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ crate::transport::state::EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	// A work target must be a servlet URN in this gateway's
	// namespace; foreign authorities and realms are refused
	// before the registry is consulted.
	if !crate::colony::common::is_bare_servlet_type(&config.namespace, &request.servlet_type) {
		let _ = trace.event(crate::instrumentation::events::CLUSTER_WORK_REFUSED);
		return reply_frame(
			&frame.metadata.id,
			crate::colony::cluster::ClusterWorkResponse::err(crate::policy::TransitStatus::PermissionDenied),
		);
	}

	let type_key = crate::colony::common::canonical_bytes(&request.servlet_type);
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
			let _ = trace.event(crate::instrumentation::events::CLUSTER_WORK_UNAVAILABLE);
			return reply_frame(
				&frame.metadata.id,
				crate::colony::cluster::ClusterWorkResponse::err(crate::policy::TransitStatus::Unavailable),
			);
		}
	};

	let metrics: Vec<crate::colony::common::InstanceMetrics> = entries
		.iter()
		.map(|e| crate::colony::common::InstanceMetrics {
			instance_key: e.route_key().to_vec(),
			pheromone: e.pheromone_level(),
		})
		.collect();

	let selected_idx = match config.load_balancer.select(&metrics) {
		Some(idx) => idx,
		None => {
			let _ = trace.event(crate::instrumentation::events::CLUSTER_WORK_UNAVAILABLE);
			return reply_frame(
				&frame.metadata.id,
				crate::colony::cluster::ClusterWorkResponse::err(crate::policy::TransitStatus::Unavailable),
			);
		}
	};

	let selected_entry = &entries[selected_idx];
	let route_key = std::sync::Arc::clone(selected_entry.route_key());
	let dial_addr = std::sync::Arc::clone(selected_entry.dial_target());
	let route_kind = selected_entry.route_kind();

	// Local hops carry bare app payload on the hive trust plane.
	// Peer hops re-enter the peer gateway as Work{forwarded:true}
	// on the peer trust plane.
	let forward_result = match route_kind {
		crate::colony::cluster::RouteKind::Local => forward_work(&pool, dial_addr, payload).await,
		crate::colony::cluster::RouteKind::Peer => match peer_pool.as_ref() {
			Some(peer_pool) => match crate::encode(&crate::colony::common::ClusterRequest::Work(
				crate::colony::common::ClusterWorkRequest::new(servlet_type, payload).into_forwarded(),
			)) {
				Ok(envelope) => forward_work(peer_pool, dial_addr, envelope).await,
				Err(error) => Err(crate::colony::cluster::ClusterError::from(error)),
			},
			None => Err(crate::colony::cluster::ClusterError::ConnectFailed),
		},
	};

	// Pheromone feedback: the outcome steers future selection
	// toward instances that answer and away from ones that fail
	match forward_result {
		Ok(response_payload) => match route_kind {
			crate::colony::cluster::RouteKind::Local => {
				work_trail_ok(&servlet_registry, &route_key, &config, &trace);
				reply_frame(
					&frame.metadata.id,
					crate::colony::cluster::ClusterWorkResponse::ok(response_payload),
				)
			}
			crate::colony::cluster::RouteKind::Peer => {
				// Peer gateways reply with ClusterWorkResponse; unwrap
				// and relay so the client sees one envelope.
				match crate::decode::<crate::colony::cluster::ClusterWorkResponse>(&response_payload) {
					Ok(peer_response) => {
						let _ = trace.event(crate::instrumentation::events::CLUSTER_WORK_FORWARDED);
						if peer_response.status == crate::policy::TransitStatus::Ok {
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
						crate::policy::TransitStatus::Unavailable,
					),
				}
			}
		},
		Err(error) => {
			// A servlet refusal relays verbatim so the caller keeps
			// its retryability contract.
			let status = match error {
				crate::colony::cluster::ClusterError::Transport(
					crate::transport::error::TransportError::OperationFailed(failure),
				) => {
					crate::policy::TransitStatus::try_from(failure).unwrap_or(crate::policy::TransitStatus::Unavailable)
				}
				_ => crate::policy::TransitStatus::Unavailable,
			};
			work_trail_fail(&servlet_registry, &route_key, &config, &trace, &frame, status)
		}
	}
}
