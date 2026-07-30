//! Thin gateway request router: gates, then match on ClusterRequest.

use crate::crypto::profiles::DefaultCryptoProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, GatewayReplayGuard};
use crate::colony::cluster::runtime::gossip_handler::handle_peer_ad;
use crate::colony::cluster::runtime::registration::{handle_address_update, handle_register};
use crate::colony::cluster::runtime::verify::evaluate_gates;
use crate::colony::cluster::runtime::work::handle_work;
use crate::colony::cluster::{ClusterConfig, ClusterWorkResponse, HiveRegistry, ServletRegistry};
use crate::colony::common::{reply_frame, ClusterRequest};
use crate::decode;
use crate::policy::{SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::colony::cluster::runtime::gossip_handler::{handle_gossip_relay, handle_publish, handle_reconcile};

pub(crate) async fn handle_gateway_request<P, D>(
	frame: Frame,
	session: SessionContext,
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	peer_pool: Option<Arc<ClusterPool<P>>>,
	trace: Arc<TraceCollector>,
	replay_guard: GatewayReplayGuard,
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
	D: ClusterDigest,
{
	if let Err(status) = evaluate_gates(&frame, &session, &config, &trace) {
		return reply_frame(frame.metadata.id.clone(), ClusterWorkResponse::err(status));
	}

	let cluster_request = match decode::<ClusterRequest>(&frame.message) {
		Ok(request) => request,
		Err(_) => {
			return reply_frame(
				frame.metadata.id.clone(),
				ClusterWorkResponse::err(TransitStatus::PermissionDenied),
			);
		}
	};

	match cluster_request {
		ClusterRequest::RegisterHive(request) => {
			handle_register(frame, request, registry, servlet_registry, config, trace, &replay_guard).await
		}
		ClusterRequest::ServletAddressUpdate(update) => {
			handle_address_update(frame, update, registry, servlet_registry, config, trace, &replay_guard).await
		}
		ClusterRequest::Work(request) => {
			handle_work(frame, request, servlet_registry, config, pool, peer_pool, trace).await
		}
		ClusterRequest::AdvertisePeer(advertisement) => {
			handle_peer_ad(frame, advertisement, servlet_registry, config, trace, &replay_guard).await
		}
		#[cfg(feature = "x509")]
		ClusterRequest::Gossip(rumor) => {
			handle_gossip_relay::<P, D>(frame, rumor, servlet_registry, config, pool, peer_pool, trace).await
		}
		#[cfg(feature = "x509")]
		ClusterRequest::PublishGossip(body) => {
			handle_publish::<P, D>(frame, body, servlet_registry, config, pool, peer_pool, trace).await
		}
		#[cfg(feature = "x509")]
		ClusterRequest::ReconcileGossip(reconciliation) => {
			handle_reconcile(frame, reconciliation, config, trace, &replay_guard).await
		}
	}
}
