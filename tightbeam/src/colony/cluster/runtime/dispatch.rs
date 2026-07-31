//! Thin gateway request router: gates, then match on ClusterRequest.

use core::hash::Hash;
use core::str::FromStr;

use crate::colony::cluster::runtime::bounds::{ClusterDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::gossip_handler::handle_peer_ad;
use crate::colony::cluster::runtime::registration::{handle_address_update, handle_register};
use crate::colony::cluster::runtime::verify::evaluate_gates;
use crate::colony::cluster::runtime::work::handle_work;
use crate::colony::cluster::ClusterWorkResponse;
use crate::colony::common::{reply_frame, ClusterRequest};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::decode;
use crate::policy::{SessionContext, TransitStatus};
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::colony::cluster::runtime::gossip_handler::{handle_gossip_relay, handle_publish, handle_reconcile};

pub(crate) async fn handle_gateway_request<P, D>(
	frame: Frame,
	session: SessionContext,
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
	D: ClusterDigest,
{
	if let Err(status) = evaluate_gates(&frame, &session, &ctx.config, &ctx.trace) {
		return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(status));
	}

	let cluster_request = match decode::<ClusterRequest>(&frame.message) {
		Ok(request) => request,
		Err(_) => {
			return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::PermissionDenied));
		}
	};

	match cluster_request {
		ClusterRequest::RegisterHive(request) => {
			handle_register(
				frame,
				request,
				ctx.registry,
				ctx.servlet_registry,
				ctx.config,
				ctx.trace,
				&ctx.replay_guard,
			)
			.await
		}
		ClusterRequest::ServletAddressUpdate(update) => {
			handle_address_update(
				frame,
				update,
				ctx.registry,
				ctx.servlet_registry,
				ctx.config,
				ctx.trace,
				&ctx.replay_guard,
			)
			.await
		}
		ClusterRequest::Work(request) => {
			handle_work(
				frame,
				request,
				ctx.servlet_registry,
				ctx.config,
				ctx.pool,
				ctx.peer_pool,
				ctx.trace,
			)
			.await
		}
		ClusterRequest::AdvertisePeer(advertisement) => {
			handle_peer_ad(
				frame,
				advertisement,
				ctx.servlet_registry,
				ctx.config,
				ctx.trace,
				&ctx.replay_guard,
			)
			.await
		}
		#[cfg(feature = "x509")]
		ClusterRequest::Gossip(rumor) => {
			handle_gossip_relay::<P, D>(
				frame,
				rumor,
				ctx.servlet_registry,
				ctx.config,
				ctx.pool,
				ctx.peer_pool,
				ctx.trace,
			)
			.await
		}
		#[cfg(feature = "x509")]
		ClusterRequest::PublishGossip(body) => {
			handle_publish::<P, D>(
				frame,
				body,
				ctx.servlet_registry,
				ctx.config,
				ctx.pool,
				ctx.peer_pool,
				ctx.trace,
			)
			.await
		}
		#[cfg(feature = "x509")]
		ClusterRequest::ReconcileGossip(reconciliation) => {
			handle_reconcile(
				frame,
				reconciliation,
				ctx.servlet_registry,
				ctx.config,
				ctx.trace,
				&ctx.replay_guard,
			)
			.await
		}
	}
}
