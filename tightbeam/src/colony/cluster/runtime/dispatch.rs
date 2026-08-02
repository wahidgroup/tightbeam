//! Thin gateway request router for unary control frames.
//!
//! [`handle_gateway_request`] evaluates gate policies, decodes the request
//! envelope, and dispatches by [`ClusterRequest`] variant. Export gates run
//! only on the work arm, where the servlet target is known after decode.
//!
//! # Evaluation order
//!
//! 1. [`evaluate_gates`] on the request frame and session.
//! 2. Decode [`ClusterRequest`] from the frame body.
//! 3. On [`ClusterRequest::Work`], [`evaluate_export_gates`] with
//!    [`spent_relay_budget`] before [`handle_work`].
//! 4. Route all other variants to their handlers (registration, gossip, etc.).

use core::hash::Hash;
use core::str::FromStr;

use crate::colony::cluster::runtime::bounds::{ClusterDigest, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::gossip_handler::handle_peer_ad;
use crate::colony::cluster::runtime::registration::{handle_address_update, handle_register};
use crate::colony::cluster::runtime::verify::{evaluate_export_gates, evaluate_gates, spent_relay_budget};
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

/// Route one unary gateway request from frame decode through dispatch.
///
/// Gate policies run first. Export gates run on the work arm only, after the
/// servlet target is known from the decoded envelope.
///
/// - `frame`: admitted unary control frame
/// - `session`: caller identity facts for the connection
/// - `ctx`: shared gateway runtime state (registry, config, trace, pools)
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
	if let Err(status) = evaluate_gates(Some(&frame), &session, &ctx.config, &ctx.trace) {
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
			// Export gates: target and relayed flag are known after decode.
			let relayed = spent_relay_budget(request.hops_remaining);
			if let Err(status) =
				evaluate_export_gates(&request.servlet_type, &session, relayed, &ctx.config, &ctx.trace)
			{
				return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(status));
			}

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
