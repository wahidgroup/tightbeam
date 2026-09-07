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
//!    [`HopBudget::is_relayed`] before [`GatewayRuntimeCtx::handle_work`].
//! 4. Route all other variants to their handlers (registration, gossip, etc.).

use core::hash::Hash;
use core::str::FromStr;

use crate::colony::cluster::runtime::bounds::{ClusterDigest, GatewayPlane, GatewayRuntimeCtx};
use crate::colony::cluster::{ClusterWorkResponse, HopBudget};
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

use crate::colony::cluster::runtime::gossip_tasks::GossipPipelineCtx;

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
	/// Route one unary gateway request from frame decode through dispatch.
	///
	/// Gate policies run first. Export gates run on the work arm only,
	/// after the servlet target is known from the decoded envelope.
	///
	/// - `frame`: admitted unary control frame
	/// - `session`: caller identity facts for the connection
	/// - `plane`: accept plane the connection arrived on. The edge plane
	///   admits `Work` only and refuses every control variant.
	pub(crate) async fn handle_request<D: ClusterDigest>(
		self,
		frame: Frame,
		session: SessionContext,
		plane: GatewayPlane,
	) -> Result<Option<Frame>, TightBeamError> {
		let gate_status = self.config.evaluate_gates(Some(&frame), &session, &self.trace)?;
		if gate_status != TransitStatus::Ok {
			return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(gate_status));
		}

		let cluster_request = match decode::<ClusterRequest>(&frame.message) {
			Ok(request) => request,
			Err(_) => {
				return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::PermissionDenied));
			}
		};

		// The edge plane is a work-submission surface only.
		if plane == GatewayPlane::Edge && !matches!(cluster_request, ClusterRequest::Work(_)) {
			return reply_frame(&frame.metadata.id, ClusterWorkResponse::err(TransitStatus::PermissionDenied));
		}

		match cluster_request {
			ClusterRequest::RegisterHive(request) => self.handle_register(frame, request).await,
			ClusterRequest::ServletAddressUpdate(update) => self.handle_address_update(frame, update).await,
			ClusterRequest::Work(request) => {
				// Target and relayed flag are known after decode, so export
				// gates run on the Work arm.
				let budget = HopBudget::from_wire(request.hops_remaining, self.config.peer.max_hops);
				let export_status = self.config.evaluate_export_gates(
					&request.servlet_type,
					&session,
					budget.is_relayed(),
					&self.trace,
				)?;

				if export_status != TransitStatus::Ok {
					let message = ClusterWorkResponse::err(export_status);
					return reply_frame(&frame.metadata.id, message);
				}

				self.handle_work(frame, request, budget).await
			}
			ClusterRequest::AdvertisePeer(advertisement) => self.handle_peer_ad(frame, advertisement).await,
			ClusterRequest::Gossip(rumor) => GossipPipelineCtx::from(self).relay::<D>(frame, rumor).await,
			ClusterRequest::PublishGossip(body) => GossipPipelineCtx::from(self).publish::<D>(frame, body).await,
			ClusterRequest::ReconcileGossip(reconciliation) => self.handle_reconcile(frame, reconciliation).await,
		}
	}
}
