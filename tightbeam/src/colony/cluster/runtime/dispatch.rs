//! Gateway request router for unary control frames.
//!
//! [`GatewayRuntimeCtx::handle_request`] evaluates gate policies, decodes the
//! request envelope, and dispatches by [`ClusterRequest`] variant.
//! [`GatewayRuntimeCtx::handle_edge_request`] is the same path for an edge
//! accept plane, where the envelope narrows to a work request. Export gates
//! run only on the work arm, where the servlet target is known after decode.
//!
//! # Evaluation order
//!
//! 1. `evaluate_gates` on the request frame and session.
//! 2. Decode [`ClusterRequest`] from the frame body.
//! 3. On [`ClusterRequest::Work`], `evaluate_export_gates` with
//!    [`HopBudget::is_relayed`] before [`GatewayRuntimeCtx::handle_work`].
//! 4. Route every other variant to its handler, such as registration or gossip.

use crate::colony::cluster::runtime::bounds::{ClusterDigest, ColonyDialProtocol, GatewayRuntimeCtx};
use crate::colony::cluster::{ClusterWorkRequest, ClusterWorkResponse, HopBudget, WireHopBudget};
use crate::colony::common::{reply_frame, ClusterRequest};
use crate::decode;
use crate::policy::{SessionContext, TransitStatus};
use crate::Frame;
use crate::TightBeamError;

use crate::colony::cluster::runtime::gossip_tasks::GossipPipelineCtx;

/// Outcome of gating and decoding one unary control frame.
enum RequestAdmission {
	/// The envelope the gates admitted.
	Admitted(ClusterRequest),
	/// The status the caller answers the sender with.
	Refused(TransitStatus),
}

impl<P: ColonyDialProtocol> GatewayRuntimeCtx<P> {
	/// Route one unary gateway request from frame decode through dispatch.
	///
	/// Gate policies run first. Export gates run on the work arm only,
	/// after the servlet target is known from the decoded envelope.
	///
	/// - `frame`: admitted unary control frame
	/// - `session`: caller identity facts for the connection
	pub(crate) async fn handle_request<D: ClusterDigest>(
		self,
		frame: Frame,
		session: SessionContext,
	) -> Result<Option<Frame>, TightBeamError> {
		let cluster_request = match self.admit_request(&frame, &session)? {
			RequestAdmission::Admitted(request) => request,
			RequestAdmission::Refused(status) => {
				return reply_frame(frame.metadata().id(), ClusterWorkResponse::err(status));
			}
		};

		match cluster_request {
			ClusterRequest::RegisterHive(request) => self.handle_register(frame, request).await,
			ClusterRequest::ServletAddressUpdate(update) => self.handle_address_update(frame, update).await,
			ClusterRequest::Work(request) => self.handle_work_request(frame, session, request).await,
			ClusterRequest::AdvertisePeer(advertisement) => self.handle_peer_ad(frame, advertisement).await,
			ClusterRequest::Gossip(rumor) => GossipPipelineCtx::from(self).relay::<D>(frame, rumor).await,
			ClusterRequest::PublishGossip(body) => GossipPipelineCtx::from(self).publish::<D>(frame, body).await,
			ClusterRequest::ReconcileGossip(reconciliation) => self.handle_reconcile(frame, reconciliation).await,
		}
	}

	/// Route one unary request that arrived on an edge accept plane.
	///
	/// An edge plane is a work-submission surface, so the envelope narrows
	/// to [`ClusterWorkRequest`] here. Every other envelope, such as a
	/// registration, a peer advertisement, or a gossip rumor, answers
	/// [`TransitStatus::PermissionDenied`].
	pub(crate) async fn handle_edge_request(
		self,
		frame: Frame,
		session: SessionContext,
	) -> Result<Option<Frame>, TightBeamError> {
		let work = match self.admit_request(&frame, &session)? {
			RequestAdmission::Admitted(ClusterRequest::Work(request)) => request,
			RequestAdmission::Admitted(_) => {
				let refusal = ClusterWorkResponse::err(TransitStatus::PermissionDenied);
				return reply_frame(frame.metadata().id(), refusal);
			}
			RequestAdmission::Refused(status) => {
				return reply_frame(frame.metadata().id(), ClusterWorkResponse::err(status));
			}
		};

		self.handle_work_request(frame, session, work).await
	}

	/// Gate and decode one unary control frame.
	///
	/// This is the one parse of the request envelope. A refused gate and an
	/// undecodable envelope both answer with the status the caller replies
	/// with.
	fn admit_request(&self, frame: &Frame, session: &SessionContext) -> Result<RequestAdmission, TightBeamError> {
		let gate_status = self.config.evaluate_gates(Some(frame), session, &self.trace)?;
		if gate_status != TransitStatus::Ok {
			return Ok(RequestAdmission::Refused(gate_status));
		}

		let Ok(request) = decode::<ClusterRequest>(frame.message()) else {
			return Ok(RequestAdmission::Refused(TransitStatus::PermissionDenied));
		};

		Ok(RequestAdmission::Admitted(request))
	}

	/// Export-gate and route one work request.
	///
	/// The target and the relayed flag are known after decode, so export gates
	/// run here rather than beside the transport gates.
	async fn handle_work_request(
		self,
		frame: Frame,
		session: SessionContext,
		request: ClusterWorkRequest,
	) -> Result<Option<Frame>, TightBeamError> {
		let budget = HopBudget::from_wire(WireHopBudget::new(request.hops_remaining), self.config.peer.max_hops);
		let export_status =
			self.config
				.evaluate_export_gates(&request.servlet_type, &session, budget.is_relayed(), &self.trace)?;

		if export_status != TransitStatus::Ok {
			return reply_frame(frame.metadata().id(), ClusterWorkResponse::err(export_status));
		}

		self.handle_work(frame, request, budget).await
	}
}
