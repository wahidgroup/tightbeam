//! The gateway request router for unary control frames.
//!
//! [`GatewayRuntimeCtx::handle_request`] evaluates gate policies, decodes the
//! request envelope, and dispatches by [`ClusterRequest`] variant.
//! [`GatewayRuntimeCtx::handle_edge_request`] is the same path for an edge
//! accept plane, where the envelope narrows to a work request.
//!
//! # Evaluation order
//!
//! 1. Run [`evaluate_gates`] on the request frame and the session.
//! 2. Decode [`ClusterRequest`] from the frame body.
//! 3. On [`ClusterRequest::Work`], admit the target through [`admit_target`],
//!    which clamps the hop budget and runs the export gates, before
//!    [`GatewayRuntimeCtx::handle_work`].
//! 4. Route every other variant to its handler, such as registration or gossip.
//!
//! [`evaluate_gates`]: crate::colony::cluster::ClusterConfig::evaluate_gates
//! [`admit_target`]: crate::colony::cluster::ColonyConfig::admit_target

use crate::colony::cluster::runtime::bounds::{ColonyDialProtocol, GatewayRuntimeCtx};
use crate::colony::cluster::WireHopBudget;
use crate::colony::protocol::{ClusterRequest, ClusterWorkRequest, ClusterWorkResponse, ReplyForm};
use crate::policy::{SessionContext, TransitStatus};
use crate::Frame;
use crate::TightBeamError;

use crate::colony::cluster::runtime::gossip_tasks::GossipPipelineCtx;
use crate::colony::cluster::runtime::verify::RequestAudit;

/// The outcome of the gates and the decode for one unary control frame.
enum RequestAdmission {
	/// The envelope the gates admitted.
	Admitted(ClusterRequest),
	/// The status the caller answers the sender with.
	Refused(TransitStatus),
}

impl<P: ColonyDialProtocol> GatewayRuntimeCtx<P> {
	/// Route one unary gateway request from the gates through its handler, in
	/// the evaluation order of the module.
	///
	/// - `frame`: the unary control frame of the call, before the gates run
	/// - `session`: the identity facts of the caller's connection
	pub(crate) async fn handle_request(
		self,
		frame: Frame,
		session: SessionContext,
	) -> Result<Option<Frame>, TightBeamError> {
		let audit = self.audit(&session);
		let cluster_request = match self.admit_request(&frame, &session, &audit)? {
			RequestAdmission::Admitted(request) => request,
			RequestAdmission::Refused(status) => {
				return ReplyForm::Plain.reply(frame.metadata().id(), ClusterWorkResponse::err(status));
			}
		};

		match cluster_request {
			ClusterRequest::RegisterHive(request) => self.handle_register(frame, request, &audit).await,
			ClusterRequest::ServletAddressUpdate(update) => self.handle_address_update(frame, update, &audit).await,
			ClusterRequest::Work(request) => self.handle_work_request(frame, session, request, &audit).await,
			ClusterRequest::AdvertisePeer(advertisement) => self.handle_peer_ad(frame, advertisement, &audit).await,
			ClusterRequest::Gossip(rumor) => GossipPipelineCtx::from(self).relay(frame, rumor, &audit).await,
			ClusterRequest::PublishGossip(body) => GossipPipelineCtx::from(self).publish(frame, body, &audit).await,
			ClusterRequest::ReconcileGossip(reconciliation) => {
				self.handle_reconcile(frame, reconciliation, &audit).await
			}
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
		let audit = self.audit(&session);
		let work = match self.admit_request(&frame, &session, &audit)? {
			RequestAdmission::Admitted(ClusterRequest::Work(request)) => request,
			RequestAdmission::Admitted(_) => {
				let status = self.refuse_edge_call("unary", &session)?;
				let refusal = ClusterWorkResponse::err(status);
				return ReplyForm::Plain.reply(frame.metadata().id(), refusal);
			}
			RequestAdmission::Refused(status) => {
				return ReplyForm::Plain.reply(frame.metadata().id(), ClusterWorkResponse::err(status));
			}
		};

		self.handle_work_request(frame, session, work, &audit).await
	}

	/// Gate and decode one unary control frame.
	///
	/// It is the one parse of the request envelope. A refused gate and an
	/// undecodable envelope both give the status the caller replies with.
	fn admit_request(
		&self,
		frame: &Frame,
		session: &SessionContext,
		audit: &RequestAudit,
	) -> Result<RequestAdmission, TightBeamError> {
		let trace = audit.unproven();
		let gate_status = self.config.evaluate_gates(Some(frame), session, trace)?;
		if gate_status != TransitStatus::Ok {
			return Ok(RequestAdmission::Refused(gate_status));
		}

		let Ok(request) = frame.decode_message::<ClusterRequest>() else {
			return Ok(RequestAdmission::Refused(TransitStatus::PermissionDenied));
		};

		Ok(RequestAdmission::Admitted(request))
	}

	/// Export-gate and route one work request.
	///
	/// The decode names the target and the relayed flag, so export gates run
	/// here rather than beside the transport gates.
	async fn handle_work_request(
		self,
		frame: Frame,
		session: SessionContext,
		request: ClusterWorkRequest,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		let wire = WireHopBudget::new(request.hops_remaining);
		let trace = audit.unproven();
		let admitted = self.config.admit_target(&request.servlet_type, wire, &session, trace)?;
		let budget = match admitted {
			Ok(budget) => budget,
			Err(status) => return ReplyForm::Plain.reply(frame.metadata().id(), ClusterWorkResponse::err(status)),
		};

		self.handle_work(frame, request, budget, trace).await
	}
}

#[cfg(all(test, feature = "testing"))]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::builder::frame::FrameBuilder;
	use crate::builder::TypeBuilder;
	use crate::colony::cluster::runtime::bounds::fixtures::Audited;
	use crate::colony::cluster::{ClusterConfig, ClusterTlsConfig, StaticExportList};
	use crate::colony::protocol::{PeerAdvertisement, RegisterHiveRequest};
	use crate::colony::urn::ColonyNamespace;
	use crate::constants::DEFAULT_HOP_BUDGET;
	use crate::crypto::x509::store::CertificateTrust;
	use crate::encode;
	use crate::instrumentation::events::{
		CLUSTER_EDGE_REFUSED, CLUSTER_EXPORT_REFUSED, CLUSTER_GATE_BLOCKED, CLUSTER_GOSSIP_REFUSED,
		CLUSTER_PEER_ADVERTISE_REFUSED, CLUSTER_REGISTER_REFUSED, CLUSTER_WORK_UNAVAILABLE,
	};
	use crate::tb_cases;
	use crate::testing::fixtures::{TestGate, TestStore};
	use crate::testing::{TestCertificate, TestFrame, TestResult};
	use crate::urn::Urn;
	use crate::Version;

	/// The gateway socket that a test advertisement claims.
	const AD_GATEWAY: &[u8] = b"192.0.2.7:9000";

	impl Audited {
		/// The counts of `event` once the colony plane answers `frame` on
		/// `session`.
		async fn records(
			&self,
			frame: Frame,
			session: SessionContext,
			event: Urn<'static>,
		) -> Result<(usize, usize), TightBeamError> {
			self.gateway.clone().handle_request(frame, session).await?;
			Ok(self.counts(event))
		}

		/// The counts of `event` once the edge plane answers `frame` on an
		/// anonymous session.
		async fn edge_records(&self, frame: Frame, event: Urn<'static>) -> Result<(usize, usize), TightBeamError> {
			let gateway = self.gateway.clone();
			gateway.handle_edge_request(frame, SessionContext::default()).await?;
			Ok(self.counts(event))
		}
	}

	/// A gateway whose hive trust enrolls its own certificate.
	fn hive_trusting_config() -> ClusterConfig {
		let hive_trust: Arc<dyn CertificateTrust> = Arc::new(TestStore::holding([TestCertificate::insecure_fixed()]));
		ClusterConfig::new(ClusterTlsConfig::fixture().with_hive_trust(hive_trust))
	}

	/// A gateway whose gate refuses every request.
	fn refusing_config() -> ClusterConfig {
		let mut config = ClusterConfig::fixture();
		config.policies.push(Arc::new(TestGate(TransitStatus::PermissionDenied)));
		config
	}

	/// A gateway that exports the servlet type `name` alone.
	fn exporting_only(name: &str) -> ClusterConfig {
		let mut config = ClusterConfig::fixture();
		let exported = StaticExportList::new([ColonyNamespace::servlet_fixture(name)]);
		config.peer.exported_types = Some(Arc::new(exported));
		config
	}

	/// `request` in a frame that no signature covers.
	fn unsigned(request: ClusterRequest) -> Frame {
		let built = FrameBuilder::from(Version::V0)
			.with_id(b"anonymous")
			.with_order(1)
			.with_message(request)
			.build();

		built.expect("an unsigned request builds")
	}

	/// An unsigned work request for the servlet type `name`.
	fn work_for(name: &str) -> Frame {
		let payload = encode(&TestFrame::v0(Some("client"), Some("work"))).expect("a test frame encodes");
		let servlet_type = ColonyNamespace::servlet_fixture(name);
		let work = ClusterWorkRequest { servlet_type, payload, hops_remaining: DEFAULT_HOP_BUDGET };
		unsigned(ClusterRequest::Work(work))
	}

	/// A registration of a hive whose address names no hive identity.
	fn nameless_registration() -> ClusterRequest {
		let request = RegisterHiveRequest { hive_addr: vec![0xff], servlet_addresses: Vec::new(), metadata: None };
		ClusterRequest::RegisterHive(request)
	}

	/// A session whose handshake proved the holder of the fixed test key.
	fn proven_peer() -> SessionContext {
		SessionContext::for_peer(Arc::new(TestCertificate::insecure_fixed()))
	}

	/// The config of a gateway, a frame its colony plane answers on a
	/// session, the event the answer records, and the count of that event on
	/// the audit trace, then on the connection trace.
	type Refused = (ClusterConfig, Frame, SessionContext, Urn<'static>, (usize, usize));

	// A refusal records on the audit trace when the session proved its peer,
	// and on the connection trace alone when it proved none: the work of
	// either session that no route answers, a gate refusal, an export
	// refusal, and each request that a signature must cover and none covers.
	tb_cases! {
		async fn a_refusal_records_on_the_trace_its_session_names(
			(config, frame, session, event, counts): Refused
		) -> TestResult {
			let audited = Audited::of(config);
			let records = audited.records(frame, session, event).await?;
			assert_eq!(records, counts);
			Ok(())
		}
		cases {
			anonymous_work => (
				ClusterConfig::fixture(),
				work_for("nobody"),
				SessionContext::default(),
				CLUSTER_WORK_UNAVAILABLE,
				(0, 1),
			),
			proven_peer_work => (
				ClusterConfig::fixture(),
				work_for("nobody"),
				proven_peer(),
				CLUSTER_WORK_UNAVAILABLE,
				(1, 0),
			),
			anonymous_gate_refusal => (
				refusing_config(),
				work_for("ping"),
				SessionContext::default(),
				CLUSTER_GATE_BLOCKED,
				(0, 1),
			),
			anonymous_export_refusal => (
				exporting_only("other"),
				work_for("ping"),
				SessionContext::default(),
				CLUSTER_EXPORT_REFUSED,
				(0, 1),
			),
			unsigned_registration => (
				hive_trusting_config(),
				unsigned(nameless_registration()),
				SessionContext::default(),
				CLUSTER_REGISTER_REFUSED,
				(0, 1),
			),
			unsigned_advertisement => (
				ClusterConfig::self_peering(),
				unsigned(ClusterRequest::AdvertisePeer(PeerAdvertisement {
					gateway_addr: AD_GATEWAY.to_vec(),
					advertised_types: Vec::new(),
				})),
				SessionContext::default(),
				CLUSTER_PEER_ADVERTISE_REFUSED,
				(0, 1),
			),
			unsigned_rumor => (
				ClusterConfig::self_peering(),
				unsigned(ClusterRequest::Gossip(Box::new(TestFrame::v0(Some("rumor"), None)))),
				SessionContext::default(),
				CLUSTER_GOSSIP_REFUSED,
				(0, 1),
			),
		}
	}

	/// An edge refusal of an anonymous call records on the connection trace.
	#[tokio::test]
	async fn an_anonymous_edge_refusal_records_on_the_connection_trace() -> TestResult {
		let audited = Audited::of(ClusterConfig::fixture());
		let frame = unsigned(nameless_registration());

		let records = audited.edge_records(frame, CLUSTER_EDGE_REFUSED).await?;
		assert_eq!(records, (0, 1));
		Ok(())
	}

	/// A verified registration's refusal records on the audit trace.
	#[tokio::test]
	async fn a_verified_registration_refusal_records_on_the_audit_trace() -> TestResult {
		let audited = Audited::of(hive_trusting_config());
		let frame = audited.gateway.config.self_signed(b"signed", nameless_registration());
		let session = SessionContext::default();

		let records = audited.records(frame, session, CLUSTER_REGISTER_REFUSED).await?;
		assert_eq!(records, (1, 0));
		Ok(())
	}

	/// A verified advertisement's refusal records on the audit trace.
	#[tokio::test]
	async fn a_verified_advertisement_refusal_records_on_the_audit_trace() -> TestResult {
		let audited = Audited::of(ClusterConfig::self_peering());
		audited.gateway.config.peer.table.poison();

		let ping = vec![ColonyNamespace::servlet_fixture("ping")];
		let signed = audited.gateway.config.mint_ad_frame(AD_GATEWAY, ping).await?;

		let (frame, session) = (signed.frame().clone(), SessionContext::default());
		let records = audited.records(frame, session, CLUSTER_PEER_ADVERTISE_REFUSED).await?;
		assert_eq!(records, (1, 0));
		Ok(())
	}
}
