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
use crate::decode;
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

		let Ok(request) = decode::<ClusterRequest>(frame.message()) else {
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
	use crate::colony::cluster::runtime::bounds::fixtures::self_peering_config;
	use crate::colony::cluster::{CertificateSpec, ClusterConfig, ClusterTlsConfig, StaticExportList};
	use crate::colony::protocol::{PeerAdvertisement, RegisterHiveRequest};
	use crate::colony::urn::ColonyNamespace;
	use crate::constants::DEFAULT_HOP_BUDGET;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
	use crate::crypto::x509::KeyCurves;
	use crate::encode;
	use crate::instrumentation::events::{
		CLUSTER_EDGE_REFUSED, CLUSTER_EXPORT_REFUSED, CLUSTER_GATE_BLOCKED, CLUSTER_GOSSIP_REFUSED,
		CLUSTER_PEER_ADVERTISE_REFUSED, CLUSTER_REGISTER_REFUSED, CLUSTER_WORK_UNAVAILABLE,
	};
	use crate::policy::GatePolicy;
	use crate::testing::{TestCertificate, TestFrame, TestKey};
	use crate::trace::TraceCollector;
	use crate::transport::TokioListener;
	use crate::urn::Urn;
	use crate::Version;

	/// The gateway socket that a test advertisement claims.
	const AD_GATEWAY: &[u8] = b"192.0.2.7:9000";

	/// A gate policy that refuses every request.
	struct RefuseAll;

	impl GatePolicy for RefuseAll {
		fn evaluate(&self, _frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
			TransitStatus::PermissionDenied
		}
	}

	/// A gateway request context beside the trace and the connection trace
	/// that it records on.
	struct Audited {
		gateway: GatewayRuntimeCtx<TokioListener>,
		trace: Arc<TraceCollector>,
		connections: Arc<TraceCollector>,
	}

	impl Audited {
		/// A gateway under `config`, with two traces of its own.
		fn of(config: ClusterConfig) -> Self {
			let (trace, connections) = (Arc::new(TraceCollector::new()), Arc::new(TraceCollector::new()));
			let gateway = GatewayRuntimeCtx::for_test(config, &trace, &connections);
			Self { gateway, trace, connections }
		}

		/// The count of `event` on the trace, then on the connection trace.
		fn counts(&self, event: Urn<'static>) -> (usize, usize) {
			(self.trace.recorded(&event), self.connections.recorded(&event))
		}

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

		/// `request` in a frame that the gateway's own identity signs.
		async fn signed(&self, request: ClusterRequest) -> Result<Frame, TightBeamError> {
			let config = &self.gateway.config;
			let order = config.clock.unix().get();
			let builder = FrameBuilder::from(Version::V2)
				.with_id(b"signed")
				.with_order(order)
				.with_message(request);

			let mut frame = config.witnessed(builder).build()?;
			frame.sign_with_provider(config.tls.identity()).await?;
			Ok(frame)
		}
	}

	/// The TLS material of a gateway under the fixed test key.
	fn house_tls() -> ClusterTlsConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let spec = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		tls.expect("the test certificate must decode")
	}

	/// A gateway whose hive trust enrolls its own certificate.
	fn hive_trusting_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
		let builder = builder.with_certificate(certificate);

		let hive_trust: Arc<dyn CertificateTrust> = Arc::new(builder.expect("the hive enrolls").build());
		ClusterConfig::new(house_tls().with_hive_trust(hive_trust))
	}

	/// The servlet type `name` of the default namespace.
	fn servlet(name: &str) -> Urn<'static> {
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	/// `request` in a frame that no signature covers.
	fn unsigned(request: ClusterRequest) -> Result<Frame, TightBeamError> {
		FrameBuilder::from(Version::V0)
			.with_id(b"anonymous")
			.with_order(1)
			.with_message(request)
			.build()
	}

	/// An unsigned work request for the servlet type `name`.
	fn work_for(name: &str) -> Result<Frame, TightBeamError> {
		let payload = encode(&TestFrame::v0(Some("client"), Some("work")))?;
		let work = ClusterWorkRequest { servlet_type: servlet(name), payload, hops_remaining: DEFAULT_HOP_BUDGET };
		unsigned(ClusterRequest::Work(work))
	}

	/// A registration of a hive whose address names no hive identity.
	fn nameless_registration() -> ClusterRequest {
		let request = RegisterHiveRequest { hive_addr: vec![0xff], servlet_addresses: Vec::new(), metadata: None };
		ClusterRequest::RegisterHive(request)
	}

	/// Work of an anonymous session records on the connection trace alone.
	#[tokio::test]
	async fn anonymous_work_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(ClusterConfig::new(house_tls()));
		let records = audited.records(work_for("nobody")?, SessionContext::default(), CLUSTER_WORK_UNAVAILABLE);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}

	/// Work of a session that proved its peer records on the audit trace.
	#[tokio::test]
	async fn work_of_a_proven_peer_records_on_the_audit_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(ClusterConfig::new(house_tls()));
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let session = SessionContext::for_peer(Arc::new(TestCertificate::self_signed(&key)));

		let records = audited.records(work_for("nobody")?, session, CLUSTER_WORK_UNAVAILABLE);
		assert_eq!(records.await?, (1, 0));
		Ok(())
	}

	/// A gate refusal of an anonymous request records on the connection trace.
	#[tokio::test]
	async fn an_anonymous_gate_refusal_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let mut config = ClusterConfig::new(house_tls());
		config.policies.push(Arc::new(RefuseAll));

		let audited = Audited::of(config);
		let records = audited.records(work_for("ping")?, SessionContext::default(), CLUSTER_GATE_BLOCKED);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}

	/// An export refusal of anonymous work records on the connection trace.
	#[tokio::test]
	async fn an_anonymous_export_refusal_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let mut config = ClusterConfig::new(house_tls());
		config.peer.exported_types = Some(Arc::new(StaticExportList::new(vec![servlet("other")])));

		let audited = Audited::of(config);
		let records = audited.records(work_for("ping")?, SessionContext::default(), CLUSTER_EXPORT_REFUSED);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}

	/// An edge refusal of an anonymous call records on the connection trace.
	#[tokio::test]
	async fn an_anonymous_edge_refusal_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(ClusterConfig::new(house_tls()));
		let records = audited.edge_records(unsigned(nameless_registration())?, CLUSTER_EDGE_REFUSED);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}

	/// An unsigned registration records its refusal on the connection trace.
	#[tokio::test]
	async fn an_unsigned_registration_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(hive_trusting_config());
		let frame = unsigned(nameless_registration())?;

		let records = audited.records(frame, SessionContext::default(), CLUSTER_REGISTER_REFUSED);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}

	/// A verified registration's refusal records on the audit trace.
	#[tokio::test]
	async fn a_verified_registration_refusal_records_on_the_audit_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(hive_trusting_config());
		let frame = audited.signed(nameless_registration()).await?;

		let records = audited.records(frame, SessionContext::default(), CLUSTER_REGISTER_REFUSED);
		assert_eq!(records.await?, (1, 0));
		Ok(())
	}

	/// An unsigned advertisement records its refusal on the connection trace.
	#[tokio::test]
	async fn an_unsigned_advertisement_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(self_peering_config());
		let advertisement = PeerAdvertisement { gateway_addr: AD_GATEWAY.to_vec(), advertised_types: Vec::new() };
		let frame = unsigned(ClusterRequest::AdvertisePeer(advertisement))?;

		let records = audited.records(frame, SessionContext::default(), CLUSTER_PEER_ADVERTISE_REFUSED);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}

	/// A verified advertisement's refusal records on the audit trace.
	#[tokio::test]
	async fn a_verified_advertisement_refusal_records_on_the_audit_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(self_peering_config());
		audited.gateway.config.peer.table.poison();

		let signed = audited.gateway.config.mint_ad_frame(AD_GATEWAY, vec![servlet("ping")]).await?;
		let frame = signed.frame().clone();

		let records = audited.records(frame, SessionContext::default(), CLUSTER_PEER_ADVERTISE_REFUSED);
		assert_eq!(records.await?, (1, 0));
		Ok(())
	}

	/// An unsigned rumor relay records its refusal on the connection trace.
	#[tokio::test]
	async fn an_unsigned_rumor_records_on_the_connection_trace() -> Result<(), TightBeamError> {
		let audited = Audited::of(self_peering_config());
		let rumor = Box::new(TestFrame::v0(Some("rumor"), None));
		let frame = unsigned(ClusterRequest::Gossip(rumor))?;

		let records = audited.records(frame, SessionContext::default(), CLUSTER_GOSSIP_REFUSED);
		assert_eq!(records.await?, (0, 1));
		Ok(())
	}
}
