//! The colony stack over a non-TCP transport: cluster, hive, and servlet
//! all bound to the in-memory "laser" protocol, work routed end to end.
//!
//! A laser tightbeam arrives at the cluster gateway and is relayed to a
//! servlet through the hive, every link encrypted and multiplexed.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature"
))]

use core::time::Duration;
use std::sync::Arc;

use tightbeam::der::Sequence;
use tightbeam::{
	at_least,
	builder::TypeBuilder,
	cluster,
	colony::{
		cluster::{ClusterConfig, ClusterRequest, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse},
		common::ColonyNamespace,
		hive::{Hive, HiveConfig, HiveTlsConfig},
		servlet::ServletConfig,
	},
	compose,
	crypto::{key::Secp256k1KeyProvider, x509::CertificateSpec},
	decode, encode, exactly, hive,
	instrumentation::events,
	policy::{SessionContext, TransitStatus},
	server, servlet, tb_assert_spec, tb_scenario,
	testing::{ClientEnv, ClusterEnv, SetupEnv},
	trace::TraceCollector,
	transport::{
		handshake::{negotiation::TransportOffer, HandshakeKeyManager},
		multiplex::StreamBody,
		serve::MuxService,
		ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig, TransportEncryptionConfig,
	},
	utils::compose as frame_compose,
	utils::urn::Urn,
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::laser::{LaserAddr, LaserListener};
use crate::common::security::expectation_failure;
use crate::common::x509::GatewayCerts;

pub(crate) const LASER_WORK_SENT: Urn<'static> = Urn::new("test", "event:laser/work-sent");
pub(crate) const LASER_WORK_STATUS: Urn<'static> = Urn::new("test", "event:laser/work-status");
pub(crate) const LASER_WORK_ECHOED: Urn<'static> = Urn::new("test", "event:laser/work-echoed");
pub(crate) const LASER_SERVER_STREAM_REPORTS_LENGTH: Urn<'static> =
	Urn::new("test", "event:laser/server-stream-reports-length");
pub(crate) const LASER_ROUTE_BEFORE_RESTART: Urn<'static> = Urn::new("test", "event:laser/route-before-restart");
pub(crate) const LASER_ROUTE_AFTER_RESTART: Urn<'static> = Urn::new("test", "event:laser/route-after-restart");

/// Stable airspace slot the restart scenario rebinds; far above the
/// slots `LaserAddr::ANY` assigns sequentially.
const RESTART_GATEWAY_ADDR: &str = "laser://9901";

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct BeamRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct BeamResponse {
	pub doubled: u32,
}

servlet! {
	LaserServlet<BeamRequest, EnvConfig = ()>,
	protocol: LaserListener,
	handle: |req, frame, _ctx| async move {
		let doubled = req.value * 2;
		let message = BeamResponse { doubled };
		let frame = compose! {
			V0: id: &frame.metadata.id,
				message: message
		}?;
		Ok(Some(frame))
	}
}

hive! {
	LaserHive,
	protocol: LaserListener
}

cluster! {
	LaserCluster,
	protocol: LaserListener
}

fn laser_certs() -> GatewayCerts {
	GatewayCerts::generate("CN=Laser Gateway")
}

fn laser_cluster_conf(certs: &GatewayCerts) -> ClusterConfig {
	let tls = ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.trust)),
		peer_trust: None,
	};

	let mut conf = ClusterConfig::new(tls);
	conf.pool_config.mux_offer = Some(TransportOffer::mux(8));
	conf
}

/// Type URN every laser scenario registers and targets.
fn beam_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("beam")
		.expect("test names satisfy the mint grammar")
}

fn laser_hive_conf(certs: &GatewayCerts) -> HiveConfig {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
		validators: vec![],
	});
	HiveConfig {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.trust)),
		mux_offer: Some(TransportOffer::mux(8)),
		..Default::default()
	}
}

fn laser_servlet_conf(certs: &GatewayCerts) -> Result<ServletConfig<LaserListener, BeamRequest>, TightBeamError> {
	let cert = CertificateSpec::Built(Box::new(certs.cert.to_owned()));
	let key = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));
	Ok(ServletConfig::<LaserListener, BeamRequest>::builder()
		.with_certificate(cert, key, vec![])?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

async fn start_laser_hive(
	trace: TraceCollector,
	certs: Arc<GatewayCerts>,
	conf: HiveConfig,
) -> Result<LaserHive, TightBeamError> {
	let config = Some(laser_servlet_conf(&certs)?);
	let trace = Arc::new(trace.share());
	let servlet = LaserServlet::start(Arc::clone(&trace), config).await?;

	let mut hive = LaserHive::new(Some(conf))?;
	hive.register(beam_urn(), servlet, |t| LaserServlet::start(t, None))?;
	hive.establish(trace).await?;
	Ok(hive)
}

/// Emit one beam work request through a gateway and decode the response.
async fn emit_beam_work(certs: &GatewayCerts, addr: LaserAddr) -> Result<ClusterWorkResponse, TightBeamError> {
	let work_request = ClusterRequest::Work(ClusterWorkRequest::new(beam_urn(), encode(&BeamRequest { value: 21 })?));

	let frame = frame_compose(Version::V0)
		.with_id(b"laser-work")
		.with_order(0)
		.with_message(work_request)
		.build()?;

	let mut client = ClientBuilder::<LaserListener>::builder()
		.with_trust_store(Arc::clone(&certs.trust))
		.build()
		.connect(addr)
		.await?;

	let response_frame: Frame = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
	decode(&response_frame.message)
}

/// Poll a gateway until it routes work: a freshly restarted gateway has
/// an empty registry until the hive's anti-entropy beat re-registers.
/// Branching lives here, not in scenarios.
async fn wait_for_routed(certs: &GatewayCerts, addr: LaserAddr) -> Result<ClusterWorkResponse, TightBeamError> {
	for _ in 0..50 {
		if let Ok(response) = emit_beam_work(certs, addr).await {
			if response.status == TransitStatus::Ok {
				return Ok(response);
			}
		}

		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	Err(expectation_failure("gateway never routed work after restart"))
}

/// Streaming-only service for the lone `server!` proof: answers with the
/// collected body length; other kinds refuse through the defaults.
#[derive(Clone)]
struct BeamLengthService;

impl MuxService for BeamLengthService {
	async fn streaming(&self, body: StreamBody, _session: SessionContext) -> Result<Option<Frame>, TightBeamError> {
		let bytes = body.into_bytes().await?;
		let doubled = bytes.len() as u32;
		let message = BeamResponse { doubled };
		let frame = compose! {
			V0: id: b"beam-length",
				message: message
		}?;
		Ok(Some(frame))
	}
}

tb_assert_spec! {
	pub LaserLoneServerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(LASER_SERVER_STREAM_REPORTS_LENGTH, exactly!(1), equals!(true))
		]
	}
}

// A lone `server!` (no colony) bound to the laser protocol serves a
// streaming interaction end to end: encryption, mux negotiation, and
// stream dispatch all go through the protocol traits.
tb_scenario! {
	name: lone_server_streams_over_laser_protocol,
	spec: LaserLoneServerSpec,
	environment ServiceClient {
		context: laser_certs(),
		server: |SetupEnv { context: certs, .. }| async move {
			let key_manager = HandshakeKeyManager::new(Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())));
			let config = TransportEncryptionConfig::new(certs.cert.to_owned(), key_manager);
			let (listener, addr) = <LaserListener as EncryptedProtocol>::bind_with(LaserAddr::ANY, config).await?;

			let handle = server! {
				protocol LaserListener: listener,
				policies: { with_mux_offer: [ Some(TransportOffer::mux(8)) ] },
				service: BeamLengthService
			};

			Ok((handle, addr))
		},
		client: |ClientEnv { trace, context: certs, addr }| async move {
			let pool = Arc::new(
				ConnectionPool::<LaserListener>::builder()
					.with_config(PoolConfig {
						idle_timeout: None,
						max_connections: 1,
						mux_offer: Some(TransportOffer::mux(8)),
					})
					.with_trust_store(Arc::clone(&certs.trust))
					.build(),
			);
			let lease = pool.connect(addr).await?;

			let (mut sink, response) = lease.open_stream()?;
			sink.push(b"lase").await?;
			sink.close_with(b"beam").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let decoded: BeamResponse = decode(&reply.message)?;
			let value = decoded.doubled == 8;
			trace.event_with(LASER_SERVER_STREAM_REPORTS_LENGTH, &[], value)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub LaserRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(LASER_WORK_SENT, exactly!(1)),
			(LASER_WORK_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(LASER_WORK_ECHOED, exactly!(1), equals!(42u32)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// A laser tightbeam reaches the cluster gateway and routes to a hive
// servlet: client -> cluster -> hive control -> servlet, all links on
// the in-memory laser protocol, all encrypted, all multiplexed.
tb_scenario! {
	name: cluster_routes_work_over_laser_protocol,
	spec: LaserRoutingSpec,
	environment Cluster {
		context: laser_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let trace = Arc::new(trace.share());
			let config = laser_cluster_conf(&certs);
			LaserCluster::start(trace, config).await
		},
		hives: |SetupEnv { trace, context: certs }| {
			let conf = laser_hive_conf(&certs);
			vec![start_laser_hive(trace, certs, conf)]
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			trace.event(LASER_WORK_SENT)?;

			let work_response = emit_beam_work(&certs, cluster.addr()).await?;
			trace.event_with(LASER_WORK_STATUS, &[], work_response.status)?;

			if let Some(payload) = work_response.payload {
				let beam_response: BeamResponse = decode(&payload)?;
				trace.event_with(LASER_WORK_ECHOED, &[], beam_response.doubled)?;
			}

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub LaserGatewayRestartSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(LASER_ROUTE_BEFORE_RESTART, exactly!(1), equals!(TransitStatus::Ok)),
			(LASER_ROUTE_AFTER_RESTART, exactly!(1), equals!(TransitStatus::Ok)),
			(events::HIVE_REREGISTERED, at_least!(1)),
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, at_least!(2))
		]
	}
}

// The gateway registry is soft state: a replacement gateway starts empty
// on the same stable address, the hive's anti-entropy beat re-registers
// within one interval, and work routes again -- no operator, no consensus,
// no persistence.
tb_scenario! {
	name: cluster_recovers_hive_after_gateway_restart,
	spec: LaserGatewayRestartSpec,
	environment Cluster {
		context: laser_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let trace = Arc::new(trace.share());
			let mut config = laser_cluster_conf(&certs);
			config.bind_addr = Some(RESTART_GATEWAY_ADDR.into());
			LaserCluster::start(trace, config).await
		},
		hives: |SetupEnv { trace, context: certs }| {
			let mut conf = laser_hive_conf(&certs);
			conf.reregister_interval = Some(Duration::from_millis(100));
			vec![start_laser_hive(trace, certs, conf)]
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let before = emit_beam_work(&certs, cluster.addr()).await?;
			trace.event_with(LASER_ROUTE_BEFORE_RESTART, &[], before.status)?;

			cluster.stop();

			let replacement = {
				let mut config = laser_cluster_conf(&certs);
				config.bind_addr = Some(RESTART_GATEWAY_ADDR.into());
				LaserCluster::start(Arc::new(trace.share()), config).await?
			};

			let after = wait_for_routed(&certs, replacement.addr()).await?;
			trace.event_with(LASER_ROUTE_AFTER_RESTART, &[], after.status)?;

			replacement.stop();
			Ok(())
		}
	}
}
