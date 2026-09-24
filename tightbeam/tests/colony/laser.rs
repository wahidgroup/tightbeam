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

use sha3::Sha3_256;
use tightbeam::der::Sequence;
use tightbeam::{
	at_least,
	builder::TypeBuilder,
	cluster,
	colony::{
		cluster::{Cluster, ClusterConfig, ClusterTlsConfig},
		common::ColonyNamespace,
		hive::{Hive, HiveConfig, HiveTlsConfig},
		servlet::ServletConfig,
		SubmitWork,
	},
	compose,
	crypto::{key::Secp256k1KeyProvider, x509::CertificateSpec},
	decode, exactly, hive,
	instrumentation::events,
	policy::TransitStatus,
	server, servlet, tb_assert_spec, tb_scenario,
	testing::{ClientEnv, ClusterEnv, SetupEnv},
	trace::TraceCollector,
	transport::{
		handshake::{negotiation::TransportOffer, HandshakeKeyManager},
		multiplex::StreamBody,
		serve::{CallContext, MuxService},
		ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig, TransportEncryptionConfig,
	},
	utils::time::{Clock, ManualClock},
	utils::urn::Urn,
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::laser::{LaserAddr, LaserListener};
use crate::common::security::expectation_failure;
use crate::common::x509::GatewayCerts;

pub(crate) const LASER_WORK_SENT: Urn<'static> = tightbeam::urn!("test", "event:laser/work-sent");
pub(crate) const LASER_WORK_STATUS: Urn<'static> = tightbeam::urn!("test", "event:laser/work-status");
pub(crate) const LASER_WORK_ECHOED: Urn<'static> = tightbeam::urn!("test", "event:laser/work-echoed");
pub(crate) const LASER_SERVER_STREAM_REPORTS_LENGTH: Urn<'static> =
	tightbeam::urn!("test", "event:laser/server-stream-reports-length");
pub(crate) const LASER_ROUTE_BEFORE_RESTART: Urn<'static> = tightbeam::urn!("test", "event:laser/route-before-restart");
pub(crate) const LASER_ROUTE_AFTER_RESTART: Urn<'static> = tightbeam::urn!("test", "event:laser/route-after-restart");
pub(crate) const LASER_UNROUTED_BEFORE_BEAT: Urn<'static> = tightbeam::urn!("test", "event:laser/unrouted-before-beat");

/// The restart scenario's re-announce interval. It is long enough that only
/// an advance of the hive clock can end it inside the test.
const REREGISTER_INTERVAL: Duration = Duration::from_secs(3600);

/// How many times the restart scenario yields to the runtime while the
/// re-announce it released lands. Each yield runs every task that is ready,
/// so the bound counts scheduler rounds, not time.
const REGISTRATION_ROUNDS: u32 = 10_000;

/// The stable airspace slot the restart scenario rebinds. It sits far
/// above the slots that `LaserAddr::ANY` assigns sequentially.
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
			V0: id: frame.metadata().id(),
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

/// The restart scenario's certificates and the clock its hive beats on.
struct LaserRestartCtx {
	certs: Arc<GatewayCerts>,
	clock: Arc<ManualClock>,
}

fn laser_restart_ctx() -> LaserRestartCtx {
	LaserRestartCtx { certs: Arc::new(laser_certs()), clock: Arc::new(ManualClock::default()) }
}

fn laser_cluster_conf(certs: &GatewayCerts) -> ClusterConfig {
	let tls = ClusterTlsConfig::new(
		CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
	)
	.expect("the test certificate must decode")
	.with_hive_trust(Some(Arc::clone(&certs.trust)));

	let mut conf = ClusterConfig::new(tls);
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf
}

/// Returns the type URN that every laser scenario registers and targets.
fn beam_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("beam")
		.expect("test names satisfy the mint grammar")
}

fn laser_hive_conf(certs: &GatewayCerts) -> HiveConfig {
	let hive_tls = Arc::new(
		HiveTlsConfig::new(
			CertificateSpec::Built(Box::new(certs.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
			vec![],
		)
		.expect("the hive TLS material must decode"),
	);

	let mut conf = HiveConfig {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.trust)),
		..Default::default()
	};
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf
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
	let config = laser_servlet_conf(&certs)?;
	let trace = Arc::new(trace.share());
	let servlet = LaserServlet::start(Arc::clone(&trace), config).await?;

	let mut hive = LaserHive::new(Some(conf))?;
	hive.register(beam_urn(), servlet, |t| LaserServlet::start(t, ServletConfig::default()))?;
	hive.establish(trace).await?;
	Ok(hive)
}

/// Submits one beam work request through a gateway via
/// [`SubmitWork::submit_work_to`] and returns the servlet's response
/// frame.
///
/// The typed request travels as the client's complete signed frame, so
/// the servlet receives the same envelope over the laser transport as
/// over any other protocol. A refusal surfaces as
/// [`TightBeamError::WorkRefused`].
async fn emit_beam_work(certs: &GatewayCerts, addr: &LaserAddr) -> Result<Frame, TightBeamError> {
	let mut inner = Version::V1
		.compose()
		.with_id(b"laser-beam")
		.with_order(0)
		.with_message(BeamRequest { value: 21 })
		.build()?;

	let provider = Secp256k1KeyProvider::from(certs.key.to_owned());
	inner.sign_with_provider::<Sha3_256, _>(&provider).await?;

	let mut client = ClientBuilder::<LaserListener>::builder()
		.with_trust_store(Arc::clone(&certs.trust))
		.build()
		.connect(addr.to_owned())
		.await?;

	client.submit_work_to(beam_urn(), &inner).await
}

/// Returns the status a gateway refused work with.
///
/// A served frame and any failure other than a gateway refusal are errors,
/// so a transport fault cannot pass for a gateway that had no route.
fn refusal_status(outcome: Result<Frame, TightBeamError>) -> Result<TransitStatus, TightBeamError> {
	match outcome {
		Err(TightBeamError::WorkRefused(status)) => Ok(status),
		Err(error) => Err(error),
		Ok(_) => Err(expectation_failure("the gateway served work before any hive registered")),
	}
}

/// Yields to the runtime until `cluster` holds `hives` registrations or
/// [`REGISTRATION_ROUNDS`] pass.
///
/// The scenario runtime runs on one thread, so each yield lets the hive's
/// beat and the gateway's handler make progress without a wait on the
/// operating system's clock. Branching lives here, not in the scenarios.
async fn wait_for_hives(cluster: &LaserCluster, hives: usize) -> Result<(), TightBeamError> {
	for _ in 0..REGISTRATION_ROUNDS {
		if cluster.hive_count()? >= hives {
			return Ok(());
		}

		tokio::task::yield_now().await;
	}

	Err(expectation_failure("the hive never re-registered with the replacement gateway"))
}

/// A streaming-only service for the lone `server!` proof. It answers with
/// the collected body length, and other interaction kinds refuse through
/// the defaults.
#[derive(Clone)]
struct BeamLengthService;

impl MuxService for BeamLengthService {
	async fn streaming(&self, body: StreamBody, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
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
		assertions: [
			(LASER_SERVER_STREAM_REPORTS_LENGTH, exactly!(1), equals!(true))
		]
	}
}

// A lone `server!` (no colony) bound to the laser protocol serves a
// streaming interaction end to end. Encryption, mux negotiation, and
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
						mux_offer: Some(Arc::new(TransportOffer::mux(8)))
					})
					.with_trust_store(Arc::clone(&certs.trust))
					.build(),
			);

			let lease = pool.connect(addr).await?;
			let (mut sink, response) = lease.open_stream()?;
			sink.push(b"lase").await?;
			sink.close_with(b"beam").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let decoded: BeamResponse = decode(reply.message())?;
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
// servlet. The path runs from the client through the cluster and hive
// control to the servlet. Every link uses the in-memory laser protocol,
// encrypted and multiplexed.
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

			// A served frame proves the gateway reported `Ok`, because the
			// client surface resolves any other status into `WorkRefused`.
			let servlet_frame = emit_beam_work(&certs, cluster.addr()).await?;
			trace.event_with(LASER_WORK_STATUS, &[], TransitStatus::Ok)?;

			let beam_response: BeamResponse = decode(servlet_frame.message())?;
			trace.event_with(LASER_WORK_ECHOED, &[], beam_response.doubled)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub LaserGatewayRestartSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(LASER_ROUTE_BEFORE_RESTART, exactly!(1), equals!(TransitStatus::Ok)),
			(LASER_UNROUTED_BEFORE_BEAT, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1)),
			(LASER_ROUTE_AFTER_RESTART, exactly!(1), equals!(TransitStatus::Ok)),
			(events::HIVE_REREGISTERED, at_least!(1)),
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, at_least!(2))
		]
	}
}

// The gateway registry is soft state. A replacement gateway starts empty
// on the same stable address, the hive's anti-entropy beat re-registers
// within one interval, and work routes again with no operator, no
// consensus, and no persistence. The hive and both gateways share a clock
// only this test moves, so the replacement routes only after the test lets
// one interval pass, and the frames the beat signs stay fresh at the
// gateway.
tb_scenario! {
	name: cluster_recovers_hive_after_gateway_restart,
	spec: LaserGatewayRestartSpec,
	environment Cluster {
		context: laser_restart_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let trace = Arc::new(trace.share());
			let mut config = laser_cluster_conf(&ctx.certs);
			config.bind_addr = Some(RESTART_GATEWAY_ADDR.into());
			config.clock = Arc::clone(&ctx.clock) as Arc<dyn Clock>;
			LaserCluster::start(trace, config).await
		},
		hives: |SetupEnv::<LaserRestartCtx> { trace, context: ctx }| {
			let mut conf = laser_hive_conf(&ctx.certs);
			conf.clock = Arc::clone(&ctx.clock) as Arc<dyn Clock>;
			conf.control.reregister_interval = Some(REREGISTER_INTERVAL);
			vec![start_laser_hive(trace, Arc::clone(&ctx.certs), conf)]
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			// Served frames prove the gateway reported `Ok` before and
			// after the restart, because refusals surface as errors instead.
			emit_beam_work(&ctx.certs, cluster.addr()).await?;

			trace.event_with(LASER_ROUTE_BEFORE_RESTART, &[], TransitStatus::Ok)?;

			cluster.stop();

			let replacement = {
				let mut config = laser_cluster_conf(&ctx.certs);
				config.bind_addr = Some(RESTART_GATEWAY_ADDR.into());
				config.clock = Arc::clone(&ctx.clock) as Arc<dyn Clock>;
				LaserCluster::start(Arc::new(trace.share()), config).await?
			};

			// An empty registry refuses the type as unavailable. Any other
			// failure fails the scenario instead of passing for that refusal.
			let unrouted = emit_beam_work(&ctx.certs, replacement.addr()).await;
			let refused = refusal_status(unrouted)?;
			trace.event_with(LASER_UNROUTED_BEFORE_BEAT, &[], refused)?;

			ctx.clock.advance(REREGISTER_INTERVAL);
			wait_for_hives(&replacement, 1).await?;
			emit_beam_work(&ctx.certs, replacement.addr()).await?;
			trace.event_with(LASER_ROUTE_AFTER_RESTART, &[], TransitStatus::Ok)?;

			replacement.stop();
			Ok(())
		}
	}
}
