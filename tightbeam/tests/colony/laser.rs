//! The colony stack over a non-TCP transport. The cluster, the hive, and the
//! servlet all bind to the in-memory "laser" protocol, and work routes end to
//! end.
//!
//! A laser tightbeam arrives at the cluster gateway, which relays it to a
//! servlet through the hive, with every link encrypted and multiplexed.

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
		cluster::{Cluster, ClusterConfig, ClusterTlsConfig},
		hive::{Hive, HiveConfig, HiveTlsConfig},
		servlet::ServletConfig,
		urn::ColonyNamespace,
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
		handshake::negotiation::TransportOffer,
		multiplex::{CallContext, MuxService, StreamBody},
		ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedProtocol, PoolConfig, TransportEncryptionConfig,
	},
	urn::Urn,
	utils::time::{Clock, ManualClock},
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::hive::scenario_hive_config;
use crate::common::laser::{LaserAddr, LaserListener};
use crate::common::security::expectation_failure;
use crate::common::x509::{signing_identity, GatewayCerts};

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

/// The request whose `value` the laser servlet doubles.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct BeamRequest {
	/// The number the servlet doubles.
	pub value: u32,
}

/// The laser servlet's reply.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct BeamResponse {
	/// Twice the request's `value`.
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

/// The restart scenario's certificates and the clock its hive beats on. The
/// hive and both gateways share the clock, and only the test moves it, so
/// the replacement routes only after the test lets one interval pass, and the
/// frames the beat signs stay fresh at the gateway.
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
		..scenario_hive_config()
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
	hive.register(beam_urn(), servlet, |t| LaserServlet::start(t, ServletConfig::cleartext()))?;
	hive.establish(trace).await?;
	Ok(hive)
}

/// Submits one beam work request through a gateway with
/// [`SubmitWork::submit_work_to`] and returns the servlet's response frame.
///
/// The typed request travels as the client's complete signed frame, so the
/// servlet receives the same envelope over the laser transport as over any
/// other protocol. A refusal surfaces as [`TightBeamError::WorkRefused`].
async fn emit_beam_work(certs: &GatewayCerts, addr: &LaserAddr) -> Result<Frame, TightBeamError> {
	let mut inner = Version::V1
		.compose()
		.with_id(b"laser-beam")
		.with_order(0)
		.with_message(BeamRequest { value: 21 })
		.build()?;

	let identity = signing_identity(certs.cert.to_owned(), certs.key.to_owned());
	inner.sign_with_provider(&identity).await?;

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
/// beat and the gateway's handler make progress, and the wait counts
/// scheduler rounds in place of the operating system's clock. The branching
/// lives here, so the scenarios stay assertion-focused.
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
			(events::GATE_ACCEPT, exactly!(1))
		]
	}
}

// A lone `server!`, outside any colony, bound to the laser protocol serves a
// streaming interaction end to end. Encryption, mux negotiation, and
// stream dispatch all go through the protocol traits.
tb_scenario! {
	name: lone_server_streams_over_laser_protocol,
	spec: LaserLoneServerSpec,
	environment ServiceClient {
		context: laser_certs(),
		server: |SetupEnv { trace, context: certs }| async move {
			let identity = signing_identity(certs.cert.to_owned(), certs.key.to_owned());
			let config = TransportEncryptionConfig::new(identity);
			let (listener, addr) = <LaserListener as EncryptedProtocol>::bind_with(LaserAddr::ANY, config).await?;

			let handle = server! {
				protocol LaserListener: listener,
				policies: {
					with_trace: [ trace.share() ],
					with_mux_offer: [ Some(TransportOffer::mux(8)) ]
				},
				service: BeamLengthService
			};

			Ok((handle, addr))
		},
		client: |ClientEnv { context: certs, addr, .. }| async move {
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
			assert_eq!(decoded.doubled, 8, "the lone server reports the 8-byte body");

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub LaserRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// A laser tightbeam runs from the client through the cluster gateway and the
// hive control plane to a hive servlet, and every link runs the in-memory
// laser protocol, encrypted and multiplexed.
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
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			// A served frame proves the gateway reported `Ok`, because the
			// client surface resolves any other status into `WorkRefused`.
			let servlet_frame = emit_beam_work(&certs, cluster.addr()).await?;

			let beam_response: BeamResponse = decode(servlet_frame.message())?;
			assert_eq!(beam_response.doubled, 42, "the laser servlet doubles 21");

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
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1)),
			(events::HIVE_REREGISTERED, at_least!(1)),
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, at_least!(2))
		]
	}
}

// The gateway registry is soft state. A replacement gateway starts empty on
// the same address, the hive's anti-entropy beat re-registers within one
// interval, and work routes again with no operator, consensus, or persistence.
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

			cluster.stop();

			let replacement = {
				let mut config = laser_cluster_conf(&ctx.certs);
				config.bind_addr = Some(RESTART_GATEWAY_ADDR.into());
				config.clock = Arc::clone(&ctx.clock) as Arc<dyn Clock>;
				LaserCluster::start(Arc::new(trace.share()), config).await?
			};

			// An empty registry refuses the type as unavailable. Any other
			// failure fails the scenario rather than pass for that refusal.
			let unrouted = emit_beam_work(&ctx.certs, replacement.addr()).await;
			let refused = refusal_status(unrouted)?;
			assert_eq!(refused, TransitStatus::Unavailable, "an empty registry refuses the type as unavailable");

			ctx.clock.advance(REREGISTER_INTERVAL);
			wait_for_hives(&replacement, 1).await?;
			emit_beam_work(&ctx.certs, replacement.addr()).await?;

			replacement.stop();
			Ok(())
		}
	}
}

/// An outside protocol over the TCP transport keeps the lease contract of
/// the house pool: a connection whose emit was dropped before its answer is
/// not leased again, though its stream is still open.
#[tokio::test]
async fn a_laser_lease_whose_emit_was_dropped_is_not_leased_again() -> Result<(), Box<dyn std::error::Error>> {
	use tightbeam::testing::TestFrame;
	use tightbeam::transport::{MessageCollector, PersistentConnection, Protocol};

	// The server reads the request and never answers, so the emit stays in
	// flight while the stream stays open.
	let (listener, addr) = <LaserListener as Protocol>::bind_cleartext(LaserAddr::ANY).await?;
	tokio::spawn(async move {
		let Ok((mut transport, _)) = listener.accept().await else {
			return;
		};

		let _request = transport.collect_message().await;
		core::future::pending::<()>().await;
	});

	let pool = Arc::new(ConnectionPool::<LaserListener>::builder().allow_cleartext().build());
	let mut lease = pool.connect(addr).await?;
	let emit = lease.emit(TestFrame::v0(Some("request"), None), None);
	let abandoned = tokio::time::timeout(Duration::from_millis(100), emit).await;

	let leasable = <LaserListener as PersistentConnection>::is_connected(lease.conn()?.transport());
	assert_eq!((abandoned.is_err(), leasable), (true, false));
	Ok(())
}
