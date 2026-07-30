//! Integration tests for Cluster environment
//!
//! Tests the Cluster lifecycle with hive registration and work routing.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "testing-csp",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature"
))]

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sha3::Sha3_256;
use tightbeam::der::Sequence;
use tightbeam::{
	at_least,
	builder::TypeBuilder,
	cluster,
	colony::{
		cluster::{
			Cluster, ClusterConf, ClusterRequest, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse,
			HeartbeatConf,
		},
		common::{
			current_timestamp_ms, servlet_instance, type_canonical_bytes, ColonyNamespace, InstanceMetrics,
			LoadBalancer, PeerAdvertisement, PeerAdvertisementResponse, RoundRobin, StochasticForager,
		},
		hive::{
			Hive, HiveConf, HiveTlsConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdate,
			ServletAddressUpdateResponse, ServletBox, ServletInfo,
		},
		servlet::ServletConf,
	},
	compose,
	constants::{DEFAULT_COMMAND_FRESHNESS_WINDOW_MS, MAX_ADVERTISED_TYPES},
	crypto::{
		key::Secp256k1KeyProvider,
		policy::Secp256k1Policy,
		profiles::DefaultCryptoProvider,
		sign::ecdsa::Secp256k1SigningKey,
		x509::{
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	decode, encode, exactly, hive,
	instrumentation::events,
	policy::{GatePolicy, SessionContext, TransitStatus},
	servlet, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ClusterEnv, HiveEnv, ScenarioConf, SetupEnv},
	trace::TraceCollector,
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
		GenericClient,
	},
	utils::compose as frame_compose,
	utils::urn::Urn,
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::x509::{combined_trust, GatewayCerts};

// Client-side markers only: facts the gateway cannot observe (the client
// reached its send, a probe fired). Gateway decisions are asserted through
// the built-in `tightbeam` events the cluster fires on the scenario trace.
pub(crate) const REGISTRATION_SENT: Urn<'static> = Urn::new("test", "event:cluster/registration-sent");
pub(crate) const REJECTED_HEARTBEAT_DECODED: Urn<'static> =
	Urn::new("test", "event:cluster/rejected-heartbeat-decoded");
pub(crate) const SERVLET_STOPPED: Urn<'static> = Urn::new("test", "event:cluster/servlet-stopped");
pub(crate) const WORK_SENT: Urn<'static> = Urn::new("test", "event:cluster/work-sent");
pub(crate) const WORK_ECHOED: Urn<'static> = Urn::new("test", "event:cluster/work-echoed");
pub(crate) const BALANCER_OFFERED: Urn<'static> = Urn::new("test", "event:cluster/balancer-offered");
pub(crate) const TOPOLOGY_REGISTER_STATUS: Urn<'static> = Urn::new("test", "event:cluster/topology-register-status");
pub(crate) const TOPOLOGY_ADD_STATUS: Urn<'static> = Urn::new("test", "event:cluster/topology-add-status");
pub(crate) const TOPOLOGY_ROUTE_STATUS: Urn<'static> = Urn::new("test", "event:cluster/topology-route-status");
pub(crate) const MULTI_REGISTER_STATUS: Urn<'static> = Urn::new("test", "event:cluster/multi-register-status");
pub(crate) const PEER_ADVERTISE_SENT: Urn<'static> = Urn::new("test", "event:cluster/peer-advertise-sent");
pub(crate) const PEER_AD_STATUS: Urn<'static> = Urn::new("test", "event:cluster/peer-ad-status");
pub(crate) const PEER_ROUTES_AFTER_INSTALLS: Urn<'static> =
	Urn::new("test", "event:cluster/peer-routes-after-installs");
pub(crate) const PEER_ROUTES_AFTER_WITHDRAWAL: Urn<'static> =
	Urn::new("test", "event:cluster/peer-routes-after-withdrawal");
pub(crate) const PEER_PING_LIVE_AFTER_WITHDRAWAL: Urn<'static> =
	Urn::new("test", "event:cluster/peer-ping-live-after-withdrawal");

/// Address the simulated peer gateway advertises itself at.
pub(crate) const PEER_GATEWAY_ADDR: &[u8] = b"127.0.0.1:9000";

// ============================================================================
// Shared Test Certificates
// ============================================================================

type ClusterTestCerts = GatewayCerts;

fn cluster_certs() -> ClusterTestCerts {
	GatewayCerts::generate("CN=Cluster Gateway")
}

// ============================================================================
// TLS Config Helpers (DRY)
// ============================================================================

fn cluster_tls_config_with_trust(
	certs: &ClusterTestCerts,
	hive_trust: Option<Arc<dyn CertificateTrust>>,
) -> ClusterTlsConfig {
	ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
		validators: vec![],
		client_validators: vec![],
		hive_trust,
		peer_trust: None,
	}
}

fn cluster_tls_config(certs: &ClusterTestCerts) -> ClusterTlsConfig {
	cluster_tls_config_with_trust(certs, Some(Arc::clone(&certs.trust)))
}

fn hive_tls_config_no_trust(certs: &ClusterTestCerts) -> HiveConf {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
		validators: vec![],
	});
	HiveConf {
		hive_tls: Some(hive_tls),
		mux_offer: Some(TransportOffer::mux(8)),
		..Default::default()
	}
}

fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConf {
	HiveConf { trust_store: Some(Arc::clone(&certs.trust)), ..hive_tls_config_no_trust(certs) }
}

fn servlet_tls_config(
	certs: &ClusterTestCerts,
) -> Result<ServletConf<TokioListener, PingRequest, DefaultCryptoProvider>, TightBeamError> {
	Ok(ServletConf::<TokioListener, PingRequest, DefaultCryptoProvider>::builder()
		.with_certificate(
			CertificateSpec::Built(Box::new(certs.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
			vec![],
		)?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

/// Start the gateway on the scenario trace so the cluster's built-in
/// lifecycle events land where the assertion specs verify them.
async fn start_cluster(trace: &TraceCollector, conf: ClusterConf) -> Result<ClusterGateway, TightBeamError> {
	ClusterGateway::start(Arc::new(trace.share()), conf).await
}

async fn connect_cluster(
	certs: &ClusterTestCerts,
	addr: <TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_trust_store(Arc::clone(&certs.trust))
		.build()
		.connect(addr)
		.await?)
}

async fn emit_frame(client: &mut GenericClient<TokioListener>, frame: Frame) -> Result<Frame, TightBeamError> {
	client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)
}

fn assert_register_status(
	response: &RegisterHiveResponse,
	status: TransitStatus,
	hive_count: usize,
	cluster: &ClusterGateway,
) {
	assert_eq!(response.status, status);
	assert_eq!(cluster.hive_count(), hive_count);
	if status != TransitStatus::Ok {
		assert!(response.hive_id.is_none(), "rejected registration must not assign a hive id");
	}
}

async fn signed_control_frame_with(
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V0)
		.with_id(id)
		.with_order(0)
		.with_message(request)
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

async fn signed_control_frame(
	certs: &ClusterTestCerts,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	signed_control_frame_with(&certs.key, id, request).await
}

fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

fn hive_urn(hive_addr: &[u8]) -> Urn<'static> {
	colony_ns()
		.hive(String::from_utf8_lossy(hive_addr).as_ref())
		.expect("test locators satisfy the mint grammar")
}

fn servlet_urn(name: &str) -> Urn<'static> {
	colony_ns().servlet(name).expect("test names satisfy the mint grammar")
}

fn registration_request(issued_at_ms: u64, hive_addr: &[u8]) -> ClusterRequest {
	ClusterRequest::RegisterHive(RegisterHiveRequest {
		issued_at_ms,
		hive_addr: hive_addr.to_vec(),
		servlet_addresses: vec![],
		metadata: None,
	})
}

fn servlet_address_update(hive_addr: &[u8], added: Vec<ServletInfo>, removed: Vec<Urn<'static>>) -> ClusterRequest {
	ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
		issued_at_ms: current_timestamp_ms(),
		hive_id: hive_urn(hive_addr),
		added,
		removed,
	})
}

fn servlet_info(servlet_name: &str, address: &[u8]) -> ServletInfo {
	ServletInfo {
		servlet_id: servlet_instance(&servlet_urn(servlet_name), String::from_utf8_lossy(address).as_ref()),
		address: address.to_vec(),
	}
}

/// ServletInfo whose instance locator disagrees with the route address.
fn servlet_info_mismatched(servlet_name: &str, urn_addr: &[u8], route_addr: &[u8]) -> ServletInfo {
	ServletInfo {
		servlet_id: servlet_instance(&servlet_urn(servlet_name), String::from_utf8_lossy(urn_addr).as_ref()),
		address: route_addr.to_vec(),
	}
}

/// Poll until the gateway has learned peer types or attempts exhaust.
/// Branching lives here, not in scenarios.
async fn wait_for_peer_types(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> Vec<Vec<u8>> {
	for _ in 0..attempts {
		let types = cluster.peer_servlets();
		if !types.is_empty() {
			return types;
		}

		tokio::time::sleep(interval).await;
	}

	cluster.peer_servlets()
}

/// Poll until the registry is empty or attempts exhaust. Branching lives here, not in scenarios.
async fn wait_for_empty_registry(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> bool {
	for _ in 0..attempts {
		let empty = cluster.hive_count() == 0;
		if empty {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	cluster.hive_count() == 0
}

// ============================================================================
// Test Messages
// ============================================================================

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct PingRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct PingResponse {
	pub doubled: u32,
}

// ============================================================================
// Test Servlet for Hive
// ============================================================================

servlet! {
	ClusterTestServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		Ok(Some(compose! {
			V0: id: &frame.metadata.id,
				message: PingResponse { doubled: req.value * 2 }
		}?))
	}
}

// ============================================================================
// Test Hive
// ============================================================================

hive! {
	ClusterTestHive,
	protocol: TokioListener
}

// ============================================================================
// Test Cluster
// ============================================================================

cluster! {
	ClusterGateway,
	protocol: TokioListener
}

// ============================================================================
// Assertion Spec
// ============================================================================

tb_assert_spec! {
	pub ClusterRoutingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(WORK_SENT, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// ============================================================================
// Integration Test
// ============================================================================

/// Ping-servlet hive with an optional mux offer for both the hive control
/// server and the hive -> cluster pool, on the scenario trace.
async fn start_ping_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
	mux_offer: Option<TransportOffer>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = ClusterTestServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;

	let mut hive = ClusterTestHive::new(Some(HiveConf { mux_offer, ..hive_tls_config(&certs) }))?;
	hive.register(servlet_urn("ping"), servlet, |t| ClusterTestServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Cluster conf with an optional mux offer for both the gateway server
/// and the cluster -> hive pool.
fn routing_cluster_conf(certs: &ClusterTestCerts, mux_offer: Option<TransportOffer>) -> ClusterConf {
	let mut conf = ClusterConf::new(cluster_tls_config(certs));
	conf.pool_config.mux_offer = mux_offer;
	conf
}

/// Emit one ping work request through the gateway and record the echoed
/// payload as a valued event. The spec asserts the gateway routed it
/// (`events::CLUSTER_WORK_ROUTED`) and the echo value (`WORK_ECHOED`);
/// a refusal or missing payload leaves `WORK_ECHOED` absent.
async fn record_ping_echo(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	trace.event(WORK_SENT)?;

	let mut client = connect_cluster(certs, cluster.addr()).await?;
	let work_response = emit_ping_work(&mut client, b"test-work").await?;
	if let Some(payload) = work_response.payload {
		let ping_response: PingResponse = decode(&payload)?;
		trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
	}

	Ok(())
}

// Work routing over multiplexed colony links: the gateway and hive both
// offer mux, so client -> cluster and cluster -> hive run multiplexed.
tb_scenario! {
	name: cluster_work_routing,
	spec: ClusterRoutingSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, Some(TransportOffer::mux(8)))],
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			record_ping_echo(&trace, &certs, &cluster).await?;
			cluster.stop();
			Ok(())
		}
	}
}

// Same routing path without mux offers: colony links stay single-flight.
tb_scenario! {
	name: cluster_work_routing_single_flight,
	spec: ClusterRoutingSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			record_ping_echo(&trace, &certs, &cluster).await?;
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterMultiGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(MULTI_REGISTER_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(2)),
			(WORK_ECHOED, exactly!(2), equals!(42u64)),
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// One hive, two independent gateways: registration fans out, each gateway
// converges on its own registry (both count exactly this one hive), and
// each routes work to the same servlet slate. Gateway redundancy needs no
// consensus -- every registry is soft state the hive keeps fresh.
tb_scenario! {
	name: cluster_hive_serves_two_gateways,
	spec: ClusterMultiGatewaySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, Some(TransportOffer::mux(8))),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let first = start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await?;
			let second = start_cluster(&trace, routing_cluster_conf(&certs, Some(TransportOffer::mux(8)))).await?;

			let registered = hive.register_with_cluster(first.addr()).await?;
			trace.event_with(MULTI_REGISTER_STATUS, &[], registered.status)?;
			let registered = hive.register_with_cluster(second.addr()).await?;
			trace.event_with(MULTI_REGISTER_STATUS, &[], registered.status)?;

			record_ping_echo(&trace, &certs, &first).await?;
			record_ping_echo(&trace, &certs, &second).await?;

			first.stop();
			second.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterInstanceWorkSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_REFUSED, exactly!(1))
		]
	}
}

// Work must target a servlet TYPE: instance-narrowed URNs are refused
// even when the type is routable, so nothing bypasses the load balancer.
tb_scenario! {
	name: cluster_refuses_instance_addressed_work,
	spec: ClusterInstanceWorkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let work_request = ClusterRequest::Work(ClusterWorkRequest {
				servlet_type: servlet_instance(&servlet_urn("ping"), "127.0.0.1:9999"),
				payload: encode(&PingRequest { value: 21 })?,
			});

			let frame = frame_compose(Version::V0)
				.with_id(b"instance-work")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			trace.event(WORK_SENT)?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			assert_eq!(
				work_response.status,
				TransitStatus::PermissionDenied,
				"instance-addressed work must not bypass the load balancer"
			);
			assert!(work_response.payload.is_none(), "refused work must not carry a payload");

			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Peer Federation (advertisement control plane)
// ============================================================================

/// Gateway conf that accepts peer advertisements: `peer_trust` anchors the
/// advertising gateway's certificate. No `peers` set, so this gateway
/// only receives.
fn peering_cluster_conf(certs: &ClusterTestCerts) -> ClusterConf {
	let tls = ClusterTlsConfig { peer_trust: Some(Arc::clone(&certs.trust)), ..cluster_tls_config(certs) };
	ClusterConf::new(tls)
}

/// Gateway conf that advertises to `peer` on a fast beat. The slate is
/// never configured: each beat snapshots the hive registry.
fn advertising_cluster_conf(certs: &ClusterTestCerts, peer: String) -> ClusterConf {
	let mut conf = ClusterConf::new(cluster_tls_config(certs));
	conf.peers = vec![peer];
	conf.advertise_interval = Some(Duration::from_millis(100));
	conf
}

/// Send one signed advertisement of `types` from a peer at `gateway_addr`,
/// signed by `signer`, and return the decoded response status.
async fn advertise_peer_signed(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	cluster: &ClusterGateway,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
) -> Result<TransitStatus, TightBeamError> {
	let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
		issued_at_ms: current_timestamp_ms(),
		gateway_addr: gateway_addr.to_vec(),
		advertised_types: types,
	});

	let frame = signed_control_frame_with(signer, b"peer-advertise", request).await?;
	send_advertisement_frame(trace, certs, cluster, frame).await
}

/// Emit an already-signed advertisement frame and decode the status:
/// lets replay scenarios resend a byte-identical frame. Every decoded
/// status lands on the trace as `PEER_AD_STATUS` for spec verification.
async fn send_advertisement_frame(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<TransitStatus, TightBeamError> {
	let mut client = connect_cluster(certs, cluster.addr()).await?;
	trace.event(PEER_ADVERTISE_SENT)?;

	let response_frame = emit_frame(&mut client, frame).await?;
	let response: PeerAdvertisementResponse = decode(&response_frame.message)?;
	trace.event_with(PEER_AD_STATUS, &[], response.status)?;
	Ok(response.status)
}

/// Send one signed advertisement of `types` from a peer at `gateway_addr`
/// and return the decoded response status.
async fn advertise_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
) -> Result<TransitStatus, TightBeamError> {
	advertise_peer_signed(trace, certs, &certs.key, cluster, gateway_addr, types).await
}

/// Advertise a one-type ping slate from the simulated peer gateway and
/// assert it installed: the shared preamble for every scenario exercising
/// behavior after a peer route exists.
async fn install_ping_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	let status = advertise_peer(trace, certs, cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;
	assert_eq!(status, TransitStatus::Ok, "trusted advertisement must install");
	Ok(())
}

tb_assert_spec! {
	pub ClusterPeerAdvertisedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1))
		]
	}
}

tb_assert_spec! {
	pub ClusterPeerRefusedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1))
		]
	}
}

// A trusted peer advertisement installs peer routes: the advertised type
// surfaces in `peer_servlets` (learned), never in `available_servlets`
// (local hives only). No forwarding happens in this stage.
tb_scenario! {
	name: cluster_accepts_peer_advertisement,
	spec: ClusterPeerAdvertisedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let peers = cluster.peer_servlets();
			assert_eq!(peers.len(), 1, "one advertised type installs one peer route");
			assert_eq!(peers[0], type_canonical_bytes(&servlet_urn("ping")), "peer route keyed by type");
			assert!(cluster.available_servlets().is_empty(), "a peer is not a local hive");

			cluster.stop();
			Ok(())
		}
	}
}

// A slate is not one type: every advertised type installs its own peer
// route, so a two-type advertisement surfaces both types.
tb_scenario! {
	name: cluster_multi_type_advertisement_installs_all,
	spec: ClusterPeerAdvertisedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let slate = vec![servlet_urn("ping"), servlet_urn("echo")];
			let status = advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, slate).await?;
			assert_eq!(status, TransitStatus::Ok, "trusted advertisement must install");

			let mut peers = cluster.peer_servlets();
			peers.sort_unstable();

			let ping_canonical = type_canonical_bytes(&servlet_urn("ping"));
			let echo_canonical = type_canonical_bytes(&servlet_urn("echo"));
			let mut expected = vec![ping_canonical, echo_canonical];
			expected.sort_unstable();

			assert_eq!(peers, expected, "every advertised type installs a route, not only the last");

			cluster.stop();
			Ok(())
		}
	}
}

/// Receiver identity plus a second, independently trusted peer signer.
struct PeerPairCerts {
	gateway: GatewayCerts,
	peer_b: (Certificate, Secp256k1SigningKey),
	peer_trust: Arc<dyn CertificateTrust>,
}

fn peer_pair_certs() -> PeerPairCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let gateway = cluster_certs();
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_b = create_test_certificate(&raw_b);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let peer_trust = combined_trust(&[&gateway.cert, &cert_b]);

	PeerPairCerts { gateway, peer_b: (cert_b, key_b), peer_trust }
}

/// Receiver conf anchoring both pair identities in `peer_trust`.
fn peering_pair_conf(certs: &PeerPairCerts) -> ClusterConf {
	let tls = ClusterTlsConfig {
		peer_trust: Some(Arc::clone(&certs.peer_trust)),
		..cluster_tls_config(&certs.gateway)
	};
	ClusterConf::new(tls)
}

tb_assert_spec! {
	pub ClusterPeerSignerKeyedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(3)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(3)),
			(PEER_AD_STATUS, exactly!(3), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(2u64)),
			(PEER_ROUTES_AFTER_WITHDRAWAL, exactly!(1), equals!(1u64)),
			(PEER_PING_LIVE_AFTER_WITHDRAWAL, exactly!(1), equals!(1u64))
		]
	}
}

// Slates belong to the authenticated signer, not the claimed gateway
// address: two trusted peers advertising under the same address keep
// independent slates (two routes after both install), and one peer's
// withdrawal only evicts its own routes (ping survives echo's exit).
tb_scenario! {
	name: cluster_peer_slates_keyed_by_signer,
	spec: ClusterPeerSignerKeyedSpec,
	environment Cluster {
		context: peer_pair_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_pair_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let gateway = &certs.gateway;
			advertise_peer_signed(&trace, gateway, &gateway.key, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")])
				.await?;
			advertise_peer_signed(&trace, gateway, &certs.peer_b.1, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("echo")])
				.await?;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], cluster.peer_servlets().len() as u64)?;

			advertise_peer_signed(&trace, gateway, &certs.peer_b.1, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;
			let survivors = cluster.peer_servlets();
			trace.event_with(PEER_ROUTES_AFTER_WITHDRAWAL, &[], survivors.len() as u64)?;
			trace.event_with(
				PEER_PING_LIVE_AFTER_WITHDRAWAL,
				&[],
				u64::from(survivors.contains(&type_canonical_bytes(&servlet_urn("ping")))),
			)?;

			cluster.stop();
			Ok(())
		}
	}
}

// Federation is default-off: a gateway without `peer_trust` refuses every
// advertisement fail-closed, installing no peer routes.
tb_scenario! {
	name: cluster_refuses_advertisement_without_peer_trust,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let status = advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;
			assert_eq!(status, TransitStatus::PermissionDenied, "peer_trust=None must refuse federation");
			assert!(cluster.peer_servlets().is_empty(), "refused advertisement installs no routes");

			cluster.stop();
			Ok(())
		}
	}
}

// Nestmate recognition: an advertised type from a foreign realm fails the
// structural CHC half and is refused even under a valid peer certificate.
tb_scenario! {
	name: cluster_refuses_foreign_realm_advertisement,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let foreign_ns =
				ColonyNamespace::new("tightbeam", "other-realm").map_err(|_| TightBeamError::MissingResponse)?;
			let foreign = foreign_ns.servlet("ping").map_err(|_| TightBeamError::MissingResponse)?;

			let status = advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![foreign]).await?;
			assert_eq!(status, TransitStatus::PermissionDenied, "foreign realm fails nestmate recognition");
			assert!(cluster.peer_servlets().is_empty(), "foreign advertisement installs no routes");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerReplayReleasedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(2)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64))
		]
	}
}

// A refusal is not a penalty box: an advertisement refused on local state
// (address conflict) releases its replay record, so the peer can resend
// the byte-identical signed frame once the conflict clears and install.
tb_scenario! {
	name: cluster_advertisement_retryable_after_refusal,
	spec: ClusterPeerReplayReleasedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let hive_addr = b"127.0.0.1:65031".as_slice();
			let locator = String::from_utf8_lossy(PEER_GATEWAY_ADDR);
			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			register_signed_hive(&mut client, &certs.key, b"reg-conflict", hive_addr).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-conflict",
				servlet_address_update(hive_addr, vec![servlet_info("ping", PEER_GATEWAY_ADDR)], vec![]),
			)
			.await?;

			let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
				issued_at_ms: current_timestamp_ms(),
				gateway_addr: PEER_GATEWAY_ADDR.to_vec(),
				advertised_types: vec![servlet_urn("ping")],
			});

			let frame = signed_control_frame(&certs, b"peer-advertise", request).await?;

			send_advertisement_frame(&trace, &certs, &cluster, frame.to_owned()).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"del-conflict",
				servlet_address_update(hive_addr, vec![], vec![servlet_instance(&servlet_urn("ping"), locator.as_ref())]),
			)
			.await?;

			send_advertisement_frame(&trace, &certs, &cluster, frame).await?;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], cluster.peer_servlets().len() as u64)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerWorkLocalOnlySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

// Work selection stays local: a type reachable only through a peer route
// is Unavailable to clients, because a bare work frame must never be
// dialed at a peer gateway as though it were a servlet.
tb_scenario! {
	name: cluster_work_ignores_peer_routes,
	spec: ClusterPeerWorkLocalOnlySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			trace.event(WORK_SENT)?;

			let work_response = emit_ping_work(&mut client, b"peer-only-work").await?;
			assert_eq!(work_response.status, TransitStatus::Unavailable, "peer routes must not serve work yet");
			assert!(work_response.payload.is_none(), "unroutable work must not carry a payload");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerSlateShrinkSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(2)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(2))
		]
	}
}

// Reconciliation is by replacement: a later advertisement carrying an
// empty slate retires every route the peer previously advertised.
tb_scenario! {
	name: cluster_empty_advertisement_clears_peer_routes,
	spec: ClusterPeerSlateShrinkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;
			assert_eq!(cluster.peer_servlets().len(), 1, "first slate carries one type");

			let cleared = advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;
			assert_eq!(cleared, TransitStatus::Ok, "empty slate is a valid reconciliation");
			assert!(cluster.peer_servlets().is_empty(), "empty slate retires the prior routes");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerBeatSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

// The advertised slate is registry truth, not configuration: a hive that
// registers AFTER both gateways are up surfaces at the peer within a
// beat, with no operator involvement.
tb_scenario! {
	name: cluster_beat_advertises_registered_hive_types,
	spec: ClusterPeerBeatSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, peering_cluster_conf(&certs)).await?;
			let receiver_addr = receiver.addr();
			let advertiser = start_cluster(&trace, advertising_cluster_conf(&certs, receiver_addr.to_string())).await?;

			let registered = hive.register_with_cluster(advertiser.addr()).await?;
			assert_eq!(registered.status, TransitStatus::Ok, "hive must join the advertising colony");

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "beat must carry the newly registered type");
			assert_eq!(learned[0], type_canonical_bytes(&servlet_urn("ping")), "peer route keyed by type");

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterBeatUpdatedSlateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64))
		]
	}
}

// The advertised slate is route truth, not registration history: a type
// that joins through a servlet address update surfaces at the peer on
// the next beat, exactly like a registration-time type.
tb_scenario! {
	name: cluster_beat_slate_tracks_servlet_updates,
	spec: ClusterBeatUpdatedSlateSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster: receiver }| async move {
			let advertiser =
				start_cluster(&trace, advertising_cluster_conf(&certs, receiver.addr().to_string())).await?;

			let hive_addr = b"127.0.0.1:65041".as_slice();
			let mut client = connect_cluster(&certs, advertiser.addr()).await?;
			register_signed_hive(&mut client, &certs.key, b"reg-beat-update", hive_addr).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-beat-echo",
				servlet_address_update(hive_addr, vec![servlet_info("echo", b"127.0.0.1:65042")], vec![]),
			)
			.await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			advertiser.stop();
			receiver.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterBeatCapSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(MAX_ADVERTISED_TYPES as u64))
		]
	}
}

// The beat honors the receiver's advertisement cap: a colony exporting
// more types than MAX_ADVERTISED_TYPES advertises a deterministic capped
// subset instead of an oversized slate every receiver refuses, which
// would silently wedge federation.
tb_scenario! {
	name: cluster_beat_bounds_slate_to_advertised_cap,
	spec: ClusterBeatCapSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster: receiver }| async move {
			let advertiser =
				start_cluster(&trace, advertising_cluster_conf(&certs, receiver.addr().to_string())).await?;

			let hive_addr = b"127.0.0.1:65043".as_slice();
			let mut client = connect_cluster(&certs, advertiser.addr()).await?;
			register_signed_hive(&mut client, &certs.key, b"reg-beat-cap", hive_addr).await?;

			let over_cap: Vec<ServletInfo> = (0..=MAX_ADVERTISED_TYPES)
				.map(|i| {
					let addr = format!("127.0.0.1:{}", 20000 + i);
					servlet_info(&format!("t{i}"), addr.as_bytes())
				})
				.collect();
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-beat-cap",
				servlet_address_update(hive_addr, over_cap, vec![]),
			)
			.await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			advertiser.stop();
			receiver.stop();
			Ok(())
		}
	}
}

/// Exporter (advertiser + hive) identity on one trust plane, receiver on
/// another: only `peer_trust` can validate the receiver's TLS identity,
/// so the advertise beat must dial on the peer plane, never the hive one.
struct SplitPlaneCerts {
	exporter: ClusterTestCerts,
	receiver: (Certificate, Secp256k1SigningKey),
	receiver_trust: Arc<dyn CertificateTrust>,
}

fn split_plane_certs() -> SplitPlaneCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let exporter = cluster_certs();
	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let receiver_cert = create_test_certificate(&raw);
	let receiver_key = Secp256k1SigningKey::from(raw);
	let receiver_trust = combined_trust(&[&receiver_cert]);
	SplitPlaneCerts { exporter, receiver: (receiver_cert, receiver_key), receiver_trust }
}

fn share_certs(certs: &ClusterTestCerts) -> Arc<ClusterTestCerts> {
	Arc::new(GatewayCerts {
		cert: certs.cert.to_owned(),
		key: certs.key.to_owned(),
		trust: Arc::clone(&certs.trust),
	})
}

/// Receiver with its own identity: `peer_trust` anchors the exporter's
/// certificate so its signed advertisements verify.
fn receiving_peer_conf(certs: &SplitPlaneCerts) -> ClusterConf {
	ClusterConf::new(ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.receiver.0.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.receiver.1.to_owned())),
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.exporter.trust)),
		peer_trust: Some(Arc::clone(&certs.exporter.trust)),
	})
}

/// Advertiser whose hive plane cannot validate the receiver: only
/// `peer_trust` anchors the receiver's identity.
fn cross_plane_advertising_conf(certs: &SplitPlaneCerts, peer: String) -> ClusterConf {
	let tls = ClusterTlsConfig {
		peer_trust: Some(Arc::clone(&certs.receiver_trust)),
		..cluster_tls_config(&certs.exporter)
	};

	let mut conf = ClusterConf::new(tls);
	conf.peers = vec![peer];
	conf.advertise_interval = Some(Duration::from_millis(100));
	conf
}

tb_assert_spec! {
	pub ClusterPeerPlaneBeatSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, at_least!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64))
		]
	}
}

// Federation crosses trust planes: the receiver's TLS identity is only
// anchored in the advertiser's `peer_trust`, so the beat must dial on the
// peer plane. A beat riding the hive-trust pool never connects.
tb_scenario! {
	name: cluster_beat_dials_on_peer_trust_plane,
	spec: ClusterPeerPlaneBeatSpec,
	environment Hive {
		context: split_plane_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, share_certs(&certs.exporter), None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, receiving_peer_conf(&certs)).await?;
			let receiver_addr = receiver.addr().to_string();
			let advertiser = start_cluster(&trace, cross_plane_advertising_conf(&certs, receiver_addr)).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

// ============================================================================
// Environment Teardown
// ============================================================================

tb_assert_spec! {
	pub ClusterTeardownSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

/// Records the teardown call instead of serving traffic: `stop_boxed` is
/// the observable under test.
struct StopProbeServlet {
	trace: TraceCollector,
}

impl ServletBox for StopProbeServlet {
	fn addr_bytes(&self) -> Vec<u8> {
		b"127.0.0.1:0".to_vec()
	}

	fn stop_boxed(self: Box<Self>) {
		let _ = self.trace.event(SERVLET_STOPPED);
	}
}

// Environment teardown must run `Hive::stop`, which drains registered
// servlets through `stop_boxed`. Plain drop only aborts control tasks.
tb_scenario! {
	name: cluster_env_teardown_stops_hive_servlets,
	spec: ClusterTeardownSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![async move {
			let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
			hive.register(servlet_urn("probe"), StopProbeServlet { trace: trace.share() }, |t| async move {
				Ok(StopProbeServlet { trace: t.share() })
			})?;
			hive.establish(Arc::new(trace.share())).await?;

			Ok::<_, TightBeamError>(hive)
		}],
		client: |ClusterEnv { cluster, .. }| async move {
			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Gate Policy Enforcement
// ============================================================================

struct RejectAllPolicy;

impl GatePolicy for RejectAllPolicy {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		TransitStatus::PermissionDenied
	}
}

tb_assert_spec! {
	pub ClusterPolicySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_GATE_BLOCKED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_policy_gate_blocks,
	spec: ClusterPolicySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let cluster_conf = ClusterConf::builder(cluster_tls_config(&certs))
				.with_gate_policy(Arc::new(RejectAllPolicy))
				.build();
			start_cluster(&trace, cluster_conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();

			let work_request = ClusterRequest::Work(ClusterWorkRequest {
				servlet_type: servlet_urn("ping"),
				payload: encode(&PingRequest { value: 21 })?,
			});

			let frame = frame_compose(Version::V0)
				.with_id(b"policy-test")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let mut client = connect_cluster(&certs, cluster_addr).await?;

			trace.event(WORK_SENT)?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			assert_eq!(
				work_response.status,
				TransitStatus::PermissionDenied,
				"gate policy must reject the request before decoding"
			);
			assert!(work_response.payload.is_none(), "rejected request must not carry a payload");

			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Unsigned Registration Rejection
// ============================================================================

tb_assert_spec! {
	pub ClusterUnsignedRegistrationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REGISTRATION_SENT, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_unsigned_registration,
	spec: ClusterUnsignedRegistrationSpec,
	environment Cluster {
		context: cluster_certs(),
		// Registration itself is under test, so no `hives:` key.
		// The client drives it and asserts the rejection.
		start: |SetupEnv { trace, context: certs }| async move {
			// Cluster requires signed hive-origin frames (hive_trust set)
			start_cluster(&trace, ClusterConf::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();

			// Hive validates the cluster's TLS certificate but has no
			// signing identity of its own: control frames go out unsigned
			let hive_conf = HiveConf {
				trust_store: Some(Arc::clone(&certs.trust)),
				..Default::default()
			};

			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(trace.share())).await?;

			trace.event(REGISTRATION_SENT)?;

			let response = hive.register_with_cluster(cluster_addr).await?;
			assert_register_status(&response, TransitStatus::Unauthenticated, 0, &cluster);

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRefusedRegNotQueuedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REGISTRATION_SENT, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(events::HIVE_REREGISTERED, exactly!(0))
		]
	}
}

// A refused RegisterHiveResponse must not enqueue the gateway: the
// anti-entropy beat would otherwise keep calling a peer that already
// rejected the hive, and scaling updates would fan out there too.
tb_scenario! {
	name: cluster_refused_registration_does_not_queue_gateway,
	spec: ClusterRefusedRegNotQueuedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConf::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();
			let hive_conf = HiveConf {
				trust_store: Some(Arc::clone(&certs.trust)),
				reregister_interval: Some(Duration::from_millis(50)),
				..Default::default()
			};

			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(trace.share())).await?;

			trace.event(REGISTRATION_SENT)?;

			let response = hive.register_with_cluster(cluster_addr).await?;
			assert_register_status(&response, TransitStatus::Unauthenticated, 0, &cluster);

			// Several anti-entropy intervals: a queued gateway would emit
			// HIVE_REREGISTERED; an unqueued one stays silent.
			tokio::time::sleep(Duration::from_millis(250)).await;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Missing Trust Store Fails Closed
// ============================================================================

tb_assert_spec! {
	pub ClusterNoTrustStoreSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REGISTRATION_SENT, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_without_hive_trust_rejects_control_frames,
	spec: ClusterNoTrustStoreSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			// Gateway without hive_trust cannot authenticate control
			// frames and must fail closed: even a validly signed
			// registration is rejected.
			let tls = ClusterTlsConfig {
				certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
				key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
				validators: vec![],
				client_validators: vec![],
				hive_trust: None,
				peer_trust: None,
			};
			start_cluster(&trace, ClusterConf::new(tls)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();

			let mut client = connect_cluster(&certs, cluster_addr).await?;
			let signed = signed_control_frame(
				&certs,
				b"no-trust-reg",
				registration_request(current_timestamp_ms(), b"127.0.0.1:65000"),
			)
			.await?;

			trace.event(REGISTRATION_SENT)?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::PermissionDenied, 0, &cluster);

			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Servlet URN locator must match route address
// ============================================================================

tb_assert_spec! {
	pub ClusterServletLocatorAlignSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1))
		]
	}
}

// Register and update must refuse ServletInfo whose instance locator
// disagrees with the announced address: routes key by address, remove
// by URN locator (CWE-639 ghost / orphan routes).
tb_scenario! {
	name: cluster_rejects_mismatched_servlet_locator,
	spec: ClusterServletLocatorAlignSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConf::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;
			let hive_addr = b"127.0.0.1:65100";

			let mismatch = servlet_info_mismatched("ping", b"127.0.0.1:65101", b"127.0.0.1:65199");
			let refused_reg = signed_control_frame(
				&certs,
				b"misalign-reg",
				ClusterRequest::RegisterHive(RegisterHiveRequest {
					issued_at_ms: current_timestamp_ms(),
					hive_addr: hive_addr.to_vec(),
					servlet_addresses: vec![mismatch],
					metadata: None,
				}),
			)
			.await?;

			let response_frame = emit_frame(&mut client, refused_reg).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::PermissionDenied, 0, &cluster);

			// Clean registration, then a mismatched add must refuse.
			let ok_reg = signed_control_frame(
				&certs,
				b"align-reg",
				registration_request(current_timestamp_ms(), hive_addr),
			)
			.await?;
			let response_frame = emit_frame(&mut client, ok_reg).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::Ok, 1, &cluster);

			let bad_add = servlet_address_update(
				hive_addr,
				vec![servlet_info_mismatched("ping", b"127.0.0.1:65102", b"127.0.0.1:65198")],
				vec![],
			);
			let refused_update = signed_control_frame(&certs, b"misalign-update", bad_add).await?;
			let response_frame = emit_frame(&mut client, refused_update).await?;
			let response: ServletAddressUpdateResponse = decode(&response_frame.message)?;
			assert_eq!(
				response.status,
				TransitStatus::PermissionDenied,
				"mismatched servlet locator on update must be refused"
			);

			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Replayed / Stale Control Frame Rejection
// ============================================================================

tb_assert_spec! {
	pub ClusterReplaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(2)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1))
		]
	}
}

// Anti-replay ordering: only after a registration lands can its replay
// (then a stale resend) be refused, and only after a fresh update lands
// can its replay be refused. Counting alone cannot prove the refusals
// follow the acceptances.
tb_process_spec! {
	pub ClusterReplayProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_REGISTER_REFUSED,
			events::CLUSTER_UPDATE_ACCEPTED,
			events::CLUSTER_UPDATE_REFUSED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_REGISTER_REFUSED => ReplayRefused },
		ReplayRefused => { events::CLUSTER_REGISTER_REFUSED => StaleRefused },
		StaleRefused => { events::CLUSTER_UPDATE_ACCEPTED => UpdateAccepted },
		UpdateAccepted => { events::CLUSTER_UPDATE_REFUSED => Done },
		Done => { }
	}
	terminal { Done }
}

tb_scenario! {
	name: cluster_rejects_replayed_and_stale_control_frames,
	config: ScenarioConf::builder()
		.with_spec(ClusterReplaySpec::latest())
		.with_csp(ClusterReplayProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConf::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;

			// Fresh signed registration is accepted
			let fresh = signed_control_frame(
				&certs,
				b"replay-reg",
				registration_request(current_timestamp_ms(), b"127.0.0.1:65000"),
			)
			.await?;
			let replayed = fresh.to_owned();

			let response_frame = emit_frame(&mut client, fresh).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::Ok, 1, &cluster);

			// Byte-identical resend carries an already-seen signature
			let response_frame = emit_frame(&mut client, replayed).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::PermissionDenied, "replayed registration must be rejected");

			// Valid signature but issued outside the freshness window
			let stale_ts = current_timestamp_ms() - 2 * DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
			let stale = signed_control_frame(
				&certs,
				b"stale-reg",
				registration_request(stale_ts, b"127.0.0.1:65000"),
			)
			.await?;

			let response_frame = emit_frame(&mut client, stale).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::PermissionDenied, "stale registration must be rejected");

			// Same enforcement on servlet address updates
			let update = servlet_address_update(
				b"127.0.0.1:65000",
				vec![servlet_info("ping", b"127.0.0.1:65001")],
				vec![],
			);
			let fresh_update = signed_control_frame(&certs, b"replay-update", update).await?;
			let replayed_update = fresh_update.to_owned();

			let response_frame = emit_frame(&mut client, fresh_update).await?;
			let response: ServletAddressUpdateResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Ok, "fresh signed update must be accepted");

			let response_frame = emit_frame(&mut client, replayed_update).await?;
			let response: ServletAddressUpdateResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::PermissionDenied, "replayed update must be rejected");

			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Rejected Heartbeats Evict The Hive
// ============================================================================

tb_assert_spec! {
	pub ClusterHeartbeatRejectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(REJECTED_HEARTBEAT_DECODED, exactly!(1)),
			(events::CLUSTER_HIVE_EVICTED, exactly!(1))
		]
	}
}

// Eviction ordering: a hive can only be evicted after it registered.
// The client-side REJECTED_HEARTBEAT_DECODED marker stays out of the
// alphabet because the heartbeat task fires the eviction event after the
// registry empties, racing the client's poll.
tb_process_spec! {
	pub ClusterEvictionProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_HIVE_EVICTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_HIVE_EVICTED => Evicted },
		Evicted => { }
	}
	terminal { Evicted }
}

/// Heartbeat-eviction fixture. The heartbeat callback (set in `start`)
/// records whether a decoded rejected heartbeat was observed. The client
/// asserts that flag after eviction.
struct HeartbeatRejectionContext {
	certs: ClusterTestCerts,
	rejected_decoded: AtomicBool,
}

tb_scenario! {
	name: cluster_evicts_hive_on_rejected_heartbeats,
	config: ScenarioConf::builder()
		.with_spec(ClusterHeartbeatRejectionSpec::latest())
		.with_csp(ClusterEvictionProcess)
		.build(),
	environment Cluster {
		context: HeartbeatRejectionContext {
			certs: cluster_certs(),
			rejected_decoded: AtomicBool::new(false),
		},
		start: |SetupEnv { trace, context: rejection }| async move {
			let callback_rejection = Arc::clone(&rejection);
			let heartbeat = HeartbeatConf::builder()
				.with_interval(Duration::from_millis(100))
				.with_max_failures(1)
				.with_callback(Arc::new(move |event| {
					// utilization is only Some when the heartbeat response
					// decoded, proving the failure came from the rejected
					// status rather than a transport error
					let decoded_reject = !event.success && event.utilization.is_some();
					callback_rejection
						.rejected_decoded
						.fetch_or(decoded_reject, Ordering::SeqCst);
				}))
				.build();

			let cluster_conf = ClusterConf::builder(cluster_tls_config(&rejection.certs))
				.with_heartbeat_config(heartbeat)
				.build();
			start_cluster(&trace, cluster_conf).await
		},
		client: |ClusterEnv { trace, context: rejection, cluster }| async move {
			let certs = &rejection.certs;
			let cluster_addr = cluster.addr();

			// Hive serves the shared cert (cluster trusts it for TLS) but
			// configures no trust store for inbound commands
			let mut hive = ClusterTestHive::new(Some(hive_tls_config_no_trust(certs)))?;
			hive.establish(Arc::new(trace.share())).await?;

			// Register the hive out-of-band with a validly signed frame
			let hive_addr_bytes = hive.addr().to_string().into_bytes();
			let registration = signed_control_frame(
				certs,
				b"hb-reject-reg",
				registration_request(current_timestamp_ms(), &hive_addr_bytes),
			)
			.await?;

			let mut client = connect_cluster(certs, cluster_addr).await?;
			let response_frame = emit_frame(&mut client, registration).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::Ok, 1, &cluster);

			// Heartbeats run every 100ms with max_failures = 1: the first
			// PermissionDenied heartbeat must evict the hive
			assert!(
				wait_for_empty_registry(&cluster, 50, Duration::from_millis(100)).await,
				"hive with rejected heartbeats must be evicted"
			);

			assert!(
				rejection.rejected_decoded.load(Ordering::SeqCst),
				"hive must answer with a decodable rejected heartbeat"
			);

			trace.event(REJECTED_HEARTBEAT_DECODED)?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Signer-bound ServletAddressUpdate (cross-hive tampering)
// ============================================================================

struct DualHiveCerts {
	gateway: ClusterTestCerts,
	hive_a: (Certificate, Secp256k1SigningKey),
	hive_b: (Certificate, Secp256k1SigningKey),
	hive_trust: Arc<dyn CertificateTrust>,
}

fn dual_hive_certs() -> DualHiveCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let gateway = cluster_certs();
	let raw_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_a = create_test_certificate(&raw_a);
	let cert_b = create_test_certificate(&raw_b);
	let key_a = Secp256k1SigningKey::from(raw_a);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert_a.to_owned())
			.expect("hive A trust")
			.with_certificate(cert_b.to_owned())
			.expect("hive B trust")
			.build(),
	);

	DualHiveCerts { gateway, hive_a: (cert_a, key_a), hive_b: (cert_b, key_b), hive_trust }
}

async fn register_signed_hive(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: &[u8],
	addr: &[u8],
) -> Result<RegisterHiveResponse, TightBeamError> {
	let frame = signed_control_frame_with(key, id, registration_request(current_timestamp_ms(), addr)).await?;
	decode(&emit_frame(client, frame).await?.message)
}

async fn emit_servlet_update(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
) -> Result<ServletAddressUpdateResponse, TightBeamError> {
	let frame = signed_control_frame_with(key, id, request).await?;
	decode(&emit_frame(client, frame).await?.message)
}

tb_assert_spec! {
	pub ClusterCrossHiveUpdateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_cross_hive_servlet_address_update,
	spec: ClusterCrossHiveUpdateSpec,
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConf::new(cluster_tls_config_with_trust(
				&certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs.gateway, cluster_addr).await?;

			let hive_a_addr = b"127.0.0.1:65010".as_slice();
			let hive_b_addr = b"127.0.0.1:65011".as_slice();

			let response_a = register_signed_hive(&mut client, &certs.hive_a.1, b"reg-a", hive_a_addr).await?;
			let response_b = register_signed_hive(&mut client, &certs.hive_b.1, b"reg-b", hive_b_addr).await?;
			assert_eq!(response_a.status, TransitStatus::Ok);
			assert_eq!(response_b.status, TransitStatus::Ok);
			assert_eq!(cluster.hive_count(), 2);

			let update_cases = [
				(
					&certs.hive_b.1,
					b"cross-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info("poison", b"127.0.0.1:65099")], vec![]),
					TransitStatus::PermissionDenied,
				),
				(
					&certs.hive_a.1,
					b"owner-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info("ping", b"127.0.0.1:65012")], vec![]),
					TransitStatus::Ok,
				),
			];

			for (key, id, request, expected) in update_cases {
				let response = emit_servlet_update(&mut client, key, id, request).await?;
				assert_eq!(response.status, expected);
			}

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRegistrationHijackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

tb_process_spec! {
	// Hijack ordering: the owner registers first, the hijacker's registration
	// is refused, and only then does the owner's update land.
	pub ClusterHijackProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_REGISTER_REFUSED,
			events::CLUSTER_UPDATE_ACCEPTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => OwnerRegistered },
		OwnerRegistered => { events::CLUSTER_REGISTER_REFUSED => HijackRefused },
		HijackRefused => { events::CLUSTER_UPDATE_ACCEPTED => OwnerBindIntact },
		OwnerBindIntact => { }
	}
	terminal { OwnerBindIntact }
}

tb_scenario! {
	name: cluster_rejects_cross_hive_registration_hijack,
	config: ScenarioConf::builder()
		.with_spec(ClusterRegistrationHijackSpec::latest())
		.with_csp(ClusterHijackProcess)
		.build(),
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConf::new(cluster_tls_config_with_trust(
				&certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs.gateway, cluster.addr()).await?;

			let hive_a_addr = b"127.0.0.1:65020".as_slice();

			let owner = register_signed_hive(&mut client, &certs.hive_a.1, b"owner-reg", hive_a_addr).await?;
			assert_eq!(owner.status, TransitStatus::Ok);
			assert_eq!(cluster.hive_count(), 1);

			let hijack = register_signed_hive(&mut client, &certs.hive_b.1, b"hijack-reg", hive_a_addr).await?;
			assert_eq!(hijack.status, TransitStatus::PermissionDenied);
			assert_eq!(cluster.hive_count(), 1);

			// The owner's update still lands: the failed hijack must not
			// have disturbed the signer binding.
			let owned = emit_servlet_update(
				&mut client,
				&certs.hive_a.1,
				b"owner-still-bound",
				servlet_address_update(hive_a_addr, vec![servlet_info("ping", b"127.0.0.1:65021")], vec![]),
			)
			.await?;
			assert_eq!(owned.status, TransitStatus::Ok);

			cluster.stop();
			Ok(())
		}
	}
}

// ============================================================================
// Removal Updates Unroute Instances
// ============================================================================

/// Ping work request through the gateway, returning the decoded response.
async fn emit_ping_work(
	client: &mut GenericClient<TokioListener>,
	id: &[u8],
) -> Result<ClusterWorkResponse, TightBeamError> {
	let work_request = ClusterRequest::Work(ClusterWorkRequest {
		servlet_type: servlet_urn("ping"),
		payload: encode(&PingRequest { value: 21 })?,
	});

	let frame = frame_compose(Version::V0)
		.with_id(id)
		.with_order(0)
		.with_message(work_request)
		.build()?;

	decode(&emit_frame(client, frame).await?.message)
}

/// Instance URN in a realm this gateway does not serve.
fn foreign_realm_instance(addr: &str) -> Urn<'static> {
	let namespace = ColonyNamespace::new("tightbeam", "elsewhere").expect("static namespace parts are valid");
	servlet_instance(&namespace.servlet("ping").expect("test names satisfy the mint grammar"), addr)
}

tb_assert_spec! {
	pub ClusterRemovalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(2)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

tb_process_spec! {
	// Removal ordering: work routes only between the add and the removal,
	// the foreign-realm refusal lands between them, and unavailability
	// follows the accepted removal. Counting cannot distinguish "routed
	// then removed" from "removed then routed".
	pub ClusterRemovalProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_UPDATE_ACCEPTED,
			events::CLUSTER_UPDATE_REFUSED,
			events::CLUSTER_WORK_ROUTED,
			events::CLUSTER_WORK_UNAVAILABLE
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_UPDATE_ACCEPTED => InstanceAdded },
		InstanceAdded => { events::CLUSTER_WORK_ROUTED => Routed },
		Routed => { events::CLUSTER_UPDATE_REFUSED => ForeignRefused },
		ForeignRefused => { events::CLUSTER_UPDATE_ACCEPTED => InstanceRemoved },
		InstanceRemoved => { events::CLUSTER_WORK_UNAVAILABLE => Unrouted },
		Unrouted => { }
	}
	terminal { Unrouted }
}

// A signed update that removes an instance URN unroutes it: work for
// the type routed before the removal and is Unavailable after. A
// removal naming a foreign realm is refused wholesale.
tb_scenario! {
	name: cluster_removal_update_unroutes_instance,
	config: ScenarioConf::builder()
		.with_spec(ClusterRemovalSpec::latest())
		.with_csp(ClusterRemovalProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let conf = routing_cluster_conf(&certs, None);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let trace = Arc::new(trace.share());
			let config = Some(servlet_tls_config(&certs)?);
			let servlet = ClusterTestServlet::start(trace, config).await?;
			let servlet_addr = servlet.addr().to_string();
			let hive_addr = b"127.0.0.1:65200".as_slice();

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			let registered = register_signed_hive(&mut client, &certs.key, b"removal-reg", hive_addr).await?;
			assert_eq!(registered.status, TransitStatus::Ok);

			let added = vec![servlet_info("ping", servlet_addr.as_bytes())];
			let removed = vec![];
			let request = servlet_address_update(hive_addr, added, removed);
			let added = emit_servlet_update(&mut client, &certs.key, b"removal-add", request).await?;
			assert_eq!(added.status, TransitStatus::Ok);

			let routed = emit_ping_work(&mut client, b"pre-removal-work").await?;
			assert_eq!(routed.status, TransitStatus::Ok, "work must route while the instance is registered");

			let removed = vec![foreign_realm_instance(&servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			let foreign = emit_servlet_update(&mut client, &certs.key, b"removal-foreign", request).await?;
			assert_eq!(foreign.status, TransitStatus::PermissionDenied, "foreign-realm removals must be refused");

			let removed = vec![servlet_instance(&servlet_urn("ping"), &servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			let removed = emit_servlet_update(&mut client, &certs.key, b"removal-remove", request).await?;
			assert_eq!(removed.status, TransitStatus::Ok, "owner removal of its instance must be accepted");

			let unrouted = emit_ping_work(&mut client, b"post-removal-work").await?;
			assert_eq!(
				unrouted.status,
				TransitStatus::Unavailable,
				"work for a fully removed type must be unavailable"
			);

			servlet.stop();
			cluster.stop();
			Ok(())
		}
	}
}

// ============================================================================
// Multi-Instance Topology: Load Balancer Wiring
// ============================================================================

/// Shared fixture for the topology scenarios: gateway certs plus the
/// selection set the [`RecordingBalancer`] populates so a scenario can
/// assert the spread ("both indices seen" is set semantics the assertion
/// spec language cannot express).
struct TopologyCtx {
	certs: Arc<GatewayCerts>,
	selected: Arc<Mutex<HashSet<usize>>>,
}

impl TopologyCtx {
	fn new() -> Self {
		Self { certs: Arc::new(cluster_certs()), selected: Arc::new(Mutex::new(HashSet::new())) }
	}

	fn selected_indices(&self) -> HashSet<usize> {
		self.selected.lock().map(|guard| guard.clone()).unwrap_or_default()
	}
}

/// Wraps any strategy to prove the `Arc<dyn LoadBalancer>` is consulted
/// and a custom strategy threads through
/// [`ClusterConfBuilder::with_load_balancer`]: every offer is recorded as
/// a `BALANCER_OFFERED` event valued with the slate width, and returned
/// indices land in the shared selection set.
struct RecordingBalancer<L: LoadBalancer> {
	inner: L,
	trace: TraceCollector,
	selected: Arc<Mutex<HashSet<usize>>>,
}

impl<L: LoadBalancer> RecordingBalancer<L> {
	fn new(inner: L, trace: &TraceCollector, ctx: &TopologyCtx) -> Self {
		Self { inner, trace: trace.share(), selected: Arc::clone(&ctx.selected) }
	}
}

impl<L: LoadBalancer> LoadBalancer for RecordingBalancer<L> {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		let value = candidates.len() as u64;
		let _ = self.trace.event_with(BALANCER_OFFERED, &[], value);
		let pick = self.inner.select(candidates);
		if let (Some(index), Ok(mut chosen)) = (pick, self.selected.lock()) {
			chosen.insert(index);
		}
		pick
	}
}

fn topology_cluster_conf(trace: &TraceCollector, ctx: &TopologyCtx, inner: impl LoadBalancer + 'static) -> ClusterConf {
	let tls = cluster_tls_config(ctx.certs.as_ref());
	let load_balancer = RecordingBalancer::new(inner, trace, ctx);
	ClusterConf::builder(tls).with_load_balancer(load_balancer).build()
}

/// Register two live ping servlets as instances of one type and route
/// `routes` work requests through the gateway. Every response status is
/// recorded as a valued event the spec asserts against
/// [`TransitStatus::Ok`].
async fn drive_topology_routes(
	trace: &TraceCollector,
	ctx: &TopologyCtx,
	cluster: &ClusterGateway,
	routes: usize,
) -> Result<(), TightBeamError> {
	let trace = Arc::new(trace.share());
	let config = Some(servlet_tls_config(ctx.certs.as_ref())?);
	let servlet_a = ClusterTestServlet::start(Arc::clone(&trace), config).await?;
	let config = Some(servlet_tls_config(ctx.certs.as_ref())?);
	let servlet_b = ClusterTestServlet::start(Arc::clone(&trace), config).await?;
	let addr_a = servlet_a.addr().to_string();
	let addr_b = servlet_b.addr().to_string();
	let hive_addr = b"127.0.0.1:65210".as_slice();

	let mut client = connect_cluster(ctx.certs.as_ref(), cluster.addr()).await?;

	let registered = register_signed_hive(&mut client, &ctx.certs.key, b"topo-reg", hive_addr).await?;
	let value = registered.status;
	trace.event_with(TOPOLOGY_REGISTER_STATUS, &[], value)?;

	let added = vec![servlet_info("ping", addr_a.as_bytes()), servlet_info("ping", addr_b.as_bytes())];
	let removed = vec![];
	let request = servlet_address_update(hive_addr, added, removed);
	let added = emit_servlet_update(&mut client, &ctx.certs.key, b"topo-add", request).await?;
	let value = added.status;
	trace.event_with(TOPOLOGY_ADD_STATUS, &[], value)?;

	for round in 0..routes {
		let id = format!("topo-work-{round}");
		let routed = emit_ping_work(&mut client, id.as_bytes()).await?;
		let value = routed.status;
		trace.event_with(TOPOLOGY_ROUTE_STATUS, &[], value)?;
	}

	servlet_a.stop();
	servlet_b.stop();
	Ok(())
}

/// Drive `routes` requests and assert the strategy selected both
/// instances. Shared by every topology scenario so they differ only in
/// strategy and volume; the offer widths travel as `BALANCER_OFFERED`
/// events the spec value-asserts.
async fn assert_topology_spread(
	trace: &TraceCollector,
	ctx: &TopologyCtx,
	cluster: &ClusterGateway,
	routes: usize,
) -> Result<(), TightBeamError> {
	drive_topology_routes(trace, ctx, cluster, routes).await?;

	assert_eq!(
		ctx.selected_indices(),
		HashSet::from([0usize, 1usize]),
		"strategy must spread work across both instances"
	);

	Ok(())
}

tb_assert_spec! {
	pub TopologySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, at_least!(4)),
			(BALANCER_OFFERED, at_least!(4), equals!(2u64)),
			(TOPOLOGY_REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(TOPOLOGY_ADD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(TOPOLOGY_ROUTE_STATUS, at_least!(4), equals!(TransitStatus::Ok))
		]
	}
}

// A pluggable RoundRobin threads through the builder and deterministically
// spreads work across both registered instances of one type.
tb_scenario! {
	name: cluster_round_robin_spreads_work_across_instances,
	spec: TopologySpec,
	environment Cluster {
		context: TopologyCtx::new(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let inner = RoundRobin::default();
			let conf = topology_cluster_conf(&trace, &ctx, inner);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			assert_topology_spread(&trace, &ctx, &cluster, 4).await?;
			cluster.stop();
			Ok(())
		}
	}
}

// The default pheromone forager (via `with_seed` for a reproducible stream)
// explores both instances rather than locking onto one, the stigmergic
// spread the deterministic-argmax predecessor could not provide.
tb_scenario! {
	name: cluster_default_forager_spreads_work_across_instances,
	spec: TopologySpec,
	environment Cluster {
		context: TopologyCtx::new(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let inner = StochasticForager::with_seed(0x7B_EA_11);
			let conf = topology_cluster_conf(&trace, &ctx, inner);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			assert_topology_spread(&trace, &ctx, &cluster, 12).await?;
			cluster.stop();
			Ok(())
		}
	}
}
