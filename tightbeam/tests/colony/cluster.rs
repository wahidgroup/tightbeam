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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sha3::Sha3_256;
use tightbeam::der::Sequence;
use tightbeam::{
	at_least, at_most,
	builder::TypeBuilder,
	cluster,
	colony::{
		cluster::{
			Admission, Cluster, ClusterConf, ClusterError, ClusterRequest, ClusterTlsConfig, ClusterWorkRequest,
			ClusterWorkResponse, GossipAdmission, GossipConf, GossipDigest, GossipJournal, HeartbeatConf,
			MemoryGossipJournal, TokenBucketAdmission,
		},
		common::{
			current_timestamp_ms, servlet_instance, type_canonical_bytes, ColonyNamespace, GossipReconciliation,
			GossipResponse, GossipRumor, GossipWant, InstanceMetrics, LoadBalancer, PeerAdvertisement,
			PeerAdvertisementResponse, RoundRobin, StochasticForager,
		},
		hive::{
			Hive, HiveConf, HiveTlsConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdate,
			ServletAddressUpdateResponse, ServletBox, ServletInfo,
		},
		servlet::ServletConf,
	},
	compose,
	constants::{
		DEFAULT_COMMAND_FRESHNESS_WINDOW_MS, DEFAULT_GOSSIP_RETENTION_MS, MAX_ADVERTISED_TYPES,
		MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_TTL,
	},
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
		ConnectionPool, GenericClient, PoolConfig,
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
pub(crate) const PEER_ROUTES_AFTER: Urn<'static> = Urn::new("test", "event:cluster/peer-routes-after");
pub(crate) const PEER_ROUTES_AFTER_INSTALLS: Urn<'static> =
	Urn::new("test", "event:cluster/peer-routes-after-installs");
pub(crate) const PEER_ROUTES_AFTER_WITHDRAWAL: Urn<'static> =
	Urn::new("test", "event:cluster/peer-routes-after-withdrawal");
pub(crate) const PEER_PING_LIVE_AFTER_WITHDRAWAL: Urn<'static> =
	Urn::new("test", "event:cluster/peer-ping-live-after-withdrawal");
pub(crate) const GOSSIP_PUBLISH_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-publish-status");
pub(crate) const GOSSIP_CONVERGED: Urn<'static> = Urn::new("test", "event:cluster/gossip-converged");
pub(crate) const GOSSIP_CLAMP_LEAKED: Urn<'static> = Urn::new("test", "event:cluster/gossip-clamp-leaked");
pub(crate) const WORK_STATUS: Urn<'static> = Urn::new("test", "event:cluster/work-status");
pub(crate) const WORK_PAYLOAD: Urn<'static> = Urn::new("test", "event:cluster/work-payload");
pub(crate) const REGISTER_STATUS: Urn<'static> = Urn::new("test", "event:cluster/register-status");
pub(crate) const REGISTRY_HIVES: Urn<'static> = Urn::new("test", "event:cluster/registry-hives");
pub(crate) const REGISTER_ASSIGNED_ID: Urn<'static> = Urn::new("test", "event:cluster/register-assigned-id");
pub(crate) const REGISTRY_EMPTIED: Urn<'static> = Urn::new("test", "event:cluster/registry-emptied");
pub(crate) const LOCAL_SERVLETS_AFTER_INSTALLS: Urn<'static> =
	Urn::new("test", "event:cluster/local-servlets-after-installs");
pub(crate) const PEER_ROUTE_EXPOSED: Urn<'static> = Urn::new("test", "event:cluster/peer-route-exposed");
pub(crate) const PEER_SLATE_MATCHES: Urn<'static> = Urn::new("test", "event:cluster/peer-slate-matches");
pub(crate) const PEER_PING_TYPE_LEARNED: Urn<'static> = Urn::new("test", "event:cluster/peer-ping-type-learned");
pub(crate) const BALANCER_SPREAD: Urn<'static> = Urn::new("test", "event:cluster/balancer-spread");
pub(crate) const GOSSIP_PENDING_BEFORE_REGISTER: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-pending-before-register");
pub(crate) const JOURNAL_RECORDS: Urn<'static> = Urn::new("test", "event:cluster/journal-records");
pub(crate) const JOURNAL_ACKS: Urn<'static> = Urn::new("test", "event:cluster/journal-acks");
pub(crate) const GOSSIP_LIMITED_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-limited-status");
pub(crate) const GOSSIP_RELAY_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-relay-status");
pub(crate) const GOSSIP_ROUTES_AFTER_SCORING: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-routes-after-scoring");
pub(crate) const GOSSIP_GREY_HOLE_CONTAINED: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-grey-hole-contained");
pub(crate) const GOSSIP_RECONCILE_MEMBER_WANT: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-reconcile-member-want");
pub(crate) const GOSSIP_RECONCILE_FOREIGN_WANT: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-reconcile-foreign-want");
pub(crate) const GOSSIP_RECONCILE_STRANGER_WANT: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-reconcile-stranger-want");
pub(crate) const GOSSIP_HELD_NO_INGRESS: Urn<'static> = Urn::new("test", "event:cluster/gossip-held-no-ingress");
pub(crate) const GOSSIP_PENDING_NO_INGRESS: Urn<'static> = Urn::new("test", "event:cluster/gossip-pending-no-ingress");

/// Address the simulated peer gateway advertises itself at.
pub(crate) const PEER_GATEWAY_ADDR: &[u8] = b"127.0.0.1:9000";

/// Failed forwards a peer trail tolerates before abandonment in the
/// infection-containment scenarios. Kept small so the gate stays fast;
/// the containment specs assert exactly this many `CLUSTER_WORK_FAILED`
/// before selection drops the peer.
const CONTAINMENT_ABANDON_LIMIT: u32 = 3;

// ============================================================================
// Shared Test Certificates
// ============================================================================

type ClusterTestCerts = GatewayCerts;

/// Colony every member gateway in these tests belongs to. Membership
/// travels as a URI SAN on the gateway certificate, never the subject.
fn test_colony_urn() -> Urn<'static> {
	colony_ns().colony("main").expect("static colony name")
}

fn cluster_certs() -> ClusterTestCerts {
	GatewayCerts::generate_colony(&test_colony_urn())
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

/// Record a registration outcome on the trace: the wire status as
/// `REGISTER_STATUS`, the registry size as `REGISTRY_HIVES`, and whether
/// a hive id was assigned as `REGISTER_ASSIGNED_ID`. The specs pin the
/// expected values, so scenarios need no inline checks.
fn record_register_response(
	trace: &TraceCollector,
	response: &RegisterHiveResponse,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	trace.event_with(REGISTER_STATUS, &[], response.status)?;
	trace.event_with(REGISTRY_HIVES, &[], cluster.hive_count() as u64)?;
	trace.event_with(REGISTER_ASSIGNED_ID, &[], u64::from(response.hive_id.is_some()))?;
	Ok(())
}

/// Record a work outcome on the trace: the wire status as `WORK_STATUS`
/// and payload presence as `WORK_PAYLOAD`, for spec verification.
fn record_work_status(trace: &TraceCollector, response: &ClusterWorkResponse) -> Result<(), TightBeamError> {
	trace.event_with(WORK_STATUS, &[], response.status)?;
	trace.event_with(WORK_PAYLOAD, &[], u64::from(response.payload.is_some()))?;
	Ok(())
}

async fn signed_control_frame_with_order(
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
	order: u64,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V0)
		.with_id(id)
		.with_order(order)
		.with_message(request)
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

async fn signed_control_frame_with(
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	signed_control_frame_with_order(key, id, request, current_timestamp_ms()).await
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

fn registration_request(hive_addr: &[u8]) -> ClusterRequest {
	ClusterRequest::RegisterHive(RegisterHiveRequest {
		hive_addr: hive_addr.to_vec(),
		servlet_addresses: vec![],
		metadata: None,
	})
}

fn servlet_address_update(hive_addr: &[u8], added: Vec<ServletInfo>, removed: Vec<Urn<'static>>) -> ClusterRequest {
	ClusterRequest::ServletAddressUpdate(ServletAddressUpdate { hive_id: hive_urn(hive_addr), added, removed })
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

/// Poll until the gateway exposes no live peer routes or attempts exhaust.
/// Abandonment happens on the advertise beat's cadence, so it is only
/// observable by polling. Branching lives here, not in scenarios.
async fn wait_for_no_peer_routes(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> bool {
	for _ in 0..attempts {
		if cluster.peer_routes().is_empty() {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	cluster.peer_routes().is_empty()
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
			(events::CLUSTER_WORK_REFUSED, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
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
			let work_request = ClusterRequest::Work(ClusterWorkRequest::new(
				servlet_instance(&servlet_urn("ping"), "127.0.0.1:9999"),
				encode(&PingRequest { value: 21 })?,
			));

			let frame = frame_compose(Version::V0)
				.with_id(b"instance-work")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			trace.event(WORK_SENT)?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			record_work_status(&trace, &work_response)?;

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
	peering_cluster_conf_with_trust(certs, Arc::clone(&certs.trust))
}

/// Like [`peering_cluster_conf`] but with an explicit peer trust store
/// (used when more than one peer identity must verify).
fn peering_cluster_conf_with_trust(certs: &ClusterTestCerts, peer_trust: Arc<dyn CertificateTrust>) -> ClusterConf {
	let tls = ClusterTlsConfig { peer_trust: Some(peer_trust), ..cluster_tls_config(certs) };
	ClusterConf::new(tls)
}

/// Importer that trusts peers only on the peer plane (hive_trust empty).
fn peering_peer_trust_only(certs: &ClusterTestCerts) -> ClusterConf {
	let tls = ClusterTlsConfig {
		hive_trust: None,
		peer_trust: Some(Arc::clone(&certs.trust)),
		..cluster_tls_config(certs)
	};
	ClusterConf::new(tls)
}

fn peering_with_dial_allowlist(certs: &ClusterTestCerts, allowlist: Vec<String>) -> ClusterConf {
	let mut conf = peering_cluster_conf(certs);
	conf.peer_dial_allowlist = Some(allowlist);
	conf
}

/// Importer conf whose peer trails abandon after a few failed forwards.
/// The limit is small so containment scenarios stay fast; the specs pin
/// [`CONTAINMENT_ABANDON_LIMIT`] failures before routing stops.
fn containment_cluster_conf(certs: &ClusterTestCerts) -> ClusterConf {
	let mut conf = peering_cluster_conf(certs);
	conf.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;
	conf
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
/// signed by `signer`. The decoded status lands on the trace for spec
/// verification.
async fn advertise_peer_signed(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	cluster: &ClusterGateway,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
) -> Result<(), TightBeamError> {
	let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
		gateway_addr: gateway_addr.to_vec(),
		advertised_types: types,
	});

	let frame = signed_control_frame_with(signer, b"peer-advertise", request).await?;
	send_advertisement_frame(trace, connect_certs, cluster, frame).await
}

/// Emit an already-signed advertisement frame: lets replay scenarios
/// resend a byte-identical frame. Every decoded status lands on the
/// trace as `PEER_AD_STATUS`, and the surviving peer-route count as
/// `PEER_ROUTES_AFTER`, for spec verification.
async fn send_advertisement_frame(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(certs, cluster.addr()).await?;
	trace.event(PEER_ADVERTISE_SENT)?;

	let response_frame = emit_frame(&mut client, frame).await?;
	let response: PeerAdvertisementResponse = decode(&response_frame.message)?;
	trace.event_with(PEER_AD_STATUS, &[], response.status)?;
	trace.event_with(PEER_ROUTES_AFTER, &[], cluster.peer_servlets().len() as u64)?;

	Ok(())
}

/// Send one signed advertisement of `types` from a peer at `gateway_addr`.
async fn advertise_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	gateway_addr: &[u8],
	types: Vec<Urn<'static>>,
) -> Result<(), TightBeamError> {
	advertise_peer_signed(trace, certs, &certs.key, cluster, gateway_addr, types).await
}

/// Advertise a one-type ping slate from the simulated peer gateway: the
/// shared preamble for every scenario exercising behavior after a peer
/// route exists. The specs assert `PEER_AD_STATUS` proved the install.
async fn install_ping_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	advertise_peer(trace, certs, cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await
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
	},
	// 1.1.0: the wire outcome joins the contract so accepting scenarios
	// prove the peer saw Ok, not merely that the install event fired.
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok))
		]
	},
	// 1.2.0: the surviving route count joins the contract: one advertised
	// type must leave exactly one installed peer route.
	V(1,2,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64))
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
	},
	// 1.1.0: refusal contract pins the wire status AND the security
	// property refuse => zero installed peer routes.
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64))
		]
	}
}

// Claimed dial outside the optional allowlist is refused before install.
tb_scenario! {
	name: cluster_refuses_peer_dial_outside_allowlist,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_with_dial_allowlist(&certs, vec![String::from("10.0.0.1:9000")])).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;

			cluster.stop();
			Ok(())
		}
	}
}

// Allowlisted dial installs normally.
tb_scenario! {
	name: cluster_accepts_peer_dial_on_allowlist,
	spec: ClusterPeerAdvertisedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let allowed = String::from_utf8_lossy(PEER_GATEWAY_ADDR).into_owned();
			start_cluster(&trace, peering_with_dial_allowlist(&certs, vec![allowed])).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerRouteIntrospectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(LOCAL_SERVLETS_AFTER_INSTALLS, exactly!(1), equals!(0u64)),
			(PEER_ROUTE_EXPOSED, exactly!(1), equals!(1u64))
		]
	}
}

// A trusted peer advertisement installs peer routes: the advertised type
// surfaces in `peer_servlets` (learned), never in `available_servlets`
// (local hives only). No forwarding happens in this stage.
tb_scenario! {
	name: cluster_accepts_peer_advertisement,
	spec: ClusterPeerRouteIntrospectionSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			trace.event_with(LOCAL_SERVLETS_AFTER_INSTALLS, &[], cluster.available_servlets().len() as u64)?;

			// One learned route keyed by the advertised type, exposing the
			// claimed dial path and the signer fingerprint.
			let ping_canonical = type_canonical_bytes(&servlet_urn("ping"));
			let routes = cluster.peer_routes();
			let exposed = routes.len() == 1
				&& routes.first().is_some_and(|route| {
					route.servlet_type == ping_canonical
						&& route.dial_addr == PEER_GATEWAY_ADDR && !route.peer_id.is_empty()
				});

			trace.event_with(PEER_ROUTE_EXPOSED, &[], u64::from(exposed))?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerMultiTypeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(2u64)),
			(PEER_SLATE_MATCHES, exactly!(1), equals!(1u64))
		]
	}
}

// A slate is not one type: every advertised type installs its own peer
// route, so a two-type advertisement surfaces both types.
tb_scenario! {
	name: cluster_multi_type_advertisement_installs_all,
	spec: ClusterPeerMultiTypeSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let slate = vec![servlet_urn("ping"), servlet_urn("echo")];
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, slate).await?;

			let mut peers = cluster.peer_servlets();
			peers.sort_unstable();

			let mut expected = vec![
				type_canonical_bytes(&servlet_urn("ping")),
				type_canonical_bytes(&servlet_urn("echo")),
			];
			expected.sort_unstable();

			trace.event_with(PEER_SLATE_MATCHES, &[], u64::from(peers == expected))?;

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
	use tightbeam::testing::utils::create_test_certificate_with_uri_sans;

	let gateway = cluster_certs();
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_b = create_test_certificate_with_uri_sans(&raw_b, &[&test_colony_urn().to_string()]);
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
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;

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

			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![foreign]).await?;

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

// Retry ordering: the conflicted advertisement is refused before the
// byte-identical resend installs. Counting alone cannot prove the
// refusal preceded the install.
tb_process_spec! {
	pub ClusterAdRetryProcess,
	events {
		observable {
			events::CLUSTER_PEER_ADVERTISE_REFUSED,
			events::CLUSTER_PEER_ADVERTISED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_PEER_ADVERTISE_REFUSED => ConflictRefused },
		ConflictRefused => { events::CLUSTER_PEER_ADVERTISED => Installed },
		Installed => { }
	}
	terminal { Installed }
}

// A refusal is not a penalty box: an advertisement refused on local state
// (address conflict) releases its replay record, so the peer can resend
// the byte-identical signed frame once the conflict clears and install.
tb_scenario! {
	name: cluster_advertisement_retryable_after_refusal,
	config: ScenarioConf::builder()
		.with_spec(ClusterPeerReplayReleasedSpec::latest())
		.with_csp(ClusterAdRetryProcess)
		.build(),
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
	pub ClusterPeerForwardLoopGuardSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Unavailable)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// Already-forwarded work never re-forwards: peer-only types stay
// Unavailable under the one-hop loop guard.
tb_scenario! {
	name: cluster_refuses_reforward_of_peer_work,
	spec: ClusterPeerForwardLoopGuardSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			trace.event(WORK_SENT)?;

			let work_response = emit_forwarded_ping_work(&mut client, b"reforward-guard").await?;
			record_work_status(&trace, &work_response)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerForwardEchoSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Unary cross-cluster forward: ping lives only on B; client asks A; A
// wraps Work{forwarded:true}, B serves locally, echo returns.
tb_scenario! {
	name: cluster_forwards_work_to_peer_gateway,
	spec: ClusterPeerForwardEchoSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, peering_cluster_conf(&certs)).await?;
			let receiver_addr = receiver.addr();
			let config = advertising_cluster_conf(&certs, receiver_addr.to_string());
			let advertiser = start_cluster(&trace, config).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			trace.event(WORK_SENT)?;

			let mut client = connect_cluster(&certs, receiver.addr()).await?;
			let work_response = emit_ping_work(&mut client, b"forward-echo").await?;
			let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;

			let ping_response: PingResponse = decode(&payload)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

// Peer hops dial on peer_trust: importer with hive_trust=None still forwards
// when the peer gateway cert is anchored only in peer_trust.
tb_scenario! {
	name: cluster_forwards_on_peer_trust_plane,
	spec: ClusterPeerForwardEchoSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, peering_peer_trust_only(&certs)).await?;
			let receiver_addr = receiver.addr();
			let config = advertising_cluster_conf(&certs, receiver_addr.to_string());
			let advertiser = start_cluster(&trace, config).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			trace.event(WORK_SENT)?;

			let mut client = connect_cluster(&certs, receiver.addr()).await?;
			let work_response = emit_ping_work(&mut client, b"peer-plane").await?;
			let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
			let ping_response: PingResponse = decode(&payload)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerCollideSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64))
		]
	}
}

// Claimed gateway_addr that matches a local servlet address is refused.
tb_scenario! {
	name: cluster_refuses_peer_dial_colliding_local_servlet,
	spec: ClusterPeerCollideSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let cluster = start_cluster(&trace, peering_cluster_conf(&certs)).await?;
			hive.register_with_cluster(cluster.addr()).await?;

			let hive_addr = hive.addr().to_string().into_bytes();
			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"collide-local",
				servlet_address_update(&hive_addr, vec![servlet_info("ping", PEER_GATEWAY_ADDR)], vec![]),
			)
			.await?;

			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("echo")]).await?;

			cluster.stop();
			hive.stop();
			Ok(())
		}
	}
}

// WORK_SENT = CONTAINMENT_ABANDON_LIMIT failing forwards + 1 probe after
// abandonment; CLUSTER_WORK_FAILED = CONTAINMENT_ABANDON_LIMIT.
tb_assert_spec! {
	pub ClusterPeerContainmentSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(4)),
			(events::CLUSTER_WORK_FAILED, exactly!(3)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

// Abandonment ordering: unavailability must follow exactly
// CONTAINMENT_ABANDON_LIMIT failed forwards on the installed route.
// Counting cannot prove the trail failed before selection dropped it.
tb_process_spec! {
	pub ClusterContainmentProcess,
	events {
		observable {
			events::CLUSTER_PEER_ADVERTISED,
			events::CLUSTER_WORK_FAILED,
			events::CLUSTER_WORK_UNAVAILABLE
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_PEER_ADVERTISED => Installed },
		Installed => { events::CLUSTER_WORK_FAILED => FailedOnce },
		FailedOnce => { events::CLUSTER_WORK_FAILED => FailedTwice },
		FailedTwice => { events::CLUSTER_WORK_FAILED => Abandoned },
		Abandoned => { events::CLUSTER_WORK_UNAVAILABLE => Contained },
		Contained => { }
	}
	terminal { Contained }
}

// Infection containment: a peer route to a gateway that never answers is
// weakened on each failed forward and, past the abandonment limit, drops
// out of selection so the peer-only type reports Unavailable with no
// further forward attempt.
tb_scenario! {
	name: cluster_abandons_failing_peer_trail,
	config: ScenarioConf::builder()
		.with_spec(ClusterPeerContainmentSpec::latest())
		.with_csp(ClusterContainmentProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, containment_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			// Each forward reaches the dead peer and weakens the trail.
			for i in 0..CONTAINMENT_ABANDON_LIMIT {
				trace.event(WORK_SENT)?;
				let id = [b'f', i as u8];
				let _ = emit_ping_work(&mut client, &id).await?;
			}

			// Trail abandoned: selection drops it, so the peer-only type
			// is Unavailable and no further forward is attempted.
			trace.event(WORK_SENT)?;
			let _ = emit_ping_work(&mut client, b"gone").await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerIsolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(4)),
			(events::CLUSTER_WORK_FAILED, exactly!(3)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Healing ordering: the local hive joins only after the dead trail has
// absorbed its full failure budget, and the successful route follows the
// join. Counting cannot prove work failed before the colony healed.
tb_process_spec! {
	pub ClusterIsolationProcess,
	events {
		observable {
			events::CLUSTER_PEER_ADVERTISED,
			events::CLUSTER_WORK_FAILED,
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_WORK_ROUTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_PEER_ADVERTISED => Installed },
		Installed => { events::CLUSTER_WORK_FAILED => FailedOnce },
		FailedOnce => { events::CLUSTER_WORK_FAILED => FailedTwice },
		FailedTwice => { events::CLUSTER_WORK_FAILED => Abandoned },
		Abandoned => { events::CLUSTER_HIVE_REGISTERED => Healed },
		Healed => { events::CLUSTER_WORK_ROUTED => Served },
		Served => { }
	}
	terminal { Served }
}

// Containment isolates only the bad nest: after the dead peer trail is
// abandoned, a local ping hive joins and serves the same type, so work
// keeps flowing on-colony while the peer stays dropped.
tb_scenario! {
	name: cluster_isolates_abandoned_peer_and_serves_local,
	config: ScenarioConf::builder()
		.with_spec(ClusterPeerIsolationSpec::latest())
		.with_csp(ClusterIsolationProcess)
		.build(),
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let importer = start_cluster(&trace, containment_cluster_conf(&certs)).await?;

			install_ping_peer(&trace, &certs, &importer).await?;

			let mut client = connect_cluster(&certs, importer.addr()).await?;

			// Fail the peer trail into abandonment before any local route.
			for i in 0..CONTAINMENT_ABANDON_LIMIT {
				trace.event(WORK_SENT)?;
				let id = [b'x', i as u8];
				let _ = emit_ping_work(&mut client, &id).await?;
			}

			// Heal the colony: a local ping hive joins after the bad nest
			// is abandoned, leaving one live route for the type.
			hive.register_with_cluster(importer.addr()).await?;

			trace.event(WORK_SENT)?;
			let work_response = emit_ping_work(&mut client, b"local").await?;
			let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
			let ping_response: PingResponse = decode(&payload)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerLocalitySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(36)),
			(events::CLUSTER_WORK_FORWARDED, at_most!(6)),
			(WORK_ECHOED, exactly!(36), equals!(42u64))
		]
	}
}

// Local and peer both serve ping: warm local trails first, then admit the
// peer route. Seeded forager keeps the roulette stream reproducible so the
// reinforced local trail claims most later work on-colony.
tb_scenario! {
	name: cluster_locality_prefers_local_over_peer,
	spec: ClusterPeerLocalitySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut local_conf = peering_cluster_conf(&certs);
			local_conf.load_balancer = Arc::new(StochasticForager::with_seed(0x7F0));
			let local_gateway = start_cluster(&trace, local_conf).await?;

			hive.register_with_cluster(local_gateway.addr()).await?;

			for i in 0..12u8 {
				trace.event(WORK_SENT)?;

				let mut client = connect_cluster(&certs, local_gateway.addr()).await?;
				let id = [b'w', b'a', b'r', i];

				let work_response = emit_ping_work(&mut client, &id).await?;
				let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
				let ping_response: PingResponse = decode(&payload)?;
				trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
			}

			let config = advertising_cluster_conf(&certs, local_gateway.addr().to_string());
			let peer_gateway = start_cluster(&trace, config).await?;
			let peer_hive = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			peer_hive.register_with_cluster(peer_gateway.addr()).await?;

			let learned = wait_for_peer_types(&local_gateway, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			for i in 0..24u8 {
				trace.event(WORK_SENT)?;
				let mut client = connect_cluster(&certs, local_gateway.addr()).await?;
				let id = [b'l', b'o', b'c', i];

				let work_response = emit_ping_work(&mut client, &id).await?;
				let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
				let ping_response: PingResponse = decode(&payload)?;
				trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
			}

			peer_hive.stop();
			peer_gateway.stop();
			local_gateway.stop();
			hive.stop();
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
			(events::CLUSTER_PEER_ADVERTISED, exactly!(2)),
			(PEER_AD_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(PEER_ROUTES_AFTER_WITHDRAWAL, exactly!(1), equals!(0u64))
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
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], cluster.peer_servlets().len() as u64)?;

			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;
			trace.event_with(PEER_ROUTES_AFTER_WITHDRAWAL, &[], cluster.peer_servlets().len() as u64)?;

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
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(PEER_PING_TYPE_LEARNED, exactly!(1), equals!(1u64))
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

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			let ping_canonical = type_canonical_bytes(&servlet_urn("ping"));
			let keyed = learned.first().is_some_and(|learned_type| *learned_type == ping_canonical);
			trace.event_with(PEER_PING_TYPE_LEARNED, &[], u64::from(keyed))?;

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

			let config = advertising_cluster_conf(&certs, receiver.addr().to_string());
			let advertiser = start_cluster(&trace, config).await?;
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
			let config = advertising_cluster_conf(&certs, receiver.addr().to_string());
			let advertiser = start_cluster(&trace, config).await?;

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
	use tightbeam::testing::utils::create_test_certificate_with_uri_sans;

	let exporter = cluster_certs();
	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let receiver_cert = create_test_certificate_with_uri_sans(&raw, &[&test_colony_urn().to_string()]);
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
			(events::CLUSTER_GATE_BLOCKED, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
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

			let work_request = ClusterRequest::Work(ClusterWorkRequest::new(
				servlet_urn("ping"),
				encode(&PingRequest { value: 21 })?,
			));

			let frame = frame_compose(Version::V0)
				.with_id(b"policy-test")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let mut client = connect_cluster(&certs, cluster_addr).await?;

			trace.event(WORK_SENT)?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			record_work_status(&trace, &work_response)?;

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
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(REGISTRY_HIVES, exactly!(1), equals!(0u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(0u64))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_unsigned_registration,
	spec: ClusterUnsignedRegistrationSpec,
	environment Cluster {
		context: cluster_certs(),
		// Registration itself is under test, so no `hives:` key.
		// The client drives it; the spec asserts the rejection.
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
			record_register_response(&trace, &response, &cluster)?;

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
			(events::HIVE_REREGISTERED, exactly!(0)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(REGISTRY_HIVES, exactly!(1), equals!(0u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(0u64))
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
			record_register_response(&trace, &response, &cluster)?;

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
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(REGISTRY_HIVES, exactly!(1), equals!(0u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(0u64))
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
				registration_request(b"127.0.0.1:65000"),
			)
			.await?;

			trace.event(REGISTRATION_SENT)?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			record_register_response(&trace, &response, &cluster)?;

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

// Alignment ordering: the mismatched registration is refused before the
// clean one lands, and the mismatched update is refused only after the
// hive registered. Counting cannot prove which registration was refused.
tb_process_spec! {
	pub ClusterLocatorAlignProcess,
	events {
		observable {
			events::CLUSTER_REGISTER_REFUSED,
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_UPDATE_REFUSED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_REGISTER_REFUSED => MisalignRefused },
		MisalignRefused => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_UPDATE_REFUSED => UpdateRefused },
		UpdateRefused => { }
	}
	terminal { UpdateRefused }
}

// Register and update must refuse ServletInfo whose instance locator
// disagrees with the announced address: routes key by address, remove
// by URN locator (CWE-639 ghost / orphan routes).
tb_scenario! {
	name: cluster_rejects_mismatched_servlet_locator,
	config: ScenarioConf::builder()
		.with_spec(ClusterServletLocatorAlignSpec::latest())
		.with_csp(ClusterLocatorAlignProcess)
		.build(),
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
					hive_addr: hive_addr.to_vec(),
					servlet_addresses: vec![mismatch],
					metadata: None,
				}),
			)
			.await?;

			let response_frame = emit_frame(&mut client, refused_reg).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// Clean registration, then a mismatched add must refuse.
			let ok_reg = signed_control_frame(
				&certs,
				b"align-reg",
				registration_request(hive_addr),
			)
			.await?;
			let response_frame = emit_frame(&mut client, ok_reg).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			let bad_add = servlet_address_update(
				hive_addr,
				vec![servlet_info_mismatched("ping", b"127.0.0.1:65102", b"127.0.0.1:65198")],
				vec![],
			);
			let refused_update = signed_control_frame(&certs, b"misalign-update", bad_add).await?;
			let response_frame = emit_frame(&mut client, refused_update).await?;
			let _: ServletAddressUpdateResponse = decode(&response_frame.message)?;

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
				registration_request(b"127.0.0.1:65000"),
			)
			.await?;
			let replayed = fresh.to_owned();

			let response_frame = emit_frame(&mut client, fresh).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// Byte-identical resend carries an already-seen signature
			let response_frame = emit_frame(&mut client, replayed).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// Valid signature but order outside the freshness window
			let stale_ts = current_timestamp_ms() - 2 * DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
			let stale = signed_control_frame_with_order(
				&certs.key,
				b"stale-reg",
				registration_request(b"127.0.0.1:65000"),
				stale_ts,
			)
			.await?;

			let response_frame = emit_frame(&mut client, stale).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// Same enforcement on servlet address updates
			let update = servlet_address_update(
				b"127.0.0.1:65000",
				vec![servlet_info("ping", b"127.0.0.1:65001")],
				vec![],
			);
			let fresh_update = signed_control_frame(&certs, b"replay-update", update).await?;
			let replayed_update = fresh_update.to_owned();

			let response_frame = emit_frame(&mut client, fresh_update).await?;
			let _: ServletAddressUpdateResponse = decode(&response_frame.message)?;

			let response_frame = emit_frame(&mut client, replayed_update).await?;
			let _: ServletAddressUpdateResponse = decode(&response_frame.message)?;

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
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(REGISTRY_HIVES, exactly!(1), equals!(1u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(1u64)),
			(REGISTRY_EMPTIED, exactly!(1), equals!(1u64)),
			(REJECTED_HEARTBEAT_DECODED, exactly!(1), equals!(1u64)),
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
/// surfaces that flag as a valued event the spec pins after eviction.
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
				registration_request(&hive_addr_bytes),
			)
			.await?;

			let mut client = connect_cluster(certs, cluster_addr).await?;
			let response_frame = emit_frame(&mut client, registration).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			record_register_response(&trace, &response, &cluster)?;

			// Heartbeats run every 100ms with max_failures = 1: the first
			// PermissionDenied heartbeat must evict the hive
			let emptied = wait_for_empty_registry(&cluster, 50, Duration::from_millis(100)).await;
			trace.event_with(REGISTRY_EMPTIED, &[], u64::from(emptied))?;

			let decoded = rejection.rejected_decoded.load(Ordering::SeqCst);
			trace.event_with(REJECTED_HEARTBEAT_DECODED, &[], u64::from(decoded))?;

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
	let frame = signed_control_frame_with(key, id, registration_request(addr)).await?;
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
			(REGISTER_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(REGISTRY_HIVES, exactly!(1), equals!(2u64)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

// Tamper ordering: the cross-hive poison update is refused before the
// owner's update lands. Counting cannot prove the refusal hit the
// poison rather than the owner's own update.
tb_process_spec! {
	pub ClusterCrossUpdateProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_UPDATE_REFUSED,
			events::CLUSTER_UPDATE_ACCEPTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => OneRegistered },
		OneRegistered => { events::CLUSTER_HIVE_REGISTERED => TwoRegistered },
		TwoRegistered => { events::CLUSTER_UPDATE_REFUSED => CrossRefused },
		CrossRefused => { events::CLUSTER_UPDATE_ACCEPTED => OwnerLanded },
		OwnerLanded => { }
	}
	terminal { OwnerLanded }
}

tb_scenario! {
	name: cluster_rejects_cross_hive_servlet_address_update,
	config: ScenarioConf::builder()
		.with_spec(ClusterCrossHiveUpdateSpec::latest())
		.with_csp(ClusterCrossUpdateProcess)
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs.gateway, cluster_addr).await?;

			let hive_a_addr = b"127.0.0.1:65010".as_slice();
			let hive_b_addr = b"127.0.0.1:65011".as_slice();

			let response_a = register_signed_hive(&mut client, &certs.hive_a.1, b"reg-a", hive_a_addr).await?;
			let response_b = register_signed_hive(&mut client, &certs.hive_b.1, b"reg-b", hive_b_addr).await?;
			trace.event_with(REGISTER_STATUS, &[], response_a.status)?;
			trace.event_with(REGISTER_STATUS, &[], response_b.status)?;
			trace.event_with(REGISTRY_HIVES, &[], cluster.hive_count() as u64)?;

			let update_cases = [
				(
					&certs.hive_b.1,
					b"cross-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info("poison", b"127.0.0.1:65099")], vec![]),
				),
				(
					&certs.hive_a.1,
					b"owner-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info("ping", b"127.0.0.1:65012")], vec![]),
				),
			];

			for (key, id, request) in update_cases {
				emit_servlet_update(&mut client, key, id, request).await?;
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
			(REGISTRY_HIVES, exactly!(1), equals!(1u64)),
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let mut client = connect_cluster(&certs.gateway, cluster.addr()).await?;

			let hive_a_addr = b"127.0.0.1:65020".as_slice();

			register_signed_hive(&mut client, &certs.hive_a.1, b"owner-reg", hive_a_addr).await?;
			register_signed_hive(&mut client, &certs.hive_b.1, b"hijack-reg", hive_a_addr).await?;

			// The registry after the refused hijack still holds exactly
			// the owner: the failed takeover must not disturb the binding.
			trace.event_with(REGISTRY_HIVES, &[], cluster.hive_count() as u64)?;

			// The owner's update still lands: the failed hijack must not
			// have disturbed the signer binding.
			emit_servlet_update(
				&mut client,
				&certs.hive_a.1,
				b"owner-still-bound",
				servlet_address_update(hive_a_addr, vec![servlet_info("ping", b"127.0.0.1:65021")], vec![]),
			)
			.await?;

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
	let work_request = ClusterRequest::Work(ClusterWorkRequest::new(
		servlet_urn("ping"),
		encode(&PingRequest { value: 21 })?,
	));

	let frame = frame_compose(Version::V0)
		.with_id(id)
		.with_order(0)
		.with_message(work_request)
		.build()?;

	decode(&emit_frame(client, frame).await?.message)
}

/// Ping work already marked forwarded (loop-guard probe).
async fn emit_forwarded_ping_work(
	client: &mut GenericClient<TokioListener>,
	id: &[u8],
) -> Result<ClusterWorkResponse, TightBeamError> {
	let work_request = ClusterRequest::Work(
		ClusterWorkRequest::new(servlet_urn("ping"), encode(&PingRequest { value: 21 })?).into_forwarded(),
	);

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

			register_signed_hive(&mut client, &certs.key, b"removal-reg", hive_addr).await?;

			let added = vec![servlet_info("ping", servlet_addr.as_bytes())];
			let request = servlet_address_update(hive_addr, added, vec![]);
			emit_servlet_update(&mut client, &certs.key, b"removal-add", request).await?;

			emit_ping_work(&mut client, b"pre-removal-work").await?;

			let removed = vec![foreign_realm_instance(&servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			emit_servlet_update(&mut client, &certs.key, b"removal-foreign", request).await?;

			let removed = vec![servlet_instance(&servlet_urn("ping"), &servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			emit_servlet_update(&mut client, &certs.key, b"removal-remove", request).await?;

			emit_ping_work(&mut client, b"post-removal-work").await?;

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
/// selection set the [`RecordingBalancer`] populates. The scenario
/// reduces the set to a `BALANCER_SPREAD` boolean event the spec pins.
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

/// Drive `routes` requests and record whether the strategy selected both
/// instances as `BALANCER_SPREAD`. Shared by every topology scenario so
/// they differ only in strategy and volume; the offer widths travel as
/// `BALANCER_OFFERED` events the spec value-asserts.
async fn record_topology_spread(
	trace: &TraceCollector,
	ctx: &TopologyCtx,
	cluster: &ClusterGateway,
	routes: usize,
) -> Result<(), TightBeamError> {
	drive_topology_routes(trace, ctx, cluster, routes).await?;

	let spread = ctx.selected_indices() == HashSet::from([0usize, 1usize]);
	trace.event_with(BALANCER_SPREAD, &[], u64::from(spread))?;

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
			(BALANCER_SPREAD, exactly!(1), equals!(1u64)),
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
			record_topology_spread(&trace, &ctx, &cluster, 4).await?;
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
			record_topology_spread(&trace, &ctx, &cluster, 12).await?;
			cluster.stop();
			Ok(())
		}
	}
}

// ============================================================================
// Gossip Flood (rumor plane)
// ============================================================================

/// Peering conf that refloods to `peers`, returning the journal handle so
/// scenarios can poll flood convergence through the public journal trait.
fn gossip_cluster_conf(certs: &ClusterTestCerts, peers: Vec<String>) -> (ClusterConf, Arc<MemoryGossipJournal>) {
	let journal = Arc::new(MemoryGossipJournal::default());
	let mut conf = peering_cluster_conf(certs);
	conf.peers = peers;
	conf.gossip = GossipConf {
		journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
		ingress: Some(servlet_urn("ping")),
		..Default::default()
	};
	(conf, journal)
}

/// Payload-only rumor body. The rumor names no destination: flood scope
/// is the origin certificate's colony URN and local delivery is the
/// receiving gateway's ingress policy. Hop radius rides the outer
/// frame's `metadata.lifetime`, never the body.
fn rumor_body(payload: Vec<u8>) -> GossipRumor {
	GossipRumor { payload }
}

/// Sign a [`PublishGossip`] control frame with issue-time order and hop radius.
async fn signed_publish_gossip(
	key: &Secp256k1SigningKey,
	id: &[u8],
	body: GossipRumor,
	hop_ttl: u64,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::PublishGossip(body))
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Mint an origin-signed rumor [`Frame`] (the nested gossip content).
async fn mint_origin_rumor(key: &Secp256k1SigningKey, id: &[u8], body: GossipRumor) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_message(body)
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Sign a [`Gossip`] relay frame carrying a verbatim origin rumor.
async fn signed_relay_gossip(
	key: &Secp256k1SigningKey,
	id: &[u8],
	rumor: Frame,
	hop_ttl: u64,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::Gossip(Box::new(rumor)))
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Emit one signed gossip frame and record the decoded status on the
/// trace as `GOSSIP_PUBLISH_STATUS`.
async fn send_gossip_frame(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<(), TightBeamError> {
	send_gossip_frame_as(trace, connect_certs, cluster, frame, GOSSIP_PUBLISH_STATUS).await
}

/// Emit one signed gossip frame and record the decoded status under the
/// given marker, so one scenario can distinguish per-publish outcomes.
async fn send_gossip_frame_as(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipResponse = decode(&emit_frame(&mut client, frame).await?.message)?;
	trace.event_with(marker, &[], response.status)?;
	Ok(())
}

/// Sign a [`ReconcileGossip`] control frame listing the sender's held digests.
async fn signed_reconcile_gossip(
	key: &Secp256k1SigningKey,
	id: &[u8],
	held: Vec<Vec<u8>>,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_message(ClusterRequest::ReconcileGossip(GossipReconciliation { held }))
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Emit one signed reconcile frame and record the want-list size under
/// the given marker. A refused reconciliation answers an empty want.
async fn send_reconcile_frame_as(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipWant = decode(&emit_frame(&mut client, frame).await?.message)?;
	trace.event_with(marker, &[], response.want.len() as u64)?;
	Ok(())
}

/// One convergence probe over the public journal interface: every journal
/// holds exactly `held` rumors and none awaits local delivery.
fn gossip_converged(journals: &[Arc<MemoryGossipJournal>], held: usize) -> bool {
	let now = current_timestamp_ms();
	journals.iter().all(|journal| {
		let held_now = journal.held_digests(now).is_ok_and(|digests| digests.len() == held);
		let none_pending = journal.pending_local(now).is_ok_and(|rumors| rumors.is_empty());
		held_now && none_pending
	})
}

/// Poll until every journal converged or attempts exhaust. Refloods run
/// detached from the publish reply, so convergence is only observable by
/// polling. Branching lives here, not in scenarios.
async fn wait_for_gossip_converged(
	journals: &[Arc<MemoryGossipJournal>],
	held: usize,
	attempts: u32,
	interval: Duration,
) -> bool {
	for _ in 0..attempts {
		if gossip_converged(journals, held) {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	gossip_converged(journals, held)
}

/// Poll until the journal holds exactly `count` rumors awaiting local delivery.
/// Attempts exhaust if the count never matches.
/// A rumor accepted before the ingress servlet registers stays pending for beat retry.
/// Branching lives here, not in scenarios.
async fn wait_for_pending_local(
	journal: &Arc<MemoryGossipJournal>,
	count: usize,
	attempts: u32,
	interval: Duration,
) -> bool {
	for _ in 0..attempts {
		let pending = journal
			.pending_local(current_timestamp_ms())
			.is_ok_and(|rumors| rumors.len() == count);
		if pending {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	journal
		.pending_local(current_timestamp_ms())
		.is_ok_and(|rumors| rumors.len() == count)
}

tb_assert_spec! {
	pub ClusterGossipFloodSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Fan-out flood: A refloods to B and C, and every cluster delivers the
// rumor to its local ping servlet exactly once (ACCEPTED = 3). A second
// publish of the byte-identical rumor is absorbed as exactly one
// DUPLICATE, still answered Ok, and delivered nowhere a second time. The
// duplicate fires before its reply, so the count needs no polling.
tb_scenario! {
	name: cluster_gossip_floods_every_cluster_once,
	spec: ClusterGossipFloodSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (conf_a, journal_a) = gossip_cluster_conf(&certs, peers_a);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			let hive_c = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			// One signed publish frame is resent byte-identical so the origin
			// gateway re-mints the same rumor (same id, order, body) and the
			// journal absorbs the second as a Duplicate.
			let frame = signed_publish_gossip(
				&certs.key,
				b"flood-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				4,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame.clone()).await?;

			let journals = [journal_a, journal_b, journal_c];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_b.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipChainSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Partial topology A -> B -> C: A is not peered to C, so the rumor only
// reaches C through B's reflood. The publish starts at ttl 2 and arrives
// at C with ttl 0, so the hop budget is exactly consumed and the chain
// still delivers once per cluster with no duplicate.
tb_scenario! {
	name: cluster_gossip_relays_across_partial_topology,
	spec: ClusterGossipChainSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![gateway_c.addr().to_string()]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			let hive_c = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"chain-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let journals = [journal_a, journal_b, journal_c];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_b.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipHiveTrustOnlySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Hive-trust-only propagation: A configures a peer but no peer_trust, so
// it builds no peer pool. The reflood falls back to the hive pool, the
// same preference the advertise beat applies, and the rumor still reaches
// B, which verifies A's relay on its own peer plane. The publish starts
// at ttl 1, so each cluster delivers exactly once and B refloods nowhere.
tb_scenario! {
	name: cluster_gossip_refloods_under_hive_trust_only,
	spec: ClusterGossipHiveTrustOnlySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;
			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);

			conf_a.tls.peer_trust = None;

			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"hive-only-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let journals = [journal_a, journal_b];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_a.stop();
			gateway_b.stop();
			hive_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipTtlClampSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(GOSSIP_CLAMP_LEAKED, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// The operator's configured gossip ttl caps the hop radius an origin
// publish may request: with ttl 0 configured, a publish requesting the
// protocol maximum is clamped, delivered locally, and never refloods to
// the configured peer. A leaked reflood would raise ACCEPTED past one.
tb_scenario! {
	name: cluster_gossip_origin_clamps_configured_ttl,
	spec: ClusterGossipTtlClampSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
			conf_a.gossip.ttl = 0;
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"clamped-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				u64::from(MAX_GOSSIP_TTL),
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let converged = wait_for_gossip_converged(&[journal_a], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			// A leaked reflood would land within this window. Correct
			// clamping leaves B's journal empty for the whole wait.
			let leaked = wait_for_gossip_converged(&[journal_b], 1, 3, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CLAMP_LEAKED, &[], u64::from(leaked))?;

			gateway_a.stop();
			gateway_b.stop();
			hive_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Fixture for the plane-separation scenario: the gateway's own certs
/// anchor the hive plane, a distinct random identity anchors the peer
/// plane. [`GatewayCerts::generate`] cannot serve here because every
/// generated cert shares the fixed test signing key, so two "identities"
/// would verify interchangeably.
struct GossipPlaneCtx {
	gateway: ClusterTestCerts,
	peer_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn gossip_plane_ctx() -> GossipPlaneCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let peer_cert = create_test_certificate(&raw);
	let peer_key = Secp256k1SigningKey::from(raw);
	let peer_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(peer_cert)
			.expect("peer trust")
			.build(),
	);

	GossipPlaneCtx { gateway: cluster_certs(), peer_key, peer_trust }
}

tb_assert_spec! {
	pub ClusterGossipPlaneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// Trust-plane separation and admission bounds: a hive-plane signer must
// not relay peer gossip, a peer-plane signer must not publish origin
// gossip, and an oversized rumor is refused at admission even on the
// correct plane. Nothing is delivered or recorded for reflood.
tb_scenario! {
	name: cluster_gossip_refuses_wrong_plane_and_oversized,
	spec: ClusterGossipPlaneSpec,
	environment Cluster {
		context: gossip_plane_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			// The oversized rumor exceeds a single-flight envelope, so the
			// gateway offers mux: the frame must chunk across the link to
			// reach gossip admission at all.
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.pool_config.mux_offer = Some(TransportOffer::mux(8));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			// Outer frame signed on the hive plane; peer trust refuses it
			// before the nested rumor is examined.
			let dummy = mint_origin_rumor(
				&ctx.gateway.key,
				b"cross-plane-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.gateway.key, b"cross-plane-relay", dummy, 2).await?;
			send_gossip_frame(&trace, &ctx.gateway, &cluster, frame).await?;

			let frame = signed_publish_gossip(
				&ctx.peer_key,
				b"cross-plane-publish",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			send_gossip_frame(&trace, &ctx.gateway, &cluster, frame).await?;

			// A rumor past the gossip bound exceeds what one single-flight
			// envelope carries, so it rides a pooled mux link (the same
			// chunked path reflood uses) to reach admission, where the
			// payload bound refuses it on the correct plane.
			let pool_config = PoolConfig {
				mux_offer: Some(TransportOffer::mux(8)),
				..Default::default()
			};
			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(pool_config)
					.with_trust_store(Arc::clone(&ctx.gateway.trust))
					.with_trace(trace.share())
					.build(),
			);
			let mut mux_client = pool.connect(cluster.addr()).await?;

			let frame = signed_publish_gossip(
				&ctx.gateway.key,
				b"oversized-rumor",
				rumor_body(vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]),
				2,
			)
			.await?;
			let reply = mux_client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: GossipResponse = decode(&reply.message)?;
			trace.event_with(GOSSIP_PUBLISH_STATUS, &[], response.status)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipReconcileRepairSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Anti-entropy repair over the beat.
// Publisher F starts the rumor at ttl 0 so it never floods.
// Receiver R learns the rumor only when F's beat reconciles digests and pushes it.
tb_scenario! {
	name: cluster_gossip_repairs_missing_peer_over_beat,
	spec: ClusterGossipReconcileRepairSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_r, journal_r) = gossip_cluster_conf(&certs, vec![]);
			let gateway_r = start_cluster(&trace, conf_r).await?;
			let hive_r = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;

			let (mut conf_f, journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			conf_f.advertise_interval = Some(Duration::from_millis(100));
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive_r.register_with_cluster(gateway_r.addr()).await?;
			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"repair-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_f, frame).await?;

			let converged = wait_for_gossip_converged(&[journal_f, journal_r], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipRetrySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PENDING_BEFORE_REGISTER, exactly!(1), equals!(1u64)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Local-delivery retry on the beat.
// The rumor reaches R before R's ping servlet registers, so it stays pending.
// After registration, R's beat delivers from the pending set and acks.
// R has no peers: the beat runs solely for pending_local retry.
tb_scenario! {
	name: cluster_gossip_retries_pending_local_delivery,
	spec: ClusterGossipRetrySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (mut conf_r, journal_r) = gossip_cluster_conf(&certs, vec![]);
			conf_r.advertise_interval = Some(Duration::from_millis(100));
			let gateway_r = start_cluster(&trace, conf_r).await?;

			let (conf_f, journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"retry-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_f, frame).await?;

			let pending = wait_for_pending_local(&journal_r, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_PENDING_BEFORE_REGISTER, &[], u64::from(pending))?;

			let hive_r = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive_r.register_with_cluster(gateway_r.addr()).await?;

			let converged = wait_for_gossip_converged(&[journal_f, journal_r], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Counting [`GossipJournal`] wrapping the in-memory default.
/// Counters show the gateway records and acks through the injected trait object.
/// A durable backend swaps in the same way.
#[derive(Default)]
struct CountingJournal {
	inner: MemoryGossipJournal,
	records: AtomicU64,
	acks: AtomicU64,
}

impl GossipJournal for CountingJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now_ms: u64,
	) -> Result<Admission, ClusterError> {
		self.records.fetch_add(1, Ordering::SeqCst);
		self.inner.record(signer, digest, rumor, now_ms)
	}

	fn seen(&self, digest: &GossipDigest, now_ms: u64) -> Result<bool, ClusterError> {
		self.inner.seen(digest, now_ms)
	}

	fn held_digests(&self, now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError> {
		self.inner.held_digests(now_ms)
	}

	fn fetch(&self, wanted: &[GossipDigest], now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		self.inner.fetch(wanted, now_ms)
	}

	fn pending_local(&self, now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		self.inner.pending_local(now_ms)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.acks.fetch_add(1, Ordering::SeqCst);
		self.inner.ack_local(digest)
	}

	fn retention_ms(&self) -> u64 {
		self.inner.retention_ms()
	}
}

tb_assert_spec! {
	pub ClusterGossipJournalSeamSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(JOURNAL_RECORDS, exactly!(1), equals!(1u64)),
			(JOURNAL_ACKS, exactly!(1), equals!(1u64))
		]
	}
}

tb_assert_spec! {
	pub ClusterGossipRateLimitSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_LIMITED_STATUS, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Per-signer rate admission at the pipeline chokepoint.
// A one-token bucket with a slow refill admits the first publish and
// refuses the second with ResourceExhausted before it is recorded.
tb_scenario! {
	name: cluster_gossip_rate_limits_signer,
	spec: ClusterGossipRateLimitSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConf {
				admission: Arc::new(TokenBucketAdmission::new(1, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"rate-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"rate-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_LIMITED_STATUS).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipDuplicateFreeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(4), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(2)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Duplicates do not spend rate tokens. A two-token bucket with a slow
// refill admits rumor A, absorbs two byte-identical echoes of A for
// free, and still has the token to admit rumor B. If duplicates were
// charged, the echoes would drain the bucket and B would be refused
// with ResourceExhausted (relay echo traffic is normal, not abuse).
tb_scenario! {
	name: cluster_gossip_duplicates_spend_no_tokens,
	spec: ClusterGossipDuplicateFreeSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConf {
				admission: Arc::new(TokenBucketAdmission::new(2, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let first = signed_publish_gossip(
				&certs.key,
				b"dup-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, first.clone()).await?;
			send_gossip_frame(&trace, &certs, &gateway, first.clone()).await?;
			send_gossip_frame(&trace, &certs, &gateway, first).await?;

			let second = signed_publish_gossip(
				&certs.key,
				b"dup-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, second).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The gateway drives an injected journal through the trait alone.
// One origin publish records once and acks once on local delivery.
// Counts are final when the publish returns because record and ack precede the reply.
tb_scenario! {
	name: cluster_gossip_uses_injected_journal,
	spec: ClusterGossipJournalSeamSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let journal = Arc::new(CountingJournal::default());
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConf {
				journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"seam-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			trace.event_with(JOURNAL_RECORDS, &[], journal.records.load(Ordering::SeqCst))?;
			trace.event_with(JOURNAL_ACKS, &[], journal.acks.load(Ordering::SeqCst))?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipInvalidRelaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(4), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(4)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(3)),
			(GOSSIP_ROUTES_AFTER_SCORING, exactly!(1), equals!(0u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1))
		]
	}
}

// Invalid-relay scoring: a trusted peer that relays rumors refused at
// admission (here an over-TTL flood request) weakens its own advertised
// work routes, one trial per refusal, until the trail is abandoned and
// `peer_routes` no longer exposes it. The weakening stops with the trail
// (the fourth refusal scores nothing), and an honest relay from the same
// signer still delivers: flooding is untouched by work-route abandonment.
tb_scenario! {
	name: cluster_gossip_abandons_invalid_relay_routes,
	spec: ClusterGossipInvalidRelaySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = containment_cluster_conf(&certs);
			conf.gossip.ingress = Some(servlet_urn("ping"));
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;
			install_ping_peer(&trace, &certs, &gateway).await?;

			// One more relay than the abandonment budget: the last refusal
			// must find the trail already abandoned and weaken nothing.
			// Each relay carries a valid origin-signed rumor so the refusal
			// is the over-radius hop lifetime, not an unverifiable origin.
			for i in 0..=CONTAINMENT_ABANDON_LIMIT {
				let rumor_id = [b'r', i as u8];
				let rumor = mint_origin_rumor(
					&certs.key,
					&rumor_id,
					rumor_body(encode(&PingRequest { value: i })?),
				)
				.await?;
				let id = [b'b', b'a', b'd', i as u8];
				let frame = signed_relay_gossip(
					&certs.key,
					&id,
					rumor,
					u64::from(MAX_GOSSIP_TTL) + 1,
				)
				.await?;
				send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_RELAY_STATUS).await?;
			}

			trace.event_with(GOSSIP_ROUTES_AFTER_SCORING, &[], gateway.peer_routes().len() as u64)?;

			let honest = mint_origin_rumor(
				&certs.key,
				b"honest-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&certs.key, b"honest-relay", honest, 0).await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Grey-hole [`GossipJournal`]: every rumor is recorded as new and
/// retained nowhere, so the gateway acknowledges each push with `Ok` and
/// then re-wants the same digest on every reconciliation round.
#[derive(Default)]
struct AmnesiacJournal;

impl GossipJournal for AmnesiacJournal {
	fn record(
		&self,
		_signer: &[u8],
		_digest: GossipDigest,
		_rumor: &Frame,
		_now_ms: u64,
	) -> Result<Admission, ClusterError> {
		Ok(Admission::New)
	}

	// Retaining nothing, the grey hole never reports a digest as seen,
	// so every repair push reaches record and is re-acknowledged.
	fn seen(&self, _digest: &GossipDigest, _now_ms: u64) -> Result<bool, ClusterError> {
		Ok(false)
	}

	fn held_digests(&self, _now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError> {
		Ok(Vec::new())
	}

	fn fetch(&self, _wanted: &[GossipDigest], _now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		Ok(Vec::new())
	}

	fn pending_local(&self, _now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		Ok(Vec::new())
	}

	fn ack_local(&self, _digest: &GossipDigest) -> Result<(), ClusterError> {
		Ok(())
	}

	// The grey hole CLAIMS the default retention while retaining nothing:
	// a misbehaving journal lies, and the start-time seen-ttl clamp only
	// defends against honest misconfiguration.
	fn retention_ms(&self) -> u64 {
		DEFAULT_GOSSIP_RETENTION_MS
	}
}

tb_assert_spec! {
	pub ClusterGossipGreyHoleSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_DROP_SIGNAL, at_least!(3)),
			(GOSSIP_GREY_HOLE_CONTAINED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2))
		]
	}
}

// Grey-hole containment over the beat: B acknowledges every repair push
// with `Ok` and retains nothing, so each reconciliation round re-wants a
// digest A already saw acknowledged. A's beat reads the reappearance as a
// drop signal, weakens B's advertised work route once per round, and
// abandons it past the limit while the rumor still converges to honest C
// through the same beat. Flooding to B keeps running off the static peer
// list; only work routing drops the grey hole.
tb_scenario! {
	name: cluster_gossip_abandons_grey_hole_peer,
	spec: ClusterGossipGreyHoleSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;
			let hive_c = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			let mut conf_b = peering_cluster_conf(&certs);
			conf_b.gossip = GossipConf {
				journal: Arc::new(AmnesiacJournal) as Arc<dyn GossipJournal>,
				..Default::default()
			};
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, peers_a);
			conf_a.advertise_interval = Some(Duration::from_millis(100));
			conf_a.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;
			let gateway_a = start_cluster(&trace, conf_a).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;

			// Give the drop signals a trail to weaken: B advertises a ping
			// route dialed at the same address A reconciles with.
			let dial = gateway_b.addr().to_string();
			advertise_peer(&trace, &certs, &gateway_a, dial.as_bytes(), vec![servlet_urn("ping")]).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"grey-hole-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			// Honest convergence first: A holds its own publish and C is
			// repaired over the beat. B never converges by design.
			let converged =
				wait_for_gossip_converged(&[journal_a, journal_c], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			let contained = wait_for_no_peer_routes(&gateway_a, 100, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_GREY_HOLE_CONTAINED, &[], u64::from(contained))?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipTamperedRelaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// Tampered-relay scoring: a trusted peer that forwards an origin-signed
// rumor whose content it altered breaks the origin signature. The gateway
// refuses PermissionDenied and weakens the relay's advertised routes,
// because an honest relay verifies before forwarding.
tb_scenario! {
	name: cluster_gossip_weakens_tampered_relay,
	spec: ClusterGossipTamperedRelaySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, containment_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut rumor = mint_origin_rumor(
				&certs.key,
				b"tamper-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			rumor.message = encode(&rumor_body(encode(&PingRequest { value: 99 })?))?;

			let frame = signed_relay_gossip(&certs.key, b"tamper-relay", rumor, 0).await?;
			send_gossip_frame_as(&trace, &certs, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Fixture for colony-membership refusals: the gateway belongs to colony
/// "main", one trusted peer identity carries a different colony URN SAN,
/// and another carries no SAN at all. Both use random keys so the three
/// identities never share a subject key id (see [`gossip_plane_ctx`]).
struct ForeignColonyCtx {
	gateway: ClusterTestCerts,
	foreign_key: Secp256k1SigningKey,
	stranger_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn foreign_colony_ctx() -> ForeignColonyCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::{create_test_certificate, create_test_certificate_with_uri_sans};

	let gateway = cluster_certs();
	let foreign_urn = colony_ns().colony("other").expect("static colony name");
	let raw_foreign = k256::ecdsa::SigningKey::random(&mut OsRng);
	let foreign_cert = create_test_certificate_with_uri_sans(&raw_foreign, &[&foreign_urn.to_string()]);
	let raw_stranger = k256::ecdsa::SigningKey::random(&mut OsRng);
	let stranger_cert = create_test_certificate(&raw_stranger);
	let peer_trust = combined_trust(&[&gateway.cert, &foreign_cert, &stranger_cert]);

	ForeignColonyCtx {
		gateway,
		foreign_key: Secp256k1SigningKey::from(raw_foreign),
		stranger_key: Secp256k1SigningKey::from(raw_stranger),
		peer_trust,
	}
}

tb_assert_spec! {
	pub ClusterGossipForeignColonySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(2), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(GOSSIP_ROUTES_AFTER_SCORING, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// Colony-membership refusal is policy, not misbehavior. A trusted peer
// from a different colony federates work routes (the advertisement
// installs), yet its relay of a foreign-origin rumor is refused
// PermissionDenied, and so is a relay from a trusted peer with no colony
// SAN. Neither refusal weakens the advertised route: the abandonment
// limit is 1, so a single weaken would evict it, and the route survives.
tb_scenario! {
	name: cluster_gossip_refuses_foreign_colony_without_weakening,
	spec: ClusterGossipForeignColonySpec,
	environment Cluster {
		context: foreign_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.pheromone.abandonment_limit = 1;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			advertise_peer_signed(
				&trace,
				&ctx.gateway,
				&ctx.foreign_key,
				&cluster,
				PEER_GATEWAY_ADDR,
				vec![servlet_urn("ping")],
			)
			.await?;

			let foreign = mint_origin_rumor(
				&ctx.foreign_key,
				b"foreign-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.foreign_key, b"foreign-relay", foreign, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			let stranger = mint_origin_rumor(
				&ctx.stranger_key,
				b"stranger-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.stranger_key, b"stranger-relay", stranger, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			trace.event_with(GOSSIP_ROUTES_AFTER_SCORING, &[], cluster.peer_routes().len() as u64)?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Fixture for origin-budget keying: one origin identity and two relay
/// identities, all members of the gateway's colony. Every identity uses
/// a random key so no two share a subject key id (see
/// [`gossip_plane_ctx`]).
struct RelayFanoutCtx {
	gateway: ClusterTestCerts,
	origin_key: Secp256k1SigningKey,
	relay_a_key: Secp256k1SigningKey,
	relay_b_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn relay_fanout_ctx() -> RelayFanoutCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate_with_uri_sans;

	let gateway = cluster_certs();
	let member_urn = test_colony_urn().to_string();
	let raw_origin = k256::ecdsa::SigningKey::random(&mut OsRng);
	let origin_cert = create_test_certificate_with_uri_sans(&raw_origin, &[&member_urn]);
	let raw_relay_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let relay_a_cert = create_test_certificate_with_uri_sans(&raw_relay_a, &[&member_urn]);
	let raw_relay_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let relay_b_cert = create_test_certificate_with_uri_sans(&raw_relay_b, &[&member_urn]);
	let peer_trust = combined_trust(&[&gateway.cert, &origin_cert, &relay_a_cert, &relay_b_cert]);

	RelayFanoutCtx {
		gateway,
		origin_key: Secp256k1SigningKey::from(raw_origin),
		relay_a_key: Secp256k1SigningKey::from(raw_relay_a),
		relay_b_key: Secp256k1SigningKey::from(raw_relay_b),
		peer_trust,
	}
}

tb_assert_spec! {
	pub ClusterGossipOriginBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_LIMITED_STATUS, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Rate admission keys on the rumor's origin, not the relaying peer. A
// one-token bucket admits the origin's first rumor via relay A, then
// refuses the same origin's second rumor via relay B with
// ResourceExhausted: fanning one origin's flood through many relays
// grants no extra budget. The refusal is local policy, so relay B's
// routes are never weakened.
tb_scenario! {
	name: cluster_gossip_relays_share_origin_budget,
	spec: ClusterGossipOriginBudgetSpec,
	environment Cluster {
		context: relay_fanout_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.gossip = GossipConf {
				admission: Arc::new(TokenBucketAdmission::new(1, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				..Default::default()
			};
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let first = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.relay_a_key, b"budget-relay-1", first, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			let second = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.relay_b_key, b"budget-relay-2", second, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_LIMITED_STATUS).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipNonMemberSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// A gateway whose own certificate carries no colony URN SAN is not a
// colony member: it refuses origin publishes PermissionDenied even from
// a trusted hive-plane signer, because it cannot scope the flood.
tb_scenario! {
	name: cluster_gossip_non_member_gateway_refuses_publish,
	spec: ClusterGossipNonMemberSpec,
	environment Cluster {
		context: GatewayCerts::generate("CN=Non-Member Gateway"),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let frame = signed_publish_gossip(
				&certs.key,
				b"non-member-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &cluster, frame).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipReconcileSameColonySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_RECONCILE_MEMBER_WANT, exactly!(1), equals!(1u64)),
			(GOSSIP_RECONCILE_FOREIGN_WANT, exactly!(1), equals!(0u64)),
			(GOSSIP_RECONCILE_STRANGER_WANT, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2))
		]
	}
}

// Reconciliation is gated on colony EQUALITY, matching the flood scope:
// a want list names local rumor state and the follow-up repair push
// carries rumor bytes, so only a same-colony member receives the
// want-list for a digest this gateway lacks. A foreign-colony member
// and a trusted peer with no colony SAN are both refused with an empty
// want, each firing one REFUSED event.
tb_scenario! {
	name: cluster_gossip_reconcile_requires_same_colony,
	spec: ClusterGossipReconcileSameColonySpec,
	environment Cluster {
		context: foreign_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let held = vec![vec![0xABu8; 32]];

			let frame = signed_reconcile_gossip(&ctx.gateway.key, b"member-reconcile", held.clone()).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_MEMBER_WANT).await?;

			let frame = signed_reconcile_gossip(&ctx.foreign_key, b"foreign-reconcile", held.clone()).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_FOREIGN_WANT).await?;

			let frame = signed_reconcile_gossip(&ctx.stranger_key, b"stranger-reconcile", held).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_STRANGER_WANT).await?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Fixture for the ingress-None delivery policy: the scenario needs the
/// journal handle to observe retention and the retry set from outside.
struct IngressNoneCtx {
	certs: ClusterTestCerts,
	journal: Arc<MemoryGossipJournal>,
}

fn ingress_none_ctx() -> IngressNoneCtx {
	IngressNoneCtx { certs: cluster_certs(), journal: Arc::new(MemoryGossipJournal::default()) }
}

tb_assert_spec! {
	pub ClusterGossipIngressNoneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0)),
			(GOSSIP_HELD_NO_INGRESS, exactly!(1), equals!(1u64)),
			(GOSSIP_PENDING_NO_INGRESS, exactly!(1), equals!(1u64))
		]
	}
}

// With no configured ingress the gateway journals and refloods only:
// the publish is answered Ok and retained (held = 1), the record is
// acked immediately so it never enters the pending retry set, and no
// local delivery is reported (ACCEPTED = 0). The journal settles before
// the publish reply returns, so the probes need no polling.
tb_scenario! {
	name: cluster_gossip_ingress_none_acks_on_record,
	spec: ClusterGossipIngressNoneSpec,
	environment Cluster {
		context: ingress_none_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf(&ctx.certs);
			conf.gossip = GossipConf {
				journal: Arc::clone(&ctx.journal) as Arc<dyn GossipJournal>,
				ingress: None,
				..Default::default()
			};
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let frame = signed_publish_gossip(
				&ctx.certs.key,
				b"ingress-none-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &ctx.certs, &cluster, frame).await?;

			let now = current_timestamp_ms();
			let held_one = ctx.journal.held_digests(now).is_ok_and(|digests| digests.len() == 1);
			let none_pending = ctx.journal.pending_local(now).is_ok_and(|rumors| rumors.is_empty());
			trace.event_with(GOSSIP_HELD_NO_INGRESS, &[], u64::from(held_one))?;
			trace.event_with(GOSSIP_PENDING_NO_INGRESS, &[], u64::from(none_pending))?;

			cluster.stop();
			Ok(())
		}
	}
}
