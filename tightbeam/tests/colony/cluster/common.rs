//! Shared fixtures for colony cluster integration tests.

use tightbeam::{cluster, compose, hive, servlet};

// Re-exports consumed by sibling scenario modules via `use super::common::*`.
pub(super) use super::events::*;
pub(super) use crate::common::x509::{combined_trust, GatewayCerts};
pub(super) use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
pub(super) use core::time::Duration;
pub(super) use sha3::Sha3_256;
pub(super) use std::collections::HashSet;
pub(super) use std::sync::{Arc, Mutex};
pub(super) use tightbeam::der::Sequence;
pub(super) use tightbeam::{
	at_least, at_most,
	builder::TypeBuilder,
	colony::{
		cluster::{
			Admission, Cluster, ClusterConfig, ClusterError, ClusterRequest, ClusterTlsConfig, ClusterWorkRequest,
			ClusterWorkResponse, GossipAdmission, GossipConfig, GossipDigest, GossipJournal, HeartbeatConfig,
			MemoryGossipJournal, TokenBucketAdmission,
		},
		common::{
			current_timestamp_ms, servlet_instance, type_canonical_bytes, ColonyNamespace, GossipReconciliation,
			GossipResponse, GossipRumor, GossipWant, InstanceMetrics, LoadBalancer, PeerAdvertisement,
			PeerAdvertisementResponse, RoundRobin, StochasticForager,
		},
		hive::{
			Hive, HiveConfig, HiveTlsConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdate,
			ServletAddressUpdateResponse, ServletBox, ServletInfo,
		},
		servlet::ServletConfig,
	},
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
	decode, encode, exactly,
	instrumentation::events,
	policy::{GatePolicy, SessionContext, TransitStatus},
	tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ClusterEnv, HiveEnv, ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
		ConnectionPool, GenericClient, PoolConfig,
	},
	utils::compose as frame_compose,
	utils::urn::Urn,
	Beamable, Frame, TightBeamError, Version,
};

/// Address the simulated peer gateway advertises itself at.
pub(crate) const PEER_GATEWAY_ADDR: &[u8] = b"127.0.0.1:9000";

/// Failed forwards a peer trail tolerates before abandonment in the
/// infection-containment scenarios. Kept small so the gate stays fast;
/// the containment specs assert exactly this many `CLUSTER_WORK_FAILED`
/// before selection drops the peer.
pub(super) const CONTAINMENT_ABANDON_LIMIT: u32 = 3;

// ============================================================================
// Shared Test Certificates
// ============================================================================

pub(super) type ClusterTestCerts = GatewayCerts;

/// Colony every member gateway in these tests belongs to. Membership
/// travels as a URI SAN on the gateway certificate, never the subject.
pub(super) fn test_colony_urn() -> Urn<'static> {
	colony_ns().colony("main").expect("static colony name")
}

pub(super) fn cluster_certs() -> ClusterTestCerts {
	GatewayCerts::generate_colony(&test_colony_urn())
}

// ============================================================================
// TLS Config Helpers (DRY)
// ============================================================================

pub(super) fn cluster_tls_config_with_trust(
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

pub(super) fn cluster_tls_config(certs: &ClusterTestCerts) -> ClusterTlsConfig {
	cluster_tls_config_with_trust(certs, Some(Arc::clone(&certs.trust)))
}

pub(super) fn hive_tls_config_no_trust(certs: &ClusterTestCerts) -> HiveConfig {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
		validators: vec![],
	});
	HiveConfig {
		hive_tls: Some(hive_tls),
		mux_offer: Some(TransportOffer::mux(8)),
		..Default::default()
	}
}

pub(super) fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConfig {
	HiveConfig { trust_store: Some(Arc::clone(&certs.trust)), ..hive_tls_config_no_trust(certs) }
}

pub(super) fn servlet_tls_config(
	certs: &ClusterTestCerts,
) -> Result<ServletConfig<TokioListener, PingRequest, DefaultCryptoProvider>, TightBeamError> {
	Ok(ServletConfig::<TokioListener, PingRequest, DefaultCryptoProvider>::builder()
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
pub(super) async fn start_cluster(trace: &TraceCollector, conf: ClusterConfig) -> Result<ClusterGateway, TightBeamError> {
	ClusterGateway::start(Arc::new(trace.share()), conf).await
}

pub(super) async fn connect_cluster(
	certs: &ClusterTestCerts,
	addr: <TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_trust_store(Arc::clone(&certs.trust))
		.build()
		.connect(addr)
		.await?)
}

pub(super) async fn emit_frame(
	client: &mut GenericClient<TokioListener>,
	frame: Frame,
) -> Result<Frame, TightBeamError> {
	client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)
}

/// Record a registration outcome on the trace: the wire status as
/// `REGISTER_STATUS`, the registry size as `REGISTRY_HIVES`, and whether
/// a hive id was assigned as `REGISTER_ASSIGNED_ID`. The specs pin the
/// expected values, so scenarios need no inline checks.
pub(super) fn record_register_response(
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
pub(super) fn record_work_status(trace: &TraceCollector, response: &ClusterWorkResponse) -> Result<(), TightBeamError> {
	trace.event_with(WORK_STATUS, &[], response.status)?;
	trace.event_with(WORK_PAYLOAD, &[], u64::from(response.payload.is_some()))?;
	Ok(())
}

pub(super) async fn signed_control_frame_with_order(
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

pub(super) async fn signed_control_frame_with(
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	signed_control_frame_with_order(key, id, request, current_timestamp_ms()).await
}

pub(super) async fn signed_control_frame(
	certs: &ClusterTestCerts,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	signed_control_frame_with(&certs.key, id, request).await
}

pub(super) fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

pub(super) fn hive_urn(hive_addr: &[u8]) -> Urn<'static> {
	colony_ns()
		.hive(String::from_utf8_lossy(hive_addr).as_ref())
		.expect("test locators satisfy the mint grammar")
}

pub(super) fn servlet_urn(name: &str) -> Urn<'static> {
	colony_ns().servlet(name).expect("test names satisfy the mint grammar")
}

pub(super) fn registration_request(hive_addr: &[u8]) -> ClusterRequest {
	ClusterRequest::RegisterHive(RegisterHiveRequest {
		hive_addr: hive_addr.to_vec(),
		servlet_addresses: vec![],
		metadata: None,
	})
}

pub(super) fn servlet_address_update(
	hive_addr: &[u8],
	added: Vec<ServletInfo>,
	removed: Vec<Urn<'static>>,
) -> ClusterRequest {
	ClusterRequest::ServletAddressUpdate(ServletAddressUpdate { hive_id: hive_urn(hive_addr), added, removed })
}

pub(super) fn servlet_info(servlet_name: &str, address: &[u8]) -> ServletInfo {
	ServletInfo {
		servlet_id: servlet_instance(&servlet_urn(servlet_name), String::from_utf8_lossy(address).as_ref()),
		address: address.to_vec(),
	}
}

/// ServletInfo whose instance locator disagrees with the route address.
pub(super) fn servlet_info_mismatched(servlet_name: &str, urn_addr: &[u8], route_addr: &[u8]) -> ServletInfo {
	ServletInfo {
		servlet_id: servlet_instance(&servlet_urn(servlet_name), String::from_utf8_lossy(urn_addr).as_ref()),
		address: route_addr.to_vec(),
	}
}

/// Poll until the gateway has learned peer types or attempts exhaust.
/// Branching lives here, not in scenarios.
pub(super) async fn wait_for_peer_types(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> Vec<Vec<u8>> {
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
pub(super) async fn wait_for_no_peer_routes(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> bool {
	for _ in 0..attempts {
		if cluster.peer_routes().is_empty() {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	cluster.peer_routes().is_empty()
}

/// Poll until the registry is empty or attempts exhaust. Branching lives here, not in scenarios.
pub(super) async fn wait_for_empty_registry(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> bool {
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
	pub ClusterTestServlet<PingRequest, EnvConfig = ()>,
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
	pub ClusterTestHive,
	protocol: TokioListener
}

// ============================================================================
// Test Cluster
// ============================================================================

cluster! {
	pub ClusterGateway,
	protocol: TokioListener
}

/// Ping-servlet hive with an optional mux offer for both the hive control
/// server and the hive -> cluster pool, on the scenario trace.
pub(super) async fn start_ping_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
	mux_offer: Option<TransportOffer>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = ClusterTestServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;

	let mut hive = ClusterTestHive::new(Some(HiveConfig { mux_offer, ..hive_tls_config(&certs) }))?;
	hive.register(servlet_urn("ping"), servlet, |t| ClusterTestServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Cluster conf with an optional mux offer for both the gateway server
/// and the cluster -> hive pool.
pub(super) fn routing_cluster_conf(certs: &ClusterTestCerts, mux_offer: Option<TransportOffer>) -> ClusterConfig {
	let mut conf = ClusterConfig::new(cluster_tls_config(certs));
	conf.pool_config.mux_offer = mux_offer;
	conf
}

/// Emit one ping work request through the gateway and record the echoed
/// payload as a valued event. The spec asserts the gateway routed it
/// (`events::CLUSTER_WORK_ROUTED`) and the echo value (`WORK_ECHOED`);
/// a refusal or missing payload leaves `WORK_ECHOED` absent.
pub(super) async fn record_ping_echo(
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

pub(super) async fn register_signed_hive(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: &[u8],
	addr: &[u8],
) -> Result<RegisterHiveResponse, TightBeamError> {
	let frame = signed_control_frame_with(key, id, registration_request(addr)).await?;
	decode(&emit_frame(client, frame).await?.message)
}

pub(super) async fn emit_servlet_update(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: &[u8],
	request: ClusterRequest,
) -> Result<ServletAddressUpdateResponse, TightBeamError> {
	let frame = signed_control_frame_with(key, id, request).await?;
	decode(&emit_frame(client, frame).await?.message)
}

pub(super) async fn emit_ping_work(
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
pub(super) async fn emit_forwarded_ping_work(
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
pub(super) fn foreign_realm_instance(addr: &str) -> Urn<'static> {
	let namespace = ColonyNamespace::new("tightbeam", "elsewhere").expect("static namespace parts are valid");
	servlet_instance(&namespace.servlet("ping").expect("test names satisfy the mint grammar"), addr)
}

/// Gateway conf that accepts peer advertisements: `peer_trust` anchors the
/// advertising gateway's certificate. No `peers` set, so this gateway
/// only receives.
pub(super) fn peering_cluster_conf(certs: &ClusterTestCerts) -> ClusterConfig {
	peering_cluster_conf_with_trust(certs, Arc::clone(&certs.trust))
}

/// Like [`peering_cluster_conf`] but with an explicit peer trust store
/// (used when more than one peer identity must verify).
pub(super) fn peering_cluster_conf_with_trust(
	certs: &ClusterTestCerts,
	peer_trust: Arc<dyn CertificateTrust>,
) -> ClusterConfig {
	let tls = ClusterTlsConfig { peer_trust: Some(peer_trust), ..cluster_tls_config(certs) };
	ClusterConfig::new(tls)
}

/// Importer that trusts peers only on the peer plane (hive_trust empty).
pub(super) fn peering_peer_trust_only(certs: &ClusterTestCerts) -> ClusterConfig {
	let tls = ClusterTlsConfig {
		hive_trust: None,
		peer_trust: Some(Arc::clone(&certs.trust)),
		..cluster_tls_config(certs)
	};
	ClusterConfig::new(tls)
}

pub(super) fn peering_with_dial_allowlist(certs: &ClusterTestCerts, allowlist: Vec<String>) -> ClusterConfig {
	let mut conf = peering_cluster_conf(certs);
	conf.peer.peer_dial_allowlist = Some(allowlist);
	conf
}

/// Importer conf whose peer trails abandon after a few failed forwards.
/// The limit is small so containment scenarios stay fast; the specs pin
/// [`CONTAINMENT_ABANDON_LIMIT`] failures before routing stops.
pub(super) fn containment_cluster_conf(certs: &ClusterTestCerts) -> ClusterConfig {
	let mut conf = peering_cluster_conf(certs);
	conf.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;
	conf
}

/// Gateway conf that advertises to `peer` on a fast beat. The slate is
/// never configured: each beat snapshots the hive registry.
pub(super) fn advertising_cluster_conf(certs: &ClusterTestCerts, peer: String) -> ClusterConfig {
	let mut conf = ClusterConfig::new(cluster_tls_config(certs));
	conf.peer.peers = vec![peer];
	conf.peer.advertise_interval = Some(Duration::from_millis(100));
	conf
}

/// Send one signed advertisement of `types` from a peer at `gateway_addr`,
/// signed by `signer`. The decoded status lands on the trace for spec
/// verification.
pub(super) async fn advertise_peer_signed(
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
pub(super) async fn send_advertisement_frame(
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
pub(super) async fn advertise_peer(
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
pub(super) async fn install_ping_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	advertise_peer(trace, certs, cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await
}
