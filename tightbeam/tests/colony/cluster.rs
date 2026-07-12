//! Integration tests for Cluster environment
//!
//! Tests the Cluster lifecycle with hive registration and work routing.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature"
))]

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::{Arc, OnceLock};

use sha3::Sha3_256;
use tightbeam::der::Sequence;
use tightbeam::{
	builder::TypeBuilder,
	cluster,
	colony::{
		cluster::{
			Cluster, ClusterConf, ClusterRequest, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse,
			HeartbeatConf,
		},
		common::current_timestamp_ms,
		hive::{
			Hive, HiveConf, HiveTlsConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdate,
			ServletAddressUpdateResponse, ServletInfo,
		},
		servlet::ServletConf,
	},
	compose,
	constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS,
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
	policy::{GatePolicy, TransitStatus},
	servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, GenericClient},
	utils::compose as frame_compose,
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::x509::create_test_cert_with_key;

// ============================================================================
// Shared Test Certificates
// ============================================================================

struct ClusterTestCerts {
	cert: Certificate,
	key: Secp256k1SigningKey,
	trust: Arc<dyn CertificateTrust>,
}

fn get_cluster_test_certs() -> &'static ClusterTestCerts {
	static CERTS: OnceLock<ClusterTestCerts> = OnceLock::new();
	CERTS.get_or_init(|| {
		let (cert, key) = create_test_cert_with_key("CN=Cluster Gateway", 365).expect("Failed to create cluster cert");
		let trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![cert.clone()])
				.expect("Failed to build trust")
				.build(),
		);
		ClusterTestCerts { cert, key, trust }
	})
}

// ============================================================================
// TLS Config Helpers (DRY)
// ============================================================================

fn cluster_tls_config_with_trust(
	certs: &ClusterTestCerts,
	hive_trust: Option<Arc<dyn CertificateTrust>>,
) -> ClusterTlsConfig {
	ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
		validators: vec![],
		client_validators: vec![],
		hive_trust,
	}
}

fn cluster_tls_config(certs: &ClusterTestCerts) -> ClusterTlsConfig {
	cluster_tls_config_with_trust(certs, Some(Arc::clone(&certs.trust)))
}

fn hive_tls_config_no_trust(certs: &ClusterTestCerts) -> HiveConf {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
		validators: vec![],
	});
	HiveConf { hive_tls: Some(hive_tls), ..Default::default() }
}

fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConf {
	HiveConf { trust_store: Some(Arc::clone(&certs.trust)), ..hive_tls_config_no_trust(certs) }
}

fn servlet_tls_config(
	certs: &ClusterTestCerts,
) -> Result<ServletConf<TokioListener, PingRequest, DefaultCryptoProvider>, TightBeamError> {
	Ok(ServletConf::<TokioListener, PingRequest, DefaultCryptoProvider>::builder()
		.with_certificate(
			CertificateSpec::Built(Box::new(certs.cert.clone())),
			Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
			vec![],
		)?
		.with_config(Arc::new(()))
		.build())
}

async fn start_cluster(conf: ClusterConf) -> Result<ClusterGateway, TightBeamError> {
	ClusterGateway::start(Arc::new(TraceCollector::new()), conf).await
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
	if status != TransitStatus::Accepted {
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

	let provider = Secp256k1KeyProvider::from(key.clone());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

async fn signed_control_frame(
	certs: &ClusterTestCerts,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	signed_control_frame_with(&certs.key, id, request).await
}

fn registration_request(issued_at_ms: u64, hive_addr: &[u8]) -> ClusterRequest {
	ClusterRequest::RegisterHive(RegisterHiveRequest {
		issued_at_ms,
		hive_addr: hive_addr.to_vec(),
		servlet_addresses: vec![],
		metadata: None,
	})
}

fn servlet_address_update(hive_id: &[u8], added: Vec<ServletInfo>) -> ClusterRequest {
	ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
		issued_at_ms: current_timestamp_ms(),
		hive_id: hive_id.to_vec(),
		added,
		removed: vec![],
	})
}

fn servlet_info(servlet_id: &[u8], address: &[u8]) -> ServletInfo {
	ServletInfo { servlet_id: servlet_id.to_vec(), address: address.to_vec() }
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
			V0: id: frame.metadata.id.clone(),
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
		gate: Accepted,
		assertions: [
			("work_sent", exactly!(1)),
			("routing_accepted", exactly!(1))
		]
	}
}

// ============================================================================
// Integration Test
// ============================================================================

tb_scenario! {
	name: cluster_work_routing,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterRoutingSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_cluster_test_certs();

			let cluster = start_cluster(ClusterConf::new(cluster_tls_config(certs))).await?;
			let cluster_addr = cluster.addr();

			let servlet_conf = servlet_tls_config(certs)?;
			let servlet =
				ClusterTestServlet::start(Arc::new(TraceCollector::new()), Some(servlet_conf)).await?;

			let mut hive = ClusterTestHive::new(Some(hive_tls_config(certs)))?;
			hive.register("ping", servlet, |t| ClusterTestServlet::start(t, None))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

			let _reg_response = hive.register_with_cluster(cluster_addr).await?;

			trace.event("work_sent")?;

			let work_request = ClusterRequest::Work(ClusterWorkRequest {
				servlet_type: b"ping".to_vec(),
				payload: encode(&PingRequest { value: 21 })?,
			});

			let frame = frame_compose(Version::V0)
				.with_id(b"test-work")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let mut client = connect_cluster(certs, cluster_addr).await?;
			let response_frame = emit_frame(&mut client, frame).await?;

			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			assert_eq!(work_response.status, TransitStatus::Accepted, "routed work must be accepted");

			let payload = work_response.payload.expect("accepted work must carry a payload");
			let ping_response: PingResponse = decode(&payload)?;
			assert_eq!(ping_response.doubled, 42);

			trace.event("routing_accepted")?;

			hive.stop();
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
	fn evaluate(&self, _message: &Frame) -> TransitStatus {
		TransitStatus::Forbidden
	}
}

tb_assert_spec! {
	pub ClusterPolicySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("work_sent", exactly!(1)),
			("policy_blocked", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_policy_gate_blocks,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterPolicySpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_cluster_test_certs();

			let cluster_conf = ClusterConf::builder(cluster_tls_config(certs))
				.with_gate_policy(Arc::new(RejectAllPolicy))
				.build();
			let cluster = start_cluster(cluster_conf).await?;
			let cluster_addr = cluster.addr();

			let work_request = ClusterRequest::Work(ClusterWorkRequest {
				servlet_type: b"ping".to_vec(),
				payload: encode(&PingRequest { value: 21 })?,
			});

			let frame = frame_compose(Version::V0)
				.with_id(b"policy-test")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let mut client = connect_cluster(certs, cluster_addr).await?;

			trace.event("work_sent")?;

			let response_frame = emit_frame(&mut client, frame).await?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			assert_eq!(
				work_response.status,
				TransitStatus::Forbidden,
				"gate policy must reject the request before decoding"
			);
			assert!(work_response.payload.is_none(), "rejected request must not carry a payload");

			trace.event("policy_blocked")?;

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
		gate: Accepted,
		assertions: [
			("registration_sent", exactly!(1)),
			("registration_unauthorized", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_unsigned_registration,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterUnsignedRegistrationSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_cluster_test_certs();

			// Cluster requires signed hive-origin frames (hive_trust set)
			let cluster = start_cluster(ClusterConf::new(cluster_tls_config(certs))).await?;
			let cluster_addr = cluster.addr();

			// Hive validates the cluster's TLS certificate but has no
			// signing identity of its own: control frames go out unsigned
			let hive_conf = HiveConf {
				trust_store: Some(Arc::clone(&certs.trust)),
				..Default::default()
			};

			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

			trace.event("registration_sent")?;

			let response = hive.register_with_cluster(cluster_addr).await?;
			assert_register_status(&response, TransitStatus::Unauthorized, 0, &cluster);

			trace.event("registration_unauthorized")?;

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
		gate: Accepted,
		assertions: [
			("registration_sent", exactly!(1)),
			("registration_forbidden", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_without_hive_trust_rejects_control_frames,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterNoTrustStoreSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_cluster_test_certs();

			// Gateway without hive_trust cannot authenticate control
			// frames and must fail closed: even a validly signed
			// registration is rejected.
			let tls = ClusterTlsConfig {
				certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
				key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
				validators: vec![],
				client_validators: vec![],
				hive_trust: None,
			};
			let cluster = start_cluster(ClusterConf::new(tls)).await?;
			let cluster_addr = cluster.addr();

			let mut client = connect_cluster(certs, cluster_addr).await?;
			let signed = signed_control_frame(
				certs,
				b"no-trust-reg",
				registration_request(current_timestamp_ms(), b"127.0.0.1:65000"),
			)
			.await?;

			trace.event("registration_sent")?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::Forbidden, 0, &cluster);

			trace.event("registration_forbidden")?;

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
		gate: Accepted,
		assertions: [
			("fresh_registration_accepted", exactly!(1)),
			("replayed_registration_rejected", exactly!(1)),
			("stale_registration_rejected", exactly!(1)),
			("fresh_update_accepted", exactly!(1)),
			("replayed_update_rejected", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_replayed_and_stale_control_frames,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterReplaySpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_cluster_test_certs();

			let cluster = start_cluster(ClusterConf::new(cluster_tls_config(certs))).await?;
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(certs, cluster_addr).await?;

			// Fresh signed registration is accepted
			let fresh = signed_control_frame(
				certs,
				b"replay-reg",
				registration_request(current_timestamp_ms(), b"127.0.0.1:65000"),
			)
			.await?;
			let replayed = fresh.clone();

			let response_frame = emit_frame(&mut client, fresh).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_register_status(&response, TransitStatus::Accepted, 1, &cluster);

			trace.event("fresh_registration_accepted")?;

			// Byte-identical resend carries an already-seen signature
			let response_frame = emit_frame(&mut client, replayed).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Forbidden, "replayed registration must be rejected");

			trace.event("replayed_registration_rejected")?;

			// Valid signature but issued outside the freshness window
			let stale_ts = current_timestamp_ms() - 2 * DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
			let stale = signed_control_frame(
				certs,
				b"stale-reg",
				registration_request(stale_ts, b"127.0.0.1:65000"),
			)
			.await?;

			let response_frame = emit_frame(&mut client, stale).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Forbidden, "stale registration must be rejected");

			trace.event("stale_registration_rejected")?;

			// Same enforcement on servlet address updates
			let update = servlet_address_update(
				b"127.0.0.1:65000",
				vec![servlet_info(b"ping", b"127.0.0.1:65001")],
			);
			let fresh_update = signed_control_frame(certs, b"replay-update", update).await?;
			let replayed_update = fresh_update.clone();

			let response_frame = emit_frame(&mut client, fresh_update).await?;
			let response: ServletAddressUpdateResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Accepted, "fresh signed update must be accepted");

			trace.event("fresh_update_accepted")?;

			let response_frame = emit_frame(&mut client, replayed_update).await?;
			let response: ServletAddressUpdateResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Forbidden, "replayed update must be rejected");

			trace.event("replayed_update_rejected")?;

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
		gate: Accepted,
		assertions: [
			("hive_registered", exactly!(1)),
			("rejected_heartbeat_decoded", exactly!(1)),
			("hive_evicted", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_evicts_hive_on_rejected_heartbeats,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterHeartbeatRejectionSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_cluster_test_certs();
			let rejected_decoded = Arc::new(AtomicBool::new(false));
			let rejected_flag = Arc::clone(&rejected_decoded);
			let heartbeat = HeartbeatConf::builder()
				.with_interval(Duration::from_millis(100))
				.with_max_failures(1)
				.with_callback(Arc::new(move |event| {
					// utilization is only Some when the heartbeat response
					// decoded, proving the failure came from the rejected
					// status rather than a transport error
					let decoded_reject = !event.success && event.utilization.is_some();
					rejected_flag.fetch_or(decoded_reject, Ordering::SeqCst);
				}))
				.build();

			let cluster_conf = ClusterConf::builder(cluster_tls_config(certs))
				.with_heartbeat_config(heartbeat)
				.build();
			let cluster = start_cluster(cluster_conf).await?;
			let cluster_addr = cluster.addr();

			// Hive serves the shared cert (cluster trusts it for TLS) but
			// configures no trust store for inbound commands
			let mut hive = ClusterTestHive::new(Some(hive_tls_config_no_trust(certs)))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

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
			assert_register_status(&response, TransitStatus::Accepted, 1, &cluster);

			trace.event("hive_registered")?;

			// Heartbeats run every 100ms with max_failures = 1: the first
			// Forbidden heartbeat must evict the hive
			assert!(
				wait_for_empty_registry(&cluster, 50, Duration::from_millis(100)).await,
				"hive with rejected heartbeats must be evicted"
			);

			assert!(
				rejected_decoded.load(Ordering::SeqCst),
				"hive must answer with a decodable rejected heartbeat"
			);

			trace.event("rejected_heartbeat_decoded")?;
			trace.event("hive_evicted")?;

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
	gateway: &'static ClusterTestCerts,
	hive_a: (Certificate, Secp256k1SigningKey),
	hive_b: (Certificate, Secp256k1SigningKey),
	hive_trust: Arc<dyn CertificateTrust>,
}

fn dual_hive_certs() -> DualHiveCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let gateway = get_cluster_test_certs();
	let raw_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_a = create_test_certificate(&raw_a);
	let cert_b = create_test_certificate(&raw_b);
	let key_a = Secp256k1SigningKey::from(raw_a);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert_a.clone())
			.expect("hive A trust")
			.with_certificate(cert_b.clone())
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
		gate: Accepted,
		assertions: [
			("hives_registered", exactly!(1)),
			("cross_hive_update_forbidden", exactly!(1)),
			("owner_update_accepted", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_cross_hive_servlet_address_update,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterCrossHiveUpdateSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = dual_hive_certs();
			let cluster = start_cluster(ClusterConf::new(cluster_tls_config_with_trust(
				certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await?;
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(certs.gateway, cluster_addr).await?;

			let hive_a_addr = b"127.0.0.1:65010".as_slice();
			let hive_b_addr = b"127.0.0.1:65011".as_slice();

			let response_a = register_signed_hive(&mut client, &certs.hive_a.1, b"reg-a", hive_a_addr).await?;
			let response_b = register_signed_hive(&mut client, &certs.hive_b.1, b"reg-b", hive_b_addr).await?;
			assert_eq!(response_a.status, TransitStatus::Accepted);
			assert_eq!(response_b.status, TransitStatus::Accepted);
			assert_eq!(cluster.hive_count(), 2);

			trace.event("hives_registered")?;

			let update_cases = [
				(
					&certs.hive_b.1,
					b"cross-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info(b"poison", b"127.0.0.1:65099")]),
					TransitStatus::Forbidden,
					"cross_hive_update_forbidden",
				),
				(
					&certs.hive_a.1,
					b"owner-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info(b"ping", b"127.0.0.1:65012")]),
					TransitStatus::Accepted,
					"owner_update_accepted",
				),
			];

			for (key, id, request, expected, event) in update_cases {
				let response = emit_servlet_update(&mut client, key, id, request).await?;
				assert_eq!(response.status, expected);
				trace.event(event)?;
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
		gate: Accepted,
		assertions: [
			("owner_registered", exactly!(1)),
			("hijack_forbidden", exactly!(1)),
			("owner_bind_intact", exactly!(1))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_cross_hive_registration_hijack,
	config: ScenarioConf::<()>::builder()
		.with_spec(ClusterRegistrationHijackSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = dual_hive_certs();
			let cluster = start_cluster(ClusterConf::new(cluster_tls_config_with_trust(
				certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await?;
			let mut client = connect_cluster(certs.gateway, cluster.addr()).await?;

			let hive_a_addr = b"127.0.0.1:65020".as_slice();

			let owner = register_signed_hive(&mut client, &certs.hive_a.1, b"owner-reg", hive_a_addr).await?;
			assert_eq!(owner.status, TransitStatus::Accepted);
			assert_eq!(cluster.hive_count(), 1);

			trace.event("owner_registered")?;

			let hijack = register_signed_hive(&mut client, &certs.hive_b.1, b"hijack-reg", hive_a_addr).await?;
			assert_eq!(hijack.status, TransitStatus::Forbidden);
			assert_eq!(cluster.hive_count(), 1);

			trace.event("hijack_forbidden")?;

			let owned = emit_servlet_update(
				&mut client,
				&certs.hive_a.1,
				b"owner-still-bound",
				servlet_address_update(hive_a_addr, vec![servlet_info(b"ping", b"127.0.0.1:65021")]),
			)
			.await?;
			assert_eq!(owned.status, TransitStatus::Accepted);

			trace.event("owner_bind_intact")?;

			cluster.stop();
			Ok(())
		}
	}
}
