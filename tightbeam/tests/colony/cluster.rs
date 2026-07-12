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
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
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

fn cluster_tls_config(certs: &ClusterTestCerts) -> ClusterTlsConfig {
	ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.trust)),
	}
}

fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConf {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
		validators: vec![],
	});
	HiveConf {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.trust)),
		..Default::default()
	}
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

			// Start cluster
			let cluster_conf = ClusterConf::new(cluster_tls_config(certs));
			let cluster_trace = Arc::new(TraceCollector::new());
			let cluster = ClusterGateway::start(Arc::clone(&cluster_trace), cluster_conf).await?;
			let cluster_addr = cluster.addr();

			// Start servlet with TLS
			let servlet_conf = servlet_tls_config(certs)?;
			let servlet_trace = Arc::new(TraceCollector::new());
			let servlet = ClusterTestServlet::start(Arc::clone(&servlet_trace), Some(servlet_conf)).await?;

			// Create and establish hive
			let mut hive = ClusterTestHive::new(Some(hive_tls_config(certs)))?;
			hive.register("ping", servlet, |t| ClusterTestServlet::start(t, None))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

			// Register hive with cluster
			let _reg_response = hive.register_with_cluster(cluster_addr).await?;

			// Send work request
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

			// Connect to cluster with TLS
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.trust))
				.build();
			let mut client = builder.connect(cluster_addr).await?;

			let response_frame = client.emit(frame, None).await?
				.ok_or(TightBeamError::MissingResponse)?;

			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			if work_response.status == TransitStatus::Accepted {
				trace.event("routing_accepted")?;
				if let Some(payload) = work_response.payload {
					let ping_response: PingResponse = decode(&payload)?;
					assert_eq!(ping_response.doubled, 42);
				}
			}

			// Cleanup
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
			let cluster = ClusterGateway::start(Arc::new(TraceCollector::new()), cluster_conf).await?;
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

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.trust))
				.build();
			let mut client = builder.connect(cluster_addr).await?;

			trace.event("work_sent")?;

			let response_frame = client.emit(frame, None).await?
				.ok_or(TightBeamError::MissingResponse)?;

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
			let cluster_conf = ClusterConf::new(cluster_tls_config(certs));
			let cluster = ClusterGateway::start(Arc::new(TraceCollector::new()), cluster_conf).await?;
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
			assert_eq!(
				response.status,
				TransitStatus::Unauthorized,
				"unsigned registration must be rejected when hive_trust is configured"
			);
			assert!(response.hive_id.is_none(), "rejected registration must not assign a hive id");
			assert_eq!(cluster.hive_count(), 0, "rejected hive must not enter the registry");

			trace.event("registration_unauthorized")?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

// ============================================================================
// Replayed / Stale Control Frame Rejection
// ============================================================================

async fn signed_control_frame(
	certs: &ClusterTestCerts,
	id: &[u8],
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V0)
		.with_id(id)
		.with_order(0)
		.with_message(request)
		.build()?;
	let provider = Secp256k1KeyProvider::from(certs.key.clone());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

fn registration_request(issued_at_ms: u64, hive_addr: &[u8]) -> ClusterRequest {
	ClusterRequest::RegisterHive(RegisterHiveRequest {
		issued_at_ms,
		hive_addr: hive_addr.to_vec(),
		servlet_addresses: vec![],
		metadata: None,
	})
}

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

			let cluster_conf = ClusterConf::new(cluster_tls_config(certs));
			let cluster = ClusterGateway::start(Arc::new(TraceCollector::new()), cluster_conf).await?;
			let cluster_addr = cluster.addr();

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.trust))
				.build();
			let mut client = builder.connect(cluster_addr).await?;

			// Fresh signed registration is accepted
			let fresh = signed_control_frame(
				certs,
				b"replay-reg",
				registration_request(current_timestamp_ms(), b"127.0.0.1:65000"),
			).await?;
			let replayed = fresh.clone();

			let response_frame = client.emit(fresh, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Accepted, "fresh signed registration must be accepted");
			assert_eq!(cluster.hive_count(), 1, "fresh registration must enter the registry");

			trace.event("fresh_registration_accepted")?;

			// Byte-identical resend carries an already-seen signature
			let response_frame = client.emit(replayed, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Forbidden, "replayed registration must be rejected");

			trace.event("replayed_registration_rejected")?;

			// Valid signature but issued outside the freshness window
			let stale_ts = current_timestamp_ms() - 2 * DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
			let stale = signed_control_frame(
				certs,
				b"stale-reg",
				registration_request(stale_ts, b"127.0.0.1:65000"),
			).await?;

			let response_frame = client.emit(stale, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Forbidden, "stale registration must be rejected");

			trace.event("stale_registration_rejected")?;

			// Same enforcement on servlet address updates
			let update = ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
				issued_at_ms: current_timestamp_ms(),
				hive_id: b"127.0.0.1:65000".to_vec(),
				added: vec![ServletInfo { servlet_id: b"ping".to_vec(), address: b"127.0.0.1:65001".to_vec() }],
				removed: vec![],
			});
			let fresh_update = signed_control_frame(certs, b"replay-update", update).await?;
			let replayed_update = fresh_update.clone();

			let response_frame = client.emit(fresh_update, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: ServletAddressUpdateResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Accepted, "fresh signed update must be accepted");

			trace.event("fresh_update_accepted")?;

			let response_frame = client.emit(replayed_update, None).await?.ok_or(TightBeamError::MissingResponse)?;
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

			// The hive has no trust store, so its security gate fails
			// closed and answers cluster heartbeats with a Forbidden
			// heartbeat-shaped response. A decoded rejection must count
			// as a failure, not reset the failure count.
			let rejected_decoded = Arc::new(AtomicBool::new(false));
			let rejected_flag = Arc::clone(&rejected_decoded);
			let heartbeat = HeartbeatConf::builder()
				.with_interval(Duration::from_millis(100))
				.with_max_failures(1)
				.with_callback(Arc::new(move |event| {
					// utilization is only Some when the heartbeat response
					// decoded, proving the failure came from the rejected
					// status rather than a transport error
					if !event.success && event.utilization.is_some() {
						rejected_flag.store(true, Ordering::SeqCst);
					}
				}))
				.build();

			let cluster_conf = ClusterConf::builder(cluster_tls_config(certs))
				.with_heartbeat_config(heartbeat)
				.build();
			let cluster = ClusterGateway::start(Arc::new(TraceCollector::new()), cluster_conf).await?;
			let cluster_addr = cluster.addr();

			// Hive serves the shared cert (cluster trusts it for TLS) but
			// configures no trust store for inbound commands
			let hive_tls = Arc::new(HiveTlsConfig {
				certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
				key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
				validators: vec![],
			});
			let hive_conf = HiveConf {
				hive_tls: Some(hive_tls),
				..Default::default()
			};

			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

			// Register the hive out-of-band with a validly signed frame
			let hive_addr_bytes = hive.addr().to_string().into_bytes();
			let registration = signed_control_frame(
				certs,
				b"hb-reject-reg",
				registration_request(current_timestamp_ms(), &hive_addr_bytes),
			).await?;

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.trust))
				.build();
			let mut client = builder.connect(cluster_addr).await?;

			let response_frame = client.emit(registration, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			assert_eq!(response.status, TransitStatus::Accepted, "signed registration must be accepted");
			assert_eq!(cluster.hive_count(), 1, "registered hive must enter the registry");

			trace.event("hive_registered")?;

			// Heartbeats run every 100ms with max_failures = 1: the first
			// Forbidden heartbeat must evict the hive
			for _ in 0..50 {
				if cluster.hive_count() == 0 {
					break;
				}

				tokio::time::sleep(Duration::from_millis(100)).await;
			}

			assert!(
				rejected_decoded.load(Ordering::SeqCst),
				"hive must answer with a decodable rejected heartbeat"
			);

			trace.event("rejected_heartbeat_decoded")?;

			assert_eq!(cluster.hive_count(), 0, "hive with rejected heartbeats must be evicted");

			trace.event("hive_evicted")?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}
