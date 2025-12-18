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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sha3::Sha3_256;
use tightbeam::{
	cluster,
	colony::{
		cluster::{ClusterConf, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse, HeartbeatConf},
		hive::HiveConf,
		servlet::Servlet,
	},
	compose,
	crypto::{
		key::Secp256k1KeyProvider,
		policy::Secp256k1Policy,
		sign::ecdsa::Secp256k1SigningKey,
		x509::{
			store::{CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	decode,
	der::Sequence,
	encode, exactly, hive,
	policy::TransitStatus,
	servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	transport::{tcp::r#async::TokioListener, ClientBuilder},
	Beamable,
};

use crate::common::x509::create_test_cert_with_key;

// ============================================================================
// Shared Test Certificates
// ============================================================================

struct ClusterTestCerts {
	cert: Certificate,
	key: Secp256k1SigningKey,
	trust: Arc<dyn tightbeam::crypto::x509::store::CertificateTrust>,
}

fn get_cluster_test_certs() -> &'static ClusterTestCerts {
	static CERTS: OnceLock<ClusterTestCerts> = OnceLock::new();
	CERTS.get_or_init(|| {
		let (cert, key) = create_test_cert_with_key("CN=Cluster Gateway", 365).expect("Failed to create cluster cert");
		let trust: Arc<dyn tightbeam::crypto::x509::store::CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![cert.clone()])
				.expect("Failed to build trust")
				.build(),
		);
		ClusterTestCerts { cert, key, trust }
	})
}

// ============================================================================
// Cluster Configuration
// ============================================================================

/// Heartbeat statistics collected via callback
#[derive(Default)]
pub struct HeartbeatStats {
	pub attempts: AtomicU32,
	pub successes: AtomicU32,
}

/// Configuration for cluster tests (test instrumentation only)
#[derive(Clone)]
pub struct ClusterTestConf {
	pub heartbeat_stats: Arc<HeartbeatStats>,
	pub heartbeat_interval: Duration,
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
	handle: |frame, _ctx| async move {
		let req: PingRequest = decode(&frame.message)?;
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
	protocol: TokioListener,
	servlets: {
		ping: ClusterTestServlet<PingRequest>
	}
}

// ============================================================================
// Test Cluster
// ============================================================================

cluster! {
	ClusterGateway,
	protocol: TokioListener,
	config: ClusterConf::default()
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
			("routing_status", exactly!(1), equals!(TransitStatus::Accepted))
		]
	}
}

// ============================================================================
// Integration Test using environment Cluster
// ============================================================================

tb_scenario! {
	name: cluster_work_routing,
	config: ScenarioConf::<ClusterTestConf>::builder()
		.with_spec(ClusterRoutingSpec::latest())
		.with_env_config(ClusterTestConf {
			heartbeat_stats: Arc::new(HeartbeatStats::default()),
			heartbeat_interval: Duration::from_millis(50),
		})
		.build(),
	environment Cluster {
		cluster: ClusterGateway,
		start: |trace, config| async move {
			let certs = get_cluster_test_certs();

			let tls = ClusterTlsConfig {
				certificate: CertificateSpec::Built(Box::new(certs.cert.clone())),
				key: Arc::new(Secp256k1KeyProvider::from(certs.key.clone())),
				validators: vec![],
				client_validators: vec![],  // No mutual auth - TLS only
				hive_trust: None,  // Servlets use plain TCP in this test
			};

			let heartbeat_conf = HeartbeatConf::builder()
				.with_interval(config.heartbeat_interval)
				.with_callback(Arc::new({
					let stats = Arc::clone(&config.heartbeat_stats);
					move |event| {
						stats.attempts.fetch_add(1, Ordering::SeqCst);
						if event.success {
							stats.successes.fetch_add(1, Ordering::SeqCst);
						}
					}
				}))
				.build();
			let cluster_conf = ClusterConf::builder(tls)
				.with_heartbeat_config(heartbeat_conf)
				.build();

			let cluster = ClusterGateway::start(trace, cluster_conf).await?;
			Ok((cluster, ()))
		},
		hives: |trace, _| {
			let certs = get_cluster_test_certs();
			vec![
				ClusterTestHive::start(Arc::clone(&trace), Some(HiveConf {
					trust_store: Some(Arc::clone(&certs.trust)),
					..Default::default()
				}))
			]
		},
		setup: |cluster_addr, _env_config| async move {
			let certs = get_cluster_test_certs();
			// Client uses TLS (validates cluster cert, no client cert needed)
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.trust));
			let client = builder.connect(cluster_addr).await?;
			Ok(client)
		},
		client: |trace, mut client, config| async move {
			// Send work request to cluster
			let request = ClusterWorkRequest {
				servlet_type: b"ping".to_vec(),
				payload: encode(&PingRequest { value: 21 })?,
			};

			trace.event("work_sent")?;

			let response_frame = client.emit(compose! {
				V0: id: b"work-001",
					message: request
			}?, None).await?;

			// Verify response
			if let Some(frame) = response_frame {
				let work_response: ClusterWorkResponse = decode(&frame.message)?;
				trace.event_with("routing_status", &[], work_response.status)?;
			}

			// Wait for heartbeat and verify stats
			tokio::time::sleep(config.heartbeat_interval * 2).await;
			let attempts = config.heartbeat_stats.attempts.load(Ordering::SeqCst);
			let successes = config.heartbeat_stats.successes.load(Ordering::SeqCst);
			assert!(attempts >= 1, "Expected at least 1 heartbeat attempt, got {attempts}");
			assert!(successes >= 1, "Expected at least 1 heartbeat success, got {successes}");

			Ok(())
		}
	}
}
