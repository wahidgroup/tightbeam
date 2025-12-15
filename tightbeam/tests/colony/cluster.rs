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
use std::sync::Arc;
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
		x509::{
			store::{CertificateTrustBuilder, TrustBuilder},
			CertificateSpec,
		},
	},
	decode,
	der::Sequence,
	encode, exactly, hive,
	policy::TransitStatus,
	servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	transport::tcp::r#async::TokioListener,
	Beamable,
};

use crate::common::x509::create_test_cert_with_key;

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
	handle: |frame, _trace, _config, _workers| async move {
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
			let (cert, key) = create_test_cert_with_key("CN=Cluster Gateway", 365)?;

			// Build hive trust from same cert (before moving cert into ClusterTlsConfig)
			let hive_trust = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![cert.clone()])?
				.build();

			let tls = ClusterTlsConfig {
				certificate: CertificateSpec::Built(Box::new(cert)),
				key: Arc::new(Secp256k1KeyProvider::from(key)),
				validators: vec![],
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
			Ok((cluster, hive_trust))
		},
		hives: |trace, hive_trust| {
			vec![
				ClusterTestHive::start(Arc::clone(&trace), Some(HiveConf {
					trust_store: Some(Arc::new(hive_trust)),
					..Default::default()
				}))
			]
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
