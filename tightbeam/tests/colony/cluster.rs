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

use std::sync::Arc;

use tightbeam::{
	cluster,
	colony::{
		cluster::{ClusterConf, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse},
		servlet::Servlet,
	},
	compose,
	crypto::{key::Secp256k1KeyProvider, x509::CertificateSpec},
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

/// Configuration for cluster tests
#[derive(Clone)]
pub struct ClusterTestConf {
	pub tls_config: Arc<ClusterTlsConfig>,
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
			tls_config: {
				let (cert, signing_key) = create_test_cert_with_key("CN=Cluster Gateway", 365).unwrap();
				Arc::new(ClusterTlsConfig {
					certificate: CertificateSpec::Built(Box::new(cert)),
					key: Arc::new(Secp256k1KeyProvider::from(signing_key)),
					validators: vec![],
				})
			},
		})
		.build(),
	environment Cluster {
		cluster: ClusterGateway,
		start: |trace, config| async move {
			let cluster_conf = ClusterConf::new((*config.tls_config).clone());
			ClusterGateway::start(trace, cluster_conf).await
		},
		drones: [
			ClusterTestHive,
		],
		client: |trace, mut client, _config| async move {
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

			Ok(())
		}
	}
}
