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

use std::sync::{Arc, OnceLock};

use sha3::Sha3_256;
use tightbeam::der::Sequence;
use tightbeam::{
	builder::TypeBuilder,
	cluster,
	colony::{
		cluster::{Cluster, ClusterConf, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse},
		hive::{Hive, HiveConf, HiveTlsConfig},
		servlet::ServletConf,
	},
	compose,
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
	policy::TransitStatus,
	servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
	utils::compose as frame_compose,
	Beamable, TightBeamError, Version,
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
	protocol: TokioListener
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

			let work_request = ClusterWorkRequest {
				servlet_type: b"ping".to_vec(),
				payload: encode(&PingRequest { value: 21 })?,
			};

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
