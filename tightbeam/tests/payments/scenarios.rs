//! Payment Gateway Test Scenario
//!
//! Single comprehensive scenario exercising TightBeam's full feature set
//! through the Cluster environment with bio-inspired ACO/ABC routing.

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
use tightbeam::{
	at_least,
	builder::TypeBuilder,
	colony::{
		cluster::{Cluster, ClusterConf, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse},
		hive::{Hive, HiveConf, HiveTlsConfig},
		servlet::ServletConf,
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
	decode, encode,
	policy::TransitStatus,
	tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
	utils::compose,
	TightBeamError, Version,
};

use super::cluster::PaymentGatewayCluster;
use super::currency::MonetaryAmount;
use super::hives::PaymentProcessorHive;
use super::messages::{CreditTransferTransaction, PaymentIdentification, PaymentStatusCode, TransactionStatus};
use super::servlets::AuthorizationServlet;
use crate::common::x509::create_test_cert_with_key;

// ============================================================================
// Shared Test Certificates (lazily initialized)
// ============================================================================

struct TestCerts {
	cluster_cert: Certificate,
	cluster_key: Secp256k1SigningKey,
	cluster_trust: Arc<dyn CertificateTrust>,
	hive_cert: Certificate,
	hive_key: Secp256k1SigningKey,
	hive_trust: Arc<dyn CertificateTrust>,
}

fn get_test_certs() -> &'static TestCerts {
	static CERTS: OnceLock<TestCerts> = OnceLock::new();
	CERTS.get_or_init(|| {
		let (cluster_cert, cluster_key) =
			create_test_cert_with_key("CN=Payment Gateway", 365).expect("Failed to create cluster cert");
		let cluster_trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![cluster_cert.clone()])
				.expect("Failed to build cluster trust")
				.build(),
		);

		let (hive_cert, hive_key) =
			create_test_cert_with_key("CN=Payment Hive", 365).expect("Failed to create hive cert");
		let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![hive_cert.clone()])
				.expect("Failed to build hive trust")
				.build(),
		);

		TestCerts { cluster_cert, cluster_key, cluster_trust, hive_cert, hive_key, hive_trust }
	})
}

// ============================================================================
// TLS Config Helpers (DRY)
// ============================================================================

fn cluster_tls_config(certs: &TestCerts) -> ClusterTlsConfig {
	ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cluster_cert.clone())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.cluster_key.clone())),
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.hive_trust)),
	}
}

fn hive_tls_config(certs: &TestCerts) -> HiveConf {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.hive_cert.clone())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.hive_key.clone())),
		validators: vec![],
	});
	HiveConf {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.cluster_trust)),
		..Default::default()
	}
}

fn servlet_tls_config(
	certs: &TestCerts,
) -> Result<ServletConf<TokioListener, CreditTransferTransaction, DefaultCryptoProvider>, TightBeamError> {
	Ok(
		ServletConf::<TokioListener, CreditTransferTransaction, DefaultCryptoProvider>::builder()
			.with_certificate(
				CertificateSpec::Built(Box::new(certs.hive_cert.clone())),
				Arc::new(Secp256k1KeyProvider::from(certs.hive_key.clone())),
				vec![],
			)?
			.with_config(Arc::new(()))
			.build(),
	)
}

// ============================================================================
// Transaction Helpers
// ============================================================================

fn create_auth_transaction(end_to_end_id: &[u8], amount: MonetaryAmount) -> CreditTransferTransaction {
	let timestamp = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0);

	CreditTransferTransaction::new(
		PaymentIdentification::new(
			format!("INST{}", timestamp).as_bytes(),
			end_to_end_id,
			format!("TXN{}", timestamp).as_bytes(),
		),
		amount,
		b"CRED_ACCT_TOKEN",
		b"DEB_ACCT_TOKEN",
		Some(b"Payment for services".to_vec()),
		timestamp,
	)
}

// ============================================================================
// Assertion Spec
// ============================================================================

tb_assert_spec! {
	pub PaymentGatewaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("work_completed", at_least!(1))
		]
	}
}

// ============================================================================
// Payment Gateway Cluster Test
// ============================================================================

tb_scenario! {
	name: payment_gateway_cluster,
	config: ScenarioConf::<()>::builder()
		.with_spec(PaymentGatewaySpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let certs = get_test_certs();

			// Start cluster
			let cluster_conf = ClusterConf::new(cluster_tls_config(certs));
			let cluster_trace = Arc::new(TraceCollector::new());
			let cluster = PaymentGatewayCluster::start(Arc::clone(&cluster_trace), cluster_conf).await?;
			let cluster_addr = cluster.addr();

			// Start servlet with TLS
			let servlet_conf = servlet_tls_config(certs)?;
			let servlet_trace = Arc::new(TraceCollector::new());
			let servlet = AuthorizationServlet::start(Arc::clone(&servlet_trace), Some(servlet_conf)).await?;

			// Create and establish hive
			let mut hive = PaymentProcessorHive::new(Some(hive_tls_config(certs)))?;
			hive.register("authorization", servlet, |t| AuthorizationServlet::start(t, None))?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

			// Register hive with cluster
			let _reg_response = hive.register_with_cluster(cluster_addr).await?;

			// Create authorization transaction
			let transaction = create_auth_transaction(b"E2E-001", MonetaryAmount::new(10000, *b"USD"));

			let work_request = ClusterWorkRequest {
				servlet_type: b"authorization".to_vec(),
				payload: encode(&transaction)?,
			};

			let frame = compose(Version::V0)
				.with_id(b"payment-auth")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			// Connect to cluster with TLS
			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.cluster_trust))
				.build();
			let mut client = builder.connect(cluster_addr).await?;

			let response_frame = client.emit(frame, None).await?
				.ok_or(TightBeamError::MissingResponse)?;

			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;

			// Mark test completion
			trace.event("work_completed")?;

			// Verify routing succeeded
			if work_response.status == TransitStatus::Accepted {
				if let Some(payload) = work_response.payload {
					let status: TransactionStatus = decode(&payload)?;
					let is_approved = matches!(status.status, PaymentStatusCode::AcceptedCustomerProfile);
					trace.event_with("authorization_approved", &[] as &[&str], is_approved)?;
				}
			}

			// Cleanup
			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}
