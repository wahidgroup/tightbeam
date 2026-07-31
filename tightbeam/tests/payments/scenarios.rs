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

use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::exactly;
use tightbeam::{
	builder::TypeBuilder,
	colony::{
		cluster::{Cluster, ClusterConfig, ClusterRequest, ClusterTlsConfig, ClusterWorkRequest, ClusterWorkResponse},
		common::ColonyNamespace,
		hive::{Hive, HiveConfig, HiveTlsConfig},
		servlet::ServletConfig,
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
	instrumentation::events,
	policy::TransitStatus,
	tb_assert_spec, tb_scenario,
	testing::SetupEnv,
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
	},
	utils::{compose, urn::Urn},
	TightBeamError, Version,
};

use crate::common::x509::create_test_cert_with_key;

use super::cluster::PaymentGatewayCluster;
use super::currency::MonetaryAmount;
use super::hives::PaymentProcessorHive;
use super::messages::{CreditTransferTransaction, PaymentIdentification};
use super::servlets::{AuthorizationServlet, AUTHORIZATION_APPROVED};

/// Client-observed work reply status (`TransitStatus` on the wire response).
pub(crate) const WORK_STATUS: Urn<'static> = Urn::new("test", "event:scenarios/work-status");

/// Type URN the payment scenario registers and targets.
fn authorization_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("authorization")
		.expect("test names satisfy the mint grammar")
}

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

impl TestCerts {
	fn generate() -> Self {
		let (cluster_cert, cluster_key) =
			create_test_cert_with_key("CN=Payment Gateway", 365).expect("Failed to create cluster cert");
		let cluster_trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![cluster_cert.to_owned()])
				.expect("Failed to build cluster trust")
				.build(),
		);

		let (hive_cert, hive_key) =
			create_test_cert_with_key("CN=Payment Hive", 365).expect("Failed to create hive cert");
		let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![hive_cert.to_owned()])
				.expect("Failed to build hive trust")
				.build(),
		);

		Self { cluster_cert, cluster_key, cluster_trust, hive_cert, hive_key, hive_trust }
	}
}

// ============================================================================
// TLS Config Helpers (DRY)
// ============================================================================

fn cluster_tls_config(certs: &TestCerts) -> ClusterTlsConfig {
	ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.cluster_cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.cluster_key.to_owned())),
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.hive_trust)),
		peer_trust: None,
	}
}

fn hive_tls_config(certs: &TestCerts) -> HiveConfig {
	let hive_tls = Arc::new(HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.hive_cert.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.hive_key.to_owned())),
		validators: vec![],
	});
	HiveConfig {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.cluster_trust)),
		..Default::default()
	}
}

fn servlet_tls_config(
	certs: &TestCerts,
) -> Result<ServletConfig<TokioListener, CreditTransferTransaction, DefaultCryptoProvider>, TightBeamError> {
	Ok(
		ServletConfig::<TokioListener, CreditTransferTransaction, DefaultCryptoProvider>::builder()
			.with_certificate(
				CertificateSpec::Built(Box::new(certs.hive_cert.to_owned())),
				Arc::new(Secp256k1KeyProvider::from(certs.hive_key.to_owned())),
				vec![],
			)?
			// Match cluster/hive mux offers so work forwards negotiate mux.
			.with_mux_offer(Some(TransportOffer::mux(8)))
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
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(events::CLUSTER_WORK_REFUSED, exactly!(0)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(0)),
			(events::CLUSTER_WORK_FAILED, exactly!(0)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(0)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(AUTHORIZATION_APPROVED, exactly!(1), equals!(true))
		]
	}
}

// ============================================================================
// Payment Gateway Cluster Test
// ============================================================================

tb_scenario! {
	name: payment_gateway_cluster,
	spec: PaymentGatewaySpec,
	environment Bare {
		context: TestCerts::generate(),
		exec: |SetupEnv { trace, context: certs }| async move {
			// One shared collector so cluster instrument events and servlet
			// outcomes land on the scenario spec (colony registration style).
			let mut cluster_conf = ClusterConfig::new(cluster_tls_config(&certs));
			cluster_conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

			let cluster = PaymentGatewayCluster::start(Arc::new(trace.share()), cluster_conf).await?;
			let cluster_addr = cluster.addr();

			let servlet_conf = servlet_tls_config(&certs)?;
			let servlet = AuthorizationServlet::start(Arc::new(trace.share()), Some(servlet_conf)).await?;

			let mut hive_conf = hive_tls_config(&certs);
			hive_conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

			let mut hive = PaymentProcessorHive::new(Some(hive_conf))?;
			hive.register(authorization_urn(), servlet, |t| AuthorizationServlet::start(t, None))?;
			hive.establish(Arc::new(trace.share())).await?;

			let _reg_response = hive.register_with_cluster(cluster_addr).await?;

			let transaction = create_auth_transaction(b"E2E-001", MonetaryAmount::new(10000, *b"USD"));
			let work_request =
				ClusterRequest::Work(ClusterWorkRequest::new(authorization_urn(), encode(&transaction)?));

			let frame = compose(Version::V0)
				.with_id(b"payment-auth")
				.with_order(0)
				.with_message(work_request)
				.build()?;

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.cluster_trust))
				.build();

			let mut client = builder.connect(cluster_addr).await?;
			let response_frame = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let work_response: ClusterWorkResponse = decode(&response_frame.message)?;
			trace.event_with(WORK_STATUS, &[], work_response.status)?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}
