//! Payment Gateway Test Scenario
//!
//! One comprehensive scenario exercises TightBeam's full feature set
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
		cluster::{Cluster, ClusterConfig, ClusterTlsConfig},
		common::ColonyNamespace,
		hive::{Hive, HiveConfig, HiveTlsConfig},
		servlet::ServletConfig,
		SubmitWork,
	},
	crypto::{
		aead::{Aes256Gcm, Aes256GcmOid, Key, KeyInit},
		key::Secp256k1KeyProvider,
		policy::Secp256k1Policy,
		profiles::DefaultCryptoProvider,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
		x509::{
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	decode,
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
use super::messages::{CreditTransferTransaction, PaymentIdentification, TransactionStatus};
use super::servlets::{AuthorizationServlet, AUTHORIZATION_APPROVED, INTEGRITY_VERIFIED};

/// Client-observed work reply status (`TransitStatus` on the wire response).
pub(crate) const WORK_STATUS: Urn<'static> = Urn::new("test", "event:scenarios/work-status");

/// Client-observed approval decoded from inside the servlet's response frame.
pub(crate) const CLIENT_AUTH_APPROVED: Urn<'static> = Urn::new("test", "event:scenarios/client-auth-approved");

/// Type URN the payment scenario registers and targets.
fn authorization_urn() -> Urn<'static> {
	ColonyNamespace::default()
		.servlet("authorization")
		.expect("test names satisfy the mint grammar")
}

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
			.with_message_decryptor(shared_payment_cipher())
			.with_config(Arc::new(()))
			.build(),
	)
}

/// Shared AES-256-GCM cipher for the client-to-servlet confidential body.
///
/// `CreditTransferTransaction` declares `confidential`, so the client
/// frame carries an encrypted message and the servlet decrypts it before
/// typed dispatch. A fixed key stands in for a real exchange in tests.
fn shared_payment_cipher() -> Aes256Gcm {
	Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]))
}

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
			(AUTHORIZATION_APPROVED, exactly!(1), equals!(true)),
			(INTEGRITY_VERIFIED, exactly!(1), equals!(true)),
			(CLIENT_AUTH_APPROVED, exactly!(1), equals!(true))
		]
	}
}

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
			let inner = compose(Version::V1)
				.with_id(b"payment-auth-txn")
				.with_order(0)
				.with_message(transaction)
				.with_message_hasher::<Sha3_256>([])
				.with_witness_hasher::<Sha3_256>()
				.with_aead::<Aes256GcmOid, _>(shared_payment_cipher())
				.with_signer::<Secp256k1Signature, _>(certs.cluster_key.to_owned())
				.build()?;

			let builder = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(Arc::clone(&certs.cluster_trust))
				.build();

			// One call on the public client surface wraps the work frame
			// in the hop-local transport envelope and resolves the reply
			// to the servlet's response frame. `served` admits only an
			// `Ok` gateway status, so reaching the next line pins the
			// wire status the spec asserts.
			let mut client = builder.connect(cluster_addr).await?;
			let servlet_frame = client.submit_work_to(authorization_urn(), &inner).await?;
			trace.event_with(WORK_STATUS, &[], TransitStatus::Ok)?;

			// The gateway returns the servlet's complete response frame.
			// Decoding the typed approval from inside it proves the
			// response envelope survived the route back to the client.
			let status: TransactionStatus = decode(&servlet_frame.message)?;
			trace.event_with(CLIENT_AUTH_APPROVED, &[], status.status.is_success())?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}
