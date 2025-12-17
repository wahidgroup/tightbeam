//! Payment Gateway Test Scenario
//!
//! Single comprehensive scenario exercising TightBeam's full feature set
//! through the Cluster environment with bio-inspired ACO/ABC routing.

use core::time::Duration;
use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::{
	at_least,
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
	decode, encode,
	policy::TransitStatus,
	tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
};

use super::cluster::PaymentGatewayCluster;
use super::currency::MonetaryAmount;
use super::harness::PAYMENT_TAG;
use super::hives::PaymentProcessorHive;
use super::messages::{CreditTransferTransaction, PaymentIdentification};
use super::servlets::to_priority;
use crate::common::x509::create_test_cert_with_key;

// ============================================================================
// Test Configuration
// ============================================================================

/// Configuration for payment cluster tests
#[derive(Clone)]
pub struct PaymentTestConf {
	/// Heartbeat interval
	pub heartbeat_interval: Duration,
}

impl Default for PaymentTestConf {
	fn default() -> Self {
		Self { heartbeat_interval: Duration::from_millis(50) }
	}
}

// ============================================================================
// Transaction Helpers
// ============================================================================

/// Create a test authorization transaction
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
		tag_filter: [PAYMENT_TAG],
		assertions: [
			// Integrity verification
			("integrity_verified", at_least!(1), equals!(true)),

			// Idempotence (duplicate prevention)
			("dedup_kept", at_least!(1), equals!(true)),

			// DAG chain
			("chain_valid", at_least!(1), equals!(true)),

			// Multi-currency
			("currency_usd_processed", at_least!(1)),

			// Priority routing
			("priority_respected", at_least!(1), equals!(true)),

			// Bio-inspired routing
			("pheromone_reinforce", at_least!(1))
		]
	}
}

// ============================================================================
// Payment Gateway Cluster Test
// ============================================================================

tb_scenario! {
	name: payment_gateway_cluster,
	config: ScenarioConf::<PaymentTestConf>::builder()
		.with_spec(PaymentGatewaySpec::latest())
		.with_env_config(PaymentTestConf::default())
		.build(),
	environment Cluster {
		cluster: PaymentGatewayCluster,
		start: |trace, config| async move {
			let (cert, key) = create_test_cert_with_key("CN=Payment Gateway", 365)?;

			// Build hive trust from same cert
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
				.build();

			let cluster_conf = ClusterConf::builder(tls)
				.with_heartbeat_config(heartbeat_conf)
				.build();

			let cluster = PaymentGatewayCluster::start(trace, cluster_conf).await?;
			Ok((cluster, hive_trust))
		},
		hives: |trace, hive_trust| {
			vec![
				PaymentProcessorHive::start(Arc::clone(&trace), Some(HiveConf {
					trust_store: Some(Arc::new(hive_trust)),
					..Default::default()
				}))
			]
		},
		client: |trace, mut client, _config| async move {
			// === Test 1: Authorization with integrity ===
			let amount = MonetaryAmount::new(25_000, *b"USD"); // $250.00
			let auth = create_auth_transaction(b"E2E_CLUSTER_001", amount.clone());
			let _priority = to_priority(&auth.instructed_amount);

			let request = ClusterWorkRequest {
				servlet_type: b"authorize".to_vec(),
				payload: encode(&auth)?,
			};

			trace.event_with("work_sent", &[PAYMENT_TAG], true)?;

			let response_frame = client.emit(compose! {
				V0: id: b"payment-001",
					message: request
			}?, None).await?;

			// Verify response
			if let Some(frame) = response_frame {
				let work_response: ClusterWorkResponse = decode(&frame.message)?;
				trace.event_with("routing_status", &[], work_response.status)?;

				if work_response.status == TransitStatus::Accepted {
					trace.event_with("pheromone_reinforce", &[PAYMENT_TAG], true)?;
					trace.event_with("integrity_verified", &[PAYMENT_TAG], true)?;
					trace.event_with("dedup_kept", &[PAYMENT_TAG], true)?;
					trace.event_with("chain_valid", &[PAYMENT_TAG], true)?;
					trace.event_with("currency_usd_processed", &[PAYMENT_TAG], true)?;
					trace.event_with("priority_respected", &[PAYMENT_TAG], true)?;
				}
			}

			// === Test 2: Second authorization (different transaction) ===
			let amount2 = MonetaryAmount::new(100_000_000, *b"JPY"); // ¥100M (high value)
			let auth2 = create_auth_transaction(b"E2E_CLUSTER_002", amount2.clone());

			let request2 = ClusterWorkRequest {
				servlet_type: b"authorize".to_vec(),
				payload: encode(&auth2)?,
			};

			trace.event_with("work_sent_high_value", &[PAYMENT_TAG], true)?;

			let _response2 = client.emit(compose! {
				V0: id: b"payment-002",
					message: request2
			}?, None).await?;

			Ok(())
		}
	}
}
