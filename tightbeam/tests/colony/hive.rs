//! Integration tests for Hive with X.509 certificates
//!
//! Tests the Hive lifecycle through its public interface with TLS.

use std::sync::Arc;

use tightbeam::{
	colony::drone::{Hive, HiveConf, HiveTlsConfig},
	colony::servlet::Servlet,
	compose,
	crypto::{key::Secp256k1KeyProvider, x509::CertificateSpec},
	decode,
	der::Sequence,
	drone, exactly, servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	transport::tcp::r#async::TokioListener,
	Beamable,
};

use crate::common::x509::create_test_cert_with_key;

// ============================================================================
// Test Messages
// ============================================================================

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct HiveTestRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct HiveTestResponse {
	pub doubled: u32,
}

// ============================================================================
// Test Servlets
// ============================================================================

servlet! {
	HiveTestServlet<HiveTestRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |frame, trace, _config, _workers| async move {
		trace.event("servlet_receive")?;
		let req: HiveTestRequest = decode(&frame.message)?;

		trace.event("servlet_respond")?;
		Ok(Some(compose! {
			V0: id: frame.metadata.id.clone(),
				message: HiveTestResponse { doubled: req.value * 2 }
		}?))
	}
}

// ============================================================================
// Test Hive
// ============================================================================

drone! {
	HiveX509Test,
	protocol: TokioListener,
	hive: true,
	servlets: {
		test_servlet: HiveTestServlet<HiveTestRequest>
	}
}

// ============================================================================
// Assertion Spec
// ============================================================================

tb_assert_spec! {
	pub HiveEstablishSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("hive_started", exactly!(1)),
			("hive_established", exactly!(1))
		]
	}
}

// ============================================================================
// Integration Test
// ============================================================================

tb_scenario! {
	name: hive_establish_with_x509,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveEstablishSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			trace.event("hive_started")?;

			// Generate test certificate and key
			let (cert, signing_key) = create_test_cert_with_key("CN=Hive Test Server", 365)?;

			// Configure TLS for servlets (no client validation for this test)
			let tls_config = Arc::new(HiveTlsConfig {
				certificate: CertificateSpec::Built(Box::new(cert)),
				key: Arc::new(Secp256k1KeyProvider::from(signing_key)),
				validators: vec![],
			});

			// Configure hive with TLS
			let hive_conf = HiveConf {
				hive_tls: Some(tls_config),
				..Default::default()
			};

			// Start the hive
			let mut hive = HiveX509Test::start(
				Arc::new(TraceCollector::new()),
				Some(hive_conf),
			).await?;

			// Establish the hive - spawns min_instances of each servlet type
			hive.establish_hive().await?;

			trace.event("hive_established")?;

			// Verify servlets are running
			let servlet_addrs = hive.servlet_addresses().await;
			assert!(!servlet_addrs.is_empty(), "Hive should have running servlets");

			// Clean up
			hive.stop();

			Ok(())
		}
	}
}

// Test without TLS to verify basic hive functionality
tb_scenario! {
	name: hive_establish_no_tls,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveEstablishSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			trace.event("hive_started")?;

			// Configure hive without TLS
			let hive_conf = HiveConf::default();

			// Start the hive
			let mut hive = HiveX509Test::start(
				Arc::new(TraceCollector::new()),
				Some(hive_conf),
			).await?;

			// Establish the hive
			hive.establish_hive().await?;

			trace.event("hive_established")?;

			// Verify servlets are running
			let servlet_addrs = hive.servlet_addresses().await;
			assert!(!servlet_addrs.is_empty(), "Hive should have running servlets");

			// Clean up
			hive.stop();

			Ok(())
		}
	}
}
