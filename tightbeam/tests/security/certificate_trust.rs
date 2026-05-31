//! # Certificate trust-anchoring threat
//!
//! ## Weakness
//! If a trust validator checks only certificate expiry without consulting its
//! configured `trust_chain` or verifying a signature, any unexpired certificate
//! is accepted regardless of its issuer.
//!
//! ## Attack
//! An adversary presents a self-signed, unexpired certificate that does not
//! chain to any configured trust anchor, enabling certificate substitution and
//! adversary-in-the-middle impersonation.
//!
//! ## Expected control
//! A validator documented as full PKI validation MUST reject a certificate that
//! does not chain to a configured trust anchor.
//!
//! ## References
//! - CWE-295: Improper Certificate Validation
//!   <https://cwe.mitre.org/data/definitions/295.html>
//! - CAPEC-94: Adversary in the Middle (AiTM)
//!   <https://capec.mitre.org/data/definitions/94.html>
//! - RFC 5280 §6: Certification Path Validation

use std::sync::Arc;

use tightbeam::{
	crypto::x509::policy::{CertificateValidation, DirectTrustValidator},
	exactly, job, tb_assert_spec, tb_process_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	TightBeamError,
};

use crate::common::security::{deterministic_signing_key, expectation_failure, random_signing_key, test_certificate};

tb_assert_spec! {
	pub CertificateTrustSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("untrusted_cert_rejected", exactly!(1u32))
		]
	}
}

tb_process_spec! {
	pub CertificateTrustProcess,
	events {
		observable { "untrusted_cert_rejected" }
		hidden { }
	}
	states {
		Idle => { "untrusted_cert_rejected" => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Certificate trust: DirectTrustValidator must enforce its trust anchor" }
}

tb_scenario! {
	name: certificate_trust,
	config: ScenarioConf::<()>::builder()
		.with_spec(CertificateTrustSpec::latest())
		.with_csp(CertificateTrustProcess)
		.build(),
	environment Bare {
		exec: |trace| async move {
			CertificateTrustScenario::run((trace,)).await
		}
	}
}

job! {
	name: CertificateTrustScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let trusted_cert = test_certificate(&deterministic_signing_key());

		// Unrelated, self-signed, still-unexpired certificate held by an attacker.
		let attacker_cert = test_certificate(&random_signing_key());
		let validator = DirectTrustValidator::default().with_trust_chain(vec![trusted_cert]);
		match validator.evaluate(&attacker_cert) {
			Err(_) => {
				trace.event("untrusted_cert_rejected")?;
			}
			Ok(()) => return Err(expectation_failure("certificate outside the trust chain was accepted")),
		}

		Ok(())
	}
}
