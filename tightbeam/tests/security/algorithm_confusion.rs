//! # Signature algorithm-confusion threat
//!
//! ## Weakness
//! If `Secp256k1Policy::verify_signature` ignored its `algorithm_oid` argument
//! and verified the bytes as secp256k1 ECDSA unconditionally, an attacker could
//! make a relying party accept a signature under an algorithm it never agreed
//! to.
//!
//! ## Attack
//! An attacker takes a signature that genuinely verifies under the real ECDSA
//! OID and presents it under an unrelated algorithm OID (here AES-256-GCM). A
//! flawed policy accepts it.
//!
//! ## Expected control
//! A sound policy MUST reject an algorithm OID it does not support. It MUST
//! refuse under an unrelated OID (`UnsupportedAlgorithm`) the same key,
//! message, and signature that it accepts under the genuine ECDSA OID.
//!
//! ## References
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CAPEC-475: Signature Spoofing by Improper Validation <https://capec.mitre.org/data/definitions/475.html>
//! - RFC 5280 §4.1.1.2: signatureAlgorithm identifier binding

use std::sync::Arc;

use tightbeam::{
	crypto::{
		hash::Sha3_256,
		policy::{Secp256k1Policy, VerificationPolicy},
		sign::{ecdsa::Secp256k1Signature, CanonicalSigner},
		x509::error::CertificateValidationError::UnsupportedAlgorithm,
	},
	der::Encode,
	exactly, job,
	oids::{AES_256_GCM, SIGNER_ECDSA_WITH_SHA3_256},
	tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ScenarioConfig, SetupEnv},
	trace::TraceCollector,
	urn::Urn,
	TightBeamError,
};

use crate::common::security::{deterministic_signing_key, expectation_failure, test_certificate};

pub(crate) const FOREIGN_OID_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:algorithm-confusion/foreign-oid-rejected");

tb_assert_spec! {
	pub AlgorithmConfusionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(FOREIGN_OID_REJECTED, exactly!(1u32), equals!(true))
		]
	}
}

tb_process_spec! {
	pub AlgorithmConfusionProcess,
	events {
		observable { FOREIGN_OID_REJECTED }
		hidden { }
	}
	states {
		Idle => { FOREIGN_OID_REJECTED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Algorithm confusion: policy must honour the advertised signature OID" }
}

tb_scenario! {
	name: algorithm_confusion,
	config: ScenarioConfig::builder()
		.with_spec(AlgorithmConfusionSpec::latest())
		.with_csp(AlgorithmConfusionProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			AlgorithmConfusionScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: AlgorithmConfusionScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let signing_key = deterministic_signing_key();
		let cert = test_certificate(&signing_key);
		let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;

		let message: &[u8] = b"tbs-certificate-bytes";
		let signature: Secp256k1Signature = signing_key.sign_canonical::<Sha3_256>(message).map_err(|_| expectation_failure("signing failed"))?;
		let signature_bytes = signature.to_bytes();

		// The signature genuinely verifies under the real secp256k1 ECDSA OID.
		let policy = Secp256k1Policy::default();
		policy
			.verify_signature(&SIGNER_ECDSA_WITH_SHA3_256, &spki_der, message, signature_bytes.as_ref())
			.map_err(|_| expectation_failure("baseline verification under the genuine OID failed"))?;

		// Under an unrelated algorithm OID a sound policy must refuse it.
		match policy.verify_signature(&AES_256_GCM, &spki_der, message, signature_bytes.as_ref()) {
			Err(error) => {
				// The policy holds one algorithm, so it refuses the foreign OID
				// by name before it reads the key.
				let unsupported = matches!(error, UnsupportedAlgorithm(oid) if oid == AES_256_GCM);
				trace.event_with(FOREIGN_OID_REJECTED, &[], unsupported)?;
			}
			Ok(_) => return Err(expectation_failure("signature accepted under an unsupported algorithm OID")),
		}

		Ok(())
	}
}
