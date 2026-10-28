//! This crate compiles one `tb_scenario!` body under two tightbeam feature
//! selections.
//!
//! `narrow` enables `testing` alone, and `wide` adds `testing-csp`,
//! `testing-fdr`, `testing-timing`, and `instrument`. A
//! `#[cfg(feature = ...)]` on [`SpecViolation::CspProcessViolation`] or
//! [`EventOrderViolationDetail`] breaks the `narrow` build, and so does a
//! `#[cfg]` on `ScenarioVerdict::exploration`, which the observer reads.

// The crate declares `narrow` and `wide` alone, so a tightbeam feature gate
// that a macro body leaks into it is a denied `unexpected_cfgs`.
#![deny(unexpected_cfgs)]

use tightbeam::testing::specs::{EventOrderViolationDetail, SpecViolation};
use tightbeam::testing::TestHooks;

/// Under `narrow`, a `tb_assert_spec!` block whose feature is off fails to
/// compile, so a spec keeps every check it states.
///
/// The `schedulability:` block needs `testing-timing`:
///
/// ```compile_fail
/// const RAN: tightbeam::urn::Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");
///
/// tightbeam::tb_assert_spec! {
///     pub ScheduleBlockSpec,
///     V(1,0,0): {
///         mode: Accept,
///         assertions: [
///             (RAN, tightbeam::exactly!(1))
///         ],
///         schedulability: {
///             task_set: tightbeam::testing::schedulability::TaskSet {
///                 tasks: vec![],
///                 scheduler: tightbeam::testing::schedulability::SchedulerType::RateMonotonic,
///             },
///             scheduler: RateMonotonic,
///             must_be_schedulable: true,
///         }
///     }
/// }
/// ```
///
/// The `events:` list needs `instrument`:
///
/// ```compile_fail
/// const RAN: tightbeam::urn::Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");
///
/// tightbeam::tb_assert_spec! {
///     pub OrderedSpec,
///     V(1,0,0): {
///         mode: Accept,
///         assertions: [],
///         events: [ RAN ]
///     }
/// }
/// ```
#[cfg(not(feature = "wide"))]
pub struct RefusedSpecForms;

/// Names the verification layer that produced a violation.
///
/// Each arm binds its variant's payload, so both payload types must resolve
/// under whichever selection compiles this crate.
pub fn layer_of(violation: &SpecViolation) -> String {
	match violation {
		SpecViolation::CspProcessViolation(violations) => {
			format!("csp: {} violation(s)", violations.len())
		}
		SpecViolation::EventOrderViolation(detail) => {
			let order: &EventOrderViolationDetail = detail;
			format!("order: position {}", order.position)
		}
		other => format!("assertion: {other:?}"),
	}
}

/// Returns hooks whose `on_fail` observer reads every violation of the run
/// and the trace of the Layer 3 exploration.
pub fn observing_hooks() -> TestHooks {
	TestHooks::on_fail(|context, violations| {
		let _layers: Vec<String> = violations.iter().map(layer_of).collect();
		let exploration = context.verdict().exploration();
		let _explored = exploration.map(|exploration| exploration.assertions().len());
	})
}

#[cfg(test)]
mod tests {
	use core::str::FromStr;
	use core::time::Duration;

	use tightbeam::crypto::policy::{Secp256k1Policy, VerificationPolicy};
	use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	use tightbeam::crypto::sign::Sha3Signer;
	use tightbeam::crypto::x509::name::Name;
	use tightbeam::der::Encode;
	use tightbeam::spki::SubjectPublicKeyInfoOwned;
	use tightbeam::testing::env::SetupEnv;
	use tightbeam::testing::specs::SpecViolation;
	use tightbeam::testing::ScenarioConfig;
	use tightbeam::urn::Urn;

	use super::{layer_of, observing_hooks};

	const SCENARIO_RAN: Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");

	/// An ECDSA signature over secp256k1 in DER form, the type that the
	/// `signature:` key of `csr!` and `cert!` names here.
	type Secp256k1Der = tightbeam::crypto::sign::ecdsa::der::Signature<tightbeam::crypto::sign::ecdsa::Secp256k1>;

	// `narrow` compiles the assertion layer alone, so that layer is the one
	// verifier both selections share.
	tightbeam::tb_assert_spec! {
		pub ScenarioRanSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SCENARIO_RAN, tightbeam::exactly!(1))
			]
		}
	}

	// `wide` turns `testing-timing` on, so the schedulability block expands
	// to its assertion. Under `narrow` the block fails to compile, as the
	// `compile_fail` examples of `RefusedSpecForms` show.
	#[cfg(feature = "wide")]
	tightbeam::tb_assert_spec! {
		pub ScheduleBlockSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SCENARIO_RAN, tightbeam::exactly!(1))
			],
			schedulability: {
				task_set: tightbeam::testing::schedulability::TaskSet {
					tasks: vec![],
					scheduler: tightbeam::testing::schedulability::SchedulerType::RateMonotonic,
				},
				scheduler: RateMonotonic,
				must_be_schedulable: true,
			}
		}
	}

	tightbeam::tb_scenario! {
		name: one_scenario_body_compiles_under_this_selection,
		config: ScenarioConfig::builder()
			.with_spec(ScenarioRanSpec::latest())
			.with_hooks(observing_hooks())
			.build(),
		environment Bare {
			exec: |env: SetupEnv<()>| {
				env.trace.event(SCENARIO_RAN)?;
				Ok(())
			}
		}
	}

	#[test]
	fn both_violation_payloads_are_nameable_under_this_selection() {
		let csp = SpecViolation::CspProcessViolation(Vec::new());
		assert_eq!(layer_of(&csp), "csp: 0 violation(s)");
	}

	#[test]
	fn a_csr_expansion_signs_the_subject_it_names() -> Result<(), Box<dyn core::error::Error>> {
		let signing_key = Secp256k1SigningKey::from_bytes(&[7; 32].into())?;
		let signer = Sha3Signer::from(&signing_key);
		let request = tightbeam::csr!(subject: "CN=consumer", signer: &signer)?;
		let public_key = request.info.public_key.to_der()?;

		let message = request.info.to_der()?;
		let signature = request.signature.raw_bytes();
		Secp256k1Policy::default().verify_signature(&request.algorithm.oid, &public_key, &message, signature)?;
		assert_eq!(request.info.subject, Name::from_str("CN=consumer")?);
		Ok(())
	}

	#[test]
	fn a_csr_expansion_takes_a_signature_key_from_an_outside_crate() -> Result<(), Box<dyn core::error::Error>> {
		let signing_key = Secp256k1SigningKey::from_bytes(&[7; 32].into())?;
		let signer = Sha3Signer::from(&signing_key);
		let request = tightbeam::csr!(subject: "CN=consumer", signer: &signer, signature: Secp256k1Der)?;
		let public_key = request.info.public_key.to_der()?;

		let message = request.info.to_der()?;
		let signature = request.signature.raw_bytes();
		Secp256k1Policy::default().verify_signature(&request.algorithm.oid, &public_key, &message, signature)?;
		Ok(())
	}

	#[test]
	fn a_cert_expansion_takes_a_signature_key_from_an_outside_crate() -> Result<(), Box<dyn core::error::Error>> {
		let signing_key = Secp256k1SigningKey::from_bytes(&[7; 32].into())?;
		let signer = Sha3Signer::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(*signing_key.verifying_key())?;
		let public_key = spki.to_der()?;
		let certificate = tightbeam::cert!(
			profile: Root,
			subject: "CN=consumer root",
			serial: 1u32,
			duration: Duration::from_secs(3600),
			signer: &signer,
			subject_public_key: spki,
			signature: Secp256k1Der
		)?;

		let message = certificate.tbs_certificate.to_der()?;
		let signature = certificate.signature.raw_bytes();
		let algorithm = &certificate.signature_algorithm.oid;
		Secp256k1Policy::default().verify_signature(algorithm, &public_key, &message, signature)?;
		Ok(())
	}
}
