#![cfg(feature = "testing-fmea")]

use tightbeam::error::TightBeamError;
use tightbeam::testing::fdr::{FdrConfig, FdrVerdict};
use tightbeam::testing::fmea::{FmeaConfig, SeverityScale};
use tightbeam::testing::{FaultModel, ScenarioConf, TestHooks};
use tightbeam::utils::BasisPoints;
use tightbeam::{tb_assert_spec, tb_gen_process_types, tb_process_spec, tb_scenario};

use safety_process::{Event, States};

// Simple test spec for FMEA tests
tb_assert_spec! {
	pub FmeaTestSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

tb_process_spec! {
	pub SafetyProcess,
	events {
		observable { "sensor_read", "validate", "actuate", "safe_mode" }
		hidden { }
	}
	states {
		Idle => { "sensor_read" => Validating },
		Validating => { "validate" => Actuating, "safe_mode" => SafeMode },
		Actuating => { "actuate" => Idle },
		SafeMode => { }
	}
	terminal { SafeMode }
}

tb_gen_process_types! { SafetyProcess, Idle, Validating, Actuating, SafeMode }

#[derive(Debug, Clone, Copy)]
struct SensorFault;

impl core::fmt::Display for SensorFault {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "sensor fault")
	}
}

impl From<SensorFault> for TightBeamError {
	fn from(e: SensorFault) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

fn create_test_config(scale: SeverityScale) -> FdrConfig {
	let start_state = States::Idle;
	let event = Event("sensor_read");
	let probability_bps = BasisPoints::new(5000);
	let error_fn = || SensorFault;
	let fault_model = FaultModel::default().with_fault(start_state, event, error_fn, probability_bps);

	FdrConfig {
		seeds: 5,
		max_depth: 10,
		specs: vec![SafetyProcess::process()],
		fault_model: Some(fault_model),
		fmea_config: Some(FmeaConfig { severity_scale: scale, rpn_critical_threshold: 100, auto_generate: true }),
		..Default::default()
	}
}

fn verify_fmea_report(verdict_opt: &Option<FdrVerdict>) -> Result<(), Box<dyn std::error::Error>> {
	let verdict = verdict_opt.as_ref().ok_or("No FDR verdict")?;
	let fmea = verdict.fmea_report.as_ref().ok_or("FMEA report not generated")?;

	assert!(!fmea.failure_modes.is_empty(), "Should have failure modes");
	assert!(fmea.total_rpn > 0, "Total RPN should be positive");

	Ok(())
}

tb_scenario! {
	name: test_fmea_mil_std,
	config: ScenarioConf::<()>::builder()
		.with_spec(FmeaTestSpec::latest())
		.with_fdr(create_test_config(SeverityScale::MilStd1629))
		.with_hooks(TestHooks {
			on_pass: Some(std::sync::Arc::new(|result| {
				verify_fmea_report(&result.fdr_verdict).expect("FMEA verification failed");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("sensor_read")?;
			trace.event("validate")?;
			trace.event("actuate")?;
			Ok(())
		}
	}
}

tb_scenario! {
	name: test_fmea_iso26262,
	config: ScenarioConf::<()>::builder()
		.with_spec(FmeaTestSpec::latest())
		.with_fdr(create_test_config(SeverityScale::Iso26262))
		.with_hooks(TestHooks {
			on_pass: Some(std::sync::Arc::new(|result| {
				verify_fmea_report(&result.fdr_verdict).expect("FMEA verification failed");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("sensor_read")?;
			trace.event("validate")?;
			trace.event("actuate")?;
			Ok(())
		}
	}
}
