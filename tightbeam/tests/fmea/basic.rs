#![cfg(feature = "testing-fmea")]

use tightbeam::error::TightBeamError;
use tightbeam::testing::fdr::{FdrConfig, FdrVerdict};
use tightbeam::testing::fmea::{FailureMode, FmeaConfig, SeverityScale};
use tightbeam::testing::specs::csp::Process;
use tightbeam::testing::{FaultModel, HookContext, ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_gen_process_types, tb_process_spec, tb_scenario};

use safety_process::States;

pub(crate) const ACTUATE: Urn<'static> = tightbeam::urn!("test", "event:fmea-basic/actuate");
pub(crate) const SAFE_MODE: Urn<'static> = tightbeam::urn!("test", "event:fmea-basic/safe-mode");
pub(crate) const SENSOR_READ: Urn<'static> = tightbeam::urn!("test", "event:fmea-basic/sensor-read");
pub(crate) const VALIDATE: Urn<'static> = tightbeam::urn!("test", "event:fmea-basic/validate");

tb_assert_spec! {
	pub FmeaTestSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SENSOR_READ, exactly!(1)),
			(VALIDATE, exactly!(1)),
			(ACTUATE, exactly!(1))
		]
	}
}

tb_process_spec! {
	pub SafetyProcess,
	events {
		observable { SENSOR_READ, VALIDATE, ACTUATE, SAFE_MODE }
		hidden { }
	}
	states {
		Idle => { SENSOR_READ => Validating },
		Validating => { VALIDATE => Actuating, SAFE_MODE => SafeMode },
		Actuating => { ACTUATE => Idle },
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

fn create_test_config(process: Process, scale: SeverityScale) -> FdrConfig {
	let start_state = States::Idle;
	let event = SENSOR_READ;
	let probability_bps = tightbeam::bps!(5000);
	let error_fn = || SensorFault;
	let fault_model = FaultModel::default().with_fault(start_state, event, error_fn, probability_bps);

	FdrConfig {
		seeds: 5,
		max_depth: 10,
		specs: vec![process],
		fault_model: Some(fault_model),
		fmea_config: Some(FmeaConfig { severity_scale: scale, rpn_critical_threshold: 100, auto_generate: true }),
		..Default::default()
	}
}

/// The configuration that grades [`FmeaTestSpec`], explores [`SafetyProcess`]
/// with FMEA on the severity `scale`, and verifies the FMEA report.
fn fmea_scenario_config(scale: SeverityScale) -> Result<ScenarioConfig, Box<dyn std::error::Error>> {
	let hooks = TestHooks::on_pass(|context| {
		verify_fmea_report(context.verdict().fdr()).expect("FMEA verification failed");
	});

	fmea_hooked_config(scale, hooks)
}

/// The configuration that grades [`FmeaTestSpec`], explores [`SafetyProcess`]
/// with FMEA on the severity `scale`, and runs `hooks`.
fn fmea_hooked_config(scale: SeverityScale, hooks: TestHooks) -> Result<ScenarioConfig, Box<dyn std::error::Error>> {
	let fdr = create_test_config(SafetyProcess::process()?, scale);
	let builder = ScenarioConfig::builder().with_spec(FmeaTestSpec::latest()).with_fdr(fdr);
	Ok(builder.with_hooks(hooks).build()?)
}

/// Records one cycle of [`SafetyProcess`]: a sensor read, a validation, and an
/// actuation.
fn run_one_cycle(trace: &TraceCollector) -> Result<(), TightBeamError> {
	trace.event(SENSOR_READ)?;
	trace.event(VALIDATE)?;
	trace.event(ACTUATE)?;
	Ok(())
}

/// The effects and the severity of the first failure mode in the FMEA report
/// of `context`.
fn first_rating(context: &HookContext) -> Option<(Vec<String>, u8)> {
	let report = context.verdict().fdr()?.fmea_report.as_ref()?;
	let FailureMode { effects, severity, .. } = report.failure_modes.first()?;
	Some((effects.clone(), *severity))
}

fn verify_fmea_report(verdict_opt: Option<&FdrVerdict>) -> Result<(), Box<dyn std::error::Error>> {
	let verdict = verdict_opt.ok_or("No FDR verdict")?;
	let fmea = verdict.fmea_report.as_ref().ok_or("FMEA report not generated")?;
	assert!(!fmea.failure_modes.is_empty(), "Should have failure modes");
	assert!(fmea.total_rpn > 0, "Total RPN should be positive");

	Ok(())
}

tb_scenario! {
	name: test_fmea_mil_std,
	config: fmea_scenario_config(SeverityScale::MilStd1629),
	environment Bare {
		exec: |SetupEnv { trace, .. }| run_one_cycle(&trace)
	}
}

tb_scenario! {
	name: test_fmea_iso26262,
	config: fmea_scenario_config(SeverityScale::Iso26262),
	environment Bare {
		exec: |SetupEnv { trace, .. }| run_one_cycle(&trace)
	}
}

// The scenario's subject is the process of its recorded trace, and the faults
// fire in `SafetyProcess`. From `Idle`, every state stays reachable and so
// does the terminal `SafeMode`, so each fault rates as a minor one.
tb_scenario! {
	name: test_fmea_rates_each_fault_in_the_spec_it_fired_in,
	config: fmea_hooked_config(SeverityScale::MilStd1629, TestHooks::on_pass(|context| {
				let rating = (vec![String::from("Can reach terminal state(s): SafeMode")], 3);
				assert_eq!(first_rating(context), Some(rating));
			})),
	environment Bare {
		exec: |SetupEnv { trace, .. }| run_one_cycle(&trace)
	}
}
