//! The fault injection tests of tightbeam.
//!
//! The suite injects faults into a request-response-retry process. Its
//! scenarios follow the research papers and the safety standards below.
//!
//! The research papers are:
//! - Avižienis et al. (2004), "Basic Concepts and Taxonomy of Dependable and Secure Computing".
//! - Arlat et al. (1990), "Fault Injection for Dependability Validation".
//! - Hsueh et al. (1997), "Fault Injection Techniques and Tools".
//!
//! The safety standards are:
//! - ISO 26262, for automotive safety.
//! - DO-178C, for avionics software.
//! - IEC 61508, for functional safety.

use core::error::Error;
use std::collections::HashSet;

use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::specs::csp::Process;
use tightbeam::testing::{FaultModel, HookContext, InjectionStrategy, ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;
use tightbeam::{at_least, exactly, tb_assert_spec, tb_gen_process_types, tb_process_spec, tb_scenario};

use fault_tolerant_process::States;

pub(crate) const FAILURE: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/failure");
pub(crate) const FALLBACK: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/fallback");
pub(crate) const INTERNAL_RETRY: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/internal-retry");
pub(crate) const REQUEST: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/request");
pub(crate) const RESPONSE: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/response");
pub(crate) const RETRY: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/retry");
pub(crate) const SUCCESS: Urn<'static> = tightbeam::urn!("test", "event:fault-basic/success");

// The fault-tolerant process, whose states and events the faults target.

tb_process_spec! {
	/// A request-response-retry process with error recovery, which models a
	/// fault-tolerant distributed system after Cristian (1991), "Understanding
	/// fault-tolerant distributed systems".
	pub FaultTolerantProcess,
	events {
		observable { REQUEST, RESPONSE, RETRY, FALLBACK, SUCCESS, FAILURE }
		hidden { INTERNAL_RETRY }
	}
	states {
		Idle => {
			REQUEST => Sending
		},
		Sending => {
			RESPONSE => Success,
			RETRY => Retrying,
			FALLBACK => Fallback
		},
		Retrying => {
			INTERNAL_RETRY => Sending,
			FALLBACK => Fallback
		},
		Success => {
			SUCCESS => Idle
		},
		Fallback => {
			FAILURE => Idle
		}
	}
}

// The macro generates the typed state enum that each fault names. The call
// lists the states by hand, because a list read from the transitions holds a
// state once for each transition that starts or ends at it.
tb_gen_process_types!(FaultTolerantProcess, Idle, Sending, Retrying, Success, Fallback);

// The error types that the faults inject.

/// A network timeout, a transient failure that a retry can clear.
#[derive(Debug, Clone)]
struct NetworkTimeoutError {
	duration_ms: u64,
	attempt: u8,
}

impl core::fmt::Display for NetworkTimeoutError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Network timeout after {}ms (attempt {})", self.duration_ms, self.attempt)
	}
}

impl From<NetworkTimeoutError> for TightBeamError {
	fn from(e: NetworkTimeoutError) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

/// A corrupted message, a permanent failure that persists across retries.
#[derive(Debug, Clone)]
struct MessageCorruptionError {
	corrupted_bytes: usize,
}

impl core::fmt::Display for MessageCorruptionError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Message corruption detected: {} bytes", self.corrupted_bytes)
	}
}

impl From<MessageCorruptionError> for TightBeamError {
	fn from(e: MessageCorruptionError) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

/// An exhausted system resource, a failure of the system as a whole.
#[derive(Debug, Clone)]
struct ResourceExhaustionError {
	resource: &'static str,
}

impl core::fmt::Display for ResourceExhaustionError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "Resource exhausted: {}", self.resource)
	}
}

impl From<ResourceExhaustionError> for TightBeamError {
	fn from(e: ResourceExhaustionError) -> Self {
		TightBeamError::InjectedFault(Box::new(e))
	}
}

// TEST 1: Deterministic fault injection, a research test of repeatability.

tb_assert_spec! {
	pub DeterministicSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REQUEST, at_least!(1))
		]
	}
}

/// The state of [`FaultTolerantProcess`] that `state` names, as an injection
/// record names it.
fn state_key(state: &str) -> String {
	format!("FaultTolerantProcess.{state}")
}

/// The injection points that took a fault in the exploration of `context`,
/// each as its state and its event, or `None` for a run with no FDR verdict.
fn injected_points(context: &HookContext) -> Option<HashSet<(String, String)>> {
	let faults = &context.verdict().fdr()?.faults_injected;
	let points = faults.iter().map(|fault| (fault.csp_state.clone(), fault.event_label.clone()));
	Some(points.collect())
}

/// The count of the faults that the exploration of `context` injected, and
/// the count of the seeds that it completed.
fn faults_and_seeds(context: &HookContext) -> Option<(usize, usize)> {
	let verdict = context.verdict().fdr()?;
	let seeds = usize::try_from(verdict.seeds_completed).ok()?;
	Some((verdict.faults_injected.len(), seeds))
}

/// The configuration that grades `spec`, explores the FDR configuration that
/// `fdr` builds over [`FaultTolerantProcess`], and runs `hooks`.
fn fault_config(
	spec: &'static BuiltAssertSpec,
	fdr: fn(Process) -> FdrConfig,
	hooks: TestHooks,
) -> Result<ScenarioConfig, Box<dyn Error>> {
	let fdr = fdr(FaultTolerantProcess::process()?);
	let builder = ScenarioConfig::builder().with_spec(spec).with_fdr(fdr);
	Ok(builder.with_hooks(hooks).build()?)
}

fn build_deterministic_config(process: Process) -> FdrConfig {
	let fault_model = FaultModel::from(InjectionStrategy::Deterministic).with_fault(
		States::Sending,
		RESPONSE,
		|| NetworkTimeoutError { duration_ms: 3000, attempt: 1 },
		tightbeam::bps!(10000), // 100%, so each visit injects the fault.
	);

	FdrConfig {
		seeds: 5,
		max_depth: 15,
		max_internal_run: 5,
		timeout_ms: 2000,
		specs: vec![process],
		fail_fast: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: Some(fault_model),
		#[cfg(feature = "testing-fmea")]
		fmea_config: None,
	}
}

tb_scenario! {
	name: test_deterministic_fault_injection,
	config: fault_config(DeterministicSpec::latest(), build_deterministic_config, TestHooks::on_pass(|context| {
			// Each injection hits the one configured state and event.
			let configured = HashSet::from([(state_key("Sending"), RESPONSE.to_string())]);
			assert_eq!(injected_points(context), Some(configured));

			// A fault at 100% fires on each visit, so each seed injects at
			// least one. A seed explores more than one path, so it can inject
			// more, and the count is the same on every run.
			let counts = faults_and_seeds(context);
			assert!(matches!(counts, Some((faults, seeds)) if seeds > 0 && faults >= seeds), "{counts:?}");
		})),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(REQUEST)?;
			trace.event(RESPONSE)?;
			trace.event(SUCCESS)?;
			Ok(())
		}
	}
}

// TEST 2: Probabilistic fault injection, an industry test of a real fault rate.

tb_assert_spec! {
	pub ProbabilisticSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REQUEST, at_least!(1))
		]
	}
}

fn build_probabilistic_config(process: Process) -> FdrConfig {
	// The fault models a network timeout at a real-world rate. A distributed
	// system times out on about 1% to 5% of requests, and AWS S3, for scale,
	// states a durability of 99.999999999% (11 nines).
	let fault_model = FaultModel::from(InjectionStrategy::Random).with_fault(
		States::Sending,
		RESPONSE,
		|| NetworkTimeoutError { duration_ms: 5000, attempt: 1 },
		tightbeam::bps!(500), // 5%, the top of the network timeout range.
	);

	FdrConfig {
		seeds: 100, // Enough seeds for a statistically significant count.
		max_depth: 15,
		max_internal_run: 5,
		timeout_ms: 5000,
		specs: vec![process],
		fail_fast: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: Some(fault_model),
		#[cfg(feature = "testing-fmea")]
		fmea_config: None,
	}
}

tb_scenario! {
	name: test_probabilistic_fault_injection,
	config: fault_config(ProbabilisticSpec::latest(), build_probabilistic_config, TestHooks::on_pass(|context| {
				// At 5% over 100 seeds, the run expects about 5 faults, and
				// the central 95% interval of Bin(100, 0.05) is 1 to 10. A
				// seed can inject more than one fault, so the interval is a
				// guide and not an exact bound. The seeded generator gives
				// the same count on every run.
				let counts = faults_and_seeds(context);
				assert!(matches!(counts, Some((1..=10, _))), "{counts:?}");
			})),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(REQUEST)?;
			trace.event(RESPONSE)?;
			trace.event(SUCCESS)?;
			Ok(())
		}
	}
}

// TEST 3: Multi-fault injection, a research test of fault combinations.

tb_assert_spec! {
	pub MultiFaultSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REQUEST, at_least!(1))
		]
	}
}

fn build_multi_fault_config(process: Process) -> FdrConfig {
	// Three fault types at three injection points reach three error paths,
	// after the multiple fault injection campaigns of Hsueh et al. (1997).
	let fault_model = FaultModel::from(InjectionStrategy::Deterministic)
		.with_fault(
			States::Sending,
			RESPONSE,
			|| NetworkTimeoutError { duration_ms: 3000, attempt: 1 },
			tightbeam::bps!(5000), // 50%, a transient failure.
		)
		.with_fault(
			States::Sending,
			RETRY,
			|| MessageCorruptionError { corrupted_bytes: 42 },
			tightbeam::bps!(3000), // 30%, a permanent failure.
		)
		.with_fault(
			States::Retrying,
			INTERNAL_RETRY,
			|| ResourceExhaustionError { resource: "memory" },
			tightbeam::bps!(2000), // 20%, a system failure.
		);

	FdrConfig {
		seeds: 20,
		max_depth: 20,
		max_internal_run: 10,
		timeout_ms: 3000,
		specs: vec![process],
		fail_fast: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: Some(fault_model),
		#[cfg(feature = "testing-fmea")]
		fmea_config: None,
	}
}

tb_scenario! {
	name: test_multi_fault_injection,
	config: fault_config(MultiFaultSpec::latest(), build_multi_fault_config, TestHooks::on_pass(|context| {
				// Each of the three injection points takes a fault, the one at
				// the hidden retry event among them.
				let configured = HashSet::from([
					(state_key("Sending"), RESPONSE.to_string()),
					(state_key("Sending"), RETRY.to_string()),
					(state_key("Retrying"), INTERNAL_RETRY.to_string()),
				]);
				assert_eq!(injected_points(context), Some(configured));
			})),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(REQUEST)?;
			trace.event(RESPONSE)?;
			trace.event(SUCCESS)?;
			Ok(())
		}
	}
}

// TEST 4: Fault coverage analysis, an industry test of test completeness.

tightbeam::tb_assert_spec! {
	pub CoverageSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(REQUEST, exactly!(1))
		]
	}
}

fn build_coverage_config(process: Process) -> FdrConfig {
	// One fault on each of five transitions aims at full branch coverage.
	let fault_model = FaultModel::from(InjectionStrategy::Deterministic)
		.with_fault(
			States::Idle,
			REQUEST,
			|| NetworkTimeoutError { duration_ms: 100, attempt: 1 },
			tightbeam::bps!(2000),
		)
		.with_fault(
			States::Sending,
			RESPONSE,
			|| NetworkTimeoutError { duration_ms: 200, attempt: 1 },
			tightbeam::bps!(2000),
		)
		.with_fault(
			States::Sending,
			RETRY,
			|| MessageCorruptionError { corrupted_bytes: 10 },
			tightbeam::bps!(2000),
		)
		.with_fault(
			States::Retrying,
			INTERNAL_RETRY,
			|| ResourceExhaustionError { resource: "cpu" },
			tightbeam::bps!(2000),
		)
		.with_fault(
			States::Sending,
			FALLBACK,
			|| ResourceExhaustionError { resource: "disk" },
			tightbeam::bps!(2000),
		);

	FdrConfig {
		seeds: 50,
		max_depth: 25,
		max_internal_run: 10,
		timeout_ms: 5000,
		specs: vec![process],
		fail_fast: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: Some(fault_model),
		#[cfg(feature = "testing-fmea")]
		fmea_config: None,
	}
}

tb_scenario! {
	name: test_fault_coverage_analysis,
	config: fault_config(CoverageSpec::latest(), build_coverage_config, TestHooks::on_pass(|context| {
				// The coverage is the share of the five configured injection
				// points that took a fault, and a critical system calls for
				// 80% of them, four of five.
				let covered = injected_points(context).map(|points| points.len());
				assert!(matches!(covered, Some(4..=5)), "{covered:?} of 5 injection points took a fault");
			})),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(REQUEST)?;
			trace.event(RESPONSE)?;
			trace.event(SUCCESS)?;
			Ok(())
		}
	}
}
