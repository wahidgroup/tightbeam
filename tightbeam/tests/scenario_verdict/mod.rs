//! The one decider for a scenario's pass or fail
//!
//! Every layer reports into [`ScenarioVerdict`], and `outcome` grades what
//! they reported against what the scenario expected. These tests drive that
//! grading directly, one layer at a time, so a layer that stops reaching the
//! decision fails here rather than leaving a scenario green.

use tightbeam::error::TightBeamError;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::fdr::{Decision, FdrVerdict};
use tightbeam::testing::specs::{CspValidationResult, CspViolation, Event, State};
use tightbeam::testing::{Expect, Layer, ScenarioResult, ScenarioVerdict, SpecViolation};

/// A Layer 2 result that rejected the trace.
fn refused_csp() -> CspValidationResult {
	CspValidationResult {
		valid: false,
		violations: vec![CspViolation::Deadlock { event: Event("verdict/probe"), state: State("s0") }],
	}
}

/// A Layer 3 verdict that rejected the exploration.
fn refused_fdr() -> FdrVerdict {
	FdrVerdict { trace_refines: Decision::Refuted, ..Default::default() }
}

/// A Layer 3 verdict whose exploration never concluded.
fn undecided_fdr() -> FdrVerdict {
	FdrVerdict { trace_refines: Decision::Unknown, ..Default::default() }
}

/// The rejections `expect` grading produced, in layer order.
fn rejections(verdict: &ScenarioVerdict, expect: Expect) -> Vec<SpecViolation> {
	match verdict.outcome(expect) {
		Ok(()) => Vec::new(),
		Err(violations) => violations.iter().cloned().collect(),
	}
}

#[test]
fn every_layer_accepting_passes_the_scenario() {
	let accepted_csp = CspValidationResult { valid: true, violations: Vec::new() };
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), Some(accepted_csp), Some(FdrVerdict::default()));

	let found = rejections(&verdict, Expect::Pass);

	assert!(found.is_empty(), "every layer accepted the run: {found:?}");
}

#[test]
fn layer2_violation_fails_the_scenario() {
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), Some(refused_csp()), None);
	let found = rejections(&verdict, Expect::Pass);
	assert!(
		matches!(found.as_slice(), [SpecViolation::CspProcessViolation(_)]),
		"Layer 2 rejected the trace, so the scenario fails on it: {found:?}"
	);
}

#[test]
fn layer3_violation_fails_the_scenario() {
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), None, Some(refused_fdr()));
	let found = rejections(&verdict, Expect::Pass);
	assert!(
		matches!(found.as_slice(), [SpecViolation::RefinementViolation]),
		"Layer 3 rejected the exploration, so the scenario fails on it: {found:?}"
	);
}

#[test]
fn execution_failure_fails_the_scenario() {
	let failed = Err(TightBeamError::TestingError(TestingError::InvalidTimingConstraint));
	let verdict = ScenarioVerdict::from_layers(failed, Ok(()), None, None);
	let found = rejections(&verdict, Expect::Pass);
	assert!(
		matches!(found.as_slice(), [SpecViolation::ExecutionFailed(_)]),
		"the scenario body returned an error, so the scenario fails on it: {found:?}"
	);
}

#[test]
fn an_expected_violation_passes_the_scenario() {
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), None, Some(refused_fdr()));
	let found = rejections(&verdict, Expect::Violation(Layer::Refinement));
	assert!(
		found.is_empty(),
		"Layer 3 rejected the run the scenario expected it to reject: {found:?}"
	);
}

#[test]
fn an_unmet_expectation_fails_the_scenario() {
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), None, Some(FdrVerdict::default()));
	let found = rejections(&verdict, Expect::Violation(Layer::Refinement));
	assert!(
		matches!(found.as_slice(), [SpecViolation::ExpectationUnmet(Layer::Refinement)]),
		"Layer 3 accepted a run the scenario expected it to reject: {found:?}"
	);
}

#[test]
fn a_result_derives_its_pass_from_the_verdict() {
	let refused = ScenarioResult::from_spec_result(Err(SpecViolation::ResponseValidationFailed));
	let accepted = ScenarioResult::from_spec_result(Ok(()));
	assert!(!refused.passed(), "Layer 1 rejected the trace: {refused}");
	assert!(accepted.passed(), "every layer accepted the run: {accepted}");
}

#[test]
fn an_undecided_layer3_is_reported_as_inconclusive() {
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), None, Some(undecided_fdr()));
	let found = rejections(&verdict, Expect::Pass);
	assert_eq!(found, vec![SpecViolation::RefinementInconclusive]);
}

#[test]
fn an_undecided_layer3_does_not_satisfy_an_expected_violation() {
	let verdict = ScenarioVerdict::from_layers(Ok(()), Ok(()), None, Some(undecided_fdr()));
	let found = rejections(&verdict, Expect::Violation(Layer::Refinement));
	assert_eq!(found, vec![SpecViolation::RefinementInconclusive]);
}
