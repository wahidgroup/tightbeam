//! The tests of the one decider for a scenario's pass or fail.
//!
//! Every layer reports into [`ScenarioVerdict`], and `outcome` grades what
//! they reported against what the scenario expected. These tests drive that
//! grading directly, one layer at a time, so a layer that stops reaching the
//! decision fails here rather than leaving a scenario green.

use tightbeam::tb_cases;
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

// The verdict grades what the layers reported against what the scenario
// expected, and rejects the run with each violation in layer order.
tb_cases! {
	fn the_verdict_rejects(
		(layer2, layer3, expect, rejected): (
			Option<CspValidationResult>,
			Option<FdrVerdict>,
			Expect,
			Vec<SpecViolation>,
		)
	) {
		let verdict = ScenarioVerdict::from_layers(Ok(()), layer2, layer3);

		let found = rejections(&verdict, expect);
		assert_eq!(found, rejected);
	}
	cases {
		/// Every layer accepted the run, so the scenario passes.
		nothing_when_every_layer_accepts => (
			Some(CspValidationResult { valid: true, violations: Vec::new() }),
			Some(FdrVerdict::default()),
			Expect::Pass,
			vec![],
		),
		/// Layer 2 rejected the trace, so the scenario fails on the violations
		/// of Layer 2.
		a_layer2_violation => (
			Some(refused_csp()),
			None,
			Expect::Pass,
			vec![SpecViolation::CspProcessViolation(refused_csp().violations)],
		),
		/// Layer 3 rejected the exploration, so the scenario fails on it.
		a_layer3_violation => (None, Some(refused_fdr()), Expect::Pass, vec![SpecViolation::RefinementViolation]),
		/// Layer 3 rejected the run that the scenario expected it to reject, so
		/// the scenario passes.
		nothing_when_the_violation_was_expected => (
			None,
			Some(refused_fdr()),
			Expect::Violation(Layer::Refinement),
			vec![],
		),
		/// Layer 3 accepted a run that the scenario expected it to reject.
		an_unmet_expectation => (
			None,
			Some(FdrVerdict::default()),
			Expect::Violation(Layer::Refinement),
			vec![SpecViolation::ExpectationUnmet(Layer::Refinement)],
		),
		/// An exploration of Layer 3 that never concluded is reported as
		/// inconclusive.
		an_undecided_layer3_as_inconclusive => (
			None,
			Some(undecided_fdr()),
			Expect::Pass,
			vec![SpecViolation::RefinementInconclusive],
		),
		/// An undecided Layer 3 leaves an expected violation of Layer 3 unmet
		/// and is reported as inconclusive.
		an_undecided_layer3_under_an_expected_violation => (
			None,
			Some(undecided_fdr()),
			Expect::Violation(Layer::Refinement),
			vec![SpecViolation::RefinementInconclusive],
		),
	}
}

// A result passes when its verdict accepts the run.
tb_cases! {
	fn a_result_passes_as_its_verdict((spec_result, passed): (Result<(), SpecViolation>, bool)) {
		let result = ScenarioResult::from_spec_result(spec_result);
		assert_eq!(result.passed(), passed);
	}
	cases {
		/// Layer 1 rejected the trace, so the result fails.
		refused => (Err(SpecViolation::ResponseValidationFailed), false),
		/// Every layer accepted the run, so the result passes.
		accepted => (Ok(()), true),
	}
}
