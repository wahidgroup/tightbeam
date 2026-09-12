//! Scenario verdict and the unified scenario result
//!
//! Layer 1 grades the trace against the assertion specs, Layer 2 against the
//! CSP process, Layer 3 against the refinement model. The scenario body's own
//! result sits beside the three: a body that errored produced a trace no layer
//! should be read as having accepted.

use core::fmt::{Display, Formatter};

use crate::error::TightBeamError;
use crate::testing::config::Expect;
use crate::testing::fdr::{Decision, FdrVerdict};
use crate::testing::macros::BuiltAssertSpec;
use crate::testing::specs::{CspValidationResult, Layer, SpecViolation, Violations};
use crate::trace::ConsumedTrace;

/// Every layer order the verdict grades, from the first layer to the last.
const LAYERS: [Layer; 3] = [Layer::Assertion, Layer::Csp, Layer::Refinement];

/// What one verification layer reported about a run.
///
/// A refutation meets an expected-violation expectation. An undecided check
/// does not, which is why they are separate.
enum Reported {
	/// Found nothing to object to, or did not run.
	Accepted,
	/// Rejected the run, with the violation it found.
	Rejected(SpecViolation),
	/// Stopped before deciding, with the report that says so.
	Undecided(SpecViolation),
}

/// What each verification layer decided about one scenario.
///
/// The one decider for a scenario's pass or fail: [`ScenarioVerdict::outcome`]
/// grades every layer together, so no call site derives it again. A layer the
/// configuration did not run contributes nothing.
#[derive(Debug)]
pub struct ScenarioVerdict {
	execution: Result<(), TightBeamError>,
	layer1: Result<(), SpecViolation>,
	layer2: Option<CspValidationResult>,
	layer3: Option<FdrVerdict>,
}

impl ScenarioVerdict {
	/// Assembles a verdict from what the body and each layer produced.
	///
	/// The signature holds in every feature configuration. A layer the
	/// configuration did not run passes `None`.
	pub fn from_layers(
		execution: Result<(), TightBeamError>,
		layer1: Result<(), SpecViolation>,
		layer2: Option<CspValidationResult>,
		layer3: Option<FdrVerdict>,
	) -> Self {
		Self { execution, layer1, layer2, layer3 }
	}

	/// The Layer 1 violation, when the assertion specs rejected the trace.
	pub fn spec(&self) -> Option<&SpecViolation> {
		self.layer1.as_ref().err()
	}

	/// The Layer 2 result, when the configuration named a CSP process.
	pub fn csp(&self) -> Option<&CspValidationResult> {
		self.layer2.as_ref()
	}

	/// The Layer 3 verdict, when the configuration named an FDR model.
	pub fn fdr(&self) -> Option<&FdrVerdict> {
		self.layer3.as_ref()
	}

	/// Grades the scenario against what it expected.
	///
	/// [`Expect::Pass`] holds when the body returned and every layer accepted.
	/// [`Expect::Violation`] holds when the named layer rejects and every
	/// other accepts, so a negative test fails both on a missing rejection and
	/// on one from a different layer. A layer that could not decide meets no
	/// expectation and is reported whatever the scenario expected.
	///
	/// # Errors
	///
	/// - [`Violations`] -- every rejection the grading found, in layer order.
	pub fn outcome(&self, expect: Expect) -> Result<(), Violations> {
		let mut found = Vec::new();

		if let Err(error) = self.execution.as_ref() {
			found.push(SpecViolation::ExecutionFailed(format!("{error:?}")));
		}

		for layer in LAYERS {
			match self.reported(layer) {
				Reported::Accepted => {
					if expect.names(layer) {
						found.push(SpecViolation::ExpectationUnmet(layer));
					}
				}
				Reported::Rejected(violation) => {
					if !expect.names(layer) {
						found.push(violation);
					}
				}
				Reported::Undecided(violation) => found.push(violation),
			}
		}

		let rejected = Violations::collected(found);
		match rejected {
			Some(violations) => Err(violations),
			None => Ok(()),
		}
	}

	/// What `layer` reported. A layer that did not run accepts.
	fn reported(&self, layer: Layer) -> Reported {
		match layer {
			Layer::Assertion => match self.layer1.as_ref().err() {
				Some(violation) => Reported::Rejected(violation.clone()),
				None => Reported::Accepted,
			},
			Layer::Csp => {
				let Some(result) = self.layer2.as_ref() else {
					return Reported::Accepted;
				};

				if result.valid {
					return Reported::Accepted;
				}

				Reported::Rejected(SpecViolation::CspProcessViolation(result.violations.clone()))
			}
			Layer::Refinement => {
				let Some(verdict) = self.layer3.as_ref() else {
					return Reported::Accepted;
				};

				match verdict.outcome() {
					Decision::Holds | Decision::NotAsserted => Reported::Accepted,
					Decision::Refuted => Reported::Rejected(SpecViolation::RefinementViolation),
					Decision::Unknown => Reported::Undecided(SpecViolation::RefinementInconclusive),
				}
			}
		}
	}
}

impl Default for ScenarioVerdict {
	fn default() -> Self {
		Self { execution: Ok(()), layer1: Ok(()), layer2: None, layer3: None }
	}
}

/// A finished scenario: its trace, the specs it was graded against, and the
/// [`ScenarioVerdict`] every layer contributed to.
#[derive(Debug)]
pub struct ScenarioResult {
	trace: ConsumedTrace,
	assert_spec: Option<BuiltAssertSpec>,
	assert_specs: Vec<BuiltAssertSpec>,
	verdict: ScenarioVerdict,
}

impl ScenarioResult {
	/// Create a scenario result from Layer 1 (spec) verification only
	pub fn from_spec_result(result: Result<(), SpecViolation>) -> Self {
		Self {
			trace: ConsumedTrace::new(),
			assert_spec: None,
			assert_specs: Vec::new(),
			verdict: ScenarioVerdict::from_layers(Ok(()), result, None, None),
		}
	}

	/// The full execution trace the scenario recorded.
	pub fn trace(&self) -> &ConsumedTrace {
		&self.trace
	}

	/// The single assertion spec, for the `single_spec` variant.
	pub fn assert_spec(&self) -> Option<&BuiltAssertSpec> {
		self.assert_spec.as_ref()
	}

	/// Every assertion spec, for the `multi_specs` variant.
	pub fn assert_specs(&self) -> &[BuiltAssertSpec] {
		&self.assert_specs
	}

	/// What each verification layer decided.
	pub fn verdict(&self) -> &ScenarioVerdict {
		&self.verdict
	}

	/// Whether every layer accepted the run.
	///
	/// Derived on each read, so a result cannot report a pass its layers do
	/// not support.
	pub fn passed(&self) -> bool {
		let outcome = self.verdict.outcome(Expect::Pass);
		outcome.is_ok()
	}
}

impl Default for ScenarioResult {
	fn default() -> Self {
		Self {
			trace: ConsumedTrace::new(),
			assert_spec: None,
			assert_specs: Vec::new(),
			verdict: ScenarioVerdict::default(),
		}
	}
}

impl Display for ScenarioResult {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		let outcome = self.verdict.outcome(Expect::Pass);
		match outcome {
			Ok(()) => write!(f, "Verification passed"),
			Err(violations) => write!(f, "Verification failed: {violations}"),
		}
	}
}
