//! The verdict of each verification layer, and the result of a finished
//! scenario.
//!
//! Layer 1 grades the trace and the body's own result against the assertion
//! specs, Layer 2 grades the trace against the CSP process, and Layer 3 grades
//! it against the refinement model.

use core::fmt::{Display, Formatter};

use crate::testing::config::Expect;
use crate::testing::fdr::{Decision, FdrVerdict};
use crate::testing::macros::BuiltAssertSpec;
use crate::testing::specs::{CspValidationResult, Layer, SpecViolation, Violations};
use crate::trace::ConsumedTrace;

/// What one verification layer reported about a run.
///
/// A refutation meets an expected-violation expectation and an undecided
/// check does not, so the two are separate variants.
enum Reported {
	/// The layer accepted the run, or the configuration skipped the layer.
	Accepted,
	/// The layer rejected the run, with the violation it found.
	Rejected(SpecViolation),
	/// The layer stopped before it decided, with the report that says so.
	Undecided(SpecViolation),
}

/// What each verification layer decided about one scenario.
///
/// [`ScenarioVerdict::outcome`] is the one decider of a scenario's pass or
/// fail. It grades every layer together, so every call site reads the same
/// answer. A layer that the configuration skipped counts as accepted.
#[derive(Debug)]
pub struct ScenarioVerdict {
	layer1: Result<(), SpecViolation>,
	layer2: Option<CspValidationResult>,
	/// The Layer 3 verdict with its exploration, in a box, so a verdict with
	/// no Layer 3 stays small.
	layer3: Option<Box<Layer3>>,
}

/// What Layer 3 decided, and the events that its exploration recorded into a
/// trace of its own.
#[derive(Debug)]
pub(crate) struct Layer3 {
	/// What the FDR model decided.
	verdict: FdrVerdict,
	/// The events that the exploration recorded, apart from the trace of the
	/// run.
	exploration: ConsumedTrace,
}

impl Layer3 {
	/// Pairs the verdict of Layer 3 with the events that its exploration
	/// recorded.
	pub(crate) fn new(verdict: FdrVerdict, exploration: ConsumedTrace) -> Self {
		Self { verdict, exploration }
	}
}

impl ScenarioVerdict {
	/// Assembles a verdict from what each layer produced.
	///
	/// The signature holds in every feature configuration. The caller passes
	/// `None` for a layer that the configuration skipped, and a Layer 3 verdict
	/// from here carries an empty exploration.
	pub fn from_layers(
		layer1: Result<(), SpecViolation>,
		layer2: Option<CspValidationResult>,
		layer3: Option<FdrVerdict>,
	) -> Self {
		let unexplored = |verdict| Layer3::new(verdict, ConsumedTrace::new());
		Self::explored(layer1, layer2, layer3.map(unexplored))
	}

	/// Assembles a verdict from what each layer produced, where Layer 3 also
	/// carries the events that its exploration recorded.
	pub(crate) fn explored(
		layer1: Result<(), SpecViolation>,
		layer2: Option<CspValidationResult>,
		layer3: Option<Layer3>,
	) -> Self {
		Self { layer1, layer2, layer3: layer3.map(Box::new) }
	}

	/// The Layer 1 violation, when Layer 1 rejected the trace or the body's own
	/// result.
	pub fn spec(&self) -> Option<&SpecViolation> {
		self.layer1.as_ref().err()
	}

	/// The Layer 2 result, when the configuration named a CSP process.
	pub fn csp(&self) -> Option<&CspValidationResult> {
		self.layer2.as_ref()
	}

	/// The Layer 3 verdict, when the configuration named an FDR model.
	pub fn fdr(&self) -> Option<&FdrVerdict> {
		let layer3 = self.layer3.as_deref();
		layer3.map(|layer3| &layer3.verdict)
	}

	/// The exploration events of Layer 3, when the configuration named an FDR
	/// model.
	///
	/// - A trace of their own holds the events, apart from the trace of the run.
	/// - The scenario's trace sets the instrumentation settings, and
	///   `FdrExplorer::explore_into` records the events they ask for.
	/// - The `overflowed` field of the trace reads `true` when its sink dropped events.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events::ENABLED_SET_SAMPLE;
	/// use tightbeam::instrumentation::TbInstrumentationConfig;
	/// use tightbeam::testing::fdr::FdrConfig;
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::ScenarioConfig;
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
	/// let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));
	/// let builder = ScenarioConfig::builder().with_csp(process).with_fdr(FdrConfig::default());
	/// let config = builder.with_trace(trace).build()?;
	///
	/// let verdict = config.verify(&ConsumedTrace::new(), Ok(()))?;
	/// let exploration = verdict.exploration();
	/// let samples = exploration.map(|exploration| exploration.count_event_urn(ENABLED_SET_SAMPLE));
	/// assert_eq!(samples, Some(2));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn exploration(&self) -> Option<&ConsumedTrace> {
		let layer3 = self.layer3.as_deref();
		layer3.map(|layer3| &layer3.exploration)
	}

	/// Grades the scenario against what it expected.
	///
	/// [`Expect::Pass`] holds when every layer accepted.
	/// [`Expect::Violation`] holds when the named layer rejects and every other
	/// accepts, so a negative test fails both on a missing rejection and on one
	/// from a different layer. A layer that could not decide meets no
	/// expectation, and the grading reports it whatever the scenario expected.
	///
	/// # Errors
	///
	/// - [`Violations`] -- every rejection the grading found, in layer order.
	pub fn outcome(&self, expect: Expect) -> Result<(), Violations> {
		let mut found = Vec::new();

		for layer in Layer::ALL {
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

	/// What `layer` reported. A layer that the configuration skipped accepts.
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
				let Some(verdict) = self.fdr() else {
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
		Self { layer1: Ok(()), layer2: None, layer3: None }
	}
}

/// A finished scenario: its trace, the assertion specs that graded it, and the
/// [`ScenarioVerdict`] that every layer contributed to.
#[derive(Debug)]
pub struct ScenarioResult {
	trace: ConsumedTrace,
	assert_spec: Option<BuiltAssertSpec>,
	assert_specs: Vec<BuiltAssertSpec>,
	verdict: ScenarioVerdict,
	expect: Expect,
}

impl ScenarioResult {
	/// Builds a scenario result from the Layer 1 result alone.
	pub fn from_spec_result(result: Result<(), SpecViolation>) -> Self {
		Self {
			trace: ConsumedTrace::new(),
			assert_spec: None,
			assert_specs: Vec::new(),
			verdict: ScenarioVerdict::from_layers(result, None, None),
			expect: Expect::Pass,
		}
	}

	/// The full execution trace the scenario recorded.
	pub fn trace(&self) -> &ConsumedTrace {
		&self.trace
	}

	/// The single assertion spec of the result, when it holds one.
	pub fn assert_spec(&self) -> Option<&BuiltAssertSpec> {
		self.assert_spec.as_ref()
	}

	/// Every assertion spec that the result holds.
	pub fn assert_specs(&self) -> &[BuiltAssertSpec] {
		&self.assert_specs
	}

	/// What each verification layer decided.
	pub fn verdict(&self) -> &ScenarioVerdict {
		&self.verdict
	}

	/// Whether the run decided what the scenario expected.
	///
	/// The result derives the answer on each read, so it reports a pass only
	/// when its layers support one.
	pub fn passed(&self) -> bool {
		self.outcome().is_ok()
	}

	/// What the run decided, measured against what the scenario expected.
	pub fn outcome(&self) -> Result<(), Violations> {
		self.verdict.outcome(self.expect)
	}
}

impl Default for ScenarioResult {
	fn default() -> Self {
		Self {
			trace: ConsumedTrace::new(),
			assert_spec: None,
			assert_specs: Vec::new(),
			verdict: ScenarioVerdict::default(),
			expect: Expect::Pass,
		}
	}
}

impl Display for ScenarioResult {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		match self.outcome() {
			Ok(()) => write!(f, "Verification passed"),
			Err(violations) => write!(f, "Verification failed: {violations}"),
		}
	}
}
