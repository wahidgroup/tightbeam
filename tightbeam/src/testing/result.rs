//! The verdict of each verification layer, and the result of a finished
//! scenario.
//!
//! - Layer 1 grades the trace and the body's own result against the assertion specs.
//! - Layer 2 grades the trace against the CSP process.
//! - Layer 3 grades the trace against the refinement model.

use core::fmt::{Display, Formatter};

use crate::error::TightBeamError;
use crate::testing::config::{Expect, ScenarioConfig};
use crate::testing::fdr::{Decision, FdrVerdict};
use crate::testing::macros::BuiltAssertSpec;
use crate::testing::specs::{CspValidationResult, Layer, SpecViolation, Violations};
use crate::trace::ConsumedTrace;

/// What one verification layer reported about a run.
///
/// A refutation meets an expected-violation expectation, and an undecided
/// check fails every expectation, so the two are separate variants.
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
/// [`ScenarioVerdict::outcome`] alone decides whether a scenario passes. It
/// grades every layer together, so every call site reads one answer. A layer
/// that the configuration skipped counts as accepted.
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
	/// The events that the exploration recorded, apart from the run's trace.
	exploration: ConsumedTrace,
}

impl Layer3 {
	/// Pairs the Layer 3 verdict with the events that its exploration recorded.
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
	/// - The events sit in a trace of their own, apart from the trace of the run.
	/// - The instrumentation settings of the scenario's trace pick the events
	///   that `FdrExplorer::explore_into` records.
	/// - [`ConsumedTrace::is_complete`] reads `false` when the sink dropped events.
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
	/// assert_eq!(samples.transpose()?, Some(2));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn exploration(&self) -> Option<&ConsumedTrace> {
		let layer3 = self.layer3.as_deref();
		layer3.map(|layer3| &layer3.exploration)
	}

	/// Grades the scenario against what it expected.
	///
	/// [`Expect::Pass`] holds when every layer accepts.
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
	assert_specs: Vec<&'static BuiltAssertSpec>,
	verdict: ScenarioVerdict,
	expect: Expect,
}

impl ScenarioResult {
	/// Grades a finished run under `config`.
	///
	/// [`ScenarioConfig::verify`] grades `trace` and the body's own result.
	/// The result keeps the trace, the assertion specs of `config`, and the
	/// expectation of [`ScenarioResult::outcome`], so each getter answers from
	/// the one graded run.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that the exploration trace refused.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::{ScenarioConfig, ScenarioResult};
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let config = ScenarioConfig::builder().with_csp(process).build()?;
	/// let result = ScenarioResult::graded(&config, ConsumedTrace::new(), Ok(()))?;
	/// assert!(result.verdict().csp().is_some());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn graded(
		config: &ScenarioConfig,
		trace: impl Into<ConsumedTrace>,
		execution: Result<(), TightBeamError>,
	) -> Result<Self, TightBeamError> {
		let trace = trace.into();
		let verdict = config.verify(&trace, execution)?;
		let assert_specs = config.specs().to_vec();
		Ok(Self { trace, assert_specs, verdict, expect: config.expect() })
	}

	/// Builds a scenario result from the Layer 1 result alone.
	pub fn from_spec_result(result: Result<(), SpecViolation>) -> Self {
		Self {
			trace: ConsumedTrace::new(),
			assert_specs: Vec::new(),
			verdict: ScenarioVerdict::from_layers(result, None, None),
			expect: Expect::Pass,
		}
	}

	/// The full execution trace the scenario recorded.
	pub fn trace(&self) -> &ConsumedTrace {
		&self.trace
	}

	/// The first assertion spec of the configuration, when it names one.
	pub fn assert_spec(&self) -> Option<&'static BuiltAssertSpec> {
		self.assert_specs.first().copied()
	}

	/// Every assertion spec of the configuration, in the order it names them.
	pub fn assert_specs(&self) -> &[&'static BuiltAssertSpec] {
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

#[cfg(test)]
mod tests {
	use super::ScenarioVerdict;
	use crate::testing::config::Expect;
	use crate::testing::specs::{Layer, SpecViolation};

	/// The rejections, in layer order, that [`ScenarioVerdict::outcome`] finds
	/// in `verdict` under `expect`.
	fn rejections(verdict: &ScenarioVerdict, expect: Expect) -> Vec<SpecViolation> {
		let outcome = verdict.outcome(expect);
		let found = outcome.err().map(|violations| violations.iter().cloned().collect());
		found.unwrap_or_default()
	}

	// A rejection from the assertion layer passes a scenario that expects it,
	// and fails with an unmet expectation a scenario that names another layer.
	crate::tb_cases! {
		fn an_assertion_rejection_leaves((expect, rejected): (Expect, Vec<SpecViolation>)) {
			let verdict = ScenarioVerdict::from_layers(Err(SpecViolation::ResponseValidationFailed), None, None);
			let found = rejections(&verdict, expect);
			assert_eq!(found, rejected);
		}

		cases {
			no_rejection_when_the_scenario_expects_it => (Expect::Violation(Layer::Assertion), Vec::new()),
			itself_and_an_unmet_expectation_when_the_scenario_names_another_layer => (
				Expect::Violation(Layer::Csp),
				vec![SpecViolation::ResponseValidationFailed, SpecViolation::ExpectationUnmet(Layer::Csp)],
			),
		}
	}

	/// A result that [`ScenarioResult::graded`] builds answers from the
	/// configuration that graded it.
	mod graded {
		use crate::testing::config::{Expect, ScenarioConfig};
		use crate::testing::macros::BuiltAssertSpec;
		use crate::testing::result::ScenarioResult;
		use crate::testing::specs::Layer;
		use crate::testing::TestResult;
		use crate::trace::ConsumedTrace;
		use crate::urn::Urn;

		const STEP: Urn<'static> = crate::urn!("test", "event:result/step");
		const REPLY: Urn<'static> = crate::urn!("test", "event:result/reply");

		crate::tb_assert_spec! {
			pub StepSpec,
			V(1,0,0): {
				mode: Accept,
				assertions: [ (STEP, crate::exactly!(1)) ]
			},
		}

		crate::tb_assert_spec! {
			pub ReplySpec,
			V(1,0,0): {
				mode: Accept,
				assertions: [ (REPLY, crate::exactly!(1)) ]
			},
		}

		/// The address of each spec, so two lists compare by identity.
		fn addresses<'a>(specs: impl IntoIterator<Item = &'a &'static BuiltAssertSpec>) -> Vec<*const BuiltAssertSpec> {
			specs.into_iter().map(|spec| core::ptr::from_ref(*spec)).collect()
		}

		/// A graded result names the first spec of its configuration as its
		/// assertion spec.
		#[test]
		fn a_graded_result_names_the_first_spec_of_its_configuration() -> TestResult {
			let specs = [StepSpec::latest(), ReplySpec::latest()];
			let config = ScenarioConfig::builder().with_specs(specs).build()?;

			let result = ScenarioResult::graded(&config, ConsumedTrace::new(), Ok(()))?;
			let first = result.assert_spec().map(core::ptr::from_ref);
			assert_eq!(first, Some(core::ptr::from_ref(StepSpec::latest())));
			Ok(())
		}

		/// A graded result holds every spec of its configuration, in order.
		#[test]
		fn a_graded_result_holds_every_spec_of_its_configuration() -> TestResult {
			let specs = [StepSpec::latest(), ReplySpec::latest()];
			let config = ScenarioConfig::builder().with_specs(specs).build()?;

			let result = ScenarioResult::graded(&config, ConsumedTrace::new(), Ok(()))?;
			assert_eq!(addresses(result.assert_specs()), addresses(&specs));
			Ok(())
		}

		/// A graded result passes when the spec rejects a trace with no step
		/// and its configuration expects an assertion rejection.
		#[test]
		fn a_graded_result_meets_the_expectation_of_its_configuration() -> TestResult {
			let expect = Expect::Violation(Layer::Assertion);
			let builder = ScenarioConfig::builder().with_spec(StepSpec::latest());
			let config = builder.with_expect(expect).build()?;

			let result = ScenarioResult::graded(&config, ConsumedTrace::new(), Ok(()))?;
			assert_eq!(result.outcome(), Ok(()));
			Ok(())
		}
	}
}
