//! The configuration that a `tb_scenario!` test runs.
//!
//! The builder takes owned values and `build()` wraps them in `Arc`, so the
//! macro and the servlets share each value through a reference count.

#[cfg(all(not(feature = "std"), feature = "testing-csp"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::{sync::Arc, vec::Vec};

use crate::error::TightBeamError;
use crate::testing::macros::{BuiltAssertSpec, TraceCollector};
use crate::testing::result::{Layer3, ScenarioResult, ScenarioVerdict};
use crate::testing::specs::{CspValidationResult, Layer, SpecViolation, TBSpec, Violations};
use crate::trace::ConsumedTrace;
use crate::Errorizable;

#[cfg(feature = "testing-fdr")]
use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig, FdrVerdict};
#[cfg(feature = "testing-csp")]
use crate::testing::specs::composition::CompositionError;
#[cfg(feature = "testing-csp")]
use crate::testing::specs::csp::{Process, ProcessSpec};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::TimingConstraints;

/// What a scenario expects its verification layers to decide.
///
/// A negative test names the one layer it expects to reject the run, so the
/// grading checks which layer rejected it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Expect {
	/// Every configured layer accepts the run.
	#[default]
	Pass,
	/// The named layer rejects the run, and every other layer accepts it.
	Violation(Layer),
}

impl Expect {
	/// Whether `layer` is the one that must reject the run.
	pub(crate) fn names(self, layer: Layer) -> bool {
		matches!(self, Self::Violation(expected) if expected == layer)
	}
}

/// Why [`ScenarioConfigBuilder::build`] or [`ScenarioConfig::guided_by`]
/// refused a configuration.
#[derive(Clone, Debug, Eq, PartialEq, Errorizable)]
pub enum ScenarioConfigError {
	/// Nothing this configuration names can reject a run.
	#[error("no configured verifier can reject a run, so the scenario cannot fail")]
	NoEffectiveVerifier,

	/// The expectation names a layer that cannot reject this configuration.
	#[error("expected a violation from {0:?}, which cannot reject this configuration")]
	ExpectViolationWithoutVerifier(Layer),

	/// A guided fuzz run names its CSP process in `csp:`, and its
	/// configuration names a process too.
	#[error("a guided fuzz run names its CSP process in csp: alone, and this configuration names one too")]
	CspNamedTwice,

	/// The CSP spec of Layer 2 has a process that does not build, or a
	/// property that it claims fails its check.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::composition::{CompositionError, CompositionProperty};
	/// use tightbeam::testing::{ScenarioConfig, ScenarioConfigError};
	/// use tightbeam::urn::Urn;
	/// use tightbeam::{tb_compose_spec, tb_process_spec};
	///
	/// const PING: Urn<'static> = tightbeam::urn!("doc", "event:refused/ping");
	/// const PONG: Urn<'static> = tightbeam::urn!("doc", "event:refused/pong");
	///
	/// tb_process_spec! {
	///     pub Pings,
	///     events { observable { PING } hidden { } }
	///     states { P0 => { PING => P1 } }
	///     terminal { P1 }
	/// }
	///
	/// tb_process_spec! {
	///     pub Pongs,
	///     events { observable { PONG } hidden { } }
	///     states { Q0 => { PONG => Q1 } }
	///     terminal { Q1 }
	/// }
	///
	/// // The interleaving reaches its terminal state on every path, so the
	/// // claim that it deadlocks is false.
	/// tb_compose_spec! {
	///     pub ClaimsADeadlock,
	///     processes: { Pings, Pongs },
	///     composition: Interleaved,
	///     properties: { deadlock_free: false }
	/// }
	///
	/// let refused = ScenarioConfig::builder().with_csp(ClaimsADeadlock).build();
	/// let holds = CompositionError::PropertyHolds { property: CompositionProperty::DeadlockFree };
	/// assert_eq!(refused.err(), Some(ScenarioConfigError::CspRefused(holds)));
	/// ```
	#[cfg(feature = "testing-csp")]
	#[error("the CSP spec of Layer 2 is refused: {0}")]
	CspRefused(CompositionError),
}

/// The CSP spec of Layer 2, beside the process that it built.
///
/// [`Self::of`] builds the process and checks the spec's claims once, so each
/// grade reads the one process.
#[cfg(feature = "testing-csp")]
#[derive(Clone)]
struct CspLayer {
	/// The spec, which checks each trace.
	spec: Arc<dyn ProcessSpec + Send + Sync>,
	/// The process of `spec`, which the trace check and FDR exploration walk.
	process: Arc<Process>,
}

#[cfg(feature = "testing-csp")]
impl CspLayer {
	/// The layer of `spec`, whose process builds and whose claims hold.
	///
	/// # Errors
	///
	/// - The [`CompositionError`] of [`ProcessSpec::to_process_cow`] or of [`ProcessSpec::verify_claims`].
	fn of(spec: Arc<dyn ProcessSpec + Send + Sync>) -> Result<Self, CompositionError> {
		let process = Arc::new(spec.to_process_cow()?.into_owned());
		spec.verify_claims()?;
		Ok(Self { spec, process })
	}
}

/// The configuration of a `tb_scenario!` test, whose fields sit behind `Arc`
/// so a clone shares them through a reference count.
#[derive(Clone)]
pub struct ScenarioConfig {
	specs: Arc<Vec<&'static BuiltAssertSpec>>,
	trace: Arc<TraceCollector>,
	hooks: Option<Arc<TestHooks>>,
	expect: Expect,

	#[cfg(feature = "testing-csp")]
	csp: Option<CspLayer>,
	#[cfg(feature = "testing-fdr")]
	fdr: Option<Arc<FdrConfig>>,
}

impl ScenarioConfig {
	/// Starts an empty builder.
	pub fn builder() -> ScenarioConfigBuilder {
		ScenarioConfigBuilder::default()
	}

	// Each accessor below returns a borrow of its shared field. `trace` returns
	// a clone of the `Arc` instead, and `expect` returns a copy.

	pub fn specs(&self) -> &[&'static BuiltAssertSpec] {
		&self.specs
	}

	#[cfg(feature = "testing-csp")]
	pub fn csp(&self) -> Option<&Arc<dyn ProcessSpec + Send + Sync>> {
		self.csp.as_ref().map(|layer| &layer.spec)
	}

	/// The configuration of a guided fuzz run whose one CSP process is `csp`,
	/// which both steers the oracle and grades the CSP layer.
	///
	/// `tb_scenario!` calls it with the process its `csp:` key names, so a
	/// guided target names its process once. It builds the process of `csp`
	/// and checks its claims, as [`ScenarioConfigBuilder::build`] does.
	///
	/// # Errors
	///
	/// - [`ScenarioConfigError::CspNamedTwice`] -- this configuration names a process already.
	/// - [`ScenarioConfigError::CspRefused`] -- the process of `csp` does not build, or a claim of it fails.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::{ScenarioConfig, ScenarioConfigError};
	/// use tightbeam::urn::Urn;
	/// use tightbeam::{exactly, tb_assert_spec, tb_process_spec};
	///
	/// const STEP: Urn<'static> = tightbeam::urn!("doc", "event:guided/step");
	///
	/// tb_assert_spec! {
	///     pub StepSpec,
	///     V(1,0,0): {
	///         mode: Accept,
	///         assertions: [ (STEP, exactly!(1)) ]
	///     },
	/// }
	///
	/// tb_process_spec! {
	///     pub StepProc,
	///     events {
	///         observable { STEP }
	///         hidden { }
	///     }
	///     states {
	///         S0 => { STEP => S1 }
	///     }
	///     terminal { S1 }
	/// }
	///
	/// let config = ScenarioConfig::builder().with_spec(StepSpec::latest()).build()?;
	/// let guided = config.guided_by(StepProc)?;
	/// assert!(guided.csp().is_some());
	///
	/// let named_twice = guided.guided_by(StepProc);
	/// assert_eq!(named_twice.err(), Some(ScenarioConfigError::CspNamedTwice));
	/// # Ok::<(), ScenarioConfigError>(())
	/// ```
	#[cfg(feature = "testing-csp")]
	pub fn guided_by<P: ProcessSpec + Send + Sync + 'static>(mut self, csp: P) -> Result<Self, ScenarioConfigError> {
		if self.csp.is_some() {
			return Err(ScenarioConfigError::CspNamedTwice);
		}

		let layer = CspLayer::of(Arc::new(csp)).map_err(ScenarioConfigError::CspRefused)?;
		self.csp = Some(layer);
		Ok(self)
	}

	#[cfg(feature = "testing-fdr")]
	pub fn fdr(&self) -> Option<&Arc<FdrConfig>> {
		self.fdr.as_ref()
	}

	pub fn trace(&self) -> Arc<TraceCollector> {
		Arc::clone(&self.trace)
	}

	pub fn hooks(&self) -> Option<&Arc<TestHooks>> {
		self.hooks.as_ref()
	}

	/// What this scenario expects its verification layers to decide.
	pub fn expect(&self) -> Expect {
		self.expect
	}

	/// Runs every verifier this configuration carries over a finished scenario.
	///
	/// The signature holds in every feature set, so a `tb_scenario!` expansion
	/// makes one call whatever the consumer selected. Layer 3 records its
	/// exploration events into its own trace, which
	/// [`ScenarioVerdict::exploration`] returns.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that the exploration trace refused.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::FdrConfig;
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::ScenarioConfig;
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let config = ScenarioConfig::builder().with_csp(process).with_fdr(FdrConfig::default()).build()?;
	/// let verdict = config.verify(&ConsumedTrace::new(), Ok(()))?;
	/// assert!(verdict.fdr().is_some());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn verify(
		&self,
		trace: &ConsumedTrace,
		execution: Result<(), TightBeamError>,
	) -> Result<ScenarioVerdict, TightBeamError> {
		let mut layer1: Result<(), SpecViolation> = match &execution {
			Err(error) if self.specs().is_empty() => Err(SpecViolation::ExecutionFailed(format!("{error:?}"))),
			_ => Ok(()),
		};
		for spec in self.specs() {
			let verified = spec.verify(trace, &execution);
			if let Err(violation) = verified {
				layer1 = Err(violation);
				break;
			}
		}

		#[cfg(feature = "testing-csp")]
		let layer2: Option<CspValidationResult> =
			self.csp.as_ref().map(|layer| layer.spec.validate_trace(&layer.process, trace));
		#[cfg(not(feature = "testing-csp"))]
		let layer2: Option<CspValidationResult> = None;

		#[cfg(feature = "testing-fdr")]
		let layer3 = self.explore(trace)?;
		#[cfg(not(feature = "testing-fdr"))]
		let layer3: Option<Layer3> = None;

		let verdict = ScenarioVerdict::explored(layer1, layer2, layer3);
		Ok(verdict)
	}

	/// Grades the scenario against its FDR configuration, or returns `None`
	/// when it names none.
	///
	/// The verdict comes with the events exploration recorded into its own
	/// trace, apart from the events of the run. That trace takes the
	/// instrumentation settings and the clock of the scenario's trace.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that the exploration trace refused.
	#[cfg(feature = "testing-fdr")]
	fn explore(&self, trace: &ConsumedTrace) -> Result<Option<Layer3>, TightBeamError> {
		let Some(fdr_cfg) = self.fdr() else {
			return Ok(None);
		};

		let exploration = self.trace.sibling();
		let verdict = self.explore_recorded(fdr_cfg, trace, &exploration)?;
		let mut recorded = ConsumedTrace::new();
		recorded.populate_from_collector(&exploration);

		Ok(Some(Layer3::new(verdict, recorded)))
	}

	/// Grades the scenario against `fdr_cfg`, and records the exploration
	/// events into `exploration`.
	///
	/// With a CSP spec, the spec model answers deadlock and divergence freedom.
	/// When the FDR configuration also names specs, the recorded trace answers
	/// refinement against them, and the two verdicts merge. Without a CSP spec,
	/// it grades the trace alone.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that `exploration` refused.
	#[cfg(feature = "testing-fdr")]
	fn explore_recorded(
		&self,
		fdr_cfg: &Arc<FdrConfig>,
		trace: &ConsumedTrace,
		exploration: &TraceCollector,
	) -> Result<FdrVerdict, TightBeamError> {
		let Some(layer) = self.csp.as_ref() else {
			let trace_process = trace.to_process();
			let trace_cfg = Arc::clone(fdr_cfg);
			let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, trace_cfg);

			return explorer.explore_into(exploration);
		};

		let model_cfg = Arc::clone(fdr_cfg);
		let mut explorer = DefaultFdrExplorer::with_defaults(&layer.process, model_cfg);
		let verdict = explorer.explore_state_space_into(exploration)?;
		if fdr_cfg.specs.is_empty() {
			return Ok(verdict);
		}

		let trace_process = trace.to_process();
		let trace_cfg = Arc::clone(fdr_cfg);
		let mut trace_explorer = DefaultFdrExplorer::with_defaults(&trace_process, trace_cfg);
		let trace_verdict = trace_explorer.explore_into(exploration)?;

		Ok(verdict.with_refinement_from(trace_verdict))
	}

	/// The timing constraints that the first FDR spec declares, if any.
	#[cfg(all(feature = "testing-timing", feature = "testing-fdr"))]
	fn spec_timing_constraints(&self) -> Option<Arc<TimingConstraints>> {
		let fdr_cfg = self.fdr()?;
		let first_spec = fdr_cfg.specs.first()?;

		let constraints = first_spec.timing_constraints.clone()?;
		Some(Arc::new(constraints))
	}

	/// Returns `None`, because FDR specs need a build with `testing-fdr`.
	#[cfg(all(feature = "testing-timing", not(feature = "testing-fdr")))]
	fn spec_timing_constraints(&self) -> Option<Arc<TimingConstraints>> {
		None
	}
}

impl Default for ScenarioConfig {
	fn default() -> Self {
		Self {
			specs: Arc::new(Vec::new()),
			trace: Arc::new(TraceCollector::default()),
			hooks: None,
			expect: Expect::default(),
			#[cfg(feature = "testing-csp")]
			csp: None,
			#[cfg(feature = "testing-fdr")]
			fdr: None,
		}
	}
}

/// The builder of a [`ScenarioConfig`], which takes owned values and wraps
/// them in `Arc` when it builds.
#[derive(Default)]
pub struct ScenarioConfigBuilder {
	specs: Vec<&'static BuiltAssertSpec>,
	trace: TraceCollector,
	hooks: Option<TestHooks>,
	expect: Expect,

	#[cfg(feature = "testing-csp")]
	csp: Option<Box<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-fdr")]
	fdr: Option<FdrConfig>,
}

impl ScenarioConfigBuilder {
	/// Adds one spec to the list.
	pub fn with_spec(mut self, spec: &'static BuiltAssertSpec) -> Self {
		self.specs.push(spec);
		self
	}

	/// Replaces the whole spec list.
	pub fn with_specs(mut self, specs: impl IntoIterator<Item = &'static BuiltAssertSpec>) -> Self {
		self.specs = specs.into_iter().collect();
		self
	}

	/// Sets the CSP spec of Layer 2, which replaces a spec that the builder
	/// holds. [`Self::build`] checks `csp` once:
	///
	/// - It builds the process of `csp`, through [`ProcessSpec::to_process_cow`].
	/// - It checks the claims of `csp`, through [`ProcessSpec::verify_claims`].
	/// - A composition spec claims its `properties:` block and those of each operand composition.
	/// - A process that does not build, or a false claim, refuses the configuration.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::{ScenarioConfig, ScenarioConfigError};
	/// use tightbeam::urn::Urn;
	/// use tightbeam::{tb_compose_spec, tb_process_spec};
	///
	/// const STALL: Urn<'static> = tightbeam::urn!("doc", "event:compose/stall");
	/// const SEND: Urn<'static> = tightbeam::urn!("doc", "event:compose/send");
	///
	/// // `Stalls` stops in `S1`, which is not terminal.
	/// tb_process_spec! {
	///     pub Stalls,
	///     events {
	///         observable { STALL }
	///         hidden { }
	///     }
	///     states {
	///         S0 => { STALL => S1 }
	///     }
	/// }
	///
	/// tb_process_spec! {
	///     pub Sends,
	///     events {
	///         observable { SEND }
	///         hidden { }
	///     }
	///     states {
	///         T0 => { SEND => T1 }
	///     }
	///     terminal { T1 }
	/// }
	///
	/// // The interleaving claims deadlock freedom, and it deadlocks.
	/// tb_compose_spec! {
	///     pub StallsBesideSends,
	///     processes: {
	///         Stalls,
	///         Sends
	///     },
	///     composition: Interleaved,
	///     properties: {
	///         deadlock_free: true,
	///         livelock_free: true,
	///         deterministic: true
	///     }
	/// }
	///
	/// let refused = ScenarioConfig::builder().with_csp(StallsBesideSends).build();
	/// assert!(matches!(refused, Err(ScenarioConfigError::CspRefused(_))));
	/// ```
	#[cfg(feature = "testing-csp")]
	pub fn with_csp<P: ProcessSpec + Send + Sync + 'static>(mut self, csp: P) -> Self {
		self.csp = Some(Box::new(csp));
		self
	}

	#[cfg(feature = "testing-fdr")]
	pub fn with_fdr(mut self, fdr: FdrConfig) -> Self {
		self.fdr = Some(fdr);
		self
	}

	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = trace;
		self
	}

	pub fn with_hooks(mut self, hooks: TestHooks) -> Self {
		self.hooks = Some(hooks);
		self
	}

	/// Sets what the scenario expects its layers to decide. The default,
	/// [`Expect::Pass`], expects every layer to accept.
	pub fn with_expect(mut self, expect: Expect) -> Self {
		self.expect = expect;
		self
	}

	/// Whether `layer` can produce a rejection in this configuration.
	///
	/// A layer rejects only through a verifier, and the assertion layer rejects
	/// only through a spec that grades something. It is the one predicate that
	/// the effective-verifier check and the expectation check both ask.
	fn can_reject_at(&self, layer: Layer) -> bool {
		match layer {
			Layer::Assertion => self.specs.iter().any(|spec| spec.can_reject()),
			#[cfg(feature = "testing-csp")]
			Layer::Csp => self.csp.is_some(),
			#[cfg(not(feature = "testing-csp"))]
			Layer::Csp => false,
			#[cfg(feature = "testing-fdr")]
			Layer::Refinement => self.fdr.is_some(),
			#[cfg(not(feature = "testing-fdr"))]
			Layer::Refinement => false,
		}
	}

	/// Consumes the builder and wraps the collected fields in `Arc`.
	///
	/// # Errors
	///
	/// - [`ScenarioConfigError::NoEffectiveVerifier`] -- no configured layer
	///   can reject the run, so the scenario would pass whatever happened.
	/// - [`ScenarioConfigError::ExpectViolationWithoutVerifier`] -- the
	///   expectation names a layer that cannot reject this configuration, so
	///   the rejection it waits for can never arrive.
	/// - [`ScenarioConfigError::CspRefused`] -- the process of the CSP spec
	///   does not build, or a property that the spec claims fails.
	pub fn build(self) -> Result<ScenarioConfig, ScenarioConfigError> {
		if !Layer::ALL.iter().any(|layer| self.can_reject_at(*layer)) {
			return Err(ScenarioConfigError::NoEffectiveVerifier);
		}

		if let Expect::Violation(layer) = self.expect {
			if !self.can_reject_at(layer) {
				return Err(ScenarioConfigError::ExpectViolationWithoutVerifier(layer));
			}
		}

		#[cfg(feature = "testing-csp")]
		let csp = self.csp.map(|csp| CspLayer::of(Arc::from(csp))).transpose();
		#[cfg(feature = "testing-csp")]
		let csp = csp.map_err(ScenarioConfigError::CspRefused)?;

		Ok(ScenarioConfig {
			specs: Arc::new(self.specs),
			trace: Arc::new(self.trace),
			hooks: self.hooks.map(Arc::new),
			expect: self.expect,
			#[cfg(feature = "testing-csp")]
			csp,
			#[cfg(feature = "testing-fdr")]
			fdr: self.fdr.map(Arc::new),
		})
	}
}

/// What a hook observes: the recorded trace, the first assertion spec, and
/// the [`ScenarioVerdict`] that every layer contributed to.
///
/// Its fields are private, because [`HookContext::build`] grades the run once,
/// through [`ScenarioResult::graded`], and an observer only reads it.
pub struct HookContext {
	/// The graded run, with its trace, its specs, its verdict, and its
	/// expectation.
	result: ScenarioResult,
	/// The outcome of `result`, read once ([`Self::outcome`]).
	outcome: Result<(), Violations>,

	#[cfg(feature = "testing-csp")]
	process: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-timing")]
	timing_constraints: Option<Arc<TimingConstraints>>,
}

impl HookContext {
	/// Assembles the observer's view of a finished scenario.
	///
	/// [`ScenarioResult::graded`] grades the consumed trace, so the context
	/// carries the one graded run that decides the scenario.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that the exploration trace refused.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::FdrConfig;
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::testing::{HookContext, ScenarioConfig};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let config = ScenarioConfig::builder().with_csp(process).with_fdr(FdrConfig::default()).build()?;
	/// let context = HookContext::build(&config, &config.trace(), Ok(()))?;
	/// assert!(context.verdict().exploration().is_some());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn build(
		config: &ScenarioConfig,
		trace: &TraceCollector,
		execution: Result<(), TightBeamError>,
	) -> Result<Self, TightBeamError> {
		let mut consumed_trace = ConsumedTrace::new();
		consumed_trace.populate_from_collector(trace);

		let result = ScenarioResult::graded(config, consumed_trace, execution)?;
		let outcome = result.outcome();

		let context = Self {
			result,
			outcome,
			#[cfg(feature = "testing-csp")]
			process: config.csp().map(Arc::clone),
			#[cfg(feature = "testing-timing")]
			timing_constraints: config.spec_timing_constraints(),
		};

		Ok(context)
	}

	/// The first assertion spec of the configuration.
	pub fn assert_spec(&self) -> Option<&'static BuiltAssertSpec> {
		self.result.assert_spec()
	}

	/// The trace the run recorded.
	pub fn trace(&self) -> &ConsumedTrace {
		self.result.trace()
	}

	/// What each verification layer decided.
	pub fn verdict(&self) -> &ScenarioVerdict {
		self.result.verdict()
	}

	/// What the scenario decided, folded across every layer and measured
	/// against what the scenario expected.
	///
	/// [`HookContext::build`] computes it once, so the observer and the
	/// harness read the same answer.
	pub fn outcome(&self) -> Result<(), &Violations> {
		self.outcome.as_ref().map(|&()| ())
	}

	/// The CSP process that Layer 2 validated the trace against.
	#[cfg(feature = "testing-csp")]
	pub fn process(&self) -> Option<&Arc<dyn ProcessSpec + Send + Sync>> {
		self.process.as_ref()
	}

	/// The timing constraints that the first FDR spec declares.
	#[cfg(feature = "testing-timing")]
	pub fn timing_constraints(&self) -> Option<&Arc<TimingConstraints>> {
		self.timing_constraints.as_ref()
	}
}

/// Reads a scenario every layer accepted. An observer only reports, and its
/// `()` return leaves every decision to the harness.
pub type AcceptedObserver = Arc<dyn Fn(&HookContext) + Send + Sync>;

/// Reads a scenario some layer rejected, with the violations it produced.
///
/// The two observers take different arguments, so code that swaps the slots
/// fails to compile instead of leaving a hook that never runs.
pub type RejectedObserver = Arc<dyn Fn(&HookContext, &Violations) + Send + Sync>;

/// What a scenario runs after the harness grades it and before the harness
/// panics on a rejection.
#[derive(Default)]
pub struct TestHooks {
	on_pass: Option<AcceptedObserver>,
	on_fail: Option<RejectedObserver>,
}

impl TestHooks {
	/// Builds hooks that observe a scenario every layer accepted.
	pub fn on_pass(observer: impl Fn(&HookContext) + Send + Sync + 'static) -> Self {
		Self { on_pass: Some(Arc::new(observer)), on_fail: None }
	}

	/// Builds hooks that observe a scenario some layer rejected, before the
	/// harness panics.
	pub fn on_fail(observer: impl Fn(&HookContext, &Violations) + Send + Sync + 'static) -> Self {
		Self { on_pass: None, on_fail: Some(Arc::new(observer)) }
	}

	/// Adds the rejection observer to hooks that already carry an acceptance
	/// observer.
	pub fn with_on_fail(mut self, observer: impl Fn(&HookContext, &Violations) + Send + Sync + 'static) -> Self {
		self.on_fail = Some(Arc::new(observer));
		self
	}

	/// Adds the acceptance observer to hooks that already carry a rejection
	/// observer.
	pub fn with_on_pass(mut self, observer: impl Fn(&HookContext) + Send + Sync + 'static) -> Self {
		self.on_pass = Some(Arc::new(observer));
		self
	}

	/// The observer for a scenario every layer accepted.
	pub fn accepted(&self) -> Option<&AcceptedObserver> {
		self.on_pass.as_ref()
	}

	/// The observer for a scenario some layer rejected.
	pub fn rejected(&self) -> Option<&RejectedObserver> {
		self.on_fail.as_ref()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::urn::Urn;

	const STEP: Urn<'static> = crate::urn!("test", "event:config/step");

	crate::tb_assert_spec! {
		pub ErrorBodySpec,
		V(1,0,0): {
			mode: Error,
			assertions: [ (STEP, crate::exactly!(0)) ]
		},
	}

	#[test]
	fn build_refuses_zero_effective_verifiers() {
		let refused = ScenarioConfig::builder().build();
		assert_eq!(refused.err(), Some(ScenarioConfigError::NoEffectiveVerifier));
	}

	#[test]
	fn an_error_mode_spec_passes_a_body_that_errored() -> Result<(), Box<dyn core::error::Error>> {
		let config = ScenarioConfig::builder().with_spec(ErrorBodySpec::latest()).build()?;
		let verdict = config.verify(&ConsumedTrace::new(), Err(TightBeamError::RecvTimeoutError))?;
		assert_eq!(verdict.outcome(Expect::Pass), Ok(()));
		Ok(())
	}

	#[cfg(feature = "testing-csp")]
	mod with_csp {
		use core::sync::atomic::{AtomicUsize, Ordering};
		use std::borrow::Cow;

		use super::*;
		use crate::testing::specs::composition::{CompositionError, CompositionSpec, DeadlockChecker};
		use crate::testing::specs::csp::{CspValidationResult, Process, ProcessSpec, State};
		use crate::trace::ConsumedTrace;

		/// A CSP layer that accepts every trace, so the configuration runs
		/// [`Layer::Csp`].
		struct AcceptsEveryTrace;

		impl ProcessSpec for AcceptsEveryTrace {
			fn validate_trace(&self, _process: &Process, _trace: &ConsumedTrace) -> CspValidationResult {
				CspValidationResult { valid: true, violations: vec![] }
			}

			fn to_process_cow(&self) -> Result<Cow<'_, Process>, CompositionError> {
				let process = Process::builder("accepts_every_trace").initial_state(State("start")).build()?;
				Ok(Cow::Owned(process))
			}
		}

		#[test]
		fn build_refuses_expectation_with_no_producer() {
			let refused = ScenarioConfig::builder()
				.with_csp(AcceptsEveryTrace)
				.with_expect(Expect::Violation(Layer::Refinement))
				.build();

			assert_eq!(
				refused.err(),
				Some(ScenarioConfigError::ExpectViolationWithoutVerifier(Layer::Refinement))
			);
		}

		#[test]
		fn a_guided_run_takes_its_process_from_the_csp_key() -> Result<(), ScenarioConfigError> {
			let config = ScenarioConfig::builder().with_spec(ErrorBodySpec::latest()).build()?;
			let guided = config.guided_by(AcceptsEveryTrace)?;
			assert!(guided.csp().is_some());
			Ok(())
		}

		#[test]
		fn a_guided_run_refuses_a_config_that_names_a_process() -> Result<(), ScenarioConfigError> {
			let config = ScenarioConfig::builder().with_csp(AcceptsEveryTrace).build()?;
			let refused = config.guided_by(AcceptsEveryTrace);
			assert_eq!(refused.err(), Some(ScenarioConfigError::CspNamedTwice));
			Ok(())
		}

		#[test]
		fn a_body_error_with_no_spec_fails_layer1() -> Result<(), Box<dyn core::error::Error>> {
			let config = ScenarioConfig::builder().with_csp(AcceptsEveryTrace).build()?;
			let verdict = config.verify(&ConsumedTrace::new(), Err(TightBeamError::RecvTimeoutError))?;
			let expected = SpecViolation::ExecutionFailed(format!("{:?}", TightBeamError::RecvTimeoutError));
			assert_eq!(verdict.spec(), Some(&expected));
			Ok(())
		}

		const STALL: Urn<'static> = crate::urn!("test", "event:config/stall");
		const SEND: Urn<'static> = crate::urn!("test", "event:config/send");

		// A process that stalls in `S1`, which is not terminal.
		crate::tb_process_spec! {
			pub Stalls,
			events {
				observable { STALL }
				hidden { }
			}
			states {
				S0 => { STALL => S1 }
			}
		}

		crate::tb_process_spec! {
			pub Sends,
			events {
				observable { SEND }
				hidden { }
			}
			states {
				T0 => { SEND => T1 }
			}
			terminal { T1 }
		}

		/// The interleaving of [`Stalls`] and [`Sends`], which claims deadlock
		/// freedom and deadlocks once both processes take their one event. The
		/// trait is implemented by hand, as a composition spec outside the
		/// crate implements it.
		struct StallsBesideSends;

		impl CompositionSpec for StallsBesideSends {
			fn process() -> Result<Process, CompositionError> {
				Process::interleaved_parallel(&Stalls::process()?, &Sends::process()?)
			}

			fn verify_properties() -> Result<(), CompositionError> {
				DeadlockChecker::check(&Self::process()?)?;
				Ok(())
			}
		}

		/// The count of the claim checks of [`CountsItsClaims`].
		static CLAIM_CHECKS: AtomicUsize = AtomicUsize::new(0);

		/// The interleaving of [`Sends`] with itself, whose claim check
		/// counts each run in [`CLAIM_CHECKS`] and holds.
		#[derive(Default)]
		struct CountsItsClaims;

		impl CompositionSpec for CountsItsClaims {
			fn process() -> Result<Process, CompositionError> {
				Process::interleaved_parallel(&Sends::process()?, &Sends::process()?)
			}

			fn verify_properties() -> Result<(), CompositionError> {
				CLAIM_CHECKS.fetch_add(1, Ordering::Relaxed);
				Ok(())
			}
		}

		#[test]
		fn a_scenario_decides_its_claims_once_for_every_grade() -> Result<(), Box<dyn core::error::Error>> {
			let config = ScenarioConfig::builder().with_csp(CountsItsClaims).build()?;
			config.verify(&ConsumedTrace::new(), Ok(()))?;
			config.verify(&ConsumedTrace::new(), Ok(()))?;
			assert_eq!(CLAIM_CHECKS.load(Ordering::Relaxed), 1);
			Ok(())
		}

		#[test]
		fn build_refuses_a_composition_whose_claimed_property_fails() -> Result<(), Box<dyn core::error::Error>> {
			let refused = ScenarioConfig::builder().with_csp(StallsBesideSends).build();
			let refuted = matches!(
				refused,
				Err(ScenarioConfigError::CspRefused(CompositionError::DeadlockDetected { .. }))
			);
			assert!(refuted, "{:?}", refused.err());
			Ok(())
		}

		#[test]
		fn a_guided_run_refuses_a_claim_that_fails() -> Result<(), Box<dyn core::error::Error>> {
			let config = ScenarioConfig::builder().with_spec(ErrorBodySpec::latest()).build()?;

			let refused = config.guided_by(StallsBesideSends);
			let refuted = matches!(
				refused,
				Err(ScenarioConfigError::CspRefused(CompositionError::DeadlockDetected { .. }))
			);
			assert!(refuted, "{:?}", refused.err());
			Ok(())
		}
	}

	/// A scenario records its FDR exploration into a trace of its own.
	#[cfg(all(feature = "testing-fdr", feature = "instrument"))]
	mod exploration {
		use std::sync::{Arc, Mutex, PoisonError};

		use crate::instrumentation::events::{DIVERGENCE_DETECT, ENABLED_SET_SAMPLE, REFUSAL_SNAPSHOT};
		use crate::instrumentation::{EventSink, TbEvent, TbInstrumentationConfig};
		use crate::testing::config::{Expect, HookContext, ScenarioConfig, TestHooks};
		use crate::testing::fdr::FdrConfig;
		use crate::testing::specs::csp::{Process, State};
		use crate::testing::specs::Layer;
		use crate::testing::SetupEnv;
		use crate::trace::{ConsumedTrace, TraceCollector, TraceConfig};
		use crate::urn::Urn;

		const SEND: Urn<'static> = crate::urn!("test", "event:exploration/send");
		const DONE: Urn<'static> = crate::urn!("test", "event:exploration/done");
		const SPIN: Urn<'static> = crate::urn!("test", "event:exploration/spin");

		/// The three exploration events.
		const EXPLORATION_EVENTS: [Urn<'static>; 3] = [ENABLED_SET_SAMPLE, REFUSAL_SNAPSHOT, DIVERGENCE_DETECT];

		/// Returns the settings that ask for every exploration event.
		fn every_flag() -> TbInstrumentationConfig {
			TbInstrumentationConfig {
				sample_enabled_sets: true,
				sample_refusals: true,
				divergence_heuristics: true,
				..Default::default()
			}
		}

		/// A process that sends at `S0`, and spins on the hidden `SPIN` between
		/// `S1` and `S2` until it is done, so each seed diverges at `S1`.
		fn spinning() -> Process {
			Process::builder("Spinning")
				.initial_state(State("S0"))
				.add_observable(SEND)
				.add_observable(DONE)
				.add_hidden(SPIN)
				.add_transition(State("S0"), SEND, State("S1"))
				.add_transition(State("S1"), SPIN, State("S2"))
				.add_transition(State("S2"), SPIN, State("S1"))
				.add_transition(State("S1"), DONE, State("S3"))
				.add_terminal(State("S3"))
				.build()
				.expect("the spinning process names its initial state")
		}

		/// The labels of the `urn` events in `trace`, or none for `None`.
		fn labels(trace: Option<&ConsumedTrace>, urn: Urn<'static>) -> Vec<String> {
			let events = trace.into_iter().flat_map(|trace| trace.instrument_events.iter());
			let named = events.filter(|event| event.urn == urn);
			named.filter_map(|event| event.label.clone().map(String::from)).collect()
		}

		/// The URNs a [`ReceivingSink`] received, in order.
		#[derive(Default)]
		struct Received(Mutex<Vec<Urn<'static>>>);

		impl Received {
			/// Keeps `urn` after the URNs received so far.
			fn keep(&self, urn: Urn<'static>) {
				let mut urns = self.0.lock().unwrap_or_else(PoisonError::into_inner);
				urns.push(urn);
			}

			/// The URNs received so far.
			fn urns(&self) -> Vec<Urn<'static>> {
				let urns = self.0.lock().unwrap_or_else(PoisonError::into_inner);
				urns.clone()
			}
		}

		/// A sink that keeps the URN of each event it receives.
		struct ReceivingSink(Arc<Received>);

		impl EventSink for ReceivingSink {
			fn emit(&self, event: TbEvent) {
				self.0.keep(event.urn);
			}

			fn drain(&self) -> Vec<TbEvent> {
				Vec::new()
			}

			fn overflowed(&self) -> bool {
				false
			}
		}

		crate::tb_scenario! {
			name: a_scenario_records_each_exploration_event_its_trace_asks_for,
			config: ScenarioConfig::builder()
				.with_csp(spinning())
				.with_fdr(FdrConfig::default())
				.with_trace(TraceCollector::from(TraceConfig::with_instrumentation(every_flag())))
				.with_expect(Expect::Violation(Layer::Refinement))
				.with_hooks(TestHooks::on_pass(|context| {
					let exploration = context.verdict().exploration();
					let offers = [
						"Spinning.S0: {urn:test:event:exploration/send}",
						"Spinning.S1: {urn:test:event:exploration/done}",
					];
					let refusals = ["Spinning.S0: {urn:test:event:exploration/done}"];
					let cycle = ["Spinning.S1: <urn:test:event:exploration/spin, urn:test:event:exploration/spin>"];
					assert_eq!(labels(exploration, ENABLED_SET_SAMPLE), offers);
					assert_eq!(labels(exploration, REFUSAL_SNAPSHOT), refusals);
					assert_eq!(labels(exploration, DIVERGENCE_DETECT), cycle);
				}))
				.build(),
			environment Bare {
				exec: |SetupEnv { trace, .. }| {
					trace.event(SEND)?;
					trace.event(DONE)?;
					Ok(())
				}
			}
		}

		#[test]
		fn the_trace_of_the_run_receives_no_exploration_event() -> Result<(), Box<dyn core::error::Error>> {
			let received = Arc::new(Received::default());
			let sink = ReceivingSink(Arc::clone(&received));
			let instrumented = TraceConfig::builder().with_instrumentation(every_flag());
			let settings = instrumented.with_sink(sink).build();
			let builder = ScenarioConfig::builder().with_csp(spinning()).with_fdr(FdrConfig::default());
			let config = builder.with_trace(TraceCollector::from(settings)).build()?;

			let context = HookContext::build(&config, &config.trace(), Ok(()))?;

			let urns = received.urns();
			let leaked: Vec<_> = urns.iter().filter(|urn| EXPLORATION_EVENTS.contains(urn)).collect();
			let exploration = context.verdict().exploration();
			let explored = exploration.map(|exploration| exploration.count_event_urn(DIVERGENCE_DETECT));
			assert_eq!(explored.transpose()?, Some(1), "the exploration trace holds the divergence");
			assert!(leaked.is_empty(), "the trace of the run received {leaked:?}");
			Ok(())
		}

		#[test]
		fn a_truncated_exploration_says_so() -> Result<(), Box<dyn core::error::Error>> {
			let settings = TbInstrumentationConfig { max_events: 2, ..every_flag() };
			let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));
			let builder = ScenarioConfig::builder().with_csp(spinning()).with_fdr(FdrConfig::default());
			let config = builder.with_trace(trace).build()?;

			let verdict = config.verify(&ConsumedTrace::new(), Ok(()))?;
			let complete = verdict.exploration().map(ConsumedTrace::is_complete);
			assert_eq!(complete, Some(false), "the sink holds two events");
			Ok(())
		}
	}
}
