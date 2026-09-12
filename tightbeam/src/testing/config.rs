//! Unified configuration for `tb_scenario!` tests
//!
//! The builder takes owned values and `build()` wraps them in `Arc`, so the
//! macro and the servlets share by refcount rather than by copy.

#[cfg(all(not(feature = "std"), feature = "testing-csp"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::{sync::Arc, vec::Vec};

use crate::error::TightBeamError;
use crate::testing::fdr::FdrVerdict;
use crate::testing::macros::{BuiltAssertSpec, TraceCollector};
use crate::testing::result::ScenarioVerdict;
use crate::testing::specs::{verify_trace, CspValidationResult, Layer, SpecViolation, Violations};
use crate::trace::ConsumedTrace;
use crate::transport::error::TransportError;

#[cfg(feature = "testing-fdr")]
use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
#[cfg(feature = "testing-csp")]
use crate::testing::specs::csp::ProcessSpec;
#[cfg(feature = "testing-timing")]
use crate::testing::timing::TimingConstraints;

/// What a scenario expects its verification layers to decide.
///
/// A negative test names the one layer it expects to reject the run, so the
/// expectation is graded rather than tolerated.
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

/// Unified configuration for tb_scenario! tests (zero-copy with Arc wrapping)
#[derive(Clone)]
pub struct ScenarioConfig {
	specs: Arc<Vec<&'static BuiltAssertSpec>>,
	trace: Arc<TraceCollector>,
	hooks: Option<Arc<TestHooks>>,
	expect: Expect,

	#[cfg(feature = "testing-csp")]
	csp: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-fdr")]
	fdr: Option<Arc<FdrConfig>>,
}

impl ScenarioConfig {
	/// Create a new builder
	pub fn builder() -> ScenarioConfigBuilder {
		ScenarioConfigBuilder::default()
	}

	// ===== Accessors (zero-copy) =====

	pub fn specs(&self) -> &[&'static BuiltAssertSpec] {
		&self.specs
	}

	#[cfg(feature = "testing-csp")]
	pub fn csp(&self) -> Option<&Arc<dyn ProcessSpec + Send + Sync>> {
		self.csp.as_ref()
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
	/// The signature holds in every feature configuration, so a `tb_scenario!`
	/// expansion states one call whatever the consumer selected.
	pub fn verify(&self, trace: &ConsumedTrace, execution: Result<(), TightBeamError>) -> ScenarioVerdict {
		let mut layer1: Result<(), SpecViolation> = Ok(());
		for spec in self.specs() {
			let verified = verify_trace(*spec, trace);
			if let Err(violation) = verified {
				layer1 = Err(violation);
				break;
			}
		}

		#[cfg(feature = "testing-csp")]
		let layer2: Option<CspValidationResult> = self.csp().map(|csp| ProcessSpec::validate_trace(csp.as_ref(), trace));
		#[cfg(not(feature = "testing-csp"))]
		let layer2: Option<CspValidationResult> = None;

		#[cfg(feature = "testing-fdr")]
		let layer3: Option<FdrVerdict> = self.explore(trace);
		#[cfg(not(feature = "testing-fdr"))]
		let layer3: Option<FdrVerdict> = None;

		ScenarioVerdict::from_layers(execution, layer1, layer2, layer3)
	}

	/// Grades the scenario against the refinement model the configuration names.
	///
	/// With a CSP spec, the spec model answers deadlock and divergence freedom
	/// and the recorded trace answers refinement against the FDR specs, and the
	/// two verdicts are merged. Without one, the trace is graded alone.
	#[cfg(feature = "testing-fdr")]
	fn explore(&self, trace: &ConsumedTrace) -> Option<FdrVerdict> {
		let fdr_cfg = self.fdr()?;

		let Some(csp_spec) = self.csp() else {
			let trace_process = trace.to_process();
			let trace_cfg = Arc::clone(fdr_cfg);
			let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, trace_cfg);

			return Some(explorer.explore());
		};

		// An empty spec list puts the explorer in state-space exploration mode.
		let spec_process_cow = csp_spec.to_process_cow();
		let mut exploration_cfg = (**fdr_cfg).clone();
		exploration_cfg.specs = Vec::new();

		let exploration_cfg = Arc::new(exploration_cfg);
		let mut explorer = DefaultFdrExplorer::with_defaults(&spec_process_cow, exploration_cfg);
		let verdict = explorer.explore();
		if fdr_cfg.specs.is_empty() {
			return Some(verdict);
		}

		let trace_process = trace.to_process();
		let trace_cfg = Arc::clone(fdr_cfg);
		let mut trace_explorer = DefaultFdrExplorer::with_defaults(&trace_process, trace_cfg);
		let trace_verdict = trace_explorer.explore();

		Some(verdict.with_refinement_from(trace_verdict))
	}

	/// The timing constraints the first FDR spec declares, when it declares any.
	#[cfg(all(feature = "testing-timing", feature = "testing-fdr"))]
	fn spec_timing_constraints(&self) -> Option<Arc<TimingConstraints>> {
		let fdr_cfg = self.fdr()?;
		let first_spec = fdr_cfg.specs.first()?;
		let constraints = first_spec.timing_constraints.clone()?;

		Some(Arc::new(constraints))
	}

	/// The timing constraints the first FDR spec declares, when it declares any.
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

/// Builder for ScenarioConfig (consumes owned values, wraps in Arc on build)
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
	/// Add a single spec to the list (builder convention)
	pub fn with_spec(mut self, spec: &'static BuiltAssertSpec) -> Self {
		self.specs.push(spec);
		self
	}

	/// Replace entire spec list (builder convention)
	pub fn with_specs(mut self, specs: impl IntoIterator<Item = &'static BuiltAssertSpec>) -> Self {
		self.specs = specs.into_iter().collect();
		self
	}

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

	/// What the scenario expects its layers to decide. Omitted means all pass.
	pub fn with_expect(mut self, expect: Expect) -> Self {
		self.expect = expect;
		self
	}

	/// Consumes the builder and wraps collected fields in `Arc`.
	pub fn build(self) -> ScenarioConfig {
		ScenarioConfig {
			specs: Arc::new(self.specs),
			trace: Arc::new(self.trace),
			hooks: self.hooks.map(Arc::new),
			expect: self.expect,
			#[cfg(feature = "testing-csp")]
			csp: self.csp.map(|csp| Arc::from(csp) as Arc<dyn ProcessSpec + Send + Sync>),
			#[cfg(feature = "testing-fdr")]
			fdr: self.fdr.map(Arc::new),
		}
	}
}

/// What a hook observes: the recorded trace, the spec it was graded against,
/// and the [`ScenarioVerdict`] every layer contributed to.
///
/// Fields are private because the verdict is assembled once, in
/// [`HookContext::build`], and an observer only reads it.
pub struct HookContext {
	assert_spec: Option<&'static BuiltAssertSpec>,
	trace: ConsumedTrace,
	verdict: ScenarioVerdict,

	#[cfg(feature = "testing-csp")]
	process: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-timing")]
	timing_constraints: Option<Arc<TimingConstraints>>,
}

impl HookContext {
	/// Assembles the observer's view of a finished scenario.
	///
	/// [`ScenarioConfig::verify`] grades the consumed trace, so the context
	/// carries the one verdict the scenario is decided by.
	pub fn build(config: &ScenarioConfig, trace: &TraceCollector, execution: Result<(), TightBeamError>) -> Self {
		let mut consumed_trace = ConsumedTrace::new();
		consumed_trace.populate_from_collector(trace);
		if execution.is_err() {
			consumed_trace.error = Some(TransportError::InvalidMessage);
		}

		let verdict = config.verify(&consumed_trace, execution);

		Self {
			assert_spec: config.specs().first().copied(),
			trace: consumed_trace,
			verdict,
			#[cfg(feature = "testing-csp")]
			process: config.csp().map(Arc::clone),
			#[cfg(feature = "testing-timing")]
			timing_constraints: config.spec_timing_constraints(),
		}
	}

	/// The first assertion spec the scenario was graded against.
	pub fn assert_spec(&self) -> Option<&'static BuiltAssertSpec> {
		self.assert_spec
	}

	/// The trace the run recorded.
	pub fn trace(&self) -> &ConsumedTrace {
		&self.trace
	}

	/// What each verification layer decided.
	pub fn verdict(&self) -> &ScenarioVerdict {
		&self.verdict
	}

	/// The CSP process the scenario was validated against.
	#[cfg(feature = "testing-csp")]
	pub fn process(&self) -> Option<&Arc<dyn ProcessSpec + Send + Sync>> {
		self.process.as_ref()
	}

	/// The timing constraints the scenario was verified against.
	#[cfg(feature = "testing-timing")]
	pub fn timing_constraints(&self) -> Option<&Arc<TimingConstraints>> {
		self.timing_constraints.as_ref()
	}
}

/// Test lifecycle hooks (receive full scenario context)
pub struct TestHooks {
	#[allow(clippy::type_complexity)]
	pub on_pass: Option<Arc<dyn Fn(&HookContext) -> Result<(), TightBeamError> + Send + Sync>>,
	#[allow(clippy::type_complexity)]
	pub on_fail: Option<Arc<dyn Fn(&HookContext, &Violations) -> Result<(), TightBeamError> + Send + Sync>>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn builder_collects_specs_without_hooks() {
		let config = ScenarioConfig::builder().build();
		assert!(config.specs().is_empty());
		assert!(config.hooks().is_none());
	}
}
