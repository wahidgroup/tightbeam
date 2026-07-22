//! Unified configuration for tb_scenario! tests
//!
//! This module provides `ScenarioConf` and `ScenarioConfBuilder` for consolidating
//! test specifications, CSP processes, FDR configuration, trace collectors, and hooks.
//!
//! ## Zero-Copy Design
//!
//! - Builder accepts owned values for ergonomic API
//! - `build()` wraps all values in `Arc` for zero-copy sharing
//! - Macro and servlets use `Arc::clone()` (pointer copy only)

#![allow(unexpected_cfgs)]

#[cfg(all(not(feature = "std"), feature = "testing-csp"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::{sync::Arc, vec::Vec};

use crate::error::TightBeamError;
use crate::testing::macros::{BuiltAssertSpec, TraceCollector};
use crate::testing::specs::SpecViolation;
use crate::trace::ConsumedTrace;

#[cfg(feature = "testing-fdr")]
use crate::testing::fdr::{FdrConfig, FdrVerdict};
#[cfg(feature = "testing-csp")]
use crate::testing::specs::csp::ProcessSpec;
#[cfg(feature = "testing-timing")]
use crate::testing::timing::TimingConstraints;

/// Unified configuration for tb_scenario! tests (zero-copy with Arc wrapping)
#[derive(Clone)]
pub struct ScenarioConf {
	specs: Arc<Vec<&'static BuiltAssertSpec>>,
	trace: Arc<TraceCollector>,
	hooks: Option<Arc<TestHooks>>,

	#[cfg(feature = "testing-csp")]
	csp: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-fdr")]
	fdr: Option<Arc<FdrConfig>>,
}

impl ScenarioConf {
	/// Create a new builder
	pub fn builder() -> ScenarioConfBuilder {
		ScenarioConfBuilder::default()
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
}

impl Default for ScenarioConf {
	fn default() -> Self {
		Self {
			specs: Arc::new(Vec::new()),
			trace: Arc::new(TraceCollector::default()),
			hooks: None,
			#[cfg(feature = "testing-csp")]
			csp: None,
			#[cfg(feature = "testing-fdr")]
			fdr: None,
		}
	}
}

/// Builder for ScenarioConf (consumes owned values, wraps in Arc on build)
#[derive(Default)]
pub struct ScenarioConfBuilder {
	specs: Vec<&'static BuiltAssertSpec>,
	trace: TraceCollector,
	hooks: Option<TestHooks>,

	#[cfg(feature = "testing-csp")]
	csp: Option<Box<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-fdr")]
	fdr: Option<FdrConfig>,
}

impl ScenarioConfBuilder {
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

	/// Consumes the builder and wraps collected fields in `Arc`.
	pub fn build(self) -> ScenarioConf {
		ScenarioConf {
			specs: Arc::new(self.specs),
			trace: Arc::new(self.trace),
			hooks: self.hooks.map(Arc::new),
			#[cfg(feature = "testing-csp")]
			csp: self.csp.map(|csp| Arc::from(csp) as Arc<dyn ProcessSpec + Send + Sync>),
			#[cfg(feature = "testing-fdr")]
			fdr: self.fdr.map(Arc::new),
		}
	}
}

/// Complete scenario execution context for hooks
pub struct HookContext {
	pub assert_spec: Option<&'static BuiltAssertSpec>,
	pub trace: ConsumedTrace,

	#[cfg(feature = "testing-fdr")]
	pub fdr_verdict: Option<FdrVerdict>,
	#[cfg(feature = "testing-fdr")]
	pub fdr_config: Option<Arc<FdrConfig>>,
	#[cfg(feature = "testing-csp")]
	pub process: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-timing")]
	pub timing_constraints: Option<Arc<TimingConstraints>>,
}

impl HookContext {
	pub fn new(trace: ConsumedTrace) -> Self {
		Self {
			assert_spec: None,
			trace,
			#[cfg(feature = "testing-fdr")]
			fdr_verdict: None,
			#[cfg(feature = "testing-fdr")]
			fdr_config: None,
			#[cfg(feature = "testing-csp")]
			process: None,
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
		}
	}
}

/// Test lifecycle hooks (receive full scenario context)
pub struct TestHooks {
	#[allow(clippy::type_complexity)]
	pub on_pass: Option<Arc<dyn Fn(&HookContext) -> Result<(), TightBeamError> + Send + Sync>>,
	#[allow(clippy::type_complexity)]
	pub on_fail: Option<Arc<dyn Fn(&HookContext, &SpecViolation) -> Result<(), TightBeamError> + Send + Sync>>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn builder_collects_specs_without_hooks() {
		let config = ScenarioConf::builder().build();
		assert!(config.specs().is_empty());
		assert!(config.hooks().is_none());
	}
}
