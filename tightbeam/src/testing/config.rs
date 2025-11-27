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

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::{boxed::Box, sync::Arc, vec::Vec};

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
pub struct ScenarioConf<E = ()> {
	specs_internal: Arc<Vec<&'static BuiltAssertSpec>>,
	trace_internal: Arc<TraceCollector>,
	hooks_internal: Option<Arc<TestHooks>>,
	env_config_internal: Option<Arc<E>>,

	#[cfg(feature = "testing-csp")]
	csp_internal: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-fdr")]
	fdr_internal: Option<Arc<FdrConfig>>,
}

impl<E> ScenarioConf<E> {
	/// Create a new builder
	pub fn builder() -> ScenarioConfBuilder<E> {
		ScenarioConfBuilder::default()
	}

	// ===== Accessors (zero-copy) =====

	pub fn specs(&self) -> &[&'static BuiltAssertSpec] {
		&self.specs_internal
	}

	#[cfg(feature = "testing-csp")]
	pub fn csp(&self) -> Option<&Arc<dyn ProcessSpec + Send + Sync>> {
		self.csp_internal.as_ref()
	}

	#[cfg(feature = "testing-fdr")]
	pub fn fdr(&self) -> Option<&Arc<FdrConfig>> {
		self.fdr_internal.as_ref()
	}

	pub fn trace(&self) -> Arc<TraceCollector> {
		Arc::clone(&self.trace_internal)
	}

	pub fn hooks(&self) -> Option<&Arc<TestHooks>> {
		self.hooks_internal.as_ref()
	}

	/// Get env_config (panics if with_env_config() was not called).
	///
	/// For E=(), the builder auto-supplies () so this never panics.
	/// For custom types, with_env_config() must be called before build().
	pub fn env_config(&self) -> &Arc<E> {
		self.env_config_internal
			.as_ref()
			.expect("env_config not set - call with_env_config() before build()")
	}
}

impl Default for ScenarioConf<()> {
	fn default() -> Self {
		Self {
			specs_internal: Arc::new(Vec::new()),
			#[cfg(feature = "testing-csp")]
			csp_internal: None,
			#[cfg(feature = "testing-fdr")]
			fdr_internal: None,
			trace_internal: Arc::new(TraceCollector::default()),
			hooks_internal: None,
			env_config_internal: Some(Arc::new(())),
		}
	}
}

/// Builder for ScenarioConf (consumes owned values, wraps in Arc on build)
pub struct ScenarioConfBuilder<E = ()> {
	specs: Vec<&'static BuiltAssertSpec>,
	trace: TraceCollector,
	hooks: Option<TestHooks>,
	env_config: Option<E>,

	#[cfg(feature = "testing-csp")]
	csp: Option<Box<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-fdr")]
	fdr: Option<FdrConfig>,
}

impl<E> Default for ScenarioConfBuilder<E> {
	fn default() -> Self {
		Self {
			specs: Vec::new(),
			#[cfg(feature = "testing-csp")]
			csp: None,
			#[cfg(feature = "testing-fdr")]
			fdr: None,
			trace: TraceCollector::default(),
			hooks: None,
			env_config: None,
		}
	}
}

impl<E> ScenarioConfBuilder<E> {
	/// Add a single spec to the list (builder convention)
	pub fn with_spec(mut self, spec: &'static BuiltAssertSpec) -> Self {
		self.specs.push(spec);
		self
	}

	/// Replace entire spec list (builder convention)
	pub fn with_specs(mut self, specs: Vec<&'static BuiltAssertSpec>) -> Self {
		self.specs = specs;
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

	pub fn with_env_config(mut self, env_config: E) -> Self {
		self.env_config = Some(env_config);
		self
	}
}

impl<E> ScenarioConfBuilder<E> {
	/// Build the final ScenarioConf (wraps all values in Arc).
	///
	/// **Note**: `env_config` is optional - call `env_config_opt()` if unsure it's set.
	/// For tests using `ScenarioConf::<()>`, env_config is rarely needed.
	pub fn build(self) -> ScenarioConf<E> {
		ScenarioConf {
			specs_internal: Arc::new(self.specs),
			#[cfg(feature = "testing-csp")]
			csp_internal: self.csp.map(|csp| Arc::from(csp) as Arc<dyn ProcessSpec + Send + Sync>),
			#[cfg(feature = "testing-fdr")]
			fdr_internal: self.fdr.map(Arc::new),
			trace_internal: Arc::new(self.trace),
			hooks_internal: self.hooks.map(Arc::new),
			env_config_internal: self.env_config.map(Arc::new),
		}
	}
}

/// Complete scenario execution context for hooks
pub struct HookContext {
	pub trace: ConsumedTrace,
	#[cfg(feature = "testing-fdr")]
	pub fdr_verdict: Option<FdrVerdict>,
	#[cfg(feature = "testing-fdr")]
	pub fdr_config: Option<Arc<FdrConfig>>,
	#[cfg(feature = "testing-csp")]
	pub process: Option<Arc<dyn ProcessSpec + Send + Sync>>,
	#[cfg(feature = "testing-timing")]
	pub timing_constraints: Option<Arc<TimingConstraints>>,
	pub assert_spec: Option<&'static BuiltAssertSpec>,
}

impl HookContext {
	pub fn new(trace: ConsumedTrace) -> Self {
		Self {
			trace,
			#[cfg(feature = "testing-fdr")]
			fdr_verdict: None,
			#[cfg(feature = "testing-fdr")]
			fdr_config: None,
			#[cfg(feature = "testing-csp")]
			process: None,
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			assert_spec: None,
		}
	}
}

/// Test lifecycle hooks (receive full scenario context)
pub struct TestHooks {
	pub on_pass: Option<Arc<dyn Fn(&HookContext) -> Result<(), TightBeamError> + Send + Sync>>,
	pub on_fail: Option<Arc<dyn Fn(&HookContext, &SpecViolation) -> Result<(), TightBeamError> + Send + Sync>>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn with_env_config_sets_value() {
		#[derive(Debug, Clone, PartialEq)]
		struct TestEnvConfig {
			value: u32,
		}

		impl Default for TestEnvConfig {
			fn default() -> Self {
				Self { value: 42 }
			}
		}

		let custom_config = TestEnvConfig { value: 123 };
		let config = ScenarioConf::builder().with_env_config(custom_config.clone()).build();
		assert_eq!(config.env_config().value, 123);
	}
}
