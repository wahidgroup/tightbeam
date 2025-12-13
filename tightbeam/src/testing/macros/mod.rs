//! Testing macro layer providing unified `tb_scenario!` macro and helpers.
//!
//! - Layer 1 (Assertions): `verification_spec`
//! - Layer 2 (CSP): `process_spec`
//! - Layer 3 (FDR): integrated via `tb_scenario!`

#![allow(unexpected_cfgs)]

// ProcessSpec macro (Layer 2 - CSP)
#[cfg(feature = "testing-csp")]
pub mod process_spec;
// CompositionSpec macro (Layer 2 - CSP Composition)
#[cfg(feature = "testing-csp")]
pub mod compose_spec;

// Gen States macro for fault injection (opt-in)
#[cfg(feature = "testing-fault")]
pub mod gen_states;

pub mod verification_spec;
pub use verification_spec::{
	absent, between, present, AssertSpecBuilder, BuiltAssertSpec, Cardinality, SpecBuildError,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// Re-exports
pub use crate::testing::assertions::{AssertionValue, IsNone, IsSome, Presence, RatioLimit};
pub use crate::trace::TraceCollector;
pub use crate::{absent, at_least, at_most, between, equals, exactly, falsy, present, truthy};

/// Helper macro to wrap values for equality assertions in specs
#[macro_export]
macro_rules! equals {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::from($value))
	};
}

/// Helper macro for boolean true assertions in specs
/// Checks that the value is truthy (non-zero, true, non-empty)
#[macro_export]
macro_rules! truthy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value != 0))
	};
}

/// Helper macro for boolean false assertions in specs
/// Checks that the value is falsy (zero, false, empty)
#[macro_export]
macro_rules! falsy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value == 0))
	};
}

/// Helper macro for ratio limits (numerator / denominator)
#[macro_export]
macro_rules! ratio {
	($numer:expr, $denom:expr) => {
		$crate::testing::assertions::RatioLimit(($numer) as u64, ($denom) as u64)
	};
}

/// Helper macro for WCET (Worst-Case Execution Time) timing constraint
/// Usage:
///   wcet!(10ms)  (simple case, backward compatible)
///   wcet!(10ms, percentile: P99)  (with percentile)
///   wcet!(10ms, analyzer: my_analyzer)  (with analyzer)
///   wcet!(10ms, percentile: P99, analyzer: my_analyzer)  (with both, order-independent)
///   wcet!(10ms, analyzer: my_analyzer, percentile: P99)  (same as above)
/// Event comes from the key in grouped syntax.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! wcet {
	// Unified builder helper - handles all combinations
	(@builder $dur:expr) => {{
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, percentile: $p:expr) => {{
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_percentile($p)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, analyzer: $a:expr) => {{
		use std::sync::Arc;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_analyzer(Arc::new($a))
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, percentile: $p:expr, analyzer: $a:expr) => {{
		use std::sync::Arc;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_percentile($p)
			.with_analyzer(Arc::new($a))
			.build()
			.expect("Failed to build WcetConfig")
	}};

	// Public API - normalize parameter order and delegate to builder
	($dur:expr) => {
		$crate::wcet!(@builder $dur)
	};
	($dur:expr, percentile: $p:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p)
	};
	($dur:expr, analyzer: $a:expr) => {
		$crate::wcet!(@builder $dur, analyzer: $a)
	};
	($dur:expr, percentile: $p:expr, analyzer: $a:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p, analyzer: $a)
	};
	($dur:expr, analyzer: $a:expr, percentile: $p:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p, analyzer: $a)
	};
}

/// Helper struct for deadline parameters (used internally by deadline! macro)
#[cfg(feature = "testing-timing")]
#[doc(hidden)]
pub struct DeadlineParams {
	pub duration: std::time::Duration,
	pub min_slack: Option<std::time::Duration>,
}

/// Helper macro for deadline timing constraint
/// Usage:
///   deadline!(duration: 100ms, slack: 5ms)  (parentheses)
///   deadline! { duration: 100ms, slack: 5ms }  (curly braces)
///   deadline!(duration: 100ms)  (without slack)
/// Events come from the key in grouped syntax.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! deadline {
	// Parentheses syntax: deadline!(duration: ..., slack: ...)
	(duration: $dur:expr, slack: $slack:expr) => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: Some($slack),
		}
	};
	(duration: $dur:expr) => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: None,
		}
	};
	// Curly braces syntax: deadline! { duration: ..., slack: ... }
	{ duration: $dur:expr, slack: $slack:expr } => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: Some($slack),
		}
	};
	{ duration: $dur:expr } => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: None,
		}
	};
}

/// Helper macro for timing guard expressions in tb_process_spec!
///
/// Usage:
///   guard!(x < 10ms)  -> ClockLessThan
///   guard!(x <= 5ms)  -> ClockLessEqual
///   guard!(x > 20ms)  -> ClockGreaterThan
///   guard!(x >= 15ms) -> ClockGreaterEqual
///   guard!(x == 10ms) -> ClockEquals
///   guard!(5ms <= x <= 10ms) -> ClockInRange
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! guard {
	// Less than: x < 10ms
	($clock:ident < $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockLessThan(stringify!($clock).to_string(), $dur)
	};
	// Less than or equal: x <= 5ms
	($clock:ident <= $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockLessEqual(stringify!($clock).to_string(), $dur)
	};
	// Greater than: x > 20ms
	($clock:ident > $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockGreaterThan(stringify!($clock).to_string(), $dur)
	};
	// Greater than or equal: x >= 15ms
	($clock:ident >= $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockGreaterEqual(stringify!($clock).to_string(), $dur)
	};
	// Equals: x == 10ms
	($clock:ident == $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockEquals(stringify!($clock).to_string(), $dur)
	};
	// Range: 5ms <= x <= 10ms
	($min_dur:tt <= $clock:ident <= $max_dur:tt) => {
		$crate::testing::timing::TimingGuard::ClockInRange(stringify!($clock).to_string(), $min_dur, $max_dur)
	};
}

/// Helper macro for jitter timing constraint
/// Usage:
///   jitter!(5ms)  (default MinMaxJitter calculator)
///   jitter!(5ms, calculator)  (custom calculator)
/// Event comes from the key in grouped syntax.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! jitter {
	($dur:expr) => {
		$crate::testing::timing::TimingConstraint::Jitter($dur, None)
	};
	($dur:expr, $calc:expr) => {{
		use std::sync::Arc;
		$crate::testing::timing::TimingConstraint::Jitter($dur, Some(Arc::new($calc)))
	}};
}

// Helper Functions for tb_scenario!

/// Helper function for exec closures (synchronous, bare/worker environments)
#[doc(hidden)]
pub fn __tb_call_exec_closure<F>(closure: F, trace: crate::trace::TraceCollector) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(crate::trace::TraceCollector) -> Result<(), crate::TightBeamError>,
{
	closure(trace)
}

/// Helper function for exec closures with Arc (multi-specs bare environment)
#[doc(hidden)]
pub fn __tb_call_exec_closure_arc<F>(
	closure: F,
	trace: std::sync::Arc<crate::trace::TraceCollector>,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(std::sync::Arc<crate::trace::TraceCollector>) -> Result<(), crate::TightBeamError>,
{
	closure(trace)
}

/// Helper function for pipeline exec closures (Pipeline environment)
/// Accepts closures that return Result<T, TightBeamError> and maps to Result<(), TightBeamError>
#[doc(hidden)]
pub fn __tb_call_pipeline_exec<F, T>(
	closure: F,
	pipeline: crate::utils::task::PipelineBuilder,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(crate::utils::task::PipelineBuilder) -> Result<T, crate::TightBeamError>,
{
	closure(pipeline).map(|_| ())
}

/// Helper function for async exec closures with Arc (multi-specs bare environment)
#[doc(hidden)]
#[cfg(feature = "tokio")]
pub async fn __tb_call_exec_closure_arc_async<F, Fut>(
	closure: F,
	trace: std::sync::Arc<crate::trace::TraceCollector>,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(std::sync::Arc<crate::trace::TraceCollector>) -> Fut,
	Fut: std::future::Future<Output = Result<(), crate::TightBeamError>>,
{
	closure(trace).await
}

/// Helper function for setup closures (worker environment)
#[doc(hidden)]
pub fn __tb_call_setup_closure<F, W>(closure: F, trace: crate::trace::TraceCollector) -> W
where
	F: FnOnce(crate::trace::TraceCollector) -> W,
{
	closure(trace)
}

/// Helper function for setup closures with fuzz input
#[doc(hidden)]
pub fn __tb_call_setup_closure_fuzz<F, W>(closure: F, trace: crate::trace::TraceCollector, fuzz_input: Vec<u8>) -> W
where
	F: FnOnce(crate::trace::TraceCollector, Vec<u8>) -> W,
{
	closure(trace, fuzz_input)
}

/// Helper function for stimulus closures (worker environment, synchronous)
#[doc(hidden)]
pub fn __tb_call_stimulus_closure<F, W>(
	closure: F,
	trace: crate::trace::TraceCollector,
	worker: &mut W,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(crate::trace::TraceCollector, &mut W) -> Result<(), crate::TightBeamError>,
{
	closure(trace, worker)
}

/// Helper function for stimulus closures with fuzz input
#[doc(hidden)]
pub fn __tb_call_stimulus_closure_fuzz<F, W>(
	closure: F,
	trace: std::sync::Arc<crate::trace::TraceCollector>,
	worker: &mut W,
	fuzz_input: Vec<u8>,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(std::sync::Arc<crate::trace::TraceCollector>, &mut W, Vec<u8>) -> Result<(), crate::TightBeamError>,
{
	closure(trace, worker, fuzz_input)
}

/// Helper function for stimulus closures (worker environment, Arc)
#[doc(hidden)]
pub fn __tb_call_stimulus_closure_arc<F, W>(
	closure: F,
	trace: std::sync::Arc<crate::trace::TraceCollector>,
	worker: &mut W,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(std::sync::Arc<crate::trace::TraceCollector>, &mut W) -> Result<(), crate::TightBeamError>,
{
	closure(trace, worker)
}

/// Helper function for client closures (async, ServiceClient environment)
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __tb_call_client_closure_async<F, Fut, T>(
	closure: F,
	trace: crate::trace::TraceCollector,
	client: T,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(crate::trace::TraceCollector, T) -> Fut,
	Fut: core::future::Future<Output = Result<(), crate::TightBeamError>>,
{
	closure(trace, client).await
}

/// Helper function for start closures (receives trace, &config, returns servlet)
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __call_start_closure<F, Fut, C, S>(
	closure: F,
	trace: std::sync::Arc<crate::trace::TraceCollector>,
	config: std::sync::Arc<C>,
) -> Result<S, crate::TightBeamError>
where
	F: FnOnce(std::sync::Arc<crate::trace::TraceCollector>, std::sync::Arc<C>) -> Fut,
	Fut: core::future::Future<Output = Result<S, crate::TightBeamError>>,
{
	closure(trace, config).await
}

/// Helper function for start closures with Arc<RwLock<Config>>
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __call_start_closure_with_rwlock<F, Fut, C, S>(
	closure: F,
	trace: std::sync::Arc<crate::trace::TraceCollector>,
	config: std::sync::Arc<std::sync::RwLock<C>>,
) -> Result<S, crate::TightBeamError>
where
	F: FnOnce(std::sync::Arc<crate::trace::TraceCollector>, std::sync::Arc<std::sync::RwLock<C>>) -> Fut,
	Fut: core::future::Future<Output = Result<S, crate::TightBeamError>>,
{
	closure(trace, config).await
}

/// Helper function for setup closures with Arc<RwLock<Config>>
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __call_setup_with_rwlock<F, Fut, A, C, T>(
	closure: F,
	addr: A,
	config: std::sync::Arc<std::sync::RwLock<C>>,
) -> Result<T, crate::TightBeamError>
where
	F: FnOnce(A, std::sync::Arc<std::sync::RwLock<C>>) -> Fut,
	Fut: core::future::Future<Output = Result<T, crate::TightBeamError>>,
{
	closure(addr, config).await
}

/// Helper function for setup closures with Arc<Config> (unified syntax, immutable)
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __call_setup_simple<F, Fut, A, C, T>(
	closure: F,
	addr: A,
	config: std::sync::Arc<C>,
) -> Result<T, crate::TightBeamError>
where
	F: FnOnce(A, std::sync::Arc<C>) -> Fut,
	Fut: core::future::Future<Output = Result<T, crate::TightBeamError>>,
{
	closure(addr, config).await
}

/// Helper function for client closures with Arc<Config>
#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __call_client_with_config<F, Fut, T, C>(
	closure: F,
	trace: crate::trace::TraceCollector,
	client: T,
	config: std::sync::Arc<std::sync::RwLock<C>>,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(crate::trace::TraceCollector, T, std::sync::Arc<std::sync::RwLock<C>>) -> Fut,
	Fut: core::future::Future<Output = Result<(), crate::TightBeamError>>,
{
	closure(trace, client, config).await
}

/// Helper macro for servlet client setup (called from tb_scenario)
#[doc(hidden)]
#[macro_export]
macro_rules! tb_servlet_setup_inner {
	($client:ident, $server_addr:expr, $env_config:expr) => {
		let $client = {
			use $crate::transport::tcp::r#async::TokioListener;
			use $crate::transport::ClientBuilder;
			async { ClientBuilder::<TokioListener>::connect($server_addr).await?.build() }
				.await
				.expect("Failed to setup servlet client (default)")
		};
	};
	($client:ident, $server_addr:expr, $env_config:expr, $setup_expr:expr) => {
		let $client = {
			let result: Result<_, $crate::TightBeamError> = ($setup_expr)($server_addr, $env_config).await;
			result.expect("Failed to setup servlet client (custom)")
		};
	};
}

/// tb_scenario! macro - MVP implementation
///
/// Supports three execution environments:
/// - Worker: Execute against a single worker instance
/// - Bare: Execute pure logic without transport
/// - ServiceClient: Full transport round-trip testing
///
/// Common top-level keys:
/// - name: test_function_name (creates standalone #[test] function)
/// - spec: AssertSpecType (uses latest version) OR specs: [expr, ...] (specific spec instances)
/// - trace: TraceConfig (OPTIONAL, when feature = "instrument")
/// - hooks { on_pass: |trace| {}, on_fail: |trace, violations| {} } (OPTIONAL)
#[macro_export]
macro_rules! tb_scenario {
	// ===== HELPER: Default protocol (internal) =====
	(@default_protocol) => {
		$crate::transport::tcp::r#async::TokioListener
	};
	(@default_protocol $protocol:path) => {
		$protocol
	};

	// ===== HELPER: Verify specs and call hooks (DRY) =====
	(@verify_and_call_hooks $config:expr, $hook_ctx:expr, $exec_result:expr) => {
		// Verify specs
		for spec in $config.specs() {
			match $crate::testing::specs::verify_trace(*spec, &$hook_ctx.trace) {
				Err(violation) => {
					if let Some(hooks) = $config.hooks() {
						if let Some(ref on_fail) = hooks.on_fail {
							let _ = on_fail(&$hook_ctx, &violation);
						}
					}
					panic!("Spec verification failed for {}: {:?}", spec.id(), violation);
				}
				Ok(()) => {}
			}
		}

		// Call on_pass hook if present
		if let Some(hooks) = $config.hooks() {
			if let Some(ref on_pass) = hooks.on_pass {
				let _ = on_pass(&$hook_ctx);
			}
		}

		if let Err(e) = $exec_result {
			panic!("Execution failed: {:?}", e);
		}
	};

	// ===== HELPER: Build hook context =====
	(@build_hook_context $config:expr, $trace:expr, $exec_result:expr) => {{
		let mut consumed_trace = $crate::trace::ConsumedTrace::new();
		consumed_trace.populate_from_collector(&$trace);
		consumed_trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
		if $exec_result.is_err() {
			consumed_trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
		}

		let mut hook_ctx = $crate::testing::HookContext::new(consumed_trace);
		#[cfg(feature = "testing-csp")]
		{
			hook_ctx.process = $config.csp().map(|p| std::sync::Arc::clone(p));
		}
		#[cfg(feature = "testing-fdr")]
		{
			if let Some(fdr_cfg) = $config.fdr() {
				hook_ctx.fdr_config = Some(std::sync::Arc::clone(fdr_cfg));
				use $crate::testing::fdr::DefaultFdrExplorer;

				// Determine what to explore based on configuration
				let fdr_verdict = if let Some(csp_spec) = $config.csp() {
					// Mode A: CSP spec provided - explore the spec model itself
					let spec_process_cow = csp_spec.to_process_cow();
					// Create exploration config (empty specs = state-space exploration)
					let exploration_cfg = std::sync::Arc::new($crate::testing::fdr::FdrConfig {
						seeds: fdr_cfg.seeds,
						max_depth: fdr_cfg.max_depth,
						max_internal_run: fdr_cfg.max_internal_run,
						timeout_ms: fdr_cfg.timeout_ms,
						specs: Vec::new(), // Empty: triggers exploration mode
						fail_fast: fdr_cfg.fail_fast,
						expect_failure: fdr_cfg.expect_failure,
						scheduler_count: fdr_cfg.scheduler_count,
						process_count: fdr_cfg.process_count,
						scheduler_model: fdr_cfg.scheduler_model.clone(),
						fault_model: fdr_cfg.fault_model.clone(),
						#[cfg(feature = "testing-fmea")]
						fmea_config: fdr_cfg.fmea_config.clone(),
					});

					let mut explorer = DefaultFdrExplorer::with_defaults(&spec_process_cow, exploration_cfg);
					let mut verdict = explorer.explore();
					// Also validate runtime trace against spec if specs are
					// provided in FdrConfig
					if !fdr_cfg.specs.is_empty() {
						let trace_process = hook_ctx.trace.to_process();
						let fdr_cfg_arc = std::sync::Arc::clone(fdr_cfg);
						let mut trace_explorer = DefaultFdrExplorer::with_defaults(&trace_process, fdr_cfg_arc);
						let trace_verdict = trace_explorer.explore();

						// Merge verdicts: spec exploration + trace validation
						verdict.trace_refines = trace_verdict.trace_refines;
						verdict.divergence_refines = trace_verdict.divergence_refines;
						verdict.trace_refinement_witness = trace_verdict.trace_refinement_witness;
						verdict.divergence_refinement_witness = trace_verdict.divergence_refinement_witness;
						verdict.passed = verdict.passed && trace_verdict.trace_refines && trace_verdict.divergence_refines;
					}
					verdict
				} else {
					// Mode B: No CSP spec - explore runtime trace
					let trace_process = hook_ctx.trace.to_process();
					let fdr_cfg_arc = std::sync::Arc::clone(fdr_cfg);
					let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, fdr_cfg_arc);
					explorer.explore()
				};

				hook_ctx.fdr_verdict = Some(fdr_verdict);
			}
		}

		if !$config.specs().is_empty() {
			hook_ctx.assert_spec = $config.specs().first().copied();
		}

		hook_ctx
	}};

	// ===== FUZZ VARIANT: AFL fuzz target for Bare environment (generates fn main()) =====
	(
		fuzz: afl,
		csp: $csp_type:ty,
		config: $config:expr,
		environment Bare { exec: $exec_closure:expr }
		$(,)?
	) => {
		#[cfg(fuzzing)]
		fn main() {
			// Type inference helper
			fn __exec_fuzz<F>(f: F, trace: $crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
			{
				f(trace)
			}

			afl::fuzz!(|data: &[u8]| {
				// Get CSP process directly from concrete type (fresh each iteration)
				#[cfg(feature = "testing-csp")]
				let process = <$csp_type>::process();

				// Create fresh trace with oracle for this AFL iteration
				let trace = $crate::trace::TraceCollector::with_fuzz_oracle(data.to_vec(), process);

				// Execute fuzz closure
				let _result = __exec_fuzz($exec_closure, trace);
			});
		}

		#[cfg(not(fuzzing))]
		fn main() {
			panic!("This is an AFL fuzz target. Build with: RUSTFLAGS='--cfg fuzzing' cargo afl build --bin <name>");
		}
	};

	// ===== FUZZ VARIANT: AFL fuzz target for Servlet environment (generates fn main()) =====
	(
		fuzz: afl,
		config: $config:expr,
		environment Servlet { $($env_body:tt)* }
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::main]
		async fn main() {
			$crate::tb_scenario!(@execute_unified
				name: fuzz_target,
				config: $config,
				environment Servlet { $($env_body)* }
			)
		}
	};

	// ===== Bare environment with async closure =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Bare { exec: |$trace_param:ident| async move $exec_body:block }
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() {
			$crate::tb_scenario!(@execute_unified_async
				name: $test_name,
				config: $config,
				exec: |$trace_param| async move $exec_body
			).await.expect(concat!("Test ", stringify!($test_name), " failed"));
		}
	};

	// ===== Bare environment with sync closure =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Bare { exec: $exec_closure:expr }
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			$crate::tb_scenario!(@execute_unified
				name: $test_name,
				config: $config,
				environment Bare { exec: $exec_closure }
			)
		}
	};

	// ===== Pipeline environment (sync) =====
	// Provides PipelineBuilder with trace context pre-configured
	// Closure returns Result<T, TightBeamError> directly from .run()
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Pipeline { exec: $exec_closure:expr }
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			$crate::tb_scenario!(@execute_unified
				name: $test_name,
				config: $config,
				environment Pipeline { exec: $exec_closure }
			)
		}
	};

	// ===== Worker environment (async) =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Worker { $($env_body:tt)* }
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() {
			$crate::tb_scenario!(@execute_unified
				name: $test_name,
				config: $config,
				environment Worker { $($env_body)* }
			)
		}
	};

	// ===== Servlet environment (async) =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Servlet { $($env_body:tt)* }
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() {
			$crate::tb_scenario!(@execute_unified
				name: $test_name,
				config: $config,
				environment Servlet { $($env_body)* }
			)
		}
	};

	// ===== ServiceClient environment with worker_threads =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment ServiceClient {
			worker_threads: $threads:literal,
			$(protocol: $protocol:path,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() {
			$crate::tb_scenario!(@execute_unified
				name: $test_name,
				config: $config,
				environment ServiceClient {
					$(protocol: $protocol,)?
					server: $server_closure,
					client: $client_closure
				}
			)
		}
	};

	// ===== ServiceClient environment without worker_threads =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() {
			$crate::tb_scenario!(@execute_unified
				name: $test_name,
				config: $config,
				environment ServiceClient {
					$(protocol: $protocol,)?
					server: $server_closure,
					client: $client_closure
				}
			)
		}
	};

	// ===== INTERNAL: Execute unified scenario for Bare environment (ASYNC) =====
	(@execute_unified_async
		name: $test_name:ident,
		config: $config:expr,
		exec: |$trace_param:ident| async move $exec_body:block
	) => {{
		async move {
			use $crate::testing::TBSpec;

			let config = $config;
			let trace = config.trace();

			// Execute the async bare closure with explicit Result type
			let closure = |$trace_param: ::std::sync::Arc<$crate::trace::TraceCollector>| -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<(), $crate::TightBeamError>> + Send>> {
				Box::pin(async move $exec_body)
			};
			let exec_result = closure(::std::sync::Arc::clone(&trace)).await;

			// Build hook context and verify
			let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);

			// Call hooks for specs (panics on failure)
			$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);

			Ok::<(), $crate::TightBeamError>(())
		}
	}};

	// ===== INTERNAL: Execute unified scenario for Bare environment (SYNC) =====
	(@execute_unified
		name: $test_name:ident,
		config: $config:expr,
		environment Bare { exec: $exec_closure:expr }
	) => {{
		use $crate::testing::TBSpec;

		let config = $config;
		let trace = config.trace();

		// Execute the bare closure (using helper for type inference)
		let exec_result = $crate::testing::macros::__tb_call_exec_closure_arc($exec_closure, std::sync::Arc::clone(&trace));

		// Build hook context and verify
		let mut hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);

		// Extract timing constraints from FDR specs if available (Bare-specific)
		#[cfg(all(feature = "testing-fdr", feature = "testing-timing"))]
		{
			if let Some(fdr_cfg) = config.fdr() {
				if let Some(first_spec) = fdr_cfg.specs.first() {
					hook_ctx.timing_constraints = first_spec.timing_constraints.clone().map(std::sync::Arc::new);
				}
			}
		}

		// Verify specs and call hooks (DRY helper)
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Execute unified scenario for Pipeline environment =====
	(@execute_unified
		name: $test_name:ident,
		config: $config:expr,
		environment Pipeline { exec: $exec_closure:expr }
	) => {{
		use $crate::testing::TBSpec;
		use $crate::utils::task::PipelineBuilder;

		let config = $config;
		let trace = config.trace();

		// Create PipelineBuilder with trace context
		let pipeline = PipelineBuilder::new(std::sync::Arc::clone(&trace));

		// Execute the pipeline closure (returns Result<T, E>, mapped to Result<(), E>)
		let exec_result = $crate::testing::macros::__tb_call_pipeline_exec($exec_closure, pipeline);

		// Build hook context and verify
		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);

		// Verify specs and call hooks (DRY helper)
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Execute unified scenario for Worker environment =====
	(@execute_unified
		name: $test_name:ident,
		config: $config:expr,
		environment Worker { setup: $setup_closure:expr, stimulus: $stimulus_closure:expr }
	) => {{
		use $crate::testing::TBSpec;

		let config = $config;
		let trace = config.trace();
		let trace_setup = trace.share();
		let trace_start = std::sync::Arc::new(trace.share());
		let trace_stimulus = std::sync::Arc::new(trace.share());

		// Execute setup and stimulus
		let builder = $crate::testing::macros::__tb_call_setup_closure($setup_closure, trace_setup);
		let mut worker = <_ as $crate::colony::worker::Worker>::start(builder, trace_start)
			.await
			.expect("Failed to start worker");

		fn __tb_call_worker_stimulus<W, F, Fut>(
			closure: F,
			trace: std::sync::Arc<$crate::trace::TraceCollector>,
			worker: W,
		) -> Fut
		where
			W: $crate::colony::worker::Worker,
			F: FnOnce(std::sync::Arc<$crate::trace::TraceCollector>, W) -> Fut,
			Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
		{
			closure(trace, worker)
		}

		let exec_result = __tb_call_worker_stimulus($stimulus_closure, trace_stimulus, worker).await;

		// Build hook context and verify
		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);

		// Verify specs and call hooks (DRY helper)
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Execute unified scenario for Servlet environment =====
	(@execute_unified
		name: $test_name:ident,
		config: $config:expr,
		environment Servlet {
			servlet: $servlet_name:ident,
			start: $start_closure:expr,
			$(setup: $setup_expr:expr,)?
			client: $client_closure:expr
		}
	) => {{
		use $crate::testing::TBSpec;

		let config = $config;
		let trace = config.trace();
		let trace_client = trace.share();
		let trace_server = std::sync::Arc::new(trace.share());

		// Get env_config as Arc for passing to closures
		let env_config = std::sync::Arc::clone(config.env_config());

		// Start servlet using start closure
		let servlet_instance = $crate::testing::macros::__call_start_closure($start_closure, trace_server, Arc::clone(&env_config))
			.await
			.expect("Failed to start servlet");
		let server_addr = servlet_instance.addr();

		// Setup client (with optional setup expression - defaults to simple connect)
		$crate::tb_servlet_setup_inner!(client, server_addr, std::sync::Arc::clone(&env_config) $(, $setup_expr)?);

		// Execute client closure with proper type inference
		fn __tb_call_servlet_client<T, F, Fut, C>(
			closure: F,
			trace: $crate::trace::TraceCollector,
			client: T,
			config: std::sync::Arc<C>,
		) -> Fut
		where
			F: FnOnce($crate::trace::TraceCollector, T, std::sync::Arc<C>) -> Fut,
			Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
		{
			closure(trace, client, config)
		}

		let client_result = __tb_call_servlet_client($client_closure, trace_client, client, env_config).await;

		// Stop servlet
		servlet_instance.stop();

		// Build hook context and verify
		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, client_result);

		// Verify specs and call hooks
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, client_result);
	}};

	// ===== INTERNAL: Execute unified scenario for ServiceClient environment =====
	(@execute_unified
		name: $test_name:ident,
		config: $config:expr,
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
	) => {{
		use $crate::testing::TBSpec;

		let config = $config;
		let trace = config.trace();
		let trace_server = trace.share();
		let trace_client = trace.share();

		// Server closure helper
		async fn __call_server_closure<F, Fut>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> Result<(tokio::task::JoinHandle<()>, $crate::transport::tcp::TightBeamSocketAddr), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector) -> Fut,
			Fut: core::future::Future<Output = Result<(tokio::task::JoinHandle<()>, $crate::transport::tcp::TightBeamSocketAddr), $crate::TightBeamError>>,
		{
			closure(trace).await
		}

		// Start server
		let server_setup_result = __call_server_closure($server_closure, trace_server).await;
		let (server_handle, server_addr) = server_setup_result.expect("Server setup failed");

		// Determine protocol
		#[allow(unused_imports)]
		use $crate::tb_scenario;
		type ProtocolType = $crate::tb_scenario!(@default_protocol $($protocol)?);

		// Connect client
		let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
			.expect("Failed to connect to server");
		let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

		// Execute client closure
		let client_result = $crate::testing::macros::__tb_call_client_closure_async($client_closure, trace_client, client).await;

		// Cleanup server
		server_handle.abort();

		// Build hook context and verify
		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, client_result);

		// Verify specs and call hooks
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, client_result);
	}};

}
