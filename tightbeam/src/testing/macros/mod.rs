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
	absent, between, present, versions_strictly_ascending, AssertSpecBuilder, BuiltAssertSpec, Cardinality,
	SpecBuildError,
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

/// Call an async scenario closure with its environment struct. The
/// concrete env type drives closure parameter inference.
#[doc(hidden)]
pub async fn __tb_env_call<E, F, Fut, T>(closure: F, env: E) -> Result<T, crate::TightBeamError>
where
	F: FnOnce(E) -> Fut,
	Fut: core::future::Future<Output = Result<T, crate::TightBeamError>>,
{
	closure(env).await
}

/// Call a synchronous scenario closure with its environment struct.
#[doc(hidden)]
pub fn __tb_env_call_sync<E, F, T>(closure: F, env: E) -> T
where
	F: FnOnce(E) -> T,
{
	closure(env)
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

/// Unified scenario entry point for AssertSpec (and optional CSP/FDR)
/// verification under a selectable execution environment.
///
/// Closures take one parameter. Non-Pipeline environments use a struct
/// from [`crate::testing::env`]: `trace` is a [`TraceCollector`] share
/// and `context` is `Arc<C>` (unit when `context:` is omitted). Name
/// the parameter `env`, or destructure fields in the pattern.
///
/// Supported environments:
/// - Bare: `exec: |env|` sync or `async move` ([`SetupEnv`])
/// - Pipeline: `exec: |pipeline|` receives [`PipelineBuilder`]
/// - Worker: `setup: |env|` sync returns builder ([`SetupEnv`]).
///   `stimulus: |env|` async owns started worker ([`WorkerEnv`])
/// - Servlet: `start: |env|` async returns servlet ([`SetupEnv`]).
///   Optional `setup: |env|` async returns connected client
///   ([`ClientEnv`]). Default connects a plain [`TokioListener`] client.
///   `client: |env|` async ([`ServletEnv`])
/// - ServiceClient: `server: |env|` async returns
///   `(JoinHandle, TightBeamSocketAddr)` ([`SetupEnv`]).
///   `client: |env|` async connects via `env.addr` ([`ClientEnv`]).
///   Optional `worker_threads: N`
/// - Cluster: `start: |env|` async returns cluster ([`SetupEnv`]).
///   Optional `hives: |env|` returns hive futures `tb_scenario!` awaits
///   and registers ([`SetupEnv`]). `client: |env|` async owns cluster
///   ([`ClusterEnv`])
/// - Hive: `start: |env|` async returns hive ([`SetupEnv`]).
///   `client: |env|` async owns hive ([`HiveEnv`])
///
/// Top-level keys:
/// - `name:` test function name (omit with `fuzz: afl`)
/// - `spec:` AssertSpec type (latest version) or `config:` ScenarioConfig
/// - `fuzz: afl` optional AFL target (Bare/Servlet/Hive/Cluster). Every
///   environment wraps `afl::fuzz!` and passes
///   [`TraceCollector::with_fuzz_oracle`] into the same runner the named
///   test uses, so each AFL iteration verifies its specs and its CSP
///   process. Requires `csp:` and feature `testing-fuzz`
///
/// Environment-block keys:
/// - `context:` fixture evaluated once per test, shared as `Arc<C>`
///
/// [`SetupEnv`]: crate::testing::env::SetupEnv
/// [`ClientEnv`]: crate::testing::env::ClientEnv
/// [`WorkerEnv`]: crate::testing::env::WorkerEnv
/// [`ServletEnv`]: crate::testing::env::ServletEnv
/// [`ClusterEnv`]: crate::testing::env::ClusterEnv
/// [`HiveEnv`]: crate::testing::env::HiveEnv
/// [`TraceCollector`]: crate::trace::TraceCollector
/// [`PipelineBuilder`]: crate::utils::task::PipelineBuilder
/// [`TokioListener`]: crate::transport::tcp::async::TokioListener
#[macro_export]
macro_rules! tb_scenario {
	// spec: -> config:
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$($rest:tt)*
	) => {
		$crate::tb_scenario! {
			name: $test_name,
			config: $crate::testing::ScenarioConfig::builder().with_spec(<$spec>::latest()).build(),
			$($rest)*
		}
	};
	(
		fuzz: afl,
		csp: $csp_type:ty,
		spec: $spec:ty,
		$($rest:tt)*
	) => {
		$crate::tb_scenario! {
			fuzz: afl,
			csp: $csp_type,
			// The oracle uses the type to pick events. Layer 2 verification
			// reads `config.csp()`, so a config without it grades nothing.
			config: $crate::testing::ScenarioConfig::builder()
				.with_spec(<$spec>::latest())
				.with_csp(<$csp_type as ::core::default::Default>::default())
				.build(),
			$($rest)*
		}
	};

	// ===== HELPER: Verify specs and call hooks =====
	(@verify_and_call_hooks $config:expr, $hook_ctx:expr, $exec_result:expr) => {
		// An AFL iteration whose input ran out drove a prefix of a run, not a
		// violation. Grading it would report every short mutation as a finding.
		if $exec_result.as_ref().err().is_some_and(|error| error.is_fuzz_input_exhausted()) {
			return;
		}

		// Verify Layer 1 assertion specs
		for spec in $config.specs() {
			match $crate::testing::specs::verify_trace(*spec, &$hook_ctx.trace) {
				Err(violation) => {
					if let Some(hooks) = $config.hooks() {
						if let Some(ref on_fail) = hooks.on_fail {
							let _ = on_fail(&$hook_ctx, &violation);
						}
					}
					panic!(
						"Spec verification failed for {}: {:?}",
						$crate::testing::TBSpec::id(*spec),
						violation
					);
				}
				Ok(()) => {}
			}
		}

		// Verify Layer 2 CSP process (when configured). Failures travel
		// the same path as Layer 1: on_fail first, then the panic.
		$crate::__tb_if_testing_csp!({
			if let Some(csp) = $config.csp() {
				let csp_result =
					$crate::testing::specs::csp::ProcessSpec::validate_trace(csp.as_ref(), &$hook_ctx.trace);
				if !csp_result.valid {
					let violation =
						$crate::testing::specs::SpecViolation::CspProcessViolation(csp_result.violations);
					if let Some(hooks) = $config.hooks() {
						if let Some(ref on_fail) = hooks.on_fail {
							let _ = on_fail(&$hook_ctx, &violation);
						}
					}

					panic!("CSP verification failed: {:?}", violation);
				}
			}
		});

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
		consumed_trace.gate_decision = Some($crate::policy::TransitStatus::Ok);
		if $exec_result.is_err() {
			consumed_trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
		}

		let mut hook_ctx = $crate::testing::HookContext::new(consumed_trace);
		$crate::__tb_if_testing_csp!({
			hook_ctx.process = $config.csp().map(|p| std::sync::Arc::clone(p));
		});
		$crate::__tb_if_testing_fdr!({
			if let Some(fdr_cfg) = $config.fdr() {
				hook_ctx.fdr_config = Some(std::sync::Arc::clone(fdr_cfg));
				use $crate::testing::fdr::DefaultFdrExplorer;

				// Determine what to explore based on configuration
				let fdr_verdict = if let Some(csp_spec) = $config.csp() {
					// Mode A: CSP spec provided - explore the spec model itself
					let spec_process_cow = csp_spec.to_process_cow();
					// Create exploration config (empty specs = state-space exploration)
					let mut exploration_cfg = (**fdr_cfg).clone();
					// Empty specs put the explorer in state-space exploration mode.
					exploration_cfg.specs = Vec::new();
					let exploration_cfg = std::sync::Arc::new(exploration_cfg);

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
						verdict.failures_refines = trace_verdict.failures_refines;
						verdict.divergence_refines = trace_verdict.divergence_refines;
						verdict.trace_refinement_witness = trace_verdict.trace_refinement_witness;
						verdict.failures_refinement_witness = trace_verdict.failures_refinement_witness;
						verdict.divergence_refinement_witness = trace_verdict.divergence_refinement_witness;
						verdict.complete = verdict.complete && trace_verdict.complete;
						verdict.passed = verdict.passed && trace_verdict.passed;
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
		});

		if !$config.specs().is_empty() {
			hook_ctx.assert_spec = $config.specs().first().copied();
		}

		hook_ctx
	}};

	// ===== INTERNAL: Sync AFL mains =====
	//
	// Shared by the Bare `fuzz: afl` arm. Both mains forward into the same
	// `@run_*` body, so spec and CSP verification is not something the
	// fuzzing path can omit: only the oracle's input bytes differ. Without
	// `--cfg fuzzing` the smoke main runs one empty-input iteration, which
	// keeps `config` and `exec` used under an IDE and `cargo check`.
	(@afl_sync
		csp: $csp_type:ty,
		config: $config:expr,
		@$run:ident
		$($run_body:tt)*
	) => {
		#[cfg(fuzzing)]
		fn main() {
			afl::fuzz!(|data: &[u8]| {
				let process = <$csp_type>::process();
				let config = $config;
				let trace = $crate::trace::TraceCollector::with_fuzz_oracle(data.to_vec(), process);
				$crate::tb_scenario!(@$run
					config: config,
					trace: trace,
					$($run_body)*
				)
			});
		}

		#[cfg(not(fuzzing))]
		fn main() {
			let process = <$csp_type>::process();
			let config = $config;
			let trace = $crate::trace::TraceCollector::with_fuzz_oracle(::std::vec::Vec::new(), process);
			$crate::tb_scenario!(@$run
				config: config,
				trace: trace,
				$($run_body)*
			)
		}
	};

	// ===== FUZZ VARIANT: AFL fuzz target for Bare environment (generates fn main()) =====
	(
		fuzz: afl,
		csp: $csp_type:ty,
		config: $config:expr,
		environment Bare { exec: $exec_closure:expr }
		$(,)?
	) => {
		$crate::tb_scenario! {
			@afl_sync
			csp: $csp_type,
			config: $config,
			@run_bare_sync
			context: [],
			exec: $exec_closure
		}
	};

	// ===== FUZZ VARIANT: AFL fuzz target for Servlet environment (generates fn main()) =====
	(
		fuzz: afl,
		csp: $csp_type:ty,
		config: $config:expr,
		environment Servlet { $($env_body:tt)* }
		$(,)?
	) => {
		$crate::tb_scenario! {
			@afl_async
			csp: $csp_type,
			config: $config,
			label: "Servlet",
			@run_servlet
			environment Servlet { $($env_body)* }
		}
	};

	// ===== INTERNAL: Tokio AFL mains =====
	//
	// Shared by the Servlet, Hive, and Cluster `fuzz: afl` arms. Builds
	// `TraceCollector::with_fuzz_oracle` each AFL iteration (or empty
	// bytes for smoke) and forwards into the matching `@run_*` body.
	// The Tokio runtime is created inside the fuzz closure so worker
	// threads are not live before AFL's forkserver handoff.
	(@afl_async
		csp: $csp_type:ty,
		config: $config:expr,
		label: $label:literal,
		@$run:ident
		$($run_body:tt)*
	) => {
		// `fuzzing` stays a consumer cfg: the fuzz target is the crate built
		// with `--cfg fuzzing`. Only the feature test belongs to tightbeam.
		$crate::__tb_select_tokio! {
			{
				#[cfg(fuzzing)]
				fn main() {
					afl::fuzz!(|data: &[u8]| {
						let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
							return;
						};
						runtime.block_on(async {
							let process = <$csp_type>::process();
							let config = $config;
							let trace = $crate::trace::TraceCollector::with_fuzz_oracle(data.to_vec(), process);
							$crate::tb_scenario!(@$run
								config: config,
								trace: trace,
								$($run_body)*
							)
						});
					});
				}

				#[cfg(not(fuzzing))]
				#[tokio::main]
				async fn main() {
					let process = <$csp_type>::process();
					let config = $config;
					let trace = $crate::trace::TraceCollector::with_fuzz_oracle(::std::vec::Vec::new(), process);
					$crate::tb_scenario!(@$run
						config: config,
						trace: trace,
						$($run_body)*
					)
				}
			}
			{
				fn main() {
					panic!(concat!($label, " AFL target requires the tokio feature"));
				}
			}
		}
	};

	// ===== FUZZ VARIANT: AFL fuzz target for Hive environment =====
	(
		fuzz: afl,
		csp: $csp_type:ty,
		config: $config:expr,
		environment Hive {
			$(context: $context:expr,)?
			start: $start_closure:expr,
			client: $client_closure:expr
		}
		$(,)?
	) => {
		$crate::tb_scenario! {
			@afl_async
			csp: $csp_type,
			config: $config,
			label: "Hive",
			@run_hive
			context: [ $($context)? ],
			start: $start_closure,
			client: $client_closure
		}
	};

	// ===== FUZZ VARIANT: AFL fuzz target for Cluster environment =====
	(
		fuzz: afl,
		csp: $csp_type:ty,
		config: $config:expr,
		environment Cluster {
			$(context: $context:expr,)?
			start: $start_closure:expr,
			$(hives: $hives_closure:expr,)?
			client: $client_closure:expr
		}
		$(,)?
	) => {
		$crate::tb_scenario! {
			@afl_async
			csp: $csp_type,
			config: $config,
			label: "Cluster",
			@run_cluster
			context: [ $($context)? ],
			start: $start_closure,
			hives: [ $($hives_closure)? ],
			client: $client_closure
		}
	};

	// ===== Bare environment, async exec =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Bare {
			$(context: $context:expr,)?
			exec: |$env:pat_param| async move $exec_body:block
		}
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				$crate::tb_scenario!(@run_bare_async
					config: $config,
					context: [ $($context)? ],
					exec: |$env| async move $exec_body
				)
			}
		}
	};

	// ===== Bare environment, sync exec =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Bare {
			$(context: $context:expr,)?
			exec: $exec_closure:expr
		}
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			let config = $config;
			let trace = config.trace();
			$crate::tb_scenario!(@run_bare_sync
				config: config,
				trace: trace,
				context: [ $($context)? ],
				exec: $exec_closure
			)
		}
	};

	// ===== Pipeline environment (sync) =====
	// exec receives a PipelineBuilder with trace context pre-configured
	// and returns Result<T, TightBeamError> directly from .run()
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Pipeline { exec: $exec_closure:expr }
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			$crate::tb_scenario!(@run_pipeline
				config: $config,
				exec: $exec_closure
			)
		}
	};

	// ===== Worker environment (async) =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Worker {
			$(context: $context:expr,)?
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				$crate::tb_scenario!(@run_worker
					config: $config,
					context: [ $($context)? ],
					setup: $setup_closure,
					stimulus: $stimulus_closure
				)
			}
		}
	};

	// ===== Servlet environment (async) =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Servlet { $($env_body:tt)* }
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				let config = $config;
				let trace = config.trace();
				$crate::tb_scenario!(@run_servlet
					config: config,
					trace: trace,
					environment Servlet { $($env_body)* }
				)
			}
		}
	};

	// ===== ServiceClient environment with worker_threads =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment ServiceClient {
			worker_threads: $threads:literal,
			$(context: $context:expr,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
			async fn $test_name() {
				$crate::tb_scenario!(@run_service_client
					config: $config,
					context: [ $($context)? ],
					server: $server_closure,
					client: $client_closure
				)
			}
		}
	};

	// ===== ServiceClient environment =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment ServiceClient {
			$(context: $context:expr,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				$crate::tb_scenario!(@run_service_client
					config: $config,
					context: [ $($context)? ],
					server: $server_closure,
					client: $client_closure
				)
			}
		}
	};

	// ===== Cluster environment (async) =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Cluster {
			$(context: $context:expr,)?
			start: $start_closure:expr,
			$(hives: $hives_closure:expr,)?
			client: $client_closure:expr
		}
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				let config = $config;
				let trace = config.trace();
				$crate::tb_scenario!(@run_cluster
					config: config,
					trace: trace,
					context: [ $($context)? ],
					start: $start_closure,
					hives: [ $($hives_closure)? ],
					client: $client_closure
				)
			}
		}
	};

	// ===== Hive environment (async) =====
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Hive {
			$(context: $context:expr,)?
			start: $start_closure:expr,
			client: $client_closure:expr
		}
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				let config = $config;
				let trace = config.trace();
				$crate::tb_scenario!(@run_hive
					config: config,
					trace: trace,
					context: [ $($context)? ],
					start: $start_closure,
					client: $client_closure
				)
			}
		}
	};

	// ===== INTERNAL: Bare environment (ASYNC) =====
	(@run_bare_async
		config: $config:expr,
		context: [ $($context:expr)? ],
		exec: |$env:pat_param| async move $exec_body:block
	) => {{
		let config = $config;
		let trace = config.trace();
		let env = $crate::testing::env::SetupEnv {
			trace: trace.share(),
			context: ::std::sync::Arc::new(($($context)?)),
		};

		let exec_result = $crate::testing::macros::__tb_env_call(|$env| async move $exec_body, env).await;

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Bare environment (SYNC) =====
	// `trace` is caller-supplied: a named test passes `config.trace()` and an
	// AFL arm passes `TraceCollector::with_fuzz_oracle(...)`, so both reach the
	// one verification below.
	(@run_bare_sync
		config: $config:expr,
		trace: $trace:expr,
		context: [ $($context:expr)? ],
		exec: $exec_closure:expr
	) => {{
		let config = $config;
		let trace = $trace;
		let env = $crate::testing::env::SetupEnv {
			trace: trace.share(),
			context: ::std::sync::Arc::new(($($context)?)),
		};

		let exec_result: Result<(), $crate::TightBeamError> =
			$crate::testing::macros::__tb_env_call_sync($exec_closure, env);

		// `mut` only used when testing-fdr + testing-timing set timing_constraints below.
		#[allow(unused_mut)]
		let mut hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);

		// Extract timing constraints from FDR specs if available (Bare-specific)
		$crate::__tb_if_testing_fdr_timing!({
			if let Some(fdr_cfg) = config.fdr() {
				if let Some(first_spec) = fdr_cfg.specs.first() {
					hook_ctx.timing_constraints = first_spec.timing_constraints.clone().map(std::sync::Arc::new);
				}
			}
		});

		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Pipeline environment =====
	(@run_pipeline
		config: $config:expr,
		exec: $exec_closure:expr
	) => {{
		use $crate::utils::task::PipelineBuilder;

		let config = $config;
		let trace = config.trace();

		// Create PipelineBuilder with trace context
		let pipeline = PipelineBuilder::new(std::sync::Arc::clone(&trace));

		// Execute the pipeline closure (returns Result<T, E>, mapped to Result<(), E>)
		let exec_result = $crate::testing::macros::__tb_call_pipeline_exec($exec_closure, pipeline);

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Worker environment =====
	(@run_worker
		config: $config:expr,
		context: [ $($context:expr)? ],
		setup: $setup_closure:expr,
		stimulus: $stimulus_closure:expr
	) => {{
		let config = $config;
		let trace = config.trace();
		let context = ::std::sync::Arc::new(($($context)?));

		let builder = $crate::testing::macros::__tb_env_call_sync(
			$setup_closure,
			$crate::testing::env::SetupEnv {
				trace: trace.share(),
				context: ::std::sync::Arc::clone(&context),
			},
		);
		let worker = <_ as $crate::colony::worker::Worker>::start(builder, ::std::sync::Arc::new(trace.share()))
			.await
			.expect("Failed to start worker");

		let exec_result = $crate::testing::macros::__tb_env_call(
			$stimulus_closure,
			$crate::testing::env::WorkerEnv {
				trace: trace.share(),
				context,
				worker,
			},
		)
		.await;

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, exec_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, exec_result);
	}};

	// ===== INTERNAL: Servlet client setup (default connect) =====
	(@servlet_client $trace:expr, $context:expr, $addr:expr) => {{
		use $crate::transport::tcp::r#async::TokioListener;
		use $crate::transport::{ClientBuilder, ConnectionBuilder};

		// The default servlet scenario provisions no trust store, so the
		// scenario runs in the clear and says so.
		let builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
		builder
			.connect($addr)
			.await
			.expect("Failed to setup servlet client (default)")
	}};
	// ===== INTERNAL: Servlet client setup (custom closure) =====
	(@servlet_client $trace:expr, $context:expr, $addr:expr, $setup_closure:expr) => {{
		$crate::testing::macros::__tb_env_call(
			$setup_closure,
			$crate::testing::env::ClientEnv {
				trace: $trace,
				context: $context,
				addr: $addr,
			},
		)
		.await
		.expect("Failed to setup servlet client (custom)")
	}};

	// ===== INTERNAL: Servlet environment =====
	// `trace` is caller-supplied (see `@run_bare_sync`).
	(@run_servlet
		config: $config:expr,
		trace: $trace:expr,
		environment Servlet {
			$(context: $context:expr,)?
			start: $start_closure:expr,
			$(setup: $setup_expr:expr,)?
			client: $client_closure:expr
		}
	) => {{
		let config = $config;
		let trace = $trace;
		let context = ::std::sync::Arc::new(($($context)?));

		let servlet_instance = $crate::testing::macros::__tb_env_call(
			$start_closure,
			$crate::testing::env::SetupEnv {
				trace: trace.share(),
				context: ::std::sync::Arc::clone(&context),
			},
		)
		.await
		.expect("Failed to start servlet");

		let server_addr = servlet_instance.addr().to_owned();
		let client = $crate::tb_scenario!(@servlet_client
			trace.share(), ::std::sync::Arc::clone(&context), server_addr $(, $setup_expr)?
		);

		let client_result = $crate::testing::macros::__tb_env_call(
			$client_closure,
			$crate::testing::env::ServletEnv {
				trace: trace.share(),
				context,
				client,
			},
		)
		.await;

		servlet_instance.stop();

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, client_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, client_result);
	}};

	// ===== INTERNAL: ServiceClient environment =====
	(@run_service_client
		config: $config:expr,
		context: [ $($context:expr)? ],
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		let config = $config;
		let trace = config.trace();
		let context = ::std::sync::Arc::new(($($context)?));

		let (server_handle, server_addr) = $crate::testing::macros::__tb_env_call(
			$server_closure,
			$crate::testing::env::SetupEnv {
				trace: trace.share(),
				context: ::std::sync::Arc::clone(&context),
			},
		)
		.await
		.expect("Server setup failed");

		let client_result = $crate::testing::macros::__tb_env_call(
			$client_closure,
			$crate::testing::env::ClientEnv {
				trace: trace.share(),
				context,
				addr: server_addr,
			},
		)
		.await;

		server_handle.abort();

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, client_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, client_result);
	}};

	// ===== INTERNAL: Cluster environment =====
	// `start` returns the cluster. Optional `hives` returns futures that
	// `tb_scenario!` awaits and registers. `client` owns the cluster for
	// registry assertions and the consuming `stop`.
	//
	// `trace` is supplied by the caller: named tests pass `config.trace()`,
	// AFL arms pass `TraceCollector::with_fuzz_oracle(...)` so the oracle
	// wires through the same path as Bare.
	(@run_cluster
		config: $config:expr,
		trace: $trace:expr,
		context: [ $($context:expr)? ],
		start: $start_closure:expr,
		hives: [ $($hives_closure:expr)? ],
		client: $client_closure:expr
	) => {{
		#[allow(unused_imports)]
		use $crate::colony::cluster::Cluster;
		#[allow(unused_imports)]
		use $crate::colony::hive::Hive;

		let config = $config;
		let trace = $trace;
		let context = ::std::sync::Arc::new(($($context)?));

		let cluster_instance = $crate::testing::macros::__tb_env_call(
			$start_closure,
			$crate::testing::env::SetupEnv {
				trace: trace.share(),
				context: ::std::sync::Arc::clone(&context),
			},
		)
		.await
		.expect("Failed to start cluster");

		// Type-erased as consuming closures because `Hive::stop(self)`
		// needs the concrete type: plain drop only aborts control tasks
		// and would leak registered servlets.
		#[allow(unused_mut)]
		let mut hive_stops: Vec<Box<dyn FnOnce() + Send>> = Vec::new();
		$(
			let cluster_addr = cluster_instance.addr().clone();
			let hive_futures = ($hives_closure)($crate::testing::env::SetupEnv {
				trace: trace.share(),
				context: ::std::sync::Arc::clone(&context),
			});
			for hive_future in hive_futures {
				let hive = hive_future.await.expect("Failed to start hive");
				hive.register_with_cluster(&cluster_addr).await.expect("Failed to register hive");
				hive_stops.push(Box::new(move || hive.stop()));
			}
		)?

		// Cluster client owns the instance. Teardown runs in the closure
		// because `stop(self)` consumes it.
		let client_result = $crate::testing::macros::__tb_env_call(
			$client_closure,
			$crate::testing::env::ClusterEnv {
				trace: trace.share(),
				context,
				cluster: cluster_instance,
			},
		)
		.await;

		for stop_hive in hive_stops {
			stop_hive();
		}

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, client_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, client_result);
	}};

	// ===== INTERNAL: Hive environment =====
	// Like Cluster without registration: `start` returns the hive and
	// `client` owns it. `trace` is caller-supplied (see `@run_cluster`).
	(@run_hive
		config: $config:expr,
		trace: $trace:expr,
		context: [ $($context:expr)? ],
		start: $start_closure:expr,
		client: $client_closure:expr
	) => {{
		let config = $config;
		let trace = $trace;
		let context = ::std::sync::Arc::new(($($context)?));

		let hive_instance = $crate::testing::macros::__tb_env_call(
			$start_closure,
			$crate::testing::env::SetupEnv {
				trace: trace.share(),
				context: ::std::sync::Arc::clone(&context),
			},
		)
		.await
		.expect("Failed to start hive");

		// Hive client owns the instance. Teardown runs in the closure
		// because `stop(self)` consumes it.
		let client_result = $crate::testing::macros::__tb_env_call(
			$client_closure,
			$crate::testing::env::HiveEnv {
				trace: trace.share(),
				context,
				hive: hive_instance,
			},
		)
		.await;

		let hook_ctx = $crate::tb_scenario!(@build_hook_context config, trace, client_result);
		$crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, client_result);
	}};
}

#[cfg(all(test, feature = "testing-csp"))]
mod tests {
	use std::borrow::Cow;
	use std::panic::{catch_unwind, AssertUnwindSafe};
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;

	use crate::testing::specs::csp::{CspValidationResult, CspViolation, Event, Process, ProcessSpec, State};
	use crate::testing::{HookContext, ScenarioConfig, TestHooks};
	use crate::trace::ConsumedTrace;

	struct AlwaysInvalidSpec;

	impl ProcessSpec for AlwaysInvalidSpec {
		fn validate_trace(&self, _trace: &ConsumedTrace) -> CspValidationResult {
			CspValidationResult {
				valid: false,
				violations: vec![CspViolation::Deadlock { event: Event("noop"), state: State("start") }],
			}
		}

		fn to_process_cow(&self) -> Cow<'_, Process> {
			let process = Process::builder("always_invalid")
				.initial_state(State("start"))
				.build()
				.expect("single-state process builds");
			Cow::Owned(process)
		}
	}

	// Layer 2 CSP failures must travel the same failure path as Layer 1
	// assertion failures: on_fail runs before the panic, so logging and
	// cleanup hooks observe the regression.
	#[test]
	fn csp_failure_invokes_on_fail_before_panicking() {
		let failed = Arc::new(AtomicBool::new(false));
		let observed = Arc::clone(&failed);
		let hooks = TestHooks {
			on_pass: None,
			on_fail: Some(Arc::new(move |_ctx, _violation| {
				observed.store(true, Ordering::SeqCst);
				Ok(())
			})),
		};

		let config = ScenarioConfig::builder().with_csp(AlwaysInvalidSpec).with_hooks(hooks).build();
		let hook_ctx = HookContext::new(ConsumedTrace::new());
		let outcome = catch_unwind(AssertUnwindSafe(|| {
			crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx, Ok::<(), crate::TightBeamError>(()));
		}));

		assert!(outcome.is_err());
		assert!(failed.load(Ordering::SeqCst));
	}
}
