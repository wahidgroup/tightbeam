//! Clean declarative testing macro & builder layer (legacy forms removed).
//! Layer 1 verification specs live in `verification_spec`, Layer 2 CSP specs
//! in `process_spec`, and this file retains the shared helpers plus `tb_scenario!`.

#![allow(unexpected_cfgs)]

// ProcessSpec macro (Layer 2 - CSP)
#[cfg(feature = "testing-csp")]
pub mod process_spec;

pub mod verification_spec;
pub use verification_spec::{
	absent, between, present, AssertSpecBuilder, BuiltAssertSpec, Cardinality, SpecBuildError, TbAssertLabelTrait,
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
/// Usage: wcet!(10ms) or wcet!(Duration::from_millis(10))
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! wcet {
	($dur:expr) => {
		$crate::testing::timing::TimingConstraint::Wcet($dur)
	};
}

/// Helper macro for deadline timing constraint
/// Usage: deadline!(100ms) or deadline!(Duration::from_millis(100))
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! deadline {
	($dur:expr) => {
		$crate::testing::timing::TimingConstraint::Deadline($dur)
	};
}

/// Helper macro for jitter timing constraint
/// Usage: jitter!(5ms) or jitter!(Duration::from_millis(5))
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! jitter {
	($dur:expr) => {
		$crate::testing::timing::TimingConstraint::Jitter($dur)
	};
}

/// Helper macro for slack timing constraint
/// Usage: slack!(2ms) or slack!(Duration::from_millis(2))
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! slack {
	($dur:expr) => {
		$crate::testing::timing::TimingConstraint::Slack($dur)
	};
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

// Removed: AssertionCollector type alias - use TraceCollector directly

// ---------------------------------------------------------------------------
// Instrumentation Mode
// ---------------------------------------------------------------------------

/// Instrumentation mode for tb_scenario!
#[cfg(feature = "instrument")]
#[derive(Clone, Debug)]
pub enum InstrumentationMode {
	/// Automatic: framework initializes and captures events (default)
	Auto,

	/// Manual: user controls init/start/end
	Manual,

	/// Custom: automatic with custom configuration
	Custom {
		enable_payloads: bool,
		enable_internal_detail: bool,
		sample_enabled_sets: bool,
		sample_refusals: bool,
		divergence_heuristics: bool,
		record_durations: bool,
		max_events: u32,
	},
}

#[cfg(feature = "instrument")]
impl Default for InstrumentationMode {
	fn default() -> Self {
		Self::Auto
	}
}

#[cfg(feature = "instrument")]
impl InstrumentationMode {
	/// Get the TbInstrumentationConfig for this mode
	pub fn config(&self) -> crate::instrumentation::TbInstrumentationConfig {
		match self {
			Self::Auto => crate::instrumentation::TbInstrumentationConfig {
				enable_payloads: false,
				enable_internal_detail: true, // Need hidden events for CSP
				sample_enabled_sets: false,
				sample_refusals: false,
				divergence_heuristics: false,
				record_durations: false,
				max_events: 4096,
			},
			Self::Manual => {
				// Manual mode shouldn't call this, but provide safe default
				crate::instrumentation::TbInstrumentationConfig::default()
			}
			Self::Custom {
				enable_payloads,
				enable_internal_detail,
				sample_enabled_sets,
				sample_refusals,
				divergence_heuristics,
				record_durations,
				max_events,
			} => crate::instrumentation::TbInstrumentationConfig {
				enable_payloads: *enable_payloads,
				enable_internal_detail: *enable_internal_detail,
				sample_enabled_sets: *sample_enabled_sets,
				sample_refusals: *sample_refusals,
				divergence_heuristics: *divergence_heuristics,
				record_durations: *record_durations,
				max_events: *max_events,
			},
		}
	}

	/// Should framework auto-initialize?
	pub fn is_auto(&self) -> bool {
		matches!(self, Self::Auto | Self::Custom { .. })
	}
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
/// - instrumentation: TbInstrumentationConfig (OPTIONAL, when feature = "instrument")
/// - hooks { on_pass: |trace| {}, on_fail: |trace, violations| {} } (OPTIONAL)
/// - assert_policies { ... } (TODO: future)
#[macro_export]
macro_rules! tb_scenario {
	// ===== Standalone test with name for ServiceClient =====
	// With tokio: generates #[tokio::test] async function (no runtime.block_on)
	// Without tokio: generates #[test] function with runtime.block_on()
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			worker_threads: $threads:literal,
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks $hooks:tt)?
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() {
			// Execute directly in async context - no runtime.block_on needed

			// Create shared trace collector and clone upfront
			let trace_collector = $crate::trace::TraceCollector::new();
			let trace_server = trace_collector.clone();
			let trace_client = trace_collector.clone();

			// Helper function for server closure to enable type inference
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

			// User's server closure - invoke it with the trace parameter
			let server_setup_result = __call_server_closure($server_closure, trace_server).await;
			let (server_handle, server_addr) = server_setup_result.expect("Server setup failed");

			// Default protocol to TokioListener if not specified
			use $crate::tb_scenario;
			type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

			// Build client transport using the actual server address
			let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
				.expect("Failed to connect to server");
			let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

			// Execute client closure - use helper to enable inference
			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::trace::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			// Collect trace from shared collector
			let mut trace = $crate::trace::ConsumedTrace::new();
			trace.populate_from_collector(&trace_collector);
			trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
			if client_result.is_err() {
				trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
			}

			// Cleanup
			server_handle.abort();

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: $hooks,)?
			};

			if let Err(e) = client_result {
				panic!("Client execution failed: {:?}", e);
			} else if let Err(v) = verification_result {
				panic!("Spec verification failed: {:?}", v);
			}
		}

		#[cfg(not(feature = "tokio"))]
		#[test]
		fn $test_name() {
			tb_scenario!(@execute ServiceClient, single_spec, $spec,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(instrumentation: $instr_cfg,)?
				$(hooks: $hooks,)?
				protocol: { $($protocol)? },
				worker_threads: { $threads },
				server: $server_closure,
				client: $client_closure
			).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Bare environment =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let trace_collector = $crate::trace::TraceCollector::new();

			// Environment-specific execution
			let trace_exec = trace_collector.clone();
			fn __call_exec_closure<F>(
				closure: F,
				trace: $crate::trace::TraceCollector,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace)
			}
			let exec_result = __call_exec_closure($exec_closure, trace_exec);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			let result = $crate::tb_scenario!(@propagate_result exec_result, verification_result);
			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== AFL fuzz target for Bare environment (NO #[test], generates fuzz!) =====
	(
		fuzz: afl,
		spec: $spec:ty,
		csp: $csp:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[allow(unexpected_cfgs)]
		#[cfg(fuzzing)]
		fn main() {
			::afl::fuzz!(|data: &[u8]| {
				// Common setup
				#[cfg(feature = "instrument")]
				let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@init_instrumentation instr_mode);

				// AFL provides the data - use it directly with FuzzContext
				let trace_collector = $crate::trace::TraceCollector::with_fuzz_oracle(
					data.to_vec(),
					<$csp>::process()
				);

				// Environment-specific execution
				let trace_exec = trace_collector.clone();
				fn __call_exec_closure<F>(
					closure: F,
					trace: $crate::trace::TraceCollector,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
				{
					closure(trace)
				}
				let exec_result = __call_exec_closure($exec_closure, trace_exec);

				// Report CSP exploration to IJON (if feature enabled)
				#[cfg(feature = "testing-fuzz-ijon")]
				{
					if exec_result.is_ok() {
						// Use public oracle() method to access oracle context
						let oracle_ctx = trace_collector.oracle();
						::afl::ijon_stack_max!(oracle_ctx.coverage_score());
						::afl::ijon_set!(oracle_ctx.track_state());
						// Track state hash distribution across trace depth
						// old = trace length (how deep), val = current state (where we are)
						let trace_depth = oracle_ctx.trace().len() as u32;
						let state_hash = oracle_ctx.track_state();
						unsafe { ::afl::ijon_hashint(trace_depth, state_hash); }
					}
				}
				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					csp: $csp,
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				// AFL fuzz targets should not panic on failure - just return
				let _ = $crate::tb_scenario!(@propagate_result exec_result, verification_result);
			});
		}

		// Stub main() for IDE - rust-analyzer needs this to see a main() function
		// This is only compiled when NOT fuzzing, so it won't conflict with the generated main() above
		#[allow(unexpected_cfgs)]
		#[cfg(not(fuzzing))]
		#[allow(dead_code)]
		fn main() {
			unreachable!("This main() is only for IDE purposes. The real main() is generated by tb_scenario! macro when cfg(fuzzing) is enabled.")
		}
	};

	// ===== Standalone test with name for Bare environment + fuzz =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		csp: $csp:ty,
		fuzz: $fuzz:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			// Fuzz wrapper handles iteration
			let result = $crate::tb_scenario!(@fuzz_wrapper $fuzz, |fuzz_input| {
				let trace_collector = $crate::trace::TraceCollector::with_fuzz_oracle(
					fuzz_input,
					<$csp>::process()
				);

				// Environment-specific execution
				let trace_exec = trace_collector.clone();
				fn __call_exec_closure<F>(
					closure: F,
					trace: $crate::trace::TraceCollector,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
				{
					closure(trace)
				}
				let exec_result = __call_exec_closure($exec_closure, trace_exec);

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					csp: $csp,
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				$crate::tb_scenario!(@propagate_result exec_result, verification_result)
			});

			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Bare environment (multiple specs) =====
	(
		name: $test_name:ident,
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
				$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
			];

			// Environment-specific execution
			let trace_collector = $crate::trace::TraceCollector::new();
			let trace_exec = trace_collector.clone();
			fn __call_exec_closure<F>(
				closure: F,
				trace: $crate::trace::TraceCollector,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace)
			}
			let exec_result = __call_exec_closure($exec_closure, trace_exec);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				multi_specs: specs,
				trace: trace,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			$crate::tb_scenario!(@propagate_result exec_result, verification_result).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment + fuzz =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		fuzz: $fuzz:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			// Fuzz wrapper handles iteration
			let result = $crate::tb_scenario!(@fuzz_wrapper $fuzz, |fuzz_input| {
				// Environment-specific execution
				let trace_collector = $crate::trace::TraceCollector::new();
				let trace_setup = trace_collector.clone();
				let trace_stimulus = trace_collector.clone();
				let fuzz_for_setup = fuzz_input.clone();
				let fuzz_for_stimulus = fuzz_input.clone();

				// Helper functions to enable type inference
				fn __call_setup_closure<F, W>(
					closure: F,
					trace: $crate::trace::TraceCollector,
					fuzz_input: Vec<u8>,
				) -> W
				where
					F: FnOnce($crate::trace::TraceCollector, Vec<u8>) -> W,
				{
					closure(trace, fuzz_input)
				}

				fn __call_stimulus_closure<F, W>(
					closure: F,
					trace: $crate::trace::TraceCollector,
					worker: &mut W,
					fuzz_input: Vec<u8>,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::trace::TraceCollector, &mut W, Vec<u8>) -> Result<(), $crate::TightBeamError>,
				{
					closure(trace, worker, fuzz_input)
				}

				let mut worker = __call_setup_closure($setup_closure, trace_setup, fuzz_for_setup);
				let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker, fuzz_for_stimulus);

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					$(csp: $csp,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				// Return combined result
				tb_scenario!(@propagate_result exec_result, verification_result)
			});

			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			// Environment-specific execution
			let trace_collector = $crate::trace::TraceCollector::new();
			let trace_setup = trace_collector.clone();
			let trace_stimulus = trace_collector.clone();

			// Helper functions to enable type inference (synchronous)
			fn __call_setup_closure<F, W>(
				closure: F,
				trace: $crate::trace::TraceCollector,
			) -> W
			where
				F: FnOnce($crate::trace::TraceCollector) -> W,
			{
				closure(trace)
			}

			fn __call_stimulus_closure<F, W>(
				closure: F,
				trace: $crate::trace::TraceCollector,
				worker: &mut W,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace, worker)
			}

			let mut worker = __call_setup_closure($setup_closure, trace_setup);
			let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			$crate::tb_scenario!(@propagate_result exec_result, verification_result).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment (multiple specs) =====
	(
		name: $test_name:ident,
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
				$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
			];

			// Environment-specific execution
			let trace_collector = $crate::trace::TraceCollector::new();
			let trace_setup = trace_collector.clone();
			let trace_stimulus = trace_collector.clone();

			// Helper functions to enable type inference (synchronous)
			fn __call_setup_closure<F, W>(
				closure: F,
				trace: $crate::trace::TraceCollector,
			) -> W
			where
				F: FnOnce($crate::trace::TraceCollector) -> W,
			{
				closure(trace)
			}

			fn __call_stimulus_closure<F, W>(
				closure: F,
				trace: $crate::trace::TraceCollector,
				worker: &mut W,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace, worker)
			}

			let mut worker = __call_setup_closure($setup_closure, trace_setup);
			let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				multi_specs: specs,
				trace: trace,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			$crate::tb_scenario!(@propagate_result exec_result, verification_result).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for ServiceClient environment (single spec) =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			const WORKER_THREADS: usize = $crate::tb_scenario!(@default_worker_threads $($threads)?);

			let runtime = tokio::runtime::Builder::new_multi_thread()
				.worker_threads(WORKER_THREADS)
				.enable_all()
				.build()
				.expect("Failed to build tokio runtime");

			let exec_result = runtime.block_on(async {
				let trace_collector = $crate::trace::TraceCollector::new();
				let trace_server = trace_collector.clone();
				let trace_client = trace_collector.clone();

				let server_setup_result: Result<(tokio::task::JoinHandle<()>, _), $crate::TightBeamError> =
					($server_closure)(trace_server).await;
				let (server_handle, server_addr) = server_setup_result?;

				type ProtocolType = $crate::tb_scenario!(@default_protocol $($protocol)?);

				let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await?;
				let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

				async fn __call_client_closure<F, Fut, T>(
					closure: F,
					trace: $crate::trace::TraceCollector,
					client: T,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::trace::TraceCollector, T) -> Fut,
					Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
				{
					closure(trace, client).await
				}
				let client_result = __call_client_closure($client_closure, trace_client, client).await;

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, client_result);

				server_handle.abort();

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					$(csp: $csp,)?
					$(fdr: $fdr_config,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				$crate::tb_scenario!(@propagate_result client_result, verification_result)
			});

			exec_result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for ServiceClient environment (multiple specs) =====
	(
		name: $test_name:ident,
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
				$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
			];

			const WORKER_THREADS: usize = $crate::tb_scenario!(@default_worker_threads $($threads)?);

			let runtime = tokio::runtime::Builder::new_multi_thread()
				.worker_threads(WORKER_THREADS)
				.enable_all()
				.build()
				.expect("Failed to build tokio runtime");

			let exec_result = runtime.block_on(async {
				let trace_collector = $crate::trace::TraceCollector::new();
				let trace_server = trace_collector.clone();
				let trace_client = trace_collector.clone();

				let server_setup_result: Result<(tokio::task::JoinHandle<()>, _), $crate::TightBeamError> =
					($server_closure)(trace_server).await;
				let (server_handle, server_addr) = server_setup_result?;

				type ProtocolType = $crate::tb_scenario!(@default_protocol $($protocol)?);

				let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await?;
				let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

				async fn __call_client_closure<F, Fut, T>(
					closure: F,
					trace: $crate::trace::TraceCollector,
					client: T,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::trace::TraceCollector, T) -> Fut,
					Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
				{
					closure(trace, client).await
				}
				let client_result = __call_client_closure($client_closure, trace_client, client).await;

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, client_result);

				server_handle.abort();

				let verification_result = $crate::__tb_scenario_verify_impl! {
					multi_specs: specs,
					trace: trace,
					$(fdr: $fdr_config,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				$crate::tb_scenario!(@propagate_result client_result, verification_result)
			});

			exec_result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Bare environment variant (single spec: Type form) =====
	(
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute Bare, single_spec, $spec, $(csp: $csp,)? $(fdr: $fdr_config,)? $(instrumentation: $instr_cfg,)? $(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)? exec: $exec_closure)
	};

	// ===== Bare environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {{
		// Common setup
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		// Environment-specific execution
		let trace_collector = $crate::trace::TraceCollector::new();
		let trace_exec = trace_collector.clone();
		fn __call_exec_closure<F>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace)
		}
		let exec_result = __call_exec_closure($exec_closure, trace_exec);

		// Common finalization
		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Worker environment variant (single spec: Type form) =====
	(
		spec: $spec:ty,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {{
		// Common setup
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		// Environment-specific execution
		let trace_collector = $crate::trace::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference (synchronous)
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::trace::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Common finalization
		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Worker environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {{
		// Common setup
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		// Environment-specific execution
		let trace_collector = $crate::trace::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference (synchronous)
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::trace::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Common finalization
		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== ServiceClient environment - user provides complete server setup =====
	// User receives assertions collector for both server and client
	(
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, single_spec, $spec,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(instrumentation: $instr_cfg,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== ServiceClient environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: |$client:ident| $client_body:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, multi_specs, [ $( $spec_expr ),+ ],
			$(fdr: $fdr_config,)?
			$(instrumentation: $instr_cfg,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client_body: |$client| $client_body
		)
	};

	// ===== Internal: Instrumentation helpers =====
	(@get_instr_mode) => {
		$crate::testing::macros::InstrumentationMode::Auto
	};
	(@get_instr_mode $mode:expr) => {
		$mode
	};

	(@init_instrumentation $mode:expr) => {
		#[cfg(feature = "instrument")]
		{
			let mode = &$mode;
			if mode.is_auto() {
				let cfg = mode.config();
				let _ = $crate::instrumentation::active::init(cfg);
				$crate::instrumentation::active::start_trace();
			}
		}
	};

	(@finalize_instrumentation $trace:expr, $mode:expr) => {
		#[cfg(feature = "instrument")]
		{
			let mode = &$mode;
			if mode.is_auto() {
				let artifact = $crate::instrumentation::active::end_trace();
				$trace.instrument_events = artifact.events;
			}
		}
	};

	// ===== Internal: Common trace setup/teardown =====
	(@setup_trace) => {{
		$crate::trace::ConsumedTrace::new()
	}};

	(@finalize_trace $trace:expr, $exec_result:expr) => {{
		$trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
		if $exec_result.is_err() {
			$trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
		}
	}};

	(@with_instrumentation $instr_mode:expr, $body:block) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = $instr_mode;
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		let result = $body;

		result
	}};

	// ===== Common execution logic helper =====
	(@common_exec_logic $exec_result:expr, $spec:tt, $spec_type:tt, $($instr_cfg:expr)?, $($csp:ty)?, $($hooks:block)?) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		let trace_collector = $crate::trace::TraceCollector::new();
		let exec_result = $exec_result;

		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);

		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			$spec_type: $spec,
			trace: trace,
			$($csp: $csp,)?
			$($hooks)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Unified test function generator =====
	(@test_function $test_name:ident, async=$is_async:tt, $($threads:literal)?, $body:block) => {
		#[cfg(feature = "tokio")]
		#[cfg_attr($($threads)?, tokio::test(flavor = "multi_thread", worker_threads = $($threads)?))]
		#[cfg_attr(not($($threads)?), tokio::test)]
		#[cfg(not(feature = "tokio"))]
		#[test]
		fn $test_name() $body
	};

	// ===== Unified test generation dispatcher =====
	(@generate_test $test_name:ident, async=$is_async:tt, worker_threads=$($threads:literal)?, $execution:expr) => {
		tb_scenario!(@test_function $test_name, async=$is_async, worker_threads=$($threads)?, {
			let result = $execution;
			result.expect(concat!("Test failed: ", stringify!($test_name)));
		});
	};

	// ===== Unified execution wrapper =====
	(@common_execution
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		$(csp: $csp:ty,)?
		$spec_type:tt: $spec:tt,
		$trace:expr,
		$exec_result:expr
	) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation $trace, instr_mode);

		tb_scenario!(@finalize_trace $trace, $exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			$spec_type: $spec,
			trace: $trace,
			$(csp: $csp,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result $exec_result, verification_result)
	}};

	// ===== Environment-specific execution dispatchers =====
	(@environment_exec Bare, $trace_collector:expr, $exec_closure:expr) => {{
		let trace_exec = $trace_collector.clone();

		fn __call_exec_closure<F>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace)
		}

		__call_exec_closure($exec_closure, trace_exec)
	}};

	(@environment_exec Worker, $trace_collector:expr, $setup_closure:expr, $stimulus_closure:expr) => {{
		let trace_setup = $trace_collector.clone();
		let trace_stimulus = $trace_collector.clone();

		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::trace::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		__call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker)
	}};

	(@environment_exec ServiceClient, $trace_collector:expr,
		$(protocol: $protocol:path,)?
		worker_threads: $threads:literal,
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		#[cfg(feature = "tokio")]
		{
			let runtime = $crate::testing::macros::__tb_build_multi_thread_runtime($threads)?;

			runtime.block_on($crate::testing::macros::__tb_run_service_client_session::<
				tb_scenario!(@default_protocol $($protocol)?)
			>(
				$trace_collector.clone(),
				$server_closure,
				$client_closure,
			))
		}

		#[cfg(not(feature = "tokio"))]
		{
			tb_scenario!(@execute ServiceClient, single_spec, $spec,
				$(csp: $csp,)?
				$(instrumentation: $instr_cfg,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				protocol: { $($protocol)? },
				worker_threads: { $threads },
				server: $server_closure,
				client: $client_closure
			)
		}
	}};

	(@environment_exec Servlet, $trace_collector:expr,
		servlet: $servlet_name:ident,
		$(start: $start_expr:expr,)?
		client: $client_closure:expr
	) => {{
		#[cfg(feature = "tokio")]
		{
			let trace_server = $trace_collector.clone();
			let trace_client = $trace_collector.clone();

			let servlet_instance = $crate::__tb_scenario_servlet_start!(
				$servlet_name,
				trace_server,
				$($start_expr)?
			);

			let server_addr = servlet_instance.addr();

			let client = async {
				Ok::<_, $crate::TightBeamError>($crate::client! {
					connect $crate::transport::tcp::r#async::TokioListener: server_addr
				})
			}.await.expect("Failed to connect client");

			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::trace::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			servlet_instance.stop();

			client_result
		}
	}};

	// ===== Unified execution generation dispatcher =====
	(@generate_execution $env:tt,
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		$(csp: $csp:ty,)?
		$spec_type:tt: $spec:tt,
		$($env_args:tt)*
	) => {{
		let trace_collector = $crate::trace::TraceCollector::new();

		let exec_result = tb_scenario!(@environment_exec $env, trace_collector, $($env_args)*);

		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		tb_scenario!(@common_execution
			$(instrumentation: $instr_mode,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			$(csp: $csp,)?
			$spec_type: $spec,
			trace,
			exec_result
		)
	}};

	// ===== Execution dispatcher for Bare environment =====
	(@execute Bare, single_spec, $spec:ty, $(csp: $csp:ty,)? $(fdr: $fdr_config:expr,)? $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? exec: $exec_closure:expr) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::trace::TraceCollector::new();
		let trace_exec = trace_collector.clone();

		// Helper function to enable type inference for exec closure (synchronous)
		fn __call_exec_closure<F>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace)
		}

		let exec_result = __call_exec_closure($exec_closure, trace_exec);

		// Populate trace from collector
		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation trace, instr_mode);

		tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Shared fuzz iteration wrapper =====
	// Wraps any test execution in fuzz iteration loop
	(@fuzz_wrapper $fuzz:ty, |$input_var:ident| $test_body:expr) => {{
		use $crate::testing::specs::FuzzSpec;

		let mut successes = 0usize;
		let mut failures = 0usize;
		let test_cases = <$fuzz>::test_cases();

		for iteration in 0..test_cases {
			// Generate fuzz input for this iteration
			let $input_var = <$fuzz>::generate_input(iteration);

			// Execute test body with fuzz input
			let result: Result<(), $crate::TightBeamError> = $test_body;

			// Track results
			if result.is_ok() {
				successes += 1;
			} else {
				failures += 1;
			}
		}

		// Report statistics
		let success_rate = (successes as f64 / test_cases as f64) * 100.0;
		let min_rate = <$fuzz>::min_success_rate();

		if <$fuzz>::print_stats() {
			println!("\nFuzz test results:");
			println!("  Test cases: {}", test_cases);
			println!("  Successes: {} ({:.1}%)", successes, success_rate);
			println!("  Failures: {} ({:.1}%)", failures, (failures as f64 / test_cases as f64) * 100.0);
			println!("  Required: >= {:.1}%", min_rate);
		}

		// Verify fuzzer can generate valid inputs at configured rate
		assert!(
			success_rate >= min_rate,
			"Fuzz test failed: only {:.1}% success rate (expected >= {:.1}%). \
			 Fuzzer unable to consistently generate valid inputs. \
			 Successes: {}, Failures: {}, Total: {}",
			success_rate,
			min_rate,
			successes,
			failures,
			test_cases
		);

		Ok::<(), $crate::TightBeamError>(())
	}};

	// ===== Execution dispatcher for Worker environment =====
	(@execute Worker, single_spec, $spec:ty, $(fdr: $fdr_config:expr,)? $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? setup: $setup_closure:expr, stimulus: $stimulus_closure:expr) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::trace::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference (synchronous)
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::trace::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Populate trace from collector
		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation trace, instr_mode);

		tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	(@execute Worker, multi_specs, [ $( $spec_expr:expr ),+ ], $(fdr: $fdr_config:expr,)? $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? setup: $setup_closure:expr, stimulus: $stimulus_closure:expr) => {{
		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::trace::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::trace::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::trace::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::trace::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Populate trace from collector
		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation trace, instr_mode);

		tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== ServiceClient environment (returns Result) =====
	// User provides complete server setup, returns Result for composition
	(
		spec: $spec:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, single_spec, $spec,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== ServiceClient environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, multi_specs, [ $( $spec_expr ),+ ],
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== Execution dispatcher for ServiceClient environment =====
	(@execute ServiceClient, single_spec, $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		worker_threads: { $($threads:literal)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		#[allow(unused_imports)]
		use std::sync::{Arc, Mutex};

		const WORKER_THREADS: usize = tb_scenario!(@default_worker_threads $($threads)?);

		let runtime = $crate::testing::macros::__tb_build_multi_thread_runtime(WORKER_THREADS)?;

		let exec_result = runtime.block_on(async {
			#[cfg(feature = "instrument")]
			let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
			#[cfg(feature = "instrument")]
			tb_scenario!(@init_instrumentation instr_mode);

			let trace_collector = $crate::trace::TraceCollector::new();

			let client_result = $crate::testing::macros::__tb_run_service_client_session::<
				tb_scenario!(@default_protocol $($protocol)?)
			>(
				trace_collector.clone(),
				$server_closure,
				$client_closure,
			)
			.await;

			let mut trace = tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);

			#[cfg(feature = "instrument")]
			tb_scenario!(@finalize_instrumentation trace, instr_mode);

			tb_scenario!(@finalize_trace trace, client_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			tb_scenario!(@propagate_result client_result, verification_result)
		});

		exec_result
	}};

	(@execute ServiceClient, multi_specs, [ $( $spec_expr:expr ),+ ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		worker_threads: { $($threads:literal)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		#[allow(unused_imports)]
		use std::sync::Arc;

		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		const WORKER_THREADS: usize = tb_scenario!(@default_worker_threads $($threads)?);

		let runtime = $crate::testing::macros::__tb_build_multi_thread_runtime(WORKER_THREADS)?;

		let exec_result = runtime.block_on(async {
			#[cfg(feature = "instrument")]
			let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
			#[cfg(feature = "instrument")]
			tb_scenario!(@init_instrumentation instr_mode);

			let result = tb_scenario!(@execute_service_client_async multi_specs, specs,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				protocol: { $($protocol)? },
				server: $server_closure,
				client: $client_closure
			);

			result
		});

		exec_result
	}};

	// ===== Async ServiceClient execution (single spec) =====
	(@execute_service_client_async single_spec, $spec:ty,
		$(fdr: $fdr_config:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

		let bind_addr = <ProtocolType as $crate::transport::Protocol>::default_bind_address()?;
		let (listener, addr) = <ProtocolType as $crate::transport::Protocol>::bind(bind_addr).await?;

		let server_handle = ($server_closure)(listener);

		let stream = <ProtocolType as $crate::transport::Protocol>::connect(addr).await?;
		let mut client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

		let client_result = ($client_closure)(&mut client).await;

		let mut trace = tb_scenario!(@setup_trace);
		tb_scenario!(@finalize_trace trace, client_result);

		server_handle.abort();

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result client_result, verification_result)
	}};

	// ===== Async ServiceClient execution (multi specs) =====
	(@execute_service_client_async multi_specs, $specs:expr,
		$(fdr: $fdr_config:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

		let bind_addr = <ProtocolType as $crate::transport::Protocol>::default_bind_address()?;
		let (listener, addr) = <ProtocolType as $crate::transport::Protocol>::bind(bind_addr).await?;

		let server_handle = ($server_closure)(listener);

		let stream = <ProtocolType as $crate::transport::Protocol>::connect(addr).await?;
		let mut client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

		let client_result = ($client_closure)(&mut client).await;

		let mut trace = tb_scenario!(@setup_trace);
		tb_scenario!(@finalize_trace trace, client_result);

		server_handle.abort();

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: $specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result client_result, verification_result)
	}};

	// ===== AFL fuzz target for Servlet environment (NO #[test], generates fuzz!) =====
	(
		fuzz: afl,
		spec: $spec:ty,
		csp: $csp:ty,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Servlet {
			servlet: $servlet_name:ident,
			$(start: $start_expr:expr,)?
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		$crate::tb_scenario! {
			spec: $spec,
			csp: $csp,
			fuzz: afl,
			$(fdr: $fdr_config,)?
			$(instrumentation: $instr_cfg,)?
			environment Servlet {
				servlet: $servlet_name,
				$(start: $start_expr,)?
				client: $client_closure
			}
			$(, hooks {
				$(on_pass: $on_pass,)?
				$(on_fail: $on_fail)?
			})?
		}
	};
	(
		spec: $spec:ty,
		csp: $csp:ty,
		fuzz: afl,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Servlet {
			servlet: $servlet_name:ident,
			$(start: $start_expr:expr,)?
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[allow(unexpected_cfgs)]
		#[cfg(fuzzing)]
		fn main() {
			::afl::fuzz!(|data: &[u8]| {
				// Common setup
				#[cfg(feature = "instrument")]
				let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@init_instrumentation instr_mode);

				// AFL provides the data - use it directly with FuzzContext
				let trace_collector = $crate::trace::TraceCollector::with_fuzz_oracle(
					data.to_vec(),
					<$csp>::process()
				);

				let runtime = tokio::runtime::Builder::new_current_thread()
					.enable_all()
					.build()
					.expect("Failed to create tokio runtime");

				let exec_result = runtime.block_on(async {
				let trace_client = trace_collector.clone();
				let trace_server = trace_collector.clone();

				let mut servlet_instance = $crate::__tb_scenario_servlet_start!(
					$servlet_name,
					trace_server.clone(),
					$($start_expr)?
				);
				servlet_instance.set_trace(trace_server.clone());

				$crate::tb_scenario!(@reset_servlet_state $servlet_name, &servlet_instance);

				let server_addr = servlet_instance.addr();

				// Wrap client creation in an async block that returns Result
				let client = async {
					Ok::<_, $crate::TightBeamError>($crate::client! {
						connect $crate::transport::tcp::r#async::TokioListener: server_addr
					})
				}.await.expect("Failed to connect client");

				// Execute client closure
				async fn __call_client_closure<F, Fut, T>(
					closure: F,
					trace: $crate::trace::TraceCollector,
					client: T,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::trace::TraceCollector, T) -> Fut,
					Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
				{
					closure(trace, client).await
				}
				let client_result = __call_client_closure($client_closure, trace_client, client).await;

				servlet_instance.stop();

				client_result
			});

				// Report CSP exploration to IJON (if feature enabled)
				#[cfg(feature = "testing-fuzz-ijon")]
				{
					if exec_result.is_ok() {
						// Use public oracle() method to access oracle context
						let oracle_ctx = trace_collector.oracle();
						::afl::ijon_stack_max!(oracle_ctx.coverage_score());
						::afl::ijon_set!(oracle_ctx.track_state());
						// Track state hash distribution across trace depth
						let trace_depth = oracle_ctx.trace().len() as u32;
						let state_hash = oracle_ctx.track_state();
						unsafe { ::afl::ijon_hashint(trace_depth, state_hash); }
					}
				}

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					csp: $csp,
					$(fdr: $fdr_config,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				// AFL fuzz targets should not panic on failure - just return
				let _ = $crate::tb_scenario!(@propagate_result exec_result, verification_result);
			});
		}

		// Stub main() for IDE - rust-analyzer needs this to see a main() function
		// This is only compiled when NOT fuzzing, so it won't conflict with the generated main() above
		#[cfg(not(fuzzing))]
		#[allow(dead_code)]
		fn main() {
			unreachable!("This main() is only for IDE purposes. The real main() is generated by tb_scenario! macro when cfg(fuzzing) is enabled.")
		}
	};

	// ===== Servlet environment variant =====
	// Servlet is defined at module scope, test environment starts it
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Servlet {
			servlet: $servlet_name:ident,
			$(start: $start_expr:expr,)?
			client: $client_closure:expr
		}
		$(, hooks $hooks:tt)?
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() {
			// Create trace collector
			let trace_collector = $crate::trace::TraceCollector::new();
			let trace_client = trace_collector.clone();
			let trace_server = trace_collector.clone();

			// Start servlet - use custom start expression or default start(trace_server)
			let servlet_instance = $crate::__tb_scenario_servlet_start!(
				$servlet_name,
				trace_server,
				$($start_expr)?
			);

			// Get servlet address and create client
			let server_addr = servlet_instance.addr();

			// Wrap client creation in an async block that returns Result
			let client = async {
				Ok::<_, $crate::TightBeamError>($crate::client! {
					connect $crate::transport::tcp::r#async::TokioListener: server_addr
				})
			}.await.expect("Failed to connect client");

			// Execute client closure
			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::trace::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::trace::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			// Stop servlet
			servlet_instance.stop();

			// Collect trace
			let mut trace = $crate::trace::ConsumedTrace::new();
			trace.populate_from_collector(&trace_collector);
			trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
			if client_result.is_err() {
				trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
			}

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: $hooks,)?
			};

			if let Err(e) = client_result {
				panic!("Client execution failed: {:?}", e);
			} else if let Err(v) = verification_result {
				panic!("Spec verification failed: {:?}", v);
			}
		}
	};	// ===== Helper dispatchers for defaults =====
	(@default_worker_threads) => { 2 };
	(@default_worker_threads $threads:literal) => { $threads };

	(@default_protocol) => { $crate::transport::tcp::r#async::TokioListener };
	(@default_protocol $protocol:path) => { $protocol };

	// ===== CSP validation helper =====
	(@csp_validate $trace:expr, $csp:ty) => {{
		let csp_spec = <$csp>::default();
		Some(<$csp as $crate::testing::specs::csp::ProcessSpec>::validate_trace(&csp_spec, &$trace))
	}};
	(@csp_validate $trace:expr,) => {{
		None::<$crate::testing::specs::csp::CspValidationResult>
	}};

	// ===== FDR validation helper =====
	(@fdr_validate_with_config $trace:expr, $fdr_config:expr) => {{
		#[cfg(feature = "testing-fdr")]
		{
			use $crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};

			let config: FdrConfig = {
				$fdr_config.into()
			};
			let trace_process = $trace.to_process();

			// FdrExplorer checks: config.specs ⊑ process (spec ⊑ impl)
			// We want to check: spec_process ⊑ trace_process
			// So we set trace_process as the main process and config.specs as the spec
			// The config.specs should already contain the specification processes
			let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, config.clone());
			(Some(explorer.explore()), Some(config))
		}
		#[cfg(not(feature = "testing-fdr"))]
		{
			compile_error!("FDR validation requires testing-fdr feature");
		}
	}};
	(@fdr_validate_with_config $trace:expr,) => {{
		(None::<$crate::testing::fdr::FdrVerdict>, None::<$crate::testing::fdr::FdrConfig>)
	}};
	(@fdr_validate $trace:expr, $fdr_config:expr) => {{
		#[cfg(feature = "testing-fdr")]
		{
			use $crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};

			let config: FdrConfig = {
				$fdr_config.into()
			};
			let trace_process = $trace.to_process();

			// FdrExplorer checks: config.specs ⊑ process (spec ⊑ impl)
			// We want to check: spec_process ⊑ trace_process
			// So we set trace_process as the main process and config.specs as the spec
			// The config.specs should already contain the specification processes
			let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, config);
			Some(explorer.explore())
		}
		#[cfg(not(feature = "testing-fdr"))]
		{
			compile_error!("FDR validation requires testing-fdr feature");
		}
	}};
	(@fdr_validate $trace:expr,) => {{
		None::<$crate::testing::fdr::FdrVerdict>
	}};

	// ===== Servlet state reset helper (for fuzzing) =====
	// This macro resets servlet state before each fuzz iteration
	// For chess servlet: resets game_state in shared Arc
	// For other servlets: may need servlet-specific reset logic
	(@reset_servlet_state ChessEngineServlet, $servlet:expr) => {
		// Chess servlet: reset shared GAME_STATE Arc
		// Calls reset_chess_game_state() function defined at module level in chess/test.rs
		let _ = $servlet; // Suppress unused warning
		// The reset_chess_game_state() function must be defined at module level in the test file
		// This macro expansion will call it - compilation will fail if function doesn't exist
		reset_chess_game_state();
	};
	(@reset_servlet_state $servlet_name:ident, $servlet:expr) => {
		// Default: no-op (servlet-specific resets can be added)
		let _ = $servlet; // Suppress unused warning
	};

	// ===== Shared result propagation logic =====
	(@propagate_result $exec_result:ident, $verification_result:ident) => {
		if let Err(e) = $exec_result {
			Err(e)
		} else if let Err(_v) = $verification_result {
			panic!("Spec verification failed: {:?}", _v);
		} else {
			Ok(())
		}
	};

	// Catch-all for unrecognized syntax
	($($tt:tt)*) => {
		compile_error!("Unrecognized tb_scenario! syntax; expected: name: test_name, spec: Type, environment <Variant> { ... }");
	};
}

/// Helper macro for starting servlets in tb_scenario!
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_scenario_servlet_start {
	// Custom start expression provided
	($servlet:ident, $trace:expr, $start:expr) => {{
		($start)($trace).await.expect("Failed to start servlet")
	}};
	// Default: call start with trace collector
	($servlet:ident, $trace:expr,) => {{
		$servlet::start($trace).await.expect("Failed to start servlet")
	}};
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
pub fn __tb_build_multi_thread_runtime(
	worker_threads: usize,
) -> Result<tokio::runtime::Runtime, crate::TightBeamError> {
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(worker_threads)
		.enable_all()
		.build()?;

	Ok(runtime)
}

#[cfg(feature = "tokio")]
#[doc(hidden)]
pub async fn __tb_run_service_client_session<Protocol, ServerFn, ServerFut, ClientFn, ClientFut>(
	trace_collector: crate::trace::TraceCollector,
	server_closure: ServerFn,
	client_closure: ClientFn,
) -> Result<(), crate::TightBeamError>
where
	Protocol: crate::transport::Protocol<Address = crate::transport::tcp::TightBeamSocketAddr>,
	ServerFn: FnOnce(crate::trace::TraceCollector) -> ServerFut,
	ServerFut: core::future::Future<
		Output = Result<
			(tokio::task::JoinHandle<()>, crate::transport::tcp::TightBeamSocketAddr),
			crate::TightBeamError,
		>,
	>,
	ClientFn: FnOnce(crate::trace::TraceCollector, <Protocol as crate::transport::Protocol>::Transport) -> ClientFut,
	ClientFut: core::future::Future<Output = Result<(), crate::TightBeamError>>,
{
	let trace_server = trace_collector.clone();
	let trace_client = trace_collector;

	let (server_handle, server_addr) = server_closure(trace_server).await?;

	let stream = <Protocol as crate::transport::Protocol>::connect(server_addr)
		.await
		.map_err(|err| crate::TightBeamError::from(err.into()))?;
	let client = <Protocol as crate::transport::Protocol>::create_transport(stream);

	let client_result = client_closure(trace_client, client).await;

	server_handle.abort();

	client_result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tb_assert_spec;
	use crate::tb_scenario;
	use crate::testing::create_test_message;
	use crate::testing::utils::TestMessage;
	use crate::trace::ExecutionMode;
	use crate::trace::TraceCollector;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::MessageEmitter;
	use crate::transport::Protocol;

	#[test]
	fn cardinality_basic() {
		let c = Cardinality::between(1, 3);
		assert!(c.is_satisfied_by(2));
		assert!(!c.is_satisfied_by(0));
		assert!(!c.is_satisfied_by(4));
	}

	#[test]
	fn builder_duplicate_label() -> Result<(), Box<dyn std::error::Error>> {
		let b = AssertSpecBuilder::new("spec", ExecutionMode::Accept)
			.assertion("L1", vec![], Cardinality::exactly(1))?
			.assertion("L1", vec![], Cardinality::exactly(2));
		assert!(matches!(b, Err(SpecBuildError::DuplicateLabel("L1"))));
		Ok(())
	}

	tb_assert_spec! {
		pub DemoSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", exactly!(1)),
				("Responded", exactly!(1))
			]
		},
		V(1,1,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", exactly!(1)),
				("Responded", exactly!(2))
			]
		},
	}

	tb_assert_spec! {
		pub ClientServerSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", exactly!(2)),
				("Responded", exactly!(2)),
				("message_content", exactly!(1), equals!("Hello TightBeam!"))
			]
		},
	}

	#[test]
	fn hash_differs_across_versions() {
		let h1 = DemoSpec::get(1, 0, 0).unwrap().spec_hash();
		let h2 = DemoSpec::get(1, 1, 0).unwrap().spec_hash();
		assert_ne!(h1, h2);
	}

	#[test]
	fn latest_points_to_highest() {
		assert_eq!(DemoSpec::latest().version(), (1, 1, 0));
	}

	tb_scenario! {
		name: scenario_bare_with_hooks,
		spec: DemoSpec,
		environment Bare {
			exec: |trace| {
				trace.event("Received");
				trace.event("Responded");
				trace.event("Responded");
				Ok(())
			}
		}
	}

	tb_scenario! {
		name: scenario_bare_specific_version,
		specs: [DemoSpec::get(1, 0, 0)],
		environment Bare {
			exec: |trace| {
				trace.event("Received");
				trace.event("Responded");
				Ok(())
			}
		}
	}

	#[test]
	#[should_panic(expected = "Spec verification failed")]
	fn scenario_bare_multiple_versions() {
		// Suppress panic output for cleaner test output
		std::panic::set_hook(Box::new(|_| {}));

		// Test against both versions - v1.1.0 expects exactly 2 Responded, we only emit 1
		// Should panic because v1.1.0 expects 2 Response but we only emitted 1
		let _result = tb_scenario! {
			specs: [DemoSpec::get(1, 0, 0), DemoSpec::get(1, 1, 0)],
			environment Bare {
				exec: |trace| {
					trace.event("Received");
					trace.event("Responded");
					Ok(())
				}
			}
		};
	}

	// Simple worker struct for testing
	struct TestWorker {
		received_count: usize,
		trace: TraceCollector,
	}

	impl TestWorker {
		fn new(trace: TraceCollector) -> Self {
			Self { received_count: 0, trace }
		}

		fn process(&mut self) -> Result<(), crate::TightBeamError> {
			self.trace.event("Received");
			self.received_count += 1;
			self.trace.event("Responded");
			self.trace.event("Responded");
			Ok(())
		}
	}

	tb_scenario! {
		name: scenario_worker_basic,
		spec: DemoSpec,
		environment Worker {
			setup: TestWorker::new,
			stimulus: |_trace, worker: &mut TestWorker| worker.process()
		}
	}

	tb_scenario! {
		name: scenario_worker_specific_version,
		specs: [DemoSpec::get(1, 0, 0)],
		environment Worker {
			setup: TestWorker::new,
			stimulus: |trace, worker: &mut TestWorker| {
				trace.event("Received");
				worker.received_count += 1;
				trace.event("Responded");
				Ok(())
			}
		}
	}

	// ServiceClient tests require async runtime and transport features
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	tb_scenario! {
		name: scenario_service_client_basic,
		spec: DemoSpec,
		environment ServiceClient {
			worker_threads: 2,
			server: |trace: TraceCollector| async move {
				let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
				let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace,
					handle: |frame, trace| async move {
						trace.event("Received");
						trace.event("Responded");
						trace.event("Responded");
						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |_trace: TraceCollector, mut client| async move {
				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				Ok(())
			}
		}
	}

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	static HOOK_CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	tb_scenario! {
		name: scenario_service_client_with_client_assertions_and_hooks,
		spec: ClientServerSpec,
		environment ServiceClient {
			worker_threads: 2,
			server: |trace: TraceCollector| async move {
				let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
				let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace,
					handle: |frame, trace| async move {
						// Server-side assertions
						trace.event("Received");
						trace.event("Responded");

						// Decode message to extract value for assertion
						let decoded: Result<TestMessage, _> = crate::decode(&frame.message);
						if let Ok(msg) = decoded {
							trace.event_with("message_content", &[], msg.content);
						}

						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |trace, mut client| async move {
				// Client-side assertion before sending
				trace.event("Responded");

				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
					}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.event("Received");

				Ok(())
			}
		},
		hooks {
			on_pass: |_trace| {
				HOOK_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
			},
			on_fail: |_trace, violations| {
				panic!("Test should not fail! Violations: {violations:?}");
			}
		}
	}
}
