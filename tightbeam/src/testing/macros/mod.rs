//! The testing macro layer: the `tb_scenario!` entry point and the macros and
//! functions that its expansion calls.
//!
//! - Layer 1 (assertions) has its macro in `verification_spec`.
//! - Layer 2 (CSP) has its macro in `process_spec`.
//! - Layer 3 (FDR) runs inside `tb_scenario!`.

// The `tb_process_spec!` macro of Layer 2 (CSP).
pub mod process_spec;
// The `tb_compose_spec!` macro of Layer 2 (CSP composition).
pub mod compose_spec;
// The opt-in `tb_gen_process_types!` macro, which generates the state and
// event types of a process for fault injection.
pub mod gen_states;
// The timing-constraint macros that `tb_process_spec!` and `tb_assert_spec!`
// use.
pub mod timing_spec;
// The `tb_assert_spec!` macro of Layer 1 (assertions).
pub mod verification_spec;

pub use timing_spec::DeadlineParams;
pub use verification_spec::{
	versions_strictly_ascending, AssertSpecBuilder, BuiltAssertSpec, Cardinality, SpecBuildError,
};

pub use crate::testing::assertions::{AssertionValue, IsNone, IsSome, Presence, RatioLimit};
pub use crate::trace::TraceCollector;
pub use crate::{absent, at_least, at_most, between, equals, exactly, falsy, present, truthy};

#[cfg(feature = "testing-timing")]
pub use verification_spec::SchedulabilityAssertion;

/// Wraps a value as the expected value of an equality assertion in a spec.
#[macro_export]
macro_rules! equals {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::from($value))
	};
}

/// Builds the boolean assertion value of a spec that holds when the value is
/// truthy, which means it compares unequal to 0.
#[macro_export]
macro_rules! truthy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value != 0))
	};
}

/// Builds the boolean assertion value of a spec that holds when the value is
/// falsy, which means it compares equal to 0.
#[macro_export]
macro_rules! falsy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value == 0))
	};
}

/// Builds a ratio limit from a numerator and a denominator, each cast to
/// `u64`.
#[macro_export]
macro_rules! ratio {
	($numer:expr, $denom:expr) => {
		$crate::testing::assertions::RatioLimit(($numer) as u64, ($denom) as u64)
	};
}

// The `tb_scenario!` expansion calls the functions below.

/// Calls an async scenario closure with its environment struct, so the
/// concrete environment type drives the inference of the closure's parameter.
#[doc(hidden)]
pub async fn __tb_env_call<E, F, Fut, T>(closure: F, env: E) -> Result<T, crate::TightBeamError>
where
	F: FnOnce(E) -> Fut,
	Fut: core::future::Future<Output = Result<T, crate::TightBeamError>>,
{
	closure(env).await
}

/// Hands one fuzz input to a raw target.
///
/// A named function lets the compiler check the closure's argument type at
/// the definition. Inside the `afl::fuzz!` expansion, a mismatch would report
/// against the macro.
#[doc(hidden)]
pub fn __tb_call_raw_fuzz<F: FnOnce(&[u8])>(target: F, data: impl AsRef<[u8]>) {
	let data = data.as_ref();
	target(data);
}

/// Calls a synchronous scenario closure with its environment struct.
#[doc(hidden)]
pub fn __tb_env_call_sync<E, F, T>(closure: F, env: E) -> T
where
	F: FnOnce(E) -> T,
{
	closure(env)
}

/// Runs the exec closure of the Pipeline environment, and maps its
/// `Result<T, TightBeamError>` to `Result<(), TightBeamError>`.
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

/// Binds the configuration a scenario runs, or fails the test with the reason
/// for the refusal.
///
/// `tb_scenario!` binds a configuration in each environment arm. This is the
/// one place that decides what a refusal does, so every arm shares its
/// message.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_accept_config {
	($config:expr) => {
		match $config {
			Ok(accepted) => accepted,
			Err(refused) => ::core::panic!("scenario configuration refused: {}", refused),
		}
	};
}

/// Binds the configuration of a guided fuzz run, whose CSP process comes from
/// the `csp:` key alone, or fails the run with the reason for the refusal.
///
/// The oracle and the CSP layer then read one process, because
/// `ScenarioConfig::guided_by` refuses a configuration that names another.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_accept_guided_config {
	($csp_type:ty, $config:expr) => {
		$crate::__tb_accept_config!(
			($config).and_then(|config| config.guided_by(<$csp_type as ::core::default::Default>::default()))
		)
	};
}

/// The scenario entry point, which verifies an AssertSpec (and optionally CSP
/// and FDR) under a selectable execution environment.
///
/// Each closure takes one parameter, a struct from [`crate::testing::env`] in
/// every environment but Pipeline. Its `trace` shares a [`TraceCollector`] (a
/// [`FuzzTraceCollector`] under `fuzz: afl`), and its `context` is `Arc<C>`
/// (`Arc<()>` without `context:`). Name it `env`, or destructure it.
///
/// # Environments
///
/// - Bare: `exec: |env|` runs sync or as `async move` ([`SetupEnv`]).
/// - Pipeline: `exec: |pipeline|` receives a [`PipelineBuilder`].
/// - Worker: the sync `setup: |env|` returns the builder ([`SetupEnv`]), and
///   the async `stimulus: |env|` owns the started worker ([`WorkerEnv`]).
/// - Servlet: the async `start: |env|` returns the servlet ([`SetupEnv`]).
///   The optional async `setup: |env|` returns a connected client
///   ([`ClientEnv`]), and without it a plain [`TokioListener`] client
///   connects. The async `client: |env|` receives a [`ServletEnv`].
/// - ServiceClient: the async `server: |env|` returns
///   `(JoinHandle, TightBeamSocketAddr)` ([`SetupEnv`]). The async
///   `client: |env|` connects through `env.addr` ([`ClientEnv`]). The
///   optional `worker_threads: N` runs the test on N runtime worker threads.
/// - Cluster: the async `start: |env|` returns the cluster ([`SetupEnv`]).
///   The optional `hives: |env|` returns hive futures that `tb_scenario!`
///   awaits and registers ([`SetupEnv`]). The async `client: |env|` owns the
///   cluster ([`ClusterEnv`]).
/// - Hive: the async `start: |env|` returns the hive ([`SetupEnv`]), and the
///   async `client: |env|` owns it ([`HiveEnv`]).
///
/// # Top-level keys
///
/// - `name:` names the test function, and a scenario with `fuzz: afl` omits it.
/// - `spec:` takes an AssertSpec type and grades with its latest version, or
///   `config:` takes the result of [`ScenarioConfigBuilder::build`].
/// - The optional `fuzz: afl` makes the scenario an AFL target (Bare, Servlet,
///   Hive, or Cluster). Each of those environments wraps `afl::fuzz!` and
///   passes a [`FuzzTraceCollector`] into the same runner the named test uses,
///   so each AFL iteration verifies its specs and its CSP process. The key
///   needs the `testing-fuzz` feature and `csp:`, the one process that steers
///   the oracle and grades the CSP layer. A `config:` that also names a
///   process fails the run when it starts, and a scenario with an environment
///   and no `csp:` fails to compile.
///
/// # Environment-block keys
///
/// - `context:` is a fixture that the test evaluates once and shares as `Arc<C>`.
///
/// [`SetupEnv`]: crate::testing::env::SetupEnv
/// [`ClientEnv`]: crate::testing::env::ClientEnv
/// [`WorkerEnv`]: crate::testing::env::WorkerEnv
/// [`ServletEnv`]: crate::testing::env::ServletEnv
/// [`ClusterEnv`]: crate::testing::env::ClusterEnv
/// [`HiveEnv`]: crate::testing::env::HiveEnv
/// [`TraceCollector`]: crate::trace::TraceCollector
/// [`FuzzTraceCollector`]: crate::testing::fuzz::FuzzTraceCollector
/// [`PipelineBuilder`]: crate::utils::task::PipelineBuilder
/// [`ScenarioConfigBuilder::build`]: crate::testing::ScenarioConfigBuilder::build
/// [`TokioListener`]: crate::transport::tcp::async::TokioListener
#[macro_export]
macro_rules! tb_scenario {
	// The `spec:` form expands to the `config:` form.
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
			// The guided arms take the process from `csp:` alone, and both the
			// oracle and the CSP layer read it.
			config: $crate::testing::ScenarioConfig::builder()
				.with_spec(<$spec>::latest())
				.build(),
			$($rest)*
		}
	};

	// The fuzz variant that feeds raw bytes into a decoder, outside an oracle
	// and a scenario. A decoder's contract is that arbitrary bytes produce a
	// typed error, so the one property under test is that the body returns.
	(
		fuzz: afl,
		raw: $body:expr
		$(,)?
	) => {
		$crate::__tb_select_fuzzing! {
			{
				fn main() {
					afl::fuzz!(|data: &[u8]| {
						$crate::testing::macros::__tb_call_raw_fuzz($body, data);
					});
				}
			}
			{
				fn main() {
					// Smoke build: this main compiles with no AFL and runs the
					// target once, so it catches a decoder that fails on an
					// empty input.
					$crate::testing::macros::__tb_call_raw_fuzz($body, &[]);
				}
			}
		}
	};

	// The fuzz variant of a guided target with no `csp:`, which fails to
	// compile, as the `fuzz: afl` key of the macro doc states.
	(
		fuzz: afl,
		$(spec: $spec:ty,)?
		$(config: $config:expr,)?
		environment $($rest:tt)*
	) => {
		::core::compile_error!(
			"tb_scenario! with fuzz: afl needs a csp: parameter, the CSP process that guides the run"
		);
	};

	// The internal arm that grades a finished scenario.
	(@grade $config:expr, $trace:expr, $exec_result:expr) => {
		// An AFL iteration whose input runs out drives only a prefix of a run.
		// A grade of that prefix would report every short mutation as a
		// violation.
		if $exec_result.as_ref().err().is_some_and(|error| error.is_fuzz_input_exhausted()) {
			return;
		}

		let collector = ::core::convert::AsRef::<$crate::trace::TraceCollector>::as_ref(&$trace);
		let built = $crate::testing::HookContext::build(&$config, collector, $exec_result);
		// A refused exploration event leaves the scenario ungraded, so the
		// test fails on the error rather than on a verdict.
		let hook_ctx = match built {
			::core::result::Result::Ok(hook_ctx) => hook_ctx,
			::core::result::Result::Err(error) => ::core::panic!("Scenario verification failed: {}", error),
		};
		$crate::tb_scenario!(@verify_and_call_hooks $config, hook_ctx);
	};

	// The internal arm that reads the verdict and calls the hooks.
	(@verify_and_call_hooks $config:expr, $hook_ctx:expr) => {
		// This arm reads the verdict once. Every layer reaches it through
		// `ScenarioVerdict::explored`, and the body's own result reaches it
		// through Layer 1.
		match $hook_ctx.outcome() {
			Err(violations) => {
				if let Some(hooks) = $config.hooks() {
					if let Some(on_fail) = hooks.rejected() {
						on_fail(&$hook_ctx, violations);
					}
				}

				panic!("Scenario verification failed: {}", violations);
			}
			Ok(()) => {
				if let Some(hooks) = $config.hooks() {
					if let Some(on_pass) = hooks.accepted() {
						on_pass(&$hook_ctx);
					}
				}
			}
		}
	};

	// The internal sync AFL mains, which the Bare `fuzz: afl` arm uses. Both
	// mains forward into the same `@run_*` body and differ only in the oracle's
	// input bytes, so the fuzzing path always runs spec and CSP verification.
	// Without `--cfg fuzzing` the smoke main runs one empty-input iteration,
	// which keeps `config` and `exec` used under an IDE and `cargo check`.
	(@afl_sync
		csp: $csp_type:ty,
		config: $config:expr,
		@$run:ident
		$($run_body:tt)*
	) => {
		$crate::__tb_select_fuzzing! {
			{
				fn main() {
					afl::fuzz!(|data: &[u8]| {
						let process = <$csp_type>::process();
						let config = $crate::__tb_accept_guided_config!($csp_type, $config);
						let trace = $crate::testing::fuzz::FuzzTraceCollector::new(data.to_vec(), process);
						$crate::tb_scenario!(@$run
							config: config,
							trace: trace,
							$($run_body)*
						)
					});
				}
			}
			{
				fn main() {
					let process = <$csp_type>::process();
					let config = $crate::__tb_accept_guided_config!($csp_type, $config);
					let trace = $crate::testing::fuzz::FuzzTraceCollector::new(::std::vec::Vec::new(), process);
					$crate::tb_scenario!(@$run
						config: config,
						trace: trace,
						$($run_body)*
					)
				}
			}
		}
	};

	// The fuzz variant that generates the `fn main()` AFL target of the Bare
	// environment.
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

	// The fuzz variant that generates the `fn main()` AFL target of the
	// Servlet environment.
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

	// The internal Tokio AFL mains, which the Servlet, Hive, and Cluster
	// `fuzz: afl` arms use. Each iteration builds a `FuzzTraceCollector`, over
	// empty bytes in the smoke main, and forwards into the matching `@run_*`
	// body. The AFL main creates its Tokio runtime inside the fuzz closure, so
	// no worker thread is live before AFL's forkserver handoff.
	(@afl_async
		csp: $csp_type:ty,
		config: $config:expr,
		label: $label:literal,
		@$run:ident
		$($run_body:tt)*
	) => {
		$crate::__tb_select_tokio! {
			{
				$crate::__tb_select_fuzzing! {
					{
						fn main() {
							afl::fuzz!(|data: &[u8]| {
								// An iteration with no runtime tests
								// nothing, so it panics, and AFL records
								// the panic as a crash.
								let built = tokio::runtime::Builder::new_current_thread().enable_all().build();
								let runtime = match built {
									Ok(runtime) => runtime,
									Err(error) => panic!("the AFL harness could not build its Tokio runtime: {error}"),
								};
								runtime.block_on(async {
									let process = <$csp_type>::process();
									let config = $crate::__tb_accept_guided_config!($csp_type, $config);
									let trace =
										$crate::testing::fuzz::FuzzTraceCollector::new(data.to_vec(), process);
									$crate::tb_scenario!(@$run
										config: config,
										trace: trace,
										$($run_body)*
									)
								});
							});
						}
					}
					{
						#[tokio::main]
						async fn main() {
							let process = <$csp_type>::process();
							let config = $crate::__tb_accept_guided_config!($csp_type, $config);
							let trace =
								$crate::testing::fuzz::FuzzTraceCollector::new(::std::vec::Vec::new(), process);
							$crate::tb_scenario!(@$run
								config: config,
								trace: trace,
								$($run_body)*
							)
						}
					}
				}
			}
			{
				::core::compile_error!(concat!($label, " AFL target requires the tokio feature"));
			}
		}
	};

	// The fuzz variant that generates the AFL target of the Hive environment.
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

	// The fuzz variant that generates the AFL target of the Cluster
	// environment.
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

	// The Bare environment with an async exec.
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

	// The Bare environment with a sync exec.
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
			let config = $crate::__tb_accept_config!($config);
			let trace = config.trace();
			$crate::tb_scenario!(@run_bare_sync
				config: config,
				trace: trace,
				context: [ $($context)? ],
				exec: $exec_closure
			)
		}
	};

	// The Pipeline environment, which is sync.
	// `exec` receives a `PipelineBuilder` with its trace context set, and it
	// returns `Result<T, TightBeamError>` straight from `.run()`.
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

	// The Worker environment, which is async.
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

	// The Servlet environment, which is async.
	(
		name: $test_name:ident,
		config: $config:expr,
		environment Servlet { $($env_body:tt)* }
		$(,)?
	) => {
		$crate::__tb_if_tokio! {
			#[tokio::test]
			async fn $test_name() {
				let config = $crate::__tb_accept_config!($config);
				let trace = config.trace();
				$crate::tb_scenario!(@run_servlet
					config: config,
					trace: trace,
					environment Servlet { $($env_body)* }
				)
			}
		}
	};

	// The ServiceClient environment with `worker_threads`.
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

	// The ServiceClient environment.
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

	// The Cluster environment, which is async.
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
				let config = $crate::__tb_accept_config!($config);
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

	// The Hive environment, which is async.
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
				let config = $crate::__tb_accept_config!($config);
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

	// The internal runner of the async Bare environment.
	(@run_bare_async
		config: $config:expr,
		context: [ $($context:expr)? ],
		exec: |$env:pat_param| async move $exec_body:block
	) => {{
		let config = $crate::__tb_accept_config!($config);
		let trace = config.trace();
		let env = $crate::testing::env::SetupEnv {
			trace: trace.share(),
			context: ::std::sync::Arc::new(($($context)?)),
		};

		let exec_result = $crate::testing::macros::__tb_env_call(|$env| async move $exec_body, env).await;

		$crate::tb_scenario!(@grade config, trace, exec_result);
	}};

	// The internal runner of the sync Bare environment, whose caller supplies
	// `trace`: a named test passes `config.trace()` and an AFL arm passes
	// `FuzzTraceCollector::new(...)`, so both reach the one verification below.
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

		$crate::tb_scenario!(@grade config, trace, exec_result);
	}};

	// The internal runner of the Pipeline environment.
	(@run_pipeline
		config: $config:expr,
		exec: $exec_closure:expr
	) => {{
		use $crate::utils::task::PipelineBuilder;

		let config = $crate::__tb_accept_config!($config);
		let trace = config.trace();

		let pipeline = PipelineBuilder::new(std::sync::Arc::clone(&trace));

		let exec_result = $crate::testing::macros::__tb_call_pipeline_exec($exec_closure, pipeline);

		$crate::tb_scenario!(@grade config, trace, exec_result);
	}};

	// The internal runner of the Worker environment.
	(@run_worker
		config: $config:expr,
		context: [ $($context:expr)? ],
		setup: $setup_closure:expr,
		stimulus: $stimulus_closure:expr
	) => {{
		let config = $crate::__tb_accept_config!($config);
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

		$crate::tb_scenario!(@grade config, trace, exec_result);
	}};

	// The internal setup of the default Servlet client, for a block with no
	// `setup:` key.
	(@servlet_client $trace:expr, $context:expr, $addr:expr) => {{
		use $crate::transport::tcp::r#async::TokioListener;
		use $crate::transport::{ClientBuilder, ConnectionBuilder};

		// The default servlet scenario provisions no trust store, so the
		// scenario runs in the clear, and `allow_cleartext` says so.
		let builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
		builder
			.connect($addr)
			.await
			.expect("Failed to setup servlet client (default)")
	}};
	// The internal Servlet client setup through a custom closure.
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

	// The internal runner of the Servlet environment.
	// The caller supplies `trace`, as for `@run_bare_sync`.
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
		let stop_servlet = $crate::testing::Teardown::new(move || servlet_instance.stop());

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

		stop_servlet.run();

		$crate::tb_scenario!(@grade config, trace, client_result);
	}};

	// The internal runner of the ServiceClient environment.
	(@run_service_client
		config: $config:expr,
		context: [ $($context:expr)? ],
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		let config = $crate::__tb_accept_config!($config);
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

		let stop_server = $crate::testing::Teardown::new(move || server_handle.abort());

		let client_result = $crate::testing::macros::__tb_env_call(
			$client_closure,
			$crate::testing::env::ClientEnv {
				trace: trace.share(),
				context,
				addr: server_addr,
			},
		)
		.await;

		stop_server.run();

		$crate::tb_scenario!(@grade config, trace, client_result);
	}};

	// The internal runner of the Cluster environment, whose `client` owns the
	// cluster for registry assertions and the consuming `stop`. The caller
	// supplies `trace` as for `@run_bare_sync`, so the oracle runs through the
	// same path as Bare.
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

		// Each hive stop is type-erased as a consuming closure, so the list
		// has one type whether or not the scenario starts hives.
		#[allow(unused_mut)]
		let mut hive_stops: Vec<$crate::testing::Teardown> = Vec::new();
		$(
			let cluster_addr = cluster_instance.addr().clone();
			let hive_futures = $crate::testing::macros::__tb_env_call_sync(
				$hives_closure,
				$crate::testing::env::SetupEnv {
					trace: trace.share(),
					context: ::std::sync::Arc::clone(&context),
				},
			);
			for hive_future in hive_futures {
				let hive = hive_future.await.expect("Failed to start hive");
				hive.register_with_cluster(&cluster_addr).await.expect("Failed to register hive");
				hive_stops.push($crate::testing::Teardown::new(move || hive.stop()));
			}
		)?

		// The cluster client owns the instance. Teardown runs in the closure
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
			stop_hive.run();
		}

		$crate::tb_scenario!(@grade config, trace, client_result);
	}};

	// The internal runner of the Hive environment, which runs as Cluster does
	// and skips the registration. The caller supplies `trace`, as for
	// `@run_cluster`.
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

		// The hive client owns the instance. Teardown runs in the closure
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

		$crate::tb_scenario!(@grade config, trace, client_result);
	}};
}

crate::__tb_if_test! {
	crate::__tb_if_testing_csp! {
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
			// assertion failures: `on_fail` runs before the panic, so logging
			// and cleanup hooks observe the regression.
			#[test]
			fn csp_failure_invokes_on_fail_before_panicking() -> Result<(), crate::TightBeamError> {
				let failed = Arc::new(AtomicBool::new(false));
				let observed = Arc::clone(&failed);
				let hooks = TestHooks::on_fail(move |_context, _violations| {
						observed.store(true, Ordering::SeqCst);
					});

				let config = crate::__tb_accept_config!(
					ScenarioConfig::builder().with_csp(AlwaysInvalidSpec).with_hooks(hooks).build()
				);
				let trace = config.trace();
				let hook_ctx = HookContext::build(&config, &trace, Ok::<(), crate::TightBeamError>(()))?;
				let outcome = catch_unwind(AssertUnwindSafe(|| {
					crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx);
				}));

				assert!(outcome.is_err());
				assert!(failed.load(Ordering::SeqCst));
				Ok(())
			}

			struct AlwaysValidSpec;

			impl ProcessSpec for AlwaysValidSpec {
				fn validate_trace(&self, _trace: &ConsumedTrace) -> CspValidationResult {
					CspValidationResult { valid: true, violations: Vec::new() }
				}

				fn to_process_cow(&self) -> Cow<'_, Process> {
					let process = Process::builder("always_valid")
						.initial_state(State("start"))
						.build()
						.expect("single-state process builds");
					Cow::Owned(process)
				}
			}

			// A scenario that every layer accepts returns, and `on_pass` runs.
			#[test]
			fn a_passing_scenario_invokes_on_pass_and_returns() -> Result<(), crate::TightBeamError> {
				let passed = Arc::new(AtomicBool::new(false));
				let observed = Arc::clone(&passed);
				let hooks = TestHooks::on_pass(move |_context| {
						observed.store(true, Ordering::SeqCst);
					});

				let config = crate::__tb_accept_config!(
					ScenarioConfig::builder().with_csp(AlwaysValidSpec).with_hooks(hooks).build()
				);

				let trace = config.trace();
				let hook_ctx = HookContext::build(&config, &trace, Ok::<(), crate::TightBeamError>(()))?;
				let outcome = catch_unwind(AssertUnwindSafe(|| {
					crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx);
				}));

				assert!(outcome.is_ok());
				assert!(passed.load(Ordering::SeqCst));
				Ok(())
			}
		}
	}
}
