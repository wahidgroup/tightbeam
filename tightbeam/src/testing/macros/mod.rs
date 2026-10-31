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
// The timing-constraint macros of `tb_process_spec!` and `tb_assert_spec!`.
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
/// truthy (unequal to 0).
#[macro_export]
macro_rules! truthy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value != 0))
	};
}

/// Builds the boolean assertion value of a spec that holds when the value is
/// falsy (equal to 0).
#[macro_export]
macro_rules! falsy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value == 0))
	};
}

/// Builds a ratio limit from a numerator and a denominator, each cast to `u64`.
#[macro_export]
macro_rules! ratio {
	($numer:expr, $denom:expr) => {
		$crate::testing::assertions::RatioLimit(($numer) as u64, ($denom) as u64)
	};
}

/// The output of the server task of a ServiceClient scenario.
///
/// The runner aborts the task at teardown and then joins it, so a server that
/// failed during the run fails the test.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::macros::ServerOutcome;
///
/// assert_eq!(().failure(), None);
/// assert_eq!(Err::<(), &str>("bound twice").failure(), Some("\"bound twice\"".to_string()));
/// ```
#[cfg(feature = "tokio")]
pub trait ServerOutcome: Sized {
	/// The failure that the task ended with, or `None` when it ended cleanly.
	fn failure(self) -> Option<String>;

	/// Settles the server task that the runner joined after its abort.
	///
	/// A task that ran until the abort, or that ended cleanly, settles.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::macros::ServerOutcome;
	///
	/// // A server that ended cleanly settles.
	/// <()>::settle(Ok(()));
	/// ```
	///
	/// # Panics
	///
	/// Testing suite functions MUST panic on error.
	///
	/// - The task panicked, and the panic resumes with its own payload.
	/// - The task ended with a failure, and the panic names it.
	fn settle(joined: Result<Self, crate::runtime::rt::JoinError>) {
		match joined {
			Ok(outcome) => {
				if let Some(failure) = outcome.failure() {
					panic!("the server of the scenario failed: {failure}");
				}
			}
			Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
			// Teardown's abort ended a live server, which is its expected end.
			Err(_cancelled) => {}
		}
	}
}

#[cfg(feature = "tokio")]
impl ServerOutcome for () {
	fn failure(self) -> Option<String> {
		None
	}
}

#[cfg(feature = "tokio")]
impl<E: core::fmt::Debug> ServerOutcome for Result<(), E> {
	fn failure(self) -> Option<String> {
		self.err().map(|error| format!("{error:?}"))
	}
}

// The `tb_scenario!` expansion calls the functions below.

/// Calls an async scenario closure with its environment struct, so the
/// compiler infers the closure's parameter from the concrete environment type.
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
/// A named function makes the compiler report a mismatch of the closure's
/// argument type at the definition, not against the `afl::fuzz!` expansion.
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
	pipeline: crate::task::PipelineBuilder,
) -> Result<(), crate::TightBeamError>
where
	F: FnOnce(crate::task::PipelineBuilder) -> Result<T, crate::TightBeamError>,
{
	closure(pipeline).map(|_| ())
}

/// Binds the configuration a scenario runs, or fails the test with the refusal.
///
/// Each environment arm of `tb_scenario!` binds its configuration here, so
/// every arm shares one refusal message.
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
/// the `csp:` key alone, or fails the run with the refusal.
///
/// The oracle and the CSP layer read one process, because
/// `ScenarioConfig::guided_by` refuses a configuration that names one.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_accept_guided_config {
	($csp_type:ty, $config:expr) => {
		$crate::__tb_accept_config!(
			($config).and_then(|config| config.guided_by(<$csp_type as ::core::default::Default>::default()))
		)
	};
}

/// Binds the process of a guided fuzz run, or fails the run with the reason
/// that the process does not build.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_accept_process {
	($process:expr) => {
		match $process {
			Ok(process) => process,
			Err(refused) => ::core::panic!("the CSP process of the guided run does not build: {}", refused),
		}
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
///   `(JoinHandle<T>, TightBeamSocketAddr)` ([`SetupEnv`]), where `T` is a
///   [`ServerOutcome`]. The async `client: |env|` connects through
///   `env.addr` ([`ClientEnv`]). The optional `worker_threads: N` runs the
///   test on N runtime worker threads.
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
///   Hive, or Cluster). The target wraps `afl::fuzz!` and passes a
///   [`FuzzTraceCollector`] into the runner of the named test, so each
///   iteration verifies the specs and the CSP process. The key needs the
///   `testing-fuzz` feature and `csp:`, the one process that steers the oracle
///   and grades the CSP layer. A `config:` that also names a process fails the
///   run at start, and an environment with no `csp:` fails to compile.
///
/// # Environment-block keys
///
/// - `context:` is a fixture that the test evaluates once and shares as `Arc<C>`.
///
/// # Panics
///
/// Testing suite functions MUST panic on error. A scenario panics, and so
/// fails its test, when:
///
/// - [`ScenarioConfigBuilder::build`] or [`ScenarioConfig::guided_by`] refuses its configuration.
/// - The process of a guided fuzz run does not build.
/// - A setup closure fails, such as a worker, a servlet, a server, a cluster, or a hive that does not start.
/// - The server task of a ServiceClient run fails or panics ([`ServerOutcome::settle`]).
/// - The grade refuses an exploration event, or a layer decides against what the scenario expects.
///
/// [`SetupEnv`]: crate::testing::env::SetupEnv
/// [`ClientEnv`]: crate::testing::env::ClientEnv
/// [`WorkerEnv`]: crate::testing::env::WorkerEnv
/// [`ServletEnv`]: crate::testing::env::ServletEnv
/// [`ClusterEnv`]: crate::testing::env::ClusterEnv
/// [`HiveEnv`]: crate::testing::env::HiveEnv
/// [`TraceCollector`]: crate::trace::TraceCollector
/// [`FuzzTraceCollector`]: crate::testing::fuzz::FuzzTraceCollector
/// [`PipelineBuilder`]: crate::task::PipelineBuilder
/// [`ScenarioConfigBuilder::build`]: crate::testing::ScenarioConfigBuilder::build
/// [`ScenarioConfig::guided_by`]: crate::testing::ScenarioConfig::guided_by
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

	// The fuzz variant that feeds raw bytes into a decoder, with no oracle and
	// no scenario. A decoder turns arbitrary bytes into a typed error, so the
	// one property under test is that the body returns.
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
					// Smoke build: without AFL, this main runs the target once,
					// which catches a decoder that fails on an empty input.
					$crate::testing::macros::__tb_call_raw_fuzz($body, &[]);
				}
			}
		}
	};

	// The guided fuzz variant with no `csp:`, which fails to compile.
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

	// The internal sync AFL mains of the Bare `fuzz: afl` arm. Both forward
	// into the same `@run_*` body and differ only in the oracle's input bytes,
	// so the fuzzing path always verifies the specs and the CSP process.
	// Without `--cfg fuzzing`, the smoke main runs one empty-input iteration,
	// so `config` and `exec` stay used under an IDE and `cargo check`.
	(@afl_sync
		csp: $csp_type:ty,
		config: $config:expr,
		@$run:ident
		$($run_body:tt)*
	) => {
		$crate::__tb_select_fuzzing! {
			{
				fn main() {
					// The run builds its configuration and its process
					// once, so each iteration grades against the claims
					// the build checked. Each iteration clones both, so a
					// panic in one leaves them whole for the next.
					let config = ::std::panic::AssertUnwindSafe($crate::__tb_accept_guided_config!($csp_type, $config));
					let process = ::std::panic::AssertUnwindSafe($crate::__tb_accept_process!(<$csp_type>::process()));
					afl::fuzz!(|data: &[u8]| {
						let trace = $crate::testing::fuzz::FuzzTraceCollector::new(data.to_vec(), process.0.clone());
						$crate::tb_scenario!(@$run
							config: config.0.clone(),
							trace: trace,
							$($run_body)*
						)
					});
				}
			}
			{
				fn main() {
					let config = $crate::__tb_accept_guided_config!($csp_type, $config);
					let process = $crate::__tb_accept_process!(<$csp_type>::process());
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

	// The internal Tokio AFL mains of the Servlet, Hive, and Cluster
	// `fuzz: afl` arms. Each iteration builds a `FuzzTraceCollector` (over
	// empty bytes in the smoke main) and forwards into the matching `@run_*`
	// body. The AFL main builds its Tokio runtime inside the fuzz closure, so
	// no worker thread is live before the AFL forkserver handoff.
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
							// As in the sync mains, the run builds its
							// configuration and its process once, and each
							// iteration clones both.
							let config =
								::std::panic::AssertUnwindSafe($crate::__tb_accept_guided_config!($csp_type, $config));
							let process =
								::std::panic::AssertUnwindSafe($crate::__tb_accept_process!(<$csp_type>::process()));
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
									let trace =
										$crate::testing::fuzz::FuzzTraceCollector::new(data.to_vec(), process.0.clone());
									$crate::tb_scenario!(@$run
										config: config.0.clone(),
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
							let config = $crate::__tb_accept_guided_config!($csp_type, $config);
							let process = $crate::__tb_accept_process!(<$csp_type>::process());
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

	// The Pipeline environment, which is sync. Its `exec` receives a
	// `PipelineBuilder` with its trace context set, and it returns
	// `Result<T, TightBeamError>` straight from `.run()`.
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

	// The internal runner of the sync Bare environment. The caller supplies
	// `trace`, `config.trace()` from a named test or a `FuzzTraceCollector`
	// from an AFL arm, so both reach the one verification below.
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
		use $crate::task::PipelineBuilder;

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
	// The internal setup of a Servlet client through the `setup:` closure.
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

	// The internal runner of the Servlet environment, whose caller supplies
	// `trace` as for `@run_bare_sync`.
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

		let server_abort = server_handle.abort_handle();
		let stop_server = $crate::testing::Teardown::new(move || server_abort.abort());

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
		$crate::testing::macros::ServerOutcome::settle(server_handle.await);

		$crate::tb_scenario!(@grade config, trace, client_result);
	}};

	// The internal runner of the Cluster environment, whose `client` owns the
	// cluster for registry assertions and the consuming `stop`. Its caller
	// supplies `trace` as for `@run_bare_sync`, so the oracle runs as in Bare.
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

	// The internal runner of the Hive environment: Cluster without the
	// registration. The caller supplies `trace`, as for `@run_cluster`.
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
			use std::panic::{catch_unwind, AssertUnwindSafe};
			use std::sync::atomic::{AtomicBool, Ordering};
			use std::sync::Arc;

			use crate::testing::fixtures::TestProcess;
			use crate::testing::specs::csp::ProcessSpec;
			use crate::testing::{HookContext, ScenarioConfig, TestHooks};

			/// Whether grading a run with no event under `spec` and `hooks`
			/// panicked.
			fn grading_panics(spec: impl ProcessSpec + Send + Sync + 'static, hooks: TestHooks) -> bool {
				let built = ScenarioConfig::builder().with_csp(spec).with_hooks(hooks).build();
				let config = crate::__tb_accept_config!(built);
				let trace = config.trace();
				let built = HookContext::build(&config, &trace, Ok::<(), crate::TightBeamError>(()));
				let hook_ctx = built.expect("a run with no event grades");
				let outcome = catch_unwind(AssertUnwindSafe(|| {
					crate::tb_scenario!(@verify_and_call_hooks config, hook_ctx);
				}));

				outcome.is_err()
			}

			/// Hooks whose failure observer raises the flag they take.
			type FailureHooks = fn(Arc<AtomicBool>) -> TestHooks;

			// Layer 2 CSP failures travel the failure path of Layer 1
			// assertion failures: `on_fail` runs before the panic, so logging
			// and cleanup hooks observe the regression. A failure observer runs
			// alone, and beside a pass observer when `with_on_fail` adds it.
			crate::tb_cases! {
				fn csp_failure_invokes_on_fail_before_panicking(hooks: FailureHooks) {
					let failed = Arc::new(AtomicBool::new(false));
					let observed = hooks(Arc::clone(&failed));

					let panicked = grading_panics(TestProcess::of("Refusing", "S0").build(), observed);

					assert_eq!((panicked, failed.load(Ordering::SeqCst)), (true, true));
				}

				cases {
					alone => |failed| {
						TestHooks::on_fail(move |_context, _violations| failed.store(true, Ordering::SeqCst))
					},
					beside_a_pass_observer => |failed| {
						let passing = TestHooks::on_pass(|_context| {});
						passing.with_on_fail(move |_context, _violations| failed.store(true, Ordering::SeqCst))
					},
				}
			}

			/// A scenario that every layer accepts returns, and `on_pass` runs.
			#[test]
			fn a_passing_scenario_invokes_on_pass_and_returns() {
				let passed = Arc::new(AtomicBool::new(false));
				let observed = Arc::clone(&passed);
				let hooks = TestHooks::on_pass(move |_context| {
					observed.store(true, Ordering::SeqCst);
				});

				let panicked = grading_panics(TestProcess::idle(), hooks);

				assert_eq!((panicked, passed.load(Ordering::SeqCst)), (false, true));
			}
		}
	}
}

/// The one-request client that the scenario tests of the macros and of the
/// CSP specs share.
#[cfg(all(test, feature = "tcp", feature = "tokio"))]
pub(crate) mod fixtures {
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::{EndpointConfig, MessageEmitter, Protocol};
	use crate::{Frame, TightBeamError};

	/// Sends `request` to the server at `addr` over a cleartext connection,
	/// and returns the answer of the server.
	pub(crate) async fn send_one(addr: TightBeamSocketAddr, request: Frame) -> Result<Option<Frame>, TightBeamError> {
		let stream = <TokioListener as Protocol>::connect(addr).await?;
		let mut client = <TokioListener as Protocol>::create_transport(stream, EndpointConfig::cleartext());
		Ok(client.emit(request, None).await?)
	}
}

#[cfg(test)]
mod outcome_tests {
	use crate::testing::TestFrame;
	use crate::trace::{ConsumedTrace, Exchange, Presence, TraceCollector};
	use crate::Frame;

	/// The request and the response of one exchange, as distinct frames.
	fn frames() -> (Frame, Frame) {
		(TestFrame::v0(None, Some("request")), TestFrame::v0(None, Some("response")))
	}

	/// The exchange in which `response` answered `request`.
	fn answered(request: &Frame, response: &Frame) -> Exchange {
		Exchange::Accepted { request: request.clone(), response: Some(Box::new(response.clone())) }
	}

	/// The trace of a run whose client recorded `exchanges` in order.
	fn traced(exchanges: Vec<Exchange>) -> ConsumedTrace {
		let collector = TraceCollector::new();
		exchanges.into_iter().for_each(|exchange| collector.record_exchange(exchange));
		ConsumedTrace::drained_from(&collector)
	}

	/// An accepted exchange records its request and its response.
	#[test]
	fn an_accepted_exchange_records_its_request_and_its_response() {
		let (request, response) = frames();
		let trace = traced(vec![answered(&request, &response)]);
		assert_eq!((trace.accepted_frame(), trace.response()), (Some(&request), Some(&response)));
	}

	/// A rejected exchange records its request as the rejected frame alone.
	#[test]
	fn a_rejected_exchange_records_its_request() {
		let (request, _) = frames();
		let trace = traced(vec![Exchange::Rejected { request: request.clone() }]);
		assert_eq!((trace.rejected_frame(), trace.accepted_frame()), (Some(&request), None));
	}

	/// The response of a run is the first response that arrived.
	#[test]
	fn the_response_of_a_run_is_the_first_that_arrived() {
		let (request, response) = frames();
		let trace = traced(vec![answered(&request, &response), answered(&request, &request)]);
		assert_eq!(trace.response(), Some(&response));
	}

	/// A trace that already holds a response keeps it over the response of the
	/// collector it drains.
	#[test]
	fn a_trace_keeps_its_own_response_over_a_drained_one() {
		let (request, response) = frames();
		let collector = TraceCollector::new();
		collector.record_exchange(answered(&request, &request));

		let mut trace = ConsumedTrace::new();
		trace.record_accepted(response.clone(), Some(response.clone()));
		trace.populate_from_collector(&collector);
		assert_eq!(trace.response(), Some(&response));
	}

	// A run reports whether a response arrived from the exchanges that its
	// client recorded.
	crate::tb_cases! {
		fn a_run_reports_the_presence_of_its_response((exchanges, presence): (Vec<Exchange>, Option<Presence>)) {
			let trace = traced(exchanges);
			let reported = trace.response_presence();
			assert_eq!(reported, presence);
		}

		cases {
			with_no_exchange => (Vec::new(), None),
			after_a_refused_request => (vec![Exchange::Rejected { request: frames().0 }], Some(Presence::Absent)),
		}
	}
}

#[cfg(all(test, feature = "tcp", feature = "tokio"))]
mod scenario_outcome_tests {
	use core::future::Future;
	use std::sync::Arc;

	use tokio::sync::Notify;

	use super::fixtures::send_one;
	use super::ServerOutcome;
	use crate::runtime::rt::JoinHandle;
	use crate::testing::{ClientEnv, Expect, Layer, ScenarioConfig, SetupEnv, TestFrame};
	use crate::trace::{Exchange, TraceCollector};
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::Protocol;
	use crate::urn::Urn;
	use crate::{exactly, tb_assert_spec, Frame, TightBeamError};

	const STEP: Urn<'static> = crate::urn!("test", "event:outcome/step");

	tb_assert_spec! {
		pub AnsweredSpec,
		V(1,0,0): {
			mode: Accept,
			response: Present,
			assertions: [
				(STEP, exactly!(1))
			]
		}
	}

	tb_assert_spec! {
		pub UnansweredSpec,
		V(1,0,0): {
			mode: Accept,
			response: Absent,
			assertions: [
				(STEP, exactly!(1))
			]
		}
	}

	tb_assert_spec! {
		pub SteppedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(STEP, exactly!(1))
			]
		}
	}

	/// Starts a server that answers each request with the request itself.
	async fn echo_server() -> Result<(JoinHandle, TightBeamSocketAddr), TightBeamError> {
		let loopback = <TokioListener as Protocol>::default_bind_address()?;
		let (listener, addr) = <TokioListener as Protocol>::bind_cleartext(loopback).await?;
		let handle = crate::server! {
			protocol TokioListener: listener,
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		};

		Ok((handle, addr))
	}

	/// Sends one request to the server at `addr`, records `STEP`, and records
	/// into `trace` how the server answered.
	async fn echo_exchange(trace: TraceCollector, addr: TightBeamSocketAddr) -> Result<(), TightBeamError> {
		let request = TestFrame::v0(None, Some("request"));
		let response = send_one(addr, request.clone()).await?;

		trace.event(STEP)?;
		trace.record_exchange(Exchange::Accepted { request, response: response.map(Box::new) });
		Ok(())
	}

	/// Starts a server task that signals `ended` and then fails.
	///
	/// A house server fails only on a fault of its transport, which a test
	/// cannot raise on demand, so this stand-in fails at once.
	async fn failed_server(
		ended: Arc<Notify>,
	) -> Result<(tokio::task::JoinHandle<Result<(), TightBeamError>>, TightBeamSocketAddr), TightBeamError> {
		let loopback = <TokioListener as Protocol>::default_bind_address()?;
		let (_listener, addr) = <TokioListener as Protocol>::bind_cleartext(loopback).await?;
		let handle = tokio::spawn(async move {
			ended.notify_one();
			Err(TightBeamError::MissingConfiguration)
		});

		Ok((handle, addr))
	}

	/// Starts a server task that signals `ended` and then panics.
	///
	/// A house server panics only on a defect of its own, so this stand-in
	/// panics at once.
	async fn panicked_server(ended: Arc<Notify>) -> Result<(JoinHandle, TightBeamSocketAddr), TightBeamError> {
		let loopback = <TokioListener as Protocol>::default_bind_address()?;
		let (_listener, addr) = <TokioListener as Protocol>::bind_cleartext(loopback).await?;
		let handle = tokio::spawn(async move {
			ended.notify_one();
			panic!("the scenario server broke");
		});

		Ok((handle, addr))
	}

	/// Waits until the server task signals `ended`, and then records `STEP`.
	async fn stepped_after(trace: TraceCollector, ended: Arc<Notify>) -> Result<(), TightBeamError> {
		ended.notified().await;
		trace.event(STEP)?;
		Ok(())
	}

	// A response that arrives breaks a spec that forbids one.
	tb_scenario! {
		name: a_response_that_arrives_breaks_a_spec_that_forbids_one,
		config: ScenarioConfig::builder()
			.with_spec(UnansweredSpec::latest())
			.with_expect(Expect::Violation(Layer::Assertion))
			.build(),
		environment ServiceClient {
			server: |_env: SetupEnv| echo_server(),
			client: |ClientEnv { trace, addr, .. }| echo_exchange(trace, addr)
		}
	}

	// A response that arrives meets a spec that requires one.
	tb_scenario! {
		name: a_response_that_arrives_meets_a_spec_that_requires_one,
		config: ScenarioConfig::builder().with_spec(AnsweredSpec::latest()).build(),
		environment ServiceClient {
			server: |_env: SetupEnv| echo_server(),
			client: |ClientEnv { trace, addr, .. }| echo_exchange(trace, addr)
		}
	}

	/// The text that a ServiceClient scenario panics with over the server
	/// that `server` starts.
	async fn panic_of<S, F, T>(server: S) -> String
	where
		S: FnOnce(Arc<Notify>) -> F + Send + 'static,
		F: Future<Output = Result<(tokio::task::JoinHandle<T>, TightBeamSocketAddr), TightBeamError>> + Send,
		T: ServerOutcome + Send + 'static,
	{
		let run = tokio::spawn(async move {
			crate::tb_scenario!(@run_service_client
				config: ScenarioConfig::builder().with_spec(SteppedSpec::latest()).build(),
				context: [ Notify::new() ],
				server: move |SetupEnv { context, .. }| server(context),
				client: |ClientEnv { trace, context, .. }| stepped_after(trace, context)
			)
		});

		let joined = run.await.expect_err("the scenario ends in a panic");
		let payload = joined.try_into_panic().expect("the scenario task runs to its panic");
		let borrowed = payload.downcast_ref::<&str>().map(|text| text.to_string());

		let text = borrowed.or_else(|| payload.downcast_ref::<String>().cloned());
		text.expect("the panic payload holds text")
	}

	/// A server that failed fails the scenario with its failure.
	#[tokio::test]
	async fn a_server_that_failed_fails_the_scenario_with_its_failure() {
		let payload = panic_of(failed_server).await;
		assert_eq!(payload, "the server of the scenario failed: MissingConfiguration");
	}

	/// A server that panicked fails the scenario with its own panic.
	#[tokio::test]
	async fn a_server_that_panicked_fails_the_scenario_with_its_own_panic() {
		let payload = panic_of(panicked_server).await;
		assert_eq!(payload, "the scenario server broke");
	}
}
