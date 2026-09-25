//! Teardown runs when the scenario body panics
//!
//! A test fails by panicking, so the statement after the client closure is
//! the one a failing run skips. These tests drive an internal `tb_scenario!`
//! arm down that path and check the scenario still released what it started.

#![cfg(all(feature = "testing", feature = "tokio"))]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use tightbeam::testing::{ClientEnv, HiveEnv, ScenarioConfig, ServletEnv, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, TightBeamError};
use tokio::time::sleep;

#[cfg(feature = "colony")]
use tightbeam::colony::worker::Worker;
#[cfg(feature = "colony")]
use tightbeam::der::Sequence;
#[cfg(feature = "colony")]
use tightbeam::testing::{ClusterEnv, WorkerEnv};
#[cfg(feature = "colony")]
use tightbeam::Beamable;
#[cfg(feature = "colony")]
use tokio::time::timeout;

const SERVER_UP: Urn<'static> = tightbeam::urn!("test", "event:teardown/server-up");

tb_assert_spec! {
	pub ServerUpSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [ (SERVER_UP, exactly!(1)) ]
	}
}

/// Advances `ticks` until the task is aborted, so the counter standing still
/// is the observable form of "the accept task was torn down".
async fn count_until_aborted(ticks: Arc<AtomicU64>) {
	loop {
		ticks.fetch_add(1, Ordering::SeqCst);
		sleep(Duration::from_millis(1)).await;
	}
}

/// Whether `ticks` stands still once the runtime has retired whatever was
/// advancing it.
async fn stands_still(ticks: &AtomicU64) -> bool {
	sleep(Duration::from_millis(50)).await;
	let settled = ticks.load(Ordering::SeqCst);
	sleep(Duration::from_millis(50)).await;

	ticks.load(Ordering::SeqCst) == settled
}

/// A value an arm hands to its closure. Its drop is the observable form of
/// "the arm released what it was holding".
struct Released(Arc<AtomicBool>);

impl Drop for Released {
	fn drop(&mut self) {
		self.0.store(true, Ordering::SeqCst);
	}
}

#[tokio::test]
async fn a_panicking_bare_async_body_still_releases_the_context() {
	let released = Arc::new(AtomicBool::new(false));
	let guard = Released(Arc::clone(&released));
	let scenario = async move {
		tb_scenario!(@run_bare_async
			config: ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build(),
			context: [ guard ],
			exec: |SetupEnv { trace, .. }| async move {
				trace.event(SERVER_UP)?;
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the exec closure's panic must reach the caller");
	assert!(released.load(Ordering::SeqCst), "the scenario context outlived the scenario");
}

#[test]
fn a_panicking_bare_sync_body_still_releases_the_context() {
	let released = Arc::new(AtomicBool::new(false));
	let guard = Released(Arc::clone(&released));
	let scenario = move || {
		let scenario_config = ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build();
		let config = tightbeam::__tb_accept_config!(scenario_config);
		let trace = config.trace();

		tb_scenario!(@run_bare_sync
			config: config,
			trace: trace,
			context: [ guard ],
			exec: |SetupEnv { trace, .. }: SetupEnv<Released>| {
				trace.event(SERVER_UP)?;
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = catch_unwind(AssertUnwindSafe(scenario));
	assert!(outcome.is_err(), "the exec closure's panic must reach the caller");
	assert!(released.load(Ordering::SeqCst), "the scenario context outlived the scenario");
}

#[test]
fn a_panicking_pipeline_body_still_releases_the_trace() {
	let scenario_config = ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build();
	let config = tightbeam::__tb_accept_config!(scenario_config);
	let held = config.trace();
	let scenario = move || {
		tb_scenario!(@run_pipeline
			config: Ok::<_, TightBeamError>(config),
			exec: |_pipeline| -> Result<(), TightBeamError> {
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = catch_unwind(AssertUnwindSafe(scenario));
	assert!(outcome.is_err(), "the exec closure's panic must reach the caller");
	assert_eq!(Arc::strong_count(&held), 1, "the pipeline's trace share outlived the scenario");
}

#[tokio::test]
async fn a_panicking_client_closure_still_releases_the_hive() {
	let released = Arc::new(AtomicBool::new(false));
	let recorded = Arc::clone(&released);
	let scenario = async move {
		let scenario_config = ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build();
		let config = tightbeam::__tb_accept_config!(scenario_config);
		let trace = config.trace();

		tb_scenario!(@run_hive
			config: config,
			trace: trace,
			context: [ recorded ],
			start: |SetupEnv { trace, context }: SetupEnv<Arc<AtomicBool>>| async move {
				trace.event(SERVER_UP)?;

				Ok::<_, TightBeamError>(Released(Arc::clone(&*context)))
			},
			client: |_env: HiveEnv<Arc<AtomicBool>, Released>| async move {
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the client closure's panic must reach the caller");
	assert!(released.load(Ordering::SeqCst), "the hive outlived the scenario");
}

#[tokio::test(start_paused = true)]
async fn a_panicking_client_closure_still_aborts_the_server_task() {
	let ticks = Arc::new(AtomicU64::new(0));
	let counted = Arc::clone(&ticks);
	let scenario = async move {
		tb_scenario!(@run_service_client
			config: ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build(),
			context: [ counted ],
			server: |SetupEnv { trace, context }| async move {
				let handle = tokio::spawn(count_until_aborted(Arc::clone(&context)));
				trace.event(SERVER_UP)?;

				Ok((handle, ()))
			},
			client: |ClientEnv { .. }: ClientEnv<Arc<AtomicU64>, ()>| async move {
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the client closure's panic must reach the caller");
	assert!(stands_still(&ticks).await, "the server task outlived the scenario");
}

/// The message the spinning worker consumes.
#[cfg(feature = "colony")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct Stimulus {
	id: u32,
}

#[cfg(feature = "colony")]
tightbeam::worker! {
	name: SpinningWorker<Stimulus, ()>,
	config: {
		ticks: Arc<AtomicU64>,
	},
	handle: |_message, _trace, config| async move {
		count_until_aborted(Arc::clone(&config.ticks)).await
	}
}

/// The worker arm hands the started worker to the stimulus closure, and a
/// panic there drops it, which closes the queue and aborts the run loop with
/// the handler it was awaiting.
#[cfg(feature = "colony")]
#[tokio::test(start_paused = true)]
async fn a_panicking_stimulus_closure_still_aborts_the_worker() {
	let ticks = Arc::new(AtomicU64::new(0));
	let counted = Arc::clone(&ticks);
	let scenario = async move {
		tb_scenario!(@run_worker
			config: ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build(),
			context: [ counted ],
			setup: |SetupEnv { context, .. }: SetupEnv<Arc<AtomicU64>>| {
				SpinningWorker::new(SpinningWorkerConfig { ticks: Arc::clone(&*context) })
			},
			stimulus: |WorkerEnv { worker, .. }: WorkerEnv<Arc<AtomicU64>, SpinningWorker>| async move {
				let relay = worker.relay(Arc::new(Stimulus { id: 1 }));
				let timed_out = timeout(Duration::from_millis(20), relay).await;
				assert!(timed_out.is_err(), "the handler must still be running when the body panics");
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the stimulus closure's panic must reach the caller");
	assert_ne!(ticks.load(Ordering::SeqCst), 0, "the worker's handler never ran");
	assert!(stands_still(&ticks).await, "the worker's handler outlived the scenario");
}

/// Stands in for a started servlet. `@run_servlet` reads `addr` and stops the
/// instance, and asks nothing else of it, so no listener is needed here.
struct StubServlet {
	stopped: Arc<AtomicBool>,
}

impl StubServlet {
	fn addr(&self) -> &str {
		"stub-servlet"
	}

	fn stop(self) {
		self.stopped.store(true, Ordering::SeqCst);
	}
}

#[tokio::test]
async fn a_panicking_client_closure_still_stops_the_servlet() {
	let stopped = Arc::new(AtomicBool::new(false));
	let recorded = Arc::clone(&stopped);

	let scenario = async move {
		let scenario_config = ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build();
		let config = tightbeam::__tb_accept_config!(scenario_config);
		let trace = config.trace();

		tb_scenario!(@run_servlet
			config: config,
			trace: trace,
			environment Servlet {
				context: recorded,
				start: |SetupEnv { trace, context }| async move {
					trace.event(SERVER_UP)?;

					Ok(StubServlet { stopped: Arc::clone(&context) })
				},
				setup: |ClientEnv { .. }: ClientEnv<Arc<AtomicBool>, String>| async move {
					Ok::<(), TightBeamError>(())
				},
				client: |_env: ServletEnv<Arc<AtomicBool>, ()>| async move {
					panic!("the scenario body failed");
				}
			}
		)
	};

	let outcome = AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the client closure's panic must reach the caller");
	assert!(stopped.load(Ordering::SeqCst), "the servlet outlived the scenario");
}

/// Stands in for a cluster gateway. `@run_cluster` reads `addr` and hands the
/// instance to the client closure.
#[cfg(feature = "colony")]
struct StubCluster;

#[cfg(feature = "colony")]
impl StubCluster {
	fn addr(&self) -> String {
		"stub-cluster".to_owned()
	}
}

/// Stands in for a registered hive. The arm registers it, then owns the stop.
#[cfg(feature = "colony")]
struct StubHive {
	stopped: Arc<AtomicBool>,
}

#[cfg(feature = "colony")]
impl StubHive {
	async fn register_with_cluster(&self, _addr: &String) -> Result<(), TightBeamError> {
		Ok(())
	}

	fn stop(self) {
		self.stopped.store(true, Ordering::SeqCst);
	}
}

#[cfg(feature = "colony")]
#[tokio::test]
async fn a_panicking_client_closure_still_stops_the_registered_hives() {
	let stopped = Arc::new(AtomicBool::new(false));
	let recorded = Arc::clone(&stopped);
	let scenario = async move {
		let scenario_config = ScenarioConfig::builder().with_spec(ServerUpSpec::latest()).build();
		let config = tightbeam::__tb_accept_config!(scenario_config);
		let trace = config.trace();

		tb_scenario!(@run_cluster
			config: config,
			trace: trace,
			context: [ recorded ],
			start: |SetupEnv { trace, .. }: SetupEnv<Arc<AtomicBool>>| async move {
				trace.event(SERVER_UP)?;

				Ok::<_, TightBeamError>(StubCluster)
			},
			hives: [ |SetupEnv { context, .. }: SetupEnv<Arc<AtomicBool>>| {
				let stopped = Arc::clone(&*context);

				vec![async move { Ok::<_, TightBeamError>(StubHive { stopped }) }]
			} ],
			client: |_env: ClusterEnv<Arc<AtomicBool>, StubCluster>| async move {
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the client closure's panic must reach the caller");
	assert!(stopped.load(Ordering::SeqCst), "the registered hive outlived the scenario");
}
