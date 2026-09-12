//! Teardown runs when the scenario body panics
//!
//! A test fails by panicking, so the statement after the client closure is
//! the one a failing run skips. These tests drive an internal `tb_scenario!`
//! arm down that path and check the scenario still released what it started.

#![cfg(all(feature = "testing", feature = "tokio"))]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use tightbeam::testing::{ClientEnv, ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario};

const SERVER_UP: Urn<'static> = Urn::new("test", "event:teardown/server-up");

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
		tokio::time::sleep(Duration::from_millis(1)).await;
	}
}

#[tokio::test]
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

	let outcome = std::panic::AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the client closure's panic must reach the caller");

	// The abort is asynchronous, so let the runtime retire the task before
	// reading the counter it was advancing.
	tokio::time::sleep(Duration::from_millis(50)).await;
	let settled = ticks.load(Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(50)).await;

	assert_eq!(ticks.load(Ordering::SeqCst), settled, "the server task outlived the scenario");
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
					Ok::<(), tightbeam::TightBeamError>(())
				},
				client: |_env: tightbeam::testing::ServletEnv<Arc<AtomicBool>, ()>| async move {
					panic!("the scenario body failed");
				}
			}
		)
	};

	let outcome = std::panic::AssertUnwindSafe(scenario).catch_unwind().await;
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
	async fn register_with_cluster(&self, _addr: &String) -> Result<(), tightbeam::TightBeamError> {
		Ok(())
	}

	fn stop(self) {
		self.stopped.store(true, Ordering::SeqCst);
	}
}

#[cfg(feature = "colony")]
#[tokio::test]
async fn a_panicking_client_closure_still_stops_the_registered_hives() {
	use tightbeam::testing::ClusterEnv;

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

				Ok::<_, tightbeam::TightBeamError>(StubCluster)
			},
			hives: [ |SetupEnv { context, .. }: SetupEnv<Arc<AtomicBool>>| {
				let stopped = Arc::clone(&*context);

				vec![async move { Ok::<_, tightbeam::TightBeamError>(StubHive { stopped }) }]
			} ],
			client: |_env: ClusterEnv<Arc<AtomicBool>, StubCluster>| async move {
				panic!("the scenario body failed");
			}
		)
	};

	let outcome = std::panic::AssertUnwindSafe(scenario).catch_unwind().await;
	assert!(outcome.is_err(), "the client closure's panic must reach the caller");
	assert!(stopped.load(Ordering::SeqCst), "the registered hive outlived the scenario");
}
