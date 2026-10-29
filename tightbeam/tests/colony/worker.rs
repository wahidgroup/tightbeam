//! The integration tests of the Worker: its environment syntax in
//! `tb_scenario!`, its resolution by type, and its drain.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::Arc;

use tokio::sync::{Notify, Semaphore};

use tightbeam::clock::{Clock, ManualClock};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveRuntime};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::worker::Worker;
use tightbeam::der::Sequence;
use tightbeam::testing::{ScenarioConfig, WorkerEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, TransportError, TransportFailure};
use tightbeam::urn::Urn;
use tightbeam::Beamable;
use tightbeam::{compose, exactly, servlet, tb_assert_spec, tb_scenario, worker, Frame, TightBeamError};

pub(crate) const RELAY_START: Urn<'static> = tightbeam::urn!("test", "event:worker/relay-start");
pub(crate) const RELAY_SUCCESS: Urn<'static> = tightbeam::urn!("test", "event:worker/relay-success");

// The message types that the workers exchange.
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct PingMessage {
	content: String,
	lucky_number: u32,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct PongMessage {
	result: String,
}

// A worker with a config, so `new` takes the `ConfigurableWorkerConfig` that
// the macro generates.
worker! {
	name: ConfigurableWorker<PingMessage, Option<PongMessage>>,
	config: {
		response: String,
	},
	handle: |message, _trace, config| async move {
		if message.content == "PING" {
			Some(PongMessage { result: config.response.to_owned() })
		} else {
			None
		}
	}
}

// A worker with no config, so `new` takes `()`.
worker! {
	name: DefaultWorker<PingMessage, Option<PongMessage>>,
	handle: |message, _trace| async move {
		if message.content == "PING" {
			Some(PongMessage { result: "DEFAULT_PONG".to_string() })
		} else {
			None
		}
	}
}

tb_assert_spec! {
	pub WorkerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(RELAY_START, exactly!(1)),
			(RELAY_SUCCESS, exactly!(1), equals!("DEFAULT_PONG"))
		]
	},
	V(2,0,0): {
		mode: Accept,
		assertions: [
			(RELAY_START, exactly!(1)),
			(RELAY_SUCCESS, exactly!(1), equals!("CUSTOM_RESPONSE"))
		]
	},
}

tb_scenario! {
	name: test_worker_with_config,
	spec: WorkerSpec,
	environment Worker {
		setup: |_env| {
			ConfigurableWorker::new(ConfigurableWorkerConfig {
				response: "CUSTOM_RESPONSE".to_string(),
			})
		},
		stimulus: |WorkerEnv { trace, worker, .. }| async move {
			trace.event_with(RELAY_START, &[], ())?;

			let ping_msg = PingMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};

			let response = worker.relay(Arc::new(ping_msg)).await?;
			if let Some(resp) = response {
				trace.event_with(RELAY_SUCCESS, &[], resp.result)?;
			}

			Ok(())
		}
	}
}

tb_scenario! {
	name: test_worker_with_type,
	config: ScenarioConfig::builder()
		.with_specs(vec![WorkerSpec::get(1, 0, 0).expect("WorkerSpec 1.0.0")])
		.build(),
	environment Worker {
	setup: |_env| DefaultWorker::new(()),
	stimulus: |WorkerEnv { trace, worker, .. }| async move {
		trace.event_with(RELAY_START, &[], ())?;

		let ping_msg = PingMessage {
			content: "PING".to_string(),
				lucky_number: 99,
			};

			let response = worker.relay(Arc::new(ping_msg)).await?;
			if let Some(resp) = response {
				trace.event_with(RELAY_SUCCESS, &[], resp.result)?;
			}

			Ok(())
		}
	}
}

/// The `Shared` worker of one module, which answers the length of the
/// content of each message.
mod first {
	use super::PingMessage;

	tightbeam::worker! {
		name: Shared<PingMessage, usize>,
		handle: |message, _trace| async move { message.content.len() }
	}
}

/// A worker type under the same name as the one of [`first`].
mod second {
	use super::PingMessage;

	tightbeam::worker! {
		name: Shared<PingMessage, usize>,
		handle: |message, _trace| async move { message.content.len() }
	}
}

/// Two worker types under one name each resolve to their own worker, because
/// a servlet keys its workers by their type.
#[test]
fn two_worker_types_under_one_name_both_resolve() -> Result<(), TightBeamError> {
	let config = ServletConfig::<TokioListener, PingMessage>::builder()
		.with_worker(first::Shared::new(()))
		.with_worker(second::Shared::new(()))
		.allow_cleartext()
		.build();

	let resolved_first = config.worker::<first::Shared>().is_some();
	let resolved_second = config.worker::<second::Shared>().is_some();
	assert_eq!((resolved_first, resolved_second), (true, true));
	Ok(())
}

/// The drain timeout of the gated hive, on its manual clock.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// A bound on a wait that the test expects to end. A wait that reaches it is
/// a hang, which the test reports as a failure.
const HANG_GUARD: Duration = Duration::from_secs(10);

/// The signals of a worker that waits: the notice it gives as a message
/// reaches its handler, the gate that handler waits on, and the mark it sets
/// once the message completes.
#[derive(Clone)]
pub struct WorkerGate {
	entered: Arc<Notify>,
	gate: Arc<Semaphore>,
	done: Arc<AtomicBool>,
}

impl Default for WorkerGate {
	fn default() -> Self {
		Self { entered: Arc::default(), gate: Arc::new(Semaphore::new(0)), done: Arc::default() }
	}
}

impl WorkerGate {
	/// Gives notice that a message arrived, waits for the gate, and marks the
	/// message done. It answers whether the gate opened.
	async fn pass(&self) -> bool {
		self.entered.notify_one();
		let opened = self.gate.acquire().await.is_ok();
		self.done.store(opened, Ordering::SeqCst);
		opened
	}

	/// Opens the gate for one message.
	fn open(&self) {
		self.gate.add_permits(1);
	}

	/// Whether a message passed the gate and completed.
	fn done(&self) -> bool {
		self.done.load(Ordering::SeqCst)
	}
}

worker! {
	name: GatedWorker<PingMessage, bool>,
	config: {
		gate: WorkerGate,
	},
	handle: |_message, _trace, config| async move {
		config.gate.pass().await
	}
}

servlet! {
	/// A servlet that relays each request to its [`GatedWorker`].
	GatedServlet<PingMessage, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |request, frame, ctx| async move {
		let passed = ctx.relay::<GatedWorker>(Arc::new(request)).await?;
		Ok(Some(compose! {
			V0: id: frame.metadata().id(),
				message: PongMessage { result: passed.to_string() }
		}?))
	}
}

/// The type the gated servlet registers under.
fn gated_type() -> Urn<'static> {
	let urn = ColonyNamespace::default().servlet("gated");
	urn.expect("test names satisfy the mint grammar")
}

/// Starts a hive on `clock` with no control plane that holds one
/// [`GatedServlet`], whose worker waits on `gate`, and returns it beside the
/// servlet's address. The hive drains within [`DRAIN_TIMEOUT`].
async fn start_gated_hive(
	gate: &WorkerGate,
	clock: &Arc<ManualClock>,
) -> Result<(HiveRuntime<TokioListener>, TightBeamSocketAddr), TightBeamError> {
	let worker = GatedWorker::new(GatedWorkerConfig { gate: gate.clone() });
	let builder = ServletConfig::<TokioListener, PingMessage>::builder().with_worker(worker);
	let servlet = GatedServlet::start(Arc::new(TraceCollector::new()), builder.allow_cleartext().build()).await?;
	let addr = *servlet.addr();

	let mut conf = HiveConfig { clock: Arc::clone(clock) as Arc<dyn Clock>, ..Default::default() };
	conf.control.drain_timeout = DRAIN_TIMEOUT;

	let mut hive = HiveRuntime::<TokioListener>::new(Some(conf))?;
	hive.register(gated_type(), servlet, |t| GatedServlet::start(t, ServletConfig::cleartext()))?;
	Ok((hive, addr))
}

/// Sends one ping to the servlet at `addr`. The servlet's drain ends the
/// connection, so the caller reads no reply.
async fn ping(addr: TightBeamSocketAddr) -> Result<Option<Frame>, TightBeamError> {
	let builder = ClientBuilder::<TokioListener>::builder().allow_cleartext().build();
	let mut client = builder.connect(addr).await?;
	let message = PingMessage { content: "PING".into(), lucky_number: 1 };
	let request = compose! { V0: id: b"gated-ping", message: message }?;
	Ok(client.emit(request, None).await?)
}

/// A hive's drain ends each worker through its kill, so a message the worker
/// holds completes before the drain returns. A stop aborts the worker and
/// drops the message.
#[tokio::test]
async fn a_servlets_workers_drain_their_queue_at_drain() -> Result<(), TightBeamError> {
	let gate = WorkerGate::default();
	let clock = Arc::new(ManualClock::default());
	let (hive, addr) = start_gated_hive(&gate, &clock).await?;
	let client = tokio::spawn(ping(addr));
	gate.entered.notified().await;

	// The drain ends the accept loop before it kills the worker, and the end
	// of the loop ends the client's exchange. So the gate opens while the
	// kill waits on the message.
	let drain = tokio::spawn(async move { hive.drain().await });
	let exchanged = client.await.map_err(|_| TightBeamError::JoinError)?;
	// The drain ended the connection before the servlet answered, so the
	// exchange holds no reply for this test to read.
	drop(exchanged);
	gate.open();

	drain.await.map_err(|_| TightBeamError::JoinError)??;
	assert!(gate.done());
	Ok(())
}

/// A drain whose worker never answers ends once the hive clock passes the
/// drain timeout, so the drain of a hive ends whatever one handler does.
#[tokio::test]
async fn a_drain_whose_worker_never_answers_ends_at_its_timeout() -> Result<(), TightBeamError> {
	let gate = WorkerGate::default();
	let clock = Arc::new(ManualClock::default());
	let (hive, addr) = start_gated_hive(&gate, &clock).await?;
	let client = tokio::spawn(ping(addr));
	gate.entered.notified().await;

	// The client's exchange ends once the drain has begun, so the clock moves
	// past the timeout of a drain that is under way.
	let drain = tokio::spawn(async move { hive.drain().await });
	let exchanged = client.await.map_err(|_| TightBeamError::JoinError)?;
	// The drain ended the connection before the servlet answered, so the
	// exchange holds no reply for this test to read.
	drop(exchanged);
	clock.advance(DRAIN_TIMEOUT);

	let ended = tokio::time::timeout(HANG_GUARD, drain).await;
	let drained = ended.map_err(|_| TightBeamError::RecvTimeoutError)?;
	let drained = drained.map_err(|_| TightBeamError::JoinError)?;
	let expired = matches!(
		drained,
		Err(TightBeamError::TransportError(TransportError::OperationFailed(
			TransportFailure::DeadlineExceeded
		)))
	);
	assert!(expired);
	Ok(())
}
