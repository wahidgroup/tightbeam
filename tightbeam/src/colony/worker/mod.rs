//! The worker framework for message processing.
//!
//! A worker is the processing unit of the colony. It receives a message,
//! applies its receptor policies, and produces a response.
//!
//! # Macro path
//!
//! ```ignore
//! worker! {
//!     name: MyWorker<RequestMessage, ResponseMessage>,
//!     config: { threshold: u32 },
//!     policies: { with_receptor_gate: [MyGate] },
//!     handle: |message, trace, config| async move {
//!         ResponseMessage { value: message.value + config.threshold }
//!     }
//! }
//! ```
//!
//! # Macro-free path
//!
//! Use [`WorkerRuntime`] and implement [`Worker`] on a thin wrapper. See the
//! [`Worker`] trait docs.

use std::sync::Arc;

use core::future::Future;
use core::pin::Pin;

use crate::Errorizable;

use crate::policy::{ReceptorPolicy, TransitStatus};
use crate::runtime::rt;
use crate::trace::TraceCollector;
use crate::Message;

pub mod macros;
pub mod runtime;

pub use runtime::WorkerRuntime;

pub(crate) struct WorkerRequest<I: Send, O> {
	pub(crate) message: Arc<I>,
	pub(crate) respond_to: rt::OneshotSender<Result<O, TransitStatus>>,
	pub(crate) trace: Arc<TraceCollector>,
}

#[derive(Errorizable, Debug)]
pub enum WorkerRelayError {
	#[error("Worker queue closed")]
	QueueClosed,
	#[error("Worker response channel dropped")]
	ResponseDropped,
	#[error("Message rejected with status {:?}")]
	Rejected(TransitStatus),
}

pub type WorkerRelayFuture<O> = Pin<Box<dyn Future<Output = Result<O, WorkerRelayError>> + Send + 'static>>;
pub type WorkerStartFuture<W> = Pin<Box<dyn Future<Output = Result<W, crate::error::TightBeamError>> + Send>>;
pub type WorkerKillFuture = Pin<Box<dyn Future<Output = Result<(), crate::error::TightBeamError>> + Send + 'static>>;

/// A message-processing unit in the colony architecture.
///
/// A worker owns a bounded request queue and a spawned run loop that
/// evaluates receptor policies, invokes the handler, and responds through a
/// oneshot channel per request. A servlet holds one worker of each type, and
/// looks a worker up by its type.
///
/// # Macro-free path
///
/// Wrap [`WorkerRuntime`]: call [`WorkerRuntime::new`], then
/// [`WorkerRuntime::start`] with policies and a handler, and implement
/// [`Worker`] by delegating to the runtime (the same shape `worker!` expands
/// to). `Config` may be `()` or any owned struct.
///
/// # Lifecycle
///
/// [`new`](Worker::new), then [`start`](Worker::start), then
/// [`relay`](Worker::relay) any number of times, then [`kill`](Worker::kill).
/// A started worker that drops before its kill aborts the run loop, which
/// then drains nothing.
///
/// A servlet that drains ([`ServletRuntime::drain`]) kills each of its
/// workers, and a servlet that stops drops them.
///
/// [`ServletRuntime::drain`]: crate::colony::servlet::ServletRuntime::drain
pub trait Worker: Send + Sync + Sized {
	/// The message type that the handler consumes.
	type Input: Send + Sync + 'static;
	/// The response type that the handler produces.
	type Output: Send + 'static;
	/// The configuration the worker takes at construction, which the handler
	/// reads by reference. It is `()` for a worker declared with no `config`
	/// block.
	type Config: Send + Sync + 'static;

	/// Construct an unstarted worker, with no queue and no run loop.
	///
	/// [`relay`](Worker::relay) before [`start`](Worker::start) fails with
	/// [`WorkerRelayError::QueueClosed`].
	fn new(config: Self::Config) -> Self;

	/// Open the request queue and spawn the run loop.
	///
	/// It consumes the unstarted worker and resolves to the started one. A
	/// start of a started worker returns it unchanged. Each relayed request
	/// carries `trace`.
	fn start(self, trace: Arc<TraceCollector>) -> WorkerStartFuture<Self>;

	/// Stop the worker gracefully.
	///
	/// It closes the queue, so the run loop drains the requests in flight and
	/// exits, then awaits the join.
	///
	/// - It takes the worker by reference, so a servlet that shares its workers
	///   with its handlers kills each one in place.
	/// - A relay after the kill fails with [`WorkerRelayError::QueueClosed`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::JoinError`] -- the run loop task fails to join.
	///
	/// [`TightBeamError::JoinError`]: crate::error::TightBeamError::JoinError
	fn kill(&self) -> WorkerKillFuture;

	/// Enqueue a message and await the handler's response.
	///
	/// # Errors
	///
	/// - [`WorkerRelayError::QueueClosed`] -- the worker never started, or a kill closed it.
	/// - [`WorkerRelayError::Rejected`] -- a receptor gate refuses the message.
	/// - [`WorkerRelayError::ResponseDropped`] -- the run loop ends before it responds.
	fn relay(&self, message: Arc<Self::Input>) -> WorkerRelayFuture<Self::Output>;

	/// Returns the bound of the request queue.
	///
	/// It is the `queue:` value of the `worker!` declaration (64 by default)
	/// while the worker runs, and `0` before [`start`](Worker::start) and after
	/// [`kill`](Worker::kill).
	fn queue_capacity(&self) -> usize;
}

pub struct WorkerPolicies<I: Send> {
	#[allow(dead_code)]
	pub(crate) receptor_gates: Vec<Arc<dyn ReceptorPolicy<I> + Send + Sync>>,
}

impl<I: Send> WorkerPolicies<I> {
	pub fn receptor_gates(&self) -> &[Arc<dyn ReceptorPolicy<I> + Send + Sync>] {
		&self.receptor_gates
	}

	/// Run every configured receptor gate over `message`.
	///
	/// The first refusal short-circuits, so a gate reached by the sweep
	/// answers on a message the gates before it already admitted.
	///
	/// # Errors
	///
	/// - [`TransitStatus`] -- a gate refuses the message, under its own status.
	pub(crate) fn admits(&self, message: &I) -> Result<(), TransitStatus>
	where
		I: Message,
	{
		for gate in self.receptor_gates.iter() {
			let status = gate.evaluate(message);
			if status != TransitStatus::Ok {
				return Err(status);
			}
		}

		Ok(())
	}
}

impl<I: Send> Default for WorkerPolicies<I> {
	fn default() -> Self {
		Self { receptor_gates: Vec::new() }
	}
}

pub struct WorkerPolicyBuilder<I: Send> {
	receptor_gates: Vec<Arc<dyn ReceptorPolicy<I> + Send + Sync>>,
}

impl<I: Send> Default for WorkerPolicyBuilder<I> {
	fn default() -> Self {
		Self { receptor_gates: Vec::new() }
	}
}

impl<I: Message + Send> WorkerPolicyBuilder<I> {
	pub fn build(self) -> WorkerPolicies<I> {
		WorkerPolicies { receptor_gates: self.receptor_gates }
	}

	pub fn with_receptor_gate<R, const N: usize>(mut self, gates: [R; N]) -> Self
	where
		R: ReceptorPolicy<I> + Send + Sync + 'static,
	{
		self.receptor_gates.extend(
			gates
				.into_iter()
				.map(|gate| Arc::new(gate) as Arc<dyn ReceptorPolicy<I> + Send + Sync>),
		);
		self
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::{Worker, WorkerRelayError};
	use crate::der::Sequence;
	use crate::policy::{ReceptorPolicy, TransitStatus};
	use crate::testing::TestResult;
	use crate::worker;
	use crate::Beamable;

	/// A request that names its content and a lucky number.
	#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct RequestMessage {
		content: String,
		lucky_number: u32,
	}

	/// The answer of a worker that plays ping pong.
	#[derive(Sequence, Beamable, Clone, Debug, PartialEq)]
	pub struct PongMessage {
		result: String,
	}

	/// A receptor gate that admits a `PING` alone.
	///
	/// A receptor gate is an implementor's own, so the test names one.
	#[derive(Default)]
	struct PingGate;

	impl ReceptorPolicy<RequestMessage> for PingGate {
		fn evaluate(&self, maybe_ping: &RequestMessage) -> TransitStatus {
			if maybe_ping.content == "PING" {
				TransitStatus::Ok
			} else {
				TransitStatus::PermissionDenied
			}
		}
	}

	worker! {
		name: LuckyNumberDeterminer<RequestMessage, bool>,
		config: {
			lotto_number: u32,
		},
		handle: |message, _trace, config| async move {
			message.lucky_number == config.lotto_number
		}
	}

	worker! {
		name: PingPongWorker<RequestMessage, PongMessage>,
		policies: {
			with_receptor_gate: [PingGate]
		},
		handle: |_message, _trace| async move {
			PongMessage {
				result: "PONG".to_string(),
			}
		}
	}

	/// A request of `content` that names `lucky_number`.
	fn request(content: &str, lucky_number: u32) -> Arc<RequestMessage> {
		Arc::new(RequestMessage { content: content.to_string(), lucky_number })
	}

	/// A lotto worker whose winning number is 42.
	fn lotto() -> LuckyNumberDeterminer {
		LuckyNumberDeterminer::new(LuckyNumberDeterminerConfig { lotto_number: 42 })
	}

	/// Relays `number` to the lotto `worker`, and asserts that the worker
	/// judges it a winner exactly when `wins` holds.
	async fn judges(worker: &LuckyNumberDeterminer, number: u32, wins: bool) -> TestResult {
		let verdict = worker.relay(request("PING", number)).await?;
		assert_eq!(verdict, wins);
		Ok(())
	}

	// A worker that names no queue bound queues 64 requests.
	crate::test_worker! {
		name: a_lucky_number_worker_queues_the_default_64_requests,
		setup: || lotto(),
		assertions: |worker| async move {
			assert_eq!(worker.queue_capacity(), 64);
			Ok(())
		}
	}

	// The lotto worker judges its winning number a winner.
	crate::test_worker! {
		name: a_lucky_number_worker_judges_the_winning_number_a_winner,
		setup: || lotto(),
		assertions: |worker| judges(worker, 42, true)
	}

	// The lotto worker judges another number a loser.
	crate::test_worker! {
		name: a_lucky_number_worker_judges_another_number_a_loser,
		setup: || lotto(),
		assertions: |worker| judges(worker, 7, false)
	}

	// The gate admits a PING, and the handler answers PONG.
	crate::test_worker! {
		name: a_ping_pong_worker_answers_a_ping,
		setup: || PingPongWorker::new(()),
		assertions: |worker| async move {
			let response = worker.relay(request("PING", 42)).await?;
			assert_eq!(response, PongMessage { result: "PONG".to_string() });
			Ok(())
		}
	}

	// The gate refuses other content, so the relay reads `Rejected`.
	crate::test_worker! {
		name: a_ping_pong_worker_refuses_other_content,
		setup: || PingPongWorker::new(()),
		assertions: |worker| async move {
			let relayed = worker.relay(request("PONG", 42)).await;
			assert!(matches!(relayed, Err(WorkerRelayError::Rejected(_))));
			Ok(())
		}
	}
}
