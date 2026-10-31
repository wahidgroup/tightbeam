//! The worker queue runtime that every [`worker!`](crate::worker) expansion
//! shares.
//!
//! The macro keeps the handler and the config binding of each named worker.
//! Start, relay, kill, and `Drop` live here.

use core::future::Future;
use core::mem;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::colony::worker::{WorkerKillFuture, WorkerPolicies, WorkerRelayError, WorkerRelayFuture, WorkerRequest};
use crate::error::TightBeamError;
use crate::runtime::{rt, ChannelClosed};
use crate::trace::TraceCollector;
use crate::Message;

/// Where one worker stands: before [`WorkerRuntime::start`] or after it.
///
/// A started worker holds its queue sender, its run-loop handle, and its
/// queue bound, so the three exist only together.
enum Phase<I, O>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
{
	/// [`WorkerRuntime::start`] has yet to open the queue and spawn the run
	/// loop, or [`WorkerRuntime::kill`] has closed it.
	Unstarted,
	/// The queue is open and the run loop is spawned.
	Started {
		/// The sender side of the request queue.
		sender: rt::Sender<WorkerRequest<I, O>>,
		/// The join handle of the spawned run loop.
		join: rt::JoinHandle,
		/// The bound of the request queue.
		queue: usize,
	},
}

impl<I, O> Phase<I, O>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
{
	/// A sender of the request queue, for one relay, or [`None`] before the
	/// queue opens.
	fn sender(&self) -> Option<rt::Sender<WorkerRequest<I, O>>> {
		match self {
			Self::Started { sender, .. } => Some(sender.clone()),
			Self::Unstarted => None,
		}
	}

	/// The bound of the request queue, `0` while no queue is open.
	fn queue(&self) -> usize {
		match self {
			Self::Started { queue, .. } => *queue,
			Self::Unstarted => 0,
		}
	}

	/// Closes the queue of a started worker and returns its run loop, which
	/// ends once each queued message has its answer.
	fn close(self) -> Option<ClosedLoop> {
		match self {
			Self::Started { sender, join, .. } => {
				drop(sender);
				Some(ClosedLoop(join))
			}
			Self::Unstarted => None,
		}
	}
}

/// The run loop of a worker whose queue is closed.
///
/// [`WorkerRuntime::kill`] waits on it. A loop that drops before it ends is
/// aborted, so a kill that its caller stops waiting on, such as a drain past
/// its timeout, leaves no handler running.
struct ClosedLoop(rt::JoinHandle);

impl ClosedLoop {
	/// Waits for the loop to end.
	async fn ended(&mut self) -> Result<(), rt::JoinError> {
		(&mut self.0).await
	}
}

impl Drop for ClosedLoop {
	fn drop(&mut self) {
		rt::abort(&self.0);
	}
}

/// The bounded queue and the run-loop handle of one worker instance.
///
/// # Poison recovery
///
/// Every write under the phase lock replaces the whole phase, so a thread
/// that panicked under the guard left a whole phase. The runtime recovers a
/// poisoned lock, and the worker stays in service.
pub struct WorkerRuntime<I, O, C = ()>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	/// The phase, which [`Self::relay`] locks for one clone of the sender and
	/// [`Self::kill`] locks to take the phase out, so no guard crosses an
	/// await.
	phase: Mutex<Phase<I, O>>,
	config: Arc<C>,
	/// The collector every relayed request records into. Both phases read it,
	/// so it sits beside the phase and not inside it.
	trace: Arc<TraceCollector>,
}

impl<I, O, C> WorkerRuntime<I, O, C>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	/// Build a worker in its unstarted phase around `config`.
	pub fn new(config: C) -> Self {
		Self {
			phase: Mutex::new(Phase::Unstarted),
			config: Arc::new(config),
			trace: Arc::new(TraceCollector::new()),
		}
	}

	/// Takes the phase lock, and recovers a poisoned lock.
	fn phase(&self) -> MutexGuard<'_, Phase<I, O>> {
		self.phase.lock().unwrap_or_else(PoisonError::into_inner)
	}

	/// Open the queue and spawn the loop that runs the policies and the
	/// handler.
	///
	/// A worker that is already started returns unchanged.
	pub fn start<F, Fut>(
		mut self,
		trace: Arc<TraceCollector>,
		queue_capacity: usize,
		policies: WorkerPolicies<I>,
		handler: F,
	) -> Self
	where
		F: Fn(Arc<I>, Arc<TraceCollector>, Arc<C>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = O> + Send + 'static,
	{
		let phase = self.phase.get_mut().unwrap_or_else(PoisonError::into_inner);
		if matches!(phase, Phase::Started { .. }) {
			return self;
		}

		let (tx, rx) = rt::channel::<WorkerRequest<I, O>>(queue_capacity);
		let config = Arc::clone(&self.config);
		let policies = Arc::new(policies);
		let join = rt::spawn(run_loop(rx, config, policies, handler));

		*phase = Phase::Started { sender: tx, join, queue: queue_capacity };
		self.trace = trace;
		self
	}

	/// Enqueue a message and await the handler response.
	///
	/// Every `worker!`-generated `Worker::relay` calls this. It locks the
	/// phase for one clone of the sender alone, so a relay that waits on a
	/// full queue holds no lock.
	pub fn relay(&self, message: Arc<I>) -> WorkerRelayFuture<O> {
		let sender = self.phase().sender();
		let trace = Arc::clone(&self.trace);

		Box::pin(async move {
			let sender = sender.ok_or(WorkerRelayError::QueueClosed)?;
			let (tx, rx) = rt::oneshot();

			let request = WorkerRequest { message, respond_to: tx, trace };
			rt::send(&sender, request)
				.await
				.map_err(|ChannelClosed| WorkerRelayError::QueueClosed)?;

			match rt::wait_response(rx).await {
				Ok(Ok(output)) => Ok(output),
				Ok(Err(status)) => Err(WorkerRelayError::Rejected(status)),
				Err(ChannelClosed) => Err(WorkerRelayError::ResponseDropped),
			}
		})
	}

	/// Close the queue and join the run loop.
	///
	/// Every `worker!`-generated `Worker::kill` calls this.
	///
	/// - The call takes the phase out under the lock and closes the queue, so
	///   a later relay meets a closed queue.
	/// - The run loop ends once each queued message has its answer, so the join sees a clean exit.
	/// - A kill future that drops before the loop ends aborts the loop.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::worker::{WorkerPolicies, WorkerRuntime};
	/// use tightbeam::testing::TestMessage;
	/// use tightbeam::trace::TraceCollector;
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	/// # runtime.block_on(async {
	/// let handler = |message: Arc<TestMessage>, _trace, _config| async move { message.content.len() };
	/// let trace = Arc::new(TraceCollector::new());
	/// let worker = WorkerRuntime::new(()).start(trace, 8, WorkerPolicies::default(), handler);
	///
	/// worker.kill().await?;
	/// assert_eq!(worker.queue_capacity(), 0);
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// # })?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn kill(&self) -> WorkerKillFuture {
		let phase = mem::replace(&mut *self.phase(), Phase::Unstarted);
		let closed = phase.close();

		Box::pin(async move {
			let Some(mut run_loop) = closed else {
				return Ok(());
			};

			run_loop.ended().await.map_err(|_| TightBeamError::JoinError)
		})
	}

	/// The bound of the request queue, which is `0` before [`Self::start`]
	/// and after [`Self::kill`].
	pub fn queue_capacity(&self) -> usize {
		self.phase().queue()
	}
}

impl<I, O, C> Drop for WorkerRuntime<I, O, C>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	fn drop(&mut self) {
		let phase = self.phase.get_mut().unwrap_or_else(PoisonError::into_inner);
		let closed = mem::replace(phase, Phase::Unstarted).close();
		// The closed loop drops unjoined, which aborts it.
		drop(closed);
	}
}

async fn run_loop<I, O, C, F, Fut>(
	mut receiver: rt::Receiver<WorkerRequest<I, O>>,
	config: Arc<C>,
	policies: Arc<WorkerPolicies<I>>,
	handler: F,
) where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
	F: Fn(Arc<I>, Arc<TraceCollector>, Arc<C>) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = O> + Send + 'static,
{
	while let Some(request) = rt::recv(&mut receiver).await {
		let WorkerRequest { message, respond_to, trace } = request;
		if let Err(status) = policies.admits(message.as_ref()) {
			// A send fails only when the caller dropped its relay future,
			// which ends the wait for this answer.
			let _ = respond_to.send(Err(status));
			continue;
		}

		let output = handler(message, trace, Arc::clone(&config)).await;
		// A send fails only when the caller dropped its relay future, which
		// ends the wait for this answer.
		let _ = respond_to.send(Ok(output));
	}
}

#[cfg(test)]
mod tests {
	use core::time::Duration;

	use tokio::sync::Notify;

	use super::*;
	use crate::testing::{TestMessage, TestResult};

	/// A bound on a wait that the test expects to end. A wait that reaches it
	/// is a hang, which the test reports as a failure.
	const HANG_GUARD: Duration = Duration::from_secs(10);

	/// `runtime` started on a queue of `queue_capacity`, with no receptor gate
	/// and a trace of its own, answering through `handler`.
	fn start_on<F, Fut>(
		runtime: WorkerRuntime<TestMessage, usize>,
		queue_capacity: usize,
		handler: F,
	) -> WorkerRuntime<TestMessage, usize>
	where
		F: Fn(Arc<TestMessage>, Arc<TraceCollector>, Arc<()>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = usize> + Send + 'static,
	{
		let policies = WorkerPolicies { receptor_gates: Vec::new() };
		runtime.start(Arc::new(TraceCollector::new()), queue_capacity, policies, handler)
	}

	/// A worker with no receptor gate that answers the length of the
	/// message it was handed, on a queue of `queue_capacity`.
	fn started(queue_capacity: usize) -> WorkerRuntime<TestMessage, usize> {
		let handler = |message: Arc<TestMessage>, _trace, _config| async move { message.content.len() };
		start_on(WorkerRuntime::new(()), queue_capacity, handler)
	}

	/// A started worker whose handler gives notice on `entered` and never
	/// answers. Its run loop holds `alive` until the loop ends.
	fn held(entered: &Arc<Notify>, alive: rt::Sender<()>) -> WorkerRuntime<TestMessage, usize> {
		let entered = Arc::clone(entered);
		let handler = move |_message: Arc<TestMessage>, _trace, _config| {
			let entered = Arc::clone(&entered);
			let alive = alive.clone();
			async move {
				let _alive = alive;
				entered.notify_one();
				core::future::pending::<usize>().await
			}
		};

		start_on(WorkerRuntime::new(()), 8, handler)
	}

	fn ping() -> Arc<TestMessage> {
		Arc::new(TestMessage { content: "ping".into() })
	}

	/// A worker that never started holds no queue, so a relay meets a closed
	/// queue.
	#[tokio::test]
	async fn an_unstarted_worker_has_no_queue() {
		let runtime: WorkerRuntime<TestMessage, usize> = WorkerRuntime::new(());

		let capacity = runtime.queue_capacity();
		let relayed = runtime.relay(ping()).await;
		assert!(matches!((capacity, relayed), (0, Err(WorkerRelayError::QueueClosed))));
	}

	/// A started worker holds its queue, and its run loop answers a relay.
	#[tokio::test]
	async fn a_started_worker_holds_its_queue_and_run_loop_together() -> TestResult {
		let runtime = started(8);

		let capacity = runtime.queue_capacity();
		let answered = runtime.relay(ping()).await?;
		runtime.kill().await?;

		assert_eq!((capacity, answered), (8, 4));
		Ok(())
	}

	/// A relay whose handler ends before it answers reads the dropped answer
	/// channel as a dropped response.
	#[tokio::test]
	async fn a_relay_whose_handler_panics_reads_a_dropped_response() {
		let handler = |_message, _trace, _config| async move { panic!("the handler ends unanswered") };
		let runtime = start_on(WorkerRuntime::new(()), 8, handler);

		let relayed = runtime.relay(ping()).await;
		assert!(matches!(relayed, Err(WorkerRelayError::ResponseDropped)));
	}

	/// A start of a started worker keeps the queue of the first start.
	#[tokio::test]
	async fn a_second_start_keeps_the_first_queue() -> TestResult {
		let runtime = started(8);
		let restarted = start_on(runtime, 16, |_message, _trace, _config| async move { 0 });
		assert_eq!(restarted.queue_capacity(), 8);
		restarted.kill().await?;
		Ok(())
	}

	/// A worker killed in place closes its queue, so a later relay meets a
	/// closed queue.
	#[tokio::test]
	async fn a_killed_worker_refuses_a_later_relay() -> TestResult {
		let runtime = started(8);
		runtime.kill().await?;

		let relayed = runtime.relay(ping()).await;
		assert!(matches!(relayed, Err(WorkerRelayError::QueueClosed)));
		Ok(())
	}

	/// A kill that drops before its run loop ends aborts the loop, so a caller
	/// that stops waiting on the kill leaves no handler running.
	#[tokio::test]
	async fn a_kill_dropped_before_its_loop_ends_aborts_the_loop() -> TestResult {
		let entered = Arc::new(Notify::new());
		let (alive, mut released) = rt::channel::<()>(1);
		let runtime = held(&entered, alive);
		let _relaying = tokio::spawn(runtime.relay(ping()));
		entered.notified().await;

		drop(runtime.kill());

		let ended = tokio::time::timeout(HANG_GUARD, rt::recv(&mut released)).await?;
		assert_eq!(ended, None);
		Ok(())
	}
}
