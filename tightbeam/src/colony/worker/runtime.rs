//! The worker queue runtime that every [`worker!`](crate::worker) expansion
//! shares.
//!
//! The macro keeps the handler and the config binding of each named worker.
//! Start, relay, kill, and `Drop` live here.

use core::future::Future;
use core::mem;
use std::sync::Arc;

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
	/// loop.
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

/// The bounded queue and the run-loop handle of one worker instance.
pub struct WorkerRuntime<I, O, C = ()>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	phase: Phase<I, O>,
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
			phase: Phase::Unstarted,
			config: Arc::new(config),
			trace: Arc::new(TraceCollector::new()),
		}
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
		if matches!(self.phase, Phase::Started { .. }) {
			return self;
		}

		let (tx, rx) = rt::channel::<WorkerRequest<I, O>>(queue_capacity);
		let config = Arc::clone(&self.config);
		let policies = Arc::new(policies);
		let join = rt::spawn(run_loop(rx, config, policies, handler));

		self.phase = Phase::Started { sender: tx, join, queue: queue_capacity };
		self.trace = trace;
		self
	}

	/// Enqueue a message and await the handler response.
	///
	/// Every `worker!`-generated `Worker::relay` calls this.
	pub fn relay(&self, message: Arc<I>) -> WorkerRelayFuture<O> {
		let sender = match &self.phase {
			Phase::Started { sender, .. } => Some(sender.clone()),
			Phase::Unstarted => None,
		};
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
	/// Every `worker!`-generated `Worker::kill` calls this. The dropped sender
	/// ends the run loop's `recv` stream, so the join sees a clean exit and no
	/// abort mid-message.
	pub fn kill(mut self) -> WorkerKillFuture {
		// `Drop` runs on `self` at the end of this method, so the phase is
		// replaced in place rather than moved out.
		let phase = mem::replace(&mut self.phase, Phase::Unstarted);

		Box::pin(async move {
			let Phase::Started { sender, join, .. } = phase else {
				return Ok(());
			};

			drop(sender);
			rt::join(join).await.map_err(|_| TightBeamError::JoinError)?;

			Ok(())
		})
	}

	/// The bound of the request queue, which is `0` before [`Self::start`].
	pub fn queue_capacity(&self) -> usize {
		match &self.phase {
			Phase::Started { queue, .. } => *queue,
			Phase::Unstarted => 0,
		}
	}
}

impl<I, O, C> Drop for WorkerRuntime<I, O, C>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	fn drop(&mut self) {
		let Phase::Started { sender, join, .. } = mem::replace(&mut self.phase, Phase::Unstarted) else {
			return;
		};

		drop(sender);
		rt::abort(&join);
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
	use core::error::Error;

	use super::*;
	use crate::testing::TestMessage;

	/// A worker with no receptor gate that answers the length of the
	/// message it was handed, on a queue of `queue_capacity`.
	fn started(queue_capacity: usize) -> WorkerRuntime<TestMessage, usize> {
		let policies = WorkerPolicies { receptor_gates: Vec::new() };
		let trace = Arc::new(TraceCollector::new());
		let handler = |message: Arc<TestMessage>, _trace, _config| async move { message.content.len() };

		WorkerRuntime::new(()).start(trace, queue_capacity, policies, handler)
	}

	fn ping() -> Arc<TestMessage> {
		Arc::new(TestMessage { content: "ping".into() })
	}

	#[tokio::test]
	async fn an_unstarted_worker_has_no_queue() -> Result<(), Box<dyn Error>> {
		let runtime: WorkerRuntime<TestMessage, usize> = WorkerRuntime::new(());

		let capacity = runtime.queue_capacity();
		let relayed = runtime.relay(ping()).await;
		assert_eq!(capacity, 0);
		assert!(matches!(relayed, Err(WorkerRelayError::QueueClosed)));
		Ok(())
	}

	#[tokio::test]
	async fn a_started_worker_holds_its_queue_and_run_loop_together() -> Result<(), Box<dyn Error>> {
		let runtime = started(8);

		let capacity = runtime.queue_capacity();
		let answered = runtime.relay(ping()).await?;
		runtime.kill().await?;

		assert_eq!(capacity, 8);
		assert_eq!(answered, 4);
		Ok(())
	}

	/// A relay whose handler ends before it answers reads the dropped answer
	/// channel as a dropped response.
	#[tokio::test]
	async fn a_relay_whose_handler_panics_reads_a_dropped_response() -> Result<(), Box<dyn Error>> {
		let policies = WorkerPolicies { receptor_gates: Vec::new() };
		let trace = Arc::new(TraceCollector::new());
		let handler =
			|_message: Arc<TestMessage>, _trace, _config| async move { panic!("the handler ends unanswered") };

		let runtime: WorkerRuntime<TestMessage, usize> = WorkerRuntime::new(()).start(trace, 8, policies, handler);
		let relayed = runtime.relay(ping()).await;
		assert!(matches!(relayed, Err(WorkerRelayError::ResponseDropped)));
		Ok(())
	}

	#[tokio::test]
	async fn a_second_start_keeps_the_first_queue() -> Result<(), Box<dyn Error>> {
		let runtime = started(8);
		let policies = WorkerPolicies { receptor_gates: Vec::new() };
		let trace = Arc::new(TraceCollector::new());

		let restarted = runtime.start(trace, 16, policies, |_message, _trace, _config| async move { 0 });
		assert_eq!(restarted.queue_capacity(), 8);
		restarted.kill().await?;
		Ok(())
	}
}
