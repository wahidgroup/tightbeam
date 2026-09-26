//! Shared worker queue runtime used by [`worker!`](crate::worker).
//!
//! Named workers keep handler/config wiring in the macro; start, relay, kill,
//! and Drop live here.

use core::future::Future;
use std::sync::Arc;

use crate::colony::worker::{
	worker_runtime, WorkerKillFuture, WorkerPolicies, WorkerRelayError, WorkerRelayFuture, WorkerRequest,
};
use crate::error::TightBeamError;
use crate::trace::TraceCollector;
use crate::Message;

/// Bounded queue + run-loop handle for one worker instance.
pub struct WorkerRuntime<I, O, C = ()>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	sender: Option<worker_runtime::rt::QueueSender<WorkerRequest<I, O>>>,
	join: Option<worker_runtime::rt::JoinHandle>,
	queue: usize,
	config: Arc<C>,
	trace: Arc<TraceCollector>,
}

impl<I, O, C> WorkerRuntime<I, O, C>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	/// Unstarted worker: no queue and no run loop.
	pub fn new(config: C) -> Self {
		Self {
			sender: None,
			join: None,
			queue: 0,
			config: Arc::new(config),
			trace: Arc::new(TraceCollector::new()),
		}
	}

	/// Open the queue and spawn the policy + handler loop.
	///
	/// Starting an already-started worker is a no-op.
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
		if self.sender.is_some() {
			return self;
		}

		let (tx, rx) = worker_runtime::rt::channel::<WorkerRequest<I, O>>(queue_capacity);
		let config = Arc::clone(&self.config);
		let policies = Arc::new(policies);
		let join = worker_runtime::rt::spawn(run_loop(rx, config, policies, handler));

		self.sender = Some(tx);
		self.join = Some(join);
		self.queue = queue_capacity;
		self.trace = trace;
		self
	}

	/// Enqueue a message and await the handler response.
	///
	/// Every `worker!`-generated `Worker::relay` calls this.
	pub fn relay(&self, message: Arc<I>) -> WorkerRelayFuture<O> {
		let sender = self.sender.clone();
		let trace = Arc::clone(&self.trace);

		Box::pin(async move {
			let sender = sender.ok_or(WorkerRelayError::QueueClosed)?;
			let (tx, rx) = worker_runtime::rt::oneshot();

			let request = WorkerRequest { message, respond_to: tx, trace };
			worker_runtime::rt::send(&sender, request)
				.await
				.map_err(|_| WorkerRelayError::QueueClosed)?;

			match worker_runtime::rt::wait_response(rx).await {
				Ok(Ok(output)) => Ok(output),
				Ok(Err(status)) => Err(WorkerRelayError::Rejected(status)),
				Err(()) => Err(WorkerRelayError::ResponseDropped),
			}
		})
	}

	/// Close the queue and join the run loop.
	///
	/// Every `worker!`-generated `Worker::kill` calls this. Dropping the
	/// sender ends the run loop's `recv` stream, so the join observes a clean
	/// exit instead of aborting mid-message.
	pub fn kill(mut self) -> WorkerKillFuture {
		let sender = self.sender.take();
		let join = self.join.take();

		Box::pin(async move {
			drop(sender);

			if let Some(handle) = join {
				worker_runtime::rt::join(handle).await.map_err(|_| TightBeamError::JoinError)?;
			}

			Ok(())
		})
	}

	/// Bound of the request queue (`0` before [`Self::start`]).
	pub fn queue_capacity(&self) -> usize {
		self.queue
	}
}

impl<I, O, C> Drop for WorkerRuntime<I, O, C>
where
	I: Message + Send + Sync + 'static,
	O: Send + 'static,
	C: Send + Sync + 'static,
{
	fn drop(&mut self) {
		if let Some(sender) = self.sender.take() {
			drop(sender);
		}
		if let Some(handle) = self.join.take() {
			worker_runtime::rt::abort(&handle);
		}
	}
}

async fn run_loop<I, O, C, F, Fut>(
	mut receiver: worker_runtime::rt::QueueReceiver<WorkerRequest<I, O>>,
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
	while let Some(request) = worker_runtime::rt::recv(&mut receiver).await {
		let WorkerRequest { message, respond_to, trace } = request;
		if let Err(status) = policies.admits(message.as_ref()) {
			let _ = respond_to.send(Err(status));
			continue;
		}

		let output = handler(message, trace, Arc::clone(&config)).await;
		let _ = respond_to.send(Ok(output));
	}
}
