//! Shared worker queue runtime used by [`worker!`](crate::worker).
//!
//! Named workers keep handler/config wiring in the macro; start, relay, kill,
//! and Drop live here.

use core::future::Future;
use std::sync::Arc;

use crate::colony::worker::{
	kill_worker, relay_to_worker, worker_runtime, WorkerKillFuture, WorkerPolicies, WorkerRelayFuture, WorkerRequest,
};
use crate::policy::TransitStatus;
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
	pub fn relay(&self, message: Arc<I>) -> WorkerRelayFuture<O> {
		relay_to_worker(self.sender.clone(), Arc::clone(&self.trace), message)
	}

	/// Close the queue and join the run loop.
	pub fn kill(mut self) -> WorkerKillFuture {
		kill_worker(self.sender.take(), self.join.take())
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

fn evaluate_policies<I: Message + Send>(policies: &WorkerPolicies<I>, message: &I) -> Result<(), TransitStatus> {
	for gate in policies.receptor_gates().iter() {
		let status = gate.evaluate(message);
		if status != TransitStatus::Ok {
			return Err(status);
		}
	}
	Ok(())
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
		if let Err(status) = evaluate_policies(&policies, message.as_ref()) {
			let _ = respond_to.send(Err(status));
			continue;
		}

		let output = handler(message, trace, Arc::clone(&config)).await;
		let _ = respond_to.send(Ok(output));
	}
}
