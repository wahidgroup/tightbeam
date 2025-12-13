//! Worker framework for message processing
//!
//! Workers are the fundamental processing units in the colony architecture.
//! They receive messages, apply policies, and produce responses.
//!
//! # Example
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

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::future::Future;
use core::pin::Pin;

#[cfg(feature = "derive")]
use crate::Errorizable;

use crate::policy::{ReceptorPolicy, TransitStatus};
use crate::trace::TraceCollector;
use crate::Message;

pub mod macros;

/// Re-export unified runtime primitives with worker-specific type aliases
pub mod worker_runtime {
	pub mod rt {
		pub use crate::runtime::rt::*;

		/// Queue sender type alias (for backwards compatibility)
		pub type QueueSender<T> = crate::runtime::rt::Sender<T>;

		/// Queue receiver type alias (for backwards compatibility)
		pub type QueueReceiver<T> = crate::runtime::rt::Receiver<T>;
	}
}

pub struct WorkerRequest<I: Send, O> {
	pub message: Arc<I>,
	pub respond_to: worker_runtime::rt::OneshotSender<Result<O, TransitStatus>>,
	pub trace: Arc<TraceCollector>,
}

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum WorkerRelayError {
	#[cfg_attr(feature = "derive", error("Worker queue closed"))]
	QueueClosed,
	#[cfg_attr(feature = "derive", error("Worker response channel dropped"))]
	ResponseDropped,
	#[cfg_attr(feature = "derive", error("Message rejected with status {:?}"))]
	#[cfg_attr(feature = "derive", from)]
	Rejected(TransitStatus),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for WorkerRelayError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::QueueClosed => f.write_str("worker queue closed"),
			Self::ResponseDropped => f.write_str("worker response channel dropped"),
			Self::Rejected(status) => write!(f, "message rejected with status {:?}", status),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl std::error::Error for WorkerRelayError {}

pub type WorkerRelayFuture<O> = Pin<Box<dyn Future<Output = Result<O, WorkerRelayError>> + Send + 'static>>;
pub type WorkerStartFuture<W> = Pin<Box<dyn Future<Output = Result<W, crate::error::TightBeamError>> + Send>>;

#[cfg(feature = "tokio")]
#[allow(dead_code)]
pub fn block_on_worker_future<F, T>(future: F) -> Result<T, std::io::Error>
where
	F: Future<Output = T> + Send + 'static,
	T: Send + 'static,
{
	// Try to use current runtime if available, otherwise create a new one
	match tokio::runtime::Handle::try_current() {
		Ok(handle) => Ok(handle.block_on(future)),
		Err(_) => {
			let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
			Ok(runtime.block_on(future))
		}
	}
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[allow(dead_code)]
pub fn block_on_worker_future<F, T>(future: F) -> T
where
	F: Future<Output = T> + Send + 'static,
	T: Send + 'static,
{
	worker_runtime::rt::block_on(future)
}

pub trait Worker: Send + Sync + Sized {
	type Input: Send + Sync + 'static;
	type Output: Send + 'static;
	type Config: Send + Sync + 'static;

	fn new(config: Self::Config) -> Self;

	fn start(self, trace: Arc<TraceCollector>) -> WorkerStartFuture<Self>;

	fn kill(self) -> ::core::result::Result<(), std::io::Error>;

	fn relay(&self, message: Arc<Self::Input>) -> WorkerRelayFuture<Self::Output>;

	fn queue_capacity(&self) -> usize;
}

/// Provides static metadata about a worker type
pub trait WorkerMetadata {
	/// Returns the registration name for this worker
	fn name() -> &'static str;
}

pub struct WorkerPolicies<I: Send> {
	#[allow(dead_code)]
	pub(crate) receptor_gates: Vec<Arc<dyn ReceptorPolicy<I> + Send + Sync>>,
}

impl<I: Send> WorkerPolicies<I> {
	pub fn receptor_gates(&self) -> &[Arc<dyn ReceptorPolicy<I> + Send + Sync>] {
		&self.receptor_gates
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

	use super::WorkerRelayError;
	use crate::der::Sequence;
	use crate::policy::{ReceptorPolicy, TransitStatus};
	use crate::Beamable;
	use crate::worker;

	#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct RequestMessage {
		content: String,
		lucky_number: u32,
	}

	#[derive(Sequence, Beamable, Clone, Debug, PartialEq)]
	pub struct PongMessage {
		result: String,
	}

	#[derive(Default)]
	struct PingGate;

	impl ReceptorPolicy<RequestMessage> for PingGate {
		fn evaluate(&self, maybe_ping: &RequestMessage) -> TransitStatus {
			if maybe_ping.content == "PING" {
				TransitStatus::Accepted
			} else {
				TransitStatus::Forbidden
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

	#[cfg(feature = "std")]
	crate::test_worker! {
		name: lucky_number_worker_checks_winner,
		setup: || {
			LuckyNumberDeterminer::new(LuckyNumberDeterminerConf { lotto_number: 42 })
		},
		assertions: |worker| async move {
			assert_eq!(worker.queue_capacity(), 64);

			let winner = worker.relay(Arc::new(RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			})).await?;
			assert!(winner);

			let loser = worker.relay(Arc::new(RequestMessage {
				content: "PING".to_string(),
				lucky_number: 7,
			})).await?;
			assert!(!loser);

			Ok(())
		}
	}

	#[cfg(feature = "std")]
	crate::test_worker! {
		name: test_ping_pong_worker,
		setup: || {
			PingPongWorker::new(())
		},
		assertions: |worker| async move {
			// Test accepted message
			let ping_msg = RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};
			let response = worker.relay(Arc::new(ping_msg)).await?;
			assert_eq!(response, PongMessage { result: "PONG".to_string() });

			// Test rejected message
			let pong_msg = RequestMessage {
				content: "PONG".to_string(),
				lucky_number: 42,
			};

			let result = worker.relay(Arc::new(pong_msg)).await;
			assert!(matches!(result, Err(WorkerRelayError::Rejected(_))));

			Ok(())
		}
	}
}
