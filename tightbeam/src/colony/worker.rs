#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(feature = "derive")]
use crate::Errorizable;

use crate::policy::{ReceptorPolicy, TransitStatus};
use crate::trace::TraceCollector;
use crate::Message;

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_worker_common_methods {
	($input:ty, $output:ty) => {
		#[allow(dead_code)]
		pub fn queue_capacity(&self) -> usize {
			self.queue
		}

		/// Relay a message to the worker
		pub async fn relay(
			&self,
			trace: $crate::trace::TraceCollector,
			message: ::std::sync::Arc<$input>,
		) -> ::core::result::Result<$output, $crate::colony::WorkerRelayError> {
			let sender = self.sender.as_ref().ok_or($crate::colony::WorkerRelayError::QueueClosed)?;
			let (tx, rx) = $crate::colony::worker_runtime::rt::oneshot();
			let result = $crate::colony::worker_runtime::rt::send(
				sender,
				$crate::colony::WorkerRequest { message, respond_to: tx, trace },
			)
			.await;
			result.map_err(|_| $crate::colony::WorkerRelayError::QueueClosed)?;

			let response = $crate::colony::worker_runtime::rt::wait_response(rx).await;
			match response {
				Ok(Ok(output)) => Ok(output),
				Ok(Err(status)) => Err($crate::colony::WorkerRelayError::Rejected(status)),
				Err(_) => Err($crate::colony::WorkerRelayError::ResponseDropped),
			}
		}

		#[allow(dead_code)]
		pub async fn kill(mut self) -> ::core::result::Result<(), tokio::task::JoinError> {
			if let Some(sender) = self.sender.take() {
				drop(sender);
			}

			if let Some(handle) = self.join.take() {
				$crate::colony::worker_runtime::rt::join(handle).await
			} else {
				Ok(())
			}
		}
	};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_worker_common_methods {
	($input:ty, $output:ty) => {
		#[allow(dead_code)]
		pub fn queue_capacity(&self) -> usize {
			self.queue
		}

		/// Relay a message to the worker
		pub async fn relay(
			&self,
			trace: crate::trace::TraceCollector,
			message: ::std::sync::Arc<$input>,
		) -> ::core::result::Result<$output, $crate::colony::WorkerRelayError> {
			let sender = self.sender.as_ref().ok_or($crate::colony::WorkerRelayError::QueueClosed)?;
			let (tx, rx) = $crate::colony::worker_runtime::rt::oneshot();
			$crate::colony::worker_runtime::rt::send(
				sender,
				$crate::colony::WorkerRequest { message, respond_to: tx, trace },
			)
			.map_err(|_| $crate::colony::WorkerRelayError::QueueClosed)?;

			let response = $crate::colony::worker_runtime::rt::wait_response(rx);
			match response {
				Ok(Ok(output)) => Ok(output),
				Ok(Err(status)) => Err($crate::colony::WorkerRelayError::Rejected(status)),
				Err(_) => Err($crate::colony::WorkerRelayError::ResponseDropped),
			}
		}

		#[allow(dead_code)]
		pub fn kill(mut self) -> ::core::result::Result<(), std::io::Error> {
			if let Some(sender) = self.sender.take() {
				drop(sender);
			}

			if let Some(handle) = self.join.take() {
				$crate::colony::worker_runtime::rt::join(handle)
			} else {
				Ok(())
			}
		}
	};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_worker_common_methods {
	($input:ty, $output:ty) => {
		compile_error!("tightbeam::worker! requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

pub mod worker_runtime {
	#![allow(dead_code)]
	#[cfg(feature = "tokio")]
	pub mod rt {
		pub type QueueSender<T> = tokio::sync::mpsc::Sender<T>;
		pub type QueueReceiver<T> = tokio::sync::mpsc::Receiver<T>;
		pub type ResponseSender<T> = tokio::sync::oneshot::Sender<T>;
		pub type ResponseReceiver<T> = tokio::sync::oneshot::Receiver<T>;
		pub type JoinHandle = tokio::task::JoinHandle<()>;

		pub fn channel<T>(cap: usize) -> (QueueSender<T>, QueueReceiver<T>) {
			tokio::sync::mpsc::channel(cap)
		}

		pub fn oneshot<T>() -> (ResponseSender<T>, ResponseReceiver<T>) {
			tokio::sync::oneshot::channel()
		}

		pub fn spawn<F>(fut: F) -> JoinHandle
		where
			F: core::future::Future<Output = ()> + Send + 'static,
		{
			tokio::spawn(fut)
		}

		pub async fn send<T>(sender: &QueueSender<T>, msg: T) -> Result<(), ()> {
			sender.send(msg).await.map_err(|_| ())
		}

		pub async fn recv<T>(recv: &mut QueueReceiver<T>) -> Option<T> {
			recv.recv().await
		}

		pub async fn wait_response<T>(rx: ResponseReceiver<T>) -> Result<T, ()> {
			rx.await.map_err(|_| ())
		}

		pub async fn join(handle: JoinHandle) -> Result<(), tokio::task::JoinError> {
			handle.await
		}

		pub fn abort(handle: &JoinHandle) {
			handle.abort();
		}
	}

	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	pub mod rt {
		#![allow(dead_code)]
		use std::{
			future::Future,
			pin::Pin,
			sync::mpsc,
			task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
			thread,
		};

		pub type QueueSender<T> = mpsc::Sender<T>;
		pub type QueueReceiver<T> = mpsc::Receiver<T>;
		pub type ResponseSender<T> = mpsc::Sender<T>;
		pub type ResponseReceiver<T> = mpsc::Receiver<T>;
		pub type JoinHandle = thread::JoinHandle<()>;

		pub fn channel<T>(_cap: usize) -> (QueueSender<T>, QueueReceiver<T>) {
			mpsc::channel()
		}

		pub fn oneshot<T>() -> (ResponseSender<T>, ResponseReceiver<T>) {
			mpsc::channel()
		}

		pub fn spawn<F>(fut: F) -> JoinHandle
		where
			F: Future<Output = ()> + Send + 'static,
		{
			thread::spawn(move || block_on(fut))
		}

		pub fn send<T>(sender: &QueueSender<T>, msg: T) -> Result<(), ()> {
			sender.send(msg).map_err(|_| ())
		}

		pub fn recv<T>(recv: &mut QueueReceiver<T>) -> Option<T> {
			recv.recv().ok()
		}

		pub fn wait_response<T>(rx: ResponseReceiver<T>) -> Result<T, ()> {
			rx.recv().map_err(|_| ())
		}

		pub fn join(handle: JoinHandle) -> Result<(), std::io::Error> {
			handle
				.join()
				.map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "worker panicked"))
		}

		pub fn abort(handle: &JoinHandle) {
			handle.thread().unpark();
		}

		fn block_on<F: Future>(mut fut: F) -> F::Output {
			fn raw_waker() -> RawWaker {
				fn clone(_: *const ()) -> RawWaker {
					raw_waker()
				}
				fn wake(_: *const ()) {}
				fn wake_by_ref(_: *const ()) {}
				fn drop(_: *const ()) {}
				RawWaker::new(core::ptr::null(), &RawWakerVTable::new(clone, wake, wake_by_ref, drop))
			}
			let waker = unsafe { Waker::from_raw(raw_waker()) };
			let mut cx = Context::from_waker(&waker);
			let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
			loop {
				match fut.as_mut().poll(&mut cx) {
					Poll::Ready(res) => break res,
					Poll::Pending => thread::yield_now(),
				}
			}
		}
	}
}

pub struct WorkerRequest<I: Send, O> {
	pub message: Arc<I>,
	pub respond_to: worker_runtime::rt::ResponseSender<Result<O, TransitStatus>>,
	pub trace: TraceCollector,
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

#[macro_export]
macro_rules! worker {
	(@queue $queue:expr) => { $queue };
	(@queue) => { 64usize };

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
		policies: { $( $policy_method:ident : $policy_value:tt ),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{ $( $policy_method : $policy_value ),* },
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		policies: { $( $policy_method:ident : $policy_value:tt ),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			no_config,
			{},
			{ $( $policy_method : $policy_value ),* },
			(|$message_ident, $trace_ident, _config| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		handle: |$message_ident:ident, $trace_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			no_config,
			{},
			{},
			(|$message_ident, $trace_ident, _config| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		policies: { $( $policy_method:ident : $policy_value:tt ),* $(,)? },
		config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{},
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(
		name: $worker_name:ident < $input:ty, $output:ty >,
		$(queue: $queue:expr,)?
		config: { $($cfg_field:ident : $cfg_ty:ty),* $(,)? },
		handle: |$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block
	) => {
		$crate::worker!(@generate
			$worker_name, $input, $output, [$($queue)?],
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{},
			(|$message_ident, $trace_ident, $config_ident| async move $handler_block)
		);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		$config_kind:ident,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			$config_kind,
			{ $($cfg_field: $cfg_ty,)* },
			{ $( $policy_method : $policy_value ),* },
			$handler
		);
		$crate::worker!(@drop_impl $worker_name);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, {});
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			no_config,
			{},
			{ $( $policy_method : $policy_value ),* },
			$handler
		);
		$crate::worker!(@drop_impl $worker_name);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{},
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, { $($cfg_field: $cfg_ty,)* });
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			config,
			{ $($cfg_field: $cfg_ty,)* },
			{},
			$handler
		);
		$crate::worker!(@drop_impl $worker_name);
	};

	(@generate $worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{},
		$handler:tt) => {
		$crate::worker!(@impl_struct $worker_name, $input, $output, {});
		$crate::worker!(@impl_methods
			$worker_name, $input, $output, [$($queue)?],
			no_config,
			{},
			{},
			$handler
		);
		$crate::worker!(@drop_impl $worker_name);
	};

	(@impl_struct $worker_name:ident, $input:ty, $output:ty, {}) => {
		pub struct $worker_name {
			sender: Option<$crate::colony::worker_runtime::rt::QueueSender<$crate::colony::WorkerRequest<$input, $output>>>,
			join: Option<$crate::colony::worker_runtime::rt::JoinHandle>,
			queue: usize,
		}
	};

	(@impl_struct $worker_name:ident, $input:ty, $output:ty, { $($cfg_field:ident: $cfg_ty:ty,)* }) => {
		$crate::paste::paste! {
			pub struct $worker_name {
				sender: Option<$crate::colony::worker_runtime::rt::QueueSender<$crate::colony::worker::WorkerRequest<$input, $output>>>,
				join: Option<$crate::colony::worker_runtime::rt::JoinHandle>,
				queue: usize,
			}

			#[derive(Clone)]
			pub struct [<$worker_name Conf>] {
				$(pub $cfg_field: $cfg_ty,)*
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt
	) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub fn start(config: [<$worker_name Conf>]) -> $crate::error::Result<Self> {
					let queue_capacity = $crate::worker!(@queue $($queue)?);
					let (tx, rx) = $crate::colony::worker_runtime::rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

					let config_arc = std::sync::Arc::new(config);
					let policies = std::sync::Arc::new(
						$crate::worker!(@build_policies $input, { $( $policy_method : $policy_value ),* })
					);

					let run_loop = {
						let config_arc = ::std::sync::Arc::clone(&config_arc);
						let policies = policies.clone();
						$crate::worker!(@run_loop rx, (config Some(config_arc)), policies, $handler)
					};

					let join = $crate::colony::worker_runtime::rt::spawn(run_loop);
					Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
				}

				$crate::worker!(@common_methods $input, $output);
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{ $( $policy_method:ident : $policy_value:tt ),* },
		$handler:tt
	) => {
		impl $worker_name {
			pub fn start() -> $crate::error::Result<Self> {
				let queue_capacity = $crate::worker!(@queue $($queue)?);
				let (tx, rx) = $crate::colony::worker_runtime::rt::channel::<$crate::colony::WorkerRequest<$input, $output>>(queue_capacity);

				let policies = std::sync::Arc::new(
					$crate::worker!(@build_policies $input, { $( $policy_method : $policy_value ),* })
				);

				let run_loop = {
					let policies = policies.clone();
					$crate::worker!(@run_loop rx, (config None), policies, $handler)
				};

				let join = $crate::colony::worker_runtime::rt::spawn(run_loop);
				Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
			}

			$crate::worker!(@common_methods $input, $output);
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		config,
		{ $($cfg_field:ident: $cfg_ty:ty,)* },
		{},
		$handler:tt
	) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub fn start(config: [<$worker_name Conf>]) -> $crate::Result<Self> {
					let queue_capacity = $crate::worker!(@queue $($queue)?);
					let (tx, rx) = rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

					let config_arc = Arc::new(config);
					let policies = Arc::new(
						$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
							.build(),
					);

					let run_loop = {
						let config_arc = ::std::sync::Arc::clone(&config_arc);
						let policies = policies.clone();
						$crate::worker!(@run_loop rx, (config Some(config_arc)), policies, $handler)
					};

					let join = rt::spawn(run_loop);
					Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
				}

				$crate::worker!(@common_methods $input, $output);
			}
		}
	};

	(@impl_methods
		$worker_name:ident, $input:ty, $output:ty, [$($queue:expr)?],
		no_config,
		{},
		{},
		$handler:tt
	) => {
		impl $worker_name {
			pub fn start() -> $crate::Result<Self> {
				let queue_capacity = $crate::worker!(@queue $($queue)?);
				let (tx, rx) = rt::channel::<$crate::colony::worker::WorkerRequest<$input, $output>>(queue_capacity);

				let policies = Arc::new(
					$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
						.build(),
				);

				let join = rt::spawn(async move {
					let policies = policies.clone();
					$crate::worker!(@run_loop rx, (config None), policies, $handler).await;
				});

				Ok(Self { sender: Some(tx), join: Some(join), queue: queue_capacity })
			}

			$crate::worker!(@common_methods $input, $output);
		}
	};

	(@run_loop $rx:ident, (config Some($config_arc:ident)), $policies:ident, (|$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block)) => {{
		let mut receiver = $rx;
		let config_arc = $config_arc;
		let policies = $policies;
		async move {
			while let Some(request) = $crate::colony::worker_runtime::rt::recv(&mut receiver).await {
				let $crate::colony::worker::WorkerRequest { message, respond_to, trace } = request;
				if let Err(status) = $crate::worker!(@evaluate_policies policies, &message) {
					let _ = respond_to.send(Err(status));
					continue;
				}
				let $message_ident = (*message).clone();
				let $trace_ident = trace;
				let $config_ident = config_arc.as_ref();
				let output = (async move $handler_block).await;
				let _ = respond_to.send(Ok(output));
			}
		}
	}};

	(@run_loop $rx:ident, (config None), $policies:ident, (|$message_ident:ident, $trace_ident:ident, $config_ident:ident| async move $handler_block:block)) => {{
		let mut receiver = $rx;
		let policies = $policies;
		async move {
			while let Some(request) = $crate::colony::worker_runtime::rt::recv(&mut receiver).await {
				let $crate::colony::WorkerRequest { message, respond_to, trace } = request;
				if let Err(status) = $crate::worker!(@evaluate_policies policies, &message) {
					let _ = respond_to.send(Err(status));
					continue;
				}
				let $message_ident = (*message).clone();
				let $trace_ident = trace;
				let $config_ident = ();
				let output = (async move $handler_block).await;
				let _ = respond_to.send(Ok(output));
			}
		}
	}};

	(@evaluate_policies $policies:expr, $message:expr) => {{
        let __result: ::core::result::Result<(), $crate::policy::TransitStatus> = (|| {
            for gate in $policies.receptor_gates().iter() {
                let status = gate.evaluate($message.as_ref());
                if status != $crate::policy::TransitStatus::Accepted {
                    return Err(status);
                }
            }
            Ok(())
        })();
        __result
    }};

	(@build_policies $input:ty, {}) => {{
		$crate::colony::WorkerPolicyBuilder::<$input>::default().build()
	}};

	(@build_policies $input:ty, { $( with_receptor_gate : [ $( $gate:expr ),* $(,)? ] ),* $(,)? }) => {{
		$crate::colony::worker::WorkerPolicyBuilder::<$input>::default()
			$(.with_receptor_gate([ $( $gate ),* ]))*
			.build()
	}};

	(@common_methods $input:ty, $output:ty) => {
		$crate::__tightbeam_worker_common_methods!($input, $output);
	};

	(@drop_impl $worker_name:ident) => {
		impl Drop for $worker_name {
			fn drop(&mut self) {
				if let Some(sender) = self.sender.take() {
					drop(sender);
				}

				if let Some(handle) = self.join.take() {
					$crate::colony::worker_runtime::rt::abort(&handle);
				}
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use crate::colony::worker::WorkerRelayError;
	use crate::der::Sequence;
	use crate::policy::{ReceptorPolicy, TransitStatus};
	use crate::Beamable;

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
			LuckyNumberDeterminer::start(LuckyNumberDeterminerConf { lotto_number: 42 })
		},
		assertions: |worker| async move {
			assert_eq!(worker.queue_capacity(), 64);

			let trace = crate::trace::TraceCollector::new();

			let winner = worker.relay(trace.clone(), ::std::sync::Arc::new(RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			})).await?;
			assert!(winner);

			let loser = worker.relay(trace.clone(), ::std::sync::Arc::new(RequestMessage {
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
			PingPongWorker::start()
		},
		assertions: |worker| async move {
			// Test accepted message
			let trace = crate::trace::TraceCollector::new();
			let ping_msg = RequestMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};
			let response = worker.relay(trace.clone(), ::std::sync::Arc::new(ping_msg)).await?;
			assert_eq!(response, PongMessage { result: "PONG".to_string() });

			// Test rejected message
			let pong_msg = RequestMessage {
				content: "PONG".to_string(),
				lucky_number: 42,
			};

			let result = worker.relay(trace, ::std::sync::Arc::new(pong_msg)).await;
			assert!(matches!(result, Err(WorkerRelayError::Rejected(_))));

			Ok(())
		}
	}
}
