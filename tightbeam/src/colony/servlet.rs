//! Servlet framework for containerized tightbeam applications
//! // TODO Disambiguate from tokio
//!
//! Servlets provide a way to create self-contained, policy-driven message
//! processing applications that can be easily deployed and tested.

use crate::transport::TightBeamAddress;

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_servlet_common_methods {
	($protocol:path) => {
		#[allow(dead_code)]
		pub fn addr(&self) -> <$protocol as $crate::transport::Protocol>::Address {
			self.addr
		}

		#[allow(dead_code)]
		pub fn set_trace(&self, trace: $crate::trace::TraceCollector) {
			if let Ok(mut guard) = self.trace_handle.lock() {
				*guard = ::std::sync::Arc::new(trace);
			}
		}

		#[allow(dead_code)]
		pub fn stop(mut self) {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::abort(handle);
			}
		}

		#[allow(dead_code)]
		pub async fn join(mut self) -> ::core::result::Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::join(handle).await
			} else {
				Ok(())
			}
		}
	};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_servlet_common_methods {
	($protocol:path) => {
		#[allow(dead_code)]
		pub fn addr(&self) -> <$protocol as $crate::transport::Protocol>::Address {
			self.addr
		}

		pub fn set_trace(&self, trace: $crate::trace::TraceCollector) {
			if let Ok(mut guard) = self.trace_handle.lock() {
				*guard = ::std::sync::Arc::new(trace);
			}
		}

		pub fn stop(mut self) {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::abort(handle);
			}
		}

		pub async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::join(handle)
			} else {
				Ok(())
			}
		}
	};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_servlet_common_methods {
	($protocol:path) => {
		compile_error!("tightbeam::servlet! requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_servlet_parallelize_methods {
	($servlets_name:tt, $input:ty, $($worker_field:ident: $worker_type:ty),*) => {
		impl<$input> $servlets_name<$input> {
			/// Parallelize a message across all workers
			/// Returns a tuple of results in the same order as worker fields
			/// The input type matches the servlet's input type parameter
			pub fn parallelize(
				&self,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				message: ::std::sync::Arc<$input>,
			) -> impl ::core::future::Future + '_
			where
				$input: Send + Sync + 'static,
			{
				async move {
					$crate::paste::paste! {
						$(
							let msg_arc = Arc::clone(&message);
							let [<r $worker_field>] = self.$worker_field.relay(
								::std::sync::Arc::clone(&trace),
								Arc::clone(&msg_arc),
							);
						)*
						tokio::join!($([<r $worker_field>],)*)
					}
				}
			}
		}
	};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_servlet_parallelize_methods {
	($servlets_name:tt, $input:ty, $($worker_field:ident: $worker_type:ty),*) => {
		impl<$input> $servlets_name<$input> {
			/// Parallelize a message across all workers (sequential in std-only mode)
			/// Returns a tuple of results in the same order as worker fields
			pub async fn parallelize(
				&self,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				message: ::std::sync::Arc<$input>,
			)
			where
				$input: 'static,
			{
				$crate::paste::paste! {
					$(
						let [<r $worker_field>] = self.$worker_field
							.relay(::std::sync::Arc::clone(&trace), Arc::clone(&message))
							.await;
					)*
					($([<r $worker_field>],)*)
				}
			}
		}
	};
}

pub mod servlet_runtime {
	#[cfg(feature = "tokio")]
	pub mod rt {
		#[allow(dead_code)]
		pub type JoinHandle = tokio::task::JoinHandle<()>;
		#[allow(dead_code)]
		pub type JoinError = tokio::task::JoinError;
		#[allow(dead_code)]
		pub type ServerPoolSender = tokio::sync::mpsc::Sender<crate::Frame>;
		#[allow(dead_code)]
		pub type ServerPoolReceiver = tokio::sync::mpsc::Receiver<crate::Frame>;

		#[allow(dead_code)]
		pub fn abort(handle: JoinHandle) {
			handle.abort();
		}

		#[allow(dead_code)]
		pub async fn join(handle: JoinHandle) -> Result<(), JoinError> {
			handle.await
		}

		#[allow(dead_code)]
		pub fn server_pool_channel(capacity: usize) -> (ServerPoolSender, ServerPoolReceiver) {
			tokio::sync::mpsc::channel(capacity)
		}

		#[allow(dead_code)]
		pub async fn send_to_pool(sender: &ServerPoolSender, frame: crate::Frame) -> Result<(), ()> {
			sender.send(frame).await.map_err(|_| ())
		}

		#[allow(dead_code)]
		pub async fn recv_from_pool(receiver: &mut ServerPoolReceiver) -> Option<crate::Frame> {
			receiver.recv().await
		}

		#[allow(dead_code)]
		pub fn spawn<F>(fut: F) -> JoinHandle
		where
			F: core::future::Future<Output = ()> + Send + 'static,
		{
			tokio::spawn(fut)
		}
	}

	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	pub mod rt {
		use std::{
			io::{Error, ErrorKind},
			sync::mpsc,
			thread,
		};

		#[allow(dead_code)]
		pub type JoinHandle = thread::JoinHandle<()>;
		#[allow(dead_code)]
		pub type JoinError = Error;
		#[allow(dead_code)]
		pub type ServerPoolSender = mpsc::Sender<crate::Frame>;
		#[allow(dead_code)]
		pub type ServerPoolReceiver = mpsc::Receiver<crate::Frame>;

		#[allow(dead_code)]
		pub fn abort(_handle: JoinHandle) {
			// No cooperative cancellation for std threads; dropping detaches.
		}

		#[allow(dead_code)]
		pub fn join(handle: JoinHandle) -> Result<(), JoinError> {
			handle
				.join()
				.map_err(|_| Error::new(ErrorKind::Other, "servlet thread panicked"))
		}

		#[allow(dead_code)]
		pub fn server_pool_channel(_capacity: usize) -> (ServerPoolSender, ServerPoolReceiver) {
			mpsc::channel()
		}

		#[allow(dead_code)]
		pub fn send_to_pool(sender: &ServerPoolSender, frame: crate::Frame) -> Result<(), ()> {
			sender.send(frame).map_err(|_| ())
		}

		#[allow(dead_code)]
		pub fn recv_from_pool(receiver: &mut ServerPoolReceiver) -> Option<crate::Frame> {
			receiver.recv().ok()
		}

		#[allow(dead_code)]
		pub fn spawn<F>(fut: F) -> JoinHandle
		where
			F: core::future::Future<Output = ()> + Send + 'static,
		{
			thread::spawn(move || {
				// Simple block_on implementation for std
				use std::{
					future::Future,
					pin::Pin,
					task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
				};
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
			})
		}
	}
}

/// Trait for worker implementations
///
/// Provides a common interface for all colony created with the `servlet!`
/// macro. Servlets are containerized applications that process TightBeam
/// messages.
///
/// The servlet is generic over the input message type `I` that it processes.
/// All workers in a servlet must share the same input type.
pub trait Servlet<I> {
	/// Configuration type for this worker (use () for no config)
	type Conf;

	/// Address type for this servlet (protocol-specific)
	type Address: TightBeamAddress;

	/// Start the worker with optional configuration
	fn start(
		trace: crate::trace::TraceCollector,
		config: Option<Self::Conf>,
	) -> impl std::future::Future<Output = Result<Self, crate::TightBeamError>> + Send
	where
		Self: Sized;

	/// Get the local address the worker is bound to
	fn addr(&self) -> Self::Address;

	/// Stop the worker gracefully
	fn stop(self);

	/// Wait for the worker to finish
	fn join(
		self,
	) -> impl std::future::Future<Output = Result<(), crate::colony::servlet_runtime::rt::JoinError>> + Send;
}

/// Servlet macro for creating containerized tightbeam applications
#[macro_export]
macro_rules! servlet {
	// New syntax: Servlet with config only (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $trace_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_only, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $trace_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_only, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body, [$input], , [$(#[$meta])*]);
	};

	// New syntax: Servlet with config and init (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		init: |$init_config:ident| $init_body:block,
		handle: |$message:ident, $trace_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_only_with_init, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body, $init_config, $init_body, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		init: |$init_config:ident| $init_body:block,
		handle: |$message:ident, $trace_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_only_with_init, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body, $init_config, $init_body, [$input], , [$(#[$meta])*]);
	};

	// New syntax: Basic servlet with trace parameter (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		handle: |$message:ident, $trace:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				basic_with_trace, {}, {},
				|$message, $trace| $handler_body, [$input], pub, [$(#[$meta])*]);
		// Note: basic_with_trace servlets have start(TraceCollector) signature, not Servlet trait
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		handle: |$message:ident, $trace:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				basic_with_trace, {}, {},
				|$message, $trace| $handler_body, [$input], , [$(#[$meta])*]);
		// Note: basic_with_trace servlets have start(TraceCollector) signature, not Servlet trait
	};

	// New syntax: Basic servlet without trace (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		handle: |$message:ident, $trace_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				basic, {}, {},
				|$message, $trace_param| $handler_body, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		handle: |$message:ident, $trace_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				basic, {}, {},
				|$message, $trace_param| $handler_body, [$input], , [$(#[$meta])*]);
	};

	// New syntax: Servlet with router and config (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		router: $router:expr,
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $trace_param:ident, $router_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 router_and_config, $router, { $($config_field: $config_type,)* },
				 |$message, $trace_param, $router_param, $config_param| $handler_body, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		router: $router:expr,
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $trace_param:ident, $router_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 router_and_config, $router, { $($config_field: $config_type,)* },
				 |$message, $trace_param, $router_param, $config_param| $handler_body, [$input], , [$(#[$meta])*]);
	};

	// New syntax: Servlet with router only (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		router: $router:expr,
		handle: |$message:ident, $trace_param:ident, $router_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				router_only, $router, {},
				|$message, $trace_param, $router_param| $handler_body, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		router: $router:expr,
		handle: |$message:ident, $trace_param:ident, $router_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				router_only, $router, {},
				|$message, $trace_param, $router_param| $handler_body, [$input], , [$(#[$meta])*]);
	};

	// New syntax: Servlet with config and workers (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		workers: |$worker_config:ident| { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* $(,)? },
		handle: |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_and_workers, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		workers: |$worker_config:ident| { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* $(,)? },
		handle: |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_and_workers, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, [$input], , [$(#[$meta])*]);
	};

	// New syntax: Servlet with config, workers, and init (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		workers: |$worker_config:ident| { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* $(,)? },
		init: |$init_config:ident| $init_body:block,
		handle: |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_and_workers_with_init, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, $init_config, $init_body, [$input], pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty>,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		workers: |$worker_config:ident| { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* $(,)? },
		init: |$init_config:ident| $init_body:block,
		handle: |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate_with_attrs $servlet_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_and_workers_with_init, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, $init_config, $init_body, [$input], , [$(#[$meta])*]);
	};

	// Generate with attributes and visibility (new syntax)
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_only, {}, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $trace_param:ident, $config_param:ident| $handler_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, { $($config_field: $config_type,)* }, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_only, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* });
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_only, {}, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $trace_param:ident, $config_param:ident| $handler_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, { $($config_field: $config_type,)* }, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_only, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* });
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_only_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $trace_param:ident, $config_param:ident| $handler_body:expr, $init_config:ident, $init_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, { $($config_field: $config_type,)* }, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_only_with_init, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body, $init_config, $init_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_only_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $trace_param:ident, $config_param:ident| $handler_body:expr, $init_config:ident, $init_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, { $($config_field: $config_type,)* }, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_only_with_init, {}, { $($config_field: $config_type,)* },
				|$message, $trace_param, $config_param| $handler_body, $init_config, $init_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  basic_with_trace, {}, {},
			  |$message:ident, $trace:ident| $handler_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, {}, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				basic_with_trace, {}, {},
				|$message, $trace| $handler_body);
		// Note: basic_with_trace servlets have start(TraceCollector) signature, not Servlet trait
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  basic_with_trace, {}, {},
			  |$message:ident, $trace:ident| $handler_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, {}, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				basic_with_trace, {}, {},
				|$message, $trace| $handler_body);
		// Note: basic_with_trace servlets have start(TraceCollector) signature, not Servlet trait
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  basic, {}, {},
			  |$message:ident, $trace_param:ident| $handler_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, {}, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				basic, {}, {},
				|$message, $trace_param| $handler_body);
		servlet!(@impl_trait_basic_with_input $worker_name, $protocol, $input);
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  basic, {}, {},
			  |$message:ident, $trace_param:ident| $handler_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, {}, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				basic, {}, {},
				|$message, $trace_param| $handler_body);
		servlet!(@impl_trait_basic_with_input $worker_name, $protocol, $input);
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $trace_param:ident, $router_param:ident, $config_param:ident| $handler_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, { $($config_field: $config_type,)* }, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				router_and_config, $router, { $($config_field: $config_type,)* },
				|$message, $trace_param, $router_param, $config_param| $handler_body);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* });
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $trace_param:ident, $router_param:ident, $config_param:ident| $handler_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, { $($config_field: $config_type,)* }, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				router_and_config, $router, { $($config_field: $config_type,)* },
				|$message, $trace_param, $router_param, $config_param| $handler_body);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* });
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  router_only, $router:tt, {},
			  |$message:ident, $trace_param:ident, $router_param:ident| $handler_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, {}, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				router_only, $router, {},
				|$message, $trace_param, $router_param| $handler_body);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, {});
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  router_only, $router:tt, {},
			  |$message:ident, $trace_param:ident, $router_param:ident| $handler_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_attrs $worker_name, $protocol, {}, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				router_only, $router, {},
				|$message, $trace_param, $router_param| $handler_body);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, {});
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_and_workers, {}, { $($config_field:ident: $config_type:ty,)* },
			  { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
			  |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@get_input_type_with_attrs [$input], $worker_name, $protocol, [$($policy_key: $policy_val),*], { $($config_field: $config_type,)* }, { $($worker_field: $worker_type = $worker_init),* }, |$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, pub, [$(#[$meta])*]);
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_and_workers, {}, { $($config_field:ident: $config_type:ty,)* },
			  { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
			  |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@get_input_type_with_attrs [$input], $worker_name, $protocol, [$($policy_key: $policy_val),*], { $($config_field: $config_type,)* }, { $($worker_field: $worker_type = $worker_init),* }, |$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, , [$(#[$meta])*]);
	};

	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_and_workers_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
			  { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
			  |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, $init_config:ident, $init_body:expr, [$input:ty], pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_workers_and_attrs $worker_name, $protocol, $input, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* }, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_and_workers_with_init, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, $init_config, $init_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};
	(@generate_with_attrs $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_and_workers_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
			  { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
			  |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, $init_config:ident, $init_body:expr, [$input:ty], , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_workers_and_attrs $worker_name, $protocol, $input, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* }, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_and_workers_with_init, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, $init_config, $init_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};
	// Extract input type with attributes - use provided or default to ()
	(@get_input_type_with_attrs [$input:ty], $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*], { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:tt = $worker_init:expr),* }, |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, pub, [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_workers_and_attrs $worker_name, $protocol, $input, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* }, pub, [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_and_workers, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, $input);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* });
	};
	(@get_input_type_with_attrs [$input:ty], $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*], { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:tt = $worker_init:expr),* }, |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, , [$(#[$meta:meta])*]) => {
		servlet!(@impl_struct_with_workers_and_attrs $worker_name, $protocol, $input, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* }, , [$(#[$meta])*]);
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_and_workers, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $trace_param, $config_param, $workers_param| $handler_body, $worker_config, $input);
		servlet!(@impl_trait_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* });
	};

	// No parallelize method - users should use tokio::join! directly for parallel execution
	(@impl_parallelize $worker_name:ident, $input:ty, $($worker_field:ident: $worker_type:tt),*) => {
		// Intentionally empty - users use tokio::join! directly
	};

	// Generate struct with attributes and visibility (new syntax)
	(@impl_struct_with_attrs $worker_name:ident, $protocol:path, {}, pub, [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		pub struct $worker_name {
			server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
		}
	};

	(@impl_struct_with_attrs $worker_name:ident, $protocol:path, {}, , [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		struct $worker_name {
			server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
		}
	};
	(@impl_struct_with_attrs $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }, pub, [$(#[$meta:meta])*]) => {
		$crate::paste::paste! {
			$(#[$meta])*
			pub struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
			}

			pub struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}
		}
	};
	(@impl_struct_with_attrs $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }, , [$(#[$meta:meta])*]) => {
		$crate::paste::paste! {
			$(#[$meta])*
			struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
			}

			struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}
		}
	};

	// Generate struct with workers and attributes
	(@impl_struct_with_workers_and_attrs $worker_name:ident, $protocol:path, $input:ty, { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:tt),* }, pub, [$(#[$meta:meta])*]) => {
		$crate::paste::paste! {
			$(#[$meta])*
			pub struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
				#[allow(dead_code)]
				workers: ::std::sync::Arc<[<$worker_name Servlets>]<$input>>,
			}

			pub struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}

			pub struct [<$worker_name Servlets>]<I> {
				$(pub $worker_field: $worker_type,)*
				#[allow(dead_code)]
				_phantom: ::std::marker::PhantomData<I>,
			}

			servlet!(@impl_parallelize $worker_name, $input, $($worker_field: $worker_type),*);
		}
	};
	(@impl_struct_with_workers_and_attrs $worker_name:ident, $protocol:path, $input:ty, { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:tt),* }, , [$(#[$meta:meta])*]) => {
		$crate::paste::paste! {
			$(#[$meta])*
			struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
				#[allow(dead_code)]
				workers: ::std::sync::Arc<[<$worker_name Servlets>]<$input>>,
			}

			struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}

			struct [<$worker_name Servlets>]<I> {
				$(pub $worker_field: $worker_type,)*
				#[allow(dead_code)]
				_phantom: ::std::marker::PhantomData<I>,
			}

			servlet!(@impl_parallelize $worker_name, $input, $($worker_field: $worker_type),*);
		}
	};

	// Generate implementation methods
	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
				|$message:ident, $router_param:ident, $config_param:ident| $handler_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(trace: $crate::trace::TraceCollector, config: ::std::sync::Arc<[<$worker_name Conf>]>) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle), $router, config,
						(|$message: $crate::Frame, $trace_param, $router_param, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   router_only, $router:tt, {},
				   |$message:ident, $router_param:ident| $handler_body:expr) => {
		impl $worker_name {
			pub async fn start(trace: $crate::trace::TraceCollector) -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
				let (server_handle, server_pool_handles) = servlet!(@build_server
					$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle), $router,
					(|$message: $crate::Frame, $trace_param, $router_param| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
			}

			servlet!(@common_methods $protocol);
		}

		servlet!(@drop_impl $worker_name);
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   config_only, {}, { $($config_field:ident: $config_type:ty,)* },
				   |$message:ident, $trace_param:ident, $config_param:ident| $handler_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(trace: $crate::trace::TraceCollector, config: ::std::sync::Arc<[<$worker_name Conf>]>) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle), config,
						(|$message: $crate::Frame, $trace_param, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   config_only_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
				   |$message:ident, $trace_param:ident, $config_param:ident| $handler_body:expr, $init_config:ident, $init_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(trace: $crate::trace::TraceCollector, config: ::std::sync::Arc<[<$worker_name Conf>]>) -> $crate::error::Result<Self> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));

					// Run init block - must return Result<(), TightBeamError>
					let $init_config = &*config;
					let init_result: core::result::Result<(), $crate::TightBeamError> = (|| $init_body)();
					init_result?;

					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle), config,
						(|$message: $crate::Frame, $trace_param, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   basic_with_trace, {}, {},
				   |$message:ident, $trace:ident| $handler_body:expr) => {
		impl $worker_name {
			pub async fn start(assertions: $crate::trace::TraceCollector) -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(assertions)));
				let (server_handle, server_pool_handles) = servlet!(@build_server_with_assertions
					$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle),
					(|$message: $crate::Frame, $trace| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
			}

			servlet!(@common_methods $protocol);
		}

		servlet!(@drop_impl $worker_name);
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   basic_with_assertions, {}, {},
				   |$message:ident, $trace:ident| $handler_body:expr, $assertions:expr) => {
		impl $worker_name {
			pub async fn start(assertions: $crate::trace::TraceCollector) -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(assertions)));
				let (server_handle, server_pool_handles) = servlet!(@build_server_with_assertions
					$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle),
					(|$message: $crate::Frame, $trace| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
			}

			servlet!(@common_methods $protocol);
		}

		servlet!(@drop_impl $worker_name);
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   basic, {}, {},
				   |$message:ident, $trace_param:ident| $handler_body:expr) => {
		impl $worker_name {
			pub async fn start(trace: $crate::trace::TraceCollector) -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));
				let (server_handle, server_pool_handles) = servlet!(@build_server
					$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle),
					(|$message: $crate::Frame, $trace_param| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr, trace_handle })
			}

			servlet!(@common_methods $protocol);
		}

		servlet!(@drop_impl $worker_name);
	};

	// Generate trait implementation (without config) - MUST come first to match before the with-config pattern
	(@impl_trait $worker_name:ident, $protocol:path, {}) => {
		// For servlets without workers, we can't extract input type, so use a placeholder
		// This case is for servlets that don't use workers
		impl $crate::colony::Servlet<()> for $worker_name {
			type Conf = ();
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(trace: $crate::trace::TraceCollector, config: Option<Self::Conf>) -> Result<Self, $crate::TightBeamError> {
				let _ = config;
				Self::start(trace).await
			}

			fn addr(&self) -> Self::Address {
				self.addr
			}

			fn stop(self) {
				self.stop()
			}

			async fn join(self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
				self.join().await
			}
		}
	};

	// Generate trait implementation for basic servlets with explicit input
	(@impl_trait_basic_with_input $worker_name:ident, $protocol:path, $input:ty) => {
		impl $crate::colony::Servlet<$input> for $worker_name {
			type Conf = ();
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(trace: $crate::trace::TraceCollector, config: Option<Self::Conf>) -> Result<Self, $crate::TightBeamError> {
				let _ = config;
				Self::start(trace).await
			}

			fn addr(&self) -> Self::Address {
				self.addr
			}

			fn stop(self) {
				self.stop()
			}

			async fn join(self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
				self.join().await
			}
		}
	};

	// Generate trait implementation (with config, no workers)
	(@impl_trait $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)+ }) => {
		$crate::paste::paste! {
			// For servlets without workers, use () as input type
			impl $crate::colony::Servlet<()> for $worker_name {
				type Conf = ::std::sync::Arc<[<$worker_name Conf>]>;
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(trace: $crate::trace::TraceCollector, config: Option<Self::Conf>) -> $crate::error::Result<Self> {
					let cfg = config.ok_or_else(|| $crate::TightBeamError::MissingConfiguration)?;
					Self::start(trace, cfg).await
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(self) {
					self.stop()
				}

				async fn join(self) -> ::core::result::Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					self.join().await
				}
			}
		}
	};


	// Generate trait implementation (with workers - has input type)
	(@impl_trait_with_input $worker_name:ident, $protocol:path, $input:ty, { $($config_field:ident: $config_type:ty,)* }) => {
		$crate::paste::paste! {
			impl $crate::colony::Servlet<$input> for $worker_name {
				type Conf = ::std::sync::Arc<[<$worker_name Conf>]>;
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(trace: $crate::trace::TraceCollector, config: Option<Self::Conf>) -> $crate::error::Result<Self> {
					let cfg = config.ok_or_else(|| $crate::TightBeamError::MissingConfiguration)?;
					Self::start(trace, cfg).await
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(self) {
					self.stop()
				}

				async fn join(self) -> ::core::result::Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					self.join().await
				}
			}
		}
	};


	// Generate struct with provided input type
	(@impl_struct_with_workers $worker_name:ident, $protocol:path, $input:ty, { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:tt),* }) => {
		servlet!(@build_with_input $worker_name, $protocol, $input, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* });
	};

	// Extract input type from first worker: WorkerName<Input, Output>
	(@extract_and_build $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }, { $first_worker_field:ident: $first_worker_type:tt, $($rest_worker_field:ident: $rest_worker_type:tt),* }) => {
		servlet!(@parse_first_worker $first_worker_type, $worker_name, $protocol, { $($config_field: $config_type,)* }, { $first_worker_field: $first_worker_type, $($rest_worker_field: $rest_worker_type),* });
	};

	// Parse first worker type and extract input
	(@parse_first_worker $worker_name:ident < $input:ty, $output:ty >, $servlet_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }, { $first_worker_field:ident: $first_worker_type:tt, $($rest_worker_field:ident: $rest_worker_type:tt),* }) => {
		// Validate all workers have same input type
		servlet!(@validate_all_workers $input, $first_worker_type, $($rest_worker_type),*);
		// Generate struct with extracted input type
		servlet!(@build_with_input $servlet_name, $protocol, $input, { $($config_field: $config_type,)* }, { $first_worker_field: $first_worker_type, $($rest_worker_field: $rest_worker_type),* });
	};

	// Validate all workers share the same input type
	(@validate_all_workers $expected_input:ty, $first:tt, $next:tt, $($rest:tt),*) => {
		servlet!(@check_worker_input $expected_input, $next);
		servlet!(@validate_all_workers $expected_input, $first, $($rest),*);
	};

	(@validate_all_workers $expected_input:ty, $first:tt,) => {};

	// Check a single worker's input type matches expected
	(@check_worker_input $expected_input:ty, $worker_name:ident < $input:ty, $output:ty >) => {
		const _: () = {
			fn assert_same<T>() {}
			fn check() {
				assert_same::<$expected_input>();
				assert_same::<$input>();
			}
		};
	};

	// Build struct with known input type
	(@build_with_input $worker_name:ident, $protocol:path, $input:ty, { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:tt),* }) => {
		$crate::paste::paste! {
			pub struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
				#[allow(dead_code)]
				workers: ::std::sync::Arc<[<$worker_name Servlets>]<$input>>,
			}

			pub struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}

			pub struct [<$worker_name Servlets>]<I> {
				$(pub $worker_field: $worker_type,)*
				#[allow(dead_code)]
				_phantom: ::std::marker::PhantomData<I>,
			}

			servlet!(@impl_parallelize $worker_name, $input, $($worker_field: $worker_type),*);
		}
	};

	// Extract input type for trait implementation
	(@extract_input_for_trait $worker_type:tt, $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }) => {
		servlet!(@parse_first_worker_for_trait $worker_type, $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	(@parse_first_worker_for_trait $worker_name:ident < $input:ty, $output:ty >, $servlet_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }) => {
		servlet!(@impl_trait_with_input $servlet_name, $protocol, $input, { $($config_field: $config_type,)* });
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
		config_and_workers, {}, { $($config_field:ident: $config_type:ty,)* },
		{ $($worker_field:ident: $worker_type:tt = $worker_init:expr),* },
		|$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, $input:ty) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(trace: $crate::trace::TraceCollector, config: ::std::sync::Arc<[<$worker_name Conf>]>) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));

					let $worker_config = &*config;
					$(
						let $worker_field = <_ as $crate::colony::Worker>::start($worker_init).await?;
					)*
					$crate::paste::paste! {
						let workers_val = [<$worker_name Servlets>]::<$input> {
							$($worker_field,)*
							_phantom: ::std::marker::PhantomData,
						};
					}
					let workers = ::std::sync::Arc::new(workers_val);

					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config_and_workers
						$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle), config, ::std::sync::Arc::clone(&workers),
					(|$message: $crate::Frame, $trace_param, $config_param, $workers_param| async move { $handler_body }));

					Ok(Self {
						server_handle: Some(server_handle),
						server_pool_handles,
						addr,
						workers,
						trace_handle,
					})
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl_with_workers $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
		config_and_workers_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
		{ $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
		|$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, $init_config:ident, $init_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(trace: $crate::trace::TraceCollector, config: ::std::sync::Arc<[<$worker_name Conf>]>) -> $crate::error::Result<Self> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::new(trace)));

					// Run init block - must return Result<(), TightBeamError>
					let $init_config = &*config;
					let init_result: $crate::error::Result<()> = (|| $init_body)();
					init_result?;

					let $worker_config = &*config;
					$(
						let $worker_field = <_ as $crate::colony::Worker>::start($worker_init).await?;
					)*
					let workers = [<$worker_name Servlets>]::<$input> {
						$($worker_field,)*
						_phantom: ::std::marker::PhantomData,
					};
					let workers = ::std::sync::Arc::new(workers);

					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config_and_workers
						$protocol, listener, [$($policy_key: $policy_val),*], ::std::sync::Arc::clone(&trace_handle), config, ::std::sync::Arc::clone(&workers),
						(|$message: $crate::Frame, $trace_param, $config_param, $workers_param| async move { $handler_body }));

					Ok(Self {
						server_handle: Some(server_handle),
						server_pool_handles,
						addr,
						workers,
						trace_handle,
					})
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl_with_workers $worker_name);
		}
	};

	// Build server with config and workers (non-empty policies)
	(@build_server_with_config_and_workers $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $trace:expr, $config:ident, $workers:expr, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $body:block)) => {
		{
			let config_arc = $config;
			let workers_arc = $workers;
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg| {
				let config_arc = ::std::sync::Arc::clone(&config_arc);
				let workers_arc = ::std::sync::Arc::clone(&workers_arc);
				let trace_handle = ::std::sync::Arc::clone(&trace_handle);
					async move {
						let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
						let $config_param = &config_arc;
						let $workers_param = &workers_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with config and workers (empty policies)
	(@build_server_with_config_and_workers $protocol:path, $listener:ident, [], $trace:expr, $config:ident, $workers:expr, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $body:block)) => {
		{
			let config_arc = $config;
			let workers_arc = $workers;
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg| {
				let config_arc = ::std::sync::Arc::clone(&config_arc);
				let workers_arc = ::std::sync::Arc::clone(&workers_arc);
				let trace_handle = ::std::sync::Arc::clone(&trace_handle);
				async move {
					let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
					let $config_param = &config_arc;
					let $workers_param = &workers_arc;
					$body
				}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Common methods shared by all colony
	(@common_methods $protocol:path) => {
		$crate::__tightbeam_servlet_common_methods!($protocol);
	};

	// Drop implementation shared by all colony
	(@drop_impl $worker_name:ident) => {
		impl Drop for $worker_name {
			fn drop(&mut self) {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
				// Abort all pool handles
				for handle in self.server_pool_handles.drain(..) {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};

	// Drop implementation with workers
	(@drop_impl_with_workers $worker_name:ident) => {
		impl Drop for $worker_name {
			fn drop(&mut self) {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
				// Abort all pool handles
				for handle in self.server_pool_handles.drain(..) {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};

	// Build server variants (simplified with proper routing to existing patterns)
	(@build_server_with_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),*],
							   $trace:expr, $router:tt, $config:ident, $handler:tt) => {
		servlet!(@build_server_router_config $protocol, $listener, [$($policy_key: $policy_val),*],
				 $trace, $router, $config, $handler)
	};

	(@build_server_with_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),*],
							   $trace:expr, $config:ident, $handler:tt) => {
		servlet!(@build_server_config_only $protocol, $listener, [$($policy_key: $policy_val),*],
				 $trace, $config, $handler)
	};

	// Protocol setup - updated to handle protocol paths
	(@setup_protocol $protocol:path, $listener:ident, $addr:ident) => {
		let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let ($listener, $addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;
	};

	// Build server with router and config (non-empty policies)
	(@build_server_router_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $trace:expr, $router:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $router_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let config_arc = $config;
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg| {
					let router_arc = ::std::sync::Arc::clone(&router_arc);
					let config_arc = ::std::sync::Arc::clone(&config_arc);
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
					async move {
						let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
						let $router_param = &router_arc;
						let $config_param = &config_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with router and config (empty policies)
	(@build_server_router_config $protocol:path, $listener:ident, [], $trace:expr, $router:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $router_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let config_arc = $config;
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg| {
					let router_arc = ::std::sync::Arc::clone(&router_arc);
					let config_arc = ::std::sync::Arc::clone(&config_arc);
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
					async move {
						let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
						let $router_param = &router_arc;
						let $config_param = &config_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with config only (non-empty policies)
	(@build_server_config_only $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $trace:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let config_arc = $config;
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg| {
					let config_arc = ::std::sync::Arc::clone(&config_arc);
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
				async move {
					let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
					let $config_param = &config_arc;
					$body
				}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with config only (empty policies)
	(@build_server_config_only $protocol:path, $listener:ident, [], $trace:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let config_arc = $config;
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg| {
					let config_arc = ::std::sync::Arc::clone(&config_arc);
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
				async move {
					let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
					let $config_param = &config_arc;
					$body
				}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with router only (non-empty policies)
	(@build_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $trace:expr, $router:expr, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $router_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg| {
					let router_arc = ::std::sync::Arc::clone(&router_arc);
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
				async move {
					let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
					let $router_param = &router_arc;
					$body
				}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with router only (empty policies)
	(@build_server $protocol:path, $listener:ident, [], $trace:expr, $router:expr, (|$msg:ident: $msg_ty:ty, $trace_param:ident, $router_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg| {
					let router_arc = ::std::sync::Arc::clone(&router_arc);
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
				async move {
					let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
					let $router_param = &router_arc;
					$body
				}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with assertions (non-empty policies)
	(@build_server_with_assertions $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $assertions:expr, (|$msg:ident: $msg_ty:ty, $trace:ident| async move $body:block)) => {
		{
			let trace_handle = $assertions;
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $crate::Frame| {
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
					async move {
						let $trace = ::std::sync::Arc::clone(&*trace_handle.lock()?);
						$body
					}
				}
			};

			(server_handle, Vec::new())
		}
	};

	// Build server with assertions (empty policies)
	(@build_server_with_assertions $protocol:path, $listener:ident, [], $assertions:expr, (|$msg:ident: $msg_ty:ty, $trace:ident| async move $body:block)) => {
		{
			let trace_handle = $assertions;
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $crate::Frame| {
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
					async move {
						let $trace = ::std::sync::Arc::clone(&*trace_handle.lock()?);
						$body
					}
				}
			};

			(server_handle, Vec::new())
		}
	};

	// Build server basic (non-empty policies)
	(@build_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $trace:expr, (|$msg:ident: $msg_ty:ty, $trace_param:ident| async move $body:block)) => {
		{
			// For now, return empty pool - the server macro spawns tasks per connection
			// which already provides concurrency
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $crate::Frame| {
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
					async move {
						let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
						$body
					}
				}
			};

			(server_handle, Vec::new())
		}
	};

	// Build server basic (empty policies)
	(@build_server $protocol:path, $listener:ident, [], $trace:expr, (|$msg:ident: $msg_ty:ty, $trace_param:ident| async move $body:block)) => {
		{
			// For now, return empty pool - the server macro spawns tasks per connection
			// which already provides concurrency
			let trace_handle = ::std::sync::Arc::clone(&$trace);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $crate::Frame| {
					let trace_handle = ::std::sync::Arc::clone(&trace_handle);
				async move {
					let $trace_param = ::std::sync::Arc::clone(&*trace_handle.lock()?);
					$body
				}
				}
			};

			(server_handle, Vec::new())
		}
	};
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use crate::der::Sequence;
	use crate::transport::policy::PolicyConf;

	#[cfg(feature = "tokio")]
	use crate::transport::tcp::r#async::TokioListener as Listener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	use crate::transport::tcp::TcpListener;

	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = TcpListener<std::net::TcpListener>;

	#[derive(crate::Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct RequestMessage {
		pub content: String,
		pub lucky_number: u32,
	}

	#[derive(crate::Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct ResponseMessage {
		pub result: String,
		pub is_winner: bool,
	}

	servlet! {
		PingPongServlet<RequestMessage>,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		config: {
			lotto_number: u32,
		},
		handle: |message, _trace, config| async move {
			let decoded: RequestMessage = crate::decode(&message.message)?;
			let is_winner = decoded.lucky_number == config.lotto_number;
			if decoded.content == "PING" {
				 Ok(Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						order: 1_700_000_000u64,
						message: ResponseMessage {
							result: "PONG".to_string(),
							is_winner,
						}
				 }?))
			 } else {
				 Ok(None)
			}
		}
	}

	#[cfg(all(feature = "tokio", feature = "tcp", feature = "std"))]
	crate::test_servlet! {
		name: test_worker_with_test_async_case,
		worker_threads: 2,
		protocol: Listener,
		setup: || {
				PingPongServlet::start(
					crate::trace::TraceCollector::new(),
					::std::sync::Arc::new(PingPongServletConf { lotto_number: 42 }),
			)
		},
		assertions: |client| async move {
			fn generate_message(
				lucky_number: u32,
				content: Option<String>
			) -> Result<crate::Frame, crate::TightBeamError> {
				let message = RequestMessage {
					content: content.unwrap_or_else(|| "PING".to_string()),
					lucky_number,
				};

				crate::compose! {
					V0: id: b"test-ping",
						order: 1_700_000_000u64,
						message: message
				}
			}

			// Test winning case
			let ping_message = generate_message(42, None)?;
			let response = client.emit(ping_message, None).await?;
			let response_message: ResponseMessage = crate::decode(&response.ok_or("No response")?.message)?;
			assert_eq!(response_message.result, "PONG");
			assert!(response_message.is_winner);

			let ping_message_loser = generate_message(99, None)?;
			let response = client.emit(ping_message_loser, None).await?;
			let response_message: ResponseMessage = crate::decode(&response.ok_or("No response")?.message)?;
			assert_eq!(response_message.result, "PONG");
			assert!(!response_message.is_winner);

			Ok(())
		}
	}

	mod workers {
		use super::*;
		use crate::policy::{ReceptorPolicy, TransitStatus};
		use crate::Beamable;

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

		crate::worker! {
			name: LuckyNumberWorker<RequestMessage, bool>,
			config: {
				lotto_number: u32,
			},
			handle: |message, _trace, config| async move {
				message.lucky_number == config.lotto_number
			}
		}

		crate::worker! {
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

		crate::servlet! {
			PingPongServletWithWorker<RequestMessage>,
			protocol: Listener,
			policies: {
				with_collector_gate: [crate::policy::AcceptAllGate],
				// with_x509: [some_cert]
				// with_x509_gate: [crate::somewhere::CertificateValidationLike]
			},
			config: {
				lotto_number: u32,
			},
			workers: |config| {
				ping_pong: PingPongWorker = PingPongWorker::start(),
				lucky_number: LuckyNumberWorker = LuckyNumberWorker::start(LuckyNumberWorkerConf {
					lotto_number: config.lotto_number,
				})
			},
			handle: |message, trace, _config, workers| async move {
				let decoded: RequestMessage = crate::decode(&message.message)?;
				let decoded_arc = Arc::new(decoded);
				let (ping_result, lucky_result) = tokio::join!(
					workers.ping_pong.relay(Arc::clone(&trace), Arc::clone(&decoded_arc)),
					workers.lucky_number.relay(Arc::clone(&trace), Arc::clone(&decoded_arc))
				);

				let reply = match ping_result {
					Ok(reply) => reply,
					Err(_) => return Ok(None),
				};

				let is_winner = match lucky_result {
					Ok(is_winner) => is_winner,
					Err(_) => return Ok(None),
				};

				Ok(crate::compose! {
					V0: id: message.metadata.id.clone(),
						message: ResponseMessage {
							result: reply.result,
							is_winner,
						}
				}?.into())
			}
		}

		#[cfg(all(feature = "tokio", feature = "tcp", feature = "std"))]
		crate::test_servlet! {
			name: test_servlet_with_workers,
			worker_threads: 2,
			protocol: Listener,
			setup: || {
				PingPongServletWithWorker::start(
					crate::trace::TraceCollector::new(),
					::std::sync::Arc::new(PingPongServletWithWorkerConf {
					lotto_number: 42,
				}))
			},
			assertions: |client| async move {
				fn generate_message(
					lucky_number: u32,
					content: Option<String>
				) -> Result<crate::Frame, crate::TightBeamError> {
					let message = RequestMessage {
						content: content.unwrap_or_else(|| "PING".to_string()),
						lucky_number,
					};

					crate::compose! { V0: id: b"test-ping", message: message }
				}

				// Test winning case
				let ping_message = generate_message(42, None)?;
				let response = client.emit(ping_message, None).await?;
				let response_message: ResponseMessage = crate::decode(&response.ok_or("No response")?.message)?;
				assert_eq!(response_message.result, "PONG");
				assert!(response_message.is_winner);

				Ok(())
			}
		}
	}
}
