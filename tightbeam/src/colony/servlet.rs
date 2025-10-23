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
			self.addr.clone()
		}

		pub fn stop(mut self) {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::abort(handle);
			}
		}

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
			self.addr.clone()
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
pub trait Servlet {
	/// Configuration type for this worker (use () for no config)
	type Conf;

	/// Address type for this servlet (protocol-specific)
	type Address: TightBeamAddress;

	/// Start the worker with optional configuration
	fn start(
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
	// Full worker with router, policies, and config
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		router: $router:expr,
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $router_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 router_and_config, $router, { $($config_field: $config_type,)* },
				 |$message, $router_param, $config_param| $handler_body);
	};

	// Servlet with router only
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		router: $router:expr,
		handle: |$message:ident, $router_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				router_only, $router, {},
				|$message, $router_param| $handler_body);
	};

	// Servlet with config only
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_only, {}, { $($config_field: $config_type,)* },
				|$message, $config_param| $handler_body);
	};

	// Servlet with config and init (no workers)
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		init: |$init_config:ident| $init_body:block,
		handle: |$message:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_only_with_init, {}, { $($config_field: $config_type,)* },
				|$message, $config_param| $handler_body, $init_config, $init_body);
	};

	// Servlet with config and workers
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		workers: |$worker_config:ident| { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* $(,)? },
		handle: |$message:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_and_workers, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $config_param, $workers_param| $handler_body, $worker_config);
	};

	// Servlet with config, workers, and init
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		workers: |$worker_config:ident| { $($worker_field:ident: $worker_type:ty = $worker_init:expr),* $(,)? },
		init: |$init_config:ident| $init_body:block,
		handle: |$message:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				config_and_workers_with_init, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $config_param, $workers_param| $handler_body, $worker_config, $init_config, $init_body);
	};

	// Basic worker with just message
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:tt),* $(,)? },)?
		handle: |$message:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				basic, {}, {},
				|$message| $handler_body);
	};

	// Main implementation generator
	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $router_param:ident, $config_param:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, $protocol, { $($config_field: $config_type,)* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				router_and_config, $router, { $($config_field: $config_type,)* },
				|$message, $router_param, $config_param| $handler_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  router_only, $router:tt, {},
			  |$message:ident, $router_param:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, $protocol, {});
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				router_only, $router, {},
				|$message, $router_param| $handler_body);
		servlet!(@impl_trait $worker_name, $protocol, {});
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_only, {}, { $( $config_field:ident : $config_type:ty, )* },
			  |$message:ident, $config_param:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, $protocol, { $($config_field: $config_type,)* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_only, {}, { $($config_field: $config_type,)* },
				|$message, $config_param| $handler_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  config_only_with_init, {}, { $( $config_field:ident : $config_type:ty, )* },
			  |$message:ident, $config_param:ident| $handler_body:expr, $init_config:ident, $init_body:expr) => {
		servlet!(@impl_struct $worker_name, $protocol, { $($config_field: $config_type,)* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_only_with_init, {}, { $($config_field: $config_type,)* },
				|$message, $config_param| $handler_body, $init_config, $init_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			  basic, {}, {},
			  |$message:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, $protocol, {});
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				basic, {}, {},
				|$message| $handler_body);
		servlet!(@impl_trait $worker_name, $protocol, {});
	};

	// Servlet with config and workers
	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			config_and_workers, {}, { $( $config_field:ident : $config_type:ty, )* },
			{ $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
			|$message:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident) => {
		servlet!(@impl_struct_with_workers $worker_name, $protocol, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_and_workers, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $config_param, $workers_param| $handler_body, $worker_config);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	// Servlet with config, workers, and init
	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt,)*],
			config_and_workers_with_init, {}, { $( $config_field:ident : $config_type:ty, )* },
			{ $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
			|$message:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, $init_config:ident, $init_body:expr) => {
		servlet!(@impl_struct_with_workers $worker_name, $protocol, { $($config_field: $config_type,)* }, { $($worker_field: $worker_type),* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				config_and_workers_with_init, {}, { $($config_field: $config_type,)* },
				{ $($worker_field: $worker_type = $worker_init),* },
				|$message, $config_param, $workers_param| $handler_body, $worker_config, $init_config, $init_body);
		servlet!(@impl_trait $worker_name, $protocol, { $($config_field: $config_type,)* });
	};

	// Generate struct and optional config struct
	(@impl_struct $worker_name:ident, $protocol:path, {}) => {
		pub struct $worker_name {
			server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
			server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
		}
	};

	(@impl_struct $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }) => {
		$crate::paste::paste! {
			pub struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
			}

			#[derive(Clone)]
			pub struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}
		}
	};

	// Generate implementation methods
	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
				|$message:ident, $router_param:ident, $config_param:ident| $handler_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Conf>]) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], $router, config,
						(|$message: $crate::Frame, $router_param, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr })
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
			pub async fn start() -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let (server_handle, server_pool_handles) = servlet!(@build_server
					$protocol, listener, [$($policy_key: $policy_val),*], $router,
					(|$message: $crate::Frame, $router_param| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr })
			}

			servlet!(@common_methods $protocol);
		}

		servlet!(@drop_impl $worker_name);
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   config_only, {}, { $($config_field:ident: $config_type:ty,)* },
				   |$message:ident, $config_param:ident| $handler_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Conf>]) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], config,
						(|$message: $crate::Frame, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr })
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   config_only_with_init, {}, { $($config_field:ident: $config_type:ty,)* },
				   |$message:ident, $config_param:ident| $handler_body:expr, $init_config:ident, $init_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Conf>]) -> $crate::error::Result<Self> {
					servlet!(@setup_protocol $protocol, listener, addr);

					// Run init block - must return Result<(), TightBeamError>
					let $init_config = &config;
					let init_result: core::result::Result<(), $crate::TightBeamError> = (|| $init_body)();
					init_result?;

					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], config,
						(|$message: $crate::Frame, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr })
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
				   basic, {}, {},
				   |$message:ident| $handler_body:expr) => {
		impl $worker_name {
			pub async fn start() -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let (server_handle, server_pool_handles) = servlet!(@build_server
					$protocol, listener, [$($policy_key: $policy_val),*],
					(|$message: $crate::Frame| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), server_pool_handles, addr })
			}

			servlet!(@common_methods $protocol);
		}

		servlet!(@drop_impl $worker_name);
	};

	// Generate trait implementation (without config) - MUST come first to match before the with-config pattern
	(@impl_trait $worker_name:ident, $protocol:path, {}) => {
		impl $crate::colony::Servlet for $worker_name {
			type Conf = ();
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(config: Option<Self::Conf>) -> Result<Self, $crate::TightBeamError> {
				let _ = config;
				Self::start().await
			}

			fn addr(&self) -> Self::Address {
				self.addr.clone()
			}

			fn stop(self) {
				self.stop()
			}

			async fn join(self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
				self.join().await
			}
		}
	};

	// Generate trait implementation (with config)
	(@impl_trait $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)+ }) => {
		$crate::paste::paste! {
			impl $crate::colony::Servlet for $worker_name {
				type Conf = [<$worker_name Conf>];
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(config: Option<Self::Conf>) -> $crate::error::Result<Self> {
					let cfg = config.ok_or_else(|| $crate::TightBeamError::MissingConfiguration)?;
					Self::start(cfg).await
				}

				fn addr(&self) -> Self::Address {
					self.addr.clone()
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

	(@impl_struct_with_workers $worker_name:ident, $protocol:path, { $($config_field:ident: $config_type:ty,)* }, { $($worker_field:ident: $worker_type:ty),* }) => {
		$crate::paste::paste! {
			pub struct $worker_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				#[allow(dead_code)]
				workers: ::std::sync::Arc<[<$worker_name Servlets>]>,
			}

			#[derive(Clone)]
			pub struct [<$worker_name Conf>] {
				$(pub $config_field: $config_type,)*
			}

			pub struct [<$worker_name Servlets>] {
				$(pub $worker_field: $worker_type,)*
			}
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*],
		config_and_workers, {}, { $($config_field:ident: $config_type:ty,)* },
		{ $($worker_field:ident: $worker_type:ty = $worker_init:expr),* },
		|$message:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Conf>]) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);

					let $worker_config = &config;
					$(
						let $worker_field = $worker_init?;
					)*
					let workers = [<$worker_name Servlets>] {
						$($worker_field,)*
					};
					let workers = ::std::sync::Arc::new(workers);

					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config_and_workers
						$protocol, listener, [$($policy_key: $policy_val),*], config, workers.clone(),
						(|$message: $crate::Frame, $config_param, $workers_param| async move { $handler_body }));

					Ok(Self {
						server_handle: Some(server_handle),
						server_pool_handles,
						addr,
						workers,
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
		|$message:ident, $config_param:ident, $workers_param:ident| $handler_body:expr, $worker_config:ident, $init_config:ident, $init_body:expr) => {
		$crate::paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Conf>]) -> $crate::error::Result<Self> {
					servlet!(@setup_protocol $protocol, listener, addr);

					// Run init block - must return Result<(), TightBeamError>
					let $init_config = &config;
					let init_result: $crate::error::Result<()> = (|| $init_body)();
					init_result?;

					let $worker_config = &config;
					$(
						let $worker_field = $worker_init?;
					)*
					let workers = [<$worker_name Servlets>] {
						$($worker_field,)*
					};
					let workers = ::std::sync::Arc::new(workers);

					let (server_handle, server_pool_handles) = servlet!(@build_server_with_config_and_workers
						$protocol, listener, [$($policy_key: $policy_val),*], config, workers.clone(),
						(|$message: $crate::Frame, $config_param, $workers_param| async move { $handler_body }));

					Ok(Self {
						server_handle: Some(server_handle),
						server_pool_handles,
						addr,
						workers,
					})
				}

				servlet!(@common_methods $protocol);
			}

			servlet!(@drop_impl_with_workers $worker_name);
		}
	};

	// Build server with config and workers (non-empty policies)
	(@build_server_with_config_and_workers $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $config:ident, $workers:expr, (|$msg:ident: $msg_ty:ty, $config_param:ident, $workers_param:ident| async move $body:block)) => {
		{
			let config_arc = ::std::sync::Arc::new($config);
			let workers_arc = $workers;
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| {
					let config_arc = config_arc.clone();
					let workers_arc = workers_arc.clone();
					async move {
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
	(@build_server_with_config_and_workers $protocol:path, $listener:ident, [], $config:ident, $workers:expr, (|$msg:ident: $msg_ty:ty, $config_param:ident, $workers_param:ident| async move $body:block)) => {
		{
			let config_arc = ::std::sync::Arc::new($config);
			let workers_arc = $workers;
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| {
					let config_arc = config_arc.clone();
					let workers_arc = workers_arc.clone();
					async move {
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
							   $router:tt, $config:ident, $handler:tt) => {
		servlet!(@build_server_router_config $protocol, $listener, [$($policy_key: $policy_val),*],
				 $router, $config, $handler)
	};

	(@build_server_with_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),*],
							   $config:ident, $handler:tt) => {
		servlet!(@build_server_config_only $protocol, $listener, [$($policy_key: $policy_val),*],
				 $config, $handler)
	};

	// Protocol setup - updated to handle protocol paths
	(@setup_protocol $protocol:path, $listener:ident, $addr:ident) => {
		let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let ($listener, $addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;
	};

	// Build server with router and config (non-empty policies)
	(@build_server_router_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $router:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $router_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let config_arc = ::std::sync::Arc::new($config);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| {
					let router_arc = router_arc.clone();
					let config_arc = config_arc.clone();
					async move {
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
	(@build_server_router_config $protocol:path, $listener:ident, [], $router:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $router_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let config_arc = ::std::sync::Arc::new($config);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| {
					let router_arc = router_arc.clone();
					let config_arc = config_arc.clone();
					async move {
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
	(@build_server_config_only $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $config:ident, (|$msg:ident: $msg_ty:ty, $config_param:ident| async move $body:block)) => {
		{
			let config_arc = ::std::sync::Arc::new($config);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| {
					let config_arc = config_arc.clone();
					async move {
						let $config_param = &config_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with config only (empty policies)
	(@build_server_config_only $protocol:path, $listener:ident, [], $config:ident, (|$msg:ident: $msg_ty:ty, $config_param:ident| async move $body:block)) => {
		{
			let config_arc = ::std::sync::Arc::new($config);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| {
					let config_arc = config_arc.clone();
					async move {
						let $config_param = &config_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with router only (non-empty policies)
	(@build_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $router:expr, (|$msg:ident: $msg_ty:ty, $router_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| {
					let router_arc = router_arc.clone();
					async move {
						let $router_param = &router_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server with router only (empty policies)
	(@build_server $protocol:path, $listener:ident, [], $router:expr, (|$msg:ident: $msg_ty:ty, $router_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| {
					let router_arc = router_arc.clone();
					async move {
						let $router_param = &router_arc;
						$body
					}
				}
			};
			(server_handle, Vec::new())
		}
	};

	// Build server basic (non-empty policies)
	(@build_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], (|$msg:ident: $msg_ty:ty| async move $body:block)) => {
		{
			// For now, return empty pool - the server macro spawns tasks per connection
			// which already provides concurrency
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| {
					async move {
						$body
					}
				}
			};

			(server_handle, Vec::new())
		}
	};

	// Build server basic (empty policies)
	(@build_server $protocol:path, $listener:ident, [], (|$msg:ident: $msg_ty:ty| async move $body:block)) => {
		{
			// For now, return empty pool - the server macro spawns tasks per connection
			// which already provides concurrency
			let server_handle = $crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| {
					async move {
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
	use crate::der::Sequence;
	use crate::transport::policy::PolicyConf;

	#[cfg(feature = "tokio")]
	use crate::transport::tcp::r#async::TokioListener as Listener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	use crate::transport::tcp::TcpListener;
	#[cfg(feature = "tokio")]
	use crate::transport::MessageEmitter;

	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = TcpListener<std::net::TcpListener>;

	#[derive(crate::Beamable, Clone, Debug, PartialEq, Sequence)]
	struct RequestMessage {
		content: String,
		lucky_number: u32,
	}

	#[derive(crate::Beamable, Clone, Debug, PartialEq, Sequence)]
	struct ResponseMessage {
		result: String,
		is_winner: bool,
	}

	servlet! {
		name: PingPongServlet,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		config: {
			lotto_number: u32,
		},
		handle: |message, config| async move {
			let decoded: RequestMessage = crate::decode(&message.message).ok()?;
			let is_winner = decoded.lucky_number == config.lotto_number;
			if decoded.content == "PING" {
				 Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						order: 1_700_000_000u64,
						message: ResponseMessage {
							result: "PONG".to_string(),
							is_winner,
						}
				 }.ok()?)
			 } else {
				 None
			}
		}
	}

	#[cfg(all(feature = "tokio", feature = "tcp", feature = "std"))]
	crate::test_servlet! {
		name: test_worker_with_test_async_case,
		worker_threads: 2,
		protocol: Listener,
		setup: || {
			PingPongServlet::start(PingPongServletConf { lotto_number: 42 })
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
			let response_message: ResponseMessage = crate::decode(&response.unwrap().message)?;
			assert_eq!(response_message.result, "PONG");
			assert!(response_message.is_winner);

			let ping_message_loser = generate_message(99, None)?;
			let response = client.emit(ping_message_loser, None).await?;
			let response_message: ResponseMessage = crate::decode(&response.unwrap().message)?;
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
			handle: |message, config| async move {
				message.lucky_number == config.lotto_number
			}
		}

		crate::worker! {
			name: PingPongWorker<RequestMessage, PongMessage>,
			policies: {
				with_receptor_gate: [PingGate]
			},
			handle: |_message | async move {
				PongMessage {
					result: "PONG".to_string(),
				}
			}
		}

		crate::servlet! {
			name: PingPongServletWithWorker,
			protocol: Listener,
			policies: {
				with_collector_gate: [crate::policy::AcceptAllGate],
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
			handle: |message, _config, workers| async move {
				let decoded: RequestMessage = crate::decode(&message.message).ok()?;
				let (ping_result, lucky_result) = tokio::join!(
					workers.ping_pong.relay(decoded.clone()),
					workers.lucky_number.relay(decoded.clone())
				);

				let reply = match ping_result {
					Ok(reply) => reply,
					Err(_) => return None,
				};

				let is_winner = match lucky_result {
					Ok(is_winner) => is_winner,
					Err(_) => return None,
				};

				crate::compose! {
					V0: id: message.metadata.id.clone(),
						message: ResponseMessage {
							result: reply.result,
							is_winner,
						}
				}.ok()
			}
		}

		#[cfg(all(feature = "tokio", feature = "tcp", feature = "std"))]
		crate::test_servlet! {
			name: test_servlet_with_workers,
			worker_threads: 2,
			protocol: Listener,
			setup: || {
				PingPongServletWithWorker::start(PingPongServletWithWorkerConf {
					lotto_number: 42,
				})
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
				let response_message: ResponseMessage = crate::decode(&response.unwrap().message)?;
				assert_eq!(response_message.result, "PONG");
				assert!(response_message.is_winner);

				Ok(())
			}
		}
	}
}
