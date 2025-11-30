//! Servlet framework for containerized tightbeam applications
//!
//! Servlets provide a way to create self-contained, policy-driven message
//! processing applications that can be easily deployed and tested.

use core::convert::TryFrom;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::Worker;
use crate::core::Message;
use crate::trace::TraceCollector;
use crate::transport::Protocol;
use crate::transport::TightBeamAddress;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::crypto::key::KeySpec;
#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::crypto::x509::Certificate;
#[cfg(feature = "x509")]
use crate::crypto::x509::CertificateSpec;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;
#[cfg(feature = "x509")]
use crate::transport::TransportEncryptionConfig;

#[macro_export]
macro_rules! __tightbeam_servlet_common_methods {
	($protocol:path) => {
		#[allow(dead_code)]
		pub fn addr(&self) -> <$protocol as $crate::transport::Protocol>::Address {
			self.addr
		}

		#[allow(dead_code)]
		pub fn set_trace(&self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) {
			if let Ok(mut guard) = self.trace_handle.lock() {
				*guard = trace;
			}
		}

		#[allow(dead_code)]
		pub fn stop(mut self) {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::abort(handle);
			}
		}

		#[allow(dead_code)]
		#[cfg(feature = "tokio")]
		pub async fn join(mut self) -> ::core::result::Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::join(handle).await
			} else {
				Ok(())
			}
		}

		#[allow(dead_code)]
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		pub fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet_runtime::rt::join(handle)
			} else {
				Ok(())
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

/// Type alias for boxed worker start future
pub type WorkerBoxStartFuture = Pin<Box<dyn Future<Output = Result<Box<dyn WorkerBox>, TightBeamError>> + Send>>;

/// Trait for type-erased worker lifecycle management
pub trait WorkerBox: Send + Sync + core::any::Any {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture;
}

impl<W: Worker + 'static> WorkerBox for W {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture {
		Box::pin(async move {
			let started = (*self).start(trace).await?;
			Ok(Box::new(started) as Box<dyn WorkerBox>)
		})
	}
}

// Downcast helper
impl dyn WorkerBox {
	pub fn downcast_ref<W: 'static>(&self) -> Option<&W> {
		(self as &dyn core::any::Any).downcast_ref()
	}
}

/// Configuration for a servlet, containing x509, application config, and workers
pub struct ServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	pub(crate) _protocol: PhantomData<P>,
	pub(crate) _message: PhantomData<M>,
	#[cfg(feature = "x509")]
	pub(crate) x509_config: Option<TransportEncryptionConfig<crate::crypto::profiles::DefaultCryptoProvider>>,
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn crate::policy::GatePolicy + Send + Sync>>,
}

/// Builder for ServletConf
pub struct ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	#[cfg(feature = "x509")]
	x509_config: Option<TransportEncryptionConfig<crate::crypto::profiles::DefaultCryptoProvider>>,
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn crate::policy::GatePolicy + Send + Sync>>,
	_phantom: PhantomData<(P, M)>,
}

impl<P, M> ServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Create a new ServletConf builder
	pub fn builder() -> ServletConfBuilder<P, M> {
		ServletConfBuilder::default()
	}

	/// Get a worker by name (downcasted to the specific type)
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	/// Get the x509 configuration
	#[cfg(feature = "x509")]
	pub fn to_encryption_config_ref(
		&self,
	) -> Option<&TransportEncryptionConfig<crate::crypto::profiles::DefaultCryptoProvider>> {
		self.x509_config.as_ref()
	}

	/// Get the servlet application config (downcasted to the specific type)
	pub fn to_env_config_ref<C: 'static>(&self) -> Option<&Arc<C>> {
		self.servlet_config.as_ref()?.downcast_ref()
	}

	/// Get servlet config
	pub fn to_servlet_conf_ref(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
		self.servlet_config.as_ref()
	}

	/// Get workers map
	pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
		self.workers
	}

	/// Get collector gates
	pub fn to_collector_gates(self) -> Vec<Arc<dyn crate::policy::GatePolicy + Send + Sync>> {
		self.collector_gates
	}

	/// Get collector gates by reference
	pub fn collector_gates_ref(&self) -> &[Arc<dyn crate::policy::GatePolicy + Send + Sync>] {
		&self.collector_gates
	}
}

impl<P, M> Default for ServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	fn default() -> Self {
		Self {
			_protocol: PhantomData,
			_message: PhantomData,
			#[cfg(feature = "x509")]
			x509_config: None,
			servlet_config: Some(Arc::new(())),
			workers: HashMap::new(),
			collector_gates: Vec::new(),
		}
	}
}

impl<P, M> Default for ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	fn default() -> Self {
		Self {
			#[cfg(feature = "x509")]
			x509_config: None,
			servlet_config: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			_phantom: PhantomData,
		}
	}
}

impl<P, M> ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Add x509 configuration for encrypted transport
	#[cfg(feature = "x509")]
	pub fn with_certificate(
		mut self,
		cert: CertificateSpec,
		key: KeySpec,
		validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self, TightBeamError> {
		let cert_obj = Certificate::try_from(cert)?;
		let key_mgr = HandshakeKeyManager::try_from(key)?;
		self.x509_config = Some(TransportEncryptionConfig::new(cert_obj, key_mgr).with_client_validators(validators));
		Ok(self)
	}

	/// Add servlet application configuration
	/// TODO avoid need when config is ()
	#[must_use]
	pub fn with_config<C: Send + Sync + 'static>(mut self, config: Arc<C>) -> Self {
		self.servlet_config = Some(config);
		self
	}

	/// Add a worker using its WorkerMetadata name
	pub fn with_worker<W>(mut self, worker: W) -> Self
	where
		W: Worker + crate::colony::WorkerMetadata + 'static,
	{
		self.workers
			.insert(W::name().to_string(), Box::new(worker) as Box<dyn WorkerBox>);
		self
	}

	/// Add a collector gate policy
	pub fn with_collector_gate<G>(mut self, gate: G) -> Self
	where
		G: crate::policy::GatePolicy + Send + Sync + 'static,
	{
		self.collector_gates.push(Arc::new(gate));
		self
	}

	/// Build the final ServletConf
	pub fn build(self) -> ServletConf<P, M> {
		ServletConf {
			_protocol: PhantomData,
			_message: PhantomData,
			#[cfg(feature = "x509")]
			x509_config: self.x509_config,
			servlet_config: self.servlet_config,
			workers: self.workers,
			collector_gates: self.collector_gates,
		}
	}
}

/// Trait for servlet implementations
///
/// Provides a common interface for all servlets created with the `servlet!`
/// macro. Servlets are containerized applications that process TightBeam
/// messages.
///
/// The servlet is generic over the input message type `I` that it processes.
/// All workers in a servlet must share the same input type.
pub trait Servlet<I> {
	/// Configuration type for this servlet (use ServletConf)
	type Conf;

	/// Address type for this servlet (protocol-specific)
	type Address: TightBeamAddress;

	/// Start the servlet with configuration
	fn start(
		trace: Arc<crate::trace::TraceCollector>,
		config: Option<Self::Conf>,
	) -> impl Future<Output = Result<Self, crate::TightBeamError>> + Send
	where
		Self: Sized;

	/// Get the local address the servlet is bound to
	fn addr(&self) -> Self::Address;

	/// Stop the servlet gracefully
	fn stop(self);

	/// Wait for the servlet to finish
	fn join(self) -> impl Future<Output = Result<(), crate::colony::servlet_runtime::rt::JoinError>> + Send;
}

// Helper macro: Generate servlet struct and workers struct definitions
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_structs {
	($vis:vis, $servlet_name:ident, $protocol:path, $env_config:ty) => {
		$crate::paste::paste! {
			$vis struct $servlet_name {
				server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
				#[allow(dead_code)]
				workers: ::std::sync::Arc<[<$servlet_name Workers>]>,
				_phantom: ::core::marker::PhantomData<$env_config>,
			}

			$vis struct [<$servlet_name Workers>] {
				#[allow(dead_code)]
				inner: ::std::collections::HashMap<String, Box<dyn $crate::colony::WorkerBox>>,
				#[allow(dead_code)]
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
			}
		}
	};
}

// Helper macro: Generate workers implementation (get, relay methods)
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_workers_impl {
	($vis:vis, $servlet_name:ident) => {
		$crate::paste::paste! {
			impl [<$servlet_name Workers>] {
				#[allow(dead_code)]
				$vis fn get<W: 'static>(&self, name: &str) -> Option<&W> {
					self.inner.get(name)?.downcast_ref()
				}

				#[allow(dead_code)]
				$vis async fn relay<W>(&self, input: ::std::sync::Arc<W::Input>)
					-> Result<W::Output, $crate::TightBeamError>
				where
					W: $crate::colony::Worker + $crate::colony::WorkerMetadata + 'static,
				{
					let name = W::name();
					let worker = self.get::<W>(name).ok_or($crate::TightBeamError::MissingConfiguration)?;
					worker.relay(input).await.map_err(|e| e.into())
				}
			}
		}
	};
}

// Helper macro: Generate server creation logic (with or without collector gates)
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_create_server {
	(
		$protocol:path,
		$listener:ident,
		$collector_gates:ident,
		$config_for_handler:ident,
		$workers_for_handler:ident,
		$trace_for_handler:ident,
		$env_config:ty,
		$message:ident,
		$trace_param:ident,
		$config_param:ident,
		$workers_param:ident,
		$handler_body:block
	) => {
		if $collector_gates.is_empty() {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |$message| {
					let config_clone = ::std::sync::Arc::clone(&$config_for_handler);
					let workers_clone = ::std::sync::Arc::clone(&$workers_for_handler);
					let trace_clone = ::std::sync::Arc::clone(&$trace_for_handler);
					async move {
						let $trace_param = ::std::sync::Arc::clone(&*trace_clone.lock()?);
						let config_arc = ::std::sync::Arc::downcast::<$env_config>(config_clone)
							.map_err(|_| $crate::TightBeamError::MissingConfiguration)?;
						let $config_param: &$env_config = &*config_arc;
						let $workers_param = &*workers_clone;
						$handler_body
					}
				}
			}
		} else {
			use $crate::transport::policy::PolicyConf;
			$crate::colony::servlet_runtime::rt::spawn({
				use $crate::transport::MessageCollector;
				async move {
					loop {
						match $listener.accept().await {
							Ok((mut transport, _addr)) => {
								for gate in &$collector_gates {
									transport = transport.with_collector_gate(::std::sync::Arc::clone(gate));
								}

								let config_clone = ::std::sync::Arc::clone(&$config_for_handler);
								let workers_clone = ::std::sync::Arc::clone(&$workers_for_handler);
								let trace_clone = ::std::sync::Arc::clone(&$trace_for_handler);

								$crate::colony::servlet_runtime::rt::spawn(async move {
									let mut transport = transport;
									loop {
										let (frame, status) = match transport.collect_message().await {
											Ok(result) => result,
											Err(_err) => break,
										};

										let frame_owned = ::std::sync::Arc::try_unwrap(frame)
											.unwrap_or_else(|arc| arc.as_ref().clone());
										let response = if status == $crate::policy::TransitStatus::Accepted {
											let $message = frame_owned;
											let trace_for_handler = ::std::sync::Arc::clone(&trace_clone);
											let config_for_handler = ::std::sync::Arc::clone(&config_clone);
											let workers_for_handler = ::std::sync::Arc::clone(&workers_clone);
											let result: Result<Option<$crate::Frame>, $crate::TightBeamError> =
												async move {
													let $trace_param =
														::std::sync::Arc::clone(&*trace_for_handler.lock()?);
													let config_arc =
														::std::sync::Arc::downcast::<$env_config>(config_for_handler)
															.map_err(|_| $crate::TightBeamError::MissingConfiguration)?;
													let $config_param: &$env_config = &*config_arc;
													let $workers_param = &*workers_for_handler;
													$handler_body
												}
												.await;

											match result {
												Ok(opt) => opt,
												Err(_) => None,
											}
										} else {
											None
										};

										match transport.send_response(status, response).await {
											Ok(()) => continue,
											Err(_err) => break,
										}
									}
								});
							}
							Err(_err) => break,
						}
					}
				}
			})
		}
	};
}

// Helper macro: Generate the start_impl method with all server setup logic
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_start_impl {
	(
		$servlet_name:ident,
		$protocol:path,
		$input:ty,
		$env_config:ty,
		$message:ident,
		$trace_param:ident,
		$config_param:ident,
		$workers_param:ident,
		$handler_body:block
	) => {
		$crate::paste::paste! {
			async fn start_impl(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				servlet_conf: $crate::colony::ServletConf<$protocol, $input>,
			) -> Result<Self, $crate::TightBeamError> {
				let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;

				#[cfg(feature = "x509")]
				let (listener, addr) = if let Some(x509_cfg) = servlet_conf.to_encryption_config_ref() {
					<$protocol as $crate::transport::EncryptedProtocol>::bind_with(
						bind_addr,
						x509_cfg.clone()
					).await?
				} else {
					<$protocol as $crate::transport::Protocol>::bind(bind_addr).await?
				};

				#[cfg(not(feature = "x509"))]
				let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

				let config_any = ::std::sync::Arc::clone(
					servlet_conf.to_servlet_conf_ref()
						.ok_or($crate::TightBeamError::MissingConfiguration)?
				);

				let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::clone(&trace)));
				let collector_gates = servlet_conf.collector_gates_ref().to_vec();
				let workers_map = servlet_conf.to_workers();

				// Auto-start all workers with servlet trace
				let mut started_workers = ::std::collections::HashMap::new();
				for (name, worker_box) in workers_map {
					let started = worker_box.start_boxed(::std::sync::Arc::clone(&trace)).await?;
					started_workers.insert(name, started);
				}

				let workers = ::std::sync::Arc::new([<$servlet_name Workers>] {
					inner: started_workers,
					trace: ::std::sync::Arc::clone(&trace),
				});
				let config_for_handler = ::std::sync::Arc::clone(&config_any);
				let workers_for_handler = ::std::sync::Arc::clone(&workers);
				let trace_for_handler = ::std::sync::Arc::clone(&trace_handle);

				let server_handle = $crate::__servlet_create_server!(
					$protocol,
					listener,
					collector_gates,
					config_for_handler,
					workers_for_handler,
					trace_for_handler,
					$env_config,
					$message,
					$trace_param,
					$config_param,
					$workers_param,
					$handler_body
				);

				Ok(Self {
					server_handle: Some(server_handle),
					server_pool_handles: Vec::new(),
					addr,
					trace_handle,
					workers,
					_phantom: ::core::marker::PhantomData,
				})
			}
		}
	};
}

// Helper macro: Generate servlet implementation methods (start, common methods)
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_impl_methods {
	($vis:vis, $servlet_name:ident, $protocol:path, $input:ty) => {
		impl $servlet_name {
			#[allow(dead_code)]
			$vis async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Option<$crate::colony::ServletConf<$protocol, $input>>,
			) -> Result<Self, $crate::TightBeamError> {
				<Self as $crate::colony::Servlet<$input>>::start(trace, config).await
			}

			$crate::__tightbeam_servlet_common_methods!($protocol);
		}
	};
}

// Helper macro: Generate Servlet trait implementation
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_trait_impl {
	($servlet_name:ident, $protocol:path, $input:ty) => {
		impl $crate::colony::Servlet<$input> for $servlet_name {
			type Conf = $crate::colony::ServletConf<$protocol, $input>;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Option<Self::Conf>,
			) -> Result<Self, $crate::TightBeamError> {
				let servlet_conf = config.unwrap_or_default();
				Self::start_impl(trace, servlet_conf).await
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
}

// Helper macro: Generate Drop implementation
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_drop_impl {
	($servlet_name:ident) => {
		impl Drop for $servlet_name {
			fn drop(&mut self) {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
				for handle in self.server_pool_handles.drain(..) {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};
}

/// Servlet macro for creating containerized tightbeam applications
#[macro_export]
macro_rules! servlet {
	// PUBLIC SERVLET WITH ENVCONFIG
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path,
		handle: |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		$crate::paste::paste! {
			$(#[$meta])*
			$crate::__servlet_structs!(pub, $servlet_name, $protocol, $env_config);
			$crate::__servlet_workers_impl!(pub, $servlet_name);

			impl $servlet_name {
				$crate::__servlet_start_impl!(
					$servlet_name, $protocol, $input, $env_config,
					$message, $trace_param, $config_param, $workers_param,
					$handler_body
				);
			}

			$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
			$crate::__servlet_trait_impl!($servlet_name, $protocol, $input);
			$crate::__servlet_drop_impl!($servlet_name);
		}
	};

	// PRIVATE SERVLET WITH ENVCONFIG
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path,
		handle: |$message:ident, $trace_param:ident, $config_param:ident, $workers_param:ident| async move $handler_body:block
	) => {
		$crate::paste::paste! {
			$(#[$meta])*
			$crate::__servlet_structs!(, $servlet_name, $protocol, $env_config);
			$crate::__servlet_workers_impl!(, $servlet_name);

			impl $servlet_name {
				$crate::__servlet_start_impl!(
					$servlet_name, $protocol, $input, $env_config,
					$message, $trace_param, $config_param, $workers_param,
					$handler_body
				);
			}

			$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
			$crate::__servlet_trait_impl!($servlet_name, $protocol, $input);
			$crate::__servlet_drop_impl!($servlet_name);
		}
	};
}
