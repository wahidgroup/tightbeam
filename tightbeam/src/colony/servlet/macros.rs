//! Servlet macros for generating containerized tightbeam applications

/// Common methods shared by all servlets (addr, stop, join)
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
				$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
			}
		}

		#[allow(dead_code)]
		#[cfg(feature = "tokio")]
		pub async fn join(
			mut self,
		) -> ::core::result::Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet::servlet_runtime::rt::join(handle).await
			} else {
				Ok(())
			}
		}

		#[allow(dead_code)]
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		pub fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
			if let Some(handle) = self.server_handle.take() {
				$crate::colony::servlet::servlet_runtime::rt::join(handle)
			} else {
				Ok(())
			}
		}
	};
}

// Helper macro: Generate servlet struct and workers struct definitions
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_structs {
	($vis:vis, $servlet_name:ident, $protocol:path, $env_config:ty) => {
		$crate::paste::paste! {
			$vis struct $servlet_name {
				server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				server_pool_handles: Vec<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace_handle: ::std::sync::Arc<::std::sync::Mutex<::std::sync::Arc<$crate::trace::TraceCollector>>>,
				#[allow(dead_code)]
				workers: ::std::sync::Arc<[<$servlet_name Workers>]>,
				_phantom: ::core::marker::PhantomData<$env_config>,
			}

			$vis struct [<$servlet_name Workers>] {
				#[allow(dead_code)]
				inner: ::std::collections::HashMap<String, Box<dyn $crate::colony::servlet::WorkerBox>>,
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
					W: $crate::colony::worker::Worker + $crate::colony::worker::WorkerMetadata + 'static,
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
			$crate::colony::servlet::servlet_runtime::rt::spawn({
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

								$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
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
				servlet_conf: $crate::colony::servlet::ServletConf<$protocol, $input>,
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
				config: Option<$crate::colony::servlet::ServletConf<$protocol, $input>>,
			) -> Result<Self, $crate::TightBeamError> {
				<Self as $crate::colony::servlet::Servlet<$input>>::start(trace, config).await
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
		impl $crate::colony::servlet::Servlet<$input> for $servlet_name {
			type Conf = $crate::colony::servlet::ServletConf<$protocol, $input>;
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

			async fn join(self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
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
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				for handle in self.server_pool_handles.drain(..) {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
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
