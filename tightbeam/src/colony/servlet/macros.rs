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

// Helper macro: Generate servlet struct definition
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
				_phantom: ::core::marker::PhantomData<$env_config>,
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
		$servlet_context:ident,
		$trace_handle:ident,
		$frame:ident,
		$ctx:ident,
		$handler_body:block
	) => {
		if $collector_gates.is_empty() {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame_in| {
					let ctx_clone = ::std::sync::Arc::clone(&$servlet_context);
					async move {
						let $frame = frame_in;
						let $ctx = &*ctx_clone;
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

								let ctx_clone = ::std::sync::Arc::clone(&$servlet_context);

								$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
									let mut transport = transport;
									loop {
										let (frame_arc, status) = match transport.collect_message().await {
											Ok(result) => result,
											Err(_err) => break,
										};

										let frame_owned = ::std::sync::Arc::try_unwrap(frame_arc)
											.unwrap_or_else(|arc| arc.as_ref().clone());
										let response = if status == $crate::policy::TransitStatus::Accepted {
											let ctx_for_handler = ::std::sync::Arc::clone(&ctx_clone);
											let result: Result<Option<$crate::Frame>, $crate::TightBeamError> =
												async move {
													let $frame = frame_owned;
													let $ctx = &*ctx_for_handler;
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
		$frame:ident,
		$ctx:ident,
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

				let env_config = ::std::sync::Arc::clone(
					servlet_conf.to_servlet_conf_ref()
						.ok_or($crate::TightBeamError::MissingConfiguration)?
				);

				let trace_handle = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::sync::Arc::clone(&trace)));
				let collector_gates = servlet_conf.collector_gates_ref().to_vec();
				let hive_context = servlet_conf.hive_context().cloned();
				// to_workers() takes ownership, so call after other borrows
				let workers_map = servlet_conf.to_workers();

				// Auto-start all workers with servlet trace
				let mut started_workers = ::std::collections::HashMap::new();
				for (name, worker_box) in workers_map {
					let started = worker_box.start_boxed(::std::sync::Arc::clone(&trace)).await?;
					started_workers.insert(name, started);
				}

				// Create the unified servlet context
				let servlet_context = ::std::sync::Arc::new($crate::colony::servlet::ServletContext::new(
					::std::sync::Arc::clone(&trace),
					env_config,
					started_workers,
					hive_context,
				));

				let server_handle = $crate::__servlet_create_server!(
					$protocol,
					listener,
					collector_gates,
					servlet_context,
					trace_handle,
					$frame,
					$ctx,
					$handler_body
				);

				Ok(Self {
					server_handle: Some(server_handle),
					server_pool_handles: Vec::new(),
					addr,
					trace_handle,
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
		handle: |$frame:ident, $ctx:ident| async move $handler_body:block
	) => {
		$crate::paste::paste! {
			$(#[$meta])*
			$crate::__servlet_structs!(pub, $servlet_name, $protocol, $env_config);

			impl $servlet_name {
				$crate::__servlet_start_impl!(
					$servlet_name, $protocol, $input, $env_config,
					$frame, $ctx,
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
		handle: |$frame:ident, $ctx:ident| async move $handler_body:block
	) => {
		$crate::paste::paste! {
			$(#[$meta])*
			$crate::__servlet_structs!(, $servlet_name, $protocol, $env_config);

			impl $servlet_name {
				$crate::__servlet_start_impl!(
					$servlet_name, $protocol, $input, $env_config,
					$frame, $ctx,
					$handler_body
				);
			}

			$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
			$crate::__servlet_trait_impl!($servlet_name, $protocol, $input);
			$crate::__servlet_drop_impl!($servlet_name);
		}
	};
}
