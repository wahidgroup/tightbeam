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

// Helper macro: Assemble the ServletHandlers service from the handler
// arms and hand the listener to the library accept loop. Every arm is
// optional; absent kinds refuse with `Unimplemented`.
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_create_server {
	(
		$protocol:path,
		$listener:ident,
		$collector_gates:ident,
		$mux_offer:ident,
		$servlet_context:ident
		$(, handle: |$frame:ident, $ctx:ident| $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| $duplex_body:block)?
	) => {{
		let __service = $crate::colony::servlet::ServletHandlers::default()
			$(
				.on_unary(move |__frame_in: $crate::Frame, __ctx: ::std::sync::Arc<$crate::colony::servlet::ServletContext>| async move {
					let $frame = __frame_in;
					let $ctx = &*__ctx;
					let __response: ::core::result::Result<
						::core::option::Option<$crate::Frame>,
						$crate::TightBeamError,
					> = $handler_body;
					__response
				})
			)?
			$(
				.on_streaming(move |__body_in: $crate::transport::multiplex::StreamBody, __ctx: ::std::sync::Arc<$crate::colony::servlet::ServletContext>| async move {
					let $sbody = __body_in;
					let $sctx = &*__ctx;
					let __response: ::core::result::Result<
						::core::option::Option<$crate::Frame>,
						$crate::TightBeamError,
					> = $stream_body;
					__response
				})
			)?
			$(
				.on_duplex(move |__body_in: $crate::transport::multiplex::StreamBody, __reply_in: $crate::transport::multiplex::ReplySink, __ctx: ::std::sync::Arc<$crate::colony::servlet::ServletContext>| async move {
					let $dbody = __body_in;
					let $dreply = __reply_in;
					let $dctx = &*__ctx;
					let __response: ::core::result::Result<(), $crate::TightBeamError> = $duplex_body;
					__response
				})
			)?;

		$crate::colony::servlet::serve_servlet(
			$listener,
			$collector_gates,
			$mux_offer,
			__service,
			::std::sync::Arc::clone(&$servlet_context),
		)
	}};
}

// Helper macro: Generate the start_impl method with all server setup logic
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_start_impl {
	(
		$servlet_name:ident,
		$protocol:path,
		$input:ty,
		$env_config:ty
		$(, handle: |$frame:ident, $ctx:ident| $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| $duplex_body:block)?
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
				let mux_offer = servlet_conf.mux_offer();
				let hive_context = servlet_conf.hive_context().cloned();
				let message_decryptor = servlet_conf.to_message_decryptor();
				let message_inflator = servlet_conf.to_message_inflator();
				let workers_map = servlet_conf.to_workers();

				// Auto-start all workers with servlet trace
				let mut started_workers = ::std::collections::HashMap::new();
				for (name, worker_box) in workers_map {
					let started = worker_box.start_boxed(::std::sync::Arc::clone(&trace)).await?;
					started_workers.insert(name, started);
				}

				// Create the unified servlet context
				let servlet_context = ::std::sync::Arc::new(
					$crate::colony::servlet::ServletContext::new(
						::std::sync::Arc::clone(&trace),
						env_config,
						started_workers,
						hive_context,
					)
					.with_message_decryptor(message_decryptor)
					.with_message_inflator(message_inflator)
				);

				let server_handle = $crate::__servlet_create_server!(
					$protocol,
					listener,
					collector_gates,
					mux_offer,
					servlet_context
					$(, handle: |$frame, $ctx| $handler_body)?
					$(, stream: |$sbody, $sctx| $stream_body)?
					$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
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

// Helper macro: Generate ServletBox trait implementation for hive registration
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_box_impl {
	($servlet_name:ident, $protocol:path) => {
		impl $crate::colony::hive::ServletBox for $servlet_name {
			fn addr_bytes(&self) -> Vec<u8> {
				let addr = self.addr();
				let addr_string: String = addr.to_string();
				addr_string.into_bytes()
			}

			fn stop_boxed(self: Box<Self>) {
				(*self).stop()
			}

			fn utilization(&self) -> Option<$crate::utils::BasisPoints> {
				// Servlets can override this via the Servlet trait's utilization method
				use $crate::colony::servlet::Servlet;
				<Self as Servlet<_>>::utilization(self)
			}
		}
	};
}

/// Servlet macro for creating containerized tightbeam applications.
///
/// Every handler arm is optional (at least one is required); kinds
/// without an arm refuse with `Unimplemented`, so a streaming-only
/// servlet declares just `stream:`.
///
/// Two unary handler forms:
///
/// - `handle: |msg, frame, ctx|` -- typed delivery (default). Encrypted or
///   compressed bodies are normalized in place via the decryptor/inflator.
/// - `handle: raw |frame, ctx|` -- opt-out for servlets that own the frame
///   lifecycle themselves.
///
/// Two streaming arms, served over negotiated multiplexed connections:
///
/// - `stream: |body, ctx| async move { ... }` -- consume a streamed request
///   body ([`StreamBody`](crate::transport::multiplex::StreamBody)), answer
///   with an optional unary reply frame.
/// - `duplex: |body, reply, ctx| async move { ... }` -- consume request
///   chunks while pushing reply chunks through the
///   [`ReplySink`](crate::transport::multiplex::ReplySink).
///
/// The macro is sugar over
/// [`ServletService`](crate::colony::servlet::ServletService) +
/// [`serve_servlet`](crate::colony::servlet::serve_servlet): implement the
/// trait directly for full control without the macro.
#[macro_export]
macro_rules! servlet {
	// NO HANDLER ARMS: refuse at compile time, a servlet answering
	// nothing is a declaration error.
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path $(,)?
	) => {
		::core::compile_error!(
			"servlet! requires at least one handler arm (`handle:`, `stream:`, or `duplex:`)"
		);
	};

	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path $(,)?
	) => {
		::core::compile_error!(
			"servlet! requires at least one handler arm (`handle:`, `stream:`, or `duplex:`)"
		);
	};
	// PUBLIC SERVLET, TYPED DELIVERY
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path,
		handle: |$msg:ident, $frame:ident, $ctx:ident| async move $handler_body:block
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$crate::servlet! {
			$(#[$meta])*
			pub $servlet_name<$input, EnvConfig = $env_config>,
			protocol: $protocol,
			handle: raw |$frame, $ctx| async move {
				let mut $frame = $frame;
				$crate::colony::servlet::prepare_typed_frame(&mut $frame, $ctx)?;
				let $msg: $input = $crate::decode(&$frame.message)?;
				$handler_body
			}
			$(, stream: |$sbody, $sctx| async move $stream_body)?
			$(, duplex: |$dbody, $dreply, $dctx| async move $duplex_body)?
		}
	};

	// PRIVATE SERVLET, TYPED DELIVERY
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path,
		handle: |$msg:ident, $frame:ident, $ctx:ident| async move $handler_body:block
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$crate::servlet! {
			$(#[$meta])*
			$servlet_name<$input, EnvConfig = $env_config>,
			protocol: $protocol,
			handle: raw |$frame, $ctx| async move {
				let mut $frame = $frame;
				$crate::colony::servlet::prepare_typed_frame(&mut $frame, $ctx)?;
				let $msg: $input = $crate::decode(&$frame.message)?;
				$handler_body
			}
			$(, stream: |$sbody, $sctx| async move $stream_body)?
			$(, duplex: |$dbody, $dreply, $dctx| async move $duplex_body)?
		}
	};

	// PUBLIC SERVLET, RAW FRAME (unary arm optional)
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path
		$(, handle: raw |$frame:ident, $ctx:ident| async move $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$crate::paste::paste! {
			$(#[$meta])*
			$crate::__servlet_structs!(pub, $servlet_name, $protocol, $env_config);

			impl $servlet_name {
				$crate::__servlet_start_impl!(
					$servlet_name, $protocol, $input, $env_config
					$(, handle: |$frame, $ctx| $handler_body)?
					$(, stream: |$sbody, $sctx| $stream_body)?
					$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
				);
			}

			$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
			$crate::__servlet_trait_impl!($servlet_name, $protocol, $input);
			$crate::__servlet_drop_impl!($servlet_name);
			$crate::__servlet_box_impl!($servlet_name, $protocol);
		}
	};

	// PRIVATE SERVLET, RAW FRAME (unary arm optional)
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path
		$(, handle: raw |$frame:ident, $ctx:ident| async move $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$crate::paste::paste! {
			$(#[$meta])*
			$crate::__servlet_structs!(, $servlet_name, $protocol, $env_config);

			impl $servlet_name {
				$crate::__servlet_start_impl!(
					$servlet_name, $protocol, $input, $env_config
					$(, handle: |$frame, $ctx| $handler_body)?
					$(, stream: |$sbody, $sctx| $stream_body)?
					$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
				);
			}

			$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
			$crate::__servlet_trait_impl!($servlet_name, $protocol, $input);
			$crate::__servlet_drop_impl!($servlet_name);
			$crate::__servlet_box_impl!($servlet_name, $protocol);
		}
	};
}
