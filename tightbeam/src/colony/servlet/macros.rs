//! Servlet macros: parse handler arms into [`ServletHandlers`], then start
//! a [`ServletRuntime`](crate::colony::servlet::ServletRuntime).
//!
//! Accept-loop and lifecycle logic live on the runtime, not in these arms.

/// Build [`ServletHandlers`] from optional unary, stream, and duplex arms.
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_handlers {
	(
		@arms
		$(, handle: |$frame:ident, $ctx:ident| $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| $duplex_body:block)?
	) => {{
		$crate::colony::servlet::ServletHandlers::default()
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
			)?
	}};
}

/// Named servlet type that wraps [`ServletRuntime`].
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_structs {
	($vis:vis, $servlet_name:ident, $protocol:path, $env_config:ty) => {
		$vis struct $servlet_name {
			runtime: $crate::colony::servlet::ServletRuntime<$protocol>,
			_phantom: ::core::marker::PhantomData<$env_config>,
		}
	};
}

/// Inherent `start` and lifecycle methods that forward to the runtime.
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_impl_methods {
	($vis:vis, $servlet_name:ident, $protocol:path, $input:ty) => {
		impl $servlet_name {
			#[allow(dead_code)]
			$vis async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Option<$crate::colony::servlet::ServletConfig<$protocol, $input>>,
			) -> Result<Self, $crate::TightBeamError> {
				let started = <Self as $crate::colony::servlet::Servlet<$input>>::start(trace, config).await?;
				Ok(started)
			}

			#[allow(dead_code)]
			pub fn addr(&self) -> <$protocol as $crate::transport::Protocol>::Address {
				self.runtime.addr().clone()
			}

			#[allow(dead_code)]
			pub fn set_trace(&self, trace: ::std::sync::Arc<$crate::trace::TraceCollector>) {
				self.runtime.set_trace(trace);
			}

			#[allow(dead_code)]
			pub fn stop(self) {
				self.runtime.stop();
			}

			#[allow(dead_code)]
			#[cfg(feature = "tokio")]
			pub async fn join(
				self,
			) -> ::core::result::Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				self.runtime.join().await
			}

			#[allow(dead_code)]
			#[cfg(all(not(feature = "tokio"), feature = "std"))]
			pub fn join(self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				self.runtime.join()
			}
		}
	};
}

/// [`Servlet`](crate::colony::servlet::Servlet) impl: handlers then runtime start.
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_trait_impl {
	(
		$servlet_name:ident,
		$protocol:path,
		$input:ty
		$(, handle: |$frame:ident, $ctx:ident| $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| $duplex_body:block)?
	) => {
		impl $crate::colony::servlet::Servlet<$input> for $servlet_name {
			type Conf = $crate::colony::servlet::ServletConfig<$protocol, $input>;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Option<Self::Conf>,
			) -> Result<Self, $crate::TightBeamError> {
				let servlet_conf = config.unwrap_or_default();
				let service = $crate::__servlet_handlers!(
					@arms
					$(, handle: |$frame, $ctx| $handler_body)?
					$(, stream: |$sbody, $sctx| $stream_body)?
					$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
				);
				let runtime = $crate::colony::servlet::ServletRuntime::<$protocol>::start(
					trace,
					servlet_conf,
					service,
				)
				.await?;
				let servlet = Self {
					runtime,
					_phantom: ::core::marker::PhantomData,
				};
				Ok(servlet)
			}

			fn addr(&self) -> Self::Address {
				self.runtime.addr().clone()
			}

			fn stop(self) {
				self.runtime.stop();
			}

			async fn join(self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				self.runtime.join().await
			}
		}
	};
}

/// [`ServletBox`](crate::colony::hive::ServletBox) forwarding for hive registration.
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_box_impl {
	($servlet_name:ident) => {
		impl $crate::colony::hive::ServletBox for $servlet_name {
			fn addr_bytes(&self) -> ::std::sync::Arc<[u8]> {
				self.runtime.addr_bytes()
			}

			fn stop_boxed(self: Box<Self>) {
				(*self).stop();
			}

			fn utilization(&self) -> Option<$crate::utils::BasisPoints> {
				use $crate::colony::servlet::Servlet;
				<Self as Servlet<_>>::utilization(self)
			}
		}
	};
}

/// Create a containerized TightBeam servlet.
///
/// At least one handler arm is required. Absent kinds refuse with
/// `Unimplemented`.
///
/// # Unary
///
/// - `handle: |msg, frame, ctx|`: typed delivery (default). Encrypted or
///   compressed bodies are normalized in place before decode.
/// - `handle: raw |frame, ctx|`: caller owns the frame lifecycle.
///
/// # Streaming (multiplexed)
///
/// - `stream: |body, ctx|`: consume a
///   [`StreamBody`](crate::transport::multiplex::StreamBody); optional unary reply.
/// - `duplex: |body, reply, ctx|`: request and reply chunks on one stream via
///   [`ReplySink`](crate::transport::multiplex::ReplySink).
///
/// # Macro-free path
///
/// Implement [`ServletService`](crate::colony::servlet::ServletService) and
/// call [`ServletRuntime::start`](crate::colony::servlet::ServletRuntime::start).
#[macro_export]
macro_rules! servlet {
	// No handler arms: refuse at compile time.
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
	// Public servlet, typed delivery.
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

	// Private servlet, typed delivery.
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

	// Public servlet, raw frame (unary arm optional).
	(
		$(#[$meta:meta])*
		pub $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path
		$(, handle: raw |$frame:ident, $ctx:ident| async move $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$(#[$meta])*
		$crate::__servlet_structs!(pub, $servlet_name, $protocol, $env_config);

		$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
		$crate::__servlet_trait_impl!(
			$servlet_name,
			$protocol,
			$input
			$(, handle: |$frame, $ctx| $handler_body)?
			$(, stream: |$sbody, $sctx| $stream_body)?
			$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
		);
		$crate::__servlet_box_impl!($servlet_name);
	};

	// Private servlet, raw frame (unary arm optional).
	(
		$(#[$meta:meta])*
		$servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path
		$(, handle: raw |$frame:ident, $ctx:ident| async move $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$(#[$meta])*
		$crate::__servlet_structs!(, $servlet_name, $protocol, $env_config);

		$crate::__servlet_impl_methods!(pub, $servlet_name, $protocol, $input);
		$crate::__servlet_trait_impl!(
			$servlet_name,
			$protocol,
			$input
			$(, handle: |$frame, $ctx| $handler_body)?
			$(, stream: |$sbody, $sctx| $stream_body)?
			$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
		);
		$crate::__servlet_box_impl!($servlet_name);
	};
}
