//! Servlet macros: parse handler arms into [`crate::colony::servlet::ServletHandlers`], then start
//! a [`ServletRuntime`](crate::colony::servlet::ServletRuntime).
//!
//! Accept-loop and lifecycle logic live on the runtime, not in these arms.

/// Build [`crate::colony::servlet::ServletHandlers`] from optional unary, stream, and duplex arms.
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
			$(.on_unary(move |$frame, __ctx| async move {
				let $ctx = __ctx.as_ref();
				$handler_body
			}))?
			$(.on_streaming(move |$sbody, __ctx| async move {
				let $sctx = __ctx.as_ref();
				$stream_body
			}))?
			$(.on_duplex(move |$dbody, $dreply, __ctx| async move {
				let $dctx = __ctx.as_ref();
				$duplex_body
			}))?
	}};
}

/// Named servlet wrapper: struct, `Deref` to runtime, [`Servlet`] + [`ServletBox`].
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_define {
	(
		$vis:vis,
		$servlet_name:ident,
		$protocol:path,
		$env_config:ty,
		$input:ty
		$(, handle: |$frame:ident, $ctx:ident| $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| $duplex_body:block)?
	) => {
		$vis struct $servlet_name {
			runtime: $crate::colony::servlet::ServletRuntime<$protocol>,
			_phantom: ::core::marker::PhantomData<$env_config>,
		}

		impl ::core::ops::Deref for $servlet_name {
			type Target = $crate::colony::servlet::ServletRuntime<$protocol>;

			fn deref(&self) -> &Self::Target {
				&self.runtime
			}
		}

		impl $servlet_name {
			/// Start convenience that does not require the [`Servlet`] trait in scope.
			#[allow(dead_code)]
			$vis async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Option<$crate::colony::servlet::ServletConfig<$protocol, $input>>,
			) -> Result<Self, $crate::TightBeamError> {
				<Self as $crate::colony::servlet::Servlet<$input>>::start(trace, config).await
			}

			/// Stop convenience for by-value calls without the [`Servlet`] trait in scope.
			#[allow(dead_code)]
			pub fn stop(self) {
				self.runtime.stop();
			}

			/// Join convenience; Deref cannot forward by-value [`ServletRuntime::join`].
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

		impl $crate::colony::servlet::Servlet<$input> for $servlet_name {
			type Conf = $crate::colony::servlet::ServletConfig<$protocol, $input>;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Option<Self::Conf>,
			) -> Result<Self, $crate::TightBeamError> {
				let service = $crate::__servlet_handlers!(
					@arms
					$(, handle: |$frame, $ctx| $handler_body)?
					$(, stream: |$sbody, $sctx| $stream_body)?
					$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
				);
				let runtime = $crate::colony::servlet::ServletRuntime::<$protocol>::start(
					trace,
					config.unwrap_or_default(),
					service,
				)
				.await?;
				Ok(Self {
					runtime,
					_phantom: ::core::marker::PhantomData,
				})
			}

			fn addr(&self) -> &Self::Address {
				self.runtime.addr()
			}

			fn stop(self) {
				self.runtime.stop();
			}

			async fn join(self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				self.runtime.join().await
			}
		}

		impl $crate::colony::hive::ServletBox for $servlet_name {
			fn addr_bytes(&self) -> ::std::sync::Arc<[u8]> {
				self.runtime.addr_bytes()
			}

			fn stop_boxed(self: Box<Self>) {
				self.runtime.stop();
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
		$vis:vis $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path $(,)?
	) => {
		::core::compile_error!(
			"servlet! requires at least one handler arm (`handle:`, `stream:`, or `duplex:`)"
		);
	};

	// Typed delivery (public or private).
	(
		$(#[$meta:meta])*
		$vis:vis $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path,
		handle: |$msg:ident, $frame:ident, $ctx:ident| async move $handler_body:block
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$crate::servlet! {
			$(#[$meta])*
			$vis $servlet_name<$input, EnvConfig = $env_config>,
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

	// Raw frame (unary arm optional).
	(
		$(#[$meta:meta])*
		$vis:vis $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path
		$(, handle: raw |$frame:ident, $ctx:ident| async move $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| async move $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| async move $duplex_body:block)?
		$(,)?
	) => {
		$(#[$meta])*
		$crate::__servlet_define!(
			$vis,
			$servlet_name,
			$protocol,
			$env_config,
			$input
			$(, handle: |$frame, $ctx| $handler_body)?
			$(, stream: |$sbody, $sctx| $stream_body)?
			$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
		);
	};
}
