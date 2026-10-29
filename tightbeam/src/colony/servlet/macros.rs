//! The servlet macros parse handler arms into
//! [`ServletHandlers`](crate::colony::servlet::ServletHandlers), then start a
//! [`ServletRuntime`](crate::colony::servlet::ServletRuntime).
//!
//! The runtime owns the accept loop and the lifecycle, so an arm holds its
//! handler code alone.

/// Build [`ServletHandlers`](crate::colony::servlet::ServletHandlers) from the
/// optional unary, stream, and duplex arms.
#[doc(hidden)]
#[macro_export]
macro_rules! __servlet_handlers {
	(
		@arms
		$env_config:ty
		$(, handle: |$frame:ident, $ctx:ident| $handler_body:block)?
		$(, stream: |$sbody:ident, $sctx:ident| $stream_body:block)?
		$(, duplex: |$dbody:ident, $dreply:ident, $dctx:ident| $duplex_body:block)?
	) => {{
		$crate::colony::servlet::ServletHandlers::<$env_config>::default()
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

/// Define a named servlet, a struct that derefs to its runtime and implements
/// [`Servlet`] and [`ServletBox`].
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
			/// Start the servlet, with no [`Servlet`] import at the call site.
			#[allow(dead_code)]
			$vis async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: $crate::colony::servlet::ServletConfig<
					$protocol,
					$input,
					<$protocol as $crate::transport::Protocol>::CryptoProvider,
					$env_config,
				>,
			) -> Result<Self, $crate::TightBeamError> {
				<Self as $crate::colony::servlet::Servlet<$input, $env_config>>::start(trace, config).await
			}

			/// Stop the servlet by value, with no [`Servlet`] import at the
			/// call site.
			#[allow(dead_code)]
			pub fn stop(self) {
				self.runtime.stop();
			}

			/// Wait for the accept loop to finish, through the by-value
			/// [`ServletRuntime::join`] that `Deref` cannot forward.
			#[allow(dead_code)]
			pub async fn join(
				self,
			) -> ::core::result::Result<(), $crate::runtime::rt::JoinError> {
				self.runtime.join().await
			}
		}

		impl $crate::colony::servlet::Servlet<$input, $env_config> for $servlet_name {
			type Conf = $crate::colony::servlet::ServletConfig<
				$protocol,
				$input,
				<$protocol as $crate::transport::Protocol>::CryptoProvider,
				$env_config,
			>;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: Self::Conf,
			) -> Result<Self, $crate::TightBeamError> {
				let service = $crate::__servlet_handlers!(
					@arms
					$env_config
					$(, handle: |$frame, $ctx| $handler_body)?
					$(, stream: |$sbody, $sctx| $stream_body)?
					$(, duplex: |$dbody, $dreply, $dctx| $duplex_body)?
				);
				let runtime = $crate::colony::servlet::ServletRuntime::<$protocol>::start(trace, config, service).await?;
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

			async fn join(self) -> Result<(), $crate::runtime::rt::JoinError> {
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

			fn signer(&self) -> Option<&$crate::cms::signed_data::SignerIdentifier> {
				$crate::colony::hive::ServletBox::signer(&self.runtime)
			}

			fn utilization(&self) -> Option<$crate::basis_points::BasisPoints> {
				$crate::colony::hive::ServletBox::utilization(&self.runtime)
			}

			fn drain_boxed(self: Box<Self>) -> $crate::colony::hive::ServletDrainFuture {
				Box::pin(self.runtime.drain())
			}
		}
	};
}

/// Declares a containerized TightBeam servlet.
///
/// The macro requires at least one handler arm. The servlet refuses a
/// request of a kind with no arm with `Unimplemented`.
///
/// # Unary
///
/// - `handle: |msg, frame, ctx|`: typed delivery, the default. The arm decodes
///   through [`Frame::open_typed`](crate::Frame::open_typed), which holds the
///   frame, as it arrived, to the requirements of the input type, and then
///   normalizes an encrypted or compressed body in place before the decode.
/// - `handle: raw |frame, ctx|`: the caller owns the frame lifecycle.
///
/// # Streaming (multiplexed)
///
/// - `stream: |body, ctx|`: consume a
///   [`StreamBody`](crate::transport::multiplex::StreamBody), with an
///   optional unary reply.
/// - `duplex: |body, reply, ctx|`: request and reply chunks on one stream via
///   [`ReplySink`](crate::transport::multiplex::ReplySink).
///
/// # Macro-free path
///
/// 1. Implement [`ServletService`](crate::colony::servlet::ServletService),
///    or build one from closures with
///    [`ServletHandlers`](crate::colony::servlet::ServletHandlers).
/// 2. Pass it to [`ServletRuntime::start`](crate::colony::servlet::ServletRuntime::start).
#[macro_export]
macro_rules! servlet {
	// An invocation with no handler arm fails at compile time.
	(
		$(#[$meta:meta])*
		$vis:vis $servlet_name:ident<$input:ty, EnvConfig = $env_config:ty>,
		protocol: $protocol:path $(,)?
	) => {
		::core::compile_error!(
			"servlet! requires at least one handler arm (`handle:`, `stream:`, or `duplex:`)"
		);
	};

	// Typed delivery, at any visibility, expands to the raw arm with a decode.
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
				let $msg: $input = $frame.open_typed($ctx).await?;
				$handler_body
			}
			$(, stream: |$sbody, $sctx| async move $stream_body)?
			$(, duplex: |$dbody, $dreply, $dctx| async move $duplex_body)?
		}
	};

	// This arm takes a raw frame, and its unary handler is optional.
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
