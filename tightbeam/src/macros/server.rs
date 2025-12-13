#![allow(clippy::type_complexity)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::{future::Future, pin::Pin};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::Frame;

pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send>>;
pub type SharedHandler = Arc<dyn Fn(Frame) -> HandlerFuture + Send + Sync>;

pub fn into_shared_handler<F, Fut>(handler: F) -> SharedHandler
where
	F: Fn(Frame) -> Fut + Send + Sync + Clone + 'static,
	Fut: Future<Output = Result<Option<Frame>, crate::TightBeamError>> + Send + 'static,
{
	let handler = Arc::new(handler);
	Arc::new(move |frame: Frame| -> HandlerFuture {
		let handler = ::std::sync::Arc::clone(&handler);
		Box::pin(async move { handler(frame).await })
	})
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx,)
		})
	}};

	($protocol:path, $listener:expr, assertions: $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		#[allow(unused_imports)]
		use $crate::trace::TraceCollector;

		let __listener = $listener;
		let __assertions = $assertions;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop_assertions $protocol, __listener, __assertions, ($param1, $param2, $handler_body), __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {{
		let __listener = $listener;
		std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_handle {
	($protocol:path, $listener:expr, $handler:expr) => {
		compile_error!("server!(protocol …) requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr).await?;
		let __server = <$protocol>::from(listener);
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
		let __server = <$protocol>::from(listener);
		std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_handle {
	($protocol:path, $addr:expr, $handler:expr) => {
		compile_error!(
			"server!(protocol …) with `bind` requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!(
			"server!(protocol …, policies: …) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		#[allow(unused_imports)]
		use $crate::trace::TraceCollector;

		let __listener = $listener;
		let __assertions = $assertions;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop_assertions $protocol, __listener, __assertions, ($param1, $param2, $handler_body), __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		compile_error!("server!(protocol …, policies: …, assertions: …) requires the `tokio` feature");
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_policies_assertions_handle {
	($protocol:path, $listener:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr)) => {{
		compile_error!(
			"server!(protocol …, policies: …, assertions: …) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	}};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = Some($error_tx);
			let __ok_tx = Some($ok_tx);
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx,)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {{
		let __listener = $listener;
		let _ = ($error_tx, $ok_tx);
		std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, $handler:expr) => {
		let _ = ($error_tx, $ok_tx);
		compile_error!(
			"server!(protocol …, channels: …) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = Some($error_tx);
			let __ok_tx = Some($ok_tx);
			$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let __listener = $listener;
		let _ = ($error_tx, $ok_tx);
		std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_channels_policies_handle {
	($protocol:path, $listener:expr, $error_tx:expr, $ok_tx:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		let _ = ($error_tx, $ok_tx);
		compile_error!(
			"server!(protocol …, channels: …) requires tightbeam to be built with either the `tokio` or `std` feature"
		);
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr).await?;
		let __server = <$protocol>::from(listener);
		$crate::macros::server::server_runtime::rt::spawn(async move {
			let __error_tx = $crate::macros::server::server_runtime::rt::empty_error_channel();
			let __ok_tx = $crate::macros::server::server_runtime::rt::empty_ok_channel();
			$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {{
		let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
		let __server = <$protocol>::from(listener);
		std::thread::spawn(move || {
			$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: [ $( $policy_expr ),* ]),*)
		})
	}};
}

#[cfg(not(any(feature = "tokio", feature = "std")))]
#[macro_export]
macro_rules! __tightbeam_server_protocol_bind_policies_handle {
	($protocol:path, $addr:expr, [$($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?], $handler:expr) => {
		compile_error!("server!(protocol …, policies: …) with `bind` requires tightbeam to be built with either the `tokio` or `std` feature");
	};
}

/// Server-specific runtime extensions
///
/// Re-exports unified runtime and adds server-specific channel helpers.
#[cfg(any(feature = "tokio", feature = "std"))]
pub mod server_runtime {
	/// Runtime primitives (re-exported from unified runtime)
	pub mod rt {
		pub use crate::runtime::rt::*;

		use crate::transport::error::TransportError;

		/// Error notification channel sender type
		pub type ErrorSender = crate::runtime::rt::Sender<TransportError>;

		/// Success notification channel sender type
		pub type OkSender = crate::runtime::rt::Sender<()>;

		/// Returns None for optional error channel
		#[allow(dead_code)]
		pub fn empty_error_channel() -> Option<ErrorSender> {
			None
		}

		/// Returns None for optional success channel
		#[allow(dead_code)]
		pub fn empty_ok_channel() -> Option<OkSender> {
			None
		}
	}
}

#[macro_export]
macro_rules! server {
	(@apply_policy $transport:ident, $policy_name:ident, [ $( $policy_expr:expr ),* $(,)? ]) => {{
		$(
			$transport = $crate::server!(@apply_one_policy $transport, $policy_name, $policy_expr);
		)*
	}};

	// Generic fallback
	(@apply_one_policy $transport:ident, $other:ident, $policy_expr:expr) => {{
		$transport.$other($policy_expr)
	}};

	(@sync_loop_body $protocol:path, $listener:ident, $handler:ident, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		loop {
			match $listener.accept() {
				Ok((mut __transport, _addr)) => {
					$(
						$(
							__transport = $crate::server!(@apply_one_policy __transport, $policy_name, $policy_expr);
						)*
					)*
					let __handler_clone = ::std::sync::Arc::clone(&$handler);
					#[allow(unused_imports)]
					use $crate::transport::MessageCollector;
					$crate::macros::server::server_runtime::rt::spawn(move || {
						let mut __transport = __transport;
						loop {
							// Read message
							let (frame, status) = match $crate::macros::server::server_runtime::rt::block_on(__transport.collect_message()) {
								Ok(result) => result,
								Err(err) => {
									break;
								}
							};

							// Process message asynchronously
							let response = if status == $crate::policy::TransitStatus::Accepted {
								$crate::macros::server::server_runtime::rt::block_on((__handler_clone)(frame))
							} else {
								None
							};

							// Send response
							match $crate::macros::server::server_runtime::rt::block_on(__transport.send_response(status, response)) {
								Ok(()) => continue,
								Err(err) => {
									break;
								}
							}
						}
					});
				}
				Err(_err) => {
					break;
				}
			}
		}
	}};

	(@async_loop_body $protocol:path, $listener:ident, $handler:ident, $error_tx:ident, $ok_tx:ident, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		loop {
			match $listener.accept().await {
				Ok((mut __transport, _addr)) => {
					$(
						$(
							__transport = $crate::server!(@apply_one_policy __transport, $policy_name, $policy_expr);
						)*
					)*
					let __handler_clone = ::std::sync::Arc::clone(&$handler);
					let mut __error_channel = $error_tx.clone();
					let mut __ok_channel = $ok_tx.clone();
					use $crate::transport::MessageCollector;
					$crate::macros::server::server_runtime::rt::spawn(async move {
						let mut __transport = __transport;
						loop {
							// Read message
							let (frame, status) = match __transport.collect_message().await {
								Ok(result) => result,
								Err(err) => {
									if let Some(tx) = __error_channel.as_mut() {
										let _ = tx.send(err).await;
									}
									break;
								}
							};

							// Process message asynchronously
							// Unwrap Arc<Frame> to Frame for handler (clone only if Arc has multiple owners)
							let frame_owned = std::sync::Arc::try_unwrap(frame)
								.unwrap_or_else(|arc| (*arc).clone());
							let response = if status == $crate::policy::TransitStatus::Accepted {
								match (__handler_clone)(frame_owned).await {
									Ok(opt) => opt,
									Err(_err) => {
										None
									}
								}
							} else {
								None
							};

							// Send response
							match __transport.send_response(status, response).await {
								Ok(()) => {
									if let Some(tx) = __ok_channel.as_mut() {
										let _ = tx.send(()).await;
									}
								}
								Err(err) => {
									if let Some(tx) = __error_channel.as_mut() {
										let _ = tx.send(err).await;
									}
									break;
								}
							}
						}
					});
				}
				Err(e) => {
					if let Some(tx) = $error_tx.as_mut() {
						let _ = tx.send(e.into()).await;
					}

					break;
				}
			}
		}
	}};

	(@sync_loop $protocol:path, $listener:expr, $handler:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::into_shared_handler($handler);

		$crate::server!(@sync_loop_body $protocol, __listener, __handler, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	(@async_loop_assertions $protocol:path, $listener:expr, $assertions:expr, ($param1:ident, $param2:ident, $handler_body:expr), $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		#[allow(unused_imports)]
		use $crate::trace::TraceCollector;

		let __assertions = ::std::sync::Arc::new($assertions);
		let __handler_with_trace = {
			let __assertions = ::std::sync::Arc::clone(&__assertions);
			move |$param1: $crate::Frame| {
				let $param2: TraceCollector = __assertions.as_ref().share();
				$handler_body
			}
		};

		$crate::server!(@async_loop $protocol, $listener, __handler_with_trace, $error_tx, $ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	(@async_loop $protocol:path, $listener:expr, $handler:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::into_shared_handler($handler);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __handler, __error_tx, __ok_tx, $($policy_name: [ $( $policy_expr ),* ]),*);
	}};

	($protocol:path: $listener:expr, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler,)
		}
	}};

	($protocol:path: bind $addr:expr, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		}
	}};

	($protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: [ $( $policy_expr ),* ]),*);
		}
	}};

	($protocol:path: bind $addr:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let (listener, _) = <$protocol as $crate::transport::Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: [ $( $policy_expr ),* ]),*);
		}
	}};

	(protocol $protocol:path: $listener:expr, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_handle!($protocol, $listener, $handler)
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, handle: move |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_handle!($protocol, $listener, assertions: $assertions, ($param1, $param2, $handler_body))
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, handle: |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_handle!($protocol, $listener, assertions: $assertions, ($param1, $param2, $handler_body))
	}};

	(protocol $protocol:path: bind $addr:expr, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_bind_handle!($protocol, $addr, $handler)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_policies_handle!($protocol, $listener, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, assertions: $assertions:expr, handle: move |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, assertions: $assertions:expr, handle: |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: move |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, assertions: $assertions:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: |$param1:ident, $param2:ident| $handler_body:expr) => {{
		$crate::__tightbeam_server_protocol_policies_assertions_handle!(
			$protocol,
			$listener,
			[ $($policy_name: [ $( $policy_expr ),* ]),* ],
			$assertions,
			($param1, $param2, $handler_body)
		)
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_channels_handle!($protocol, $listener, $error_tx, $ok_tx, $handler)
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_channels_policies_handle!($protocol, $listener, $error_tx, $ok_tx, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(protocol $protocol:path: bind $addr:expr, policies: { $($policy_name:ident: [ $( $policy_expr:expr ),* $(,)? ]),* $(,)? }, handle: $handler:expr) => {{
		$crate::__tightbeam_server_protocol_bind_policies_handle!($protocol, $addr, [ $($policy_name: [ $( $policy_expr ),* ]),* ], $handler)
	}};

	(async $($rest:tt)*) => {
		$crate::server!(protocol $($rest)*)
	};
}
