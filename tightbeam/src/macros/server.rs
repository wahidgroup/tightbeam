#![allow(clippy::type_complexity)]

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::{future::Future, pin::Pin};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::Frame;

pub type HandlerFuture = Pin<Box<dyn Future<Output = Option<Frame>> + Send>>;
pub type SharedHandler = Arc<dyn Fn(Frame) -> HandlerFuture + Send + Sync>;

pub fn into_shared_handler<F, Fut>(handler: F) -> SharedHandler
where
	F: Fn(Frame) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Option<Frame>> + Send + 'static,
{
	Arc::new(move |frame: Frame| -> HandlerFuture { Box::pin(handler(frame)) })
}

#[cfg(any(feature = "tokio", feature = "std"))]
pub mod server_runtime {
	#[cfg(feature = "tokio")]
	pub mod rt {
		#![allow(dead_code)]
		use core::future::Future;

		pub type JoinHandle = tokio::task::JoinHandle<()>;

		pub fn spawn<F>(task: F) -> JoinHandle
		where
			F: Future<Output = ()> + Send + 'static,
		{
			tokio::spawn(task)
		}

		pub fn block_on<F>(future: F) -> F::Output
		where
			F: Future,
		{
			tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
		}
	}

	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	pub(crate) mod rt {
		#![allow(dead_code)]
		use core::{
			future::Future,
			pin::Pin,
			task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
		};
		use std::thread;

		pub type JoinHandle = thread::JoinHandle<()>;

		pub fn spawn<F>(task: F) -> JoinHandle
		where
			F: FnOnce() + Send + 'static,
		{
			thread::spawn(task)
		}

		pub fn block_on<F: Future>(mut future: F) -> F::Output {
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
			let mut pinned = unsafe { Pin::new_unchecked(&mut future) };
			loop {
				match pinned.as_mut().poll(&mut cx) {
					Poll::Ready(output) => break output,
					Poll::Pending => thread::yield_now(),
				}
			}
		}
	}
}

#[macro_export]
macro_rules! server {
	(@sync_loop_body $protocol:path, $listener:ident, $handler:ident, $($policy_name:ident: $policy_value:expr),* $(,)?) => {{
		loop {
			match $listener.accept() {
				Ok((__stream, _addr)) => {
					let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(__stream);
					$(
						__transport = __transport.$policy_name($policy_value);
					)*
					let __handler_clone = $handler.clone();
					#[allow(unused_imports)]
					use $crate::transport::policy::PolicyConfiguration;
					use $crate::transport::MessageCollector;
					$crate::macros::server::server_runtime::rt::spawn(move || {
						let mut __transport = __transport;
						loop {
							// Read message
							let (frame, status) = match $crate::macros::server::server_runtime::rt::block_on(__transport.collect_message()) {
								Ok(result) => result,
								Err(err) => {
									eprintln!("Server connection closed: {:?}", err);
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
									eprintln!("Server connection closed: {:?}", err);
									break;
								}
							}
						}
					});
				}
				Err(e) => {
					eprintln!("Server accept error: {:?}", e);
					break;
				}
			}
		}
	}};

	(@async_loop_body $protocol:path, $listener:ident, $handler:ident, $error_tx:ident, $ok_tx:ident, $($policy_name:ident: $policy_value:expr),* $(,)?) => {{
		loop {
			match $listener.accept().await {
				Ok((__stream, _addr)) => {
					let mut __transport = <$protocol as $crate::transport::Protocol>::create_transport(__stream);
					$(
						__transport = __transport.$policy_name($policy_value);
					)*
					let __handler_clone = $handler.clone();
					let mut __error_channel = $error_tx.clone();
					let mut __ok_channel = $ok_tx.clone();
					#[allow(unused_imports)]
					use $crate::transport::policy::PolicyConfiguration;
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
							let response = if status == $crate::policy::TransitStatus::Accepted {
								(__handler_clone)(frame).await
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
					let err_msg = format!("Server accept error: {:?}", e);
					if let Some(tx) = $error_tx.as_mut() {
						let _ = tx.send(e.into()).await;
					}
					eprintln!("{}", err_msg);
					break;
				}
			}
		}
	}};

	(@sync_loop $protocol:path, $listener:expr, $handler:expr, $($policy_name:ident: $policy_value:expr),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::into_shared_handler($handler);

		$crate::server!(@sync_loop_body $protocol, __listener, __handler, $($policy_name: $policy_value),*);
	}};

	(@async_loop $protocol:path, $listener:expr, $handler:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: $policy_value:expr),* $(,)?) => {{
		let mut __listener = $listener;
		let __handler = $crate::macros::server::into_shared_handler($handler);
		let mut __error_tx = $error_tx;
		let mut __ok_tx = $ok_tx;

		$crate::server!(@async_loop_body $protocol, __listener, __handler, __error_tx, __ok_tx, $($policy_name: $policy_value),*);
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
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler,)
		}
	}};

	($protocol:path: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let __listener = $listener;
			$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: $policy_value),*)
		}
	}};

	($protocol:path: bind $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: $policy_value),*)
		}
	}};

	(protocol $protocol:path: $listener:expr, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let __listener = $listener;
			tokio::spawn(async move {
				let __error_tx: Option<tokio::sync::mpsc::Sender<$crate::transport::error::TransportError>> = None;
				let __ok_tx: Option<tokio::sync::mpsc::Sender<()>> = None;
				$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx,)
			})
		}
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		{
			let __listener = $listener;
			std::thread::spawn(move || {
				$crate::server!(@sync_loop $protocol, __listener, $handler,)
			})
		}
		#[cfg(not(any(feature = "tokio", feature = "std")))]
		{
			compile_error!("server!(protocol …) requires either the `tokio` or `std` feature");
		}
	}};

	(protocol $protocol:path: bind $addr:expr, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr).await?;
			let __server = <$protocol>::from(listener);
			tokio::spawn(async move {
				let __error_tx: Option<tokio::sync::mpsc::Sender<$crate::transport::error::TransportError>> = None;
				let __ok_tx: Option<tokio::sync::mpsc::Sender<()>> = None;
				$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx,)
			})
		}
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			std::thread::spawn(move || {
				$crate::server!(@sync_loop $protocol, __server, $handler,)
			});
		}
		#[cfg(not(any(feature = "tokio", feature = "std")))]
		{
			compile_error!("server!(protocol …) with `bind` requires the `tokio` feature; enable it or use the sync forms");
		}
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let __listener = $listener;
			tokio::spawn(async move {
				let __error_tx: Option<tokio::sync::mpsc::Sender<$crate::transport::error::TransportError>> = None;
				let __ok_tx: Option<tokio::sync::mpsc::Sender<()>> = None;
				$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: $policy_value),*)
			})
		}
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		{
			let __listener = $listener;
			std::thread::spawn(move || {
				$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: $policy_value),*)
			})
		}
		#[cfg(not(any(feature = "tokio", feature = "std")))]
		{
			compile_error!("server!(protocol …, policies: …) requires either the `tokio` or `std` feature");
		}
	}};

	(protocol $protocol:path: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let __listener = $listener;
			tokio::spawn(async move {
				let __error_tx = Some($error_tx);
				let __ok_tx = Some($ok_tx);
				$crate::server!(@async_loop $protocol, __listener, $handler, __error_tx, __ok_tx, $($policy_name: $policy_value),*)
			})
		}
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		{
			let __listener = $listener;
			std::thread::spawn(move || {
				$crate::server!(@sync_loop $protocol, __listener, $handler, $($policy_name: $policy_value),*)
			})
		}
		#[cfg(not(any(feature = "tokio", feature = "std")))]
		{
			compile_error!("server!(protocol …, channels: …) requires either the `tokio` or `std` feature");
		}
	}};

	(protocol $protocol:path: bind $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr).await?;
			let __server = <$protocol>::from(listener);
			tokio::spawn(async move {
				let __error_tx: Option<tokio::sync::mpsc::Sender<$crate::transport::error::TransportError>> = None;
				let __ok_tx: Option<tokio::sync::mpsc::Sender<()>> = None;
				$crate::server!(@async_loop $protocol, __server, $handler, __error_tx, __ok_tx, $($policy_name: $policy_value),*)
			})
		}
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr)?;
			let __server = <$protocol>::from(listener);
			std::thread::spawn(move || {
				$crate::server!(@sync_loop $protocol, __server, $handler, $($policy_name: $policy_value),*)
			});
		}
		#[cfg(not(any(feature = "tokio", feature = "std")))]
		{
			compile_error!("server!(protocol …, policies: …) with `bind` requires the `tokio` feature; enable it or use the sync forms");
		}
	}};

	(async $($rest:tt)*) => {
		$crate::server!(protocol $($rest)*)
	};
}
