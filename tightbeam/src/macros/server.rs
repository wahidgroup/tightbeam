#[cfg(any(feature = "tokio", feature = "std"))]
pub(crate) mod server_runtime {
	#[cfg(feature = "tokio")]
	pub(crate) mod rt {
		use std::future::Future;

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
		use std::{
			future::Future,
			pin::Pin,
			task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
			thread,
		};

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
    // Internal helper: sync accept loop (no policies)
    (@sync_loop $server:expr, $handler:expr) => {{
        $crate::server!(@sync_loop $server, $handler,)
    }};

    // Internal helper: sync accept loop (with policies)
    (@sync_loop $server:expr, $handler:expr, $($policy_name:ident: $policy_value:expr),*) => {{
        use std::sync::Arc;
        use $crate::transport::{MessageCollector, ResponseHandler};
        use $crate::transport::tcp::r#sync::TcpTransport;

        let handler = Arc::new($handler);
        loop {
            match $server.accept() {
                Ok((stream, _addr)) => {
					#[allow(unused_mut)]
                    let mut transport = TcpTransport::from(stream);
                    $(
                        transport = transport.$policy_name($policy_value);
                    )*
					let handler = handler.clone();
                    $crate::macros::server::server_runtime::rt::spawn(move || {
                        let mut transport = transport.with_handler(Box::new(move |msg: $crate::Frame| {
                            let handler = handler.clone();
                            handler(msg)
                        }));

                        loop {
                            match $crate::macros::server::server_runtime::rt::block_on(transport.collect()) {
                                Ok(()) => {}
                                Err(e) => {
                                    eprintln!("Server connection closed: {:?}", e);
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

    // Internal: async accept loop with policies
    (@async_loop $server:expr, $handler:expr, $($policy_name:ident: $policy_value:expr),*) => {{
        use std::sync::Arc;
        use $crate::transport::ResponseHandler;
        let handler = Arc::new($handler);
        loop {
            match $server.accept().await {
                Ok((stream, _addr)) => {
                    use $crate::transport::tcp::r#async::TcpTransportAsync;
                    let mut transport = TcpTransportAsync::from(stream);
                    $(
                        transport = transport.$policy_name($policy_value);
                    )*
                    let handler = handler.clone();
                    $crate::macros::server::server_runtime::rt::spawn(async move {
                        let mut transport = transport.with_handler(Box::new(move |msg: $crate::Frame| {
                            let handler = handler.clone();
                            handler(msg)
                        }));

                        loop {
                            match transport.collect().await {
                                Ok(()) => {}
                                Err(e) => {
                                    eprintln!("Server connection closed: {:?}", e);
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

    // Internal: async accept loop with channels
    (@async_loop $server:expr, $handler:expr, $error_tx:expr, $ok_tx:expr, $($policy_name:ident: $policy_value:expr),*) => {{
        use std::sync::Arc;
        use $crate::transport::AsyncListenerTrait;
        let handler = Arc::new($handler);
        loop {
            match $server.accept().await {
                Ok((stream, _addr)) => {
                    use $crate::transport::tcp::r#async::TcpTransportAsync;
                    use $crate::transport::{ResponseHandler, MessageCollector};
                    #[allow(unused_mut)]
                    let mut transport = TcpTransportAsync::from(stream);
                    $(
                        transport = transport.$policy_name($policy_value);
                    )*
                    let handler = handler.clone();
                    let error_tx: Option<tokio::sync::mpsc::Sender<$crate::transport::error::TransportError>> = $error_tx.clone();
                    let ok_tx: Option<tokio::sync::mpsc::Sender<()>> = $ok_tx.clone();
                    $crate::macros::server::server_runtime::rt::spawn(async move {
                        let mut transport = transport.with_handler(Box::new(move |msg: $crate::Frame| {
                            let handler = handler.clone();
                            handler(msg)
                        }));

                        loop {
                            match transport.collect().await {
                                Ok(()) => {
                                    if let Some(tx) = &ok_tx {
                                        let _ = tx.send(()).await;
                                    }
                                }
                                Err(e) => {
                                    if let Some(tx) = &error_tx {
                                        let _ = tx.send(e).await;
                                    }
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

    // Generic sync: protocol: listener, handle: $handler:expr
    ($protocol:path: $listener:expr, handle: $handler:expr) => {{
        #[cfg(feature = "std")]
        {
            let server = $listener;
            $crate::server!(@sync_loop server, $handler)
        }
    }};

    // Generic sync: protocol: bind "addr", handle: $handler:expr
    ($protocol:path: bind $addr:expr, handle: $handler:expr) => {{
        #[cfg(feature = "std")]
        {
            use $crate::transport::Protocol;
            let (listener, _) = <$protocol as Protocol>::bind($addr)?;
            let server = <$protocol>::from(listener);
            $crate::server!(@sync_loop server, $handler)
        }
    }};

    // Generic sync: protocol: listener, policies: {...}, handle: $handler:expr
    ($protocol:path: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
        #[cfg(feature = "std")]
        {
            let server = $listener;
            $crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
        }
    }};

    // Generic sync: protocol: bind "addr", policies: {...}, handle: $handler:expr
    ($protocol:path: bind $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
        #[cfg(feature = "std")]
        {
            use $crate::transport::Protocol;
            let (listener, _) = <$protocol as Protocol>::bind($addr)?;
            let server = <$protocol>::from(listener);
            $crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
        }
    }};

    // Async patterns - use protocol to handle the async keyword
    (protocol $protocol:path: $listener:expr, handle: $handler:expr) => {{
        #[cfg(feature = "tokio")]
        {
            let server = $listener;
            tokio::spawn(async move {
                $crate::server!(@async_loop server, $handler, None, None,)
            })
        }
        #[cfg(all(not(feature = "tokio"), feature = "std"))]
        {
            let server = $listener;
            std::thread::spawn(move || {
                $crate::server!(@sync_loop server, $handler)
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
            let server = <$protocol>::from(listener);
            tokio::spawn(async move {
                $crate::server!(@async_loop server, $handler, None, None,)
            })
        }
        #[cfg(all(not(feature = "tokio"), feature = "std"))]
        {
            use $crate::transport::Protocol;
            let (listener, _) = <$protocol as Protocol>::bind($addr)?;
            let server = <$protocol>::from(listener);
            std::thread::spawn(move || {
                $crate::server!(@sync_loop server, $handler)
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
            let server = $listener;
            tokio::spawn(async move {
                $crate::server!(@async_loop server, $handler, None, None, $($policy_name: $policy_value),*)
            })
        }
        #[cfg(all(not(feature = "tokio"), feature = "std"))]
        {
            let server = $listener;
            std::thread::spawn(move || {
                $crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
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
            let server = $listener;
            tokio::spawn(async move {
                $crate::server!(@async_loop server, $handler, Some($error_tx), Some($ok_tx), $($policy_name: $policy_value),*)
            })
        }
        #[cfg(all(not(feature = "tokio"), feature = "std"))]
        {
            let server = $listener;
            std::thread::spawn(move || {
                $crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
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
            let server = <$protocol>::from(listener);
            tokio::spawn(async move {
                $crate::server!(@async_loop server, $handler, None, None, $($policy_name: $policy_value),*)
            })
        }
        #[cfg(all(not(feature = "tokio"), feature = "std"))]
        {
            use $crate::transport::Protocol;
            let (listener, _) = <$protocol as Protocol>::bind($addr)?;
            let server = <$protocol>::from(listener);
            std::thread::spawn(move || {
                $crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
            });
        }
        #[cfg(not(any(feature = "tokio", feature = "std")))]
        {
            compile_error!("server!(protocol …, policies: …) with `bind` requires the `tokio` feature; enable it or use the sync forms");
        }
    }};

    // Public async entry points
    (async $($rest:tt)*) => {
        $crate::server!(protocol $($rest)*)
    };
}
