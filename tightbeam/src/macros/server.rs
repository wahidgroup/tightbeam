/// Server macro - creates and runs an accept loop
#[macro_export]
macro_rules! server {
	// Internal: sync accept loop
	(@sync_loop $server:expr, $handler:expr) => {{
		loop {
			let mut transport = $server.accept()?;
			let handler = $handler;

			std::thread::spawn(move || {
				let message = transport.collect().unwrap();
				handler(message);
			});
		}
	}};

	// Internal: sync accept loop with policies
	(@sync_loop $server:expr, $handler:expr, $($policy_name:ident: $policy_value:expr),*) => {{
		loop {
			let mut transport = $server.accept()?;
			$(
				let transport = transport.$policy_name($policy_value);
			)*
			let handler = $handler;

			std::thread::spawn(move || {
				let message = transport.collect().unwrap();
				handler(message);
			});
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
					tokio::spawn(async move {
						let mut transport = transport.with_handler(Box::new(move |msg: $crate::Frame| {
							let handler = handler.clone();
							tokio::task::block_in_place(|| {
								tokio::runtime::Handle::current().block_on(handler(msg.clone()))
							})
						}));

						// Keep the connection alive for multiple messages
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
					// False positive: transport is used mutably
					#[allow(unused_mut)]
					let mut transport = TcpTransportAsync::from(stream);
					$(
						transport = transport.$policy_name($policy_value);
					)*
					let handler = handler.clone();
					// Explicitly annotate channel types to satisfy inference
					let error_tx: Option<tokio::sync::mpsc::Sender<$crate::transport::error::TransportError>> = $error_tx.clone();
					let ok_tx: Option<tokio::sync::mpsc::Sender<()>> = $ok_tx.clone();
					tokio::spawn(async move {
						let mut transport = transport.with_handler(Box::new(move |msg: $crate::Frame| {
							let handler = handler.clone();
							tokio::task::block_in_place(|| {
								let handler_fn = (*handler).clone();
								tokio::runtime::Handle::current().block_on(handler_fn(msg.clone()))
							})
						}));

						// Keep the connection alive
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

	// Generic sync: protocol: listener, handle: closure
	($protocol:path: $listener:expr, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			// Use generic server construction - protocol must provide server type
			let server = $listener;
			$crate::server!(@sync_loop server, $handler)
		}
	}};

	// Generic sync: protocol: bind "addr", handle: $handler:expr
	($protocol:path: bind $addr:expr, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr).await?;
			let server = $listener;
			$crate::server!(@sync_loop server, $handler)
		}
	}};

	// Generic sync: protocol: listener, policies: {...}, handle: closure
	($protocol:path: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let server = $listener;
			$crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
		}
	}};

	// Generic sync: protocol: bind "addr", policies: {...}, handle: closure
	($protocol:path: bind $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			use $crate::transport::Protocol;
			let (listener, _) = <$protocol as Protocol>::bind($addr).await?;
			let server = $listener;
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
	}};

	(protocol $protocol:path: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let server = $listener;
			tokio::spawn(async move {
				$crate::server!(@async_loop server, $handler, None, None, $($policy_name: $policy_value),*)
			})
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
	}};

	// Public async entry points
	(async $($rest:tt)*) => {
		$crate::server!(protocol $($rest)*)
	};
}
