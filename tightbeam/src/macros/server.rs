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
				Ok(transport) => {
					$(
						let transport = transport.$policy_name($policy_value);
					)*
					let handler = handler.clone();
					tokio::spawn(async move {
						let mut transport = transport.with_handler(Box::new(move |msg: tightbeam::TightBeam| {
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
		use $crate::transport::{ResponseHandler, MessageCollector};
		let handler = Arc::new($handler);
		loop {
			match $server.accept().await {
				Ok(transport) => {
					$(
						let transport = transport.$policy_name($policy_value);
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

	// Sync: tcp: listener, handle: closure
	(tcp: $listener:expr, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let server = $crate::transport::tcp::sync::TcpServer::from_listener($listener);
			$crate::server!(@sync_loop server, $handler)
		}
	}};

	// Sync: tcp: bind "addr", handle: $handler:expr
	(tcp: bind $addr:expr, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let listener = std::net::TcpListener::bind($addr)?;
			let server = $crate::transport::tcp::sync::TcpServer::from_listener(listener);
			$crate::server!(@sync_loop server, $handler)
		}
	}};

	// Sync: tcp: listener, policies: {...}, handle: closure
	(tcp: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let server = $crate::transport::tcp::sync::TcpServer::from_listener($listener);
			$crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
		}
	}};

	// Sync: tcp: bind "addr", policies: {...}, handle: closure
	(tcp: bind $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "std")]
		{
			let listener = std::net::TcpListener::bind($addr)?;
			let server = $crate::transport::tcp::sync::TcpServer::from_listener(listener);
			$crate::server!(@sync_loop server, $handler, $($policy_name: $policy_value),*)
		}
	}};

	// Async: async tcp: listener, handle: closure
	(async tcp: $listener:expr, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let server = $crate::transport::tcp::r#async::TcpServerAsync::from($listener);
			tokio::spawn(async move {
				$crate::server!(@async_loop server, $handler, None, None,)
			})
		}
	}};

	// Async: async tcp: bind "addr", handle: $handler:expr
	(async tcp: bind $addr:expr, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let listener = $crate::transport::tcp::r#async::TokioListener::bind($addr).await?;
			let server = $crate::transport::tcp::r#async::TcpServerAsync::from(listener);
			tokio::spawn(async move {
				$crate::server!(@async_loop server, $handler, None, None,)
			})
		}
	}};

	// Async: async tcp: listener, policies: {...}, handle: closure
	(async tcp: $listener:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let server = $crate::transport::tcp::r#async::TcpServerAsync::from($listener);
			tokio::spawn(async move {
				$crate::server!(@async_loop server, $handler, None, None, $($policy_name: $policy_value),*)
			})
		}
	}};

	// Async: async tcp: listener, channels: {...}, policies: {...}, handle: closure
	(async tcp: $listener:expr, channels: { error: $error_tx:expr, ok: $ok_tx:expr }, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let server = $crate::transport::tcp::r#async::TcpServerAsync::from($listener);
			tokio::spawn(async move {
				$crate::server!(@async_loop server, $handler, Some($error_tx), Some($ok_tx), $($policy_name: $policy_value),*)
			})
		}
	}};

	// Async: async tcp: bind "addr", policies: {...}, handle: closure
	(async tcp: bind $addr:expr, policies: { $($policy_name:ident: $policy_value:expr),* $(,)? }, handle: $handler:expr) => {{
		#[cfg(feature = "tokio")]
		{
			let listener = $crate::transport::tcp::r#async::TokioListener::bind($addr).await?;
			let server = $crate::transport::tcp::r#async::TcpServerAsync::from(listener);
			tokio::spawn(async move {
				$crate::server!(@async_loop server, $handler, None, None, $($policy_name: $policy_value),*)
			})
		}
	}};
}
