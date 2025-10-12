//! Servlet framework for containerized tightbeam applications
//!
//! Servlets provide a way to create self-contained, policy-driven message processing
//! applications that can be easily deployed and tested.

/// Servlet macro for creating containerized tightbeam applications
#[macro_export]
macro_rules! servlet {
	// Full servlet with router and policies
	(
		name: $servlet_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:ident,
		$(policies: { $($policy_key:ident: $policy_val:expr),* $(,)? },)?
		$(router: $router:expr,)?
		handle: |$message:ident $(, $router_param:ident)?| async move $handler_body:block
	) => {
		servlet!(@impl {
			name: $servlet_name,
			$(threads: $threads,)?
			protocol: $protocol,
			policies: [$($($policy_key: $policy_val,)*)?],
			$(router: $router,)?
			|$message $(, $router_param)?| $handler_body
		});
	};

	// Implementation
	(@impl
		{
			name: $servlet_name:ident,
			$(threads: $threads:literal,)?
			protocol: $protocol:ident,
			policies: [$($policy_key:ident: $policy_val:expr,)*],
			$(router: $router:expr,)?
		|$message:ident $(, $router_param:ident)?| $handler_body:expr
		}
	) => {
		pub struct $servlet_name {
			server_handle: Option<tokio::task::JoinHandle<()>>,
			addr: std::net::SocketAddr,
		}

		impl $servlet_name {
			pub async fn start() -> Result<Self, Box<dyn std::error::Error>>
			 {
				servlet!(@setup_protocol $protocol listener addr);

				let server_handle = servlet!(@build_server
					$protocol,
					listener,
					[$($policy_key: $policy_val),*],
					$($router,)?
					(|$message: $crate::Frame $(, $router_param)?| async move { $handler_body })
				 );

				Ok(Self {
					server_handle: Some(server_handle),
					addr,
				})
			}

			pub fn addr(&self) -> std::net::SocketAddr {
				self.addr
			}

			pub fn stop(mut self) {
				if let Some(handle) = self.server_handle.take() {
					handle.abort();
				}
			}

			pub async fn join(mut self) -> Result<(), tokio::task::JoinError> {
				if let Some(handle) = self.server_handle.take() {
					handle.await
				} else {
					// Already stopped or joined
					Ok(())
				}
			}
		}

		impl Drop for $servlet_name {
			fn drop(&mut self) {
				if let Some(handle) = self.server_handle.take() {
					handle.abort();
				}
			}
		}
	};

	// Build server with router and non-empty policies
	(@build_server $protocol:ident, $listener:ident, [$($policy_key:ident: $policy_val:expr),+], $router:expr, (|$msg:ident: $msg_ty:ty, $router_param:ident| async move $body:block)) => {
		 {
			 let router_arc = ::std::sync::Arc::new($router);
			  $crate::server! {
				  async $protocol: $listener,
				  policies: { $($policy_key: $policy_val),* },
				  handle: move |$msg: $msg_ty| async move {
					  let router_arc = router_arc.clone();
					  let $router_param = &router_arc;
						  $body
				  }
			  }
		  }
	 };

	// Build server with router and empty policies
	(@build_server $protocol:ident, $listener:ident, [], $router:expr, (|$msg:ident: $msg_ty:ty, $router_param:ident| async move $body:block)) => {
		 {
			 let router_arc = ::std::sync::Arc::new($router);
			  $crate::server! {
				  async $protocol: $listener,
				  handle: move |$msg: $msg_ty| async move {
					   let router_arc = router_arc.clone();
					   let $router_param = &router_arc;
						  $body
				  }
			  }
		  }
	 };

	// Build server without router and non-empty policies
	(@build_server $protocol:ident, $listener:ident, [$($policy_key:ident: $policy_val:expr),+], (|$msg:ident: $msg_ty:ty| async move $body:block)) => {
		 {
			 $crate::server! {
				 async $protocol: $listener,
				 policies: { $($policy_key: $policy_val),* },
				 handle: move |$msg: $msg_ty| async move {
					 $body
				 }
			 }
		 }
	 };

	// Build server without router and empty policies
	(@build_server $protocol:ident, $listener:ident, [], (|$msg:ident: $msg_ty:ty| async move $body:block)) => {
		 {
			 $crate::server! {
				 async $protocol: $listener,
				 handle: move |$msg: $msg_ty| async move {
					 $body
				 }
			 }
		 }
	 };

	// TCP protocol setup
	(@setup_protocol tcp $listener:ident $addr:ident) => {
		use $crate::transport::tcp::r#async::TokioListener;

		let $listener = TokioListener::bind("127.0.0.1:0").await
			.map_err(|e| $crate::transport::error::TransportError::IoError(e))?;
		let $addr = $listener.local_addr()
			.map_err(|e| $crate::transport::error::TransportError::IoError(e))?;
	};
}

#[cfg(test)]
mod tests {
	use std::sync::mpsc;

	use crate::transport::policy::PolicyConfiguration;
	use crate::testing::*;

	crate::routes! {
		EchoRouter { 
			echo_tx: mpsc::Sender<crate::Frame>,
		}:
			TestMessage |router, msg| {
				let _ = router.echo_tx.send(msg);
			}
	}

	#[derive(crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct RequestMessage {
		content: String,
	}

	#[derive(crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct ResponseMessage {
		result: String,
	}

	servlet! {
		name: PingPongServlet,
		protocol: tcp,
		policies: {
			with_collector_gate: crate::policy::AcceptAllGate
		},
		router: {
			let (tx, _rx) = mpsc::channel();
			EchoRouter { echo_tx: tx }
		},
		handle: |message, router| async move {
			let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
			if decoded.content == "PING" {
				 Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						order: 1_700_000_000u64,
						message: ResponseMessage {
							result: "PONG".to_string()
						}
				 }.ok()?)
			 } else {
				 None
			}
		}
	}

	#[tokio::test]
	async fn test_servlet_ping_pong() -> Result<(), Box<dyn std::error::Error>> {
		let servlet = PingPongServlet::start().await?;
		 
		// Give server time to start
		 tokio::time::sleep(std::time::Duration::from_millis(10)).await;

		 servlet.stop();
		 Ok(())
	 }
 }