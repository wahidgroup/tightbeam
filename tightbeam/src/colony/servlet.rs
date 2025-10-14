//! Worker framework for containerized tightbeam applications
//! // TODO Disambiguate from tokio
//!
//! Workers provide a way to create self-contained, policy-driven message
//! processing applications that can be easily deployed and tested.

use std::net::SocketAddr;

/// Trait for worker implementations
///
/// Provides a common interface for all colony created with the `servlet!`
/// macro. Workers are containerized applications that process TightBeam
/// messages.
pub trait Worker {
	/// Configuration type for this worker (use () for no config)
	type Config;

	/// Start the worker with optional configuration
	fn start(
		config: Option<Self::Config>,
	) -> impl std::future::Future<Output = Result<Self, crate::TightBeamError>> + Send
	where
		Self: Sized;

	/// Get the local address the worker is bound to
	fn addr(&self) -> SocketAddr;

	/// Stop the worker gracefully
	fn stop(self);

	/// Wait for the worker to finish
	fn join(self) -> impl std::future::Future<Output = Result<(), tokio::task::JoinError>> + Send;
}

/// Worker macro for creating containerized tightbeam applications
#[macro_export]
macro_rules! servlet {
	// Full worker with router, policies, and config
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:expr),* $(,)? },)?
		router: $router:expr,
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $router_param:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 router_and_config, $router, { $($config_field: $config_type,)* },
				 |$message, $router_param, $config_param| $handler_body);
	};

	// Worker with router only
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:expr),* $(,)? },)?
		router: $router:expr,
		handle: |$message:ident, $router_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 router_only, $router, {},
				 |$message, $router_param| $handler_body);
	};

	// Worker with config only
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:expr),* $(,)? },)?
		config: { $($config_field:ident: $config_type:ty),* $(,)? },
		handle: |$message:ident, $config_param:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 config_only, {}, { $($config_field: $config_type,)* },
				 |$message, $config_param| $handler_body);
	};

	// Basic worker with just message
	(
		name: $worker_name:ident,
		$(worker_threads: $threads:literal,)?
		protocol: $protocol:path,
		$(policies: { $($policy_key:ident: $policy_val:expr),* $(,)? },)?
		handle: |$message:ident| async move $handler_body:block
	) => {
		servlet!(@generate $worker_name, $protocol, [$($($policy_key: $policy_val,)*)?],
				 basic, {}, {},
				 |$message| $handler_body);
	};

	// Main implementation generator
	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr,)*],
			  router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $router_param:ident, $config_param:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, { $($config_field: $config_type,)* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				 router_and_config, $router, { $($config_field: $config_type,)* },
				 |$message, $router_param, $config_param| $handler_body);
		servlet!(@impl_trait $worker_name, { $($config_field: $config_type,)* });
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr,)*],
			  router_only, $router:tt, {},
			  |$message:ident, $router_param:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, {});
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				 router_only, $router, {},
				 |$message, $router_param| $handler_body);
		servlet!(@impl_trait $worker_name, {});
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr,)*],
			  config_only, {}, { $($config_field:ident: $config_type:ty,)* },
			  |$message:ident, $config_param:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, { $($config_field: $config_type,)* });
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				 config_only, {}, { $($config_field: $config_type,)* },
				 |$message, $config_param| $handler_body);
		servlet!(@impl_trait $worker_name, { $($config_field: $config_type,)* });
	};

	(@generate $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr,)*],
			  basic, {}, {},
			  |$message:ident| $handler_body:expr) => {
		servlet!(@impl_struct $worker_name, {});
		servlet!(@impl_methods $worker_name, $protocol, [$($policy_key: $policy_val),*],
				 basic, {}, {},
				 |$message| $handler_body);
		servlet!(@impl_trait $worker_name, {});
	};

	// Generate struct and optional config struct
	(@impl_struct $worker_name:ident, {}) => {
		pub struct $worker_name {
			server_handle: Option<tokio::task::JoinHandle<()>>,
			addr: std::net::SocketAddr,
		}
	};

	(@impl_struct $worker_name:ident, { $($config_field:ident: $config_type:ty,)* }) => {
		paste::paste! {
			pub struct $worker_name {
				server_handle: Option<tokio::task::JoinHandle<()>>,
				addr: std::net::SocketAddr,
			}

			#[derive(Clone)]
			pub struct [<$worker_name Config>] {
				$(pub $config_field: $config_type,)*
			}
		}
	};

	// Generate implementation methods
	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr),*],
				   router_and_config, $router:tt, { $($config_field:ident: $config_type:ty,)* },
				   |$message:ident, $router_param:ident, $config_param:ident| $handler_body:expr) => {
		paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Config>]) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let server_handle = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], $router, config,
						(|$message: $crate::Frame, $router_param, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), addr })
				}

				servlet!(@common_methods);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr),*],
				   router_only, $router:tt, {},
				   |$message:ident, $router_param:ident| $handler_body:expr) => {
		impl $worker_name {
			pub async fn start() -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let server_handle = servlet!(@build_server
					$protocol, listener, [$($policy_key: $policy_val),*], $router,
					(|$message: $crate::Frame, $router_param| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), addr })
			}

			servlet!(@common_methods);
		}

		servlet!(@drop_impl $worker_name);
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr),*],
				   config_only, {}, { $($config_field:ident: $config_type:ty,)* },
				   |$message:ident, $config_param:ident| $handler_body:expr) => {
		paste::paste! {
			impl $worker_name {
				pub async fn start(config: [<$worker_name Config>]) -> Result<Self, $crate::TightBeamError> {
					servlet!(@setup_protocol $protocol, listener, addr);
					let server_handle = servlet!(@build_server_with_config
						$protocol, listener, [$($policy_key: $policy_val),*], config,
						(|$message: $crate::Frame, $config_param| async move { $handler_body }));
					Ok(Self { server_handle: Some(server_handle), addr })
				}

				servlet!(@common_methods);
			}

			servlet!(@drop_impl $worker_name);
		}
	};

	(@impl_methods $worker_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:expr),*],
				   basic, {}, {},
				   |$message:ident| $handler_body:expr) => {
		impl $worker_name {
			pub async fn start() -> Result<Self, $crate::TightBeamError> {
				servlet!(@setup_protocol $protocol, listener, addr);
				let server_handle = servlet!(@build_server
					$protocol, listener, [$($policy_key: $policy_val),*],
					(|$message: $crate::Frame| async move { $handler_body }));
				Ok(Self { server_handle: Some(server_handle), addr })
			}

			servlet!(@common_methods);
		}

		servlet!(@drop_impl $worker_name);
	};

	// Generate trait implementation (with config)
	(@impl_trait $worker_name:ident, { $($config_field:ident: $config_type:ty,)* }) => {
		paste::paste! {
			impl $crate::colony::Worker for $worker_name {
				type Config = [<$worker_name Config>];

				async fn start(config: Option<Self::Config>) -> Result<Self, $crate::TightBeamError> {
					let cfg = config.ok_or_else(|| $crate::TightBeamError::MissingConfiguration)?;
					Self::start(cfg).await
				}

				fn addr(&self) -> std::net::SocketAddr {
					self.addr()
				}

				fn stop(self) {
					self.stop()
				}

				async fn join(self) -> Result<(), tokio::task::JoinError> {
					self.join().await
				}
			}
		}
	};

	// Generate trait implementation (without config)
	(@impl_trait $worker_name:ident, {}) => {
		impl $crate::colony::Worker for $worker_name {
			type Config = ();

			async fn start(config: Option<Self::Config>) -> Result<Self, $crate::TightBeamError> {
				let _ = config; // Ignore config for basic colony
				Self::start().await.map_err(|e| $crate::TightBeamError::ConfigurationError(e.to_string()))
			}

			fn addr(&self) -> std::net::SocketAddr {
				self.addr()
			}

			fn stop(self) {
				self.stop()
			}

			async fn join(self) -> Result<(), tokio::task::JoinError> {
				self.join().await
			}
		}
	};

	// Common methods shared by all colony
	(@common_methods) => {
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
				Ok(())
			}
		}
	};

	// Drop implementation shared by all colony
	(@drop_impl $worker_name:ident) => {
		impl Drop for $worker_name {
			fn drop(&mut self) {
				if let Some(handle) = self.server_handle.take() {
					handle.abort();
				}
			}
		}
	};

	// Build server variants (simplified with proper routing to existing patterns)
	(@build_server_with_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:expr),*],
							   $router:tt, $config:ident, $handler:tt) => {
		servlet!(@build_server_router_config $protocol, $listener, [$($policy_key: $policy_val),*],
				 $router, $config, $handler)
	};

	(@build_server_with_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:expr),*],
							   $config:ident, $handler:tt) => {
		servlet!(@build_server_config_only $protocol, $listener, [$($policy_key: $policy_val),*],
				 $config, $handler)
	};

	// Protocol setup - updated to handle protocol paths
	(@setup_protocol $protocol:path, $listener:ident, $addr:ident) => {
		use $crate::transport::Protocol;

		let ($listener, $addr) = <$protocol as Protocol>::bind("127.0.0.1:0").await
			.map_err(|e| $crate::TightBeamError::from(e))?;
	};

	// Build server with router and config (non-empty policies)
	(@build_server_router_config $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:expr),+], $router:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $router_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let config_arc = ::std::sync::Arc::new($config);
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| async move {
					let router_arc = router_arc.clone();
					let config_arc = config_arc.clone();
					let $router_param = &router_arc;
					let $config_param = &config_arc;
					$body
				}
			}
		}
	};

	// Build server with router and config (empty policies)
	(@build_server_router_config $protocol:path, $listener:ident, [], $router:expr, $config:ident, (|$msg:ident: $msg_ty:ty, $router_param:ident, $config_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			let config_arc = ::std::sync::Arc::new($config);
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| async move {
					let router_arc = router_arc.clone();
					let config_arc = config_arc.clone();
					let $router_param = &router_arc;
					let $config_param = &config_arc;
					$body
				}
			}
		}
	};

	// Build server with config only (non-empty policies)
	(@build_server_config_only $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:expr),+], $config:ident, (|$msg:ident: $msg_ty:ty, $config_param:ident| async move $body:block)) => {
		{
			let config_arc = ::std::sync::Arc::new($config);
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| async move {
					let config_arc = config_arc.clone();
					let $config_param = &config_arc;
					$body
				}
			}
		}
	};

	// Build server with config only (empty policies)
	(@build_server_config_only $protocol:path, $listener:ident, [], $config:ident, (|$msg:ident: $msg_ty:ty, $config_param:ident| async move $body:block)) => {
		{
			let config_arc = ::std::sync::Arc::new($config);
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| async move {
					let config_arc = config_arc.clone();
					let $config_param = &config_arc;
					$body
				}
			}
		}
	};

	// Build server with router only (non-empty policies)
	(@build_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:expr),+], $router:expr, (|$msg:ident: $msg_ty:ty, $router_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
				handle: move |$msg: $msg_ty| async move {
					let router_arc = router_arc.clone();
					let $router_param = &router_arc;
					$body
				}
			}
		}
	};

	// Build server with router only (empty policies)
	(@build_server $protocol:path, $listener:ident, [], $router:expr, (|$msg:ident: $msg_ty:ty, $router_param:ident| async move $body:block)) => {
		{
			let router_arc = ::std::sync::Arc::new($router);
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| async move {
					let router_arc = router_arc.clone();
					let $router_param = &router_arc;
					$body
				}
			}
		}
	};

	// Build server basic (non-empty policies)
	(@build_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:expr),+], (|$msg:ident: $msg_ty:ty| async move $body:block)) => {
		$crate::server! {
			protocol $protocol: $listener,
			policies: { $($policy_key: $policy_val),* },
			handle: move |$msg: $msg_ty| async move {
				$body
			}
		}
	};

	// Build server basic (empty policies)
	(@build_server $protocol:path, $listener:ident, [], (|$msg:ident: $msg_ty:ty| async move $body:block)) => {
		$crate::server! {
			protocol $protocol: $listener,
			handle: move |$msg: $msg_ty| async move {
				$body
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use crate::transport::policy::PolicyConfiguration;
	use crate::transport::tcp::TokioListener;
	use crate::transport::MessageEmitter;

	// crate::routes! {
	// 	EchoRouter {
	// 		echo_tx: mpsc::Sender<crate::Frame>,
	// 	}:
	// 		TestMessage |router, msg| {
	// 			let _ = router.echo_tx.send(msg);
	// 		}
	// }

	#[derive(crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct RequestMessage {
		content: String,
		lucky_number: u32,
	}

	#[derive(crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct ResponseMessage {
		result: String,
		is_winner: bool,
	}

	servlet! {
		name: PingPongWorker,
		protocol: TokioListener,
		policies: {
			with_collector_gate: crate::policy::AcceptAllGate::default()
		},
		config: {
			lotto_number: u32,
		},
		handle: |message, config| async move {
			let decoded = crate::decode::<RequestMessage, _>(&message.message).ok()?;
			let is_winner = decoded.lucky_number == config.lotto_number;
			if decoded.content == "PING" {
				 Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						order: 1_700_000_000u64,
						message: ResponseMessage {
							result: "PONG".to_string(),
							is_winner,
						}
				 }.ok()?)
			 } else {
				 None
			}
		}
	}

	crate::test_servlet! {
		name: test_worker_with_test_async_case,
		features: ["std", "tcp", "tokio"],
		worker_threads: 2,
		protocol: TokioListener,
		setup: || {
			PingPongWorker::start(PingPongWorkerConfig { lotto_number: 42 })
		},
		assertions: |client| async move {
			fn generate_message(
				lucky_number: u32,
				content: Option<String>
			) -> Result<crate::Frame, crate::TightBeamError> {
				let message = RequestMessage {
					content: content.unwrap_or_else(|| "PING".to_string()),
					lucky_number,
				};

				crate::compose! {
					V0: id: b"test-ping",
						order: 1_700_000_000u64,
						message: message
				}
			}

			// Test winning case
			let ping_message = generate_message(42, None)?;
			let response = client.emit(ping_message, None).await?;
			let response_message = crate::decode::<ResponseMessage, _>(&response.unwrap().message)?;
			assert_eq!(response_message.result, "PONG");
			assert!(response_message.is_winner);

			let ping_message_loser = generate_message(99, None)?;
			let response = client.emit(ping_message_loser, None).await?;
			let response_message = crate::decode::<ResponseMessage, _>(&response.unwrap().message)?;
			assert_eq!(response_message.result, "PONG");
			assert!(!response_message.is_winner);

			Ok(())
		}
	}
}
