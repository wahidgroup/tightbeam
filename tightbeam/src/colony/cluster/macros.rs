//! Cluster macros for generating cluster gateway servers

/// Macro for creating clusters with pre-configured settings
///
/// # Syntax
///
/// ```ignore
/// use tightbeam::crypto::key::KeySpec;
///
/// const CLUSTER_KEY: &[u8] = &[/* 32-byte secret key */];
///
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     config: ClusterConfig::new(KeySpec::Bytes(CLUSTER_KEY))
/// }
/// ```
#[macro_export]
macro_rules! cluster {
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, pub, [$(#[$meta])*]);
	};

	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, , [$(#[$meta])*]);
	};

	// Generate cluster struct (public)
	(@impl_cluster $cluster_name:ident, $protocol:path, pub, [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		pub struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::cluster::HiveRegistry>,
			config: ::std::sync::Arc<$crate::colony::cluster::ClusterConf>,
			pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
			server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Generate cluster struct (private)
	(@impl_cluster $cluster_name:ident, $protocol:path, , [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::cluster::HiveRegistry>,
			config: ::std::sync::Arc<$crate::colony::cluster::ClusterConf>,
			pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
			server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Implement Cluster trait
	(@impl_cluster_trait $cluster_name:ident, $protocol:path) => {
		impl $crate::colony::cluster::Cluster for $cluster_name {
			type Protocol = $protocol;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: $crate::colony::cluster::ClusterConf,
			) -> Result<Self, $crate::TightBeamError> {
				use $crate::transport::Protocol;

				// Wrap config in Arc for zero-copy sharing
				let config = ::std::sync::Arc::new(config);

				// Bind to a port for the gateway server
				let bind_addr = <$protocol>::default_bind_address()?;
				let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

				// Create registry with timeout from config
				let registry = ::std::sync::Arc::new(
					$crate::colony::cluster::HiveRegistry::new(config.heartbeat.timeout)
				);
				let registry_for_server = ::std::sync::Arc::clone(&registry);
				let trace_for_server = ::std::sync::Arc::clone(&trace);

				// Build connection pool with TLS configuration
				let pool = {
					use $crate::transport::client::pool::ConnectionBuilder;
					let builder = $crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
						.with_config(config.pool_config.clone())
						.with_client_identity(config.tls.certificate.clone(), ::std::sync::Arc::clone(&config.tls.key))?;
					::std::sync::Arc::new(builder.build())
				};

				// Start the gateway server
				let server_handle = $crate::cluster!(
					@build_gateway_server $protocol,
					listener,
					registry_for_server,
					trace_for_server
				);

				// Start the heartbeat loop - 3-tier implementation
				let heartbeat_handle = {
					let registry = ::std::sync::Arc::clone(&registry);
					let config = ::std::sync::Arc::clone(&config);
					let pool = ::std::sync::Arc::clone(&pool);

					// Tier 1: Tokio - use JoinSet for bounded concurrency
					#[cfg(feature = "tokio")]
					{
						$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
							loop {
								let hives = registry.all_hives().unwrap_or_default();
								let max_concurrent = config.heartbeat.max_concurrent;
								let mut set = ::tokio::task::JoinSet::new();

								let tasks: Vec<_> = hives
									.into_iter()
									.filter_map(|hive| $crate::cluster!(@parse_hive_addr hive))
									.collect();

								for (hive_addr, addr) in tasks {
									// Bounded: wait if at capacity
									while set.len() >= max_concurrent {
										let _ = set.join_next().await;
									}

									let registry = ::std::sync::Arc::clone(&registry);
									let config = ::std::sync::Arc::clone(&config);
									let pool = ::std::sync::Arc::clone(&pool);
									let max_failures = config.heartbeat.max_failures;

									set.spawn(async move {
										let result = $crate::cluster!(@send_heartbeat_async pool, config, addr);
										$crate::cluster!(@process_heartbeat_result registry, hive_addr, result, max_failures);
									});
								}

								// Drain remaining tasks
								while set.join_next().await.is_some() {}

								$crate::colony::servlet::servlet_runtime::rt::sleep(config.heartbeat.interval).await;
							}
						})
					}

					// Tier 2: std + futures - use block_on with for_each_concurrent
					#[cfg(all(not(feature = "tokio"), feature = "std", feature = "futures"))]
					{
						use futures::{executor::block_on, stream::{self, StreamExt}};

						$crate::colony::servlet::servlet_runtime::rt::spawn(move || {
							loop {
								let hives = registry.all_hives().unwrap_or_default();
								let max_concurrent = config.heartbeat.max_concurrent;

								block_on(async {
									stream::iter(hives.into_iter().filter_map(|hive| {
										$crate::cluster!(@parse_hive_addr hive)
									}))
									.for_each_concurrent(max_concurrent, |(hive_addr, addr)| {
										let registry = ::std::sync::Arc::clone(&registry);
										let config = ::std::sync::Arc::clone(&config);
										let pool = ::std::sync::Arc::clone(&pool);
										let max_failures = config.heartbeat.max_failures;
										async move {
											let result = $crate::cluster!(@send_heartbeat_async pool, config, addr);
											$crate::cluster!(@process_heartbeat_result registry, hive_addr, result, max_failures);
										}
									})
									.await;
								});

								$crate::colony::servlet::servlet_runtime::rt::sleep(config.heartbeat.interval);
							}
						})
					}

					// Tier 3: std only - sequential fallback
					#[cfg(all(not(feature = "tokio"), feature = "std", not(feature = "futures")))]
					{
						$crate::colony::servlet::servlet_runtime::rt::spawn(move || {
							loop {
								registry
									.all_hives()
									.unwrap_or_default()
									.into_iter()
									.filter_map(|hive| $crate::cluster!(@parse_hive_addr hive))
									.for_each(|(hive_addr, _addr)| {
										// Note: Sequential sync version - no async pool available
										// This tier is a placeholder for sync transport implementations
										let _ = registry.increment_failure(&hive_addr);
									});
								$crate::colony::servlet::servlet_runtime::rt::sleep(config.heartbeat.interval);
							}
						})
					}
				};

				Ok(Self {
					registry,
					config,
					pool,
					server_handle: Some(server_handle),
					heartbeat_handle: Some(heartbeat_handle),
					addr,
					trace,
				})
			}

			fn addr(&self) -> Self::Address {
				self.addr
			}

			fn available_servlets(&self) -> Vec<Vec<u8>> {
				self.registry.to_available_servlets().unwrap_or_default()
			}

			fn hive_count(&self) -> usize {
				self.registry.len().unwrap_or(0)
			}

			fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
				::std::sync::Arc::clone(&self.trace)
			}

			fn stop(mut self) {
				if let Some(handle) = self.heartbeat_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
			}

			#[cfg(feature = "tokio")]
			async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::join(handle).await
				} else {
					Ok(())
				}
			}

			#[cfg(all(not(feature = "tokio"), feature = "std"))]
			async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::join(handle)
				} else {
					Ok(())
				}
			}

			// =====================================================================
			// Heartbeat Methods
			// =====================================================================

			fn registry(&self) -> &::std::sync::Arc<$crate::colony::cluster::HiveRegistry> {
				&self.registry
			}

			fn heartbeat_config(&self) -> &$crate::colony::cluster::HeartbeatConf {
				&self.config.heartbeat
			}

			async fn send_heartbeat(
				&self,
				addr: Self::Address,
			) -> Result<$crate::colony::common::HeartbeatResult, $crate::colony::cluster::ClusterError> {
				use $crate::builder::TypeBuilder;

				// Build heartbeat command
				let cmd = $crate::colony::common::ClusterCommand {
					heartbeat: Some($crate::colony::common::HeartbeatParams {
						cluster_status: $crate::colony::common::ClusterStatus::Healthy,
					}),
					manage: None,
				};

				let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V1)
					.with_message(cmd)
					.with_priority($crate::MessagePriority::Heartbeat)
					.build()?;

				let signed_frame = frame
					.sign_with_provider::<$crate::crypto::hash::Sha3_256, _>(self.config.tls.key.as_ref())
					.await?;

				// Send via pool
				let mut client = self.pool.connect(addr).await?;
				let response = client.conn()?.emit(signed_frame, None).await?
					.ok_or($crate::colony::cluster::ClusterError::HiveCommunicationFailed($crate::colony::cluster::error::NO_RESPONSE_MSG.to_vec()))?;

				let cmd_response: $crate::colony::common::ClusterCommandResponse = $crate::decode(&response.message)?;
				cmd_response.heartbeat.ok_or($crate::colony::cluster::ClusterError::EncodingError)
			}
		}
	};

	// Build gateway server
	(@build_gateway_server $protocol:path, $listener:ident, $registry:ident, $trace:ident) => {
		$crate::server! {
			protocol $protocol: $listener,
			handle: move |frame: $crate::Frame| {
				let registry = ::std::sync::Arc::clone(&$registry);
				let _trace = ::std::sync::Arc::clone(&$trace);
				async move {
					$crate::cluster!(@handle_gateway_request frame, registry)
				}
			}
		}
	};

	// Helper: Build response frame (DRY)
	(@reply $frame:ident, $message:expr) => {{
		use $crate::builder::TypeBuilder;
		Ok(Some(
			$crate::utils::compose($crate::Version::V0)
				.with_id($frame.metadata.id.clone())
				.with_order(0)
				.with_message($message)
				.build()?
		))
	}};

	// Handle gateway requests (registration + work)
	(@handle_gateway_request $frame:ident, $registry:ident) => {{
		// Try to decode as RegisterHiveRequest (hive registration)
		if let Ok(request) = $crate::decode::<$crate::colony::hive::RegisterHiveRequest>(&$frame.message) {
			let status = match $registry.register(request.clone()) {
				Ok(()) => $crate::policy::TransitStatus::Accepted,
				Err(_) => $crate::policy::TransitStatus::Forbidden,
			};

			let response = $crate::colony::hive::RegisterHiveResponse {
				status,
				hive_id: Some(request.hive_addr.clone()),
			};

			return $crate::cluster!(@reply $frame, response);
		}

		// Try to decode as ClusterWorkRequest (work routing)
		if let Ok(request) = $crate::decode::<$crate::colony::cluster::ClusterWorkRequest>(&$frame.message) {
			// Check if any hives support this servlet type
			let hives = match $registry.hives_for_type(&request.servlet_type) {
				Ok(h) if !h.is_empty() => h,
				_ => {
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::Forbidden)
					);
				}
			};

			// TODO: Load balance and forward to selected hive
			// For now, return accepted with the payload echoed back
			let _ = hives; // Suppress unused warning until forwarding is implemented
			return $crate::cluster!(@reply $frame,
				$crate::colony::cluster::ClusterWorkResponse::ok(request.payload)
			);
		}

		// Unknown message type
		Ok(None)
	}};

	// Implement Drop
	(@impl_drop $cluster_name:ident) => {
		impl Drop for $cluster_name {
			fn drop(&mut self) {
				if let Some(handle) = self.heartbeat_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
			}
		}
	};

	// =========================================================================
	// Helpers
	// =========================================================================

	// Helper: Send heartbeat async - builds, signs, and sends heartbeat frame
	(@send_heartbeat_async $pool:expr, $config:expr, $addr:expr) => {
		async {
			use $crate::builder::TypeBuilder;

			let cmd = $crate::colony::common::ClusterCommand {
				heartbeat: Some($crate::colony::common::HeartbeatParams {
					cluster_status: $crate::colony::common::ClusterStatus::Healthy,
				}),
				manage: None,
			};

			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V1)
				.with_message(cmd)
				.with_priority($crate::MessagePriority::Heartbeat)
				.build()?;

			let signed_frame = frame
				.sign_with_provider::<$crate::crypto::hash::Sha3_256, _>($config.tls.key.as_ref())
				.await?;

			let mut client = $pool.connect($addr).await?;
			let response = client.conn()?.emit(signed_frame, None).await?
				.ok_or($crate::colony::cluster::ClusterError::HiveCommunicationFailed(
					$crate::colony::cluster::error::NO_RESPONSE_MSG.to_vec()
				))?;

			let cmd_response: $crate::colony::common::ClusterCommandResponse =
				$crate::decode(&response.message)?;
			cmd_response.heartbeat.ok_or($crate::colony::cluster::ClusterError::EncodingError)
		}.await
	};

	// Helper: Process heartbeat result - updates registry based on success/failure
	(@process_heartbeat_result $registry:expr, $hive_addr:expr, $result:expr, $max_failures:expr) => {
		match $result {
			Ok(hb) => {
				let _ = $registry.touch(&$hive_addr, hb.utilization);
			}
			Err(_) => {
				if let Ok(failures) = $registry.increment_failure(&$hive_addr) {
					if failures >= $max_failures {
						let _ = $registry.unregister(&$hive_addr);
					}
				}
			}
		}
	};

	// Helper: Parse hive address from bytes to protocol address
	(@parse_hive_addr $hive:expr) => {
		{
			let hive_addr = ::std::sync::Arc::clone(&$hive.address);
			core::str::from_utf8(&hive_addr)
				.ok()
				.and_then(|s| s.parse().ok())
				.map(|addr| (hive_addr, addr))
		}
	};
}
