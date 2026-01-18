//! Cluster macros for generating cluster gateway servers

/// Macro for creating clusters with pre-configured settings
///
/// # Syntax
///
/// ```ignore
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     config: ClusterConf::default()
/// }
///
/// // With custom digest:
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     digest: Blake3,
///     config: ClusterConf::default()
/// }
/// ```
#[macro_export]
macro_rules! cluster {
	// Public with custom digest
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		digest: $digest:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $digest, pub, [$(#[$meta])*]);
	};

	// Public with default digest (Sha3_256)
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $crate::crypto::hash::Sha3_256, pub, [$(#[$meta])*]);
	};

	// Private with custom digest
	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		digest: $digest:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $digest, , [$(#[$meta])*]);
	};

	// Private with default digest (Sha3_256)
	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		config: $config:expr
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $crate::crypto::hash::Sha3_256, , [$(#[$meta])*]);
	};

	// Generate cluster struct (public)
	(@impl_cluster $cluster_name:ident, $protocol:path, $digest:path, pub, [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		pub struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::cluster::HiveRegistry>,
			servlet_registry: ::std::sync::Arc<$crate::colony::cluster::ServletRegistry>,
			config: ::std::sync::Arc<$crate::colony::cluster::ClusterConf>,
			pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
			server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			evaporation_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol, $digest);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Generate cluster struct (private)
	(@impl_cluster $cluster_name:ident, $protocol:path, $digest:path, , [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::cluster::HiveRegistry>,
			servlet_registry: ::std::sync::Arc<$crate::colony::cluster::ServletRegistry>,
			config: ::std::sync::Arc<$crate::colony::cluster::ClusterConf>,
			pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
			server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			evaporation_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol, $digest);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Implement Cluster trait
	(@impl_cluster_trait $cluster_name:ident, $protocol:path, $digest:path) => {
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

				// Bind to a port for the gateway server with TLS
				// Always uses TLS when x509 is enabled (cluster has cert)
				// client_validators controls whether client certs are required
				let bind_addr = <$protocol>::default_bind_address()?;

				#[cfg(feature = "x509")]
				let (listener, addr) = {
					// Clone certificate spec (required - try_from consumes, config is in Arc)
					let cert_obj = $crate::crypto::x509::Certificate::try_from(config.tls.certificate.clone())?;
					let key_mgr = $crate::transport::handshake::HandshakeKeyManager::new(
						::std::sync::Arc::clone(&config.tls.key)
					);
					let mut encryption_config = $crate::transport::TransportEncryptionConfig::new(cert_obj, key_mgr);
					// Only require client certs if client_validators is non-empty
					if !config.tls.client_validators.is_empty() {
						let validators: Vec<_> = config.tls.client_validators.iter().map(::std::sync::Arc::clone).collect();
						encryption_config = encryption_config.with_client_validators(validators);
					}
					<$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, encryption_config).await?
				};

				#[cfg(not(feature = "x509"))]
				let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

				// Create hive registry with timeout from config
				let registry = ::std::sync::Arc::new(
					$crate::colony::cluster::HiveRegistry::new(config.heartbeat.timeout)
				);

				// Create servlet registry with pheromone config
				let servlet_registry = ::std::sync::Arc::new(
					$crate::colony::cluster::ServletRegistry::new(config.pheromone.clone())
				);

				// Build connection pool with TLS configuration
				let pool = {
					use $crate::transport::client::pool::ConnectionBuilder;
					let mut builder = $crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
						.with_config(config.pool_config.clone())
						.with_client_identity(config.tls.certificate.clone(), ::std::sync::Arc::clone(&config.tls.key))?;

					// Add trust store for validating hive/servlet certs if configured
					if let Some(ref trust) = config.tls.hive_trust {
						builder = builder.with_trust_store(::std::sync::Arc::clone(trust));
					}

					::std::sync::Arc::new(builder.build())
				};

				let registry_for_server = ::std::sync::Arc::clone(&registry);
				let servlet_registry_for_server = ::std::sync::Arc::clone(&servlet_registry);
				let config_for_server = ::std::sync::Arc::clone(&config);
				let pool_for_server = ::std::sync::Arc::clone(&pool);
				let trace_for_server = ::std::sync::Arc::clone(&trace);

				// Start the gateway server
				let server_handle = $crate::cluster!(
					@build_gateway_server $protocol,
					listener,
					registry_for_server,
					servlet_registry_for_server,
					config_for_server,
					pool_for_server,
					trace_for_server
				);

				// Start the heartbeat loop - 3-tier implementation
				let heartbeat_handle = {
					let registry = ::std::sync::Arc::clone(&registry);
					let servlet_registry_for_hb = ::std::sync::Arc::clone(&servlet_registry);
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
									let servlet_registry = ::std::sync::Arc::clone(&servlet_registry_for_hb);
									let config = ::std::sync::Arc::clone(&config);
									let pool = ::std::sync::Arc::clone(&pool);
									let max_failures = config.heartbeat.max_failures;

									set.spawn(async move {
										let result = $crate::cluster!(@send_heartbeat_async pool, config, addr, $digest);
										$crate::cluster!(@process_heartbeat_result registry, servlet_registry, hive_addr, result, max_failures, config);
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
										let servlet_registry = ::std::sync::Arc::clone(&servlet_registry_for_hb);
										let config = ::std::sync::Arc::clone(&config);
										let pool = ::std::sync::Arc::clone(&pool);
										let max_failures = config.heartbeat.max_failures;
									async move {
										let result = $crate::cluster!(@send_heartbeat_async pool, config, addr, $digest);
										$crate::cluster!(@process_heartbeat_result registry, servlet_registry, hive_addr, result, max_failures, config);
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
										// Fire callback with failure (no async executor available)
										if let Some(ref callback) = config.heartbeat.on_heartbeat {
											let event = $crate::colony::cluster::HeartbeatEvent {
												hive_addr: ::std::sync::Arc::clone(&hive_addr),
												success: false,
												utilization: None,
											};
											callback(event);
										}
										let _ = registry.increment_failure(&hive_addr);
									});
								$crate::colony::servlet::servlet_runtime::rt::sleep(config.heartbeat.interval);
							}
						})
					}
				};

				// Start the evaporation loop for bio-inspired routing
				let evaporation_handle = {
					let servlet_registry = ::std::sync::Arc::clone(&servlet_registry);
					let evaporation_interval = config.pheromone.evaporation_interval;

					#[cfg(feature = "tokio")]
					{
						$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
							loop {
								$crate::colony::servlet::servlet_runtime::rt::sleep(evaporation_interval).await;
								let _ = servlet_registry.evaporate();
								let _ = servlet_registry.remove_abandoned();
							}
						})
					}

					#[cfg(all(not(feature = "tokio"), feature = "std"))]
					{
						$crate::colony::servlet::servlet_runtime::rt::spawn(move || {
							loop {
								$crate::colony::servlet::servlet_runtime::rt::sleep(evaporation_interval);
								let _ = servlet_registry.evaporate();
								let _ = servlet_registry.remove_abandoned();
							}
						})
					}
				};

				Ok(Self {
					registry,
					servlet_registry,
					config,
					pool,
					server_handle: Some(server_handle),
					heartbeat_handle: Some(heartbeat_handle),
					evaporation_handle: Some(evaporation_handle),
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
				if let Some(handle) = self.evaporation_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
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
				$crate::cluster!(@send_heartbeat_async self.pool, self.config, addr, $digest)
			}
		}
	};

	// Build gateway server
	(@build_gateway_server $protocol:path, $listener:ident, $registry:ident, $servlet_registry:ident, $config:ident, $pool:ident, $trace:ident) => {
		$crate::server! {
			protocol $protocol: $listener,
			handle: move |frame: $crate::Frame| {
				let registry = ::std::sync::Arc::clone(&$registry);
				let servlet_registry = ::std::sync::Arc::clone(&$servlet_registry);
				let config = ::std::sync::Arc::clone(&$config);
				let pool = ::std::sync::Arc::clone(&$pool);
				let _trace = ::std::sync::Arc::clone(&$trace);
				async move {
					$crate::cluster!(@handle_gateway_request frame, registry, servlet_registry, config, pool)
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
	(@handle_gateway_request $frame:ident, $registry:ident, $servlet_registry:ident, $config:ident, $pool:ident) => {{
		// Try to decode as RegisterHiveRequest (hive registration)
		if let Ok(request) = $crate::decode::<$crate::colony::hive::RegisterHiveRequest>(&$frame.message) {
			// Extract data before consuming request (zero-copy: single Arc allocation)
			let hive_addr: ::std::sync::Arc<[u8]> = request.hive_addr.clone().into();

			// Extract servlet info for ServletRegistry (actual addresses)
			let servlet_info: Vec<(::std::sync::Arc<[u8]>, ::std::sync::Arc<[u8]>)> = request
				.servlet_addresses
				.iter()
				.map(|info| (
					::std::sync::Arc::from(info.servlet_id.as_slice()),
					::std::sync::Arc::from(info.address.as_slice()),
				))
				.collect();

				let status = match $registry.register(request) {
				Ok(()) => {
					// Store actual servlet addresses in ServletRegistry
					for (servlet_type, servlet_addr) in &servlet_info {
						let entry = $crate::colony::cluster::ServletEntry::new(
							::std::sync::Arc::clone(servlet_addr),  // Actual servlet address!
							::std::sync::Arc::clone(servlet_type),
							::std::sync::Arc::clone(&hive_addr),
							$config.pheromone.initial_pheromone,
							$config.pheromone.abandonment_limit,
						);
						let _ = $servlet_registry.add(entry);
					}
					$crate::policy::TransitStatus::Accepted
				}
				Err(_) => $crate::policy::TransitStatus::Forbidden,
			};

			let response = $crate::colony::hive::RegisterHiveResponse {
				status,
				hive_id: Some(hive_addr.to_vec()),
			};

			return $crate::cluster!(@reply $frame, response);
		}

		// Try to decode as ServletAddressUpdate (scaling notification from hive)
		if let Ok(update) = $crate::decode::<$crate::colony::hive::ServletAddressUpdate>(&$frame.message) {
			let hive_id: ::std::sync::Arc<[u8]> = update.hive_id.into();

			// Add new servlet entries
			for info in &update.added {
				let entry = $crate::colony::cluster::ServletEntry::new(
					::std::sync::Arc::from(info.address.as_slice()),
					::std::sync::Arc::from(info.servlet_id.as_slice()),
					::std::sync::Arc::clone(&hive_id),
					$config.pheromone.initial_pheromone,
					$config.pheromone.abandonment_limit,
				);
				let _ = $servlet_registry.add(entry);
			}

			// Remove stopped servlet entries
			for servlet_id in &update.removed {
				let _ = $servlet_registry.remove(servlet_id);
			}

			return $crate::cluster!(@reply $frame, $crate::colony::hive::ServletAddressUpdateResponse {
				status: $crate::policy::TransitStatus::Accepted,
			});
		}

		// Try to decode as ClusterWorkRequest (work routing)
		if let Ok(request) = $crate::decode::<$crate::colony::cluster::ClusterWorkRequest>(&$frame.message) {
			// Look up servlet entries by type (bio-inspired routing)
			let entries = match $servlet_registry.entries_for_type(&request.servlet_type) {
				Ok(e) if !e.is_empty() => e,
				_ => {
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::Busy)
					);
				}
			};

			// Apply scoring policy to convert entries to InstanceMetrics
			let scoring_policy = $crate::colony::common::PheromoneScoring;
			let metrics: Vec<$crate::colony::common::InstanceMetrics> = entries
				.iter()
				.map(|e| {
					use core::sync::atomic::Ordering;
					use $crate::colony::common::ScoringPolicy;
					$crate::colony::common::InstanceMetrics {
						servlet_id: e.address.to_vec(),
						utilization: scoring_policy.score(e.pheromone.load(Ordering::Relaxed), $crate::utils::BasisPoints::default()),
						active_requests: 0,
					}
				})
				.collect();

			// Use load balancer to select a servlet
			use $crate::colony::hive::LoadBalancer;
			let selected_idx = match $config.load_balancer.select(&metrics) {
				Some(idx) => idx,
				None => {
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::Busy)
					);
				}
			};

			let selected_entry = &entries[selected_idx];
			let selected_addr = ::std::sync::Arc::clone(&selected_entry.address);

			// Parse the servlet address and forward the request
			let forward_result = $crate::cluster!(@forward_work $pool, selected_addr, request.payload);

			// Reinforce or weaken based on outcome
			match forward_result {
				Ok(response_payload) => {
					// Reinforce pheromone on success using configured boost
					let _ = $servlet_registry.reinforce(&selected_entry.address, $config.pheromone.reinforcement_boost);
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::ok(response_payload)
					);
				}
				Err(_) => {
					// Weaken on failure using configured penalty
					let _ = $servlet_registry.weaken_with_penalty(&selected_entry.address, $config.pheromone.weakening_penalty);
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::Busy)
					);
				}
			}
		}

		// Unknown message type
		Ok(None)
	}};

	// Helper: Forward work to a servlet
	(@forward_work $pool:expr, $addr:expr, $payload:expr) => {{
		async {
			// Parse servlet address from bytes
			let addr_str = core::str::from_utf8(&$addr)
				.map_err(|_| $crate::colony::cluster::ClusterError::InvalidAddress($addr.to_vec()))?;
			let parsed_addr = addr_str.parse()
				.map_err(|_| $crate::colony::cluster::ClusterError::InvalidAddress($addr.to_vec()))?;

			// Build minimal frame with payload as message
			let mut metadata = $crate::Metadata::default();
			metadata.id = b"work-forward".to_vec();

			let frame = $crate::Frame {
				version: $crate::Version::V0,
				metadata,
				message: $payload,
				integrity: None,
				nonrepudiation: None,
			};

			// Connect to servlet and send
			let mut client = $pool.connect(parsed_addr).await
				.map_err(|_| $crate::colony::cluster::ClusterError::HiveCommunicationFailed(b"connect failed".to_vec()))?;

			let response = match client.conn()?.emit(frame, None).await {
				Ok(Some(r)) => r,
				Ok(None) => {
					return Err($crate::colony::cluster::ClusterError::HiveCommunicationFailed(b"no response".to_vec()));
				}
				Err(_) => {
					return Err($crate::colony::cluster::ClusterError::HiveCommunicationFailed(b"transport error".to_vec()));
				}
			};

			// Clone the message to avoid moving out of Frame (which has Drop)
			Ok::<_, $crate::colony::cluster::ClusterError>(response.message.clone())
		}.await
	}};

	// Implement Drop
	(@impl_drop $cluster_name:ident) => {
		impl Drop for $cluster_name {
			fn drop(&mut self) {
				if let Some(handle) = self.evaporation_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
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
	(@send_heartbeat_async $pool:expr, $config:expr, $addr:expr, $digest:path) => {
		async {
			use $crate::builder::TypeBuilder;

			let cmd = $crate::colony::common::ClusterCommand {
				heartbeat: Some($crate::colony::common::HeartbeatParams {
					cluster_status: $crate::colony::common::ClusterStatus::Healthy,
				}),
				manage: None,
			};

			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V1)
				.with_id(b"heartbeat")
				.with_message(cmd)
				.with_priority($crate::MessagePriority::Heartbeat)
				.with_witness_hasher::<$digest>()
				.build()?;

			let signed_frame = frame
				.sign_with_provider::<$digest, _>($config.tls.key.as_ref())
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
	(@process_heartbeat_result $registry:expr, $servlet_registry:expr, $hive_addr:expr, $result:expr, $max_failures:expr, $config:expr) => {
		// Fire callback if configured
		$crate::cluster!(@fire_heartbeat_callback $config, $hive_addr, $result);

		match $result {
			Ok(hb) => {
				let _ = $registry.touch(&$hive_addr, hb.utilization);
			}
			Err(_) => {
				if let Ok(failures) = $registry.increment_failure(&$hive_addr) {
					if failures >= $max_failures {
						// Remove from HiveRegistry
						let _ = $registry.unregister(&$hive_addr);
						// Also remove all servlet entries for this hive
						let _ = $servlet_registry.remove_by_hive(&$hive_addr);
					}
				}
			}
		}
	};

	// Helper: Fire heartbeat callback if configured
	(@fire_heartbeat_callback $config:expr, $hive_addr:expr, $result:expr) => {
		if let Some(ref callback) = $config.heartbeat.on_heartbeat {
			let event = $crate::colony::cluster::HeartbeatEvent {
				hive_addr: ::std::sync::Arc::clone(&$hive_addr),
				success: $result.is_ok(),
				utilization: $result.as_ref().ok().map(|r| r.utilization),
			};
			callback(event);
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
