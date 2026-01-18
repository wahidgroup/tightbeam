/// Macro for creating hives that orchestrate dynamically registered servlets.
///
/// Hives coordinate multiple servlets, enabling intra-hive communication,
/// lifecycle management, auto-scaling, and cluster integration.
#[macro_export]
macro_rules! hive {
	// Public hive
	(
		$(#[$meta:meta])*
		pub $hive_name:ident,
		protocol: $protocol:path
	) => {
		hive!(@impl $hive_name, $protocol, [pub], [$(#[$meta])*]);
	};

	// Private hive
	(
		$(#[$meta:meta])*
		$hive_name:ident,
		protocol: $protocol:path
	) => {
		hive!(@impl $hive_name, $protocol, [], [$(#[$meta])*]);
	};

	// ==========================================================================
	// Main Implementation
	// ==========================================================================

	(@impl $hive_name:ident, $protocol:path, [$($vis:tt)*], [$(#[$meta:meta])*]) => {
		paste::paste! {
			// =================================================================
			// HiveContext - defined first so main struct can reference it
			// =================================================================

			/// Intra-hive communication context
			struct [<$hive_name Context>] {
				/// Map of servlet keys to addresses (type + "_" + addr -> addr)
				servlet_addresses: ::std::sync::Arc<::std::sync::RwLock<::std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
				/// Type index for O(1) lookup (type_name -> first address)
				type_index: ::std::sync::Arc<::std::sync::RwLock<::std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
				/// Connection pool for calling sibling servlets
				pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
			}

			// =================================================================
			// Hive Struct
			// =================================================================

			$(#[$meta])*
			$($vis)* struct $hive_name {
				/// Registered servlets via ServletRegistry
				servlets: ::std::sync::Arc<$crate::colony::hive::HashMapRegistry>,
				/// Spawner functions for auto-scaling (type name -> spawner)
				spawners: ::std::sync::Arc<
					::std::collections::HashMap<&'static str, $crate::colony::hive::SpawnerFn>
				>,
				/// Hive configuration
				config: $crate::colony::hive::HiveConf,
				/// Trace collector for hive-level events
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				/// Control server handle (for cluster commands)
				control_server_handle: ::std::option::Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				/// Hive control server address
				addr: <$protocol as $crate::transport::Protocol>::Address,
				/// Scaling task handle
				scaling_handle: ::std::option::Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				/// Aggregate utilization for backpressure (basis points)
				utilization: ::std::sync::Arc<::core::sync::atomic::AtomicU16>,
				/// Per-instance utilization map (servlet_key -> utilization_bps)
				utilization_map: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<::std::vec::Vec<u8>, u16>>>,
				/// Connection pool for intra-hive calls
				servlet_pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
				/// Draining state: None = running, Some(Instant) = draining since
				draining_since: ::std::sync::Arc<::std::sync::RwLock<::std::option::Option<::std::time::Instant>>>,
				/// Cluster address (set after registration)
				cluster_addr: ::std::sync::Arc<::std::sync::RwLock<::std::option::Option<<$protocol as $crate::transport::Protocol>::Address>>>,
				/// Intra-hive communication context
				hive_context: ::std::sync::Arc<[<$hive_name Context>]>,
			}

			impl [<$hive_name Context>] {
				/// Build a frame for hive-internal calls
				fn build_internal_frame(request: Vec<u8>) -> $crate::Frame {
					$crate::Frame {
						version: $crate::Version::V0,
						metadata: $crate::Metadata {
							id: b"hive-call".to_vec(),
							order: 0,
							compactness: None,
							integrity: None,
							confidentiality: None,
							priority: None,
							lifetime: None,
							previous_frame: None,
							matrix: None,
						},
						message: request,
						integrity: None,
						nonrepudiation: None,
					}
				}
			}

			impl $crate::colony::hive::HiveContext for [<$hive_name Context>] {
				fn call<'a>(&'a self, servlet_type: &'a [u8], request: Vec<u8>) -> $crate::colony::hive::CallFuture<'a> {
					Box::pin(async move {
						use $crate::transport::client::pool::ConnectionBuilder;

						let route_err = || $crate::TightBeamError::RouterError(
							$crate::router::RouterError::UnknownRoute
						);

						// O(1) lookup by type using type_index
						let addr: <$protocol as $crate::transport::Protocol>::Address = {
							let type_idx = self.type_index.read()
								.map_err(|_| $crate::TightBeamError::LockPoisoned)?;

							let addr_bytes = type_idx.get(servlet_type)
								.cloned()
								.ok_or_else(route_err)?;

							// Parse address bytes as string for SocketAddr parsing
							let addr_str = String::from_utf8(addr_bytes)
								.map_err(|_| route_err())?;
							addr_str.parse().map_err(|_| route_err())?
						};

						// Connect and send
						let mut pooled_conn = (&self.pool).connect(addr).await?;
						let frame = Self::build_internal_frame(request);

						pooled_conn.conn()?.emit(frame, None).await?
							.map(|mut r| core::mem::take(&mut r.message))
							.ok_or($crate::TightBeamError::MissingResponse)
					})
				}
			}

			// =================================================================
			// Helper Methods
			// =================================================================

			impl [<$hive_name>] {
				/// Build a minimal frame for internal hive communication
				fn build_frame(id: &[u8], message: Vec<u8>) -> $crate::Frame {
					$crate::Frame {
						version: $crate::Version::V0,
						metadata: $crate::Metadata {
							id: id.to_vec(),
							order: 0,
							compactness: None,
							integrity: None,
							confidentiality: None,
							priority: None,
							lifetime: None,
							previous_frame: None,
							matrix: None,
						},
						message,
						integrity: None,
						nonrepudiation: None,
					}
				}

				/// Count instances for a servlet type
				fn count_instances(
					servlets: &::std::sync::MutexGuard<'_, ::std::collections::HashMap<Vec<u8>, $crate::colony::hive::ServletRegistration>>,
					servlet_type: &[u8],
				) -> usize {
					servlets.keys()
						.filter(|k| k.starts_with(servlet_type))
						.count()
				}

				/// Collect utilization metrics for a servlet type
				fn collect_type_metrics(
					servlets: &::std::sync::MutexGuard<'_, ::std::collections::HashMap<Vec<u8>, $crate::colony::hive::ServletRegistration>>,
					utilization_map: &::std::sync::MutexGuard<'_, ::std::collections::HashMap<Vec<u8>, u16>>,
					servlet_type: &[u8],
				) -> (usize, u32) {
					servlets.iter()
						.filter(|(key, _)| key.starts_with(servlet_type))
						.fold((0usize, 0u32), |(count, util_sum), (key, reg)| {
							let util_bps = reg.servlet.utilization()
								.map(|bp| bp.get())
								.or_else(|| utilization_map.get(key).copied())
								.unwrap_or(5000); // Default 50%
							(count + 1, util_sum + util_bps as u32)
						})
				}
			}

			// =================================================================
			// Hive Trait Implementation
			// =================================================================

			// Import trait to bring methods into scope for generated code
			#[allow(unused_imports)]
			use $crate::colony::hive::ServletRegistry as __ServletRegistry;

			impl $crate::colony::hive::Hive for $hive_name {
				type Protocol = $protocol;
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				fn new(config: Option<$crate::colony::hive::HiveConf>) -> Result<Self, $crate::TightBeamError> {
					use $crate::transport::client::pool::ConnectionBuilder;

					let config = config.unwrap_or_default();

					// Create connection pool for intra-hive calls
					let pool_config = $crate::transport::client::pool::PoolConfig {
						idle_timeout: config.servlet_pool_idle_timeout,
						max_connections: config.servlet_pool_size,
					};
					let servlet_pool = ::std::sync::Arc::new(
						$crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
							.with_config(pool_config)
							.build()
					);

					// Create empty hive context (will be populated in establish)
					let servlet_addresses: ::std::collections::HashMap<Vec<u8>, Vec<u8>> = ::std::collections::HashMap::new();
					let type_index: ::std::collections::HashMap<Vec<u8>, Vec<u8>> = ::std::collections::HashMap::new();
					let hive_context = ::std::sync::Arc::new([<$hive_name Context>] {
						servlet_addresses: ::std::sync::Arc::new(::std::sync::RwLock::new(servlet_addresses)),
						type_index: ::std::sync::Arc::new(::std::sync::RwLock::new(type_index)),
						pool: ::std::sync::Arc::clone(&servlet_pool),
					});

					// Default bind address (will be updated in establish)
					let addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;

					Ok(Self {
						servlets: ::std::sync::Arc::new($crate::colony::hive::HashMapRegistry::default()),
						spawners: ::std::sync::Arc::new(::std::collections::HashMap::new()),
						config,
						trace: ::std::sync::Arc::new($crate::trace::TraceCollector::new()),
						control_server_handle: None,
						addr,
						scaling_handle: None,
						utilization: ::std::sync::Arc::new(::core::sync::atomic::AtomicU16::new(0)),
						utilization_map: ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::HashMap::new())),
						servlet_pool,
						draining_since: ::std::sync::Arc::new(::std::sync::RwLock::new(None)),
						cluster_addr: ::std::sync::Arc::new(::std::sync::RwLock::new(None)),
						hive_context,
					})
				}

				fn register<S, F, Fut>(
					&mut self,
					name: &'static str,
					servlet: S,
					spawner: F,
				) -> Result<(), $crate::TightBeamError>
				where
					S: $crate::colony::hive::ServletBox + 'static,
					F: Fn(::std::sync::Arc<$crate::trace::TraceCollector>) -> Fut + Send + Sync + 'static,
					Fut: ::core::future::Future<Output = Result<S, $crate::TightBeamError>> + Send + 'static,
				{
					// Cannot register after establish
					if self.control_server_handle.is_some() {
						return Err($crate::TightBeamError::AlreadyEstablished);
					}

					// Wrap spawner to return Box<dyn ServletBox>
					let spawner_boxed: $crate::colony::hive::SpawnerFn = ::std::sync::Arc::new(move |trace| {
						let fut = spawner(trace);
						Box::pin(async move {
							let servlet = fut.await?;
							Ok(Box::new(servlet) as Box<dyn $crate::colony::hive::ServletBox>)
						}) as ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<Box<dyn $crate::colony::hive::ServletBox>, $crate::TightBeamError>> + Send>>
					});

					let registration = $crate::colony::hive::ServletRegistration {
						servlet: Box::new(servlet),
						spawner: spawner_boxed,
						servlet_type: name,
					};

					self.servlets.insert(name.as_bytes().to_vec(), registration)?;

					Ok(())
				}

				async fn establish(
					&mut self,
					trace: ::std::sync::Arc<$crate::trace::TraceCollector>
				) -> Result<(), $crate::TightBeamError> {
					use $crate::transport::Protocol;

					if self.control_server_handle.is_some() {
						return Err($crate::TightBeamError::AlreadyEstablished);
					}

					self.trace = trace;

					// Bind control server
					let bind_addr = <$protocol as Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as Protocol>::bind(bind_addr).await?;
					self.addr = addr;

					// Build spawner map from registrations (keyed by &'static str)
					let mut spawners_map: ::std::collections::HashMap<&'static str, $crate::colony::hive::SpawnerFn> =
						::std::collections::HashMap::new();
					self.servlets.for_each(|_key, reg| {
						spawners_map.insert(reg.servlet_type, ::std::sync::Arc::clone(&reg.spawner));
					});
					self.spawners = ::std::sync::Arc::new(spawners_map);

					// Update hive context with servlet addresses and type index
					{
						let mut addrs = self.hive_context.servlet_addresses.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;
						let mut type_idx = self.hive_context.type_index.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;
						self.servlets.for_each(|name, reg| {
							let addr_bytes = reg.servlet.addr_bytes();
							addrs.insert(name.clone(), addr_bytes.clone());
							// O(1) type lookup: first registration per type wins
							let type_key = reg.servlet_type.as_bytes().to_vec();
							type_idx.entry(type_key).or_insert(addr_bytes);
						});
					}

					// Clone values for control server
					let servlets_for_server = ::std::sync::Arc::clone(&self.servlets);
					let trace_for_server = ::std::sync::Arc::clone(&self.trace);
					let utilization_for_server = ::std::sync::Arc::clone(&self.utilization);
					let utilization_map_for_server = ::std::sync::Arc::clone(&self.utilization_map);
					let draining_for_server = ::std::sync::Arc::clone(&self.draining_since);
					let spawners_for_server = ::std::sync::Arc::clone(&self.spawners);
					let servlet_pool_for_server = ::std::sync::Arc::clone(&self.servlet_pool);
					let hive_context_for_server = ::std::sync::Arc::clone(&self.hive_context);

					#[cfg(feature = "x509")]
					let trust_store = self.config.trust_store.clone();
					let cb_threshold = self.config.circuit_breaker_threshold;
					let cb_cooldown_ms = self.config.circuit_breaker_cooldown_ms;

					// Start control server
					let control_server_handle = hive!(
						@build_hive_control_server $protocol,
						listener,
						servlets_for_server,
						trace_for_server,
						utilization_for_server,
						utilization_map_for_server,
						draining_for_server,
						spawners_for_server,
						servlet_pool_for_server,
						hive_context_for_server,
						trust_store,
						cb_threshold,
						cb_cooldown_ms
					);
					self.control_server_handle = Some(control_server_handle);

					// Start scaling task
					let scaling_handle = hive!(
						@build_scaling_task $protocol,
						::std::sync::Arc::clone(&self.servlets),
						::std::sync::Arc::clone(&self.spawners),
						::std::sync::Arc::clone(&self.trace),
						::std::sync::Arc::clone(&self.utilization),
						::std::sync::Arc::clone(&self.utilization_map),
						::std::sync::Arc::clone(&self.cluster_addr),
						::std::sync::Arc::clone(&self.hive_context),
						self.addr,
						self.config.clone()
					);
					self.scaling_handle = Some(scaling_handle);

					Ok(())
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn servlet_addresses(&self) -> Vec<(&'static str, Vec<u8>)> {
					self.servlets.addresses()
				}

				fn stop(mut self) {
					// Stop scaling task
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					// Stop control server
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					// Stop all servlets
					self.servlets.drain_all().into_iter().for_each(|(_, reg)| reg.servlet.stop_boxed());
				}

				#[cfg(feature = "tokio")]
				async fn join(mut self) -> Result<(), $crate::TightBeamError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle).await
							.map_err(|_| $crate::TightBeamError::JoinError)?;
					}
					Ok(())
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::TightBeamError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle)
							.map_err(|_| $crate::TightBeamError::JoinError)?;
					}
					Ok(())
				}

				async fn register_with_cluster(
					&self,
					cluster_addr: <Self::Protocol as $crate::transport::Protocol>::Address,
				) -> Result<$crate::colony::hive::RegisterHiveResponse, $crate::TightBeamError> {
					use $crate::transport::MessageEmitter;

					// Build servlet info list
					let mut servlet_info_list: Vec<$crate::colony::hive::ServletInfo> = Vec::new();
					self.servlets.for_each(|name, reg| {
						servlet_info_list.push($crate::colony::hive::ServletInfo {
							servlet_id: name.clone(),
							address: reg.servlet.addr_bytes(),
						});
					});
					let servlet_addresses = servlet_info_list;

					let hive_addr_bytes: Vec<u8> = self.addr.into();

					let request = $crate::colony::hive::RegisterHiveRequest {
						hive_addr: hive_addr_bytes,
						servlet_addresses,
						metadata: Some(b"hive".to_vec()),
					};

					// Connect to cluster
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await?;
					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

					// Apply TLS configuration
					#[cfg(feature = "x509")]
					{
						use $crate::transport::X509ClientConfig;

						if let Some(ref store) = self.config.trust_store {
							transport = transport.with_trust_store(::std::sync::Arc::clone(store));
						}

						if let Some(ref hive_tls) = self.config.hive_tls {
							let cert = $crate::crypto::x509::Certificate::try_from(hive_tls.certificate.clone())?;
							let key_mgr = $crate::transport::handshake::HandshakeKeyManager::new(
								::std::sync::Arc::clone(&hive_tls.key)
							);
							transport = transport.with_client_identity(cert, key_mgr);
						}
					}

					let frame = {
						use $crate::builder::TypeBuilder;
						$crate::utils::compose($crate::Version::V0)
							.with_id(b"hive-registration")
							.with_order(0)
							.with_message(request)
							.build()?
					};

					let response_frame = transport.emit(frame, None).await?
						.ok_or($crate::TightBeamError::MissingResponse)?;

					// Store cluster address
					let _ = self.cluster_addr.write().map(|mut addr| *addr = Some(cluster_addr));

					$crate::decode::<$crate::colony::hive::RegisterHiveResponse>(&response_frame.message)
				}

				async fn drain(&self) -> Result<(), $crate::TightBeamError> {
					// Set draining state
					{
						let mut guard = self.draining_since.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;
						*guard = Some(::std::time::Instant::now());
					}

					let drain_timeout = self.config.drain_timeout;
					let start = ::std::time::Instant::now();

					// Poll until all servlets stopped or timeout
					loop {
						let active_count = self.servlets.count();

						if active_count == 0 {
							break;
						}

						if start.elapsed() >= drain_timeout {
							// Force stop remaining servlets
							self.servlets.drain_all().into_iter().for_each(|(_, reg)| reg.servlet.stop_boxed());
							break;
						}

						#[cfg(feature = "tokio")]
						tokio::time::sleep(::std::time::Duration::from_millis(100)).await;
						#[cfg(all(not(feature = "tokio"), feature = "std"))]
						std::thread::sleep(::std::time::Duration::from_millis(100));
					}

					Ok(())
				}

				fn is_draining(&self) -> bool {
					self.draining_since.read()
						.map(|g| g.is_some())
						.unwrap_or(false)
				}
			}

			// =================================================================
			// Drop Implementation
			// =================================================================

			impl Drop for $hive_name {
				fn drop(&mut self) {
					// Stop the scaling task
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					// Stop the control server
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
				}
			}
		}
	};

	// ==========================================================================
	// Control Server
	// ==========================================================================

	(@build_hive_control_server $protocol:path,
		$listener:ident,
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$draining_since:ident,
		$spawners:ident,
		$servlet_pool:ident,
		$hive_context:ident,
		$trust_store:ident,
		$cb_threshold:ident,
		$cb_cooldown_ms:ident
	) => {{
		#[cfg(feature = "x509")]
		let circuit_breaker = ::std::sync::Arc::new(
			$crate::colony::hive::ClusterCircuitBreaker::new($cb_threshold, $cb_cooldown_ms)
		);

		$crate::server! {
			protocol $protocol: $listener,
			handle: move |frame: $crate::Frame| {
				let servlets = ::std::sync::Arc::clone(&$servlets);
				let trace = ::std::sync::Arc::clone(&$trace);
				let utilization = ::std::sync::Arc::clone(&$utilization);
				let utilization_map = ::std::sync::Arc::clone(&$utilization_map);
				let draining_since = ::std::sync::Arc::clone(&$draining_since);
				let spawners = ::std::sync::Arc::clone(&$spawners);
				let hive_context = ::std::sync::Arc::clone(&$hive_context);
				#[cfg(feature = "x509")]
				let circuit_breaker = ::std::sync::Arc::clone(&circuit_breaker);
				#[cfg(feature = "x509")]
				let trust_store = $trust_store.clone();

				async move {
					hive!(
						@handle_cluster_command $protocol,
						frame,
						servlets,
						trace,
						utilization,
						utilization_map,
						draining_since,
						spawners,
						hive_context,
						circuit_breaker,
						trust_store
					)
				}
			}
		}
	}};

	// ==========================================================================
	// Cluster Command Handler
	// ==========================================================================

	(@handle_cluster_command $protocol:path,
		$frame:ident,
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$draining_since:ident,
		$spawners:ident,
		$hive_context:ident,
		$circuit_breaker:ident,
		$trust_store:ident
	) => {{
		use ::core::sync::atomic::Ordering;

		let active_count = || -> u32 {
			$servlets.count() as u32
		};

		let current_util = || -> $crate::utils::BasisPoints {
			$crate::utils::BasisPoints::new_saturating($utilization.load(::core::sync::atomic::Ordering::Relaxed))
		};

		// 0. Check drain state - reject non-heartbeat requests when draining
		let is_draining = $draining_since.read().map(|g| g.is_some()).unwrap_or(false);
		let is_heartbeat = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message)
			.map(|cmd| cmd.heartbeat.is_some())
			.unwrap_or(false);

		if is_draining && !is_heartbeat {
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::heartbeat(
				$crate::policy::TransitStatus::Busy, current_util(), active_count()
			));
		}

		// 1. Apply ClusterSecurityGate with certificate trust store
		#[cfg(feature = "x509")]
		{
			let security_status = match &$trust_store {
				Some(store) => {
					let security_gate = $crate::colony::hive::ClusterSecurityGate::new(
						::std::sync::Arc::clone(&$circuit_breaker),
						::std::sync::Arc::clone(store),
					);
					$crate::policy::GatePolicy::evaluate(&security_gate, &$frame)
				}
				None => $crate::policy::TransitStatus::Forbidden,
			};
			if security_status != $crate::policy::TransitStatus::Accepted {
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_err(security_status)
				));
			}
		}

		// 2. Apply BackpressureGate
		let backpressure_gate = $crate::colony::hive::BackpressureGate::new(
			::std::sync::Arc::clone(&$utilization),
			$crate::utils::BasisPoints::new(9000)
		);
		let bp_status = $crate::policy::GatePolicy::evaluate(&backpressure_gate, &$frame);
		if bp_status == $crate::policy::TransitStatus::Busy {
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::heartbeat(
				$crate::policy::TransitStatus::Busy,
				current_util(),
				active_count(),
			));
		}

		// 3. Try ClusterCommand (the protocol envelope)
		if let Ok(cmd) = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message) {
			if cmd.heartbeat.is_some() {
				let util_bps = current_util();
				let status = if util_bps.get() >= 9000 {
					$crate::policy::TransitStatus::Busy
				} else {
					$crate::policy::TransitStatus::Accepted
				};

				return hive!(@reply_priority $frame, $crate::MessagePriority::Heartbeat,
					$crate::colony::common::ClusterCommandResponse::heartbeat(status, util_bps, active_count())
				);
			}

			if let Some(manage_request) = cmd.manage {
				return hive!(
					@handle_management_request $frame,
					manage_request,
					$servlets,
					$trace,
					$spawners,
					$hive_context
				);
			}
		}

		// Unknown message type
		Ok(None)
	}};

	// ==========================================================================
	// Management Request Handler
	// ==========================================================================

	(@handle_management_request $frame:ident,
		$request:ident,
		$servlets:ident,
		$trace:ident,
		$spawners:ident,
		$hive_context:ident
	) => {{
		// Handle spawn request
		if let Some(spawn_params) = $request.spawn {
			let servlet_type_bytes = &spawn_params.servlet_type;

			// Find spawner for this type by matching &str key
			// Convert bytes to str for lookup
			let servlet_type_str = core::str::from_utf8(servlet_type_bytes).unwrap_or("");

			// Find the spawner and get the static key
			if let Some((&static_type, spawner)) = $spawners.iter().find(|(k, _)| **k == servlet_type_str) {
				match spawner(::std::sync::Arc::clone(&$trace)).await {
					Ok(new_servlet) => {
						let addr_bytes = new_servlet.addr_bytes();

						// Generate unique key for this instance
						let key = format!("{}_{}", static_type, String::from_utf8_lossy(&addr_bytes));

						// Create registration - reuse the &'static str from spawner map
						let registration = $crate::colony::hive::ServletRegistration {
							servlet: new_servlet,
							spawner: ::std::sync::Arc::clone(spawner),
							servlet_type: static_type,
						};

						let key_bytes = key.into_bytes();

						// Update hive context addresses and type index
						if let Ok(mut addrs) = $hive_context.servlet_addresses.write() {
							addrs.insert(key_bytes.clone(), addr_bytes.clone());
						}
						if let Ok(mut type_idx) = $hive_context.type_index.write() {
							// Update type index if this is the first of this type
							let type_key = servlet_type_bytes.to_vec();
							type_idx.entry(type_key).or_insert(addr_bytes.clone());
						}

						// Add to servlets map (clone key for response)
						let response_key = key_bytes.clone();
						let _ = $servlets.insert(key_bytes, registration);

						return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::hive::HiveManagementResponse::spawn_ok(addr_bytes, response_key)
						));
					}
					Err(_) => {
						return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::hive::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
						));
					}
				}
			} else {
				// Unknown servlet type
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
				));
			}
		}

		// Handle list request
		if $request.list.is_some() {
			let mut servlet_list: Vec<$crate::colony::common::ServletInfo> = Vec::new();
			$servlets.for_each(|name, reg| {
				servlet_list.push($crate::colony::common::ServletInfo {
					servlet_id: name.clone(),
					address: reg.servlet.addr_bytes(),
				});
			});

			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
				$crate::colony::hive::HiveManagementResponse::list_ok(servlet_list)
			));
		}

		// Handle stop request
		if let Some(stop_params) = $request.stop {
			let servlet_id_bytes = &stop_params.servlet_id;

			// Find key to remove
			let key_to_remove: Option<Vec<u8>> = $servlets.keys()
				.into_iter()
				.find(|k| k.as_slice() == servlet_id_bytes.as_slice());

			let removed = if let Some(key) = key_to_remove {
				if let Some(reg) = $servlets.remove(&key) {
					let removed_type = reg.servlet_type;
					let removed_addr = reg.servlet.addr_bytes();
					reg.servlet.stop_boxed();
					// Remove from hive context addresses
					let _ = $hive_context.servlet_addresses.write().map(|mut addrs| {
						addrs.remove(&key);
					});
					// Update type_index: find next available for this type or remove
					if let Ok(mut type_idx) = $hive_context.type_index.write() {
						let type_key = removed_type.as_bytes().to_vec();
						if type_idx.get(&type_key) == Some(&removed_addr) {
							// This was the indexed address, find replacement
							if let Ok(addrs) = $hive_context.servlet_addresses.read() {
								let replacement = addrs.iter()
									.find(|(k, _)| k.starts_with(&type_key))
									.map(|(_, addr)| addr.clone());
								match replacement {
									Some(new_addr) => { type_idx.insert(type_key, new_addr); }
									None => { type_idx.remove(&type_key); }
								}
							}
						}
					}
					true
				} else {
					false
				}
			} else {
				false
			};

			if removed {
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_ok()
				));
			} else {
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
				));
			}
		}

		// No recognized request type
		Ok(None)
	}};

	// ==========================================================================
	// Scaling Task
	// ==========================================================================

	(@build_scaling_task $protocol:path,
		$servlets:expr,
		$spawners:expr,
		$trace:expr,
		$utilization:expr,
		$utilization_map:expr,
		$cluster_addr:expr,
		$hive_context:expr,
		$hive_addr:expr,
		$config:expr
	) => {{
		let servlets = $servlets;
		let spawners = $spawners;
		let trace = $trace;
		let utilization = $utilization;
		let utilization_map = $utilization_map;
		let cluster_addr = $cluster_addr;
		let hive_context = $hive_context;
		let hive_addr: Vec<u8> = $hive_addr.into();
		let config = $config;

		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			loop {
				// Sleep for cooldown period
				#[cfg(feature = "tokio")]
				tokio::time::sleep(config.cooldown).await;
				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				std::thread::sleep(config.cooldown);

				// Evaluate scaling for each registered servlet type
				for (&servlet_type, spawner) in spawners.iter() {
					let type_bytes = servlet_type.as_bytes();
					let scale_conf = config.servlet_overrides
						.get(type_bytes)
						.cloned()
						.unwrap_or_else(|| config.default_scale.clone());

					// Collect metrics for this type
					let (current_instances, type_utilization_sum) = {
						let util_guard = utilization_map.lock();
						let count = ::core::cell::Cell::new(0usize);
						let util_sum = ::core::cell::Cell::new(0u32);

						servlets.for_each_by_type(type_bytes, |key, reg| {
							count.set(count.get() + 1);
							let util_bps = reg.servlet.utilization()
								.map(|bp| bp.get())
								.or_else(|| util_guard.as_ref().ok().and_then(|g| g.get(key).copied()))
								.unwrap_or(5000);
							util_sum.set(util_sum.get() + util_bps as u32);
						});

						(count.get(), util_sum.get())
					};

					// Calculate average utilization
					let utilization_bps = if current_instances == 0 {
						$crate::utils::BasisPoints::MAX
					} else {
						let avg = (type_utilization_sum / current_instances as u32) as u16;
						$crate::utils::BasisPoints::new_saturating(avg)
					};

					// Update aggregate utilization
					utilization.store(utilization_bps.get(), ::core::sync::atomic::Ordering::Relaxed);

					let metrics = $crate::colony::common::ScalingMetrics {
						servlet_type: type_bytes.to_vec(),
						utilization: utilization_bps,
						current_instances,
						config: scale_conf,
					};

					let decision = $crate::colony::common::ScalingDecision::evaluate(&metrics);
					match decision {
						$crate::colony::common::ScalingDecision::ScaleUp => {
							// Spawn new instance
							if let Ok(new_servlet) = spawner(::std::sync::Arc::clone(&trace)).await {
								let addr_bytes = new_servlet.addr_bytes();
								let key_str = format!("{}_{}", servlet_type, String::from_utf8_lossy(&addr_bytes));
								let key_bytes = key_str.into_bytes();

								// Use the &'static str directly from spawner map (no Box::leak!)
								let registration = $crate::colony::hive::ServletRegistration {
									servlet: new_servlet,
									spawner: ::std::sync::Arc::clone(spawner),
									servlet_type,
								};

								// Update hive context first (needs clones)
								if let Ok(mut addrs) = hive_context.servlet_addresses.write() {
									addrs.insert(key_bytes.clone(), addr_bytes.clone());
								}
								// Update type_index if this type has no index yet
								if let Ok(mut type_idx) = hive_context.type_index.write() {
									type_idx.entry(type_bytes.to_vec()).or_insert(addr_bytes.clone());
								}

								// Notify cluster (addr_bytes moved here)
								let notify_addr = addr_bytes;
								hive!(@notify_cluster $protocol, cluster_addr.clone(), hive_addr.clone(),
									$crate::colony::hive::ServletInfo {
										servlet_id: type_bytes.to_vec(),
										address: notify_addr,
									},
									true, // added
									::std::sync::Arc::clone(&config.cluster_notify_retry)
								);

								// Add to servlets map (key_bytes moved here)
								let _ = servlets.insert(key_bytes, registration);
							}
						}
						$crate::colony::common::ScalingDecision::ScaleDown => {
							// Stop oldest instance of this type
							// Find key to remove (last one matching type prefix)
							let key_to_remove: Option<Vec<u8>> = servlets.keys()
								.into_iter()
								.filter(|k| k.starts_with(type_bytes))
								.last();

							let removed_addr: Option<Vec<u8>> = if let Some(key) = key_to_remove {
								if let Some(reg) = servlets.remove(&key) {
									let addr = reg.servlet.addr_bytes();
									reg.servlet.stop_boxed();
									// Remove from hive context addresses
									let _ = hive_context.servlet_addresses.write().map(|mut addrs| {
										addrs.remove(&key);
									});
									// Update type_index: find next available for this type or remove
									if let Ok(mut type_idx) = hive_context.type_index.write() {
										if type_idx.get(type_bytes) == Some(&addr) {
											// This was the indexed address, find replacement
											if let Ok(addrs) = hive_context.servlet_addresses.read() {
												let replacement = addrs.iter()
													.find(|(k, _)| k.starts_with(type_bytes))
													.map(|(_, a)| a.clone());
												match replacement {
													Some(new_addr) => { type_idx.insert(type_bytes.to_vec(), new_addr); }
													None => { type_idx.remove(type_bytes); }
												}
											}
										}
									}
									Some(addr)
								} else {
									None
								}
							} else {
								None
							};

							// Notify cluster of removal
							if let Some(addr) = removed_addr {
								hive!(@notify_cluster $protocol, cluster_addr.clone(), hive_addr.clone(),
									$crate::colony::hive::ServletInfo {
										servlet_id: type_bytes.to_vec(),
										address: addr,
									},
									false, // removed
									::std::sync::Arc::clone(&config.cluster_notify_retry)
								);
							}
						}
						$crate::colony::common::ScalingDecision::Hold => {}
					}
				}
			}
		})
	}};

	// ==========================================================================
	// Notify Cluster
	// ==========================================================================

	(@notify_cluster $protocol:path, $cluster_addr:expr, $hive_addr:expr, $servlet_info:expr, $is_added:expr, $retry_policy:expr) => {{
		let cluster_addr_arc = $cluster_addr;
		let hive_id = $hive_addr;
		let servlet_info = $servlet_info;
		let is_added = $is_added;
		let retry_policy = $retry_policy;

		// Cluster notification with configurable retry
		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			use $crate::transport::policy::CoreRetryPolicy;

			let cluster_addr = {
				let Ok(guard) = cluster_addr_arc.read() else { return };
				match *guard {
					Some(addr) => addr,
					None => return,
				}
			};

			let update = if is_added {
				$crate::colony::hive::ServletAddressUpdate {
					hive_id,
					added: vec![servlet_info],
					removed: vec![],
				}
			} else {
				$crate::colony::hive::ServletAddressUpdate {
					hive_id,
					added: vec![],
					removed: vec![servlet_info.address],
				}
			};

			let Ok(frame) = (|| -> Result<$crate::Frame, $crate::TightBeamError> {
				use $crate::builder::TypeBuilder;
				$crate::utils::compose($crate::Version::V0)
					.with_id(b"scaling-update")
					.with_order(0)
					.with_message(update)
					.build()
			})() else { return };

			// Retry loop with configurable policy
			let max_attempts = retry_policy.max_attempts();
			for attempt in 0..=max_attempts {
				// Connect to cluster
				let stream = match <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await {
					Ok(s) => s,
					Err(_) => {
						if attempt < max_attempts {
							#[cfg(feature = "tokio")]
							tokio::time::sleep(::std::time::Duration::from_millis(retry_policy.delay_ms(attempt))).await;
							#[cfg(all(not(feature = "tokio"), feature = "std"))]
							std::thread::sleep(::std::time::Duration::from_millis(retry_policy.delay_ms(attempt)));
						}
						continue;
					}
				};

				let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

				use $crate::transport::MessageEmitter;
				if transport.emit(frame.clone(), None).await.is_ok() {
					return; // Success
				}

				// Delay before next attempt
				if attempt < max_attempts {
					#[cfg(feature = "tokio")]
					tokio::time::sleep(::std::time::Duration::from_millis(retry_policy.delay_ms(attempt))).await;
					#[cfg(all(not(feature = "tokio"), feature = "std"))]
					std::thread::sleep(::std::time::Duration::from_millis(retry_policy.delay_ms(attempt)));
				}
			}
			// All retries exhausted - notification lost (fire-and-forget)
		});
	}};

	// ==========================================================================
	// Response Helpers
	// ==========================================================================

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

	(@reply_priority $frame:ident, $priority:expr, $message:expr) => {{
		use $crate::builder::TypeBuilder;
		Ok(Some(
			$crate::utils::compose($crate::Version::V0)
				.with_id($frame.metadata.id.clone())
				.with_order(0)
				.with_priority($priority)
				.with_message($message)
				.build()?
		))
	}};
}
