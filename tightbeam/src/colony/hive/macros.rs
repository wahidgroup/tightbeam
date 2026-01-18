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
				/// Build a minimal frame for hive-internal calls
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
						let frame = Self::build_frame(b"hive-call", request);

						pooled_conn.conn()?.emit(frame, None).await?
							.map(|mut r| core::mem::take(&mut r.message))
							.ok_or($crate::TightBeamError::MissingResponse)
					})
				}
			}

			// =================================================================
			// Hive Trait Implementation
			// =================================================================

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
					let hive_context = ::std::sync::Arc::new([<$hive_name Context>] {
						servlet_addresses: ::std::sync::Arc::new(::std::sync::RwLock::new(::std::collections::HashMap::new())),
						type_index: ::std::sync::Arc::new(::std::sync::RwLock::new(::std::collections::HashMap::new())),
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

					// Populate hive context with servlet addresses
					{
						let mut addrs = self.hive_context.servlet_addresses.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;
						let mut type_idx = self.hive_context.type_index.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;

						self.servlets.for_each(|name, reg| {
							let addr_bytes = reg.servlet.addr_bytes();
							addrs.insert(name.clone(), addr_bytes.clone());
							// First registration per type wins for O(1) lookup
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
					let hive_context_for_server = ::std::sync::Arc::clone(&self.hive_context);

					#[cfg(feature = "x509")]
					let trust_store = self.config.trust_store.clone();
					let cb_threshold = self.config.circuit_breaker_threshold;
					let cb_cooldown_ms = self.config.circuit_breaker_cooldown_ms;

					// Start control server
					let control_server_handle = hive!(
						@build_control_server $protocol,
						listener,
						servlets_for_server,
						trace_for_server,
						utilization_for_server,
						utilization_map_for_server,
						draining_for_server,
						spawners_for_server,
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
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
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

					let request = $crate::colony::hive::RegisterHiveRequest {
						hive_addr: self.addr.into(),
						servlet_addresses: servlet_info_list,
						metadata: Some(b"hive".to_vec()),
					};

					// Connect to cluster
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await?;
					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

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
					if let Ok(mut addr) = self.cluster_addr.write() {
						*addr = Some(cluster_addr);
					}

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

					loop {
						let timed_out = start.elapsed() >= drain_timeout;
						if self.servlets.count() == 0 || timed_out {
							if timed_out {
								self.servlets.drain_all().into_iter().for_each(|(_, reg)| reg.servlet.stop_boxed());
							}
							break;
						}
						hive!(@sleep ::std::time::Duration::from_millis(100));
					}

					Ok(())
				}

				fn is_draining(&self) -> bool {
					self.draining_since.read().map(|g| g.is_some()).unwrap_or(false)
				}
			}

			// =================================================================
			// Drop Implementation
			// =================================================================

			impl Drop for $hive_name {
				fn drop(&mut self) {
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
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

	(@build_control_server $protocol:path,
		$listener:ident,
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$draining_since:ident,
		$spawners:ident,
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
						@handle_command $protocol,
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
	// Command Handler
	// ==========================================================================

	(@handle_command $protocol:path,
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
		let current_util = || $crate::utils::BasisPoints::new_saturating(
			$utilization.load(::core::sync::atomic::Ordering::Relaxed)
		);
		let active_count = || $servlets.count() as u32;
		let is_draining = $draining_since.read().map(|g| g.is_some()).unwrap_or(false);
		let is_heartbeat = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message)
			.map(|cmd| cmd.heartbeat.is_some())
			.unwrap_or(false);

		// Reject non-heartbeat when draining
		if is_draining && !is_heartbeat {
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::heartbeat(
				$crate::policy::TransitStatus::Busy, current_util(), active_count()
			));
		}

		// Security gate (x509 feature)
		#[cfg(feature = "x509")]
		{
			let security_status = match &$trust_store {
				Some(store) => {
					let gate = $crate::colony::hive::ClusterSecurityGate::new(
						::std::sync::Arc::clone(&$circuit_breaker),
						::std::sync::Arc::clone(store),
					);
					$crate::policy::GatePolicy::evaluate(&gate, &$frame)
				}
				None => $crate::policy::TransitStatus::Forbidden,
			};

			if security_status != $crate::policy::TransitStatus::Accepted {
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_err(security_status)
				));
			}
		}

		// Backpressure gate
		let bp_gate = $crate::colony::hive::BackpressureGate::new(
			::std::sync::Arc::clone(&$utilization),
			$crate::utils::BasisPoints::new(9000)
		);
		if $crate::policy::GatePolicy::evaluate(&bp_gate, &$frame) == $crate::policy::TransitStatus::Busy {
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::heartbeat(
				$crate::policy::TransitStatus::Busy, current_util(), active_count()
			));
		}

		// Parse and handle command
		if let Ok(cmd) = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message) {
			if cmd.heartbeat.is_some() {
				let util = current_util();
				let status = if util.get() >= 9000 {
					$crate::policy::TransitStatus::Busy
				} else {
					$crate::policy::TransitStatus::Accepted
				};
				return hive!(@reply_priority $frame, $crate::MessagePriority::Heartbeat,
					$crate::colony::common::ClusterCommandResponse::heartbeat(status, util, active_count())
				);
			}

			if let Some(manage) = cmd.manage {
				return hive!(@handle_manage $frame, manage, $servlets, $trace, $spawners, $hive_context);
			}
		}

		Ok(None)
	}};

	// ==========================================================================
	// Management Handler
	// ==========================================================================

	(@handle_manage $frame:ident, $request:ident, $servlets:ident, $trace:ident, $spawners:ident, $hive_context:ident) => {{
		// Spawn request
		if let Some(spawn) = $request.spawn {
			let type_bytes = &spawn.servlet_type;
			let type_str = core::str::from_utf8(type_bytes).unwrap_or("");

			if let Some((&static_type, spawner)) = $spawners.iter().find(|(k, _)| **k == type_str) {
				match spawner(::std::sync::Arc::clone(&$trace)).await {
					Ok(new_servlet) => {
						let addr_bytes = new_servlet.addr_bytes();
						let key_bytes = [static_type.as_bytes(), b"_", &addr_bytes].concat();

						let registration = $crate::colony::hive::ServletRegistration {
							servlet: new_servlet,
							spawner: ::std::sync::Arc::clone(spawner),
							servlet_type: static_type,
						};

						hive!(@add_to_context $hive_context, key_bytes.clone(), addr_bytes.clone(), type_bytes);
						let _ = $servlets.insert(key_bytes.clone(), registration);

						return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::hive::HiveManagementResponse::spawn_ok(addr_bytes, key_bytes)
						));
					}
					Err(_) => {
						return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::hive::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
						));
					}
				}
			} else {
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
				));
			}
		}

		// List request
		if $request.list.is_some() {
			let mut list: Vec<$crate::colony::common::ServletInfo> = Vec::new();
			$servlets.for_each(|name, reg| {
				list.push($crate::colony::common::ServletInfo {
					servlet_id: name.clone(),
					address: reg.servlet.addr_bytes(),
				});
			});
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
				$crate::colony::hive::HiveManagementResponse::list_ok(list)
			));
		}

		// Stop request
		if let Some(stop) = $request.stop {
			let id_bytes = &stop.servlet_id;
			let key_to_remove = $servlets.keys()
				.into_iter()
				.find(|k| k.as_slice() == id_bytes.as_slice());

			if let Some(key) = key_to_remove {
				if let Some(reg) = $servlets.remove(&key) {
					let removed_type = reg.servlet_type.as_bytes();
					let removed_addr = reg.servlet.addr_bytes();
					reg.servlet.stop_boxed();
					hive!(@remove_from_context $hive_context, key, removed_type, removed_addr);

					return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
						$crate::colony::hive::HiveManagementResponse::stop_ok()
					));
				}
			}

			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
				$crate::colony::hive::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
			));
		}

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
			let mut last_scale_up: std::collections::HashMap<Vec<u8>, std::time::Instant> = std::collections::HashMap::new();
			let mut last_scale_down: std::collections::HashMap<Vec<u8>, std::time::Instant> = std::collections::HashMap::new();

			loop {
				hive!(@sleep config.cooldown);

				for (&servlet_type, spawner) in spawners.iter() {
					let type_bytes = servlet_type.as_bytes();
					let type_key = type_bytes.to_vec();
					let scale_conf = config.servlet_overrides
						.get(type_bytes)
						.copied()
						.unwrap_or(config.default_scale);

					// Collect metrics using mutable captures (FnMut allows this)
					let mut count = 0usize;
					let mut util_sum = 0u32;
					{
						let util_guard = utilization_map.lock();
						servlets.for_each_by_type(type_bytes, |key, reg| {
							count += 1;
							util_sum += reg.servlet.utilization()
								.map(|bp| bp.get() as u32)
								.or_else(|| util_guard.as_ref().ok().and_then(|g| g.get(key).map(|&v| v as u32)))
								.unwrap_or(5000);
						});
					}

					let util_bps = match count {
						0 => $crate::utils::BasisPoints::MAX,
						n => $crate::utils::BasisPoints::new_saturating((util_sum / n as u32) as u16),
					};
					utilization.store(util_bps.get(), ::core::sync::atomic::Ordering::Relaxed);

					let metrics = $crate::colony::common::ScalingMetrics {
						servlet_type: type_key.clone(),
						utilization: util_bps,
						current_instances: count,
						config: scale_conf,
					};

					match $crate::colony::common::ScalingDecision::evaluate(&metrics) {
						$crate::colony::common::ScalingDecision::ScaleUp => {
							// Check cooldown
							if last_scale_up.get(type_bytes)
								.is_some_and(|t| t.elapsed() < scale_conf.scale_up_cooldown)
							{
								continue;
							}

							let Ok(new_servlet) = spawner(::std::sync::Arc::clone(&trace)).await else {
								continue;
							};

							let addr_bytes = new_servlet.addr_bytes();
							let key_bytes = [type_bytes, b"_", &addr_bytes].concat();

							hive!(@add_to_context hive_context, key_bytes.clone(), addr_bytes.clone(), type_bytes);

							hive!(@notify_cluster $protocol, cluster_addr.clone(), hive_addr.clone(),
								$crate::colony::hive::ServletInfo {
									servlet_id: type_key.clone(),
									address: addr_bytes,
								},
								true,
								::std::sync::Arc::clone(&config.cluster_notify_retry)
							);

							let registration = $crate::colony::hive::ServletRegistration {
								servlet: new_servlet,
								spawner: ::std::sync::Arc::clone(spawner),
								servlet_type,
							};
							let _ = servlets.insert(key_bytes, registration);
							last_scale_up.insert(type_key.clone(), std::time::Instant::now());
						}
						$crate::colony::common::ScalingDecision::ScaleDown => {
							// Check cooldown
							if last_scale_down.get(type_bytes)
								.is_some_and(|t| t.elapsed() < scale_conf.scale_down_cooldown)
							{
								continue;
							}

						// Find and remove oldest instance of this type
						let Some(key) = servlets.keys()
							.into_iter()
							.filter(|k| k.starts_with(type_bytes))
							.last()
						else {
							continue;
						};

							let Some(reg) = servlets.remove(&key) else {
								continue;
							};

							let addr = reg.servlet.addr_bytes();
							reg.servlet.stop_boxed();
							hive!(@remove_from_context hive_context, key, type_bytes, addr.clone());

							hive!(@notify_cluster $protocol, cluster_addr.clone(), hive_addr.clone(),
								$crate::colony::hive::ServletInfo {
									servlet_id: type_key.clone(),
									address: addr,
								},
								false,
								::std::sync::Arc::clone(&config.cluster_notify_retry)
							);

							last_scale_down.insert(type_key.clone(), std::time::Instant::now());
						}
						$crate::colony::common::ScalingDecision::Hold => {}
					}
				}
			}
		})
	}};

	// ==========================================================================
	// Context Helpers
	// ==========================================================================

	// Add servlet to context addresses and type index
	(@add_to_context $ctx:expr, $key:expr, $addr:expr, $type_bytes:expr) => {{
		if let Ok(mut addrs) = $ctx.servlet_addresses.write() {
			addrs.insert($key, $addr.clone());
		}
		if let Ok(mut type_idx) = $ctx.type_index.write() {
			type_idx.entry($type_bytes.to_vec()).or_insert($addr);
		}
	}};

	// Remove servlet from context and update type index
	(@remove_from_context $ctx:expr, $key:expr, $type_bytes:expr, $removed_addr:expr) => {{
		if let Ok(mut addrs) = $ctx.servlet_addresses.write() {
			addrs.remove(&$key);
		}
		if let Ok(mut type_idx) = $ctx.type_index.write() {
			// Only update if this was the indexed address
			if type_idx.get($type_bytes) == Some(&$removed_addr) {
				if let Ok(addrs) = $ctx.servlet_addresses.read() {
					let replacement = addrs.iter()
						.find(|(k, _)| k.starts_with($type_bytes))
						.map(|(_, a)| a.clone());
					match replacement {
						Some(new_addr) => { type_idx.insert($type_bytes.to_vec(), new_addr); }
						None => { type_idx.remove($type_bytes); }
					}
				}
			}
		}
	}};

	// ==========================================================================
	// Cluster Notification
	// ==========================================================================

	(@notify_cluster $protocol:path, $cluster_addr:expr, $hive_addr:expr, $servlet_info:expr, $is_added:expr, $retry_policy:expr) => {{
		let cluster_addr_arc = $cluster_addr;
		let hive_id = $hive_addr;
		let servlet_info = $servlet_info;
		let is_added = $is_added;
		let retry_policy = $retry_policy;

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

			let max_attempts = retry_policy.max_attempts();
			for attempt in 0..=max_attempts {
				let stream = match <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await {
					Ok(s) => s,
					Err(_) => {
						hive!(@retry_delay attempt, max_attempts, retry_policy);
						continue;
					}
				};

				let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

				use $crate::transport::MessageEmitter;
				if transport.emit(frame.clone(), None).await.is_ok() {
					return;
				}

				hive!(@retry_delay attempt, max_attempts, retry_policy);
			}
		});
	}};

	// Retry delay helper
	(@retry_delay $attempt:ident, $max:ident, $policy:ident) => {{
		if $attempt < $max {
			hive!(@sleep ::std::time::Duration::from_millis($policy.delay_ms($attempt)));
		}
	}};

	// Sleep helper - abstracts tokio/std sleep
	(@sleep $duration:expr) => {{
		#[cfg(feature = "tokio")]
		tokio::time::sleep($duration).await;
		#[cfg(all(not(feature = "tokio"), feature = "std"))]
		std::thread::sleep($duration);
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
