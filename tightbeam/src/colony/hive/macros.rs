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
				/// Map of canonical instance-URN bytes to addresses
				servlet_addresses: ::std::sync::Arc<::std::sync::RwLock<::std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
				/// Type index for O(1) lookup (canonical type-URN bytes -> first address)
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
				/// Spawner functions for auto-scaling (type URN -> spawner)
				spawners: ::std::sync::Arc<
					::std::collections::HashMap<$crate::utils::urn::Urn<'static>, $crate::colony::hive::SpawnerFn>
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
				/// Cluster gateway addresses (appended by `register_with_cluster`);
				/// scaling updates and the re-registration beat fan out to every entry
				cluster_addrs: ::std::sync::Arc<::std::sync::RwLock<Vec<<$protocol as $crate::transport::Protocol>::Address>>>,
				/// Anti-entropy re-registration task handle
				reregister_handle: ::std::option::Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
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

				/// O(1) servlet-type to address resolution via type_index
				fn resolve_addr(
					&self,
					servlet_type: &$crate::utils::urn::Urn<'_>,
				) -> Result<<$protocol as $crate::transport::Protocol>::Address, $crate::TightBeamError> {
					let route_err = || $crate::TightBeamError::RouterError(
						$crate::router::RouterError::UnknownRoute
					);

					let type_idx = self.type_index.read()
						.map_err(|_| $crate::TightBeamError::LockPoisoned)?;

					let addr_bytes = type_idx.get(&$crate::colony::common::canonical_bytes(servlet_type))
						.cloned()
						.ok_or_else(route_err)?;

					let addr_str = String::from_utf8(addr_bytes)
						.map_err(|_| route_err())?;
					addr_str.parse().map_err(|_| route_err())
				}
			}

			impl $crate::colony::hive::HiveContext for [<$hive_name Context>] {
				fn call<'a>(&'a self, servlet_type: &'a $crate::utils::urn::Urn<'a>, request: Vec<u8>) -> $crate::colony::hive::CallFuture<'a> {
					Box::pin(async move {
						use $crate::transport::client::pool::ConnectionBuilder;

						let addr = self.resolve_addr(servlet_type)?;

						let mut pooled_conn = (&self.pool).connect(addr).await?;
						let frame = Self::build_frame(b"hive-call", request);

						pooled_conn.emit(frame, None).await?
							.map(|mut r| core::mem::take(&mut r.message))
							.ok_or($crate::TightBeamError::MissingResponse)
					})
				}

				fn open_stream<'a>(&'a self, servlet_type: &'a $crate::utils::urn::Urn<'a>) -> $crate::colony::hive::StreamOpenFuture<'a> {
					Box::pin(async move {
						use $crate::transport::client::pool::ConnectionBuilder;

						let addr = self.resolve_addr(servlet_type)?;
						let pooled_conn = (&self.pool).connect(addr).await?;
						let (sink, response) = pooled_conn.open_stream()?;

						// The lease returns to the pool here; the sink and
						// response live on the shared mux plane independently.
						// Reply shape matches `call`: message bytes out.
						let response: $crate::colony::hive::StreamResponseFuture =
							Box::pin(async move {
								response.await?
									.map(|mut r| core::mem::take(&mut r.message))
									.ok_or($crate::TightBeamError::MissingResponse)
							});
						Ok((sink, response))
					})
				}

				fn open_duplex<'a>(&'a self, servlet_type: &'a $crate::utils::urn::Urn<'a>) -> $crate::colony::hive::DuplexOpenFuture<'a> {
					Box::pin(async move {
						use $crate::transport::client::pool::ConnectionBuilder;

						let addr = self.resolve_addr(servlet_type)?;
						let pooled_conn = (&self.pool).connect(addr).await?;
						Ok(pooled_conn.open_duplex()?)
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

					let pool_config = $crate::transport::client::pool::PoolConfig {
						idle_timeout: config.servlet_pool_idle_timeout,
						max_connections: config.servlet_pool_size,
						mux_offer: config.mux_offer.to_owned(),
					};
					let pool_builder = $crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
						.with_config(pool_config);

					// Intra-hive calls validate servlet certificates against
					// the hive trust store.
					#[cfg(feature = "x509")]
					let pool_builder = match config.trust_store.as_ref() {
						Some(store) => pool_builder.with_trust_store(::std::sync::Arc::clone(store)),
						None => pool_builder,
					};

					let servlet_pool = ::std::sync::Arc::new(pool_builder.build());

					// Empty until establish() installs the servlet addresses
					let hive_context = ::std::sync::Arc::new([<$hive_name Context>] {
						servlet_addresses: ::std::sync::Arc::new(::std::sync::RwLock::new(::std::collections::HashMap::new())),
						type_index: ::std::sync::Arc::new(::std::sync::RwLock::new(::std::collections::HashMap::new())),
						pool: ::std::sync::Arc::clone(&servlet_pool),
					});

					// Placeholder until establish() binds the control server
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
						cluster_addrs: ::std::sync::Arc::new(::std::sync::RwLock::new(Vec::new())),
						reregister_handle: None,
						hive_context,
					})
				}

				fn register<S, F, Fut>(
					&mut self,
					servlet_type: $crate::utils::urn::Urn<'static>,
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

					// The type URN must belong to this hive's namespace and
					// carry no instance tail: registration under a foreign
					// authority or realm is refused before anything reaches
					// a cluster.
					match self.config.namespace.validate(&servlet_type)? {
						$crate::colony::common::ColonyResource::Servlet { instance: None, .. } => {}
						_ => return Err($crate::TightBeamError::UrnValidationError(
							$crate::utils::urn::UrnValidationError::InvalidFormat {
								field: "resource-id",
								pattern: None,
							}
						)),
					}

					let spawner_boxed: $crate::colony::hive::SpawnerFn = ::std::sync::Arc::new(move |trace| {
						let fut = spawner(trace);
						Box::pin(async move {
							let servlet = fut.await?;
							Ok(Box::new(servlet) as Box<dyn $crate::colony::hive::ServletBox>)
						}) as ::core::pin::Pin<Box<dyn ::core::future::Future<Output = Result<Box<dyn $crate::colony::hive::ServletBox>, $crate::TightBeamError>> + Send>>
					});

					// Registry keys are canonical instance-URN bytes: the
					// type URN with this instance's locator as the tail.
					let key = $crate::colony::common::canonical_bytes(
						&hive!(@instance_urn servlet_type, servlet.addr_bytes())?
					);

					let registration = $crate::colony::hive::ServletRegistration {
						servlet: Box::new(servlet),
						spawner: spawner_boxed,
						servlet_type,
					};

					self.servlets.insert(key, registration)?;
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

					// Bind control server. With hive_tls configured the
					// control plane is encrypted end to end: spawn/stop
					// commands otherwise travel plaintext and are trivially
					// observable/injectable on the network path.
					let bind_addr = <$protocol as Protocol>::default_bind_address()?;

					#[cfg(feature = "x509")]
					let (listener, addr) = match self.config.hive_tls.as_ref() {
						Some(hive_tls) => {
							let cert_obj = $crate::crypto::x509::Certificate::try_from(hive_tls.certificate.clone())?;
							let key_mgr = $crate::transport::handshake::HandshakeKeyManager::new(
								::std::sync::Arc::clone(&hive_tls.key)
							);

							let mut encryption_config = $crate::transport::TransportEncryptionConfig::new(cert_obj, key_mgr);
							if !hive_tls.validators.is_empty() {
								let validators: Vec<_> = hive_tls.validators.iter().map(::std::sync::Arc::clone).collect();
								encryption_config = encryption_config.with_client_validators(validators);
							}

							<$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, encryption_config).await?
						}
						None => <$protocol as Protocol>::bind(bind_addr).await?,
					};

					#[cfg(not(feature = "x509"))]
					let (listener, addr) = <$protocol as Protocol>::bind(bind_addr).await?;

					self.addr = addr;

					let mut spawners_map: ::std::collections::HashMap<$crate::utils::urn::Urn<'static>, $crate::colony::hive::SpawnerFn> =
						::std::collections::HashMap::new();
					self.servlets.for_each(|_key, reg| {
						spawners_map.insert(reg.servlet_type.clone(), ::std::sync::Arc::clone(&reg.spawner));
					});
					self.spawners = ::std::sync::Arc::new(spawners_map);

					{
						let mut addrs = self.hive_context.servlet_addresses.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;
						let mut type_idx = self.hive_context.type_index.write()
							.map_err(|_| $crate::TightBeamError::LockPoisoned)?;

						self.servlets.for_each(|key, reg| {
							let addr_bytes = reg.servlet.addr_bytes();
							addrs.insert(key.clone(), addr_bytes.clone());
							// First registration per type wins for O(1) lookup
							let type_key = $crate::colony::common::canonical_bytes(&reg.servlet_type);
							type_idx.entry(type_key).or_insert(addr_bytes);
						});
					}

					let servlets_for_server = ::std::sync::Arc::clone(&self.servlets);
					let trace_for_server = ::std::sync::Arc::clone(&self.trace);
					let utilization_for_server = ::std::sync::Arc::clone(&self.utilization);
					let utilization_map_for_server = ::std::sync::Arc::clone(&self.utilization_map);
					let draining_for_server = ::std::sync::Arc::clone(&self.draining_since);
					let spawners_for_server = ::std::sync::Arc::clone(&self.spawners);
					let hive_context_for_server = ::std::sync::Arc::clone(&self.hive_context);

					let cb_threshold = self.config.circuit_breaker_threshold;
					let cb_cooldown_ms = self.config.circuit_breaker_cooldown_ms;
					let bp_threshold = self.config.backpressure_threshold;

					#[cfg(feature = "x509")]
					let trust_store = self.config.trust_store.as_ref().map(::std::sync::Arc::clone);
					#[cfg(feature = "x509")]
					let freshness_window_ms = self.config.command_freshness_window_ms;
					let mux_offer_for_server = self.config.mux_offer.to_owned();

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
						cb_cooldown_ms,
						bp_threshold,
						freshness_window_ms,
						mux_offer_for_server
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
						::std::sync::Arc::clone(&self.cluster_addrs),
						::std::sync::Arc::clone(&self.hive_context),
						self.addr,
						self.config.clone()
					);
					self.scaling_handle = Some(scaling_handle);

					// Start the anti-entropy re-registration beat: gateway
					// registries are soft state, so the hive re-announces its
					// slate to every registered gateway each interval.
					let reregister_handle = hive!(
						@build_reregister_task $protocol,
						::std::sync::Arc::clone(&self.servlets),
						::std::sync::Arc::clone(&self.trace),
						::std::sync::Arc::clone(&self.cluster_addrs),
						self.addr,
						self.config.clone()
					);
					self.reregister_handle = Some(reregister_handle);

					Ok(())
				}

				fn context(&self) -> ::std::sync::Arc<dyn $crate::colony::hive::HiveContext> {
					::std::sync::Arc::clone(&self.hive_context) as ::std::sync::Arc<dyn $crate::colony::hive::HiveContext>
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn servlet_addresses(&self) -> Vec<($crate::utils::urn::Urn<'static>, Vec<u8>)> {
					self.servlets.addresses()
				}

				fn stop(mut self) {
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					if let Some(handle) = self.reregister_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					self.servlets.drain_all().into_iter().for_each(|(_, reg)| reg.servlet.stop_boxed());
				}

				async fn join(mut self) -> Result<(), $crate::TightBeamError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle).await
							.map_err(|_| $crate::TightBeamError::JoinError)?;
					}
					Ok(())
				}

				async fn register_with_cluster(
					&self,
					cluster_addr: <Self::Protocol as $crate::transport::Protocol>::Address,
				) -> Result<$crate::colony::hive::RegisterHiveResponse, $crate::TightBeamError> {
					let response = hive!(
						@register_once $protocol, self.servlets, self.addr, cluster_addr, self.config
					).await?;

					// Remember the gateway only after acceptance. A refused
					// registration must not enqueue the peer: the
					// anti-entropy beat and scaling fan-out would keep
					// calling a gateway that already rejected this hive.
					if response.status == $crate::policy::TransitStatus::Ok {
						if let Ok(mut addrs) = self.cluster_addrs.write() {
							let incoming: Vec<u8> = cluster_addr.clone().into();
							let known = addrs.iter().any(|addr| {
								let bytes: Vec<u8> = addr.clone().into();
								bytes == incoming
							});
							if !known {
								addrs.push(cluster_addr);
							}
						}
					}

					Ok(response)
				}

				async fn drain(&self) -> Result<(), $crate::TightBeamError> {
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
					if let Some(handle) = self.reregister_handle.take() {
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
		$cb_cooldown_ms:ident,
		$bp_threshold:ident,
		$freshness_window_ms:ident,
		$mux_offer:ident
	) => {{
		#[cfg(feature = "x509")]
		let circuit_breaker = ::std::sync::Arc::new(
			$crate::colony::hive::ClusterCircuitBreaker::new($cb_threshold, $cb_cooldown_ms)
		);
		#[cfg(feature = "x509")]
		let replay_guard = ::std::sync::Arc::new(
			$crate::colony::hive::ReplayGuard::new($freshness_window_ms)
		);
		let bp_threshold = $bp_threshold;

		$crate::server! {
			protocol $protocol: $listener,
			policies: { with_mux_offer: [ $mux_offer.to_owned() ] },
			handle: move |frame: $crate::Frame, session: $crate::policy::SessionContext| {
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
				let replay_guard = ::std::sync::Arc::clone(&replay_guard);
				#[cfg(feature = "x509")]
				let trust_store = $trust_store.clone();

				async move {
					hive!(
						@handle_command $protocol,
						frame,
						session,
						servlets,
						trace,
						utilization,
						utilization_map,
						draining_since,
						spawners,
						hive_context,
						circuit_breaker,
						replay_guard,
						trust_store,
						bp_threshold
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
		$session:ident,
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$draining_since:ident,
		$spawners:ident,
		$hive_context:ident,
		$circuit_breaker:ident,
		$replay_guard:ident,
		$trust_store:ident,
		$bp_threshold:ident
	) => {{
		let current_util = || $crate::utils::BasisPoints::new_saturating(
			$utilization.load(::core::sync::atomic::Ordering::Relaxed)
		);
		let active_count = || $servlets.count() as u32;
		let is_draining = $draining_since.read().map(|g| g.is_some()).unwrap_or(false);
		let is_heartbeat = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message)
			.map(|cmd| cmd.heartbeat.is_some())
			.unwrap_or(false);

		// Security gate (x509 feature). Runs before the drain check so
		// unauthenticated peers cannot probe the draining state.
		#[cfg(feature = "x509")]
		{
			let security_status = match &$trust_store {
				Some(store) => {
					let gate = $crate::colony::hive::ClusterSecurityGate::new(
						::std::sync::Arc::clone(&$circuit_breaker),
						::std::sync::Arc::clone(store),
						::std::sync::Arc::clone(&$replay_guard),
					);
					$crate::policy::GatePolicy::evaluate(&gate, ::core::option::Option::Some(&$frame), &$session)
				}
				None => $crate::policy::TransitStatus::PermissionDenied,
			};

			if security_status != $crate::policy::TransitStatus::Ok {
				// Rejects reply in the CHOICE variant the sender decodes:
				// heartbeat commands get a heartbeat-shaped verdict, manage
				// commands a manage-shaped one. A mismatched shape decodes
				// as MalformedResponse on the cluster, counts toward
				// max_failures, and evicts the hive over a transient
				// rejection (e.g. breaker cooldown).
				if is_heartbeat {
					return hive!(@reply_priority $frame, $crate::MessagePriority::NetworkControl,
						$crate::colony::common::ClusterCommandResponse::heartbeat(
							security_status, $crate::utils::BasisPoints::default(), 0
						)
					);
				}

				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_err(security_status)
				));
			}
		}

		// Reject non-heartbeat when draining. Unavailable replies in the
		// manage CHOICE shape: these branches only see manage commands, and
		// a heartbeat-shaped verdict would decode as MalformedResponse on
		// the cluster and evict the hive over a transient rejection.
		if is_draining && !is_heartbeat {
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
				$crate::colony::hive::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Unavailable)
			));
		}

		// Backpressure gate. Authenticated heartbeats are exempted HERE,
		// after the security gate, so health monitoring survives load
		// without giving unauthenticated peers a priority-flag bypass.
		if !is_heartbeat {
			let bp_gate = $crate::colony::hive::BackpressureGate::new(
				::std::sync::Arc::clone(&$utilization),
				$bp_threshold
			);
			if $crate::policy::GatePolicy::evaluate(&bp_gate, ::core::option::Option::Some(&$frame), &$session) == $crate::policy::TransitStatus::ResourceExhausted {
				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_err($crate::policy::TransitStatus::ResourceExhausted)
				));
			}
		}

		if let Ok(cmd) = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message) {
			if cmd.heartbeat.is_some() {
				let util = current_util();
				let status = if util.get() >= $bp_threshold.get() {
					$crate::policy::TransitStatus::ResourceExhausted
				} else {
					$crate::policy::TransitStatus::Ok
				};
				return hive!(@reply_priority $frame, $crate::MessagePriority::NetworkControl,
					$crate::colony::common::ClusterCommandResponse::heartbeat(status, util, active_count())
				);
			}

				if let Some(manage) = cmd.manage {
				return hive!(@handle_manage $frame, manage, $servlets, $trace, $spawners, $hive_context, $replay_guard);
			}
		}

		Ok(None)
	}};

	// ==========================================================================
	// Management Handler
	// ==========================================================================

	(@handle_manage $frame:ident, $request:ident, $servlets:ident, $trace:ident, $spawners:ident, $hive_context:ident, $replay_guard:ident) => {{
		#[cfg(feature = "x509")]
		let forget_replay = || {
			if let Some(signer_info) = $frame.nonrepudiation.as_ref() {
				$replay_guard.forget(signer_info.signature.as_bytes());
			}
		};
		#[cfg(not(feature = "x509"))]
		let forget_replay = || {};

		// Spawn request (keyed by type URN)
		if let Some(spawn) = $request.spawn {
			if let Some(spawner) = $spawners.get(&spawn.servlet_type) {
				let spawned = spawner(::std::sync::Arc::clone(&$trace)).await;
				let keyed = match spawned {
					Ok(new_servlet) => {
						match hive!(@instance_urn spawn.servlet_type, new_servlet.addr_bytes()) {
							Ok(instance) => Ok((new_servlet, instance)),
							Err(err) => {
								new_servlet.stop_boxed();
								Err(err)
							}
						}
					}
					Err(e) => Err(e),
				};

				match keyed {
					Ok((new_servlet, instance)) => {
						let addr_bytes = new_servlet.addr_bytes();
						let key_bytes = $crate::colony::common::canonical_bytes(&instance);
						let type_key = $crate::colony::common::canonical_bytes(&spawn.servlet_type);

						let registration = $crate::colony::hive::ServletRegistration {
							servlet: new_servlet,
							spawner: ::std::sync::Arc::clone(spawner),
							servlet_type: spawn.servlet_type.clone(),
						};

						hive!(@add_to_context $hive_context, key_bytes.clone(), addr_bytes.clone(), &type_key);
						let _ = $servlets.insert(key_bytes, registration);

						return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::hive::HiveManagementResponse::spawn_ok(addr_bytes, instance)
						));
					}
					Err(_) => {
						forget_replay();

						return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::hive::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::PermissionDenied)
						));
					}
				}
			} else {
				forget_replay();

				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::PermissionDenied)
				));
			}
		}

		// List request (identities are instance URNs)
		if $request.list.is_some() {
			let mut list: Vec<$crate::colony::common::ServletInfo> = Vec::new();
			$servlets.for_each(|_key, reg| {
				let address = reg.servlet.addr_bytes();
				if let Ok(servlet_id) = hive!(@instance_urn reg.servlet_type, address.clone()) {
					list.push($crate::colony::common::ServletInfo { servlet_id, address });
				}
			});
			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
				$crate::colony::hive::HiveManagementResponse::list_ok(list)
			));
		}

		// Stop request (instance URN IS the registry key)
		if let Some(stop) = $request.stop {
			let id_bytes = $crate::colony::common::canonical_bytes(&stop.servlet_id);

			if let Some(reg) = $servlets.remove(&id_bytes) {
				let removed_type_urn = reg.servlet_type.clone();
				let removed_type = $crate::colony::common::canonical_bytes(&removed_type_urn);
				let removed_addr = reg.servlet.addr_bytes();
				reg.servlet.stop_boxed();
				hive!(@remove_from_context $hive_context, id_bytes, &removed_type_urn, &removed_type, removed_addr);

				return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
					$crate::colony::hive::HiveManagementResponse::stop_ok()
				));
			}

			forget_replay();

			return hive!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
				$crate::colony::hive::HiveManagementResponse::stop_err($crate::policy::TransitStatus::PermissionDenied)
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
		$cluster_addrs:expr,
		$hive_context:expr,
		$hive_addr:expr,
		$config:expr
	) => {{
		let servlets = $servlets;
		let spawners = $spawners;
		let trace = $trace;
		let utilization = $utilization;
		let utilization_map = $utilization_map;
		let cluster_addrs = $cluster_addrs;
		let hive_context = $hive_context;
		let config = ::std::sync::Arc::new($config);
		// Hive identity URN for scaling updates, minted once from the
		// control address. Locators are Display-formatted so this is
		// always Some; an address that cannot mint an exact identity
		// (non-UTF-8 or empty) disables cluster notification rather
		// than announcing a corrupted one.
		let hive_addr = $hive_addr;
		let hive_urn = {
			let bytes: Vec<u8> = hive_addr.into();
			String::from_utf8(bytes)
				.ok()
				.and_then(|addr| config.namespace.hive(addr).ok())
				.map(::std::sync::Arc::new)
		};

		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			let mut last_scale_up: std::collections::HashMap<Vec<u8>, std::time::Instant> = std::collections::HashMap::new();
			let mut last_scale_down: std::collections::HashMap<Vec<u8>, std::time::Instant> = std::collections::HashMap::new();

			loop {
				hive!(@sleep config.cooldown);

				// Without a mintable hive identity, local add/remove is
				// refused when any gateway is remembered: those peers
				// cannot be notified and would keep stale routes.
				let scale_blocked = hive_urn.is_none() && match cluster_addrs.read() {
					Ok(guard) => !guard.is_empty(),
					Err(_) => true,
				};

				// Scaling decisions are per type, but the shared utilization
				// atomic feeds backpressure and heartbeats for the WHOLE
				// hive, so it is stored once per cycle from the totals below
				// -- never per type, which would leave whichever type
				// iterated last masking every other type's load.
				let mut hive_total_util = 0u64;
				let mut hive_total_count = 0usize;

				for (servlet_type, spawner) in spawners.iter() {
					let type_key = $crate::colony::common::canonical_bytes(servlet_type);
					let type_prefix = $crate::colony::common::type_prefix_bytes(servlet_type);
					let scale_conf = config.servlet_overrides
						.get(servlet_type)
						.copied()
						.unwrap_or(config.default_scale);

					// Collect metrics using mutable captures (FnMut allows this)
					let mut count = 0usize;
					let mut util_sum = 0u64;
					{
						let util_guard = utilization_map.lock();
						servlets.for_each_by_type(&type_prefix, |key, reg| {
							count += 1;
							util_sum += reg.servlet.utilization()
								.map(|bp| bp.get() as u64)
								.or_else(|| util_guard.as_ref().ok().and_then(|g| g.get(key).map(|&v| v as u64)))
								.unwrap_or($crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS as u64);
						});
					}

					hive_total_util += util_sum;
					hive_total_count += count;

					let util_bps = $crate::colony::common::aggregate_utilization(util_sum, count);

					let metrics = $crate::colony::common::ScalingMetrics {
						servlet_type: servlet_type.clone(),
						utilization: util_bps,
						current_instances: count,
						config: scale_conf,
					};

					match $crate::colony::common::ScalingDecision::evaluate(&metrics) {
						$crate::colony::common::ScalingDecision::ScaleUp => {
							if scale_blocked {
								continue;
							}

							// Check cooldown
							if last_scale_up.get(&type_key)
								.is_some_and(|t| t.elapsed() < scale_conf.scale_up_cooldown)
							{
								continue;
							}

							let Ok(new_servlet) = spawner(::std::sync::Arc::clone(&trace)).await else {
								continue;
							};

							let addr_bytes = new_servlet.addr_bytes();
							let Ok(instance) = hive!(@instance_urn servlet_type, addr_bytes.clone()) else {
								new_servlet.stop_boxed();
								continue;
							};
							let key_bytes = $crate::colony::common::canonical_bytes(&instance);

							hive!(@add_to_context hive_context, key_bytes.clone(), addr_bytes.clone(), &type_key);

							let registration = $crate::colony::hive::ServletRegistration {
								servlet: new_servlet,
								spawner: ::std::sync::Arc::clone(spawner),
								servlet_type: servlet_type.clone(),
							};

							// Register before announcing: the notify task's
							// failure-path full-slate reconcile reads the
							// registry, so the new servlet must be visible.
							let _ = servlets.insert(key_bytes, registration);

							if let Some(hive_urn) = hive_urn.as_ref() {
								hive!(@notify_cluster $protocol,
									::std::sync::Arc::clone(&servlets),
									::std::sync::Arc::clone(&cluster_addrs),
									hive_addr,
									::std::sync::Arc::clone(hive_urn),
									$crate::colony::hive::ServletInfo {
										servlet_id: instance,
										address: addr_bytes,
									},
									true,
									::std::sync::Arc::clone(&config),
								);
							}

							last_scale_up.insert(type_key.clone(), std::time::Instant::now());
						}
						$crate::colony::common::ScalingDecision::ScaleDown => {
							if scale_blocked {
								continue;
							}

							// Check cooldown
							if last_scale_down.get(&type_key)
								.is_some_and(|t| t.elapsed() < scale_conf.scale_down_cooldown)
							{
								continue;
							}

						// Remove one instance of this type. Registry iteration
						// order is unspecified (HashMap-backed), so the victim
						// is arbitrary, not the oldest.
						let Some(key) = servlets.keys()
							.into_iter()
							.filter(|k| k.starts_with(&type_prefix))
							.last()
						else {
							continue;
						};

							let Some(reg) = servlets.remove(&key) else {
								continue;
							};

							let addr = reg.servlet.addr_bytes();
							reg.servlet.stop_boxed();
							hive!(@remove_from_context hive_context, key, servlet_type, &type_key, addr.clone());

							let Ok(instance) = hive!(@instance_urn servlet_type, addr.clone()) else {
								continue;
							};
							if let Some(hive_urn) = hive_urn.as_ref() {
								hive!(@notify_cluster $protocol,
									::std::sync::Arc::clone(&servlets),
									::std::sync::Arc::clone(&cluster_addrs),
									hive_addr,
									::std::sync::Arc::clone(hive_urn),
									$crate::colony::hive::ServletInfo {
										servlet_id: instance,
										address: addr,
									},
									false,
									::std::sync::Arc::clone(&config),
								);
							}

							last_scale_down.insert(type_key.clone(), std::time::Instant::now());
						}
						$crate::colony::common::ScalingDecision::Hold => {}
					}
				}

				let aggregate = $crate::colony::common::aggregate_utilization(hive_total_util, hive_total_count);
				utilization.store(aggregate.get(), ::core::sync::atomic::Ordering::Relaxed);
			}
		})
	}};

	// ==========================================================================
	// URN Helpers
	// ==========================================================================

	// Instance URN for a servlet: its type URN with the locator as tail.
	// Locators are Display-formatted addresses, so non-UTF-8 bytes are a
	// caller error surfaced as URN validation failure.
	(@instance_urn $type_urn:expr, $addr_bytes:expr) => {{
		String::from_utf8($addr_bytes)
			.map_err(|_| $crate::TightBeamError::UrnValidationError(
				$crate::utils::urn::UrnValidationError::InvalidFormat {
					field: "resource-id",
					pattern: None,
				}
			))
			.map(|addr| $crate::colony::common::servlet_instance(&$type_urn, addr))
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

	// Remove servlet from context and update type index. $type_urn is
	// the removed registration's type URN.
	(@remove_from_context $ctx:expr, $key:expr, $type_urn:expr, $type_bytes:expr, $removed_addr:expr) => {{
		if let Ok(mut addrs) = $ctx.servlet_addresses.write() {
			addrs.remove(&$key);
		}
		if let Ok(mut type_idx) = $ctx.type_index.write() {
			// Only update if this was the indexed address
			if type_idx.get($type_bytes) == Some(&$removed_addr) {
				let type_prefix = $crate::colony::common::type_prefix_bytes($type_urn);
				if let Ok(addrs) = $ctx.servlet_addresses.read() {
					let replacement = addrs.iter()
						.find(|(k, _)| k.starts_with(&type_prefix))
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
	// Cluster Registration
	// ==========================================================================

	// One signed registration of the hive's current servlet slate to one
	// gateway. Shared by `register_with_cluster` and the re-registration
	// beat: the gateway treats each registration as slate reconciliation.
	(@register_once $protocol:path, $servlets:expr, $hive_addr:expr, $cluster_addr:expr, $config:expr) => {{
		async {
			use $crate::transport::MessageEmitter;

			// Announced identities are instance URNs; non-UTF-8
			// locators cannot occur past register()
			let mut servlet_info_list: Vec<$crate::colony::hive::ServletInfo> = Vec::new();
			$servlets.for_each(|_key, reg| {
				let address = reg.servlet.addr_bytes();
				if let Ok(servlet_id) = hive!(@instance_urn reg.servlet_type, address.clone()) {
					servlet_info_list.push($crate::colony::hive::ServletInfo {
						servlet_id,
						address,
					});
				}
			});

			let request = $crate::colony::common::ClusterRequest::RegisterHive(
				$crate::colony::hive::RegisterHiveRequest {
					issued_at_ms: $crate::colony::common::current_timestamp_ms(),
					hive_addr: $hive_addr.into(),
					servlet_addresses: servlet_info_list,
					metadata: Some(b"hive".to_vec()),
				}
			);

			let stream = <$protocol as $crate::transport::Protocol>::connect($cluster_addr).await?;
			let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

			#[cfg(feature = "x509")]
			{
				use $crate::transport::X509ClientConfig;

				if let Some(ref store) = $config.trust_store {
					let store = ::std::sync::Arc::clone(store);
					transport = transport.with_trust_store(store);
				}

				if let Some(ref hive_tls) = $config.hive_tls {
					let cert = $crate::crypto::x509::Certificate::try_from(hive_tls.certificate.clone())?;
					let key_mgr = $crate::transport::handshake::HandshakeKeyManager::new(
						::std::sync::Arc::clone(&hive_tls.key)
					);
					let cert = ::std::sync::Arc::new(cert);
					let key = ::std::sync::Arc::new(key_mgr);

					transport = transport.with_client_identity(cert, key);
				}
			}

			#[cfg(feature = "x509")]
			let hive_tls_for_frame = $config.hive_tls.as_ref().map(::std::sync::Arc::clone);
			let frame = hive!(@control_frame b"hive-registration", request, hive_tls_for_frame);

			let response_frame = transport.emit(frame, None).await?
				.ok_or($crate::TightBeamError::MissingResponse)?;

			$crate::decode::<$crate::colony::hive::RegisterHiveResponse>(&response_frame.message)
		}
	}};

	// Anti-entropy beat: every interval, re-announce the full slate to
	// every registered gateway. Gateway registries are soft state; this
	// beat is what makes them converge after restarts, evictions, and
	// partitions -- no consensus, no persistence.
	(@build_reregister_task $protocol:path,
		$servlets:expr,
		$trace:expr,
		$cluster_addrs:expr,
		$hive_addr:expr,
		$config:expr
	) => {{
		let servlets = $servlets;
		let trace = $trace;
		let cluster_addrs = $cluster_addrs;
		let hive_addr = $hive_addr;
		let config = $config;

		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			let Some(interval) = config.reregister_interval else { return };

			loop {
				hive!(@sleep interval);

				let gateways: Vec<_> = match cluster_addrs.read() {
					Ok(guard) => guard.clone(),
					Err(_) => return,
				};

				for gateway in gateways {
					let outcome = hive!(
						@register_once $protocol, servlets, hive_addr, gateway, config
					).await;
					let status = outcome
						.map(|response| response.status)
						.unwrap_or($crate::policy::TransitStatus::Unavailable);
					let _ = trace.event_with(
						$crate::instrumentation::events::HIVE_REREGISTERED,
						&[],
						status,
					);
				}
			}
		})
	}};

	// ==========================================================================
	// Cluster Notification
	// ==========================================================================

	(@notify_cluster $protocol:path, $servlets:expr, $cluster_addrs:expr, $hive_addr:expr, $hive_urn:expr, $servlet_info:expr, $is_added:expr, $config:expr $(,)?) => {{
		let servlets = $servlets;
		let cluster_addrs_arc = $cluster_addrs;
		let hive_addr = $hive_addr;
		let hive_id = $hive_urn;
		let servlet_info = $servlet_info;
		let is_added = $is_added;
		let config = $config;

		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			use $crate::transport::policy::CoreRetryPolicy;

			// Scaling updates fan out to every registered gateway so all
			// of them converge on the same slate.
			let gateways: Vec<_> = {
				let Ok(guard) = cluster_addrs_arc.read() else { return };
				guard.clone()
			};
			if gateways.is_empty() {
				return;
			}

			let update = if is_added {
				$crate::colony::common::ClusterRequest::ServletAddressUpdate(
					$crate::colony::hive::ServletAddressUpdate {
						issued_at_ms: $crate::colony::common::current_timestamp_ms(),
						hive_id: (*hive_id).clone(),
						added: vec![servlet_info],
						removed: vec![],
					}
				)
			} else {
				$crate::colony::common::ClusterRequest::ServletAddressUpdate(
					$crate::colony::hive::ServletAddressUpdate {
						issued_at_ms: $crate::colony::common::current_timestamp_ms(),
						hive_id: (*hive_id).clone(),
						added: vec![],
						removed: vec![servlet_info.servlet_id],
					}
				)
			};

			#[cfg(feature = "x509")]
			let hive_tls = config.hive_tls.as_ref().map(::std::sync::Arc::clone);
			#[cfg(feature = "x509")]
			let trust_store = config.trust_store.as_ref().map(::std::sync::Arc::clone);

			let frame_result: Result<$crate::Frame, $crate::TightBeamError> = async {
				Ok(hive!(@control_frame b"scaling-update", update, hive_tls))
			}.await;
			let Ok(frame) = frame_result else { return };

			// The hive identity is converted once. A hive that registered over
			// TLS must not fallback to cleartext for scaling updates (CWE-319).
			#[cfg(feature = "x509")]
			let client_identity = match hive_tls.as_ref() {
				Some(hive_tls) => {
					let Ok(cert) = $crate::crypto::x509::Certificate::try_from(hive_tls.certificate.clone()) else {
						return;
					};
					let key_mgr = $crate::transport::handshake::HandshakeKeyManager::new(
						::std::sync::Arc::clone(&hive_tls.key)
					);
					let cert = ::std::sync::Arc::new(cert);
					let key = ::std::sync::Arc::new(key_mgr);

					Some((cert, key))
				}
				None => None,
			};

			let retry_policy = ::std::sync::Arc::clone(&config.cluster_notify_retry);
			let max_attempts = retry_policy.max_attempts();
			let mut any_failed = false;
			for gateway in gateways.iter().copied() {
				let mut accepted = false;
				for attempt in 0..=max_attempts {
					let stream = match <$protocol as $crate::transport::Protocol>::connect(gateway).await {
						Ok(s) => s,
						Err(_) => {
							hive!(@retry_delay attempt, max_attempts, retry_policy);
							continue;
						}
					};

					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

					#[cfg(feature = "x509")]
					{
						use $crate::transport::X509ClientConfig;

						if let Some(ref store) = trust_store {
							let store = ::std::sync::Arc::clone(store);
							transport = transport.with_trust_store(store);
						}

						if let Some((ref cert, ref key_mgr)) = client_identity {
							let cert = ::std::sync::Arc::clone(cert);
							let key = ::std::sync::Arc::clone(key_mgr);
							transport = transport.with_client_identity(cert, key);
						}
					}

					use $crate::transport::MessageEmitter;
					// Transport Ok is not acceptance: decode the body and
					// require TransitStatus::Ok (same rule as registration).
					// Clone is not in the hot path here
					match transport.emit(frame.clone(), None).await {
						Ok(Some(response)) => {
							match $crate::decode::<$crate::colony::hive::ServletAddressUpdateResponse>(
								&response.message,
							) {
								Ok(body) if body.status == $crate::policy::TransitStatus::Ok => {
									accepted = true;
									break;
								}
								_ => {
									hive!(@retry_delay attempt, max_attempts, retry_policy);
								}
							}
						}
						Ok(None) | Err(_) => {
							hive!(@retry_delay attempt, max_attempts, retry_policy);
						}
					}
				}
				if !accepted {
					any_failed = true;
				}
			}

			// Soft-state reconcile: any gateway that exhausted retries leaves
			// the fleet divergent until the next beat. Push the full slate
			// to every remembered peer immediately.
			if any_failed {
				for gateway in gateways {
					let _ = hive!(
						@register_once $protocol, servlets, hive_addr, gateway, config
					).await;
				}
			}
		});
	}};

	// Retry delay helper
	(@retry_delay $attempt:ident, $max:ident, $policy:ident) => {{
		if $attempt < $max {
			hive!(@sleep ::std::time::Duration::from_millis($policy.delay_ms($attempt)));
		}
	}};

	// Sleep helper (colony requires tokio)
	(@sleep $duration:expr) => {{
		tokio::time::sleep($duration).await;
	}};

	// ==========================================================================
	// Frame Helpers
	// ==========================================================================

	// Hive -> cluster control-plane frame (registration, scaling updates).
	// Signed with the hive identity when hive_tls is configured: clusters
	// enforcing hive trust reject unsigned registrations/updates.
	(@control_frame $id:expr, $message:expr, $hive_tls:ident) => {{
		use $crate::builder::TypeBuilder;

		#[cfg(feature = "x509")]
		let frame = match $hive_tls.as_ref() {
			Some(hive_tls) => {
				let unsigned = $crate::utils::compose($crate::Version::V0)
					.with_id($id)
					.with_order(0)
					.with_message($message)
					.build()?;
				unsigned
					.sign_with_provider::<$crate::crypto::hash::Sha3_256, _>(hive_tls.key.as_ref())
					.await?
			}
			None => $crate::utils::compose($crate::Version::V0)
				.with_id($id)
				.with_order(0)
				.with_message($message)
				.build()?,
		};

		#[cfg(not(feature = "x509"))]
		let frame = $crate::utils::compose($crate::Version::V0)
			.with_id($id)
			.with_order(0)
			.with_message($message)
			.build()?;

		frame
	}};

	(@reply $frame:ident, $message:expr) => {
		$crate::colony::common::reply_frame($frame.metadata.id.clone(), $message)
	};

	(@reply_priority $frame:ident, $priority:expr, $message:expr) => {
		$crate::colony::common::reply_frame_with_priority($frame.metadata.id.clone(), $priority, $message)
	};
}
