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
				let (listener, addr) = <$protocol>::bind(bind_addr).await?;

				// Create registry with timeout from config
				let registry = ::std::sync::Arc::new(
					$crate::colony::cluster::HiveRegistry::new(config.heartbeat.timeout)
				);
				let registry_for_server = ::std::sync::Arc::clone(&registry);
				let trace_for_server = ::std::sync::Arc::clone(&trace);

				// Start the gateway server
				let server_handle = $crate::cluster!(
					@build_gateway_server $protocol,
					listener,
					registry_for_server,
					trace_for_server
				);

				// Start the heartbeat loop
				let heartbeat_handle = {
					let registry = ::std::sync::Arc::clone(&registry);
					let config = ::std::sync::Arc::clone(&config);
					let trace = ::std::sync::Arc::clone(&trace);
					$crate::colony::servlet::servlet_runtime::rt::spawn(
						$crate::colony::cluster::run_heartbeat_loop(registry, config, trace)
					)
				};

				Ok(Self {
					registry,
					config,
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
		// Try to decode as RegisterDroneRequest (hive registration)
		if let Ok(request) = $crate::decode::<$crate::colony::drone::RegisterDroneRequest>(&$frame.message) {
			let status = match $registry.register(request.clone()) {
				Ok(()) => $crate::policy::TransitStatus::Accepted,
				Err(_) => $crate::policy::TransitStatus::Forbidden,
			};

			let response = $crate::colony::drone::RegisterDroneResponse {
				status,
				drone_id: Some(request.drone_addr.clone()),
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
}

