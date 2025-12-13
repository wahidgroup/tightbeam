/// Macro for creating drones with pre-registered servlets
#[macro_export]
macro_rules! drone {
	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol, [hive],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[hive],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[$($policy_key: $policy_val),+],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[hive],
			[],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[hive],
			[],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[],
			$($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]
		);
	};

	// Implement hive struct without attributes and visibility
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(
			@generate_with_attrs $drone_name,
			$protocol,
			[],
			[],
			$($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]
		);
	};

	// Generate with attributes and visibility
	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[hive],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]
	) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
		drone!(@impl_servlet_trait_for_hive $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait_for_hive $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_hive_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop_for_hive $drone_name);
	};

	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[hive],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]
	) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
		drone!(@impl_servlet_trait_for_hive $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait_for_hive $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_hive_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop_for_hive $drone_name);
	};

	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]
	) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_struct_with_attrs $drone_name, $protocol, pub, [$(#[$meta])*]);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop $drone_name);
	};

	(
		@generate_with_attrs $drone_name:ident,
		$protocol:path,
		[],
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]
	) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_struct_with_attrs $drone_name, $protocol, , [$(#[$meta])*]);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop $drone_name);
	};

	// Start servlet
	(
		@start_servlet $servlet_name:ident<$input:ty>,
		$instance:ident,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr
	) => {
		paste::paste! {
			let servlet = <$servlet_name as $crate::colony::servlet::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$instance.trace), None,
			).await.map_err(|_| $crate::colony::drone::DroneError::InvalidServletId($error_id))?;

			let mut active = $instance.active_servlet.lock()?;
			*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);
			return Ok($crate::policy::TransitStatus::Accepted);
		}
	};

	// Start servlet with response (for control server)
	(
		@start_servlet_with_response $servlet_name:ident<$input:ty>,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr,
		$active_servlet:ident,
		$trace:ident,
		$stop_old:ident,
		$frame:ident
	) => {
		paste::paste! {
			// Stop old servlet if any
			let old_servlet = {
				let mut active = $active_servlet.lock()?;
				core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None)
			};

			$stop_old(old_servlet);

			// Start new servlet
			match <$servlet_name as $crate::colony::servlet::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$trace), None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();
					let mut active = $active_servlet.lock()?;
					*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);
					drop(active);
					return drone!(@reply $frame, $crate::colony::drone::ActivateServletResponse::ok(addr_bytes));
				}
				Err(_) => {
					return drone!(@reply $frame,
						$crate::colony::drone::ActivateServletResponse::err($crate::policy::TransitStatus::Forbidden)
					);
				}
			}
		}
	};

	// Generate the enum for holding different servlet types
	(@impl_enum $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			// Generate an enum to hold any of the possible servlet types
			enum [<$drone_name ActiveServlet>] {
				None,
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}

			impl Default for [<$drone_name ActiveServlet>] {
				fn default() -> Self {
					Self::None
				}
			}
		}
	};

	// Generate the drone struct
	(@impl_struct $drone_name:ident, $protocol:path) => {
		drone!(@impl_struct_with_attrs $drone_name, $protocol, pub, []);
	};

	// Generate the drone struct with attributes and visibility
	(@impl_struct_with_attrs $drone_name:ident, $protocol:path, pub, [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			pub struct $drone_name {
				active_servlet: ::std::sync::Arc<::std::sync::Mutex<[<$drone_name ActiveServlet>]>>,
				control_server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
			}
		}
	};
	(@impl_struct_with_attrs $drone_name:ident, $protocol:path, , [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			struct $drone_name {
				active_servlet: ::std::sync::Arc<::std::sync::Mutex<[<$drone_name ActiveServlet>]>>,
				control_server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
			}
		}
	};

	// Implement Servlet trait
	(
		@impl_servlet_trait $drone_name:ident,
		$protocol:path,
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			impl $crate::colony::servlet::Servlet<()> for $drone_name {
				type Conf = ();
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(
					trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
					_config: Option<Self::Conf>
				) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

					// Create shared state for the active servlet
					let active_servlet = ::std::sync::Arc::new(::std::sync::Mutex::new([<$drone_name ActiveServlet>]::None));
					let active_servlet_clone = ::std::sync::Arc::clone(&active_servlet);

					// Clone trace for control server
					let trace_clone = ::std::sync::Arc::clone(&trace);

					// Start the control server that listens for ActivateServletRequest messages
					let control_server_handle = drone!(
						@build_control_server $protocol,
						listener,
						[$($policy_key: $policy_val),*],
						active_servlet_clone,
						trace_clone,
						$drone_name,
						$($servlet_id: $servlet_name<$input>),*
					);

					Ok(Self {
						active_servlet,
						control_server_handle: Some(control_server_handle),
						addr,
						trace,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(mut self) {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					// Stop any active servlet
					if let Ok(mut active) = self.active_servlet.lock() {
						let servlet = ::core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None);
						drop(active);
						match servlet {
							[<$drone_name ActiveServlet>]::None => {},
							$(
								[<$drone_name ActiveServlet>]::[<$servlet_id:camel>](s) => {
									s.stop();
								}
							)*
						}
					}
				}

				#[cfg(feature = "tokio")]
				async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle).await
					} else {
						Ok(())
					}
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
			}
		}
	};

	// Start servlet for hive establishment (no response needed)
	(
		@start_servlet_for_hive_establish_impl $protocol:path,
		$servlet_name:ident<$input:ty>,
		$instance:ident,
		$drone_name:ident,
		$servlet_id:ident
	) => {
		paste::paste! {
			// Build servlet config (with TLS if configured)
			#[cfg(feature = "x509")]
			let servlet_conf = if let Some(ref tls) = $instance.config.hive_tls {
				use $crate::colony::servlet::ServletConf;
				ServletConf::<$protocol, $input>::builder()
					.with_certificate(tls.certificate.clone(), tls.key.clone(), tls.validators.clone())
					.ok()
					.map(|builder| builder.with_config(::std::sync::Arc::new(())).build())
			} else {
				None
			};
			#[cfg(not(feature = "x509"))]
			let servlet_conf: Option<<$servlet_name as $crate::colony::servlet::Servlet<$input>>::Conf> = None;

			match <$servlet_name as $crate::colony::servlet::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$instance.trace),
				servlet_conf,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();

					// Pre-allocate with exact capacity
					let type_prefix = stringify!($servlet_id).as_bytes();
					let mut servlet_id = Vec::with_capacity(type_prefix.len() + 1 + addr_bytes.len());

					servlet_id.extend_from_slice(type_prefix);
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_bytes);

					// Initialize utilization_map entry for this instance
					if let Ok(mut util_map) = $instance.utilization_map.lock() {
						util_map.insert(servlet_id.clone(), 0);
					}

					if let Ok(mut servlets) = $instance.servlets.lock() {
						servlets.insert(servlet_id, [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));
					}
				}
				Err(_e) => {
					// Servlet start failed - continue with other servlets
					#[cfg(feature = "std")]
					eprintln!("Warning: Failed to start servlet {}: {:?}", stringify!($servlet_id), _e);
				}
			}
		}
	};

	// Start servlet for hive (with response) - legacy version
	(
		@start_servlet_for_hive $servlet_name:ident<$input:ty>,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr,
		$servlets:ident,
		$trace:ident,
		$frame:ident
	) => {
		paste::paste! {
			match <$servlet_name as $crate::colony::servlet::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$trace),
				None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();

					// Pre-allocate with exact capacity
					let type_prefix = stringify!($servlet_id).as_bytes();
					let mut servlet_id = Vec::with_capacity(type_prefix.len() + 1 + addr_bytes.len());

					servlet_id.extend_from_slice(type_prefix);
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_bytes);

					let mut servlets = $servlets.lock()?;
					servlets.insert(servlet_id.clone(), [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));

					drop(servlets);

					return drone!(@reply $frame,
						$crate::colony::drone::HiveManagementResponse::spawn_ok(addr_bytes, servlet_id)
					);
				}
				Err(_) => {
					return drone!(@reply $frame,
						$crate::colony::drone::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
					);
				}
			}
		}
	};

	// Start servlet for hive (with ClusterCommandResponse wrapper)
	(
		@start_servlet_for_hive_cmd $servlet_name:ident<$input:ty>,
		$drone_name:ident,
		$servlet_id:ident,
		$servlet_id_str:expr,
		$error_id:expr,
		$servlets:ident,
		$trace:ident,
		$frame:ident
	) => {
		paste::paste! {
			match <$servlet_name as $crate::colony::servlet::Servlet<$input>>::start(
				::std::sync::Arc::clone(&$trace),
				None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_bytes: Vec<u8> = servlet_addr.into();
					let type_prefix = stringify!($servlet_id).as_bytes();
					let mut servlet_id = Vec::with_capacity(type_prefix.len() + 1 + addr_bytes.len());

					servlet_id.extend_from_slice(type_prefix);
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_bytes);

					let mut servlets = $servlets.lock()?;
					servlets.insert(servlet_id.clone(), [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));

					drop(servlets);

					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
						$crate::colony::drone::HiveManagementResponse::spawn_ok(addr_bytes, servlet_id)
					));
				}
				Err(_) => {
					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
						$crate::colony::drone::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
					));
				}
			}
		}
	};

	// Implement Drone trait
	(@impl_drone_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::drone::Drone<()> for $drone_name {
				type Protocol = $protocol;

				fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
					::std::sync::Arc::clone(&self.trace)
				}

				async fn morph(
					&mut self,
					msg: $crate::colony::drone::ActivateServletRequest,
				) -> Result<$crate::policy::TransitStatus, $crate::colony::drone::DroneError> {
					// Deactivate current servlet if any
					if self.is_active() {
						self.deactivate().await?;
					}

					// Match servlet_id and activate the corresponding servlet
					$(
						if msg.servlet_id == stringify!($servlet_id).as_bytes() {
							drone!(
								@start_servlet $servlet_name<$input>,
								self,
								$drone_name,
								$servlet_id,
								stringify!($servlet_id),
								msg.servlet_id.clone()
							);
						}
					)*

					// Unknown servlet ID
					Err($crate::colony::drone::DroneError::InvalidServletId(msg.servlet_id))
				}

				fn is_active(&self) -> bool {
					self.active_servlet.lock()
						.map(|active| !matches!(*active, [<$drone_name ActiveServlet>]::None))
						.unwrap_or(false)
				}

				async fn deactivate(&mut self) -> Result<(), $crate::colony::drone::DroneError> {
					// Take the active servlet and stop it
					let mut active = self.active_servlet.lock()?;
					let servlet = core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None);

					drop(active);

					match servlet {
						[<$drone_name ActiveServlet>]::None => {},
						$(
							[<$drone_name ActiveServlet>]::[<$servlet_id:camel>](s) => {
								s.stop();
							}
						)*
					}

					Ok(())
				}

				async fn register_with_cluster(
					&self,
					cluster_addr: <$protocol as $crate::transport::Protocol>::Address,
				) -> Result<$crate::colony::drone::RegisterDroneResponse, $crate::colony::drone::DroneError> {
					use $crate::transport::MessageEmitter;

					// Get this drone's address
					let drone_addr = self.addr();
					// Convert address to bytes
					let drone_addr_bytes: Vec<u8> = drone_addr.into();

					// Build list of available servlet IDs
					let available_servlets = vec![
						$(
							stringify!($servlet_id).as_bytes().to_vec(),
						)*
					];

					// Create registration request
					let request = $crate::colony::drone::RegisterDroneRequest {
						drone_addr: drone_addr_bytes,
						available_servlets,
						metadata: None,
					};

					// Connect to cluster and send registration
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await?;
					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
					let frame = {
						use $crate::builder::TypeBuilder;
						$crate::utils::compose($crate::Version::V0)
							.with_id(b"drone-registration")
							.with_order(0)
							.with_message(request)
							.build()?
					};

					// Send and wait for response
					let response_frame = transport.emit(frame, None).await
						.map_err(|_| $crate::colony::drone::DroneError::EmitFailed)?
						.ok_or_else(|| $crate::colony::drone::DroneError::NoResponse)?;

					// Decode response
					let response = $crate::decode::<$crate::colony::drone::RegisterDroneResponse>(&response_frame.message)
						.map_err(|_| $crate::colony::drone::DroneError::DecodeFailed)?;

					Ok(response)
				}
			}
		}
	};

	// Generate hive struct (stores multiple servlet instances)
	(@impl_hive_struct $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, pub, []);
	};

	// Generate hive struct with attributes and visibility
	(
		@impl_hive_struct_with_attrs $drone_name:ident,
		$protocol:path,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]
	) => {
		paste::paste! {
			$(#[$meta])*
			pub struct $drone_name {
				servlets: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, [<$drone_name Servlet>]>>>,
				config: $crate::colony::drone::HiveConf,
				control_server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				scaling_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				utilization: ::std::sync::Arc<::core::sync::atomic::AtomicU16>,
				utilization_map: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, u16>>>,
				#[allow(dead_code)]
				servlet_pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
				/// Draining state: None = running, Some(Instant) = draining since
				draining_since: ::std::sync::Arc<::std::sync::RwLock<Option<::std::time::Instant>>>,
			}

			enum [<$drone_name Servlet>] {
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}
		}
	};

	// Implement hive struct with attributes and visibility
	(
		@impl_hive_struct_with_attrs $drone_name:ident,
		$protocol:path,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]
	) => {
		paste::paste! {
			$(#[$meta])*
			struct $drone_name {
				servlets: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, [<$drone_name Servlet>]>>>,
				config: $crate::colony::drone::HiveConf,
				control_server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				scaling_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				utilization: ::std::sync::Arc<::core::sync::atomic::AtomicU16>,
				utilization_map: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, u16>>>,
				#[allow(dead_code)]
				servlet_pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
				/// Draining state: None = running, Some(Instant) = draining since
				draining_since: ::std::sync::Arc<::std::sync::RwLock<Option<::std::time::Instant>>>,
			}

			enum [<$drone_name Servlet>] {
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}
		}
	};

	// Implement Servlet trait for hive
	(
		@impl_servlet_trait_for_hive $drone_name:ident,
		$protocol:path,
		[$($policy_key:ident: $policy_val:tt),*],
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			impl $crate::colony::servlet::Servlet<()> for $drone_name {
				type Conf = $crate::colony::drone::HiveConf;
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(
					trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
					config: Option<Self::Conf>
				) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

					// Use provided config or default
					let config = config.unwrap_or_default();

					// Create shared state for servlets
					let servlets = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::HashMap::new()));
					let servlets_clone = ::std::sync::Arc::clone(&servlets);
					let trace_clone = ::std::sync::Arc::clone(&trace);

					// Create utilization atomic for backpressure
					let utilization = ::std::sync::Arc::new(::core::sync::atomic::AtomicU16::new(0));
					let utilization_for_server = ::std::sync::Arc::clone(&utilization);

					// Create per-instance utilization map for load balancing
					let utilization_map = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::HashMap::new()));
					let utilization_map_for_server = ::std::sync::Arc::clone(&utilization_map);

					// Circuit breaker and security settings from config
					let cb_threshold = config.circuit_breaker_threshold;
					let cb_cooldown_ms = config.circuit_breaker_cooldown_ms;
					let trusted_keys = config.trusted_cluster_keys.clone();

					// Create connection pool for servlet forwarding
					let pool_config = $crate::transport::client::pool::PoolConfig {
						idle_timeout: config.servlet_pool_idle_timeout,
						max_connections: config.servlet_pool_size,
					};
					let servlet_pool = {
						use $crate::transport::client::pool::ConnectionBuilder;
						::std::sync::Arc::new(
							$crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
								.with_config(pool_config)
								.build()
						)
					};
					let servlet_pool_for_server = ::std::sync::Arc::clone(&servlet_pool);

					// Create draining state for graceful shutdown
					let draining_since = ::std::sync::Arc::new(::std::sync::RwLock::new(None));
					let draining_since_for_server = ::std::sync::Arc::clone(&draining_since);

					// Start the control server that listens for management commands
					let control_server_handle = drone!(
						@build_hive_control_server $protocol,
						listener,
						[$($policy_key: $policy_val),*],
						servlets_clone,
						trace_clone,
						utilization_for_server,
						utilization_map_for_server,
						cb_threshold,
						cb_cooldown_ms,
						trusted_keys,
						servlet_pool_for_server,
						draining_since_for_server,
						$drone_name,
						$($servlet_id: $servlet_name<$input>),*
					);

					Ok(Self {
						servlets,
						config,
						control_server_handle: Some(control_server_handle),
						scaling_handle: None,
						addr,
						trace,
						utilization,
						utilization_map,
						servlet_pool,
						draining_since,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(mut self) {
					// Stop the scaling task
					if let Some(handle) = self.scaling_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					// Stop the control server
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
					}
					// Stop all servlets
					if let Ok(mut servlets) = self.servlets.lock() {
						for (_name, servlet) in servlets.drain() {
							match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => {
										s.stop();
									}
								)*
							}
						}
					}
				}

				#[cfg(feature = "tokio")]
				async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle).await
					} else {
						Ok(())
					}
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet::servlet_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
			}
		}
	};

	// Implement Drone trait for hive (minimal implementation)
	(
		@impl_drone_trait_for_hive $drone_name:ident,
		$protocol:path,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			impl $crate::colony::drone::Drone<()> for $drone_name {
				type Protocol = $protocol;

				fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
					::std::sync::Arc::clone(&self.trace)
				}

				async fn morph(
					&mut self,
					_msg: $crate::colony::drone::ActivateServletRequest,
				) -> Result<$crate::policy::TransitStatus, $crate::colony::drone::DroneError> {
					// Hives don't morph - they manage multiple servlets
					Err($crate::colony::drone::DroneError::InvalidServletId(b"hive_does_not_morph".to_vec()))
				}

				fn is_active(&self) -> bool {
					self.servlets.lock()
						.map(|servlets| !servlets.is_empty())
						.unwrap_or(false)
				}

				async fn deactivate(&mut self) -> Result<(), $crate::colony::drone::DroneError> {
					// Stop all servlets
					let mut servlets = self.servlets.lock()?;
					for (_name, servlet) in servlets.drain() {
						match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => {
									s.stop();
								}
							)*
						}
					}

					Ok(())
				}

				async fn register_with_cluster(
					&self,
					cluster_addr: <$protocol as $crate::transport::Protocol>::Address,
				) -> Result<$crate::colony::drone::RegisterDroneResponse, $crate::colony::drone::DroneError> {
					use $crate::transport::MessageEmitter;

					// Get this hive's address
					let drone_addr = self.addr();
					let drone_addr_bytes: Vec<u8> = drone_addr.into();

					// Build list of available servlet IDs
					let available_servlets = vec![
						$(
							stringify!($servlet_id).as_bytes().to_vec(),
						)*
					];

					// Create registration request
					let request = $crate::colony::drone::RegisterDroneRequest {
						drone_addr: drone_addr_bytes,
						available_servlets,
						metadata: Some(b"hive".to_vec()),
					};

					// Connect to cluster and send registration
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await?;
					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);
					let frame = {
						use $crate::builder::TypeBuilder;
						$crate::utils::compose($crate::Version::V0)
							.with_id(b"hive-registration")
							.with_order(0)
							.with_message(request)
							.build()?
					};

					// Send and wait for response
					let response_frame = transport.emit(frame, None).await?
						.ok_or($crate::colony::drone::DroneError::NoResponse)?;

					// Decode response
					Ok($crate::decode::<$crate::colony::drone::RegisterDroneResponse>(&response_frame.message)?)
				}
			}
		}
	};

	// Implement Hive trait for mycelial async protocols
	(@impl_hive_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::drone::Hive<()> for $drone_name
			where
				$protocol: $crate::transport::Mycelial + $crate::transport::AsyncListenerTrait,
			{
				async fn establish_hive(&mut self) -> Result<(), $crate::colony::drone::DroneError> {
					// Start min_instances of each servlet type
					// Each servlet will call Protocol::bind() with default_bind_address()
					// which returns "0.0.0.0:0" (or equivalent), causing the OS to allocate
					// a unique port for each servlet. This is the mycelial networking model.
					$(
						{
							let min_instances = self.config.servlet_overrides
								.get(stringify!($servlet_id).as_bytes())
								.map(|c| c.min_instances)
								.unwrap_or(self.config.default_scale.min_instances);

							for _ in 0..min_instances {
								drone!(
									@start_servlet_for_hive_establish_impl $protocol,
									$servlet_name<$input>,
									self,
									$drone_name,
									$servlet_id
								);
							}
						}
					)*

					// Spawn the auto-scaling background task
					let servlets = ::std::sync::Arc::clone(&self.servlets);
					let config = self.config.clone();
					let trace = ::std::sync::Arc::clone(&self.trace);
					let utilization_for_scaling = ::std::sync::Arc::clone(&self.utilization);
					let utilization_map_for_scaling = ::std::sync::Arc::clone(&self.utilization_map);

					// Define helper closure to stop any servlet variant (avoids nested macro repetition)
					let stop_servlet = |servlet: [<$drone_name Servlet>]| {
						match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
							)*
						}
					};

					// Define servlet type names for iteration
					let servlet_types: Vec<&'static [u8]> = vec![
						$(stringify!($servlet_id).as_bytes(),)*
					];

					// Type alias for spawn function closures
					type SpawnFn = ::std::sync::Arc<
						dyn Fn() -> ::core::pin::Pin<::std::boxed::Box<dyn ::core::future::Future<Output = ()> + Send>>
						+ Send + Sync
					>;

					// Build spawn function map - each closure captures its own Arc clones
					let spawn_fns: ::std::collections::HashMap<&'static [u8], SpawnFn> = {
						let mut map: ::std::collections::HashMap<&'static [u8], SpawnFn> = ::std::collections::HashMap::new();
						let util_map_for_spawn = ::std::sync::Arc::clone(&self.utilization_map);

						$(
							{
								let trace_for_spawn = ::std::sync::Arc::clone(&trace);
								let servlets_for_spawn = ::std::sync::Arc::clone(&servlets);
								let util_map_inner = ::std::sync::Arc::clone(&util_map_for_spawn);
								map.insert(
									stringify!($servlet_id).as_bytes(),
									::std::sync::Arc::new(move || -> ::core::pin::Pin<::std::boxed::Box<dyn ::core::future::Future<Output = ()> + Send>> {
										let trace_inner = ::std::sync::Arc::clone(&trace_for_spawn);
										let servlets_inner = ::std::sync::Arc::clone(&servlets_for_spawn);
										let util_map_spawn = ::std::sync::Arc::clone(&util_map_inner);
										::std::boxed::Box::pin(async move {
											if let Ok(servlet) = <$servlet_name as $crate::colony::servlet::Servlet<$input>>::start(
												trace_inner,
												None,
											).await {
												let servlet_addr = servlet.addr();
												let addr_str: Vec<u8> = servlet_addr.into();
												let mut key: Vec<u8> = Vec::new();

												key.extend_from_slice(stringify!($servlet_id).as_bytes());
												key.push(b'_');
												key.extend_from_slice(&addr_str);

												// Initialize utilization_map entry for new servlet
												if let Ok(mut util_guard) = util_map_spawn.lock() {
													util_guard.insert(key.clone(), 0);
												}

												if let Ok(mut guard) = servlets_inner.lock() {
													guard.insert(key, [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));
												}
											}
										})
									})
								);
							}
						)*
						map
					};

					let scaling_handle = $crate::colony::servlet::servlet_runtime::rt::spawn(async move {
						loop {
							// Sleep for cooldown period
							#[cfg(feature = "tokio")]
							tokio::time::sleep(config.cooldown).await;
							#[cfg(all(not(feature = "tokio"), feature = "std"))]
							std::thread::sleep(config.cooldown);

							// Evaluate scaling for each servlet type
							for servlet_type in &servlet_types {
								let scale_conf = config.servlet_overrides
									.get(*servlet_type)
									.cloned()
									.unwrap_or_else(|| config.default_scale.clone());

								// Count instances and collect utilization from each servlet
								let (current_instances, type_utilization_sum) = {
									let servlets_guard = match servlets.lock() {
										Ok(g) => g,
										Err(_) => continue,
									};

									let mut count = 0usize;
									let mut util_sum = 0u32;

									for (key, servlet) in servlets_guard.iter() {
										if !key.starts_with(*servlet_type) {
											continue;
										}
										count += 1;

										// Get utilization from servlet (if it reports one)
										let util_bps: u16 = match servlet {
											$(
												[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => {
													s.utilization()
														.map(|bp| bp.get())
														.unwrap_or(5000) // Default 50% if not reported
												}
											)*
										};

										util_sum += util_bps as u32;

										// Update per-instance utilization map
										if let Ok(mut util_map) = utilization_map_for_scaling.lock() {
											util_map.insert(key.clone(), util_bps);
										}
									}

									(count, util_sum)
								};

								// Calculate average utilization for this servlet type
								let utilization_bps = if current_instances == 0 {
									$crate::utils::BasisPoints::MAX
								} else {
									let avg = (type_utilization_sum / current_instances as u32) as u16;
									$crate::utils::BasisPoints::new_saturating(avg)
								};

								// Update the shared aggregate utilization atomic for backpressure signaling
								utilization_for_scaling.store(
									utilization_bps.get(),
									::core::sync::atomic::Ordering::Relaxed
								);

								let metrics = $crate::colony::common::ScalingMetrics {
									servlet_type: servlet_type.to_vec(),
									utilization: utilization_bps,
									current_instances,
									config: scale_conf,
								};

								let decision = $crate::colony::common::ScalingDecision::evaluate(&metrics);
								match decision {
									$crate::colony::common::ScalingDecision::ScaleUp => {
										// Look up and call the spawn function for this servlet type
										if let Some(spawn_fn) = spawn_fns.get(*servlet_type) {
											spawn_fn().await;
										}
									}
									$crate::colony::common::ScalingDecision::ScaleDown => {
										// Stop the most recently added servlet of this type
										if let Ok(mut guard) = servlets.lock() {
											let key_to_remove: Option<Vec<u8>> = guard.keys()
												.filter(|k| k.starts_with(*servlet_type))
												.last()
												.cloned();
											if let Some(key) = key_to_remove {
												if let Some(servlet) = guard.remove(&key) {
													// Remove from utilization_map
													if let Ok(mut util_guard) = utilization_map_for_scaling.lock() {
														util_guard.remove(&key);
													}
													stop_servlet(servlet);
												}
											}
										}
									}

									$crate::colony::common::ScalingDecision::Hold => {}
								}
							}
						}
					});

					self.scaling_handle = Some(scaling_handle);
					Ok(())
				}

				async fn servlet_addresses(&self) -> Vec<(Vec<u8>, <$protocol as $crate::transport::Protocol>::Address)> {
					self.servlets.lock()
						.map(|servlets| {
							// Collect addresses of all active servlets
							let mut addresses = Vec::new();
							for (name, servlet) in servlets.iter() {
								let addr = match servlet {
									$(
										[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
									)*
								};

								addresses.push((name.clone(), addr));
							}

							addresses
						})
						.unwrap_or_else(|_| Vec::new())
				}

				async fn drain(&self) -> Result<(), $crate::colony::drone::DroneError> {
					// Set draining state
					{
						let mut guard = self.draining_since.write()?;
						*guard = Some(::std::time::Instant::now());
					}

					let drain_timeout = self.config.drain_timeout;
					let start = ::std::time::Instant::now();

					// Poll until all servlets stopped or timeout
					loop {
						let active_count = self.servlets.lock()
							.map(|s| s.len())
							.unwrap_or(0);

						if active_count == 0 {
							break;
						}

						if start.elapsed() >= drain_timeout {
							// Force stop remaining servlets
							if let Ok(mut guard) = self.servlets.lock() {
								let keys: Vec<_> = guard.keys().cloned().collect();
								for key in keys {
									if let Some(servlet) = guard.remove(&key) {
										match servlet {
											$(
												[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
											)*
										}
									}
								}
							}
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
		}
	};

	// Implement Drop for hive
	(@impl_drop_for_hive $drone_name:ident) => {
		impl Drop for $drone_name {
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
	};

	// Implement Drop trait
	(@impl_drop $drone_name:ident) => {
		impl Drop for $drone_name {
			fn drop(&mut self) {
				if let Some(handle) = self.control_server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
			}
		}
	};

	// Helper to build control server with policies
	(
		@build_control_server $protocol:path,
		$listener:ident,
		[$($policy_key:ident: $policy_val:tt),+],
		$active_servlet:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let active_servlet = std::sync::Arc::clone(&$active_servlet);
					let trace = ::std::sync::Arc::clone(&$trace);
					async move {
						drone!(
							@handle_activation_request frame,
							active_servlet,
							trace,
							$drone_name, $($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	};

	// Helper to build control server without policies
	(
		@build_control_server $protocol:path,
		$listener:ident,
		[],
		$active_servlet:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let active_servlet = ::std::sync::Arc::clone(&$active_servlet);
					let trace = ::std::sync::Arc::clone(&$trace);
					async move {
						drone!(
							@handle_activation_request frame,
							$active_servlet,
							trace,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	};

	// Helper to build hive control server with policies
	(
		@build_hive_control_server $protocol:path,
		$listener:ident,
		[$($policy_key:ident: $policy_val:tt),+],
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$cb_threshold:ident,
		$cb_cooldown_ms:ident,
		$trusted_keys:ident,
		$servlet_pool:ident,
		$draining_since:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {{
		let circuit_breaker = ::std::sync::Arc::new(
			$crate::colony::drone::ClusterCircuitBreaker::new($cb_threshold, $cb_cooldown_ms)
		);
		let trusted_keys = ::std::sync::Arc::new($trusted_keys);

		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let servlets = ::std::sync::Arc::clone(&$servlets);
					let trace = ::std::sync::Arc::clone(&$trace);
					let utilization = ::std::sync::Arc::clone(&$utilization);
					let utilization_map = ::std::sync::Arc::clone(&$utilization_map);
					let circuit_breaker = ::std::sync::Arc::clone(&circuit_breaker);
					let trusted_keys = ::std::sync::Arc::clone(&trusted_keys);
					let servlet_pool = ::std::sync::Arc::clone(&$servlet_pool);
					let draining_since = ::std::sync::Arc::clone(&$draining_since);
					async move {
						drone!(
							@handle_cluster_command $protocol,
							frame,
							servlets,
							trace,
							utilization,
							utilization_map,
							circuit_breaker,
							trusted_keys,
							servlet_pool,
							draining_since,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	}};

	// Helper to build hive control server without policies
	(
		@build_hive_control_server $protocol:path,
		$listener:ident,
		[],
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$cb_threshold:ident,
		$cb_cooldown_ms:ident,
		$trusted_keys:ident,
		$servlet_pool:ident,
		$draining_since:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {{
		let circuit_breaker = ::std::sync::Arc::new(
			$crate::colony::drone::ClusterCircuitBreaker::new($cb_threshold, $cb_cooldown_ms)
		);
		let trusted_keys = ::std::sync::Arc::new($trusted_keys);

		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let servlets = ::std::sync::Arc::clone(&$servlets);
					let trace = ::std::sync::Arc::clone(&$trace);
					let utilization = ::std::sync::Arc::clone(&$utilization);
					let utilization_map = ::std::sync::Arc::clone(&$utilization_map);
					let circuit_breaker = ::std::sync::Arc::clone(&circuit_breaker);
					let trusted_keys = ::std::sync::Arc::clone(&trusted_keys);
					let servlet_pool = ::std::sync::Arc::clone(&$servlet_pool);
					let draining_since = ::std::sync::Arc::clone(&$draining_since);
					async move {
						drone!(
							@handle_cluster_command $protocol,
							frame,
							servlets,
							trace,
							utilization,
							utilization_map,
							circuit_breaker,
							trusted_keys,
							servlet_pool,
							draining_since,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						)
					}
				}
			}
		}
	}};

	// ==========================================================================
	// Response Composition Helpers
	// ==========================================================================

	// Helper: compose a response frame with message
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

	// Helper: compose a response frame with message and priority
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

	// Helper to handle activation requests and route messages to active servlet
	(
		@handle_activation_request $frame:ident,
		$active_servlet:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				// Define a helper function to stop old servlets
				// This must be defined outside the repetition so we can
				// generate all match arms
				let stop_old_servlet = |old: [<$drone_name ActiveServlet>]| {
					match old {
						[<$drone_name ActiveServlet>]::None => {},
						$(
							[<$drone_name ActiveServlet>]::[<$servlet_id:camel>](s) => {
								s.stop();
							}
						)*
					}
				};

				// First, try to decode as an activation request
				if let Ok(request) = $crate::decode::<$crate::colony::drone::ActivateServletRequest>(&$frame.message) {
					// Match servlet_id and activate the corresponding servlet
					$(
						if request.servlet_id == stringify!($servlet_id).as_bytes() {
							// Start the servlet with correct generic parameter
							paste::paste! {
								drone!(
									@start_servlet_with_response $servlet_name<$input>,
									$drone_name,
									$servlet_id,
									stringify!($servlet_id),
									request.servlet_id.clone(),
									$active_servlet,
									$trace,
									stop_old_servlet,
									$frame
								);
							}
						}
					)*

					// Unknown servlet ID - return error
					return drone!(@reply $frame,
						$crate::colony::drone::ActivateServletResponse::err($crate::policy::TransitStatus::Forbidden)
					);
				}

				Ok(None)
			}
		}
	};

	// Helper to handle cluster commands for hives (with gate checks)
	(
		@handle_cluster_command $protocol:path,
		$frame:ident,
		$servlets:ident,
		$trace:ident,
		$utilization:ident,
		$utilization_map:ident,
		$circuit_breaker:ident,
		$trusted_keys:ident,
		$servlet_pool:ident,
		$draining_since:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				use ::core::sync::atomic::Ordering;
				use $crate::transport::Protocol;

				let active_count = || -> u32 {
					$servlets.lock().map(|s| s.len() as u32).unwrap_or(0)
				};

				let current_util = || -> $crate::utils::BasisPoints {
					$crate::utils::BasisPoints::new_saturating($utilization.load(Ordering::Relaxed))
				};

				// 0. Check drain state - reject non-heartbeat requests when draining
				let is_draining = $draining_since.read().map(|g| g.is_some()).unwrap_or(false);
				let is_heartbeat = $crate::decode::<$crate::colony::common::ClusterCommand>(&$frame.message)
					.map(|cmd| cmd.heartbeat.is_some())
					.unwrap_or(false);

				if is_draining && !is_heartbeat {
					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::heartbeat(
						$crate::policy::TransitStatus::Busy, current_util(), active_count()
					));
				}

				// 1. Apply ClusterSecurityGate with trusted keys from HiveConf
				let parsed_keys: Vec<$crate::crypto::sign::ecdsa::Secp256k1VerifyingKey> = $trusted_keys
					.iter()
					.filter_map(|der_bytes| {
						$crate::crypto::sign::ecdsa::Secp256k1VerifyingKey::from_sec1_bytes(der_bytes).ok()
					})
					.collect();
				let security_gate = match $crate::colony::drone::ClusterSecurityGate::<
					$crate::crypto::sign::ecdsa::Secp256k1Signature,
					$crate::crypto::sign::ecdsa::Secp256k1VerifyingKey,
				>::new(
					::std::sync::Arc::clone(&$circuit_breaker),
					parsed_keys,
				) {
					Ok(gate) => gate,
					Err(_) => {
						// No trusted keys configured - reject all cluster commands
						return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::drone::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
						));
					}
				};
				let security_status = $crate::policy::GatePolicy::evaluate(&security_gate, &$frame);
				if security_status != $crate::policy::TransitStatus::Accepted {
					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
						$crate::colony::drone::HiveManagementResponse::stop_err(security_status)
					));
				}

				// 2. Apply BackpressureGate (heartbeat priority frames exempt)
				let backpressure_gate = $crate::colony::drone::BackpressureGate::new(
					::std::sync::Arc::clone(&$utilization),
					$crate::utils::BasisPoints::new(9000)
				);
				let bp_status = $crate::policy::GatePolicy::evaluate(&backpressure_gate, &$frame);
				if bp_status == $crate::policy::TransitStatus::Busy {
					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::heartbeat(
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

						return drone!(@reply_priority $frame, $crate::MessagePriority::Heartbeat,
							$crate::colony::common::ClusterCommandResponse::heartbeat(status, util_bps, active_count())
						);
					}

					if let Some(manage_request) = cmd.manage {
						return drone!(
							@handle_management_request $frame,
							manage_request,
							$servlets,
							$trace,
							$drone_name,
							$($servlet_id: $servlet_name<$input>),*
						);
					}
				}

				// 4. Work routing: match message to servlet type and forward via pooled connection
				let mut matched_type: Option<&'static [u8]> = None;
				$(
					if matched_type.is_none() && $crate::decode::<$input>(&$frame.message).is_ok() {
						matched_type = Some(stringify!($servlet_id).as_bytes());
					}
				)*

				if let Some(type_prefix) = matched_type {
					let instances: Vec<$crate::colony::common::InstanceMetrics> = {
						let servlets_guard = $servlets.lock()?;
						let util_guard = $utilization_map.lock()?;

						servlets_guard.keys()
							.filter(|k| k.starts_with(type_prefix))
							.map(|k| {
								let utilization_bps = util_guard.get(k).copied().unwrap_or(0);
								$crate::colony::common::InstanceMetrics {
									servlet_id: k.clone(),
									utilization: $crate::utils::BasisPoints::new_saturating(utilization_bps),
									active_requests: 0,
								}
							})
							.collect()
					};

					let load_balancer = $crate::colony::common::LeastLoaded;
					if let Some(idx) = $crate::colony::common::LoadBalancer::select(&load_balancer, &instances) {
						let target = &instances[idx];

						let addr_bytes = &target.servlet_id[type_prefix.len() + 1..];
						let addr_str = ::std::string::String::from_utf8(addr_bytes.to_vec())?;
						let addr: <$protocol as Protocol>::Address = addr_str.parse()?;

						let mut pooled_client = $servlet_pool.connect(addr).await?;
						return Ok(pooled_client.conn()?.emit($frame.clone(), None).await?);
					}
				}

				Ok(None)
			}
		}
	};

	// Helper to handle management request (extracted for reuse)
	// Now wraps responses in ClusterCommandResponse
	(
		@handle_management_request $frame:ident,
		$request:ident,
		$servlets:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				// Handle spawn request
				if let Some(spawn_params) = $request.spawn {
					let servlet_type_name = spawn_params.servlet_type;

					// Try to spawn the requested servlet type
					$(
						if servlet_type_name == stringify!($servlet_id).as_bytes() {
							drone!(
								@start_servlet_for_hive_cmd $servlet_name<$input>,
								$drone_name,
								$servlet_id,
								stringify!($servlet_id),
								servlet_type_name,
								$servlets,
								$trace,
								$frame
							);
						}
					)*

					// Unknown servlet type
					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
						$crate::colony::drone::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
					));
				}

				// Handle list request
				if $request.list.is_some() {
					let servlets = $servlets.lock()?;
					let servlet_list: Vec<_> = servlets.iter().map(|(id, servlet)| {
						let addr = match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
							)*
						};
						$crate::colony::common::ServletInfo {
							servlet_id: id.clone(),
							address: addr.into(),
						}
					}).collect();
					drop(servlets);

					return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
						$crate::colony::drone::HiveManagementResponse::list_ok(servlet_list)
					));
				}

				// Handle stop request
				if let Some(stop_params) = $request.stop {
					let mut servlets = $servlets.lock()?;
					if let Some(servlet) = servlets.remove(&stop_params.servlet_id) {
						drop(servlets);
						// Stop the servlet
						match servlet {
							$(
								[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
							)*
						}
						return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::drone::HiveManagementResponse::stop_ok()
						));
					} else {
						drop(servlets);
						return drone!(@reply $frame, $crate::colony::common::ClusterCommandResponse::manage(
							$crate::colony::drone::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
						));
					}
				}

				// No recognized request type
				Ok(None)
			}
		}
	};

	// Legacy helper to handle management commands for hives (kept for reference)
	(
		@handle_hive_management $frame:ident,
		$servlets:ident,
		$trace:ident,
		$drone_name:ident,
		$($servlet_id:ident: $servlet_name:ident<$input:ty>),*
	) => {
		paste::paste! {
			{
				// Decode the management request
				if let Ok(request) = $crate::decode::<$crate::colony::drone::HiveManagementRequest>(&$frame.message) {
					// Handle spawn request
					if let Some(spawn_params) = request.spawn {
						let servlet_type_name = spawn_params.servlet_type;

						// Try to spawn the requested servlet type
						$(
							if servlet_type_name == stringify!($servlet_id).as_bytes() {
								drone!(
									@start_servlet_for_hive $servlet_name<$input>,
									$drone_name,
									$servlet_id,
									stringify!($servlet_id),
									servlet_type_name,
									$servlets,
									$trace,
									$frame
								);
							}
						)*

						// Unknown servlet type
						return drone!(@reply $frame,
							$crate::colony::drone::HiveManagementResponse::spawn_err($crate::policy::TransitStatus::Forbidden)
						);
					}

					// Handle list request
					if request.list.is_some() {
						let servlets = $servlets.lock()?;
						let servlet_list: Vec<_> = servlets.iter().map(|(id, servlet)| {
							let addr = match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
								)*
							};
							$crate::colony::common::ServletInfo {
								servlet_id: id.clone(),
								address: addr.into(),
							}
						}).collect();
						drop(servlets);

						return drone!(@reply $frame, $crate::colony::drone::HiveManagementResponse::list_ok(servlet_list));
					}

					// Handle stop request
					if let Some(stop_params) = request.stop {
						let mut servlets = $servlets.lock()?;
						if let Some(servlet) = servlets.remove(&stop_params.servlet_id) {
							drop(servlets);
							// Stop the servlet
							match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
								)*
							}
							return drone!(@reply $frame, $crate::colony::drone::HiveManagementResponse::stop_ok());
						} else {
							drop(servlets);
							return drone!(@reply $frame,
								$crate::colony::drone::HiveManagementResponse::stop_err($crate::policy::TransitStatus::Forbidden)
							);
						}
					}
				}

				// Unknown message type
				Ok(None)
			}
		}
	};
}
