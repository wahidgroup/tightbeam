//! Drone framework for dynamic servlet deployment
//!
//! This module provides two types of servlet orchestration:
//!
//! ## Drone
//! A **Drone** is a containerized servlet runner that can morph into **one servlet at a time**.
//! - Receives `ActivateServletRequest` from cluster
//! - Stops current servlet and starts the requested one
//! - Useful for dynamic workload allocation
//!
//! ## Hive
//! A **Hive** is an orchestrator that manages **multiple servlets simultaneously**.
//! - Requires a mycelial protocol (different port per servlet)
//! - Receives `OverlordMessage` from cluster containing `servlet_name` and `frame`
//! - Routes messages to the appropriate servlet
//! - All servlets run concurrently on different ports
//!
//! # Architecture
//!
//! ## Drone Flow:
//! 1. **Drone starts** and listens for control messages on its protocol
//! 2. **Drone registers** with a cluster controller, announcing its capabilities
//! 3. **Cluster sends** `ActivateServletRequest` to morph the drone into a specific servlet
//! 4. **Drone activates** the requested servlet and responds with status
//! 5. **Drone processes** messages using the active servlet
//!
//! ## Hive Flow:
//! 1. **Hive starts** and establishes all servlets on different ports (mycelial)
//! 2. **Hive registers** with cluster, providing addresses for all servlets
//! 3. **Cluster sends** `OverlordMessage` with `servlet_name` and `frame`
//! 4. **Hive routes** the frame to the specified servlet
//! 5. **Hive returns** the servlet's response to the cluster
//!
//! # Example
//!
//! ```ignore
//! use tightbeam::drone;
//! use tightbeam::trace::TraceCollector;
//!
//! // Regular drone (non-mycelial)
//! drone! {
//!     name: RegularDrone,
//!     protocol: Listener,
//!     servlets: {
//!         simple_servlet: SimpleServlet,
//!         worker_servlet: WorkerServlet
//!     }
//! }
//!
//! // Start the drone
//! let drone = RegularDrone::start(TraceCollector::new(), None).await?;
//!
//! // Register with cluster
//! let cluster_addr = "127.0.0.1:8888".parse()?;
//! let response = drone.register_with_cluster(cluster_addr).await?;
//! println!("Registered with cluster: {:?}", response);
//!
//! // Cluster can now send ActivateServletRequest to morph the drone
//! // The drone will automatically handle these requests in its control server
//!
//! // Mycelial drone with hive support
//! drone! {
//!     name: MycelialDrone,
//!     protocol: std::net::TcpListener,  // Must implement Mycelial trait
//!     hive: true,
//!     servlets: {
//!         simple_servlet: SimpleServlet,
//!         worker_servlet: WorkerServlet
//!     }
//! }
//!
//! // Only mycelial drones can call establish_hive()
//! let mut mycelial_drone = MycelialDrone::start(TraceCollector::new(), None).await?;
//! mycelial_drone.establish_hive();  // ✓ Compiles
//!
//! let mut regular_drone = RegularDrone::start(TraceCollector::new(), None).await?;
//! // regular_drone.establish_hive();  // ✗ Compile error: Hive trait not implemented
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use core::future::Future;

use crate::colony::Servlet;
use crate::der::Sequence;
use crate::policy::TransitStatus;
use crate::transport::{AsyncListenerTrait, Mycelial, Protocol};
use crate::Beamable;
#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to drones
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DroneError {
	/// Invalid servlet ID
	#[cfg_attr(feature = "derive", error("Invalid servlet ID: {:#?}"))]
	InvalidServletId(Vec<u8>),
	/// Transport connection failed
	#[cfg_attr(feature = "derive", error("Transport connection failed: {:#?}"))]
	ConnectionFailed(Vec<u8>),
	/// Message composition failed
	#[cfg_attr(feature = "derive", error("Message composition failed"))]
	ComposeFailed,
	/// Message emission failed
	#[cfg_attr(feature = "derive", error("Message emission failed"))]
	EmitFailed,
	/// No response received
	#[cfg_attr(feature = "derive", error("No response received"))]
	NoResponse,
	/// Message decoding failed
	#[cfg_attr(feature = "derive", error("Message decoding failed"))]
	DecodeFailed,
	/// Lock poisoned
	#[cfg_attr(feature = "derive", error("Lock poisoned"))]
	LockPoisoned,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for DroneError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			DroneError::InvalidServletId(id) => write!(f, "Invalid servlet ID: {:#?}", id),
			DroneError::ConnectionFailed(addr) => write!(f, "Transport connection failed: {:#?}", addr),
			DroneError::ComposeFailed => write!(f, "Message composition failed"),
			DroneError::EmitFailed => write!(f, "Message emission failed"),
			DroneError::NoResponse => write!(f, "No response received"),
			DroneError::DecodeFailed => write!(f, "Message decoding failed"),
			DroneError::LockPoisoned => write!(f, "Lock poisoned"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for DroneError {}

#[cfg(feature = "std")]
impl<T> From<::std::sync::PoisonError<T>> for DroneError {
	fn from(_: ::std::sync::PoisonError<T>) -> Self {
		DroneError::LockPoisoned
	}
}

/// Message type for registering a drone with a cluster
///
/// This message is sent from a drone to a cluster controller to announce
/// its availability and capabilities.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterDroneRequest {
	/// The address where this drone can be reached
	pub drone_addr: Vec<u8>,
	/// List of servlet IDs this drone can run
	pub available_servlets: Vec<Vec<u8>>,
	/// Optional metadata about the drone
	pub metadata: Option<Vec<u8>>,
}

/// Response message for drone registration
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct RegisterDroneResponse {
	/// The status of the registration request
	pub status: TransitStatus,
	/// Optional cluster-assigned drone ID
	pub drone_id: Option<Vec<u8>>,
}

/// Message type for activating a servlet on a drone
///
/// This message is sent from a cluster controller to a drone to instruct
/// it to morph into a specific servlet configuration.
///
/// **Drones** morph into a single servlet at a time.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletRequest {
	/// The identifier of the servlet to activate
	pub servlet_id: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Response message for servlet activation
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletResponse {
	/// The status of the activation request
	pub status: TransitStatus,
	/// The address of the activated servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
}

/// Servlet information entry
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ServletInfo {
	/// The servlet instance ID
	pub servlet_id: Vec<u8>,
	/// The servlet's address
	pub address: Vec<u8>,
}

/// Hive management request message
///
/// Uses context-specific tags to distinguish between different request types.
/// Only one field should be set per request.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementRequest {
	/// Spawn a new servlet instance [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletParams>,
	/// List all active servlets [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsParams>,
	/// Stop a specific servlet instance [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletParams>,
}

/// Parameters for spawning a new servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct SpawnServletParams {
	/// The type of servlet to spawn (e.g., "worker_servlet")
	pub servlet_type: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Parameters for listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsParams {
	/// Optional filter (reserved for future use)
	pub filter: Option<Vec<u8>>,
}

/// Parameters for stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletParams {
	/// The ID of the servlet instance to stop
	pub servlet_id: Vec<u8>,
}

/// Hive management response message
///
/// Uses context-specific tags to distinguish between different response types.
/// Only one field should be set per response.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct HiveManagementResponse {
	/// Response to spawn request [context 0]
	#[asn1(context_specific = "0", optional = "true")]
	pub spawn: Option<SpawnServletResult>,
	/// Response to list request [context 1]
	#[asn1(context_specific = "1", optional = "true")]
	pub list: Option<ListServletsResult>,
	/// Response to stop request [context 2]
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletResult>,
}

/// Result of spawning a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct SpawnServletResult {
	/// The status of the spawn request
	pub status: TransitStatus,
	/// The address of the newly spawned servlet (if successful)
	pub servlet_address: Option<Vec<u8>>,
	/// The identifier of the servlet instance (e.g., "worker_servlet_127.0.0.1:8080")
	pub servlet_id: Option<Vec<u8>>,
}

/// Result of listing servlets
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ListServletsResult {
	/// The status of the request
	pub status: TransitStatus,
	/// List of active servlets
	pub servlets: Vec<ServletInfo>,
}

/// Result of stopping a servlet
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct StopServletResult {
	/// The status of the stop request
	pub status: TransitStatus,
}

/// Trait for drone implementations
///
/// Drones are containerized servlet runners that can dynamically morph
/// between different servlet types based on activation messages.
///
/// Drones extend the `Servlet` trait, inheriting the standard lifecycle methods
/// (start, addr, stop, join) and adding drone-specific capabilities for morphing
/// between different servlet types.
pub trait Drone<I>: Servlet<I> {
	/// The protocol type this drone uses
	type Protocol: Protocol;

	/// Activate a servlet on this drone
	///
	/// # Arguments
	/// * `msg` - The activation message containing servlet ID and configuration
	///
	/// # Returns
	/// * `Ok(TransitStatus)` indicating whether the servlet was activated
	/// * `Err(DroneError)` if activation failed
	fn morph(&mut self, msg: ActivateServletRequest) -> impl Future<Output = Result<TransitStatus, DroneError>> + Send;

	/// Check if a servlet is currently active
	fn is_active(&self) -> bool;

	/// Stop the currently active servlet
	fn deactivate(&mut self) -> impl Future<Output = Result<(), DroneError>> + Send;

	/// Register this drone with a cluster
	///
	/// Sends a `RegisterDroneRequest` to the cluster controller with this drone's
	/// address and available servlet types.
	///
	/// # Arguments
	/// * `cluster_addr` - The address of the cluster controller
	///
	/// # Returns
	/// * `Ok(RegisterDroneResponse)` if registration succeeded
	/// * `Err(DroneError)` if registration failed
	fn register_with_cluster(
		&self,
		cluster_addr: <Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterDroneResponse, DroneError>> + Send;
}

/// Configuration for hives
#[derive(Debug, Clone)]
pub struct HiveConf {
	/// Maximum number of servlet instances per type (default: 10)
	pub max_servlets: usize,
}

impl Default for HiveConf {
	fn default() -> Self {
		Self { max_servlets: 10 }
	}
}

/// Trait for hives that manage multiple servlets simultaneously
///
/// **Design Philosophy:**
/// - **Drone**: Morphs into a single servlet at a time (one active servlet)
/// - **Hive**: Orchestrates multiple servlet instances simultaneously (many active servlets)
///
/// Hives act as orchestrators that manage servlet lifecycle based on cluster demand:
/// - Spawn new servlet instances on demand
/// - Stop/restart servlets
/// - Provide service discovery (servlet addresses)
/// - Health monitoring
///
/// Clusters connect directly to individual servlets for actual work messages.
/// The hive's control server is only used for management commands.
///
/// This trait can only be implemented by drones whose protocol implements both `Mycelial`
/// and `AsyncListenerTrait` (hives require async protocols for concurrent servlet management).
pub trait Hive<I>: Drone<I>
where
	Self::Protocol: Mycelial + AsyncListenerTrait,
{
	/// Establish a hive for this mycelial drone
	///
	/// This starts all registered servlets on different ports (using mycelial networking)
	/// and begins listening for `OverlordMessage` commands from the cluster.
	fn establish_hive(&mut self) -> impl Future<Output = Result<(), DroneError>> + Send;

	/// Get the addresses of all active servlets in the hive
	///
	/// Returns a map of servlet names to their addresses.
	fn servlet_addresses(&self) -> impl Future<Output = Vec<(Vec<u8>, <Self::Protocol as Protocol>::Address)>> + Send;
}

/// Macro for creating drones with pre-registered servlets
#[macro_export]
macro_rules! drone {
	// New syntax: Drone with policies and hive support (with attributes/doc comments and visibility)
	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [hive], [$($policy_key: $policy_val),+], $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [hive], [$($policy_key: $policy_val),+], $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
	};

	// New syntax: Drone with policies (no hive)
	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [], [$($policy_key: $policy_val),+], $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [], [$($policy_key: $policy_val),+], $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
	};

	// New syntax: Drone with hive support (no policies)
	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [hive], [], $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [hive], [], $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
	};

	// New syntax: Drone without policies or hive
	(
		$(#[$meta:meta])*
		pub $drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [], [], $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
	};
	(
		$(#[$meta:meta])*
		$drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_name:ident<$input:ty>),* $(,)? }
	) => {
		drone!(@generate_with_attrs $drone_name, $protocol, [], [], $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
	};

	// Generate with attributes and visibility (new syntax)
	(@generate_with_attrs $drone_name:ident, $protocol:path, [hive], [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, pub, [$(#[$meta])*]);
		drone!(@impl_servlet_trait_for_hive $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait_for_hive $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_hive_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop_for_hive $drone_name);
	};
	(@generate_with_attrs $drone_name:ident, $protocol:path, [hive], [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]) => {
		drone!(@impl_hive_struct_with_attrs $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*, , [$(#[$meta])*]);
		drone!(@impl_servlet_trait_for_hive $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait_for_hive $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_hive_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop_for_hive $drone_name);
	};
	(@generate_with_attrs $drone_name:ident, $protocol:path, [], [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_struct_with_attrs $drone_name, $protocol, pub, [$(#[$meta])*]);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop $drone_name);
	};
	(@generate_with_attrs $drone_name:ident, $protocol:path, [], [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_struct_with_attrs $drone_name, $protocol, , [$(#[$meta])*]);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_name<$input>),*);
		drone!(@impl_drop $drone_name);
	};

	// Start servlet
	(@start_servlet $servlet_name:ident<$input:ty>, $instance:ident, $drone_name:ident, $servlet_id:ident, $servlet_id_str:expr, $error_id:expr) => {
		paste::paste! {
			let servlet = <$servlet_name as $crate::colony::Servlet<$input>>::start(
				$crate::trace::TraceCollector::new(),
				None,
			).await
				.map_err(|_| $crate::colony::drone::DroneError::InvalidServletId($error_id))?;
			let mut active = $instance.active_servlet.lock()?;
			*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);
			return Ok($crate::policy::TransitStatus::Accepted);
		}
	};

	// Start servlet with response (for control server)
	(@start_servlet_with_response $servlet_name:ident<$input:ty>, $drone_name:ident, $servlet_id:ident, $servlet_id_str:expr, $error_id:expr, $active_servlet:ident, $stop_old:ident, $frame:ident) => {
		paste::paste! {
			// Stop old servlet if any
			let old_servlet = {
				let mut active = $active_servlet.lock()?;
				core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::None)
			};
			$stop_old(old_servlet);

			// Start new servlet
			match <$servlet_name as $crate::colony::Servlet<$input>>::start(
				$crate::trace::TraceCollector::new(),
				None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_str: Vec<u8> = servlet_addr.clone().into();
					let mut active = $active_servlet.lock()?;
					*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);
					drop(active);
					return Ok(Some($crate::compose! {
						V0: id: $frame.metadata.id.clone(),
							message: $crate::colony::drone::ActivateServletResponse {
								status: $crate::policy::TransitStatus::Accepted,
								servlet_address: Some(addr_str)
							}
					}?));
				}
				Err(_) => {
					return Ok(Some($crate::compose! {
						V0: id: $frame.metadata.id.clone(),
							message: $crate::colony::drone::ActivateServletResponse {
								status: $crate::policy::TransitStatus::Forbidden,
								servlet_address: None
							}
					}?));
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
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
			}
		}
	};
	(@impl_struct_with_attrs $drone_name:ident, $protocol:path, , [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			struct $drone_name {
				active_servlet: ::std::sync::Arc<::std::sync::Mutex<[<$drone_name ActiveServlet>]>>,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
			}
		}
	};

	// Implement Servlet trait
	(@impl_servlet_trait $drone_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::Servlet<()> for $drone_name {
				type Conf = ();
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(_trace: $crate::trace::TraceCollector, _config: Option<Self::Conf>) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

					// Create shared state for the active servlet
					let active_servlet = ::std::sync::Arc::new(::std::sync::Mutex::new([<$drone_name ActiveServlet>]::None));
					let active_servlet_clone = ::std::sync::Arc::clone(&active_servlet);

					// Start the control server that listens for ActivateServletRequest messages
					let control_server_handle = drone!(@build_control_server $protocol, listener, [$($policy_key: $policy_val),*], active_servlet_clone, $drone_name, $($servlet_id: $servlet_name<$input>),*);

					Ok(Self {
						active_servlet,
						control_server_handle: Some(control_server_handle),
						addr,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(mut self) {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::abort(handle);
					}
					// Stop any active servlet
					if let Ok(mut active) = self.active_servlet.lock() {
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
					}
				}

				#[cfg(feature = "tokio")]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle).await
					} else {
						Ok(())
					}
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
			}
		}
	};

	// Start servlet for hive establishment (no response needed)
	(@start_servlet_for_hive_establish_impl $servlet_name:ident<$input:ty>, $instance:ident, $drone_name:ident, $servlet_id:ident) => {
		paste::paste! {
			if let Ok(servlet) = <$servlet_name as $crate::colony::Servlet<$input>>::start(
				$crate::trace::TraceCollector::new(),
				None,
			).await {
				let servlet_addr = servlet.addr();
				let addr_str: Vec<u8> = servlet_addr.clone().into();
				let mut servlet_id: Vec<u8> = Vec::new();
				servlet_id.extend_from_slice(stringify!($servlet_id).as_bytes());
				servlet_id.push(b'_');
				servlet_id.extend_from_slice(&addr_str);
				if let Ok(mut servlets) = $instance.servlets.lock() {
					servlets.insert(servlet_id, [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));
					drop(servlets);
				}
			}
		}
	};

	// Start servlet for hive (with response)
	(@start_servlet_for_hive $servlet_name:ident<$input:ty>, $drone_name:ident, $servlet_id:ident, $servlet_id_str:expr, $error_id:expr, $servlets:ident, $frame:ident) => {
		paste::paste! {
			match <$servlet_name as $crate::colony::Servlet<$input>>::start(
				$crate::trace::TraceCollector::new(),
				None,
			).await {
				Ok(servlet) => {
					let servlet_addr = servlet.addr();
					let addr_str: Vec<u8> = servlet_addr.clone().into();
					let mut servlet_id: Vec<u8> = Vec::new();
					servlet_id.extend_from_slice(stringify!($servlet_id).as_bytes());
					servlet_id.push(b'_');
					servlet_id.extend_from_slice(&addr_str);
					let mut servlets = $servlets.lock()?;
					servlets.insert(servlet_id.clone(), [<$drone_name Servlet>]::[<$servlet_id:camel>](servlet));
					drop(servlets);
					return Ok(Some($crate::compose! {
						V0: id: $frame.metadata.id.clone(),
							message: $crate::colony::drone::HiveManagementResponse {
								spawn: Some($crate::colony::drone::SpawnServletResult {
									status: $crate::policy::TransitStatus::Accepted,
									servlet_address: Some(addr_str),
									servlet_id: Some(servlet_id)
								}),
								list: None,
								stop: None,
							}
					}?));
				}
				Err(_) => {
					return Ok(Some($crate::compose! {
						V0: id: $frame.metadata.id.clone(),
							message: $crate::colony::drone::HiveManagementResponse {
								spawn: Some($crate::colony::drone::SpawnServletResult {
									status: $crate::policy::TransitStatus::Forbidden,
									servlet_address: None,
									servlet_id: None
								}),
								list: None,
								stop: None,
							}
					}?));
				}
			}
		}
	};

	// Implement Drone trait
	(@impl_drone_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::drone::Drone<()> for $drone_name {
				type Protocol = $protocol;

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
							drone!(@start_servlet $servlet_name<$input>, self, $drone_name, $servlet_id, stringify!($servlet_id), msg.servlet_id.clone());
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
						drone_addr: drone_addr_bytes.clone(),
						available_servlets,
						metadata: None,
					};

					// Connect to cluster and send registration
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await
						.map_err(|_| $crate::colony::drone::DroneError::ConnectionFailed(drone_addr_bytes))?;

					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

					// Compose and send the registration message
					let frame = $crate::compose! {
						V0: id: b"drone-registration",
							message: request
					}.map_err(|_| $crate::colony::drone::DroneError::ComposeFailed)?;

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
	(@impl_hive_struct_with_attrs $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*, pub, [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			pub struct $drone_name {
				// Map of servlet IDs to their instances
				// Key format: "servlet_type_address" (e.g., "worker_servlet_127.0.0.1:8080")
				servlets: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, [<$drone_name Servlet>]>>>,
				// Configuration
				#[allow(dead_code)]
				config: $crate::colony::drone::HiveConf,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
			}

			// Enum to hold any servlet type
			enum [<$drone_name Servlet>] {
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}
		}
	};
	(@impl_hive_struct_with_attrs $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*, , [$(#[$meta:meta])*]) => {
		paste::paste! {
			$(#[$meta])*
			struct $drone_name {
				// Map of servlet IDs to their instances
				// Key format: "servlet_type_address" (e.g., "worker_servlet_127.0.0.1:8080")
				servlets: ::std::sync::Arc<::std::sync::Mutex<::std::collections::HashMap<Vec<u8>, [<$drone_name Servlet>]>>>,
				// Configuration
				#[allow(dead_code)]
				config: $crate::colony::drone::HiveConf,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
			}

			// Enum to hold any servlet type
			enum [<$drone_name Servlet>] {
				$(
					[<$servlet_id:camel>]($servlet_name),
				)*
			}
		}
	};

	// Implement Servlet trait for hive
	(@impl_servlet_trait_for_hive $drone_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::Servlet<()> for $drone_name {
				type Conf = $crate::colony::drone::HiveConf;
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(_trace: $crate::trace::TraceCollector, config: Option<Self::Conf>) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

					// Use provided config or default
					let config = config.unwrap_or_default();

					// Create shared state for servlets
					let servlets = ::std::sync::Arc::new(::std::sync::Mutex::new(::std::collections::HashMap::new()));
					let servlets_clone = ::std::sync::Arc::clone(&servlets);

					// Start the control server that listens for management commands
					let control_server_handle = drone!(@build_hive_control_server $protocol, listener, [$($policy_key: $policy_val),*], servlets_clone, $drone_name, $($servlet_id: $servlet_name<$input>),*);

					Ok(Self {
						servlets,
						config,
						control_server_handle: Some(control_server_handle),
						addr,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr
				}

				fn stop(mut self) {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::abort(handle);
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
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle).await
					} else {
						Ok(())
					}
				}

				#[cfg(all(not(feature = "tokio"), feature = "std"))]
				async fn join(mut self) -> Result<(), $crate::colony::servlet_runtime::rt::JoinError> {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::join(handle)
					} else {
						Ok(())
					}
				}
			}
		}
	};

	// Implement Drone trait for hive (minimal implementation)
	(@impl_drone_trait_for_hive $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::drone::Drone<()> for $drone_name {
				type Protocol = $protocol;

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
						drone_addr: drone_addr_bytes.clone(),
						available_servlets,
						metadata: Some(b"hive".to_vec()),
					};

					// Connect to cluster and send registration
					let stream = <$protocol as $crate::transport::Protocol>::connect(cluster_addr).await
						.map_err(|_| $crate::colony::drone::DroneError::ConnectionFailed(drone_addr_bytes))?;

					let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

					// Compose and send the registration message
					let frame = $crate::compose! {
						V0: id: b"hive-registration",
							message: request
					}.map_err(|_| $crate::colony::drone::DroneError::ComposeFailed)?;

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

	// Implement Hive trait for mycelial async protocols
	(@impl_hive_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			impl $crate::colony::drone::Hive<()> for $drone_name
			where
				$protocol: $crate::transport::Mycelial + $crate::transport::AsyncListenerTrait,
			{
				async fn establish_hive(&mut self) -> Result<(), $crate::colony::drone::DroneError> {
					// Start one instance of each servlet type by default
					// Each servlet will call Protocol::bind() with default_bind_address()
					// which returns "0.0.0.0:0" (or equivalent), causing the OS to allocate
					// a unique port for each servlet. This is the mycelial networking model.
					$(
						{
							// Start the servlet - it will bind to its own unique port
							drone!(@start_servlet_for_hive_establish_impl $servlet_name<$input>, self, $drone_name, $servlet_id);
						}
					)*
					Ok(())
				}

				async fn servlet_addresses(&self) -> Vec<(Vec<u8>, <$protocol as $crate::transport::Protocol>::Address)> {
					self.servlets.lock()
						.map(|servlets| {
							let mut addresses = Vec::new();

							// Collect addresses of all active servlets
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
			}
		}
	};

	// Implement Drop for hive
	(@impl_drop_for_hive $drone_name:ident) => {
		impl Drop for $drone_name {
			fn drop(&mut self) {
				if let Some(handle) = self.control_server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};

	// Implement Drop trait
	(@impl_drop $drone_name:ident) => {
		impl Drop for $drone_name {
			fn drop(&mut self) {
				if let Some(handle) = self.control_server_handle.take() {
					$crate::colony::servlet_runtime::rt::abort(handle);
				}
			}
		}
	};

	// Helper to build control server with policies
	(@build_control_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $active_servlet:ident, $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let active_servlet = std::sync::Arc::clone(&$active_servlet);
					async move {
						drone!(@handle_activation_request frame, active_servlet, $drone_name, $($servlet_id: $servlet_name<$input>),*)
					}
				}
			}
		}
	};

	// Helper to build control server without policies
	(@build_control_server $protocol:path, $listener:ident, [], $active_servlet:ident, $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let active_servlet = ::std::sync::Arc::clone(&$active_servlet);
				async move {
					drone!(@handle_activation_request frame, $active_servlet, $drone_name, $($servlet_id: $servlet_name<$input>),*)
				}
				}
			}
		}
	};

	// Helper to build hive control server with policies
	(@build_hive_control_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $servlets:ident, $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let servlets = ::std::sync::Arc::clone(&$servlets);
				async move {
					drone!(@handle_hive_management frame, $servlets, $drone_name, $($servlet_id: $servlet_name<$input>),*)
				}
				}
			}
		}
	};

	// Helper to build hive control server without policies
	(@build_hive_control_server $protocol:path, $listener:ident, [], $servlets:ident, $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let servlets = ::std::sync::Arc::clone(&$servlets);
					async move {
						drone!(@handle_hive_management frame, servlets, $drone_name, $($servlet_id: $servlet_name<$input>),*)
					}
				}
			}
		}
	};

	// Helper to handle activation requests and route messages to active servlet
	(@handle_activation_request $frame:ident, $active_servlet:ident, $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
		paste::paste! {
			{
				// Define a helper function to stop old servlets
				// This must be defined outside the repetition so we can generate all match arms
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
							// Start the servlet with correct generic parameter (handles both generic and non-generic)
							paste::paste! {
							drone!(@start_servlet_with_response $servlet_name<$input>, $drone_name, $servlet_id, stringify!($servlet_id), request.servlet_id.clone(), $active_servlet, stop_old_servlet, $frame);
							}
						}
					)*

					// Unknown servlet ID - return error
					return Ok(Some($crate::compose! {
						V0: id: $frame.metadata.id.clone(),
							message: $crate::colony::drone::ActivateServletResponse {
								status: $crate::policy::TransitStatus::Forbidden,
								servlet_address: None
							}
					}?));
				}

				// Not an activation request - check if there's an active servlet to handle it
				// Note: Servlets don't have a handle() method we can call directly
				// This is a design limitation - servlets run their own servers
				// For now, return None to indicate the message wasn't handled
				Ok(None)
			}
		}
	};

	// Helper to handle management commands for hives
	(@handle_hive_management $frame:ident, $servlets:ident, $drone_name:ident, $($servlet_id:ident: $servlet_name:ident<$input:ty>),*) => {
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
								// Start the servlet with correct generic parameter (handles both generic and non-generic)
								paste::paste! {
							drone!(@start_servlet_for_hive $servlet_name<$input>, $drone_name, $servlet_id, stringify!($servlet_id), servlet_type_name.to_vec(), $servlets, $frame);
								}
							}
						)*

						// Unknown servlet type
						return Ok(Some($crate::compose! {
							V0: id: $frame.metadata.id.clone(),
								message: $crate::colony::drone::HiveManagementResponse {
									spawn: Some($crate::colony::drone::SpawnServletResult {
										status: $crate::policy::TransitStatus::Forbidden,
										servlet_address: None,
										servlet_id: None
									}),
									list: None,
									stop: None,
								}
					}?));
					}

					// Handle list request
					if let Some(_list_params) = request.list {
						let servlets = $servlets.lock()?;
						let mut servlet_list = Vec::new();

						for (servlet_id, servlet) in servlets.iter() {
							let addr = match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.addr(),
								)*
							};
							let addr_bytes: Vec<u8> = addr.into();
							servlet_list.push($crate::colony::drone::ServletInfo {
								servlet_id: servlet_id.clone(),
								address: addr_bytes,
							});
						}
						drop(servlets);

						return Ok(Some($crate::compose! {
							V0: id: $frame.metadata.id.clone(),
								message: $crate::colony::drone::HiveManagementResponse {
									spawn: None,
									list: Some($crate::colony::drone::ListServletsResult {
										status: $crate::policy::TransitStatus::Accepted,
										servlets: servlet_list
									}),
									stop: None,
								}
					}?));
					}

					// Handle stop request
					if let Some(stop_params) = request.stop {
						let mut servlets = $servlets.lock()?;

						if let Some(servlet) = servlets.remove(&stop_params.servlet_id) {
							// Stop the servlet
							match servlet {
								$(
									[<$drone_name Servlet>]::[<$servlet_id:camel>](s) => s.stop(),
								)*
							}
							drop(servlets);

							return Ok(Some($crate::compose! {
								V0: id: $frame.metadata.id.clone(),
									message: $crate::colony::drone::HiveManagementResponse {
										spawn: None,
										list: None,
										stop: Some($crate::colony::drone::StopServletResult {
											status: $crate::policy::TransitStatus::Accepted
										}),
									}
						}?));
						} else {
							drop(servlets);

							return Ok(Some($crate::compose! {
								V0: id: $frame.metadata.id.clone(),
									message: $crate::colony::drone::HiveManagementResponse {
										spawn: None,
										list: None,
										stop: Some($crate::colony::drone::StopServletResult {
											status: $crate::policy::TransitStatus::Forbidden
										}),
									}
						}?));
						}
					}
				}

				// Unknown message type
				Ok(None)
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
	use crate::der::Sequence;
	use crate::policy::GatePolicy;
	use crate::policy::TransitStatus;
	use crate::transport::policy::PolicyConf;
	use crate::{compose, job, mutex, policy, servlet, worker};
	use crate::{Beamable, Frame};

	#[cfg(feature = "tokio")]
	type Listener = crate::transport::tcp::r#async::TokioListener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = crate::transport::tcp::sync::TcpListener<std::net::TcpListener>;

	// Jobs for hive management operations
	job! {
		name: ListServletsJob,
		fn run(id: &[u8]) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: HiveManagementRequest {
						spawn: None,
						list: Some(ListServletsParams {
							filter: None,
						}),
						stop: None,
					}
			}
		}
	}

	job! {
		name: SpawnServletJob,
		fn run(id: &[u8], servlet_type: &[u8], config: Option<Vec<u8>>) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: HiveManagementRequest {
						spawn: Some(SpawnServletParams {
							servlet_type: servlet_type.to_vec(),
							config,
						}),
						list: None,
						stop: None,
					}
			}
		}
	}

	job! {
		name: StopServletJob,
		fn run(id: &[u8], servlet_id: Vec<u8>) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: HiveManagementRequest {
						spawn: None,
						list: None,
						stop: Some(StopServletParams {
							servlet_id,
						}),
					}
			}
		}
	}

	job! {
		name: ActivateServletJob,
		fn run(id: &[u8], servlet_id: &[u8], config: Option<Vec<u8>>, signing_key: Secp256k1SigningKey) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: ActivateServletRequest {
						servlet_id: servlet_id.to_vec(),
						config,
					},
					nonrepudiation<Secp256k1Signature, _>: signing_key
			}
		}
	}

	// Jobs for servlet responses
	job! {
		name: DroneResponseJob,
		fn run(id: Vec<u8>, result: String) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					message: DroneResponseMessage {
						result,
					}
			}
		}
	}

	job! {
		name: DroneResponseWithOrderJob,
		fn run(id: Vec<u8>, order: u64, message: DroneResponseMessage) -> crate::error::Result<Frame> {
			compose! {
				V0: id: id,
					order: order,
					message: message
			}
		}
	}

	mutex! { SIGNING_KEY: Secp256k1SigningKey = crate::testing::create_test_signing_key() }

	// Helper to safely get signing key for gate policy initialization
	fn get_signing_key_for_gate() -> Secp256k1VerifyingKey {
		SIGNING_KEY()
			.lock()
			.map(|guard| *guard.verifying_key())
			.unwrap_or_else(|_| *crate::testing::create_test_signing_key().verifying_key())
	}

	// Test message types
	#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct DroneTestMessage {
		content: String,
		value: u32,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
	pub struct DroneResponseMessage {
		result: String,
	}

	// Firewall signature gate that verifies cryptographic signatures on activation requests
	struct SignatureGate {
		verifying_key: Secp256k1VerifyingKey,
	}

	impl SignatureGate {
		fn new(verifying_key: Secp256k1VerifyingKey) -> Self {
			Self { verifying_key }
		}
	}

	impl GatePolicy for SignatureGate {
		fn evaluate(&self, frame: &Frame) -> TransitStatus {
			// Check if the frame has a nonrepudiation signature
			if frame.nonrepudiation.is_some() {
				// Verify the signature using the built-in verify method
				if frame.verify::<Secp256k1Signature>(&self.verifying_key).is_ok() {
					TransitStatus::Accepted
				} else {
					TransitStatus::Forbidden
				}
			} else {
				TransitStatus::Unauthorized
			}
		}
	}

	policy! {
		ReceptorPolicy<DroneTestMessage>: TestGate |msg| {
			if msg.value > 0 {
				TransitStatus::Accepted
			} else {
				TransitStatus::Forbidden
			}
		}
	}

	// Create test workers
	worker! {
		name: ValueCheckerWorker<DroneTestMessage, bool>,
		config: {
			threshold: u32,
		},
		handle: |message, _trace, config| async move {
			message.value >= config.threshold
		}
	}

	worker! {
		name: EchoWorker<DroneTestMessage, DroneResponseMessage>,
		policies: {
			with_receptor_gate: [TestGate]
		},
		handle: |message, _trace| async move {
			DroneResponseMessage {
				result: message.content.clone(),
			}
		}
	}

	// Create test servlets
	servlet! {
		pub SimpleServlet<DroneTestMessage>,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		handle: |message, _trace| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			if decoded.content == "PING" {
				Ok(Some(DroneResponseJob::run(message.metadata.id.clone(), "PONG".to_string())?))
			} else {
				Ok(None)
			}
		}
	}

	use crate::colony::servlet::Servlet;
	use crate::trace::TraceCollector;

	impl Servlet<DroneTestMessage> for SimpleServlet {
		type Conf = ();
		type Address = <Listener as crate::transport::Protocol>::Address;

		async fn start(trace: TraceCollector, config: Option<Self::Conf>) -> Result<Self, crate::TightBeamError> {
			let _ = config;
			SimpleServlet::start(trace).await
		}

		fn addr(&self) -> Self::Address {
			self.addr
		}

		fn stop(self) {
			self.stop()
		}

		async fn join(self) -> Result<(), crate::colony::servlet_runtime::rt::JoinError> {
			self.join().await
		}
	}

	servlet! {
		pub ConfigurableServlet<DroneTestMessage>,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		config: {
			threshold: u32,
		},
		handle: |message, _trace, config| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			if decoded.value >= config.threshold {
				Ok(Some(DroneResponseJob::run(message.metadata.id.clone(), "ACCEPTED".to_string())?))
			} else {
				Ok(None)
			}
		}
	}

	servlet! {
		pub WorkerServlet<DroneTestMessage>,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		config: {
			threshold: u32,
		},
		workers: |config| {
			echo: EchoWorker = EchoWorker::start(),
			checker: ValueCheckerWorker = ValueCheckerWorker::start(ValueCheckerWorkerConf {
				threshold: config.threshold,
			})
		},
		handle: |message, trace, _config, workers| async move {
			let trace = ::std::sync::Arc::new(trace);
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			let decoded_arc = ::std::sync::Arc::new(decoded);
			let (echo_result, check_result) = tokio::join!(
				workers
					.echo
					.relay(::std::sync::Arc::clone(&trace), ::std::sync::Arc::clone(&decoded_arc)),
				workers
					.checker
					.relay(::std::sync::Arc::clone(&trace), ::std::sync::Arc::clone(&decoded_arc))
			);

			let echo_msg = match echo_result {
				Ok(msg) => msg,
				Err(_) => return Ok(None),
			};

			let is_valid = match check_result {
				Ok(valid) => valid,
				Err(_) => return Ok(None),
			};

			Ok(if is_valid {
				DroneResponseWithOrderJob::run(
					message.metadata.id.clone(),
					1_700_000_000u64,
					echo_msg
				).ok()
			} else {
				None
			})
		}
	}

	// Regular drone with multiple servlets
	drone! {
		RegularDrone,
		protocol: Listener,
		policies: {
			with_collector_gate: [SignatureGate::new(get_signing_key_for_gate())]
		},
		servlets: {
			simple_servlet: SimpleServlet<DroneTestMessage>,
			configurable_servlet: ConfigurableServlet<DroneTestMessage>,
			worker_servlet: WorkerServlet<DroneTestMessage>
		}
	}

	crate::test_drone! {
		name: test_mycelial_drone_with_collector_gate,
		protocol: Listener,
		drone: RegularDrone,
		config: None,
		setup: |drone| async {
			// No additional setup needed
			drone
		},
		assertions: |client, _channels| async move {
			// Note: Gate observation channels not yet implemented for drones
			// let (ok_rx, reject_rx) = channels;

			// Step 1: Send a signed activation request to morph the drone into simple_servlet
			let signing_key = SIGNING_KEY().lock().map_err(|_| "Lock error")?.clone();
			let signed_frame = ActivateServletJob::run(
				b"cluster-activation-001",
				b"simple_servlet",
				None,
				signing_key.clone()
			)?;

			// Send activation request to drone's control server
			let response = client.emit(signed_frame, None).await?
				.ok_or("No response received from drone")?;

			// Decode the activation response
			let activation_response: ActivateServletResponse = crate::decode(&response.message)?;
			assert_eq!(activation_response.status, TransitStatus::Accepted, "Servlet activation should succeed");

			// Step 2: Test morphing back to simple_servlet (verify we can morph multiple times)
			let signed_simple_again_frame = ActivateServletJob::run(
				b"cluster-activation-002",
				b"simple_servlet",
				None,
				signing_key.clone()
			)?;

			let simple_again_response = client.emit(signed_simple_again_frame, None).await?
				.ok_or("No response from drone for second simple activation")?;

			let simple_again_activation: ActivateServletResponse = crate::decode(&simple_again_response.message)?;
			assert_eq!(simple_again_activation.status, TransitStatus::Accepted, "Second simple servlet activation should succeed");

			// Step 3: Test invalid servlet ID
			let signed_invalid_frame = ActivateServletJob::run(
				b"cluster-activation-003",
				b"nonexistent_servlet",
				None,
				signing_key
			)?;

			let invalid_response = client.emit(signed_invalid_frame, None).await?
				.ok_or("No response from drone for invalid activation")?;

			let invalid_activation: ActivateServletResponse = crate::decode(&invalid_response.message)?;
			assert_eq!(invalid_activation.status, TransitStatus::Forbidden, "Invalid servlet activation should be rejected");

			Ok(())
		}
	}

	// Test hive with mycelial port allocation using TokioListener
	#[cfg(feature = "tokio")]
	drone! {
		TestHive,
		protocol: crate::transport::tcp::r#async::TokioListener,
		hive: true,
		servlets: {
			simple_servlet: SimpleServlet<DroneTestMessage>,
			echo_servlet: EchoServlet<DroneTestMessage>
		}
	}

	#[cfg(feature = "tokio")]
	servlet! {
		EchoServlet<DroneTestMessage>,
		protocol: crate::transport::tcp::r#async::TokioListener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		handle: |message, _trace| async move {
			let decoded: DroneTestMessage = crate::decode(&message.message)?;
			Ok(Some(DroneResponseJob::run(
				message.metadata.id.clone(),
				format!("ECHO: {}", decoded.content)
			)?))
		}
	}

	#[cfg(feature = "tokio")]
	impl Servlet<DroneTestMessage> for EchoServlet {
		type Conf = ();
		type Address = <Listener as crate::transport::Protocol>::Address;

		async fn start(trace: TraceCollector, config: Option<Self::Conf>) -> Result<Self, crate::TightBeamError> {
			let _ = config;
			EchoServlet::start(trace).await
		}

		fn addr(&self) -> Self::Address {
			self.addr
		}

		fn stop(self) {
			self.stop()
		}

		async fn join(self) -> Result<(), crate::colony::servlet_runtime::rt::JoinError> {
			self.join().await
		}
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_hive_mycelial_port_allocation() -> Result<(), Box<dyn std::error::Error>> {
		use crate::colony::drone::Hive;

		// Start the hive
		let mut hive = TestHive::start(crate::trace::TraceCollector::new(), None).await?;

		// Get the hive's control server address
		let control_addr = hive.addr();
		println!("Hive control server at: {control_addr:?}");

		// Establish the hive (start all servlets on unique ports)
		hive.establish_hive().await?;

		// Get addresses of all servlets
		let servlet_addrs: Vec<(Vec<u8>, crate::prelude::TightBeamSocketAddr)> = hive.servlet_addresses().await;

		// Verify we have the expected number of servlets
		assert_eq!(servlet_addrs.len(), 2, "Should have 2 servlets");

		// Verify each servlet has a unique address
		let (servlet1_name, servlet1_addr) = &servlet_addrs[0];
		let (servlet2_name, servlet2_addr) = &servlet_addrs[1];

		println!("Servlet '{}' at: {:?}", String::from_utf8_lossy(servlet1_name), servlet1_addr);
		println!("Servlet '{}' at: {:?}", String::from_utf8_lossy(servlet2_name), servlet2_addr);

		// Verify addresses are all different (mycelial networking)
		assert_ne!(
			format!("{control_addr:?}"),
			format!("{:?}", servlet1_addr),
			"Servlet 1 should have a different address than control server"
		);
		assert_ne!(
			format!("{control_addr:?}"),
			format!("{:?}", servlet2_addr),
			"Servlet 2 should have a different address than control server"
		);
		assert_ne!(
			format!("{servlet1_addr:?}"),
			format!("{:?}", servlet2_addr),
			"Servlets should have different addresses from each other"
		);

		// Clean up
		hive.stop();

		Ok(())
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_hive_management_commands() -> Result<(), Box<dyn std::error::Error>> {
		use crate::colony::drone::Hive;
		use crate::trace::TraceCollector;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::{MessageEmitter, Protocol};

		// Start the hive
		let mut hive = TestHive::start(TraceCollector::new(), None).await?;
		let control_addr = hive.addr();
		println!("Hive control server at: {control_addr:?}");

		// Establish the hive (start default servlets)
		hive.establish_hive().await?;

		// Connect to the hive control server
		let stream = TokioListener::connect(control_addr).await?;
		let mut transport = TokioListener::create_transport(stream);

		// Test 1: List servlets (should have 2 default servlets)
		println!("\n=== Test 1: List initial servlets ===");
		let list_frame = ListServletsJob::run(b"list-1")?;

		let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
		let management_response: HiveManagementResponse = crate::decode(&response.message)?;
		let list_response = management_response.list.ok_or("No list response")?;

		assert_eq!(list_response.status, crate::policy::TransitStatus::Accepted);
		assert_eq!(list_response.servlets.len(), 2, "Should have 2 default servlets");

		for servlet in &list_response.servlets {
			println!(
				"  - {}: {}",
				String::from_utf8_lossy(&servlet.servlet_id),
				String::from_utf8_lossy(&servlet.address)
			);
		}

		// Test 2: Spawn a new servlet instance
		println!("\n=== Test 2: Spawn new servlet ===");
		let spawn_frame = SpawnServletJob::run(b"spawn-1", b"simple_servlet", None)?;

		let response = transport.emit(spawn_frame, None).await?.ok_or("No response")?;
		let management_response: HiveManagementResponse = crate::decode(&response.message)?;
		let spawn_response = management_response.spawn.ok_or("No spawn response")?;

		assert_eq!(spawn_response.status, crate::policy::TransitStatus::Accepted);
		assert!(spawn_response.servlet_address.is_some());
		assert!(spawn_response.servlet_id.is_some());

		let new_servlet_id = spawn_response.servlet_id.ok_or("No servlet_id")?;
		let new_servlet_addr = spawn_response.servlet_address.ok_or("No servlet_address")?;

		println!(
			"  Spawned: {} at {}",
			String::from_utf8_lossy(&new_servlet_id),
			String::from_utf8_lossy(&new_servlet_addr)
		);

		// Test 3: List servlets again (should have 3 now)
		println!("\n=== Test 3: List servlets after spawn ===");
		let list_frame = ListServletsJob::run(b"list-2")?;

		let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
		let management_response: HiveManagementResponse = crate::decode(&response.message)?;
		let list_response = management_response.list.ok_or("No list response")?;

		assert_eq!(list_response.status, crate::policy::TransitStatus::Accepted);
		assert_eq!(list_response.servlets.len(), 3, "Should have 3 servlets after spawn");

		for servlet in &list_response.servlets {
			println!(
				"  - {}: {}",
				String::from_utf8_lossy(&servlet.servlet_id),
				String::from_utf8_lossy(&servlet.address)
			);
		}

		// Test 4: Stop the newly spawned servlet
		println!("\n=== Test 4: Stop servlet ===");
		println!("  Attempting to stop: {}", String::from_utf8_lossy(&new_servlet_id));
		let stop_frame = StopServletJob::run(b"stop-1", new_servlet_id.clone())?;

		let response = transport.emit(stop_frame, None).await?.ok_or("No response")?;
		let management_response: HiveManagementResponse = crate::decode(&response.message)?;
		let stop_response = management_response.stop.ok_or("No stop response")?;

		if stop_response.status != crate::policy::TransitStatus::Accepted {
			println!("  ERROR: Stop failed with status: {:?}", stop_response.status);
			println!("  Servlet ID sent: {new_servlet_id:?}");
			println!("  Current servlets:");
			let list_frame = ListServletsJob::run(b"list-debug")?;
			let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
			let management_response: HiveManagementResponse = crate::decode(&response.message)?;
			let list_response = management_response.list.ok_or("No list response")?;
			for servlet in &list_response.servlets {
				println!("    - ID: {:?}", servlet.servlet_id);
			}
		}

		assert_eq!(stop_response.status, crate::policy::TransitStatus::Accepted);
		println!("  Stopped: {}", String::from_utf8_lossy(&new_servlet_id));

		// Test 5: List servlets again (should be back to 2)
		println!("\n=== Test 5: List servlets after stop ===");
		let list_frame = ListServletsJob::run(b"list-3")?;

		let response = transport.emit(list_frame, None).await?.ok_or("No response")?;
		let management_response: HiveManagementResponse = crate::decode(&response.message)?;
		let list_response = management_response.list.ok_or("No list response")?;

		assert_eq!(list_response.status, crate::policy::TransitStatus::Accepted);
		assert_eq!(list_response.servlets.len(), 2, "Should be back to 2 servlets after stop");

		for servlet in &list_response.servlets {
			println!(
				"  - {}: {}",
				String::from_utf8_lossy(&servlet.servlet_id),
				String::from_utf8_lossy(&servlet.address)
			);
		}

		// Test 6: Try to spawn unknown servlet type
		println!("\n=== Test 6: Spawn unknown servlet type ===");
		let spawn_frame = SpawnServletJob::run(b"spawn-2", b"unknown_servlet", None)?;

		let response = transport.emit(spawn_frame, None).await?.ok_or("No response")?;
		let management_response: HiveManagementResponse = crate::decode(&response.message)?;
		let spawn_response = management_response.spawn.ok_or("No spawn response")?;

		assert_eq!(spawn_response.status, crate::policy::TransitStatus::Forbidden);
		assert!(spawn_response.servlet_address.is_none());
		println!("  Correctly rejected unknown servlet type");

		// Clean up
		hive.stop();

		Ok(())
	}
}
