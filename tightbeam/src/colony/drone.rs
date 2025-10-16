//! Drone framework for dynamic servlet deployment
//!
//! Drones are containerized servlet runners that can be dynamically morphed
//! to run different servlets based on messages from a cluster controller.
//!
//! # Example
//!
//! ```ignore
//! use tightbeam::drone;
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
//! let mut mycelial_drone = MycelialDrone::start(None).await?;
//! mycelial_drone.establish_hive();  // ✓ Compiles
//!
//! let mut regular_drone = RegularDrone::start(None).await?;
//! // regular_drone.establish_hive();  // ✗ Compile error: Hive trait not implemented
//! ```

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

use core::future::Future;

use crate::colony::Servlet;
use crate::der::Sequence;
use crate::policy::TransitStatus;
use crate::transport::{Mycelial, Protocol};
use crate::Beamable;
#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to drones
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DroneError {
	/// Invalid servlet ID
	#[cfg_attr(feature = "derive", error("Missing required field: {:#?}"))]
	InvalidServletId(Vec<u8>),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for DroneError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			InvalidServletId(id) => write!(f, "Invalid servlet ID: {:#?}", id),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for DroneError {}

/// Message type for activating a servlet on a drone
///
/// This message is sent from a cluster controller to a drone to instruct
/// it to morph into a specific servlet configuration.
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
}

/// Trait for drone implementations
///
/// Drones are containerized servlet runners that can dynamically morph
/// between different servlet types based on activation messages.
///
/// Drones extend the `Servlet` trait, inheriting the standard lifecycle methods
/// (start, addr, stop, join) and adding drone-specific capabilities for morphing
/// between different servlet types.
pub trait Drone: Servlet {
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
}

/// Trait for drones that support mycelial networking (hive establishment)
///
/// This trait can only be implemented by drones whose protocol implements `Mycelial`.
/// Mycelial drones can establish hives, which allow them to process incoming messages
/// by starting a servlet on a different port for each request.
pub trait Hive: Drone
where
	Self::Protocol: Mycelial,
{
	/// Establish a hive for this mycelial drone
	///
	/// This allows the drone to accept a servlet to operate as but will process
	/// incoming messages by starting a servlet on a different port for each request.
	fn establish_hive(&mut self);
}

/// Macro for creating drones with pre-registered servlets
#[macro_export]
macro_rules! drone {
	// Drone with policies and hive support
	(
		name: $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_type:ty),* $(,)? }
	) => {
		drone!(@generate $drone_name, $protocol, [hive], [$($policy_key: $policy_val),+], $($servlet_id: $servlet_type),*);
	};

	// Drone with policies (no hive)
	(
		name: $drone_name:ident,
		protocol: $protocol:path,
		policies: { $($policy_key:ident: $policy_val:tt),+ $(,)? },
		servlets: { $($servlet_id:ident: $servlet_type:ty),* $(,)? }
	) => {
		drone!(@generate $drone_name, $protocol, [], [$($policy_key: $policy_val),+], $($servlet_id: $servlet_type),*);
	};

	// Drone with hive support (no policies)
	(
		name: $drone_name:ident,
		protocol: $protocol:path,
		hive: true,
		servlets: { $($servlet_id:ident: $servlet_type:ty),* $(,)? }
	) => {
		drone!(@generate $drone_name, $protocol, [hive], [], $($servlet_id: $servlet_type),*);
	};

	// Drone without policies or hive
	(
		name: $drone_name:ident,
		protocol: $protocol:path,
		servlets: { $($servlet_id:ident: $servlet_type:ty),* $(,)? }
	) => {
		drone!(@generate $drone_name, $protocol, [], [], $($servlet_id: $servlet_type),*);
	};

	// Main implementation generator with hive flag
	(@generate $drone_name:ident, $protocol:path, [hive], [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_type:ty),*) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_type),*);
		drone!(@impl_struct $drone_name, $protocol);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_type),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_type),*);
		drone!(@impl_hive_trait $drone_name, $protocol);
		drone!(@impl_drop $drone_name);
	};

	// Main implementation generator without hive
	(@generate $drone_name:ident, $protocol:path, [], [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_type:ty),*) => {
		drone!(@impl_enum $drone_name, $($servlet_id: $servlet_type),*);
		drone!(@impl_struct $drone_name, $protocol);
		drone!(@impl_servlet_trait $drone_name, $protocol, [$($policy_key: $policy_val),*], $($servlet_id: $servlet_type),*);
		drone!(@impl_drone_trait $drone_name, $protocol, $($servlet_id: $servlet_type),*);
		drone!(@impl_drop $drone_name);
	};

	// Generate the enum for holding different servlet types
	(@impl_enum $drone_name:ident, $($servlet_id:ident: $servlet_type:ty),*) => {
		paste::paste! {
			// Generate an enum to hold any of the possible servlet types
			enum [<$drone_name ActiveServlet>] {
				None,
				$(
					[<$servlet_id:camel>]($servlet_type),
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
		paste::paste! {
			pub struct $drone_name {
				active_servlet: ::std::sync::Arc<::std::sync::Mutex<[<$drone_name ActiveServlet>]>>,
				control_server_handle: Option<$crate::colony::servlet_runtime::rt::JoinHandle>,
				addr: <$protocol as $crate::transport::Protocol>::Address,
			}
		}
	};

	// Implement Servlet trait
	(@impl_servlet_trait $drone_name:ident, $protocol:path, [$($policy_key:ident: $policy_val:tt),*], $($servlet_id:ident: $servlet_type:ty),*) => {
		paste::paste! {
			impl $crate::colony::Servlet for $drone_name {
				type Conf = ();
				type Address = <$protocol as $crate::transport::Protocol>::Address;

				async fn start(_config: Option<Self::Conf>) -> Result<Self, $crate::TightBeamError> {
					// Bind to a port for the control server
					let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
						.map_err(|e| $crate::TightBeamError::from(e))?;
					let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
						.map_err(|e| $crate::TightBeamError::from(e))?;

					// Create shared state for the active servlet
					let active_servlet = ::std::sync::Arc::new(::std::sync::Mutex::new([<$drone_name ActiveServlet>]::None));
					let active_servlet_clone = active_servlet.clone();

					// Start the control server that listens for ActivateServletRequest messages
					let control_server_handle = drone!(@build_control_server $protocol, listener, [$($policy_key: $policy_val),*], active_servlet_clone, $drone_name, $($servlet_id: $servlet_type),*);

					Ok(Self {
						active_servlet,
						control_server_handle: Some(control_server_handle),
						addr,
					})
				}

				fn addr(&self) -> Self::Address {
					self.addr.clone()
				}

				fn stop(mut self) {
					if let Some(handle) = self.control_server_handle.take() {
						$crate::colony::servlet_runtime::rt::abort(handle);
					}
					// Stop any active servlet
					let mut active = self.active_servlet.lock().unwrap();
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

	// Implement Drone trait
	(@impl_drone_trait $drone_name:ident, $protocol:path, $($servlet_id:ident: $servlet_type:ty),*) => {
		paste::paste! {
			impl $crate::colony::drone::Drone for $drone_name {
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
							// Start the servlet with optional config
							let servlet = <$servlet_type as $crate::colony::Servlet>::start(None).await
								.map_err(|_| $crate::colony::drone::DroneError::InvalidServletId(msg.servlet_id.clone()))?;

							// Store the servlet
							let mut active = self.active_servlet.lock().unwrap();
							*active = [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet);

							return Ok($crate::policy::TransitStatus::Accepted);
						}
					)*

					// Unknown servlet ID
					Err($crate::colony::drone::DroneError::InvalidServletId(msg.servlet_id))
				}

				fn is_active(&self) -> bool {
					let active = self.active_servlet.lock().unwrap();
					!matches!(*active, [<$drone_name ActiveServlet>]::None)
				}

				async fn deactivate(&mut self) -> Result<(), $crate::colony::drone::DroneError> {
					// Take the active servlet and stop it
					let mut active = self.active_servlet.lock().unwrap();
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
			}
		}
	};

	// Conditionally implement Hive trait for mycelial protocols
	(@impl_hive_trait $drone_name:ident, $protocol:path) => {
		paste::paste! {
			// Only implement Hive if the protocol is Mycelial
			// This will fail to compile if $protocol doesn't implement Mycelial
			impl $crate::colony::drone::Hive for $drone_name
			where
				$protocol: $crate::transport::Mycelial,
			{
				fn establish_hive(&mut self) {
					// TODO: Implement hive establishment for mycelial protocols
					// This method can now safely use Mycelial-specific methods
					// Example: self.protocol.get_available_connect().await
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
	(@build_control_server $protocol:path, $listener:ident, [$($policy_key:ident: $policy_val:tt),+], $active_servlet:ident, $drone_name:ident, $($servlet_id:ident: $servlet_type:ty),*) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |frame: $crate::Frame| {
					let active_servlet = $active_servlet.clone();
					async move {
						drone!(@handle_activation_request frame, active_servlet, $drone_name, $($servlet_id: $servlet_type),*)
					}
				}
			}
		}
	};

	// Helper to build control server without policies
	(@build_control_server $protocol:path, $listener:ident, [], $active_servlet:ident, $drone_name:ident, $($servlet_id:ident: $servlet_type:ty),*) => {
		paste::paste! {
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |frame: $crate::Frame| {
					let active_servlet = $active_servlet.clone();
					async move {
						drone!(@handle_activation_request frame, active_servlet, $drone_name, $($servlet_id: $servlet_type),*)
					}
				}
			}
		}
	};

	// Helper to handle activation requests
	(@handle_activation_request $frame:ident, $active_servlet:ident, $drone_name:ident, $($servlet_id:ident: $servlet_type:ty),*) => {
		paste::paste! {
			{
				// Decode the activation request
				let request = match $crate::decode::<$crate::colony::drone::ActivateServletRequest, _>(&$frame.message) {
					Ok(req) => req,
					Err(_) => return None,
				};

				// Match servlet_id and activate the corresponding servlet
				$(
					if request.servlet_id == stringify!($servlet_id).as_bytes() {
						// Start the servlet with optional config
						match <$servlet_type as $crate::colony::Servlet>::start(None).await {
							Ok(servlet) => {
								// Store the servlet
								let mut active = $active_servlet.lock().unwrap();
								// Stop any existing servlet - use a catch-all pattern
								let old_servlet = core::mem::replace(&mut *active, [<$drone_name ActiveServlet>]::[<$servlet_id:camel>](servlet));
								drop(active);

								// Stop the old servlet if there was one
								// Use a wildcard pattern to match any non-None variant
								match old_servlet {
									[<$drone_name ActiveServlet>]::None => {},
									_ => {
										// The enum variants will be dropped here, calling stop() via Drop if implemented
										// For now, we need to manually stop each variant
										// This is a limitation - we'll handle it in the main impl block instead
									}
								}

								// Return success response
								return Some($crate::compose! {
									V0: id: $frame.metadata.id.clone(),
										message: $crate::colony::drone::ActivateServletResponse {
											status: $crate::policy::TransitStatus::Accepted
										}
								}.ok()?);
							}
							Err(_) => {
								// Return error response
								return Some($crate::compose! {
									V0: id: $frame.metadata.id.clone(),
										message: $crate::colony::drone::ActivateServletResponse {
											status: $crate::policy::TransitStatus::Forbidden
										}
								}.ok()?);
							}
						}
					}
				)*

				// Unknown servlet ID - return error
				Some($crate::compose! {
					V0: id: $frame.metadata.id.clone(),
						message: $crate::colony::drone::ActivateServletResponse {
							status: $crate::policy::TransitStatus::Forbidden
						}
				}.ok()?)
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1SigningKey};
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
	use crate::der::Sequence;
	use crate::policy::GatePolicy;
	use crate::policy::TransitStatus;
	use crate::transport::policy::PolicyConf;
	use crate::Beamable;
	use crate::{mutex, policy, servlet, worker};

	#[cfg(feature = "tokio")]
	type Listener = crate::transport::tcp::r#async::TokioListener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = crate::transport::tcp::sync::TcpListener<std::net::TcpListener>;

	mutex! { SIGNING_KEY: Secp256k1SigningKey = crate::testing::create_test_signing_key() }

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
		fn evaluate(&self, frame: &crate::Frame) -> TransitStatus {
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
		handle: |message, config| async move {
			message.value >= config.threshold
		}
	}

	worker! {
		name: EchoWorker<DroneTestMessage, DroneResponseMessage>,
		policies: {
			with_receptor_gate: [TestGate]
		},
		handle: |message| async move {
			DroneResponseMessage {
				result: message.content.clone(),
			}
		}
	}

	// Create test servlets
	servlet! {
		name: SimpleServlet,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		handle: |message| async move {
			let decoded = crate::decode::<DroneTestMessage, _>(&message.message).ok()?;
			if decoded.content == "PING" {
				Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						message: DroneResponseMessage {
							result: "PONG".to_string(),
						}
				}.ok()?)
			} else {
				None
			}
		}
	}

	servlet! {
		name: ConfurableServlet,
		protocol: Listener,
		policies: {
			with_collector_gate: [crate::policy::AcceptAllGate]
		},
		config: {
			threshold: u32,
		},
		handle: |message, config| async move {
			let decoded = crate::decode::<DroneTestMessage, _>(&message.message).ok()?;
			if decoded.value >= config.threshold {
				Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						message: DroneResponseMessage {
							result: "ACCEPTED".to_string(),
						}
				}.ok()?)
			} else {
				None
			}
		}
	}

	servlet! {
		name: WorkerServlet,
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
		handle: |message, _config, workers| async move {
			let decoded = crate::decode::<DroneTestMessage, _>(&message.message).ok()?;

			#[cfg(feature = "tokio")]
			let (echo_result, check_result) = tokio::join!(
				workers.echo.relay(decoded.clone()),
				workers.checker.relay(decoded.clone())
			);

			#[cfg(not(feature = "tokio"))]
			let (echo_result, check_result) = {
				let echo = workers.echo.relay(decoded.clone()).await;
				let check = workers.checker.relay(decoded.clone()).await;
				(echo, check)
			};

			let echo_msg = match echo_result {
				Ok(msg) => msg,
				Err(_) => return None,
			};

			let is_valid = match check_result {
				Ok(valid) => valid,
				Err(_) => return None,
			};

			if is_valid {
				Some(crate::compose! {
					V0: id: message.metadata.id.clone(),
						order: 1_700_000_000u64,
						message: echo_msg
				}.ok()?)
			} else {
				None
			}
		}
	}

	// Regular drone with multiple servlets
	drone! {
		name: RegularDrone,
		protocol: Listener,
		policies: {
			with_collector_gate: [SignatureGate::new(*SIGNING_KEY().lock().unwrap().verifying_key())]
		},
		servlets: {
			simple_servlet: SimpleServlet,
			configurable_servlet: ConfurableServlet,
			worker_servlet: WorkerServlet
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
			use crate::transport::MessageEmitter;

			// Note: Gate observation channels not yet implemented for drones
			// let (ok_rx, reject_rx) = channels;

			// Test that servlet is accessible and responds to PING
			let ping_msg = crate::compose! {
				V0: id: b"mycelial-test-001",
					message: DroneTestMessage {
						content: "PING".to_string(),
						value: 42,
					}
			}?;

			let response = client.emit(ping_msg, None).await?
				.ok_or("No response received")?;
			let decoded = crate::decode::<DroneResponseMessage, _>(&response.message)?;
			assert_eq!(decoded.result, "PONG");

			// Create a signed activation request
			let activate_request = ActivateServletRequest {
				servlet_id: b"simple_servlet".to_vec(),
				config: None,
			};

			let signing_key = SIGNING_KEY().lock().unwrap().clone();
			let _signed_frame = crate::compose! {
				V0: id: b"cluster-activation-001",
					message: activate_request,
					nonrepudiation<Secp256k1, Secp256k1Signature, _>: &signing_key
			}?;

			// TODO: Send activation request to drone and verify response

			Ok(())
		}
	}

	#[test]
	fn test_regular_drone() {}

	// // Mycelial drone with access receptor for cluster orchestration
	// drone! {
	// 	name: MycelialDrone,
	// 	protocol: Listener,
	// 	with_collector_gate: [SignatureGate::new(*SIGNING_KEY().lock().unwrap().verifying_key())],
	// 	servlets: {
	// 		simple_servlet: SimpleServlet,
	// 		worker_servlet: WorkerServlet
	// 	}
	// }

	// crate::test_drone! {
	// 	name: test_regular_drone,
	// 	protocol: Listener,
	// 	drone: RegularDrone,
	// 	servlet_id: b"simple_servlet",
	// 	assertions: |client, channels| async move {
	// 		use crate::transport::MessageEmitter;

	// 		let (ok_rx, reject_rx) = channels;

	// 		// ...

	// 		Ok(())
	// 	}
	// }

	// crate::test_drone! {
	// 	name: test_mycelial_drone_with_collector_gate,
	// 	protocol: Listener,
	// 	drone: MycelialDrone,
	// 	servlet_id: b"simple_servlet",
	// 	config: None,
	// 	setup: |drone| async {
	// 		// No additional setup needed
	// 		drone
	// 	},
	// 	assertions: |client, channels| async move {
	// 		use crate::transport::MessageEmitter;

	// 		let (ok_rx, reject_rx) = channels;

	// 		// Test that servlet is accessible and responds to PING
	// 		let ping_msg = crate::compose! {
	// 			V0: id: b"mycelial-test-001",
	// 				message: DroneTestMessage {
	// 					content: "PING".to_string(),
	// 					value: 42,
	// 				}
	// 		}?;

	// 		let response = client.emit(ping_msg, None).await?
	// 			.ok_or("No response received")?;
	// 		let decoded = crate::decode::<DroneResponseMessage, _>(&response.message)?;
	// 		assert_eq!(decoded.result, "PONG");

	// 		// Create a signed activation request
	// 		let activate_request = ActivateServletRequest {
	// 			servlet_id: b"simple_servlet".to_vec(),
	// 			config: None,
	// 		};

	// 		let signing_key = SIGNING_KEY().lock().unwrap().clone();
	// 		let signed_frame = crate::compose! {
	// 			V0: id: b"cluster-activation-001",
	// 				order: 1_700_000_000u64,
	// 				message: activate_request,
	// 				nonrepudiation<Secp256k1, Secp256k1Signature, _>: &signing_key
	// 		}?;

	// 		Ok(())
	// 	}
	// }
}
