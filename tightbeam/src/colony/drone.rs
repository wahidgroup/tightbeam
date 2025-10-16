//! Drone framework for dynamic servlet deployment
//!
//! Drones are containerized servlet runners that can be dynamically morphed
//! to run different servlets based on messages from a cluster controller.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use hashbrown::HashMap;

use core::future::Future;
use core::pin::Pin;

use crate::colony::Servlet;
use crate::transport::TightBeamAddress;
use crate::TightBeamError;

/// Message type for activating a servlet on a drone
///
/// This message is sent from a cluster controller to a drone to instruct
/// it to morph into a specific servlet configuration.
#[derive(Clone, Debug)]
pub struct ActivateServletMessage {
	/// The identifier of the servlet to activate
	pub servlet_id: Vec<u8>,
	/// Optional configuration data for the servlet
	pub config: Option<Vec<u8>>,
}

/// Handle to an active servlet instance
///
/// Provides a type-erased interface to control a running servlet without
/// requiring the Servlet trait to be dyn-compatible.
///
/// Generic over the address type to support different protocols.
pub struct ServletHandle<Addr: Clone> {
	/// Address the servlet is bound to (protocol-specific)
	addr: Addr,
	/// Function to stop the servlet
	stop_fn: Box<dyn FnOnce() + Send>,
}

impl<Addr: Clone> ServletHandle<Addr> {
	/// Create a new servlet handle from a servlet instance
	///
	/// The address is obtained by calling the provided address extractor function
	/// on the servlet, allowing protocol-agnostic address handling.
	pub fn new<S: Servlet + Send + 'static, F>(servlet: S, addr_fn: F) -> Self
	where
		F: FnOnce(&S) -> Addr,
	{
		let addr = addr_fn(&servlet);
		Self {
			addr,
			stop_fn: Box::new(move || {
				servlet.stop();
			}),
		}
	}

	/// Get the address the servlet is bound to
	pub fn addr(&self) -> &Addr {
		&self.addr
	}

	/// Stop the servlet
	pub fn stop(self) {
		(self.stop_fn)();
	}
}

/// Factory function type for creating servlet instances
///
/// Takes optional configuration bytes and returns a pinned future that
/// resolves to a ServletHandle.
pub type ServletFactory<Addr> = Box<
	dyn Fn(Option<Vec<u8>>) -> Pin<Box<dyn Future<Output = Result<ServletHandle<Addr>, TightBeamError>> + Send>>
		+ Send
		+ Sync,
>;

/// Trait for drone implementations
///
/// Drones are containerized servlet runners that can dynamically morph
/// between different servlet types based on activation messages.
pub trait TightBeamDrone<Addr: Clone> {
	/// Activate a servlet on this drone
	///
	/// # Arguments
	/// * `msg` - The activation message containing servlet ID and configuration
	///
	/// # Returns
	/// * `Ok(())` if the servlet was successfully activated
	/// * `Err(TightBeamError)` if activation failed
	fn morph(
		&mut self,
		msg: ActivateServletMessage,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Get the current drone ID
	fn id(&self) -> &[u8];

	/// Check if a servlet is currently active
	fn is_active(&self) -> bool;

	/// Stop the currently active servlet
	fn deactivate(&mut self) -> impl Future<Output = Result<(), TightBeamError>> + Send;
}

/// Registry-based drone listener
///
/// Maintains a registry of servlet factories that can be instantiated
/// on demand when activation messages are received.
///
/// Generic over the address type to support different protocols.
pub struct DroneListener<Addr: Clone> {
	/// Drone identifier
	id: Vec<u8>,
	/// Registry mapping servlet names to factory functions
	registry: HashMap<String, ServletFactory<Addr>>,
	/// Currently active servlet (if any)
	active_servlet: Option<ServletHandle<Addr>>,
}

impl<Addr: TightBeamAddress + 'static> DroneListener<Addr> {
	/// Create a new drone listener with the given ID
	pub fn new(id: Vec<u8>) -> Self {
		Self {
			id,
			registry: HashMap::new(),
			active_servlet: None,
		}
	}

	/// Register a servlet factory with the given name
	///
	/// # Arguments
	/// * `name` - The name/identifier for this servlet type
	/// * `factory` - Factory function that creates servlet instances
	pub fn register<S>(&mut self, name: S, factory: ServletFactory<Addr>)
	where
		S: Into<String>,
	{
		self.registry.insert(name.into(), factory);
	}

	/// Get a reference to the registry
	pub fn registry(&self) -> &HashMap<String, ServletFactory<Addr>> {
		&self.registry
	}

	/// Get a mutable reference to the registry
	pub fn registry_mut(&mut self) -> &mut HashMap<String, ServletFactory<Addr>> {
		&mut self.registry
	}

	/// Helper to register a servlet with no config
	pub fn register_simple<S, Fut, F>(&mut self, servlet_id: &str, start_fn: fn() -> Fut, addr_fn: F)
	where
		S: Servlet + Send + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static,
		F: Fn(&S) -> Addr + Send + Sync + 'static + Clone,
	{
		self.register(
			servlet_id,
			Box::new(move |_config| {
				let addr_fn = addr_fn.clone();
				Box::pin(async move {
					let servlet = start_fn().await?;
					Ok(ServletHandle::new(servlet, addr_fn))
				})
			}),
		);
	}
}

impl<Addr: TightBeamAddress + 'static> TightBeamDrone<Addr> for DroneListener<Addr> {
	async fn morph(&mut self, msg: ActivateServletMessage) -> Result<(), TightBeamError> {
		// Convert servlet_id to string for registry lookup
		let servlet_name = core::str::from_utf8(&msg.servlet_id)
			.map_err(|_| TightBeamError::InvalidMetadata)?
			.to_string();

		// Deactivate any currently active servlet first
		if self.active_servlet.is_some() {
			self.deactivate().await?;
		}

		// Look up the factory in the registry
		let factory = self
			.registry
			.get(&servlet_name)
			.ok_or(TightBeamError::MissingConfiguration)?;

		// Create the new servlet instance
		let servlet_handle = factory(msg.config).await?;

		// Store the active servlet handle
		self.active_servlet = Some(servlet_handle);

		Ok(())
	}

	fn id(&self) -> &[u8] {
		&self.id
	}

	fn is_active(&self) -> bool {
		self.active_servlet.is_some()
	}

	async fn deactivate(&mut self) -> Result<(), TightBeamError> {
		if let Some(handle) = self.active_servlet.take() {
			handle.stop();
		}
		Ok(())
	}
}

impl<Addr: TightBeamAddress + 'static> DroneListener<Addr> {
	/// Get the address of the currently active servlet
	///
	/// Returns None if no servlet is currently active
	pub fn active_addr(&self) -> Option<&Addr> {
		self.active_servlet.as_ref().map(|h| h.addr())
	}
}

/// Macro for creating drones with pre-registered servlets
#[macro_export]
macro_rules! drone {
	(
		name: $drone_name:ident,
		protocol: $protocol:ident,
		id: $id:expr,
		servlets: {
			$($servlet_id:ident: $servlet_type:ty),* $(,)?
		}
	) => {
		pub struct $drone_name {
			inner: $crate::colony::drone::DroneListener<<$protocol as $crate::transport::Protocol>::Address>,
		}

		impl $drone_name {
			pub fn new() -> Self {
				let mut inner = $crate::colony::drone::DroneListener::new($id.to_vec());

				$(
					inner.register(
						stringify!($servlet_id),
						Box::new(|_config| {
							Box::pin(async move {
								let servlet = <$servlet_type as $crate::colony::Servlet>::start(None).await?;
								Ok($crate::colony::drone::ServletHandle::new(servlet, |s| s.addr()))
							})
						}),
					);
				)*

				Self { inner }
			}

			/// Get the address of the currently active servlet
			pub fn active_addr(&self) -> Option<&<$protocol as $crate::transport::Protocol>::Address> {
				self.inner.active_addr()
			}
		}

		impl $crate::colony::drone::TightBeamDrone<<$protocol as $crate::transport::Protocol>::Address> for $drone_name {
			async fn morph(&mut self, msg: $crate::colony::drone::ActivateServletMessage) -> Result<(), $crate::TightBeamError> {
				self.inner.morph(msg).await
			}

			fn id(&self) -> &[u8] {
				self.inner.id()
			}

			fn is_active(&self) -> bool {
				self.inner.is_active()
			}

			async fn deactivate(&mut self) -> Result<(), $crate::TightBeamError> {
				self.inner.deactivate().await
			}
		}
	};
}

#[cfg(test)]
#[allow(private_interfaces)]
mod tests {
	use super::*;
	use crate::der::Sequence;
	use crate::policy::{ReceptorPolicy, TransitStatus};
	use crate::{servlet, worker};
    use crate::transport::policy::PolicyConf;

	#[cfg(feature = "tokio")]
	type Listener = crate::transport::tcp::r#async::TokioListener;
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	type Listener = crate::transport::tcp::sync::TcpListener<std::net::TcpListener>;

	// Test message types
	#[derive(crate::Beamable, Clone, Debug, PartialEq, Sequence)]
	struct DroneTestMessage {
		content: String,
		value: u32,
	}

	#[derive(crate::Beamable, Clone, Debug, PartialEq, Sequence)]
	struct DroneResponseMessage {
		result: String,
	}

	// Simple gate policy for testing
	#[derive(Default)]
	struct TestGate;

	impl ReceptorPolicy<DroneTestMessage> for TestGate {
		fn evaluate(&self, msg: &DroneTestMessage) -> TransitStatus {
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
						order: 1_700_000_000u64,
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
						order: 1_700_000_000u64,
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

	#[test]
	fn test_drone_listener_creation() {
		let drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());
		assert_eq!(drone.id(), b"test-drone-001");
		assert!(!drone.is_active());
	}

	#[test]
	fn test_drone_register_servlet() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register a servlet factory
		drone.register(
			"simple_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet = SimpleServlet::start().await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		assert_eq!(drone.registry().len(), 1);
		assert!(drone.registry().contains_key("simple_servlet"));
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_colonize_simple_servlet() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register a simple servlet factory
		drone.register(
			"simple_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet = SimpleServlet::start().await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		// Activate the servlet
		let msg = ActivateServletMessage {
			servlet_id: b"simple_servlet".to_vec(),
			config: None,
		};

		let result = drone.morph(msg).await;
		assert!(result.is_ok());
		assert!(drone.is_active());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_colonize_configurable_servlet() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register a configurable servlet factory
		drone.register(
			"configurable_servlet",
			Box::new(|_config| {
				Box::pin(async move {
					// For this test, we'll use a default config if none provided
					let servlet_config = ConfurableServletConf { threshold: 10 };
					let servlet = ConfurableServlet::start(servlet_config).await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		// Activate the servlet
		let msg = ActivateServletMessage {
			servlet_id: b"configurable_servlet".to_vec(),
			config: None,
		};

		let result = drone.morph(msg).await;
		assert!(result.is_ok());
		assert!(drone.is_active());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_colonize_worker_servlet() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register a servlet with workers
		drone.register(
			"worker_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet_config = WorkerServletConf { threshold: 5 };
					let servlet = WorkerServlet::start(servlet_config).await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		// Activate the servlet
		let msg = ActivateServletMessage {
			servlet_id: b"worker_servlet".to_vec(),
			config: None,
		};

		let result = drone.morph(msg).await;
		assert!(result.is_ok());
		assert!(drone.is_active());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_deactivate() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register and activate a servlet
		drone.register(
			"simple_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet = SimpleServlet::start().await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		let msg = ActivateServletMessage {
			servlet_id: b"simple_servlet".to_vec(),
			config: None,
		};

		drone.morph(msg).await.unwrap();
		assert!(drone.is_active());

		// Deactivate
		let result = drone.deactivate().await;
		assert!(result.is_ok());
		assert!(!drone.is_active());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_morph_between_servlets() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register two different servlets
		drone.register(
			"simple_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet = SimpleServlet::start().await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		drone.register(
			"worker_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet_config = WorkerServletConf { threshold: 5 };
					let servlet = WorkerServlet::start(servlet_config).await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		// Activate first servlet
		let msg_a = ActivateServletMessage {
			servlet_id: b"simple_servlet".to_vec(),
			config: None,
		};
		drone.morph(msg_a).await.unwrap();
		assert!(drone.is_active());

		// Morph to second servlet (should deactivate first)
		let msg_b = ActivateServletMessage {
			servlet_id: b"worker_servlet".to_vec(),
			config: None,
		};
		let result = drone.morph(msg_b).await;
		assert!(result.is_ok());
		assert!(drone.is_active());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_invalid_servlet() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Try to activate a servlet that doesn't exist
		let msg = ActivateServletMessage {
			servlet_id: b"nonexistent".to_vec(),
			config: None,
		};

		let result = drone.morph(msg).await;
		assert!(result.is_err());
		assert!(!drone.is_active());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_drone_multiple_morphs() {
		let mut drone = DroneListener::<core::net::SocketAddr>::new(b"test-drone-001".to_vec());

		// Register three different servlets
		drone.register(
			"simple_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet = SimpleServlet::start().await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		drone.register(
			"configurable_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet_config = ConfurableServletConf { threshold: 10 };
					let servlet = ConfurableServlet::start(servlet_config).await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		drone.register(
			"worker_servlet",
			Box::new(|_config| {
				Box::pin(async {
					let servlet_config = WorkerServletConf { threshold: 5 };
					let servlet = WorkerServlet::start(servlet_config).await?;
					Ok(ServletHandle::new(servlet, |s| s.addr()))
				})
			}),
		);

		// Morph through all three servlets
		let msg1 = ActivateServletMessage {
			servlet_id: b"simple_servlet".to_vec(),
			config: None,
		};
		drone.morph(msg1).await.unwrap();
		assert!(drone.is_active());

		let msg2 = ActivateServletMessage {
			servlet_id: b"configurable_servlet".to_vec(),
			config: None,
		};
		drone.morph(msg2).await.unwrap();
		assert!(drone.is_active());

		let msg3 = ActivateServletMessage {
			servlet_id: b"worker_servlet".to_vec(),
			config: None,
		};
		drone.morph(msg3).await.unwrap();
		assert!(drone.is_active());

		// Finally deactivate
		drone.deactivate().await.unwrap();
		assert!(!drone.is_active());
	}

	// Test the drone! macro
	#[test]
	fn test_drone_macro_creation() {
		use crate::transport::tcp::r#async::TokioListener as Listener;

		drone! {
			name: TestDrone,
			protocol: Listener,
			id: b"test-drone-macro",
			servlets: {
				simple_servlet: SimpleServlet,
				configurable_servlet: ConfurableServlet
			}
		}

		let drone = TestDrone::new();
		assert_eq!(drone.id(), b"test-drone-macro");
		assert!(!drone.is_active());
	}

	#[tokio::test]
	async fn test_drone_macro_morph() {
		use crate::transport::tcp::r#async::TokioListener as Listener;

		drone! {
			name: TestDroneMorph,
			protocol: Listener,
			id: b"test-drone-morph",
			servlets: {
				simple_servlet: SimpleServlet,
				configurable_servlet: ConfurableServlet
			}
		}

		let mut drone = TestDroneMorph::new();
		assert!(!drone.is_active());

		// Morph to simple servlet
		let msg = ActivateServletMessage {
			servlet_id: b"simple_servlet".to_vec(),
			config: None,
		};
		drone.morph(msg).await.unwrap();
		assert!(drone.is_active());
		assert!(drone.active_addr().is_some());

		// Deactivate
		drone.deactivate().await.unwrap();
		assert!(!drone.is_active());
		assert!(drone.active_addr().is_none());
	}

	// Test the test_drone! macro
	mod test_drone_macro_test {
		use super::*;
		use crate::transport::tcp::r#async::TokioListener as Listener;
		use crate::transport::MessageEmitter;

		drone! {
			name: TestDroneForMacroTest,
			protocol: Listener,
			id: b"test-drone-for-macro",
			servlets: {
				simple_servlet: SimpleServlet
			}
		}

		crate::test_drone! {
			name: test_test_drone_macro,
			protocol: Listener,
			drone: TestDroneForMacroTest,
			servlet_id: b"simple_servlet",
			assertions: |client, _drone| async move {
				// Send a PING message
				let ping_msg = crate::compose! {
					V0: id: b"ping-test-001",
						order: 1_700_000_000u64,
						message: DroneTestMessage {
							content: "PING".to_string(),
							value: 42,
						}
				}?;

				let response = client.emit(ping_msg, None).await?
					.ok_or("No response received")?;
				let decoded = crate::decode::<DroneResponseMessage, _>(&response.message)?;
				assert_eq!(decoded.result, "PONG");

				Ok(())
			}
		}
	}
}

/*
// Future: Derive macro implementation

tightbeam::drone! {
    name: MyDrone,
    id: b"drone-001",
    servlets: {
        ping_pong: PingPongServlet::start,
        ping_pong_workers: |config| async move {
            let cfg = WorkerServletConf { threshold: 10 };
            PingPongServletWithWorker::start(cfg).await
        }
    }
}

crate::test_drone! {
	name: test_my_drone,
	drone: MyDrone {
		ping_pong: PingPongServlet,
		ping_pong_workers: PingPongServletWithWorker
	},
	assertions: |client| async move {

		Ok(())
	}
}
*/