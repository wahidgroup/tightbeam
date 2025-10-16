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
use std::hash::HashMap;

use core::future::Future;
use core::pin::Pin;

use crate::colony::Servlet;
use crate::der::Sequence;
use crate::transport::{Protocol, TightBeamAddress};
use crate::{Beamable, TightBeamError};

#[cfg(feature = "policy")]
use crate::policy::{GatePolicy, ReceptorPolicy};

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

/// Message type for activating a servlet on a drone
///
/// This message is sent from a cluster controller to a drone to instruct
/// it to morph into a specific servlet configuration.
#[derive(Debug, Beamable, Sequence, Clone, PartialEq)]
pub struct ActivateServletResponse {
	/// The address of the activated servlet
	pub address: Vec<u8>,
	/// Optional data
	pub data: Option<Vec<u8>>,
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
pub trait TightBeamDrone {
	/// Activate a servlet on this drone
	///
	/// # Arguments
	/// * `msg` - The activation message containing servlet ID and configuration
	///
	/// # Returns
	/// * `Ok(ActivateServletResponse)` with the address where the servlet is running
	/// * `Err(TightBeamError)` if activation failed
	fn morph(
		&mut self,
		msg: ActivateServletRequest,
	) -> impl Future<Output = Result<ActivateServletResponse, TightBeamError>> + Send;

	/// Get the current drone ID
	fn id(&self) -> &[u8];

	/// Check if a servlet is currently active
	fn is_active(&self) -> bool;

	/// Stop the currently active servlet
	fn deactivate(&mut self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Set the access receptor gate for the drone (controls servlet activation)
	#[allow(async_fn_in_trait)]
	async fn with_access_receptor<G: ReceptorPolicy<ActivateServletResponse> + 'static>(&mut self, gate: G);

	/// Set the collector gate for the drone (controls message acceptance from clusters)
	#[allow(async_fn_in_trait)]
	async fn with_collector_gate<G: GatePolicy + 'static>(&mut self, gate: G);
}

/// Registry-based drone listener
///
/// Maintains a registry of servlet factories that can be instantiated
/// on demand when activation messages are received.
///
/// Generic over the protocol type to support different protocols.
pub struct DroneListener<P: Protocol> {
	/// Drone identifier
	id: Vec<u8>,
	/// Registry mapping servlet names to factory functions
	registry: HashMap<String, ServletFactory<P::Address>>,
	/// Currently active servlet (if any)
	active_servlet: Option<ServletHandle<P::Address>>,
	/// Protocol listener for spawning new servlets (for Mycelial protocols)
	listener: Option<P::Listener>,
	/// Access gate for mycelial behaviour (controls servlet activation)
	#[cfg(feature = "policy")]
	access_gate: Option<Box<dyn ReceptorPolicy<ActivateServletResponse> + Send>>,
	/// Collector gate for message acceptance from clusters
    #[cfg(feature = "policy")]
    collector_gate: Option<Vec<Box<dyn GatePolicy + Send>>>,
}

impl<P: Protocol> DroneListener<P>
where
	P::Address: TightBeamAddress + 'static,
{
	/// Create a new drone listener with the given ID
	pub fn new(id: Vec<u8>) -> Self {
		Self {
			id,
			registry: HashMap::new(),
			active_servlet: None,
			listener: None,
			#[cfg(feature = "policy")]
			access_gate: None,
			#[cfg(feature = "policy")]
			collector_gate: None,
		}
	}

	/// Create a new drone listener with a protocol listener (for Mycelial protocols)
	pub fn with_listener(id: Vec<u8>, listener: P::Listener) -> Self {
		Self {
			id,
			registry: HashMap::new(),
			active_servlet: None,
			listener: Some(listener),
			#[cfg(feature = "policy")]
			access_gate: None,
			#[cfg(feature = "policy")]
			collector_gate: None,
		}
	}

	/// Register a servlet factory with the given name
	///
	/// # Arguments
	/// * `name` - The name/identifier for this servlet type
	/// * `factory` - Factory function that creates servlet instances
	pub fn register<S>(&mut self, name: S, factory: ServletFactory<P::Address>)
	where
		S: Into<String>,
	{
		self.registry.insert(name.into(), factory);
	}

	/// Get a reference to the registry
	pub fn registry(&self) -> &HashMap<String, ServletFactory<P::Address>> {
		&self.registry
	}

	/// Get a mutable reference to the registry
	pub fn registry_mut(&mut self) -> &mut HashMap<String, ServletFactory<P::Address>> {
		&mut self.registry
	}

	/// Helper to register a servlet with no config
	pub fn register_simple<S, Fut, F>(&mut self, servlet_id: &str, start_fn: fn() -> Fut, addr_fn: F)
	where
		S: Servlet + Send + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static,
		F: Fn(&S) -> P::Address + Send + Sync + 'static + Clone,
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

	#[cfg(feature = "policy")]
	pub fn set_access_receptor<G: ReceptorPolicy<ActivateServletResponse> + 'static>(&mut self, gate: G) {
        self.access_gate = Some(Box::new(gate));
    }

    #[cfg(feature = "policy")]
    pub fn set_collector_gate<G: GatePolicy + 'static>(&mut self, gate: G) {
        match self.collector_gate.as_mut() {
            Some(gates) => gates.push(Box::new(gate)),
            None => self.collector_gate = Some(vec![Box::new(gate)]),
        }
    }
}

impl<P: Protocol> TightBeamDrone for DroneListener<P>
where
	P::Address: TightBeamAddress + 'static,
{
		
	async fn morph(&mut self, msg: ActivateServletRequest) -> Result<ActivateServletResponse, TightBeamError> {
		// Convert servlet_id to string for registry lookup
		let servlet_name = core::str::from_utf8(&msg.servlet_id)
			.map_err(|_| TightBeamError::InvalidMetadata)?
			.to_string();

		// Deactivate any currently active servlet first
		if self.active_servlet.is_some() {
			self.deactivate().await?;
		}

		// Look up the factory in the registry
		let factory = self.registry.get(&servlet_name).ok_or(TightBeamError::MissingConfiguration)?;
		// Create the new servlet instance
		let servlet_handle = factory(msg.config).await?;
		// Get the address where the servlet is running
		let addr = servlet_handle.addr().clone();

		// Store the active servlet handle
		self.active_servlet = Some(servlet_handle);

		// Return the response with the servlet address
		// Convert address to bytes using Into<Vec<u8>>
		let addr_bytes: Vec<u8> = addr.into();
		let response = ActivateServletResponse { address: addr_bytes, data: None };

		// Check access gate if configured
		#[cfg(feature = "policy")]
		if let Some(gate) = &self.access_gate {
			let status = gate.evaluate(&response);
			if status != crate::policy::TransitStatus::Accepted {
				// Deactivate the servlet if gate check fails
				self.deactivate().await?;
				return Err(TightBeamError::MissingConfiguration);
			}
		}

		Ok(response)
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

	#[cfg(feature = "policy")]
	async fn with_access_receptor<G: ReceptorPolicy<ActivateServletResponse> + 'static>(&mut self, gate: G) {
        self.set_access_receptor(gate);
    }

    async fn with_collector_gate<G: GatePolicy + 'static>(&mut self, gate: G) {
        #[cfg(feature = "policy")]
        {
            self.set_collector_gate(gate);
        }
        #[cfg(not(feature = "policy"))]
        {
            let _ = gate;
        }
    }
}

impl<P: Protocol> DroneListener<P>
where
	P::Address: TightBeamAddress + 'static,
{
	/// Get the address of the currently active servlet
	///
	/// Returns None if no servlet is currently active
	pub fn active_addr(&self) -> Option<&P::Address> {
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
		$(with_collector_gate: [ $( $collector_gate:expr ),* $(,)? ],)?
		servlets: {
			$($servlet_id:ident: $servlet_type:ty),* $(,)?
		}
		$(, with_access_receptor: $receptor:expr)?
	) => {
		pub struct $drone_name {
			inner: $crate::colony::drone::DroneListener<$protocol>,
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

				#[cfg(feature = "policy")]
				{
					$(
						$(
							inner.set_collector_gate($collector_gate);
						)*
					)?
					$(
						inner.set_access_receptor($receptor);
					)?
				}

				Self { inner }
			}

			/// Get the address of the currently active servlet
			#[allow(dead_code)]
			pub fn active_addr(&self) -> Option<&<$protocol as $crate::transport::Protocol>::Address> {
				self.inner.active_addr()
			}
		}

		impl $crate::colony::drone::TightBeamDrone for $drone_name {
			async fn morph(&mut self, msg: $crate::colony::drone::ActivateServletRequest) -> Result<$crate::colony::drone::ActivateServletResponse, $crate::TightBeamError> {
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

			async fn with_access_receptor<G: $crate::policy::ReceptorPolicy<$crate::colony::drone::ActivateServletResponse> + 'static>(&mut self, gate: G) {
				self.inner.with_access_receptor(gate).await;
			}

			async fn with_collector_gate<G: $crate::policy::GatePolicy + 'static>(&mut self, gate: G) {
				self.inner.with_collector_gate(gate).await;
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::der::Sequence;
	use crate::policy::TransitStatus;
	use crate::transport::policy::PolicyConf;
	use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1VerifyingKey, Secp256k1Signature};
	use crate::{policy, servlet, worker, mutex};
	use crate::Beamable;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::policy::GatePolicy;

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
		id: b"regular-drone",
		servlets: {
			simple_servlet: SimpleServlet,
			configurable_servlet: ConfurableServlet,
			worker_servlet: WorkerServlet
		}
	}

	// Mycelial drone with access receptor for cluster orchestration
	drone! {
		name: MycelialDrone,
		protocol: Listener,
		id: b"mycelial-drone",
		with_collector_gate: [SignatureGate::new(*SIGNING_KEY().lock().unwrap().verifying_key())],
		servlets: {
			simple_servlet: SimpleServlet,
			worker_servlet: WorkerServlet
		}
	}

	crate::test_drone! {
		name: test_regular_drone,
		protocol: Listener,
		drone: RegularDrone,
		servlet_id: b"simple_servlet",
		assertions: |client, _channels| async move {
			use crate::transport::MessageEmitter;

			// Test simple servlet with PING
			let ping_msg = crate::compose! {
				V0: id: b"ping-test-001",
					message: DroneTestMessage {
						content: "PING".to_string(),
						value: 42,
					}
			}?;

			let response = client.emit(ping_msg, None).await?.ok_or("No response received")?;
			let decoded = crate::decode::<DroneResponseMessage, _>(&response.message)?;
			assert_eq!(decoded.result, "PONG");

			Ok(())
		}
	}

	crate::test_drone! {
		name: test_mycelial_drone_with_collector_gate,
		protocol: Listener,
		drone: MycelialDrone,
		servlet_id: b"simple_servlet",
		config: None,
		setup: |drone| async {
			// No additional setup needed
			drone
		},
		assertions: |client, channels| async move {
			use crate::transport::MessageEmitter;

			let (ok_rx, reject_rx) = channels;

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
			let signed_frame = crate::compose! {
				V0: id: b"cluster-activation-001",
					order: 1_700_000_000u64,
					message: activate_request,
					nonrepudiation<Secp256k1, Secp256k1Signature, _>: &signing_key
			}?;

			Ok(())
		}
	}
}
