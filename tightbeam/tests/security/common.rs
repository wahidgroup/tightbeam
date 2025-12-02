//! Common helpers and fixtures for security threat integration tests.
//!
//! This module provides a protocol-agnostic abstraction for testing security threats
//! across multiple handshake backends (ECIES, CMS) without code duplication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::{
	crypto::{
		ecies::Secp256k1EciesMessage,
		key::{InMemoryKeyProvider, KeyProvider},
		profiles::{DefaultCryptoProvider, SecurityProfileDesc, TightbeamProfile},
		sign::ecdsa::Secp256k1SigningKey,
	},
	testing::{
		error::{FdrConfigError, TestingError},
		utils::{create_test_certificate, create_test_signing_key},
	},
	transport::handshake::{client::EciesHandshakeClient, negotiation::SecurityOffer, server::EciesHandshakeServer},
	TightBeamError,
};

#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{client::CmsHandshakeClient, server::CmsHandshakeServer};

use tightbeam::x509::Certificate;

// ============================================================================
// Core Types for Protocol Abstraction
// ============================================================================

/// Direction of a handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
	ClientToServer,
	ServerToClient,
}

/// A single handshake message captured during the flow.
#[derive(Debug, Clone)]
pub struct CapturedMessage {
	pub step: usize,
	pub direction: Direction,
	pub payload: Vec<u8>,
}

/// Result of running a full handshake with capture.
#[derive(Debug, Clone)]
pub struct CapturedHandshake {
	pub messages: Vec<CapturedMessage>,
	pub kind: HandshakeBackendKind,
}

impl CapturedHandshake {
	/// Get the last client-to-server message (common replay target).
	pub fn final_client_message(&self) -> Option<&CapturedMessage> {
		self.messages.iter().rev().find(|m| m.direction == Direction::ClientToServer)
	}

	/// Get all client-to-server messages.
	pub fn client_messages(&self) -> impl Iterator<Item = &CapturedMessage> {
		self.messages.iter().filter(|m| m.direction == Direction::ClientToServer)
	}

	/// Get message at a specific step.
	pub fn message_at(&self, step: usize) -> Option<&CapturedMessage> {
		self.messages.iter().find(|m| m.step == step)
	}
}

/// Outcome of injecting a message during handshake.
#[derive(Debug)]
pub enum InjectionOutcome {
	/// Handshake continued/completed (bad for replay attack tests).
	Accepted,
	/// Handshake was rejected with an error (good for replay attack tests).
	Rejected(TightBeamError),
}

/// Protocol-agnostic handshake operations for security testing.
///
/// This trait abstracts the differences between ECIES and CMS handshake flows,
/// allowing tests to work with any backend without code duplication.
pub trait HandshakeProtocol: Send {
	/// Returns the backend kind for this session.
	fn kind(&self) -> HandshakeBackendKind;

	/// Run a complete handshake, capturing all exchanged messages.
	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>>;

	/// Run handshake up to step N, then inject a different message at step N.
	/// Returns the outcome of the injection attempt.
	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>>;
}

// ============================================================================
// Server Materials
// ============================================================================

/// Generated server-side credentials for handshake orchestration.
#[derive(Clone)]
pub struct ServerMaterials {
	pub certificate: Arc<Certificate>,
	pub key_provider: Arc<dyn KeyProvider>,
}

impl ServerMaterials {
	pub fn generate() -> Self {
		let signing_key = create_test_signing_key();
		let certificate = Arc::new(create_test_certificate(&signing_key));
		let server_key = Secp256k1SigningKey::from(signing_key);
		let provider: Arc<dyn KeyProvider> = Arc::new(InMemoryKeyProvider::from(server_key));
		Self { certificate, key_provider: provider }
	}
}

/// Default profile descriptor reused across threats.
pub fn default_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&TightbeamProfile)
}

// ============================================================================
// Backend Kind
// ============================================================================

/// Total number of handshake backends exercised by the security harness.
pub const BACKEND_COUNT: usize = 1 + cfg!(feature = "transport-cms") as usize;
/// Same as [`BACKEND_COUNT`] but with a `u32` representation for spec macros.
pub const BACKEND_COUNT_U32: u32 = BACKEND_COUNT as u32;

/// Supported backend identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeBackendKind {
	Ecies,
	#[cfg(feature = "transport-cms")]
	Cms,
}

impl HandshakeBackendKind {
	/// Human-readable backend label (useful for logging/trace events).
	pub fn label(self) -> &'static str {
		match self {
			Self::Ecies => "ecies",
			#[cfg(feature = "transport-cms")]
			Self::Cms => "cms",
		}
	}

	/// Iterate over all enabled backends.
	pub fn all() -> Vec<Self> {
		let mut kinds = vec![Self::Ecies];
		#[cfg(feature = "transport-cms")]
		{
			kinds.push(Self::Cms);
		}
		kinds
	}
}

// ============================================================================
// Security Threat Harness
// ============================================================================

/// Harness that can spawn handshake sessions across all enabled backends.
#[derive(Clone)]
pub struct SecurityThreatHarness {
	materials: ServerMaterials,
}

impl Default for SecurityThreatHarness {
	fn default() -> Self {
		Self { materials: ServerMaterials::generate() }
	}
}

impl SecurityThreatHarness {
	/// Spawn a protocol session for the given backend kind.
	pub fn spawn(&self, kind: HandshakeBackendKind) -> Box<dyn HandshakeProtocol> {
		match kind {
			HandshakeBackendKind::Ecies => Box::new(EciesSession::new(&self.materials)),
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => Box::new(CmsSession::new(&self.materials)),
		}
	}
}

/// Helper to create an error for invalid injection step.
fn invalid_step_error(msg: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "inject_at_step",
		reason: msg,
	}))
}

// ============================================================================
// ECIES Session Implementation
// ============================================================================

/// ECIES handshake session bundle.
pub struct EciesSession {
	client: EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage>,
	server: EciesHandshakeServer<DefaultCryptoProvider>,
}

impl EciesSession {
	fn new(materials: &ServerMaterials) -> Self {
		let client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
			.with_security_offer(SecurityOffer::new(vec![default_security_profile()]));

		let server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
			Arc::clone(&materials.key_provider),
			Arc::clone(&materials.certificate),
			None,
			None,
		)
		.with_supported_profiles(vec![default_security_profile()]);

		Self { client, server }
	}
}

impl HandshakeProtocol for EciesSession {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeBackendKind::Ecies
	}

	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>> {
		Box::pin(async move {
			let mut messages = Vec::new();

			// Step 0: Client Hello (C -> S)
			let client_hello = self.client.build_client_hello()?;
			messages.push(CapturedMessage {
				step: 0,
				direction: Direction::ClientToServer,
				payload: client_hello.clone(),
			});

			// Step 1: Server Handshake (S -> C)
			let server_handshake = self.server.process_client_hello(&client_hello).await?;
			messages.push(CapturedMessage {
				step: 1,
				direction: Direction::ServerToClient,
				payload: server_handshake.clone(),
			});

			// Step 2: Client Key Exchange (C -> S)
			let client_kex = self.client.process_server_handshake(&server_handshake).await?;
			messages.push(CapturedMessage {
				step: 2,
				direction: Direction::ClientToServer,
				payload: client_kex.clone(),
			});

			// Step 3: Server processes KEX (no message, but completes handshake)
			self.server.process_client_key_exchange(&client_kex).await?;

			// Complete both sides
			let _ = self.client.complete()?;
			let _ = self.server.complete()?;

			Ok(CapturedHandshake { messages, kind: HandshakeBackendKind::Ecies })
		})
	}

	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>> {
		let msg = msg.to_vec();
		Box::pin(async move {
			// Run handshake up to the injection point, then inject the message
			match step {
				0 => {
					// Inject at ClientHello - process injected message as client hello
					match self.server.process_client_hello(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				1 => {
					// Run step 0 normally, then inject at ServerHandshake
					let client_hello = self.client.build_client_hello()?;
					let _ = self.server.process_client_hello(&client_hello).await?;
					// Now inject the message as server handshake response
					match self.client.process_server_handshake(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				2 => {
					// Run steps 0-1 normally, then inject at ClientKeyExchange
					let client_hello = self.client.build_client_hello()?;
					let server_handshake = self.server.process_client_hello(&client_hello).await?;
					let _ = self.client.process_server_handshake(&server_handshake).await?;
					// Now inject the message as client key exchange
					match self.server.process_client_key_exchange(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				_ => Err(invalid_step_error("ECIES has only 3 injectable steps (0-2)")),
			}
		})
	}
}

// ============================================================================
// CMS Session Implementation
// ============================================================================

/// CMS handshake session bundle.
#[cfg(feature = "transport-cms")]
pub struct CmsSession {
	client: CmsHandshakeClient<DefaultCryptoProvider>,
	server: CmsHandshakeServer<DefaultCryptoProvider>,
}

#[cfg(feature = "transport-cms")]
impl CmsSession {
	fn new(materials: &ServerMaterials) -> Self {
		// Create client credentials
		let client_key = create_test_signing_key();
		let client_cert = Arc::new(create_test_certificate(&client_key));
		let client_provider: Arc<dyn KeyProvider> =
			Arc::new(InMemoryKeyProvider::from(Secp256k1SigningKey::from(client_key)));

		// Use internal transcript computation for proper replay detection
		let client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			client_provider,
			Arc::clone(&materials.certificate),
		)
		.with_security_offer(SecurityOffer::new(vec![default_security_profile()]));

		let mut server = CmsHandshakeServer::<DefaultCryptoProvider>::new(Arc::clone(&materials.key_provider), None)
			.with_supported_profiles(vec![default_security_profile()]);

		// Set client certificate on server for mutual auth
		server.set_client_certificate((*client_cert).clone()).ok();

		Self { client, server }
	}
}

#[cfg(feature = "transport-cms")]
impl HandshakeProtocol for CmsSession {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeBackendKind::Cms
	}

	fn capture_full(&mut self) -> Pin<Box<dyn Future<Output = Result<CapturedHandshake, TightBeamError>> + Send + '_>> {
		Box::pin(async move {
			let mut messages = Vec::new();
			let session_key = vec![0xA5; 32];

			// Step 0: Key Exchange (C -> S)
			let key_exchange = self.client.build_key_exchange(session_key)?;
			messages.push(CapturedMessage {
				step: 0,
				direction: Direction::ClientToServer,
				payload: key_exchange.clone(),
			});

			// Step 1: Server processes KEX (internal)
			self.server.process_key_exchange(&key_exchange).await?;

			// Step 2: Server Finished (S -> C)
			let server_finished = self.server.build_server_finished().await?;
			messages.push(CapturedMessage {
				step: 2,
				direction: Direction::ServerToClient,
				payload: server_finished.clone(),
			});

			// Step 3: Client processes Server Finished (internal)
			self.client.process_server_finished(&server_finished)?;

			// Step 4: Client Finished (C -> S)
			let client_finished = self.client.build_client_finished().await?;
			messages.push(CapturedMessage {
				step: 4,
				direction: Direction::ClientToServer,
				payload: client_finished.clone(),
			});

			// Step 5: Server processes Client Finished
			self.server.process_client_finished(&client_finished)?;

			// Complete both sides
			self.client.complete()?;
			self.server.complete()?;

			Ok(CapturedHandshake { messages, kind: HandshakeBackendKind::Cms })
		})
	}

	fn inject_at_step(
		&mut self,
		step: usize,
		msg: &[u8],
	) -> Pin<Box<dyn Future<Output = Result<InjectionOutcome, TightBeamError>> + Send + '_>> {
		let msg = msg.to_vec();
		Box::pin(async move {
			let session_key = vec![0xA5; 32];

			match step {
				0 => {
					// Inject at KeyExchange
					match self.server.process_key_exchange(&msg).await {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				2 => {
					// Run step 0-1 normally, then inject at ServerFinished
					let key_exchange = self.client.build_key_exchange(session_key)?;
					self.server.process_key_exchange(&key_exchange).await?;
					// Now inject the message as server finished
					match self.client.process_server_finished(&msg) {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				4 => {
					// Run steps 0-3 normally, then inject at ClientFinished
					let key_exchange = self.client.build_key_exchange(session_key)?;
					self.server.process_key_exchange(&key_exchange).await?;
					let server_finished = self.server.build_server_finished().await?;
					self.client.process_server_finished(&server_finished)?;
					// Now inject the message as client finished
					match self.server.process_client_finished(&msg) {
						Ok(_) => Ok(InjectionOutcome::Accepted),
						Err(e) => Ok(InjectionOutcome::Rejected(e.into())),
					}
				}
				_ => Err(invalid_step_error("CMS injectable steps are 0, 2, 4")),
			}
		})
	}
}
