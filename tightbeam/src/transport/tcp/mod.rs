#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

pub mod sync;

#[cfg(feature = "tokio")]
pub mod r#async;

use crate::transport::{Protocol, ProtocolStream};

#[cfg(feature = "x509")]
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::crypto::x509::Certificate;
#[cfg(not(feature = "tokio"))]
use crate::transport::tcp::r#async::TcpTransport;
#[cfg(feature = "std")]
use crate::transport::{tcp::sync::TcpTransport, Mycelial};

/// Maximum wire size allowed for handshake-phase messages.
/// Handshake messages are small (cert + SPKI + nonces + signature + ECIES blob),
/// therefore we use a much tighter cap than general envelopes to reduce DoS risk.
pub(crate) const HANDSHAKE_MAX_WIRE: usize = 16 * 1024; // 16 KiB

/// Composite validator that runs multiple validators in sequence.
#[cfg(feature = "x509")]
struct CompositeValidator {
	validators: Arc<Vec<Arc<dyn CertificateValidation>>>,
}

#[cfg(feature = "x509")]
impl CertificateValidation for CompositeValidator {
	fn evaluate(&self, cert: &Certificate) -> ::core::result::Result<(), CertificateValidationError> {
		for validator in self.validators.iter() {
			validator.evaluate(cert)?;
		}
		Ok(())
	}
}

/// Abstract TCP listener trait for different networking backends.
pub trait TcpListenerTrait: Protocol + Send {
	#[cfg(feature = "std")]
	fn accept(&self) -> Result<(Self::Stream, std::net::SocketAddr), Self::Error>;

	#[cfg(not(feature = "std"))]
	fn accept(&self) -> Result<(Self::Stream, SocketAddr), Self::Error>;
}

/// Socket address abstraction for no_std environments
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub enum SocketAddr {
	V4 { ip: [u8; 4], port: u16 },
	V6 { ip: [u8; 16], port: u16 },
}

#[cfg(feature = "std")]
impl Protocol for std::net::TcpListener {
	type Listener = std::net::TcpListener;
	type Stream = std::net::TcpStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<Self::Stream>;
	type Address = TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		Ok("127.0.0.1:0".parse().expect("Valid default TCP address"))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = std::net::TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((listener, TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		std::net::TcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn get_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(TightBeamSocketAddr(self.local_addr()?))
	}
}

// The EncryptedProtocol impl for sync TCP lives on the wrapper in sync.rs

#[cfg(feature = "std")]
impl Mycelial for std::net::TcpListener {
	async fn get_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let addr = "0.0.0.0:0"
			.parse::<TightBeamSocketAddr>()
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
		<std::net::TcpListener as Protocol>::bind(addr).await
	}
}

#[cfg(feature = "std")]
impl TcpListenerTrait for std::net::TcpListener {
	fn accept(&self) -> Result<(Self::Stream, std::net::SocketAddr), Self::Error> {
		std::net::TcpListener::accept(self)
	}
}

// std::net implementations when std is available
#[cfg(feature = "std")]
impl ProtocolStream for std::net::TcpStream {
	type Error = std::io::Error;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		std::io::Write::write_all(self, buf)
	}

	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		std::io::Read::read_exact(self, buf)
	}
}

// New type wrapper for SocketAddr that implements Into<Vec<u8>>
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TightBeamSocketAddr(pub std::net::SocketAddr);

#[cfg(feature = "std")]
impl From<std::net::SocketAddr> for TightBeamSocketAddr {
	fn from(addr: std::net::SocketAddr) -> Self {
		Self(addr)
	}
}

#[cfg(feature = "std")]
impl From<TightBeamSocketAddr> for std::net::SocketAddr {
	fn from(addr: TightBeamSocketAddr) -> Self {
		addr.0
	}
}

#[cfg(feature = "std")]
impl From<TightBeamSocketAddr> for Vec<u8> {
	fn from(addr: TightBeamSocketAddr) -> Self {
		std::format!("{}", addr.0).into_bytes()
	}
}

#[cfg(feature = "std")]
impl core::fmt::Display for TightBeamSocketAddr {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		self.0.fmt(f)
	}
}

#[cfg(feature = "std")]
impl core::str::FromStr for TightBeamSocketAddr {
	type Err = std::net::AddrParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(s.parse()?))
	}
}

#[cfg(feature = "std")]
impl core::ops::Deref for TightBeamSocketAddr {
	type Target = std::net::SocketAddr;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

#[cfg(feature = "std")]
impl crate::transport::TightBeamAddress for TightBeamSocketAddr {}

/// Macro to generate common transport implementation for both sync and async.
#[macro_export]
macro_rules! impl_tcp_common {
	($transport:ident, $stream_trait:path) => {
		#[cfg(not(feature = "transport-policy"))]
		impl<S: $stream_trait> From<S> for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			fn from(stream: S) -> Self {
				Self {
					stream,
					handler: None,
					#[cfg(feature = "x509")]
					server_certificate: None,
					#[cfg(feature = "x509")]
					client_certificate: None,
					#[cfg(feature = "x509")]
					client_validators: None,
					#[cfg(feature = "x509")]
					peer_certificate: None,
					#[cfg(feature = "x509")]
					aad_domain_tag: None,
					#[cfg(feature = "x509")]
					max_cleartext_envelope: None,
					#[cfg(feature = "x509")]
					max_encrypted_envelope: None,
					#[cfg(feature = "x509")]
					signatory: None,
					#[cfg(feature = "x509")]
					handshake_state: $crate::transport::handshake::TcpHandshakeState::None,
					#[cfg(feature = "x509")]
					handshake_timeout: std::time::Duration::from_secs(1),
					#[cfg(feature = "x509")]
					symmetric_key: None,
					#[cfg(feature = "x509")]
					server_handshake: None,
					#[cfg(feature = "x509")]
					handshake_protocol_kind: $crate::transport::handshake::HandshakeProtocolKind::default(),
				}
			}
		}

		#[cfg(feature = "transport-policy")]
		impl<S: $stream_trait> From<S> for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			fn from(stream: S) -> Self {
				use $crate::policy::AcceptAllGate;
				use $crate::transport::policy::NoRestart;
				Self {
					stream,
					restart_policy: Box::new(NoRestart),
					emitter_gate: Box::new(AcceptAllGate),
					collector_gate: Box::new(AcceptAllGate),
					handler: None,
					#[cfg(feature = "x509")]
					server_certificate: None,
					#[cfg(feature = "x509")]
					client_certificate: None,
					#[cfg(feature = "x509")]
					client_validators: None,
					#[cfg(feature = "x509")]
					peer_certificate: None,
					#[cfg(feature = "x509")]
					aad_domain_tag: None,
					#[cfg(feature = "x509")]
					max_cleartext_envelope: None,
					#[cfg(feature = "x509")]
					max_encrypted_envelope: None,
					#[cfg(feature = "x509")]
					signatory: None,
					#[cfg(feature = "x509")]
					handshake_state: $crate::transport::handshake::TcpHandshakeState::None,
					#[cfg(feature = "x509")]
					handshake_timeout: std::time::Duration::from_secs(1),
					#[cfg(feature = "x509")]
					symmetric_key: None,
					#[cfg(feature = "x509")]
					server_handshake: None,
					#[cfg(feature = "x509")]
					handshake_protocol_kind: $crate::transport::handshake::HandshakeProtocolKind::default(),
				}
			}
		}

		impl<S: $stream_trait> $crate::transport::ResponseHandler for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			fn with_handler<F>(mut self, handler: F) -> Self
			where
				F: Fn($crate::Frame) -> Option<$crate::Frame> + Send + 'static,
			{
				self.handler = Some(Box::new(handler));
				self
			}

			fn handler(&self) -> Option<&(dyn Fn($crate::Frame) -> Option<$crate::Frame> + Send)> {
				self.handler.as_ref().map(|h| h.as_ref())
			}
		}

		#[cfg(feature = "x509")]
		impl<S: $stream_trait> $transport<S>
		where
			TransportError: From<S::Error>,
		{
			/// Set the server's certificate on the client transport
			/// This indicates that the server requires encryption
			pub fn with_server_certificate(mut self, cert: $crate::x509::Certificate) -> Self {
				self.server_certificate = Some(Arc::new(cert));
				self
			}

			/// Set the client's identity (certificate and signing key) for mutual authentication
			pub fn with_client_identity(
				mut self,
				cert: $crate::x509::Certificate,
				key: Arc<dyn $crate::transport::handshake::ServerHandshakeKey>,
			) -> Self {
				self.client_certificate = Some(Arc::new(cert));
				self.signatory = Some(key);
				self
			}

			/// Get the peer certificate from a completed mutual authentication handshake.
			/// Returns None if mutual auth was not performed or handshake not complete.
			pub fn peer_certificate(&self) -> Option<&$crate::x509::Certificate> {
				self.peer_certificate.as_ref()
			}
		}

		#[cfg(feature = "x509")]
		impl<S: $stream_trait> $transport<S>
		where
			TransportError: From<S::Error>,
		{
			/// Perform client-side handshake with server using ClientHandshakeProtocol trait.
			///
			/// This method:
			/// 1. Creates appropriate handshake orchestrator based on protocol kind
			/// 2. Calls start() to get initial message and sends it
			/// 3. Receives server response
			/// 4. Calls handle_response() to process response and get next message (if any)
			/// 5. Sends next message if needed (multi-round support)
			/// 6. Calls complete() to derive session key
			/// 7. Stores session key and marks handshake complete
			async fn perform_client_handshake(&mut self) -> TransportResult<()> {
				use $crate::der::{Decode, Encode};
				use $crate::transport::handshake::ClientHello;
				use $crate::transport::handshake::HandshakeError;
				use $crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};
				use $crate::transport::handshake::client::EciesHandshakeClientSecp256k1;
				use $crate::transport::tcp::CompositeValidator;
				use $crate::transport::handshake::{
					ClientHandshakeProtocol, HandshakeProtocolKind,
				};

				let mut orchestrator: Box<dyn ClientHandshakeProtocol<Error = HandshakeError>> = match self.handshake_protocol_kind {
					HandshakeProtocolKind::Ecies => {
						// Set client identity if available
						let mut client = EciesHandshakeClientSecp256k1::new(None);
						if let (Some(cert_arc), Some(key)) = (&self.client_certificate, &self.signatory) {
							client = client.with_client_identity(Arc::clone(cert_arc), Arc::clone(key));
						}

						// Set certificate validators if available
						#[cfg(all(feature = "x509", feature = "std"))]
						if let Some(validators) = &self.client_validators {
							let composite = CompositeValidator {
								validators: Arc::clone(validators),
							};
							client = client.with_certificate_validator(Arc::new(composite));
						}

						Box::new(client)
					}

					#[cfg(feature = "transport-cms")]
					HandshakeProtocolKind::Cms => {
						// Get server certificate and signatory for CMS client
						let server_cert = self.server_certificate.as_ref()
							.ok_or(TransportError::Forbidden)?;
						let signatory = self.signatory.as_ref()
							.ok_or(TransportError::Forbidden)?;

						// Build composite validator if validators are configured
						#[cfg(all(feature = "x509", feature = "std"))]
						let validator = self.client_validators.as_ref().map(|validators| {
							let composite = CompositeValidator {
								validators: Arc::clone(validators),
							};
							Arc::new(composite) as Arc<dyn $crate::crypto::x509::policy::CertificateValidation>
						});

						#[cfg(not(all(feature = "x509", feature = "std")))]
						let validator = None;

						// Use trait method to create CMS client with concrete key type
						signatory.create_cms_client(Arc::clone(server_cert), validator)?
					}
				};

				// Step 1: Start handshake - get initial message
				let initial_message = orchestrator.start().await?;
				if initial_message.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}

				// Parse ClientHello and wrap in SignedData → TransportEnvelope
				let client_hello = ClientHello::from_der(&initial_message)?;
				let signed_data: $crate::cms::signed_data::SignedData =
					(&client_hello).try_into().map_err(|_| TransportError::InvalidMessage)?;
				let initial_envelope = TransportEnvelope::SignedData(signed_data);

				let wire_envelope = WireEnvelope::Cleartext(initial_envelope);
				self.write_envelope(&wire_envelope.to_der()?).await?;

				// Update state machine
				#[cfg(feature = "std")]
				{
					self.set_handshake_state($crate::transport::handshake::TcpHandshakeState::AwaitingServerResponse {
						initiated_at: std::time::Instant::now(),
					});
				}
				#[cfg(not(feature = "std"))]
				{
					self.set_handshake_state($crate::transport::handshake::TcpHandshakeState::AwaitingServerResponse {
						initiated_at: 0,
					});
				}

				// Step 2: Receive server response
				let response_wire_bytes = self.read_envelope().await?;
				if response_wire_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}

				// Unwrap WireEnvelope to get TransportEnvelope
				let response_wire = WireEnvelope::from_der(&response_wire_bytes)?;
				let response_envelope = match response_wire {
					WireEnvelope::Cleartext(env) => env,
					WireEnvelope::Encrypted(_) => {
						// Handshake messages must be cleartext
						return Err(TransportError::InvalidMessage);
					}
				};

				// Extract SignedData and convert to ServerHandshake
				use $crate::transport::handshake::ServerHandshake;
				let signed_data = match response_envelope {
					TransportEnvelope::SignedData(sd) => sd,
					_ => return Err(TransportError::InvalidMessage),
				};
				let server_handshake: ServerHandshake =
					(&signed_data).try_into().map_err(|_| TransportError::InvalidMessage)?;

				let response_bytes = server_handshake.to_der()?;
				if response_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}

				// Step 3: Handle server response - may return next message to send
				let next_message = orchestrator.handle_response(&response_bytes).await?;

				// Step 4: Send next message if any (multi-round support)
				if let Some(msg_bytes) = next_message {
					if msg_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
						return Err(TransportError::InvalidMessage);
					}

					// Parse ClientKeyExchange and wrap in EnvelopedData
					use $crate::transport::handshake::ClientKeyExchange;
					let client_kex = ClientKeyExchange::from_der(&msg_bytes)?;
					let enveloped_data: $crate::cms::enveloped_data::EnvelopedData =
						(&client_kex).try_into().map_err(|_| TransportError::InvalidMessage)?;
					let msg_envelope = TransportEnvelope::EnvelopedData(enveloped_data);

					let wire_envelope = WireEnvelope::Cleartext(msg_envelope);
					self.write_envelope(&wire_envelope.to_der()?).await?;
				}

				// Step 5: Complete handshake and get RuntimeAead
				let session_key = orchestrator.complete().await?;

				// Store session key and mark handshake complete
				self.set_symmetric_key(session_key);
				self.set_handshake_state($crate::transport::handshake::TcpHandshakeState::Complete);

				Ok(())
			}

			/// Perform server-side handshake with client using ServerHandshakeProtocol trait.
			///
			/// This method handles multi-round handshakes:
			/// 1. Creates appropriate handshake orchestrator based on protocol kind (if not exists)
			/// 2. Calls handle_request() to process client message and get response (if any)
			/// 3. Sends response message if any (multi-round support)
			/// 4. Calls complete() when handshake is finished to derive session key
			/// 5. Stores session key and marks handshake complete
			///
			/// The orchestrator instance persists across multiple calls for multi-round protocols.
			async fn perform_server_handshake(&mut self, handshake_bytes: &[u8]) -> TransportResult<()> {
				use $crate::der::{Decode, Encode};
				use $crate::transport::handshake::HandshakeProtocolKind;
				use $crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};

				if handshake_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}

				// Parse TransportEnvelope and extract the handshake message
				let transport_envelope = TransportEnvelope::from_der(handshake_bytes)?;
				let raw_message = match &transport_envelope {
					TransportEnvelope::SignedData(sd) => {
						// This is ClientHello (first message from client)
						use $crate::transport::handshake::ClientHello;
						ClientHello::try_from(sd)
							.map_err(|_| TransportError::InvalidMessage)?
							.to_der()?
					}
					TransportEnvelope::EnvelopedData(ed) => {
						// This is ClientKeyExchange (second message from client)
						use $crate::transport::handshake::ClientKeyExchange;
						ClientKeyExchange::try_from(ed)
							.map_err(|_| TransportError::InvalidMessage)?
							.to_der()?
					}
					_ => return Err(TransportError::InvalidMessage),
				};

				// Get server certificate and signatory (required for handshake)
				let cert_arc = self.server_certificate.as_ref().ok_or(TransportError::Forbidden)?;
				let signatory = self.signatory.as_ref().ok_or(TransportError::Forbidden)?;

				// Get or create handshake orchestrator (persists state across multiple messages)
				if self.server_handshake.is_none() {
					self.server_handshake = Some(match self.handshake_protocol_kind {
						HandshakeProtocolKind::Ecies => {
							// Create default security profile for negotiation
							let default_profile = $crate::crypto::profiles::DefaultSecurityProfile::default();
							let profile_desc = $crate::crypto::profiles::SecurityProfileDesc::from(&default_profile);

							Box::new(
								$crate::transport::handshake::server::EciesHandshakeServer::<$crate::crypto::profiles::DefaultCryptoProvider>::new(
									Arc::clone(&signatory),
									Arc::clone(cert_arc),
									None, // Use default AAD domain tag
									self.client_validators.as_ref().map(Arc::clone)
								)
								.with_supported_profiles(vec![profile_desc])
							)
						}

					#[cfg(all(
						feature = "aead",
						feature = "signature"
					))]
					HandshakeProtocolKind::Cms => {
						// Use factory method to create CMS server with concrete key type
						signatory.create_cms_server(
							self.client_validators.as_ref().map(Arc::clone)
						)?
					}
					});
				}

				let orchestrator = self.server_handshake.as_mut().unwrap();

				// Process client handshake message - may return response to send
				let response_bytes = orchestrator.handle_request(&raw_message).await?;

				// Send response if any (multi-round support)
				if let Some(response) = response_bytes {
					if response.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
						return Err(TransportError::InvalidMessage);
					}

					// Parse ServerHandshake and wrap in SignedData → TransportEnvelope
					use $crate::transport::handshake::ServerHandshake;
					let server_handshake = ServerHandshake::from_der(&response)?;
					let signed_data: $crate::cms::signed_data::SignedData =
						(&server_handshake).try_into().map_err(|_| TransportError::InvalidMessage)?;
					let server_envelope = TransportEnvelope::SignedData(signed_data);

					let wire_envelope = WireEnvelope::Cleartext(server_envelope);
					self.write_envelope(&wire_envelope.to_der()?).await?;

					// Set server awaiting state with timeout tracking
					#[cfg(feature = "std")]
					{
						self.set_handshake_state($crate::transport::handshake::TcpHandshakeState::AwaitingClientFinish {
							initiated_at: std::time::Instant::now(),
						});
					}
					#[cfg(not(feature = "std"))]
					{
						self.set_handshake_state($crate::transport::handshake::TcpHandshakeState::AwaitingClientFinish {
							initiated_at: 0,
						});
					}
				} else {
					// No response means handshake is complete - get RuntimeAead
					let session_key = orchestrator.complete().await?;

					// Extract peer certificate if mutual auth was performed
					#[cfg(feature = "x509")]
					{
						self.peer_certificate = orchestrator.peer_certificate().cloned();
					}

					self.set_symmetric_key(session_key);
					self.set_handshake_state($crate::transport::handshake::TcpHandshakeState::Complete);

					// Clear handshake instance - no longer needed
					self.server_handshake = None;
				}

				Ok(())
			}
		}

		#[cfg(feature = "transport-policy")]
		impl<S: $stream_trait> $crate::transport::policy::PolicyConf for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			fn with_restart<P: RestartPolicy + 'static>(mut self, policy: P) -> Self {
				self.restart_policy = Box::new(policy);
				self
			}

			fn with_emitter_gate<G: GatePolicy + 'static>(mut self, gate: G) -> Self {
				self.emitter_gate = Box::new(gate);
				self
			}

			fn with_collector_gate<G: GatePolicy + 'static>(mut self, gate: G) -> Self {
				self.collector_gate = Box::new(gate);
				self
			}

			#[cfg(all(feature = "x509", feature = "std"))]
			fn with_x509_gate<V>(mut self, validator: V) -> Self
			where
				V: $crate::crypto::x509::policy::CertificateValidation + 'static,
			{
				let new_validator = Arc::new(validator);
				match self.client_validators.as_mut() {
					Some(validators) => {
						let mut validators_vec = Arc::try_unwrap(std::mem::replace(validators, Arc::new(vec![])))
							.unwrap_or_else(|arc| (*arc).clone());
						validators_vec.push(new_validator);
						self.client_validators = Some(Arc::new(validators_vec));
					}
					None => {
						self.client_validators = Some(Arc::new(vec![new_validator]));
					}
				}
				self
			}
		}

		#[cfg(all(feature = "transport-policy", not(feature = "x509")))]
		impl<S: $stream_trait> $crate::transport::MessageEmitter for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			type EmitterGate = dyn GatePolicy;
			type RestartPolicy = dyn RestartPolicy;

			fn get_restart_policy(&self) -> &Self::RestartPolicy {
				self.restart_policy.as_ref()
			}

			fn get_emitter_gate_policy(&self) -> &Self::EmitterGate {
				self.emitter_gate.as_ref()
			}
		}

		#[cfg(all(feature = "transport-policy", not(feature = "x509")))]
		impl<S: $stream_trait> $crate::transport::MessageCollector for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			type CollectorGate = dyn GatePolicy;

			fn collector_gate(&self) -> &Self::CollectorGate {
				self.collector_gate.as_ref()
			}
		}

		#[cfg(not(feature = "transport-policy"))]
		impl<S: $stream_trait> $crate::transport::MessageEmitter for $transport<S>
		where
			TransportError: From<S::Error>
		{}

		#[cfg(not(feature = "transport-policy"))]
		impl<S: $stream_trait> $crate::transport::MessageCollector for $transport<S>
		where
			TransportError: From<S::Error>
		{}
	};
}
