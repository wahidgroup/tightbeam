#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

pub mod sync;

#[cfg(feature = "tokio")]
pub mod r#async;

use crate::transport::{Protocol, ProtocolStream};

#[cfg(not(feature = "tokio"))]
use crate::transport::tcp::r#async::TcpTransport;
#[cfg(feature = "std")]
use crate::transport::{tcp::sync::TcpTransport, Mycelial};

/// Maximum wire size allowed for handshake-phase messages.
/// Handshake messages are small (cert + SPKI + nonces + signature + ECIES blob),
/// therefore we use a much tighter cap than general envelopes to reduce DoS risk.
pub(crate) const HANDSHAKE_MAX_WIRE: usize = 16 * 1024; // 16 KiB

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
					server_public_key: None,
					#[cfg(feature = "x509")]
					enforce_encryption: false,
					#[cfg(feature = "x509")]
					server_certificate: None,
					#[cfg(feature = "x509")]
					aad_domain_tag: None,
					#[cfg(feature = "x509")]
					max_cleartext_envelope: None,
					#[cfg(feature = "x509")]
					max_encrypted_envelope: None,
					#[cfg(all(feature = "x509", feature = "secp256k1"))]
									signatory: None,
					#[cfg(feature = "x509")]
					handshake_state: $crate::transport::handshake::HandshakeState::None,
					#[cfg(feature = "x509")]
					handshake_timeout: std::time::Duration::from_secs(1),
					#[cfg(feature = "x509")]
					symmetric_key: None,
					#[cfg(all(feature = "x509", feature = "secp256k1"))]
					handshake: None,
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
					server_public_key: None,
					#[cfg(feature = "x509")]
					enforce_encryption: false,
					#[cfg(feature = "x509")]
					server_certificate: None,
					#[cfg(feature = "x509")]
					aad_domain_tag: None,
					#[cfg(feature = "x509")]
					max_cleartext_envelope: None,
					#[cfg(feature = "x509")]
					max_encrypted_envelope: None,
					#[cfg(all(feature = "x509", feature = "secp256k1"))]
									signatory: None,
					#[cfg(feature = "x509")]
					handshake_state: $crate::transport::handshake::HandshakeState::None,
					#[cfg(feature = "x509")]
					handshake_timeout: std::time::Duration::from_secs(1),
					#[cfg(feature = "x509")]
					symmetric_key: None,
					#[cfg(all(feature = "x509", feature = "secp256k1"))]
					handshake: None,
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
				self.server_certificate = Some(cert);
				self
			}
		}

		#[cfg(all(feature = "x509", feature = "secp256k1"))]
		impl<S: $stream_trait> $transport<S>
		where
			TransportError: From<S::Error>,
		{
			/// Perform client-side handshake with server
			///
			/// This method:
			/// 1. Creates a new TightBeamHandshake instance
			/// 2. Generates and sends ClientKeyExchange
			/// 3. Receives and validates ServerHandshake
			/// 4. Derives session key from ECDH
			/// 5. Stores session key and marks handshake complete
			async fn perform_client_handshake(&mut self) -> TransportResult<()> {
				use crate::der::{Decode, Encode};
				use crate::transport::handshake::{HandshakeProtocol, TightBeamHandshake};
				use crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};

				// Create handshake instance
				let mut handshake = TightBeamHandshake::new_client();

				// Step 1: Generate and send ClientHello
				let client_hello_bytes = handshake.initiate_client().await?;
				if client_hello_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}
				let client_hello_envelope = TransportEnvelope::from_der(&client_hello_bytes)?;
				let wire_envelope = WireEnvelope::Cleartext(client_hello_envelope);
				self.write_envelope(&wire_envelope.to_der()?).await?;

				// Update state machine
				#[cfg(feature = "std")]
				{
					self.set_handshake_state($crate::transport::handshake::HandshakeState::AwaitingServerResponse {
						initiated_at: std::time::Instant::now(),
					});
				}
				#[cfg(not(feature = "std"))]
				{
					self.set_handshake_state($crate::transport::handshake::HandshakeState::AwaitingServerResponse { initiated_at: 0 });
				}

				// Step 2: Receive ServerHandshake response
				let response_wire_bytes = self.read_envelope().await?;
				if response_wire_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}
				let response_wire = WireEnvelope::from_der(&response_wire_bytes)?;

				// Unwrap WireEnvelope to get TransportEnvelope
				let response_envelope = match response_wire {
					WireEnvelope::Cleartext(env) => env,
					WireEnvelope::Encrypted(_) => {
						// Handshake messages must be cleartext
						return Err(TransportError::InvalidMessage);
					}
				};

				// Re-encode TransportEnvelope for process_server_response
				let response_bytes = response_envelope.to_der()?;
				if response_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}

				// Step 3: Process ServerHandshake, derive session key, and get ClientKeyExchange to send
				let session_key = handshake.process_server_response(&response_bytes).await?;

				// Step 4: Send ClientKeyExchange (if pending)
				if let Some(client_kex_bytes) = handshake.take_client_key_exchange() {
					if client_kex_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
						return Err(TransportError::InvalidMessage);
					}
					let client_kex_envelope = TransportEnvelope::from_der(&client_kex_bytes)?;
					let wire_envelope = WireEnvelope::Cleartext(client_kex_envelope);
					self.write_envelope(&wire_envelope.to_der()?).await?;
				}

				// Store session key and mark handshake complete
				self.set_symmetric_key(session_key);
				self.set_handshake_state($crate::transport::handshake::HandshakeState::Complete);

				Ok(())
			}

			/// Perform server-side handshake with client
			///
			/// This method handles both:
			/// 1. ClientHello → responds with ServerHandshake (cert + server_random + sig)
			/// 2. ClientKeyExchange → decrypts and derives session key, completes handshake
			///
			/// The handshake instance is stored in the transport and persists across both calls.
			async fn perform_server_handshake(&mut self, handshake_bytes: &[u8]) -> TransportResult<()> {
				use crate::der::{Decode, Encode};
				use crate::transport::handshake::{HandshakeProtocol, TightBeamHandshake};
				use crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};

				if handshake_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE {
					return Err(TransportError::InvalidMessage);
				}
				// Get server certificate and signatory
				let cert = self.server_certificate().ok_or(TransportError::Forbidden)?.clone();
				let signatory = self.signatory.as_ref().ok_or(TransportError::Forbidden)?.clone();

				// Get or create handshake instance (persists state across ClientHello → ClientKeyExchange)
				if self.handshake.is_none() {
					// If available in transport, bind AAD domain tag from transport; otherwise let handshake default
					let aad = self.aad_domain_tag.clone();
					self.handshake = Some(TightBeamHandshake::new_server(cert, signatory, aad));
				}

				let handshake = self.handshake.as_mut().unwrap();

				// Process handshake message (ClientHello or ClientKeyExchange)
				let response_bytes = handshake.handle_client_request(handshake_bytes).await?;
				if !response_bytes.is_empty()
					&& response_bytes.len() > $crate::transport::tcp::HANDSHAKE_MAX_WIRE
				{
					return Err(TransportError::InvalidMessage);
				}

				// Send response if any (ServerHandshake for ClientHello, empty for ClientKeyExchange)
				if !response_bytes.is_empty() {
					// Parse TransportEnvelope, wrap in WireEnvelope, send
					let server_envelope = TransportEnvelope::from_der(&response_bytes)?;
					let wire_envelope = WireEnvelope::Cleartext(server_envelope);
					self.write_envelope(&wire_envelope.to_der()?).await?;

					// Set server awaiting state with timeout tracking
					#[cfg(feature = "std")]
					{
						self.set_handshake_state($crate::transport::handshake::HandshakeState::AwaitingClientFinish {
							initiated_at: std::time::Instant::now(),
						});
					}
					#[cfg(not(feature = "std"))]
					{
						self.set_handshake_state($crate::transport::handshake::HandshakeState::AwaitingClientFinish {
							initiated_at: 0,
						});
					}
				} else {
					// Empty response means ClientKeyExchange was processed - complete handshake
					let session_key = handshake.complete_server_handshake().await?;
					self.set_symmetric_key(session_key);
					self.set_handshake_state($crate::transport::handshake::HandshakeState::Complete);

					// Clear handshake instance - no longer needed
					self.handshake = None;
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
		}

		#[cfg(all(feature = "transport-policy", not(all(feature = "x509", feature = "secp256k1"))))]
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
