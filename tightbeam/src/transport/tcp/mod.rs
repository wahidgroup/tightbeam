#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
#[allow(unused_imports)] // Used in macro expansion
use std::sync::Arc;

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
		"127.0.0.1:0"
			.parse()
			.map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid default address"))
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

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(TightBeamSocketAddr(self.local_addr()?))
	}
}

// The EncryptedProtocol impl for sync TCP lives on the wrapper in sync.rs

#[cfg(feature = "std")]
impl Mycelial for std::net::TcpListener {
	async fn try_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
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

	fn set_timeout(&mut self, timeout: Option<std::time::Duration>) -> Result<(), Self::Error> {
		self.set_read_timeout(timeout)?;
		self.set_write_timeout(timeout)?;
		Ok(())
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
					server_certificates: Vec::new(),
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
					#[cfg(feature = "std")]
					operation_timeout: None,
					handler: None,
					#[cfg(feature = "x509")]
					server_certificates: Vec::new(),
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
					key_manager: None,
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
		impl<S: $stream_trait> $crate::transport::X509ClientConfig for $transport<S>
		where
			TransportError: From<S::Error>,
		{
			fn with_server_certificate(mut self, cert: $crate::x509::Certificate) -> Self {
				self.server_certificates.push(Arc::new(cert));
				self
			}

			fn with_server_certificates(mut self, certs: impl IntoIterator<Item = $crate::x509::Certificate>) -> Self {
				self.server_certificates.extend(certs.into_iter().map(Arc::new));
				self
			}

			fn with_client_identity(
				mut self,
				cert: $crate::x509::Certificate,
				key: $crate::transport::handshake::HandshakeKeyManager,
			) -> Self {
				self.client_certificate = Some(Arc::new(cert));
				self.key_manager = Some(Arc::new(key));
				self
			}
		}

		#[cfg(feature = "x509")]
		impl<S: $stream_trait> $transport<S>
		where
			TransportError: From<S::Error>,
		{
			/// Get the peer certificate from a completed mutual authentication handshake.
			/// Returns None if mutual auth was not performed or handshake not complete.
			pub fn peer_certificate(&self) -> Option<&$crate::x509::Certificate> {
				self.peer_certificate.as_ref()
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

			#[cfg(feature = "std")]
			fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
				self.operation_timeout = Some(timeout);
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

			fn to_restart_policy_ref(&self) -> &Self::RestartPolicy {
				self.restart_policy.as_ref()
			}

			fn to_emitter_gate_policy_ref(&self) -> &Self::EmitterGate {
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
