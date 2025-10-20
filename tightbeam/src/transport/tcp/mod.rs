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
#[cfg(feature = "x509")]
use crate::transport::EncryptedProtocol;
#[cfg(feature = "std")]
use crate::transport::{tcp::sync::TcpTransport, Mycelial};

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

#[cfg(feature = "x509")]
impl EncryptedProtocol<crate::crypto::ecies::EciesSecp256k1Oid> for std::net::TcpListener {
	type Encryptor = crate::crypto::aead::Aes256Gcm;
	type Decryptor = crate::crypto::aead::Aes256Gcm;

	async fn bind_with(
		addr: Self::Address,
		_cert: x509_cert::Certificate,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = std::net::TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((listener, TightBeamSocketAddr(bound_addr)))
	}
}

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

// Newtype wrapper for SocketAddr that implements Into<Vec<u8>>
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
					symmetric_key: None,
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

		#[cfg(feature = "transport-policy")]
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

		#[cfg(feature = "transport-policy")]
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
