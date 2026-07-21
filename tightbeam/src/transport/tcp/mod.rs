#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
#[allow(unused_imports)] // Used in macro expansion
use std::sync::Arc;

#[cfg(feature = "tcp")]
pub mod sync;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub mod r#async;

#[cfg(feature = "std")]
use core::fmt;
#[cfg(feature = "std")]
use core::ops;
#[cfg(feature = "std")]
use core::str::FromStr;
#[cfg(all(feature = "std", feature = "tcp"))]
use std::io::{Error as IoError, ErrorKind, Read, Write};
#[cfg(feature = "std")]
use std::net::{AddrParseError, SocketAddr};
#[cfg(all(feature = "std", feature = "tcp"))]
use std::net::{TcpListener, TcpStream};
#[cfg(all(feature = "std", feature = "tcp"))]
use std::time::Duration;

#[cfg(feature = "std")]
use crate::transport::TightBeamAddress;
#[cfg(feature = "tcp")]
use crate::transport::{tcp::sync::TcpTransport, Mycelial, Protocol, ProtocolStream};

// Canonical definition lives in transport::io so it exists without the TCP features.
pub(crate) use crate::transport::io::HANDSHAKE_MAX_WIRE;

/// Abstract TCP listener trait for different networking backends.
#[cfg(feature = "tcp")]
pub trait TcpListenerTrait: Protocol + Send {
	#[cfg(feature = "std")]
	fn accept(&self) -> Result<(Self::Stream, SocketAddr), Self::Error>;

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

#[cfg(all(feature = "std", feature = "tcp"))]
impl Protocol for TcpListener {
	type Listener = TcpListener;
	type Stream = TcpStream;
	type Error = IoError;
	type Transport = TcpTransport<Self::Stream>;
	type Address = TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		"127.0.0.1:0"
			.parse()
			.map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid default address"))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((listener, TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		TcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(TightBeamSocketAddr(self.local_addr()?))
	}
}

// The EncryptedProtocol impl for sync TCP lives on the wrapper in sync.rs

#[cfg(all(feature = "std", feature = "tcp"))]
impl Mycelial for TcpListener {
	async fn try_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let addr = "0.0.0.0:0"
			.parse::<TightBeamSocketAddr>()
			.map_err(|e| IoError::new(ErrorKind::InvalidInput, e))?;
		<TcpListener as Protocol>::bind(addr).await
	}
}

#[cfg(all(feature = "std", feature = "tcp"))]
impl TcpListenerTrait for TcpListener {
	fn accept(&self) -> Result<(Self::Stream, SocketAddr), Self::Error> {
		TcpListener::accept(self)
	}
}

// std::net implementations when std is available
#[cfg(all(feature = "std", feature = "tcp"))]
impl ProtocolStream for TcpStream {
	type Error = IoError;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		Write::write_all(self, buf)
	}

	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		Read::read_exact(self, buf)
	}

	fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Self::Error> {
		self.set_read_timeout(timeout)?;
		self.set_write_timeout(timeout)?;
		Ok(())
	}
}

// New type wrapper for SocketAddr that implements Into<Vec<u8>>
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TightBeamSocketAddr(pub SocketAddr);

#[cfg(feature = "std")]
impl From<SocketAddr> for TightBeamSocketAddr {
	fn from(addr: SocketAddr) -> Self {
		Self(addr)
	}
}

#[cfg(feature = "std")]
impl From<TightBeamSocketAddr> for SocketAddr {
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
impl fmt::Display for TightBeamSocketAddr {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.0.fmt(f)
	}
}

#[cfg(feature = "std")]
impl FromStr for TightBeamSocketAddr {
	type Err = AddrParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(Self(s.parse()?))
	}
}

#[cfg(feature = "std")]
impl ops::Deref for TightBeamSocketAddr {
	type Target = SocketAddr;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

#[cfg(feature = "std")]
impl TightBeamAddress for TightBeamSocketAddr {}

/// Macro to generate common transport implementation for both sync and async.
///
/// Defines the transport struct itself (single source for the field list --
/// the sync and async variants must stay distinct types because their stream
/// traits would produce overlapping trait impls on one shared struct) plus
/// the `From<S>` constructor, key-dropping `Drop`, and shared trait impls.
#[macro_export]
macro_rules! impl_tcp_common {
	($transport:ident, $stream_trait:path) => {
		/// TCP transport over a stream `S`, generated by `impl_tcp_common!`.
		pub struct $transport<
			S: $stream_trait,
			P: $crate::crypto::profiles::CryptoProvider = $crate::crypto::profiles::DefaultCryptoProvider,
		> {
			pub(crate) stream: S,
			pub(crate) handler: Option<Box<dyn Fn($crate::Frame) -> Option<$crate::Frame> + Send + Sync>>,
			#[cfg(feature = "transport-policy")]
			pub(crate) restart_policy: Box<dyn $crate::transport::policy::RestartPolicy>,
			#[cfg(feature = "transport-policy")]
			pub(crate) emitter_gate: Box<dyn $crate::policy::GatePolicy>,
			#[cfg(feature = "transport-policy")]
			pub(crate) collector_gate: Box<dyn $crate::policy::GatePolicy>,
			#[cfg(all(feature = "std", feature = "transport-policy"))]
			pub(crate) operation_timeout: Option<core::time::Duration>,
			#[cfg(feature = "x509")]
			pub(crate) trust_store: Option<Arc<dyn $crate::crypto::x509::store::CertificateTrust>>,
			#[cfg(feature = "x509")]
			pub(crate) server_identity: Option<Arc<$crate::x509::Certificate>>,
			#[cfg(feature = "x509")]
			pub(crate) client_certificate: Option<Arc<$crate::x509::Certificate>>,
			#[cfg(feature = "x509")]
			pub(crate) server_certificate_chain: Option<Arc<[$crate::x509::Certificate]>>,
			#[cfg(feature = "x509")]
			pub(crate) client_validators:
				Option<Arc<Vec<Arc<dyn $crate::crypto::x509::policy::CertificateValidation>>>>,
			#[cfg(feature = "x509")]
			pub(crate) peer_certificate: Option<$crate::x509::Certificate>,
			#[cfg(feature = "x509")]
			pub(crate) aad_domain_tag: Option<&'static [u8]>,
			#[cfg(feature = "x509")]
			pub(crate) max_cleartext_envelope: Option<usize>,
			#[cfg(feature = "x509")]
			pub(crate) max_encrypted_envelope: Option<usize>,
			#[cfg(feature = "x509")]
			pub(crate) key_manager: Option<Arc<$crate::transport::handshake::HandshakeKeyManager<P>>>,
			#[cfg(feature = "x509")]
			pub(crate) handshake_state: $crate::transport::handshake::TcpHandshakeState,
			#[cfg(feature = "x509")]
			pub(crate) handshake_timeout: core::time::Duration,
			#[cfg(feature = "x509")]
			pub(crate) session_keys: Option<$crate::crypto::aead::SessionKeys>,
			#[cfg(feature = "x509")]
			pub(crate) mux_config: Option<$crate::transport::handshake::negotiation::TransportOffer>,
			#[cfg(feature = "x509")]
			pub(crate) mux_settings: Option<$crate::transport::handshake::negotiation::MuxSettings>,
			#[cfg(feature = "x509")]
			pub(crate) server_handshake: Option<$crate::transport::handshake::BoxedServerHandshake>,
			#[cfg(feature = "x509")]
			pub(crate) handshake_protocol_kind: $crate::transport::handshake::HandshakeProtocolKind,
			pub(crate) _phantom: core::marker::PhantomData<P>,
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> From<S> for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn from(stream: S) -> Self {
				Self {
					stream,
					handler: None,
					#[cfg(feature = "transport-policy")]
					restart_policy: Box::new($crate::transport::policy::NoRestart),
					#[cfg(feature = "transport-policy")]
					emitter_gate: Box::new($crate::policy::AcceptAllGate),
					#[cfg(feature = "transport-policy")]
					collector_gate: Box::new($crate::policy::AcceptAllGate),
					#[cfg(all(feature = "std", feature = "transport-policy"))]
					operation_timeout: None,
					#[cfg(feature = "x509")]
					trust_store: None,
					#[cfg(feature = "x509")]
					server_identity: None,
					#[cfg(feature = "x509")]
					client_certificate: None,
					#[cfg(feature = "x509")]
					server_certificate_chain: None,
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
					handshake_timeout: core::time::Duration::from_secs(1),
					#[cfg(feature = "x509")]
					session_keys: None,
					#[cfg(feature = "x509")]
					mux_config: None,
					#[cfg(feature = "x509")]
					mux_settings: None,
					#[cfg(feature = "x509")]
					server_handshake: None,
					#[cfg(feature = "x509")]
					handshake_protocol_kind: $crate::transport::handshake::HandshakeProtocolKind::default(),
					_phantom: core::marker::PhantomData,
				}
			}
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::ResponseHandler for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn with_handler<F>(mut self, handler: F) -> Self
			where
				F: Fn($crate::Frame) -> Option<$crate::Frame> + Send + Sync + 'static,
			{
				self.handler = Some(Box::new(handler));
				self
			}

			fn handler(&self) -> Option<&(dyn Fn($crate::Frame) -> Option<$crate::Frame> + Send + Sync)> {
				self.handler.as_ref().map(|h| h.as_ref())
			}
		}

		#[cfg(feature = "x509")]
		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::X509ClientConfig for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			type CryptoProvider = P;

			fn with_trust_store(mut self, store: Arc<dyn $crate::crypto::x509::store::CertificateTrust>) -> Self {
				self.trust_store = Some(store);
				self
			}

			fn with_client_identity(
				mut self,
				cert: Arc<$crate::x509::Certificate>,
				key: Arc<$crate::transport::handshake::HandshakeKeyManager<P>>,
			) -> Self {
				self.client_certificate = Some(cert);
				self.key_manager = Some(key);

				self
			}

			fn with_server_certificate_chain(mut self, chain: Arc<[$crate::x509::Certificate]>) -> Self {
				self.server_certificate_chain = Some(chain);
				self
			}

			fn with_handshake_protocol(mut self, kind: $crate::transport::handshake::HandshakeProtocolKind) -> Self {
				self.handshake_protocol_kind = kind;
				self
			}
		}

		#[cfg(feature = "x509")]
		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			/// Get the peer certificate from a completed mutual authentication handshake.
			/// Returns None if mutual auth was not performed or handshake not complete.
			pub fn peer_certificate(&self) -> Option<&$crate::x509::Certificate> {
				self.peer_certificate.as_ref()
			}

			/// Configure the local transport capability advertisement
			/// (multiplexing). Clients offer it in their handshake opening.
			pub fn with_mux_config(
				mut self,
				config: $crate::transport::handshake::negotiation::TransportOffer,
			) -> Self {
				self.mux_config = Some(config);
				self
			}

			/// Get the negotiated multiplexing settings from a completed
			/// handshake. `None` means the connection is lock-step.
			pub fn negotiated_mux(&self) -> Option<$crate::transport::handshake::negotiation::MuxSettings> {
				self.mux_settings
			}

			/// True while this endpoint expects an encryption handshake that has
			/// not completed yet. Such reads face an unauthenticated peer, so the
			/// read layer applies the tight `HANDSHAKE_MAX_WIRE` cap and the
			/// handshake deadline instead of the general envelope limits.
			pub(crate) fn is_handshake_pending(&self) -> bool {
				let expects_handshake = self.server_identity.is_some()
					|| self.trust_store.is_some()
					|| self.client_validators.is_some()
					|| self.key_manager.is_some();
				expects_handshake
					&& self.handshake_state != $crate::transport::handshake::TcpHandshakeState::Complete
			}
		}

		#[cfg(feature = "transport-policy")]
		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::policy::PolicyConf for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn with_restart<Pol: RestartPolicy + 'static>(mut self, policy: Pol) -> Self {
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

			#[cfg(feature = "std")]
			fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
				self.operation_timeout = Some(timeout);
				self
			}
		}

		#[cfg(all(feature = "transport-policy", not(feature = "x509")))]
		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::MessageEmitter for $transport<S, P>
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
