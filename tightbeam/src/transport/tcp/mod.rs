#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
#[allow(unused_imports)] // The expansion of `impl_tcp_common!` names it.
use std::sync::Arc;

#[cfg(feature = "std")]
use core::fmt;
#[cfg(feature = "std")]
use core::ops;
#[cfg(feature = "std")]
use core::str::FromStr;
#[cfg(all(feature = "std", feature = "tcp"))]
use core::time::Duration;
#[cfg(all(feature = "std", feature = "tcp"))]
use std::io::{Error as IoError, ErrorKind, Read, Write};
#[cfg(feature = "std")]
use std::net::{AddrParseError, SocketAddr};
#[cfg(all(feature = "std", feature = "tcp"))]
use std::net::{TcpListener, TcpStream};

#[cfg(feature = "std")]
use crate::transport::TightBeamAddress;
#[cfg(feature = "tcp")]
use crate::transport::{tcp::sync::TcpTransport, Protocol, ProtocolStream, TransportError};

#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub mod r#async;
#[cfg(feature = "tcp")]
pub mod sync;

/// The blocking TCP listener trait that a networking backend implements to
/// accept a stream and its peer address.
///
/// The house [`TcpListener`](sync::TcpListener) builds each transport from the
/// stream the backend accepts.
///
/// # Examples
///
/// ```
/// use std::io::Error as IoError;
/// use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
///
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::testing::{TestIdentity, TestKey};
/// use tightbeam::transport::tcp::sync::TcpListener;
/// use tightbeam::transport::tcp::TcpListenerTrait;
/// use tightbeam::transport::TransportEncryptionConfig;
///
/// /// A backend that accepts on a socket it bound itself.
/// struct Backend(NetTcpListener);
///
/// impl TcpListenerTrait for Backend {
///     type Stream = NetTcpStream;
///     type Error = IoError;
///
///     fn accept(&self) -> Result<(NetTcpStream, SocketAddr), IoError> {
///         self.0.accept()
///     }
/// }
///
/// let backend = Backend(NetTcpListener::bind("127.0.0.1:0")?);
/// let identity = TestIdentity::of(&TestKey::insecure_fixed_signing());
/// let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
/// let _listener = TcpListener::from_listener_with(backend, config)?;
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[cfg(feature = "tcp")]
pub trait TcpListenerTrait: Send {
	/// The stream of one accepted connection.
	type Stream: ProtocolStream;
	/// The error the listener reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Accepts one connection and returns its stream and peer address.
	///
	/// # Errors
	///
	/// - `Self::Error` -- the listener accepts no connection.
	fn accept(&self) -> Result<(Self::Stream, SocketAddr), Self::Error>;
}

/// The socket address of a `no_std` build.
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
	type CryptoProvider = crate::crypto::profiles::DefaultCryptoProvider;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		"127.0.0.1:0"
			.parse()
			.map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid default address"))
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((listener, TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		TcpStream::connect(addr.0)
	}

	/// Connects within `budget` through `TcpStream::connect_timeout`, because a
	/// blocking connect holds its thread, so no race of the dial pre-empts it.
	async fn connect_within(addr: Self::Address, budget: Duration) -> Result<Self::Stream, Self::Error> {
		TcpStream::connect_timeout(&addr.0, budget)
	}

	fn create_transport(
		stream: Self::Stream,
		config: crate::transport::EndpointConfig<Self::CryptoProvider>,
	) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

// The `EncryptedProtocol` impl of sync TCP sits on the wrapper in `sync.rs`.

#[cfg(all(feature = "std", feature = "tcp"))]
impl ProtocolStream for TcpStream {
	type Error = IoError;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		Write::write_all(self, buf)
	}

	/// A send that a signal interrupts runs again, as `write_all` does.
	fn write_some(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
		loop {
			match Write::write(self, buf) {
				Err(error) if error.kind() == ErrorKind::Interrupted => continue,
				sent => return sent,
			}
		}
	}

	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		Read::read_exact(self, buf)
	}

	/// A receive that a signal interrupts runs again, as `read_exact` does.
	fn read_some(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
		loop {
			match Read::read(self, buf) {
				Err(error) if error.kind() == ErrorKind::Interrupted => continue,
				received => return received,
			}
		}
	}

	fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Self::Error> {
		self.set_read_timeout(timeout)?;
		self.set_write_timeout(timeout)?;
		Ok(())
	}
}

/// A newtype over `SocketAddr` that implements `Into<Vec<u8>>`.
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

/// Generates the transport implementation that the sync and the async TCP
/// transports share.
///
/// It defines the transport struct, the single source of the field list, with
/// its one constructor and the shared trait impls.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_tcp_common {
	($transport:ident, $stream_trait:path) => {
		/// A TCP transport over a stream `S`, generated by `impl_tcp_common!`.
		pub struct $transport<
			S: $stream_trait,
			P: $crate::crypto::profiles::CryptoProvider = $crate::crypto::profiles::DefaultCryptoProvider,
		> {
			pub(crate) stream: S,
			pub(crate) restart_policy: Box<dyn $crate::transport::policy::RestartPolicy>,
			pub(crate) emitter_gate: $crate::policy::GateChain,
			pub(crate) collector_gate: $crate::policy::GateChain,
			pub(crate) state: $crate::transport::state::SessionState<P>,
			pub(crate) limits: $crate::transport::TransportLimits,
			pub(crate) clock: Arc<dyn $crate::utils::time::Clock>,
			pub(crate) server_handshake: Option<$crate::transport::handshake::BoxedServerHandshake>,
			/// The instrumentation collector of this connection.
			#[cfg(feature = "instrument")]
			pub(crate) trace: Option<$crate::trace::TraceCollector>,
			/// The peer address that a listener accepted this connection from,
			/// which the acceptance record names.
			#[cfg(feature = "instrument")]
			pub(crate) accepted_from: Option<core::net::SocketAddr>,
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			/// Builds a transport over `stream` from `config`. It is the one
			/// constructor.
			///
			/// The provisioning already answered the dialer rule, so the
			/// session starts where it says: `Provisioned` when it names a peer
			/// authority, and `Cleartext` only when it names cleartext.
			pub fn new(stream: S, config: $crate::transport::EndpointConfig<P>) -> Self {
				let $crate::transport::EndpointConfig {
					encryption,
					negotiation,
					limits,
					clock,
					#[cfg(feature = "instrument")]
					trace,
				} = config;

				Self {
					stream,
					restart_policy: Box::new($crate::transport::policy::NoRestart),
					emitter_gate: $crate::policy::GateChain::default(),
					collector_gate: $crate::policy::GateChain::default(),
					state: $crate::transport::state::SessionState::negotiating(encryption, negotiation),
					limits,
					clock,
					server_handshake: None,
					#[cfg(feature = "instrument")]
					trace,
					#[cfg(feature = "instrument")]
					accepted_from: None,
				}
			}

			/// Returns the validated peer certificate of the established
			/// session, or `None` when no session is established or the peer
			/// presented none.
			pub fn peer_certificate(&self) -> Option<&$crate::x509::Certificate> {
				self.state.peer_certificate()
			}

			/// Returns the negotiated multiplexing settings, or `None` for a
			/// single-flight session.
			pub fn negotiated_mux(&self) -> Option<$crate::transport::handshake::negotiation::MuxSettings> {
				self.state.established()?.mux()
			}

			/// Returns the dual-signed session receipt of a budget-bearing
			/// handshake, if the session holds one.
			pub fn session_receipt(&self) -> Option<&$crate::transport::handshake::receipt::StoredReceipt> {
				self.state.receipt()
			}

			/// Overrides the budget-grant policy that the server consults
			/// between the client's transport offer and its accept. The default
			/// grants the ceiling of the local configuration.
			#[must_use]
			pub fn with_transport_authorizer(
				mut self,
				authorizer: Arc<dyn $crate::transport::handshake::negotiation::TransportAuthorizer>,
			) -> Self {
				self.state.authorize_transport(authorizer);
				self
			}

			/// Sets the observer of session outcomes for the budget-bearing
			/// handshakes that this endpoint serves.
			#[must_use]
			pub fn with_session_observer(
				mut self,
				observer: Arc<dyn $crate::transport::handshake::receipt::SessionObserver>,
			) -> Self {
				self.state.observe_sessions(observer);
				self
			}

			/// Sets the approver that this endpoint consults before it
			/// countersigns a challenge-bearing receipt.
			#[must_use]
			pub fn with_receipt_approver(
				mut self,
				approver: Arc<dyn $crate::transport::handshake::receipt::ReceiptApprover>,
			) -> Self {
				self.state.approve_receipts(approver);
				self
			}

			/// Sets the handshake protocol that this endpoint runs once
			/// provisioned.
			#[must_use]
			pub fn with_handshake_protocol(
				mut self,
				kind: $crate::transport::handshake::HandshakeProtocolKind,
			) -> Self {
				self.state.select_handshake(kind);
				self
			}

			/// Attaches the connection's instrumentation collector.
			#[cfg(feature = "instrument")]
			#[must_use]
			pub fn with_trace(mut self, trace: $crate::trace::TraceCollector) -> Self {
				self.trace = Some(trace);
				self
			}

			/// Returns a share of the connection's instrumentation collector,
			/// if one is attached.
			#[cfg(feature = "instrument")]
			pub fn trace(&self) -> Option<$crate::trace::TraceCollector> {
				self.trace.as_ref().map($crate::trace::TraceCollector::share)
			}

			/// Returns this connection with `peer` as the address that a
			/// listener accepted it from.
			// The async expansion has its one caller in the tokio listener.
			#[cfg(feature = "instrument")]
			#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
			#[must_use]
			pub(crate) fn accepted_from_peer(mut self, peer: core::net::SocketAddr) -> Self {
				self.accepted_from = Some(peer);
				self
			}
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::policy::RestartConfig
			for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn with_restart<Pol: RestartPolicy + 'static>(mut self, policy: Pol) -> Self {
				self.restart_policy = Box::new(policy);
				self
			}
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::policy::EmitterGateConfig
			for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn with_emitter_gate<G: GatePolicy + 'static>(mut self, gate: G) -> Self {
				self.emitter_gate.push(gate);
				self
			}
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider>
			$crate::transport::policy::CollectorGateConfig for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn with_collector_gate<G: GatePolicy + 'static>(mut self, gate: G) -> Self {
				self.collector_gate.push(gate);
				self
			}
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::policy::TimeoutConfig
			for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			fn with_timeout(mut self, timeout: core::time::Duration) -> Self {
				self.limits.operation_timeout = timeout;
				self
			}
		}

		// This impl is the one audit source of gate verdicts for every
		// collector plane this transport serves.
		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::GateAudit
			for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			#[cfg(feature = "instrument")]
			fn audit_trace(&self) -> Option<&$crate::trace::TraceCollector> {
				self.trace.as_ref()
			}
		}

		// Each transport implements the seal by name, one impl per type, so
		// only the types of this crate reach the traits it guards.
		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider> $crate::transport::state::sealed::Sealed
			for $transport<S, P>
		{
		}

		impl<S: $stream_trait, P: $crate::crypto::profiles::CryptoProvider + Send + Sync + 'static>
			$crate::transport::state::EncryptedProtocolState for $transport<S, P>
		where
			TransportError: From<S::Error>,
		{
			type CryptoProvider = P;

			fn session_state(&self) -> &$crate::transport::state::SessionState<P> {
				&self.state
			}

			fn session_state_mut(&mut self) -> &mut $crate::transport::state::SessionState<P> {
				&mut self.state
			}

			fn limits(&self) -> &$crate::transport::TransportLimits {
				&self.limits
			}

			#[cfg(feature = "instrument")]
			fn to_trace_ref(&self) -> Option<&TraceCollector> {
				self.trace.as_ref()
			}

			// `Self::with_trace` resolves to the inherent builder ahead of this
			// method, so the call forwards to the one setter of the trail.
			#[cfg(feature = "instrument")]
			fn with_trace(self, trace: TraceCollector) -> Self {
				Self::with_trace(self, trace)
			}

			#[cfg(feature = "instrument")]
			fn accepted_from(&self) -> Option<core::net::SocketAddr> {
				self.accepted_from
			}
		}
	};
}
