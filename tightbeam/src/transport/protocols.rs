//! Protocol trait abstractions defining what a protocol is and what it can do

use core::future::Future;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::transport::error::TransportError;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;
#[cfg(feature = "x509")]
use crate::transport::TransportEncryptionConfig;
#[cfg(feature = "x509")]
use crate::x509::Certificate;

/// Marker trait for applications to handle the address the way they wish
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}

/// Stream trait - defines how to read and write
pub trait ProtocolStream: Send {
	type Error: Into<TransportError>;

	/// Write all bytes to the stream
	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;

	/// Read exact bytes from the stream
	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

	/// Set read and write timeouts on the underlying stream.
	/// Returns Ok(()) if timeouts were set, or Err if not supported.
	/// This is used for operation-level timeouts in blocking I/O.
	#[cfg(feature = "std")]
	fn set_timeout(&mut self, timeout: Option<std::time::Duration>) -> Result<(), Self::Error> {
		let _ = timeout;
		// Default implementation: no-op (not supported)
		Ok(())
	}

	/// Set read and write timeouts on the underlying stream.
	/// Returns Ok(()) if timeouts were set, or Err if not supported.
	/// This is used for operation-level timeouts in blocking I/O.
	#[cfg(not(feature = "std"))]
	fn set_timeout(&mut self, timeout: Option<core::time::Duration>) -> Result<(), Self::Error> {
		let _ = timeout;
		// Default implementation: no-op (not supported)
		Ok(())
	}
}

/// Protocol trait - defines how to bind and connect
pub trait Protocol {
	type Listener: Send;
	type Stream: Send;
	type Transport: Send;
	type Error: Into<TransportError>;
	type Address: TightBeamAddress;

	/// Get a default address for binding to any available port/endpoint
	/// This is protocol-specific (e.g., "127.0.0.1:0" for TCP)
	fn default_bind_address() -> Result<Self::Address, Self::Error>;

	/// Bind to an address and return listener + actual bound address
	fn bind(addr: Self::Address) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;

	/// Connect to an address
	fn connect(addr: Self::Address) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;

	/// Create transport from stream
	fn create_transport(stream: Self::Stream) -> Self::Transport;

	// Get the tightbeam address for this protocol
	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error>;
}

#[cfg(feature = "x509")]
pub trait EncryptedProtocol: Protocol {
	type Encryptor: Send;
	type Decryptor: Send;

	/// Bind to an address with transport encryption configuration
	fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig,
	) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// Trait for configuring client-side X.509 mutual authentication.
/// Supports multiple server certificates for rotation and multi-CA scenarios.
#[cfg(feature = "x509")]
pub trait X509ClientConfig: Sized {
	/// Add a server certificate for verification.
	fn with_server_certificate(self, cert: Certificate) -> Self;

	/// Add multiple server certificates at once.
	fn with_server_certificates(self, certs: impl IntoIterator<Item = Certificate>) -> Self;

	/// Set server certificate validators for strict validation.
	fn with_server_validators(self, validators: Arc<Vec<Arc<dyn CertificateValidation>>>) -> Self;

	/// Set the client's identity for mutual authentication.
	/// The client presents this certificate to the server when requested.
	fn with_client_identity(self, cert: Certificate, key: HandshakeKeyManager) -> Self;
}

/// This protocol can operate as a mycelial network (ie. TCP SocketAddress)
pub trait Mycelial: Protocol {
	fn try_available_connect(
		&self,
	) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// Async listener trait
pub trait AsyncListenerTrait: Protocol + Send {
	#[allow(async_fn_in_trait)]
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error>;
}

/// Protocol supports persistent connections (keep-alive)
///
/// This trait allows protocols to opt-in to connection reuse,
/// enabling TLS handshakes to occur once per connection lifecycle
/// rather than per message.
pub trait PersistentConnection: Protocol {
	/// Check if underlying transport is still connected
	///
	/// Returns false on EOF, socket error, or explicit close.
	/// Protocols should use lightweight checks (e.g., peek) without
	/// blocking or allocating.
	fn is_connected(transport: &Self::Transport) -> bool;

	/// Attempt graceful close (best effort, no panic)
	///
	/// This is a best-effort operation that should not panic.
	/// Implementations may be no-ops if graceful close is not
	/// supported by the underlying protocol.
	fn try_close(transport: &mut Self::Transport);
}
