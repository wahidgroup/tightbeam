use core::marker::PhantomData;
#[cfg(feature = "std")]
use core::time::Duration;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::transport::{MessageEmitter, Protocol, TransportResult};

#[cfg(feature = "std")]
use crate::crypto::sign::SigningIdentity;
#[cfg(feature = "std")]
use crate::crypto::x509::store::CertificateTrust;

pub mod macros;

mod builder;

#[cfg(feature = "std")]
mod pool;

pub use builder::{ClientBuilder, ClientPolicies, DynGate, DynRestart};

#[cfg(feature = "std")]
pub use pool::{ConnectionPool, ConnectionPoolBuilder, PoolConfig, PooledClient};

/// The shared builder surface of direct clients and connection pools.
///
/// [`ClientBuilder`] and [`ConnectionPoolBuilder`] both implement this trait,
/// so callers configure timeouts and identity the same way. The crate builds
/// each client and pool through one of these two builders, so the trait is
/// sealed, and a builder of another type fails to compile:
///
/// ```compile_fail,E0277
/// use core::time::Duration;
/// use std::sync::Arc;
///
/// use tightbeam::crypto::sign::SigningIdentity;
/// use tightbeam::crypto::x509::store::CertificateTrust;
/// use tightbeam::transport::{ConnectionBuilder, Protocol};
///
/// struct Forged;
///
/// impl<P: Protocol> ConnectionBuilder<P> for Forged {
///     type Output = Self;
///
///     fn with_timeout(self, _timeout: Duration) -> Self {
///         self
///     }
///
///     fn with_trust_store(self, _store: Arc<dyn CertificateTrust>) -> Self {
///         self
///     }
///
///     fn with_client_identity(self, _identity: SigningIdentity) -> Self {
///         self
///     }
///
///     fn build(self) -> Self {
///         self
///     }
/// }
/// ```
#[cfg(feature = "std")]
pub trait ConnectionBuilder<P: Protocol>: sealed::Sealed + Sized {
	/// The client or pool that [`ConnectionBuilder::build`] produces.
	type Output;

	/// Caps how long a connect or an I/O wait may block.
	fn with_timeout(self, timeout: Duration) -> Self;

	/// Sets the trust anchors that validate the peer certificate.
	fn with_trust_store(self, store: Arc<dyn CertificateTrust>) -> Self;

	/// Sets the client certificate and the key that proves it, for mutual
	/// authentication.
	///
	/// [`SigningIdentity::from_spec`] decodes a certificate specification
	/// into one and checks the key against it, so the fallible step happens
	/// once, before the builder. A clone of the identity clones its `Arc`
	/// handles and copies the `sid`, so every dial shares one certificate.
	///
	/// [`SigningIdentity::from_spec`]: crate::crypto::sign::SigningIdentity::from_spec
	fn with_client_identity(self, identity: SigningIdentity) -> Self;

	/// Finishes the configuration and produces the client or pool.
	fn build(self) -> Self::Output;
}

#[cfg(feature = "std")]
mod sealed {
	/// The seal of [`ConnectionBuilder`](super::ConnectionBuilder),
	/// implemented by its two builders alone.
	pub trait Sealed {}
}

pub struct GenericClient<P: Protocol> {
	transport: P::Transport,
	_ph: PhantomData<P>,
}

impl<P: Protocol> GenericClient<P> {
	pub(crate) fn from_transport(transport: P::Transport) -> Self {
		Self { transport, _ph: PhantomData }
	}

	pub fn transport(&self) -> &P::Transport {
		&self.transport
	}

	pub fn into_transport(self) -> P::Transport {
		self.transport
	}

	#[allow(async_fn_in_trait)]
	pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>>
	where
		P::Transport: MessageEmitter,
	{
		self.transport.emit(frame, attempt).await
	}

	/// Drives the client handshake to completion ahead of the first
	/// application frame.
	///
	/// The single-flight dial defers its handshake to the first
	/// [`emit`](Self::emit). A caller that must read peer identity before it
	/// discloses any request, as a membership proof does, warms the connection
	/// here first. With no encryption material, the call returns at once.
	#[cfg(all(feature = "transport-multiplex", feature = "colony"))]
	pub(crate) async fn complete_handshake(&mut self) -> TransportResult<()>
	where
		P::Transport: crate::transport::multiplex::MuxConnector,
	{
		use crate::transport::multiplex::MuxConnector;

		self.transport.complete_client_handshake().await
	}
}
