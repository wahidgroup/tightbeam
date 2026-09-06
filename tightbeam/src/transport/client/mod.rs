use core::marker::PhantomData;

use crate::asn1::Frame;
use crate::transport::{MessageEmitter, Protocol, TransportResult};

#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "derive")]
pub mod macros;
#[cfg(feature = "std")]
pub mod pool;

#[cfg(feature = "builder")]
pub use builder::{ClientBuilder, ClientPolicies};
#[cfg(feature = "std")]
pub use pool::{ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient};

pub struct GenericClient<P: Protocol> {
	transport: P::Transport,
	_ph: PhantomData<P>,
}

impl<P: Protocol> GenericClient<P> {
	pub fn from_transport(transport: P::Transport) -> Self {
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

	/// Drive the client handshake to completion without emitting an
	/// application frame.
	///
	/// The single-flight dial defers its handshake to the first
	/// [`emit`](Self::emit), so a caller that must read peer identity
	/// (for example a colony gate) before disclosing any request warms
	/// the connection here first. A transport without encryption
	/// material completes as a no-op.
	#[cfg(all(feature = "transport-multiplex", feature = "colony"))]
	pub(crate) async fn complete_handshake(&mut self) -> TransportResult<()>
	where
		P::Transport: crate::transport::multiplex::MuxConnector,
	{
		use crate::transport::multiplex::MuxConnector;

		self.transport.complete_client_handshake().await
	}
}
