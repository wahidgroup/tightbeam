use core::marker::PhantomData;

use crate::asn1::Frame;
use crate::transport::error::TransportError;
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

pub(super) struct ClientConnectionParams<P: Protocol> {
	pub(super) addr: Option<P::Address>,
}

pub struct GenericClient<P: Protocol> {
	transport: P::Transport,
	connection_params: ClientConnectionParams<P>,
	_ph: PhantomData<P>,
}

impl<P: Protocol> GenericClient<P> {
	pub fn from_transport(transport: P::Transport) -> Self {
		Self {
			transport,
			connection_params: ClientConnectionParams { addr: None },
			_ph: PhantomData,
		}
	}

	pub(crate) fn from_transport_with_addr(transport: P::Transport, addr: P::Address) -> Self {
		Self {
			transport,
			connection_params: ClientConnectionParams { addr: Some(addr) },
			_ph: PhantomData,
		}
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
	#[cfg(feature = "transport-multiplex")]
	pub(crate) async fn complete_handshake(&mut self) -> TransportResult<()>
	where
		P::Transport: crate::transport::multiplex::MuxConnector,
	{
		use crate::transport::multiplex::MuxConnector;

		self.transport.complete_client_handshake().await
	}

	pub async fn reconnect(&mut self) -> TransportResult<()>
	where
		P::Address: Clone,
	{
		let addr = self
			.connection_params
			.addr
			.as_ref()
			.ok_or(TransportError::ConnectionFailed)?
			.clone();

		let stream = P::connect(addr).await.map_err(|e| e.into())?;
		self.transport = P::create_transport(stream);
		Ok(())
	}
}
