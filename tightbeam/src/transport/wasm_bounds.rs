//! A protocol whose listener, stream, transport, address, and futures hold
//! `!Send` handles, as a browser socket does, compiles on `wasm32` and
//! provisions a client from `ClientBuilder::on_clock`. The wasm32 check of the
//! feature script builds this proof, so a `Send` bound on one of them fails
//! that check.

use core::future::ready;
use core::marker::PhantomData;
use std::sync::Arc;

use crate::clock::Clock;
use crate::transport::client::GenericClient;
use crate::transport::error::TransportError;
use crate::transport::handshake::HandshakeProvider;
use crate::transport::protocols::{
	AsyncListenerTrait, AsyncProtocolStream, EncryptedProtocol, Protocol, TightBeamAddress,
};
use crate::transport::{
	ClientBuilder, ConnectionBuilder, EndpointConfig, TcpTransport, TransportEncryptionConfig, TransportResult,
};

/// A JavaScript handle, which the raw pointer makes `!Send`, as `JsValue` is.
#[derive(Clone)]
struct Handle(PhantomData<*const ()>);

impl Handle {
	fn new() -> Self {
		Self(PhantomData)
	}

	/// Holds the handle across an await, so the caller's future is `!Send`.
	async fn held(self) -> Self {
		ready(()).await;
		self
	}
}

impl From<Handle> for Vec<u8> {
	fn from(_: Handle) -> Self {
		Vec::new()
	}
}

impl TightBeamAddress for Handle {}

impl AsyncProtocolStream for Handle {
	type Error = TransportError;

	async fn read_frame(&mut self, _cap: usize) -> Result<Vec<u8>, Self::Error> {
		Err(TransportError::InvalidState)
	}

	async fn write_frame(&mut self, _buffer: &[u8]) -> Result<(), Self::Error> {
		Err(TransportError::InvalidState)
	}

	fn is_alive(&self) -> bool {
		false
	}
}

struct Browser<P>(Handle, PhantomData<fn() -> P>);

impl<P: HandshakeProvider> Protocol for Browser<P> {
	type Listener = Handle;
	type Stream = Handle;
	type Transport = TcpTransport<Handle, P>;
	type Error = TransportError;
	type Address = Handle;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		Ok(Handle::new())
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		Ok((Handle::new(), addr.held().await))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		Ok(addr.held().await)
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

impl<P: HandshakeProvider> EncryptedProtocol for Browser<P> {
	type Encryptor = Handle;
	type Decryptor = Handle;

	async fn bind_with(
		addr: Self::Address,
		_config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		Ok((Handle::new(), addr.held().await))
	}
}

impl<P: HandshakeProvider> AsyncListenerTrait for Browser<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		Err(TransportError::InvalidState)
	}
}

fn started<P: HandshakeProvider>(clock: Arc<dyn Clock>) -> ClientBuilder<Browser<P>> {
	ClientBuilder::on_clock(clock)
}

fn adopted<P: HandshakeProvider>(
	builder: ClientBuilder<Browser<P>>,
	stream: Handle,
) -> TransportResult<GenericClient<Browser<P>>> {
	builder.adopt(stream)
}

async fn connected<P: HandshakeProvider>(
	builder: ClientBuilder<Browser<P>>,
	addr: Handle,
) -> TransportResult<GenericClient<Browser<P>>> {
	builder.connect(addr).await
}

fn built<P: HandshakeProvider>(builder: ClientBuilder<Browser<P>>) -> ClientBuilder<Browser<P>> {
	builder.build()
}
