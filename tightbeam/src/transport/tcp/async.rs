use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::transport::{
	AsyncListenerTrait, MessageIO, Pingable, Protocol, TransportEnvelope, TransportError, TransportResult,
};
use crate::Frame;

#[cfg(feature = "transport-policy")]
use crate::{policy::GatePolicy, transport::policy::RestartPolicy};

pub trait AsyncProtocolStream: Send + Unpin {
	type Error: Into<TransportError>;
	fn inner_mut(&mut self) -> &mut TcpStream;
}

pub struct TokioStream {
	stream: TcpStream,
}

impl AsyncProtocolStream for TokioStream {
	type Error = std::io::Error;
	fn inner_mut(&mut self) -> &mut TcpStream {
		&mut self.stream
	}
}

impl From<TcpStream> for TokioStream {
	fn from(stream: TcpStream) -> Self {
		Self { stream }
	}
}

pub struct TokioListener {
	listener: TcpListener,
}

impl TokioListener {
	pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
		self.listener.local_addr()
	}

	pub async fn bind(addr: &str) -> std::io::Result<Self> {
		let listener = TcpListener::bind(addr).await?;
		Ok(Self { listener })
	}
}

impl Protocol for TokioListener {
	type Listener = TokioListener;
	type Stream = TokioStream;
	type Error = std::io::Error;
	type Transport = TcpTransportAsync<TokioStream>;
	type Address = std::net::SocketAddr;

	async fn bind(addr: &str) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TokioListener::bind(addr).await?;
		let bound_addr = listener.local_addr()?;
		Ok((listener, bound_addr))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let stream = TcpStream::connect(addr).await?;
		Ok(TokioStream::from(stream))
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransportAsync::from(stream)
	}
}

impl AsyncListenerTrait for TokioListener {
	async fn accept(&self) -> Result<(Self::Stream, Self::Address), Self::Error> {
		let (stream, addr) = self.listener.accept().await?;
		Ok((TokioStream { stream }, addr))
	}
}

#[cfg(not(feature = "transport-policy"))]
pub struct TcpTransportAsync<S: AsyncProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
}

#[cfg(feature = "transport-policy")]
pub struct TcpTransportAsync<S: AsyncProtocolStream> {
	stream: S,
	restart_policy: Box<dyn RestartPolicy>,
	emitter_gate: Box<dyn GatePolicy>,
	collector_gate: Box<dyn GatePolicy>,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
}

impl<S: AsyncProtocolStream> Pingable for TcpTransportAsync<S>
where
	TransportError: From<S::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		// Check if the connection is still valid by calling peer_addr()
		// This is a synchronous method that will fail if the socket is closed
		self.stream.inner_mut().peer_addr().map(|_| ()).map_err(TransportError::IoError)
	}
}

crate::impl_tcp_common!(TcpTransportAsync, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransportAsync<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let s = self.stream.inner_mut();

		// Read tag byte
		let mut tag_byte = [0u8; 1];
		s.read_exact(&mut tag_byte).await?;

		// Read length encoding
		let mut length_first = [0u8; 1];
		s.read_exact(&mut length_first).await?;

		let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
			// Short form
			(vec![], length_first[0] as usize)
		} else {
			// Long form
			let num_length_octets = (length_first[0] & 0x7F) as usize;
			let mut length_octets = vec![0u8; num_length_octets];
			s.read_exact(&mut length_octets).await?;

			let length = Self::parse_der_length(length_first[0], &length_octets);
			(length_octets, length)
		};

		// Read content
		let mut content = vec![0u8; content_length];
		s.read_exact(&mut content).await?;

		// Reconstruct full DER encoding using the helper
		let buffer = Self::reconstruct_der_encoding(tag_byte[0], length_first[0], &length_octets, &content);

		// Decode
		let envelope: TransportEnvelope = crate::decode(&buffer)?;
		Ok(envelope)
	}

	async fn write_envelope(&mut self, envelope: &TransportEnvelope) -> TransportResult<()> {
		let s = self.stream.inner_mut();

		// Encode and write directly
		let data = crate::encode(envelope)?;
		s.write_all(&data).await?;

		Ok(())
	}
}

pub struct TcpServerAsync<L: AsyncListenerTrait> {
	listener: L,
}

impl<L> TcpServerAsync<L>
where
	L: AsyncListenerTrait,
	L::Stream: AsyncProtocolStream<Error = std::io::Error>,
	TransportError: From<L::Error>,
{
	pub async fn accept(&self) -> TransportResult<TcpTransportAsync<L::Stream>> {
		let (stream, _addr) = self.listener.accept().await?;
		Ok(TcpTransportAsync::from(stream))
	}

	/// Accept loop spawning a task per connection.
	pub async fn run<F, Fut>(&self, handler: F) -> TransportResult<()>
	where
		F: Send + Sync + Clone + 'static + Fn(TcpTransportAsync<L::Stream>) -> Fut,
		Fut: core::future::Future<Output = ()> + Send + 'static,
		L::Stream: Send + 'static,
	{
		loop {
			let (stream, _addr) = self.listener.accept().await?;
			let transport = TcpTransportAsync::from(stream);
			let h = handler.clone();

			tokio::spawn(async move { h(transport).await });
		}
	}
}

impl<L> From<L> for TcpServerAsync<L>
where
	L: AsyncListenerTrait,
	L::Stream: AsyncProtocolStream<Error = std::io::Error>,
	TransportError: From<L::Error>,
{
	fn from(listener: L) -> Self {
		Self { listener }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::*;
	use crate::transport::{MessageCollector, MessageEmitter, ResponseHandler, TransitStatus};
	use crate::Frame;

	#[tokio::test]
	async fn async_round_trip() -> TransportResult<()> {
		let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.listener.local_addr().unwrap();
		let server = TcpServerAsync::from(listener);

		let test_message = create_v0_tightbeam(None, None);
		let expected_response = create_v0_tightbeam(None, None);

		// Spawn server task with handler
		let (tx, mut rx) = tokio::sync::mpsc::channel(1);
		let response_msg = expected_response.clone();
		let server_handle = tokio::spawn(async move {
			let mut transport = server.accept().await.unwrap().with_handler(Box::new(move |msg: Frame| {
				let _ = tx.try_send(msg.clone());
				Some(response_msg.clone())
			}));
			transport.collect().await.unwrap();
		});

		// Client
		let stream = TcpStream::connect(addr).await.unwrap();
		let mut transport = TcpTransportAsync::from(TokioStream { stream });
		let response = transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await.unwrap();
		assert_eq!(test_message, received);
		// Response should match what the handler returned
		assert_eq!(response, Some(expected_response));

		server_handle.await.unwrap();
		Ok(())
	}

	#[cfg(feature = "transport-policy")]
	#[tokio::test]
	async fn async_with_gate_policy() -> TransportResult<()> {
		use std::sync::atomic::{AtomicBool, Ordering};

		use crate::transport::policy::PolicyConfiguration;

		/// Policy: First Busy, then Accepted
		struct BusyFirstGate {
			first: AtomicBool,
		}

		impl BusyFirstGate {
			fn new() -> Self {
				Self { first: AtomicBool::new(true) }
			}
		}

		impl GatePolicy for BusyFirstGate {
			fn evaluate(&self, _msg: &Frame) -> TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					TransitStatus::Busy
				} else {
					TransitStatus::Accepted
				}
			}
		}

		let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.listener.local_addr().unwrap();
		let server = TcpServerAsync::from(listener);

		let test_message = create_v0_tightbeam(None, None);

		// Spawn server task
		let (tx, mut rx) = tokio::sync::mpsc::channel(2);
		let server_handle = tokio::spawn(async move {
			let mut transport = server
				.accept()
				.await
				.unwrap()
				.with_collector_gate(BusyFirstGate::new())
				.with_handler(Box::new(move |msg: Frame| {
					let _ = tx.try_send(msg.clone());
					Some(msg.clone())
				}));

			// First collect - gate returns Busy, handler NOT called
			transport.collect().await.unwrap();

			// Second collect - gate returns Accepted, handler IS called
			transport.collect().await.unwrap();
		});

		// Client
		let stream = TcpStream::connect(addr).await.unwrap();
		let mut transport = TcpTransportAsync::from(TokioStream { stream });

		// First attempt - server responds with Busy
		let first = transport.emit(test_message.clone(), None).await;
		assert!(matches!(first, Err(TransportError::Busy)));

		// Second attempt - server responds with Accepted
		transport.emit(test_message.clone(), None).await?;

		// Server should have only received the second message (first was rejected by
		// gate)
		let received = rx.recv().await.unwrap();
		assert_eq!(test_message, received);

		// No more messages should be in the channel
		assert!(rx.try_recv().is_err());

		server_handle.await.unwrap();
		Ok(())
	}
}
