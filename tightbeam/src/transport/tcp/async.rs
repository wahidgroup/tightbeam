use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::transport::{AsyncListenerTrait, MessageIO, Pingable, Protocol, TransportError, TransportResult};
use crate::Frame;

#[cfg(feature = "x509")]
use crate::transport::{EncryptedMessageIO, EncryptedProtocol};
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

	pub async fn accept(&self) -> std::io::Result<(TokioStream, std::net::SocketAddr)> {
		let (stream, addr) = self.listener.accept().await?;
		Ok((TokioStream::from(stream), addr))
	}
}

impl Protocol for TokioListener {
	type Listener = TokioListener;
	type Stream = TokioStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<TokioStream>;
	type Address = crate::transport::tcp::TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		Ok("127.0.0.1:0".parse().expect("Valid default TCP address"))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		Ok((Self { listener }, crate::transport::tcp::TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let stream = TcpStream::connect(addr.0).await?;
		Ok(TokioStream::from(stream))
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn get_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(crate::transport::tcp::TightBeamSocketAddr(self.local_addr()?))
	}
}

#[cfg(feature = "x509")]
impl EncryptedProtocol<crate::crypto::ecies::EciesSecp256k1Oid> for TokioListener {
	type Encryptor = crate::crypto::aead::Aes256Gcm;
	type Decryptor = crate::crypto::aead::Aes256Gcm;

	async fn bind_with(
		addr: Self::Address,
		_cert: crate::crypto::x509::Certificate,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		Ok((Self { listener }, crate::transport::tcp::TightBeamSocketAddr(bound_addr)))
	}
}

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream> EncryptedMessageIO<crate::crypto::ecies::EciesSecp256k1Oid> for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type Encryptor = crate::crypto::aead::Aes256Gcm;
	type Decryptor = crate::crypto::aead::Aes256Gcm;

	fn encryptor(&self) -> TransportResult<&Self::Encryptor> {
		self.symmetric_key.as_ref().ok_or(TransportError::Forbidden)
	}

	fn decryptor(&self) -> TransportResult<&Self::Decryptor> {
		self.symmetric_key.as_ref().ok_or(TransportError::Forbidden)
	}
}

impl AsyncListenerTrait for TokioListener {
	async fn accept(&self) -> Result<(Self::Stream, Self::Address), Self::Error> {
		let (stream, addr) = self.listener.accept().await?;
		Ok((TokioStream::from(stream), crate::transport::tcp::TightBeamSocketAddr(addr)))
	}
}

impl crate::transport::Mycelial for TokioListener {
	async fn get_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
		// Bind to an available port (0.0.0.0:0 lets the OS choose)
		let addr = "0.0.0.0:0"
			.parse::<crate::transport::tcp::TightBeamSocketAddr>()
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
		<TokioListener as Protocol>::bind(addr).await
	}
}

#[cfg(not(feature = "transport-policy"))]
pub struct TcpTransport<S: AsyncProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
}

#[cfg(feature = "transport-policy")]
pub struct TcpTransport<S: AsyncProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
	restart_policy: Box<dyn RestartPolicy>,
	emitter_gate: Box<dyn GatePolicy>,
	collector_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "x509")]
	symmetric_key: Option<crate::crypto::aead::Aes256Gcm>,
}

impl<S: AsyncProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
	TransportError: From<std::io::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		self.stream.inner_mut().peer_addr().map(|_| ()).map_err(TransportError::from)
	}
}

crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		let stream = self.stream.inner_mut();

		let mut tag = [0u8; 1];
		stream.read_exact(&mut tag).await?;

		let mut length_first = [0u8; 1];
		stream.read_exact(&mut length_first).await?;

		let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
			(vec![], length_first[0] as usize)
		} else {
			let octet_count = (length_first[0] & 0x7F) as usize;
			let mut length_octets = vec![0u8; octet_count];
			stream.read_exact(&mut length_octets).await?;
			let length = Self::parse_der_length(length_first[0], &length_octets);
			(length_octets, length)
		};

		let mut content = vec![0u8; content_length];
		stream.read_exact(&mut content).await?;

		let buffer = Self::reconstruct_der_encoding(tag[0], length_first[0], &length_octets, &content);
		Ok(buffer)
	}

	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()> {
		let stream = self.stream.inner_mut();
		stream.write_all(buffer).await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::*;
	use crate::transport::{MessageCollector, MessageEmitter, ResponseHandler, TransitStatus};

	#[tokio::test]
	async fn async_round_trip() -> TransportResult<()> {
		let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();

		let test_message = create_v0_tightbeam(None, None);
		let expected_response = create_v0_tightbeam(None, None);

		let (tx, mut rx) = tokio::sync::mpsc::channel(1);
		let response_msg = expected_response.clone();
		let server = listener;
		let server_handle = tokio::spawn(async move {
			let (stream, _) = server.accept().await.unwrap();
			let mut transport = TcpTransport::from(stream).with_handler(Box::new(move |msg: Frame| {
				let _ = tx.try_send(msg.clone());
				Some(response_msg.clone())
			}));
			transport.collect().await.unwrap();
		});

		let stream = TcpStream::connect(addr).await.unwrap();
		let mut transport = TcpTransport::from(TokioStream::from(stream));
		let response = transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await.unwrap();
		assert_eq!(test_message, received);
		assert_eq!(response, Some(expected_response));

		server_handle.await.unwrap();
		Ok(())
	}

	#[cfg(feature = "transport-policy")]
	#[tokio::test]
	async fn async_with_gate_policy() -> TransportResult<()> {
		use std::sync::atomic::{AtomicBool, Ordering};

		use crate::transport::policy::PolicyConf;

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
		let addr = listener.local_addr().unwrap();
		let server = listener;

		let test_message = create_v0_tightbeam(None, None);

		let (tx, mut rx) = tokio::sync::mpsc::channel(2);
		let server_handle = tokio::spawn(async move {
			let (stream, _) = server.accept().await.unwrap();
			let mut transport = TcpTransport::from(stream)
				.with_collector_gate(BusyFirstGate::new())
				.with_handler(Box::new(move |msg: Frame| {
					let _ = tx.try_send(msg.clone());
					Some(msg.clone())
				}));

			transport.collect().await.ok();
			transport.collect().await.unwrap();
		});

		let stream = TcpStream::connect(addr).await.unwrap();
		let mut transport = TcpTransport::from(TokioStream::from(stream));

		let first = transport.emit(test_message.clone(), None).await;
		assert!(matches!(first, Err(TransportError::Busy)));

		transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await.unwrap();
		assert_eq!(test_message, received);
		assert!(rx.try_recv().is_err());

		server_handle.await.unwrap();
		Ok(())
	}
}
