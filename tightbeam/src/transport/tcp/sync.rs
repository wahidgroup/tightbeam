use core::str::FromStr;

use crate::transport::tcp::TcpListenerTrait;
#[cfg(feature = "x509")]
use crate::transport::EncryptedMessageIO;
use crate::transport::{MessageIO, Pingable, TransportResult};
use crate::Frame;

#[cfg(feature = "transport-policy")]
use crate::{
	policy::GatePolicy,
	transport::{error::TransportError, policy::RestartPolicy, tcp::ProtocolStream},
};

#[cfg(feature = "x509")]
use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeState;
#[cfg(feature = "x509")]
use crate::x509::Certificate;
#[cfg(feature = "x509")]
use std::time::Duration;

pub struct TcpTransport<S: ProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
	#[cfg(feature = "transport-policy")]
	restart_policy: Box<dyn RestartPolicy>,
	#[cfg(feature = "transport-policy")]
	emitter_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "transport-policy")]
	collector_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "x509")]
	server_public_key: Option<Secp256k1VerifyingKey>,
	#[cfg(feature = "x509")]
	enforce_encryption: bool,
	#[cfg(feature = "x509")]
	server_certificate: Option<Certificate>,
	#[cfg(all(feature = "x509", feature = "secp256k1"))]
	signing_key: Option<crate::crypto::sign::ecdsa::Secp256k1SigningKey>,
	#[cfg(feature = "x509")]
	handshake_state: HandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<crate::crypto::aead::Aes256Gcm>,
	#[cfg(all(feature = "x509", feature = "secp256k1"))]
	handshake: Option<crate::transport::handshake::TightBeamHandshake>,
}

impl<S: ProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		// Try to write zero bytes to check if the connection is alive
		self.stream.write_all(&[]).map_err(|e| e.into())
	}
}

// Use the macro to generate common implementations
crate::impl_tcp_common!(TcpTransport, crate::transport::tcp::ProtocolStream);

impl<S: ProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		// Read tag byte
		let mut tag_byte = [0u8; 1];
		self.stream.read_exact(&mut tag_byte)?;

		// Read length encoding
		let mut length_first = [0u8; 1];
		self.stream.read_exact(&mut length_first)?;

		let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
			// Short form
			(vec![], length_first[0] as usize)
		} else {
			// Long form
			let num_length_octets = (length_first[0] & 0x7F) as usize;
			let mut length_octets = vec![0u8; num_length_octets];
			self.stream.read_exact(&mut length_octets)?;

			let length = Self::parse_der_length(length_first[0], &length_octets);
			(length_octets, length)
		};

		// Read content
		let mut content = vec![0u8; content_length];
		self.stream.read_exact(&mut content)?;

		// Reconstruct full DER encoding using the helper
		let buffer = Self::reconstruct_der_encoding(tag_byte[0], length_first[0], &length_octets, &content);
		Ok(buffer)
	}

	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()> {
		self.stream.write_all(buffer)?;
		Ok(())
	}
}

#[cfg(feature = "x509")]
impl<S: ProtocolStream> EncryptedMessageIO<crate::crypto::ecies::EciesSecp256k1Oid> for TcpTransport<S>
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

	fn handshake_state(&self) -> HandshakeState {
		self.handshake_state
	}

	fn set_handshake_state(&mut self, state: HandshakeState) {
		self.handshake_state = state;
	}

	fn server_certificate(&self) -> Option<&Certificate> {
		self.server_certificate.as_ref()
	}

	fn set_symmetric_key(&mut self, key: Self::Encryptor) {
		self.symmetric_key = Some(key);
	}
}

/// TCP server using abstract listener trait
pub struct TcpListener<L: TcpListenerTrait> {
	listener: L,
}

#[cfg(feature = "std")]
impl crate::transport::Protocol for TcpListener<std::net::TcpListener> {
	type Listener = std::net::TcpListener;
	type Stream = std::net::TcpStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<std::net::TcpStream>;
	type Address = crate::transport::tcp::TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		std::net::SocketAddr::from_str("127.0.0.1:0")
			.map(crate::transport::tcp::TightBeamSocketAddr)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = std::net::TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((listener, crate::transport::tcp::TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		std::net::TcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn get_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(crate::transport::tcp::TightBeamSocketAddr(self.listener.local_addr()?))
	}
}

impl<L: TcpListenerTrait> TcpListener<L>
where
	TransportError: From<L::Error>,
	TransportError: From<<L::Stream as ProtocolStream>::Error>,
	L::Stream: ProtocolStream,
{
	pub fn from_listener(listener: L) -> Self {
		Self { listener }
	}

	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream>> {
		let (stream, _) = self.listener.accept()?;
		Ok(TcpTransport::from(stream))
	}
}

#[cfg(test)]
mod tests {
	use std::net::TcpStream;
	use std::sync::mpsc;

	use super::*;
	use crate::testing::*;
	use crate::transport::{MessageCollector, MessageEmitter};

	#[cfg(not(feature = "x509"))]
	#[tokio::test]
	async fn test_tcp_transport_emit_collect() -> TransportResult<()> {
		let message = create_v0_tightbeam(None, None);
		let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = std::thread::spawn(move || {
			let server = TcpListener::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept().unwrap();

			let rt = tokio::runtime::Runtime::new().unwrap();
			rt.block_on(transport.handle_request()).unwrap();
		});

		// Await server ready signal
		let _ = ready_rx.recv();

		let stream = TcpStream::connect(addr)?;
		let mut client_transport = TcpTransport::from(stream);
		let response = client_transport.emit(message.clone(), None).await?;

		server_handle.join().unwrap();

		// Response should be None since no handler is set
		assert_eq!(response, None);
		Ok(())
	}

	#[cfg(all(feature = "transport-policy", not(feature = "x509")))]
	#[tokio::test]
	async fn test_tcp_transport_with_gate_policy() -> TransportResult<()> {
		use std::sync::atomic::{AtomicBool, Ordering};

		use crate::transport::policy::PolicyConf;

		/// Policy: first Busy, then Accepted
		struct BusyFirstGate {
			first: AtomicBool,
		}

		impl BusyFirstGate {
			fn new() -> Self {
				Self { first: AtomicBool::new(true) }
			}
		}

		impl GatePolicy for BusyFirstGate {
			fn evaluate(&self, _msg: &crate::asn1::Frame) -> crate::transport::TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					crate::transport::TransitStatus::Busy
				} else {
					crate::transport::TransitStatus::Accepted
				}
			}
		}

		let message = create_v0_tightbeam(None, None);
		let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = std::thread::spawn(move || {
			let server = TcpListener::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept().unwrap().with_collector_gate(BusyFirstGate::new());

			let rt = tokio::runtime::Runtime::new().unwrap();

			// First handle_request - gate policy returns Busy
			rt.block_on(transport.handle_request()).ok();

			// Second handle_request - gate policy returns Accepted
			rt.block_on(transport.handle_request()).unwrap();
		});

		let _ = ready_rx.recv();

		let stream = TcpStream::connect(addr)?;
		let mut transport = TcpTransport::from(stream);

		// First attempt - server responds with Busy
		let result = transport.emit(message.clone(), None).await;
		assert!(matches!(result, Err(TransportError::Busy)));

		// Second attempt - server responds with Accepted
		transport.emit(message.clone(), None).await?;

		server_handle.join().unwrap();
		Ok(())
	}
}
