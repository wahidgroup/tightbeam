use crate::transport::tcp::TcpListenerTrait;
use crate::transport::{MessageIO, Pingable, TransportEnvelope, TransportResult};
use crate::Frame;

#[cfg(feature = "transport-policy")]
use crate::{
	policy::GatePolicy,
	transport::{
		error::TransportError,
		policy::RestartPolicy,
		tcp::TcpStreamTrait,
	},
};

/// TCP transport implementation using abstract traits
#[cfg(not(feature = "transport-policy"))]
pub struct TcpTransport<S: TcpStreamTrait> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
}

#[cfg(feature = "transport-policy")]
pub struct TcpTransport<S: TcpStreamTrait> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
	restart_policy: Box<dyn RestartPolicy>,
	emitter_gate: Box<dyn GatePolicy>,
	collector_gate: Box<dyn GatePolicy>,
}

impl<S: TcpStreamTrait> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		// Try to write zero bytes to check if the connection is alive
		self.stream.write_all(&[]).map_err(|e| e.into())
	}
}

// Use the macro to generate common implementations
crate::impl_tcp_common!(TcpTransport, crate::transport::tcp::TcpStreamTrait);

impl<S: TcpStreamTrait> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
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

		// Decode
		let envelope: TransportEnvelope = crate::decode(&buffer)?;
		Ok(envelope)
	}

	async fn write_envelope(&mut self, envelope: &TransportEnvelope) -> TransportResult<()> {
		// Encode and write directly
		let data = crate::encode(envelope)?;
		self.stream.write_all(&data)?;
		Ok(())
	}
}

/// TCP server using abstract listener trait
pub struct TcpServer<L: TcpListenerTrait> {
	listener: L,
}

impl<L: TcpListenerTrait> TcpServer<L>
where
	TransportError: From<L::Error>,
	TransportError: From<<L::Stream as TcpStreamTrait>::Error>,
{
	pub fn from_listener(listener: L) -> Self {
		Self { listener }
	}

	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream>> {
		let (stream, _) = self.listener.accept()?;
		Ok(TcpTransport::from(stream))
	}
}

// std::net implementations when std is available
#[cfg(feature = "std")]
impl TcpStreamTrait for std::net::TcpStream {
	type Error = std::io::Error;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		std::io::Write::write_all(self, buf)
	}

	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		std::io::Read::read_exact(self, buf)
	}
}

#[cfg(feature = "std")]
impl TcpListenerTrait for std::net::TcpListener {
	type Stream = std::net::TcpStream;
	type Error = std::io::Error;

	fn accept(&self) -> Result<(Self::Stream, std::net::SocketAddr), Self::Error> {
		self.accept()
	}
}

#[cfg(test)]
mod tests {
	use std::net::{TcpListener, TcpStream};
	use std::sync::mpsc;

	use super::*;
	use crate::testing::*;
	use crate::transport::{MessageCollector, MessageEmitter};

	#[tokio::test]
	async fn test_tcp_transport_emit_collect() -> TransportResult<()> {
		let message = create_v0_tightbeam(None, None);
		let listener = TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = std::thread::spawn(move || {
			let server = TcpServer::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept().unwrap();

			let rt = tokio::runtime::Runtime::new().unwrap();
			rt.block_on(transport.collect()).unwrap();
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

	#[cfg(feature = "transport-policy")]
	#[tokio::test]
	async fn test_tcp_transport_with_gate_policy() -> TransportResult<()> {
		use std::sync::atomic::{AtomicBool, Ordering};

		use crate::transport::policy::PolicyConfiguration;

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
		let listener = TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = std::thread::spawn(move || {
			let server = TcpServer::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept().unwrap().with_collector_gate(BusyFirstGate::new());

			let rt = tokio::runtime::Runtime::new().unwrap();

			// First collect - gate policy returns Busy
			rt.block_on(transport.collect()).ok();

			// Second collect - gate policy returns Accepted
			rt.block_on(transport.collect()).unwrap();
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
