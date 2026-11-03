//! The in-memory "laser" protocol stands in for a free-space optical link. It
//! carries bytes over duplex pipes in an address space of its own.
//!
//! It implements the byte traits ([`AsyncByteRead`], [`AsyncByteWrite`], and
//! [`AsyncByteStream`]) and the listener traits, as an outside transport crate
//! writes them. DER framing, handshakes, multiplexing, and the colony stack
//! all arrive through library code, so the colony suite proves that the stack
//! runs over a transport other than TCP.

use core::fmt;
use core::str::FromStr;
use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use tightbeam::crypto::aead::RuntimeAead;
use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use tightbeam::transport::tcp::r#async::TcpTransport;
use tightbeam::transport::{
	AsyncByteRead, AsyncByteStream, AsyncByteWrite, AsyncListenerTrait, EncryptedProtocol, EndpointConfig,
	PersistentConnection, Protocol, SplittableStream, TightBeamAddress, TransportEncryptionConfig, TransportError,
};

/// The buffered capacity of each direction of a laser link.
const BEAM_CAPACITY: usize = 64 * 1024;

/// An address in the laser airspace, written `laser://N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LaserAddr(
	/// The slot in the airspace, where [`LaserAddr::ANY`] asks for a fresh one.
	pub u64,
);

impl LaserAddr {
	/// The address that binds to any slot, for which the airspace assigns a
	/// fresh one.
	pub const ANY: LaserAddr = LaserAddr(0);
}

impl fmt::Display for LaserAddr {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "laser://{}", self.0)
	}
}

impl FromStr for LaserAddr {
	type Err = TransportError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let id = s
			.strip_prefix("laser://")
			.and_then(|raw| raw.parse().ok())
			.ok_or(TransportError::InvalidMessage)?;
		Ok(Self(id))
	}
}

impl From<LaserAddr> for Vec<u8> {
	fn from(addr: LaserAddr) -> Self {
		addr.to_string().into_bytes()
	}
}

impl TightBeamAddress for LaserAddr {}

/// One end of a laser link: a byte pipe with no framing of its own.
pub struct LaserStream(DuplexStream);

impl LaserStream {
	/// Both ends of one link, apart from any listener.
	pub fn pair() -> (Self, Self) {
		let (near, far) = duplex(BEAM_CAPACITY);
		(Self(near), Self(far))
	}
}

impl AsyncByteRead for LaserStream {
	type Error = TransportError;

	async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		self.0.read_exact(buf).await.map(|_| ()).map_err(TransportError::IoError)
	}
}

impl AsyncByteWrite for LaserStream {
	type Error = TransportError;

	async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		self.0.write_all(buf).await.map_err(TransportError::IoError)
	}
}

impl AsyncByteStream for LaserStream {
	fn is_alive(&self) -> bool {
		// A pipe that tore down fails its next read or write, which reports the
		// loss of the link.
		true
	}
}

/// The read half of a split laser link, for the concurrent mux drivers.
pub struct LaserReadHalf(ReadHalf<DuplexStream>);

impl AsyncByteRead for LaserReadHalf {
	type Error = TransportError;

	async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		self.0.read_exact(buf).await.map(|_| ()).map_err(TransportError::IoError)
	}
}

/// The write half of a split laser link.
pub struct LaserWriteHalf(WriteHalf<DuplexStream>);

impl AsyncByteWrite for LaserWriteHalf {
	type Error = TransportError;

	async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		self.0.write_all(buf).await.map_err(TransportError::IoError)
	}
}

impl SplittableStream for LaserStream {
	type ReadHalf = LaserReadHalf;
	type WriteHalf = LaserWriteHalf;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		let (read, write) = split(self.0);
		(LaserReadHalf(read), LaserWriteHalf(write))
	}
}

/// The laser transport is the shared transport machinery over a
/// [`LaserStream`]: handshakes, multiplexing, and message collection all
/// come from the library.
pub type LaserTransport<P = DefaultCryptoProvider> = TcpTransport<LaserStream, P>;

/// The registry of the airspace, which maps each address to the channel of
/// its incoming beams.
type Airspace = Mutex<HashMap<u64, mpsc::UnboundedSender<DuplexStream>>>;

/// The registry of every bound laser address in the process.
fn airspace() -> &'static Airspace {
	static AIRSPACE: OnceLock<Airspace> = OnceLock::new();
	AIRSPACE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The next slot of the airspace, counted from 1 across the process.
fn next_addr() -> u64 {
	static NEXT: AtomicU64 = AtomicU64::new(1);
	NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The error that a poisoned lock of the airspace reads as.
fn poisoned() -> TransportError {
	TransportError::InvalidState
}

/// The listener half of a laser endpoint. It builds each beam it accepts from
/// one endpoint configuration, encrypted or cleartext.
pub struct LaserListener<P: CryptoProvider = DefaultCryptoProvider> {
	incoming: AsyncMutex<mpsc::UnboundedReceiver<DuplexStream>>,
	config: EndpointConfig<P>,
}

impl<P: CryptoProvider + Send + Sync + 'static> LaserListener<P> {
	fn bind_airspace(addr: LaserAddr) -> Result<(mpsc::UnboundedReceiver<DuplexStream>, LaserAddr), TransportError> {
		let id = if addr.0 == 0 {
			next_addr()
		} else {
			addr.0
		};
		let (tx, rx) = mpsc::unbounded_channel();

		airspace().lock().map_err(|_| poisoned())?.insert(id, tx);
		Ok((rx, LaserAddr(id)))
	}

	/// Accepts one beam as a transport built from the configuration of this
	/// listener.
	pub async fn accept(&self) -> Result<(LaserTransport<P>, LaserAddr), TransportError> {
		let stream = self
			.incoming
			.lock()
			.await
			.recv()
			.await
			.ok_or(TransportError::ConnectionClosed)?;

		let transport = LaserTransport::new(LaserStream(stream), self.config.clone());
		Ok((transport, LaserAddr(0)))
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> Protocol for LaserListener<P> {
	type Listener = LaserListener<P>;
	type Stream = LaserStream;
	type Transport = LaserTransport<P>;
	type Error = TransportError;
	type Address = LaserAddr;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		Ok(LaserAddr::ANY)
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let (incoming, bound) = Self::bind_airspace(addr)?;
		let incoming = AsyncMutex::new(incoming);
		Ok((Self { incoming, config: EndpointConfig::cleartext() }, bound))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let acceptor = airspace()
			.lock()
			.map_err(|_| poisoned())?
			.get(&addr.0)
			.cloned()
			.ok_or(TransportError::ConnectionClosed)?;

		let (client_end, server_end) = duplex(BEAM_CAPACITY);
		acceptor.send(server_end).map_err(|_| TransportError::ConnectionClosed)?;
		Ok(LaserStream(client_end))
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		LaserTransport::new(stream, config)
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> EncryptedProtocol for LaserListener<P> {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let (incoming, bound) = Self::bind_airspace(addr)?;
		let incoming = AsyncMutex::new(incoming);
		Ok((Self { incoming, config: EndpointConfig::try_from(config)? }, bound))
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> AsyncListenerTrait for LaserListener<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		LaserListener::accept(self).await
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> PersistentConnection for LaserListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// The pipe closes when both ends drop.
	}
}
