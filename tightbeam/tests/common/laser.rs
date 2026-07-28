//! In-memory "laser" protocol: a free-space optical link stand-in built
//! from byte-level duplex pipes with its own address space.
//!
//! Implements only the byte traits ([`AsyncByteRead`] / [`AsyncByteWrite`] /
//! [`AsyncByteStream`]) plus the listener traits, exactly what an external
//! transport crate would write: DER framing, handshakes, multiplexing, and
//! the colony stack all arrive through library code. Proof that nothing in
//! the stack is coupled to TCP.

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
	AsyncByteRead, AsyncByteStream, AsyncByteWrite, AsyncListenerTrait, EncryptedProtocol, PersistentConnection,
	Protocol, SplittableStream, TightBeamAddress, TransportEncryptionConfig, TransportError,
};

/// Buffered capacity of one laser link direction.
const BEAM_CAPACITY: usize = 64 * 1024;

/// Address in the laser airspace: `laser://N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LaserAddr(
	/// Airspace slot; [`LaserAddr::ANY`] asks bind for a fresh one.
	pub u64,
);

impl LaserAddr {
	/// Bind-to-any address: the airspace assigns a fresh slot.
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

/// One end of a laser link: a byte pipe, no framing of its own.
pub struct LaserStream(DuplexStream);

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
		// Liveness surfaces as read/write errors on a torn-down pipe.
		true
	}
}

/// Read half of a split laser link, for the concurrent mux drivers.
pub struct LaserReadHalf(ReadHalf<DuplexStream>);

impl AsyncByteRead for LaserReadHalf {
	type Error = TransportError;

	async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		self.0.read_exact(buf).await.map(|_| ()).map_err(TransportError::IoError)
	}
}

/// Write half of a split laser link.
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
/// come from the library, none from this fixture.
pub type LaserTransport<P = DefaultCryptoProvider> = TcpTransport<LaserStream, P>;

/// Airspace registry: addresses to incoming-beam channels.
type Airspace = Mutex<HashMap<u64, mpsc::UnboundedSender<DuplexStream>>>;

fn airspace() -> &'static Airspace {
	static AIRSPACE: OnceLock<Airspace> = OnceLock::new();
	AIRSPACE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_addr() -> u64 {
	static NEXT: AtomicU64 = AtomicU64::new(1);
	NEXT.fetch_add(1, Ordering::Relaxed)
}

fn poisoned() -> TransportError {
	TransportError::InvalidState
}

/// Listener half of a laser endpoint, with optional server encryption.
pub struct LaserListener<P: CryptoProvider = DefaultCryptoProvider> {
	incoming: AsyncMutex<mpsc::UnboundedReceiver<DuplexStream>>,
	config: Option<TransportEncryptionConfig<P>>,
}

impl<P: CryptoProvider + Send + Sync> LaserListener<P> {
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

	/// Accept one beam, applying server encryption when configured.
	pub async fn accept(&self) -> Result<(LaserTransport<P>, LaserAddr), TransportError> {
		let stream = self
			.incoming
			.lock()
			.await
			.recv()
			.await
			.ok_or(TransportError::ConnectionClosed)?;

		let mut transport = LaserTransport::from(LaserStream(stream));
		if let Some(config) = &self.config {
			transport = transport.with_server_encryption(config.clone());
		}

		Ok((transport, LaserAddr(0)))
	}
}

impl<P: CryptoProvider + Send + Sync> Protocol for LaserListener<P> {
	type Listener = LaserListener<P>;
	type Stream = LaserStream;
	type Transport = LaserTransport<P>;
	type Error = TransportError;
	type Address = LaserAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		Ok(LaserAddr::ANY)
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let (incoming, bound) = Self::bind_airspace(addr)?;
		let incoming = AsyncMutex::new(incoming);
		Ok((Self { incoming, config: None }, bound))
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

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		LaserTransport::from(stream)
	}
}

impl<P: CryptoProvider + Send + Sync> EncryptedProtocol for LaserListener<P> {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;
	type CryptoProvider = P;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let (incoming, bound) = Self::bind_airspace(addr)?;
		let incoming = AsyncMutex::new(incoming);
		Ok((Self { incoming, config: Some(config) }, bound))
	}
}

impl<P: CryptoProvider + Send + Sync> AsyncListenerTrait for LaserListener<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		LaserListener::accept(self).await
	}
}

impl<P: CryptoProvider + Send + Sync> PersistentConnection for LaserListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_alive()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// The pipe closes when both ends drop.
	}
}
