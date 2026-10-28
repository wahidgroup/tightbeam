//! These tests run the blocking TCP transport, over `std::net`, under a
//! provider an outside crate defines. A client and a server complete the
//! handshake of the provider, and one frame goes out and comes back.
//!
//! - [`OutsideProvider`] runs it here.
//! - The P-256 provider of [`curve`](super::curve) runs it through [`blocking_exchange`].
//! - [`listener`](super::listener) runs it on its own listener, with
//!   [`blocking_echo_one`] and [`client_trusting`].
//! - The house provider runs the same exchange here, beside them.
//! - [`OutsideStream`] brings a blocking stream of its own, whose expired
//!   timeout the transport reports as `DeadlineExceeded`.

#![cfg(all(feature = "transport-hpke", feature = "tcp"))]

use std::error::Error;
use std::io::{Error as IoError, Read, Write};
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::policy::ProviderPolicy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::KeyCurves;
use tightbeam::random::OsRng;
use tightbeam::runtime::rt;
use tightbeam::testing::{TestFrame, TestIdentity};
use tightbeam::transport::client::ClientBuilder;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use tightbeam::transport::{
	EncryptedProtocol, EndpointConfig, MessageCollector, MessageEmitter, MessageIO, ProtocolStream,
	TransportEncryptionConfig, TransportError, TransportFailure, TransportLimits,
};
use tightbeam::x509::Certificate;
use tightbeam::Frame;

use super::{outside_identity, OutsideProvider};

/// A blocking listener under `P` on a loopback port, whose transports
/// present `identity`, and the address it binds.
async fn blocking_listener_under<P: HandshakeProvider>(
	identity: SigningIdentity,
) -> (TcpListener<NetTcpListener, P>, SocketAddr) {
	let config = TransportEncryptionConfig::<P>::new(identity);
	let bind = "127.0.0.1:0".parse::<TightBeamSocketAddr>().expect("a loopback address parses");
	let bound = TcpListener::<NetTcpListener, P>::bind_with(bind, config).await;
	let (listener, addr) = bound.expect("a loopback listener binds");

	(listener, *addr)
}

/// Echoes the first frame of one connection on `listener`, on its own thread.
///
/// [`rt::block_on`] drives it outside a runtime, as in the blocking `server!`
/// forms. A failure panics the thread.
pub(super) fn blocking_echo_one<L, P>(listener: TcpListener<L, P>)
where
	L: TcpListenerTrait<Stream = NetTcpStream, Error = IoError> + Send + 'static,
	P: HandshakeProvider,
{
	thread::spawn(move || {
		let served = rt::block_on(async move {
			let mut transport = listener.accept()?;
			let (frame, status) = transport.collect_message().await?;
			transport.send_response(status, Some(Frame::clone(&frame))).await
		});
		served.expect("the server echoes the first frame of its client");
	});
}

/// A blocking client under `P`, connected to `addr`, that trusts the
/// certificate `server` alone.
pub(super) fn client_trusting<P: HandshakeProvider>(
	addr: SocketAddr,
	server: &Certificate,
) -> TcpTransport<NetTcpStream, P> {
	let builder = CertificateTrustBuilder::new(ProviderPolicy::<P>::default(), KeyCurves::HOUSE, NoRevocation);
	let anchored = builder.with_certificate(server.to_owned());
	let store = anchored.expect("the server certificate anchors");
	let store: Arc<dyn CertificateTrust> = Arc::new(store.build());

	let stream = NetTcpStream::connect(addr).expect("the client reaches the listener");
	let client = ClientBuilder::<TcpListener<NetTcpListener, P>>::builder().with_trust_store(store);
	let client = client.adopt(stream).expect("the client names a trust store");
	client.into_transport()
}

/// One exchange of a blocking client with a blocking echo server.
pub(super) struct BlockingExchange {
	/// The frame the client emits, and the certificate the server presents.
	pub(super) sent: (Option<Frame>, Option<Certificate>),
	/// The frame that comes back, and the certificate the client holds.
	pub(super) received: (Option<Frame>, Option<Certificate>),
}

/// One exchange under `P`. A blocking server presents `server` and echoes the
/// first frame it collects. A blocking client that trusts `server` alone emits
/// one frame with id `id`.
pub(super) async fn blocking_exchange<P: HandshakeProvider>(
	server: SigningIdentity,
	id: &str,
) -> Result<BlockingExchange, Box<dyn Error>> {
	let certificate = server.certificate().to_owned();
	let (listener, addr) = blocking_listener_under::<P>(server).await;

	blocking_echo_one(listener);

	let mut client = client_trusting::<P>(addr, &certificate);
	let frame = TestFrame::v0(Some(id), None);

	let echoed = client.emit(frame.clone(), None).await?;
	let held = client.peer_certificate().cloned();
	Ok(BlockingExchange { sent: (Some(frame), Some(certificate)), received: (echoed, held) })
}

/// A blocking client and server under [`OutsideProvider`] complete its
/// handshake. The client holds the server certificate and gets its frame back.
#[tokio::test]
async fn an_outside_provider_runs_the_blocking_transport() -> Result<(), Box<dyn Error>> {
	let exchange = blocking_exchange::<OutsideProvider>(outside_identity(), "outside-blocking").await?;
	assert_eq!(exchange.received, exchange.sent);
	Ok(())
}

/// A blocking client and server under the house provider complete its
/// handshake and echo a frame, as the outside providers do.
#[tokio::test]
async fn the_house_provider_runs_the_blocking_transport() -> Result<(), Box<dyn Error>> {
	let server = TestIdentity::of(&SigningKey::random(&mut OsRng));
	let exchange = blocking_exchange::<DefaultCryptoProvider>(server, "house-blocking").await?;
	assert_eq!(exchange.received, exchange.sent);
	Ok(())
}

/// The operation deadline of a read over [`OutsideStream`] that no byte
/// answers.
const READ_DEADLINE: Duration = Duration::from_millis(50);

/// A blocking stream an outside crate writes over a socket of its own, which
/// it bounds by the timeouts of that socket.
struct OutsideStream(NetTcpStream);

impl ProtocolStream for OutsideStream {
	type Error = IoError;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), IoError> {
		Write::write_all(&mut self.0, buf)
	}

	fn write_some(&mut self, buf: &[u8]) -> Result<usize, IoError> {
		Write::write(&mut self.0, buf)
	}

	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), IoError> {
		Read::read_exact(&mut self.0, buf)
	}

	fn read_some(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
		Read::read(&mut self.0, buf)
	}

	fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), IoError> {
		self.0.set_read_timeout(timeout)?;
		self.0.set_write_timeout(timeout)
	}
}

/// The two ends of one loopback connection: the end a transport reads, and
/// the end of a peer that stays silent.
fn loopback_pair() -> (NetTcpStream, NetTcpStream) {
	let listener = NetTcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
	let addr = listener.local_addr().expect("a bound listener has an address");
	let peer = NetTcpStream::connect(addr).expect("the loopback listener takes the dial");
	let (stream, _) = listener.accept().expect("the dial arrives");
	(stream, peer)
}

/// The blocking transport over an outside stream reports a read that a silent
/// peer runs past its deadline as `DeadlineExceeded`, whichever of
/// `WouldBlock` and `TimedOut` the timeout of the stream raises.
#[test]
fn an_outside_blocking_stream_that_times_out_reports_the_deadline() -> Result<(), Box<dyn Error>> {
	let (stream, _silent) = loopback_pair();
	let limits = TransportLimits { operation_timeout: READ_DEADLINE, ..TransportLimits::default() };
	let endpoint = EndpointConfig::<DefaultCryptoProvider>::cleartext().with_limits(limits);
	let mut transport = TcpTransport::new(OutsideStream(stream), endpoint);

	let read = rt::block_on(transport.read_envelope_bytes());
	assert!(matches!(
		read,
		Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
	));
	Ok(())
}
