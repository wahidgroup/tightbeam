//! These tests run the blocking TCP transport, over `std::net`, under a
//! provider an outside crate defines. A client and a server complete the
//! handshake of the provider, and one frame goes out and comes back.
//!
//! - [`OutsideProvider`] runs it here.
//! - The P-256 provider of [`curve`](super::curve) runs it through [`blocking_exchange`].
//! - [`listener`](super::listener) runs it on its own listener, with
//!   [`blocking_echo_one`] and [`client_trusting`].
//! - The house provider runs the same exchange here, beside them.

#![cfg(all(feature = "transport-hpke", feature = "tcp"))]

use std::error::Error;
use std::io::Error as IoError;
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::sync::Arc;
use std::thread;

use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::policy::ProviderPolicy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::random::OsRng;
use tightbeam::testing::{TestFrame, TestIdentity};
use tightbeam::transport::client::ClientBuilder;
use tightbeam::transport::handshake::HandshakeProvider;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use tightbeam::transport::{EncryptedProtocol, MessageCollector, MessageEmitter, TransportEncryptionConfig};
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

/// A server under `P`, on a thread of its own, that accepts one connection
/// on `listener` and answers the first frame it collects with that frame. A
/// failure of the server panics its thread, so the client reads a closed
/// connection.
pub(super) fn blocking_echo_one<L, P>(listener: TcpListener<L, P>)
where
	L: TcpListenerTrait<Stream = NetTcpStream, Error = IoError> + Send + 'static,
	P: HandshakeProvider,
{
	thread::spawn(move || {
		let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
		let runtime = runtime.expect("a current-thread runtime builds");
		let served = runtime.block_on(async move {
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
	let builder = CertificateTrustBuilder::from(ProviderPolicy::<P>::default());
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

/// One exchange of a blocking client under `P` with a blocking server under
/// `P` that presents `server` and echoes the first frame it collects. The
/// client trusts the certificate of `server` alone, and emits one frame whose
/// id is `id`.
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
/// handshake, so the client holds the certificate of the server, and a frame
/// the client emits comes back to it.
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
