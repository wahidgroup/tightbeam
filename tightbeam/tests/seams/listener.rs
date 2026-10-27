//! A blocking listener an outside crate writes, as the backend of the house
//! [`TcpListener`], which accepts on it and builds each transport.
//!
//! - [`TcpListener::from_listener_with`] serves it under the handshake of [`OutsideProvider`].
//! - [`TcpListener::from_listener_cleartext`] serves it in the clear.

#![cfg(all(feature = "transport-hpke", feature = "tcp"))]

use std::error::Error;
use std::io::Error as IoError;
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};

use tightbeam::testing::TestFrame;
use tightbeam::transport::client::ClientBuilder;
use tightbeam::transport::tcp::sync::TcpListener;
use tightbeam::transport::tcp::TcpListenerTrait;
use tightbeam::transport::{MessageEmitter, TransportEncryptionConfig};

use super::blocking::{blocking_echo_one, client_trusting};
use super::{outside_identity, OutsideProvider};

/// A blocking listener an outside crate writes: a backend that accepts on a
/// socket it bound itself.
struct OutsideListener(NetTcpListener);

impl TcpListenerTrait for OutsideListener {
	type Stream = NetTcpStream;
	type Error = IoError;

	fn accept(&self) -> Result<(NetTcpStream, SocketAddr), IoError> {
		self.0.accept()
	}
}

/// An outside listener on a loopback port, over a socket it binds itself,
/// and the address it binds.
fn outside_listener() -> (OutsideListener, SocketAddr) {
	let socket = NetTcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
	let addr = socket.local_addr().expect("a bound socket has an address");
	(OutsideListener(socket), addr)
}

/// The house listener over an outside backend serves the handshake of
/// [`OutsideProvider`], so the client holds the certificate of the server,
/// and a frame the client emits comes back to it.
#[tokio::test]
async fn an_outside_listener_serves_the_handshake() -> Result<(), Box<dyn Error>> {
	let server = outside_identity();
	let certificate = server.certificate().to_owned();
	let (outside, addr) = outside_listener();
	let config = TransportEncryptionConfig::<OutsideProvider>::new(server);
	blocking_echo_one(TcpListener::from_listener_with(outside, config)?);
	let mut client = client_trusting::<OutsideProvider>(addr, &certificate);
	let frame = TestFrame::v0(Some("outside-listener"), None);

	let echoed = client.emit(frame.clone(), None).await?;
	assert_eq!((echoed, client.peer_certificate()), (Some(frame), Some(&certificate)));
	Ok(())
}

/// The house listener over an outside backend serves a cleartext client, and
/// a frame the client emits comes back to it.
#[tokio::test]
async fn an_outside_listener_serves_in_the_clear() -> Result<(), Box<dyn Error>> {
	let (outside, addr) = outside_listener();
	blocking_echo_one(TcpListener::<_, OutsideProvider>::from_listener_cleartext(outside));
	let stream = NetTcpStream::connect(addr)?;
	let builder = ClientBuilder::<TcpListener<NetTcpListener, OutsideProvider>>::builder().allow_cleartext();
	let mut client = builder.adopt(stream)?.into_transport();
	let frame = TestFrame::v0(Some("outside-cleartext"), None);

	let echoed = client.emit(frame.clone(), None).await?;
	assert_eq!(echoed, Some(frame));
	Ok(())
}
