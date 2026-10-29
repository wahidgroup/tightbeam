//! A blocking listener an outside crate writes, as the backend of the house
//! [`TcpListener`], which accepts on it and builds each transport.
//!
//! - [`TcpListener::from_listener_with`] serves it under the handshake of [`OutsideProvider`].
//! - [`TcpListener::from_listener_cleartext`] serves it in the clear.
//!
//! [`SilentProtocol`] is an outside protocol whose connect waits for a peer
//! that never answers. The house client ends its dial at the operation timeout
//! on the client's clock.
//!
//! [`BudgetedProtocol`] is an outside blocking protocol that overrides
//! [`Protocol::connect_within`] to end its connect at the budget the dial hands
//! it, which is the operation timeout.

#![cfg(all(feature = "transport-hpke", feature = "tcp"))]

use core::fmt;
use core::future::{pending, Future};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::sync::Arc;
use std::time::Duration;

use tightbeam::clock::{Clock, ManualClock};
use tightbeam::testing::TestFrame;
use tightbeam::transport::client::ClientBuilder;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use tightbeam::transport::{
	ConnectionBuilder, EndpointConfig, MessageEmitter, Protocol, TransportEncryptionConfig, TransportError,
	TransportFailure,
};

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

/// The operation timeout of a client whose dial no peer answers.
const DIAL_BUDGET: Duration = Duration::from_secs(5);

/// A protocol an outside crate writes, whose connect waits for a peer that
/// never answers, over the blocking transport of the house.
struct SilentProtocol;

impl Protocol for SilentProtocol {
	type Listener = OutsideListener;
	type Stream = NetTcpStream;
	type Error = IoError;
	type Transport = TcpTransport<NetTcpStream, OutsideProvider>;
	type Address = TightBeamSocketAddr;
	type CryptoProvider = OutsideProvider;

	fn default_bind_address() -> Result<TightBeamSocketAddr, IoError> {
		Ok(TightBeamSocketAddr(SocketAddr::from(([127, 0, 0, 1], 0))))
	}

	async fn bind_cleartext(_addr: TightBeamSocketAddr) -> Result<(OutsideListener, TightBeamSocketAddr), IoError> {
		let (listener, addr) = outside_listener();
		Ok((listener, TightBeamSocketAddr(addr)))
	}

	async fn connect(_addr: TightBeamSocketAddr) -> Result<NetTcpStream, IoError> {
		pending().await
	}

	fn create_transport(stream: NetTcpStream, config: EndpointConfig<OutsideProvider>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

/// A dial that no peer answers ends with `DeadlineExceeded` once the
/// operation timeout passes on the clock of the client, though the connect of
/// the protocol never returns (CWE-400).
#[cfg(feature = "tokio")]
#[test]
fn a_dial_that_never_answers_ends_at_the_operation_timeout() -> Result<(), Box<dyn Error>> {
	let clock = Arc::new(ManualClock::default());
	let builder = ClientBuilder::<SilentProtocol>::on_clock(Arc::clone(&clock) as Arc<dyn Clock>);
	let builder = builder.allow_cleartext().with_timeout(DIAL_BUDGET);
	let mut dial = pin!(builder.connect(SilentProtocol::default_bind_address()?));
	let mut context = Context::from_waker(Waker::noop());
	let waiting = dial.as_mut().poll(&mut context).is_pending();

	clock.advance(DIAL_BUDGET);

	let ended = dial.as_mut().poll(&mut context);
	assert!(waiting);
	assert!(matches!(
		ended,
		Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded)))
	));
	Ok(())
}

/// The budget a [`BudgetedProtocol`] connect spent, which its timeout carries.
#[derive(Debug)]
struct BudgetSpent(Duration);

impl fmt::Display for BudgetSpent {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "the connect spent its budget of {:?}", self.0)
	}
}

impl Error for BudgetSpent {}

/// A blocking protocol an outside crate writes. Its plain connect waits for a
/// peer that never answers, and its `connect_within` ends the connect at the
/// budget the dial hands it, as `TcpStream::connect_timeout` does.
struct BudgetedProtocol;

impl Protocol for BudgetedProtocol {
	type Listener = OutsideListener;
	type Stream = NetTcpStream;
	type Error = IoError;
	type Transport = TcpTransport<NetTcpStream, OutsideProvider>;
	type Address = TightBeamSocketAddr;
	type CryptoProvider = OutsideProvider;

	fn default_bind_address() -> Result<TightBeamSocketAddr, IoError> {
		Ok(TightBeamSocketAddr(SocketAddr::from(([127, 0, 0, 1], 0))))
	}

	async fn bind_cleartext(_addr: TightBeamSocketAddr) -> Result<(OutsideListener, TightBeamSocketAddr), IoError> {
		let (listener, addr) = outside_listener();
		Ok((listener, TightBeamSocketAddr(addr)))
	}

	async fn connect(_addr: TightBeamSocketAddr) -> Result<NetTcpStream, IoError> {
		pending().await
	}

	/// Ends at once with the timeout of a connect that no peer answers within
	/// `budget`, and names the budget it spent.
	async fn connect_within(_addr: TightBeamSocketAddr, budget: Duration) -> Result<NetTcpStream, IoError> {
		Err(IoError::new(ErrorKind::TimedOut, BudgetSpent(budget)))
	}

	fn create_transport(stream: NetTcpStream, config: EndpointConfig<OutsideProvider>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

/// The budget that the connect of a [`BudgetedProtocol`] spent, when `ended`
/// is the timeout it reports.
fn spent_budget<T>(ended: Poll<Result<T, TransportError>>) -> Option<Duration> {
	let Poll::Ready(Err(TransportError::IoError(error))) = ended else {
		return None;
	};

	let spent = error.get_ref()?.downcast_ref::<BudgetSpent>()?;
	Some(spent.0)
}

/// The dial hands a blocking protocol that overrides `connect_within` the
/// client's operation timeout as its budget. That connect's timeout ends the
/// dial on its first poll, though the client's clock never moves (CWE-400).
#[test]
fn a_dial_hands_an_overriding_protocol_the_operation_timeout() -> Result<(), Box<dyn Error>> {
	let clock = Arc::new(ManualClock::default());
	let builder = ClientBuilder::<BudgetedProtocol>::on_clock(Arc::clone(&clock) as Arc<dyn Clock>);
	let builder = builder.allow_cleartext().with_timeout(DIAL_BUDGET);
	let mut dial = pin!(builder.connect(BudgetedProtocol::default_bind_address()?));
	let mut context = Context::from_waker(Waker::noop());

	let ended = dial.as_mut().poll(&mut context);
	assert_eq!(spent_budget(ended), Some(DIAL_BUDGET));
	Ok(())
}
