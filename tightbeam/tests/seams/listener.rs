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
//! [`Protocol::connect_within`] to end its connect at the operation timeout of
//! the limits the dial hands it.

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
use tightbeam::transport::client::{ClientBuilder, ConnectionPool};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use tightbeam::transport::{
	CheckedLimits, ClientPolicies, ConnectionBuilder, EndpointConfig, MessageEmitter, PersistentConnection, Protocol,
	TransportEncryptionConfig, TransportError, TransportFailure, TransportLimits,
};

#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::handshake::negotiation::TransportOffer;
#[cfg(feature = "tokio")]
use tightbeam::transport::tcp::r#async::{TcpTransport as TokioTransport, TokioStream};
#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::PoolConfig;

use super::blocking::{blocking_echo_one, client_trusting};
use super::{outside_identity, OutsideProvider, SERVER_SEED};
use crate::common::result::TestResult;

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
async fn an_outside_listener_serves_the_handshake() -> TestResult {
	let server = outside_identity(SERVER_SEED);
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
async fn an_outside_listener_serves_in_the_clear() -> TestResult {
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
fn a_dial_that_never_answers_ends_at_the_operation_timeout() -> TestResult {
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

/// The budget and the encrypted-envelope ceiling a [`BudgetedProtocol`]
/// connect saw, which its timeout carries.
#[derive(Debug)]
struct BudgetSpent(Duration, usize);

impl fmt::Display for BudgetSpent {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "the connect spent its budget of {:?}", self.0)
	}
}

impl Error for BudgetSpent {}

impl BudgetSpent {
	/// The timeout that ends a connect under `limits`.
	fn refusal(limits: &CheckedLimits) -> IoError {
		let spent = Self(limits.operation_timeout, limits.encrypted_envelope);
		IoError::new(ErrorKind::TimedOut, spent)
	}
}

/// A blocking protocol an outside crate writes. Its plain connect waits for a
/// peer that never answers, and its `connect_within` ends the connect at the
/// operation timeout of the limits the dial hands it, as
/// `TcpStream::connect_timeout` does.
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
	/// its budget, and names the budget it spent.
	async fn connect_within(_addr: TightBeamSocketAddr, limits: &CheckedLimits) -> Result<NetTcpStream, IoError> {
		Err(BudgetSpent::refusal(limits))
	}

	fn create_transport(stream: NetTcpStream, config: EndpointConfig<OutsideProvider>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

/// The limits that reached the connect of a [`BudgetedProtocol`], when `ended`
/// is the timeout it reports.
fn spent<T>(ended: Poll<Result<T, TransportError>>) -> Option<(Duration, usize)> {
	let Poll::Ready(Err(TransportError::IoError(error))) = ended else {
		return None;
	};

	let spent = error.get_ref()?.downcast_ref::<BudgetSpent>()?;
	Some((spent.0, spent.1))
}

/// The limits that reach the connect of `builder` on the first poll of its
/// dial.
fn first_poll(builder: ClientBuilder<BudgetedProtocol>) -> Option<(Duration, usize)> {
	let addr = BudgetedProtocol::default_bind_address();
	let mut dial = pin!(builder.connect(addr.expect("the protocol names a bind address")));
	let mut context = Context::from_waker(Waker::noop());

	spent(dial.as_mut().poll(&mut context))
}

/// Ceilings apart from the defaults, whose timeout outlasts [`DIAL_BUDGET`].
fn raised_limits() -> CheckedLimits {
	let defaults = TransportLimits::default();
	let encrypted_envelope = defaults.encrypted_envelope + 1;
	let operation_timeout = DIAL_BUDGET + DIAL_BUDGET;
	let raised = TransportLimits { encrypted_envelope, operation_timeout, ..defaults };

	raised.checked().expect("the raised ceilings agree with the defaults")
}

/// A cleartext client of [`BudgetedProtocol`] on a clock that no test moves.
fn budgeted_client() -> ClientBuilder<BudgetedProtocol> {
	ClientBuilder::<BudgetedProtocol>::on_clock(Arc::new(ManualClock::default())).allow_cleartext()
}

/// With no timeout of its own, a dial runs under the timeout inside its limits.
#[test]
fn a_dial_under_limits_alone_hands_over_their_timeout() {
	let limits = raised_limits();

	let builder = budgeted_client().with_limits(limits);
	let ceilings = Some((limits.operation_timeout, limits.encrypted_envelope));
	assert_eq!(first_poll(builder), ceilings);
}

/// A client's ceilings reach the connect, so a protocol with socket ceilings of
/// its own reads them, and a timeout outranks the one inside the limits.
#[test]
fn a_dial_hands_an_overriding_protocol_the_ceilings_of_its_client() {
	let limits = raised_limits();
	let builder = budgeted_client().with_limits(limits).with_timeout(DIAL_BUDGET);
	assert_eq!(first_poll(builder), Some((DIAL_BUDGET, limits.encrypted_envelope)));
}

/// `client!` sets its timeout and code generic over [`ConnectionBuilder`] sets
/// the ceilings through the trait, whose methods forward to the setters of the
/// client.
#[test]
fn the_trait_setters_reach_the_dial_of_a_client() {
	let limits = raised_limits();
	let builder = ConnectionBuilder::with_limits(budgeted_client(), limits);
	let builder = ConnectionBuilder::with_timeout(builder, DIAL_BUDGET);
	assert_eq!(first_poll(builder), Some((DIAL_BUDGET, limits.encrypted_envelope)));
}

/// Policies replace the restart and the gates alone, so the ceilings and the
/// timeout set before them still reach the dial.
#[test]
fn policies_keep_the_ceilings_set_before_them() {
	let limits = raised_limits();
	let builder = budgeted_client().with_limits(limits).with_timeout(DIAL_BUDGET);
	let builder = builder.policies(ClientPolicies::default());
	assert_eq!(first_poll(builder), Some((DIAL_BUDGET, limits.encrypted_envelope)));
}

/// An adopted stream runs under the ceilings and the timeout of its client, as
/// a dialed one does.
#[test]
fn an_adopted_stream_runs_under_the_ceilings_of_its_client() -> TestResult {
	let limits = raised_limits();
	let (_outside, addr) = outside_listener();
	let builder = ClientBuilder::<TcpListener<NetTcpListener, OutsideProvider>>::builder().allow_cleartext();
	let builder = builder.with_limits(limits).with_timeout(DIAL_BUDGET);
	let transport = builder.adopt(NetTcpStream::connect(addr)?)?.into_transport();

	let held = transport.limits();
	let held = (held.operation_timeout, held.encrypted_envelope);
	assert_eq!(held, (DIAL_BUDGET, limits.encrypted_envelope));
	Ok(())
}

/// [`BudgetedProtocol`] over a tokio stream, the kind of stream a
/// [`ConnectionPool`] dials.
#[cfg(feature = "tokio")]
struct PooledProtocol;

#[cfg(feature = "tokio")]
impl Protocol for PooledProtocol {
	type Listener = OutsideListener;
	type Stream = TokioStream;
	type Error = IoError;
	type Transport = TokioTransport<TokioStream, OutsideProvider>;
	type Address = TightBeamSocketAddr;
	type CryptoProvider = OutsideProvider;

	fn default_bind_address() -> Result<TightBeamSocketAddr, IoError> {
		BudgetedProtocol::default_bind_address()
	}

	async fn bind_cleartext(addr: TightBeamSocketAddr) -> Result<(OutsideListener, TightBeamSocketAddr), IoError> {
		BudgetedProtocol::bind_cleartext(addr).await
	}

	async fn connect(_addr: TightBeamSocketAddr) -> Result<TokioStream, IoError> {
		pending().await
	}

	/// Ends as the connect of [`BudgetedProtocol`] ends.
	async fn connect_within(_addr: TightBeamSocketAddr, limits: &CheckedLimits) -> Result<TokioStream, IoError> {
		Err(BudgetSpent::refusal(limits))
	}

	fn create_transport(stream: TokioStream, config: EndpointConfig<OutsideProvider>) -> Self::Transport {
		TokioTransport::new(stream, config)
	}
}

#[cfg(feature = "tokio")]
impl PersistentConnection for PooledProtocol {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	fn try_close(_transport: &mut Self::Transport) {}
}

/// The ceilings of an async client reach the connect it dials.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn an_async_dial_hands_an_overriding_protocol_the_ceilings_of_its_client() -> TestResult {
	let limits = raised_limits();
	let builder = ClientBuilder::<PooledProtocol>::builder().allow_cleartext();
	let builder = builder.with_limits(limits).with_timeout(DIAL_BUDGET);

	let ended = builder.connect(PooledProtocol::default_bind_address()?).await;
	assert_eq!(spent(Poll::Ready(ended)), Some((DIAL_BUDGET, limits.encrypted_envelope)));
	Ok(())
}

/// The ceilings of a pool reach each connect it dials.
#[cfg(feature = "tokio")]
#[tokio::test]
async fn a_pooled_dial_hands_an_overriding_protocol_the_ceilings_of_its_pool() -> TestResult {
	let limits = raised_limits();
	let builder = ConnectionPool::<PooledProtocol>::builder().allow_cleartext();
	let pool = Arc::new(builder.with_limits(limits).with_timeout(DIAL_BUDGET).build());

	let ended = pool.connect(PooledProtocol::default_bind_address()?).await;
	assert_eq!(spent(Poll::Ready(ended)), Some((DIAL_BUDGET, limits.encrypted_envelope)));
	Ok(())
}

/// A pool that offers multiplexing dials on a path of its own, and the ceilings
/// of the pool reach that dial too.
#[cfg(all(feature = "tokio", feature = "transport-multiplex"))]
#[tokio::test]
async fn a_multiplexed_pooled_dial_hands_an_overriding_protocol_the_ceilings_of_its_pool() -> TestResult {
	let limits = raised_limits();
	let mux_offer = Some(Arc::new(TransportOffer::mux(4)));
	let config = PoolConfig { mux_offer, ..PoolConfig::default() };
	let builder = ConnectionPool::<PooledProtocol>::builder().allow_cleartext();
	let builder = builder.with_config(config).with_limits(limits).with_timeout(DIAL_BUDGET);
	let pool = Arc::new(builder.build());

	let ended = pool.connect(PooledProtocol::default_bind_address()?).await;
	assert_eq!(spent(Poll::Ready(ended)), Some((DIAL_BUDGET, limits.encrypted_envelope)));
	Ok(())
}

/// The dial hands a blocking protocol that overrides `connect_within` the
/// client's operation timeout inside its limits. That connect's timeout ends
/// the dial on its first poll, though the client's clock never moves (CWE-400).
#[test]
fn a_dial_hands_an_overriding_protocol_the_operation_timeout() {
	let builder = budgeted_client().with_timeout(DIAL_BUDGET);
	let spent = first_poll(builder);
	assert_eq!(spent.map(|(budget, _)| budget), Some(DIAL_BUDGET));
}
