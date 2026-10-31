//! The bounded acceptance of connections.
//!
//! One plane type states the connection cap, the permit lifetime, and the
//! accept retry pace of each kind of accept loop:
//!
//! - [`AcceptPlane`] serves the servlet, hive, gateway, and async `server!` planes, a task per connection.
//! - [`BlockingAcceptPlane`] serves the blocking `server!`, a thread per connection.
//!
//! The servlet, hive, and gateway planes also set the trace and the mux offer
//! of their owner on each connection here.

use core::num::NonZeroUsize;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;

#[cfg(feature = "tokio")]
use core::future::Future;

use crate::constants::DEFAULT_ACCEPT_RETRY_DELAY;

#[cfg(feature = "tokio")]
use crate::clock::Clock;
#[cfg(feature = "colony")]
use crate::trace::TraceHandle;
#[cfg(feature = "colony")]
use crate::transport::handshake::negotiation::TransportOffer;
#[cfg(feature = "colony")]
use crate::transport::multiplex::MuxCapable;
#[cfg(feature = "tokio")]
use crate::transport::protocols::AsyncListenerTrait;
#[cfg(feature = "colony")]
use crate::transport::state::EncryptedProtocolState;

/// A plane that accepts connections under a fixed cap and owns what it admits.
///
/// One permit per live connection caps concurrent handlers, so a connection
/// flood queues in the listener backlog, which bounds live tasks and
/// descriptors by the cap (CWE-400). The plane owns the handler task set,
/// so a drop of the plane aborts those handlers and an aborted accept task
/// ends the connections it started (CWE-772).
#[cfg(feature = "tokio")]
pub struct AcceptPlane {
	permits: Arc<tokio::sync::Semaphore>,
	connections: tokio::task::JoinSet<()>,
	/// The clock on which an accept failure waits out its retry delay.
	clock: Arc<dyn Clock>,
}

#[cfg(feature = "tokio")]
impl AcceptPlane {
	/// Creates a plane that admits `max_connections` live handlers and paces
	/// accept retries on `clock`.
	///
	/// [`DEFAULT_MAX_SERVER_CONNECTIONS`] is the cap every accept plane uses
	/// unless a policy names its own. The cap is a [`NonZeroUsize`], so the
	/// plane admits its first connection.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::clock::SystemClock;
	/// use tightbeam::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
	/// use tightbeam::transport::accept::AcceptPlane;
	///
	/// let _plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, Arc::new(SystemClock));
	/// ```
	///
	/// [`DEFAULT_MAX_SERVER_CONNECTIONS`]: crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS
	#[must_use]
	pub fn new(max_connections: NonZeroUsize, clock: Arc<dyn Clock>) -> Self {
		Self {
			permits: Arc::new(tokio::sync::Semaphore::new(max_connections.get())),
			connections: tokio::task::JoinSet::new(),
			clock,
		}
	}

	/// Waits for a free connection slot, after it reaps the finished handlers.
	///
	/// Returns [`None`] once the plane closes, which ends the accept loop.
	async fn reserve(&mut self) -> Option<tokio::sync::OwnedSemaphorePermit> {
		while self.connections.try_join_next().is_some() {}
		Arc::clone(&self.permits).acquire_owned().await.ok()
	}

	/// Runs `handler` on a reserved slot, and releases the slot on every exit
	/// path.
	fn serve<F>(&mut self, permit: tokio::sync::OwnedSemaphorePermit, handler: F)
	where
		F: Future<Output = ()> + Send + 'static,
	{
		self.connections.spawn(async move {
			let _permit = permit;
			handler.await;
		});
	}

	/// Waits out one failed accept.
	///
	/// A listener this plane holds stays usable, so an accept failure is a
	/// descriptor shortage or a refused peer. The plane paces the retry and
	/// accepts again, until the owner of the task ends the loop.
	async fn absorb_failure(&self) {
		self.clock.sleep(DEFAULT_ACCEPT_RETRY_DELAY).await;
	}

	/// Accepts on `listener` until the plane closes, and runs each admitted
	/// transport through `handler`.
	///
	/// The future owns the plane, so the task a caller spawns it on owns
	/// every connection the loop starts: an abort of that task ends them all.
	pub async fn accept_on<L, F, Fut>(self, listener: L, handler: F)
	where
		L: AsyncListenerTrait + Sync,
		F: Fn(L::Transport) -> Fut,
		Fut: Future<Output = ()> + Send + 'static,
	{
		self.accept_on_reporting(listener, handler, |_| async {}).await;
	}

	/// Accepts as [`AcceptPlane::accept_on`] does, and sets `terms` on each
	/// admitted transport before `handler` runs it.
	#[cfg(feature = "colony")]
	pub(crate) fn accept_owned<L, F, Fut>(
		self,
		listener: L,
		terms: ConnectionTerms,
		handler: F,
	) -> impl Future<Output = ()>
	where
		L: AsyncListenerTrait + Sync,
		L::Transport: MuxCapable + EncryptedProtocolState,
		F: Fn(L::Transport) -> Fut,
		Fut: Future<Output = ()> + Send + 'static,
	{
		self.accept_on(listener, move |transport| handler(terms.apply(transport)))
	}

	/// Accepts as [`AcceptPlane::accept_on`] does, and hands each failed
	/// accept to `report` before the backoff.
	///
	/// `report` receives the listener's own error, which a caller that
	/// publishes accept failures on a channel converts and forwards.
	pub async fn accept_on_reporting<L, F, Fut, R, RFut>(mut self, listener: L, handler: F, report: R)
	where
		L: AsyncListenerTrait + Sync,
		F: Fn(L::Transport) -> Fut,
		Fut: Future<Output = ()> + Send + 'static,
		R: Fn(L::Error) -> RFut,
		RFut: Future<Output = ()>,
	{
		loop {
			let Some(permit) = self.reserve().await else {
				break;
			};

			// `report` consumes the error before the await, so a listener
			// whose error type is not `Send` leaves this future `Send`.
			let failure = match listener.accept().await {
				Ok((transport, _addr)) => {
					self.serve(permit, handler(transport));
					continue;
				}
				Err(error) => report(error),
			};

			drop(permit);
			failure.await;
			self.absorb_failure().await;
		}
	}
}

/// A plane that accepts connections on a blocking listener under a fixed
/// cap, and serves each connection it admits on a thread of its own.
///
/// - One permit per live connection caps the threads, so a flood queues in the listener backlog (CWE-770).
/// - A failed accept, or a thread that the system refuses to start, waits out the accept retry delay.
///
/// # Sources
///
/// - CWE-770, resource allocation without limits: <https://cwe.mitre.org/data/definitions/770.html>
pub struct BlockingAcceptPlane {
	permits: Arc<Permits>,
}

impl BlockingAcceptPlane {
	/// Creates a plane that admits `max_connections` live handlers.
	///
	/// [`DEFAULT_MAX_SERVER_CONNECTIONS`] is the cap that the blocking
	/// `server!` uses unless a policy names its own. The cap is a
	/// [`NonZeroUsize`], so the plane admits its first connection.
	///
	/// [`DEFAULT_MAX_SERVER_CONNECTIONS`]: crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
	/// use tightbeam::transport::accept::BlockingAcceptPlane;
	///
	/// let _plane = BlockingAcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS);
	/// ```
	#[must_use]
	pub fn new(max_connections: NonZeroUsize) -> Self {
		Self { permits: Arc::new(Permits::new(max_connections)) }
	}

	/// Accepts through `accept` for as long as the calling thread runs, and
	/// runs the work that `handler` builds for each admitted connection on a
	/// thread of its own.
	///
	/// - `handler` runs on the accepting thread, before the thread of the connection starts.
	/// - One slot stays taken from before each accept until the work of that connection ends.
	///
	/// # Examples
	///
	/// ```
	/// use std::net::{SocketAddr, TcpListener, TcpStream};
	/// use std::num::NonZeroUsize;
	/// use std::sync::mpsc;
	/// use std::thread;
	///
	/// use tightbeam::transport::accept::BlockingAcceptPlane;
	///
	/// let listener = TcpListener::bind("127.0.0.1:0")?;
	/// let addr = listener.local_addr()?;
	/// let (served, seen) = mpsc::channel();
	///
	/// // The plane accepts for as long as its thread runs.
	/// thread::spawn(move || {
	///     let report = move |(_stream, peer): (TcpStream, SocketAddr)| {
	///         let served = served.clone();
	///         move || {
	///             // The receiver outlives the one report of the example.
	///             let _ = served.send(peer);
	///         }
	///     };
	///     BlockingAcceptPlane::new(NonZeroUsize::MIN).accept_on(|| listener.accept(), report);
	/// });
	///
	/// let client = TcpStream::connect(addr)?;
	/// assert_eq!(seen.recv()?, client.local_addr()?);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn accept_on<T, E, A, H, W>(self, mut accept: A, mut handler: H)
	where
		A: FnMut() -> Result<T, E>,
		H: FnMut(T) -> W,
		W: FnOnce() + Send + 'static,
	{
		loop {
			let permit = self.permits.acquire();

			// A failed accept costs the plane its retry delay alone: the slot
			// frees before the delay, and the listener's error drops here.
			let Ok(connection) = accept() else {
				drop(permit);
				Self::absorb_failure();
				continue;
			};

			let work = handler(connection);
			if Self::serve(permit, work).is_err() {
				Self::absorb_failure();
			}
		}
	}

	/// Runs `work` on a thread of its own that holds `permit`, so the slot
	/// frees on every exit path of the work.
	///
	/// # Errors
	///
	/// - The I/O error of a thread that the system refuses to start. The work
	///   drops unrun with its permit, which ends its connection and frees its
	///   slot.
	fn serve(permit: Permit, work: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
		let started = thread::Builder::new().spawn(move || {
			let _permit = permit;
			work();
		});

		// The thread runs detached, and it ends with its connection.
		let _detached = started?;
		Ok(())
	}

	/// Waits out one failed accept or one refused thread, as
	/// [`AcceptPlane`] waits out a failed accept.
	fn absorb_failure() {
		thread::sleep(DEFAULT_ACCEPT_RETRY_DELAY);
	}
}

/// The free connection slots of a [`BlockingAcceptPlane`], and the condition
/// that a full plane waits on.
///
/// Each write sets the whole count in one saturating step, so a poisoned lock
/// holds a whole count, and each reader reads through the poison.
struct Permits {
	free: Mutex<usize>,
	freed: Condvar,
}

impl Permits {
	/// Creates `slots` free slots.
	fn new(slots: NonZeroUsize) -> Self {
		Self { free: Mutex::new(slots.get()), freed: Condvar::new() }
	}

	/// Waits for a free slot, and takes it.
	fn acquire(self: &Arc<Self>) -> Permit {
		let free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
		let waited = self.freed.wait_while(free, |free| *free == 0);
		let mut free = waited.unwrap_or_else(PoisonError::into_inner);
		*free = free.saturating_sub(1);

		Permit(Arc::clone(self))
	}

	/// Gives one slot back, and wakes one waiter.
	fn release(&self) {
		let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
		*free = free.saturating_add(1);
		self.freed.notify_one();
	}
}

/// One taken slot of [`Permits`], which its drop gives back.
struct Permit(Arc<Permits>);

impl Drop for Permit {
	fn drop(&mut self) {
		self.0.release();
	}
}

/// The terms that an owner sets on each connection it serves: its trace, and
/// its mux offer.
///
/// They hold the handle of the owner's trace, so each connection records into
/// the trace the handle holds when the connection starts. The trace goes on
/// before the handshake, so it records the handshake of every connection, a
/// peer that never authenticates included.
#[cfg(feature = "colony")]
#[derive(Clone)]
pub(crate) struct ConnectionTerms {
	// The `instrument` build alone attaches a trail to a connection, so that
	// build alone reads the trace.
	#[cfg_attr(not(feature = "instrument"), allow(dead_code))]
	trace: TraceHandle,
	mux_offer: Option<Arc<TransportOffer>>,
}

#[cfg(feature = "colony")]
impl ConnectionTerms {
	/// The terms of an owner that records into the trace `trace` holds and
	/// advertises `mux_offer`.
	pub(crate) fn new(trace: TraceHandle, mux_offer: Option<Arc<TransportOffer>>) -> Self {
		Self { trace, mux_offer }
	}

	/// Sets these terms on `transport`: the mux offer, and the trace that the
	/// handle holds at the call as the transport's trail.
	///
	/// Each connection shares the mux offer by reference count, so the
	/// authorization octets stay in one allocation.
	pub(crate) fn apply<T>(&self, transport: T) -> T
	where
		T: MuxCapable + EncryptedProtocolState,
	{
		let transport = transport.with_mux_offer(self.mux_offer.clone());
		#[cfg(feature = "instrument")]
		let transport = transport.with_trace(self.trace.current().share());
		transport
	}
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
	use core::future::Future;
	use core::pin::pin;
	use core::sync::atomic::{AtomicBool, Ordering};
	use core::task::{Context, Waker};
	use core::time::Duration;

	use super::*;
	use crate::clock::ManualClock;

	#[cfg(all(pooled_mux, feature = "tcp"))]
	use crate::transport::handshake::negotiation::MuxSettings;
	#[cfg(all(pooled_mux, feature = "tcp"))]
	use crate::transport::multiplex::{MuxAcceptor, MuxRole, MuxService, MuxTransport};
	#[cfg(all(pooled_mux, feature = "tcp"))]
	use crate::transport::tcp::r#async::{TcpTransport, TokioStream};
	#[cfg(all(pooled_mux, feature = "tcp"))]
	use crate::transport::{EndpointConfig, TransportError};

	/// How long the peer of an ended connection has to read its close.
	#[cfg(all(pooled_mux, feature = "tcp"))]
	const CLOSE_GUARD: Duration = Duration::from_secs(5);

	/// A plane of one slot, on a clock that the test moves.
	fn plane() -> AcceptPlane {
		AcceptPlane::new(NonZeroUsize::MIN, Arc::new(ManualClock::default()))
	}

	/// Serves `handler` on a slot that the test knows the plane has free.
	async fn serve_on_free_slot(plane: &mut AcceptPlane, handler: impl Future<Output = ()> + Send + 'static) {
		let permit = plane.reserve().await.expect("the plane under test has a free slot");
		plane.serve(permit, handler);
	}

	/// A failed accept waits out its retry delay on the plane's clock, so a
	/// runtime that installs its own clock paces the retry too.
	#[tokio::test]
	async fn a_failed_accept_waits_on_the_planes_clock() {
		let clock = Arc::new(ManualClock::default());
		let plane = AcceptPlane::new(NonZeroUsize::MIN, Arc::clone(&clock) as Arc<dyn Clock>);
		let mut context = Context::from_waker(Waker::noop());
		let mut wait = pin!(plane.absorb_failure());
		assert!(wait.as_mut().poll(&mut context).is_pending());

		clock.advance(DEFAULT_ACCEPT_RETRY_DELAY);
		assert!(wait.as_mut().poll(&mut context).is_ready());
	}

	/// A plane with every slot held admits no further connection.
	#[tokio::test(start_paused = true)]
	async fn a_full_plane_admits_no_further_connection() {
		let mut plane = plane();
		let _held = plane.reserve().await;
		let blocked = tokio::time::timeout(Duration::from_secs(1), plane.reserve()).await;
		assert!(blocked.is_err());
	}

	/// A connection that finished returns its slot to the plane.
	#[tokio::test(start_paused = true)]
	async fn a_finished_connection_returns_its_slot() {
		let mut plane = plane();
		serve_on_free_slot(&mut plane, async {}).await;
		tokio::task::yield_now().await;

		let reserved = tokio::time::timeout(Duration::from_secs(1), plane.reserve()).await;
		assert!(matches!(reserved, Ok(Some(_))));
	}

	/// The drop of a plane aborts the connections it serves, so a handler that
	/// waits past the drop never finishes. The plane spawns through its own
	/// `serve`, so the case paces the paused clock inline.
	#[tokio::test(start_paused = true)]
	async fn dropping_the_plane_aborts_its_connections() {
		let finished = Arc::new(AtomicBool::new(false));
		let flag = Arc::clone(&finished);
		let mut plane = plane();
		serve_on_free_slot(&mut plane, async move {
			tokio::time::sleep(Duration::from_secs(30)).await;
			flag.store(true, Ordering::SeqCst);
		})
		.await;

		tokio::task::yield_now().await;
		drop(plane);
		tokio::time::advance(Duration::from_secs(60)).await;
		tokio::task::yield_now().await;
		assert!(!finished.load(Ordering::SeqCst));
	}

	/// A service that refuses every kind of stream through the defaults of its
	/// trait.
	///
	/// The case serves no request, so the trait defaults stand in for a
	/// service.
	#[cfg(all(pooled_mux, feature = "tcp"))]
	struct Refusing;

	#[cfg(all(pooled_mux, feature = "tcp"))]
	impl MuxService for Refusing {}

	/// The client and the server transport of one cleartext loopback
	/// connection.
	#[cfg(all(pooled_mux, feature = "tcp"))]
	async fn cleartext_pair() -> (TcpTransport<TokioStream>, TcpTransport<TokioStream>) {
		let (accepted, dialing) = crate::testing::fixtures::TestLoopback::tokio_pair().await;
		let server = TcpTransport::new(TokioStream::from(accepted), EndpointConfig::cleartext());
		let client = TcpTransport::new(TokioStream::from(dialing), EndpointConfig::cleartext());
		(client, server)
	}

	/// A handler of the plane holds the drivers of the multiplexed connection
	/// it serves, so the drop of the plane ends the connection, and its peer
	/// reads the close (CWE-772).
	#[cfg(all(pooled_mux, feature = "tcp"))]
	#[tokio::test]
	async fn dropping_the_plane_ends_a_multiplexed_connection() -> crate::testing::TestResult {
		let (client, server) = cleartext_pair().await;
		let settings = MuxSettings::symmetric(4);

		let mut plane = plane();
		serve_on_free_slot(&mut plane, async move {
			// The drop of the plane ends the serve, so its outcome has no
			// reader.
			let _ended = server.serve(settings, Refusing, None).await;
		})
		.await;

		let (reader, writer) = client.into_split()?;
		let client = MuxTransport::new(reader, writer, MuxRole::Client, settings);
		let (_handle, client_reader, _client_writer, _responder) = client.into_parts();
		tokio::task::yield_now().await;

		drop(plane);

		let closed = tokio::time::timeout(CLOSE_GUARD, client_reader.drive()).await;
		assert!(matches!(closed, Ok(Err(TransportError::ConnectionClosed))));
		Ok(())
	}
}
