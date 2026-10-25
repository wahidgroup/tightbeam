//! Bounded connection acceptance.
//!
//! [`AcceptPlane`] is the crate's accept loop. The servlet, hive, gateway,
//! and async `server!` planes each drive one, so one type states the
//! connection cap, the permit lifetime, the handler task set, and the accept
//! retry pace. The servlet, hive, and gateway planes also set the trace and
//! the mux offer of their owner on each connection here.

use core::future::Future;
use std::sync::Arc;

use crate::constants::DEFAULT_ACCEPT_RETRY_DELAY;
use crate::transport::protocols::AsyncListenerTrait;
use crate::utils::time::Clock;

#[cfg(feature = "colony")]
use crate::trace::TraceHandle;
#[cfg(feature = "colony")]
use crate::transport::handshake::negotiation::TransportOffer;
#[cfg(feature = "colony")]
use crate::transport::multiplex::MuxCapable;
#[cfg(feature = "colony")]
use crate::transport::state::EncryptedProtocolState;

/// A plane that accepts connections under a fixed cap and owns what it admits.
///
/// One permit per live connection caps concurrent handlers, so a connection
/// flood queues in the listener backlog, which bounds live tasks and
/// descriptors by the cap (CWE-400). The plane owns the handler task set,
/// so a drop of the plane aborts those handlers and an aborted accept task
/// ends the connections it started (CWE-772).
pub struct AcceptPlane {
	permits: Arc<tokio::sync::Semaphore>,
	connections: tokio::task::JoinSet<()>,
	/// The clock on which an accept failure waits out its retry delay.
	clock: Arc<dyn Clock>,
}

impl AcceptPlane {
	/// Creates a plane that admits `max_connections` live handlers and paces
	/// accept retries on `clock`.
	///
	/// [`DEFAULT_MAX_SERVER_CONNECTIONS`] is the cap every accept plane uses
	/// unless a policy names its own.
	///
	/// [`DEFAULT_MAX_SERVER_CONNECTIONS`]: crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS
	#[must_use]
	pub fn new(max_connections: usize, clock: Arc<dyn Clock>) -> Self {
		Self {
			permits: Arc::new(tokio::sync::Semaphore::new(max_connections)),
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
	///
	/// The servlet, hive, and gateway planes accept here, so each connection
	/// they serve carries the trace and the mux offer of its owner.
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

/// The terms that an owner sets on each connection it serves: its trace, and
/// its mux offer.
///
/// The terms hold the handle of the owner's trace, so each connection records
/// into the trace that the handle holds when the connection starts. The trace
/// goes on before the handshake, so the trace records the handshake of every
/// connection, a peer that never authenticates included.
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

#[cfg(test)]
mod tests {
	use core::future::Future;
	use core::pin::pin;
	use core::sync::atomic::{AtomicBool, Ordering};
	use core::task::{Context, Waker};
	use core::time::Duration;

	use super::*;
	use crate::utils::time::ManualClock;

	fn plane(max_connections: usize) -> AcceptPlane {
		AcceptPlane::new(max_connections, Arc::new(ManualClock::default()))
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
		let plane = AcceptPlane::new(1, Arc::clone(&clock) as Arc<dyn Clock>);
		let mut context = Context::from_waker(Waker::noop());
		let mut wait = pin!(plane.absorb_failure());
		assert!(wait.as_mut().poll(&mut context).is_pending());

		clock.advance(DEFAULT_ACCEPT_RETRY_DELAY);
		assert!(wait.as_mut().poll(&mut context).is_ready());
	}

	#[tokio::test(start_paused = true)]
	async fn a_full_plane_admits_no_further_connection() {
		let mut plane = plane(1);
		let _held = plane.reserve().await;
		let blocked = tokio::time::timeout(Duration::from_secs(1), plane.reserve()).await;
		assert!(blocked.is_err());
	}

	#[tokio::test(start_paused = true)]
	async fn a_finished_connection_returns_its_slot() {
		let mut plane = plane(1);
		serve_on_free_slot(&mut plane, async {}).await;
		tokio::task::yield_now().await;

		let reserved = tokio::time::timeout(Duration::from_secs(1), plane.reserve()).await;
		assert!(reserved.is_ok());
	}

	#[tokio::test(start_paused = true)]
	async fn dropping_the_plane_aborts_its_connections() {
		static FINISHED: AtomicBool = AtomicBool::new(false);

		let mut plane = plane(1);
		serve_on_free_slot(&mut plane, async {
			tokio::time::sleep(Duration::from_secs(30)).await;
			FINISHED.store(true, Ordering::SeqCst);
		})
		.await;

		tokio::task::yield_now().await;
		drop(plane);
		tokio::time::advance(Duration::from_secs(60)).await;
		tokio::task::yield_now().await;
		assert!(!FINISHED.load(Ordering::SeqCst));
	}
}
