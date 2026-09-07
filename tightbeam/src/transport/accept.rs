//! Bounded connection acceptance.
//!
//! [`AcceptPlane`] is the crate's accept loop. The servlet, hive, gateway,
//! and `server!` planes each drive one, so the connection cap, the permit
//! lifetime, the handler task set, and the accept-failure budget stated once.

use core::future::Future;
use std::sync::Arc;

use crate::constants::{DEFAULT_ACCEPT_FAILURE_BUDGET, DEFAULT_ACCEPT_RETRY_DELAY, DEFAULT_MAX_SERVER_CONNECTIONS};
use crate::runtime::rt;
use crate::transport::protocols::AsyncListenerTrait;

/// Accepts connections under a fixed budget, owning what it admits.
///
/// One permit per live connection caps concurrent handlers, so a connection
/// flood queues in the listener backlog, which bounds live tasks and
/// descriptors by the cap (CWE-400). The plane owns the handler task set,
/// so dropping it aborts those handlers and an aborted accept task ends
/// the connections it started (CWE-772).
pub struct AcceptPlane {
	permits: Arc<tokio::sync::Semaphore>,
	connections: tokio::task::JoinSet<()>,
	consecutive_failures: u32,
}

impl Default for AcceptPlane {
	/// A plane admitting [`DEFAULT_MAX_SERVER_CONNECTIONS`] live handlers.
	fn default() -> Self {
		Self::new(DEFAULT_MAX_SERVER_CONNECTIONS)
	}
}

impl AcceptPlane {
	/// Creates a plane admitting `max_connections` live handlers.
	///
	/// [`AcceptPlane::default`] carries the cap every accept plane uses
	/// unless a policy names its own.
	#[must_use]
	pub fn new(max_connections: usize) -> Self {
		Self {
			permits: Arc::new(tokio::sync::Semaphore::new(max_connections)),
			connections: tokio::task::JoinSet::new(),
			consecutive_failures: 0,
		}
	}

	/// Waits for a free connection slot, reaping finished handlers first.
	///
	/// Returns [`None`] once the plane closes, which ends the accept loop.
	async fn reserve(&mut self) -> Option<tokio::sync::OwnedSemaphorePermit> {
		while self.connections.try_join_next().is_some() {}
		Arc::clone(&self.permits).acquire_owned().await.ok()
	}

	/// Runs `handler` on a reserved slot, releasing it on every exit path.
	fn serve<F>(&mut self, permit: tokio::sync::OwnedSemaphorePermit, handler: F)
	where
		F: Future<Output = ()> + Send + 'static,
	{
		self.consecutive_failures = 0;
		self.connections.spawn(async move {
			let _permit = permit;
			handler.await;
		});
	}

	/// Waits out one failed accept.
	///
	/// Returns `false` once the failures exhaust
	/// [`DEFAULT_ACCEPT_FAILURE_BUDGET`], which stops a loop whose listener
	/// has closed.
	async fn absorb_failure(&mut self) -> bool {
		self.consecutive_failures = self.consecutive_failures.saturating_add(1);
		if self.consecutive_failures > DEFAULT_ACCEPT_FAILURE_BUDGET {
			return false;
		}

		rt::sleep(DEFAULT_ACCEPT_RETRY_DELAY).await;
		true
	}

	/// Accepts on `listener` until the plane closes, running each admitted
	/// transport through `handler`.
	///
	/// The future owns the plane, so the task a caller spawns it on owns
	/// every connection the loop starts: aborting that task ends them all.
	pub async fn accept_on<L, F, Fut>(self, listener: L, handler: F)
	where
		L: AsyncListenerTrait + Sync,
		F: Fn(L::Transport) -> Fut,
		Fut: Future<Output = ()> + Send + 'static,
	{
		self.accept_on_reporting(listener, handler, |_| async {}).await;
	}

	/// Accepts as [`AcceptPlane::accept_on`] does, handing each failed
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
			if !self.absorb_failure().await {
				break;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::time::Duration;

	/// Fails `plane` up to its budget, returning the last verdict.
	async fn spend_failure_budget(plane: &mut AcceptPlane) -> bool {
		let mut verdict = true;
		for _ in 0..DEFAULT_ACCEPT_FAILURE_BUDGET {
			verdict = plane.absorb_failure().await;
		}

		verdict
	}

	#[tokio::test(start_paused = true)]
	async fn a_full_plane_admits_no_further_connection() {
		let mut plane = AcceptPlane::new(1);
		let _held = plane.reserve().await;
		let blocked = tokio::time::timeout(Duration::from_secs(1), plane.reserve()).await;
		assert!(blocked.is_err());
	}

	#[tokio::test(start_paused = true)]
	async fn a_finished_connection_returns_its_slot() {
		let mut plane = AcceptPlane::new(1);
		let permit = plane.reserve().await.expect("a free slot");
		plane.serve(permit, async {});
		tokio::task::yield_now().await;
		assert!(tokio::time::timeout(Duration::from_secs(1), plane.reserve()).await.is_ok());
	}

	#[tokio::test(start_paused = true)]
	async fn the_budget_ends_a_loop_whose_listener_stays_broken() {
		let mut plane = AcceptPlane::new(1);
		assert!(spend_failure_budget(&mut plane).await);
		assert!(!plane.absorb_failure().await);
	}

	#[tokio::test(start_paused = true)]
	async fn a_served_connection_restores_the_budget() {
		let mut plane = AcceptPlane::new(1);
		assert!(spend_failure_budget(&mut plane).await);

		let permit = plane.reserve().await.expect("a free slot");
		plane.serve(permit, async {});
		assert!(spend_failure_budget(&mut plane).await);
	}

	#[tokio::test]
	async fn dropping_the_plane_aborts_its_connections() {
		static FINISHED: AtomicBool = AtomicBool::new(false);

		let mut plane = AcceptPlane::new(1);
		let permit = plane.reserve().await.expect("a free slot");
		plane.serve(permit, async {
			tokio::time::sleep(Duration::from_secs(30)).await;
			FINISHED.store(true, Ordering::SeqCst);
		});

		tokio::task::yield_now().await;
		drop(plane);
		tokio::time::sleep(Duration::from_millis(50)).await;
		assert!(!FINISHED.load(Ordering::SeqCst));
	}
}
