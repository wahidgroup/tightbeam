//! The bounded waits that the integration suites share.
//!
//! These suites drive real servers over real sockets, and the state they wait
//! on changes on another task: a beat, a flood, a rekey, or a goaway. A test
//! that moves the clock the code under test reads still waits for the socket
//! work that the move sets off. The code offers no event to await for that
//! work, so a bounded poll is the wait.
//!
//! One home for the poll decides the bound, the final read, and the failure
//! answer once.

use core::future::IntoFuture;
use core::time::Duration;

use tokio::task::JoinHandle;

/// The longest that a wait on another task runs, so a hang fails its test in
/// place of the run.
pub const HANG_GUARD: Duration = Duration::from_secs(10);

/// Polls `ready` until it holds or `attempts` run out, and answers whether it
/// held.
///
/// The condition is read once more after the last sleep, so a state that
/// settles during the final interval still counts. The branching lives here,
/// so a scenario reads as one straight line.
pub async fn poll_until(attempts: u32, interval: Duration, mut ready: impl FnMut() -> bool) -> bool {
	for _ in 0..attempts {
		if ready() {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	ready()
}

/// The output of `work`, once it ends.
///
/// The wait panics with `expectation` when `work` outlasts [`HANG_GUARD`].
pub async fn within_hang_guard<F: IntoFuture>(work: F, expectation: &str) -> F::Output {
	let ended = tokio::time::timeout(HANG_GUARD, work).await;
	ended.expect(expectation)
}

/// The output of the task of `handle`, once the task ends.
///
/// The wait panics when the task panics or outlasts [`HANG_GUARD`], and the
/// panic names the cause.
pub async fn joined<T>(handle: JoinHandle<T>) -> T {
	let joined = within_hang_guard(handle, "the task ends within the hang guard").await;
	joined.expect("the task ends without a panic")
}
