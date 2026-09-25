//! The one bounded wait the integration suites share.
//!
//! These suites drive real servers over real sockets, and the state they wait
//! on changes on another task: a beat, a flood, a rekey, or a goaway. A test
//! that moves the clock the code under test reads still waits for the socket
//! work that the move sets off. The code offers no event to await for that
//! work, so a bounded poll is the wait.
//!
//! One home for the poll decides the bound, the final read, and the failure
//! answer once.

use core::time::Duration;

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
