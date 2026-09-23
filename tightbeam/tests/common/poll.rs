//! The one bounded wait the integration suites share.
//!
//! These suites drive real servers over real sockets, and the state they wait
//! on changes on another task: a beat, a flood, a rekey, a goaway. There is no
//! event to await and no clock the code under test reads that a test controls,
//! so a bounded poll is the wait. Keeping it in one place means the bound, the
//! final read, and the failure answer are decided once.

use core::time::Duration;

/// Polls `ready` until it holds or `attempts` run out, and answers whether it
/// held.
///
/// The condition is read once more after the last sleep, so a state that
/// settles during the final interval still counts. Branching lives here, not
/// in scenarios.
pub async fn poll_until(attempts: u32, interval: Duration, mut ready: impl FnMut() -> bool) -> bool {
	for _ in 0..attempts {
		if ready() {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	ready()
}
