//! The system clock of a build without `tokio`, whose sleep parks the thread
//! on its first poll.

use std::time::Duration;

use tightbeam::clock::{Clock, SystemClock};

/// The call that builds a five-second sleep returns at once, because the park
/// waits for the first poll.
#[test]
fn building_a_sleep_returns_at_once() {
	let clock = SystemClock;
	let started = clock.monotonic();
	let wait = clock.sleep(Duration::from_secs(5));
	let built = clock.monotonic().saturating_duration_since(started);

	drop(wait);
	assert!(built < Duration::from_millis(100));
}
