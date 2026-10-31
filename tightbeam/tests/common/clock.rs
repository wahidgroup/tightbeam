//! The manual clock that a test hands a hive.
//!
//! A hive sleeps on its clock in tasks of its own, and [`ManualClock`] gives
//! no signal when a task parks a sleep on it. A sleep starts its span when the
//! task creates it, so an advance that comes before the sleep is lost to it.
//! [`ParkingClock`] records each sleep as it starts, so a test awaits the
//! sleep and then advances.

use core::time::Duration;

use tokio::sync::watch;

use tightbeam::clock::{Clock, ManualClock, MonotonicInstant, UnixMillis};
use tightbeam::marker::MaybeSendFuture;

use crate::common::poll::within_hang_guard;

/// A [`Clock`] over a [`ManualClock`] that records the span of each sleep a
/// task starts on it.
///
/// A hive sleeps in more than one task, so a wait names the span of the sleep
/// it awaits. A wait takes any sleep of its span, so the loop that a test
/// waits on must be the only loop that sleeps that span on the clock.
#[derive(Debug, Default)]
pub struct ParkingClock {
	/// The clock that each reading and each sleep runs on.
	clock: ManualClock,
	/// The span of each sleep that started and that no wait took.
	parked: watch::Sender<Vec<Duration>>,
}

impl ParkingClock {
	/// Waits for a task to sleep for `span`, and takes that sleep, so the next
	/// wait for `span` waits for a later sleep.
	///
	/// A sleep that started before the call counts. The wait panics when no
	/// task sleeps for `span` within [`HANG_GUARD`].
	///
	/// [`HANG_GUARD`]: crate::common::poll::HANG_GUARD
	pub async fn parked(&self, span: Duration) {
		let take = move |parked: &mut Vec<Duration>| {
			let at = parked.iter().position(|started| *started == span);
			at.map(|at| parked.remove(at)).is_some()
		};

		let mut started = self.parked.subscribe();
		let taken = async {
			while !self.parked.send_if_modified(take) {
				started.changed().await.expect("the clock holds the sender of its sleeps");
			}
		};

		within_hang_guard(taken, "a task sleeps for the span within the hang guard").await;
	}

	/// Moves the clock forward by `span`, and wakes each sleep that the move
	/// ends.
	pub fn advance(&self, span: Duration) {
		self.clock.advance(span);
	}
}

impl Clock for ParkingClock {
	fn unix(&self) -> UnixMillis {
		self.clock.unix()
	}

	fn monotonic(&self) -> MonotonicInstant {
		self.clock.monotonic()
	}

	// The sleep fixes its end before the record wakes a wait, so an advance
	// that follows the wait ends this sleep.
	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		let sleep = self.clock.sleep(span);
		self.parked.send_modify(|parked| parked.push(span));
		sleep
	}
}
