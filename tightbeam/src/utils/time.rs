//! Wall-clock instants as protocol values, and the clock that reads them.
//!
//! Freshness, replay, retention and lease decisions compare an instant
//! against a window. The window is a [`Duration`]. The instant arrives on the
//! wire as unix milliseconds, and a bare `u64` there lets a call site pass an
//! instant where a window belongs and still compile. [`UnixMillis`] gives the
//! instant its own type, so the two cannot be exchanged.
//!
//! A runtime reads the time through a [`Clock`], so a test names the instant
//! a decision sees instead of sleeping until it arrives.
//!
//! # Sources
//!
//! - CWE-294, authentication bypass by capture-replay:
//!   <https://cwe.mitre.org/data/definitions/294.html>

use core::time::Duration;

use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};

/// A point in time, as unix milliseconds.
///
/// This is what `Frame.metadata.order` carries when a protocol uses it as an
/// issue time, and what a freshness or replay decision compares against.
/// Spans between instants are [`Duration`]s.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixMillis(u64);

impl UnixMillis {
	/// An instant from the milliseconds a peer stated.
	#[must_use]
	pub const fn new(millis: u64) -> Self {
		Self(millis)
	}

	/// The current instant from the system clock.
	///
	/// A clock set before the unix epoch reads as the epoch itself, so a
	/// comparison against this value stays defined. Present where
	/// [`SystemClock`] is.
	#[cfg(host_clock)]
	#[must_use]
	pub fn now() -> Self {
		SystemClock.unix()
	}

	/// The instant a system time names, reading a time before the epoch as
	/// the epoch.
	#[cfg(host_clock)]
	fn from_system(time: std::time::SystemTime) -> Self {
		let since_epoch = time.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();

		Self(saturating_millis(since_epoch))
	}

	/// The instant as unix milliseconds, for the wire field that carries it.
	#[must_use]
	pub const fn get(self) -> u64 {
		self.0
	}

	/// The span between this instant and `other`, in either direction.
	///
	/// Freshness tolerates clock skew on both sides, so the comparison is
	/// on the magnitude rather than the sign.
	#[must_use]
	pub const fn abs_diff(self, other: Self) -> Duration {
		Duration::from_millis(self.0.abs_diff(other.0))
	}

	/// The span from `earlier` to this instant, saturating at zero.
	///
	/// A clock that moved backwards yields a zero span rather than
	/// wrapping, so a window never widens on a clock step.
	#[must_use]
	pub const fn saturating_since(self, earlier: Self) -> Duration {
		Duration::from_millis(self.0.saturating_sub(earlier.0))
	}

	/// This instant advanced by `span`, saturating at the type's maximum.
	#[must_use]
	pub fn saturating_add(self, span: Duration) -> Self {
		Self(self.0.saturating_add(saturating_millis(span)))
	}
}

/// A reading of a clock that never steps backwards.
///
/// Leases, idle timeouts and handshake deadlines measure spans from it. Where
/// the standard library's clocks work it wraps [`std::time::Instant`].
/// Elsewhere it is the span since an origin the embedding runtime chooses,
/// because no `Instant` can be read there. This type is the one place that
/// choice is made.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(MonotonicReading);

#[cfg(host_clock)]
type MonotonicReading = std::time::Instant;

#[cfg(not(host_clock))]
type MonotonicReading = Duration;

impl MonotonicInstant {
	/// The reading a standard library clock took.
	#[cfg(host_clock)]
	#[must_use]
	pub const fn from_std(instant: std::time::Instant) -> Self {
		Self(instant)
	}

	/// The reading `since_origin` after the embedding runtime's origin.
	#[cfg(not(host_clock))]
	#[must_use]
	pub const fn from_elapsed(since_origin: Duration) -> Self {
		Self(since_origin)
	}

	/// The span from `earlier` to this reading, saturating at zero.
	#[must_use]
	pub fn saturating_duration_since(self, earlier: Self) -> Duration {
		#[cfg(host_clock)]
		let span = self.0.saturating_duration_since(earlier.0);

		#[cfg(not(host_clock))]
		let span = self.0.saturating_sub(earlier.0);

		span
	}

	/// This reading advanced by `span`, or `None` where the result has no
	/// representation.
	///
	/// A deadline that cannot be represented lies beyond any reading, so a
	/// caller treats `None` as a deadline that never arrives.
	#[must_use]
	pub fn checked_add(self, span: Duration) -> Option<Self> {
		let advanced = self.0.checked_add(span)?;

		Some(Self(advanced))
	}
}

/// The source a runtime reads the current time from, and waits on.
///
/// Each member answers a different question:
///
/// - [`Clock::unix`] is the wall clock, which freshness and replay compare
///   against the time a peer stated.
/// - [`Clock::monotonic`] never steps backwards, so leases, idle timeouts and
///   handshake deadlines measure from it.
/// - [`Clock::sleep`] waits on the same clock, so a restart backoff is
///   observed on every target that has a clock at all.
///
/// [`SystemClock`] is the default where the standard library's clocks work.
/// Elsewhere the embedding runtime installs a clock that reads its host. A
/// test installs a [`ManualClock`] and advances it, so a decision sees
/// exactly the instant the test names.
pub trait Clock: MaybeSend + MaybeSync + core::fmt::Debug {
	/// The current wall-clock instant.
	fn unix(&self) -> UnixMillis;

	/// The current monotonic instant.
	fn monotonic(&self) -> MonotonicInstant;

	/// Resolve once `span` has passed on this clock.
	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()>;
}

/// The operating system's clocks.
///
/// Absent on `wasm32-unknown-unknown`, where the standard library's clocks
/// panic when read, so a build for that target cannot name it and installs a
/// [`Clock`] that reads the host instead.
#[cfg(host_clock)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(host_clock)]
impl Clock for SystemClock {
	fn unix(&self) -> UnixMillis {
		UnixMillis::from_system(std::time::SystemTime::now())
	}

	fn monotonic(&self) -> MonotonicInstant {
		MonotonicInstant::from_std(std::time::Instant::now())
	}

	/// A tokio build yields the worker so other tasks keep running. A build
	/// without a reactor parks the calling thread, which is the only timer it
	/// has.
	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		#[cfg(feature = "tokio")]
		let wait: MaybeSendFuture<'_, ()> = Box::pin(tokio::time::sleep(span));

		#[cfg(not(feature = "tokio"))]
		let wait: MaybeSendFuture<'_, ()> = {
			std::thread::sleep(span);
			Box::pin(core::future::ready(()))
		};

		wait
	}
}

/// A clock that moves only when a test advances it.
///
/// Both readings start at the system clock's and move together, so a peer
/// that still reads the system clock agrees with this one until the first
/// [`ManualClock::advance`]. A sleep resolves once an advance carries the
/// clock past its span, so a loop sleeping on this clock waits for the test
/// rather than spinning.
#[cfg(all(host_clock, any(test, feature = "testing")))]
#[derive(Debug)]
pub struct ManualClock {
	unix_start: UnixMillis,
	monotonic_start: std::time::Instant,
	state: std::sync::Mutex<ManualState>,
}

/// How far a [`ManualClock`] has moved, and the sleeps waiting on it.
#[cfg(all(host_clock, any(test, feature = "testing")))]
#[derive(Debug, Default)]
struct ManualState {
	elapsed: Duration,
	sleepers: Vec<core::task::Waker>,
}

#[cfg(all(host_clock, any(test, feature = "testing")))]
impl ManualClock {
	/// Move both readings forward by `span`, waking every sleep it ends.
	pub fn advance(&self, span: Duration) {
		let sleepers = {
			let mut state = self.lock();
			state.elapsed = state.elapsed.saturating_add(span);
			core::mem::take(&mut state.sleepers)
		};

		// Woken outside the lock, so a sleeper that polls at once finds it
		// free.
		sleepers.into_iter().for_each(core::task::Waker::wake);
	}

	/// The total span every advance has moved this clock.
	pub fn elapsed(&self) -> Duration {
		self.lock().elapsed
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, ManualState> {
		self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}
}

/// A sleep on a [`ManualClock`], ready once the clock reaches `until`.
#[cfg(all(host_clock, any(test, feature = "testing")))]
struct ManualSleep<'a> {
	clock: &'a ManualClock,
	until: Duration,
}

#[cfg(all(host_clock, any(test, feature = "testing")))]
impl core::future::Future for ManualSleep<'_> {
	type Output = ();

	fn poll(self: core::pin::Pin<&mut Self>, context: &mut core::task::Context<'_>) -> core::task::Poll<()> {
		let mut state = self.clock.lock();
		if state.elapsed >= self.until {
			return core::task::Poll::Ready(());
		}

		state.sleepers.push(context.waker().clone());
		core::task::Poll::Pending
	}
}

#[cfg(all(host_clock, any(test, feature = "testing")))]
impl Default for ManualClock {
	fn default() -> Self {
		Self {
			unix_start: SystemClock.unix(),
			monotonic_start: std::time::Instant::now(),
			state: Default::default(),
		}
	}
}

#[cfg(all(host_clock, any(test, feature = "testing")))]
impl Clock for ManualClock {
	fn unix(&self) -> UnixMillis {
		self.unix_start.saturating_add(self.elapsed())
	}

	fn monotonic(&self) -> MonotonicInstant {
		let start = self.monotonic_start;
		let reading = start.checked_add(self.elapsed()).unwrap_or(start);
		MonotonicInstant::from_std(reading)
	}

	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		let until = self.elapsed().saturating_add(span);
		Box::pin(ManualSleep { clock: self, until })
	}
}

/// Whole milliseconds in `span`, saturating where they exceed a `u64`.
fn saturating_millis(span: Duration) -> u64 {
	u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_span_between_instants_never_wraps_on_a_backward_clock() {
		let earlier = UnixMillis::new(1_000);
		let later = UnixMillis::new(400);
		assert_eq!(later.saturating_since(earlier), Duration::ZERO);
	}

	#[test]
	fn an_instant_advanced_past_the_range_saturates() {
		let near_end = UnixMillis::new(u64::MAX - 1);
		let advanced = near_end.saturating_add(Duration::from_secs(1));
		assert_eq!(advanced, UnixMillis::new(u64::MAX));
	}

	#[test]
	fn a_manual_clock_moves_both_readings_together() {
		let clock = ManualClock::default();
		let unix_before = clock.unix();
		let monotonic_before = clock.monotonic();

		clock.advance(Duration::from_secs(2));

		assert_eq!(clock.unix().saturating_since(unix_before), Duration::from_secs(2));
		assert_eq!(
			clock.monotonic().saturating_duration_since(monotonic_before),
			Duration::from_secs(2)
		);
	}

	/// A sleep on a manual clock waits for the test, so a loop sleeping on
	/// it never spins, and resolves once an advance covers its span.
	#[test]
	fn a_manual_clock_sleep_resolves_once_advanced_past_its_span() {
		let clock = ManualClock::default();
		let mut context = core::task::Context::from_waker(core::task::Waker::noop());
		let mut wait = clock.sleep(Duration::from_secs(30));
		assert!(wait.as_mut().poll(&mut context).is_pending());

		clock.advance(Duration::from_secs(29));
		assert!(wait.as_mut().poll(&mut context).is_pending());

		clock.advance(Duration::from_secs(1));
		assert!(wait.as_mut().poll(&mut context).is_ready());
	}

	#[test]
	fn a_deadline_past_the_representable_range_is_absent() {
		let clock = ManualClock::default();
		assert!(clock.monotonic().checked_add(Duration::MAX).is_none());
	}

	#[test]
	fn skew_reads_the_same_in_either_direction() {
		let early = UnixMillis::new(1_000);
		let late = UnixMillis::new(1_250);
		assert_eq!(early.abs_diff(late), late.abs_diff(early));
	}
}
