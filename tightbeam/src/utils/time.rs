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
	/// comparison against this value stays defined.
	///
	/// Absent on `wasm32-unknown-unknown`, where the standard library's
	/// system clock panics when read. A browser build takes its instant from
	/// the host and passes it to [`UnixMillis::new`].
	#[cfg(all(feature = "std", not(all(target_arch = "wasm32", target_os = "unknown"))))]
	#[must_use]
	pub fn now() -> Self {
		Self::from_system(std::time::SystemTime::now())
	}

	/// The instant a system time names, reading a time before the epoch as
	/// the epoch.
	#[cfg(feature = "std")]
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

/// The source a runtime reads the current time from.
///
/// It gives two readings because they answer different questions:
///
/// - [`Clock::unix`] is the wall clock, which freshness and replay compare
///   against the time a peer stated.
/// - [`Clock::monotonic`] never steps backwards, so leases and idle timeouts
///   measure from it.
///
/// [`SystemClock`] is the default. A test installs a [`ManualClock`] and
/// advances it, so a decision sees exactly the instant the test names.
#[cfg(feature = "std")]
pub trait Clock: Send + Sync + core::fmt::Debug {
	/// The current wall-clock instant.
	fn unix(&self) -> UnixMillis;

	/// The current monotonic instant.
	fn monotonic(&self) -> std::time::Instant;
}

/// The operating system's clocks.
///
/// On `wasm32-unknown-unknown` the standard library's clocks panic when read,
/// so a browser build installs a [`Clock`] that reads the host's time.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
	fn unix(&self) -> UnixMillis {
		UnixMillis::from_system(std::time::SystemTime::now())
	}

	fn monotonic(&self) -> std::time::Instant {
		std::time::Instant::now()
	}
}

/// A clock that moves only when a test advances it.
///
/// Both readings start at the system clock's and move together, so a peer
/// that still reads the system clock agrees with this one until the first
/// [`ManualClock::advance`].
#[cfg(all(feature = "std", any(test, feature = "testing")))]
#[derive(Debug)]
pub struct ManualClock {
	unix_start: UnixMillis,
	monotonic_start: std::time::Instant,
	elapsed: std::sync::Mutex<Duration>,
}

#[cfg(all(feature = "std", any(test, feature = "testing")))]
impl ManualClock {
	/// Move both readings forward by `span`.
	pub fn advance(&self, span: Duration) {
		let mut elapsed = self.elapsed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		*elapsed = elapsed.saturating_add(span);
	}

	fn elapsed(&self) -> Duration {
		*self.elapsed.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
	}
}

#[cfg(all(feature = "std", any(test, feature = "testing")))]
impl Default for ManualClock {
	fn default() -> Self {
		let system = SystemClock;

		Self {
			unix_start: system.unix(),
			monotonic_start: system.monotonic(),
			elapsed: Default::default(),
		}
	}
}

#[cfg(all(feature = "std", any(test, feature = "testing")))]
impl Clock for ManualClock {
	fn unix(&self) -> UnixMillis {
		self.unix_start.saturating_add(self.elapsed())
	}

	fn monotonic(&self) -> std::time::Instant {
		let start = self.monotonic_start;
		start.checked_add(self.elapsed()).unwrap_or(start)
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
		assert_eq!(clock.monotonic().duration_since(monotonic_before), Duration::from_secs(2));
	}

	#[test]
	fn skew_reads_the_same_in_either_direction() {
		let early = UnixMillis::new(1_000);
		let late = UnixMillis::new(1_250);
		assert_eq!(early.abs_diff(late), late.abs_diff(early));
	}
}
