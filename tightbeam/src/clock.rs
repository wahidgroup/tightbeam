//! Unix-time instants as protocol values, and the clock that reads them.
//!
//! Freshness, replay, retention and lease decisions compare an instant
//! against a window. The window is a [`Duration`]. The instant arrives on the
//! wire as unix milliseconds, and a bare `u64` there lets a call site pass an
//! instant where a window belongs and still compile. [`UnixMillis`] gives the
//! instant its own type, so a call site cannot exchange the two.
//!
//! A runtime reads the time through a [`Clock`], so a test names the instant
//! a decision sees and does not sleep until it arrives. Every bounded wait
//! runs through `within` on `dyn Clock` or a [`Timer`].
//!
//! # Sources
//!
//! - CWE-294, authentication bypass by capture-replay: <https://cwe.mitre.org/data/definitions/294.html>

use core::fmt;
use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(feature = "tokio")]
use tokio::runtime::Handle;

use crate::marker::{MaybeSend, MaybeSendFuture, MaybeSync};

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
	/// comparison against this value stays defined. It exists where
	/// [`SystemClock`] exists.
	#[cfg(host_clock)]
	#[must_use]
	pub fn now() -> Self {
		SystemClock.unix()
	}

	/// The current instant from the `time` crate, for a build that has no
	/// host clock and enables `time`.
	///
	/// On `wasm32-unknown-unknown` that crate reads the JavaScript clock, the
	/// one clock such a build has. A reading before the unix epoch is the
	/// epoch itself, as on a host.
	#[cfg(all(feature = "time", not(host_clock)))]
	#[must_use]
	pub fn now() -> Self {
		let reading = crate::time::OffsetDateTime::now_utc();
		Self::from_unix_nanos(reading.unix_timestamp_nanos())
	}

	/// The instant `nanos` after the unix epoch, where a time before the epoch
	/// reads as the epoch.
	#[cfg(any(test, all(feature = "time", not(host_clock))))]
	fn from_unix_nanos(nanos: i128) -> Self {
		let millis = nanos / 1_000_000;
		Self(u64::try_from(millis).unwrap_or_default())
	}

	/// The instant a system time names, where a time before the epoch reads as
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
/// - [`Clock::unix`] reads unix time, which freshness and replay compare against the time a peer stated.
/// - [`Clock::monotonic`] never steps backwards, so leases, idle timeouts and
///   handshake deadlines measure from it.
/// - [`Clock::sleep`] waits on the same clock, so a restart backoff is
///   observed on every target that has a clock at all.
/// - [`Clock::timing`] states whether a bound races, runs unbounded, or refuses on the calling thread.
/// - [`Clock::resetting_sleep`] offers one sleep that a [`Timer`] resets for each wait.
///
/// [`SystemClock`] is the default where the standard library's clocks work.
/// Elsewhere the embedding runtime installs a clock that reads its host. A
/// test installs a [`ManualClock`] and advances it, so a decision sees the
/// instant the test names.
pub trait Clock: MaybeSend + MaybeSync + core::fmt::Debug {
	/// The current instant in unix time.
	fn unix(&self) -> UnixMillis;

	/// The current monotonic instant.
	fn monotonic(&self) -> MonotonicInstant;

	/// Resolve once `span` has passed on this clock.
	///
	/// The future returns `Pending` while it waits, or parks the calling
	/// thread for the span.
	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()>;

	/// How a bound on this clock runs on the calling thread. `within` on
	/// `dyn Clock` and [`Timer`] read it at the first wait of a bound.
	///
	/// A clock whose sleep parks the thread MUST NOT return
	/// [`Timing::Races`], because a race against a sleep that parks holds the
	/// work beside it.
	fn timing(&self) -> Timing;

	/// A sleep that a [`Timer`] keeps and resets for each wait, so a party that
	/// waits many times makes its sleep once. The default is `None`, and a
	/// timer on such a clock makes a fresh sleep for each wait.
	fn resetting_sleep(&self) -> Option<Pin<Box<dyn ResetSleep>>> {
		None
	}
}

/// How a clock runs a bound on the calling thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Timing {
	/// The sleep returns `Pending` while it waits, so a bound races the work
	/// against it.
	Races,
	/// The sleep parks the thread, so no sleep can race the work, and a bound
	/// runs the work unbounded.
	Parks,
	/// The calling thread has no timer for this clock, so a bound refuses work
	/// that waits with [`Lapse::NoTimer`].
	Absent,
}

/// A sleep that a [`Timer`] moves to a new span for each wait.
///
/// A transport keeps its timer, so the sleep is `Sync` wherever a transport
/// is.
pub trait ResetSleep: Future<Output = ()> + MaybeSend + MaybeSync {
	/// Resolve once `span` passes from now, in place of the span it held.
	fn reset(self: Pin<&mut Self>, span: Duration);

	/// Whether this sleep runs on the timer of the calling thread. A [`Timer`]
	/// makes a new sleep in place of one that does not. The default is `true`.
	fn runs_here(&self) -> bool {
		true
	}
}

/// The longest span a reset sleep waits: thirty years, past every deadline
/// of a connection.
#[cfg(feature = "tokio")]
const LONGEST_SLEEP: Duration = Duration::from_secs(946_080_000);

/// A tokio sleep beside the runtime that made it.
///
/// A tokio sleep runs on the timer of its own runtime alone, so the sleep
/// reports that runtime, and a [`Timer`] polled on another runtime makes a
/// sleep there.
#[cfg(feature = "tokio")]
struct RuntimeSleep {
	runtime: tokio::runtime::Id,
	sleep: Pin<Box<tokio::time::Sleep>>,
}

#[cfg(feature = "tokio")]
impl Future for RuntimeSleep {
	type Output = ();

	fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
		self.get_mut().sleep.as_mut().poll(context)
	}
}

#[cfg(feature = "tokio")]
impl ResetSleep for RuntimeSleep {
	fn reset(self: Pin<&mut Self>, span: Duration) {
		let now = tokio::time::Instant::now();
		let deadline = now.checked_add(span.min(LONGEST_SLEEP)).unwrap_or(now);
		self.get_mut().sleep.as_mut().reset(deadline);
	}

	fn runs_here(&self) -> bool {
		Handle::try_current().is_ok_and(|current| current.id() == self.runtime)
	}
}

/// Why a bound ended before its work.
///
/// `within` on `dyn Clock` and [`Timer`] return it. A transport reports
/// [`Lapse::Passed`] as `TransportFailure::DeadlineExceeded` and
/// [`Lapse::NoTimer`] as `TransportFailure::FailedPrecondition`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lapse {
	/// The span passed on the clock before the work ended.
	Passed,
	/// The polling thread has no timer for the clock ([`Timing::Absent`]), so
	/// the bound refused work that waits.
	NoTimer,
}

impl fmt::Display for Lapse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Passed => f.write_str("the span passed before the work ended"),
			Self::NoTimer => f.write_str("the polling thread has no timer to bound the work"),
		}
	}
}

impl core::error::Error for Lapse {}

impl<'d> dyn Clock + 'd {
	/// Run `work` until it ends or `span` passes on this clock. It is the one
	/// race of a wait against a span in this crate, and [`Timer`] runs the same
	/// race for a party that waits many times.
	///
	/// - The work takes the first poll, and the sleep starts only when the work
	///   waits, so work that is ready wins and makes no sleep.
	/// - Past the span, `work` drops unfinished.
	/// - The race reads [`Clock::timing`] at the first wait, on the thread that
	///   polls it. Under [`Timing::Parks`] the work runs unbounded, and under
	///   [`Timing::Absent`] work that waits ends at once with
	///   [`Lapse::NoTimer`].
	/// - `work` is `Unpin`, so the race polls it in place and holds it once. A
	///   caller pins an `async` block or call where it makes it, with
	///   [`core::pin::pin!`].
	///
	/// # Errors
	///
	/// - [`Lapse::Passed`] -- `span` passed before `work` ended.
	/// - [`Lapse::NoTimer`] -- the polling thread has no timer, and `work` waits.
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(all(feature = "tokio", feature = "testing"))]
	/// # {
	/// use core::pin::pin;
	/// use std::sync::Arc;
	/// use std::time::Duration;
	///
	/// use tightbeam::clock::{Clock, Lapse, ManualClock};
	/// use tightbeam::runtime::rt;
	///
	/// let clock: Arc<dyn Clock> = Arc::new(ManualClock::default());
	///
	/// let answered = rt::block_on(clock.within(Duration::from_secs(5), pin!(async { 7 })));
	/// assert_eq!(answered, Ok(7));
	///
	/// let stalled = rt::block_on(clock.within(Duration::ZERO, core::future::pending::<()>()));
	/// assert_eq!(stalled, Err(Lapse::Passed));
	/// # }
	/// ```
	pub fn within<'c, F: Future + Unpin>(
		&'c self,
		span: Duration,
		work: F,
	) -> impl Future<Output = Result<F::Output, Lapse>> + use<'c, 'd, F> {
		race(self, work, move || self.sleep(span))
	}
}

/// The bound of a party that waits many times on one clock, such as one half
/// of a connection.
///
/// It runs the race of `within` on `dyn Clock`. Where the clock offers a
/// [`Clock::resetting_sleep`], the timer keeps that sleep across waits and
/// sleeps, so the party makes its sleep at its first wait that waits. A timer
/// that waits on another runtime makes a sleep there, as
/// [`ResetSleep::runs_here`] reports.
pub struct Timer {
	clock: Arc<dyn Clock>,
	kept: Option<Pin<Box<dyn ResetSleep>>>,
}

impl Timer {
	/// A timer on `clock` that holds no sleep yet.
	#[must_use]
	pub fn new(clock: Arc<dyn Clock>) -> Self {
		Self { clock, kept: None }
	}

	/// The clock this timer runs on.
	#[must_use]
	pub fn clock(&self) -> &Arc<dyn Clock> {
		&self.clock
	}

	/// Run `work` until it ends or `span` passes, as `within` on `dyn Clock`
	/// does.
	///
	/// # Errors
	///
	/// - The errors of `within` on `dyn Clock`.
	pub fn within<F: Future + Unpin>(
		&mut self,
		span: Duration,
		work: F,
	) -> impl Future<Output = Result<F::Output, Lapse>> + use<'_, F> {
		let Self { clock, kept } = self;
		let clock: &dyn Clock = &**clock;
		race(clock, work, move || Expiry::of(clock, kept, span))
	}

	/// Resolve once `span` passes on the clock of this timer, on the sleep the
	/// timer keeps where the clock offers one.
	pub fn sleep(&mut self, span: Duration) -> impl Future<Output = ()> + use<'_> {
		let Self { clock, kept } = self;
		Expiry::of(&**clock, kept, span)
	}
}

/// The sleep that ends one wait of a [`Timer`]: the sleep it keeps, reset to
/// the span, or a fresh sleep where the clock offers none to keep.
enum Expiry<'a> {
	Kept(Pin<&'a mut (dyn ResetSleep + 'static)>),
	Fresh(MaybeSendFuture<'a, ()>),
}

impl<'a> Expiry<'a> {
	/// The sleep of a wait of `span` on `clock`, which keeps its resetting
	/// sleep in `kept` once the clock offers one.
	fn of(clock: &'a dyn Clock, kept: &'a mut Option<Pin<Box<dyn ResetSleep>>>, span: Duration) -> Self {
		// The timer makes its sleep at its first wait, and again where the
		// sleep it keeps runs on the timer of another thread.
		if kept.as_ref().is_none_or(|sleep| !sleep.runs_here()) {
			*kept = clock.resetting_sleep();
		}

		match kept {
			Some(sleep) => {
				sleep.as_mut().reset(span);
				Self::Kept(sleep.as_mut())
			}
			None => Self::Fresh(clock.sleep(span)),
		}
	}
}

impl Future for Expiry<'_> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
		match self.get_mut() {
			Self::Kept(sleep) => sleep.as_mut().poll(context),
			Self::Fresh(sleep) => sleep.as_mut().poll(context),
		}
	}
}

/// Run `work` until it ends or the sleep that `arm` makes resolves, as the
/// timing of `clock` allows. `work` is polled in place, so the race holds it
/// once.
async fn race<F, E>(clock: &dyn Clock, mut work: F, arm: impl FnOnce() -> E) -> Result<F::Output, Lapse>
where
	F: Future + Unpin,
	E: Future<Output = ()> + Unpin,
{
	// 1. The work takes the first poll, so work that is ready wins and makes no sleep.
	if let Poll::Ready(output) = poll_fn(|context| Poll::Ready(Pin::new(&mut work).poll(context))).await {
		return Ok(output);
	}

	// 2. The clock of the polling thread decides how the waiting work runs.
	let mut expiry = match clock.timing() {
		Timing::Races => arm(),
		Timing::Parks => return Ok(poll_fn(|context| Pin::new(&mut work).poll(context)).await),
		Timing::Absent => return Err(Lapse::NoTimer),
	};

	// 3. The sleep takes its first poll in the wake of the first wait, and
	//    each later wake polls the work first.
	let mut first_wake = true;
	poll_fn(|context| {
		if !core::mem::take(&mut first_wake) {
			if let Poll::Ready(output) = Pin::new(&mut work).poll(context) {
				return Poll::Ready(Ok(output));
			}
		}

		Pin::new(&mut expiry).poll(context).map(|()| Err(Lapse::Passed))
	})
	.await
}

/// The operating system's clocks.
///
/// The type needs `std` and is absent on `wasm32-unknown-unknown`, where the
/// standard library's clocks panic when read, so a build for that target cannot
/// name it and installs a [`Clock`] that reads the host instead.
///
/// # Panics
///
/// - A sleep or a bound that waits on a thread that runs a tokio runtime built
///   without its time driver panics in tokio. Tokio offers no check for the
///   driver, so the runtime MUST enable time (`enable_time` or `enable_all`).
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

	/// The sleep reads its thread at its first poll. On a thread that runs a
	/// tokio runtime it yields the worker, so other tasks keep running. A
	/// build without a reactor, and a thread outside any tokio runtime, park
	/// the calling thread, which is the only timer there.
	#[cfg_attr(
		feature = "tokio",
		expect(
			clippy::disallowed_methods,
			reason = "SystemClock makes every tokio timer of the crate"
		)
	)]
	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		Box::pin(async move {
			#[cfg(feature = "tokio")]
			if Handle::try_current().is_ok() {
				tokio::time::sleep(span).await;
				return;
			}

			std::thread::sleep(span);
		})
	}

	/// A thread that runs a tokio runtime races a bound. A thread outside any
	/// tokio runtime has no timer that yields, so a bound there refuses work
	/// that waits. A build without `tokio` parks, so its bounds run unbounded.
	fn timing(&self) -> Timing {
		#[cfg(feature = "tokio")]
		let timing = match Handle::try_current() {
			Ok(_) => Timing::Races,
			Err(_) => Timing::Absent,
		};

		#[cfg(not(feature = "tokio"))]
		let timing = Timing::Parks;

		timing
	}

	/// A thread that runs a tokio runtime offers one tokio sleep to keep, which
	/// runs on that runtime. A thread outside a runtime, and a build without
	/// `tokio`, offer none.
	#[cfg_attr(
		feature = "tokio",
		expect(
			clippy::disallowed_methods,
			reason = "SystemClock makes every tokio timer of the crate"
		)
	)]
	fn resetting_sleep(&self) -> Option<Pin<Box<dyn ResetSleep>>> {
		#[cfg(feature = "tokio")]
		if let Ok(current) = Handle::try_current() {
			let sleep = Box::pin(tokio::time::sleep(Duration::ZERO));

			return Some(Box::pin(RuntimeSleep { runtime: current.id(), sleep }));
		}

		None
	}
}

/// A clock that moves only when a test advances it.
///
/// Both readings start at the system clock's and move together, so a peer
/// that still reads the system clock agrees with this one until the first
/// [`ManualClock::advance`]. A sleep resolves once an advance carries the
/// clock to the end of its span, so a loop that sleeps on this clock waits for
/// the test and does not spin.
#[cfg(all(host_clock, any(test, feature = "testing")))]
#[derive(Debug)]
pub struct ManualClock {
	unix_start: UnixMillis,
	monotonic_start: std::time::Instant,
	state: std::sync::Mutex<ManualState>,
}

/// How far a [`ManualClock`] has moved, and the sleeps that wait on it.
#[cfg(all(host_clock, any(test, feature = "testing")))]
#[derive(Debug, Default)]
struct ManualState {
	elapsed: Duration,
	sleepers: Vec<core::task::Waker>,
}

#[cfg(all(host_clock, any(test, feature = "testing")))]
impl ManualClock {
	/// A clock whose unix reading starts at `unix` in place of the system
	/// clock's, so a test that names an instant reads it on every run.
	pub(crate) fn at(unix: UnixMillis) -> Self {
		Self { unix_start: unix, ..Self::default() }
	}

	/// Move both readings forward by `span`, and wake every sleep it ends.
	pub fn advance(&self, span: Duration) {
		let sleepers = {
			let mut state = self.lock();
			state.elapsed = state.elapsed.saturating_add(span);
			core::mem::take(&mut state.sleepers)
		};

		// The sleepers wake outside the lock, so a sleeper that polls at once
		// finds the lock free.
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

	fn timing(&self) -> Timing {
		Timing::Races
	}
}

/// A [`ManualClock`] whose bounds run unbounded, as a clock whose sleep parks
/// the thread does ([`Timing::Parks`]).
#[cfg(all(host_clock, test))]
#[derive(Debug, Default)]
pub(crate) struct BlockingClock(pub(crate) ManualClock);

#[cfg(all(host_clock, test))]
impl Clock for BlockingClock {
	fn unix(&self) -> UnixMillis {
		self.0.unix()
	}

	fn monotonic(&self) -> MonotonicInstant {
		self.0.monotonic()
	}

	fn sleep(&self, span: Duration) -> MaybeSendFuture<'_, ()> {
		self.0.sleep(span)
	}

	fn timing(&self) -> Timing {
		Timing::Parks
	}
}

/// Whole milliseconds in `span`, saturating where they exceed a `u64`.
fn saturating_millis(span: Duration) -> u64 {
	u64::try_from(span.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
	use core::pin::pin;

	use super::*;

	/// The span to an earlier instant is zero, so a clock that steps back
	/// yields no span that wraps.
	#[test]
	fn a_span_between_instants_never_wraps_on_a_backward_clock() {
		let earlier = UnixMillis::new(1_000);
		let later = UnixMillis::new(400);
		assert_eq!(later.saturating_since(earlier), Duration::ZERO);
	}

	// The arm that reads the `time` crate runs on no host, so this table pins
	// its one conversion: whole milliseconds, with a reading before the epoch
	// clamped to zero.
	crate::tb_cases! {
		fn a_reading_in_nanoseconds_becomes_whole_milliseconds((nanos, millis): (i128, u64)) {
			assert_eq!(UnixMillis::from_unix_nanos(nanos), UnixMillis::new(millis));
		}
		cases {
			positive => (1_500_000, 1),
			negative_clamps_to_zero => (-1_500_000, 0),
		}
	}

	/// An instant advanced past the end of the range saturates at the end.
	#[test]
	fn an_instant_advanced_past_the_range_saturates() {
		let near_end = UnixMillis::new(u64::MAX - 1);
		let advanced = near_end.saturating_add(Duration::from_secs(1));
		assert_eq!(advanced, UnixMillis::new(u64::MAX));
	}

	/// A bound on `clock` around `work`, polled once with a waker that drops
	/// every wake.
	fn poll_once<F: Future + Unpin>(clock: &dyn Clock, span: Duration, work: F) -> Poll<Result<F::Output, Lapse>> {
		let mut context = core::task::Context::from_waker(core::task::Waker::noop());
		let mut bounded = pin!(clock.within(span, work));
		bounded.as_mut().poll(&mut context)
	}

	/// Work that ends with 7, boxed so one case table holds work that is
	/// ready and work that waits.
	type Work = Pin<Box<dyn Future<Output = u8>>>;

	/// Work that waits once, then ends with 7.
	fn waits_once() -> impl Future<Output = u8> + Unpin {
		let mut waited = false;
		poll_fn(move |context| {
			if core::mem::replace(&mut waited, true) {
				return Poll::Ready(7);
			}

			context.waker().wake_by_ref();
			Poll::Pending
		})
	}

	// The work takes the first poll, so work that is ready wins over a span
	// that already passed, and work that waits loses to it.
	crate::tb_cases! {
		fn a_bound_answers_by_the_first_poll((work, expected): (Work, Poll<Result<u8, Lapse>>)) {
			assert_eq!(poll_once(&ManualClock::default(), Duration::ZERO, work), expected);
		}
		cases {
			ready_work => (Box::pin(core::future::ready(7)), Poll::Ready(Ok(7))),
			waiting_work => (Box::pin(core::future::pending::<u8>()), Poll::Ready(Err(Lapse::Passed))),
		}
	}

	/// A clock that parks runs waiting work unbounded, so the work ends past a
	/// span that already passed.
	#[test]
	fn a_bound_on_a_clock_that_parks_runs_its_work_unbounded() {
		let bounded = poll_once(&BlockingClock::default(), Duration::ZERO, waits_once());
		assert_eq!(bounded, Poll::Ready(Ok(7)));
	}

	/// Work that outlasts its span drops at the span, and not before it.
	#[test]
	fn a_bound_ends_work_that_outlasts_its_span() {
		let manual = ManualClock::default();
		let clock: &dyn Clock = &manual;
		let mut context = core::task::Context::from_waker(core::task::Waker::noop());
		let mut bounded = pin!(clock.within(Duration::from_secs(3), core::future::pending::<()>()));
		assert!(bounded.as_mut().poll(&mut context).is_pending());

		manual.advance(Duration::from_millis(2_999));
		assert!(bounded.as_mut().poll(&mut context).is_pending());

		manual.advance(Duration::from_millis(1));
		assert_eq!(bounded.as_mut().poll(&mut context), Poll::Ready(Err(Lapse::Passed)));
	}

	/// A thread outside any tokio runtime has no timer, so a bound on the
	/// system clock refuses waiting work at once.
	#[cfg(feature = "tokio")]
	#[test]
	fn a_bound_outside_a_runtime_fails_closed() {
		let bounded = poll_once(&SystemClock, Duration::from_secs(60), core::future::pending::<()>());
		assert_eq!(bounded, Poll::Ready(Err(Lapse::NoTimer)));
	}

	/// A sleep of the system clock on a thread outside any tokio runtime parks
	/// for its whole span, as `Clock::sleep` states.
	#[test]
	fn a_system_sleep_outside_a_runtime_waits_out_its_span() {
		let mut context = core::task::Context::from_waker(core::task::Waker::noop());
		let started = std::time::Instant::now();
		let mut sleep = SystemClock.sleep(Duration::from_millis(20));

		let slept = sleep.as_mut().poll(&mut context).is_ready();
		assert!(slept);
		assert!(started.elapsed() >= Duration::from_millis(20));
	}

	/// The system clock races a bound on a thread that runs a tokio runtime,
	/// and has no timer outside one.
	#[cfg(feature = "tokio")]
	#[test]
	fn the_system_clock_times_by_the_runtime_of_its_thread() {
		let outside = SystemClock.timing();
		let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
		let runtime = runtime.expect("a current-thread runtime builds");

		let inside = runtime.block_on(async { SystemClock.timing() });
		assert_eq!((outside, inside), (Timing::Absent, Timing::Races));
	}

	/// Work that is ready wins before the timer makes a sleep.
	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn ready_work_makes_no_sleep() {
		let mut timer = Timer::new(Arc::new(SystemClock));
		let answered = timer.within(Duration::from_secs(1), core::future::ready(7)).await;
		assert_eq!((answered, timer.kept.is_none()), (Ok(7), true));
	}

	/// The address of the sleep that `timer` keeps.
	#[cfg(feature = "tokio")]
	fn kept_sleep(timer: &Timer) -> Option<*const ()> {
		timer
			.kept
			.as_ref()
			.map(|sleep| core::ptr::from_ref(sleep.as_ref().get_ref()).cast::<()>())
	}

	/// A timer keeps the one sleep its clock offers across waits and sleeps, so
	/// a party that waits many times makes its sleep once.
	#[cfg(feature = "tokio")]
	#[tokio::test(start_paused = true)]
	async fn a_timer_keeps_one_sleep_across_waits() {
		let mut timer = Timer::new(Arc::new(SystemClock));
		let first = timer.within(Duration::from_secs(1), core::future::pending::<()>()).await;
		let kept = kept_sleep(&timer);

		let second = timer.within(Duration::from_secs(1), core::future::pending::<()>()).await;
		timer.sleep(Duration::from_secs(1)).await;
		assert_eq!((first, second), (Err(Lapse::Passed), Err(Lapse::Passed)));
		assert!(kept.is_some());
		assert_eq!(kept, kept_sleep(&timer));
	}

	/// A current-thread runtime with its timers.
	#[cfg(feature = "tokio")]
	fn timed_runtime() -> tokio::runtime::Runtime {
		let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build();
		runtime.expect("a current-thread runtime builds")
	}

	/// A bound reads the timing of its clock where it waits, so a bound made
	/// outside a runtime races on the runtime that polls it.
	#[cfg(feature = "tokio")]
	#[test]
	fn a_bound_made_outside_a_runtime_races_on_the_runtime_that_polls_it() {
		let clock: Arc<dyn Clock> = Arc::new(SystemClock);
		let yielded = pin!(tokio::task::yield_now());
		let bounded = clock.within(Duration::from_secs(60), yielded);

		assert_eq!(timed_runtime().block_on(bounded), Ok(()));
	}

	/// A timer polled on a second runtime makes a sleep there, so its wait
	/// ends on the timer of the runtime that polls it after the first one
	/// shuts down.
	#[cfg(feature = "tokio")]
	#[test]
	fn a_timer_makes_a_new_sleep_on_another_runtime() {
		let mut timer = Timer::new(Arc::new(SystemClock));
		let span = Duration::from_millis(1);
		let first = timed_runtime().block_on(timer.within(span, core::future::pending::<()>()));

		let second = timed_runtime().block_on(timer.within(span, core::future::pending::<()>()));
		assert_eq!((first, second), (Err(Lapse::Passed), Err(Lapse::Passed)));
	}

	/// An advance of a manual clock moves its unix and monotonic readings by
	/// the same span.
	#[test]
	fn a_manual_clock_moves_both_readings_together() {
		let clock = ManualClock::default();
		let unix_before = clock.unix();
		let monotonic_before = clock.monotonic();

		clock.advance(Duration::from_secs(2));

		let unix_moved = clock.unix().saturating_since(unix_before);
		let monotonic_moved = clock.monotonic().saturating_duration_since(monotonic_before);
		assert_eq!((unix_moved, monotonic_moved), (Duration::from_secs(2), Duration::from_secs(2)));
	}

	/// A sleep on a manual clock waits for the test and resolves once an
	/// advance covers its span, so a loop that sleeps on it never spins.
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

	/// A deadline past the representable range of the monotonic clock is
	/// absent.
	#[test]
	fn a_deadline_past_the_representable_range_is_absent() {
		let clock = ManualClock::default();
		assert!(clock.monotonic().checked_add(Duration::MAX).is_none());
	}

	// The skew between two instants is the span between them, whichever of
	// the two comes first.
	crate::tb_cases! {
		fn skew_reads_the_same_in_either_direction((from, to): (u64, u64)) {
			let skew = UnixMillis::new(from).abs_diff(UnixMillis::new(to));
			assert_eq!(skew, Duration::from_millis(250));
		}
		cases {
			forward => (1_000, 1_250),
			backward => (1_250, 1_000),
		}
	}
}
