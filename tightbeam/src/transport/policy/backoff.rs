//! The house restart policies and the jitter strategy they apply: a policy
//! that fails on the first error, exponential and linear backoff, and
//! decorrelated jitter.

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "std")]
use core::time::Duration;
#[cfg(feature = "std")]
use std::hash::{DefaultHasher, Hash, Hasher};

use crate::transport::error::TransportFailure;
use crate::transport::policy::{CoreRetryPolicy, RestartPolicy, RetryAction};
use crate::Frame;

#[cfg(feature = "std")]
use crate::random::{generate_nonce, placement_entropy};
#[cfg(feature = "std")]
use crate::transport::policy::JitterStrategy;

/// Computes the bounds of the decorrelated-jitter window for a base value.
///
/// Returns `(min, range)` with `min = base / 3`, and the window spans
/// `min..min + range`. The restart backoff strategy ([`DecorrelatedJitter`])
/// and the timing framework's `DecorrelatedJitterCalculator` share it, so the
/// algorithm has one definition.
#[cfg(feature = "std")]
pub(crate) const fn decorrelated_bounds(base: u64) -> (u64, u64) {
	let min = base / 3;
	(min, base.saturating_sub(min))
}

/// The decorrelated jitter strategy, which draws a random value between
/// `base_delay / 3` and `base_delay`, so peers that fail together retry apart
/// and avoid the thundering herd problem.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct DecorrelatedJitter;

#[cfg(feature = "std")]
impl JitterStrategy for DecorrelatedJitter {
	fn apply(&self, base_delay: u64) -> u64 {
		// The draw comes from the random source, because jitter spreads peers
		// apart and a clock reading would move every peer together. A refused
		// draw drops its error, because `draw` then seeds from `refused_seed`.
		let drawn = generate_nonce::<8>(None).ok();
		Self::draw(base_delay, drawn)
	}
}

/// The count of the draws that the random source refused in this process.
#[cfg(feature = "std")]
static REFUSED_DRAWS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "std")]
impl DecorrelatedJitter {
	/// The delay inside the window of `base_delay` that `drawn`, eight octets
	/// of the random source, picks. A draw that the source refused, `None`,
	/// picks with the seed of [`Self::refused_seed`].
	fn draw(base_delay: u64, drawn: Option<[u8; 8]>) -> u64 {
		let seed = drawn.map_or_else(Self::refused_seed, u64::from_le_bytes);

		let (min, range) = decorrelated_bounds(base_delay);
		let Some(offset) = seed.checked_rem(range) else {
			return base_delay;
		};

		min.saturating_add(offset)
	}

	/// The seed of a draw that the random source refused: the hash of the
	/// [`placement_entropy`] of this process and of the count of
	/// [`REFUSED_DRAWS`].
	///
	/// The placement differs between processes, so peers that lose the source
	/// together seed apart, and the count moves each later seed of one process.
	fn refused_seed() -> u64 {
		let refused = REFUSED_DRAWS.fetch_add(1, Ordering::Relaxed);
		let mut hasher = DefaultHasher::new();
		(placement_entropy(), refused).hash(&mut hasher);

		hasher.finish()
	}
}

/// A restart policy that fails immediately on any error.
#[derive(Default)]
pub struct NoRestart;

impl RestartPolicy for NoRestart {
	fn evaluate(&self, _frame: Box<Frame>, _failure: &TransportFailure, _attempt: usize) -> RetryAction {
		RetryAction::NoRetry
	}
}

/// An exponential backoff restart policy.
///
/// The policy retries after each failure, and the delay doubles with each
/// attempt: `base_delay * 2^attempt` before the jitter.
#[cfg(feature = "std")]
pub struct RestartExponentialBackoff {
	/// The number of attempts after which the policy answers
	/// [`RetryAction::NoRetry`].
	pub max_attempts: usize,
	/// The delay before the first retry, which doubles per attempt.
	///
	/// The field is a [`Duration`], as the interval of
	/// [`RestartLinearBackoff`] is, so a call site cannot swap it with
	/// `max_attempts`. The policy reads it in whole milliseconds, and a delay
	/// past `u64::MAX` milliseconds saturates.
	pub base_delay: Duration,
	/// The randomization that the policy applies to each computed delay.
	/// `None` retries on the exact schedule.
	pub jitter: Option<Box<dyn JitterStrategy>>,
}

#[cfg(feature = "std")]
impl RestartExponentialBackoff {
	/// A policy that retries up to `max_attempts` times, after `base_delay`
	/// doubled per attempt and then jittered by `jitter`.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::transport::policy::{CoreRetryPolicy, RestartExponentialBackoff};
	///
	/// let policy = RestartExponentialBackoff::new(4, Duration::from_millis(250), None);
	/// assert_eq!((policy.delay_ms(0), policy.delay_ms(2)), (250, 1_000));
	/// ```
	pub fn new(max_attempts: usize, base_delay: Duration, jitter: Option<Box<dyn JitterStrategy>>) -> Self {
		Self { max_attempts, base_delay, jitter }
	}
}

#[cfg(feature = "std")]
impl Default for RestartExponentialBackoff {
	fn default() -> Self {
		Self {
			max_attempts: 5,
			base_delay: Duration::from_secs(1),
			jitter: Some(Box::new(DecorrelatedJitter)),
		}
	}
}

/// A linear backoff restart policy.
///
/// The policy retries after each failure, and the delay grows linearly:
/// `scale_factor * interval * (attempt + 1)` before the jitter.
#[cfg(feature = "std")]
pub struct RestartLinearBackoff {
	/// The number of attempts after which the policy answers
	/// [`RetryAction::NoRetry`].
	pub max_attempts: usize,
	/// The delay increment per attempt.
	///
	/// The field is a [`Duration`] rather than a bare count, so a call site
	/// that passes both cannot swap it with `scale_factor`.
	pub interval: Duration,
	/// The multiplier that the policy applies to the linear delay.
	pub scale_factor: u64,
	/// The randomization that the policy applies to each computed delay.
	/// `None` retries on the exact schedule.
	pub jitter: Option<Box<dyn JitterStrategy>>,
}

#[cfg(feature = "std")]
impl RestartLinearBackoff {
	/// A policy that retries up to `max_attempts` times, after
	/// `scale_factor * interval * (attempt + 1)` jittered by `jitter`.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::transport::policy::{CoreRetryPolicy, RestartLinearBackoff};
	///
	/// let policy = RestartLinearBackoff::new(3, Duration::from_millis(100), 2, None);
	/// assert_eq!((policy.delay_ms(0), policy.delay_ms(1)), (200, 400));
	/// ```
	pub fn new(
		max_attempts: usize,
		interval: Duration,
		scale_factor: u64,
		jitter: Option<Box<dyn JitterStrategy>>,
	) -> Self {
		Self { max_attempts, interval, scale_factor, jitter }
	}
}

#[cfg(feature = "std")]
impl Default for RestartLinearBackoff {
	fn default() -> Self {
		Self {
			max_attempts: 5,
			interval: Duration::from_secs(1),
			scale_factor: 1,
			jitter: Some(Box::new(DecorrelatedJitter)),
		}
	}
}

/// The restart policy of a house backoff. It stops at `max_attempts`, and it
/// waits the delay of [`CoreRetryPolicy::delay_ms`] before each retry, so a
/// transport and a hive under one policy wait one delay.
#[cfg(feature = "std")]
macro_rules! impl_timed_backoff_policy {
	($policy:ident) => {
		impl RestartPolicy for $policy {
			fn evaluate(&self, frame: Box<Frame>, _failure: &TransportFailure, attempt: usize) -> RetryAction {
				if attempt >= self.max_attempts {
					return RetryAction::NoRetry;
				}

				let delay = Duration::from_millis(self.delay_ms(attempt));
				RetryAction::Retry { frame, delay }
			}
		}
	};
}

#[cfg(feature = "std")]
impl_timed_backoff_policy!(RestartExponentialBackoff);

#[cfg(feature = "std")]
impl_timed_backoff_policy!(RestartLinearBackoff);

#[cfg(feature = "std")]
impl CoreRetryPolicy for RestartExponentialBackoff {
	fn max_attempts(&self) -> usize {
		self.max_attempts
	}

	fn delay_ms(&self, attempt: usize) -> u64 {
		// The exponent caps at 63 to prevent overflow, because 2^63 is the
		// largest power of 2 in a `u64`.
		let exp = (attempt as u32).min(63);
		let base_ms = u64::try_from(self.base_delay.as_millis()).unwrap_or(u64::MAX);
		let base_delay = base_ms.saturating_mul(2_u64.saturating_pow(exp));

		match &self.jitter {
			Some(jitter_strategy) => jitter_strategy.apply(base_delay),
			None => base_delay,
		}
	}
}

#[cfg(feature = "std")]
impl CoreRetryPolicy for RestartLinearBackoff {
	fn max_attempts(&self) -> usize {
		self.max_attempts
	}

	fn delay_ms(&self, attempt: usize) -> u64 {
		let base_delay = self
			.scale_factor
			.saturating_mul(self.interval.as_millis() as u64)
			.saturating_mul((attempt as u64).saturating_add(1));

		match &self.jitter {
			Some(jitter_strategy) => jitter_strategy.apply(base_delay),
			None => base_delay,
		}
	}
}

impl CoreRetryPolicy for NoRestart {
	fn max_attempts(&self) -> usize {
		0
	}

	fn delay_ms(&self, _attempt: usize) -> u64 {
		0
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use std::collections::BTreeSet;

	use super::*;

	/// Returns the distinct delays that a run of `draws` draws of `jitter`
	/// yields over `base`.
	fn drawn_delays(jitter: fn(u64) -> u64, base: u64, draws: usize) -> BTreeSet<u64> {
		(0..draws).map(|_| jitter(base)).collect()
	}

	// A run of draws over one base yields more than one delay, each inside the
	// decorrelated window, whether the random source serves each draw or
	// refuses it. A draw that ignored its seed would yield one value.
	crate::tb_cases! {
		fn jitter_spreads_its_draws_inside_the_window(jitter: fn(u64) -> u64) {
			let base = 3_000_000;
			let (min, range) = decorrelated_bounds(base);

			let delays = drawn_delays(jitter, base, 32);
			let (lowest, highest) = (delays.first().copied(), delays.last().copied());
			assert!(delays.len() > 1);
			assert!(lowest >= Some(min));
			assert!(highest < Some(min + range));
		}

		cases {
			from_the_random_source => |base| DecorrelatedJitter.apply(base),
			with_the_source_refused => |base| DecorrelatedJitter::draw(base, None),
		}
	}

	/// The default exponential policy waits one second before its first retry.
	#[test]
	fn the_default_exponential_policy_waits_one_second_first() {
		let policy = RestartExponentialBackoff { jitter: None, ..RestartExponentialBackoff::default() };
		assert_eq!(policy.delay_ms(0), 1_000);
	}

	/// A policy that a struct literal names reads its base delay in whole
	/// milliseconds, and doubles it per attempt.
	#[test]
	fn a_literal_base_delay_doubles_in_milliseconds() {
		let base_delay = Duration::from_millis(500);
		let policy = RestartExponentialBackoff { max_attempts: 3, base_delay, jitter: None };
		assert_eq!(policy.delay_ms(1), 1_000);
	}

	// The exponential policy reads the base delay its constructor takes as a
	// `Duration` in whole milliseconds, and saturates a base past `u64::MAX`
	// milliseconds.
	crate::tb_cases! {
		fn an_exponential_base_delay_keeps_its_milliseconds((base_delay, expected): (Duration, u64)) {
			let policy = RestartExponentialBackoff::new(4, base_delay, None);
			assert_eq!(policy.delay_ms(0), expected);
		}
		cases {
			a_quarter_second => (Duration::from_millis(250), 250),
			under_one_millisecond => (Duration::from_micros(999), 0),
			past_the_largest_count => (Duration::MAX, u64::MAX),
		}
	}
}
