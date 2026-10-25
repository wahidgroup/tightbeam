//! The house restart policies and the jitter strategy they apply: a policy
//! that fails on the first error, exponential and linear backoff, and
//! decorrelated jitter.

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use core::time::Duration;

use crate::transport::error::TransportFailure;
use crate::transport::policy::{CoreRetryPolicy, RestartPolicy, RetryAction};
use crate::Frame;

#[cfg(feature = "std")]
use crate::random::generate_nonce;
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
		// The draw comes from the random source, because jitter exists to
		// spread peers apart and a clock reading would move every peer
		// together. A source that fails seeds the draw with the base delay.
		let seed = generate_nonce::<8>(None).map_or(base_delay, u64::from_le_bytes);

		let (min, range) = decorrelated_bounds(base_delay);
		let Some(offset) = seed.checked_rem(range) else {
			return base_delay;
		};

		min.saturating_add(offset)
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
/// attempt: `scale_factor * 2^attempt` milliseconds before the jitter.
#[cfg(feature = "std")]
pub struct RestartExponentialBackoff {
	/// The number of attempts after which the policy answers
	/// [`RetryAction::NoRetry`].
	pub max_attempts: usize,
	/// The base delay in milliseconds, which doubles per attempt.
	pub scale_factor: u64,
	/// The randomization that the policy applies to each computed delay.
	/// `None` retries on the exact schedule.
	pub jitter: Option<Box<dyn JitterStrategy>>,
}

#[cfg(feature = "std")]
impl RestartExponentialBackoff {
	pub fn new(max_attempts: usize, scale_factor: u64, jitter: Option<Box<dyn JitterStrategy>>) -> Self {
		Self { max_attempts, scale_factor, jitter }
	}
}

#[cfg(feature = "std")]
impl Default for RestartExponentialBackoff {
	fn default() -> Self {
		Self { max_attempts: 5, scale_factor: 1000, jitter: Some(Box::new(DecorrelatedJitter)) }
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
		let base_delay = self.scale_factor.saturating_mul(2_u64.saturating_pow(exp));

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

	/// Returns the distinct delays that a run of `draws` jitter draws yields
	/// over `base`.
	fn drawn_delays(base: u64, draws: usize) -> BTreeSet<u64> {
		let jitter = DecorrelatedJitter;
		(0..draws).map(|_| jitter.apply(base)).collect()
	}

	/// Jitter exists to spread peers apart, so a run of draws over one base
	/// yields more than one delay, and each sits inside the decorrelated
	/// window. A draw that ignored the random source would yield one value.
	#[test]
	fn jitter_spreads_its_draws_inside_the_window() {
		let base = 3_000_000;
		let (min, range) = decorrelated_bounds(base);

		let delays = drawn_delays(base, 32);
		let (lowest, highest) = (delays.first().copied(), delays.last().copied());
		assert!(delays.len() > 1);
		assert!(lowest >= Some(min));
		assert!(highest < Some(min + range));
	}
}
