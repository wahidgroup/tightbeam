#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use core::time::Duration;

use crate::policy::GatePolicy;
use crate::transport::error::TransportFailure;
use crate::Frame;

#[cfg(feature = "std")]
use crate::random::generate_nonce;
#[cfg(feature = "std")]
use crate::utils::jitter::decorrelated_bounds;

/// A transport that honours a restart policy.
pub trait RestartConfig
where
	Self: Sized,
{
	/// Configure the restart policy for this transport.
	fn with_restart<P: RestartPolicy + 'static>(self, policy: P) -> Self;
}

/// A transport that honours emitter gates.
pub trait EmitterGateConfig
where
	Self: Sized,
{
	/// Add an emitter gate.
	///
	/// Repeated calls accumulate into a [`crate::policy::GateChain`]: gates
	/// evaluate in configuration order and the first non-`Ok` verdict decides.
	fn with_emitter_gate<G: GatePolicy + 'static>(self, gate: G) -> Self;
}

/// A transport that honours collector gates.
pub trait CollectorGateConfig
where
	Self: Sized,
{
	/// Add a collector gate.
	///
	/// Repeated calls accumulate into a [`crate::policy::GateChain`]: gates
	/// evaluate in configuration order and the first non-`Ok` verdict decides.
	fn with_collector_gate<G: GatePolicy + 'static>(self, gate: G) -> Self;
}

/// A transport that honours an operation deadline.
pub trait TimeoutConfig
where
	Self: Sized,
{
	/// Set the deadline for a single read or write.
	fn with_timeout(self, timeout: core::time::Duration) -> Self;
}

/// A transport that honours every policy kind.
///
/// This names the whole set for callers that need all of it. Each capability
/// is its own trait, so a transport advertises exactly what it honours.
pub trait PolicyConfig: RestartConfig + EmitterGateConfig + CollectorGateConfig + TimeoutConfig {}

impl<T> PolicyConfig for T where T: RestartConfig + EmitterGateConfig + CollectorGateConfig + TimeoutConfig {}

/// The core retry policy, which provides the attempt limit and the delay
/// calculation.
///
/// It is the foundation trait for all retry behavior and stays independent of
/// any transport.
pub trait CoreRetryPolicy: Send + Sync {
	/// Returns the maximum number of retry attempts. Zero means that only the
	/// initial attempt runs.
	fn max_attempts(&self) -> usize;

	/// Returns the delay in milliseconds before the given attempt, which counts
	/// from zero.
	fn delay_ms(&self, attempt: usize) -> u64;
}

/// A restart policy, which decides whether to retry a transport operation.
///
/// A restart policy is a stateless procedure that determines the retry behavior
/// after a transport operation. It builds on [`CoreRetryPolicy`] for the
/// attempt limit and the delays.
pub trait RestartPolicy: CoreRetryPolicy {
	/// Decide whether to restart after a failed transport operation.
	///
	/// `frame` is the frame the operation failed on, and `attempt` counts from
	/// zero. The answer either retries with a frame or stops.
	fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction;
}

/// The action that a restart policy answers with.
#[derive(Debug, Clone, PartialEq)]
pub enum RetryAction {
	/// Resend `frame` once `delay` has elapsed.
	///
	/// The policy decides how long to wait. The caller performs the wait,
	/// so an async caller yields its worker for the duration.
	Retry { frame: Box<Frame>, delay: core::time::Duration },
	/// Stop retrying and propagate the error.
	NoRetry,
}

/// A jitter strategy, which adds randomness to a delay.
pub trait JitterStrategy: Send + Sync {
	fn apply(&self, base_delay: u64) -> u64;
}

/// Decorrelated jitter, which draws a random value between `base_delay / 3` and
/// `base_delay`. It helps prevent the thundering herd problem.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct DecorrelatedJitter;

#[cfg(feature = "std")]
impl JitterStrategy for DecorrelatedJitter {
	fn apply(&self, base_delay: u64) -> u64 {
		// The draw comes from the random source, because jitter exists to
		// spread peers apart and a clock reading would move every peer
		// together. A source that fails leaves the draw at the base delay.
		let seed = generate_nonce::<8>(None).map_or(base_delay, u64::from_le_bytes);

		let (min, range) = decorrelated_bounds(base_delay);
		if range == 0 {
			return base_delay;
		}

		min + (seed % range)
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
/// The policy retries on errors with exponentially increasing delays. The delay
/// doubles with each attempt and is `scale_factor * 2^attempt` milliseconds.
#[cfg(feature = "std")]
pub struct RestartExponentialBackoff {
	/// Attempts after which the policy answers [`RetryAction::NoRetry`].
	pub max_attempts: usize,
	/// Base delay in milliseconds, doubled per attempt.
	pub scale_factor: u64,
	/// Randomization applied to each computed delay. `None` retries on the
	/// exact schedule.
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
/// The policy retries on errors with linearly increasing delays. The delay is
/// `scale_factor * interval * (attempt + 1)`.
#[cfg(feature = "std")]
pub struct RestartLinearBackoff {
	/// Attempts after which the policy answers [`RetryAction::NoRetry`].
	pub max_attempts: usize,
	/// Delay increment per attempt.
	///
	/// The field is a [`Duration`] rather than a bare count, so it cannot be
	/// exchanged with `scale_factor` at a call site that passes both.
	pub interval: Duration,
	/// Multiplier applied to the linear delay.
	pub scale_factor: u64,
	/// Randomization applied to each computed delay. `None` retries on the
	/// exact schedule.
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

#[cfg(feature = "std")]
macro_rules! impl_timed_backoff_policy {
	($policy:ident, $delay_calc:expr) => {
		impl RestartPolicy for $policy {
			fn evaluate(&self, frame: Box<Frame>, _failure: &TransportFailure, attempt: usize) -> RetryAction {
				use core::time::Duration;

				if attempt >= self.max_attempts {
					return RetryAction::NoRetry;
				}

				let base_ms = $delay_calc(self, attempt);
				let delay_ms = match &self.jitter {
					Some(jitter_strategy) => jitter_strategy.apply(base_ms),
					None => base_ms,
				};

				RetryAction::Retry { frame, delay: Duration::from_millis(delay_ms) }
			}
		}
	};
}

#[cfg(feature = "std")]
impl_timed_backoff_policy!(
	RestartExponentialBackoff,
	|policy: &RestartExponentialBackoff, attempt: usize| {
		// The exponent is capped at 63 to prevent overflow, because 2^63 is the
		// largest power of 2 in a `u64`.
		let exp = (attempt as u32).min(63);
		policy.scale_factor.saturating_mul(2_u64.saturating_pow(exp))
	}
);

#[cfg(feature = "std")]
impl_timed_backoff_policy!(RestartLinearBackoff, |policy: &RestartLinearBackoff, attempt: usize| {
	policy
		.scale_factor
		.saturating_mul(policy.interval.as_millis() as u64)
		.saturating_mul(attempt as u64 + 1)
});

#[cfg(feature = "std")]
impl CoreRetryPolicy for RestartExponentialBackoff {
	fn max_attempts(&self) -> usize {
		self.max_attempts
	}

	fn delay_ms(&self, attempt: usize) -> u64 {
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
			.saturating_mul(attempt as u64 + 1);

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
