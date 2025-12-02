#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use std::time::SystemTime;

use crate::policy::{GatePolicy, ReceptorPolicy};
use crate::transport::error::TransportFailure;
use crate::{Frame, Message};

/// Trait for transports that support policy configuration
pub trait PolicyConf
where
	Self: Sized,
{
	fn with_restart<P: RestartPolicy + 'static>(self, _: P) -> Self {
		unimplemented!("Restart policy is not supported on this transport");
	}

	fn with_emitter_gate<G: GatePolicy + 'static>(self, _: G) -> Self {
		unimplemented!("Emitter gate is not supported on this transport");
	}

	fn with_collector_gate<G: GatePolicy + 'static>(self, _: G) -> Self {
		unimplemented!("Collector gate is not supported on this transport");
	}

	fn with_receptor_gate<T: Message, R: ReceptorPolicy<T> + 'static>(self, _: R) -> Self {
		unimplemented!("Receptor policy is not supported on this transport");
	}

	#[cfg(feature = "std")]
	fn with_timeout(self, _: std::time::Duration) -> Self {
		unimplemented!("Timeout is not supported on this transport");
	}
}

/// Core retry policy - provides basic retry configuration.
///
/// This is the foundation trait for all retry behavior, providing
/// max attempts and delay calculation without transport-specific details.
pub trait CoreRetryPolicy: Send + Sync {
	/// Maximum number of retry attempts (0 means no retries, just initial attempt).
	fn max_attempts(&self) -> usize;

	/// Delay in milliseconds before the given attempt (0-indexed).
	fn delay_ms(&self, attempt: usize) -> u64;
}

/// Restart policy trait - decides whether to retry transport operations.
///
/// Restart policies are stateless procedures that determine retry behavior
/// after a transport operation. Requires `CoreRetryPolicy` for basic config.
pub trait RestartPolicy: CoreRetryPolicy {
	/// Evaluate whether to restart after a transport operation.
	///
	/// # Arguments
	/// * `frame` - Boxed frame from the failed operation
	/// * `failure` - The failure reason
	/// * `attempt` - The current attempt number (0-indexed)
	///
	/// # Returns
	/// * `RetryAction` - What action to take (retry with frame, or no retry)
	fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction;
}

/// Action to take when evaluating retry policy
#[derive(Debug, Clone, PartialEq)]
pub enum RetryAction {
	/// Retry with the provided frame (same or modified from input)
	Retry(Box<Frame>),
	/// Do not retry, propagate the error
	NoRetry,
}

/// Jitter strategy trait - modifies delay durations to add randomness.
pub trait JitterStrategy: Send + Sync {
	fn apply(&self, base_delay: u64) -> u64;
}

/// Decorrelated jitter - random value between base/3 and base_delay.
/// Helps prevent thundering herd problem.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct DecorrelatedJitter;

#[cfg(feature = "std")]
impl JitterStrategy for DecorrelatedJitter {
	fn apply(&self, base_delay: u64) -> u64 {
		let seed = SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_nanos() as u64)
			// Use base_delay as fallback to ensure non-zero range
			.unwrap_or(base_delay);

		let min = base_delay / 3;
		let range = base_delay.saturating_sub(min);
		if range == 0 {
			return base_delay;
		}

		min + (seed % range)
	}
}

/// Never restart - fail immediately on any error.
#[derive(Default)]
pub struct NoRestart;

impl RestartPolicy for NoRestart {
	fn evaluate(&self, _frame: Box<Frame>, _failure: &TransportFailure, _attempt: usize) -> RetryAction {
		RetryAction::NoRetry
	}
}

/// Exponential backoff restart policy.
///
/// Retries on errors with exponentially increasing delays.
/// The delay doubles with each attempt: scale_factor * 2^attempt milliseconds.
#[cfg(feature = "std")]
pub struct RestartExponentialBackoff {
	pub max_attempts: usize,
	pub scale_factor: u64,
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

#[cfg(not(feature = "std"))]
impl Default for RestartExponentialBackoff {
	fn default() -> Self {
		Self { max_attempts: 5, scale_factor: 1000, jitter: Box::new(NoJitter) }
	}
}

/// Linear backoff restart policy.
///
/// Retries on errors with linearly increasing delays.
/// The delay increases by: scale_factor * interval_ms * (attempt + 1)
/// milliseconds.
#[cfg(feature = "std")]
pub struct RestartLinearBackoff {
	pub max_attempts: usize,
	pub interval_ms: u64,
	pub scale_factor: u64,
	pub jitter: Option<Box<dyn JitterStrategy>>,
}

impl RestartLinearBackoff {
	pub fn new(
		max_attempts: usize,
		interval_ms: u64,
		scale_factor: u64,
		jitter: Option<Box<dyn JitterStrategy>>,
	) -> Self {
		Self { max_attempts, interval_ms, scale_factor, jitter }
	}
}

#[cfg(feature = "std")]
impl Default for RestartLinearBackoff {
	fn default() -> Self {
		Self {
			max_attempts: 5,
			interval_ms: 1000,
			scale_factor: 1,
			jitter: Some(Box::new(DecorrelatedJitter)),
		}
	}
}

#[cfg(not(feature = "std"))]
impl Default for RestartLinearBackoff {
	fn default() -> Self {
		Self { max_attempts: 5, interval_ms: 1000, scale_factor: 1, jitter: None }
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

				// Calculate delay and sleep
				match &self.jitter {
					Some(jitter_strategy) => {
						let delay_ms = $delay_calc(self, attempt);
						let delay_ms = jitter_strategy.apply(delay_ms);
						std::thread::sleep(Duration::from_millis(delay_ms));
					}
					None => {
						std::thread::sleep(Duration::from_millis($delay_calc(self, attempt)));
					}
				}

				// Return the same box for retry
				RetryAction::Retry(frame)
			}
		}
	};
}

#[cfg(feature = "std")]
impl_timed_backoff_policy!(
	RestartExponentialBackoff,
	|policy: &RestartExponentialBackoff, attempt: usize| {
		// Prevent overflow by capping the exponent The exponent is capped
		// at 63 to prevent overflow (2^63 is the max power of 2 in u64).
		let exp = (attempt as u32).min(63);
		policy.scale_factor.saturating_mul(2_u64.saturating_pow(exp))
	}
);

#[cfg(feature = "std")]
impl_timed_backoff_policy!(RestartLinearBackoff, |policy: &RestartLinearBackoff, attempt: usize| {
	policy
		.scale_factor
		.saturating_mul(policy.interval_ms)
		.saturating_mul(attempt as u64 + 1)
});

// CoreRetryPolicy implementations (required by RestartPolicy supertrait)

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
			.saturating_mul(self.interval_ms)
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
