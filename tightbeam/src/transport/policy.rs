#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(feature = "std")]
use std::time::SystemTime;

use crate::policy::{GatePolicy, ReceptorPolicy};
use crate::transport::TransportResult;
use crate::{Frame, Message};

/// Trait for transports that support policy configuration
pub trait PolicyConfiguration where Self: Sized {
	fn with_restart_policy<P: RestartPolicy + 'static>(self, _: P) -> Self {
		panic!("Restart policy is not supported on this transport");
	}
	fn with_emitter_gate<G: GatePolicy + 'static>(self, _: G) -> Self {
		panic!("Emitter gate is not supported on this transport");
	}
	fn with_collector_gate<G: GatePolicy + 'static>(self, _: G) -> Self {
		panic!("Collector gate is not supported on this transport");
	}
	fn with_receptor_gate<T: Message, R: ReceptorPolicy<T> + 'static>(self, _: R) -> Self {
		panic!("Receptor policy is not supported on this transport");
	}
}

/// Restart policy trait - decides whether to retry and with what message.
///
/// Restart policies are stateless procedures that determine retry behavior
/// after a transport operation.
pub trait RestartPolicy: Send + Sync {
	/// Evaluate whether to restart after a transport operation.
	///
	/// # Arguments
	/// * `message` - The original message that was sent
	/// * `result` - The result of the emit operation (response or error)
	/// * `attempt` - The current attempt number (0-indexed)
	///
	/// # Returns
	/// * `Some(TightBeam)` - Retry with this message (can be modified or same)
	/// * `None` - Stop attempting, propagate the error
	fn evaluate(&self, message: Frame, result: TransportResult<&Frame>, attempt: usize) -> Option<Frame>;
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
	fn evaluate(&self, _: Frame, _: TransportResult<&Frame>, _: usize) -> Option<Frame> {
		None
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
			fn evaluate(&self, message: Frame, result: TransportResult<&Frame>, attempt: usize) -> Option<Frame> {
				if attempt >= self.max_attempts {
					return None;
				}

				if result.is_ok() {
					return None;
				}

				// Retry only on error
				match &self.jitter {
					Some(jitter_strategy) => {
						let delay_ms = $delay_calc(self, attempt);
						let delay_ms = jitter_strategy.apply(delay_ms);

						std::thread::sleep(std::time::Duration::from_millis(delay_ms));
						Some(message)
					}
					None => {
						std::thread::sleep(std::time::Duration::from_millis($delay_calc(self, attempt)));
						Some(message)
					}
				}
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
