#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

use crate::policy::GatePolicy;
use crate::transport::error::TransportFailure;
use crate::Frame;

mod backoff;

pub use backoff::NoRestart;

#[cfg(feature = "testing-timing")]
pub(crate) use backoff::decorrelated_bounds;
#[cfg(feature = "std")]
pub use backoff::{DecorrelatedJitter, RestartExponentialBackoff, RestartLinearBackoff};

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
	///
	/// The blocking transport arms it on its stream, and the async transport
	/// arms it under `tokio`. An async build without `tokio` has no timer, so
	/// the application owns the deadline there.
	fn with_timeout(self, timeout: core::time::Duration) -> Self;
}

/// A transport that honours every policy kind.
///
/// This names the whole set for callers that need all of it. Each capability
/// is its own trait, so a transport advertises exactly what it honours.
pub trait PolicyConfig: RestartConfig + EmitterGateConfig + CollectorGateConfig + TimeoutConfig {}

impl<T> PolicyConfig for T where T: RestartConfig + EmitterGateConfig + CollectorGateConfig + TimeoutConfig {}

/// The core retry policy: the attempt limit and the delay of each attempt.
///
/// It is apart from any transport, so a caller that retries its own
/// operation, such as a hive's scaling updates, reads the attempt limit and
/// each delay from it.
///
/// # Examples
///
/// ```
/// use tightbeam::transport::policy::CoreRetryPolicy;
///
/// /// Three retries, each 100 ms later than the one before.
/// struct ThreeSteps;
///
/// impl CoreRetryPolicy for ThreeSteps {
///     fn max_attempts(&self) -> usize {
///         3
///     }
///
///     fn delay_ms(&self, attempt: usize) -> u64 {
///         100 * (attempt as u64 + 1)
///     }
/// }
///
/// assert_eq!(ThreeSteps.delay_ms(1), 200);
/// ```
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
/// The policy is stateless, and the transport waits the delay of the
/// [`RetryAction`] that [`Self::evaluate`] answers.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam::testing::TestFrame;
/// use tightbeam::transport::policy::{RestartPolicy, RetryAction};
/// use tightbeam::transport::TransportFailure;
/// use tightbeam::Frame;
///
/// /// Sends a frame the peer refuses as unavailable once more, 10 ms later.
/// struct RetryOnce;
///
/// impl RestartPolicy for RetryOnce {
///     fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction {
///         let delay = Duration::from_millis(10);
///         match (failure, attempt) {
///             (TransportFailure::Unavailable, 0) => RetryAction::Retry { frame, delay },
///             _ => RetryAction::NoRetry,
///         }
///     }
/// }
///
/// let frame = Box::new(TestFrame::v0(Some("refused"), None));
/// let action = RetryOnce.evaluate(frame, &TransportFailure::Unavailable, 1);
/// assert_eq!(action, RetryAction::NoRetry);
/// ```
pub trait RestartPolicy: Send + Sync {
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
	/// Stop the retries and propagate the error.
	NoRetry,
}

/// A jitter strategy, which adds randomness to a delay.
pub trait JitterStrategy: Send + Sync {
	fn apply(&self, base_delay: u64) -> u64;
}
