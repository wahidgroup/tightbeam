#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::der::Enumerated;
use crate::{Frame, Message};

/// Transport response status codes
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitStatus {
	#[default]
	Request = 0,
	Accepted = 1,
	Busy = 2,
	Unauthorized = 3,
	Forbidden = 4,
	Timeout = 5,
}

/// Policy trait a user implements to decide message acceptance.
///
/// Gate policies are stateless procedures that evaluate whether a message
/// should be accepted or rejected.
pub trait GatePolicy: Send + Sync {
	fn evaluate(&self, message: &std::sync::Arc<Frame>) -> TransitStatus;
}

/// Policy trait a user implements to decide message acceptance.
pub trait ReceptorPolicy<T: Message>: Send + Sync {
	fn evaluate(&self, message: &T) -> TransitStatus;
}

/// Middleware wrapper for receptor policies that observes evaluations.
///
/// Wraps any `ReceptorPolicy` and calls a closure with the evaluation result.
/// The middleware is transparent - it passes through the gate's decision
/// unchanged.
pub struct ReceptorMiddleware<T: Message, R: ReceptorPolicy<T>, F>
where
	F: Fn(&T, &TransitStatus) + Send + Sync,
{
	inner: R,
	observer: F,
	_phantom: core::marker::PhantomData<T>,
}

impl<T: Message, R: ReceptorPolicy<T>, F> ReceptorMiddleware<T, R, F>
where
	F: Fn(&T, &TransitStatus) + Send + Sync,
{
	/// Create a new middleware wrapper around a receptor policy.
	///
	/// # Arguments
	/// * `inner` - The underlying receptor policy to wrap
	/// * `observer` - Closure called with the message and evaluation result
	pub fn new(inner: R, observer: F) -> Self {
		Self { inner, observer, _phantom: core::marker::PhantomData }
	}
}

impl<T: Message, R: ReceptorPolicy<T>, F> ReceptorPolicy<T> for ReceptorMiddleware<T, R, F>
where
	F: Fn(&T, &TransitStatus) + Send + Sync,
{
	fn evaluate(&self, message: &T) -> TransitStatus {
		let status = self.inner.evaluate(message);

		// Observe the evaluation (transparent)
		(self.observer)(message, &status);

		status
	}
}
/// Default gate that always accepts.
#[derive(Default)]
pub struct AcceptAllGate;

impl GatePolicy for AcceptAllGate {
	fn evaluate(&self, _: &std::sync::Arc<Frame>) -> TransitStatus {
		TransitStatus::Accepted
	}
}

/// Middleware wrapper for gate policies that observes evaluations.
///
/// Wraps any `GatePolicy` and calls a closure with the evaluation result.
/// The middleware is transparent - it passes through the gate's decision
/// unchanged.
#[derive(Debug, Clone)]
pub struct GateMiddleware<G: GatePolicy, F>
where
	F: Fn(&Arc<Frame>, &TransitStatus) + Send + Sync,
{
	inner: G,
	observer: F,
}

impl<G: GatePolicy, F> GateMiddleware<G, F>
where
	F: Fn(&Arc<Frame>, &TransitStatus) + Send + Sync,
{
	/// Create a new middleware wrapper around a gate policy.
	///
	/// # Arguments
	/// * `inner` - The underlying gate policy to wrap
	/// * `observer` - Closure called with the message and evaluation result
	pub fn new(inner: G, observer: F) -> Self {
		Self { inner, observer }
	}
}

impl<G: GatePolicy, F> GatePolicy for GateMiddleware<G, F>
where
	F: Fn(&Arc<Frame>, &TransitStatus) + Send + Sync,
{
	fn evaluate(&self, message: &Arc<Frame>) -> TransitStatus {
		let status = self.inner.evaluate(message);

		// Observe the evaluation (transparent)
		(self.observer)(message, &status);

		status
	}
}
