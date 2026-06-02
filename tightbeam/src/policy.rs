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
	fn evaluate(&self, message: &Frame) -> TransitStatus;
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
	fn evaluate(&self, _: &Frame) -> TransitStatus {
		TransitStatus::Accepted
	}
}

/// Gate that requires every frame to carry a valid frame integrity (FI) digest.
///
/// A frame is [`TransitStatus::Accepted`] only when it carries an FI value that
/// recomputes to the same digest under `D`. Every other case is rejected with
/// [`TransitStatus::Forbidden`].
#[cfg(feature = "digest")]
pub struct FrameIntegrityGate<D> {
	_marker: core::marker::PhantomData<fn() -> D>,
}

#[cfg(feature = "digest")]
impl<D> Default for FrameIntegrityGate<D> {
	fn default() -> Self {
		Self { _marker: core::marker::PhantomData }
	}
}

#[cfg(feature = "digest")]
impl<D> GatePolicy for FrameIntegrityGate<D>
where
	D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
{
	fn evaluate(&self, message: &Frame) -> TransitStatus {
		match message.verify_frame_integrity::<D>() {
			Ok(true) => TransitStatus::Accepted,
			_ => TransitStatus::Forbidden,
		}
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
	F: Fn(&Frame, &TransitStatus) + Send + Sync,
{
	inner: G,
	observer: F,
}

impl<G: GatePolicy, F> GateMiddleware<G, F>
where
	F: Fn(&Frame, &TransitStatus) + Send + Sync,
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
	F: Fn(&Frame, &TransitStatus) + Send + Sync,
{
	fn evaluate(&self, message: &Frame) -> TransitStatus {
		let status = self.inner.evaluate(message);

		// Observe the evaluation (transparent)
		(self.observer)(message, &status);

		status
	}
}

#[cfg(all(test, feature = "digest", feature = "builder", feature = "sha3"))]
mod tests {
	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::testing::{create_frame_with_frame_integrity, create_test_message};

	#[test]
	fn accepts_intact_frame() {
		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(
			gate.evaluate(&create_frame_with_frame_integrity()),
			TransitStatus::Accepted
		));
	}

	#[test]
	fn rejects_tampered_frame() {
		let mut frame = create_frame_with_frame_integrity();
		frame.metadata.id = b"tampered".to_vec();
		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(gate.evaluate(&frame), TransitStatus::Forbidden));
	}

	#[test]
	fn rejects_frame_without_integrity() {
		let message = create_test_message(None);
		let frame = compose! { V0: id: "gate-no-fi", order: 1u64, message: message }.unwrap();
		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(gate.evaluate(&frame), TransitStatus::Forbidden));
	}
}
