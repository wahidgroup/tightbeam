use crate::der::Enumerated;
use crate::{Frame, Message};

/// Transport response status codes.
///
/// The gRPC canonical status registry (`google.rpc.Code`) adopted:
///
/// - `Ok`: the request was processed
/// - `Cancelled`: the caller cancelled the operation
/// - `Unknown`: unclassified server failure.
/// - `InvalidArgument`: the request is malformed regardless of system state.
/// - `DeadlineExceeded`: the peer gave up waiting
/// - `NotFound`: the requested entity does not exist.
/// - `PermissionDenied`: the caller is identified but refused authorization.
/// - `ResourceExhausted`: capacity refusal, retry with backoff may succeed.
/// - `FailedPrecondition`: system state must change before a retry can succeed.
/// - `Unimplemented`: no handler answers the requested operation.
/// - `Unavailable`: transient unavailability, retry with backoff.
/// - `Unauthenticated`: the caller lacks valid authentication credentials.
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitStatus {
	Ok = 0,
	Cancelled = 1,
	#[default]
	Unknown = 2,
	InvalidArgument = 3,
	DeadlineExceeded = 4,
	NotFound = 5,
	AlreadyExists = 6,
	PermissionDenied = 7,
	ResourceExhausted = 8,
	FailedPrecondition = 9,
	Aborted = 10,
	OutOfRange = 11,
	Unimplemented = 12,
	Internal = 13,
	Unavailable = 14,
	DataLoss = 15,
	Unauthenticated = 16,
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
		TransitStatus::Ok
	}
}

/// Gate that requires every frame to carry a valid frame integrity (FI) digest.
///
/// A frame is [`TransitStatus::Ok`] only when it carries an FI value that
/// recomputes to the same digest under `D`. Every other case is rejected with
/// [`TransitStatus::PermissionDenied`].
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
			Ok(true) => TransitStatus::Ok,
			_ => TransitStatus::PermissionDenied,
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
		assert!(matches!(gate.evaluate(&create_frame_with_frame_integrity()), TransitStatus::Ok));
	}

	#[test]
	fn rejects_tampered_frame() {
		let mut frame = create_frame_with_frame_integrity();
		frame.metadata.id = b"tampered".to_vec();
		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(gate.evaluate(&frame), TransitStatus::PermissionDenied));
	}

	#[test]
	fn rejects_frame_without_integrity() {
		let message = create_test_message(None);
		let frame = compose! { V0: id: "gate-no-fi", order: 1u64, message: message }.unwrap();
		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(gate.evaluate(&frame), TransitStatus::PermissionDenied));
	}
}
