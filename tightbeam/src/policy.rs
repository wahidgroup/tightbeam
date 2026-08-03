use core::marker::PhantomData;

#[cfg(all(feature = "transport", not(feature = "std")))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
#[cfg(all(feature = "transport", feature = "std"))]
use std::sync::Arc;

use crate::der::Enumerated;
use crate::{Frame, Message};

#[cfg(feature = "transport")]
use crate::der::Encode;
#[cfg(feature = "transport")]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(feature = "transport")]
use crate::transport::state::EncryptedProtocolState;
#[cfg(feature = "transport")]
use crate::x509::Certificate;

/// Transport response status codes.
///
/// The gRPC canonical status registry (`google.rpc.Code`), adopted
/// verbatim so wire values match the registry.
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitStatus {
	/// The request was processed.
	Ok = 0,
	/// The caller cancelled the operation.
	Cancelled = 1,
	/// Unclassified failure. Never a valid gate verdict: evaluation
	/// normalizes it to [`TransitStatus::Internal`].
	#[default]
	Unknown = 2,
	/// The request is malformed regardless of system state.
	InvalidArgument = 3,
	/// The peer gave up waiting.
	DeadlineExceeded = 4,
	/// The requested entity does not exist.
	NotFound = 5,
	/// The entity the request would create already exists.
	AlreadyExists = 6,
	/// The caller is identified but refused authorization.
	PermissionDenied = 7,
	/// Capacity refusal; retry with backoff may succeed.
	ResourceExhausted = 8,
	/// System state must change before a retry can succeed.
	FailedPrecondition = 9,
	/// The operation was aborted, typically by a concurrency conflict.
	Aborted = 10,
	/// The request walked past the valid range of the operation.
	OutOfRange = 11,
	/// No handler answers the requested operation.
	Unimplemented = 12,
	/// The receiver hit a local fault; nothing was wrong with the request.
	Internal = 13,
	/// Transient unavailability; retry with backoff.
	Unavailable = 14,
	/// Unrecoverable data loss or corruption.
	DataLoss = 15,
	/// The caller lacks valid authentication credentials.
	Unauthenticated = 16,
}

impl TransitStatus {
	/// Gate-verdict normalization for [`GatePolicy`] and export-gate loops.
	///
	/// [`TransitStatus::Unknown`] is a local bug, not a verdict, so it
	/// maps to [`TransitStatus::Internal`]. The peer then sees a server
	/// fault. Call sites apply this before a gate status reaches the wire
	/// or the export audit trail. The built-in export allowlist does not
	/// use this helper.
	#[must_use]
	pub(crate) const fn normalized_verdict(self) -> Self {
		match self {
			Self::Unknown => Self::Internal,
			verdict => verdict,
		}
	}

	/// Canonical variant name, e.g. as an audit-event label.
	pub const fn as_str(&self) -> &'static str {
		match self {
			Self::Ok => "Ok",
			Self::Cancelled => "Cancelled",
			Self::Unknown => "Unknown",
			Self::InvalidArgument => "InvalidArgument",
			Self::DeadlineExceeded => "DeadlineExceeded",
			Self::NotFound => "NotFound",
			Self::AlreadyExists => "AlreadyExists",
			Self::PermissionDenied => "PermissionDenied",
			Self::ResourceExhausted => "ResourceExhausted",
			Self::FailedPrecondition => "FailedPrecondition",
			Self::Aborted => "Aborted",
			Self::OutOfRange => "OutOfRange",
			Self::Unimplemented => "Unimplemented",
			Self::Internal => "Internal",
			Self::Unavailable => "Unavailable",
			Self::DataLoss => "DataLoss",
			Self::Unauthenticated => "Unauthenticated",
		}
	}
}

/// Authenticated peer context of one established session.
///
/// The identity facts a gate or request handler may key on: the validated
/// peer certificate from a mutual-auth handshake and the dual-signed
/// session receipt when the session is budget-bearing. The empty (default)
/// context means no authenticated facts: cleartext connections, client-side
/// emit paths, and in-process evaluation all answer it.
///
/// On the mux serving path (`serve_mux`) the context is assembled per
/// invocation with the live receipt, so gates and handlers observe
/// post-rekey rotations. Single-flight sessions cannot rekey, so a
/// one-shot [`SessionContext::capture`] is exact there.
#[derive(Clone, Debug, Default)]
pub struct SessionContext {
	#[cfg(feature = "transport")]
	peer_certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "transport")]
	peer_public_key: Option<Arc<[u8]>>,
	#[cfg(feature = "transport")]
	session_receipt: Option<Arc<StoredReceipt>>,
}

/// DER-encoded `SubjectPublicKeyInfo` of a certificate.
#[cfg(feature = "transport")]
fn spki_der(certificate: &Certificate) -> Option<Arc<[u8]>> {
	let der = certificate.tbs_certificate.subject_public_key_info.to_der().ok()?;
	Some(Arc::from(der))
}

#[cfg(feature = "transport")]
impl SessionContext {
	/// Snapshot the peer identity and settled receipt off an encrypted
	/// transport after its handshake completed.
	pub fn capture<T: EncryptedProtocolState>(transport: &T) -> Self {
		let peer_certificate = transport.to_peer_certificate_arc();
		// Capture encodes SPKI once per session snapshot. Transport
		// admission does not yet share a cached Arc for this field.
		let peer_public_key = peer_certificate.as_deref().and_then(spki_der);
		Self {
			peer_certificate,
			peer_public_key,
			session_receipt: transport.to_session_receipt_arc(),
		}
	}

	/// The same identity with the receipt replaced when a live one exists.
	#[cfg(all(
		feature = "tokio",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) fn with_live_receipt(&self, receipt: Option<Arc<StoredReceipt>>) -> Self {
		Self {
			peer_certificate: self.peer_certificate.clone(),
			peer_public_key: self.peer_public_key.clone(),
			session_receipt: receipt.or_else(|| self.session_receipt.clone()),
		}
	}

	/// Validated peer certificate: client identity on a mutual-auth
	/// server, trust-store-validated server identity on a client.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.peer_certificate.as_deref()
	}

	/// DER-encoded `SubjectPublicKeyInfo` of the authenticated peer: the
	/// stable account key services meter or list against. Encoded once
	/// at capture; `None` without a peer certificate or when encoding
	/// failed.
	pub fn peer_public_key(&self) -> Option<&[u8]> {
		self.peer_public_key.as_deref()
	}

	/// Dual-signed session receipt, when the session is budget-bearing.
	pub fn session_receipt(&self) -> Option<&Arc<StoredReceipt>> {
		self.session_receipt.as_ref()
	}
}

/// Policy trait a user implements to decide message acceptance.
///
/// Gate policies are stateless procedures that evaluate whether a message
/// should be accepted or rejected. Every evaluation carries the
/// connection's [`SessionContext`]: identity-blind gates ignore it,
/// identity gates (black/white lists, receipt checks) key on it. Sites
/// without authenticated facts pass the empty context.
///
/// `message` is [`None`] when the stream kind has no request frame at dispatch
/// (mux streaming / duplex). Choose the `None` verdict by gate class:
/// - Session / capacity gates (peer lists, backpressure): ignore the
///   frame and key on `session` or shared state.
/// - Optional integrity (e.g. [`FrameIntegrityGate`]): return
///   [`TransitStatus::Ok`] when no frame exists.
/// - Auth that requires a signed or intact frame: fail closed with
///   [`TransitStatus::Unauthenticated`] or [`TransitStatus::PermissionDenied`].
///
/// Streaming authz belongs on session facts (mutual TLS, peer lists).
/// Frame-content rules alone do not protect stream opens.
pub trait GatePolicy: Send + Sync {
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus;
}

/// Policy trait a user implements to decide message acceptance.
pub trait ReceptorPolicy<T: Message>: Send + Sync {
	fn evaluate(&self, message: &T) -> TransitStatus;
}

/// Middleware wrapper for receptor policies that observes evaluations.
///
/// Wraps any `ReceptorPolicy` and calls a closure with the evaluation result.
/// The middleware is transparent.
pub struct ReceptorMiddleware<T: Message, R: ReceptorPolicy<T>, F>
where
	F: Fn(&T, &TransitStatus) + Send + Sync,
{
	inner: R,
	observer: F,
	_phantom: PhantomData<T>,
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
		Self { inner, observer, _phantom: PhantomData }
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
	fn evaluate(&self, _: Option<&Frame>, _: &SessionContext) -> TransitStatus {
		TransitStatus::Ok
	}
}

/// Ordered gate composition: member gates evaluate in insertion order and
/// the first non-[`TransitStatus::Ok`] verdict decides. An empty chain
/// accepts, matching [`AcceptAllGate`].
#[derive(Default)]
pub struct GateChain {
	gates: Vec<Box<dyn GatePolicy>>,
}

impl GateChain {
	/// Append a gate to the end of the evaluation order.
	pub fn with(mut self, gate: impl GatePolicy + 'static) -> Self {
		self.push(gate);
		self
	}

	/// Append a gate to the end of the evaluation order.
	pub fn push(&mut self, gate: impl GatePolicy + 'static) {
		self.gates.push(Box::new(gate));
	}
}

impl GatePolicy for GateChain {
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		self.gates
			.iter()
			.map(|gate| gate.evaluate(message, session))
			.find(|status| *status != TransitStatus::Ok)
			.unwrap_or(TransitStatus::Ok)
	}
}

/// Gate that requires every frame to carry a valid frame integrity (FI) digest.
///
/// A frame is [`TransitStatus::Ok`] only when it carries an FI value that
/// recomputes to the same digest under `D`. Every other case is rejected with
/// [`TransitStatus::PermissionDenied`].
#[cfg(feature = "digest")]
pub struct FrameIntegrityGate<D> {
	_marker: PhantomData<fn() -> D>,
}

#[cfg(feature = "digest")]
impl<D> Default for FrameIntegrityGate<D> {
	fn default() -> Self {
		Self { _marker: PhantomData }
	}
}

#[cfg(feature = "digest")]
impl<D> GatePolicy for FrameIntegrityGate<D>
where
	D: crate::crypto::hash::Digest + crate::der::oid::AssociatedOid,
{
	fn evaluate(&self, message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		// Optional integrity: no request frame means nothing to check.
		let Some(message) = message else {
			return TransitStatus::Ok;
		};

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
	F: Fn(Option<&Frame>, &TransitStatus) + Send + Sync,
{
	inner: G,
	observer: F,
}

impl<G: GatePolicy, F> GateMiddleware<G, F>
where
	F: Fn(Option<&Frame>, &TransitStatus) + Send + Sync,
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
	F: Fn(Option<&Frame>, &TransitStatus) + Send + Sync,
{
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		let status = self.inner.evaluate(message, session);

		// Observe the evaluation (transparent)
		(self.observer)(message, &status);

		status
	}
}

#[cfg(all(test, feature = "digest", feature = "builder", feature = "sha3"))]
mod tests {
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;

	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::testing::{create_frame_with_frame_integrity, create_test_message};

	struct StaticGate(TransitStatus);

	impl GatePolicy for StaticGate {
		fn evaluate(&self, _: Option<&Frame>, _: &SessionContext) -> TransitStatus {
			self.0
		}
	}

	struct ProbeGate(Arc<AtomicBool>);

	impl GatePolicy for ProbeGate {
		fn evaluate(&self, _: Option<&Frame>, _: &SessionContext) -> TransitStatus {
			self.0.store(true, Ordering::SeqCst);
			TransitStatus::Ok
		}
	}

	#[test]
	fn empty_chain_accepts() {
		let chain = GateChain::default();
		assert!(matches!(
			chain.evaluate(Some(&create_frame_with_frame_integrity()), &SessionContext::default()),
			TransitStatus::Ok
		));
	}

	#[test]
	fn chain_returns_first_refusal() {
		let chain = GateChain::default()
			.with(StaticGate(TransitStatus::Ok))
			.with(StaticGate(TransitStatus::ResourceExhausted))
			.with(StaticGate(TransitStatus::PermissionDenied));

		let frame = create_frame_with_frame_integrity();
		assert!(matches!(
			chain.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::ResourceExhausted
		));
	}

	#[test]
	fn chain_short_circuits_after_refusal() {
		let evaluated = Arc::new(AtomicBool::new(false));
		let chain = GateChain::default()
			.with(StaticGate(TransitStatus::PermissionDenied))
			.with(ProbeGate(Arc::clone(&evaluated)));

		let frame = create_frame_with_frame_integrity();
		let _ = chain.evaluate(Some(&frame), &SessionContext::default());
		assert!(!evaluated.load(Ordering::SeqCst));
	}

	#[test]
	fn accepts_intact_frame() {
		let gate = FrameIntegrityGate::<Sha3_256>::default();

		let frame = create_frame_with_frame_integrity();
		assert!(matches!(
			gate.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::Ok
		));
	}

	#[test]
	fn rejects_tampered_frame() {
		let mut frame = create_frame_with_frame_integrity();
		frame.metadata.id = b"tampered".to_vec();

		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(
			gate.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::PermissionDenied
		));
	}

	#[test]
	fn rejects_frame_without_integrity() -> crate::error::Result<()> {
		let message = create_test_message(None);
		let frame = compose! { V0: id: "gate-no-fi", order: 1u64, message: message }?;

		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(
			gate.evaluate(Some(&frame), &SessionContext::default()),
			TransitStatus::PermissionDenied
		));
		Ok(())
	}

	#[test]
	fn session_path_skips_frame_integrity() {
		let gate = FrameIntegrityGate::<Sha3_256>::default();
		assert!(matches!(gate.evaluate(None, &SessionContext::default()), TransitStatus::Ok));
	}
}
