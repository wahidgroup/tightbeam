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
use crate::crypto::x509::CanonicalKey;
#[cfg(feature = "transport")]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(feature = "transport")]
use crate::transport::handshake::SessionPeer;
#[cfg(feature = "transport")]
use crate::transport::state::EncryptedProtocolState;
#[cfg(feature = "transport")]
use crate::x509::Certificate;

/// A transport response status code.
///
/// The variants and their wire values are those of the gRPC canonical status
/// registry (`google.rpc.Code`).
#[derive(Enumerated, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitStatus {
	/// The request was processed.
	Ok = 0,
	/// The caller cancelled the operation.
	Cancelled = 1,
	/// An unclassified failure. It is never a valid gate verdict, so
	/// evaluation normalizes it to [`TransitStatus::Internal`].
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
	/// The receiver refused for lack of capacity. A retry with backoff may
	/// succeed.
	ResourceExhausted = 8,
	/// System state must change before a retry can succeed.
	FailedPrecondition = 9,
	/// The operation was aborted, typically by a concurrency conflict.
	Aborted = 10,
	/// The request walked past the valid range of the operation.
	OutOfRange = 11,
	/// No handler answers the requested operation.
	Unimplemented = 12,
	/// The receiver hit a local fault, and the request itself was valid.
	Internal = 13,
	/// The receiver is unavailable for a transient reason. Retry with backoff.
	Unavailable = 14,
	/// The receiver hit unrecoverable data loss or corruption.
	DataLoss = 15,
	/// The caller lacks valid authentication credentials.
	Unauthenticated = 16,
}

impl TransitStatus {
	/// Normalizes a gate verdict for [`GatePolicy`] and export-gate loops.
	///
	/// [`TransitStatus::Unknown`] is a local bug, not a verdict, so it maps to
	/// [`TransitStatus::Internal`], which the peer reads as a server fault.
	/// Call sites apply this to the status of a configured gate before it
	/// reaches the wire or the export audit trail. The verdict of the built-in
	/// export allowlist goes out as it stands.
	#[cfg(feature = "transport-policy")]
	#[must_use]
	pub(crate) const fn normalized_verdict(self) -> Self {
		match self {
			Self::Unknown => Self::Internal,
			verdict => verdict,
		}
	}

	/// Converts this status into a terminal stream refusal.
	///
	/// The mux responder maps the failure onto the stream's `End` trailer.
	#[cfg(all(feature = "transport", feature = "colony"))]
	#[must_use]
	pub(crate) fn refusal(self) -> crate::TightBeamError {
		crate::transport::error::TransportError::from(self).into()
	}

	/// The canonical name of the variant, which an audit event uses as a label.
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

/// The authenticated peer context of one established session.
///
/// These are the identity facts a gate or request handler may key on:
///
/// - The validated peer certificate from a mutual-auth handshake.
/// - The [`CanonicalKey`] of the peer's key.
/// - The dual-signed session receipt, when the session is budget-bearing.
///
/// The default context holds no authenticated fact. Cleartext connections,
/// client-side emit paths, and in-process evaluation pass it.
///
/// # Rekey
///
/// On the mux serving path (`MuxAcceptor::serve`), each invocation builds the
/// context with the live receipt, so gates and handlers see the receipt of
/// each rekey. A single-flight session keeps the keys of its handshake for
/// its whole life, so one [`SessionContext::capture`] is exact there.
#[derive(Clone, Debug, Default)]
pub struct SessionContext {
	/// The record of the peer the session holds: the certificate, and the DER
	/// and the canonical form of its key, which the handshake derived from it
	/// once.
	#[cfg(feature = "transport")]
	peer: Option<Arc<SessionPeer>>,
	#[cfg(feature = "transport")]
	session_receipt: Option<Arc<StoredReceipt>>,
}

#[cfg(feature = "transport")]
impl SessionContext {
	/// Snapshot the peer identity and settled receipt off an encrypted
	/// transport after its handshake completed.
	///
	/// The snapshot shares the session's record of its peer and its receipt,
	/// at one reference count each.
	pub fn capture<T: EncryptedProtocolState>(transport: &T) -> Self {
		let session = transport.session_state();
		let peer = session.session_peer().map(Arc::clone);
		Self { peer, session_receipt: session.receipt_arc() }
	}

	/// The same identity with the receipt replaced when a live one exists.
	#[cfg(all(
		feature = "tokio",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(crate) fn with_live_receipt(&self, receipt: Option<Arc<StoredReceipt>>) -> Self {
		Self {
			peer: self.peer.clone(),
			session_receipt: receipt.or_else(|| self.session_receipt.clone()),
		}
	}

	/// The validated peer certificate. On a mutual-auth server this is the
	/// client identity. On a client it is the trust-store-validated
	/// server identity.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		let peer = self.peer.as_deref();
		peer.map(|peer| peer.certificate().as_ref())
	}

	/// The key identity of the authenticated peer, which a peer list matches,
	/// or `None` without a peer certificate.
	///
	/// A gate that lists a peer by its key compares this value with the
	/// canonical form that [`CanonicalKey::of`] reads from that key.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::{CanonicalKey, Certificate};
	/// use tightbeam::policy::SessionContext;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// // Whether the peer of `session` holds the key that `listed` carries.
	/// fn is_listed(session: &SessionContext, listed: &Certificate) -> bool {
	///     let listed = CanonicalKey::of(&listed.tbs_certificate.subject_public_key_info);
	///     listed.is_ok_and(|listed| session.peer_key() == Some(&listed))
	/// }
	///
	/// // A context that proved no peer lists no key.
	/// let listed = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// assert!(!is_listed(&SessionContext::default(), &listed));
	/// ```
	pub fn peer_key(&self) -> Option<&CanonicalKey> {
		self.peer.as_deref().map(SessionPeer::key)
	}

	/// A session bound to `certificate` as its authenticated peer.
	#[cfg(all(test, feature = "colony"))]
	pub(crate) fn for_peer(certificate: Arc<Certificate>) -> Self {
		let peer = SessionPeer::try_from(certificate).expect("a test certificate records its peer");
		Self { peer: Some(Arc::new(peer)), session_receipt: None }
	}

	/// The identity this session's handshake proved, or [`None`] when the
	/// transport authenticated no peer.
	///
	/// A per-identity budget MUST NOT fall back to a shared stand-in:
	/// every unauthenticated caller would key on the same row, so one
	/// caller's failures would deny all the others (CWE-645). Each caller
	/// decides what an unauthenticated transport may do instead.
	pub fn proven_peer(&self) -> Option<ProvenPeer<'_>> {
		self.peer_key().map(ProvenPeer)
	}

	/// The dual-signed session receipt, when the session is budget-bearing.
	pub fn session_receipt(&self) -> Option<&Arc<StoredReceipt>> {
		self.session_receipt.as_ref()
	}
}

/// An identity the transport handshake proved.
///
/// A gate that counts failures before it checks a frame's signature MUST
/// key those counts on something the sender could not choose. This type is
/// that key:
///
/// - [`SessionContext::proven_peer`] alone creates one, so frame-carried bytes
///   stay out of a per-identity budget (CWE-345).
/// - A `ProvenPeer` exists only for a session whose transport proved a peer,
///   so a budget keyed on this type is always attributable to one caller.
#[cfg(feature = "transport")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProvenPeer<'a>(&'a CanonicalKey);

#[cfg(feature = "transport")]
impl<'a> ProvenPeer<'a> {
	/// The key identity of the peer, as the [`CanonicalKey`] of its key.
	///
	/// A gate keys its per-identity state on this value. It comes from the
	/// transport handshake, so a sender cannot pick the budget that its frames
	/// count against.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::CanonicalKey;
	/// use tightbeam::policy::SessionContext;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// // Whether the handshake of `session` proved the key `listed`.
	/// fn is_proven(session: &SessionContext, listed: &CanonicalKey) -> bool {
	///     session.proven_peer().is_some_and(|peer| peer.as_key() == listed)
	/// }
	///
	/// // A context that proved no peer proves no key.
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let listed = CanonicalKey::of(&certificate.tbs_certificate.subject_public_key_info)?;
	/// assert!(!is_proven(&SessionContext::default(), &listed));
	/// # Ok::<(), tightbeam::der::Error>(())
	/// ```
	#[must_use]
	pub fn as_key(&self) -> &'a CanonicalKey {
		self.0
	}

	/// Create an identity for a test that stands in for a handshake.
	#[cfg(all(test, feature = "colony"))]
	pub(crate) fn for_test(key: &'a CanonicalKey) -> Self {
		Self(key)
	}
}

/// The policy trait a user implements to decide message acceptance.
///
/// Every evaluation carries the connection's [`SessionContext`], and a site
/// without authenticated facts passes the empty context:
///
/// - An identity-blind gate ignores the context.
/// - An identity gate, such as an allow or deny list or a receipt check, keys on it.
///
/// # Streams
///
/// `message` is [`None`] when the stream kind has no request frame at dispatch
/// (mux streaming and duplex). Choose the `None` verdict by gate class:
///
/// - A session or capacity gate (peer lists, backpressure) ignores the frame
///   and keys on `session` or shared state.
/// - An optional integrity gate, such as [`FrameIntegrityGate`], returns
///   [`TransitStatus::Ok`] when no frame exists.
/// - An auth gate that requires a signed or intact frame fails closed with
///   [`TransitStatus::Unauthenticated`] or [`TransitStatus::PermissionDenied`].
///
/// Streaming authorization belongs on session facts (mutual TLS, peer lists),
/// because frame-content rules alone leave stream opens unprotected.
pub trait GatePolicy: Send + Sync {
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus;
}

/// The policy trait a user implements to decide whether to accept a typed
/// message.
pub trait ReceptorPolicy<T: Message>: Send + Sync {
	fn evaluate(&self, message: &T) -> TransitStatus;
}

/// A middleware wrapper for receptor policies that observes evaluations.
///
/// It calls a closure with each evaluation result and returns the decision of
/// the wrapped [`ReceptorPolicy`] unchanged.
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
	/// Wrap a receptor policy in a middleware.
	///
	/// # Arguments
	///
	/// - `inner`: the receptor policy whose decision the middleware returns.
	/// - `observer`: the closure the middleware calls with the message and the evaluation result.
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

		(self.observer)(message, &status);

		status
	}
}
/// The default gate, which accepts every message.
#[derive(Default)]
pub struct AcceptAllGate;

impl GatePolicy for AcceptAllGate {
	fn evaluate(&self, _: Option<&Frame>, _: &SessionContext) -> TransitStatus {
		TransitStatus::Ok
	}
}

/// An ordered composition of gates. Member gates evaluate in insertion order,
/// and the first non-[`TransitStatus::Ok`] verdict decides. An empty chain
/// accepts, as [`AcceptAllGate`] does.
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

/// A shared gate evaluates as the gate it points to, so a chain or a builder
/// holds one gate behind an `Arc`.
#[cfg(feature = "transport")]
impl GatePolicy for Arc<dyn GatePolicy + Send + Sync> {
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		(**self).evaluate(message, session)
	}
}

/// A gate that requires a valid frame integrity (FI) digest on every frame.
///
/// A frame passes as [`TransitStatus::Ok`] only when it carries an FI value
/// that recomputes to the same digest under `D`. The gate refuses every other
/// frame with [`TransitStatus::PermissionDenied`], and a stream open with no
/// request frame passes.
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
		// Integrity is optional here, so no request frame means
		// nothing to check.
		let Some(message) = message else {
			return TransitStatus::Ok;
		};

		match message.verify_frame_integrity::<D>() {
			Ok(true) => TransitStatus::Ok,
			_ => TransitStatus::PermissionDenied,
		}
	}
}

/// A middleware wrapper for gate policies that observes evaluations.
///
/// It calls a closure with each evaluation result and returns the decision of
/// the wrapped [`GatePolicy`] unchanged.
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
	/// Wrap a gate policy in a middleware.
	///
	/// # Arguments
	///
	/// - `inner`: the gate policy whose decision the middleware returns.
	/// - `observer`: the closure the middleware calls with the message and the evaluation result.
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
		(self.observer)(message, &status);
		status
	}
}

#[cfg(all(test, feature = "digest", feature = "builder", feature = "sha3"))]
mod tests {
	use std::sync::mpsc;

	use crate::crypto::hash::Sha3_256;
	use crate::testing::fixtures::TestGate;
	use crate::testing::TestFrame;

	use super::*;

	/// An accept-all gate under a middleware whose observer sends the id of
	/// each frame that reaches the gate, beside the receiver of those ids.
	fn observed_accept_all() -> (impl GatePolicy, mpsc::Receiver<Option<Vec<u8>>>) {
		let (reached, ids) = mpsc::channel();
		let observer = move |frame: Option<&Frame>, _: &TransitStatus| {
			let id = frame.map(|frame| frame.metadata().id().to_vec());
			// The test holds the receiver until it reads it, so the send lands.
			let _ = reached.send(id);
		};

		(GateMiddleware::new(AcceptAllGate, observer), ids)
	}

	// A chain answers with the first refusal of its gates, in the order they
	// joined, and an empty chain accepts.
	crate::tb_cases! {
		fn a_chain_answers((chain, expected): (GateChain, TransitStatus)) {
			let frame = TestFrame::with_integrity();
			let verdict = chain.evaluate(Some(&frame), &SessionContext::default());
			assert_eq!(verdict, expected);
		}
		cases {
			ok_with_no_gates => (GateChain::default(), TransitStatus::Ok),
			with_its_first_refusal => (
				GateChain::default()
					.with(TestGate(TransitStatus::Ok))
					.with(TestGate(TransitStatus::ResourceExhausted))
					.with(TestGate(TransitStatus::PermissionDenied)),
				TransitStatus::ResourceExhausted
			),
		}
	}

	/// A refusal ends the chain, so the frame reaches no gate after it.
	#[test]
	fn chain_short_circuits_after_refusal() {
		let (observed, reached) = observed_accept_all();
		let chain = GateChain::default()
			.with(TestGate(TransitStatus::PermissionDenied))
			.with(observed);

		let frame = TestFrame::with_integrity();
		let verdict = chain.evaluate(Some(&frame), &SessionContext::default());

		assert_eq!(verdict, TransitStatus::PermissionDenied);
		assert!(matches!(reached.try_recv(), Err(mpsc::TryRecvError::Empty)));
	}

	// The frame integrity gate accepts a frame whose digest recomputes, and a
	// stream open with no frame. It denies every other frame.
	crate::tb_cases! {
		fn the_integrity_gate_answers((frame, expected): (Option<Frame>, TransitStatus)) {
			let gate = FrameIntegrityGate::<Sha3_256>::default();
			let verdict = gate.evaluate(frame.as_ref(), &SessionContext::default());
			assert_eq!(verdict, expected);
		}
		cases {
			ok_to_an_intact_frame => (Some(TestFrame::with_integrity()), TransitStatus::Ok),
			denied_to_a_tampered_frame => (
				Some(TestFrame::tamper(&TestFrame::with_integrity(), b"fi-frame", b"tampered")),
				TransitStatus::PermissionDenied
			),
			denied_to_a_frame_without_integrity => (
				Some(TestFrame::v0(None, Some("gate-no-fi"))),
				TransitStatus::PermissionDenied
			),
			ok_to_the_session_path => (None, TransitStatus::Ok),
		}
	}

	// Each status names its variant, the label that an audit event writes.
	crate::tb_cases! {
		fn a_status_names_its_variant((status, name): (TransitStatus, &str)) {
			assert_eq!(status.as_str(), name);
		}
		cases {
			ok => (TransitStatus::Ok, "Ok"),
			cancelled => (TransitStatus::Cancelled, "Cancelled"),
			unknown => (TransitStatus::Unknown, "Unknown"),
			invalid_argument => (TransitStatus::InvalidArgument, "InvalidArgument"),
			deadline_exceeded => (TransitStatus::DeadlineExceeded, "DeadlineExceeded"),
			not_found => (TransitStatus::NotFound, "NotFound"),
			already_exists => (TransitStatus::AlreadyExists, "AlreadyExists"),
			permission_denied => (TransitStatus::PermissionDenied, "PermissionDenied"),
			resource_exhausted => (TransitStatus::ResourceExhausted, "ResourceExhausted"),
			failed_precondition => (TransitStatus::FailedPrecondition, "FailedPrecondition"),
			aborted => (TransitStatus::Aborted, "Aborted"),
			out_of_range => (TransitStatus::OutOfRange, "OutOfRange"),
			unimplemented => (TransitStatus::Unimplemented, "Unimplemented"),
			internal => (TransitStatus::Internal, "Internal"),
			unavailable => (TransitStatus::Unavailable, "Unavailable"),
			data_loss => (TransitStatus::DataLoss, "DataLoss"),
			unauthenticated => (TransitStatus::Unauthenticated, "Unauthenticated"),
		}
	}
}
