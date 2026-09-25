//! Application-facing message transmission, which sends and receives frames.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "transport-policy"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::future::Future;

use crate::asn1::Frame;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::transport::envelopes::TransportEnvelope;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::io::MessageIO;
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;

#[cfg(all(
	feature = "transport-policy",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::transport::envelopes::WireEnvelope;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
mod x509 {
	pub use crate::crypto::aead::{DecryptContent, KeyInit};
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
	pub use crate::crypto::sign::Verifier;
	pub use crate::der::Decode;
	pub use crate::spki::EncodePublicKey;
	pub use crate::transport::handshake::HandshakeMessage;
	pub use crate::transport::io::EncryptedMessageIO;
	pub use crate::transport::state::EncryptedProtocolState;
	pub use crate::transport::state::SessionPhase;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use crate::transport::state::ServerHandshakeSlot;

	#[cfg(feature = "transport-ecies")]
	pub use crate::crypto::ecies::EciesPublicKeyOps;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use x509::*;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::transport::policy::{RestartPolicy, RetryAction};
}

#[cfg(feature = "transport-policy")]
use policy::*;

#[cfg(all(feature = "transport-policy", feature = "instrument"))]
use crate::instrumentation::events;
#[cfg(all(feature = "transport-policy", feature = "instrument"))]
use crate::trace::TraceCollector;

/// Source of the connection audit trail for access-gate verdicts.
///
/// Every plane that evaluates a collector gate implements this (the TCP
/// transports, the mux handle) so `gate_inbound` can record the
/// verdict wherever the gate runs.
#[cfg(feature = "transport-policy")]
pub trait GateAudit {
	/// The connection audit trail, when instrumentation is attached.
	#[cfg(feature = "instrument")]
	fn audit_trace(&self) -> Option<&TraceCollector>;
}

/// Gate one inbound request with the session's authenticated context and
/// record the verdict into the connection audit trail (`GATE_ACCEPT` or
/// `GATE_REJECT`).
///
/// # Emission point
///
/// This is the only gate-verdict emission point. The mux responder and the
/// cleartext and encrypted single-flight collectors all route through here,
/// so access decisions are observable evidence on every plane.
///
/// # Verdicts
///
/// - `frame` is [`None`] for a mux streaming or duplex open that has no request
///   frame at dispatch. Session-scoped gates still evaluate.
/// - A gate that returns [`TransitStatus::Unknown`] signals a local bug, so
///   [`TransitStatus::normalized_verdict`] maps it to
///   [`TransitStatus::Internal`] and the peer sees a server fault.
#[cfg(feature = "transport-policy")]
pub(crate) fn gate_inbound<G, A>(gate: &G, audit: &A, frame: Option<&Frame>, session: &SessionContext) -> TransitStatus
where
	G: GatePolicy + ?Sized,
	A: GateAudit + ?Sized,
{
	let status = gate.evaluate(frame, session).normalized_verdict();

	#[cfg(feature = "instrument")]
	if let Some(trace) = audit.audit_trace() {
		let event = if status == TransitStatus::Ok {
			events::GATE_ACCEPT
		} else {
			events::GATE_REJECT
		};

		// Verdict evidence: the status names why, the peer SPKI names who.
		trace.emit_event_with_evidence(event, status.as_str(), session.peer_public_key());
	}
	#[cfg(not(feature = "instrument"))]
	let _ = audit;

	status
}

#[cfg(feature = "transport-policy")]
#[derive(Debug)]
/// A frame routed through retries, modeled on a physical letter that can
/// return to its sender.
pub(crate) struct Letter {
	frame: Option<Frame>,
}

#[cfg(feature = "transport-policy")]
impl Letter {
	pub fn new(frame: Frame) -> Self {
		Self { frame: Some(frame) }
	}

	pub fn try_peek(&self) -> TransportResult<&Frame> {
		self.frame.as_ref().ok_or(TransportError::MissingRequest)
	}

	pub fn try_take(&mut self) -> TransportResult<Frame> {
		self.frame.take().ok_or(TransportError::MissingRequest)
	}

	pub fn try_return_to_sender(&mut self, frame: Frame) -> TransportResult<()> {
		if self.frame.is_some() {
			return Err(TransportError::InvalidMessage);
		}
		self.frame = Some(frame);
		Ok(())
	}
}

#[cfg(feature = "transport-policy")]
impl From<Frame> for Letter {
	fn from(frame: Frame) -> Self {
		Self::new(frame)
	}
}

/// Run one restart-policy evaluation over a failed send.
///
/// - `Ok` carries the frame to resend and the delay to observe first.
/// - `Err` carries the terminal error.
///
/// An error that carries no frame passes through unchanged.
#[cfg(feature = "transport-policy")]
fn evaluate_retry<P>(
	policy: &P,
	error: TransportError,
	attempt: usize,
) -> Result<(Box<Frame>, core::time::Duration), TransportError>
where
	P: RestartPolicy + ?Sized,
{
	match error {
		TransportError::MessageNotSent(boxed_frame, ref failure) => {
			// Pass the box to the policy, so the frame stays in its single
			// allocation.
			match policy.evaluate(boxed_frame, failure, attempt) {
				RetryAction::Retry { .. } if attempt == usize::MAX => Err(TransportError::MaxRetriesExceeded),
				RetryAction::Retry { frame, delay } => Ok((frame, delay)),
				RetryAction::NoRetry => Err(TransportError::OperationFailed(*failure)),
			}
		}
		other_error => Err(other_error),
	}
}

/// Base emitter trait, which sends TightBeam messages with gate and restart
/// policies.
#[cfg(feature = "transport-policy")]
pub trait MessageEmitter: MessageIO {
	type EmitterGate: GatePolicy + ?Sized;
	type RestartPolicy: RestartPolicy + ?Sized;

	/// Return the restart policy.
	fn to_restart_policy_ref(&self) -> &Self::RestartPolicy;

	/// Return the emitter gate policy.
	fn to_emitter_gate_policy_ref(&self) -> &Self::EmitterGate;

	/// Run the protocol-specific send and receive operation.
	///
	/// The operation sends the message and receives the response.
	///
	/// # Returns
	///
	/// - `status`: the TransitStatus from the response.
	/// - `response`: the optional response frame from the server.
	/// - `original`: the original frame when the server rejected it, for a
	///   retry, or `None` when the frame was sent or consumed.
	fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> impl Future<Output = TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>> + MaybeSend;

	/// Send a TightBeam message.
	fn emit(
		&mut self,
		message: Frame,
		attempt: Option<usize>,
	) -> impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		emit_with_retry(self, message, attempt)
	}
}

/// Default [`MessageEmitter::emit`] body as a free function so the returned
/// future can carry [`MaybeSend`] without an AFIT default-method capture.
async fn emit_with_retry<T: MessageEmitter + MaybeSend + ?Sized>(
	emitter: &mut T,
	message: Frame,
	attempt: Option<usize>,
) -> TransportResult<Option<Frame>> {
	let mut letter = Letter::from(message);
	let mut current_attempt = attempt.unwrap_or(0);

	loop {
		// Evaluate the gate policy before sending. Emitter gates are
		// client-side and need no connection context, so they get the empty
		// context.
		let message = Some(letter.try_peek()?);
		let session = SessionContext::default();
		let status = emitter.to_emitter_gate_policy_ref().evaluate(message, &session);
		if status != TransitStatus::Ok {
			return Err(TransportError::from(status));
		}

		let message_to_send = letter.try_take()?;

		let (status, response, original_message) = match emitter.perform_send_receive(message_to_send).await {
			Ok(result) => result,
			Err(e) => {
				let (frame, delay) = evaluate_retry(emitter.to_restart_policy_ref(), e, current_attempt)?;
				emitter.clock().sleep(delay).await;

				// Unbox the frame to put it back into the Letter.
				letter.try_return_to_sender(*frame)?;
				current_attempt += 1;
				continue;
			}
		};

		let result: TransportResult<&Frame> = if status != TransitStatus::Ok {
			if let Some(msg) = original_message {
				// The server rejected the frame, so return it for a retry.
				match TransportFailure::try_from(status) {
					Ok(failure) => Err(TransportError::from_failure(msg, failure)),
					Err(error) => Err(error),
				}
			} else {
				return Err(TransportError::from(status));
			}
		} else {
			match &response {
				Some(msg) => Ok(msg),
				None => return Ok(None),
			}
		};

		// Evaluate the retry policy only on an error.
		match result {
			Err(error) => {
				let (frame, delay) = evaluate_retry(emitter.to_restart_policy_ref(), error, current_attempt)?;
				emitter.clock().sleep(delay).await;
				// Unbox the frame to put it back into the Letter.
				letter.try_return_to_sender(*frame)?;
				current_attempt += 1;
			}
			Ok(_) => {
				return Ok(response);
			}
		}
	}
}

/// Every capability a message collector must already have.
///
/// The trait exists because a supertrait takes no inline feature gate. With
/// `transport-policy`, every collector must also expose an audit trail
/// ([`GateAudit`]) for gate-verdict recording. The blanket impl satisfies
/// the requirement, so implementers reach it through [`MessageCollector`]
/// alone.
pub trait CollectorRequirements: MessageIO + GateAudit {}

#[cfg(feature = "transport-policy")]
impl<T: MessageIO + GateAudit> CollectorRequirements for T {}

/// Every capability a message collector must already have. Without
/// `transport-policy`, the trait requires no audit trail.
#[cfg(not(feature = "transport-policy"))]
pub trait CollectorRequirements: MessageIO {}

#[cfg(not(feature = "transport-policy"))]
impl<T: MessageIO> CollectorRequirements for T {}

/// Message collector trait, which receives TightBeam messages.
pub trait MessageCollector: CollectorRequirements {
	/// Gate policy consulted for every collected message.
	#[cfg(feature = "transport-policy")]
	type CollectorGate: GatePolicy + ?Sized;

	/// Return the collector gate policy.
	#[cfg(feature = "transport-policy")]
	fn collector_gate(&self) -> &Self::CollectorGate;

	/// Read and validate a message without sending a response.
	///
	/// The method returns the message and the gate evaluation status.
	#[cfg(feature = "transport-policy")]
	fn collect_message(&mut self) -> impl Future<Output = TransportResult<(Arc<Frame>, TransitStatus)>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// Read and decode the envelope. An encrypted transport overrides
			// this step.
			let decoded_envelope = self.read_decoded_envelope().await?;
			// A cleartext connection carries no peer identity, so it gets the
			// empty context.
			let session = SessionContext::default();
			gate_collected_envelope(self, decoded_envelope, &session)
		}
	}

	/// Read and validate a message without sending a response.
	///
	/// The method returns the message. Without policies, the status is always
	/// `Ok`.
	#[cfg(not(feature = "transport-policy"))]
	fn collect_message(&mut self) -> impl Future<Output = TransportResult<(Arc<Frame>, TransitStatus)>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			let request_envelope = self.read_decoded_envelope().await?;
			let request = request_envelope.into_request_frame()?;
			Ok((request, TransitStatus::Ok))
		}
	}

	/// Try to collect the next message without blocking on a closed connection.
	///
	/// - `Ok(None)` means that the connection closed gracefully (EOF).
	/// - `Err` means that the connection failed unexpectedly.
	#[cfg(feature = "transport-policy")]
	fn try_collect_message(
		&mut self,
	) -> impl Future<Output = TransportResult<Option<(Arc<Frame>, TransitStatus)>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// Try to read the envelope, which is `None` on a graceful close.
			let decoded_envelope = match self.try_read_decoded_envelope().await? {
				Some(envelope) => envelope,
				None => return Ok(None), // Connection closed gracefully
			};

			// A cleartext connection carries no peer identity, so it gets the
			// empty context.
			let session = SessionContext::default();
			let gated = gate_collected_envelope(self, decoded_envelope, &session)?;
			Ok(Some(gated))
		}
	}

	/// Try to collect the next message without blocking on a closed connection.
	///
	/// - `Ok(None)` means that the connection closed gracefully (EOF).
	/// - `Err` means that the connection failed unexpectedly.
	#[cfg(not(feature = "transport-policy"))]
	fn try_collect_message(
		&mut self,
	) -> impl Future<Output = TransportResult<Option<(Arc<Frame>, TransitStatus)>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// Try to read the envelope, which is `None` on a graceful close.
			let request_envelope = match self.try_read_decoded_envelope().await? {
				Some(envelope) => envelope,
				None => return Ok(None), // Connection closed gracefully
			};

			let request = request_envelope.into_request_frame()?;
			Ok(Some((request, TransitStatus::Ok)))
		}
	}

	/// Send a response for one collected message, in the wire mode the session
	/// phase decides.
	#[cfg(feature = "x509")]
	fn send_response(
		&mut self,
		status: TransitStatus,
		message: Option<Frame>,
	) -> impl Future<Output = TransportResult<()>> + MaybeSend
	where
		Self: MaybeSend;

	/// The X.509 `collect_message` with encryption and handshake support.
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn collect_message_with_encryption<P>(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)>
	where
		Self: EncryptedMessageIO + Sized + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EciesPublicKeyOps,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature>,
		for<'b> P::VerifyingKey: From<&'b PublicKey<P::Curve>>,
		P::AeadCipher: KeyInit,
	{
		loop {
			match collect_step(self).await? {
				CollectStep::Handshake(request) => self.perform_server_handshake(request).await?,
				CollectStep::Envelope(envelope) => {
					let session = SessionContext::capture(self);
					return gate_collected_envelope(self, envelope, &session);
				}
			}
		}
	}

	/// The X.509 `collect_message` with encryption and handshake support, for
	/// the CMS-only build.
	///
	/// A trait where-clause stays with the trait, so the method is
	/// declared per feature combination with that build's predicate set.
	#[cfg(all(
		feature = "transport-policy",
		not(feature = "transport-ecies"),
		feature = "transport-cms"
	))]
	#[allow(async_fn_in_trait)]
	async fn collect_message_with_encryption<P>(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)>
	where
		Self: EncryptedMessageIO + Sized + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		loop {
			match collect_step(self).await? {
				CollectStep::Handshake(request) => self.perform_server_handshake(request).await?,
				CollectStep::Envelope(envelope) => {
					let session = SessionContext::capture(self);
					return gate_collected_envelope(self, envelope, &session);
				}
			}
		}
	}
}

/// Outcome of one protocol-agnostic collector step.
#[cfg(all(
	feature = "transport-policy",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) enum CollectStep {
	/// Cleartext handshake container to feed the server-side dispatcher,
	/// decoded once with the bytes it arrived as.
	Handshake(HandshakeMessage),
	/// Decrypted (or legitimately cleartext) application envelope.
	Envelope(TransportEnvelope),
}

/// Read one wire envelope, enforce size ceilings, and classify it.
///
/// The step is protocol-agnostic. It surfaces a handshake container as a
/// decoded message for the caller's dispatcher, and it decrypts and returns
/// everything else.
#[cfg(all(
	feature = "transport-policy",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) async fn collect_step<T>(transport: &mut T) -> TransportResult<CollectStep>
where
	T: EncryptedMessageIO + EncryptedProtocolState + Sized,
{
	// Read the wire envelope, then enforce the size ceiling of its kind.
	let wire_bytes = transport.read_envelope_bytes().await?;
	let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
	let ceiling = match &wire_envelope {
		WireEnvelope::Cleartext(_) => transport.limits().cleartext_envelope,
		WireEnvelope::Encrypted(_) => transport.limits().encrypted_envelope,
	};
	if wire_bytes.len() > ceiling {
		return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
	}

	// An established session reads and writes encrypted, so nothing cleartext
	// is admitted on it. Before that, a provisioned endpoint admits only the
	// handshake containers, and an unprovisioned one admits traffic.
	let established = transport.session_state().phase().requires_encryption();
	let expects_encryption = transport.session_state().phase().is_handshake_pending();
	match wire_envelope {
		WireEnvelope::Cleartext(envelope) => {
			if established {
				// Circuit breaker: a cleartext frame on an agreed session is
				// not the peer this session established (CWE-319).
				transport.session_state_mut().reset();
				return Err(TransportError::MissingEncryption);
			}

			if expects_encryption {
				match envelope {
					TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
						Ok(CollectStep::Handshake(HandshakeMessage::try_from(envelope)?))
					}
					// Circuit breaker: once encryption is configured,
					// application traffic arrives encrypted.
					_ => {
						transport.session_state_mut().reset();
						Err(TransportError::MissingEncryption)
					}
				}
			} else {
				Ok(CollectStep::Envelope(envelope))
			}
		}
		WireEnvelope::Encrypted(encrypted_info) => {
			if !matches!(transport.session_state().phase(), SessionPhase::Encrypted(_)) {
				transport.session_state_mut().reset();
				return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
			}

			let decrypted_bytes = match transport.session_state().decryptor()?.decrypt_content(&encrypted_info) {
				Ok(bytes) => bytes,
				Err(_) => {
					transport.session_state_mut().reset();
					return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
				}
			};

			let envelope = decrypted_bytes.with(|bytes| T::decode_envelope(bytes))?;
			Ok(CollectStep::Envelope(envelope))
		}
	}
}

/// Extract the application request from a collected envelope and gate it
/// with the session's peer context, recording the verdict through
/// `gate_inbound`.
#[cfg(feature = "transport-policy")]
fn gate_collected_envelope<T>(
	transport: &T,
	envelope: TransportEnvelope,
	session: &SessionContext,
) -> TransportResult<(Arc<Frame>, TransitStatus)>
where
	T: MessageCollector + ?Sized,
{
	let request = envelope.into_request_frame()?;
	let status = gate_inbound(transport.collector_gate(), transport, Some(request.as_ref()), session);
	Ok((request, status))
}

/// Bidirectional transport that combines an emitter and a collector.
pub trait Transport: MessageEmitter + MessageCollector {}

impl<T> Transport for T where T: MessageEmitter + MessageCollector {}

#[cfg(all(test, feature = "transport-policy", feature = "instrument", feature = "testing"))]
mod tests {
	use super::*;
	use crate::instrumentation::events;
	use crate::policy::{GateChain, GatePolicy};
	use crate::testing::TestFrame;
	use crate::trace::TraceCollector;
	use crate::transport::policy::RestartLinearBackoff;
	use crate::utils::marker::MaybeSendFuture;
	use crate::utils::time::{Clock, MonotonicInstant, UnixMillis};
	use crate::TightBeamError;

	struct DenyGate;

	impl GatePolicy for DenyGate {
		fn evaluate(&self, _: Option<&Frame>, _: &SessionContext) -> TransitStatus {
			TransitStatus::PermissionDenied
		}
	}

	struct AuditProbe(TraceCollector);

	/// A clock that records every sleep and resolves it at once.
	#[derive(Debug, Default)]
	struct RecordingClock {
		sleeps: std::sync::Mutex<Vec<core::time::Duration>>,
	}

	impl Clock for RecordingClock {
		fn unix(&self) -> UnixMillis {
			UnixMillis::new(0)
		}

		fn monotonic(&self) -> MonotonicInstant {
			MonotonicInstant::from_std(std::time::Instant::now())
		}

		fn sleep(&self, span: core::time::Duration) -> MaybeSendFuture<'_, ()> {
			self.sleeps.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(span);
			Box::pin(core::future::ready(()))
		}
	}

	/// An emitter whose every send fails, so every attempt reaches the
	/// restart policy.
	struct FailingEmitter {
		clock: RecordingClock,
		gate: GateChain,
		restart: RestartLinearBackoff,
	}

	impl MessageIO for FailingEmitter {
		fn clock(&self) -> &dyn Clock {
			&self.clock
		}

		async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
			Err(TransportError::ConnectionClosed)
		}

		async fn write_envelope_bytes(&mut self, _buffer: &[u8]) -> TransportResult<()> {
			Ok(())
		}
	}

	impl MessageEmitter for FailingEmitter {
		type EmitterGate = GateChain;
		type RestartPolicy = RestartLinearBackoff;

		fn to_restart_policy_ref(&self) -> &RestartLinearBackoff {
			&self.restart
		}

		fn to_emitter_gate_policy_ref(&self) -> &GateChain {
			&self.gate
		}

		async fn perform_send_receive(
			&mut self,
			message: Frame,
		) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
			Err(TransportError::from_failure(message, TransportFailure::DeadlineExceeded))
		}
	}

	/// Every restart waits out its backoff on the transport's clock, so no
	/// target retries hot, and the waits follow the policy's schedule.
	#[tokio::test]
	async fn a_restart_backoff_waits_on_the_transport_clock() {
		let restart = RestartLinearBackoff::new(3, core::time::Duration::from_secs(1), 1, None);
		let mut emitter = FailingEmitter { clock: RecordingClock::default(), gate: GateChain::default(), restart };

		let outcome = emitter.emit(TestFrame::v0(None, None), None).await;
		assert!(outcome.is_err());

		let sleeps = emitter
			.clock
			.sleeps
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.clone();

		let schedule = [1, 2, 3].map(core::time::Duration::from_secs);
		assert_eq!(sleeps, schedule);
	}

	impl GateAudit for AuditProbe {
		fn audit_trace(&self) -> Option<&TraceCollector> {
			Some(&self.0)
		}
	}

	#[test]
	fn gate_verdict_records_reason_and_time() -> Result<(), TightBeamError> {
		let audit = AuditProbe(TraceCollector::new());
		let frame = TestFrame::v0(Some("gated"), None);

		let status = gate_inbound(&DenyGate, &audit, Some(&frame), &SessionContext::default());
		assert_eq!(status, TransitStatus::PermissionDenied);

		let recorded = audit.0.drain_events();
		let reject = recorded
			.iter()
			.find(|event| event.urn == events::GATE_REJECT)
			.ok_or(TightBeamError::MissingResponse)?;
		assert_eq!(reject.label.as_deref(), Some("PermissionDenied"));
		assert!(reject.timestamp_ns.is_some());
		Ok(())
	}
}
