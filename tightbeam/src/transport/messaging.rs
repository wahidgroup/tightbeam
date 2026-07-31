//! Application-facing message transmission (send/receive)

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "transport-policy"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::future::Future;

use crate::asn1::Frame;
use crate::der::Encode;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::transport::envelopes::{ResponsePackage, TransportEnvelope, WireEnvelope};
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::io::MessageIO;
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;

#[cfg(all(
	feature = "transport-policy",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::TightBeamError;

#[cfg(not(feature = "x509"))]
use crate::transport::envelopes::RequestPackage;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
mod x509 {
	pub use crate::crypto::aead::{Decryptor, KeyInit};
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
	pub use crate::crypto::sign::Verifier;
	pub use crate::der::Decode;
	pub use crate::spki::EncodePublicKey;
	pub use crate::transport::handshake::TcpHandshakeState;
	pub use crate::transport::io::EncryptedMessageIO;
	pub use crate::transport::state::EncryptedProtocolState;

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
/// record the verdict into the connection audit trail (`GATE_ACCEPT` /
/// `GATE_REJECT`).
///
/// The only gate-verdict emission point: the mux responder and the
/// cleartext and encrypted single-flight collectors all route through
/// here, so access decisions are observable evidence on every plane.
///
/// `frame` is [`None`] for mux streaming / duplex opens that have no
/// request frame at dispatch; session-scoped gates still evaluate.
///
/// A gate returning [`TransitStatus::Unknown`] is a local bug, not a
/// verdict: it is normalized to [`TransitStatus::Internal`] so the peer
/// sees a server fault and the audit trail records a reject.
#[cfg(feature = "transport-policy")]
pub(crate) fn gate_inbound<G, A>(gate: &G, audit: &A, frame: Option<&Frame>, session: &SessionContext) -> TransitStatus
where
	G: GatePolicy + ?Sized,
	A: GateAudit + ?Sized,
{
	let status = match gate.evaluate(frame, session) {
		TransitStatus::Unknown => TransitStatus::Internal,
		verdict => verdict,
	};

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
/// Helper that represents a physical letter being routed through retries.
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

/// One restart-policy evaluation over a failed send: `Ok` carries the
/// frame to resend, `Err` the terminal error. Errors without a frame
/// cannot retry and pass through unchanged.
#[cfg(feature = "transport-policy")]
fn evaluate_retry<P>(policy: &P, error: TransportError, attempt: usize) -> Result<Box<Frame>, TransportError>
where
	P: RestartPolicy + ?Sized,
{
	match error {
		TransportError::MessageNotSent(boxed_frame, ref failure) => {
			// Pass the box to policy (no unboxing, single allocation)
			match policy.evaluate(boxed_frame, failure, attempt) {
				RetryAction::Retry(_) if attempt == usize::MAX => Err(TransportError::MaxRetriesExceeded),
				RetryAction::Retry(retry_boxed_frame) => Ok(retry_boxed_frame),
				RetryAction::NoRetry => Err(TransportError::OperationFailed(*failure)),
			}
		}
		other_error => Err(other_error),
	}
}

/// Base emitter functionality
#[cfg(feature = "transport-policy")]
pub trait MessageEmitter: MessageIO {
	type EmitterGate: GatePolicy + ?Sized;
	type RestartPolicy: RestartPolicy + ?Sized;

	/// Get the restart policy instance
	fn to_restart_policy_ref(&self) -> &Self::RestartPolicy;

	/// Get the emitter gate policy instance
	fn to_emitter_gate_policy_ref(&self) -> &Self::EmitterGate;

	/// Protocol-specific send/receive operation
	///
	/// Performs the core protocol operation: send message and receive response.
	///
	/// # Returns
	/// - `status`: TransitStatus from the response
	/// - `response`: Optional response frame from server
	/// - `original`: Original frame if rejected (for retry), None if sent/consumed
	fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> impl Future<Output = TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>> + MaybeSend;

	/// Send a TightBeam message
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

	/// Default implementation for non-x509 transports
	#[cfg(not(feature = "x509"))]
	fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> impl Future<Output = TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>> + MaybeSend {
		async {
			// Build the request around a shared Arc so the frame stays available
			// for retry without pattern-matching the envelope back apart.
			let frame_arc = Arc::new(message);
			let message = Arc::clone(&frame_arc);
			let envelope = TransportEnvelope::Request(RequestPackage { message });

			// Send the envelope
			self.write_envelope_bytes(&envelope.to_der()?).await?;

			// Receive response
			let response_bytes = self.read_envelope_bytes().await?;
			let response_envelope = Self::decode_envelope(&response_bytes)?;

			// Parse response
			let (status, response) = match response_envelope {
				TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
				TransportEnvelope::Request(_) => {
					return Err(TransportError::InvalidMessage);
				}
				#[cfg(any(feature = "x509", feature = "transport-multiplex"))]
				_ => {
					return Err(TransportError::InvalidMessage);
				}
			};

			// Return frame if rejected
			let original = if status != TransitStatus::Ok {
				Some(Arc::try_unwrap(frame_arc).unwrap_or_else(|arc| (*arc).clone()))
			} else {
				None
			};

			Ok((
				status,
				response.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone())),
				original,
			))
		}
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
		// Evaluate gate policy before sending. Emitter gates are
		// client-side and connection-context-free: the empty context.
		let status = emitter
			.to_emitter_gate_policy_ref()
			.evaluate(Some(letter.try_peek()?), &SessionContext::default());
		if status != TransitStatus::Ok {
			return Err(TransportError::from(status));
		}

		// Take message for send operation
		let message_to_send = letter.try_take()?;

		// Perform protocol-specific send/receive
		let (status, response, original_message) = match emitter.perform_send_receive(message_to_send).await {
			Ok(result) => result,
			Err(e) => {
				let frame = evaluate_retry(emitter.to_restart_policy_ref(), e, current_attempt)?;
				// Unbox to put back into Letter
				letter.try_return_to_sender(*frame)?;
				current_attempt += 1;
				continue;
			}
		};

		// Check transport status and handle response
		let result: TransportResult<&Frame> = if status != TransitStatus::Ok {
			if let Some(msg) = original_message {
				// Server rejected - return frame for retry
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

		// Evaluate retry policy only on error
		match result {
			Err(error) => {
				let frame = evaluate_retry(emitter.to_restart_policy_ref(), error, current_attempt)?;
				// Unbox to put back into Letter
				letter.try_return_to_sender(*frame)?;
				current_attempt += 1;
			}
			Ok(_) => {
				return Ok(response);
			}
		}
	}
}

/// Extract the application request frame from a single-flight envelope.
fn single_flight_frame(envelope: TransportEnvelope) -> TransportResult<Arc<Frame>> {
	match envelope {
		TransportEnvelope::Request(msg) => Ok(msg.message),
		TransportEnvelope::Response(_) => Err(TransportError::InvalidMessage),
		#[cfg(feature = "x509")]
		TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => Err(TransportError::InvalidMessage),
		#[cfg(feature = "transport-multiplex")]
		TransportEnvelope::Mux(_) => Err(TransportError::InvalidMessage),
	}
}

/// Write a single-flight response envelope, shared by both
/// `MessageCollector` cfg twins. With `x509` the response wraps in a
/// [`WireEnvelope`] for protocol compatibility.
async fn send_single_flight_response<T>(
	transport: &mut T,
	status: TransitStatus,
	message: Option<Frame>,
) -> TransportResult<()>
where
	T: MessageIO + MaybeSend + ?Sized,
{
	let response_pkg = ResponsePackage { status, message: message.map(Arc::new) };
	let response_envelope = TransportEnvelope::from(response_pkg);

	#[cfg(feature = "x509")]
	let response_bytes = WireEnvelope::Cleartext(response_envelope).to_der()?;
	#[cfg(not(feature = "x509"))]
	let response_bytes = T::encode_envelope(&response_envelope)?;

	transport.write_envelope_bytes(&response_bytes).await
}

/// Everything a message collector must already be.
///
/// Exists because supertraits cannot be feature-gated inline: with
/// `transport-policy` every collector must also expose an audit trail
/// ([`GateAudit`]) for gate-verdict recording. The blanket impl satisfies
/// the requirement automatically; implementers never name this trait.
#[cfg(feature = "transport-policy")]
pub trait CollectorRequirements: MessageIO + GateAudit {}

#[cfg(feature = "transport-policy")]
impl<T: MessageIO + GateAudit> CollectorRequirements for T {}

/// Everything a message collector must already be (no audit trail
/// requirement without `transport-policy`).
#[cfg(not(feature = "transport-policy"))]
pub trait CollectorRequirements: MessageIO {}

#[cfg(not(feature = "transport-policy"))]
impl<T: MessageIO> CollectorRequirements for T {}

/// Message collector trait - receives TightBeam messages
pub trait MessageCollector: CollectorRequirements {
	/// Gate policy consulted for every collected message.
	#[cfg(feature = "transport-policy")]
	type CollectorGate: GatePolicy + ?Sized;

	/// Get the collector gate policy instance
	#[cfg(feature = "transport-policy")]
	fn collector_gate(&self) -> &Self::CollectorGate;

	/// Read and validate a message without sending a response
	/// Returns the message and the gate evaluation status
	#[cfg(feature = "transport-policy")]
	fn collect_message(&mut self) -> impl Future<Output = TransportResult<(Arc<Frame>, TransitStatus)>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// Read and decode the envelope (can be overridden for encryption)
			let decoded_envelope = self.read_decoded_envelope().await?;
			// Cleartext connections authenticate nothing: empty context.
			let session = SessionContext::default();
			gate_collected_envelope(self, decoded_envelope, &session)
		}
	}

	/// Read and validate a message without sending a response
	/// Returns the message (status is always Ok without policies)
	#[cfg(not(feature = "transport-policy"))]
	fn collect_message(&mut self) -> impl Future<Output = TransportResult<(Arc<Frame>, TransitStatus)>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			let request_envelope = self.read_decoded_envelope().await?;
			let request = single_flight_frame(request_envelope)?;

			Ok((request, TransitStatus::Ok))
		}
	}

	/// Try to collect next message without blocking on closed connections
	///
	/// Returns Ok(None) if connection closed gracefully (EOF).
	/// Returns Err if connection failed unexpectedly.
	#[cfg(feature = "transport-policy")]
	fn try_collect_message(
		&mut self,
	) -> impl Future<Output = TransportResult<Option<(Arc<Frame>, TransitStatus)>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// Try to read envelope (returns None on graceful close)
			let decoded_envelope = match self.try_read_decoded_envelope().await? {
				Some(envelope) => envelope,
				None => return Ok(None), // Connection closed gracefully
			};

			// Cleartext connections authenticate nothing: empty context.
			let session = SessionContext::default();
			let gated = gate_collected_envelope(self, decoded_envelope, &session)?;
			Ok(Some(gated))
		}
	}

	/// Try to collect next message without blocking on closed connections
	///
	/// Returns Ok(None) if connection closed gracefully (EOF).
	/// Returns Err if connection failed unexpectedly.
	#[cfg(not(feature = "transport-policy"))]
	fn try_collect_message(
		&mut self,
	) -> impl Future<Output = TransportResult<Option<(Arc<Frame>, TransitStatus)>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// Try to read envelope (returns None on graceful close)
			let request_envelope = match self.try_read_decoded_envelope().await? {
				Some(envelope) => envelope,
				None => return Ok(None), // Connection closed gracefully
			};

			let request = single_flight_frame(request_envelope)?;
			Ok(Some((request, TransitStatus::Ok)))
		}
	}

	/// Send a response for a previously collected message
	fn send_response(
		&mut self,
		status: TransitStatus,
		message: Option<Frame>,
	) -> impl Future<Output = TransportResult<()>> + MaybeSend
	where
		Self: MaybeSend,
	{
		send_single_flight_response(self, status, message)
	}

	/// X509-enabled collect_message with encryption and handshake support
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn collect_message_with_encryption<P>(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)>
	where
		Self: EncryptedMessageIO + Sized + EncryptedProtocolState<CryptoProvider = P>,
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
				CollectStep::Handshake(handshake_bytes) => self.perform_server_handshake(&handshake_bytes).await?,
				CollectStep::Envelope(envelope) => {
					let session = SessionContext::capture(self);
					return gate_collected_envelope(self, envelope, &session);
				}
			}
		}
	}

	/// X509-enabled collect_message with encryption and handshake support
	/// (CMS-only build variant).
	///
	/// Trait where-clauses do not elaborate to callers, so the method is
	/// declared per feature combination with that build's predicate set.
	#[cfg(all(
		feature = "transport-policy",
		not(feature = "transport-ecies"),
		feature = "transport-cms"
	))]
	#[allow(async_fn_in_trait)]
	async fn collect_message_with_encryption<P>(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)>
	where
		Self: EncryptedMessageIO + Sized + EncryptedProtocolState<CryptoProvider = P>,
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
				CollectStep::Handshake(handshake_bytes) => self.perform_server_handshake(&handshake_bytes).await?,
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
	/// Cleartext handshake container to feed the server-side dispatcher.
	Handshake(Vec<u8>),
	/// Decrypted (or legitimately cleartext) application envelope.
	Envelope(TransportEnvelope),
}

/// Read one wire envelope, enforce size ceilings, and classify it.
///
/// Protocol-agnostic: handshake containers are surfaced as raw bytes for the
/// caller's dispatcher, everything else is decrypted and returned.
#[cfg(all(
	feature = "transport-policy",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) async fn collect_step<T>(transport: &mut T) -> TransportResult<CollectStep>
where
	T: EncryptedMessageIO + EncryptedProtocolState + Sized,
{
	// Read wire envelope
	// Enforce size ceilings
	let wire_bytes = transport.read_envelope_bytes().await?;
	let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
	match &wire_envelope {
		WireEnvelope::Cleartext(_) => {
			if let Some(max) = transport.to_max_cleartext_envelope() {
				if wire_bytes.len() > max {
					return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
				}
			}
		}
		WireEnvelope::Encrypted(_) => {
			if let Some(max) = transport.to_max_encrypted_envelope() {
				if wire_bytes.len() > max {
					return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
				}
			}
		}
	}

	let has_certificate = transport.to_server_certificate_ref().is_some();
	match wire_envelope {
		WireEnvelope::Cleartext(envelope) => {
			if has_certificate {
				match envelope {
					TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
						Ok(CollectStep::Handshake(envelope.to_der()?))
					}
					// Circuit breaker: application traffic must never arrive
					// cleartext once encryption is configured.
					_ => {
						transport.set_handshake_state(TcpHandshakeState::None);
						transport.unset_session_keys();
						Err(TransportError::MissingEncryption)
					}
				}
			} else {
				Ok(CollectStep::Envelope(envelope))
			}
		}
		WireEnvelope::Encrypted(encrypted_info) => {
			if transport.to_handshake_state() != TcpHandshakeState::Complete {
				transport.set_handshake_state(TcpHandshakeState::None);
				transport.unset_session_keys();
				return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
			}

			let decrypted_bytes = match transport.to_decryptor_ref()?.decrypt_content(&encrypted_info) {
				Ok(bytes) => bytes,
				Err(_) => {
					transport.set_handshake_state(TcpHandshakeState::None);
					transport.unset_session_keys();
					return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
				}
			};

			let envelope = decrypted_bytes
				.with(|bytes| T::decode_envelope(bytes))
				.map_err(TightBeamError::from)??;

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
	let request = single_flight_frame(envelope)?;
	let status = gate_inbound(transport.collector_gate(), transport, Some(request.as_ref()), session);

	Ok((request, status))
}

/// Bidirectional transport combines emitter and collector
pub trait Transport: MessageEmitter + MessageCollector {}

impl<T> Transport for T where T: MessageEmitter + MessageCollector {}

#[cfg(all(test, feature = "transport-policy", feature = "instrument", feature = "testing"))]
mod tests {
	use super::*;
	use crate::instrumentation::events;
	use crate::policy::GatePolicy;
	use crate::testing::create_v0_tightbeam;
	use crate::trace::TraceCollector;
	use crate::TightBeamError;

	struct DenyGate;

	impl GatePolicy for DenyGate {
		fn evaluate(&self, _: Option<&Frame>, _: &SessionContext) -> TransitStatus {
			TransitStatus::PermissionDenied
		}
	}

	struct AuditProbe(TraceCollector);

	impl GateAudit for AuditProbe {
		fn audit_trace(&self) -> Option<&TraceCollector> {
			Some(&self.0)
		}
	}

	#[test]
	fn gate_verdict_records_reason_and_time() -> Result<(), TightBeamError> {
		let audit = AuditProbe(TraceCollector::new());
		let frame = create_v0_tightbeam(Some("gated"), None);

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
