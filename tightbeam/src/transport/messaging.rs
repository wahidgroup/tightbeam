//! The traits that send and receive application frames.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use core::future::Future;

use crate::asn1::Frame;
use crate::error::TightBeamError;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::transport::envelopes::TransportEnvelope;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::io::MessageIO;
use crate::transport::policy::{RestartPolicy, RetryAction};
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::state::CollectStep;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod x509 {
	pub use crate::transport::handshake::HandshakeProvider;
	pub use crate::transport::io::EncryptedMessageIO;
	pub use crate::transport::state::{EncryptedProtocolState, ServerHandshakeSlot};
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use x509::*;

#[cfg(feature = "instrument")]
use crate::crypto::x509::CanonicalKey;
#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::{InternalEvent, TraceCollector};

/// The source of the connection audit trail for access-gate verdicts.
///
/// Every plane that evaluates a collector gate implements this, such as the
/// TCP transports and the mux handle, so `gate_inbound` can record the verdict
/// wherever the gate runs.
pub trait GateAudit {
	/// Returns the connection audit trail when instrumentation is attached.
	#[cfg(feature = "instrument")]
	fn audit_trace(&self) -> Option<&TraceCollector>;
}

/// The gate verdict every [`GateAudit`] plane records.
///
/// The trait is a crate-private extension, so the public [`GateAudit`] keeps
/// its one method and stays usable as a trait object.
pub(crate) trait GateInbound: GateAudit {
	/// Gates one inbound request with the session's authenticated context and
	/// records the verdict into the connection audit trail (`GATE_ACCEPT` or
	/// `GATE_REJECT`).
	///
	/// # Emission point
	///
	/// This is the only gate-verdict emission point. The mux responder and the
	/// cleartext and encrypted single-flight collectors all route through here,
	/// so access decisions are observable evidence on every plane. When the
	/// trace config sets `enable_internal_detail`, the internal event
	/// `POLICY_EVAL` marks the evaluation ahead of its verdict.
	///
	/// # Verdicts
	///
	/// - `frame` is [`None`] for a mux streaming or duplex open that has no
	///   request frame at dispatch. Session-scoped gates judge it too.
	/// - A gate that returns [`TransitStatus::Unknown`] signals a local bug, so
	///   [`TransitStatus::normalized_verdict`] maps it to
	///   [`TransitStatus::Internal`] and the peer sees a server fault.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at
	///   the event of the evaluation or the verdict.
	fn gate_inbound<G>(
		&self,
		gate: &G,
		frame: Option<&Frame>,
		session: &SessionContext,
	) -> Result<TransitStatus, TightBeamError>
	where
		G: GatePolicy + ?Sized,
	{
		let status = gate.evaluate(frame, session).normalized_verdict();

		#[cfg(feature = "instrument")]
		if let Some(trace) = self.audit_trace() {
			trace.emit_internal_event(InternalEvent::PolicyEval)?;

			let event = if status == TransitStatus::Ok {
				events::GATE_ACCEPT
			} else {
				events::GATE_REJECT
			};

			// As evidence, the status names why and the canonical form of the
			// peer's key names who, so one peer leaves one audit identity in
			// either SEC 1 form of its key. The status is also the value that a
			// spec asserts.
			let peer = session.peer_key().map(CanonicalKey::as_der);
			trace.emit_event_with_value_and_evidence(event, status.as_str(), status, peer)?;
		}

		Ok(status)
	}
}

impl<A: GateAudit + ?Sized> GateInbound for A {}

/// What one call that a plane admitted came to, as
/// [`HandlerAudit::run_handler`] names it from the result of the handler and
/// from the span around it.
#[cfg(feature = "std")]
#[derive(Debug)]
pub(crate) enum HandlerOutcome<T> {
	/// The handler ran and answered with its value.
	Answered(T),
	/// The handler ran and failed with its own error.
	Failed(TightBeamError),
	/// The handler is the default of a kind or an operation that its service
	/// leaves out, which refuses the call with [`TransportError::NotServed`].
	NotServed,
	/// The trace injected a fault at the entry of the handler, which stopped
	/// the handler before it ran, or at the exit of a handler that answered.
	Faulted(TightBeamError),
}

#[cfg(feature = "std")]
impl<T> HandlerOutcome<T> {
	/// The outcome of a handler that returned `outcome`, in a span whose exit
	/// record returned `exited`.
	///
	/// The error of a handler comes first, so a fault the trace injects at
	/// the exit leaves it in place.
	pub(crate) fn of(outcome: Result<T, TightBeamError>, exited: Result<(), TightBeamError>) -> Self {
		match (outcome, exited) {
			(Err(error), _) if error.is_not_served() => Self::NotServed,
			(Err(error), _) => Self::Failed(error),
			(Ok(_), Err(fault)) => Self::Faulted(fault),
			(Ok(value), Ok(())) => Self::Answered(value),
		}
	}

	/// Settles this outcome on a stream of `plane`: the status that the
	/// stream reads, beside the value of an answered call. A failed handler
	/// records its failure on the trail of `plane`, with the status that the
	/// failure carries.
	///
	/// # Errors
	///
	/// - [`TransportError::NotServed`] -- the service leaves out the kind of
	///   the stream, which the responder records and answers.
	/// - The injected error, when the runtime fault model injects a fault at the record of a failure.
	#[cfg(pooled_mux)]
	pub(crate) fn settle_stream(
		self,
		plane: &(impl HandlerAudit + ?Sized),
	) -> TransportResult<(TransitStatus, Option<T>)> {
		match self {
			Self::Answered(value) => Ok((TransitStatus::Ok, Some(value))),
			Self::Failed(error) => {
				let status = error.failure_status();
				plane.audit_failure(status)?;

				Ok((status, None))
			}
			Self::NotServed => Err(TransportError::NotServed),
			Self::Faulted(fault) => Ok((fault.failure_status(), None)),
		}
	}
}

/// The handler span, and the answer of a failed handler, that every
/// [`GateAudit`] plane records.
///
/// The mux planes and the single-flight turn of the async and the blocking
/// `server!` run each admitted handler through it. The trait is a
/// crate-private extension, as [`GateInbound`] is.
#[cfg(feature = "std")]
pub(crate) trait HandlerAudit: GateAudit {
	/// Runs `handler`, the application handler of one call that this plane
	/// admitted, between the internal events `HANDLER_ENTER` and
	/// `HANDLER_EXIT` of the plane's audit trail, and names what the call came
	/// to.
	///
	/// The returned future borrows the trail alone. A fault the trace injects
	/// at the entry stops `handler` before it runs.
	fn run_handler<'a, T, F>(&'a self, handler: F) -> impl Future<Output = HandlerOutcome<T>> + MaybeSend + 'a
	where
		F: Future<Output = Result<T, TightBeamError>> + MaybeSend + 'a,
	{
		#[cfg(feature = "instrument")]
		let trace = self.audit_trace();

		async move {
			#[cfg(feature = "instrument")]
			if let Some(trace) = trace {
				if let Err(fault) = trace.emit_internal_event(InternalEvent::HandlerEnter) {
					return HandlerOutcome::Faulted(fault);
				}
			}

			let outcome = handler.await;

			#[cfg(feature = "instrument")]
			let exited = trace.map_or(Ok(()), |trace| trace.emit_internal_event(InternalEvent::HandlerExit));
			#[cfg(not(feature = "instrument"))]
			let exited = Ok(());

			HandlerOutcome::of(outcome, exited)
		}
	}

	/// Records `status`, the answer of a call whose handler failed with an
	/// error of its own, on the plane's audit trail as `HANDLER_FAILED`.
	///
	/// A plane calls it for [`HandlerOutcome::Failed`] alone, at the step
	/// where it maps the failure to the answer.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	fn audit_failure(&self, status: TransitStatus) -> Result<(), TightBeamError> {
		#[cfg(feature = "instrument")]
		if let Some(trace) = self.audit_trace() {
			trace.emit_event_with_value(events::HANDLER_FAILED, status.as_str(), status)?;
		}

		#[cfg(not(feature = "instrument"))]
		let _ = status;

		Ok(())
	}
}

#[cfg(feature = "std")]
impl<A: GateAudit + ?Sized> HandlerAudit for A {}

/// The acceptance of a connection that a server records.
///
/// The service of an accepted connection records it once, ahead of the
/// negotiation of multiplexing. The trait is a crate-private extension, as
/// [`GateInbound`] is.
#[cfg(feature = "tokio")]
pub(crate) trait ConnectionAudit: GateAudit + crate::transport::state::EncryptedProtocolState {
	/// Records the acceptance of this connection on its audit trail, as
	/// `CONNECTION_ACCEPTED`, with the address that the listener accepted the
	/// connection from as its evidence.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	fn audit_accepted(&self) -> Result<(), TightBeamError> {
		#[cfg(feature = "instrument")]
		if let Some(trace) = self.audit_trace() {
			let peer = self.accepted_from();
			let evidence = || peer.map(|peer| peer.to_string());
			trace.emit_event_with_rendered_evidence(events::CONNECTION_ACCEPTED, evidence)?;
		}

		Ok(())
	}
}

#[cfg(feature = "tokio")]
impl<A: GateAudit + crate::transport::state::EncryptedProtocolState> ConnectionAudit for A {}

#[derive(Debug)]
/// A frame routed through retries, modeled on a physical letter that can
/// return to its sender.
pub(crate) struct Letter {
	frame: Option<Frame>,
}

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

impl From<Frame> for Letter {
	fn from(frame: Frame) -> Self {
		Self::new(frame)
	}
}

/// Runs one restart-policy evaluation over a failed send.
///
/// - `Ok` carries the frame to resend and the delay to observe first.
/// - `Err` carries the terminal error.
///
/// An error that carries no frame passes through unchanged, and so does a
/// failure that spends its session, ahead of the policy, because a resend on
/// that session can never succeed. The frame then goes back unsent.
fn evaluate_retry<P>(
	policy: &P,
	error: TransportError,
	attempt: usize,
) -> Result<(Box<Frame>, core::time::Duration), TransportError>
where
	P: RestartPolicy + ?Sized,
{
	match error {
		TransportError::MessageNotSent(_, failure) if failure.spends_the_session() => Err(error),
		TransportError::MessageNotSent(boxed_frame, ref failure) => {
			// The policy takes the box, so the frame stays in its single
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

/// The base emitter trait, which sends TightBeam messages with gate and
/// restart policies.
pub trait MessageEmitter: MessageIO {
	/// The gate policy that every outbound message passes before a send.
	type EmitterGate: GatePolicy + ?Sized;
	/// The restart policy that decides whether a failed send goes out again.
	type RestartPolicy: RestartPolicy + ?Sized;

	/// The restart policy that [`Self::emit`] consults after a failed send.
	fn to_restart_policy_ref(&self) -> &Self::RestartPolicy;

	/// The gate policy that [`Self::emit`] evaluates before each send.
	fn to_emitter_gate_policy_ref(&self) -> &Self::EmitterGate;

	/// Runs the protocol-specific send and receive operation.
	///
	/// # Returns
	///
	/// - `status`: the [`TransitStatus`] of the response.
	/// - `response`: the optional response frame from the server.
	/// - `original`: the original frame when the server rejected it, for a
	///   retry, or `None` when the server accepted the frame or the send
	///   consumed it.
	fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> impl Future<Output = TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>> + MaybeSend;

	/// Sends a TightBeam message through the emitter gate, and retries a failed
	/// send as the restart policy decides.
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

/// Runs the default [`MessageEmitter::emit`] body. It is a free function, so
/// the returned future can carry [`MaybeSend`] without the capture of an AFIT
/// default method.
async fn emit_with_retry<T: MessageEmitter + MaybeSend + ?Sized>(
	emitter: &mut T,
	message: Frame,
	attempt: Option<usize>,
) -> TransportResult<Option<Frame>> {
	let mut letter = Letter::from(message);
	let mut current_attempt = attempt.unwrap_or(0);

	loop {
		// Emitter gates are client-side and need no connection context, so they
		// get the empty context.
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

				letter.try_return_to_sender(*frame)?;
				current_attempt = current_attempt.saturating_add(1);
				continue;
			}
		};

		let result: TransportResult<&Frame> = if status != TransitStatus::Ok {
			if let Some(msg) = original_message {
				// The server rejected the frame, so it goes back for a retry.
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

		match result {
			Err(error) => {
				let (frame, delay) = evaluate_retry(emitter.to_restart_policy_ref(), error, current_attempt)?;
				emitter.clock().sleep(delay).await;
				letter.try_return_to_sender(*frame)?;
				current_attempt = current_attempt.saturating_add(1);
			}
			Ok(_) => {
				return Ok(response);
			}
		}
	}
}

/// The message collector trait, which receives TightBeam messages.
///
/// Every collector is a [`GateAudit`] plane, so its audit trail records each
/// gate verdict.
///
/// # Examples
///
/// ```
/// use tightbeam::policy::TransitStatus;
/// use tightbeam::transport::{MessageCollector, TransportResult};
///
/// /// Read one message, and whether the gate of the collector admitted it.
/// async fn admitted<C: MessageCollector + Send>(collector: &mut C) -> TransportResult<bool> {
///     let (_frame, status) = collector.collect_message().await?;
///     Ok(status == TransitStatus::Ok)
/// }
/// ```
pub trait MessageCollector: MessageIO + GateAudit {
	/// The gate policy that the collector consults for every collected
	/// message.
	type CollectorGate: GatePolicy + ?Sized;

	/// The gate policy that every collected message passes through.
	fn collector_gate(&self) -> &Self::CollectorGate;

	/// Reads and validates one message, and returns it with the status of its
	/// gate evaluation. The caller sends the response.
	fn collect_message(&mut self) -> impl Future<Output = TransportResult<(Arc<Frame>, TransitStatus)>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			// An encrypted transport overrides this read.
			let decoded_envelope = self.read_decoded_envelope().await?;
			// A cleartext connection carries no peer identity, so it gets the
			// empty context.
			let session = SessionContext::default();
			gate_collected_envelope(self, decoded_envelope, &session)
		}
	}

	/// Collects the next message, and tells a close at EOF from an error.
	///
	/// - `Ok(None)` means that the connection closed at EOF.
	/// - `Err` means that the connection failed unexpectedly.
	fn try_collect_message(
		&mut self,
	) -> impl Future<Output = TransportResult<Option<(Arc<Frame>, TransitStatus)>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			let decoded_envelope = match self.try_read_decoded_envelope().await? {
				Some(envelope) => envelope,
				None => return Ok(None), // The connection closed at EOF.
			};

			// A cleartext connection carries no peer identity, so it gets the
			// empty context.
			let session = SessionContext::default();
			let gated = gate_collected_envelope(self, decoded_envelope, &session)?;
			Ok(Some(gated))
		}
	}

	/// Sends a response for one collected message, in the wire mode the session
	/// phase decides.
	fn send_response(
		&mut self,
		status: TransitStatus,
		message: Option<Frame>,
	) -> impl Future<Output = TransportResult<()>> + MaybeSend
	where
		Self: MaybeSend;

	/// The X.509 form of [`Self::collect_message`] over an encrypted session,
	/// which serves each handshake request that arrives before the message.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn collect_message_with_encryption<P>(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)>
	where
		Self: EncryptedMessageIO + Sized + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: HandshakeProvider,
	{
		// A session that can answer no request collects none, so a request on
		// its way never reaches a handler.
		if self.session_state().phase().is_spent() {
			return Err(TransportError::OperationFailed(TransportFailure::RekeyRequired));
		}

		loop {
			match self.collect_step().await? {
				CollectStep::Handshake(request) => self.perform_server_handshake(request).await?,
				CollectStep::Envelope(envelope) => {
					let session = SessionContext::capture(self);
					return gate_collected_envelope(self, envelope, &session);
				}
			}
		}
	}
}

/// Extracts the application request from a collected envelope and gates it
/// with the session's peer context. [`GateInbound::gate_inbound`] records the
/// verdict.
fn gate_collected_envelope<T>(
	transport: &T,
	envelope: TransportEnvelope,
	session: &SessionContext,
) -> TransportResult<(Arc<Frame>, TransitStatus)>
where
	T: MessageCollector + ?Sized,
{
	let request = envelope.into_request_frame()?;
	let status = transport.gate_inbound(transport.collector_gate(), Some(request.as_ref()), session)?;
	Ok((request, status))
}

/// A bidirectional transport that combines an emitter and a collector.
pub trait Transport: MessageEmitter + MessageCollector {}

impl<T> Transport for T where T: MessageEmitter + MessageCollector {}

#[cfg(all(test, feature = "instrument", feature = "testing"))]
mod tests {
	use super::*;
	use crate::instrumentation::events;
	use crate::policy::{GateChain, GatePolicy};
	use crate::testing::TestFrame;
	use crate::trace::{AssertionLabel, AssertionValue, TraceCollector};
	use crate::transport::policy::RestartLinearBackoff;
	use crate::urn::Urn;
	use crate::utils::marker::MaybeSendFuture;
	use crate::utils::time::{Clock, MonotonicInstant, UnixMillis};
	use crate::TightBeamError;

	#[cfg(feature = "testing-fault")]
	use crate::testing::fdr::FaultModel;

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

	/// An emitter whose every send fails with `failure`, so every attempt
	/// reaches the restart policy.
	struct FailingEmitter {
		clock: RecordingClock,
		gate: GateChain,
		restart: RestartLinearBackoff,
		failure: TransportFailure,
	}

	impl FailingEmitter {
		/// An emitter that fails each send with `failure`, under three
		/// restarts a second apart and a second more each time.
		fn failing_with(failure: TransportFailure) -> Self {
			let restart = RestartLinearBackoff::new(3, core::time::Duration::from_secs(1), 1, None);
			Self { clock: RecordingClock::default(), gate: GateChain::default(), restart, failure }
		}

		/// The waits the emitter slept through, in order.
		fn sleeps(&self) -> Vec<core::time::Duration> {
			let sleeps = self.clock.sleeps.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
			sleeps.clone()
		}
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
			Err(TransportError::from_failure(message, self.failure))
		}
	}

	/// Every restart waits out its backoff on the transport's clock, so no
	/// target retries hot, and the waits follow the policy's schedule.
	#[tokio::test]
	async fn a_restart_backoff_waits_on_the_transport_clock() {
		let mut emitter = FailingEmitter::failing_with(TransportFailure::DeadlineExceeded);

		let outcome = emitter.emit(TestFrame::v0(None, None), None).await;
		assert!(outcome.is_err());

		let schedule = [1, 2, 3].map(core::time::Duration::from_secs);
		assert_eq!(emitter.sleeps(), schedule);
	}

	/// A send refused at the record limit is not resent on its session, which
	/// can never send again, so the frame goes back unsent at once.
	#[tokio::test]
	async fn a_send_at_the_record_limit_is_not_resent() {
		let mut emitter = FailingEmitter::failing_with(TransportFailure::RekeyRequired);

		let outcome = emitter.emit(TestFrame::v0(None, None), None).await;
		let unsent = matches!(outcome, Err(TransportError::MessageNotSent(_, TransportFailure::RekeyRequired)));
		assert_eq!((unsent, emitter.sleeps()), (true, Vec::new()));
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

		let status = audit.gate_inbound(&DenyGate, Some(&frame), &SessionContext::default())?;
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

	/// A fault the trace injects at the event of a verdict fails the gate, so
	/// the collector that gates the request fails with it.
	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_fault_at_the_verdict_fails_the_gate() {
		let fault = || TightBeamError::ChannelClosed;
		let model = FaultModel::default().with_event_fault(events::GATE_REJECT, fault, crate::bps!(10000));
		let audit = AuditProbe(TraceCollector::new().with_fault_model(model));
		let frame = TestFrame::v0(Some("gated"), None);

		let refused = audit.gate_inbound(&DenyGate, Some(&frame), &SessionContext::default());
		assert!(matches!(refused, Err(TightBeamError::ChannelClosed)));
	}

	/// The values that `trace` recorded for `event`, in the order it recorded
	/// them.
	fn recorded_values(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<AssertionValue>> {
		let label = AssertionLabel::Custom(event.to_string().into());
		let recorded = trace.drain_assertions();
		recorded
			.into_iter()
			.filter(|record| record.label == label)
			.map(|record| record.value)
			.collect()
	}

	/// A gate verdict records its normalized status as the value that a spec
	/// asserts.
	#[test]
	fn a_gate_verdict_records_its_status_as_its_value() -> Result<(), TightBeamError> {
		let audit = AuditProbe(TraceCollector::new());
		audit.gate_inbound(&DenyGate, None, &SessionContext::default())?;

		let denied = Some(AssertionValue::from(TransitStatus::PermissionDenied));
		assert_eq!(recorded_values(&audit.0, events::GATE_REJECT), [denied]);
		Ok(())
	}

	/// A plane records the answer of a failed handler as `HANDLER_FAILED`,
	/// with the status that the call answers as its value.
	#[test]
	fn a_failed_handler_records_the_status_it_answers() -> Result<(), TightBeamError> {
		let audit = AuditProbe(TraceCollector::new());
		audit.audit_failure(TransitStatus::PermissionDenied)?;

		let denied = Some(AssertionValue::from(TransitStatus::PermissionDenied));
		assert_eq!(recorded_values(&audit.0, events::HANDLER_FAILED), [denied]);
		Ok(())
	}

	/// The outcome of a handler, the record of its exit, and the name of the
	/// outcome that the two make.
	type OutcomeCase = (Result<(), TightBeamError>, Result<(), TightBeamError>, &'static str);

	/// The name of the variant of `outcome`.
	fn outcome_name(outcome: &HandlerOutcome<()>) -> &'static str {
		match outcome {
			HandlerOutcome::Answered(()) => "answered",
			HandlerOutcome::Failed(_) => "failed",
			HandlerOutcome::NotServed => "not-served",
			HandlerOutcome::Faulted(_) => "faulted",
		}
	}

	// A call comes to what its handler returned, and the error of a handler
	// comes ahead of a fault at its exit. A default that refuses its kind is
	// no failure of a handler.
	crate::tb_cases! {
		fn a_call_comes_to_what_its_handler_returned((outcome, exited, expected): OutcomeCase) {
			let settled = HandlerOutcome::of(outcome, exited);
			assert_eq!(outcome_name(&settled), expected);
		}
		cases {
			answered => (Ok(()), Ok(()), "answered"),
			failed => (Err(TightBeamError::MissingResponse), Ok(()), "failed"),
			failed_ahead_of_a_fault_at_its_exit => (
				Err(TightBeamError::MissingResponse),
				Err(TightBeamError::ChannelClosed),
				"failed",
			),
			not_served => (Err(TransportError::NotServed.into()), Ok(()), "not-served"),
			faulted_at_its_exit => (Ok(()), Err(TightBeamError::ChannelClosed), "faulted"),
			unimplemented_of_its_own => (Err(TransportError::from(TransitStatus::Unimplemented).into()), Ok(()), "failed"),
		}
	}

	/// The evidence a gate verdict records of its peer, read from a session
	/// that `SessionContext::for_peer` binds to a certificate.
	#[cfg(feature = "colony")]
	mod evidence {
		use super::*;
		use crate::crypto::hash::{Digest, Sha3_256};
		use crate::instrumentation::TbInstrumentationConfig;
		use crate::testing::{TestCertificate, TestKey};
		use crate::trace::TraceConfig;

		/// The SHA3-256 digest of the evidence that a gate refusal of
		/// `session` records, under a collector that records the digest of
		/// every evidence payload.
		fn rejection_evidence(session: &SessionContext) -> Option<[u8; 32]> {
			let config = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
			let audit = AuditProbe(TraceCollector::from(TraceConfig::with_instrumentation(config)));
			let verdict = audit.gate_inbound(&DenyGate, None, session);
			assert!(verdict.is_ok(), "a collector with no fault model records the verdict");

			let recorded = audit.0.drain_events();
			let reject = recorded.iter().find(|event| event.urn == events::GATE_REJECT);
			reject.and_then(|event| event.payload_hash)
		}

		/// The audit evidence of a gate verdict names the peer by the canonical
		/// form of its key, so a peer whose certificate holds an uncompressed
		/// point leaves the identity of its compressed form.
		#[test]
		fn gate_evidence_names_the_peer_by_its_canonical_key() -> Result<(), Box<dyn std::error::Error>> {
			let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
			let canonical = CanonicalKey::of(&certificate.tbs_certificate.subject_public_key_info)?;

			let expected: [u8; 32] = Sha3_256::digest(canonical.as_der()).into();
			let session = SessionContext::for_peer(Arc::new(certificate));
			assert_eq!(rejection_evidence(&session), Some(expected));
			Ok(())
		}
	}

	/// The internal events that a gate plane records under the detail flag of
	/// its trace config.
	mod internal_detail {
		use super::*;
		use crate::testing::fixtures::TestTrace;
		use crate::urn::Urn;

		#[cfg(all(feature = "testing-fault", feature = "tokio"))]
		use core::sync::atomic::{AtomicBool, Ordering};

		/// A probe whose trace config sets `enable_internal_detail` to
		/// `detail`.
		fn probe_with_detail(detail: bool) -> AuditProbe {
			AuditProbe(TestTrace::with_detail(detail))
		}

		/// The URNs of the policy steps and the verdicts that one refused gate
		/// evaluation records, in order, under the detail flag `detail`.
		fn gate_trail(detail: bool) -> Result<Vec<Urn<'static>>, TightBeamError> {
			let audit = probe_with_detail(detail);
			audit.gate_inbound(&DenyGate, None, &SessionContext::default())?;

			Ok(TestTrace::trail(&audit.0, &[events::POLICY_EVAL, events::GATE_REJECT]))
		}

		/// A gate evaluation records its policy step ahead of its verdict when
		/// the trace config sets the detail flag, and its verdict alone when
		/// the config clears it.
		#[test]
		fn a_gate_records_its_policy_step_under_the_detail_flag_alone() -> Result<(), TightBeamError> {
			let detailed = vec![events::POLICY_EVAL, events::GATE_REJECT];
			assert_eq!([gate_trail(true)?, gate_trail(false)?], [detailed, vec![events::GATE_REJECT]]);
			Ok(())
		}

		/// A probe whose trace records the internal events and injects
		/// [`TightBeamError::ChannelClosed`] at every record of `event`.
		#[cfg(feature = "testing-fault")]
		fn probe_faulting_at(event: Urn<'static>) -> AuditProbe {
			let fault = || TightBeamError::ChannelClosed;
			let model = FaultModel::default().with_event_fault(event, fault, crate::bps!(10000));
			let AuditProbe(trace) = probe_with_detail(true);
			AuditProbe(trace.with_fault_model(model))
		}

		/// A fault the trace injects at the policy step fails the gate, so the
		/// collector that gates the request fails with it.
		#[cfg(feature = "testing-fault")]
		#[test]
		fn a_fault_at_the_policy_step_fails_the_gate() {
			let audit = probe_faulting_at(events::POLICY_EVAL);
			let refused = audit.gate_inbound(&DenyGate, None, &SessionContext::default());
			assert!(matches!(refused, Err(TightBeamError::ChannelClosed)));
		}

		/// A fault the trace injects at the entry of a handler fails the call
		/// before the handler runs.
		#[cfg(all(feature = "testing-fault", feature = "tokio"))]
		#[tokio::test]
		async fn a_fault_at_the_handler_entry_keeps_the_handler_from_running() {
			let audit = probe_faulting_at(events::HANDLER_ENTER);
			let ran = AtomicBool::new(false);
			let handler = async {
				ran.store(true, Ordering::SeqCst);
				Ok(())
			};

			let outcome = audit.run_handler(handler).await;
			assert!(matches!(outcome, HandlerOutcome::Faulted(TightBeamError::ChannelClosed)));
			assert!(!ran.load(Ordering::SeqCst));
		}

		/// A fault the trace injects at the exit of a handler that succeeded
		/// fails the call.
		#[cfg(all(feature = "testing-fault", feature = "tokio"))]
		#[tokio::test]
		async fn a_fault_at_the_handler_exit_fails_the_call() {
			let audit = probe_faulting_at(events::HANDLER_EXIT);
			let outcome = audit.run_handler(async { Ok(()) }).await;
			assert!(matches!(outcome, HandlerOutcome::Faulted(TightBeamError::ChannelClosed)));
		}

		/// The error of a handler comes ahead of a fault the trace injects at
		/// its exit, so the call fails with why the handler failed.
		#[cfg(all(feature = "testing-fault", feature = "tokio"))]
		#[tokio::test]
		async fn a_handler_error_comes_ahead_of_a_fault_at_its_exit() {
			let audit = probe_faulting_at(events::HANDLER_EXIT);
			let handler = async { Err::<(), _>(TightBeamError::MissingResponse) };
			let outcome = audit.run_handler(handler).await;
			assert!(matches!(outcome, HandlerOutcome::Failed(TightBeamError::MissingResponse)));
		}
	}
}
