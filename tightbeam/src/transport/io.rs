//! Envelope I/O over a transport, in cleartext and in encrypted form.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::future::Future;

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::der::{Decode, Encode};
use crate::encode;
use crate::policy::TransitStatus;
use crate::transport::builders::EnvelopeBuilder;
use crate::transport::envelopes::{TransportEnvelope, WireEnvelope};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke", feature = "instrument"))]
use crate::transport::error::ArrivalRefusal;
use crate::transport::error::TransportError;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;
use crate::utils::time::Clock;
use crate::zeroize::Zeroizing;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(host_clock)]
use crate::utils::time::SystemClock;
// Doc links name this import, so the docs build carries it.
#[cfg(doc)]
use crate::transport::error::TransportFailure;
#[cfg(feature = "instrument")]
use crate::transport::handshake::SessionPeer;
#[cfg(feature = "instrument")]
use crate::TightBeamError;

#[cfg(all(
	feature = "tokio",
	feature = "std",
	not(target_arch = "wasm32"),
	any(feature = "transport-cms", feature = "transport-hpke")
))]
mod deadline {
	pub use tokio::time::timeout;
}

#[cfg(all(
	feature = "tokio",
	feature = "std",
	not(target_arch = "wasm32"),
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use deadline::*;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::state::{CollectStep, ServerHandshakeSlot};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod handshake {
	pub use crate::transport::handshake::{
		BoxedClientHandshake, ClientHandshakeProtocol, HandshakeMessage, HandshakeProvider, ServerHandshakeProtocol,
	};
	pub use crate::transport::state::SessionPhase;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use handshake::*;

/// The receive side of a split envelope link.
///
/// The trait decouples the
/// [`MuxTransport`](crate::transport::multiplex::MuxTransport) router from the
/// link's protection policy. An implementation over an encrypted link
/// decrypts each record and enforces AEAD sequencing, while one over a
/// cleartext link reads envelopes as they arrive.
pub trait EnvelopeSource: MaybeSend {
	/// Reads the next envelope from the link.
	///
	/// # Errors
	///
	/// - The link's read failure, such as a closed connection, a decode
	///   failure, or a decrypt failure on an encrypted link.
	fn read_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend;

	/// Returns the number of envelopes that stay readable before the link
	/// demands a rekey.
	///
	/// The count tracks the peer's send counter on the ordered channel, so a
	/// rekey initiator watches the receive direction from the records alone.
	/// A link without keys reports the default, `u64::MAX`.
	fn remaining_records(&self) -> u64 {
		u64::MAX
	}

	/// Installs a fresh receive-direction cipher at an epoch key-switch
	/// boundary ([RFC 9846 § 4.7.3][rfc9846-4.7.3]).
	///
	/// The default fails closed, because a link without keys has no epoch to
	/// switch. An epoch install on an unprotected link therefore returns an
	/// error.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- the default, on a link without keys.
	///
	/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
	fn install_recv_cipher(&mut self, _cipher: RecvCipher) -> TransportResult<()> {
		Err(TransportError::MissingEncryption)
	}

	/// Returns the instrumentation collector that this half inherits from its
	/// connection, or `None` by default. A plane built over the half, such as
	/// the mux, adopts it.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		None
	}
}

/// The send side of a split envelope link, and the counterpart of
/// [`EnvelopeSource`].
pub trait EnvelopeSink: MaybeSend {
	/// Writes `envelope` to the link.
	///
	/// # Errors
	///
	/// - The link's write failure, such as a closed connection, an encode
	///   failure, or an encrypt failure on an encrypted link.
	fn write_envelope(&mut self, envelope: TransportEnvelope) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Returns the number of envelopes that stay writable before the link
	/// demands a rekey.
	///
	/// A link without keys reports `u64::MAX`.
	fn remaining_records(&self) -> u64;

	/// Installs a fresh send-direction cipher at an epoch key-switch boundary
	/// ([RFC 9846 § 4.7.3][rfc9846-4.7.3]).
	///
	/// The default fails closed, because a link without keys has no epoch to
	/// switch. An epoch install on an unprotected link therefore returns an
	/// error.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- the default, on a link without keys.
	///
	/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
	fn install_send_cipher(&mut self, _cipher: SendCipher) -> TransportResult<()> {
		Err(TransportError::MissingEncryption)
	}

	/// Returns the instrumentation collector that this half inherits from its
	/// connection, or `None` by default. A plane built over the half, such as
	/// the mux, adopts it.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		None
	}

	/// Returns the clock that this half inherits from its connection. A plane
	/// built over the half, such as the mux, adopts it, so one endpoint reads
	/// one clock. The default returns the system clock.
	#[cfg(host_clock)]
	fn clock(&self) -> Arc<dyn Clock> {
		Arc::new(SystemClock)
	}
}

/// The base I/O operations of a message transport.
///
/// The read and write futures carry an explicit send bound, so generic server
/// code, such as an accept loop or a single-flight server, can hold them
/// across task spawns. On wasm targets the bound is vacuous.
pub trait MessageIO {
	/// Returns the clock that this transport measures deadlines and backoff
	/// against.
	fn clock(&self) -> &dyn Clock;

	/// Reads raw DER-encoded envelope bytes from the transport.
	///
	/// A read while a handshake is pending MUST admit at most the cap of
	/// [`SessionPhase::read_policy`], because the handshake driver relies on
	/// that bound.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the peer closed the stream.
	/// - The transport's own read failure.
	///
	/// [`SessionPhase::read_policy`]: crate::transport::state::SessionPhase::read_policy
	fn read_envelope_bytes(&mut self) -> impl Future<Output = TransportResult<Vec<u8>>> + MaybeSend;

	/// Writes raw DER-encoded envelope bytes to the transport.
	///
	/// # Errors
	///
	/// - The transport's own write failure.
	fn write_envelope_bytes(&mut self, buffer: &[u8]) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Decodes an envelope from DER bytes.
	///
	/// # Errors
	///
	/// - [`TransportError::DerError`] -- `buffer` is not a valid envelope.
	fn decode_envelope(buffer: &[u8]) -> TransportResult<TransportEnvelope> {
		Ok(TransportEnvelope::from_der(buffer)?)
	}

	/// Encodes an envelope as DER bytes.
	///
	/// # Errors
	///
	/// - The encode failure of an envelope that does not serialize.
	fn encode_envelope(envelope: &TransportEnvelope) -> TransportResult<Vec<u8>> {
		Ok(encode(envelope)?)
	}

	/// Reads and decodes a transport envelope.
	///
	/// An encrypted transport may override this method to parse a
	/// [`WireEnvelope`].
	///
	/// # Errors
	///
	/// - The errors of [`read_envelope_bytes`](Self::read_envelope_bytes) and
	///   [`decode_envelope`](Self::decode_envelope).
	fn read_decoded_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			let bytes = self.read_envelope_bytes().await?;
			Self::decode_envelope(&bytes)
		}
	}

	/// Tries to read the next envelope, and tells an orderly close from an
	/// error.
	///
	/// - `Ok(Some(envelope))`: the method read a message.
	/// - `Ok(None)`: the peer closed the connection in order (EOF).
	/// - `Err(..)`: the connection failed unexpectedly.
	///
	/// A servlet loops on this method to keep its connection alive, and
	/// serves requests until the client closes the connection.
	///
	/// # Default
	///
	/// The default maps [`TransportError::ConnectionClosed`] to `Ok(None)`. A
	/// protocol-specific implementation that detects its own EOF conditions,
	/// such as `UnexpectedEof` for TCP, should override this method to map them
	/// to `Ok(None)`.
	///
	/// # Errors
	///
	/// - The errors of [`read_decoded_envelope`](Self::read_decoded_envelope),
	///   apart from the close that maps to `Ok(None)`.
	fn try_read_decoded_envelope(
		&mut self,
	) -> impl Future<Output = TransportResult<Option<TransportEnvelope>>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			match self.read_decoded_envelope().await {
				Ok(envelope) => Ok(Some(envelope)),
				Err(TransportError::ConnectionClosed) => Ok(None),
				Err(e) => Err(e),
			}
		}
	}
}

/// Message I/O with session encryption and the handshake drivers.
pub trait EncryptedMessageIO: MessageIO {
	/// Reads one wire envelope, enforces size ceilings, and classifies it.
	///
	/// The step is protocol-agnostic. It surfaces a handshake container as a
	/// decoded message for the caller's dispatcher, and it decrypts and returns
	/// everything else.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the wire envelope passes the
	///   ceiling of its mode.
	/// - [`TransportError::MissingEncryption`] -- cleartext traffic arrived
	///   where encryption is required, and the session resets.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptionFailed`] -- a record arrived on a
	///   session that holds no keys, and the session resets.
	/// - The open failure of a record that did not open, such as
	///   [`TransportFailure::TamperDetected`], after the session resets.
	/// - The read and decode failures.
	///
	/// A traced session records a refused envelope as
	/// [`TRANSPORT_ENVELOPE_REFUSED`].
	///
	/// [`TRANSPORT_ENVELOPE_REFUSED`]: crate::instrumentation::events::TRANSPORT_ENVELOPE_REFUSED
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn collect_step(&mut self) -> TransportResult<CollectStep>
	where
		Self: EncryptedProtocolState + Sized,
	{
		let step: Result<CollectStep, ArrivalRefusal> = async {
			// A record opens in the buffer it arrived in, so the buffer wipes
			// when it drops. The session admits the arrival by its outer tag
			// before any decode, and names its peer in each refusal.
			let read = self.read_envelope_bytes().await;
			let mut wire_bytes = Zeroizing::new(read.map_err(|error| self.session_state().refuse(error))?);
			let limits = *self.limits();
			let contents = self.session_state_mut().admit_arrival(&mut wire_bytes, &limits)?;
			let envelope = Self::decode_envelope(contents).map_err(|error| self.session_state().refuse(error))?;
			let collected = self.session_state_mut().collect(envelope);

			collected.map_err(|error| self.session_state().refuse(error))
		}
		.await;

		#[cfg(feature = "instrument")]
		let step = TransportRefusal::audit_read(step, self.to_trace_ref());

		step.map_err(TransportError::from)
	}

	/// Wraps a message in a request [`TransportEnvelope`].
	///
	/// The default is protocol-agnostic.
	fn wrap_message(message: Frame) -> TransportEnvelope {
		TransportEnvelope::new_request(message)
	}

	/// Reads the bytes of one envelope, and names a close by the phase it
	/// interrupts.
	///
	/// The session phase already records whether a handshake is outstanding,
	/// so it decides how an end of stream reads and every caller on this
	/// session gets the same answer.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerClosedBeforeHandshake`] -- the peer ended the
	///   stream while a handshake is pending, before the two ends agree a
	///   session.
	/// - [`TransportError::ConnectionClosed`] -- the peer ended the stream on a
	///   session already agreed, whether cleartext or encrypted.
	/// - The other read failures of [`read_envelope_bytes`](MessageIO::read_envelope_bytes).
	#[allow(async_fn_in_trait)]
	async fn read_session_bytes(&mut self) -> TransportResult<Vec<u8>>
	where
		Self: EncryptedProtocolState,
	{
		match self.read_envelope_bytes().await {
			Err(TransportError::ConnectionClosed) if self.session_state().phase().is_handshake_pending() => {
				Err(TransportError::PeerClosedBeforeHandshake)
			}
			other => other,
		}
	}

	/// Wraps and encrypts a message into a [`WireEnvelope`].
	///
	/// The default is protocol-agnostic. The endpoint's own [`TransportLimits`]
	/// size the envelope, so an oversized request fails locally with a typed
	/// `SizeExceeded` that returns the frame, ahead of any connection reset by
	/// the peer.
	///
	/// # Errors
	///
	/// - [`TransportError::MessageNotSent`] -- the envelope did not encode,
	///   encrypt, or fit its ceiling, and the frame travels with the error.
	/// - The errors of [`EncryptedProtocolState::apply_wire_mode`], before the handshake installs keys.
	///
	/// A traced session records a send that its cipher refuses at the record
	/// limit as [`TRANSPORT_REKEY_REQUIRED`].
	///
	/// [`TransportLimits`]: crate::transport::TransportLimits
	/// [`TRANSPORT_REKEY_REQUIRED`]: crate::instrumentation::events::TRANSPORT_REKEY_REQUIRED
	#[allow(async_fn_in_trait)]
	async fn wrap_and_encrypt_message(&mut self, message: Frame) -> TransportResult<WireEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let builder = EnvelopeBuilder::request(message).with_limits(*self.limits());
		let builder = self.apply_wire_mode(builder)?;
		let sealed = builder.finish();

		#[cfg(feature = "instrument")]
		let sealed = TransportRefusal::audit_send(sealed, self.to_trace_ref(), self.session_state().encryptor().ok());

		sealed
	}

	/// Decrypts a response from its encoded bytes.
	///
	/// The default is protocol-agnostic. The answer reads under the phase rule
	/// of the inbound collector, so the session admits it by its outer tag
	/// before any decode.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the answer passes the ceiling of
	///   its mode.
	/// - [`TransportError::MissingEncryption`] -- a cleartext answer arrived
	///   on an established session, and the session resets.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptionFailed`] -- an encrypted answer arrived
	///   on a session that holds no keys, and the session resets.
	/// - [`TransportError::DerError`] -- the bytes are not a wire envelope, or
	///   the contents of the wire envelope are not a transport envelope.
	/// - The open failure of an encrypted answer, after the session resets.
	///
	/// A traced session records a refused answer as
	/// [`TRANSPORT_ENVELOPE_REFUSED`].
	///
	/// [`TRANSPORT_ENVELOPE_REFUSED`]: crate::instrumentation::events::TRANSPORT_ENVELOPE_REFUSED
	#[allow(async_fn_in_trait)]
	async fn decrypt_response(&mut self, wire_bytes: impl Into<Vec<u8>>) -> TransportResult<TransportEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		// A record opens in the buffer it arrived in, so the buffer wipes when
		// it drops. The session names its peer in each refusal.
		let mut wire_bytes = Zeroizing::new(wire_bytes.into());
		let limits = *self.limits();
		let admitted = self.session_state_mut().admit_arrival(&mut wire_bytes, &limits);
		let answer = admitted.and_then(|contents| {
			let decoded = Self::decode_envelope(contents);
			decoded.map_err(|error| self.session_state().refuse(error))
		});

		#[cfg(feature = "instrument")]
		let answer = TransportRefusal::audit_read(answer, self.to_trace_ref());

		answer.map_err(TransportError::from)
	}

	/// Dual-writes the outcome of a handshake at the transport driver
	/// interface, and returns the outcome.
	///
	/// - A completed handshake records the completion, and the settlement when the session holds a receipt.
	/// - A refused handshake records the audit event its error names: a receipt
	///   refusal, a rejected certificate or proof, a refusal of the authorizer,
	///   or a deadline that ends the handshake.
	///
	/// # Errors
	///
	/// - The error of a refused handshake. It comes first, so a fault the
	///   trace injects at its record leaves it in place.
	/// - The injected error, when the runtime fault model injects a fault at
	///   an event of a completed handshake.
	///
	/// # Examples
	///
	/// ```no_run
	/// use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
	/// use tightbeam::transport::{EncryptedMessageIO, TransportResult};
	///
	/// /// Record the outcome of the handshake that `transport` ran, and hand
	/// /// it on.
	/// fn settle(transport: &TcpTransport<TokioStream>, outcome: TransportResult<()>) -> TransportResult<()> {
	///     transport.emit_handshake_outcome(outcome)
	/// }
	/// ```
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn emit_handshake_outcome(&self, outcome: TransportResult<()>) -> TransportResult<()>
	where
		Self: EncryptedProtocolState,
	{
		let Some(trace) = self.to_trace_ref() else {
			return outcome;
		};

		if let Err(refusal) = &outcome {
			let audit = refusal.handshake_audit();
			let recorded = audit.map_or(Ok(()), |audit| audit.file(trace));

			// The error of the handshake names why the session failed, so it
			// comes ahead of a fault at its record.
			return outcome.and(recorded.map_err(TransportError::from));
		}

		// A multi-round server handshake reports `Ok` per round, so only the
		// encrypted phase marks the session as established.
		if !matches!(self.session_state().phase(), SessionPhase::Encrypted(_)) {
			return outcome;
		}

		trace.emit_event(events::SESSION_HANDSHAKE_COMPLETE)?;
		if self.session_state().receipt().is_some() {
			trace.emit_event(events::SESSION_RECEIPT_SETTLED)?;
		}

		outcome
	}

	/// Runs the client handshake while the session is provisioned.
	///
	/// # Errors
	///
	/// - The errors of [`perform_client_handshake`](Self::perform_client_handshake).
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn ensure_handshake_complete<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let should_handshake = matches!(self.session_state().phase(), SessionPhase::Provisioned);
		if should_handshake {
			self.perform_client_handshake().await?;
		}

		Ok(())
	}

	/// Drives the protocol-agnostic client handshake state machine, with bytes
	/// in and bytes out.
	///
	/// Handshake messages cross this interface as containers, so the driver
	/// moves each one the same way for every protocol.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- a handshake message passes the wire ceiling.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptionFailed`] -- the server response arrived
	///   encrypted, and the session resets.
	/// - [`TransportError::InvalidState`] -- the session refuses the move to the handshaking phase.
	/// - The orchestrator, read, decode, write, and install failures.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn drive_client_handshake(&mut self, mut orchestrator: BoxedClientHandshake) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState,
	{
		// Step 1: Start the handshake and send the initial message.
		let initial_message = orchestrator.start().await?;
		if initial_message.der().len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		let wire_envelope = WireEnvelope::Cleartext(initial_message.into());
		self.write_envelope_bytes(&wire_envelope.to_der()?).await?;

		// The phase moves to handshaking once the first message is out.
		let now = self.clock().monotonic();
		if !self.session_state_mut().begin_handshake(now) {
			return Err(TransportError::InvalidState);
		}

		// Step 2: Receive the server response. The read runs under the
		// handshake ceiling, because the phase is handshaking, and the phase
		// admits the response in cleartext alone.
		let mut response_wire_bytes = self.read_session_bytes().await?;
		let limits = *self.limits();
		let response_contents = self.session_state_mut().admit_arrival(&mut response_wire_bytes, &limits)?;
		let response_envelope = Self::decode_envelope(response_contents)?;

		// Step 3: Handle the server response, which may yield the next message.
		let response = HandshakeMessage::try_from(response_envelope)?;
		let next_message = orchestrator.handle_response(response).await?;

		// Step 4: Send the next message, if any, for a multi-round handshake.
		if let Some(next_message) = next_message {
			if next_message.der().len() > self.limits().handshake_wire {
				return Err(TransportError::InvalidMessage);
			}

			let wire_envelope = WireEnvelope::Cleartext(next_message.into());
			self.write_envelope_bytes(&wire_envelope.to_der()?).await?;
		}

		// Step 5: Complete the handshake, which hands over everything it
		// agreed.
		let session = orchestrator.complete().await?;
		self.install_established(session)?;

		Ok(())
	}

	/// Performs the client-side handshake with the configured protocol.
	///
	/// # Errors
	///
	/// - [`TransportError::UnsupportedHandshakeProtocol`] -- this build lacks the configured protocol.
	/// - The orchestrator build failure, and the errors of
	///   [`drive_client_handshake`](Self::drive_client_handshake).
	/// - The injected error, when the runtime fault model injects a fault at
	///   an event of a completed handshake.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let orchestrator = self.session_state().endpoint().client_handshake()?;

		let outcome = self.drive_client_handshake(orchestrator).await;

		#[cfg(feature = "instrument")]
		let outcome = self.emit_handshake_outcome(outcome);

		outcome
	}

	/// Drives the protocol-agnostic server handshake state machine.
	///
	/// The persisted orchestrator must already exist.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the slot holds no orchestrator, or
	///   the session refuses the move to the handshaking phase.
	/// - [`TransportError::InvalidMessage`] -- the response passes the wire ceiling.
	/// - The orchestrator, write, and install failures.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn drive_server_handshake(&mut self, request: HandshakeMessage) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState + ServerHandshakeSlot,
	{
		let orchestrator = self.server_handshake_mut().as_mut().ok_or(TransportError::InvalidState)?;
		let response = orchestrator.handle_request(request).await?;

		// A response means another round follows.
		if let Some(response) = response {
			if response.der().len() > self.limits().handshake_wire {
				return Err(TransportError::InvalidMessage);
			}

			// The driver writes the response only after the session accepts the
			// move, because a write ahead of a refusal would send a handshake
			// response on a session that already agreed one.
			let now = self.clock().monotonic();
			if !self.session_state_mut().begin_handshake(now) {
				return Err(TransportError::InvalidState);
			}

			let wire_envelope = WireEnvelope::Cleartext(response.into());
			self.write_envelope_bytes(&wire_envelope.to_der()?).await?;
		} else {
			// No response means the handshake is complete.
			let orchestrator = self.server_handshake_mut().take().ok_or(TransportError::InvalidState)?;
			let session = orchestrator.complete().await?;
			self.install_established(session)?;
		}

		Ok(())
	}

	/// Performs the server-side handshake with the configured protocol.
	///
	/// # Deadline
	///
	/// The tokio runtime supplies the timer. The handshake deadline bounds all
	/// the work on the unauthenticated path: the reads, and the authorizer and
	/// observer hooks too. Under another runtime this method has no portable
	/// timer, so the application that embeds the crate owns that deadline.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the request passes the wire ceiling.
	/// - [`TransportError::UnsupportedHandshakeProtocol`] -- this build lacks the configured protocol.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::DeadlineExceeded`] -- the handshake timed out.
	/// - The orchestrator build failure, and the errors of
	///   [`drive_server_handshake`](Self::drive_server_handshake).
	/// - The injected error, when the runtime fault model injects a fault at
	///   an event of a completed handshake.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake<P>(&mut self, request: HandshakeMessage) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: HandshakeProvider,
	{
		if request.der().len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		// The orchestrator persists across messages, so this method creates it
		// once.
		if self.server_handshake_mut().is_none() {
			let orchestrator = self.session_state().endpoint().server_handshake()?;

			*self.server_handshake_mut() = Some(orchestrator);
		}

		// A deadline that ends the handshake is its outcome, so the record of
		// the outcome below files it.
		#[cfg(all(feature = "tokio", feature = "std", not(target_arch = "wasm32")))]
		let outcome = {
			let now = self.clock().monotonic();
			let policy = self.session_state().phase().read_policy(self.limits(), now);
			match policy.remaining(now) {
				Ok(Some(remaining)) => {
					let bounded = timeout(remaining, self.drive_server_handshake(request)).await;
					bounded.unwrap_or_else(|elapsed| Err(elapsed.into()))
				}
				Ok(None) => self.drive_server_handshake(request).await,
				Err(expired) => Err(expired),
			}
		};

		#[cfg(not(all(feature = "tokio", feature = "std", not(target_arch = "wasm32"))))]
		let outcome = self.drive_server_handshake(request).await;

		#[cfg(feature = "instrument")]
		let outcome = self.emit_handshake_outcome(outcome);

		outcome
	}

	/// Performs a single request-response cycle.
	///
	/// It returns `(status, response, original_message)`. The original message
	/// is `Some` when `status` is not `Ok` and the request went out in
	/// cleartext, so the caller can evaluate a retry.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the reply is not a response envelope.
	/// - The errors of
	///   [`wrap_and_encrypt_message`](Self::wrap_and_encrypt_message),
	///   [`write_envelope_bytes`](MessageIO::write_envelope_bytes),
	///   [`read_session_bytes`](Self::read_session_bytes), and
	///   [`decrypt_response`](Self::decrypt_response).
	#[allow(async_fn_in_trait)]
	async fn perform_emit_cycle(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>
	where
		Self: Sized + MessageIO + EncryptedProtocolState,
	{
		let wire_envelope = self.wrap_and_encrypt_message(message).await?;
		let wire_bytes = wire_envelope.to_der()?;

		self.write_envelope_bytes(&wire_bytes).await?;

		let response_bytes = self.read_session_bytes().await?;
		let response_envelope = self.decrypt_response(response_bytes).await?;
		let (status, response) = match response_envelope {
			TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
			TransportEnvelope::Request(_) => return Err(TransportError::InvalidMessage),
			TransportEnvelope::SignedData(_) | TransportEnvelope::AuthEnvelopedData(_) | TransportEnvelope::Data(_) => {
				return Err(TransportError::InvalidMessage)
			}
			#[cfg(feature = "transport-multiplex")]
			TransportEnvelope::Mux(_) => return Err(TransportError::InvalidMessage),
		};

		// A refused cleartext request returns its frame for retry evaluation.
		let returned_message = if status != TransitStatus::Ok {
			match wire_envelope {
				WireEnvelope::Cleartext(TransportEnvelope::Request(pkg)) => Some(pkg.message),
				_ => None, // An encrypted request has no cleartext frame.
			}
		} else {
			None
		};

		let response_frame = response.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		let returned_frame = returned_message.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		Ok((status, response_frame, returned_frame))
	}
}

/// A refusal that the read or the send step of a transport makes about one
/// envelope, which the audit trail of its connection records.
#[cfg(feature = "instrument")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportRefusal {
	/// The read step refused an inbound envelope for the failure it names,
	/// which files [`TRANSPORT_ENVELOPE_REFUSED`].
	///
	/// [`TRANSPORT_ENVELOPE_REFUSED`]: events::TRANSPORT_ENVELOPE_REFUSED
	Envelope(&'static str),
	/// The send cipher refused an outbound envelope at the record limit it
	/// holds, which files [`TRANSPORT_REKEY_REQUIRED`].
	///
	/// [`TRANSPORT_REKEY_REQUIRED`]: events::TRANSPORT_REKEY_REQUIRED
	RecordLimit(u64),
}

#[cfg(feature = "instrument")]
impl TransportRefusal {
	/// Files the refusal that `read`, the outcome of one read step, names in
	/// `trace`, with the key of the peer that the refusal names as evidence,
	/// and returns `read`.
	///
	/// # Errors
	///
	/// - The refusal of `read`. It comes first, so a fault the trace injects at
	///   its record leaves it in place.
	pub(crate) fn audit_read<T>(
		read: Result<T, ArrivalRefusal>,
		trace: Option<&TraceCollector>,
	) -> Result<T, ArrivalRefusal> {
		let refused = read.as_ref().err();
		let refusal = refused.and_then(ArrivalRefusal::refusal).map(Self::Envelope);
		let peer = refused.and_then(ArrivalRefusal::peer);
		let recorded = Self::record(refusal, trace, peer);

		// The refusal names why the step failed, so it comes ahead of a fault
		// at its record.
		read.and_then(|value| {
			recorded
				.map(|()| value)
				.map_err(|fault| ArrivalRefusal::new(TransportError::from(fault), None))
		})
	}

	/// Files the refusal that `sent`, the outcome of one seal under `cipher`,
	/// names in `trace`, and returns `sent`.
	///
	/// # Errors
	///
	/// - The error of `sent`. It comes first, so a fault the trace injects at its record leaves it in place.
	pub(crate) fn audit_send<T>(
		sent: TransportResult<T>,
		trace: Option<&TraceCollector>,
		cipher: Option<&SendCipher>,
	) -> TransportResult<T> {
		let failure = sent.as_ref().err().zip(cipher);
		let refusal = failure.and_then(|(error, cipher)| Self::of_send(error, cipher));
		let recorded = Self::record(refusal, trace, None);

		// The error names why the seal failed, so it comes ahead of a fault at
		// its record.
		sent.and_then(|value| recorded.map(|()| value).map_err(TransportError::from))
	}

	/// The refusal that `error`, the failure of a seal under `cipher`, names,
	/// or `None` for a failure other than the record limit of `cipher`.
	fn of_send(error: &TransportError, cipher: &SendCipher) -> Option<Self> {
		error.at_record_limit().then(|| Self::RecordLimit(cipher.rekey_limit()))
	}

	/// Files `refusal` in `trace` when both are present, with the key of
	/// `peer` as the evidence of an inbound refusal.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the event of the refusal.
	fn record(
		refusal: Option<Self>,
		trace: Option<&TraceCollector>,
		peer: Option<&SessionPeer>,
	) -> Result<(), TightBeamError> {
		let (Some(refusal), Some(trace)) = (refusal, trace) else {
			return Ok(());
		};

		refusal.file(trace, peer)
	}

	/// Files this refusal in `trace`, with the key of `peer` as the evidence
	/// of an inbound refusal.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the event of this refusal.
	fn file(self, trace: &TraceCollector, peer: Option<&SessionPeer>) -> Result<(), TightBeamError> {
		match self {
			Self::Envelope(failure) => {
				let event = events::TRANSPORT_ENVELOPE_REFUSED;
				let evidence = || peer.map(|peer| peer.key().as_der());
				trace.emit_event_with_value_and_rendered_evidence(event, failure, failure, evidence)
			}
			Self::RecordLimit(limit) => trace.emit_event_with_value(events::TRANSPORT_REKEY_REQUIRED, "send", limit),
		}
	}
}

impl TransportEnvelope {
	/// Returns the application request frame inside a single-flight envelope.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the envelope is any kind other than a request.
	pub(crate) fn into_request_frame(self) -> TransportResult<Arc<Frame>> {
		match self {
			TransportEnvelope::Request(msg) => Ok(msg.message),
			TransportEnvelope::Response(_) => Err(TransportError::InvalidMessage),
			TransportEnvelope::SignedData(_) | TransportEnvelope::AuthEnvelopedData(_) | TransportEnvelope::Data(_) => {
				Err(TransportError::InvalidMessage)
			}
			#[cfg(feature = "transport-multiplex")]
			TransportEnvelope::Mux(_) => Err(TransportError::InvalidMessage),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::testing::TestFrame;
	use crate::transport::envelopes::{RequestPackage, ResponsePackage};
	use crate::transport::handshake::EstablishedSession;
	use crate::transport::state::{EncryptionConfig, SessionState};
	use crate::utils::time::ManualClock;
	use crate::Version;

	use crate::crypto::aead::SessionKeys;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::transport::error::TransportFailure;
	use crate::transport::handshake::PeerAuthentication;
	use crate::transport::TransportLimits;

	#[cfg(all(
		feature = "instrument",
		feature = "testing-fault",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	use crate::testing::FaultModel;
	#[cfg(all(
		feature = "instrument",
		feature = "testing-fault",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	use crate::transport::handshake::HandshakeError;
	#[cfg(feature = "instrument")]
	use crate::urn::Urn;

	#[cfg(feature = "instrument")]
	mod audit_fixtures {
		pub use crate::crypto::hash::{Digest, Sha3_256};
		pub use crate::instrumentation::TbInstrumentationConfig;
		pub use crate::testing::{TestCertificate, TestKey};
		pub use crate::trace::TraceConfig;
	}

	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	use crate::crypto::aead::RecordDirection;
	#[cfg(feature = "instrument")]
	use audit_fixtures::*;

	/// A minimal `MessageIO` probe, so ingress goes through `decode_envelope`.
	#[derive(Default)]
	struct DecodeProbe {
		clock: ManualClock,
	}

	impl MessageIO for DecodeProbe {
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

	/// A probe whose stream yields at most one envelope and then reads EOF, in
	/// the session phase that the case under test sets.
	struct StreamProbe {
		state: SessionState<DefaultCryptoProvider>,
		limits: TransportLimits,
		clock: ManualClock,
		inbound: Option<Vec<u8>>,
		#[cfg(feature = "instrument")]
		trace: Option<TraceCollector>,
	}

	impl StreamProbe {
		/// Returns a provisioned endpoint placed directly in `phase`, whose
		/// stream is closed.
		fn at(phase: SessionPhase) -> Self {
			let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
			let peer_authentication = PeerAuthentication::mutual([validator]);
			let encryption = EncryptionConfig { peer_authentication, ..EncryptionConfig::unconfigured() };

			Self {
				state: SessionState::at(encryption, phase),
				limits: TransportLimits::default(),
				clock: ManualClock::default(),
				inbound: None,
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		/// Returns the endpoint of [`Self::at`], whose stream yields `envelope`
		/// once before it closes.
		fn reading(phase: SessionPhase, envelope: WireEnvelope) -> Self {
			let mut probe = Self::at(phase);
			probe.inbound = Some(envelope.to_der().expect("a wire envelope encodes"));
			probe
		}

		/// Returns the endpoint of [`Self::at`], whose stream yields `bytes`
		/// once before it closes.
		fn reading_bytes(phase: SessionPhase, bytes: &[u8]) -> Self {
			let mut probe = Self::at(phase);
			probe.inbound = Some(bytes.to_vec());
			probe
		}
	}

	/// A wire envelope under the cleartext tag whose contents, a NULL, decode
	/// to no transport envelope.
	const UNDECODABLE_CLEARTEXT: [u8; 4] = [0xa0, 0x02, 0x05, 0x00];

	/// A wire envelope under the record tag whose contents, a NULL, open under
	/// no receive cipher.
	const UNOPENED_RECORD: [u8; 4] = [0xa1, 0x02, 0x05, 0x00];

	impl MessageIO for StreamProbe {
		fn clock(&self) -> &dyn Clock {
			&self.clock
		}

		async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
			self.inbound.take().ok_or(TransportError::ConnectionClosed)
		}

		async fn write_envelope_bytes(&mut self, _buffer: &[u8]) -> TransportResult<()> {
			Ok(())
		}
	}

	impl EncryptedMessageIO for StreamProbe {}

	impl crate::transport::state::sealed::Sealed for StreamProbe {}

	impl EncryptedProtocolState for StreamProbe {
		type CryptoProvider = DefaultCryptoProvider;

		fn limits(&self) -> &TransportLimits {
			&self.limits
		}

		fn session_state(&self) -> &SessionState<DefaultCryptoProvider> {
			&self.state
		}

		fn session_state_mut(&mut self) -> &mut SessionState<DefaultCryptoProvider> {
			&mut self.state
		}

		#[cfg(feature = "instrument")]
		fn to_trace_ref(&self) -> Option<&TraceCollector> {
			self.trace.as_ref()
		}

		#[cfg(feature = "instrument")]
		fn with_trace(mut self, trace: TraceCollector) -> Self {
			self.trace = Some(trace);
			self
		}
	}

	fn encrypted_phase() -> SessionPhase {
		let keys = SessionKeys::for_client(crate::testing::TestKey::insecure_directional_keys());
		SessionPhase::Encrypted(Box::new(EstablishedSession::forged(keys, None, None)))
	}

	fn handshaking_phase() -> SessionPhase {
		SessionPhase::Handshaking { initiated_at: ManualClock::default().monotonic() }
	}

	// The session phase decides how an end of stream reads. A session that
	// agreed its terms reports an ordinary close, so a pool evicts the
	// connection on a close that is distinct from a handshake failure.
	crate::tb_cases! {
		fn a_close_is_named_by_the_phase_it_interrupts((phase, expected): (SessionPhase, TransportError))
			-> TransportResult<()>
		{
			let mut probe = StreamProbe::at(phase);
			let runtime = tokio::runtime::Builder::new_current_thread().build()?;
			let outcome = runtime.block_on(probe.read_session_bytes());
			assert!(
				matches!(&outcome, Err(error) if core::mem::discriminant(error) == core::mem::discriminant(&expected)),
				"expected {expected:?}, got {outcome:?}"
			);
			Ok(())
		}
		cases {
			cleartext_session => (SessionPhase::Cleartext, TransportError::ConnectionClosed),
			provisioned_before_the_handshake => (SessionPhase::Provisioned, TransportError::PeerClosedBeforeHandshake),
			handshake_in_flight => (handshaking_phase(), TransportError::PeerClosedBeforeHandshake),
			established_session => (encrypted_phase(), TransportError::ConnectionClosed),
		}
	}

	/// A cleartext envelope that is no handshake container, read while a
	/// handshake is in flight, trips the circuit breaker. The step refuses it,
	/// and the session drops the handshake and returns to its provisioned
	/// start.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test]
	async fn a_cleartext_request_during_the_handshake_trips_the_breaker() {
		let request = TransportEnvelope::Request(RequestPackage::new(TestFrame::prioritized()));
		let mut probe = StreamProbe::reading(handshaking_phase(), WireEnvelope::Cleartext(request));

		let refusal = probe.collect_step().await;
		assert!(matches!(refusal, Err(TransportError::MissingEncryption)));
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
	}

	/// An established session refuses a cleartext envelope by its outer tag,
	/// before its contents decode, so contents that decode to nothing trip the
	/// breaker as any cleartext does.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test]
	async fn an_established_session_refuses_cleartext_before_it_decodes() {
		let mut probe = StreamProbe::reading_bytes(encrypted_phase(), &UNDECODABLE_CLEARTEXT);

		let refusal = probe.collect_step().await;
		assert!(matches!(refusal, Err(TransportError::MissingEncryption)));
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
	}

	/// An answer reads under the phase rule of the inbound collector, so an
	/// established session refuses a cleartext answer before it decodes.
	#[tokio::test]
	async fn an_established_session_refuses_a_cleartext_answer_before_it_decodes() {
		let mut probe = StreamProbe::at(encrypted_phase());

		let refusal = probe.decrypt_response(UNDECODABLE_CLEARTEXT).await;
		assert!(matches!(refusal, Err(TransportError::MissingEncryption)));
	}

	/// A record that arrives while a handshake is pending trips the circuit
	/// breaker, so the session drops the handshake and returns to its
	/// provisioned start.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test]
	async fn a_record_during_the_handshake_trips_the_breaker() {
		let mut probe = StreamProbe::reading_bytes(handshaking_phase(), &UNOPENED_RECORD);
		let expected = TransportFailure::EncryptionFailed;

		let refusal = probe.collect_step().await;
		let refused = matches!(refusal, Err(TransportError::OperationFailed(failure)) if failure == expected);
		assert!(refused);
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
	}

	/// An answer that fails to open on an established session trips the
	/// circuit breaker, as a record on the inbound collector does.
	#[tokio::test]
	async fn an_answer_that_fails_to_open_trips_the_breaker() {
		let mut probe = StreamProbe::at(encrypted_phase());

		let refusal = probe.decrypt_response(UNOPENED_RECORD).await;
		assert!(matches!(refusal, Err(TransportError::InvalidMessage)));
		assert!(matches!(probe.session_state().phase(), SessionPhase::Provisioned));
	}

	/// An answer passes under the ceiling of its own mode, so the session
	/// refuses a cleartext answer past the cleartext ceiling, though it fits
	/// the encrypted one.
	#[tokio::test]
	async fn a_cleartext_answer_past_its_ceiling_is_refused() -> crate::error::Result<()> {
		let mut probe = StreamProbe::at(SessionPhase::Cleartext);
		probe.limits.cleartext_envelope = UNDECODABLE_CLEARTEXT.len();
		let response = TransportEnvelope::Response(ResponsePackage::new(TransitStatus::Ok, None));
		let answer = WireEnvelope::Cleartext(response).to_der()?;

		let refusal = probe.decrypt_response(answer).await;
		let oversize = matches!(refusal, Err(TransportError::OperationFailed(TransportFailure::SizeExceeded)));
		assert!(oversize);
		Ok(())
	}

	/// The error of a refused handshake names why the session failed, so a
	/// fault the trace injects at the record of the refusal leaves it in place.
	#[cfg(all(
		feature = "instrument",
		feature = "testing-fault",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[test]
	fn a_fault_at_the_record_of_a_refused_handshake_keeps_its_error() {
		let injected = || TransportError::InvalidAddress;
		let model = FaultModel::default().with_event_fault(events::SESSION_CERT_REJECTED, injected, crate::bps!(10000));
		let mut probe = StreamProbe::at(handshaking_phase());
		probe.trace = Some(TraceCollector::new().with_fault_model(model));

		let refusal = probe.emit_handshake_outcome(Err(HandshakeError::MutualAuthRequired.into()));
		let kept = matches!(refusal, Err(TransportError::HandshakeError(HandshakeError::MutualAuthRequired)));
		assert!(kept);
	}

	/// The error of a refused envelope names why the read failed, so a fault
	/// the trace injects at the record of the refusal leaves it in place.
	#[cfg(all(
		feature = "instrument",
		feature = "testing-fault",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[tokio::test]
	async fn a_fault_at_the_record_of_a_refused_envelope_keeps_its_error() {
		let injected = || TransportError::InvalidAddress;
		let event = events::TRANSPORT_ENVELOPE_REFUSED;
		let model = FaultModel::default().with_event_fault(event, injected, crate::bps!(10000));
		let mut probe = StreamProbe::reading_bytes(handshaking_phase(), &UNOPENED_RECORD);
		probe.trace = Some(TraceCollector::new().with_fault_model(model));
		let expected = TransportFailure::EncryptionFailed;

		let refusal = probe.collect_step().await;
		let kept = matches!(refusal, Err(TransportError::OperationFailed(failure)) if failure == expected);
		assert!(kept);
	}

	/// A collector that keeps the hash of every payload.
	#[cfg(feature = "instrument")]
	fn payload_trace() -> TraceCollector {
		let config = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
		TraceCollector::from(TraceConfig::with_instrumentation(config))
	}

	/// An established session whose peer holds the self-signed test
	/// certificate, beside the hash of the canonical key of that peer.
	#[cfg(feature = "instrument")]
	fn peered_phase() -> (SessionPhase, [u8; 32]) {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let peer = SessionPeer::try_from(Arc::new(certificate)).expect("a test certificate records its peer");
		let key_hash: [u8; 32] = Sha3_256::digest(peer.key().as_der()).into();

		let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());
		let session = EstablishedSession::forged(keys, None, Some(peer));
		(SessionPhase::Encrypted(Box::new(session)), key_hash)
	}

	/// The label and the payload hash of each event of kind `event` that
	/// `trace` holds, in the order it recorded them.
	#[cfg(feature = "instrument")]
	fn records_of(trace: &TraceCollector, event: Urn<'static>) -> Vec<(Option<String>, Option<[u8; 32]>)> {
		let recorded = trace.drain_events();
		recorded
			.into_iter()
			.filter(|record| record.urn == event)
			.map(|record| (record.label, record.payload_hash))
			.collect()
	}

	/// A traced session records an arrival that its inbound collector refuses,
	/// by the name of the failure and by the key of the peer of the session,
	/// which the refusal resets.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[tokio::test]
	async fn a_traced_session_records_the_arrival_it_refuses() {
		let trace = payload_trace();
		let (phase, peer_key) = peered_phase();
		let mut probe = StreamProbe::reading_bytes(phase, &UNDECODABLE_CLEARTEXT).with_trace(trace.share());
		let expected = (Some(String::from("MissingEncryption")), Some(peer_key));

		let refusal = probe.collect_step().await;
		assert!(matches!(refusal, Err(TransportError::MissingEncryption)));
		assert_eq!(records_of(&trace, events::TRANSPORT_ENVELOPE_REFUSED), [expected]);
	}

	/// A traced session records an answer that it refuses, by the name of the
	/// failure and by the key of the peer of the session, which the refusal
	/// resets.
	#[cfg(feature = "instrument")]
	#[tokio::test]
	async fn a_traced_session_records_the_answer_it_refuses() {
		let trace = payload_trace();
		let (phase, peer_key) = peered_phase();
		let mut probe = StreamProbe::at(phase).with_trace(trace.share());
		let expected = (Some(String::from("MissingEncryption")), Some(peer_key));

		let refusal = probe.decrypt_response(UNDECODABLE_CLEARTEXT).await;
		assert!(matches!(refusal, Err(TransportError::MissingEncryption)));
		assert_eq!(records_of(&trace, events::TRANSPORT_ENVELOPE_REFUSED), [expected]);
	}

	/// A record that the server-to-client key of the test keys seals at
	/// `epoch`, as the wire envelope that a client session reads.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn sealed_for_client(epoch: u32) -> TransportResult<Vec<u8>> {
		let key = TestKey::insecure_directional_keys().server_to_client;
		let sender = SendCipher::new(key, epoch, RecordDirection::ServerToClient);
		let record = sender.encrypt_next(b"forged".to_vec())?;
		Ok(WireEnvelope::Encrypted(record).to_der()?)
	}

	/// The record of epoch 0 with its last octet flipped. The octet lies in
	/// the tag of the record, so the record fails to open.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn with_its_tag_flipped() -> TransportResult<Vec<u8>> {
		let mut forged = sealed_for_client(0)?;
		let last = forged.last_mut().expect("a sealed record holds octets");
		*last ^= 0x01;

		Ok(forged)
	}

	/// A record that the server-to-client key of the test keys seals at
	/// `sequence` of epoch 0, past the sequence that a client session expects.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn sealed_for_client_at(sequence: u64) -> TransportResult<Vec<u8>> {
		let key = TestKey::insecure_directional_keys().server_to_client;
		let sender = SendCipher::new(key, 0, RecordDirection::ServerToClient);
		let record = sender.seal_at(b"forged".to_vec(), sequence)?;
		Ok(WireEnvelope::Encrypted(record).to_der()?)
	}

	/// A record that the server-to-client key of the test keys seals with an
	/// OCTET STRING in place of its position.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn sealed_for_client_with_an_undecodable_position() -> TransportResult<Vec<u8>> {
		let key = TestKey::insecure_directional_keys().server_to_client;
		let sender = SendCipher::new(key, 0, RecordDirection::ServerToClient);
		let position = crate::der::Any::encode_from(&crate::der::asn1::OctetString::new([0u8; 4])?)?;
		let record = sender.seal_with_position(b"forged".to_vec(), position)?;
		Ok(WireEnvelope::Encrypted(record).to_der()?)
	}

	/// Whether `error` is the [`TransportError::InvalidMessage`] of a record
	/// whose key refused it.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn is_invalid_message(error: &TransportError) -> bool {
		matches!(error, TransportError::InvalidMessage)
	}

	/// Whether `error` is the record limit of the receive key.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn is_rekey_required(error: &TransportError) -> bool {
		matches!(error, TransportError::OperationFailed(TransportFailure::RekeyRequired))
	}

	/// Whether `error` is the decode failure of a position.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn is_der_error(error: &TransportError) -> bool {
		matches!(error, TransportError::DerError(_))
	}

	/// A forged record, the cause its record names, and the test of the error
	/// that the read returns.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	type ForgedRecordCase = (TransportResult<Vec<u8>>, &'static str, fn(&TransportError) -> bool);

	// A traced session records a forged record by its cause and by the key of
	// its peer, and its read returns the error that the open names.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	crate::tb_cases! {
		fn a_traced_session_records_a_forged_record((forged, cause, returned): ForgedRecordCase)
			-> TransportResult<()>
		{
			let trace = payload_trace();
			let (phase, peer_key) = peered_phase();
			let mut probe = StreamProbe::reading_bytes(phase, &forged?).with_trace(trace.share());
			let expected = (Some(String::from(cause)), Some(peer_key));

			let runtime = tokio::runtime::Builder::new_current_thread().build()?;
			let refusal = runtime.block_on(probe.collect_step());
			assert!(matches!(&refusal, Err(error) if returned(error)));
			assert_eq!(records_of(&trace, events::TRANSPORT_ENVELOPE_REFUSED), [expected]);
			Ok(())
		}
		cases {
			whose_tag_fails => (with_its_tag_flipped(), "OpenFailed", is_invalid_message),
			of_another_epoch => (sealed_for_client(1), "WrongEpoch", is_invalid_message),
			past_the_record_limit => (
				sealed_for_client_at(crate::constants::DEFAULT_REKEY_RECORD_LIMIT),
				"OpenFailed",
				is_rekey_required,
			),
			whose_position_does_not_decode => (
				sealed_for_client_with_an_undecodable_position(),
				"OpenFailed",
				is_der_error,
			),
		}
	}

	/// A traced session records an arrival whose wire envelope does not
	/// decode, by the name of the failure and by the key of its peer.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[tokio::test]
	async fn a_traced_session_records_an_envelope_that_does_not_decode() {
		let trace = payload_trace();
		let (phase, peer_key) = peered_phase();
		let mut probe = StreamProbe::reading_bytes(phase, &[0x05, 0x00]).with_trace(trace.share());
		let expected = (Some(String::from("DerError")), Some(peer_key));

		let refusal = probe.collect_step().await;
		assert!(matches!(refusal, Err(TransportError::DerError(_))));
		assert_eq!(records_of(&trace, events::TRANSPORT_ENVELOPE_REFUSED), [expected]);
	}

	/// An established session whose send cipher holds a record limit of zero.
	#[cfg(feature = "instrument")]
	fn spent_phase() -> SessionPhase {
		let keys = SessionKeys::for_client(TestKey::insecure_directional_keys());

		// A ceiling larger than the renewal volume sets the record limit of
		// the send cipher to zero.
		let keys = keys.with_envelope_ceiling(usize::MAX);
		SessionPhase::Encrypted(Box::new(EstablishedSession::forged(keys, None, None)))
	}

	/// A traced session records a send that its cipher refuses at the record
	/// limit, in the direction of that cipher.
	#[cfg(feature = "instrument")]
	#[tokio::test]
	async fn a_traced_session_records_the_send_its_cipher_refuses() {
		let trace = TraceCollector::new();
		let mut probe = StreamProbe::at(spent_phase()).with_trace(trace.share());
		let expected = (Some(String::from("send")), None);

		let refusal = probe.wrap_and_encrypt_message(TestFrame::prioritized()).await;
		let at_limit = matches!(refusal, Err(TransportError::MessageNotSent(_, TransportFailure::RekeyRequired)));
		assert!(at_limit);
		assert_eq!(records_of(&trace, events::TRANSPORT_REKEY_REQUIRED), [expected]);
	}

	/// A request around `frame`.
	fn request_with(frame: Frame) -> TransportEnvelope {
		TransportEnvelope::Request(RequestPackage::new(frame))
	}

	/// A response of status `Ok` around `frame`, when one is given.
	fn response_with(frame: Option<Frame>) -> TransportEnvelope {
		TransportEnvelope::Response(ResponsePackage::new(TransitStatus::Ok, frame))
	}

	/// The encoding of the envelope that `carry` builds around the prioritized
	/// test frame, with the version of that frame forged to V0, which forbids
	/// the priority the frame keeps.
	fn forged_as_v0(carry: impl FnOnce(Frame) -> TransportEnvelope) -> Vec<u8> {
		let frame = TestFrame::prioritized();
		let envelope = carry(frame.clone());
		TestFrame::forge_version(&envelope, &frame, Version::V0)
	}

	/// The encoding of `envelope`.
	fn encoded(envelope: TransportEnvelope) -> Vec<u8> {
		crate::encode(&envelope).expect("a test envelope encodes")
	}

	// Ingress admits a frame that holds the fields its version allows, and
	// refuses a frame that holds a field its version forbids.
	crate::tb_cases! {
		fn decode_ingress_refuses_a_field_the_frame_version_forbids((bytes, accepted): (Vec<u8>, bool)) {
			let decoded = <DecodeProbe as MessageIO>::decode_envelope(&bytes);
			assert_eq!(decoded.is_ok(), accepted);
		}
		cases {
			request_v0_with_priority => (forged_as_v0(request_with), false),
			request_v2_with_priority => (encoded(request_with(TestFrame::prioritized())), true),
			response_v0_with_priority => (forged_as_v0(|frame| response_with(Some(frame))), false),
			response_without_frame => (encoded(response_with(None)), true),
		}
	}
}
