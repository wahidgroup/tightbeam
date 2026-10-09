//! Envelope I/O over a transport, in cleartext and in encrypted form.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::future::Future;

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::der::{Decode, Encode};
use crate::encode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{TransportEnvelope, WireEnvelope};
use crate::transport::error::TransportError;
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;
use crate::utils::time::Clock;

#[cfg(feature = "aead")]
use crate::crypto::aead::{RecvCipher, SendCipher};
#[cfg(host_clock)]
use crate::utils::time::SystemClock;
// Named only by `emit_handshake_outcome`, so this carries that method's gate.
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;

#[cfg(all(
	feature = "tokio",
	feature = "std",
	not(target_arch = "wasm32"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
mod deadline {
	pub use tokio::time::timeout;
}

#[cfg(all(
	feature = "tokio",
	feature = "std",
	not(target_arch = "wasm32"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use deadline::*;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::aead::DecryptContent;
	pub use crate::transport::builders::EnvelopeBuilder;
	pub use crate::transport::state::EncryptedProtocolState;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use crate::transport::state::ServerHandshakeSlot;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	mod handshake {
		pub use crate::transport::error::TransportFailure;
		pub use crate::transport::handshake::negotiation::RunnableProfile;
		pub(crate) use crate::transport::handshake::ServerFlow;
		pub use crate::transport::handshake::{
			BoxedClientHandshake, BoxedServerHandshake, ClientConfig, ClientHandshakeProtocol, Handshake,
			HandshakeError, HandshakeMessage, HandshakeProtocolKind, HandshakeProvider, ServerConfig,
			ServerHandshakeProtocol, SupportedProfiles,
		};
		pub use crate::transport::state::SessionPhase;
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use handshake::*;

	#[cfg(feature = "transport-ecies")]
	mod ecies {
		pub use crate::crypto::x509::policy::CertificateValidation;
		pub use crate::transport::handshake::{Ecies, EciesClientSettings, EciesServerSettings, LearnedTrust};
	}

	#[cfg(feature = "transport-ecies")]
	pub use ecies::*;

	#[cfg(feature = "transport-cms")]
	mod cms {
		pub use crate::transport::handshake::negotiation::SecurityOffer;
		pub use crate::transport::handshake::{Cms, CmsClientSettings, CmsServerSettings, ProvisionedTrust};
	}

	#[cfg(feature = "transport-cms")]
	pub use cms::*;
}

#[cfg(feature = "x509")]
use x509::*;

/// Receive side of a split envelope link.
///
/// The trait decouples the
/// [`MuxTransport`](crate::transport::multiplex::MuxTransport) router from the
/// link's protection policy. An encrypting implementation decrypts and
/// enforces AEAD sequencing, while a cleartext one enforces neither.
pub trait EnvelopeSource: MaybeSend {
	/// Read the next envelope from the link.
	///
	/// # Errors
	///
	/// - The link's read failure, such as a closed connection, a decode
	///   failure, or a decrypt failure on an encrypting link.
	fn read_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend;

	/// Returns the number of envelopes still readable before the link demands a
	/// rekey.
	///
	/// The count tracks the peer's send counter on the ordered channel, so a
	/// rekey initiator watches the receive direction with no extra protocol
	/// field. A link without keys never rekeys and reports `u64::MAX`.
	fn remaining_records(&self) -> u64 {
		u64::MAX
	}

	/// Install a fresh receive-direction cipher at an epoch key-switch
	/// boundary ([RFC 9846 § 4.7.3][rfc9846-4.7.3]).
	///
	/// A link without keys never rekeys, so the default fails closed and an
	/// epoch install never lands silently on an unprotected link.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- the default, on a link without keys.
	///
	/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
	#[cfg(feature = "aead")]
	fn install_recv_cipher(&mut self, _cipher: RecvCipher) -> TransportResult<()> {
		Err(TransportError::MissingEncryption)
	}

	/// Returns the instrumentation collector inherited from the connection this
	/// half was split from. Planes assembled over the half (mux) adopt it.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		None
	}
}

/// Send side of a split envelope link, the counterpart of [`EnvelopeSource`].
pub trait EnvelopeSink: MaybeSend {
	/// Write `envelope` to the link.
	///
	/// # Errors
	///
	/// - The link's write failure, such as a closed connection, an encode
	///   failure, or an encrypt failure on an encrypting link.
	fn write_envelope(&mut self, envelope: TransportEnvelope) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Returns the number of envelopes still writable before the link demands a
	/// rekey.
	///
	/// A link without keys never rekeys and reports `u64::MAX`.
	fn remaining_records(&self) -> u64;

	/// Install a fresh send-direction cipher at an epoch key-switch boundary
	/// ([RFC 9846 § 4.7.3][rfc9846-4.7.3]).
	///
	/// A link without keys never rekeys, so the default fails closed and an
	/// epoch install never lands silently on an unprotected link.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- the default, on a link without keys.
	///
	/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
	#[cfg(feature = "aead")]
	fn install_send_cipher(&mut self, _cipher: SendCipher) -> TransportResult<()> {
		Err(TransportError::MissingEncryption)
	}

	/// Returns the instrumentation collector inherited from the connection this
	/// half was split from. Planes assembled over the half (mux) adopt it.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		None
	}

	/// Returns the clock inherited from the connection this half was split
	/// from. Planes assembled over the half (mux) adopt it, so one endpoint
	/// reads one clock. A link that carries none reads the system clock.
	#[cfg(host_clock)]
	fn clock(&self) -> Arc<dyn Clock> {
		Arc::new(SystemClock)
	}
}

/// The base I/O operations of a message transport.
///
/// The read and write futures carry an explicit send bound, so generic serving
/// code such as accept loops and single-flight serving can hold them across
/// task spawns. On wasm targets the bound is vacuous.
pub trait MessageIO {
	/// Returns the clock that this transport measures deadlines and backoff
	/// against.
	fn clock(&self) -> &dyn Clock;

	/// Read raw DER-encoded envelope bytes from the transport.
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

	/// Write raw DER-encoded envelope bytes to the transport.
	///
	/// # Errors
	///
	/// - The transport's own write failure.
	fn write_envelope_bytes(&mut self, buffer: &[u8]) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Decode an envelope from DER bytes.
	///
	/// # Errors
	///
	/// - [`TransportError::DerError`] -- `buffer` is not a valid envelope.
	fn decode_envelope(buffer: &[u8]) -> TransportResult<TransportEnvelope> {
		Ok(TransportEnvelope::from_der(buffer)?)
	}

	/// Encode an envelope as DER bytes.
	///
	/// # Errors
	///
	/// - The encode failure of an envelope that does not serialize.
	fn encode_envelope(envelope: &TransportEnvelope) -> TransportResult<Vec<u8>> {
		Ok(encode(envelope)?)
	}

	/// Read and decode a transport envelope.
	///
	/// An encrypted transport may override this method to parse a
	/// [`WireEnvelope`].
	///
	/// # Errors
	///
	/// - The [`read_envelope_bytes`](Self::read_envelope_bytes) and
	///   [`decode_envelope`](Self::decode_envelope) sets.
	fn read_decoded_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend
	where
		Self: MaybeSend,
	{
		async move {
			let bytes = self.read_envelope_bytes().await?;
			Self::decode_envelope(&bytes)
		}
	}

	/// Try to read the next envelope, and tell a graceful close from an error.
	///
	/// - `Ok(Some(envelope))`: a message was read.
	/// - `Ok(None)`: the connection closed gracefully (EOF).
	/// - `Err(..)`: the connection failed unexpectedly.
	///
	/// This method enables keep-alive, because a servlet loops on its
	/// connection and handles requests until the client closes it.
	///
	/// # Default
	///
	/// The default maps the `ConnectionClosed` error variant to `Ok(None)`. A
	/// protocol-specific implementation detects its own EOF conditions, such as
	/// `UnexpectedEof` for TCP, and should override this method to map them to
	/// `Ok(None)`.
	///
	/// # Errors
	///
	/// - The [`read_decoded_envelope`](Self::read_decoded_envelope) set, apart
	///   from the close that maps to `Ok(None)`.
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

/// Outcome of one protocol-agnostic collector step.
#[cfg(all(
	feature = "transport-policy",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub enum CollectStep {
	/// The step read a cleartext handshake container for the server-side
	/// dispatcher, decoded once with the bytes it arrived as.
	Handshake(HandshakeMessage),
	/// The step read a decrypted, or legitimately cleartext, application
	/// envelope.
	Envelope(TransportEnvelope),
}

/// Message I/O with session encryption and the handshake drivers.
#[cfg(feature = "x509")]
pub trait EncryptedMessageIO: MessageIO {
	/// Read one wire envelope, enforce size ceilings, and classify it.
	///
	/// The step is protocol-agnostic. It surfaces a handshake container as a
	/// decoded message for the caller's dispatcher, and it decrypts and returns
	/// everything else.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::SizeExceeded`] -- the wire envelope passes the
	///   ceiling of its kind.
	/// - [`TransportError::MissingEncryption`] -- cleartext traffic arrived
	///   where encryption is required, and the session was reset.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::EncryptionFailed`] -- an encrypted envelope came
	///   before encryption or did not decrypt, and the session was reset.
	/// - The read, decode, and handshake-container conversion failures.
	#[cfg(all(
		feature = "transport-policy",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	#[allow(async_fn_in_trait)]
	async fn collect_step(&mut self) -> TransportResult<CollectStep>
	where
		Self: EncryptedProtocolState + Sized,
	{
		let wire_bytes = self.read_envelope_bytes().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		let ceiling = match &wire_envelope {
			WireEnvelope::Cleartext(_) => self.limits().cleartext_envelope,
			WireEnvelope::Encrypted(_) => self.limits().encrypted_envelope,
		};
		if wire_bytes.len() > ceiling {
			return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		}

		// An established session admits only encrypted traffic. Before that, a
		// provisioned endpoint admits only the handshake containers, and an
		// unprovisioned one admits traffic.
		let established = self.session_state().phase().requires_encryption();
		let expects_encryption = self.session_state().phase().is_handshake_pending();
		match wire_envelope {
			WireEnvelope::Cleartext(envelope) => {
				if established {
					// Circuit breaker: a cleartext frame on an agreed session
					// is not the peer this session established (CWE-319).
					self.session_state_mut().reset();
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
							self.session_state_mut().reset();
							Err(TransportError::MissingEncryption)
						}
					}
				} else {
					Ok(CollectStep::Envelope(envelope))
				}
			}
			WireEnvelope::Encrypted(encrypted_info) => {
				if !matches!(self.session_state().phase(), SessionPhase::Encrypted(_)) {
					self.session_state_mut().reset();
					return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
				}

				let decrypted_bytes = match self.session_state().decryptor()?.decrypt_content(&encrypted_info) {
					Ok(bytes) => bytes,
					Err(_) => {
						self.session_state_mut().reset();
						return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
					}
				};

				let envelope = decrypted_bytes.with(|bytes| Self::decode_envelope(bytes))?;
				Ok(CollectStep::Envelope(envelope))
			}
		}
	}

	/// Wrap a message in a request [`TransportEnvelope`].
	///
	/// The default is protocol-agnostic.
	fn wrap_message(message: Frame) -> TransportEnvelope {
		TransportEnvelope::new_request(message)
	}

	/// Read one envelope, naming a close by the phase it interrupted.
	///
	/// The session phase already records whether a handshake is outstanding,
	/// so it decides how an end of stream reads and every caller on this
	/// session gets the same answer.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerClosedBeforeHandshake`] -- the peer ended the
	///   stream while a handshake was pending, so no session was agreed.
	/// - [`TransportError::ConnectionClosed`] -- the peer ended the stream on a
	///   session already agreed, whether cleartext or encrypted.
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

	/// Wrap and encrypt a message into a [`WireEnvelope`].
	///
	/// The default is protocol-agnostic. The endpoint's own [`TransportLimits`]
	/// size the envelope, so an oversized request fails locally with a typed
	/// `SizeExceeded` that returns the frame, before a peer connection reset.
	///
	/// # Errors
	///
	/// - [`TransportError::MessageNotSent`] -- the envelope did not encode,
	///   encrypt, or fit its ceiling, and the frame travels with the error.
	/// - The [`EncryptedProtocolState::apply_wire_mode`] set, while the handshake has not yet installed keys.
	///
	/// [`TransportLimits`]: crate::transport::TransportLimits
	#[allow(async_fn_in_trait)]
	async fn wrap_and_encrypt_message(&mut self, message: Frame) -> TransportResult<WireEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let builder = EnvelopeBuilder::request(message).with_limits(*self.limits());
		let builder = self.apply_wire_mode(builder)?;
		builder.finish()
	}

	/// Decrypt a response from its encoded bytes.
	///
	/// The default is protocol-agnostic.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- a cleartext answer arrived
	///   on an established session, and the session was reset.
	/// - [`TransportError::DerError`] -- the bytes are not a wire envelope.
	/// - The decrypt failure of an encrypted answer.
	#[allow(async_fn_in_trait)]
	async fn decrypt_response(&mut self, wire_bytes: impl Into<Vec<u8>>) -> TransportResult<TransportEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let wire_bytes: Vec<u8> = wire_bytes.into();
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(env) => {
				// The phase decides the wire mode for both directions, so an
				// established session refuses an unauthenticated cleartext
				// answer (CWE-319) and resets, as the inbound collector does.
				if self.session_state().phase().requires_encryption() {
					self.session_state_mut().reset();
					return Err(TransportError::MissingEncryption);
				}

				Ok(env)
			}
			WireEnvelope::Encrypted(encrypted_info) => {
				let decrypted_bytes = self.session_state().decryptor()?.decrypt_content(&encrypted_info)?;
				decrypted_bytes.with(|bytes| Self::decode_envelope(bytes))
			}
		}
	}

	/// Dual-write the handshake outcome at the transport driver interface.
	///
	/// - A completed handshake records the completion, and the settlement when the session holds a receipt.
	/// - A refused handshake records the audit event its error names: a receipt
	///   approval or settlement refusal, or a rejected certificate or proof.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	fn emit_handshake_outcome(&self, outcome: &TransportResult<()>)
	where
		Self: EncryptedProtocolState,
	{
		let Some(trace) = self.to_trace_ref() else {
			return;
		};

		match outcome {
			// A multi-round server handshake reports `Ok` per round, so only
			// the encrypted phase marks the session as established.
			Ok(()) => {
				if !matches!(self.session_state().phase(), SessionPhase::Encrypted(_)) {
					return;
				}

				trace.emit_event(events::SESSION_HANDSHAKE_COMPLETE);
				if self.session_state().receipt().is_some() {
					trace.emit_event(events::SESSION_RECEIPT_SETTLED);
				}
			}
			Err(TransportError::HandshakeError(error)) => {
				if let Some(event) = error.audit_event() {
					trace.emit_event(event);
				}
			}
			Err(_) => {}
		}
	}

	/// Run the client handshake when the session is still provisioned.
	///
	/// # Errors
	///
	/// - The [`perform_client_handshake`](Self::perform_client_handshake) set.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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

	/// Build the ECIES client orchestrator from transport state.
	///
	/// The client proves the configured identity when one is present and dials
	/// anonymously otherwise, so both cases run the one driver. The trust
	/// store admits the certificate the server names, so a missing store fails
	/// closed before the client sends anything (CWE-295).
	///
	/// # Errors
	///
	/// - [`TransportError::HandshakeError`] with
	///   [`HandshakeError::MissingTrustStore`] -- no trust store is configured.
	#[cfg(feature = "transport-ecies")]
	fn build_ecies_client_orchestrator<P>(&self) -> TransportResult<BoxedClientHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let encryption = self.encryption();
		let store = encryption.trust_store.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		let validator = Arc::clone(store) as Arc<dyn CertificateValidation>;
		let settings = EciesClientSettings {
			trust: LearnedTrust { validator },
			aad_domain_tag: encryption.aad_domain_tag,
			identity: encryption.client_identity.clone(),
		};

		let mut config = ClientConfig::<Ecies, P>::new(settings);
		config.transport_offer = encryption.mux_offer.as_deref().cloned();
		config.receipt_approver = encryption.receipt_approver.as_ref().map(Arc::clone);

		Ok(Box::new(Handshake::client(config)))
	}

	/// Build the CMS client orchestrator from transport state.
	///
	/// CMS encrypts the base secret to the server's public key up front, so
	/// the server identity comes from the provisioned chain. The client signs
	/// its Finished under its identity, and the server verifies that
	/// signature under the certificate, so a client without one fails closed
	/// before it sends anything.
	///
	/// # Errors
	///
	/// - [`TransportError::HandshakeError`] with
	///   [`HandshakeError::MissingTrustStore`] -- no trust store is configured.
	/// - [`TransportError::MissingServerCertificateChain`] -- no server chain is provisioned.
	/// - [`TransportError::HandshakeError`] with
	///   [`HandshakeError::MutualAuthRequired`] -- no client identity is configured.
	#[cfg(feature = "transport-cms")]
	fn build_cms_client_orchestrator<P>(&self) -> TransportResult<BoxedClientHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let encryption = self.encryption();
		let store = encryption.trust_store.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		let chain = encryption.server_certificate_chain.as_ref();
		let chain = chain.ok_or(TransportError::MissingServerCertificateChain)?;
		let identity = encryption.client_identity.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
		let trust = ProvisionedTrust { identity: Arc::clone(chain).into(), store: Arc::clone(store) };
		let settings = CmsClientSettings { trust, identity: identity.clone() };

		let mut config = ClientConfig::<Cms, P>::new(settings);
		config.security_offer = Some(SecurityOffer::new(vec![RunnableProfile::<P>::native().descriptor()]));
		config.transport_offer = encryption.mux_offer.as_deref().cloned();
		config.receipt_approver = encryption.receipt_approver.as_ref().map(Arc::clone);

		Ok(Box::new(Handshake::client(config)))
	}

	/// Drive the protocol-agnostic client handshake state machine, with bytes
	/// in and bytes out.
	///
	/// Handshake messages cross this interface as containers, so the driver
	/// moves one with no per-protocol knowledge.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- a handshake message passes the
	///   wire ceiling, or the server response arrived encrypted.
	/// - [`TransportError::InvalidState`] -- the session refused the move to the handshaking phase.
	/// - The orchestrator, read, write, and install failures.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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
		// handshake ceiling, because the phase is handshaking.
		let response_wire_bytes = self.read_session_bytes().await?;
		let response_wire = WireEnvelope::from_der(&response_wire_bytes)?;
		let response_envelope = match response_wire {
			WireEnvelope::Cleartext(env) => env,
			WireEnvelope::Encrypted(_) => {
				// A handshake message must travel in cleartext.
				return Err(TransportError::InvalidMessage);
			}
		};

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

	/// Perform the client-side handshake with the configured protocol.
	///
	/// # Errors
	///
	/// - [`TransportError::UnsupportedHandshakeProtocol`] -- this build lacks the configured protocol.
	/// - The orchestrator build failure, and the
	///   [`drive_client_handshake`](Self::drive_client_handshake) set.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let kind = self.encryption().handshake_protocol;
		let orchestrator = match kind {
			#[cfg(feature = "transport-ecies")]
			HandshakeProtocolKind::Ecies => self.build_ecies_client_orchestrator()?,

			#[cfg(feature = "transport-cms")]
			HandshakeProtocolKind::Cms => self.build_cms_client_orchestrator()?,

			#[cfg(not(all(feature = "transport-cms", feature = "transport-ecies")))]
			unsupported => return Err(TransportError::UnsupportedHandshakeProtocol(unsupported)),
		};

		let outcome = self.drive_client_handshake(orchestrator).await;

		#[cfg(feature = "instrument")]
		self.emit_handshake_outcome(&outcome);

		outcome
	}

	/// Returns the server configuration that every protocol shares, around the
	/// settings of flow `F`.
	///
	/// The server runs the one profile its provider names, so the profile list
	/// always holds that profile.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- no key manager is configured.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn server_config<F, P>(&self, flow: F::Settings) -> TransportResult<ServerConfig<F, P>>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		F: ServerFlow<P>,
		P: HandshakeProvider,
	{
		let encryption = self.encryption();
		let key_manager = encryption.key_manager.as_ref().ok_or(TransportError::MissingEncryption)?;
		let profiles = SupportedProfiles::from(RunnableProfile::<P>::native().descriptor());

		let mut config = ServerConfig::new(flow, key_manager.signing_provider(), profiles);
		config.peer_authentication = encryption.peer_authentication.clone();
		config.transport = encryption.mux_offer.as_deref().cloned();
		config.transport_authorizer = encryption.transport_authorizer.as_ref().map(Arc::clone);
		config.session_observer = encryption.session_observer.as_ref().map(Arc::clone);
		Ok(config)
	}

	/// Build the ECIES server orchestrator from transport state.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- no server certificate or key manager is configured.
	#[cfg(feature = "transport-ecies")]
	fn build_ecies_server_orchestrator<P>(&self) -> TransportResult<BoxedServerHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let encryption = self.encryption();
		let certificate = encryption.server_certificate.as_ref();
		let certificate = certificate.ok_or(TransportError::MissingEncryption)?;
		let certificate = Arc::clone(certificate);
		let settings = EciesServerSettings { certificate, aad_domain_tag: encryption.aad_domain_tag };

		let config = self.server_config::<Ecies, P>(settings)?;
		Ok(Box::new(Handshake::server(config)))
	}

	/// Build the CMS server orchestrator from transport state.
	///
	/// # Errors
	///
	/// - [`TransportError::MissingEncryption`] -- no key manager is configured.
	#[cfg(feature = "transport-cms")]
	fn build_cms_server_orchestrator<P>(&self) -> TransportResult<BoxedServerHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: HandshakeProvider,
	{
		let config = self.server_config::<Cms, P>(CmsServerSettings)?;
		Ok(Box::new(Handshake::server(config)))
	}

	/// Drive the protocol-agnostic server handshake state machine.
	///
	/// The persisted orchestrator must already exist.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- no orchestrator is persisted, or
	///   the session refused the move to the handshaking phase.
	/// - [`TransportError::InvalidMessage`] -- the response passes the wire ceiling.
	/// - The orchestrator, write, and install failures.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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

			// The transition is attempted first, so a refused move emits
			// nothing. Writing before the refusal would send a handshake
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

	/// Perform the server-side handshake with the configured protocol.
	///
	/// # Deadline
	///
	/// The tokio runtime supplies the timer. The handshake deadline bounds all
	/// processing on the unauthenticated path, including the authorizer and
	/// observer hooks, as well as the reads. A non-tokio runtime has no
	/// portable timer here and relies on the embedding application.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the request passes the wire ceiling.
	/// - [`TransportError::UnsupportedHandshakeProtocol`] -- this build lacks the configured protocol.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::DeadlineExceeded`] -- the handshake deadline elapsed.
	/// - The orchestrator build failure, and the
	///   [`drive_server_handshake`](Self::drive_server_handshake) set.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake<P>(&mut self, request: HandshakeMessage) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: HandshakeProvider,
	{
		if request.der().len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		let kind = self.encryption().handshake_protocol;

		// The orchestrator persists across messages, so it is created once.
		if self.server_handshake_mut().is_none() {
			let orchestrator = match kind {
				#[cfg(feature = "transport-ecies")]
				HandshakeProtocolKind::Ecies => self.build_ecies_server_orchestrator()?,

				#[cfg(feature = "transport-cms")]
				HandshakeProtocolKind::Cms => self.build_cms_server_orchestrator()?,

				#[cfg(not(all(feature = "transport-cms", feature = "transport-ecies")))]
				unsupported => return Err(TransportError::UnsupportedHandshakeProtocol(unsupported)),
			};

			*self.server_handshake_mut() = Some(orchestrator);
		}

		#[cfg(all(feature = "tokio", feature = "std", not(target_arch = "wasm32")))]
		let outcome = {
			let now = self.clock().monotonic();
			let policy = self.session_state().phase().read_policy(self.limits(), now);
			match policy.remaining(now)? {
				Some(remaining) => timeout(remaining, self.drive_server_handshake(request)).await?,
				None => self.drive_server_handshake(request).await,
			}
		};

		#[cfg(not(all(feature = "tokio", feature = "std", not(target_arch = "wasm32"))))]
		let outcome = self.drive_server_handshake(request).await;

		#[cfg(feature = "instrument")]
		self.emit_handshake_outcome(&outcome);

		outcome
	}

	/// Perform a single request-response cycle.
	///
	/// It returns `(status, response, original_message)`. The original message
	/// is `Some` when `status` is not `Ok` and the request went out in
	/// cleartext, so the caller can evaluate a retry.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the reply is not a response envelope.
	/// - The [`wrap_and_encrypt_message`](Self::wrap_and_encrypt_message),
	///   [`read_session_bytes`](Self::read_session_bytes), and
	///   [`decrypt_response`](Self::decrypt_response) sets.
	#[cfg(feature = "x509")]
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
			TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
				return Err(TransportError::InvalidMessage)
			}
			#[cfg(feature = "transport-multiplex")]
			TransportEnvelope::Mux(_) => return Err(TransportError::InvalidMessage),
		};

		// A refused cleartext request returns its frame for retry evaluation.
		let returned_message = if status != TransitStatus::Ok {
			match wire_envelope {
				WireEnvelope::Cleartext(TransportEnvelope::Request(pkg)) => Some(pkg.message),
				_ => None, // Encrypted - can't extract original
			}
		} else {
			None
		};

		let response_frame = response.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		let returned_frame = returned_message.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		Ok((status, response_frame, returned_frame))
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
			#[cfg(feature = "x509")]
			TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => Err(TransportError::InvalidMessage),
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

	#[cfg(feature = "aead")]
	use crate::crypto::aead::SessionKeys;
	#[cfg(feature = "aead")]
	use crate::crypto::x509::policy::ExpiryValidator;
	#[cfg(feature = "aead")]
	use crate::transport::handshake::PeerAuthentication;
	#[cfg(feature = "aead")]
	use crate::transport::TransportLimits;

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

	/// A probe that reads EOF on every call, in the session phase that the case
	/// under test sets.
	#[cfg(feature = "aead")]
	struct ClosedStreamProbe {
		state: SessionState<DefaultCryptoProvider>,
		limits: TransportLimits,
		clock: ManualClock,
	}

	#[cfg(feature = "aead")]
	impl ClosedStreamProbe {
		/// Returns a provisioned endpoint placed directly in `phase`.
		fn at(phase: SessionPhase) -> Self {
			let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
			let peer_authentication = PeerAuthentication::mutual([validator]);
			let encryption = EncryptionConfig { peer_authentication, ..EncryptionConfig::unconfigured() };

			Self {
				state: SessionState::at(encryption, phase),
				limits: TransportLimits::default(),
				clock: ManualClock::default(),
			}
		}
	}

	#[cfg(feature = "aead")]
	impl MessageIO for ClosedStreamProbe {
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

	#[cfg(feature = "aead")]
	impl EncryptedMessageIO for ClosedStreamProbe {}

	#[cfg(feature = "aead")]
	impl crate::transport::state::sealed::Sealed for ClosedStreamProbe {}

	#[cfg(feature = "aead")]
	impl EncryptedProtocolState for ClosedStreamProbe {
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
	}

	#[cfg(feature = "aead")]
	fn encrypted_phase() -> SessionPhase {
		use crate::crypto::aead::{Aes256Gcm, DirectionalCiphers, KeyInit};

		let keys = SessionKeys::for_client(DirectionalCiphers {
			client_to_server: Aes256Gcm::new(&[0u8; 32].into()),
			server_to_client: Aes256Gcm::new(&[1u8; 32].into()),
		});

		SessionPhase::Encrypted(Box::new(EstablishedSession::new(keys, None, None, None, None)))
	}

	#[cfg(feature = "aead")]
	fn handshaking_phase() -> SessionPhase {
		SessionPhase::Handshaking { initiated_at: ManualClock::default().monotonic() }
	}

	// The session phase decides how an end of stream reads. A session that
	// agreed its terms reports an ordinary close, so a pool evicts the
	// connection instead of recording a handshake failure.
	#[cfg(feature = "aead")]
	crate::tb_cases! {
		fn a_close_is_named_by_the_phase_it_interrupts((phase, expected): (SessionPhase, TransportError))
			-> TransportResult<()>
		{
			let mut probe = ClosedStreamProbe::at(phase);
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

	/// Cases of `(label, envelope bytes, whether ingress accepts them)`.
	fn version_envelope_cases() -> crate::error::Result<Vec<(&'static str, Vec<u8>, bool)>> {
		let frame = TestFrame::prioritized();
		let request = TransportEnvelope::Request(RequestPackage::new(frame.clone()));
		let response = TransportEnvelope::Response(ResponsePackage::new(TransitStatus::Ok, Some(frame.clone())));
		let empty_response = TransportEnvelope::Response(ResponsePackage::new(TransitStatus::Ok, None));

		Ok(vec![
			(
				"request V0+priority",
				TestFrame::forge_version(&request, &frame, Version::V0),
				false,
			),
			("request V2+priority", crate::encode(&request)?, true),
			(
				"response V0+priority",
				TestFrame::forge_version(&response, &frame, Version::V0),
				false,
			),
			("response without frame", crate::encode(&empty_response)?, true),
		])
	}

	#[test]
	fn decode_ingress_refuses_a_field_the_frame_version_forbids() -> crate::error::Result<()> {
		for (label, bytes, accepted) in version_envelope_cases()? {
			let decoded = <DecodeProbe as MessageIO>::decode_envelope(&bytes);
			assert_eq!(decoded.is_ok(), accepted, "{label}");
		}
		Ok(())
	}
}
