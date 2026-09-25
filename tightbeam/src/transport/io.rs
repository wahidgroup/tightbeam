//! Envelope I/O over a transport, in cleartext and in encrypted form.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(all(not(feature = "std"), feature = "transport-ecies"))]
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
	pub use core::time::Duration;

	pub use tokio::time::timeout;

	pub use crate::transport::error::TransportFailure;
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
		pub use crate::crypto::aead::KeyInit;
		pub use crate::crypto::profiles::CryptoProvider;
		pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
		pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
		pub use crate::crypto::sign::Verifier;
		pub use crate::spki::EncodePublicKey;
		pub use crate::transport::handshake::negotiation::RunnableProfile;
		pub use crate::transport::handshake::{
			BoxedClientHandshake, BoxedServerHandshake, ClientHandshakeProtocol, HandshakeError, HandshakeMessage,
			HandshakeProtocolKind, ServerHandshakeProtocol,
		};
		pub use crate::transport::state::SessionPhase;
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use handshake::*;

	#[cfg(feature = "transport-ecies")]
	mod ecies {
		pub use crate::crypto::ecies::{EciesEphemeral, EciesPublicKeyOps};
		pub use crate::crypto::sign::SignatureEncoding;
		pub use crate::der::oid::AssociatedOid;
		pub use crate::transport::handshake::client::{EciesHandshakeClient, ExtractVerifyingKey};

		#[cfg(feature = "std")]
		pub use crate::crypto::x509::policy::CertificateValidation;
	}

	#[cfg(feature = "transport-ecies")]
	pub use ecies::*;

	#[cfg(feature = "transport-cms")]
	mod cms {
		pub use crate::transport::handshake::negotiation::SecurityOffer;
		pub use crate::transport::handshake::CmsClientConfig;
	}

	#[cfg(feature = "transport-cms")]
	pub use cms::*;

	#[cfg(all(
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	mod rekey {
		pub(crate) use crate::transport::handshake::receipt::ReceiptSigner;
		pub(crate) use crate::transport::handshake::HandshakeVerifyingKey;
		pub use crate::transport::multiplex::{MuxRekeyContext, MuxRole};
		pub(crate) use crate::transport::rekey::{ClientRekey, RekeyDriver, RekeyMaterials, ServerRekey};
	}

	#[cfg(all(
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) use rekey::*;
}

#[cfg(feature = "x509")]
use x509::*;

/// Remaining allowance before the handshake deadline elapses.
///
/// - A fresh handshake receives the full configured timeout.
/// - An in-flight handshake receives the unexpired remainder of its deadline.
#[cfg(all(
	feature = "tokio",
	feature = "std",
	not(target_arch = "wasm32"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
fn remaining_handshake_deadline<T: EncryptedProtocolState + MessageIO>(state: &T) -> Duration {
	let allowance = state.to_handshake_timeout();
	let Some(initiated_at) = state.session_state().phase().initiated_at() else {
		return allowance;
	};

	// A deadline past every reading never arrives, so the full allowance
	// stands.
	let Some(deadline) = initiated_at.checked_add(allowance) else {
		return allowance;
	};

	let now = state.clock().monotonic();
	deadline.saturating_duration_since(now)
}

/// Harvest the in-band rekey context from a completed receipt-bearing
/// handshake.
///
/// [`MuxTransport::with_rekey`] consumes the result. The function is
/// crate-internal, so the transport's [`MuxConnector::take_rekey`] or
/// [`MuxAcceptor::take_rekey`] always fixes the endpoint role.
///
/// # Returns
///
/// - `Ok(Some(..))` at most once per handshake, because the call detaches the
///   retained epoch materials.
/// - `Ok(None)` when the session carries no dual-signed receipt, no retained
///   peer identity, or no epoch materials.
///
/// # Errors
///
/// - `EncryptorUnavailable` when no handshake completed.
/// - An extraction error when the peer key or the signer identifier fails to extract.
///
/// [`MuxTransport::with_rekey`]: crate::transport::multiplex::MuxTransport::with_rekey
/// [`MuxConnector::take_rekey`]: crate::transport::multiplex::MuxConnector::take_rekey
/// [`MuxAcceptor::take_rekey`]: crate::transport::multiplex::MuxAcceptor::take_rekey
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) fn take_rekey_context<T, P>(state: &mut T, role: MuxRole) -> TransportResult<Option<MuxRekeyContext>>
where
	T: EncryptedProtocolState<CryptoProvider = P>,
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey: From<PublicKey<P::Curve>>,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::AeadCipher: KeyInit + 'static,
{
	let Some(stored) = state.session_state().receipt().cloned() else {
		return Ok(None);
	};
	let Some(provider) = state
		.encryption()
		.key_manager
		.as_ref()
		.map(|manager| manager.signing_provider())
	else {
		return Ok(None);
	};

	let Some(peer_certificate) = state.session_state().peer_certificate_arc() else {
		return Ok(None);
	};

	let public_key = peer_certificate.verifying_key::<P::Curve>()?;
	let peer_verifying_key = P::VerifyingKey::from(public_key);
	let peer_sid = peer_certificate.signer_identifier::<P::Digest>()?;

	// Detached last so a session refused above keeps its materials
	let Some(epoch) = state.session_state_mut().take_epoch_materials() else {
		return Ok(None);
	};

	let reference_receipt = stored.receipt().clone();
	let materials = RekeyMaterials::<P>::new(epoch, reference_receipt, provider, peer_verifying_key, peer_sid);

	let driver = match role {
		MuxRole::Client => {
			let exchange = ClientRekey::new(materials, state.encryption().receipt_approver.as_ref().map(Arc::clone));
			RekeyDriver::client(exchange)
		}
		MuxRole::Server => {
			let exchange = ServerRekey::new(
				materials,
				state.encryption().transport_authorizer.as_ref().map(Arc::clone),
				state.encryption().session_observer.as_ref().map(Arc::clone),
				Some(peer_certificate),
			);
			RekeyDriver::server(exchange)
		}
	};

	Ok(Some(MuxRekeyContext { driver, receipt: stored }))
}

/// Decode a `TransportEnvelope` from DER bytes.
///
/// This is the single decode path that [`MessageIO::decode_envelope`] and the
/// split transport halves share. The frame decoder rejects a frame that carries
/// a field its version forbids.
pub(crate) fn decode_transport_envelope(buffer: &[u8]) -> TransportResult<TransportEnvelope> {
	let envelope = TransportEnvelope::from_der(buffer)?;
	Ok(envelope)
}

/// Receive side of a split envelope link.
///
/// Decouples the [`MuxTransport`](crate::transport::multiplex::MuxTransport)
/// router from the link's protection policy: an encrypting implementation
/// decrypts and enforces AEAD sequencing, a cleartext one enforces neither.
pub trait EnvelopeSource: MaybeSend {
	/// Read the next envelope from the link.
	fn read_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend;

	/// The number of envelopes still readable before the link demands a
	/// rekey.
	///
	/// The count tracks the peer's send counter on the ordered channel, so a
	/// rekey initiator watches the receive direction with no new protocol
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
	/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
	#[cfg(feature = "aead")]
	fn install_recv_cipher(&mut self, _cipher: RecvCipher) -> TransportResult<()> {
		Err(TransportError::MissingEncryption)
	}

	/// Instrumentation collector inherited from the connection this half
	/// was split from. Planes assembled over the half (mux) adopt it.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		None
	}
}

/// Send side of a split envelope link.
///
/// Send-direction counterpart of [`EnvelopeSource`].
pub trait EnvelopeSink: MaybeSend {
	/// Write `envelope` to the link.
	fn write_envelope(&mut self, envelope: TransportEnvelope) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// The number of envelopes still writable before the link demands a
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
	/// [rfc9846-4.7.3]: https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3
	#[cfg(feature = "aead")]
	fn install_send_cipher(&mut self, _cipher: SendCipher) -> TransportResult<()> {
		Err(TransportError::MissingEncryption)
	}

	/// Instrumentation collector inherited from the connection this half
	/// was split from. Planes assembled over the half (mux) adopt it.
	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		None
	}
}

/// The base I/O operations of a message transport.
///
/// The read and write futures carry an explicit send bound, so generic serving
/// code such as accept loops and single-flight serving can hold them across
/// task spawns. On wasm targets the bound is vacuous.
pub trait MessageIO {
	/// The clock this transport measures deadlines and backoff against.
	fn clock(&self) -> &dyn Clock;

	/// Read raw DER-encoded envelope bytes from the transport.
	fn read_envelope_bytes(&mut self) -> impl Future<Output = TransportResult<Vec<u8>>> + MaybeSend;

	/// Write raw DER-encoded envelope bytes to the transport.
	fn write_envelope_bytes(&mut self, buffer: &[u8]) -> impl Future<Output = TransportResult<()>> + MaybeSend;

	/// Decode an envelope from DER bytes.
	fn decode_envelope(buffer: &[u8]) -> TransportResult<TransportEnvelope> {
		decode_transport_envelope(buffer)
	}

	/// Encode an envelope as DER bytes.
	fn encode_envelope(envelope: &TransportEnvelope) -> TransportResult<Vec<u8>> {
		Ok(encode(envelope)?)
	}

	/// Read and decode a transport envelope.
	///
	/// An encrypted transport may override this method to parse a
	/// [`WireEnvelope`].
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
#[cfg(feature = "x509")]
pub trait EncryptedMessageIO: MessageIO {
	/// Read one envelope in cleartext or in encrypted form.
	#[allow(async_fn_in_trait)]
	async fn relay_message(&mut self) -> TransportResult<TransportEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let wire_bytes = self.read_envelope_bytes().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(transport_envelope) => {
				// A server with a decryptor configured refuses cleartext.
				if self.session_state().decryptor().is_ok() {
					return Err(TransportError::MissingEncryption);
				}

				Ok(transport_envelope)
			}
			WireEnvelope::Encrypted(encrypted_info) => {
				let decrypted_bytes = self.session_state().decryptor()?.decrypt_content(&encrypted_info)?;
				decrypted_bytes.with(|bytes| Self::decode_envelope(bytes))
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
				// established session refuses a cleartext answer and its
				// unauthenticated content (CWE-319). The session breaks here,
				// as it does in the inbound collector.
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
	/// The outcome is a completion, or a receipt approval or settlement
	/// refusal.
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
			// Multi-round server handshakes report Ok per round.
			// Only the completed state marks the session as established.
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
	#[cfg(feature = "transport-ecies")]
	#[allow(async_fn_in_trait)]
	async fn ensure_handshake_complete<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + EncryptedProtocolState<CryptoProvider = P>,
		// Curve and elliptic curve bounds
		P: CryptoProvider + Default + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic + AssociatedOid,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EciesPublicKeyOps + EncodePublicKey,
		<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
		// Signature bounds
		P::Signature: SignatureEncoding,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		for<'b> <P::Signature as TryFrom<&'b [u8]>>::Error: Into<HandshakeError>,
		P::VerifyingKey: Verifier<P::Signature> + ExtractVerifyingKey + From<PublicKey<P::Curve>> + EncodePublicKey,
		// AEAD bound
		P::AeadCipher: KeyInit,
	{
		let should_handshake = matches!(self.session_state().phase(), SessionPhase::Provisioned);
		if should_handshake {
			self.perform_client_handshake().await?;
		}

		Ok(())
	}

	/// Run the client handshake when the session is still provisioned, in the
	/// CMS-only build.
	///
	/// Trait where-clauses do not elaborate to callers, so each feature
	/// combination declares the dispatcher with that build's predicate set.
	#[cfg(all(not(feature = "transport-ecies"), feature = "transport-cms"))]
	#[allow(async_fn_in_trait)]
	async fn ensure_handshake_complete<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Default + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EncodePublicKey,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync,
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
	/// anonymously otherwise, so both cases run the one driver.
	#[cfg(feature = "transport-ecies")]
	fn build_ecies_client_orchestrator<P>(&self) -> TransportResult<BoxedClientHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Default + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EciesPublicKeyOps,
		<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
		P::Signature: SignatureEncoding + 'static,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		for<'b> <P::Signature as TryFrom<&'b [u8]>>::Error: Into<HandshakeError>,
		P::VerifyingKey: Verifier<P::Signature> + ExtractVerifyingKey + 'static,
		P::AeadCipher: KeyInit + Send + Sync,
	{
		let encryption = self.encryption();
		let identity = encryption.client_identity.clone();
		let mut client =
			EciesHandshakeClient::<P, P::EciesMessage>::new_with_identity(Some(encryption.aad_domain_tag), identity);

		// The trust store validates the server certificate.
		#[cfg(all(feature = "x509", feature = "std"))]
		if let Some(store) = encryption.trust_store.as_ref() {
			let validator = Arc::clone(store) as Arc<dyn CertificateValidation>;
			client = client.with_certificate_validator(validator);
		}

		// The client offers multiplexing when it is locally configured.
		if let Some(offer) = encryption.mux_offer.as_deref().cloned() {
			client = client.with_transport_offer(offer);
		}

		// A budget-bearing session needs the receipt approver.
		if let Some(approver) = encryption.receipt_approver.as_ref().map(Arc::clone) {
			client = client.with_receipt_approver(approver);
		}

		Ok(Box::new(client))
	}

	/// Build the CMS client orchestrator from transport state.
	///
	/// CMS encrypts the session key to the server's public key up front, so
	/// the server identity comes from the provisioned chain. A missing trust
	/// store or chain fails closed.
	#[cfg(feature = "transport-cms")]
	fn build_cms_client_orchestrator<P>(&self) -> TransportResult<BoxedClientHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Default + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EncodePublicKey,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync,
	{
		let key = self
			.encryption()
			.key_manager
			.as_ref()
			.ok_or(TransportError::MissingEncryption)?;
		let store = self
			.encryption()
			.trust_store
			.as_ref()
			.ok_or(TransportError::HandshakeError(HandshakeError::MissingTrustStore))?;
		let chain = self
			.encryption()
			.server_certificate_chain
			.as_ref()
			.ok_or(TransportError::MissingServerCertificateChain)?;

		let trust_store = Arc::clone(store);
		let server_identity = Arc::clone(chain).into();
		let security_offer = Some(SecurityOffer::new(vec![RunnableProfile::<P>::native().descriptor()]));
		let client_certificate = self
			.encryption()
			.client_identity
			.as_ref()
			.map(|identity| identity.certificate_arc());

		Ok(key.create_cms_client(CmsClientConfig {
			server_identity,
			trust_store,
			security_offer,
			transport_offer: self.encryption().mux_offer.as_deref().cloned(),
			client_certificate,
			receipt_approver: self.encryption().receipt_approver.as_ref().map(Arc::clone),
		})?)
	}

	/// Drive the protocol-agnostic client handshake state machine, with bytes
	/// in and bytes out.
	///
	/// Handshake messages cross this interface as containers, so the driver
	/// moves one with no per-protocol knowledge.
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

		// Step 2: Receive the server response.
		let response_wire_bytes = self.read_session_bytes().await?;
		if response_wire_bytes.len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		let response_wire = WireEnvelope::from_der(&response_wire_bytes)?;
		let response_envelope = match response_wire {
			WireEnvelope::Cleartext(env) => env,
			WireEnvelope::Encrypted(_) => {
				// A handshake message must travel in cleartext.
				return Err(TransportError::InvalidMessage);
			}
		};

		let response = HandshakeMessage::try_from(response_envelope)?;
		if response.der().len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		// Step 3: Handle the server response, which may yield the next message.
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
		if !self.session_state_mut().install_session(session) {
			return Err(TransportError::InvalidState);
		}

		Ok(())
	}

	/// Perform the client-side handshake with the configured protocol.
	#[cfg(feature = "transport-ecies")]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P>,
		// Curve and elliptic curve bounds
		P: CryptoProvider + Default + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic + AssociatedOid,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EciesPublicKeyOps + EncodePublicKey,
		<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
		// Signature bounds
		P::Signature: SignatureEncoding + 'static,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		for<'b> <P::Signature as TryFrom<&'b [u8]>>::Error: Into<HandshakeError>,
		P::VerifyingKey:
			Verifier<P::Signature> + ExtractVerifyingKey + From<PublicKey<P::Curve>> + EncodePublicKey + 'static,
		// Digest and AEAD bounds
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync,
	{
		let kind = self.encryption().handshake_protocol;
		let orchestrator = match kind {
			HandshakeProtocolKind::Ecies => self.build_ecies_client_orchestrator()?,

			#[cfg(feature = "transport-cms")]
			HandshakeProtocolKind::Cms => self.build_cms_client_orchestrator()?,

			#[cfg(not(feature = "transport-cms"))]
			HandshakeProtocolKind::Cms => {
				return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Cms));
			}
		};

		let outcome = self.drive_client_handshake(orchestrator).await;

		#[cfg(feature = "instrument")]
		self.emit_handshake_outcome(&outcome);

		outcome
	}

	/// Perform the client-side handshake in the CMS-only build.
	///
	/// Trait where-clauses do not elaborate to callers, so each feature
	/// combination declares the dispatcher with that build's predicate set.
	#[cfg(all(not(feature = "transport-ecies"), feature = "transport-cms"))]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake<P>(&mut self) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Default + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EncodePublicKey,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync,
	{
		let kind = self.encryption().handshake_protocol;
		let orchestrator = match kind {
			HandshakeProtocolKind::Ecies => {
				return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Ecies));
			}
			HandshakeProtocolKind::Cms => self.build_cms_client_orchestrator()?,
		};

		let outcome = self.drive_client_handshake(orchestrator).await;

		#[cfg(feature = "instrument")]
		self.emit_handshake_outcome(&outcome);

		outcome
	}

	/// Build the ECIES server orchestrator from transport state.
	#[cfg(feature = "transport-ecies")]
	fn build_ecies_server_orchestrator<P>(&self) -> TransportResult<BoxedServerHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		P::Signature: SignatureEncoding,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		P::VerifyingKey: Verifier<P::Signature> + for<'b> From<&'b PublicKey<P::Curve>>,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		let cert_arc = self
			.encryption()
			.server_certificate
			.as_ref()
			.map(Arc::clone)
			.ok_or(TransportError::MissingEncryption)?;
		let key_manager = self
			.encryption()
			.key_manager
			.as_ref()
			.ok_or(TransportError::MissingEncryption)?;

		let peer_authentication = self.encryption().peer_authentication.clone();
		let supported_profiles = vec![RunnableProfile::<P>::native().descriptor()];

		Ok(key_manager.create_ecies_server(
			cert_arc,
			Some(self.encryption().aad_domain_tag),
			supported_profiles,
			peer_authentication,
			self.encryption().mux_offer.as_deref().cloned(),
			self.encryption().transport_authorizer.as_ref().map(Arc::clone),
			self.encryption().session_observer.as_ref().map(Arc::clone),
		)?)
	}

	/// Build the CMS server orchestrator from transport state.
	#[cfg(feature = "transport-cms")]
	fn build_cms_server_orchestrator<P>(&self) -> TransportResult<BoxedServerHandshake>
	where
		Self: EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		let key_manager = self
			.encryption()
			.key_manager
			.as_ref()
			.ok_or(TransportError::MissingEncryption)?;

		let peer_authentication = self.encryption().peer_authentication.clone();
		let supported_profiles = vec![RunnableProfile::<P>::native().descriptor()];

		Ok(key_manager.create_cms_server(
			peer_authentication,
			supported_profiles,
			self.encryption().mux_offer.as_deref().cloned(),
			self.encryption().transport_authorizer.as_ref().map(Arc::clone),
			self.encryption().session_observer.as_ref().map(Arc::clone),
		)?)
	}

	/// Drive the protocol-agnostic server handshake state machine.
	///
	/// The persisted orchestrator must already exist.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn drive_server_handshake(&mut self, request: HandshakeMessage) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState + ServerHandshakeSlot,
	{
		let orchestrator = self.server_handshake_mut().as_mut().ok_or(TransportError::InvalidState)?;
		// The client message may yield a response to send.
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
			if !self.session_state_mut().install_session(session) {
				return Err(TransportError::InvalidState);
			}
		}

		Ok(())
	}

	/// Perform the server-side handshake with the configured protocol.
	#[cfg(feature = "transport-ecies")]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake<P>(&mut self, request: HandshakeMessage) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EciesPublicKeyOps,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		for<'b> P::VerifyingKey: From<&'b PublicKey<P::Curve>>,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		if request.der().len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		let kind = self.encryption().handshake_protocol;

		// The orchestrator persists across messages, so it is created once.
		if self.server_handshake_mut().is_none() {
			let orchestrator = match kind {
				HandshakeProtocolKind::Ecies => self.build_ecies_server_orchestrator()?,

				#[cfg(feature = "transport-cms")]
				HandshakeProtocolKind::Cms => self.build_cms_server_orchestrator()?,

				#[cfg(not(feature = "transport-cms"))]
				HandshakeProtocolKind::Cms => {
					return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Cms));
				}
			};

			*self.server_handshake_mut() = Some(orchestrator);
		}

		// The tokio runtime supplies the timer. The handshake deadline bounds
		// all processing on the unauthenticated path, including the authorizer
		// and observer hooks, as well as the reads. A non-tokio runtime has no
		// portable timer here and relies on the embedding application.
		#[cfg(all(feature = "tokio", feature = "std", not(target_arch = "wasm32")))]
		let outcome = {
			let remaining = remaining_handshake_deadline(self);
			if remaining.is_zero() {
				return Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded));
			}

			timeout(remaining, self.drive_server_handshake(request)).await?
		};

		#[cfg(not(all(feature = "tokio", feature = "std", not(target_arch = "wasm32"))))]
		let outcome = self.drive_server_handshake(request).await;

		#[cfg(feature = "instrument")]
		self.emit_handshake_outcome(&outcome);

		outcome
	}

	/// Perform the server-side handshake in the CMS-only build.
	///
	/// Trait where-clauses do not elaborate to callers, so each feature
	/// combination declares the dispatcher with that build's predicate set.
	#[cfg(all(not(feature = "transport-ecies"), feature = "transport-cms"))]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake<P>(&mut self, request: HandshakeMessage) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P> + ServerHandshakeSlot,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		if request.der().len() > self.limits().handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		let kind = self.encryption().handshake_protocol;

		// The orchestrator persists across messages, so it is created once.
		if self.server_handshake_mut().is_none() {
			let orchestrator = match kind {
				HandshakeProtocolKind::Ecies => {
					return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Ecies));
				}
				HandshakeProtocolKind::Cms => self.build_cms_server_orchestrator()?,
			};

			*self.server_handshake_mut() = Some(orchestrator);
		}

		// The tokio runtime supplies the timer. The handshake deadline bounds
		// all processing on the unauthenticated path, including the authorizer
		// and observer hooks, as well as the reads. A non-tokio runtime has no
		// portable timer here and relies on the embedding application.
		#[cfg(all(feature = "tokio", feature = "std", not(target_arch = "wasm32")))]
		let outcome = {
			let remaining = remaining_handshake_deadline(self);
			if remaining.is_zero() {
				return Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded));
			}

			timeout(remaining, self.drive_server_handshake(request)).await?
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

		// Unwrap each `Arc<Frame>`, and clone the frame when another owner
		// holds it.
		let response_frame = response.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		let returned_frame = returned_message.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));

		Ok((status, response_frame, returned_frame))
	}
}

impl TransportEnvelope {
	/// The application request frame inside a single-flight envelope.
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

	/// Minimal `MessageIO` probe so ingress goes through `decode_envelope`.
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
		/// A provisioned endpoint placed directly in `phase`.
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

	// An end of stream reads differently either side of a handshake, and the
	// session phase is what separates the two. A session that already agreed
	// its terms reports an ordinary close, so a pool evicts the connection
	// rather than recording a handshake failure.
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
