//! I/O operations for reading and writing data (cleartext and encrypted)

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

#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(all(
	feature = "std",
	not(target_arch = "wasm32"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use std::time::Instant;

use core::mem;

use crate::asn1::Frame;
use crate::der::{Decode, Encode};
use crate::encode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{TransportEnvelope, WireEnvelope, WireMode};
use crate::transport::error::TransportError;
use crate::transport::messaging::ResponseHandler;
use crate::transport::TransportResult;
use crate::TightBeamError;

#[cfg(feature = "transport-ecies")]
use crate::crypto::ecies::Secp256k1EciesMessage;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::aead::Decryptor;
	pub use crate::transport::builders::{EnvelopeBuilder, EnvelopeLimits};
	pub use crate::transport::handshake::TcpHandshakeState;
	pub use crate::transport::state::EncryptedProtocolState;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	mod handshake {
		pub use crate::crypto::aead::KeyInit;
		pub use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc, TightbeamProfile};
		pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
		pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
		pub use crate::crypto::sign::Verifier;
		pub use crate::spki::EncodePublicKey;
		pub use crate::transport::handshake::{
			BoxedClientHandshake, BoxedServerHandshake, ClientHandshakeProtocol, HandshakeError, HandshakeProtocolKind,
			ServerHandshakeProtocol,
		};
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use handshake::*;

	#[cfg(feature = "transport-ecies")]
	mod ecies {
		pub use crate::cms::enveloped_data::EnvelopedData;
		pub use crate::cms::signed_data::SignedData;
		pub use crate::crypto::aead::SessionKeys;
		pub use crate::crypto::ecies::{EciesEphemeral, EciesMessageOps, EciesPublicKeyOps};
		pub use crate::crypto::sign::SignatureEncoding;
		pub use crate::der::oid::AssociatedOid;
		pub use crate::transport::handshake::client::{EciesHandshakeClient, ExtractVerifyingKey};
		pub use crate::transport::handshake::{ClientHello, ClientKeyExchange, HandshakeFinalization, ServerHandshake};

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
}

#[cfg(feature = "x509")]
use x509::*;

/// Maximum wire size allowed for handshake-phase messages.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) const HANDSHAKE_MAX_WIRE: usize = 16 * 1024; // 16 KiB

/// Parse a DER length field into its numeric value.
pub(crate) fn parse_der_length(first_byte: u8, length_octets: &[u8]) -> Option<usize> {
	if first_byte & 0x80 == 0 {
		return Some(first_byte as usize);
	}

	let octet_count = (first_byte & 0x7F) as usize;
	// 0x80 is the BER indefinite-length marker, forbidden in DER.
	if octet_count == 0 || octet_count != length_octets.len() || octet_count > mem::size_of::<usize>() {
		return None;
	}

	// Canonical form: no leading zero octet, and the long form is only used
	// for values the short form cannot express (>= 128).
	if length_octets[0] == 0 {
		return None;
	}

	let mut length = 0usize;
	for &byte in length_octets.iter() {
		length = (length << 8) | (byte as usize);
	}

	if length < 0x80 {
		return None;
	}

	Some(length)
}

/// Reconstruct a full DER encoding from its parsed tag, length, and content parts.
pub(crate) fn reconstruct_der_encoding(tag: u8, length_first: u8, length_octets: &[u8], content: &[u8]) -> Vec<u8> {
	let length_bytes_count = if length_first & 0x80 == 0 {
		1
	} else {
		1 + length_octets.len()
	};

	let mut buffer = Vec::with_capacity(1 + length_bytes_count + content.len());
	buffer.push(tag);
	buffer.push(length_first);

	if length_first & 0x80 != 0 {
		buffer.extend_from_slice(length_octets);
	}

	buffer.extend_from_slice(content);

	buffer
}

/// Decode a `TransportEnvelope` from DER bytes with version validation.
///
/// Single decode path shared by `MessageIO::decode_envelope` and the split
/// transport halves.
pub(crate) fn decode_transport_envelope(buffer: &[u8]) -> TransportResult<TransportEnvelope> {
	let envelope = TransportEnvelope::from_der(buffer)?;
	if !envelope_versions_compatible(&envelope) {
		return Err(TransportError::InvalidMessage);
	}

	Ok(envelope)
}

/// Check that every frame carried by an inbound envelope satisfies the same
/// version/metadata compatibility the builder enforces at construction.
fn envelope_versions_compatible(envelope: &TransportEnvelope) -> bool {
	match envelope {
		TransportEnvelope::Request(pkg) => pkg.message.validate_version_compatibility(),
		TransportEnvelope::Response(pkg) => {
			pkg.message.as_ref().is_none_or(|frame| frame.validate_version_compatibility())
		}
		#[cfg(feature = "x509")]
		TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => true,
		#[cfg(feature = "transport-multiplex")]
		TransportEnvelope::MuxedRequest(pkg) => pkg.message.validate_version_compatibility(),
		#[cfg(feature = "transport-multiplex")]
		TransportEnvelope::MuxedResponse(pkg) => {
			let message = pkg.response.message.as_ref();
			message.is_none_or(|frame| frame.validate_version_compatibility())
		}
		#[cfg(feature = "transport-multiplex")]
		TransportEnvelope::MuxCancel(_) | TransportEnvelope::GoAway(_) => true,
	}
}

/// Base I/O operations for message transport
pub trait MessageIO: ResponseHandler {
	/// Read raw DER-encoded bytes from the transport
	#[allow(async_fn_in_trait)]
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>>;

	/// Write raw DER-encoded bytes to the transport
	#[allow(async_fn_in_trait)]
	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()>;

	/// Decode envelope from DER bytes
	fn decode_envelope(buffer: &[u8]) -> TransportResult<TransportEnvelope> {
		decode_transport_envelope(buffer)
	}

	/// Encode envelope to DER bytes
	fn encode_envelope(envelope: &TransportEnvelope) -> TransportResult<Vec<u8>> {
		Ok(encode(envelope)?)
	}

	/// Read and decode a transport envelope
	/// This can be overridden by EncryptedMessageIO to handle WireEnvelope parsing
	#[allow(async_fn_in_trait)]
	async fn read_decoded_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let bytes = self.read_envelope().await?;
		Self::decode_envelope(&bytes)
	}

	/// Try to read next envelope, distinguishing graceful close from errors
	///
	/// Returns:
	/// - `Ok(Some(envelope))` - Successfully read a message
	/// - `Ok(None)` - Connection closed gracefully (EOF)
	/// - `Err(...)` - Connection failed unexpectedly
	///
	/// This method enables keep-alive: servlets loop on connections, handling
	/// multiple requests until the client closes the connection.
	///
	/// **Default implementation**: Handles the `ConnectionClosed` error variant but
	/// relies on protocol-specific implementations to detect EOF conditions (e.g.,
	/// `UnexpectedEof` for TCP). Protocols should override to map their EOF errors
	/// to `Ok(None)`.
	#[allow(async_fn_in_trait)]
	async fn try_read_decoded_envelope(&mut self) -> TransportResult<Option<TransportEnvelope>> {
		match self.read_decoded_envelope().await {
			Ok(envelope) => Ok(Some(envelope)),
			Err(TransportError::ConnectionClosed) => Ok(None),
			Err(e) => Err(e),
		}
	}

	/// Send a response back to the sender
	///
	fn handle_message(&self, message: Arc<Frame>) -> Option<Frame> {
		let frame = Arc::try_unwrap(message).unwrap_or_else(|arc| (*arc).clone());
		self.handler().and_then(|handler| handler(frame))
	}

	/// Helper for parsing DER length encoding.
	/// Returns `None` for non-canonical or indefinite-length encodings.
	fn parse_der_length(first_byte: u8, length_octets: &[u8]) -> Option<usize> {
		parse_der_length(first_byte, length_octets)
	}

	/// Helper to reconstruct full DER encoding from parts
	fn reconstruct_der_encoding(tag: u8, length_first: u8, length_octets: &[u8], content: &[u8]) -> Vec<u8> {
		reconstruct_der_encoding(tag, length_first, length_octets, content)
	}
}

#[cfg(feature = "x509")]
pub trait EncryptedMessageIO: MessageIO {
	/// Relay a message by detecting whether it's encrypted or cleartext
	/// Returns the decrypted TransportEnvelope ready for processing
	#[allow(async_fn_in_trait)]
	async fn relay_message(&mut self) -> TransportResult<TransportEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let wire_bytes = self.read_envelope().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(transport_envelope) => {
				// Check if server expects encryption but received cleartext
				if self.to_decryptor_ref().is_ok() {
					// Server has encryption configured, reject cleartext
					return Err(TransportError::MissingEncryption);
				}

				Ok(transport_envelope)
			}
			WireEnvelope::Encrypted(encrypted_info) => {
				let decrypted_bytes = self.to_decryptor_ref()?.decrypt_content(&encrypted_info)?;
				decrypted_bytes
					.with(|bytes| Self::decode_envelope(bytes))
					.map_err(TightBeamError::from)?
			}
		}
	}

	/// Send a cleartext or encrypted envelope based on encryption flag
	#[allow(async_fn_in_trait)]
	async fn send_envelope(&mut self, envelope: TransportEnvelope, encrypt: bool) -> TransportResult<()>
	where
		Self: EncryptedProtocolState,
	{
		let wire_envelope = if encrypt {
			let envelope_bytes = Self::encode_envelope(&envelope)?;
			let encrypted_info = self.to_encryptor_ref()?.encrypt_next(&envelope_bytes, None)?;

			WireEnvelope::Encrypted(encrypted_info)
		} else {
			WireEnvelope::Cleartext(envelope)
		};

		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope(&wire_bytes).await
	}

	/// Wrap a message in a TransportEnvelope
	/// Protocol-agnostic default implementation
	fn wrap_message(message: Frame) -> TransportEnvelope {
		TransportEnvelope::new_request(message)
	}

	/// Wrap and encrypt a message, returning WireEnvelope
	/// Protocol-agnostic default implementation
	#[allow(async_fn_in_trait)]
	async fn wrap_and_encrypt_message(&mut self, message: Frame) -> TransportResult<WireEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let limits = EnvelopeLimits::from_pair(self.to_max_cleartext_envelope(), self.to_max_encrypted_envelope());
		let mut builder = limits.apply(EnvelopeBuilder::request(message));

		if self.to_handshake_state() == TcpHandshakeState::Complete {
			let encryptor = self.to_encryptor_ref()?;
			let wire_mode = WireMode::Encrypted;
			builder = builder.with_wire_mode(wire_mode);
			builder = builder.with_encryptor(encryptor);
		} else {
			let wire_mode = WireMode::Cleartext;
			builder = builder.with_wire_mode(wire_mode);
		}

		builder.finish()
	}

	/// Decrypt a response from wire bytes
	/// Protocol-agnostic default implementation
	#[allow(async_fn_in_trait)]
	async fn decrypt_response(&mut self, wire_bytes: Vec<u8>) -> TransportResult<TransportEnvelope>
	where
		Self: EncryptedProtocolState,
	{
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(env) => Ok(env),
			WireEnvelope::Encrypted(encrypted_info) => {
				let decrypted_bytes = self.to_decryptor_ref()?.decrypt_content(&encrypted_info)?;
				decrypted_bytes
					.with(|bytes| Self::decode_envelope(bytes))
					.map_err(TightBeamError::from)?
			}
		}
	}

	/// Ensure handshake is complete, performing it if needed
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
		let should_handshake = (self.to_server_certificate_ref().is_some()
			|| self.to_trust_store_ref().is_some()
			|| self.is_client_validators_present())
			&& self.to_handshake_state() == TcpHandshakeState::None;

		if should_handshake {
			self.perform_client_handshake().await?;
		}

		Ok(())
	}

	/// Ensure handshake is complete, performing it if needed (CMS-only build variant).
	///
	/// Trait where-clauses do not elaborate to callers, so the dispatcher is
	/// declared per feature combination with that build's predicate set.
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
		let should_handshake = (self.to_server_certificate_ref().is_some()
			|| self.to_trust_store_ref().is_some()
			|| self.is_client_validators_present())
			&& self.to_handshake_state() == TcpHandshakeState::None;

		if should_handshake {
			self.perform_client_handshake().await?;
		}

		Ok(())
	}

	/// Perform client-side ECIES handshake without mutual authentication (K=() variant)
	/// This is a helper method because K=() cannot be cast to trait object due to missing Signer bound
	#[cfg(feature = "transport-ecies")]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake_no_mutual_auth<P>(&mut self) -> TransportResult<()>
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
		P::Signature: SignatureEncoding,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		for<'b> <P::Signature as TryFrom<&'b [u8]>>::Error: Into<HandshakeError>,
		P::VerifyingKey: Verifier<P::Signature> + ExtractVerifyingKey + From<PublicKey<P::Curve>> + EncodePublicKey,
		// AEAD and ECIES message bounds
		P::AeadCipher: KeyInit,
		P::EciesMessage: EciesMessageOps,
	{
		// Create client without mutual auth
		let mut client = EciesHandshakeClient::<P, P::EciesMessage>::new(None);

		// Use trust store for server certificate validation
		#[cfg(all(feature = "x509", feature = "std"))]
		if let Some(store) = self.to_trust_store_ref() {
			let validator = Arc::clone(store) as Arc<dyn CertificateValidation>;
			client = client.with_certificate_validator(validator);
		}

		// Offer transport capabilities (multiplexing) when locally configured
		if let Some(offer) = self.to_mux_config() {
			client = client.with_transport_offer(offer);
		}

		// Step 1: Build and send client hello
		let initial_message = client.build_client_hello()?;
		if initial_message.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		let client_hello = ClientHello::from_der(&initial_message)?;
		let signed_data: SignedData = (&client_hello).try_into().map_err(|_| TransportError::InvalidMessage)?;
		let signed_data = Box::new(signed_data);
		let initial_envelope = TransportEnvelope::SignedData(signed_data);

		let wire_envelope = WireEnvelope::Cleartext(initial_envelope);
		self.write_envelope(&wire_envelope.to_der()?).await?;

		// Update state machine
		#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse { initiated_at: Instant::now() });
		}
		#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse { initiated_at: 0 });
		}

		// Step 2: Receive server response
		let response_wire_bytes = self.read_envelope().await?;
		if response_wire_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		let response_wire = WireEnvelope::from_der(&response_wire_bytes)?;
		let response_envelope = match response_wire {
			WireEnvelope::Cleartext(env) => env,
			WireEnvelope::Encrypted(_) => return Err(TransportError::InvalidMessage),
		};

		let signed_data = match response_envelope {
			TransportEnvelope::SignedData(sd) => sd,
			_ => return Err(TransportError::InvalidMessage),
		};
		let server_handshake: ServerHandshake =
			signed_data.as_ref().try_into().map_err(|_| TransportError::InvalidMessage)?;
		let response_bytes = server_handshake.to_der()?;
		if response_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Step 3: Process server handshake
		let next_message_bytes = client.process_server_handshake(&response_bytes).await?;
		if next_message_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Step 4: Send client key exchange
		let client_kex = ClientKeyExchange::from_der(&next_message_bytes)?;
		let enveloped_data: EnvelopedData = (&client_kex).try_into().map_err(|_| TransportError::InvalidMessage)?;
		let enveloped_data = Box::new(enveloped_data);
		let msg_envelope = TransportEnvelope::EnvelopedData(enveloped_data);

		let wire_envelope = WireEnvelope::Cleartext(msg_envelope);
		self.write_envelope(&wire_envelope.to_der()?).await?;

		// Step 5: Complete handshake and role-map the directional session keys
		let ciphers = client.complete()?;
		let profile = HandshakeFinalization::selected_profile(&client).ok_or(TransportError::InvalidMessage)?;
		let aead_oid = profile.aead.ok_or(TransportError::InvalidMessage)?;

		let session_keys = SessionKeys::for_client(ciphers.client_to_server, ciphers.server_to_client, aead_oid);
		self.set_session_keys(session_keys);
		self.set_mux_settings(client.negotiated_mux());
		self.set_handshake_state(TcpHandshakeState::Complete);

		Ok(())
	}

	/// Build the ECIES client orchestrator (mutual-auth path) from transport state.
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
		// Use trust store for server certificate validation
		#[cfg(all(feature = "x509", feature = "std"))]
		let validator = self
			.to_trust_store_ref()
			.map(|store| Arc::clone(store) as Arc<dyn CertificateValidation>);

		#[cfg(not(all(feature = "x509", feature = "std")))]
		let validator = None;

		let key = self.to_key_manager_ref().ok_or(TransportError::MissingEncryption)?;
		let client_cert = self.to_client_certificate_ref().map(Arc::clone);

		Ok(key.create_ecies_client::<Secp256k1EciesMessage>(
			None,
			client_cert,
			None,
			validator,
			self.to_mux_config(),
		)?)
	}

	/// Build the CMS client orchestrator from transport state.
	///
	/// CMS encrypts the session key to the server's public key up front, so
	/// the server identity comes from the provisioned chain; missing trust
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
		let key = self.to_key_manager_ref().ok_or(TransportError::MissingEncryption)?;
		let store = self
			.to_trust_store_ref()
			.ok_or(TransportError::HandshakeError(HandshakeError::MissingTrustStore))?;
		let chain = self
			.to_server_certificate_chain_ref()
			.ok_or(TransportError::MissingServerCertificateChain)?;

		let trust_store = Arc::clone(store);
		let server_identity = Arc::clone(chain).into();
		let security_offer = Some(SecurityOffer::new(vec![SecurityProfileDesc::from(&TightbeamProfile)]));
		let client_certificate = self.to_client_certificate_ref().map(Arc::clone);

		Ok(key.create_cms_client(CmsClientConfig {
			server_identity,
			trust_store,
			security_offer,
			transport_offer: self.to_mux_config(),
			client_certificate,
		})?)
	}

	/// Protocol-agnostic client handshake state machine: bytes in, bytes out.
	///
	/// The orchestrator produces and consumes raw handshake bytes; `kind`
	/// maps them to and from their wire envelopes.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn drive_client_handshake(
		&mut self,
		kind: HandshakeProtocolKind,
		mut orchestrator: BoxedClientHandshake,
	) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState,
	{
		// Step 1: Start handshake - get initial message
		let initial_message = orchestrator.start().await?;
		if initial_message.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		let initial_envelope = kind.wrap_client_start(&initial_message)?;
		let wire_envelope = WireEnvelope::Cleartext(initial_envelope);
		self.write_envelope(&wire_envelope.to_der()?).await?;

		// Update state machine
		#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse { initiated_at: Instant::now() });
		}
		#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse { initiated_at: 0 });
		}

		// Step 2: Receive server response
		let response_wire_bytes = self.read_envelope().await?;
		if response_wire_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Unwrap WireEnvelope to get TransportEnvelope
		let response_wire = WireEnvelope::from_der(&response_wire_bytes)?;
		let response_envelope = match response_wire {
			WireEnvelope::Cleartext(env) => env,
			WireEnvelope::Encrypted(_) => {
				// Handshake messages must be cleartext
				return Err(TransportError::InvalidMessage);
			}
		};

		let response_bytes = kind.unwrap_server_response(response_envelope)?;
		if response_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Step 3: Handle server response - may return next message to send
		let next_message = orchestrator.handle_response(&response_bytes).await?;

		// Step 4: Send next message if any (multi-round support)
		if let Some(msg_bytes) = next_message {
			if msg_bytes.len() > HANDSHAKE_MAX_WIRE {
				return Err(TransportError::InvalidMessage);
			}

			let msg_envelope = kind.wrap_client_followup(&msg_bytes)?;
			let wire_envelope = WireEnvelope::Cleartext(msg_envelope);
			self.write_envelope(&wire_envelope.to_der()?).await?;
		}

		// Step 5: Complete handshake and get the directional session keys
		let session_keys = orchestrator.complete().await?;

		// Store session keys, negotiated mux settings, and mark handshake complete
		self.set_session_keys(session_keys);
		self.set_mux_settings(orchestrator.negotiated_mux());
		self.set_handshake_state(TcpHandshakeState::Complete);

		Ok(())
	}

	/// Perform client-side handshake (extracted from macro)
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
		let kind = self.to_handshake_protocol_kind();

		// Branch: Handle ECIES without mutual auth separately (K=() cannot be trait object)
		if matches!(kind, HandshakeProtocolKind::Ecies) && self.to_key_manager_ref().is_none() {
			return self.perform_client_handshake_no_mutual_auth().await;
		}

		// Path: Mutual auth clients - trait objects via per-protocol builders
		let orchestrator = match kind {
			HandshakeProtocolKind::Ecies => self.build_ecies_client_orchestrator()?,

			#[cfg(feature = "transport-cms")]
			HandshakeProtocolKind::Cms => self.build_cms_client_orchestrator()?,

			#[cfg(not(feature = "transport-cms"))]
			HandshakeProtocolKind::Cms => {
				return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Cms));
			}
		};

		self.drive_client_handshake(kind, orchestrator).await
	}

	/// Perform client-side handshake (CMS-only build variant).
	///
	/// Trait where-clauses do not elaborate to callers, so the dispatcher is
	/// declared per feature combination with that build's predicate set.
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
		let kind = self.to_handshake_protocol_kind();

		let orchestrator = match kind {
			HandshakeProtocolKind::Ecies => {
				return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Ecies));
			}
			HandshakeProtocolKind::Cms => self.build_cms_client_orchestrator()?,
		};

		self.drive_client_handshake(kind, orchestrator).await
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
		let cert_arc = self.to_server_certificate_arc().ok_or(TransportError::MissingEncryption)?;
		let key_manager = self.to_key_manager_ref().ok_or(TransportError::MissingEncryption)?;
		let client_validators = self.to_client_validators_ref().map(Arc::clone);
		let supported_profiles = vec![SecurityProfileDesc::from(&TightbeamProfile)];

		Ok(key_manager.create_ecies_server(
			cert_arc,
			None,
			supported_profiles,
			client_validators,
			self.to_mux_config(),
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
		let key_manager = self.to_key_manager_ref().ok_or(TransportError::MissingEncryption)?;
		let client_validators = self.to_client_validators_ref().map(Arc::clone);
		let supported_profiles = vec![SecurityProfileDesc::from(&TightbeamProfile)];

		Ok(key_manager.create_cms_server(client_validators, supported_profiles, self.to_mux_config())?)
	}

	/// Protocol-agnostic server handshake state machine: bytes in, bytes out.
	///
	/// Assumes the persisted orchestrator exists; `kind` maps its response
	/// bytes to their wire envelope.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[allow(async_fn_in_trait)]
	async fn drive_server_handshake(&mut self, kind: HandshakeProtocolKind, request: &[u8]) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState,
	{
		let orchestrator = self.to_server_handshake_mut().as_mut().ok_or(TransportError::InvalidState)?;

		// Process client handshake message - may return response to send
		let response_bytes = orchestrator.handle_request(request).await?;

		// Send response if any (multi-round support)
		if let Some(response) = response_bytes {
			if response.len() > HANDSHAKE_MAX_WIRE {
				return Err(TransportError::InvalidMessage);
			}

			let server_envelope = kind.wrap_server_response(&response)?;
			let wire_envelope = WireEnvelope::Cleartext(server_envelope);
			self.write_envelope(&wire_envelope.to_der()?).await?;

			// Set server awaiting state with timeout tracking
			#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
			{
				self.set_handshake_state(TcpHandshakeState::AwaitingClientFinish { initiated_at: Instant::now() });
			}
			#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
			{
				self.set_handshake_state(TcpHandshakeState::AwaitingClientFinish { initiated_at: 0 });
			}
		} else {
			// No response means handshake is complete - get the directional session keys
			let session_keys = orchestrator.complete().await?;
			let mux_settings = orchestrator.negotiated_mux();

			// Extract peer certificate if mutual auth was performed
			if let Some(peer_cert) = orchestrator.peer_certificate().cloned() {
				self.set_peer_certificate(peer_cert);
			}

			self.set_session_keys(session_keys);
			self.set_mux_settings(mux_settings);
			self.set_handshake_state(TcpHandshakeState::Complete);

			// Clear handshake instance - no longer needed
			*self.to_server_handshake_mut() = None;
		}

		Ok(())
	}

	/// Perform server-side handshake (extracted from macro)
	#[cfg(feature = "transport-ecies")]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake<P>(&mut self, handshake_bytes: &[u8]) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P>,
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
		if handshake_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		let kind = self.to_handshake_protocol_kind();

		// Parse the wire container and extract the raw handshake message
		let transport_envelope = TransportEnvelope::from_der(handshake_bytes)?;
		let raw_message = kind.unwrap_client_request(&transport_envelope)?;

		// Get or create handshake orchestrator (persists state across multiple messages)
		if self.to_server_handshake_mut().is_none() {
			let orchestrator = match kind {
				HandshakeProtocolKind::Ecies => self.build_ecies_server_orchestrator()?,

				#[cfg(feature = "transport-cms")]
				HandshakeProtocolKind::Cms => self.build_cms_server_orchestrator()?,

				#[cfg(not(feature = "transport-cms"))]
				HandshakeProtocolKind::Cms => {
					return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Cms));
				}
			};

			*self.to_server_handshake_mut() = Some(orchestrator);
		}

		self.drive_server_handshake(kind, &raw_message).await
	}

	/// Perform server-side handshake (CMS-only build variant).
	///
	/// Trait where-clauses do not elaborate to callers, so the dispatcher is
	/// declared per feature combination with that build's predicate set.
	#[cfg(all(not(feature = "transport-ecies"), feature = "transport-cms"))]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake<P>(&mut self, handshake_bytes: &[u8]) -> TransportResult<()>
	where
		Self: Sized + MessageIO + EncryptedProtocolState<CryptoProvider = P>,
		P: CryptoProvider + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		if handshake_bytes.len() > HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		let kind = self.to_handshake_protocol_kind();

		// Parse the wire container and extract the raw handshake message.
		// The Ecies kind fails closed inside unwrap_client_request.
		let transport_envelope = TransportEnvelope::from_der(handshake_bytes)?;
		let raw_message = kind.unwrap_client_request(&transport_envelope)?;

		// Get or create handshake orchestrator (persists state across multiple messages)
		if self.to_server_handshake_mut().is_none() {
			let orchestrator = match kind {
				HandshakeProtocolKind::Ecies => {
					return Err(TransportError::UnsupportedHandshakeProtocol(HandshakeProtocolKind::Ecies));
				}
				HandshakeProtocolKind::Cms => self.build_cms_server_orchestrator()?,
			};

			*self.to_server_handshake_mut() = Some(orchestrator);
		}

		self.drive_server_handshake(kind, &raw_message).await
	}

	/// Perform a single request-response cycle
	/// Returns (status, response, original_message) where original_message is Some when status != Accepted
	#[cfg(feature = "x509")]
	#[allow(async_fn_in_trait)]
	async fn perform_emit_cycle(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>
	where
		Self: Sized + MessageIO + EncryptedProtocolState,
	{
		// Wrap and encrypt message
		let wire_envelope = self.wrap_and_encrypt_message(message).await?;
		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope(&wire_bytes).await?;

		// Read and decrypt response
		let response_bytes = self.read_envelope().await?;
		let response_envelope = self.decrypt_response(response_bytes).await?;

		// Parse response
		let (status, response) = match response_envelope {
			TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
			TransportEnvelope::Request(_) => return Err(TransportError::InvalidMessage),
			TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
				return Err(TransportError::InvalidMessage)
			}
			#[cfg(feature = "transport-multiplex")]
			TransportEnvelope::MuxedRequest(_)
			| TransportEnvelope::MuxedResponse(_)
			| TransportEnvelope::MuxCancel(_)
			| TransportEnvelope::GoAway(_) => return Err(TransportError::InvalidMessage),
		};

		// Return original message when status != Accepted (for retry evaluation)
		let returned_message = if status != TransitStatus::Accepted {
			match wire_envelope {
				WireEnvelope::Cleartext(TransportEnvelope::Request(pkg)) => Some(pkg.message),
				_ => None, // Encrypted - can't extract original
			}
		} else {
			None
		};

		// Convert Arc<Frame> to Frame
		let response_frame = response.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		let returned_frame = returned_message.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));

		Ok((status, response_frame, returned_frame))
	}
}

/// Trait for checking transport connectivity
pub trait Pingable {
	/// Ping the transport layer to check connectivity
	fn ping(&mut self) -> TransportResult<()>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::{MessagePriority, Metadata};
	use crate::transport::envelopes::{RequestPackage, ResponsePackage};
	use crate::transport::ResponseHandler as TransportResponseHandler;
	use crate::Version;

	/// (first length octet, remaining octets, expected decode)
	const PARSE_DER_LENGTH_CASES: &[(u8, &[u8], Option<usize>)] = &[
		(0x00, &[], Some(0)),
		(0x7F, &[], Some(127)),
		(0x81, &[0x80], Some(128)),
		(0x81, &[0xFF], Some(255)),
		(0x82, &[0x01, 0x00], Some(256)),
		(0x80, &[], None),
		(0x81, &[0x05], None),
		(0x82, &[0x00, 0x80], None),
		(0x89, &[0x01; 9], None),
		(0x82, &[0x01], None),
		(0x81, &[], None),
	];

	#[test]
	fn parse_der_length_cases() {
		for &(first, rest, expected) in PARSE_DER_LENGTH_CASES {
			assert_eq!(parse_der_length(first, rest), expected);
		}
	}

	fn frame_with_priority(version: Version) -> Frame {
		let mut metadata = Metadata::default();
		metadata.priority = Some(MessagePriority::Standard);

		Frame { version, metadata, message: Vec::new(), integrity: None, nonrepudiation: None }
	}

	/// Minimal `MessageIO` probe so ingress goes through `decode_envelope`.
	struct DecodeProbe;

	impl TransportResponseHandler for DecodeProbe {
		fn with_handler<F>(self, _handler: F) -> Self
		where
			F: Fn(Frame) -> Option<Frame> + Send + Sync + 'static,
		{
			self
		}

		fn handler(&self) -> Option<&(dyn Fn(Frame) -> Option<Frame> + Send + Sync)> {
			None
		}
	}

	impl MessageIO for DecodeProbe {
		async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
			Err(TransportError::ConnectionClosed)
		}

		async fn write_envelope(&mut self, _buffer: &[u8]) -> TransportResult<()> {
			Ok(())
		}
	}

	/// (label, envelope, must be version-compatible)
	fn version_envelope_cases() -> Vec<(&'static str, TransportEnvelope, bool)> {
		vec![
			(
				"request V0+priority",
				TransportEnvelope::Request(RequestPackage::new(frame_with_priority(Version::V0))),
				false,
			),
			(
				"request V2+priority",
				TransportEnvelope::Request(RequestPackage::new(frame_with_priority(Version::V2))),
				true,
			),
			(
				"response V0+priority",
				TransportEnvelope::Response(ResponsePackage::new(
					TransitStatus::Accepted,
					Some(frame_with_priority(Version::V0)),
				)),
				false,
			),
			(
				"response without frame",
				TransportEnvelope::Response(ResponsePackage::new(TransitStatus::Accepted, None)),
				true,
			),
		]
	}

	#[test]
	fn envelope_version_compatibility_and_decode_ingress() {
		for (_label, envelope, compatible) in version_envelope_cases() {
			assert_eq!(envelope_versions_compatible(&envelope), compatible);

			let bytes = crate::encode(&envelope).expect("encode probe envelope");
			let decoded = <DecodeProbe as MessageIO>::decode_envelope(&bytes);
			assert_eq!(decoded.is_ok(), compatible);
			if !compatible {
				assert!(matches!(decoded, Err(TransportError::InvalidMessage)));
			}
		}
	}
}
