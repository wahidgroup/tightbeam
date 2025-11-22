#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(all(feature = "x509", feature = "std"))]
use std::time::Duration;

pub mod builders;
pub mod error;
pub mod handshake;
pub mod state;

#[cfg(feature = "transport-policy")]
pub mod policy;
#[cfg(feature = "tcp")]
pub mod tcp;

use crate::asn1::Frame;
use crate::builder::TypeBuilder;
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData};
use crate::cms::signed_data::SignedData;
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::der::{Choice, Decode, Encode, EncodeValue, Tag, Tagged};
use crate::policy::{GatePolicy, TransitStatus};
use crate::transport::builders::{EnvelopeBuilder, EnvelopeLimits};
use crate::transport::error::{TransportError, TransportFailure};
use crate::{encode, TightBeamError};

#[cfg(feature = "x509")]
use crate::crypto::aead::{Decryptor, RuntimeAead};
#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::transport::handshake::{
	ClientHandshakeProtocol, HandshakeError, HandshakeKeyManager, HandshakeProtocolKind, TcpHandshakeState,
};
#[cfg(feature = "transport-policy")]
use crate::transport::policy::RestartPolicy;
#[cfg(feature = "x509")]
use crate::x509::Certificate;
#[cfg(feature = "derive")]
use crate::Beamable;

/// Transport-agnostic result type
pub type TransportResult<T> = Result<T, TransportError>;

/// Composite validator that runs multiple validators in sequence
#[cfg(feature = "x509")]
pub(crate) struct CompositeValidator {
	pub(crate) validators: Arc<Vec<Arc<dyn CertificateValidation>>>,
}

#[cfg(feature = "x509")]
impl CertificateValidation for CompositeValidator {
	fn evaluate(
		&self,
		cert: &Certificate,
	) -> core::result::Result<(), crate::crypto::x509::error::CertificateValidationError> {
		for validator in self.validators.iter() {
			validator.evaluate(cert)?;
		}
		Ok(())
	}
}

/// Marker crate for applications to handle the address the way they wish
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}

#[cfg(all(feature = "x509", feature = "std"))]
#[derive(Clone)]
pub struct TransportEncryptionConfig {
	pub certificate: Certificate,
	pub key_manager: Arc<HandshakeKeyManager>,
	pub client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	pub aad_domain_tag: &'static [u8],
	pub max_cleartext_envelope: usize,
	pub max_encrypted_envelope: usize,
	pub handshake_timeout: Duration,
}

#[cfg(all(feature = "x509", feature = "std"))]
impl TransportEncryptionConfig {
	pub fn new(certificate: Certificate, key_manager: HandshakeKeyManager) -> Self {
		Self {
			certificate,
			key_manager: Arc::new(key_manager),
			client_validators: None,
			aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG,
			max_cleartext_envelope: 128 * 1024,
			max_encrypted_envelope: 256 * 1024,
			handshake_timeout: Duration::from_secs(10),
		}
	}

	pub fn with_client_validators(mut self, validators: Vec<Arc<dyn CertificateValidation>>) -> Self {
		self.client_validators = Some(Arc::new(validators));
		self
	}
}

/// Request package containing the message frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPackage {
	message: Arc<Frame>,
}

impl RequestPackage {
	pub fn new(message: Frame) -> Self {
		Self { message: Arc::new(message) }
	}
}

impl EncodeValue for RequestPackage {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		self.message.as_ref().encoded_len()
	}

	fn encode_value(&self, writer: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		self.message.as_ref().encode(writer)
	}
}

impl Tagged for RequestPackage {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

impl<'a> Decode<'a> for RequestPackage {
	fn decode<R: crate::der::Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		reader.sequence(|reader| {
			let frame = Frame::decode(reader)?;
			Ok(Self { message: Arc::new(frame) })
		})
	}
}

/// Response package containing status and optional message
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponsePackage {
	status: TransitStatus,
	message: Option<Arc<Frame>>,
}

impl ResponsePackage {
	pub fn new(status: TransitStatus, message: Option<Frame>) -> Self {
		Self { status, message: message.map(Arc::new) }
	}

	pub fn status(&self) -> TransitStatus {
		self.status
	}

	pub fn message(&self) -> Option<&Arc<Frame>> {
		self.message.as_ref()
	}
}

impl EncodeValue for ResponsePackage {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		let message_len = match &self.message {
			Some(arc) => arc.as_ref().encoded_len()?,
			None => crate::der::Length::ZERO,
		};
		[self.status.encoded_len()?, message_len]
			.into_iter()
			.try_fold(crate::der::Length::ZERO, |acc, len| acc + len)
	}

	fn encode_value(&self, writer: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		self.status.encode(writer)?;
		if let Some(arc) = &self.message {
			arc.as_ref().encode(writer)?;
		}

		Ok(())
	}
}

impl Tagged for ResponsePackage {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

impl<'a> Decode<'a> for ResponsePackage {
	fn decode<R: crate::der::Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		reader.sequence(|reader| {
			let status = TransitStatus::decode(reader)?;
			let message: Option<Frame> = Option::<Frame>::decode(reader)?;
			Ok(Self { status, message: message.map(Arc::new) })
		})
	}
}

/// Transport envelope wrapping all messages at the transport layer.
/// This is transparent to users and handled internally.
#[cfg_attr(feature = "derive", derive(Beamable))]
#[derive(Choice, Clone, Debug, PartialEq)]
pub enum TransportEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Request(RequestPackage),
	#[asn1(context_specific = "1", constructed = "true")]
	Response(ResponsePackage),
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "2", constructed = "true")]
	EnvelopedData(EnvelopedData),
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "3", constructed = "true")]
	SignedData(SignedData),
}

/// Wire-level envelope that can be either cleartext or encrypted
#[derive(Choice, Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum WireEnvelope {
	#[asn1(context_specific = "0", constructed = "true")]
	Cleartext(TransportEnvelope),
	#[asn1(context_specific = "1", constructed = "true")]
	Encrypted(EncryptedContentInfo),
}

/// Determines whether an envelope should be emitted as cleartext or encrypted bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireMode {
	/// Emit raw `TransportEnvelope` bytes.
	Cleartext,
	/// Encrypt the encoded envelope prior to emission.
	Encrypted,
}

#[cfg(not(feature = "derive"))]
impl Message for TransportEnvelope {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: Version = Version::V0;
}

impl From<ResponsePackage> for TransportEnvelope {
	fn from(pkg: ResponsePackage) -> Self {
		Self::Response(pkg)
	}
}

impl From<Frame> for TransportEnvelope {
	fn from(msg: Frame) -> Self {
		Self::Request(RequestPackage { message: Arc::new(msg) })
	}
}

impl TransportEnvelope {
	/// Create a new request envelope from a message
	pub fn new_request(msg: Frame) -> Self {
		Self::Request(RequestPackage { message: Arc::new(msg) })
	}
}

/// Stream trait - defines how to read and write
pub trait ProtocolStream: Send {
	type Error: Into<TransportError>;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

	/// Set read and write timeouts on the underlying stream.
	/// Returns Ok(()) if timeouts were set, or Err if not supported.
	/// This is used for operation-level timeouts in blocking I/O.
	#[cfg(feature = "std")]
	fn set_timeout(&mut self, timeout: Option<std::time::Duration>) -> Result<(), Self::Error> {
		let _ = timeout;
		// Default implementation: no-op (not supported)
		Ok(())
	}

	#[cfg(not(feature = "std"))]
	fn set_timeout(&mut self, timeout: Option<core::time::Duration>) -> Result<(), Self::Error> {
		let _ = timeout;
		// Default implementation: no-op (not supported)
		Ok(())
	}
}

/// Protocol trait - defines how to bind and connect
pub trait Protocol {
	type Listener: Send;
	type Stream: Send;
	type Transport: Send;
	type Error: Into<TransportError>;
	type Address: TightBeamAddress;

	/// Get a default address for binding to any available port/endpoint
	/// This is protocol-specific (e.g., "127.0.0.1:0" for TCP)
	fn default_bind_address() -> Result<Self::Address, Self::Error>;

	/// Bind to an address and return listener + actual bound address
	fn bind(
		addr: Self::Address,
	) -> impl core::future::Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;

	/// Connect to an address
	fn connect(addr: Self::Address) -> impl core::future::Future<Output = Result<Self::Stream, Self::Error>> + Send;

	/// Create transport from stream
	fn create_transport(stream: Self::Stream) -> Self::Transport;

	// Get the tightbeam address for this protocol
	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error>;
}

#[cfg(feature = "x509")]
pub trait EncryptedProtocol: Protocol {
	type Encryptor: Send;
	type Decryptor: Send;

	/// Bind to an address with transport encryption configuration
	fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig,
	) -> impl core::future::Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// Trait for configuring client-side X.509 mutual authentication.
/// Supports multiple server certificates for rotation and multi-CA scenarios.
#[cfg(feature = "x509")]
pub trait X509ClientConfig: Sized {
	/// Add a server certificate for verification.
	fn with_server_certificate(self, cert: Certificate) -> Self;

	/// Add multiple server certificates at once.
	fn with_server_certificates(self, certs: impl IntoIterator<Item = Certificate>) -> Self;

	/// Set the client's identity (certificate and private key) for mutual authentication.
	/// The client presents this certificate to the server when requested.
	fn with_client_identity(self, cert: Certificate, key: HandshakeKeyManager) -> Self;
}

/// This protocol can operate as a mycelial network (ie. TCP SocketAddress)
pub trait Mycelial: Protocol {
	fn try_available_connect(
		&self,
	) -> impl core::future::Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// Async listener trait
pub trait AsyncListenerTrait: Protocol + Send {
	#[allow(async_fn_in_trait)]
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error>;
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
		Ok(TransportEnvelope::from_der(buffer)?)
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

	/// Send a response back to the sender
	///
	fn handle_message(&self, message: Arc<Frame>) -> Option<Frame> {
		let frame = Arc::try_unwrap(message).unwrap_or_else(|arc| (*arc).clone());
		self.handler().and_then(|handler| handler(frame))
	}

	/// Helper for parsing DER length encoding
	fn parse_der_length(first_byte: u8, length_octets: &[u8]) -> usize {
		if first_byte & 0x80 == 0 {
			first_byte as usize
		} else {
			let mut length = 0usize;
			for &byte in length_octets {
				length = (length << 8) | (byte as usize);
			}
			length
		}
	}

	/// Helper to reconstruct full DER encoding from parts
	fn reconstruct_der_encoding(tag: u8, length_first: u8, length_octets: &[u8], content: &[u8]) -> Vec<u8> {
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
}
#[cfg(feature = "x509")]
pub trait EncryptedMessageIO: MessageIO {
	/// Relay a message by detecting whether it's encrypted or cleartext
	/// Returns the decrypted TransportEnvelope ready for processing
	#[allow(async_fn_in_trait)]
	async fn relay_message(&mut self) -> TransportResult<TransportEnvelope>
	where
		Self: crate::transport::state::EncryptedProtocolState,
	{
		let wire_bytes = self.read_envelope().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)
			.map_err(TightBeamError::from)
			.map_err(TransportError::from)?;

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
				let decrypted_bytes = self
					.to_decryptor_ref()?
					.decrypt_content(&encrypted_info)
					.map_err(TransportError::from)?;

				Self::decode_envelope(&decrypted_bytes)
			}
		}
	}

	/// Send a cleartext or encrypted envelope based on encryption flag
	#[allow(async_fn_in_trait)]
	async fn send_envelope(&mut self, envelope: TransportEnvelope, encrypt: bool) -> TransportResult<()>
	where
		Self: crate::transport::state::EncryptedProtocolState,
	{
		let wire_envelope = if encrypt {
			let envelope_bytes = Self::encode_envelope(&envelope)?;
			let encrypted_info = self
				.to_encryptor_ref()?
				.encrypt_content(&envelope_bytes, [], None)
				.map_err(TransportError::from)?;

			WireEnvelope::Encrypted(encrypted_info)
		} else {
			WireEnvelope::Cleartext(envelope)
		};

		let wire_bytes = wire_envelope
			.to_der()
			.map_err(TightBeamError::from)
			.map_err(TransportError::from)?;

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
		Self: crate::transport::state::EncryptedProtocolState,
	{
		let limits = EnvelopeLimits::from_pair(self.to_max_cleartext_envelope(), self.to_max_encrypted_envelope());
		let mut builder = limits.apply(EnvelopeBuilder::request(message));

		if self.to_handshake_state() == TcpHandshakeState::Complete {
			let encryptor = self.to_encryptor_ref()?;
			builder = builder.with_wire_mode(WireMode::Encrypted).with_encryptor(encryptor);
		} else {
			builder = builder.with_wire_mode(WireMode::Cleartext);
		}

		builder.build()
	}

	/// Decrypt a response from wire bytes
	/// Protocol-agnostic default implementation
	#[allow(async_fn_in_trait)]
	async fn decrypt_response(&mut self, wire_bytes: Vec<u8>) -> TransportResult<TransportEnvelope>
	where
		Self: crate::transport::state::EncryptedProtocolState,
	{
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)
			.map_err(TightBeamError::from)
			.map_err(TransportError::from)?;

		match wire_envelope {
			WireEnvelope::Cleartext(env) => Ok(env),
			WireEnvelope::Encrypted(encrypted_info) => {
				use crate::crypto::aead::Decryptor;
				let decrypted_bytes = self
					.to_decryptor_ref()?
					.decrypt_content(&encrypted_info)
					.map_err(TransportError::from)?;
				Self::decode_envelope(&decrypted_bytes)
			}
		}
	}

	/// Ensure handshake is complete, performing it if needed
	#[cfg(feature = "x509")]
	#[allow(async_fn_in_trait)]
	async fn ensure_handshake_complete(&mut self) -> TransportResult<()>
	where
		Self: Sized + crate::transport::state::EncryptedProtocolState,
	{
		let should_handshake = (self.to_server_certificate_ref().is_some() || self.is_client_validators_present())
			&& self.to_handshake_state() == TcpHandshakeState::None;

		if should_handshake {
			self.perform_client_handshake().await?;
		}

		Ok(())
	}

	/// Perform client-side ECIES handshake without mutual authentication (K=() variant)
	/// This is a helper method because K=() cannot be cast to trait object due to missing Signer bound
	#[cfg(feature = "x509")]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake_no_mutual_auth(
		&mut self,
		#[cfg(all(feature = "x509", feature = "std"))] validator: Option<Arc<dyn CertificateValidation>>,
		#[cfg(not(all(feature = "x509", feature = "std")))] validator: Option<()>,
	) -> TransportResult<()>
	where
		Self: Sized + MessageIO + crate::transport::state::EncryptedProtocolState,
	{
		use crate::crypto::ecies::Secp256k1EciesMessage;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::transport::handshake::client::EciesHandshakeClient;
		use crate::transport::handshake::{ClientHello, ClientKeyExchange, HandshakeFinalization, ServerHandshake};

		// Create client without mutual auth
		let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None);
		#[cfg(all(feature = "x509", feature = "std"))]
		if let Some(val) = validator {
			client = client.with_certificate_validator(val);
		}

		// Step 1: Build and send client hello
		let initial_message = client.build_client_hello()?;
		if initial_message.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		let client_hello = ClientHello::from_der(&initial_message)?;
		let signed_data: SignedData = (&client_hello).try_into().map_err(|_| TransportError::InvalidMessage)?;
		let initial_envelope = TransportEnvelope::SignedData(signed_data);
		let wire_envelope = WireEnvelope::Cleartext(initial_envelope);
		self.write_envelope(&wire_envelope.to_der()?).await?;

		// Update state machine
		#[cfg(feature = "std")]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse {
				initiated_at: std::time::Instant::now(),
			});
		}
		#[cfg(not(feature = "std"))]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse { initiated_at: 0 });
		}

		// Step 2: Receive server response
		let response_wire_bytes = self.read_envelope().await?;
		if response_wire_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
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
			(&signed_data).try_into().map_err(|_| TransportError::InvalidMessage)?;
		let response_bytes = server_handshake.to_der()?;
		if response_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Step 3: Process server handshake (no mutual auth)
		let next_message_bytes = client.process_server_handshake_no_auth(&response_bytes)?;
		if next_message_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Step 4: Send client key exchange
		let client_kex = ClientKeyExchange::from_der(&next_message_bytes)?;
		let enveloped_data: EnvelopedData = (&client_kex).try_into().map_err(|_| TransportError::InvalidMessage)?;
		let msg_envelope = TransportEnvelope::EnvelopedData(enveloped_data);
		let wire_envelope = WireEnvelope::Cleartext(msg_envelope);
		self.write_envelope(&wire_envelope.to_der()?).await?;

		// Step 5: Complete handshake and get RuntimeAead
		let cipher = client.complete()?;
		let profile = HandshakeFinalization::selected_profile(&client).ok_or(TransportError::InvalidMessage)?;
		let aead_oid = profile.aead.ok_or(TransportError::InvalidMessage)?;
		let session_key = RuntimeAead::new(cipher, aead_oid);
		self.set_symmetric_key(session_key);
		self.set_handshake_state(TcpHandshakeState::Complete);

		Ok(())
	}

	/// Perform client-side handshake (extracted from macro)
	#[cfg(feature = "x509")]
	#[allow(async_fn_in_trait)]
	async fn perform_client_handshake(&mut self) -> TransportResult<()>
	where
		Self: Sized + MessageIO + crate::transport::state::EncryptedProtocolState,
	{
		use crate::transport::handshake::{ClientHello, ClientKeyExchange, ServerHandshake};

		// Build composite validator if validators are configured
		#[cfg(all(feature = "x509", feature = "std"))]
		let validator = self.to_client_validators_ref().map(|validators| {
			let composite = CompositeValidator { validators: Arc::clone(validators) };
			Arc::new(composite) as Arc<dyn CertificateValidation>
		});

		#[cfg(not(all(feature = "x509", feature = "std")))]
		let validator = None;

		// Branch: Handle ECIES without mutual auth separately (K=() cannot be trait object)
		if matches!(self.to_handshake_protocol_kind(), HandshakeProtocolKind::Ecies)
			&& self.to_key_manager_ref().is_none()
		{
			return self.perform_client_handshake_no_mutual_auth(validator).await;
		}

		// Path: Mutual auth clients - use trait object via factory
		let key_manager = self.to_key_manager_ref().ok_or(TransportError::MissingEncryption)?;
		let mut orchestrator: Box<dyn ClientHandshakeProtocol<Error = HandshakeError>> =
			match (self.to_handshake_protocol_kind(), key_manager) {
				(HandshakeProtocolKind::Ecies, key) => {
					key.create_ecies_client(
						self.to_server_certificates_ref().first().map(Arc::clone),
						self.to_client_certificate_ref().map(Arc::clone),
						None, // Use default AAD domain tag
						validator,
					)?
				}

				#[cfg(feature = "transport-cms")]
				(HandshakeProtocolKind::Cms, key) => {
					let server_cert = self
						.to_server_certificates_ref()
						.first()
						.ok_or(TransportError::MissingEncryption)?;
					key.create_cms_client(Arc::clone(server_cert), validator)?
				}

				#[cfg(not(feature = "transport-cms"))]
				(HandshakeProtocolKind::Cms, _) => {
					return Err(TransportError::MissingEncryption); // CMS not enabled
				}
			};

		// Step 1: Start handshake - get initial message
		let initial_message = orchestrator.start().await?;
		if initial_message.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Parse ClientHello and wrap in SignedData → TransportEnvelope
		let client_hello = ClientHello::from_der(&initial_message)?;
		let signed_data: SignedData = (&client_hello).try_into().map_err(|_| TransportError::InvalidMessage)?;
		let initial_envelope = TransportEnvelope::SignedData(signed_data);

		let wire_envelope = WireEnvelope::Cleartext(initial_envelope);
		self.write_envelope(&wire_envelope.to_der()?).await?;

		// Update state machine
		#[cfg(feature = "std")]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse {
				initiated_at: std::time::Instant::now(),
			});
		}
		#[cfg(not(feature = "std"))]
		{
			self.set_handshake_state(TcpHandshakeState::AwaitingServerResponse { initiated_at: 0 });
		}

		// Step 2: Receive server response
		let response_wire_bytes = self.read_envelope().await?;
		if response_wire_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
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

		// Extract SignedData and convert to ServerHandshake
		let signed_data = match response_envelope {
			TransportEnvelope::SignedData(sd) => sd,
			_ => return Err(TransportError::InvalidMessage),
		};
		let server_handshake: ServerHandshake =
			(&signed_data).try_into().map_err(|_| TransportError::InvalidMessage)?;

		let response_bytes = server_handshake.to_der()?;
		if response_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Step 3: Handle server response - may return next message to send
		let next_message = orchestrator.handle_response(&response_bytes).await?;

		// Step 4: Send next message if any (multi-round support)
		if let Some(msg_bytes) = next_message {
			if msg_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
				return Err(TransportError::InvalidMessage);
			}

			// Parse ClientKeyExchange and wrap in EnvelopedData
			let client_kex = ClientKeyExchange::from_der(&msg_bytes)?;
			let enveloped_data: EnvelopedData = (&client_kex).try_into().map_err(|_| TransportError::InvalidMessage)?;
			let msg_envelope = TransportEnvelope::EnvelopedData(enveloped_data);

			let wire_envelope = WireEnvelope::Cleartext(msg_envelope);
			self.write_envelope(&wire_envelope.to_der()?).await?;
		}

		// Step 5: Complete handshake and get RuntimeAead
		let session_key = orchestrator.complete().await?;

		// Store session key and mark handshake complete
		self.set_symmetric_key(session_key);
		self.set_handshake_state(TcpHandshakeState::Complete);

		Ok(())
	}

	/// Perform server-side handshake (extracted from macro)
	#[cfg(feature = "x509")]
	#[allow(async_fn_in_trait)]
	async fn perform_server_handshake(&mut self, handshake_bytes: &[u8]) -> TransportResult<()>
	where
		Self: Sized + MessageIO + crate::transport::state::EncryptedProtocolState,
	{
		use crate::transport::handshake::{ClientHello, ClientKeyExchange, ServerHandshake};

		if handshake_bytes.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
			return Err(TransportError::InvalidMessage);
		}

		// Parse TransportEnvelope and extract the handshake message
		let transport_envelope = TransportEnvelope::from_der(handshake_bytes)?;
		let raw_message = match &transport_envelope {
			TransportEnvelope::SignedData(sd) => {
				// This is ClientHello (first message from client)
				ClientHello::try_from(sd)
					.map_err(|_| TransportError::InvalidMessage)?
					.to_der()?
			}
			TransportEnvelope::EnvelopedData(ed) => {
				// This is ClientKeyExchange (second message from client)
				ClientKeyExchange::try_from(ed)
					.map_err(|_| TransportError::InvalidMessage)?
					.to_der()?
			}
			_ => return Err(TransportError::InvalidMessage),
		};

		// Get all immutable data first before mutable borrow
		let cert_arc = self
			.to_server_certificates_ref()
			.first()
			.ok_or(TransportError::MissingEncryption)?;
		let cert_arc = Arc::clone(cert_arc);
		let key_manager = self.to_key_manager_ref().ok_or(TransportError::MissingEncryption)?;
		let key_manager = Arc::clone(key_manager);
		let protocol_kind = self.to_handshake_protocol_kind();
		let client_validators = self.to_client_validators_ref().map(Arc::clone);

		// Get or create handshake orchestrator (persists state across multiple messages)
		let server_handshake_opt = self.to_server_handshake_mut();
		if server_handshake_opt.is_none() {
			*server_handshake_opt = Some(match protocol_kind {
				HandshakeProtocolKind::Ecies => {
					// Create default security profile for negotiation
					let default_profile = crate::crypto::profiles::TightbeamProfile;
					let profile_desc = crate::crypto::profiles::SecurityProfileDesc::from(&default_profile);

					// Use factory method to create ECIES server with concrete key type
					key_manager.create_ecies_server(
						cert_arc,
						None, // Use default AAD domain tag
						vec![profile_desc],
						client_validators.clone(),
					)?
				}

				#[cfg(all(feature = "aead", feature = "signature"))]
				HandshakeProtocolKind::Cms => {
					// Use factory method to create CMS server with concrete key type
					key_manager.create_cms_server(client_validators.clone())?
				}

				#[cfg(not(all(feature = "aead", feature = "signature")))]
				HandshakeProtocolKind::Cms => {
					return Err(TransportError::MissingEncryption); // CMS not enabled
				}
			});
		}

		let orchestrator = server_handshake_opt.as_mut().ok_or(TransportError::InvalidState)?;

		// Process client handshake message - may return response to send
		let response_bytes = orchestrator.handle_request(&raw_message).await?;

		// Send response if any (multi-round support)
		if let Some(response) = response_bytes {
			if response.len() > crate::transport::tcp::HANDSHAKE_MAX_WIRE {
				return Err(TransportError::InvalidMessage);
			}

			// Parse ServerHandshake and wrap in SignedData → TransportEnvelope
			let server_handshake = ServerHandshake::from_der(&response)?;
			let signed_data: SignedData = (&server_handshake).try_into().map_err(|_| TransportError::InvalidMessage)?;
			let server_envelope = TransportEnvelope::SignedData(signed_data);

			let wire_envelope = WireEnvelope::Cleartext(server_envelope);
			self.write_envelope(&wire_envelope.to_der()?).await?;

			// Set server awaiting state with timeout tracking
			#[cfg(feature = "std")]
			{
				self.set_handshake_state(TcpHandshakeState::AwaitingClientFinish {
					initiated_at: std::time::Instant::now(),
				});
			}
			#[cfg(not(feature = "std"))]
			{
				self.set_handshake_state(TcpHandshakeState::AwaitingClientFinish { initiated_at: 0 });
			}
		} else {
			// No response means handshake is complete - get RuntimeAead
			let session_key = orchestrator.complete().await?;

			// Extract peer certificate if mutual auth was performed
			if let Some(peer_cert) = orchestrator.peer_certificate().cloned() {
				self.set_peer_certificate(peer_cert);
			}

			self.set_symmetric_key(session_key);
			self.set_handshake_state(TcpHandshakeState::Complete);

			// Clear handshake instance - no longer needed
			*self.to_server_handshake_mut() = None;
		}

		Ok(())
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
		Self: Sized + MessageIO + crate::transport::state::EncryptedProtocolState,
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

/// Trait for handling responses to incoming messages
pub trait Pingable {
	/// Ping the transport layer to check connectivity
	fn ping(&mut self) -> TransportResult<()>;
}

#[cfg(feature = "transport-policy")]
#[derive(Debug)]
/// Helper that mirrors a physical letter being routed through retries.
/// It guarantees zero-copy ownership transfers without panicking.
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

impl From<Frame> for Letter {
	fn from(frame: Frame) -> Self {
		Self::new(frame)
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
	/// This method handles protocol-specific concerns like handshakes, timeouts, and encryption.
	///
	/// # Returns
	/// - `status`: TransitStatus from the response
	/// - `response`: Optional response frame from server
	/// - `original`: Original frame if rejected (for retry), None if sent/consumed
	#[allow(async_fn_in_trait)]
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>;

	/// Send a TightBeam message
	#[allow(async_fn_in_trait)]
	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		use crate::transport::policy::RetryAction;

		let mut letter = Letter::from(message);
		let mut current_attempt = attempt.unwrap_or(0);

		loop {
			// Evaluate gate policy before sending
			let status = self.to_emitter_gate_policy_ref().evaluate(letter.try_peek()?);
			if status != TransitStatus::Accepted {
				return Err(TransportError::OperationFailed(TransportFailure::Unauthorized));
			}

			// Take message for send operation
			let message_to_send = letter.try_take()?;

			// Perform protocol-specific send/receive
			let (status, response, original_message) = match self.perform_send_receive(message_to_send).await {
				Ok(result) => result,
				Err(e) => {
					// Error during send - check if we can extract frame and failure for retry
					match e {
						TransportError::MessageNotSent(boxed_frame, ref failure) => {
							// Pass the box to policy (no unboxing, single allocation)
							let action = self.to_restart_policy_ref().evaluate(boxed_frame, failure, current_attempt);
							match action {
								RetryAction::Retry(retry_boxed_frame) => {
									if current_attempt == usize::MAX {
										return Err(TransportError::MaxRetriesExceeded);
									}
									// Unbox to put back into Letter
									letter.try_return_to_sender(*retry_boxed_frame)?;
									current_attempt += 1;
									continue;
								}
								RetryAction::NoRetry => {
									return Err(TransportError::OperationFailed(*failure));
								}
							}
						}
						other_error => {
							// Non-retriable error (doesn't have a frame)
							return Err(other_error);
						}
					}
				}
			};

			// Check transport status and handle response
			let result: TransportResult<&Frame> = if status != TransitStatus::Accepted {
				if let Some(msg) = original_message {
					// Server rejected - return frame for retry
					let failure = match status {
						TransitStatus::Busy => TransportFailure::Busy,
						TransitStatus::Forbidden => TransportFailure::Forbidden,
						TransitStatus::Unauthorized => TransportFailure::Unauthorized,
						TransitStatus::Timeout => TransportFailure::Timeout,
						_ => TransportFailure::PolicyRejection,
					};
					Err(TransportError::from_failure(msg, failure))
				} else {
					return Err(<TransportError as From<TransitStatus>>::from(status));
				}
			} else {
				match &response {
					Some(msg) => Ok(msg),
					None => return Ok(None),
				}
			};

			// Evaluate retry policy only on error
			match result {
				Err(TransportError::MessageNotSent(boxed_frame, ref failure)) => {
					let action = self.to_restart_policy_ref().evaluate(boxed_frame, failure, current_attempt);
					match action {
						RetryAction::Retry(retry_boxed_frame) => {
							if current_attempt == usize::MAX {
								return Err(TransportError::MaxRetriesExceeded);
							}
							// Unbox to put back into Letter
							letter.try_return_to_sender(*retry_boxed_frame)?;
							current_attempt += 1;
							continue;
						}
						RetryAction::NoRetry => {
							return Err(TransportError::OperationFailed(*failure));
						}
					}
				}
				Err(other_error) => {
					// Non-retriable error (doesn't have a frame)
					return Err(other_error);
				}
				Ok(_) => {
					return Ok(response);
				}
			}
		}
	}

	/// Default implementation for non-x509 transports
	#[cfg(not(feature = "x509"))]
	#[allow(async_fn_in_trait)]
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		// Wrap in envelope and send
		let envelope = TransportEnvelope::new_request(message);

		// Extract Arc for potential return
		let frame_arc = match &envelope {
			TransportEnvelope::Request(pkg) => Arc::clone(&pkg.message),
			_ => unreachable!("new_request always creates Request variant"),
		};

		// Send the envelope
		self.write_envelope(&envelope.to_der()?).await?;

		// Receive response
		let response_bytes = self.read_envelope().await?;
		let response_envelope = Self::decode_envelope(&response_bytes)?;

		// Parse response
		let (status, response) = match response_envelope {
			TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
			TransportEnvelope::Request(_) => {
				return Err(TransportError::InvalidMessage);
			}
		};

		// Return frame if rejected
		let original = if status != TransitStatus::Accepted {
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

/// Message collector trait - receives TightBeam messages
#[cfg(feature = "transport-policy")]
pub trait MessageCollector: MessageIO {
	type CollectorGate: GatePolicy + ?Sized;

	/// Get the collector gate policy instance
	fn collector_gate(&self) -> &Self::CollectorGate;

	/// Read and validate a message without sending a response
	/// Returns the message and the gate evaluation status
	#[allow(async_fn_in_trait)]
	async fn collect_message(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)> {
		// Read and decode the envelope (can be overridden for encryption)
		let decoded_envelope = self.read_decoded_envelope().await?;
		let request = match decoded_envelope {
			TransportEnvelope::Request(msg) => msg.message,
			TransportEnvelope::Response(_) => {
				// Only requests are valid here
				return Err(TransportError::InvalidMessage);
			}
			#[cfg(feature = "x509")]
			TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
				// Handshake messages not expected here
				return Err(TransportError::InvalidMessage);
			}
		};

		// Instrumentation removed - transport layer no longer has access to TraceCollector

		// Evaluate gate policy
		let status = self.collector_gate().evaluate(&request);
		if status == TransitStatus::Request {
			// Invalid status from gate
			return Err(TransportError::InvalidReply);
		}

		Ok((request, status))
	}

	/// Send a response for a previously collected message
	#[allow(async_fn_in_trait)]
	async fn send_response(&mut self, status: TransitStatus, message: Option<Frame>) -> TransportResult<()> {
		let response_pkg = ResponsePackage { status, message: message.map(Arc::new) };
		let response_envelope = TransportEnvelope::from(response_pkg);

		// When x509 is enabled, wrap in WireEnvelope for protocol compatibility
		#[cfg(feature = "x509")]
		{
			let wire_envelope = WireEnvelope::Cleartext(response_envelope);
			let wire_bytes = wire_envelope.to_der()?;
			self.write_envelope(&wire_bytes).await?;
		}

		#[cfg(not(feature = "x509"))]
		{
			let response_bytes = Self::encode_envelope(&response_envelope)?;
			self.write_envelope(&response_bytes).await?;
		}

		Ok(())
	}

	/// Handle incoming request: collect message, process it, and send response
	#[allow(async_fn_in_trait)]
	async fn handle_request(&mut self) -> TransportResult<()> {
		let (request, status) = match self.collect_message().await {
			Ok(result) => result,
			#[cfg(feature = "x509")]
			Err(TransportError::MissingEncryption) => {
				// Client sent unencrypted message when encryption required
				self.send_response(TransitStatus::Forbidden, None).await?;
				return Ok(());
			}
			Err(e) => return Err(e),
		};

		let message = if status == TransitStatus::Accepted {
			// If the gate accepted it, handle the message
			self.handle_message(request)
		} else {
			// If not accepted, no response message
			None
		};

		self.send_response(status, message).await
	}

	/// X509-enabled collect_message with encryption and handshake support
	#[cfg(feature = "x509")]
	#[allow(async_fn_in_trait)]
	async fn collect_message_with_encryption(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)>
	where
		Self: EncryptedMessageIO + Sized + crate::transport::state::EncryptedProtocolState,
	{
		use crate::crypto::aead::Decryptor;

		loop {
			// Read wire envelope
			// Enforce size ceilings
			let wire_bytes = self.read_envelope().await?;
			let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
			match &wire_envelope {
				WireEnvelope::Cleartext(_) => {
					if let Some(max) = self.to_max_cleartext_envelope() {
						if wire_bytes.len() > max {
							return Err(TransportError::InvalidMessage);
						}
					}
				}
				WireEnvelope::Encrypted(_) => {
					if let Some(max) = self.to_max_encrypted_envelope() {
						if wire_bytes.len() > max {
							return Err(TransportError::InvalidMessage);
						}
					}
				}
			}

			let has_certificate = self.to_server_certificate_ref().is_some();
			let decoded_envelope = match wire_envelope {
				WireEnvelope::Cleartext(envelope) => {
					if has_certificate {
						match envelope {
							TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
								let handshake_bytes = envelope.to_der()?;
								self.perform_server_handshake(&handshake_bytes).await?;
								continue;
							}
							TransportEnvelope::Request(_) | TransportEnvelope::Response(_) => {
								// Circuit breaker
								self.set_handshake_state(TcpHandshakeState::None);
								self.unset_symmetric_key();
								return Err(TransportError::MissingEncryption);
							}
						}
					} else {
						envelope
					}
				}
				WireEnvelope::Encrypted(encrypted_info) => {
					if self.to_handshake_state() != TcpHandshakeState::Complete {
						self.set_handshake_state(TcpHandshakeState::None);
						self.unset_symmetric_key();
						return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
					}

					let decrypted_bytes = match self.to_decryptor_ref()?.decrypt_content(&encrypted_info) {
						Ok(bytes) => bytes,
						Err(_) => {
							self.set_handshake_state(TcpHandshakeState::None);
							self.unset_symmetric_key();
							return Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed));
						}
					};
					Self::decode_envelope(&decrypted_bytes)?
				}
			};

			let request = match decoded_envelope {
				TransportEnvelope::Request(msg) => msg.message,
				TransportEnvelope::Response(_) => return Err(TransportError::InvalidMessage),
				TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
					return Err(TransportError::InvalidMessage)
				}
			};

			let status = self.collector_gate().evaluate(&request);
			if status == TransitStatus::Request {
				return Err(TransportError::InvalidReply);
			}

			return Ok((request, status));
		}
	}
}

#[cfg(not(feature = "transport-policy"))]
pub trait MessageCollector: MessageIO {
	/// Read and validate a message without sending a response
	/// Returns the message (status is always Accepted without policies)
	#[allow(async_fn_in_trait)]
	async fn collect_message(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)> {
		// Read the envelope
		let request_envelope = self.read_envelope().await?;
		// Extract message from request
		let request = match request_envelope {
			TransportEnvelope::Request(msg) => msg.message,
			TransportEnvelope::Response(_) => {
				return Err(TransportError::InvalidMessage);
			}
		};

		Ok((request, TransitStatus::Accepted))
	}

	/// Send a response for a previously collected message
	#[allow(async_fn_in_trait)]
	async fn send_response(&mut self, status: TransitStatus, message: Option<Frame>) -> TransportResult<()> {
		let response_pkg = ResponsePackage { status, message: message.map(Arc::new) };
		let response_envelope = TransportEnvelope::from(response_pkg);

		// When x509 is enabled, wrap in WireEnvelope for protocol compatibility
		#[cfg(feature = "x509")]
		{
			let wire_envelope = WireEnvelope::Cleartext(response_envelope);
			let wire_bytes = wire_envelope.to_der()?;
			self.write_envelope(&wire_bytes).await?;
		}

		#[cfg(not(feature = "x509"))]
		{
			self.write_envelope(&response_envelope.to_der()?).await?;
		}

		Ok(())
	}

	/// Handle incoming request: collect message, process it, and send response
	#[allow(async_fn_in_trait)]
	async fn handle_request(&mut self) -> TransportResult<()> {
		let (request, status) = match self.collect_message().await {
			Ok(result) => result,
			#[cfg(feature = "x509")]
			Err(TransportError::MissingEncryption) => {
				// Client sent unencrypted message when encryption required
				self.send_response(TransitStatus::Forbidden, None).await?;
				return Ok(());
			}
			Err(e) => return Err(e),
		};

		let message = if status == TransitStatus::Accepted {
			// If the gate accepted it, handle the message
			self.handle_message(request)
		} else {
			// If not accepted, no response message
			None
		};

		self.send_response(status, message).await
	}
}

/// Bidirectional transport combines emitter and collector
#[cfg(feature = "transport-policy")]
pub trait Transport: MessageEmitter + MessageCollector {}

#[cfg(feature = "transport-policy")]
impl<T> Transport for T where T: MessageEmitter + MessageCollector {}

#[cfg(not(feature = "transport-policy"))]
pub trait Transport: MessageEmitter + MessageCollector {}

#[cfg(not(feature = "transport-policy"))]
impl<T> Transport for T where T: MessageEmitter + MessageCollector {}

/// Trait for transports that support custom response handlers
pub trait ResponseHandler {
	/// Set a handler that processes incoming messages and generates responses
	fn with_handler<F>(self, handler: F) -> Self
	where
		F: Fn(Frame) -> Option<Frame> + Send + 'static;

	/// Get the current handler if one is set
	fn handler(&self) -> Option<&(dyn Fn(Frame) -> Option<Frame> + Send)>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::oid::AssociatedOid;
	use crate::testing::create_v0_tightbeam;
	use crate::transport::error::TransportFailure;
	use crate::transport::policy::PolicyConf;

	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_server_and_client_macros() -> TransportResult<()> {
		use std::sync::{mpsc, Arc};

		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

		let (tx, rx) = mpsc::channel();
		let tx = Arc::new(tx);

		// Spawn server using server! macro
		let server_handle = crate::server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = Arc::clone(&tx);
				async move {
					// Quantum tunnel testing channel -- TUNNEL
					let _ = tx.send(message);
					Ok(None)
				}
			}
		};

		// Create client using client! macro
		let mut client = crate::client! {
			connect TokioListener: addr,
			policies: {
				restart_policy: RestartLinearBackoff::default(),
			}
		};

		let message = create_v0_tightbeam(None, None);
		let result = client.emit(message.clone(), None).await;
		result?;

		// Verify server received the message -- TUNNEL
		let received = rx
			.recv_timeout(Duration::from_secs(1))
			.map_err(|_| TransportError::OperationFailed(error::TransportFailure::Timeout))?;
		assert_eq!(message, received);

		server_handle.abort();

		Ok(())
	}

	struct PackageTestCase {
		message_value: &'static str,
		expected_status: TransitStatus,
		should_have_message: bool,
	}

	impl PackageTestCase {
		fn create_request(&self) -> RequestPackage {
			RequestPackage::new(create_v0_tightbeam(Some(self.message_value), None))
		}

		fn create_response(&self) -> ResponsePackage {
			ResponsePackage {
				status: self.expected_status,
				message: if self.should_have_message {
					Some(Arc::new(create_v0_tightbeam(Some(self.message_value), None)))
				} else {
					None
				},
			}
		}
	}

	fn as_test_cases() -> Vec<PackageTestCase> {
		vec![
			PackageTestCase {
				message_value: "Hi",
				expected_status: TransitStatus::Accepted,
				should_have_message: true,
			},
			PackageTestCase {
				// cspell:disable-next-line
				message_value: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
				expected_status: TransitStatus::Accepted,
				should_have_message: true,
			},
			PackageTestCase {
				message_value: "",
				expected_status: TransitStatus::Accepted,
				should_have_message: true,
			},
			PackageTestCase {
				message_value: "Busy",
				expected_status: TransitStatus::Busy,
				should_have_message: false,
			},
			PackageTestCase {
				message_value: "Unauthorized",
				expected_status: TransitStatus::Unauthorized,
				should_have_message: false,
			},
		]
	}

	#[test]
	fn test_request_package_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
		for test_case in as_test_cases() {
			let original = test_case.create_request();
			let encoded = original.to_der()?;
			let decoded = RequestPackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}

		Ok(())
	}

	#[test]
	fn test_response_package_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
		for test_case in as_test_cases() {
			let original = test_case.create_response();
			let encoded = original.to_der()?;
			let decoded = ResponsePackage::from_der(&encoded)?;
			assert_eq!(original.status, decoded.status);
			assert_eq!(original.message, decoded.message);
		}

		Ok(())
	}

	#[test]
	fn test_length_validation_request() -> Result<(), Box<dyn std::error::Error>> {
		let original = RequestPackage::new(create_v0_tightbeam(None, None));
		let mut encoded = original.to_der()?;

		// Corrupt the length field by manipulating bytes after encoding
		// The length is encoded as a Uint at the beginning of the sequence
		// We need to find and modify it carefully
		if encoded.len() > 10 {
			// Corrupt a byte in the middle to simulate wrong length
			let corrupt_pos = 5;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// Decoding should fail due to length mismatch
			let result = RequestPackage::from_der(&encoded);
			assert!(result.is_err(), "Should fail with corrupted length");
		}

		Ok(())
	}

	#[test]
	fn test_length_validation_response() -> Result<(), Box<dyn std::error::Error>> {
		let original = ResponsePackage {
			status: TransitStatus::Accepted,
			message: Some(Arc::new(create_v0_tightbeam(None, None))),
		};
		let mut encoded = original.to_der()?;

		// Corrupt the length field
		if encoded.len() > 10 {
			let corrupt_pos = 8;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// Decoding should fail due to length mismatch
			let result = ResponsePackage::from_der(&encoded);
			assert!(result.is_err(), "Should fail with corrupted length");
		}

		Ok(())
	}

	#[test]
	fn test_response_empty_message() -> Result<(), Box<dyn std::error::Error>> {
		let original = ResponsePackage { status: TransitStatus::Busy, message: None };

		let encoded = original.to_der()?;
		let decoded = ResponsePackage::from_der(&encoded)?;
		assert_eq!(original.status, decoded.status);
		assert_eq!(original.message, decoded.message);
		Ok(())
	}

	#[test]
	fn test_envelope_builder_cleartext_limit_returns_message() {
		let frame = create_v0_tightbeam(None, None);
		let err = EnvelopeBuilder::request(frame.clone())
			.with_max_cleartext_envelope(1)
			.finish()
			.expect_err("cleartext size limit should fail");

		match err {
			TransportError::MessageNotSent(returned, TransportFailure::SizeExceeded) => {
				assert_eq!(*returned, frame);
			}
			other => panic!("unexpected error variant: {other:?}"),
		}
	}

	#[cfg(feature = "aes-gcm")]
	#[test]
	fn test_envelope_builder_encrypted_limit_returns_message() -> Result<(), Box<dyn std::error::Error>> {
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid, KeyInit};

		let frame = create_v0_tightbeam(None, None);
		let cipher = Aes256Gcm::new_from_slice(&[0u8; 32]).map_err(|_| "Invalid key")?;
		let encryptor = RuntimeAead::new(cipher, Aes256GcmOid::OID);

		let err = EnvelopeBuilder::request(frame.clone())
			.with_wire_mode(WireMode::Encrypted)
			.with_encryptor(&encryptor)
			.with_max_encrypted_envelope(1)
			.finish()
			.expect_err("encrypted size limit should fail");

		match err {
			TransportError::MessageNotSent(returned, TransportFailure::SizeExceeded) => {
				assert_eq!(*returned, frame);
			}
			other => panic!("unexpected error variant: {other:?}"),
		}
		Ok(())
	}
}
