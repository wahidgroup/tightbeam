#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "x509")]
use crate::crypto::aead::{Decryptor, Encryptor};
#[cfg(feature = "derive")]
use crate::Beamable;

pub mod error;
pub mod handshake;

#[cfg(feature = "transport-policy")]
pub mod policy;
#[cfg(feature = "tcp")]
pub mod tcp;

use crate::asn1::Frame;
use crate::cms::enveloped_data::EncryptedContentInfo;
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::der::asn1::Uint;
use crate::der::{Choice, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use crate::policy::{GatePolicy, TransitStatus};
use crate::transport::error::TransportError;

#[cfg(feature = "transport-policy")]
use crate::transport::policy::RestartPolicy;

/// Transport-agnostic result type
pub type TransportResult<T> = Result<T, TransportError>;

/// Marker crate for applications to handle the address the way they wish
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}

#[cfg(all(feature = "x509", feature = "std"))]
#[derive(Clone)]
pub struct TransportEncryptionConfig {
	pub certificate: crate::x509::Certificate,
	pub signatory: std::sync::Arc<dyn crate::transport::handshake::ServerHandshakeKey>,
	pub aad_domain_tag: Vec<u8>,
	pub max_cleartext_envelope: usize,
	pub max_encrypted_envelope: usize,
	pub handshake_timeout: std::time::Duration,
	pub enforce_encryption: bool,
	pub accept_cleartext_before_handshake: bool,
}

#[cfg(all(feature = "x509", feature = "std"))]
impl TransportEncryptionConfig {
	pub fn new(
		certificate: crate::x509::Certificate,
		signatory: std::sync::Arc<dyn crate::transport::handshake::ServerHandshakeKey>,
	) -> Self {
		Self {
			certificate,
			signatory,
			aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG.to_vec(),
			max_cleartext_envelope: 128 * 1024,
			max_encrypted_envelope: 256 * 1024,
			handshake_timeout: std::time::Duration::from_secs(10),
			enforce_encryption: true,
			accept_cleartext_before_handshake: true,
		}
	}
}

// Remove Sequence derive, implement custom encoding
#[derive(Debug, Clone)]
pub struct RequestPackage {
	/// The length is critical for transport
	#[allow(dead_code)]
	length: Option<u64>,
	message: Frame,
}

impl PartialEq for RequestPackage {
	fn eq(&self, other: &Self) -> bool {
		self.message == other.message
	}
}

impl RequestPackage {
	pub fn new(message: Frame) -> Self {
		Self { length: None, message }
	}
}

impl EncodeValue for RequestPackage {
	fn value_len(&self) -> der::Result<Length> {
		let message_len = self.message.encoded_len()?;
		let length_value = u64::from(u32::from(message_len));
		let length_field = Uint::new(&length_value.to_be_bytes())?;

		length_field.encoded_len()? + message_len
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		let message_len = self.message.encoded_len()?;
		let length_value = u64::from(u32::from(message_len));
		let length_field = Uint::new(&length_value.to_be_bytes())?;

		length_field.encode(writer)?;
		self.message.encode(writer)?;
		Ok(())
	}
}

impl<'a> DecodeValue<'a> for RequestPackage {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _: Header) -> der::Result<Self> {
		let length_uint = Uint::decode(reader)?;
		let bytes = length_uint.as_bytes();

		// Convert bytes to u64 (big-endian)
		let mut length_bytes = [0u8; 8];
		let offset = 8usize.saturating_sub(bytes.len());
		length_bytes[offset..].copy_from_slice(bytes);
		let length = u64::from_be_bytes(length_bytes);

		let message = reader.decode::<Frame>()?;
		let actual_len = message.encoded_len()?;

		if u64::from(u32::from(actual_len)) != length {
			// Length mismatch
			return Err(der::Error::from(der::ErrorKind::Length { tag: Tag::Integer }));
		}

		Ok(Self { length: Some(length), message })
	}
}

impl FixedTag for RequestPackage {
	const TAG: Tag = Tag::Sequence;
}

// Remove Sequence derive, implement custom encoding
#[derive(Debug, Clone, Default)]
pub struct ResponsePackage {
	/// The length is critical for transport
	#[allow(dead_code)]
	length: Option<u64>,
	status: TransitStatus,
	message: Option<Frame>,
}

impl PartialEq for ResponsePackage {
	fn eq(&self, other: &Self) -> bool {
		self.status == other.status && self.message == other.message
	}
}

impl EncodeValue for ResponsePackage {
	fn value_len(&self) -> der::Result<Length> {
		let status_len = self.status.encoded_len()?;
		let message_len = self
			.message
			.as_ref()
			.map(|m| m.encoded_len())
			.transpose()?
			.unwrap_or(Length::ZERO);
		let length_value = u64::from(u32::from(message_len));
		let length_field = Uint::new(&length_value.to_be_bytes())?;

		status_len + length_field.encoded_len()? + message_len
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		self.status.encode(writer)?;

		let message_len = self
			.message
			.as_ref()
			.map(|m| m.encoded_len())
			.transpose()?
			.unwrap_or(Length::ZERO);
		let length_value = u64::from(u32::from(message_len));
		let length_field = Uint::new(&length_value.to_be_bytes())?;
		length_field.encode(writer)?;

		if let Some(ref message) = self.message {
			message.encode(writer)?;
		}

		Ok(())
	}
}

impl<'a> DecodeValue<'a> for ResponsePackage {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _: Header) -> der::Result<Self> {
		let status = TransitStatus::decode(reader)?;
		let length_uint = Uint::decode(reader)?;
		let bytes = length_uint.as_bytes();

		// Convert bytes to u64 (big-endian)
		let mut length_bytes = [0u8; 8];
		let offset = 8usize.saturating_sub(bytes.len());
		length_bytes[offset..].copy_from_slice(bytes);
		let length = u64::from_be_bytes(length_bytes);

		let message = if length > 0 {
			let msg = reader.decode::<Frame>()?;
			let actual_len = msg.encoded_len()?;

			if u64::from(u32::from(actual_len)) != length {
				// Length mismatch
				return Err(der::Error::from(der::ErrorKind::Length { tag: Tag::Integer }));
			}

			Some(msg)
		} else {
			None
		};

		Ok(Self { length: Some(length), status, message })
	}
}

impl FixedTag for ResponsePackage {
	const TAG: Tag = Tag::Sequence;
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
	EnvelopedData(crate::cms::enveloped_data::EnvelopedData),
	#[cfg(feature = "x509")]
	#[asn1(context_specific = "3", constructed = "true")]
	SignedData(crate::cms::signed_data::SignedData),
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

#[cfg(not(feature = "derive"))]
impl crate::Message for TransportEnvelope {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: crate::Version = crate::Version::V0;
}

impl From<ResponsePackage> for TransportEnvelope {
	fn from(pkg: ResponsePackage) -> Self {
		Self::Response(pkg)
	}
}

impl From<Frame> for TransportEnvelope {
	fn from(msg: Frame) -> Self {
		Self::Request(RequestPackage { length: None, message: msg })
	}
}

/// Stream trait - defines how to read and write
pub trait ProtocolStream: Send {
	type Error: Into<TransportError>;

	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
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
	fn get_tightbeam_addr(&self) -> Result<Self::Address, Self::Error>;
}

#[cfg(feature = "x509")]
pub trait EncryptedProtocol: Protocol {
	type Encryptor: crate::crypto::aead::Encryptor<crate::crypto::aead::Aes256GcmOid>;
	type Decryptor: crate::crypto::aead::Decryptor;

	/// Bind to an address with transport encryption configuration
	fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig,
	) -> impl core::future::Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// This protocol can operate as a mycelial network (ie. TCP SocketAddress)
pub trait Mycelial: Protocol {
	fn get_available_connect(
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
		crate::encode(envelope).map_err(TransportError::from)
	}

	/// Read and decode a transport envelope
	/// This can be overridden by EncryptedMessageIO to handle WireEnvelope parsing
	#[allow(async_fn_in_trait)]
	async fn read_decoded_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let bytes = self.read_envelope().await?;
		Self::decode_envelope(&bytes)
	}

	/// Send a response back to the sender
	fn handle_message(&self, message: Frame) -> Option<Frame> {
		// If a handler is set, use it to generate the response
		self.handler().and_then(|handler| handler(message))
	}

	/// Helper for parsing DER length encoding
	fn parse_der_length(first_byte: u8, length_octets: &[u8]) -> usize {
		if first_byte & 0x80 == 0 {
			// Short form
			first_byte as usize
		} else {
			// Long form
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
	type Encryptor: crate::crypto::aead::Encryptor<crate::crypto::aead::Aes256GcmOid>;
	type Decryptor: crate::crypto::aead::Decryptor;

	/// Get the encryptor instance
	fn encryptor(&self) -> TransportResult<&Self::Encryptor>;

	/// Get the decryptor instance
	fn decryptor(&self) -> TransportResult<&Self::Decryptor>;

	/// Get current handshake state (pure accessor)
	fn handshake_state(&self) -> crate::transport::handshake::HandshakeState;

	/// Set handshake state (pure mutator)
	fn set_handshake_state(&mut self, state: crate::transport::handshake::HandshakeState);

	/// Get server certificate if present (pure accessor)
	fn server_certificate(&self) -> Option<&crate::x509::Certificate>;

	/// Set symmetric encryption key (pure mutator)
	fn set_symmetric_key(&mut self, key: Self::Encryptor);

	/// Relay a message by detecting whether it's encrypted or cleartext
	/// Returns the decrypted TransportEnvelope ready for processing
	#[allow(async_fn_in_trait)]
	async fn relay_message(&mut self) -> TransportResult<TransportEnvelope> {
		let wire_bytes = self.read_envelope().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)
			.map_err(crate::TightBeamError::from)
			.map_err(TransportError::from)?;

		match wire_envelope {
			WireEnvelope::Cleartext(transport_envelope) => {
				// Check if server expects encryption but received cleartext
				if self.decryptor().is_ok() {
					// Server has encryption configured, reject cleartext
					return Err(TransportError::MissingEncryption);
				}
				Ok(transport_envelope)
			}
			WireEnvelope::Encrypted(encrypted_info) => {
				let decrypted_bytes = self
					.decryptor()?
					.decrypt_content(&encrypted_info)
					.map_err(TransportError::from)?;

				Self::decode_envelope(&decrypted_bytes)
			}
		}
	}

	/// Read and decrypt an envelope (legacy method, use relay_message instead)
	#[allow(async_fn_in_trait)]
	async fn read_encrypted_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let encrypted_bytes = self.read_envelope().await?;
		let encrypted_info = crate::EncryptedContentInfo::from_der(&encrypted_bytes)
			.map_err(crate::TightBeamError::from)
			.map_err(TransportError::from)?;

		let decrypted_bytes = self
			.decryptor()?
			.decrypt_content(&encrypted_info)
			.map_err(TransportError::from)?;

		Self::decode_envelope(&decrypted_bytes)
	}

	/// Send a cleartext or encrypted envelope based on encryption flag
	#[allow(async_fn_in_trait)]
	async fn send_envelope(&mut self, envelope: &TransportEnvelope, encrypt: bool) -> TransportResult<()> {
		let wire_envelope = if encrypt {
			let envelope_bytes = Self::encode_envelope(envelope)?;
			let encrypted_info = self
				.encryptor()?
				.encrypt_content(&envelope_bytes, [], None)
				.map_err(TransportError::from)?;

			WireEnvelope::Encrypted(encrypted_info)
		} else {
			WireEnvelope::Cleartext(envelope.clone())
		};

		let wire_bytes = wire_envelope
			.to_der()
			.map_err(crate::TightBeamError::from)
			.map_err(TransportError::from)?;

		self.write_envelope(&wire_bytes).await
	}

	/// Encrypt and write an envelope (legacy method, use send_envelope instead)
	#[allow(async_fn_in_trait)]
	async fn write_encrypted_envelope(&mut self, envelope: &TransportEnvelope) -> TransportResult<()> {
		self.send_envelope(envelope, true).await
	}
}

/// Trait for handling responses to incoming messages
pub trait Pingable {
	/// Ping the transport layer to check connectivity
	fn ping(&mut self) -> TransportResult<()>;
}

/// Base emitter functionality
#[cfg(feature = "transport-policy")]
pub trait MessageEmitter: MessageIO {
	type EmitterGate: GatePolicy + ?Sized;
	type RestartPolicy: RestartPolicy + ?Sized;

	/// Get the restart policy instance
	fn get_restart_policy(&self) -> &Self::RestartPolicy;

	/// Get the emitter gate policy instance
	fn get_emitter_gate_policy(&self) -> &Self::EmitterGate;

	/// Send a TightBeam message
	#[allow(async_fn_in_trait)]
	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		let mut current_message = message;
		let mut current_attempt = attempt.unwrap_or(0);

		loop {
			// Evaluate gate policy before sending
			let status = self.get_emitter_gate_policy().evaluate(&current_message);
			if status != TransitStatus::Accepted {
				// The gate did not accept the message
				return Err(TransportError::from(status));
			}

			// Wrap in envelope and send
			let envelope = TransportEnvelope::from(current_message);

			// When x509 is enabled, wrap in WireEnvelope for protocol compatibility
			#[cfg(feature = "x509")]
			{
				let wire_envelope = WireEnvelope::Cleartext(envelope.clone());
				self.write_envelope(&wire_envelope.to_der()?).await?;
			}

			#[cfg(not(feature = "x509"))]
			{
				self.write_envelope(&envelope.to_der()?).await?;
			}

			// Extract message back from envelope
			current_message = match envelope {
				TransportEnvelope::Request(msg) => msg.message,
				// This should never happen as we just created it
				_ => unreachable!(),
			};

			// Wait for receiver's response envelope
			let response_bytes = self.read_envelope().await?;

			// When x509 is enabled, parse as WireEnvelope first
			#[cfg(feature = "x509")]
			let response_envelope = {
				let wire_envelope = WireEnvelope::from_der(&response_bytes)?;
				match wire_envelope {
					WireEnvelope::Cleartext(env) => env,
					WireEnvelope::Encrypted(_) => {
						// Client doesn't handle encrypted responses in emit() yet
						return Err(TransportError::InvalidMessage);
					}
				}
			};

			#[cfg(not(feature = "x509"))]
			let response_envelope = Self::decode_envelope(&response_bytes)?;

			let (status, response) = match response_envelope {
				TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
				TransportEnvelope::Request(_) => {
					// Only responses are valid here
					return Err(TransportError::InvalidMessage);
				}
				#[cfg(feature = "x509")]
				TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
					// Handshake messages not expected here
					return Err(TransportError::InvalidMessage);
				}
			};

			// Check transport status and handle response
			let result = if status != TransitStatus::Accepted {
				Err(TransportError::from(status))
			} else {
				match &response {
					Some(msg) => Ok(msg),
					None => return Ok(None),
				}
			};

			let policy = self.get_restart_policy().evaluate(current_message, result, current_attempt);
			match policy {
				Some(retry_message) => {
					if current_attempt == usize::MAX {
						// Prevent overflow
						return Err(TransportError::MaxRetriesExceeded);
					} else {
						current_message = retry_message;
						current_attempt += 1;
						continue;
					}
				}
				None => {
					// Return based on the original result construction
					if status != TransitStatus::Accepted {
						return Err(TransportError::from(status));
					} else {
						return Ok(response);
					}
				}
			}
		}
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
	async fn collect_message(&mut self) -> TransportResult<(Frame, TransitStatus)> {
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
		let response_pkg = ResponsePackage { status, message, length: None };
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
}

#[cfg(not(feature = "transport-policy"))]
pub trait MessageCollector: MessageIO {
	/// Read and validate a message without sending a response
	/// Returns the message (status is always Accepted without policies)
	#[allow(async_fn_in_trait)]
	async fn collect_message(&mut self) -> TransportResult<(Frame, TransitStatus)> {
		// Read the envelope
		let request_envelope = self.read_envelope().await?;
		// Extract message from request
		let request = match request_envelope {
			TransportEnvelope::Request(msg) => msg,
			TransportEnvelope::Response(_) => {
				return Err(TransportError::InvalidMessage);
			}
		};

		Ok((request, TransitStatus::Accepted))
	}

	/// Send a response for a previously collected message
	#[allow(async_fn_in_trait)]
	async fn send_response(&mut self, status: TransitStatus, message: Option<Frame>) -> TransportResult<()> {
		let response_pkg = ResponsePackage { status, message, length: None };
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
		F: Fn(crate::Frame) -> Option<crate::Frame> + Send + 'static;

	/// Get the current handler if one is set
	fn handler(&self) -> Option<&(dyn Fn(crate::Frame) -> Option<crate::Frame> + Send)>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::{Decode, Encode};
	use crate::testing::create_v0_tightbeam;
	use crate::transport::policy::PolicyConf;

	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_server_and_client_macros() -> TransportResult<()> {
		use std::sync::{mpsc, Arc};

		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
		let addr = TightBeamSocketAddr(listener.local_addr().unwrap());

		let (tx, rx) = mpsc::channel();
		let tx = Arc::new(tx);

		// Spawn server using server! macro
		let server_handle = crate::server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = tx.clone();
				async move {
					// Quantum tunnel testing channel -- TUNNEL
					let _ = tx.send(message);
					None
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
		let received = rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
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
				length: None,
				status: self.expected_status,
				message: if self.should_have_message {
					Some(create_v0_tightbeam(Some(self.message_value), None))
				} else {
					None
				},
			}
		}
	}

	fn get_test_cases() -> Vec<PackageTestCase> {
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
	fn test_request_package_encode_decode() {
		for test_case in get_test_cases() {
			let original = test_case.create_request();

			let encoded = original.to_der().unwrap();
			let decoded = RequestPackage::from_der(&encoded).unwrap();
			assert_eq!(original, decoded);
			assert!(decoded.length.is_some());
		}
	}

	#[test]
	fn test_response_package_encode_decode() {
		for test_case in get_test_cases() {
			let original = test_case.create_response();

			let encoded = original.to_der().unwrap();
			let decoded = ResponsePackage::from_der(&encoded).unwrap();
			assert_eq!(original.status, decoded.status);
			assert_eq!(original.message, decoded.message);
			assert!(decoded.length.is_some());
		}
	}

	#[test]
	fn test_length_validation_request() {
		let original = RequestPackage::new(create_v0_tightbeam(None, None));
		let mut encoded = original.to_der().unwrap();

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
	}

	#[test]
	fn test_length_validation_response() {
		let original = ResponsePackage {
			length: None,
			status: TransitStatus::Accepted,
			message: Some(create_v0_tightbeam(None, None)),
		};
		let mut encoded = original.to_der().unwrap();

		// Corrupt the length field
		if encoded.len() > 10 {
			let corrupt_pos = 8;
			encoded[corrupt_pos] = encoded[corrupt_pos].wrapping_add(1);

			// Decoding should fail due to length mismatch
			let result = ResponsePackage::from_der(&encoded);
			assert!(result.is_err(), "Should fail with corrupted length");
		}
	}

	#[test]
	fn test_response_empty_message() {
		let original = ResponsePackage { length: None, status: TransitStatus::Busy, message: None };

		let encoded = original.to_der().unwrap();
		let decoded = ResponsePackage::from_der(&encoded).unwrap();

		assert_eq!(original.status, decoded.status);
		assert_eq!(original.message, decoded.message);
		assert_eq!(decoded.length.unwrap(), 0);
	}
}
