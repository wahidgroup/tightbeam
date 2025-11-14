#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(all(feature = "x509", feature = "std"))]
use std::time::Duration;

pub mod error;
pub mod handshake;

#[cfg(feature = "transport-policy")]
pub mod policy;
#[cfg(feature = "tcp")]
pub mod tcp;

use crate::asn1::Frame;
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData};
use crate::cms::signed_data::SignedData;
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::der::{Choice, Decode, Encode, Sequence};
use crate::policy::{GatePolicy, TransitStatus};
use crate::transport::error::TransportError;
use crate::{encode, TightBeamError};

#[cfg(feature = "x509")]
use crate::crypto::aead::{Decryptor, RuntimeAead};
#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::transport::handshake::{ServerKeyManager, TcpHandshakeState};
#[cfg(feature = "transport-policy")]
use crate::transport::policy::RestartPolicy;
#[cfg(feature = "x509")]
use crate::x509::Certificate;
#[cfg(feature = "derive")]
use crate::Beamable;

/// Transport-agnostic result type
pub type TransportResult<T> = Result<T, TransportError>;

/// Marker crate for applications to handle the address the way they wish
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}

#[cfg(all(feature = "x509", feature = "std"))]
#[derive(Clone)]
pub struct TransportEncryptionConfig {
	pub certificate: Certificate,
	pub signatory: ServerKeyManager,
	pub client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	pub aad_domain_tag: &'static [u8],
	pub max_cleartext_envelope: usize,
	pub max_encrypted_envelope: usize,
	pub handshake_timeout: Duration,
}

#[cfg(all(feature = "x509", feature = "std"))]
impl TransportEncryptionConfig {
	pub fn new(certificate: Certificate, signatory: ServerKeyManager) -> Self {
		Self {
			certificate,
			signatory,
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

/// Request package containing a TightBeam message
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct RequestPackage {
	message: Frame,
}

impl RequestPackage {
	pub fn new(message: Frame) -> Self {
		Self { message }
	}
}

/// Response package containing status and optional message
#[derive(Sequence, Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponsePackage {
	status: TransitStatus,
	#[asn1(optional = "true")]
	message: Option<Frame>,
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
		Self::Request(RequestPackage { message: msg })
	}
}

impl TransportEnvelope {
	/// Create a new request envelope from a message
	pub fn new_request(msg: Frame) -> Self {
		Self::Request(RequestPackage { message: msg })
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
	type Encryptor: Send;
	type Decryptor: Send;

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
		encode(envelope).map_err(TransportError::from)
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
	/// Get the encryptor instance (RuntimeAead)
	fn encryptor(&self) -> TransportResult<&RuntimeAead>;

	/// Get the decryptor instance (RuntimeAead)
	fn decryptor(&self) -> TransportResult<&RuntimeAead>;

	/// Get current handshake state (pure accessor)
	fn handshake_state(&self) -> TcpHandshakeState;

	/// Set handshake state (pure mutator)
	fn set_handshake_state(&mut self, state: TcpHandshakeState);

	/// Get server certificate if present (pure accessor)
	fn server_certificate(&self) -> Option<&Certificate>;

	/// Set symmetric encryption key (pure mutator)
	fn set_symmetric_key(&mut self, key: RuntimeAead);

	/// Relay a message by detecting whether it's encrypted or cleartext
	/// Returns the decrypted TransportEnvelope ready for processing
	#[allow(async_fn_in_trait)]
	async fn relay_message(&mut self) -> TransportResult<TransportEnvelope> {
		let wire_bytes = self.read_envelope().await?;
		let wire_envelope = WireEnvelope::from_der(&wire_bytes)
			.map_err(TightBeamError::from)
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
		let encrypted_info = EncryptedContentInfo::from_der(&encrypted_bytes)
			.map_err(TightBeamError::from)
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
			.map_err(TightBeamError::from)
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
		// Instrument message emit event
		#[cfg(feature = "instrument")]
		{
			let _ = crate::instrumentation::emit(
				crate::instrumentation::TbEventKind::RequestRecv,
				Some("message_emit"),
				None,
				None,
				0,
				None,
			);
		}

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
			let envelope = TransportEnvelope::new_request(current_message.clone());

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

			// Evaluate retry policy only on error
			if result.is_err() {
				let action = self.get_restart_policy().evaluate(&current_message, &result, current_attempt);
				match action {
					crate::transport::policy::RetryAction::RetryWithSame => {
						if current_attempt == usize::MAX {
							return Err(TransportError::MaxRetriesExceeded);
						} else {
							current_attempt += 1;
							continue;
						}
					}
					crate::transport::policy::RetryAction::RetryWithModified(retry_message) => {
						if current_attempt == usize::MAX {
							return Err(TransportError::MaxRetriesExceeded);
						} else {
							current_message = *retry_message;
							current_attempt += 1;
							continue;
						}
					}
					crate::transport::policy::RetryAction::NoRetry => {
						// Return the error
						return result.map(|_| None);
					}
				}
			} else {
				// Success case - return response
				return Ok(response);
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

		// Instrument message collect event
		#[cfg(feature = "instrument")]
		{
			let _ = crate::instrumentation::emit(
				crate::instrumentation::TbEventKind::ResponseSend,
				Some("message_collect"),
				None,
				None,
				0,
				None,
			);
		}

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
		let response_pkg = ResponsePackage { status, message };
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
		let response_pkg = ResponsePackage { status, message };
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

		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

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
		let received = rx.recv_timeout(Duration::from_secs(1)).map_err(|_| TransportError::Timeout)?;
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
	fn test_request_package_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
		for test_case in get_test_cases() {
			let original = test_case.create_request();

			let encoded = original.to_der()?;
			let decoded = RequestPackage::from_der(&encoded)?;
			assert_eq!(original, decoded);
		}
		Ok(())
	}

	#[test]
	fn test_response_package_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
		for test_case in get_test_cases() {
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
		let original =
			ResponsePackage { status: TransitStatus::Accepted, message: Some(create_v0_tightbeam(None, None)) };
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
}
