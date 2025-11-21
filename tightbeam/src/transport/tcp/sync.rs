#![cfg(feature = "x509")]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::str::FromStr;
use core::time::Duration;

use crate::builder::TypeBuilder;
use crate::crypto::aead::RuntimeAead;
use crate::crypto::x509::policy::CertificateValidation;
use crate::der::Encode;
use crate::prelude::TightBeamSocketAddr;
use crate::transport::handshake::{
	HandshakeError, HandshakeKeyManager, HandshakeProtocolKind, ServerHandshakeProtocol, TcpHandshakeState,
};
use crate::transport::tcp::TcpListenerTrait;
use crate::transport::{EncryptedMessageIO, EncryptedProtocol, Protocol, ResponsePackage, TransportEncryptionConfig};
use crate::transport::{MessageIO, Pingable, TransportResult};
use crate::x509::Certificate;
use crate::Frame;

#[cfg(feature = "transport-policy")]
use crate::{
	policy::GatePolicy,
	transport::{
		error::TransportError, policy::RestartPolicy, tcp::ProtocolStream, EnvelopeBuilder, EnvelopeLimits, WireMode,
	},
};

pub struct TcpTransport<S: ProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<Frame> + Send>>,
	#[cfg(feature = "transport-policy")]
	restart_policy: Box<dyn RestartPolicy>,
	#[cfg(feature = "transport-policy")]
	emitter_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "transport-policy")]
	collector_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "std")]
	operation_timeout: Option<std::time::Duration>,

	server_certificates: Vec<Arc<Certificate>>,

	client_certificate: Option<Arc<Certificate>>,

	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,

	peer_certificate: Option<Certificate>,

	aad_domain_tag: Option<&'static [u8]>,

	max_cleartext_envelope: Option<usize>,

	max_encrypted_envelope: Option<usize>,

	key_manager: Option<Arc<HandshakeKeyManager>>,

	handshake_state: TcpHandshakeState,

	handshake_timeout: Duration,

	symmetric_key: Option<RuntimeAead>,

	server_handshake: Option<Box<dyn ServerHandshakeProtocol<Error = HandshakeError>>>,

	handshake_protocol_kind: HandshakeProtocolKind,
}

impl<S: ProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		// Try to write zero bytes to check if the connection is alive
		self.stream.write_all(&[]).map_err(|e| e.into())
	}
}

// Use the macro to generate common implementations
crate::impl_tcp_common!(TcpTransport, ProtocolStream);

impl<S: ProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		// Apply operation timeout if configured
		#[cfg(feature = "std")]
		if let Some(timeout) = self.operation_timeout {
			self.stream.set_timeout(Some(timeout))?;
		}

		// Perform all reads - timeout will apply to all operations
		let result = (|| -> TransportResult<Vec<u8>> {
			// Read tag byte
			let mut tag_byte = [0u8; 1];
			self.stream.read_exact(&mut tag_byte)?;

			// Read length encoding
			let mut length_first = [0u8; 1];
			self.stream.read_exact(&mut length_first)?;

			let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
				// Short form
				(vec![], length_first[0] as usize)
			} else {
				// Long form
				let num_length_octets = (length_first[0] & 0x7F) as usize;
				let mut length_octets = vec![0u8; num_length_octets];
				self.stream.read_exact(&mut length_octets)?;

				let length = Self::parse_der_length(length_first[0], &length_octets);
				(length_octets, length)
			};

			// Enforce size ceilings if configured
			{
				let max_allowed = self
					.max_encrypted_envelope
					.or(self.max_cleartext_envelope)
					.unwrap_or(512 * 1024);
				if content_length > max_allowed {
					return Err(TransportError::InvalidMessage);
				}
			}

			// If in handshake waiting state, optionally enforce timeout by
			// short read deadline using std only
			{
				match self.handshake_state() {
					TcpHandshakeState::AwaitingServerResponse { initiated_at }
					| TcpHandshakeState::AwaitingClientFinish { initiated_at } => {
						let now = std::time::Instant::now();
						if now >= initiated_at + self.handshake_timeout {
							return Err(TransportError::Timeout);
						}
					}
					_ => {}
				}
			}

			// Read content
			let mut content = vec![0u8; content_length];
			self.stream.read_exact(&mut content)?;

			// Reconstruct full DER encoding using the helper
			let buffer = Self::reconstruct_der_encoding(tag_byte[0], length_first[0], &length_octets, &content);
			Ok(buffer)
		})();

		// Clear timeout before handling result
		#[cfg(feature = "std")]
		if self.operation_timeout.is_some() {
			let _ = self.stream.set_timeout(None);
		}

		result
	}

	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()> {
		// Apply operation timeout if configured
		#[cfg(feature = "std")]
		if let Some(timeout) = self.operation_timeout {
			self.stream.set_timeout(Some(timeout))?;
		}

		let result = self.stream.write_all(buffer);

		// Clear timeout before handling result
		#[cfg(feature = "std")]
		if self.operation_timeout.is_some() {
			let _ = self.stream.set_timeout(None);
		}

		result?;
		Ok(())
	}
}

#[cfg(feature = "transport-policy")]
impl<S: ProtocolStream> crate::transport::MessageCollector for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type CollectorGate = dyn crate::policy::GatePolicy;

	fn collector_gate(&self) -> &Self::CollectorGate {
		self.collector_gate.as_ref()
	}

	async fn collect_message(&mut self) -> TransportResult<(Arc<Frame>, crate::policy::TransitStatus)> {
		use crate::crypto::aead::Decryptor;
		use crate::der::{Decode, Encode};
		use crate::policy::TransitStatus;
		use crate::transport::handshake::TcpHandshakeState;
		use crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};

		loop {
			let wire_bytes = self.read_envelope().await?;
			let wire_envelope = match WireEnvelope::from_der(&wire_bytes) {
				Ok(env) => env,
				Err(e) => return Err(TransportError::DerError(e)),
			};

			// Per-envelope size ceilings

			{
				match &wire_envelope {
					WireEnvelope::Cleartext(_) => {
						if let Some(max) = self.max_cleartext_envelope {
							if wire_bytes.len() > max {
								return Err(TransportError::InvalidMessage);
							}
						}
					}
					WireEnvelope::Encrypted(_) => {
						if let Some(max) = self.max_encrypted_envelope {
							if wire_bytes.len() > max {
								return Err(TransportError::InvalidMessage);
							}
						}
					}
				}
			}

			let has_certificate = self.server_certificate().is_some();
			let decoded_envelope = match wire_envelope {
				WireEnvelope::Cleartext(envelope) => {
					if has_certificate {
						// Server with certificate - enforce encryption based on handshake state
						match envelope {
							// Handshake messages - always allowed as cleartext
							TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
								let handshake_bytes = envelope.to_der()?;
								self.perform_server_handshake(&handshake_bytes).await?;
								continue;
							}
							// Application messages - use circuit breaker pattern
							TransportEnvelope::Request(_) | TransportEnvelope::Response(_) => {
								// Circuit breaker: cleartext application messages not allowed when server has certificate
								// Reset handshake state and reject
								self.set_handshake_state(TcpHandshakeState::None);
								self.symmetric_key = None;
								return Err(TransportError::MissingEncryption);
							}
						}
					} else {
						envelope
					}
				}
				WireEnvelope::Encrypted(encrypted_info) => {
					// Encrypted message - verify handshake is complete
					if self.handshake_state() != TcpHandshakeState::Complete {
						// Circuit breaker: encrypted message before handshake complete
						self.set_handshake_state(TcpHandshakeState::None);
						self.symmetric_key = None;
						return Err(TransportError::Forbidden);
					}

					// Decrypt the envelope
					let decrypted_bytes = match self.decryptor()?.decrypt_content(&encrypted_info) {
						Ok(bytes) => bytes,
						Err(_) => {
							// Circuit breaker: decryption failure, reset state
							self.set_handshake_state(TcpHandshakeState::None);
							self.symmetric_key = None;
							return Err(TransportError::Forbidden);
						}
					};
					<Self as MessageIO>::decode_envelope(&decrypted_bytes)?
				}
			};
			let request = match decoded_envelope {
				TransportEnvelope::Request(msg) => msg.message,
				TransportEnvelope::Response(_) => return Err(TransportError::InvalidMessage),
				TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
					return Err(TransportError::InvalidMessage)
				}
			};

			let status: TransitStatus = self.collector_gate().evaluate(&request);
			if status == TransitStatus::Request {
				return Err(TransportError::InvalidReply);
			}

			return Ok((request, status));
		}
	}

	async fn send_response(
		&mut self,
		status: crate::policy::TransitStatus,
		message: Option<Frame>,
	) -> TransportResult<()> {
		let response_pkg = ResponsePackage { status, message: message.map(Arc::new) };
		let limits = EnvelopeLimits::from_pair(self.max_cleartext_envelope, self.max_encrypted_envelope);
		let mut builder = limits.apply(EnvelopeBuilder::response(response_pkg));

		if self.handshake_state() == TcpHandshakeState::Complete {
			let encryptor = self.encryptor()?;
			builder = builder.with_wire_mode(WireMode::Encrypted).with_encryptor(encryptor);
		} else {
			builder = builder.with_wire_mode(WireMode::Cleartext);
		}

		let wire_envelope = builder.build()?;
		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope(&wire_bytes).await
	}
}

#[cfg(feature = "transport-policy")]
impl<S: ProtocolStream> TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	/// Ensure handshake is complete, performing it if needed
	/// Returns error if handshake fails (caller handles message return)
	async fn ensure_handshake_complete(&mut self) -> TransportResult<()> {
		use crate::transport::handshake::TcpHandshakeState;

		// Check if handshake is needed
		#[cfg(feature = "x509")]
		let should_handshake = (self.server_certificate().is_some() || self.client_validators.is_some())
			&& self.handshake_state() == TcpHandshakeState::None;
		#[cfg(not(feature = "x509"))]
		let should_handshake = false;

		if should_handshake {
			self.perform_client_handshake().await?;
		}

		Ok(())
	}

	// Helper method to perform a single request-response cycle
	// Takes ownership of message and returns it on error via TransportError variants
	// Returns (status, response, original_message) where original_message is Some when status != Accepted
	async fn perform_emit_cycle(
		&mut self,
		message: Frame,
	) -> TransportResult<(crate::policy::TransitStatus, Option<Frame>, Option<Frame>)> {
		use crate::der::Encode;
		use crate::policy::TransitStatus;
		use crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};

		// Wrap and encrypt message (returns message on error)
		let wire_envelope = self.wrap_and_encrypt_message(message).await?;
		// Write envelope bytes (uses reference, doesn't consume)
		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope(&wire_bytes).await?;

		// Read response bytes
		let response_bytes = self.read_envelope().await?;
		// Decrypt response using trait method
		let response_envelope = <Self as EncryptedMessageIO>::decrypt_response(self, response_bytes).await?;

		// Parse response
		let (status, response) = match response_envelope {
			TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
			TransportEnvelope::Request(_) => return Err(TransportError::InvalidMessage),
			TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
				return Err(TransportError::InvalidMessage)
			}
		};

		// Return original message when status != Accepted (for retry evaluation)
		// For cleartext, we can extract it from the WireEnvelope
		// For encrypted, message is consumed during encryption, so we can't return it
		let returned_message = if status != TransitStatus::Accepted {
			// Extract Arc<Frame> from cleartext WireEnvelope
			match wire_envelope {
				WireEnvelope::Cleartext(TransportEnvelope::Request(pkg)) => Some(pkg.message),
				_ => None, // Encrypted - can't extract original message
			}
		} else {
			None
		};

		// Convert Arc<Frame> to Frame for return
		let response_frame = response.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));
		let returned_frame = returned_message.map(|arc| Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone()));

		Ok((status, response_frame, returned_frame))
	}
}

#[cfg(feature = "transport-policy")]
impl<S: ProtocolStream> crate::transport::MessageEmitter for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type EmitterGate = dyn crate::policy::GatePolicy;
	type RestartPolicy = dyn crate::transport::policy::RestartPolicy;

	fn as_restart_policy(&self) -> &Self::RestartPolicy {
		self.restart_policy.as_ref()
	}

	fn as_emitter_gate_policy(&self) -> &Self::EmitterGate {
		self.emitter_gate.as_ref()
	}

	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		use crate::policy::TransitStatus;
		use crate::transport::policy::RetryAction;
		use crate::transport::Letter;

		let mut letter = Letter::from(message);
		let mut current_attempt = attempt.unwrap_or(0);

		loop {
			// Check handshake FIRST - if fails, message stays in current_message, return HandshakeError
			self.ensure_handshake_complete().await?;

			// Evaluate gate policy before moving message
			let gate_status = self.as_emitter_gate_policy().evaluate(letter.try_peek()?);
			if gate_status != TransitStatus::Accepted {
				return Err(TransportError::Unauthorized);
			}

			let message_to_send = letter.try_take()?;

			#[cfg(feature = "std")]
			let operation_result = {
				// Set socket timeout before operation (if configured)
				let timeout_duration = self.operation_timeout;
				if let Some(duration) = timeout_duration {
					// Set timeout on socket - this applies to all blocking I/O operations
					// Timeout will cause I/O operations to return WouldBlock or TimedOut errors
					self.stream.set_timeout(Some(duration))?;
				}

				let result = self.perform_emit_cycle(message_to_send).await;

				// Restore/clear timeout after operation
				// Note: We could save/restore original timeout, but clearing is simpler
				if timeout_duration.is_some() {
					let _ = self.stream.set_timeout(None);
				}

				// Convert I/O timeout errors to TransportError::Timeout
				result.map_err(|e| {
					if let TransportError::IoError(io_err) = &e {
						if io_err.kind() == std::io::ErrorKind::TimedOut {
							return TransportError::Timeout;
						}
					}
					e
				})
			};

			#[cfg(not(feature = "std"))]
			let operation_result = self.perform_emit_cycle(message_to_send).await;

			let (status, response, original_message) = match operation_result {
				Ok((stat, resp, orig_msg)) => (stat, resp, orig_msg),
				Err(e) => {
					// Extract Frame from error variant if present (for retry evaluation)
					// Use take_frame() which consumes the error but gives us the frame
					let returned_frame = e.take_frame();
					if let Some(frame) = returned_frame {
						// Error carries Frame - restore it for retry evaluation
						letter.try_return_to_sender(frame)?;

						// Create error result for retry policy evaluation (without frame since we took it)
						// Policy evaluation doesn't need the frame, just the error type
						let result: TransportResult<&Frame> = Err(TransportError::SendFailed);
						let action = self.as_restart_policy().evaluate(letter.try_peek()?, &result, current_attempt);
						match action {
							RetryAction::RetryWithSame => {
								if current_attempt == usize::MAX {
									return Err(TransportError::MaxRetriesExceeded);
								} else {
									current_attempt += 1;
									continue;
								}
							}
							RetryAction::RetryWithModified(retry_message) => {
								if current_attempt == usize::MAX {
									return Err(TransportError::MaxRetriesExceeded);
								} else {
									letter.overwrite(*retry_message);
									current_attempt += 1;
									continue;
								}
							}
							RetryAction::NoRetry => {
								return result.map(|_| None);
							}
						}
					} else {
						// Error doesn't carry Frame - message was already sent or consumed
						// Can't retry in this case - return original error
						return Err(TransportError::SendFailed);
					}
				}
			};

			// Check transport status and handle response
			// If status is not Accepted, use original message from
			// perform_emit_cycle for retry evaluation
			let result: TransportResult<&Frame> = if status != TransitStatus::Accepted {
				// Use original message returned from perform_emit_cycle
				if let Some(msg) = original_message {
					letter.try_return_to_sender(msg)?;
				} else {
					return Err(<TransportError as From<TransitStatus>>::from(status));
				}

				Err(<TransportError as From<TransitStatus>>::from(status))
			} else {
				match &response {
					Some(msg) => Ok(msg),
					None => return Ok(None),
				}
			};

			if result.is_err() {
				let action = self.as_restart_policy().evaluate(letter.try_peek()?, &result, current_attempt);
				match action {
					RetryAction::RetryWithSame => {
						if current_attempt == usize::MAX {
							return Err(TransportError::MaxRetriesExceeded);
						} else {
							current_attempt += 1;
							continue;
						}
					}
					RetryAction::RetryWithModified(retry_message) => {
						if current_attempt == usize::MAX {
							return Err(TransportError::MaxRetriesExceeded);
						} else {
							letter.overwrite(*retry_message);
							current_attempt += 1;
							continue;
						}
					}
					RetryAction::NoRetry => {
						result?;
					}
				}
			} else {
				return Ok(response);
			}
		}
	}
}

impl<S: ProtocolStream> EncryptedMessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	fn encryptor(&self) -> TransportResult<&RuntimeAead> {
		self.symmetric_key.as_ref().ok_or(TransportError::Forbidden)
	}

	fn decryptor(&self) -> TransportResult<&RuntimeAead> {
		self.symmetric_key.as_ref().ok_or(TransportError::Forbidden)
	}

	fn handshake_state(&self) -> TcpHandshakeState {
		self.handshake_state
	}

	fn set_handshake_state(&mut self, state: TcpHandshakeState) {
		self.handshake_state = state;
	}

	fn server_certificate(&self) -> Option<&Certificate> {
		self.server_certificates.first().map(|arc| arc.as_ref())
	}

	fn set_symmetric_key(&mut self, key: RuntimeAead) {
		// Replace existing key, ensuring the old key material is dropped immediately
		let _ = self.symmetric_key.take();
		self.symmetric_key = Some(key);
	}

	fn max_cleartext_envelope(&self) -> Option<usize> {
		self.max_cleartext_envelope
	}

	fn max_encrypted_envelope(&self) -> Option<usize> {
		self.max_encrypted_envelope
	}
}

/// TCP server using abstract listener trait
pub struct TcpListener<L: TcpListenerTrait> {
	listener: L,
	certificate: Option<Arc<crate::x509::Certificate>>,
	#[cfg(feature = "x509")]
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	aad_domain_tag: Option<&'static [u8]>,
	max_cleartext_envelope: Option<usize>,
	max_encrypted_envelope: Option<usize>,
	key_manager: Option<Arc<HandshakeKeyManager>>,
	handshake_timeout: Option<Duration>,
}

#[cfg(feature = "std")]
impl crate::transport::Protocol for TcpListener<std::net::TcpListener> {
	type Listener = TcpListener<std::net::TcpListener>;
	type Stream = std::net::TcpStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<std::net::TcpStream>;
	type Address = crate::transport::tcp::TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		std::net::SocketAddr::from_str("127.0.0.1:0")
			.map(crate::transport::tcp::TightBeamSocketAddr)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = std::net::TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((
			TcpListener {
				listener,
				certificate: None,
				#[cfg(feature = "x509")]
				client_validators: None,
				aad_domain_tag: None,
				max_cleartext_envelope: None,
				max_encrypted_envelope: None,
				key_manager: None,
				handshake_timeout: None,
			},
			crate::transport::tcp::TightBeamSocketAddr(bound_addr),
		))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		std::net::TcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(crate::transport::tcp::TightBeamSocketAddr(self.listener.local_addr()?))
	}
}

impl<L: TcpListenerTrait> TcpListener<L>
where
	TransportError: From<L::Error>,
	TransportError: From<<L::Stream as ProtocolStream>::Error>,
	L::Stream: ProtocolStream,
{
	pub fn from_listener(listener: L) -> Self {
		Self {
			listener,
			certificate: None,
			#[cfg(feature = "x509")]
			client_validators: None,
			aad_domain_tag: None,
			max_cleartext_envelope: None,
			max_encrypted_envelope: None,
			key_manager: None,
			handshake_timeout: None,
		}
	}

	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream>> {
		let (stream, _) = self.listener.accept()?;
		let mut transport = TcpTransport::from(stream);

		{
			if let Some(ref cert) = self.certificate {
				transport.server_certificates.push(Arc::clone(cert));
			}
			if let Some(ref validators) = self.client_validators {
				transport.client_validators = Some(Arc::clone(validators));
			}
			if let Some(aad) = self.aad_domain_tag {
				transport.aad_domain_tag = Some(aad);
			}
			if let Some(max) = self.max_cleartext_envelope {
				transport.max_cleartext_envelope = Some(max);
			}
			if let Some(max) = self.max_encrypted_envelope {
				transport.max_encrypted_envelope = Some(max);
			}
			if let Some(timeout) = self.handshake_timeout {
				transport.handshake_timeout = timeout;
			}
		}

		if let Some(ref signatory) = self.key_manager {
			transport.key_manager = Some(Arc::clone(signatory));
		}
		Ok(transport)
	}
}

impl EncryptedProtocol for TcpListener<std::net::TcpListener> {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;

	async fn bind_with(
		addr: <Self as Protocol>::Address,
		config: TransportEncryptionConfig,
	) -> Result<(Self::Listener, <Self as Protocol>::Address), <Self as Protocol>::Error> {
		let listener = std::net::TcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		Ok((
			TcpListener {
				listener,
				certificate: Some(Arc::new(config.certificate)),
				#[cfg(feature = "x509")]
				client_validators: config.client_validators.as_ref().map(Arc::clone),
				aad_domain_tag: Some(config.aad_domain_tag),
				max_cleartext_envelope: Some(config.max_cleartext_envelope),
				max_encrypted_envelope: Some(config.max_encrypted_envelope),

				key_manager: Some(Arc::clone(&config.key_manager)),
				handshake_timeout: Some(config.handshake_timeout),
			},
			TightBeamSocketAddr(bound_addr),
		))
	}
}

#[cfg(test)]
mod tests {
	#![allow(unused_imports)]
	use std::net::TcpStream;
	use std::sync::mpsc;

	use super::*;
	use crate::testing::*;
	use crate::transport::{MessageCollector, MessageEmitter};

	#[cfg(not(feature = "x509"))]
	#[tokio::test]
	async fn test_tcp_transport_emit_collect() -> TransportResult<()> {
		let message = create_v0_tightbeam(None, None);
		let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = std::thread::spawn(move || {
			let server = TcpListener::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept().unwrap();

			let rt = tokio::runtime::Runtime::new().unwrap();
			rt.block_on(transport.handle_request()).unwrap();
		});

		// Await server ready signal
		let _ = ready_rx.recv();

		let stream = TcpStream::connect(addr)?;
		let mut client_transport = TcpTransport::from(stream);
		let response = client_transport.emit(message, None).await?;

		server_handle.join().unwrap();

		// Response should be None since no handler is set
		assert_eq!(response, None);
		Ok(())
	}

	#[cfg(all(feature = "transport-policy", not(feature = "x509")))]
	#[tokio::test]
	async fn test_tcp_transport_with_gate_policy() -> TransportResult<()> {
		use std::sync::atomic::{AtomicBool, Ordering};

		use crate::transport::policy::PolicyConf;

		/// Policy: first Busy, then Accepted
		struct BusyFirstGate {
			first: AtomicBool,
		}

		impl BusyFirstGate {
			fn new() -> Self {
				Self { first: AtomicBool::new(true) }
			}
		}

		impl GatePolicy for BusyFirstGate {
			fn evaluate(&self, _msg: &crate::asn1::Frame) -> crate::transport::TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					crate::transport::TransitStatus::Busy
				} else {
					crate::transport::TransitStatus::Accepted
				}
			}
		}

		let message = create_v0_tightbeam(None, None);
		let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = std::thread::spawn(move || {
			let server = TcpListener::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept().unwrap().with_collector_gate(BusyFirstGate::new());

			let rt = tokio::runtime::Runtime::new().unwrap();

			// First handle_request - gate policy returns Busy
			rt.block_on(transport.handle_request()).ok();

			// Second handle_request - gate policy returns Accepted
			rt.block_on(transport.handle_request()).unwrap();
		});

		let _ = ready_rx.recv();

		let stream = TcpStream::connect(addr)?;
		let mut transport = TcpTransport::from(stream);

		// First attempt - server responds with Busy
		let result = transport.emit(message.clone(), None).await;
		assert!(matches!(result, Err(TransportError::Busy)));

		// Second attempt - server responds with Accepted
		transport.emit(message.clone(), None).await?;

		server_handle.join().unwrap();
		Ok(())
	}
}
