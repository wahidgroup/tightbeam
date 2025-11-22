//! Application-facing message transmission (send/receive)

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::der::{Decode, Encode};
use crate::policy::{GatePolicy, TransitStatus};
use crate::transport::envelopes::{ResponsePackage, TransportEnvelope, WireEnvelope};
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::io::MessageIO;
use crate::transport::TransportResult;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::aead::Decryptor;
	pub use crate::transport::handshake::TcpHandshakeState;
	pub use crate::transport::io::EncryptedMessageIO;
	pub use crate::transport::state::EncryptedProtocolState;
}

#[cfg(feature = "x509")]
use x509::*;

#[cfg(feature = "transport-policy")]
use crate::transport::policy::{RestartPolicy, RetryAction};

/// Trait for transports that support custom response handlers
pub trait ResponseHandler {
	/// Set a handler that processes incoming messages and generates responses
	fn with_handler<F>(self, handler: F) -> Self
	where
		F: Fn(Frame) -> Option<Frame> + Send + 'static;

	/// Get the current handler if one is set
	fn handler(&self) -> Option<&(dyn Fn(Frame) -> Option<Frame> + Send)>;
}

#[cfg(feature = "transport-policy")]
#[derive(Debug)]
/// Helper that mirrors a physical letter being routed through retries.
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
	#[allow(async_fn_in_trait)]
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>;

	/// Send a TightBeam message
	#[allow(async_fn_in_trait)]
	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
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
			#[cfg(feature = "x509")]
			_ => {
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
		Self: EncryptedMessageIO + Sized + EncryptedProtocolState,
	{
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
		let request_envelope = self.read_decoded_envelope().await?;
		// Extract message from request
		let request = match request_envelope {
			TransportEnvelope::Request(msg) => msg.message,
			TransportEnvelope::Response(_) => {
				return Err(TransportError::InvalidMessage);
			}
			#[cfg(feature = "x509")]
			_ => {
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
