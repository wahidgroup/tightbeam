#![cfg(feature = "x509")]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::str::FromStr;
use core::time::Duration;

use crate::crypto::aead::RuntimeAead;
use crate::crypto::x509::policy::CertificateValidation;
use crate::der::{Decode, Encode};
use crate::prelude::TightBeamSocketAddr;
use crate::transport::handshake::{
	HandshakeError, HandshakeProtocolKind, ServerHandshakeProtocol, ServerKeyManager, TcpHandshakeState,
};
use crate::transport::policy::RetryAction;
use crate::transport::tcp::TcpListenerTrait;
use crate::transport::{EncryptedMessageIO, EncryptedProtocol, Protocol, TransportEncryptionConfig};
use crate::transport::{MessageIO, Pingable, TransportResult};
use crate::transport::{TransitStatus, TransportEnvelope, WireEnvelope};
use crate::x509::Certificate;
use crate::Frame;

#[cfg(feature = "transport-policy")]
use crate::{
	policy::GatePolicy,
	transport::{error::TransportError, policy::RestartPolicy, tcp::ProtocolStream},
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

	server_certificate: Option<Arc<Certificate>>,

	client_certificate: Option<Arc<Certificate>>,

	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,

	peer_certificate: Option<Certificate>,

	aad_domain_tag: Option<&'static [u8]>,

	max_cleartext_envelope: Option<usize>,

	max_encrypted_envelope: Option<usize>,

	signatory: Option<ServerKeyManager>,

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

		// Enforce size ceilings if configured (pick larger bound conservatively)

		{
			let max_allowed = self
				.max_encrypted_envelope
				.or(self.max_cleartext_envelope)
				.unwrap_or(512 * 1024);
			if content_length > max_allowed {
				return Err(TransportError::InvalidMessage);
			}
		}

		// If in handshake waiting state, optionally enforce timeout by short read deadline using std only

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
	}

	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()> {
		self.stream.write_all(buffer)?;
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

	async fn collect_message(&mut self) -> TransportResult<(crate::Frame, crate::policy::TransitStatus)> {
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
		// Removed unused imports
		use crate::der::Encode;
		use crate::transport::{ResponsePackage, TransportEnvelope, WireEnvelope};

		let response_pkg = ResponsePackage { status, message };
		let response_envelope = TransportEnvelope::from(response_pkg);

		let wire_envelope = if self.handshake_state() == TcpHandshakeState::Complete {
			let envelope_bytes = response_envelope.to_der()?;
			if let Some(max) = self.max_encrypted_envelope {
				if envelope_bytes.len() > max {
					return Err(TransportError::InvalidMessage);
				}
			}
			let nonce = crate::random::generate_nonce::<12>(None)?;
			let encrypted = self.encryptor()?.encrypt_content(&envelope_bytes, nonce, None)?;
			WireEnvelope::Encrypted(encrypted)
		} else {
			let bytes = response_envelope.to_der()?;
			if let Some(max) = self.max_cleartext_envelope {
				if bytes.len() > max {
					return Err(TransportError::InvalidMessage);
				}
			}
			WireEnvelope::Cleartext(response_envelope)
		};

		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope(&wire_bytes).await
	}
}

#[cfg(feature = "transport-policy")]
impl<S: ProtocolStream> crate::transport::MessageEmitter for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type EmitterGate = dyn crate::policy::GatePolicy;
	type RestartPolicy = dyn crate::transport::policy::RestartPolicy;

	fn get_restart_policy(&self) -> &Self::RestartPolicy {
		self.restart_policy.as_ref()
	}

	fn get_emitter_gate_policy(&self) -> &Self::EmitterGate {
		self.emitter_gate.as_ref()
	}

	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		let mut current_message = message;
		let mut current_attempt = attempt.unwrap_or(0);

		loop {
			let status: TransitStatus = self.get_emitter_gate_policy().evaluate(&current_message);
			if status != TransitStatus::Accepted {
				return Err(TransportError::Unauthorized);
			}

			// Initiate handshake when:
			// - State is None (no handshake attempted yet) AND
			// - We have server_certificate (expecting encrypted connection) OR
			// - We have x509_gate validators (expecting to validate server cert)
			#[cfg(feature = "x509")]
			let should_handshake = (self.server_certificate().is_some() || self.client_validators.is_some())
				&& self.handshake_state() == TcpHandshakeState::None;
			#[cfg(not(feature = "x509"))]
			let should_handshake = false;

			if should_handshake {
				self.perform_client_handshake().await?;
			}

			let envelope = TransportEnvelope::new_request(current_message.clone());
			let wire_envelope = if self.handshake_state() == TcpHandshakeState::Complete {
				// Removed unused imports
				let envelope_bytes = envelope.to_der()?;
				if let Some(max) = self.max_encrypted_envelope {
					if envelope_bytes.len() > max {
						return Err(TransportError::InvalidMessage);
					}
				}
				let nonce = crate::random::generate_nonce::<12>(None)?;
				let encrypted = self.encryptor()?.encrypt_content(&envelope_bytes, nonce, None)?;
				WireEnvelope::Encrypted(encrypted)
			} else {
				let bytes = envelope.to_der()?;
				if let Some(max) = self.max_cleartext_envelope {
					if bytes.len() > max {
						return Err(TransportError::InvalidMessage);
					}
				}
				WireEnvelope::Cleartext(envelope)
			};

			self.write_envelope(&wire_envelope.to_der()?).await?;

			let response_bytes = self.read_envelope().await?;
			let response_envelope = {
				let wire_envelope = WireEnvelope::from_der(&response_bytes)?;
				match wire_envelope {
					WireEnvelope::Cleartext(env) => env,
					WireEnvelope::Encrypted(encrypted_info) => {
						use crate::crypto::aead::Decryptor;
						let decrypted_bytes = self.decryptor()?.decrypt_content(&encrypted_info)?;
						<Self as MessageIO>::decode_envelope(&decrypted_bytes)?
					}
				}
			};

			let (status, response) = match response_envelope {
				TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
				TransportEnvelope::Request(_) => return Err(TransportError::InvalidMessage),
				TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
					return Err(TransportError::InvalidMessage)
				}
			};

			let result: TransportResult<&Frame> = if status != TransitStatus::Accepted {
				Err(<TransportError as From<TransitStatus>>::from(status))
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
							current_message = *retry_message;
							current_attempt += 1;
							continue;
						}
					}
					RetryAction::NoRetry => {
						// Return the error
						return Err(result.unwrap_err());
					}
				}
			} else {
				// Success case - return response
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
		self.server_certificate.as_ref().map(|arc| arc.as_ref())
	}

	fn set_symmetric_key(&mut self, key: RuntimeAead) {
		// Replace existing key, ensuring the old key material is dropped immediately
		let _ = self.symmetric_key.take();
		self.symmetric_key = Some(key);
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
	signatory: Option<ServerKeyManager>,
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
				signatory: None,
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

	fn get_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
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
			signatory: None,
			handshake_timeout: None,
		}
	}

	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream>> {
		let (stream, _) = self.listener.accept()?;
		let mut transport = TcpTransport::from(stream);

		{
			if let Some(ref cert) = self.certificate {
				transport.server_certificate = Some(Arc::clone(cert));
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

		if let Some(ref signatory) = self.signatory {
			transport.signatory = Some(signatory.clone());
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

				signatory: Some(config.signatory.clone()),
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
		let response = client_transport.emit(message.clone(), None).await?;

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
