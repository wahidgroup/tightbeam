use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::builder::TypeBuilder;
use crate::transport::{
	AsyncListenerTrait, EnvelopeBuilder, EnvelopeLimits, MessageIO, Pingable, Protocol, TransportError,
	TransportResult, WireMode,
};
use crate::Frame;

#[cfg(feature = "x509")]
use crate::crypto::aead::RuntimeAead;
#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::transport::handshake::{
	HandshakeError, HandshakeProtocolKind, ServerHandshakeProtocol, ServerKeyManager, TcpHandshakeState,
};
#[cfg(feature = "x509")]
use crate::transport::{EncryptedMessageIO, EncryptedProtocol};
#[cfg(feature = "x509")]
use crate::x509::Certificate;
#[cfg(feature = "x509")]
use std::time::Duration;

#[cfg(feature = "transport-policy")]
use crate::policy::GatePolicy;
#[cfg(feature = "transport-policy")]
use crate::transport::policy::RestartPolicy;

pub trait AsyncProtocolStream: Send + Unpin {
	type Error: Into<TransportError>;
	fn inner_mut(&mut self) -> &mut TcpStream;
}

pub struct TokioStream {
	stream: TcpStream,
}

impl AsyncProtocolStream for TokioStream {
	type Error = std::io::Error;

	fn inner_mut(&mut self) -> &mut TcpStream {
		&mut self.stream
	}
}

impl From<TcpStream> for TokioStream {
	fn from(stream: TcpStream) -> Self {
		Self { stream }
	}
}

pub struct TokioListener {
	listener: TcpListener,
	#[cfg(feature = "x509")]
	certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	#[cfg(feature = "x509")]
	aad_domain_tag: Option<&'static [u8]>,
	#[cfg(feature = "x509")]
	max_cleartext_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	max_encrypted_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	handshake_timeout: Option<Duration>,
	#[cfg(feature = "x509")]
	signatory: Option<ServerKeyManager>,
}

impl TokioListener {
	pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
		self.listener.local_addr()
	}

	pub async fn bind(addr: &str) -> std::io::Result<Self> {
		let listener = TcpListener::bind(addr).await?;
		Ok(Self {
			listener,
			#[cfg(feature = "x509")]
			certificate: None,
			#[cfg(feature = "x509")]
			client_validators: None,
			#[cfg(feature = "x509")]
			aad_domain_tag: None,
			#[cfg(feature = "x509")]
			max_cleartext_envelope: None,
			#[cfg(feature = "x509")]
			max_encrypted_envelope: None,
			#[cfg(feature = "x509")]
			handshake_timeout: None,
			#[cfg(feature = "x509")]
			signatory: None,
		})
	}

	#[cfg(not(feature = "x509"))]
	pub async fn accept(&self) -> std::io::Result<(TokioStream, std::net::SocketAddr)> {
		let (stream, addr) = self.listener.accept().await?;
		Ok((TokioStream::from(stream), addr))
	}

	#[cfg(feature = "x509")]
	pub async fn accept(&self) -> std::io::Result<(TcpTransport<TokioStream>, std::net::SocketAddr)> {
		let (stream, addr) = self.listener.accept().await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream));

		if let Some(cert) = &self.certificate {
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

		#[cfg(feature = "x509")]
		if let Some(timeout) = self.handshake_timeout {
			transport.handshake_timeout = timeout;
		}

		#[cfg(feature = "x509")]
		if let Some(signatory) = &self.signatory {
			transport.signatory = Some(signatory.clone());
		}

		Ok((transport, addr))
	}
}

impl Protocol for TokioListener {
	type Listener = TokioListener;
	type Stream = TokioStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<TokioStream>;
	type Address = crate::transport::tcp::TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		"127.0.0.1:0"
			.parse()
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		Ok((
			Self {
				listener,
				#[cfg(feature = "x509")]
				certificate: None,
				#[cfg(feature = "x509")]
				client_validators: None,
				#[cfg(feature = "x509")]
				aad_domain_tag: None,
				#[cfg(feature = "x509")]
				max_cleartext_envelope: None,
				#[cfg(feature = "x509")]
				max_encrypted_envelope: None,
				#[cfg(feature = "x509")]
				handshake_timeout: None,
				#[cfg(feature = "x509")]
				signatory: None,
			},
			crate::transport::tcp::TightBeamSocketAddr(bound_addr),
		))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let stream = TcpStream::connect(addr.0).await?;
		Ok(TokioStream::from(stream))
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(crate::transport::tcp::TightBeamSocketAddr(self.local_addr()?))
	}
}

#[cfg(feature = "x509")]
impl EncryptedProtocol for TokioListener {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;

	async fn bind_with(
		addr: Self::Address,
		config: crate::transport::TransportEncryptionConfig,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		Ok((
			Self {
				listener,
				certificate: Some(Arc::new(config.certificate)),
				client_validators: config.client_validators.as_ref().map(Arc::clone),
				aad_domain_tag: Some(config.aad_domain_tag),
				max_cleartext_envelope: Some(config.max_cleartext_envelope),
				max_encrypted_envelope: Some(config.max_encrypted_envelope),
				handshake_timeout: Some(config.handshake_timeout),
				signatory: Some(config.signatory),
			},
			crate::transport::tcp::TightBeamSocketAddr(bound_addr),
		))
	}
}

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream> EncryptedMessageIO for TcpTransport<S>
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

	fn max_cleartext_envelope(&self) -> Option<usize> {
		self.max_cleartext_envelope
	}

	fn max_encrypted_envelope(&self) -> Option<usize> {
		self.max_encrypted_envelope
	}
}

// Ensure symmetric key material is dropped when the transport is dropped
impl<S: AsyncProtocolStream> Drop for TcpTransport<S> {
	fn drop(&mut self) {
		let _ = self.symmetric_key.take();
	}
}

impl AsyncListenerTrait for TokioListener {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		let (stream, addr) = self.listener.accept().await?;
		let mut transport = Self::create_transport(TokioStream::from(stream));

		#[cfg(feature = "x509")]
		if let Some(ref cert) = self.certificate {
			transport.server_certificate = Some(Arc::clone(cert));
		}

		#[cfg(feature = "x509")]
		if let Some(ref signatory) = self.signatory {
			transport.signatory = Some(signatory.clone());
		}

		#[cfg(feature = "x509")]
		if let Some(timeout) = self.handshake_timeout {
			transport.handshake_timeout = timeout;
		}

		Ok((transport, crate::transport::tcp::TightBeamSocketAddr(addr)))
	}
}

impl crate::transport::Mycelial for TokioListener {
	async fn try_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
		// Bind to an available port (0.0.0.0:0 lets the OS choose)
		let addr = "0.0.0.0:0"
			.parse::<crate::transport::tcp::TightBeamSocketAddr>()
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
		<TokioListener as Protocol>::bind(addr).await
	}
}

#[cfg(not(feature = "transport-policy"))]
pub struct TcpTransport<S: AsyncProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<Frame> + Send>>,
	#[cfg(feature = "x509")]
	server_certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	#[cfg(feature = "x509")]
	peer_certificate: Option<Certificate>,
	#[cfg(feature = "x509")]
	aad_domain_tag: Option<&'static [u8]>,
	#[cfg(feature = "x509")]
	max_cleartext_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	max_encrypted_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	signatory: Option<ServerKeyManager>,
	#[cfg(feature = "x509")]
	handshake_state: TcpHandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<RuntimeAead>,
}

// (single Drop impl above covers both feature variants)
#[cfg(feature = "transport-policy")]
pub struct TcpTransport<S: AsyncProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<Frame> + Send>>,
	restart_policy: Box<dyn RestartPolicy>,
	emitter_gate: Box<dyn GatePolicy>,
	collector_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "std")]
	operation_timeout: Option<std::time::Duration>,
	#[cfg(feature = "x509")]
	server_certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	#[cfg(feature = "x509")]
	peer_certificate: Option<Certificate>,
	#[cfg(feature = "x509")]
	aad_domain_tag: Option<&'static [u8]>,
	#[cfg(feature = "x509")]
	max_cleartext_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	max_encrypted_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	signatory: Option<ServerKeyManager>,
	#[cfg(feature = "x509")]
	handshake_state: TcpHandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<RuntimeAead>,
	#[cfg(feature = "x509")]
	server_handshake: Option<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send>>,
	#[cfg(feature = "x509")]
	handshake_protocol_kind: HandshakeProtocolKind,
}

impl<S: AsyncProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
	TransportError: From<std::io::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		self.stream.inner_mut().peer_addr().map(|_| ()).map_err(TransportError::from)
	}
}

crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		use tokio::time::timeout;
		// Compute handshake deadline before mutably borrowing the stream
		#[cfg(feature = "x509")]
		let handshake_deadline: Option<std::time::Instant> = {
			use crate::transport::handshake::TcpHandshakeState;
			match self.handshake_state() {
				TcpHandshakeState::AwaitingServerResponse { initiated_at }
				| TcpHandshakeState::AwaitingClientFinish { initiated_at } => Some(initiated_at + self.handshake_timeout),
				_ => None,
			}
		};

		let stream = self.stream.inner_mut();

		let mut tag = [0u8; 1];
		#[cfg(feature = "x509")]
		{
			if let Some(deadline) = handshake_deadline {
				let now = std::time::Instant::now();
				if now >= deadline {
					return Err(TransportError::Timeout);
				}
				let dur = deadline.saturating_duration_since(now);
				timeout(dur, stream.read_exact(&mut tag))
					.await
					.map_err(|_| TransportError::Timeout)??;
			} else {
				stream.read_exact(&mut tag).await?;
			}
		}
		#[cfg(not(feature = "x509"))]
		{
			stream.read_exact(&mut tag).await?;
		}

		let mut length_first = [0u8; 1];
		#[cfg(feature = "x509")]
		{
			if let Some(deadline) = handshake_deadline {
				let now = std::time::Instant::now();
				if now >= deadline {
					return Err(TransportError::Timeout);
				}
				let dur = deadline.saturating_duration_since(now);
				timeout(dur, stream.read_exact(&mut length_first))
					.await
					.map_err(|_| TransportError::Timeout)??;
			} else {
				stream.read_exact(&mut length_first).await?;
			}
		}
		#[cfg(not(feature = "x509"))]
		{
			stream.read_exact(&mut length_first).await?;
		}

		let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
			(vec![], length_first[0] as usize)
		} else {
			let octet_count = (length_first[0] & 0x7F) as usize;
			let mut length_octets = vec![0u8; octet_count];
			#[cfg(feature = "x509")]
			{
				if let Some(deadline) = handshake_deadline {
					let now = std::time::Instant::now();
					if now >= deadline {
						return Err(TransportError::Timeout);
					}
					let dur = deadline.saturating_duration_since(now);
					timeout(dur, stream.read_exact(&mut length_octets))
						.await
						.map_err(|_| TransportError::Timeout)??;
				} else {
					stream.read_exact(&mut length_octets).await?;
				}
			}
			#[cfg(not(feature = "x509"))]
			{
				stream.read_exact(&mut length_octets).await?;
			}
			let length = Self::parse_der_length(length_first[0], &length_octets);
			(length_octets, length)
		};

		// Enforce size ceilings if configured
		#[cfg(feature = "x509")]
		{
			// We can’t tell encrypted vs cleartext at this point,
			// so choose the larger cap conservatively
			let max_allowed = self
				.max_encrypted_envelope
				.or(self.max_cleartext_envelope)
				.unwrap_or(512 * 1024);
			if content_length > max_allowed {
				return Err(TransportError::InvalidMessage);
			}
		}

		let mut content = vec![0u8; content_length];
		#[cfg(feature = "x509")]
		{
			if let Some(deadline) = handshake_deadline {
				let now = std::time::Instant::now();
				if now >= deadline {
					return Err(TransportError::Timeout);
				}
				let dur = deadline.saturating_duration_since(now);
				timeout(dur, stream.read_exact(&mut content))
					.await
					.map_err(|_| TransportError::Timeout)??;
			} else {
				stream.read_exact(&mut content).await?;
			}
		}
		#[cfg(not(feature = "x509"))]
		{
			stream.read_exact(&mut content).await?;
		}

		let buffer = Self::reconstruct_der_encoding(tag[0], length_first[0], &length_octets, &content);
		Ok(buffer)
	}

	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()> {
		let stream = self.stream.inner_mut();
		stream.write_all(buffer).await?;
		Ok(())
	}
}

#[cfg(all(feature = "x509", feature = "transport-policy"))]
impl<S: AsyncProtocolStream> crate::transport::MessageCollector for TcpTransport<S>
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

		// Loop until we get an actual message (may need to perform handshake first)
		loop {
			// Read and parse as WireEnvelope (always - this is the wire protocol)
			let wire_bytes = self.read_envelope().await?;
			let wire_envelope = match WireEnvelope::from_der(&wire_bytes) {
				Ok(env) => env,
				Err(e) => return Err(TransportError::DerError(e)),
			};

			// Enforce per-envelope size ceilings: cleartext vs encrypted
			#[cfg(feature = "x509")]
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

			// Only enable handshake/encryption logic if server has a certificate configured
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
								// After processing, loop back to read next message
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
						// No certificate - allow all cleartext
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

			// Extract the request message
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
			let status: TransitStatus = self.collector_gate().evaluate(&request);
			if status == TransitStatus::Request {
				// Invalid status from gate
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
		use crate::der::Encode;
		use crate::transport::ResponsePackage;

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
		self.write_envelope(&wire_bytes).await?;
		Ok(())
	}
}

#[cfg(all(feature = "x509", feature = "transport-policy"))]
impl<S: AsyncProtocolStream> TcpTransport<S>
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
			TransportEnvelope::Request(_) => {
				// Only responses are valid here
				return Err(TransportError::InvalidMessage);
			}
			TransportEnvelope::EnvelopedData(_) | TransportEnvelope::SignedData(_) => {
				// Handshake messages not expected here
				return Err(TransportError::InvalidMessage);
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

#[cfg(all(feature = "x509", feature = "transport-policy"))]
impl<S: AsyncProtocolStream> crate::transport::MessageEmitter for TcpTransport<S>
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

	/// Send a TightBeam message with automatic handshake
	///
	/// # Handshake Flow (when x509 enabled)
	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		use crate::policy::TransitStatus;
		use crate::transport::policy::RetryAction;
		use crate::transport::Letter;

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

		let mut letter = Letter::from(message);
		let mut current_attempt = attempt.unwrap_or(0);

		loop {
			self.ensure_handshake_complete().await?;

			let status: TransitStatus = self.as_emitter_gate_policy().evaluate(letter.try_peek()?);
			if status != TransitStatus::Accepted {
				return Err(TransportError::Unauthorized);
			}

			let message_to_send = letter.try_take()?;
			let operation_result = {
				#[cfg(feature = "std")]
				{
					let timeout_duration = self.operation_timeout;
					if let Some(duration) = timeout_duration {
						use tokio::time::timeout;
						match timeout(duration, async { self.perform_emit_cycle(message_to_send).await }).await {
							Ok(result) => result,
							Err(_) => Err(TransportError::Timeout),
						}
					} else {
						self.perform_emit_cycle(message_to_send).await
					}
				}

				#[cfg(not(feature = "std"))]
				{
					self.perform_emit_cycle(message_to_send).await
				}
			};

			let (status, response, original_message) = match operation_result {
				Ok((stat, resp, orig_msg)) => (stat, resp, orig_msg),
				Err(e) => {
					if let Some(frame) = e.take_frame() {
						letter.try_return_to_sender(frame)?;

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
						return Err(TransportError::SendFailed);
					}
				}
			};

			let result: TransportResult<&Frame> = if status != TransitStatus::Accepted {
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
						return result.map(|_| None);
					}
				}
			} else {
				return Ok(response);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
	use crate::crypto::sign::Sha3Signer;
	use crate::testing::*;
	use crate::transport::policy::PolicyConf;
	use crate::transport::{MessageCollector, MessageEmitter, ResponseHandler, TransitStatus};
	use crate::{assert_channel_empty, assert_channels_quiet, assert_recv, test_container};

	#[tokio::test]
	async fn async_round_trip() -> TransportResult<()> {
		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;

		let test_message = create_v0_tightbeam(None, None);
		let expected_response = create_v0_tightbeam(None, None);

		let (tx, mut rx) = tokio::sync::mpsc::channel(1);
		let response_msg = expected_response.clone();
		let server = listener;
		let server_handle = tokio::spawn(async move {
			let (transport, _) = server.accept().await?;
			let mut transport = transport.with_handler(Box::new(move |msg: Frame| {
				let _ = tx.try_send(msg);
				Some(response_msg.clone())
			}));

			transport.handle_request().await
		});

		let stream = TcpStream::connect(addr).await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream));
		let response = transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert_eq!(response.clone(), Some(expected_response));

		server_handle.await??;
		Ok(())
	}

	#[cfg(feature = "transport-policy")]
	#[tokio::test]
	async fn async_with_encrypted_and_gate_policy() -> TransportResult<()> {
		use std::str::FromStr;
		use std::sync::atomic::{AtomicBool, Ordering};

		use spki::SubjectPublicKeyInfoOwned;

		use crate::{prelude::TightBeamSocketAddr, transport::policy::PolicyConf};

		struct BusyFirstGate {
			first: AtomicBool,
		}

		impl BusyFirstGate {
			fn new() -> Self {
				Self { first: AtomicBool::new(true) }
			}
		}

		impl GatePolicy for BusyFirstGate {
			fn evaluate(&self, _msg: &Frame) -> TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					TransitStatus::Busy
				} else {
					TransitStatus::Accepted
				}
			}
		}

		let signing_key = create_test_signing_key();
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let sha3_signer = Sha3Signer::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

		let not_before = std::time::Instant::now();
		let not_after = not_before + std::time::Duration::from_secs(365 * 24 * 60 * 60);

		// Create a self-signed root certificate
		let cert = crate::cert!(
			profile: Root,
			subject: "CN=Test Root CA,O=Test Org,C=US",
			serial: 1u32,
			validity: (not_before, not_after),
			signer: &sha3_signer,
			subject_public_key: spki
		)?;

		let addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
		let config = crate::transport::TransportEncryptionConfig::new(cert.clone(), signing_key.clone().into());
		let (listener, socket_addr) = TokioListener::bind_with(addr, config).await?;
		let server = listener;

		let test_message = create_v0_tightbeam(None, None);

		let (tx, mut rx) = tokio::sync::mpsc::channel(2);

		let server_handle = tokio::spawn(async move {
			let (transport, _) = server.accept().await?;
			let mut transport =
				transport
					.with_collector_gate(BusyFirstGate::new())
					.with_handler(Box::new(move |msg: Frame| {
						let _ = tx.try_send(msg.clone());
						Some(msg)
					}));

			// First handle_request: processes handshake (ClientHello + ClientKeyExchange)
			// and first application message. Gate returns Busy for first app message.
			let result = transport.handle_request().await;
			result?;

			// Second handle_request: processes second application message
			// Gate returns Accepted this time
			transport.handle_request().await
		});

		let stream = TcpStream::connect(*socket_addr).await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream)).with_server_certificate(cert);

		// First emit triggers handshake, then sends encrypted message
		// Gate policy returns Busy for first application message
		let first = transport.emit(test_message.clone(), None).await;
		assert!(matches!(first, Err(TransportError::Busy)));

		// Second emit sends encrypted message, gate returns Accepted
		transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert!(rx.try_recv().is_err());

		server_handle.await??;
		Ok(())
	}

	#[cfg(all(feature = "transport-policy", feature = "x509"))]
	crate::test_container! {
		name: test_ecies_end_to_end_encryption,
		worker_threads: 2,
		protocol: TokioListener,
		service_policies: {
			with_collector_gate: [crate::policy::AcceptAllGate],
			with_x509: []
		},
		client_policies: {
			with_emitter_gate: [crate::policy::AcceptAllGate],
			with_restart: [crate::transport::policy::RestartLinearBackoff::new(3, 1, 1, None)],
			with_x509: []
		},
		service: |message, tx| async move {
			// Echo the message back as response
			let _ = tx.send(message.clone());
			Ok(Some(message))
		},
		container: |client, channels| async move {
			use crate::transport::MessageEmitter;
			use crate::transport::handshake::TcpHandshakeState;
			use crate::transport::EncryptedMessageIO;

			let (rx, ok_rx, reject_rx) = channels;

			// Create test message
			let test_message = create_v0_tightbeam(Some("Hello ECIES!"), Some("test-ecies-1"));

			// Verify client starts without encryption
			assert_eq!(client.handshake_state(), TcpHandshakeState::None);
			assert!(client.encryptor().is_err());

			// First emit triggers ECIES handshake and sends encrypted message
			let response = client.emit(test_message.clone(), None).await?;

			// Verify encryption is now active
			assert_eq!(client.handshake_state(), TcpHandshakeState::Complete);
			assert!(client.encryptor().is_ok());

			// Verify response matches
			assert_eq!(response, Some(test_message.clone()));

			// Verify server received the message
			assert_recv!(rx, test_message.clone(), 1);
			assert_recv!(ok_rx, test_message.clone(), 1);
			assert_channels_quiet!(reject_rx);

			// Second message should reuse encrypted channel (no re-handshake)
			let test_message2 = create_v0_tightbeam(Some("Second ECIES"), Some("test-ecies-2"));
			let response2 = client.emit(test_message2.clone(), None).await?;

			// Verify still encrypted
			assert_eq!(client.handshake_state(), TcpHandshakeState::Complete);
			assert_eq!(response2, Some(test_message2.clone()));

			// Verify second message received
			assert_recv!(rx, test_message2, 1);

			Ok(())
		}
	}
}
