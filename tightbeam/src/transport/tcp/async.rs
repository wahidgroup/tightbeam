use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::transport::{AsyncListenerTrait, MessageIO, Pingable, Protocol, TransportError, TransportResult};
use crate::Frame;

#[cfg(feature = "x509")]
use crate::transport::{EncryptedMessageIO, EncryptedProtocol};
#[cfg(feature = "transport-policy")]
use crate::{policy::GatePolicy, transport::policy::RestartPolicy};

#[cfg(feature = "x509")]
use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeState;
#[cfg(feature = "x509")]
use crate::x509::Certificate;
#[cfg(feature = "x509")]
use std::time::Duration;

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
	certificate: Option<crate::x509::Certificate>,
	#[cfg(feature = "x509")]
	aad_domain_tag: Option<Vec<u8>>,
	#[cfg(feature = "x509")]
	max_cleartext_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	max_encrypted_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	handshake_timeout: Option<Duration>,
	#[cfg(all(feature = "x509", feature = "secp256k1"))]
	signatory: Option<std::sync::Arc<dyn crate::transport::handshake::ServerHandshakeKey>>,
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
			aad_domain_tag: None,
			#[cfg(feature = "x509")]
			max_cleartext_envelope: None,
			#[cfg(feature = "x509")]
			max_encrypted_envelope: None,
			#[cfg(feature = "x509")]
			handshake_timeout: None,
			#[cfg(all(feature = "x509", feature = "secp256k1"))]
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
			transport.server_certificate = Some(cert.clone());
		}

		if let Some(ref aad) = self.aad_domain_tag {
			transport.aad_domain_tag = Some(aad.clone());
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

		#[cfg(feature = "secp256k1")]
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
		Ok("127.0.0.1:0".parse().expect("Valid default TCP address"))
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
				aad_domain_tag: None,
				#[cfg(feature = "x509")]
				max_cleartext_envelope: None,
				#[cfg(feature = "x509")]
				max_encrypted_envelope: None,
				#[cfg(feature = "x509")]
				handshake_timeout: None,
				#[cfg(all(feature = "x509", feature = "secp256k1"))]
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

	fn get_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(crate::transport::tcp::TightBeamSocketAddr(self.local_addr()?))
	}
}

#[cfg(feature = "x509")]
impl EncryptedProtocol<crate::crypto::ecies::EciesSecp256k1Oid> for TokioListener {
	type Encryptor = crate::crypto::aead::Aes256Gcm;
	type Decryptor = crate::crypto::aead::Aes256Gcm;

	async fn bind_with(
		addr: Self::Address,
		config: crate::transport::TransportEncryptionConfig,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		Ok((
			Self {
				listener,
				certificate: Some(config.certificate.clone()),
				aad_domain_tag: Some(config.aad_domain_tag.clone()),
				max_cleartext_envelope: Some(config.max_cleartext_envelope),
				max_encrypted_envelope: Some(config.max_encrypted_envelope),
				handshake_timeout: Some(config.handshake_timeout),
				signatory: Some(config.signatory.clone()),
			},
			crate::transport::tcp::TightBeamSocketAddr(bound_addr),
		))
	}

	// Non-secp256k1 builds can be extended later if needed
}

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream> EncryptedMessageIO<crate::crypto::ecies::EciesSecp256k1Oid> for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type Encryptor = crate::crypto::aead::Aes256Gcm;
	type Decryptor = crate::crypto::aead::Aes256Gcm;

	fn encryptor(&self) -> TransportResult<&Self::Encryptor> {
		self.symmetric_key.as_ref().ok_or(TransportError::Forbidden)
	}

	fn decryptor(&self) -> TransportResult<&Self::Decryptor> {
		self.symmetric_key.as_ref().ok_or(TransportError::Forbidden)
	}

	fn handshake_state(&self) -> HandshakeState {
		self.handshake_state
	}

	fn set_handshake_state(&mut self, state: HandshakeState) {
		self.handshake_state = state;
	}

	fn server_certificate(&self) -> Option<&Certificate> {
		self.server_certificate.as_ref()
	}

	fn set_symmetric_key(&mut self, key: Self::Encryptor) {
		// Replace existing key, ensuring the old key material is dropped immediately
		let _ = self.symmetric_key.take();
		self.symmetric_key = Some(key);
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
			transport.server_certificate = Some(cert.clone());
		}

		#[cfg(all(feature = "x509", feature = "secp256k1"))]
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
	async fn get_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
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
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
	#[cfg(feature = "x509")]
	#[allow(dead_code)]
	server_public_key: Option<Secp256k1VerifyingKey>,
	#[cfg(feature = "x509")]
	#[allow(dead_code)]
	enforce_encryption: bool,
	#[cfg(feature = "x509")]
	server_certificate: Option<Certificate>,
	#[cfg(feature = "x509")]
	aad_domain_tag: Option<Vec<u8>>,
	#[cfg(feature = "x509")]
	max_cleartext_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	max_encrypted_envelope: Option<usize>,
	#[cfg(all(feature = "x509", feature = "secp256k1"))]
	signatory: Option<std::sync::Arc<dyn crate::transport::handshake::ServerHandshakeKey>>,
	#[cfg(feature = "x509")]
	handshake_state: HandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<crate::crypto::aead::Aes256Gcm>,
}

// (single Drop impl above covers both feature variants)
#[cfg(feature = "transport-policy")]
pub struct TcpTransport<S: AsyncProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<crate::Frame> + Send>>,
	restart_policy: Box<dyn RestartPolicy>,
	emitter_gate: Box<dyn GatePolicy>,
	collector_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "x509")]
	#[allow(dead_code)]
	server_public_key: Option<Secp256k1VerifyingKey>,
	#[cfg(feature = "x509")]
	#[allow(dead_code)]
	enforce_encryption: bool,
	#[cfg(feature = "x509")]
	server_certificate: Option<Certificate>,
	#[cfg(feature = "x509")]
	aad_domain_tag: Option<Vec<u8>>,
	#[cfg(feature = "x509")]
	max_cleartext_envelope: Option<usize>,
	#[cfg(feature = "x509")]
	max_encrypted_envelope: Option<usize>,
	#[cfg(all(feature = "x509", feature = "secp256k1"))]
	signatory: Option<std::sync::Arc<dyn crate::transport::handshake::ServerHandshakeKey>>,
	#[cfg(feature = "x509")]
	handshake_state: HandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<crate::crypto::aead::Aes256Gcm>,
	#[cfg(all(feature = "x509", feature = "secp256k1"))]
	handshake: Option<crate::transport::handshake::TightBeamHandshake>,
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
			use crate::transport::handshake::HandshakeState;
			match self.handshake_state() {
				HandshakeState::AwaitingServerResponse { initiated_at }
				| HandshakeState::AwaitingClientFinish { initiated_at } => Some(initiated_at + self.handshake_timeout),
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
			// We can’t tell encrypted vs cleartext at this point, so choose the larger cap conservatively
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

	async fn collect_message(&mut self) -> TransportResult<(crate::Frame, crate::policy::TransitStatus)> {
		use crate::crypto::aead::Decryptor;
		use crate::der::{Decode, Encode};
		use crate::policy::TransitStatus;
		use crate::transport::handshake::HandshakeState;
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
						// Server with certificate - check for handshakes and enforce encryption after handshake
						match envelope {
							// Handshake messages - let perform_server_handshake handle them
							TransportEnvelope::ClientHello(_) | TransportEnvelope::ClientKeyExchange(_) => {
								// Re-encode as TransportEnvelope bytes
								let handshake_bytes = envelope.to_der()?;
								self.perform_server_handshake(&handshake_bytes).await?;

								// After processing, loop back to read next message
								continue;
							}
							// ServerHandshake not expected on server (only sent by server)
							TransportEnvelope::ServerHandshake(_) => {
								return Err(TransportError::InvalidMessage);
							}
							// Regular messages - check if encryption is required
							TransportEnvelope::Request(_) | TransportEnvelope::Response(_) => {
								// Only enforce encryption AFTER handshake is complete
								if self.handshake_state() == HandshakeState::Complete {
									// Circuit breaker: reset state on protocol violation
									self.set_handshake_state(HandshakeState::None);
									// Drop symmetric key to force re-handshake and zeroize underlying material
									self.symmetric_key = None;
									return Err(TransportError::MissingEncryption);
								}
								// Before handshake or no certificate, allow cleartext requests
								envelope
							}
						}
					} else {
						// No certificate - allow all cleartext
						envelope
					}
				}
				WireEnvelope::Encrypted(encrypted_info) => {
					// Decrypt the envelope (requires certificate/handshake)
					let decrypted_bytes = match self.decryptor()?.decrypt_content(&encrypted_info) {
						Ok(bytes) => bytes,
						Err(_) => {
							// Drop symmetric key on decrypt failure
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
				TransportEnvelope::ClientHello(_)
				| TransportEnvelope::ClientKeyExchange(_)
				| TransportEnvelope::ServerHandshake(_) => {
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
		message: Option<crate::Frame>,
	) -> TransportResult<()> {
		use crate::crypto::aead::{Aes256GcmOid, Encryptor};
		use crate::der::Encode;
		use crate::transport::{ResponsePackage, TransportEnvelope, WireEnvelope};

		let response_pkg = ResponsePackage { status, message, length: None };
		let response_envelope = TransportEnvelope::from(response_pkg);

		// Check if encryption should be used
		let wire_envelope = if self.handshake_state() == HandshakeState::Complete {
			// Use encryption after handshake complete
			let envelope_bytes = response_envelope.to_der()?;
			// Enforce size ceiling for encrypted responses
			if let Some(max) = self.max_encrypted_envelope {
				if envelope_bytes.len() > max {
					return Err(TransportError::InvalidMessage);
				}
			}
			let nonce = crate::random::generate_nonce::<12>(None)?; // AES-GCM nonce
			let encrypted =
				<_ as Encryptor<Aes256GcmOid>>::encrypt_content(self.encryptor()?, &envelope_bytes, nonce, None)?;
			WireEnvelope::Encrypted(encrypted)
		} else {
			// Use cleartext before handshake or when no certificate
			// Enforce size ceiling for cleartext responses
			{
				let bytes = response_envelope.to_der()?;
				if let Some(max) = self.max_cleartext_envelope {
					if bytes.len() > max {
						return Err(TransportError::InvalidMessage);
					}
				}
				WireEnvelope::Cleartext(response_envelope)
			}
		};

		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope(&wire_bytes).await?;
		Ok(())
	}
}

#[cfg(all(feature = "x509", feature = "secp256k1", feature = "transport-policy"))]
impl<S: AsyncProtocolStream> crate::transport::MessageEmitter for TcpTransport<S>
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

	/// Send a TightBeam message with automatic handshake
	///
	/// # Handshake Flow (when x509 enabled)
	async fn emit(&mut self, message: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		use crate::der::{Decode, Encode};
		use crate::policy::TransitStatus;
		use crate::transport::handshake::HandshakeState;
		use crate::transport::{EncryptedMessageIO, MessageIO, TransportEnvelope, WireEnvelope};

		let mut current_message: Frame = message;
		let mut current_attempt = attempt.unwrap_or(0);

		loop {
			// Evaluate gate policy before sending
			let status: TransitStatus = self.get_emitter_gate_policy().evaluate(&current_message);
			if status != TransitStatus::Accepted {
				// The gate did not accept the message: map to Unauthorized per policy
				return Err(TransportError::Unauthorized);
			}

			// Check if handshake is needed before sending
			if self.server_certificate().is_some() && self.handshake_state() == HandshakeState::None {
				// Perform client-side handshake
				println!("Client: performing handshake");
				self.perform_client_handshake().await?;
				println!("Client: handshake complete, state = {:?}", self.handshake_state());
			}

			// Wrap in envelope and send
			let envelope = TransportEnvelope::from(current_message.clone());

			// Check if encryption should be used
			println!("Client: about to send, handshake_state = {:?}", self.handshake_state());
			let wire_envelope = if self.handshake_state() == HandshakeState::Complete {
				// Use encryption after handshake complete
				println!("Client: encrypting message");
				use crate::crypto::aead::{Aes256GcmOid, Encryptor};
				let envelope_bytes = envelope.to_der()?;
				if let Some(max) = self.max_encrypted_envelope {
					if envelope_bytes.len() > max {
						return Err(TransportError::InvalidMessage);
					}
				}
				let nonce = crate::random::generate_nonce::<12>(None)?; // AES-GCM nonce
				let encrypted =
					<_ as Encryptor<Aes256GcmOid>>::encrypt_content(self.encryptor()?, &envelope_bytes, nonce, None)?;
				WireEnvelope::Encrypted(encrypted)
			} else {
				// Use cleartext before handshake or when no certificate
				println!("Client: sending cleartext");
				{
					let bytes = envelope.to_der()?;
					if let Some(max) = self.max_cleartext_envelope {
						if bytes.len() > max {
							return Err(TransportError::InvalidMessage);
						}
					}
					WireEnvelope::Cleartext(envelope.clone())
				}
			};

			self.write_envelope(&wire_envelope.to_der()?).await?;

			// Extract message back from envelope
			current_message = match envelope {
				TransportEnvelope::Request(msg) => msg.message,
				// This should never happen as we just created it
				_ => unreachable!(),
			};

			// Wait for receiver's response envelope
			let response_bytes = self.read_envelope().await?;

			// When x509 is enabled, parse as WireEnvelope first
			let response_envelope = {
				let wire_envelope = WireEnvelope::from_der(&response_bytes)?;
				match wire_envelope {
					WireEnvelope::Cleartext(env) => env,
					WireEnvelope::Encrypted(encrypted_info) => {
						// Decrypt response when handshake is complete
						use crate::crypto::aead::Decryptor;
						let decrypted_bytes = self.decryptor()?.decrypt_content(&encrypted_info)?;
						<Self as MessageIO>::decode_envelope(&decrypted_bytes)?
					}
				}
			};

			let (status, response) = match response_envelope {
				TransportEnvelope::Response(pkg) => (pkg.status, pkg.message),
				TransportEnvelope::Request(_) => {
					// Only responses are valid here
					return Err(TransportError::InvalidMessage);
				}
				TransportEnvelope::ClientHello(_)
				| TransportEnvelope::ClientKeyExchange(_)
				| TransportEnvelope::ServerHandshake(_) => {
					// Handshake messages not expected here
					return Err(TransportError::InvalidMessage);
				}
			};

			// Check transport status and handle response
			let result: TransportResult<&Frame> = if status != TransitStatus::Accepted {
				Err(<TransportError as From<TransitStatus>>::from(status))
			} else {
				match &response {
					Some(msg) => Ok(msg),
					None => return Ok(None),
				}
			};

			let policy: Option<Frame> =
				self.get_restart_policy()
					.evaluate(current_message.clone(), result, current_attempt);
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
						return Err(<TransportError as From<TransitStatus>>::from(status));
					} else {
						return Ok(response);
					}
				}
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
	use crate::transport::{MessageCollector, MessageEmitter, ResponseHandler, TransitStatus};

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
				let _ = tx.try_send(msg.clone());
				Some(response_msg.clone())
			}));

			transport.handle_request().await
		});

		let stream = TcpStream::connect(addr).await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream));
		let response = transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert_eq!(response, Some(expected_response));

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
		let config = crate::transport::TransportEncryptionConfig::new(
			cert.clone(),
			std::sync::Arc::new(signing_key.clone())
				as std::sync::Arc<dyn crate::transport::handshake::ServerHandshakeKey>,
		);
		let (listener, socket_addr) = TokioListener::bind_with(addr, config).await?;
		let server = listener;

		let test_message = create_v0_tightbeam(None, None);

		let (tx, mut rx) = tokio::sync::mpsc::channel(2);

		let server_handle = tokio::spawn(async move {
			let (transport, _) = server.accept().await?;
			println!("Server: accepted connection");
			let mut transport =
				transport
					.with_collector_gate(BusyFirstGate::new())
					.with_handler(Box::new(move |msg: Frame| {
						let _ = tx.try_send(msg.clone());
						Some(msg.clone())
					}));

			// First handle_request: processes handshake (ClientHello + ClientKeyExchange)
			// and first application message. Gate returns Busy for first app message.
			println!("Server: handling first request (handshake + app message)");
			let result = transport.handle_request().await;
			println!("Server: first handle_request result: {result:?}");
			result?;

			// Second handle_request: processes second application message
			// Gate returns Accepted this time
			println!("Server: handling second request");
			transport.handle_request().await
		});

		let stream = TcpStream::connect(*socket_addr).await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream)).with_server_certificate(cert);

		// First emit triggers handshake, then sends encrypted message
		// Gate policy returns Busy for first application message
		let first = transport.emit(test_message.clone(), None).await;
		println!("First attempt: {first:?}");
		assert!(matches!(first, Err(TransportError::Busy)));

		// Second emit sends encrypted message, gate returns Accepted
		transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert!(rx.try_recv().is_err());

		server_handle.await??;
		Ok(())
	}
}
