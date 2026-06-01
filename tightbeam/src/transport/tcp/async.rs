use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "tokio")]
use std::time::Instant;

#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tokio")]
use tokio::net::{TcpListener, TcpStream};

use crate::builder::TypeBuilder;
use crate::der::Encode;
use crate::transport::error::TransportFailure;
#[cfg(feature = "tokio")]
use crate::transport::protocols::PersistentConnection;
use crate::transport::ResponsePackage;
#[cfg(feature = "tokio")]
use crate::transport::{AsyncListenerTrait, Protocol};
use crate::transport::{
	EnvelopeBuilder, EnvelopeLimits, MessageIO, Pingable, TransportError, TransportResult, WireMode,
};
use crate::Frame;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::aead::RuntimeAead;
	pub use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
	pub use crate::crypto::x509::policy::CertificateValidation;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::transport::handshake::{
		HandshakeError, HandshakeKeyManager, HandshakeProtocolKind, ServerHandshakeProtocol, TcpHandshakeState,
	};
	pub use crate::transport::state::EncryptedProtocolState;
	#[cfg(feature = "tokio")]
	pub use crate::transport::EncryptedProtocol;
	pub use crate::transport::{EncryptedMessageIO, TransportEncryptionConfig};
	pub use crate::x509::Certificate;
}

#[cfg(feature = "x509")]
use x509::*;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::policy::GatePolicy;
	pub use crate::transport::policy::RestartPolicy;
}

#[cfg(feature = "transport-policy")]
use policy::*;

/// Marker relaxing `Send` on non-`wasm32` targets only.
///
/// Native transports run on multi-threaded executors and MUST stay `Send`; the
/// browser is single-threaded and its stream (gloo) is `!Send`, so on `wasm32`
/// this collapses to a no-op bound, letting the same transport core compile
/// without `Send`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// A frame-oriented async byte transport carrying DER-encoded envelopes.
pub trait AsyncProtocolStream: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Read one complete DER-encoded envelope from the transport.
	///
	/// `max_len` is the largest envelope content length the caller accepts; an
	/// implementation MUST reject a frame whose declared length exceeds it
	/// before allocating, to bound memory use.
	fn read_frame(
		&mut self,
		max_len: Option<usize>,
	) -> impl core::future::Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;

	/// Write one complete DER-encoded envelope to the transport.
	fn write_frame(&mut self, buffer: &[u8])
		-> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;

	/// Report whether the underlying transport still appears connected.
	fn is_alive(&self) -> bool;
}

#[cfg(feature = "tokio")]
pub struct TokioStream {
	stream: TcpStream,
}

#[cfg(feature = "tokio")]
impl AsyncProtocolStream for TokioStream {
	type Error = std::io::Error;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		let stream = &mut self.stream;

		let mut tag = [0u8; 1];
		stream.read_exact(&mut tag).await?;

		let mut length_first = [0u8; 1];
		stream.read_exact(&mut length_first).await?;

		let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
			(Vec::new(), length_first[0] as usize)
		} else {
			let octet_count = (length_first[0] & 0x7F) as usize;
			let mut length_octets = vec![0u8; octet_count];
			stream.read_exact(&mut length_octets).await?;
			let length = crate::transport::io::parse_der_length(length_first[0], &length_octets);
			(length_octets, length)
		};

		if let Some(max) = max_len {
			if content_length > max {
				return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
			}
		}

		let mut content = vec![0u8; content_length];
		stream.read_exact(&mut content).await?;

		Ok(crate::transport::io::reconstruct_der_encoding(
			tag[0],
			length_first[0],
			&length_octets,
			&content,
		))
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.stream.write_all(buffer).await
	}

	fn is_alive(&self) -> bool {
		self.stream.peer_addr().is_ok()
	}
}

#[cfg(feature = "tokio")]
impl From<TcpStream> for TokioStream {
	fn from(stream: TcpStream) -> Self {
		Self { stream }
	}
}

#[cfg(feature = "tokio")]
pub struct TokioListener<P: CryptoProvider = DefaultCryptoProvider> {
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
	key_manager: Option<Arc<HandshakeKeyManager<P>>>,
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider> TokioListener<P> {
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
			key_manager: None,
		})
	}

	#[cfg(not(feature = "x509"))]
	pub async fn accept(&self) -> std::io::Result<(TokioStream, std::net::SocketAddr)> {
		let (stream, addr) = self.listener.accept().await?;
		Ok((TokioStream::from(stream), addr))
	}

	#[cfg(feature = "x509")]
	pub async fn accept(&self) -> std::io::Result<(TcpTransport<TokioStream, P>, std::net::SocketAddr)> {
		let (stream, addr) = self.listener.accept().await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream));

		if let Some(cert) = &self.certificate {
			transport.server_identity = Some(Arc::clone(cert));
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
		if let Some(signatory) = &self.key_manager {
			transport.key_manager = Some(Arc::clone(signatory));
		}

		Ok((transport, addr))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> Protocol for TokioListener<P> {
	type Listener = TokioListener<P>;
	type Stream = TokioStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<TokioStream, P>;
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
				key_manager: None,
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

#[cfg(all(feature = "tokio", feature = "x509"))]
impl<P: CryptoProvider + Send + Sync> EncryptedProtocol for TokioListener<P> {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;
	type CryptoProvider = P;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
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
				key_manager: Some(Arc::clone(&config.key_manager)),
			},
			crate::transport::tcp::TightBeamSocketAddr(bound_addr),
		))
	}
}

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync + 'static> EncryptedProtocolState for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	type CryptoProvider = P;

	fn to_encryptor_ref(&self) -> TransportResult<&RuntimeAead> {
		self.symmetric_key
			.as_ref()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
	}

	fn to_decryptor_ref(&self) -> TransportResult<&RuntimeAead> {
		self.symmetric_key
			.as_ref()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
	}

	fn to_handshake_state(&self) -> TcpHandshakeState {
		self.handshake_state
	}

	fn set_handshake_state(&mut self, state: TcpHandshakeState) {
		self.handshake_state = state;
	}

	fn to_server_certificate_ref(&self) -> Option<&Certificate> {
		self.server_identity.as_ref().map(|arc| arc.as_ref())
	}

	fn to_server_certificate_arc(&self) -> Option<Arc<Certificate>> {
		self.server_identity.clone()
	}

	fn set_symmetric_key(&mut self, key: RuntimeAead) {
		// Replace existing key, ensuring the old key material is dropped immediately
		let _ = self.symmetric_key.take();
		self.symmetric_key = Some(key);
	}

	fn to_max_cleartext_envelope(&self) -> Option<usize> {
		self.max_cleartext_envelope
	}

	fn to_max_encrypted_envelope(&self) -> Option<usize> {
		self.max_encrypted_envelope
	}

	fn is_client_validators_present(&self) -> bool {
		self.client_validators.is_some()
	}

	fn to_handshake_protocol_kind(&self) -> HandshakeProtocolKind {
		self.handshake_protocol_kind
	}

	fn to_key_manager_ref(&self) -> Option<&Arc<HandshakeKeyManager<P>>> {
		self.key_manager.as_ref()
	}

	fn to_client_certificate_ref(&self) -> Option<&Arc<Certificate>> {
		self.client_certificate.as_ref()
	}

	fn to_trust_store_ref(&self) -> Option<&Arc<dyn CertificateTrust>> {
		self.trust_store.as_ref()
	}

	fn to_server_handshake_mut(
		&mut self,
	) -> &mut Option<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send + Sync>> {
		&mut self.server_handshake
	}

	fn set_peer_certificate(&mut self, cert: Certificate) {
		self.peer_certificate = Some(cert);
	}

	fn to_handshake_timeout(&self) -> Duration {
		self.handshake_timeout
	}

	fn to_client_validators_ref(&self) -> Option<&Arc<Vec<Arc<dyn CertificateValidation>>>> {
		self.client_validators.as_ref()
	}

	fn unset_symmetric_key(&mut self) {
		self.symmetric_key = None;
	}
}

// EncryptedMessageIO trait - now only contains operation methods
#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream> EncryptedMessageIO for TcpTransport<S> where TransportError: From<S::Error> {}

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Configure this transport as an encrypted server endpoint.
	pub fn with_server_encryption(mut self, config: TransportEncryptionConfig<P>) -> Self {
		self.server_identity = Some(Arc::new(config.certificate));
		self.client_validators = config.client_validators;
		self.aad_domain_tag = Some(config.aad_domain_tag);
		self.max_cleartext_envelope = Some(config.max_cleartext_envelope);
		self.max_encrypted_envelope = Some(config.max_encrypted_envelope);
		self.handshake_timeout = config.handshake_timeout;
		self.key_manager = Some(config.key_manager);
		self
	}
}

// Ensure symmetric key material is dropped when the transport is dropped
impl<S: AsyncProtocolStream, P: crate::crypto::profiles::CryptoProvider> Drop for TcpTransport<S, P> {
	fn drop(&mut self) {
		let _ = self.symmetric_key.take();
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> AsyncListenerTrait for TokioListener<P> {
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		let (stream, addr) = self.listener.accept().await?;
		let mut transport = Self::create_transport(TokioStream::from(stream));

		#[cfg(feature = "x509")]
		if let Some(ref cert) = self.certificate {
			transport.server_identity = Some(Arc::clone(cert));
		}

		#[cfg(feature = "x509")]
		if let Some(ref signatory) = self.key_manager {
			transport.key_manager = Some(Arc::clone(signatory));
		}

		#[cfg(feature = "x509")]
		if let Some(timeout) = self.handshake_timeout {
			transport.handshake_timeout = timeout;
		}

		Ok((transport, crate::transport::tcp::TightBeamSocketAddr(addr)))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> crate::transport::Mycelial for TokioListener<P> {
	async fn try_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
		// Bind to an available port (0.0.0.0:0 lets the OS choose)
		let addr = "0.0.0.0:0"
			.parse::<crate::transport::tcp::TightBeamSocketAddr>()
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
		<TokioListener<P> as Protocol>::bind(addr).await
	}
}

#[cfg(not(feature = "transport-policy"))]
pub struct TcpTransport<S: AsyncProtocolStream, P: CryptoProvider = DefaultCryptoProvider> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<Frame> + Send + Sync>>,
	#[cfg(feature = "x509")]
	trust_store: Option<Arc<dyn CertificateTrust>>,
	#[cfg(feature = "x509")]
	server_identity: Option<Arc<Certificate>>,
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
	key_manager: Option<Arc<HandshakeKeyManager<P>>>,
	#[cfg(feature = "x509")]
	handshake_state: TcpHandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<RuntimeAead>,
	_phantom: core::marker::PhantomData<P>,
}

// (single Drop impl above covers both feature variants)
#[cfg(feature = "transport-policy")]
pub struct TcpTransport<S: AsyncProtocolStream, P: CryptoProvider = DefaultCryptoProvider> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<Frame> + Send + Sync>>,
	restart_policy: Box<dyn RestartPolicy>,
	emitter_gate: Box<dyn GatePolicy>,
	collector_gate: Box<dyn GatePolicy>,
	operation_timeout: Option<Duration>,
	#[cfg(feature = "x509")]
	trust_store: Option<Arc<dyn CertificateTrust>>,
	#[cfg(feature = "x509")]
	server_identity: Option<Arc<Certificate>>,
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
	key_manager: Option<Arc<HandshakeKeyManager<P>>>,
	#[cfg(feature = "x509")]
	handshake_state: TcpHandshakeState,
	#[cfg(feature = "x509")]
	handshake_timeout: Duration,
	#[cfg(feature = "x509")]
	symmetric_key: Option<RuntimeAead>,
	#[cfg(feature = "x509")]
	server_handshake: Option<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send + Sync>>,
	#[cfg(feature = "x509")]
	handshake_protocol_kind: HandshakeProtocolKind,
	_phantom: core::marker::PhantomData<P>,
}

impl<S: AsyncProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
	TransportError: From<std::io::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		if self.stream.is_alive() {
			Ok(())
		} else {
			Err(TransportError::ConnectionClosed)
		}
	}
}

crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		// Conservative pre-allocation ceiling: we cannot tell encrypted from
		// cleartext at this point, so choose the larger cap.
		#[cfg(feature = "x509")]
		let max_len = Some(
			self.max_encrypted_envelope
				.or(self.max_cleartext_envelope)
				.unwrap_or(512 * 1024),
		);

		#[cfg(not(feature = "x509"))]
		let max_len = None;

		// The tokio runtime supplies `tokio::time::timeout`; non-tokio runtimes
		// (e.g. wasm/gloo) have no portable timer here, so they read without a
		// deadline. The handshake clock is likewise absent off-tokio.
		#[cfg(feature = "tokio")]
		{
			use tokio::time::timeout;

			// Determine timeout duration: prefer handshake_timeout during
			// handshake, operation_timeout otherwise
			#[cfg(feature = "x509")]
			let timeout_duration: Option<Duration> = {
				match self.to_handshake_state() {
					TcpHandshakeState::AwaitingServerResponse { initiated_at }
					| TcpHandshakeState::AwaitingClientFinish { initiated_at } => {
						let now = Instant::now();
						let deadline = initiated_at + self.handshake_timeout;
						if now >= deadline {
							return Err(TransportError::OperationFailed(TransportFailure::Timeout));
						}
						Some(deadline.saturating_duration_since(now))
					}
					_ => {
						// Not in handshake - use operation_timeout if configured
						#[cfg(feature = "transport-policy")]
						{
							self.operation_timeout
						}
						#[cfg(not(feature = "transport-policy"))]
						{
							None
						}
					}
				}
			};

			#[cfg(not(feature = "x509"))]
			let timeout_duration: Option<Duration> = {
				#[cfg(feature = "transport-policy")]
				{
					self.operation_timeout
				}
				#[cfg(not(feature = "transport-policy"))]
				{
					None
				}
			};

			let buffer = if let Some(dur) = timeout_duration {
				timeout(dur, self.stream.read_frame(max_len)).await??
			} else {
				self.stream.read_frame(max_len).await?
			};

			Ok(buffer)
		}

		#[cfg(not(feature = "tokio"))]
		{
			let buffer = self.stream.read_frame(max_len).await?;
			Ok(buffer)
		}
	}

	async fn write_envelope(&mut self, buffer: &[u8]) -> TransportResult<()> {
		// Apply operation timeout if configured (tokio only; see read_envelope).
		#[cfg(all(feature = "tokio", feature = "transport-policy"))]
		if let Some(dur) = self.operation_timeout {
			tokio::time::timeout(dur, self.stream.write_frame(buffer)).await??;
		} else {
			self.stream.write_frame(buffer).await?;
		}

		#[cfg(not(all(feature = "tokio", feature = "transport-policy")))]
		self.stream.write_frame(buffer).await?;

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
		// Use the default trait implementation
		self.collect_message_with_encryption().await
	}

	async fn send_response(
		&mut self,
		status: crate::policy::TransitStatus,
		message: Option<Frame>,
	) -> TransportResult<()> {
		let response_pkg = ResponsePackage { status, message: message.map(Arc::new) };
		let limits = EnvelopeLimits::from_pair(self.max_cleartext_envelope, self.max_encrypted_envelope);
		let mut builder = limits.apply(EnvelopeBuilder::response(response_pkg));

		if self.to_handshake_state() == TcpHandshakeState::Complete {
			let encryptor = self.to_encryptor_ref()?;
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
impl<S: AsyncProtocolStream> crate::transport::MessageEmitter for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type EmitterGate = dyn crate::policy::GatePolicy;
	type RestartPolicy = dyn crate::transport::policy::RestartPolicy;

	fn to_restart_policy_ref(&self) -> &Self::RestartPolicy {
		self.restart_policy.as_ref()
	}

	fn to_emitter_gate_policy_ref(&self) -> &Self::EmitterGate {
		self.emitter_gate.as_ref()
	}

	/// Protocol-specific send/receive with handshake and timeout
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(crate::policy::TransitStatus, Option<Frame>, Option<Frame>)> {
		// Ensure handshake is complete
		self.ensure_handshake_complete().await?;

		// Perform send/receive with optional timeout (tokio only; non-tokio
		// runtimes have no portable timer and emit without a deadline).
		#[cfg(feature = "tokio")]
		{
			let timeout_duration = self.operation_timeout;
			if let Some(duration) = timeout_duration {
				use tokio::time::timeout;
				match timeout(duration, async { self.perform_emit_cycle(message).await }).await {
					Ok(result) => result,
					Err(_) => Err(TransportError::OperationFailed(TransportFailure::Timeout)),
				}
			} else {
				self.perform_emit_cycle(message).await
			}
		}

		#[cfg(not(feature = "tokio"))]
		{
			self.perform_emit_cycle(message).await
		}
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> PersistentConnection for TokioListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		// Lightweight liveness check delegated to the stream; performs no I/O.
		transport.stream.is_alive()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// Best-effort graceful shutdown
		// TCP connections will be fully closed when transport drops
		// tokio TcpStream doesn't provide a shutdown method, relies on Drop
	}
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
	use super::*;
	use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
	use crate::crypto::sign::Sha3Signer;
	use crate::testing::*;
	use crate::transport::{MessageCollector, MessageEmitter, ResponseHandler};

	#[cfg(feature = "x509")]
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
		use core::str::FromStr;
		use core::sync::atomic::{AtomicBool, Ordering};
		use std::sync::Arc;

		use crate::crypto::hash::Sha3_256;
		use crate::crypto::policy::Secp256k1Policy;
		use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
		use crate::policy::TransitStatus;
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::transport::TransportEncryptionConfig;
		use crate::transport::X509ClientConfig;
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
		let not_after = not_before + Duration::from_secs(365 * 24 * 60 * 60);

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
		let config = TransportEncryptionConfig::new(cert.clone(), signing_key.clone().into());
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
		// Create trust store from certificate
		let trust_store: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_certificate(cert)?
				.build(),
		);
		let mut transport = TcpTransport::from(TokioStream::from(stream)).with_trust_store(trust_store);

		// First emit triggers handshake, then sends encrypted message
		// Gate policy returns Busy for first application message
		let first = transport.emit(test_message.clone(), None).await;
		assert!(matches!(first, Err(TransportError::OperationFailed(TransportFailure::Busy))));

		// Second emit sends encrypted message, gate returns Accepted
		transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert!(rx.try_recv().is_err());

		server_handle.await??;
		Ok(())
	}
}
