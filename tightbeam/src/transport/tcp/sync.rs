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
use crate::transport::error::TransportFailure;
use crate::transport::handshake::{
	HandshakeError, HandshakeKeyManager, HandshakeProtocolKind, ServerHandshakeProtocol, TcpHandshakeState,
};
use crate::transport::state::EncryptedProtocolState;
use crate::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use crate::transport::{
	EncryptedMessageIO, EncryptedProtocol, MessageCollector, MessageEmitter, MessageIO, Pingable, Protocol,
	ResponsePackage, TransportEncryptionConfig, TransportResult,
};
use crate::x509::Certificate;
use crate::Frame;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::policy::GatePolicy;
	pub use crate::policy::TransitStatus;
	pub use crate::transport::error::TransportError;
	pub use crate::transport::policy::RestartPolicy;
	pub use crate::transport::{EnvelopeBuilder, EnvelopeLimits, ProtocolStream, WireMode};
}

#[cfg(feature = "transport-policy")]
use policy::*;

pub struct TcpTransport<S: ProtocolStream> {
	stream: S,
	handler: Option<Box<dyn Fn(Frame) -> Option<Frame> + Send + Sync>>,
	#[cfg(feature = "transport-policy")]
	restart_policy: Box<dyn RestartPolicy>,
	#[cfg(feature = "transport-policy")]
	emitter_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "transport-policy")]
	collector_gate: Box<dyn GatePolicy>,
	#[cfg(feature = "std")]
	operation_timeout: Option<std::time::Duration>,

	server_certificates: Vec<Arc<Certificate>>,
	
	server_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,

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

	server_handshake: Option<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send + Sync>>,

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
				match self.to_handshake_state() {
					TcpHandshakeState::AwaitingServerResponse { initiated_at }
					| TcpHandshakeState::AwaitingClientFinish { initiated_at } => {
						let now = std::time::Instant::now();
						if now >= initiated_at + self.handshake_timeout {
							return Err(TransportError::OperationFailed(TransportFailure::Timeout));
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
impl<S: ProtocolStream> MessageCollector for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type CollectorGate = dyn GatePolicy;

	fn collector_gate(&self) -> &Self::CollectorGate {
		self.collector_gate.as_ref()
	}

	async fn collect_message(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)> {
		// Use the default trait implementation
		self.collect_message_with_encryption().await
	}

	async fn send_response(&mut self, status: TransitStatus, message: Option<Frame>) -> TransportResult<()> {
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
		self.write_envelope(&wire_bytes).await
	}
}

#[cfg(feature = "transport-policy")]
impl<S: ProtocolStream> MessageEmitter for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	type EmitterGate = dyn GatePolicy;
	type RestartPolicy = dyn RestartPolicy;

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
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		// Ensure handshake is complete
		self.ensure_handshake_complete().await?;

		#[cfg(feature = "std")]
		{
			// Set socket timeout before operation (if configured)
			let timeout_duration = self.operation_timeout;
			if let Some(duration) = timeout_duration {
				self.stream.set_timeout(Some(duration))?;
			}

			let result = self.perform_emit_cycle(message).await;

			// Restore/clear timeout after operation
			if timeout_duration.is_some() {
				let _ = self.stream.set_timeout(None);
			}

			// Convert I/O timeout errors to TransportError::OperationFailed
			result.map_err(|e| {
				if let TransportError::IoError(io_err) = &e {
					if io_err.kind() == std::io::ErrorKind::TimedOut {
						return TransportError::OperationFailed(TransportFailure::Timeout);
					}
				}

				e
			})
		}

		#[cfg(not(feature = "std"))]
		{
			self.perform_emit_cycle(message).await
		}
	}
}

// Old emit() implementation removed - now uses default trait implementation

impl<S: ProtocolStream> EncryptedProtocolState for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
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
		self.server_certificates.first().map(|arc| arc.as_ref())
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

	fn to_key_manager_ref(&self) -> Option<&Arc<HandshakeKeyManager>> {
		self.key_manager.as_ref()
	}

	fn to_client_certificate_ref(&self) -> Option<&Arc<Certificate>> {
		self.client_certificate.as_ref()
	}

	fn to_server_certificates_ref(&self) -> &[Arc<Certificate>] {
		&self.server_certificates
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
impl<S: ProtocolStream> EncryptedMessageIO for TcpTransport<S> where TransportError: From<S::Error> {}

/// TCP server using abstract listener trait
pub struct TcpListener<L: TcpListenerTrait> {
	listener: L,
	certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	aad_domain_tag: Option<&'static [u8]>,
	max_cleartext_envelope: Option<usize>,
	max_encrypted_envelope: Option<usize>,
	key_manager: Option<Arc<HandshakeKeyManager>>,
	handshake_timeout: Option<Duration>,
}

#[cfg(feature = "std")]
impl Protocol for TcpListener<std::net::TcpListener> {
	type Listener = TcpListener<std::net::TcpListener>;
	type Stream = std::net::TcpStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<std::net::TcpStream>;
	type Address = TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		std::net::SocketAddr::from_str("127.0.0.1:0")
			.map(TightBeamSocketAddr)
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
			TightBeamSocketAddr(bound_addr),
		))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		std::net::TcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(TightBeamSocketAddr(self.listener.local_addr()?))
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

		use crate::policy::TransitStatus;
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
			fn evaluate(&self, _msg: &Frame) -> TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					TransitStatus::Busy
				} else {
					TransitStatus::Accepted
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
		assert!(matches!(result, Err(TransportError::OperationFailed(TransportFailure::Busy))));

		// Second attempt - server responds with Accepted
		transport.emit(message.clone(), None).await?;

		server_handle.join().unwrap();
		Ok(())
	}
}
