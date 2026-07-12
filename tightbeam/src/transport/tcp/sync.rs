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
use crate::crypto::x509::store::CertificateTrust;
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
	pub use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
	pub use crate::policy::GatePolicy;
	pub use crate::policy::TransitStatus;
	pub use crate::transport::error::TransportError;
	pub use crate::transport::policy::RestartPolicy;
	pub use crate::transport::{EnvelopeBuilder, EnvelopeLimits, ProtocolStream, WireMode};
}

#[cfg(feature = "transport-policy")]
use policy::*;

impl<S: ProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	fn ping(&mut self) -> TransportResult<()> {
		// Try to write zero bytes to check if the connection is alive
		self.stream.write_all(&[]).map_err(|e| e.into())
	}
}

// Generates the TcpTransport struct definition and common implementations
crate::impl_tcp_common!(TcpTransport, ProtocolStream);

/// Slice sizes for deadline-bounded content reads. The stream timeout is
/// per-recv (SO_RCVTIMEO), so the absolute budget is only re-checked between
/// slices: the worst-case overrun past the deadline is one slice of
/// per-recv resets.
#[cfg(feature = "std")]
const HANDSHAKE_READ_SLICE: usize = 64;
#[cfg(feature = "std")]
const ESTABLISHED_READ_SLICE: usize = 1024;

#[cfg(feature = "std")]
impl<S: ProtocolStream, P: CryptoProvider> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Re-arm the stream's per-recv timeout with the budget remaining until
	/// `deadline`, failing with `Timeout` once the budget is exhausted.
	fn arm_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> TransportResult<()> {
		let Some(deadline) = deadline else {
			return Ok(());
		};
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		if remaining.is_zero() {
			return Err(TransportError::OperationFailed(TransportFailure::Timeout));
		}
		self.stream.set_timeout(Some(remaining))?;
		Ok(())
	}
}

impl<S: ProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		let handshake_pending = self.is_handshake_pending();

		// Absolute deadline for the whole envelope read; every stage below
		// re-arms the per-recv timeout with the *remaining* budget. Handshake
		// reads face an unauthenticated peer, so the handshake deadline
		// applies from the first byte onward; established sessions use the
		// optional operation timeout.
		#[cfg(feature = "std")]
		let deadline = if handshake_pending {
			match self.to_handshake_state() {
				TcpHandshakeState::AwaitingServerResponse { initiated_at }
				| TcpHandshakeState::AwaitingClientFinish { initiated_at } => Some(initiated_at + self.handshake_timeout),
				_ => Some(std::time::Instant::now() + self.handshake_timeout),
			}
		} else {
			self.operation_timeout.map(|timeout| std::time::Instant::now() + timeout)
		};

		let result = (|| -> TransportResult<Vec<u8>> {
			// Read tag byte
			#[cfg(feature = "std")]
			self.arm_read_deadline(deadline)?;
			let mut tag_byte = [0u8; 1];
			self.stream.read_exact(&mut tag_byte)?;

			// Read length encoding
			#[cfg(feature = "std")]
			self.arm_read_deadline(deadline)?;
			let mut length_first = [0u8; 1];
			self.stream.read_exact(&mut length_first)?;

			let (length_octets, content_length) = if length_first[0] & 0x80 == 0 {
				// Short form
				(vec![], length_first[0] as usize)
			} else {
				// Long form
				let num_length_octets = (length_first[0] & 0x7F) as usize;
				let mut length_octets = vec![0u8; num_length_octets];
				#[cfg(feature = "std")]
				self.arm_read_deadline(deadline)?;
				self.stream.read_exact(&mut length_octets)?;

				let length =
					Self::parse_der_length(length_first[0], &length_octets).ok_or(TransportError::InvalidMessage)?;
				(length_octets, length)
			};

			// Enforce size ceilings: unauthenticated handshake reads get the
			// tight handshake cap, established sessions the envelope limits.
			{
				let max_allowed = if handshake_pending {
					crate::transport::tcp::HANDSHAKE_MAX_WIRE
				} else {
					self.max_encrypted_envelope
						.or(self.max_cleartext_envelope)
						.unwrap_or(512 * 1024)
				};
				if content_length > max_allowed {
					return Err(TransportError::InvalidMessage);
				}
			}

			// Read content. Without a deadline one read suffices; with one,
			// read in slices and re-check the remaining budget between them
			// so a byte-dripping peer cannot stretch the read via per-recv
			// timeout resets inside a single large read_exact.
			let mut content = vec![0u8; content_length];
			#[cfg(feature = "std")]
			{
				if deadline.is_some() {
					let slice_len = if handshake_pending {
						HANDSHAKE_READ_SLICE
					} else {
						ESTABLISHED_READ_SLICE
					};

					let mut filled = 0;
					while filled < content_length {
						self.arm_read_deadline(deadline)?;
						let end = usize::min(filled + slice_len, content_length);
						self.stream.read_exact(&mut content[filled..end])?;
						filled = end;
					}
				} else {
					self.stream.read_exact(&mut content)?;
				}
			}
			#[cfg(not(feature = "std"))]
			self.stream.read_exact(&mut content)?;

			// Reconstruct full DER encoding using the helper
			let buffer = Self::reconstruct_der_encoding(tag_byte[0], length_first[0], &length_octets, &content);
			Ok(buffer)
		})();

		// Clear timeout before handling result
		#[cfg(feature = "std")]
		if deadline.is_some() {
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

impl<S: ProtocolStream, P: CryptoProvider + Send + Sync + 'static> EncryptedProtocolState for TcpTransport<S, P>
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
		self.server_identity.as_ref().map(Arc::clone)
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
impl<S: ProtocolStream> EncryptedMessageIO for TcpTransport<S> where TransportError: From<S::Error> {}

/// TCP server using abstract listener trait
pub struct TcpListener<L: TcpListenerTrait, P: CryptoProvider = DefaultCryptoProvider> {
	listener: L,
	certificate: Option<Arc<Certificate>>,
	#[cfg(feature = "x509")]
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	aad_domain_tag: Option<&'static [u8]>,
	max_cleartext_envelope: Option<usize>,
	max_encrypted_envelope: Option<usize>,
	key_manager: Option<Arc<HandshakeKeyManager<P>>>,
	handshake_timeout: Option<Duration>,
}

#[cfg(feature = "std")]
impl<P: CryptoProvider + Send + Sync> Protocol for TcpListener<std::net::TcpListener, P> {
	type Listener = TcpListener<std::net::TcpListener, P>;
	type Stream = std::net::TcpStream;
	type Error = std::io::Error;
	type Transport = TcpTransport<std::net::TcpStream, P>;
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

impl<L: TcpListenerTrait, P: CryptoProvider> TcpListener<L, P>
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

	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream, P>> {
		let (stream, _) = self.listener.accept()?;
		let mut transport = TcpTransport::from(stream);

		{
			if let Some(ref cert) = self.certificate {
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

impl<P: CryptoProvider + Send + Sync> EncryptedProtocol for TcpListener<std::net::TcpListener, P> {
	type Encryptor = RuntimeAead;
	type Decryptor = RuntimeAead;
	type CryptoProvider = P;

	async fn bind_with(
		addr: <Self as Protocol>::Address,
		config: TransportEncryptionConfig<P>,
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

	/// Under the per-recv-only scheme this read complete after ~6s of dripping
	/// the absolute deadline aborts it at the first slice boundary past
	/// the budget.
	#[cfg(feature = "x509")]
	#[tokio::test]
	async fn handshake_read_deadline_bounds_byte_drip() -> TransportResult<()> {
		use std::io::Write;

		let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;

		let server_handle = std::thread::spawn(move || -> TransportResult<(TransportResult<Vec<u8>>, Duration)> {
			let (stream, _) = listener.accept()?;
			let mut transport: TcpTransport<std::net::TcpStream> = TcpTransport::from(stream);
			// Configured client validation marks the endpoint as expecting a
			// handshake, putting the first read under the handshake clock.
			transport.client_validators = Some(Arc::new(Vec::new()));
			transport.handshake_timeout = Duration::from_millis(250);

			let rt = tokio::runtime::Runtime::new()?;
			let started = std::time::Instant::now();
			let result = rt.block_on(transport.read_envelope());
			Ok((result, started.elapsed()))
		});

		// SEQUENCE header declaring 600 content bytes, sent whole; the body
		// then drips one byte per 10ms (well under any per-recv timeout).
		let mut stream = TcpStream::connect(addr)?;
		Write::write_all(&mut stream, &[0x30, 0x82, 0x02, 0x58])?;
		let drip_handle = std::thread::spawn(move || {
			for _ in 0..600 {
				if Write::write_all(&mut stream, &[0u8]).is_err() {
					break;
				}
				std::thread::sleep(Duration::from_millis(10));
			}
		});

		// A panicked server thread surfaces as an I/O error rather than a
		// re-panic; the closure itself only fails through `?`.
		let (result, elapsed) = server_handle
			.join()
			.map_err(|_| TransportError::IoError(std::io::Error::from(std::io::ErrorKind::Other)))??;
		drip_handle.join().ok();

		assert!(result.is_err());
		assert!(elapsed < Duration::from_secs(5));
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
