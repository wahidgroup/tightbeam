#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::str::FromStr;

#[cfg(feature = "std")]
use core::time::Duration;
#[cfg(feature = "std")]
use std::io::{Error as IoError, ErrorKind};
#[cfg(feature = "std")]
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::time::Instant;

use crate::builder::TypeBuilder;
use crate::crypto::aead::{RecvCipher, SendCipher, SessionKeys};
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::store::CertificateTrust;
use crate::der::Encode;
use crate::transport::error::TransportFailure;
use crate::transport::framing::{
	classify_boundary_error, classify_truncation_error, parse_der_length, reconstruct_der_encoding, LengthForm,
};
use crate::transport::handshake::negotiation::{MuxSettings, TransportAuthorizer, TransportOffer};
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver, StoredReceipt};
use crate::transport::handshake::{
	BoxedServerHandshake, HandshakeKeyManager, HandshakeProtocolKind, TcpHandshakeState,
};
use crate::transport::state::EncryptedProtocolState;
use crate::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr, HANDSHAKE_MAX_WIRE};
use crate::transport::{
	EncryptedMessageIO, EncryptedProtocol, MessageCollector, MessageEmitter, MessageIO, Protocol, ResponsePackage,
	TransportEncryptionConfig, TransportResult,
};
use crate::x509::Certificate;
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "aead")]
use crate::transport::handshake::EpochMaterials;

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
	fn arm_read_deadline(&mut self, deadline: Option<Instant>) -> TransportResult<()> {
		let Some(deadline) = deadline else {
			return Ok(());
		};

		let remaining = deadline.saturating_duration_since(Instant::now());
		if remaining.is_zero() {
			return Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded));
		}

		self.stream.set_timeout(Some(remaining))?;
		Ok(())
	}
}

impl<S: ProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
		let handshake_pending = self.is_handshake_pending();

		// Absolute deadline for the whole envelope read. Every stage below
		// re-arms the per-recv timeout with the *remaining* budget. Handshake
		// reads face an unauthenticated peer, so the handshake deadline
		// applies from the first byte onward.
		#[cfg(feature = "std")]
		let deadline = if handshake_pending {
			match self.to_handshake_state() {
				TcpHandshakeState::AwaitingServerResponse { initiated_at }
				| TcpHandshakeState::AwaitingClientFinish { initiated_at } => Some(initiated_at + self.handshake_timeout),
				_ => Some(Instant::now() + self.handshake_timeout),
			}
		} else {
			self.operation_timeout.map(|timeout| Instant::now() + timeout)
		};

		let result = (|| -> TransportResult<Vec<u8>> {
			#[cfg(feature = "std")]
			self.arm_read_deadline(deadline)?;

			// EOF before the tag is the peer closing between frames; EOF
			// anywhere after it is a truncated frame.
			let mut tag_byte = [0u8; 1];
			self.stream
				.read_exact(&mut tag_byte)
				.map_err(|e| classify_boundary_error(e.into()))?;

			#[cfg(feature = "std")]
			self.arm_read_deadline(deadline)?;

			let mut length_first = [0u8; 1];
			self.stream
				.read_exact(&mut length_first)
				.map_err(|e| classify_truncation_error(e.into()))?;

			let (length_octets, content_length) = match LengthForm::from(length_first[0]) {
				LengthForm::Short(length) => (vec![], length),
				LengthForm::Long(octet_count) => {
					let mut length_octets = vec![0u8; octet_count];

					#[cfg(feature = "std")]
					self.arm_read_deadline(deadline)?;

					self.stream
						.read_exact(&mut length_octets)
						.map_err(|e| classify_truncation_error(e.into()))?;

					let length =
						parse_der_length(length_first[0], &length_octets).ok_or(TransportError::InvalidMessage)?;
					(length_octets, length)
				}
			};

			// Enforce size ceilings: unauthenticated handshake reads get the
			// tight handshake cap, established sessions the envelope limits.
			{
				let max_allowed = if handshake_pending {
					HANDSHAKE_MAX_WIRE
				} else {
					self.max_encrypted_envelope
						.or(self.max_cleartext_envelope)
						.unwrap_or(512 * 1024)
				};

				if content_length > max_allowed {
					return Err(TransportError::InvalidMessage);
				}
			}

			// Read content. Without a deadline one read suffices. With one,
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
						self.stream
							.read_exact(&mut content[filled..end])
							.map_err(|e| classify_truncation_error(e.into()))?;
						filled = end;
					}
				} else {
					self.stream
						.read_exact(&mut content)
						.map_err(|e| classify_truncation_error(e.into()))?;
				}
			}
			#[cfg(not(feature = "std"))]
			self.stream
				.read_exact(&mut content)
				.map_err(|e| classify_truncation_error(e.into()))?;

			let buffer = reconstruct_der_encoding(tag_byte[0], length_first[0], &length_octets, &content);
			Ok(buffer)
		})();

		#[cfg(feature = "std")]
		if deadline.is_some() {
			let _ = self.stream.set_timeout(None);
		}

		result
	}

	async fn write_envelope_bytes(&mut self, buffer: &[u8]) -> TransportResult<()> {
		#[cfg(feature = "std")]
		if let Some(timeout) = self.operation_timeout {
			self.stream.set_timeout(Some(timeout))?;
		}

		let result = self.stream.write_all(buffer);

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
		&self.collector_gate
	}

	async fn collect_message(&mut self) -> TransportResult<(Arc<Frame>, TransitStatus)> {
		self.collect_message_with_encryption().await
	}

	async fn send_response(&mut self, status: TransitStatus, message: Option<Frame>) -> TransportResult<()> {
		let response_pkg = ResponsePackage { status, message: message.map(Arc::new) };
		let limits = EnvelopeLimits::from_pair(self.max_cleartext_envelope, self.max_encrypted_envelope);
		let mut builder = limits.apply(EnvelopeBuilder::response(response_pkg));

		if self.to_handshake_state() == TcpHandshakeState::Complete {
			let wire_mode = WireMode::Encrypted;
			builder = builder.with_wire_mode(wire_mode);

			let encryptor = self.to_encryptor_ref()?;
			builder = builder.with_encryptor(encryptor);
		} else {
			let wire_mode = WireMode::Cleartext;
			builder = builder.with_wire_mode(wire_mode);
		}

		let wire_envelope = builder.build()?;
		let wire_bytes = wire_envelope.to_der()?;
		self.write_envelope_bytes(&wire_bytes).await
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
		&self.emitter_gate
	}

	/// Protocol-specific send/receive with handshake and timeout
	fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> impl core::future::Future<Output = TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)>>
	       + crate::utils::marker::MaybeSend {
		async {
			self.ensure_handshake_complete().await?;

			#[cfg(feature = "std")]
			{
				let timeout_duration = self.operation_timeout;
				if let Some(duration) = timeout_duration {
					self.stream.set_timeout(Some(duration))?;
				}

				let result = self.perform_emit_cycle(message).await;

				if timeout_duration.is_some() {
					let _ = self.stream.set_timeout(None);
				}

				result.map_err(|e| {
					if let TransportError::IoError(io_err) = &e {
						if io_err.kind() == ErrorKind::TimedOut {
							return TransportError::OperationFailed(TransportFailure::DeadlineExceeded);
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
}

// EncryptedMessageIO: operation methods only
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
impl<P: CryptoProvider + Send + Sync> Protocol for TcpListener<NetTcpListener, P> {
	type Listener = TcpListener<NetTcpListener, P>;
	type Stream = NetTcpStream;
	type Error = IoError;
	type Transport = TcpTransport<NetTcpStream, P>;
	type Address = TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		SocketAddr::from_str("127.0.0.1:0")
			.map(TightBeamSocketAddr)
			.map_err(|e| IoError::new(ErrorKind::InvalidInput, e))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = NetTcpListener::bind(addr.0)?;
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
		NetTcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
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

impl<P: CryptoProvider + Send + Sync> EncryptedProtocol for TcpListener<NetTcpListener, P> {
	type Encryptor = SendCipher;
	type Decryptor = RecvCipher;
	type CryptoProvider = P;

	async fn bind_with(
		addr: <Self as Protocol>::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, <Self as Protocol>::Address), <Self as Protocol>::Error> {
		let listener = NetTcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		let certificate = Arc::new(config.certificate);
		let client_validators = config.client_validators.as_ref().map(Arc::clone);
		let key_manager = Arc::clone(&config.key_manager);

		Ok((
			TcpListener {
				listener,
				certificate: Some(certificate),
				#[cfg(feature = "x509")]
				client_validators,
				aad_domain_tag: Some(config.aad_domain_tag),
				max_cleartext_envelope: Some(config.max_cleartext_envelope),
				max_encrypted_envelope: Some(config.max_encrypted_envelope),

				key_manager: Some(key_manager),
				handshake_timeout: Some(config.handshake_timeout),
			},
			TightBeamSocketAddr(bound_addr),
		))
	}
}

#[cfg(test)]
mod tests {
	#![allow(unused_imports)]
	use std::io::Write;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc;
	use std::thread;

	use super::*;
	use crate::policy::TransitStatus;
	use crate::testing::*;
	use crate::transport::policy::PolicyConfig;

	/// Serve one single-flight request with an empty reply, answering
	/// with the gate's status.
	#[cfg(not(feature = "x509"))]
	async fn respond_none<T: MessageCollector>(transport: &mut T) -> TransportResult<()> {
		let (_request, status) = transport.collect_message().await?;
		transport.send_response(status, None).await
	}

	#[cfg(not(feature = "x509"))]
	#[tokio::test]
	async fn test_tcp_transport_emit_collect() -> TransportResult<()> {
		let message = create_v0_tightbeam(None, None);
		let listener = NetTcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = thread::spawn(move || -> TransportResult<()> {
			let server = TcpListener::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept()?;

			let rt = tokio::runtime::Runtime::new()?;
			rt.block_on(respond_none(&mut transport))?;
			Ok(())
		});

		let _ = ready_rx.recv();

		let stream = NetTcpStream::connect(addr)?;
		let mut client_transport = TcpTransport::from(stream);
		let response = client_transport.emit(message, None).await?;

		// A panicked server thread surfaces as an I/O error rather than a
		// re-panic. The closure itself only fails through `?`.
		server_handle
			.join()
			.map_err(|_| TransportError::IoError(IoError::from(ErrorKind::Other)))??;

		assert_eq!(response, None);
		Ok(())
	}

	/// Under the per-recv-only scheme this read complete after ~6s of dripping
	/// the absolute deadline aborts it at the first slice boundary past
	/// the budget.
	#[cfg(feature = "x509")]
	#[tokio::test]
	async fn handshake_read_deadline_bounds_byte_drip() -> TransportResult<()> {
		let listener = NetTcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;

		let server_handle = thread::spawn(move || -> TransportResult<(TransportResult<Vec<u8>>, Duration)> {
			let (stream, _) = listener.accept()?;
			let mut transport: TcpTransport<NetTcpStream> = TcpTransport::from(stream);
			transport.client_validators = Some(Arc::new(Vec::new()));
			transport.handshake_timeout = Duration::from_millis(250);

			let rt = tokio::runtime::Runtime::new()?;
			let started = Instant::now();
			let result = rt.block_on(transport.read_envelope_bytes());
			Ok((result, started.elapsed()))
		});

		// SEQUENCE header declaring 600 content bytes, sent whole. The body
		// then drips one byte per 10ms (well under any per-recv timeout).
		let mut stream = NetTcpStream::connect(addr)?;
		Write::write_all(&mut stream, &[0x30, 0x82, 0x02, 0x58])?;

		let drip_handle = thread::spawn(move || {
			for _ in 0..600 {
				if Write::write_all(&mut stream, &[0u8]).is_err() {
					break;
				}

				thread::sleep(Duration::from_millis(10));
			}
		});

		// A panicked server thread surfaces as an I/O error rather than a
		// re-panic. The closure itself only fails through `?`.
		let (result, elapsed) = server_handle
			.join()
			.map_err(|_| TransportError::IoError(IoError::from(ErrorKind::Other)))??;

		drip_handle.join().ok();

		assert!(result.is_err());
		assert!(elapsed < Duration::from_secs(5));
		Ok(())
	}

	#[cfg(all(feature = "transport-policy", not(feature = "x509")))]
	#[tokio::test]
	async fn test_tcp_transport_with_gate_policy() -> TransportResult<()> {
		/// First request: ResourceExhausted; second: Ok.
		struct BusyFirstGate {
			first: AtomicBool,
		}

		impl BusyFirstGate {
			fn new() -> Self {
				Self { first: AtomicBool::new(true) }
			}
		}

		impl GatePolicy for BusyFirstGate {
			fn evaluate(&self, _msg: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					TransitStatus::ResourceExhausted
				} else {
					TransitStatus::Ok
				}
			}
		}

		let message = create_v0_tightbeam(None, None);
		let listener = NetTcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;
		let (ready_tx, ready_rx) = mpsc::channel();

		let server_handle = thread::spawn(move || -> TransportResult<()> {
			let server = TcpListener::from_listener(listener);
			let _ = ready_tx.send(());
			let mut transport = server.accept()?.with_collector_gate(BusyFirstGate::new());

			let rt = tokio::runtime::Runtime::new()?;
			rt.block_on(respond_none(&mut transport)).ok();
			rt.block_on(respond_none(&mut transport))?;
			Ok(())
		});

		let _ = ready_rx.recv();

		let stream = NetTcpStream::connect(addr)?;
		let mut transport = TcpTransport::from(stream);

		let result = transport.emit(message.clone(), None).await;
		assert!(matches!(
			result,
			Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
		));

		transport.emit(message.clone(), None).await?;

		// A panicked server thread surfaces as an I/O error rather than a
		// re-panic. The closure itself only fails through `?`.
		server_handle
			.join()
			.map_err(|_| TransportError::IoError(IoError::from(ErrorKind::Other)))??;
		Ok(())
	}
}
