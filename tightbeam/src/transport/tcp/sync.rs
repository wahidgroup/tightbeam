#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::str::FromStr;

#[cfg(feature = "std")]
use std::io::{Error as IoError, ErrorKind};
#[cfg(feature = "std")]
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::builder::TypeBuilder;
use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::der::Encode;
use crate::transport::error::TransportFailure;
use crate::transport::framing::{FrameHeader, HeaderPrefix, LengthForm};
use crate::transport::handshake::BoxedServerHandshake;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use crate::transport::{
	EncryptedMessageIO, EncryptedProtocol, EndpointConfig, MessageCollector, MessageEmitter, MessageIO, Protocol,
	ResponsePackage, TransportEncryptionConfig, TransportResult,
};
use crate::utils::time::{Clock, MonotonicInstant};
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
	pub use crate::policy::GatePolicy;
	pub use crate::policy::TransitStatus;
	pub use crate::transport::error::TransportError;
	pub use crate::transport::policy::RestartPolicy;
	pub use crate::transport::{EnvelopeBuilder, ProtocolStream};
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
	fn arm_read_deadline(&mut self, deadline: Option<MonotonicInstant>) -> TransportResult<()> {
		let Some(deadline) = deadline else {
			return Ok(());
		};

		let remaining = deadline.saturating_duration_since(self.clock.monotonic());
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
	fn clock(&self) -> &dyn Clock {
		self.clock.as_ref()
	}

	async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
		let handshake_pending = self.is_handshake_pending();

		// Absolute deadline for the whole envelope read. Every stage below
		// re-arms the per-recv timeout with the *remaining* budget. Handshake
		// reads face an unauthenticated peer, so the handshake deadline
		// applies from the first byte onward. A deadline past every reading
		// never arrives, so it is absent.
		#[cfg(feature = "std")]
		let deadline = {
			let (started, allowance) = match self.state.phase().initiated_at() {
				Some(initiated_at) if handshake_pending => (initiated_at, self.limits.handshake_timeout),
				_ if handshake_pending => (self.clock.monotonic(), self.limits.handshake_timeout),
				_ => (self.clock.monotonic(), self.limits.operation_timeout),
			};

			started.checked_add(allowance)
		};

		let result = (|| -> TransportResult<Vec<u8>> {
			#[cfg(feature = "std")]
			self.arm_read_deadline(deadline)?;

			// EOF before the tag is the peer closing between frames. EOF
			// anywhere after it is a truncated frame.
			let mut tag_byte = [0u8; 1];
			self.stream
				.read_exact(&mut tag_byte)
				.map_err(|e| (e.into()).at_frame_boundary())?;

			#[cfg(feature = "std")]
			self.arm_read_deadline(deadline)?;

			let mut length_first = [0u8; 1];
			self.stream
				.read_exact(&mut length_first)
				.map_err(|e| (e.into()).inside_frame())?;

			let length_octets = match LengthForm::from(length_first[0]) {
				LengthForm::Short(_) => Vec::new(),
				LengthForm::Long(octet_count) => {
					let mut length_octets = vec![0u8; octet_count];

					#[cfg(feature = "std")]
					self.arm_read_deadline(deadline)?;

					self.stream
						.read_exact(&mut length_octets)
						.map_err(|e| (e.into()).inside_frame())?;

					length_octets
				}
			};

			// Unauthenticated handshake reads get the tight handshake cap, and
			// established sessions the envelope limits. The admitted header is
			// the only source of a length to allocate with.
			let cap = if handshake_pending {
				self.limits.handshake_wire
			} else {
				self.limits.max_envelope()
			};

			let prefix = HeaderPrefix { tag: tag_byte[0], length_first: length_first[0] };
			let header = FrameHeader::parse(prefix, length_octets)?.admit(cap)?;
			let content_length = header.content_len();

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
							.map_err(|e| (e.into()).inside_frame())?;
						filled = end;
					}
				} else {
					self.stream.read_exact(&mut content).map_err(|e| (e.into()).inside_frame())?;
				}
			}
			#[cfg(not(feature = "std"))]
			self.stream.read_exact(&mut content).map_err(|e| (e.into()).inside_frame())?;

			let buffer = header.reconstruct(&content);
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
		self.stream.set_timeout(Some(self.limits.operation_timeout))?;

		let result = self.stream.write_all(buffer);

		#[cfg(feature = "std")]
		let _ = self.stream.set_timeout(None);

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
		let builder = EnvelopeBuilder::response(response_pkg).with_limits(self.limits);
		let builder = self.apply_wire_mode(builder)?;

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
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		self.ensure_handshake_complete().await?;

		#[cfg(feature = "std")]
		{
			self.stream.set_timeout(Some(self.limits.operation_timeout))?;

			let result = self.perform_emit_cycle(message).await;
			let _ = self.stream.set_timeout(None);
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

// EncryptedMessageIO: operation methods only
impl<S: ProtocolStream> EncryptedMessageIO for TcpTransport<S> where TransportError: From<S::Error> {}

/// TCP server using abstract listener trait. Every accepted transport is
/// built from one [`EndpointConfig`].
pub struct TcpListener<L: TcpListenerTrait, P: CryptoProvider = DefaultCryptoProvider> {
	listener: L,
	/// What every accepted transport is built from.
	config: EndpointConfig<P>,
}

#[cfg(feature = "std")]
impl<P: CryptoProvider + Send + Sync + 'static> Protocol for TcpListener<NetTcpListener, P> {
	type Listener = TcpListener<NetTcpListener, P>;
	type Stream = NetTcpStream;
	type Error = IoError;
	type Transport = TcpTransport<NetTcpStream, P>;
	type Address = TightBeamSocketAddr;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		SocketAddr::from_str("127.0.0.1:0")
			.map(TightBeamSocketAddr)
			.map_err(|e| IoError::new(ErrorKind::InvalidInput, e))
	}

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = NetTcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		let config = EndpointConfig::cleartext();

		Ok((TcpListener { listener, config }, TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		NetTcpStream::connect(addr.0)
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

impl<L: TcpListenerTrait, P: CryptoProvider + Send + Sync + 'static> TcpListener<L, P>
where
	TransportError: From<L::Error>,
	TransportError: From<<L::Stream as ProtocolStream>::Error>,
	L::Stream: ProtocolStream,
{
	/// Serve `listener` in the clear.
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication. See [`EndpointConfig::cleartext`].
	#[cfg(feature = "std")]
	pub fn from_listener(listener: L) -> Self {
		let config = EndpointConfig::cleartext();
		Self { listener, config }
	}

	/// Accept one connection as a transport built from this listener's
	/// configuration.
	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream, P>> {
		let (stream, _) = self.listener.accept()?;
		let transport = TcpTransport::new(stream, self.config.clone());
		Ok(transport)
	}
}

impl<P: CryptoProvider + Send + Sync + 'static> EncryptedProtocol for TcpListener<NetTcpListener, P> {
	type Encryptor = SendCipher;
	type Decryptor = RecvCipher;

	async fn bind_with(
		addr: <Self as Protocol>::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, <Self as Protocol>::Address), <Self as Protocol>::Error> {
		let listener = NetTcpListener::bind(addr.0)?;
		let bound_addr = listener.local_addr()?;
		let config = EndpointConfig::from(config);

		Ok((TcpListener { listener, config }, TightBeamSocketAddr(bound_addr)))
	}
}

#[cfg(test)]
mod tests {
	#![allow(unused_imports)]
	use std::io::Write;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc;
	use std::thread;
	use std::time::{Duration, Instant};

	use super::*;
	use crate::policy::TransitStatus;
	use crate::testing::*;
	use crate::transport::policy::PolicyConfig;
	use crate::transport::state::{DialableEncryption, EncryptionConfig};
	use crate::transport::TransportLimits;
	use crate::utils::time::SystemClock;

	/// A server that validates client certificates, so its reads face an
	/// unauthenticated peer under the handshake ceilings in `limits`.
	fn validating_server(limits: TransportLimits) -> EndpointConfig<DefaultCryptoProvider> {
		let validators = Some(Arc::new(Vec::new()));
		let encryption = EncryptionConfig { client_validators: validators, ..EncryptionConfig::unconfigured() };
		let encryption = DialableEncryption::new(encryption).expect("client validators answer for the peer");

		EndpointConfig::new(encryption, Arc::new(SystemClock)).with_limits(limits)
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
			let deadline = Duration::from_millis(250);
			let limits = TransportLimits { handshake_timeout: deadline, ..TransportLimits::default() };
			let mut transport: TcpTransport<NetTcpStream> = TcpTransport::new(stream, validating_server(limits));

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

	// A header that declares more than the handshake cap is refused on the
	// header alone, before any content is read or allocated (CWE-770).
	#[cfg(feature = "x509")]
	#[tokio::test]
	async fn a_handshake_header_above_the_cap_is_refused() -> TransportResult<()> {
		let listener = NetTcpListener::bind("127.0.0.1:0")?;
		let addr = listener.local_addr()?;

		let server_handle = thread::spawn(move || -> TransportResult<TransportResult<Vec<u8>>> {
			let (stream, _) = listener.accept()?;
			let limits = TransportLimits { handshake_wire: 16, ..TransportLimits::default() };
			let mut transport: TcpTransport<NetTcpStream> = TcpTransport::new(stream, validating_server(limits));

			let rt = tokio::runtime::Runtime::new()?;
			Ok(rt.block_on(transport.read_envelope_bytes()))
		});

		// SEQUENCE header declaring 600 content bytes, with no content sent.
		let mut stream = NetTcpStream::connect(addr)?;
		Write::write_all(&mut stream, &[0x30, 0x82, 0x02, 0x58])?;

		let result = server_handle
			.join()
			.map_err(|_| TransportError::IoError(IoError::from(ErrorKind::Other)))??;
		assert!(matches!(
			result,
			Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))
		));
		Ok(())
	}
}
