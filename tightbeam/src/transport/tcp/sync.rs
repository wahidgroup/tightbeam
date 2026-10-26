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
use crate::transport::handshake::{BoxedServerHandshake, HandshakeProvider};
use crate::transport::state::{EncryptedProtocolState, ReadPolicy};
use crate::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use crate::transport::{
	EncryptedMessageIO, EncryptedProtocol, EndpointConfig, MessageCollector, MessageEmitter, MessageIO, Protocol,
	ResponsePackage, TransportEncryptionConfig, TransportResult,
};
use crate::utils::time::Clock;
use crate::Frame;

use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::policy::GatePolicy;
use crate::policy::TransitStatus;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
use crate::transport::error::TransportError;
use crate::transport::policy::RestartPolicy;
use crate::transport::{EnvelopeBuilder, ProtocolStream};

// The macro generates the `TcpTransport` struct and its common implementations.
crate::impl_tcp_common!(TcpTransport, ProtocolStream);

/// The slice sizes of a deadline-bounded content read. The stream timeout is
/// per-recv (SO_RCVTIMEO), so the read re-checks the absolute budget only
/// between slices, and the worst-case overrun past the deadline is one slice
/// of per-recv resets.
#[cfg(feature = "std")]
const HANDSHAKE_READ_SLICE: usize = 64;
#[cfg(feature = "std")]
const ESTABLISHED_READ_SLICE: usize = 1024;

#[cfg(feature = "std")]
impl<S: ProtocolStream, P: CryptoProvider> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Re-arms the stream's per-recv timeout with the budget `policy` leaves at
	/// this instant, and fails with `DeadlineExceeded` once the budget is
	/// spent.
	fn arm_read_deadline(&mut self, policy: &ReadPolicy) -> TransportResult<()> {
		let now = self.clock.monotonic();
		let Some(remaining) = policy.remaining(now)? else {
			return Ok(());
		};

		self.stream.set_timeout(Some(remaining))?;
		Ok(())
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TcpListener`] shows under `# Provider`.
impl<S: ProtocolStream, P: CryptoProvider + Send + Sync + 'static> MessageIO for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	fn clock(&self) -> &dyn Clock {
		self.clock.as_ref()
	}

	async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
		let handshake_pending = self.state.phase().is_handshake_pending();

		// Every stage below re-arms the per-recv timeout with the remaining
		// budget of the phase's read policy, so the handshake deadline applies
		// from the first byte.
		let now = self.clock.monotonic();
		let policy = self.state.phase().read_policy(&self.limits, now);

		let result = (|| -> TransportResult<Vec<u8>> {
			#[cfg(feature = "std")]
			self.arm_read_deadline(&policy)?;

			// EOF before the tag means the peer closed between frames. EOF
			// anywhere after it is a truncated frame.
			let mut tag_byte = [0u8; 1];
			self.stream
				.read_exact(&mut tag_byte)
				.map_err(|e| (e.into()).at_frame_boundary())?;

			#[cfg(feature = "std")]
			self.arm_read_deadline(&policy)?;

			let mut length_first = [0u8; 1];
			self.stream
				.read_exact(&mut length_first)
				.map_err(|e| (e.into()).inside_frame())?;

			let length_octets = match LengthForm::from(length_first[0]) {
				LengthForm::Short(_) => Vec::new(),
				LengthForm::Long(octet_count) => {
					let mut length_octets = vec![0u8; octet_count];

					#[cfg(feature = "std")]
					self.arm_read_deadline(&policy)?;

					self.stream
						.read_exact(&mut length_octets)
						.map_err(|e| (e.into()).inside_frame())?;

					length_octets
				}
			};

			// The admitted header is the only source of a length to allocate
			// with.
			let prefix = HeaderPrefix { tag: tag_byte[0], length_first: length_first[0] };
			let header = FrameHeader::parse(prefix, length_octets)?.admit(policy.cap())?;
			let content_length = header.content_len();

			// With a deadline, the read runs in slices, so a peer that drips
			// bytes cannot stretch the budget through per-recv timeout resets.
			// Without a deadline, one read suffices.
			let mut content = vec![0u8; content_length];
			#[cfg(feature = "std")]
			{
				if policy.deadline().is_some() {
					let slice_len = if handshake_pending {
						HANDSHAKE_READ_SLICE
					} else {
						ESTABLISHED_READ_SLICE
					};

					for slice in content.chunks_mut(slice_len) {
						self.arm_read_deadline(&policy)?;

						self.stream.read_exact(slice).map_err(|e| (e.into()).inside_frame())?;
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
		if policy.deadline().is_some() {
			// The reset is cleanup. The result in hand is what the caller acts
			// on, and a failed reset does not change it.
			let _ = self.stream.set_timeout(None);
		}

		result
	}

	async fn write_envelope_bytes(&mut self, buffer: &[u8]) -> TransportResult<()> {
		#[cfg(feature = "std")]
		self.stream.set_timeout(Some(self.limits.operation_timeout))?;

		let result = self.stream.write_all(buffer);

		// The reset is cleanup. The result in hand is what the caller acts on,
		// and a failed reset does not change it.
		#[cfg(feature = "std")]
		let _ = self.stream.set_timeout(None);

		result?;
		Ok(())
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TcpListener`] shows under `# Provider`.
impl<S: ProtocolStream, P: HandshakeProvider> MessageCollector for TcpTransport<S, P>
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

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TcpListener`] shows under `# Provider`.
impl<S: ProtocolStream, P: HandshakeProvider> MessageEmitter for TcpTransport<S, P>
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

	/// Runs the protocol-specific send and receive with the handshake and the
	/// timeout.
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		self.ensure_handshake_complete().await?;

		#[cfg(feature = "std")]
		{
			self.stream.set_timeout(Some(self.limits.operation_timeout))?;

			let result = self.perform_emit_cycle(message).await;
			// The reset is cleanup. The result in hand is what the caller acts
			// on, and a failed reset does not change it.
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

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TcpListener`] shows under `# Provider`. It runs the
/// default operation methods.
impl<S: ProtocolStream, P: CryptoProvider + Send + Sync + 'static> EncryptedMessageIO for TcpTransport<S, P> where
	TransportError: From<S::Error>
{
}

/// A TCP server over the abstract listener trait. It builds every accepted
/// transport from one [`EndpointConfig`].
///
/// # Provider
///
/// In a type position, `TcpListener<L>` names the house provider,
/// [`DefaultCryptoProvider`]. In an expression, the compiler infers the
/// provider `P` from the calls, so a call names `P` where no other type names
/// it, in one of these shapes:
///
/// - `TcpListener::<_, DefaultCryptoProvider>`, for a listener that a `server!` block serves, and
/// - `EndpointConfig::<DefaultCryptoProvider>::cleartext()`, for a transport built over a stream.
///
/// # Examples
///
/// ```
/// use std::net::TcpListener as NetTcpListener;
///
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::transport::tcp::sync::TcpListener;
///
/// let bound = NetTcpListener::bind("127.0.0.1:0")?;
/// // No other type of this call names the provider, so the call names it.
/// let _listener = TcpListener::<_, DefaultCryptoProvider>::from_listener_cleartext(bound);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct TcpListener<L: TcpListenerTrait, P: CryptoProvider = DefaultCryptoProvider> {
	listener: L,
	/// The configuration this listener builds every accepted transport from.
	config: EndpointConfig<P>,
}

#[cfg(all(feature = "std", feature = "tcp"))]
impl TcpListenerTrait for NetTcpListener {
	type Stream = NetTcpStream;
	type Error = IoError;

	fn accept(&self) -> Result<(NetTcpStream, SocketAddr), IoError> {
		NetTcpListener::accept(self)
	}
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

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
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
{
	/// Serves `listener` in the clear.
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication. See [`EndpointConfig::cleartext`].
	#[cfg(feature = "std")]
	pub fn from_listener_cleartext(listener: L) -> Self {
		let config = EndpointConfig::cleartext();
		Self { listener, config }
	}

	/// Serves `listener` under the transport encryption `config`, so each
	/// accepted transport runs the server handshake of the provider `P`.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the errors of [`DialableEncryption::new`] on the identity of `config`.
	///
	/// # Examples
	///
	/// ```
	/// use std::net::TcpListener as NetTcpListener;
	///
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::testing::{TestIdentity, TestKey};
	/// use tightbeam::transport::tcp::sync::TcpListener;
	/// use tightbeam::transport::TransportEncryptionConfig;
	///
	/// let identity = TestIdentity::of(&TestKey::insecure_fixed_signing());
	/// let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
	/// let bound = NetTcpListener::bind("127.0.0.1:0")?;
	/// let _listener = TcpListener::from_listener_with(bound, config)?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`DialableEncryption::new`]: crate::transport::state::DialableEncryption::new
	pub fn from_listener_with(listener: L, config: TransportEncryptionConfig<P>) -> TransportResult<Self> {
		let config = EndpointConfig::try_from(config)?;
		Ok(Self { listener, config })
	}

	/// Accepts one connection as a transport built from this listener's
	/// configuration, which names the address it accepted the connection
	/// from.
	pub fn accept(&self) -> TransportResult<TcpTransport<L::Stream, P>> {
		let (stream, peer) = self.listener.accept()?;
		let transport = TcpTransport::new(stream, self.config.clone());

		#[cfg(feature = "instrument")]
		let transport = transport.accepted_from_peer(peer);
		#[cfg(not(feature = "instrument"))]
		let _ = peer;

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
		let listener = Self::from_listener_with(listener, config).map_err(std::io::Error::other)?;

		Ok((listener, TightBeamSocketAddr(bound_addr)))
	}
}

#[cfg(test)]
mod tests {
	#![allow(unused_imports)]
	use std::io::Write;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc::{self, RecvTimeoutError};
	use std::thread;
	use std::time::{Duration, Instant};

	use super::*;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::policy::TransitStatus;
	use crate::testing::*;
	use crate::transport::handshake::PeerAuthentication;
	use crate::transport::policy::PolicyConfig;
	use crate::transport::state::{DialableEncryption, EncryptionConfig};
	use crate::transport::TransportLimits;
	use crate::utils::time::{ManualClock, SystemClock};

	/// How long a case waits for a read on another thread before it reports
	/// the read as blocked.
	const READ_GUARD: Duration = Duration::from_secs(5);

	/// A server that validates client certificates, so its reads face an
	/// unauthenticated peer under the handshake ceilings in `limits`.
	fn validating_server(limits: TransportLimits) -> EndpointConfig<DefaultCryptoProvider> {
		validating_server_on(limits, Arc::new(SystemClock))
	}

	/// The server of [`validating_server`], which reads its deadlines on
	/// `clock`.
	fn validating_server_on(limits: TransportLimits, clock: Arc<dyn Clock>) -> EndpointConfig<DefaultCryptoProvider> {
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
		let peer_authentication = PeerAuthentication::mutual([validator]);

		let encryption = EncryptionConfig { peer_authentication, ..EncryptionConfig::unconfigured() };
		let encryption = DialableEncryption::new(encryption).expect("mutual authentication answers for the peer");
		EndpointConfig::new(encryption, clock).with_limits(limits)
	}

	/// A server over one end of a loopback connection, beside the stream of
	/// its peer, which sends nothing. The server reads its deadlines on
	/// `clock`, and its handshake began at the clock's reading.
	fn handshaking_server(
		limits: TransportLimits,
		clock: &Arc<ManualClock>,
	) -> (TcpTransport<NetTcpStream>, NetTcpStream) {
		let listener = NetTcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
		let addr = listener.local_addr().expect("a bound listener has an address");
		let peer = NetTcpStream::connect(addr).expect("the loopback listener takes the dial");
		let (stream, _) = listener.accept().expect("the dial arrives");

		let endpoint = validating_server_on(limits, Arc::clone(clock) as Arc<dyn Clock>);
		let mut transport: TcpTransport<NetTcpStream> = TcpTransport::new(stream, endpoint);
		let began = transport.state.begin_handshake(clock.monotonic());
		assert!(began, "a provisioned server begins its handshake");

		(transport, peer)
	}

	/// The outcome of one read of `transport` on a thread of its own, or
	/// `None` when the read blocks past `guard`.
	///
	/// # Panics
	///
	/// - The read thread ends with no outcome, which a panic in the read causes.
	fn read_within(mut transport: TcpTransport<NetTcpStream>, guard: Duration) -> Option<TransportResult<Vec<u8>>> {
		let (sender, receiver) = mpsc::channel();
		thread::spawn(move || {
			let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime builds");
			let outcome = runtime.block_on(transport.read_envelope_bytes());
			// The receiver is gone once the guard runs out, and the case then
			// reports the read as blocked.
			let _ = sender.send(outcome);
		});

		match receiver.recv_timeout(guard) {
			Ok(outcome) => Some(outcome),
			Err(RecvTimeoutError::Timeout) => None,
			Err(RecvTimeoutError::Disconnected) => panic!("the read thread ended without an outcome"),
		}
	}

	/// A silent peer ends the read once the handshake budget left on the
	/// connection clock runs out, though the handshake timeout counted from
	/// this read would allow a minute.
	#[test]
	fn a_silent_peer_ends_the_read_with_the_budget_left_on_the_clock() -> TransportResult<()> {
		let clock = Arc::new(ManualClock::default());
		let limits = TransportLimits { handshake_timeout: Duration::from_secs(60), ..TransportLimits::default() };
		let (transport, _peer) = handshaking_server(limits, &clock);
		clock.advance(limits.handshake_timeout - Duration::from_millis(100));

		let outcome = read_within(transport, READ_GUARD);
		let timed_out = matches!(
			&outcome,
			Some(Err(TransportError::IoError(error))) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
		);
		assert!(timed_out);
		Ok(())
	}

	/// A peer that drips bytes cannot stretch the read. A per-recv timeout
	/// alone would let this read complete after the whole drip of about 6s,
	/// and the absolute deadline aborts it at the first slice boundary past
	/// the budget.
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

		// The SEQUENCE header declares 600 content bytes and goes out whole.
		// The body then drips one byte per 10ms, well under any per-recv
		// timeout.
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

		// A panicked server thread surfaces as an I/O error in place of a
		// second panic. The closure itself only fails through `?`.
		let (result, elapsed) = server_handle
			.join()
			.map_err(|_| TransportError::IoError(IoError::from(ErrorKind::Other)))??;

		drip_handle.join().ok();

		assert!(result.is_err());
		assert!(elapsed < Duration::from_secs(5));
		Ok(())
	}

	// The server refuses a header that declares more than the handshake cap
	// on the header alone, before it reads or allocates any content (CWE-770).
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

		// The SEQUENCE header declares 600 content bytes, and no content
		// follows.
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
