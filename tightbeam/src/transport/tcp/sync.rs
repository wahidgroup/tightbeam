#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::future::Future;
use core::str::FromStr;
use core::time::Duration;

#[cfg(feature = "std")]
use std::io::{Error as IoError, ErrorKind};
#[cfg(feature = "std")]
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::builder::TypeBuilder;
use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::der::Encode;
use crate::policy::GatePolicy;
use crate::policy::TransitStatus;
use crate::transport::error::TransportError;
use crate::transport::error::TransportFailure;
use crate::transport::framing::{FrameHeader, HeaderPrefix, LengthForm};
use crate::transport::handshake::{BoxedServerHandshake, HandshakeProvider};
use crate::transport::policy::RestartPolicy;
use crate::transport::state::{EncryptedProtocolState, IoDeadline};
use crate::transport::tcp::{TcpListenerTrait, TightBeamSocketAddr};
use crate::transport::{
	EncryptedMessageIO, EncryptedProtocol, EndpointConfig, MessageCollector, MessageEmitter, MessageIO, Protocol,
	ResponsePackage, TransportEncryptionConfig, TransportResult,
};
use crate::transport::{EnvelopeBuilder, ProtocolStream};
use crate::utils::time::Clock;
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::state::ServerHandshakeSlot;

// The macro generates the `TcpTransport` struct and its common implementations.
crate::impl_tcp_common!(TcpTransport, ProtocolStream);

#[cfg(feature = "std")]
impl<S: ProtocolStream, P: CryptoProvider> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Re-arms the stream's per-call timeout with the budget `deadline` leaves
	/// at this instant, and fails with `DeadlineExceeded` once it is spent.
	fn arm_deadline(&mut self, deadline: IoDeadline) -> TransportResult<()> {
		let now = self.clock.monotonic();
		let Some(remaining) = deadline.remaining(now)? else {
			return Ok(());
		};

		self.stream.set_timeout(Some(remaining))?;
		Ok(())
	}

	/// Fills `buf` by `deadline`.
	///
	/// Each recv waits at most the budget that is left, so a peer that drips
	/// bytes cannot stretch the read.
	fn fill_within(&mut self, buf: &mut [u8], deadline: IoDeadline) -> TransportResult<()> {
		if deadline.0.is_none() {
			self.stream.read_exact(buf)?;
			return Ok(());
		}

		let mut unread = buf;
		while !unread.is_empty() {
			self.arm_deadline(deadline)?;

			let received = self.stream.read_some(unread)?;
			if received == 0 {
				return Err(TransportError::ConnectionClosed);
			}

			// A count past the buffer breaks the contract of the stream.
			let rest = core::mem::take(&mut unread);
			unread = rest.get_mut(received..).ok_or(TransportError::InvalidState)?;
		}

		Ok(())
	}

	/// Sends all of `buf` by `deadline`.
	///
	/// Each send waits at most the budget that is left, so a peer that reads
	/// slowly cannot stretch the write.
	fn send_within(&mut self, buf: &[u8], deadline: IoDeadline) -> TransportResult<()> {
		if deadline.0.is_none() {
			self.stream.write_all(buf)?;
			return Ok(());
		}

		let mut unsent = buf;
		while !unsent.is_empty() {
			self.arm_deadline(deadline)?;

			let sent = self.stream.write_some(unsent)?;
			if sent == 0 {
				return Err(TransportError::IoError(IoError::from(ErrorKind::WriteZero)));
			}

			// A count past the buffer breaks the contract of the stream.
			unsent = unsent.get(sent..).ok_or(TransportError::InvalidState)?;
		}

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
		// Every stage below re-arms the per-recv timeout with the remaining
		// budget of the phase's read policy, so the handshake deadline applies
		// from the first byte.
		let now = self.clock.monotonic();
		let policy = self.state.phase().read_policy(&self.limits, now);
		let deadline = IoDeadline(policy.deadline());

		let result = (|| -> TransportResult<Vec<u8>> {
			// EOF before the tag means the peer closed between frames. EOF
			// anywhere after it is a truncated frame.
			let mut tag_byte = [0u8; 1];
			let tag_read = self.fill_within(&mut tag_byte, deadline);
			tag_read.map_err(TransportError::at_frame_boundary)?;

			let mut length_first = [0u8; 1];
			let length_read = self.fill_within(&mut length_first, deadline);
			length_read.map_err(TransportError::inside_frame)?;

			let length_octets = match LengthForm::from(length_first[0]) {
				LengthForm::Short(_) => Vec::new(),
				LengthForm::Long(octet_count) => {
					let mut length_octets = vec![0u8; octet_count];
					let octets_read = self.fill_within(&mut length_octets, deadline);
					octets_read.map_err(TransportError::inside_frame)?;

					length_octets
				}
			};

			// The admitted header is the only source of a length to allocate
			// with.
			let prefix = HeaderPrefix { tag: tag_byte[0], length_first: length_first[0] };
			let header = FrameHeader::parse(prefix, length_octets)?.admit(policy.cap())?;
			let content_length = header.content_len();

			let mut content = vec![0u8; content_length];
			let content_read = self.fill_within(&mut content, deadline);
			content_read.map_err(TransportError::inside_frame)?;

			let buffer = header.reconstruct(&content);
			Ok(buffer)
		})();

		#[cfg(feature = "std")]
		if policy.deadline().is_some() {
			// The reset is cleanup, and a failed reset does not change the
			// result the caller acts on.
			let _ = self.stream.set_timeout(None);
		}

		result
	}

	async fn write_envelope_bytes(&mut self, buffer: &[u8]) -> TransportResult<()> {
		let now = self.clock.monotonic();
		let deadline = IoDeadline(now.checked_add(self.limits.operation_timeout));
		let result = self.send_within(buffer, deadline);

		// The reset is cleanup, and a failed reset does not change the result
		// the caller acts on.
		#[cfg(feature = "std")]
		let _ = self.stream.set_timeout(None);

		result
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<S: ProtocolStream, P: CryptoProvider> ServerHandshakeSlot for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	fn server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake> {
		&mut self.server_handshake
	}

	/// Runs `operation` unbounded, because a blocking read holds its thread.
	///
	/// The stream timeouts end each read and write.
	async fn within_budget<T, F>(_budget: Duration, operation: F) -> TransportResult<T>
	where
		F: Future<Output = TransportResult<T>>,
	{
		operation.await
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
			// The reset is cleanup, and a failed reset does not change the
			// result the caller acts on.
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
/// [`DefaultCryptoProvider`]. In an expression, the compiler infers `P` from
/// the calls, so a call names `P` where no other type names it, in one of these
/// shapes:
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
	/// configuration. With `instrument`, the transport names the peer address
	/// it came from.
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
	use std::io::{Read, Write};
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc::{self, RecvTimeoutError};
	use std::thread;
	use std::time::{Duration, Instant};

	use super::*;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::policy::TransitStatus;
	use crate::runtime::{rt, ParkingExecutor};
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

	/// The accepted end and the peer end of one loopback connection.
	fn loopback_pair() -> (NetTcpStream, NetTcpStream) {
		let listener = NetTcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
		let addr = listener.local_addr().expect("a bound listener has an address");

		let peer = NetTcpStream::connect(addr).expect("the loopback listener takes the dial");
		let (stream, _) = listener.accept().expect("the dial arrives");
		(stream, peer)
	}

	/// A server over one end of a loopback connection, beside the silent peer
	/// stream. The server reads its deadlines on `clock`, and its handshake
	/// began at the clock's reading.
	fn handshaking_server(
		limits: TransportLimits,
		clock: &Arc<ManualClock>,
	) -> (TcpTransport<NetTcpStream>, NetTcpStream) {
		let (stream, peer) = loopback_pair();
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

	/// Sends `header` to `peer`, then drips `count` bytes on a thread, one per
	/// `interval`. The drip stops at the first failed write.
	fn drip_after(header: &[u8], mut peer: NetTcpStream, count: usize, interval: Duration) {
		Write::write_all(&mut peer, header).expect("the header reaches the server");

		thread::spawn(move || {
			for _ in 0..count {
				thread::sleep(interval);
				if Write::write_all(&mut peer, &[0u8]).is_err() {
					break;
				}
			}
		});
	}

	/// A peer that drips bytes loses the read when the handshake budget ends.
	#[test]
	fn a_peer_that_drips_bytes_loses_the_read_at_its_budget() -> TransportResult<()> {
		let limits = TransportLimits { handshake_timeout: Duration::from_millis(300), ..TransportLimits::default() };
		let (stream, peer) = loopback_pair();
		let transport = TcpTransport::new(stream, validating_server(limits));
		// The header declares 128 bytes, and 40 of them drip for 4s.
		drip_after(&[0x30, 0x81, 0x80], peer, 40, Duration::from_millis(100));

		let started = Instant::now();
		let outcome = read_within(transport, READ_GUARD);
		let elapsed = started.elapsed();

		assert!(matches!(outcome, Some(Err(_))));
		assert!(elapsed < Duration::from_secs(2));
		Ok(())
	}

	/// A peer that closes between frames ends the read as a closed connection.
	#[test]
	fn a_peer_that_closes_between_frames_ends_the_read_as_closed() -> TransportResult<()> {
		let (stream, peer) = loopback_pair();
		let transport = TcpTransport::new(stream, validating_server(TransportLimits::default()));
		drop(peer);

		let outcome = read_within(transport, READ_GUARD);
		assert!(matches!(outcome, Some(Err(TransportError::ConnectionClosed))));
		Ok(())
	}

	/// Reads up to `chunk` bytes from `peer` on a thread, one read per
	/// `interval`, `count` times. The peer closes once the reads end.
	fn drain_slowly(mut peer: NetTcpStream, chunk: usize, count: usize, interval: Duration) {
		thread::spawn(move || {
			let mut buffer = vec![0u8; chunk];
			for _ in 0..count {
				thread::sleep(interval);
				if Read::read(&mut peer, &mut buffer).is_err() {
					break;
				}
			}
		});
	}

	/// A peer that reads slowly loses the write when the operation budget ends.
	#[test]
	fn a_peer_that_reads_slowly_loses_the_write_at_its_budget() -> TransportResult<()> {
		let limits = TransportLimits { operation_timeout: Duration::from_millis(300), ..TransportLimits::default() };
		let (stream, peer) = loopback_pair();
		let mut transport = TcpTransport::new(stream, validating_server(limits));

		// The peer drains 64 KiB per 50 ms for 3 s, far less than the payload.
		drain_slowly(peer, 64 * 1024, 60, Duration::from_millis(50));

		let payload = vec![0u8; 32 * 1024 * 1024];
		let started = Instant::now();
		let write = transport.write_envelope_bytes(&payload);

		let outcome = rt::block_on(write);
		let elapsed = started.elapsed();
		assert!(outcome.is_err());
		assert!(elapsed < Duration::from_secs(2));
		Ok(())
	}

	/// The blocking budget runs its operation to its end outside a runtime.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_blocking_budget_runs_its_operation_outside_a_runtime() -> TransportResult<()> {
		let operation = async { Ok(7) };
		let bounded = <TcpTransport<NetTcpStream> as ServerHandshakeSlot>::within_budget(Duration::ZERO, operation);

		let outcome = ParkingExecutor::on_current_thread().block_on(bounded)?;
		assert_eq!(outcome, 7);
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
