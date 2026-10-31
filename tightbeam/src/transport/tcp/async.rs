//! The async TCP transport.
//!
//! [`TcpTransport`] runs over any [`AsyncProtocolStream`], and [`TokioStream`]
//! carries it over a tokio TCP socket. An established transport splits into
//! a [`TransportReader`] and a [`TransportWriter`] for the multiplexed plane.
use std::sync::Arc;

#[cfg(feature = "tokio")]
mod tokio_rt {
	pub use core::task::{Context, Poll, Waker};
	pub use std::io::Error as IoError;
	pub use std::io::ErrorKind;
	pub use std::net::SocketAddr;

	pub use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
	pub use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
	pub use tokio::net::{TcpListener, TcpStream};
	pub use tokio::time::timeout;

	pub use crate::crypto::profiles::DefaultCryptoProvider;
	pub use crate::transport::error::TransportFailure;
	pub use crate::transport::protocols::PersistentConnection;
	pub use crate::transport::protocols::{AsyncByteRead, AsyncByteStream, AsyncByteWrite};
	pub use crate::transport::tcp::TightBeamSocketAddr;
	pub use crate::transport::EncryptedProtocol;
	pub use crate::transport::{AsyncListenerTrait, Protocol};
	pub use crate::transport::{EndpointConfig, TransportEncryptionConfig};
}

#[cfg(feature = "tokio")]
use tokio_rt::*;

use crate::clock::Clock;
use crate::crypto::aead::{RecvCipher, SendCipher};
use crate::crypto::profiles::CryptoProvider;
use crate::der::Decode;
use crate::der::Encode;
use crate::policy::GatePolicy;
use crate::policy::TransitStatus;
use crate::transport::builders::Sealing;
use crate::transport::envelopes::{TransportEnvelope, WireEnvelope};
use crate::transport::error::{ArrivalCause, ArrivalRefusal};
use crate::transport::handshake::HandshakeProvider;
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::policy::RestartPolicy;
use crate::transport::protocols::{AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, SplittableStream};
use crate::transport::state::{ReadPolicy, SettledExchange};
use crate::transport::EncryptedMessageIO;
use crate::transport::{
	CheckedLimits, EnvelopeBuilder, MessageCollector, MessageEmitter, MessageIO, TransportError, TransportResult,
	WireMode,
};
use crate::zeroize::Zeroizing;
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod handshake_imports {
	pub use core::future::Future;
	pub use core::time::Duration;

	pub use crate::transport::state::{HandshakeSlot, ServerHandshakeSlot};
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use handshake_imports::*;

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
mod mux_imports {
	pub use crate::marker::MaybeSend;
	pub use crate::policy::SessionContext;
	pub use crate::transport::handshake::negotiation::MuxSettings;
	pub use crate::transport::handshake::negotiation::TransportOffer;
	pub use crate::transport::state::EncryptedProtocolState;
	pub use crate::x509::Certificate;
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use mux_imports::*;

#[cfg(feature = "instrument")]
mod instrument_imports {
	pub use crate::trace::TraceCollector;
	pub(crate) use crate::transport::handshake::SessionPeer;
	pub(crate) use crate::transport::io::TransportRefusal;
}

#[cfg(feature = "instrument")]
use instrument_imports::*;

/// A tokio TCP stream that carries DER-framed envelopes through the
/// byte-level traits.
#[cfg(feature = "tokio")]
pub struct TokioStream {
	stream: TcpStream,
}

#[cfg(feature = "tokio")]
impl AsyncByteRead for TokioStream {
	type Error = IoError;

	async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		AsyncReadExt::read_exact(&mut self.stream, buf).await.map(|_| ())
	}
}

#[cfg(feature = "tokio")]
impl AsyncByteWrite for TokioStream {
	type Error = IoError;

	async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		AsyncWriteExt::write_all(&mut self.stream, buf).await
	}
}

#[cfg(feature = "tokio")]
impl AsyncByteStream for TokioStream {
	/// Peeks one byte under a no-op waker, so the check returns at once and
	/// leaves every byte in the stream. End of stream or an error reads dead.
	/// A byte that waits, or a peek that would wait, reads alive.
	///
	/// A read borrows the stream mutably, so it runs apart from the peek and
	/// registers its own waker.
	fn is_alive(&self) -> bool {
		let mut byte = [0u8; 1];
		let mut probe = ReadBuf::new(&mut byte);
		let mut context = Context::from_waker(Waker::noop());
		let peeked = self.stream.poll_peek(&mut context, &mut probe);

		match peeked {
			Poll::Ready(Ok(0) | Err(_)) => false,
			Poll::Ready(Ok(_)) | Poll::Pending => true,
		}
	}
}

/// The owned read half of a [`TokioStream`].
#[cfg(feature = "tokio")]
pub struct TokioReadHalf {
	half: OwnedReadHalf,
}

#[cfg(feature = "tokio")]
impl AsyncByteRead for TokioReadHalf {
	type Error = IoError;

	async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
		AsyncReadExt::read_exact(&mut self.half, buf).await.map(|_| ())
	}
}

/// The owned write half of a [`TokioStream`].
#[cfg(feature = "tokio")]
pub struct TokioWriteHalf {
	half: OwnedWriteHalf,
}

#[cfg(feature = "tokio")]
impl AsyncByteWrite for TokioWriteHalf {
	type Error = IoError;

	async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
		AsyncWriteExt::write_all(&mut self.half, buf).await
	}
}

#[cfg(feature = "tokio")]
impl SplittableStream for TokioStream {
	type ReadHalf = TokioReadHalf;
	type WriteHalf = TokioWriteHalf;

	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
		let (read_half, write_half) = self.stream.into_split();
		(TokioReadHalf { half: read_half }, TokioWriteHalf { half: write_half })
	}
}

#[cfg(feature = "tokio")]
impl From<TcpStream> for TokioStream {
	fn from(stream: TcpStream) -> Self {
		Self { stream }
	}
}

/// A tokio TCP listener that builds every accepted transport from one
/// [`EndpointConfig`].
///
/// # Provider
///
/// In a type position, `TokioListener` alone names the house provider,
/// [`DefaultCryptoProvider`]. In an expression, the compiler infers `P` from
/// the calls, so a call names `P` where no other type names it, in one of these
/// shapes:
///
/// - `TokioListener::<DefaultCryptoProvider>::bind_cleartext(addr)` for a listener a `server!` block serves.
/// - `<TokioListener as EncryptedProtocol>::bind_with(addr, config)` for a listener bound through the trait.
/// - `TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity)` for a server configuration.
/// - `EncryptionConfig::<DefaultCryptoProvider>::unconfigured()` for a provisioning built field by field.
#[cfg(feature = "tokio")]
pub struct TokioListener<P: CryptoProvider = DefaultCryptoProvider> {
	listener: TcpListener,
	/// The configuration the listener builds every accepted transport from.
	config: EndpointConfig<P>,
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> TokioListener<P> {
	/// Returns the local address that the listener is bound to.
	///
	/// # Errors
	///
	/// - [`std::io::Error`] -- the socket reports no local address.
	pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
		self.listener.local_addr()
	}

	/// Binds a cleartext listener on `addr`.
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication. See [`EndpointConfig::cleartext`].
	///
	/// # Errors
	///
	/// - [`std::io::Error`] -- the bind fails.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
	/// # let runtime = tokio::runtime::Builder::new_current_thread().enable_io().build()?;
	/// # runtime.block_on(async {
	/// // No other type of this call names the provider, so the call names it.
	/// let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	/// assert!(listener.local_addr()?.ip().is_loopback());
	/// # Ok::<(), std::io::Error>(())
	/// # })?;
	/// # Ok(())
	/// # }
	/// ```
	pub async fn bind_cleartext(addr: impl AsRef<str>) -> Result<Self, IoError> {
		let listener = TcpListener::bind(addr.as_ref()).await?;
		let config = EndpointConfig::cleartext();

		Ok(Self { listener, config })
	}

	/// Accepts one connection as a transport built from this listener's
	/// configuration, and returns it with the address of the peer.
	///
	/// # Errors
	///
	/// - [`std::io::Error`] -- the accept fails.
	pub async fn accept(&self) -> Result<(TcpTransport<TokioStream, P>, SocketAddr), IoError> {
		let (stream, peer_addr) = self.listener.accept().await?;
		let tokio_stream = TokioStream::from(stream);
		let transport = TcpTransport::new(tokio_stream, self.config.clone());

		#[cfg(feature = "instrument")]
		let transport = transport.accepted_from_peer(peer_addr);

		Ok((transport, peer_addr))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> Protocol for TokioListener<P> {
	type Listener = TokioListener<P>;
	type Stream = TokioStream;
	type Error = IoError;
	type Transport = TcpTransport<TokioStream, P>;
	type Address = TightBeamSocketAddr;
	type CryptoProvider = P;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		"127.0.0.1:0".parse().map_err(|e| IoError::new(ErrorKind::InvalidInput, e))
	}

	async fn bind_cleartext(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		let config = EndpointConfig::cleartext();
		Ok((Self { listener, config }, TightBeamSocketAddr(bound_addr)))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let stream = TcpStream::connect(addr.0).await?;
		let tokio_stream = TokioStream::from(stream);
		Ok(tokio_stream)
	}

	fn create_transport(stream: Self::Stream, config: EndpointConfig<P>) -> Self::Transport {
		TcpTransport::new(stream, config)
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> EncryptedProtocol for TokioListener<P> {
	type Encryptor = SendCipher;
	type Decryptor = RecvCipher;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		let config = EndpointConfig::try_from(config).map_err(std::io::Error::other)?;

		Ok((Self { listener, config }, TightBeamSocketAddr(bound_addr)))
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`. It takes the
/// default of every `EncryptedMessageIO` method.
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync + 'static> EncryptedMessageIO for TcpTransport<S, P> where
	TransportError: From<S::Error>
{
}

impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Reports whether the underlying stream appears connected.
	pub fn is_alive(&self) -> bool {
		AsyncProtocolStream::is_alive(&self.stream)
	}

	/// Whether a pool may lease this transport again: its stream is alive, its
	/// session may write, and no exchange is in flight.
	///
	/// A protocol over this transport implements
	/// [`PersistentConnection::is_connected`] through this hook, because the
	/// stream and the session stay private.
	pub fn is_leasable(&self) -> bool {
		self.is_alive() && self.state.is_leasable()
	}
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
mod mux {
	pub use crate::transport::multiplex::{
		IntoMuxOffer, MuxCapable, MuxConnector, MuxRekeyContext, MuxRole, MuxTransport,
	};

	pub use crate::transport::multiplex::{GatedHalves, MuxAcceptor};
	pub(crate) use crate::transport::multiplex::{ACCEPTOR_ROLE, CONNECTOR_ROLE};
	pub(crate) use crate::transport::state::CollectStep;
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
use mux::*;

/// Only async transports advertise multiplexing. The mux plane needs split
/// halves and spawned drivers, so an advertisement anywhere else would
/// negotiate a capability that the endpoint cannot honor.
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Sets the local mux advertisement, which the handshake transcript binds.
	///
	/// A `None` offer advertises nothing.
	pub fn with_mux_offer(mut self, offer: impl IntoMuxOffer) -> Self {
		self.state.offer_mux(offer.into_mux_offer());
		self
	}
}

/// The multiplexed plane that [`TcpTransport::into_mux`] assembles.
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
pub type SplitMuxTransport<S> = MuxTransport<
	TransportReader<<S as SplittableStream>::ReadHalf>,
	TransportWriter<<S as SplittableStream>::WriteHalf>,
>;

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`.
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl<S, P> TcpTransport<S, P>
where
	S: SplittableStream,
	P: HandshakeProvider,
	TransportError: From<S::Error>,
{
	/// Consumes a handshaken transport into its multiplexed plane.
	///
	/// - The negotiated settings drive the assembly.
	/// - The in-band rekey context attaches when the session carries a dual-signed receipt.
	/// - The halves split for the mux drivers.
	///
	/// # Role
	///
	/// The caller passes the role it assembles. Unlike the [`MuxConnector`] and
	/// [`MuxAcceptor`] pool traits, this method serves either role without the
	/// policy plane, so native and wasm WebSocket transports assemble the same
	/// way.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the peer did not negotiate
	///   multiplexing, or the handshake has not completed.
	/// - [`TransportError`] -- the errors of [`Self::into_split`], and of a
	///   rekey context that fails to detach.
	pub fn into_mux(mut self, role: MuxRole) -> TransportResult<SplitMuxTransport<S>> {
		let Some(settings) = self.negotiated_mux() else {
			return Err(TransportError::InvalidState);
		};

		let rekey = MuxRekeyContext::detach(&mut self, role)?;
		let (reader, writer) = self.into_split()?;

		let mux = MuxTransport::assemble(reader, writer, role, settings, rekey);
		Ok(mux)
	}
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> MuxCapable for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	fn with_mux_offer(self, offer: Option<Arc<TransportOffer>>) -> Self {
		self.with_mux_offer(offer)
	}

	fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.negotiated_mux()
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`.
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl<S, P> MuxConnector for TcpTransport<S, P>
where
	S: SplittableStream,
	P: HandshakeProvider,
	S::ReadHalf: MaybeSend + 'static,
	S::WriteHalf: MaybeSend + 'static,
	TransportError: From<S::Error>,
{
	type EnvelopeReader = TransportReader<S::ReadHalf>;
	type EnvelopeWriter = TransportWriter<S::WriteHalf>;

	async fn complete_client_handshake(&mut self) -> TransportResult<()> {
		self.ensure_handshake_complete().await
	}

	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		MuxRekeyContext::detach(self, CONNECTOR_ROLE)
	}

	fn handshake_peer_certificate(&self) -> Option<Arc<Certificate>> {
		self.session_state().peer_certificate_arc()
	}

	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)> {
		self.into_split()
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`.
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
impl<S, P> MuxAcceptor for TcpTransport<S, P>
where
	S: SplittableStream,
	P: HandshakeProvider,
	S::ReadHalf: MaybeSend + 'static,
	S::WriteHalf: MaybeSend + 'static,
	TransportError: From<S::Error>,
{
	type EnvelopeReader = TransportReader<S::ReadHalf>;
	type EnvelopeWriter = TransportWriter<S::WriteHalf>;

	/// A provisioned endpoint serves handshake rounds until its session is
	/// encrypted, then returns the settings it negotiated. An endpoint without
	/// encryption provisioning returns `Ok(None)` with no I/O.
	async fn negotiate_mux(&mut self) -> TransportResult<Option<MuxSettings>> {
		if !self.encryption().is_provisioned() {
			return Ok(None);
		}

		while !self.state.phase().requires_encryption() {
			match self.collect_step().await? {
				CollectStep::Handshake(request) => {
					self.perform_server_handshake(request).await?;
				}
				CollectStep::Envelope(_) => return Err(TransportError::InvalidState),
			}
		}

		Ok(self.negotiated_mux())
	}

	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		MuxRekeyContext::detach(self, ACCEPTOR_ROLE)
	}

	fn session_context(&self) -> SessionContext {
		SessionContext::capture(self)
	}

	fn into_gated_halves(mut self) -> TransportResult<GatedHalves<Self>> {
		let gate = Box::new(core::mem::take(&mut self.collector_gate));
		let halves = self.into_split()?;
		Ok((gate, halves))
	}

	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)> {
		self.into_split()
	}
}

/// The wire mode a split receive half reads, with the cipher an encrypted
/// session needs.
enum SplitRecv {
	/// The endpoint names cleartext, so envelopes carry NO confidentiality,
	/// integrity, replay, or deletion protection.
	Cleartext,
	/// The receive-direction cipher of the established session.
	Encrypted(RecvCipher),
}

impl SplitRecv {
	/// The wire mode this half reads.
	const fn wire_mode(&self) -> WireMode {
		match self {
			Self::Cleartext => WireMode::Cleartext,
			Self::Encrypted(_) => WireMode::Encrypted,
		}
	}

	/// The receive cipher of an encrypted half, under which the half admits an
	/// arrival, or `None` for a cleartext half. The half lends it exclusively,
	/// so one open runs on the key at a time.
	const fn cipher(&mut self) -> Option<&mut RecvCipher> {
		match self {
			Self::Cleartext => None,
			Self::Encrypted(recv_key) => Some(recv_key),
		}
	}
}

/// The wire mode a split send half writes, with the cipher an encrypted
/// session needs.
enum SplitSend {
	/// The endpoint names cleartext.
	Cleartext,
	/// The send-direction cipher of the established session.
	Encrypted(SendCipher),
}

impl SplitSend {
	/// The sealing this half writes each envelope under.
	const fn sealing(&self) -> Sealing<'_> {
		match self {
			Self::Cleartext => Sealing::Cleartext,
			Self::Encrypted(send_key) => Sealing::Encrypted(send_key),
		}
	}
}

#[cfg(feature = "instrument")]
impl SplitSend {
	/// The send cipher of an encrypted half, or `None` for a cleartext half.
	const fn cipher(&self) -> Option<&SendCipher> {
		match self {
			Self::Cleartext => None,
			Self::Encrypted(send_key) => Some(send_key),
		}
	}
}

/// The exclusive receive half of a split transport.
///
/// It carries the wire mode of its session at the split. An encrypted half
/// owns the receive-direction cipher, so decryption needs no locks and can run
/// concurrently with a [`TransportWriter`] on the same connection.
pub struct TransportReader<R>
where
	R: AsyncReadStream,
{
	stream: R,
	mode: SplitRecv,
	limits: CheckedLimits,
	/// The connection clock carried across the split, which the read deadline
	/// counts from.
	clock: Arc<dyn Clock>,
	/// The connection collector carried across the split. See
	/// [`EnvelopeSource::trace`].
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
	/// The peer of the session this half split from, which the record of a
	/// refused envelope names.
	#[cfg(feature = "instrument")]
	peer: Option<Arc<SessionPeer>>,
}

impl<R> TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Overrides the receive-direction renewal threshold that
	/// `remaining_records` counts down ([RFC 9846 § 5.5][rfc9846-5.5]).
	///
	/// The value sets trigger policy only. Decryption refuses records at the
	/// AES-GCM volume bounds whatever this value is. The limit applies to an
	/// encrypted half alone, because a cleartext half holds no key to renew.
	///
	/// [rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		if let SplitRecv::Encrypted(cipher) = self.mode {
			self.mode = SplitRecv::Encrypted(cipher.with_rekey_limit(limit));
		}

		self
	}

	/// Reads the bytes of one envelope in the wire mode this half took from the
	/// split, under the operation deadline.
	async fn read_wire(&mut self) -> TransportResult<Vec<u8>> {
		let cap = self.limits.envelope_ceiling(self.mode.wire_mode());

		// A split half belongs to an established session, so the read runs
		// under the policy of one.
		let now = self.clock.monotonic();
		let policy = ReadPolicy::established(cap, &self.limits, now);

		#[cfg(all(feature = "tokio", feature = "std"))]
		let wire_bytes = match policy.remaining(now)? {
			Some(budget) => timeout(budget, self.stream.read_frame(policy.cap())).await??,
			None => self.stream.read_frame(policy.cap()).await?,
		};
		#[cfg(not(all(feature = "tokio", feature = "std")))]
		let wire_bytes = self.stream.read_frame(policy.cap()).await?;

		Ok(wire_bytes)
	}

	/// Reads one envelope in the wire mode this half took from the split,
	/// under the operation deadline.
	async fn read_in_mode(&mut self) -> Result<TransportEnvelope, ArrivalRefusal> {
		// A record opens in the buffer it arrived in, so the buffer wipes when
		// it drops. The outer tag names the mode, so the half refuses a mode
		// other than its own before any decode.
		let read = self.read_wire().await;
		let mut wire_bytes = Zeroizing::new(read.map_err(|error| self.refuse(error))?);
		let arriving =
			WireEnvelope::admit(&mut wire_bytes).map_err(|error| self.refuse(TransportError::DerError(error)))?;

		let contents = arriving.admit_under(self.mode.cipher()).map_err(|cause| self.refuse(cause))?;
		let envelope = TransportEnvelope::from_der(contents);
		envelope.map_err(|error| self.refuse(TransportError::DerError(error)))
	}

	/// The refusal of an arrival on this half for `cause`, with the peer of the
	/// session that the half split from.
	fn refuse(&self, cause: impl Into<ArrivalCause>) -> ArrivalRefusal {
		#[cfg(feature = "instrument")]
		let peer = self.peer.as_ref();
		#[cfg(not(feature = "instrument"))]
		let peer = None;

		ArrivalRefusal::new(cause, peer)
	}
}

impl<R> EnvelopeSource for TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Reads one envelope in the wire mode this half took from the split.
	///
	/// The operation deadline bounds the read in either mode, so a peer that
	/// stops mid-frame cannot pin the reader task (CWE-400). A traced half
	/// records a refused envelope as [`TRANSPORT_ENVELOPE_REFUSED`].
	///
	/// [`TRANSPORT_ENVELOPE_REFUSED`]: crate::instrumentation::events::TRANSPORT_ENVELOPE_REFUSED
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let read = self.read_in_mode().await;
		#[cfg(feature = "instrument")]
		let read = TransportRefusal::audit_read(read, self.trace.as_ref());
		Ok(read?)
	}

	/// Returns the number of records that the half can read before the receive
	/// cipher demands a rekey. A cleartext half never demands one, so it
	/// reports `u64::MAX`.
	fn remaining_records(&self) -> u64 {
		match &self.mode {
			SplitRecv::Cleartext => u64::MAX,
			SplitRecv::Encrypted(recv_key) => recv_key.remaining_records(),
		}
	}

	/// Swaps in the new epoch's receive cipher.
	///
	/// The fresh counter resets the sequence discipline, because counter
	/// nonces restart only with a fresh key (NIST SP 800-38D § 8.2.1). The
	/// configured renewal threshold carries over, so a tightened rekey cadence
	/// survives every epoch. A cleartext half holds no keys, so it refuses the
	/// install.
	fn install_recv_cipher(&mut self, cipher: RecvCipher) -> TransportResult<()> {
		let SplitRecv::Encrypted(current) = &self.mode else {
			return Err(TransportError::MissingEncryption);
		};

		let renewed = cipher.with_rekey_limit(current.rekey_limit());
		self.mode = SplitRecv::Encrypted(renewed);
		Ok(())
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

/// The exclusive send half of a split transport.
///
/// It carries the wire mode of its session at the split. An encrypted half
/// owns the send-direction cipher and its record sequence, so encryption needs
/// no locks and can run concurrently with a [`TransportReader`] on the same
/// connection.
pub struct TransportWriter<W>
where
	W: AsyncWriteStream,
{
	stream: W,
	mode: SplitSend,
	/// Every ceiling carried across the split, as on the unsplit path. A peer
	/// that never drains its receive buffer cannot pin the writer task forever
	/// (CWE-400).
	limits: CheckedLimits,
	/// The connection clock carried across the split. See
	/// [`EnvelopeSink::clock`].
	#[cfg(host_clock)]
	clock: Arc<dyn Clock>,
	/// The connection collector carried across the split. See
	/// [`EnvelopeSink::trace`].
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

impl<W> TransportWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	/// Overrides the send cipher's rekey record limit
	/// ([RFC 9846 § 5.5][rfc9846-5.5]).
	///
	/// The limit applies to an encrypted half alone, because a cleartext half
	/// holds no key to renew.
	///
	/// [rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		if let SplitSend::Encrypted(cipher) = self.mode {
			self.mode = SplitSend::Encrypted(cipher.with_rekey_limit(limit));
		}

		self
	}
}

impl<W> EnvelopeSink for TransportWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	/// Writes one envelope in the wire mode this half took from the split,
	/// under the operation deadline in either mode.
	///
	/// A traced half records an envelope that its send cipher refuses at the
	/// record limit as [`TRANSPORT_REKEY_REQUIRED`].
	///
	/// [`TRANSPORT_REKEY_REQUIRED`]: crate::instrumentation::events::TRANSPORT_REKEY_REQUIRED
	async fn write_envelope(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		let builder = EnvelopeBuilder::transport(envelope).with_limits(self.limits);
		let builder = builder.with_sealing(self.mode.sealing());

		let sealed = builder.finish();

		#[cfg(feature = "instrument")]
		let sealed = TransportRefusal::audit_send(sealed, self.trace.as_ref(), self.mode.cipher());

		let wire_envelope = sealed?;
		let wire_bytes = wire_envelope.to_der()?;

		#[cfg(all(feature = "tokio", feature = "std"))]
		timeout(self.limits.operation_timeout, self.stream.write_frame(&wire_bytes)).await??;

		#[cfg(not(all(feature = "tokio", feature = "std")))]
		self.stream.write_frame(&wire_bytes).await?;

		Ok(())
	}

	/// Returns the number of records that the half can write before the send
	/// cipher demands a rekey. A cleartext half never demands one, so it
	/// reports `u64::MAX`.
	fn remaining_records(&self) -> u64 {
		match &self.mode {
			SplitSend::Cleartext => u64::MAX,
			SplitSend::Encrypted(send_key) => send_key.remaining_records(),
		}
	}

	/// Swaps in the new epoch's send cipher.
	///
	/// The fresh counter resets the sequence discipline, because counter
	/// nonces restart only with a fresh key (NIST SP 800-38D § 8.2.1). The
	/// fresh cipher takes this half's envelope ceiling and keeps the current
	/// record limit, so a tightened cadence survives every epoch. A cleartext
	/// half holds no keys, so it refuses the install.
	fn install_send_cipher(&mut self, cipher: SendCipher) -> TransportResult<()> {
		let SplitSend::Encrypted(current) = &self.mode else {
			return Err(TransportError::MissingEncryption);
		};

		let renewed = cipher
			.with_envelope_ceiling(self.limits.encrypted_envelope)
			.with_rekey_limit(current.rekey_limit());
		self.mode = SplitSend::Encrypted(renewed);
		Ok(())
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}

	#[cfg(host_clock)]
	fn clock(&self) -> Arc<dyn Clock> {
		Arc::clone(&self.clock)
	}
}

/// The read and write halves that [`TcpTransport::into_split`] produces.
pub type SplitTransport<S> = (
	TransportReader<<S as SplittableStream>::ReadHalf>,
	TransportWriter<<S as SplittableStream>::WriteHalf>,
);

impl<S, P> TcpTransport<S, P>
where
	S: SplittableStream,
	P: CryptoProvider + Send + Sync + 'static,
	TransportError: From<S::Error>,
{
	/// Splits the transport into exclusive read and write halves in the wire
	/// mode its session holds.
	///
	/// - An established session moves its receive key into the
	///   [`TransportReader`] and its send key into the [`TransportWriter`].
	///   Directional keys make this a transfer of ownership, so the halves
	///   share no mutable cryptographic state.
	/// - A transport that names cleartext splits into cleartext halves, which
	///   carry NO confidentiality, integrity, replay, or deletion protection.
	///
	/// The operation deadline carries onto both halves and bounds every read
	/// and write, as on the unsplit path. A peer that goes idle, or sends a
	/// byte at a time, ends the call with
	/// [`TransportFailure::DeadlineExceeded`], so the driver task stays free.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the session is provisioned for
	///   encryption and its handshake has not completed.
	/// - [`TransportError::ConnectionFailed`] -- an exchange broke the session.
	pub fn into_split(mut self) -> TransportResult<SplitTransport<S>> {
		// The split takes the session apart, so the reader keeps its peer for
		// the record of a refused envelope.
		#[cfg(feature = "instrument")]
		let peer = self.state.session_peer().cloned();

		let (recv_mode, send_mode) = match self.state.take_split_keys()? {
			Some((send_key, recv_key)) => (SplitRecv::Encrypted(recv_key), SplitSend::Encrypted(send_key)),
			None => (SplitRecv::Cleartext, SplitSend::Cleartext),
		};

		let limits = self.limits;
		let clock = self.clock;

		#[cfg(feature = "instrument")]
		let trace = self.trace.as_ref().map(TraceCollector::share);

		let (read_half, write_half) = self.stream.into_split();
		let reader = TransportReader {
			stream: read_half,
			mode: recv_mode,
			limits,
			clock: Arc::clone(&clock),
			#[cfg(feature = "instrument")]
			trace: trace.as_ref().map(TraceCollector::share),
			#[cfg(feature = "instrument")]
			peer,
		};
		let writer = TransportWriter {
			stream: write_half,
			mode: send_mode,
			limits,
			#[cfg(host_clock)]
			clock,
			#[cfg(feature = "instrument")]
			trace,
		};
		Ok((reader, writer))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> AsyncListenerTrait for TokioListener<P> {
	/// Delegates to the inherent [`TokioListener::accept`], so both entry
	/// points install the full listener state.
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		{
			let (transport, peer_addr) = TokioListener::<P>::accept(self).await?;
			Ok((transport, TightBeamSocketAddr(peer_addr)))
		}
	}
}

// The macro generates the `TcpTransport` struct and its common
// implementations.
crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`.
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync + 'static> MessageIO for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	fn clock(&self) -> &dyn Clock {
		self.clock.as_ref()
	}

	async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
		// The phase decides the ceiling and the deadline of this read, as
		// `SessionPhase::read_policy` describes.
		let now = self.clock.monotonic();
		let policy = self.state.phase().read_policy(&self.limits, now);

		#[cfg(feature = "tokio")]
		{
			let buffer = match policy.remaining(now)? {
				Some(budget) => timeout(budget, self.stream.read_frame(policy.cap())).await??,
				None => self.stream.read_frame(policy.cap()).await?,
			};

			Ok(buffer)
		}

		#[cfg(not(feature = "tokio"))]
		{
			let buffer = self.stream.read_frame(policy.cap()).await?;
			Ok(buffer)
		}
	}

	async fn write_envelope_bytes(&mut self, buffer: &[u8]) -> TransportResult<()> {
		#[cfg(feature = "tokio")]
		timeout(self.limits.operation_timeout, self.stream.write_frame(buffer)).await??;

		#[cfg(not(feature = "tokio"))]
		self.stream.write_frame(buffer).await?;

		Ok(())
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<S: AsyncProtocolStream, P: CryptoProvider> ServerHandshakeSlot for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	fn handshake_slot(&mut self) -> &mut HandshakeSlot {
		self.state.handshake_slot()
	}

	/// Bounds `operation` with the tokio timer, as the reads and writes are.
	///
	/// A thread with no runtime has no timer, so the call fails closed.
	/// A build without `tokio` runs `operation` unbounded.
	async fn within_budget<T, F>(budget: Duration, operation: F) -> TransportResult<T>
	where
		F: Future<Output = TransportResult<T>>,
	{
		#[cfg(feature = "tokio")]
		{
			if tokio::runtime::Handle::try_current().is_err() {
				return Err(TransportError::OperationFailed(TransportFailure::FailedPrecondition));
			}

			let bounded = timeout(budget, operation).await;
			bounded.unwrap_or_else(|elapsed| Err(elapsed.into()))
		}

		#[cfg(not(feature = "tokio"))]
		{
			let _unbounded = budget;
			operation.await
		}
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`.
impl<S: AsyncProtocolStream, P: HandshakeProvider> MessageCollector for TcpTransport<S, P>
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
		self.send_response_with_encryption(status, message).await
	}
}

/// This impl covers every provider `P`, so a call names `P` where no other
/// type names it, as [`TokioListener`] shows under `# Provider`.
impl<S: AsyncProtocolStream, P: HandshakeProvider> MessageEmitter for TcpTransport<S, P>
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

	/// Completes the handshake, then runs one emit cycle under the operation
	/// deadline.
	///
	/// The handshake and the cycle run as one settled exchange of the
	/// session, so a broken exchange fails the session, and a dropped one
	/// leaves the mark of the exchange in flight set.
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		self.settled_exchange(async move |transport: &mut Self| {
			transport.ensure_handshake_complete().await?;

			#[cfg(feature = "tokio")]
			{
				let budget = transport.limits.operation_timeout;
				match timeout(budget, transport.perform_emit_cycle(message)).await {
					Ok(result) => result,
					Err(_) => Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded)),
				}
			}

			#[cfg(not(feature = "tokio"))]
			{
				transport.perform_emit_cycle(message).await
			}
		})
		.await
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> PersistentConnection for TokioListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_leasable()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// Shutdown is best-effort. The tokio `TcpStream` relies on `Drop`, so
		// the connection closes fully when the transport drops.
	}
}

#[cfg(all(test, feature = "tokio"))]
mod tests {

	use core::time::Duration;
	use std::sync::Arc;

	#[cfg(feature = "transport-hpke")]
	use std::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::clock::{ManualClock, SystemClock};
	use crate::crypto::x509::store::CertificateTrust;
	use crate::policy::TransitStatus;
	use crate::runtime::ParkingExecutor;
	use crate::testing::fixtures::{TestLoopback, TestStore};
	use crate::testing::*;
	use crate::transport::handshake::{HandshakeError, HandshakeProtocolKind};
	use crate::transport::io::EncryptedMessageIO;
	use crate::transport::state::{DialableEncryption, EncryptionConfig};
	use crate::transport::{MessageCollector, MessageEmitter, TransportEncryptionConfig, TransportLimits};

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::crypto::aead::SessionKeys;
	#[cfg(feature = "transport-hpke")]
	use crate::crypto::key::Secp256k1KeyProvider;
	#[cfg(feature = "transport-hpke")]
	use crate::crypto::sign::SigningIdentity;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::crypto::x509::error::CertificateValidationError::{CertificateNotTrusted, Expired};
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::crypto::x509::policy::{CertificateValidation, DirectTrustValidator};
	#[cfg(feature = "transport-cms")]
	use crate::crypto::x509::store::TrustBuilder;
	#[cfg(feature = "instrument")]
	use crate::instrumentation::events;
	#[cfg(feature = "instrument")]
	use crate::testing::fixtures::TestTrace;
	#[cfg(feature = "transport-hpke")]
	use crate::transport::client::ClientBuilder;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::transport::handshake::tests::create_test_signed_data;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::transport::handshake::HandshakeMessage;
	#[cfg(feature = "transport-hpke")]
	use crate::transport::handshake::PeerAuthentication;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::transport::handshake::ValidatorChain;
	#[cfg(feature = "instrument")]
	use crate::transport::state::{SessionPhase, SessionState};

	/// Serves one single-flight request. It applies `reply` to an accepted
	/// frame and answers with the gate's status.
	async fn respond_with<T, F>(transport: &mut T, reply: F) -> TransportResult<()>
	where
		T: MessageCollector + Send,
		F: Fn(Frame) -> Option<Frame>,
	{
		let (request, status) = transport.collect_message().await?;
		let frame = Arc::try_unwrap(request).unwrap_or_else(|shared| (*shared).clone());
		let message = match status {
			TransitStatus::Ok => reply(frame),
			_ => None,
		};

		transport.send_response(status, message).await
	}

	/// A reply that records each frame it serves and answers with `answer`,
	/// beside the receiver of the recorded frames.
	fn recording(
		answer: Option<Frame>,
	) -> (
		impl Fn(Frame) -> Option<Frame> + Send + 'static,
		tokio::sync::mpsc::Receiver<Frame>,
	) {
		let (recorded, received) = tokio::sync::mpsc::channel(2);
		let reply = move |frame: Frame| {
			// The receiver lives for the whole test, so a refused send shows
			// as the missing frame the assertion reads.
			let _ = recorded.try_send(frame);
			answer.clone()
		};

		(reply, received)
	}

	#[cfg(feature = "transport-hpke")]
	use crate::policy::SessionContext;
	#[cfg(feature = "transport-hpke")]
	use crate::transport::policy::CollectorGateConfig;

	mod cipher_install {
		use core::time::Duration;

		use super::super::*;
		use crate::clock::{ManualClock, SystemClock};
		use crate::constants::{DEFAULT_MAX_ENCRYPTED_ENVELOPE, DEFAULT_REKEY_RECORD_LIMIT};
		use crate::crypto::aead::{RecordDirection, RuntimeAead};
		use crate::testing::{TestFrame, TestKey, TestResult};
		use crate::transport::TransportLimits;
		use crate::TightBeamError;

		const PLAINTEXT: &[u8] = b"epoch boundary traffic";

		/// A frame stream that discards writes and yields empty frames.
		///
		/// The cases read the cipher state of a half and send no byte that a
		/// peer reads, so the double stands in for a connection.
		struct NullStream;

		impl AsyncReadStream for NullStream {
			type Error = IoError;

			async fn read_frame(&mut self, _cap: usize) -> Result<Vec<u8>, Self::Error> {
				Ok(Vec::new())
			}
		}

		impl AsyncWriteStream for NullStream {
			type Error = IoError;

			async fn write_frame(&mut self, _buffer: &[u8]) -> Result<(), Self::Error> {
				Ok(())
			}
		}

		fn test_runtime() -> RuntimeAead {
			TestKey::insecure_directional_keys().client_to_server
		}

		/// A client-to-server send cipher of epoch 0.
		fn test_sender() -> SendCipher {
			SendCipher::new(test_runtime(), 0, RecordDirection::ClientToServer)
		}

		/// A client-to-server receive cipher of epoch 0.
		fn test_receiver() -> RecvCipher {
			RecvCipher::new(test_runtime(), 0, RecordDirection::ClientToServer)
		}

		/// A send half in `mode` over `stream` under `limits`, which reads its
		/// deadlines on `clock`.
		fn writer_over<S: AsyncWriteStream>(
			stream: S,
			mode: SplitSend,
			limits: CheckedLimits,
			clock: Arc<dyn Clock>,
		) -> TransportWriter<S> {
			TransportWriter {
				stream,
				mode,
				limits,
				clock,
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		/// A receive half in `mode` over `stream` under `limits`, which reads
		/// its deadlines on `clock`.
		fn reader_over<S: AsyncReadStream>(
			stream: S,
			mode: SplitRecv,
			limits: CheckedLimits,
			clock: Arc<dyn Clock>,
		) -> TransportReader<S> {
			TransportReader {
				stream,
				mode,
				limits,
				clock,
				#[cfg(feature = "instrument")]
				trace: None,
				#[cfg(feature = "instrument")]
				peer: None,
			}
		}

		fn writer(mode: SplitSend) -> TransportWriter<NullStream> {
			writer_over(NullStream, mode, CheckedLimits::default(), Arc::new(SystemClock))
		}

		fn reader(mode: SplitRecv) -> TransportReader<NullStream> {
			reader_over(NullStream, mode, CheckedLimits::default(), Arc::new(SystemClock))
		}

		/// A write half hands out the clock of the connection it split from, so
		/// a plane assembled over it reads the endpoint's clock.
		#[test]
		fn a_split_writer_hands_out_the_connection_clock() {
			let clock = Arc::new(ManualClock::default());
			clock.advance(Duration::from_secs(3600));
			let writer = writer_over(
				NullStream,
				SplitSend::Cleartext,
				CheckedLimits::default(),
				Arc::clone(&clock) as Arc<dyn Clock>,
			);

			let handed = EnvelopeSink::clock(&writer);
			assert_eq!(handed.monotonic(), clock.monotonic());
		}

		/// The limits at twice the default encrypted-envelope ceiling, where a
		/// key admits half the default record volume.
		fn doubled_ceiling() -> CheckedLimits {
			let encrypted_envelope = 2 * DEFAULT_MAX_ENCRYPTED_ENVELOPE;
			let limits = TransportLimits { encrypted_envelope, ..TransportLimits::default() };
			limits.checked().expect("twice the default ceiling agrees with the defaults")
		}

		/// The send cipher of an encrypted half. A cleartext half has none, so
		/// a test that reaches for one names the wrong fixture.
		fn send_key(writer: &TransportWriter<NullStream>) -> &SendCipher {
			match &writer.mode {
				SplitSend::Encrypted(send_key) => send_key,
				SplitSend::Cleartext => panic!("the fixture must be an encrypted half"),
			}
		}

		/// The receive cipher of an encrypted half.
		fn recv_key(reader: &mut TransportReader<NullStream>) -> &mut RecvCipher {
			match &mut reader.mode {
				SplitRecv::Encrypted(recv_key) => recv_key,
				SplitRecv::Cleartext => panic!("the fixture must be an encrypted half"),
			}
		}

		/// A send install brings a fresh key and a reset counter, and the
		/// configured record limit survives it.
		#[test]
		fn a_writer_install_swaps_the_cipher_and_keeps_its_limit() -> TestResult {
			let send_cipher = test_sender().with_rekey_limit(1);
			let mut writer = writer(SplitSend::Encrypted(send_cipher));
			send_key(&writer).encrypt_next(PLAINTEXT)?;

			let spent = writer.remaining_records();

			writer.install_send_cipher(test_sender())?;

			assert_eq!((spent, writer.remaining_records()), (0, 1));
			send_key(&writer).encrypt_next(PLAINTEXT)?;
			Ok(())
		}

		/// A receive install restarts the exact-next sequence, and the renewal
		/// threshold survives it.
		#[test]
		fn a_reader_install_swaps_the_cipher_and_keeps_its_threshold() -> TestResult {
			let record_zero = test_sender().encrypt_next(PLAINTEXT)?.to_der()?;
			let mut reader = reader(SplitRecv::Encrypted(test_receiver().with_rekey_limit(2)));
			let mut first = record_zero.clone();
			recv_key(&mut reader).open(&mut first)?;

			let mut replayed = record_zero.clone();
			let replay = recv_key(&mut reader).open(&mut replayed).map(<[u8]>::to_vec);
			let before = reader.remaining_records();

			reader.install_recv_cipher(test_receiver())?;

			assert!(matches!(replay, Err(TightBeamError::NonceReplayed(_))));
			assert_eq!((before, reader.remaining_records()), (1, 2));

			let mut reopened = record_zero;
			recv_key(&mut reader).open(&mut reopened)?;
			Ok(())
		}

		/// A renewal bounds the fresh send cipher by this half's
		/// encrypted-envelope ceiling, so a later override stops at the lower
		/// volume that ceiling admits (RFC 9846 § 5.5).
		#[test]
		fn writer_install_bounds_the_fresh_cipher_by_the_envelope_ceiling() -> TestResult {
			let limits = doubled_ceiling();
			let current = test_sender().with_envelope_ceiling(limits.encrypted_envelope);
			let mut writer = writer_over(NullStream, SplitSend::Encrypted(current), limits, Arc::new(SystemClock));
			writer.install_send_cipher(test_sender())?;

			let raised = writer.with_rekey_limit(u64::MAX);
			assert_eq!(raised.remaining_records(), DEFAULT_REKEY_RECORD_LIMIT / 2);
			Ok(())
		}

		/// A frame stream that stays pending on every read and write, as with a
		/// stalled peer.
		///
		/// A loopback peer that stalls on a write needs its kernel buffer full,
		/// and the double holds a half at the deadline with no buffer to fill.
		struct StalledStream;

		impl AsyncReadStream for StalledStream {
			type Error = IoError;

			async fn read_frame(&mut self, _cap: usize) -> Result<Vec<u8>, Self::Error> {
				core::future::pending().await
			}
		}

		impl AsyncWriteStream for StalledStream {
			type Error = IoError;

			async fn write_frame(&mut self, _buffer: &[u8]) -> Result<(), Self::Error> {
				core::future::pending().await
			}
		}

		fn one_second_deadline() -> CheckedLimits {
			let limits = TransportLimits { operation_timeout: Duration::from_secs(1), ..TransportLimits::default() };
			limits.checked().expect("a one-second deadline agrees with the defaults")
		}

		// The operation deadline bounds a cleartext half as it bounds an
		// encrypted one, so a stalled peer cannot pin its task (CWE-400).
		crate::tb_cases! {
			#[tokio::test(start_paused = true)]
			async fn a_cleartext_half_gives_up_at_the_operation_deadline(outcome: TransportResult<()>) {
				assert!(matches!(
					outcome,
					Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
				));
			}
			cases {
				reader => reader_over(StalledStream, SplitRecv::Cleartext, one_second_deadline(), Arc::new(SystemClock))
					.read_envelope()
					.await
					.map(drop),
				writer => writer_over(StalledStream, SplitSend::Cleartext, one_second_deadline(), Arc::new(SystemClock))
					.write_envelope(TransportEnvelope::from(TestFrame::v0(None, None)))
					.await,
			}
		}

		/// A split half sets its deadline one operation timeout past the
		/// reading of its connection clock, so a read from a stalled peer ends
		/// once that timeout has passed on the runtime's timer, and no later.
		#[tokio::test(start_paused = true)]
		async fn a_split_reader_waits_out_exactly_the_operation_timeout() {
			let clock = Arc::new(ManualClock::default());
			clock.advance(Duration::from_secs(3600));

			let limits = one_second_deadline();
			let mut reader = reader_over(StalledStream, SplitRecv::Cleartext, limits, clock);

			let started = tokio::time::Instant::now();
			let outcome = tokio::time::timeout(limits.operation_timeout * 2, reader.read_envelope()).await;
			assert!(matches!(
				outcome,
				Ok(Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded)))
			));
			assert_eq!(started.elapsed(), limits.operation_timeout);
		}

		// A cleartext half holds no cipher, so it refuses an install.
		crate::tb_cases! {
			fn a_cleartext_half_refuses_a_cipher_install(installed: TransportResult<()>) {
				assert!(matches!(installed, Err(TransportError::MissingEncryption)));
			}
			cases {
				writer => writer(SplitSend::Cleartext).install_send_cipher(test_sender()),
				reader => reader(SplitRecv::Cleartext).install_recv_cipher(test_receiver()),
			}
		}

		/// A frame stream whose every read yields the one wire envelope it
		/// holds.
		///
		/// The cases hand a half a malformed envelope that no peer of the house
		/// writes, so the double serves it in place of a peer.
		struct OneFrameStream(Vec<u8>);

		impl AsyncReadStream for OneFrameStream {
			type Error = IoError;

			async fn read_frame(&mut self, _cap: usize) -> Result<Vec<u8>, Self::Error> {
				Ok(self.0.clone())
			}
		}

		/// A wire envelope under the cleartext tag whose contents, a NULL,
		/// decode to no transport envelope.
		const UNDECODABLE_CLEARTEXT: &[u8] = &[0xa0, 0x02, 0x05, 0x00];

		/// A wire envelope under the record tag whose contents, a NULL, open
		/// under no receive cipher.
		const UNOPENED_RECORD: &[u8] = &[0xa1, 0x02, 0x05, 0x00];

		/// A receive half in `mode` over a stream that yields `frame`.
		fn reading(mode: SplitRecv, frame: impl AsRef<[u8]>) -> TransportReader<OneFrameStream> {
			let stream = OneFrameStream(frame.as_ref().to_vec());
			reader_over(stream, mode, CheckedLimits::default(), Arc::new(SystemClock))
		}

		// A half refuses an envelope of the other mode by its outer tag: an
		// encrypted half before the contents decode, a cleartext half before
		// the record opens.
		crate::tb_cases! {
			async fn a_half_refuses_an_envelope_of_the_other_mode(
				(mut reader, refused): (TransportReader<OneFrameStream>, fn(&TransportError) -> bool)
			) {
				let outcome = reader.read_envelope().await;
				assert!(matches!(&outcome, Err(error) if refused(error)));
			}
			cases {
				encrypted_refuses_cleartext => (
					reading(SplitRecv::Encrypted(test_receiver()), UNDECODABLE_CLEARTEXT),
					|error| matches!(error, TransportError::MissingEncryption),
				),
				cleartext_refuses_a_record => (
					reading(SplitRecv::Cleartext, UNOPENED_RECORD),
					|error| matches!(error, TransportError::OperationFailed(TransportFailure::EncryptionFailed)),
				),
			}
		}

		/// The audit record that a traced half files for an envelope it
		/// refuses.
		#[cfg(feature = "instrument")]
		mod refusal_audit {
			use super::*;
			use crate::instrumentation::events;
			use crate::testing::fixtures::{TestPeer, TestTrace};
			use crate::transport::io::fixtures::{records_of, Forgery};

			/// A traced half records the envelope it refuses by the failure's
			/// name and by the canonical key of its session peer.
			#[tokio::test]
			async fn a_traced_half_records_the_envelope_it_refuses() {
				let (peer, expected) = TestPeer::fixed();
				let trace = TestTrace::with_payloads();
				let mut reader = reading(SplitRecv::Encrypted(test_receiver()), UNDECODABLE_CLEARTEXT);
				reader.trace = Some(trace.share());
				reader.peer = Some(Arc::new(peer));

				let outcome = reader.read_envelope().await;
				let evidence = records_of(&trace, events::TRANSPORT_ENVELOPE_REFUSED);
				assert!(matches!(outcome, Err(TransportError::MissingEncryption)));
				assert_eq!(evidence, [(Some(String::from("MissingEncryption")), Some(expected))]);
			}

			/// A forged record of the client direction, the cause its record
			/// names, and the test of the error that the read returns.
			type ForgedRecordCase = (Forgery, &'static str, fn(&TransportError) -> bool);

			// A traced half records a forged record by its cause, once, and its
			// read returns the error that the open names.
			crate::tb_cases! {
				async fn a_traced_half_records_a_forged_record((forgery, cause, returned): ForgedRecordCase) {
					let trace = TraceCollector::new();
					let forged = forgery.record(RecordDirection::ClientToServer);
					let mut reader = reading(SplitRecv::Encrypted(test_receiver()), forged);
					reader.trace = Some(trace.share());

					let outcome = reader.read_envelope().await;
					assert!(matches!(&outcome, Err(error) if returned(error)));

					let labels = TestTrace::labels(&trace, events::TRANSPORT_ENVELOPE_REFUSED);
					assert_eq!(labels, [Some(String::from(cause))]);
				}
				cases {
					past_the_record_limit => (
						Forgery::AtSequence(crate::constants::DEFAULT_REKEY_RECORD_LIMIT),
						"OpenFailed",
						|error| {
							let past_the_bound = TransportFailure::RenewalBoundExceeded;
							matches!(error, TransportError::OperationFailed(failure) if *failure == past_the_bound)
						},
					),
					whose_position_does_not_decode => (
						Forgery::UndecodablePosition,
						"OpenFailed",
						|error| matches!(error, TransportError::DerError(_)),
					),
					whose_tag_fails => (
						Forgery::TagFlipped,
						"OpenFailed",
						|error| matches!(error, TransportError::InvalidMessage),
					),
					of_another_epoch => (
						Forgery::AtEpoch(1),
						"WrongEpoch",
						|error| matches!(error, TransportError::InvalidMessage),
					),
				}
			}
		}
	}

	/// A cleartext exchange carries the request to the server and its
	/// response back.
	#[tokio::test]
	async fn a_cleartext_exchange_carries_the_request_and_its_response() -> TestResult {
		let (listener, client_stream) = bind_and_connect().await;
		let request = TestFrame::v0(None, None);
		let expected_response = TestFrame::v0(None, None);
		let (reply, mut received) = recording(Some(expected_response.to_owned()));
		let server_handle = tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			respond_with(&mut transport, reply).await
		});

		let mut transport = tcp_transport_from(client_stream);
		let response = transport.emit(request.to_owned(), None).await?;
		assert_eq!(received.recv().await, Some(request));
		assert_eq!(response, Some(expected_response));
		server_handle.await??;
		Ok(())
	}

	struct EncryptedTestServer {
		server: TestCmsServer,
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
	}

	/// An endpoint of a fresh test server that signs with its signing
	/// identity and opens the CMS opening with its key-agreement identity.
	fn encrypted_test_server() -> EncryptedTestServer {
		let server = TestCmsServer::generate("Test Server");
		let config = TransportEncryptionConfig::new(server.signing_identity());
		let config = config.with_key_agreement(server.key_agreement_identity());
		let config = config.expect("the test server holds a key-agreement identity");
		EncryptedTestServer { server, config }
	}

	/// A store that holds the authority of `server`'s two certificates.
	fn trust_store_for(server: &TestCmsServer) -> Arc<dyn CertificateTrust> {
		Arc::new(server.store())
	}

	#[cfg(feature = "transport-cms")]
	fn empty_trust_store() -> Arc<dyn CertificateTrust> {
		Arc::new(TestStore::empty().build())
	}

	async fn bind_encrypted(
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
	) -> (TokioListener<DefaultCryptoProvider>, SocketAddr) {
		let bind_addr = <TokioListener as Protocol>::default_bind_address().expect("the loopback address parses");
		let bound = TokioListener::bind_with(bind_addr, config).await;

		let (listener, socket_addr) = bound.expect("a loopback port binds");
		(listener, *socket_addr)
	}

	fn spawn_accept_handle_request(
		listener: TokioListener<DefaultCryptoProvider>,
	) -> tokio::task::JoinHandle<TransportResult<()>> {
		tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			respond_with(&mut transport, |_| None).await
		})
	}

	/// The task of a server of `config` that handles one request, beside a
	/// raw stream that dialed it.
	async fn dial_handling_server(
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
	) -> (tokio::task::JoinHandle<TransportResult<()>>, TcpStream) {
		let (listener, server_addr) = bind_encrypted(config).await;

		let server = spawn_accept_handle_request(listener);
		let dialed = TcpStream::connect(server_addr)
			.await
			.expect("the loopback server takes the dial");
		(server, dialed)
	}

	async fn bind_and_connect() -> (TokioListener, TcpStream) {
		let listener = TokioListener::bind_cleartext("127.0.0.1:0")
			.await
			.expect("a loopback port binds");

		let listen_addr = listener.local_addr().expect("a bound listener has an address");
		let client_stream = TcpStream::connect(listen_addr)
			.await
			.expect("the loopback listener takes the dial");
		(listener, client_stream)
	}

	/// The handshake opening that carries signed `content`.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn opening(content: &[u8]) -> HandshakeMessage {
		HandshakeMessage::try_from(create_test_signed_data(content)).expect("signed data makes an opening")
	}

	/// A client over `stream` built from `encryption`, which must answer the
	/// dialer rule.
	fn client_over(
		stream: TcpStream,
		encryption: EncryptionConfig<DefaultCryptoProvider>,
	) -> TcpTransport<TokioStream> {
		let encryption = DialableEncryption::new(encryption).expect("the fixture names a peer authority or cleartext");
		let endpoint = EndpointConfig::new(encryption, Arc::new(SystemClock));
		TcpTransport::new(TokioStream::from(stream), endpoint)
	}

	/// A client that validates the server against `trust_store`.
	fn trusting_client(stream: TcpStream, trust_store: Arc<dyn CertificateTrust>) -> TcpTransport<TokioStream> {
		client_over(
			stream,
			EncryptionConfig { trust_store: Some(trust_store), ..EncryptionConfig::unconfigured() },
		)
	}

	fn tcp_transport_from(stream: TcpStream) -> TcpTransport<TokioStream> {
		TcpTransport::new(TokioStream::from(stream), EndpointConfig::cleartext())
	}

	/// A CMS client that holds a signing identity, and `trust_store` when the
	/// caller gives one.
	#[cfg(feature = "transport-cms")]
	fn cms_test_client(stream: TcpStream, trust_store: Option<Arc<dyn CertificateTrust>>) -> TcpTransport<TokioStream> {
		let identity = TestIdentity::insecure_fixed();

		// Without a trust store, the dialer rule builds the client only when it
		// names cleartext. The handshake the test drives over that client must
		// still refuse to run blind.
		let allow_cleartext = trust_store.is_none();
		let encryption = EncryptionConfig {
			trust_store,
			client_identity: Some(identity),
			allow_cleartext,
			..EncryptionConfig::unconfigured()
		};

		let transport = client_over(stream, encryption);
		transport.with_handshake_protocol(HandshakeProtocolKind::Cms)
	}

	/// A CMS client that holds a trust store and the server chain, and no
	/// identity.
	#[cfg(feature = "transport-cms")]
	fn cms_client_without_identity(stream: TcpStream) -> TcpTransport<TokioStream> {
		let server = TestCmsServer::generate("Test Server");
		let encryption = EncryptionConfig {
			trust_store: Some(empty_trust_store()),
			cms_server: Some(server.trust()),
			..EncryptionConfig::unconfigured()
		};

		client_over(stream, encryption).with_handshake_protocol(HandshakeProtocolKind::Cms)
	}

	/// An HPKE client that names cleartext and holds no trust store.
	#[cfg(feature = "transport-hpke")]
	fn hpke_client_without_trust_store(stream: TcpStream) -> TcpTransport<TokioStream> {
		let encryption = EncryptionConfig { allow_cleartext: true, ..EncryptionConfig::unconfigured() };
		client_over(stream, encryption)
	}

	/// A CMS client whose server policy refuses every certificate.
	#[cfg(feature = "transport-cms")]
	fn cms_client_under_a_refusing_policy(stream: TcpStream) -> TcpTransport<TokioStream> {
		let server = TestCmsServer::generate("Test Server");
		let encryption = EncryptionConfig {
			cms_server: Some(server.trust()),
			server_policy: refusing_policy(),
			client_identity: Some(TestIdentity::insecure_fixed()),
			..EncryptionConfig::unconfigured()
		};

		client_over(stream, encryption).with_handshake_protocol(HandshakeProtocolKind::Cms)
	}

	/// A CMS client whose endpoint clock reads past the validity period of
	/// the pinned key-agreement certificate, while the host clock reads a
	/// time inside it.
	#[cfg(feature = "transport-cms")]
	fn cms_client_past_validity(stream: TcpStream) -> TcpTransport<TokioStream> {
		let server = TestCmsServer::generate("Test Server");
		let encryption = EncryptionConfig::<DefaultCryptoProvider> {
			cms_server: Some(server.trust()),
			client_identity: Some(TestIdentity::insecure_fixed()),
			..EncryptionConfig::unconfigured()
		};

		let encryption = DialableEncryption::new(encryption).expect("the pinned server answers the dialer rule");
		let endpoint = EndpointConfig::new(encryption, TestCertificate::clock_past_validity());

		let transport = TcpTransport::new(TokioStream::from(stream), endpoint);
		transport.with_handshake_protocol(HandshakeProtocolKind::Cms)
	}

	/// A transport over the dialing end of a loopback connection, and the test
	/// of the error its handshake returns.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	type DialCase = (fn(TcpStream) -> TcpTransport<TokioStream>, fn(&TransportError) -> bool);

	// A client refuses its handshake before it sends anything when it lacks
	// what the server's answer needs: a CMS client with no server trust or no
	// server chain, a CMS client with no identity, an HPKE client with no
	// trust store, a CMS client whose server policy refuses the pinned
	// certificate, and a CMS client whose endpoint clock reads the pinned
	// certificate as expired.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	crate::tb_cases! {
		async fn a_client_refuses_its_handshake_before_it_sends((client, refused): DialCase) {
			let (_listener, client_stream) = bind_and_connect().await;
			let mut transport = client(client_stream);

			let handshake = transport.perform_client_handshake().await;
			assert!(matches!(&handshake, Err(error) if refused(error)));
		}
		cases {
			#[cfg(feature = "transport-cms")]
			cms_without_server_trust => (
				|stream| cms_test_client(stream, None),
				|error| matches!(error, TransportError::MissingServerCertificateChain),
			),
			#[cfg(feature = "transport-cms")]
			cms_without_server_chain => (
				|stream| cms_test_client(stream, Some(empty_trust_store())),
				|error| matches!(error, TransportError::MissingServerCertificateChain),
			),
			#[cfg(feature = "transport-cms")]
			cms_without_identity => (
				cms_client_without_identity,
				|error| matches!(error, TransportError::HandshakeError(HandshakeError::MutualAuthRequired)),
			),
			#[cfg(feature = "transport-hpke")]
			hpke_without_trust_store => (
				hpke_client_without_trust_store,
				|error| matches!(error, TransportError::HandshakeError(HandshakeError::MissingTrustStore)),
			),
			#[cfg(feature = "transport-cms")]
			cms_under_a_refusing_policy => (
				cms_client_under_a_refusing_policy,
				|error| {
					matches!(
						error,
						TransportError::HandshakeError(HandshakeError::CertificateValidationError(
							CertificateNotTrusted
						))
					)
				},
			),
			#[cfg(feature = "transport-cms")]
			cms_past_validity => (
				cms_client_past_validity,
				|error| {
					matches!(
						error,
						TransportError::HandshakeError(HandshakeError::CertificateValidationError(Expired))
					)
				},
			),
		}
	}

	/// A CMS server that holds a signing identity alone.
	#[cfg(feature = "transport-cms")]
	fn cms_server_without_key_agreement(stream: TcpStream) -> TcpTransport<TokioStream> {
		let server = TestCmsServer::generate("Test Server");
		let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(server.signing_identity());
		let endpoint = EndpointConfig::try_from(config).expect("a server identity answers the dialer rule");

		let transport = TcpTransport::new(TokioStream::from(stream), endpoint);
		transport.with_handshake_protocol(HandshakeProtocolKind::Cms)
	}

	/// An HPKE server that client validators provision and that presents no
	/// identity.
	#[cfg(feature = "transport-hpke")]
	fn hpke_server_without_identity(stream: TcpStream) -> TcpTransport<TokioStream> {
		let peer_authentication = PeerAuthentication::Anonymous.and(refusing_validator());
		let unconfigured = EncryptionConfig::<DefaultCryptoProvider>::unconfigured();
		let encryption = EncryptionConfig { peer_authentication, ..unconfigured };
		let encryption = DialableEncryption::new(encryption).expect("client validators answer the dialer rule");
		let endpoint = EndpointConfig::new(encryption, Arc::new(SystemClock));

		TcpTransport::new(TokioStream::from(stream), endpoint)
	}

	// A server that holds no key for its part of the handshake refuses the
	// handshake before it reads the opening: a CMS server with no key for the
	// opening to seal to, and an HPKE server with no key to sign its reply.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	crate::tb_cases! {
		async fn a_server_without_its_key_refuses_the_handshake((server, refused): DialCase) {
			let (_listener, stream) = bind_and_connect().await;
			let mut transport = server(stream);

			let handshake = transport.perform_server_handshake(opening(b"opening")).await;
			assert!(matches!(&handshake, Err(error) if refused(error)));
		}
		cases {
			#[cfg(feature = "transport-cms")]
			cms_without_key_agreement => (
				cms_server_without_key_agreement,
				|error| matches!(error, TransportError::MissingKeyAgreementIdentity),
			),
			#[cfg(feature = "transport-hpke")]
			hpke_without_identity => (
				hpke_server_without_identity,
				|error| matches!(error, TransportError::MissingEncryption),
			),
		}
	}

	/// A validator that refuses every certificate: a direct-trust validator
	/// with no anchor.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn refusing_validator() -> Arc<dyn CertificateValidation> {
		Arc::new(DirectTrustValidator::default())
	}

	/// A server policy that refuses every certificate.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn refusing_policy() -> Option<ValidatorChain> {
		ValidatorChain::new([refusing_validator()])
	}

	/// A mutual server reads the validity period of a client certificate on
	/// the clock of its endpoint, so a clock past the end of the period
	/// refuses a client that the host clock reads as current.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn a_mutual_server_reads_validity_on_the_clock_of_its_endpoint() -> TestResult {
		let (stream, peer) = TestLoopback::tokio_pair().await;
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let anchor = TestCertificate::insecure_fixed();
		let anchored: Arc<dyn CertificateValidation> =
			Arc::new(DirectTrustValidator::default().with_trust_chain([anchor])?);

		let endpoint = EndpointConfig::try_from(config.with_client_validators([anchored]))?;
		let endpoint = endpoint.with_clock(TestCertificate::clock_past_validity());
		let mut accepted = TcpTransport::new(TokioStream::from(stream), endpoint);
		let served = tokio::spawn(async move { respond_with(&mut accepted, |_| None).await });

		let encryption = EncryptionConfig {
			trust_store: Some(trust_store_for(&server)),
			client_identity: Some(TestIdentity::insecure_fixed()),
			..EncryptionConfig::unconfigured()
		};

		let mut client = client_over(peer, encryption);
		// The verdict on the closing is the server's, so the outcome of the
		// dial drops here. The close ends a server that admitted the client.
		let _ = client.ensure_handshake_complete().await;
		drop(client);

		let served = served.await?;
		assert!(matches!(
			served,
			Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
				Expired
			)))
		));
		Ok(())
	}

	/// An HPKE client carries its server policy into the handshake, so a
	/// policy that refuses the server's certificate refuses the server that
	/// its store admits.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn an_hpke_client_runs_its_server_policy_at_the_reply() {
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let (_server, client_stream) = dial_handling_server(config).await;
		let encryption = EncryptionConfig {
			trust_store: Some(trust_store_for(&server)),
			server_policy: refusing_policy(),
			..EncryptionConfig::unconfigured()
		};

		let mut transport = client_over(client_stream, encryption);
		let dial = transport.ensure_handshake_complete().await;
		assert!(matches!(
			dial,
			Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
				CertificateNotTrusted
			)))
		));
	}

	/// An HPKE client whose store holds the root alone admits a server whose
	/// signing certificate an intermediate issued, because the endpoint's trust
	/// validates the path the reply presents to that root (RFC 5280 § 6.1).
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn an_hpke_client_of_the_root_alone_admits_an_intermediate() -> TestResult {
		let TestCertificateChain { root, intermediate, leaf, leaf_key, .. } = TestCertificate::insecure_fixed_chain()?;
		let identity = SigningIdentity::new(leaf.to_owned(), Arc::new(Secp256k1KeyProvider::from(leaf_key)))?;
		let config = TransportEncryptionConfig::new(identity.with_chain([intermediate])?);
		let (_server, client_stream) = dial_handling_server(config).await;

		let mut transport = trusting_client(client_stream, Arc::new(TestStore::holding([root])));
		transport.ensure_handshake_complete().await?;
		assert_eq!(transport.session_state().peer_certificate(), Some(&leaf));
		Ok(())
	}

	/// `ClientBuilder::with_server_policy` carries its policy into the dial,
	/// so a policy that refuses the server's certificate refuses the server
	/// that the builder's store admits, at the first exchange.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn a_client_builder_runs_its_server_policy_on_the_dial() -> TestResult {
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let (listener, server_addr) = bind_encrypted(config).await;
		let _server = spawn_accept_handle_request(listener);

		let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(trust_store_for(&server));
		let mut client = builder.with_server_policy([refusing_validator()]).connect(server_addr).await?;

		let exchange = client.emit(TestFrame::v0(None, None), None).await;
		assert!(matches!(
			exchange,
			Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
				CertificateNotTrusted
			)))
		));
		Ok(())
	}

	/// A CMS exchange carries the request to the server and its response
	/// back.
	#[cfg(feature = "transport-cms")]
	#[tokio::test]
	async fn a_cms_exchange_carries_the_request_and_its_response() -> TestResult {
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let (listener, server_addr) = bind_encrypted(config).await;
		let request = TestFrame::v0(None, None);
		let expected_response = TestFrame::v0(None, None);
		let (reply, mut received) = recording(Some(expected_response.to_owned()));
		let server_handle = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut transport = transport.with_handshake_protocol(HandshakeProtocolKind::Cms);
			respond_with(&mut transport, reply).await
		});

		let client_stream = TcpStream::connect(server_addr).await?;
		let encryption = EncryptionConfig {
			trust_store: Some(trust_store_for(&server)),
			cms_server: Some(server.trust()),
			client_identity: Some(TestIdentity::of(&TestKey::fixed(0x02))),
			..EncryptionConfig::unconfigured()
		};

		let transport = client_over(client_stream, encryption);
		let mut transport = transport.with_handshake_protocol(HandshakeProtocolKind::Cms);
		let response = transport.emit(request.to_owned(), None).await?;
		assert_eq!(received.recv().await, Some(request));
		assert_eq!(response, Some(expected_response));
		server_handle.await??;
		Ok(())
	}

	/// The handshake read deadline ends the handshake of a client that sends
	/// nothing. The runtime clock is paused, so the deadline passes on the
	/// runtime's timer and the test waits on no wall clock.
	#[tokio::test(start_paused = true)]
	async fn the_handshake_read_deadline_ends_a_silent_client() -> TestResult {
		let EncryptedTestServer { config, .. } = encrypted_test_server();
		let limits = TransportLimits { handshake_timeout: Duration::from_millis(500), ..*config.limits };
		let (server_handle, _silent_client) = dial_handling_server(config.with_limits(limits)?).await;

		let joined = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
		assert!(matches!(
			joined,
			Ok(Ok(Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))))
		));
		Ok(())
	}

	/// A whole frame on the wire: a NULL under the cleartext tag.
	const WAITING_FRAME: &[u8] = &[0xa0, 0x02, 0x05, 0x00];

	/// A server transport over one end of a loopback connection, beside the
	/// raw stream of its peer. The server reads its deadlines on `clock`, and
	/// its handshake begins at the clock's reading.
	async fn handshaking_server(clock: &Arc<ManualClock>) -> (TcpTransport<TokioStream>, TcpStream) {
		let (stream, peer) = TestLoopback::tokio_pair().await;

		let EncryptedTestServer { config, .. } = encrypted_test_server();
		let endpoint = EndpointConfig::try_from(config).expect("a server identity answers the dialer rule");
		let endpoint = endpoint.with_clock(Arc::clone(clock) as Arc<dyn Clock>);
		let mut transport = TcpTransport::new(TokioStream::from(stream), endpoint);

		let began = transport.state.begin_handshake(clock.monotonic());
		assert!(began);
		(transport, peer)
	}

	/// A stream whose peer sent its FIN reads dead, though the socket still
	/// names the address of that peer.
	#[tokio::test]
	async fn a_stream_whose_peer_closed_is_not_alive() -> TestResult {
		let (stream, peer) = TestLoopback::tokio_pair().await;
		let stream = TokioStream::from(stream);
		drop(peer);
		stream.stream.readable().await?;

		assert!(!AsyncByteStream::is_alive(&stream));
		Ok(())
	}

	/// A stream whose peer holds the connection open and sends nothing reads
	/// alive.
	#[tokio::test]
	async fn a_stream_whose_peer_waits_is_alive() {
		let (stream, _peer) = TestLoopback::tokio_pair().await;
		let stream = TokioStream::from(stream);
		assert!(AsyncByteStream::is_alive(&stream));
	}

	/// A stream that holds bytes of its peer reads alive, and the next read
	/// still takes each of those bytes.
	#[tokio::test]
	async fn a_stream_with_bytes_waiting_is_alive_and_keeps_them() -> TestResult {
		let (stream, mut peer) = TestLoopback::tokio_pair().await;
		let mut stream = TokioStream::from(stream);

		peer.write_all(WAITING_FRAME).await?;
		stream.stream.readable().await?;

		let alive = AsyncByteStream::is_alive(&stream);
		// The close ends a read that finds fewer bytes than the peer sent.
		drop(peer);

		let mut waiting = [0u8; WAITING_FRAME.len()];
		AsyncByteRead::read_exact(&mut stream, &mut waiting).await?;
		assert_eq!((alive, waiting.as_slice()), (true, WAITING_FRAME));
		Ok(())
	}

	/// A read refuses once the handshake deadline has passed on the connection
	/// clock, before it takes a byte, though a whole frame of the peer waits.
	#[tokio::test]
	async fn a_read_past_the_handshake_deadline_is_refused() -> TestResult {
		let clock = Arc::new(ManualClock::default());
		let (mut transport, mut peer) = handshaking_server(&clock).await;
		peer.write_all(WAITING_FRAME).await?;
		clock.advance(transport.limits.handshake_timeout);

		let read = transport.read_envelope_bytes().await;
		assert!(matches!(
			read,
			Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
		));
		Ok(())
	}

	/// The server driver refuses a handshake message that arrives once the
	/// handshake deadline has passed on the connection clock, before the
	/// message runs.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn a_handshake_message_past_the_deadline_is_refused() {
		let clock = Arc::new(ManualClock::default());
		let (mut transport, _peer) = handshaking_server(&clock).await;

		clock.advance(transport.limits.handshake_timeout);

		let driven = transport.perform_server_handshake(opening(b"late")).await;
		assert!(matches!(
			driven,
			Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
		));
	}

	/// The async budget refuses a thread outside any runtime.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn a_budget_on_a_thread_outside_a_runtime_is_refused() {
		let operation = async { Ok(7) };
		let budget = Duration::from_secs(1);
		let bounded = <TcpTransport<TokioStream> as ServerHandshakeSlot>::within_budget(budget, operation);

		let outcome = ParkingExecutor::on_current_thread().block_on(bounded);
		assert!(matches!(
			outcome,
			Err(TransportError::OperationFailed(TransportFailure::FailedPrecondition))
		));
	}

	/// The async budget ends an operation that outlasts it, on the tokio timer.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test(start_paused = true)]
	async fn a_budget_ends_an_operation_that_outlasts_it() {
		let operation = async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			Ok(7)
		};

		let budget = Duration::from_secs(1);
		let bounded = <TcpTransport<TokioStream> as ServerHandshakeSlot>::within_budget(budget, operation);

		let outcome = bounded.await;
		assert!(matches!(
			outcome,
			Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
		));
	}

	/// A split hands the peer of its session to the reader half, so the record
	/// of an envelope that the half refuses names that peer.
	#[cfg(feature = "instrument")]
	#[tokio::test]
	async fn a_split_reader_names_the_peer_of_its_session() -> TestResult {
		let clock = Arc::new(ManualClock::default());
		let (transport, mut raw_peer) = handshaking_server(&clock).await;
		let trace = TestTrace::with_payloads();
		let (phase, expected) = SessionPhase::peered(SessionKeys::insecure_server());
		let mut transport = transport.with_trace(trace.share());
		transport.state = SessionState::at(EncryptionConfig::unconfigured(), phase);

		let (mut reader, _writer) = transport.into_split()?;
		raw_peer.write_all(WAITING_FRAME).await?;

		let refused = reader.read_envelope().await;
		assert!(matches!(refused, Err(TransportError::MissingEncryption)));
		assert_eq!(
			TestTrace::payloads(&trace, events::TRANSPORT_ENVELOPE_REFUSED),
			[Some(expected)]
		);
		Ok(())
	}

	/// What a server whose session holds `keys` collects while `record`, a
	/// record of the client direction, waits on the wire.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	async fn collected_under(
		keys: crate::crypto::aead::SessionKeys,
		record: crate::asn1::AuthEnvelopedData,
	) -> TransportResult<(Arc<Frame>, TransitStatus)> {
		use crate::transport::envelopes::WireEnvelope;
		use crate::transport::state::{SessionPhase, SessionState};

		let clock = Arc::new(ManualClock::default());
		let (mut transport, mut peer) = handshaking_server(&clock).await;
		transport.state = SessionState::at(EncryptionConfig::unconfigured(), SessionPhase::encrypted(keys));

		let envelope = WireEnvelope::Encrypted(record);
		let wire = envelope.to_der().expect("a record encodes as a wire envelope");
		peer.write_all(&wire).await.expect("the loopback peer takes the record");
		transport.collect_message().await
	}

	/// The DER of a request envelope, which a record of the client direction
	/// seals.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn request_der() -> Vec<u8> {
		use crate::transport::envelopes::{RequestPackage, TransportEnvelope};

		let request = TransportEnvelope::Request(RequestPackage::new(TestFrame::prioritized()));
		request.to_der().expect("a request envelope encodes")
	}

	/// The failure that the error of `result` names, with its frame or without
	/// it, or `None` for a result that names none.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	fn failure_of<T>(result: &TransportResult<T>) -> Option<TransportFailure> {
		let Err(error) = result else {
			return None;
		};

		match error {
			TransportError::OperationFailed(failure) | TransportError::MessageNotSent(_, failure) => Some(*failure),
			_ => None,
		}
	}

	/// A server whose send cipher is spent can answer no request, so it
	/// collects none, and the request that waits on the wire never reaches a
	/// handler.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test]
	async fn a_spent_server_collects_no_request() -> TestResult {
		let record = SessionKeys::insecure_client().send().encrypt_next(request_der())?;
		let collected = collected_under(SessionKeys::insecure_server().with_envelope_ceiling(usize::MAX), record).await;
		assert!(matches!(
			collected,
			Err(TransportError::OperationFailed(TransportFailure::RekeyRequired))
		));
		Ok(())
	}

	/// A record past a renewal bound of the receive key fails a collect with
	/// another failure than a spent send cipher does, so the error tells a
	/// fault of the inbound stream from a routine end of keys.
	#[cfg(all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[tokio::test]
	async fn a_receive_overrun_fails_apart_from_a_spent_cipher() -> TestResult {
		let client = SessionKeys::insecure_client();
		let limit = crate::constants::DEFAULT_REKEY_RECORD_LIMIT;
		let past_the_bound = client.send().seal_at(request_der(), limit)?;
		let in_sequence = client.send().encrypt_next(request_der())?;

		let overrun = collected_under(SessionKeys::insecure_server(), past_the_bound).await;
		let unbounded = SessionKeys::insecure_server().with_envelope_ceiling(usize::MAX);
		let refused = collected_under(unbounded, in_sequence).await;

		let failures = (failure_of(&overrun), failure_of(&refused));
		let expected = (
			Some(TransportFailure::RenewalBoundExceeded),
			Some(TransportFailure::RekeyRequired),
		);
		assert_eq!(failures, expected);
		Ok(())
	}

	/// A traced server records the handshake that its deadline ends, as the
	/// outcome of that handshake.
	#[cfg(all(feature = "transport-hpke", feature = "instrument"))]
	#[tokio::test]
	async fn a_handshake_past_the_deadline_records_its_expiry() {
		let clock = Arc::new(ManualClock::default());
		let trace = TraceCollector::new();
		let (transport, _peer) = handshaking_server(&clock).await;
		let mut transport = transport.with_trace(trace.share());

		clock.advance(transport.limits.handshake_timeout);

		let driven = transport.perform_server_handshake(opening(b"late")).await;
		assert!(matches!(
			driven,
			Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
		));
		assert_eq!(TestTrace::records(&trace, events::SESSION_HANDSHAKE_EXPIRED).len(), 1);
	}

	/// The server refuses a handshake-phase frame by its declared length when
	/// that length exceeds the 16 KiB handshake cap, before it reads the body.
	/// The runtime clock is paused and the join budget is below the handshake
	/// deadline, so a server that waited for the body would miss the budget.
	#[tokio::test(start_paused = true)]
	async fn a_handshake_frame_over_the_cap_is_refused_before_its_body() -> TestResult {
		let EncryptedTestServer { config, .. } = encrypted_test_server();
		let limits = TransportLimits { handshake_timeout: Duration::from_secs(5), ..*config.limits };
		let (server_handle, mut client_stream) = dial_handling_server(config.with_limits(limits)?).await;
		let oversize_header = [0x30u8, 0x83, 0x01, 0x00, 0x00];
		client_stream.write_all(&oversize_header).await?;

		let joined = tokio::time::timeout(Duration::from_secs(4), server_handle).await;
		assert!(matches!(
			joined,
			Ok(Ok(Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))))
		));
		Ok(())
	}

	/// A gate that answers its first request as busy and every later one as
	/// admitted.
	///
	/// Each house gate decides its status from the frame and the session, so
	/// a test that needs a status that changes between two equal requests
	/// holds this double.
	#[cfg(feature = "transport-hpke")]
	struct BusyFirstGate {
		first: AtomicBool,
	}

	#[cfg(feature = "transport-hpke")]
	impl BusyFirstGate {
		fn new() -> Self {
			Self { first: AtomicBool::new(true) }
		}
	}

	#[cfg(feature = "transport-hpke")]
	impl GatePolicy for BusyFirstGate {
		fn evaluate(&self, _msg: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
			if self.first.swap(false, Ordering::SeqCst) {
				TransitStatus::ResourceExhausted
			} else {
				TransitStatus::Ok
			}
		}
	}

	/// An encrypted server's collector gate refuses the first request as
	/// exhausted, so that request reaches no handler, and the retry passes
	/// the gate.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn a_gate_that_refuses_the_first_request_admits_the_retry() -> TestResult {
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let (listener, server_addr) = bind_encrypted(config).await;
		let request = TestFrame::v0(None, None);
		let (echo, mut received) = recording(Some(request.to_owned()));
		let server_handle = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut transport = transport.with_collector_gate(BusyFirstGate::new());
			respond_with(&mut transport, &echo).await?;
			respond_with(&mut transport, &echo).await
		});

		let client_stream = TcpStream::connect(server_addr).await?;
		let mut transport = trusting_client(client_stream, trust_store_for(&server));
		let first_emit = transport.emit(request.to_owned(), None).await;

		transport.emit(request.to_owned(), None).await?;
		server_handle.await??;

		assert!(matches!(
			first_emit,
			Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
		));
		assert_eq!((received.recv().await, received.recv().await), (Some(request), None));
		Ok(())
	}

	/// The task of a server of `config` that records the frame of the one
	/// request it serves and answers it with no frame, beside the receiver of
	/// the recorded frames and a dial to that server.
	#[cfg(feature = "transport-hpke")]
	async fn dial_recording_server(
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
	) -> (
		tokio::task::JoinHandle<TransportResult<()>>,
		tokio::sync::mpsc::Receiver<Frame>,
		TcpStream,
	) {
		let (listener, server_addr) = bind_encrypted(config).await;
		let (reply, received) = recording(None);
		let server_handle = tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			respond_with(&mut transport, reply).await
		});

		let dialed = TcpStream::connect(server_addr)
			.await
			.expect("the loopback server takes the dial");
		(server_handle, received, dialed)
	}

	/// The gossip membership proof reads the peer certificate before the
	/// gateway discloses any request (CWE-668), so the deferred single-flight
	/// handshake must run on its own and populate the peer certificate.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn a_lone_handshake_populates_the_peer_certificate() -> TestResult {
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let (_server_handle, _received, client_stream) = dial_recording_server(config).await;
		let mut transport = trusting_client(client_stream, trust_store_for(&server));
		let before = transport.session_state().peer_certificate().is_none();

		transport.ensure_handshake_complete().await?;

		assert!(before);
		assert_eq!(transport.session_state().peer_certificate(), Some(&server.signing));
		Ok(())
	}

	/// A lone handshake sends no application frame and a repeat of it does
	/// nothing, so the one frame the server records is the request of the
	/// later exchange.
	#[cfg(feature = "transport-hpke")]
	#[tokio::test]
	async fn a_lone_handshake_sends_no_application_frame() -> TestResult {
		let EncryptedTestServer { server, config } = encrypted_test_server();
		let (server_handle, mut received, client_stream) = dial_recording_server(config).await;
		let mut transport = trusting_client(client_stream, trust_store_for(&server));
		let request = TestFrame::v0(None, None);

		transport.ensure_handshake_complete().await?;
		transport.ensure_handshake_complete().await?;
		transport.emit(request.to_owned(), None).await?;
		server_handle.await??;

		assert_eq!((received.recv().await, received.recv().await), (Some(request), None));
		Ok(())
	}
}
