use std::sync::Arc;

#[cfg(feature = "tokio")]
use core::time::Duration;
#[cfg(feature = "tokio")]
use std::io::Error as IoError;

#[cfg(feature = "tokio")]
mod tokio_rt {
	pub use std::io::ErrorKind;
	pub use std::net::SocketAddr;

	pub use crate::transport::protocols::PersistentConnection;
	pub use crate::transport::tcp::TightBeamSocketAddr;
	pub use crate::transport::{AsyncListenerTrait, Protocol};
	pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
	pub use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
	pub use tokio::net::{TcpListener, TcpStream};
	pub use tokio::time::timeout;

	#[cfg(feature = "x509")]
	pub use crate::crypto::profiles::DefaultCryptoProvider;
	#[cfg(feature = "x509")]
	pub use crate::transport::EncryptedProtocol;
}

#[cfg(feature = "tokio")]
use tokio_rt::*;

use crate::builder::TypeBuilder;
use crate::der::Encode;
use crate::policy::TransitStatus;
use crate::transport::error::TransportFailure;
use crate::transport::protocols::{AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, SplittableStream};
use crate::transport::ResponsePackage;
use crate::transport::{
	EnvelopeBuilder, MessageCollector, MessageEmitter, MessageIO, TransportError, TransportLimits, TransportResult,
	WireMode,
};
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::transport::handshake::negotiation::MuxSettings;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::transport::handshake::negotiation::TransportOffer;
#[cfg(feature = "tokio")]
use crate::transport::protocols::{AsyncByteRead, AsyncByteStream, AsyncByteWrite};
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::utils::marker::MaybeSend;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::aead::{DecryptContent, RecvCipher, SendCipher};
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::der::Decode;
	pub use crate::transport::envelopes::{TransportEnvelope, WireEnvelope};
	pub use crate::transport::handshake::BoxedServerHandshake;
	pub use crate::transport::io::{EnvelopeSink, EnvelopeSource};
	pub use crate::transport::state::{EncryptedProtocolState, SessionPhase};
	pub use crate::transport::EncryptedMessageIO;
	#[cfg(feature = "tokio")]
	pub use crate::transport::{EndpointConfig, TransportEncryptionConfig};
	pub use crate::utils::time::Clock;
	#[cfg(all(
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub use crate::x509::Certificate;

	#[cfg(all(
		feature = "transport-policy",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub use crate::policy::SessionContext;
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
	fn is_alive(&self) -> bool {
		self.stream.peer_addr().is_ok()
	}
}

/// Owned read half of a [`TokioStream`].
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

/// Owned write half of a [`TokioStream`].
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
#[cfg(feature = "tokio")]
pub struct TokioListener<P: CryptoProvider = DefaultCryptoProvider> {
	listener: TcpListener,
	/// What every accepted transport is built from.
	config: EndpointConfig<P>,
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> TokioListener<P> {
	/// The local address that the listener is bound to.
	pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
		self.listener.local_addr()
	}

	/// Bind a cleartext listener on `addr`.
	///
	/// Accepted transports carry no confidentiality, integrity, or peer
	/// authentication. See [`EndpointConfig::cleartext`].
	pub async fn bind(addr: impl AsRef<str>) -> Result<Self, IoError> {
		let listener = TcpListener::bind(addr.as_ref()).await?;
		let config = EndpointConfig::cleartext();

		Ok(Self { listener, config })
	}

	/// Accept one connection as a transport built from this listener's
	/// configuration.
	pub async fn accept(&self) -> Result<(TcpTransport<TokioStream, P>, SocketAddr), IoError> {
		let (stream, peer_addr) = self.listener.accept().await?;
		let tokio_stream = TokioStream::from(stream);
		let transport = TcpTransport::new(tokio_stream, self.config.clone());

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

	async fn bind(addr: Self::Address) -> Result<(Self::Listener, Self::Address), Self::Error> {
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
		let config = EndpointConfig::from(config);

		Ok((Self { listener, config }, TightBeamSocketAddr(bound_addr)))
	}
}

// `TcpTransport` takes the default of every `EncryptedMessageIO` method.
#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream> EncryptedMessageIO for TcpTransport<S> where TransportError: From<S::Error> {}

impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Report whether the underlying stream still appears connected.
	///
	/// External protocols need this liveness hook to implement
	/// [`PersistentConnection`] for pooled connections, and the stream itself
	/// stays private.
	pub fn is_alive(&self) -> bool {
		AsyncProtocolStream::is_alive(&self.stream)
	}
}

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
mod mux {
	pub use crate::transport::multiplex::{
		IntoMuxOffer, MuxCapable, MuxConnector, MuxRekeyContext, MuxRole, MuxTransport,
	};

	#[cfg(feature = "transport-policy")]
	pub(crate) use crate::transport::io::CollectStep;
	#[cfg(feature = "transport-policy")]
	pub use crate::transport::multiplex::{GatedHalves, MuxAcceptor};
}

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use mux::*;

/// Only async transports advertise multiplexing. The mux plane needs split
/// halves and spawned drivers, so an advertisement anywhere else would
/// negotiate a capability that the endpoint cannot honor.
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Set the local mux advertisement, which the handshake transcript binds.
	///
	/// A `None` offer advertises nothing.
	pub fn with_mux_offer(mut self, offer: impl IntoMuxOffer) -> Self {
		self.state.offer_mux(offer.into_mux_offer());
		self
	}
}

/// The multiplexed plane that [`TcpTransport::into_mux`] assembles.
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub type SplitMuxTransport<S> = MuxTransport<
	TransportReader<<S as SplittableStream>::ReadHalf>,
	TransportWriter<<S as SplittableStream>::WriteHalf>,
>;

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl<S> TcpTransport<S>
where
	S: SplittableStream,
	TransportError: From<S::Error>,
{
	/// Consume a handshaken transport into its multiplexed plane.
	///
	/// - The negotiated settings drive the assembly.
	/// - The in-band rekey context attaches when the session carries a dual-signed receipt.
	/// - The halves split for the mux drivers.
	///
	/// # Role
	///
	/// The caller passes the endpoint role that it assembles. Unlike the
	/// [`MuxConnector`] and `MuxAcceptor` pool traits, this method works for
	/// either role without the policy plane, so WebSocket transports, native
	/// and wasm, assemble the same way.
	///
	/// # Errors
	///
	/// - `InvalidState` when the peer did not negotiate multiplexing, or the
	///   handshake has not completed.
	/// - A rekey harvest or split failure from the underlying transport.
	pub fn into_mux(mut self, role: MuxRole) -> TransportResult<SplitMuxTransport<S>> {
		let Some(settings) = self.negotiated_mux() else {
			return Err(TransportError::InvalidState);
		};

		let rekey = MuxRekeyContext::detach(&mut self, role)?;
		let (reader, writer) = self.into_split()?;

		let mut mux = MuxTransport::new(reader, writer, role, settings);
		if let Some(context) = rekey {
			mux = mux.with_rekey(context);
		}

		Ok(mux)
	}
}

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
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

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl<S> MuxConnector for TcpTransport<S>
where
	S: SplittableStream,
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
		MuxRekeyContext::detach(self, MuxRole::Client)
	}

	fn handshake_peer_certificate(&self) -> Option<Arc<Certificate>> {
		self.session_state().peer_certificate_arc()
	}

	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)> {
		self.into_split()
	}
}

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl<S> MuxAcceptor for TcpTransport<S>
where
	S: SplittableStream,
	S::ReadHalf: MaybeSend + 'static,
	S::WriteHalf: MaybeSend + 'static,
	TransportError: From<S::Error>,
{
	type EnvelopeReader = TransportReader<S::ReadHalf>;
	type EnvelopeWriter = TransportWriter<S::WriteHalf>;

	/// A cleartext server, which has no certificate, never handshakes and
	/// never multiplexes, so it returns `Ok(None)` with no I/O.
	async fn negotiate_mux(&mut self) -> TransportResult<Option<MuxSettings>> {
		if !self.encryption().is_provisioned() {
			return Ok(None);
		}

		while !matches!(self.state.phase(), SessionPhase::Encrypted(_)) {
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
		MuxRekeyContext::detach(self, MuxRole::Server)
	}

	#[cfg(feature = "transport-policy")]
	fn session_context(&self) -> SessionContext {
		SessionContext::capture(self)
	}

	#[cfg(feature = "transport-policy")]
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
#[cfg(feature = "x509")]
enum SplitRecv {
	/// The transport was named cleartext, so envelopes carry NO
	/// confidentiality, integrity, replay, or deletion protection.
	Cleartext,
	/// The receive-direction cipher of the established session.
	Encrypted(RecvCipher),
}

/// The wire mode a split send half writes, with the cipher an encrypted
/// session needs.
#[cfg(feature = "x509")]
enum SplitSend {
	/// The transport was named cleartext.
	Cleartext,
	/// The send-direction cipher of the established session.
	Encrypted(SendCipher),
}

/// The exclusive receive half of a split transport.
///
/// It carries the wire mode that its session held when it split. An
/// encrypted half owns the receive-direction cipher, so decryption needs no
/// locks and can run concurrently with a [`TransportWriter`] on the same
/// connection.
#[cfg(feature = "x509")]
pub struct TransportReader<R>
where
	R: AsyncReadStream,
{
	stream: R,
	mode: SplitRecv,
	limits: TransportLimits,
	/// The connection collector carried across the split. See
	/// [`EnvelopeSource::trace`].
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "x509")]
impl<R> TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Override the receive-direction renewal threshold that
	/// `remaining_records` counts down ([RFC 9846 § 5.5][rfc9846-5.5]).
	///
	/// The value sets trigger policy only. Decryption refuses records at the
	/// AES-GCM volume bound ([`DEFAULT_REKEY_RECORD_LIMIT`]) whatever this
	/// value is. A cleartext half never rekeys, so the limit does not apply to
	/// it.
	///
	/// [rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
	/// [`DEFAULT_REKEY_RECORD_LIMIT`]: crate::constants::DEFAULT_REKEY_RECORD_LIMIT
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		if let SplitRecv::Encrypted(cipher) = self.mode {
			self.mode = SplitRecv::Encrypted(cipher.with_rekey_limit(limit));
		}

		self
	}
}

#[cfg(feature = "x509")]
impl<R> EnvelopeSource for TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Read one envelope in the wire mode this half was split in.
	///
	/// The operation deadline bounds the read in either mode, so a peer that
	/// stops mid-frame cannot pin the reader task (CWE-400).
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let max_len = match &self.mode {
			SplitRecv::Cleartext => self.limits.cleartext_envelope,
			SplitRecv::Encrypted(_) => self.limits.encrypted_envelope,
		};

		#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
		let wire_bytes = timeout(self.limits.operation_timeout, self.stream.read_frame(max_len)).await??;
		#[cfg(not(all(feature = "tokio", feature = "std", feature = "transport-policy")))]
		let wire_bytes = self.stream.read_frame(max_len).await?;

		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match (&self.mode, wire_envelope) {
			(SplitRecv::Cleartext, WireEnvelope::Cleartext(envelope)) => Ok(envelope),
			(SplitRecv::Cleartext, WireEnvelope::Encrypted(_)) => {
				Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed))
			}
			(SplitRecv::Encrypted(_), WireEnvelope::Cleartext(_)) => Err(TransportError::MissingEncryption),
			(SplitRecv::Encrypted(recv_key), WireEnvelope::Encrypted(encrypted_info)) => {
				let decrypted_bytes = recv_key.decrypt_content(&encrypted_info)?;
				let envelope = decrypted_bytes.with(|bytes| TransportEnvelope::from_der(bytes))?;
				Ok(envelope)
			}
		}
	}

	/// The number of records still readable before the receive cipher demands
	/// a rekey. A cleartext half never demands one, so it reports `u64::MAX`.
	fn remaining_records(&self) -> u64 {
		match &self.mode {
			SplitRecv::Cleartext => u64::MAX,
			SplitRecv::Encrypted(recv_key) => recv_key.remaining_records(),
		}
	}

	/// Swap in the new epoch's receive cipher.
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
/// It carries the wire mode that its session held when it split. An
/// encrypted half owns the send-direction cipher and its counter nonce, so
/// encryption needs no locks and can run concurrently with a
/// [`TransportReader`] on the same connection.
#[cfg(feature = "x509")]
pub struct TransportWriter<W>
where
	W: AsyncWriteStream,
{
	stream: W,
	mode: SplitSend,
	/// Every ceiling carried across the split, as on the unsplit path. A peer
	/// that never drains its receive buffer cannot pin the writer task forever
	/// (CWE-400).
	limits: TransportLimits,
	/// The connection collector carried across the split. See
	/// [`EnvelopeSink::trace`].
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "x509")]
impl<W> TransportWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	/// Override the send cipher's rekey record limit
	/// ([RFC 9846 § 5.5][rfc9846-5.5]).
	///
	/// A cleartext half never rekeys, so the limit does not apply to it.
	///
	/// [rfc9846-5.5]: https://datatracker.ietf.org/doc/html/rfc9846#section-5.5
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		if let SplitSend::Encrypted(cipher) = self.mode {
			self.mode = SplitSend::Encrypted(cipher.with_rekey_limit(limit));
		}

		self
	}
}

#[cfg(feature = "x509")]
impl<W> EnvelopeSink for TransportWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	/// Write one envelope in the wire mode this half was split in, bounded
	/// by the operation deadline in either mode.
	async fn write_envelope(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		let builder = EnvelopeBuilder::transport(envelope).with_limits(self.limits);
		let builder = match &self.mode {
			SplitSend::Cleartext => builder.with_wire_mode(WireMode::Cleartext),
			SplitSend::Encrypted(send_key) => builder.with_wire_mode(WireMode::Encrypted).with_encryptor(send_key),
		};

		let wire_envelope = builder.finish()?;
		let wire_bytes = wire_envelope.to_der()?;

		#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
		timeout(self.limits.operation_timeout, self.stream.write_frame(&wire_bytes)).await??;

		#[cfg(not(all(feature = "tokio", feature = "std", feature = "transport-policy")))]
		self.stream.write_frame(&wire_bytes).await?;

		Ok(())
	}

	/// The number of records still writable before the send cipher demands a
	/// rekey. A cleartext half never demands one, so it reports `u64::MAX`.
	fn remaining_records(&self) -> u64 {
		match &self.mode {
			SplitSend::Cleartext => u64::MAX,
			SplitSend::Encrypted(send_key) => send_key.remaining_records(),
		}
	}

	/// Swap in the new epoch's send cipher.
	///
	/// The fresh counter resets the sequence discipline, because counter
	/// nonces restart only with a fresh key (NIST SP 800-38D § 8.2.1). The
	/// configured record limit carries over, so a tightened rekey cadence
	/// survives every epoch. A cleartext half holds no keys, so it refuses the
	/// install.
	fn install_send_cipher(&mut self, cipher: SendCipher) -> TransportResult<()> {
		let SplitSend::Encrypted(current) = &self.mode else {
			return Err(TransportError::MissingEncryption);
		};

		let renewed = cipher.with_rekey_limit(current.rekey_limit());
		self.mode = SplitSend::Encrypted(renewed);
		Ok(())
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

/// The read and write halves that [`TcpTransport::into_split`] produces.
#[cfg(feature = "x509")]
pub type SplitTransport<S> = (
	TransportReader<<S as SplittableStream>::ReadHalf>,
	TransportWriter<<S as SplittableStream>::WriteHalf>,
);

#[cfg(feature = "x509")]
impl<S, P> TcpTransport<S, P>
where
	S: SplittableStream,
	P: CryptoProvider + Send + Sync + 'static,
	TransportError: From<S::Error>,
{
	/// Split the transport into exclusive read and write halves in the wire
	/// mode its session holds.
	///
	/// - An established session moves its receive key into the
	///   [`TransportReader`] and its send key into the [`TransportWriter`].
	///   Directional keys make this a clean ownership transfer with no shared
	///   mutable crypto state.
	/// - A transport named cleartext splits into cleartext halves, which carry
	///   NO confidentiality, integrity, replay, or deletion protection.
	///
	/// The operation deadline carries onto both halves and bounds every read
	/// and write, as on the unsplit path. An idle or byte-dripping peer
	/// surfaces as `DeadlineExceeded` instead of pinning the driver task.
	///
	/// # Errors
	///
	/// - `InvalidState` when the session is provisioned for encryption and its
	///   handshake has not completed.
	pub fn into_split(mut self) -> TransportResult<SplitTransport<S>> {
		let (recv_mode, send_mode) = match self.state.phase() {
			SessionPhase::Cleartext => (SplitRecv::Cleartext, SplitSend::Cleartext),
			SessionPhase::Encrypted(_) => {
				let session = self.state.take_established().ok_or(TransportError::InvalidState)?;
				let (send_key, recv_key) = session.into_keys().into_parts();
				(SplitRecv::Encrypted(recv_key), SplitSend::Encrypted(send_key))
			}
			SessionPhase::Provisioned | SessionPhase::Handshaking { .. } => {
				return Err(TransportError::InvalidState);
			}
		};

		let limits = self.limits;

		#[cfg(feature = "instrument")]
		let trace = self.trace.as_ref().map(TraceCollector::share);

		let (read_half, write_half) = self.stream.into_split();
		let reader = TransportReader {
			stream: read_half,
			mode: recv_mode,
			limits,
			#[cfg(feature = "instrument")]
			trace: trace.as_ref().map(TraceCollector::share),
		};
		let writer = TransportWriter {
			stream: write_half,
			mode: send_mode,
			limits,
			#[cfg(feature = "instrument")]
			trace,
		};
		Ok((reader, writer))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> AsyncListenerTrait for TokioListener<P> {
	/// This delegates to the inherent accept, so both entry points install
	/// the full listener state.
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		#[cfg(feature = "x509")]
		{
			let (transport, peer_addr) = TokioListener::<P>::accept(self).await?;
			Ok((transport, TightBeamSocketAddr(peer_addr)))
		}
	}
}

// The macro generates the `TcpTransport` struct and its common
// implementations.
crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	fn clock(&self) -> &dyn Clock {
		self.clock.as_ref()
	}

	async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
		// An unauthenticated handshake read gets the tight handshake ceiling.
		// An established session gets the larger of the two envelope ceilings,
		// because the encoded form is unknown until the bytes are parsed.
		#[cfg(feature = "x509")]
		let cap = if self.is_handshake_pending() {
			self.limits.handshake_wire
		} else {
			self.limits.max_envelope()
		};

		#[cfg(feature = "tokio")]
		{
			#[cfg(feature = "x509")]
			let timeout_duration: Option<Duration> = {
				match self.state.phase().initiated_at() {
					Some(initiated_at) => match initiated_at.checked_add(self.limits.handshake_timeout) {
						Some(deadline) => {
							let now = self.clock.monotonic();
							if now >= deadline {
								return Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded));
							}

							Some(deadline.saturating_duration_since(now))
						}
						// A deadline past every reading never arrives.
						None => None,
					},
					_ if self.is_handshake_pending() => Some(self.limits.handshake_timeout),
					_ => {
						#[cfg(feature = "transport-policy")]
						{
							Some(self.limits.operation_timeout)
						}
						#[cfg(not(feature = "transport-policy"))]
						{
							None
						}
					}
				}
			};

			let buffer = if let Some(dur) = timeout_duration {
				timeout(dur, self.stream.read_frame(cap)).await??
			} else {
				self.stream.read_frame(cap).await?
			};

			Ok(buffer)
		}

		#[cfg(not(feature = "tokio"))]
		{
			let buffer = self.stream.read_frame(cap).await?;
			Ok(buffer)
		}
	}

	async fn write_envelope_bytes(&mut self, buffer: &[u8]) -> TransportResult<()> {
		#[cfg(all(feature = "tokio", feature = "transport-policy"))]
		timeout(self.limits.operation_timeout, self.stream.write_frame(buffer)).await??;

		#[cfg(not(all(feature = "tokio", feature = "transport-policy")))]
		self.stream.write_frame(buffer).await?;

		Ok(())
	}
}

#[cfg(all(feature = "x509", feature = "transport-policy"))]
impl<S: AsyncProtocolStream> MessageCollector for TcpTransport<S>
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

		self.write_envelope_bytes(&wire_bytes).await?;
		Ok(())
	}
}

#[cfg(all(feature = "x509", feature = "transport-policy"))]
impl<S: AsyncProtocolStream> MessageEmitter for TcpTransport<S>
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

	/// Complete the handshake, then run one emit cycle under the operation
	/// deadline.
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		self.ensure_handshake_complete().await?;

		#[cfg(feature = "tokio")]
		{
			match timeout(self.limits.operation_timeout, async { self.perform_emit_cycle(message).await }).await {
				Ok(result) => result,
				Err(_) => Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded)),
			}
		}

		#[cfg(not(feature = "tokio"))]
		{
			self.perform_emit_cycle(message).await
		}
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync + 'static> PersistentConnection for TokioListener<P> {
	fn is_connected(transport: &Self::Transport) -> bool {
		transport.is_alive() && transport.session_state().phase().is_writable()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// Shutdown is best-effort. The tokio `TcpStream` relies on `Drop`, so
		// the connection closes fully when the transport drops.
	}
}

#[cfg(all(test, feature = "tokio"))]
mod tests {

	use core::str::FromStr;
	use std::sync::Arc;

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use std::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey, SigningKey};
	use crate::crypto::sign::Sha3Signer;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::prelude::TightBeamSocketAddr;
	use crate::spki::SubjectPublicKeyInfoOwned;
	use crate::testing::*;
	use crate::transport::handshake::{HandshakeError, HandshakeKeyManager, HandshakeProtocolKind};
	use crate::transport::io::EncryptedMessageIO;
	use crate::transport::state::{ClientIdentity, DialableEncryption, EncryptionConfig};
	use crate::transport::{MessageCollector, MessageEmitter, TransportEncryptionConfig};
	use crate::utils::time::SystemClock;
	use std::time::Instant;

	#[cfg(feature = "x509")]
	use crate::policy::TransitStatus;

	/// Serve one single-flight request.
	///
	/// The helper collects the request, applies `reply` to an accepted frame,
	/// and answers with the gate's status.
	#[cfg(feature = "x509")]
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

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use crate::crypto::ecies::EciesError;
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use crate::policy::SessionContext;
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use crate::transport::policy::CollectorGateConfig;

	#[cfg(all(feature = "x509", feature = "aead"))]
	mod cipher_install {
		use super::super::*;
		use crate::crypto::aead::RuntimeAead;
		use crate::testing::{TestFrame, TestKey};
		use crate::TightBeamError;

		const PLAINTEXT: &[u8] = b"epoch boundary traffic";

		/// A frame stream that discards writes and yields nothing.
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
			let (_key, cipher) = TestKey::insecure_fixed_cipher();
			RuntimeAead::new(cipher)
		}

		fn writer(mode: SplitSend) -> TransportWriter<NullStream> {
			TransportWriter {
				stream: NullStream,
				mode,
				limits: TransportLimits::default(),
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		fn reader(mode: SplitRecv) -> TransportReader<NullStream> {
			TransportReader {
				stream: NullStream,
				mode,
				limits: TransportLimits::default(),
				#[cfg(feature = "instrument")]
				trace: None,
			}
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
		fn recv_key(reader: &TransportReader<NullStream>) -> &RecvCipher {
			match &reader.mode {
				SplitRecv::Encrypted(recv_key) => recv_key,
				SplitRecv::Cleartext => panic!("the fixture must be an encrypted half"),
			}
		}

		#[test]
		fn writer_install_swaps_cipher_and_preserves_limit() -> Result<(), TightBeamError> {
			let send_cipher = SendCipher::new(test_runtime()).with_rekey_limit(1);
			let mut writer = writer(SplitSend::Encrypted(send_cipher));

			send_key(&writer).encrypt_next(PLAINTEXT, None)?;
			assert_eq!(writer.remaining_records(), 0);

			// The install brings a fresh key and a reset counter, and the
			// configured record limit survives it.
			let fresh_send = SendCipher::new(test_runtime());
			writer.install_send_cipher(fresh_send)?;
			assert_eq!(writer.remaining_records(), 1);

			send_key(&writer).encrypt_next(PLAINTEXT, None)?;
			Ok(())
		}

		#[test]
		fn reader_install_swaps_cipher_and_preserves_threshold() -> Result<(), TightBeamError> {
			let sender = SendCipher::new(test_runtime());
			let record_zero = sender.encrypt_next(PLAINTEXT, None)?;
			let recv_cipher = RecvCipher::new(test_runtime()).with_rekey_limit(2);
			let mut reader = reader(SplitRecv::Encrypted(recv_cipher));

			recv_key(&reader).decrypt_content(&record_zero)?;

			let replay = recv_key(&reader).decrypt_content(&record_zero);
			assert!(replay.is_err());
			assert_eq!(reader.remaining_records(), 1);

			// Only a fresh key restarts the exact-next counter
			// (NIST SP 800-38D § 8.2.1). The renewal threshold survives the
			// install.
			let fresh_recv = RecvCipher::new(test_runtime());
			reader.install_recv_cipher(fresh_recv)?;

			assert_eq!(reader.remaining_records(), 2);

			recv_key(&reader).decrypt_content(&record_zero)?;
			Ok(())
		}

		/// A frame stream whose peer never sends and never drains.
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

		fn one_second_deadline() -> TransportLimits {
			TransportLimits { operation_timeout: Duration::from_secs(1), ..TransportLimits::default() }
		}

		/// A cleartext half is bounded by the operation deadline like an
		/// encrypted one, so a stalled peer cannot pin its task (CWE-400).
		#[cfg(feature = "transport-policy")]
		#[tokio::test(start_paused = true)]
		async fn a_cleartext_reader_gives_up_at_the_operation_deadline() {
			let mut reader = TransportReader {
				stream: StalledStream,
				mode: SplitRecv::Cleartext,
				limits: one_second_deadline(),
				#[cfg(feature = "instrument")]
				trace: None,
			};

			let outcome = reader.read_envelope().await;
			assert!(matches!(
				outcome,
				Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
			));
		}

		#[cfg(feature = "transport-policy")]
		#[tokio::test(start_paused = true)]
		async fn a_cleartext_writer_gives_up_at_the_operation_deadline() {
			let mut writer = TransportWriter {
				stream: StalledStream,
				mode: SplitSend::Cleartext,
				limits: one_second_deadline(),
				#[cfg(feature = "instrument")]
				trace: None,
			};

			let envelope = TransportEnvelope::from(TestFrame::v0(None, None));
			let outcome = writer.write_envelope(envelope).await;
			assert!(matches!(
				outcome,
				Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
			));
		}

		#[test]
		fn cleartext_halves_fail_closed() {
			let send_cipher = SendCipher::new(test_runtime());
			let recv_cipher = RecvCipher::new(test_runtime());

			let writer_install = writer(SplitSend::Cleartext).install_send_cipher(send_cipher);
			assert!(matches!(writer_install, Err(TransportError::MissingEncryption)));

			let reader_install = reader(SplitRecv::Cleartext).install_recv_cipher(recv_cipher);
			assert!(matches!(reader_install, Err(TransportError::MissingEncryption)));
		}
	}

	#[cfg(feature = "x509")]
	#[tokio::test]
	async fn async_round_trip() -> TransportResult<()> {
		let (listener, client_stream) = bind_and_connect().await?;

		let request = TestFrame::v0(None, None);
		let expected_response = TestFrame::v0(None, None);

		let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(1);
		let response_frame = expected_response.to_owned();
		let server_handle = tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			respond_with(&mut transport, move |msg: Frame| {
				let _ = received_tx.try_send(msg);
				Some(response_frame.to_owned())
			})
			.await
		});

		let mut transport = tcp_transport_from(client_stream);
		let response = transport.emit(request.to_owned(), None).await?;

		let received = received_rx.recv().await;
		assert_eq!(Some(request), received);
		assert_eq!(response.to_owned(), Some(expected_response));

		server_handle.await??;
		Ok(())
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	struct EncryptedTestServer {
		cert: Certificate,
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	fn encrypted_test_server() -> TransportResult<EncryptedTestServer> {
		let signing_key = TestKey::insecure_fixed_signing();
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let sha3_signer = Sha3Signer::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

		let cert = crate::cert!(
			profile: Root,
			subject: "CN=Test Root CA,O=Test Org,C=US",
			serial: 1u32,
			duration: Duration::from_secs(365 * 24 * 60 * 60),
			signer: &sha3_signer,
			subject_public_key: spki
		)?;

		let key_manager = HandshakeKeyManager::<DefaultCryptoProvider>::from(signing_key);
		let config = TransportEncryptionConfig::new(cert.to_owned(), key_manager);
		Ok(EncryptedTestServer { cert, config })
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	fn trust_store_for(cert: Certificate) -> TransportResult<Arc<dyn CertificateTrust>> {
		let trust = CertificateTrustBuilder::from(Secp256k1Policy).with_certificate(cert)?.build();
		Ok(Arc::new(trust))
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	fn empty_trust_store() -> Arc<dyn CertificateTrust> {
		let trust = CertificateTrustBuilder::from(Secp256k1Policy).build();
		Arc::new(trust)
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	async fn bind_encrypted(
		config: TransportEncryptionConfig<DefaultCryptoProvider>,
	) -> TransportResult<(TokioListener<DefaultCryptoProvider>, SocketAddr)> {
		let bind_addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
		let (listener, socket_addr) = TokioListener::bind_with(bind_addr, config).await?;
		Ok((listener, *socket_addr))
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	fn spawn_accept_handle_request(
		listener: TokioListener<DefaultCryptoProvider>,
	) -> tokio::task::JoinHandle<TransportResult<()>> {
		tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			respond_with(&mut transport, |_| None).await
		})
	}

	#[cfg(feature = "x509")]
	async fn bind_and_connect() -> TransportResult<(TokioListener, TcpStream)> {
		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let listen_addr = listener.local_addr()?;
		let client_stream = TcpStream::connect(listen_addr).await?;
		Ok((listener, client_stream))
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
	#[cfg(feature = "x509")]
	fn trusting_client(stream: TcpStream, trust_store: Arc<dyn CertificateTrust>) -> TcpTransport<TokioStream> {
		client_over(
			stream,
			EncryptionConfig { trust_store: Some(trust_store), ..EncryptionConfig::unconfigured() },
		)
	}

	fn tcp_transport_from(stream: TcpStream) -> TcpTransport<TokioStream> {
		TcpTransport::new(TokioStream::from(stream), EndpointConfig::cleartext())
	}

	/// A CMS client holding a signing key, and `trust_store` if one is given.
	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	fn cms_test_client(stream: TcpStream, trust_store: Option<Arc<dyn CertificateTrust>>) -> TcpTransport<TokioStream> {
		let signing_key = Secp256k1SigningKey::from(TestKey::insecure_fixed_signing());
		let key_provider = Secp256k1KeyProvider::from(signing_key);
		let provider = Arc::new(key_provider);
		let key_manager = HandshakeKeyManager::new(provider);

		// Without a trust store the client names cleartext, which is the only
		// way to build it, and the handshake it is then driven through must
		// still refuse to run blind.
		let allow_cleartext = trust_store.is_none();
		let encryption = EncryptionConfig {
			trust_store,
			key_manager: Some(Arc::new(key_manager)),
			handshake_protocol: HandshakeProtocolKind::Cms,
			allow_cleartext,
			..EncryptionConfig::unconfigured()
		};

		client_over(stream, encryption)
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	#[tokio::test]
	async fn cms_client_without_trust_store_fails_closed() -> TransportResult<()> {
		let (_listener, client_stream) = bind_and_connect().await?;
		let mut transport = cms_test_client(client_stream, None);
		let handshake = transport.perform_client_handshake().await;
		assert!(matches!(
			handshake,
			Err(TransportError::HandshakeError(HandshakeError::MissingTrustStore))
		));
		Ok(())
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	#[tokio::test]
	async fn cms_client_without_server_chain_fails_closed() -> TransportResult<()> {
		let (_listener, client_stream) = bind_and_connect().await?;
		let trust_store = empty_trust_store();
		let mut transport = cms_test_client(client_stream, Some(trust_store));

		let handshake = transport.perform_client_handshake().await;
		assert!(matches!(handshake, Err(TransportError::MissingServerCertificateChain)));
		Ok(())
	}

	#[cfg(all(feature = "transport-cms", feature = "transport-policy"))]
	#[tokio::test]
	async fn async_cms_round_trip() -> TransportResult<()> {
		let EncryptedTestServer { cert: server_cert, config } = encrypted_test_server()?;
		let (listener, server_addr) = bind_encrypted(config).await?;

		let request = TestFrame::v0(None, None);
		let expected_response = TestFrame::v0(None, None);

		let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(1);
		let response_frame = expected_response.to_owned();
		let server_handle = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let mut transport = transport.with_handshake_protocol(HandshakeProtocolKind::Cms);

			respond_with(&mut transport, move |msg: Frame| {
				let _ = received_tx.try_send(msg);
				Some(response_frame.to_owned())
			})
			.await
		});

		let client_key = SigningKey::from_bytes(&[2u8; 32].into()).map_err(|_| TransportError::InvalidState)?;
		let client_cert = Arc::new(TestCertificate::self_signed(&client_key));
		let client_signing = Secp256k1SigningKey::from(client_key);
		let key_provider = Secp256k1KeyProvider::from(client_signing);
		let client_provider = Arc::new(key_provider);
		let client_keys = Arc::new(HandshakeKeyManager::new(client_provider));
		let server_chain = Arc::from(vec![server_cert.to_owned()]);
		let trust_store = trust_store_for(server_cert)?;

		let client_stream = TcpStream::connect(server_addr).await?;
		let mut encryption = EncryptionConfig {
			trust_store: Some(trust_store),
			server_certificate_chain: Some(server_chain),
			handshake_protocol: HandshakeProtocolKind::Cms,
			..EncryptionConfig::unconfigured()
		};
		ClientIdentity::new(client_cert, client_keys).install(&mut encryption);

		let mut transport = client_over(client_stream, encryption);
		let response = transport.emit(request.to_owned(), None).await?;
		let received = received_rx.recv().await;
		assert_eq!(Some(request), received);
		assert_eq!(response, Some(expected_response));

		server_handle.await??;
		Ok(())
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	#[tokio::test]
	async fn handshake_read_deadline_bounds_silent_client() -> TransportResult<()> {
		let EncryptedTestServer { mut config, .. } = encrypted_test_server()?;
		config.limits.handshake_timeout = Duration::from_millis(500);

		let (listener, server_addr) = bind_encrypted(config).await?;
		let server_handle = spawn_accept_handle_request(listener);
		let _silent_client = TcpStream::connect(server_addr).await?;

		let deadline = Duration::from_secs(5);
		let joined = tokio::time::timeout(deadline, server_handle).await;
		assert!(matches!(joined, Ok(Ok(Err(_)))));
		Ok(())
	}

	/// A handshake-phase frame whose declared length exceeds the 16 KiB
	/// handshake cap must be rejected on the declared length, before the body
	/// is read.
	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	#[tokio::test]
	async fn handshake_read_rejects_oversize_frame_before_body() -> TransportResult<()> {
		let EncryptedTestServer { mut config, .. } = encrypted_test_server()?;
		config.limits.handshake_timeout = Duration::from_secs(5);

		let (listener, server_addr) = bind_encrypted(config).await?;
		let server_handle = spawn_accept_handle_request(listener);

		let mut client_stream = TcpStream::connect(server_addr).await?;
		let oversize_header = [0x30u8, 0x83, 0x01, 0x00, 0x00];
		client_stream.write_all(&oversize_header).await?;

		let started = Instant::now();
		let join_budget = Duration::from_secs(4);
		let joined = tokio::time::timeout(join_budget, server_handle).await;
		assert!(matches!(joined, Ok(Ok(Err(_)))));
		assert!(started.elapsed() < Duration::from_secs(2));
		Ok(())
	}

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[tokio::test]
	async fn async_with_encrypted_and_gate_policy() -> TransportResult<()> {
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

		let EncryptedTestServer { cert, config } = encrypted_test_server()?;
		let (listener, server_addr) = bind_encrypted(config).await?;

		let request = TestFrame::v0(None, None);
		let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(2);
		let server_handle = tokio::spawn(async move {
			let (transport, _peer) = listener.accept().await?;
			let echo = move |msg: Frame| {
				let _ = received_tx.try_send(msg.to_owned());
				Some(msg)
			};

			let gate = BusyFirstGate::new();
			let mut transport = transport.with_collector_gate(gate);

			respond_with(&mut transport, &echo).await?;
			respond_with(&mut transport, &echo).await
		});

		let trust_store = trust_store_for(cert)?;
		let client_stream = TcpStream::connect(server_addr).await?;
		let mut transport = trusting_client(client_stream, trust_store);
		let first_emit = transport.emit(request.to_owned(), None).await;
		assert!(matches!(
			first_emit,
			Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
		));

		transport.emit(request.to_owned(), None).await?;

		let received = received_rx.recv().await;
		assert_eq!(Some(request), received);
		assert!(received_rx.try_recv().is_err());

		server_handle.await??;
		Ok(())
	}

	// The gossip colony gate reads the peer certificate before any
	// request is disclosed (CWE-668), so the deferred single-flight
	// handshake must be drivable on its own. It populates the peer
	// certificate and sends no application frame, and a repeat does nothing.
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[tokio::test]
	async fn handshake_completes_alone_and_populates_peer_certificate() -> TransportResult<()> {
		let EncryptedTestServer { cert, config } = encrypted_test_server()?;
		let (listener, server_addr) = bind_encrypted(config).await?;

		let request = TestFrame::v0(None, None);
		let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(1);
		let server_handle = tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			respond_with(&mut transport, move |msg: Frame| {
				let _ = received_tx.try_send(msg);
				None
			})
			.await
		});

		let trust_store = trust_store_for(cert)?;
		let client_stream = TcpStream::connect(server_addr).await?;
		let mut transport = trusting_client(client_stream, trust_store);
		assert!(transport.session_state().peer_certificate().is_none());

		transport.ensure_handshake_complete().await?;
		assert!(transport.session_state().peer_certificate().is_some());
		assert!(received_rx.try_recv().is_err());

		transport.ensure_handshake_complete().await?;
		transport.emit(request.to_owned(), None).await?;

		let received = received_rx.recv().await;
		assert_eq!(Some(request), received);

		server_handle.await??;
		Ok(())
	}

	// Both endpoints bind the domain tag into the key exchange's associated
	// data, so a server tag the client does not share fails the session
	// before the first frame is answered.
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[tokio::test]
	async fn a_server_domain_tag_the_client_does_not_share_fails_the_session() -> TransportResult<()> {
		let EncryptedTestServer { cert, config } = encrypted_test_server()?;
		let config = config.with_aad_domain_tag(b"tightbeam-test-other-domain");
		let (listener, server_addr) = bind_encrypted(config).await?;
		let server_handle = spawn_accept_handle_request(listener);

		let trust_store = trust_store_for(cert)?;
		let client_stream = TcpStream::connect(server_addr).await?;
		let mut transport = trusting_client(client_stream, trust_store);

		// The server cannot authenticate the key exchange, so it refuses the
		// handshake and closes the connection under the client's frame.
		let emitted = transport.emit(TestFrame::v0(None, None), None).await;
		let served = server_handle.await?;
		assert!(matches!(emitted, Err(TransportError::ConnectionClosed)));
		assert!(matches!(
			served,
			Err(TransportError::HandshakeError(HandshakeError::EciesError(
				EciesError::DecryptionFailed(_)
			)))
		));
		Ok(())
	}

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[tokio::test]
	async fn endpoints_that_share_a_domain_tag_complete_the_session() -> TransportResult<()> {
		const DOMAIN_TAG: &[u8] = b"tightbeam-test-other-domain";
		let EncryptedTestServer { cert, config } = encrypted_test_server()?;
		let (listener, server_addr) = bind_encrypted(config.with_aad_domain_tag(DOMAIN_TAG)).await?;
		let server_handle = spawn_accept_handle_request(listener);

		let trust_store = trust_store_for(cert)?;
		let client_stream = TcpStream::connect(server_addr).await?;
		let encryption = EncryptionConfig {
			trust_store: Some(trust_store),
			aad_domain_tag: DOMAIN_TAG,
			..EncryptionConfig::unconfigured()
		};

		let mut transport = client_over(client_stream, encryption);
		transport.emit(TestFrame::v0(None, None), None).await?;

		server_handle.await??;
		Ok(())
	}
}
