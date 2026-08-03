use core::time::Duration;
#[cfg(feature = "tokio")]
use std::io::Error as IoError;
use std::sync::Arc;

#[cfg(feature = "tokio")]
mod tokio_rt {
	pub use std::io::ErrorKind;
	pub use std::net::SocketAddr;
	pub use std::time::Instant;

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
use crate::transport::handshake::negotiation::{MuxSettings, TransportAuthorizer, TransportOffer};
use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver, StoredReceipt};
use crate::transport::io::{decode_transport_envelope, ensure_compatible_versions};
use crate::transport::protocols::{
	enforce_frame_cap, AsyncProtocolStream, AsyncReadStream, AsyncWriteStream, SplittableStream,
};
use crate::transport::tcp::HANDSHAKE_MAX_WIRE;
use crate::transport::ResponsePackage;
use crate::transport::{
	EnvelopeBuilder, EnvelopeLimits, MessageCollector, MessageEmitter, MessageIO, TransportError, TransportResult,
	WireMode,
};
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "tokio")]
use crate::transport::protocols::{AsyncByteRead, AsyncByteStream, AsyncByteWrite};
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use crate::utils::marker::MaybeSend;

/// Fallback envelope read cap when no explicit limit is configured.
const DEFAULT_MAX_ENVELOPE: usize = 512 * 1024;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::aead::{Decryptor, RecvCipher, SendCipher, SessionKeys};
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::x509::policy::CertificateValidation;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::der::Decode;
	pub use crate::transport::envelopes::{TransportEnvelope, WireEnvelope};
	pub use crate::transport::handshake::{
		BoxedServerHandshake, HandshakeKeyManager, HandshakeProtocolKind, TcpHandshakeState,
	};
	pub use crate::transport::io::{EnvelopeSink, EnvelopeSource};
	pub use crate::transport::state::EncryptedProtocolState;
	pub use crate::transport::{EncryptedMessageIO, TransportEncryptionConfig};
	pub use crate::x509::Certificate;

	#[cfg(all(
		feature = "transport-policy",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub use crate::policy::SessionContext;
	#[cfg(feature = "aead")]
	pub use crate::transport::handshake::EpochMaterials;
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
	pub fn local_addr(&self) -> Result<SocketAddr, IoError> {
		self.listener.local_addr()
	}

	/// `addr` accepts any type that converts via [`AsRef<str>`].
	pub async fn bind(addr: impl AsRef<str>) -> Result<Self, IoError> {
		let listener = TcpListener::bind(addr.as_ref()).await?;
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
	pub async fn accept(&self) -> Result<(TokioStream, SocketAddr), IoError> {
		let (stream, peer_addr) = self.listener.accept().await?;
		let tokio_stream = TokioStream::from(stream);
		Ok((tokio_stream, peer_addr))
	}

	#[cfg(feature = "x509")]
	pub async fn accept(&self) -> Result<(TcpTransport<TokioStream, P>, SocketAddr), IoError> {
		let (stream, peer_addr) = self.listener.accept().await?;
		let tokio_stream = TokioStream::from(stream);
		let mut transport = TcpTransport::from(tokio_stream);

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

		Ok((transport, peer_addr))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> Protocol for TokioListener<P> {
	type Listener = TokioListener<P>;
	type Stream = TokioStream;
	type Error = IoError;
	type Transport = TcpTransport<TokioStream, P>;
	type Address = TightBeamSocketAddr;

	fn default_bind_address() -> Result<Self::Address, Self::Error> {
		"127.0.0.1:0".parse().map_err(|e| IoError::new(ErrorKind::InvalidInput, e))
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
			TightBeamSocketAddr(bound_addr),
		))
	}

	async fn connect(addr: Self::Address) -> Result<Self::Stream, Self::Error> {
		let stream = TcpStream::connect(addr.0).await?;
		let tokio_stream = TokioStream::from(stream);
		Ok(tokio_stream)
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}
}

#[cfg(all(feature = "tokio", feature = "x509"))]
impl<P: CryptoProvider + Send + Sync> EncryptedProtocol for TokioListener<P> {
	type Encryptor = SendCipher;
	type Decryptor = RecvCipher;
	type CryptoProvider = P;

	async fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<P>,
	) -> Result<(Self::Listener, Self::Address), Self::Error> {
		let listener = TcpListener::bind(addr.0).await?;
		let bound_addr = listener.local_addr()?;
		let certificate = Arc::new(config.certificate);
		let client_validators = config.client_validators.as_ref().map(Arc::clone);
		let key_manager = Arc::clone(&config.key_manager);

		Ok((
			Self {
				listener,
				certificate: Some(certificate),
				client_validators,
				aad_domain_tag: Some(config.aad_domain_tag),
				max_cleartext_envelope: Some(config.max_cleartext_envelope),
				max_encrypted_envelope: Some(config.max_encrypted_envelope),
				handshake_timeout: Some(config.handshake_timeout),
				key_manager: Some(key_manager),
			},
			TightBeamSocketAddr(bound_addr),
		))
	}
}

// EncryptedMessageIO: operation methods only
#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream> EncryptedMessageIO for TcpTransport<S> where TransportError: From<S::Error> {}

impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Report whether the underlying stream still appears connected.
	///
	/// The liveness hook external protocols need to implement
	/// [`PersistentConnection`]
	/// for pooled connections; the stream itself is not exposed.
	pub fn is_alive(&self) -> bool {
		AsyncProtocolStream::is_alive(&self.stream)
	}
}

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Configure this transport as an encrypted server endpoint.
	pub fn with_server_encryption(mut self, config: TransportEncryptionConfig<P>) -> Self {
		let certificate = Arc::new(config.certificate);
		self.server_identity = Some(certificate);
		self.client_validators = config.client_validators;
		self.aad_domain_tag = Some(config.aad_domain_tag);
		self.max_cleartext_envelope = Some(config.max_cleartext_envelope);
		self.max_encrypted_envelope = Some(config.max_encrypted_envelope);
		self.handshake_timeout = config.handshake_timeout;
		self.key_manager = Some(config.key_manager);
		self
	}
}

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
mod mux {
	pub(crate) use crate::transport::io::take_rekey_context;
	pub use crate::transport::multiplex::{
		IntoMuxOffer, MuxCapable, MuxConnector, MuxRekeyContext, MuxRole, MuxTransport,
	};

	#[cfg(feature = "transport-policy")]
	pub(crate) use crate::transport::messaging::{collect_step, CollectStep};
	#[cfg(feature = "transport-policy")]
	pub use crate::transport::multiplex::{GatedHalves, MuxAcceptor};
}

#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use mux::*;

/// Async transports only: the mux plane needs split halves and spawned
/// drivers, so advertising multiplexing anywhere else would negotiate a
/// capability the endpoint cannot honor.
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync> TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	/// Local mux advertisement bound into the handshake transcript; `None` advertises nothing.
	pub fn with_mux_offer(mut self, offer: impl IntoMuxOffer) -> Self {
		self.mux_config = offer.into_mux_offer();
		self
	}
}

/// Multiplexed plane assembled by [`TcpTransport::into_mux`].
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
	/// Consume a handshaken transport into its multiplexed plane:
	/// negotiated settings drive the assembly, in-band rekey wiring
	/// attaches when the session carries a dual-signed receipt, and
	/// the halves split for the mux drivers.
	///
	/// Role-fixed: callers pass the endpoint role they are assembling.
	/// Unlike the [`MuxConnector`] / `MuxAcceptor` pool traits, this
	/// works for either role without the policy plane, so WebSocket
	/// transports (native and wasm) assemble the same way.
	///
	/// # Errors
	/// - `InvalidState`: the peer did not negotiate multiplexing, or
	///   the handshake has not completed
	/// - rekey harvest / split failures from the underlying transport
	pub fn into_mux(mut self, role: MuxRole) -> TransportResult<SplitMuxTransport<S>> {
		let Some(settings) = self.negotiated_mux() else {
			return Err(TransportError::InvalidState);
		};

		let rekey = take_rekey_context(&mut self, role)?;
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
		take_rekey_context(self, MuxRole::Client)
	}

	fn handshake_peer_certificate(&self) -> Option<Arc<Certificate>> {
		self.to_peer_certificate_arc()
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

	/// Cleartext servers (no certificate) never handshake and never mux:
	/// `Ok(None)` without touching the wire.
	async fn negotiate_mux(&mut self) -> TransportResult<Option<MuxSettings>> {
		if self.to_server_certificate_ref().is_none() {
			return Ok(None);
		}

		while self.to_handshake_state() != TcpHandshakeState::Complete {
			match collect_step(self).await? {
				CollectStep::Handshake(handshake_bytes) => {
					self.perform_server_handshake(&handshake_bytes).await?;
				}
				CollectStep::Envelope(_) => return Err(TransportError::InvalidState),
			}
		}

		Ok(self.negotiated_mux())
	}

	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		take_rekey_context(self, MuxRole::Server)
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

/// Exclusive receive half of a split encrypted transport.
///
/// Owns the receive-direction cipher, so decryption needs no locks and can
/// run concurrently with a [`TransportWriter`] on the same connection.
#[cfg(feature = "x509")]
pub struct TransportReader<R>
where
	R: AsyncReadStream,
{
	stream: R,
	recv_key: RecvCipher,
	max_encrypted_envelope: Option<usize>,
	/// Per-read deadline carried across the split, matching the unsplit
	/// path: a peer that byte-drips a frame cannot pin the reader task
	/// forever (CWE-400).
	#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
	operation_timeout: Option<Duration>,
	/// Connection collector carried across the split (see
	/// [`EnvelopeSource::trace`])
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "x509")]
impl<R> TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Override the receive-direction renewal threshold counted down by
	/// `remaining_records` ([RFC 9846 § 5.5](https://datatracker.ietf.org/doc/html/rfc9846#section-5.5)).
	///
	/// Trigger policy only: decryption refuses records at the AES-GCM volume bound
	/// ([`DEFAULT_REKEY_RECORD_LIMIT`](crate::constants::DEFAULT_REKEY_RECORD_LIMIT))
	/// regardless of this value.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.recv_key = self.recv_key.with_rekey_limit(limit);
		self
	}
}

#[cfg(feature = "x509")]
impl<R> EnvelopeSource for TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Decrypt one envelope (post-handshake split: wire must be encrypted).
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let max_len = self.max_encrypted_envelope.unwrap_or(DEFAULT_MAX_ENVELOPE);

		#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
		let wire_bytes = match self.operation_timeout {
			Some(deadline) => timeout(deadline, self.stream.read_frame(Some(max_len))).await??,
			None => self.stream.read_frame(Some(max_len)).await?,
		};
		#[cfg(not(all(feature = "tokio", feature = "std", feature = "transport-policy")))]
		let wire_bytes = self.stream.read_frame(Some(max_len)).await?;

		enforce_frame_cap(&wire_bytes, Some(max_len))?;

		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(_) => Err(TransportError::MissingEncryption),
			WireEnvelope::Encrypted(encrypted_info) => {
				let decrypted_bytes = self.recv_key.decrypt_content(&encrypted_info)?;
				let decoded = decrypted_bytes.with(decode_transport_envelope).map_err(TightBeamError::from)?;

				let envelope = decoded?;
				Ok(envelope)
			}
		}
	}

	/// Records still readable before the receive cipher demands a rekey.
	fn remaining_records(&self) -> u64 {
		self.recv_key.remaining_records()
	}

	/// Swap in the new epoch's receive cipher; its fresh counter resets
	/// the sequence discipline (NIST SP 800-38D § 8.2.1: counter nonces
	/// restart only with a fresh key). The configured renewal threshold
	/// carries over so a tightened rekey cadence survives every epoch.
	fn install_recv_cipher(&mut self, cipher: RecvCipher) -> TransportResult<()> {
		self.recv_key = cipher.with_rekey_limit(self.recv_key.rekey_limit());
		Ok(())
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

/// Exclusive send half of a split encrypted transport.
///
/// Owns the send-direction cipher and its counter nonce, so encryption needs
/// no locks and can run concurrently with a [`TransportReader`] on the same
/// connection.
#[cfg(feature = "x509")]
pub struct TransportWriter<W>
where
	W: AsyncWriteStream,
{
	stream: W,
	send_key: SendCipher,
	max_encrypted_envelope: Option<usize>,
	/// Per-write deadline carried across the split, matching the unsplit
	/// path: a peer that never drains its receive buffer cannot pin the
	/// writer task forever (CWE-400).
	#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
	operation_timeout: Option<Duration>,
	/// Connection collector carried across the split (see
	/// [`EnvelopeSink::trace`])
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
	/// ([RFC 9846 § 5.5](https://datatracker.ietf.org/doc/html/rfc9846#section-5.5)).
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.send_key = self.send_key.with_rekey_limit(limit);
		self
	}
}

#[cfg(feature = "x509")]
impl<W> EnvelopeSink for TransportWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	async fn write_envelope(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		let limits = EnvelopeLimits::from_pair(None, self.max_encrypted_envelope);
		let mut builder = limits.apply(EnvelopeBuilder::transport(envelope));
		builder = builder.with_wire_mode(WireMode::Encrypted);
		builder = builder.with_encryptor(&self.send_key);

		let wire_envelope = builder.finish()?;
		let wire_bytes = wire_envelope.to_der()?;

		#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
		match self.operation_timeout {
			Some(deadline) => timeout(deadline, self.stream.write_frame(&wire_bytes)).await??,
			None => self.stream.write_frame(&wire_bytes).await?,
		}

		#[cfg(not(all(feature = "tokio", feature = "std", feature = "transport-policy")))]
		self.stream.write_frame(&wire_bytes).await?;

		Ok(())
	}

	/// Records still writable before the send cipher demands a rekey.
	fn remaining_records(&self) -> u64 {
		self.send_key.remaining_records()
	}

	/// Swap in the new epoch's send cipher; its fresh counter resets
	/// the sequence discipline (NIST SP 800-38D § 8.2.1: counter nonces
	/// restart only with a fresh key). The configured record limit
	/// carries over so a tightened rekey cadence survives every epoch.
	fn install_send_cipher(&mut self, cipher: SendCipher) -> TransportResult<()> {
		self.send_key = cipher.with_rekey_limit(self.send_key.rekey_limit());
		Ok(())
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

/// Exclusive receive half of a split cleartext transport.
///
/// Carries envelopes with NO confidentiality, integrity, replay, or deletion
/// protection. Only the size cap and frame version checks apply. Use only on
/// links trusted by other means.
#[cfg(feature = "x509")]
pub struct CleartextReader<R>
where
	R: AsyncReadStream,
{
	stream: R,
	max_cleartext_envelope: Option<usize>,
	/// Connection collector carried across the split (see
	/// [`EnvelopeSource::trace`])
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "x509")]
impl<R> EnvelopeSource for CleartextReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let max_len = self.max_cleartext_envelope.unwrap_or(DEFAULT_MAX_ENVELOPE);
		let wire_bytes = self.stream.read_frame(Some(max_len)).await?;

		enforce_frame_cap(&wire_bytes, Some(max_len))?;

		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(envelope) => ensure_compatible_versions(envelope),
			WireEnvelope::Encrypted(_) => Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed)),
		}
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

/// Exclusive send half of a split cleartext transport.
///
/// Writes envelopes with NO confidentiality, integrity, replay, or deletion
/// protection. See [`CleartextReader`] for the trust prerequisites.
#[cfg(feature = "x509")]
pub struct CleartextWriter<W>
where
	W: AsyncWriteStream,
{
	stream: W,
	max_cleartext_envelope: Option<usize>,
	/// Connection collector carried across the split (see
	/// [`EnvelopeSink::trace`])
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "x509")]
impl<W> EnvelopeSink for CleartextWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	async fn write_envelope(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		let limits = EnvelopeLimits::from_pair(self.max_cleartext_envelope, None);
		let builder = limits
			.apply(EnvelopeBuilder::transport(envelope))
			.with_wire_mode(WireMode::Cleartext);

		let wire_envelope = builder.finish()?;
		let wire_bytes = wire_envelope.to_der()?;

		self.stream.write_frame(&wire_bytes).await?;
		Ok(())
	}

	fn remaining_records(&self) -> u64 {
		u64::MAX
	}

	#[cfg(feature = "instrument")]
	fn trace(&self) -> Option<TraceCollector> {
		self.trace.as_ref().map(TraceCollector::share)
	}
}

/// Read/write halves produced by [`TcpTransport::into_split`].
#[cfg(feature = "x509")]
pub type SplitTransport<S> = (
	TransportReader<<S as SplittableStream>::ReadHalf>,
	TransportWriter<<S as SplittableStream>::WriteHalf>,
);

/// Read/write halves produced by [`TcpTransport::into_split_cleartext`].
#[cfg(feature = "x509")]
pub type CleartextSplitTransport<S> = (
	CleartextReader<<S as SplittableStream>::ReadHalf>,
	CleartextWriter<<S as SplittableStream>::WriteHalf>,
);

#[cfg(feature = "x509")]
impl<S, P> TcpTransport<S, P>
where
	S: SplittableStream,
	P: CryptoProvider + Send + Sync + 'static,
	TransportError: From<S::Error>,
{
	/// Split a fully handshaken transport into exclusive read and write halves.
	///
	/// The receive key moves into the [`TransportReader`] and the send key
	/// into the [`TransportWriter`]. Directional keys (M0) make this a clean
	/// ownership transfer with no shared mutable crypto state.
	///
	/// A configured `with_timeout` deadline carries onto both halves and
	/// bounds every read and write, exactly like the unsplit path: an idle
	/// or byte-dripping peer surfaces as `DeadlineExceeded` instead of
	/// pinning the driver task forever.
	///
	/// # Errors
	/// - `InvalidState`: handshake has not completed
	/// - `OperationFailed(EncryptorUnavailable)`: no session keys present
	pub fn into_split(mut self) -> TransportResult<SplitTransport<S>> {
		if self.to_handshake_state() != TcpHandshakeState::Complete {
			return Err(TransportError::InvalidState);
		}

		let session_keys = self
			.session_keys
			.take()
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))?;
		let (send_key, recv_key) = session_keys.into_parts();

		let max_encrypted_envelope = self.max_encrypted_envelope;

		#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
		let operation_timeout = self.operation_timeout;
		#[cfg(feature = "instrument")]
		let trace = self.trace.as_ref().map(TraceCollector::share);

		let (read_half, write_half) = self.stream.into_split();
		let reader = TransportReader {
			stream: read_half,
			recv_key,
			max_encrypted_envelope,
			#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
			operation_timeout,
			#[cfg(feature = "instrument")]
			trace: trace.as_ref().map(TraceCollector::share),
		};
		let writer = TransportWriter {
			stream: write_half,
			send_key,
			max_encrypted_envelope,
			#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
			operation_timeout,
			#[cfg(feature = "instrument")]
			trace,
		};
		Ok((reader, writer))
	}

	/// Split a never-handshaken transport into exclusive cleartext halves.
	///
	/// The halves carry envelopes with NO confidentiality, integrity, replay,
	/// or deletion protection. See [`CleartextReader`].
	///
	/// # Errors
	/// - `InvalidState`: handshake started or completed.
	/// - `MissingEncryption`: encryption material is configured.
	pub fn into_split_cleartext(self) -> TransportResult<CleartextSplitTransport<S>> {
		if self.to_handshake_state() != TcpHandshakeState::None {
			return Err(TransportError::InvalidState);
		}

		let encryption_configured = self.server_identity.is_some() || self.key_manager.is_some();
		if encryption_configured {
			return Err(TransportError::MissingEncryption);
		}

		let max_cleartext_envelope = self.max_cleartext_envelope;

		#[cfg(feature = "instrument")]
		let trace = self.trace.as_ref().map(TraceCollector::share);

		let (read_half, write_half) = self.stream.into_split();
		let reader = CleartextReader {
			stream: read_half,
			max_cleartext_envelope,
			#[cfg(feature = "instrument")]
			trace: trace.as_ref().map(TraceCollector::share),
		};
		let writer = CleartextWriter {
			stream: write_half,
			max_cleartext_envelope,
			#[cfg(feature = "instrument")]
			trace,
		};
		Ok((reader, writer))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> AsyncListenerTrait for TokioListener<P> {
	/// Delegates to the inherent accept so both entry points install the
	/// full listener state.
	async fn accept(&self) -> Result<(Self::Transport, Self::Address), Self::Error> {
		#[cfg(feature = "x509")]
		{
			let (transport, peer_addr) = TokioListener::<P>::accept(self).await?;
			Ok((transport, TightBeamSocketAddr(peer_addr)))
		}

		#[cfg(not(feature = "x509"))]
		{
			let (stream, peer_addr) = TokioListener::<P>::accept(self).await?;
			let transport = Self::create_transport(stream);
			Ok((transport, TightBeamSocketAddr(peer_addr)))
		}
	}
}

// Generates the TcpTransport struct definition and common implementations
crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope_bytes(&mut self) -> TransportResult<Vec<u8>> {
		#[cfg(feature = "x509")]
		let max_len = if self.is_handshake_pending() {
			Some(HANDSHAKE_MAX_WIRE)
		} else {
			Some(
				self.max_encrypted_envelope
					.or(self.max_cleartext_envelope)
					.unwrap_or(DEFAULT_MAX_ENVELOPE),
			)
		};

		#[cfg(not(feature = "x509"))]
		let max_len = None;

		#[cfg(feature = "tokio")]
		{
			#[cfg(feature = "x509")]
			let timeout_duration: Option<Duration> = {
				match self.to_handshake_state() {
					TcpHandshakeState::AwaitingServerResponse { initiated_at }
					| TcpHandshakeState::AwaitingClientFinish { initiated_at } => {
						let now = Instant::now();
						let deadline = initiated_at + self.handshake_timeout;
						if now >= deadline {
							return Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded));
						}

						Some(deadline.saturating_duration_since(now))
					}
					_ if self.is_handshake_pending() => Some(self.handshake_timeout),
					_ => {
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

			enforce_frame_cap(&buffer, max_len)?;
			Ok(buffer)
		}

		#[cfg(not(feature = "tokio"))]
		{
			let buffer = self.stream.read_frame(max_len).await?;
			enforce_frame_cap(&buffer, max_len)?;
			Ok(buffer)
		}
	}

	async fn write_envelope_bytes(&mut self, buffer: &[u8]) -> TransportResult<()> {
		#[cfg(all(feature = "tokio", feature = "transport-policy"))]
		if let Some(dur) = self.operation_timeout {
			timeout(dur, self.stream.write_frame(buffer)).await??;
		} else {
			self.stream.write_frame(buffer).await?;
		}

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
		let limits = EnvelopeLimits::from_pair(self.max_cleartext_envelope, self.max_encrypted_envelope);
		let mut builder = limits.apply(EnvelopeBuilder::response(response_pkg));

		if self.to_handshake_state() == TcpHandshakeState::Complete {
			let encryptor = self.to_encryptor_ref()?;
			let wire_mode = WireMode::Encrypted;
			builder = builder.with_wire_mode(wire_mode);
			builder = builder.with_encryptor(encryptor);
		} else {
			let wire_mode = WireMode::Cleartext;
			builder = builder.with_wire_mode(wire_mode);
		}

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

	/// Protocol-specific send/receive with handshake and timeout
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		self.ensure_handshake_complete().await?;

		#[cfg(feature = "tokio")]
		{
			let timeout_duration = self.operation_timeout;
			if let Some(duration) = timeout_duration {
				match timeout(duration, async { self.perform_emit_cycle(message).await }).await {
					Ok(result) => result,
					Err(_) => Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded)),
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
		transport.is_alive()
	}

	fn try_close(_transport: &mut Self::Transport) {
		// Best-effort graceful shutdown
		// TCP connections will be fully closed when transport drops
		// tokio TcpStream doesn't provide a shutdown method and relies on Drop
	}
}

#[cfg(all(test, feature = "tokio"))]
mod tests {

	use core::str::FromStr;
	use std::sync::Arc;

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use std::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::crypto::hash::Sha3_256;
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
	use crate::transport::{MessageCollector, MessageEmitter, TransportEncryptionConfig, X509ClientConfig};

	#[cfg(feature = "x509")]
	use crate::policy::TransitStatus;

	/// Serve one single-flight request: collect, apply `reply` to an
	/// accepted frame, answer with the gate's status.
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
	use crate::policy::SessionContext;
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use crate::transport::policy::PolicyConfig;

	#[cfg(all(feature = "x509", feature = "aead"))]
	mod cipher_install {
		use super::super::*;
		use crate::crypto::aead::RuntimeAead;
		use crate::oids::AES_256_GCM;
		use crate::testing::create_test_cipher_key;

		const PLAINTEXT: &[u8] = b"epoch boundary traffic";

		/// Frame stream that discards writes and yields nothing.
		struct NullStream;

		impl AsyncReadStream for NullStream {
			type Error = IoError;

			async fn read_frame(&mut self, _max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
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
			let (_key, cipher) = create_test_cipher_key();
			RuntimeAead::new(cipher, AES_256_GCM)
		}

		fn encrypted_writer(rekey_limit: u64) -> TransportWriter<NullStream> {
			TransportWriter {
				stream: NullStream,
				send_key: SendCipher::new(test_runtime()).with_rekey_limit(rekey_limit),
				max_encrypted_envelope: None,
				#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
				operation_timeout: None,
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		fn encrypted_reader() -> TransportReader<NullStream> {
			TransportReader {
				stream: NullStream,
				recv_key: RecvCipher::new(test_runtime()),
				max_encrypted_envelope: None,
				#[cfg(all(feature = "tokio", feature = "std", feature = "transport-policy"))]
				operation_timeout: None,
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		fn cleartext_writer() -> CleartextWriter<NullStream> {
			CleartextWriter {
				stream: NullStream,
				max_cleartext_envelope: None,
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		fn cleartext_reader() -> CleartextReader<NullStream> {
			CleartextReader {
				stream: NullStream,
				max_cleartext_envelope: None,
				#[cfg(feature = "instrument")]
				trace: None,
			}
		}

		#[test]
		fn writer_install_swaps_cipher_and_preserves_limit() -> Result<(), TightBeamError> {
			let mut writer = encrypted_writer(1);

			writer.send_key.encrypt_next(PLAINTEXT, None)?;
			assert_eq!(writer.remaining_records(), 0);

			// Fresh key, reset counter, preserved record policy: the
			// configured limit survives the install.
			let fresh_send = SendCipher::new(test_runtime());
			writer.install_send_cipher(fresh_send)?;
			assert_eq!(writer.remaining_records(), 1);

			writer.send_key.encrypt_next(PLAINTEXT, None)?;
			Ok(())
		}

		#[test]
		fn reader_install_swaps_cipher_and_preserves_threshold() -> Result<(), TightBeamError> {
			let sender = SendCipher::new(test_runtime());
			let record_zero = sender.encrypt_next(PLAINTEXT, None)?;
			let mut reader = encrypted_reader();
			reader.recv_key = reader.recv_key.with_rekey_limit(2);

			reader.recv_key.decrypt_content(&record_zero)?;

			let replay = reader.recv_key.decrypt_content(&record_zero);
			assert!(replay.is_err());
			assert_eq!(reader.remaining_records(), 1);

			// Fresh key is the only restart of the exact-next counter
			// (NIST SP 800-38D § 8.2.1). The renewal threshold survives
			// the install.
			let fresh_recv = RecvCipher::new(test_runtime());
			reader.install_recv_cipher(fresh_recv)?;

			assert_eq!(reader.remaining_records(), 2);

			reader.recv_key.decrypt_content(&record_zero)?;
			Ok(())
		}

		#[test]
		fn cleartext_halves_fail_closed() {
			let send_cipher = SendCipher::new(test_runtime());
			let recv_cipher = RecvCipher::new(test_runtime());

			let writer_install = cleartext_writer().install_send_cipher(send_cipher);
			assert!(matches!(writer_install, Err(TransportError::MissingEncryption)));

			let reader_install = cleartext_reader().install_recv_cipher(recv_cipher);
			assert!(matches!(reader_install, Err(TransportError::MissingEncryption)));
		}
	}

	#[cfg(feature = "x509")]
	#[tokio::test]
	async fn async_round_trip() -> TransportResult<()> {
		let (listener, client_stream) = bind_and_connect().await?;

		let request = create_v0_tightbeam(None, None);
		let expected_response = create_v0_tightbeam(None, None);

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
		let signing_key = create_test_signing_key();
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

		let config = TransportEncryptionConfig::new(cert.to_owned(), signing_key.into());
		Ok(EncryptedTestServer { cert, config })
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	fn trust_store_for(cert: Certificate) -> TransportResult<Arc<dyn CertificateTrust>> {
		let trust = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert)?
			.build();
		Ok(Arc::new(trust))
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	fn empty_trust_store() -> Arc<dyn CertificateTrust> {
		let trust = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy).build();
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

	#[cfg(feature = "x509")]
	fn tcp_transport_from(stream: TcpStream) -> TcpTransport<TokioStream> {
		let tokio_stream = TokioStream::from(stream);
		TcpTransport::from(tokio_stream)
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	fn cms_test_client(stream: TcpStream) -> TcpTransport<TokioStream> {
		let signing_key = Secp256k1SigningKey::from(create_test_signing_key());
		let key_provider = Secp256k1KeyProvider::from(signing_key);
		let provider = Arc::new(key_provider);
		let key_manager = HandshakeKeyManager::new(provider);

		let mut transport = tcp_transport_from(stream);
		transport.handshake_protocol_kind = HandshakeProtocolKind::Cms;
		transport.key_manager = Some(Arc::new(key_manager));
		transport
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	#[tokio::test]
	async fn cms_client_without_trust_store_fails_closed() -> TransportResult<()> {
		let (_listener, client_stream) = bind_and_connect().await?;
		let mut transport = cms_test_client(client_stream);

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
		let mut transport = cms_test_client(client_stream).with_trust_store(trust_store);

		let handshake = transport.perform_client_handshake().await;
		assert!(matches!(handshake, Err(TransportError::MissingServerCertificateChain)));
		Ok(())
	}

	#[cfg(all(feature = "transport-cms", feature = "transport-policy"))]
	#[tokio::test]
	async fn async_cms_round_trip() -> TransportResult<()> {
		let EncryptedTestServer { cert: server_cert, config } = encrypted_test_server()?;
		let (listener, server_addr) = bind_encrypted(config).await?;

		let request = create_v0_tightbeam(None, None);
		let expected_response = create_v0_tightbeam(None, None);

		let (received_tx, mut received_rx) = tokio::sync::mpsc::channel(1);
		let response_frame = expected_response.to_owned();
		let server_handle = tokio::spawn(async move {
			let (mut transport, _peer) = listener.accept().await?;
			transport.handshake_protocol_kind = HandshakeProtocolKind::Cms;

			respond_with(&mut transport, move |msg: Frame| {
				let _ = received_tx.try_send(msg);
				Some(response_frame.to_owned())
			})
			.await
		});

		let client_key = SigningKey::from_bytes(&[2u8; 32].into()).map_err(|_| TransportError::InvalidState)?;
		let client_cert = Arc::new(create_test_certificate(&client_key));
		let client_signing = Secp256k1SigningKey::from(client_key);
		let key_provider = Secp256k1KeyProvider::from(client_signing);
		let client_provider = Arc::new(key_provider);
		let client_keys = Arc::new(HandshakeKeyManager::new(client_provider));
		let server_chain = Arc::from(vec![server_cert.to_owned()]);
		let trust_store = trust_store_for(server_cert)?;

		let client_stream = TcpStream::connect(server_addr).await?;
		let mut transport = tcp_transport_from(client_stream)
			.with_trust_store(trust_store)
			.with_client_identity(client_cert, client_keys)
			.with_server_certificate_chain(server_chain)
			.with_handshake_protocol(HandshakeProtocolKind::Cms);

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
		config.handshake_timeout = Duration::from_millis(500);

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
		config.handshake_timeout = Duration::from_secs(5);

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

		let request = create_v0_tightbeam(None, None);
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
		let mut transport = tcp_transport_from(client_stream).with_trust_store(trust_store);

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
	// handshake must be drivable on its own: it populates the peer
	// certificate, sends no application frame, and repeats as a no-op.
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	#[tokio::test]
	async fn handshake_completes_alone_and_populates_peer_certificate() -> TransportResult<()> {
		let EncryptedTestServer { cert, config } = encrypted_test_server()?;
		let (listener, server_addr) = bind_encrypted(config).await?;

		let request = create_v0_tightbeam(None, None);
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
		let mut transport = tcp_transport_from(client_stream).with_trust_store(trust_store);
		assert!(transport.to_peer_certificate_ref().is_none());

		transport.ensure_handshake_complete().await?;
		assert!(transport.to_peer_certificate_ref().is_some());
		assert!(received_rx.try_recv().is_err());

		transport.ensure_handshake_complete().await?;
		transport.emit(request.to_owned(), None).await?;

		let received = received_rx.recv().await;
		assert_eq!(Some(request), received);

		server_handle.await??;
		Ok(())
	}
}
