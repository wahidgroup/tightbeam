use core::future::Future;
use std::io::Error as IoError;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "tokio")]
mod tokio_rt {
	pub use std::io::ErrorKind;
	pub use std::net::SocketAddr;
	pub use std::time::Instant;

	pub(crate) use crate::transport::io::{parse_der_length, reconstruct_der_encoding};
	pub use crate::transport::protocols::PersistentConnection;
	pub use crate::transport::tcp::TightBeamSocketAddr;
	pub use crate::transport::{AsyncListenerTrait, Mycelial, Protocol};
	pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
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
use crate::transport::handshake::negotiation::{MuxSettings, TransportOffer};
use crate::transport::io::{decode_transport_envelope, ensure_compatible_versions};
use crate::transport::tcp::HANDSHAKE_MAX_WIRE;
use crate::transport::ResponsePackage;
use crate::transport::{
	EnvelopeBuilder, EnvelopeLimits, MessageCollector, MessageEmitter, MessageIO, Pingable, TransportError,
	TransportResult, WireMode,
};
use crate::Frame;
use crate::TightBeamError;

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

pub use crate::utils::marker::MaybeSend;

/// Read-half capability of a frame-oriented async byte transport.
pub trait AsyncReadStream: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Read one complete DER-encoded envelope from the transport.
	///
	/// `max_len` is the largest envelope content length the caller accepts. An
	/// implementation MUST reject a frame whose declared length exceeds it
	/// before allocating, to bound memory use.
	fn read_frame(&mut self, max_len: Option<usize>) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// Write-half capability of a frame-oriented async byte transport.
pub trait AsyncWriteStream: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Write one complete DER-encoded envelope to the transport.
	fn write_frame(&mut self, buffer: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// A frame-oriented async byte transport carrying DER-encoded envelopes.
pub trait AsyncProtocolStream: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Read one complete DER-encoded envelope from the transport.
	///
	/// `max_len` is the largest envelope content length the caller accepts. An
	/// implementation MUST reject a frame whose declared length exceeds it
	/// before allocating, to bound memory use.
	fn read_frame(&mut self, max_len: Option<usize>) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;

	/// Write one complete DER-encoded envelope to the transport.
	fn write_frame(&mut self, buffer: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

	/// Report whether the underlying transport still appears connected.
	fn is_alive(&self) -> bool;
}

/// A stream that can be decomposed into independently owned read and write
/// halves, enabling concurrent reader and writer tasks over one connection.
pub trait SplittableStream: AsyncProtocolStream {
	type ReadHalf: AsyncReadStream<Error = Self::Error>;
	type WriteHalf: AsyncWriteStream<Error = Self::Error>;

	/// Consume the stream, yielding its read and write halves.
	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

#[cfg(feature = "tokio")]
pub struct TokioStream {
	stream: TcpStream,
}

/// Read one DER-framed envelope from any tokio byte reader.
///
/// Shared by the whole stream and its split read half so the length-cap and
/// canonical-length enforcement cannot diverge between the two paths.
#[cfg(feature = "tokio")]
async fn read_der_frame<R>(stream: &mut R, max_len: Option<usize>) -> Result<Vec<u8>, IoError>
where
	R: AsyncRead + Unpin,
{
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

		let length =
			parse_der_length(length_first[0], &length_octets).ok_or_else(|| IoError::from(ErrorKind::InvalidData))?;
		(length_octets, length)
	};

	if let Some(max) = max_len {
		if content_length > max {
			return Err(IoError::from(ErrorKind::InvalidData));
		}
	}

	let mut content = vec![0u8; content_length];
	stream.read_exact(&mut content).await?;

	Ok(reconstruct_der_encoding(tag[0], length_first[0], &length_octets, &content))
}

#[cfg(feature = "tokio")]
impl AsyncProtocolStream for TokioStream {
	type Error = IoError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_der_frame(&mut self.stream, max_len).await
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.stream.write_all(buffer).await
	}

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
impl AsyncReadStream for TokioReadHalf {
	type Error = IoError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_der_frame(&mut self.half, max_len).await
	}
}

/// Owned write half of a [`TokioStream`].
#[cfg(feature = "tokio")]
pub struct TokioWriteHalf {
	half: OwnedWriteHalf,
}

#[cfg(feature = "tokio")]
impl AsyncWriteStream for TokioWriteHalf {
	type Error = IoError;

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.half.write_all(buffer).await
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

	pub async fn bind(addr: &str) -> Result<Self, IoError> {
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
	pub async fn accept(&self) -> Result<(TokioStream, SocketAddr), IoError> {
		let (stream, addr) = self.listener.accept().await?;
		Ok((TokioStream::from(stream), addr))
	}

	#[cfg(feature = "x509")]
	pub async fn accept(&self) -> Result<(TcpTransport<TokioStream, P>, SocketAddr), IoError> {
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
		Ok(TokioStream::from(stream))
	}

	fn create_transport(stream: Self::Stream) -> Self::Transport {
		TcpTransport::from(stream)
	}

	fn to_tightbeam_addr(&self) -> Result<Self::Address, Self::Error> {
		Ok(TightBeamSocketAddr(self.local_addr()?))
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

#[cfg(feature = "x509")]
impl<S: AsyncProtocolStream, P: CryptoProvider + Send + Sync + 'static> EncryptedProtocolState for TcpTransport<S, P>
where
	TransportError: From<S::Error>,
{
	type CryptoProvider = P;

	fn to_encryptor_ref(&self) -> TransportResult<&SendCipher> {
		let session_keys = self.session_keys.as_ref();
		session_keys
			.map(SessionKeys::send)
			.ok_or(TransportError::OperationFailed(TransportFailure::EncryptorUnavailable))
	}

	fn to_decryptor_ref(&self) -> TransportResult<&RecvCipher> {
		let session_keys = self.session_keys.as_ref();
		session_keys
			.map(SessionKeys::recv)
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

	fn set_session_keys(&mut self, keys: SessionKeys) {
		// Replace existing keys, ensuring the old key material is dropped immediately
		let _ = self.session_keys.take();
		self.session_keys = Some(keys);
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

	fn to_server_certificate_chain_ref(&self) -> Option<&Arc<[Certificate]>> {
		self.server_certificate_chain.as_ref()
	}

	fn to_server_handshake_mut(&mut self) -> &mut Option<BoxedServerHandshake> {
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

	fn unset_session_keys(&mut self) {
		self.session_keys = None;
	}

	fn to_mux_config(&self) -> Option<TransportOffer> {
		self.mux_config
	}

	fn set_mux_settings(&mut self, settings: Option<MuxSettings>) {
		self.mux_settings = settings;
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
	pub use crate::transport::multiplex::{MuxCapable, MuxConnector};

	#[cfg(feature = "transport-policy")]
	pub use crate::policy::AcceptAllGate;
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
	/// Set the local mux advertisement, bound into the handshake
	/// transcript. `None` advertises nothing.
	///
	/// Inherent so concrete callers need no [`MuxCapable`] import.
	pub fn with_mux_offer(mut self, offer: Option<TransportOffer>) -> Self {
		self.mux_config = offer;
		self
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
	fn with_mux_offer(self, offer: Option<TransportOffer>) -> Self {
		// Inherent method wins lookup, so this is not self-recursion
		self.with_mux_offer(offer)
	}

	fn negotiated_mux(&self) -> Option<MuxSettings> {
		// Inherent getter shared by all TCP transports
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
	S::ReadHalf: Send + 'static,
	S::WriteHalf: Send + 'static,
	TransportError: From<S::Error>,
{
	type EnvelopeReader = TransportReader<S::ReadHalf>;
	type EnvelopeWriter = TransportWriter<S::WriteHalf>;

	async fn complete_client_handshake(&mut self) -> TransportResult<()> {
		self.ensure_handshake_complete().await
	}

	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)> {
		self.into_split()
	}
}

#[cfg(all(
	feature = "x509",
	feature = "transport-policy",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
impl<S> MuxAcceptor for TcpTransport<S>
where
	S: SplittableStream,
	S::ReadHalf: Send + 'static,
	S::WriteHalf: Send + 'static,
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

	fn into_gated_halves(mut self) -> TransportResult<GatedHalves<Self>> {
		let gate = core::mem::replace(&mut self.collector_gate, Box::new(AcceptAllGate));
		let halves = self.into_split()?;
		Ok((gate, halves))
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
}

#[cfg(feature = "x509")]
impl<R> TransportReader<R>
where
	R: AsyncReadStream,
	TransportError: From<R::Error>,
{
	/// Override the receive cipher's rekey record limit (RFC 8446 § 5.5).
	/// MUST be at least the peer's send limit or legitimate records near
	/// the limit are refused.
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
	/// Read and decrypt one transport envelope.
	///
	/// The split exists only after handshake completion, so every inbound
	/// wire envelope must be encrypted.
	async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
		let max_len = self.max_encrypted_envelope.unwrap_or(DEFAULT_MAX_ENVELOPE);
		let wire_bytes = self.stream.read_frame(Some(max_len)).await?;

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
}

#[cfg(feature = "x509")]
impl<W> TransportWriter<W>
where
	W: AsyncWriteStream,
	TransportError: From<W::Error>,
{
	/// Override the send cipher's rekey record limit (RFC 8446 § 5.5).
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
	/// Encrypt and write one transport envelope.
	async fn write_envelope(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		let limits = EnvelopeLimits::from_pair(None, self.max_encrypted_envelope);
		let mut builder = limits.apply(EnvelopeBuilder::transport(envelope));
		builder = builder.with_wire_mode(WireMode::Encrypted);
		builder = builder.with_encryptor(&self.send_key);

		let wire_envelope = builder.finish()?;
		let wire_bytes = wire_envelope.to_der()?;

		self.stream.write_frame(&wire_bytes).await?;
		Ok(())
	}

	/// Records still writable before the send cipher demands a rekey.
	fn remaining_records(&self) -> u64 {
		self.send_key.remaining_records()
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

		let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
		match wire_envelope {
			WireEnvelope::Cleartext(envelope) => ensure_compatible_versions(envelope),
			WireEnvelope::Encrypted(_) => Err(TransportError::OperationFailed(TransportFailure::EncryptionFailed)),
		}
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

	/// Cleartext link never rekeys.
	fn remaining_records(&self) -> u64 {
		u64::MAX
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

		let (read_half, write_half) = self.stream.into_split();

		let reader = TransportReader { stream: read_half, recv_key, max_encrypted_envelope };
		let writer = TransportWriter { stream: write_half, send_key, max_encrypted_envelope };
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
		let (read_half, write_half) = self.stream.into_split();

		let reader = CleartextReader { stream: read_half, max_cleartext_envelope };
		let writer = CleartextWriter { stream: write_half, max_cleartext_envelope };
		Ok((reader, writer))
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

		Ok((transport, TightBeamSocketAddr(addr)))
	}
}

#[cfg(feature = "tokio")]
impl<P: CryptoProvider + Send + Sync> Mycelial for TokioListener<P> {
	async fn try_available_connect(&self) -> Result<(Self::Listener, Self::Address), Self::Error> {
		// Bind to an available port (0.0.0.0:0 lets the OS choose)
		let addr = "0.0.0.0:0"
			.parse::<TightBeamSocketAddr>()
			.map_err(|e| IoError::new(ErrorKind::InvalidInput, e))?;
		<TokioListener<P> as Protocol>::bind(addr).await
	}
}

impl<S: AsyncProtocolStream> Pingable for TcpTransport<S>
where
	TransportError: From<S::Error>,
	TransportError: From<IoError>,
{
	fn ping(&mut self) -> TransportResult<()> {
		if self.stream.is_alive() {
			Ok(())
		} else {
			Err(TransportError::ConnectionClosed)
		}
	}
}

// Generates the TcpTransport struct definition and common implementations
crate::impl_tcp_common!(TcpTransport, AsyncProtocolStream);

impl<S: AsyncProtocolStream> MessageIO for TcpTransport<S>
where
	TransportError: From<S::Error>,
{
	async fn read_envelope(&mut self) -> TransportResult<Vec<u8>> {
		// Reads from an unauthenticated peer (handshake pending) get the
		// tight handshake cap.
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

		// The tokio runtime supplies `tokio::time::timeout`: non-tokio runtimes
		// (e.g. wasm/gloo) have no portable timer here, so they read without a
		// deadline. The handshake clock is likewise absent off-tokio.
		#[cfg(feature = "tokio")]
		{
			// Determine timeout duration: prefer handshake_timeout during
			// handshake operation_timeout otherwise.
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
			let wire_mode = WireMode::Encrypted;
			builder = builder.with_wire_mode(wire_mode);
			builder = builder.with_encryptor(encryptor);
		} else {
			let wire_mode = WireMode::Cleartext;
			builder = builder.with_wire_mode(wire_mode);
		}

		let wire_envelope = builder.build()?;
		let wire_bytes = wire_envelope.to_der()?;

		self.write_envelope(&wire_bytes).await?;
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
		self.emitter_gate.as_ref()
	}

	/// Protocol-specific send/receive with handshake and timeout
	async fn perform_send_receive(
		&mut self,
		message: Frame,
	) -> TransportResult<(TransitStatus, Option<Frame>, Option<Frame>)> {
		// Ensure handshake is complete
		self.ensure_handshake_complete().await?;

		// Perform send/receive with optional timeout (tokio only; non-tokio
		// runtimes have no portable timer and emit without a deadline).
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
	use core::str::FromStr;
	use std::sync::Arc;

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use std::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey, SigningKey};
	use crate::crypto::sign::Sha3Signer;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::prelude::TightBeamSocketAddr;
	use crate::spki::SubjectPublicKeyInfoOwned;
	use crate::testing::*;
	use crate::transport::handshake::{HandshakeError, HandshakeKeyManager, HandshakeProtocolKind};
	use crate::transport::io::EncryptedMessageIO;
	use crate::transport::{
		MessageCollector, MessageEmitter, ResponseHandler, TransportEncryptionConfig, X509ClientConfig,
	};

	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use crate::policy::TransitStatus;
	#[cfg(all(feature = "transport-policy", feature = "transport-ecies"))]
	use crate::transport::policy::PolicyConf;

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
			let handler = Box::new(move |msg: Frame| {
				let _ = tx.try_send(msg);
				Some(response_msg.clone())
			});
			let mut transport = transport.with_handler(handler);

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

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	fn cms_test_client(stream: TcpStream) -> TcpTransport<TokioStream> {
		let signing_key = Secp256k1SigningKey::from(create_test_signing_key());
		let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));

		let mut transport = TcpTransport::from(TokioStream::from(stream));
		transport.handshake_protocol_kind = HandshakeProtocolKind::Cms;
		transport.key_manager = Some(Arc::new(HandshakeKeyManager::new(provider)));

		transport
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	#[tokio::test]
	async fn cms_client_without_trust_store_fails_closed() -> TransportResult<()> {
		let listener: TokioListener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let stream = TcpStream::connect(addr).await?;

		let mut transport = cms_test_client(stream);

		let result = transport.perform_client_handshake().await;
		assert!(matches!(
			result,
			Err(TransportError::HandshakeError(HandshakeError::MissingTrustStore))
		));
		Ok(())
	}

	#[cfg(all(feature = "x509", feature = "transport-cms"))]
	#[tokio::test]
	async fn cms_client_without_server_chain_fails_closed() -> TransportResult<()> {
		let listener: TokioListener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let stream = TcpStream::connect(addr).await?;

		let trust_store: Arc<dyn CertificateTrust> =
			Arc::new(CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy).build());
		let mut transport = cms_test_client(stream).with_trust_store(trust_store);

		let result = transport.perform_client_handshake().await;
		assert!(matches!(result, Err(TransportError::MissingServerCertificateChain)));
		Ok(())
	}

	#[cfg(all(feature = "transport-cms", feature = "transport-policy"))]
	#[tokio::test]
	async fn async_cms_round_trip() -> TransportResult<()> {
		let signing_key = create_test_signing_key();
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let sha3_signer = Sha3Signer::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

		let server_cert = crate::cert!(
			profile: Root,
			subject: "CN=Test Root CA,O=Test Org,C=US",
			serial: 1u32,
			duration: Duration::from_secs(365 * 24 * 60 * 60),
			signer: &sha3_signer,
			subject_public_key: spki
		)?;

		let addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
		let config = TransportEncryptionConfig::new(server_cert.clone(), signing_key.into());
		let (listener, socket_addr) = TokioListener::bind_with(addr, config).await?;

		let test_message = create_v0_tightbeam(None, None);
		let expected_response = create_v0_tightbeam(None, None);

		let (tx, mut rx) = tokio::sync::mpsc::channel(1);
		let response_msg = expected_response.clone();
		let server_handle = tokio::spawn(async move {
			let (mut transport, _) = listener.accept().await?;
			transport.handshake_protocol_kind = HandshakeProtocolKind::Cms;

			let handler = Box::new(move |msg: Frame| {
				let _ = tx.try_send(msg);
				Some(response_msg.clone())
			});

			let mut transport = transport.with_handler(handler);
			transport.handle_request().await
		});

		// Distinct client identity: its own key pair and self-signed certificate.
		let client_key = SigningKey::from_bytes(&[2u8; 32].into()).map_err(|_| TransportError::InvalidState)?;
		let client_cert = create_test_certificate(&client_key);
		let signing_key = Secp256k1SigningKey::from(client_key);
		let key_provider = Secp256k1KeyProvider::from(signing_key);
		let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(key_provider);

		let trust_store: Arc<dyn CertificateTrust> = {
			let certificate = server_cert.clone();
			Arc::new(
				CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
					.with_certificate(certificate)?
					.build(),
			)
		};

		let cert = Arc::new(client_cert);
		let key = Arc::new(HandshakeKeyManager::new(client_provider));
		let chain = Arc::from(vec![server_cert]);

		let stream = TcpStream::connect(*socket_addr).await?;
		let mut transport = TcpTransport::from(TokioStream::from(stream));
		transport = transport.with_trust_store(trust_store);
		transport = transport.with_client_identity(cert, key);
		transport = transport.with_server_certificate_chain(chain);
		transport = transport.with_handshake_protocol(HandshakeProtocolKind::Cms);

		let response = transport.emit(test_message.clone(), None).await?;
		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert_eq!(response, Some(expected_response));

		server_handle.await??;
		Ok(())
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	fn encrypted_test_config() -> TransportResult<TransportEncryptionConfig<DefaultCryptoProvider>> {
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

		Ok(TransportEncryptionConfig::new(cert, signing_key.into()))
	}

	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	#[tokio::test]
	async fn handshake_read_deadline_bounds_silent_client() -> TransportResult<()> {
		let mut config = encrypted_test_config()?;
		config.handshake_timeout = Duration::from_millis(500);

		let addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
		let (listener, socket_addr) = TokioListener::bind_with(addr, config).await?;

		let server_handle = tokio::spawn(async move {
			let (mut transport, _) = listener.accept().await?;
			transport.handle_request().await
		});

		let _silent_client = TcpStream::connect(*socket_addr).await?;

		let joined = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
		assert!(matches!(joined, Ok(Ok(Err(_)))));
		Ok(())
	}

	/// A handshake-phase frame whose declared length exceeds the 16 KiB
	/// handshake cap must be rejected on the declared length, before the body
	/// is read.
	#[cfg(all(feature = "x509", feature = "transport-policy"))]
	#[tokio::test]
	async fn handshake_read_rejects_oversize_frame_before_body() -> TransportResult<()> {
		let mut config = encrypted_test_config()?;
		config.handshake_timeout = Duration::from_secs(5);

		let addr = TightBeamSocketAddr::from_str("127.0.0.1:0")?;
		let (listener, socket_addr) = TokioListener::bind_with(addr, config).await?;

		let server_handle = tokio::spawn(async move {
			let (mut transport, _) = listener.accept().await?;
			transport.handle_request().await
		});

		let mut stream = TcpStream::connect(*socket_addr).await?;
		// SEQUENCE header declaring 65536 content bytes, body never sent.
		stream.write_all(&[0x30, 0x83, 0x01, 0x00, 0x00]).await?;

		let started = Instant::now();
		let joined = tokio::time::timeout(Duration::from_secs(4), server_handle).await;
		assert!(matches!(joined, Ok(Ok(Err(_)))));
		assert!(started.elapsed() < Duration::from_secs(2));
		Ok(())
	}

	// Exercises the default (ECIES) handshake end to end.
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
			fn evaluate(&self, _msg: &Frame) -> TransitStatus {
				if self.first.swap(false, Ordering::SeqCst) {
					TransitStatus::ResourceExhausted
				} else {
					TransitStatus::Ok
				}
			}
		}

		let signing_key = create_test_signing_key();
		let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
		let sha3_signer = Sha3Signer::from(&signing_key);
		let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

		// Create a self-signed root certificate
		let cert = crate::cert!(
			profile: Root,
			subject: "CN=Test Root CA,O=Test Org,C=US",
			serial: 1u32,
			duration: Duration::from_secs(365 * 24 * 60 * 60),
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
			let handler = Box::new(move |msg: Frame| {
				let _ = tx.try_send(msg.clone());
				Some(msg)
			});
			let mut transport = transport.with_collector_gate(BusyFirstGate::new()).with_handler(handler);

			// First handle_request: processes handshake (ClientHello + ClientKeyExchange)
			// and first application message. Gate returns ResourceExhausted for first app message.
			let result = transport.handle_request().await;
			result?;

			// Second handle_request: processes second application message
			// Gate returns Ok this time
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
		// Gate policy returns ResourceExhausted for first application message
		let first = transport.emit(test_message.clone(), None).await;
		assert!(matches!(
			first,
			Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted))
		));

		// Second emit sends encrypted message, gate returns Ok
		transport.emit(test_message.clone(), None).await?;

		let received = rx.recv().await;
		assert_eq!(Some(test_message), received);
		assert!(rx.try_recv().is_err());

		server_handle.await??;
		Ok(())
	}
}
