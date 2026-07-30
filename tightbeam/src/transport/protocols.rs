//! Protocol trait abstractions defining what a protocol is and what it can do

use core::future::Future;
use core::time::Duration;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
use core::mem;

use crate::transport::error::{TransportError, TransportFailure};

#[cfg(all(feature = "x509", feature = "instrument"))]
use crate::trace::TraceCollector;
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::transport::framing::{
	classify_boundary_error, classify_truncation_error, parse_der_length, reconstruct_der_encoding, LengthForm,
};
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::transport::handshake::receipt::ReceiptApprover;
	pub use crate::transport::handshake::{HandshakeKeyManager, HandshakeProtocolKind};
	pub use crate::transport::TransportEncryptionConfig;
	pub use crate::x509::Certificate;
}

#[cfg(feature = "x509")]
use x509::*;

/// Marker trait for applications to handle the address the way they wish
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}

/// Stream trait - defines how to read and write
pub trait ProtocolStream: Send {
	type Error: Into<TransportError>;

	/// Write all bytes to the stream
	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;

	/// Read exact bytes from the stream
	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

	/// Set read and write timeouts on the underlying stream.
	/// Returns Ok(()) if timeouts were set, or Err if not supported.
	/// This is used for operation-level timeouts in blocking I/O.
	fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Self::Error> {
		let _ = timeout;
		// Default implementation: no-op (not supported)
		Ok(())
	}
}

/// Protocol trait - defines how to bind and connect
pub trait Protocol {
	type Listener: Send;
	type Stream: Send;
	type Transport: Send;
	type Error: Into<TransportError>;
	type Address: TightBeamAddress;

	/// Get a default address for binding to any available port/endpoint
	/// This is protocol-specific (e.g., "127.0.0.1:0" for TCP)
	fn default_bind_address() -> Result<Self::Address, Self::Error>;

	/// Bind to an address and return listener + actual bound address
	fn bind(addr: Self::Address) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;

	/// Connect to an address
	fn connect(addr: Self::Address) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;

	/// Create transport from stream
	fn create_transport(stream: Self::Stream) -> Self::Transport;
}

#[cfg(feature = "x509")]
pub trait EncryptedProtocol: Protocol {
	type Encryptor: Send;
	type Decryptor: Send;
	type CryptoProvider: CryptoProvider;

	/// Bind to an address with transport encryption configuration
	fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<Self::CryptoProvider>,
	) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// Trait for configuring client-side X.509 mutual authentication.
#[cfg(feature = "x509")]
pub trait X509ClientConfig: Sized {
	type CryptoProvider: CryptoProvider;

	/// Trust store against which the peer server certificate is validated.
	fn with_trust_store(self, store: Arc<dyn CertificateTrust>) -> Self;

	/// Client certificate + signing keys for mutual authentication.
	///
	/// Arcs so pooled connections share one identity without deep-copying
	/// the certificate per dial.
	fn with_client_identity(self, cert: Arc<Certificate>, key: Arc<HandshakeKeyManager<Self::CryptoProvider>>) -> Self;

	/// Provision the expected server certificate chain, ordered root to
	/// leaf.
	///
	/// Required for key-transport handshakes (CMS): the client encrypts the
	/// session key to the server's public key in its first message, before
	/// the server can present a certificate on the wire.
	fn with_server_certificate_chain(self, chain: Arc<[Certificate]>) -> Self;

	/// Select the handshake protocol used when encryption is enabled.
	fn with_handshake_protocol(self, kind: HandshakeProtocolKind) -> Self;

	/// Receipt approver consulted before countersigning at the handshake
	/// and each in-band epoch renewal. Without one the client fails closed
	/// on challenge-bearing receipts.
	fn with_receipt_approver(self, approver: Arc<dyn ReceiptApprover>) -> Self;

	/// Production instrumentation collector, propagated downstream
	/// (handshake, mux plane) by the transport.
	#[cfg(feature = "instrument")]
	fn with_trace(self, trace: TraceCollector) -> Self;
}

/// Async listener trait
pub trait AsyncListenerTrait: Protocol + Send {
	/// Accept one connection. The future is held across task spawns by
	/// generic accept loops (e.g. servlet serving).
	fn accept(&self) -> impl Future<Output = Result<(Self::Transport, Self::Address), Self::Error>> + MaybeSend;
}

/// Read-half capability of a frame-oriented async byte transport.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
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
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncWriteStream: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Write one complete DER-encoded envelope to the transport.
	fn write_frame(&mut self, buffer: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// A frame-oriented async byte transport carrying DER-encoded envelopes.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
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
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait SplittableStream: AsyncProtocolStream {
	type ReadHalf: AsyncReadStream<Error = Self::Error>;
	type WriteHalf: AsyncWriteStream<Error = Self::Error>;

	/// Consume the stream, yielding its read and write halves.
	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

/// Read half of an async byte-level transport: moves bytes, knows nothing
/// of envelopes. The blanket [`AsyncReadStream`] impl recovers DER framing
/// in library code, so implementations never touch wire framing.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncByteRead: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Fill `buf` completely from the transport.
	fn read_exact(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Write half of an async byte-level transport.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncByteWrite: MaybeSend + Unpin {
	type Error: Into<TransportError>;

	/// Write all of `buf` to the transport.
	fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Full-duplex async byte-level transport.
///
/// Byte-oriented transports implement this (plus the half traits) and
/// receive the frame-oriented traits through the blanket impls below;
/// message-delimited transports implement [`AsyncProtocolStream`]
/// directly instead. Trait coherence makes the two paths mutually
/// exclusive, so a byte transport cannot supply its own framing.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncByteStream: AsyncByteRead + AsyncByteWrite {
	/// Report whether the underlying transport still appears connected.
	fn is_alive(&self) -> bool;
}

#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl<T: AsyncByteRead> AsyncReadStream for T {
	type Error = TransportError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_der_frame(self, max_len).await
	}
}

#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl<T: AsyncByteWrite> AsyncWriteStream for T {
	type Error = TransportError;

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.write_all(buffer).await.map_err(Into::into)
	}
}

#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl<T: AsyncByteStream> AsyncProtocolStream for T {
	type Error = TransportError;

	async fn read_frame(&mut self, max_len: Option<usize>) -> Result<Vec<u8>, Self::Error> {
		read_der_frame(self, max_len).await
	}

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.write_all(buffer).await.map_err(Into::into)
	}

	fn is_alive(&self) -> bool {
		AsyncByteStream::is_alive(self)
	}
}

/// Read one DER-framed envelope from any async byte reader.
///
/// The single async framing-recovery path (length classification, canonical
/// enforcement, cap-before-allocate), applied through the blanket frame-trait
/// impls so no byte-level transport can diverge on wire framing.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
async fn read_der_frame<R>(stream: &mut R, max_len: Option<usize>) -> TransportResult<Vec<u8>>
where
	R: AsyncByteRead + ?Sized,
{
	// EOF before the tag is the peer closing between frames; EOF anywhere
	// after it is a truncated frame.
	let mut tag = [0u8; 1];
	stream
		.read_exact(&mut tag)
		.await
		.map_err(|e| classify_boundary_error(e.into()))?;

	let mut length_first = [0u8; 1];
	stream
		.read_exact(&mut length_first)
		.await
		.map_err(|e| classify_truncation_error(e.into()))?;

	let (length_octets, content_length) = match LengthForm::from(length_first[0]) {
		LengthForm::Short(length) => (Vec::new(), length),
		LengthForm::Long(octet_count) => {
			let mut length_octets = vec![0u8; octet_count];

			stream
				.read_exact(&mut length_octets)
				.await
				.map_err(|e| classify_truncation_error(e.into()))?;

			let length = parse_der_length(length_first[0], &length_octets).ok_or(TransportError::InvalidMessage)?;
			(length_octets, length)
		}
	};

	if let Some(max) = max_len {
		if content_length > max {
			// Refuse before allocating or reading the content (CWE-400).
			// The typed failure distinguishes an oversized frame from a malformed one.
			return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
		}
	}

	let mut content = vec![0u8; content_length];
	stream
		.read_exact(&mut content)
		.await
		.map_err(|e| classify_truncation_error(e.into()))?;

	Ok(reconstruct_der_encoding(tag[0], length_first[0], &length_octets, &content))
}

/// Largest DER header this transport accepts: tag octet, first length
/// octet, and up to `usize`-width length octets.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
const DER_HEADER_MAX: usize = 2 + mem::size_of::<usize>();

/// Defense in depth behind [`AsyncReadStream::read_frame`]: whatever code
/// framed the envelope, the bytes handed downstream must respect the cap.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub(crate) fn enforce_frame_cap(buffer: &[u8], max_len: Option<usize>) -> TransportResult<()> {
	let Some(max) = max_len else {
		return Ok(());
	};

	if buffer.len() > max.saturating_add(DER_HEADER_MAX) {
		return Err(TransportError::OperationFailed(TransportFailure::SizeExceeded));
	}

	Ok(())
}

/// Protocol supports persistent connections (keep-alive)
///
/// This trait allows protocols to opt-in to connection reuse,
/// enabling TLS handshakes to occur once per connection lifecycle
/// rather than per message.
pub trait PersistentConnection: Protocol {
	/// Check if underlying transport is still connected
	///
	/// Returns false on EOF, socket error, or explicit close.
	/// Protocols should use lightweight checks (e.g., peek) without
	/// blocking or allocating.
	fn is_connected(transport: &Self::Transport) -> bool;

	/// Attempt graceful close (best effort, no panic)
	///
	/// This is a best-effort operation that should not panic.
	/// Implementations may be no-ops if graceful close is not
	/// supported by the underlying protocol.
	fn try_close(transport: &mut Self::Transport);
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
	use std::io::{Error as IoError, ErrorKind};

	use super::*;

	/// Byte-level fixture replaying a scripted wire image; implements
	/// only the byte traits, so every frame below is recovered by the
	/// blanket impls. Exhaustion surfaces as `UnexpectedEof`, matching
	/// real byte transports.
	struct ScriptedBytes {
		data: Vec<u8>,
		pos: usize,
		written: Vec<u8>,
	}

	impl ScriptedBytes {
		fn new(data: &[u8]) -> Self {
			Self { data: data.to_vec(), pos: 0, written: Vec::new() }
		}
	}

	impl AsyncByteRead for ScriptedBytes {
		type Error = TransportError;

		async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
			let end = self.pos + buf.len();
			let chunk = self
				.data
				.get(self.pos..end)
				.ok_or_else(|| TransportError::IoError(IoError::from(ErrorKind::UnexpectedEof)))?;
			buf.copy_from_slice(chunk);
			self.pos = end;
			Ok(())
		}
	}

	impl AsyncByteWrite for ScriptedBytes {
		type Error = TransportError;

		async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
			self.written.extend_from_slice(buf);
			Ok(())
		}
	}

	impl AsyncByteStream for ScriptedBytes {
		fn is_alive(&self) -> bool {
			true
		}
	}

	#[tokio::test]
	async fn blanket_recovers_short_form_frame() -> Result<(), TransportError> {
		let wire = [0x30, 0x03, 0x01, 0x02, 0x03];
		let mut stream = ScriptedBytes::new(&wire);

		let frame = AsyncProtocolStream::read_frame(&mut stream, Some(64)).await?;
		assert_eq!(frame, wire);
		Ok(())
	}

	#[tokio::test]
	async fn blanket_recovers_long_form_frame() -> Result<(), TransportError> {
		let mut wire = vec![0x30, 0x81, 0x80];
		wire.extend_from_slice(&[0xAB; 0x80]);
		let mut stream = ScriptedBytes::new(&wire);

		let frame = AsyncProtocolStream::read_frame(&mut stream, Some(256)).await?;
		assert_eq!(frame, wire);
		Ok(())
	}

	#[tokio::test]
	async fn blanket_rejects_non_canonical_length() {
		let mut stream = ScriptedBytes::new(&[0x30, 0x81, 0x05]);

		let result = AsyncProtocolStream::read_frame(&mut stream, None).await;
		assert!(matches!(result, Err(TransportError::InvalidMessage)));
	}

	#[tokio::test]
	async fn blanket_rejects_indefinite_length() {
		let mut stream = ScriptedBytes::new(&[0x30, 0x80]);

		let result = AsyncProtocolStream::read_frame(&mut stream, None).await;
		assert!(matches!(result, Err(TransportError::InvalidMessage)));
	}

	#[tokio::test]
	async fn blanket_rejects_over_cap_before_reading_content() {
		let mut stream = ScriptedBytes::new(&[0x30, 0x82, 0x01, 0x00]);

		let result = AsyncProtocolStream::read_frame(&mut stream, Some(64)).await;
		assert!(matches!(
			result,
			Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))
		));
		// Only the header was consumed: the cap fired before any content
		// allocation or read.
		assert_eq!(stream.pos, 4);
	}

	#[tokio::test]
	async fn boundary_eof_maps_to_connection_closed() {
		let mut stream = ScriptedBytes::new(&[]);

		let result = AsyncProtocolStream::read_frame(&mut stream, None).await;
		assert!(matches!(result, Err(TransportError::ConnectionClosed)));
	}

	#[tokio::test]
	async fn truncated_frame_maps_to_invalid_message() {
		// Frame promises three content bytes, delivers one: EOF mid-frame
		// is truncation, not a clean close.
		let mut stream = ScriptedBytes::new(&[0x30, 0x03, 0x01]);

		let result = AsyncProtocolStream::read_frame(&mut stream, None).await;
		assert!(matches!(result, Err(TransportError::InvalidMessage)));
	}

	#[tokio::test]
	async fn blanket_write_frame_passes_bytes_through() -> Result<(), TransportError> {
		let mut stream = ScriptedBytes::new(&[]);

		AsyncProtocolStream::write_frame(&mut stream, &[0x30, 0x01, 0xFF]).await?;
		assert_eq!(stream.written, vec![0x30, 0x01, 0xFF]);
		Ok(())
	}

	#[test]
	fn frame_cap_guards_returned_buffers() {
		let oversized = vec![0u8; 64 + DER_HEADER_MAX + 1];

		assert!(matches!(
			enforce_frame_cap(&oversized, Some(64)),
			Err(TransportError::OperationFailed(TransportFailure::SizeExceeded))
		));
		assert!(enforce_frame_cap(&oversized, None).is_ok());
		assert!(enforce_frame_cap(&[0u8; 8], Some(64)).is_ok());
	}
}
