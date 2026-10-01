//! Protocol traits that define what a transport protocol is and what it can
//! do.

use core::future::Future;
use core::time::Duration;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::transport::error::TransportError;
use crate::utils::marker::MaybeSend;

#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::transport::framing::{FrameHeader, HeaderPrefix, LengthForm};
#[cfg(any(feature = "tokio", feature = "async-transport"))]
use crate::transport::TransportResult;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::transport::{EndpointConfig, TransportEncryptionConfig};
}

#[cfg(feature = "x509")]
use x509::*;

/// Marker trait for a protocol address, which an application may represent
/// the way it wishes.
pub trait TightBeamAddress: Into<Vec<u8>> + Clone + Send {}

/// Blocking byte stream that a protocol reads from and writes to.
pub trait ProtocolStream: Send {
	/// Error the stream reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Write all of `buf` to the stream.
	///
	/// # Errors
	///
	/// The stream's own error when the write fails.
	fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;

	/// Fill `buf` exactly from the stream.
	///
	/// # Errors
	///
	/// The stream's own error when the read fails or the stream ends early.
	fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;

	/// Arm the read and write deadline for every later operation on the
	/// stream, or clear it with `None`.
	///
	/// The blocking transport arms its handshake and operation deadlines
	/// through this method and treats `Ok` as armed, so a stream that
	/// cannot bound its I/O MUST return an error instead of succeeding with
	/// no deadline. Every stream states its own answer.
	///
	/// # Errors
	///
	/// The stream's own error when the deadline cannot be armed.
	fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Self::Error>;
}

/// Transport protocol that binds listeners, connects streams, and builds
/// transports over them.
pub trait Protocol {
	/// Listener that accepts inbound connections.
	type Listener: Send;
	/// Connected byte stream.
	type Stream: Send;
	/// Transport built over one stream.
	type Transport: Send;
	/// Error the protocol reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;
	/// Address the protocol binds and connects to.
	type Address: TightBeamAddress;
	/// Crypto provider every transport of this protocol is built with.
	type CryptoProvider: CryptoProvider + Send + Sync + 'static;

	/// A default address that binds to any available port or endpoint.
	///
	/// The address is protocol-specific, such as `127.0.0.1:0` for TCP.
	///
	/// # Errors
	///
	/// The protocol's error when it cannot form a default address.
	fn default_bind_address() -> Result<Self::Address, Self::Error>;

	/// Bind to `addr`, returning the listener and the address it actually
	/// bound.
	///
	/// # Errors
	///
	/// The protocol's error when the bind fails.
	fn bind(addr: Self::Address) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;

	/// Connect to `addr`.
	///
	/// # Errors
	///
	/// The protocol's error when the connection fails.
	fn connect(addr: Self::Address) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;

	/// Build a transport over `stream` from `config`.
	///
	/// The configuration carries provisioning that already answered the
	/// dialer rule, so every transport this protocol builds either holds a
	/// peer authority or was named cleartext.
	fn create_transport(stream: Self::Stream, config: EndpointConfig<Self::CryptoProvider>) -> Self::Transport;
}

/// Protocol whose listeners bind with transport encryption.
#[cfg(feature = "x509")]
pub trait EncryptedProtocol: Protocol {
	/// Encryptor the protocol's transports seal outbound envelopes with.
	type Encryptor: Send;
	/// Decryptor the protocol's transports open inbound envelopes with.
	type Decryptor: Send;

	/// Bind to `addr` with the transport encryption `config`.
	///
	/// # Errors
	///
	/// The protocol's error when the bind fails.
	fn bind_with(
		addr: Self::Address,
		config: TransportEncryptionConfig<Self::CryptoProvider>,
	) -> impl Future<Output = Result<(Self::Listener, Self::Address), Self::Error>> + Send;
}

/// Protocol whose listener accepts connections asynchronously.
pub trait AsyncListenerTrait: Protocol + Send {
	/// Accept one connection.
	///
	/// Generic accept loops, such as servlet serving, hold the future across
	/// task spawns.
	///
	/// # Errors
	///
	/// The protocol's error when the accept fails.
	fn accept(&self) -> impl Future<Output = Result<(Self::Transport, Self::Address), Self::Error>> + MaybeSend;
}

/// Read-half capability of a frame-oriented async byte transport.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncReadStream: MaybeSend + Unpin {
	/// Error the stream reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Read one complete DER-encoded envelope from the transport.
	///
	/// `cap` is the largest envelope content length the caller accepts. An
	/// implementation MUST refuse a frame whose declared length exceeds `cap`
	/// before sizing any buffer. Every implementation in this crate reaches a
	/// content length only after that check has run.
	///
	/// # Errors
	///
	/// The stream's error, including the refusal of a frame past `cap`.
	fn read_frame(&mut self, cap: usize) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;
}

/// Write-half capability of a frame-oriented async byte transport.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncWriteStream: MaybeSend + Unpin {
	/// Error the stream reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Write one complete DER-encoded envelope to the transport.
	///
	/// # Errors
	///
	/// The stream's error when the write fails.
	fn write_frame(&mut self, buffer: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// A frame-oriented async byte transport carrying DER-encoded envelopes.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncProtocolStream: MaybeSend + Unpin {
	/// Error the stream reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Read one complete DER-encoded envelope from the transport.
	///
	/// `cap` is the largest envelope content length the caller accepts. An
	/// implementation MUST refuse a frame whose declared length exceeds `cap`
	/// before sizing any buffer. Every implementation in this crate reaches a
	/// content length only after that check has run.
	///
	/// # Errors
	///
	/// The stream's error, including the refusal of a frame past `cap`.
	fn read_frame(&mut self, cap: usize) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;

	/// Write one complete DER-encoded envelope to the transport.
	///
	/// # Errors
	///
	/// The stream's error when the write fails.
	fn write_frame(&mut self, buffer: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

	/// Report whether the underlying transport still appears connected.
	fn is_alive(&self) -> bool;
}

/// A stream that can be decomposed into independently owned read and write
/// halves, enabling concurrent reader and writer tasks over one connection.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait SplittableStream: AsyncProtocolStream {
	/// Read half, which reports the stream's own error type.
	type ReadHalf: AsyncReadStream<Error = Self::Error>;
	/// Write half, which reports the stream's own error type.
	type WriteHalf: AsyncWriteStream<Error = Self::Error>;

	/// Consume the stream, yielding its read and write halves.
	fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

/// Read half of an async byte-level transport, which moves bytes and leaves
/// envelopes to library code.
///
/// The blanket [`AsyncReadStream`] impl recovers DER framing, so
/// implementations never touch wire framing.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncByteRead: MaybeSend + Unpin {
	/// Error the transport reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Fill `buf` completely from the transport.
	///
	/// # Errors
	///
	/// The transport's error when the read fails or the stream ends early.
	fn read_exact(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Write half of an async byte-level transport.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncByteWrite: MaybeSend + Unpin {
	/// Error the transport reports, convertible into a [`TransportError`].
	type Error: Into<TransportError>;

	/// Write all of `buf` to the transport.
	///
	/// # Errors
	///
	/// The transport's error when the write fails.
	fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Full-duplex async byte-level transport.
///
/// Byte-oriented transports implement this, plus the half traits, and receive
/// the frame-oriented traits through the blanket impls below. Message-delimited
/// transports implement [`AsyncProtocolStream`] directly instead. Trait
/// coherence makes the two paths mutually exclusive, so a byte transport cannot
/// supply its own framing.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub trait AsyncByteStream: AsyncByteRead + AsyncByteWrite {
	/// Report whether the underlying transport still appears connected.
	fn is_alive(&self) -> bool;
}

/// Recover DER framing over any byte reader through the one framing path.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl<T: AsyncByteRead> AsyncReadStream for T {
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		read_der_frame(self, cap).await
	}
}

/// Write each frame through the byte writer as one complete buffer.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl<T: AsyncByteWrite> AsyncWriteStream for T {
	type Error = TransportError;

	async fn write_frame(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.write_all(buffer).await.map_err(Into::into)
	}
}

/// Give every full-duplex byte transport the frame-oriented stream, with the
/// framing path of the half impls.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
impl<T: AsyncByteStream> AsyncProtocolStream for T {
	type Error = TransportError;

	async fn read_frame(&mut self, cap: usize) -> Result<Vec<u8>, Self::Error> {
		read_der_frame(self, cap).await
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
/// This is the single async framing-recovery path, which classifies the
/// length, enforces canonical encoding, and checks the cap before it
/// allocates. The blanket frame-trait impls apply it, so no byte-level
/// transport can diverge on wire framing.
#[cfg(any(feature = "tokio", feature = "async-transport"))]
async fn read_der_frame<R>(stream: &mut R, cap: usize) -> TransportResult<Vec<u8>>
where
	R: AsyncByteRead + ?Sized,
{
	// EOF before the tag is the peer closing between frames. EOF anywhere after
	// it is a truncated frame.
	let mut tag = [0u8; 1];
	stream.read_exact(&mut tag).await.map_err(|e| (e.into()).at_frame_boundary())?;

	let mut length_first = [0u8; 1];
	stream
		.read_exact(&mut length_first)
		.await
		.map_err(|e| (e.into()).inside_frame())?;

	let length_octets = match LengthForm::from(length_first[0]) {
		LengthForm::Short(_) => Vec::new(),
		LengthForm::Long(octet_count) => {
			let mut length_octets = vec![0u8; octet_count];

			stream
				.read_exact(&mut length_octets)
				.await
				.map_err(|e| (e.into()).inside_frame())?;

			length_octets
		}
	};

	// Refuse before allocating or reading the content (CWE-400). `content_len`
	// exists only on an admitted header, so the buffer below cannot be sized
	// by a length this cap has not seen.
	let prefix = HeaderPrefix { tag: tag[0], length_first: length_first[0] };
	let header = FrameHeader::parse(prefix, length_octets)?.admit(cap)?;

	let mut content = vec![0u8; header.content_len()];
	stream.read_exact(&mut content).await.map_err(|e| (e.into()).inside_frame())?;

	Ok(header.reconstruct(&content))
}

/// Protocol that supports persistent connections, or keep-alive.
///
/// A protocol opts in to connection reuse through this trait, so a TLS-style
/// handshake runs once per connection lifecycle instead of once per message.
pub trait PersistentConnection: Protocol {
	/// Whether the underlying transport is still connected.
	///
	/// Returns `false` on EOF, a socket error, or an explicit close. A protocol
	/// should use a lightweight check, such as a peek, that neither blocks nor
	/// allocates.
	fn is_connected(transport: &Self::Transport) -> bool;

	/// Attempt a best-effort graceful close.
	///
	/// The close should not panic. An implementation may do nothing when the
	/// underlying protocol has no graceful close.
	fn try_close(transport: &mut Self::Transport);
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
	use std::io::{Error as IoError, ErrorKind};

	use super::*;
	use crate::transport::error::TransportFailure;

	/// Byte-level fixture that replays a scripted wire image. It implements
	/// only the byte traits, so the blanket impls recover every frame below.
	/// Exhaustion surfaces as `UnexpectedEof`, matching real byte transports.
	struct ScriptedBytes {
		data: Vec<u8>,
		pos: usize,
		written: Vec<u8>,
	}

	impl ScriptedBytes {
		fn new(data: impl AsRef<[u8]>) -> Self {
			let data = data.as_ref();
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
		let mut stream = ScriptedBytes::new(wire);
		let frame = AsyncProtocolStream::read_frame(&mut stream, 64).await?;
		assert_eq!(frame, wire);
		Ok(())
	}

	#[tokio::test]
	async fn blanket_recovers_long_form_frame() -> Result<(), TransportError> {
		let mut wire = vec![0x30, 0x81, 0x80];
		wire.extend_from_slice(&[0xAB; 0x80]);

		let mut stream = ScriptedBytes::new(&wire);
		let frame = AsyncProtocolStream::read_frame(&mut stream, 256).await?;
		assert_eq!(frame, wire);
		Ok(())
	}

	#[tokio::test]
	async fn blanket_rejects_non_canonical_length() {
		let mut stream = ScriptedBytes::new([0x30, 0x81, 0x05]);
		let result = AsyncProtocolStream::read_frame(&mut stream, 1024).await;
		assert!(matches!(result, Err(TransportError::InvalidMessage)));
	}

	#[tokio::test]
	async fn blanket_rejects_indefinite_length() {
		let mut stream = ScriptedBytes::new([0x30, 0x80]);
		let result = AsyncProtocolStream::read_frame(&mut stream, 1024).await;
		assert!(matches!(result, Err(TransportError::InvalidMessage)));
	}

	#[tokio::test]
	async fn blanket_rejects_over_cap_before_reading_content() {
		let mut stream = ScriptedBytes::new([0x30, 0x82, 0x01, 0x00]);
		let result = AsyncProtocolStream::read_frame(&mut stream, 64).await;
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
		let mut stream = ScriptedBytes::new([]);
		let result = AsyncProtocolStream::read_frame(&mut stream, 1024).await;
		assert!(matches!(result, Err(TransportError::ConnectionClosed)));
	}

	#[tokio::test]
	async fn truncated_frame_maps_to_invalid_message() {
		// The frame promises three content bytes and delivers one, so EOF
		// mid-frame is truncation and not a clean close.
		let mut stream = ScriptedBytes::new([0x30, 0x03, 0x01]);
		let result = AsyncProtocolStream::read_frame(&mut stream, 1024).await;
		assert!(matches!(result, Err(TransportError::InvalidMessage)));
	}

	#[tokio::test]
	async fn blanket_write_frame_passes_bytes_through() -> Result<(), TransportError> {
		let mut stream = ScriptedBytes::new([]);
		AsyncProtocolStream::write_frame(&mut stream, &[0x30, 0x01, 0xFF]).await?;
		assert_eq!(stream.written, vec![0x30, 0x01, 0xFF]);
		Ok(())
	}
}
