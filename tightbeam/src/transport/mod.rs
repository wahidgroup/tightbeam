//! Transport layer for TightBeam protocol

// Cargo features express "any of" alone, so a protocol-less TCP transport
// would compile without a handshake or message collection. Fail the build
// early with a clear message.
#[cfg(all(
	any(feature = "tcp", feature = "async-transport"),
	not(any(feature = "transport-cms", feature = "transport-ecies"))
))]
compile_error!(
	"the `tcp` and `async-transport` features require a handshake protocol: enable `transport-ecies` and/or `transport-cms`"
);

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(feature = "x509", not(feature = "std")))]
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "x509")]
use core::time::Duration;
#[cfg(feature = "std")]
use std::sync::Arc;

// Module declarations
pub mod builders;
pub mod client;
pub mod envelopes;
pub mod error;
pub mod handshake;
pub mod io;
pub mod messaging;
pub mod protocols;
pub mod state;

#[cfg(feature = "tokio")]
pub mod accept;
#[cfg(any(feature = "tcp", feature = "tokio", feature = "async-transport"))]
pub(crate) mod framing;
#[cfg(feature = "transport-multiplex")]
pub mod multiplex;
#[cfg(feature = "transport-policy")]
pub mod policy;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) mod rekey;
#[cfg(pooled_mux)]
pub mod serve;
#[cfg(any(feature = "tcp", feature = "async-transport"))]
pub mod tcp;

// Re-exports from submodules
pub use builders::EnvelopeBuilder;
pub use client::GenericClient;
pub use envelopes::{RequestPackage, ResponsePackage, TransportEnvelope, WireEnvelope, WireMode};
pub use error::{TransportError, TransportFailure};
pub use io::{EncryptedMessageIO, EnvelopeSink, EnvelopeSource, MessageIO};
pub use messaging::{MessageCollector, Transport};
pub use protocols::{
	AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol, ProtocolStream, TightBeamAddress,
	X509ClientConfig,
};

#[cfg(feature = "builder")]
pub use client::{ClientBuilder, ClientPolicies};
#[cfg(feature = "std")]
pub use client::{ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient};
#[cfg(feature = "transport-policy")]
pub use messaging::GateAudit;
#[cfg(feature = "transport-policy")]
pub use messaging::MessageEmitter;
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub use protocols::{
	AsyncByteRead, AsyncByteStream, AsyncByteWrite, AsyncProtocolStream, AsyncReadStream, AsyncWriteStream,
	SplittableStream,
};
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub use tcp::r#async::TcpTransport;
#[cfg(all(feature = "tcp", feature = "tokio"))]
pub use tcp::r#async::TokioListener;
#[cfg(all(any(feature = "tokio", feature = "async-transport"), feature = "x509"))]
pub use tcp::r#async::{CleartextReader, CleartextWriter, TransportReader, TransportWriter};

/// Transport-agnostic result type
pub type TransportResult<T> = Result<T, TransportError>;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::x509::policy::CertificateValidation;
	pub use crate::x509::Certificate;
}

#[cfg(feature = "x509")]
use x509::*;

use crate::constants::{
	DEFAULT_HANDSHAKE_MAX_WIRE, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_CLEARTEXT_ENVELOPE,
	DEFAULT_MAX_ENCRYPTED_ENVELOPE, DEFAULT_OPERATION_TIMEOUT, TIGHTBEAM_AAD_DOMAIN_TAG,
};
use crate::transport::handshake::HandshakeKeyManager;

/// Every ceiling a transport enforces, in one value.
///
/// Each field is a plain `usize` or `Duration` rather than an `Option`, so a
/// transport that forgot to configure a limit is unrepresentable.
///
/// [`Default`] is the only place these values are chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportLimits {
	/// Ceiling in bytes for a cleartext envelope on the wire.
	pub cleartext_envelope: usize,
	/// Ceiling in bytes for an encrypted envelope on the wire.
	pub encrypted_envelope: usize,
	/// Ceiling in bytes for one handshake-phase message on the wire.
	pub handshake_wire: usize,
	/// Deadline for a single read or write on the transport.
	pub operation_timeout: Duration,
	/// Deadline for the whole handshake exchange.
	pub handshake_timeout: Duration,
}

impl TransportLimits {
	/// Largest envelope this endpoint will read before parsing decides which
	/// ceiling actually applies.
	///
	/// A reader cannot know whether the bytes are a cleartext or an encrypted
	/// envelope until it has them, so it admits the larger ceiling and the
	/// per-mode check runs once the wire form is known.
	#[must_use]
	pub fn max_envelope(&self) -> usize {
		if self.encrypted_envelope > self.cleartext_envelope {
			self.encrypted_envelope
		} else {
			self.cleartext_envelope
		}
	}
}

impl Default for TransportLimits {
	fn default() -> Self {
		Self {
			cleartext_envelope: DEFAULT_MAX_CLEARTEXT_ENVELOPE,
			encrypted_envelope: DEFAULT_MAX_ENCRYPTED_ENVELOPE,
			handshake_wire: DEFAULT_HANDSHAKE_MAX_WIRE,
			operation_timeout: DEFAULT_OPERATION_TIMEOUT,
			handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
		}
	}
}

#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct TransportEncryptionConfig<P: CryptoProvider> {
	/// Identity certificate this endpoint presents during the handshake.
	pub certificate: Certificate,
	/// Signing and key-agreement material backing the certificate.
	pub key_manager: Arc<HandshakeKeyManager<P>>,
	/// Peer-certificate checks; `Some` demands mutual authentication.
	pub client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	/// Domain-separation tag bound into every AEAD associated-data block.
	pub aad_domain_tag: &'static [u8],
	/// Every ceiling this endpoint enforces.
	pub limits: TransportLimits,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> TransportEncryptionConfig<P> {
	pub fn new(certificate: Certificate, key_manager: HandshakeKeyManager<P>) -> Self {
		let key_manager = Arc::new(key_manager);
		Self {
			certificate,
			key_manager,
			client_validators: None,
			aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG,
			limits: TransportLimits::default(),
		}
	}

	/// Accepts any iterator of shared [`CertificateValidation`] values.
	pub fn with_client_validators(
		mut self,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> Self {
		let validators = Arc::new(validators.into_iter().collect::<Vec<_>>());
		self.client_validators = Some(validators);
		self
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::create_v0_tightbeam;
	use crate::transport::error::TransportFailure;
	use std::error::Error;

	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_server_and_client_macros() -> TransportResult<()> {
		use std::sync::{mpsc, Arc};

		use crate::asn1::Frame;
		use crate::transport::policy::{RestartConfig, RestartLinearBackoff};
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

		let (tx, rx) = mpsc::channel();
		let tx = Arc::new(tx);

		// Spawn server using server! macro
		let server_handle = crate::server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = Arc::clone(&tx);
				async move {
					let _ = tx.send(message);
					Ok(None)
				}
			}
		};

		// Create client using client! macro
		let mut client = crate::client! {
			connect TokioListener: addr,
			policies: {
				restart_policy: RestartLinearBackoff::default(),
			}
		};

		let message = create_v0_tightbeam(None, None);
		let result = client.emit(message.clone(), None).await;
		result?;

		let received = rx
			.recv_timeout(Duration::from_secs(1))
			.map_err(|_| TransportError::OperationFailed(error::TransportFailure::DeadlineExceeded))?;
		assert_eq!(message, received);

		server_handle.abort();

		Ok(())
	}

	/// A builder that was told nothing about limits still has them.
	///
	/// The transport previously carried `Option<usize>` ceilings defaulted to
	/// `None`, so a default endpoint read cleartext with no bound at all. Every
	/// other limit test sets a ceiling explicitly and would not have noticed.
	#[test]
	fn default_limits_bound_a_cleartext_envelope() {
		let limits = TransportLimits::default();
		assert!(limits.cleartext_envelope > 0);
		assert!(limits.encrypted_envelope > 0);
		assert!(limits.handshake_wire > 0);

		// A payload past the default ceiling is refused without the caller
		// having configured anything.
		let oversized = "a".repeat(limits.cleartext_envelope + 1);
		let frame = create_v0_tightbeam(Some(&oversized), None);
		let result = builders::EnvelopeBuilder::request(frame).finish();
		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(_, TransportFailure::SizeExceeded))
		));
	}

	/// The encrypted ceiling names the sealed wire form, not the plaintext.
	///
	/// With a ceiling set to exactly the plaintext length, the payload must
	/// still be refused: the AEAD tag, the nonce, and the `WireEnvelope`
	/// wrapper are all added after encoding, and measuring before them let an
	/// oversized envelope reach the peer as a connection reset.
	#[cfg(feature = "aes-gcm")]
	#[test]
	fn encrypted_ceiling_measures_the_sealed_wire_form() -> Result<(), Box<dyn Error>> {
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid, KeyInit, RuntimeAead, SendCipher};
		use crate::der::oid::AssociatedOid;
		use crate::der::Encode;

		let frame = create_v0_tightbeam(None, None);
		let plaintext_len = TransportEnvelope::from(frame.clone()).to_der()?.len();
		let cipher = Aes256Gcm::new_from_slice(&[0u8; 32])
			.map_err(|_| TransportError::OperationFailed(TransportFailure::Internal))?;

		let encryptor = SendCipher::new(RuntimeAead::new(cipher, Aes256GcmOid::OID));
		let result = builders::EnvelopeBuilder::request(frame)
			.with_wire_mode(WireMode::Encrypted)
			.with_encryptor(&encryptor)
			.with_limits(TransportLimits { encrypted_envelope: plaintext_len, ..TransportLimits::default() })
			.finish();

		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(_, TransportFailure::SizeExceeded))
		));

		Ok(())
	}

	#[cfg(feature = "aes-gcm")]
	#[test]
	fn test_envelope_builder_encrypted_limit_returns_message() -> Result<(), Box<dyn Error>> {
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid, KeyInit, RuntimeAead, SendCipher};
		use crate::der::oid::AssociatedOid;

		let frame = create_v0_tightbeam(None, None);
		let cipher = Aes256Gcm::new_from_slice(&[0u8; 32])
			.map_err(|_| TransportError::OperationFailed(TransportFailure::Internal))?;

		let encryptor = SendCipher::new(RuntimeAead::new(cipher, Aes256GcmOid::OID));
		let result = builders::EnvelopeBuilder::request(frame.clone())
			.with_wire_mode(WireMode::Encrypted)
			.with_encryptor(&encryptor)
			.with_limits(TransportLimits { encrypted_envelope: 1, ..TransportLimits::default() })
			.finish();

		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(ref returned, TransportFailure::SizeExceeded)) if **returned == frame
		));

		Ok(())
	}

	#[test]
	fn test_envelope_builder_cleartext_limit_returns_message() {
		let frame = create_v0_tightbeam(None, None);
		let result = builders::EnvelopeBuilder::request(frame.clone())
			.with_limits(TransportLimits { cleartext_envelope: 1, ..TransportLimits::default() })
			.finish();

		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(ref returned, TransportFailure::SizeExceeded)) if **returned == frame
		));
	}
}
