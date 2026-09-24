//! Transport layer for the TightBeam protocol.

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
#[cfg(feature = "x509")]
use core::time::Duration;
#[cfg(feature = "std")]
use std::sync::Arc;

pub mod builders;
pub mod client;
pub mod envelopes;
pub mod error;
pub mod handshake;
pub mod io;
pub mod messaging;
pub mod protocols;
pub mod state;
pub mod wire_der;

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

pub use builders::EnvelopeBuilder;
pub use client::GenericClient;
pub use envelopes::{RequestPackage, ResponsePackage, TransportEnvelope, WireEnvelope, WireMode};
pub use error::{TransportError, TransportFailure};
pub use io::{EncryptedMessageIO, EnvelopeSink, EnvelopeSource, MessageIO};
pub use messaging::{MessageCollector, Transport};
pub use protocols::{
	AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol, ProtocolStream, TightBeamAddress,
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
pub use tcp::r#async::{TransportReader, TransportWriter};

/// Transport-agnostic result type.
pub type TransportResult<T> = Result<T, TransportError>;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::x509::policy::CertificateValidation;
	pub use crate::transport::handshake::PeerAuthentication;
	pub use crate::transport::state::{DialableEncryption, EncryptionConfig};
	pub use crate::utils::time::Clock;
	pub use crate::x509::Certificate;

	#[cfg(feature = "instrument")]
	pub use crate::trace::TraceCollector;
	#[cfg(host_clock)]
	pub use crate::utils::time::SystemClock;
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
#[non_exhaustive]
pub struct TransportEncryptionConfig<P: CryptoProvider> {
	/// Identity certificate this endpoint presents during the handshake.
	pub(crate) certificate: Arc<Certificate>,
	/// Signing and key-agreement material backing the certificate.
	pub(crate) key_manager: Arc<HandshakeKeyManager<P>>,
	/// How this server authenticates its client.
	pub(crate) peer_authentication: PeerAuthentication,
	/// Domain-separation tag bound into every AEAD associated-data block.
	pub(crate) aad_domain_tag: &'static [u8],
	/// Every ceiling this endpoint enforces.
	pub(crate) limits: TransportLimits,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> From<TransportEncryptionConfig<P>> for DialableEncryption<P> {
	/// The one place a server's configuration becomes provisioning.
	///
	/// A server presents a certificate, which is one of the things that answers
	/// for the peer, so the dialer rule holds for every configuration of this
	/// shape and is discharged by the type rather than by a check. `limits` is
	/// not provisioning, so [`EndpointConfig`] carries it beside this value.
	fn from(config: TransportEncryptionConfig<P>) -> Self {
		let encryption = EncryptionConfig {
			server_certificate: Some(config.certificate),
			peer_authentication: config.peer_authentication,
			aad_domain_tag: config.aad_domain_tag,
			key_manager: Some(config.key_manager),
			..EncryptionConfig::unconfigured()
		};

		Self::from_peer_authority(encryption)
	}
}

/// Everything a transport is built from: provisioning that answered the
/// dialer rule, the ceilings it enforces, and the clock it measures against.
///
/// Listeners, clients, and pools each build one of these, and every transport
/// constructor takes it whole, so no transport exists without all three. A
/// clone bumps refcounts and copies no certificate.
#[cfg(feature = "x509")]
pub struct EndpointConfig<P: CryptoProvider> {
	pub(crate) encryption: DialableEncryption<P>,
	pub(crate) limits: TransportLimits,
	pub(crate) clock: Arc<dyn Clock>,
	#[cfg(feature = "instrument")]
	pub(crate) trace: Option<TraceCollector>,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> EndpointConfig<P> {
	/// An endpoint for `encryption` that measures time against `clock`, with
	/// the default ceilings.
	pub fn new(encryption: impl Into<DialableEncryption<P>>, clock: Arc<dyn Clock>) -> Self {
		Self {
			encryption: encryption.into(),
			limits: TransportLimits::default(),
			clock,
			#[cfg(feature = "instrument")]
			trace: None,
		}
	}

	/// A cleartext endpoint on the operating system's clocks.
	///
	/// Frames travel with no confidentiality, integrity, or peer
	/// authentication. See [`DialableEncryption::cleartext`].
	#[cfg(host_clock)]
	pub fn cleartext() -> Self {
		Self::new(DialableEncryption::cleartext(), Arc::new(SystemClock))
	}

	/// Replace every ceiling this endpoint enforces.
	#[must_use]
	pub fn with_limits(mut self, limits: TransportLimits) -> Self {
		self.limits = limits;
		self
	}

	/// Replace the clock this endpoint measures deadlines and backoff against.
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Attach the production instrumentation collector each transport built
	/// from this configuration shares.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// Return the provisioning this endpoint was given.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		self.encryption.encryption()
	}

	/// Return every ceiling this endpoint enforces.
	pub fn limits(&self) -> &TransportLimits {
		&self.limits
	}
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> Clone for EndpointConfig<P> {
	fn clone(&self) -> Self {
		Self {
			encryption: self.encryption.clone(),
			limits: self.limits,
			clock: Arc::clone(&self.clock),
			#[cfg(feature = "instrument")]
			trace: self.trace.as_ref().map(TraceCollector::share),
		}
	}
}

/// A server endpoint on the operating system's clocks, enforcing the
/// ceilings `config` names.
#[cfg(all(feature = "x509", host_clock))]
impl<P: CryptoProvider> From<TransportEncryptionConfig<P>> for EndpointConfig<P> {
	fn from(config: TransportEncryptionConfig<P>) -> Self {
		let limits = config.limits;

		Self::new(config, Arc::new(SystemClock)).with_limits(limits)
	}
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> TransportEncryptionConfig<P> {
	/// Create a server configuration from its certificate and key manager.
	///
	/// `certificate` accepts an owned certificate or a handle to a shared one,
	/// so a caller that already parsed its identity hands it over without
	/// copying it.
	pub fn new(certificate: impl Into<Arc<Certificate>>, key_manager: impl Into<Arc<HandshakeKeyManager<P>>>) -> Self {
		let certificate = certificate.into();
		let key_manager = key_manager.into();
		Self {
			certificate,
			key_manager,
			peer_authentication: PeerAuthentication::Anonymous,
			aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG,
			limits: TransportLimits::default(),
		}
	}

	/// Name the validators that authenticate the client.
	///
	/// `validators` accepts any iterator of shared [`CertificateValidation`]
	/// values. Naming validators demands mutual authentication, and the set
	/// replaces any set named before.
	///
	/// # Empty set
	///
	/// [`PeerAuthentication::mutual`] decides that an empty set demands
	/// nothing, so an empty set leaves the endpoint where it was and never
	/// turns mutual authentication off.
	#[must_use]
	pub fn with_client_validators(
		mut self,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> Self {
		let demanded = PeerAuthentication::mutual(validators);
		if demanded.requires_certificate() {
			self.peer_authentication = demanded;
		}

		self
	}

	/// Replace every ceiling this endpoint enforces.
	#[must_use]
	pub fn with_limits(mut self, limits: TransportLimits) -> Self {
		self.limits = limits;
		self
	}

	/// Replace the domain-separation tag of the ECIES key exchange.
	///
	/// The ECIES handshake binds this tag into the associated data of the
	/// encrypted key exchange, so an ECIES session completes only when both
	/// endpoints hold the same tag. The CMS handshake and session records do
	/// not read it.
	#[must_use]
	pub fn with_aad_domain_tag(mut self, tag: &'static [u8]) -> Self {
		self.aad_domain_tag = tag;
		self
	}

	/// Return every ceiling this endpoint enforces.
	pub fn limits(&self) -> &TransportLimits {
		&self.limits
	}

	/// Return the identity certificate this endpoint presents during the
	/// handshake.
	pub fn certificate(&self) -> &Certificate {
		&self.certificate
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::TestFrame;
	use crate::transport::error::TransportFailure;
	use std::error::Error;

	/// An empty validator set demands nothing, so it leaves an endpoint that
	/// already demands mutual authentication where it was.
	#[cfg(all(feature = "testing", feature = "secp256k1"))]
	#[test]
	fn an_empty_validator_set_keeps_the_configured_authentication() {
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::x509::policy::ExpiryValidator;
		use crate::testing::fixtures::{TestCertificate, TestKey};
		use crate::transport::handshake::HandshakeKeyManager;

		let key = TestKey::signing();
		let certificate = TestCertificate::self_signed(&key);
		let key_manager = HandshakeKeyManager::<DefaultCryptoProvider>::from(key);
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
		let mutual = TransportEncryptionConfig::new(certificate, key_manager).with_client_validators([validator]);

		let config = mutual.with_client_validators([]);
		assert!(config.peer_authentication.requires_certificate());
	}

	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_server_and_client_macros() -> TransportResult<()> {
		use std::sync::{mpsc, Arc};

		use crate::asn1::Frame;
		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

		let (tx, rx) = mpsc::channel();
		let tx = Arc::new(tx);

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

		let mut client = crate::client! {
			connect TokioListener: addr,
			cleartext,
			policies: {
				restart_policy: RestartLinearBackoff::default(),
			}
		};

		let message = TestFrame::v0(None, None);
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
	/// A default endpoint reads cleartext under a bound. Every other limit test
	/// sets a ceiling explicitly, so only this test covers the default.
	#[test]
	fn default_limits_bound_a_cleartext_envelope() {
		let limits = TransportLimits::default();
		assert!(limits.cleartext_envelope > 0);
		assert!(limits.encrypted_envelope > 0);
		assert!(limits.handshake_wire > 0);

		// A payload past the default ceiling is refused without the caller
		// having configured anything.
		let oversized = "a".repeat(limits.cleartext_envelope + 1);
		let frame = TestFrame::v0(Some(&oversized), None);
		let result = builders::EnvelopeBuilder::request(frame).finish();
		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(_, TransportFailure::SizeExceeded))
		));
	}

	/// The encrypted ceiling measures the sealed wire form instead of the
	/// plaintext.
	///
	/// With a ceiling set to exactly the plaintext length, the payload must
	/// still be refused. The AEAD tag, the nonce, and the `WireEnvelope`
	/// wrapper are all added after encoding, so a measurement before them would
	/// let an oversized envelope reach the peer as a connection reset.
	#[cfg(feature = "aes-gcm")]
	#[test]
	fn encrypted_ceiling_measures_the_sealed_wire_form() -> Result<(), Box<dyn Error>> {
		use crate::crypto::aead::{Aes256Gcm, KeyInit, RuntimeAead, SendCipher};
		use crate::der::Encode;

		let frame = TestFrame::v0(None, None);
		let plaintext_len = TransportEnvelope::from(frame.clone()).to_der()?.len();
		let cipher = Aes256Gcm::new_from_slice(&[0u8; 32])
			.map_err(|_| TransportError::OperationFailed(TransportFailure::Internal))?;

		let encryptor = SendCipher::new(RuntimeAead::new(cipher));
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
		use crate::crypto::aead::{Aes256Gcm, KeyInit, RuntimeAead, SendCipher};

		let frame = TestFrame::v0(None, None);
		let cipher = Aes256Gcm::new_from_slice(&[0u8; 32])
			.map_err(|_| TransportError::OperationFailed(TransportFailure::Internal))?;

		let encryptor = SendCipher::new(RuntimeAead::new(cipher));
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
		let frame = TestFrame::v0(None, None);
		let result = builders::EnvelopeBuilder::request(frame.clone())
			.with_limits(TransportLimits { cleartext_envelope: 1, ..TransportLimits::default() })
			.finish();
		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(ref returned, TransportFailure::SizeExceeded)) if **returned == frame
		));
	}
}
