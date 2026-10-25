//! Transport layer for the TightBeam protocol.

// A Cargo feature can require only all of a list, so `tcp` alone would
// compile a transport with no handshake and no message collection. The build
// fails here and names the protocol features to enable.
#[cfg(all(
	any(feature = "tcp", feature = "async-transport"),
	not(any(feature = "transport-cms", feature = "transport-hpke"))
))]
compile_error!(
	"the `tcp` and `async-transport` features require a handshake protocol: enable `transport-hpke` and/or `transport-cms`"
);

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
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
pub mod policy;
pub mod protocols;
pub mod state;

#[cfg(feature = "tokio")]
pub mod accept;
#[cfg(any(feature = "tcp", feature = "tokio", feature = "async-transport"))]
pub(crate) mod framing;
#[cfg(feature = "transport-multiplex")]
pub mod multiplex;
#[cfg(mux_rekey)]
pub(crate) mod rekey;
#[cfg(any(feature = "tcp", feature = "async-transport"))]
pub mod tcp;

pub use crate::asn1::wire_der;
pub use builders::EnvelopeBuilder;
pub use client::GenericClient;
pub use client::{ClientBuilder, ClientPolicies};
pub use envelopes::{Arrived, RequestPackage, ResponsePackage, TransportEnvelope, WireEnvelope, WireMode};
pub use error::{TransportError, TransportFailure};
pub use io::{EncryptedMessageIO, EnvelopeSink, EnvelopeSource, MessageIO};
pub use messaging::GateAudit;
pub use messaging::MessageEmitter;
pub use messaging::{MessageCollector, Transport};
pub use protocols::{
	AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol, ProtocolStream, TightBeamAddress,
};

#[cfg(feature = "std")]
pub use client::{ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient};
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub use protocols::{
	AsyncByteRead, AsyncByteStream, AsyncByteWrite, AsyncProtocolStream, AsyncReadStream, AsyncWriteStream,
	SplittableStream,
};
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub use tcp::r#async::TcpTransport;
#[cfg(all(feature = "tcp", feature = "tokio"))]
pub use tcp::r#async::TokioListener;
#[cfg(any(feature = "tokio", feature = "async-transport"))]
pub use tcp::r#async::{TransportReader, TransportWriter};

/// Transport-agnostic result type.
pub type TransportResult<T> = Result<T, TransportError>;

use crate::constants::{
	DEFAULT_HANDSHAKE_MAX_WIRE, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_CLEARTEXT_ENVELOPE,
	DEFAULT_MAX_ENCRYPTED_ENVELOPE, DEFAULT_OPERATION_TIMEOUT,
};
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::policy::CertificateValidation;
use crate::transport::handshake::PeerAuthentication;
use crate::transport::state::{DialableEncryption, EncryptionConfig, Negotiation};

use crate::transport::state::ServerIdentities;
use crate::utils::time::Clock;
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
use crate::crypto::cms::KeyAgreementIdentity;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::KeyPurposes;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::{CmsIdentityPair, HandshakeError};
#[cfg(host_clock)]
use crate::utils::time::SystemClock;

/// Every ceiling a transport enforces, in one value.
///
/// Each field is a plain `usize` or `Duration` rather than an `Option`, so a
/// transport that forgot to configure a limit is unrepresentable.
///
/// [`Default`] is the one place that chooses these values.
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
	/// Returns the largest envelope this endpoint reads before parsing decides
	/// which ceiling applies.
	///
	/// A reader learns whether the bytes are a cleartext or an encrypted
	/// envelope only once it has them, so it admits the larger ceiling, and the
	/// per-mode check runs once the reader knows the wire form.
	#[must_use]
	pub fn max_envelope(&self) -> usize {
		if self.encrypted_envelope > self.cleartext_envelope {
			self.encrypted_envelope
		} else {
			self.cleartext_envelope
		}
	}

	/// The ceiling in bytes of a wire envelope of `mode`. A write and a read
	/// both take their ceiling from here.
	pub(crate) const fn envelope_ceiling(&self, mode: WireMode) -> usize {
		match mode {
			WireMode::Cleartext => self.cleartext_envelope,
			WireMode::Encrypted => self.encrypted_envelope,
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

/// The configuration of a server endpoint under provider `P`: the identity it
/// presents, how it authenticates its client, the key purposes its handshakes
/// admit, and the ceilings it enforces.
///
/// It converts into [`DialableEncryption`] through
/// [`DialableEncryption::new`], the one guard of every provisioning.
#[derive(Clone)]
#[non_exhaustive]
pub struct TransportEncryptionConfig<P: CryptoProvider> {
	/// The certificate this endpoint presents during the handshake, with the
	/// key that signs for it, and for a CMS server its key-agreement identity.
	pub(crate) identity: ServerIdentities<P>,
	/// How this server authenticates its client.
	pub(crate) peer_authentication: PeerAuthentication,
	/// The key purpose of each role the server's handshakes admit.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) key_purposes: KeyPurposes,
	/// Every ceiling this endpoint enforces.
	pub(crate) limits: TransportLimits,
	/// The provider the endpoint's handshakes run under.
	_provider: core::marker::PhantomData<fn() -> P>,
}

impl<P: CryptoProvider> TryFrom<TransportEncryptionConfig<P>> for DialableEncryption<P> {
	type Error = TransportError;

	/// The one place a server's configuration becomes provisioning.
	///
	/// The conversion runs [`DialableEncryption::new`], the one guard of every
	/// provisioning, which admits the identity for the server purpose once. A
	/// server presents a certificate, which answers for the peer, so the dialer
	/// rule holds for every configuration of this shape. [`EndpointConfig`]
	/// carries `limits` beside this value, outside provisioning.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the errors of [`DialableEncryption::new`].
	fn try_from(config: TransportEncryptionConfig<P>) -> TransportResult<Self> {
		let encryption = EncryptionConfig {
			server_identity: Some(config.identity),
			peer_authentication: config.peer_authentication,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			key_purposes: config.key_purposes,
			..EncryptionConfig::unconfigured()
		};

		Self::new(encryption)
	}
}

/// Everything a transport is built from: provisioning that answered the
/// dialer rule, its negotiation input, the ceilings it enforces, and the clock
/// it measures against.
///
/// Listeners, clients, and pools each build one of these, and every transport
/// constructor takes it whole, so every transport holds all four. A clone
/// copies `Arc` handles, so it shares each certificate with the original.
pub struct EndpointConfig<P: CryptoProvider> {
	pub(crate) encryption: DialableEncryption<P>,
	pub(crate) negotiation: Negotiation,
	pub(crate) limits: TransportLimits,
	pub(crate) clock: Arc<dyn Clock>,

	#[cfg(feature = "instrument")]
	pub(crate) trace: Option<TraceCollector>,
}

impl<P: CryptoProvider> EndpointConfig<P> {
	/// Returns an endpoint for `encryption` that measures time against `clock`,
	/// with the default ceilings.
	pub fn new(encryption: impl Into<DialableEncryption<P>>, clock: Arc<dyn Clock>) -> Self {
		Self {
			encryption: encryption.into(),
			negotiation: Negotiation::default(),
			limits: TransportLimits::default(),
			clock,
			#[cfg(feature = "instrument")]
			trace: None,
		}
	}

	/// Returns a cleartext endpoint on the operating system's clocks.
	///
	/// Frames travel with no confidentiality, integrity, or peer
	/// authentication. See [`DialableEncryption::cleartext`].
	#[cfg(host_clock)]
	pub fn cleartext() -> Self {
		Self::new(DialableEncryption::cleartext(), Arc::new(SystemClock))
	}

	/// Replace the negotiation input each transport built from this
	/// configuration starts with.
	#[must_use]
	pub(crate) fn with_negotiation(mut self, negotiation: Negotiation) -> Self {
		self.negotiation = negotiation;
		self
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

	/// Return the provisioning this endpoint holds.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		self.encryption.encryption()
	}

	/// Return every ceiling this endpoint enforces.
	pub fn limits(&self) -> &TransportLimits {
		&self.limits
	}
}

impl<P: CryptoProvider> Clone for EndpointConfig<P> {
	fn clone(&self) -> Self {
		Self {
			encryption: self.encryption.clone(),
			negotiation: self.negotiation.clone(),
			limits: self.limits,
			clock: Arc::clone(&self.clock),
			#[cfg(feature = "instrument")]
			trace: self.trace.as_ref().map(TraceCollector::share),
		}
	}
}

/// Converts a server configuration into an endpoint on the operating system's
/// clocks that enforces the ceilings `config` names.
#[cfg(host_clock)]
impl<P: CryptoProvider> TryFrom<TransportEncryptionConfig<P>> for EndpointConfig<P> {
	type Error = TransportError;

	/// # Errors
	///
	/// - [`TransportError`] -- the errors of the [`DialableEncryption`] conversion.
	fn try_from(config: TransportEncryptionConfig<P>) -> TransportResult<Self> {
		let limits = config.limits;
		let encryption = DialableEncryption::try_from(config)?;
		Ok(Self::new(encryption, Arc::new(SystemClock)).with_limits(limits))
	}
}

impl<P: CryptoProvider> TransportEncryptionConfig<P> {
	/// Create a server configuration that presents `identity`.
	///
	/// The identity pairs the certificate with the key that signs for it, so
	/// the two arrive checked against each other.
	pub fn new(identity: SigningIdentity) -> Self {
		Self {
			identity: identity.into(),
			peer_authentication: PeerAuthentication::Anonymous,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			key_purposes: KeyPurposes::default(),
			limits: TransportLimits::default(),
			_provider: core::marker::PhantomData,
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
	/// nothing, so an empty set leaves the endpoint where it was, and an
	/// endpoint that demands mutual authentication keeps demanding it.
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

	/// Return every ceiling this endpoint enforces.
	pub fn limits(&self) -> &TransportLimits {
		&self.limits
	}

	/// Set the key purpose of each role: the purpose the server's own
	/// certificates carry, and the purpose a client's certificate carries.
	/// The default is [`KeyPurposes::HOUSE`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[must_use]
	pub fn with_key_purposes(mut self, key_purposes: KeyPurposes) -> Self {
		self.key_purposes = key_purposes;
		self
	}

	/// Return the identity certificate this endpoint presents during the
	/// handshake, the one whose key signs its replies.
	pub fn certificate(&self) -> &Certificate {
		self.identity.signing().certificate()
	}
}

#[cfg(feature = "transport-cms")]
impl<P: CryptoProvider> TransportEncryptionConfig<P> {
	/// Pair the signing identity this endpoint presents with `key_agreement`,
	/// the identity the CMS opening seals to, once, as a
	/// [`CmsIdentityPair`].
	///
	/// A server of the CMS flow needs the pair, and a server of the HPKE flow
	/// signs with the signing identity alone.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
	/// - [`HandshakeError::CertificateValidationError`] -- a `subjectAltName`
	///   of an empty subject fails to decode.
	/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key.
	pub fn with_key_agreement(self, key_agreement: KeyAgreementIdentity<P::Kem>) -> Result<Self, HandshakeError> {
		let signing = self.identity.into_signing();
		let pair = CmsIdentityPair::new(signing, key_agreement)?;
		Ok(Self { identity: ServerIdentities::Cms(pair), ..self })
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
	#[cfg(feature = "testing")]
	#[test]
	fn an_empty_validator_set_keeps_the_configured_authentication() {
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::x509::policy::ExpiryValidator;
		use crate::testing::fixtures::TestIdentity;

		let identity = TestIdentity::insecure_fixed();
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
		let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
		let mutual = config.with_client_validators([validator]);

		let config = mutual.with_client_validators([]);
		assert!(config.peer_authentication.requires_certificate());
	}

	/// Both `bind_cleartext` arms of `server!` expand and bind on the tokio
	/// runtime, with policies and with none.
	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn the_bind_cleartext_arms_of_the_server_macro_bind() -> TransportResult<()> {
		use crate::asn1::Frame;
		use crate::trace::TraceCollector;
		use crate::transport::tcp::r#async::TokioListener;

		let addr = <TokioListener as Protocol>::default_bind_address()?;
		let trace = TraceCollector::new();

		let plain = crate::server! {
			protocol TokioListener: bind_cleartext addr,
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		};
		let traced = crate::server! {
			protocol TokioListener: bind_cleartext addr,
			policies: { with_trace: [ trace.share() ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		};

		plain.abort();
		traced.abort();
		Ok(())
	}

	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_server_and_client_macros() -> TransportResult<()> {
		use std::sync::{mpsc, Arc};

		use crate::asn1::Frame;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

		let (tx, rx) = mpsc::channel();
		let tx = Arc::new(tx);

		let server_handle = crate::server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = Arc::clone(&tx);
				async move {
					// The receiver lives for the whole test, so a refused send
					// surfaces as the missing message the assertion below
					// reads.
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

	/// A builder with no configured limits still enforces the defaults.
	///
	/// A default endpoint reads cleartext under a bound. Every other limit test
	/// sets a ceiling explicitly, so only this test covers the default.
	#[test]
	fn default_limits_bound_a_cleartext_envelope() {
		let limits = TransportLimits::default();
		assert!(limits.cleartext_envelope > 0);
		assert!(limits.encrypted_envelope > 0);
		assert!(limits.handshake_wire > 0);

		// The builder refuses a payload past the default ceiling, though the
		// caller configured nothing.
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
	/// With a ceiling of exactly the plaintext length, the builder must still
	/// refuse the payload. The AEAD tag, the nonce, and the `WireEnvelope`
	/// wrapper all come after encoding, so a measurement before them would let
	/// an oversized envelope reach the peer as a connection reset.
	#[test]
	fn encrypted_ceiling_measures_the_sealed_wire_form() -> Result<(), Box<dyn Error>> {
		use crate::crypto::aead::{RecordDirection, RuntimeAead, SendCipher};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::der::Encode;

		let frame = TestFrame::v0(None, None);
		let plaintext_len = TransportEnvelope::from(frame.clone()).to_der()?.len();
		let cipher = RuntimeAead::new::<DefaultCryptoProvider>(vec![0u8; 32])?;

		let encryptor = SendCipher::new(cipher, 0, RecordDirection::ClientToServer);
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

	#[test]
	fn test_envelope_builder_encrypted_limit_returns_message() -> Result<(), Box<dyn Error>> {
		use crate::crypto::aead::{RecordDirection, RuntimeAead, SendCipher};
		use crate::crypto::profiles::DefaultCryptoProvider;

		let frame = TestFrame::v0(None, None);
		let cipher = RuntimeAead::new::<DefaultCryptoProvider>(vec![0u8; 32])?;

		let encryptor = SendCipher::new(cipher, 0, RecordDirection::ClientToServer);
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
