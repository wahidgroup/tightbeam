//! The transport layer of the TightBeam protocol.

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

use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
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

mod limits;

#[cfg(feature = "std")]
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
pub use error::{LimitsRefusal, Result as TransportResult, TransportError, TransportFailure};
pub use io::{EncryptedMessageIO, EnvelopeSink, EnvelopeSource, MessageIO};
pub use limits::{CheckedLimits, TransportLimits};
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

use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::policy::CertificateValidation;
use crate::transport::handshake::PeerAuthentication;
use crate::transport::state::{DialableEncryption, EncryptionConfig, Negotiation};

use crate::clock::Clock;
use crate::transport::state::ServerIdentities;
use crate::x509::Certificate;

#[cfg(host_clock)]
use crate::clock::SystemClock;
#[cfg(feature = "transport-cms")]
use crate::crypto::cms::KeyAgreementIdentity;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::KeyPurposes;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::{CmsIdentityPair, HandshakeError};

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
	/// The rule by which this server authenticates its client.
	pub(crate) peer_authentication: PeerAuthentication,
	/// The key purpose of each role the server's handshakes admit.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) key_purposes: KeyPurposes,
	/// Every ceiling this endpoint enforces.
	pub(crate) limits: CheckedLimits,
	/// The provider the endpoint's handshakes run under.
	_provider: core::marker::PhantomData<fn() -> P>,
}

impl<P: CryptoProvider> TryFrom<TransportEncryptionConfig<P>> for DialableEncryption<P> {
	type Error = TransportError;

	/// The one place a server's configuration becomes provisioning.
	///
	/// [`DialableEncryption::new`] admits the identity for the server purpose
	/// once. A server presents a certificate that answers for the peer, so
	/// every such configuration holds the dialer rule. `limits` stay outside
	/// provisioning, beside this value on [`EndpointConfig`].
	///
	/// # Errors
	///
	/// - [`TransportError`] -- an error of [`DialableEncryption::new`].
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

/// The inputs of a transport: the provisioning that answered the dialer rule,
/// its negotiation input, the ceilings it enforces, and the clock it measures
/// against.
///
/// Listeners, clients, and pools each build one, and every transport
/// constructor takes it whole, so every transport holds all four. A clone
/// shares each certificate with the original through its `Arc` handles.
pub struct EndpointConfig<P: CryptoProvider> {
	pub(crate) encryption: DialableEncryption<P>,
	pub(crate) negotiation: Negotiation,
	pub(crate) limits: CheckedLimits,
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
			limits: CheckedLimits::default(),
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

	/// Replaces the negotiation input each transport built from this
	/// configuration starts with.
	#[must_use]
	pub(crate) fn with_negotiation(mut self, negotiation: Negotiation) -> Self {
		self.negotiation = negotiation;
		self
	}

	/// Replaces every ceiling this endpoint enforces with `limits`, once
	/// [`TransportLimits::checked`] admits them.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidLimits`] -- the errors of [`TransportLimits::checked`].
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::transport::{EndpointConfig, TransportLimits};
	///
	/// // An endpoint that gives each read and each write 5 seconds.
	/// let limits = TransportLimits { operation_timeout: Duration::from_secs(5), ..TransportLimits::default() };
	/// let endpoint = EndpointConfig::<DefaultCryptoProvider>::cleartext().with_limits(limits)?;
	/// assert_eq!(endpoint.limits().operation_timeout, Duration::from_secs(5));
	/// # Ok::<(), tightbeam::transport::TransportError>(())
	/// ```
	pub fn with_limits(mut self, limits: TransportLimits) -> TransportResult<Self> {
		self.limits = limits.checked()?;
		Ok(self)
	}

	/// Replaces the clock this endpoint measures deadlines and backoff against.
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Replaces the operation timeout of this endpoint when `timeout` is set,
	/// so a dial and every transport built from this configuration run under
	/// it.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidLimits`] -- `timeout` is zero.
	pub(crate) fn with_operation_timeout(self, timeout: Option<Duration>) -> TransportResult<Self> {
		let Some(operation_timeout) = timeout else {
			return Ok(self);
		};

		let limits = TransportLimits { operation_timeout, ..*self.limits };
		self.with_limits(limits)
	}

	/// Attaches the production instrumentation collector each transport built
	/// from this configuration shares.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// Returns the provisioning this endpoint holds.
	pub fn encryption(&self) -> &EncryptionConfig<P> {
		self.encryption.encryption()
	}

	/// Returns every ceiling this endpoint enforces.
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

	/// The limits of `config` passed [`TransportLimits::checked`] when it took
	/// them, so the endpoint holds them as they are.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- an error of the [`DialableEncryption`] conversion.
	fn try_from(config: TransportEncryptionConfig<P>) -> TransportResult<Self> {
		let limits = config.limits;
		let encryption = DialableEncryption::try_from(config)?;

		Ok(Self { limits, ..Self::new(encryption, Arc::new(SystemClock)) })
	}
}

impl<P: CryptoProvider> TransportEncryptionConfig<P> {
	/// Creates a server configuration that presents `identity`.
	///
	/// The identity pairs the certificate with the key that signs for it, so
	/// the two arrive checked against each other.
	pub fn new(identity: SigningIdentity) -> Self {
		Self {
			identity: identity.into(),
			peer_authentication: PeerAuthentication::Anonymous,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			key_purposes: KeyPurposes::default(),
			limits: CheckedLimits::default(),
			_provider: core::marker::PhantomData,
		}
	}

	/// Names the validators that authenticate the client.
	///
	/// A non-empty set demands mutual authentication, and it replaces any set
	/// named before.
	///
	/// # Empty set
	///
	/// An empty set names no demand, by the rule of
	/// [`PeerAuthentication::mutual`], so it leaves the endpoint as it is. An
	/// endpoint that demands mutual authentication keeps that demand.
	#[must_use]
	pub fn with_client_validators(
		mut self,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> Self {
		if let Some(demanded) = PeerAuthentication::mutual(validators) {
			self.peer_authentication = demanded;
		}

		self
	}

	/// Names `authentication` as the rule by which this server authenticates
	/// its client, in place of the rule named before.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::crypto::x509::policy::ExpiryValidator;
	/// use tightbeam::testing::TestIdentity;
	/// use tightbeam::transport::handshake::PeerAuthentication;
	/// use tightbeam::transport::TransportEncryptionConfig;
	///
	/// let authentication = PeerAuthentication::Anonymous.and(Arc::new(ExpiryValidator::default()));
	/// let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(TestIdentity::insecure_fixed());
	/// let mutual = config.with_peer_authentication(authentication);
	/// # drop(mutual);
	/// ```
	#[must_use]
	pub fn with_peer_authentication(mut self, authentication: impl Into<PeerAuthentication>) -> Self {
		self.peer_authentication = authentication.into();
		self
	}

	/// Replaces every ceiling this endpoint enforces with `limits`, once
	/// [`TransportLimits::checked`] admits them.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidLimits`] -- the errors of [`TransportLimits::checked`].
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::testing::TestIdentity;
	/// use tightbeam::transport::{TransportEncryptionConfig, TransportLimits};
	///
	/// // A server that gives each handshake 5 seconds.
	/// let limits = TransportLimits { handshake_timeout: Duration::from_secs(5), ..TransportLimits::default() };
	/// let identity = TestIdentity::insecure_fixed();
	/// let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity).with_limits(limits)?;
	/// assert_eq!(config.limits().handshake_timeout, Duration::from_secs(5));
	/// # Ok::<(), tightbeam::transport::TransportError>(())
	/// ```
	pub fn with_limits(mut self, limits: TransportLimits) -> TransportResult<Self> {
		self.limits = limits.checked()?;
		Ok(self)
	}

	/// Returns every ceiling this endpoint enforces.
	pub fn limits(&self) -> &TransportLimits {
		&self.limits
	}

	/// Sets the key purpose of each role: the purpose the server's own
	/// certificates carry, and the purpose a client's certificate carries.
	/// The default is [`KeyPurposes::HOUSE`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[must_use]
	pub fn with_key_purposes(mut self, key_purposes: KeyPurposes) -> Self {
		self.key_purposes = key_purposes;
		self
	}

	/// Returns the identity certificate this endpoint presents during the
	/// handshake, the one whose key signs its replies.
	pub fn certificate(&self) -> &Certificate {
		self.identity.signing().certificate()
	}
}

#[cfg(feature = "transport-cms")]
impl<P: CryptoProvider> TransportEncryptionConfig<P> {
	/// Pairs the signing identity this endpoint presents with `key_agreement`,
	/// the identity the CMS opening seals to, once, as a [`CmsIdentityPair`].
	///
	/// A CMS server needs the pair. An HPKE server signs with the signing
	/// identity alone.
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
	use crate::crypto::aead::SessionKeys;
	use crate::testing::TestFrame;
	use crate::transport::error::TransportFailure;

	#[cfg(feature = "tokio")]
	use crate::testing::TestResult;

	/// An empty validator set demands nothing, so it leaves an endpoint that
	/// already demands mutual authentication as it is.
	#[cfg(feature = "testing")]
	#[test]
	fn an_empty_validator_set_keeps_the_configured_authentication() {
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::x509::policy::ExpiryValidator;
		use crate::testing::fixtures::TestIdentity;

		let identity = TestIdentity::insecure_fixed();
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator::default());
		let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(identity);
		let mutual = config.with_client_validators([validator]);

		let config = mutual.with_client_validators([]);
		assert!(config.peer_authentication.requires_certificate());
	}

	/// An endpoint refuses a set of limits whose handshake ceiling passes its
	/// cleartext ceiling, before any transport reads the set.
	#[cfg(host_clock)]
	#[test]
	fn an_endpoint_refuses_an_inverted_set_of_limits() {
		use crate::crypto::profiles::DefaultCryptoProvider;

		let endpoint = EndpointConfig::<DefaultCryptoProvider>::cleartext();
		let inverted = TransportLimits { handshake_wire: 1 << 20, ..TransportLimits::default() };

		let refused = endpoint.with_limits(inverted);
		assert!(matches!(
			refused,
			Err(TransportError::InvalidLimits(LimitsRefusal::HandshakePastCleartext))
		));
	}

	/// A server configuration refuses a set of limits with a zero ceiling, so
	/// no listener binds under it.
	#[cfg(feature = "testing")]
	#[test]
	fn a_server_configuration_refuses_a_zero_ceiling() {
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::testing::fixtures::TestIdentity;

		let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(TestIdentity::insecure_fixed());
		let zero = TransportLimits { handshake_wire: 0, ..TransportLimits::default() };

		let refused = config.with_limits(zero);
		assert!(matches!(
			refused,
			Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling))
		));
	}

	/// A zero operation timeout refuses every operation it bounds, so an
	/// endpoint refuses it before a dial.
	#[cfg(host_clock)]
	#[test]
	fn an_endpoint_refuses_a_zero_operation_timeout() {
		use crate::crypto::profiles::DefaultCryptoProvider;

		let endpoint = EndpointConfig::<DefaultCryptoProvider>::cleartext();
		let refused = endpoint.with_operation_timeout(Some(Duration::ZERO));
		assert!(matches!(
			refused,
			Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling))
		));
	}

	/// Both `bind_cleartext` arms of `server!` expand and bind on the tokio
	/// runtime, with policies and with none.
	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn the_bind_cleartext_arms_of_the_server_macro_bind() -> TestResult {
		use crate::asn1::Frame;
		use crate::transport::tcp::r#async::TokioListener;

		let addr = <TokioListener as Protocol>::default_bind_address()?;
		let plain = crate::server! {
			protocol TokioListener: bind_cleartext addr,
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		};
		let capped = crate::server! {
			protocol TokioListener: bind_cleartext addr,
			policies: { max_connections: [ 4 ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		};

		plain.abort();
		capped.abort();
		Ok(())
	}

	/// The server and client macros carry a frame from the client to the
	/// handler of the server.
	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn the_server_and_client_macros_carry_a_frame() -> TestResult {
		use crate::asn1::Frame;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);
		let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
		let server_handle = crate::server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = tx.clone();
				async move {
					// The receiver lives for the whole test, so a refused send
					// surfaces as a missing message at the assertion.
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

		client.emit(message.clone(), None).await?;

		assert_eq!(rx.recv().await, Some(message));
		server_handle.abort();

		Ok(())
	}

	/// The handler events that one call to a cleartext server records on the
	/// trail of its connection, in order, under a trace whose config sets
	/// `enable_internal_detail` to `detail`. The `client!` macro raises its
	/// dial error with `?`, so the span comes back as a result.
	#[cfg(all(feature = "tokio", feature = "instrument"))]
	async fn single_flight_handler_span(detail: bool) -> TransportResult<Vec<crate::urn::Urn<'static>>> {
		use crate::asn1::Frame;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::instrumentation::events;
		use crate::testing::fixtures::TestTrace;
		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let trace = TestTrace::with_detail(detail);
		let served = trace.share();
		let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

		let server_handle = crate::server! {
			protocol TokioListener: listener,
			policies: { with_trace: [ served.share() ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		};
		let mut client = crate::client! {
			connect TokioListener: addr,
			cleartext,
			policies: {
				restart_policy: RestartLinearBackoff::default(),
			}
		};

		// The server records the exit of its handler before it sends the
		// answer, so the answer orders the span ahead of the drain below.
		client.emit(TestFrame::v0(None, None), None).await?;
		server_handle.abort();

		Ok(TestTrace::trail(&trace, &[events::HANDLER_ENTER, events::HANDLER_EXIT]))
	}

	// A single-flight call records the span of its handler when, and only
	// when, the trace config sets the detail flag.
	#[cfg(all(feature = "tokio", feature = "instrument"))]
	crate::tb_cases! {
		#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
		async fn a_single_flight_call_records_its_handler_span_under_the_detail_flag_alone(
			(detail, expected): (bool, Vec<crate::urn::Urn<'static>>)
		) -> TestResult {
			let span = single_flight_handler_span(detail).await?;
			assert_eq!(span, expected);
			Ok(())
		}
		cases {
			detailed => (
				true,
				vec![crate::instrumentation::events::HANDLER_ENTER, crate::instrumentation::events::HANDLER_EXIT],
			),
			plain => (false, vec![]),
		}
	}

	/// A builder with no configured limits refuses a payload past the
	/// default cleartext ceiling, though the caller configured nothing. Every
	/// other limit test sets a ceiling explicitly, so only this test covers
	/// the default.
	#[test]
	fn default_limits_bound_a_cleartext_envelope() {
		let limits = TransportLimits::default();
		let oversized = "a".repeat(limits.cleartext_envelope + 1);
		let frame = TestFrame::v0(Some(&oversized), None);
		let result = builders::EnvelopeBuilder::request(frame).finish();
		assert!(matches!(
			result,
			Err(TransportError::MessageNotSent(_, TransportFailure::SizeExceeded))
		));
	}

	/// The length of the DER of a request envelope of `frame`, before a seal.
	fn plaintext_length(frame: &crate::asn1::Frame) -> usize {
		use crate::der::Encode;

		let encoded = TransportEnvelope::from(frame.clone()).to_der();
		encoded.expect("a request envelope encodes").len()
	}

	/// The outcome of a build of a request envelope of `frame` under
	/// `limits`, sealed by the send half of [`SessionKeys::insecure_client`]
	/// when `sealed` is set.
	fn built(frame: &crate::asn1::Frame, sealed: bool, limits: TransportLimits) -> TransportResult<WireEnvelope> {
		let (sender, _receiver) = SessionKeys::insecure_client().into_parts();
		let limits = limits.checked().expect("the case limits agree");
		let builder = builders::EnvelopeBuilder::request(frame.clone());
		if sealed {
			builder.sealed_by(&sender).with_limits(limits).finish()
		} else {
			builder.with_limits(limits).finish()
		}
	}

	// A builder past its ceiling refuses the envelope and returns the frame.
	// The encrypted ceiling measures the sealed wire form, so a ceiling of
	// exactly the plaintext length refuses: the AEAD tag, the nonce, and the
	// `WireEnvelope` wrapper come after the encode, and a measurement before
	// them would let an oversized envelope reach the peer as a connection
	// reset. A handshake message of one octet takes three on the wire, so a
	// cleartext ceiling of four admits the set and refuses the frame.
	crate::tb_cases! {
		fn a_builder_past_its_ceiling_returns_the_frame((sealed, limits): (bool, TransportLimits)) {
			let frame = TestFrame::v1(None, Some("ceiling"));
			let result = built(&frame, sealed, limits);
			assert!(matches!(
				result,
				Err(TransportError::MessageNotSent(ref returned, TransportFailure::SizeExceeded)) if **returned == frame
			));
		}
		cases {
			sealed_at_the_plaintext_length => (
				true,
				TransportLimits {
					encrypted_envelope: plaintext_length(&TestFrame::v1(None, Some("ceiling"))),
					..TransportLimits::default()
				},
			),
			sealed_at_one_octet => (true, TransportLimits { encrypted_envelope: 1, ..TransportLimits::default() }),
			cleartext_at_four_octets => (
				false,
				TransportLimits { handshake_wire: 1, cleartext_envelope: 4, ..TransportLimits::default() },
			),
		}
	}
}
