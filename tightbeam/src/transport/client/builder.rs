#[cfg(not(feature = "std"))]
extern crate alloc;

use core::marker::PhantomData;
use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use super::GenericClient;
use crate::asn1::Frame;
use crate::crypto::x509::store::CertificateTrust;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::transport::error::TransportFailure;
use crate::transport::handshake::HandshakeProtocolKind;
use crate::transport::state::{DialableEncryption, EncryptionConfig, Negotiation};
use crate::transport::EndpointConfig;
use crate::transport::MessageEmitter;
use crate::transport::{MessageCollector, Protocol, TransportResult};
use crate::utils::time::Clock;

#[cfg(feature = "std")]
use crate::crypto::sign::SigningIdentity;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::KeyPurposes;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::ProvisionedTrust;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::ValidatorChain;
#[cfg(feature = "std")]
use crate::transport::ConnectionBuilder;
#[cfg(host_clock)]
use crate::utils::time::SystemClock;

use crate::transport::policy::{
	CollectorGateConfig, EmitterGateConfig, PolicyConfig, RestartConfig, RestartPolicy, RetryAction, TimeoutConfig,
};

#[derive(Default)]
pub struct ClientPolicies {
	restart: Option<DynRestart>,
	emitter_gates: Vec<DynGate>,
	collector_gates: Vec<DynGate>,
	timeout: Option<Duration>,
}

/// A restart policy the client policies hold behind one box.
pub struct DynRestart(
	/// The policy every restart decision delegates to.
	pub Box<dyn RestartPolicy + Send + Sync>,
);

impl RestartPolicy for DynRestart {
	fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction {
		self.0.evaluate(frame, failure, attempt)
	}
}

/// A gate policy the client policies hold behind one shared pointer.
pub struct DynGate(
	/// The policy every gate decision delegates to.
	pub Arc<dyn GatePolicy + Send + Sync>,
);
impl GatePolicy for DynGate {
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		self.0.evaluate(message, session)
	}
}

impl ClientPolicies {
	pub fn with_restart<P>(mut self, policy: P) -> Self
	where
		P: RestartPolicy + Send + Sync + 'static,
	{
		self.restart = Some(DynRestart(Box::new(policy)));
		self
	}

	pub fn with_emitter_gate<G>(mut self, gate: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		let gate = Arc::new(gate);
		self.emitter_gates.push(DynGate(gate));
		self
	}

	pub fn with_collector_gate<G>(mut self, gate: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		let gate = Arc::new(gate);
		self.collector_gates.push(DynGate(gate));
		self
	}

	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	pub fn apply<P>(self, mut transport: P::Transport) -> P::Transport
	where
		P: Protocol,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig,
	{
		if let Some(r) = self.restart {
			transport = transport.with_restart(r);
		}
		for g in self.emitter_gates.into_iter() {
			transport = transport.with_emitter_gate(g);
		}
		for g in self.collector_gates.into_iter() {
			transport = transport.with_collector_gate(g);
		}
		if let Some(timeout) = self.timeout {
			transport = transport.with_timeout(timeout);
		}
		transport
	}
}

pub struct ClientBuilder<P: Protocol> {
	policies: ClientPolicies,
	/// The provisioning this builder gathers and hands to the transport whole.
	encryption: EncryptionConfig<P::CryptoProvider>,
	/// The negotiation input this builder accumulates, which the transport
	/// starts with.
	negotiation: Negotiation,
	/// The clock the transport measures deadlines and backoff against.
	clock: Arc<dyn Clock>,
	_ph: PhantomData<P>,
}

impl<P: Protocol> ClientBuilder<P> {
	/// A builder on the operating system's clocks.
	#[cfg(host_clock)]
	pub fn builder() -> Self {
		Self::on_clock(Arc::new(SystemClock))
	}

	/// A builder whose transport measures deadlines and backoff against
	/// `clock`.
	pub fn on_clock(clock: Arc<dyn Clock>) -> Self {
		Self {
			policies: ClientPolicies::default(),
			encryption: EncryptionConfig::unconfigured(),
			negotiation: Negotiation::default(),
			clock,
			_ph: PhantomData,
		}
	}

	pub fn policies(mut self, policies: ClientPolicies) -> Self {
		self.policies = policies;
		self
	}

	pub fn with_restart<R>(mut self, p: R) -> Self
	where
		R: RestartPolicy + Send + Sync + 'static,
	{
		self.policies = self.policies.with_restart(p);
		self
	}

	pub fn with_emitter_gate<G>(mut self, g: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		self.policies = self.policies.with_emitter_gate(g);
		self
	}

	pub fn with_collector_gate<G>(mut self, g: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		self.policies = self.policies.with_collector_gate(g);
		self
	}

	pub fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.encryption.trust_store = Some(store);
		self
	}

	/// Provisions the trust in the CMS server, built once over its pinned
	/// key-agreement certificate: the opening seals to it, and the trust's
	/// store admits the signing certificate the reply carries.
	#[cfg(feature = "transport-cms")]
	pub fn with_cms_server(mut self, trust: ProvisionedTrust) -> Self {
		self.encryption.cms_server = Some(trust);
		self
	}

	/// Sets the key purpose of each role: the purpose the server's
	/// certificates carry, and the purpose the client identity carries. The
	/// default is [`KeyPurposes::HOUSE`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn with_key_purposes(mut self, key_purposes: KeyPurposes) -> Self {
		self.encryption.key_purposes = key_purposes;
		self
	}

	/// Sets the server policy, which every validator of `validators` runs on
	/// the identity certificate of the server under either flow, as
	/// [`ClientConfig::with_server_policy`] states. An empty set sets no
	/// policy.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	/// use tightbeam::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	/// use tightbeam::transport::client::{ClientBuilder, ConnectionBuilder};
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// let store = Arc::new(CertificateTrustBuilder::from(Secp256k1Policy::default()).build());
	/// let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(store);
	///
	/// // The policy narrows which server the store admits.
	/// let expiry: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
	/// let _builder = builder.with_server_policy([expiry]);
	/// ```
	///
	/// [`ClientConfig::with_server_policy`]: crate::transport::handshake::ClientConfig::with_server_policy
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn with_server_policy(mut self, validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Self {
		self.encryption.server_policy = ValidatorChain::new(validators);
		self
	}

	/// Selects the handshake protocol that runs when encryption is enabled.
	pub fn with_handshake_protocol(mut self, kind: HandshakeProtocolKind) -> Self {
		self.negotiation.select_handshake(kind);
		self
	}

	/// Runs this client with no authentication of the server.
	///
	/// A client with no trust store verifies nobody, so [`Self::connect`] and
	/// [`Self::adopt`] refuse it until this names that as the intent. Frames
	/// then travel in the clear, and the client accepts any peer that answers
	/// the address, which suits a loopback fixture or a link that a lower
	/// layer already secures.
	pub fn allow_cleartext(mut self) -> Self {
		self.encryption.allow_cleartext = true;
		self
	}

	/// Collects everything the transport is built from, once the dialer rule
	/// has answered.
	///
	/// # Errors
	///
	/// - [`crate::transport::error::TransportError::PeerAuthenticationUnconfigured`] --
	///   the client holds no trust store and did not call
	///   [`Self::allow_cleartext`], so it would have accepted any peer, or it
	///   sets a server policy and holds no trust in a server, whether or not it
	///   names cleartext.
	fn endpoint(
		encryption: EncryptionConfig<P::CryptoProvider>,
		negotiation: Negotiation,
		clock: Arc<dyn Clock>,
	) -> TransportResult<EndpointConfig<P::CryptoProvider>> {
		let encryption = DialableEncryption::new(encryption)?;
		Ok(EndpointConfig::new(encryption, clock).with_negotiation(negotiation))
	}
}

impl<P: Protocol + Send> ClientBuilder<P>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConfig,
	P::Address: Send,
{
	/// Connects and configures the client.
	///
	/// The dialer rule answers before the connection opens, so a refused
	/// client never reaches the address.
	///
	/// # Errors
	///
	/// - [`crate::transport::error::TransportError::PeerAuthenticationUnconfigured`] --
	///   the client holds no trust store and did not call
	///   [`Self::allow_cleartext`], so it would have accepted any peer, or it
	///   sets a server policy and holds no trust in a server, whether or not it
	///   names cleartext.
	pub async fn connect(self, addr: impl Into<P::Address>) -> TransportResult<GenericClient<P>> {
		let endpoint = Self::endpoint(self.encryption, self.negotiation, self.clock)?;
		let destination = addr.into();
		let stream = P::connect(destination).await.map_err(|e| e.into())?;

		let transport = P::create_transport(stream, endpoint);
		let configured = self.policies.apply::<P>(transport);
		Ok(GenericClient::from_transport(configured))
	}

	/// Configures a client over a stream that the caller already opened.
	///
	/// The stream answers the same dialer rule as [`Self::connect`], so a
	/// client adopted this way is as authenticated as one this builder dialed.
	///
	/// # Errors
	///
	/// - [`crate::transport::error::TransportError::PeerAuthenticationUnconfigured`] --
	///   the client holds no trust store and did not call
	///   [`Self::allow_cleartext`], or it sets a server policy and holds no
	///   trust in a server, whether or not it names cleartext.
	pub fn adopt(self, stream: P::Stream) -> TransportResult<GenericClient<P>> {
		let endpoint = Self::endpoint(self.encryption, self.negotiation, self.clock)?;

		let transport = P::create_transport(stream, endpoint);
		let configured = self.policies.apply::<P>(transport);
		Ok(GenericClient::from_transport(configured))
	}
}

#[cfg(feature = "std")]
impl<P: Protocol> super::sealed::Sealed for ClientBuilder<P> {}

#[cfg(feature = "std")]
impl<P: Protocol + Send> ConnectionBuilder<P> for ClientBuilder<P>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConfig,
	P::Address: Send,
{
	type Output = Self;

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.policies = self.policies.with_timeout(timeout);
		self
	}

	fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.encryption.trust_store = Some(store);
		self
	}

	fn with_client_identity(mut self, identity: SigningIdentity) -> Self {
		self.encryption.client_identity = Some(identity);
		self
	}

	fn build(self) -> Self::Output {
		self
	}
}

impl GatePolicy for Arc<dyn GatePolicy + Send + Sync> {
	fn evaluate(&self, message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		(**self).evaluate(message, session)
	}
}

#[cfg(all(test, feature = "tokio", feature = "std", not(target_arch = "wasm32")))]
mod tests {
	use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::transport::error::TransportError;
	use crate::transport::tcp::r#async::{TokioListener, TokioStream};
	use crate::transport::tcp::TightBeamSocketAddr;

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::crypto::x509::policy::ExpiryValidator;

	/// Port 1 on loopback, where a connection attempt fails fast. The refusal
	/// under test is reached before the dial, so the first case never leaves
	/// the builder and the second fails at the address.
	const UNREACHABLE: TightBeamSocketAddr =
		TightBeamSocketAddr(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)));

	/// A client with no trust store authenticates nobody, so it is refused
	/// before it opens a connection (CWE-295).
	#[tokio::test]
	async fn a_client_without_a_trust_store_is_refused() {
		let refused = ClientBuilder::<TokioListener>::builder().connect(UNREACHABLE).await;
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
	}

	/// The shortest `client!` form reaches the wire only through the same
	/// rule, so a bare dial is refused before it opens a connection
	/// (CWE-295).
	#[tokio::test]
	async fn a_bare_client_macro_is_refused_before_it_dials() {
		async fn bare_client() -> TransportResult<GenericClient<TokioListener>> {
			let client = crate::client!(connect TokioListener: UNREACHABLE);
			Ok(client)
		}

		let refused = bare_client().await;
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
	}

	/// A stream the caller opened answers the same rule as a dial, so no
	/// path reaches the wire without it.
	#[tokio::test]
	async fn an_adopted_stream_without_a_peer_authority_is_refused() -> TransportResult<()> {
		let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
		let stream = tokio::net::TcpStream::connect(listener.local_addr()?).await?;

		let refused = ClientBuilder::<TokioListener>::builder().adopt(TokioStream::from(stream));
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
		Ok(())
	}

	/// A client that names cleartext passes the same rule, so it reaches the
	/// address and fails there instead.
	#[tokio::test]
	async fn naming_cleartext_admits_the_same_client() {
		let admitted = ClientBuilder::<TokioListener>::builder()
			.allow_cleartext()
			.connect(UNREACHABLE)
			.await;
		assert!(!matches!(admitted, Err(TransportError::PeerAuthenticationUnconfigured)));
	}

	/// The policy that admits every certificate within its validity period.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn expiry_policy() -> [Arc<dyn CertificateValidation>; 1] {
		[Arc::new(ExpiryValidator)]
	}

	/// A server policy narrows which server a trust admits and names no peer
	/// authority, so a client with a policy alone is refused before it
	/// opens a connection (CWE-295).
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test]
	async fn a_server_policy_alone_is_refused_before_it_dials() {
		let builder = ClientBuilder::<TokioListener>::builder().with_server_policy(expiry_policy());
		let refused = builder.connect(UNREACHABLE).await;
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
	}

	/// A cleartext dial checks no server, so a client that names cleartext
	/// beside a server policy and no trust is refused before it opens a
	/// connection (CWE-295).
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[tokio::test]
	async fn a_server_policy_with_cleartext_is_refused_before_it_dials() {
		let builder = ClientBuilder::<TokioListener>::builder().with_server_policy(expiry_policy());
		let refused = builder.allow_cleartext().connect(UNREACHABLE).await;
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
	}
}
