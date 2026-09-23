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
use crate::transport::error::TransportFailure;
use crate::transport::{MessageCollector, Protocol, TransportResult};

#[cfg(feature = "policy")]
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
#[cfg(feature = "std")]
use crate::transport::ConnectionBuilder;
#[cfg(feature = "transport-policy")]
use crate::transport::MessageEmitter;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::transport::handshake::HandshakeProtocolKind;
	pub use crate::transport::state::{DialableEncryption, EncryptionConfig};
	pub use crate::transport::EndpointConfig;
	pub use crate::utils::time::Clock;
	pub use crate::x509::Certificate;

	#[cfg(feature = "std")]
	pub use crate::transport::state::ClientIdentity;
	#[cfg(host_clock)]
	pub use crate::utils::time::SystemClock;
}

#[cfg(feature = "x509")]
use x509::*;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::transport::policy::{
		CollectorGateConfig, CoreRetryPolicy, EmitterGateConfig, PolicyConfig, RestartConfig, RestartPolicy,
		RetryAction, TimeoutConfig,
	};
}

#[cfg(feature = "transport-policy")]
use policy::*;

#[derive(Default)]
pub struct ClientPolicies {
	restart: Option<DynRestart>,
	emitter_gates: Vec<DynGate>,
	collector_gates: Vec<DynGate>,
	timeout: Option<Duration>,
}

pub struct DynRestart(pub Box<dyn RestartPolicy + Send + Sync>);

impl CoreRetryPolicy for DynRestart {
	fn max_attempts(&self) -> usize {
		self.0.max_attempts()
	}

	fn delay_ms(&self, attempt: usize) -> u64 {
		self.0.delay_ms(attempt)
	}
}

impl RestartPolicy for DynRestart {
	fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction {
		self.0.evaluate(frame, failure, attempt)
	}
}

pub struct DynGate(pub Arc<dyn GatePolicy + Send + Sync>);
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
	/// Provisioning this builder accumulates, handed to the transport whole.
	#[cfg(feature = "x509")]
	encryption: EncryptionConfig<P::CryptoProvider>,
	/// The clock the transport measures deadlines and backoff against.
	#[cfg(feature = "x509")]
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
	#[cfg(feature = "x509")]
	pub fn on_clock(clock: Arc<dyn Clock>) -> Self {
		Self {
			policies: ClientPolicies::default(),
			encryption: EncryptionConfig::unconfigured(),
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

	#[cfg(feature = "x509")]
	pub fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.encryption.trust_store = Some(store);
		self
	}

	/// Provision the expected server certificate chain, ordered root to
	/// leaf, for key-transport handshakes (CMS).
	#[cfg(feature = "x509")]
	pub fn with_server_certificate_chain(mut self, chain: impl Into<Arc<[Certificate]>>) -> Self {
		self.encryption.server_certificate_chain = Some(chain.into());
		self
	}

	/// Select the handshake protocol used when encryption is enabled.
	#[cfg(feature = "x509")]
	pub fn with_handshake_protocol(mut self, kind: HandshakeProtocolKind) -> Self {
		self.encryption.handshake_protocol = kind;
		self
	}

	/// Replace the domain-separation tag of the ECIES key exchange.
	///
	/// The ECIES handshake binds this tag into the associated data of the
	/// encrypted key exchange, so an ECIES session completes only when both
	/// endpoints hold the same tag. The CMS handshake and session records do
	/// not read it.
	#[cfg(feature = "x509")]
	pub fn with_aad_domain_tag(mut self, tag: &'static [u8]) -> Self {
		self.encryption.aad_domain_tag = tag;
		self
	}

	/// Run this client without authenticating the server.
	///
	/// A client with no trust store verifies nobody, so [`Self::connect`] and
	/// [`Self::adopt`] refuse it until this names that as the intent. Frames
	/// then travel in the clear and any peer answering the address is
	/// accepted, which suits a loopback fixture or a link a lower layer
	/// already secures.
	#[cfg(feature = "x509")]
	pub fn allow_cleartext(mut self) -> Self {
		self.encryption.allow_cleartext = true;
		self
	}

	/// Everything the transport is built from, once the dialer rule has
	/// answered.
	///
	/// # Errors
	///
	/// - [`crate::transport::error::TransportError::PeerAuthenticationUnconfigured`] --
	///   the client holds no trust store and did not call [`Self::allow_cleartext`],
	///   so it would have accepted any peer.
	#[cfg(feature = "x509")]
	fn endpoint(
		encryption: EncryptionConfig<P::CryptoProvider>,
		clock: Arc<dyn Clock>,
	) -> TransportResult<EndpointConfig<P::CryptoProvider>> {
		let encryption = DialableEncryption::new(encryption)?;
		Ok(EndpointConfig::new(encryption, clock))
	}
}

#[cfg(feature = "x509")]
impl<P: Protocol + Send> ClientBuilder<P>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConfig,
	P::Address: Send,
{
	/// Connect and configure the client.
	///
	/// The dialer rule answers before the connection opens, so a refused
	/// client never reaches the address.
	///
	/// # Errors
	///
	/// - [`crate::transport::error::TransportError::PeerAuthenticationUnconfigured`] --
	///   the client holds no trust store and did not call [`Self::allow_cleartext`],
	///   so it would have accepted any peer.
	pub async fn connect(self, addr: impl Into<P::Address>) -> TransportResult<GenericClient<P>> {
		let endpoint = Self::endpoint(self.encryption, self.clock)?;
		let destination = addr.into();
		let stream = P::connect(destination).await.map_err(|e| e.into())?;

		let transport = P::create_transport(stream, endpoint);
		let configured = self.policies.apply::<P>(transport);
		Ok(GenericClient::from_transport(configured))
	}

	/// Configure a client over a stream the caller already opened.
	///
	/// The stream answers the same dialer rule as [`Self::connect`], so a
	/// client adopted this way is no less authenticated than one this builder
	/// dialed.
	///
	/// # Errors
	///
	/// - [`crate::transport::error::TransportError::PeerAuthenticationUnconfigured`] --
	///   the client holds no trust store and did not call [`Self::allow_cleartext`].
	pub fn adopt(self, stream: P::Stream) -> TransportResult<GenericClient<P>> {
		let endpoint = Self::endpoint(self.encryption, self.clock)?;

		let transport = P::create_transport(stream, endpoint);
		let configured = self.policies.apply::<P>(transport);
		Ok(GenericClient::from_transport(configured))
	}
}

#[cfg(all(feature = "std", feature = "x509"))]
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

	fn with_client_identity(mut self, identity: ClientIdentity<P::CryptoProvider>) -> Self {
		identity.install(&mut self.encryption);
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

#[cfg(all(
	test,
	feature = "x509",
	feature = "tokio",
	feature = "std",
	not(target_arch = "wasm32")
))]
mod tests {
	use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::transport::error::TransportError;
	use crate::transport::tcp::r#async::{TokioListener, TokioStream};
	use crate::transport::tcp::TightBeamSocketAddr;

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
		let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0").await?;
		let stream = tokio::net::TcpStream::connect(listener.local_addr()?).await?;

		let refused = ClientBuilder::<TokioListener>::builder().adopt(TokioStream::from(stream));
		assert!(matches!(refused, Err(TransportError::PeerAuthenticationUnconfigured)));
		Ok(())
	}

	/// Naming cleartext is what lets the same client through, so it reaches
	/// the address and fails there instead.
	#[tokio::test]
	async fn naming_cleartext_admits_the_same_client() {
		let admitted = ClientBuilder::<TokioListener>::builder()
			.allow_cleartext()
			.connect(UNREACHABLE)
			.await;
		assert!(!matches!(admitted, Err(TransportError::PeerAuthenticationUnconfigured)));
	}
}
