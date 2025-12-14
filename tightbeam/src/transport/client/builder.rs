#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use core::time::Duration;

use super::GenericClient;
use crate::asn1::Frame;
use crate::policy::{GatePolicy, TransitStatus};
use crate::transport::error::TransportFailure;
use crate::transport::{ConnectionBuilder, MessageCollector, MessageEmitter, Protocol, TransportResult};

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::key::SigningKeyProvider;
	pub use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::crypto::x509::CertificateSpec;
	pub use crate::transport::handshake::HandshakeKeyManager;
	pub use crate::transport::X509ClientConfig;
	pub use crate::x509::Certificate;
}

#[cfg(feature = "x509")]
use x509::*;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::transport::policy::{CoreRetryPolicy, PolicyConf, RestartPolicy, RetryAction};
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
	fn evaluate(&self, message: &Frame) -> TransitStatus {
		self.0.evaluate(message)
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
		self.emitter_gates.push(DynGate(Arc::new(gate)));
		self
	}

	pub fn with_collector_gate<G>(mut self, gate: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		self.collector_gates.push(DynGate(Arc::new(gate)));
		self
	}

	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	pub fn apply<P>(self, mut transport: P::Transport) -> P::Transport
	where
		P: Protocol,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf,
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

pub struct ClientBuilder<P: Protocol, C: CryptoProvider + 'static = DefaultCryptoProvider> {
	policies: ClientPolicies,
	#[cfg(feature = "x509")]
	trust_store: Option<Arc<dyn CertificateTrust>>,
	#[cfg(feature = "x509")]
	client_certificate: Option<Certificate>,
	#[cfg(feature = "x509")]
	client_key: Option<HandshakeKeyManager<C>>,
	_ph: core::marker::PhantomData<(P, C)>,
}

impl<P: Protocol, C: CryptoProvider + 'static> ClientBuilder<P, C> {
	pub fn builder() -> Self {
		Self {
			policies: ClientPolicies::default(),
			#[cfg(feature = "x509")]
			trust_store: None,
			#[cfg(feature = "x509")]
			client_certificate: None,
			#[cfg(feature = "x509")]
			client_key: None,
			_ph: core::marker::PhantomData,
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
		self.trust_store = Some(store);
		self
	}
}

#[cfg(not(feature = "x509"))]
impl<P: Protocol + Send, C: CryptoProvider + 'static> ClientBuilder<P, C>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConf,
	P::Address: Send,
{
	pub async fn connect(self, addr: P::Address) -> TransportResult<GenericClient<P>> {
		let stream = P::connect(addr.clone()).await.map_err(|e| e.into())?;
		let transport = P::create_transport(stream);
		let configured = self.policies.apply::<P>(transport);
		Ok(GenericClient::from_transport_with_addr(configured, addr))
	}
}

#[cfg(feature = "x509")]
impl<P: Protocol + Send, C: CryptoProvider + Send + Sync + 'static> ClientBuilder<P, C>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig<CryptoProvider = C>,
	P::Address: Send,
{
	pub async fn connect(self, addr: P::Address) -> TransportResult<GenericClient<P>> {
		let stream = P::connect(addr.clone()).await.map_err(|e| e.into())?;
		let mut transport = P::create_transport(stream);
		if let Some(store) = self.trust_store {
			transport = transport.with_trust_store(store);
		}
		if let (Some(cert), Some(key)) = (self.client_certificate, self.client_key) {
			transport = transport.with_client_identity(cert, key);
		}

		let configured = self.policies.apply::<P>(transport);
		Ok(GenericClient::from_transport_with_addr(configured, addr))
	}
}

#[cfg(all(feature = "std", not(feature = "x509")))]
impl<P: Protocol + Send, C: CryptoProvider + 'static> ConnectionBuilder<P> for ClientBuilder<P, C>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConf,
	P::Address: Send,
{
	type Output = Self;

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.policies = self.policies.with_timeout(timeout);
		self
	}

	fn build(self) -> Self::Output {
		self
	}
}

#[cfg(all(feature = "std", feature = "x509"))]
impl<P: Protocol + Send, C: CryptoProvider + Send + Sync + 'static> ConnectionBuilder<P> for ClientBuilder<P, C>
where
	P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig<CryptoProvider = C>,
	P::Address: Send,
{
	type Output = Self;

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.policies = self.policies.with_timeout(timeout);
		self
	}

	fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.trust_store = Some(store);
		self
	}

	fn with_client_identity(
		mut self,
		cert: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
	) -> TransportResult<Self> {
		let cert = Certificate::try_from(cert)?;
		let key_manager: HandshakeKeyManager<C> = HandshakeKeyManager::new(key);

		self.client_certificate = Some(cert);
		self.client_key = Some(key_manager);
		Ok(self)
	}

	fn build(self) -> Self::Output {
		self
	}
}

impl GatePolicy for Arc<dyn GatePolicy + Send + Sync> {
	fn evaluate(&self, message: &Frame) -> TransitStatus {
		(**self).evaluate(message)
	}
}
