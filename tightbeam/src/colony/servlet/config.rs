use core::any::Any;
use core::marker::PhantomData;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::hive::HiveContext;
use crate::colony::servlet::runtime;
use crate::colony::servlet::WorkerBox;
use crate::colony::worker::{Worker, WorkerMetadata};
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::policy::GatePolicy;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::IntoMuxOffer;
use crate::transport::Protocol;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::crypto::key::SigningKeyProvider;
#[cfg(feature = "x509")]
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::crypto::x509::{Certificate, CertificateSpec};
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;
#[cfg(feature = "x509")]
use crate::transport::TransportEncryptionConfig;

/// Servlet bind and handler configuration (includes transport encryption).
#[cfg(feature = "x509")]
pub struct ServletConfig<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	pub(crate) _protocol: PhantomData<P>,
	pub(crate) _message: PhantomData<M>,
	pub(crate) _crypto: PhantomData<C>,
	pub(crate) x509_config: Option<TransportEncryptionConfig<C>>,
	pub(crate) mux_offer: Option<Arc<TransportOffer>>,
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

/// Servlet bind and handler configuration (cleartext transport).
#[cfg(not(feature = "x509"))]
pub struct ServletConfig<P, M>
where
	P: Protocol,
	M: Message,
{
	pub(crate) _protocol: PhantomData<P>,
	pub(crate) _message: PhantomData<M>,
	pub(crate) mux_offer: Option<Arc<TransportOffer>>,
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

/// Builder for [`ServletConfig`] with transport encryption.
#[cfg(feature = "x509")]
pub struct ServletConfigBuilder<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	x509_config: Option<TransportEncryptionConfig<C>>,
	mux_offer: Option<Arc<TransportOffer>>,
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	_phantom: PhantomData<(P, M, C)>,
}

/// Builder for [`ServletConfig`] without transport encryption.
#[cfg(not(feature = "x509"))]
pub struct ServletConfigBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	mux_offer: Option<Arc<TransportOffer>>,
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	_phantom: PhantomData<(P, M)>,
}

macro_rules! config_accessors {
	() => {
		/// Application env config downcast to `Cfg`.
		pub fn to_env_config_ref<Cfg: 'static>(&self) -> Option<&Arc<Cfg>> {
			self.servlet_config.as_ref()?.downcast_ref()
		}

		/// Type-erased application env config.
		pub fn to_servlet_conf_ref(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
			self.servlet_config.as_ref()
		}

		/// Take ownership of registered workers for servlet startup.
		pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
			self.workers
		}

		/// Take ownership of collector gates for the accept loop.
		pub fn to_collector_gates(self) -> Vec<Arc<dyn GatePolicy + Send + Sync>> {
			self.collector_gates
		}

		/// Collector gates by reference.
		pub fn collector_gates_ref(&self) -> &[Arc<dyn GatePolicy + Send + Sync>] {
			&self.collector_gates
		}

		/// Intra-hive communication handle, when set.
		pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
			self.hive_context.as_ref()
		}

		/// Frame-body decryptor clone, when configured.
		pub fn to_message_decryptor(&self) -> Option<Arc<dyn Decryptor + Send + Sync>> {
			self.message_decryptor.as_ref().map(Arc::clone)
		}

		/// Frame-body inflator clone, when configured.
		pub fn to_message_inflator(&self) -> Option<Arc<dyn Inflator + Send + Sync>> {
			self.message_inflator.as_ref().map(Arc::clone)
		}

		/// Multiplexing advertisement applied to accepted connections.
		pub fn mux_offer(&self) -> Option<Arc<TransportOffer>> {
			self.mux_offer.as_ref().map(Arc::clone)
		}
	};
}

#[cfg(feature = "x509")]
impl<P, M, C> ServletConfig<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Start a [`ServletConfigBuilder`].
	pub fn builder() -> ServletConfigBuilder<P, M, C> {
		ServletConfigBuilder::default()
	}

	/// Worker registered under `name`, downcast to `W`.
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	/// Transport encryption config, when set.
	pub fn to_encryption_config_ref(&self) -> Option<&TransportEncryptionConfig<C>> {
		self.x509_config.as_ref()
	}

	config_accessors!();
}

#[cfg(not(feature = "x509"))]
impl<P, M> ServletConfig<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Start a [`ServletConfigBuilder`].
	pub fn builder() -> ServletConfigBuilder<P, M> {
		ServletConfigBuilder::default()
	}

	/// Worker registered under `name`, downcast to `W`.
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	config_accessors!();
}

#[cfg(feature = "x509")]
impl<P, M, C> ServletConfig<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Move encryption material out for bind without cloning keys.
	pub(crate) fn take_encryption_config(&mut self) -> Option<TransportEncryptionConfig<C>> {
		self.x509_config.take()
	}

	/// Split bind leftovers into the runtime accept-loop parts.
	pub(crate) fn into_runtime_parts(self) -> Result<runtime::ServletRuntimeParts, TightBeamError> {
		let env_config = self.servlet_config.ok_or(TightBeamError::MissingConfiguration)?;
		Ok(runtime::ServletRuntimeParts {
			env_config,
			collector_gates: self.collector_gates,
			mux_offer: self.mux_offer,
			hive_context: self.hive_context,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			workers: self.workers,
		})
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> ServletConfig<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Split bind leftovers into the runtime accept-loop parts.
	pub(crate) fn into_runtime_parts(self) -> Result<runtime::ServletRuntimeParts, TightBeamError> {
		let env_config = self.servlet_config.ok_or(TightBeamError::MissingConfiguration)?;
		Ok(runtime::ServletRuntimeParts {
			env_config,
			collector_gates: self.collector_gates,
			mux_offer: self.mux_offer,
			hive_context: self.hive_context,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			workers: self.workers,
		})
	}
}

#[cfg(feature = "x509")]
impl<P, M, C> Default for ServletConfig<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	fn default() -> Self {
		Self {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			x509_config: None,
			mux_offer: None,
			servlet_config: Some(Arc::new(())),
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
		}
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> Default for ServletConfig<P, M>
where
	P: Protocol,
	M: Message,
{
	fn default() -> Self {
		Self {
			_protocol: PhantomData,
			_message: PhantomData,
			mux_offer: None,
			servlet_config: Some(Arc::new(())),
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
		}
	}
}

#[cfg(feature = "x509")]
impl<P, M, C> Default for ServletConfigBuilder<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	fn default() -> Self {
		Self {
			x509_config: None,
			mux_offer: None,
			servlet_config: None,
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
			_phantom: PhantomData,
		}
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> Default for ServletConfigBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	fn default() -> Self {
		Self {
			mux_offer: None,
			servlet_config: None,
			hive_context: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
			message_decryptor: None,
			message_inflator: None,
			_phantom: PhantomData,
		}
	}
}

macro_rules! builder_methods {
	() => {
		/// Advertise multiplexing on accepted connections.
		///
		/// Requires encrypted transport: the offer is bound into the handshake
		/// transcript, so cleartext servlets never negotiate it.
		#[must_use]
		pub fn with_mux_offer(mut self, offer: impl IntoMuxOffer) -> Self {
			self.mux_offer = offer.into_mux_offer();
			self
		}

		/// Set the application env config.
		#[must_use]
		pub fn with_config<Cfg: Send + Sync + 'static>(mut self, config: Arc<Cfg>) -> Self {
			self.servlet_config = Some(config);
			self
		}

		/// Register a worker under its [`WorkerMetadata`] name.
		pub fn with_worker<W>(mut self, worker: W) -> Self
		where
			W: Worker + WorkerMetadata + 'static,
		{
			self.workers
				.insert(W::name().to_string(), Box::new(worker) as Box<dyn WorkerBox>);
			self
		}

		/// Append a collector gate policy.
		pub fn with_collector_gate<G>(mut self, gate: G) -> Self
		where
			G: GatePolicy + Send + Sync + 'static,
		{
			self.collector_gates.push(Arc::new(gate));
			self
		}

		/// Attach the hive context for intra-hive calls.
		#[must_use]
		pub fn with_hive_context(mut self, ctx: Arc<dyn HiveContext>) -> Self {
			self.hive_context = Some(ctx);
			self
		}

		/// Enable typed delivery of encrypted frame bodies.
		pub fn with_message_decryptor<D>(mut self, decryptor: D) -> Self
		where
			D: Decryptor + Send + Sync + 'static,
		{
			self.message_decryptor = Some(Arc::new(decryptor));
			self
		}

		/// Enable typed delivery of compressed frame bodies.
		pub fn with_message_inflator<I>(mut self, inflator: I) -> Self
		where
			I: Inflator + Send + Sync + 'static,
		{
			self.message_inflator = Some(Arc::new(inflator));
			self
		}
	};
}

#[cfg(feature = "x509")]
impl<P, M, C> ServletConfigBuilder<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Enable encrypted transport with the given server certificate.
	///
	/// - Non-empty `validators`: mutual auth; every validator must accept the client cert.
	/// - Empty `validators`: no client authentication.
	pub fn with_certificate(
		mut self,
		cert: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
		validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self, TightBeamError> {
		let certificate = Certificate::try_from(cert)?;
		let key_manager: HandshakeKeyManager<C> = HandshakeKeyManager::new(key);
		let mut encryption_config = TransportEncryptionConfig::new(certificate, key_manager);

		if !validators.is_empty() {
			encryption_config = encryption_config.with_client_validators(validators);
		}

		self.x509_config = Some(encryption_config);
		Ok(self)
	}

	builder_methods!();

	/// Finish the builder into a [`ServletConfig`].
	///
	/// When [`Self::with_config`] was not called, env defaults to `()` so
	/// [`ServletRuntime::start`] matches [`ServletConfig::default`].
	pub fn build(self) -> ServletConfig<P, M, C> {
		ServletConfig {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			x509_config: self.x509_config,
			mux_offer: self.mux_offer,
			servlet_config: self.servlet_config.or_else(|| Some(Arc::new(()))),
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
		}
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> ServletConfigBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	builder_methods!();

	/// Finish the builder into a [`ServletConfig`].
	///
	/// When [`Self::with_config`] was not called, env defaults to `()` so
	/// [`ServletRuntime::start`] matches [`ServletConfig::default`].
	pub fn build(self) -> ServletConfig<P, M> {
		ServletConfig {
			_protocol: PhantomData,
			_message: PhantomData,
			mux_offer: self.mux_offer,
			servlet_config: self.servlet_config.or_else(|| Some(Arc::new(()))),
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
		}
	}
}
