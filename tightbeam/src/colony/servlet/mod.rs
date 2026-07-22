//! Servlet framework for containerized tightbeam applications
//!
//! Servlets provide a way to create self-contained, policy-driven message
//! processing applications that can be easily deployed and tested.

pub mod macros;
pub mod tracking;

// Re-export tracking types
pub use tracking::{LatencyTracker, ServletMetrics, UtilizationReporter};

use core::convert::TryFrom;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::hive::HiveContext;
use crate::colony::servlet::servlet_runtime::rt;
use crate::colony::worker::Worker;
use crate::colony::worker::WorkerMetadata;
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::policy::GatePolicy;
use crate::router::RouterError;
use crate::trace::TraceCollector;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::Protocol;
use crate::transport::TightBeamAddress;
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::key::SigningKeyProvider;
	pub use crate::crypto::profiles::CryptoProvider;
	pub use crate::crypto::x509::policy::CertificateValidation;
	pub use crate::crypto::x509::{Certificate, CertificateSpec};
	pub use crate::transport::handshake::HandshakeKeyManager;
	pub use crate::transport::TransportEncryptionConfig;
}

#[cfg(feature = "x509")]
use x509::*;

/// Re-export unified runtime primitives
pub mod servlet_runtime {
	pub use crate::runtime::rt;
}

/// Type alias for boxed worker start future
pub type WorkerBoxStartFuture = Pin<Box<dyn Future<Output = Result<Box<dyn WorkerBox>, TightBeamError>> + Send>>;

/// Trait for type-erased worker lifecycle management
pub trait WorkerBox: Send + Sync + core::any::Any {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture;
}

impl<W: Worker + 'static> WorkerBox for W {
	fn start_boxed(self: Box<Self>, trace: Arc<TraceCollector>) -> WorkerBoxStartFuture {
		Box::pin(async move {
			let started = (*self).start(trace).await?;
			Ok(Box::new(started) as Box<dyn WorkerBox>)
		})
	}
}

// Downcast helper
impl dyn WorkerBox {
	pub fn downcast_ref<W: 'static>(&self) -> Option<&W> {
		(self as &dyn core::any::Any).downcast_ref()
	}
}

// =============================================================================
// Servlet Context
// =============================================================================

/// Unified context for servlet handlers.
///
/// Provides access to trace collection, environment configuration, workers,
/// and hive context for intra-hive communication.
pub struct ServletContext {
	trace: Arc<TraceCollector>,
	env_config: Arc<dyn Any + Send + Sync>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

impl ServletContext {
	/// Create a new servlet context
	pub fn new(
		trace: Arc<TraceCollector>,
		env_config: Arc<dyn Any + Send + Sync>,
		workers: HashMap<String, Box<dyn WorkerBox>>,
		hive_context: Option<Arc<dyn HiveContext>>,
	) -> Self {
		Self {
			trace,
			env_config,
			workers,
			hive_context,
			message_decryptor: None,
			message_inflator: None,
		}
	}

	/// Attach the decryptor used for frame-level (message body) decryption
	#[must_use]
	pub fn with_message_decryptor(mut self, decryptor: Option<Arc<dyn Decryptor + Send + Sync>>) -> Self {
		self.message_decryptor = decryptor;
		self
	}

	/// Attach the inflator used for message body decompression
	#[must_use]
	pub fn with_message_inflator(mut self, inflator: Option<Arc<dyn Inflator + Send + Sync>>) -> Self {
		self.message_inflator = inflator;
		self
	}

	/// Get the frame-level message decryptor, when configured
	pub fn message_decryptor(&self) -> Option<&dyn Decryptor> {
		self.message_decryptor.as_deref().map(|decryptor| decryptor as &dyn Decryptor)
	}

	/// Get the message body inflator, when configured
	pub fn message_inflator(&self) -> Option<&dyn Inflator> {
		self.message_inflator.as_deref().map(|inflator| inflator as &dyn Inflator)
	}

	/// Get the trace collector
	pub fn trace(&self) -> &Arc<TraceCollector> {
		&self.trace
	}

	/// Get the environment configuration (downcasted to the specific type)
	pub fn env_config<T: 'static>(&self) -> Result<&T, TightBeamError> {
		self.env_config.downcast_ref().ok_or(TightBeamError::MissingConfiguration)
	}

	/// Get the hive context for intra-hive servlet communication
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// Get a worker by name (downcasted to the specific type)
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	/// Relay a message to a worker by type name
	///
	/// This finds the worker by its registered name and calls its relay method.
	pub async fn relay<W>(&self, input: Arc<W::Input>) -> Result<W::Output, TightBeamError>
	where
		W: Worker + WorkerMetadata + 'static,
	{
		let name = W::name();
		let worker = self.worker::<W>(name).ok_or(TightBeamError::MissingConfiguration)?;
		worker.relay(input).await.map_err(|e| e.into())
	}
}

/// Normalize a frame to cleartext before typed delivery.
///
/// Applies the servlet's configured message-body capabilities in place,
/// fail-closed: an encrypted body without a configured decryptor and a
/// compressed body without a configured inflator are rejected before any
/// decode attempt. On success the frame is cleartext and its body can be
/// decoded as the servlet's declared input type.
///
/// # Errors
///
/// - [`RouterError::ConfidentialFrame`] -- encrypted body, no decryptor.
/// - [`RouterError::CompressedFrame`] -- compressed body, no inflator.
/// - Decryption or decompression errors from the configured
///   implementations.
pub fn prepare_typed_frame(frame: &mut Frame, ctx: &ServletContext) -> Result<(), TightBeamError> {
	if frame.metadata.confidentiality.is_some() {
		let decryptor = ctx.message_decryptor().ok_or(RouterError::ConfidentialFrame)?;
		frame.decrypt_in_place(decryptor, ctx.message_inflator())?;

		return Ok(());
	}

	if frame.metadata.compactness.is_some() {
		let inflator = ctx.message_inflator().ok_or(RouterError::CompressedFrame)?;
		frame.inflate_in_place(inflator)?;
	}

	Ok(())
}

// =============================================================================
// Servlet Configuration
// =============================================================================

/// Configuration for a servlet, containing x509, application config, and workers
#[cfg(feature = "x509")]
pub struct ServletConf<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	pub(crate) _protocol: PhantomData<P>,
	pub(crate) _message: PhantomData<M>,
	pub(crate) _crypto: PhantomData<C>,
	pub(crate) x509_config: Option<TransportEncryptionConfig<C>>,
	pub(crate) mux_offer: Option<TransportOffer>,
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

/// Configuration for a servlet, containing application config and workers
#[cfg(not(feature = "x509"))]
pub struct ServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	pub(crate) _protocol: PhantomData<P>,
	pub(crate) _message: PhantomData<M>,
	pub(crate) mux_offer: Option<TransportOffer>,
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

/// Builder for ServletConf
#[cfg(feature = "x509")]
pub struct ServletConfBuilder<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	x509_config: Option<TransportEncryptionConfig<C>>,
	mux_offer: Option<TransportOffer>,
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	_phantom: PhantomData<(P, M, C)>,
}

/// Builder for ServletConf
#[cfg(not(feature = "x509"))]
pub struct ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	mux_offer: Option<TransportOffer>,
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	_phantom: PhantomData<(P, M)>,
}

#[cfg(feature = "x509")]
impl<P, M, C> ServletConf<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Create a new ServletConf builder
	pub fn builder() -> ServletConfBuilder<P, M, C> {
		ServletConfBuilder::default()
	}

	/// Get a worker by name (downcasted to the specific type)
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	/// Get the x509 configuration
	pub fn to_encryption_config_ref(&self) -> Option<&TransportEncryptionConfig<C>> {
		self.x509_config.as_ref()
	}

	/// Get the servlet application config (downcasted to the specific type)
	pub fn to_env_config_ref<Cfg: 'static>(&self) -> Option<&Arc<Cfg>> {
		self.servlet_config.as_ref()?.downcast_ref()
	}

	/// Get servlet config
	pub fn to_servlet_conf_ref(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
		self.servlet_config.as_ref()
	}

	/// Get workers map
	pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
		self.workers
	}

	/// Get collector gates
	pub fn to_collector_gates(self) -> Vec<Arc<dyn GatePolicy + Send + Sync>> {
		self.collector_gates
	}

	/// Get collector gates by reference
	pub fn collector_gates_ref(&self) -> &[Arc<dyn GatePolicy + Send + Sync>] {
		&self.collector_gates
	}

	/// Get the hive context for intra-hive servlet communication
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// Get the frame-level message decryptor, when configured
	pub fn to_message_decryptor(&self) -> Option<Arc<dyn Decryptor + Send + Sync>> {
		self.message_decryptor.as_ref().map(Arc::clone)
	}

	/// Get the message body inflator, when configured
	pub fn to_message_inflator(&self) -> Option<Arc<dyn Inflator + Send + Sync>> {
		self.message_inflator.as_ref().map(Arc::clone)
	}

	/// Get the multiplexing advertisement for accepted connections
	pub fn mux_offer(&self) -> Option<TransportOffer> {
		self.mux_offer
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> ServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Create a new ServletConf builder
	pub fn builder() -> ServletConfBuilder<P, M> {
		ServletConfBuilder::default()
	}

	/// Get a worker by name (downcasted to the specific type)
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	/// Get the servlet application config (downcasted to the specific type)
	pub fn to_env_config_ref<Cfg: 'static>(&self) -> Option<&Arc<Cfg>> {
		self.servlet_config.as_ref()?.downcast_ref()
	}

	/// Get servlet config
	pub fn to_servlet_conf_ref(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
		self.servlet_config.as_ref()
	}

	/// Get workers map
	pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
		self.workers
	}

	/// Get collector gates
	pub fn to_collector_gates(self) -> Vec<Arc<dyn GatePolicy + Send + Sync>> {
		self.collector_gates
	}

	/// Get collector gates by reference
	pub fn collector_gates_ref(&self) -> &[Arc<dyn GatePolicy + Send + Sync>] {
		&self.collector_gates
	}

	/// Get the hive context for intra-hive servlet communication
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// Get the frame-level message decryptor, when configured
	pub fn to_message_decryptor(&self) -> Option<Arc<dyn Decryptor + Send + Sync>> {
		self.message_decryptor.as_ref().map(Arc::clone)
	}

	/// Get the message body inflator, when configured
	pub fn to_message_inflator(&self) -> Option<Arc<dyn Inflator + Send + Sync>> {
		self.message_inflator.as_ref().map(Arc::clone)
	}

	/// Get the multiplexing advertisement for accepted connections
	pub fn mux_offer(&self) -> Option<TransportOffer> {
		self.mux_offer
	}
}

#[cfg(feature = "x509")]
impl<P, M, C> Default for ServletConf<P, M, C>
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
impl<P, M> Default for ServletConf<P, M>
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
impl<P, M, C> Default for ServletConfBuilder<P, M, C>
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
impl<P, M> Default for ServletConfBuilder<P, M>
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

#[cfg(feature = "x509")]
impl<P, M, C> ServletConfBuilder<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	/// Add x509 configuration for encrypted transport
	pub fn with_certificate(
		mut self,
		cert: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
		validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self, TightBeamError> {
		let certificate = Certificate::try_from(cert)?;
		let key_manager: HandshakeKeyManager<C> = HandshakeKeyManager::new(key);
		let encryption_config = TransportEncryptionConfig::new(certificate, key_manager);

		self.x509_config = Some(encryption_config.with_client_validators(validators));
		Ok(self)
	}

	/// Advertise multiplexing on accepted connections. Requires an
	/// encrypted transport: the offer is bound into the handshake
	/// transcript, so cleartext servlets never negotiate it
	#[must_use]
	pub fn with_mux_offer(mut self, offer: Option<TransportOffer>) -> Self {
		self.mux_offer = offer;
		self
	}

	/// Add servlet application configuration
	#[must_use]
	pub fn with_config<Cfg: Send + Sync + 'static>(mut self, config: Arc<Cfg>) -> Self {
		self.servlet_config = Some(config);
		self
	}

	/// Add a worker using its WorkerMetadata name
	pub fn with_worker<W>(mut self, worker: W) -> Self
	where
		W: Worker + WorkerMetadata + 'static,
	{
		self.workers
			.insert(W::name().to_string(), Box::new(worker) as Box<dyn WorkerBox>);
		self
	}

	/// Add a collector gate policy
	pub fn with_collector_gate<G>(mut self, gate: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		let gate = Arc::new(gate);
		self.collector_gates.push(gate);
		self
	}

	/// Add hive context for intra-hive servlet communication
	#[must_use]
	pub fn with_hive_context(mut self, ctx: Arc<dyn HiveContext>) -> Self {
		self.hive_context = Some(ctx);
		self
	}

	/// Add a decryptor so typed handlers can receive encrypted frames
	pub fn with_message_decryptor<D>(mut self, decryptor: D) -> Self
	where
		D: Decryptor + Send + Sync + 'static,
	{
		let decryptor = Arc::new(decryptor);
		self.message_decryptor = Some(decryptor);
		self
	}

	/// Add an inflator so typed handlers can receive compressed frames
	pub fn with_message_inflator<I>(mut self, inflator: I) -> Self
	where
		I: Inflator + Send + Sync + 'static,
	{
		let inflator = Arc::new(inflator);
		self.message_inflator = Some(inflator);
		self
	}

	/// Build the final ServletConf
	pub fn build(self) -> ServletConf<P, M, C> {
		ServletConf {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			x509_config: self.x509_config,
			mux_offer: self.mux_offer,
			servlet_config: self.servlet_config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
		}
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Advertise multiplexing on accepted connections. Requires an
	/// encrypted transport: the offer is bound into the handshake
	/// transcript, so cleartext servlets never negotiate it
	#[must_use]
	pub fn with_mux_offer(mut self, offer: Option<TransportOffer>) -> Self {
		self.mux_offer = offer;
		self
	}

	/// Add servlet application configuration
	#[must_use]
	pub fn with_config<Cfg: Send + Sync + 'static>(mut self, config: Arc<Cfg>) -> Self {
		self.servlet_config = Some(config);
		self
	}

	/// Add a worker using its WorkerMetadata name
	pub fn with_worker<W>(mut self, worker: W) -> Self
	where
		W: Worker + WorkerMetadata + 'static,
	{
		self.workers
			.insert(W::name().to_string(), Box::new(worker) as Box<dyn WorkerBox>);
		self
	}

	/// Add a collector gate policy
	pub fn with_collector_gate<G>(mut self, gate: G) -> Self
	where
		G: GatePolicy + Send + Sync + 'static,
	{
		let gate = Arc::new(gate);
		self.collector_gates.push(gate);
		self
	}

	/// Add hive context for intra-hive servlet communication
	#[must_use]
	pub fn with_hive_context(mut self, ctx: Arc<dyn HiveContext>) -> Self {
		self.hive_context = Some(ctx);
		self
	}

	/// Add a decryptor so typed handlers can receive encrypted frames
	pub fn with_message_decryptor<D>(mut self, decryptor: D) -> Self
	where
		D: Decryptor + Send + Sync + 'static,
	{
		let decryptor = Arc::new(decryptor);
		self.message_decryptor = Some(decryptor);
		self
	}

	/// Add an inflator so typed handlers can receive compressed frames
	pub fn with_message_inflator<I>(mut self, inflator: I) -> Self
	where
		I: Inflator + Send + Sync + 'static,
	{
		let inflator = Arc::new(inflator);
		self.message_inflator = Some(inflator);
		self
	}

	/// Build the final ServletConf
	pub fn build(self) -> ServletConf<P, M> {
		ServletConf {
			_protocol: PhantomData,
			_message: PhantomData,
			mux_offer: self.mux_offer,
			servlet_config: self.servlet_config,
			hive_context: self.hive_context,
			workers: self.workers,
			collector_gates: self.collector_gates,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
		}
	}
}

/// Trait for servlet implementations
///
/// Provides a common interface for all servlets created with the `servlet!`
/// macro. Servlets are containerized applications that process TightBeam
/// messages.
///
/// The servlet is generic over the input message type `I` that it processes.
/// All workers in a servlet must share the same input type.
pub trait Servlet<I> {
	/// Configuration type for this servlet (use ServletConf)
	type Conf;

	/// Address type for this servlet (protocol-specific)
	type Address: TightBeamAddress;

	/// Start the servlet with configuration
	fn start(
		trace: Arc<TraceCollector>,
		config: Option<Self::Conf>,
	) -> impl Future<Output = Result<Self, TightBeamError>> + Send
	where
		Self: Sized;

	/// Get the local address the servlet is bound to
	fn addr(&self) -> Self::Address;

	/// Stop the servlet gracefully
	fn stop(self);

	/// Wait for the servlet to finish
	fn join(self) -> impl Future<Output = Result<(), rt::JoinError>> + Send;

	/// Report current utilization as basis points (0-10000)
	///
	/// Used by hives for load balancing and auto-scaling decisions.
	/// Returns `None` by default, indicating no metrics are available.
	/// Servlets can override this to report actual utilization
	/// (e.g., using `LatencyTracker`).
	fn utilization(&self) -> Option<BasisPoints> {
		None
	}
}
