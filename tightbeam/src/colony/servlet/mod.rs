//! Servlet framework for containerized tightbeam applications
//!
//! Servlets provide a way to create self-contained, policy-driven message
//! processing applications that can be easily deployed and tested.

pub mod macros;
pub mod tracking;

// Re-export tracking types
pub use tracking::{LatencyTracker, ServletMetrics};

use core::convert::TryFrom;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::colony::worker::Worker;
use crate::core::Message;
use crate::trace::TraceCollector;
use crate::transport::Protocol;
use crate::transport::TightBeamAddress;
use crate::utils::BasisPoints;
use crate::TightBeamError;
use crate::policy::GatePolicy;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::colony::servlet::servlet_runtime::rt;
use crate::colony::worker::WorkerMetadata;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::key::KeySpec;
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
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
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
	pub(crate) servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
}

/// Builder for ServletConf
#[cfg(feature = "x509")]
pub struct ServletConfBuilder<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	x509_config: Option<TransportEncryptionConfig<C>>,
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	_phantom: PhantomData<(P, M, C)>,
}

/// Builder for ServletConf
#[cfg(not(feature = "x509"))]
pub struct ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
	servlet_config: Option<Arc<dyn Any + Send + Sync>>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
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
			servlet_config: Some(Arc::new(())),
			workers: HashMap::new(),
			collector_gates: Vec::new(),
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
			servlet_config: Some(Arc::new(())),
			workers: HashMap::new(),
			collector_gates: Vec::new(),
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
			servlet_config: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
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
			servlet_config: None,
			workers: HashMap::new(),
			collector_gates: Vec::new(),
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
		key: KeySpec,
		validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self, TightBeamError> {
		let cert_obj = Certificate::try_from(cert)?;
		let key_mgr = HandshakeKeyManager::try_from(key)?;
		self.x509_config = Some(TransportEncryptionConfig::new(cert_obj, key_mgr).with_client_validators(validators));
		Ok(self)
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
		self.collector_gates.push(Arc::new(gate));
		self
	}

	/// Build the final ServletConf
	pub fn build(self) -> ServletConf<P, M, C> {
		ServletConf {
			_protocol: PhantomData,
			_message: PhantomData,
			_crypto: PhantomData,
			x509_config: self.x509_config,
			servlet_config: self.servlet_config,
			workers: self.workers,
			collector_gates: self.collector_gates,
		}
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> ServletConfBuilder<P, M>
where
	P: Protocol,
	M: Message,
{
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
		self.collector_gates.push(Arc::new(gate));
		self
	}

	/// Build the final ServletConf
	pub fn build(self) -> ServletConf<P, M> {
		ServletConf {
			_protocol: PhantomData,
			_message: PhantomData,
			servlet_config: self.servlet_config,
			workers: self.workers,
			collector_gates: self.collector_gates,
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
