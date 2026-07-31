//! Servlet framework: policy-gated accept loops that dispatch unary,
//! streaming, and duplex handlers with shared workers and env config.
//!
//! # Macro-free path
//!
//! 1. Build handlers with [`ServletHandlers`] (or implement [`ServletService`]).
//! 2. Call [`ServletRuntime::start`] with a [`ServletConfig`].
//! 3. For call sites that need [`Servlet`], pass [`RuntimeServletConf`]
//!    (config + handlers) into [`Servlet::start`] on [`ServletRuntime`].
//!
//! Typed unary delivery without `servlet!`:
//! [`ServletHandlers::on_typed_unary`] or [`dispatch_typed_unary`].

pub mod macros;
pub mod runtime;
pub mod tracking;

pub use runtime::ServletRuntime;
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
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::GatePolicy;
use crate::policy::SessionContext;
use crate::router::RouterError;
use crate::trace::TraceCollector;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::{MuxCapable, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::serve::{unimplemented_error, MuxService};
use crate::transport::AsyncListenerTrait;
use crate::transport::Protocol;
use crate::transport::TightBeamAddress;
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

use tokio::sync::Semaphore;

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

/// Runtime task primitives used by servlet accept loops.
pub mod servlet_runtime {
	pub use crate::runtime::rt;
}

/// Boxed future returned by [`WorkerBox::start_boxed`].
pub type WorkerBoxStartFuture = Pin<Box<dyn Future<Output = Result<Box<dyn WorkerBox>, TightBeamError>> + Send>>;

/// Type-erased worker lifecycle for servlet-owned worker maps.
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

impl dyn WorkerBox {
	pub fn downcast_ref<W: 'static>(&self) -> Option<&W> {
		(self as &dyn core::any::Any).downcast_ref()
	}
}

// ============================================================================
// Servlet Context
// ============================================================================

/// Handler context: trace, env config, workers, optional hive link, and
/// message-body decryptor/inflator.
pub struct ServletContext {
	trace: Arc<TraceCollector>,
	env_config: Arc<dyn Any + Send + Sync>,
	workers: HashMap<String, Box<dyn WorkerBox>>,
	hive_context: Option<Arc<dyn HiveContext>>,
	message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
}

impl ServletContext {
	/// Build a context without message-body crypto or compression.
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

	/// Attach the frame-body decryptor used by typed delivery.
	#[must_use]
	pub fn with_message_decryptor(mut self, decryptor: Option<Arc<dyn Decryptor + Send + Sync>>) -> Self {
		self.message_decryptor = decryptor;
		self
	}

	/// Attach the frame-body inflator used by typed delivery.
	#[must_use]
	pub fn with_message_inflator(mut self, inflator: Option<Arc<dyn Inflator + Send + Sync>>) -> Self {
		self.message_inflator = inflator;
		self
	}

	/// Frame-body decryptor, when configured.
	pub fn message_decryptor(&self) -> Option<&dyn Decryptor> {
		self.message_decryptor.as_deref().map(|decryptor| decryptor as &dyn Decryptor)
	}

	/// Frame-body inflator, when configured.
	pub fn message_inflator(&self) -> Option<&dyn Inflator> {
		self.message_inflator.as_deref().map(|inflator| inflator as &dyn Inflator)
	}

	/// Trace collector for this servlet.
	pub fn trace(&self) -> &Arc<TraceCollector> {
		&self.trace
	}

	/// Environment configuration downcast to `T`.
	pub fn env_config<T: 'static>(&self) -> Result<&T, TightBeamError> {
		self.env_config.downcast_ref().ok_or(TightBeamError::MissingConfiguration)
	}

	/// Intra-hive communication handle, when this servlet runs inside a hive.
	pub fn hive_context(&self) -> Option<&Arc<dyn HiveContext>> {
		self.hive_context.as_ref()
	}

	/// Worker registered under `name`, downcast to `W`.
	pub fn worker<W: 'static>(&self, name: &str) -> Option<&W> {
		self.workers.get(name)?.downcast_ref()
	}

	/// Relay `input` to the worker named by [`WorkerMetadata`].
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
/// Fail-closed and in place: encrypted bodies without a decryptor, and
/// compressed bodies without an inflator, are rejected before decode.
/// On success the body is cleartext for the servlet's declared input type.
///
/// # Errors
///
/// - [`RouterError::ConfidentialFrame`]: encrypted body, no decryptor.
/// - [`RouterError::CompressedFrame`]: compressed body, no inflator.
/// - Decryption or decompression errors from the configured implementations.
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

/// Prepare, decode, and invoke a typed unary handler.
///
/// Same cleartext contract as the typed `handle:` arm of `servlet!`.
pub async fn dispatch_typed_unary<I, F, Fut>(
	mut frame: Frame,
	ctx: &ServletContext,
	handler: F,
) -> Result<Option<Frame>, TightBeamError>
where
	I: Message,
	F: FnOnce(I, Frame, &ServletContext) -> Fut,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>>,
{
	prepare_typed_frame(&mut frame, ctx)?;

	let message: I = crate::decode(&frame.message)?;
	let response = handler(message, frame, ctx).await?;
	Ok(response)
}

// ============================================================================
// Servlet Configuration
// ============================================================================

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
	pub(crate) mux_offer: Option<TransportOffer>,
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
	pub(crate) mux_offer: Option<TransportOffer>,
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
	mux_offer: Option<TransportOffer>,
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

	/// Application env config downcast to `Cfg`.
	pub fn to_env_config_ref<Cfg: 'static>(&self) -> Option<&Arc<Cfg>> {
		self.servlet_config.as_ref()?.downcast_ref()
	}

	/// Type-erased application env config.
	pub fn to_servlet_conf_ref(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
		self.servlet_config.as_ref()
	}

	/// Consume and return the worker map.
	pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
		self.workers
	}

	/// Consume and return collector gates.
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
	pub fn mux_offer(&self) -> Option<TransportOffer> {
		self.mux_offer.to_owned()
	}

	/// Take encryption config for bind without cloning key material.
	pub(crate) fn take_encryption_config(&mut self) -> Option<TransportEncryptionConfig<C>> {
		self.x509_config.take()
	}

	/// Consume into the parts [`ServletRuntime`] needs after bind.
	pub(crate) fn into_runtime_parts(self) -> Result<runtime::ServletRuntimeParts, TightBeamError> {
		let env_config = self.servlet_config.ok_or(TightBeamError::MissingConfiguration)?;
		let parts = runtime::ServletRuntimeParts {
			env_config,
			collector_gates: self.collector_gates,
			mux_offer: self.mux_offer,
			hive_context: self.hive_context,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			workers: self.workers,
		};
		Ok(parts)
	}
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

	/// Application env config downcast to `Cfg`.
	pub fn to_env_config_ref<Cfg: 'static>(&self) -> Option<&Arc<Cfg>> {
		self.servlet_config.as_ref()?.downcast_ref()
	}

	/// Type-erased application env config.
	pub fn to_servlet_conf_ref(&self) -> Option<&Arc<dyn Any + Send + Sync>> {
		self.servlet_config.as_ref()
	}

	/// Consume and return the worker map.
	pub fn to_workers(self) -> HashMap<String, Box<dyn WorkerBox>> {
		self.workers
	}

	/// Consume and return collector gates.
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
	pub fn mux_offer(&self) -> Option<TransportOffer> {
		self.mux_offer.to_owned()
	}

	/// Consume into the parts [`ServletRuntime`] needs after bind.
	pub(crate) fn into_runtime_parts(self) -> Result<runtime::ServletRuntimeParts, TightBeamError> {
		let env_config = self.servlet_config.ok_or(TightBeamError::MissingConfiguration)?;
		let parts = runtime::ServletRuntimeParts {
			env_config,
			collector_gates: self.collector_gates,
			mux_offer: self.mux_offer,
			hive_context: self.hive_context,
			message_decryptor: self.message_decryptor,
			message_inflator: self.message_inflator,
			workers: self.workers,
		};
		Ok(parts)
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

	/// Advertise multiplexing on accepted connections.
	///
	/// Requires encrypted transport: the offer is bound into the handshake
	/// transcript, so cleartext servlets never negotiate it.
	#[must_use]
	pub fn with_mux_offer(mut self, offer: Option<TransportOffer>) -> Self {
		self.mux_offer = offer;
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
		let gate = Arc::new(gate);
		self.collector_gates.push(gate);
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
		let decryptor = Arc::new(decryptor);
		self.message_decryptor = Some(decryptor);
		self
	}

	/// Enable typed delivery of compressed frame bodies.
	pub fn with_message_inflator<I>(mut self, inflator: I) -> Self
	where
		I: Inflator + Send + Sync + 'static,
	{
		let inflator = Arc::new(inflator);
		self.message_inflator = Some(inflator);
		self
	}

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
	/// Advertise multiplexing on accepted connections.
	///
	/// Requires encrypted transport: the offer is bound into the handshake
	/// transcript, so cleartext servlets never negotiate it.
	#[must_use]
	pub fn with_mux_offer(mut self, offer: Option<TransportOffer>) -> Self {
		self.mux_offer = offer;
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
		let gate = Arc::new(gate);
		self.collector_gates.push(gate);
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
		let decryptor = Arc::new(decryptor);
		self.message_decryptor = Some(decryptor);
		self
	}

	/// Enable typed delivery of compressed frame bodies.
	pub fn with_message_inflator<I>(mut self, inflator: I) -> Self
	where
		I: Inflator + Send + Sync + 'static,
	{
		let inflator = Arc::new(inflator);
		self.message_inflator = Some(inflator);
		self
	}

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

/// Lifecycle interface for named servlets and [`ServletRuntime`].
///
/// Generic over input message type `I`. Workers attached to a servlet share
/// that same input type. `servlet!` implements this for the generated type;
/// macro-free code uses [`ServletRuntime`] with [`RuntimeServletConf`].
pub trait Servlet<I> {
	/// Configuration type (typically [`ServletConfig`]).
	type Conf;

	/// Protocol-specific listen address.
	type Address: TightBeamAddress;

	/// Bind, start workers, and spawn the accept loop.
	fn start(
		trace: Arc<TraceCollector>,
		config: Option<Self::Conf>,
	) -> impl Future<Output = Result<Self, TightBeamError>> + Send
	where
		Self: Sized;

	/// Bound listen address (borrowed; no clone).
	fn addr(&self) -> &Self::Address;

	/// Abort the accept loop.
	fn stop(self);

	/// Wait for the accept loop to finish.
	fn join(self) -> impl Future<Output = Result<(), rt::JoinError>> + Send;

	/// Utilization in basis points (`0..=10000`) for hive balancing.
	///
	/// Default `None` means no metrics. Override (for example with
	/// [`LatencyTracker`]) when the hive should read load.
	fn utilization(&self) -> Option<BasisPoints> {
		None
	}
}

/// One method per stream kind; servlet analogue of [`MuxService`].
///
/// Handlers receive [`ServletContext`] (workers, env, decryptor/inflator,
/// hive link), not the transport [`SessionContext`]. Absent kinds refuse
/// with `Unimplemented`.
///
/// - `servlet!` builds this via [`ServletHandlers`].
/// - Macro-free path: implement the trait (or use [`ServletHandlers`]) and
///   call [`ServletRuntime::start`].
pub trait ServletService: Send + Sync + 'static {
	/// Answer one unary request frame.
	///
	/// # Errors
	///
	/// Failure closes the stream with its mapped status.
	fn unary(
		&self,
		frame: Frame,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (frame, ctx);
		async { Err(unimplemented_error()) }
	}

	/// Consume a streamed request body; optional unary reply frame.
	///
	/// # Errors
	///
	/// Failure closes the stream with its mapped status.
	fn streaming(
		&self,
		body: StreamBody,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (body, ctx);
		async { Err(unimplemented_error()) }
	}

	/// Full duplex on one stream: request chunks in, reply chunks out.
	///
	/// # Errors
	///
	/// Failure closes the stream with its mapped status.
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let _ = (body, reply, ctx);
		async { Err(unimplemented_error()) }
	}
}

/// Boxed handler future used by [`ServletHandlers`].
pub type ServletFuture<T> = Pin<Box<dyn Future<Output = Result<T, TightBeamError>> + Send>>;

type UnaryHandler = Box<dyn Fn(Frame, Arc<ServletContext>) -> ServletFuture<Option<Frame>> + Send + Sync>;
type StreamingHandler = Box<dyn Fn(StreamBody, Arc<ServletContext>) -> ServletFuture<Option<Frame>> + Send + Sync>;
type DuplexHandler = Box<dyn Fn(StreamBody, ReplySink, Arc<ServletContext>) -> ServletFuture<()> + Send + Sync>;

/// Closure-built [`ServletService`]. Absent kinds refuse with `Unimplemented`.
///
/// Assembled by `servlet!` handler arms. Hand-written services implement
/// [`ServletService`] directly instead.
#[derive(Default)]
pub struct ServletHandlers {
	unary: Option<UnaryHandler>,
	streaming: Option<StreamingHandler>,
	duplex: Option<DuplexHandler>,
}

impl ServletHandlers {
	/// Install the unary handler.
	pub fn on_unary<F, Fut>(mut self, handler: F) -> Self
	where
		F: Fn(Frame, Arc<ServletContext>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send + 'static,
	{
		self.unary = Some(Box::new(move |frame, ctx| Box::pin(handler(frame, ctx))));
		self
	}

	/// Install the streaming handler.
	pub fn on_streaming<F, Fut>(mut self, handler: F) -> Self
	where
		F: Fn(StreamBody, Arc<ServletContext>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send + 'static,
	{
		self.streaming = Some(Box::new(move |body, ctx| Box::pin(handler(body, ctx))));
		self
	}

	/// Install the duplex handler.
	pub fn on_duplex<F, Fut>(mut self, handler: F) -> Self
	where
		F: Fn(StreamBody, ReplySink, Arc<ServletContext>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<(), TightBeamError>> + Send + 'static,
	{
		self.duplex = Some(Box::new(move |body, reply, ctx| Box::pin(handler(body, reply, ctx))));
		self
	}

	/// Typed unary arm: [`prepare_typed_frame`], decode `I`, then `handler`.
	pub fn on_typed_unary<I, F, Fut>(self, handler: F) -> Self
	where
		I: Message + Send + 'static,
		F: Fn(I, Frame, &ServletContext) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send + 'static,
	{
		let handler = Arc::new(handler);
		self.on_unary(move |frame, ctx| {
			let handler = Arc::clone(&handler);
			async move {
				dispatch_typed_unary(frame, ctx.as_ref(), |message, frame, ctx| handler(message, frame, ctx)).await
			}
		})
	}
}

/// Config + handlers for [`Servlet`] on [`ServletRuntime`].
///
/// Use this when a call site needs [`Servlet::start`] without `servlet!`.
/// Hive registration only needs [`ServletBox`], which [`ServletRuntime`]
/// already implements.
#[cfg(feature = "x509")]
pub struct RuntimeServletConf<P, M, C: CryptoProvider = DefaultCryptoProvider>
where
	P: Protocol,
	M: Message,
{
	/// Bind, workers, gates, and env for the accept loop.
	pub config: ServletConfig<P, M, C>,
	/// Request handlers installed on the runtime.
	pub service: ServletHandlers,
}

#[cfg(feature = "x509")]
impl<P, M, C> Default for RuntimeServletConf<P, M, C>
where
	P: Protocol,
	M: Message,
	C: CryptoProvider + Send + Sync + 'static,
{
	fn default() -> Self {
		Self { config: ServletConfig::default(), service: ServletHandlers::default() }
	}
}

/// Config + handlers for [`Servlet`] on [`ServletRuntime`].
#[cfg(not(feature = "x509"))]
pub struct RuntimeServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	/// Bind, workers, gates, and env for the accept loop.
	pub config: ServletConfig<P, M>,
	/// Request handlers installed on the runtime.
	pub service: ServletHandlers,
}

#[cfg(not(feature = "x509"))]
impl<P, M> Default for RuntimeServletConf<P, M>
where
	P: Protocol,
	M: Message,
{
	fn default() -> Self {
		Self { config: ServletConfig::default(), service: ServletHandlers::default() }
	}
}

impl ServletService for ServletHandlers {
	fn unary(
		&self,
		frame: Frame,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		match self.unary.as_ref() {
			Some(handler) => handler(frame, ctx),
			None => Box::pin(async { Err(unimplemented_error()) }) as ServletFuture<_>,
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		match self.streaming.as_ref() {
			Some(handler) => handler(body, ctx),
			None => Box::pin(async { Err(unimplemented_error()) }) as ServletFuture<_>,
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		ctx: Arc<ServletContext>,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		match self.duplex.as_ref() {
			Some(handler) => handler(body, reply, ctx),
			None => Box::pin(async { Err(unimplemented_error()) }) as ServletFuture<_>,
		}
	}
}

/// [`MuxService`] adapter that binds a [`ServletService`] to its context.
///
/// Drops transport [`SessionContext`] at this boundary. Peer identity is
/// enforced by collector gates before dispatch; handlers see
/// [`ServletContext`] only. Session-aware logic belongs on [`MuxService`].
struct ContextService<S> {
	service: Arc<S>,
	ctx: Arc<ServletContext>,
}

impl<S: ServletService> MuxService for ContextService<S> {
	fn unary(
		&self,
		frame: Frame,
		_session: SessionContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let ctx = Arc::clone(&self.ctx);
		async move { service.unary(frame, ctx).await }
	}

	fn streaming(
		&self,
		body: StreamBody,
		_session: SessionContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let ctx = Arc::clone(&self.ctx);
		async move { service.streaming(body, ctx).await }
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		_session: SessionContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let ctx = Arc::clone(&self.ctx);
		async move { service.duplex(body, reply, ctx).await }
	}
}

/// Accept-loop task: apply collector gates and mux offer, then serve.
///
/// - Returns the loop [`rt::JoinHandle`]; aborting it stops the servlet.
/// - Generic over [`AsyncListenerTrait`] so every protocol shares one path.
/// - Called by [`ServletRuntime::start`] after bind and context setup.
pub fn serve_servlet<L, S>(
	listener: L,
	gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	mux_offer: Option<TransportOffer>,
	service: S,
	ctx: Arc<ServletContext>,
) -> rt::JoinHandle
where
	L: AsyncListenerTrait + Sync + 'static,
	L::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	S: ServletService,
{
	let service = Arc::new(ContextService { service: Arc::new(service), ctx });
	rt::spawn(async move {
		// Cap concurrent connection tasks (CWE-400). Excess accepts wait
		// in the listener backlog instead of spawning unbounded work.
		let permits = Arc::new(Semaphore::new(DEFAULT_MAX_SERVER_CONNECTIONS));
		loop {
			let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
				// Semaphore is never closed; acquire fails only if it were.
				break;
			};
			match listener.accept().await {
				Ok((mut transport, _addr)) => {
					for gate in &gates {
						transport = transport.with_collector_gate(Arc::clone(gate));
					}

					transport = transport.with_mux_offer(mux_offer.clone());

					let service = Arc::clone(&service);
					rt::spawn(async move {
						// Hold the permit for the connection task lifetime.
						let _permit = permit;
						serve_connection_service(transport, service, None, None).await;
					});
				}
				Err(_err) => break,
			}
		}
	})
}
