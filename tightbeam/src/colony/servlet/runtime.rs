//! Protocol-generic servlet accept-loop state.
//!
//! - `servlet!` builds [`ServletHandlers`] and calls [`ServletRuntime::start`].
//! - Hand-written [`ServletService`]s use the same entry point.
//! - Address bytes are encoded once at start and shared as [`Arc<[u8]>`].
//! - Callers borrow [`addr`](ServletRuntime::addr) instead of cloning it.

use core::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::colony::common::take_and_abort;
use crate::colony::hive::{HiveContext, ServletBox};
use crate::colony::servlet::servlet_runtime::rt;
use crate::colony::servlet::{
	serve_servlet, RuntimeServletConf, Servlet, ServletConfig, ServletContext, ServletService, WorkerBox,
};
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::macros::server::AcceptedConnection;
use crate::policy::GatePolicy;
use crate::trace::TraceCollector;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::PolicyConfig;
use crate::transport::AsyncListenerTrait;
use crate::transport::Protocol;
use crate::transport::TransportError;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::crypto::profiles::CryptoProvider;
#[cfg(feature = "x509")]
use crate::transport::EncryptedProtocol;

/// Config fields [`ServletRuntime::start`] needs after the listener binds.
pub(crate) struct ServletRuntimeParts {
	pub(crate) env_config: Arc<dyn Any + Send + Sync>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) mux_offer: Option<Arc<TransportOffer>>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
}

/// Running accept loop and bound address for protocol `P`.
///
/// - Owns the accept-loop task handle and a replaceable trace handle.
/// - Retains address bytes as [`Arc<[u8]>`] for hive registration and scaling.
pub struct ServletRuntime<P: Protocol> {
	server_handle: Option<rt::JoinHandle>,
	addr: P::Address,
	addr_bytes: Arc<[u8]>,
	trace_handle: Arc<Mutex<Arc<TraceCollector>>>,
}

fn protocol_error<E: Into<TransportError>>(error: E) -> TightBeamError {
	let transport = error.into();
	TightBeamError::from(transport)
}

impl<P> ServletRuntime<P>
where
	P: Protocol + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
{
	/// Bind, start workers, build context, and spawn the accept loop.
	#[cfg(feature = "x509")]
	pub async fn start<M, C, S>(
		trace: Arc<TraceCollector>,
		mut servlet_conf: ServletConfig<P, M, C>,
		service: S,
	) -> Result<Self, TightBeamError>
	where
		M: Message,
		C: CryptoProvider + Send + Sync + 'static,
		S: ServletService,
		P: EncryptedProtocol<CryptoProvider = C>,
	{
		let bind_addr = P::default_bind_address().map_err(protocol_error)?;
		let encryption = servlet_conf.take_encryption_config();
		let (listener, addr) = if let Some(encryption_config) = encryption {
			P::bind_with(bind_addr, encryption_config).await.map_err(protocol_error)?
		} else {
			P::bind(bind_addr).await.map_err(protocol_error)?
		};

		let parts = servlet_conf.into_runtime_parts()?;
		let runtime = Self::spawn_loop(trace, parts, service, listener, addr).await?;
		Ok(runtime)
	}

	/// Bind, start workers, build context, and spawn the accept loop.
	#[cfg(not(feature = "x509"))]
	pub async fn start<M, S>(
		trace: Arc<TraceCollector>,
		servlet_conf: ServletConfig<P, M>,
		service: S,
	) -> Result<Self, TightBeamError>
	where
		M: Message,
		S: ServletService,
	{
		let bind_addr = P::default_bind_address().map_err(protocol_error)?;
		let (listener, addr) = P::bind(bind_addr).await.map_err(protocol_error)?;
		let parts = servlet_conf.into_runtime_parts()?;
		let runtime = Self::spawn_loop(trace, parts, service, listener, addr).await?;
		Ok(runtime)
	}

	async fn spawn_loop<S>(
		trace: Arc<TraceCollector>,
		parts: ServletRuntimeParts,
		service: S,
		listener: P::Listener,
		addr: P::Address,
	) -> Result<Self, TightBeamError>
	where
		S: ServletService,
	{
		let ServletRuntimeParts {
			env_config,
			collector_gates,
			mux_offer,
			hive_context,
			message_decryptor,
			message_inflator,
			workers,
		} = parts;

		let mut started_workers = HashMap::new();
		for (name, worker_box) in workers {
			let started = worker_box.start_boxed(Arc::clone(&trace)).await?;
			started_workers.insert(name, started);
		}

		let servlet_context = Arc::new(
			ServletContext::new(Arc::clone(&trace), env_config, started_workers, hive_context)
				.with_message_decryptor(message_decryptor)
				.with_message_inflator(message_inflator),
		);

		let server_handle = serve_servlet(listener, collector_gates, mux_offer, service, servlet_context);
		let addr_bytes: Arc<[u8]> = Arc::from(addr.clone().into());
		let trace_handle = Arc::new(Mutex::new(trace));

		let runtime = Self { server_handle: Some(server_handle), addr, addr_bytes, trace_handle };
		Ok(runtime)
	}
}

impl<P: Protocol> ServletRuntime<P> {
	/// Bound listen address (borrowed; no clone).
	pub fn addr(&self) -> &P::Address {
		&self.addr
	}

	/// Shared address bytes encoded once at start.
	pub fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::clone(&self.addr_bytes)
	}

	/// Address bytes without bumping the refcount.
	pub fn addr_bytes_ref(&self) -> &[u8] {
		&self.addr_bytes
	}

	/// Replace the live trace collector behind the shared handle.
	pub fn set_trace(&self, trace: Arc<TraceCollector>) {
		if let Ok(mut guard) = self.trace_handle.lock() {
			*guard = trace;
		}
	}

	/// Abort the accept loop.
	pub fn stop(mut self) {
		take_and_abort(&mut self.server_handle);
	}

	/// Wait for the accept loop to finish after stop or peer close.
	#[cfg(feature = "tokio")]
	pub async fn join(mut self) -> Result<(), rt::JoinError> {
		if let Some(handle) = self.server_handle.take() {
			let joined = rt::join(handle).await;
			return joined;
		}

		Ok(())
	}

	/// Wait for the accept loop to finish after stop or peer close.
	#[cfg(all(not(feature = "tokio"), feature = "std"))]
	pub fn join(mut self) -> Result<(), rt::JoinError> {
		if let Some(handle) = self.server_handle.take() {
			let joined = rt::join(handle);
			return joined;
		}

		Ok(())
	}
}

impl<P: Protocol> Drop for ServletRuntime<P> {
	fn drop(&mut self) {
		take_and_abort(&mut self.server_handle);
	}
}

impl<P> ServletBox for ServletRuntime<P>
where
	P: Protocol + 'static,
	P::Address: Sync,
{
	fn addr_bytes(&self) -> Arc<[u8]> {
		ServletRuntime::addr_bytes(self)
	}

	fn stop_boxed(self: Box<Self>) {
		(*self).stop();
	}
}

/// [`Servlet`] entry that takes [`RuntimeServletConf`] (config + handlers).
///
/// Prefer inherent [`ServletRuntime::start`] when you already have a
/// [`ServletService`]. Use this impl when an API bounds on [`Servlet`].
#[cfg(feature = "x509")]
impl<P, M, C> Servlet<M> for ServletRuntime<P>
where
	P: Protocol + EncryptedProtocol<CryptoProvider = C> + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	M: Message + Send + Sync + 'static,
	C: CryptoProvider + Send + Sync + 'static,
{
	type Conf = RuntimeServletConf<P, M, C>;
	type Address = P::Address;

	async fn start(trace: Arc<TraceCollector>, config: Option<Self::Conf>) -> Result<Self, TightBeamError> {
		let RuntimeServletConf { config, service } = config.unwrap_or_default();
		// Three-argument inherent start (not this trait method).
		ServletRuntime::start(trace, config, service).await
	}

	fn addr(&self) -> &Self::Address {
		ServletRuntime::addr(self)
	}

	fn stop(self) {
		ServletRuntime::stop(self);
	}

	async fn join(self) -> Result<(), rt::JoinError> {
		ServletRuntime::join(self).await
	}
}

#[cfg(not(feature = "x509"))]
impl<P, M> Servlet<M> for ServletRuntime<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	M: Message + Send + Sync + 'static,
{
	type Conf = RuntimeServletConf<P, M>;
	type Address = P::Address;

	async fn start(trace: Arc<TraceCollector>, config: Option<Self::Conf>) -> Result<Self, TightBeamError> {
		let RuntimeServletConf { config, service } = config.unwrap_or_default();
		ServletRuntime::start(trace, config, service).await
	}

	fn addr(&self) -> &Self::Address {
		ServletRuntime::addr(self)
	}

	fn stop(self) {
		ServletRuntime::stop(self);
	}

	async fn join(self) -> Result<(), rt::JoinError> {
		ServletRuntime::join(self).await
	}
}
