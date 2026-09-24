//! Protocol-generic servlet accept-loop state.
//!
//! - `servlet!` builds [`crate::colony::servlet::ServletHandlers`] and
//!   calls [`ServletRuntime::start`].
//! - Hand-written [`ServletService`]s use the same entry point.
//! - Address bytes are encoded once at start and shared as [`Arc<[u8]>`].
//! - Callers borrow [`addr`](ServletRuntime::addr) instead of cloning it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::colony::hive::{HiveContext, ServletBox};
use crate::colony::servlet::serve::ContextService;
use crate::colony::servlet::servlet_runtime::rt;
use crate::colony::servlet::{RuntimeServletConf, Servlet, ServletConfig, ServletContext, ServletService, WorkerBox};
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::GatePolicy;
use crate::trace::TraceCollector;
use crate::transport::accept::AcceptPlane;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::{CollectorGateConfig, PolicyConfig};
use crate::transport::AsyncListenerTrait;
use crate::transport::Protocol;
use crate::transport::TransportError;
use crate::utils::time::Clock;
use crate::TightBeamError;

use crate::crypto::profiles::CryptoProvider;
use crate::transport::EncryptedProtocol;

/// The config fields [`ServletRuntime::start`] needs after the listener
/// binds.
pub(crate) struct ServletRuntimeParts<Env> {
	pub(crate) env_config: Arc<Env>,
	pub(crate) collector_gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	pub(crate) mux_offer: Option<Arc<TransportOffer>>,
	pub(crate) hive_context: Option<Arc<dyn HiveContext>>,
	pub(crate) message_decryptor: Option<Arc<dyn Decryptor + Send + Sync>>,
	pub(crate) message_inflator: Option<Arc<dyn Inflator + Send + Sync>>,
	pub(crate) workers: HashMap<String, Box<dyn WorkerBox>>,
	/// The accept loop paces its retries on this clock.
	pub(crate) clock: Arc<dyn Clock>,
}

/// A running accept loop and its bound address for protocol `P`.
///
/// - The runtime owns the accept-loop task handle and a replaceable trace handle.
/// - The runtime retains the address bytes as [`Arc<[u8]>`] for hive registration and scaling.
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
	/// Binds the listener, starts the workers, builds the servlet context,
	/// and spawns the accept loop.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the listener fails to bind, or a worker fails to start.
	pub async fn start<M, C, Env, S>(
		trace: Arc<TraceCollector>,
		servlet_conf: ServletConfig<P, M, C, Env>,
		service: S,
	) -> Result<Self, TightBeamError>
	where
		M: Message,
		C: CryptoProvider + Send + Sync + 'static,
		S: ServletService<Env = Env>,
		Env: Send + Sync + 'static,
		P: EncryptedProtocol<CryptoProvider = C>,
	{
		let bind_addr = P::default_bind_address().map_err(protocol_error)?;
		let (encryption, parts) = servlet_conf.into_bind_parts();
		let (listener, addr) = if let Some(encryption_config) = encryption {
			P::bind_with(bind_addr, encryption_config).await.map_err(protocol_error)?
		} else {
			P::bind(bind_addr).await.map_err(protocol_error)?
		};

		let runtime = Self::spawn_loop(trace, parts, service, listener, addr).await?;
		Ok(runtime)
	}

	async fn spawn_loop<Env, S>(
		trace: Arc<TraceCollector>,
		parts: ServletRuntimeParts<Env>,
		service: S,
		listener: P::Listener,
		addr: P::Address,
	) -> Result<Self, TightBeamError>
	where
		S: ServletService<Env = Env>,
		Env: Send + Sync + 'static,
	{
		let ServletRuntimeParts {
			env_config,
			collector_gates,
			mux_offer,
			hive_context,
			message_decryptor,
			message_inflator,
			workers,
			clock,
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

		let service = Arc::new(ContextService::new(service, servlet_context));
		let plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, clock);

		// The gates go on each connection before it dispatches, so a peer the
		// collector gates refuse never reaches a handler.
		let accept_loop = plane.accept_on(listener, move |mut transport: <P::Listener as Protocol>::Transport| {
			for gate in &collector_gates {
				transport = transport.with_collector_gate(Arc::clone(gate));
			}

			transport = transport.with_mux_offer(mux_offer.clone());

			let service = Arc::clone(&service);
			async move { serve_connection_service(transport, service, None, None).await }
		});

		let server_handle = rt::spawn(accept_loop);
		let addr_bytes: Arc<[u8]> = Arc::from(addr.clone().into());
		let trace_handle = Arc::new(Mutex::new(trace));

		let runtime = Self { server_handle: Some(server_handle), addr, addr_bytes, trace_handle };
		Ok(runtime)
	}
}

impl<P: Protocol> ServletRuntime<P> {
	/// Returns the bound listen address by reference, so the call clones
	/// nothing.
	pub fn addr(&self) -> &P::Address {
		&self.addr
	}

	/// Returns the shared address bytes, encoded once at start.
	pub fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::clone(&self.addr_bytes)
	}

	/// Borrows the address bytes without bumping the reference count.
	pub fn addr_bytes_ref(&self) -> &[u8] {
		&self.addr_bytes
	}

	/// Replaces the live trace collector behind the shared handle. A
	/// poisoned handle keeps its old collector.
	pub fn set_trace(&self, trace: Arc<TraceCollector>) {
		if let Ok(mut guard) = self.trace_handle.lock() {
			*guard = trace;
		}
	}

	/// Aborts the accept loop.
	pub fn stop(mut self) {
		rt::take_and_abort(&mut self.server_handle);
	}

	/// Waits for the accept loop task to finish.
	pub async fn join(mut self) -> Result<(), rt::JoinError> {
		if let Some(handle) = self.server_handle.take() {
			let joined = rt::join(handle).await;
			return joined;
		}

		Ok(())
	}
}

impl<P: Protocol> Drop for ServletRuntime<P> {
	fn drop(&mut self) {
		rt::take_and_abort(&mut self.server_handle);
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

/// The [`Servlet`] entry point, which takes a [`RuntimeServletConf`] that
/// bundles the config and the handlers.
///
/// Prefer the inherent [`ServletRuntime::start`] when you already have a
/// [`ServletService`]. Use this impl when an API bounds on [`Servlet`].
impl<P, M, C, Env> Servlet<M, Env> for ServletRuntime<P>
where
	P: Protocol + EncryptedProtocol<CryptoProvider = C> + Send + Sync + 'static,
	P::Listener: AsyncListenerTrait + Sync + 'static,
	<P::Listener as Protocol>::Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static,
	M: Message + Send + Sync + 'static,
	C: CryptoProvider + Send + Sync + 'static,
	Env: Send + Sync + 'static,
{
	type Conf = RuntimeServletConf<P, M, C, Env>;
	type Address = P::Address;

	async fn start(trace: Arc<TraceCollector>, config: Self::Conf) -> Result<Self, TightBeamError> {
		let RuntimeServletConf { config, service } = config;
		// The path names the three-argument inherent `start`, so the call
		// reaches that method and not this trait method.
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
