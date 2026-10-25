//! The state of a servlet accept loop, generic over its protocol.
//!
//! - `servlet!` builds [`crate::colony::servlet::ServletHandlers`] and calls [`ServletRuntime::start`].
//! - A [`ServletService`] written without the macro uses the same entry point.

use std::collections::HashMap;
use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::hive::{HiveContext, ServletBox};
use crate::colony::servlet::serve::ContextService;
use crate::colony::servlet::{RuntimeServletConf, Servlet, ServletConfig, ServletContext, ServletService, WorkerBox};
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::core::{Inflator, Message};
use crate::crypto::aead::Decryptor;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::GatePolicy;
use crate::runtime::rt;
use crate::trace::{TraceCollector, TraceHandle};
use crate::transport::accept::{AcceptPlane, ConnectionTerms};
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::MuxCapable;
use crate::transport::policy::{CollectorGateConfig, PolicyConfig};
use crate::transport::AsyncListenerTrait;
use crate::transport::Protocol;
use crate::utils::time::Clock;
use crate::TightBeamError;

use crate::crypto::profiles::CryptoProvider;
use crate::transport::EncryptedProtocol;

/// The config fields [`ServletRuntime::start`] needs after the listener
/// binds.
pub(crate) struct ServletRuntimeParts<Env> {
	/// The signer of the certificate the listener presents, [`None`] in the
	/// clear.
	pub(crate) signer: Option<SignerIdentifier>,
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

/// A live accept loop and its bound address for protocol `P`.
///
/// - The runtime owns the accept-loop task handle and a replaceable trace handle.
/// - The runtime retains the address bytes as [`Arc<[u8]>`] for hive registration and scaling.
pub struct ServletRuntime<P: Protocol> {
	server_handle: Option<rt::JoinHandle>,
	addr: P::Address,
	addr_bytes: Arc<[u8]>,
	/// The signer of the certificate the listener presents, recorded at start.
	signer: Option<SignerIdentifier>,
	trace_handle: TraceHandle,
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
	/// The loop attaches the servlet's trace to each connection it accepts,
	/// before the handshake.
	///
	/// # Warning
	///
	/// The trace records every connection, a peer that never authenticates
	/// included. The default `BoundedMemorySink` drops each event past
	/// `max_events`, the servlet's own included, so a long-lived servlet needs
	/// an `EventSink` that forwards each event, or a reader that drains the
	/// trace.
	///
	/// # Errors
	///
	/// - [`TightBeamError::TransportError`] -- the protocol forms no default
	///   bind address, or the listener fails to bind.
	/// - [`TightBeamError`] -- a worker fails to start, as the worker reports it.
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
		let bind_addr = P::default_bind_address().map_err(TightBeamError::transport)?;
		let (accept, parts) = servlet_conf.into_bind_parts();
		let bound = accept.bind::<P>(bind_addr).await;
		let (listener, addr) = bound.map_err(TightBeamError::transport)?;

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
			signer,
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

		let trace_handle = TraceHandle::new(trace);
		let servlet_context = Arc::new(
			ServletContext::sharing_trace(trace_handle.clone(), env_config, started_workers, hive_context)
				.with_message_decryptor(message_decryptor)
				.with_message_inflator(message_inflator),
		);

		let service = Arc::new(ContextService::new(service, servlet_context));
		let plane = AcceptPlane::new(DEFAULT_MAX_SERVER_CONNECTIONS, clock);
		let terms = ConnectionTerms::new(trace_handle.clone(), mux_offer);

		// The gates go on each connection before it dispatches, so a peer the
		// collector gates refuse never reaches a handler.
		let serve = move |mut transport: <P::Listener as Protocol>::Transport| {
			for gate in &collector_gates {
				transport = transport.with_collector_gate(Arc::clone(gate));
			}

			let service = Arc::clone(&service);
			async move { serve_connection_service(transport, service, None, None).await }
		};
		let accept_loop = plane.accept_owned(listener, terms, serve);

		let server_handle = rt::spawn(accept_loop);
		let addr_bytes: Arc<[u8]> = Arc::from(addr.clone().into());

		let runtime = Self { server_handle: Some(server_handle), addr, addr_bytes, signer, trace_handle };
		Ok(runtime)
	}
}

impl<P: Protocol> ServletRuntime<P> {
	/// Borrows the bound listen address.
	pub fn addr(&self) -> &P::Address {
		&self.addr
	}

	/// Returns the shared address bytes, encoded once at start.
	pub fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::clone(&self.addr_bytes)
	}

	/// Borrows the address bytes and leaves the reference count unchanged.
	pub fn addr_bytes_ref(&self) -> &[u8] {
		&self.addr_bytes
	}

	/// Replaces the live trace of this servlet with `trace`.
	///
	/// - Each connection that the servlet accepts after the call records into `trace`.
	/// - Each handler that reads [`ServletContext::trace`] after the call records into `trace`.
	/// - A connection accepted before the call, and each worker, keep the trace they started with.
	///
	/// The handle holds one whole collector, so a lock that a holder poisoned
	/// in a panic holds no torn state, and the replacement goes in.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::servlet::ServletRuntime;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// /// Gives the connections that `runtime` accepts from here on a fresh trace.
	/// fn rotate(runtime: &ServletRuntime<TokioListener>) -> Arc<TraceCollector> {
	///     let trace = Arc::new(TraceCollector::default());
	///     runtime.set_trace(Arc::clone(&trace));
	///     trace
	/// }
	/// ```
	pub fn set_trace(&self, trace: Arc<TraceCollector>) {
		self.trace_handle.replace(trace);
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

	fn signer(&self) -> Option<&SignerIdentifier> {
		self.signer.as_ref()
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
