use core::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::colony::servlet::servlet_runtime::rt;
use crate::colony::servlet::{ServletContext, ServletService};
use crate::constants::DEFAULT_MAX_SERVER_CONNECTIONS;
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::{GatePolicy, SessionContext};
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::{MuxCapable, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::serve::MuxService;
use crate::transport::AsyncListenerTrait;
use crate::{Frame, TightBeamError};

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
/// Returns the loop [`rt::JoinHandle`]; aborting it stops the servlet.
/// Generic over [`AsyncListenerTrait`] so every protocol shares one path.
/// [`crate::colony::servlet::ServletRuntime::start`] calls this after bind and context setup.
pub fn serve_servlet<L, S>(
	listener: L,
	gates: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	mux_offer: Option<Arc<TransportOffer>>,
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

					// Share the mux offer with each accepted connection.
					transport = transport.with_mux_offer(mux_offer.clone());

					let service = Arc::clone(&service);
					rt::spawn(async move {
						// Hold the permit for the connection task lifetime.
						let _permit = permit;
						serve_connection_service(transport, service, None, None).await;
					});
				}
				Err(_error) => break,
			}
		}
	})
}
