use core::future::Future;
use std::sync::Arc;

use crate::colony::servlet::servlet_runtime::rt;
use crate::colony::servlet::{ServletContext, ServletService};
use crate::macros::server::{serve_connection_service, AcceptedConnection};
use crate::policy::GatePolicy;
use crate::transport::accept::AcceptPlane;
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::multiplex::{MuxCapable, ReplySink, StreamBody};
use crate::transport::policy::PolicyConfig;
use crate::transport::serve::{CallContext, MuxService};
use crate::transport::AsyncListenerTrait;
use crate::{Frame, TightBeamError};

/// [`MuxService`] adapter that binds a [`ServletService`] to its context.
///
/// Handlers receive [`ServletContext`], and collector gates enforce peer
/// identity before dispatch. Session-aware or route-aware logic belongs on
/// [`MuxService`], which keeps the transport [`CallContext`].
struct ContextService<S> {
	service: Arc<S>,
	ctx: Arc<ServletContext>,
}

impl<S: ServletService> MuxService for ContextService<S> {
	fn unary(
		&self,
		frame: Frame,
		_cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let ctx = Arc::clone(&self.ctx);
		async move { service.unary(frame, ctx).await }
	}

	fn streaming(
		&self,
		body: StreamBody,
		_cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let ctx = Arc::clone(&self.ctx);
		async move { service.streaming(body, ctx).await }
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		_cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let service = Arc::clone(&self.service);
		let ctx = Arc::clone(&self.ctx);
		async move { service.duplex(body, reply, ctx).await }
	}
}

/// Serves one servlet: apply collector gates and the mux offer, then
/// dispatch each connection.
///
/// Returns the loop [`rt::JoinHandle`]. Aborting it stops the servlet.
/// Generic over [`AsyncListenerTrait`] so every protocol shares one path.
/// [`crate::colony::servlet::ServletRuntime::start`] calls this after bind
/// and context setup.
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
	rt::spawn(AcceptPlane::default().accept_on(listener, move |mut transport: L::Transport| {
		for gate in &gates {
			transport = transport.with_collector_gate(Arc::clone(gate));
		}

		// Share the mux offer with each accepted connection.
		transport = transport.with_mux_offer(mux_offer.clone());

		let service = Arc::clone(&service);
		async move { serve_connection_service(transport, service, None, None).await }
	}))
}
