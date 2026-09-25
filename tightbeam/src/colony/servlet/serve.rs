use core::future::Future;
use std::sync::Arc;

use crate::colony::servlet::{ServletContext, ServletService};
use crate::transport::multiplex::{ReplySink, StreamBody};
use crate::transport::serve::{CallContext, MuxService};
use crate::{Frame, TightBeamError};

/// [`MuxService`] adapter that binds a [`ServletService`] to its context.
///
/// Handlers receive [`ServletContext`], and collector gates enforce peer
/// identity before dispatch. Session-aware or route-aware logic belongs on
/// [`MuxService`], which keeps the transport [`CallContext`].
pub(super) struct ContextService<S: ServletService> {
	service: Arc<S>,
	ctx: Arc<ServletContext<S::Env>>,
}

impl<S: ServletService> ContextService<S> {
	/// Binds `service` to the context every one of its handlers receives.
	pub(super) fn new(service: S, ctx: Arc<ServletContext<S::Env>>) -> Self {
		Self { service: Arc::new(service), ctx }
	}
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
