//! The library side of a served mux connection: the [`MuxService`] trait,
//! its call context, and the adapter that gates each call.
//!
//! The `server!` async accept loop applies its policies and negotiates
//! multiplexing ([`MuxAcceptor::negotiate_mux`]), then hands each connection
//! that negotiated it to [`MuxAcceptor::serve`]. That method runs the whole
//! mux plane (gated halves, drivers, responder) with the caller's
//! [`MuxService`] behind the transport's collector gate.
//!
//! [`MuxAcceptor::negotiate_mux`]: crate::transport::multiplex::MuxAcceptor::negotiate_mux
//! [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve

use core::future::Future;
use std::sync::Arc;

use crate::policy::GatePolicy;
use crate::policy::SessionContext;
use crate::policy::TransitStatus;
use crate::transport::envelopes::ResponsePackage;
use crate::transport::messaging::{GateInbound, HandlerAudit};
use crate::transport::multiplex::{MuxDispatch, MuxHandle, ReplySink, StreamBody, StreamRoute};
use crate::transport::TransportResult;
use crate::urn::Urn;
use crate::utils::marker::MaybeSend;
use crate::{Frame, TightBeamError};

/// The per-call context that every [`MuxService`] method receives.
///
/// It bundles two values, and a handler takes what it needs through the
/// accessors, so the struct grows without a change to any method signature:
///
/// - The connection's live [`SessionContext`]: the peer identity and the current receipt, renewals included.
/// - The stream's [`StreamRoute`]: the grpc-style dispatch target the initiator stamped on the Open.
///
/// # Routing
///
/// A unary frame states its addressing in its payload, so the initiator
/// opens a unary stream unrouted and [`CallContext::target`] is `None`.
/// Streaming and duplex opens carry the route a gateway reads to dispatch
/// locally or splice to a peer.
pub struct CallContext {
	session: SessionContext,
	route: StreamRoute,
}

impl CallContext {
	/// Bundles a live session with the stream's route.
	///
	/// The constructor is public so that an external [`MuxService`]
	/// implementation can build a context in its own tests. The serve path
	/// assembles one per dispatch. An unrouted call takes
	/// `StreamRoute::default()`.
	pub fn new(session: SessionContext, route: StreamRoute) -> Self {
		Self { session, route }
	}

	/// The connection's live session (peer identity and receipt).
	pub fn session(&self) -> &SessionContext {
		&self.session
	}

	/// Consumes the context into its owned session, for a handler that
	/// stores or forwards the session past the call.
	pub fn into_session(self) -> SessionContext {
		self.session
	}

	/// The stream's grpc-style route.
	pub fn route(&self) -> &StreamRoute {
		&self.route
	}

	/// The grpc-style dispatch target, or `None` for an unrouted open.
	pub fn target(&self) -> Option<&Urn<'static>> {
		self.route.target()
	}

	/// The relay budget left on this open: the number of gateway forwards
	/// that the stream has left to spend. The gateway that holds a stream at
	/// `0` serves it locally.
	pub fn hops_remaining(&self) -> u8 {
		self.route.hops_remaining()
	}
}

/// The interactions one served connection answers.
///
/// Each client call stamps its interaction kind on the Open record of its
/// stream, and [`MuxAcceptor::serve`] routes every peer stream to the method
/// of that kind here. One connection serves unary, streaming, and duplex
/// interactions concurrently, so the handler's shape is the only thing an
/// application decides.
///
/// # Call context
///
/// Every method receives a [`CallContext`]: the live session plus the
/// stream's route, so a handler reads the peer identity and the dispatch
/// target through one parameter.
///
/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
pub trait MuxService: Send + Sync + 'static {
	/// Answers one unary request. The frame has already passed the
	/// transport's collector gate.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the failure closes the stream with a mapped
	///   status (see [`MuxAcceptor::serve`]).
	///
	/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		// The default refuses this kind and drops its inputs unread.
		let _ = (frame, cx);
		async { Err(TightBeamError::unimplemented()) }
	}

	/// Consumes a streamed request body and answers with an optional
	/// unary reply frame. The collector gate has already run at
	/// dispatch with no request frame (`None`). See [`GatePolicy`].
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the failure closes the stream with its mapped
	///   status (see [`MuxAcceptor::serve`]).
	///
	/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
	fn streaming(
		&self,
		body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		// The default refuses this kind and drops its inputs unread.
		let _ = (body, cx);
		async { Err(TightBeamError::unimplemented()) }
	}

	/// Consumes request chunks and pushes reply chunks at the same time, in
	/// full duplex on one stream. The collector gate has already run at
	/// dispatch with no request frame (`None`). See [`GatePolicy`].
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the failure closes the stream with a mapped
	///   status (see [`MuxAcceptor::serve`]).
	///
	/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		// The default refuses this kind and drops its inputs unread.
		let _ = (body, reply, cx);
		async { Err(TightBeamError::unimplemented()) }
	}
}

/// A closure from a request frame to a reply frame is a unary-only
/// [`MuxService`], so its streaming and duplex streams answer
/// [`TransitStatus::Unimplemented`]. The closure takes the bare
/// [`SessionContext`], because a unary open is unrouted.
impl<F, Fut> MuxService for F
where
	F: Fn(Frame, SessionContext) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send,
{
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		self(frame, cx.into_session())
	}
}

/// A [`MuxDispatch`] adapter that runs a [`MuxService`] behind the transport's
/// collector gate, where every invocation sees the live session receipt.
///
/// - A call that the gate refuses answers with the gate's status, and stops short of the service.
/// - The connection's trail records each service call as a handler span.
/// - A handler that fails with an error of its own records `HANDLER_FAILED`.
/// - A default method of the service returns [`TransportError::NotServed`] to the responder.
///
/// [`TransportError::NotServed`]: crate::transport::TransportError::NotServed
pub(crate) struct GatedService<S> {
	service: Arc<S>,
	gate: Box<dyn GatePolicy>,
	snapshot: SessionContext,
	handle: MuxHandle,
}

impl<S> GatedService<S> {
	/// Puts `service` behind `gate` on the connection that `handle` serves,
	/// with `snapshot` as the session before the live receipt.
	pub(crate) fn new(service: S, gate: Box<dyn GatePolicy>, snapshot: SessionContext, handle: MuxHandle) -> Self {
		Self { service: Arc::new(service), gate, snapshot, handle }
	}

	/// Returns the session context with the live receipt, built per invocation.
	fn session(&self) -> SessionContext {
		self.snapshot.with_live_receipt(self.handle.session_receipt())
	}

	/// Gates one invocation and records its verdict in the connection's trace.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at
	///   the event of the evaluation or the verdict.
	fn verdict(&self, frame: Option<&Frame>, session: &SessionContext) -> TransportResult<TransitStatus> {
		Ok(self.handle.gate_inbound(self.gate.as_ref(), frame, session)?)
	}
}

impl<S: MuxService> MuxDispatch for GatedService<S> {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		// Gates are synchronous, so the call evaluates the gate and audits the
		// verdict at dispatch. The service, its inputs, and the handle whose
		// trail records the handler span enter the task.
		let session = self.session();
		let verdict = self.verdict(Some(frame.as_ref()), &session);
		let service = Arc::clone(&self.service);
		let handle = &self.handle;
		async move {
			let status = verdict?;
			if status != TransitStatus::Ok {
				return Ok(ResponsePackage::new(status, None));
			}

			let request = Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone());
			let cx = CallContext::new(session, StreamRoute::local());
			let outcome = handle.run_handler(service.unary(request, cx)).await;
			let (status, reply) = outcome.settle_stream(handle)?;

			Ok(ResponsePackage::new(status, reply.flatten()))
		}
	}

	fn streaming(
		&self,
		body: StreamBody,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		let session = self.session();
		let verdict = self.verdict(None, &session);
		let service = Arc::clone(&self.service);
		let handle = &self.handle;
		async move {
			let status = verdict?;
			if status != TransitStatus::Ok {
				return Ok(ResponsePackage::new(status, None));
			}

			let cx = CallContext::new(session, route);
			let outcome = handle.run_handler(service.streaming(body, cx)).await;
			let (status, reply) = outcome.settle_stream(handle)?;

			Ok(ResponsePackage::new(status, reply.flatten()))
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		let session = self.session();
		let verdict = self.verdict(None, &session);
		let service = Arc::clone(&self.service);
		let handle = &self.handle;
		async move {
			let status = verdict?;
			if status != TransitStatus::Ok {
				return Ok(status);
			}

			let cx = CallContext::new(session, route);
			let outcome = handle.run_handler(service.duplex(body, reply, cx)).await;
			let (status, _closed) = outcome.settle_stream(handle)?;

			Ok(status)
		}
	}
}
