//! Library-side mux serving orchestration.
//!
//! The `server!` async accept loop hands each connection to
//! [`MuxAcceptor::serve`] after policy application and negotiation
//! ([`MuxAcceptor::negotiate_mux`]). That method runs the whole mux plane
//! (gated halves, drivers, responder) with the caller's [`MuxService`] behind
//! the transport's collector gate.
//!
//! [`MuxAcceptor::negotiate_mux`]: crate::transport::multiplex::MuxAcceptor::negotiate_mux
//! [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve

use core::future::Future;
use std::sync::Arc;

use crate::policy::GatePolicy;
use crate::policy::SessionContext;
use crate::policy::TransitStatus;
use crate::transport::envelopes::ResponsePackage;
use crate::transport::messaging::GateInbound;
use crate::transport::multiplex::{MuxDispatch, MuxHandle, ReplySink, StreamBody, StreamRoute};
use crate::utils::marker::MaybeSend;
use crate::utils::urn::Urn;
use crate::{Frame, TightBeamError};

/// Per-call context handed to every [`MuxService`] method.
///
/// Bundles the connection's live [`SessionContext`] (pre-split peer
/// identity plus the current receipt, so epoch renewals are observed
/// rather than a stale handshake snapshot) with the stream's
/// [`StreamRoute`] (the grpc-style dispatch target the initiator
/// stamped on the Open). Handlers take only what they need through the
/// accessors, so the struct grows without churning method signatures.
///
/// Unary opens are unrouted today ([`CallContext::target`] is `None`):
/// a unary frame self-describes its addressing in its payload, and no
/// routed-unary initiator exists. Streaming and duplex opens carry the
/// route a gateway reads to dispatch locally or splice to a peer.
pub struct CallContext {
	session: SessionContext,
	route: StreamRoute,
}

impl CallContext {
	/// Bundle a live session with the stream's route.
	///
	/// Public so an external [`MuxService`] implementation can build a
	/// context in its own tests. The serving path assembles one per
	/// dispatch. An unrouted call takes `StreamRoute::default()`.
	pub fn new(session: SessionContext, route: StreamRoute) -> Self {
		Self { session, route }
	}

	/// The connection's live session (peer identity and receipt).
	pub fn session(&self) -> &SessionContext {
		&self.session
	}

	/// Consume the context into its owned session, for a handler that
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

	/// Relay budget left on this open: the number of gateway forwards
	/// the stream may still spend. A `0` stream is served locally and
	/// never re-forwarded.
	pub fn hops_remaining(&self) -> u8 {
		self.route.hops_remaining()
	}
}

/// The interactions one served connection answers.
///
/// Each initiating client call stamps its interaction kind on the stream's
/// Open record, and [`MuxAcceptor::serve`] routes every peer stream to the
/// matching method here. One connection serves unary, streaming, and duplex
/// interactions concurrently, so the handler's shape is the only thing an
/// application decides.
///
/// # Call context
///
/// Every method receives a [`CallContext`]: the live session plus the
/// stream's route, so a handler reads peer identity and dispatch target
/// through one parameter.
///
/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
pub trait MuxService: Send + Sync + 'static {
	/// Answer one unary request. The frame has already passed the
	/// transport's collector gate.
	///
	/// # Errors
	/// The failure closes the stream with a mapped status (see
	/// [`MuxAcceptor::serve`]).
	///
	/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
	fn unary(
		&self,
		frame: Frame,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (frame, cx);
		async { Err(TightBeamError::unimplemented()) }
	}

	/// Consume a streamed request body and answer with an optional
	/// unary reply frame. The collector gate has already run at
	/// dispatch with no request frame (`None`). See [`GatePolicy`].
	///
	/// # Errors
	/// The failure closes the stream with its mapped status (see
	/// [`MuxAcceptor::serve`]).
	///
	/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
	fn streaming(
		&self,
		body: StreamBody,
		cx: CallContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (body, cx);
		async { Err(TightBeamError::unimplemented()) }
	}

	/// Consume request chunks while pushing reply chunks (full duplex
	/// on one stream). The collector gate has already run at dispatch
	/// with no request frame (`None`). See [`GatePolicy`].
	///
	/// # Errors
	/// The failure closes the stream with a mapped status (see
	/// [`MuxAcceptor::serve`]).
	///
	/// [`MuxAcceptor::serve`]: crate::transport::multiplex::MuxAcceptor::serve
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		cx: CallContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let _ = (body, reply, cx);
		async { Err(TightBeamError::unimplemented()) }
	}
}

/// A frame-in/frame-out closure is a unary-only [`MuxService`]:
/// streaming and duplex streams answer [`TransitStatus::Unimplemented`].
/// The closure keeps the bare [`SessionContext`] grammar, and a unary
/// open carries no route to expose.
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

/// [`MuxDispatch`] adapter running a [`MuxService`] behind the transport's
/// collector gate: gated unary frames answer with the gate's status and never
/// reach the service, and every invocation sees the live session receipt.
pub(crate) struct GatedService<S> {
	service: Arc<S>,
	gate: Box<dyn GatePolicy>,
	snapshot: SessionContext,
	handle: MuxHandle,
}

impl<S> GatedService<S> {
	/// Put `service` behind `gate` on the connection that `handle` serves,
	/// with `snapshot` as the session before the live receipt.
	pub(crate) fn new(service: S, gate: Box<dyn GatePolicy>, snapshot: SessionContext, handle: MuxHandle) -> Self {
		Self { service: Arc::new(service), gate, snapshot, handle }
	}

	/// Session context with the live receipt, per invocation.
	fn session(&self) -> SessionContext {
		self.snapshot.with_live_receipt(self.handle.session_receipt())
	}
}

impl<S: MuxService> MuxDispatch for GatedService<S> {
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = ResponsePackage> + MaybeSend {
		// Gates are synchronous: evaluate and audit at dispatch, so
		// only the service and its inputs enter the task.
		let session = self.session();
		let status = self.handle.gate_inbound(self.gate.as_ref(), Some(frame.as_ref()), &session);
		let service = Arc::clone(&self.service);
		async move {
			if status != TransitStatus::Ok {
				return ResponsePackage::new(status, None);
			}

			let request = Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone());
			let cx = CallContext::new(session, StreamRoute::local());
			ResponsePackage::from_outcome(service.unary(request, cx).await)
		}
	}

	fn streaming(&self, body: StreamBody, route: StreamRoute) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let session = self.session();
		let status = self.handle.gate_inbound(self.gate.as_ref(), None, &session);
		let service = Arc::clone(&self.service);
		async move {
			if status != TransitStatus::Ok {
				return ResponsePackage::new(status, None);
			}

			let cx = CallContext::new(session, route);
			ResponsePackage::from_outcome(service.streaming(body, cx).await)
		}
	}

	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransitStatus> + MaybeSend {
		let session = self.session();
		let status = self.handle.gate_inbound(self.gate.as_ref(), None, &session);
		let service = Arc::clone(&self.service);
		async move {
			if status != TransitStatus::Ok {
				return status;
			}

			let cx = CallContext::new(session, route);
			match service.duplex(body, reply, cx).await {
				Ok(()) => TransitStatus::Ok,
				Err(error) => error.failure_status(),
			}
		}
	}
}
