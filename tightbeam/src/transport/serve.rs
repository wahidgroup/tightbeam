//! Library-side mux serving orchestration.
//!
//! The `server!` async accept loop delegates here after policy application
//! and negotiation ([`MuxAcceptor::negotiate_mux`]): [`serve_mux`] runs the
//! whole mux plane (gated halves, drivers, responder) with the caller's
//! [`MuxService`] behind the transport's collector gate. The connection
//! pool uses [`drive_mux`] for the client side of the same plane, staying
//! generic over [`MuxConnector`](crate::transport::multiplex::MuxConnector).

use core::future::Future;
use std::sync::Arc;

use crate::policy::GatePolicy;
use crate::policy::SessionContext;
use crate::policy::TransitStatus;
use crate::runtime::rt;
use crate::transport::envelopes::ResponsePackage;
use crate::transport::error::TransportError;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::messaging::gate_inbound_frame;
use crate::transport::multiplex::{
	MuxAcceptor, MuxDispatch, MuxHandle, MuxRekeyContext, MuxResponder, MuxRole, MuxTransport, ReplySink, SpawnedMux,
	StreamBody,
};
use crate::transport::TransportResult;
use crate::utils::marker::MaybeSend;
use crate::{Frame, TightBeamError};

/// Assemble the mux plane over split halves and spawn both drivers
/// through [`MuxTransport::spawn`].
pub(crate) fn drive_mux<R, W>(
	reader: R,
	writer: W,
	role: MuxRole,
	settings: MuxSettings,
	cancel_budget: Option<u32>,
	rekey: Option<MuxRekeyContext>,
) -> (MuxHandle, MuxResponder, rt::JoinHandle)
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	let mut mux = MuxTransport::new(reader, writer, role, settings);
	if let Some(budget) = cancel_budget {
		mux = mux.with_cancel_budget(budget);
	}
	if let Some(context) = rekey {
		mux = mux.with_rekey(context);
	}

	let SpawnedMux { handle, responder, reader_task } = mux.spawn();
	(handle, responder, reader_task)
}

/// The interactions one served connection answers.
///
/// Each initiating client call stamps its interaction kind on the stream's
/// Open record, and [`serve_mux`] routes every peer stream to the matching
/// method here. One connection serves unary, streaming, and duplex
/// interactions concurrently, so the handler's shape is the only thing an
/// application decides.
///
/// Every method receives the connection's [`SessionContext`]: the pre-split
/// peer identity plus the live session receipt, so epoch renewals rotating
/// the receipt are observed rather than a stale handshake snapshot.
pub trait MuxService: Send + Sync + 'static {
	/// Answer one unary request. The frame has already passed the
	/// transport's collector gate.
	///
	/// # Errors
	/// The failure closes the stream with a mapped status (see [`serve_mux`]).
	fn unary(
		&self,
		frame: Frame,
		session: SessionContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (frame, session);
		async { Err(unimplemented_error()) }
	}

	/// Consume a streamed request body and answer with an optional
	/// unary reply frame.
	///
	/// # Errors
	/// The failure closes the stream with its mapped status (see
	/// [`serve_mux`]).
	fn streaming(
		&self,
		body: StreamBody,
		session: SessionContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		let _ = (body, session);
		async { Err(unimplemented_error()) }
	}

	/// Consume request chunks while pushing reply chunks (full duplex
	/// on one stream). Frame gates cannot apply.
	///
	/// # Errors
	/// The failure closes the stream with a mapped status (see [`serve_mux`]).
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		session: SessionContext,
	) -> impl Future<Output = Result<(), TightBeamError>> + Send {
		let _ = (body, reply, session);
		async { Err(unimplemented_error()) }
	}
}

/// A frame-in/frame-out closure is a unary-only [`MuxService`]:
/// streaming and duplex streams answer [`TransitStatus::Unimplemented`].
impl<F, Fut> MuxService for F
where
	F: Fn(Frame, SessionContext) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send,
{
	fn unary(
		&self,
		frame: Frame,
		session: SessionContext,
	) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
		self(frame, session)
	}
}

/// The refusal behind every [`MuxService`] default.
fn unimplemented_error() -> TightBeamError {
	TransportError::from(TransitStatus::Unimplemented).into()
}

/// Map a service failure to the stream's terminal status: a failure already
/// carrying a transit status keeps it, anything else answers
/// [`TransitStatus::Internal`] so the peer can tell a failure apart from an
/// accepted empty reply and the failure stays attributable.
fn failure_status(error: &TightBeamError) -> TransitStatus {
	if let TightBeamError::TransportError(TransportError::OperationFailed(failure)) = error {
		return TransitStatus::try_from(*failure).unwrap_or(TransitStatus::Internal);
	}

	TransitStatus::Internal
}

/// Terminal response for a unary or streaming service outcome.
fn respond(outcome: Result<Option<Frame>, TightBeamError>) -> ResponsePackage {
	match outcome {
		Ok(message) => ResponsePackage::new(TransitStatus::Ok, message),
		Err(error) => ResponsePackage::new(failure_status(&error), None),
	}
}

/// [`MuxDispatch`] adapter running a [`MuxService`] behind the transport's
/// collector gate: gated unary frames answer with the gate's status and never
/// reach the service, and every invocation sees the live session receipt.
struct GatedService<S> {
	service: Arc<S>,
	gate: Box<dyn GatePolicy>,
	snapshot: SessionContext,
	handle: MuxHandle,
}

impl<S> GatedService<S> {
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
		let status = gate_inbound_frame(self.gate.as_ref(), &self.handle, &frame, &session);
		let service = Arc::clone(&self.service);
		async move {
			if status != TransitStatus::Ok {
				return ResponsePackage::new(status, None);
			}

			let request = Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone());
			respond(service.unary(request, session).await)
		}
	}

	fn streaming(&self, body: StreamBody) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let session = self.session();
		let service = Arc::clone(&self.service);
		async move { respond(service.streaming(body, session).await) }
	}

	fn duplex(&self, body: StreamBody, reply: ReplySink) -> impl Future<Output = TransitStatus> + MaybeSend {
		let session = self.session();
		let service = Arc::clone(&self.service);
		async move {
			match service.duplex(body, reply, session).await {
				Ok(()) => TransitStatus::Ok,
				Err(error) => failure_status(&error),
			}
		}
	}
}

/// Serve a mux-negotiated connection until it ends.
///
/// Consumes the transport into gated halves, spawns both drivers, and runs
/// the responder with `service` routed by each stream's kind: unary frames
/// pass the transport's collector gate before reaching [`MuxService::unary`],
/// streaming and duplex bodies reach their methods as they arrive. Service
/// failures close their stream with the failure's mapped status.
///
/// - `cancel_budget` overrides CVE-2023-44487 cancel-abuse default when set.
///
/// # Errors
/// - `InvalidState` / `OperationFailed(EncryptorUnavailable)`: no handshake
/// - Terminal responder failures (see [`MuxResponder::serve_with`])
pub async fn serve_mux<T, S>(
	mut transport: T,
	settings: MuxSettings,
	service: S,
	cancel_budget: Option<u32>,
) -> TransportResult<()>
where
	T: MuxAcceptor,
	S: MuxService,
{
	let rekey = transport.take_rekey()?;
	let snapshot = transport.session_context();
	let (gate, (reader, writer)) = transport.into_gated_halves()?;
	let (handle, responder, _reader_task) = drive_mux(reader, writer, MuxRole::Server, settings, cancel_budget, rekey);

	responder
		.serve_with(GatedService { service: Arc::new(service), gate, snapshot, handle })
		.await
}
