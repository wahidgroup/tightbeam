//! Library-side mux serving orchestration.
//!
//! The `server!` async accept loop delegates here after policy application
//! and negotiation ([`MuxAcceptor::negotiate_mux`]): [`serve_mux`] runs the
//! whole mux plane (gated halves, drivers, responder) with the caller's
//! handler behind the transport's collector gate. The connection pool uses
//! [`drive_mux`] for the client side of the same plane, staying generic
//! over [`MuxConnector`](crate::transport::multiplex::MuxConnector).

use core::future::Future;
use std::sync::Arc;

use crate::policy::SessionContext;
use crate::policy::TransitStatus;
use crate::runtime::rt;
use crate::transport::envelopes::ResponsePackage;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::messaging::gate_inbound_frame;
use crate::transport::multiplex::{
	MuxAcceptor, MuxHandle, MuxRekeyContext, MuxResponder, MuxRole, MuxTransport, ReplySink, SpawnedMux, StreamBody,
};
use crate::transport::TransportResult;
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

/// Serve a mux-negotiated connection until it ends.
///
/// Consumes the transport into gated halves, spawns both drivers, and runs
/// the responder with `handler` behind the transport's collector gate:
/// gated frames answer with the gate's status and never reach the handler,
/// handler failures answer `TransitStatus::Internal` with no frame so the
/// peer can tell them apart from an accepted empty reply. `cancel_budget`
/// overrides the CVE-2023-44487 cancel-abuse default when set.
///
/// Every gate and handler invocation receives the connection's
/// [`SessionContext`]: the pre-split peer identity plus the live session
/// receipt, so epoch renewals rotating the receipt are observed rather
/// than a stale handshake snapshot.
///
/// # Errors
/// - `InvalidState` / `OperationFailed(EncryptorUnavailable)`: no handshake
/// - Terminal responder failures (see [`MuxResponder::serve`])
pub async fn serve_mux<T, H, Fut>(
	mut transport: T,
	settings: MuxSettings,
	handler: H,
	cancel_budget: Option<u32>,
) -> TransportResult<()>
where
	T: MuxAcceptor,
	H: Fn(Frame, SessionContext) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send,
{
	let rekey = transport.take_rekey()?;
	let snapshot = transport.session_context();
	let (gate, (reader, writer)) = transport.into_gated_halves()?;
	let (handle, responder, _reader_task) = drive_mux(reader, writer, MuxRole::Server, settings, cancel_budget, rekey);

	// The handler enters one concurrent task per frame.
	let handler = Arc::new(handler);

	responder
		.serve(move |frame: Arc<Frame>| {
			// Gates are synchronous: evaluate and audit at dispatch, so
			// only the handler and its inputs enter the task.
			let session = snapshot.with_live_receipt(handle.session_receipt());
			let status = gate_inbound_frame(gate.as_ref(), &handle, &frame, &session);
			let handler = Arc::clone(&handler);
			async move {
				if status != TransitStatus::Ok {
					return ResponsePackage::new(status, None);
				}

				let request = Arc::try_unwrap(frame).unwrap_or_else(|shared| (*shared).clone());
				match handler(request, session).await {
					Ok(message) => ResponsePackage::new(TransitStatus::Ok, message),
					// A handler failure is answered with a distinct status so
					// the peer can tell it apart from an accepted empty reply
					// and so the failure is attributable, not laundered to Ok.
					Err(_) => ResponsePackage::new(TransitStatus::Internal, None),
				}
			}
		})
		.await
}

/// Serve a mux-negotiated connection with streamed request bodies.
///
/// Frame gates cannot apply: dispatch happens before the body has
/// arrived, so there is no frame to evaluate. Identity-based policy
/// moves into the handler, which receives the connection's
/// [`SessionContext`] (pre-split peer identity plus the live session
/// receipt). Handler failures answer `TransitStatus::Internal`.
///
/// # Errors
/// - `InvalidState` / `OperationFailed(EncryptorUnavailable)`: no handshake
/// - Terminal responder failures (see [`MuxResponder::serve_streaming`])
pub async fn serve_streaming_mux<T, H, Fut>(
	mut transport: T,
	settings: MuxSettings,
	handler: H,
	cancel_budget: Option<u32>,
) -> TransportResult<()>
where
	T: MuxAcceptor,
	H: Fn(StreamBody, SessionContext) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<Option<Frame>, TightBeamError>> + Send,
{
	let rekey = transport.take_rekey()?;
	let snapshot = transport.session_context();
	let (reader, writer) = transport.into_envelope_halves()?;
	let (handle, responder, _reader_task) = drive_mux(reader, writer, MuxRole::Server, settings, cancel_budget, rekey);

	let handler = Arc::new(handler);

	responder
		.serve_streaming(move |body: StreamBody| {
			let session = snapshot.with_live_receipt(handle.session_receipt());
			let handler = Arc::clone(&handler);
			async move {
				match handler(body, session).await {
					Ok(message) => ResponsePackage::new(TransitStatus::Ok, message),
					Err(_) => ResponsePackage::new(TransitStatus::Internal, None),
				}
			}
		})
		.await
}

/// Serve a mux-negotiated connection with duplex streams.
///
/// Frame gates cannot apply (see [`serve_streaming_mux`]); the handler
/// receives the connection's [`SessionContext`] for identity-based
/// policy.
///
/// # Errors
/// - `InvalidState` / `OperationFailed(EncryptorUnavailable)`: no handshake
/// - Terminal responder failures (see [`MuxResponder::serve_duplex`])
pub async fn serve_duplex_mux<T, H, Fut>(
	mut transport: T,
	settings: MuxSettings,
	handler: H,
	cancel_budget: Option<u32>,
) -> TransportResult<()>
where
	T: MuxAcceptor,
	H: Fn(StreamBody, ReplySink, SessionContext) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<(), TightBeamError>> + Send,
{
	let rekey = transport.take_rekey()?;
	let snapshot = transport.session_context();
	let (reader, writer) = transport.into_envelope_halves()?;
	let (handle, responder, _reader_task) = drive_mux(reader, writer, MuxRole::Server, settings, cancel_budget, rekey);

	let handler = Arc::new(handler);

	responder
		.serve_duplex(move |body: StreamBody, sink: ReplySink| {
			let session = snapshot.with_live_receipt(handle.session_receipt());
			let handler = Arc::clone(&handler);
			async move {
				match handler(body, sink, session).await {
					Ok(()) => TransitStatus::Ok,
					Err(_) => TransitStatus::Internal,
				}
			}
		})
		.await
}
