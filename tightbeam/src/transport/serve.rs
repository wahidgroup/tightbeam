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
use crate::transport::multiplex::{MuxAcceptor, MuxHandle, MuxRekeyContext, MuxResponder, MuxRole, MuxTransport};
use crate::transport::TransportResult;
use crate::{Frame, TightBeamError};

/// Assemble the mux plane over split halves and spawn both drivers.
///
/// Driver failures resolve pending streams through the shared state
/// (`fail_all_pending`), so the tasks themselves are fire-and-forget. The
/// returned handle is the reader driver's: it finishes when the connection
/// dies, so holders use it as the connection's liveness witness. The writer
/// driver ends on its own when the connection does.
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

	let (handle, reader_driver, writer_driver, responder) = mux.into_parts();
	let reader_task = rt::spawn(async move {
		let _ = reader_driver.drive().await;
	});

	rt::spawn(async move {
		let _ = writer_driver.drive().await;
	});

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
