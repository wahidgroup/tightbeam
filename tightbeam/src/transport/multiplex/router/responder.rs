//! Responder loop: dispatches peer-initiated streams to their
//! handlers and sends each stream's terminal response.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::Poll;
use std::collections::HashMap;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::future::{ready, AbortHandle, Abortable, Aborted, Either};
use futures::stream::FuturesUnordered;
use futures::{SinkExt, Stream};

use super::body::StreamBody;
use super::flow::{cap_as_usize, chunk_records, payload_credits};
use super::outbound::{outbound_handle, Outbound};
use super::reader::InboundEvent;
use super::shared::{BudgetStanding, MuxShared};
use super::sink::{send_data_envelope, ReplySink};
use super::writer::{drain_with_reason, goaway_best_effort};
use crate::constants::DEFAULT_MUX_CANCEL_BUDGET;
use crate::der::Encode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{
	GoAwayReason, MuxDataPackage, MuxEndPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::error::TransportFailure;
use crate::transport::{TransportError, TransportResult};
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

/// Event multiplexer for the responder loop: handler completions take
/// priority over new inbound work.
enum ResponderEvent {
	Stream(u32, StreamWork),
	Cancelled(u32),
	Finished(u32, TransportResult<()>),
	Aborted,
	Closed,
}

/// Peer stream work handed to the serve dispatcher: a reassembled
/// frame (unary kind) or an incremental body carrying the kind the
/// initiator stamped on the stream.
enum StreamWork {
	Frame(Arc<Frame>),
	Body(MuxStreamKind, StreamBody),
}

/// Kind-routed handler set for one connection's peer streams.
///
/// The initiating call stamps each stream's kind on its Open record
/// ([`MuxStreamKind`]) and the responder routes it to the matching
/// method here. Every default answers [`TransitStatus::Unimplemented`],
/// so a kind the service does not serve refuses its stream without
/// touching the connection.
pub trait MuxDispatch {
	/// Answer one unary request with its terminal response.
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let _ = frame;
		ready(ResponsePackage::new(TransitStatus::Unimplemented, None))
	}

	/// Consume a streamed request body and answer with the terminal
	/// response. Consuming chunks replenishes the peer's stream
	/// credit, so a slow handler parks the sender (end-to-end backpressure).
	fn streaming(&self, body: StreamBody) -> impl Future<Output = ResponsePackage> + MaybeSend {
		let _ = body;
		ready(ResponsePackage::new(TransitStatus::Unimplemented, None))
	}

	/// Consume request chunks while pushing reply chunks (full
	/// duplex on one stream). The returned status closes the stream
	/// as its `End` trailer.
	fn duplex(&self, body: StreamBody, reply: ReplySink) -> impl Future<Output = TransitStatus> + MaybeSend {
		let _ = (body, reply);
		ready(TransitStatus::Unimplemented)
	}
}

async fn next_responder_event<Fut>(
	inbound: &mut mpsc::Receiver<InboundEvent>,
	tasks: &mut FuturesUnordered<Abortable<Fut>>,
	inbound_open: bool,
) -> ResponderEvent
where
	Fut: Future<Output = (u32, TransportResult<()>)>,
{
	poll_fn(|cx| {
		if let Poll::Ready(Some(completion)) = Pin::new(&mut *tasks).poll_next(cx) {
			let event = match completion {
				Ok((stream_id, result)) => ResponderEvent::Finished(stream_id, result),
				Err(Aborted) => ResponderEvent::Aborted,
			};

			return Poll::Ready(event);
		}
		if inbound_open {
			match Pin::new(&mut *inbound).poll_next(cx) {
				Poll::Ready(Some(InboundEvent::Request(stream_id, frame))) => {
					return Poll::Ready(ResponderEvent::Stream(stream_id, StreamWork::Frame(frame)));
				}
				Poll::Ready(Some(InboundEvent::StreamOpen(stream_id, kind, body))) => {
					return Poll::Ready(ResponderEvent::Stream(stream_id, StreamWork::Body(kind, body)));
				}
				Poll::Ready(Some(InboundEvent::Cancel(stream_id))) => {
					return Poll::Ready(ResponderEvent::Cancelled(stream_id));
				}
				Poll::Ready(None) => return Poll::Ready(ResponderEvent::Closed),
				Poll::Pending => {}
			}
		}

		Poll::Pending
	})
	.await
}

/// Record a responder answering [`TransitStatus::Internal`] from a
/// local inconsistency, so the peer-observed status has a local
/// investigation trail.
fn note_internal_error(shared: &MuxShared) {
	#[cfg(feature = "instrument")]
	shared.emit_event(events::MUX_INTERNAL_ERROR);
	#[cfg(not(feature = "instrument"))]
	let _ = shared;
}

/// [`MuxDispatch`] over a unary closure: serves only unary-kind
/// streams, refusing the rest through the trait defaults.
struct UnaryFn<H>(H);

impl<H, Fut> MuxDispatch for UnaryFn<H>
where
	H: Fn(Arc<Frame>) -> Fut,
	Fut: Future<Output = ResponsePackage> + MaybeSend,
{
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = ResponsePackage> + MaybeSend {
		(self.0)(frame)
	}
}

/// [`MuxDispatch`] over a streaming closure: serves only
/// streaming-kind streams, refusing the rest through the trait
/// defaults.
struct StreamingFn<H>(H);

impl<H, Fut> MuxDispatch for StreamingFn<H>
where
	H: Fn(StreamBody) -> Fut,
	Fut: Future<Output = ResponsePackage> + MaybeSend,
{
	fn streaming(&self, body: StreamBody) -> impl Future<Output = ResponsePackage> + MaybeSend {
		(self.0)(body)
	}
}

/// [`MuxDispatch`] over a duplex closure: serves only duplex-kind
/// streams, refusing the rest through the trait defaults.
struct DuplexFn<H>(H);

impl<H, Fut> MuxDispatch for DuplexFn<H>
where
	H: Fn(StreamBody, ReplySink) -> Fut,
	Fut: Future<Output = TransitStatus> + MaybeSend,
{
	fn duplex(&self, body: StreamBody, reply: ReplySink) -> impl Future<Output = TransitStatus> + MaybeSend {
		(self.0)(body, reply)
	}
}

/// Box a dispatch method's future: erasing the `impl Future` opaque
/// type sidesteps rustc's over-strict `Send` proof for futures that
/// borrow from an `Arc` they live beside
/// ([rust-lang/rust#100013](https://github.com/rust-lang/rust/issues/100013)).
fn boxed<'a, T>(future: impl Future<Output = T> + MaybeSend + 'a) -> MaybeSendFuture<'a, T> {
	Box::pin(future)
}

/// One peer stream's full lifecycle: route the work to the
/// [`MuxDispatch`] method matching its kind, then send the stream's
/// terminal record (response or trailer).
async fn dispatch_stream<D: MuxDispatch>(
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	dispatch: Arc<D>,
	stream_id: u32,
	work: StreamWork,
) -> TransportResult<()> {
	match work {
		StreamWork::Frame(frame) => {
			let response = boxed(dispatch.unary(frame)).await;
			send_response(&shared, &outbound, stream_id, response).await
		}
		StreamWork::Body(MuxStreamKind::Streaming, body) => {
			let response = boxed(dispatch.streaming(body)).await;
			send_response(&shared, &outbound, stream_id, response).await
		}
		StreamWork::Body(MuxStreamKind::Duplex, body) => {
			let reply = ReplySink::new(stream_id, Arc::clone(&shared), outbound_handle(&outbound));
			let status = boxed(dispatch.duplex(body, reply)).await;
			send_end_trailer(&shared, &outbound, stream_id, status).await
		}
		// Unreachable by construction: the reader reassembles
		// unary-kind streams into frames. Answered safely rather
		// than asserted.
		StreamWork::Body(MuxStreamKind::Unary, _) => {
			note_internal_error(&shared);
			let refusal = ResponsePackage::new(TransitStatus::Internal, None);
			send_response(&shared, &outbound, stream_id, refusal).await
		}
	}
}

/// Task tail shared by the response-bearing dispatchers: await the
/// handler's response, then send it as the stream's terminal record.
fn respond_task<Fut>(
	shared: &Arc<MuxShared>,
	outbound: &mpsc::Sender<Outbound>,
	stream_id: u32,
	response: Fut,
) -> impl Future<Output = TransportResult<()>> + MaybeSend
where
	Fut: Future<Output = ResponsePackage> + MaybeSend,
{
	let shared = Arc::clone(shared);
	let outbound = outbound_handle(outbound);
	async move {
		let response = response.await;
		send_response(&shared, &outbound, stream_id, response).await
	}
}

/// Send a response on a peer-initiated stream, chunking when it
/// exceeds the peer's advertised receive size: full chunks travel as
/// `Data(last = false)` and the final chunk travels inline in the `End`
/// trailer (responder grammar). Every payload-bearing record is gated
/// by the peer's stream credit. A response the session budget cannot
/// carry degrades to a payload-free `ResourceExhausted` refusal.
async fn send_response(
	shared: &MuxShared,
	outbound: &mpsc::Sender<Outbound>,
	stream_id: u32,
	response: ResponsePackage,
) -> TransportResult<()> {
	let mut status = response.status();
	let mut payload = match response.message() {
		Some(frame) => frame.as_ref().to_der()?,
		None => Vec::new(),
	};

	let credits = payload_credits(payload.len(), shared.send_chunk_size, shared.credit_unit);
	match shared.admit_debit(credits, true).await {
		Ok(BudgetStanding::Healthy) => {}
		Ok(BudgetStanding::Exhausting) => {
			drain_with_reason(shared, outbound, GoAwayReason::BudgetExhausted).await?;
		}
		// Even the drain reserve cannot carry the payload: refuse
		// the stream for free instead of tearing the connection
		Err(_) => {
			status = TransitStatus::ResourceExhausted;
			payload = Vec::new();
		}
	}

	if payload.is_empty() {
		return send_end_trailer(shared, outbound, stream_id, status).await;
	}
	let mut outbound = outbound_handle(outbound);

	let chunk_size = shared.send_chunk_size;
	let total = chunk_records(payload.len(), chunk_size);
	shared.register_send_stream(stream_id, total);

	let mut sent: u64 = 0;
	for chunk in payload.chunks(chunk_size) {
		sent += 1;

		let envelope = if sent == total {
			TransportEnvelope::from(MuxEndPackage::new(stream_id, status, chunk)?)
		} else {
			TransportEnvelope::from(MuxDataPackage::new(stream_id, false, chunk)?)
		};
		match send_data_envelope(shared, &mut outbound, stream_id, envelope).await {
			Ok(()) => {}
			// Ledger removed mid-send: the peer cancelled the stream
			// and the receiver will discard what already went out
			Err(TransportError::OperationFailed(TransportFailure::Cancelled)) => return Ok(()),
			Err(err) => {
				shared.finish_send_stream(stream_id);
				return Err(err);
			}
		}
	}

	shared.finish_send_stream(stream_id);

	Ok(())
}

/// Terminal `End` trailer closing a peer-initiated stream. Payload-free,
/// so it travels outside stream credit like every empty `End`, and it
/// releases the stream's sender ledger.
async fn send_end_trailer(
	shared: &MuxShared,
	outbound: &mpsc::Sender<Outbound>,
	stream_id: u32,
	status: TransitStatus,
) -> TransportResult<()> {
	let package = MuxEndPackage::new(stream_id, status, Vec::new())?;
	let mut outbound = outbound_handle(outbound);
	let sent = outbound.send(Outbound::Envelope(package.into())).await;
	shared.finish_send_stream(stream_id);

	sent.map_err(|_| TransportError::ConnectionClosed)
}

/// Serves peer-initiated streams with a caller-supplied handler.
///
/// Handlers for distinct streams run concurrently, and each stream's
/// response is sent from its own task, so neither a slow handler nor
/// a credit-parked response blocks other streams. Cap exhaustion answers
/// with [`TransitStatus::ResourceExhausted`]. A peer cancel aborts the
/// in-flight handler (or its response send) and sends no response.
///
/// Cancels of in-flight handlers draw on a per-connection budget
/// (CVE-2023-44487 "Rapid Reset" hardening): a peer that opens streams
/// only to cancel them exhausts the budget and is told to go away.
pub struct MuxResponder {
	inbound: mpsc::Receiver<InboundEvent>,
	outbound: mpsc::Sender<Outbound>,
	shared: Arc<MuxShared>,
	peer_cap: u32,
	cancel_budget: u32,
}

impl MuxResponder {
	/// Assemble the responder over the inbound event queue, at the
	/// default cancel budget ([`DEFAULT_MUX_CANCEL_BUDGET`]).
	pub(super) fn new(
		inbound: mpsc::Receiver<InboundEvent>,
		outbound: mpsc::Sender<Outbound>,
		shared: Arc<MuxShared>,
		peer_cap: u32,
	) -> Self {
		Self { inbound, outbound, shared, peer_cap, cancel_budget: DEFAULT_MUX_CANCEL_BUDGET }
	}

	/// Override the peer cancel budget (CVE-2023-44487 hardening).
	pub(super) fn set_cancel_budget(&mut self, budget: u32) {
		self.cancel_budget = budget;
	}

	/// Run the responder until the connection ends, routing each peer
	/// stream to the `dispatch` method matching the kind the
	/// initiating call stamped on it.
	///
	/// Unary-kind streams arrive reassembled into their frame. Streaming and
	/// duplex kinds arrive as incremental [`StreamBody`] chunks whose
	/// consumption replenishes the peer's stream credit (end-to-end
	/// backpressure). Flow control, budgets, and the cancel machinery are
	/// identical across kinds: every interaction is metered and paid.
	///
	/// # Errors
	/// - `ConnectionClosed`: writer driver gone
	/// - `OperationFailed(PolicyRejection)`: peer exhausted the cancel
	///   budget. A [`GoAwayReason::EnhanceYourCalm`] was sent
	pub async fn serve_with<D>(self, dispatch: D) -> TransportResult<()>
	where
		D: MuxDispatch + MaybeSend + MaybeSync + 'static,
	{
		let shared = Arc::clone(&self.shared);
		let outbound = outbound_handle(&self.outbound);
		let dispatch = Arc::new(dispatch);
		self.dispatch_streams(move |stream_id, work| {
			dispatch_stream(
				Arc::clone(&shared),
				outbound_handle(&outbound),
				Arc::clone(&dispatch),
				stream_id,
				work,
			)
		})
		.await
	}

	/// Run the responder until the connection ends, dispatching each
	/// unary-kind frame to `handler`. Sugar on [`serve_with`](Self::serve_with)
	/// over a unary-only service: streaming and duplex streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Errors
	/// [`serve_with`](Self::serve_with)'s set.
	pub async fn serve<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(Arc<Frame>) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = ResponsePackage> + MaybeSend,
	{
		self.serve_with(UnaryFn(handler)).await
	}

	/// Run the responder until the connection ends, dispatching each
	/// streaming-kind stream to `handler` as an incremental
	/// [`StreamBody`]. Sugar for [`serve_with`](Self::serve_with)
	/// over a streaming-only service: unary and duplex streams
	/// answer [`TransitStatus::Unimplemented`].
	///
	/// # Errors
	/// [`serve_with`](Self::serve_with)'s set.
	pub async fn serve_streaming<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(StreamBody) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = ResponsePackage> + MaybeSend,
	{
		self.serve_with(StreamingFn(handler)).await
	}

	/// Run the responder until the connection ends, dispatching each
	/// duplex-kind stream to `handler` as an incremental [`StreamBody`]
	/// paired with a [`ReplySink`] for streaming the reply. The handler's
	/// returned [`TransitStatus`] closes the stream as its `End` trailer.
	///
	/// Sugar for [`serve_with`](Self::serve_with) over a duplex-only service:
	/// unary and streaming streams answers [`TransitStatus::Unimplemented`].
	///
	/// Request chunks arrive as the initiator pushes them (see
	/// [`crate::transport::multiplex::RequestSink::push`]), so a conversational handler may reply
	/// per chunk. The request body ends at the initiator's close, so
	/// a handler that replies per chunk still consumes the body to
	/// its end before returning the trailer status.
	///
	/// # Errors
	/// - [`serve_with`](Self::serve_with)'s set.
	pub async fn serve_duplex<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(StreamBody, ReplySink) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = TransitStatus> + MaybeSend,
	{
		self.serve_with(DuplexFn(handler)).await
	}

	/// Shared responder loop: one dispatcher call per peer stream,
	/// one task per stream outcome. The dispatcher's future owns its
	/// terminal record (response or trailer); the loop owns
	/// concurrency caps, cancels, and the cancel budget.
	async fn dispatch_streams<D, Fut>(mut self, dispatch: D) -> TransportResult<()>
	where
		D: Fn(u32, StreamWork) -> Fut,
		Fut: Future<Output = TransportResult<()>> + MaybeSend,
	{
		let mut in_flight: HashMap<u32, AbortHandle> = HashMap::new();
		let mut tasks = FuturesUnordered::new();
		let mut inbound_open = true;
		let mut last_stream_id = 0;

		loop {
			if !inbound_open && tasks.is_empty() {
				return Ok(());
			}

			match next_responder_event(&mut self.inbound, &mut tasks, inbound_open).await {
				ResponderEvent::Closed => inbound_open = false,
				ResponderEvent::Aborted => {}
				ResponderEvent::Cancelled(stream_id) => {
					if let Some(handle) = in_flight.remove(&stream_id) {
						handle.abort();

						if self.cancel_budget == 0 {
							return Err(self.refuse_cancel_abuse(last_stream_id));
						}

						self.cancel_budget -= 1;
					}
				}
				ResponderEvent::Stream(stream_id, work) => {
					last_stream_id = stream_id;

					// A request at the concurrency cap resolves to an
					// immediate refusal. Both outcomes ship as tasks so
					// the event loop never parks on a full outbound queue.
					let at_cap = in_flight.len() >= cap_as_usize(self.peer_cap);
					let work = if at_cap {
						let refusal = ready(ResponsePackage::new(TransitStatus::ResourceExhausted, None));
						Either::Right(respond_task(&self.shared, &self.outbound, stream_id, refusal))
					} else {
						Either::Left(dispatch(stream_id, work))
					};

					let (handle, registration) = AbortHandle::new_pair();
					if !at_cap {
						in_flight.insert(stream_id, handle);
					}

					let task = async move { (stream_id, work.await) };
					tasks.push(Abortable::new(task, registration));
				}
				ResponderEvent::Finished(stream_id, result) => {
					in_flight.remove(&stream_id);
					result?;
				}
			}
		}
	}

	/// CVE-2023-44487 hardening: too many cancels of in-flight
	/// handlers ends the connection with a best-effort GoAway.
	/// `try_send` keeps the courtesy notice from parking the
	/// responder on a full outbound queue: the connection is being
	/// torn down either way.
	fn refuse_cancel_abuse(&mut self, last_stream_id: u32) -> TransportError {
		#[cfg(feature = "instrument")]
		self.shared.emit_event(events::MUX_CANCEL_BUDGET);

		goaway_best_effort(&self.shared, &self.outbound, last_stream_id, GoAwayReason::EnhanceYourCalm);

		TransportError::OperationFailed(TransportFailure::PolicyRejection)
	}
}
