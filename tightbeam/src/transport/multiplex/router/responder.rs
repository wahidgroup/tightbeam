//! Responder loop that dispatches peer-initiated streams to their handlers
//! and sends the terminal response of each stream.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::Poll;
use std::collections::HashMap;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::future::{ready, AbortHandle, Abortable, Aborted};
use futures::stream::FuturesUnordered;
use futures::Stream;

use super::body::StreamBody;
use super::flow::cap_as_usize;
use super::link::MuxLink;
use super::reader::InboundEvent;
use super::sink::ReplySink;
use crate::constants::DEFAULT_MUX_CANCEL_BUDGET;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{GoAwayReason, MuxStreamKind, ResponsePackage};
use crate::transport::error::TransportFailure;
use crate::transport::multiplex::StreamRoute;
use crate::transport::{TransportError, TransportResult};
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

/// Event multiplexer for the responder loop, in which handler completions
/// take priority over new inbound work.
enum ResponderEvent {
	/// New work arrived on a peer stream.
	Stream(u32, StreamWork),
	/// The peer cancelled a stream.
	Cancelled(u32),
	/// A handler task finished with its result.
	Finished(u32, TransportResult<()>),
	/// An aborted handler task completed.
	Aborted,
	/// The inbound queue ended.
	Closed,
}

/// Peer stream work handed to the serve dispatcher.
enum StreamWork {
	/// A unary-kind stream, reassembled into its frame.
	Frame(Arc<Frame>),
	/// An incremental body that carries the kind the initiator stamped on the
	/// stream.
	Body(MuxStreamKind, Box<StreamBody>, StreamRoute),
}

/// Kind-routed handler set for one connection's peer streams.
///
/// The initiating call stamps each stream's kind on its Open record
/// ([`MuxStreamKind`]) and the responder routes it to the matching method here.
/// Every default answers [`TransitStatus::Unimplemented`], so a kind outside
/// the service refuses its own stream and the connection keeps serving.
pub trait MuxDispatch {
	/// Answer one unary request with its terminal response.
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = ResponsePackage> + MaybeSend {
		// The default refuses the request, so the frame goes unread.
		let _ = frame;
		ready(ResponsePackage::new(TransitStatus::Unimplemented, None))
	}

	/// Consume a streamed request body and answer with the terminal response.
	///
	/// Consuming chunks replenishes the peer's stream credit, so a slow
	/// handler parks the sender with end-to-end backpressure. `route` carries
	/// the grpc-style dispatch target stamped on the Open.
	fn streaming(&self, body: StreamBody, route: StreamRoute) -> impl Future<Output = ResponsePackage> + MaybeSend {
		// The default refuses the stream, so the body and route go unread.
		let _ = (body, route);
		ready(ResponsePackage::new(TransitStatus::Unimplemented, None))
	}

	/// Consume request chunks while pushing reply chunks, in full duplex on one
	/// stream.
	///
	/// The returned status closes the stream as its `End` trailer. `route`
	/// carries the grpc-style dispatch target stamped on the Open.
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		route: StreamRoute,
	) -> impl Future<Output = TransitStatus> + MaybeSend {
		// The default refuses the stream, so body, reply, and route go unread.
		let _ = (body, reply, route);
		ready(TransitStatus::Unimplemented)
	}
}

impl MuxResponder {
	/// Wait for the next responder event, preferring handler completions over
	/// new inbound work so a finished stream releases its slot before the loop
	/// admits another.
	async fn next_event<Fut>(
		&mut self,
		tasks: &mut FuturesUnordered<Abortable<Fut>>,
		inbound_open: bool,
	) -> ResponderEvent
	where
		Fut: Future<Output = (u32, TransportResult<()>)>,
	{
		let inbound = &mut self.inbound;
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
					Poll::Ready(Some(InboundEvent::StreamOpen(stream_id, kind, body, route))) => {
						return Poll::Ready(ResponderEvent::Stream(stream_id, StreamWork::Body(kind, body, route)));
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
}

/// [`MuxDispatch`] over a unary closure, which serves only unary-kind streams
/// and refuses the rest through the trait defaults.
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

/// [`MuxDispatch`] over a streaming closure, which serves only streaming-kind
/// streams and refuses the rest through the trait defaults.
struct StreamingFn<H>(H);

impl<H, Fut> MuxDispatch for StreamingFn<H>
where
	H: Fn(StreamBody) -> Fut,
	Fut: Future<Output = ResponsePackage> + MaybeSend,
{
	fn streaming(&self, body: StreamBody, _route: StreamRoute) -> impl Future<Output = ResponsePackage> + MaybeSend {
		(self.0)(body)
	}
}

/// [`MuxDispatch`] over a duplex closure, which serves only duplex-kind
/// streams and refuses the rest through the trait defaults.
struct DuplexFn<H>(H);

impl<H, Fut> MuxDispatch for DuplexFn<H>
where
	H: Fn(StreamBody, ReplySink) -> Fut,
	Fut: Future<Output = TransitStatus> + MaybeSend,
{
	fn duplex(
		&self,
		body: StreamBody,
		reply: ReplySink,
		_route: StreamRoute,
	) -> impl Future<Output = TransitStatus> + MaybeSend {
		(self.0)(body, reply)
	}
}

/// Box the future of a dispatch method.
///
/// Erasing the `impl Future` opaque type sidesteps the over-strict `Send`
/// proof that rustc applies to a future that borrows from an `Arc` it lives
/// beside.
///
/// # Sources
///
/// - rust-lang/rust#100013, the over-strict `Send` proof: <https://github.com/rust-lang/rust/issues/100013>
fn boxed<'a, T>(future: impl Future<Output = T> + MaybeSend + 'a) -> MaybeSendFuture<'a, T> {
	Box::pin(future)
}

impl MuxLink {
	/// Run the full lifecycle of one peer stream.
	///
	/// The work goes to the [`MuxDispatch`] method that matches its kind. The
	/// terminal record of the stream, a response or a trailer, then goes out.
	async fn dispatch_stream<D: MuxDispatch>(
		self,
		dispatch: Arc<D>,
		stream_id: u32,
		work: StreamWork,
	) -> TransportResult<()> {
		match work {
			StreamWork::Frame(frame) => {
				let response = boxed(dispatch.unary(frame)).await;
				self.send_response(stream_id, response).await
			}
			StreamWork::Body(MuxStreamKind::Streaming, body, route) => {
				let response = boxed(dispatch.streaming(*body, route)).await;
				self.send_response(stream_id, response).await
			}
			StreamWork::Body(MuxStreamKind::Duplex, body, route) => {
				let reply = ReplySink::new(stream_id, self.clone());
				let status = boxed(dispatch.duplex(*body, reply, route)).await;
				self.send_end_trailer(stream_id, status).await
			}
			// Unreachable by construction, because the reader reassembles
			// unary-kind streams into frames. The arm answers safely instead
			// of asserting.
			StreamWork::Body(MuxStreamKind::Unary, _, _) => {
				self.shared().note_internal_error();
				let refusal = ResponsePackage::new(TransitStatus::Internal, None);
				self.send_response(stream_id, refusal).await
			}
		}
	}
}

/// Serves peer-initiated streams with a caller-supplied handler.
///
/// Handlers for distinct streams run concurrently, and each stream's
/// response is sent from its own task, so neither a slow handler nor
/// a credit-parked response blocks other streams.
///
/// # Caps and cancels
///
/// - Cap exhaustion answers with [`TransitStatus::ResourceExhausted`] on the
///   responder's own queue slot, so a peer flooding past its cap buffers at
///   most one refusal.
/// - A peer cancel aborts the in-flight handler (or its response send) and sends no response.
/// - Cancels of in-flight handlers draw on a per-connection budget
///   (CVE-2023-44487 "Rapid Reset" hardening). A peer that opens streams
///   only to cancel them exhausts the budget and is told to go away.
///
/// # Sources
///
/// - CVE-2023-44487, HTTP/2 Rapid Reset: <https://nvd.nist.gov/vuln/detail/CVE-2023-44487>
pub struct MuxResponder {
	inbound: mpsc::Receiver<InboundEvent>,
	link: MuxLink,
	peer_cap: u32,
	cancel_budget: u32,
}

impl MuxResponder {
	/// Assemble the responder over the inbound event queue, at the
	/// default cancel budget ([`DEFAULT_MUX_CANCEL_BUDGET`]).
	pub(crate) fn new(inbound: mpsc::Receiver<InboundEvent>, link: MuxLink, peer_cap: u32) -> Self {
		Self { inbound, link, peer_cap, cancel_budget: DEFAULT_MUX_CANCEL_BUDGET }
	}

	/// Override the peer cancel budget, which hardens the connection against
	/// CVE-2023-44487 Rapid Reset.
	pub fn set_cancel_budget(&mut self, budget: u32) {
		self.cancel_budget = budget;
	}

	/// Run the responder until the connection ends, routing each peer stream to
	/// the `dispatch` method that matches the kind the initiating call stamped
	/// on it.
	///
	/// - Unary-kind streams arrive reassembled into their frame.
	/// - Streaming and duplex kinds arrive as incremental [`StreamBody`]
	///   chunks, whose consumption replenishes the peer's stream credit.
	///
	/// Flow control, budgets, and the cancel machinery are identical across
	/// kinds, so every interaction is metered and paid.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::PolicyRejection`] -- the peer exhausted the cancel
	///   budget, and a [`GoAwayReason::EnhanceYourCalm`] was sent.
	pub async fn serve_with<D>(self, dispatch: D) -> TransportResult<()>
	where
		D: MuxDispatch + MaybeSend + MaybeSync + 'static,
	{
		let link = self.link.clone();
		let dispatch = Arc::new(dispatch);
		self.dispatch_streams(move |stream_id, work| {
			link.clone().dispatch_stream(Arc::clone(&dispatch), stream_id, work)
		})
		.await
	}

	/// Run the responder until the connection ends, dispatching each unary-kind
	/// frame to `handler`.
	///
	/// This is sugar on [`serve_with`](Self::serve_with) over a unary-only
	/// service, so streaming and duplex streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Errors
	///
	/// - The [`serve_with`](Self::serve_with) set.
	pub async fn serve<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(Arc<Frame>) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = ResponsePackage> + MaybeSend,
	{
		self.serve_with(UnaryFn(handler)).await
	}

	/// Run the responder until the connection ends, dispatching each
	/// streaming-kind stream to `handler` as an incremental [`StreamBody`].
	///
	/// This is sugar on [`serve_with`](Self::serve_with) over a streaming-only
	/// service, so unary and duplex streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Errors
	///
	/// - The [`serve_with`](Self::serve_with) set.
	pub async fn serve_streaming<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(StreamBody) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = ResponsePackage> + MaybeSend,
	{
		self.serve_with(StreamingFn(handler)).await
	}

	/// Run the responder until the connection ends, dispatching each
	/// duplex-kind stream to `handler` as an incremental [`StreamBody`] paired
	/// with a [`ReplySink`] for streaming the reply.
	///
	/// This is sugar on [`serve_with`](Self::serve_with) over a duplex-only
	/// service, so unary and streaming streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Stream lifecycle
	///
	/// Request chunks arrive as the initiator pushes them with
	/// [`RequestSink::push`], so a conversational handler may reply per chunk.
	/// The request body ends at the initiator's close, so a handler that
	/// replies per chunk still consumes the body to its end.
	///
	/// The returned [`TransitStatus`] of the handler then closes the stream as
	/// its `End` trailer.
	///
	/// # Errors
	///
	/// - The [`serve_with`](Self::serve_with) set.
	///
	/// [`RequestSink::push`]: crate::transport::multiplex::RequestSink::push
	pub async fn serve_duplex<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(StreamBody, ReplySink) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = TransitStatus> + MaybeSend,
	{
		self.serve_with(DuplexFn(handler)).await
	}

	/// Shared responder loop, with one dispatcher call per peer stream and one
	/// task per stream outcome.
	///
	/// The future of the dispatcher owns its terminal record, a response or a
	/// trailer. The loop owns concurrency caps, cancels, and the cancel budget.
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

			match self.next_event(&mut tasks, inbound_open).await {
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

					// A request at the concurrency cap is refused without
					// waiting on the queue, so the loop keeps running on a full
					// outbound queue, and `refuse_at_cap` bounds the backlog.
					if in_flight.len() >= cap_as_usize(self.peer_cap) {
						self.link.refuse_at_cap(stream_id)?;
						continue;
					}

					// Handlers ship as tasks so a slow one never parks the
					// loop.
					let (handle, registration) = AbortHandle::new_pair();
					in_flight.insert(stream_id, handle);

					let work = dispatch(stream_id, work);
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

	/// End the connection with a best-effort GoAway after too many cancels of
	/// in-flight handlers, which hardens it against CVE-2023-44487.
	///
	/// `try_send` keeps the courtesy notice from parking the responder on a
	/// full outbound queue, because the connection is torn down either way.
	fn refuse_cancel_abuse(&mut self, last_stream_id: u32) -> TransportError {
		#[cfg(feature = "instrument")]
		self.link.shared().emit_event(events::MUX_CANCEL_BUDGET);

		self.link.goaway_best_effort(last_stream_id, GoAwayReason::EnhanceYourCalm);

		TransportError::OperationFailed(TransportFailure::PolicyRejection)
	}
}

#[cfg(test)]
mod tests {
	use core::future::pending;

	use super::super::outbound::Outbound;
	use super::super::shared::MuxShared;
	use super::super::testing::poll_times;
	use super::*;
	use crate::testing::TestFrame;
	use crate::transport::envelopes::{MuxEnvelope, TransportEnvelope};
	use crate::transport::handshake::negotiation::MuxSettings;
	use crate::transport::multiplex::MuxRole;

	/// Responder over a zero-buffer outbound queue whose only free
	/// capacity is the responder link's own slot, with `peer_cap` peer
	/// streams admitted and every later one refused at the cap.
	struct ResponderFixture {
		responder: MuxResponder,
		inbound: mpsc::Sender<InboundEvent>,
		wire: mpsc::Receiver<Outbound>,
		/// Holds the filler that saturates the queue's buffer.
		_filler: mpsc::Sender<Outbound>,
	}

	fn responder_with_full_queue(peer_cap: u32) -> ResponderFixture {
		let settings = MuxSettings::symmetric(peer_cap);
		let (outbound, wire) = mpsc::channel(0);
		let mut filler = outbound.clone();
		assert!(filler.try_send(Outbound::Close).is_ok());

		let shared = Arc::new(MuxShared::new(MuxRole::Server, &settings));
		let (link, _drained) = MuxLink::new(shared, outbound);
		let (inbound, inbound_receiver) = mpsc::channel(16);
		let responder = MuxResponder::new(inbound_receiver, link, peer_cap);

		ResponderFixture { responder, inbound, wire, _filler: filler }
	}

	impl ResponderFixture {
		/// Deliver one unary request per id in `stream_ids`, as a peer
		/// flooding opens does.
		fn flood(&mut self, stream_ids: &[u32]) {
			let frame = Arc::new(TestFrame::v0(None, None));
			for stream_id in stream_ids {
				self.inbound
					.try_send(InboundEvent::Request(*stream_id, Arc::clone(&frame)))
					.expect("the inbound channel has room for the flood");
			}
		}
	}

	fn is_cap_refusal(command: &Outbound) -> bool {
		matches!(
			command,
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::End(package)))
				if package.status() == TransitStatus::ResourceExhausted
		)
	}

	/// A peer past the cap it was advertised opens streams at zero cost to
	/// itself, so a refusal that took a fresh queue slot per open would let
	/// a stalled writer hold one trailer per open (CWE-770). Refusals share
	/// the responder link's one slot, and the rest are dropped.
	#[test]
	fn test_refusals_at_cap_stop_at_the_link_slot() {
		let mut fixture = responder_with_full_queue(1);
		fixture.flood(&[1, 3, 5, 7, 9, 11]);

		let mut serve = Box::pin(fixture.responder.serve(|_frame| pending::<ResponsePackage>()));
		poll_times(&mut serve, 8);

		assert!(matches!(fixture.wire.try_recv(), Ok(Outbound::Close)));
		assert!(fixture.wire.try_recv().is_ok_and(|command| is_cap_refusal(&command)));
		assert!(fixture.wire.try_recv().is_err());
	}
}
