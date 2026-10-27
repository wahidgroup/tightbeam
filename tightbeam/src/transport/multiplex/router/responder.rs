//! The responder loop, which dispatches peer-initiated streams to their
//! handlers and sends the terminal record of each stream.

use core::future::{poll_fn, Future};
use core::pin::Pin;
use core::task::Poll;
use std::collections::HashMap;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::future::{AbortHandle, Abortable, Aborted};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, Stream};

use super::body::StreamBody;
use super::flow::cap_as_usize;
use super::link::MuxLink;
use super::reader::InboundEvent;
use super::sink::ReplySink;
use crate::constants::DEFAULT_MUX_CANCEL_BUDGET;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{GoAwayReason, MuxStreamKind, ResponsePackage};
use crate::transport::error::TransportFailure;
use crate::transport::multiplex::{MuxDispatch, StreamRoute};
use crate::transport::{TransportError, TransportResult};
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

/// One event of the responder loop, from [`MuxResponder::next_event`].
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

/// The work of a peer stream that the responder hands to the serve dispatcher.
enum StreamWork {
	/// A unary-kind stream, which the reader reassembles into its frame.
	Frame(Arc<Frame>),
	/// An incremental body, with the kind and the route that the initiator
	/// stamped on the stream.
	Body(MuxStreamKind, Box<StreamBody>, StreamRoute),
}

impl MuxResponder {
	/// Waits for the next responder event. Handler completions come before new
	/// inbound work, so a finished stream releases its slot before the loop
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
	fn unary(&self, frame: Arc<Frame>) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		(self.0)(frame).map(Ok)
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
	fn streaming(
		&self,
		body: StreamBody,
		_route: StreamRoute,
	) -> impl Future<Output = TransportResult<ResponsePackage>> + MaybeSend {
		(self.0)(body).map(Ok)
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
	) -> impl Future<Output = TransportResult<TransitStatus>> + MaybeSend {
		(self.0)(body, reply).map(Ok)
	}
}

/// Boxes the future of a dispatch method.
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
	/// Runs the full lifecycle of one peer stream.
	///
	/// The work goes to the [`MuxDispatch`] method of its kind, a route step
	/// the connection's trail records. Then the stream's terminal record, a
	/// response or a trailer, goes out.
	///
	/// - A failed method answers its own stream through
	///   [`Self::refuse_failed`], so the failure ends that stream alone. A
	///   refused stream kind is one such failure.
	/// - A method's `Ok` answer goes out as it is.
	///
	/// # Errors
	///
	/// - The errors of [`send_response`](Self::send_response) and
	///   [`send_end_trailer`](Self::send_end_trailer).
	/// - The errors of [`refuse_failed`](Self::refuse_failed).
	/// - The injected error, when the runtime fault model injects a fault at the route step.
	async fn dispatch_stream<D: MuxDispatch>(
		self,
		dispatch: Arc<D>,
		stream_id: u32,
		work: StreamWork,
	) -> TransportResult<()> {
		self.shared().note_route_step()?;

		match work {
			StreamWork::Frame(frame) => {
				let response = match boxed(dispatch.unary(frame)).await {
					Ok(response) => response,
					Err(failure) => ResponsePackage::new(self.refuse_failed(&failure)?, None),
				};
				self.send_response(stream_id, response).await
			}
			StreamWork::Body(MuxStreamKind::Streaming, body, route) => {
				let response = match boxed(dispatch.streaming(*body, route)).await {
					Ok(response) => response,
					Err(failure) => ResponsePackage::new(self.refuse_failed(&failure)?, None),
				};
				self.send_response(stream_id, response).await
			}
			StreamWork::Body(MuxStreamKind::Duplex, body, route) => {
				let reply = ReplySink::new(stream_id, self.clone());
				let status = match boxed(dispatch.duplex(*body, reply, route)).await {
					Ok(status) => status,
					Err(failure) => self.refuse_failed(&failure)?,
				};
				self.send_end_trailer(stream_id, status).await
			}
			// The reader reassembles unary-kind streams into frames, so this
			// arm is unreachable. It records the fault and answers `Internal`
			// in place of an assertion.
			StreamWork::Body(MuxStreamKind::Unary, _, _) => {
				self.shared().note_internal_error()?;
				let refusal = ResponsePackage::new(TransitStatus::Internal, None);
				self.send_response(stream_id, refusal).await
			}
		}
	}

	/// The status a stream reads when its dispatch method failed with
	/// `failure`, under the mapping of [`MuxDispatch`], and the record of the
	/// failure on the connection's trail.
	///
	/// - [`TransportError::NotServed`], the dispatch's refusal of the stream
	///   kind, reads `Unimplemented` and records `MUX_STREAM_REFUSED`.
	/// - Any other failure records a fault of this endpoint, so the status the
	///   peer reads has a local trail.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	fn refuse_failed(&self, failure: &TransportError) -> TransportResult<TransitStatus> {
		let status = failure.failure_status();
		if let TransportError::NotServed = failure {
			self.shared().note_stream_refused(status)?;
		} else {
			self.shared().note_internal_error()?;
		}

		Ok(status)
	}
}

/// Serves peer-initiated streams with a caller-supplied handler.
///
/// Handlers for distinct streams run concurrently, and each stream sends
/// its response from its own task, so a slow handler or a credit-parked
/// response holds up its own stream alone.
///
/// # Caps and cancels
///
/// - Cap exhaustion answers [`TransitStatus::ResourceExhausted`] on the
///   responder's own queue slot, so a peer that floods past its cap buffers
///   at most one refusal. The connection's trail records each refusal as
///   [`MUX_STREAM_REFUSED`].
/// - A peer cancel aborts the in-flight handler, or its response send, and
///   records [`MUX_STREAM_CANCELLED`] on the trail. The cancel is the
///   stream's last record on the wire.
/// - Cancels of in-flight handlers draw on a per-connection budget against
///   CVE-2023-44487 "Rapid Reset". A peer that opens streams only to cancel
///   them exhausts the budget and draws a best-effort GoAway.
///
/// # Sources
///
/// - CVE-2023-44487, HTTP/2 Rapid Reset: <https://nvd.nist.gov/vuln/detail/CVE-2023-44487>
///
/// [`MUX_STREAM_CANCELLED`]: crate::instrumentation::events::MUX_STREAM_CANCELLED
/// [`MUX_STREAM_REFUSED`]: crate::instrumentation::events::MUX_STREAM_REFUSED
pub struct MuxResponder {
	inbound: mpsc::Receiver<InboundEvent>,
	link: MuxLink,
	peer_cap: u32,
	cancel_budget: u32,
}

impl MuxResponder {
	/// Assembles the responder over the inbound event queue, at the
	/// default cancel budget ([`DEFAULT_MUX_CANCEL_BUDGET`]).
	pub(crate) fn new(inbound: mpsc::Receiver<InboundEvent>, link: MuxLink, peer_cap: u32) -> Self {
		Self { inbound, link, peer_cap, cancel_budget: DEFAULT_MUX_CANCEL_BUDGET }
	}

	/// Overrides the peer cancel budget, which hardens the connection against
	/// CVE-2023-44487 Rapid Reset.
	pub fn set_cancel_budget(&mut self, budget: u32) {
		self.cancel_budget = budget;
	}

	/// Runs the responder until the connection ends, and routes each peer
	/// stream to the `dispatch` method of the kind the initiator stamped on it.
	///
	/// - Unary-kind streams arrive reassembled into their frame.
	/// - Streaming and duplex kinds arrive as incremental [`StreamBody`]
	///   chunks, and their consumption replenishes the peer's stream credit.
	///
	/// Flow control, budgets, and cancels are the same for every kind, so the
	/// budgets meter every interaction.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::PolicyRejection`] -- the peer exhausted the cancel
	///   budget, and the responder tried to queue a GoAway with
	///   [`GoAwayReason::EnhanceYourCalm`].
	/// - The encode failure of a response or a trailer that does not serialize.
	/// - The injected error, when the runtime fault model injects a fault at the route step of a stream.
	/// - The injected error, when the runtime fault model injects a fault at the record of a failed stream.
	/// - The injected error, when the runtime fault model injects a fault at the record of a refused stream.
	/// - The injected error, when the runtime fault model injects a fault at the record of a peer cancel.
	/// - The injected error, when the runtime fault model injects a fault at
	///   the cancel-budget event or at the event of the GoAway, in place of the
	///   `PolicyRejection`.
	///
	/// # Examples
	///
	/// ```no_run
	/// use std::sync::Arc;
	///
	/// use tightbeam::policy::TransitStatus;
	/// use tightbeam::transport::multiplex::{MuxDispatch, MuxResponder};
	/// use tightbeam::transport::{ResponsePackage, TransportResult};
	/// use tightbeam::Frame;
	///
	/// /// Echoes each unary frame.
	/// struct Echo;
	///
	/// impl MuxDispatch for Echo {
	///     async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
	///         Ok(ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame))))
	///     }
	/// }
	///
	/// /// Serve the peer streams of one connection until it ends.
	/// async fn serve(responder: MuxResponder) -> TransportResult<()> {
	///     responder.serve_with(Echo).await
	/// }
	/// ```
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

	/// Runs the responder until the connection ends, and dispatches each
	/// unary-kind frame to `handler`.
	///
	/// This is sugar on [`serve_with`](Self::serve_with) over a unary-only
	/// service, so streaming and duplex streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Errors
	///
	/// - The errors of [`serve_with`](Self::serve_with).
	pub async fn serve<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(Arc<Frame>) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = ResponsePackage> + MaybeSend,
	{
		self.serve_with(UnaryFn(handler)).await
	}

	/// Runs the responder until the connection ends, and dispatches each
	/// streaming-kind stream to `handler` as an incremental [`StreamBody`].
	///
	/// This is sugar on [`serve_with`](Self::serve_with) over a streaming-only
	/// service, so unary and duplex streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Errors
	///
	/// - The errors of [`serve_with`](Self::serve_with).
	pub async fn serve_streaming<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(StreamBody) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = ResponsePackage> + MaybeSend,
	{
		self.serve_with(StreamingFn(handler)).await
	}

	/// Runs the responder until the connection ends, and dispatches each
	/// duplex-kind stream to `handler` as an incremental [`StreamBody`], paired
	/// with a [`ReplySink`] that streams the reply.
	///
	/// This is sugar on [`serve_with`](Self::serve_with) over a duplex-only
	/// service, so unary and streaming streams answer
	/// [`TransitStatus::Unimplemented`].
	///
	/// # Stream lifecycle
	///
	/// Request chunks arrive as the initiator pushes them with
	/// [`RequestSink::push`], so a conversational handler may reply per chunk.
	/// The body ends at the initiator's close, so even such a handler consumes
	/// the body to its end. The [`TransitStatus`] the handler returns closes
	/// the stream as its `End` trailer.
	///
	/// # Errors
	///
	/// - The errors of [`serve_with`](Self::serve_with).
	///
	/// [`RequestSink::push`]: crate::transport::multiplex::RequestSink::push
	pub async fn serve_duplex<H, Fut>(self, handler: H) -> TransportResult<()>
	where
		H: Fn(StreamBody, ReplySink) -> Fut + MaybeSend + MaybeSync + 'static,
		Fut: Future<Output = TransitStatus> + MaybeSend,
	{
		self.serve_with(DuplexFn(handler)).await
	}

	/// The shared responder loop, with one dispatcher call per peer stream and
	/// one task per stream outcome.
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
						// The abort ends the handler span short of its exit,
						// so the trail records the cancel in its place.
						#[cfg(feature = "instrument")]
						self.link.shared().emit_event(events::MUX_STREAM_CANCELLED)?;

						let Some(remaining) = self.cancel_budget.checked_sub(1) else {
							return Err(self.refuse_cancel_abuse(last_stream_id));
						};

						self.cancel_budget = remaining;
					}
				}
				ResponderEvent::Stream(stream_id, work) => {
					last_stream_id = stream_id;

					// The refusal at the concurrency cap is synchronous, so a
					// full outbound queue leaves the loop free to run, and
					// `refuse_at_cap` bounds the backlog.
					if in_flight.len() >= cap_as_usize(self.peer_cap) {
						self.link.shared().note_stream_refused(TransitStatus::ResourceExhausted)?;
						self.link.refuse_at_cap(stream_id)?;
						continue;
					}

					// Each handler runs as its own task, so a slow one leaves
					// the loop free.
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

	/// Ends the connection with a best-effort GoAway once the peer's cancels
	/// exhaust the cancel budget (CVE-2023-44487).
	///
	/// The notice goes out through `try_send`, so a full outbound queue drops
	/// it and the responder moves on, since the connection ends either way. A
	/// fault the trace injects at either event is the error that ends it.
	fn refuse_cancel_abuse(&mut self, last_stream_id: u32) -> TransportError {
		#[cfg(feature = "instrument")]
		if let Err(fault) = self.link.shared().emit_event(events::MUX_CANCEL_BUDGET) {
			return fault;
		}

		if let Err(fault) = self.link.goaway_best_effort(last_stream_id, GoAwayReason::EnhanceYourCalm) {
			return fault;
		}

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

	/// A responder over a zero-buffer outbound queue whose one free slot is
	/// the responder link's own, which admits `peer_cap` peer streams and
	/// refuses every later one at the cap.
	struct ResponderFixture {
		responder: MuxResponder,
		inbound: mpsc::Sender<InboundEvent>,
		wire: mpsc::Receiver<Outbound>,
		/// The filler sender, whose queued message saturates the buffer.
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
		/// Delivers one unary request per ID in `stream_ids`, as a peer that
		/// floods opens does.
		fn flood(&mut self, stream_ids: &[u32]) {
			let frame = Arc::new(TestFrame::v0(None, None));
			for stream_id in stream_ids {
				self.inbound
					.try_send(InboundEvent::Request(*stream_id, Arc::clone(&frame)))
					.expect("the inbound channel has room for the flood");
			}
		}
	}

	/// Tests of a fault that the trace injects at the gate of a stream, against
	/// the gated service of a connection.
	#[cfg(all(pooled_mux, feature = "testing-fault", feature = "instrument"))]
	mod gate_fault {
		use futures::future::ready;

		use super::*;
		use crate::policy::{AcceptAllGate, SessionContext};
		use crate::testing::FaultModel;
		use crate::trace::TraceCollector;
		use crate::transport::multiplex::service::GatedService;
		use crate::transport::multiplex::{MuxHandle, MuxService};
		use crate::TightBeamError;

		/// The peer streams of [`gate_faulting_responder`], in the order the
		/// gate reads them.
		const STREAMS: [u32; 3] = [1, 3, 5];

		/// A server-role responder whose trace injects
		/// [`TransportError::InvalidAddress`] at every second gate acceptance,
		/// the gated echo service of its connection, and the receiver of its
		/// outbound queue. A unary request on each of [`STREAMS`] waits on the
		/// inbound queue, which then closes.
		fn gate_faulting_responder() -> (MuxResponder, GatedService<impl MuxService>, mpsc::Receiver<Outbound>) {
			// The deterministic strategy injects at 5,000 bps on the second
			// record of the event, then the fourth.
			let injected = || TransportError::InvalidAddress;
			let model = FaultModel::default().with_event_fault(events::GATE_ACCEPT, injected, crate::bps!(5000));
			let mut shared = MuxShared::new(MuxRole::Server, &MuxSettings::symmetric(4));
			shared.trace = Some(TraceCollector::new().with_fault_model(model));

			let (outbound, wire) = mpsc::channel(4);
			let (link, _drained) = MuxLink::new(Arc::new(shared), outbound);
			let (mut inbound, inbound_receiver) = mpsc::channel(STREAMS.len());
			let frame = Arc::new(TestFrame::v0(None, None));
			for stream_id in STREAMS {
				let request = InboundEvent::Request(stream_id, Arc::clone(&frame));
				inbound
					.try_send(request)
					.expect("the inbound channel has room for every request");
			}

			let echo = |frame: Frame, _session: SessionContext| ready(Ok::<_, TightBeamError>(Some(frame)));
			let handle = MuxHandle::new(link.clone());
			let service = GatedService::new(echo, Box::new(AcceptAllGate), SessionContext::default(), handle);
			(MuxResponder::new(inbound_receiver, link, 4), service, wire)
		}

		/// The status that answers each stream on `wire`, by stream ID.
		fn answered(wire: &mut mpsc::Receiver<Outbound>) -> Vec<(u32, TransitStatus)> {
			let mut answered = Vec::new();
			while let Ok(command) = wire.try_recv() {
				if let Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::End(package))) = command {
					answered.push((package.stream_id(), package.status()));
				}
			}

			answered
		}

		/// A fault the trace injects at the gate verdict of one stream refuses
		/// that stream alone: it reads `Internal`, and the responder serves the
		/// stream after it.
		#[tokio::test]
		async fn a_fault_at_the_gate_verdict_refuses_its_stream_alone() -> TransportResult<()> {
			let (responder, service, mut wire) = gate_faulting_responder();
			let expected = [(1, TransitStatus::Ok), (3, TransitStatus::Internal), (5, TransitStatus::Ok)];

			responder.serve_with(service).await?;
			assert_eq!(answered(&mut wire), expected);
			Ok(())
		}

		/// A fault the trace injects at the entry of a handler stops the
		/// handler before it runs, so its stream reads `Internal` and the trail
		/// records no failed handler.
		#[tokio::test]
		async fn a_fault_at_the_entry_of_a_handler_files_no_handler_failure() -> TransportResult<()> {
			let injected = || TransportError::InvalidAddress;
			let model = FaultModel::default().with_event_fault(events::HANDLER_ENTER, injected, crate::bps!(10000));
			let trace = crate::testing::fixtures::TestTrace::with_detail(true).with_fault_model(model);
			let mut shared = MuxShared::new(MuxRole::Server, &MuxSettings::symmetric(4));
			shared.trace = Some(trace.share());
			let (outbound, mut wire) = mpsc::channel(4);
			let (link, _drained) = MuxLink::new(Arc::new(shared), outbound);
			let (mut inbound, inbound_receiver) = mpsc::channel(1);
			let request = InboundEvent::Request(1, Arc::new(TestFrame::v0(None, None)));
			assert!(inbound.try_send(request).is_ok());
			drop(inbound);

			let echo = |frame: Frame, _session: SessionContext| ready(Ok::<_, TightBeamError>(Some(frame)));
			let service = GatedService::new(
				echo,
				Box::new(AcceptAllGate),
				SessionContext::default(),
				MuxHandle::new(link.clone()),
			);
			MuxResponder::new(inbound_receiver, link, 4).serve_with(service).await?;

			assert_eq!(answered(&mut wire), [(1, TransitStatus::Internal)]);
			assert_eq!(trace.recorded(events::HANDLER_FAILED), 0);
			Ok(())
		}
	}

	/// Tests of the internal events that a responder records into the trail of
	/// its connection.
	#[cfg(feature = "instrument")]
	mod internal_detail {
		use futures::future::ready;

		use super::*;
		use crate::testing::fixtures::TestTrace;
		use crate::trace::TraceCollector;
		use crate::urn::Urn;

		#[cfg(pooled_mux)]
		use super::super::super::testing::body_fixture;
		#[cfg(pooled_mux)]
		use crate::policy::{AcceptAllGate, SessionContext};
		#[cfg(pooled_mux)]
		use crate::transport::multiplex::service::GatedService;
		#[cfg(pooled_mux)]
		use crate::transport::multiplex::{MuxDispatch, MuxHandle, MuxService};
		#[cfg(pooled_mux)]
		use crate::TightBeamError;

		/// A server-role responder whose connection records into `trace`, the
		/// link it answers on, and the receiver of its outbound queue. The
		/// events of `inbound` wait on the inbound queue, which then closes.
		pub(super) fn responder_with(
			trace: &TraceCollector,
			inbound: Vec<InboundEvent>,
		) -> (MuxResponder, MuxLink, mpsc::Receiver<Outbound>) {
			let mut shared = MuxShared::new(MuxRole::Server, &MuxSettings::symmetric(4));
			shared.trace = Some(trace.share());

			let (outbound, wire) = mpsc::channel(4);
			let (link, _drained) = MuxLink::new(Arc::new(shared), outbound);
			let (mut sender, inbound_receiver) = mpsc::channel(inbound.len());
			for event in inbound {
				sender.try_send(event).expect("the inbound channel has room for every event");
			}

			(MuxResponder::new(inbound_receiver, link.clone(), 4), link, wire)
		}

		/// Calls [`responder_with`] with one unary request on stream 1.
		pub(super) fn responder_with_one_request(
			trace: &TraceCollector,
		) -> (MuxResponder, MuxLink, mpsc::Receiver<Outbound>) {
			let request = InboundEvent::Request(1, Arc::new(TestFrame::v0(None, None)));
			responder_with(trace, vec![request])
		}

		/// The route steps that one served unary request records under the
		/// detail flag `detail`.
		async fn route_trail(detail: bool) -> TransportResult<Vec<Urn<'static>>> {
			let trace = TestTrace::with_detail(detail);
			let (responder, _link, _wire) = responder_with_one_request(&trace);
			let echo = |frame: Arc<Frame>| ready(ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame))));
			responder.serve(echo).await?;

			Ok(TestTrace::trail(&trace, &[events::ROUTE_STEP]))
		}

		/// A responder records the route step of a peer stream when, and only
		/// when, the trace config sets the detail flag.
		#[tokio::test]
		async fn a_peer_stream_records_its_route_step_under_the_detail_flag_alone() -> TransportResult<()> {
			let trails = [route_trail(true).await?, route_trail(false).await?];
			assert_eq!(trails, [vec![events::ROUTE_STEP], vec![]]);
			Ok(())
		}

		/// The steps of one gated request, with its verdict, in the order the
		/// request takes them.
		#[cfg(pooled_mux)]
		const GATED_STEPS: [Urn<'static>; 5] = [
			events::ROUTE_STEP,
			events::POLICY_EVAL,
			events::GATE_ACCEPT,
			events::HANDLER_ENTER,
			events::HANDLER_EXIT,
		];

		/// The span of one handler that runs to its end.
		#[cfg(pooled_mux)]
		const HANDLER_SPAN: [Urn<'static>; 2] = [events::HANDLER_ENTER, events::HANDLER_EXIT];

		/// Wraps `service` in an accept-all gate on the connection that `link`
		/// serves.
		#[cfg(pooled_mux)]
		pub(super) fn gated(service: impl MuxService, link: MuxLink) -> GatedService<impl MuxService> {
			let gate = Box::new(AcceptAllGate);
			GatedService::new(service, gate, SessionContext::default(), MuxHandle::new(link))
		}

		/// An echo service, which serves unary calls and answers each
		/// streaming kind with the refusal of its default method.
		#[cfg(pooled_mux)]
		pub(super) fn echo() -> impl MuxService {
			|frame: Frame, _session: SessionContext| ready(Ok::<_, TightBeamError>(Some(frame)))
		}

		/// The [`GATED_STEPS`] that one gated unary request records, in order,
		/// under the detail flag `detail`.
		#[cfg(pooled_mux)]
		async fn gated_trail(detail: bool) -> TransportResult<Vec<Urn<'static>>> {
			let trace = TestTrace::with_detail(detail);
			let (responder, link, _wire) = responder_with_one_request(&trace);
			responder.serve_with(gated(echo(), link)).await?;

			Ok(TestTrace::trail(&trace, &GATED_STEPS))
		}

		/// Under the detail flag, a gated request records its route step,
		/// policy step, verdict, and handler span, in that order. With the flag
		/// clear, it records its verdict alone.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_gated_request_records_its_steps_in_order_under_the_detail_flag_alone() -> TransportResult<()> {
			let trails = [gated_trail(true).await?, gated_trail(false).await?];
			assert_eq!(trails, [GATED_STEPS.to_vec(), vec![events::GATE_ACCEPT]]);
			Ok(())
		}

		/// A gated streaming call runs its handler inside the span of the
		/// handler. The echo service refuses the streaming kind, and the
		/// refusal runs inside the span too.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_streaming_call_records_its_handler_span() -> TransportResult<()> {
			let trace = TestTrace::with_detail(true);
			let (_responder, link, _wire) = responder_with(&trace, Vec::new());
			let (body, _forwarder, _notes) = body_fixture(1, 4);
			let refused = MuxDispatch::streaming(&gated(echo(), link), body, StreamRoute::local()).await;

			assert!(matches!(refused, Err(TransportError::NotServed)));
			assert_eq!(TestTrace::trail(&trace, &HANDLER_SPAN), HANDLER_SPAN);
			Ok(())
		}

		/// A gated duplex call runs its handler inside the span of the handler.
		/// The echo service refuses the duplex kind, and the refusal runs
		/// inside the span too.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_duplex_call_records_its_handler_span() -> TransportResult<()> {
			let trace = TestTrace::with_detail(true);
			let (_responder, link, _wire) = responder_with(&trace, Vec::new());
			let (body, _forwarder, _notes) = body_fixture(1, 4);

			let reply = ReplySink::new(1, link.clone());
			let refused = MuxDispatch::duplex(&gated(echo(), link), body, reply, StreamRoute::local()).await;
			assert!(matches!(refused, Err(TransportError::NotServed)));
			assert_eq!(TestTrace::trail(&trace, &HANDLER_SPAN), HANDLER_SPAN);
			Ok(())
		}

		/// A peer cancel of a stream whose handler runs closes the span of that
		/// handler with the record of the cancel.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_peer_cancel_closes_the_handler_span_with_its_record() -> TransportResult<()> {
			let trace = TestTrace::with_detail(true);
			let request = InboundEvent::Request(1, Arc::new(TestFrame::v0(None, None)));
			let (responder, link, _wire) = responder_with(&trace, vec![request, InboundEvent::Cancel(1)]);
			let stalled = |_frame: Frame, _session: SessionContext| pending::<Result<Option<Frame>, TightBeamError>>();
			responder.serve_with(gated(stalled, link)).await?;

			let kept = [events::HANDLER_ENTER, events::HANDLER_EXIT, events::MUX_STREAM_CANCELLED];
			let cancelled = [events::HANDLER_ENTER, events::MUX_STREAM_CANCELLED];
			assert_eq!(TestTrace::trail(&trace, &kept), cancelled);
			Ok(())
		}
	}

	/// Tests of the refusals and the failed handlers that a responder records
	/// into the trail of its connection.
	#[cfg(feature = "instrument")]
	mod outcomes {
		use futures::future::ready;

		use super::internal_detail::{responder_with, responder_with_one_request};
		use super::*;
		use crate::trace::TraceCollector;
		use crate::urn::Urn;

		#[cfg(pooled_mux)]
		use super::super::super::testing::body_fixture;
		#[cfg(pooled_mux)]
		use super::internal_detail::{echo, gated};
		#[cfg(pooled_mux)]
		use crate::transport::multiplex::{CallContext, MuxDispatch, MuxService};
		#[cfg(pooled_mux)]
		use crate::TightBeamError;

		/// The labels of the records of `event` that `trace` holds, in the
		/// order it recorded them.
		fn labels(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<String>> {
			let records = trace.drain_events();
			records
				.into_iter()
				.filter(|record| record.urn == event)
				.map(|record| record.label.map(String::from))
				.collect()
		}

		/// A label that names `status`.
		fn label(status: TransitStatus) -> Option<String> {
			Some(status.as_str().to_owned())
		}

		/// A unary stream that reaches a dispatch with no unary method answers
		/// `Unimplemented`, and the responder records the refused kind.
		#[tokio::test]
		async fn a_stream_of_a_kind_the_dispatch_leaves_out_records_its_refusal() -> TransportResult<()> {
			let trace = TraceCollector::new();
			let (responder, _link, _wire) = responder_with_one_request(&trace);
			let streaming = |_body: StreamBody| ready(ResponsePackage::new(TransitStatus::Ok, None));
			responder.serve_streaming(streaming).await?;

			let refused = label(TransitStatus::Unimplemented);
			assert_eq!(labels(&trace, events::MUX_STREAM_REFUSED), [refused]);
			Ok(())
		}

		/// The responder refuses a peer stream that opens past the advertised
		/// cap with `ResourceExhausted`, and records the refusal.
		#[test]
		fn a_stream_past_the_cap_records_its_refusal() {
			let trace = TraceCollector::new();
			let frame = Arc::new(TestFrame::v0(None, None));
			let requests = [1, 3, 5, 7, 9].map(|stream_id| InboundEvent::Request(stream_id, Arc::clone(&frame)));
			let (responder, _link, _wire) = responder_with(&trace, requests.into());

			let mut serve = Box::pin(responder.serve(|_frame| pending::<ResponsePackage>()));
			poll_times(&mut serve, 8);

			let refused = label(TransitStatus::ResourceExhausted);
			assert_eq!(labels(&trace, events::MUX_STREAM_REFUSED), [refused]);
		}

		/// The refusal of every handler of [`Denying`].
		#[cfg(pooled_mux)]
		fn denied() -> TightBeamError {
			TransportError::from(TransitStatus::PermissionDenied).into()
		}

		/// A service whose every handler fails with `PermissionDenied`.
		#[cfg(pooled_mux)]
		struct Denying;

		#[cfg(pooled_mux)]
		impl MuxService for Denying {
			fn unary(
				&self,
				_frame: Frame,
				_cx: CallContext,
			) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
				ready(Err(denied()))
			}

			fn streaming(
				&self,
				_body: StreamBody,
				_cx: CallContext,
			) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
				ready(Err(denied()))
			}

			fn duplex(
				&self,
				_body: StreamBody,
				_reply: ReplySink,
				_cx: CallContext,
			) -> impl Future<Output = Result<(), TightBeamError>> + Send {
				ready(Err(denied()))
			}
		}

		/// A gated unary call whose handler fails records the failure, with
		/// the status that the call answers.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_unary_call_whose_handler_fails_records_the_failure() -> TransportResult<()> {
			let trace = TraceCollector::new();
			let (responder, link, _wire) = responder_with_one_request(&trace);
			responder.serve_with(gated(Denying, link)).await?;

			let failed = label(TransitStatus::PermissionDenied);
			assert_eq!(labels(&trace, events::HANDLER_FAILED), [failed]);
			Ok(())
		}

		/// A gated streaming call whose handler fails records the failure,
		/// with the status that the call answers.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_streaming_call_whose_handler_fails_records_the_failure() -> TransportResult<()> {
			let trace = TraceCollector::new();
			let (_responder, link, _wire) = responder_with(&trace, Vec::new());
			let (body, _forwarder, _notes) = body_fixture(1, 4);
			MuxDispatch::streaming(&gated(Denying, link), body, StreamRoute::local()).await?;

			let failed = label(TransitStatus::PermissionDenied);
			assert_eq!(labels(&trace, events::HANDLER_FAILED), [failed]);
			Ok(())
		}

		/// A gated duplex call whose handler fails records the failure, with
		/// the status that the call answers.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_duplex_call_whose_handler_fails_records_the_failure() -> TransportResult<()> {
			let trace = TraceCollector::new();
			let (_responder, link, _wire) = responder_with(&trace, Vec::new());
			let (body, _forwarder, _notes) = body_fixture(1, 4);
			let reply = ReplySink::new(1, link.clone());
			MuxDispatch::duplex(&gated(Denying, link), body, reply, StreamRoute::local()).await?;

			let failed = label(TransitStatus::PermissionDenied);
			assert_eq!(labels(&trace, events::HANDLER_FAILED), [failed]);
			Ok(())
		}

		/// A streaming open that reaches the default of a service refuses its
		/// kind: the responder records the refusal, and no handler failure.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_service_default_records_a_refused_kind_and_no_failure() -> TransportResult<()> {
			let trace = TraceCollector::new();
			let (body, _forwarder, _notes) = body_fixture(1, 4);
			let open = InboundEvent::StreamOpen(1, MuxStreamKind::Streaming, Box::new(body), StreamRoute::local());
			let (responder, link, _wire) = responder_with(&trace, vec![open]);
			responder.serve_with(gated(echo(), link)).await?;

			let refused = label(TransitStatus::Unimplemented);
			assert_eq!(labels(&trace, events::MUX_STREAM_REFUSED), [refused]);
			assert_eq!(trace.recorded(events::HANDLER_FAILED), 0);
			Ok(())
		}

		/// A service whose unary handler answers `Unimplemented` of its own.
		#[cfg(pooled_mux)]
		struct Unimplementing;

		#[cfg(pooled_mux)]
		impl MuxService for Unimplementing {
			fn unary(
				&self,
				_frame: Frame,
				_cx: CallContext,
			) -> impl Future<Output = Result<Option<Frame>, TightBeamError>> + Send {
				ready(Err(TransportError::from(TransitStatus::Unimplemented).into()))
			}
		}

		/// A handler that runs and fails with `Unimplemented` is a failed
		/// handler of a kind its service serves, so the trail records the
		/// failure and no refused kind.
		#[cfg(pooled_mux)]
		#[tokio::test]
		async fn a_handler_that_answers_unimplemented_records_its_failure() -> TransportResult<()> {
			let trace = TraceCollector::new();
			let (responder, link, _wire) = responder_with_one_request(&trace);
			responder.serve_with(gated(Unimplementing, link)).await?;

			let failed = label(TransitStatus::Unimplemented);
			assert_eq!(labels(&trace, events::HANDLER_FAILED), [failed]);
			assert_eq!(trace.recorded(events::MUX_STREAM_REFUSED), 0);
			Ok(())
		}
	}

	fn is_cap_refusal(command: &Outbound) -> bool {
		matches!(
			command,
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::End(package)))
				if package.status() == TransitStatus::ResourceExhausted
		)
	}

	/// A peer past the cap that this endpoint advertised opens streams at zero
	/// cost to itself, so a refusal that took a fresh queue slot per open would
	/// let a stalled writer hold one trailer per open (CWE-770). Refusals share
	/// the responder link's one slot, and the responder drops the rest.
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
