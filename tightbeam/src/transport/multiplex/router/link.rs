//! One connection's shared state paired with the queue it writes on.

use core::future::poll_fn;
use std::collections::VecDeque;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::SinkExt;

use super::body::{BodyEvent, DrainNote};
use super::outbound::Outbound;
use super::shared::{BudgetStanding, MuxShared, OpenRequest, StreamOutcome, StreamReservation};
use crate::der::Encode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{
	CancelReason, GoAwayPackage, GoAwayReason, MuxCancelPackage, MuxDataPackage, MuxEndPackage, ResponsePackage,
	TransportEnvelope,
};
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::TransportResult;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

/// A connection's shared state and the outbound queue that serves it.
///
/// Every send path needs both handles, so one owner of both keeps each queue
/// on the state of its own connection.
pub(crate) struct MuxLink {
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	/// The sender of consumption reports from stream bodies to the reader's
	/// credit replenishment. The channel has a zero-length buffer, so every
	/// body reports through the one slot its own sender clone owns.
	drain_feedback: mpsc::Sender<DrainNote>,
}

impl Clone for MuxLink {
	fn clone(&self) -> Self {
		Self {
			shared: Arc::clone(&self.shared),
			outbound: self.outbound.clone(),
			drain_feedback: self.drain_feedback.clone(),
		}
	}
}

impl MuxLink {
	/// Pair `shared` with the queue its sends travel on, and open the channel
	/// its stream bodies report consumption on.
	///
	/// The link keeps the sending end. The caller receives the other end for
	/// the reader, so the reader drains the channel this link feeds.
	///
	/// # Drain bound
	///
	/// The drain channel has a zero-length buffer, so its capacity is one slot
	/// per live sender.
	///
	/// - Live bodies bound the outstanding notes, so a reader that stops its
	///   drain holds at most one note per live body (CWE-770).
	/// - A body whose slot holds an unread note reports its current count once
	///   the slot frees ([`StreamBody`](super::body::StreamBody)).
	pub(crate) fn new(shared: Arc<MuxShared>, outbound: mpsc::Sender<Outbound>) -> (Self, mpsc::Receiver<DrainNote>) {
		let (drain_feedback, drained) = mpsc::channel(0);
		let link = Self { shared, outbound, drain_feedback };

		(link, drained)
	}

	/// The connection state behind this link.
	pub(crate) fn shared(&self) -> &Arc<MuxShared> {
		&self.shared
	}

	/// A fresh sender over the same queue.
	///
	/// A `futures::mpsc` channel admits `buffer + senders` items, so every
	/// clone carries a slot of its own. A send that backpressure must not drop
	/// takes a clone to claim that slot.
	///
	/// # Sources
	///
	/// - `futures::channel::mpsc::channel`, guaranteed per-sender slot:
	///   <https://docs.rs/futures/latest/futures/channel/mpsc/fn.channel.html>
	pub(crate) fn sender(&self) -> mpsc::Sender<Outbound> {
		self.outbound.clone()
	}

	/// A drain-note sender for a stream body on this connection.
	///
	/// Each clone carries its own guaranteed slot, so every body reports
	/// through its own capacity.
	pub(crate) fn drain_feedback(&self) -> mpsc::Sender<DrainNote> {
		self.drain_feedback.clone()
	}

	/// Hand `command` to the writer on this link's own sender without a
	/// wait.
	///
	/// The link's sender keeps its slot across calls, so a full queue
	/// refuses the command, which a fresh slot would admit.
	///
	/// # Errors
	///
	/// - The refused command, when the queue is full or the writer driver is gone.
	pub(crate) fn try_send(&mut self, command: Outbound) -> Result<(), mpsc::TrySendError<Outbound>> {
		self.outbound.try_send(command)
	}

	/// Refuse a peer stream at the concurrency cap with a payload-free
	/// `ResourceExhausted` trailer on this link's own sender, without a
	/// wait.
	///
	/// # Resource bound
	///
	/// - The sender keeps its slot across calls, so a stalled writer admits
	///   one refusal, and the link drops each later one rather than queue it.
	/// - Only a peer that opens past the cap this side advertises reaches this
	///   path, so its excess opens buy no memory here (CWE-770).
	/// - The refusal comes before the stream registers, so the call leaves the ledgers as they are.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - The encode failure of a trailer that does not serialize.
	pub(crate) fn refuse_at_cap(&mut self, stream_id: u32) -> TransportResult<()> {
		let package = MuxEndPackage::new(stream_id, TransitStatus::ResourceExhausted, Vec::new())?;
		match self.outbound.try_send(Outbound::Envelope(package.into())) {
			Ok(()) => Ok(()),
			// An earlier refusal holds the slot, and this peer is past its cap,
			// so the refusal is the one record that a stalled writer may drop.
			Err(refused) if refused.is_full() => Ok(()),
			Err(_) => Err(TransportError::ConnectionClosed),
		}
	}

	/// Drain buffered control into the writer queue.
	///
	/// The drain is cancellation-safe, because a command leaves the buffer only
	/// after the drain reserves its slot.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	pub(crate) async fn flush_control(&mut self, pending: &mut VecDeque<Outbound>) -> TransportResult<()> {
		let outbound = &mut self.outbound;
		while !pending.is_empty() {
			let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
			if ready.is_err() {
				return Err(TransportError::ConnectionClosed);
			}

			let Some(command) = pending.pop_front() else {
				return Ok(());
			};

			outbound.start_send(command).map_err(|_| TransportError::ConnectionClosed)?;
		}

		Ok(())
	}

	/// Send a response on a peer-initiated stream, in chunks when it exceeds
	/// the peer's advertised receive size.
	///
	/// - Full chunks travel as `Data(last = false)`, and the final chunk
	///   travels inline in the `End` trailer (responder grammar).
	/// - The peer's stream credit gates every payload-bearing record.
	/// - A response the session budget cannot carry degrades to a payload-free `ResourceExhausted` refusal.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended before the response left.
	/// - The encode failure of a response frame that does not serialize.
	/// - The injected error, when the runtime fault model injects a fault at the record of a budget refusal.
	pub(crate) async fn send_response(&self, stream_id: u32, response: ResponsePackage) -> TransportResult<()> {
		let mut status = response.status();
		let mut payload = match response.message() {
			Some(frame) => frame.as_ref().to_der()?,
			None => Vec::new(),
		};

		let credits = self.shared.credits_for(payload.len());
		match self.shared.admit_debit(credits, true).await {
			Ok(BudgetStanding::Healthy) => {}
			Ok(BudgetStanding::Exhausting) => self.drain_budget(credits).await?,
			// Even the drain reserve cannot carry the payload, so the call
			// refuses the stream for free and keeps the connection up.
			Err(TransportError::OperationFailed(TransportFailure::BudgetExhausted)) => {
				status = TransitStatus::ResourceExhausted;
				payload = Vec::new();
			}
			Err(fault) => return Err(fault),
		}

		if payload.is_empty() {
			return self.send_end_trailer(stream_id, status).await;
		}

		let chunk_size = self.shared.send_chunk_size;
		let total = self.shared.records_for(payload.len());

		self.shared.register_send_stream(stream_id, total);

		let mut sent: u64 = 0;
		for chunk in payload.chunks(chunk_size.get()) {
			sent = sent.saturating_add(1);

			let envelope = if sent == total {
				TransportEnvelope::from(MuxEndPackage::new(stream_id, status, chunk)?)
			} else {
				TransportEnvelope::from(MuxDataPackage::new(stream_id, false, chunk)?)
			};

			match self.send_data_envelope(stream_id, envelope).await {
				Ok(()) => {}
				// A peer cancel removes the stream's ledger mid-send, and the
				// receiver discards the chunks that went out.
				Err(TransportError::OperationFailed(TransportFailure::Cancelled)) => return Ok(()),
				Err(err) => {
					self.shared.finish_send_stream(stream_id);
					return Err(err);
				}
			}
		}

		self.shared.finish_send_stream(stream_id);

		Ok(())
	}

	/// Send the terminal `End` trailer that closes a peer-initiated stream.
	///
	/// The trailer is payload-free, so it travels outside stream credit like
	/// every empty `End`, and it releases the stream's sender ledger.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - The encode failure of a trailer that does not serialize.
	pub(crate) async fn send_end_trailer(&self, stream_id: u32, status: TransitStatus) -> TransportResult<()> {
		let package = MuxEndPackage::new(stream_id, status, Vec::new())?;
		let mut outbound = self.sender();
		let sent = outbound.send(Outbound::Envelope(package.into())).await;

		self.shared.finish_send_stream(stream_id);

		sent.map_err(|_| TransportError::ConnectionClosed)
	}

	/// Tear down an abandoned locally-initiated stream on this side. Drop
	/// guards, abandoned sinks, and an explicit close share the call.
	///
	/// # Delivery
	///
	/// The cancel goes out on a fresh sender from [`MuxLink::sender`], so
	/// the peer frees its stream slot on this notice rather than on its
	/// own timeout.
	pub(crate) fn enqueue_stream_cancel(&self, stream_id: u32) {
		if let Some(mut forwarder) = self.shared.take_duplex(stream_id) {
			// A reply body that has dropped has no reader for the failure, and
			// this call tears the stream down either way.
			let _ = forwarder.forward(BodyEvent::Failed(CancelReason::Cancelled.cancel_error()));
		}
		if let Some(sender) = self.shared.remove_pending(stream_id) {
			// The initiator may have dropped its future, which is one way to
			// abandon a stream.
			let _ = sender.send(StreamOutcome::Cancelled(CancelReason::Cancelled));
			let package = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
			// A full or closed queue drops the notice, and the peer then frees
			// the slot on its own timeout.
			let _ = self.sender().try_send(Outbound::Envelope(package.into()));
		}
	}

	/// Send one credit-gated data chunk.
	///
	/// The send reserves a writer-queue slot, then takes the stream credit and
	/// enqueues in one critical section, as [`MuxShared::poll_send_enqueue`]
	/// describes.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with
	///   [`TransportFailure::Cancelled`] -- the stream's ledger is gone,
	///   whether cancelled, resolved, or lost with the connection.
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	pub(crate) async fn send_data_envelope(&self, stream_id: u32, envelope: TransportEnvelope) -> TransportResult<()> {
		let mut outbound = self.sender();
		let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
		if ready.is_err() {
			return Err(TransportError::ConnectionClosed);
		}

		let mut slot = Some(envelope);
		poll_fn(|cx| self.shared.poll_send_enqueue(stream_id, &mut outbound, &mut slot, cx)).await
	}

	/// Send a stream's Open record through the atomic open of
	/// [`StreamReservation::poll_open`], and return the stream ID it assigns.
	///
	/// The send reserves a writer-queue slot, then assigns the stream ID and
	/// enqueues in one critical section, so Opens reach the wire in ID order.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway ended admission, or the ID space is exhausted.
	pub(crate) async fn send_open_envelope(
		&self,
		reservation: &mut StreamReservation,
		request: &mut OpenRequest<'_>,
	) -> TransportResult<u32> {
		let mut outbound = self.sender();
		let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
		if ready.is_err() {
			return Err(TransportError::ConnectionClosed);
		}

		poll_fn(|cx| reservation.poll_open(request, &mut outbound, cx)).await
	}

	/// Queue a GoAway with `reason` and halt the allocator, exactly once per
	/// connection.
	///
	/// Graceful shutdown and the budget drain share this path. The call records
	/// the GoAway once it queues it, so a fault the trace injects at the record
	/// leaves the GoAway on its way.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer queue closed.
	/// - The injected error, when the runtime fault model injects a fault at the event of the GoAway.
	pub(crate) async fn announce_goaway(&self, reason: GoAwayReason) -> TransportResult<()> {
		let Some(package) = self.shared.goaway_package(reason) else {
			return Ok(());
		};

		self.sender()
			.send(Outbound::Envelope(package.into()))
			.await
			.map_err(|_| TransportError::ConnectionClosed)?;

		#[cfg(feature = "instrument")]
		self.shared.emit_goaway_event(events::MUX_GOAWAY_SENT, reason)?;

		Ok(())
	}

	/// Announce the drain that a debit of `credits` from the reserve reached.
	///
	/// The debit stands once the drain records its GoAway. A drain that fails
	/// returns the credits to the budget, because the payload they meter does
	/// not leave.
	///
	/// # Errors
	///
	/// - The errors of [`announce_goaway`](Self::announce_goaway).
	pub(crate) async fn drain_budget(&self, credits: u64) -> TransportResult<()> {
		let drained = self.announce_goaway(GoAwayReason::BudgetExhausted).await;
		if drained.is_err() {
			self.shared.refund_budget(credits);
		}

		drained
	}

	/// Queue a best-effort GoAway on a fault path. A full queue drops it.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the event of the GoAway.
	pub(crate) fn goaway_best_effort(&self, last_stream_id: u32, reason: GoAwayReason) -> TransportResult<()> {
		let package = GoAwayPackage::new(last_stream_id, reason);
		// A full or closed queue drops the GoAway, which is the best effort
		// a fault path promises.
		let _ = self.sender().try_send(Outbound::Envelope(package.into()));

		#[cfg(feature = "instrument")]
		self.shared.emit_goaway_event(events::MUX_GOAWAY_SENT, reason)?;

		Ok(())
	}

	/// Renew in band when a budget reaches the drain reserve, or drain with a
	/// GoAway when no rekey materials are ready.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer queue closed.
	pub(crate) async fn renew_or_drain(&self) -> TransportResult<()> {
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		if self.shared.renewal_ready() {
			// A full queue drops the trigger. The budget stays at the reserve,
			// so the next debit fires it again.
			let _ = self.sender().try_send(Outbound::StartRenewal);
			return Ok(());
		}

		self.announce_goaway(GoAwayReason::BudgetExhausted).await
	}
}

#[cfg(test)]
impl MuxLink {
	/// A link over `shared` whose outbound queue holds `queue` commands,
	/// beside the receiver of that queue and the receiver of its drain notes.
	pub(crate) fn over(
		shared: Arc<MuxShared>,
		queue: usize,
	) -> (MuxLink, mpsc::Receiver<Outbound>, mpsc::Receiver<DrainNote>) {
		let (outbound, wire) = mpsc::channel(queue);
		let (link, notes) = MuxLink::new(shared, outbound);
		(link, wire, notes)
	}
}

#[cfg(all(test, feature = "testing-fault", feature = "instrument"))]
mod tests {
	use core::task::Poll;

	use super::super::fixtures::poll_now;
	use super::*;
	use crate::testing::fixtures::TestTrace;
	use crate::testing::TestFrame;
	use crate::transport::envelopes::MuxEnvelope;
	use crate::transport::handshake::negotiation::MuxSettings;
	use crate::transport::multiplex::MuxRole;

	/// A server link under `settings` whose trace injects
	/// [`TransportError::InvalidAddress`] at every record of `MUX_GOAWAY_SENT`,
	/// beside the receiver of its outbound queue.
	fn goaway_faulting_link(settings: &MuxSettings) -> (MuxLink, mpsc::Receiver<Outbound>) {
		let trace = TestTrace::faulting(events::MUX_GOAWAY_SENT, || TransportError::InvalidAddress, crate::bps!(10000));
		let shared = MuxShared::traced(MuxRole::Server, settings, trace);
		let (link, wire, _drained) = MuxLink::over(Arc::new(shared), 4);
		(link, wire)
	}

	/// The link records the GoAway once it queues it, so a fault the trace
	/// injects at the record leaves the GoAway on its way to the peer
	/// (RFC 9113 § 6.8).
	#[test]
	fn a_fault_at_the_goaway_record_leaves_the_goaway_queued() {
		let (link, mut wire) = goaway_faulting_link(&MuxSettings::symmetric(4));

		let announced = poll_now(link.announce_goaway(GoAwayReason::Shutdown));
		let queued = wire.try_recv().ok();
		assert!(matches!(announced, Poll::Ready(Err(TransportError::InvalidAddress))));
		assert!(matches!(queued.as_ref().and_then(Outbound::mux), Some(MuxEnvelope::GoAway(_))));
	}

	/// A response whose debit reaches the drain reserve, and whose drain
	/// fails at its record, returns its credits, because the response does
	/// not leave.
	#[test]
	fn a_failed_drain_returns_its_debit() {
		let (link, _wire) = goaway_faulting_link(&MuxSettings::budgeted(6));
		let response = ResponsePackage::new(TransitStatus::Ok, Some(TestFrame::v0(None, None)));

		let sent = poll_now(link.send_response(1, response));
		assert!(matches!(sent, Poll::Ready(Err(TransportError::InvalidAddress))));
		assert_eq!(link.shared().send_budget(), Some(6));
	}
}
