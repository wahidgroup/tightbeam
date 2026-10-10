//! One connection's shared state paired with the queue it writes on.

use core::future::poll_fn;
use std::collections::VecDeque;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::SinkExt;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

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

/// A connection's shared state and the outbound queue that serves it.
///
/// Every send path needs both handles, and they belong to one connection.
/// Pairing them in one owner keeps a queue from serving the state of a
/// different connection.
pub(crate) struct MuxLink {
	shared: Arc<MuxShared>,
	outbound: mpsc::Sender<Outbound>,
	/// Consumption reports from stream bodies back to the reader's credit
	/// replenishment. The channel carries no buffer of its own, so every
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
	/// - Outstanding notes are bounded by live bodies, and a reader that stops
	///   draining cannot be made to hold more (CWE-770).
	/// - A body whose slot is taken reports its current count once the slot
	///   frees ([`StreamBody`](super::body::StreamBody)).
	pub(crate) fn new(shared: Arc<MuxShared>, outbound: mpsc::Sender<Outbound>) -> (Self, mpsc::Receiver<DrainNote>) {
		let (drain_feedback, drained) = mpsc::channel(0);
		let link = Self { shared, outbound, drain_feedback };

		(link, drained)
	}

	/// Connection state behind this link.
	pub(crate) fn shared(&self) -> &Arc<MuxShared> {
		&self.shared
	}

	/// A fresh sender over the same queue.
	///
	/// A `futures::mpsc` channel admits `buffer + senders` items, so every
	/// clone carries a slot of its own. A send that must not be lost to
	/// backpressure takes a clone to claim that slot.
	///
	/// # Sources
	///
	/// - `futures::channel::mpsc::channel`, guaranteed per-sender slot:
	///   <https://docs.rs/futures/latest/futures/channel/mpsc/fn.channel.html>
	pub(crate) fn sender(&self) -> mpsc::Sender<Outbound> {
		self.outbound.clone()
	}

	/// Drain-note sender for a stream body on this connection.
	///
	/// Each clone carries its own guaranteed slot, so every body reports
	/// through its own capacity.
	pub(crate) fn drain_feedback(&self) -> mpsc::Sender<DrainNote> {
		self.drain_feedback.clone()
	}

	/// Hand `command` to the writer on this link's own sender without
	/// waiting.
	///
	/// The link's sender keeps its slot across calls, so a full queue
	/// refuses the command instead of admitting it through a fresh slot.
	///
	/// # Errors
	///
	/// - The refused command, when the queue is full or the writer driver is gone.
	pub(crate) fn try_send(&mut self, command: Outbound) -> Result<(), mpsc::TrySendError<Outbound>> {
		self.outbound.try_send(command)
	}

	/// Refuse a peer stream at the concurrency cap with a payload-free
	/// `ResourceExhausted` trailer on this link's own sender, without
	/// waiting.
	///
	/// # Resource bound
	///
	/// - The sender keeps its slot across calls, so a stalled writer admits
	///   one refusal and every later one is dropped instead of queued.
	/// - Only a peer that opens past the cap it was advertised reaches this
	///   path, so its excess opens buy no memory here (CWE-770).
	/// - Nothing was registered for the stream, so there is no ledger to release.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - The encode failure of a trailer that does not serialize.
	pub(crate) fn refuse_at_cap(&mut self, stream_id: u32) -> TransportResult<()> {
		let package = MuxEndPackage::new(stream_id, TransitStatus::ResourceExhausted, Vec::new())?;
		match self.outbound.try_send(Outbound::Envelope(package.into())) {
			Ok(()) => Ok(()),
			// An earlier refusal still holds the slot: this peer is past its
			// cap, so the refusal is the one thing a stalled writer may drop.
			Err(refused) if refused.is_full() => Ok(()),
			Err(_) => Err(TransportError::ConnectionClosed),
		}
	}

	/// Drain buffered control into the writer queue.
	///
	/// The drain is cancellation-safe, because a command leaves the buffer only
	/// after its slot is reserved.
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

	/// Send a response on a peer-initiated stream, chunking when it exceeds the
	/// peer's advertised receive size.
	///
	/// - Full chunks travel as `Data(last = false)`, and the final chunk
	///   travels inline in the `End` trailer (responder grammar).
	/// - Every payload-bearing record is gated by the peer's stream credit.
	/// - A response the session budget cannot carry degrades to a payload-free `ResourceExhausted` refusal.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - The encode failure of a response frame that does not serialize.
	pub(crate) async fn send_response(&self, stream_id: u32, response: ResponsePackage) -> TransportResult<()> {
		let mut status = response.status();
		let mut payload = match response.message() {
			Some(frame) => frame.as_ref().to_der()?,
			None => Vec::new(),
		};

		let credits = self.shared.credits_for(payload.len());
		match self.shared.admit_debit(credits, true).await {
			Ok(BudgetStanding::Healthy) => {}
			Ok(BudgetStanding::Exhausting) => {
				self.announce_goaway(GoAwayReason::BudgetExhausted).await?;
			}
			// Even the drain reserve cannot carry the payload, so refuse the
			// stream for free instead of tearing the connection down.
			Err(_) => {
				status = TransitStatus::ResourceExhausted;
				payload = Vec::new();
			}
		}

		if payload.is_empty() {
			return self.send_end_trailer(stream_id, status).await;
		}

		let chunk_size = self.shared.send_chunk_size;
		let total = self.shared.records_for(payload.len());

		self.shared.register_send_stream(stream_id, total);

		let mut sent: u64 = 0;
		for chunk in payload.chunks(chunk_size.get()) {
			sent += 1;

			let envelope = if sent == total {
				TransportEnvelope::from(MuxEndPackage::new(stream_id, status, chunk)?)
			} else {
				TransportEnvelope::from(MuxDataPackage::new(stream_id, false, chunk)?)
			};

			match self.send_data_envelope(stream_id, envelope).await {
				Ok(()) => {}
				// The peer cancelled the stream and removed its ledger
				// mid-send, so the receiver discards what already went out.
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

	/// Local teardown for an abandoned locally-initiated stream, shared by
	/// drop guards, abandoned sinks, and explicit close.
	///
	/// # Delivery
	///
	/// The cancel goes out on a fresh sender from [`MuxLink::sender`], so
	/// the peer frees its stream slot on this notice rather than on its
	/// own timeout.
	pub(crate) fn enqueue_stream_cancel(&self, stream_id: u32) {
		if let Some(mut forwarder) = self.shared.take_duplex(stream_id) {
			// A reply body already dropped has no reader for the failure, and
			// the stream is torn down either way.
			let _ = forwarder.forward(BodyEvent::Failed(CancelReason::Cancelled.cancel_error()));
		}
		if let Some(sender) = self.shared.remove_pending(stream_id) {
			// The initiator may already have dropped its future, which is one
			// of the ways a stream is abandoned.
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
	/// - [`TransportError::ConnectionClosed`] -- the writer queue closed.
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
	/// [`MuxShared::poll_open_enqueue`], returning the assigned stream ID.
	///
	/// The send reserves a writer-queue slot, then assigns the stream ID and
	/// enqueues in one critical section, so Opens reach the wire in ID order.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer queue closed.
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

		poll_fn(|cx| self.shared.poll_open_enqueue(reservation, request, &mut outbound, cx)).await
	}

	/// Queue a GoAway with `reason` and halt the allocator, exactly once per
	/// connection.
	///
	/// Graceful shutdown and the budget drain share this path.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer queue closed.
	pub(crate) async fn announce_goaway(&self, reason: GoAwayReason) -> TransportResult<()> {
		let Some(package) = self.shared.goaway_package(reason) else {
			return Ok(());
		};

		self.sender()
			.send(Outbound::Envelope(package.into()))
			.await
			.map_err(|_| TransportError::ConnectionClosed)?;

		Ok(())
	}

	/// Queue a best-effort GoAway on a fault path. A full queue drops it.
	pub(crate) fn goaway_best_effort(&self, last_stream_id: u32, reason: GoAwayReason) {
		#[cfg(feature = "instrument")]
		self.shared.emit_goaway_event(events::MUX_GOAWAY_SENT, reason);

		let package = GoAwayPackage::new(last_stream_id, reason);
		// A full or closed queue drops the GoAway, which is the best effort
		// a fault path promises.
		let _ = self.sender().try_send(Outbound::Envelope(package.into()));
	}

	/// Renew in band when a budget reaches the drain reserve, or drain with a
	/// GoAway when no rekey materials are ready.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer queue closed.
	pub(crate) async fn renew_or_drain(&self) -> TransportResult<()> {
		#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
		if self.shared.renewal_ready() {
			// A full queue drops the trigger. The budget stays at the reserve,
			// so the next debit fires it again.
			let _ = self.sender().try_send(Outbound::StartRenewal);
			return Ok(());
		}

		self.announce_goaway(GoAwayReason::BudgetExhausted).await
	}
}
