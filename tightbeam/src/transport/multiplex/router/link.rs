//! One connection's shared state paired with the queue it writes on.

use core::future::poll_fn;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::SinkExt;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

use super::body::BodyEvent;
use super::flow::{chunk_records, payload_credits};
use super::outbound::{outbound_handle, Outbound};
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
}

impl Clone for MuxLink {
	fn clone(&self) -> Self {
		Self { shared: Arc::clone(&self.shared), outbound: outbound_handle(&self.outbound) }
	}
}

impl MuxLink {
	/// Pair `shared` with the queue its sends travel on.
	pub(crate) fn new(shared: Arc<MuxShared>, outbound: mpsc::Sender<Outbound>) -> Self {
		Self { shared, outbound }
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
		outbound_handle(&self.outbound)
	}

	/// Send a response on a peer-initiated stream, chunking when it
	/// exceeds the peer's advertised receive size: full chunks travel as
	/// `Data(last = false)` and the final chunk travels inline in the `End`
	/// trailer (responder grammar). Every payload-bearing record is gated
	/// by the peer's stream credit. A response the session budget cannot
	/// carry degrades to a payload-free `ResourceExhausted` refusal.
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

		let credits = payload_credits(payload.len(), self.shared.send_chunk_size, self.shared.credit_unit);
		match self.shared.admit_debit(credits, true).await {
			Ok(BudgetStanding::Healthy) => {}
			Ok(BudgetStanding::Exhausting) => {
				self.announce_goaway(GoAwayReason::BudgetExhausted).await?;
			}
			// Even the drain reserve cannot carry the payload: refuse
			// the stream for free instead of tearing the connection
			Err(_) => {
				status = TransitStatus::ResourceExhausted;
				payload = Vec::new();
			}
		}

		if payload.is_empty() {
			return self.send_end_trailer(stream_id, status).await;
		}

		let chunk_size = self.shared.send_chunk_size;
		let total = chunk_records(payload.len(), chunk_size);

		self.shared.register_send_stream(stream_id, total);

		let mut sent: u64 = 0;
		for chunk in payload.chunks(chunk_size) {
			sent += 1;

			let envelope = if sent == total {
				TransportEnvelope::from(MuxEndPackage::new(stream_id, status, chunk)?)
			} else {
				TransportEnvelope::from(MuxDataPackage::new(stream_id, false, chunk)?)
			};

			match self.send_data_envelope(stream_id, envelope).await {
				Ok(()) => {}
				// Ledger removed mid-send: the peer cancelled the stream
				// and the receiver will discard what already went out
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

	/// Terminal `End` trailer closing a peer-initiated stream. Payload-free,
	/// so it travels outside stream credit like every empty `End`, and it
	/// releases the stream's sender ledger.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
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
			let _ = forwarder.forward(BodyEvent::Failed(CancelReason::Cancelled.cancel_error()));
		}
		if let Some(sender) = self.shared.remove_pending(stream_id) {
			let _ = sender.send(StreamOutcome::Cancelled(CancelReason::Cancelled));
			let package = MuxCancelPackage::new(stream_id, CancelReason::Cancelled);
			let _ = self.sender().try_send(Outbound::Envelope(package.into()));
		}
	}

	/// Send one credit-gated data chunk: reserve a writer-queue slot,
	/// then take the stream credit and enqueue in one critical section
	/// (see [`MuxShared::poll_send_enqueue`]).
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- once the stream's ledger is
	///   gone, whether cancelled, resolved, or lost with the connection
	pub(crate) async fn send_data_envelope(&self, stream_id: u32, envelope: TransportEnvelope) -> TransportResult<()> {
		let mut outbound = self.sender();
		let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
		if ready.is_err() {
			return Err(TransportError::ConnectionClosed);
		}

		let mut slot = Some(envelope);
		poll_fn(|cx| self.shared.poll_send_enqueue(stream_id, &mut outbound, &mut slot, cx)).await
	}

	/// Send a stream's Open record through the atomic open (see
	/// [`MuxShared::poll_open_enqueue`]): reserve a writer-queue slot,
	/// then assign the stream ID and enqueue in one critical section so
	/// Opens reach the wire in ID order.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- when the writer queue closed
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

	/// Queue a GoAway with `reason` and halt the allocator, exactly once
	/// per connection. Shared by graceful shutdown and the budget drain.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- when the writer queue closed
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

	/// Best-effort GoAway on a fault path.
	pub(crate) fn goaway_best_effort(&self, last_stream_id: u32, reason: GoAwayReason) {
		#[cfg(feature = "instrument")]
		self.shared.emit_goaway_event(events::MUX_GOAWAY_SENT, reason);

		let package = GoAwayPackage::new(last_stream_id, reason);
		let _ = self.sender().try_send(Outbound::Envelope(package.into()));
	}

	/// On a budget at the drain reserve, renew in band when possible,
	/// otherwise GoAway drain (no rekey materials).
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- when the writer queue closed
	pub(crate) async fn renew_or_drain(&self) -> TransportResult<()> {
		#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
		if self.shared.renewal_ready() {
			// A full queue drops the trigger: the budget stays at the
			// reserve, so the next debit re-fires it.
			let _ = self.sender().try_send(Outbound::StartRenewal);
			return Ok(());
		}

		self.announce_goaway(GoAwayReason::BudgetExhausted).await
	}
}
