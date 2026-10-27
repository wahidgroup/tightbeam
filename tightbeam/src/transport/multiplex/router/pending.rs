//! The replies a connection still awaits: its reserved streams, its open
//! streams, and its pings.

use std::collections::BTreeMap;

use futures::channel::oneshot;

use super::body::{BodyEvent, ForwardedStream};
use super::shared::StreamOutcome;
use crate::transport::envelopes::CancelReason;
use crate::transport::{TransportError, TransportResult};

/// Identity of a reserved stream until its Open record assigns the stream ID.
///
/// Only [`PendingReplies::reserve`] makes one, and opening or cancelling the
/// stream consumes it.
pub struct ReservationKey(u64);

/// One stream that holds a cap slot and has not opened yet.
struct Reserved {
	/// Resolves the initiator's response future.
	outcome: oneshot::Sender<StreamOutcome>,
	/// Reply forwarder of a duplex stream, which waits here for the stream ID.
	reply: Option<ForwardedStream>,
}

/// Whether the table takes new streams and pings, and what ended that.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Admission {
	/// Streams and pings register.
	#[default]
	Open,
	/// A GoAway went out or came in. The open streams still resolve.
	Draining,
	/// A driver of the connection ended, so nothing is asked or answered.
	Closed,
}

/// Locally-initiated streams and local pings, each held until its answer
/// arrives or its caller gives it up.
///
/// - The table decides admission, and [`Self::reserve`] and [`Self::admit_ping`] are the only ways in.
/// - [`Self::drain`] and [`Self::close`] end admission, so nothing registers where no answer can come.
/// - A stream is held from its reservation on, so each end of the connection reaches an unopened one.
#[derive(Default)]
pub struct PendingReplies {
	/// Streams reserved and not yet opened.
	reserved: BTreeMap<u64, Reserved>,
	/// Key of the next reservation.
	next_reservation: u64,
	/// Open streams awaiting their response, keyed by stream ID.
	streams: BTreeMap<u32, oneshot::Sender<StreamOutcome>>,
	/// Pings awaiting their ack, keyed by correlation value.
	pings: BTreeMap<u64, oneshot::Sender<()>>,
	/// Whether new streams and pings register. It only moves forward, from
	/// open to draining to closed.
	admission: Admission,
}

impl PendingReplies {
	/// Why nothing new registers, or `None` while the table admits.
	///
	/// A connection that failed answers [`TransportError::ConnectionClosed`]
	/// even after a GoAway, because a drain could still finish and a failed
	/// connection cannot.
	pub fn refusal(&self) -> Option<TransportError> {
		match self.admission {
			Admission::Open => None,
			Admission::Draining => Some(TransportError::Draining),
			Admission::Closed => Some(TransportError::ConnectionClosed),
		}
	}

	/// Whether a driver of the connection ended, so that nothing can be
	/// answered.
	pub fn is_closed(&self) -> bool {
		self.admission == Admission::Closed
	}

	/// Whether a GoAway ended admission on a connection that still runs.
	pub fn is_draining(&self) -> bool {
		self.admission == Admission::Draining
	}

	/// Count the streams awaiting their response.
	pub fn stream_count(&self) -> usize {
		self.streams.len()
	}

	/// Count the streams that hold a cap slot: the open ones and the reserved
	/// ones.
	pub fn open_load(&self) -> usize {
		self.streams.len().saturating_add(self.reserved.len())
	}

	/// Whether `stream_id` is awaiting its response.
	pub fn holds_stream(&self, stream_id: u32) -> bool {
		self.streams.contains_key(&stream_id)
	}

	/// Hold `outcome` for a stream that opens later, with the reply forwarder
	/// of a duplex.
	///
	/// # Errors
	///
	/// - The [`refusal`](Self::refusal) that ended admission.
	pub fn reserve(
		&mut self,
		outcome: oneshot::Sender<StreamOutcome>,
		reply: Option<ForwardedStream>,
	) -> TransportResult<ReservationKey> {
		if let Some(refusal) = self.refusal() {
			return Err(refusal);
		}

		let key = self.next_reservation;
		self.next_reservation = key.wrapping_add(1);
		self.reserved.insert(key, Reserved { outcome, reply });
		Ok(ReservationKey(key))
	}

	/// Open a reserved stream under its assigned ID.
	///
	/// The outcome sender moves to the open streams. The reply forwarder of a
	/// duplex comes back for the registry that the reader feeds.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- a driver of the connection ended.
	/// - [`TransportError::Draining`] -- a GoAway resolved the reservation first.
	pub fn open(&mut self, key: ReservationKey, stream_id: u32) -> TransportResult<Option<ForwardedStream>> {
		if self.is_closed() {
			return Err(TransportError::ConnectionClosed);
		}

		let Some(reserved) = self.reserved.remove(&key.0) else {
			return Err(TransportError::Draining);
		};

		self.streams.insert(stream_id, reserved.outcome);
		Ok(reserved.reply)
	}

	/// Give up a reserved stream, and report whether it still held its cap
	/// slot.
	///
	/// Its response future and its duplex body both read a local cancel. An
	/// end of admission that resolved the stream first leaves nothing to do.
	pub fn cancel(&mut self, key: ReservationKey) -> bool {
		let Some(mut reserved) = self.reserved.remove(&key.0) else {
			return false;
		};

		// The initiator may already have dropped its future, which is what
		// abandons a reservation in the first place.
		let _ = reserved.outcome.send(StreamOutcome::Cancelled(CancelReason::Cancelled));
		if let Some(reply) = reserved.reply.as_mut() {
			// A reply body already dropped has no reader for the cancel.
			let _ = reply.forward(BodyEvent::Failed(CancelReason::Cancelled.cancel_error()));
		}

		true
	}

	/// End admission for a GoAway in either direction, and resolve every
	/// reserved stream as draining, because none of them can open.
	///
	/// The open streams stay. A table already closed stays closed.
	pub fn drain(&mut self) {
		if self.admission == Admission::Open {
			self.admission = Admission::Draining;
		}

		for (_, mut reserved) in core::mem::take(&mut self.reserved) {
			// A dropped receiver is a duplex, whose reply travels through its
			// body, or an initiator that gave up before the GoAway.
			let _ = reserved.outcome.send(StreamOutcome::Draining);
			if let Some(reply) = reserved.reply.as_mut() {
				// A reply body already dropped has no reader for the failure.
				let _ = reply.forward(BodyEvent::Failed(TransportError::Draining));
			}
		}
	}

	/// Hold `sender` until the ack of the ping `opaque` arrives.
	///
	/// # Errors
	///
	/// - The [`refusal`](Self::refusal) that ended admission.
	pub fn admit_ping(&mut self, opaque: u64, sender: oneshot::Sender<()>) -> TransportResult<()> {
		if let Some(refusal) = self.refusal() {
			return Err(refusal);
		}

		self.pings.insert(opaque, sender);
		Ok(())
	}

	/// Detach the outcome sender of `stream_id`, or return `None` for an
	/// unknown ID.
	pub fn take_stream(&mut self, stream_id: u32) -> Option<oneshot::Sender<StreamOutcome>> {
		self.streams.remove(&stream_id)
	}

	/// Detach every stream whose ID is `first` or above.
	pub fn take_streams_from(&mut self, first: u32) -> BTreeMap<u32, oneshot::Sender<StreamOutcome>> {
		self.streams.split_off(&first)
	}

	/// Detach the ack sender of the ping `opaque`, or return `None` for an
	/// unknown correlation value.
	pub fn take_ping(&mut self, opaque: u64) -> Option<oneshot::Sender<()>> {
		self.pings.remove(&opaque)
	}

	/// Drop the ping `opaque` unresolved. An unknown correlation value is a
	/// ping already resolved, which leaves nothing to drop.
	pub fn forget_ping(&mut self, opaque: u64) {
		self.pings.remove(&opaque);
	}

	/// Drop every slot and end admission for good. Each receiver observes the
	/// cancellation, and each reply body observes its closed channel.
	pub fn close(&mut self) {
		self.admission = Admission::Closed;
		self.reserved.clear();
		self.streams.clear();
		self.pings.clear();
	}
}

#[cfg(test)]
mod tests {
	use core::task::Poll;

	use super::super::testing::body_fixture;
	use super::*;
	use crate::transport::error::TransportFailure;

	fn closed() -> PendingReplies {
		let mut pending = PendingReplies::default();
		pending.close();
		pending
	}

	fn draining() -> PendingReplies {
		let mut pending = PendingReplies::default();
		pending.drain();
		pending
	}

	#[test]
	fn test_reservation_refused_once_closed() {
		let (outcome, _receiver) = oneshot::channel();
		let reserved = closed().reserve(outcome, None);
		assert!(matches!(reserved, Err(TransportError::ConnectionClosed)));
	}

	#[test]
	fn test_ping_refused_once_closed() {
		let (sender, _receiver) = oneshot::channel();
		let admitted = closed().admit_ping(0, sender);
		assert!(matches!(admitted, Err(TransportError::ConnectionClosed)));
	}

	#[test]
	fn test_reservation_refused_once_draining() {
		let (outcome, _receiver) = oneshot::channel();
		let reserved = draining().reserve(outcome, None);
		assert!(matches!(reserved, Err(TransportError::Draining)));
	}

	#[test]
	fn test_ping_refused_once_draining() {
		let (sender, _receiver) = oneshot::channel();
		let admitted = draining().admit_ping(0, sender);
		assert!(matches!(admitted, Err(TransportError::Draining)));
	}

	// A drain could still finish, and a failed connection cannot, so the end
	// wins in either order.
	#[test]
	fn test_close_outranks_a_drain() {
		let mut drained_first = draining();
		drained_first.close();

		let mut closed_first = closed();
		closed_first.drain();

		assert!(matches!(drained_first.refusal(), Some(TransportError::ConnectionClosed)));
		assert!(matches!(closed_first.refusal(), Some(TransportError::ConnectionClosed)));
		assert!(!closed_first.is_draining());
	}

	#[test]
	fn test_open_moves_a_reservation_to_the_open_streams() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (outcome, _receiver) = oneshot::channel();
		let key = pending.reserve(outcome, None)?;
		assert_eq!((pending.open_load(), pending.stream_count()), (1, 0));

		let reply = pending.open(key, 1)?;
		assert!(reply.is_none());
		assert!(pending.holds_stream(1));
		assert_eq!((pending.open_load(), pending.stream_count()), (1, 1));
		Ok(())
	}

	#[test]
	fn test_open_returns_the_reply_forwarder() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (outcome, _receiver) = oneshot::channel();
		let (_body, forwarder, _notes) = body_fixture(1, 4);
		let key = pending.reserve(outcome, Some(forwarder))?;

		let reply = pending.open(key, 1)?;
		assert!(reply.is_some());
		Ok(())
	}

	#[test]
	fn test_cancel_frees_the_cap_slot_and_tells_both_halves() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (outcome, mut response) = oneshot::channel();
		let (mut body, forwarder, _notes) = body_fixture(1, 4);
		let key = pending.reserve(outcome, Some(forwarder))?;

		assert!(pending.cancel(key));
		assert_eq!(pending.open_load(), 0);

		let told = response.try_recv();
		assert!(matches!(told, Ok(Some(StreamOutcome::Cancelled(CancelReason::Cancelled)))));

		let ended = body.poll_chunk_now();
		assert!(matches!(
			ended,
			Poll::Ready(Err(TransportError::OperationFailed(TransportFailure::Cancelled)))
		));
		Ok(())
	}

	#[test]
	fn test_cancel_after_a_drain_finds_nothing() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (outcome, _receiver) = oneshot::channel();
		let key = pending.reserve(outcome, None)?;

		pending.drain();

		assert!(!pending.cancel(key));
		Ok(())
	}

	#[test]
	fn test_close_cancels_every_slot() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (reserved, mut reserved_outcome) = oneshot::channel();
		let (opened, mut opened_outcome) = oneshot::channel();
		let (ping, mut ack) = oneshot::channel();
		let (mut body, forwarder, _notes) = body_fixture(1, 4);

		pending.reserve(reserved, Some(forwarder))?;

		let key = pending.reserve(opened, None)?;
		pending.open(key, 1)?;
		pending.admit_ping(0, ping)?;
		pending.close();

		assert!(reserved_outcome.try_recv().is_err());
		assert!(opened_outcome.try_recv().is_err());
		assert!(ack.try_recv().is_err());

		let ended = body.poll_chunk_now();
		assert!(matches!(ended, Poll::Ready(Err(TransportError::ConnectionClosed))));
		assert_eq!(pending.open_load(), 0);
		Ok(())
	}

	#[test]
	fn test_drain_resolves_the_reserved_and_keeps_the_open() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (reserved, mut reserved_outcome) = oneshot::channel();
		let (opened, mut opened_outcome) = oneshot::channel();
		let (mut body, forwarder, _notes) = body_fixture(1, 4);

		pending.reserve(reserved, Some(forwarder))?;

		let key = pending.reserve(opened, None)?;
		pending.open(key, 1)?;
		pending.drain();

		assert!(matches!(reserved_outcome.try_recv(), Ok(Some(StreamOutcome::Draining))));
		assert!(matches!(opened_outcome.try_recv(), Ok(None)));

		let ended = body.poll_chunk_now();
		assert!(matches!(ended, Poll::Ready(Err(TransportError::Draining))));
		assert_eq!(pending.open_load(), 1);
		Ok(())
	}

	#[test]
	fn test_open_after_close_is_refused() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (outcome, _receiver) = oneshot::channel();
		let key = pending.reserve(outcome, None)?;

		pending.close();

		let opened = pending.open(key, 1);
		assert!(matches!(opened, Err(TransportError::ConnectionClosed)));
		Ok(())
	}

	#[test]
	fn test_open_after_a_drain_is_refused() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (outcome, _receiver) = oneshot::channel();
		let key = pending.reserve(outcome, None)?;

		pending.drain();

		let opened = pending.open(key, 1);
		assert!(matches!(opened, Err(TransportError::Draining)));
		Ok(())
	}
}
