//! The replies a connection still awaits: its open streams and its pings.

use std::collections::BTreeMap;

use futures::channel::oneshot;

use super::shared::StreamOutcome;
use crate::transport::{TransportError, TransportResult};

/// Open locally-initiated streams and local pings, each held until its answer
/// arrives or its caller gives it up.
///
/// Every answer arrives through the reader. [`Self::close`] records that it
/// has ended, and the two `admit` methods are the only inserts, so no slot
/// registers on a connection that cannot answer it.
#[derive(Default)]
pub struct PendingReplies {
	/// Open streams awaiting their response, keyed by stream ID.
	streams: BTreeMap<u32, oneshot::Sender<StreamOutcome>>,
	/// Pings awaiting their ack, keyed by correlation value.
	pings: BTreeMap<u64, oneshot::Sender<()>>,
	/// Whether the reader has ended. Nothing clears it.
	closed: bool,
}

impl PendingReplies {
	/// Whether the reader has ended, so that no slot can be resolved.
	pub fn is_closed(&self) -> bool {
		self.closed
	}

	/// Count the streams awaiting their response.
	pub fn stream_count(&self) -> usize {
		self.streams.len()
	}

	/// Whether `stream_id` is awaiting its response.
	pub fn holds_stream(&self, stream_id: u32) -> bool {
		self.streams.contains_key(&stream_id)
	}

	/// Hold `sender` until the response of `stream_id` arrives.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the reader has ended.
	pub fn admit_stream(&mut self, stream_id: u32, sender: oneshot::Sender<StreamOutcome>) -> TransportResult<()> {
		if self.closed {
			return Err(TransportError::ConnectionClosed);
		}

		self.streams.insert(stream_id, sender);

		Ok(())
	}

	/// Hold `sender` until the ack of the ping `opaque` arrives.
	///
	/// # Errors
	///
	/// - [`TransportError::ConnectionClosed`] -- the reader has ended.
	pub fn admit_ping(&mut self, opaque: u64, sender: oneshot::Sender<()>) -> TransportResult<()> {
		if self.closed {
			return Err(TransportError::ConnectionClosed);
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
	/// cancellation.
	pub fn close(&mut self) {
		self.closed = true;
		self.streams.clear();
		self.pings.clear();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn closed() -> PendingReplies {
		let mut pending = PendingReplies::default();
		pending.close();
		pending
	}

	#[test]
	fn test_stream_refused_once_closed() {
		let (sender, _receiver) = oneshot::channel();
		let admitted = closed().admit_stream(1, sender);
		assert!(matches!(admitted, Err(TransportError::ConnectionClosed)));
	}

	#[test]
	fn test_ping_refused_once_closed() {
		let (sender, _receiver) = oneshot::channel();
		let admitted = closed().admit_ping(0, sender);
		assert!(matches!(admitted, Err(TransportError::ConnectionClosed)));
	}

	#[test]
	fn test_close_cancels_every_slot() -> TransportResult<()> {
		let mut pending = PendingReplies::default();
		let (stream, mut outcome) = oneshot::channel();
		let (ping, mut ack) = oneshot::channel();
		pending.admit_stream(1, stream)?;
		pending.admit_ping(0, ping)?;

		pending.close();
		assert!(outcome.try_recv().is_err());
		assert!(ack.try_recv().is_err());
		Ok(())
	}
}
