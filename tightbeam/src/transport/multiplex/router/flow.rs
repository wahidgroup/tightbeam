//! Flow-control arithmetic and the receiver-side credit policy.

use crate::constants::DEFAULT_MUX_STREAM_CREDIT;
use crate::transport::multiplex::StreamId;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::constants::DEFAULT_REKEY_RENEWAL_ALLOWANCE;

pub(super) fn cap_as_usize(cap: u32) -> usize {
	usize::try_from(cap).unwrap_or(usize::MAX)
}

pub(super) fn len_as_u64(len: usize) -> u64 {
	u64::try_from(len).unwrap_or(u64::MAX)
}

/// Chunk records a payload occupies at `chunk_size` bytes per chunk.
/// An empty payload travels inline in its trailer and occupies none.
pub(super) fn chunk_records(payload_len: usize, chunk_size: usize) -> u64 {
	len_as_u64(payload_len).div_ceil(len_as_u64(chunk_size.max(1)))
}

/// Session-budget credits a payload debits: `ceil(len / credit_unit)`
/// summed per chunk, so the sender's whole-frame debit equals the sum
/// of the receiver's per-chunk debits.
pub(super) fn payload_credits(payload_len: usize, chunk_size: usize, credit_unit: u32) -> u64 {
	let chunk_size = len_as_u64(chunk_size.max(1));
	let unit = u64::from(credit_unit.max(1));
	let len = len_as_u64(payload_len);

	let full_chunks = len / chunk_size;
	let remainder = len % chunk_size;
	let per_full_chunk = chunk_size.div_ceil(unit);

	full_chunks
		.saturating_mul(per_full_chunk)
		.saturating_add(remainder.div_ceil(unit))
}

/// Send records at which a renewal opens: the dynamic drain floor
/// plus fixed slack so the exchange legs land before the drain
/// threshold would trip ([`DEFAULT_REKEY_RENEWAL_ALLOWANCE`]).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(super) fn renewal_floor(drain_floor: u64) -> u64 {
	drain_floor.saturating_add(DEFAULT_REKEY_RENEWAL_ALLOWANCE)
}

/// Receiver-side stream credit policy: decides when to raise a
/// stream's absolute cumulative chunk limit (QUIC MAX_STREAM_DATA analog,
/// [RFC 9000 § 4.1](https://datatracker.ietf.org/doc/html/rfc9000#section-4.1)).
///
/// The receiver's granted limit bounds per-stream reassembly memory
/// at `limit * chunk size`. Withholding grants applies backpressure
/// to the sender, which parks until the limit rises.
///
/// Every grant travels as one `MuxCredit` envelope. It is a control-plane
/// AEAD record outside the session budget, so implementations SHOULD batch
/// grants rather than raise the limit per chunk, or a long transfer spends
/// the cipher's record limit on control traffic.
pub trait CreditGrantor: Send + Sync {
	/// New absolute chunk limit for a stream that has accepted
	/// `received` chunks under `limit`, or `None` to leave the limit
	/// unchanged. Values at or below `limit` are discarded.
	fn replenish(&self, stream_id: StreamId, received: u64, limit: u64) -> Option<u64>;
}

/// Default grantor: replenishes a fixed chunk window in batches,
/// bounding per-stream reassembly memory at `window * chunk size`
/// while letting frames of any length flow.
///
/// Grants fire only once remaining credit falls to the half-window
/// low-water mark, then top the limit back up to a full window ahead
/// of arrival. One `MuxCredit` record therefore covers about half a
/// window of data chunks, keeping control-plane AEAD record
/// consumption at `O(chunks / window)`.
pub struct BufferedGrantor {
	window: u64,
}

impl BufferedGrantor {
	/// Grantor keeping `window` chunks (at least one) of credit open.
	pub fn new(window: u64) -> Self {
		Self { window: window.max(1) }
	}
}

impl Default for BufferedGrantor {
	fn default() -> Self {
		Self::new(DEFAULT_MUX_STREAM_CREDIT)
	}
}

impl CreditGrantor for BufferedGrantor {
	fn replenish(&self, _stream_id: StreamId, received: u64, limit: u64) -> Option<u64> {
		let remaining = limit.saturating_sub(received);
		let low_water = (self.window / 2).max(1);
		if remaining > low_water {
			return None;
		}

		let target = received.saturating_add(self.window);
		if target > limit {
			return Some(target);
		}

		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	use crate::transport::handshake::negotiation::MuxSettings;

	#[test]
	fn test_chunk_records_boundaries() {
		for (len, chunk, expect) in [
			(0usize, 1024usize, 0u64),
			(1, 1024, 1),
			(1023, 1024, 1),
			(1024, 1024, 1),
			(2048, 1024, 2),
			(2049, 1024, 3),
		] {
			assert_eq!(chunk_records(len, chunk), expect);
		}
	}

	#[test]
	fn test_payload_credits_match_per_chunk_sum() {
		for (len, chunk, unit, expect) in [
			(0usize, 1024usize, 1000u32, 0u64),
			(100, 1024, 1000, 1),
			(1024, 1024, 1024, 1),
			(2048, 1024, 512, 4),
			// Sender's whole-frame debit equals the receiver's
			// per-chunk sum, not the naive whole-frame ceil (3)
			(2500, 1024, 1000, 5),
		] {
			assert_eq!(payload_credits(len, chunk, unit), expect);
		}
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_renewal_floor_adds_exchange_allowance() {
		use crate::constants::DEFAULT_REKEY_RENEWAL_ALLOWANCE;

		assert_eq!(renewal_floor(0), DEFAULT_REKEY_RENEWAL_ALLOWANCE);

		let drain_floor = MuxSettings::symmetric(4).drain_reserve_records();
		assert_eq!(renewal_floor(drain_floor), drain_floor + DEFAULT_REKEY_RENEWAL_ALLOWANCE);
		assert_eq!(renewal_floor(u64::MAX), u64::MAX);
	}

	#[test]
	fn test_buffered_grantor_batches_at_low_water() {
		let grantor = BufferedGrantor::new(4);
		// Above the half-window low-water mark: no grant
		assert_eq!(grantor.replenish(StreamId::new(1), 0, 4), None);
		assert_eq!(grantor.replenish(StreamId::new(1), 1, 4), None);
		assert_eq!(grantor.replenish(StreamId::new(1), 3, 8), None);
		// At the low-water mark: top back up to a full window ahead
		assert_eq!(grantor.replenish(StreamId::new(1), 2, 4), Some(6));
		assert_eq!(grantor.replenish(StreamId::new(1), 6, 8), Some(10));
	}

	#[test]
	fn test_buffered_grantor_single_chunk_window() {
		let grantor = BufferedGrantor::new(1);
		// A grant to limit itself would not raise it: stay silent
		assert_eq!(grantor.replenish(StreamId::new(1), 3, 4), None);
		// Fully consumed: open the next chunk
		assert_eq!(grantor.replenish(StreamId::new(1), 4, 4), Some(5));
	}
}
