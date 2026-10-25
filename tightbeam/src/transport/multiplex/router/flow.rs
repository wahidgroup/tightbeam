//! Flow-control arithmetic and the receiver-side credit policy.

use core::num::{NonZeroU64, NonZeroUsize};

use crate::constants::DEFAULT_MUX_STREAM_CREDIT;
use crate::transport::multiplex::{CreditGrantor, StreamId};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::constants::DEFAULT_REKEY_RENEWAL_ALLOWANCE;

pub fn cap_as_usize(cap: u32) -> usize {
	usize::try_from(cap).unwrap_or(usize::MAX)
}

pub fn len_as_u64(len: usize) -> u64 {
	u64::try_from(len).unwrap_or(u64::MAX)
}

/// Bytes carried per mux chunk.
///
/// A payload length and a chunk size are both byte counts, so a call site
/// that holds them loose can swap them and still compile while the credit
/// arithmetic silently inverts. The chunk size therefore travels as its own
/// type, which applies the floor of one once for every call site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkSize(NonZeroUsize);

impl ChunkSize {
	/// The chunk size for one direction of a link, floored at one byte.
	#[must_use]
	pub fn new(bytes: usize) -> Self {
		Self(NonZeroUsize::new(bytes).unwrap_or(NonZeroUsize::MIN))
	}

	/// The size in bytes, for arithmetic that needs the count.
	#[must_use]
	pub fn get(self) -> usize {
		self.0.get()
	}

	/// The size in bytes as the `u64` the credit arithmetic divides by.
	fn width(self) -> NonZeroU64 {
		NonZeroU64::try_from(self.0).unwrap_or(NonZeroU64::MAX)
	}

	/// Chunk records a payload occupies at this many bytes per chunk.
	/// An empty payload travels inline in its trailer and occupies none.
	#[must_use]
	pub fn records(self, payload_len: usize) -> u64 {
		len_as_u64(payload_len).div_ceil(self.width().get())
	}

	/// Session-budget credits a payload debits: `ceil(len / credit_unit)`
	/// summed per chunk, so the sender's whole-frame debit equals the sum
	/// of the receiver's per-chunk debits.
	#[must_use]
	pub fn credits(self, payload_len: usize, credit_unit: u32) -> u64 {
		let chunk_size = self.width();
		let unit = u64::from(credit_unit.max(1));
		let len = len_as_u64(payload_len);

		let full_chunks = len / chunk_size;
		let remainder = len % chunk_size;
		let per_full_chunk = chunk_size.get().div_ceil(unit);

		full_chunks
			.saturating_mul(per_full_chunk)
			.saturating_add(remainder.div_ceil(unit))
	}
}

/// Send records at which a renewal opens: the dynamic drain floor
/// plus a fixed slack, so the exchange legs land before the drain
/// threshold would trip ([`DEFAULT_REKEY_RENEWAL_ALLOWANCE`]).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn renewal_floor(drain_floor: u64) -> u64 {
	drain_floor.saturating_add(DEFAULT_REKEY_RENEWAL_ALLOWANCE)
}

/// Default grantor, which replenishes a fixed chunk window in batches.
/// It bounds per-stream reassembly memory at `window * chunk size` and
/// lets frames of any length flow.
///
/// # Low-water mark
///
/// Grants fire only once remaining credit falls to the half-window
/// low-water mark, then top the limit back up to a full window ahead
/// of arrival. One `MuxCredit` record therefore covers about half a
/// window of data chunks, so control-plane AEAD record consumption
/// stays at `O(chunks / window)`.
pub struct BufferedGrantor {
	window: u64,
}

impl BufferedGrantor {
	/// Grantor that keeps `window` chunks (at least one) of credit open.
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

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
			assert_eq!(ChunkSize::new(chunk).records(len), expect);
		}
	}

	#[test]
	fn test_payload_credits_match_per_chunk_sum() {
		for (len, chunk, unit, expect) in [
			(0usize, 1024usize, 1000u32, 0u64),
			(100, 1024, 1000, 1),
			(1024, 1024, 1024, 1),
			(2048, 1024, 512, 4),
			// The sender's whole-frame debit equals the receiver's
			// per-chunk sum, and not the naive whole-frame ceil (3).
			(2500, 1024, 1000, 5),
		] {
			assert_eq!(ChunkSize::new(chunk).credits(len, unit), expect);
		}
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
		// Above the half-window low-water mark, no grant fires.
		assert_eq!(grantor.replenish(StreamId::new(1), 0, 4), None);
		assert_eq!(grantor.replenish(StreamId::new(1), 1, 4), None);
		assert_eq!(grantor.replenish(StreamId::new(1), 3, 8), None);
		// At the low-water mark, the grant tops back up to a full window ahead.
		assert_eq!(grantor.replenish(StreamId::new(1), 2, 4), Some(6));
		assert_eq!(grantor.replenish(StreamId::new(1), 6, 8), Some(10));
	}

	#[test]
	fn test_buffered_grantor_single_chunk_window() {
		let grantor = BufferedGrantor::new(1);
		// A grant to the limit itself would not raise it, so none fires.
		assert_eq!(grantor.replenish(StreamId::new(1), 3, 4), None);
		// A fully consumed window opens the next chunk.
		assert_eq!(grantor.replenish(StreamId::new(1), 4, 4), Some(5));
	}
}
