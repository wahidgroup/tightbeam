//! Flow-control arithmetic and the receiver-side credit policy.

use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

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

/// The count of bytes that one mux chunk carries.
///
/// A payload length and a chunk size are both byte counts, so two loose values
/// can swap, compile, and invert the credit arithmetic. The chunk size is its
/// own type, and it applies the floor of one for every call site.
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

	/// The number of chunk records that a payload occupies at this chunk size.
	/// An empty payload travels inline in its trailer and occupies none.
	#[must_use]
	pub fn records(self, payload_len: usize) -> u64 {
		len_as_u64(payload_len).div_ceil(self.width().get())
	}

	/// The session-budget credits that a payload debits, which are
	/// `ceil(len / credit_unit)` summed per chunk, so the sender's whole-frame
	/// debit equals the sum of the receiver's per-chunk debits.
	#[must_use]
	pub fn credits(self, payload_len: usize, credit_unit: NonZeroU32) -> u64 {
		let chunk_size = self.width();
		let unit = u64::from(credit_unit.get());
		let len = len_as_u64(payload_len);

		let full_chunks = len / chunk_size;
		let remainder = len % chunk_size;
		let per_full_chunk = chunk_size.get().div_ceil(unit);

		full_chunks
			.saturating_mul(per_full_chunk)
			.saturating_add(remainder.div_ceil(unit))
	}
}

/// The count of send records at which a renewal opens: the dynamic drain
/// floor plus a fixed slack, so the exchange legs land before the drain
/// threshold would trip ([`DEFAULT_REKEY_RENEWAL_ALLOWANCE`]).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub fn renewal_floor(drain_floor: u64) -> u64 {
	drain_floor.saturating_add(DEFAULT_REKEY_RENEWAL_ALLOWANCE)
}

/// The default grantor, which replenishes a fixed chunk window in batches. It
/// bounds the reassembly memory of each stream at `window * chunk size` and
/// lets frames of any length flow.
///
/// # Low-water mark
///
/// A grant fires when the remaining credit falls to half the window, and it
/// tops the limit up to a full window ahead of arrival. One `MuxCredit` record
/// covers about half a window of data chunks, so the control plane spends AEAD
/// records at `O(chunks / window)`.
pub struct BufferedGrantor {
	window: u64,
}

impl BufferedGrantor {
	/// Creates a grantor whose credit window is `window` chunks, at least one.
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

	// A payload takes one record per chunk it starts. Each case is (payload
	// length, chunk size, records).
	crate::tb_cases! {
		fn a_payload_takes_one_record_per_chunk_it_starts((len, chunk, expect): (usize, usize, u64)) {
			assert_eq!(ChunkSize::new(chunk).records(len), expect);
		}
		cases {
			empty => (0, 1024, 0),
			one_octet => (1, 1024, 1),
			one_short_of_a_chunk => (1023, 1024, 1),
			one_chunk => (1024, 1024, 1),
			two_chunks => (2048, 1024, 2),
			one_past_two_chunks => (2049, 1024, 3),
		}
	}

	/// A credit unit of `bytes`, which is at least one byte.
	fn credit_unit(bytes: u32) -> NonZeroU32 {
		NonZeroU32::new(bytes).expect("a credit unit holds at least one byte")
	}

	// Each case is (payload length, chunk size, credit unit, credits). The
	// sender's whole-frame debit equals the receiver's per-chunk sum, and not
	// the naive whole-frame ceil (3 for the last case).
	crate::tb_cases! {
		fn the_credits_of_a_payload_match_its_per_chunk_sum(
			(len, chunk, unit, expect): (usize, usize, NonZeroU32, u64)
		) {
			assert_eq!(ChunkSize::new(chunk).credits(len, unit), expect);
		}
		cases {
			empty => (0, 1024, credit_unit(1000), 0),
			under_one_unit => (100, 1024, credit_unit(1000), 1),
			one_chunk_of_one_unit => (1024, 1024, credit_unit(1024), 1),
			two_chunks_of_two_units => (2048, 1024, credit_unit(512), 4),
			three_chunks_past_their_units => (2500, 1024, credit_unit(1000), 5),
		}
	}

	// The renewal floor adds the exchange allowance to the drain floor, and
	// saturates at the top of the range. Each case is (drain floor, renewal
	// floor).
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	crate::tb_cases! {
		fn the_renewal_floor_adds_the_exchange_allowance((drain_floor, expected): (u64, u64)) {
			assert_eq!(renewal_floor(drain_floor), expected);
		}
		cases {
			zero => (0, crate::constants::DEFAULT_REKEY_RENEWAL_ALLOWANCE),
			the_drain_floor => (
				MuxSettings::symmetric(4).drain_reserve_records(),
				MuxSettings::symmetric(4).drain_reserve_records() + crate::constants::DEFAULT_REKEY_RENEWAL_ALLOWANCE,
			),
			saturates => (u64::MAX, u64::MAX),
		}
	}

	// A buffered grantor grants at its half-window low-water mark, topping
	// back up to a full window ahead, and fires no grant above the mark or at
	// a grant that would not raise the limit. Each case is (window, consumed,
	// limit, grant).
	crate::tb_cases! {
		fn a_buffered_grantor_grants_at_low_water((window, consumed, limit, expected): (u64, u64, u64, Option<u64>)) {
			let grantor = BufferedGrantor::new(window);
			assert_eq!(grantor.replenish(StreamId::new(1), consumed, limit), expected);
		}
		cases {
			nothing_consumed => (4, 0, 4, None),
			above_the_mark => (4, 1, 4, None),
			above_the_mark_of_a_raised_limit => (4, 3, 8, None),
			at_the_mark => (4, 2, 4, Some(6)),
			at_the_mark_of_a_raised_limit => (4, 6, 8, Some(10)),
			a_one_chunk_window_short_of_its_limit => (1, 3, 4, None),
			a_one_chunk_window_fully_consumed => (1, 4, 4, Some(5)),
		}
	}
}
