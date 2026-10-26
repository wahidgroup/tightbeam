//! The validation components of the payment harness.
//!
//! The harness keeps a local copy of the `zero_queue.rs` patterns for test
//! isolation:
//! - `DedupBook` tracks idempotence by `(frame.metadata.id, frame.metadata.order)`.
//! - `ChainState` validates the DAG of `previous_frame` links.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use sha3::Sha3_256;
use tightbeam::asn1::DigestInfo;
use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::{utils, Frame, TightBeamError};

use super::messages::TransactionStatus;

pub(crate) const CHAIN_BROKEN: Urn<'static> = tightbeam::urn!("test", "event:harness/chain-broken");
pub(crate) const CHAIN_VALID: Urn<'static> = tightbeam::urn!("test", "event:harness/chain-valid");
pub(crate) const DEDUP_CACHE_HIT: Urn<'static> = tightbeam::urn!("test", "event:harness/dedup-cache-hit");
pub(crate) const DEDUP_KEPT: Urn<'static> = tightbeam::urn!("test", "event:harness/dedup-kept");
pub(crate) const DEDUP_SKIPPED: Urn<'static> = tightbeam::urn!("test", "event:harness/dedup-skipped");

// The tag of every payment event.

pub const PAYMENT_TAG: &str = "payment";

// Each component keys a frame by the same idempotency key.

/// The idempotency key of a frame: its ID and its order.
type IdempotencyKey = (Vec<u8>, u64);

/// Returns the idempotency key of `frame`, which both components share.
#[inline]
fn frame_key(frame: &Frame) -> IdempotencyKey {
	(frame.metadata().id().to_owned(), frame.metadata().order())
}

// The dedup book tracks idempotence.

type SeenSet = Arc<Mutex<BTreeSet<IdempotencyKey>>>;
type CacheMap = Arc<Mutex<std::collections::HashMap<IdempotencyKey, TransactionStatus>>>;

/// The deduplication book of idempotent payment processing.
///
/// The book keys each frame by `(metadata.id, metadata.order)`, and it caches
/// a response per key for duplicate detection.
#[derive(Clone, Default)]
pub struct DedupBook {
	seen: SeenSet,
	cache: CacheMap,
}

impl DedupBook {
	/// Records `frame` and reports whether it is new.
	///
	/// - `Ok(true)` when the frame is new, so the caller processes it.
	/// - `Ok(false)` when the frame is a duplicate, so the caller skips it.
	pub fn record(&self, frame: &Frame, trace: &TraceCollector) -> Result<bool, TightBeamError> {
		let key = frame_key(frame);
		let mut guard = self.seen.lock().map_err(|_| TightBeamError::LockPoisoned)?;

		let inserted = guard.insert(key);
		if inserted {
			trace.event_with(DEDUP_KEPT, &[PAYMENT_TAG], ())?;
		} else {
			trace.event_with(DEDUP_SKIPPED, &[PAYMENT_TAG], ())?;
		}

		Ok(inserted)
	}

	/// Caches `response` as the reply to `frame`.
	pub fn cache_response(&self, frame: &Frame, response: TransactionStatus) -> Result<(), TightBeamError> {
		let key = frame_key(frame);
		let mut guard = self.cache.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		guard.insert(key, response);

		Ok(())
	}

	/// Returns the response cached for `frame`, if the book holds one.
	pub fn get_cached(&self, frame: &Frame) -> Option<TransactionStatus> {
		let key = frame_key(frame);
		let guard = self.cache.lock().ok()?;
		guard.get(&key).cloned()
	}
}

// The chain state validates the frame DAG.

/// The chain state of DAG validation.
///
/// It validates that each frame links to its predecessor through
/// `previous_frame` and carries a higher order than that predecessor.
#[derive(Clone, Default)]
pub struct ChainState {
	state: Arc<Mutex<ChainInner>>,
}

#[derive(Default)]
struct ChainInner {
	last_order: Option<u64>,
	last_digest: Option<DigestInfo>,
}

impl ChainState {
	/// Records `frame` when it extends the chain, and returns whether it does.
	pub fn record(&self, frame: &Frame, trace: &TraceCollector) -> Result<bool, TightBeamError> {
		let mut guard = self.state.lock().map_err(|_| TightBeamError::LockPoisoned)?;

		let expected = guard.last_digest.to_owned();
		let actual = frame.metadata().previous_frame();

		let prev_ok = match (expected.as_ref(), actual) {
			(None, None) => true, // First frame, no previous
			(Some(expected_digest), Some(actual_digest)) => {
				expected_digest.algorithm == actual_digest.algorithm
					&& expected_digest.digest.as_bytes() == actual_digest.digest.as_bytes()
			}
			(None, Some(_)) => false, // Unexpected previous frame
			(Some(_), None) => false, // Missing expected previous frame
		};

		let order_ok = guard.last_order.is_none_or(|prev| frame.metadata().order() > prev);
		let valid = prev_ok && order_ok;
		if valid {
			trace.event_with(CHAIN_VALID, &[PAYMENT_TAG], ())?;

			guard.last_order = Some(frame.metadata().order());

			let digest = utils::digest::<Sha3_256>(frame.message())?;
			guard.last_digest = Some(digest);
		} else {
			trace.event_with(CHAIN_BROKEN, &[PAYMENT_TAG], ())?;
		}

		Ok(valid)
	}

	/// Returns the digest that the next frame links to.
	#[allow(dead_code)]
	pub fn last_digest(&self) -> Option<DigestInfo> {
		let guard = self.state.lock().ok()?;
		guard.last_digest.to_owned()
	}

	/// Resets the chain state, so a test can start a different chain.
	#[allow(dead_code)]
	pub fn reset(&self) -> Result<(), TightBeamError> {
		let mut guard = self.state.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		guard.last_order = None;
		guard.last_digest = None;
		Ok(())
	}
}

// The payment harness combines both validations.

/// The payment harness, which combines the dedup book and the chain state.
///
/// The servlets of one payment flow share one harness as their environment,
/// so the dedup book and the chain state span every frame of the flow.
#[derive(Clone, Default)]
pub struct PaymentHarness {
	/// The book of the frames the flow has seen, with the reply to each.
	pub dedup: DedupBook,
	/// The chain of the frames of the flow, each linked to the one before.
	pub chain: ChainState,
}

impl PaymentHarness {
	/// Runs both validations on an incoming frame.
	///
	/// - `Ok(true)` when the frame is new, so the caller processes it.
	/// - `Ok(false)` when the frame is a duplicate, so the caller uses the cached response.
	pub fn handle(&self, frame: &Frame, trace: &TraceCollector) -> Result<bool, TightBeamError> {
		// A duplicate returns before the chain check, so a replay leaves the
		// chain intact.
		if !self.dedup.record(frame, trace)? {
			return Ok(false);
		}

		self.chain.record(frame, trace)?;

		Ok(true)
	}

	/// Checks whether `frame` is a duplicate, and returns its cached response.
	///
	/// - `Ok(Some(cached))` when the frame is a duplicate with a cached response.
	///   The cache hit emits the `DEDUP_CACHE_HIT` trace event.
	/// - `Ok(None)` when the frame is new or has no cached response.
	pub fn check_dedup_cache(
		&self,
		frame: &Frame,
		trace: &TraceCollector,
	) -> Result<Option<TransactionStatus>, TightBeamError> {
		if !self.handle(frame, trace)? {
			if let Some(cached) = self.dedup.get_cached(frame) {
				trace.event_with(DEDUP_CACHE_HIT, &[PAYMENT_TAG], ())?;
				return Ok(Some(cached));
			}
		}
		Ok(None)
	}
}

// The unit tests of the dedup book.

#[cfg(test)]
mod tests {
	use super::*;
	use tightbeam::asn1::Version;
	use tightbeam::builder::TypeBuilder;
	use tightbeam::testing::TestMessage;

	fn test_frame(id: impl AsRef<[u8]>, order: u64) -> Frame {
		let id = id.as_ref();
		Version::V2
			.compose()
			.with_id(id)
			.with_order(order)
			.with_message(TestMessage::sample(None))
			.build()
			.expect("a V2 frame with an id and an order builds")
	}

	#[test]
	fn dedup_first_frame_accepted() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::default();
		let frame = test_frame(b"txn1", 1);

		let result = dedup.record(&frame, &trace);
		assert!(result.is_ok());
		assert!(result?);
		Ok(())
	}

	#[test]
	fn dedup_duplicate_rejected() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::default();
		let frame = test_frame(b"txn1", 1);

		dedup.record(&frame, &trace)?;

		let result = dedup.record(&frame, &trace);
		assert!(result.is_ok());
		assert!(!result?);
		Ok(())
	}

	#[test]
	fn dedup_different_order_accepted() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::default();
		let frame1 = test_frame(b"txn1", 1);
		let frame2 = test_frame(b"txn1", 2);

		dedup.record(&frame1, &trace)?;

		let result = dedup.record(&frame2, &trace);
		assert!(result.is_ok());
		assert!(result?);
		Ok(())
	}
}
