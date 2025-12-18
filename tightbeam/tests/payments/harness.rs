//! Payment Harness - Validation Components
//!
//! Re-implements patterns from zero_queue.rs locally for test isolation:
//! - DedupBook: Idempotence tracking using (frame.metadata.id, frame.metadata.order)
//! - ChainState: DAG validation for previous_frame linkage

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use sha3::Sha3_256;
use tightbeam::asn1::DigestInfo;
use tightbeam::trace::TraceCollector;
use tightbeam::{utils, Frame, TightBeamError};

use super::messages::TransactionStatus;

// ============================================================================
// Constants
// ============================================================================

pub const PAYMENT_TAG: &str = "payment";

// ============================================================================
// Helpers
// ============================================================================

/// Idempotency key type: (frame ID, frame order)
type IdempotencyKey = (Vec<u8>, u64);

/// Extract idempotency key from frame (DRY helper)
#[inline]
fn frame_key(frame: &Frame) -> IdempotencyKey {
	(frame.metadata.id.clone(), frame.metadata.order)
}

// ============================================================================
// DedupBook - Idempotence Tracking
// ============================================================================

type SeenSet = Arc<Mutex<BTreeSet<IdempotencyKey>>>;
type CacheMap = Arc<Mutex<std::collections::HashMap<IdempotencyKey, TransactionStatus>>>;

/// Deduplication book for idempotent payment processing
///
/// Uses Frame's (metadata.id, metadata.order) as the idempotency key.
/// Caches responses for duplicate detection.
#[derive(Clone)]
pub struct DedupBook {
	trace: Arc<TraceCollector>,
	seen: SeenSet,
	cache: CacheMap,
}

impl DedupBook {
	/// Create a new dedup book
	pub fn new(trace: Arc<TraceCollector>) -> Self {
		Self {
			trace,
			seen: Arc::new(Mutex::new(BTreeSet::new())),
			cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
		}
	}

	/// Record a frame and check if it's a duplicate
	///
	/// Returns Ok(true) if this is a new frame (should process)
	/// Returns Ok(false) if this is a duplicate (skip processing)
	pub fn record(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		let key = frame_key(frame);
		let mut guard = self.seen.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		let inserted = guard.insert(key);

		if inserted {
			self.trace.event_with("dedup_kept", &[PAYMENT_TAG], true)?;
		} else {
			self.trace.event_with("dedup_skipped", &[PAYMENT_TAG], true)?;
		}

		Ok(inserted)
	}

	/// Cache a response for a frame
	pub fn cache_response(&self, frame: &Frame, response: TransactionStatus) -> Result<(), TightBeamError> {
		let key = frame_key(frame);
		let mut guard = self.cache.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		guard.insert(key, response);
		Ok(())
	}

	/// Get cached response for a frame
	pub fn get_cached(&self, frame: &Frame) -> Option<TransactionStatus> {
		let key = frame_key(frame);
		let guard = self.cache.lock().ok()?;
		guard.get(&key).cloned()
	}
}

// ============================================================================
// ChainState - DAG Validation
// ============================================================================

/// Chain state for DAG validation
///
/// Validates that frames correctly link to their predecessors via previous_frame.
#[derive(Clone)]
pub struct ChainState {
	trace: Arc<TraceCollector>,
	state: Arc<Mutex<ChainInner>>,
}

struct ChainInner {
	last_order: Option<u64>,
	last_digest: Option<DigestInfo>,
}

impl ChainState {
	/// Create a new chain state
	pub fn new(trace: Arc<TraceCollector>) -> Self {
		Self {
			trace,
			state: Arc::new(Mutex::new(ChainInner { last_order: None, last_digest: None })),
		}
	}

	/// Record a frame and validate chain linkage
	pub fn record(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		let mut guard = self.state.lock().map_err(|_| TightBeamError::LockPoisoned)?;

		let expected = guard.last_digest.clone();
		let actual = frame.metadata.previous_frame.as_ref();

		// Validate previous frame linkage
		let prev_ok = match (expected.as_ref(), actual) {
			(None, None) => true, // First frame, no previous
			(Some(expected_digest), Some(actual_digest)) => {
				// Compare digests by algorithm and value
				expected_digest.algorithm == actual_digest.algorithm
					&& expected_digest.digest.as_bytes() == actual_digest.digest.as_bytes()
			}
			(None, Some(_)) => false, // Unexpected previous frame
			(Some(_), None) => false, // Missing expected previous frame
		};

		// Validate order is increasing
		let order_ok = guard.last_order.is_none_or(|prev| frame.metadata.order > prev);

		let valid = prev_ok && order_ok;

		if valid {
			self.trace.event_with("chain_valid", &[PAYMENT_TAG], true)?;
			guard.last_order = Some(frame.metadata.order);
			let digest = utils::digest::<Sha3_256>(&frame.message)?;
			guard.last_digest = Some(digest);
		} else {
			self.trace.event_with("chain_broken", &[PAYMENT_TAG], true)?;
		}

		Ok(valid)
	}

	/// Get the last digest for linking the next frame
	pub fn last_digest(&self) -> Option<DigestInfo> {
		let guard = self.state.lock().ok()?;
		guard.last_digest.clone()
	}

	/// Reset the chain state (for testing different chains)
	pub fn reset(&self) -> Result<(), TightBeamError> {
		let mut guard = self.state.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		guard.last_order = None;
		guard.last_digest = None;
		Ok(())
	}
}

// ============================================================================
// PaymentHarness - Combined Validation
// ============================================================================

/// Payment harness combining all validation components
#[derive(Clone)]
pub struct PaymentHarness {
	pub trace: Arc<TraceCollector>,
	pub dedup: DedupBook,
	pub chain: ChainState,
}

impl PaymentHarness {
	/// Create a new payment harness
	pub fn new(trace: Arc<TraceCollector>) -> Self {
		Self {
			dedup: DedupBook::new(Arc::clone(&trace)),
			chain: ChainState::new(Arc::clone(&trace)),
			trace,
		}
	}

	/// Handle an incoming frame with full validation
	///
	/// Returns Ok(true) if frame should be processed
	/// Returns Ok(false) if frame is duplicate (use cached response)
	pub fn handle(&self, frame: &Frame) -> Result<bool, TightBeamError> {
		// Check for duplicates first
		if !self.dedup.record(frame)? {
			return Ok(false);
		}

		// Validate chain linkage
		self.chain.record(frame)?;

		Ok(true)
	}

	/// Check if frame is duplicate and return cached response if available
	///
	/// Returns Ok(Some(cached)) if duplicate with cached response
	/// Returns Ok(None) if not duplicate or no cached response
	/// Emits dedup_cache_hit trace event on cache hit
	pub fn check_dedup_cache(&self, frame: &Frame) -> Result<Option<TransactionStatus>, TightBeamError> {
		if !self.handle(frame)? {
			if let Some(cached) = self.dedup.get_cached(frame) {
				self.trace.event_with("dedup_cache_hit", &[PAYMENT_TAG], true)?;
				return Ok(Some(cached));
			}
		}
		Ok(None)
	}
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use tightbeam::asn1::{Metadata, Version};

	fn test_frame(id: &[u8], order: u64) -> Frame {
		let mut metadata = Metadata::default();
		metadata.id = id.to_vec();
		metadata.order = order;
		Frame {
			version: Version::V2,
			metadata,
			message: vec![1, 2, 3],
			integrity: None,
			nonrepudiation: None,
		}
	}

	#[test]
	fn dedup_first_frame_accepted() {
		let trace = Arc::new(TraceCollector::default());
		let dedup = DedupBook::new(trace);
		let frame = test_frame(b"txn1", 1);

		let result = dedup.record(&frame);
		assert!(result.is_ok());
		assert!(result.unwrap());
	}

	#[test]
	fn dedup_duplicate_rejected() {
		let trace = Arc::new(TraceCollector::default());
		let dedup = DedupBook::new(trace);
		let frame = test_frame(b"txn1", 1);

		let _ = dedup.record(&frame);
		let result = dedup.record(&frame);
		assert!(result.is_ok());
		assert!(!result.unwrap());
	}

	#[test]
	fn dedup_different_order_accepted() {
		let trace = Arc::new(TraceCollector::default());
		let dedup = DedupBook::new(trace);
		let frame1 = test_frame(b"txn1", 1);
		let frame2 = test_frame(b"txn1", 2);

		let _ = dedup.record(&frame1);
		let result = dedup.record(&frame2);
		assert!(result.is_ok());
		assert!(result.unwrap());
	}
}
