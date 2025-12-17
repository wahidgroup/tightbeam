//! Payment Harness - Validation Components
//!
//! Re-implements patterns from zero_queue.rs locally for test isolation:
//! - DedupBook: Idempotence tracking using (frame.metadata.id, frame.metadata.order)
//! - ChainState: DAG validation for previous_frame linkage
//! - ProcessorGate: AdaptiveGate for backpressure simulation

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use sha3::Sha3_256;
use tightbeam::asn1::DigestInfo;
use tightbeam::policy::{GatePolicy, TransitStatus};
use tightbeam::trace::TraceCollector;
use tightbeam::{utils, Frame, TightBeamError};

use super::messages::TransactionStatus;

// ============================================================================
// Constants
// ============================================================================

pub const PAYMENT_TAG: &str = "payment";
pub const AUTH_TAG: &str = "auth";
pub const CAPTURE_TAG: &str = "capture";
pub const PROCESSOR_1_TAG: &str = "processor:1";
pub const PROCESSOR_2_TAG: &str = "processor:2";
pub const PROCESSOR_3_TAG: &str = "processor:3";

// ============================================================================
// DedupBook - Idempotence Tracking
// ============================================================================

type SeenSet = Arc<Mutex<BTreeSet<(Vec<u8>, u64)>>>;
type CacheMap = Arc<Mutex<std::collections::HashMap<(Vec<u8>, u64), TransactionStatus>>>;

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
		let key = (frame.metadata.id.clone(), frame.metadata.order);
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
		let key = (frame.metadata.id.clone(), frame.metadata.order);
		let mut guard = self.cache.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		guard.insert(key, response);
		Ok(())
	}

	/// Get cached response for a frame
	pub fn get_cached(&self, frame: &Frame) -> Option<TransactionStatus> {
		let key = (frame.metadata.id.clone(), frame.metadata.order);
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
// ProcessorGate - Adaptive Backpressure
// ============================================================================

/// Backpressure statistics for throttling simulation
#[derive(Clone, Default)]
pub struct BackpressureStats {
	/// Set of frame orders that have been throttled
	throttled: Arc<Mutex<BTreeSet<u64>>>,
	/// Whether the processor is in failure mode
	failure_mode: Arc<Mutex<bool>>,
}

impl BackpressureStats {
	/// Mark a frame as throttled (returns true if first time)
	pub fn mark_throttled(&self, order: u64) -> bool {
		let mut guard = match self.throttled.lock() {
			Ok(g) => g,
			Err(_) => return false,
		};
		if guard.contains(&order) {
			false
		} else {
			guard.insert(order);
			true
		}
	}

	/// Set failure mode (simulate processor failure)
	pub fn set_failure_mode(&self, enabled: bool) {
		if let Ok(mut guard) = self.failure_mode.lock() {
			*guard = enabled;
		}
	}

	/// Check if in failure mode
	pub fn is_failure_mode(&self) -> bool {
		self.failure_mode.lock().map(|g| *g).unwrap_or(false)
	}
}

/// Adaptive gate for processor backpressure
///
/// Simulates processor overload by rejecting frames with Busy status.
/// First encounter of a frame is throttled; subsequent attempts are accepted.
#[derive(Clone)]
pub struct ProcessorGate {
	stats: Arc<BackpressureStats>,
	trace: Arc<TraceCollector>,
}

impl ProcessorGate {
	/// Create a new processor gate
	pub fn new(stats: Arc<BackpressureStats>, trace: Arc<TraceCollector>) -> Self {
		Self { stats, trace }
	}
}

impl GatePolicy for ProcessorGate {
	fn evaluate(&self, frame: &Frame) -> TransitStatus {
		// If in failure mode, always reject
		if self.stats.is_failure_mode() {
			let _ = self.trace.event_with("throttle_engaged", &[PAYMENT_TAG], true);
			return TransitStatus::Busy;
		}

		// Throttle on first encounter, accept on retry
		if self.stats.mark_throttled(frame.metadata.order) {
			let _ = self.trace.event_with("throttle_engaged", &[PAYMENT_TAG], true);
			TransitStatus::Busy
		} else {
			let _ = self.trace.event_with("retry_with_jitter", &[PAYMENT_TAG], true);
			TransitStatus::Accepted
		}
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

	#[test]
	fn backpressure_first_throttled() {
		let stats = Arc::new(BackpressureStats::default());
		let trace = Arc::new(TraceCollector::default());
		let gate = ProcessorGate::new(stats, trace);
		let frame = test_frame(b"txn1", 1);

		assert_eq!(gate.evaluate(&frame), TransitStatus::Busy);
	}

	#[test]
	fn backpressure_retry_accepted() {
		let stats = Arc::new(BackpressureStats::default());
		let trace = Arc::new(TraceCollector::default());
		let gate = ProcessorGate::new(stats, trace);
		let frame = test_frame(b"txn1", 1);

		gate.evaluate(&frame); // First: throttled
		assert_eq!(gate.evaluate(&frame), TransitStatus::Accepted); // Retry: accepted
	}

	#[test]
	fn failure_mode_always_busy() {
		let stats = Arc::new(BackpressureStats::default());
		stats.set_failure_mode(true);
		let trace = Arc::new(TraceCollector::default());
		let gate = ProcessorGate::new(stats, trace);
		let frame = test_frame(b"txn1", 1);

		assert_eq!(gate.evaluate(&frame), TransitStatus::Busy);
		assert_eq!(gate.evaluate(&frame), TransitStatus::Busy); // Still busy
	}
}
