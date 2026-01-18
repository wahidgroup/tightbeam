//! Latency and utilization tracking for servlets

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::utils::BasisPoints;

/// Lightweight metrics exposed by each servlet instance for auto-scaling
///
/// Used by hives to calculate utilization and make scaling decisions.
/// Metrics are updated atomically for thread-safe concurrent access.
#[derive(Debug, Default)]
pub struct ServletMetrics {
	/// Current pending messages in queue
	queue_depth: AtomicU32,
}

impl ServletMetrics {
	/// Create new metrics with zero queue depth
	pub fn new() -> Self {
		Self { queue_depth: AtomicU32::new(0) }
	}

	/// Increment queue depth when a message is enqueued
	pub fn enqueue(&self) {
		self.queue_depth.fetch_add(1, Ordering::Relaxed);
	}

	/// Decrement queue depth when a message is dequeued/processed
	pub fn dequeue(&self) {
		self.queue_depth.fetch_sub(1, Ordering::Relaxed);
	}

	/// Get the current queue depth
	pub fn queue_depth(&self) -> u32 {
		self.queue_depth.load(Ordering::Relaxed)
	}
}

/// Exponential moving average latency tracker for utilization metrics
///
/// Tracks response latency using an atomic EMA for lock-free updates.
/// Converts latency to utilization based on a configurable target threshold.
///
/// Servlets can embed this to implement `Servlet::utilization()`.
#[derive(Debug)]
pub struct LatencyTracker {
	/// Exponential moving average in microseconds (stored as u64 for atomics)
	ema_us: AtomicU64,
	/// Smoothing factor in basis points (e.g., 2000 = 0.2 weight for new samples)
	alpha_bps: u16,
	/// Target latency threshold in microseconds (100% utilization point)
	target_us: u64,
}

impl LatencyTracker {
	/// Create a new latency tracker
	///
	/// # Arguments
	/// * `alpha_bps` - Smoothing factor (0-10000). Higher = more weight on new samples.
	///   2000 (20%) is a good default for responsive tracking.
	/// * `target_us` - Target latency in microseconds. Latency at or above this
	///   value reports 100% utilization.
	pub const fn new(alpha_bps: u16, target_us: u64) -> Self {
		Self { ema_us: AtomicU64::new(0), alpha_bps, target_us }
	}

	/// Record a latency sample
	///
	/// Updates the EMA atomically: `new_ema = alpha * sample + (1 - alpha) * old_ema`
	///
	/// # Arguments
	/// * `latency_us` - Latency in microseconds
	pub fn record(&self, latency_us: u64) {
		// EMA formula: new = alpha * sample + (1 - alpha) * old
		// Using basis points: new = (alpha * sample + (10000 - alpha) * old) / 10000
		let alpha = self.alpha_bps as u64;
		let one_minus_alpha = 10000u64.saturating_sub(alpha);

		loop {
			let current = self.ema_us.load(Ordering::Relaxed);
			let new_ema = (alpha.saturating_mul(latency_us) + one_minus_alpha.saturating_mul(current)) / 10000;
			let success = Ordering::Release;
			let failure = Ordering::Relaxed;
			match self.ema_us.compare_exchange_weak(current, new_ema, success, failure) {
				Ok(_) => break,
				Err(_) => continue, // Retry on contention
			}
		}
	}

	/// Get current utilization as basis points
	///
	/// Calculates `(ema_us / target_us) * 10000`, capped at 10000 (100%)
	pub fn utilization(&self) -> BasisPoints {
		let ema = self.ema_us.load(Ordering::Relaxed);
		if self.target_us == 0 {
			return BasisPoints::MAX;
		}

		let ratio_bps = ema.saturating_mul(10000) / self.target_us;
		BasisPoints::new_saturating(ratio_bps.min(10000) as u16)
	}

	/// Get the raw EMA value in microseconds
	pub fn ema_microseconds(&self) -> u64 {
		self.ema_us.load(Ordering::Relaxed)
	}

	/// Reset the tracker to zero
	pub fn reset(&self) {
		self.ema_us.store(0, Ordering::Relaxed);
	}
}

impl Default for LatencyTracker {
	/// Default: 20% alpha, 100ms target
	fn default() -> Self {
		Self::new(2000, 100_000)
	}
}

// ============================================================================
// Utilization Reporter
// ============================================================================

/// Default latency weight in basis points (70%)
const DEFAULT_LATENCY_WEIGHT_BPS: u16 = 7000;

/// Helper for servlets to track and report utilization.
///
/// Wraps a `LatencyTracker` with a convenient interface for recording
/// request latencies and reporting utilization to the hive.
///
/// Optionally combines latency-based utilization with queue depth for
/// more accurate load measurement. Use [`with_queue`](Self::with_queue) to
/// enable queue-aware utilization.
///
/// Servlets can embed this and return `Some(reporter.utilization())` from
/// `ServletBox::utilization()`.
///
/// # Example
///
/// ```ignore
/// struct MyServlet {
///     reporter: UtilizationReporter,
///     // ... other fields
/// }
///
/// impl MyServlet {
///     fn handle_request(&self, request: Request) -> Response {
///         let start = std::time::Instant::now();
///         let response = self.process(request);
///         self.reporter.record_latency(start.elapsed());
///         response
///     }
/// }
///
/// impl ServletBox for MyServlet {
///     fn utilization(&self) -> Option<BasisPoints> {
///         Some(self.reporter.utilization())
///     }
///     // ... other methods
/// }
/// ```
#[derive(Debug)]
pub struct UtilizationReporter {
	tracker: LatencyTracker,
	/// Optional queue metrics for combined utilization
	queue: Option<Arc<ServletMetrics>>,
	/// Queue capacity for utilization percentage (default: 100)
	queue_capacity: u32,
	/// Weight for latency in basis points (default: 7000 = 70%)
	latency_weight_bps: u16,
}

impl UtilizationReporter {
	/// Create a new utilization reporter with custom parameters.
	///
	/// # Arguments
	/// * `alpha_bps` - Smoothing factor (0-10000). Higher = more weight on new samples.
	/// * `target_us` - Target latency in microseconds (100% utilization point).
	pub const fn new(alpha_bps: u16, target_us: u64) -> Self {
		Self {
			tracker: LatencyTracker::new(alpha_bps, target_us),
			queue: None,
			queue_capacity: 100,
			latency_weight_bps: DEFAULT_LATENCY_WEIGHT_BPS,
		}
	}

	/// Create a utilization reporter that combines latency with queue depth.
	///
	/// The combined utilization is calculated as:
	/// `(latency_weight * latency_util + (1 - latency_weight) * queue_util)`
	///
	/// where `queue_util = (queue_depth / capacity) * 10000`.
	///
	/// # Arguments
	/// * `alpha_bps` - Smoothing factor for latency EMA (0-10000).
	/// * `target_us` - Target latency in microseconds (100% utilization point).
	/// * `queue` - Shared queue metrics to track.
	/// * `capacity` - Queue capacity for utilization calculation.
	/// * `latency_weight_bps` - Weight for latency component (0-10000).
	///   7000 (70% latency, 30% queue) is a good default.
	pub fn with_queue(
		alpha_bps: u16,
		target_us: u64,
		queue: Arc<ServletMetrics>,
		capacity: u32,
		latency_weight_bps: u16,
	) -> Self {
		Self {
			tracker: LatencyTracker::new(alpha_bps, target_us),
			queue: Some(queue),
			queue_capacity: capacity,
			latency_weight_bps,
		}
	}

	/// Record a latency sample from a request duration.
	pub fn record_latency(&self, duration: core::time::Duration) {
		self.tracker.record(duration.as_micros() as u64);
	}

	/// Record a latency sample in microseconds.
	pub fn record_microseconds(&self, latency_us: u64) {
		self.tracker.record(latency_us);
	}

	/// Get current utilization as basis points (0-10000).
	///
	/// If queue metrics are configured, returns a weighted combination
	/// of latency and queue utilization. Otherwise returns latency-only.
	pub fn utilization(&self) -> BasisPoints {
		let latency_util = self.tracker.utilization().get() as u32;

		let Some(ref queue) = self.queue else {
			return self.tracker.utilization();
		};

		// Calculate queue utilization: (depth / capacity) * 10000
		let queue_util = if self.queue_capacity == 0 {
			0
		} else {
			queue.queue_depth().saturating_mul(10000) / self.queue_capacity
		};

		// Weighted average: (latency_weight * latency + queue_weight * queue) / 10000
		let latency_weight = self.latency_weight_bps as u32;
		let queue_weight = 10000u32.saturating_sub(latency_weight);
		let combined = (latency_weight.saturating_mul(latency_util) + queue_weight.saturating_mul(queue_util)) / 10000;

		BasisPoints::new_saturating(combined.min(10000) as u16)
	}

	/// Get the raw EMA latency in microseconds.
	pub fn ema_microseconds(&self) -> u64 {
		self.tracker.ema_microseconds()
	}

	/// Get the current queue depth (if queue tracking is enabled).
	pub fn queue_depth(&self) -> Option<u32> {
		self.queue.as_ref().map(|q| q.queue_depth())
	}

	/// Reset the latency tracker to zero.
	pub fn reset(&self) {
		self.tracker.reset();
	}
}

impl Default for UtilizationReporter {
	/// Default: 20% alpha, 100ms target latency, no queue tracking
	fn default() -> Self {
		Self::new(2000, 100_000)
	}
}
