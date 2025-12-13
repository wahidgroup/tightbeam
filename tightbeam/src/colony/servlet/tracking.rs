//! Latency and utilization tracking for servlets

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
