//! Latency and queue gauges that a servlet reports to the hive as utilization.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use crate::utils::BasisPoints;

/// Queue-depth metrics a servlet instance keeps for auto-scaling.
///
/// A servlet author holds one, counts queued work with
/// [`ServletMetrics::enqueue`], and reports the result through
/// [`UtilizationReporter`], which the hive reads when it scales. The depth
/// is one atomic counter, so concurrent handlers update it with no lock.
#[derive(Debug, Default)]
pub struct ServletMetrics {
	/// Count of the queued messages, one for each live [`QueueSlot`].
	queue_depth: AtomicU32,
}

impl ServletMetrics {
	/// Creates metrics with a queue depth of zero.
	pub fn new() -> Self {
		Self { queue_depth: AtomicU32::new(0) }
	}

	/// Counts one queued message for as long as the returned slot lives.
	///
	/// The slot releases the count on drop, so the depth falls back on every
	/// exit of a handler, whether it returns early, panics, or is cancelled.
	/// Each release pairs with one count, so the depth stays at or above
	/// zero.
	pub fn enqueue(self: &Arc<Self>) -> QueueSlot {
		self.queue_depth.fetch_add(1, Ordering::Relaxed);
		QueueSlot(Arc::clone(self))
	}

	/// Returns the count of live queue slots.
	pub fn queue_depth(&self) -> u32 {
		self.queue_depth.load(Ordering::Relaxed)
	}
}

/// One queued message, counted while this slot lives.
///
/// [`ServletMetrics::enqueue`] creates it, and its drop releases the count,
/// so the binding is what counts the work. A slot dropped in the same
/// statement releases the count at once and measures nothing.
#[derive(Debug)]
#[must_use = "the queue slot releases its count as soon as it is dropped"]
pub struct QueueSlot(Arc<ServletMetrics>);

impl Drop for QueueSlot {
	fn drop(&mut self) {
		self.0.queue_depth.fetch_sub(1, Ordering::Relaxed);
	}
}

/// Exponential moving average (EMA) of response latency, read as utilization.
///
/// The average lives in one atomic word, so [`Self::record`] updates it with
/// no lock. [`Self::utilization`] reads it against the target latency that
/// [`Self::new`] sets.
///
/// [`ServletConfigBuilder::with_utilization`] installs one as the gauge of a
/// servlet.
///
/// [`ServletConfigBuilder::with_utilization`]: crate::colony::servlet::ServletConfigBuilder::with_utilization
#[derive(Debug)]
pub struct LatencyTracker {
	/// The average in microseconds, held as a `u64` in one atomic word.
	ema_us: AtomicU64,
	/// Smoothing factor in basis points, so 2000 weighs a new sample at 0.2.
	alpha: BasisPoints,
	/// Target latency in microseconds, which reads as 100% utilization.
	target_us: u64,
}

impl LatencyTracker {
	/// Creates a tracker whose average starts at zero.
	///
	/// # Arguments
	/// - `alpha`: the smoothing factor. A higher value gives new samples more
	///   weight, and 20% ([`crate::bps!(2000)`](crate::bps)) tracks
	///   responsively.
	/// - `target_us`: the target latency in microseconds. Latency at or above
	///   this value reports 100% utilization.
	pub const fn new(alpha: BasisPoints, target_us: u64) -> Self {
		Self { ema_us: AtomicU64::new(0), alpha, target_us }
	}

	/// Folds one latency sample into the average.
	///
	/// One atomic compare-and-swap, which retries under contention, applies
	/// `new_ema = alpha * sample + (1 - alpha) * old_ema`.
	///
	/// # Arguments
	/// - `latency_us`: the sample, in microseconds.
	pub fn record(&self, latency_us: u64) {
		// Alpha counts out of 10000 basis points, so the update is
		// `new = (alpha * sample + (10000 - alpha) * old) / 10000`.
		let alpha = self.alpha.get() as u64;
		let one_minus_alpha = 10000u64.saturating_sub(alpha);

		loop {
			let current = self.ema_us.load(Ordering::Relaxed);
			let sample_part = alpha.saturating_mul(latency_us);
			let history_part = one_minus_alpha.saturating_mul(current);
			let new_ema = sample_part.saturating_add(history_part) / 10000;
			let success = Ordering::Release;
			let failure = Ordering::Relaxed;
			match self.ema_us.compare_exchange_weak(current, new_ema, success, failure) {
				Ok(_) => break,
				Err(_) => continue, // Retry on contention
			}
		}
	}

	/// Reads the average against the target as utilization in basis points.
	///
	/// The value is `(ema_us / target_us) * 10000`, capped at 10000 (100%). A
	/// target of zero reads as 10000.
	pub fn utilization(&self) -> BasisPoints {
		let ema = self.ema_us.load(Ordering::Relaxed);
		let Some(ratio_bps) = ema.saturating_mul(10000).checked_div(self.target_us) else {
			return BasisPoints::MAX;
		};

		BasisPoints::saturating_from(ratio_bps)
	}

	/// Returns the average as it stands, in microseconds.
	pub fn ema_microseconds(&self) -> u64 {
		self.ema_us.load(Ordering::Relaxed)
	}

	/// Sets the average back to zero.
	pub fn reset(&self) {
		self.ema_us.store(0, Ordering::Relaxed);
	}
}

impl Default for LatencyTracker {
	/// Uses an alpha of 20% and a target latency of 100 ms.
	fn default() -> Self {
		Self::new(crate::bps!(2000), 100_000)
	}
}

// ============================================================================
// Utilization Reporter
// ============================================================================

/// Default weight that the combined utilization gives latency, 70%.
const DEFAULT_LATENCY_WEIGHT: BasisPoints = crate::bps!(7000);

/// How a queue-aware reporter weighs its two inputs.
///
/// Both values are basis points, so a positional pair would let a caller
/// swap them and silently reweight every utilization report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtilizationWeights {
	/// Smoothing factor of the latency EMA. A higher value favours new samples.
	pub smoothing: BasisPoints,
	/// Share of the combined utilization that latency accounts for. The
	/// remainder is the queue's share.
	pub latency_share: BasisPoints,
}

impl Default for UtilizationWeights {
	/// Uses 20% smoothing and a 70% latency share.
	fn default() -> Self {
		Self { smoothing: crate::bps!(2000), latency_share: DEFAULT_LATENCY_WEIGHT }
	}
}

/// A latency and queue gauge that a servlet reports to the hive.
///
/// It reads a [`LatencyTracker`], plus the queue depth of a [`ServletMetrics`]
/// with [`Self::with_queue`]. [`ServletConfigBuilder::with_utilization`]
/// installs it on a servlet, and a hand-written [`ServletBox`] returns
/// `Some(reporter.utilization())` from [`ServletBox::utilization`].
///
/// [`ServletBox`]: crate::colony::hive::ServletBox
/// [`ServletBox::utilization`]: crate::colony::hive::ServletBox::utilization
/// [`ServletConfigBuilder::with_utilization`]: crate::colony::servlet::ServletConfigBuilder::with_utilization
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
	/// Queue metrics that the combined reading adds, when set.
	queue: Option<Arc<ServletMetrics>>,
	/// Queue depth that reads as full, 100 unless [`Self::with_queue`] sets it.
	queue_capacity: u32,
	/// Weight of latency in basis points, 7000 (70%) unless
	/// [`Self::with_queue`] sets it.
	latency_weight: BasisPoints,
}

impl UtilizationReporter {
	/// Creates a reporter that reads latency alone.
	///
	/// # Arguments
	/// - `alpha`: the smoothing factor. A higher value gives new samples more weight.
	/// - `target_us`: the target latency in microseconds, which reads as 100% utilization.
	pub const fn new(alpha: BasisPoints, target_us: u64) -> Self {
		Self {
			tracker: LatencyTracker::new(alpha, target_us),
			queue: None,
			queue_capacity: 100,
			latency_weight: DEFAULT_LATENCY_WEIGHT,
		}
	}

	/// Creates a reporter that combines latency with queue depth.
	///
	/// The combined utilization is this weighted sum:
	/// `(latency_weight * latency_util + (1 - latency_weight) * queue_util)`
	///
	/// Here `queue_util = (queue_depth / capacity) * 10000`, and a capacity of
	/// zero reads as a queue utilization of zero.
	///
	/// # Arguments
	/// - `weights`: the smoothing factor and the latency share.
	/// - `target_us`: the target latency in microseconds, which reads as 100% utilization.
	/// - `queue`: the shared queue metrics to read.
	/// - `capacity`: the queue depth that reads as 100% queue utilization.
	pub fn with_queue(weights: UtilizationWeights, target_us: u64, queue: Arc<ServletMetrics>, capacity: u32) -> Self {
		Self {
			tracker: LatencyTracker::new(weights.smoothing, target_us),
			queue: Some(queue),
			queue_capacity: capacity,
			latency_weight: weights.latency_share,
		}
	}

	/// Records the duration of one request as a latency sample.
	pub fn record_latency(&self, duration: core::time::Duration) {
		self.tracker.record(duration.as_micros() as u64);
	}

	/// Records one latency sample, given in microseconds.
	pub fn record_microseconds(&self, latency_us: u64) {
		self.tracker.record(latency_us);
	}

	/// Reads the current utilization in basis points, from 0 to 10000.
	///
	/// A reporter with queue metrics returns the weighted sum that
	/// [`Self::with_queue`] states. Any other reporter returns the latency
	/// utilization alone.
	pub fn utilization(&self) -> BasisPoints {
		let latency_util = self.tracker.utilization().get() as u32;
		let Some(ref queue) = self.queue else {
			return self.tracker.utilization();
		};

		// A capacity of zero reads as an empty queue.
		let queue_util = queue
			.queue_depth()
			.saturating_mul(10000)
			.checked_div(self.queue_capacity)
			.unwrap_or(0);

		// The two weights sum to 10000, so the quotient stays in basis points.
		let latency_weight = u32::from(self.latency_weight.get());
		let queue_weight = 10000u32.saturating_sub(latency_weight);
		let latency_part = latency_weight.saturating_mul(latency_util);
		let queue_part = queue_weight.saturating_mul(queue_util);

		let combined = latency_part.saturating_add(queue_part) / 10000;
		BasisPoints::saturating_from(combined)
	}

	/// Returns the latency average as it stands, in microseconds.
	pub fn ema_microseconds(&self) -> u64 {
		self.tracker.ema_microseconds()
	}

	/// Returns the current queue depth, or [`None`] with no queue metrics.
	pub fn queue_depth(&self) -> Option<u32> {
		self.queue.as_ref().map(|q| q.queue_depth())
	}

	/// Sets the latency average back to zero.
	pub fn reset(&self) {
		self.tracker.reset();
	}
}

impl Default for UtilizationReporter {
	/// Uses an alpha of 20%, a target latency of 100 ms, and no queue metrics.
	fn default() -> Self {
		Self::new(crate::bps!(2000), 100_000)
	}
}

/// A gauge of the load of a servlet, which the hive reads as the servlet's
/// utilization when it scales.
///
/// [`ServletConfigBuilder::with_utilization`] installs a gauge on a servlet,
/// and the runtime of the servlet answers [`ServletBox::utilization`] from it.
/// [`LatencyTracker`] and [`UtilizationReporter`] are the house gauges, and an
/// outside crate implements its own.
///
/// [`ServletBox::utilization`]: crate::colony::hive::ServletBox::utilization
/// [`ServletConfigBuilder::with_utilization`]: crate::colony::servlet::ServletConfigBuilder::with_utilization
///
/// # Examples
///
/// ```
/// use tightbeam::colony::servlet::UtilizationGauge;
/// use tightbeam::utils::BasisPoints;
///
/// /// A gauge that reads one fixed load.
/// struct Fixed(BasisPoints);
///
/// impl UtilizationGauge for Fixed {
///     fn utilization(&self) -> BasisPoints {
///         self.0
///     }
/// }
///
/// let gauge = Fixed(tightbeam::bps!(5000));
/// assert_eq!(gauge.utilization(), tightbeam::bps!(5000));
/// ```
pub trait UtilizationGauge: Send + Sync {
	/// Reads the current load in basis points, from 0 to 10000.
	fn utilization(&self) -> BasisPoints;
}

impl UtilizationGauge for LatencyTracker {
	fn utilization(&self) -> BasisPoints {
		LatencyTracker::utilization(self)
	}
}

impl UtilizationGauge for UtilizationReporter {
	fn utilization(&self) -> BasisPoints {
		UtilizationReporter::utilization(self)
	}
}

/// A gauge that a servlet's handlers also hold, behind the shared handle the
/// servlet was given.
pub(crate) struct SharedGauge<G: ?Sized>(pub(crate) Arc<G>);

impl<G: UtilizationGauge + ?Sized> UtilizationGauge for SharedGauge<G> {
	fn utilization(&self) -> BasisPoints {
		self.0.utilization()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_queue_slot_releases_its_count_when_it_drops() {
		let metrics = Arc::new(ServletMetrics::new());

		{
			let _first = metrics.enqueue();
			let _second = metrics.enqueue();
			assert_eq!(metrics.queue_depth(), 2);
		}

		assert_eq!(metrics.queue_depth(), 0);
	}

	#[test]
	fn a_handler_that_returns_early_still_releases_its_slot() {
		let metrics = Arc::new(ServletMetrics::new());

		fn refuse(metrics: &Arc<ServletMetrics>) -> Option<u32> {
			let _slot = metrics.enqueue();
			None
		}

		assert_eq!(refuse(&metrics), None);
		assert_eq!(metrics.queue_depth(), 0);
	}
}
