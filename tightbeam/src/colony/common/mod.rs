//! Shared colony types: load balancers, pheromone metrics, control-plane
//! helpers, and scaling utilities used by cluster and hive.

pub mod messages;
pub mod scaling;
pub mod urn;

use core::sync::atomic::{AtomicU64, Ordering};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{SPLITMIX64_GAMMA, SPLITMIX64_MIX_1, SPLITMIX64_MIX_2};
use crate::utils::BasisPoints;

use crate::runtime::rt;

pub use messages::*;
pub use scaling::*;
pub use urn::{
	canonical_bytes, instance_urn, is_bare_servlet_type, servlet_instance, type_canonical_bytes, type_prefix_bytes,
	ColonyNamespace, ColonyResource, COLONY_NID,
};

// ============================================================================
// Load Balancing
// ============================================================================

/// Pheromone signal one servlet instance carries into a balancing round.
///
/// - `pheromone`: stigmergic trail strength in `0..=`[`MAX_PHEROMONE`].
///   The registry raises it on a successful forward and lowers it on
///   failure or evaporation. Balancers use it as the sole selection signal.
/// - `instance_key`: opaque identity (canonical instance-URN bytes).
///   Balancers treat these bytes as opaque.
#[derive(Debug, Clone)]
pub struct InstanceMetrics {
	/// Opaque instance handle for the balancing round.
	///
	/// The key is owned on purpose. A borrowed key would put a lifetime
	/// on the public [`LoadBalancer`] trait and every implementor.
	/// Canonical instance-URN bytes are short, so the per-round copy is
	/// bounded and cheaper than that API cost.
	pub instance_key: Vec<u8>,
	/// Stigmergic trail strength in `0..=`[`MAX_PHEROMONE`]. Higher is
	/// stronger.
	pub pheromone: u64,
}

/// Upper bound of the pheromone scale, in basis points.
///
/// Shared by the registry cap and every balancer that reads the signal.
pub const MAX_PHEROMONE: u64 = 10_000;

/// Default [`StochasticForager`] exploration floor.
///
/// Baseline weight every live instance keeps so a cold instance stays
/// selectable.
pub const DEFAULT_EXPLORATION_FLOOR: u64 = MAX_PHEROMONE / 20;

/// Default [`StochasticForager`] repellency threshold.
///
/// Trail strength past which extra pheromone stops attracting and begins
/// to repel. See [`StochasticForager`] sources.
pub const DEFAULT_REPELLENCY_THRESHOLD: u64 = (MAX_PHEROMONE * 4) / 5;

/// Strategy that selects one instance among candidates of a servlet type.
///
/// Object-safe so [`ClusterConfig`](crate::colony::cluster::ClusterConfig)
/// can hold `Arc<dyn LoadBalancer>`. The default strategy is
/// [`StochasticForager`].
pub trait LoadBalancer: Send + Sync {
	/// Choose an index into `candidates`, or `None` when the slice is empty.
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize>;
}

/// Gamma-stepped sequence so each balancer gets a distinct SplitMix64 stream.
static BALANCER_SEED_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Build the next balancer seed from the sequence XOR the clock.
///
/// Balancers constructed in the same instant still diverge.
fn fresh_seed() -> u64 {
	let sequence = BALANCER_SEED_SEQUENCE.fetch_add(SPLITMIX64_GAMMA, Ordering::Relaxed);
	sequence ^ current_timestamp_ms()
}

/// Advance SplitMix64 state and return the mixed output.
///
/// Reference: Vigna, `splitmix64.c` (2015). See [`SPLITMIX64_GAMMA`].
/// One `fetch_add` claims a unique state, so concurrent callers each draw
/// their own value.
fn splitmix64_next(state: &AtomicU64) -> u64 {
	let mut z = state
		.fetch_add(SPLITMIX64_GAMMA, Ordering::Relaxed)
		.wrapping_add(SPLITMIX64_GAMMA);

	z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_MIX_1);
	z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_MIX_2);
	z ^ (z >> 31)
}

/// Default balancer: stochastic, pheromone-proportional instance selection.
///
/// Each instance is drawn with probability proportional to its foraging
/// weight, the faithful realization of the stigmergic model the registry
/// maintains. Unlike a deterministic argmax, equal trails split the load
/// which spreads load across the eligible instances.
///
/// # Behavior
///
/// - **Exploitation**: higher pheromone raises an instance's draw probability.
/// - **Exploration**: the exploration floor keeps every live instance reachable.
/// - **Repellency**: past the repellency threshold, additional pheromone
///   *lowers* the draw weight, stopping any instance from monopolizing the wheel.
///
/// # Configuration
///
/// - [`DEFAULT_EXPLORATION_FLOOR`]: the floor is the baseline weight every
///   live instance keeps regardless of pheromone.
/// - [`DEFAULT_REPELLENCY_THRESHOLD`]: the threshold is the pheromone value
///   past which additional pheromone stops attracting and begins to repel.
///
/// # Example
///
/// ```
/// # use tightbeam::colony::common::StochasticForager;
/// let forager = StochasticForager::default()
///     .with_exploration_floor(250)
///     .with_repellency_threshold(9_000);
/// ```
///
/// # Sources
///
/// - Grassé (1959), stigmergy - indirect coordination through a shared
///   medium: [doi:10.1007/BF02223791](https://doi.org/10.1007/BF02223791)
/// - Di Caro & Dorigo (1998), AntNet - stochastic (not argmax) stigmergic
///   routing: [doi:10.1613/jair.530](https://doi.org/10.1613/jair.530)
/// - Nakrani & Tovey (2004), honey-bee dynamic server allocation:
///   [doi:10.1177/105971230401200308](https://doi.org/10.1177/105971230401200308)
/// - Saran et al. (2007), termite trail pheromone turning repellent above
///   ~10 pg/cm: [doi:10.1007/s10886-006-9229-2](https://doi.org/10.1007/s10886-006-9229-2)
#[derive(Debug, Clone)]
pub struct StochasticForager {
	exploration_floor: u64,
	repellency_threshold: u64,
	rng: Arc<AtomicU64>,
}

impl Default for StochasticForager {
	fn default() -> Self {
		Self {
			exploration_floor: DEFAULT_EXPLORATION_FLOOR,
			repellency_threshold: DEFAULT_REPELLENCY_THRESHOLD,
			rng: Arc::new(AtomicU64::new(fresh_seed())),
		}
	}
}

impl StochasticForager {
	/// Build with a fixed RNG seed for reproducible selection streams.
	///
	/// Other knobs keep their defaults. Chain setters to override them.
	pub fn with_seed(seed: u64) -> Self {
		Self { rng: Arc::new(AtomicU64::new(seed)), ..Self::default() }
	}

	/// Set the exploration floor (default [`DEFAULT_EXPLORATION_FLOOR`]).
	///
	/// A higher floor spreads more. A lower floor exploits strong trails harder.
	pub fn with_exploration_floor(mut self, floor: u64) -> Self {
		self.exploration_floor = floor;
		self
	}

	/// Set the repellency threshold (default [`DEFAULT_REPELLENCY_THRESHOLD`]).
	///
	/// Trails above the threshold lose pull.
	pub fn with_repellency_threshold(mut self, threshold: u64) -> Self {
		self.repellency_threshold = threshold;
		self
	}

	/// Roulette-wheel weight: exploration floor plus attractive pheromone.
	///
	/// The pheromone term declines once it crosses the repellency threshold.
	fn forage_weight(&self, pheromone: u64) -> u64 {
		let attractive = if pheromone <= self.repellency_threshold {
			pheromone
		} else {
			self.repellency_threshold.saturating_sub(pheromone - self.repellency_threshold)
		};

		self.exploration_floor + attractive
	}
}

impl LoadBalancer for StochasticForager {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates.len() {
			0 => None,
			1 => Some(0),
			last_plus_one => {
				let total: u64 = candidates.iter().map(|c| self.forage_weight(c.pheromone)).sum();
				let raw = splitmix64_next(&self.rng);

				// Zero floor and dead trails: every weight is zero. Draw
				// uniformly, which also covers a zero count.
				if total == 0 {
					return Some((raw as usize) % last_plus_one);
				}

				let draw = raw % total;
				let mut cumulative = 0u64;
				for (index, candidate) in candidates.iter().enumerate() {
					cumulative += self.forage_weight(candidate.pheromone);
					if draw < cumulative {
						return Some(index);
					}
				}
				Some(last_plus_one - 1)
			}
		}
	}
}

/// Power of Two Choices: probe two distinct random instances and keep the
/// stronger trail.
///
/// - Spreads concurrent routers across the pool.
/// - Still favors instances with a stronger pheromone trail.
///
/// # Sources
///
/// - Mitzenmacher (2001), *The Power of Two Choices in Randomized Load
///   Balancing*, IEEE TPDS 12(10):
///   [doi:10.1109/71.963420](https://doi.org/10.1109/71.963420)
#[derive(Debug, Clone)]
pub struct PowerOfTwoChoices {
	rng: Arc<AtomicU64>,
}

impl Default for PowerOfTwoChoices {
	fn default() -> Self {
		Self { rng: Arc::new(AtomicU64::new(fresh_seed())) }
	}
}

impl LoadBalancer for PowerOfTwoChoices {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates.len() {
			0 => None,
			1 => Some(0),
			2 => Some(usize::from(candidates[1].pheromone > candidates[0].pheromone)),
			n => {
				// Split one 64-bit draw into a uniformly distinct pair:
				// second is drawn from [0, n-1) and shifted past first.
				let draw = splitmix64_next(&self.rng);
				let first = ((draw >> 32) as usize) % n;
				let offset = ((draw & u64::from(u32::MAX)) as usize) % (n - 1);
				let second = offset + usize::from(offset >= first);

				if candidates[first].pheromone >= candidates[second].pheromone {
					Some(first)
				} else {
					Some(second)
				}
			}
		}
	}
}

/// Round-robin: cycle instances in order and ignore pheromone.
#[derive(Debug, Clone, Default)]
pub struct RoundRobin {
	counter: Arc<AtomicU64>,
}

impl LoadBalancer for RoundRobin {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		if candidates.is_empty() {
			return None;
		}

		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		Some((count as usize) % candidates.len())
	}
}

// ============================================================================
// Timestamp
// ============================================================================

/// Current time in milliseconds since the UNIX epoch.
///
/// Uses the system clock (`colony` implies `std`).
pub fn current_timestamp_ms() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

// ============================================================================
// Utilization
// ============================================================================

/// Mean utilization across a hive's servlet instances, in basis points.
///
/// - `total_utilization`: sum of per-instance basis points.
/// - `instance_count`: number of instances in that sum.
///
/// A hive with zero instances returns [`BasisPoints::MAX`] so backpressure
/// and heartbeats report saturation. Per-type scaling still sees the zero
/// count and can spawn.
pub fn aggregate_utilization(total_utilization: u64, instance_count: usize) -> BasisPoints {
	match instance_count {
		0 => BasisPoints::MAX,
		n => BasisPoints::new_saturating((total_utilization / n as u64) as u16),
	}
}

// ============================================================================
// Control-Plane Replies
// ============================================================================

/// Build a V0 response frame that echoes the request id.
pub fn reply_frame<M: crate::Message>(
	id: impl AsRef<[u8]>,
	message: M,
) -> Result<Option<crate::Frame>, crate::TightBeamError> {
	use crate::builder::TypeBuilder;

	let frame = crate::utils::compose(crate::Version::V0)
		.with_id(id)
		.with_order(0)
		.with_message(message)
		.build()?;

	Ok(Some(frame))
}

/// Build a V2 response frame with an explicit priority.
///
/// Heartbeat replies use `NetworkControl` so monitoring stays distinct
/// from work traffic.
pub fn reply_frame_with_priority<M: crate::Message>(
	id: impl AsRef<[u8]>,
	priority: crate::MessagePriority,
	message: M,
) -> Result<Option<crate::Frame>, crate::TightBeamError> {
	use crate::builder::TypeBuilder;

	let frame = crate::utils::compose(crate::Version::V2)
		.with_id(id)
		.with_order(0)
		.with_priority(priority)
		.with_message(message)
		.build()?;

	Ok(Some(frame))
}

// ============================================================================
// Task Lifecycle
// ============================================================================

/// Take an optional join handle and abort it when present.
///
/// Shared by servlet, hive, and cluster `stop` / `Drop` paths.
pub fn take_and_abort(handle: &mut Option<rt::JoinHandle>) {
	if let Some(handle) = handle.take() {
		rt::abort(&handle);
	}
}

/// Whether a runtime has entered drain, and since when.
///
/// Drain is one fact read from several places: the control plane refuses
/// new manage work, the scaling loop stops changing the slate, and the
/// re-announce loop stops advertising a hive that is going away. Each
/// reading the same handle keeps those decisions from disagreeing.
///
/// Drain is terminal. A runtime that has entered it stays in it.
#[derive(Clone, Default)]
pub struct DrainMode(std::sync::Arc<std::sync::RwLock<Option<std::time::Instant>>>);

impl DrainMode {
	/// Enters drain, keeping the instant of the first entry.
	pub fn begin(&self) {
		let Ok(mut since) = self.0.write() else {
			return;
		};

		since.get_or_insert_with(std::time::Instant::now);
	}

	/// Whether drain has begun.
	#[must_use]
	pub fn is_draining(&self) -> bool {
		self.0.read().is_ok_and(|since| since.is_some())
	}
}

/// The background tasks one runtime started.
///
/// A runtime keeps one group and puts every task it spawns in it, so
/// stopping the runtime stops that work with a single call. Spawning
/// without the group leaves a task running past the stop that was meant to
/// end it (CWE-772), which is why the group is the only spawn path these
/// runtimes offer.
///
/// The handle is shared, so a context handed to a request handler can adopt
/// work the handler starts.
#[derive(Clone, Default)]
pub struct TaskGroup(std::sync::Arc<std::sync::Mutex<TaskGroupState>>);

/// Running handles, and whether the group has stopped.
#[derive(Default)]
struct TaskGroupState {
	running: Vec<rt::JoinHandle>,
	stopped: bool,
}

impl TaskGroup {
	/// Takes ownership of `handle`, releasing handles whose task has ended.
	///
	/// A stopped group aborts `handle` on arrival, so work that starts while
	/// the runtime is stopping ends with the stop (CWE-772). The sweep bounds
	/// the group by the tasks actually running, which keeps a runtime that
	/// spawns per request at the size of its live work.
	pub fn adopt(&self, handle: rt::JoinHandle) {
		let Ok(mut state) = self.0.lock() else {
			// A poisoned group has lost track of what it holds, so the handle
			// is aborted here.
			rt::abort(&handle);
			return;
		};

		if state.stopped {
			rt::abort(&handle);
			return;
		}

		state.running.retain(|task| !task.is_finished());
		state.running.push(handle);
	}

	/// Runs `task` under this group's ownership.
	pub fn spawn<F>(&self, task: F)
	where
		F: core::future::Future<Output = ()> + Send + 'static,
	{
		self.adopt(rt::spawn(task));
	}

	/// Stops the group and aborts every task it still owns.
	///
	/// Stopping is terminal: a later [`TaskGroup::spawn`] aborts on
	/// arrival, which keeps the stop reaching every task the group starts.
	pub fn abort_all(&self) {
		let Ok(mut state) = self.0.lock() else {
			return;
		};

		state.stopped = true;
		for task in state.running.drain(..) {
			rt::abort(&task);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{DrainMode, TaskGroup};
	use std::collections::HashSet;
	use std::time::Duration;

	use super::{
		InstanceMetrics, LoadBalancer, PowerOfTwoChoices, RoundRobin, StochasticForager, DEFAULT_EXPLORATION_FLOOR,
		DEFAULT_REPELLENCY_THRESHOLD, MAX_PHEROMONE,
	};

	fn pool(pheromones: &[u64]) -> Vec<InstanceMetrics> {
		pheromones
			.iter()
			.enumerate()
			.map(|(index, &pheromone)| InstanceMetrics { instance_key: vec![index as u8], pheromone })
			.collect()
	}

	fn uniform(count: usize) -> Vec<InstanceMetrics> {
		pool(&vec![MAX_PHEROMONE / 2; count])
	}

	fn histogram(balancer: &dyn LoadBalancer, candidates: &[InstanceMetrics], draws: usize) -> Vec<usize> {
		let mut counts = vec![0usize; candidates.len()];
		for _ in 0..draws {
			if let Some(index) = balancer.select(candidates) {
				counts[index] += 1;
			}
		}
		counts
	}

	#[test]
	fn empty_pool_selects_nothing() {
		let forager = StochasticForager::with_seed(1);
		let p2c = PowerOfTwoChoices::default();
		let round_robin = RoundRobin::default();
		assert_eq!(forager.select(&[]), None);
		assert_eq!(p2c.select(&[]), None);
		assert_eq!(round_robin.select(&[]), None);
	}

	#[test]
	fn sole_candidate_is_selected() {
		let forager = StochasticForager::with_seed(1);
		let p2c = PowerOfTwoChoices::default();
		let round_robin = RoundRobin::default();
		let single = uniform(1);
		assert_eq!(forager.select(&single), Some(0));
		assert_eq!(p2c.select(&single), Some(0));
		assert_eq!(round_robin.select(&single), Some(0));
	}

	#[test]
	fn forager_spreads_equal_trails_across_all() {
		let forager = StochasticForager::with_seed(0xF0);
		let candidates = uniform(4);
		let counts = histogram(&forager, &candidates, 8_000);
		let floor = 8_000 / 8;
		assert!(counts.iter().all(|&c| c > floor), "equal trails must spread, got {counts:?}");
	}

	#[test]
	fn forager_favors_stronger_trail() {
		let forager = StochasticForager::with_seed(0xA1);
		let candidates = pool(&[MAX_PHEROMONE / 10, DEFAULT_REPELLENCY_THRESHOLD]);
		let counts = histogram(&forager, &candidates, 8_000);
		assert!(counts[1] > counts[0], "stronger trail must win more draws, got {counts:?}");
	}

	#[test]
	fn forager_floor_keeps_zero_trail_reachable() {
		let forager = StochasticForager::with_seed(0xB2);
		let candidates = pool(&[0, MAX_PHEROMONE]);
		let counts = histogram(&forager, &candidates, 8_000);
		assert!(
			counts[0] > 0,
			"exploration floor must keep zero-trail reachable, got {counts:?}"
		);
	}

	#[test]
	fn forager_repellency_caps_saturated_share() {
		let forager = StochasticForager::with_seed(0xC3);
		let saturated = pool(&[MAX_PHEROMONE, DEFAULT_REPELLENCY_THRESHOLD]);
		let counts = histogram(&forager, &saturated, 8_000);
		assert!(
			counts[1] >= counts[0],
			"over-saturated trail must not out-pull one at the repellency peak, got {counts:?}"
		);
	}

	#[test]
	fn p2c_picks_stronger_of_two() {
		let balancer = PowerOfTwoChoices::default();
		let candidates = pool(&[100, MAX_PHEROMONE]);
		assert_eq!(balancer.select(&candidates), Some(1));
	}

	#[test]
	fn p2c_covers_all_indices_under_equal_trails() {
		let balancer = PowerOfTwoChoices::default();
		let candidates = uniform(8);
		let seen: HashSet<usize> = (0..4096).filter_map(|_| balancer.select(&candidates)).collect();
		assert_eq!(seen.len(), candidates.len());
	}

	#[test]
	fn round_robin_cycles_indices() {
		let balancer = RoundRobin::default();
		let candidates = uniform(3);
		let picks: Vec<Option<usize>> = (0..6).map(|_| balancer.select(&candidates)).collect();
		assert_eq!(picks, vec![Some(0), Some(1), Some(2), Some(0), Some(1), Some(2)]);
	}

	#[test]
	fn forage_weight_stays_positive_and_declines_past_threshold() {
		let forager = StochasticForager::with_seed(0xD4);
		assert_eq!(forager.forage_weight(0), DEFAULT_EXPLORATION_FLOOR);
		assert_eq!(
			forager.forage_weight(DEFAULT_REPELLENCY_THRESHOLD),
			DEFAULT_EXPLORATION_FLOOR + DEFAULT_REPELLENCY_THRESHOLD
		);
		assert!(forager.forage_weight(MAX_PHEROMONE) < forager.forage_weight(DEFAULT_REPELLENCY_THRESHOLD));
		assert!(forager.forage_weight(MAX_PHEROMONE) >= DEFAULT_EXPLORATION_FLOOR);
	}

	#[test]
	fn forager_knobs_reshape_the_weight_curve() {
		let tuned = StochasticForager::with_seed(0xE5)
			.with_exploration_floor(0)
			.with_repellency_threshold(MAX_PHEROMONE / 2);
		assert_eq!(tuned.forage_weight(0), 0);
		assert_eq!(tuned.forage_weight(MAX_PHEROMONE / 2), MAX_PHEROMONE / 2);
		assert_eq!(tuned.forage_weight(MAX_PHEROMONE), 0);
	}

	#[test]
	fn zero_floor_and_dead_trails_still_select_uniformly() {
		let tuned = StochasticForager::with_seed(0xF6).with_exploration_floor(0);
		let dead = pool(&[0, 0, 0]);
		let seen: HashSet<usize> = (0..256).filter_map(|_| tuned.select(&dead)).collect();
		assert_eq!(seen.len(), dead.len());
	}

	/// Cases: (total_utilization, instance_count, expected_bps)
	const AGGREGATE_CASES: &[(u64, usize, u16)] = &[
		(0, 0, 10000),     // no instances -> saturated, route elsewhere
		(0, 4, 0),         // all idle
		(20000, 4, 5000),  // uniform mean
		(10000, 2, 5000),  // one loaded type + one idle type
		(40000, 4, 10000), // fully loaded
	];

	#[test]
	fn aggregate_utilization_means_across_all_instances() {
		for &(total, count, expected) in AGGREGATE_CASES {
			assert_eq!(super::aggregate_utilization(total, count).get(), expected);
		}
	}

	#[test]
	fn a_fresh_runtime_is_not_draining() {
		assert!(!DrainMode::default().is_draining());
	}

	#[test]
	fn every_holder_of_the_handle_sees_the_drain() {
		let mode = DrainMode::default();
		let reader = mode.clone();
		mode.begin();
		assert!(reader.is_draining());
	}

	/// Handles the group is still holding.
	fn owned(group: &TaskGroup) -> usize {
		group.0.lock().expect("task group lock").running.len()
	}

	#[tokio::test]
	async fn stopping_a_group_aborts_the_work_it_owns() {
		static FINISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

		let group = TaskGroup::default();
		group.spawn(async {
			tokio::time::sleep(Duration::from_secs(30)).await;
			FINISHED.store(true, std::sync::atomic::Ordering::SeqCst);
		});

		tokio::task::yield_now().await;
		group.abort_all();
		tokio::time::sleep(Duration::from_millis(50)).await;
		assert!(!FINISHED.load(std::sync::atomic::Ordering::SeqCst));
	}

	/// A beat already past its own checks is ended by the group that owns
	/// it, so work cannot outlast the stop that withdrew its routes
	/// (CWE-362).
	#[tokio::test]
	async fn a_running_task_ends_when_its_group_stops() {
		static BEATS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

		let group = TaskGroup::default();
		group.spawn(async {
			loop {
				BEATS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
		});

		tokio::time::sleep(Duration::from_millis(30)).await;
		group.abort_all();
		let settled = BEATS.load(std::sync::atomic::Ordering::SeqCst);

		tokio::time::sleep(Duration::from_millis(40)).await;
		assert_eq!(BEATS.load(std::sync::atomic::Ordering::SeqCst), settled);
	}

	#[tokio::test]
	async fn work_started_after_the_stop_does_not_outlive_it() {
		static FINISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

		let group = TaskGroup::default();
		group.abort_all();
		group.spawn(async {
			tokio::time::sleep(Duration::from_millis(10)).await;
			FINISHED.store(true, std::sync::atomic::Ordering::SeqCst);
		});

		tokio::time::sleep(Duration::from_millis(50)).await;
		assert!(!FINISHED.load(std::sync::atomic::Ordering::SeqCst));
		assert_eq!(owned(&group), 0);
	}

	#[tokio::test]
	async fn a_finished_task_leaves_the_group_on_the_next_spawn() {
		let group = TaskGroup::default();
		group.spawn(async {});
		tokio::time::sleep(Duration::from_millis(20)).await;

		group.spawn(std::future::pending());
		assert_eq!(owned(&group), 1);
	}
}
