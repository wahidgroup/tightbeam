//! This module holds the shared colony types: load balancers, pheromone
//! metrics, control-plane helpers, and scaling utilities used by cluster and
//! hive.

pub mod messages;
pub mod scaling;
pub mod urn;

use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use std::sync::{Arc, Mutex};

use crate::builder::TypeBuilder;
use crate::constants::{SPLITMIX64_GAMMA, SPLITMIX64_MIX_1, SPLITMIX64_MIX_2};
use crate::random::generate_nonce;
use crate::utils::BasisPoints;
use crate::{Frame, Message, MessagePriority, TightBeamError, Version};

use crate::runtime::rt;

pub use messages::*;
pub use scaling::*;
pub use urn::{ColonyNamespace, ColonyResource, ServletTypeKey, COLONY_NID};

/// Pheromone signal one servlet instance carries into a balancing round.
#[derive(Debug, Clone)]
pub struct InstanceMetrics {
	/// Opaque instance handle for the balancing round, which holds the
	/// canonical instance-URN bytes. Balancers treat these bytes as opaque.
	///
	/// The key is owned on purpose. A borrowed key would put a lifetime
	/// on the public [`LoadBalancer`] trait and every implementor.
	/// Canonical instance-URN bytes are short, so the per-round copy is
	/// bounded and cheaper than that API cost.
	pub instance_key: Vec<u8>,
	/// Stigmergic trail strength in `0..=`[`MAX_PHEROMONE`], where higher is
	/// stronger.
	///
	/// The registry raises it on a successful forward and lowers it on
	/// failure or evaporation. Balancers use it as the sole selection signal.
	pub pheromone: u64,
}

/// Upper bound of the pheromone scale, in basis points.
///
/// Shared by the registry cap and every balancer that reads the signal.
pub const MAX_PHEROMONE: u64 = 10_000;

/// Default [`StochasticForager`] exploration floor.
///
/// It is the baseline weight every live instance keeps, so a cold instance
/// stays selectable.
pub const DEFAULT_EXPLORATION_FLOOR: u64 = MAX_PHEROMONE / 20;

/// Default [`StochasticForager`] repellency threshold.
///
/// It is the trail strength past which extra pheromone stops attracting and
/// begins to repel. See the [`StochasticForager`] sources.
pub const DEFAULT_REPELLENCY_THRESHOLD: u64 = (MAX_PHEROMONE * 4) / 5;

/// Strategy that selects one instance among candidates of a servlet type.
///
/// The trait is object-safe, so
/// [`ClusterConfig`](crate::colony::cluster::ClusterConfig) can hold
/// `Arc<dyn LoadBalancer>`. The default strategy is [`StochasticForager`].
pub trait LoadBalancer: Send + Sync {
	/// Chooses an index into `candidates`, or returns `None` when the slice
	/// is empty.
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize>;
}

/// The gamma-stepped sequence that gives each balancer a distinct SplitMix64
/// stream.
static BALANCER_SEED_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Builds the next balancer seed from the sequence XOR fresh OS entropy.
///
/// The sequence alone already gives each balancer its own stream, so an
/// entropy source that fails leaves the streams distinct. The entropy only
/// keeps two gateways that started together from choosing alike, and a
/// balancer needs no secret.
fn fresh_seed() -> u64 {
	let sequence = BALANCER_SEED_SEQUENCE.fetch_add(SPLITMIX64_GAMMA, Ordering::Relaxed);
	let entropy = generate_nonce::<8>(None).map_or(0, u64::from_le_bytes);
	sequence ^ entropy
}

/// Advances the SplitMix64 state and returns the mixed output.
///
/// The mix follows Vigna, `splitmix64.c` (2015). See [`SPLITMIX64_GAMMA`].
///
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
/// weight, which follows the stigmergic model the registry maintains. A
/// deterministic argmax would send every call to one of two equal trails,
/// and the draw splits that load across the eligible instances instead.
///
/// # Behavior
///
/// - **Exploitation**: higher pheromone raises an instance's draw probability.
/// - **Exploration**: the exploration floor keeps every live instance reachable.
/// - **Repellency**: past the repellency threshold, additional pheromone
///   *lowers* the draw weight, which stops any instance from monopolizing
///   the wheel.
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
	/// Builds a forager with a fixed RNG seed for reproducible selection
	/// streams.
	///
	/// The other knobs keep their defaults, and the chained setters override
	/// them.
	pub fn with_seed(seed: u64) -> Self {
		Self { rng: Arc::new(AtomicU64::new(seed)), ..Self::default() }
	}

	/// Sets the exploration floor, which defaults to
	/// [`DEFAULT_EXPLORATION_FLOOR`].
	///
	/// A higher floor spreads more. A lower floor exploits strong trails
	/// harder.
	pub fn with_exploration_floor(mut self, floor: u64) -> Self {
		self.exploration_floor = floor;
		self
	}

	/// Sets the repellency threshold, which defaults to
	/// [`DEFAULT_REPELLENCY_THRESHOLD`].
	///
	/// Trails above the threshold lose pull.
	pub fn with_repellency_threshold(mut self, threshold: u64) -> Self {
		self.repellency_threshold = threshold;
		self
	}

	/// Returns the roulette-wheel weight, which is the exploration floor plus
	/// the attractive pheromone.
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

				// A zero floor with dead trails makes every weight zero, so the
				// draw is uniform, and the modulo below never sees a zero
				// total.
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
/// - The probe spreads concurrent routers across the pool.
/// - The probe still favors instances with a stronger pheromone trail.
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
				// One 64-bit draw splits into a uniform distinct pair: `second`
				// comes from `[0, n-1)` and shifts past `first`.
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

/// Round-robin balancer that cycles through instances in order and ignores
/// pheromone.
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

/// Mean utilization across a hive's servlet instances, in basis points.
///
/// - `total_utilization` is the sum of per-instance basis points.
/// - `instance_count` is the number of instances in that sum.
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

/// Builds a V0 response frame that echoes the request id.
pub fn reply_frame<M: Message>(id: impl AsRef<[u8]>, message: M) -> Result<Option<Frame>, TightBeamError> {
	let frame = Version::V0.compose().with_id(id).with_order(0).with_message(message).build()?;

	Ok(Some(frame))
}

/// Builds a V2 response frame with an explicit priority.
///
/// Heartbeat replies use `NetworkControl` so monitoring stays distinct
/// from work traffic.
pub fn reply_frame_with_priority<M: Message>(
	id: impl AsRef<[u8]>,
	priority: MessagePriority,
	message: M,
) -> Result<Option<Frame>, TightBeamError> {
	let frame = Version::V2
		.compose()
		.with_id(id)
		.with_order(0)
		.with_priority(priority)
		.with_message(message)
		.build()?;

	Ok(Some(frame))
}

/// Whether a runtime has entered drain.
///
/// Drain is one fact read from several places: the control plane refuses
/// new manage work, the scaling loop stops changing the slate, and the
/// re-announce loop stops advertising a hive that is going away. Every
/// reader holds the same handle, so those decisions agree.
///
/// Drain is terminal. A runtime that has entered it stays in it.
#[derive(Clone, Default)]
pub struct DrainMode(Arc<AtomicBool>);

impl DrainMode {
	/// Enters drain.
	pub fn begin(&self) {
		self.0.store(true, Ordering::Release);
	}

	/// Whether drain has begun.
	#[must_use]
	pub fn is_draining(&self) -> bool {
		self.0.load(Ordering::Acquire)
	}
}

/// The background tasks one runtime started.
///
/// A runtime keeps one group and puts every task it spawns in it, so stopping
/// the runtime stops that work with a single call. The handle is shared, so a
/// context handed to a request handler can adopt work the handler starts.
///
/// # Single spawn path
///
/// Spawning without the group leaves a task running past the stop that was
/// meant to end it (CWE-772), which is why the group is the only spawn path
/// these runtimes offer.
#[derive(Clone, Default)]
pub struct TaskGroup(Arc<Mutex<TaskGroupState>>);

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
		F: Future<Output = ()> + Send + 'static,
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
	use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use core::time::Duration;

	use std::collections::HashSet;

	use super::{
		DrainMode, InstanceMetrics, LoadBalancer, PowerOfTwoChoices, RoundRobin, StochasticForager, TaskGroup,
		DEFAULT_EXPLORATION_FLOOR, DEFAULT_REPELLENCY_THRESHOLD, MAX_PHEROMONE,
	};

	fn pool(pheromones: impl AsRef<[u64]>) -> Vec<InstanceMetrics> {
		let pheromones = pheromones.as_ref();
		pheromones
			.iter()
			.enumerate()
			.map(|(index, &pheromone)| InstanceMetrics { instance_key: vec![index as u8], pheromone })
			.collect()
	}

	fn uniform(count: usize) -> Vec<InstanceMetrics> {
		pool(vec![MAX_PHEROMONE / 2; count])
	}

	fn histogram(balancer: &dyn LoadBalancer, candidates: impl AsRef<[InstanceMetrics]>, draws: usize) -> Vec<usize> {
		let candidates = candidates.as_ref();
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
		let candidates = pool([MAX_PHEROMONE / 10, DEFAULT_REPELLENCY_THRESHOLD]);
		let counts = histogram(&forager, &candidates, 8_000);
		assert!(counts[1] > counts[0], "stronger trail must win more draws, got {counts:?}");
	}

	#[test]
	fn forager_floor_keeps_zero_trail_reachable() {
		let forager = StochasticForager::with_seed(0xB2);
		let candidates = pool([0, MAX_PHEROMONE]);
		let counts = histogram(&forager, &candidates, 8_000);
		assert!(
			counts[0] > 0,
			"exploration floor must keep zero-trail reachable, got {counts:?}"
		);
	}

	#[test]
	fn forager_repellency_caps_saturated_share() {
		let forager = StochasticForager::with_seed(0xC3);
		let saturated = pool([MAX_PHEROMONE, DEFAULT_REPELLENCY_THRESHOLD]);
		let counts = histogram(&forager, &saturated, 8_000);
		assert!(
			counts[1] >= counts[0],
			"over-saturated trail must not out-pull one at the repellency peak, got {counts:?}"
		);
	}

	#[test]
	fn p2c_picks_stronger_of_two() {
		let balancer = PowerOfTwoChoices::default();
		let candidates = pool([100, MAX_PHEROMONE]);
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
		let dead = pool([0, 0, 0]);
		let seen: HashSet<usize> = (0..256).filter_map(|_| tuned.select(&dead)).collect();
		assert_eq!(seen.len(), dead.len());
	}

	/// Each case is a `(total_utilization, instance_count, expected_bps)` row.
	const AGGREGATE_CASES: &[(u64, usize, u16)] = &[
		(0, 0, 10000),     // With no instances, the hive reports saturation so work routes elsewhere.
		(0, 4, 0),         // Every instance is idle.
		(20000, 4, 5000),  // The instances share one uniform mean.
		(10000, 2, 5000),  // One loaded type and one idle type average to half.
		(40000, 4, 10000), // Every instance is fully loaded.
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

	/// Counts the handles the group still holds.
	fn owned(group: &TaskGroup) -> usize {
		group.0.lock().expect("task group lock").running.len()
	}

	/// A span longer than any test moves its clock. A task that sleeps it out
	/// and then finishes was never stopped.
	const LONG_RUN: Duration = Duration::from_secs(30);

	/// The pause between two beats of the running task.
	const BEAT: Duration = Duration::from_millis(5);

	/// Moves the paused test clock forward by `span` and lets every task it
	/// woke run.
	///
	/// The test runtime runs on one thread, so the yield hands that thread to
	/// each task the advance made ready before the test reads what it did.
	async fn advance_past(span: Duration) {
		tokio::time::advance(span).await;
		tokio::task::yield_now().await;
	}

	#[tokio::test(start_paused = true)]
	async fn stopping_a_group_aborts_the_work_it_owns() {
		static FINISHED: AtomicBool = AtomicBool::new(false);

		let group = TaskGroup::default();
		group.spawn(async {
			tokio::time::sleep(LONG_RUN).await;
			FINISHED.store(true, Ordering::SeqCst);
		});

		tokio::task::yield_now().await;
		group.abort_all();
		advance_past(LONG_RUN * 2).await;
		assert!(!FINISHED.load(Ordering::SeqCst));
	}

	/// A beat already past its own checks is ended by the group that owns
	/// it, so work cannot outlast the stop that withdrew its routes
	/// (CWE-362).
	#[tokio::test(start_paused = true)]
	async fn a_running_task_ends_when_its_group_stops() {
		static BEATS: AtomicUsize = AtomicUsize::new(0);

		let group = TaskGroup::default();
		group.spawn(async {
			loop {
				BEATS.fetch_add(1, Ordering::SeqCst);
				tokio::time::sleep(BEAT).await;
			}
		});

		tokio::task::yield_now().await;
		group.abort_all();
		let settled = BEATS.load(Ordering::SeqCst);
		assert_ne!(settled, 0);

		advance_past(BEAT * 8).await;
		assert_eq!(BEATS.load(Ordering::SeqCst), settled);
	}

	#[tokio::test(start_paused = true)]
	async fn work_started_after_the_stop_does_not_outlive_it() {
		static FINISHED: AtomicBool = AtomicBool::new(false);

		let group = TaskGroup::default();
		group.abort_all();
		group.spawn(async {
			tokio::time::sleep(BEAT).await;
			FINISHED.store(true, Ordering::SeqCst);
		});

		advance_past(BEAT * 8).await;
		assert!(!FINISHED.load(Ordering::SeqCst));
		assert_eq!(owned(&group), 0);
	}

	/// The test runtime runs on one thread, so the yield runs the empty task
	/// to its end before the second spawn sweeps the group.
	#[tokio::test]
	async fn a_finished_task_leaves_the_group_on_the_next_spawn() {
		let group = TaskGroup::default();
		group.spawn(async {});
		tokio::task::yield_now().await;

		group.spawn(core::future::pending());
		assert_eq!(owned(&group), 1);
	}
}
