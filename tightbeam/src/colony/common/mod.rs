//! The shared colony types that the cluster and the hive use: load
//! balancers, pheromone metrics, control-plane helpers, the protocol
//! messages, the colony URNs, and the scaling utilities.

pub mod messages;
pub mod scaling;
pub mod urn;

use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::constants::{SPLITMIX64_GAMMA, SPLITMIX64_MIX_1, SPLITMIX64_MIX_2};
use crate::random::generate_nonce;

use crate::runtime::rt;

pub use messages::*;
pub use scaling::*;
pub use urn::{ColonyNamespace, ColonyResource, ServletTypeKey, COLONY_NID};

/// The pheromone signal one servlet instance carries into a balancing round.
#[derive(Debug, Clone)]
pub struct InstanceMetrics {
	/// The instance handle for the balancing round, which holds the
	/// canonical instance-URN bytes. Balancers treat these bytes as opaque.
	///
	/// The key is owned on purpose. A borrowed key would put a lifetime
	/// on the public [`LoadBalancer`] trait and every implementor.
	/// Canonical instance-URN bytes are short, so the per-round copy is
	/// bounded and cheaper than that API cost.
	pub instance_key: Vec<u8>,
	/// The stigmergic trail strength in `0..=`[`MAX_PHEROMONE`], where a
	/// higher value is a stronger trail.
	///
	/// The registry raises it on a successful forward and lowers it on
	/// failure or evaporation. [`StochasticForager`] and [`PowerOfTwoChoices`]
	/// select on it alone, and [`RoundRobin`] ignores it.
	pub pheromone: u64,
}

/// The upper bound of the pheromone scale, in basis points.
///
/// The registry cap and every balancer that reads the signal share this bound.
pub const MAX_PHEROMONE: u64 = 10_000;

/// The default exploration floor of a [`StochasticForager`].
///
/// It is the baseline weight every live instance keeps, so a cold instance
/// stays selectable.
pub const DEFAULT_EXPLORATION_FLOOR: u64 = MAX_PHEROMONE / 20;

/// The default repellency threshold of a [`StochasticForager`].
///
/// It is the trail strength past which extra pheromone repels rather than
/// attracts. See the [`StochasticForager`] sources.
pub const DEFAULT_REPELLENCY_THRESHOLD: u64 = (MAX_PHEROMONE * 4) / 5;

/// A strategy that selects one instance among candidates of a servlet type.
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
/// separates the streams of two gateways that started together, and a
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

/// The default balancer, with stochastic, pheromone-proportional instance
/// selection.
///
/// The forager draws each instance with a probability proportional to its
/// foraging weight, which follows the stigmergic model the registry keeps. A
/// deterministic argmax would send every call to one of two equal trails,
/// and the draw splits that load across the eligible instances instead.
///
/// # Behavior
///
/// - **Exploitation**: higher pheromone raises an instance's draw probability.
/// - **Exploration**: the exploration floor keeps every live instance reachable.
/// - **Repellency**: past the repellency threshold, additional pheromone
///   *lowers* the draw weight, which caps the share of the wheel that one
///   instance can hold.
///
/// # Configuration
///
/// - [`DEFAULT_EXPLORATION_FLOOR`]: the floor is the baseline weight every
///   live instance keeps regardless of pheromone.
/// - [`DEFAULT_REPELLENCY_THRESHOLD`]: the threshold is the pheromone value
///   past which additional pheromone repels rather than attracts.
///
/// # Examples
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
/// - Grassé (1959), stigmergy as indirect coordination through a shared
///   medium: [doi:10.1007/BF02223791](https://doi.org/10.1007/BF02223791)
/// - Di Caro & Dorigo (1998), AntNet, which routes by stochastic (not argmax)
///   stigmergy: [doi:10.1613/jair.530](https://doi.org/10.1613/jair.530)
/// - Nakrani & Tovey (2004), honey-bee dynamic server allocation:
///   [doi:10.1177/105971230401200308](https://doi.org/10.1177/105971230401200308)
/// - Saran et al. (2007), termite trail pheromone that turns repellent
///   above ~10 pg/cm:
///   [doi:10.1007/s10886-006-9229-2](https://doi.org/10.1007/s10886-006-9229-2)
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
	/// A higher floor spreads selection wider, and a lower floor exploits
	/// strong trails harder.
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
		let attractive = match pheromone.checked_sub(self.repellency_threshold) {
			Some(excess) if excess > 0 => self.repellency_threshold.saturating_sub(excess),
			_ => pheromone,
		};

		self.exploration_floor.saturating_add(attractive)
	}
}

impl LoadBalancer for StochasticForager {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates.len() {
			0 => None,
			1 => Some(0),
			last_plus_one => {
				let weights = candidates.iter().map(|c| self.forage_weight(c.pheromone));
				let total = weights.fold(0, u64::saturating_add);
				let raw = splitmix64_next(&self.rng);

				// A zero floor with dead trails makes every weight zero, so the
				// draw is uniform.
				let Some(draw) = raw.checked_rem(total) else {
					return (raw as usize).checked_rem(last_plus_one);
				};

				let mut cumulative = 0u64;
				for (index, candidate) in candidates.iter().enumerate() {
					cumulative = cumulative.saturating_add(self.forage_weight(candidate.pheromone));
					if draw < cumulative {
						return Some(index);
					}
				}
				last_plus_one.checked_sub(1)
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
		match candidates {
			[] => None,
			[_] => Some(0),
			[first, second] => Some(usize::from(second.pheromone > first.pheromone)),
			all => {
				// One 64-bit draw splits into a uniform distinct pair: `second`
				// comes from `[0, n-1)` and shifts past `first`.
				let n = all.len();
				let draw = splitmix64_next(&self.rng);
				let others = n.checked_sub(1)?;
				let first = ((draw >> 32) as usize).checked_rem(n)?;
				let offset = ((draw & u64::from(u32::MAX)) as usize).checked_rem(others)?;
				let second = offset.checked_add(usize::from(offset >= first))?;

				if all.get(first)?.pheromone >= all.get(second)?.pheromone {
					Some(first)
				} else {
					Some(second)
				}
			}
		}
	}
}

/// A round-robin balancer that cycles through instances in order and
/// ignores pheromone.
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
		(count as usize).checked_rem(candidates.len())
	}
}

/// Whether a runtime has entered drain.
///
/// Every clone of the handle shares one flag, so its readers agree:
///
/// - The hive control plane refuses each command that yields to load.
/// - [`Hive::is_draining`](crate::colony::hive::Hive::is_draining) reports the flag.
///
/// The hive drain aborts the scaling loop and the re-announce loop through the
/// runtime's [`TaskGroup`] before it waits on commands in flight.
///
/// Drain is terminal. A runtime that has entered it stays in it.
#[derive(Clone, Default)]
pub struct DrainMode(Arc<AtomicBool>);

impl DrainMode {
	/// Enters drain.
	pub fn begin(&self) {
		self.0.store(true, Ordering::Release);
	}

	/// Returns `true` once drain has begun.
	#[must_use]
	pub fn is_draining(&self) -> bool {
		self.0.load(Ordering::Acquire)
	}
}

/// The background tasks one runtime started.
///
/// A runtime keeps one group and puts every task it spawns in it, so one call
/// stops that work when the runtime stops. The handle is shared, so a context
/// handed to a request handler can adopt work the handler starts.
///
/// # Single spawn path
///
/// A task spawned outside the group runs past the stop that was meant to
/// end it (CWE-772), which is why the group is the only spawn path these
/// runtimes offer.
#[derive(Clone, Default)]
pub struct TaskGroup(Arc<Mutex<TaskGroupState>>);

/// The handles of the tasks that run, and whether the group has stopped.
#[derive(Default)]
struct TaskGroupState {
	running: Vec<rt::JoinHandle>,
	stopped: bool,
}

impl TaskGroup {
	/// Takes ownership of `handle`, and releases each handle whose task ended.
	///
	/// A stopped group aborts `handle` on arrival, so work that starts while
	/// the runtime stops ends with the stop (CWE-772). The sweep bounds
	/// the group by the tasks that still run, which keeps a runtime that
	/// spawns per request at the size of its live work.
	pub fn adopt(&self, handle: rt::JoinHandle) {
		let mut state = self.state();
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
	/// A stop is terminal: a later [`TaskGroup::spawn`] aborts on
	/// arrival, so the stop reaches every task the group starts.
	pub fn abort_all(&self) {
		let mut state = self.state();
		state.stopped = true;
		for task in state.running.drain(..) {
			rt::abort(&task);
		}
	}

	/// The group state, recovered from a poisoned lock because every write
	/// under the guard leaves a whole handle list and a whole flag.
	fn state(&self) -> MutexGuard<'_, TaskGroupState> {
		self.0.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

#[cfg(test)]
mod tests {
	use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use core::time::Duration;

	use std::collections::HashSet;
	use std::panic::{catch_unwind, AssertUnwindSafe};

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

	/// Poisons the group lock, as a task that panics while it holds the
	/// guard would.
	fn poison(group: &TaskGroup) {
		let panicked = catch_unwind(AssertUnwindSafe(|| {
			let _held = group.0.lock().expect("the lock is live until this panic");
			panic!("poison the task group lock");
		}));

		assert!(panicked.is_err());
		assert!(group.0.is_poisoned());
	}

	/// A span longer than any test moves its clock. A task that sleeps it out
	/// and then finishes was never stopped.
	const LONG_RUN: Duration = Duration::from_secs(30);

	/// The pause between two beats of the task under test.
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

	/// The group that owns a beat ends it even past the beat's own checks,
	/// so work cannot outlast the stop that withdrew its routes (CWE-362).
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

	/// A poisoned lock still holds every handle the group adopted, so the stop
	/// reaches them all (CWE-772).
	#[tokio::test(start_paused = true)]
	async fn stopping_a_poisoned_group_aborts_the_work_it_owns() {
		static FINISHED: AtomicBool = AtomicBool::new(false);

		let group = TaskGroup::default();
		group.spawn(async {
			tokio::time::sleep(LONG_RUN).await;
			FINISHED.store(true, Ordering::SeqCst);
		});
		tokio::task::yield_now().await;
		poison(&group);

		group.abort_all();
		advance_past(LONG_RUN * 2).await;
		assert!(!FINISHED.load(Ordering::SeqCst));
	}

	/// A poisoned lock carries no damaged state, so a live group still runs
	/// the work it adopts.
	#[tokio::test(start_paused = true)]
	async fn a_poisoned_group_runs_the_work_it_adopts() {
		static FINISHED: AtomicBool = AtomicBool::new(false);

		let group = TaskGroup::default();
		poison(&group);

		group.spawn(async {
			tokio::time::sleep(BEAT).await;
			FINISHED.store(true, Ordering::SeqCst);
		});
		tokio::task::yield_now().await;

		advance_past(BEAT * 8).await;
		assert!(FINISHED.load(Ordering::SeqCst));
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
