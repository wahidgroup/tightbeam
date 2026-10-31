//! The load balancers that pick the servlet instance a gateway forwards work
//! to, and the pheromone signal they read.

use core::sync::atomic::{AtomicU64, Ordering};

use std::sync::Arc;

use crate::constants::{SPLITMIX64_GAMMA, SPLITMIX64_MIX_1, SPLITMIX64_MIX_2};
use crate::random::{generate_nonce, placement_entropy};

/// The pheromone signal one servlet instance carries into a balancing round.
#[derive(Debug, Clone)]
pub struct InstanceMetrics {
	/// The key that names the instance in the balancing round, which holds
	/// the canonical instance-URN bytes. Balancers treat these bytes as opaque.
	///
	/// The key is owned because a borrowed key would put a lifetime on the
	/// public [`LoadBalancer`] trait and every implementor. Canonical
	/// instance-URN bytes are short, so the per-round copy is bounded and
	/// cheaper than that API cost.
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
	let drawn = generate_nonce::<8>(None).ok();
	seed_of(sequence, drawn)
}

/// The seed at `sequence`, where `drawn` holds eight octets of the random
/// source, or `None` when the source refused the draw.
///
/// A refused draw takes [`placement_entropy`] in place of the octets, so
/// gateways that lose the source together seed apart. That entropy holds one
/// value per process, so the sequence keeps the seeds of one process distinct.
fn seed_of(sequence: u64, drawn: Option<[u8; 8]>) -> u64 {
	let entropy = drawn.map_or_else(placement_entropy, u64::from_le_bytes);
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
/// # use tightbeam::colony::cluster::StochasticForager;
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
///   [doi:10.1177/105971230401200308][nakrani-2004]
/// - Saran et al. (2007), termite trail pheromone that turns repellent
///   above ~10 pg/cm:
///   [doi:10.1007/s10886-006-9229-2](https://doi.org/10.1007/s10886-006-9229-2)
///
/// [nakrani-2004]: https://doi.org/10.1177/105971230401200308
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
/// - The probe also favors instances with a stronger pheromone trail.
/// - A tie keeps the first of the two draws, so equal trails share the load.
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

#[cfg(test)]
impl PowerOfTwoChoices {
	/// A balancer whose draws start from `seed`, so a test replays its picks.
	pub(crate) fn with_seed(seed: u64) -> Self {
		Self { rng: Arc::new(AtomicU64::new(seed)) }
	}
}

impl LoadBalancer for PowerOfTwoChoices {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		match candidates {
			[] => None,
			[_] => Some(0),
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

#[cfg(test)]
mod tests {
	use std::collections::HashSet;

	use super::{
		seed_of, InstanceMetrics, LoadBalancer, PowerOfTwoChoices, RoundRobin, StochasticForager,
		DEFAULT_EXPLORATION_FLOOR, DEFAULT_REPELLENCY_THRESHOLD, MAX_PHEROMONE,
	};
	use crate::tb_cases;

	fn pool(pheromones: impl AsRef<[u64]>) -> Vec<InstanceMetrics> {
		let pheromones = pheromones.as_ref();
		pheromones
			.iter()
			.enumerate()
			.map(|(index, &pheromone)| InstanceMetrics { instance_key: vec![index as u8], pheromone })
			.collect()
	}

	/// The pheromone of a trail midway to saturation.
	const HALF: u64 = MAX_PHEROMONE / 2;

	/// The index that `balancer` picks in each of `count` draws from the pool
	/// of `pheromones`.
	fn draws(balancer: &dyn LoadBalancer, pheromones: impl AsRef<[u64]>, count: usize) -> Vec<usize> {
		let candidates = pool(pheromones);
		let picks: Option<Vec<usize>> = (0..count).map(|_| balancer.select(&candidates)).collect();
		picks.expect("a pool of one or more candidates selects")
	}

	/// The count of picks of each candidate of `pheromones` over `count`
	/// draws.
	fn histogram<const N: usize>(balancer: &dyn LoadBalancer, pheromones: [u64; N], count: usize) -> [usize; N] {
		let mut counts = [0usize; N];
		for index in draws(balancer, pheromones, count) {
			counts[index] += 1;
		}

		counts
	}

	/// The candidates of `pheromones` that `balancer` picks at least once over
	/// `count` draws.
	fn distinct(balancer: &dyn LoadBalancer, pheromones: impl AsRef<[u64]>, count: usize) -> HashSet<usize> {
		draws(balancer, pheromones, count).into_iter().collect()
	}

	// An empty pool selects nothing and a pool of one selects its sole
	// candidate, under each balancer.
	tb_cases! {
		fn a_degenerate_pool_selects((balancer, size, selected): (Box<dyn LoadBalancer>, usize, Option<usize>)) {
			let candidates = pool(vec![HALF; size]);
			assert_eq!(balancer.select(&candidates), selected);
		}
		cases {
			forager_empty => (Box::new(StochasticForager::with_seed(1)), 0, None),
			p2c_empty => (Box::new(PowerOfTwoChoices::with_seed(1)), 0, None),
			round_robin_empty => (Box::new(RoundRobin::default()), 0, None),
			forager_sole => (Box::new(StochasticForager::with_seed(1)), 1, Some(0)),
			p2c_sole => (Box::new(PowerOfTwoChoices::with_seed(1)), 1, Some(0)),
			round_robin_sole => (Box::new(RoundRobin::default()), 1, Some(0)),
		}
	}

	/// The forager spreads its draws over equal trails, so no trail of four
	/// takes fewer than half its even share of 2,000.
	#[test]
	fn forager_spreads_equal_trails_across_all() {
		let forager = StochasticForager::with_seed(0xF0);
		let counts = histogram(&forager, [HALF; 4], 8_000);
		assert!(counts.into_iter().min() > Some(1_000));
	}

	/// The forager draws a stronger trail more often than a weaker one.
	#[test]
	fn forager_favors_stronger_trail() {
		let forager = StochasticForager::with_seed(0xA1);
		let [weaker, stronger] = histogram(&forager, [MAX_PHEROMONE / 10, DEFAULT_REPELLENCY_THRESHOLD], 8_000);
		assert!(stronger > weaker);
	}

	/// The exploration floor keeps a trail of zero pheromone reachable beside
	/// a saturated one.
	#[test]
	fn forager_floor_keeps_zero_trail_reachable() {
		let forager = StochasticForager::with_seed(0xB2);
		let [zero, _saturated] = histogram(&forager, [0, MAX_PHEROMONE], 8_000);
		assert!(zero > 0);
	}

	/// Repellency caps a saturated trail, so it draws no more often than a
	/// trail at the repellency peak.
	#[test]
	fn forager_repellency_caps_saturated_share() {
		let forager = StochasticForager::with_seed(0xC3);
		let [saturated, peak] = histogram(&forager, [MAX_PHEROMONE, DEFAULT_REPELLENCY_THRESHOLD], 8_000);
		assert!(peak >= saturated);
	}

	/// Power of two choices picks the stronger of a pair.
	#[test]
	fn p2c_picks_stronger_of_two() {
		let balancer = PowerOfTwoChoices::with_seed(0x5A);
		let candidates = pool([100, MAX_PHEROMONE]);
		assert_eq!(balancer.select(&candidates), Some(1));
	}

	/// Each default balancer seeds a stream of its own, so two balancers that
	/// start together draw apart over one pool of equal trails.
	#[test]
	fn each_default_p2c_balancer_draws_a_stream_of_its_own() {
		let (first, second) = (PowerOfTwoChoices::default(), PowerOfTwoChoices::default());
		let streams = (draws(&first, [HALF; 64], 16), draws(&second, [HALF; 64], 16));
		assert_ne!(streams.0, streams.1);
	}

	// Each balancer that draws reaches every candidate of equal trails, and
	// the forager reaches every dead trail at a zero floor.
	tb_cases! {
		fn every_index_is_drawn((balancer, pheromones, count): (Box<dyn LoadBalancer>, Vec<u64>, usize)) {
			let drawn = distinct(&*balancer, &pheromones, count);
			assert_eq!(drawn.len(), pheromones.len());
		}
		cases {
			p2c_two_equal => (Box::new(PowerOfTwoChoices::with_seed(0x5B)), vec![HALF; 2], 256),
			p2c_eight_equal => (Box::new(PowerOfTwoChoices::with_seed(0x5C)), vec![HALF; 8], 4_096),
			forager_dead_trails_at_a_zero_floor => (
				Box::new(StochasticForager::with_seed(0xF6).with_exploration_floor(0)),
				vec![0, 0, 0],
				256,
			),
		}
	}

	/// Round robin cycles through the indices in order.
	#[test]
	fn round_robin_cycles_indices() {
		let balancer = RoundRobin::default();
		let picks = draws(&balancer, [HALF; 3], 6);
		assert_eq!(picks, [0, 1, 2, 0, 1, 2]);
	}

	/// A forager whose floor is zero and whose repellency peaks at half
	/// saturation.
	fn tuned() -> StochasticForager {
		let forager = StochasticForager::with_seed(0xE5).with_exploration_floor(0);
		forager.with_repellency_threshold(HALF)
	}

	// The weight of a trail is the floor plus its pheromone up to the
	// repellency threshold, under the default knobs and under tuned ones.
	tb_cases! {
		fn the_forage_weight_follows_the_floor_and_threshold(
			(forager, pheromone, weight): (StochasticForager, u64, u64)
		) {
			assert_eq!(forager.forage_weight(pheromone), weight);
		}
		cases {
			default_at_zero => (StochasticForager::with_seed(0xD4), 0, DEFAULT_EXPLORATION_FLOOR),
			default_at_the_threshold => (
				StochasticForager::with_seed(0xD4),
				DEFAULT_REPELLENCY_THRESHOLD,
				DEFAULT_EXPLORATION_FLOOR + DEFAULT_REPELLENCY_THRESHOLD,
			),
			tuned_at_zero => (tuned(), 0, 0),
			tuned_at_half => (tuned(), HALF, HALF),
			tuned_at_max => (tuned(), MAX_PHEROMONE, 0),
		}
	}

	/// Past the repellency threshold the default weight declines, and it stays
	/// at the exploration floor or above.
	#[test]
	fn a_default_weight_declines_past_the_threshold_to_no_less_than_the_floor() {
		let forager = StochasticForager::with_seed(0xD4);
		let peak = DEFAULT_EXPLORATION_FLOOR + DEFAULT_REPELLENCY_THRESHOLD;

		let saturated = forager.forage_weight(MAX_PHEROMONE);
		assert!((DEFAULT_EXPLORATION_FLOOR..peak).contains(&saturated));
	}

	/// A refused draw seeds from the entropy of the process, so the first
	/// balancer of a gateway seeds apart from the bare sequence at 0, which
	/// every process repeats.
	#[test]
	fn a_refused_draw_seeds_apart_from_the_sequence_every_process_repeats() {
		let seed = seed_of(0, None);
		assert_ne!(seed, 0);
	}
}
