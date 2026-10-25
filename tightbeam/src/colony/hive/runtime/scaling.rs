//! The hive auto-scaling loop decides a scale per servlet type and fans each
//! change out to the cluster.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::colony::common::{ScalingDecision, ScalingMetrics, ServletChange, ServletScaleConfig, TaskGroup};
use crate::colony::hive::runtime::{ClusterLink, HiveContextImpl, HiveInstances};
use crate::colony::hive::{HashMapRegistry, HiveConfig, ServletRegistration, ServletRegistry, SpawnerFn};
use crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS;
use crate::runtime::rt;
use crate::trace::TraceCollector;
use crate::transport::{MessageEmitter, Protocol};
use crate::urn::Urn;
use crate::utils::time::{Clock, MonotonicInstant};
use crate::utils::BasisPoints;
use crate::TightBeamError;

/// The shared handles that the hive auto-scaling loop runs on.
pub struct ScalingLoop<P: Protocol> {
	/// The registered servlet instances, keyed by instance URN bytes.
	pub servlets: Arc<HashMapRegistry>,
	/// The per-type spawners that a scale-up calls.
	pub spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// The hive-level trace collector, shared with each spawned servlet.
	pub trace: Arc<TraceCollector>,
	/// The aggregate utilization, published for manage-path backpressure.
	pub utilization: Arc<AtomicU16>,
	/// The per-instance utilization samples, keyed by instance URN bytes.
	pub utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	/// The gateways that receive scaling address updates.
	pub cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	/// The intra-hive route maps, updated when instances appear or leave.
	pub hive_context: Arc<HiveContextImpl<P>>,
	/// The hive control-plane address that the hive URN derives from.
	///
	/// It is [`None`] for a hive with no control plane, which scales its own
	/// servlets but announces to no cluster.
	pub hive_addr: Option<P::Address>,
	/// The hive configuration, which carries the scaling thresholds, the
	/// cooldowns, and the notify retry policy.
	pub config: HiveConfig,
	/// The owner of the gateway notifications that this loop starts.
	pub tasks: TaskGroup,
}

impl<P> ScalingLoop<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	/// Spawns the loop that evaluates each servlet type once per cooldown,
	/// scales its instances, and publishes the hive's aggregate utilization.
	pub fn spawn(self) -> rt::JoinHandle {
		let ScalingLoop {
			servlets,
			spawners,
			trace,
			utilization,
			utilization_map,
			cluster_addrs,
			hive_context,
			hive_addr,
			config,
			tasks,
		} = self;

		let config = Arc::new(config);
		let link = hive_addr.map(|addr| {
			ClusterLink::<P>::new(Arc::clone(&servlets), Arc::clone(&cluster_addrs), addr, Arc::clone(&config))
		});
		let evaluation_period = config.scaling.cooldown;
		let task = ScalingTask {
			hive_urn: hive_addr.and_then(|addr| config.hive_urn(addr)).map(Arc::new),
			servlets,
			trace,
			utilization,
			utilization_map,
			hive_context,
			link,
			config,
			tasks,
		};

		rt::spawn(async move {
			let clock = Arc::clone(&task.config.clock);
			let mut scaled_up = Cooldowns::new(Arc::clone(&clock));
			let mut scaled_down = Cooldowns::new(Arc::clone(&clock));

			loop {
				clock.sleep(evaluation_period).await;

				let mut hive_load = TypeLoad::default();
				for (servlet_type, spawner) in spawners.iter() {
					let scale = task.config.scaling.scale_config(servlet_type);
					let load = task.type_load(servlet_type.type_prefix_bytes());
					let metrics = ScalingMetrics {
						servlet_type: servlet_type.clone(),
						utilization: load.utilization(),
						current_instances: load.instances,
						config: scale,
					};

					hive_load.absorb(&load);

					match metrics.decide() {
						ScalingDecision::ScaleUp => task.scale_up(servlet_type, spawner, scale, &mut scaled_up).await,
						ScalingDecision::ScaleDown => task.scale_down(servlet_type, scale, &mut scaled_down),
						ScalingDecision::Hold => {}
					}
				}

				task.utilization.store(hive_load.utilization().get(), Ordering::Relaxed);
			}
		})
	}
}

/// The instance count and the summed utilization of one servlet type.
///
/// The two numbers are only meaningful together: a mean over the wrong
/// count reads as a different load. One value carries both, so the division
/// stays with the pair it divides.
#[derive(Default)]
struct TypeLoad {
	instances: usize,
	utilization_sum: u64,
}

impl TypeLoad {
	/// Adds one type's load into this running hive total.
	fn absorb(&mut self, load: &Self) {
		self.instances = self.instances.saturating_add(load.instances);
		self.utilization_sum = self.utilization_sum.saturating_add(load.utilization_sum);
	}

	/// The mean utilization across the counted instances.
	///
	/// A load of no instances reads as [`BasisPoints::MAX`], so backpressure
	/// and heartbeats report saturation while per-type scaling still sees the
	/// zero count and can spawn. A mean past the range of [`BasisPoints`]
	/// saturates.
	fn utilization(&self) -> BasisPoints {
		let instances = u64::try_from(self.instances).unwrap_or(u64::MAX);
		match NonZeroU64::new(instances) {
			None => BasisPoints::MAX,
			Some(count) => BasisPoints::saturating_from(self.utilization_sum / count),
		}
	}
}

/// Per-type stamps for one scale direction, read against the hive clock.
///
/// The loop writes a stamp only after a scale reaches the registry, so an
/// attempt that failed to spawn or found nothing to remove leaves the next
/// evaluation free to retry.
struct Cooldowns {
	stamps: HashMap<Vec<u8>, MonotonicInstant>,
	clock: Arc<dyn Clock>,
}

impl Cooldowns {
	fn new(clock: Arc<dyn Clock>) -> Self {
		Self { stamps: HashMap::new(), clock }
	}

	/// Whether `type_key` scaled within the last `cooldown`.
	fn active(&self, type_key: impl AsRef<[u8]>, cooldown: Duration) -> bool {
		let type_key = type_key.as_ref();
		let Some(stamp) = self.stamps.get(type_key) else {
			return false;
		};

		let age = self.clock.monotonic().saturating_duration_since(*stamp);

		age < cooldown
	}

	/// Records a scale of `type_key` at this instant.
	fn stamp(&mut self, type_key: impl Into<Vec<u8>>) {
		let type_key: Vec<u8> = type_key.into();
		self.stamps.insert(type_key, self.clock.monotonic());
	}
}

/// The resolved handles of one live scaling loop.
///
/// [`ScalingLoop`] names what the hive supplies. This names what the loop
/// body works with once [`ScalingLoop::spawn`] derives the hive URN and binds
/// the cluster link, so every scale decision reads one owner instead of a
/// parameter bundle rebuilt per attempt.
struct ScalingTask<P: Protocol> {
	servlets: Arc<HashMapRegistry>,
	trace: Arc<TraceCollector>,
	utilization: Arc<AtomicU16>,
	utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	hive_context: Arc<HiveContextImpl<P>>,
	link: Option<ClusterLink<P>>,
	hive_urn: Option<Arc<Urn<'static>>>,
	config: Arc<HiveConfig>,
	tasks: TaskGroup,
}

impl<P> ScalingTask<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	/// Whether local scaling must hold off.
	///
	/// A hive that derived its own URN attributes a scale change to itself.
	/// Without that identity, a gateway that watches this hive would keep a
	/// slate the hive has moved past, so scaling waits until the gateway list
	/// empties.
	fn scale_blocked(&self) -> bool {
		self.hive_urn.is_none() && self.link.as_ref().is_some_and(|link| link.has_gateways())
	}

	/// Counts the instances of one servlet type and sums their utilization.
	///
	/// An instance that reports no utilization falls back to its last
	/// sample, then to [`UNKNOWN_SERVLET_UTILIZATION_BPS`].
	fn type_load(&self, type_prefix: impl AsRef<[u8]>) -> TypeLoad {
		let type_prefix = type_prefix.as_ref();
		let mut load = TypeLoad::default();
		// Each sample is one `u16` insert, so a poisoned lock still holds a
		// whole map, and the loop reads the samples rather than drop them.
		let samples = self.utilization_map.lock().unwrap_or_else(PoisonError::into_inner);

		self.servlets.for_each_by_type(type_prefix, |key, reg| {
			load.instances = load.instances.saturating_add(1);

			let reported = reg.servlet.utilization().map(|bp| bp.get() as u64);
			let cached = samples.get(key).map(|&sample| sample as u64);
			let unknown = UNKNOWN_SERVLET_UTILIZATION_BPS as u64;

			let utilization = reported.or(cached).unwrap_or(unknown);
			load.utilization_sum = load.utilization_sum.saturating_add(utilization);
		});

		load
	}

	/// Adds one instance of `servlet_type` and announces it.
	async fn scale_up(
		&self,
		servlet_type: &Urn<'static>,
		spawner: &SpawnerFn,
		scale: ServletScaleConfig,
		cooldowns: &mut Cooldowns,
	) {
		let type_key = servlet_type.canonical_bytes();
		if self.scale_blocked() || cooldowns.active(&type_key, scale.scale_up_cooldown()) {
			return;
		}

		let Ok(new_servlet) = (spawner)(Arc::clone(&self.trace)).await else {
			return;
		};

		let registration = ServletRegistration {
			servlet: new_servlet,
			spawner: Arc::clone(spawner),
			servlet_type: servlet_type.clone(),
		};

		// The registry takes the instance before the announcement, because
		// the notify failure path reconciles from the registry.
		let instances = HiveInstances::new(self.servlets.as_ref(), &self.hive_context);
		let Ok(placed) = instances.insert(registration) else {
			return;
		};

		// The slate leaves out an instance that names no signer, so the hive
		// announces only an instance that has a route.
		if let Some(added) = placed.into_servlet_info() {
			self.announce(ServletChange::Added(added));
		}
		cooldowns.stamp(type_key);
	}

	/// Removes one instance of `servlet_type` and announces its departure.
	fn scale_down(&self, servlet_type: &Urn<'static>, scale: ServletScaleConfig, cooldowns: &mut Cooldowns) {
		let type_key = servlet_type.canonical_bytes();
		if self.scale_blocked() || cooldowns.active(&type_key, scale.scale_down_cooldown()) {
			return;
		}

		let type_prefix = servlet_type.type_prefix_bytes();
		// `HashMap` order is unspecified, so scale-down picks any instance.
		let Some(key) = self.servlets.keys().into_iter().rfind(|k| k.starts_with(&type_prefix)) else {
			return;
		};

		let instances = HiveInstances::new(self.servlets.as_ref(), &self.hive_context);
		let Some((_removed_type, addr)) = instances.remove(&key) else {
			return;
		};

		let Ok(instance) = servlet_type.instance_urn(addr.as_ref()) else {
			return;
		};

		self.announce(ServletChange::Removed(instance));
		cooldowns.stamp(type_key);
	}

	/// Announces one slate change to every registered gateway.
	///
	/// A hive with no control plane reaches no gateway, so the change stays
	/// local to its own registry.
	fn announce(&self, change: ServletChange) {
		let Some(link) = self.link.as_ref() else {
			return;
		};

		link.notify_scaling(&self.tasks, self.hive_urn.as_ref(), change);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tb_cases;
	use crate::utils::time::ManualClock;

	/// The cooldown every stamp in this module holds for.
	const COOLDOWN: Duration = Duration::from_secs(30);

	/// A clock that moves only when the test advances it.
	fn manual_clock() -> Arc<ManualClock> {
		Arc::new(ManualClock::default())
	}

	/// Cooldowns on `clock`, with the `echo` type stamped at its current
	/// instant.
	fn stamped_cooldowns(clock: &Arc<ManualClock>) -> Cooldowns {
		let mut cooldowns = Cooldowns::new(Arc::clone(clock) as Arc<dyn Clock>);
		cooldowns.stamp(b"echo".as_slice());
		cooldowns
	}

	// A scale holds its type for the cooldown on the hive clock, and the
	// type frees the moment that clock reaches the cooldown.
	tb_cases! {
		fn a_cooldown_runs_on_the_hive_clock((advance, active): (Duration, bool)) {
			let clock = manual_clock();
			let cooldowns = stamped_cooldowns(&clock);

			clock.advance(advance);

			assert_eq!(cooldowns.active(b"echo", COOLDOWN), active);
		}

		cases {
			one_millisecond_short => (COOLDOWN.saturating_sub(Duration::from_millis(1)), true),
			at_the_cooldown => (COOLDOWN, false),
		}
	}

	// A load reads as the mean of its instances' basis points. Each case is
	// an `(instances, utilization_sum, expected_bps)` row.
	tb_cases! {
		fn aggregate_utilization_means_across_all_instances((instances, utilization_sum, expected): (usize, u64, u16)) {
			let load = TypeLoad { instances, utilization_sum };

			assert_eq!(load.utilization().get(), expected);
		}

		cases {
			with_no_instances_saturates => (0, 0, 10_000),
			with_every_instance_idle => (4, 0, 0),
			with_one_uniform_mean => (4, 20_000, 5_000),
			with_one_loaded_type_and_one_idle => (2, 10_000, 5_000),
			with_every_instance_fully_loaded => (4, 40_000, 10_000),
		}
	}

	// A mean of 65,536 basis points is past the `u16` range, and it reads as
	// saturation.
	#[test]
	fn a_mean_past_the_u16_range_reads_as_saturation() {
		let load = TypeLoad { instances: 2, utilization_sum: 131_072 };

		assert_eq!(load.utilization(), BasisPoints::MAX);
	}
}
