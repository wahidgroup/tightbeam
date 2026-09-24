//! Hive auto-scaling loop: per-type scale decisions and cluster fan-out.

use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::colony::common::{
	aggregate_utilization, ScalingDecision, ScalingMetrics, ServletChange, ServletInfo, ServletScaleConfig, TaskGroup,
};
use crate::colony::hive::runtime::{ClusterLink, HiveContextImpl, HiveInstances};
use crate::colony::hive::{HashMapRegistry, HiveConfig, ServletRegistration, ServletRegistry, SpawnerFn};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::trace::TraceCollector;
use crate::transport::{MessageEmitter, Protocol};
use crate::utils::time::{Clock, MonotonicInstant};
use crate::utils::urn::Urn;
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
	P: Protocol<CryptoProvider = DefaultCryptoProvider>,
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	/// Spawns the loop that evaluates each servlet type once per cooldown and
	/// scales its instances.
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

/// Instance count and summed utilization over one servlet type.
///
/// The two numbers are only meaningful together: a mean over the wrong
/// count reads as a different load. Carrying them in one value keeps the
/// division with the pair it divides.
#[derive(Default)]
struct TypeLoad {
	instances: usize,
	utilization_sum: u64,
}

impl TypeLoad {
	/// Adds one type's load into this running hive total.
	fn absorb(&mut self, load: &Self) {
		self.instances += load.instances;
		self.utilization_sum += load.utilization_sum;
	}

	/// The mean utilization across the counted instances.
	fn utilization(&self) -> BasisPoints {
		aggregate_utilization(self.utilization_sum, self.instances)
	}
}

/// Per-type stamps for one scale direction, read against the hive clock.
///
/// A stamp is written where a scale reached the registry, so an attempt
/// that failed to spawn or found nothing to remove leaves the next
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

/// One running scaling loop's resolved handles.
///
/// [`ScalingLoop`] names what the hive supplies. This names what the loop
/// body works with once the hive URN is created and the cluster link is
/// bound, so every scale decision reads one owner instead of a parameter
/// bundle rebuilt per attempt.
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
	P: Protocol<CryptoProvider = DefaultCryptoProvider>,
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
	/// Without that identity a watching gateway would keep a slate this
	/// hive has moved past, so scaling waits until the gateway list empties.
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
		// whole map and the samples are read rather than dropped.
		let samples = self.utilization_map.lock().unwrap_or_else(PoisonError::into_inner);

		self.servlets.for_each_by_type(type_prefix, |key, reg| {
			load.instances += 1;

			let reported = reg.servlet.utilization().map(|bp| bp.get() as u64);
			let cached = samples.get(key).map(|&sample| sample as u64);
			let unknown = UNKNOWN_SERVLET_UTILIZATION_BPS as u64;

			load.utilization_sum += reported.or(cached).unwrap_or(unknown);
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
		let Ok((instance, addr_bytes)) = instances.insert(registration) else {
			return;
		};

		let added = ServletInfo { servlet_id: instance, address: addr_bytes.as_ref().to_vec() };
		self.announce(ServletChange::Added(added));
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

	/// Cooldowns on `clock`, with the `echo` type stamped now.
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
}
