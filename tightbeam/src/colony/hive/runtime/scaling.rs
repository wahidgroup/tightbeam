//! Hive auto-scaling loop: per-type scale decisions and cluster fan-out.

use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::colony::common::{
	aggregate_utilization, ScalingDecision, ScalingMetrics, ServletChange, ServletInfo, ServletScaleConfig, TaskGroup,
};
use crate::colony::hive::runtime::{ClusterLink, HiveContextImpl, HiveInstances};
use crate::colony::hive::{HashMapRegistry, HiveConfig, ServletRegistration, ServletRegistry, SpawnerFn};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::trace::TraceCollector;
use crate::transport::{MessageEmitter, Protocol, X509ClientConfig};
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::TightBeamError;

/// Shared handles for the hive auto-scaling loop.
pub struct ScalingLoop<P: Protocol> {
	/// Registered servlet instances keyed by instance URN bytes.
	pub servlets: Arc<HashMapRegistry>,
	/// Per-type spawners used when scaling up.
	pub spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// Hive-level instrumentation collector.
	pub trace: Arc<TraceCollector>,
	/// Aggregate utilization published for manage-path backpressure.
	pub utilization: Arc<AtomicU16>,
	/// Per-instance utilization samples keyed by instance URN bytes.
	pub utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	/// Gateways that receive scaling address updates.
	pub cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	/// Intra-hive route maps updated when instances appear or leave.
	pub hive_context: Arc<HiveContextImpl<P>>,
	/// Hive control-plane address that mints the hive URN.
	pub hive_addr: P::Address,
	/// Scaling thresholds, cooldowns, and notify retry policy.
	pub config: HiveConfig,
	/// Owner of the gateway notifications this loop starts.
	pub tasks: TaskGroup,
}

impl<P> ScalingLoop<P>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	/// Runs the cooling loop that scales servlet instances per type.
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
		let link = ClusterLink::<P>::new(
			Arc::clone(&servlets),
			Arc::clone(&cluster_addrs),
			hive_addr,
			Arc::clone(&config),
		);
		let evaluation_period = config.scaling.cooldown;
		let task = ScalingTask {
			hive_urn: config.hive_urn(hive_addr).map(Arc::new),
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
			let mut scaled_up = Cooldowns::default();
			let mut scaled_down = Cooldowns::default();

			loop {
				tokio::time::sleep(evaluation_period).await;

				let mut hive_load = TypeLoad::default();
				for (servlet_type, spawner) in spawners.iter() {
					let scale = task.config.scaling.scale_config(servlet_type);
					let load = task.type_load(&servlet_type.type_prefix_bytes());
					let metrics = ScalingMetrics {
						servlet_type: servlet_type.clone(),
						utilization: load.utilization(),
						current_instances: load.instances,
						config: scale,
					};

					hive_load.absorb(&load);

					match ScalingDecision::evaluate(&metrics) {
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

	/// Mean utilization across the counted instances.
	fn utilization(&self) -> BasisPoints {
		aggregate_utilization(self.utilization_sum, self.instances)
	}
}

/// Per-type stamps for one scale direction.
///
/// A stamp is written where a scale reached the registry, so an attempt
/// that failed to spawn or found nothing to remove leaves the next
/// evaluation free to retry.
#[derive(Default)]
struct Cooldowns(HashMap<Vec<u8>, Instant>);

impl Cooldowns {
	/// Whether `type_key` scaled within the last `cooldown`.
	fn active(&self, type_key: &[u8], cooldown: Duration) -> bool {
		self.0.get(type_key).is_some_and(|stamp| stamp.elapsed() < cooldown)
	}

	/// Records a scale of `type_key` at this instant.
	fn stamp(&mut self, type_key: Vec<u8>) {
		self.0.insert(type_key, Instant::now());
	}
}

/// One running scaling loop's resolved handles.
///
/// [`ScalingLoop`] names what the hive supplies. This names what the loop
/// body works with once the hive URN is minted and the cluster link is
/// bound, so every scale decision reads one owner instead of a parameter
/// bundle rebuilt per attempt.
struct ScalingTask<P: Protocol> {
	servlets: Arc<HashMapRegistry>,
	trace: Arc<TraceCollector>,
	utilization: Arc<AtomicU16>,
	utilization_map: Arc<Mutex<HashMap<Vec<u8>, u16>>>,
	hive_context: Arc<HiveContextImpl<P>>,
	link: ClusterLink<P>,
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
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	/// Whether local scaling must hold off.
	///
	/// A hive that minted its own URN attributes a scale change to itself.
	/// Without that identity a watching gateway would keep a slate this
	/// hive has moved past, so scaling waits until the gateway list empties.
	fn scale_blocked(&self) -> bool {
		self.hive_urn.is_none() && self.link.has_gateways()
	}

	/// Instance count and summed utilization for one servlet type.
	///
	/// An instance that reports no utilization falls back to its last
	/// sample, then to [`UNKNOWN_SERVLET_UTILIZATION_BPS`].
	fn type_load(&self, type_prefix: &[u8]) -> TypeLoad {
		let mut load = TypeLoad::default();
		let util_guard = self.utilization_map.lock();

		self.servlets.for_each_by_type(type_prefix, |key, reg| {
			load.instances += 1;

			let reported = reg.servlet.utilization().map(|bp| bp.get() as u64);
			let cached = util_guard.as_ref().ok().and_then(|g| g.get(key).map(|&v| v as u64));
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
		if self.scale_blocked() || cooldowns.active(&type_key, scale.scale_up_cooldown) {
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

		// Register before announcing: the notify failure path reconciles from the registry.
		let instances = HiveInstances::new(&self.servlets, &self.hive_context);
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
		if self.scale_blocked() || cooldowns.active(&type_key, scale.scale_down_cooldown) {
			return;
		}

		let type_prefix = servlet_type.type_prefix_bytes();
		// HashMap iteration order is unspecified, so the removed instance is arbitrary.
		let Some(key) = self.servlets.keys().into_iter().rfind(|k| k.starts_with(&type_prefix)) else {
			return;
		};

		let instances = HiveInstances::new(&self.servlets, &self.hive_context);
		let Some((_removed_type, addr)) = instances.remove(&key) else {
			return;
		};

		let Ok(instance) = servlet_type.instance_urn(addr.as_ref()) else {
			return;
		};

		let removed = ServletInfo { servlet_id: instance, address: addr.as_ref().to_vec() };
		self.announce(ServletChange::Removed(removed));
		cooldowns.stamp(type_key);
	}

	/// Announces one slate change to every registered gateway.
	fn announce(&self, change: ServletChange) {
		self.link.notify_scaling(&self.tasks, self.hive_urn.as_ref(), change);
	}
}
