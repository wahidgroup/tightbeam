//! Hive auto-scaling loop: per-type scale decisions and cluster fan-out.

use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use crate::colony::common::{
	aggregate_utilization, canonical_bytes, type_prefix_bytes, ScalingDecision, ScalingMetrics, ServletInfo,
	ServletScaleConfig,
};
use crate::colony::hive::runtime::{insert_instance, instance_urn, notify_cluster, remove_instance, HiveContextImpl};
use crate::colony::hive::{HashMapRegistry, HiveConfig, ServletRegistration, ServletRegistry, SpawnerFn};
use crate::colony::servlet::servlet_runtime::rt;
use crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::trace::TraceCollector;
use crate::transport::{MessageEmitter, Protocol, X509ClientConfig};
use crate::utils::urn::Urn;
use crate::TightBeamError;

/// Shared handles for the hive auto-scaling loop.
pub struct ScalingTaskCtx<P: Protocol> {
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
	/// Hive control-plane address used to mint the hive URN.
	pub hive_addr: P::Address,
	/// Scaling thresholds, cooldowns, and notify retry policy.
	pub config: HiveConfig,
}

/// Spawn the cooling-loop task that scales servlet instances per type.
pub fn spawn_scaling_task<P>(ctx: ScalingTaskCtx<P>) -> rt::JoinHandle
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	let ScalingTaskCtx {
		servlets,
		spawners,
		trace,
		utilization,
		utilization_map,
		cluster_addrs,
		hive_context,
		hive_addr,
		config,
	} = ctx;
	let config = Arc::new(config);
	let hive_urn = mint_hive_urn(hive_addr, &config);

	rt::spawn(async move {
		let mut last_scale_up: HashMap<Vec<u8>, Instant> = HashMap::new();
		let mut last_scale_down: HashMap<Vec<u8>, Instant> = HashMap::new();

		loop {
			tokio::time::sleep(config.scaling.cooldown).await;

			let scale_blocked = is_scale_blocked(hive_urn.is_none(), &cluster_addrs);
			let mut hive_total_util = 0u64;
			let mut hive_total_count = 0usize;
			for (servlet_type, spawner) in spawners.iter() {
				let type_key = canonical_bytes(servlet_type);
				let type_prefix = type_prefix_bytes(servlet_type);
				let scale_conf = scale_config_for(&config, servlet_type);
				let (count, util_sum) = collect_type_load(&servlets, &utilization_map, &type_prefix);

				hive_total_util += util_sum;
				hive_total_count += count;

				let metrics = ScalingMetrics {
					servlet_type: servlet_type.clone(),
					utilization: aggregate_utilization(util_sum, count),
					current_instances: count,
					config: scale_conf,
				};

				match ScalingDecision::evaluate(&metrics) {
					ScalingDecision::ScaleUp => {
						let scaled = try_scale_up::<P>(ScaleUp {
							gate: ScaleGate {
								scale_blocked,
								type_key: &type_key,
								cooldown: scale_conf.scale_up_cooldown,
								last_action: &last_scale_up,
							},
							servlets: &servlets,
							hive_context: &hive_context,
							cluster_addrs: &cluster_addrs,
							hive_addr,
							hive_urn: hive_urn.as_ref(),
							config: &config,
							trace: &trace,
							servlet_type,
							spawner,
						})
						.await;
						if scaled {
							last_scale_up.insert(type_key, Instant::now());
						}
					}
					ScalingDecision::ScaleDown => {
						let scaled = try_scale_down::<P>(ScaleDown {
							gate: ScaleGate {
								scale_blocked,
								type_key: &type_key,
								cooldown: scale_conf.scale_down_cooldown,
								last_action: &last_scale_down,
							},
							servlets: &servlets,
							hive_context: &hive_context,
							cluster_addrs: &cluster_addrs,
							hive_addr,
							hive_urn: hive_urn.as_ref(),
							config: &config,
							servlet_type,
						});
						if scaled {
							last_scale_down.insert(type_key, Instant::now());
						}
					}
					ScalingDecision::Hold => {}
				}
			}

			let aggregate = aggregate_utilization(hive_total_util, hive_total_count);
			utilization.store(aggregate.get(), Ordering::Relaxed);
		}
	})
}

/// Cooldown and announce-gate checks shared by scale-up and scale-down.
struct ScaleGate<'a> {
	scale_blocked: bool,
	type_key: &'a [u8],
	cooldown: Duration,
	last_action: &'a HashMap<Vec<u8>, Instant>,
}

/// Inputs for one scale-up attempt.
struct ScaleUp<'a, P: Protocol> {
	gate: ScaleGate<'a>,
	servlets: &'a Arc<HashMapRegistry>,
	hive_context: &'a Arc<HiveContextImpl<P>>,
	cluster_addrs: &'a Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	hive_urn: Option<&'a Arc<Urn<'static>>>,
	config: &'a Arc<HiveConfig>,
	trace: &'a Arc<TraceCollector>,
	servlet_type: &'a Urn<'static>,
	spawner: &'a SpawnerFn,
}

/// Inputs for one scale-down attempt.
struct ScaleDown<'a, P: Protocol> {
	gate: ScaleGate<'a>,
	servlets: &'a Arc<HashMapRegistry>,
	hive_context: &'a Arc<HiveContextImpl<P>>,
	cluster_addrs: &'a Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	hive_urn: Option<&'a Arc<Urn<'static>>>,
	config: &'a Arc<HiveConfig>,
	servlet_type: &'a Urn<'static>,
}

fn mint_hive_urn(hive_addr: impl Into<Vec<u8>>, config: &HiveConfig) -> Option<Arc<Urn<'static>>> {
	// Mint once from the control address for scaling updates. A non-mintable
	// address disables cluster notify instead of announcing a bad URN.
	let bytes: Vec<u8> = hive_addr.into();
	let addr = String::from_utf8(bytes).ok()?;
	let hive = config.namespace.hive(addr).ok()?;

	Some(Arc::new(hive))
}

fn is_scale_blocked<A>(hive_urn_missing: bool, cluster_addrs: &RwLock<Vec<A>>) -> bool {
	// Block local scale when gateways exist but hive identity cannot be announced.
	if !hive_urn_missing {
		return false;
	}

	match cluster_addrs.read() {
		Ok(guard) => !guard.is_empty(),
		Err(_) => true,
	}
}

fn scale_config_for(config: &HiveConfig, servlet_type: &Urn<'_>) -> ServletScaleConfig {
	config
		.scaling
		.overrides
		.get(servlet_type)
		.copied()
		.unwrap_or(config.scaling.default_scale)
}

fn collect_type_load(
	servlets: &HashMapRegistry,
	utilization_map: &Mutex<HashMap<Vec<u8>, u16>>,
	type_prefix: &[u8],
) -> (usize, u64) {
	let mut count = 0usize;
	let mut util_sum = 0u64;
	let util_guard = utilization_map.lock();

	servlets.for_each_by_type(type_prefix, |key, reg| {
		count += 1;

		let reported = reg.servlet.utilization().map(|bp| bp.get() as u64);
		let cached = util_guard.as_ref().ok().and_then(|g| g.get(key).map(|&v| v as u64));
		let unknown = UNKNOWN_SERVLET_UTILIZATION_BPS as u64;

		util_sum += reported.or(cached).unwrap_or(unknown);
	});

	(count, util_sum)
}

fn cooldown_active(last_action: &HashMap<Vec<u8>, Instant>, type_key: &[u8], cooldown: Duration) -> bool {
	last_action.get(type_key).is_some_and(|stamp| stamp.elapsed() < cooldown)
}

async fn try_scale_up<P>(action: ScaleUp<'_, P>) -> bool
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	if !gate_allows(&action.gate) {
		return false;
	}

	let Ok(new_servlet) = (action.spawner)(Arc::clone(action.trace)).await else {
		return false;
	};

	let registration = ServletRegistration {
		servlet: new_servlet,
		spawner: Arc::clone(action.spawner),
		servlet_type: action.servlet_type.clone(),
	};

	// Register before announcing: the notify failure path reconciles from the registry.
	let Ok((instance, addr_bytes)) = insert_instance(&**action.servlets, &**action.hive_context, registration) else {
		return false;
	};

	announce_scale_change::<P>(
		action.servlets,
		action.cluster_addrs,
		action.hive_addr,
		action.hive_urn,
		action.config,
		ServletInfo { servlet_id: instance, address: addr_bytes.as_ref().to_vec() },
		true,
	);

	true
}

fn try_scale_down<P>(action: ScaleDown<'_, P>) -> bool
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	if !gate_allows(&action.gate) {
		return false;
	}

	let type_prefix = type_prefix_bytes(action.servlet_type);
	// HashMap iteration order is unspecified, so the removed instance is arbitrary.
	let Some(key) = action.servlets.keys().into_iter().rfind(|k| k.starts_with(&type_prefix)) else {
		return false;
	};

	let Some((_removed_type, addr)) = remove_instance(&**action.servlets, &**action.hive_context, &key) else {
		return false;
	};

	let Ok(instance) = instance_urn(action.servlet_type, addr.as_ref()) else {
		return false;
	};

	announce_scale_change::<P>(
		action.servlets,
		action.cluster_addrs,
		action.hive_addr,
		action.hive_urn,
		action.config,
		ServletInfo { servlet_id: instance, address: addr.as_ref().to_vec() },
		false,
	);

	true
}

fn gate_allows(gate: &ScaleGate<'_>) -> bool {
	if gate.scale_blocked {
		return false;
	}
	!cooldown_active(gate.last_action, gate.type_key, gate.cooldown)
}

fn announce_scale_change<P>(
	servlets: &Arc<HashMapRegistry>,
	cluster_addrs: &Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	hive_urn: Option<&Arc<Urn<'static>>>,
	config: &Arc<HiveConfig>,
	servlet_info: ServletInfo,
	is_added: bool,
) where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	TightBeamError: From<P::Error>,
{
	let Some(hive_urn) = hive_urn else {
		return;
	};

	notify_cluster::<P>(
		Arc::clone(servlets),
		Arc::clone(cluster_addrs),
		hive_addr,
		Arc::clone(hive_urn),
		servlet_info,
		is_added,
		Arc::clone(config),
	);
}
