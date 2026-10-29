//! The hive auto-scaling loop decides a scale per servlet type and fans each
//! change out to the cluster.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU16, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::basis_points::BasisPoints;
use crate::clock::{Clock, MonotonicInstant};
use crate::colony::hive::runtime::{
	ClusterLink, DrainMode, HiveContextImpl, HiveInstances, HiveRuntime, RemoveRefusal,
};
use crate::colony::hive::{
	HiveConfig, ScalingDecision, ScalingMetrics, ServletRegistration, ServletRegistry, ServletScaleConfig, SpawnerFn,
};
use crate::colony::protocol::{IssueClock, ServletChange};
use crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS;
use crate::instrumentation::events::{HIVE_SCALED, HIVE_SCALE_REFUSED};
use crate::runtime::{rt, TaskGroup};
use crate::trace::TraceCollector;
use crate::transport::multiplex::MuxCapable;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{MessageEmitter, Protocol};
use crate::urn::Urn;
use crate::TightBeamError;

/// The shared handles that the hive auto-scaling loop runs on.
///
/// [`Self::new`] alone builds one, from the runtime that owns the handles, so
/// the drain state and the servlets of a loop come from the same runtime.
pub struct ScalingLoop<P: Protocol, R: ServletRegistry> {
	/// The registered servlet instances, keyed by instance URN bytes.
	servlets: Arc<R>,
	/// The per-type spawners that a scale-up calls.
	spawners: Arc<HashMap<Urn<'static>, SpawnerFn>>,
	/// The hive-level trace collector, shared with each spawned servlet.
	trace: Arc<TraceCollector>,
	/// The aggregate utilization, published for manage-path backpressure.
	utilization: Arc<AtomicU16>,
	/// The gateways that receive scaling address updates.
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	/// The intra-hive route maps, updated when instances appear or leave.
	hive_context: Arc<HiveContextImpl<P>>,
	/// The admission lock of the hive's instance set, which the control
	/// plane shares.
	admission: Arc<Mutex<()>>,
	/// The drain state, which a scale-up reads as it inserts its instance.
	drain: DrainMode,
	/// The hive control-plane address that the hive URN derives from.
	///
	/// It is [`None`] for a hive with no control plane, which scales its own
	/// servlets but announces to no cluster.
	hive_addr: Option<P::Address>,
	/// The hive configuration, which carries the scaling thresholds, the
	/// cooldowns, and the notify retry policy.
	config: HiveConfig,
	/// The owner of the gateway notifications that this loop starts.
	tasks: TaskGroup,
	/// The issue times of the hive's control frames, which the link this loop
	/// builds stamps on its scaling updates.
	issue_clock: Arc<IssueClock>,
}

impl<P: Protocol, R: ServletRegistry> ScalingLoop<P, R> {
	/// The scaling loop of `runtime`, whose control plane, when it serves one,
	/// listens at `hive_addr`.
	pub(crate) fn new(runtime: &HiveRuntime<P, R>, hive_addr: Option<P::Address>) -> Self {
		let shares = runtime.shares();

		Self {
			servlets: Arc::clone(shares.servlets),
			spawners: Arc::clone(shares.spawners),
			trace: Arc::clone(shares.trace),
			utilization: Arc::clone(shares.utilization),
			cluster_addrs: Arc::clone(shares.cluster_addrs),
			hive_context: Arc::clone(shares.hive_context),
			admission: Arc::clone(shares.admission),
			drain: shares.drain.clone(),
			hive_addr,
			config: shares.config.clone(),
			tasks: shares.tasks.clone(),
			issue_clock: Arc::clone(shares.issue_clock),
		}
	}
}

impl<P, R> ScalingLoop<P, R>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + MuxCapable + EncryptedProtocolState + Send + Sync + 'static,
	R: ServletRegistry + 'static,
	TightBeamError: From<P::Error>,
{
	/// Spawns the loop that evaluates each servlet type once per cooldown,
	/// scales its instances, and publishes the hive's aggregate utilization.
	///
	/// A trace that refuses the record of a scale ends the loop, which is the
	/// effect a `testing-fault` injection observes.
	pub fn spawn(self) -> rt::JoinHandle {
		let ScalingLoop {
			servlets,
			spawners,
			trace,
			utilization,
			cluster_addrs,
			hive_context,
			admission,
			drain,
			hive_addr,
			config,
			tasks,
			issue_clock,
		} = self;

		let config = Arc::new(config);
		let link = hive_addr.map(|addr| {
			ClusterLink::<P, R>::new(
				Arc::clone(&servlets),
				Arc::clone(&cluster_addrs),
				addr,
				Arc::clone(&config),
				Arc::clone(&trace),
				issue_clock,
			)
		});

		let evaluation_period = config.scaling.cooldown;
		let mut task = ScalingTask {
			hive_urn: hive_addr.and_then(|addr| config.hive_urn(addr)).map(Arc::new),
			servlets,
			trace,
			utilization,
			samples: LastSamples::default(),
			hive_context,
			admission,
			drain,
			link,
			config,
			tasks,
		};

		rt::spawn(async move {
			let clock = Arc::clone(&task.config.clock);
			let mut scaled_up = Cooldowns::new(Arc::clone(&clock));
			let mut scaled_down = Cooldowns::new(Arc::clone(&clock));

			let looped: Result<(), TightBeamError> = async {
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
							ScalingDecision::ScaleUp => {
								task.scale_up(servlet_type, spawner, scale, &mut scaled_up).await?;
							}
							ScalingDecision::ScaleDown => task.scale_down(servlet_type, scale, &mut scaled_down)?,
							ScalingDecision::Hold => {}
						}
					}

					task.utilization.store(hive_load.utilization().get(), Ordering::Relaxed);
					task.samples.close_tick();
				}
			}
			.await;

			// A trace fault ends the loop, which is the effect a
			// `testing-fault` injection observes.
			drop(looped);
		})
	}
}

/// The instance count and the summed utilization of one servlet type.
///
/// A mean over the wrong count reads as a different load, so one value
/// carries both numbers and the division stays with the pair it divides.
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
	/// and heartbeats report saturation while per-type scaling sees the zero
	/// count and can spawn. A mean past the range of [`BasisPoints`] saturates.
	fn utilization(&self) -> BasisPoints {
		let instances = u64::try_from(self.instances).unwrap_or(u64::MAX);
		match NonZeroU64::new(instances) {
			None => BasisPoints::MAX,
			Some(count) => BasisPoints::saturating_from(self.utilization_sum / count),
		}
	}
}

/// The last utilization each instance reported, which counts for a tick in
/// which the instance reports none.
///
/// A tick keeps the sample of each instance it counts, so the sample of an
/// instance that left the registry drops at the end of the next tick.
#[derive(Default)]
struct LastSamples {
	/// The samples the current tick reads, kept by the tick before it.
	held: HashMap<Vec<u8>, BasisPoints>,
	/// The samples the current tick keeps for the next one.
	kept: HashMap<Vec<u8>, BasisPoints>,
}

impl LastSamples {
	/// Returns the utilization that counts for the instance under `key` in
	/// this tick: its report, else its last sample, else
	/// [`UNKNOWN_SERVLET_UTILIZATION_BPS`].
	///
	/// A report or a last sample stays as the instance's sample for the next
	/// tick. The key moves from the held samples to the kept ones, so a sample
	/// that stays copies no key.
	fn resolve(&mut self, key: &[u8], reported: Option<BasisPoints>) -> u64 {
		let held = self.held.remove_entry(key);
		let last = held.as_ref().map(|(_, sample)| *sample);
		let Some(sample) = reported.or(last) else {
			return u64::from(UNKNOWN_SERVLET_UTILIZATION_BPS);
		};

		let key = held.map_or_else(|| key.to_vec(), |(key, _)| key);
		self.kept.insert(key, sample);

		u64::from(sample.get())
	}

	/// Ends a tick, so the samples it kept are the ones the next tick reads.
	fn close_tick(&mut self) {
		self.held = core::mem::take(&mut self.kept);
	}
}

/// The per-type stamps of one scale direction, read against the hive clock.
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
/// [`ScalingLoop`] names what the hive supplies. This type holds what the
/// loop body works with once [`ScalingLoop::spawn`] derives the hive URN and
/// binds the cluster link, so every scale decision reads one owner.
struct ScalingTask<P: Protocol, R: ServletRegistry> {
	servlets: Arc<R>,
	trace: Arc<TraceCollector>,
	utilization: Arc<AtomicU16>,
	samples: LastSamples,
	hive_context: Arc<HiveContextImpl<P>>,
	admission: Arc<Mutex<()>>,
	drain: DrainMode,
	link: Option<ClusterLink<P, R>>,
	hive_urn: Option<Arc<Urn<'static>>>,
	config: Arc<HiveConfig>,
	tasks: TaskGroup,
}

impl<P, R> ScalingTask<P, R>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + MuxCapable + EncryptedProtocolState + Send + Sync + 'static,
	R: ServletRegistry + 'static,
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

	/// The hive's instance set, which a scale moves under its admission lock.
	fn instances(&self) -> HiveInstances<'_, R, P> {
		let servlets = self.servlets.as_ref();
		let routes = &self.hive_context;
		HiveInstances::new(servlets, routes, &self.admission, &self.drain, &self.config.scaling)
	}

	/// Counts the instances of one servlet type and sums their utilization.
	///
	/// An instance that reports no utilization falls back to its last
	/// sample, then to [`UNKNOWN_SERVLET_UTILIZATION_BPS`].
	fn type_load(&mut self, type_prefix: impl AsRef<[u8]>) -> TypeLoad {
		let type_prefix = type_prefix.as_ref();
		let mut load = TypeLoad::default();
		let samples = &mut self.samples;

		self.servlets.for_each_by_type(type_prefix, |key, reg| {
			load.instances = load.instances.saturating_add(1);

			let reported = reg.servlet.utilization();
			let utilization = samples.resolve(key, reported);
			load.utilization_sum = load.utilization_sum.saturating_add(utilization);
		});

		load
	}

	/// Adds one instance of `servlet_type`, records it, and announces it.
	///
	/// A scale the instance set refuses, or whose spawner fails, records its
	/// refusal and leaves the type as it is, and the next evaluation decides
	/// again.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the record of the scale or of its refusal.
	async fn scale_up(
		&self,
		servlet_type: &Urn<'static>,
		spawner: &SpawnerFn,
		scale: ServletScaleConfig,
		cooldowns: &mut Cooldowns,
	) -> Result<(), TightBeamError> {
		let type_key = servlet_type.canonical_bytes();
		if self.scale_blocked() || cooldowns.active(&type_key, scale.scale_up_cooldown()) {
			return Ok(());
		}

		let Ok(new_servlet) = (spawner)(Arc::clone(&self.trace)).await else {
			return self.record_refused(servlet_type, "SpawnFailed");
		};

		let registration = ServletRegistration {
			servlet: new_servlet,
			spawner: Arc::clone(spawner),
			servlet_type: servlet_type.clone(),
		};

		// The registry takes the instance before the announcement, because the
		// notify failure path reconciles from the registry. A refused insert
		// stops its servlet.
		let placed = match self.instances().insert(registration) {
			Ok(placed) => placed,
			Err(refusal) => return self.record_refused(servlet_type, refusal.as_str()),
		};

		self.record_scaled("Added", servlet_type, || placed.instance.canonical_bytes())?;

		// The slate leaves out an instance that names no signer, so the hive
		// announces only an instance that has a route.
		if let Some(added) = placed.into_servlet_info() {
			self.announce(ServletChange::Added(added));
		}

		cooldowns.stamp(type_key);
		Ok(())
	}

	/// Removes one instance of `servlet_type`, records it, and announces its
	/// departure.
	///
	/// A removal the instance set refuses records its refusal and leaves the
	/// instance in place, and the next evaluation decides again.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the record of the scale or of its refusal.
	fn scale_down(
		&self,
		servlet_type: &Urn<'static>,
		scale: ServletScaleConfig,
		cooldowns: &mut Cooldowns,
	) -> Result<(), TightBeamError> {
		let type_key = servlet_type.canonical_bytes();
		if self.scale_blocked() || cooldowns.active(&type_key, scale.scale_down_cooldown()) {
			return Ok(());
		}

		let type_prefix = servlet_type.type_prefix_bytes();
		// The registry states no key order, so scale-down picks any instance.
		let Some(key) = self.servlets.keys().into_iter().rfind(|k| k.starts_with(&type_prefix)) else {
			return self.record_refused(servlet_type, RemoveRefusal::Absent.as_str());
		};

		let removed = match self.instances().remove(&key) {
			Ok(removed) => removed,
			Err(refusal) => return self.record_refused(servlet_type, refusal.as_str()),
		};

		self.record_scaled("Removed", servlet_type, || &key)?;

		// An instance whose URN fails to derive names no slate change, so the
		// re-announce beat, which carries the slate whole, tells the gateways.
		if let Ok(instance) = removed.servlet_type.instance_urn(removed.address.as_ref()) {
			self.announce(ServletChange::Removed(instance));
		}

		cooldowns.stamp(type_key);
		Ok(())
	}

	/// Records [`HIVE_SCALED`] under `label` for an instance of
	/// `servlet_type`, whose canonical URN bytes `instance` renders.
	///
	/// The trace runs `instance` only when its sink keeps the event and its
	/// config keeps payloads.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault the `testing-fault` feature injects.
	fn record_scaled<E: AsRef<[u8]>>(
		&self,
		label: &'static str,
		servlet_type: &Urn<'static>,
		instance: impl FnOnce() -> E,
	) -> Result<(), TightBeamError> {
		let value = servlet_type.to_string();
		let evidence = || Some(instance());
		let trace = &self.trace;
		trace.emit_event_with_value_and_rendered_evidence(HIVE_SCALED, label, value, evidence)
	}

	/// Records [`HIVE_SCALE_REFUSED`] under `label` for a scale of
	/// `servlet_type` that landed no change.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault the `testing-fault` feature injects.
	fn record_refused(&self, servlet_type: &Urn<'static>, label: &'static str) -> Result<(), TightBeamError> {
		let value = servlet_type.to_string();
		let trace = &self.trace;
		trace.emit_event_with_value_and_evidence(HIVE_SCALE_REFUSED, label, value, None)
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
	use std::sync::{Mutex, PoisonError};

	use super::*;
	use crate::bps;
	use crate::clock::ManualClock;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::hive::{HashMapRegistry, ServletBox};
	use crate::colony::urn::ColonyNamespace;
	use crate::tb_cases;
	use crate::transport::client::{ConnectionBuilder, ConnectionPool};
	use crate::transport::TokioListener;

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

	/// The utilization a servlet reports in the tick a test runs: `Some`
	/// basis points, or `None` for a tick in which it reports nothing.
	type Report = Arc<Mutex<Option<BasisPoints>>>;

	/// A servlet whose utilization report the test sets for each tick.
	struct ReportingProbe {
		report: Report,
	}

	impl ServletBox for ReportingProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7010".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {}

		fn signer(&self) -> Option<&SignerIdentifier> {
			None
		}

		fn utilization(&self) -> Option<BasisPoints> {
			*self.report.lock().unwrap_or_else(PoisonError::into_inner)
		}
	}

	/// The servlet type of the probe.
	fn echo_type() -> Urn<'static> {
		let namespace = ColonyNamespace::default();
		namespace.servlet("echo").expect("test names satisfy the mint grammar")
	}

	/// A scaling task over a registry that holds one [`ReportingProbe`] of
	/// [`echo_type`], which reports what `report` holds.
	fn reporting_task(report: &Report) -> ScalingTask<TokioListener, HashMapRegistry> {
		let servlet_type = echo_type();
		let key = servlet_type.instance_urn(b"127.0.0.1:7010");
		let key = key.expect("the probe locator names an instance");
		let probe = ReportingProbe { report: Arc::clone(report) };
		let spawner: SpawnerFn = Arc::new(|_| Box::pin(async { Err(TightBeamError::NotEstablished) }));
		let registration = ServletRegistration { servlet: Box::new(probe), spawner, servlet_type };
		let servlets = HashMapRegistry::default();
		let inserted = servlets.insert(key.canonical_bytes(), registration);
		assert!(inserted.is_ok(), "the map registry takes every registration");

		let pool = Arc::new(ConnectionPool::<TokioListener>::builder().build());
		ScalingTask {
			servlets: Arc::new(servlets),
			trace: Arc::new(TraceCollector::default()),
			utilization: Arc::new(AtomicU16::new(0)),
			samples: LastSamples::default(),
			hive_context: Arc::new(HiveContextImpl::new(pool)),
			admission: Arc::default(),
			drain: DrainMode::default(),
			link: None,
			hive_urn: None,
			config: Arc::new(HiveConfig::default()),
			tasks: TaskGroup::default(),
		}
	}

	/// The load of the probe's type in a tick in which the probe reports
	/// nothing, after a tick in which it reported `last`.
	fn load_after_a_silent_tick(last: BasisPoints) -> TypeLoad {
		let report: Report = Arc::new(Mutex::new(Some(last)));
		let mut task = reporting_task(&report);
		let type_prefix = echo_type().type_prefix_bytes();
		task.type_load(&type_prefix);
		task.samples.close_tick();

		*report.lock().unwrap_or_else(PoisonError::into_inner) = None;
		task.type_load(&type_prefix)
	}

	/// An instance that reports nothing in a tick counts at the sample it
	/// reported last.
	#[test]
	fn a_silent_instance_counts_at_its_last_sample() {
		let load = load_after_a_silent_tick(bps!(9000));
		assert_eq!(load.utilization_sum, 9_000);
	}

	/// The key of the one instance the sample tests read.
	const INSTANCE: &[u8] = b"urn:tightbeam:servlet:echo/127.0.0.1:7010";

	/// An instance with no report and no sample counts at the unknown figure.
	#[test]
	fn an_instance_with_no_sample_counts_as_unknown() {
		let mut samples = LastSamples::default();
		assert_eq!(samples.resolve(INSTANCE, None), u64::from(UNKNOWN_SERVLET_UTILIZATION_BPS));
	}

	/// A tick that skips an instance drops its sample, so the samples hold the
	/// registered instances alone.
	#[test]
	fn a_sample_drops_after_a_tick_that_skips_its_instance() {
		let mut samples = LastSamples::default();
		samples.resolve(INSTANCE, Some(bps!(9000)));
		samples.close_tick();
		samples.close_tick();
		assert_eq!(samples.resolve(INSTANCE, None), u64::from(UNKNOWN_SERVLET_UTILIZATION_BPS));
	}
}
