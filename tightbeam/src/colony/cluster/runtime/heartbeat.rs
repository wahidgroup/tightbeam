//! The gateway's hive heartbeat and its pheromone evaporation loop.
//!
//! [`HiveBeat`] sends one signed probe to a hive. The gateway runtime spawns
//! the loop that beats every registered hive and settles each answer against
//! the registries, and the loop that evaporates pheromone and prunes stale
//! relay trails.

use core::hash::Hash;
use core::str::FromStr;
use core::time::Duration;
use std::sync::Arc;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::LoopFault;
use crate::colony::cluster::{ClusterConfig, ClusterError, HeartbeatEvent};
use crate::colony::common::{
	ClusterCommand, ClusterCommandKind, ClusterCommandOutcome, ClusterCommandResponse, ClusterStatus, HeartbeatParams,
	HeartbeatResult,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::decode;
use crate::instrumentation::events::{CLUSTER_HIVE_EVICTED, CLUSTER_RELAY_TRAIL_PRUNED};
use crate::policy::TransitStatus;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol};
use crate::TightBeamError;
use crate::{MessagePriority, Version};

/// The dial half of a heartbeat: the signing key and the pool to send on.
///
/// Both the background beat and [`ClusterHeartbeat::send_heartbeat`]
/// reach a hive through this one composer, so a probe from either side
/// carries the same command, version, and freshness binding.
///
/// [`ClusterHeartbeat::send_heartbeat`]:
/// crate::colony::cluster::ClusterHeartbeat::send_heartbeat
pub(crate) struct HiveBeat<P: Protocol> {
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
}

impl<P> HiveBeat<P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Signs with `config`'s identity and dials over `pool`.
	pub(crate) fn new(config: &Arc<ClusterConfig>, pool: &Arc<ClusterPool<P>>) -> Self {
		Self { config: Arc::clone(config), pool: Arc::clone(pool) }
	}

	/// Sends one signed heartbeat command to a hive and decodes its answer.
	///
	/// # Errors
	///
	/// - [`ClusterError::NoResponse`] -- the hive closed without answering.
	/// - [`ClusterError::MalformedResponse`] -- the answer carried no heartbeat result.
	/// - [`ClusterError::Transport`] -- the dial or the emit failed.
	/// - [`ClusterError::Frame`] -- the frame failed to build, sign, or decode.
	pub(crate) async fn send<D: ClusterDigest>(self, addr: P::Address) -> Result<HeartbeatResult, ClusterError> {
		let probe = ClusterCommandKind::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy });
		let cmd = ClusterCommand::from(probe);

		// Priority is a V2+ metadata field. Composing it on V1 fails at
		// build time and every heartbeat would count as a send failure.
		// `metadata.order` is the command freshness binding (CWE-294).
		let mut signed_frame = FrameBuilder::from(Version::V2)
			.with_id(b"heartbeat")
			.with_order(self.config.clock.unix().get())
			.with_message(cmd)
			.with_priority(MessagePriority::NetworkControl)
			.with_witness_hasher::<D>()
			.build()?;

		signed_frame
			.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
			.await?;

		let mut client = self.pool.connect(addr).await?;
		let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

		let cmd_response: ClusterCommandResponse = decode(response.message())?;
		match cmd_response.into_choice() {
			Ok(ClusterCommandOutcome::Heartbeat(result)) => Ok(result),
			Ok(ClusterCommandOutcome::Manage(_)) | Err(_) => Err(ClusterError::MalformedResponse),
		}
	}
}

impl<P> GatewayRuntimeCtx<P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Dials one hive and settles the answer against `hive_addr`.
	///
	/// A dial fault is this hive's answer and settles as a failed beat, so
	/// every other hive in the interval still settles and the next interval
	/// retries this one. A registry fault is the loop's to end on.
	async fn beat_hive<D: ClusterDigest>(self, hive_addr: Arc<[u8]>, addr: P::Address) -> Result<(), LoopFault> {
		let result = HiveBeat::new(&self.config, &self.pool).send::<D>(addr).await;
		self.settle_heartbeat(hive_addr, result)
	}

	/// Settles one heartbeat outcome against the registries.
	///
	/// - A live answer refreshes the hive's lease and utilization.
	/// - A dead or refused answer counts one failure. At the configured
	///   `max_failures` the hive unregisters, its servlet routes drop, and the
	///   eviction traces as [`CLUSTER_HIVE_EVICTED`].
	/// - The configured heartbeat callback fires for both outcomes.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- a registry lock is poisoned, which ends the beat.
	/// - [`LoopFault::Runtime`] -- the trace refused the eviction event.
	fn settle_heartbeat(
		&self,
		hive_addr: Arc<[u8]>,
		result: Result<HeartbeatResult, ClusterError>,
	) -> Result<(), LoopFault> {
		let alive = matches!(
			&result,
			Ok(hb) if matches!(
				hb.status,
				TransitStatus::Ok | TransitStatus::ResourceExhausted
			)
		);

		self.report_heartbeat(&hive_addr, &result, alive);

		match (alive, result) {
			(true, Ok(hb)) => {
				self.registry.touch(&hive_addr, hb.utilization)?;
			}
			_ => {
				let max_failures = self.config.heartbeat.max_failures;
				let failures = self.registry.increment_failure(&hive_addr)?;
				if failures >= max_failures {
					self.membership().retire(&hive_addr)?;
					self.trace.event(CLUSTER_HIVE_EVICTED)?;
				}
			}
		}

		Ok(())
	}

	/// Settles what one finished beat task left behind.
	///
	/// A task that did not join is a runtime fault. A task that joined
	/// hands its own settlement through, so a registry fault inside a beat
	/// reaches the loop that spawned it.
	fn settle_joined(joined: Option<Result<Result<(), LoopFault>, rt::JoinError>>) -> Result<(), LoopFault> {
		match joined {
			None => Ok(()),
			Some(Err(_)) => Err(LoopFault::Runtime(TightBeamError::JoinError)),
			Some(Ok(settled)) => settled,
		}
	}

	/// Reports the outcome to the operator's configured callback.
	fn report_heartbeat(&self, hive_addr: &Arc<[u8]>, result: &Result<HeartbeatResult, ClusterError>, alive: bool) {
		let Some(ref callback) = self.config.heartbeat.on_heartbeat else {
			return;
		};

		callback(HeartbeatEvent {
			hive_addr: Arc::clone(hive_addr),
			success: alive,
			utilization: result.as_ref().ok().map(|r| r.utilization),
		});
	}

	/// Runs the periodic heartbeat over every registered hive.
	///
	/// A poisoned registry lock never clears, so it ends the beat and is
	/// recorded as [`CLUSTER_LOOP_POISONED`]. Every beat task's settlement
	/// is read, including the ones drained for a concurrency slot, so a
	/// registry fault inside one beat ends the loop too.
	///
	/// [`CLUSTER_LOOP_POISONED`]: crate::instrumentation::events::CLUSTER_LOOP_POISONED
	pub(crate) fn spawn_heartbeat<D: ClusterDigest>(self) -> rt::JoinHandle {
		let beat_ctx = self.clone();
		let GatewayRuntimeCtx { registry, config, trace, .. } = self;

		rt::spawn(async move {
			let beat: Result<(), LoopFault> = async {
				loop {
					let hives = registry.all_hives()?;
					let max_concurrent = config.heartbeat.max_concurrent;
					let mut set = tokio::task::JoinSet::new();

					let tasks: Vec<_> = hives.into_iter().filter_map(|hive| hive.dial_target()).collect();
					for (hive_addr, addr) in tasks {
						while set.len() >= max_concurrent {
							Self::settle_joined(set.join_next().await)?;
						}

						set.spawn(beat_ctx.clone().beat_hive::<D>(hive_addr, addr));
					}

					while let Some(joined) = set.join_next().await {
						Self::settle_joined(Some(joined))?;
					}

					// Each hive that lost its lease gets its own event that
					// names it, so an expiry stays attributable after the fact.
					for retired in beat_ctx.membership().retire_stale()? {
						trace.event(CLUSTER_HIVE_EVICTED)?.with_payload(&retired.address).emit();
					}

					config.clock.sleep(config.heartbeat.interval).await;
				}
			}
			.await;

			// A trace fault ends the beat silently, which is the effect a
			// `testing-fault` injection observes. A poisoned registry ends
			// it on the record.
			if let Err(fault) = beat {
				fault.record(&trace);
			}
		})
	}

	/// Runs the pheromone evaporation loop, which also retires abandoned
	/// routes and relay trails older than `relay_trail_ttl`.
	///
	/// A poisoned registry lock never clears, so it ends the loop and is
	/// recorded as [`CLUSTER_LOOP_POISONED`].
	///
	/// [`CLUSTER_LOOP_POISONED`]: crate::instrumentation::events::CLUSTER_LOOP_POISONED
	pub(crate) fn spawn_evaporation(self, relay_trail_ttl: Duration) -> rt::JoinHandle {
		let evaporation_interval = self.config.pheromone.evaporation_interval;
		let clock = Arc::clone(&self.config.clock);
		let GatewayRuntimeCtx { servlet_registry, trace, .. } = self;

		rt::spawn(async move {
			let sweep: Result<(), LoopFault> = async {
				loop {
					clock.sleep(evaporation_interval).await;
					servlet_registry.evaporate()?;
					servlet_registry.remove_abandoned()?;

					// Relay trails refresh through relayed rumors, so age is
					// the lifecycle bound that retires an unpicked one. A
					// retired fallback traces with its count, which keeps a
					// route that vanished diagnosable (ISO 27001 A.8.15).
					let pruned = servlet_registry.prune_stale_relay_trails(relay_trail_ttl)?;
					if pruned > 0 {
						let count = u64::try_from(pruned).unwrap_or(u64::MAX);
						trace.event_with(CLUSTER_RELAY_TRAIL_PRUNED, &[], count)?;
					}
				}
			}
			.await;

			// A trace fault ends the sweep silently, which is the effect a
			// `testing-fault` injection observes. A poisoned registry ends
			// it on the record.
			if let Err(fault) = sweep {
				fault.record(&trace);
			}
		})
	}
}
