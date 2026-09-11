//! Hive heartbeat send/process and evaporation loop spawn.

use core::hash::Hash;
use core::str::FromStr;
use core::time::Duration;
use std::sync::Arc;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool, GatewayRuntimeCtx};
use crate::colony::cluster::{ClusterConfig, ClusterError, HeartbeatEvent};
use crate::colony::common::{
	current_timestamp_ms, ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, HeartbeatResult,
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
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::TightBeamError;
use crate::{MessagePriority, Version};

/// The dial half of a heartbeat: the signing key and the pool to send on.
///
/// Both the background beat and [`ClusterHeartbeat::send_heartbeat`]
/// reach a hive through this one composer, so a probe from either side
/// carries the same command, version, and freshness binding.
///
/// [`ClusterHeartbeat::send_heartbeat`]: crate::colony::cluster::ClusterHeartbeat::send_heartbeat
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
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
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
	/// - [`ClusterError::NoResponse`]: the hive closed without answering
	/// - [`ClusterError::MalformedResponse`]: the answer carried no heartbeat result
	/// - transport or signing failures from the dial and emit
	pub(crate) async fn send<D: ClusterDigest>(self, addr: P::Address) -> Result<HeartbeatResult, ClusterError> {
		let cmd = ClusterCommand {
			heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
			manage: None,
		};

		// Priority is a V2+ metadata field. Composing it on V1 fails at
		// build time and every heartbeat would count as a send failure.
		// `metadata.order` is the command freshness binding (CWE-294).
		let frame = FrameBuilder::from(Version::V2)
			.with_id(b"heartbeat")
			.with_order(current_timestamp_ms())
			.with_message(cmd)
			.with_priority(MessagePriority::NetworkControl)
			.with_witness_hasher::<D>()
			.build()?;

		let signed_frame = frame
			.sign_with_provider::<D, _>(self.config.tls.identity().signing_provider())
			.await?;
		let mut client = self.pool.connect(addr).await?;
		let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

		let cmd_response: ClusterCommandResponse = decode(&response.message)?;
		cmd_response.heartbeat.ok_or(ClusterError::MalformedResponse)
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
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Dials one hive and settles the answer against `hive_addr`.
	///
	/// A fault ends this hive's round alone, so every other hive in the
	/// interval still settles and the next interval retries this one.
	async fn beat_hive<D: ClusterDigest>(self, hive_addr: Arc<[u8]>, addr: P::Address) {
		let result = HiveBeat::new(&self.config, &self.pool).send::<D>(addr).await;
		let _settled = self.settle_heartbeat(hive_addr, result);
	}

	/// Settles one heartbeat outcome against the registries.
	///
	/// A live answer refreshes the hive's lease and utilization. A dead or
	/// refused answer counts one failure. At the configured `max_failures`
	/// the hive unregisters, its servlet routes drop, and the eviction traces
	/// as [`CLUSTER_HIVE_EVICTED`]. The configured heartbeat callback fires
	/// for both outcomes.
	///
	/// A registry lock is poisoned only by a panic the crate forbids, so
	/// a skipped lease or route update leaves the beat itself intact.
	fn settle_heartbeat(
		&self,
		hive_addr: Arc<[u8]>,
		result: Result<HeartbeatResult, ClusterError>,
	) -> Result<(), TightBeamError> {
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
				let _ = self.registry.touch(&hive_addr, hb.utilization);
			}
			_ => {
				let max_failures = self.config.heartbeat.max_failures;
				let evicting = self
					.registry
					.increment_failure(&hive_addr)
					.is_ok_and(|failures| failures >= max_failures);
				if evicting {
					let _ = self.registry.unregister(&hive_addr);
					let _ = self.servlet_registry.remove_by_hive(&hive_addr);
					self.trace.event(CLUSTER_HIVE_EVICTED)?;
				}
			}
		}

		Ok(())
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
	/// A registry lock is poisoned only by a panic this crate forbids, so a
	/// skipped eviction is retried by the next interval rather than ending
	/// the beat. Draining a finished task discards its join result because
	/// only the concurrency slot is wanted.
	pub(crate) fn spawn_heartbeat<D: ClusterDigest>(self) -> rt::JoinHandle {
		let beat_ctx = self.clone();
		let GatewayRuntimeCtx { registry, servlet_registry, config, trace, .. } = self;

		rt::spawn(async move {
			let beat: Result<(), TightBeamError> = async move {
				loop {
					let hives = registry.all_hives().unwrap_or_default();
					let max_concurrent = config.heartbeat.max_concurrent;
					let mut set = tokio::task::JoinSet::new();

					let tasks: Vec<_> = hives.into_iter().filter_map(|hive| hive.dial_target()).collect();
					for (hive_addr, addr) in tasks {
						while set.len() >= max_concurrent {
							let _ = set.join_next().await;
						}

						set.spawn(beat_ctx.clone().beat_hive::<D>(hive_addr, addr));
					}

					while set.join_next().await.is_some() {}

					for entry in registry.evict_stale().unwrap_or_default() {
						let _ = servlet_registry.remove_by_hive(&entry.address);
						trace.event(CLUSTER_HIVE_EVICTED)?;
					}

					rt::sleep(config.heartbeat.interval).await;
				}
			}
			.await;

			// A trace fault ends the beat, which is the effect a
			// `testing-fault` injection observes. Production traces are
			// infallible, so this arm is unreachable there.
			drop(beat);
		})
	}

	/// Runs the pheromone evaporation loop, which also retires abandoned
	/// routes and relay trails older than `relay_trail_ttl`.
	///
	/// A registry lock is poisoned only by a panic this crate forbids, so a
	/// skipped sweep is retried by the next interval rather than ending the
	/// loop.
	pub(crate) fn spawn_evaporation(self, relay_trail_ttl: Duration) -> rt::JoinHandle {
		let evaporation_interval = self.config.pheromone.evaporation_interval;
		let GatewayRuntimeCtx { servlet_registry, trace, .. } = self;

		rt::spawn(async move {
			let sweep: Result<(), TightBeamError> = async move {
				loop {
					rt::sleep(evaporation_interval).await;
					let _ = servlet_registry.evaporate();
					let _ = servlet_registry.remove_abandoned();

					// Relay trails refresh through relayed rumors, so age is
					// the lifecycle bound that retires an unpicked one. A
					// retired fallback traces with its count, which keeps a
					// route that vanished diagnosable (ISO 27001 A.8.15).
					let pruned = servlet_registry.prune_stale_relay_trails(relay_trail_ttl).unwrap_or(0);
					if pruned > 0 {
						let count = u64::try_from(pruned).unwrap_or(u64::MAX);
						trace.event_with(CLUSTER_RELAY_TRAIL_PRUNED, &[], count)?;
					}
				}
			}
			.await;

			// A trace fault ends the sweep, which is the effect a
			// `testing-fault` injection observes.
			drop(sweep);
		})
	}
}
