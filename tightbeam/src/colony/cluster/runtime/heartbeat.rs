//! The gateway's hive heartbeat and its pheromone evaporation loop.
//!
//! [`HiveBeat`] sends one signed probe to a hive. The gateway runtime spawns
//! the loop that beats every registered hive and settles each answer against
//! the registries, and the loop that evaporates pheromone and prunes stale
//! relay trails.

use core::time::Duration;
use std::sync::Arc;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::registry::FailureCount;
use crate::colony::cluster::runtime::bounds::{ColonyConfig, ColonyDialProtocol, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::hop::HivePlane;
use crate::colony::cluster::runtime::LoopFault;
use crate::colony::cluster::{ClusterError, HeartbeatEvent, HiveEntry};
use crate::colony::protocol::{
	ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, HeartbeatResult,
};
use crate::decode;
use crate::instrumentation::events::{
	CLUSTER_HEARTBEAT_FAILED, CLUSTER_HIVE_EVICTED, CLUSTER_PEER_ROUTES_WITHDRAWN, CLUSTER_RELAY_TRAIL_PRUNED,
};
use crate::policy::TransitStatus;
use crate::runtime::rt;
use crate::transport::Protocol;
use crate::TightBeamError;
use crate::{MessagePriority, Version};

/// The dial half of a heartbeat: the signing key and the plane to send on.
///
/// Both the background beat and [`ClusterHeartbeat::send_heartbeat`]
/// reach a hive through this one composer, so a probe from either side
/// carries the same command, version, freshness binding, and [`BoundDial`].
///
/// [`ClusterHeartbeat::send_heartbeat`]: crate::colony::cluster::ClusterHeartbeat::send_heartbeat
/// [`BoundDial`]: crate::colony::bound_dial::BoundDial
pub(crate) struct HiveBeat<P: Protocol> {
	config: ColonyConfig<P>,
	/// The plane the probe dials on, which records a dial the hive's answer
	/// refused.
	plane: HivePlane<P>,
}

impl<P: ColonyDialProtocol> HiveBeat<P> {
	/// A composer that signs with `config`'s identity and dials on `plane`.
	pub(crate) fn new(config: &ColonyConfig<P>, plane: &HivePlane<P>) -> Self {
		Self { config: config.clone(), plane: plane.clone() }
	}

	/// Sends one signed heartbeat command to `hive` and decodes its answer.
	///
	/// The dial is [`HivePlane::hive`], so the command leaves only toward the
	/// identity that signed the hive's registration (CWE-346).
	///
	/// # Errors
	///
	/// - [`ClusterError::PeerMismatch`] -- another identity answered at the hive's address.
	/// - [`ClusterError::InvalidAddress`] -- the hive's address does not parse
	///   as an address of this protocol.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	/// - [`ClusterError::NoResponse`] -- the hive closed before it answered.
	/// - [`ClusterError::MalformedResponse`] -- the answer carried no heartbeat result.
	/// - [`ClusterError::Transport`] -- the emit failed.
	/// - [`ClusterError::Frame`] -- the frame failed to build, sign, or decode,
	///   or the trace refused the event of a refused dial.
	pub(crate) async fn send(self, hive: &HiveEntry) -> Result<HeartbeatResult, ClusterError> {
		let cmd = ClusterCommand::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy });

		// Priority is a metadata field of V2 or later. A V1 frame that composes
		// it fails at build time, so every heartbeat would count as a send
		// failure. `metadata.order` is the command freshness binding (CWE-294).
		let builder = FrameBuilder::from(Version::V2)
			.with_id(b"heartbeat")
			.with_order(self.config.clock.unix().get())
			.with_message(cmd)
			.with_priority(MessagePriority::NetworkControl);
		let mut signed_frame = self.config.witnessed(builder).build()?;

		signed_frame.sign_with_provider(self.config.tls.identity()).await?;

		let mut client = self.plane.hive(hive).connect().await?;
		let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

		let cmd_response: ClusterCommandResponse = decode(response.message())?;
		match cmd_response {
			ClusterCommandResponse::Heartbeat(result) => Ok(result),
			ClusterCommandResponse::Manage(_) => Err(ClusterError::MalformedResponse),
		}
	}
}

impl<P: ColonyDialProtocol> GatewayRuntimeCtx<P> {
	/// Dials one hive and settles the answer against its address.
	///
	/// A dial fault is this hive's answer and settles as a failed beat, so the
	/// other hives of the interval still settle and the next interval retries
	/// this one. A registry fault returns to the loop, which ends on it.
	async fn beat_hive(self, hive: HiveEntry) -> Result<(), LoopFault> {
		let result = HiveBeat::new(&self.config, &self.hive_plane).send(&hive).await;
		self.settle_heartbeat(hive.address, result)
	}

	/// Settles one heartbeat outcome against the registries.
	///
	/// - A live answer refreshes the hive's lease and utilization.
	/// - A dead or refused answer counts one failure and traces it as
	///   [`CLUSTER_HEARTBEAT_FAILED`]. The membership retires the hive with
	///   its servlet routes at the configured `max_failures`, and the gateway
	///   traces the retirement as [`CLUSTER_HIVE_EVICTED`] with the count of
	///   hives left.
	/// - The configured heartbeat callback fires for both outcomes.
	///
	/// # Errors
	///
	/// - [`LoopFault::Registry`] -- a registry lock is poisoned, which ends the beat.
	/// - [`LoopFault::Runtime`] -- the trace refused the failure or the eviction event.
	fn settle_heartbeat(
		&self,
		hive_addr: Arc<[u8]>,
		result: Result<HeartbeatResult, ClusterError>,
	) -> Result<(), LoopFault> {
		// A live answer carries the hive's utilization. A failure carries the
		// status the hive answered, or the status that a dial or an exchange
		// fault forwards as.
		let verdict = match &result {
			Ok(hb) => match hb.status {
				TransitStatus::Ok | TransitStatus::ResourceExhausted => Ok(hb.utilization),
				status => Err(status),
			},
			Err(error) => Err(error.forward_status()),
		};

		self.report_heartbeat(&hive_addr, &result, verdict.is_ok());

		match verdict {
			Ok(utilization) => {
				self.registry.touch(&hive_addr, utilization)?;
			}
			Err(status) => {
				let max_failures = self.config.heartbeat.max_failures;
				let counted = self.membership().count_failure(&hive_addr, max_failures)?;
				let trace = &self.trace;
				let label = status.as_str();
				let evidence = Some(hive_addr.as_ref());
				trace.emit_event_with_value_and_evidence(CLUSTER_HEARTBEAT_FAILED, label, status, evidence)?;

				if let FailureCount::Retired { remaining } = counted {
					trace.emit_event_with_value_and_evidence(CLUSTER_HIVE_EVICTED, "", remaining, evidence)?;
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
	/// A poisoned registry lock never clears, so it ends the beat, which
	/// records it as [`CLUSTER_LOOP_POISONED`]. The loop reads every beat
	/// task's settlement, including those it drains for a concurrency slot, so
	/// a registry fault inside one beat ends the loop too.
	///
	/// [`CLUSTER_LOOP_POISONED`]: crate::instrumentation::events::CLUSTER_LOOP_POISONED
	pub(crate) fn spawn_heartbeat(self) -> rt::JoinHandle {
		let beat_ctx = self.clone();
		let GatewayRuntimeCtx { registry, config, trace, .. } = self;

		rt::spawn(async move {
			let beat: Result<(), LoopFault> = async {
				loop {
					let hives = registry.all_hives()?;
					let max_concurrent = config.heartbeat.max_concurrent.get();
					let mut set = tokio::task::JoinSet::new();

					for hive in hives {
						while set.len() >= max_concurrent {
							Self::settle_joined(set.join_next().await)?;
						}

						set.spawn(beat_ctx.clone().beat_hive(hive));
					}

					while let Some(joined) = set.join_next().await {
						Self::settle_joined(Some(joined))?;
					}

					// Each hive that lost its lease gets its own event that
					// names it, so an expiry stays attributable after the fact.
					for retired in beat_ctx.membership().retire_stale()? {
						let remaining = retired.remaining;
						let evidence = Some(retired.entry.address.as_ref());
						trace.emit_event_with_value_and_evidence(CLUSTER_HIVE_EVICTED, "", remaining, evidence)?;
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
	/// A poisoned registry lock never clears, so it ends the loop, and the loop
	/// records it as [`CLUSTER_LOOP_POISONED`].
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

					// The sweep drops each route at its abandonment limit, and
					// the traced count of the peer routes among them keeps a
					// vanished peer route diagnosable (ISO 27001 A.8.15).
					if let Some(count) = servlet_registry.remove_abandoned()? {
						let cause = "evaporated";
						trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ROUTES_WITHDRAWN, cause, count, None)?;
					}

					// Relay trails refresh through relayed rumors, so age
					// retires an unpicked fallback. The traced count keeps
					// a vanished route diagnosable (ISO 27001 A.8.15).
					if let Some(pruned) = servlet_registry.prune_stale_relay_trails(relay_trail_ttl)? {
						trace.emit_event_with_value_and_evidence(CLUSTER_RELAY_TRAIL_PRUNED, "", pruned, None)?;
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
