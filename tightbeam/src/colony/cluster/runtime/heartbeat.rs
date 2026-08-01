//! Hive heartbeat send/process and evaporation loop spawn.

use core::hash::Hash;
use core::str::{from_utf8, FromStr};
use core::time::Duration;
use std::sync::Arc;

use crate::builder::frame::FrameBuilder;
use crate::builder::TypeBuilder;
use crate::colony::cluster::runtime::bounds::{ClusterDigest, ClusterPool};
use crate::colony::cluster::{ClusterConfig, ClusterError, HeartbeatEvent, HiveEntry, HiveRegistry, ServletRegistry};
use crate::colony::common::{
	current_timestamp_ms, ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, HeartbeatResult,
};
use crate::colony::servlet::servlet_runtime::rt;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::decode;
use crate::instrumentation::events::{CLUSTER_HIVE_EVICTED, CLUSTER_RELAY_TRAIL_PRUNED};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};
use crate::{MessagePriority, Version};

/// Parse a registered hive's stored address into the protocol address
/// type, returning the raw bytes beside the parsed form. `None` means
/// the stored bytes are not a dialable address for this protocol.
pub fn parse_hive_addr<A: FromStr>(hive: &HiveEntry) -> Option<(Arc<[u8]>, A)> {
	let hive_addr = Arc::clone(&hive.address);
	from_utf8(&hive_addr)
		.ok()
		.and_then(|s| s.parse().ok())
		.map(|addr| (hive_addr, addr))
}

fn fire_heartbeat_callback(
	config: &ClusterConfig,
	hive_addr: &Arc<[u8]>,
	result: &Result<HeartbeatResult, ClusterError>,
	alive: bool,
) {
	if let Some(ref callback) = config.heartbeat.on_heartbeat {
		let event = HeartbeatEvent {
			hive_addr: Arc::clone(hive_addr),
			success: alive,
			utilization: result.as_ref().ok().map(|r| r.utilization),
		};
		callback(event);
	}
}

/// Settle one heartbeat outcome against the registries.
///
/// A live answer refreshes the hive's lease and utilization. A dead
/// or refused answer counts one failure. At `max_failures` the hive
/// unregisters, its servlet routes drop, and the eviction traces as
/// [`CLUSTER_HIVE_EVICTED`]. The configured heartbeat callback fires
/// for both outcomes.
pub fn process_heartbeat_result(
	registry: &HiveRegistry,
	servlet_registry: &ServletRegistry,
	hive_addr: Arc<[u8]>,
	result: Result<HeartbeatResult, ClusterError>,
	max_failures: u32,
	config: &ClusterConfig,
	trace: &TraceCollector,
) {
	let alive = matches!(
		&result,
		Ok(hb) if matches!(
			hb.status,
			TransitStatus::Ok | TransitStatus::ResourceExhausted
		)
	);
	fire_heartbeat_callback(config, &hive_addr, &result, alive);
	match (alive, result) {
		(true, Ok(hb)) => {
			let _ = registry.touch(&hive_addr, hb.utilization);
		}
		_ => {
			if let Ok(failures) = registry.increment_failure(&hive_addr) {
				if failures >= max_failures {
					let _ = registry.unregister(&hive_addr);
					let _ = servlet_registry.remove_by_hive(&hive_addr);
					let _ = trace.event(CLUSTER_HIVE_EVICTED);
				}
			}
		}
	}
}

/// Send one signed heartbeat command to a hive and decode its answer.
///
/// # Errors
/// - [`ClusterError::NoResponse`]: the hive closed without answering
/// - [`ClusterError::MalformedResponse`]: the answer carried no heartbeat result
/// - transport or signing failures from the dial and emit
pub async fn send_heartbeat_async<P, D>(
	pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	addr: P::Address,
) -> Result<HeartbeatResult, ClusterError>
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
	D: ClusterDigest,
{
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

	let signed_frame = frame.sign_with_provider::<D, _>(config.tls.key.as_ref()).await?;

	let mut client = pool.connect(addr).await?;
	let response = client.emit(signed_frame, None).await?.ok_or(ClusterError::NoResponse)?;

	let cmd_response: ClusterCommandResponse = decode(&response.message)?;
	cmd_response.heartbeat.ok_or(ClusterError::MalformedResponse)
}

/// Spawn the periodic heartbeat loop over every registered hive.
pub(crate) fn spawn_heartbeat_loop<P, D>(
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	pool: Arc<ClusterPool<P>>,
	trace: Arc<TraceCollector>,
) -> rt::JoinHandle
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
	D: ClusterDigest,
{
	rt::spawn(async move {
		loop {
			let hives = registry.all_hives().unwrap_or_default();
			let max_concurrent = config.heartbeat.max_concurrent;
			let mut set = tokio::task::JoinSet::new();

			let tasks: Vec<_> = hives.into_iter().filter_map(|hive| parse_hive_addr(&hive)).collect();
			for (hive_addr, addr) in tasks {
				while set.len() >= max_concurrent {
					let _ = set.join_next().await;
				}

				let registry = Arc::clone(&registry);
				let servlet_registry = Arc::clone(&servlet_registry);
				let config = Arc::clone(&config);
				let pool = Arc::clone(&pool);
				let trace = Arc::clone(&trace);
				let max_failures = config.heartbeat.max_failures;

				set.spawn(async move {
					let result = send_heartbeat_async::<P, D>(Arc::clone(&pool), Arc::clone(&config), addr).await;
					process_heartbeat_result(
						&registry,
						&servlet_registry,
						hive_addr,
						result,
						max_failures,
						&config,
						&trace,
					);
				});
			}

			while set.join_next().await.is_some() {}

			if let Ok(evicted) = registry.evict_stale() {
				for entry in evicted {
					let _ = servlet_registry.remove_by_hive(&entry.address);
					let _ = trace.event(CLUSTER_HIVE_EVICTED);
				}
			}

			rt::sleep(config.heartbeat.interval).await;
		}
	})
}

/// Spawn the pheromone evaporation loop, which also retires abandoned
/// routes and relay trails older than `relay_trail_ttl`.
pub(crate) fn spawn_evaporation_loop(
	servlet_registry: Arc<ServletRegistry>,
	evaporation_interval: Duration,
	relay_trail_ttl: Duration,
	trace: Arc<TraceCollector>,
) -> rt::JoinHandle {
	rt::spawn(async move {
		loop {
			rt::sleep(evaporation_interval).await;
			let _ = servlet_registry.evaporate();
			let _ = servlet_registry.remove_abandoned();
			// Relay trails refresh only through relayed rumors, so a
			// trail that outlived its refresh window retires by age.
			// Selection alone can never abandon an unpicked trail.
			// A retired fallback traces with its count, so a route
			// that silently vanished stays diagnosable (ISO 27001
			// A.8.15).
			if let Ok(pruned) = servlet_registry.prune_stale_relay_trails(relay_trail_ttl) {
				if pruned > 0 {
					let count = u64::try_from(pruned).unwrap_or(u64::MAX);
					let _ = trace.event_with(CLUSTER_RELAY_TRAIL_PRUNED, &[], count);
				}
			}
		}
	})
}
