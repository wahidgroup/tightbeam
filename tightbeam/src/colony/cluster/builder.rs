//! Builders for [`ClusterConfig`] and [`HeartbeatConfig`].
//!
//! [`ClusterConfigBuilder`] assembles gateway runtime configuration from
//! TLS material, peer federation, the export boundary, gossip, and hive
//! routing defaults. [`HeartbeatConfigBuilder`] configures hive health
//! probes separately.
//!
//! # Export boundary
//!
//! Discoverability and enforcement share one [`ExportAllowlist`]:
//!
//! - [`ClusterConfigBuilder::with_exported_types`] installs a static list
//!   that filters the advertise slate and drives the fail-closed allowlist.
//! - [`ClusterConfigBuilder::with_export_allowlist`] installs a live handle
//!   when membership must change after start.
//! - [`ClusterConfigBuilder::with_export_grant`] adds positive grants
//!   that compose as union with the allowlist.
//! - [`ClusterConfigBuilder::with_export_gate`] adds per-identity gates
//!   that compose as intersection with those allow sources.
//!
//! # Peer federation
//!
//! Peer dial list, advertise beat, dial allowlist, relay budget, and
//! rumor refresh live on [`PeerConfig`] and are set through the matching
//! builder methods or [`ClusterConfigBuilder::with_peer_config`].
//!
//! # Build-time derivation
//!
//! [`ClusterConfigBuilder::build`] derives colony membership from the
//! certificate, rebuilds the peer discovery table from the dial list,
//! and clamps rumor refresh to the gossip freshness window.

use core::time::Duration;
use std::sync::Arc;

use super::{
	ClusterConfig, ClusterTlsConfig, HeartbeatCallback, HeartbeatConfig, PeerConfig, PheromoneConfig,
	DEFAULT_HEARTBEAT_INTERVAL_SECS, DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FAILURES,
};
use crate::colony::common::{ColonyNamespace, LoadBalancer, StochasticForager};
use crate::policy::GatePolicy;
use crate::transport::client::pool::PoolConfig;

#[cfg(feature = "x509")]
mod x509 {
	pub(crate) use crate::colony::cluster::{
		cert_colony_urn, ExportAllowlist, ExportGate, ExportGrant, GossipAdmission, GossipConfig, MemoryPeerStore,
		PeerStore, PeerTable, StaticExportList,
	};
	pub(crate) use crate::crypto::x509::Certificate;
	pub(crate) use crate::utils::urn::Urn;
}

#[cfg(feature = "x509")]
use x509::*;

// ============================================================================
// HeartbeatConfigBuilder
// ============================================================================

/// Builder for [`HeartbeatConfig`].
pub struct HeartbeatConfigBuilder {
	interval: Duration,
	timeout: Duration,
	max_concurrent: usize,
	max_failures: u32,
	on_heartbeat: Option<HeartbeatCallback>,
}

impl Default for HeartbeatConfigBuilder {
	fn default() -> Self {
		Self {
			interval: Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS),
			timeout: Duration::from_secs(DEFAULT_HEARTBEAT_TIMEOUT_SECS),
			max_concurrent: DEFAULT_MAX_CONCURRENT,
			max_failures: DEFAULT_MAX_FAILURES,
			on_heartbeat: None,
		}
	}
}

impl HeartbeatConfig {
	/// Create a builder with default interval, timeout, and failure limits.
	pub fn builder() -> HeartbeatConfigBuilder {
		HeartbeatConfigBuilder::default()
	}
}

impl HeartbeatConfigBuilder {
	/// Set the time between heartbeat cycles.
	pub fn with_interval(mut self, interval: Duration) -> Self {
		self.interval = interval;
		self
	}

	/// Set the age after which a silent hive is evicted.
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Set consecutive failures before unregistering a hive.
	pub fn with_max_failures(mut self, max: u32) -> Self {
		self.max_failures = max;
		self
	}

	/// Set the cap on concurrent heartbeat dials per cycle.
	pub fn with_max_concurrent(mut self, max: usize) -> Self {
		self.max_concurrent = max;
		self
	}

	/// Attach a callback invoked after each heartbeat result.
	pub fn with_callback(mut self, callback: HeartbeatCallback) -> Self {
		self.on_heartbeat = Some(callback);
		self
	}

	/// Build the heartbeat configuration.
	pub fn build(self) -> HeartbeatConfig {
		HeartbeatConfig {
			interval: self.interval,
			timeout: self.timeout,
			max_concurrent: self.max_concurrent,
			max_failures: self.max_failures,
			on_heartbeat: self.on_heartbeat,
		}
	}
}

// ============================================================================
// ClusterConfigBuilder
// ============================================================================

/// Builder for [`ClusterConfig`].
///
/// Start from TLS material via [`ClusterConfig::builder`], then chain
/// federation, export, gossip, and routing options before
/// [`ClusterConfigBuilder::build`].
#[cfg(feature = "x509")]
pub struct ClusterConfigBuilder {
	namespace: ColonyNamespace,
	load_balancer: Arc<dyn LoadBalancer>,
	heartbeat: HeartbeatConfig,
	pheromone: PheromoneConfig,
	policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	export_gates: Vec<Arc<dyn ExportGate>>,
	export_grants: Vec<Arc<dyn ExportGrant>>,
	pool_config: PoolConfig,
	control_freshness_window_ms: u64,
	bind_addr: Option<String>,
	peer: PeerConfig,
	peer_store: Arc<dyn PeerStore>,
	gossip: GossipConfig,
	tls: ClusterTlsConfig,
}

#[cfg(feature = "x509")]
impl ClusterConfig {
	/// Create a builder seeded with the given TLS material.
	pub fn builder(tls: ClusterTlsConfig) -> ClusterConfigBuilder {
		ClusterConfigBuilder {
			namespace: ColonyNamespace::default(),
			load_balancer: Arc::new(StochasticForager::default()),
			heartbeat: HeartbeatConfig::default(),
			pheromone: PheromoneConfig::default(),
			policies: Vec::new(),
			export_gates: Vec::new(),
			export_grants: Vec::new(),
			pool_config: PoolConfig::default(),
			control_freshness_window_ms: crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS,
			bind_addr: None,
			peer: PeerConfig::default(),
			peer_store: Arc::new(MemoryPeerStore),
			gossip: GossipConfig::default(),
			tls,
		}
	}
}

#[cfg(feature = "x509")]
impl ClusterConfigBuilder {
	/// Replace the hive heartbeat configuration.
	pub fn with_heartbeat_config(mut self, config: HeartbeatConfig) -> Self {
		self.heartbeat = config;
		self
	}

	/// Set route scoring: reinforcement, weaken, and evaporation.
	pub fn with_pheromone_config(mut self, config: PheromoneConfig) -> Self {
		self.pheromone = config;
		self
	}

	/// Set the naming scope inbound resource URNs are validated against.
	pub fn with_namespace(mut self, namespace: ColonyNamespace) -> Self {
		self.namespace = namespace;
		self
	}

	/// Set the load balancer strategy.
	///
	/// Defaults to [`StochasticForager`] when unset.
	pub fn with_load_balancer(mut self, load_balancer: impl LoadBalancer + 'static) -> Self {
		self.load_balancer = Arc::new(load_balancer);
		self
	}

	/// Add a gate policy evaluated before request decode.
	pub fn with_gate_policy(mut self, policy: Arc<dyn GatePolicy + Send + Sync>) -> Self {
		self.policies.push(policy);
		self
	}

	/// Restrict the export boundary to these servlet types.
	///
	/// This list drives both planes of the export boundary (see
	/// [`PeerConfig::exported_types`](super::PeerConfig)):
	///
	/// - **Discoverability**: the advertise beat filters the slate, so
	///   ads and rumors never disclose unexported types.
	/// - **Enforcement**: the built-in allowlist refuses external peers
	///   and relayed requests on unexported targets.
	///
	/// # Defaults
	///
	/// - Unset exports every locally served type.
	/// - An empty list advertises nothing and refuses every target for
	///   external peers and relayed requests.
	///
	/// First-party recognition of unexported origin traffic requires
	/// mutual TLS (see
	/// [`ClusterTlsConfig::client_validators`](super::ClusterTlsConfig)).
	pub fn with_exported_types(mut self, exported: impl IntoIterator<Item = Urn<'static>>) -> Self {
		self.peer.exported_types = Some(Arc::new(StaticExportList::new(exported)));
		self
	}

	/// Install a live export allowlist shared by discoverability and
	/// enforcement.
	///
	/// Use this when the membership must change after
	/// [`Cluster::start`](super::Cluster::start), for example a fuzz
	/// harness that mutates exports under load. Prefer
	/// [`ClusterConfigBuilder::with_exported_types`] for a fixed list.
	pub fn with_export_allowlist(mut self, exported: Arc<dyn ExportAllowlist>) -> Self {
		self.peer.exported_types = Some(exported);
		self
	}

	/// Add an export gate for granular per-identity target rules.
	///
	/// Custom [`ExportGate`] implementations compose as intersection with
	/// the allow sources (exported list, grants, and the first-party
	/// origin rule), so a gate may only narrow access.
	///
	/// # Call sites
	///
	/// Gates run where the servlet target is known:
	///
	/// - Unary work arm
	/// - Streaming and duplex open handlers
	///
	/// Gates do not filter advertisements. Discoverability follows
	/// [`ClusterConfigBuilder::with_exported_types`] alone, because ads
	/// are minted per beat, not per session.
	pub fn with_export_gate(mut self, gate: Arc<dyn ExportGate>) -> Self {
		self.export_gates.push(gate);
		self
	}

	/// Add a positive export grant for selected caller identities.
	///
	/// Grants compose as union with the exported list and the
	/// first-party origin rule, so a grant may only widen access to the
	/// granted target. Deny gates from
	/// [`ClusterConfigBuilder::with_export_gate`] still override.
	///
	/// Grants do not advertise. A granted type stays off the slate and
	/// the grantee learns its URN out of band.
	pub fn with_export_grant(mut self, grant: Arc<dyn ExportGrant>) -> Self {
		self.export_grants.push(grant);
		self
	}

	/// Set outbound connection pool settings for hive and peer dials.
	pub fn with_pool_config(mut self, config: PoolConfig) -> Self {
		self.pool_config = config;
		self
	}

	/// Set the freshness window for signed hive control frames.
	pub fn with_control_freshness_window_ms(mut self, window_ms: u64) -> Self {
		self.control_freshness_window_ms = window_ms;
		self
	}

	/// Bind the gateway to a stable address instead of the protocol default.
	///
	/// A stable address lets hives re-register through gateway restarts
	/// without reconfiguration.
	pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
		self.bind_addr = Some(addr.into());
		self
	}

	/// Replace the peer-federation configuration wholesale.
	///
	/// Covers dial list, advertise beat, dial allowlist, relay budget,
	/// rumor refresh, and exported types. Prefer granular methods when
	/// only one field changes.
	pub fn with_peer_config(mut self, config: PeerConfig) -> Self {
		self.peer = config;
		self
	}

	/// Set peer gateway addresses dialed to advertise exported types.
	///
	/// The dial list is not an identity gate. Partial or asymmetric
	/// federation graphs are expected. An empty list disables outbound
	/// advertisement.
	pub fn with_peers(mut self, peers: impl IntoIterator<Item = String>) -> Self {
		self.peer.peers = peers.into_iter().collect();
		self
	}

	/// Set the re-advertise beat cadence and enable the advertise beat.
	pub fn with_advertise_interval(mut self, interval: Duration) -> Self {
		self.peer.advertise_interval = Some(interval);
		self
	}

	/// Restrict claimed peer dial addresses to this exact-match allowlist.
	///
	/// Peer-exchange hints pass the same gate before the discovery table
	/// learns them.
	pub fn with_peer_dial_allowlist(mut self, allowlist: impl IntoIterator<Item = String>) -> Self {
		self.peer.peer_dial_allowlist = Some(allowlist.into_iter().collect());
		self
	}

	/// Cap the relay budget honored on inbound work and routed stream opens.
	///
	/// The effective budget is `min(wire value, max_hops)`. An origin
	/// request carries the sentinel budget, so the clamp also stamps the
	/// origin with this cap.
	///
	/// - The default honors a single forward.
	/// - `0` disables forwarding entirely.
	/// - `2` enables relay-trail fallback (one forward at the relay and
	///   one more to reach the owner). A gateway below that cap never
	///   installs relay trails.
	pub fn with_max_hops(mut self, max_hops: u8) -> Self {
		self.peer.max_hops = max_hops;
		self
	}

	/// Set the advertisement-rumor refresh interval.
	///
	/// The beat floods the slate rumor when the slate or flood target set
	/// changed, plus one refresh on this interval.
	///
	/// [`ClusterConfigBuilder::build`] clamps the interval to
	/// [`GossipConfig::seen_ttl`], because a refresh slower than the
	/// freshness window would re-publish rumors that peers refuse as stale.
	pub fn with_rumor_refresh(mut self, rumor_refresh: Duration) -> Self {
		self.peer.rumor_refresh = rumor_refresh;
		self
	}

	/// Set the persistence driver beneath the peer discovery table.
	///
	/// Defaults to the process-local [`MemoryPeerStore`]. A durable driver
	/// preserves learned peers across restarts. The table still owns every
	/// discovery bound, so a driver cannot bypass them.
	pub fn with_peer_store(mut self, store: Arc<dyn PeerStore>) -> Self {
		self.peer_store = store;
		self
	}

	/// Replace gossip subsystem configuration.
	///
	/// Covers freshness, origin TTL, ingress, journal, and admission.
	/// Defaults to [`GossipConfig::default`].
	pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
		self.gossip = config;
		self
	}

	/// Set per-signer gossip rate admission.
	///
	/// Defaults to the token bucket in [`GossipConfig::default`].
	pub fn with_gossip_admission(mut self, admission: Arc<dyn GossipAdmission>) -> Self {
		self.gossip.admission = admission;
		self
	}

	/// Deliver admitted rumors to local instances of this servlet type.
	///
	/// Defaults to `None`: the gateway journals and refloods only. The
	/// ingress sink sits outside the export boundary (see
	/// [`GossipConfig::ingress`](super::GossipConfig::ingress)).
	pub fn with_gossip_ingress(mut self, ingress: Urn<'static>) -> Self {
		self.gossip.ingress = Some(ingress);
		self
	}

	/// Build the cluster configuration.
	///
	/// Derives colony membership from the certificate, rebuilds the peer
	/// discovery table from the dial list, and clamps rumor refresh to the
	/// gossip freshness window.
	pub fn build(self) -> ClusterConfig {
		// Colony membership is derived from the certificate exactly once:
		// the colony URN binds to the cert's URI SAN, and every per-frame
		// membership check compares against this cached value. A cert
		// that fails to decode or carries no valid colony URN leaves the
		// gateway a non-member, fail closed.
		let colony_urn = Certificate::try_from(self.tls.certificate.clone())
			.ok()
			.and_then(|cert| cert_colony_urn(&self.namespace, &cert));

		// The discovery table derives from the dial list at build, so the
		// configured peers are always its un-evictable anchors. The
		// injected driver rehydrates learned peers through the capped
		// admission path. The anchor list is a one-time copy because
		// `peers` stays readable configuration beside the table.
		let mut peer = self.peer;
		peer.table = Arc::new(PeerTable::new(peer.peers.clone(), self.peer_store));

		// A refresh slower than the gossip freshness window would
		// re-publish advertisement rumors that peers refuse as stale,
		// so the interval clamps to the window.
		peer.rumor_refresh = peer.rumor_refresh.min(self.gossip.seen_ttl);

		ClusterConfig {
			namespace: self.namespace,
			load_balancer: self.load_balancer,
			heartbeat: self.heartbeat,
			pheromone: self.pheromone,
			policies: self.policies,
			export_gates: self.export_gates,
			export_grants: self.export_grants,
			pool_config: self.pool_config,
			control_freshness_window_ms: self.control_freshness_window_ms,
			bind_addr: self.bind_addr,
			peer,
			gossip: self.gossip,
			colony_urn,
			tls: self.tls,
		}
	}
}
