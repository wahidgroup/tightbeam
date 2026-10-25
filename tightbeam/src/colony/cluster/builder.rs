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
//! certificate and rebuilds the peer discovery table from the dial list.
//! [`ClusterConfig::rumor_refresh`] derives the effective rumor refresh
//! interval on every read, because the gossip freshness window it clamps to
//! narrows at startup.

use core::num::NonZeroUsize;
use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

use super::{
	ClusterConfig, ClusterTlsConfig, HeartbeatCallback, HeartbeatConfig, PeerConfig, PheromoneConfig,
	DEFAULT_HEARTBEAT_INTERVAL_SECS, DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FAILURES,
};
use crate::colony::cluster::{LoadBalancer, StochasticForager};
use crate::colony::urn::ColonyNamespace;
use crate::policy::GatePolicy;
use crate::transport::client::PoolConfig;
use crate::utils::time::{Clock, SystemClock};

use crate::colony::cluster::{
	ClusterError, ExportAllowlist, ExportGate, ExportGrant, GossipAdmission, GossipConfig, MemoryPeerStore,
	PeerAddress, PeerStore, PeerTable, StaticExportList,
};
use crate::urn::Urn;

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

	/// Set the count of consecutive failures after which the cluster
	/// unregisters a hive.
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

/// Builder for [`ClusterConfig`].
///
/// Start from TLS material through [`ClusterConfig::builder`], then chain
/// federation, export, gossip, and routing options before
/// [`ClusterConfigBuilder::build`].
pub struct ClusterConfigBuilder {
	namespace: ColonyNamespace,
	load_balancer: Arc<dyn LoadBalancer>,
	heartbeat: HeartbeatConfig,
	pheromone: PheromoneConfig,
	policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	export_gates: Vec<Arc<dyn ExportGate>>,
	export_grants: Vec<Arc<dyn ExportGrant>>,
	pool_config: PoolConfig,
	control_freshness_window: Duration,
	bind_addr: Option<String>,
	edge_bind_addr: Option<String>,
	peer: PeerConfig,
	peer_store: Arc<dyn PeerStore>,
	gossip: GossipConfig,
	clock: Arc<dyn Clock>,
	tls: ClusterTlsConfig,
}

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
			control_freshness_window: Duration::from_millis(crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS),
			bind_addr: None,
			edge_bind_addr: None,
			peer: PeerConfig::default(),
			peer_store: Arc::new(MemoryPeerStore),
			gossip: GossipConfig::default(),
			clock: Arc::new(SystemClock),
			tls,
		}
	}
}

impl ClusterConfigBuilder {
	/// Replace the hive heartbeat configuration.
	pub fn with_heartbeat_config(mut self, config: HeartbeatConfig) -> Self {
		self.heartbeat = config;
		self
	}

	/// Set route scoring: the reinforcement boost, the weakening penalty, and
	/// evaporation.
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
	/// - An empty list advertises nothing and refuses every target for external peers and relayed requests.
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
	/// Discoverability follows [`ClusterConfigBuilder::with_exported_types`]
	/// alone and gates leave advertisements as they are, because the gateway
	/// creates ads per beat and not per session.
	pub fn with_export_gate(mut self, gate: Arc<dyn ExportGate>) -> Self {
		self.export_gates.push(gate);
		self
	}

	/// Add a positive export grant for selected caller identities.
	///
	/// - Grants compose as union with the exported list and the first-party
	///   origin rule, so a grant only widens access to the granted target.
	/// - Deny gates from [`ClusterConfigBuilder::with_export_gate`] still override.
	/// - A grant leaves the slate as it is, so a granted type stays off it and
	///   the grantee learns its URN out of band.
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
	pub fn with_control_freshness_window(mut self, window: Duration) -> Self {
		self.control_freshness_window = window;
		self
	}

	/// Bind the gateway to a stable address instead of the protocol default.
	///
	/// A stable address lets hives re-register after a gateway restart with
	/// the address they already hold.
	pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
		self.bind_addr = Some(addr.into());
		self
	}

	/// Bind a second accept plane for external clients on the edge
	/// protocol declared by the `cluster!` macro.
	///
	/// Use this to expose the gateway to a browser transport while the colony
	/// keeps its internal protocol.
	///
	/// # Edge plane
	///
	/// - It serves the same TLS material and gate policies as the colony plane.
	/// - It admits `Work` frames only. Registration, updates, peer ads, and
	///   gossip are refused with `PermissionDenied`.
	pub fn with_edge_bind_addr(mut self, addr: impl Into<String>) -> Self {
		self.edge_bind_addr = Some(addr.into());
		self
	}

	/// Replace the peer-federation configuration wholesale.
	///
	/// The configuration covers the dial list, the advertise beat, the dial
	/// allowlist, the relay budget, the rumor refresh, and the exported types.
	/// Prefer the granular methods when only one field changes.
	pub fn with_peer_config(mut self, config: PeerConfig) -> Self {
		self.peer = config;
		self
	}

	/// Set the peer gateway addresses this gateway dials to advertise its
	/// exported types.
	///
	/// The method accepts any iterator of values convertible into [`String`],
	/// such as a `&str` array. The dial list names whom to dial and peer trust
	/// decides which identities federate, so a partial or asymmetric federation
	/// graph is expected. An empty list disables outbound advertisement.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- an entry names no socket. A
	///   typo fails here with a diagnostic, so it cannot leave the federation
	///   with no anchors.
	pub fn with_peers<I, S>(mut self, peers: I) -> Result<Self, ClusterError>
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		let spellings: Vec<String> = peers.into_iter().map(Into::into).collect();
		self.peer.set_anchors(spellings)?;
		Ok(self)
	}

	/// Set the re-advertise beat cadence and enable the advertise beat.
	pub fn with_advertise_interval(mut self, interval: Duration) -> Self {
		self.peer.advertise_interval = Some(interval);
		self
	}

	/// Set the socket this gateway advertises as its own gateway address.
	///
	/// The beat advertises the bound address by default. A gateway bound to
	/// the wildcard address (`0.0.0.0` or `[::]`) would advertise a socket
	/// every peer refuses, so it names the address peers dial here.
	/// [`Cluster::start`] refuses a federating gateway that binds the
	/// wildcard and sets no advertise address.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- the address names no socket.
	///
	/// [`Cluster::start`]: super::Cluster::start
	pub fn with_advertise_addr(mut self, addr: impl AsRef<str>) -> Result<Self, ClusterError> {
		let address: PeerAddress = addr.as_ref().parse()?;
		self.peer.advertise_addr = Some(address);
		Ok(self)
	}

	/// Restrict claimed peer dial addresses to this allowlist.
	///
	/// The method accepts any iterator of values convertible into [`String`].
	/// Peer-exchange hints pass the same gate before the discovery table
	/// learns them. The gate compares entries as parsed sockets, so a peer
	/// cannot pass it with two spellings of one address.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- an entry names no socket.
	pub fn with_peer_dial_allowlist<I, S>(mut self, allowlist: I) -> Result<Self, ClusterError>
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		let mut parsed = HashSet::new();
		for entry in allowlist {
			let entry: String = entry.into();
			let address: PeerAddress = entry.parse()?;
			parsed.insert(address);
		}

		self.peer.peer_dial_allowlist = Some(Arc::new(parsed));
		Ok(self)
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

	/// Cap the tried entries one signer may hold in the discovery table.
	///
	/// A candidate whose signer already holds `cap` tried entries stays in the
	/// `new` table, the way a candidate of a full prefix bucket does. A signer
	/// is one certificate, counted by fingerprint. The default sets no cap.
	pub fn with_tried_per_signer(mut self, cap: NonZeroUsize) -> Self {
		self.peer.tried_per_signer = Some(cap);
		self
	}

	/// Set the advertisement-rumor refresh interval.
	///
	/// The beat floods the slate rumor when the slate or flood target set
	/// changed, plus one refresh on this interval.
	/// [`ClusterConfig::rumor_refresh`] reads the effective interval, which it
	/// clamps to the freshness window.
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

	/// Replace the gossip subsystem configuration.
	///
	/// The configuration covers freshness, origin TTL, ingress, the journal,
	/// and admission, and it defaults to [`GossipConfig::default`].
	pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
		self.gossip = config;
		self
	}

	/// Set the clock the gateway reads, which defaults to [`SystemClock`].
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Set per-signer gossip rate admission.
	///
	/// The admission defaults to the token bucket of [`GossipConfig::default`].
	pub fn with_gossip_admission(mut self, admission: Arc<dyn GossipAdmission>) -> Self {
		self.gossip.admission = admission;
		self
	}

	/// Deliver admitted rumors to local instances of this servlet type.
	///
	/// The ingress defaults to `None`, so the gateway journals and refloods
	/// only. The ingress sink sits outside the export boundary (see
	/// [`GossipConfig::ingress`](super::GossipConfig::ingress)).
	///
	/// # Errors
	///
	/// - [`ClusterError::UnknownServletType`] -- the URN is not a bare
	///   servlet type in this colony's namespace, so no route could ever
	///   answer it. A gateway that admitted gossip for it would deliver none
	///   of that gossip, so the call refuses the URN here.
	pub fn with_gossip_ingress(mut self, ingress: Urn<'static>) -> Result<Self, ClusterError> {
		let Some(type_key) = self.namespace.servlet_type_key(&ingress) else {
			return Err(ClusterError::UnknownServletType(ingress.canonical_bytes()));
		};

		self.gossip.ingress = Some(type_key);
		Ok(self)
	}

	/// Build the cluster configuration.
	///
	/// It derives colony membership from the certificate and rebuilds the
	/// peer discovery table from the dial list.
	pub fn build(self) -> ClusterConfig {
		// The discovery table derives from the dial list here, so the
		// configured peers are always its un-evictable anchors. The anchor
		// list is a copy, because `peers` stays readable beside the table.
		let mut peer = self.peer;
		peer.table = Arc::new(PeerTable::new(&peer, self.peer_store));

		// Membership binds to the certificate's URI SAN, and every per-frame
		// flood check reads the cached value. A certificate with no single
		// valid colony URN leaves the gateway a non-member, which fails closed.
		let mut config = ClusterConfig {
			namespace: self.namespace,
			load_balancer: self.load_balancer,
			heartbeat: self.heartbeat,
			pheromone: self.pheromone,
			policies: self.policies,
			export_gates: self.export_gates,
			export_grants: self.export_grants,
			pool_config: self.pool_config,
			control_freshness_window: self.control_freshness_window,
			bind_addr: self.bind_addr,
			edge_bind_addr: self.edge_bind_addr,
			peer,
			gossip: self.gossip,
			clock: self.clock,
			colony_urn: None,
			tls: self.tls,
		};

		config.bind_colony_membership();

		config
	}
}
