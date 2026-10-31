//! Builders for [`ClusterConfig`] and [`HeartbeatConfig`].
//!
//! [`ClusterConfigBuilder`] assembles the gateway runtime configuration: TLS
//! material, peer federation, the export boundary, gossip, and hive routing
//! defaults. [`HeartbeatConfigBuilder`] configures the hive health probes.
//!
//! # Export boundary
//!
//! Discovery and enforcement share one [`ExportAllowlist`]:
//!
//! - [`ClusterConfigBuilder::with_exported_types`] sets a static list that
//!   filters the advertise slate and drives the fail-closed allowlist.
//! - [`ClusterConfigBuilder::with_export_allowlist`] sets a live handle for
//!   membership that changes after start.
//! - [`ClusterConfigBuilder::with_export_grant`] adds positive grants, a union with the allowlist.
//! - [`ClusterConfigBuilder::with_export_gate`] adds per-identity gates that narrow the allow sources.
//!
//! # Peer federation
//!
//! The peer dial list, the advertise beat, the dial allowlist, the relay
//! budget, and the rumor refresh live on [`PeerConfig`]. Each matching
//! builder method sets one, and [`ClusterConfigBuilder::with_peer_config`]
//! replaces the section.
//!
//! # Sections and their fields
//!
//! A method that sets one field of the peer or the gossip section wins over
//! [`ClusterConfigBuilder::with_peer_config`] and
//! [`ClusterConfigBuilder::with_gossip_config`] in either call order.
//! [`ClusterConfigBuilder::build`] applies the section first and each field
//! method after it, in call order, so no field a method set is lost.
//!
//! # Build-time derivation
//!
//! [`ClusterConfigBuilder::build`] derives colony membership from the
//! certificate and rebuilds the peer discovery table from the dial list.
//! [`ClusterConfig::rumor_refresh`] clamps the rumor refresh on each read,
//! because the gossip freshness window narrows at startup.

use core::num::NonZeroUsize;
use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

use super::{
	ClusterConfig, ClusterTlsConfig, HeartbeatCallback, HeartbeatConfig, PeerConfig, PheromoneConfig,
	DEFAULT_HEARTBEAT_INTERVAL_SECS, DEFAULT_HEARTBEAT_TIMEOUT_SECS, DEFAULT_MAX_CONCURRENT, DEFAULT_MAX_FAILURES,
};
use crate::clock::{Clock, SystemClock};
use crate::colony::cluster::{LoadBalancer, StochasticForager};
use crate::colony::urn::ColonyNamespace;
use crate::policy::GatePolicy;
use crate::transport::client::PoolConfig;

use crate::colony::cluster::{
	ClusterError, ExportAllowlist, ExportGate, ExportGrant, GossipAdmission, GossipConfig, MemoryPeerStore,
	PeerAddress, PeerStore, PeerTable, StaticExportList,
};
use crate::urn::Urn;

/// The builder of [`HeartbeatConfig`].
pub struct HeartbeatConfigBuilder {
	interval: Duration,
	timeout: Duration,
	max_concurrent: NonZeroUsize,
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
	/// Create a builder with the default interval, timeout, and failure limits.
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

	/// Set the age after which the hive registry evicts a silent hive.
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

	/// Set the cap on concurrent heartbeat dials per cycle. The cap is at
	/// least one, so each cycle dials every hive in turn (CWE-835).
	///
	/// # Examples
	///
	/// ```
	/// use core::num::NonZeroUsize;
	/// use tightbeam::colony::cluster::HeartbeatConfig;
	///
	/// let one_at_a_time = HeartbeatConfig::builder().with_max_concurrent(NonZeroUsize::MIN).build();
	///
	/// assert_eq!(one_at_a_time.max_concurrent, NonZeroUsize::MIN);
	/// ```
	pub fn with_max_concurrent(mut self, max: NonZeroUsize) -> Self {
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

/// The change one field method makes to a section of the configuration.
///
/// [`ClusterConfigBuilder::build`] applies the changes of a section, in call
/// order, over the section that its whole-section method set.
type SectionEdit<S> = Box<dyn FnOnce(&mut S) + Send + Sync>;

/// The builder of [`ClusterConfig`].
///
/// Start from TLS material with [`ClusterConfig::builder`], chain the options,
/// and finish with [`ClusterConfigBuilder::build`].
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
	/// The peer section that [`Self::with_peer_config`] set.
	peer: PeerConfig,
	/// The peer fields that the field methods set, which apply over `peer`.
	peer_edits: Vec<SectionEdit<PeerConfig>>,
	peer_store: Arc<dyn PeerStore>,
	/// The gossip section that [`Self::with_gossip_config`] set.
	gossip: GossipConfig,
	/// The gossip fields that the field methods set, which apply over `gossip`.
	gossip_edits: Vec<SectionEdit<GossipConfig>>,
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
			peer_edits: Vec::new(),
			peer_store: Arc::new(MemoryPeerStore),
			gossip: GossipConfig::default(),
			gossip_edits: Vec::new(),
			clock: Arc::new(SystemClock),
			tls,
		}
	}
}

impl ClusterConfigBuilder {
	/// Replace the hive heartbeat configuration. It defaults to
	/// [`HeartbeatConfig::default`].
	pub fn with_heartbeat_config(mut self, config: HeartbeatConfig) -> Self {
		self.heartbeat = config;
		self
	}

	/// Set route scoring: the reinforcement boost, the weakening penalty, and
	/// evaporation. It defaults to [`PheromoneConfig::default`].
	pub fn with_pheromone_config(mut self, config: PheromoneConfig) -> Self {
		self.pheromone = config;
		self
	}

	/// Set the naming scope that inbound resource URNs must validate against.
	/// It defaults to [`ColonyNamespace::default`].
	pub fn with_namespace(mut self, namespace: ColonyNamespace) -> Self {
		self.namespace = namespace;
		self
	}

	/// Set the load balancer strategy.
	///
	/// The strategy defaults to [`StochasticForager`].
	pub fn with_load_balancer(mut self, load_balancer: impl LoadBalancer + 'static) -> Self {
		self.load_balancer = Arc::new(load_balancer);
		self
	}

	/// Add a gate policy that runs before the gateway decodes a request.
	pub fn with_gate_policy(mut self, policy: Arc<dyn GatePolicy + Send + Sync>) -> Self {
		self.policies.push(policy);
		self
	}

	/// Restrict the export boundary to these servlet types.
	///
	/// The list drives both planes of the export boundary
	/// ([`PeerConfig::exported_types`](super::PeerConfig)):
	///
	/// - Discovery: the advertise beat filters the slate, so ads and rumors name exported types alone.
	/// - Enforcement: the built-in allowlist refuses external peers and relayed requests on other targets.
	///
	/// # Defaults
	///
	/// - An unset list exports every local type.
	/// - An empty list advertises nothing and refuses every target for external peers and relayed requests.
	///
	/// First-party recognition of unexported origin traffic requires mutual TLS
	/// ([`ClusterTlsConfig::client_authentication`]).
	///
	/// [`ClusterTlsConfig::client_authentication`]: super::ClusterTlsConfig::client_authentication
	pub fn with_exported_types(self, exported: impl IntoIterator<Item = Urn<'static>>) -> Self {
		let list: Arc<dyn ExportAllowlist> = Arc::new(StaticExportList::new(exported));
		self.edit_peer(move |peer| peer.exported_types = Some(list))
	}

	/// Install a live export allowlist that discovery and enforcement share.
	///
	/// Use it when membership changes after
	/// [`Cluster::start`](super::Cluster::start), such as in a fuzz harness
	/// that mutates exports under load. For a fixed list, use
	/// [`ClusterConfigBuilder::with_exported_types`].
	pub fn with_export_allowlist(self, exported: Arc<dyn ExportAllowlist>) -> Self {
		self.edit_peer(move |peer| peer.exported_types = Some(exported))
	}

	/// Add an export gate for per-identity target rules.
	///
	/// Every [`ExportGate`] must pass, so a gate only narrows what the allow
	/// sources (the exported list, the grants, the first-party rule) admit.
	///
	/// # Call sites
	///
	/// Gates run where the servlet target is known:
	///
	/// - The unary work arm
	/// - The streaming and duplex open handlers
	///
	/// Gates leave advertisements as they are, because the gateway creates ads
	/// per beat, not per session. Discovery follows
	/// [`ClusterConfigBuilder::with_exported_types`] alone.
	pub fn with_export_gate(mut self, gate: Arc<dyn ExportGate>) -> Self {
		self.export_gates.push(gate);
		self
	}

	/// Add a positive export grant for selected caller identities.
	///
	/// - A target passes when exported, granted, or a first-party origin, so a grant only widens access.
	/// - A deny gate from [`ClusterConfigBuilder::with_export_gate`] overrides a grant.
	/// - A granted type stays off the slate, so the grantee learns its URN out of band.
	pub fn with_export_grant(mut self, grant: Arc<dyn ExportGrant>) -> Self {
		self.export_grants.push(grant);
		self
	}

	/// Set the outbound connection pool settings for hive and peer dials. They
	/// default to [`PoolConfig::default`].
	pub fn with_pool_config(mut self, config: PoolConfig) -> Self {
		self.pool_config = config;
		self
	}

	/// Set the freshness window for signed hive control frames. It defaults to
	/// 30 seconds.
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

	/// Bind a second accept plane for external clients, on the edge protocol
	/// that the `cluster!` macro declares.
	///
	/// It exposes the gateway to a browser transport while the colony keeps its
	/// internal protocol.
	///
	/// # Edge plane
	///
	/// - It serves the same TLS material and gate policies as the colony plane.
	/// - It admits `Work` frames alone and refuses registration, updates, peer
	///   ads, and gossip with `PermissionDenied`.
	pub fn with_edge_bind_addr(mut self, addr: impl Into<String>) -> Self {
		self.edge_bind_addr = Some(addr.into());
		self
	}

	/// Replace the peer-federation section.
	///
	/// It covers the dial list, the advertise beat, the dial allowlist, the
	/// relay budget, the rumor refresh, and the exported types. A method that
	/// sets one of these fields wins over the section, whether it comes before
	/// or after this one.
	///
	/// # Examples
	///
	/// ```
	/// # use std::sync::Arc;
	/// # use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig, PeerConfig};
	/// # use tightbeam::crypto::key::Secp256k1KeyProvider;
	/// # use tightbeam::crypto::x509::CertificateSpec;
	/// # use tightbeam::testing::{TestCertificate, TestKey};
	/// # let key = TestKey::insecure_fixed_signing();
	/// # let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
	/// # let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
	/// let mut section = PeerConfig::default();
	/// section.max_hops = 2;
	///
	/// let config = ClusterConfig::builder(tls).with_peers(["127.0.0.1:9000"])?.with_peer_config(section).build();
	///
	/// // The dial list set before the section survives it.
	/// assert_eq!((config.peer.peers().len(), config.peer.max_hops), (1, 2));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn with_peer_config(mut self, config: PeerConfig) -> Self {
		self.peer = config;
		self
	}

	/// Record a change to one peer field, which [`Self::build`] applies over
	/// the peer section.
	fn edit_peer(mut self, edit: impl FnOnce(&mut PeerConfig) + Send + Sync + 'static) -> Self {
		self.peer_edits.push(Box::new(edit));
		self
	}

	/// Set the peer gateways this gateway dials to advertise exported types.
	///
	/// The dial list names whom to dial, and peer trust decides which
	/// identities federate, so a federation graph can be partial or asymmetric.
	/// An empty list sets no anchor, so the beat advertises only to learned
	/// peers its probes proved.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- an entry names no socket. A typo
	///   fails here, so it cannot leave the federation with no anchors.
	pub fn with_peers<I, S>(self, peers: I) -> Result<Self, ClusterError>
	where
		I: IntoIterator<Item = S>,
		S: Into<String>,
	{
		let spellings: Vec<String> = peers.into_iter().map(Into::into).collect();
		let anchors = PeerConfig::anchors(spellings)?;
		Ok(self.edit_peer(move |peer| peer.peers = anchors))
	}

	/// Set the re-advertise beat cadence and enable the advertise beat.
	pub fn with_advertise_interval(self, interval: Duration) -> Self {
		self.edit_peer(move |peer| peer.advertise_interval = Some(interval))
	}

	/// Set the socket this gateway advertises as its own address.
	///
	/// The beat advertises the bound address by default. Every peer refuses the
	/// wildcard address (`0.0.0.0` or `[::]`), so a gateway bound to it names
	/// its dial address here. [`Cluster::start`] refuses a federating gateway
	/// that binds the wildcard with no advertise address.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- the address names no socket.
	///
	/// [`Cluster::start`]: super::Cluster::start
	pub fn with_advertise_addr(self, addr: impl AsRef<str>) -> Result<Self, ClusterError> {
		let address: PeerAddress = addr.as_ref().parse()?;
		Ok(self.edit_peer(move |peer| peer.advertise_addr = Some(address)))
	}

	/// Restrict claimed peer dial addresses to this allowlist.
	///
	/// Peer-exchange hints pass the same gate before the discovery table learns
	/// them. Entries are parsed sockets, so two spellings of one address are
	/// one entry.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidPeerAddress`] -- an entry names no socket.
	pub fn with_peer_dial_allowlist<I, S>(self, allowlist: I) -> Result<Self, ClusterError>
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

		let parsed = Arc::new(parsed);
		Ok(self.edit_peer(move |peer| peer.peer_dial_allowlist = Some(parsed)))
	}

	/// Cap the relay budget honored on inbound work and routed stream opens.
	///
	/// The effective budget is `min(wire value, max_hops)`, and an origin
	/// request, which carries the sentinel budget, takes this cap.
	///
	/// - The default honors a single forward.
	/// - `0` disables forwarding.
	/// - `2` enables relay-trail fallback (one forward at the relay and one more
	///   to reach the owner). A lower cap installs no relay trails.
	pub fn with_max_hops(self, max_hops: u8) -> Self {
		self.edit_peer(move |peer| peer.max_hops = max_hops)
	}

	/// Cap the tried entries one signer may hold in the discovery table.
	///
	/// A candidate whose signer already holds `cap` tried entries stays in the
	/// `new` table, the way a candidate of a full prefix bucket does. A signer
	/// is one certificate, counted by fingerprint. The default sets no cap.
	pub fn with_tried_per_signer(self, cap: NonZeroUsize) -> Self {
		self.edit_peer(move |peer| peer.tried_per_signer = Some(cap))
	}

	/// Set the advertisement-rumor refresh interval.
	///
	/// The beat floods the slate rumor on each change of the slate or the flood
	/// targets, and once per interval. [`ClusterConfig::rumor_refresh`] reads
	/// the effective interval, clamped to the freshness window. It defaults to
	/// 30 seconds.
	pub fn with_rumor_refresh(self, rumor_refresh: Duration) -> Self {
		self.edit_peer(move |peer| peer.rumor_refresh = rumor_refresh)
	}

	/// Set the persistence driver beneath the peer discovery table.
	///
	/// The driver defaults to the process-local [`MemoryPeerStore`]. A durable
	/// driver preserves learned peers across restarts. The table owns every
	/// discovery bound, so a driver cannot bypass them.
	pub fn with_peer_store(mut self, store: Arc<dyn PeerStore>) -> Self {
		self.peer_store = store;
		self
	}

	/// Replace the gossip section.
	///
	/// The section covers freshness, origin TTL, ingress, the journal, and
	/// admission, and it defaults to [`GossipConfig::default`]. The ingress
	/// and the admission that their own methods set win over the section,
	/// whether those methods come before or after this one.
	pub fn with_gossip_config(mut self, config: GossipConfig) -> Self {
		self.gossip = config;
		self
	}

	/// Record a change to one gossip field, which [`Self::build`] applies
	/// over the gossip section.
	fn edit_gossip(mut self, edit: impl FnOnce(&mut GossipConfig) + Send + Sync + 'static) -> Self {
		self.gossip_edits.push(Box::new(edit));
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
	pub fn with_gossip_admission(self, admission: Arc<dyn GossipAdmission>) -> Self {
		self.edit_gossip(move |gossip| gossip.admission = admission)
	}

	/// Deliver admitted rumors to local instances of this servlet type.
	///
	/// With no ingress, the default, the gateway only journals and refloods.
	/// The ingress sink is outside the export boundary
	/// ([`GossipConfig::ingress`](super::GossipConfig::ingress)).
	///
	/// # Call order
	///
	/// [`Cluster::start`] mints the route key of the ingress under the
	/// namespace the gateway serves ([`ClusterConfig::gossip_ingress_key`]),
	/// so this method and [`Self::with_namespace`] take effect in either order.
	///
	/// # Errors
	///
	/// - [`ClusterError::UnknownServletType`] -- the URN is no bare servlet
	///   type of the namespace it names, such as an instance or a hive. No
	///   route could answer it, so the gateway would deliver no gossip to it.
	///
	/// [`Cluster::start`]: super::Cluster::start
	pub fn with_gossip_ingress(self, ingress: Urn<'static>) -> Result<Self, ClusterError> {
		let namespace = ColonyNamespace::of(&ingress);
		let bare = namespace.is_some_and(|namespace| namespace.is_bare_servlet_type(&ingress));
		if !bare {
			return Err(ClusterError::UnknownServletType(ingress.canonical_bytes()));
		}

		Ok(self.edit_gossip(move |gossip| gossip.ingress = Some(ingress)))
	}

	/// Build the cluster configuration.
	///
	/// It applies each field method over its section, derives colony
	/// membership from the certificate, and rebuilds the peer discovery table
	/// from the dial list.
	pub fn build(self) -> ClusterConfig {
		// 1. Apply each field method over the section it changes, in call
		// order, so a whole-section method drops no field a method set.
		let mut peer = self.peer;
		self.peer_edits.into_iter().for_each(|edit| edit(&mut peer));
		let mut gossip = self.gossip;
		self.gossip_edits.into_iter().for_each(|edit| edit(&mut gossip));

		// 2. The table derives from the dial list here, so the configured peers
		// are always its anchors, which never evict. The anchors are a copy,
		// because `peers` stays readable beside the table.
		peer.table = Arc::new(PeerTable::new(&peer, self.peer_store));

		// 3. Membership binds to the certificate's URI SAN, and every per-frame
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
			gossip,
			clock: self.clock,
			colony_urn: None,
			tls: self.tls,
		};

		config.bind_colony_membership();

		config
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::urn::ServletTypeKey;
	use crate::testing::TestResult;

	/// The gossip ingress set before the gossip section survives the section.
	#[test]
	fn a_gossip_field_set_before_its_section_survives_it() -> TestResult {
		let ingress = ColonyNamespace::servlet_fixture("feed");
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let builder = builder.with_gossip_ingress(ingress.clone())?;

		let config = builder.with_gossip_config(GossipConfig::default()).build();
		assert_eq!(config.gossip.ingress, Some(ingress));
		Ok(())
	}

	/// The gossip ingress set before its namespace keys under that namespace.
	#[test]
	fn a_gossip_ingress_set_before_its_namespace_keys_under_it() -> TestResult {
		let acme = ColonyNamespace::new("acme", "prod")?;
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let builder = builder.with_gossip_ingress(acme.servlet("feed")?)?;
		let config = builder.with_namespace(acme).build();

		let key = config.gossip_ingress_key()?;
		let named = key.as_ref().map(ServletTypeKey::as_bytes);
		assert_eq!(named, Some(b"urn:acme:prod:servlet:feed".as_slice()));
		Ok(())
	}

	/// The dial list and the relay cap set before the peer section survive
	/// the section.
	#[test]
	fn a_peer_field_set_before_its_section_survives_it() -> TestResult {
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let builder = builder.with_peers(["127.0.0.1:9000"])?.with_max_hops(2);

		let config = builder.with_peer_config(PeerConfig::default()).build();
		assert_eq!((config.peer.peers().len(), config.peer.max_hops), (1, 2));
		Ok(())
	}
}
