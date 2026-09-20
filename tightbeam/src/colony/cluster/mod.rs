//! Cluster framework: gateways that route work to registered hives.
//!
//! A gateway keeps hive and servlet registries, selects routes, and
//! forwards [`ClusterWorkRequest`] payloads. Hives register dynamically
//! and announce servlet types at runtime.
//!
//! # Work routing
//!
//! - Hives register and announce servlet types.
//! - Clients send work with a servlet type and payload.
//! - The gateway selects a route and forwards the payload.
//!
//! # Peer federation
//!
//! With the `x509` feature, gateways advertise exported servlet types to
//! peer gateways, honor relay budgets, and learn remote routes through
//! gossip. Trust anchors live on [`ClusterTlsConfig::peer_trust`].
//!
//! # Export boundary
//!
//! [`PeerConfig::exported_types`], [`ClusterConfig::export_grants`]
//! (via [`export::ExportGrant`]), and [`ClusterConfig::export_gates`]
//! (via [`export::ExportGate`]) govern what external peers may discover
//! and reach. Enforcement order is allowlist, then grants, then deny
//! gates. See the [`export`] module.
//!
//! # Gossip
//!
//! Colony-scoped rumor floods use the [`gossip`] subsystem for
//! deduplication, retention, and anti-entropy repair.

pub mod builder;
pub mod error;
pub mod macros;
pub mod registry;
mod runtime;
pub mod servlet_registry;

pub mod export;
pub(crate) mod outbound;
pub(crate) mod peer;

#[doc(hidden)]
pub mod gossip;
#[doc(hidden)]
pub mod peer_table;

pub use builder::{ClusterConfigBuilder, HeartbeatConfigBuilder};
pub use error::ClusterError;
pub use export::{
	DynamicExportList, ExportAllowlist, ExportGate, ExportGrant, Party, StaticExportList, TrustPlaneStores, TrustPlanes,
};
pub use gossip::{
	gossip_fresh, gossip_want, wanted_digests, Admission, AdmittedGossip, GossipAdmission, GossipConfig, GossipDigest,
	GossipJournal, LocalClaim, LocalClaimGuard, MemoryGossipJournal, TokenBucketAdmission,
};
pub use peer::{AdmittedPeerAd, HopBudget, RelayTrail};
pub use peer_table::{AddressGroup, MemoryPeerStore, PeerAddress, PeerHint, PeerRecord, PeerStore, PeerTable};
pub use registry::{HiveEntry, HiveRegistry, SharedId};
pub use runtime::ClusterGateway;
pub use servlet_registry::{
	LocalRoute, PeerCaps, PeerRoute, PeerRouteInfo, PheromoneConfig, RelayRoute, RouteKind, ServletEntry,
	ServletRegistry, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS, DEFAULT_EVAPORATION_RATE_BPS,
	DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};

use core::future::Future;
use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

use crate::constants::{DEFAULT_AD_RUMOR_REFRESH_MS, DEFAULT_MAX_HOPS};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::x509::{policy::CertificateValidation, CertificateSpec};
use crate::policy::GatePolicy;
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::state::ClientIdentity;
use crate::transport::{Protocol, TightBeamAddress};
use crate::utils::urn::Urn;
use crate::TightBeamError;

use super::common::{ColonyNamespace, ColonyResource, InstanceMetrics, LoadBalancer, ServletAddressUpdate};

// =============================================================================
// Configuration
// =============================================================================

pub(crate) const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;
pub(crate) const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 15;
pub(crate) const DEFAULT_MAX_CONCURRENT: usize = 10;
pub(crate) const DEFAULT_MAX_FAILURES: u32 = 3;

/// Heartbeat cadence, eviction timeout, and failure tolerance.
///
/// A failed heartbeat is retried on the next `interval` cycle.
/// Eviction uses `max_failures`, not a separate retry policy.
pub struct HeartbeatConfig {
	/// Time between heartbeat cycles.
	pub interval: Duration,
	/// Age after which a silent hive is evicted.
	pub timeout: Duration,
	/// Cap on concurrent heartbeat dials per cycle.
	pub max_concurrent: usize,
	/// Consecutive failures before unregistering a hive.
	pub max_failures: u32,
	/// Optional per-result callback for monitoring or tests.
	pub on_heartbeat: Option<HeartbeatCallback>,
}

impl Default for HeartbeatConfig {
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

impl core::fmt::Debug for HeartbeatConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HeartbeatConfig")
			.field("interval", &self.interval)
			.field("timeout", &self.timeout)
			.field("max_concurrent", &self.max_concurrent)
			.field("max_failures", &self.max_failures)
			.field("on_heartbeat", &self.on_heartbeat.as_ref().map(|_| "Some(...)"))
			.finish()
	}
}

impl HeartbeatConfig {
	/// Attach a callback invoked after each heartbeat result.
	pub fn with_callback(mut self, callback: HeartbeatCallback) -> Self {
		self.on_heartbeat = Some(callback);
		self
	}
}

/// Outcome of one hive heartbeat, for monitoring or tests.
#[derive(Debug, Clone)]
pub struct HeartbeatEvent {
	/// Hive control address that was dialed.
	pub hive_addr: Arc<[u8]>,
	/// Whether the hive answered within policy.
	pub success: bool,
	/// Utilization from the hive when the heartbeat succeeded.
	pub utilization: Option<crate::utils::BasisPoints>,
}

/// Callback after each heartbeat result.
///
/// Must be `Send + Sync`: the loop may invoke it from concurrent tasks.
pub type HeartbeatCallback = Arc<dyn Fn(HeartbeatEvent) + Send + Sync>;

/// TLS material for the gateway accept loop and hive/peer dials.
#[non_exhaustive]
pub struct ClusterTlsConfig {
	/// The gateway certificate and handshake key, decoded once by
	/// [`Self::new`]. The certificate is the server identity, and outbound
	/// dials present it as the client certificate.
	identity: ClientIdentity,
	/// Server-certificate validators for outbound dials.
	///
	/// Each validator evaluates the dialed server certificate after the
	/// trust-store check, on both the hive and the peer plane. Use this
	/// chain for operator checks such as pinning or expiry policy.
	pub validators: Vec<Arc<dyn CertificateValidation>>,
	/// Client-certificate validators for inbound mutual TLS.
	pub client_validators: Vec<Arc<dyn CertificateValidation>>,
	/// Trust store for the hive plane.
	///
	/// The store fills three roles:
	///
	/// 1. Outbound dials to hives and servlets validate the server
	///    certificate against it.
	/// 2. Hive-origin control frames (registration, spawn results)
	///    verify their signature against it.
	/// 3. The export boundary classifies a caller as first-party when
	///    the store holds the caller's public key and `peer_trust` does
	///    not (see [`TrustPlanes`]).
	pub hive_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
	/// Trust anchor for peer-gateway advertisements and relayed gossip.
	///
	/// Separate from `hive_trust`: peer certificates cannot register as
	/// hives, and hive certificates cannot forge peer ads. Membership
	/// here wins over `hive_trust` on every plane, so a public key held
	/// by both stores stays an external peer. `None` disables inbound
	/// federation (advertisements are refused).
	pub peer_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
}

impl ClusterTlsConfig {
	/// Decode `certificate` and bind it to the key that proves it.
	///
	/// One identity serves every plane: the colony and edge listeners present
	/// it, and outbound hive and peer dials offer it as the client
	/// certificate. Decoding it here means those planes share one certificate
	/// rather than each decoding the specification again.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `certificate` holds PEM or
	///   DER that does not decode as a certificate.
	pub fn new(certificate: CertificateSpec, key: Arc<dyn SigningKeyProvider>) -> Result<Self, TightBeamError> {
		let identity = ClientIdentity::from_spec(certificate, key)?;

		Ok(Self {
			identity,
			validators: Vec::new(),
			client_validators: Vec::new(),
			hive_trust: None,
			peer_trust: None,
		})
	}

	/// Replace the server-certificate validators applied to outbound dials.
	#[must_use]
	pub fn with_validators(mut self, validators: Vec<Arc<dyn CertificateValidation>>) -> Self {
		self.validators = validators;
		self
	}

	/// Replace the client-certificate validators applied to inbound mutual TLS.
	#[must_use]
	pub fn with_client_validators(mut self, validators: Vec<Arc<dyn CertificateValidation>>) -> Self {
		self.client_validators = validators;
		self
	}

	/// Replace the hive-plane trust store.
	#[must_use]
	pub fn with_hive_trust(
		mut self,
		store: impl Into<Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>>,
	) -> Self {
		self.hive_trust = store.into();
		self
	}

	/// Replace the peer-plane trust anchor.
	#[must_use]
	pub fn with_peer_trust(
		mut self,
		store: impl Into<Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>>,
	) -> Self {
		self.peer_trust = store.into();
		self
	}

	/// The certificate and handshake key this gateway presents.
	///
	/// One identity serves the colony listener, the edge listener, and every
	/// outbound hive and peer dial, so all of them read it here and cannot
	/// disagree.
	pub fn identity(&self) -> &ClientIdentity {
		&self.identity
	}
}

impl Clone for ClusterTlsConfig {
	fn clone(&self) -> Self {
		Self {
			identity: self.identity.clone(),
			validators: self.validators.iter().map(Arc::clone).collect(),
			client_validators: self.client_validators.iter().map(Arc::clone).collect(),
			hive_trust: self.hive_trust.as_ref().map(Arc::clone),
			peer_trust: self.peer_trust.as_ref().map(Arc::clone),
		}
	}
}

impl core::fmt::Debug for ClusterTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterTlsConfig")
			.field("identity", &"<ClientIdentity>")
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.field("client_validators", &format!("[{} validators]", self.client_validators.len()))
			.field("hive_trust", &self.hive_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.field("peer_trust", &self.peer_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.finish()
	}
}

/// Peer-federation dial list, advertise beat, and inbound dial allowlist.
///
/// Trust anchors stay on [`ClusterTlsConfig::peer_trust`]. Export
/// discoverability and enforcement share [`PeerConfig::exported_types`].
#[derive(Clone)]
pub struct PeerConfig {
	/// Peer gateway addresses dialed to advertise exported types.
	///
	/// The dial list is not an identity gate. Partial or asymmetric
	/// federation graphs are expected. An empty list disables outbound
	/// advertisement.
	///
	/// The slate is never configured directly: each beat snapshots the
	/// local servlet registry so peers learn types currently served.
	///
	/// Private because [`PeerConfig::table`] derives its anchor set from
	/// this list at build. Set it with
	/// [`ClusterConfigBuilder::with_peers`], which parses each entry, and
	/// read it with [`PeerConfig::peers`].
	peers: Vec<PeerAddress>,
	/// Re-advertise beat cadence. `None` disables the beat.
	pub advertise_interval: Option<Duration>,
	/// Inbound peer ads may only claim dial addresses in this list.
	///
	/// Entries are parsed sockets, so one address spelled two ways is one
	/// entry. `None` accepts any parseable socket. Peer-exchange hints pass
	/// the same gate before the table learns them, so discovery never dials
	/// an address outside the list.
	///
	/// Private because the parse is the point. Set it with
	/// [`ClusterConfigBuilder::with_peer_dial_allowlist`] and read it with
	/// [`PeerConfig::peer_dial_allowlist`].
	peer_dial_allowlist: Option<Arc<HashSet<PeerAddress>>>,
	/// Discovery table: `peers` as un-evictable anchors plus bounded,
	/// prefix-bucketed learned peers.
	///
	/// The config builder rebuilds it so anchors always derive from
	/// `peers` and the injected [`PeerStore`] rehydrates learned peers
	/// through the capped admission path.
	///
	/// Private because it is derived. Read it with [`PeerConfig::table`].
	table: Arc<PeerTable>,
	/// Cap on the relay budget this gateway honors on inbound work and
	/// routed stream opens.
	///
	/// The effective budget is `min(wire value, max_hops)`. An origin
	/// request carries the sentinel budget, so the clamp also stamps the
	/// origin with this cap.
	///
	/// - The default [`DEFAULT_MAX_HOPS`] forwards at most once.
	/// - `0` disables forwarding entirely.
	/// - `2` enables relay-trail fallback.
	pub max_hops: u8,
	/// Advertisement-rumor refresh interval.
	///
	/// The beat floods the slate rumor when the slate or flood target set
	/// changed, plus one refresh on this interval.
	///
	/// This is the configured interval. A refreshed rumor must still admit
	/// as fresh, so the effective interval is this value clamped to
	/// [`GossipConfig::seen_ttl`]. Private because the clamped value is the
	/// one every caller wants: set it with
	/// [`ClusterConfigBuilder::with_rumor_refresh`] and read it with
	/// [`ClusterConfig::rumor_refresh`].
	rumor_refresh: Duration,
	/// Servlet types disclosed to and reachable by external peers.
	///
	/// `None` exports every locally served type. `Some` restricts both
	/// planes of the export boundary through an [`ExportAllowlist`]:
	///
	/// - **Discoverability**: each advertise beat asks
	///   [`ExportAllowlist::allows_canonical`] per local servlet key,
	///   so ads and rumors never disclose unexported types.
	/// - **Enforcement**: the gateway calls
	///   [`ExportAllowlist::contains`] on unary Work and routed stream
	///   opens. External peers and relayed requests are refused on
	///   unexported targets even when they guess the type name.
	///
	/// Install a static list with
	/// [`ClusterConfigBuilder::with_exported_types`] or a live handle
	/// with [`ClusterConfigBuilder::with_export_allowlist`].
	pub exported_types: Option<Arc<dyn ExportAllowlist>>,
}

impl PeerConfig {
	/// Peer gateway addresses this plane dials to advertise exported types.
	///
	/// These are the table's un-evictable anchors.
	#[must_use]
	pub fn peers(&self) -> &[PeerAddress] {
		&self.peers
	}

	/// The discovery table the anchors and learned peers live in.
	#[must_use]
	pub fn table(&self) -> &Arc<PeerTable> {
		&self.table
	}

	/// Dial addresses inbound peer ads may claim, when restricted.
	#[must_use]
	pub fn peer_dial_allowlist(&self) -> Option<&Arc<HashSet<PeerAddress>>> {
		self.peer_dial_allowlist.as_ref()
	}

	/// Whether this plane may dial `address`.
	///
	/// Both sides are parsed sockets, so one address spelled two ways
	/// cannot pass one caller's check and fail another's. An unrestricted
	/// plane admits any address that parsed at all.
	#[must_use]
	pub fn dial_allowed(&self, address: &PeerAddress) -> bool {
		match &self.peer_dial_allowlist {
			Some(allowed) => allowed.contains(address),
			None => true,
		}
	}

	/// Restrict claimed dial addresses to `allowlist`.
	///
	/// The builder is the configuration path;
	/// [`ClusterConfigBuilder::with_peer_dial_allowlist`] parses operator
	/// strings into the set this takes. Tests that already hold parsed
	/// addresses install them here.
	#[cfg(test)]
	pub(crate) fn set_dial_allowlist(&mut self, allowlist: HashSet<PeerAddress>) {
		self.peer_dial_allowlist = Some(Arc::new(allowlist));
	}
}

/// The default peer plane: no peers, no beat, no allowlist, and the
/// single-forward relay cap.
impl Default for PeerConfig {
	fn default() -> Self {
		Self {
			peers: Vec::new(),
			advertise_interval: None,
			peer_dial_allowlist: None,
			table: Arc::default(),
			max_hops: DEFAULT_MAX_HOPS,
			rumor_refresh: Duration::from_millis(DEFAULT_AD_RUMOR_REFRESH_MS),
			exported_types: None,
		}
	}
}

impl core::fmt::Debug for PeerConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut debug = f.debug_struct("PeerConfig");
		debug
			.field("peers", &self.peers)
			.field("advertise_interval", &self.advertise_interval)
			.field("peer_dial_allowlist", &self.peer_dial_allowlist)
			.field("table", &self.table)
			.field("max_hops", &self.max_hops)
			.field("rumor_refresh", &self.rumor_refresh);

		debug.field("exported_types", &self.exported_types.as_ref().map(|_| "<ExportAllowlist>"));

		debug.finish()
	}
}

/// Runtime configuration for a cluster gateway.
///
/// Assembled through [`ClusterConfigBuilder`] or
/// [`ClusterConfig::new`]. The load balancer defaults to
/// [`StochasticForager`](crate::colony::common::StochasticForager).
pub struct ClusterConfig {
	/// Naming scope for inbound resource URNs.
	///
	/// Foreign authority or realm on register, update, or work is refused.
	pub namespace: ColonyNamespace,
	/// Strategy for selecting among candidate servlet instances.
	pub load_balancer: Arc<dyn LoadBalancer>,
	/// Hive health probes and eviction policy.
	pub heartbeat: HeartbeatConfig,
	/// Route scoring: reinforcement, weaken, and evaporation.
	pub pheromone: PheromoneConfig,
	/// Gate policies evaluated before request decode.
	pub policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	/// Custom export gates evaluated where the servlet target is known.
	///
	/// All gates must pass, so they compose as intersection with the allow
	/// sources (exported list, grants, and the first-party origin rule).
	pub export_gates: Vec<Arc<dyn ExportGate>>,
	/// Positive export grants evaluated when the built-in allowlist
	/// refuses a target.
	///
	/// Allow sources compose as union: exported, granted, or first-party
	/// origin. Deny gates still override a grant. Granted types never
	/// appear on the advertised slate.
	pub export_grants: Vec<Arc<dyn ExportGrant>>,
	/// Outbound connection pool settings for hive and peer dials.
	pub pool_config: PoolConfig,
	/// Freshness window (ms) for signed hive control frames.
	///
	/// Stale or replayed registration/update frames are rejected (CWE-294).
	pub control_freshness_window_ms: u64,
	/// Gateway bind address via the protocol address `FromStr`.
	///
	/// `None` binds the protocol default. A stable address lets hives
	/// re-register across gateway restarts without reconfiguration.
	pub bind_addr: Option<String>,
	/// Edge accept plane bind address via the edge protocol address `FromStr`.
	///
	/// `None` disables the edge plane. When set, the gateway binds a second
	/// listener with the same TLS material for external clients (for example
	/// a browser transport) and admits `Work` frames only: control frames are
	/// refused with `PermissionDenied`, so an edge client can never join the
	/// colony control plane. Hives keep registering on `bind_addr`.
	pub edge_bind_addr: Option<String>,
	/// Peer-federation dial list, advertise beat, and dial allowlist.
	pub peer: PeerConfig,
	/// Gossip freshness, origin TTL, ingress, journal, and admission.
	pub gossip: GossipConfig,
	/// Colony URN from the gateway certificate URI SAN.
	///
	/// `None` means not a colony member: gossip publish/relay/reconcile
	/// and peer ads are refused, and the advertise beat skips gossip
	/// reconciliation. Work and hive registration never require membership.
	///
	/// Private so membership cannot drift from the certificate.
	/// [`ClusterConfig::bind_colony_membership`] derives it, last at
	/// startup, and [`ClusterConfig::colony_urn`] reads it.
	colony_urn: Option<Urn<'static>>,
	/// TLS material for accept and outbound dials.
	pub tls: ClusterTlsConfig,
}

/// Parsed address-update delta: hive id, added entries, removed locators.
pub(crate) type ParsedAddressUpdate<'a> = (Arc<[u8]>, Vec<ServletEntry>, Vec<&'a [u8]>);

impl ClusterConfig {
	/// Effective advertisement-rumor refresh interval.
	///
	/// A refresh slower than the gossip freshness window would re-publish
	/// rumors that peers refuse as stale, so the configured interval is
	/// clamped to [`GossipConfig::seen_ttl`] here. The window itself narrows
	/// at startup to journal retention, and deriving on read is what keeps
	/// the two from disagreeing.
	#[must_use]
	pub fn rumor_refresh(&self) -> Duration {
		self.peer.rumor_refresh.min(self.gossip.seen_ttl)
	}

	/// Parse hive identity, added entries, and removed instance locators.
	///
	/// [`None`] where the hive URN, any added locator, or any removed URN
	/// falls outside this colony's namespace. The delta is parsed whole, so
	/// the registry applies it or sees nothing.
	pub(crate) fn parse_address_update<'a>(&self, update: &'a ServletAddressUpdate) -> Option<ParsedAddressUpdate<'a>> {
		let ColonyResource::Hive { addr } = self.namespace.validate(&update.hive_id).ok()? else {
			return None;
		};

		if !update.added.iter().all(|info| self.namespace.locator_matches(info)) {
			return None;
		}

		let mut removed = Vec::with_capacity(update.removed.len());
		for urn in &update.removed {
			match self.namespace.validate(urn) {
				Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => removed.push(locator.as_bytes()),
				_ => return None,
			}
		}

		let hive_id: Arc<[u8]> = Arc::from(addr.as_bytes());
		let added = self.pheromone.servlet_slate(&update.added, &hive_id);
		Some((hive_id, added, removed))
	}

	/// One balancer draw over `entries`, guarding the untrusted index.
	///
	/// The balancer is operator-configurable, so its answer is untrusted.
	pub(crate) fn pick_instance<'e>(
		&self,
		entries: &'e (impl AsRef<[Arc<ServletEntry>]> + ?Sized),
	) -> Option<&'e Arc<ServletEntry>> {
		let entries = entries.as_ref();
		// The key copy is deliberate. `InstanceMetrics` owns its key.
		let metrics: Vec<InstanceMetrics> = entries
			.iter()
			.map(|entry| InstanceMetrics {
				instance_key: entry.route_key().to_vec(),
				pheromone: entry.pheromone_level(),
			})
			.collect();

		self.load_balancer.select(&metrics).and_then(|idx| entries.get(idx))
	}

	/// Build a default config around the given TLS material.
	pub fn new(tls: ClusterTlsConfig) -> Self {
		Self::builder(tls).build()
	}

	/// Colony URN from the gateway certificate URI SAN.
	///
	/// `None` when this gateway is not a colony member.
	#[must_use]
	pub fn colony_urn(&self) -> Option<&Urn<'static>> {
		self.colony_urn.as_ref()
	}

	/// Binds colony membership to the certificate this config now holds.
	///
	/// Unlike [`ClusterConfig::rumor_refresh`], which derives on read, this
	/// one is cached: deriving it means decoding the certificate's URI SAN,
	/// and every inbound gossip frame asks. It is bound again at startup
	/// because the certificate and the namespace stay writable until the
	/// gateway takes the config, and a value derived from an earlier
	/// certificate would claim the wrong colony.
	pub(crate) fn bind_colony_membership(&mut self) {
		self.colony_urn = self.namespace.cert_colony_urn(self.tls.identity().certificate());
	}
}

impl core::fmt::Debug for ClusterConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterConfig")
			.field("namespace", &self.namespace)
			.field("heartbeat", &self.heartbeat)
			.field("pheromone", &self.pheromone)
			.field("policies", &format!("[{} policies]", self.policies.len()))
			.field("export_gates", &format!("[{} gates]", self.export_gates.len()))
			.field("export_grants", &format!("[{} grants]", self.export_grants.len()))
			.field("pool_config", &self.pool_config)
			.field("control_freshness_window_ms", &self.control_freshness_window_ms)
			.field("bind_addr", &self.bind_addr)
			.field("edge_bind_addr", &self.edge_bind_addr)
			.field("peer", &self.peer)
			.field("gossip", &self.gossip)
			.field("colony_urn", &self.colony_urn)
			.field("tls", &self.tls)
			.finish()
	}
}

// =============================================================================
// Work Request/Response Messages
// =============================================================================

pub use crate::colony::common::{ClusterRequest, ClusterWorkRequest, ClusterWorkResponse};

// =============================================================================
// Cluster Trait
// =============================================================================

/// Trait for cluster gateway implementations.
///
/// Gateways route work to registered hives by servlet type. Hives
/// register dynamically, and servlet types are learned from those
/// registrations.
pub trait Cluster: Sized + Send + Sync {
	/// Protocol this gateway serves.
	type Protocol: Protocol;

	/// Bound address type for this gateway.
	type Address: TightBeamAddress;

	/// Bind, spawn accept and background loops, and return the running gateway.
	fn start(
		trace: Arc<TraceCollector>,
		config: ClusterConfig,
	) -> impl Future<Output = Result<Self, crate::TightBeamError>> + Send;

	/// Gateway listen address, borrowed without a clone.
	fn addr(&self) -> &Self::Address;

	/// Servlet types available from registered local hives.
	fn available_servlets(&self) -> Vec<SharedId>;

	/// Servlet types reachable through peer gateways (learned, not local).
	fn peer_servlets(&self) -> Vec<SharedId>;

	/// Learned peer routes with dial address and peer identity.
	fn peer_routes(&self) -> Vec<PeerRouteInfo>;

	/// Count of currently registered hives.
	fn hive_count(&self) -> usize;

	/// Shared trace collector for this gateway.
	fn trace(&self) -> Arc<TraceCollector>;

	/// Abort accept and background tasks.
	fn stop(self);

	/// Wait until the accept loops finish.
	///
	/// Awaits the colony accept task and, when bound, the edge accept task.
	fn join(self) -> impl Future<Output = Result<(), crate::colony::servlet::servlet_runtime::rt::JoinError>> + Send;
}

/// Heartbeat surface of a cluster gateway.
///
/// Split from [`Cluster`] so work-only consumers never depend on health
/// internals. [`ClusterGateway`] implements both traits for every alias.
pub trait ClusterHeartbeat: Cluster {
	/// Shared hive registry.
	fn registry(&self) -> &Arc<HiveRegistry>;

	/// Heartbeat interval, timeout, and failure policy.
	fn heartbeat_config(&self) -> &HeartbeatConfig;

	/// Send one signed heartbeat to a hive via the connection pool.
	///
	/// The background loop lives in [`ClusterGateway::start`]
	/// (`JoinSet`, bounded concurrency). It is not on this trait.
	fn send_heartbeat(
		&self,
		addr: Self::Address,
	) -> impl Future<Output = Result<super::common::HeartbeatResult, ClusterError>> + Send;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::common::{ColonyNamespace, RegisterHiveRequest};
	use crate::colony::hive::ServletInfo;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::policy::TransitStatus;
	use crate::testing::{TestCertificate, TestKey};

	// =========================================================================
	// Test Helpers
	// =========================================================================

	fn test_tls_config() -> ClusterTlsConfig {
		let key: Secp256k1SigningKey = TestKey::signing();
		ClusterTlsConfig::new(
			CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key))),
			Arc::new(Secp256k1KeyProvider::from(key)),
		)
		.expect("the test certificate must decode")
	}

	fn test_registry() -> HiveRegistry {
		HiveRegistry::new(Duration::from_secs(15))
	}

	fn servlet_urn(name: &(impl AsRef<str> + ?Sized)) -> crate::utils::urn::Urn<'static> {
		let name = name.as_ref();
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	/// The signer every fixture registration binds. Registration always
	/// names one, so the tests name one too.
	fn test_signer() -> SharedId {
		Arc::from(b"test-signer".as_slice())
	}

	fn request(addr: impl AsRef<[u8]>, servlets: &[&str]) -> RegisterHiveRequest {
		let addr = addr.as_ref();
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			metadata: None,
			servlet_addresses: servlets
				.iter()
				.map(|s| ServletInfo { servlet_id: servlet_urn(s), address: addr.to_vec() })
				.collect(),
		}
	}

	fn request_with_meta(addr: impl AsRef<[u8]>, servlets: &[&str], meta: impl AsRef<[u8]>) -> RegisterHiveRequest {
		let addr = addr.as_ref();
		let meta = meta.as_ref();
		let mut request = request(addr, servlets);
		request.metadata = Some(meta.to_vec());
		request
	}

	// =========================================================================
	// ClusterConfig Tests
	// =========================================================================

	#[test]
	fn cluster_config_defaults() {
		let config = ClusterConfig::new(test_tls_config());
		assert_eq!(config.heartbeat.interval, Duration::from_secs(5));
		assert_eq!(config.heartbeat.timeout, Duration::from_secs(15));
		assert!(config.policies.is_empty());
		assert!(config.peer.peer_dial_allowlist.is_none());
	}

	/// A parsed dial address, which every fixture spelling names.
	fn address(spelling: &str) -> PeerAddress {
		spelling.parse().expect("fixture addresses name sockets")
	}

	/// A config whose configured refresh and gossip window are set apart,
	/// so each side of the clamp can be asserted on its own.
	fn config_refreshing(refresh: Duration, seen_ttl: Duration) -> ClusterConfig {
		let mut config = ClusterConfig::builder(test_tls_config()).with_rumor_refresh(refresh).build();
		config.gossip.seen_ttl = seen_ttl;
		config
	}

	#[test]
	fn a_refresh_slower_than_the_window_is_clamped_to_it() {
		let config = config_refreshing(Duration::from_millis(900), Duration::from_millis(400));

		// The window narrows at startup, so a refresh stored clamped at
		// build would re-publish rumors peers refuse as stale.
		assert_eq!(config.rumor_refresh(), Duration::from_millis(400));
	}

	#[test]
	fn a_refresh_inside_the_window_is_the_one_configured() {
		let config = config_refreshing(Duration::from_millis(300), Duration::from_millis(400));

		// The clamp is a ceiling, not a replacement: an operator asking to
		// refresh more often than the window still gets what they asked for.
		assert_eq!(config.rumor_refresh(), Duration::from_millis(300));
	}

	#[test]
	fn cluster_config_peers_accept_str_slices() -> Result<(), ClusterError> {
		let config = ClusterConfig::builder(test_tls_config())
			.with_peers(["127.0.0.1:9000", "127.0.0.1:9001"])?
			.with_peer_dial_allowlist(["127.0.0.1:9000"])?
			.build();

		let anchors: Vec<String> = config.peer.peers().iter().map(PeerAddress::to_string).collect();
		assert_eq!(anchors, ["127.0.0.1:9000", "127.0.0.1:9001"]);

		let allowed = address("127.0.0.1:9000");
		assert!(config.peer.dial_allowed(&allowed));

		let refused = address("127.0.0.1:9001");
		assert!(!config.peer.dial_allowed(&refused));
		Ok(())
	}

	/// A peer the operator mistyped is refused where it was written, not
	/// dropped into a federation with no anchors.
	#[test]
	fn cluster_config_refuses_a_peer_that_names_no_socket() {
		let refusal = ClusterConfig::builder(test_tls_config()).with_peers(["not-an-address"]);

		assert!(matches!(refusal, Err(ClusterError::InvalidPeerAddress)));
	}

	// =========================================================================
	// ClusterWorkResponse Tests
	// =========================================================================

	#[test]
	fn work_response_ok() {
		let response = ClusterWorkResponse::ok(b"test".to_vec());
		assert_eq!(response.status, TransitStatus::Ok);
		assert_eq!(response.payload, Some(b"test".to_vec()));
	}

	#[test]
	fn work_response_ok_accepts_byte_slices() {
		let response = ClusterWorkResponse::ok(b"test");
		assert_eq!(response.status, TransitStatus::Ok);
		assert_eq!(response.payload.as_deref(), Some(b"test".as_slice()));
	}

	#[test]
	fn work_response_err() {
		let response = ClusterWorkResponse::err(TransitStatus::PermissionDenied);
		assert_eq!(response.status, TransitStatus::PermissionDenied);
		assert!(response.payload.is_none());
	}

	// =========================================================================
	// HiveRegistry Tests
	// =========================================================================

	#[test]
	fn registry_register_and_lookup() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping", "calc"]), test_signer())?;

		let hives = registry.all_hives()?;
		assert_eq!(hives.len(), 1);
		assert_eq!(hives[0].address.as_ref(), b"127.0.0.1:8080");
		Ok(())
	}

	#[test]
	fn registry_unregister() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping"]), test_signer())?;
		assert_eq!(registry.len()?, 1);
		assert!(registry.unregister(b"127.0.0.1:8080")?.is_some());
		assert_eq!(registry.len()?, 0);
		Ok(())
	}

	#[test]
	fn registry_update_utilization() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping"]), test_signer())?;
		assert!(registry.update_utilization(b"127.0.0.1:8080", crate::bps!(5000))?);

		let hives = registry.all_hives()?;
		assert_eq!(hives.len(), 1);
		assert_eq!(hives[0].utilization.get(), 5000);
		Ok(())
	}

	#[test]
	fn registry_all_hives() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &["ping"]), test_signer())?;
		registry.register(request_with_meta(b"hive2", &["calc"], b"metadata"), test_signer())?;

		let all = registry.all_hives()?;
		assert_eq!(all.len(), 2);

		let addrs: Vec<_> = all.iter().map(|e| e.address.as_ref()).collect();
		assert!(addrs.contains(&b"hive1".as_slice()));
		assert!(addrs.contains(&b"hive2".as_slice()));

		Ok(())
	}
}
