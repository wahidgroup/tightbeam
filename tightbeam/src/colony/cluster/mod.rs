//! The cluster framework, whose gateways route work to registered hives.
//!
//! A gateway keeps hive and servlet registries, selects routes, and
//! forwards [`ClusterWorkRequest`] payloads. Hives register and announce
//! their servlet types at runtime.
//!
//! # Work routing
//!
//! - Hives register and announce servlet types.
//! - Clients send work with a servlet type and a payload.
//! - The gateway selects a route and forwards the payload.
//!
//! # Peer federation
//!
//! Gateways advertise exported servlet types to peer gateways, honor relay
//! budgets, and learn remote routes through gossip. Trust anchors live on
//! [`ClusterTlsConfig::peer_trust`]. Every address a peer claims passes
//! [`PeerConfig::admit_dial`], and the [`AdmittedDial`] it returns is the one
//! form a claimed address takes on the way to a dial.
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
//! Rumor floods across the colonies use the gossip subsystem ([`GossipConfig`],
//! [`GossipJournal`]) for deduplication, retention, and anti-entropy repair.

mod dial;
mod runtime;

pub mod builder;
pub mod error;
pub mod macros;
pub mod registry;
pub mod servlet_registry;

pub mod export;
pub(crate) mod outbound;
pub(crate) mod peer;

pub(crate) mod gossip;
pub(crate) mod peer_table;

pub use builder::{ClusterConfigBuilder, HeartbeatConfigBuilder};
pub use dial::{AdmittedDial, DialRefusal};
pub use error::ClusterError;
pub use export::{
	DynamicExportList, ExportAllowlist, ExportGate, ExportGrant, Party, StaticExportList, TrustPlaneStores, TrustPlanes,
};
pub use gossip::{
	gossip_fresh, gossip_want, wanted_digests, Admission, AdmittedGossip, GossipAdmission, GossipConfig, GossipDigest,
	GossipJournal, JournalLimits, LocalClaim, LocalClaimGuard, MemoryGossipJournal, TokenBucketAdmission,
	VerifiedRumor,
};
pub use peer::{AdmittedPeerAd, HopBudget, RelayTrail, WireHopBudget};
pub use peer_table::{
	AddressGroup, MemoryPeerStore, NotASocket, PeerAddress, PeerHint, PeerRecord, PeerStore, PeerTable,
};
pub use registry::{HiveEntry, HiveRegistry, SharedId};
pub use runtime::ClusterGateway;
pub(crate) use runtime::{ColonyConfig, ColonyDialProtocol};
pub(crate) use servlet_registry::HiveSlate;
pub use servlet_registry::{
	DialTarget, LocalRoute, PeerCaps, PeerRoute, PeerRouteInfo, PheromoneConfig, RelayRoute, RouteKind, ServletEntry,
	ServletRegistry, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS, DEFAULT_EVAPORATION_RATE_BPS,
	DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
};

#[cfg(test)]
pub(crate) use runtime::ColonyDigest;

use core::future::Future;
use core::num::NonZeroUsize;
use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

use crate::constants::{DEFAULT_AD_RUMOR_REFRESH_MS, DEFAULT_MAX_HOPS};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::{policy::CertificateValidation, CertificateSpec, KeyPurposes};
use crate::policy::GatePolicy;
use crate::trace::TraceCollector;
use crate::transport::client::{ConnectionBuilder, ConnectionPoolBuilder, PoolConfig};
use crate::transport::handshake::PeerAuthentication;
use crate::transport::{Protocol, TightBeamAddress, TransportEncryptionConfig};
use crate::urn::Urn;
use crate::utils::time::Clock;
use crate::TightBeamError;

use super::common::{ColonyNamespace, ColonyResource, InstanceMetrics, LoadBalancer, ServletAddressUpdate};

pub(crate) const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;
pub(crate) const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 15;
pub(crate) const DEFAULT_MAX_CONCURRENT: usize = 10;
pub(crate) const DEFAULT_MAX_FAILURES: u32 = 3;

/// Heartbeat cadence, eviction timeout, and failure tolerance.
///
/// The heartbeat loop retries a failed heartbeat on the next `interval`
/// cycle, and eviction counts against `max_failures` rather than a separate
/// retry policy.
pub struct HeartbeatConfig {
	/// Time between heartbeat cycles.
	pub interval: Duration,
	/// Age after which a silent hive is evicted.
	pub timeout: Duration,
	/// Cap on concurrent heartbeat dials per cycle.
	pub max_concurrent: usize,
	/// Consecutive failures that unregister a hive.
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
	/// The hive control address the heartbeat dialed.
	pub hive_addr: Arc<[u8]>,
	/// Whether the hive answered within policy.
	pub success: bool,
	/// Utilization from the hive when the heartbeat succeeded.
	pub utilization: Option<crate::utils::BasisPoints>,
}

/// Callback invoked after each heartbeat result.
///
/// The callback MUST be `Send + Sync` because the loop may invoke it from
/// concurrent tasks.
pub type HeartbeatCallback = Arc<dyn Fn(HeartbeatEvent) + Send + Sync>;

/// TLS material for the gateway accept loop and the hive and peer dials.
#[non_exhaustive]
pub struct ClusterTlsConfig {
	/// The gateway certificate and handshake key, from [`Self::new`] or
	/// [`Self::from_identity`]. The certificate is the server identity, and
	/// outbound dials present it as the client certificate.
	identity: SigningIdentity,
	/// The key purpose of each role the identity serves. The identity's
	/// certificate is held to the signer purpose here, and the accept planes
	/// and the outbound dials hold it to the server and client purposes.
	key_purposes: KeyPurposes,
	/// The server policy of every outbound dial on both planes. Every gateway
	/// dial runs the HPKE flow, so each validator evaluates the signing
	/// certificate that the dialed server's reply names.
	///
	/// The store alone admits each issuer and each root. A check of every
	/// certificate, such as a denylist, belongs in the store's
	/// [`RevocationChecker`](crate::crypto::x509::store::RevocationChecker).
	pub validators: Vec<Arc<dyn CertificateValidation>>,
	/// Client-certificate validators for inbound mutual TLS.
	pub client_validators: Vec<Arc<dyn CertificateValidation>>,
	/// Trust store for the hive plane.
	///
	/// The store fills three roles:
	///
	/// 1. Outbound dials to hives and servlets validate the server certificate against it.
	/// 2. Hive-origin control frames (registration, spawn results) verify their signature against it.
	/// 3. The export boundary classifies a caller as first-party when
	///    the store holds the caller's public key and `peer_trust` does
	///    not (see [`TrustPlanes`]).
	pub hive_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
	/// Trust anchor for peer-gateway advertisements and relayed gossip.
	///
	/// The store is separate from `hive_trust`, so a peer certificate cannot
	/// register as a hive and a hive certificate cannot forge a peer ad.
	/// Membership here wins over `hive_trust` on every plane, so a public key
	/// held by both stores stays an external peer. `None` disables inbound
	/// federation, and the gateway then refuses advertisements.
	pub peer_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
}

impl ClusterTlsConfig {
	/// Decode `certificate` and bind it to the key that proves it, under the
	/// house provider.
	///
	/// One identity serves every plane: the colony and edge listeners present
	/// it, and outbound hive and peer dials offer it as the client
	/// certificate. This method decodes it once, so every plane shares the one
	/// decoded certificate.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `certificate` holds PEM or
	///   DER that does not decode as a certificate.
	/// - [`TightBeamError::CertificateValidationError`] -- the certificate
	///   fails [`Self::from_identity`] under [`KeyPurposes::HOUSE`].
	/// - [`TightBeamError`] -- the errors of [`SigningIdentity::new`], as their conversion names them.
	pub fn new(certificate: CertificateSpec, key: Arc<dyn SigningKeyProvider>) -> Result<Self, TightBeamError> {
		let identity = SigningIdentity::from_spec(certificate, key)?;
		Ok(Self::from_identity(identity, KeyPurposes::HOUSE)?)
	}

	/// Serve every plane under `identity`, with the key purpose of each role
	/// that `key_purposes` names. [`KeyPurposes::HOUSE`] holds the house
	/// purposes.
	///
	/// - The identity signs this gateway's frames, so its certificate MUST
	///   name `key_purposes.signer` or `anyExtendedKeyUsage`, or carry no
	///   `extendedKeyUsage` (RFC 5280 §4.2.1.12).
	/// - The accept planes and the outbound dials hold the certificate to the
	///   server and client purposes, as
	///   [`TransportEncryptionConfig::with_key_purposes`] states.
	///
	/// # Errors
	///
	/// - [`CertificateValidationError`] -- the certificate fails
	///   [`CertificateExt::require_purpose`] for `key_purposes.signer`.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::cluster::ClusterTlsConfig;
	/// use tightbeam::crypto::key::Secp256k1KeyProvider;
	/// use tightbeam::crypto::sign::SigningIdentity;
	/// use tightbeam::crypto::x509::KeyPurposes;
	/// use tightbeam::der::asn1::ObjectIdentifier;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let own = ObjectIdentifier::new("1.3.6.1.4.1.99999.3.12")?;
	/// let certificate = TestCertificate::self_signed(&key);
	/// let certificate = TestCertificate::with_key_purposes(certificate, [own]);
	/// let provider = Arc::new(Secp256k1KeyProvider::from(key));
	/// let identity = SigningIdentity::new(certificate, provider)?;
	///
	/// let purposes = KeyPurposes { signer: own, ..KeyPurposes::HOUSE };
	/// let tls = ClusterTlsConfig::from_identity(identity, purposes)?;
	/// assert!(tls.peer_trust.is_none());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`TransportEncryptionConfig::with_key_purposes`]: TransportEncryptionConfig::with_key_purposes
	pub fn from_identity(
		identity: SigningIdentity,
		key_purposes: KeyPurposes,
	) -> Result<Self, CertificateValidationError> {
		identity.certificate().require_purpose(key_purposes.signer)?;

		Ok(Self {
			identity,
			key_purposes,
			validators: Vec::new(),
			client_validators: Vec::new(),
			hive_trust: None,
			peer_trust: None,
		})
	}

	/// Replace the server policy of outbound dials, which evaluates the
	/// signing certificate that the dialed server's HPKE reply names, as
	/// [`Self::validators`] states.
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

	/// How the accept planes authenticate their clients.
	///
	/// [`PeerAuthentication::mutual`] decides what the validator list means,
	/// so an empty list is server authentication only, and the gateway then
	/// captures no client identity.
	pub fn peer_authentication(&self) -> PeerAuthentication {
		PeerAuthentication::mutual(self.client_validators.iter().map(Arc::clone))
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

	/// The store that names a peer gateway this gateway dials.
	///
	/// - A dial to a peer verifies its handshake against it.
	/// - The flood reads its members from it.
	/// - [`TrustPlanes::peer_identity`] names a peer by it.
	///
	/// A configured peer plane keeps peer dials on `peer_trust`. A gateway with
	/// no peer plane dials its peers on the hive pool, so `hive_trust` answers
	/// for it, by the rule of [`TrustPlanes::peer_dial`]. [`Self::pools`]
	/// builds the pools by the same rule.
	#[must_use]
	pub(crate) fn peer_dial_trust(&self) -> Option<&dyn crate::crypto::x509::store::CertificateTrust> {
		TrustPlanes::from(self).peer_dial()
	}

	/// The certificate and handshake key this gateway presents.
	///
	/// One identity serves the colony listener, the edge listener, and every
	/// outbound hive and peer dial, so all of them read it here and agree.
	pub fn identity(&self) -> &SigningIdentity {
		&self.identity
	}

	/// The encryption config the colony and edge listeners share.
	///
	/// Both planes present the same certificate and key, so an external edge
	/// client pins the same gateway identity that hives already trust.
	///
	/// - The client validators are those of [`Self::peer_authentication`].
	/// - The key purposes are the ones [`Self::from_identity`] installed.
	pub(crate) fn accept_encryption<C: CryptoProvider>(&self) -> TransportEncryptionConfig<C> {
		let encryption = TransportEncryptionConfig::new(self.identity.clone());
		let validators = self.client_validators.iter().map(Arc::clone);

		let encryption = encryption.with_client_validators(validators);
		encryption.with_key_purposes(self.key_purposes)
	}

	/// Configures `builder` to dial under this identity: the pool presents the
	/// identity as its client certificate, runs [`Self::validators`] as the
	/// server policy, and holds both sides to the key purposes
	/// [`Self::from_identity`] installed.
	pub(crate) fn outbound<P: Protocol>(&self, builder: ConnectionPoolBuilder<P>) -> ConnectionPoolBuilder<P> {
		let validators = self.validators.iter().map(Arc::clone);
		let builder = builder.with_client_identity(self.identity.clone());
		builder.with_server_policy(validators).with_key_purposes(self.key_purposes)
	}
}

impl Clone for ClusterTlsConfig {
	fn clone(&self) -> Self {
		Self {
			identity: self.identity.clone(),
			key_purposes: self.key_purposes,
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
			.field("identity", &self.identity)
			.field("key_purposes", &self.key_purposes)
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.field("client_validators", &format!("[{} validators]", self.client_validators.len()))
			.field("hive_trust", &self.hive_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.field("peer_trust", &self.peer_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.finish()
	}
}

/// Peer-federation dial list, advertise beat and address, and the policy that
/// admits the dial addresses peers claim.
///
/// Trust anchors stay on [`ClusterTlsConfig::peer_trust`]. Export
/// discoverability and enforcement share [`PeerConfig::exported_types`].
#[derive(Clone)]
pub struct PeerConfig {
	/// Peer gateway addresses dialed to advertise exported types.
	///
	/// - The dial list picks dial targets alone, and partial or asymmetric federation graphs are expected.
	/// - An empty list disables outbound advertisement.
	/// - Each beat snapshots the local servlet registry as the slate, so peers
	///   learn the types this gateway serves at that beat.
	///
	/// The field is private because [`PeerConfig::table`] derives its anchor
	/// set from this list at build. Set it with
	/// [`ClusterConfigBuilder::with_peers`], which parses each entry, and
	/// read it with [`PeerConfig::peers`].
	peers: Vec<AdmittedDial>,
	/// Cadence of the re-advertise beat, where `None` disables the beat.
	pub advertise_interval: Option<Duration>,
	/// The socket this gateway advertises as its own, when the operator set
	/// one.
	///
	/// - `None` advertises the bound address, which peers dial for a gateway bound to one interface.
	/// - A gateway bound to the wildcard address sets this, because every peer refuses a claim of `0.0.0.0`.
	advertise_addr: Option<PeerAddress>,
	/// Inbound peer ads may only claim dial addresses in this list.
	///
	/// - Entries are parsed sockets, so one address spelled two ways is one entry.
	/// - `None` accepts any parseable socket.
	/// - Peer-exchange hints pass the same gate before the table learns them,
	///   so discovery dials addresses from the list alone.
	///
	/// The field is private so that every entry is a parsed socket. Set it with
	/// [`ClusterConfigBuilder::with_peer_dial_allowlist`] and read it with
	/// [`PeerConfig::peer_dial_allowlist`].
	peer_dial_allowlist: Option<Arc<HashSet<PeerAddress>>>,
	/// The discovery table, which holds `peers` as un-evictable anchors beside
	/// the bounded, prefix-bucketed learned peers.
	///
	/// - The config builder rebuilds it, so anchors always derive from
	///   `peers` and the injected [`PeerStore`] rehydrates learned peers
	///   through the capped admission path.
	/// - The field is private because it is derived. Read it with [`PeerConfig::table`].
	table: Arc<PeerTable>,
	/// Cap on the relay budget this gateway honors on inbound work and
	/// routed stream opens.
	///
	/// The effective budget is `min(wire value, max_hops)`. An origin
	/// request carries the sentinel budget, so the clamp also stamps the
	/// origin with this cap.
	///
	/// - The default [`DEFAULT_MAX_HOPS`] forwards at most once.
	/// - `0` disables forwarding.
	/// - `2` enables relay-trail fallback.
	pub max_hops: u8,
	/// Cap on the tried entries one signer may hold in the discovery table,
	/// where `None` sets no cap.
	///
	/// - The prefix buckets bound a network position, and this bounds an identity (CWE-770).
	/// - One enrolled certificate that answers at many addresses takes at most this many beat-target slots.
	/// - It is off by default, so an implementor whose trust store admits
	///   parties it does not control turns it on.
	/// - A signer is one certificate, counted by fingerprint. A party that
	///   enrolls more than one certificate holds this many entries under each.
	/// - The field is private because the builder copies it into the table at
	///   build, so a later write changes nothing. Set it with
	///   [`ClusterConfigBuilder::with_tried_per_signer`].
	tried_per_signer: Option<NonZeroUsize>,
	/// Advertisement-rumor refresh interval, as configured.
	///
	/// The beat floods the slate rumor when the slate or flood target set
	/// changed, plus one refresh on this interval.
	///
	/// The field is private because the clamped value is the one every caller
	/// wants. Set it with [`ClusterConfigBuilder::with_rumor_refresh`] and
	/// read the effective interval with [`ClusterConfig::rumor_refresh`].
	rumor_refresh: Duration,
	/// Servlet types disclosed to and reachable by external peers.
	///
	/// `None` exports every locally served type. `Some` restricts both
	/// planes of the export boundary through an [`ExportAllowlist`]:
	///
	/// - **Discoverability**: each advertise beat asks
	///   [`ExportAllowlist::allows_canonical`] per local servlet key,
	///   so ads and rumors disclose exported types only.
	/// - **Enforcement**: the gateway calls
	///   [`ExportAllowlist::contains`] on unary Work and routed stream
	///   opens. It refuses external peers and relayed requests on
	///   unexported targets, even when they guess the type name.
	///
	/// Install a static list with
	/// [`ClusterConfigBuilder::with_exported_types`] or a live handle
	/// with [`ClusterConfigBuilder::with_export_allowlist`].
	pub exported_types: Option<Arc<dyn ExportAllowlist>>,
}

impl PeerConfig {
	/// Peer gateway addresses this plane dials to advertise exported types.
	///
	/// These are the table's un-evictable anchors, admitted as operator
	/// configuration.
	#[must_use]
	pub fn peers(&self) -> &[AdmittedDial] {
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
}

/// The default peer plane has no peers, no beat, and no allowlist. It
/// advertises the bound address and holds the single-forward relay cap.
impl Default for PeerConfig {
	fn default() -> Self {
		Self {
			peers: Vec::new(),
			advertise_interval: None,
			advertise_addr: None,
			peer_dial_allowlist: None,
			table: Arc::default(),
			max_hops: DEFAULT_MAX_HOPS,
			tried_per_signer: None,
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
			.field("advertise_addr", &self.advertise_addr)
			.field("peer_dial_allowlist", &self.peer_dial_allowlist)
			.field("tried_per_signer", &self.tried_per_signer)
			.field("table", &self.table)
			.field("max_hops", &self.max_hops)
			.field("rumor_refresh", &self.rumor_refresh);

		debug.field("exported_types", &self.exported_types.as_ref().map(|_| "<ExportAllowlist>"));
		debug.finish()
	}
}

/// Runtime configuration for a cluster gateway.
///
/// Build one with [`ClusterConfigBuilder`] or
/// [`ClusterConfig::new`]. The load balancer defaults to
/// [`StochasticForager`](crate::colony::common::StochasticForager).
pub struct ClusterConfig {
	/// Naming scope for inbound resource URNs.
	///
	/// The gateway refuses a register, update, or work request that names a
	/// foreign authority or realm.
	pub namespace: ColonyNamespace,
	/// Strategy that selects among candidate servlet instances.
	pub load_balancer: Arc<dyn LoadBalancer>,
	/// Hive health probes and eviction policy.
	pub heartbeat: HeartbeatConfig,
	/// Route scoring: reinforcement, weakening, and evaporation.
	pub pheromone: PheromoneConfig,
	/// Gate policies the gateway evaluates before it decodes a request.
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
	/// origin. Deny gates still override a grant. The advertised slate lists
	/// exported types alone, so a granted type stays off it.
	pub export_grants: Vec<Arc<dyn ExportGrant>>,
	/// Outbound connection pool settings for hive and peer dials. The pools
	/// read [`ClusterConfig::clock`].
	pub pool_config: PoolConfig,
	/// Freshness window for signed hive control frames.
	///
	/// The gateway refuses a stale or replayed registration or update frame
	/// (CWE-294).
	pub control_freshness_window: Duration,
	/// Gateway bind address, parsed through the protocol address `FromStr`.
	///
	/// `None` binds the protocol default. A stable address lets hives
	/// re-register across gateway restarts without reconfiguration.
	pub bind_addr: Option<String>,
	/// Edge accept plane bind address, parsed by the edge address `FromStr`.
	///
	/// - `None` disables the edge plane.
	/// - `Some` binds a second listener with the same TLS material for external
	///   clients, such as a browser transport.
	/// - The edge listener admits `Work` frames only. It refuses control frames
	///   with `PermissionDenied`, so an edge client can never join the colony
	///   control plane.
	/// - Hives still register on `bind_addr`.
	pub edge_bind_addr: Option<String>,
	/// Peer-federation dial list, advertise beat and address, and dial policy.
	pub peer: PeerConfig,
	/// Gossip freshness, origin TTL, ingress, journal, and admission.
	///
	/// Startup clamps [`GossipConfig::seen_ttl`] to the journal's retention. A
	/// rumor older than retention has no digest left, so a wider window would
	/// re-admit a replay as new (CWE-294).
	pub gossip: GossipConfig,
	/// The clock every freshness, replay, retention and lease decision on
	/// this gateway reads. It defaults to
	/// [`SystemClock`](crate::utils::time::SystemClock).
	pub clock: Arc<dyn Clock>,
	/// Colony URN from the gateway certificate URI SAN.
	///
	/// `None` means the gateway is not a colony member, so it is in no flood
	/// ([`ClusterConfig::flood`]):
	///
	/// - The gateway refuses peer ads and every gossip publish, relay, and reconcile.
	/// - The advertise beat skips gossip reconciliation.
	/// - Work and hive registration proceed without membership.
	///
	/// The field is private so membership stays bound to the certificate.
	/// [`ClusterConfig::bind_colony_membership`] derives it, last at
	/// startup, and [`ClusterConfig::colony_urn`] reads it.
	colony_urn: Option<Urn<'static>>,
	/// TLS material for the accept planes and the outbound dials.
	pub tls: ClusterTlsConfig,
}

/// Parsed address-update delta: the hive's added routes, owned by that
/// hive, and the locators it removes.
pub(crate) type ParsedAddressUpdate<'a> = (HiveSlate, Vec<&'a [u8]>);

impl ClusterConfig {
	/// Effective advertisement-rumor refresh interval.
	///
	/// A refresh slower than the gossip freshness window would re-publish
	/// rumors that peers refuse as stale, so this method clamps the configured
	/// interval to [`GossipConfig::seen_ttl`]. The window itself narrows at
	/// startup to journal retention, so this method derives the interval on
	/// each read and the two stay in agreement.
	#[must_use]
	pub fn rumor_refresh(&self) -> Duration {
		self.peer.rumor_refresh.min(self.gossip.seen_ttl)
	}

	/// Parse the hive identity, the added entries, and the removed instance
	/// locators.
	///
	/// Returns [`None`] when the hive URN, any added locator, or any removed
	/// URN falls outside this colony's namespace, or when an added locator
	/// names an address other than the one beside it. This method parses the
	/// delta whole, so the registry applies all of it or none of it.
	pub(crate) fn parse_address_update<'a>(&self, update: &'a ServletAddressUpdate) -> Option<ParsedAddressUpdate<'a>> {
		let ColonyResource::Hive { addr } = self.namespace.validate(&update.hive_id).ok()? else {
			return None;
		};

		let mut removed = Vec::with_capacity(update.removed.len());
		for urn in &update.removed {
			match self.namespace.validate(urn) {
				Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => removed.push(locator.as_bytes()),
				_ => return None,
			}
		}

		let hive_id: Arc<[u8]> = Arc::from(addr.as_bytes());
		let added = self.servlet_slate(&update.added, &hive_id).ok()?;
		Some((added, removed))
	}

	/// Draws one balancer pick over `entries` and guards the untrusted index.
	///
	/// The balancer is operator-configurable, so its answer is untrusted.
	pub(crate) fn pick_instance<'e>(
		&self,
		entries: &'e (impl AsRef<[Arc<ServletEntry>]> + ?Sized),
	) -> Option<&'e Arc<ServletEntry>> {
		let entries = entries.as_ref();
		// `InstanceMetrics` owns its key, so the copy is deliberate.
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
	/// It returns `None` when this gateway is not a colony member.
	#[must_use]
	pub fn colony_urn(&self) -> Option<&Urn<'static>> {
		self.colony_urn.as_ref()
	}

	/// Binds colony membership to the certificate this config holds.
	///
	/// # Caching
	///
	/// [`ClusterConfig::rumor_refresh`] derives on read, but this config caches
	/// membership, because its derivation decodes the certificate's URI SAN
	/// and every inbound gossip frame asks for it.
	///
	/// # Rebinding at startup
	///
	/// The certificate and the namespace stay writable until the gateway takes
	/// the config, so a value derived from an earlier certificate would claim
	/// the wrong colony. Startup binds it again for that reason.
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
			.field("control_freshness_window", &self.control_freshness_window)
			.field("bind_addr", &self.bind_addr)
			.field("edge_bind_addr", &self.edge_bind_addr)
			.field("peer", &self.peer)
			.field("gossip", &self.gossip)
			.field("clock", &self.clock)
			.field("colony_urn", &self.colony_urn)
			.field("tls", &self.tls)
			.finish()
	}
}

pub use crate::colony::common::{ClusterRequest, ClusterWorkRequest, ClusterWorkResponse};

/// The trait a cluster gateway implements.
///
/// Gateways route work to registered hives by servlet type. Hives
/// register at runtime, and the gateway learns servlet types from those
/// registrations.
pub trait Cluster: Sized + Send + Sync {
	/// Protocol this gateway serves.
	type Protocol: Protocol;

	/// Bound address type for this gateway.
	type Address: TightBeamAddress;

	/// Bind, spawn the accept and background loops, and return the running
	/// gateway.
	///
	/// # Errors
	///
	/// - [`TightBeamError::TransportError`] -- `bind_addr` or `edge_bind_addr`
	///   does not parse, or an accept plane fails to bind.
	/// - [`TightBeamError::ClusterError`] -- the gateway beats from a wildcard
	///   bind with no advertise address.
	/// - [`TightBeamError`] -- the trace collector refuses an export-posture warning.
	fn start(
		trace: Arc<TraceCollector>,
		config: ClusterConfig,
	) -> impl Future<Output = Result<Self, crate::TightBeamError>> + Send;

	/// The address the gateway listens on.
	fn addr(&self) -> &Self::Address;

	/// Servlet types available from registered local hives.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route registry is poisoned.
	fn available_servlets(&self) -> Result<Vec<SharedId>, ClusterError>;

	/// Servlet types reachable through the routes learned from peer gateways.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route registry is poisoned.
	fn peer_servlets(&self) -> Result<Vec<SharedId>, ClusterError>;

	/// Learned peer routes, each with its dial address and peer identity.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route registry is poisoned.
	fn peer_routes(&self) -> Result<Vec<PeerRouteInfo>, ClusterError>;

	/// The number of registered hives.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the hive registry is poisoned.
	fn hive_count(&self) -> Result<usize, ClusterError>;

	/// Shared trace collector for this gateway.
	fn trace(&self) -> Arc<TraceCollector>;

	/// Abort the accept and background tasks.
	fn stop(self);

	/// Wait until the accept loops finish.
	///
	/// Awaits the colony accept task and, when bound, the edge accept task.
	///
	/// # Errors
	///
	/// - [`JoinError`](crate::runtime::rt::JoinError) -- an accept task panicked or was aborted.
	fn join(self) -> impl Future<Output = Result<(), crate::runtime::rt::JoinError>> + Send;
}

/// Heartbeat surface of a cluster gateway.
///
/// The trait is split from [`Cluster`], so work-only consumers depend on the
/// work surface alone. [`ClusterGateway`] implements both traits for every
/// alias.
pub trait ClusterHeartbeat: Cluster {
	/// Shared hive registry.
	fn registry(&self) -> &Arc<HiveRegistry>;

	/// Heartbeat interval, timeout, and failure policy.
	fn heartbeat_config(&self) -> &HeartbeatConfig;

	/// Send one signed heartbeat to the hive registered at `addr`, through the
	/// connection pool.
	///
	/// The dial admits only the identity that signed the hive's registration,
	/// so the command leaves only toward that identity (CWE-346). The
	/// background loop, a `JoinSet` with bounded concurrency, lives in
	/// [`ClusterGateway::start`] rather than on this trait.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- no hive is registered at `addr`,
	///   or `addr` does not parse to dial.
	/// - [`ClusterError::PeerMismatch`] -- another identity answered at `addr`.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	/// - [`ClusterError::NoResponse`] -- the hive closed without answering.
	/// - [`ClusterError::MalformedResponse`] -- the answer carried no heartbeat result.
	/// - [`ClusterError::Transport`] -- the emit failed.
	/// - [`ClusterError::Frame`] -- the frame failed to build, sign, or decode.
	/// - [`ClusterError::LockPoisoned`] -- the hive registry is poisoned.
	fn send_heartbeat(
		&self,
		addr: Self::Address,
	) -> impl Future<Output = Result<super::common::HeartbeatResult, ClusterError>> + Send;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::common::{ColonyNamespace, RegisterHiveRequest};
	use crate::colony::hive::ServletInfo;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::error::CertificateValidationError::ExcludedKeyPurpose;
	use crate::crypto::x509::policy::ExpiryValidator;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::oid::db::rfc5280::ANY_EXTENDED_KEY_USAGE;
	use crate::policy::TransitStatus;
	use crate::tb_cases;
	use crate::testing::{TestCertificate, TestKey};
	use crate::transport::client::ConnectionPool;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::TokioListener;
	use crate::utils::time::ManualClock;

	fn test_tls_config() -> ClusterTlsConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		ClusterTlsConfig::new(
			CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key))),
			Arc::new(Secp256k1KeyProvider::from(key)),
		)
		.expect("the test certificate must decode")
	}

	/// A signer purpose of an implementor's own, outside the house purposes.
	const OWN_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.12");

	/// An identity on the fixed test key whose certificate names `purpose` as
	/// its one key purpose, or carries no `extendedKeyUsage` for `None`.
	fn identity_naming(purpose: Option<ObjectIdentifier>) -> SigningIdentity {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let certificate = match purpose {
			Some(purpose) => TestCertificate::with_key_purposes(certificate, [purpose]),
			None => certificate,
		};

		let provider = Arc::new(Secp256k1KeyProvider::from(key));
		SigningIdentity::new(certificate, provider).expect("the fixture key proves its certificate")
	}

	// The identity signs the gateway's frames, so `from_identity` holds it to
	// the signer purpose (RFC 5280 §4.2.1.12). A certificate that names the
	// signer purpose, any purpose, or no purpose installs.
	tb_cases! {
		fn from_identity_admits_an_identity_for_the_signer(
			purpose: Option<ObjectIdentifier>
		) -> Result<(), TightBeamError> {
			ClusterTlsConfig::from_identity(identity_naming(purpose), KeyPurposes::HOUSE)?;

			Ok(())
		}
		cases {
			an_identity_for_the_signer => Some(KeyPurposes::HOUSE.signer),
			an_identity_for_any_purpose => Some(ANY_EXTENDED_KEY_USAGE),
			an_identity_with_no_key_purpose => None,
		}
	}

	// `from_identity` refuses a certificate whose key purposes leave the
	// signer out.
	tb_cases! {
		fn from_identity_refuses_an_identity_outside_the_signer(purpose: ObjectIdentifier) {
			let installed = ClusterTlsConfig::from_identity(identity_naming(Some(purpose)), KeyPurposes::HOUSE);
			let excluded = matches!(installed, Err(ExcludedKeyPurpose));
			assert!(excluded);
		}
		cases {
			an_identity_for_servers_alone => KeyPurposes::HOUSE.server,
			an_identity_for_clients_alone => KeyPurposes::HOUSE.client,
		}
	}

	// An identity that names an implementor's own signer purpose alone
	// installs under the purposes that name it.
	#[test]
	fn from_identity_installs_an_own_signer_purpose_under_the_purposes_that_name_it() -> Result<(), TightBeamError> {
		let key_purposes = KeyPurposes { signer: OWN_SIGNER, ..KeyPurposes::HOUSE };
		ClusterTlsConfig::from_identity(identity_naming(Some(OWN_SIGNER)), key_purposes)?;
		Ok(())
	}

	// The house purposes refuse an identity that names an implementor's own
	// signer purpose alone.
	#[test]
	fn from_identity_refuses_an_own_signer_purpose_under_the_house_purposes() {
		let installed = ClusterTlsConfig::from_identity(identity_naming(Some(OWN_SIGNER)), KeyPurposes::HOUSE);
		let excluded = matches!(installed, Err(ExcludedKeyPurpose));
		assert!(excluded);
	}

	/// A client purpose of an implementor's own, outside the house purposes.
	const OWN_CLIENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.13");

	// An outbound pool holds the gateway's identity to the client purpose its
	// TLS config names. The pool answers that at the dial, before any
	// handshake, so a dial under an identity of the implementor's own client
	// purpose returns its lease.
	#[tokio::test]
	async fn the_outbound_pool_takes_the_configured_key_purposes() -> Result<(), Box<dyn core::error::Error>> {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let certificate = TestCertificate::with_key_purposes(certificate, [OWN_CLIENT, KeyPurposes::HOUSE.signer]);
		let trust = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(certificate.clone())?;
		let trust: Arc<dyn CertificateTrust> = Arc::new(trust.build());
		let identity = SigningIdentity::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
		let tls = ClusterTlsConfig::from_identity(identity, KeyPurposes { client: OWN_CLIENT, ..KeyPurposes::HOUSE })?;
		let pool = tls.outbound(ConnectionPool::<TokioListener>::builder()).with_trust_store(trust);
		let pool = Arc::new(pool.build());
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;

		pool.connect(TightBeamSocketAddr(listener.local_addr()?)).await?;

		Ok(())
	}

	// `new` installs through `from_identity`, so it refuses the same identity
	// in its own error.
	#[test]
	fn new_refuses_an_identity_for_servers_alone() -> Result<(), TightBeamError> {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let certificate = TestCertificate::with_key_purposes(certificate, [KeyPurposes::HOUSE.server]);
		let spec = CertificateSpec::Built(Box::new(certificate));

		let refused = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let excluded = matches!(refused, Err(TightBeamError::CertificateValidationError(ExcludedKeyPurpose)));
		assert!(excluded);
		Ok(())
	}

	// An empty client-validator list is server authentication only, and a
	// named validator demands a client certificate.
	tb_cases! {
		fn the_client_validator_list_decides_client_authentication(
			(validators, requires_certificate): (Vec<Arc<dyn CertificateValidation>>, bool)
		) {
			let tls = test_tls_config().with_client_validators(validators);

			let authentication = tls.peer_authentication();

			assert_eq!(authentication.requires_certificate(), requires_certificate);
		}
		cases {
			no_validators => (Vec::new(), false),
			one_validator => (vec![Arc::new(ExpiryValidator) as Arc<dyn CertificateValidation>], true),
		}
	}

	fn test_registry() -> HiveRegistry {
		HiveRegistry::new(Duration::from_secs(15), Arc::new(ManualClock::default()))
	}

	fn servlet_urn(name: &(impl AsRef<str> + ?Sized)) -> crate::urn::Urn<'static> {
		let name = name.as_ref();
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	/// The signer every fixture registration binds. Registration always
	/// names one, so the tests name one too.
	fn test_signer() -> Arc<SignerIdentifier> {
		Arc::new(ServletInfo::fixture_signer())
	}

	fn request(addr: impl AsRef<[u8]>, servlets: &[&str]) -> RegisterHiveRequest {
		let addr = addr.as_ref();
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			metadata: None,
			servlet_addresses: servlets
				.iter()
				.map(|s| ServletInfo {
					servlet_id: servlet_urn(s),
					address: addr.to_vec(),
					signer: ServletInfo::fixture_signer(),
				})
				.collect(),
		}
	}

	/// The instance URN of servlet type `name` at `addr`.
	fn instance_urn(name: &(impl AsRef<str> + ?Sized), addr: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
		servlet_urn(name)
			.servlet_instance(addr)
			.expect("a servlet type URN yields an instance URN")
	}

	/// A servlet that advertises one address under the locator of another
	/// gets no slate, so no route can redirect that locator's traffic.
	#[test]
	fn a_slate_refuses_a_locator_that_names_another_address() {
		let config = ClusterConfig::new(test_tls_config());
		let hive_addr: SharedId = Arc::from(b"127.0.0.1:9000".as_slice());
		let mismatched = ServletInfo {
			servlet_id: instance_urn("ping", "127.0.0.1:9001"),
			address: b"127.0.0.1:9002".to_vec(),
			signer: ServletInfo::fixture_signer(),
		};

		let refused = config.servlet_slate(&[mismatched], &hive_addr);
		assert!(matches!(refused, Err(ClusterError::InvalidAddress(address)) if address == b"127.0.0.1:9002"));
	}

	fn request_with_meta(addr: impl AsRef<[u8]>, servlets: &[&str], meta: impl AsRef<[u8]>) -> RegisterHiveRequest {
		let addr = addr.as_ref();
		let meta = meta.as_ref();
		let mut request = request(addr, servlets);
		request.metadata = Some(meta.to_vec());
		request
	}

	#[test]
	fn cluster_config_defaults() {
		let config = ClusterConfig::new(test_tls_config());
		assert_eq!(config.heartbeat.interval, Duration::from_secs(5));
		assert_eq!(config.heartbeat.timeout, Duration::from_secs(15));
		assert!(config.policies.is_empty());
		assert!(config.peer.peer_dial_allowlist.is_none());
	}

	/// A config whose configured refresh and gossip window are set apart,
	/// so a test can assert each side of the clamp on its own.
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
		// The clamp is a ceiling, so an operator who asks to refresh more often
		// than the window gets the interval they asked for.
		assert_eq!(config.rumor_refresh(), Duration::from_millis(300));
	}

	#[test]
	fn cluster_config_peers_accept_str_slices() -> Result<(), ClusterError> {
		let config = ClusterConfig::builder(test_tls_config())
			.with_peers(["127.0.0.1:9000", "127.0.0.1:9001"])?
			.with_peer_dial_allowlist(["127.0.0.1:9000"])?
			.build();

		let anchors: Vec<String> = config.peer.peers().iter().map(AdmittedDial::to_string).collect();
		assert_eq!(anchors, ["127.0.0.1:9000", "127.0.0.1:9001"]);

		let allowed = config.peer.admit_dial(PeerAddress::fixture("127.0.0.1:9000"));
		assert_eq!(allowed.map(|dial| dial.address()), Ok(PeerAddress::fixture("127.0.0.1:9000")));

		let refused = config.peer.admit_dial(PeerAddress::fixture("127.0.0.1:9001"));
		assert_eq!(refused, Err(DialRefusal::OffAllowlist));
		Ok(())
	}

	/// The builder refuses a peer the operator mistyped where the operator
	/// wrote it, rather than drop it into a federation with no anchors.
	#[test]
	fn cluster_config_refuses_a_peer_that_names_no_socket() {
		let refusal = ClusterConfig::builder(test_tls_config()).with_peers(["not-an-address"]);

		assert!(matches!(refusal, Err(ClusterError::InvalidPeerAddress)));
	}

	// The builder parses the advertise address once, where the operator
	// writes it, so the beat advertises the canonical socket and the builder
	// refuses a typo at build rather than advertise it to every peer.
	#[test]
	fn with_advertise_addr_stores_the_canonical_socket() -> Result<(), ClusterError> {
		let config = ClusterConfig::builder(test_tls_config())
			.with_advertise_addr("[::ffff:192.0.2.1]:9000")?
			.with_advertise_interval(Duration::from_secs(5))
			.build();

		let advertised = config.peer.advertised_address(b"0.0.0.0:9000")?;
		assert_eq!(advertised.as_ref(), b"192.0.2.1:9000");
		Ok(())
	}

	#[test]
	fn with_advertise_addr_refuses_a_spelling_that_names_no_socket() {
		let refusal = ClusterConfig::builder(test_tls_config()).with_advertise_addr("gateway.example");
		assert!(matches!(refusal, Err(ClusterError::InvalidPeerAddress)));
	}

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

	/// The builder creates the ingress route key, so it refuses an unroutable
	/// URN where the operator configures it.
	///
	/// Delivery reads the created key, so every ingress a gateway holds is
	/// one a route can answer. A rumor therefore stays in the retry set only
	/// for a fault that can clear.
	#[test]
	fn gossip_ingress_refuses_a_urn_no_route_can_answer() -> Result<(), ClusterError> {
		let bare = servlet_urn("ping");
		let instance = bare
			.servlet_instance("10.0.0.5:9100")
			.expect("a servlet type URN yields an instance URN");

		let refused = ClusterConfig::builder(test_tls_config()).with_gossip_ingress(instance);
		assert!(matches!(refused, Err(ClusterError::UnknownServletType(_))));

		let conf = ClusterConfig::builder(test_tls_config())
			.with_gossip_ingress(bare.clone())?
			.build();
		assert_eq!(conf.gossip.ingress, ColonyNamespace::default().servlet_type_key(&bare));

		Ok(())
	}
}
