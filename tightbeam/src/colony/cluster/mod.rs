//! The cluster framework: gateways that route work to registered hives.
//!
//! A gateway keeps hive and servlet registries, picks a route for each work
//! request, and forwards the [`ClusterWorkRequest`] payload.
//!
//! # Work routing
//!
//! - Hives register at runtime and announce their servlet types.
//! - Clients send work that names a servlet type and carries a payload.
//! - The gateway picks a route and forwards the payload.
//!
//! # Peer federation
//!
//! Gateways advertise their exported servlet types to peer gateways, honor
//! relay budgets, and learn remote routes through gossip.
//!
//! - The trust anchors are on [`ClusterTlsConfig::peer_trust`].
//! - Every address a peer claims passes [`PeerConfig::admit_dial`]. Only the
//!   [`AdmittedDial`] it returns reaches a dial.
//!
//! # Gossip
//!
//! Rumors flood across colonies through the gossip subsystem ([`GossipConfig`],
//! [`GossipJournal`]), which deduplicates, retains, and repairs them.
//!
//! [`ClusterWorkRequest`]: crate::colony::protocol::ClusterWorkRequest

mod balance;
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

pub use balance::{
	InstanceMetrics, LoadBalancer, PowerOfTwoChoices, RoundRobin, StochasticForager, DEFAULT_EXPLORATION_FLOOR,
	DEFAULT_REPELLENCY_THRESHOLD, MAX_PHEROMONE,
};
pub use builder::{ClusterConfigBuilder, HeartbeatConfigBuilder};
pub use dial::{AdmittedDial, DialRefusal};
pub use error::ClusterError;
pub use export::{
	DynamicExportList, ExportAllowlist, ExportGate, ExportGrant, Party, StaticExportList, TrustPlaneStores, TrustPlanes,
};
pub use gossip::{
	Admission, AdmittedGossip, GossipAdmission, GossipConfig, GossipDigest, GossipJournal, JournalLimits, LocalClaim,
	LocalClaimGuard, MemoryGossipJournal, TokenBucketAdmission, VerifiedRumor, WantList,
};
pub use peer::{AdmittedPeerAd, HopBudget, RelayTrail, WireHopBudget};
pub use peer_table::{
	AddressGroup, MemoryPeerStore, NotASocket, PeerAddress, PeerHint, PeerRecord, PeerStore, PeerTable,
};
pub use registry::{HiveEntry, HiveRegistry, SharedId};
pub use runtime::{ClusterGateway, FreshnessWindow};
pub(crate) use runtime::{ColonyConfig, ColonyDialProtocol};
pub(crate) use servlet_registry::HiveSlate;
pub use servlet_registry::{
	DialTarget, PeerCaps, PeerRoute, PeerRouteInfo, PheromoneConfig, RelayRoute, RouteKind, ServletEntry,
	ServletRegistry, Weakened, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_EVAPORATION_INTERVAL_SECS,
	DEFAULT_EVAPORATION_RATE_BPS, DEFAULT_INITIAL_PHEROMONE, DEFAULT_REINFORCEMENT_BOOST, DEFAULT_WEAKENING_PENALTY,
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

use super::protocol::ServletAddressUpdate;
use super::urn::{ColonyNamespace, ColonyResource};

pub(crate) const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;
pub(crate) const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 15;
// The compiler evaluates the match, so a cap of zero fails to compile here.
pub(crate) const DEFAULT_MAX_CONCURRENT: NonZeroUsize = match NonZeroUsize::new(10) {
	Some(max) => max,
	None => panic!("the default heartbeat cap takes one dial or more"),
};
pub(crate) const DEFAULT_MAX_FAILURES: u32 = 3;

/// The heartbeat cadence, eviction timeout, and failure tolerance.
///
/// A failed heartbeat retries on the next `interval`. Eviction counts against
/// `max_failures`, with no separate retry policy.
pub struct HeartbeatConfig {
	/// The time between heartbeat cycles.
	pub interval: Duration,
	/// The age past which the hive registry evicts a silent hive.
	pub timeout: Duration,
	/// The cap on concurrent heartbeat dials in one cycle. It is at least
	/// one, so each cycle dials every hive in turn (CWE-835).
	pub max_concurrent: NonZeroUsize,
	/// The count of consecutive failures that unregisters a hive.
	pub max_failures: u32,
	/// The callback for each heartbeat result, for a monitor or a test.
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
	/// Attach a callback that the heartbeat loop calls after each heartbeat
	/// result.
	pub fn with_callback(mut self, callback: HeartbeatCallback) -> Self {
		self.on_heartbeat = Some(callback);
		self
	}
}

/// The outcome of one hive heartbeat, for a monitor or a test.
#[derive(Debug, Clone)]
pub struct HeartbeatEvent {
	/// The hive control address the heartbeat dialed.
	pub hive_addr: Arc<[u8]>,
	/// Whether the hive answered within policy.
	pub success: bool,
	/// The utilization the hive reported, when it answered with a heartbeat
	/// result.
	pub utilization: Option<crate::utils::BasisPoints>,
}

/// The callback the heartbeat loop calls after each heartbeat result.
/// Concurrent tasks call it, so it is `Send + Sync`.
pub type HeartbeatCallback = Arc<dyn Fn(HeartbeatEvent) + Send + Sync>;

/// The TLS material for the gateway accept loop and the hive and peer dials.
#[non_exhaustive]
pub struct ClusterTlsConfig {
	/// The gateway certificate and handshake key, from [`Self::new`] or
	/// [`Self::from_identity`]. The certificate is the server identity, and
	/// outbound dials present it as the client certificate.
	identity: SigningIdentity,
	/// The key purpose of each role the identity serves: signer, server, and
	/// client.
	key_purposes: KeyPurposes,
	/// The server policy of every outbound dial on both planes. Each validator
	/// evaluates the signing certificate in the dialed server's HPKE reply.
	///
	/// The store alone admits issuers and roots. Put a check of every
	/// certificate, such as a denylist, in the store's
	/// [`RevocationChecker`](crate::crypto::x509::store::RevocationChecker).
	pub validators: Vec<Arc<dyn CertificateValidation>>,
	/// The client-certificate validators for inbound mutual TLS.
	pub client_validators: Vec<Arc<dyn CertificateValidation>>,
	/// The trust store of the hive plane. It has three roles:
	///
	/// - Outbound dials to hives and servlets validate the server certificate against it.
	/// - Hive control frames (registration, spawn results) verify their signature against it.
	/// - The export boundary treats a caller as first-party when this store
	///   holds its key and `peer_trust` does not ([`TrustPlanes`]).
	pub hive_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
	/// The trust anchor for peer-gateway advertisements and relayed gossip.
	///
	/// It is apart from `hive_trust`, so a peer cannot register as a hive and a
	/// hive cannot forge a peer ad. It wins over `hive_trust` on every plane,
	/// so a key in both stores stays an external peer. `None` disables inbound
	/// federation, and the gateway refuses advertisements.
	pub peer_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
}

impl ClusterTlsConfig {
	/// Decode `certificate` and bind it to the key that proves it, under the
	/// house provider. Every plane shares the one decoded certificate.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `certificate` holds PEM or
	///   DER that does not decode as a certificate.
	/// - [`TightBeamError::CertificateValidationError`] -- the certificate
	///   fails [`Self::from_identity`] under [`KeyPurposes::HOUSE`].
	/// - [`TightBeamError`] -- an error of [`SigningIdentity::new`].
	pub fn new(certificate: CertificateSpec, key: Arc<dyn SigningKeyProvider>) -> Result<Self, TightBeamError> {
		let identity = SigningIdentity::from_spec(certificate, key)?;
		Ok(Self::from_identity(identity, KeyPurposes::HOUSE)?)
	}

	/// Serve every plane under `identity`, with the key purposes that
	/// `key_purposes` names ([`KeyPurposes::HOUSE`] for the house purposes).
	///
	/// - The identity signs this gateway's frames, so its certificate MUST name
	///   `key_purposes.signer` or `anyExtendedKeyUsage`, or carry no
	///   `extendedKeyUsage` (RFC 5280 §4.2.1.12). [`CertificateExt::require_purpose`] checks it.
	/// - The accept planes and the outbound dials hold the certificate to the
	///   server and client purposes ([`TransportEncryptionConfig::with_key_purposes`]).
	///
	/// # Errors
	///
	/// - [`CertificateValidationError::ExcludedKeyPurpose`] -- the
	///   certificate's `extendedKeyUsage` names neither `key_purposes.signer`
	///   nor `anyExtendedKeyUsage`.
	/// - [`CertificateValidationError::DuplicateExtension`] -- the `extendedKeyUsage` extension repeats.
	/// - [`CertificateValidationError::EncodingError`] -- the `extendedKeyUsage` value fails to decode.
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

	/// Replace the server policy of outbound dials ([`Self::validators`]).
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
	/// An empty validator list is server authentication alone, by the rule of
	/// [`PeerAuthentication::mutual`], so the gateway captures no client
	/// identity.
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

	/// The store that names a peer gateway this gateway dials: `peer_trust`, or
	/// `hive_trust` for a gateway with no peer plane, by the rule of
	/// [`TrustPlanes::peer_dial`]. [`Self::pools`] follows the same rule.
	#[must_use]
	pub(crate) fn peer_dial_trust(&self) -> Option<&dyn crate::crypto::x509::store::CertificateTrust> {
		TrustPlanes::from(self).peer_dial()
	}

	/// The certificate and handshake key this gateway presents on the colony
	/// listener, the edge listener, and every outbound hive and peer dial.
	pub fn identity(&self) -> &SigningIdentity {
		&self.identity
	}

	/// The encryption config the colony and edge listeners share, so an edge
	/// client pins the same gateway identity that hives trust.
	pub(crate) fn accept_encryption<C: CryptoProvider>(&self) -> TransportEncryptionConfig<C> {
		let encryption = TransportEncryptionConfig::new(self.identity.clone());
		let validators = self.client_validators.iter().map(Arc::clone);

		let encryption = encryption.with_client_validators(validators);
		encryption.with_key_purposes(self.key_purposes)
	}

	/// Configures `builder` to dial under this identity, with
	/// [`Self::validators`] as the server policy.
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

/// The peer-federation dial list, the advertise beat and address, and the
/// policy that admits the dial addresses peers claim.
///
/// The trust anchors are on [`ClusterTlsConfig::peer_trust`].
/// [`PeerConfig::exported_types`] governs export discovery and enforcement.
#[derive(Clone)]
pub struct PeerConfig {
	/// The peer gateways this gateway dials to advertise exported types.
	///
	/// - Each gateway picks its own targets, so a federation graph can be partial or asymmetric.
	/// - An empty list sets no anchor, so the beat advertises only to learned peers its probes proved.
	/// - Each beat sends a snapshot of the local servlet registry as the slate.
	///
	/// Private, because [`PeerConfig::table`] derives its anchors from it at
	/// build. Set it with [`ClusterConfigBuilder::with_peers`], which parses
	/// each entry.
	peers: Vec<AdmittedDial>,
	/// The cadence of the re-advertise beat, where `None` disables the beat.
	pub advertise_interval: Option<Duration>,
	/// The socket this gateway advertises as its own, when the operator sets
	/// one.
	///
	/// - `None` advertises the bound address, which works for a gateway bound to one interface.
	/// - A gateway bound to the wildcard address needs it, because every peer refuses `0.0.0.0`.
	advertise_addr: Option<PeerAddress>,
	/// The dial addresses that inbound peer ads may claim, or any parsed socket
	/// for `None`.
	///
	/// - Entries are parsed sockets, so two spellings of one address are one entry.
	/// - Peer-exchange hints pass the same gate, so discovery dials listed addresses alone.
	///
	/// Private, so every entry is a parsed socket. Set it with
	/// [`ClusterConfigBuilder::with_peer_dial_allowlist`].
	peer_dial_allowlist: Option<Arc<HashSet<PeerAddress>>>,
	/// The discovery table: `peers` as anchors that never evict, beside the
	/// bounded, prefix-bucketed learned peers.
	///
	/// Private, because the builder rebuilds it. The anchors derive from
	/// `peers`, and the injected [`PeerStore`] reloads the learned peers
	/// through the capped admission path.
	table: Arc<PeerTable>,
	/// The cap on the relay budget this gateway honors on inbound work and
	/// routed stream opens. The effective budget is `min(wire value,
	/// max_hops)`, and an origin request, which carries the sentinel budget,
	/// takes this cap.
	///
	/// - The default [`DEFAULT_MAX_HOPS`] forwards at most once.
	/// - `0` disables forwarding.
	/// - `2` enables relay-trail fallback.
	pub max_hops: u8,
	/// The cap on the tried entries one signer may hold in the discovery table,
	/// or no cap for `None`, the default.
	///
	/// - One certificate that answers at many addresses takes at most this many beat targets.
	/// - The prefix buckets bound a network position, and this cap bounds an identity (CWE-770).
	/// - A signer is one certificate, counted by fingerprint, so a party with two
	///   certificates holds this many entries under each.
	/// - Turn it on when the trust store admits parties outside your control.
	///
	/// Private, because the builder copies it into the table, which reads that
	/// copy alone. Set it with [`ClusterConfigBuilder::with_tried_per_signer`].
	tried_per_signer: Option<NonZeroUsize>,
	/// The advertisement-rumor refresh interval, as configured. The beat floods
	/// the slate rumor on each change of the slate or the flood targets, and
	/// once per interval.
	///
	/// Private, because callers want the clamped value
	/// ([`ClusterConfig::rumor_refresh`]). Set it with
	/// [`ClusterConfigBuilder::with_rumor_refresh`].
	rumor_refresh: Duration,
	/// The servlet types that external peers may discover and reach, or every
	/// local type for `None`. `Some` restricts both planes of the export
	/// boundary through an [`ExportAllowlist`]:
	///
	/// - Discovery: each advertise beat asks [`ExportAllowlist::allows_canonical`]
	///   per local servlet key, so ads and rumors name exported types alone.
	/// - Enforcement: unary work and routed stream opens ask
	///   [`ExportAllowlist::contains`]. The gateway refuses external peers and
	///   relayed requests on other targets, even when they guess the type name.
	///
	/// Set a static list with [`ClusterConfigBuilder::with_exported_types`], or
	/// a live handle with [`ClusterConfigBuilder::with_export_allowlist`].
	pub exported_types: Option<Arc<dyn ExportAllowlist>>,
}

impl PeerConfig {
	/// The peer gateways this plane dials to advertise exported types: the
	/// table's anchors, which never evict.
	#[must_use]
	pub fn peers(&self) -> &[AdmittedDial] {
		&self.peers
	}

	/// The discovery table the anchors and learned peers live in.
	#[must_use]
	pub fn table(&self) -> &Arc<PeerTable> {
		&self.table
	}

	/// The dial addresses inbound peer ads may claim, when the operator
	/// restricts them.
	#[must_use]
	pub fn peer_dial_allowlist(&self) -> Option<&Arc<HashSet<PeerAddress>>> {
		self.peer_dial_allowlist.as_ref()
	}
}

/// The default peer plane starts with an empty peer list, the beat off, and
/// an open dial allowlist. It advertises the bound address and holds the
/// single-forward relay cap.
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

/// The runtime configuration of a cluster gateway.
///
/// Build one with [`ClusterConfigBuilder`] or [`ClusterConfig::new`]. The
/// load balancer defaults to [`StochasticForager`].
pub struct ClusterConfig {
	/// The namespace that scopes inbound resource URNs.
	///
	/// The gateway refuses a register, update, or work request that names a
	/// foreign authority or realm.
	pub namespace: ColonyNamespace,
	/// The strategy that selects among candidate servlet instances.
	pub load_balancer: Arc<dyn LoadBalancer>,
	/// The hive health probes and eviction policy.
	pub heartbeat: HeartbeatConfig,
	/// The route score policy: reinforcement, weakening, and evaporation.
	pub pheromone: PheromoneConfig,
	/// The gate policies the gateway evaluates before it decodes a request.
	pub policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	/// The custom export gates, which the gateway evaluates once it knows the
	/// servlet target. Every gate must pass, so the gates narrow what the allow
	/// sources (the exported list, the grants, the first-party rule) admit.
	pub export_gates: Vec<Arc<dyn ExportGate>>,
	/// The positive export grants, which the gateway evaluates when the
	/// built-in allowlist refuses a target.
	///
	/// A target passes when it is exported, granted, or a first-party origin,
	/// and a deny gate overrides a grant. The advertised slate lists exported
	/// types alone, so a granted type stays off it.
	pub export_grants: Vec<Arc<dyn ExportGrant>>,
	/// The outbound connection pool settings for hive and peer dials. The
	/// pools read [`ClusterConfig::clock`].
	pub pool_config: PoolConfig,
	/// The freshness window for signed hive control frames.
	///
	/// The gateway refuses a stale or replayed registration or update frame
	/// (CWE-294).
	pub control_freshness_window: Duration,
	/// The gateway bind address, parsed through the protocol address `FromStr`.
	/// `None` binds the protocol default. A stable address lets hives register
	/// again across gateway restarts.
	pub bind_addr: Option<String>,
	/// The bind address of the edge accept plane, parsed through the edge
	/// address `FromStr`, or no edge plane for `None`.
	///
	/// - The edge listener serves external clients, such as a browser transport, with the same TLS material.
	/// - It admits `Work` frames alone and refuses control frames with
	///   `PermissionDenied`, so an edge client never joins the control plane.
	/// - Hives register on `bind_addr` in either case.
	pub edge_bind_addr: Option<String>,
	/// The peer-federation dial list, the advertise beat and address, and the
	/// dial policy.
	pub peer: PeerConfig,
	/// The gossip freshness, origin TTL, ingress, journal, and admission.
	///
	/// Startup clamps [`GossipConfig::seen_ttl`] to the journal's retention.
	/// The journal keeps a digest only while its rumor's issue time lies inside
	/// retention, so a wider window would admit a replay again (CWE-294).
	pub gossip: GossipConfig,
	/// The clock every freshness, replay, retention, and lease decision on
	/// this gateway reads. It defaults to
	/// [`SystemClock`](crate::utils::time::SystemClock).
	pub clock: Arc<dyn Clock>,
	/// The colony URN from the URI SAN of the gateway certificate. `None` means
	/// the gateway is in no colony and no flood ([`ClusterConfig::flood`]):
	///
	/// - The gateway refuses peer ads and every gossip publish, relay, and reconcile.
	/// - The advertise beat skips gossip reconciliation.
	/// - Work and hive registration work without membership.
	///
	/// Private, so membership stays bound to the certificate.
	/// [`ClusterConfig::bind_colony_membership`] derives it at startup.
	colony_urn: Option<Urn<'static>>,
	/// The TLS material for the accept planes and the outbound dials.
	pub tls: ClusterTlsConfig,
}

/// A parsed address-update delta: the hive's added routes, owned by that
/// hive, and the locators it removes.
pub(crate) type ParsedAddressUpdate<'a> = (HiveSlate, Vec<&'a [u8]>);

impl ClusterConfig {
	/// The effective advertisement-rumor refresh interval: the configured
	/// value, clamped to [`GossipConfig::seen_ttl`].
	///
	/// A slower refresh would publish rumors that peers refuse as stale. The
	/// window narrows at startup to the journal retention, so the clamp runs
	/// on each read.
	#[must_use]
	pub fn rumor_refresh(&self) -> Duration {
		self.peer.rumor_refresh.min(self.gossip.seen_ttl)
	}

	/// Parse the hive identity, the added entries, and the removed instance
	/// locators, whole, so the registry applies all of the delta or none of it.
	/// It returns [`None`] in each case below:
	///
	/// - The hive URN names no hive of this colony's namespace.
	/// - An added or removed URN names no servlet instance of this namespace.
	/// - An added locator names an address other than the one beside it.
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

	/// The colony URN from the URI SAN of the gateway certificate.
	///
	/// It returns `None` when this gateway is not a colony member.
	#[must_use]
	pub fn colony_urn(&self) -> Option<&Urn<'static>> {
		self.colony_urn.as_ref()
	}

	/// Binds colony membership to the certificate this config holds.
	///
	/// The config caches membership, because every inbound gossip frame asks
	/// and the derivation decodes the certificate's URI SAN. Startup binds it
	/// again, because the certificate and the namespace stay writable until
	/// the gateway takes the config.
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

/// The trait a cluster gateway implements.
pub trait Cluster: Sized + Send + Sync {
	/// The protocol this gateway serves.
	type Protocol: Protocol;

	/// The bound address type of this gateway.
	type Address: TightBeamAddress;

	/// Bind, spawn the accept and background loops, and return the gateway
	/// that runs them.
	///
	/// `trace` files the gateway's audit records. Each connection records on
	/// [`Cluster::connection_trace`].
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

	/// The servlet types that registered local hives offer.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route registry is poisoned.
	fn available_servlets(&self) -> Result<Vec<SharedId>, ClusterError>;

	/// The servlet types reachable through the routes learned from peer
	/// gateways.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route registry is poisoned.
	fn peer_servlets(&self) -> Result<Vec<SharedId>, ClusterError>;

	/// The learned peer routes, each with its dial address and peer identity.
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

	/// The shared trace collector of this gateway, which files its audit
	/// records.
	fn trace(&self) -> Arc<TraceCollector>;

	/// The trace of each connection of the colony and edge planes.
	///
	/// It holds each record that no proven peer or verified signature backs, in
	/// the sink that [`sibling`] names. A test build shares the assertions of
	/// [`trace`].
	///
	/// [`trace`]: Cluster::trace
	/// [`sibling`]: crate::instrumentation::EventSink::sibling
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::cluster::{Cluster, ClusterConfig, ClusterTlsConfig};
	/// use tightbeam::crypto::key::Secp256k1KeyProvider;
	/// use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
	/// use tightbeam::crypto::x509::CertificateSpec;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// tightbeam::cluster! {
	///     Gateway,
	///     protocol: TokioListener
	/// }
	///
	/// # let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	/// # runtime.block_on(async {
	/// let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
	/// let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
	/// let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
	/// let gateway = Gateway::start(Arc::new(TraceCollector::new()), ClusterConfig::new(tls)).await?;
	///
	/// let connections = gateway.connection_trace();
	/// assert!(connections.drain_events().is_empty());
	/// gateway.stop();
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// # })?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn connection_trace(&self) -> Arc<TraceCollector>;

	/// Abort the accept and background tasks.
	fn stop(self);

	/// Wait until the accept loops finish.
	///
	/// It awaits the colony accept task and, when bound, the edge accept task.
	///
	/// # Errors
	///
	/// - [`JoinError`](crate::runtime::rt::JoinError) -- an accept task panicked, or an abort cancelled it.
	fn join(self) -> impl Future<Output = Result<(), crate::runtime::rt::JoinError>> + Send;
}

/// The heartbeat surface of a cluster gateway.
///
/// It is apart from [`Cluster`], so a work-only consumer needs the work
/// surface alone. [`ClusterGateway`] implements both.
pub trait ClusterHeartbeat: Cluster {
	/// The shared hive registry.
	fn registry(&self) -> &Arc<HiveRegistry>;

	/// The heartbeat interval, timeout, and failure policy.
	fn heartbeat_config(&self) -> &HeartbeatConfig;

	/// Send one signed heartbeat to the hive registered at `addr`, through the
	/// connection pool.
	///
	/// The dial admits only the identity that signed the hive's registration
	/// (CWE-346). The bounded background loop lives in
	/// [`ClusterGateway::start`].
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- no hive is registered at `addr`,
	///   or `addr` does not parse to dial.
	/// - [`ClusterError::PeerMismatch`] -- another identity answered at `addr`.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	/// - [`ClusterError::NoResponse`] -- the hive closed the connection with no answer.
	/// - [`ClusterError::MalformedResponse`] -- the answer carried no heartbeat result.
	/// - [`ClusterError::Transport`] -- the emit failed.
	/// - [`ClusterError::Frame`] -- the frame failed to build, sign, or decode,
	///   or the trace refused the event of a refused dial.
	/// - [`ClusterError::LockPoisoned`] -- the hive registry is poisoned.
	fn send_heartbeat(
		&self,
		addr: Self::Address,
	) -> impl Future<Output = Result<super::protocol::HeartbeatResult, ClusterError>> + Send;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::protocol::{ClusterWorkResponse, RegisterHiveRequest, ServletInfo};
	use crate::colony::urn::ColonyNamespace;
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

	// `from_identity` installs a certificate that names the signer purpose,
	// any purpose, or none (RFC 5280 §4.2.1.12).
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

	// The outbound pool checks the client purpose at the dial, before any
	// handshake, so a dial under an own client purpose returns its lease.
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

	// The builder parses the advertise address once, so the beat advertises the
	// canonical socket and a typo fails at build.
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
