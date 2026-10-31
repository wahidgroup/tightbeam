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
use core::str::FromStr;
use core::time::Duration;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use crate::clock::Clock;
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
use crate::urn::{Urn, UrnValidationError};
use crate::TightBeamError;

use super::protocol::ServletAddressUpdate;
use super::urn::{ColonyNamespace, ColonyResource, ServletTypeKey};

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
	pub utilization: Option<crate::basis_points::BasisPoints>,
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
	/// How the accept planes authenticate their clients:
	/// [`PeerAuthentication::Anonymous`], the default, or mutual TLS over the
	/// validators the operator names.
	pub client_authentication: PeerAuthentication,
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
			client_authentication: PeerAuthentication::Anonymous,
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

	/// Set how the accept planes authenticate their clients
	/// ([`Self::client_authentication`]).
	///
	/// An operator who demands mutual TLS names it whole, so an empty validator
	/// list never turns into anonymous clients by accident (CWE-1188).
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::cluster::ClusterTlsConfig;
	/// use tightbeam::crypto::key::Secp256k1KeyProvider;
	/// use tightbeam::crypto::x509::policy::ExpiryValidator;
	/// use tightbeam::crypto::x509::CertificateSpec;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	/// use tightbeam::transport::handshake::PeerAuthentication;
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
	/// let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
	///
	/// let mutual = PeerAuthentication::Anonymous.and(Arc::new(ExpiryValidator::default()));
	/// let tls = tls.with_client_authentication(mutual);
	/// assert!(tls.peer_authentication().requires_certificate());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn with_client_authentication(mut self, authentication: impl Into<PeerAuthentication>) -> Self {
		self.client_authentication = authentication.into();
		self
	}

	/// How the accept planes authenticate their clients: the
	/// [`Self::client_authentication`] this config holds.
	///
	/// Under [`PeerAuthentication::Anonymous`], the gateway captures no client
	/// identity.
	pub fn peer_authentication(&self) -> PeerAuthentication {
		self.client_authentication.clone()
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
		let authentication = self.peer_authentication();

		let encryption = encryption.with_peer_authentication(authentication);
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
			client_authentication: self.client_authentication.clone(),
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
			.field("client_authentication", &self.client_authentication)
			.field("hive_trust", &self.hive_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.field("peer_trust", &self.peer_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.finish()
	}
}

#[cfg(test)]
impl ClusterTlsConfig {
	/// The TLS material of a gateway that presents the self-signed certificate
	/// of the fixed test key.
	pub(crate) fn fixture() -> Self {
		let key = crate::testing::TestKey::insecure_fixed_signing();
		ClusterTlsConfig::fixture_of(crate::testing::TestCertificate::insecure_fixed(), key)
	}

	/// The TLS material of a gateway that presents `certificate` on `key`.
	pub(crate) fn fixture_of(
		certificate: crate::x509::Certificate,
		key: crate::crypto::sign::ecdsa::Secp256k1SigningKey,
	) -> Self {
		let spec = CertificateSpec::Built(Box::new(certificate));
		let provider = crate::testing::TestKey::provider(key);
		ClusterTlsConfig::new(spec, provider).expect("the fixture key proves its certificate")
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
	/// (CWE-294), and a second frame of one signer at one `order` inside the
	/// window (README §5.7.1).
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
	/// [`SystemClock`](crate::clock::SystemClock).
	///
	/// A trust store reads the validity period of a signer on its own clock,
	/// so the stores of [`ClusterTlsConfig`] are built on this one
	/// ([`CertificateTrustBuilder::with_clock`]).
	///
	/// [`CertificateTrustBuilder::with_clock`]: crate::crypto::x509::store::CertificateTrustBuilder::with_clock
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
/// hive, and the locators it removes, percent-decoded.
pub(crate) type ParsedAddressUpdate<'a> = (HiveSlate, Vec<Cow<'a, [u8]>>);

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

	/// The time a relay trail lives with no refresh: three refresh intervals
	/// ([`Self::rumor_refresh`]), floored at the default refresh interval.
	///
	/// One missed refresh is churn, and three mean the refresh path died. The
	/// floor keeps a healthy fallback under an aggressive refresh.
	pub(crate) fn relay_trail_ttl(&self) -> Duration {
		let ttl = self.rumor_refresh().saturating_mul(3);
		ttl.max(Duration::from_millis(DEFAULT_AD_RUMOR_REFRESH_MS))
	}

	/// The gateway bind address, parsed as `A`, or [`None`] to bind the
	/// protocol default.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- [`Self::bind_addr`] does not parse as `A`.
	pub(crate) fn bind_address<A: FromStr>(&self) -> Result<Option<A>, ClusterError> {
		Self::parse_bind_address(self.bind_addr.as_deref())
	}

	/// The bind address of the edge accept plane, parsed as `A`, or [`None`]
	/// for a gateway with no edge plane.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- [`Self::edge_bind_addr`] does not parse as `A`.
	pub(crate) fn edge_bind_address<A: FromStr>(&self) -> Result<Option<A>, ClusterError> {
		Self::parse_bind_address(self.edge_bind_addr.as_deref())
	}

	/// Parses `raw`, a configured bind address, as `A`, or answers [`None`]
	/// for an address the operator left unset.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- `raw` does not parse as `A`, and the error carries its octets.
	fn parse_bind_address<A: FromStr>(raw: Option<&str>) -> Result<Option<A>, ClusterError> {
		let Some(raw) = raw else {
			return Ok(None);
		};

		let parsed = raw.parse().map_err(|_| ClusterError::InvalidAddress(raw.as_bytes().to_vec()));
		Ok(Some(parsed?))
	}

	/// Parse the hive identity, the added entries, and the removed instance
	/// locators, whole, so the registry applies all of the delta or none of it.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidUrn`] -- the hive URN names no hive of this
	///   colony's namespace, or a removed URN names no servlet instance of it.
	/// - [`ClusterError::InvalidAddress`] -- an added locator names an address other than the one beside it.
	pub(crate) fn parse_address_update<'a>(
		&self,
		update: &'a ServletAddressUpdate,
	) -> Result<ParsedAddressUpdate<'a>, ClusterError> {
		let hive = self.namespace.validate(&update.hive_id).map_err(ClusterError::InvalidUrn)?;
		let ColonyResource::Hive { addr } = hive else {
			let named = UrnValidationError::InvalidFormat { field: "resource-type", pattern: None };
			return Err(ClusterError::InvalidUrn(named));
		};

		let mut removed = Vec::with_capacity(update.removed.len());
		for urn in &update.removed {
			let resource = self.namespace.validate(urn).map_err(ClusterError::InvalidUrn)?;
			let ColonyResource::Servlet { instance: Some(locator), .. } = resource else {
				return Err(ClusterError::InvalidUrn(UrnValidationError::RequiredFieldMissing("instance")));
			};

			removed.push(locator.decoded());
		}

		let hive_id: Arc<[u8]> = Arc::from(addr.decoded().as_ref());
		let added = self.servlet_slate(&update.added, &hive_id)?;
		Ok((added, removed))
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

	/// The route key of the gossip ingress ([`GossipConfig::ingress`]) under
	/// [`Self::namespace`], or [`None`] when the gateway delivers no rumor to
	/// a local servlet.
	///
	/// - The namespace and the gossip section stay writable until a gateway takes the config.
	/// - [`Cluster::start`] mints the key here once, and its gossip pipeline delivers under it.
	/// - An implementor of [`Cluster`] outside this crate mints the key here too.
	///
	/// # Errors
	///
	/// - [`ClusterError::UnknownServletType`] -- the ingress is no bare
	///   servlet type of [`Self::namespace`], so no route answers it and the
	///   gateway would deliver none of its gossip.
	///
	/// # Examples
	///
	/// ```
	/// # use std::sync::Arc;
	/// # use tightbeam::colony::cluster::{ClusterConfig, ClusterTlsConfig};
	/// # use tightbeam::colony::urn::ColonyNamespace;
	/// # use tightbeam::crypto::key::Secp256k1KeyProvider;
	/// # use tightbeam::crypto::x509::CertificateSpec;
	/// # use tightbeam::testing::{TestCertificate, TestKey};
	/// # let key = TestKey::insecure_fixed_signing();
	/// # let certificate = CertificateSpec::Built(Box::new(TestCertificate::self_signed(&key)));
	/// # let tls = ClusterTlsConfig::new(certificate, Arc::new(Secp256k1KeyProvider::from(key)))?;
	/// let acme = ColonyNamespace::new("acme", "prod")?;
	/// let feed = acme.servlet("feed")?;
	///
	/// // The ingress names a servlet type of `acme`, so the key reads the
	/// // namespace the builder sets, in either call order.
	/// let builder = ClusterConfig::builder(tls).with_gossip_ingress(feed.clone())?;
	/// let config = builder.with_namespace(acme.clone()).build();
	/// assert_eq!(config.gossip_ingress_key()?, acme.servlet_type_key(&feed));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn gossip_ingress_key(&self) -> Result<Option<ServletTypeKey>, ClusterError> {
		let Some(ingress) = self.gossip.ingress.as_ref() else {
			return Ok(None);
		};

		let key = self.namespace.servlet_type_key(ingress);
		let refused = || ClusterError::UnknownServletType(ingress.canonical_bytes());
		key.map(Some).ok_or_else(refused)
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

#[cfg(test)]
impl ClusterConfig {
	/// A config with every default, on [`ClusterTlsConfig::fixture`].
	pub(crate) fn fixture() -> Self {
		ClusterConfig::new(ClusterTlsConfig::fixture())
	}

	/// A colony member whose peer trust enrolls its own certificate, so it
	/// admits a peer advertisement that it signs itself.
	pub(crate) fn self_peering() -> Self {
		use crate::crypto::x509::store::CertificateTrust;
		use crate::testing::fixtures::TestStore;
		use crate::testing::{TestCertificate, TestKey};

		let key = TestKey::insecure_fixed_signing();
		let colony = ColonyNamespace::colony_fixture("main");
		let certificate = TestCertificate::with_uri_sans(&key, &[&colony.to_string()]);
		let peer_trust: Arc<dyn CertificateTrust> = Arc::new(TestStore::holding([certificate.clone()]));
		let tls = ClusterTlsConfig::fixture_of(certificate, key).with_peer_trust(peer_trust);

		let mut config = ClusterConfig::new(tls);
		config.bind_colony_membership();
		config
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
	/// - [`TightBeamError::TransportError`] -- an accept plane fails to bind.
	/// - [`TightBeamError::ClusterError`] -- `bind_addr` or `edge_bind_addr`
	///   does not parse ([`ClusterError::InvalidAddress`]), the gossip ingress
	///   is no bare servlet type of `namespace`
	///   ([`ClusterConfig::gossip_ingress_key`]), or the gateway beats from a
	///   wildcard bind with no advertise address.
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
	use crate::colony::hive::HiveTlsConfig;
	use crate::colony::protocol::ServletInfo;
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::x509::error::CertificateValidationError::ExcludedKeyPurpose;
	use crate::crypto::x509::store::CertificateTrust;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::oid::db::rfc5280::ANY_EXTENDED_KEY_USAGE;
	use crate::tb_cases;
	use crate::testing::fixtures::{TestIdentity, TestStore};
	use crate::testing::{TestCertificate, TestKey, TestResult};
	use crate::transport::client::ConnectionPool;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::TokioListener;

	/// The two configs that install a signing identity: the TLS of a cluster
	/// gateway and the TLS of a hive control plane.
	#[derive(Clone, Copy)]
	enum TlsBackend {
		Cluster,
		Hive,
	}

	impl TlsBackend {
		/// Installs `identity` under `key_purposes` in the config of this
		/// backend.
		fn install(
			self,
			identity: SigningIdentity,
			key_purposes: KeyPurposes,
		) -> Result<(), CertificateValidationError> {
			match self {
				TlsBackend::Cluster => ClusterTlsConfig::from_identity(identity, key_purposes).map(drop),
				TlsBackend::Hive => {
					HiveTlsConfig::from_identity(identity, PeerAuthentication::Anonymous, key_purposes).map(drop)
				}
			}
		}

		/// Builds the config of this backend through `new`, from a certificate
		/// on the fixed test key that names `purpose` alone.
		fn build_naming(self, purpose: ObjectIdentifier) -> Result<(), TightBeamError> {
			let key = TestKey::insecure_fixed_signing();
			let certificate = TestCertificate::with_key_purposes(TestCertificate::self_signed(&key), [purpose]);
			let spec = CertificateSpec::Built(Box::new(certificate));
			let provider = TestKey::provider(key);
			match self {
				TlsBackend::Cluster => ClusterTlsConfig::new(spec, provider).map(drop),
				TlsBackend::Hive => HiveTlsConfig::new(spec, provider, PeerAuthentication::Anonymous).map(drop),
			}
		}
	}

	/// The house purposes with an implementor's own signer purpose in place of
	/// the house signer.
	const OWN_SIGNER_PURPOSES: KeyPurposes = KeyPurposes { signer: TestIdentity::OWN_SIGNER, ..KeyPurposes::HOUSE };

	// `from_identity` installs a certificate that names the signer purpose of
	// the purposes it installs under, any purpose, or none
	// (RFC 5280 §4.2.1.12), on each backend.
	tb_cases! {
		fn from_identity_installs_an_identity_that_names_the_signer(
			(backend, purpose, key_purposes): (TlsBackend, Option<ObjectIdentifier>, KeyPurposes)
		) -> TestResult {
			backend.install(TestIdentity::naming(purpose), key_purposes)?;

			Ok(())
		}
		cases {
			cluster_the_house_signer => (TlsBackend::Cluster, Some(KeyPurposes::HOUSE.signer), KeyPurposes::HOUSE),
			cluster_any_purpose => (TlsBackend::Cluster, Some(ANY_EXTENDED_KEY_USAGE), KeyPurposes::HOUSE),
			cluster_no_key_purpose => (TlsBackend::Cluster, None, KeyPurposes::HOUSE),
			cluster_an_own_signer_under_its_purposes => (
				TlsBackend::Cluster,
				Some(TestIdentity::OWN_SIGNER),
				OWN_SIGNER_PURPOSES,
			),
			hive_the_house_signer => (TlsBackend::Hive, Some(KeyPurposes::HOUSE.signer), KeyPurposes::HOUSE),
			hive_any_purpose => (TlsBackend::Hive, Some(ANY_EXTENDED_KEY_USAGE), KeyPurposes::HOUSE),
			hive_no_key_purpose => (TlsBackend::Hive, None, KeyPurposes::HOUSE),
			hive_an_own_signer_under_its_purposes => (
				TlsBackend::Hive,
				Some(TestIdentity::OWN_SIGNER),
				OWN_SIGNER_PURPOSES,
			),
		}
	}

	// `from_identity` refuses a certificate whose key purposes leave the house
	// signer out, on each backend.
	tb_cases! {
		fn from_identity_refuses_an_identity_outside_the_signer((backend, purpose): (TlsBackend, ObjectIdentifier)) {
			let installed = backend.install(TestIdentity::naming(purpose), KeyPurposes::HOUSE);
			assert!(matches!(installed, Err(ExcludedKeyPurpose)));
		}
		cases {
			cluster_servers_alone => (TlsBackend::Cluster, KeyPurposes::HOUSE.server),
			cluster_clients_alone => (TlsBackend::Cluster, KeyPurposes::HOUSE.client),
			cluster_an_own_signer_under_the_house_purposes => (TlsBackend::Cluster, TestIdentity::OWN_SIGNER),
			hive_servers_alone => (TlsBackend::Hive, KeyPurposes::HOUSE.server),
			hive_clients_alone => (TlsBackend::Hive, KeyPurposes::HOUSE.client),
			hive_an_own_signer_under_the_house_purposes => (TlsBackend::Hive, TestIdentity::OWN_SIGNER),
		}
	}

	// `new` installs through `from_identity`, so each backend refuses the same
	// identity in its own error.
	tb_cases! {
		fn new_refuses_an_identity_for_servers_alone(backend: TlsBackend) {
			let refused = backend.build_naming(KeyPurposes::HOUSE.server);
			assert!(matches!(refused, Err(TightBeamError::CertificateValidationError(ExcludedKeyPurpose))));
		}
		cases {
			cluster => TlsBackend::Cluster,
			hive => TlsBackend::Hive,
		}
	}

	/// A client purpose of an implementor's own, outside the house purposes.
	const OWN_CLIENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.13");

	/// The outbound pool checks the client purpose at the dial, before any
	/// handshake, so a dial under an own client purpose returns its lease.
	#[tokio::test]
	async fn the_outbound_pool_takes_the_configured_key_purposes() -> TestResult {
		let key = TestKey::insecure_fixed_signing();
		let certificate = TestCertificate::self_signed(&key);
		let certificate = TestCertificate::with_key_purposes(certificate, [OWN_CLIENT, KeyPurposes::HOUSE.signer]);
		let trust: Arc<dyn CertificateTrust> = Arc::new(TestStore::holding([certificate.clone()]));
		let identity = TestIdentity::presenting(certificate, &key);
		let tls = ClusterTlsConfig::from_identity(identity, KeyPurposes { client: OWN_CLIENT, ..KeyPurposes::HOUSE })?;
		let pool = tls.outbound(ConnectionPool::<TokioListener>::builder()).with_trust_store(trust);
		let pool = Arc::new(pool.build());
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;

		pool.connect(TightBeamSocketAddr(listener.local_addr()?)).await?;

		Ok(())
	}

	// The config keeps the client authentication its operator named, so an
	// anonymous plane and a mutual plane each come back as named (CWE-1188).
	tb_cases! {
		fn a_cluster_config_keeps_the_authentication_it_was_given(
			(authentication, requires_certificate): (PeerAuthentication, bool)
		) {
			let tls = ClusterTlsConfig::fixture().with_client_authentication(authentication);
			let kept = tls.peer_authentication();
			assert_eq!(kept.requires_certificate(), requires_certificate);
		}
		cases {
			anonymous => (PeerAuthentication::Anonymous, false),
			mutual => (PeerAuthentication::mutual_by_expiry(), true),
		}
	}

	/// A servlet that advertises one address under the locator of another
	/// gets no slate, so no route can redirect that locator's traffic.
	#[test]
	fn a_slate_refuses_a_locator_that_names_another_address() {
		let hive_addr: SharedId = Arc::from(b"127.0.0.1:9000".as_slice());
		let mismatched = ServletInfo { address: b"127.0.0.1:9002".to_vec(), ..ServletInfo::fixture("127.0.0.1:9001") };

		let refused = ClusterConfig::fixture().servlet_slate(&[mismatched], &hive_addr);
		assert!(matches!(refused, Err(ClusterError::InvalidAddress(address)) if address == b"127.0.0.1:9002"));
	}

	/// An update of a hive at an IPv6 literal names the hive and its servlets
	/// under percent-encoded locators, and the parse gives back the address of
	/// the hive, of each added servlet, and of each removed one.
	#[test]
	fn an_update_of_a_hive_at_an_ipv6_literal_parses_to_its_addresses() -> TestResult {
		let config = ClusterConfig::fixture();
		let update = ServletAddressUpdate {
			hive_id: ColonyNamespace::hive_fixture("[::1]:9000"),
			added: vec![ServletInfo::fixture("[::1]:9001")],
			removed: vec![ColonyNamespace::instance_fixture("ping", "[::1]:9002")],
		};

		let (slate, removed) = config.parse_address_update(&update)?;

		let hive: &[u8] = slate.hive_id().as_ref();
		let removed: Vec<&[u8]> = removed.iter().map(AsRef::as_ref).collect();
		assert_eq!((hive, removed), (b"[::1]:9000".as_slice(), vec![b"[::1]:9002".as_slice()]));
		Ok(())
	}

	/// A config built from TLS alone beats on the default heartbeat, applies
	/// no gate policy, and dials every admitted peer.
	#[test]
	fn a_new_config_takes_the_default_heartbeat_and_no_restriction() {
		let config = ClusterConfig::fixture();
		let heartbeat = (config.heartbeat.interval, config.heartbeat.timeout);
		let restrictions = (config.policies.len(), config.peer.peer_dial_allowlist.is_none());

		let defaults = (Duration::from_secs(5), Duration::from_secs(15));
		assert_eq!((heartbeat, restrictions), (defaults, (0, true)));
	}

	/// A config whose configured refresh and gossip window are set apart,
	/// so a test can assert each side of the clamp on its own.
	fn config_refreshing(refresh: Duration, seen_ttl: Duration) -> ClusterConfig {
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let mut config = builder.with_rumor_refresh(refresh).build();
		config.gossip.seen_ttl = seen_ttl;
		config
	}

	// The window narrows at startup, so a refresh stored clamped at build
	// would re-publish rumors peers refuse as stale. The clamp is a ceiling,
	// so an operator who asks to refresh more often than the window gets the
	// interval they asked for.
	tb_cases! {
		fn the_rumor_refresh_is_clamped_to_the_window((refresh, window, refreshed): (u64, u64, u64)) {
			let config = config_refreshing(Duration::from_millis(refresh), Duration::from_millis(window));
			assert_eq!(config.rumor_refresh(), Duration::from_millis(refreshed));
		}
		cases {
			slower_than_the_window => (900, 400, 400),
			inside_the_window => (300, 400, 300),
		}
	}

	// A relay trail outlives three missed refreshes, and an aggressive
	// refresh keeps the default interval as its floor.
	tb_cases! {
		fn a_relay_trail_ttl_is_three_refreshes_floored_at_the_default((refresh, ttl): (Duration, Duration)) {
			let config = config_refreshing(refresh, Duration::from_secs(120));
			assert_eq!(config.relay_trail_ttl(), ttl);
		}
		cases {
			three_refreshes => (Duration::from_secs(20), Duration::from_secs(60)),
			floored_at_the_default => (Duration::from_secs(5), Duration::from_secs(30)),
		}
	}

	/// A config that dials two peers and allows the first alone.
	fn config_with_two_peers() -> ClusterConfig {
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let builder = builder.with_peers(["127.0.0.1:9000", "127.0.0.1:9001"]);
		let builder = builder.expect("each fixture peer parses");
		let builder = builder.with_peer_dial_allowlist(["127.0.0.1:9000"]);
		builder.expect("the fixture allowlist parses").build()
	}

	/// The builder takes its peers as string slices, and keeps them in the
	/// order the operator wrote them.
	#[test]
	fn the_builder_takes_peers_as_str_slices() {
		let config = config_with_two_peers();
		let anchors = config.peer.peers();

		let in_order = ["127.0.0.1:9000", "127.0.0.1:9001"].map(AdmittedDial::fixture);
		assert_eq!(anchors, in_order);
	}

	// The allowlist admits a dial to the peer it names and refuses a dial to
	// a peer it leaves out, even one the config dials.
	tb_cases! {
		fn the_allowlist_admits_only_what_it_names((peer, admitted): (&str, Result<PeerAddress, DialRefusal>)) {
			let verdict = config_with_two_peers().peer.admit_dial(PeerAddress::fixture(peer));
			assert_eq!(verdict.map(|dial| dial.address()), admitted);
		}
		cases {
			a_listed_peer => ("127.0.0.1:9000", Ok(PeerAddress::fixture("127.0.0.1:9000"))),
			an_unlisted_peer => ("127.0.0.1:9001", Err(DialRefusal::OffAllowlist)),
		}
	}

	/// A builder setter that takes a socket spelling.
	type SocketSetter = fn(ClusterConfigBuilder) -> Result<ClusterConfigBuilder, ClusterError>;

	// The builder refuses a socket the operator mistyped where the operator
	// wrote it, rather than drop a peer into a federation with no anchors or
	// advertise an address no peer can dial.
	tb_cases! {
		fn a_socket_setter_refuses_a_spelling_that_names_no_socket(setter: SocketSetter) {
			let refusal = setter(ClusterConfig::builder(ClusterTlsConfig::fixture()));
			assert!(matches!(refusal, Err(ClusterError::InvalidPeerAddress)));
		}
		cases {
			peers => |builder| builder.with_peers(["not-an-address"]),
			advertise_addr => |builder| builder.with_advertise_addr("gateway.example"),
		}
	}

	/// The builder parses the advertise address once, so the beat advertises
	/// the canonical socket and a typo fails at build.
	#[test]
	fn with_advertise_addr_stores_the_canonical_socket() -> TestResult {
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let builder = builder.with_advertise_addr("[::ffff:192.0.2.1]:9000")?;
		let config = builder.with_advertise_interval(Duration::from_secs(5)).build();

		let advertised = config.peer.advertised_address(b"0.0.0.0:9000")?;
		assert_eq!(advertised.as_ref(), b"192.0.2.1:9000");
		Ok(())
	}

	/// The builder refuses an unroutable URN where the operator configures it.
	#[test]
	fn gossip_ingress_refuses_a_urn_no_route_can_answer() {
		let instance = ColonyNamespace::instance_fixture("ping", "10.0.0.5:9100");
		let refused = ClusterConfig::builder(ClusterTlsConfig::fixture()).with_gossip_ingress(instance);
		assert!(matches!(refused, Err(ClusterError::UnknownServletType(_))));
	}

	/// The ingress key of a configuration is the route key of its ingress
	/// under its namespace.
	#[test]
	fn the_gossip_ingress_key_is_the_route_key_of_the_ingress() -> TestResult {
		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let conf = builder.with_gossip_ingress(ColonyNamespace::servlet_fixture("ping"))?.build();

		let key = conf.gossip_ingress_key()?;
		let named = key.as_ref().map(ServletTypeKey::as_bytes);
		assert_eq!(named, Some(b"urn:tightbeam::servlet:ping".as_slice()));
		Ok(())
	}

	/// A gossip section whose ingress names a servlet type of another
	/// namespace mints no key, as an ingress set through the builder does.
	#[test]
	fn a_gossip_section_of_another_namespace_mints_no_ingress_key() -> TestResult {
		let ingress = ColonyNamespace::new("acme", "prod")?.servlet("feed")?;
		let gossip = GossipConfig { ingress: Some(ingress), ..GossipConfig::default() };

		let builder = ClusterConfig::builder(ClusterTlsConfig::fixture());
		let config = builder.with_gossip_config(gossip).build();
		let minted = config.gossip_ingress_key();
		assert!(matches!(minted, Err(ClusterError::UnknownServletType(_))));
		Ok(())
	}
}
