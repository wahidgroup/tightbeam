//! Cluster framework: gateways that route work to registered hives.
//!
//! - Hives register and announce servlet types.
//! - The gateway keeps hive and servlet registries.
//! - Clients send [`ClusterWorkRequest`] with a servlet type and payload.
//! - The gateway selects a route and forwards the payload.

pub mod builder;
pub mod error;
pub mod macros;
pub mod registry;
pub mod runtime;
pub mod servlet_registry;

#[cfg(feature = "x509")]
#[doc(hidden)]
pub mod gossip;
#[doc(hidden)]
pub mod outbound;
#[doc(hidden)]
pub mod peer;

pub use builder::{ClusterConfigBuilder, HeartbeatConfigBuilder};
pub use error::ClusterError;
pub use registry::{HiveEntry, HiveRegistry, SharedId};
pub use runtime::ClusterGateway;
pub use servlet_registry::{PeerCaps, PeerRouteInfo, PheromoneConfig, RouteKind, ServletEntry, ServletRegistry};

#[cfg(feature = "x509")]
pub use gossip::{
	gossip_digest, gossip_fresh, gossip_want, signer_attribution, wanted_digests, Admission, AdmittedGossip,
	GossipAdmission, GossipConfig, GossipDigest, GossipJournal, MemoryGossipJournal, TokenBucketAdmission,
};

#[cfg(feature = "x509")]
pub use peer::{cert_colony_urn, frame_colony_urn, frame_signer_cert, peer_signer_fingerprint};

use core::future::Future;
use core::time::Duration;
use std::sync::Arc;

use crate::crypto::key::SigningKeyProvider;
use crate::policy::GatePolicy;
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::{Protocol, TightBeamAddress};

#[cfg(feature = "x509")]
use crate::crypto::x509::{policy::CertificateValidation, CertificateSpec};
#[cfg(feature = "x509")]
use crate::utils::urn::Urn;

use super::common::{ColonyNamespace, LoadBalancer};

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
	/// Time between heartbeat cycles
	pub interval: Duration,
	/// Age after which a silent hive is evicted
	pub timeout: Duration,
	/// Cap on concurrent heartbeat dials per cycle
	pub max_concurrent: usize,
	/// Consecutive failures before unregistering a hive
	pub max_failures: u32,
	/// Optional per-result callback for monitoring or tests
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
	/// Hive control address that was dialed
	pub hive_addr: Arc<[u8]>,
	/// Whether the hive answered within policy
	pub success: bool,
	/// Utilization from the hive when the heartbeat succeeded
	pub utilization: Option<crate::utils::BasisPoints>,
}

/// Callback after each heartbeat result.
///
/// Must be `Send + Sync`: the loop may invoke it from concurrent tasks.
pub type HeartbeatCallback = Arc<dyn Fn(HeartbeatEvent) + Send + Sync>;

/// TLS material for the gateway accept loop and hive/peer dials.
#[cfg(feature = "x509")]
pub struct ClusterTlsConfig {
	/// Gateway certificate (server identity; also used on outbound client dials)
	pub certificate: CertificateSpec,
	/// Signing key for control frames and TLS (HSM/KMS capable)
	pub key: Arc<dyn SigningKeyProvider>,
	/// Server-certificate validators for outbound hive dials
	pub validators: Vec<Arc<dyn CertificateValidation>>,
	/// Client-certificate validators for inbound mutual TLS
	pub client_validators: Vec<Arc<dyn CertificateValidation>>,
	/// Trust store for hive/servlet server certificates on outbound dials
	pub hive_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
	/// Trust anchor for peer-gateway advertisements and relayed gossip.
	/// Separate from `hive_trust`: peer certificates cannot register as
	/// hives; hive certificates cannot forge peer ads. `None` disables
	/// inbound federation (advertisements are refused).
	pub peer_trust: Option<Arc<dyn crate::crypto::x509::store::CertificateTrust>>,
}

#[cfg(feature = "x509")]
impl Clone for ClusterTlsConfig {
	fn clone(&self) -> Self {
		Self {
			certificate: self.certificate.clone(),
			key: Arc::clone(&self.key),
			validators: self.validators.iter().map(Arc::clone).collect(),
			client_validators: self.client_validators.iter().map(Arc::clone).collect(),
			hive_trust: self.hive_trust.as_ref().map(Arc::clone),
			peer_trust: self.peer_trust.as_ref().map(Arc::clone),
		}
	}
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for ClusterTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterTlsConfig")
			.field("certificate", &self.certificate)
			.field("key", &"<KeyProvider>")
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.field("client_validators", &format!("[{} validators]", self.client_validators.len()))
			.field("hive_trust", &self.hive_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.field("peer_trust", &self.peer_trust.as_ref().map(|_| "Some(<TrustStore>)"))
			.finish()
	}
}

/// Peer-federation dial list, advertise beat, and inbound dial allowlist.
///
/// Trust anchors stay on [`ClusterTlsConfig::peer_trust`].
#[derive(Clone, Debug, Default)]
pub struct PeerConfig {
	/// Peer gateway addresses dialed to advertise exported types.
	/// Dial list, not an identity gate; partial or asymmetric graphs are
	/// expected. Empty disables outbound advertisement.
	///
	/// The slate is never configured: each beat snapshots the local
	/// servlet registry so peers learn types currently served.
	pub peers: Vec<String>,
	/// Re-advertise beat cadence. `None` disables the beat.
	pub advertise_interval: Option<Duration>,
	/// When `Some`, inbound peer ads may only claim dial addresses in this
	/// list (exact string match). `None` accepts any parseable socket.
	pub peer_dial_allowlist: Option<Vec<String>>,
}

/// Runtime configuration for a cluster gateway.
///
/// Load balancer is `Arc<dyn LoadBalancer>`, defaulting to
/// [`StochasticForager`](crate::colony::common::StochasticForager).
pub struct ClusterConfig {
	/// Naming scope for inbound resource URNs.
	/// Foreign authority or realm on register, update, or work is refused.
	pub namespace: ColonyNamespace,
	/// Strategy for selecting among candidate servlet instances
	pub load_balancer: Arc<dyn LoadBalancer>,
	/// Hive health probes and eviction policy
	pub heartbeat: HeartbeatConfig,
	/// Route scoring: reinforcement, weaken, and evaporation
	pub pheromone: PheromoneConfig,
	/// Gate policies evaluated before request decode
	pub policies: Vec<Arc<dyn GatePolicy + Send + Sync>>,
	/// Outbound connection pool settings for hive and peer dials
	pub pool_config: PoolConfig,
	/// Freshness window (ms) for signed hive control frames.
	/// Stale or replayed registration/update frames are rejected (CWE-294).
	pub control_freshness_window_ms: u64,
	/// Gateway bind address via the protocol address `FromStr`.
	/// `None` binds the protocol default. A stable address lets hives
	/// re-register across gateway restarts without reconfiguration.
	pub bind_addr: Option<String>,
	/// Peer-federation dial list, advertise beat, and dial allowlist
	pub peer: PeerConfig,
	/// Gossip freshness, TTL, ingress, journal, and admission
	#[cfg(feature = "x509")]
	pub gossip: GossipConfig,
	/// Colony URN from the gateway certificate URI SAN, derived once at
	/// build by [`cert_colony_urn`](crate::colony::cluster::cert_colony_urn).
	/// `None` means not a colony member: gossip publish/relay/reconcile
	/// and peer ads are refused; the advertise beat skips gossip
	/// reconciliation. Work and hive registration never require membership.
	///
	/// Private so membership cannot drift from the certificate: the
	/// builder derives it; [`ClusterConfig::colony_urn`] reads it.
	#[cfg(feature = "x509")]
	colony_urn: Option<Urn<'static>>,
	/// TLS material for accept and outbound dials
	#[cfg(feature = "x509")]
	pub tls: ClusterTlsConfig,
}

#[cfg(feature = "x509")]
impl ClusterConfig {
	/// Build a default config around the given TLS material.
	pub fn new(tls: ClusterTlsConfig) -> Self {
		Self::builder(tls).build()
	}

	/// Colony URN from the gateway certificate URI SAN.
	///
	/// `None` when this gateway is not a colony member. Derived once by
	/// the builder; read-only afterwards.
	#[must_use]
	pub fn colony_urn(&self) -> Option<&Urn<'static>> {
		self.colony_urn.as_ref()
	}
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for ClusterConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("ClusterConfig")
			.field("namespace", &self.namespace)
			.field("heartbeat", &self.heartbeat)
			.field("pheromone", &self.pheromone)
			.field("policies", &format!("[{} policies]", self.policies.len()))
			.field("pool_config", &self.pool_config)
			.field("control_freshness_window_ms", &self.control_freshness_window_ms)
			.field("bind_addr", &self.bind_addr)
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
/// Gateways route work to registered hives by servlet type. Hives register
/// dynamically; servlet types are learned from those registrations.
pub trait Cluster: Sized + Send + Sync {
	/// Protocol this gateway serves
	type Protocol: Protocol;

	/// Bound address type for this gateway
	type Address: TightBeamAddress;

	/// Bind, spawn accept and background loops, return the running gateway
	fn start(
		trace: Arc<TraceCollector>,
		config: ClusterConfig,
	) -> impl Future<Output = Result<Self, crate::TightBeamError>> + Send;

	/// Gateway listen address (borrowed; no clone).
	fn addr(&self) -> &Self::Address;

	/// Servlet types available from registered local hives
	fn available_servlets(&self) -> Vec<SharedId>;

	/// Servlet types reachable through peer gateways (learned, not local)
	fn peer_servlets(&self) -> Vec<SharedId>;

	/// Learned peer routes with dial address and peer identity
	fn peer_routes(&self) -> Vec<PeerRouteInfo>;

	/// Count of currently registered hives
	fn hive_count(&self) -> usize;

	/// Shared trace collector for this gateway
	fn trace(&self) -> Arc<TraceCollector>;

	/// Abort accept and background tasks
	fn stop(self);

	/// Wait until the accept loop finishes
	fn join(self) -> impl Future<Output = Result<(), crate::colony::servlet::servlet_runtime::rt::JoinError>> + Send;
}

/// Heartbeat surface of a cluster gateway.
///
/// Split from [`Cluster`] so work-only consumers never depend on health
/// internals. [`ClusterGateway`] implements both traits for every alias.
pub trait ClusterHeartbeat: Cluster {
	/// Shared hive registry
	fn registry(&self) -> &Arc<HiveRegistry>;

	/// Heartbeat interval, timeout, and failure policy
	fn heartbeat_config(&self) -> &HeartbeatConfig;

	/// Send one signed heartbeat to a hive via the connection pool.
	///
	/// The background loop lives in [`ClusterGateway::start`]
	/// (`JoinSet`, bounded concurrency); it is not on this trait.
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
	use crate::colony::common::{canonical_bytes, ColonyNamespace, RegisterHiveRequest};
	use crate::colony::hive::ServletInfo;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::policy::TransitStatus;
	use crate::testing::create_test_signing_key;
	use crate::utils::BasisPoints;

	// =========================================================================
	// Test Helpers
	// =========================================================================

	fn test_tls_config() -> ClusterTlsConfig {
		let key: Secp256k1SigningKey = create_test_signing_key();
		ClusterTlsConfig {
			certificate: CertificateSpec::Der(&[]),
			key: Arc::new(Secp256k1KeyProvider::from(key)),
			validators: Vec::new(),
			client_validators: Vec::new(),
			hive_trust: None,
			peer_trust: None,
		}
	}

	fn test_registry() -> HiveRegistry {
		HiveRegistry::new(Duration::from_secs(15))
	}

	fn servlet_urn(name: &str) -> crate::utils::urn::Urn<'static> {
		ColonyNamespace::default()
			.servlet(name)
			.expect("test names satisfy the mint grammar")
	}

	fn type_key(name: &str) -> Vec<u8> {
		canonical_bytes(&servlet_urn(name))
	}

	fn request(addr: &[u8], servlets: &[&str]) -> RegisterHiveRequest {
		RegisterHiveRequest {
			hive_addr: addr.to_vec(),
			metadata: None,
			servlet_addresses: servlets
				.iter()
				.map(|s| ServletInfo { servlet_id: servlet_urn(s), address: addr.to_vec() })
				.collect(),
		}
	}

	fn request_with_meta(addr: &[u8], servlets: &[&str], meta: &[u8]) -> RegisterHiveRequest {
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
		registry.register(request(b"127.0.0.1:8080", &["ping", "calc"]))?;

		// Registered types found
		assert_eq!(registry.hives_for_type(&type_key("ping"))?.len(), 1);
		assert_eq!(registry.hives_for_type(&type_key("calc"))?.len(), 1);
		assert_eq!(
			registry.hives_for_type(&type_key("ping"))?[0].address.as_ref(),
			b"127.0.0.1:8080"
		);

		// Unknown type not found
		assert!(registry.hives_for_type(&type_key("unknown"))?.is_empty());

		Ok(())
	}

	#[test]
	fn registry_unregister() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping"]))?;

		assert_eq!(registry.len()?, 1);
		assert!(registry.unregister(b"127.0.0.1:8080")?.is_some());
		assert_eq!(registry.len()?, 0);
		assert!(registry.hives_for_type(&type_key("ping"))?.is_empty());

		Ok(())
	}

	#[test]
	fn registry_update_utilization() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"127.0.0.1:8080", &["ping"]))?;

		assert!(registry.update_utilization(b"127.0.0.1:8080", BasisPoints::new(5000))?);
		assert_eq!(registry.hives_for_type(&type_key("ping"))?[0].utilization.get(), 5000);

		Ok(())
	}

	#[test]
	fn registry_available_servlets_deduplicated() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &["ping", "calc"]))?;
		registry.register(request(b"hive2", &["ping", "worker"]))?;

		// ping, calc, worker - ping deduplicated
		assert_eq!(registry.to_available_servlets()?.len(), 3);

		Ok(())
	}

	#[test]
	fn registry_multiple_hives_same_type() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &["ping"]))?;
		registry.register(request(b"hive2", &["ping"]))?;

		assert_eq!(registry.hives_for_type(&type_key("ping"))?.len(), 2);

		Ok(())
	}

	#[test]
	fn registry_all_hives() -> Result<(), ClusterError> {
		let registry = test_registry();
		registry.register(request(b"hive1", &["ping"]))?;
		registry.register(request_with_meta(b"hive2", &["calc"], b"metadata"))?;

		let all = registry.all_hives()?;
		assert_eq!(all.len(), 2);

		let addrs: Vec<_> = all.iter().map(|e| e.address.as_ref()).collect();
		assert!(addrs.contains(&b"hive1".as_slice()));
		assert!(addrs.contains(&b"hive2".as_slice()));

		Ok(())
	}
}
