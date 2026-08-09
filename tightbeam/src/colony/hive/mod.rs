//! Hive framework for servlet orchestration.
//!
//! - Manages servlet registration, scaling, and cluster control-plane traffic.
//! - Exposes [`Hive`] and [`HiveConfig`] for application wiring.

pub mod error;
pub mod gates;
pub mod runtime;

pub use runtime::{HiveContextImpl, HiveRuntime};

pub use crate::colony::common::{
	ActivateServletRequest, ActivateServletResponse, ClusterCommand, ClusterCommandResponse, ClusterStatus,
	ColonyNamespace, ColonyResource, HeartbeatParams, HeartbeatResult, HiveManagementRequest, HiveManagementResponse,
	InstanceMetrics, ListServletsParams, ListServletsResult, LoadBalancer, PowerOfTwoChoices, RegisterHiveRequest,
	RegisterHiveResponse, RoundRobin, ScalingDecision, ScalingMetrics, ServletAddressUpdate,
	ServletAddressUpdateResponse, ServletInfo, ServletScaleConfig, SpawnServletParams, SpawnServletResult,
	StochasticForager, StopServletParams, StopServletResult,
};

pub use error::HiveError;
pub use gates::{BackpressureGate, CircuitState, ClusterCircuitBreaker};

#[cfg(feature = "x509")]
pub use gates::{
	verify_frame_signature, ClusterSecurityGate, PeerListGate, PeerListMode, ReplayGuard, TrustVerification,
};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
use std::sync::Arc;

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use crate::constants::DEFAULT_BACKPRESSURE_THRESHOLD_BPS;
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::multiplex::{RequestSink, StreamBody};
use crate::transport::policy::CoreRetryPolicy;
use crate::transport::serve::unimplemented_error;
use crate::transport::Protocol;
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

#[cfg(feature = "x509")]
pub use crate::crypto::x509::store::CertificateTrust;

/// Type alias for the spawner function used in auto-scaling.
///
/// A spawner function creates a new servlet instance given a trace collector.
/// This enables hives to spawn additional servlet instances when scaling up.
pub type SpawnerFn = Arc<
	dyn Fn(Arc<TraceCollector>) -> Pin<Box<dyn Future<Output = Result<Box<dyn ServletBox>, TightBeamError>> + Send>>
		+ Send
		+ Sync,
>;

/// Trait for type-erased servlet storage in hives.
///
/// This enables hives to store servlets of different types in a single collection.
/// Servlets implement this trait to be registerable with a hive.
pub trait ServletBox: Send + Sync {
	/// Shared bound-address bytes (encoded once at servlet start).
	fn addr_bytes(&self) -> Arc<[u8]>;

	/// Stop the servlet, consuming the boxed instance.
	fn stop_boxed(self: Box<Self>);

	/// Get the servlet's current utilization (0-10000 basis points).
	///
	/// Returns `None` if the servlet does not report utilization.
	/// Used by the scaling task to evaluate scaling decisions.
	///
	/// Default implementation returns `None`, indicating the servlet
	/// does not self-report utilization.
	fn utilization(&self) -> Option<BasisPoints> {
		None
	}

	/// Check if the servlet is healthy and responsive.
	///
	/// The scaling task uses this for self-healing, so unhealthy
	/// servlets may be stopped and respawned. Implementations can check
	/// internal state, connectivity, or other health indicators.
	///
	/// Default implementation returns `true`, assuming the servlet is healthy.
	fn is_healthy(&self) -> bool {
		true
	}
}

/// A registered servlet with its spawner function for auto-scaling.
pub struct ServletRegistration {
	/// Running servlet instance stored under the hive registry.
	pub servlet: Box<dyn ServletBox>,
	/// Closure that creates another instance of this servlet type.
	pub spawner: SpawnerFn,
	/// Type URN that identifies this servlet kind for routing and scaling.
	pub servlet_type: Urn<'static>,
}

/// Abstraction for servlet storage within a hive.
///
/// Provides a consistent interface for storing and retrieving servlet
/// registrations. The default implementation uses a HashMap, but custom
/// implementations could use sharded storage for high concurrency.
pub trait ServletRegistry: Send + Sync {
	/// Insert a servlet registration.
	fn insert(&self, key: Vec<u8>, registration: ServletRegistration) -> Result<(), TightBeamError>;

	/// Remove and return a servlet registration.
	fn remove(&self, key: &[u8]) -> Option<ServletRegistration>;

	/// Iterate over all registrations via callback.
	fn for_each<F>(&self, f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration);

	/// Find registrations by type prefix via callback.
	fn for_each_by_type<F>(&self, prefix: &[u8], f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration);

	/// Count of registered servlets.
	fn count(&self) -> usize;

	/// Get all servlet addresses as (type URN, address) pairs.
	fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)>;

	/// Drain all registrations and return them.
	/// Used during shutdown to stop all servlets.
	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)>;

	/// Get all keys (for collecting keys to remove).
	fn keys(&self) -> Vec<Vec<u8>>;
}

/// Default HashMap-based implementation of ServletRegistry.
pub struct HashMapRegistry {
	inner: std::sync::Mutex<HashMap<Vec<u8>, ServletRegistration>>,
}

impl Default for HashMapRegistry {
	fn default() -> Self {
		Self { inner: std::sync::Mutex::new(HashMap::new()) }
	}
}

impl ServletRegistry for HashMapRegistry {
	fn insert(&self, key: Vec<u8>, registration: ServletRegistration) -> Result<(), TightBeamError> {
		self.inner
			.lock()
			.map_err(|_| TightBeamError::LockPoisoned)?
			.insert(key, registration);
		Ok(())
	}

	fn remove(&self, key: &[u8]) -> Option<ServletRegistration> {
		self.inner.lock().ok()?.remove(key)
	}

	fn for_each<F>(&self, mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		if let Ok(guard) = self.inner.lock() {
			guard.iter().for_each(|(k, v)| f(k, v));
		}
	}

	fn for_each_by_type<F>(&self, prefix: &[u8], mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		if let Ok(guard) = self.inner.lock() {
			guard.iter().filter(|(k, _)| k.starts_with(prefix)).for_each(|(k, v)| f(k, v));
		}
	}

	fn count(&self) -> usize {
		self.inner.lock().map(|g| g.len()).unwrap_or(0)
	}

	fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)> {
		self.inner
			.lock()
			.map(|guard| {
				guard
					.values()
					.map(|reg| {
						let address = reg.servlet.addr_bytes().as_ref().to_vec();
						(reg.servlet_type.clone(), address)
					})
					.collect()
			})
			.unwrap_or_default()
	}

	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)> {
		self.inner.lock().map(|mut guard| guard.drain().collect()).unwrap_or_default()
	}

	fn keys(&self) -> Vec<Vec<u8>> {
		self.inner
			.lock()
			.map(|guard| guard.keys().cloned().collect())
			.unwrap_or_default()
	}
}

/// Trait for hive implementations.
///
/// Hives are orchestrators that manage servlet instances. Servlets are started
/// independently with their own configs, then registered with the hive along
/// with a spawner function for auto-scaling.
///
/// # Usage
///
/// ```ignore
/// // 1. Start servlets independently with their own configs
/// let trace = Arc::new(TraceCollector::new());
/// let auth_conf = auth_conf.clone();
/// let auth = AuthServlet::start(Arc::clone(&trace), Some(auth_conf.clone())).await?;
/// let capture = CaptureServlet::start(Arc::clone(&trace), None).await?;
///
/// // 2. Create hive
/// let mut hive = PaymentHive::new(Some(hive_conf))?;
///
/// // 3. Register with spawners for auto-scaling (types named by URN)
/// let ns = ColonyNamespace::default();
/// hive.register(ns.servlet("auth")?, auth, |t| AuthServlet::start(t, Some(auth_conf.clone())))?;
/// hive.register(ns.servlet("capture")?, capture, |t| CaptureServlet::start(t, None))?;
///
/// // 4. Establish (starts control server + scaling task)
/// hive.establish(trace).await?;
///
/// // 5. Register with cluster
/// hive.register_with_cluster(cluster_addr).await?;
/// ```
pub trait Hive: Sized + Send + Sync {
	/// The protocol type this hive uses.
	type Protocol: Protocol;

	/// The address type for this hive.
	type Address;

	/// Create a new hive instance.
	///
	/// The hive is created but not yet established. Call `register()` to add
	/// servlets, then `establish()` to start the hive.
	fn new(config: Option<HiveConfig>) -> Result<Self, TightBeamError>;

	/// Register an already-started servlet with the hive.
	///
	/// The spawner function enables auto-scaling: when the hive needs to spawn
	/// additional instances, it calls the spawner with a trace collector.
	///
	/// # Arguments
	/// * `servlet_type` - Type URN for this servlet, used for intra-hive
	///   and cluster routing. Create it with [`ColonyNamespace::servlet`].
	/// * `servlet` - An already-started servlet instance
	/// * `spawner` - Function to spawn additional instances of this servlet type
	///
	/// # Type Parameters
	/// * `S` - The servlet type (must implement `ServletBox`)
	/// * `F` - The spawner function type
	/// * `Fut` - The future returned by the spawner
	fn register<S, F, Fut>(&mut self, servlet_type: Urn<'static>, servlet: S, spawner: F) -> Result<(), TightBeamError>
	where
		S: ServletBox + 'static,
		F: Fn(Arc<TraceCollector>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static;

	/// Establish the hive.
	///
	/// Sets up intra-hive routing (HiveContext), starts the control server
	/// for cluster commands, and begins the auto-scaling task.
	/// All servlets should be registered before calling this.
	///
	/// # Arguments
	/// * `trace` - Trace collector for hive-level events
	fn establish(&mut self, trace: Arc<TraceCollector>) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Shared intra-hive communication context.
	///
	/// Created at `new` and populated with servlet addresses at
	/// `establish`. The same `Arc` is live-updated as servlets scale.
	/// Hand it to
	/// [`ServletConfigBuilder::with_hive_context`](crate::colony::servlet::ServletConfigBuilder::with_hive_context)
	/// so servlet handlers can reach siblings, or use it directly for
	/// [`HiveContext::call`], [`HiveContext::open_stream`], and
	/// [`HiveContext::open_duplex`].
	fn context(&self) -> Arc<dyn HiveContext>;

	/// Get the hive's control server address.
	fn addr(&self) -> &Self::Address;

	/// Get addresses of all registered servlets.
	///
	/// Returns a list of (type URN, address_bytes) pairs.
	fn servlet_addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)>;

	/// Stop the hive, control server, scaling task, and all registered servlets.
	fn stop(self);

	/// Wait for the hive to complete (joins control server handle).
	fn join(self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Register this hive with a cluster.
	///
	/// Sends `RegisterHiveRequest` with all servlet addresses to the cluster.
	/// The cluster will then route work to the servlets and send management
	/// commands (heartbeat, spawn, stop) to this hive's control server.
	///
	/// Must be called after [`Hive::establish`]. A provisional address from
	/// [`Hive::new`] is not a live control socket.
	///
	/// # Arguments
	/// * `cluster_addr` - The address of the cluster controller
	fn register_with_cluster(
		&self,
		cluster_addr: &<Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterHiveResponse, TightBeamError>> + Send;

	/// Begin graceful shutdown and stop accepting new requests.
	///
	/// Sets draining state and waits for in-flight requests to complete
	/// or until the configured drain timeout is reached.
	fn drain(&self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Check if the hive is currently draining.
	fn is_draining(&self) -> bool;
}

/// TLS material for hive control-plane and servlet identity.
///
/// Wrapped in `Arc` inside [`HiveConfig`] because validators are trait objects.
#[cfg(feature = "x509")]
pub struct HiveTlsConfig {
	/// Server certificate specification used for TLS identity.
	pub certificate: crate::crypto::x509::CertificateSpec,
	/// Private key provider used for handshake and control-frame signing.
	pub key: Arc<dyn crate::crypto::key::SigningKeyProvider>,
	/// Client certificate validators such as public-key pinning.
	pub validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
}

#[cfg(feature = "x509")]
impl core::fmt::Debug for HiveTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HiveTlsConfig")
			.field("certificate", &self.certificate)
			.field("key", &"<KeyProvider>")
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.finish()
	}
}

/// Reply future of an intra-hive call. Resolves to the sibling
/// servlet's complete reply [`Frame`]. A servlet answering with no
/// frame is `MissingResponse`.
pub type CallFuture<'a> = Pin<Box<dyn Future<Output = Result<Frame, TightBeamError>> + Send + 'a>>;

/// Unary reply future of a streamed intra-hive call. Resolves once the
/// sibling servlet answers the stream's trailer. Yields the servlet's
/// complete trailer reply [`Frame`], the same shape as
/// [`HiveContext::call`] and the cluster plane's `open_stream_to`
/// guarantee. A servlet answering with no frame is `MissingResponse`.
pub type StreamResponseFuture = Pin<Box<dyn Future<Output = Result<Frame, TightBeamError>> + Send>>;

/// Future resolving to a streamed intra-hive call's producer half: the
/// [`RequestSink`] plus the [`StreamResponseFuture`] for the reply.
pub type StreamOpenFuture<'a> =
	Pin<Box<dyn Future<Output = Result<(RequestSink, StreamResponseFuture), TightBeamError>> + Send + 'a>>;

/// Future resolving to a duplex intra-hive call's two halves: the
/// [`RequestSink`] for pushing and the [`StreamBody`] carrying the reply.
pub type DuplexOpenFuture<'a> =
	Pin<Box<dyn Future<Output = Result<(RequestSink, StreamBody), TightBeamError>> + Send + 'a>>;

/// Context for intra-hive servlet communication.
///
/// This trait enables servlets within the same hive to call each other
/// without going through the cluster. This is useful for patterns like
/// a KeyManager servlet that provides encryption/decryption services
/// to other servlets in the hive.
///
/// Every verb is envelope-preserving. The caller's complete [`Frame`]
/// travels to the sibling unmodified, and the sibling's complete reply
/// frame travels back unmodified. Callers compose their own envelope
/// with [`compose!`](crate::compose), sign it when the sibling is
/// signature-gated, and verify or decode the reply themselves.
///
/// # Example
///
/// The caller owns the whole exchange: compose the envelope, sign it,
/// send it through [`HiveContext::call`], then verify and decode the
/// sibling's reply. The stand-in sibling here answers with a signed
/// echo, so the example runs without a live hive.
///
/// ```
/// # use sha3::Sha3_256;
/// # use tightbeam::builder::{frame::FrameBuilder, TypeBuilder};
/// # use tightbeam::colony::hive::{CallFuture, HiveContext};
/// # use tightbeam::crypto::key::Secp256k1KeyProvider;
/// # use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
/// # use tightbeam::testing::{create_test_signing_key, TestMessage};
/// # use tightbeam::utils::urn::Urn;
/// # use tightbeam::{decode, Frame, TightBeamError, Version};
/// #
/// # struct EchoSibling;
/// #
/// # impl HiveContext for EchoSibling {
/// #     fn call<'a>(&'a self, _servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a> {
/// #         Box::pin(async move {
/// #             let echoed: TestMessage = decode(&frame.message)?;
/// #             let unsigned = FrameBuilder::from(Version::V0).with_id(b"km-reply").with_message(echoed).build()?;
/// #             let provider = Secp256k1KeyProvider::from(create_test_signing_key());
/// #             unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
/// #         })
/// #     }
/// # }
/// #
/// # fn main() -> Result<(), TightBeamError> {
/// # let runtime = tokio::runtime::Builder::new_current_thread().build().expect("doctest runtime");
/// # runtime.block_on(async {
/// # let ctx = EchoSibling;
/// # let keymanager_urn = Urn::new("tightbeam", "servlet:keymanager");
/// # let sibling_key = create_test_signing_key();
/// let caller_provider = Secp256k1KeyProvider::from(create_test_signing_key());
///
/// let unsigned = FrameBuilder::from(Version::V0)
///     .with_id(b"km-decrypt")
///     .with_message(TestMessage { content: "unwrap key 7".into() })
///     .build()?;
/// let request = unsigned.sign_with_provider::<Sha3_256, _>(&caller_provider).await?;
///
/// let reply = ctx.call(&keymanager_urn, request).await?;
///
/// // The reply is the sibling's complete envelope: verify, then decode.
/// reply.verify::<Secp256k1Signature, Sha3_256>(sibling_key.verifying_key())?;
/// let response: TestMessage = decode(&reply.message)?;
/// assert_eq!(response.content, "unwrap key 7");
/// # Ok::<(), TightBeamError>(())
/// # })
/// # }
/// ```
pub trait HiveContext: Send + Sync {
	/// Call a sibling servlet with a complete, caller-built [`Frame`]
	/// and get the servlet's complete reply frame.
	///
	/// The frame emits as-is, so a `nonrepudiation` signature the caller
	/// applied stays verifiable at the servlet. The reply is the
	/// servlet's complete envelope. Callers verify it with
	/// [`Frame::verify`] before trusting the message body. A servlet
	/// answering with no frame is `MissingResponse`.
	///
	/// # Arguments
	/// * `servlet_type` - Type URN of the target servlet (e.g.,
	///   `urn:tightbeam::servlet:keymanager`)
	/// * `frame` - The complete command frame to deliver unmodified
	fn call<'a>(&'a self, servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a>;

	/// Open a request stream to a sibling servlet. Push chunks through the
	/// [`RequestSink`], then await the returned response future for the
	/// servlet's unary reply. Requires a multiplex-negotiated connection.
	///
	/// Default refuses with `Unimplemented` so context implementations
	/// without a mux-capable pool stay valid.
	fn open_stream<'a>(&'a self, servlet_type: &'a Urn<'a>) -> StreamOpenFuture<'a> {
		let _ = servlet_type;
		Box::pin(async { Err(unimplemented_error()) })
	}

	/// Open a duplex stream to a sibling servlet. Push request chunks
	/// through the [`RequestSink`] while the servlet's reply chunks arrive
	/// on the [`StreamBody`]. Requires a multiplex-negotiated connection.
	///
	/// Default refuses with `Unimplemented` so context implementations
	/// without a mux-capable pool stay valid.
	fn open_duplex<'a>(&'a self, servlet_type: &'a Urn<'a>) -> DuplexOpenFuture<'a> {
		let _ = servlet_type;
		Box::pin(async { Err(unimplemented_error()) })
	}
}

/// Auto-scale evaluation cadence and per-type overrides.
#[derive(Clone, Debug)]
pub struct HiveScalingConfig {
	/// Default scaling thresholds applied when no per-type override exists.
	pub default_scale: ServletScaleConfig,
	/// Per-type scaling overrides keyed by servlet type URN.
	pub overrides: HashMap<Urn<'static>, ServletScaleConfig>,
	/// Minimum wait between scaling evaluation cycles.
	pub cooldown: Duration,
}

impl Default for HiveScalingConfig {
	fn default() -> Self {
		Self {
			default_scale: ServletScaleConfig::default(),
			overrides: HashMap::new(),
			cooldown: Duration::from_secs(5),
		}
	}
}

/// Manage-path admission, drain, and gateway anti-entropy.
#[derive(Clone)]
pub struct HiveControlConfig {
	/// Utilization threshold that trips manage-path backpressure.
	pub backpressure_threshold: BasisPoints,
	/// Maximum wait for graceful drain before force-stopping remaining servlets.
	pub drain_timeout: Duration,
	/// Anti-entropy interval for re-announcing the servlet slate to gateways.
	///
	/// Every interval the hive re-announces its full servlet slate, freshly
	/// signed, to every gateway it has registered with. `None` disables the beat.
	pub reregister_interval: Option<Duration>,
	/// Consecutive auth failures that open the cluster circuit breaker.
	pub circuit_breaker_threshold: u8,
	/// Milliseconds the circuit breaker stays open before a half-open probe.
	pub circuit_breaker_cooldown_ms: u64,
	/// Freshness window for signed cluster commands in milliseconds.
	///
	/// Commands whose `Frame.metadata.order` is outside this window, or whose
	/// signature was already seen inside it, are rejected. See [`ReplayGuard`].
	#[cfg(feature = "x509")]
	pub command_freshness_window_ms: u64,
	/// Retry policy used when fanning out scaling updates to gateways.
	#[cfg(feature = "std")]
	pub notify_retry: Arc<dyn CoreRetryPolicy + Send + Sync>,
}

impl core::fmt::Debug for HiveControlConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut d = f.debug_struct("HiveControlConfig");
		d.field("backpressure_threshold", &self.backpressure_threshold)
			.field("drain_timeout", &self.drain_timeout)
			.field("reregister_interval", &self.reregister_interval)
			.field("circuit_breaker_threshold", &self.circuit_breaker_threshold)
			.field("circuit_breaker_cooldown_ms", &self.circuit_breaker_cooldown_ms);
		#[cfg(feature = "x509")]
		d.field("command_freshness_window_ms", &self.command_freshness_window_ms);
		#[cfg(feature = "std")]
		d.field("notify_retry", &"<RetryPolicy>");
		d.finish()
	}
}

impl Default for HiveControlConfig {
	fn default() -> Self {
		Self {
			backpressure_threshold: BasisPoints::new(DEFAULT_BACKPRESSURE_THRESHOLD_BPS),
			drain_timeout: Duration::from_secs(30),
			reregister_interval: Some(Duration::from_secs(5)),
			circuit_breaker_threshold: 3,
			circuit_breaker_cooldown_ms: 30_000,
			#[cfg(feature = "x509")]
			command_freshness_window_ms: crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS,
			#[cfg(feature = "std")]
			notify_retry: Arc::new(crate::transport::policy::RestartExponentialBackoff {
				max_attempts: 3,
				scale_factor: 500,
				jitter: Some(Box::new(crate::transport::policy::DecorrelatedJitter)),
			}),
		}
	}
}

/// Configuration for hive lifecycle, scaling, and control-plane security.
///
/// A hive resolves each servlet type to one local instance address.
/// Instance selection across replicas is the cluster gateway's job.
/// See [`ClusterConfig`](crate::colony::cluster::ClusterConfig).
#[derive(Clone)]
pub struct HiveConfig {
	/// Naming scope resource URNs are validated against.
	/// Registrations with a foreign authority or realm fail at [`Hive::register`].
	pub namespace: ColonyNamespace,
	/// Auto-scale evaluation and per-type overrides.
	pub scaling: HiveScalingConfig,
	/// Manage-path admission, drain, and gateway anti-entropy.
	pub control: HiveControlConfig,
	/// Intra-hive servlet pool and control-server mux advertisement.
	///
	/// Pool connections multiplex only when the servlet also advertises via
	/// [`ServletConfigBuilder::with_mux_offer`](crate::colony::servlet::ServletConfigBuilder::with_mux_offer).
	pub pool: PoolConfig,
	/// Trust store for cluster-command auth and intra-hive servlet TLS.
	///
	/// When `None`, authenticated cluster commands are rejected and encrypted
	/// servlet calls fail closed without a trust anchor.
	#[cfg(feature = "x509")]
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
	/// TLS identity for control-plane signing and encrypted transport.
	#[cfg(feature = "x509")]
	pub hive_tls: Option<Arc<HiveTlsConfig>>,
}

impl core::fmt::Debug for HiveConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut d = f.debug_struct("HiveConfig");
		d.field("namespace", &self.namespace)
			.field("scaling", &self.scaling)
			.field("control", &self.control)
			.field("pool", &self.pool);
		#[cfg(feature = "x509")]
		d.field("trust_store", &self.trust_store.as_ref().map(|_| "<CertificateTrust>"));
		#[cfg(feature = "x509")]
		d.field("hive_tls", &self.hive_tls);
		d.finish()
	}
}

impl Default for HiveConfig {
	fn default() -> Self {
		Self {
			namespace: ColonyNamespace::default(),
			scaling: HiveScalingConfig::default(),
			control: HiveControlConfig::default(),
			pool: PoolConfig { max_connections: 8, idle_timeout: Some(Duration::from_secs(30)), mux_offer: None },
			#[cfg(feature = "x509")]
			trust_store: None,
			#[cfg(feature = "x509")]
			hive_tls: None,
		}
	}
}

// The hive! macro is defined in macros.rs and exported via #[macro_export].
#[path = "macros.rs"]
mod macros_impl;
