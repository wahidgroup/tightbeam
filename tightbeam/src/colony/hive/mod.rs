//! The hive framework for servlet orchestration.
//!
//! A hive registers servlets, scales them, and answers the cluster's
//! control-plane traffic.
//!
//! - [`Hive`] is the lifecycle trait, and [`HiveRuntime`] implements it.
//! - [`HiveConfig`] carries the scaling, control-plane, and identity settings.
//! - [`HiveContext`] carries calls between sibling servlets in one hive.
//! - [`ServletRegistry`] stores the registered servlets.
//! - [`gates`] holds the admission gates for cluster commands.

pub mod error;
pub mod gates;
pub mod runtime;

pub use runtime::{HiveContextImpl, HiveRuntime};

pub use crate::colony::common::{
	ActivateServletRequest, ActivateServletResponse, ClusterCommand, ClusterCommandResponse, ClusterStatus,
	ColonyNamespace, ColonyResource, HeartbeatParams, HeartbeatResult, HiveManagementRequest, HiveManagementResponse,
	InstanceMetrics, ListServletsParams, ListServletsResult, LoadBalancer, PowerOfTwoChoices, RegisterHiveRequest,
	RegisterHiveResponse, RoundRobin, ScaleConfigRefusal, ScaleCooldowns, ScalingDecision, ScalingMetrics,
	ServletAddressUpdate, ServletAddressUpdateResponse, ServletInfo, ServletScaleConfig, SpawnServletParams,
	SpawnServletResult, StochasticForager, StopServletParams, StopServletResult,
};

pub use error::HiveError;
pub use gates::{BackpressureGate, CircuitState, ClusterCircuitBreaker};

pub use gates::{BackpressureReport, ClusterSecurityGate, GateLimits, PeerListGate, PeerListMode, ReplayGuard};

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::constants::DEFAULT_BACKPRESSURE_THRESHOLD_BPS;
use crate::trace::TraceCollector;
use crate::transport::client::pool::PoolConfig;
use crate::transport::multiplex::{RequestSink, StreamBody};
use crate::transport::policy::CoreRetryPolicy;
use crate::transport::serve::unimplemented_error;
use crate::transport::state::ClientIdentity;
use crate::transport::Protocol;
use crate::utils::time::{Clock, SystemClock};
use crate::utils::urn::Urn;
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

pub use crate::crypto::x509::store::CertificateTrust;

/// The spawner that a hive calls to add one servlet instance on a scale-up.
///
/// The spawner receives the hive's trace collector and resolves to a new,
/// running instance of its servlet type.
pub type SpawnerFn = Arc<
	dyn Fn(Arc<TraceCollector>) -> Pin<Box<dyn Future<Output = Result<Box<dyn ServletBox>, TightBeamError>> + Send>>
		+ Send
		+ Sync,
>;

/// A type-erased servlet that a hive stores and controls.
///
/// A hive holds servlets of different types in one collection through this
/// trait, so a servlet implements it to register with a hive.
pub trait ServletBox: Send + Sync {
	/// The servlet's bound address as shared bytes, encoded once when the
	/// servlet starts.
	fn addr_bytes(&self) -> Arc<[u8]>;

	/// Stops the servlet and consumes the boxed instance.
	fn stop_boxed(self: Box<Self>);

	/// The servlet's current utilization, from 0 to 10000 basis points.
	///
	/// The scaling task reads this sample for its scaling decisions. The
	/// default implementation returns [`None`], which the scaling task reads
	/// as an unreported sample and replaces with the instance's last sample
	/// or [`UNKNOWN_SERVLET_UTILIZATION_BPS`].
	///
	/// [`UNKNOWN_SERVLET_UTILIZATION_BPS`]: crate::constants::UNKNOWN_SERVLET_UTILIZATION_BPS
	fn utilization(&self) -> Option<BasisPoints> {
		None
	}

	/// Whether the servlet is healthy and responsive.
	///
	/// An implementation can check internal state, connectivity, or other
	/// health indicators. The default implementation returns `true`.
	fn is_healthy(&self) -> bool {
		true
	}
}

/// A registered servlet with its spawner function for auto-scaling.
pub struct ServletRegistration {
	/// The running servlet instance that the hive registry stores.
	pub servlet: Box<dyn ServletBox>,
	/// The closure that creates another instance of this servlet type.
	pub spawner: SpawnerFn,
	/// The type URN that identifies this servlet kind for routing and scaling.
	pub servlet_type: Urn<'static>,
}

/// A registration a [`ServletRegistry`] refused, handed back to its caller.
///
/// The registration travels with the error, so the caller still holds the
/// servlet and stops it the one way [`ServletBox::stop_boxed`] names.
pub struct RefusedRegistration {
	/// Why the registry refused the insert.
	pub error: TightBeamError,
	/// The registration the registry did not take.
	pub registration: ServletRegistration,
}

impl RefusedRegistration {
	/// Stops the servlet the registry did not take and yields the refusal.
	///
	/// Every refused registration ends here, so the servlet stops the one
	/// way [`ServletBox::stop_boxed`] names rather than through its drop.
	pub fn stop_servlet(self) -> TightBeamError {
		self.registration.servlet.stop_boxed();

		self.error
	}
}

/// The servlet storage behind a hive.
///
/// [`HashMapRegistry`] is the shipped implementation. A custom
/// implementation MAY shard its storage for high concurrency.
pub trait ServletRegistry: Send + Sync {
	/// Stores `registration` under `key`.
	///
	/// # Errors
	///
	/// - [`RefusedRegistration`] -- the registry did not take the
	///   registration, which comes back so the caller can stop its servlet.
	///   It is boxed, so the success path pays one pointer for it.
	fn insert(
		&self,
		key: impl Into<Vec<u8>>,
		registration: ServletRegistration,
	) -> Result<(), Box<RefusedRegistration>>;

	/// Removes and returns the registration under `key`, if there is one.
	fn remove(&self, key: impl AsRef<[u8]>) -> Option<ServletRegistration>;

	/// Calls `f` with every registration and its key.
	fn for_each<F>(&self, f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration);

	/// Calls `f` with every registration whose key starts with `prefix`.
	fn for_each_by_type<F>(&self, prefix: impl AsRef<[u8]>, f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration);

	/// The current servlet slate, one entry per registered instance.
	///
	/// A registration whose address is not a valid instance locator is
	/// skipped, so a malformed entry costs its own row and not the slate.
	fn slate(&self) -> Vec<ServletInfo> {
		let mut list = Vec::new();
		self.for_each(|_key, reg| {
			let address = reg.servlet.addr_bytes();
			let Ok(servlet_id) = reg.servlet_type.instance_urn(address.as_ref()) else {
				return;
			};

			list.push(ServletInfo { servlet_id, address: address.as_ref().to_vec() });
		});

		list
	}

	/// The number of registered servlets.
	fn count(&self) -> usize;

	/// Every servlet address, as a pair of type URN and address bytes.
	fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)>;

	/// Removes and returns every registration, so that a stop or a drain can
	/// stop each servlet.
	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)>;

	/// Every registration key, which a scale-down reads to pick an instance.
	fn keys(&self) -> Vec<Vec<u8>>;
}

/// The shipped [`ServletRegistry`]: one `HashMap` behind a mutex.
///
/// Every write under the lock is one `HashMap` insert, remove or drain,
/// so a thread that panicked while holding the guard left a whole map
/// behind it. The registry therefore recovers a poisoned lock and keeps
/// serving, and every method answers.
pub struct HashMapRegistry {
	inner: Mutex<HashMap<Vec<u8>, ServletRegistration>>,
}

impl Default for HashMapRegistry {
	fn default() -> Self {
		Self { inner: Mutex::new(HashMap::new()) }
	}
}

impl HashMapRegistry {
	/// The spawner for every servlet type that is registered.
	///
	/// Instances of one type share a spawner, so the map holds one entry
	/// per type rather than one per instance.
	pub(crate) fn spawners(&self) -> HashMap<Urn<'static>, SpawnerFn> {
		let mut spawners = HashMap::new();
		self.for_each(|_key, reg| {
			spawners.insert(reg.servlet_type.clone(), Arc::clone(&reg.spawner));
		});

		spawners
	}

	/// The map, recovered from a poisoned lock because every write under
	/// the guard leaves a whole map.
	fn map(&self) -> MutexGuard<'_, HashMap<Vec<u8>, ServletRegistration>> {
		self.inner.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

impl ServletRegistry for HashMapRegistry {
	/// Takes every registration, so the result is always `Ok`.
	fn insert(
		&self,
		key: impl Into<Vec<u8>>,
		registration: ServletRegistration,
	) -> Result<(), Box<RefusedRegistration>> {
		let key: Vec<u8> = key.into();
		self.map().insert(key, registration);

		Ok(())
	}

	fn remove(&self, key: impl AsRef<[u8]>) -> Option<ServletRegistration> {
		let key = key.as_ref();
		self.map().remove(key)
	}

	fn for_each<F>(&self, mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		self.map().iter().for_each(|(k, v)| f(k, v));
	}

	fn for_each_by_type<F>(&self, prefix: impl AsRef<[u8]>, mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		let prefix = prefix.as_ref();
		self.map()
			.iter()
			.filter(|(k, _)| k.starts_with(prefix))
			.for_each(|(k, v)| f(k, v));
	}

	fn count(&self) -> usize {
		self.map().len()
	}

	fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)> {
		self.map()
			.values()
			.map(|reg| {
				let address = reg.servlet.addr_bytes().as_ref().to_vec();
				(reg.servlet_type.clone(), address)
			})
			.collect()
	}

	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)> {
		self.map().drain().collect()
	}

	fn keys(&self) -> Vec<Vec<u8>> {
		self.map().keys().cloned().collect()
	}
}

/// The lifecycle of a hive, which orchestrates servlet instances.
///
/// Each servlet starts on its own with its own configuration. The caller
/// then registers it with the hive together with a spawner that
/// auto-scaling calls.
///
/// # Usage
///
/// ```ignore
/// // 1. Start servlets independently with their own configs
/// let trace = Arc::new(TraceCollector::new());
/// let auth_conf = auth_conf.clone();
/// let auth = AuthServlet::start(Arc::clone(&trace), auth_conf.clone()).await?;
/// let capture = CaptureServlet::start(Arc::clone(&trace), ServletConfig::default()).await?;
///
/// // 2. Create hive
/// let mut hive = PaymentHive::new(Some(hive_conf))?;
///
/// // 3. Register with spawners for auto-scaling (types named by URN)
/// let ns = ColonyNamespace::default();
/// hive.register(ns.servlet("auth")?, auth, |t| AuthServlet::start(t, auth_conf.clone()))?;
/// hive.register(ns.servlet("capture")?, capture, |t| CaptureServlet::start(t, ServletConfig::default()))?;
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

	/// The address type that a cluster dials this hive on.
	type Address;

	/// Creates a provisional hive.
	///
	/// Call [`Hive::register`] to add servlets, then [`Hive::establish`] to
	/// start the hive.
	fn new(config: Option<HiveConfig>) -> Result<Self, TightBeamError>;

	/// Registers an already-started servlet with the hive.
	///
	/// `servlet_type` routes the servlet inside the hive and across the
	/// cluster. Create it with [`ColonyNamespace::servlet`]. The spawner
	/// enables auto-scaling: when the hive needs more instances of this type,
	/// it calls the spawner with a trace collector.
	fn register<S, F, Fut>(&mut self, servlet_type: Urn<'static>, servlet: S, spawner: F) -> Result<(), TightBeamError>
	where
		S: ServletBox + 'static,
		F: Fn(Arc<TraceCollector>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<S, TightBeamError>> + Send + 'static;

	/// Establishes the hive.
	///
	/// The hive seeds intra-hive routing on its [`HiveContext`] and begins the
	/// auto-scaling task. A hive with a `hive_tls` identity also starts the
	/// control server for cluster commands and the re-registration beat.
	/// `trace` records hive-level events. Register every servlet before
	/// calling this.
	fn establish(&mut self, trace: Arc<TraceCollector>) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// The shared intra-hive communication context.
	///
	/// The hive creates it in [`Hive::new`] and fills it with servlet addresses
	/// in [`Hive::establish`]. The same `Arc` tracks each scale change.
	///
	/// - Hand it to [`ServletConfigBuilder::with_hive_context`] so servlet handlers reach siblings.
	/// - Call [`HiveContext::call`], [`HiveContext::open_stream`], or
	///   [`HiveContext::open_duplex`] on it directly.
	///
	/// [`ServletConfigBuilder::with_hive_context`]: crate::colony::servlet::ServletConfigBuilder::with_hive_context
	fn context(&self) -> Arc<dyn HiveContext>;

	/// The address a cluster dials this hive on.
	///
	/// It is [`None`] until [`Hive::establish`], and it stays [`None`] for a
	/// hive configured with no `hive_tls`. Signing a registration needs that
	/// identity, so a hive without one has no address to publish.
	fn addr(&self) -> Option<&Self::Address>;

	/// The addresses of all registered servlets, as pairs of type URN and
	/// address bytes.
	fn servlet_addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)>;

	/// Stops the hive, its control server, its scaling task, every connection
	/// it is serving, and all registered servlets.
	///
	/// Connection handlers are aborted where they stand. Use [`Hive::drain`]
	/// first to let in-flight requests finish.
	fn stop(self);

	/// Waits for the hive's control server to finish. A hive with no control
	/// plane returns at once.
	fn join(self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Registers this hive with the cluster controller at `cluster_addr`.
	///
	/// The hive sends a [`RegisterHiveRequest`] with all servlet addresses.
	/// The cluster then routes work to the servlets and sends management
	/// commands (heartbeat, spawn, and stop) to this hive's control server.
	/// Call this after [`Hive::establish`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::NotEstablished`] -- the hive has no control address
	///   to register, because it is not established or has no `hive_tls`.
	fn register_with_cluster(
		&self,
		cluster_addr: &<Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterHiveResponse, TightBeamError>> + Send;

	/// Drains the hive for a graceful shutdown.
	///
	/// The hive refuses every new command except the heartbeat and stops its
	/// background beats. It then waits until no command is in flight, so an
	/// idle hive drains at once, and the configured drain timeout on the hive
	/// clock is the backstop. Either way the registered servlets stop, and the
	/// hive announces its emptied slate so gateways retire its routes.
	fn drain(&self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Whether the hive has begun to drain.
	fn is_draining(&self) -> bool;
}

/// The TLS material for the hive's control-plane and servlet identity.
///
/// [`HiveConfig`] holds it in an `Arc`, since its validators are trait objects.
#[non_exhaustive]
pub struct HiveTlsConfig {
	/// The certificate and handshake key this hive presents, decoded once by
	/// [`Self::new`].
	identity: ClientIdentity,
	/// The client certificate validators, such as public-key pinning.
	pub validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
}

impl HiveTlsConfig {
	/// Decodes `certificate` and binds it to the key that proves it.
	///
	/// A hive presents one identity everywhere: dialing a gateway, dialing a
	/// sibling servlet, and accepting on its own control plane. One decode
	/// here gives those three one shared certificate, in place of a fresh
	/// decode of the specification on every control-plane event.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `certificate` holds PEM or
	///   DER that does not decode as a certificate.
	pub fn new(
		certificate: crate::crypto::x509::CertificateSpec,
		key: Arc<dyn crate::crypto::key::SigningKeyProvider>,
		validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
	) -> Result<Self, TightBeamError> {
		let identity = ClientIdentity::from_spec(certificate, key)?;

		Ok(Self { identity, validators })
	}

	/// The certificate and handshake key this hive presents.
	///
	/// One identity serves the control plane, sibling dials, and gateway
	/// dials, so all three read it here and cannot disagree.
	pub fn identity(&self) -> &ClientIdentity {
		&self.identity
	}
}

impl core::fmt::Debug for HiveTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HiveTlsConfig")
			.field("identity", &"<ClientIdentity>")
			.field("validators", &format!("[{} validators]", self.validators.len()))
			.finish()
	}
}

/// The reply future of an intra-hive call.
///
/// It resolves to the sibling servlet's complete reply [`Frame`]. A servlet
/// that answers with no frame resolves to
/// [`TightBeamError::MissingResponse`].
pub type CallFuture<'a> = Pin<Box<dyn Future<Output = Result<Frame, TightBeamError>> + Send + 'a>>;

/// The unary reply future of a streamed intra-hive call.
///
/// It resolves once the sibling servlet answers the stream's trailer, and it
/// yields the servlet's complete trailer reply [`Frame`]. That is the same
/// shape that [`HiveContext::call`] and the cluster plane's `open_stream_to`
/// guarantee. A servlet that answers with no frame resolves to
/// [`TightBeamError::MissingResponse`].
pub type StreamResponseFuture = Pin<Box<dyn Future<Output = Result<Frame, TightBeamError>> + Send>>;

/// The future of a streamed intra-hive call's producer half, which is the
/// [`RequestSink`] and the [`StreamResponseFuture`] for the reply.
pub type StreamOpenFuture<'a> =
	Pin<Box<dyn Future<Output = Result<(RequestSink, StreamResponseFuture), TightBeamError>> + Send + 'a>>;

/// The future of a duplex intra-hive call's two halves, which are the
/// [`RequestSink`] for pushing and the [`StreamBody`] that carries the reply.
pub type DuplexOpenFuture<'a> =
	Pin<Box<dyn Future<Output = Result<(RequestSink, StreamBody), TightBeamError>> + Send + 'a>>;

/// The context that servlets in one hive call each other through.
///
/// A call through it skips the cluster, which suits a pattern such as a
/// KeyManager servlet that serves encryption and decryption to its siblings.
///
/// # Envelopes
///
/// Every verb is envelope-preserving: the caller's complete [`Frame`] travels
/// to the sibling unmodified, and the sibling's complete reply frame travels
/// back unmodified.
///
/// Callers compose their own envelope with [`compose!`](crate::compose!), sign
/// it when the sibling is signature-gated, and verify or decode the reply
/// themselves.
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
/// # use tightbeam::testing::{TestKey, TestMessage};
/// # use tightbeam::utils::urn::Urn;
/// # use tightbeam::{decode, Frame, TightBeamError, Version};
/// #
/// # struct EchoSibling;
/// #
/// # impl HiveContext for EchoSibling {
/// #     fn call<'a>(&'a self, _servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a> {
/// #         Box::pin(async move {
/// #             let echoed: TestMessage = decode(frame.message())?;
/// #             let mut reply = FrameBuilder::from(Version::V1).with_id(b"km-reply").with_message(echoed).build()?;
/// #             let provider = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
/// #             reply.sign_with_provider::<Sha3_256, _>(&provider).await?;
/// #             Ok(reply)
/// #         })
/// #     }
/// # }
/// #
/// # fn main() -> Result<(), TightBeamError> {
/// # let runtime = tokio::runtime::Builder::new_current_thread().build().expect("doctest runtime");
/// # runtime.block_on(async {
/// # let ctx = EchoSibling;
/// # let keymanager_urn = tightbeam::urn!("tightbeam", "servlet:keymanager");
/// # let sibling_key = TestKey::insecure_fixed_signing();
/// let caller_provider = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
///
/// let mut request = FrameBuilder::from(Version::V1)
///     .with_id(b"km-decrypt")
///     .with_message(TestMessage { content: "unwrap key 7".into() })
///     .build()?;
/// request.sign_with_provider::<Sha3_256, _>(&caller_provider).await?;
///
/// let reply = ctx.call(&keymanager_urn, request).await?;
///
/// // The reply is the sibling's complete envelope: verify, then decode.
/// reply.verify::<Secp256k1Signature, Sha3_256>(sibling_key.verifying_key())?;
/// let response: TestMessage = decode(reply.message())?;
/// assert_eq!(response.content, "unwrap key 7");
/// # Ok::<(), TightBeamError>(())
/// # })
/// # }
/// ```
pub trait HiveContext: Send + Sync {
	/// Calls a sibling servlet with a complete, caller-built [`Frame`] and
	/// resolves to the servlet's complete reply frame.
	///
	/// `servlet_type` is the target's type URN, such as
	/// `urn:tightbeam::servlet:keymanager`.
	///
	/// - The frame emits as-is, so a `nonrepudiation` signature that the
	///   caller applied stays verifiable at the servlet.
	/// - The reply is the servlet's complete envelope. Verify it with
	///   [`Frame::verify`] before trusting the message body.
	/// - A servlet that answers with no frame resolves to [`TightBeamError::MissingResponse`].
	fn call<'a>(&'a self, servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a>;

	/// Opens a request stream to a sibling servlet.
	///
	/// Push chunks through the [`RequestSink`], then await the returned
	/// response future for the servlet's unary reply. The stream needs a
	/// multiplex-negotiated connection.
	///
	/// The default implementation refuses with `Unimplemented`, so a context
	/// implementation without a mux-capable pool stays valid.
	fn open_stream<'a>(&'a self, servlet_type: &'a Urn<'a>) -> StreamOpenFuture<'a> {
		let _ = servlet_type;
		Box::pin(async { Err(unimplemented_error()) })
	}

	/// Opens a duplex stream to a sibling servlet.
	///
	/// Push request chunks through the [`RequestSink`] while the servlet's
	/// reply chunks arrive on the [`StreamBody`]. The stream needs a
	/// multiplex-negotiated connection.
	///
	/// The default implementation refuses with `Unimplemented`, so a context
	/// implementation without a mux-capable pool stays valid.
	fn open_duplex<'a>(&'a self, servlet_type: &'a Urn<'a>) -> DuplexOpenFuture<'a> {
		let _ = servlet_type;
		Box::pin(async { Err(unimplemented_error()) })
	}
}

/// The auto-scale evaluation cadence and the per-type overrides.
#[derive(Clone, Debug)]
pub struct HiveScalingConfig {
	/// The scaling thresholds for a type that has no per-type override.
	pub default_scale: ServletScaleConfig,
	/// The per-type scaling overrides, keyed by servlet type URN.
	pub overrides: HashMap<Urn<'static>, ServletScaleConfig>,
	/// The minimum wait between scaling evaluation cycles.
	pub cooldown: Duration,
}

impl HiveScalingConfig {
	/// Scaling thresholds that apply to `servlet_type`.
	///
	/// A type with no entry in [`Self::overrides`] scales on
	/// [`Self::default_scale`].
	pub(crate) fn scale_config(&self, servlet_type: &Urn<'_>) -> ServletScaleConfig {
		self.overrides.get(servlet_type).copied().unwrap_or(self.default_scale)
	}
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

/// The settings for manage-path admission, drain, and gateway anti-entropy.
#[derive(Clone)]
pub struct HiveControlConfig {
	/// The utilization threshold that trips manage-path backpressure.
	pub backpressure_threshold: BasisPoints,
	/// The longest wait for a graceful drain before remaining servlets stop.
	pub drain_timeout: Duration,
	/// The anti-entropy interval for re-announcing the servlet slate.
	///
	/// Every interval the hive re-announces its full servlet slate, freshly
	/// signed, to every gateway it has registered with. [`None`] disables
	/// the beat.
	pub reregister_interval: Option<Duration>,
	/// The count of consecutive authentication failures that opens the
	/// cluster circuit breaker.
	pub circuit_breaker_threshold: u8,
	/// The time the circuit breaker stays open before a half-open probe.
	pub circuit_breaker_cooldown: Duration,
	/// The freshness window for signed cluster commands.
	///
	/// Commands whose `Frame.metadata.order` is outside this window, or whose
	/// signature was already seen inside it, are rejected. See [`ReplayGuard`].
	pub command_freshness_window: Duration,
	/// The retry policy for the fan-out of scaling updates to gateways.
	pub notify_retry: Arc<dyn CoreRetryPolicy + Send + Sync>,
}

impl core::fmt::Debug for HiveControlConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut d = f.debug_struct("HiveControlConfig");
		d.field("backpressure_threshold", &self.backpressure_threshold)
			.field("drain_timeout", &self.drain_timeout)
			.field("reregister_interval", &self.reregister_interval)
			.field("circuit_breaker_threshold", &self.circuit_breaker_threshold)
			.field("circuit_breaker_cooldown", &self.circuit_breaker_cooldown);
		d.field("command_freshness_window", &self.command_freshness_window);
		d.field("notify_retry", &"<RetryPolicy>");
		d.finish()
	}
}

impl Default for HiveControlConfig {
	fn default() -> Self {
		Self {
			backpressure_threshold: crate::bps!(DEFAULT_BACKPRESSURE_THRESHOLD_BPS),
			drain_timeout: Duration::from_secs(30),
			reregister_interval: Some(Duration::from_secs(5)),
			circuit_breaker_threshold: 3,
			circuit_breaker_cooldown: Duration::from_secs(30),
			command_freshness_window: Duration::from_millis(crate::constants::DEFAULT_COMMAND_FRESHNESS_WINDOW_MS),
			notify_retry: Arc::new(crate::transport::policy::RestartExponentialBackoff {
				max_attempts: 3,
				scale_factor: 500,
				jitter: Some(Box::new(crate::transport::policy::DecorrelatedJitter)),
			}),
		}
	}
}

/// The settings for the hive lifecycle, scaling, and control-plane security.
///
/// A hive resolves each servlet type to one local instance address.
/// Instance selection across replicas is the cluster gateway's job.
/// See [`ClusterConfig`](crate::colony::cluster::ClusterConfig).
#[derive(Clone)]
pub struct HiveConfig {
	/// The naming scope that resource URNs are validated against. A
	/// registration with a foreign authority or realm fails at
	/// [`Hive::register`].
	pub namespace: ColonyNamespace,
	/// The auto-scale evaluation settings and the per-type overrides.
	pub scaling: HiveScalingConfig,
	/// The manage-path admission, drain, and gateway anti-entropy settings.
	pub control: HiveControlConfig,
	/// The intra-hive servlet pool and the control-server mux advertisement.
	///
	/// A pool connection multiplexes only when the servlet also advertises
	/// through [`ServletConfigBuilder::with_mux_offer`]. The pool reads
	/// [`HiveConfig::clock`].
	///
	/// [`ServletConfigBuilder::with_mux_offer`]: crate::colony::servlet::ServletConfigBuilder::with_mux_offer
	pub pool: PoolConfig,
	/// The trust store for cluster-command authentication and intra-hive
	/// servlet TLS.
	///
	/// When it is [`None`], the hive rejects every cluster command, and an
	/// encrypted servlet call fails closed without a trust anchor.
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
	/// The TLS identity for control-plane signing and encrypted transport.
	/// The hive binds its control plane only when this is set.
	pub hive_tls: Option<Arc<HiveTlsConfig>>,
	/// The clock every freshness, cooldown, drain, scaling, and retry
	/// decision on this hive reads. It defaults to [`SystemClock`].
	pub clock: Arc<dyn Clock>,
}

impl HiveConfig {
	/// The hive identity URN derived from the control address `hive_addr`.
	///
	/// It is [`None`] when the address is not UTF-8 or falls outside
	/// [`Self::namespace`]. A hive that reaches [`None`] withholds its scaling
	/// announcements, which keeps an unusable identity out of the colony.
	pub(crate) fn hive_urn(&self, hive_addr: impl Into<Vec<u8>>) -> Option<Urn<'static>> {
		let bytes: Vec<u8> = hive_addr.into();
		self.namespace.hive_from_bytes(&bytes)
	}
}

impl core::fmt::Debug for HiveConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let mut d = f.debug_struct("HiveConfig");
		d.field("namespace", &self.namespace)
			.field("scaling", &self.scaling)
			.field("control", &self.control)
			.field("pool", &self.pool);
		d.field("trust_store", &self.trust_store.as_ref().map(|_| "<CertificateTrust>"));
		d.field("hive_tls", &self.hive_tls);
		d.field("clock", &self.clock);
		d.finish()
	}
}

impl Default for HiveConfig {
	fn default() -> Self {
		Self {
			namespace: ColonyNamespace::default(),
			scaling: HiveScalingConfig::default(),
			control: HiveControlConfig::default(),
			pool: PoolConfig {
				max_connections: 8,
				idle_timeout: Some(Duration::from_secs(30)),
				..PoolConfig::default()
			},
			trust_store: None,
			hive_tls: None,
			clock: Arc::new(SystemClock),
		}
	}
}

// `macros.rs` defines the `hive!` macro, and `#[macro_export]` places it at
// the crate root.
#[path = "macros.rs"]
mod macros_impl;
