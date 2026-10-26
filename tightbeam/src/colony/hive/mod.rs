//! The hive framework for servlet orchestration.
//!
//! A hive registers servlets, scales them, and answers the cluster's
//! control-plane traffic.
//!
//! - [`Hive`] is the lifecycle trait, and [`HiveRuntime`] implements it.
//! - [`HiveConfig`] carries the scaling, control-plane, and identity settings.
//! - [`HiveContext`] carries calls between sibling servlets in one hive.
//! - [`ServletRegistry`] stores the registered servlets.
//! - [`gates`] holds the hive's admission gates: cluster command security, backpressure, and the peer list.

pub mod error;
pub mod gates;
mod runtime;
mod scaling;

pub use runtime::{HiveContextImpl, HiveRuntime};

pub use scaling::{ScaleConfigRefusal, ScaleCooldowns, ScalingDecision, ScalingMetrics, ServletScaleConfig};

pub use error::HiveError;
pub use gates::{BackpressureGate, CircuitState, ClusterCircuitBreaker};

pub use gates::{BackpressureReport, ClusterSecurityGate, GateLimits, PeerListGate, PeerListMode, ReplayGuard};

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::protocol::{RegisterHiveResponse, ServletInfo};
use crate::colony::urn::ColonyNamespace;
use crate::constants::DEFAULT_BACKPRESSURE_THRESHOLD_BPS;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::KeyPurposes;
use crate::trace::TraceCollector;
use crate::transport::client::{ConnectionBuilder, ConnectionPoolBuilder, PoolConfig};
use crate::transport::multiplex::{RequestSink, StreamBody};
use crate::transport::policy::CoreRetryPolicy;
use crate::transport::state::EncryptionConfig;
use crate::transport::{Protocol, TransportEncryptionConfig};
use crate::urn::Urn;
use crate::utils::time::{Clock, SystemClock};
use crate::utils::BasisPoints;
use crate::{Frame, TightBeamError};

use crate::crypto::x509::store::CertificateTrust;

/// The spawner that a hive calls to add one servlet instance on a scale-up.
///
/// The spawner receives the hive's trace collector and resolves to a new
/// instance of its servlet type that already runs.
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
	/// Returns the servlet's bound address as shared bytes, which the servlet
	/// encodes once when it starts.
	fn addr_bytes(&self) -> Arc<[u8]>;

	/// Stops the servlet and consumes the boxed instance.
	fn stop_boxed(self: Box<Self>);

	/// Returns the [`SignerIdentifier`] that names the certificate the servlet
	/// presents in its handshake (RFC 5652 §5.3), or [`None`] for a servlet
	/// that presents no certificate.
	///
	/// - A hive's registration carries this signer, and a gateway or a
	///   sibling that dials the servlet admits only the certificate it names.
	/// - A servlet that names none has no route: the slate and the hive's sibling routes leave it out.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::cms::signed_data::SignerIdentifier;
	/// use tightbeam::colony::hive::ServletBox;
	/// use tightbeam::crypto::key::Secp256k1KeyProvider;
	/// use tightbeam::crypto::sign::SigningIdentity;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	///
	/// /// A servlet that answers under `identity`.
	/// struct Signed {
	///     identity: SigningIdentity,
	/// }
	///
	/// impl ServletBox for Signed {
	///     fn addr_bytes(&self) -> Arc<[u8]> {
	///         Arc::from(b"127.0.0.1:7000".as_slice())
	///     }
	///
	///     fn stop_boxed(self: Box<Self>) {}
	///
	///     fn signer(&self) -> Option<&SignerIdentifier> {
	///         Some(self.identity.signer_identifier())
	///     }
	/// }
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let certificate = TestCertificate::self_signed(&key);
	/// let provider = Arc::new(Secp256k1KeyProvider::from(key));
	/// let servlet = Signed { identity: SigningIdentity::new(certificate, provider)? };
	/// assert!(servlet.signer().is_some());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn signer(&self) -> Option<&SignerIdentifier>;

	/// Returns the servlet's current utilization, from 0 to 10000 basis points.
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

	/// Returns whether the servlet is healthy and responsive.
	///
	/// An implementation may check its internal state or its connectivity.
	/// The default implementation returns `true`.
	fn is_healthy(&self) -> bool {
		true
	}
}

/// A registered servlet with its spawner function for auto-scaling.
pub struct ServletRegistration {
	/// The live servlet instance that the hive registry stores.
	pub servlet: Box<dyn ServletBox>,
	/// The closure that creates another instance of this servlet type.
	pub spawner: SpawnerFn,
	/// The type URN that identifies this servlet kind for routing and scaling.
	pub servlet_type: Urn<'static>,
}

impl ServletRegistration {
	/// Returns where this registration's servlet sits: its instance URN, its
	/// address, and its signer. The instance URN derives once from the type
	/// and the address.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UrnValidationError`] -- the servlet's address is not a valid instance locator.
	pub(crate) fn placement(&self) -> Result<ServletPlacement, TightBeamError> {
		let address = self.servlet.addr_bytes();
		let instance = self.servlet_type.instance_urn(address.as_ref())?;
		let signer = self.servlet.signer().cloned().map(Arc::new);

		Ok(ServletPlacement { instance, address, signer })
	}

	/// Returns the slate entry of this registration: the instance, the address
	/// that reaches it, and the signer of the certificate it presents.
	///
	/// It returns [`None`] for an address that is not a valid instance locator,
	/// or for a servlet that names no signer, as
	/// [`ServletPlacement::into_servlet_info`] states.
	pub(crate) fn servlet_info(&self) -> Option<ServletInfo> {
		self.placement().ok()?.into_servlet_info()
	}
}

/// Where one registered servlet sits: its instance URN, the address that
/// reaches it, and the signer of the certificate it presents.
pub(crate) struct ServletPlacement {
	/// The instance URN, derived from the servlet type and the address.
	pub(crate) instance: Urn<'static>,
	/// The address the servlet answers at.
	pub(crate) address: Arc<[u8]>,
	/// The signer of the certificate the servlet presents, or [`None`] for a
	/// servlet that presents none.
	pub(crate) signer: Option<Arc<SignerIdentifier>>,
}

impl ServletPlacement {
	/// Returns the slate entry of this instance, or [`None`] for a servlet that
	/// names no signer.
	///
	/// A gateway admits a servlet's answer by that signer alone, so a servlet
	/// that names none has no route to offer.
	pub(crate) fn into_servlet_info(self) -> Option<ServletInfo> {
		let signer = self.signer?;
		let signer = Arc::try_unwrap(signer).unwrap_or_else(|shared| (*shared).clone());
		let address = self.address.to_vec();

		Some(ServletInfo { servlet_id: self.instance, address, signer })
	}
}

/// A registration a [`ServletRegistry`] refused, handed back to its caller.
///
/// The registration travels with the error, so the caller holds the servlet
/// and stops it the one way [`ServletBox::stop_boxed`] names.
pub struct RefusedRegistration {
	/// Why the registry refused the insert.
	pub error: TightBeamError,
	/// The registration the registry refused. Its servlet runs until the
	/// caller stops it.
	pub registration: ServletRegistration,
}

impl RefusedRegistration {
	/// Stops the servlet of the refused registration and returns the refusal.
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
	/// - A registration under a key the registry already holds replaces the one there.
	/// - The implementation MUST stop the servlet of the replaced registration
	///   through [`ServletBox::stop_boxed`], because no stop or drain of the
	///   hive reaches a servlet once the registry drops its registration.
	/// - [`HashMapRegistry`] stops the replaced servlet once the registry lock is free.
	///
	/// # Errors
	///
	/// - [`RefusedRegistration`] -- the registry refused the registration,
	///   which comes back so the caller can stop its servlet. It is boxed, so
	///   the success path pays one pointer for it.
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

	/// Returns the current servlet slate, one entry per registered instance.
	///
	/// The slate skips a registration whose address is not a valid instance
	/// locator, or whose servlet names no signer, so such an entry drops its
	/// own row and the rest of the slate stands.
	fn slate(&self) -> Vec<ServletInfo> {
		let mut list = Vec::new();
		self.for_each(|_key, reg| list.extend(reg.servlet_info()));

		list
	}

	/// Returns the number of registered servlets.
	fn count(&self) -> usize;

	/// Returns every servlet address, as a pair of type URN and address bytes.
	fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)>;

	/// Removes and returns every registration, so that a stop or a drain can
	/// stop each servlet.
	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)>;

	/// Returns every registration key, which a scale-down reads to pick an
	/// instance.
	fn keys(&self) -> Vec<Vec<u8>>;
}

/// The shipped [`ServletRegistry`]: one [`HashMap`] behind a mutex.
///
/// Every write under the lock is one `HashMap` insert, remove, or drain,
/// so a thread that panicked while it held the guard left a whole map
/// behind it. The registry therefore recovers a poisoned lock and continues
/// to serve, so every method answers.
pub struct HashMapRegistry {
	inner: Mutex<HashMap<Vec<u8>, ServletRegistration>>,
}

impl Default for HashMapRegistry {
	fn default() -> Self {
		Self { inner: Mutex::new(HashMap::new()) }
	}
}

impl HashMapRegistry {
	/// Returns the spawner of every registered servlet type.
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

	/// Locks the map. It recovers a poisoned lock, because every write under
	/// the guard leaves a whole map.
	fn map(&self) -> MutexGuard<'_, HashMap<Vec<u8>, ServletRegistration>> {
		self.inner.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

impl ServletRegistry for HashMapRegistry {
	/// Takes every registration, so the result is always `Ok`.
	///
	/// A registration under a key the registry holds replaces the one there,
	/// and the replaced servlet stops through [`ServletBox::stop_boxed`] once
	/// the registry lock is free.
	fn insert(
		&self,
		key: impl Into<Vec<u8>>,
		registration: ServletRegistration,
	) -> Result<(), Box<RefusedRegistration>> {
		let key: Vec<u8> = key.into();
		let replaced = self.map().insert(key, registration);
		if let Some(previous) = replaced {
			previous.servlet.stop_boxed();
		}

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
/// let capture = CaptureServlet::start(Arc::clone(&trace), ServletConfig::cleartext()).await?;
///
/// // 2. Create hive
/// let mut hive = PaymentHive::new(Some(hive_conf))?;
///
/// // 3. Register with spawners for auto-scaling (types named by URN)
/// let ns = ColonyNamespace::default();
/// hive.register(ns.servlet("auth")?, auth, |t| AuthServlet::start(t, auth_conf.clone()))?;
/// hive.register(ns.servlet("capture")?, capture, |t| CaptureServlet::start(t, ServletConfig::cleartext()))?;
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
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the implementation cannot build a hive from
	///   `config`. [`HiveRuntime`] always returns `Ok`.
	fn new(config: Option<HiveConfig>) -> Result<Self, TightBeamError>;

	/// Registers an already-started servlet with the hive.
	///
	/// `servlet_type` routes the servlet inside the hive and across the
	/// cluster. Create it with [`ColonyNamespace::servlet`]. The spawner
	/// enables auto-scaling: when the hive needs more instances of this type,
	/// it calls the spawner with a trace collector.
	///
	/// # Errors
	///
	/// - [`TightBeamError::AlreadyEstablished`] -- the hive is established, so its registration is closed.
	/// - [`TightBeamError::UrnValidationError`] -- `servlet_type` falls outside
	///   the hive's namespace or names an instance, or the servlet's address is
	///   not UTF-8.
	/// - [`TightBeamError`] -- the [`ServletRegistry`] refuses the insert, and the servlet stops.
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
	/// `trace` records hive-level events. Register every servlet first.
	///
	/// # Errors
	///
	/// - [`TightBeamError::AlreadyEstablished`] -- the hive is already established.
	/// - [`TightBeamError`] -- the control plane fails to bind, as the protocol's error converts.
	/// - [`TightBeamError`] -- `trace` refuses the [`HIVE_ESTABLISHED`] event,
	///   the fault the `testing-fault` feature injects. The hive stays
	///   provisional, so a later establish can succeed.
	///
	/// [`HIVE_ESTABLISHED`]: crate::instrumentation::events::HIVE_ESTABLISHED
	fn establish(&mut self, trace: Arc<TraceCollector>) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Returns the shared intra-hive communication context.
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

	/// Returns the address a cluster dials this hive on.
	///
	/// It is [`None`] until [`Hive::establish`], and it stays [`None`] for a
	/// hive configured with no `hive_tls`. A signed registration needs that
	/// identity, so a hive without one has no address to publish.
	fn addr(&self) -> Option<&Self::Address>;

	/// Returns the addresses of all registered servlets, as pairs of type URN
	/// and address bytes.
	fn servlet_addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)>;

	/// Stops the hive, its control server, its scaling task, every connection
	/// it serves, and all registered servlets.
	///
	/// The stop aborts connection handlers where they stand. Use
	/// [`Hive::drain`] first to let in-flight requests finish.
	fn stop(self);

	/// Waits for the hive's control server to finish. A hive with no control
	/// plane returns at once.
	///
	/// # Errors
	///
	/// - [`TightBeamError::JoinError`] -- the control server task panicked, or an abort ended it.
	fn join(self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Registers this hive with the cluster controller at `cluster_addr`.
	///
	/// The hive sends a [`RegisterHiveRequest`] that carries its servlet slate.
	/// The cluster then routes work to the servlets and sends management
	/// commands (heartbeat, spawn, and stop) to this hive's control server.
	/// Call this after [`Hive::establish`].
	///
	/// [`RegisterHiveRequest`]: crate::colony::protocol::RegisterHiveRequest
	///
	/// # Errors
	///
	/// - [`TightBeamError::NotEstablished`] -- the hive has no control address
	///   to register, because it is not established or has no `hive_tls`.
	/// - [`TightBeamError::MissingResponse`] -- the cluster answers with no frame.
	/// - [`TightBeamError`] -- the dial, the frame's signature, the exchange,
	///   or the decode of the answer fails.
	fn register_with_cluster(
		&self,
		cluster_addr: &<Self::Protocol as Protocol>::Address,
	) -> impl Future<Output = Result<RegisterHiveResponse, TightBeamError>> + Send;

	/// Drains the in-flight commands of the hive, then stops its servlets.
	///
	/// The hive refuses every new command except the heartbeat and stops its
	/// background beats. It then waits until no command is in flight, so an
	/// idle hive drains at once, and the configured drain timeout on the hive
	/// clock is the backstop. Either way the registered servlets stop, and the
	/// hive announces its emptied slate so gateways retire its routes.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the implementation fails to drain. [`HiveRuntime`] always returns `Ok`.
	fn drain(&self) -> impl Future<Output = Result<(), TightBeamError>> + Send;

	/// Returns whether the hive began to drain.
	fn is_draining(&self) -> bool;
}

/// The TLS material for the hive's control-plane and servlet identity.
///
/// [`HiveConfig`] holds it in an `Arc`, because its validators are trait
/// objects.
#[non_exhaustive]
pub struct HiveTlsConfig {
	/// The certificate and handshake key this hive presents, from
	/// [`Self::new`] or [`Self::from_identity`].
	identity: SigningIdentity,
	/// The key purpose of each role the identity serves.
	/// [`Self::from_identity`] holds the identity's certificate to the signer
	/// purpose, and the control plane and the gateway dials hold it to the
	/// server and client purposes.
	key_purposes: KeyPurposes,
	/// The client certificate validators, such as public-key pinning.
	pub validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
}

impl HiveTlsConfig {
	/// Decodes `certificate`, binds it to the key that proves it, and installs
	/// the identity under [`KeyPurposes::HOUSE`].
	///
	/// A hive presents one identity everywhere: to dial a gateway, to dial a
	/// sibling servlet, and to accept on its own control plane. One decode
	/// here gives those three roles one shared certificate, and every
	/// control-plane event reads that certificate.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- `certificate` holds PEM or
	///   DER that does not decode as a certificate.
	/// - [`TightBeamError::CertificateValidationError`] -- the certificate
	///   fails a check of [`Self::from_identity`] under
	///   [`KeyPurposes::HOUSE`].
	/// - [`TightBeamError`] -- the errors of [`SigningIdentity::new`], as their conversion names them.
	pub fn new(
		certificate: crate::crypto::x509::CertificateSpec,
		key: Arc<dyn crate::crypto::key::SigningKeyProvider>,
		validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
	) -> Result<Self, TightBeamError> {
		let identity = SigningIdentity::from_spec(certificate, key)?;
		Ok(Self::from_identity(identity, validators, KeyPurposes::HOUSE)?)
	}

	/// Presents `identity` under the key purpose of each role that
	/// `key_purposes` names, and holds the client certificate `validators`.
	/// [`KeyPurposes::HOUSE`] holds the house purposes.
	///
	/// - The identity signs this hive's registrations, so its certificate MUST
	///   name `key_purposes.signer` or `anyExtendedKeyUsage`, or carry no
	///   `extendedKeyUsage` (RFC 5280 §4.2.1.12).
	/// - The control plane and the gateway dials hold the certificate to the server and client purposes.
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
	/// use tightbeam::colony::hive::HiveTlsConfig;
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
	/// let tls = HiveTlsConfig::from_identity(identity, Vec::new(), purposes)?;
	/// assert!(tls.validators.is_empty());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn from_identity(
		identity: SigningIdentity,
		validators: Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
		key_purposes: KeyPurposes,
	) -> Result<Self, CertificateValidationError> {
		identity.certificate().require_purpose(key_purposes.signer)?;

		Ok(Self { identity, key_purposes, validators })
	}

	/// Returns the certificate and handshake key this hive presents.
	///
	/// One identity serves the control plane, sibling dials, and gateway
	/// dials, so all three read the same identity here.
	pub fn identity(&self) -> &SigningIdentity {
		&self.identity
	}

	/// Builds the encryption config of the control plane: this identity, the
	/// client [`Self::validators`] and `command_trust`, and the key purposes
	/// [`Self::from_identity`] installed.
	pub(crate) fn accept_encryption<C: CryptoProvider>(
		&self,
		command_trust: Option<Arc<dyn CertificateValidation>>,
	) -> TransportEncryptionConfig<C> {
		let encryption = TransportEncryptionConfig::new(self.identity.clone());
		let validators = self.validators.iter().map(Arc::clone).chain(command_trust);

		let encryption = encryption.with_client_validators(validators);
		encryption.with_key_purposes(self.key_purposes)
	}

	/// Configures `encryption` to dial a gateway under this identity: it
	/// presents the identity as its client certificate, and holds both sides
	/// to the key purposes [`Self::from_identity`] installed.
	pub(crate) fn outbound<C: CryptoProvider>(&self, encryption: &mut EncryptionConfig<C>) {
		encryption.client_identity = Some(self.identity.clone());
		encryption.key_purposes = self.key_purposes;
	}
}

impl core::fmt::Debug for HiveTlsConfig {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("HiveTlsConfig")
			.field("identity", &self.identity)
			.field("key_purposes", &self.key_purposes)
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
/// [`RequestSink`] that pushes requests and the [`StreamBody`] that carries
/// the reply.
pub type DuplexOpenFuture<'a> =
	Pin<Box<dyn Future<Output = Result<(RequestSink, StreamBody), TightBeamError>> + Send + 'a>>;

/// The context that servlets in one hive call each other through.
///
/// A call through it skips the cluster, which suits a pattern such as a
/// KeyManager servlet that serves encryption and decryption to its siblings.
///
/// # Envelopes
///
/// Every verb preserves the envelope: the caller's complete [`Frame`] travels
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
/// # use tightbeam::builder::{frame::FrameBuilder, TypeBuilder};
/// # use tightbeam::colony::hive::{CallFuture, HiveContext};
/// # use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// # use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
/// # use tightbeam::testing::{TestCertificate, TestIdentity, TestKey, TestMessage};
/// # use tightbeam::urn::Urn;
/// # use tightbeam::{decode, Frame, TightBeamError, Version};
/// #
/// # struct EchoSibling;
/// #
/// # impl HiveContext for EchoSibling {
/// #     fn call<'a>(&'a self, _servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a> {
/// #         Box::pin(async move {
/// #             let echoed: TestMessage = decode(frame.message())?;
/// #             let mut reply = FrameBuilder::from(Version::V1).with_id(b"km-reply").with_message(echoed).build()?;
/// #             let sibling = TestIdentity::insecure_fixed();
/// #             reply.sign_with_provider(&sibling).await?;
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
/// # let sibling_certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// # let purpose = KeyPurposes::HOUSE.signer;
/// # let sibling = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(sibling_certificate, purpose)?;
/// let caller = TestIdentity::insecure_fixed();
///
/// let mut request = FrameBuilder::from(Version::V1)
///     .with_id(b"km-decrypt")
///     .with_message(TestMessage { content: "unwrap key 7".into() })
///     .build()?;
/// request.sign_with_provider(&caller).await?;
///
/// let reply = ctx.call(&keymanager_urn, request).await?;
///
/// // The reply is the sibling's complete envelope: verify, then decode.
/// reply.verify(&sibling)?;
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
	/// - The context emits the frame as-is, so a `nonrepudiation` signature
	///   that the caller applied stays verifiable at the servlet.
	/// - The reply is the servlet's complete envelope. Verify it with
	///   [`Frame::verify`] before you trust the message body.
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
		Box::pin(async { Err(TightBeamError::unimplemented()) })
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
		Box::pin(async { Err(TightBeamError::unimplemented()) })
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
	/// Returns the scaling thresholds that apply to `servlet_type`.
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
	/// The longest wait of a drain for in-flight commands, after which the
	/// registered servlets stop.
	pub drain_timeout: Duration,
	/// The anti-entropy interval of the servlet slate re-announce.
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
	/// The hive rejects a command whose `Frame.metadata.order` is outside this
	/// window, or whose signature it already saw inside it. See
	/// [`ReplayGuard`].
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
	/// The naming scope that the hive validates resource URNs against. A
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
	/// encrypted servlet call fails closed without a trust anchor. When it is
	/// set, the control plane demands a client certificate that it validates.
	pub trust_store: Option<Arc<dyn CertificateTrust>>,
	/// The TLS identity for control-plane signing and encrypted transport.
	/// The hive binds its control plane only when this is set.
	pub hive_tls: Option<Arc<HiveTlsConfig>>,
	/// The clock every freshness, cooldown, drain, scaling, and retry
	/// decision on this hive reads. It defaults to [`SystemClock`].
	pub clock: Arc<dyn Clock>,
}

impl HiveConfig {
	/// Returns the encryption config of the control plane, or [`None`] when
	/// the hive binds no control plane.
	///
	/// A hive with a [`Self::trust_store`] authenticates each cluster command
	/// against the peer its handshake proves, so the plane demands a client
	/// certificate that the store validates, beside the
	/// [`HiveTlsConfig::validators`].
	pub(crate) fn control_encryption<C: CryptoProvider>(&self) -> Option<TransportEncryptionConfig<C>> {
		let hive_tls = self.hive_tls.as_ref()?;
		let trust_store = self.trust_store.as_ref().map(Arc::clone);
		let command_trust = trust_store.map(|store| store as Arc<dyn CertificateValidation>);

		Some(hive_tls.accept_encryption(command_trust))
	}

	/// Configures `builder` for the hive's calls to its own servlets: each dial
	/// validates the servlet's certificate with [`Self::trust_store`], when the
	/// hive has one.
	pub(crate) fn sibling_dials<P: Protocol>(&self, builder: ConnectionPoolBuilder<P>) -> ConnectionPoolBuilder<P> {
		match self.trust_store.as_ref() {
			Some(store) => builder.with_trust_store(Arc::clone(store)),
			None => builder,
		}
	}

	/// Returns the encryption config of a dial to a gateway.
	///
	/// - The dial validates the gateway's certificate with [`Self::trust_store`], when the hive has one.
	/// - It presents the identity of [`Self::hive_tls`], under its key purposes, when the hive has one.
	pub(crate) fn gateway_dial<C: CryptoProvider>(&self) -> EncryptionConfig<C> {
		let trust_store = self.trust_store.as_ref().map(Arc::clone);
		let mut encryption = EncryptionConfig { trust_store, ..EncryptionConfig::unconfigured() };
		if let Some(hive_tls) = &self.hive_tls {
			hive_tls.outbound(&mut encryption);
		}

		encryption
	}

	/// Derives the hive identity URN from the control address `hive_addr`.
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::error::CertificateValidationError::ExcludedKeyPurpose;
	use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
	use crate::crypto::x509::CertificateSpec;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::oid::db::rfc5280::ANY_EXTENDED_KEY_USAGE;
	use crate::tb_cases;
	use crate::testing::{TestCertificate, TestKey};

	/// A signer purpose of an implementor's own, outside the house purposes.
	const OWN_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.12");

	/// Builds an identity on the fixed test key whose certificate names
	/// `purpose` as its one key purpose, or carries no `extendedKeyUsage` for
	/// `None`.
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

	// The identity signs the hive's registrations, so the install holds it
	// to the signer purpose (RFC 5280 §4.2.1.12). A certificate that names
	// the signer purpose, any purpose, or no purpose installs.
	tb_cases! {
		fn from_identity_admits_an_identity_for_the_signer(
			purpose: Option<ObjectIdentifier>
		) -> Result<(), TightBeamError> {
			HiveTlsConfig::from_identity(identity_naming(purpose), Vec::new(), KeyPurposes::HOUSE)?;

			Ok(())
		}
		cases {
			an_identity_for_the_signer => Some(KeyPurposes::HOUSE.signer),
			an_identity_for_any_purpose => Some(ANY_EXTENDED_KEY_USAGE),
			an_identity_with_no_key_purpose => None,
		}
	}

	// The install refuses a certificate whose key purposes omit the signer.
	tb_cases! {
		fn from_identity_refuses_an_identity_outside_the_signer(purpose: ObjectIdentifier) {
			let identity = identity_naming(Some(purpose));

			let installed = HiveTlsConfig::from_identity(identity, Vec::new(), KeyPurposes::HOUSE);

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

		HiveTlsConfig::from_identity(identity_naming(Some(OWN_SIGNER)), Vec::new(), key_purposes)?;

		Ok(())
	}

	// The house purposes refuse an identity that names an implementor's own
	// signer purpose alone.
	#[test]
	fn from_identity_refuses_an_own_signer_purpose_under_the_house_purposes() {
		let identity = identity_naming(Some(OWN_SIGNER));

		let installed = HiveTlsConfig::from_identity(identity, Vec::new(), KeyPurposes::HOUSE);

		let excluded = matches!(installed, Err(ExcludedKeyPurpose));
		assert!(excluded);
	}

	/// A servlet at a fixed locator that names `signer` as the identity it
	/// answers under.
	struct SignerProbe {
		signer: Option<SignerIdentifier>,
	}

	impl ServletBox for SignerProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7003".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {}

		fn signer(&self) -> Option<&SignerIdentifier> {
			self.signer.as_ref()
		}
	}

	/// Returns the spawner of a [`SignerProbe`] that names no signer.
	fn probe_spawner() -> SpawnerFn {
		Arc::new(|_| Box::pin(async { Ok(Box::new(SignerProbe { signer: None }) as Box<dyn ServletBox>) }))
	}

	/// Builds a registry with one [`SignerProbe`] that names `signer`.
	fn registry_holding(signer: Option<SignerIdentifier>) -> HashMapRegistry {
		let registry = HashMapRegistry::default();
		let namespace = ColonyNamespace::default();
		let servlet_type = namespace.servlet("echo").expect("test names satisfy the mint grammar");
		let spawner = probe_spawner();
		let registration = ServletRegistration { servlet: Box::new(SignerProbe { signer }), spawner, servlet_type };

		let inserted = registry.insert(b"echo".to_vec(), registration);
		assert!(inserted.is_ok(), "the map registry takes every registration");

		registry
	}

	// The slate carries the signer each servlet names, and leaves out a
	// servlet that names none, which no gateway dial could admit (CWE-346).
	tb_cases! {
		fn the_slate_carries_the_signer_each_servlet_names(
			(signer, carried): (Option<SignerIdentifier>, Vec<SignerIdentifier>)
		) {
			let registry = registry_holding(signer);

			let slate = registry.slate();

			let signers: Vec<SignerIdentifier> = slate.into_iter().map(|info| info.signer).collect();
			assert_eq!(signers, carried);
		}
		cases {
			a_signed_servlet_joins => (Some(ServletInfo::fixture_signer()), vec![ServletInfo::fixture_signer()]),
			an_unsigned_servlet_is_left_out => (None, Vec::new()),
		}
	}

	/// The key purposes that put the house client purpose in the server role.
	const SWAPPED_SERVER: KeyPurposes = KeyPurposes { server: KeyPurposes::HOUSE.client, ..KeyPurposes::HOUSE };

	// A hive with a trust store authenticates each command against the peer
	// its handshake proves, so its control plane demands a client
	// certificate when its TLS config names no validator.
	#[test]
	fn a_hive_that_authenticates_commands_demands_a_client_certificate() -> Result<(), TightBeamError> {
		let tls = HiveTlsConfig::from_identity(identity_naming(None), Vec::new(), KeyPurposes::HOUSE)?;
		let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
		let store: Arc<dyn CertificateTrust> = Arc::new(builder.build());
		let config = HiveConfig { trust_store: Some(store), hive_tls: Some(Arc::new(tls)), ..Default::default() };

		let accept = config.control_encryption::<DefaultCryptoProvider>();
		assert!(accept.is_some_and(|accept| accept.peer_authentication.requires_certificate()));
		Ok(())
	}

	// The control plane holds the hive's identity to the purposes its TLS
	// config names, so the transport and the hive read one purpose set.
	#[test]
	fn the_control_plane_takes_the_configured_key_purposes() -> Result<(), TightBeamError> {
		let tls = HiveTlsConfig::from_identity(identity_naming(None), Vec::new(), SWAPPED_SERVER)?;
		let accept = tls.accept_encryption::<DefaultCryptoProvider>(None);
		assert_eq!(accept.key_purposes, SWAPPED_SERVER);
		Ok(())
	}

	// A gateway dial presents the hive's identity under the purposes its TLS
	// config names.
	#[test]
	fn a_gateway_dial_takes_the_configured_key_purposes() -> Result<(), TightBeamError> {
		let tls = HiveTlsConfig::from_identity(identity_naming(None), Vec::new(), SWAPPED_SERVER)?;
		let mut encryption = EncryptionConfig::<DefaultCryptoProvider>::unconfigured();

		tls.outbound(&mut encryption);

		assert_eq!(encryption.key_purposes, SWAPPED_SERVER);
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

		let refused = HiveTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)), Vec::new());
		let excluded = matches!(refused, Err(TightBeamError::CertificateValidationError(ExcludedKeyPurpose)));
		assert!(excluded);
		Ok(())
	}
}
