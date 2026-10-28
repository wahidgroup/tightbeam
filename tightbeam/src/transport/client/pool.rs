//! The connection pool of the transport layer.

use core::hash::Hash;
use core::marker::PhantomData;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

#[cfg(all(pooled_mux, feature = "instrument"))]
use std::borrow::Cow;
#[cfg(feature = "std")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "std")]
use std::sync::{Arc, RwLock, RwLockWriteGuard};

use crate::constants::DEFAULT_MAX_POOL_CONNECTIONS;
use crate::crypto::profiles::CryptoProvider;
use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::instrumentation::events;
use crate::transport::client::{ConnectionBuilder, GenericClient};
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::handshake::HandshakeProtocolKind;
use crate::transport::policy::PolicyConfig;
use crate::transport::protocols::{PersistentConnection, Protocol};
use crate::transport::state::{DialableEncryption, EncryptionConfig, Negotiation};
use crate::transport::MessageCollector;
use crate::transport::MessageEmitter;
use crate::transport::{EndpointConfig, TransportResult};
use crate::urn::Urn;
use crate::utils::time::{Clock, MonotonicInstant};
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::KeyPurposes;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::ReceiptApprover;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::ProvisionedTrust;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::ValidatorChain;
#[cfg(host_clock)]
use crate::utils::time::SystemClock;

/// Gates each item it wraps behind the `pooled_mux` alias of `build.rs`.
/// Multiplexed pooling needs the mux engine, the service module's connector,
/// an encryption handshake, and a tokio executor for the driver tasks.
macro_rules! pooled_mux {
	($($item:item)*) => {
		$(
			#[cfg(pooled_mux)]
			$item
		)*
	};
}

pooled_mux! {
	use core::future::Future;
	use core::sync::atomic::AtomicU64;
	use std::sync::{Mutex, PoisonError};

	use crate::crypto::x509::error::CertificateValidationError;
	use crate::runtime::rt;
	use crate::utils::marker::MaybeSend;
	use crate::transport::handshake::receipt::StoredReceipt;
	use crate::transport::multiplex::{
		MuxCapable, MuxConnector, MuxDrivers, MuxHandle, MuxTransport, RequestSink, SpawnedMux, StreamBody,
		CONNECTOR_ROLE,
	};

	#[cfg(feature = "colony")]
	use crate::transport::multiplex::StreamRoute;
}

/// The limits and multiplexing policy of a [`ConnectionPool`].
#[derive(Clone, Debug)]
pub struct PoolConfig {
	/// The idle time after which the pool drops a pooled connection, exclusive
	/// or multiplexed. `None` keeps idle connections until another reason
	/// evicts them.
	pub idle_timeout: Option<Duration>,
	/// The cap on live connections across all destinations,
	/// [`DEFAULT_MAX_POOL_CONNECTIONS`] by default.
	pub max_connections: NonZeroUsize,
	/// The multiplexing offer that pooled dials advertise.
	///
	/// When set, [`ConnectionPool::connect`] reuses a pooled multiplexed
	/// connection to a destination until its stream caps fill. Two concurrent
	/// first dials to one destination can each open one, within
	/// `max_connections`. Every dial shares the offer through its `Arc`, and
	/// the handshake clones it once into the orchestrator.
	pub mux_offer: Option<Arc<TransportOffer>>,
}

impl Default for PoolConfig {
	fn default() -> Self {
		Self {
			idle_timeout: None,
			max_connections: DEFAULT_MAX_POOL_CONNECTIONS,
			mux_offer: None,
		}
	}
}

#[derive(Clone)]
/// The shared encryption provisioning that every pooled connection reuses.
struct PoolTlsConfig<C: CryptoProvider> {
	/// Every dial from this pool starts with this provisioning.
	encryption: EncryptionConfig<C>,
}

impl<C: CryptoProvider> PoolTlsConfig<C> {
	fn unconfigured() -> Self {
		Self { encryption: EncryptionConfig::unconfigured() }
	}

	fn set_trust_store(&mut self, store: Arc<dyn CertificateTrust>) {
		self.encryption.trust_store = Some(store);
	}

	#[cfg(feature = "transport-cms")]
	fn set_cms_server(&mut self, trust: ProvisionedTrust) {
		self.encryption.cms_server = Some(trust);
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn set_key_purposes(&mut self, key_purposes: KeyPurposes) {
		self.encryption.key_purposes = key_purposes;
	}

	/// Answers this provisioning once, when the builder builds the pool: the
	/// dialer rule, and the key purpose of the client identity's role.
	fn answer(self) -> PoolProvisioning<C> {
		// A refused provisioning keeps its configuration, and each dial
		// answers it again to return the refusal, so the error drops here.
		match DialableEncryption::new(self.encryption.clone()) {
			Ok(answered) => PoolProvisioning::Answered(answered),
			Err(_) => PoolProvisioning::Refused(self.encryption),
		}
	}
}

/// The provisioning of a built pool, answered once.
#[derive(Clone)]
enum PoolProvisioning<C: CryptoProvider> {
	/// The provisioning that answered, which every dial clones.
	Answered(DialableEncryption<C>),
	/// The provisioning that [`DialableEncryption::new`] refused, which each
	/// dial answers again.
	Refused(EncryptionConfig<C>),
}

impl<C: CryptoProvider> PoolProvisioning<C> {
	/// Returns the endpoint that one dial from this pool starts from, over this
	/// provisioning and `clock`.
	///
	/// A dial's clone of the answered provisioning shares its `Arc` handles.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- the pool
	///   authenticates no peer and did not name cleartext, or it sets a server
	///   policy with no trust in a server, with or without cleartext.
	/// - [`TransportError::HandshakeError`] -- the client identity names a key
	///   purpose other than the client's, or its extended key usage fails to
	///   decode.
	fn endpoint(&self, clock: &Arc<dyn Clock>) -> TransportResult<EndpointConfig<C>> {
		let encryption = match self {
			Self::Answered(answered) => answered.clone(),
			Self::Refused(encryption) => DialableEncryption::new(encryption.clone())?,
		};

		Ok(EndpointConfig::new(encryption, Arc::clone(clock)))
	}
}

/// The builder of a configured [`ConnectionPool`].
pub struct ConnectionPoolBuilder<P: Protocol> {
	config: PoolConfig,
	clock: Arc<dyn Clock>,
	timeout: Option<Duration>,
	tls: PoolTlsConfig<P::CryptoProvider>,
	negotiation: Negotiation,
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
	_phantom: PhantomData<P>,
}

impl<P: Protocol> ConnectionPoolBuilder<P> {
	/// Returns a builder for a pool configured by `config` that measures idle
	/// time, deadlines, and backoff against `clock`.
	pub fn new(config: PoolConfig, clock: Arc<dyn Clock>) -> Self {
		Self {
			config,
			clock,
			timeout: None,
			tls: PoolTlsConfig::unconfigured(),
			negotiation: Negotiation::default(),
			#[cfg(feature = "instrument")]
			trace: None,
			_phantom: PhantomData,
		}
	}
}

/// The default builder exists where the standard library's clocks work. A
/// pool on `wasm32-unknown-unknown`, which has no [`SystemClock`], names its
/// clock through [`ConnectionPoolBuilder::new`].
#[cfg(host_clock)]
impl<P: Protocol> Default for ConnectionPoolBuilder<P> {
	fn default() -> Self {
		Self::new(PoolConfig::default(), Arc::new(SystemClock))
	}
}

impl<P: Protocol> ConnectionPoolBuilder<P> {
	/// Runs this pool's connections with no peer authentication.
	///
	/// Every dial carries the decision. Without it, a pool that holds no trust
	/// in a server fails each connect with
	/// [`TransportError::PeerAuthenticationUnconfigured`] before it opens a
	/// socket.
	pub fn allow_cleartext(mut self) -> Self {
		self.tls.encryption.allow_cleartext = true;
		self
	}

	/// Replaces the pool configuration.
	pub fn with_config(mut self, config: PoolConfig) -> Self {
		self.config = config;
		self
	}

	/// Replaces the clock that the pool measures idle time, deadlines, and
	/// backoff against.
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.clock = clock;
		self
	}

	/// Attaches the production instrumentation collector, the single
	/// client-side entry point. The pool emits its own lifecycle events and
	/// passes the collector to every dialed transport.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// Provisions the trust in the CMS server. The caller builds it once over
	/// its pinned key-agreement certificate, and every pooled connection
	/// shares it. The opening seals to it, and its store admits the signing
	/// certificate the reply carries.
	#[cfg(feature = "transport-cms")]
	pub fn with_cms_server(mut self, trust: ProvisionedTrust) -> Self {
		self.tls.set_cms_server(trust);
		self
	}

	/// Sets the key purpose of each role for every pooled connection: the
	/// purpose the server's certificates carry, and the purpose the client
	/// identity carries. The default is [`KeyPurposes::HOUSE`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn with_key_purposes(mut self, key_purposes: KeyPurposes) -> Self {
		self.tls.set_key_purposes(key_purposes);
		self
	}

	/// Sets the server policy of every pooled connection. Each validator runs
	/// on the server's identity certificate under either flow
	/// ([`ClientConfig::with_server_policy`]). An empty set sets no policy.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	/// use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::KeyCurves;
	/// use tightbeam::transport::client::{ConnectionBuilder, ConnectionPool};
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// let trust = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	/// let store = Arc::new(trust.build());
	/// let builder = ConnectionPool::<TokioListener>::builder().with_trust_store(store);
	///
	/// // Every pooled dial runs the policy on the server the store admits.
	/// let expiry: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
	/// let _builder = builder.with_server_policy([expiry]);
	/// ```
	///
	/// [`ClientConfig::with_server_policy`]: crate::transport::handshake::ClientConfig::with_server_policy
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn with_server_policy(mut self, validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Self {
		self.tls.encryption.server_policy = ValidatorChain::new(validators);
		self
	}

	/// Selects the handshake protocol that every pooled connection runs.
	pub fn with_handshake_protocol(mut self, kind: HandshakeProtocolKind) -> Self {
		self.negotiation.select_handshake(kind);
		self
	}

	/// Installs the receipt approver for every dialed transport.
	///
	/// A transport consults it before it countersigns at the handshake and at
	/// each in-band epoch renewal. Without one, pooled clients fail closed on
	/// challenge-bearing receipts.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn with_receipt_approver(mut self, approver: Arc<dyn ReceiptApprover>) -> Self {
		self.negotiation.approve_receipts(approver);
		self
	}
}

#[cfg(feature = "std")]
impl<P: Protocol> super::sealed::Sealed for ConnectionPoolBuilder<P> {}

#[cfg(feature = "std")]
impl<P: Protocol> ConnectionBuilder<P> for ConnectionPoolBuilder<P> {
	type Output = ConnectionPool<P>;

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.tls.set_trust_store(store);
		self
	}

	fn with_client_identity(mut self, identity: SigningIdentity) -> Self {
		self.tls.encryption.client_identity = Some(identity);
		self
	}

	fn build(self) -> Self::Output {
		ConnectionPool {
			pools: Arc::new(RwLock::new(HashMap::new())),
			config: self.config,
			clock: self.clock,
			timeout: self.timeout,
			total_connections: Arc::new(AtomicUsize::new(0)),
			#[cfg(pooled_mux)]
			mux_ids: AtomicU64::new(0),
			tls: self.tls.answer(),
			negotiation: self.negotiation,
			#[cfg(feature = "instrument")]
			trace: self.trace,
		}
	}
}

#[cfg(feature = "std")]
struct AvailableEntry<P: Protocol> {
	client: GenericClient<P>,
	last_used: MonotonicInstant,
}

pooled_mux! {
	/// Holds the instant a mux entry last carried traffic, on the pool's clock.
	///
	/// The entry and every lease drawn from it share one stamp, so an emit or a
	/// stream open through any lease resets the idle time of the entry.
	struct ActivityStamp {
		at: Mutex<MonotonicInstant>,
		clock: Arc<dyn Clock>,
	}

	impl ActivityStamp {
		/// Returns a stamp set to the clock's current instant.
		fn new(clock: Arc<dyn Clock>) -> Self {
			let at = Mutex::new(clock.monotonic());

			Self { at, clock }
		}

		/// Records activity at the clock's current instant.
		fn touch(&self) {
			*self.at.lock().unwrap_or_else(PoisonError::into_inner) = self.clock.monotonic();
		}

		/// Returns the instant of the last recorded activity.
		fn at(&self) -> MonotonicInstant {
			*self.at.lock().unwrap_or_else(PoisonError::into_inner)
		}
	}
}

pooled_mux! {
	/// One shared multiplexed connection to a destination.
	///
	/// The handle is cloneable, so every caller shares the entry. The entry
	/// leaves the pool when its reader ends, when it idles out, or when a
	/// terminal failure or a discard evicts it.
	struct MuxEntry {
		id: u64,
		handle: MuxHandle,
		/// The driver tasks of the connection. Their reader witnesses that the
		/// entry is live, and their drop ends the connection.
		drivers: MuxDrivers,
		/// The shared activity stamp that the idle prune reads for this entry.
		///
		/// Each lease updates it outside the pool lock. An entry with pending
		/// streams stays pooled whatever its stamp reads.
		last_used: Arc<ActivityStamp>,
		/// The validated peer certificate that the eager mux handshake pinned.
		///
		/// The mux drivers consume the transport, so the pool captures the
		/// certificate at dial. Every lease on this entry reads the peer
		/// identity from this shared handle.
		peer_certificate: Option<Arc<Certificate>>,
	}
}

/// The connection pool of one destination.
#[cfg(feature = "std")]
struct DestinationPool<P: Protocol> {
	/// The exclusive connections that are ready for reuse.
	available: VecDeque<AvailableEntry<P>>,
	/// The multiplexed connections, which every caller shares.
	#[cfg(pooled_mux)]
	mux: Vec<MuxEntry>,
	/// The drivers of the multiplexed connections that left the pool.
	#[cfg(pooled_mux)]
	draining: DrainingShelf,
}

#[cfg(feature = "std")]
impl<P: Protocol> Default for DestinationPool<P> {
	fn default() -> Self {
		Self {
			available: VecDeque::new(),
			#[cfg(pooled_mux)]
			mux: Vec::new(),
			#[cfg(pooled_mux)]
			draining: DrainingShelf::default(),
		}
	}
}

pooled_mux! {
	/// The drivers of the multiplexed connections that left the pool of one
	/// destination and still drain the streams of their leases
	/// (RFC 9113 § 6.8).
	///
	/// [`Self::shelve`] is the one way onto the shelf, so the shelf holds at
	/// most the connection cap of the pool, though a peer keeps a connection
	/// open past its GoAway. The drop of the pool ends the rest.
	#[derive(Default)]
	struct DrainingShelf {
		drivers: VecDeque<MuxDrivers>,
	}

	impl DrainingShelf {
		/// Shelves `drivers` under `cap`.
		///
		/// The finished drivers leave first. While the shelf is full, its
		/// oldest drivers leave, and their drop aborts both of their tasks,
		/// which closes a connection that its peer never closed (CWE-400).
		fn shelve(&mut self, drivers: MuxDrivers, cap: NonZeroUsize) {
			self.drivers.retain(|held| !held.is_finished());
			while self.drivers.len() >= cap.get() {
				let Some(oldest) = self.drivers.pop_front() else {
					break;
				};

				drop(oldest);
			}

			self.drivers.push_back(drivers);
		}
	}
}

/// A connection pool for protocol `P` with a global connection limit.
///
/// # Invariants
///
/// - `total_connections` counts live connections and stays within
///   `0..=config.max_connections`. A dial adds 1 when it reserves a slot, and
///   gives it back when it builds no connection.
/// - Each acquire prunes the connections of its destination idle past
///   [`PoolConfig::idle_timeout`], so the prune is lazy.
/// - A poisoned pool map fails the call that acquires with
///   [`TransportFailure::Internal`], and eviction and the drop-time return skip
///   their write. An activity stamp recovers from poison, because it holds
///   one instant.
#[cfg(feature = "std")]
pub struct ConnectionPool<P: Protocol> {
	/// The sub-pools, one per destination.
	pools: Arc<RwLock<HashMap<P::Address, DestinationPool<P>>>>,
	/// The limits and multiplexing policy that this pool enforces.
	config: PoolConfig,
	/// The clock that the pool measures idle time, deadlines, and backoff
	/// against.
	clock: Arc<dyn Clock>,
	/// The timeout that every connection shares.
	timeout: Option<Duration>,
	/// The count of live connections across all destinations.
	total_connections: Arc<AtomicUsize>,
	/// The monotonic IDs that correlate mux pool entries with their leases.
	#[cfg(pooled_mux)]
	mux_ids: AtomicU64,
	/// The shared encryption provisioning that every pooled connection
	/// reuses, answered once.
	tls: PoolProvisioning<P::CryptoProvider>,
	/// The negotiation input every dial from this pool starts with.
	negotiation: Negotiation,
	/// The production instrumentation collector, the single client-side entry
	/// point.
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "std")]
impl<P: Protocol> ConnectionPool<P> {
	/// Decrements the live-connection count for a discarded connection. The
	/// count saturates at zero, so an accounting defect cannot wrap the counter
	/// and wedge the pool into permanent refusal.
	fn release_connection_count(&self) {
		// An `Err` means the count already stands at its floor of zero.
		let _ = self
			.total_connections
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| current.checked_sub(1));
	}

	/// Returns the endpoint that one dial from this pool starts from: the
	/// shared provisioning, the negotiation input, the pool's timeout, the
	/// pool's clock, and its instrumentation collector.
	///
	/// A dial builds the endpoint before it opens a socket, so a pool whose
	/// provisioning the dialer rule refuses never connects.
	///
	/// # Errors
	///
	/// - [`TransportError::PeerAuthenticationUnconfigured`] -- the pool
	///   authenticates no peer and did not name cleartext, or it sets a server
	///   policy with no trust in a server, with or without cleartext.
	/// - [`TransportError::HandshakeError`] -- the client identity names a key
	///   purpose other than the client's, or its extended key usage fails to
	///   decode.
	fn dial_endpoint(&self) -> TransportResult<EndpointConfig<P::CryptoProvider>> {
		let endpoint = self.tls.endpoint(&self.clock)?;
		let endpoint = endpoint.with_negotiation(self.negotiation.clone());
		let endpoint = endpoint.with_operation_timeout(self.timeout);

		#[cfg(feature = "instrument")]
		let endpoint = match self.trace.as_ref() {
			Some(trace) => endpoint.with_trace(trace.share()),
			None => endpoint,
		};

		Ok(endpoint)
	}

	/// Dual-writes a pool lifecycle event: its URN goes into the instrument log
	/// and, under `testing`, becomes the label of spec assertions and CSP
	/// alphabets.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the error the runtime fault model injects at `event`.
	#[cfg(feature = "instrument")]
	fn emit_event(&self, event: Urn<'static>) -> TransportResult<()> {
		let Some(trace) = self.trace.as_ref() else {
			return Ok(());
		};

		Ok(trace.emit_event(event)?)
	}

	/// Writes a pool event that carries evidence: `label` names why, and the
	/// payload that `evidence` renders names who, such as the certificate of a
	/// peer. The evidence renders only when the pool holds a trace that keeps
	/// the payload.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the error the runtime fault model injects at `event`.
	#[cfg(all(pooled_mux, feature = "instrument"))]
	fn emit_event_with_evidence<E: AsRef<[u8]>>(
		&self,
		event: Urn<'static>,
		label: impl Into<Cow<'static, str>>,
		evidence: impl FnOnce() -> Option<E>,
	) -> TransportResult<()> {
		let Some(trace) = self.trace.as_ref() else {
			return Ok(());
		};

		Ok(trace.emit_event_with_value_and_rendered_evidence(event, label, (), evidence)?)
	}

	/// Retires `departed` connections that have left the pool. It gives back
	/// the count of each, then records `event` once for each, so a fault at an
	/// event finds the pool whole. An eviction records
	/// [`events::POOL_EVICTED`], and an idle prune records
	/// [`events::POOL_PRUNED_IDLE`].
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the error the runtime fault model injects at `event`.
	// The `instrument` build alone records the event, so that build alone
	// reads it.
	#[cfg_attr(not(feature = "instrument"), allow(unused_variables))]
	fn retire(&self, departed: usize, event: Urn<'static>) -> TransportResult<()> {
		for _ in 0..departed {
			self.release_connection_count();
		}

		#[cfg(feature = "instrument")]
		for _ in 0..departed {
			self.emit_event(event.clone())?;
		}

		Ok(())
	}
}

#[cfg(feature = "std")]
impl<P: Protocol + Send + Sync> ConnectionPool<P>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	/// Creates a connection pool builder on the default clock,
	/// [`SystemClock`].
	#[cfg(host_clock)]
	pub fn builder() -> ConnectionPoolBuilder<P> {
		ConnectionPoolBuilder::default()
	}

	fn wrap_client(self: &Arc<Self>, client: GenericClient<P>, addr: P::Address) -> PooledClient<P>
	where
		P: PersistentConnection,
	{
		let pool = Arc::clone(self);

		PooledClient {
			client: Some(client),
			#[cfg(pooled_mux)]
			mux: None,
			pool,
			addr,
		}
	}

	fn write_pools(&self) -> TransportResult<RwLockWriteGuard<'_, HashMap<P::Address, DestinationPool<P>>>> {
		self.pools
			.write()
			.map_err(|_| TransportError::OperationFailed(TransportFailure::Internal))
	}

	fn try_take_ready_client(self: &Arc<Self>, addr: &P::Address) -> TransportResult<Option<GenericClient<P>>>
	where
		P: PersistentConnection,
	{
		let mut pools = self.write_pools()?;
		if let Some(dest_pool) = pools.get_mut(addr) {
			self.prune_idle_locked(dest_pool, self.clock.monotonic())?;

			while let Some(entry) = dest_pool.available.pop_front() {
				if <P as PersistentConnection>::is_connected(entry.client.transport()) {
					// A fault at the lease fails the lease, and the live
					// connection stays pooled.
					#[cfg(feature = "instrument")]
					if let Err(fault) = self.emit_event(events::POOL_REUSE_READY) {
						dest_pool.available.push_front(entry);
						return Err(fault);
					}

					return Ok(Some(entry.client));
				}

				// The pool discards a dead candidate here, so it leaves the
				// live set.
				self.retire(1, events::POOL_EVICTED)?;
			}
		}
		Ok(None)
	}

	fn reserve_slot(self: &Arc<Self>, addr: &P::Address) -> TransportResult<SlotGuard<P>> {
		// One atomic check-and-increment means concurrent callers cannot all
		// pass a separate limit check and overshoot `max_connections`.
		let reserved = self
			.total_connections
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
				if current >= self.config.max_connections.get() {
					None
				} else {
					current.checked_add(1)
				}
			});
		if reserved.is_err() {
			#[cfg(feature = "instrument")]
			self.emit_event(events::POOL_EXHAUSTED)?;

			return Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted));
		}

		// A poisoned pool map must not leak the reservation, so give the
		// counter back before the call returns the failure.
		let mut pools = match self.write_pools() {
			Ok(pools) => pools,
			Err(err) => {
				self.release_connection_count();
				return Err(err);
			}
		};

		// The guard gives the reservation back when the prune fails.
		let slot = SlotGuard::new(Arc::clone(self));
		let dest_pool = pools.entry(addr.clone()).or_default();
		self.prune_idle_locked(dest_pool, self.clock.monotonic())?;

		Ok(slot)
	}

	/// Prunes the idle connections of `dest_pool` that passed the idle timeout
	/// at `now`. Every expired mux entry leaves the pool before the prune
	/// records its events, so a fault at one leaves the pool whole.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- the error the runtime fault model injects at a prune.
	fn prune_idle_locked(&self, dest_pool: &mut DestinationPool<P>, now: MonotonicInstant) -> TransportResult<()> {
		let Some(timeout) = self.config.idle_timeout else {
			return Ok(());
		};

		while let Some(entry) = dest_pool.available.front() {
			if now.saturating_duration_since(entry.last_used) >= timeout {
				dest_pool.available.pop_front();
				// The pop drops and closes the idle connection, so it leaves
				// the live set.
				self.retire(1, events::POOL_PRUNED_IDLE)?;
			} else {
				break;
			}
		}

		// The pruner only reads the stamp, which a lease writes outside the
		// pool lock (`MuxEntry::last_used`).
		#[cfg(pooled_mux)]
		{
			let idle_past = |entry: &mut MuxEntry| {
				let idle = now.saturating_duration_since(entry.last_used.at());
				!entry.handle.has_pending_streams() && idle >= timeout
			};

			let cap = self.config.max_connections;
			let mut pruned: usize = 0;
			for entry in dest_pool.mux.extract_if(.., idle_past) {
				// GoAway precedes the close (RFC 9113 § 6.8), so the reader
				// task ends on its EOF. A concurrent stream sees `Draining`,
				// or `ConnectionClosed` once the reader ends.
				let MuxEntry { handle, drivers, .. } = entry;
				rt::spawn(async move {
					// The drain runs detached from the prune that spawned it.
					// Its only failure is `ConnectionClosed`, which names a
					// connection that is already closed.
					let _ = handle.shutdown().await;
				});

				dest_pool.draining.shelve(drivers, cap);
				pruned = pruned.saturating_add(1);
			}

			// A pruned idle connection leaves the live set.
			self.retire(pruned, events::POOL_PRUNED_IDLE)?;
		}
		Ok(())
	}

	/// Leases a ready connection or opens a fresh one, held exclusively.
	async fn connect_single_flight(self: &Arc<Self>, addr: &P::Address) -> TransportResult<PooledClient<P>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig + Send + Sync,
	{
		if let Some(client) = self.try_take_ready_client(addr)? {
			return Ok(self.wrap_client(client, addr.clone()));
		}

		let endpoint = self.dial_endpoint()?;
		let mut reservation = self.reserve_slot(addr)?;
		let stream = endpoint.dial::<P>(addr.clone()).await?;
		let transport = P::create_transport(stream, endpoint);

		#[cfg(feature = "instrument")]
		self.emit_event(events::POOL_DIAL)?;

		let client = GenericClient::from_transport(transport);

		reservation.disarm();

		Ok(self.wrap_client(client, addr.clone()))
	}

	/// Connects to a destination and holds the connection exclusively.
	#[cfg(not(all(
		feature = "tokio",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-hpke")
	)))]
	pub async fn connect(self: &Arc<Self>, addr: impl Into<P::Address>) -> TransportResult<PooledClient<P>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig + Send + Sync,
	{
		let destination = addr.into();
		self.connect_single_flight(&destination).await
	}

	/// Leases a ready pooled connection to `addr` without a dial, or returns
	/// `None` when none is ready.
	///
	/// # Errors
	///
	/// - [`TransportError::OperationFailed`] with [`TransportFailure::Internal`] -- the pool map is poisoned.
	/// - [`TransportError`] -- the error the runtime fault model injects at a
	///   prune, an eviction, or the reuse.
	pub fn try_acquire(self: &Arc<Self>, addr: &P::Address) -> TransportResult<Option<PooledClient<P>>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig + Send + Sync,
	{
		let maybe_client = self.try_take_ready_client(addr)?;
		Ok(maybe_client.map(|client| self.wrap_client(client, addr.clone())))
	}
}

pooled_mux! {
	impl<P: Protocol + Send + Sync> ConnectionPool<P>
	where
		P: PersistentConnection,
		P::Address: Hash + Eq + Clone + Send + Sync,
		P::Transport: MessageEmitter
			+ MessageCollector
			+ PolicyConfig
			+ MuxConnector
			+ Send
			+ Sync,
	{
		/// Connects to a destination, over a multiplexed connection when
		/// [`PoolConfig::mux_offer`] is set and the peer accepts the offer.
		pub async fn connect(
			self: &Arc<Self>,
			addr: impl Into<P::Address>,
		) -> TransportResult<PooledClient<P>>
		where
			P::Address: Clone,
		{
			let destination = addr.into();
			if self.config.mux_offer.is_none() {
				return self.connect_single_flight(&destination).await;
			}

			self.acquire_mux(&destination, MuxSelection::PreferHeadroom).await
		}

		/// Acquires a mux lease through the reuse tiers, in order:
		///
		/// 1. A pooled mux entry.
		/// 2. An idle exclusive lease left when a peer declined multiplexing.
		/// 3. A fresh dial.
		///
		/// Every caller that offers mux shares this path, so each one tries the
		/// tiers in this order.
		async fn acquire_mux(
			self: &Arc<Self>,
			addr: &P::Address,
			selection: MuxSelection,
		) -> TransportResult<PooledClient<P>> {
			if let Some(lease) = self.try_take_mux_handle(addr, selection)? {
				return Ok(self.wrap_mux_client(lease, addr.clone()));
			}

			if let Some(client) = self.try_take_ready_client(addr)? {
				return Ok(self.wrap_client(client, addr.clone()));
			}

			let offer = match &self.config.mux_offer {
				// Every dial shares the one `PoolConfig` offer.
				Some(offer) => Arc::clone(offer),
				None => {
					return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
				}
			};

			self.open_mux_connection(addr.clone(), offer).await
		}

		/// Opens a fresh connection with a mux offer. When the peer declines
		/// the offer, the connection pools as an exclusive lease.
		async fn open_mux_connection(
			self: &Arc<Self>,
			addr: P::Address,
			offer: Arc<TransportOffer>,
		) -> TransportResult<PooledClient<P>> {
			let endpoint = self.dial_endpoint()?;
			let mut reservation = self.reserve_slot(&addr)?;

			let stream = endpoint.dial::<P>(addr.clone()).await?;
			let transport = P::create_transport(stream, endpoint);

			// Mux requires the negotiation result before first use, so the
			// handshake runs eagerly instead of on first emit.
			let mut transport = transport.with_mux_offer(Some(offer));
			transport.complete_client_handshake().await?;

			#[cfg(feature = "instrument")]
			self.emit_event(events::POOL_DIAL)?;

			let settings = match transport.negotiated_mux() {
				Some(settings) => settings,
				None => {
					#[cfg(feature = "instrument")]
					self.emit_event(events::POOL_MUX_DECLINED)?;

					let client = GenericClient::from_transport(transport);

					reservation.disarm();

					return Ok(self.wrap_client(client, addr));
				}
			};

			// The mux drivers consume the transport below, so this is the
			// last point where the handshake certificate is readable.
			let peer_certificate = transport.handshake_peer_certificate();

			let rekey = transport.take_rekey()?;
			let (reader, writer) = transport.into_envelope_halves()?;
			let mux = MuxTransport::assemble(reader, writer, CONNECTOR_ROLE, settings, rekey);
			let SpawnedMux { handle, responder, drivers } = mux.spawn();

			// A pool endpoint serves only the streams it opens, so the drop of
			// the responder refuses every peer-initiated stream.
			drop(responder);

			let id = self.mux_ids.fetch_add(1, Ordering::Relaxed);
			let last_used = Arc::new(ActivityStamp::new(Arc::clone(&self.clock)));

			{
				// A failed lock returns before the entry holds the drivers, and
				// their drop then ends the connection.
				let mut pools = self.write_pools()?;

				// The handle clone shares the one connection, so the pool
				// entry and the lease co-own it.
				let dest_pool = pools.entry(addr.clone()).or_default();
				dest_pool.mux.push(MuxEntry {
					id,
					handle: handle.clone(),
					drivers,
					last_used: Arc::clone(&last_used),
					peer_certificate: peer_certificate.clone(),
				});
			}

			reservation.disarm();

			let lease = MuxLease { id, handle, last_used, peer_certificate };
			Ok(self.wrap_mux_client(lease, addr))
		}

		/// Takes a live mux entry for the destination in round-robin order.
		///
		/// It prunes idle entries, evicts entries whose reader driver ended,
		/// and prefers entries with stream headroom over saturated ones.
		fn try_take_mux_handle(
			self: &Arc<Self>,
			addr: &P::Address,
			selection: MuxSelection,
		) -> TransportResult<Option<MuxLease>> {
			let mut pools = self.write_pools()?;
			let dest_pool = match pools.get_mut(addr) {
				Some(dest_pool) => dest_pool,
				None => return Ok(None),
			};

			self.prune_idle_locked(dest_pool, self.clock.monotonic())?;

			// Every dead entry leaves the pool before the pool retires it.
			let live_before = dest_pool.mux.len();

			dest_pool.mux.retain(|entry| !entry.drivers.is_finished());

			let evicted = live_before.saturating_sub(dest_pool.mux.len());
			self.retire(evicted, events::POOL_EVICTED)?;

			if dest_pool.mux.len() > 1 {
				dest_pool.mux.rotate_left(1);
			}

			let with_headroom = dest_pool.mux.iter().find(|entry| entry.handle.has_stream_headroom());
			let fallback = match selection {
				// A saturated entry stays shareable, because an in-flight
				// stream may finish before the caller emits.
				MuxSelection::PreferHeadroom => dest_pool.mux.first(),
				// Cap-exhaustion failover must not land back on a
				// saturated entry, so it falls through to the next tier.
				MuxSelection::RequireHeadroom => None,
			};

			// The lease holds a clone of the handle, so the entry stays pooled
			// for other callers.
			let selected = with_headroom.or(fallback).map(MuxLease::from);

			#[cfg(feature = "instrument")]
			if selected.is_some() {
				self.emit_event(events::POOL_REUSE_MUX)?;
			}

			Ok(selected)
		}

		/// Removes a mux entry after a discard or a terminal failure, which is
		/// [`TransportError::ConnectionClosed`] or
		/// [`TransportError::Draining`]. The next connect re-establishes the
		/// connection, and a poisoned pool map skips the eviction.
		///
		/// The drivers of the entry move to the draining shelf, so the leases
		/// that still hold its handle finish their streams.
		///
		/// # Errors
		///
		/// - [`TransportError`] -- the error the runtime fault model injects at
		///   the eviction, which the entry has already left.
		fn evict_mux(&self, addr: &P::Address, id: u64) -> TransportResult<()> {
			let mut pools = match self.pools.write() {
				Ok(pools) => pools,
				Err(_) => return Ok(()),
			};
			if let Some(dest_pool) = pools.get_mut(addr) {
				let cap = self.config.max_connections;
				let mut evicted: usize = 0;
				for entry in dest_pool.mux.extract_if(.., |entry| entry.id == id) {
					dest_pool.draining.shelve(entry.drivers, cap);
					evicted = evicted.saturating_add(1);
				}

				// An evicted mux connection leaves the live set.
				self.retire(evicted, events::POOL_EVICTED)?;
			}
			Ok(())
		}

		fn wrap_mux_client(self: &Arc<Self>, lease: MuxLease, addr: P::Address) -> PooledClient<P> {
			PooledClient {
				client: None,
				mux: Some(lease),
				pool: Arc::clone(self),
				addr,
			}
		}
	}

	/// A caller's reference to one shared mux pool entry.
	struct MuxLease {
		id: u64,
		handle: MuxHandle,
		/// The stamp shared with the pool entry. The lease stamps it on each
		/// emit and stream open, so the pruner reads idle time from the pool's
		/// clock outside the mux core ([`MuxEntry::last_used`]).
		last_used: Arc<ActivityStamp>,
		/// A shared handle to the entry's pinned peer certificate
		/// ([`MuxEntry::peer_certificate`]).
		peer_certificate: Option<Arc<Certificate>>,
	}

	impl MuxLease {
		/// Records activity for the pruner when an emit or a stream open
		/// starts. While the stream is in flight,
		/// [`MuxHandle::has_pending_streams`] covers it.
		fn stamp(&self) {
			self.last_used.touch();
		}
	}

	impl From<&MuxEntry> for MuxLease {
		fn from(entry: &MuxEntry) -> Self {
			Self {
				id: entry.id,
				handle: entry.handle.clone(),
				last_used: Arc::clone(&entry.last_used),
				peer_certificate: entry.peer_certificate.clone(),
			}
		}
	}

	/// The policy that selects a mux entry in the acquisition funnel.
	#[derive(Clone, Copy)]
	enum MuxSelection {
		/// Prefers an entry with stream headroom, and falls back to a saturated
		/// one, because a slot may free before the caller emits.
		PreferHeadroom,
		/// Takes only an entry with stream headroom, or `None`.
		RequireHeadroom,
	}
}

/// A pooled client connection that returns to the pool on drop.
///
/// An exclusive lease holds the connection alone, and its drop returns a live
/// connection to the pool. A multiplexed lease shares one connection with
/// every other caller, and the pool entry keeps that connection when the lease
/// drops.
#[cfg(feature = "std")]
pub struct PooledClient<P: Protocol + PersistentConnection>
where
	P::Address: Hash + Eq + Send + Sync,
{
	client: Option<GenericClient<P>>,
	#[cfg(pooled_mux)]
	mux: Option<MuxLease>,
	pool: Arc<ConnectionPool<P>>,
	addr: P::Address,
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection> PooledClient<P>
where
	P::Address: Hash + Eq + Send + Sync,
{
	/// Returns a mutable reference to the exclusive connection of this lease.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`] -- the lease is multiplexed and holds
	///   no exclusive connection. Use [`PooledClient::emit`] instead.
	pub fn conn(&mut self) -> TransportResult<&mut GenericClient<P>> {
		self.client.as_mut().ok_or(TransportError::InvalidState)
	}

	/// Returns the validated peer certificate that this connection's handshake
	/// pinned.
	///
	/// A mux lease answers from the certificate pinned at its eager dial
	/// handshake. An exclusive lease reads its transport, so the answer is
	/// `None` until the handshake completes. A caller that gates policy on peer
	/// identity MUST fail closed on `None`.
	pub fn peer_certificate(&self) -> Option<&Certificate>
	where
		P::Transport: crate::transport::state::EncryptedProtocolState,
	{
		use crate::transport::state::EncryptedProtocolState;

		#[cfg(pooled_mux)]
		if let Some(lease) = self.mux.as_ref() {
			return lease.peer_certificate.as_deref();
		}

		self.client.as_ref()?.transport().session_state().peer_certificate()
	}
}

#[cfg(all(
	feature = "std",
	not(all(
		feature = "tokio",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-hpke")
	))
))]
impl<P: Protocol + PersistentConnection> PooledClient<P>
where
	P::Address: Hash + Eq + Send + Sync,
{
	/// Emits a message through the pooled connection.
	pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>>
	where
		P::Transport: MessageEmitter,
	{
		self.conn()?.emit(frame, attempt).await
	}
}

pooled_mux! {
	impl<P: Protocol + PersistentConnection + Send + Sync> PooledClient<P>
	where
		P::Address: Hash + Eq + Clone + Send + Sync,
		P::Transport: MessageEmitter
			+ MessageCollector
			+ PolicyConfig
			+ MuxConnector
			+ Send
			+ Sync,
	{
		/// Returns the current epoch's dual-signed session receipt on a
		/// multiplexed lease.
		///
		/// Every lease on the connection shares it, and each completed in-band
		/// renewal rotates it in place. It is `None` on an exclusive lease and
		/// on a session without receipt-bearing rekey materials.
		pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
			self.mux.as_ref().and_then(|lease| lease.handle.session_receipt())
		}

		/// Emits a message through the pooled connection, as a stream on the
		/// shared mux connection or on the exclusive lease.
		///
		/// A mux failure takes one of two paths:
		///
		/// - `StreamsExhausted` (the local stream cap is full) moves the lease
		///   to a pooled connection with stream headroom, or an additional one
		///   up to `max_connections`, and retries there once.
		/// - `ConnectionClosed` or `Draining` (a rekey GoAway or an idle-prune
		///   drain) evicts the entry so the next connect re-establishes it,
		///   then reports the failure.
		pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
			// The local handle clone releases the `self.mux` borrow before the
			// failover arm takes `&mut self`.
			let (lease_id, handle) = match self.mux.as_ref() {
				Some(lease) => {
					lease.stamp();
					(lease.id, lease.handle.clone())
				}
				None => return self.conn()?.emit(frame, attempt).await,
			};

			match handle.emit_on_stream(&frame).await {
				Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)) => {
					self.emit_failover(frame, attempt).await
				}
				Err(err @ (TransportError::ConnectionClosed | TransportError::Draining)) => {
					self.pool.evict_mux(&self.addr, lease_id)?;
					Err(err)
				}
				outcome => outcome,
			}
		}

		/// Warms the connection: it completes its handshake before it carries
		/// an application frame.
		///
		/// A caller that gates on peer identity before it discloses a request
		/// calls this first, so [`peer_certificate`](Self::peer_certificate)
		/// has an answer.
		///
		/// - A mux lease completed its handshake at dial, so it returns at once.
		/// - An exclusive lease completes its handshake here, in place of the first [`emit`](Self::emit).
		#[cfg(feature = "colony")]
		pub(crate) async fn complete_handshake(&mut self) -> TransportResult<()> {
			if self.mux.is_some() {
				return Ok(());
			}

			self.conn()?.complete_handshake().await
		}

		/// Takes this connection out of the pool and closes it, so no later
		/// lease reaches the party that answered it.
		///
		/// A colony dial whose answer fails its proof ends the connection
		/// here, in place of the drop that returns it to the pool (CWE-346).
		///
		/// - An exclusive lease closes its connection and gives back its slot.
		/// - A mux lease evicts its entry, which every lease of the connection
		///   shares, and drains the connection as an idle prune does.
		///
		/// # Errors
		///
		/// - [`TransportError`] -- the error the runtime fault model injects at
		///   the eviction, which the connection has already left.
		#[cfg(feature = "colony")]
		pub(crate) fn discard(mut self) -> TransportResult<()> {
			if let Some(lease) = self.mux.take() {
				// The entry leaves the pool before its event can fault, so the
				// drain starts whatever the event answers.
				let evicted = self.pool.evict_mux(&self.addr, lease.id);

				// The drain runs detached, as an idle prune's does. Its only
				// failure is `ConnectionClosed`, which names a connection that
				// is already closed.
				rt::spawn(async move {
					let _ = lease.handle.shutdown().await;
				});
				evicted?;
			}

			if let Some(client) = self.client.take() {
				// The drop of the client closes its connection, so the
				// connection leaves the live set.
				drop(client);
				self.pool.retire(1, events::POOL_EVICTED)?;
			}

			Ok(())
		}

		/// Returns this lease's mux handle, with its activity recorded.
		///
		/// Every stream-open method below needs the same two steps: refuse an
		/// exclusive lease, then stamp the entry so the pruner counts the lease
		/// as active.
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		fn stamped_handle(&self) -> TransportResult<&MuxHandle> {
			let lease = self.mux.as_ref().ok_or(TransportError::InvalidState)?;
			lease.stamp();
			Ok(&lease.handle)
		}

		/// Opens a streamed request on the shared mux connection. The caller
		/// pushes chunks through the sink, then awaits the unary response.
		///
		/// The stream counts as pending on the connection, so the pruner
		/// keeps the entry alive while it is in flight.
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		/// - [`TransportError`] -- the errors of [`MuxHandle::open_stream`].
		pub fn open_stream(
			&self,
		) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
			self.stamped_handle()?.open_stream()
		}

		/// Opens a streamed request routed to `target`. The peer gateway reads
		/// the grpc-style route to dispatch locally or to splice the stream to
		/// a further peer.
		///
		/// It is otherwise identical to [`open_stream`](Self::open_stream).
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		/// - [`TransportError`] -- the errors of [`MuxHandle::open_stream`].
		pub fn open_stream_to(
			&self,
			target: impl Into<Urn<'static>>,
		) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
			self.stamped_handle()?.open_stream_to(target)
		}

		/// Opens a streamed request that carries a fully formed
		/// [`StreamRoute`].
		///
		/// - [`StreamRoute::to`] builds the route for an origin open.
		/// - [`StreamRoute::relayed_to`] builds the route that re-emits a spent hop budget.
		///
		/// Prefer [`open_stream_to`](Self::open_stream_to) for a plain origin
		/// target. Crate-internal callers pass a fully formed route when it
		/// carries more than an origin target. It is otherwise identical to
		/// [`open_stream`](Self::open_stream).
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		/// - [`TransportError`] -- the errors of [`MuxHandle::open_stream`].
		#[cfg(feature = "colony")]
		pub(crate) fn open_stream_with_route(
			&self,
			route: StreamRoute,
		) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
			self.stamped_handle()?.open_stream_with_route(route)
		}

		/// Opens a duplex stream on the shared mux connection. The caller
		/// pushes request chunks through the sink while the peer's reply
		/// arrives incrementally through the body.
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		/// - [`TransportError`] -- the errors of [`MuxHandle::open_duplex`].
		pub fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)> {
			self.stamped_handle()?.open_duplex()
		}

		/// Opens a duplex stream routed to `target`. The peer gateway reads the
		/// grpc-style route to dispatch locally or to splice both directions to
		/// a further peer.
		///
		/// It is otherwise identical to [`open_duplex`](Self::open_duplex).
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		/// - [`TransportError`] -- the errors of [`MuxHandle::open_duplex`].
		pub fn open_duplex_to(&self, target: impl Into<Urn<'static>>) -> TransportResult<(RequestSink, StreamBody)> {
			self.stamped_handle()?.open_duplex_to(target)
		}

		/// Opens a duplex stream that carries a fully formed [`StreamRoute`].
		///
		/// - [`StreamRoute::to`] builds the route for an origin open.
		/// - [`StreamRoute::relayed_to`] builds the route that re-emits a spent hop budget.
		///
		/// Prefer [`open_duplex_to`](Self::open_duplex_to) for a plain origin
		/// target. Crate-internal callers pass a fully formed route when it
		/// carries more than an origin target. It is otherwise identical to
		/// [`open_duplex`](Self::open_duplex).
		///
		/// # Errors
		///
		/// - [`TransportError::InvalidState`] -- the lease is exclusive, and a stream needs the mux plane.
		/// - [`TransportError`] -- the errors of [`MuxHandle::open_duplex`].
		#[cfg(feature = "colony")]
		pub(crate) fn open_duplex_with_route(&self, route: StreamRoute) -> TransportResult<(RequestSink, StreamBody)> {
			self.stamped_handle()?.open_duplex_with_route(route)
		}

		/// Fails over on cap exhaustion through the acquisition funnel, pooled
		/// headroom before a fresh dial, and retries there once.
		///
		/// A caller may have judged the peer this lease pinned, but a fresh
		/// dial of the same address pins whoever answers. The failover lands on
		/// the pinned certificate, or it ends before the frame leaves
		/// (CWE-367).
		///
		/// # Errors
		///
		/// - [`TransportFailure::StreamsExhausted`] -- the pool offers no mux plane to move to.
		/// - [`CertificateValidationError::CertificateNotPinned`] -- another
		///   peer answered the failover. It comes ahead of a fault the trace
		///   injects at its record.
		/// - [`TransportError`] -- the error the runtime fault model injects at
		///   the failover, or at the events of the dial and the reuse.
		async fn emit_failover(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
			if self.pool.config.mux_offer.is_none() {
				// A mux lease exists only when `PoolConfig::mux_offer` is set.
				return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
			}

			#[cfg(feature = "instrument")]
			self.pool.emit_event(events::POOL_FAILOVER)?;

			let pinned = self.mux.as_ref().and_then(|lease| lease.peer_certificate.clone());
			let moved = self
				.pool
				.acquire_mux(&self.addr, MuxSelection::RequireHeadroom)
				.await?;

			let landed = moved.mux.as_ref().and_then(|lease| lease.peer_certificate.clone());
			if pinned.is_some() && landed != pinned {
				let refusal = CertificateValidationError::CertificateNotPinned;

				// As evidence, the certificate that answered names who. A
				// certificate that does not encode names no one, and the pin
				// check refuses it all the same.
				#[cfg(feature = "instrument")]
				let recorded = {
					let answered = || landed.as_deref().and_then(|certificate| der::Encode::to_der(certificate).ok());
					self.pool.emit_event_with_evidence(events::POOL_FAILOVER_REFUSED, refusal.as_str(), answered)
				};

				// The refusal names why the failover ended, so it comes ahead
				// of a fault at its record.
				let refused: TransportResult<Option<Frame>> = Err(TransportError::InvalidCertificate(refusal));
				#[cfg(feature = "instrument")]
				let refused = refused.and(recorded.map(|()| None));

				return refused;
			}

			*self = moved;

			match self.mux.as_ref() {
				Some(lease) => {
					lease.stamp();
					lease.handle.emit_on_stream(&frame).await
				}
				None => self.conn()?.emit(frame, attempt).await,
			}
		}
	}
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection> Drop for PooledClient<P>
where
	P::Address: Hash + Eq + Send + Sync,
{
	fn drop(&mut self) {
		let client = match self.client.take() {
			Some(client) => client,
			None => return,
		};

		// A drop has no caller to fail, so a fault the trace injects at the
		// release ends with the drop, and the connection returns to the pool.
		#[cfg(feature = "instrument")]
		drop(self.pool.emit_event(events::POOL_RELEASED));

		let mut returned_to_pool = false;

		let is_healthy = <P as PersistentConnection>::is_connected(client.transport());
		if let Ok(mut pools) = self.pool.pools.write() {
			if let Some(dest_pool) = pools.get_mut(&self.addr) {
				if is_healthy {
					dest_pool
						.available
						.push_back(AvailableEntry { client, last_used: self.pool.clock.monotonic() });

					returned_to_pool = true;
				}
			}
		}

		// A connection parked in `available` is live and stays counted.
		// Only a discarded (unhealthy or unparkable) connection leaves the set.
		if !returned_to_pool {
			self.pool.release_connection_count();
		}
	}
}

#[cfg(feature = "std")]
struct SlotGuard<P: Protocol>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	pool: Arc<ConnectionPool<P>>,
	active: bool,
}

#[cfg(feature = "std")]
impl<P: Protocol> SlotGuard<P>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn new(pool: Arc<ConnectionPool<P>>) -> Self {
		Self { pool, active: true }
	}

	fn disarm(&mut self) {
		self.active = false;
	}
}

#[cfg(feature = "std")]
impl<P: Protocol> Drop for SlotGuard<P>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn drop(&mut self) {
		if !self.active {
			return;
		}

		// The reserved slot holds no connection, so it leaves the live set.
		self.pool.release_connection_count();
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use super::*;

	#[test]
	fn test_pool_config_default() {
		let config = PoolConfig::default();
		assert!(config.idle_timeout.is_none());
	}

	#[test]
	fn the_default_pool_cap_is_the_named_constant() {
		let config = PoolConfig::default();
		assert_eq!(config.max_connections, DEFAULT_MAX_POOL_CONNECTIONS);
	}

	#[test]
	fn test_pool_config_with_timeout() {
		let config = PoolConfig { idle_timeout: Some(Duration::from_secs(30)), ..PoolConfig::default() };
		assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
	}

	#[test]
	fn test_pool_config_with_max_connections() {
		let config = PoolConfig { max_connections: NonZeroUsize::MIN, ..PoolConfig::default() };
		assert_eq!(config.max_connections, NonZeroUsize::MIN);
	}

	/// A fault the trace injects where a connection leaves the pool reaches the
	/// caller, and the connection has left by then. Each case holds a pool of
	/// one connection, so a connection that stayed would block the next dial.
	#[cfg(all(
		feature = "colony",
		feature = "transport-cms",
		feature = "instrument",
		feature = "testing-fault"
	))]
	mod eviction_faults {
		use super::*;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::testing::{FaultModel, TestCmsServer, TestFrame};
		use crate::transport::multiplex::MuxAcceptor;
		use crate::transport::tcp::TightBeamSocketAddr;
		use crate::transport::{EncryptedProtocol, TokioListener, TransportEncryptionConfig};
		use tokio::net::TcpListener;

		/// The number of reads that a wait on the pool state takes, one every
		/// [`SETTLE_INTERVAL`] for 2 s.
		const SETTLE_ATTEMPTS: u32 = 400;

		/// The interval between the reads of a wait on the pool state.
		const SETTLE_INTERVAL: Duration = Duration::from_millis(5);

		/// The fault the trace injects at each eviction, an error distinct from
		/// every answer of the eviction paths.
		fn injected() -> TransportError {
			TransportError::InvalidAddress
		}

		/// A collector whose trace injects [`injected`] at every eviction.
		fn faulting_trace() -> TraceCollector {
			let model = FaultModel::default().with_event_fault(events::POOL_EVICTED, injected, crate::bps!(10000));
			TraceCollector::new().with_fault_model(model)
		}

		/// A pool of one connection from `builder`, which multiplexes under
		/// `offer` when it is set and records into `trace`.
		fn pool_of_one(
			builder: ConnectionPoolBuilder<TokioListener>,
			offer: Option<TransportOffer>,
			trace: &TraceCollector,
		) -> Arc<ConnectionPool<TokioListener>> {
			let config = PoolConfig {
				max_connections: NonZeroUsize::MIN,
				mux_offer: offer.map(Arc::new),
				..PoolConfig::default()
			};
			Arc::new(builder.with_config(config).with_trace(trace.share()).build())
		}

		/// A cleartext pool of one exclusive connection, beside a listener that
		/// only takes its dials.
		async fn exclusive_pool(trace: &TraceCollector) -> (Arc<ConnectionPool<TokioListener>>, TcpListener) {
			let bound = TcpListener::bind("127.0.0.1:0").await;
			let listener = bound.expect("a loopback port binds");
			let builder = ConnectionPool::<TokioListener>::builder().allow_cleartext();
			(pool_of_one(builder, None, trace), listener)
		}

		/// A multiplexed pool of one connection, beside the address of a test
		/// server that hangs up on each dial once its mux negotiation ends.
		async fn mux_pool(trace: &TraceCollector) -> (Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr) {
			let server = TestCmsServer::generate("Pool Server");
			let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(server.signing_identity());
			let bind = TightBeamSocketAddr("127.0.0.1:0".parse().expect("a loopback address parses"));
			let (listener, addr) = TokioListener::bind_with(bind, config).await.expect("the test server binds");
			tokio::spawn(async move {
				while let Ok((transport, _)) = listener.accept().await {
					let mut transport = transport.with_mux_offer(Some(TransportOffer::mux(4)));
					// The connection ends here whatever the negotiation
					// answered, which is the hang-up the cases wait for.
					let _ = transport.negotiate_mux().await;
				}
			});

			let store: Arc<dyn CertificateTrust> = Arc::new(server.store());
			let builder = ConnectionPool::<TokioListener>::builder().with_trust_store(store);
			(pool_of_one(builder, Some(TransportOffer::mux(4)), trace), addr)
		}

		/// The address `listener` takes dials on.
		fn address_of(listener: &TcpListener) -> TightBeamSocketAddr {
			TightBeamSocketAddr(listener.local_addr().expect("a bound listener has an address"))
		}

		/// Polls `settled` every [`SETTLE_INTERVAL`] for up to
		/// [`SETTLE_ATTEMPTS`] reads, and asserts that it held. The socket work
		/// it waits on runs on other tasks.
		async fn await_settled(mut settled: impl FnMut() -> bool) {
			let mut attempts = 0;
			while !settled() && attempts < SETTLE_ATTEMPTS {
				tokio::time::sleep(SETTLE_INTERVAL).await;
				attempts += 1;
			}

			assert!(settled(), "the pool state settles");
		}

		/// Whether the pool holds idle connections to `addr` and each one has
		/// lost its peer.
		fn idle_leases_dead(pool: &ConnectionPool<TokioListener>, addr: &TightBeamSocketAddr) -> bool {
			let pools = pool.pools.read().expect("the pool map is unpoisoned");
			pools.get(addr).is_some_and(|dest_pool| {
				let idle = &dest_pool.available;
				let dead = idle.iter().all(|entry| {
					let transport = entry.client.transport();
					!<TokioListener as PersistentConnection>::is_connected(transport)
				});
				!idle.is_empty() && dead
			})
		}

		/// Whether the pool holds mux connections to `addr` and the reader of
		/// each one has ended.
		fn mux_connections_ended(pool: &ConnectionPool<TokioListener>, addr: &TightBeamSocketAddr) -> bool {
			let pools = pool.pools.read().expect("the pool map is unpoisoned");
			pools.get(addr).is_some_and(|dest_pool| {
				let held = &dest_pool.mux;
				!held.is_empty() && held.iter().all(|entry| entry.drivers.is_finished())
			})
		}

		/// Whether a connect to `addr` dials a connection of its own. In a pool
		/// of one, it does only when the pool holds and counts no other.
		///
		/// # Errors
		///
		/// - [`TransportFailure::ResourceExhausted`] -- the pool counts the connection that left as live.
		/// - [`TransportError`] -- any other error of [`ConnectionPool::connect`].
		async fn connects_fresh(
			pool: &Arc<ConnectionPool<TokioListener>>,
			addr: TightBeamSocketAddr,
			trace: &TraceCollector,
		) -> TransportResult<bool> {
			let dials_before = trace.recorded(events::POOL_DIAL);
			let _lease = pool.connect(addr).await?;
			Ok(trace.recorded(events::POOL_DIAL) == dials_before + 1)
		}

		/// An idle exclusive connection whose peer reset it leaves the pool
		/// when a connect finds it, before the fault at its eviction reaches
		/// that connect.
		#[tokio::test]
		async fn a_fault_at_evicting_a_dead_idle_lease_reaches_the_connect() -> TransportResult<()> {
			let trace = faulting_trace();
			let (pool, listener) = exclusive_pool(&trace).await;
			let addr = address_of(&listener);
			let lease = pool.connect(addr).await?;
			let (served, _) = listener.accept().await?;
			drop(lease);
			served.set_zero_linger()?;
			drop(served);
			await_settled(|| idle_leases_dead(&pool, &addr)).await;

			let evicted = pool.connect(addr).await;
			assert!(matches!(evicted, Err(TransportError::InvalidAddress)));
			assert!(connects_fresh(&pool, addr, &trace).await?);
			Ok(())
		}

		/// A mux connection whose reader ended leaves the pool when a connect
		/// finds it, before the fault at its eviction reaches that connect.
		#[tokio::test]
		async fn a_fault_at_evicting_an_ended_mux_connection_reaches_the_connect() -> TransportResult<()> {
			let trace = faulting_trace();
			let (pool, addr) = mux_pool(&trace).await;
			drop(pool.connect(addr).await?);
			await_settled(|| mux_connections_ended(&pool, &addr)).await;

			let evicted = pool.connect(addr).await;
			assert!(matches!(evicted, Err(TransportError::InvalidAddress)));
			assert!(connects_fresh(&pool, addr, &trace).await?);
			Ok(())
		}

		/// An emit that meets a closed mux connection evicts it, and the fault
		/// at the eviction reaches the emit after the connection left the pool.
		#[tokio::test]
		async fn a_fault_at_evicting_after_a_closed_emit_reaches_the_emit() -> TransportResult<()> {
			let trace = faulting_trace();
			let (pool, addr) = mux_pool(&trace).await;
			let mut lease = pool.connect(addr).await?;
			await_settled(|| mux_connections_ended(&pool, &addr)).await;

			let emitted = lease.emit(TestFrame::v0(None, None), None).await;
			assert!(matches!(emitted, Err(TransportError::InvalidAddress)));
			assert!(connects_fresh(&pool, addr, &trace).await?);
			Ok(())
		}

		/// A discarded mux lease evicts its connection, and the fault at the
		/// eviction reaches the discard after the connection left the pool.
		#[tokio::test]
		async fn a_fault_at_discarding_a_mux_lease_reaches_the_discard() -> TransportResult<()> {
			let trace = faulting_trace();
			let (pool, addr) = mux_pool(&trace).await;
			let lease = pool.connect(addr).await?;

			let discarded = lease.discard();
			assert!(matches!(discarded, Err(TransportError::InvalidAddress)));
			assert!(connects_fresh(&pool, addr, &trace).await?);
			Ok(())
		}

		/// A discarded exclusive lease closes its connection, and the fault at
		/// the eviction reaches the discard after the connection left the pool.
		#[tokio::test]
		async fn a_fault_at_discarding_an_exclusive_lease_reaches_the_discard() -> TransportResult<()> {
			let trace = faulting_trace();
			let (pool, listener) = exclusive_pool(&trace).await;
			let addr = address_of(&listener);
			let lease = pool.connect(addr).await?;

			let discarded = lease.discard();
			assert!(matches!(discarded, Err(TransportError::InvalidAddress)));
			assert!(connects_fresh(&pool, addr, &trace).await?);
			Ok(())
		}
	}

	/// A destination whose peer keeps each connection open past its GoAway
	/// holds no more drivers on its draining shelf than its connection cap
	/// (CWE-400).
	#[cfg(all(pooled_mux, feature = "transport-cms", feature = "testing"))]
	mod draining {
		use super::*;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::testing::TestCmsServer;
		use crate::transport::multiplex::MuxAcceptor;
		use crate::transport::tcp::TightBeamSocketAddr;
		use crate::transport::{EncryptedProtocol, TokioListener, TransportEncryptionConfig};
		use crate::utils::time::ManualClock;

		/// The idle timeout of the pool, which the test clock passes at once.
		const IDLE: Duration = Duration::from_secs(1);

		/// A multiplexed pool of one connection on `clock`, whose idle
		/// connections leave at [`IDLE`], beside the address of a test server
		/// that holds each connection open once its mux negotiation ends.
		async fn holding_pool(clock: &Arc<ManualClock>) -> (Arc<ConnectionPool<TokioListener>>, TightBeamSocketAddr) {
			let server = TestCmsServer::generate("Holding Server");
			let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(server.signing_identity());
			let bind = TightBeamSocketAddr("127.0.0.1:0".parse().expect("a loopback address parses"));
			let (listener, addr) = TokioListener::bind_with(bind, config).await.expect("the test server binds");
			tokio::spawn(async move {
				let mut held = Vec::new();
				while let Ok((transport, _)) = listener.accept().await {
					let mut transport = transport.with_mux_offer(Some(TransportOffer::mux(4)));
					// The connection stays open whatever the negotiation
					// answered, as a peer that never closes after its GoAway.
					let _negotiated = transport.negotiate_mux().await;
					held.push(transport);
				}
			});

			let store: Arc<dyn CertificateTrust> = Arc::new(server.store());
			let offer = Some(Arc::new(TransportOffer::mux(4)));
			let config = PoolConfig { idle_timeout: Some(IDLE), max_connections: NonZeroUsize::MIN, mux_offer: offer };
			let builder = ConnectionPool::<TokioListener>::builder().with_trust_store(store);
			let pool = builder
				.with_clock(Arc::clone(clock) as Arc<dyn Clock>)
				.with_config(config)
				.build();
			(Arc::new(pool), addr)
		}

		/// Leases a connection to `addr` and idles it past [`IDLE`], so the
		/// next lease prunes it onto the shelf.
		async fn idle_one(
			pool: &Arc<ConnectionPool<TokioListener>>,
			addr: TightBeamSocketAddr,
			clock: &ManualClock,
		) -> TransportResult<()> {
			drop(pool.connect(addr).await?);
			clock.advance(IDLE);
			Ok(())
		}

		/// The drivers the draining shelf of `addr` holds.
		fn shelved(pool: &ConnectionPool<TokioListener>, addr: &TightBeamSocketAddr) -> usize {
			let pools = pool.pools.read().expect("the pool map is unpoisoned");
			pools.get(addr).map_or(0, |dest_pool| dest_pool.draining.drivers.len())
		}

		#[tokio::test]
		async fn the_draining_shelf_holds_no_more_than_the_connection_cap() -> TransportResult<()> {
			let clock = Arc::new(ManualClock::default());
			let (pool, addr) = holding_pool(&clock).await;
			idle_one(&pool, addr, &clock).await?;
			idle_one(&pool, addr, &clock).await?;
			idle_one(&pool, addr, &clock).await?;

			let _live = pool.connect(addr).await?;
			assert_eq!(shelved(&pool, &addr), 1);
			Ok(())
		}
	}
}
