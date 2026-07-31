//! Connection pooling for the transport layer.

use core::hash::Hash;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

#[cfg(feature = "std")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "std")]
use std::sync::{Arc, RwLock, RwLockWriteGuard};
#[cfg(feature = "std")]
use std::time::Instant;

use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::CryptoProvider;
use crate::transport::client::GenericClient;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::handshake::negotiation::TransportOffer;
use crate::transport::handshake::HandshakeKeyManager;
use crate::transport::protocols::{PersistentConnection, Protocol};
use crate::transport::MessageCollector;
use crate::transport::{TransportResult, X509ClientConfig};

#[cfg(feature = "aes-gcm")]
use crate::crypto::profiles::DefaultCryptoProvider;
#[cfg(not(feature = "x509"))]
use crate::transport::client::ClientBuilder;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::crypto::x509::{Certificate, CertificateSpec};
	pub use crate::transport::handshake::receipt::ReceiptApprover;
	pub use crate::transport::handshake::HandshakeProtocolKind;
}

#[cfg(feature = "x509")]
use x509::*;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::transport::policy::PolicyConfig;
	pub use crate::transport::MessageEmitter;
	pub use crate::Frame;
}

#[cfg(feature = "transport-policy")]
use policy::*;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(feature = "instrument")]
use crate::trace::TraceCollector;
#[cfg(feature = "instrument")]
use crate::utils::urn::Urn;

/// Item gate for the pooled-mux path: multiplexed pooling needs the mux
/// engine, the serve module's connector, and a tokio executor for the
/// driver tasks.
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

	use crate::runtime::rt;
	use crate::utils::marker::MaybeSend;
	use crate::transport::handshake::receipt::StoredReceipt;
	use crate::transport::multiplex::{MuxCapable, MuxConnector, MuxHandle, MuxRole, RequestSink, StreamBody};
	use crate::transport::serve::drive_mux;
}

/// Shared builder surface for direct clients and connection pools.
///
/// [`ClientBuilder`] and [`ConnectionPoolBuilder`] both implement this trait
/// so callers configure timeouts and identity the same way.
pub trait ConnectionBuilder<P: Protocol>: Sized {
	/// Built client or pool produced by [`ConnectionBuilder::build`].
	type Output;

	/// Cap how long a connect or I/O wait may block.
	fn with_timeout(self, timeout: Duration) -> Self;

	/// Trust anchors used to validate the peer certificate.
	#[cfg(feature = "x509")]
	fn with_trust_store(self, store: Arc<dyn CertificateTrust>) -> Self;

	/// Client certificate and key for mutual authentication.
	#[cfg(feature = "x509")]
	fn with_client_identity(self, cert: CertificateSpec, key: Arc<dyn SigningKeyProvider>) -> TransportResult<Self>;

	/// Finish configuration and produce the client or pool.
	fn build(self) -> Self::Output;
}

/// Limits and multiplexing policy for a [`ConnectionPool`].
#[derive(Clone, Debug)]
pub struct PoolConfig {
	/// Drop idle exclusive leases after this duration.
	///
	/// `None` keeps idle connections until the pool evicts them for other reasons.
	pub idle_timeout: Option<Duration>,
	/// Hard cap on live connections across all destinations (default: 64).
	pub max_connections: usize,
	/// Multiplexing advertisement for pooled dials.
	///
	/// When set, `connect` reuses one multiplexed connection per destination
	/// until stream caps fill. The value is shared by refcount across dials.
	/// The handshake still clones the offer once into the orchestrator.
	pub mux_offer: Option<Arc<TransportOffer>>,
}

impl Default for PoolConfig {
	fn default() -> Self {
		Self { idle_timeout: None, max_connections: 64, mux_offer: None }
	}
}

#[cfg(feature = "x509")]
#[derive(Clone)]
/// Client authentication bundle kept behind Arc for zero-copy reuse.
struct ClientIdentity<C: CryptoProvider = DefaultCryptoProvider> {
	certificate: Arc<Certificate>,
	key: Arc<HandshakeKeyManager<C>>,
}

#[cfg(feature = "x509")]
#[derive(Clone, Default)]
/// Shared TLS assets reused across pooled connections without reallocations.
struct PoolTlsConfig<C: CryptoProvider = DefaultCryptoProvider> {
	trust_store: Option<Arc<dyn CertificateTrust>>,
	client_identity: Option<ClientIdentity<C>>,
	server_certificate_chain: Option<Arc<[Certificate]>>,
	handshake_protocol: Option<HandshakeProtocolKind>,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
}

#[cfg(feature = "x509")]
impl<C: CryptoProvider> PoolTlsConfig<C> {
	fn set_trust_store(&mut self, store: Arc<dyn CertificateTrust>) {
		self.trust_store = Some(store);
	}

	fn set_client_identity(&mut self, cert: Certificate, key: HandshakeKeyManager<C>) {
		self.set_shared_client_identity(Arc::new(cert), Arc::new(key));
	}

	fn set_shared_client_identity(&mut self, certificate: Arc<Certificate>, key: Arc<HandshakeKeyManager<C>>) {
		self.client_identity = Some(ClientIdentity { certificate, key });
	}

	fn set_server_certificate_chain(&mut self, chain: Arc<[Certificate]>) {
		self.server_certificate_chain = Some(chain);
	}

	fn set_handshake_protocol(&mut self, kind: HandshakeProtocolKind) {
		self.handshake_protocol = Some(kind);
	}

	fn set_receipt_approver(&mut self, approver: Arc<dyn ReceiptApprover>) {
		self.receipt_approver = Some(approver);
	}

	fn apply<Pro>(&self, transport: Pro::Transport) -> Pro::Transport
	where
		Pro: Protocol,
		Pro::Transport: MessageEmitter + MessageCollector + PolicyConfig + X509ClientConfig<CryptoProvider = C>,
	{
		let mut configured = transport;
		if let Some(store) = &self.trust_store {
			let store = Arc::clone(store);
			configured = configured.with_trust_store(store);
		}
		if let Some(identity) = &self.client_identity {
			let cert = Arc::clone(&identity.certificate);
			let key = Arc::clone(&identity.key);
			configured = configured.with_client_identity(cert, key);
		}
		if let Some(chain) = &self.server_certificate_chain {
			let chain = Arc::clone(chain);
			configured = configured.with_server_certificate_chain(chain);
		}
		if let Some(kind) = self.handshake_protocol {
			configured = configured.with_handshake_protocol(kind);
		}
		if let Some(approver) = &self.receipt_approver {
			let approver = Arc::clone(approver);
			configured = configured.with_receipt_approver(approver);
		}

		configured
	}
}

/// Builder for creating a configured ConnectionPool
pub struct ConnectionPoolBuilder<P: Protocol, C: CryptoProvider = DefaultCryptoProvider> {
	config: PoolConfig,
	timeout: Option<Duration>,
	#[cfg(feature = "x509")]
	tls: PoolTlsConfig<C>,
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
	_phantom: PhantomData<(P, C)>,
}

impl<P: Protocol, C: CryptoProvider> Default for ConnectionPoolBuilder<P, C> {
	fn default() -> Self {
		Self {
			config: PoolConfig::default(),
			timeout: None,
			#[cfg(feature = "x509")]
			tls: PoolTlsConfig::default(),
			#[cfg(feature = "instrument")]
			trace: None,
			_phantom: PhantomData,
		}
	}
}

impl<P: Protocol, C: CryptoProvider> ConnectionPoolBuilder<P, C> {
	pub fn with_config(mut self, config: PoolConfig) -> Self {
		self.config = config;
		self
	}

	/// Production instrumentation collector: the single clientside
	/// entrypoint. The pool emits its own lifecycle events and
	/// propagates the collector to every dialed transport.
	#[cfg(feature = "instrument")]
	#[must_use]
	pub fn with_trace(mut self, trace: TraceCollector) -> Self {
		self.trace = Some(trace);
		self
	}

	/// Provision the expected server certificate chain, ordered root to
	/// leaf, shared by every pooled connection.
	#[cfg(feature = "x509")]
	pub fn with_server_certificate_chain(mut self, chain: impl Into<Arc<[Certificate]>>) -> Self {
		self.tls.set_server_certificate_chain(chain.into());
		self
	}

	/// Select the handshake protocol used by every pooled connection.
	#[cfg(feature = "x509")]
	pub fn with_handshake_protocol(mut self, kind: HandshakeProtocolKind) -> Self {
		self.tls.set_handshake_protocol(kind);
		self
	}

	/// Receipt approver for every dialed transport: consulted before
	/// countersigning at the handshake and each in-band epoch renewal.
	/// Without one, pooled clients fail closed on challenge-bearing receipts.
	#[cfg(feature = "x509")]
	pub fn with_receipt_approver(mut self, approver: Arc<dyn ReceiptApprover>) -> Self {
		self.tls.set_receipt_approver(approver);
		self
	}

	/// Install a pre-shared client identity (zero extra cert materialization)
	#[cfg(feature = "x509")]
	pub fn with_shared_client_identity(
		mut self,
		certificate: Arc<Certificate>,
		key: Arc<HandshakeKeyManager<C>>,
	) -> Self {
		self.tls.set_shared_client_identity(certificate, key);
		self
	}
}

#[cfg(feature = "std")]
impl<P: Protocol, C: CryptoProvider + Send + Sync + 'static> ConnectionBuilder<P> for ConnectionPoolBuilder<P, C> {
	type Output = ConnectionPool<P, C>;

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	#[cfg(feature = "x509")]
	fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.tls.set_trust_store(store);
		self
	}

	#[cfg(feature = "x509")]
	fn with_client_identity(
		mut self,
		cert: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
	) -> TransportResult<Self> {
		let cert_converted = Certificate::try_from(cert)?;
		let key_converted: HandshakeKeyManager<C> = HandshakeKeyManager::new(key);

		self.tls.set_client_identity(cert_converted, key_converted);
		Ok(self)
	}

	fn build(self) -> Self::Output {
		ConnectionPool {
			pools: Arc::new(RwLock::new(HashMap::new())),
			config: self.config,
			timeout: self.timeout,
			total_connections: Arc::new(AtomicUsize::new(0)),
			#[cfg(pooled_mux)]
			mux_ids: AtomicU64::new(0),
			#[cfg(feature = "x509")]
			tls: self.tls,
			#[cfg(feature = "instrument")]
			trace: self.trace,
		}
	}
}

#[cfg(feature = "std")]
struct AvailableEntry<P: Protocol> {
	client: GenericClient<P>,
	last_used: Instant,
}

pooled_mux! {
	/// One shared multiplexed connection to a destination.
	///
	/// The handle is cloneable, so entries are never leased exclusively and
	/// leave the pool only through eviction.
	struct MuxEntry {
		id: u64,
		handle: MuxHandle,
		/// Reader driver task used as the entry liveness witness.
		///
		/// The task ends when the connection dies.
		reader_task: rt::JoinHandle,
		/// Shared activity stamp used by idle pruning for this mux entry.
		///
		/// The mux core does not read a clock. Each lease updates this stamp
		/// when emit starts, outside the pool lock. An entry with pending
		/// streams stays active even if the stamp is old.
		last_used: Arc<Mutex<Instant>>,
		/// Validated peer certificate pinned at the eager mux handshake.
		///
		/// The mux drivers consume the transport, so the certificate is
		/// captured at dial. Every lease on this entry reads peer
		/// identity from this shared handle.
		peer_certificate: Option<Arc<Certificate>>,
	}
}

/// Per-destination connection pool
#[cfg(feature = "std")]
struct DestinationPool<P: Protocol> {
	/// Available connections ready for reuse
	available: VecDeque<AvailableEntry<P>>,
	/// Shared multiplexed connections (never leased exclusively)
	#[cfg(pooled_mux)]
	mux: Vec<MuxEntry>,
}

#[cfg(feature = "std")]
impl<P: Protocol> Default for DestinationPool<P> {
	fn default() -> Self {
		Self {
			available: VecDeque::new(),
			#[cfg(pooled_mux)]
			mux: Vec::new(),
		}
	}
}

/// Connection pool for protocol P with global connection limit
///
/// # Invariants
/// - `total_connections` counts live connections and stays within
///   `0..=config.max_connections`: +1 when a socket is created.
/// - Idle connections exceeding `PoolConfig::idle_timeout` are pruned lazily
/// - Lock poisoning never panics. Callers receive `TransportFailure::Internal` instead
#[cfg(feature = "std")]
pub struct ConnectionPool<P: Protocol, C: CryptoProvider = DefaultCryptoProvider> {
	/// Per-destination sub-pools
	pools: Arc<RwLock<HashMap<P::Address, DestinationPool<P>>>>,
	/// Pool configuration
	config: PoolConfig,
	/// Shared timeout for all connections
	timeout: Option<Duration>,
	/// Total connections across all destinations
	total_connections: Arc<AtomicUsize>,
	/// Monotonic IDs correlating mux pool entries with their leases
	#[cfg(pooled_mux)]
	mux_ids: AtomicU64,
	/// Shared TLS assets reused across pooled connections
	#[cfg(feature = "x509")]
	tls: PoolTlsConfig<C>,
	/// Production instrumentation collector (single clientside entrypoint)
	#[cfg(feature = "instrument")]
	trace: Option<TraceCollector>,
}

#[cfg(feature = "std")]
impl<P: Protocol, C: CryptoProvider> ConnectionPool<P, C> {
	/// Decrement the live-connection count for a discarded connection,
	/// saturating at zero so an accounting defect can never wrap the counter
	/// and wedge the pool into permanent refusal.
	fn release_connection_count(&self) {
		let _ = self
			.total_connections
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| current.checked_sub(1));
	}

	/// Dual-write a pool lifecycle event: core kind URN into the
	/// instrument log, plus the stable label for spec assertions and
	/// CSP alphabets.
	#[cfg(feature = "instrument")]
	fn emit_event(&self, event: Urn<'static>) {
		let Some(trace) = self.trace.as_ref() else {
			return;
		};

		trace.emit_event(event);
	}
}

#[cfg(feature = "std")]
impl<P: Protocol + Send + Sync, C: CryptoProvider + Send + Sync + 'static> ConnectionPool<P, C>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	/// Create a new connection pool builder
	pub fn builder() -> ConnectionPoolBuilder<P, C> {
		ConnectionPoolBuilder::default()
	}

	fn wrap_client(self: &Arc<Self>, client: GenericClient<P>, addr: P::Address) -> PooledClient<P, C>
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

	#[cfg(not(feature = "x509"))]
	fn apply_timeout_to_builder<B>(&self, builder: B) -> B
	where
		B: ConnectionBuilder<P>,
	{
		if let Some(timeout) = self.timeout {
			builder.with_timeout(timeout)
		} else {
			builder
		}
	}

	fn try_take_ready_client(self: &Arc<Self>, addr: &P::Address) -> TransportResult<Option<GenericClient<P>>>
	where
		P: PersistentConnection,
	{
		let mut pools = self.write_pools()?;
		if let Some(dest_pool) = pools.get_mut(addr) {
			self.prune_idle_locked(dest_pool, Instant::now());

			while let Some(entry) = dest_pool.available.pop_front() {
				if <P as PersistentConnection>::is_connected(entry.client.transport()) {
					#[cfg(feature = "instrument")]
					self.emit_event(events::POOL_REUSE_READY);

					return Ok(Some(entry.client));
				}

				// Dead candidate is discarded here, so it leaves the live set.
				self.release_connection_count();

				#[cfg(feature = "instrument")]
				self.emit_event(events::POOL_EVICTED);
			}
		}
		Ok(None)
	}

	fn reserve_slot(self: &Arc<Self>, addr: &P::Address) -> TransportResult<SlotGuard<P, C>> {
		// Single atomic check-and-increment so concurrent callers cannot all
		// pass a separate limit check and overshoot max_connections.
		let reserved = self
			.total_connections
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
				if current >= self.config.max_connections {
					None
				} else {
					Some(current + 1)
				}
			});
		if reserved.is_err() {
			#[cfg(feature = "instrument")]
			self.emit_event(events::POOL_EXHAUSTED);

			return Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted));
		}

		// A poisoned pool map must not leak the reservation: give the
		// counter back before surfacing the failure.
		let mut pools = match self.write_pools() {
			Ok(pools) => pools,
			Err(err) => {
				self.release_connection_count();
				return Err(err);
			}
		};

		let dest_pool = pools.entry(addr.clone()).or_default();
		self.prune_idle_locked(dest_pool, Instant::now());

		Ok(SlotGuard::new(Arc::clone(self)))
	}

	fn prune_idle_locked(&self, dest_pool: &mut DestinationPool<P>, now: Instant) {
		let Some(timeout) = self.config.idle_timeout else {
			return;
		};

		while let Some(entry) = dest_pool.available.front() {
			if now.duration_since(entry.last_used) >= timeout {
				dest_pool.available.pop_front();
				// Pruned idle connection is closed, so it leaves the live set.
				self.release_connection_count();

				#[cfg(feature = "instrument")]
				self.emit_event(events::POOL_PRUNED_IDLE);
			} else {
				break;
			}
		}

		// Shared mux entries are stamped by their leases at emit time
		// (emits bypass the pool lock), so the pruner only reads. An
		// in-flight stream pins the entry as active no matter how old
		// the stamp is.
		#[cfg(pooled_mux)]
		dest_pool.mux.retain(|entry| {
			if entry.handle.has_pending_streams() {
				return true;
			}

			let last_used = *entry.last_used.lock().unwrap_or_else(PoisonError::into_inner);
			let expired = now.duration_since(last_used) >= timeout;
			if expired {
				// GoAway before close (RFC 9113 § 6.8): the reader task
				// ends on the resulting EOF. A stream racing this drain
				// observes `Draining`, which the lease lifecycle already
				// maps to eviction.
				let handle = entry.handle.clone();
				rt::spawn(async move {
					let _ = handle.shutdown().await;
				});

				// Pruned idle connection leaves the live set.
				self.release_connection_count();
				#[cfg(feature = "instrument")]
				self.emit_event(events::POOL_PRUNED_IDLE);
			}

			!expired
		});
	}

	#[cfg(not(feature = "x509"))]
	pub async fn connect(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, C>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig + Send + Sync,
	{
		if let Some(client) = self.try_take_ready_client(&addr)? {
			return Ok(self.wrap_client(client, addr));
		}

		let mut reservation = self.reserve_slot(&addr)?;
		let builder = self.apply_timeout_to_builder(ClientBuilder::<P, C>::builder());
		let builder = ConnectionBuilder::build(builder);
		let client = builder.connect(addr.clone()).await?;

		#[cfg(feature = "instrument")]
		self.emit_event(events::POOL_DIAL);

		reservation.disarm();

		Ok(self.wrap_client(client, addr))
	}

	/// Lease a ready connection or open a fresh one, held exclusively.
	#[cfg(feature = "x509")]
	async fn connect_single_flight(self: &Arc<Self>, addr: &P::Address) -> TransportResult<PooledClient<P, C>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport:
			MessageEmitter + MessageCollector + PolicyConfig + X509ClientConfig<CryptoProvider = C> + Send + Sync,
	{
		if let Some(client) = self.try_take_ready_client(addr)? {
			return Ok(self.wrap_client(client, addr.clone()));
		}

		let mut reservation = self.reserve_slot(addr)?;
		let stream = P::connect(addr.clone()).await.map_err(|e| e.into())?;

		let mut transport = self.tls.apply::<P>(P::create_transport(stream));
		if let Some(timeout) = self.timeout {
			transport = transport.with_timeout(timeout);
		}

		#[cfg(feature = "instrument")]
		if let Some(trace) = self.trace.as_ref() {
			transport = transport.with_trace(trace.share());
		}

		#[cfg(feature = "instrument")]
		self.emit_event(events::POOL_DIAL);

		let client = GenericClient::from_transport_with_addr(transport, addr.clone());

		reservation.disarm();

		Ok(self.wrap_client(client, addr.clone()))
	}

	#[cfg(all(
		feature = "x509",
		not(all(
			feature = "tokio",
			feature = "transport-policy",
			feature = "transport-multiplex",
			any(feature = "transport-cms", feature = "transport-ecies")
		))
	))]
	pub async fn connect(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, C>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport:
			MessageEmitter + MessageCollector + PolicyConfig + X509ClientConfig<CryptoProvider = C> + Send + Sync,
	{
		self.connect_single_flight(&addr).await
	}

	pub fn try_acquire(self: &Arc<Self>, addr: &P::Address) -> TransportResult<Option<PooledClient<P, C>>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConfig + Send + Sync,
	{
		let maybe_client = self.try_take_ready_client(addr)?;
		Ok(maybe_client.map(|client| self.wrap_client(client, addr.clone())))
	}
}

// Separate impl with tighter bounds for non-x509 features
#[cfg(feature = "std")]
#[cfg(not(feature = "x509"))]
impl<P: Protocol + Send + Sync, C: CryptoProvider + Send + Sync + 'static> ConnectionPool<P, C>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
}

pooled_mux! {
	impl<P: Protocol + Send + Sync, C: CryptoProvider + Send + Sync + 'static> ConnectionPool<P, C>
	where
		P: PersistentConnection,
		P::Address: Hash + Eq + Clone + Send + Sync,
		P::Transport: MessageEmitter
			+ MessageCollector
			+ PolicyConfig
			+ X509ClientConfig<CryptoProvider = C>
			+ MuxConnector
			+ Send
			+ Sync,
	{
		/// Connect to a destination, multiplexing when
		/// [`PoolConfig::mux_offer`] is set and the peer accepts.
		pub async fn connect(
			self: &Arc<Self>,
			addr: impl core::borrow::Borrow<P::Address>,
		) -> TransportResult<PooledClient<P, C>>
		where
			P::Address: Clone,
		{
			let addr = addr.borrow();
			if self.config.mux_offer.is_none() {
				return self.connect_single_flight(addr).await;
			}

			self.acquire_mux(addr, MuxSelection::PreferHeadroom).await
		}

		/// Acquire a mux lease through the reuse tiers, in order.
		///
		/// Tries a pooled mux entry first. Next tries an idle exclusive lease
		/// left when a peer declined multiplexing. Finally opens a fresh dial.
		/// All mux-offering callers share this path so no tier is skipped.
		async fn acquire_mux(
			self: &Arc<Self>,
			addr: &P::Address,
			selection: MuxSelection,
		) -> TransportResult<PooledClient<P, C>> {
			if let Some(lease) = self.try_take_mux_handle(addr, selection)? {
				return Ok(self.wrap_mux_client(lease, addr.clone()));
			}

			if let Some(client) = self.try_take_ready_client(addr)? {
				return Ok(self.wrap_client(client, addr.clone()));
			}

			let offer = match &self.config.mux_offer {
				// One shared PoolConfig offer for every dial.
				Some(offer) => Arc::clone(offer),
				None => {
					return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
				}
			};

			self.open_mux_connection(addr.clone(), offer).await
		}

		/// Open a fresh connection with a mux offer, falling back to an
		/// exclusive lease when the peer declines multiplexing.
		async fn open_mux_connection(
			self: &Arc<Self>,
			addr: P::Address,
			offer: Arc<TransportOffer>,
		) -> TransportResult<PooledClient<P, C>> {
			let mut reservation = self.reserve_slot(&addr)?;

			let stream = P::connect(addr.clone()).await.map_err(|e| e.into())?;
			let mut transport = self.tls.apply::<P>(P::create_transport(stream));
			if let Some(timeout) = self.timeout {
				transport = transport.with_timeout(timeout);
			}

			#[cfg(feature = "instrument")]
			if let Some(trace) = self.trace.as_ref() {
				transport = transport.with_trace(trace.share());
			}

			// Mux requires the negotiation result before first use, so the
			// handshake runs eagerly instead of on first emit.
			let mut transport = transport.with_mux_offer(Some(offer));
			transport.complete_client_handshake().await?;

			#[cfg(feature = "instrument")]
			self.emit_event(events::POOL_DIAL);

			let settings = match transport.negotiated_mux() {
				Some(settings) => settings,
				None => {
					// Peer declined the mux offer: the connection pools as
					// an exclusive lease instead.
					#[cfg(feature = "instrument")]
					self.emit_event(events::POOL_MUX_DECLINED);

					let client = GenericClient::from_transport_with_addr(transport, addr.clone());

					reservation.disarm();

					return Ok(self.wrap_client(client, addr));
				}
			};

			// The mux drivers consume the transport below, so this is the
			// last point where the handshake certificate is readable.
			let peer_certificate = transport.handshake_peer_certificate();

			let rekey = transport.take_rekey()?;
			let (reader, writer) = transport.into_envelope_halves()?;
			let (handle, responder, reader_task) = drive_mux(reader, writer, MuxRole::Client, settings, None, rekey);

			// Pool endpoints never serve peer-initiated streams: dropping
			// the responder auto-refuses them.
			drop(responder);

			let id = self.mux_ids.fetch_add(1, Ordering::Relaxed);
			let last_used = Arc::new(Mutex::new(Instant::now()));

			{
				// A failed lock must not leak the spawned drivers: aborting
				// the reader closes the connection and ends the writer.
				let mut pools = match self.write_pools() {
					Ok(pools) => pools,
					Err(err) => {
						rt::abort(&reader_task);
						return Err(err);
					}
				};

				let dest_pool = pools.entry(addr.clone()).or_default();

				// Handle clone is a refcount bump: pool entry and lease co-own the connection.
				dest_pool.mux.push(MuxEntry {
					id,
					handle: handle.clone(),
					reader_task,
					last_used: Arc::clone(&last_used),
					peer_certificate: peer_certificate.clone(),
				});
			}

			reservation.disarm();

			let lease = MuxLease { id, handle, last_used, peer_certificate };
			Ok(self.wrap_mux_client(lease, addr))
		}

		/// Round-robin a live mux entry for the destination: prunes idle
		/// entries, evicts those whose reader driver already ended, and
		/// prefers entries with stream headroom over saturated ones.
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

			self.prune_idle_locked(dest_pool, Instant::now());

			dest_pool.mux.retain(|entry| {
				let alive = !entry.reader_task.is_finished();
				if !alive {
					// Dead mux connection is discarded here, so it leaves
					// the live set.
					self.release_connection_count();

					#[cfg(feature = "instrument")]
					self.emit_event(events::POOL_EVICTED);
				}
				alive
			});

			if dest_pool.mux.len() > 1 {
				dest_pool.mux.rotate_left(1);
			}

			let with_headroom = dest_pool.mux.iter().find(|entry| entry.handle.has_stream_headroom());
			let fallback = match selection {
				// A saturated entry stays shareable: an in-flight stream
				// may finish before the caller emits.
				MuxSelection::PreferHeadroom => dest_pool.mux.first(),
				// Cap-exhaustion failover must not land back on a
				// saturated entry, so it falls through to a fresh dial.
				MuxSelection::RequireHeadroom => None,
			};

			// Handle clone is a refcount bump: the entry stays pooled for other callers.
			let selected = with_headroom.or(fallback).map(MuxLease::from);

			#[cfg(feature = "instrument")]
			if selected.is_some() {
				self.emit_event(events::POOL_REUSE_MUX);
			}

			Ok(selected)
		}

		/// Remove a mux entry after a terminal failure (`ConnectionClosed`
		/// or rekey `Draining`). The next connect re-establishes.
		fn evict_mux(&self, addr: &P::Address, id: u64) {
			let mut pools = match self.pools.write() {
				Ok(pools) => pools,
				Err(_) => return,
			};
			if let Some(dest_pool) = pools.get_mut(addr) {
				let live_before = dest_pool.mux.len();

				dest_pool.mux.retain(|entry| entry.id != id);

				if dest_pool.mux.len() < live_before {
					// Evicted mux connection leaves the live set.
					self.release_connection_count();

					#[cfg(feature = "instrument")]
					self.emit_event(events::POOL_EVICTED);
				}
			}
		}

		fn wrap_mux_client(self: &Arc<Self>, lease: MuxLease, addr: P::Address) -> PooledClient<P, C> {
			let pool = Arc::clone(self);

			PooledClient {
				client: None,
				mux: Some(lease),
				pool,
				addr,
			}
		}
	}

	/// A caller's reference to one shared mux pool entry.
	struct MuxLease {
		id: u64,
		handle: MuxHandle,
		/// Shared with the pool entry: the lease stamps it on each emit
		/// so the pruner can read idle time without a clock in the mux
		/// core (see [`MuxEntry::last_used`]).
		last_used: Arc<Mutex<Instant>>,
		/// Shared handle to the entry's pinned peer certificate
		/// (see [`MuxEntry::peer_certificate`]).
		peer_certificate: Option<Arc<Certificate>>,
	}

	impl MuxLease {
		/// Record activity for the pruner. Stamped at emit start: the
		/// stream itself is covered by `has_pending_streams` while in
		/// flight.
		fn stamp(&self) {
			*self.last_used.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
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

	/// Mux entry selection policy for the acquisition funnel.
	#[derive(Clone, Copy)]
	enum MuxSelection {
		/// Prefer an entry with stream headroom, fall back to a saturated
		/// one (a slot may free before the caller emits)
		PreferHeadroom,
		/// Only an entry with stream headroom, `None` otherwise
		RequireHeadroom,
	}
}

/// A pooled client connection that returns to the pool on drop
///
/// Exclusive leases hold the connection alone. Multiplexed leases share
/// one connection with every other caller and return nothing on drop.
#[cfg(feature = "std")]
pub struct PooledClient<P: Protocol + PersistentConnection, C: CryptoProvider = DefaultCryptoProvider>
where
	P::Address: Hash + Eq + Send + Sync,
{
	client: Option<GenericClient<P>>,
	#[cfg(pooled_mux)]
	mux: Option<MuxLease>,
	pool: Arc<ConnectionPool<P, C>>,
	addr: P::Address,
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection, C: CryptoProvider> PooledClient<P, C>
where
	P::Address: Hash + Eq + Send + Sync,
{
	/// Returns a mutable reference to the underlying connection
	///
	/// # Errors
	/// - `InvalidState`: multiplexed lease. There is no exclusive
	///   connection to hand out. Use [`PooledClient::emit`]
	pub fn conn(&mut self) -> TransportResult<&mut GenericClient<P>> {
		self.client.as_mut().ok_or(TransportError::InvalidState)
	}

	/// Validated TLS peer certificate pinned by this connection's handshake
	///
	/// A mux lease answers from the certificate pinned at its eager dial
	/// handshake. An exclusive lease reads its transport, so the answer
	/// is `None` until the handshake completes. A caller that gates
	/// policy on peer identity MUST fail closed on `None`.
	#[cfg(feature = "x509")]
	pub fn peer_certificate(&self) -> Option<&Certificate>
	where
		P::Transport: crate::transport::state::EncryptedProtocolState,
	{
		use crate::transport::state::EncryptedProtocolState;

		#[cfg(pooled_mux)]
		if let Some(lease) = self.mux.as_ref() {
			return lease.peer_certificate.as_deref();
		}

		self.client.as_ref()?.transport().to_peer_certificate_ref()
	}
}

#[cfg(all(
	feature = "std",
	feature = "transport-policy",
	not(all(
		feature = "x509",
		feature = "tokio",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))
))]
impl<P: Protocol + PersistentConnection, C: CryptoProvider> PooledClient<P, C>
where
	P::Address: Hash + Eq + Send + Sync,
{
	/// Emit a message through the pooled connection.
	pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>>
	where
		P::Transport: MessageEmitter,
	{
		self.conn()?.emit(frame, attempt).await
	}
}

pooled_mux! {
	impl<P: Protocol + PersistentConnection + Send + Sync, C: CryptoProvider + Send + Sync + 'static> PooledClient<P, C>
	where
		P::Address: Hash + Eq + Clone + Send + Sync,
		P::Transport: MessageEmitter
			+ MessageCollector
			+ PolicyConfig
			+ X509ClientConfig<CryptoProvider = C>
			+ MuxConnector
			+ Send
			+ Sync,
	{
		/// Current epoch's dual-signed session receipt on a multiplexed
		/// lease, shared per connection across every lease and rotated
		/// in place by each completed in-band renewal. `None` on
		/// exclusive leases and on sessions without receipt-bearing
		/// rekey materials.
		pub fn session_receipt(&self) -> Option<Arc<StoredReceipt>> {
			self.mux.as_ref().and_then(|lease| lease.handle.session_receipt())
		}

		/// Emit a message through the pooled connection: a stream on the
		/// shared mux connection, or the exclusive lease.
		///
		/// Mux lifecycle handling:
		/// - `StreamsExhausted` (local stream cap full): moves to a pooled
		///   connection with stream headroom, or an additional one up to
		///   `max_connections`, and retries there once
		/// - `ConnectionClosed` / `Draining` (rekey GoAway): evicts the entry
		///   so the next connect re-establishes, then reports the failure
		pub async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
			// Handle clone is a refcount bump, releasing the `self.mux` borrow
			// before the failover arm takes `&mut self`.
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
					self.pool.evict_mux(&self.addr, lease_id);
					Err(err)
				}
				outcome => outcome,
			}
		}

		/// Warm the connection by completing its handshake without
		/// emitting an application frame.
		///
		/// Callers that gate on peer identity before disclosing a request
		/// drive this first so [`peer_certificate`](Self::peer_certificate)
		/// is populated.
		///
		/// - A mux lease already handshook eagerly at dial, so it returns at once.
		/// - A single-flight lease defers its handshake to the first
		///   [`emit`](Self::emit).
		pub(crate) async fn complete_handshake(&mut self) -> TransportResult<()> {
			if self.mux.is_some() {
				return Ok(());
			}

			self.conn()?.complete_handshake().await
		}

		/// Open a streamed request on the shared mux connection: push
		/// chunks through the sink, then await the unary response.
		///
		/// The stream counts as pending on the connection, so the pruner
		/// keeps the entry alive while it is in flight.
		///
		/// # Errors
		/// - `InvalidState`: exclusive lease - streaming needs the mux plane
		pub fn open_stream(
			&self,
		) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
			let lease = self.mux.as_ref().ok_or(TransportError::InvalidState)?;
			lease.stamp();

			lease.handle.open_stream()
		}

		/// Open a duplex stream on the shared mux connection: push request
		/// chunks through the sink while the peer's reply arrives
		/// incrementally through the body.
		///
		/// # Errors
		/// - `InvalidState`: exclusive lease - streaming needs the mux plane
		pub fn open_duplex(&self) -> TransportResult<(RequestSink, StreamBody)> {
			let lease = self.mux.as_ref().ok_or(TransportError::InvalidState)?;
			lease.stamp();

			lease.handle.open_duplex()
		}

		/// Cap-exhaustion failover: move the lease through the acquisition
		/// funnel (pooled headroom before a fresh dial) and retry there once.
		async fn emit_failover(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
			if self.pool.config.mux_offer.is_none() {
				// A mux lease exists only when an offer is configured
				return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted));
			}

			#[cfg(feature = "instrument")]
			self.pool.emit_event(events::POOL_FAILOVER);

			*self = self
				.pool
				.acquire_mux(&self.addr, MuxSelection::RequireHeadroom)
				.await?;

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
impl<P: Protocol + PersistentConnection, C: CryptoProvider> Drop for PooledClient<P, C>
where
	P::Address: Hash + Eq + Send + Sync,
{
	fn drop(&mut self) {
		let client = match self.client.take() {
			Some(client) => client,
			None => return,
		};

		#[cfg(feature = "instrument")]
		self.pool.emit_event(events::POOL_RELEASED);

		let mut returned_to_pool = false;

		let is_healthy = <P as PersistentConnection>::is_connected(client.transport());
		if let Ok(mut pools) = self.pool.pools.write() {
			if let Some(dest_pool) = pools.get_mut(&self.addr) {
				if is_healthy {
					dest_pool
						.available
						.push_back(AvailableEntry { client, last_used: Instant::now() });

					returned_to_pool = true;
				}
			}
		}

		// A connection parked in `available` is still live and stays counted.
		// Only a discarded (unhealthy or unparkable) connection leaves the set.
		if !returned_to_pool {
			self.pool.release_connection_count();
		}
	}
}

#[cfg(feature = "std")]
struct SlotGuard<P: Protocol, C: CryptoProvider = DefaultCryptoProvider>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	pool: Arc<ConnectionPool<P, C>>,
	active: bool,
}

#[cfg(feature = "std")]
impl<P: Protocol, C: CryptoProvider> SlotGuard<P, C>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn new(pool: Arc<ConnectionPool<P, C>>) -> Self {
		Self { pool, active: true }
	}

	fn disarm(&mut self) {
		self.active = false;
	}
}

#[cfg(feature = "std")]
impl<P: Protocol, C: CryptoProvider> Drop for SlotGuard<P, C>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn drop(&mut self) {
		if !self.active {
			return;
		}

		// The reserved connection never materialized, so it leaves the live set.
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
		assert_eq!(config.max_connections, 64);
	}

	#[test]
	fn test_pool_config_with_timeout() {
		let config = PoolConfig { idle_timeout: Some(Duration::from_secs(30)), ..PoolConfig::default() };
		assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
	}

	#[test]
	fn test_pool_config_with_max_connections() {
		let config = PoolConfig { max_connections: 16, ..PoolConfig::default() };
		assert_eq!(config.max_connections, 16);
	}
}
