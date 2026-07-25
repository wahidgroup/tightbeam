//! Connection pooling for transport layer

use core::hash::Hash;
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
	pub use crate::transport::handshake::HandshakeProtocolKind;
}

#[cfg(feature = "x509")]
use x509::*;

#[cfg(feature = "transport-policy")]
mod policy {
	pub use crate::transport::policy::PolicyConf;
	pub use crate::transport::MessageEmitter;
	pub use crate::Frame;
}

#[cfg(feature = "transport-policy")]
use policy::*;

/// Item gate for the pooled-mux path: multiplexed pooling needs the mux
/// engine, the serve module's connector, and a tokio executor for the
/// driver tasks.
macro_rules! pooled_mux {
	($($item:item)*) => {
		$(
			#[cfg(all(
				feature = "x509",
				feature = "tokio",
				feature = "transport-policy",
				feature = "transport-multiplex",
				any(feature = "transport-cms", feature = "transport-ecies")
			))]
			$item
		)*
	};
}

pooled_mux! {
	use core::sync::atomic::AtomicU64;
	use std::sync::{Mutex, PoisonError};

	use crate::runtime::rt;
	use crate::transport::multiplex::{MuxCapable, MuxConnector, MuxHandle, MuxRole};
	use crate::transport::serve::drive_mux;
}

/// Builder trait for connection configuration
///
/// Implemented by both ClientBuilder (for direct connections) and
/// ConnectionPoolBuilder (for pooled connections), enabling unified builder API.
pub trait ConnectionBuilder<P: Protocol>: Sized {
	/// The type returned by build()
	type Output;

	/// Configure timeout for operations
	fn with_timeout(self, timeout: Duration) -> Self;

	/// Configure trust store for server certificate validation
	#[cfg(feature = "x509")]
	fn with_trust_store(self, store: Arc<dyn CertificateTrust>) -> Self;

	/// Configure client identity for mutual TLS
	#[cfg(feature = "x509")]
	fn with_client_identity(self, cert: CertificateSpec, key: Arc<dyn SigningKeyProvider>) -> TransportResult<Self>;

	/// Build the configured builder/pool (sync)
	fn build(self) -> Self::Output;
}

/// Configuration for connection pool
#[derive(Clone, Debug)]
pub struct PoolConfig {
	/// Optional idle timeout for connections
	/// None means connections never expire
	pub idle_timeout: Option<Duration>,
	/// Maximum total connections in the pool (default: 64)
	pub max_connections: usize,
	/// Multiplexing advertisement for pooled connections. With an offer set,
	/// `connect` shares multiplexed connections per destination, opening
	/// additional ones only when stream caps fill.
	///
	/// TODO: store `Option<Arc<TransportOffer>>` on the config plane
	/// (pool / transport / orchestrator) so dials share by refcount;
	/// ASN.1 wire types stay owned. Today each fresh dial deep-copies.
	pub mux_offer: Option<TransportOffer>,
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
}

#[cfg(feature = "x509")]
impl<C: CryptoProvider> PoolTlsConfig<C> {
	fn set_trust_store(&mut self, store: Arc<dyn CertificateTrust>) {
		self.trust_store = Some(store);
	}

	fn set_client_identity(&mut self, cert: Certificate, key: HandshakeKeyManager<C>) {
		let certificate = Arc::new(cert);
		let key = Arc::new(key);

		self.client_identity = Some(ClientIdentity { certificate, key });
	}

	fn set_server_certificate_chain(&mut self, chain: Arc<[Certificate]>) {
		self.server_certificate_chain = Some(chain);
	}

	fn set_handshake_protocol(&mut self, kind: HandshakeProtocolKind) {
		self.handshake_protocol = Some(kind);
	}

	fn apply<Pro>(&self, transport: Pro::Transport) -> Pro::Transport
	where
		Pro: Protocol,
		Pro::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig<CryptoProvider = C>,
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

		configured
	}
}

/// Builder for creating a configured ConnectionPool
pub struct ConnectionPoolBuilder<P: Protocol, C: CryptoProvider = DefaultCryptoProvider> {
	config: PoolConfig,
	timeout: Option<Duration>,
	#[cfg(feature = "x509")]
	tls: PoolTlsConfig<C>,
	_phantom: core::marker::PhantomData<(P, C)>,
}

impl<P: Protocol, C: CryptoProvider> Default for ConnectionPoolBuilder<P, C> {
	fn default() -> Self {
		Self {
			config: PoolConfig::default(),
			timeout: None,
			#[cfg(feature = "x509")]
			tls: PoolTlsConfig::default(),
			_phantom: core::marker::PhantomData,
		}
	}
}

impl<P: Protocol, C: CryptoProvider> ConnectionPoolBuilder<P, C> {
	pub fn with_config(mut self, config: PoolConfig) -> Self {
		self.config = config;
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
			#[cfg(all(
				feature = "x509",
				feature = "tokio",
				feature = "transport-policy",
				feature = "transport-multiplex",
				any(feature = "transport-cms", feature = "transport-ecies")
			))]
			mux_ids: AtomicU64::new(0),
			#[cfg(feature = "x509")]
			tls: self.tls,
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
		/// Reader driver task: finishes when the connection dies, so it
		/// doubles as the entry's liveness witness.
		reader_task: rt::JoinHandle,
		/// When a lease last emitted on this connection.
		///
		/// The mux core never reads a clock
		/// ([sans-io](https://sans-io.readthedocs.io/how-to-sans-io.html), as
		/// [quinn-proto](https://docs.rs/quinn-proto) and [h2](https://docs.rs/h2)
		/// keep their state machines), so the pool stamps activity at its own
		/// emit boundary. This is the same recipe as
		/// [hyper-util's pool `idle_at`](https://docs.rs/hyper-util/latest/src/hyper_util/client/legacy/pool.rs.html).
		/// Shared with every lease, which stamps it outside the pool lock.
		/// While [`MuxHandle::has_pending_streams`] returns `true`, the pruner
		/// treats the entry as active no matter how old the stamp is.
		last_used: Arc<Mutex<Instant>>,
	}
}

/// Per-destination connection pool
#[cfg(feature = "std")]
struct DestinationPool<P: Protocol> {
	/// Available connections ready for reuse
	available: VecDeque<AvailableEntry<P>>,
	/// Number of connections currently in use
	in_use: usize,
	/// Shared multiplexed connections (never leased exclusively)
	#[cfg(all(
		feature = "x509",
		feature = "tokio",
		feature = "transport-policy",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	mux: Vec<MuxEntry>,
}

#[cfg(feature = "std")]
impl<P: Protocol> Default for DestinationPool<P> {
	fn default() -> Self {
		Self {
			available: VecDeque::new(),
			in_use: 0,
			#[cfg(all(
				feature = "x509",
				feature = "tokio",
				feature = "transport-policy",
				feature = "transport-multiplex",
				any(feature = "transport-cms", feature = "transport-ecies")
			))]
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
	#[cfg(all(
		feature = "x509",
		feature = "tokio",
		feature = "transport-policy",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	mux_ids: AtomicU64,
	/// Shared TLS assets reused across pooled connections
	#[cfg(feature = "x509")]
	tls: PoolTlsConfig<C>,
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
			#[cfg(all(
				feature = "x509",
				feature = "tokio",
				feature = "transport-policy",
				feature = "transport-multiplex",
				any(feature = "transport-cms", feature = "transport-ecies")
			))]
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
					dest_pool.in_use += 1;
					return Ok(Some(entry.client));
				}

				// Dead candidate is discarded here, so it leaves the live set.
				self.release_connection_count();
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
			return Err(TransportError::OperationFailed(TransportFailure::ResourceExhausted));
		}

		let mut pools = self.write_pools()?;
		let dest_pool = pools.entry(addr.clone()).or_default();

		self.prune_idle_locked(dest_pool, Instant::now());

		dest_pool.in_use += 1;

		let pool = Arc::clone(self);
		let addr = addr.clone();
		Ok(SlotGuard::new(pool, addr))
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
			} else {
				break;
			}
		}

		// Shared mux entries are stamped by their leases at emit time
		// (emits bypass the pool lock), so the pruner only reads. An
		// in-flight stream pins the entry as active no matter how old
		// the stamp is.
		#[cfg(all(
			feature = "x509",
			feature = "tokio",
			feature = "transport-policy",
			feature = "transport-multiplex",
			any(feature = "transport-cms", feature = "transport-ecies")
		))]
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
			}

			!expired
		});
	}

	#[cfg(not(feature = "x509"))]
	pub async fn connect(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, C>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
	{
		if let Some(client) = self.try_take_ready_client(&addr)? {
			return Ok(self.wrap_client(client, addr));
		}

		let mut reservation = self.reserve_slot(&addr)?;

		let builder = self.apply_timeout_to_builder(ClientBuilder::<P, C>::builder());
		let builder = ConnectionBuilder::build(builder);
		let client = builder.connect(addr.clone()).await?;

		reservation.disarm();

		Ok(self.wrap_client(client, addr))
	}

	/// Lease a ready connection or open a fresh one, held exclusively.
	#[cfg(feature = "x509")]
	async fn connect_single_flight(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, C>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport:
			MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig<CryptoProvider = C> + Send + Sync,
	{
		if let Some(client) = self.try_take_ready_client(&addr)? {
			return Ok(self.wrap_client(client, addr));
		}

		let mut reservation = self.reserve_slot(&addr)?;
		let stream = P::connect(addr.clone()).await.map_err(|e| e.into())?;

		let mut transport = self.tls.apply::<P>(P::create_transport(stream));
		if let Some(timeout) = self.timeout {
			transport = transport.with_timeout(timeout);
		}

		let client = GenericClient::from_transport_with_addr(transport, addr.clone());

		reservation.disarm();

		Ok(self.wrap_client(client, addr))
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
			MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig<CryptoProvider = C> + Send + Sync,
	{
		self.connect_single_flight(addr).await
	}

	pub fn try_acquire(self: &Arc<Self>, addr: &P::Address) -> TransportResult<Option<PooledClient<P, C>>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
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
			+ PolicyConf
			+ X509ClientConfig<CryptoProvider = C>
			+ MuxConnector
			+ Send
			+ Sync,
	{
		/// Connect to a destination, multiplexing when
		/// [`PoolConfig::mux_offer`] is set and the peer accepts.
		pub async fn connect(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, C>> {
			let offer = match &self.config.mux_offer {
				Some(offer) => offer.to_owned(),
				None => return self.connect_single_flight(addr).await,
			};

			self.acquire_mux(addr, offer, MuxSelection::PreferHeadroom).await
		}

		/// The acquisition funnel for every mux-offering caller: a pooled mux
		/// entry, then an idle exclusive connection left over from a peer that
		/// declined the mux offer at handshake, then a fresh dial. Selection
		/// policy lives here alone so no caller can skip a reuse tier.
		async fn acquire_mux(
			self: &Arc<Self>,
			addr: P::Address,
			offer: TransportOffer,
			selection: MuxSelection,
		) -> TransportResult<PooledClient<P, C>> {
			if let Some(lease) = self.try_take_mux_handle(&addr, selection)? {
				return Ok(self.wrap_mux_client(lease, addr));
			}

			if let Some(client) = self.try_take_ready_client(&addr)? {
				return Ok(self.wrap_client(client, addr));
			}

			self.open_mux_connection(addr, offer).await
		}

		/// Open a fresh connection with a mux offer, falling back to an
		/// exclusive lease when the peer declines multiplexing.
		async fn open_mux_connection(
			self: &Arc<Self>,
			addr: P::Address,
			offer: TransportOffer,
		) -> TransportResult<PooledClient<P, C>> {
			let mut reservation = self.reserve_slot(&addr)?;

			let stream = P::connect(addr.clone()).await.map_err(|e| e.into())?;
			let mut transport = self.tls.apply::<P>(P::create_transport(stream));
			if let Some(timeout) = self.timeout {
				transport = transport.with_timeout(timeout);
			}

			// Mux requires the negotiation result before first use, so the
			// handshake runs eagerly instead of on first emit.
			let mut transport = transport.with_mux_offer(Some(offer));
			transport.complete_client_handshake().await?;

			let settings = match transport.negotiated_mux() {
				Some(settings) => settings,
				None => {
					let client = GenericClient::from_transport_with_addr(transport, addr.clone());

					reservation.disarm();

					return Ok(self.wrap_client(client, addr));
				}
			};

			let (reader, writer) = transport.into_envelope_halves()?;
			let (handle, responder, reader_task) = drive_mux(reader, writer, MuxRole::Client, settings, None);

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
				});

				// Shared mux connections are never leased exclusively, so
				// the slot reserved above leaves the in-use count.
				dest_pool.in_use = dest_pool.in_use.saturating_sub(1);
			}

			reservation.disarm();

			let lease = MuxLease { id, handle, last_used };
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
	#[cfg(all(
		feature = "x509",
		feature = "tokio",
		feature = "transport-policy",
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
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
			+ PolicyConf
			+ X509ClientConfig<CryptoProvider = C>
			+ MuxConnector
			+ Send
			+ Sync,
	{
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

		/// Cap-exhaustion failover: move the lease through the acquisition
		/// funnel (pooled headroom before a fresh dial) and retry there
		/// once.
		async fn emit_failover(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
			let offer = match &self.pool.config.mux_offer {
				Some(offer) => offer.to_owned(),
				// A mux lease exists only when an offer is configured
				None => return Err(TransportError::OperationFailed(TransportFailure::StreamsExhausted)),
			};

			*self = self
				.pool
				.acquire_mux(self.addr.clone(), offer, MuxSelection::RequireHeadroom)
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

		let mut returned_to_pool = false;

		let is_healthy = <P as PersistentConnection>::is_connected(client.transport());
		if let Ok(mut pools) = self.pool.pools.write() {
			if let Some(dest_pool) = pools.get_mut(&self.addr) {
				dest_pool.in_use = dest_pool.in_use.saturating_sub(1);
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
	addr: P::Address,
	active: bool,
}

#[cfg(feature = "std")]
impl<P: Protocol, C: CryptoProvider> SlotGuard<P, C>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn new(pool: Arc<ConnectionPool<P, C>>, addr: P::Address) -> Self {
		Self { pool, addr, active: true }
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

		let pools = self.pool.pools.write();
		if let Ok(mut pools) = pools {
			if let Some(dest_pool) = pools.get_mut(&self.addr) {
				dest_pool.in_use = dest_pool.in_use.saturating_sub(1);
			}
		}
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
