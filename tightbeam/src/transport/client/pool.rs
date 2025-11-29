//! Connection pooling for transport layer

use core::hash::Hash;
use core::ops::{Deref, DerefMut};
use core::time::Duration;

#[cfg(feature = "std")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "std")]
use std::sync::{Arc, RwLock, RwLockWriteGuard};
#[cfg(feature = "std")]
use std::time::Instant;

use crate::crypto::{key::KeySpec, x509::CertificateSpec};
use crate::transport::client::GenericClient;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::policy::PolicyConf;
use crate::transport::protocols::{PersistentConnection, Protocol};
use crate::transport::{MessageCollector, MessageEmitter, TransportResult, X509ClientConfig};

#[cfg(feature = "x509")]
use crate::crypto::x509::Certificate;
#[cfg(not(feature = "x509"))]
use crate::transport::client::ClientBuilder;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;

/// Builder trait for connection configuration
///
/// Implemented by both ClientBuilder (for direct connections) and
/// ConnectionPoolBuilder (for pooled connections), enabling unified builder API.
pub trait ConnectionBuilder<P: Protocol>: Sized {
	/// The type returned by build()
	type Output;

	/// Configure timeout for operations
	fn with_timeout(self, timeout: Duration) -> Self;

	/// Configure server certificate for TLS validation
	#[cfg(feature = "x509")]
	fn with_server_certificate(self, cert: CertificateSpec) -> TransportResult<Self>;

	/// Configure multiple server certificates for TLS validation
	#[cfg(feature = "x509")]
	fn with_server_certificates(self, certs: impl IntoIterator<Item = CertificateSpec>) -> TransportResult<Self>;

	/// Configure client identity for mutual TLS
	#[cfg(feature = "x509")]
	fn with_client_identity(self, cert: CertificateSpec, key: KeySpec) -> TransportResult<Self>;

	/// Build the configured builder/pool (sync)
	fn build(self) -> Self::Output;
}

/// Configuration for connection pool
#[derive(Clone, Debug, Default)]
pub struct PoolConfig {
	/// Optional idle timeout for connections
	/// None means connections never expire
	pub idle_timeout: Option<Duration>,
}

#[cfg(feature = "x509")]
#[derive(Clone)]
/// Client authentication bundle kept behind Arc for zero-copy reuse.
struct ClientIdentity {
	certificate: Arc<Certificate>,
	key: Arc<HandshakeKeyManager>,
}

#[cfg(feature = "x509")]
#[derive(Clone)]
/// Shared TLS assets reused across pooled connections without reallocations.
struct PoolTlsConfig {
	server_certificates: Vec<Arc<Certificate>>,
	client_identity: Option<ClientIdentity>,
}

#[cfg(feature = "x509")]
impl Default for PoolTlsConfig {
	fn default() -> Self {
		Self { server_certificates: Vec::new(), client_identity: None }
	}
}

#[cfg(feature = "x509")]
impl PoolTlsConfig {
	fn push_server_certificate(&mut self, cert: Certificate) {
		self.server_certificates.push(Arc::new(cert));
	}

	fn set_client_identity(&mut self, cert: Certificate, key: HandshakeKeyManager) {
		self.client_identity = Some(ClientIdentity { certificate: Arc::new(cert), key: Arc::new(key) });
	}

	fn apply<P>(&self, transport: P::Transport) -> P::Transport
	where
		P: Protocol,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig,
	{
		let mut configured = transport;

		if !self.server_certificates.is_empty() {
			let certs: Vec<_> = self.server_certificates.iter().map(|cert| (**cert).clone()).collect();
			configured = configured.with_server_certificates(certs);
		}

		if let Some(identity) = &self.client_identity {
			let cert = (*identity.certificate).clone();
			let key = (*identity.key).clone();
			configured = configured.with_client_identity(cert, key);
		}

		configured
	}
}

/// Builder for creating a configured ConnectionPool
pub struct ConnectionPoolBuilder<P: Protocol, const N: usize> {
	config: PoolConfig,
	timeout: Option<Duration>,
	#[cfg(feature = "x509")]
	tls: PoolTlsConfig,
	_phantom: core::marker::PhantomData<P>,
}

impl<P: Protocol, const N: usize> Default for ConnectionPoolBuilder<P, N> {
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

impl<P: Protocol, const N: usize> ConnectionPoolBuilder<P, N> {
	pub fn with_config(mut self, config: PoolConfig) -> Self {
		self.config = config;
		self
	}
}

#[cfg(feature = "std")]
impl<P: Protocol, const N: usize> ConnectionBuilder<P> for ConnectionPoolBuilder<P, N> {
	type Output = ConnectionPool<P, N>;

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	#[cfg(feature = "x509")]
	fn with_server_certificate(mut self, cert: CertificateSpec) -> TransportResult<Self> {
		let converted = Certificate::try_from(cert)?;
		self.tls.push_server_certificate(converted);
		Ok(self)
	}

	#[cfg(feature = "x509")]
	fn with_server_certificates(mut self, certs: impl IntoIterator<Item = CertificateSpec>) -> TransportResult<Self> {
		for cert_spec in certs {
			let cert = Certificate::try_from(cert_spec)?;
			self.tls.push_server_certificate(cert);
		}

		Ok(self)
	}

	#[cfg(feature = "x509")]
	fn with_client_identity(mut self, cert: CertificateSpec, key: KeySpec) -> TransportResult<Self> {
		let cert_converted = Certificate::try_from(cert)?;
		let key_converted = HandshakeKeyManager::try_from(key)?;

		self.tls.set_client_identity(cert_converted, key_converted);
		Ok(self)
	}

	fn build(self) -> Self::Output {
		ConnectionPool {
			pools: Arc::new(RwLock::new(HashMap::new())),
			config: self.config,
			timeout: self.timeout,
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

/// Per-destination connection pool
#[cfg(feature = "std")]
struct DestinationPool<P: Protocol> {
	/// Available connections ready for reuse
	available: VecDeque<AvailableEntry<P>>,
	/// Number of connections currently in use
	in_use: usize,
}

/// Connection pool for protocol P with max N connections per destination
///
/// # Invariants
/// - `available.len() + in_use <= N` at all times (enforced by `SlotGuard`)
/// - Idle connections exceeding `PoolConfig::idle_timeout` are pruned lazily
/// - Lock poisoning never panics; callers receive `TransportFailure::Busy` instead
#[cfg(feature = "std")]
pub struct ConnectionPool<P: Protocol, const N: usize> {
	/// Per-destination sub-pools
	pools: Arc<RwLock<HashMap<P::Address, DestinationPool<P>>>>,
	/// Pool configuration
	config: PoolConfig,
	/// Shared timeout for all connections
	timeout: Option<Duration>,
	/// Shared TLS assets reused across pooled connections
	#[cfg(feature = "x509")]
	tls: PoolTlsConfig,
}

#[cfg(feature = "std")]
impl<P: Protocol + Send + Sync, const N: usize> ConnectionPool<P, N>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	/// Create a new connection pool builder
	pub fn builder() -> ConnectionPoolBuilder<P, N> {
		ConnectionPoolBuilder::default()
	}

	fn wrap_client(self: &Arc<Self>, client: GenericClient<P>, addr: P::Address) -> PooledClient<P, N>
	where
		P: PersistentConnection,
	{
		PooledClient { client: Some(client), pool: Arc::clone(self), addr }
	}

	fn write_pools(&self) -> TransportResult<RwLockWriteGuard<'_, HashMap<P::Address, DestinationPool<P>>>> {
		self.pools
			.write()
			.map_err(|_| TransportError::OperationFailed(TransportFailure::Busy))
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
			}
		}
		Ok(None)
	}

	fn reserve_slot(self: &Arc<Self>, addr: &P::Address) -> TransportResult<SlotGuard<P, N>> {
		let mut pools = self.write_pools()?;
		let dest_pool = pools
			.entry(addr.clone())
			.or_insert_with(|| DestinationPool { available: VecDeque::new(), in_use: 0 });

		self.prune_idle_locked(dest_pool, Instant::now());

		let total_connections = dest_pool.available.len() + dest_pool.in_use;
		if total_connections >= N {
			return Err(TransportError::OperationFailed(TransportFailure::Busy));
		}

		dest_pool.in_use += 1;
		Ok(SlotGuard::new(Arc::clone(self), addr.clone()))
	}

	fn prune_idle_locked(&self, dest_pool: &mut DestinationPool<P>, now: Instant) {
		if let Some(timeout) = self.config.idle_timeout {
			while let Some(entry) = dest_pool.available.front() {
				if now.duration_since(entry.last_used) >= timeout {
					dest_pool.available.pop_front();
				} else {
					break;
				}
			}
		}
	}

	#[cfg(not(feature = "x509"))]
	pub async fn connect(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, N>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
	{
		if let Some(client) = self.try_take_ready_client(&addr)? {
			return Ok(self.wrap_client(client, addr));
		}

		let mut reservation = self.reserve_slot(&addr)?;

		let builder = self.apply_timeout_to_builder(ClientBuilder::<P>::builder());
		let builder = ConnectionBuilder::build(builder);
		let client = builder.connect(addr.clone()).await?;

		reservation.disarm();

		Ok(self.wrap_client(client, addr))
	}

	#[cfg(feature = "x509")]
	pub async fn connect(self: &Arc<Self>, addr: P::Address) -> TransportResult<PooledClient<P, N>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig + Send + Sync,
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

	pub fn try_acquire(self: &Arc<Self>, addr: &P::Address) -> TransportResult<Option<PooledClient<P, N>>>
	where
		P: PersistentConnection + Send + Sync,
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
	{
		let maybe_client = self.try_take_ready_client(addr)?;
		Ok(maybe_client.map(|client| self.wrap_client(client, addr.clone())))
	}
}

/// A pooled client connection that returns to the pool on drop
#[cfg(feature = "std")]
pub struct PooledClient<P: Protocol + PersistentConnection, const N: usize>
where
	P::Address: Hash + Eq + Send + Sync,
{
	client: Option<GenericClient<P>>,
	pool: Arc<ConnectionPool<P, N>>,
	addr: P::Address,
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection, const N: usize> Deref for PooledClient<P, N>
where
	P::Address: Hash + Eq + Send + Sync,
{
	type Target = GenericClient<P>;

	fn deref(&self) -> &Self::Target {
		debug_assert!(self.client.is_some(), "pooled client should never be None before drop");
		self.client.as_ref().expect("pooled client still active")
	}
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection, const N: usize> DerefMut for PooledClient<P, N>
where
	P::Address: Hash + Eq + Send + Sync,
{
	fn deref_mut(&mut self) -> &mut Self::Target {
		debug_assert!(self.client.is_some(), "pooled client should never be None before drop");
		self.client.as_mut().expect("pooled client still active")
	}
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection, const N: usize> Drop for PooledClient<P, N>
where
	P::Address: Hash + Eq + Send + Sync,
{
	fn drop(&mut self) {
		let client = match self.client.take() {
			Some(client) => client,
			None => return,
		};

		let is_healthy = <P as PersistentConnection>::is_connected(client.transport());

		let mut pools = match self.pool.pools.write() {
			Ok(p) => p,
			Err(_) => return,
		};

		if let Some(dest_pool) = pools.get_mut(&self.addr) {
			dest_pool.in_use = dest_pool.in_use.saturating_sub(1);
			if is_healthy {
				dest_pool
					.available
					.push_back(AvailableEntry { client, last_used: Instant::now() });
			}
		}
	}
}

#[cfg(feature = "std")]
struct SlotGuard<P: Protocol, const N: usize>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	pool: Arc<ConnectionPool<P, N>>,
	addr: P::Address,
	active: bool,
}

#[cfg(feature = "std")]
impl<P: Protocol, const N: usize> SlotGuard<P, N>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn new(pool: Arc<ConnectionPool<P, N>>, addr: P::Address) -> Self {
		Self { pool, addr, active: true }
	}

	fn disarm(&mut self) {
		self.active = false;
	}
}

#[cfg(feature = "std")]
impl<P: Protocol, const N: usize> Drop for SlotGuard<P, N>
where
	P::Address: Hash + Eq + Clone + Send + Sync,
{
	fn drop(&mut self) {
		if !self.active {
			return;
		}

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
	}

	#[test]
	fn test_pool_config_with_timeout() {
		let config = PoolConfig { idle_timeout: Some(Duration::from_secs(30)) };
		assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
	}
}
