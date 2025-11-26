//! Connection pooling for transport layer
//!
//! Provides connection pooling via the Client trait, which both ClientBuilder
//! and ConnectionPool implement. This allows identical builder pattern APIs for
//! direct and pooled connections.

use core::ops::{Deref, DerefMut};
use core::time::Duration;

#[cfg(feature = "std")]
use std::collections::{HashMap, VecDeque};
#[cfg(feature = "std")]
use std::sync::{Arc, RwLock};

use crate::crypto::{key::KeySpec, x509::CertificateSpec};
use crate::macros::client::builder::GenericClient;
use crate::transport::{
	error::{TransportError, TransportFailure},
	policy::PolicyConf,
	protocols::{PersistentConnection, Protocol},
	MessageCollector, MessageEmitter, TransportResult, X509ClientConfig,
};

/// Client trait providing builder pattern for connection creation
///
/// Implemented by both ClientBuilder (for direct connections) and
/// PooledClientBuilder (for pooled connections), enabling identical APIs.
#[allow(async_fn_in_trait)]
pub trait Client<P: Protocol>: Sized {
	/// The type returned by build()
	type Output;

	/// Start building a client connection to the given address
	async fn connect(addr: P::Address) -> TransportResult<Self>;

	/// Configure timeout for operations
	fn with_timeout(self, timeout: Duration) -> Self;

	/// Configure server certificate for TLS validation
	#[cfg(feature = "x509")]
	fn with_server_certificate(self, cert: CertificateSpec) -> TransportResult<Self>;

	/// Configure client identity for mutual TLS
	#[cfg(feature = "x509")]
	fn with_client_identity(self, cert: CertificateSpec, key: KeySpec) -> TransportResult<Self>;

	/// Build the client connection (sync for ClientBuilder, async for pooling)
	async fn build(self) -> TransportResult<Self::Output>;
}

/// Configuration for connection pool
#[derive(Clone, Debug, Default)]
pub struct PoolConfig {
	/// Optional idle timeout for connections
	/// None means connections never expire
	pub idle_timeout: Option<Duration>,
}

/// Per-destination connection pool
#[cfg(feature = "std")]
struct DestinationPool<P: Protocol> {
	/// Available connections ready for reuse
	available: VecDeque<GenericClient<P>>,
	/// Number of connections currently in use
	in_use: usize,
}

/// Connection pool for protocol P with max N connections per destination
#[cfg(feature = "std")]
pub struct ConnectionPool<P: Protocol, const N: usize> {
	/// Per-destination sub-pools
	pools: Arc<RwLock<HashMap<P::Address, DestinationPool<P>>>>,
	/// TODO Pool configuration
	#[allow(dead_code)]
	config: PoolConfig,
}

#[cfg(feature = "std")]
impl<P: Protocol + Send + Sync, const N: usize> ConnectionPool<P, N>
where
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	/// Create a new connection pool with the given configuration
	pub fn new(config: PoolConfig) -> Self {
		Self { pools: Arc::new(RwLock::new(HashMap::new())), config }
	}

	/// Start building a pooled client connection
	///
	/// Returns a PooledClientBuilder that implements the Client trait,
	/// allowing the same builder pattern as ClientBuilder.
	pub fn connect(self: &Arc<Self>, addr: P::Address) -> PooledClientBuilder<P, N> {
		PooledClientBuilder {
			pool: Arc::clone(self),
			addr,
			timeout: None,
			#[cfg(feature = "x509")]
			server_cert: None,
			#[cfg(feature = "x509")]
			client_cert: None,
			#[cfg(feature = "x509")]
			client_key: None,
		}
	}
}

/// Builder for pooled client connections
#[cfg(feature = "std")]
pub struct PooledClientBuilder<P: Protocol, const N: usize> {
	pool: Arc<ConnectionPool<P, N>>,
	addr: P::Address,
	timeout: Option<Duration>,
	#[cfg(feature = "x509")]
	server_cert: Option<CertificateSpec>,
	#[cfg(feature = "x509")]
	client_cert: Option<CertificateSpec>,
	#[cfg(feature = "x509")]
	client_key: Option<KeySpec>,
}

#[cfg(feature = "std")]
impl<P: Protocol + PersistentConnection + Send + Sync, const N: usize> PooledClientBuilder<P, N>
where
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	/// Build the pooled client connection
	///
	/// 1. Checks pool for available connection to this destination
	/// 2. If available and healthy, returns it
	/// 3. If none available and under limit N, creates new connection
	/// 4. If at limit N, returns error
	#[cfg(not(feature = "x509"))]
	pub async fn build_impl(self) -> TransportResult<PooledClient<P, N>>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
	{
		self.build_internal().await
	}

	#[cfg(feature = "x509")]
	pub async fn build_impl(self) -> TransportResult<PooledClient<P, N>>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig + Send + Sync,
	{
		self.build_internal().await
	}

	/// Internal implementation shared by both x509 and non-x509 builds
	#[cfg(not(feature = "x509"))]
	async fn build_internal(self) -> TransportResult<PooledClient<P, N>>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
	{
		use crate::macros::client::builder::ClientBuilder;

		// Try to acquire existing healthy connection from pool
		if let Some(client) = self.try_acquire_from_pool()? {
			return Ok(client);
		}

		// Reserve slot for new connection
		self.reserve_slot()?;

		// Create and configure new client
		let mut builder = ClientBuilder::<P>::connect(self.addr.clone()).await?;
		if let Some(timeout) = self.timeout {
			builder = builder.with_timeout(timeout);
		}

		let client = builder.build().await?;
		Ok(PooledClient { client: Some(client), pool: Arc::clone(&self.pool), addr: self.addr })
	}

	#[cfg(feature = "x509")]
	async fn build_internal(self) -> TransportResult<PooledClient<P, N>>
	where
		P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig + Send + Sync,
	{
		use crate::macros::client::builder::ClientBuilder;

		// Try to acquire existing healthy connection from pool
		if let Some(client) = self.try_acquire_from_pool()? {
			return Ok(client);
		}

		// Reserve slot for new connection
		self.reserve_slot()?;

		// Create and configure new client
		let mut builder = ClientBuilder::<P>::connect(self.addr.clone()).await?;
		if let Some(timeout) = self.timeout {
			builder = builder.with_timeout(timeout);
		}

		if let Some(cert) = self.server_cert {
			builder = builder.with_server_certificate(cert)?;
		}
		if let (Some(cert), Some(key)) = (self.client_cert, self.client_key) {
			builder = builder.with_client_identity(cert, key)?;
		}

		let client = builder.build().await?;
		Ok(PooledClient { client: Some(client), pool: Arc::clone(&self.pool), addr: self.addr })
	}

	/// Try to acquire an existing healthy connection from the pool
	fn try_acquire_from_pool(&self) -> TransportResult<Option<PooledClient<P, N>>> {
		let mut pools = self.pool.pools.write().map_err(|_| TransportError::ConnectionFailed)?;

		if let Some(dest_pool) = pools.get_mut(&self.addr) {
			// Health check available connections
			while let Some(client) = dest_pool.available.pop_front() {
				if <P as PersistentConnection>::is_connected(client.transport()) {
					dest_pool.in_use += 1;
					return Ok(Some(PooledClient {
						client: Some(client),
						pool: Arc::clone(&self.pool),
						addr: self.addr.clone(),
					}));
				}
				// Stale connection, drop and try next
			}
		}

		Ok(None)
	}

	/// Reserve a slot for a new connection, checking the per-destination limit
	fn reserve_slot(&self) -> TransportResult<()> {
		let mut pools = self.pool.pools.write().map_err(|_| TransportError::ConnectionFailed)?;
		let dest_pool = pools
			.entry(self.addr.clone())
			.or_insert_with(|| DestinationPool { available: VecDeque::new(), in_use: 0 });

		if dest_pool.in_use >= N {
			return Err(TransportError::OperationFailed(TransportFailure::Timeout));
		}

		dest_pool.in_use += 1;
		Ok(())
	}
}

// Client trait implementation for PooledClientBuilder
#[cfg(all(feature = "std", not(feature = "x509")))]
impl<P: Protocol + PersistentConnection + Send + Sync, const N: usize> Client<P> for PooledClientBuilder<P, N>
where
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: MessageEmitter + MessageCollector + PolicyConf + Send + Sync,
{
	type Output = PooledClient<P, N>;

	async fn connect(_addr: P::Address) -> TransportResult<Self> {
		// Cannot create PooledClientBuilder without a pool instance
		// Users must call pool.connect(addr) instead
		Err(TransportError::ConnectionFailed)
	}

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	async fn build(self) -> TransportResult<Self::Output> {
		self.build_impl().await
	}
}

#[cfg(all(feature = "std", feature = "x509"))]
impl<P: Protocol + PersistentConnection + Send + Sync, const N: usize> Client<P> for PooledClientBuilder<P, N>
where
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: MessageEmitter + MessageCollector + PolicyConf + X509ClientConfig + Send + Sync,
{
	type Output = PooledClient<P, N>;

	async fn connect(_addr: P::Address) -> TransportResult<Self> {
		// Cannot create PooledClientBuilder without a pool instance
		// Users must call pool.connect(addr) instead
		Err(TransportError::ConnectionFailed)
	}

	fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = Some(timeout);
		self
	}

	fn with_server_certificate(mut self, cert: CertificateSpec) -> TransportResult<Self> {
		self.server_cert = Some(cert);
		Ok(self)
	}

	fn with_client_identity(mut self, cert: CertificateSpec, key: KeySpec) -> TransportResult<Self> {
		self.client_cert = Some(cert);
		self.client_key = Some(key);
		Ok(self)
	}

	async fn build(self) -> TransportResult<Self::Output> {
		self.build_impl().await
	}
}

/// A pooled client connection that returns to the pool on drop
#[cfg(feature = "std")]
pub struct PooledClient<P: Protocol, const N: usize>
where
	P::Address: core::hash::Hash + Eq + Send + Sync,
{
	client: Option<GenericClient<P>>,
	pool: Arc<ConnectionPool<P, N>>,
	addr: P::Address,
}

#[cfg(feature = "std")]
impl<P: Protocol, const N: usize> Deref for PooledClient<P, N>
where
	P::Address: core::hash::Hash + Eq + Send + Sync,
{
	type Target = GenericClient<P>;

	fn deref(&self) -> &Self::Target {
		self.client.as_ref().expect("PooledClient should always have a client")
	}
}

#[cfg(feature = "std")]
impl<P: Protocol, const N: usize> DerefMut for PooledClient<P, N>
where
	P::Address: core::hash::Hash + Eq + Send + Sync,
{
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.client.as_mut().expect("PooledClient should always have a client")
	}
}

#[cfg(feature = "std")]
impl<P: Protocol, const N: usize> Drop for PooledClient<P, N>
where
	P::Address: core::hash::Hash + Eq + Send + Sync,
{
	fn drop(&mut self) {
		if let Some(client) = self.client.take() {
			if let Ok(mut pools) = self.pool.pools.write() {
				if let Some(dest_pool) = pools.get_mut(&self.addr) {
					dest_pool.available.push_back(client);
					dest_pool.in_use = dest_pool.in_use.saturating_sub(1);
				}
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
