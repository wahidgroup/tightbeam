//! Shared pool, digest, and request-context types for cluster gateway runtime.

use std::sync::Arc;

use digest::consts::U32;
use digest::{Digest, OutputSizeUser};

use crate::colony::cluster::{ClusterConfig, HiveRegistry, ServletRegistry};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::der::oid::AssociatedOid;
use crate::trace::TraceCollector;
use crate::transport::client::pool::ConnectionPool;
use crate::transport::Protocol;

#[cfg(feature = "x509")]
use crate::colony::hive::ReplayGuard;

pub(crate) type ClusterPool<P> = ConnectionPool<P, DefaultCryptoProvider>;

#[cfg(feature = "x509")]
pub(crate) type GatewayReplayGuard = Arc<ReplayGuard>;
#[cfg(not(feature = "x509"))]
pub(crate) type GatewayReplayGuard = ();

/// Shared gateway state passed into accept-loop request handling.
pub(crate) struct GatewayRuntimeCtx<P: Protocol> {
	pub(crate) registry: Arc<HiveRegistry>,
	pub(crate) servlet_registry: Arc<ServletRegistry>,
	pub(crate) config: Arc<ClusterConfig>,
	pub(crate) pool: Arc<ClusterPool<P>>,
	pub(crate) peer_pool: Option<Arc<ClusterPool<P>>>,
	pub(crate) trace: Arc<TraceCollector>,
	pub(crate) replay_guard: GatewayReplayGuard,
}

impl<P: Protocol> Clone for GatewayRuntimeCtx<P> {
	fn clone(&self) -> Self {
		Self {
			registry: Arc::clone(&self.registry),
			servlet_registry: Arc::clone(&self.servlet_registry),
			config: Arc::clone(&self.config),
			pool: Arc::clone(&self.pool),
			peer_pool: self.peer_pool.as_ref().map(Arc::clone),
			trace: Arc::clone(&self.trace),
			#[cfg(feature = "x509")]
			replay_guard: Arc::clone(&self.replay_guard),
			#[cfg(not(feature = "x509"))]
			replay_guard: (),
		}
	}
}

/// Digest bound used by signed cluster control and gossip frames.
pub trait ClusterDigest: Digest + OutputSizeUser<OutputSize = U32> + AssociatedOid + Send + Sync + 'static {}

impl<D> ClusterDigest for D where D: Digest + OutputSizeUser<OutputSize = U32> + AssociatedOid + Send + Sync + 'static {}
