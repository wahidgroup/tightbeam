//! Shared pool, digest, and request-context types for cluster gateway runtime.

use core::hash::Hash;
use core::str::FromStr;
use std::sync::Arc;

use digest::consts::U32;
use digest::{Digest, OutputSizeUser};

use crate::colony::cluster::{ClusterConfig, HiveRegistry, ServletRegistry};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::der::oid::AssociatedOid;
use crate::macros::server::AcceptedConnection;
use crate::trace::TraceCollector;
use crate::transport::client::pool::ConnectionPool;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol, X509ClientConfig};

#[cfg(feature = "x509")]
use crate::colony::hive::ReplayGuard;

pub(crate) type ClusterPool<P> = ConnectionPool<P, DefaultCryptoProvider>;

#[cfg(feature = "x509")]
pub(crate) type GatewayReplayGuard = Arc<ReplayGuard>;
#[cfg(not(feature = "x509"))]
pub(crate) type GatewayReplayGuard = ();

/// Accept plane a gateway connection arrived on.
///
/// The colony plane serves hives and peers with full control dispatch.
/// The edge plane serves external clients and admits `Work` frames only,
/// so an edge client can never register hives, advertise peers, or
/// inject gossip.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum GatewayPlane {
	Colony,
	Edge,
}

/// Protocol that can bind a gateway accept plane (colony or edge).
///
/// Associated-type bounds are written in supertrait position so
/// `T: GatewayAcceptProtocol` implies listener and address requirements
/// at use sites. Dial and pool machinery live on [`GatewayColonyProtocol`].
pub(crate) trait GatewayAcceptProtocol:
	Protocol<
		Listener: AsyncListenerTrait
		              + Protocol<Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static>
		              + Sync
		              + 'static,
		Address: Clone + Send + Sync + FromStr + 'static,
	> + EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
	+ Send
	+ Sync
	+ 'static
{
}

impl<T> GatewayAcceptProtocol for T where
	T: Protocol<
			Listener: AsyncListenerTrait
			              + Protocol<Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static>
			              + Sync
			              + 'static,
			Address: Clone + Send + Sync + FromStr + 'static,
		> + EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static
{
}

/// Colony protocol: accept plane plus outbound pool dial stack.
///
/// Edge protocols need only [`GatewayAcceptProtocol`]. The colony type is
/// also the pool protocol (`P`) for hive and peer dials.
pub(crate) trait GatewayColonyProtocol:
	GatewayAcceptProtocol
	+ PersistentConnection
	+ Protocol<
		Address: Hash + Eq,
		Transport: MessageEmitter
		               + MessageCollector
		               + PolicyConfig
		               + X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		               + MuxConnector
		               + EncryptedProtocolState
		               + Send
		               + Sync
		               + 'static,
	>
{
}

impl<T> GatewayColonyProtocol for T where
	T: GatewayAcceptProtocol
		+ PersistentConnection
		+ Protocol<
			Address: Hash + Eq,
			Transport: MessageEmitter
			               + MessageCollector
			               + PolicyConfig
			               + X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
			               + MuxConnector
			               + EncryptedProtocolState
			               + Send
			               + Sync
			               + 'static,
		>
{
}

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
