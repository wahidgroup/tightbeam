//! Shared pool, digest, and request-context types for the cluster gateway
//! runtime.

use core::hash::Hash;
use core::str::FromStr;
use std::sync::{Arc, Mutex};

use digest::consts::U32;
use digest::{Digest, OutputSizeUser};

use crate::colony::cluster::registry::ColonyMembership;
use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
use crate::colony::cluster::runtime::gossip_tasks::PeerLedgers;
use crate::colony::cluster::runtime::hop::{HivePlane, PeerPlane};
use crate::colony::cluster::{ClusterConfig, HiveRegistry, ServletRegistry};
use crate::colony::common::TaskGroup;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::der::oid::AssociatedOid;
use crate::macros::server::AcceptedConnection;
use crate::trace::TraceCollector;
use crate::transport::client::ConnectionPool;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol};

pub(crate) type ClusterPool<P> = ConnectionPool<P>;

/// Protocol that can bind a gateway accept plane (colony or edge).
///
/// The associated-type bounds sit in supertrait position, so
/// `T: GatewayAcceptProtocol` implies the listener and address requirements
/// at use sites. The dial and pool bounds live on [`ColonyDialProtocol`].
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

/// Protocol of a colony dial: the pool, the handshake, and the transport that
/// a bound dial connects, admits, and emits on.
///
/// The associated-type bounds sit in supertrait position, so
/// `T: ColonyDialProtocol` implies the address and transport requirements at
/// use sites. The gateway's hive and peer planes and a hive's sibling calls
/// dial through it.
pub(crate) trait ColonyDialProtocol:
	Protocol<
		Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
		Transport: MessageEmitter
		               + MessageCollector
		               + PolicyConfig
		               + MuxConnector
		               + EncryptedProtocolState
		               + Send
		               + Sync
		               + 'static,
	> + PersistentConnection
	+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
	+ Send
	+ Sync
	+ 'static
{
}

impl<T> ColonyDialProtocol for T where
	T: Protocol<
			Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
			Transport: MessageEmitter
			               + MessageCollector
			               + PolicyConfig
			               + MuxConnector
			               + EncryptedProtocolState
			               + Send
			               + Sync
			               + 'static,
		> + PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static
{
}

/// Colony protocol: the accept plane plus the dial stack of the outbound pool.
///
/// Edge protocols need only [`GatewayAcceptProtocol`]. The colony type is
/// also the pool protocol (`P`) for hive and peer dials, through
/// [`ColonyDialProtocol`].
pub(crate) trait GatewayColonyProtocol: GatewayAcceptProtocol + ColonyDialProtocol {}

impl<T> GatewayColonyProtocol for T where T: GatewayAcceptProtocol + ColonyDialProtocol {}

/// Shared gateway state passed into accept-loop request handling.
pub(crate) struct GatewayRuntimeCtx<P: Protocol> {
	/// Registered hives and the servlet types each advertises.
	pub(crate) registry: Arc<HiveRegistry>,
	/// Servlet routes, both local and peer-learned, with their trails.
	pub(crate) servlet_registry: Arc<ServletRegistry>,
	/// Serialises one hive's membership move across both registries.
	pub(crate) admission: Arc<Mutex<()>>,
	/// Colony identity, gates, peer caps, and gossip policy.
	pub(crate) config: Arc<ClusterConfig>,
	/// The plane this gateway dials its hives and their servlets on, which
	/// holds the hive pool and hands out bound dials alone.
	pub(crate) hive_plane: HivePlane<P>,
	/// The plane peer gateways are dialed on, when one is configured.
	pub(crate) peer_plane: Option<PeerPlane<P>>,
	/// Instrumentation collector for gateway control-plane events.
	pub(crate) trace: Arc<TraceCollector>,
	/// Freshness ledger that admits each signed control frame once.
	pub(crate) replay_guard: GatewayReplayGuard,
	/// Owner of the background work a request handler starts.
	pub(crate) tasks: TaskGroup,
	/// What each gossip target acknowledged and refused, shared by the beat
	/// and by every inbound reflood.
	pub(crate) ledgers: Arc<PeerLedgers>,
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// The two registries one hive's membership spans.
	///
	/// Admission and retirement move both, so they run here rather than as
	/// a sequence each call site repeats.
	pub(crate) fn membership(&self) -> ColonyMembership<'_> {
		ColonyMembership::new(&self.registry, &self.servlet_registry, &self.admission)
	}
}

impl<P: Protocol> Clone for GatewayRuntimeCtx<P> {
	fn clone(&self) -> Self {
		Self {
			registry: Arc::clone(&self.registry),
			servlet_registry: Arc::clone(&self.servlet_registry),
			admission: Arc::clone(&self.admission),
			config: Arc::clone(&self.config),
			hive_plane: self.hive_plane.clone(),
			peer_plane: self.peer_plane.clone(),
			trace: Arc::clone(&self.trace),
			tasks: self.tasks.clone(),
			ledgers: Arc::clone(&self.ledgers),
			replay_guard: self.replay_guard.clone(),
		}
	}
}

/// Digest bound used by signed cluster control and gossip frames.
pub trait ClusterDigest: Digest + OutputSizeUser<OutputSize = U32> + AssociatedOid + Send + Sync + 'static {}

impl<D> ClusterDigest for D where D: Digest + OutputSizeUser<OutputSize = U32> + AssociatedOid + Send + Sync + 'static {}
