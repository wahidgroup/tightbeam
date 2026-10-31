//! The shared pool, digest, and request-context types of the cluster gateway
//! runtime.

use core::hash::Hash;
use core::marker::PhantomData;
use core::ops::Deref;
use core::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::builder::frame::{CheckDigestOid, FrameBuilder};
use crate::colony::cluster::registry::ColonyMembership;
use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
use crate::colony::cluster::runtime::gossip_tasks::PeerLedgers;
use crate::colony::cluster::runtime::hop::{HivePlane, PeerPlane};
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::{ClusterConfig, ClusterError, HiveRegistry, HopBudget, ServletRegistry, WireHopBudget};
use crate::colony::protocol::{IssueClock, IssuedOrder};
use crate::colony::urn::ServletTypeKey;
use crate::crypto::profiles::DigestProvider;
use crate::macros::server::AcceptedConnection;
use crate::policy::{SessionContext, TransitStatus};
use crate::runtime::TaskGroup;
use crate::trace::TraceCollector;
use crate::transport::client::ConnectionPool;
use crate::transport::handshake::HandshakeProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol};
use crate::urn::Urn;
use crate::{Message, MessagePriority, TightBeamError, Version};

pub(crate) type ClusterPool<P> = ConnectionPool<P>;

/// A protocol that can bind a gateway accept plane, colony or edge.
///
/// The associated-type bounds are in supertrait position, so
/// `T: GatewayAcceptProtocol` implies the listener and address requirements
/// at use sites. The dial and pool bounds are on [`ColonyDialProtocol`].
pub(crate) trait GatewayAcceptProtocol:
	Protocol<
		Listener: AsyncListenerTrait
		              + Protocol<Transport: AcceptedConnection + PolicyConfig + MuxCapable + 'static>
		              + Sync
		              + 'static,
		Address: Clone + Send + Sync + FromStr + 'static,
	> + EncryptedProtocol<CryptoProvider: HandshakeProvider>
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
		> + EncryptedProtocol<CryptoProvider: HandshakeProvider>
		+ Send
		+ Sync
		+ 'static
{
}

/// The protocol of a colony dial: the pool, the handshake, and the transport
/// that a bound dial connects, admits, and emits on.
///
/// The associated-type bounds are in supertrait position, so
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
	+ EncryptedProtocol<CryptoProvider: HandshakeProvider>
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
		+ EncryptedProtocol<CryptoProvider: HandshakeProvider>
		+ Send
		+ Sync
		+ 'static
{
}

/// The colony protocol: the accept plane plus the dial stack of the outbound
/// pool.
///
/// Edge protocols need only [`GatewayAcceptProtocol`]. The colony type is
/// also the pool protocol (`P`) for hive and peer dials, through
/// [`ColonyDialProtocol`].
pub(crate) trait GatewayColonyProtocol: GatewayAcceptProtocol + ColonyDialProtocol {}

impl<T> GatewayColonyProtocol for T where T: GatewayAcceptProtocol + ColonyDialProtocol {}

/// The gateway state that the accept loop shares with each request handler.
pub(crate) struct GatewayRuntimeCtx<P: Protocol> {
	/// The registered hives and the servlet types each one advertises.
	pub(crate) registry: Arc<HiveRegistry>,
	/// The servlet routes, local and peer-learned, with their trails.
	pub(crate) servlet_registry: Arc<ServletRegistry>,
	/// Serialises one hive's membership move across both registries.
	pub(crate) admission: Arc<Mutex<()>>,
	/// The colony identity, gates, peer caps, and gossip policy.
	pub(crate) config: ColonyConfig<P>,
	/// The plane this gateway dials its hives and their servlets on, which
	/// holds the hive pool and hands out bound dials alone.
	pub(crate) hive_plane: HivePlane<P>,
	/// The plane this gateway dials peer gateways on: the peer pool, or the
	/// hive pool for a gateway that configures no peer trust.
	pub(crate) peer_plane: PeerPlane<P>,
	/// The instrumentation collector for the gateway's control-plane events.
	pub(crate) trace: Arc<TraceCollector>,
	/// The trace of the accept planes, and of each record no credential backs.
	pub(crate) connections: Arc<TraceCollector>,
	/// The freshness ledger that admits each signed control frame once.
	pub(crate) replay_guard: GatewayReplayGuard,
	/// The owner of the background work that a request handler starts.
	pub(crate) tasks: TaskGroup,
	/// What each gossip target acknowledged and refused, shared by the beat
	/// and by every inbound reflood.
	pub(crate) ledgers: Arc<PeerLedgers>,
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// The two registries one hive's membership spans.
	///
	/// Admission and retirement move both, so they run on the returned
	/// `ColonyMembership` and not at each call site.
	pub(crate) fn membership(&self) -> ColonyMembership<'_> {
		ColonyMembership::new(&self.registry, &self.servlet_registry, &self.admission)
	}

	/// The traces that the records of a request on `session` go on.
	pub(crate) fn audit(&self, session: &SessionContext) -> RequestAudit {
		RequestAudit::of(&self.trace, &self.connections, session)
	}
}

impl<P: Protocol> Clone for GatewayRuntimeCtx<P> {
	fn clone(&self) -> Self {
		Self {
			registry: Arc::clone(&self.registry),
			servlet_registry: Arc::clone(&self.servlet_registry),
			admission: Arc::clone(&self.admission),
			config: self.config.clone(),
			hive_plane: self.hive_plane.clone(),
			peer_plane: self.peer_plane.clone(),
			trace: Arc::clone(&self.trace),
			connections: Arc::clone(&self.connections),
			tasks: self.tasks.clone(),
			ledgers: Arc::clone(&self.ledgers),
			replay_guard: self.replay_guard.clone(),
		}
	}
}

/// The digest of the provider that protocol `P` names, which names each
/// gateway and digests each rumor and frame witness of the colony.
///
/// In production code, the methods of [`ColonyConfig`] alone name it.
pub(crate) type ColonyDigest<P> = <<P as Protocol>::CryptoProvider as DigestProvider>::Digest;

/// The configuration of a gateway that runs protocol `P`, whose provider
/// names the colony digest.
///
/// Each operation that names a gateway, or digests a rumor or a frame
/// witness, is a method here under [`ColonyDigest`] of `P`, so all of them
/// use one digest. It shares the configuration and dereferences to it.
pub(crate) struct ColonyConfig<P> {
	config: Arc<ClusterConfig>,
	/// The issue times of the gateway's signed control frames, which every
	/// clone shares, so the orders of the gateway increase strictly.
	issue_clock: Arc<IssueClock>,
	/// The route key of the gossip ingress, minted once under the namespace
	/// of the gateway.
	gossip_ingress: Option<Arc<ServletTypeKey>>,
	protocol: PhantomData<fn() -> P>,
}

impl<P> ColonyConfig<P> {
	/// The shared configuration `config` of a gateway that runs `P`, with the
	/// route key of its gossip ingress minted under its namespace.
	///
	/// # Errors
	///
	/// - The errors of [`ClusterConfig::gossip_ingress_key`] -- the ingress is
	///   no bare servlet type of the namespace.
	pub(crate) fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
		let gossip_ingress = config.gossip_ingress_key()?.map(Arc::new);
		let issue_clock = Arc::new(IssueClock::new(Arc::clone(&config.clock)));

		Ok(Self { config: Arc::new(config), issue_clock, gossip_ingress, protocol: PhantomData })
	}

	/// The issue time of the next signed control frame of this gateway, which
	/// [`Self::control_frame`] states in `metadata.order` (README §5.7.1).
	pub(crate) fn issue_order(&self) -> IssuedOrder {
		self.issue_clock.issue()
	}

	/// The route key that the gateway delivers admitted rumors under, or
	/// [`None`] when it delivers none to a local servlet.
	pub(crate) fn gossip_ingress(&self) -> Option<&ServletTypeKey> {
		self.gossip_ingress.as_deref()
	}
}

// The impl is manual because a derive would demand `P: Clone`, and the
// configuration is reference-counted regardless of `P`.
impl<P> Clone for ColonyConfig<P> {
	fn clone(&self) -> Self {
		let issue_clock = Arc::clone(&self.issue_clock);
		let gossip_ingress = self.gossip_ingress.as_ref().map(Arc::clone);
		let config = Arc::clone(&self.config);

		Self { config, issue_clock, gossip_ingress, protocol: PhantomData }
	}
}

impl<P> Deref for ColonyConfig<P> {
	type Target = ClusterConfig;

	fn deref(&self) -> &ClusterConfig {
		&self.config
	}
}

impl<P: Protocol> ColonyConfig<P> {
	/// Admits a work request or a routed stream open to `target`: it clamps
	/// the `wire` budget to the operator's cap and runs the export gates, which
	/// read whether a peer relayed the request.
	///
	/// The unary work arm and the stream gate both admit through it, so the
	/// two read one clamp of one octet and one export verdict. A refusal that
	/// the caller answers comes back as the inner `Err`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- `trace` refused the record of the export verdict.
	pub(crate) fn admit_target(
		&self,
		target: &Urn<'_>,
		wire: WireHopBudget,
		session: &SessionContext,
		trace: &TraceCollector,
	) -> Result<Result<HopBudget, TransitStatus>, TightBeamError> {
		let budget = HopBudget::from_wire(wire, self.peer.max_hops);
		let relayed = budget.is_relayed();
		let status = self.evaluate_export_gates(target, session, relayed, trace)?;
		if status != TransitStatus::Ok {
			return Ok(Err(status));
		}

		Ok(Ok(budget))
	}
}

impl<P: ColonyDialProtocol> ColonyConfig<P> {
	/// `builder`, set to digest its frame witness under the colony digest.
	pub(crate) fn witnessed<T>(&self, builder: FrameBuilder<T>) -> FrameBuilder<T>
	where
		T: Message + CheckDigestOid<ColonyDigest<P>>,
	{
		builder.with_witness_hasher::<ColonyDigest<P>>()
	}

	/// The builder of a signed control frame of this gateway: `message` at
	/// V2 under `id`, with network-control priority, the frame witness under
	/// the colony digest, and `issued` in `metadata.order`.
	///
	/// - The replay guard of a receiver refuses a second frame of one signer
	///   at one order, so the order comes from the issue clock of the gateway
	///   (README §5.7.1).
	/// - Priority is a metadata field of V2 or later, so the frame is V2.
	pub(crate) fn control_frame<T>(&self, id: impl AsRef<[u8]>, issued: IssuedOrder, message: T) -> FrameBuilder<T>
	where
		T: Message + CheckDigestOid<ColonyDigest<P>>,
	{
		let builder = FrameBuilder::from(Version::V2)
			.with_id(id)
			.with_order(issued.instant().get())
			.with_message(message)
			.with_priority(MessagePriority::NetworkControl);

		self.witnessed(builder)
	}
}

/// The gateway request contexts that the runtime tests hand frames to.
#[cfg(test)]
pub(crate) mod fixtures {
	use std::sync::Arc;

	use super::{ColonyConfig, ColonyDigest, GatewayRuntimeCtx};
	use crate::builder::frame::{CheckDigestOid, FrameBuilder};
	use crate::builder::TypeBuilder;
	use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
	use crate::colony::cluster::runtime::hop::HivePlane;
	use crate::colony::cluster::{Cluster, ClusterConfig, ClusterGateway, HiveRegistry, ServletRegistry};
	use crate::runtime::TaskGroup;
	use crate::testing::TestFrame;
	use crate::trace::TraceCollector;
	use crate::transport::TokioListener;
	use crate::urn::Urn;
	use crate::{Frame, Message, Version};

	/// A gateway request context beside the trace and the connection trace
	/// that it records on.
	pub(crate) struct Audited {
		/// The request context, which binds no listener.
		pub(crate) gateway: GatewayRuntimeCtx<TokioListener>,
		/// The trace that records the events of a proven peer.
		pub(crate) trace: Arc<TraceCollector>,
		/// The trace that records the events of an anonymous connection.
		pub(crate) connections: Arc<TraceCollector>,
	}

	impl Audited {
		/// A gateway under `config`, with two traces of its own.
		pub(crate) fn of(config: ClusterConfig) -> Self {
			let (trace, connections) = (Arc::new(TraceCollector::new()), Arc::new(TraceCollector::new()));
			let gateway = GatewayRuntimeCtx::for_test(config, &trace, &connections);
			Self { gateway, trace, connections }
		}

		/// The count of `event` on the trace, then on the connection trace.
		pub(crate) fn counts(&self, event: Urn<'static>) -> (usize, usize) {
			(self.trace.recorded(&event), self.connections.recorded(&event))
		}
	}

	impl ColonyConfig<TokioListener> {
		/// `config` as the configuration of a house gateway, whose colony
		/// digest is SHA3-256.
		pub(crate) fn house(config: ClusterConfig) -> Self {
			ColonyConfig::new(config).expect("a test configuration mints its gossip ingress key")
		}

		/// `message` in the V2 frame `id`, issued at the reading of this
		/// gateway's clock, witnessed under its colony digest, and signed by
		/// its own identity.
		pub(crate) fn self_signed<T>(&self, id: impl AsRef<[u8]>, message: T) -> Frame
		where
			T: Message + CheckDigestOid<ColonyDigest<TokioListener>>,
		{
			let issued = FrameBuilder::from(Version::V2).with_id(id).with_order(self.clock.unix().get());
			let built = self.witnessed(issued.with_message(message)).build();
			TestFrame::signed_by(built.expect("a witnessed frame builds"), self.tls.identity())
		}
	}

	impl GatewayRuntimeCtx<TokioListener> {
		/// The request context of a gateway under `config` that binds no
		/// listener, and files its records on `trace` and `connections`.
		pub(crate) fn for_test(
			config: ClusterConfig,
			trace: &Arc<TraceCollector>,
			connections: &Arc<TraceCollector>,
		) -> Self {
			let config = ColonyConfig::house(config);
			let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock, trace);
			let clock = Arc::clone(&config.clock);
			let registry = HiveRegistry::new(config.heartbeat.timeout, Arc::clone(&clock));
			let servlet_registry = ServletRegistry::new(config.pheromone.clone(), Arc::clone(&clock))
				.with_ad_tombstone_window(config.control_freshness_window);
			let hive_plane = HivePlane::new(pools.hive, Arc::clone(trace));
			let peer_plane = hive_plane.peers(pools.peer, config.clone());

			Self {
				registry: Arc::new(registry),
				servlet_registry: Arc::new(servlet_registry),
				admission: Arc::default(),
				hive_plane,
				peer_plane,
				trace: Arc::clone(trace),
				connections: Arc::clone(connections),
				replay_guard: GatewayReplayGuard::new(config.control_freshness_window, clock),
				tasks: TaskGroup::default(),
				ledgers: Arc::default(),
				config,
			}
		}
	}

	impl ClusterGateway<TokioListener> {
		/// A live gateway under `config` on a loopback port, which records on
		/// `trace`.
		pub(crate) async fn started(config: ClusterConfig, trace: Arc<TraceCollector>) -> Self {
			let started = ClusterGateway::start(trace, config).await;
			started.expect("a gateway binds a loopback port")
		}
	}
}
