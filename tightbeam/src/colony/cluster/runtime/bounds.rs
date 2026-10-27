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
use crate::colony::cluster::{ClusterConfig, HiveRegistry, ServletRegistry};
use crate::crypto::profiles::DigestProvider;
use crate::macros::server::AcceptedConnection;
use crate::policy::SessionContext;
use crate::runtime::TaskGroup;
use crate::trace::TraceCollector;
use crate::transport::client::ConnectionPool;
use crate::transport::handshake::HandshakeProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxCapable, MuxConnector};
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{AsyncListenerTrait, EncryptedProtocol, PersistentConnection, Protocol};
use crate::Message;

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
	/// The plane this gateway dials peer gateways on, when one is configured.
	pub(crate) peer_plane: Option<PeerPlane<P>>,
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
	/// Admission and retirement move both, so they run here rather than as
	/// a sequence each call site repeats.
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
/// witness, is a method here under [`ColonyDigest`] of `P`, so a gateway names
/// its peers and digests its rumors under one digest. The configuration is
/// shared, and this type dereferences to it.
pub(crate) struct ColonyConfig<P> {
	config: Arc<ClusterConfig>,
	protocol: PhantomData<fn() -> P>,
}

impl<P> ColonyConfig<P> {
	/// The shared configuration `config` of a gateway that runs `P`.
	pub(crate) fn new(config: ClusterConfig) -> Self {
		Self { config: Arc::new(config), protocol: PhantomData }
	}
}

// The impl is manual because a derive would demand `P: Clone`, and the
// configuration is reference-counted regardless of `P`.
impl<P> Clone for ColonyConfig<P> {
	fn clone(&self) -> Self {
		Self { config: Arc::clone(&self.config), protocol: PhantomData }
	}
}

impl<P> Deref for ColonyConfig<P> {
	type Target = ClusterConfig;

	fn deref(&self) -> &ClusterConfig {
		&self.config
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
}

/// The gateway request contexts that the runtime tests hand frames to.
#[cfg(test)]
pub(crate) mod fixtures {
	use std::sync::Arc;

	use super::{ColonyConfig, GatewayRuntimeCtx};
	use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
	use crate::colony::cluster::runtime::hop::HivePlane;
	use crate::colony::cluster::{CertificateSpec, ClusterConfig, ClusterTlsConfig, HiveRegistry, ServletRegistry};
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::runtime::TaskGroup;
	use crate::testing::{TestCertificate, TestKey};
	use crate::trace::TraceCollector;
	use crate::transport::TokioListener;

	/// A colony member whose peer trust enrolls its own certificate, so it
	/// admits a peer advertisement that it signs itself.
	pub(crate) fn self_peering_config() -> ClusterConfig {
		let key: Secp256k1SigningKey = TestKey::insecure_fixed_signing();
		let colony = ColonyNamespace::default().colony("main").expect("a literal colony name");
		let certificate = TestCertificate::with_uri_sans(&key, &[&colony.to_string()]);
		let enrolled = CertificateTrustBuilder::from(Secp256k1Policy::default()).with_certificate(certificate.clone());
		let peer_trust: Arc<dyn CertificateTrust> = Arc::new(enrolled.expect("the member enrolls").build());
		let spec = CertificateSpec::Built(Box::new(certificate));
		let tls = ClusterTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key)));
		let tls = tls.expect("the member certificate must decode").with_peer_trust(peer_trust);

		let mut config = ClusterConfig::new(tls);
		config.bind_colony_membership();
		config
	}

	impl GatewayRuntimeCtx<TokioListener> {
		/// The request context of a gateway under `config` that binds no
		/// listener, and files its records on `trace` and `connections`.
		pub(crate) fn for_test(
			config: ClusterConfig,
			trace: &Arc<TraceCollector>,
			connections: &Arc<TraceCollector>,
		) -> Self {
			let config = ColonyConfig::<TokioListener>::new(config);
			let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock, trace);
			let clock = Arc::clone(&config.clock);
			let registry = HiveRegistry::new(config.heartbeat.timeout, Arc::clone(&clock));
			let servlet_registry = ServletRegistry::new(config.pheromone.clone(), Arc::clone(&clock));

			Self {
				registry: Arc::new(registry),
				servlet_registry: Arc::new(servlet_registry),
				admission: Arc::default(),
				hive_plane: HivePlane::new(pools.hive, Arc::clone(trace)),
				peer_plane: None,
				trace: Arc::clone(trace),
				connections: Arc::clone(connections),
				replay_guard: GatewayReplayGuard::new(config.control_freshness_window, clock),
				tasks: TaskGroup::default(),
				ledgers: Arc::default(),
				config,
			}
		}
	}
}
