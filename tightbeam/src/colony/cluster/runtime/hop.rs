//! One dial target on a gateway trust plane.
//!
//! Every outbound gateway hop pairs a plane with the address to dial on
//! it. [`Hop`] holds that pair, so a hop fixes the plane of its payload once,
//! at construction.
//!
//! - A servlet hop dials through [`HivePlane::servlet`], which binds it to the signer its registration names.
//! - A heartbeat dials through [`HivePlane::hive`], which binds it to the signer of the hive's registration.
//! - A peer hop dials through [`PeerPlane::hop`], which binds the hop to the gateway its route names.
//! - A gossip dial goes through [`PeerPlane::connect_member`], which proves the answer is a flood member.
//! - A direct advertisement goes through [`PeerPlane::advertiser`], the one
//!   unbound dial, so its client talks to whichever gateway answers. Its
//!   connection stays pooled only when that gateway is a flood member.

use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::bound_dial::{BoundDial, ExpectedSigner};
use crate::colony::cluster::peer::FloodMember;
use crate::colony::cluster::runtime::advertise::Advertiser;
use crate::colony::cluster::runtime::bounds::{ClusterPool, ColonyConfig, ColonyDialProtocol};
use crate::colony::cluster::{ClusterError, DialTarget, HiveEntry};
use crate::crypto::x509::Certificate;
use crate::trace::TraceCollector;
use crate::transport::TransportResult;
use crate::transport::{PooledClient, Protocol};
use crate::Frame;

/// The plane this gateway dials its own hives and their servlets on.
///
/// The pool is private, and the plane offers two ways to it, each a
/// [`BoundDial`], so a frame leaves toward a hive or a servlet only under the
/// identity its registration names (CWE-346):
///
/// - [`Self::servlet`] binds a hop to the signer a servlet's registration names.
/// - [`Self::hive`] binds a hop to the signer of a hive's registration.
///
/// A gateway with no peer pool dials its peers on this pool, through the
/// [`PeerPlane`] that [`Self::peers`] lends it to.
pub(crate) struct HivePlane<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	/// The collector that records each refused hop.
	trace: Arc<TraceCollector>,
}

// The impl is manual because a derive would demand `P: Clone`, and every
// field is reference-counted regardless of `P`.
impl<P: Protocol> Clone for HivePlane<P> {
	fn clone(&self) -> Self {
		Self { pool: Arc::clone(&self.pool), trace: Arc::clone(&self.trace) }
	}
}

impl<P: Protocol> HivePlane<P> {
	/// A plane that dials hives and their servlets on `pool`, and records
	/// each refused hop on `trace`.
	pub(crate) fn new(pool: Arc<ClusterPool<P>>, trace: Arc<TraceCollector>) -> Self {
		Self { pool, trace }
	}

	/// Targets the servlet at `dial`, bound to `signer`, the signer its hive's
	/// registration names.
	pub(crate) fn servlet(&self, dial: DialTarget, signer: Arc<SignerIdentifier>) -> Hop<'_, P> {
		let bound = BoundDial::new(dial, ExpectedSigner::Hive(signer));

		Hop { pool: &self.pool, dial: bound, trace: &self.trace }
	}

	/// Targets the control address of `hive`, bound to the signer of its
	/// registration, so a heartbeat admits that identity alone (CWE-346).
	pub(crate) fn hive(&self, hive: &HiveEntry) -> Hop<'_, P> {
		Hop { pool: &self.pool, dial: hive.bound_dial(), trace: &self.trace }
	}

	/// The plane this gateway dials its peers on: `peer_pool`, which keeps
	/// peer traffic off the hive pool, or this plane's pool for a gateway that
	/// configures no peer pool. It names each gateway that answers through
	/// [`ColonyConfig::peer_identity`] of `config`.
	///
	/// The gateway resolves its peer plane here once, as it starts.
	pub(crate) fn peers(&self, peer_pool: Option<Arc<ClusterPool<P>>>, config: ColonyConfig<P>) -> PeerPlane<P> {
		let pool = peer_pool.unwrap_or_else(|| Arc::clone(&self.pool));
		PeerPlane::new(pool, config, Arc::clone(&self.trace))
	}
}

/// The plane this gateway dials peer gateways on: the peer pool, or the hive
/// pool when the gateway configures no peer trust.
///
/// An advertisement binds its signer to the socket it claims. The pool is
/// private, and the plane offers three ways to it:
///
/// - [`Self::hop`] carries a route and holds the answer to the gateway it
///   names before any frame leaves. A forward dials this way, so it reaches
///   only that gateway (CWE-668).
/// - [`Self::connect_member`] proves the answer at an address is a flood
///   member before any frame leaves. A reconcile round and a rumor flood dial
///   this way, so gossip stays inside the flood (CWE-668).
/// - [`Self::advertiser`] hands out the one unbound dial, which a direct
///   advertisement uses, so its client talks to whichever gateway answers.
pub(crate) struct PeerPlane<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	config: ColonyConfig<P>,
	/// The collector that records each refused hop.
	trace: Arc<TraceCollector>,
}

// The impl is manual because a derive would demand `P: Clone`, and every
// field is reference-counted regardless of `P`.
impl<P: Protocol> Clone for PeerPlane<P> {
	fn clone(&self) -> Self {
		Self {
			pool: Arc::clone(&self.pool),
			config: self.config.clone(),
			trace: Arc::clone(&self.trace),
		}
	}
}

impl<P: Protocol> PeerPlane<P> {
	/// A plane that dials peer gateways on `pool`, names each gateway that
	/// answers through [`ColonyConfig::peer_identity`] of `config`, and
	/// records each refused hop on `trace`.
	pub(crate) fn new(pool: Arc<ClusterPool<P>>, config: ColonyConfig<P>, trace: Arc<TraceCollector>) -> Self {
		Self { pool, config, trace }
	}

	/// Targets `dial` on this plane, bound to the gateway whose slate key is
	/// `gateway_id`.
	pub(crate) fn hop<'p>(&'p self, dial: DialTarget, gateway_id: &'p (impl AsRef<[u8]> + ?Sized)) -> Hop<'p, P> {
		let expected = ExpectedSigner::Gateway { gateway_id: gateway_id.as_ref(), config: &self.config };
		let bound = BoundDial::new(dial, expected);

		Hop { pool: &self.pool, dial: bound, trace: &self.trace }
	}

	/// The one unbound dial on this plane's pool, which a direct
	/// advertisement sends through.
	pub(crate) fn advertiser(&self) -> Advertiser<P> {
		Advertiser::new(Arc::clone(&self.pool), self.config.clone())
	}
}

/// A dialed connection whose far end proved it belongs to this gateway's
/// flood.
///
/// [`PeerPlane::connect_member`] is the only constructor, and a gossip frame
/// leaves through [`Self::emit`] alone, so gossip reaches a flood member and
/// no other gateway (CWE-668).
pub(crate) struct FloodClient<P: ColonyDialProtocol> {
	client: PooledClient<P>,
}

impl<P: ColonyDialProtocol> FloodClient<P> {
	/// Wraps `client`, whose far end `_proof` names as a flood member.
	fn new(client: PooledClient<P>, _proof: FloodMember) -> Self {
		Self { client }
	}

	/// Emits `frame` to the member and returns its reply, when it sends one.
	///
	/// # Errors
	///
	/// - [`crate::transport::TransportError`] -- the emit failed on the pooled connection.
	pub(crate) async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		self.client.emit(frame, attempt).await
	}

	/// The certificate the member presented in the handshake.
	pub(crate) fn peer_certificate(&self) -> Option<&Certificate> {
		self.client.peer_certificate()
	}
}

/// A bound dial on the pool of its plane.
///
/// Every hop is a [`BoundDial`], so a frame leaves a hop only toward the party
/// its route names.
pub(crate) struct Hop<'p, P: Protocol> {
	/// The pool the hop dials on: the hive pool for a hive or a servlet, and
	/// the peer plane's pool for a gateway.
	pool: &'p Arc<ClusterPool<P>>,
	/// The target, and the identity its answer must prove.
	dial: BoundDial<'p, P>,
	/// The collector that records a refused dial.
	trace: &'p TraceCollector,
}

impl<P: ColonyDialProtocol> PeerPlane<P> {
	/// Connects to `address` and returns the client once the gateway that
	/// answered proved it belongs to this gateway's flood.
	///
	/// - A cold connection defers its handshake to the first emit, so the
	///   handshake completes here, before the caller can send anything.
	/// - `None` means a gateway outside the flood answered, which is an answer
	///   about the address. An `Err` is a failed dial.
	/// - It asks for the proof on every call, so a pooled connection to a
	///   gateway the trust store has since dropped yields `None`.
	/// - An answer outside the flood takes its connection out of the pool, so a
	///   later dial of the address meets the party that answers it then.
	///
	/// # Errors
	///
	/// - [`ClusterError::Transport`] -- the dial or the handshake failed, or
	///   the runtime fault model injects a fault at the eviction of an answer
	///   outside the flood.
	pub(crate) async fn connect_member(
		&self,
		address: impl Into<P::Address>,
	) -> Result<Option<FloodClient<P>>, ClusterError> {
		let mut client = self.pool.connect(address).await?;
		client.complete_handshake().await?;

		let member = client.peer_certificate().and_then(|answer| self.config.flood_member(answer));
		let Some(member) = member else {
			client.discard()?;
			return Ok(None);
		};

		Ok(Some(FloodClient::new(client, member)))
	}
}

impl<P: ColonyDialProtocol> Hop<'_, P> {
	/// Delivers a client's end-to-end frame and returns the peer's
	/// complete reply frame.
	///
	/// - `frame` is the client's frame from [`ClusterWorkRequest::payload`],
	///   re-emitted as-is. DER is canonical, so the emitted bytes match what
	///   the client signed and the servlet can verify the envelope end to end.
	/// - An origin-signed gossip rumor reaches an ingress servlet through this path too, for the same reason.
	///
	/// [`ClusterWorkRequest::payload`]: crate::colony::protocol::ClusterWorkRequest::payload
	pub(crate) async fn deliver_frame(self, frame: Frame) -> Result<Frame, ClusterError> {
		self.emit(frame).await
	}

	/// Delivers hop-local bytes under a fresh transport wrapper and
	/// returns the reply frame.
	///
	/// This path carries the one hop-local message, a re-encoded
	/// [`ClusterRequest::Work`] envelope toward a peer gateway. Every other
	/// path carries an end-to-end frame.
	///
	/// [`ClusterRequest::Work`]: crate::colony::protocol::ClusterRequest::Work
	pub(crate) async fn deliver_envelope(self, message: impl Into<Vec<u8>>) -> Result<Frame, ClusterError> {
		let message: Vec<u8> = message.into();
		let frame = Frame::v0(b"work-forward", message);

		self.emit(frame).await
	}

	/// Opens a pooled connection to the target, with its handshake complete,
	/// so a refused handshake is a refused connect and no frame has left.
	///
	/// - The target becomes a protocol address through
	///   [`DialTarget::protocol_address`], so a stream open and a unary emit
	///   reach a peer through the one conversion every dial uses.
	/// - [`BoundDial::connect`] records a refused answer on the trace of this hop's plane.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- the errors of [`BoundDial::connect`].
	pub(crate) async fn connect(self) -> Result<PooledClient<P>, ClusterError> {
		self.dial.connect(self.pool, self.trace).await
	}

	/// Dials the target, emits `frame`, and returns the reply frame.
	async fn emit(self, frame: Frame) -> Result<Frame, ClusterError> {
		let mut client = self.connect().await?;
		match client.emit(frame, None).await {
			Ok(Some(response)) => Ok(response),
			Ok(None) => Err(ClusterError::NoResponse),
			Err(e) => Err(ClusterError::from(e)),
		}
	}
}

#[cfg(test)]
mod tests {
	use core::num::NonZeroUsize;

	use super::*;
	use crate::colony::cluster::peer::ColonyCertificate;
	use crate::colony::cluster::runtime::advertise::SignedAdvertisement;
	use crate::colony::cluster::{
		AdmittedDial, Cluster, ClusterConfig, ClusterGateway, ClusterTlsConfig, ColonyDigest, SharedId,
	};
	use crate::colony::urn::ColonyNamespace;
	use crate::crypto::x509::store::CertificateTrust;
	use crate::crypto::x509::utils::CertificateExt;
	#[cfg(feature = "testing")]
	use crate::instrumentation::events::CLUSTER_DIAL_REFUSED;
	use crate::policy::TransitStatus;
	use crate::tb_cases;
	use crate::testing::fixtures::TestStore;
	use crate::testing::{TestCertificate, TestKey, TestResult};
	use crate::transport::client::PoolConfig;
	use crate::transport::error::TransportError;
	use crate::transport::handshake::negotiation::TransportOffer;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::urn::Urn;

	type Gateway = ClusterGateway<TokioListener>;

	/// A gateway certificate on the fixed key of `seed` that carries each of
	/// `colonies` as a URI Subject Alternative Name, beside its TLS material.
	fn identity(seed: u8, cn: &str, colonies: &[&str]) -> (Certificate, ClusterTlsConfig) {
		let key = TestKey::fixed(seed);
		let certificate = TestCertificate::with_cn_and_uri_sans(&key, cn, colonies);
		(certificate.clone(), ClusterTlsConfig::fixture_of(certificate, key))
	}

	/// A gateway that serves under `tls` on a loopback port, and accepts a
	/// multiplexed dial.
	async fn serve(tls: ClusterTlsConfig) -> Gateway {
		let mut config = ClusterConfig::new(tls);
		config.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
		ClusterGateway::started(config, Arc::default()).await
	}

	/// The dial target of the socket `gateway` listens on, as a peer would
	/// claim it.
	fn target_of(gateway: &Gateway) -> DialTarget {
		let socket = gateway.addr().0.to_string();
		DialTarget::of_claimed(AdmittedDial::fixture(socket))
	}

	/// The signer identifier a registration that names `certificate` carries.
	fn signer_of(certificate: &Certificate) -> Arc<SignerIdentifier> {
		let signer = certificate.signer_identifier();
		Arc::new(signer.expect("the fixture certificate names its signer"))
	}

	/// A gateway with no peer plane, which dials its peers on its hive pool,
	/// and the two gateways it can reach there.
	///
	/// - Its hive trust holds the member and the stranger, so a handshake with either completes.
	/// - The member carries the colony URN of the dialer, and the stranger carries none.
	struct Dialer {
		config: ColonyConfig<TokioListener>,
		pool: Arc<ClusterPool<TokioListener>>,
		plane: HivePlane<TokioListener>,
		member_certificate: Certificate,
		stranger_certificate: Certificate,
		member: Gateway,
		stranger: Gateway,
	}

	impl Dialer {
		/// Starts the member and the stranger, and builds the dialer's hive
		/// pool from the `pool` configuration.
		async fn start(pool: PoolConfig) -> Self {
			let colony = ColonyNamespace::colony_fixture("main").to_string();
			let (member_certificate, member) = identity(3, "Member Gateway", &[&colony]);
			let (stranger_certificate, stranger) = identity(4, "Stranger Gateway", &[]);
			let (_, dialing) = identity(5, "Dialing Gateway", &[&colony]);

			let held = [member_certificate.clone(), stranger_certificate.clone()];
			let hive_trust: Arc<dyn CertificateTrust> = Arc::new(TestStore::holding(held));

			let mut config = ClusterConfig::new(dialing.with_hive_trust(Some(hive_trust)));
			config.pool_config = pool;

			let trace = Arc::new(TraceCollector::default());
			let pools = config.tls.pools::<TokioListener>(&config.pool_config, &config.clock, &trace);
			let plane = HivePlane::new(Arc::clone(&pools.hive), trace);

			Self {
				config: ColonyConfig::new(config).expect("the test configuration names no gossip ingress"),
				pool: pools.hive,
				plane,
				member_certificate,
				stranger_certificate,
				member: serve(member).await,
				stranger: serve(stranger).await,
			}
		}

		/// The configuration of a hive pool that holds one connection, which it
		/// offers for multiplexing when `multiplexed` holds.
		fn one_connection(multiplexed: bool) -> PoolConfig {
			let mux_offer = multiplexed.then(|| Arc::new(TransportOffer::mux(8)));
			PoolConfig { idle_timeout: None, max_connections: NonZeroUsize::MIN, mux_offer }
		}

		/// The plane this gateway dials its peers on, which is its hive pool.
		fn peers(&self) -> PeerPlane<TokioListener> {
			self.plane.peers(None, self.config.clone())
		}

		/// A servlet hop to `gateway`, bound to the signer that a registration
		/// of the member names.
		fn member_hop_to<'d>(&'d self, gateway: &Gateway) -> Hop<'d, TokioListener> {
			self.plane.servlet(target_of(gateway), signer_of(&self.member_certificate))
		}

		/// The dial of a servlet hop to the stranger, bound to the signer of
		/// the member, which the stranger's answer refuses.
		async fn refused_member_hop(&self) -> Result<PooledClient<TokioListener>, ClusterError> {
			self.member_hop_to(&self.stranger).connect().await
		}

		/// A servlet hop to the stranger, bound to the signer that its own
		/// certificate names, so the stranger's answer proves it.
		fn stranger_hop(&self) -> Hop<'_, TokioListener> {
			let signer = signer_of(&self.stranger_certificate);
			self.plane.servlet(target_of(&self.stranger), signer)
		}

		/// The slate key a route of the member carries.
		fn member_name(&self) -> SharedId {
			let name = self.member_certificate.fingerprint_id::<ColonyDigest<TokioListener>>();
			name.expect("the member certificate has a fingerprint")
		}

		/// Advertises this gateway, with an empty type list, to whichever
		/// party answers at the socket of `gateway`.
		async fn advertise_to(&self, gateway: &Gateway) -> Result<TransitStatus, ClusterError> {
			let types: Vec<Urn<'static>> = Vec::new();
			let minted = self.config.mint_ad_frame(b"127.0.0.1:1", types).await;
			let advertisement: SignedAdvertisement = minted.expect("the dialing gateway signs its advertisement");

			self.peers().advertiser().advertise(*gateway.addr(), &advertisement).await
		}
	}

	/// A refused answer leaves the pool, so a later dial of the address meets
	/// whichever party answers it then.
	#[tokio::test]
	async fn a_refused_hop_leaves_the_pool() -> TestResult {
		let dialer = Dialer::start(PoolConfig::default()).await;

		let refused = dialer.refused_member_hop().await;
		let pooled = dialer.pool.try_acquire(dialer.stranger.addr())?;
		assert!(matches!(refused, Err(ClusterError::PeerMismatch)));
		assert!(pooled.is_none());
		Ok(())
	}

	/// A refused answer records the refusal on the trace of the hop's plane.
	#[cfg(feature = "testing")]
	#[tokio::test]
	async fn a_refused_hop_records_its_refusal_on_its_plane() {
		let dialer = Dialer::start(PoolConfig::default()).await;

		let refused = dialer.refused_member_hop().await;
		let recorded = dialer.plane.trace.recorded(CLUSTER_DIAL_REFUSED);
		assert!(matches!(refused, Err(ClusterError::PeerMismatch)));
		assert_eq!(recorded, 1);
	}

	// A refused answer gives back the slot of its connection, plain or
	// multiplexed, so a pool of one connection reaches the party that the
	// next dial names. A refused multiplexed answer also takes its entry out
	// of the pool.
	tb_cases! {
		async fn a_refused_hop_gives_back_its_slot(multiplexed: bool) {
			let dialer = Dialer::start(Dialer::one_connection(multiplexed)).await;

			let refused = dialer.refused_member_hop().await;
			let admitted = dialer.member_hop_to(&dialer.member).connect().await;
			assert!(matches!([refused, admitted], [Err(ClusterError::PeerMismatch), Ok(_)]));
		}
		cases {
			plain => false,
			multiplexed => true,
		}
	}

	/// A refused multiplexed answer drains and closes the connection that every
	/// lease of it shares, so the next emit of a lease that holds it fails.
	#[tokio::test]
	async fn a_refused_multiplexed_answer_drains_its_connection() -> TestResult {
		let dialer = Dialer::start(Dialer::one_connection(true)).await;
		let mut held = dialer.stranger_hop().connect().await?;
		let refused = dialer.refused_member_hop().await;

		// The refusal drains the shared connection on a task of its own, and
		// the transport signals no end of that drain, so one yield lets the
		// task run before the emit reads the connection.
		tokio::task::yield_now().await;

		let emitted = held.emit(Frame::v0(b"after-refusal", Vec::new()), None).await;
		assert!(matches!(refused, Err(ClusterError::PeerMismatch)));
		assert!(matches!(
			emitted,
			Err(TransportError::Draining | TransportError::ConnectionClosed)
		));
		Ok(())
	}

	/// A gossip dial that a gateway outside the flood answers leaves the pool.
	#[tokio::test]
	async fn a_gossip_dial_answered_outside_the_flood_leaves_the_pool() -> TestResult {
		let dialer = Dialer::start(PoolConfig::default()).await;

		let answered = dialer.peers().connect_member(*dialer.stranger.addr()).await?;
		let pooled = dialer.pool.try_acquire(dialer.stranger.addr())?;
		assert!(answered.is_none());
		assert!(pooled.is_none());
		Ok(())
	}

	/// The gateway of a dialer that an advertisement goes to.
	type Advertised = fn(&Dialer) -> &Gateway;

	// An advertisement goes to whichever gateway answers. Its connection
	// leaves the pool when that gateway is outside the flood, and stays
	// pooled when a flood member answers, so the gossip round that follows
	// reuses the connection.
	tb_cases! {
		async fn an_advertisement_keeps_its_connection_for_a_member_alone((advertised, pooled): (Advertised, bool))
			-> TestResult
		{
			let dialer = Dialer::start(PoolConfig::default()).await;
			let gateway = advertised(&dialer);

			dialer.advertise_to(gateway).await?;

			let held = dialer.pool.try_acquire(gateway.addr())?;
			assert_eq!(held.is_some(), pooled);
			Ok(())
		}
		cases {
			outside_the_flood => (|dialer| &dialer.stranger, false),
			member => (|dialer| &dialer.member, true),
		}
	}

	/// A gateway records on its connection trace the gate verdict of each
	/// request its colony plane answers, and its own trace records none.
	#[cfg(feature = "instrument")]
	#[tokio::test]
	async fn a_gateway_records_the_gate_verdicts_of_its_colony_plane_on_its_connection_trace() -> TestResult {
		use crate::instrumentation::events;
		use crate::testing::fixtures::TestTrace;

		let dialer = Dialer::start(PoolConfig::default()).await;
		dialer.advertise_to(&dialer.member).await?;

		let kept = [events::GATE_ACCEPT, events::GATE_REJECT];
		let own = TestTrace::trail(&dialer.member.trace(), &kept);
		let connections = TestTrace::trail(&dialer.member.connection_trace(), &kept);
		assert_eq!((own, connections), (vec![], vec![events::GATE_ACCEPT]));
		Ok(())
	}

	/// A gateway with no peer plane names the peer it dials by its hive trust,
	/// the store its hive pool verifies the handshake against.
	#[tokio::test]
	async fn a_peer_hop_without_a_peer_plane_admits_the_gateway_its_hive_trust_names() {
		let dialer = Dialer::start(PoolConfig::default()).await;
		let peers = dialer.peers();
		let member = dialer.member_name();

		let admitted = peers.hop(target_of(&dialer.member), &member).connect().await;
		assert!(admitted.is_ok());
	}

	/// A peer hop with no peer plane refuses a stranger at the address its
	/// route names, though the hive trust admits its handshake (CWE-346).
	#[tokio::test]
	async fn a_peer_hop_without_a_peer_plane_refuses_a_stranger() {
		let dialer = Dialer::start(PoolConfig::default()).await;
		let peers = dialer.peers();
		let member = dialer.member_name();

		let refused = peers.hop(target_of(&dialer.stranger), &member).connect().await;
		assert!(matches!(refused, Err(ClusterError::PeerMismatch)));
	}
}
