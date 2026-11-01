//! A colony an outside crate runs under [`OutsideProvider`] alone: two member
//! gateways, a hive, and the hive's servlet, each on [`TokioListener`] of that
//! provider.
//!
//! - Every frame signs under the outside signature, and every party verifies it under the outside policy.
//! - A gateway goes by its certificate's fingerprint under the outside digest, SHA3-512.
//! - A rumor digests under the outside digest too.
//! - The outside provider names [`NoStrengthFloor`] as its floor, because its profile runs AES-128-GCM.
//!
//! The scenarios run a registration, a heartbeat, a peer advertisement, a
//! gossip rumor, a work forward, and a call through the hive's context, and
//! each dial the colony binds admits the party its route or its registration
//! names. A second hive and a third gateway give a dial another identity at
//! the address it binds, and the dial refuses that identity.
//!
//! [`NoStrengthFloor`]: tightbeam::crypto::profiles::NoStrengthFloor

#![cfg(feature = "colony")]

use core::time::Duration;
use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::clock::UnixMillis;
use tightbeam::colony::cluster::{
	Cluster, ClusterConfig, ClusterError, ClusterHeartbeat, ClusterTlsConfig, GossipConfig, GossipDigest,
	GossipJournal, MemoryGossipJournal,
};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
use tightbeam::colony::protocol::{
	ClusterRequest, GossipResponse, GossipRumor, PeerAdvertisement, PeerAdvertisementResponse, RegisterHiveRequest,
	RegisterHiveResponse,
};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::hash::{Digest, Sha3_512};
use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::utils::Fingerprint;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::random::OsRng;
use tightbeam::testing::{HiveEnv, SetupEnv, TestCertificate, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, Protocol};
use tightbeam::urn::Urn;
use tightbeam::x509::Certificate;
use tightbeam::{absent, at_least, cluster, exactly, hive, servlet, tb_assert_spec, tb_scenario, urn};
use tightbeam::{Frame, Message, TightBeamError, Version};

use super::{forged_identity_of, outside_identity_of, OutsideProvider};
use crate::common::hive::scenario_hive_config;
use crate::common::poll::poll_until;
use crate::common::result::TestResult;
use crate::common::security::trust_under;

const OUTSIDE_ECHO_RAN: Urn<'static> = urn!("test", "event:seams/outside-echo-ran");

/// The content the client's work frame carries and the servlet echoes.
const OUTSIDE_CONTENT: &str = "forwarded under an outside provider";

/// The advertise beat of each gateway, so a scenario sees its peer within a
/// few beats.
const BEAT: Duration = Duration::from_millis(100);

/// The hop radius of a relay that a test builds.
const RELAY_TTL: u64 = 2;

/// The protocol every party of the outside colony runs: TCP under the outside
/// provider.
type OutsideListener = TokioListener<OutsideProvider>;

/// The identity of a party that signs one layer of a relay.
type RelaySigner = fn(&Party) -> SigningIdentity;

servlet! {
	/// The servlet of the outside hive. It records each frame it runs and
	/// echoes the frame.
	OutsideEchoServlet<TestMessage, EnvConfig = ()>,
	protocol: OutsideListener,
	handle: raw |frame, ctx| async move {
		ctx.trace().event(OUTSIDE_ECHO_RAN)?;
		Ok(Some(frame))
	}
}

hive! {
	OutsideHive,
	protocol: OutsideListener
}

cluster! {
	OutsideGateway,
	protocol: OutsideListener
}

/// One party of the outside colony: a certificate that carries the colony URN
/// of the test namespace, and its key.
struct Party {
	certificate: Certificate,
	key: SigningKey,
}

impl Party {
	/// A party named `cn` on a fresh key.
	fn generate(cn: &str) -> Self {
		let key = SigningKey::random(&mut OsRng);
		let colony = ColonyNamespace::default().colony("main").expect("the test colony name mints");
		let certificate = TestCertificate::with_cn_and_uri_sans(&key, cn, &[&colony.to_string()]);

		Self { certificate, key }
	}

	/// The identity of this party under the outside provider.
	fn identity(&self) -> SigningIdentity {
		outside_identity_of(self.certificate.clone(), self.key.clone())
	}

	/// The identity of this party whose signatures another key makes, so each
	/// fails against the certificate of this party.
	fn forged_identity(&self) -> SigningIdentity {
		forged_identity_of(self.certificate.clone(), self.key.clone())
	}

	/// A client of this party's gateway at `addr`, which trusts this party's
	/// certificate.
	async fn client(&self, addr: &<OutsideListener as Protocol>::Address) -> GenericClient<OutsideListener> {
		let builder = ClientBuilder::<OutsideListener>::builder();
		let client = builder.with_trust_store(outside_trust(&[self])).build();

		let connected = client.connect(addr.to_owned()).await;
		connected.expect("the client reaches its gateway")
	}

	/// A publish of one application rumor, which this party signs under the
	/// outside provider.
	async fn publish(&self) -> Frame {
		let rumor = GossipRumor::application(b"rumor under an outside provider".to_vec());
		let request = ClusterRequest::PublishGossip(rumor);
		let order = UnixMillis::now().get();
		let builder = Version::V2.compose().with_id(b"outside-rumor").with_order(order);
		let mut frame = builder.with_message(request).build().expect("the publish frame builds");

		let signed = frame.sign_with_provider(&self.identity()).await;
		signed.expect("the outside identity signs the publish");
		frame
	}

	/// A control frame of `request`, which this party signs under the outside
	/// provider.
	async fn control_frame(&self, id: &[u8], request: ClusterRequest) -> Frame {
		let order = UnixMillis::now().get();
		let builder = Version::V1.compose().with_id(id).with_order(order);
		let mut frame = builder.with_message(request).build().expect("the control frame builds");

		let signed = frame.sign_with_provider(&self.identity()).await;
		signed.expect("the outside identity signs the control frame");
		frame
	}

	/// A hop of one application rumor of this party: the identity that
	/// `origin` names signs the rumor, and the identity that `outer` names
	/// signs the frame that carries it.
	async fn relay(&self, outer: RelaySigner, origin: RelaySigner) -> Frame {
		let body = GossipRumor::application(b"relayed under an outside provider".to_vec());
		let order = UnixMillis::now().get();
		let builder = Version::V2.compose().with_id(b"outside-relay").with_order(order);
		let mut rumor = builder.with_message(body).build().expect("the rumor frame builds");
		let signed = rumor.sign_with_provider(&origin(self)).await;
		signed.expect("the origin identity signs the rumor");

		let request = ClusterRequest::Gossip(Box::new(rumor));
		let builder = Version::V2
			.compose()
			.with_id(b"outside-relay")
			.with_order(order)
			.with_lifetime(RELAY_TTL);

		let mut frame = builder.with_message(request).build().expect("the relay frame builds");
		let signed = frame.sign_with_provider(&outer(self)).await;
		signed.expect("the outer identity signs the relay");
		frame
	}
}

/// The parties of one outside colony.
///
/// - The advertiser is the gateway the hive registers with, and it advertises its slate to the receiver.
/// - The receiver learns the advertiser's route and forwards work along it.
/// - The hive's servlet answers under the hive's identity.
/// - The second hive signs a registration in the hive trust of each gateway, and runs no hive.
/// - The third gateway sits in the peer trust of each gateway, and no route names it.
struct OutsideColony {
	receiver: Party,
	advertiser: Party,
	hive: Party,
	second_hive: Party,
	third_gateway: Party,
}

impl OutsideColony {
	/// A colony of fresh parties.
	fn generate() -> Self {
		let receiver = Party::generate("Outside Receiver");
		let advertiser = Party::generate("Outside Advertiser");
		let hive = Party::generate("Outside Hive");
		let second_hive = Party::generate("Outside Second Hive");
		let third_gateway = Party::generate("Outside Third Gateway");
		Self { receiver, advertiser, hive, second_hive, third_gateway }
	}

	/// The TLS material of `gateway`, with `peer` and the third gateway as its
	/// peer trust, and both hives as its hive trust.
	fn gateway_tls(&self, gateway: &Party, peer: &Party) -> ClusterTlsConfig {
		let tls = ClusterTlsConfig::from_identity(gateway.identity(), KeyPurposes::HOUSE);
		let tls = tls.expect("an outside certificate with no extended key usage signs for the gateway");
		let tls = tls.with_hive_trust(outside_trust(&[&self.hive, &self.second_hive]));
		tls.with_peer_trust(outside_trust(&[peer, &self.third_gateway]))
	}

	/// The configuration of `gateway`, which dials no peer of its own.
	fn lone_gateway_conf(&self, gateway: &Party) -> ClusterConfig {
		ClusterConfig::builder(self.gateway_tls(gateway, &self.receiver)).build()
	}

	/// The configuration of the receiver, which keeps the rumors it admits in
	/// `journal`.
	fn receiver_conf(&self, journal: Arc<MemoryGossipJournal>) -> ClusterConfig {
		let tls = self.gateway_tls(&self.receiver, &self.advertiser);
		let gossip = GossipConfig { journal, ..GossipConfig::default() };
		ClusterConfig::builder(tls).with_gossip_config(gossip).build()
	}

	/// The configuration of the advertiser, which advertises to the receiver
	/// at `receiver` on every beat.
	fn advertiser_conf(&self, receiver: &<OutsideListener as Protocol>::Address) -> ClusterConfig {
		let tls = self.gateway_tls(&self.advertiser, &self.receiver);
		let builder = ClusterConfig::builder(tls).with_peers([receiver.to_string()]);
		let builder = builder.expect("a bound gateway address names a socket");
		builder.with_advertise_interval(BEAT).with_rumor_refresh(BEAT).build()
	}

	/// The configuration of the hive, which trusts both gateways and its own
	/// servlet.
	fn hive_conf(&self) -> HiveConfig {
		let tls = HiveTlsConfig::from_identity(self.hive.identity(), PeerAuthentication::Anonymous, KeyPurposes::HOUSE);
		let tls = tls.expect("an outside certificate with no extended key usage signs for the hive");

		let hive_tls = Some(Arc::new(tls));
		let trust_store = Some(outside_trust(&[&self.receiver, &self.advertiser, &self.hive]));
		HiveConfig { hive_tls, trust_store, ..scenario_hive_config() }
	}

	/// The configuration of the hive's servlet, which answers under the hive's
	/// identity.
	fn servlet_conf(&self) -> ServletConfig<OutsideListener, TestMessage, OutsideProvider> {
		let builder = ServletConfig::<OutsideListener, TestMessage, OutsideProvider>::builder();
		let builder = builder.with_identity(self.hive.identity(), []);
		builder.with_config(Arc::new(())).build()
	}
}

/// A store under the outside policy that anchors the certificate of each of
/// `parties`.
fn outside_trust(parties: &[&Party]) -> Arc<dyn CertificateTrust> {
	trust_under::<OutsideProvider>(parties.iter().map(|party| &party.certificate))
}

/// The type URN the outside servlet registers under.
fn echo_urn() -> Urn<'static> {
	let namespace = ColonyNamespace::default();
	namespace.servlet("outside-echo").expect("test names satisfy the mint grammar")
}

/// Starts an established hive of `colony` with one echo servlet.
async fn start_outside_hive(trace: TraceCollector, colony: Arc<OutsideColony>) -> Result<OutsideHive, TightBeamError> {
	let servlet = OutsideEchoServlet::start(Arc::new(trace.share()), colony.servlet_conf()).await?;

	let mut hive = OutsideHive::new(Some(colony.hive_conf()))?;
	let spawner = |t| OutsideEchoServlet::start(t, ServletConfig::cleartext());
	hive.register(echo_urn(), servlet, spawner)?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// The started parties of an outside colony, with the hive registered at the
/// advertiser.
struct RegisteredColony {
	/// The gateway that learns the advertiser's route.
	receiver: OutsideGateway,
	/// The gateway the hive registers with.
	advertiser: OutsideGateway,
	/// The established hive, registered at the advertiser.
	hive: OutsideHive,
	/// The journal that keeps the rumors the receiver admits.
	journal: Arc<MemoryGossipJournal>,
}

impl RegisteredColony {
	/// Starts the receiver and the advertiser of `colony`, and registers
	/// `hive` with the advertiser.
	async fn start(trace: &TraceCollector, colony: &OutsideColony, hive: OutsideHive) -> Self {
		let journal = Arc::new(MemoryGossipJournal::default());
		let receiver_conf = colony.receiver_conf(Arc::clone(&journal));
		let receiver = OutsideGateway::start(Arc::new(trace.share()), receiver_conf).await;
		let receiver = receiver.expect("the receiver binds and starts");
		let advertiser_conf = colony.advertiser_conf(receiver.addr());
		let advertiser = OutsideGateway::start(Arc::new(trace.share()), advertiser_conf).await;
		let advertiser = advertiser.expect("the advertiser binds and starts");

		let registration = hive.register_with_cluster(advertiser.addr()).await;
		registration.expect("the advertiser admits the hive's registration");
		Self { receiver, advertiser, hive, journal }
	}

	/// Stops the advertiser, the receiver, and the hive.
	fn stop(self) {
		self.advertiser.stop();
		self.receiver.stop();
		self.hive.stop();
	}
}

/// Polls until `receiver` holds a route of the advertiser's slate.
async fn await_route(receiver: &OutsideGateway) {
	let learned = || receiver.peer_routes().is_ok_and(|routes| !routes.is_empty());
	poll_until(50, BEAT, learned).await;
}

/// Polls until `trace` holds a direct advertisement that a gateway admitted.
async fn await_advertisement(trace: &TraceCollector) {
	let advertised = || trace.recorded(events::CLUSTER_PEER_ADVERTISED) > 0;
	poll_until(50, BEAT, advertised).await;
}

/// Polls until `journal` holds a rumor, and returns its digest beside the
/// rumor, or `None` when none arrived.
async fn held_rumor(journal: &MemoryGossipJournal) -> Option<(GossipDigest, Frame)> {
	let held = || journal.held_digests(UnixMillis::now()).is_ok_and(|held| !held.is_empty());
	poll_until(50, BEAT, held).await;

	let now = UnixMillis::now();
	let held = journal.held_digests(now).unwrap_or_default();
	journal.fetch(&held, now).unwrap_or_default().into_iter().next()
}

/// The SHA3-512 digest of `rumor`, over its to-be-signed encoding and its
/// signature.
fn sha3_512_of(rumor: &Frame) -> Result<Vec<u8>, TightBeamError> {
	let tbs = rumor.to_tbs()?;
	let signer = rumor.nonrepudiation().ok_or(TightBeamError::MissingSignature)?;
	let digest = Sha3_512::digest([tbs.as_slice(), signer.signature.as_bytes()].concat());
	Ok(digest.to_vec())
}

/// The request that registers a hive with no servlet at `hive_addr`.
fn registration_at(hive_addr: impl ToString) -> ClusterRequest {
	let hive_addr = hive_addr.to_string().into_bytes();
	ClusterRequest::RegisterHive(RegisterHiveRequest { hive_addr, servlet_addresses: vec![], metadata: None })
}

/// The request that advertises [`echo_urn`] at `gateway_addr`.
fn advertisement_at(gateway_addr: impl ToString) -> ClusterRequest {
	let gateway_addr = gateway_addr.to_string().into_bytes();
	ClusterRequest::AdvertisePeer(PeerAdvertisement { gateway_addr, advertised_types: vec![echo_urn()] })
}

/// The answer of type `M` to `frame`, which `client` emits to its gateway.
async fn answer_of<M: Message>(client: &mut GenericClient<OutsideListener>, frame: Frame) -> Result<M, TightBeamError> {
	let answer = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
	answer.decode_message()
}

tb_assert_spec! {
	pub OutsideRegistrationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// A gateway admits the registration of a hive whose frame signs under the
// outside signature.
tb_scenario! {
	name: an_outside_hive_registers_with_an_outside_gateway,
	spec: OutsideRegistrationSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let registered = RegisteredColony::start(&trace, &colony, hive).await;

			registered.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideHeartbeatSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_ESTABLISHED, exactly!(1)),
			(events::HIVE_COMMAND_REFUSED, absent!()),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// The hive admits a heartbeat the gateway signs under the outside signature,
// on a dial bound to the identity of the hive's registration.
tb_scenario! {
	name: an_outside_hive_answers_the_heartbeat_of_its_gateway,
	spec: OutsideHeartbeatSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let registered = RegisteredColony::start(&trace, &colony, hive).await;
			let hive_addr = registered.hive.addr().copied().ok_or(TightBeamError::NotEstablished)?;

			let beat = registered.advertiser.send_heartbeat(hive_addr).await?;
			assert_eq!(beat.status, TransitStatus::Ok, "the hive answers the outside heartbeat");

			registered.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideHeartbeatBindingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, at_least!(1))
		]
	}
}

// The heartbeat dial admits the identity of the hive's registration alone
// (CWE-346). The second hive registers the address where the hive answers, and
// the hive trust of the gateway holds both identities, so the handshake
// completes and the binding of the dial refuses the answer.
tb_scenario! {
	name: an_outside_heartbeat_refuses_a_hive_that_answers_under_another_identity,
	spec: OutsideHeartbeatBindingSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let conf = colony.lone_gateway_conf(&colony.advertiser);
			let gateway = OutsideGateway::start(Arc::new(trace.share()), conf).await?;
			let hive_addr = hive.addr().copied().ok_or(TightBeamError::NotEstablished)?;
			let registration = colony.second_hive.control_frame(b"outside-register", registration_at(hive_addr)).await;
			let mut client = colony.advertiser.client(gateway.addr()).await;
			let registered: RegisterHiveResponse = answer_of(&mut client, registration).await?;

			let refused = gateway.send_heartbeat(hive_addr).await;
			assert_eq!(registered.status, TransitStatus::Ok);
			assert!(matches!(refused, Err(ClusterError::PeerMismatch)));

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideAdvertisementSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// A gateway admits the advertisement a peer signs under the outside
// signature.
tb_scenario! {
	name: an_outside_gateway_admits_the_advertisement_of_its_peer,
	spec: OutsideAdvertisementSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let registered = RegisteredColony::start(&trace, &colony, hive).await;

			await_advertisement(&trace).await;

			registered.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideGatewayNameSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// A route names the gateway that advertised it by the fingerprint of its
// certificate under the outside digest, SHA3-512.
tb_scenario! {
	name: an_outside_gateway_goes_by_its_sha3_512_fingerprint,
	spec: OutsideGatewayNameSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let registered = RegisteredColony::start(&trace, &colony, hive).await;
			await_route(&registered.receiver).await;

			let routes = registered.receiver.peer_routes()?;
			let fingerprint = Fingerprint::<Sha3_512>::from_certificate(&colony.advertiser.certificate)?;
			let named = routes.first().map(|route| route.peer_id.as_ref());
			assert_eq!(
				named,
				Some(fingerprint.as_slice()),
				"the route names the advertiser by its SHA3-512 fingerprint"
			);

			registered.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideRumorSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// A rumor the hive publishes through its gateway floods to the peer, which
// verifies both signatures under the outside policy and keeps the rumor under
// its 64-octet SHA3-512 digest.
tb_scenario! {
	name: an_outside_rumor_floods_under_its_sha3_512_digest,
	spec: OutsideRumorSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let registered = RegisteredColony::start(&trace, &colony, hive).await;
			let mut publisher = colony.advertiser.client(registered.advertiser.addr()).await;

			let publish = colony.hive.publish().await;
			// The receiver's journal is the observation, so the publisher's
			// reply goes unread.
			let _reply = publisher.emit(publish, None).await?;
			let held = held_rumor(&registered.journal).await;
			let (digest, rumor) = held.ok_or(TightBeamError::MissingResponse)?;
			assert_eq!(digest.as_bytes(), sha3_512_of(&rumor)?.as_slice());

			registered.stop();
			Ok(())
		}
	}
}

// A receiver verifies both signatures of a relay under the outside policy, so
// a forgery in either layer leaves the journal empty, and the relay that signs
// both layers under the key of its certificate is the positive control.
tightbeam::tb_cases! {
	async fn a_receiver_judges_each_signature_of_a_relay(
		(outer, origin, verdict): (RelaySigner, RelaySigner, (TransitStatus, usize))
	) -> TestResult {
		let colony = OutsideColony::generate();
		let journal = Arc::new(MemoryGossipJournal::default());
		let conf = colony.receiver_conf(Arc::clone(&journal));
		let receiver = OutsideGateway::start(Arc::new(TraceCollector::new()), conf).await?;
		let relay = colony.advertiser.relay(outer, origin).await;
		let mut client = colony.receiver.client(receiver.addr()).await;

		let answer: GossipResponse = answer_of(&mut client, relay).await?;
		let held = journal.held_digests(UnixMillis::now())?;
		assert_eq!((answer.status, held.len()), verdict);
		Ok(())
	}
	cases {
		/// The receiver keeps a rumor whose two signatures verify.
		of_honest_layers => (Party::identity, Party::identity, (TransitStatus::Ok, 1)),
		/// The receiver refuses a hop whose outer signature fails.
		of_a_forged_hop => (Party::forged_identity, Party::identity, (TransitStatus::PermissionDenied, 0)),
		/// The receiver refuses a rumor whose origin signature fails.
		of_a_forged_rumor => (Party::identity, Party::forged_identity, (TransitStatus::PermissionDenied, 0)),
	}
}

tb_assert_spec! {
	pub OutsideForwardSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(OUTSIDE_ECHO_RAN, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// The receiver forwards work along the route the advertiser named, on a dial
// bound to that gateway's SHA3-512 name, and the advertiser delivers it to the
// servlet its hive registered, on a dial bound to the hive's signer.
tb_scenario! {
	name: an_outside_gateway_forwards_work_to_its_peer,
	spec: OutsideForwardSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { trace, context: colony, hive }| async move {
			let registered = RegisteredColony::start(&trace, &colony, hive).await;
			await_route(&registered.receiver).await;

			let mut client = colony.receiver.client(registered.receiver.addr()).await;
			let message = TestMessage { content: OUTSIDE_CONTENT.into() };
			let work = Version::V0.compose().with_id(b"outside-work").with_message(message).build()?;
			let echoed = client.submit_work_to(echo_urn(), &work).await?;

			let content: TestMessage = echoed.decode_message()?;
			assert_eq!(content.content, OUTSIDE_CONTENT, "the forwarded work echoes");

			registered.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideBoundForwardSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(0)),
			(events::CLUSTER_WORK_FAILED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, at_least!(1))
		]
	}
}

// The dial of a forward admits the gateway that the route names alone
// (CWE-346). The advertiser signs a route to the address where the third
// gateway answers, and the peer trust of the receiver holds both identities,
// so the handshake completes and the binding of the dial refuses the answer.
tb_scenario! {
	name: an_outside_forward_refuses_a_gateway_that_answers_under_another_identity,
	spec: OutsideBoundForwardSpec,
	environment Bare {
		context: OutsideColony::generate(),
		exec: |SetupEnv { trace, context: colony }| async move {
			let third_conf = colony.lone_gateway_conf(&colony.third_gateway);
			let third = OutsideGateway::start(Arc::new(trace.share()), third_conf).await?;
			let receiver_conf = colony.receiver_conf(Arc::default());
			let receiver = OutsideGateway::start(Arc::new(trace.share()), receiver_conf).await?;
			let request = advertisement_at(third.addr());
			let advertisement = colony.advertiser.control_frame(b"outside-advertise", request).await;
			let mut client = colony.receiver.client(receiver.addr()).await;
			let advertised: PeerAdvertisementResponse = answer_of(&mut client, advertisement).await?;
			let message = TestMessage { content: OUTSIDE_CONTENT.into() };
			let work = Version::V0.compose().with_id(b"outside-work").with_message(message).build()?;

			let refused = client.submit_work_to(echo_urn(), &work).await;
			assert_eq!(advertised.status, TransitStatus::Ok);
			assert!(matches!(refused, Err(TightBeamError::WorkRefused(TransitStatus::Unavailable))));

			receiver.stop();
			third.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideSiblingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(OUTSIDE_ECHO_RAN, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// A call through the hive's context reaches its servlet on the hive's own
// pool, which runs the floor of the outside provider.
tb_scenario! {
	name: an_outside_hive_calls_its_servlet_through_its_context,
	spec: OutsideSiblingSpec,
	environment Hive {
		context: OutsideColony::generate(),
		start: |SetupEnv { trace, context: colony }| start_outside_hive(trace, colony),
		client: |HiveEnv { hive, .. }| async move {
			let message = TestMessage { content: OUTSIDE_CONTENT.into() };
			let call = Version::V0.compose().with_id(b"outside-call").with_message(message).build()?;

			let echoed = hive.context().call(&echo_urn(), call).await?;
			let content: TestMessage = echoed.decode_message()?;
			assert_eq!(content.content, OUTSIDE_CONTENT, "the hive's context call echoes");

			hive.stop();
			Ok(())
		}
	}
}

/// A gateway outside the crate mints the route key of its gossip ingress
/// through the public method that the house gateway calls at start, so it
/// refuses an ingress outside the namespace its configuration serves.
#[test]
fn an_outside_gateway_refuses_a_gossip_ingress_outside_its_namespace() -> TestResult {
	let colony = OutsideColony::generate();
	let feed = ColonyNamespace::default().servlet("feed")?;
	let ingress = feed.canonical_bytes();
	let gossip = GossipConfig { ingress: Some(feed), ..GossipConfig::default() };

	let tls = colony.gateway_tls(&colony.receiver, &colony.advertiser);
	let acme = ColonyNamespace::new("acme", "prod")?;
	let builder = ClusterConfig::builder(tls).with_gossip_config(gossip);
	let config = builder.with_namespace(acme).build();
	let refused = config.gossip_ingress_key();
	assert!(matches!(refused, Err(ClusterError::UnknownServletType(named)) if named == ingress));
	Ok(())
}
