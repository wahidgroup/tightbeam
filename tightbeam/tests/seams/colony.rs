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
//! names.
//!
//! [`NoStrengthFloor`]: tightbeam::crypto::profiles::NoStrengthFloor

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature",
	feature = "colony"
))]

use core::time::Duration;
use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::colony::cluster::{
	Cluster, ClusterConfig, ClusterHeartbeat, ClusterTlsConfig, GossipConfig, GossipJournal, MemoryGossipJournal,
};
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig};
use tightbeam::colony::protocol::{ClusterRequest, GossipRumor};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::colony::SubmitWork;
use tightbeam::crypto::hash::Sha3_512;
use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::policy::ProviderPolicy;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::crypto::x509::utils::Fingerprint;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::random::OsRng;
use tightbeam::testing::{HiveEnv, SetupEnv, TestCertificate, TestMessage};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, Protocol};
use tightbeam::urn::Urn;
use tightbeam::utils::time::UnixMillis;
use tightbeam::x509::Certificate;
use tightbeam::{at_least, cluster, decode, exactly, hive, servlet, tb_assert_spec, tb_scenario, urn};
use tightbeam::{Frame, TightBeamError, Version};

use super::{outside_identity_of, OutsideProvider};
use crate::common::hive::scenario_hive_config;
use crate::common::poll::poll_until;

const OUTSIDE_ECHO_RAN: Urn<'static> = urn!("test", "event:seams/outside-echo-ran");
const OUTSIDE_WORK_ECHOED: Urn<'static> = urn!("test", "event:seams/outside-work-echoed");
const OUTSIDE_HEARTBEAT_ANSWERED: Urn<'static> = urn!("test", "event:seams/outside-heartbeat-answered");
const OUTSIDE_RUMOR_DIGEST_WIDTH: Urn<'static> = urn!("test", "event:seams/outside-rumor-digest-width");
const OUTSIDE_GATEWAY_NAMED: Urn<'static> = urn!("test", "event:seams/outside-gateway-named");
const OUTSIDE_SIBLING_ECHOED: Urn<'static> = urn!("test", "event:seams/outside-sibling-echoed");

/// The content the client's work frame carries and the servlet echoes.
const OUTSIDE_CONTENT: &str = "forwarded under an outside provider";

/// The advertise beat of each gateway, so a scenario sees its peer within a
/// few beats.
const BEAT: Duration = Duration::from_millis(100);

/// The protocol every party of the outside colony runs: TCP under the outside
/// provider.
type OutsideListener = TokioListener<OutsideProvider>;

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
}

/// The parties of one outside colony.
///
/// - The advertiser is the gateway the hive registers with, and it advertises its slate to the receiver.
/// - The receiver learns the advertiser's route and forwards work along it.
/// - The hive's servlet answers under the hive's identity.
struct OutsideColony {
	receiver: Party,
	advertiser: Party,
	hive: Party,
}

impl OutsideColony {
	/// A colony of three fresh parties.
	fn generate() -> Self {
		let receiver = Party::generate("Outside Receiver");
		let advertiser = Party::generate("Outside Advertiser");
		let hive = Party::generate("Outside Hive");
		Self { receiver, advertiser, hive }
	}

	/// The TLS material of `gateway`, with `peer` as its peer trust and the
	/// hive as its hive trust.
	fn gateway_tls(&self, gateway: &Party, peer: &Party) -> ClusterTlsConfig {
		let tls = ClusterTlsConfig::from_identity(gateway.identity(), KeyPurposes::HOUSE);
		let tls = tls.expect("an outside certificate with no extended key usage signs for the gateway");
		let tls = tls.with_hive_trust(outside_trust(&[&self.hive]));
		tls.with_peer_trust(outside_trust(&[peer]))
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
		let tls = HiveTlsConfig::from_identity(self.hive.identity(), Vec::new(), KeyPurposes::HOUSE);
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
	let builder = CertificateTrustBuilder::from(ProviderPolicy::<OutsideProvider>::default());
	let anchor = |builder: CertificateTrustBuilder, party: &&Party| builder.with_certificate(party.certificate.clone());
	let builder = parties.iter().try_fold(builder, anchor);
	Arc::new(builder.expect("an outside certificate anchors").build())
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

/// Polls until `journal` holds a rumor, and returns the width of its digest,
/// or 0 when none arrived.
async fn held_digest_width(journal: &MemoryGossipJournal) -> u64 {
	let held = || journal.held_digests(UnixMillis::now()).is_ok_and(|held| !held.is_empty());
	poll_until(50, BEAT, held).await;

	let held = journal.held_digests(UnixMillis::now()).unwrap_or_default();
	held.first().map_or(0, |digest| digest.as_bytes().len() as u64)
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
			(OUTSIDE_HEARTBEAT_ANSWERED, exactly!(1), equals!(TransitStatus::Ok)),
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
			trace.event_with(OUTSIDE_HEARTBEAT_ANSWERED, &[], beat.status)?;

			registered.stop();
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
			(OUTSIDE_GATEWAY_NAMED, exactly!(1), equals!(true)),
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
			let route = routes.first();
			let named = route.is_some_and(|route| route.peer_id.as_ref() == fingerprint.as_slice());
			trace.event_with(OUTSIDE_GATEWAY_NAMED, &[], named)?;

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
			(OUTSIDE_RUMOR_DIGEST_WIDTH, exactly!(1), equals!(64u64)),
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
			let width = held_digest_width(&registered.journal).await;
			trace.event_with(OUTSIDE_RUMOR_DIGEST_WIDTH, &[], width)?;

			registered.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub OutsideForwardSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(OUTSIDE_ECHO_RAN, exactly!(1)),
			(OUTSIDE_WORK_ECHOED, exactly!(1), equals!(true)),
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
			let content: TestMessage = decode(echoed.message())?;
			trace.event_with(OUTSIDE_WORK_ECHOED, &[], content.content == OUTSIDE_CONTENT)?;

			registered.stop();
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
			(OUTSIDE_SIBLING_ECHOED, exactly!(1), equals!(true))
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
		client: |HiveEnv { trace, hive, .. }| async move {
			let message = TestMessage { content: OUTSIDE_CONTENT.into() };
			let call = Version::V0.compose().with_id(b"outside-call").with_message(message).build()?;

			let echoed = hive.context().call(&echo_urn(), call).await?;
			let content: TestMessage = decode(echoed.message())?;
			trace.event_with(OUTSIDE_SIBLING_ECHOED, &[], content.content == OUTSIDE_CONTENT)?;

			hive.stop();
			Ok(())
		}
	}
}
