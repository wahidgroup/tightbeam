//! The shared fixtures of the colony cluster integration tests.
//!
//! Certificate identities, TLS configs, trace recorders, and peering
//! preambles live here, so scenario modules stay assertion-focused.
//!
//! # Certificates
//!
//! [`member_identity`] creates a distinct gateway certificate per
//! organization. [`cluster_certs`] gives a scenario one signing key, which its
//! gateways share, so it cannot tell a relay from an origin in multi-gateway
//! topologies. Each call draws a fresh key, so each scenario trusts its own
//! identity alone.
//!
//! # Trust planes
//!
//! Use the layout that matches the scenario:
//!
//! - Shared [`cluster_certs`] with overlapping `peer_trust`: register and
//!   sign hive control frames with [`hive_plane_certs`] and
//!   [`split_hive_trust`], because peer membership wins on the hive plane.
//! - Distinct [`member_identity`] federation or org topologies: put the full
//!   combined store on `hive_trust` and exclude self from `peer_trust`.
//! - Distinct [`colony_identity`] flood topologies: put each gateway's own
//!   certificate in its `peer_trust`, so an echo of its own rumor verifies,
//!   and sign publishes with [`hive_plane_certs`] under [`split_hive_trust`].
//! - Export-boundary scenarios: use the per-org split planes in `exports.rs`,
//!   where `hive_trust` holds the own org and `peer_trust` the external peer.
//!
//! # Work probes
//!
//! - [`record_ping_echo`] drives the public `SubmitWork` client surface end to end.
//! - [`emit_typed_work`] submits the same signed ping frame
//!   ([`signed_work_frame`]) under a caller-chosen type URN. Export
//!   scenarios reuse it for private types that still run the ping
//!   servlet.
//! - [`work_refusal_status`] resolves a [`TightBeamError::WorkRefused`]
//!   refusal back to its transit status for denial scenarios.
//! - [`emit_relayed_ping_work`] alone composes the wire envelope itself,
//!   because its pre-spent hop budget is the wire shape under test.

// Sibling scenario modules consume these re-exports through
// `use super::common::*`.
pub use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
pub use core::time::Duration;
pub use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
pub use std::sync::{Arc, Mutex};

use tokio::net::TcpSocket;

pub use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::crypto::policy::VerificationPolicy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::{ErasedSigning, KeyPurposes, PeerCertificate, Signing};
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::TestCertificate;
pub use tightbeam::{
	at_least, at_most,
	builder::TypeBuilder,
	colony::{
		cluster::{
			Admission, AdmittedDial, Cluster, ClusterConfig, ClusterError, ClusterTlsConfig, GossipAdmission,
			GossipConfig, GossipDigest, GossipJournal, HeartbeatConfig, InstanceMetrics, LoadBalancer, LocalClaim,
			MemoryGossipJournal, PeerAddress, PeerHint, PeerTable, RoundRobin, StochasticForager, TokenBucketAdmission,
		},
		hive::{Hive, HiveConfig, HiveTlsConfig, ServletBox},
		protocol::{
			ClusterRequest, ClusterWorkRequest, ClusterWorkResponse, GossipReconciliation, GossipResponse, GossipRumor,
			GossipWant, PeerAdvertisement, PeerAdvertisementResponse, RegisterHiveRequest, RegisterHiveResponse,
			ServletAddressUpdate, ServletAddressUpdateResponse, ServletInfo,
		},
		servlet::{ServletConfig, ServletConfigBuilder, WithCertificate},
		urn::{ColonyNamespace, ServletTypeKey},
		SubmitWork,
	},
	constants::{
		DEFAULT_COMMAND_FRESHNESS_WINDOW_MS, DEFAULT_GOSSIP_RETENTION_MS, MAX_ADVERTISED_TYPES,
		MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_TTL, MAX_PEER_BUCKET,
	},
	crypto::{
		key::Secp256k1KeyProvider,
		policy::Secp256k1Policy,
		profiles::DefaultCryptoProvider,
		sign::ecdsa::Secp256k1SigningKey,
		x509::{
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	decode,
	der::Sequence,
	encode, exactly,
	instrumentation::events,
	policy::{GatePolicy, SessionContext, TransitStatus},
	tb_assert_spec, tb_process_spec, tb_scenario,
	testing::{ClusterEnv, HiveEnv, ScenarioConfig, ScenarioConfigError, SetupEnv, TestIdentity, TestKey},
	trace::TraceCollector,
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
		ConnectionPool, GenericClient, PoolConfig,
	},
	urn::Urn,
	utils::time::{Clock, ManualClock, UnixMillis},
	Beamable, Frame, TightBeamError, Version,
};
use tightbeam::{cluster, compose, hive, servlet};

pub(crate) use super::events::*;
pub use crate::common::hive::scenario_hive_config;
pub use crate::common::poll::poll_until;
use crate::common::security::expectation_failure;
pub use crate::common::x509::{combined_trust, combined_validator, signing_identity, GatewayCerts};

/// The address that the simulated peer gateway advertises itself at.
pub(crate) const PEER_GATEWAY_ADDR: &[u8] = b"127.0.0.1:9000";

/// The failed forwards that a peer trail tolerates before abandonment in the
/// infection-containment scenarios. The limit stays small, so the gate stays
/// fast. The containment specs assert exactly this many `CLUSTER_WORK_FAILED`
/// events before selection drops the peer.
pub const CONTAINMENT_ABANDON_LIMIT: u32 = 3;

pub type ClusterTestCerts = GatewayCerts;

/// The colony that the gateway identity of each scenario and every
/// [`member_identity`] belong to. Membership travels as a URI SAN on the
/// gateway certificate, never as the subject.
pub fn test_colony_urn() -> Urn<'static> {
	colony_ns().colony("main").expect("static colony name")
}

/// A fresh gateway identity in the [`test_colony_urn`] colony.
///
/// A scenario holds one as its context, and its gateways, hives, and servlets
/// derive their identities from that one value. Only that scenario trusts it,
/// so a dial that a released port carries to the listener of another scenario
/// fails its handshake.
pub fn cluster_certs() -> ClusterTestCerts {
	GatewayCerts::generate_colony(&test_colony_urn())
}

/// A fresh gateway identity in `colony`: a random key and a certificate that
/// carries the colony URN as a URI SAN.
///
/// [`cluster_certs`] cannot serve multi-gateway topologies, because the
/// gateways of a scenario share its one signing key. All gateways would
/// then resolve to one signer fingerprint, and no check could tell a relay
/// apart from an origin.
pub fn colony_identity(cn: impl AsRef<str>, colony: &Urn<'_>) -> (Certificate, Secp256k1SigningKey) {
	let cn = cn.as_ref();
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert = TestCertificate::with_cn_and_uri_sans(&raw, cn, &[&colony.to_string()]);
	(cert, Secp256k1SigningKey::from(raw))
}

/// A fresh gateway identity whose certificate carries no colony URN.
///
/// Transport trusts it where a store enrolls it, and it is outside every
/// flood. Its own `CN` keeps issuer resolution unambiguous in a store that
/// also anchors the shared gateway identity.
pub fn stranger_gateway_certs() -> ClusterTestCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert = TestCertificate::with_cn_and_uri_sans(&raw, "Stranger Gateway", &[]);
	let key = Secp256k1SigningKey::from(raw);
	let trust = combined_trust(&[&cert]);

	GatewayCerts { cert, key, trust }
}

/// A peer trust store an operator replaces while the gateway runs.
///
/// It answers from `before` until [`Self::switch`], and from `after` from
/// then on. Each answer borrows from the store that gave it.
#[derive(Debug)]
pub struct SwitchTrust {
	before: Arc<dyn CertificateTrust>,
	after: Arc<dyn CertificateTrust>,
	switched: AtomicBool,
}

impl SwitchTrust {
	pub fn new(before: Arc<dyn CertificateTrust>, after: Arc<dyn CertificateTrust>) -> Arc<Self> {
		Arc::new(Self { before, after, switched: AtomicBool::new(false) })
	}

	/// Replaces the store the gateway reads.
	pub fn switch(&self) {
		self.switched.store(true, Ordering::SeqCst);
	}

	fn current(&self) -> &dyn CertificateTrust {
		if self.switched.load(Ordering::SeqCst) {
			self.after.as_ref()
		} else {
			self.before.as_ref()
		}
	}
}

impl CertificateValidation for SwitchTrust {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		self.current().evaluate(cert)
	}
}

impl CertificateTrust for SwitchTrust {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		self.current().is_trusted(cert)
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		self.current().verify_chain(chain)
	}

	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		self.current().trust_anchor(cert)
	}

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		self.current().find_by_signer_identifier(sid)
	}

	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		self.current().find_by_public_key(spki)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		self.current().to_policy_ref()
	}
}

/// A peer trust store that enrolls both certificates of a gateway that rotated
/// its certificate under one key, the enrolled one first.
///
/// Each lookup answers from `enrolled` when it holds an answer, and from
/// `rotated` otherwise. A key therefore resolves to the enrolled certificate,
/// and a `sid` that names the rotated certificate alone resolves to that one
/// (RFC 5652 §5.3).
#[derive(Debug)]
pub struct RotatingTrust {
	enrolled: Arc<dyn CertificateTrust>,
	rotated: Arc<dyn CertificateTrust>,
}

impl RotatingTrust {
	pub fn new(enrolled: Arc<dyn CertificateTrust>, rotated: Arc<dyn CertificateTrust>) -> Arc<Self> {
		Arc::new(Self { enrolled, rotated })
	}
}

impl CertificateValidation for RotatingTrust {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		self.enrolled.evaluate(cert).or_else(|_| self.rotated.evaluate(cert))
	}
}

impl CertificateTrust for RotatingTrust {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		self.enrolled.is_trusted(cert) || self.rotated.is_trusted(cert)
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		self.enrolled.verify_chain(chain).or_else(|_| self.rotated.verify_chain(chain))
	}

	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		self.enrolled.trust_anchor(cert).or_else(|_| self.rotated.trust_anchor(cert))
	}

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		let enrolled = self.enrolled.find_by_signer_identifier(sid);
		enrolled.or_else(|| self.rotated.find_by_signer_identifier(sid))
	}

	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		let enrolled = self.enrolled.find_by_public_key(spki);
		enrolled.or_else(|| self.rotated.find_by_public_key(spki))
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		self.enrolled.to_policy_ref()
	}
}

/// A [`colony_identity`] in the colony that [`test_colony_urn`] names.
pub fn member_identity(cn: impl AsRef<str>) -> (Certificate, Secp256k1SigningKey) {
	let cn = cn.as_ref();
	colony_identity(cn, &test_colony_urn())
}

/// The hive-plane identity of the scenario whose gateway identity is
/// `gateway`, disjoint from that gateway identity.
///
/// The hive plane refuses a signer that `peer_trust` also holds, because
/// peer membership wins. Fixtures that put the gateway certificate in
/// `peer_trust` for relay verification therefore register hives and sign
/// origin publishes with this identity instead.
///
/// - The key derives from the gateway key, so every closure of a scenario derives the one identity.
/// - The bundled trust store covers the gateway identity, so the hive can dial its gateway.
pub fn hive_plane_certs(gateway: &ClusterTestCerts) -> Arc<ClusterTestCerts> {
	use tightbeam::crypto::hash::{Digest, Sha3_256};
	use tightbeam::testing::fixtures::TestCertificate;

	let gateway_key = gateway.key.to_bytes();
	let seed = [b"hive plane".as_slice(), gateway_key.as_slice()].concat();
	let scalar = Sha3_256::digest(&seed);
	let raw = k256::ecdsa::SigningKey::from_bytes(&scalar).expect("a digest of a key is a valid scalar");
	let cert = TestCertificate::with_cn_and_uri_sans(&raw, "Hive Plane", &[&test_colony_urn().to_string()]);
	let trust = combined_trust(&[&gateway.cert, &cert]);
	let key = Secp256k1SigningKey::from(raw);

	Arc::new(GatewayCerts { cert, key, trust })
}

/// Gateway hive trust for a fixture whose `peer_trust` holds the gateway's own
/// certificate.
///
/// - The gateway identity serves the hive-pool dials between gateways.
/// - The hive-plane identity serves registration, address updates, and origin publishes.
/// - Federation and organization scenarios leave the gateway out of its own `peer_trust` and need no split.
pub fn split_hive_trust(gateway: &ClusterTestCerts) -> Arc<dyn CertificateTrust> {
	combined_trust(&[&gateway.cert, &hive_plane_certs(gateway).cert])
}

pub fn cluster_tls_config_with_trust(
	certs: &ClusterTestCerts,
	hive_trust: Option<Arc<dyn CertificateTrust>>,
) -> ClusterTlsConfig {
	ClusterTlsConfig::new(
		CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
	)
	.expect("the test certificate must decode")
	.with_hive_trust(hive_trust)
}

pub fn cluster_tls_config(certs: &ClusterTestCerts) -> ClusterTlsConfig {
	cluster_tls_config_with_trust(certs, Some(Arc::clone(&certs.trust)))
}

pub fn hive_tls_config_no_trust(certs: &ClusterTestCerts) -> HiveConfig {
	let hive_tls = Arc::new(
		HiveTlsConfig::new(
			CertificateSpec::Built(Box::new(certs.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
			vec![],
		)
		.expect("the hive TLS material must decode"),
	);

	let mut conf = HiveConfig { hive_tls: Some(hive_tls), ..scenario_hive_config() };
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf
}

pub fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConfig {
	HiveConfig { trust_store: Some(Arc::clone(&certs.trust)), ..hive_tls_config_no_trust(certs) }
}

/// The builder of a servlet config on the fixture identity with the standard
/// mux offer, for a scenario that adds a gate, a hive context, or an
/// environment of its own before it builds.
pub fn servlet_tls_builder<M: tightbeam::Message>(
	certs: &ClusterTestCerts,
) -> Result<
	ServletConfigBuilder<TokioListener, M, DefaultCryptoProvider, (), WithCertificate<DefaultCryptoProvider>>,
	TightBeamError,
> {
	let builder = ServletConfig::<TokioListener, M, DefaultCryptoProvider>::builder().with_certificate(
		CertificateSpec::Built(Box::new(certs.cert.to_owned())),
		Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
		vec![],
	)?;

	Ok(builder.with_mux_offer(Some(TransportOffer::mux(8))))
}

/// A servlet config on the fixture identity, for a servlet of any message
/// type `M`.
pub fn servlet_tls_config<M: tightbeam::Message>(
	certs: &ClusterTestCerts,
) -> Result<ServletConfig<TokioListener, M, DefaultCryptoProvider>, TightBeamError> {
	Ok(servlet_tls_builder(certs)?.with_config(Arc::new(())).build())
}

/// Whether another socket may bind beside a [`HeldPort`].
#[derive(Clone, Copy)]
pub enum PortSharing {
	/// `SO_REUSEADDR` cleared, so every other bind of the port conflicts with
	/// the hold.
	Exclusive,
	/// `SO_REUSEADDR` set, so a listener that names the port and sets it too
	/// binds beside the hold.
	Shared,
}

/// A port that a bound socket holds for as long as this value lives, against
/// a concurrent test that binds a port of its own.
///
/// - The socket holds the port in the bound state alone.
/// - A bind that asks the kernel for any port passes over the held one.
pub struct HeldPort {
	_socket: TcpSocket,
	address: SocketAddr,
}

impl HeldPort {
	/// Holds a fresh port on `host`, shared with other binds as `sharing`
	/// names.
	pub fn hold(host: Ipv4Addr, sharing: PortSharing) -> Self {
		let socket = TcpSocket::new_v4().expect("a TCP socket opens");
		let shared = matches!(sharing, PortSharing::Shared);
		socket.set_reuseaddr(shared).expect("SO_REUSEADDR sets");
		let any_port = SocketAddr::from((host, 0));
		socket.bind(any_port).expect("the host has a free port");
		let address = socket.local_addr().expect("a bound socket has an address");

		Self { _socket: socket, address }
	}

	/// The held port's address.
	pub fn address(&self) -> SocketAddr {
		self.address
	}
}

/// Starts the gateway on the scenario trace so the cluster's built-in
/// lifecycle events land where the assertion specs verify them.
pub async fn start_cluster(trace: &TraceCollector, conf: ClusterConfig) -> Result<ClusterGateway, TightBeamError> {
	ClusterGateway::start(Arc::new(trace.share()), conf).await
}

pub async fn connect_cluster(
	certs: &ClusterTestCerts,
	addr: &<TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_trust_store(Arc::clone(&certs.trust))
		.build()
		.connect(addr.to_owned())
		.await?)
}

pub async fn emit_frame(client: &mut GenericClient<TokioListener>, frame: Frame) -> Result<Frame, TightBeamError> {
	client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)
}

/// A gate policy that denies every request, for scenarios that prove the
/// gateway enforces `with_gate_policy` on unary work and stream opens.
pub struct RejectAllPolicy;

impl GatePolicy for RejectAllPolicy {
	fn evaluate(&self, _message: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		TransitStatus::PermissionDenied
	}
}

/// Converts a count into a trace value. A fixture cannot produce a count past
/// `u64`, so the conversion saturates.
pub fn count_u64(count: usize) -> u64 {
	u64::try_from(count).unwrap_or(u64::MAX)
}

/// Records a registration outcome on the trace: the wire status as
/// `REGISTER_STATUS`, the registry size as `REGISTRY_HIVES`, and whether
/// the registry assigned a hive id as `REGISTER_ASSIGNED_ID`. The specs pin the
/// expected values, so scenarios need no inline checks.
pub fn record_register_response(
	trace: &TraceCollector,
	response: &RegisterHiveResponse,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	trace.event_with(REGISTER_STATUS, &[], response.status)?;
	trace.event_with(REGISTRY_HIVES, &[], count_u64(cluster.hive_count()?))?;
	trace.event_with(REGISTER_ASSIGNED_ID, &[], u64::from(response.hive_id.is_some()))?;
	Ok(())
}

/// Records a work outcome on the trace for spec verification: the wire
/// status as `WORK_STATUS` and payload presence as `WORK_PAYLOAD`.
pub fn record_work_status(trace: &TraceCollector, response: &ClusterWorkResponse) -> Result<(), TightBeamError> {
	trace.event_with(WORK_STATUS, &[], response.status)?;
	trace.event_with(WORK_PAYLOAD, &[], u64::from(response.payload.is_some()))?;
	Ok(())
}

/// Signs `frame` with `key` under the canonical SHA3-256 convention.
///
/// One shared signer keeps every test frame on the same bytes-to-sign
/// formula the gateways verify. The signer identifier is the key identifier
/// of `key`, which every fixture certificate over `key` carries.
pub async fn sign_frame(mut frame: Frame, key: &Secp256k1SigningKey) -> Result<Frame, TightBeamError> {
	let identity = TestIdentity::of(key);
	frame.sign_with_provider(&identity).await?;
	Ok(frame)
}

/// The deterministic signing key of end-to-end work envelopes.
///
/// The client and the probe servlet both derive it, so each side can
/// cryptographically verify the other's frame signature without key
/// distribution.
pub fn probe_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::from(TestKey::insecure_fixed_signing())
}

/// Returns whether `frame` carries a signature that verifies against the
/// public half of `key` over the frame's to-be-signed bytes.
///
/// Every fixture certificate of a key carries that key's identifier, so the
/// self-signed one is the signer any frame of `key` names. A verified
/// signature proves byte fidelity end to end, and the function adapts
/// [`Frame::verify`] to a boolean for trace events.
pub fn frame_signature_verifies(frame: &Frame, key: &Secp256k1SigningKey) -> bool {
	let certificate = TestCertificate::self_signed(key);
	let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer);
	let signer = signer.expect("a fixture certificate asserts digitalSignature");
	frame.verify(&signer).is_ok()
}

/// Signs a [`ClusterRequest::PublishGossip`] control frame with an
/// issue-time order and a hop radius.
pub async fn signed_publish_gossip(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	body: GossipRumor,
	hop_ttl: u64,
) -> Result<Frame, TightBeamError> {
	signed_publish_gossip_at(key, id, body, hop_ttl, UnixMillis::now()).await
}

/// Signs a [`ClusterRequest::PublishGossip`] control frame issued at
/// `issued_at`, the reading of the clock its gateway judges freshness on.
pub async fn signed_publish_gossip_at(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	body: GossipRumor,
	hop_ttl: u64,
	issued_at: UnixMillis,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let unsigned = Version::V2
		.compose()
		.with_id(id)
		.with_order(issued_at.get())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::PublishGossip(body))
		.build()?;

	sign_frame(unsigned, key).await
}

pub async fn signed_control_frame_with_order(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	request: ClusterRequest,
	order: u64,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let unsigned = Version::V1
		.compose()
		.with_id(id)
		.with_order(order)
		.with_message(request)
		.build()?;

	sign_frame(unsigned, key).await
}

pub async fn signed_control_frame_with(
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	signed_control_frame_with_order(key, id, request, UnixMillis::now().get()).await
}

pub async fn signed_control_frame(
	certs: &ClusterTestCerts,
	id: impl AsRef<[u8]>,
	request: ClusterRequest,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	signed_control_frame_with(&certs.key, id, request).await
}

pub fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

pub fn hive_urn(hive_addr: &(impl AsRef<[u8]> + ?Sized)) -> Urn<'static> {
	let hive_addr = hive_addr.as_ref();
	colony_ns()
		.hive(String::from_utf8_lossy(hive_addr).as_ref())
		.expect("test locators satisfy the mint grammar")
}

pub fn servlet_urn(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
	let name = name.as_ref();
	colony_ns().servlet(name).expect("test names satisfy the mint grammar")
}

/// The gossip ingress key for `name`, created the way the builder creates
/// it.
///
/// [`GossipConfig::ingress`] holds a route key, so a fixture names its
/// ingress through the same namespace check that production passes.
pub fn servlet_ingress(name: &(impl AsRef<str> + ?Sized)) -> ServletTypeKey {
	let urn = servlet_urn(name);
	colony_ns().servlet_type_key(&urn).expect("test names mint a bare servlet type")
}

pub fn registration_request(hive_addr: impl AsRef<[u8]>) -> ClusterRequest {
	registration_request_serving(hive_addr, [])
}

/// A registration for `hive_addr` that declares `servlets`.
pub fn registration_request_serving(
	hive_addr: impl AsRef<[u8]>,
	servlets: impl IntoIterator<Item = ServletInfo>,
) -> ClusterRequest {
	let hive_addr = hive_addr.as_ref();
	ClusterRequest::RegisterHive(RegisterHiveRequest {
		hive_addr: hive_addr.to_vec(),
		servlet_addresses: servlets.into_iter().collect(),
		metadata: None,
	})
}

pub fn servlet_address_update(
	hive_addr: impl AsRef<[u8]>,
	added: impl IntoIterator<Item = ServletInfo>,
	removed: impl IntoIterator<Item = Urn<'static>>,
) -> ClusterRequest {
	let hive_addr = hive_addr.as_ref();
	let added: Vec<ServletInfo> = added.into_iter().collect();
	let removed: Vec<Urn<'static>> = removed.into_iter().collect();
	ClusterRequest::ServletAddressUpdate(ServletAddressUpdate { hive_id: hive_urn(hive_addr), added, removed })
}

/// The signer that names `certificate` (RFC 5652 §5.3).
pub fn signer_of(certificate: &Certificate) -> SignerIdentifier {
	certificate.signer_identifier().expect("a fixture certificate names its key")
}

/// A registration entry for servlet type `servlet_name` at `address`, served
/// under the scenario identity `certs`.
pub fn servlet_info(certs: &ClusterTestCerts, servlet_name: impl AsRef<str>, address: impl AsRef<[u8]>) -> ServletInfo {
	servlet_info_signed_by(servlet_name, address, signer_of(&certs.cert))
}

/// A registration entry for servlet type `servlet_name` at `address` that
/// names `signer` as the identity the servlet answers under.
pub fn servlet_info_signed_by(
	servlet_name: impl AsRef<str>,
	address: impl AsRef<[u8]>,
	signer: SignerIdentifier,
) -> ServletInfo {
	let servlet_name = servlet_name.as_ref();
	let address = address.as_ref();
	ServletInfo {
		servlet_id: servlet_urn(servlet_name)
			.servlet_instance(String::from_utf8_lossy(address).as_ref())
			.expect("a servlet type URN yields an instance URN"),
		address: address.to_vec(),
		signer,
	}
}

/// A `ServletInfo` whose instance locator disagrees with the route address,
/// served under the scenario identity `certs`.
pub fn servlet_info_mismatched(
	certs: &ClusterTestCerts,
	servlet_name: impl AsRef<str>,
	urn_addr: impl AsRef<[u8]>,
	route_addr: impl AsRef<[u8]>,
) -> ServletInfo {
	let servlet_name = servlet_name.as_ref();
	let urn_addr = urn_addr.as_ref();
	let route_addr = route_addr.as_ref();
	ServletInfo {
		servlet_id: servlet_urn(servlet_name)
			.servlet_instance(String::from_utf8_lossy(urn_addr).as_ref())
			.expect("a servlet type URN yields an instance URN"),
		address: route_addr.to_vec(),
		signer: signer_of(&certs.cert),
	}
}

/// Polls until the gateway has learned peer types and `trace` holds a direct
/// advertisement, or the attempts run out.
///
/// The routes alone can come from a slate rumor first, so the wait also holds
/// for [`wait_for_direct_advertisement`]. The branching lives here, so
/// scenarios stay assertion-focused.
pub async fn wait_for_peer_types(
	trace: &TraceCollector,
	cluster: &ClusterGateway,
	attempts: u32,
	interval: Duration,
) -> Vec<tightbeam::colony::cluster::SharedId> {
	poll_until(attempts, interval, || {
		cluster.peer_servlets().is_ok_and(|types| !types.is_empty())
	})
	.await;
	wait_for_direct_advertisement(trace, attempts, interval).await;

	cluster.peer_servlets().expect("the gateway under test holds no poisoned lock")
}

/// Polls until `trace` holds a direct peer advertisement that a gateway
/// admitted, or the attempts run out.
///
/// A beat sends its slate as a direct advertisement and inside a slate rumor.
/// Either copy installs the routes, and only the direct copy records
/// [`events::CLUSTER_PEER_ADVERTISED`]. The spec judges the count, so the wait
/// answers nothing.
pub async fn wait_for_direct_advertisement(trace: &TraceCollector, attempts: u32, interval: Duration) {
	let advertised = || trace.recorded(events::CLUSTER_PEER_ADVERTISED) > 0;
	poll_until(attempts, interval, advertised).await;
}

/// Polls until the gateway exposes no live peer routes or the attempts run
/// out.
///
/// Abandonment happens on the advertise beat's cadence, so a poll is the
/// way to observe it.
pub async fn wait_for_no_peer_routes(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> bool {
	poll_until(attempts, interval, || {
		cluster.peer_routes().is_ok_and(|routes| routes.is_empty())
	})
	.await
}

/// Polls until the registry is empty or the attempts run out.
pub async fn wait_for_empty_registry(cluster: &ClusterGateway, attempts: u32, interval: Duration) -> bool {
	poll_until(attempts, interval, || cluster.hive_count().is_ok_and(|count| count == 0)).await
}

/// The request whose `value` the ping servlet doubles.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct PingRequest {
	/// The number the servlet doubles.
	pub value: u32,
}

/// The ping servlet's reply.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct PingResponse {
	/// Twice the request's `value`.
	pub doubled: u32,
}

servlet! {
	pub ClusterTestServlet<PingRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		Ok(Some(compose! {
			V0: id: frame.metadata().id(),
				message: PingResponse { doubled: req.value * 2 }
		}?))
	}
}

servlet! {
	/// The gossip ingress servlet. It receives the origin-signed rumor frame,
	/// records whether the gateway key its environment holds signed it, and
	/// answers the ping the rumor carries.
	pub ClusterRumorServlet<GossipRumor, EnvConfig = Option<Secp256k1SigningKey>>,
	protocol: TokioListener,
	handle: |rumor, frame, ctx| async move {
		let ping: PingRequest = decode(&rumor.payload)?;
		let origin = ctx.env_config().as_ref();
		let signed_by_gateway = origin.is_some_and(|key| frame_signature_verifies(&frame, key));
		ctx.trace().event_with(GOSSIP_INGRESS_SIGNED_BY_GATEWAY, &[], signed_by_gateway)?;

		Ok(Some(compose! {
			V0: id: frame.metadata().id(),
				message: PingResponse { doubled: ping.value * 2 }
		}?))
	}
}

hive! {
	pub ClusterTestHive,
	protocol: TokioListener
}

cluster! {
	pub ClusterGateway,
	protocol: TokioListener
}

/// Starts a ping-servlet hive on the scenario trace, with an optional mux
/// offer for both the hive control server and the hive-to-cluster pool.
pub async fn start_ping_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
	mux_offer: Option<TransportOffer>,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_config(&certs)?;
	let servlet = ClusterTestServlet::start(Arc::new(trace.share()), servlet_conf).await?;

	let mut conf = hive_tls_config(&certs);
	conf.pool.mux_offer = mux_offer.map(Arc::new);

	let mut hive = ClusterTestHive::new(Some(conf))?;
	hive.register(servlet_urn("ping"), servlet, |t| {
		ClusterTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Starts a hive on `certs` whose one servlet is the gossip ingress,
/// registered as the type `rumor`, which checks each rumor against
/// `origin_key`.
pub async fn start_rumor_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
	origin_key: Secp256k1SigningKey,
) -> Result<ClusterTestHive, TightBeamError> {
	let servlet_conf = servlet_tls_builder(&certs)?.with_config(Arc::new(Some(origin_key))).build();
	let servlet = ClusterRumorServlet::start(Arc::new(trace.share()), servlet_conf).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("rumor"), servlet, |t| {
		ClusterRumorServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Starts the rumor hive of the scenario whose gateway identity is `certs`.
///
/// The hive runs on the scenario's hive plane ([`hive_plane_certs`]) and
/// checks each rumor against the scenario's gateway key. The future owns
/// what it reads, so a `start:` closure returns it as is.
pub fn start_scenario_rumor_hive(
	trace: TraceCollector,
	certs: &ClusterTestCerts,
) -> impl core::future::Future<Output = Result<ClusterTestHive, TightBeamError>> {
	start_rumor_hive(trace, hive_plane_certs(certs), certs.key.to_owned())
}

/// A cluster configuration with an optional mux offer for both the gateway
/// server and the cluster-to-hive pool.
pub fn routing_cluster_conf(certs: &ClusterTestCerts, mux_offer: Option<TransportOffer>) -> ClusterConfig {
	let mut conf = ClusterConfig::new(cluster_tls_config(certs));
	conf.pool_config.mux_offer = mux_offer.map(Arc::new);
	conf
}

/// A muxed gateway configuration whose hive trust holds the fixture identity
/// and `impostor`, so a servlet that serves under `impostor` completes the
/// handshake, and only the dial's signer binding tells it from the servlet a
/// registration names.
pub fn impostor_trusting_conf(certs: &ClusterTestCerts, impostor: &ClusterTestCerts) -> ClusterConfig {
	let trust = combined_trust(&[&certs.cert, &impostor.cert]);
	let tls = cluster_tls_config_with_trust(certs, Some(trust));

	with_mux_offer(ClusterConfig::new(tls))
}

/// Adds the standard eight-stream mux offer to a cluster configuration, so
/// the gateway serves routed streams and its pools open them.
pub fn with_mux_offer(mut conf: ClusterConfig) -> ClusterConfig {
	conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
	conf
}

/// Emits one ping work request through the gateway with
/// [`SubmitWork::submit_work_to`] and records the echoed payload as a valued
/// event. The spec asserts that the gateway routed it
/// (`events::CLUSTER_WORK_ROUTED`) and the echo value (`WORK_ECHOED`). A
/// refusal surfaces as [`TightBeamError::WorkRefused`].
pub async fn record_ping_echo(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	trace.event(WORK_SENT)?;

	let inner = signed_work_frame(&certs.key, b"test-work").await?;
	let mut client = connect_cluster(certs, cluster.addr()).await?;
	let servlet_frame = client.submit_work_to(servlet_urn("ping"), &inner).await?;

	let ping_response: PingResponse = decode(servlet_frame.message())?;
	trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

	Ok(())
}

pub async fn register_signed_hive(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	addr: impl AsRef<[u8]>,
) -> Result<RegisterHiveResponse, TightBeamError> {
	register_signed_hive_serving(client, key, id, addr, []).await
}

/// Registers a hive that declares `servlets`, signed by `key`.
pub async fn register_signed_hive_serving(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	addr: impl AsRef<[u8]>,
	servlets: impl IntoIterator<Item = ServletInfo>,
) -> Result<RegisterHiveResponse, TightBeamError> {
	let id = id.as_ref();
	let frame = signed_control_frame_with(key, id, registration_request_serving(addr, servlets)).await?;
	decode(&emit_frame(client, frame).await?.message())
}

pub async fn emit_servlet_update(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
	request: ClusterRequest,
) -> Result<ServletAddressUpdateResponse, TightBeamError> {
	let id = id.as_ref();
	let frame = signed_control_frame_with(key, id, request).await?;
	decode(&emit_frame(client, frame).await?.message())
}

/// Composes and signs one end-to-end client work frame whose message is the
/// standard ping input. Gateways must deliver this frame to the servlet
/// byte-for-byte.
pub async fn signed_work_frame(key: &Secp256k1SigningKey, id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let unsigned = Version::V1
		.compose()
		.with_id(id)
		.with_order(UnixMillis::now().get())
		.with_message(PingRequest { value: 21 })
		.build()?;

	sign_frame(unsigned, key).await
}

/// Decodes the servlet's typed ping echo from its response frame.
pub fn decode_ping_echo(frame: &Frame) -> Result<PingResponse, TightBeamError> {
	decode(frame.message())
}

/// Resolves a work submission that a denial scenario expects the gateway to
/// refuse into the refusal's transit status.
///
/// A successful submission or a non-refusal error fails the scenario. The
/// branching lives here, so scenarios stay assertion-focused.
pub fn work_refusal_status(result: Result<Frame, TightBeamError>) -> Result<TransitStatus, TightBeamError> {
	match result {
		Err(TightBeamError::WorkRefused(status)) => Ok(status),
		Err(err) => Err(err),
		Ok(_) => Err(expectation_failure("work succeeded where the scenario expects a refusal")),
	}
}

/// Records a refused work submission on the trace: the refusal status as
/// `WORK_STATUS` and the absent servlet frame as `WORK_PAYLOAD`.
///
/// A refusal resolved through [`SubmitWork::submit_work_to`] delivers no
/// servlet frame to the caller, so the function records payload presence as
/// zero.
pub fn record_work_refusal(
	trace: &TraceCollector,
	result: Result<Frame, TightBeamError>,
) -> Result<(), TightBeamError> {
	trace.event_with(WORK_STATUS, &[], work_refusal_status(result)?)?;
	trace.event_with(WORK_PAYLOAD, &[], 0u64)?;
	Ok(())
}

/// Submits unary work under `type_name` with a signed ping client frame
/// through [`SubmitWork::submit_work_to`], and returns the servlet's
/// response frame.
///
/// The type URN is caller-chosen, but the body is always [`PingRequest`].
/// Export scenarios use this for private types that still host the ping
/// servlet. A refusal surfaces as [`TightBeamError::WorkRefused`].
pub async fn emit_typed_work(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	type_name: impl AsRef<str>,
	id: impl AsRef<[u8]>,
) -> Result<Frame, TightBeamError> {
	let type_name = type_name.as_ref();
	let id = id.as_ref();
	let inner = signed_work_frame(key, id).await?;

	client.submit_work_to(servlet_urn(type_name), &inner).await
}

pub async fn emit_ping_work(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	emit_typed_work(client, key, "ping", id).await
}

/// Emits ping work with a spent relay budget, as a hop-exhaustion probe.
///
/// This function composes the wire envelope itself, because the pre-spent
/// `hops_remaining` field is the wire shape under test, and
/// [`SubmitWork::submit_work_to`] cannot produce it.
pub async fn emit_relayed_ping_work(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	id: impl AsRef<[u8]>,
) -> Result<ClusterWorkResponse, TightBeamError> {
	let id = id.as_ref();
	let inner = signed_work_frame(key, id).await?;
	let work_request = ClusterRequest::Work(ClusterWorkRequest::new(servlet_urn("ping"), &inner)?.into_relayed(0));

	let frame = Version::V0
		.compose()
		.with_id(id)
		.with_order(0)
		.with_message(work_request)
		.build()?;

	decode(&emit_frame(client, frame).await?.message())
}

/// An instance URN in a realm this gateway does not serve.
pub fn foreign_realm_instance(addr: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
	let addr = addr.as_ref();
	let namespace = ColonyNamespace::new("tightbeam", "elsewhere").expect("static namespace parts are valid");
	namespace
		.servlet("ping")
		.expect("test names satisfy the mint grammar")
		.servlet_instance(addr)
		.expect("a servlet type URN yields an instance URN")
}

/// A gateway configuration that accepts peer advertisements.
///
/// `peer_trust` anchors the advertising gateway's certificate. The
/// configuration sets no `peers`, so this gateway only receives.
pub fn peering_cluster_conf(certs: &ClusterTestCerts) -> ClusterConfig {
	peering_cluster_conf_with_trust(certs, Arc::clone(&certs.trust))
}

/// Builds a configuration like [`peering_cluster_conf`], but with an explicit
/// peer trust store.
///
/// Scenarios use it when more than one peer identity must verify, including
/// federation peer-exclusion layouts and export split-plane scenarios.
pub fn peering_cluster_conf_with_trust(
	certs: &ClusterTestCerts,
	peer_trust: Arc<dyn CertificateTrust>,
) -> ClusterConfig {
	let tls = cluster_tls_config(certs).with_peer_trust(peer_trust);
	ClusterConfig::new(tls)
}

/// An importer that trusts peers only on the peer plane, with an empty
/// `hive_trust`.
pub fn peering_peer_trust_only(certs: &ClusterTestCerts) -> ClusterConfig {
	let tls = cluster_tls_config(certs)
		.with_hive_trust(None)
		.with_peer_trust(Arc::clone(&certs.trust));
	ClusterConfig::new(tls)
}

pub fn peering_with_dial_allowlist(
	certs: &ClusterTestCerts,
	allowlist: impl IntoIterator<Item = String>,
) -> ClusterConfig {
	let tls = cluster_tls_config(certs).with_peer_trust(Arc::clone(&certs.trust));
	ClusterConfig::builder(tls)
		.with_peer_dial_allowlist(allowlist)
		.expect("fixture allowlist entries name sockets")
		.build()
}

/// An importer configuration whose peer trails abandon after a few failed
/// forwards. The limit is small, so containment scenarios stay fast. The
/// specs pin [`CONTAINMENT_ABANDON_LIMIT`] failures before routing stops.
pub fn containment_cluster_conf(certs: &ClusterTestCerts) -> ClusterConfig {
	let mut conf = peering_cluster_conf(certs);
	conf.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;
	conf
}

/// Builds a configuration like [`peering_cluster_conf`], but one that dials
/// `peers` as beat anchors. Peers must pass through the builder, because the
/// discovery table derives its un-evictable anchor set at build.
pub fn peering_cluster_conf_with_peers(
	certs: &ClusterTestCerts,
	peers: impl IntoIterator<Item = String>,
) -> ClusterConfig {
	let peers: Vec<String> = peers.into_iter().collect();
	let tls = cluster_tls_config(certs).with_peer_trust(Arc::clone(&certs.trust));
	ClusterConfig::builder(tls)
		.with_peers(peers)
		.expect("fixture peers name sockets")
		.build()
}

/// A gateway configuration that advertises to `peer` on a fast beat. The
/// configuration sets no slate, so each beat snapshots the hive registry.
pub fn advertising_cluster_conf(certs: &ClusterTestCerts, peer: impl Into<String>) -> ClusterConfig {
	let peer: String = peer.into();
	ClusterConfig::builder(cluster_tls_config(certs))
		.with_peers([peer])
		.expect("fixture peers name sockets")
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

/// Sends one advertisement of `types`, signed by `signer`, from a peer at
/// `gateway_addr`.
///
/// The decoded status lands on the trace for spec verification.
pub async fn advertise_peer_signed(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	signer: &Secp256k1SigningKey,
	cluster: &ClusterGateway,
	gateway_addr: impl AsRef<[u8]>,
	types: impl IntoIterator<Item = Urn<'static>>,
) -> Result<(), TightBeamError> {
	let gateway_addr = gateway_addr.as_ref();
	let types: Vec<Urn<'static>> = types.into_iter().collect();
	let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
		gateway_addr: gateway_addr.to_vec(),
		advertised_types: types,
	});

	let frame = signed_control_frame_with(signer, b"peer-advertise", request).await?;
	send_advertisement_frame(trace, connect_certs, cluster, frame).await
}

/// Emits an already-signed advertisement frame.
///
/// Replay scenarios resend a byte-identical frame. Every decoded status
/// lands on the trace as `PEER_AD_STATUS`, and the surviving peer-route
/// count as `PEER_ROUTES_AFTER`, for spec verification.
pub async fn send_advertisement_frame(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(certs, cluster.addr()).await?;
	trace.event(PEER_ADVERTISE_SENT)?;

	let response_frame = emit_frame(&mut client, frame).await?;
	let response: PeerAdvertisementResponse = decode(response_frame.message())?;
	trace.event_with(PEER_AD_STATUS, &[], response.status)?;
	trace.event_with(PEER_ROUTES_AFTER, &[], count_u64(cluster.peer_servlets()?.len()))?;

	Ok(())
}

/// Sends one advertisement of `types` from a peer at `gateway_addr`, signed
/// with the fixture certificates' own key.
pub async fn advertise_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	gateway_addr: impl AsRef<[u8]>,
	types: impl IntoIterator<Item = Urn<'static>>,
) -> Result<(), TightBeamError> {
	let gateway_addr = gateway_addr.as_ref();
	let types: Vec<Urn<'static>> = types.into_iter().collect();
	advertise_peer_signed(trace, certs, &certs.key, cluster, gateway_addr, types).await
}

/// Advertises a one-type ping slate from the simulated peer gateway.
/// This is the shared preamble for every scenario that exercises behavior
/// after a peer route exists. The specs assert that `PEER_AD_STATUS`
/// proved the install.
pub async fn install_ping_peer(
	trace: &TraceCollector,
	certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
) -> Result<(), TightBeamError> {
	advertise_peer(trace, certs, cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await
}
