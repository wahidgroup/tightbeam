//! The integration tests of the Hive with X.509 certificates.
//!
//! They drive the Hive lifecycle through its public interface, over TLS.

use core::time::Duration;
use std::sync::{Arc, Barrier};

use sha3::Sha3_256;
use tokio::sync::{AcquireError, Notify, Semaphore, SemaphorePermit};

use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::{CheckDigestOid, TypeBuilder};
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig, ServletBox, ServletScaleConfig};
use tightbeam::colony::protocol::{
	ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, HiveManagement, HiveManagementOutcome,
	ListServletsParams, SpawnServletParams, StopServletParams,
};
use tightbeam::colony::servlet::{ServletConfig, UtilizationGauge};
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::DirectTrustValidator;
use tightbeam::crypto::x509::{Certificate, CertificateSpec, KeyPurposes, PeerCertificate, Signing};
use tightbeam::der::Sequence;
use tightbeam::instrumentation::{events, TbInstrumentationConfig};
use tightbeam::policy::TransitStatus;
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::{HiveEnv, SetupEnv, TestCertificate, TestDigest, TestIdentity, TestKey};
use tightbeam::trace::{TraceCollector, TraceConfig};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, GenericClient, Protocol, TransportError, TransportFailure,
};
use tightbeam::urn::Urn;
use tightbeam::utils::time::{Clock, ManualClock, UnixMillis};
use tightbeam::utils::BasisPoints;
use tightbeam::{
	absent, compose, decode, exactly, hive, servlet, tb_assert_spec, tb_scenario, Beamable, Frame, Message,
	TightBeamError, Version,
};

use crate::common::poll::poll_until;
use crate::common::security::{expectation_failure, pinning_trust_store, ServerMaterials};
use crate::common::x509::{create_test_cert_with_key, signing_identity};

#[cfg(feature = "instrument")]
use crate::common::hive::recorded_labels;

fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

fn servlet_urn(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
	let name = name.as_ref();
	colony_ns().servlet(name).expect("test names satisfy the mint grammar")
}

pub(crate) const SERVLET_STOPPED: Urn<'static> = tightbeam::urn!("test", "event:hive/servlet-stopped");

/// The request whose `value` the hive's test servlets double.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct HiveTestRequest {
	/// The number the servlet doubles.
	pub value: u32,
}

/// The reply of a hive test servlet.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct HiveTestResponse {
	/// Twice the request's `value`.
	pub doubled: u32,
}

servlet! {
	HiveTestServlet<HiveTestRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, _ctx| async move {
		Ok(Some(compose! {
			V0: id: frame.metadata().id(),
				message: HiveTestResponse { doubled: req.value * 2 }
		}?))
	}
}

hive! {
	HiveX509Test,
	protocol: TokioListener
}

tb_assert_spec! {
	pub HiveEstablishSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_ESTABLISHED, exactly!(1), equals!(1u64))
		]
	}
}

/// Registers a test servlet and establishes the hive on the scenario trace.
/// The hive records [`events::HIVE_ESTABLISHED`] with its servlet count.
async fn establish_registered_hive(
	trace: &TraceCollector,
	conf: Option<HiveConfig>,
) -> Result<HiveX509Test, TightBeamError> {
	let servlet = HiveTestServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await?;
	let mut hive = HiveX509Test::new(conf)?;
	hive.register(servlet_urn("test_servlet"), servlet, |t| {
		HiveTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;

	Ok(hive)
}

fn hive_tls() -> HiveTlsConfig {
	let (cert, signing_key) = create_test_cert_with_key("CN=Hive Test Server", 365).expect("hive TLS material");
	HiveTlsConfig::new(
		CertificateSpec::Built(Box::new(cert)),
		Arc::new(Secp256k1KeyProvider::from(signing_key)),
		PeerAuthentication::Anonymous,
	)
	.expect("the hive TLS material must decode")
}

tb_scenario! {
	name: hive_establish_with_x509,
	spec: HiveEstablishSpec,
	environment Hive {
		context: hive_tls(),
		start: |SetupEnv { trace, context: tls }| async move {
			let mut conf = HiveConfig { hive_tls: Some(tls), ..Default::default() };
			conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(4)));
			establish_registered_hive(&trace, Some(conf)).await
		},
		client: |HiveEnv { hive, .. }| async move {
			hive.stop();
			Ok(())
		}
	}
}

// A trace that refuses `HIVE_ESTABLISHED` fails the establish before the
// control plane serves. The hive stays provisional with no address, and a later
// establish on a trace that records the event succeeds.
#[cfg(feature = "testing-fault")]
#[tokio::test]
async fn a_refused_established_event_leaves_the_hive_provisional() -> Result<(), TightBeamError> {
	use tightbeam::testing::FaultModel;

	let refused = || TightBeamError::ChannelClosed;
	let model = FaultModel::default().with_event_fault(events::HIVE_ESTABLISHED, refused, tightbeam::bps!(10000));
	let refusing = Arc::new(TraceCollector::new().with_fault_model(model));
	let mut hive = HiveX509Test::new(Some(HiveConfig { hive_tls: Some(Arc::new(hive_tls())), ..Default::default() }))?;

	let first = hive.establish(refusing).await;
	let unbound = hive.addr().is_none();
	let second = hive.establish(Arc::new(TraceCollector::new())).await;
	hive.stop();

	assert!(matches!(first, Err(TightBeamError::ChannelClosed)));
	assert!(unbound);
	second?;
	Ok(())
}

/// Builds a fresh heartbeat command body. Freshness binds to
/// `Frame.metadata.order`.
fn heartbeat_command() -> ClusterCommand {
	ClusterCommand::Heartbeat(HeartbeatParams { cluster_status: ClusterStatus::Healthy })
}

/// A cluster command spelled as a SEQUENCE whose `[0]` heartbeat and `[1]`
/// management fields are each OPTIONAL.
///
/// A hive reads a command as a CHOICE, which encodes as its one alternative,
/// so a body of this shape decodes as no command.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
#[beam(frame_integrity)]
pub struct SequenceShapedCommand {
	/// The heartbeat field [context 0].
	#[asn1(context_specific = "0", optional = "true")]
	pub heartbeat: Option<HeartbeatParams>,
	/// The management field [context 1].
	#[asn1(context_specific = "1", optional = "true")]
	pub manage: Option<SequenceShapedManagement>,
}

/// A management request spelled as a SEQUENCE with an OPTIONAL `[2]` stop
/// field.
#[derive(Sequence, Clone, Debug, PartialEq)]
pub struct SequenceShapedManagement {
	/// The stop field [context 2].
	#[asn1(context_specific = "2", optional = "true")]
	pub stop: Option<StopServletParams>,
}

impl SequenceShapedCommand {
	/// A body that sets neither field.
	fn empty() -> Self {
		Self { heartbeat: None, manage: None }
	}

	/// A body that sets its heartbeat field alone.
	fn heartbeat() -> Self {
		Self { heartbeat: Some(Self::healthy()), manage: None }
	}

	/// A body that sets both its heartbeat field and its management field.
	fn both() -> Self {
		let instance = servlet_urn("none").servlet_instance("127.0.0.1:0");
		let servlet_id = instance.expect("a servlet type URN yields an instance URN");
		let stop = SequenceShapedManagement { stop: Some(StopServletParams { servlet_id }) };

		Self { heartbeat: Some(Self::healthy()), manage: Some(stop) }
	}

	/// The heartbeat parameters of a healthy cluster.
	fn healthy() -> HeartbeatParams {
		HeartbeatParams { cluster_status: ClusterStatus::Healthy }
	}
}

/// Builds an unsigned command frame with an integrity witness, for the caller
/// to sign. `metadata.order` is the freshness binding (CWE-294).
fn command_frame_with_order<M>(id: impl AsRef<[u8]>, cmd: M, order: u64) -> Result<Frame, TightBeamError>
where
	M: Message + CheckDigestOid<Sha3_256>,
{
	let id = id.as_ref();
	FrameBuilder::from(Version::V1)
		.with_id(id)
		.with_order(order)
		.with_message(cmd)
		.with_witness_hasher::<Sha3_256>()
		.build()
}

fn command_frame<M>(id: impl AsRef<[u8]>, cmd: M) -> Result<Frame, TightBeamError>
where
	M: Message + CheckDigestOid<Sha3_256>,
{
	let id = id.as_ref();
	command_frame_with_order(id, cmd, UnixMillis::now().get())
}

/// Builds a manage command frame with a stop request. Each call site
/// passes a unique id.
fn stop_command_frame(id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let servlet_id = servlet_urn("none")
		.servlet_instance("127.0.0.1:0")
		.expect("a servlet type URN yields an instance URN");

	stop_instance_frame(id, servlet_id)
}

/// Builds a manage command frame that stops the instance `servlet_id`.
fn stop_instance_frame(id: impl AsRef<[u8]>, servlet_id: Urn<'static>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let stop = StopServletParams { servlet_id };
	let manage_cmd = ClusterCommand::Manage(HiveManagement::Stop(stop));

	command_frame(id, manage_cmd)
}

/// Builds a manage command frame with a list request.
fn list_command_frame(id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let list = ListServletsParams { filter: None };
	let manage_cmd = ClusterCommand::Manage(HiveManagement::List(list));

	command_frame(id, manage_cmd)
}

/// Builds a manage command frame with a spawn request.
fn spawn_command_frame(id: impl AsRef<[u8]>, servlet_type: impl AsRef<str>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let servlet_type = servlet_type.as_ref();
	let spawn = SpawnServletParams { servlet_type: servlet_urn(servlet_type), config: None };
	let manage_cmd = ClusterCommand::Manage(HiveManagement::Spawn(spawn));

	command_frame(id, manage_cmd)
}

/// A signer that the hive trust store pins: `start` builds the trust store
/// from the certificate, and the client signs command frames under the
/// identity.
struct TrustedSignerContext {
	certificate: Certificate,
	identity: SigningIdentity,
}

impl TrustedSignerContext {
	/// The control-plane TLS this signer's hive presents.
	///
	/// The validator chain makes the accept side request and keep the caller
	/// certificate. The security gate keys its per-signer breaker on the peer
	/// the handshake proves, so a plane that proves no peer has no budget to
	/// key on.
	fn control_tls(&self) -> HiveTlsConfig {
		let anchor = DirectTrustValidator::default().with_trust_chain([self.certificate.to_owned()]);
		let anchor = anchor.expect("a test certificate encodes");

		HiveTlsConfig::new(
			CertificateSpec::Built(Box::new(self.certificate.to_owned())),
			self.identity.provider_arc(),
			PeerAuthentication::Anonymous.and(Arc::new(anchor)),
		)
		.expect("the hive TLS material must decode")
	}
}

fn trusted_signer(subject: impl AsRef<str>) -> TrustedSignerContext {
	let subject = subject.as_ref();
	let (certificate, signing_key) = create_test_cert_with_key(subject, 365).expect("signer material");
	let identity = signing_identity(certificate.to_owned(), signing_key);
	TrustedSignerContext { certificate, identity }
}

/// Starts an established hive with the context signer pinned in its trust
/// store.
async fn start_trusted_hive(
	trace: &TraceCollector,
	ctx: &TrustedSignerContext,
	mut conf: HiveConfig,
) -> Result<HiveX509Test, TightBeamError> {
	conf.trust_store = Some(pinning_trust_store(&ctx.certificate)?);
	conf.hive_tls = Some(Arc::new(ctx.control_tls()));

	let mut hive = HiveX509Test::new(Some(conf))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Dials the hive control plane as the trusted signer. The client presents
/// `ctx` as its certificate, so the security gate has a proven peer to key on.
async fn connect_hive(
	hive: &HiveX509Test,
	ctx: &TrustedSignerContext,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	let client = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(pinning_trust_store(&ctx.certificate)?)
		.with_client_identity(ctx.identity.clone())
		.build();

	let addr = hive.addr().ok_or(TightBeamError::NotEstablished)?;
	Ok(client.connect(addr.to_owned()).await?)
}

async fn emit_command(
	client: &mut GenericClient<TokioListener>,
	frame: Frame,
) -> Result<ClusterCommandResponse, TightBeamError> {
	let response = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
	decode(response.message())
}

/// Requires the response to name the heartbeat alternative. When
/// `sealed_capacity` is set, the reply must not leak capacity before
/// authentication. Returns the status for the caller to assert.
fn heartbeat_shape_status(
	response: ClusterCommandResponse,
	sealed_capacity: bool,
) -> Result<TransitStatus, TightBeamError> {
	let heartbeat = match response {
		ClusterCommandResponse::Heartbeat(heartbeat) => heartbeat,
		ClusterCommandResponse::Manage(_) => {
			return Err(expectation_failure("heartbeat response must not use the manage shape"));
		}
	};

	if sealed_capacity && (heartbeat.utilization.get() != 0 || heartbeat.active_servlets != 0) {
		return Err(expectation_failure("pre-auth reject must not leak capacity"));
	}

	Ok(heartbeat.status)
}

/// Requires the response to name the manage/stop alternative. Returns the
/// stop status for the caller to assert.
fn manage_stop_shape_status(response: ClusterCommandResponse) -> Result<TransitStatus, TightBeamError> {
	match response {
		ClusterCommandResponse::Manage(HiveManagementOutcome::Stop(stop)) => Ok(stop.status),
		ClusterCommandResponse::Heartbeat(_) => {
			Err(expectation_failure("manage response must not use the heartbeat shape"))
		}
		ClusterCommandResponse::Manage(_) => Err(expectation_failure("manage/stop CHOICE required")),
	}
}

/// Requires the response to name the manage/list alternative. Returns the
/// list status for the caller to assert.
fn manage_list_shape_status(response: ClusterCommandResponse) -> Result<TransitStatus, TightBeamError> {
	match response {
		ClusterCommandResponse::Manage(HiveManagementOutcome::List(list)) => Ok(list.status),
		ClusterCommandResponse::Heartbeat(_) => {
			Err(expectation_failure("manage response must not use the heartbeat shape"))
		}
		ClusterCommandResponse::Manage(_) => Err(expectation_failure("manage/list CHOICE required")),
	}
}

/// Requires the response to name the manage/spawn alternative. Returns the
/// spawn status for the caller to assert.
fn manage_spawn_shape_status(response: ClusterCommandResponse) -> Result<TransitStatus, TightBeamError> {
	match response {
		ClusterCommandResponse::Manage(HiveManagementOutcome::Spawn(spawn)) => Ok(spawn.status),
		ClusterCommandResponse::Heartbeat(_) => {
			Err(expectation_failure("manage response must not use the heartbeat shape"))
		}
		ClusterCommandResponse::Manage(_) => Err(expectation_failure("manage/spawn CHOICE required")),
	}
}

async fn signed_heartbeat_frame(identity: &SigningIdentity, id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut frame = command_frame(id, heartbeat_command())?;
	frame.sign_with_provider(identity).await?;
	Ok(frame)
}

async fn signed_stop_frame(identity: &SigningIdentity, id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut frame = stop_command_frame(id)?;
	frame.sign_with_provider(identity).await?;
	Ok(frame)
}

/// Signs `command`, a body spelled as a SEQUENCE, which the CHOICE decoder
/// rejects.
async fn signed_sequence_command_frame(
	identity: &SigningIdentity,
	id: impl AsRef<[u8]>,
	command: SequenceShapedCommand,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut frame = command_frame(id, command)?;
	frame.sign_with_provider(identity).await?;
	Ok(frame)
}

async fn signed_spawn_frame(
	identity: &SigningIdentity,
	id: impl AsRef<[u8]>,
	servlet_type: impl AsRef<str>,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let servlet_type = servlet_type.as_ref();
	let mut frame = spawn_command_frame(id, servlet_type)?;
	frame.sign_with_provider(identity).await?;
	Ok(frame)
}

async fn signed_stop_instance_frame(
	identity: &SigningIdentity,
	id: impl AsRef<[u8]>,
	servlet_id: Urn<'static>,
) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut frame = stop_instance_frame(id, servlet_id)?;
	frame.sign_with_provider(identity).await?;
	Ok(frame)
}

/// Requires the response to name the manage/spawn alternative with the
/// instance it spawned. Returns the spawn status and that instance.
fn spawned_instance(response: ClusterCommandResponse) -> Result<(TransitStatus, Urn<'static>), TightBeamError> {
	let ClusterCommandResponse::Manage(HiveManagementOutcome::Spawn(spawn)) = response else {
		return Err(expectation_failure("manage/spawn CHOICE required"));
	};

	let unnamed = expectation_failure("an accepted spawn names its instance");
	let instance = spawn.servlet_id.ok_or(unnamed)?;
	Ok((spawn.status, instance))
}

/// The configuration of a hive that pins the context signer in its trust
/// store and presents the signer's control-plane TLS.
fn serving_conf(ctx: &TrustedSignerContext) -> Result<HiveConfig, TightBeamError> {
	let trust_store = Some(pinning_trust_store(&ctx.certificate)?);
	let hive_tls = Some(Arc::new(ctx.control_tls()));

	Ok(HiveConfig { trust_store, hive_tls, ..Default::default() })
}

/// Starts an established hive that pins the context signer in its trust
/// store and registers one [`HiveTestServlet`] under `test_servlet`, so the
/// signer can spawn and stop instances of that type.
async fn start_serving_hive(
	trace: &TraceCollector,
	ctx: &TrustedSignerContext,
) -> Result<HiveX509Test, TightBeamError> {
	let conf = serving_conf(ctx)?;
	start_serving_hive_under(trace, conf).await
}

/// Starts an established hive under `conf` that registers one
/// [`HiveTestServlet`] under `test_servlet`.
async fn start_serving_hive_under(trace: &TraceCollector, conf: HiveConfig) -> Result<HiveX509Test, TightBeamError> {
	let servlet = HiveTestServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await?;

	let mut hive = HiveX509Test::new(Some(conf))?;
	hive.register(servlet_urn("test_servlet"), servlet, |t| {
		HiveTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// The replies of a hive to one spawn and one stop of an instance, and the
/// instance that the spawn named.
struct CarriedOut {
	/// The status of the spawn reply and of the stop reply.
	statuses: (TransitStatus, TransitStatus),
	/// The instance that the hive spawned and then stopped.
	instance: Urn<'static>,
}

/// Spawns one `test_servlet` instance on `hive` as the context signer, then
/// stops it. It returns the status of each reply and the instance.
async fn spawn_and_stop(hive: &HiveX509Test, signer: &TrustedSignerContext) -> Result<CarriedOut, TightBeamError> {
	let mut client = connect_hive(hive, signer).await?;
	let spawn = signed_spawn_frame(&signer.identity, b"spawn-carried-out", "test_servlet").await?;
	let (spawned, instance) = spawned_instance(emit_command(&mut client, spawn).await?)?;

	let stop = signed_stop_instance_frame(&signer.identity, b"stop-carried-out", instance.clone()).await?;
	let stopped = manage_stop_shape_status(emit_command(&mut client, stop).await?)?;
	Ok(CarriedOut { statuses: (spawned, stopped), instance })
}

/// Lists the servlets of `hive` and sends it one heartbeat as the context
/// signer. It returns the status of each reply.
async fn list_and_beat(
	hive: &HiveX509Test,
	signer: &TrustedSignerContext,
) -> Result<(TransitStatus, TransitStatus), TightBeamError> {
	let mut client = connect_hive(hive, signer).await?;
	let mut list = list_command_frame(b"list-read")?;
	list.sign_with_provider(&signer.identity).await?;
	let listed = manage_list_shape_status(emit_command(&mut client, list).await?)?;

	let beat = signed_heartbeat_frame(&signer.identity, b"beat-read").await?;
	let beaten = heartbeat_shape_status(emit_command(&mut client, beat).await?, false)?;
	Ok((listed, beaten))
}

// The refusals carry three statuses, and `equals!` binds every record of its
// label, so the spec counts the refusals and the client asserts each status.
tb_assert_spec! {
	pub HiveGateShapeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(3))
		]
	},
	V(1,1,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(6))
		]
	},
	V(1,2,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(6))
		]
	}
}

// Security rejects must come back in the CHOICE the sender expects. The
// cluster counts a heartbeat refused in the manage shape, a MalformedResponse,
// toward eviction and would sever a plane its breaker recovers after cooldown.
tb_scenario! {
	name: hive_gate_reply_shapes,
	spec: HiveGateShapeSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Gate Cluster"),
		start: |SetupEnv { trace, context: signer }| async move {
			let mut conf = HiveConfig::default();
			conf.control.circuit_breaker_threshold = 1;
			conf.control.circuit_breaker_cooldown = Duration::from_secs(60);
			start_trusted_hive(&trace, &signer, conf).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;

			// An unsigned heartbeat must come back in the heartbeat CHOICE
			// with no capacity data before authentication.
			let unsigned_heartbeat = command_frame(b"hb-unsigned", heartbeat_command())?;
			let response = emit_command(&mut client, unsigned_heartbeat).await?;
			let status = heartbeat_shape_status(response, true)?;
			assert_eq!(
				status,
				TransitStatus::Unauthenticated,
				"the hive refuses an unsigned heartbeat in the heartbeat shape"
			);

			// An unsigned manage command must come back in the manage CHOICE
			// as a security verdict, not a drain probe.
			let unsigned_stop = stop_command_frame(b"manage-unsigned")?;
			let response = emit_command(&mut client, unsigned_stop).await?;
			let status = manage_stop_shape_status(response)?;
			assert_eq!(status, TransitStatus::Unauthenticated, "the hive refuses an unsigned stop in the manage shape");

			// The hive must accept a signed heartbeat end to end.
			let signed_heartbeat = signed_heartbeat_frame(&signer.identity, b"hb-signed").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			let status = heartbeat_shape_status(response, false)?;
			assert_eq!(status, TransitStatus::Ok, "the hive answers a signed heartbeat");

			hive.drain().await?;

			// A liveness command survives the drain, so the hive answers a
			// signed heartbeat and the cluster still reads its health.
			let signed_heartbeat = signed_heartbeat_frame(&signer.identity, b"hb-draining").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			let status = heartbeat_shape_status(response, false)?;
			assert_eq!(status, TransitStatus::Ok, "a draining hive still answers a signed heartbeat");

			// A signed manage command during drain must come back
			// Unavailable in the manage CHOICE.
			let signed_stop = signed_stop_frame(&signer.identity, b"manage-draining").await?;
			let response = emit_command(&mut client, signed_stop).await?;
			let status = manage_stop_shape_status(response)?;
			assert_eq!(status, TransitStatus::Unavailable, "a draining hive refuses a signed stop");

			// A spawn the drain refuses answers in the spawn alternative, which
			// its sender decodes.
			let signed_spawn = signed_spawn_frame(&signer.identity, b"spawn-draining", "orphan").await?;
			let response = emit_command(&mut client, signed_spawn).await?;
			let status = manage_spawn_shape_status(response)?;
			assert_eq!(status, TransitStatus::Unavailable, "a draining hive refuses a signed spawn in the spawn shape");

			// Trip the breaker at threshold 1. A trusted signer's signature
			// transplanted from another frame is the one failure class the
			// breaker counts.
			let now = UnixMillis::now();
			let mut donor = command_frame_with_order(b"hb-donor", heartbeat_command(), now.get())?;
			donor.sign_with_provider(&signer.identity).await?;

			let transplanted = donor.nonrepudiation().cloned().ok_or(TightBeamError::MissingSignature)?;
			let forged_order = now.saturating_add(Duration::from_millis(1)).get();
			let mut forged = command_frame_with_order(b"hb-forged", heartbeat_command(), forged_order)?;
			forged.attach_signer_info(transplanted)?;

			let response = emit_command(&mut client, forged).await?;
			let status = heartbeat_shape_status(response, false)?;
			assert_eq!(status, TransitStatus::PermissionDenied, "the hive refuses a transplanted signature");

			// With the breaker open, the hive refuses a valid heartbeat during
			// cooldown but keeps the heartbeat CHOICE, so the cluster records a
			// reply instead of MalformedResponse eviction pressure.
			let signed_heartbeat = signed_heartbeat_frame(&signer.identity, b"hb-open").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			let status = heartbeat_shape_status(response, true)?;
			assert_eq!(
				status,
				TransitStatus::PermissionDenied,
				"an open breaker refuses a valid heartbeat in the heartbeat shape"
			);

			hive.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveBackpressureShapeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(2), equals!(TransitStatus::ResourceExhausted))
		]
	}
}

// A ResourceExhausted backpressure refusal must also come back in the sender's
// CHOICE. Only manage commands hit the gate, so the verdict must use the manage
// shape.
tb_scenario! {
	name: hive_backpressure_reply_shape,
	spec: HiveBackpressureShapeSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Backpressure Cluster"),
		// Under a zero threshold, idle utilization saturates the gate, so every
		// manage command sees the backpressure verdict.
		start: |SetupEnv { trace, context: signer }| async move {
			let mut conf = HiveConfig::default();
			conf.control.backpressure_threshold = BasisPoints::default();

			start_trusted_hive(&trace, &signer, conf).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;

			let signed_stop = signed_stop_frame(&signer.identity, b"manage-bp").await?;
			let response = emit_command(&mut client, signed_stop).await?;
			let status = manage_stop_shape_status(response)?;
			assert_eq!(
				status,
				TransitStatus::ResourceExhausted,
				"a saturated hive refuses a signed stop in the manage shape"
			);

			let signed_spawn = signed_spawn_frame(&signer.identity, b"spawn-bp", "orphan").await?;
			let response = emit_command(&mut client, signed_spawn).await?;
			let status = manage_spawn_shape_status(response)?;
			assert_eq!(
				status,
				TransitStatus::ResourceExhausted,
				"a saturated hive refuses a signed spawn in the spawn shape"
			);

			// A signed heartbeat is exempt from the gate. The hive answers it
			// in the heartbeat CHOICE with real capacity data, and the
			// ResourceExhausted status reflects saturation.
			let signed_heartbeat = signed_heartbeat_frame(&signer.identity, b"hb-bp").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			let status = heartbeat_shape_status(response, false)?;
			assert_eq!(
				status,
				TransitStatus::ResourceExhausted,
				"a saturated hive answers a signed heartbeat with its load"
			);

			hive.stop();

			Ok(())
		}
	}
}

// The establish flow must also work without TLS.
tb_scenario! {
	name: hive_establish_no_tls,
	spec: HiveEstablishSpec,
	environment Hive {
		context: (),
		start: |SetupEnv { trace, .. }| async move { establish_registered_hive(&trace, None).await },
		client: |HiveEnv { hive, .. }| async move {
			hive.stop();
			Ok(())
		}
	}
}

/// A provisional `addr` from `HiveRuntime::new` must not reach the cluster,
/// so the hive refuses registration before establish with `NotEstablished`.
#[tokio::test]
async fn hive_register_before_establish_refused() -> Result<(), TightBeamError> {
	let hive = HiveX509Test::new(None)?;
	let cluster_addr: <TokioListener as Protocol>::Address = "127.0.0.1:9".parse()?;
	let refused = hive.register_with_cluster(&cluster_addr).await;
	hive.stop();

	assert!(
		matches!(refused, Err(TightBeamError::NotEstablished)),
		"a provisional hive refuses to register"
	);
	Ok(())
}

tb_assert_spec! {
	pub HiveSequenceShapeRefusalSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(3), equals!(TransitStatus::InvalidArgument))
		]
	}
}

// Each SEQUENCE body, with none, one, or both fields, must draw a refusal the
// sender can decode. Silence would hang the cluster until its timeout, which
// counts the hive as lost. PermissionDenied would blame authorized credentials.
tb_scenario! {
	name: hive_refuses_a_command_of_the_sequence_shape,
	spec: HiveSequenceShapeRefusalSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Choice Refusal"),
		start: |SetupEnv { trace, context: signer }| async move {
			start_trusted_hive(&trace, &signer, HiveConfig::default()).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;
			let empty = SequenceShapedCommand::empty();
			let empty = signed_sequence_command_frame(&signer.identity, b"cmd-empty", empty).await?;
			let response = emit_command(&mut client, empty).await?;

			let status = manage_stop_shape_status(response)?;
			assert_eq!(status, TransitStatus::InvalidArgument, "the hive refuses a body that sets no field");

			let heartbeat = SequenceShapedCommand::heartbeat();
			let heartbeat = signed_sequence_command_frame(&signer.identity, b"cmd-heartbeat", heartbeat).await?;
			let response = emit_command(&mut client, heartbeat).await?;

			let status = manage_stop_shape_status(response)?;
			assert_eq!(
				status,
				TransitStatus::InvalidArgument,
				"the hive refuses a body that sets its heartbeat field alone"
			);

			let both = SequenceShapedCommand::both();
			let both = signed_sequence_command_frame(&signer.identity, b"cmd-both", both).await?;
			let response = emit_command(&mut client, both).await?;

			let status = manage_stop_shape_status(response)?;
			assert_eq!(status, TransitStatus::InvalidArgument, "the hive refuses a body that sets both fields");

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveSpawnRetrySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::Unavailable))
		]
	}
}

// A spawner failure is a refusal a retry can change, so the hive answers
// Unavailable and releases the replay slot. It then admits the same signed
// frame, and the retry succeeds.
tb_scenario! {
	name: hive_manage_failure_allows_signed_retry,
	spec: HiveSpawnRetrySpec,
	environment Hive {
		context: trusted_signer("CN=Hive Spawn Retry"),
		start: |SetupEnv { trace, context: signer }| async move {
			use core::sync::atomic::{AtomicBool, Ordering};

			let fail_once = Arc::new(AtomicBool::new(true));
			let seed = HiveTestServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await?;
			let trust_store = pinning_trust_store(&signer.certificate)?;
			let conf = HiveConfig {
				trust_store: Some(trust_store),
				hive_tls: Some(Arc::new(signer.control_tls())),
				..Default::default()
			};

			let mut hive = HiveX509Test::new(Some(conf))?;
			hive.register(servlet_urn("flaky"), seed, move |t| {
				let fail_flag = Arc::clone(&fail_once);
				async move {
					if fail_flag.swap(false, Ordering::SeqCst) {
						return Err(TightBeamError::MissingResponse);
					}

					HiveTestServlet::start(t, ServletConfig::cleartext()).await
				}
			})?;

			hive.establish(Arc::new(trace.share())).await?;
			Ok(hive)
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;
			let signed = signed_spawn_frame(&signer.identity, b"spawn-retry", "flaky").await?;
			let replay = signed.to_owned();

			let first = emit_command(&mut client, signed).await?;
			let status = manage_spawn_shape_status(first)?;
			assert_eq!(status, TransitStatus::Unavailable, "the hive refuses a spawn whose spawner fails");

			let second = emit_command(&mut client, replay).await?;
			let status = manage_spawn_shape_status(second)?;
			assert_eq!(status, TransitStatus::Ok, "the hive admits the signed retry");

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HivePermanentRefusalKeepsSlotSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(2))
		]
	}
}

// A drain refusal holds for every resubmission, so it keeps the replay slot
// spent. The same frame sent again draws PermissionDenied as a replay, not
// Unavailable as a drain refusal, so a captured frame buys its holder nothing.
tb_scenario! {
	name: hive_permanent_refusal_keeps_the_replay_slot,
	spec: HivePermanentRefusalKeepsSlotSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Permanent Refusal"),
		start: |SetupEnv { trace, context: signer }| async move {
			start_trusted_hive(&trace, &signer, HiveConfig::default()).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;
			hive.drain().await?;

			let signed = signed_stop_frame(&signer.identity, b"stop-draining").await?;
			let replay = signed.to_owned();

			let first = emit_command(&mut client, signed).await?;
			let status = manage_stop_shape_status(first)?;
			assert_eq!(status, TransitStatus::Unavailable, "a drain refuses the stop");

			let second = emit_command(&mut client, replay).await?;
			let status = manage_stop_shape_status(second)?;
			assert_eq!(status, TransitStatus::PermissionDenied, "the hive refuses the resent frame as a replay");

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveCommandAcceptedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_ACCEPTED, exactly!(2)),
			(events::HIVE_COMMAND_REFUSED, absent!())
		]
	}
}

// A spawn and a stop that the hive carries out each leave one record that
// names the peer who sent it, and the hive refuses neither (CWE-778).
tb_scenario! {
	name: hive_records_each_command_it_carries_out,
	spec: HiveCommandAcceptedSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Accepted Commands"),
		start: |SetupEnv { trace, context: signer }| async move { start_serving_hive(&trace, &signer).await },
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let carried = spawn_and_stop(&hive, &signer).await?;
			let statuses = (TransitStatus::Ok, TransitStatus::Ok);
			assert_eq!(carried.statuses, statuses, "the hive spawns and stops the instance");

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveReadCommandSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_ACCEPTED, absent!()),
			(events::HIVE_COMMAND_REFUSED, absent!())
		]
	}
}

// A list and a heartbeat read the hive and change no servlet, so the hive
// answers both and records no acceptance of either (CWE-778).
tb_scenario! {
	name: hive_records_no_acceptance_of_a_read,
	spec: HiveReadCommandSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Read Commands"),
		start: |SetupEnv { trace, context: signer }| async move { start_serving_hive(&trace, &signer).await },
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let statuses = list_and_beat(&hive, &signer).await?;
			assert_eq!(statuses, (TransitStatus::Ok, TransitStatus::Ok), "the hive answers the list and the heartbeat");

			hive.stop();
			Ok(())
		}
	}
}

/// Starts a serving hive whose `test_servlet` type holds one instance at
/// most and at least.
async fn start_single_instance_hive(ctx: &TrustedSignerContext) -> Result<HiveX509Test, TightBeamError> {
	let bounds = ServletScaleConfig::new(1, 1, tightbeam::bps!(8000), tightbeam::bps!(2000));
	let bounds = bounds.expect("one instance is a legal range");
	let mut conf = serving_conf(ctx)?;
	conf.scaling.overrides.insert(servlet_urn("test_servlet"), bounds);

	start_serving_hive_under(&TraceCollector::new(), conf).await
}

/// The instance of the one servlet that `hive` registered.
fn registered_instance(hive: &HiveX509Test) -> Urn<'static> {
	let registered = hive.servlet_addresses().into_iter().next();
	let (servlet_type, address) = registered.expect("the hive registers one servlet");

	let instance = servlet_type.instance_urn(address);
	instance.expect("the servlet's address names an instance")
}

/// A spawn past the most instances of its type is refused at capacity, so
/// the type stays within its bounds (CWE-770).
#[tokio::test]
async fn a_manage_spawn_past_max_instances_is_refused_at_capacity() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive At Capacity");
	let hive = start_single_instance_hive(&signer).await?;
	let mut client = connect_hive(&hive, &signer).await?;

	let spawn = signed_spawn_frame(&signer.identity, b"spawn-past-max", "test_servlet").await?;
	let status = manage_spawn_shape_status(emit_command(&mut client, spawn).await?)?;
	hive.stop();

	assert_eq!(status, TransitStatus::ResourceExhausted);
	Ok(())
}

/// A stop of the last instance of a type is refused under its floor, so the
/// type keeps the fewest instances its bounds name.
#[tokio::test]
async fn a_manage_stop_under_min_instances_is_refused() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive Below Floor");
	let hive = start_serving_hive(&TraceCollector::new(), &signer).await?;
	let mut client = connect_hive(&hive, &signer).await?;

	let instance = registered_instance(&hive);
	let stop = signed_stop_instance_frame(&signer.identity, b"stop-the-floor", instance).await?;
	let status = manage_stop_shape_status(emit_command(&mut client, stop).await?)?;
	hive.stop();

	assert_eq!(status, TransitStatus::FailedPrecondition);
	Ok(())
}

/// A servlet at a fixed locator that reports itself unhealthy.
struct UnhealthyServlet;

impl ServletBox for UnhealthyServlet {
	fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::from(b"127.0.0.1:7060".as_slice())
	}

	fn stop_boxed(self: Box<Self>) {}

	fn signer(&self) -> Option<&SignerIdentifier> {
		None
	}

	fn is_healthy(&self) -> bool {
		false
	}
}

/// Starts a serving hive that registers an [`UnhealthyServlet`] beside its
/// one [`HiveTestServlet`].
async fn start_hive_with_an_unhealthy_servlet(ctx: &TrustedSignerContext) -> Result<HiveX509Test, TightBeamError> {
	let trace = TraceCollector::new();
	let servlet = HiveTestServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await?;

	let mut hive = HiveX509Test::new(Some(serving_conf(ctx)?))?;
	hive.register(servlet_urn("test_servlet"), servlet, |t| {
		HiveTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.register(servlet_urn("unhealthy"), UnhealthyServlet, |_| async { Ok(UnhealthyServlet) })?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Requires the response to name the heartbeat alternative, and returns the
/// count of servlets it reports.
fn heartbeat_active_servlets(response: ClusterCommandResponse) -> Result<u32, TightBeamError> {
	let ClusterCommandResponse::Heartbeat(heartbeat) = response else {
		return Err(expectation_failure("heartbeat response must not use the manage shape"));
	};

	Ok(heartbeat.active_servlets)
}

/// A heartbeat counts the servlets that report themselves healthy, so a
/// gateway reads the capacity that serves.
#[tokio::test]
async fn a_heartbeat_counts_only_the_servlets_that_report_healthy() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive Healthy Count");
	let hive = start_hive_with_an_unhealthy_servlet(&signer).await?;
	let mut client = connect_hive(&hive, &signer).await?;

	let beat = signed_heartbeat_frame(&signer.identity, b"beat-healthy-count").await?;
	let active = heartbeat_active_servlets(emit_command(&mut client, beat).await?)?;
	hive.stop();

	assert_eq!(active, 1);
	Ok(())
}

/// The scaling cadence of the loaded hive, on its manual clock.
const SCALING_PERIOD: Duration = Duration::from_secs(5);

/// A gauge that reads full load, so the hive scales up the servlet that
/// holds it.
struct FullLoad;

impl UtilizationGauge for FullLoad {
	fn utilization(&self) -> BasisPoints {
		BasisPoints::MAX
	}
}

/// A gauge that reads no load, so the hive scales down the servlets that
/// hold it.
#[cfg(feature = "instrument")]
struct NoLoad;

#[cfg(feature = "instrument")]
impl UtilizationGauge for NoLoad {
	fn utilization(&self) -> BasisPoints {
		BasisPoints::MIN
	}
}

/// The configuration of a hive on `clock` that decides its scale once each
/// [`SCALING_PERIOD`].
fn scaling_conf(clock: &Arc<ManualClock>) -> HiveConfig {
	let mut conf = HiveConfig { clock: Arc::clone(clock) as Arc<dyn Clock>, ..Default::default() };
	conf.scaling.cooldown = SCALING_PERIOD;

	conf
}

/// Starts a servlet that reads `gauge` and records on `trace`.
async fn gauged_servlet(
	trace: &TraceCollector,
	gauge: Arc<dyn UtilizationGauge>,
) -> Result<HiveTestServlet, TightBeamError> {
	let builder = ServletConfig::<TokioListener, HiveTestRequest>::builder().with_utilization(gauge);
	HiveTestServlet::start(Arc::new(trace.share()), builder.allow_cleartext().build()).await
}

/// Starts a hive on `clock` with no control plane, whose one servlet holds a
/// [`FullLoad`] gauge, and which records on `trace`.
async fn start_loaded_hive(trace: &TraceCollector, clock: &Arc<ManualClock>) -> Result<HiveX509Test, TightBeamError> {
	let servlet = gauged_servlet(trace, Arc::new(FullLoad)).await?;

	let mut hive = HiveX509Test::new(Some(scaling_conf(clock)))?;
	hive.register(servlet_urn("loaded"), servlet, |t| {
		HiveTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// The scaling loop records each instance it adds, so the trail shows every
/// scale (CWE-778). Each poll moves the hive clock one scaling period.
#[tokio::test]
async fn a_scale_up_records_hive_scaled() -> Result<(), TightBeamError> {
	let trace = TraceCollector::new();
	let clock = Arc::new(ManualClock::default());
	let hive = start_loaded_hive(&trace, &clock).await?;

	let recorded = poll_until(100, Duration::from_millis(50), || {
		clock.advance(SCALING_PERIOD);
		trace.recorded(events::HIVE_SCALED) > 0
	})
	.await;
	hive.stop();

	assert!(recorded);
	Ok(())
}

/// The configuration of a serving hive on `clock` that decides its scale once
/// each [`SCALING_PERIOD`], and whose `gated` type holds two instances at most.
#[cfg(feature = "instrument")]
fn contended_conf(ctx: &TrustedSignerContext, clock: &Arc<ManualClock>) -> Result<HiveConfig, TightBeamError> {
	let bounds = ServletScaleConfig::new(1, 2, tightbeam::bps!(8000), tightbeam::bps!(2000));
	let bounds = bounds.expect("two instances is a legal range");
	let mut conf = serving_conf(ctx)?;
	conf.clock = Arc::clone(clock) as Arc<dyn Clock>;
	conf.scaling.cooldown = SCALING_PERIOD;
	conf.scaling.overrides.insert(servlet_urn("gated"), bounds);

	Ok(conf)
}

/// Starts a serving hive under `conf` whose `gated` servlet holds a
/// [`FullLoad`] gauge, and whose type spawns each instance only once `gate`
/// releases it. The hive records on `trace`.
#[cfg(feature = "instrument")]
async fn start_contended_hive(
	trace: &TraceCollector,
	conf: HiveConfig,
	gate: &SpawnGate,
) -> Result<HiveX509Test, TightBeamError> {
	let servlet = gauged_servlet(trace, Arc::new(FullLoad)).await?;

	let mut hive = HiveX509Test::new(Some(conf))?;
	let gate = gate.clone();
	hive.register(servlet_urn("gated"), servlet, move |t| {
		let gate = gate.clone();
		async move {
			gate.pass().await?;
			HiveTestServlet::start(t, ServletConfig::cleartext()).await
		}
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Moves `clock` one scaling period per poll until a scale-up waits at `gate`.
///
/// The wait is bounded, so a hive that starts no scale-up fails the test with
/// a message.
#[cfg(feature = "instrument")]
async fn scale_up_into(gate: &SpawnGate, clock: &ManualClock) -> Result<(), TightBeamError> {
	let waiting = poll_until(100, Duration::from_millis(50), || {
		clock.advance(SCALING_PERIOD);
		gate.is_entered()
	})
	.await;
	let unscaled = || expectation_failure("a loaded type below its bound scales up");

	waiting.then_some(()).ok_or_else(unscaled)
}

/// A scale-up that a spawn command beats to the bound of its type records its
/// refusal at capacity, so the trail shows a scale that added no instance
/// (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_scale_up_beaten_to_the_bound_records_hive_scale_refused() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive Scale Refused");
	let trace = TraceCollector::new();
	let clock = Arc::new(ManualClock::default());
	let gate = SpawnGate::default();
	let hive = start_contended_hive(&trace, contended_conf(&signer, &clock)?, &gate).await?;

	// 1. The command waits at the gate ahead of the scale-up, so the first
	//    permit lets the command alone through.
	let release_the_command = async {
		gate.entered_by(1).await?;
		scale_up_into(&gate, &clock).await?;
		gate.release(1);
		Ok::<(), TightBeamError>(())
	};
	let command = spawn_gated(&hive, &signer, b"spawn-ahead");
	let (spawned, ()) = tokio::try_join!(command, release_the_command)?;

	// 2. The command holds the last slot of the type, so the scale-up meets
	//    the bound.
	gate.release(1);
	let refused = || trace.recorded(events::HIVE_SCALE_REFUSED) > 0;
	let recorded = poll_until(100, Duration::from_millis(50), refused).await;
	hive.stop();

	let labels = recorded_labels(&trace, events::HIVE_SCALE_REFUSED);
	let at_capacity = (TransitStatus::Ok, true, vec![Some(String::from("AtCapacity"))]);
	assert_eq!((spawned, recorded, labels), at_capacity);
	Ok(())
}

/// Starts a hive on `clock` with no control plane, whose `idle` type holds
/// two servlets that read no load, and which records on `trace`.
#[cfg(feature = "instrument")]
async fn start_idle_hive(trace: &TraceCollector, clock: &Arc<ManualClock>) -> Result<HiveX509Test, TightBeamError> {
	let first = gauged_servlet(trace, Arc::new(NoLoad)).await?;
	let second = gauged_servlet(trace, Arc::new(NoLoad)).await?;
	let spawn = |t: Arc<TraceCollector>| HiveTestServlet::start(t, ServletConfig::cleartext());

	let mut hive = HiveX509Test::new(Some(scaling_conf(clock)))?;
	hive.register(servlet_urn("idle"), first, spawn)?;
	hive.register(servlet_urn("idle"), second, spawn)?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// The scaling loop records each instance it takes out of an idle type above
/// its floor, so the trail shows every scale (CWE-778). Each poll moves the
/// hive clock one scaling period.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_scale_down_records_hive_scaled_removed() -> Result<(), TightBeamError> {
	let trace = TraceCollector::new();
	let clock = Arc::new(ManualClock::default());
	let hive = start_idle_hive(&trace, &clock).await?;

	let recorded = poll_until(100, Duration::from_millis(50), || {
		clock.advance(SCALING_PERIOD);
		trace.recorded(events::HIVE_SCALED) > 0
	})
	.await;
	hive.stop();

	let labels = recorded_labels(&trace, events::HIVE_SCALED);
	assert_eq!((recorded, labels), (true, vec![Some(String::from("Removed"))]));
	Ok(())
}

/// The drain timeout of the gated hive, on its manual clock.
const GATED_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The two signals of a spawner that waits: the permit it adds when it starts,
/// and the permit it takes before its servlet starts. Permits add up, so one
/// gate holds any count of spawns.
#[derive(Clone)]
struct SpawnGate {
	entered: Arc<Semaphore>,
	release: Arc<Semaphore>,
}

impl Default for SpawnGate {
	fn default() -> Self {
		Self { entered: Arc::new(Semaphore::new(0)), release: Arc::new(Semaphore::new(0)) }
	}
}

impl SpawnGate {
	/// Waits at the gate, from inside a spawner, until the test releases it.
	async fn pass(&self) -> Result<(), TightBeamError> {
		self.entered.add_permits(1);
		let released = self.release.acquire().await;

		released.map(SemaphorePermit::forget).map_err(Self::closed)
	}

	/// Resolves once `spawns` spawners wait at the gate.
	async fn entered_by(&self, spawns: u32) -> Result<(), TightBeamError> {
		let entered = self.entered.acquire_many(spawns).await;

		entered.map(SemaphorePermit::forget).map_err(Self::closed)
	}

	/// Whether a spawner waits at the gate that no [`Self::entered_by`] has
	/// counted yet.
	#[cfg(feature = "instrument")]
	fn is_entered(&self) -> bool {
		self.entered.available_permits() > 0
	}

	/// The failure of a wait on a gate that closed.
	fn closed(_closed: AcquireError) -> TightBeamError {
		expectation_failure("a spawn gate stays open")
	}

	/// Lets `spawns` spawners that wait at the gate start their servlets.
	fn release(&self, spawns: usize) {
		self.release.add_permits(spawns);
	}
}

/// The configuration of a serving hive on `clock` that drains within
/// [`GATED_DRAIN_TIMEOUT`].
fn gated_drain_conf(ctx: &TrustedSignerContext, clock: &Arc<ManualClock>) -> Result<HiveConfig, TightBeamError> {
	let mut conf = serving_conf(ctx)?;
	conf.clock = Arc::clone(clock) as Arc<dyn Clock>;
	conf.control.drain_timeout = GATED_DRAIN_TIMEOUT;

	Ok(conf)
}

/// Starts a serving hive under `conf` whose `gated` type spawns each instance
/// only once `gate` releases it.
async fn start_gated_hive(conf: HiveConfig, gate: &SpawnGate) -> Result<HiveX509Test, TightBeamError> {
	let trace = Arc::new(TraceCollector::new());
	let servlet = HiveTestServlet::start(Arc::clone(&trace), ServletConfig::cleartext()).await?;

	let mut hive = HiveX509Test::new(Some(conf))?;
	let gate = gate.clone();
	hive.register(servlet_urn("gated"), servlet, move |t| {
		let gate = gate.clone();
		async move {
			gate.pass().await?;
			HiveTestServlet::start(t, ServletConfig::cleartext()).await
		}
	})?;
	hive.establish(trace).await?;
	Ok(hive)
}

/// Drains `hive` with a command in flight, and moves `clock` past the drain
/// timeout once the drain waits on it, so the drain aborts each registered
/// servlet and reports its deadline.
///
/// The wait for the drain to begin is bounded, so a hive that stays out of
/// drain fails the test with a message.
async fn drain_past_the_timeout(hive: &HiveX509Test, clock: &ManualClock) -> Result<(), TightBeamError> {
	let expire = async {
		let draining = poll_until(50, Duration::from_millis(100), || hive.is_draining()).await;
		let unbegun = || expectation_failure("the hive reports draining once its drain begins");
		draining.then_some(()).ok_or_else(unbegun)?;

		clock.advance(GATED_DRAIN_TIMEOUT);
		Ok::<(), TightBeamError>(())
	};

	let (drained, expired) = tokio::join!(hive.drain(), expire);
	expired?;

	let unreported = || expectation_failure("a drain past its timeout reports its deadline");
	let reported = matches!(
		drained,
		Err(TightBeamError::TransportError(TransportError::OperationFailed(
			TransportFailure::DeadlineExceeded
		)))
	);
	reported.then_some(()).ok_or_else(unreported)
}

/// A spawn whose spawner outlives the drain timeout lands in a drained hive,
/// which registers no servlet for it (CWE-362).
#[tokio::test]
async fn a_spawn_that_outlives_the_drain_timeout_registers_no_servlet() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive Late Spawn");
	let clock = Arc::new(ManualClock::default());
	let gate = SpawnGate::default();
	let hive = start_gated_hive(gated_drain_conf(&signer, &clock)?, &gate).await?;
	let mut client = connect_hive(&hive, &signer).await?;
	let spawn = signed_spawn_frame(&signer.identity, b"spawn-late", "gated").await?;
	let spawned = tokio::spawn(async move { emit_command(&mut client, spawn).await });

	gate.entered_by(1).await?;
	drain_past_the_timeout(&hive, &clock).await?;
	gate.release(1);

	let reply = spawned.await.map_err(|_| TightBeamError::JoinError)?;
	reply?;

	let registered = hive.servlet_addresses();
	hive.stop();
	assert!(registered.is_empty());
	Ok(())
}

/// Starts a serving hive whose `gated` type holds two instances at most, the
/// one it registers among them, and spawns each instance only once `gate`
/// releases it.
async fn start_gated_hive_short_of_its_bound(
	ctx: &TrustedSignerContext,
	gate: &SpawnGate,
) -> Result<HiveX509Test, TightBeamError> {
	let bounds = ServletScaleConfig::new(1, 2, tightbeam::bps!(8000), tightbeam::bps!(2000));
	let bounds = bounds.expect("two instances is a legal range");
	let mut conf = serving_conf(ctx)?;
	conf.scaling.overrides.insert(servlet_urn("gated"), bounds);

	start_gated_hive(conf, gate).await
}

/// Spawns one `gated` instance on `hive` as the context signer, on a
/// connection of its own, and returns the status of the reply.
async fn spawn_gated(
	hive: &HiveX509Test,
	signer: &TrustedSignerContext,
	id: impl AsRef<[u8]>,
) -> Result<TransitStatus, TightBeamError> {
	let mut client = connect_hive(hive, signer).await?;
	let spawn = signed_spawn_frame(&signer.identity, id, "gated").await?;
	manage_spawn_shape_status(emit_command(&mut client, spawn).await?)
}

/// Two spawns that overlap one short of the bound of their type admit one
/// instance and refuse the other at capacity, so the bound holds for commands
/// in flight together (CWE-362, CWE-770).
#[tokio::test]
async fn two_spawns_that_overlap_at_the_bound_admit_one() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive Overlapping Spawns");
	let gate = SpawnGate::default();
	let hive = start_gated_hive_short_of_its_bound(&signer, &gate).await?;
	let release_both = async {
		gate.entered_by(2).await?;
		gate.release(2);
		Ok::<(), TightBeamError>(())
	};

	let first = spawn_gated(&hive, &signer, b"spawn-first");
	let second = spawn_gated(&hive, &signer, b"spawn-second");
	let (first, second, ()) = tokio::try_join!(first, second, release_both)?;

	hive.stop();

	let statuses = [first, second];
	assert!(statuses.contains(&TransitStatus::Ok), "{statuses:?}");
	assert!(statuses.contains(&TransitStatus::ResourceExhausted), "{statuses:?}");
	Ok(())
}

/// The two signals of a spawner that holds its worker thread: the one it
/// sends when it starts, and the barrier it waits at before its servlet
/// starts.
///
/// The spawner blocks where a [`SpawnGate`] spawner awaits, so the control
/// task that runs it is mid-poll while the test drops the hive, and the abort
/// of the control plane lands once that poll ends.
#[derive(Clone)]
struct BlockingGate {
	entered: Arc<Notify>,
	release: Arc<Barrier>,
}

impl Default for BlockingGate {
	fn default() -> Self {
		Self { entered: Arc::default(), release: Arc::new(Barrier::new(2)) }
	}
}

/// Starts a serving hive whose `blocking` type spawns each instance behind
/// `gate`. Each instance it spawns records its stop on `stops`, and the
/// instance it registers records nothing.
async fn start_blocking_hive(
	ctx: &TrustedSignerContext,
	gate: &BlockingGate,
	stops: &TraceCollector,
) -> Result<HiveX509Test, TightBeamError> {
	let registered = LocatorStopProbe { trace: stops.share(), addr: b"127.0.0.1:7200".to_vec(), report_stop: false };
	let gate = gate.clone();
	let stops = stops.share();

	let mut hive = HiveX509Test::new(Some(serving_conf(ctx)?))?;
	hive.register(servlet_urn("blocking"), registered, move |_| {
		let gate = gate.clone();
		let trace = stops.share();
		async move {
			gate.entered.notify_one();
			gate.release.wait();
			Ok(LocatorStopProbe { trace, addr: b"127.0.0.1:7201".to_vec(), report_stop: true })
		}
	})?;
	hive.establish(Arc::new(TraceCollector::new())).await?;
	Ok(hive)
}

/// A spawn that lands after its hive drops registers no servlet, and the hive
/// stops the servlet that the spawner started (CWE-362, CWE-772).
///
/// The runtime has two workers, so the spawner holds one of them while the
/// test drops the hive on its own thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spawn_that_lands_after_the_hive_drops_registers_no_servlet() -> Result<(), TightBeamError> {
	let signer = trusted_signer("CN=Hive Dropped Spawn");
	let gate = BlockingGate::default();
	let stops = TraceCollector::new();
	let hive = start_blocking_hive(&signer, &gate, &stops).await?;
	let mut client = connect_hive(&hive, &signer).await?;
	let spawn = signed_spawn_frame(&signer.identity, b"spawn-dropped", "blocking").await?;
	// The drop of the hive ends the connection, so the stop of the servlet is
	// the observable and the reply goes unread.
	let _reply = tokio::spawn(async move { emit_command(&mut client, spawn).await });
	gate.entered.notified().await;

	drop(hive);
	gate.release.wait();

	let stopped = poll_until(50, Duration::from_millis(100), || stops.recorded(SERVLET_STOPPED) == 1).await;
	assert!(stopped, "the hive stops the servlet of a spawn that lands after its drop");
	Ok(())
}

/// A probe servlet with a caller-chosen locator. It emits [`SERVLET_STOPPED`]
/// on teardown when `report_stop` is set.
struct LocatorStopProbe {
	trace: TraceCollector,
	addr: Vec<u8>,
	report_stop: bool,
}

impl ServletBox for LocatorStopProbe {
	fn addr_bytes(&self) -> std::sync::Arc<[u8]> {
		std::sync::Arc::from(self.addr.as_slice())
	}

	fn stop_boxed(self: Box<Self>) {
		if self.report_stop {
			self.trace
				.event(SERVLET_STOPPED)
				.expect("recording the servlet stop is what this probe exists to do");
		}
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		None
	}
}

tb_assert_spec! {
	pub HiveSpawnNonUtf8Spec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

// The hive must refuse to register a manage spawn whose locator is not UTF-8,
// since its instance URN fails to build, and stop the orphan through
// `stop_boxed`. The seed holds a UTF-8 locator, so `register` succeeds.
tb_scenario! {
	name: hive_manage_spawn_non_utf8_stops_orphan,
	spec: HiveSpawnNonUtf8Spec,
	environment Hive {
		context: trusted_signer("CN=Hive Spawn NonUtf8"),
		start: |SetupEnv { trace, context: signer }| async move {
			let seed = LocatorStopProbe {
				trace: trace.share(),
				addr: b"127.0.0.1:0".to_vec(),
				report_stop: false,
			};

			let trust_store = pinning_trust_store(&signer.certificate)?;
			let conf = HiveConfig {
				trust_store: Some(trust_store),
				hive_tls: Some(Arc::new(signer.control_tls())),
				..Default::default()
			};

			let mut hive = HiveX509Test::new(Some(conf))?;
			hive.register(servlet_urn("orphan"), seed, |t| async move {
				Ok(LocatorStopProbe {
					trace: t.share(),
					addr: vec![0xff, 0xfe, 0xfd],
					report_stop: true,
				})
			})?;

			hive.establish(Arc::new(trace.share())).await?;
			Ok(hive)
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;
			let signed = signed_spawn_frame(&signer.identity, b"spawn-orphan", "orphan").await?;
			let response = emit_command(&mut client, signed).await?;
			let status = manage_spawn_shape_status(response)?;
			assert_eq!(status, TransitStatus::PermissionDenied, "the hive refuses a spawn it cannot name");

			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveDropStopsServletsSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

// A hive that drops without `stop`, as a scenario that panics drops it, must
// stop every registered servlet as `stop` does.
tb_scenario! {
	name: hive_drop_stops_registered_servlets,
	spec: HiveDropStopsServletsSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let registered = LocatorStopProbe {
				trace: trace.share(),
				addr: b"127.0.0.1:0".to_vec(),
				report_stop: true,
			};

			let mut hive = HiveX509Test::new(None)?;
			hive.register(servlet_urn("dropped"), registered, |t| async move {
				Ok(LocatorStopProbe {
					trace: t.share(),
					addr: b"127.0.0.1:0".to_vec(),
					report_stop: false,
				})
			})?;

			drop(hive);
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveRegisterStopsOneServletSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

// A registration whose type and address name an instance the hive holds
// replaces that instance, and the hive stops the replaced servlet through
// `stop_boxed`.
tb_scenario! {
	name: hive_register_stops_the_servlet_it_replaces,
	spec: HiveRegisterStopsOneServletSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let replaced = LocatorStopProbe {
				trace: trace.share(),
				addr: b"127.0.0.1:0".to_vec(),
				report_stop: true,
			};
			let replacing = LocatorStopProbe {
				trace: trace.share(),
				addr: b"127.0.0.1:0".to_vec(),
				report_stop: false,
			};
			let mut hive = HiveX509Test::new(None)?;
			hive.register(servlet_urn("replaced"), replaced, |t| async move {
				Ok(LocatorStopProbe { trace: t.share(), addr: b"127.0.0.1:0".to_vec(), report_stop: false })
			})?;

			hive.register(servlet_urn("replaced"), replacing, |t| async move {
				Ok(LocatorStopProbe { trace: t.share(), addr: b"127.0.0.1:0".to_vec(), report_stop: false })
			})?;

			hive.stop();
			Ok(())
		}
	}
}

// A registration that the hive refuses, here one that names an instance
// where a servlet type belongs, stops its servlet through `stop_boxed`.
tb_scenario! {
	name: hive_register_stops_the_servlet_it_refuses,
	spec: HiveRegisterStopsOneServletSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let refused = LocatorStopProbe {
				trace: trace.share(),
				addr: b"127.0.0.1:0".to_vec(),
				report_stop: true,
			};
			let instance = servlet_urn("refused").instance_urn(b"127.0.0.1:0")?;
			let mut hive = HiveX509Test::new(None)?;
			let registered = hive.register(instance, refused, |t| async move {
				Ok(LocatorStopProbe { trace: t.share(), addr: b"127.0.0.1:0".to_vec(), report_stop: false })
			});

			hive.stop();
			let refused_by_urn = matches!(registered, Err(TightBeamError::UrnValidationError(_)));
			assert!(refused_by_urn, "{registered:?}");
			Ok(())
		}
	}
}

pub(crate) const CONTRACT_FRAME_CLIENT_ID: Urn<'static> =
	tightbeam::urn!("test", "event:hive/contract-frame-client-id");
pub(crate) const CONTRACT_FRAME_SIGNED: Urn<'static> = tightbeam::urn!("test", "event:hive/contract-frame-signed");
pub(crate) const CONTRACT_FRAME_PREVIOUS: Urn<'static> = tightbeam::urn!("test", "event:hive/contract-frame-previous");
pub(crate) const CONTRACT_FRAME_SIG_VALID: Urn<'static> =
	tightbeam::urn!("test", "event:hive/contract-frame-sig-valid");

/// Returns the fixed contract key that the caller and the sibling servlet
/// share, so each side verifies the other's signature with no key
/// distribution.
fn contract_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::from(TestKey::insecure_fixed_signing())
}

/// Signs `frame` with the shared contract key under the canonical
/// SHA3-256 convention.
async fn sign_contract_frame(mut frame: Frame) -> Result<Frame, TightBeamError> {
	let identity = TestIdentity::of(&contract_signing_key());
	frame.sign_with_provider(&identity).await?;
	Ok(frame)
}

/// Whether the signature on `frame` verifies against the certificate of the
/// shared contract key. A verified signature proves byte fidelity end to end.
fn contract_signature_verifies(frame: &Frame) -> bool {
	let certificate = TestCertificate::self_signed(&contract_signing_key());
	let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer);
	let signer = signer.expect("the contract certificate asserts digitalSignature");
	frame.verify(&signer).is_ok()
}

servlet! {
	/// Records what it observes about the frame of an intra-hive call, and
	/// answers with a signed frame so the caller can verify the reply the same
	/// way.
	///
	/// The probes cover:
	///
	/// - the caller's frame id,
	/// - the nonrepudiation block,
	/// - the previous-frame linkage,
	/// - whether the caller's signature verifies over the received bytes.
	FrameContractServlet<HiveTestRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = ctx.trace();

		// The SIGNED and PREVIOUS probes witness presence only. Byte
		// fidelity rests on SIG_VALID, whose signature covers the frame's
		// to-be-signed bytes.
		let sig_valid = contract_signature_verifies(&frame);

		trace.event_with(CONTRACT_FRAME_CLIENT_ID, &[], u32::from(frame.metadata().id() == b"hive-signed-call"))?;
		trace.event_with(CONTRACT_FRAME_SIGNED, &[], u32::from(frame.nonrepudiation().is_some()))?;
		trace.event_with(CONTRACT_FRAME_PREVIOUS, &[], u32::from(frame.metadata().previous_frame().is_some()))?;
		trace.event_with(CONTRACT_FRAME_SIG_VALID, &[], u32::from(sig_valid))?;

		let unsigned = FrameBuilder::from(Version::V1)
			.with_id(b"hive-contract-reply")
			.with_message(HiveTestResponse { doubled: req.value * 2 })
			.build()?;

		Ok(Some(sign_contract_frame(unsigned).await?))
	}
}

/// Builds the contract-servlet TLS config so the hive pool can pin its
/// certificate.
fn contract_servlet_conf(
	materials: &ServerMaterials,
) -> Result<ServletConfig<TokioListener, HiveTestRequest>, TightBeamError> {
	let cert = CertificateSpec::Built(Box::new((*materials.certificate).to_owned()));
	let key = Arc::clone(&materials.key_provider);
	Ok(ServletConfig::<TokioListener, HiveTestRequest>::builder()
		.with_certificate(cert, key, vec![])?
		.with_mux_offer(Some(TransportOffer::mux(8)))
		.with_config(Arc::new(()))
		.build())
}

/// Starts an established hive on `trace` with one `FrameContractServlet`
/// sibling on `servlet_trace`. The intra-hive pool pins the servlet
/// certificate and offers mux.
async fn start_contract_hive(
	trace: TraceCollector,
	servlet_trace: TraceCollector,
	materials: &ServerMaterials,
) -> Result<HiveX509Test, TightBeamError> {
	let config = contract_servlet_conf(materials)?;
	let trace = Arc::new(trace);
	let servlet = FrameContractServlet::start(Arc::new(servlet_trace), config).await?;

	let trust_store = pinning_trust_store(&materials.certificate)?;
	let mut conf = HiveConfig { trust_store: Some(trust_store), ..Default::default() };
	conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(8)));

	let mut hive = HiveX509Test::new(Some(conf))?;
	hive.register(servlet_urn("contract"), servlet, |t| {
		FrameContractServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(trace).await?;
	Ok(hive)
}

tb_assert_spec! {
	pub HiveCallFrameDeliverySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(CONTRACT_FRAME_CLIENT_ID, exactly!(1), equals!(1u32)),
			(CONTRACT_FRAME_SIGNED, exactly!(1), equals!(1u32)),
			(CONTRACT_FRAME_PREVIOUS, exactly!(1), equals!(1u32)),
			(CONTRACT_FRAME_SIG_VALID, exactly!(1), equals!(1u32))
		]
	}
}

// The servlet's SIG_VALID probe and the client's check of the reply signature
// prove byte fidelity, because a signature verifies only over the bytes its
// signer signed.
tb_scenario! {
	name: hive_context_call_delivers_signed_frame,
	spec: HiveCallFrameDeliverySpec,
	environment Hive {
		context: ServerMaterials::generate(),
		start: |SetupEnv { trace, context: materials }| async move {
			start_contract_hive(trace.share(), trace, &materials).await
		},
		client: |HiveEnv { hive, .. }| async move {
			let unsigned = FrameBuilder::from(Version::V2)
				.with_id(b"hive-signed-call")
				.with_order(UnixMillis::now().get())
				.with_previous_hash(TestDigest::info())
				.with_message(HiveTestRequest { value: 21 })
				.build()?;

			let signed = sign_contract_frame(unsigned).await?;

			assert!(signed.nonrepudiation().is_some(), "the caller signs its frame");
			assert!(signed.metadata().previous_frame().is_some(), "the caller links its frame to a previous frame");

			// The surface under test is `HiveContext::call`. The caller's whole
			// signed frame goes out as composed, and the servlet's whole reply
			// frame comes back.
			let ctx = hive.context();
			let contract = servlet_urn("contract");
			let reply = ctx.call(&contract, signed).await?;

			assert_eq!(
				reply.metadata().id(),
				b"hive-contract-reply",
				"HiveContext::call returns the servlet's reply frame"
			);
			assert!(reply.nonrepudiation().is_some(), "the reply keeps the servlet's signature");
			assert!(
				contract_signature_verifies(&reply),
				"the reply signature verifies over the bytes the caller received"
			);

			let response: HiveTestResponse = decode(reply.message())?;
			assert_eq!(response.doubled, 42, "the contract servlet doubles 21");

			hive.stop();
			Ok(())
		}
	}
}

/// The events among `kept` that a hive records, in order, as its control
/// plane answers one unsigned heartbeat: the trail of its own trace, then of
/// its connection trace. The client dials with a default endpoint, so both
/// traces hold the hive's events alone.
async fn hive_trails(kept: &[Urn<'static>]) -> Result<(Vec<Urn<'static>>, Vec<Urn<'static>>), TightBeamError> {
	let trace = TraceCollector::new();
	let signer = trusted_signer("CN=Hive Trail Cluster");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await?;
	let connections = hive.connection_trace().ok_or(TightBeamError::NotEstablished)?.share();
	let mut client = connect_hive(&hive, &signer).await?;
	emit_command(&mut client, command_frame(b"hb-trail", heartbeat_command())?).await?;
	hive.stop();

	Ok((TestTrace::trail(&trace, kept), TestTrace::trail(&connections, kept)))
}

/// A hive's connection trace records the gate verdict of each command its
/// control plane answers, and the hive's own trace records none.
#[tokio::test]
async fn a_hive_records_the_gate_verdicts_of_its_control_plane_on_its_connection_trace() -> Result<(), TightBeamError> {
	let trails = hive_trails(&[events::GATE_ACCEPT, events::GATE_REJECT]).await?;
	assert_eq!(trails, (vec![], vec![events::GATE_ACCEPT]));
	Ok(())
}

/// A hive's own trace records its refusal of an unsigned command, and the
/// connection trace records the verdict of the transport gate that admitted
/// the frame.
#[tokio::test]
async fn a_hive_records_its_refusal_on_its_own_trace_apart_from_the_gate_verdict() -> Result<(), TightBeamError> {
	let trails = hive_trails(&[events::GATE_ACCEPT, events::HIVE_COMMAND_REFUSED]).await?;
	assert_eq!(trails, (vec![events::HIVE_COMMAND_REFUSED], vec![events::GATE_ACCEPT]));
	Ok(())
}

/// The [`events::HIVE_COMMAND_ACCEPTED`] records on a hive's own trace after
/// it carries out one spawn and one stop for `signer`, beside the instance the
/// two commands changed. The trace keeps the digest of each payload.
#[cfg(feature = "instrument")]
async fn carried_out_records(
	signer: &TrustedSignerContext,
) -> Result<(Vec<tightbeam::instrumentation::TbEvent>, Urn<'static>), TightBeamError> {
	let config = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let hive = start_serving_hive(&trace, signer).await?;
	let carried = spawn_and_stop(&hive, signer).await?;
	hive.stop();

	let recorded = trace.drain_events().into_iter();
	let accepted = recorded.filter(|event| event.urn == events::HIVE_COMMAND_ACCEPTED).collect();
	Ok((accepted, carried.instance))
}

/// A hive names each spawn and each stop it carries out by the command and
/// the instance it changed, so its trail shows which servlet started and
/// which stopped (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_names_each_command_it_carries_out() -> Result<(), TightBeamError> {
	let (records, instance) = carried_out_records(&trusted_signer("CN=Hive Carried Out Cluster")).await?;
	let labels: Vec<Option<String>> = records
		.into_iter()
		.map(|event| event.label.as_deref().map(String::from))
		.collect();
	assert_eq!(labels, [Some(format!("Spawn/{instance}")), Some(format!("Stop/{instance}"))]);
	Ok(())
}

/// A hive names the peer of each spawn and stop it carries out by the peer's
/// canonical key, so its trail shows who started and who stopped a servlet
/// (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_names_the_peer_of_each_command_it_carries_out() -> Result<(), TightBeamError> {
	use sha3::Digest;
	use tightbeam::crypto::x509::CanonicalKey;

	let signer = trusted_signer("CN=Hive Carried Out Peer");
	let key = CanonicalKey::of(&signer.certificate.tbs_certificate.subject_public_key_info)?;
	let expected: [u8; 32] = Sha3_256::digest(key.as_der()).into();

	let (records, _) = carried_out_records(&signer).await?;
	let payloads: Vec<Option<[u8; 32]>> = records.iter().map(|event| event.payload_hash).collect();
	assert_eq!(payloads, [Some(expected), Some(expected)]);
	Ok(())
}

/// The count of peers that fail the handshake of a hive's control plane, and
/// the bound of the hive's trace, in the test of that bound.
const REFUSED_PEERS: usize = 4;

/// Dials `hive` as `stranger`, a signer whose certificate the hive does not
/// pin, and sends one heartbeat. The client trusts the certificate of
/// `signer`, which the hive presents.
async fn dial_as_stranger(
	hive: &HiveX509Test,
	signer: &TrustedSignerContext,
	stranger: &TrustedSignerContext,
) -> Result<ClusterCommandResponse, TightBeamError> {
	let client = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(pinning_trust_store(&signer.certificate)?)
		.with_client_identity(stranger.identity.clone())
		.build();

	let addr = hive.addr().ok_or(TightBeamError::NotEstablished)?;
	let mut client = client.connect(addr.to_owned()).await?;
	emit_command(&mut client, command_frame(b"hb-stranger", heartbeat_command())?).await
}

/// What a hive records after [`REFUSED_PEERS`] strangers fail its
/// control-plane handshake and it records one event of its own: the hive's own
/// events its trace keeps, its overflow latch, and the count of refused
/// certificates on its connection trace. Each trace holds at most
/// [`REFUSED_PEERS`] events.
async fn hive_traces_after_refused_peers() -> Result<(Vec<Urn<'static>>, bool, usize), TightBeamError> {
	let config = TbInstrumentationConfig { max_events: REFUSED_PEERS as u32, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let signer = trusted_signer("CN=Hive Bound Cluster");
	let stranger = trusted_signer("CN=Hive Bound Stranger");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await?;
	let connections = hive.connection_trace().ok_or(TightBeamError::NotEstablished)?.share();
	// The start records into the trace, so a drain gives every slot to the
	// strangers. A drain keeps the latch.
	let _started = trace.drain_events();

	for _ in 0..REFUSED_PEERS {
		// The hive refuses the stranger's certificate, so the heartbeat fails
		// and the test reads the refusal from the trace.
		let _refused = dial_as_stranger(&hive, &signer, &stranger).await;
	}

	// A wait that runs out leaves the connection trace short of the
	// strangers, which the count of refused certificates then shows.
	let refused = || connections.recorded(events::SESSION_CERT_REJECTED) >= REFUSED_PEERS;
	poll_until(50, Duration::from_millis(100), refused).await;
	trace.emit_event(events::HIVE_REREGISTERED)?;
	hive.stop();

	let kept = TestTrace::trail(&trace, &[events::HIVE_REREGISTERED]);
	Ok((kept, trace.overflowed(), connections.recorded(events::SESSION_CERT_REJECTED)))
}

/// Peers that never authenticate record on a hive's connection trace, so the
/// hive's own bounded trace keeps its next event and sets no overflow latch.
#[tokio::test]
async fn refused_peers_leave_the_trace_of_a_hive_to_its_own_events() -> Result<(), TightBeamError> {
	let recorded = hive_traces_after_refused_peers().await?;
	assert_eq!(recorded, (vec![events::HIVE_REREGISTERED], false, REFUSED_PEERS));
	Ok(())
}

/// The count of commands that a client with no certificate sends to a hive,
/// and the bound of the hive's trace, in the test of that bound.
const ANONYMOUS_COMMANDS: usize = 4;

/// What a hive keeps after [`ANONYMOUS_COMMANDS`] anonymous heartbeats to a
/// control plane that demands no certificate, then one event of its own: its
/// own events in its trace's sink, the overflow latch, and the refusals.
async fn hive_traces_after_anonymous_commands() -> Result<(Vec<Urn<'static>>, bool, usize), TightBeamError> {
	let config = TbInstrumentationConfig { max_events: ANONYMOUS_COMMANDS as u32, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let signer = trusted_signer("CN=Hive Anonymous Cluster");
	let certificate = CertificateSpec::Built(Box::new(signer.certificate.to_owned()));
	let hive_tls = HiveTlsConfig::new(certificate, signer.identity.provider_arc(), PeerAuthentication::Anonymous)?;
	let mut hive = HiveX509Test::new(Some(HiveConfig { hive_tls: Some(Arc::new(hive_tls)), ..Default::default() }))?;
	hive.establish(Arc::new(trace.share())).await?;

	let connections = hive.connection_trace().ok_or(TightBeamError::NotEstablished)?.share();
	// The establish records into the trace, so a drain gives every slot to
	// the commands. A drain keeps the latch.
	let _started = trace.drain_events();

	let trust = pinning_trust_store(&signer.certificate)?;
	let client = ClientBuilder::<TokioListener>::builder().with_trust_store(trust).build();
	let addr = hive.addr().ok_or(TightBeamError::NotEstablished)?;
	let mut client = client.connect(addr.to_owned()).await?;
	for _ in 0..ANONYMOUS_COMMANDS {
		// The hive has no trust store, so it refuses each command.
		let _refused = emit_command(&mut client, command_frame(b"hb-anonymous", heartbeat_command())?).await;
	}

	trace.emit_event(events::HIVE_REREGISTERED)?;
	hive.stop();

	let kept = TestTrace::trail(&trace, &[events::HIVE_REREGISTERED]);
	Ok((kept, trace.overflowed(), connections.recorded(events::HIVE_COMMAND_REFUSED)))
}

/// Anonymous commands leave the bounded trace of a hive to its own events.
#[tokio::test]
async fn anonymous_commands_leave_the_trace_of_a_hive_to_its_own_events() -> Result<(), TightBeamError> {
	let recorded = hive_traces_after_anonymous_commands().await?;
	assert_eq!(recorded, (vec![events::HIVE_REREGISTERED], false, ANONYMOUS_COMMANDS));
	Ok(())
}

/// A sink that forwards each event, and names itself for each trace that
/// splits from its own.
#[cfg(feature = "instrument")]
#[derive(Clone, Default)]
struct Forwarded(Arc<std::sync::Mutex<Vec<Urn<'static>>>>);

#[cfg(feature = "instrument")]
impl Forwarded {
	/// The count of the forwarded events that record `event`.
	fn count(&self, event: Urn<'static>) -> usize {
		let seen = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		seen.iter().filter(|urn| **urn == event).count()
	}
}

#[cfg(feature = "instrument")]
impl tightbeam::instrumentation::EventSink for Forwarded {
	fn emit(&self, event: tightbeam::instrumentation::TbEvent) {
		let mut seen = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		seen.push(event.urn);
	}

	fn drain(&self) -> Vec<tightbeam::instrumentation::TbEvent> {
		Vec::new()
	}

	fn overflowed(&self) -> bool {
		false
	}

	fn sibling(&self) -> Option<Arc<dyn tightbeam::instrumentation::EventSink>> {
		Some(Arc::new(self.clone()))
	}
}

/// The accepted connections that reach the sink of a hive's trace as one
/// trusted signer sends a heartbeat.
#[cfg(feature = "instrument")]
async fn forwarded_connections_of_a_hive() -> Result<usize, TightBeamError> {
	let forwarded = Forwarded::default();
	let trace = TraceCollector::from(TraceConfig::default().with_sink(forwarded.clone()));
	let signer = trusted_signer("CN=Hive Forward Cluster");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await?;
	let mut client = connect_hive(&hive, &signer).await?;
	emit_command(&mut client, command_frame(b"hb-forward", heartbeat_command())?).await?;
	hive.stop();

	Ok(forwarded.count(events::CONNECTION_ACCEPTED))
}

/// A connection of a hive reaches the sink of the hive's trace (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_connection_reaches_the_sink_of_the_trace_of_the_hive() -> Result<(), TightBeamError> {
	assert_eq!(forwarded_connections_of_a_hive().await?, 1);
	Ok(())
}

/// The dials that a hive's own trace records as a caller reaches a sibling
/// servlet through the hive context. The servlet records into its own trace, so
/// the hive's trace holds the dials of its servlet pool alone.
async fn hive_sibling_dials() -> Result<Vec<Urn<'static>>, TightBeamError> {
	let trace = TraceCollector::new();
	let materials = ServerMaterials::generate();
	let hive = start_contract_hive(trace.share(), TraceCollector::new(), &materials).await?;
	let unsigned = FrameBuilder::from(Version::V2)
		.with_id(b"hive-pool-dial")
		.with_order(UnixMillis::now().get())
		.with_previous_hash(TestDigest::info())
		.with_message(HiveTestRequest { value: 21 })
		.build()?;

	let signed = sign_contract_frame(unsigned).await?;

	hive.context().call(&servlet_urn("contract"), signed).await?;
	hive.stop();

	Ok(TestTrace::trail(&trace, &[events::POOL_DIAL]))
}

/// A hive records each dial of its servlet pool on its own trace, the trace
/// it establishes with.
#[tokio::test]
async fn a_hive_records_the_dials_of_its_servlet_pool_on_its_own_trace() -> Result<(), TightBeamError> {
	assert_eq!(hive_sibling_dials().await?, [events::POOL_DIAL]);
	Ok(())
}
