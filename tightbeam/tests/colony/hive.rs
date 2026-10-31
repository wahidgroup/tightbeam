//! The integration tests of the Hive with X.509 certificates.
//!
//! They drive the Hive lifecycle through its public interface, over TLS.

use core::time::Duration;
use std::sync::{Arc, Barrier};

use tokio::sync::{Notify, Semaphore};

use tightbeam::basis_points::BasisPoints;
use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::{CheckDigestOid, TypeBuilder};
use tightbeam::clock::{Clock, ManualClock, UnixMillis};
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::hive::{Hive, HiveConfig, HiveTlsConfig, ServletBox, ServletScaleConfig};
use tightbeam::colony::protocol::{
	ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, HiveManagement, HiveManagementOutcome,
	ListServletsParams, SpawnServletParams, StopServletParams,
};
use tightbeam::colony::servlet::ServletConfig;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::{Certificate, CertificateSpec, KeyPurposes, PeerCertificate, Signing};
use tightbeam::der::Sequence;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::{HiveEnv, SetupEnv, TestCertificate, TestDigest, TestIdentity, TestKey};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, GenericClient, Protocol, TransportError, TransportFailure,
};
use tightbeam::urn::Urn;
use tightbeam::{
	absent, compose, exactly, hive, servlet, tb_assert_spec, tb_scenario, Beamable, Frame, Message, TightBeamError,
	Version,
};

#[cfg(feature = "instrument")]
use tightbeam::colony::servlet::UtilizationGauge;

use crate::common::hive::{anonymous_hive_tls, servlet_urn};
use crate::common::poll::{joined, poll_until};
use crate::common::result::TestResult;
use crate::common::security::{
	combined_trust, expectation_failure, pinning_trust_store, pinning_validator, ServerMaterials,
};
use crate::common::x509::create_test_cert_with_key;

#[cfg(feature = "instrument")]
use crate::colony::trace::{bounded_trace, payload_digests, payload_trace, session_digest, TraceWaiter};
#[cfg(feature = "instrument")]
use crate::colony::tracker_at;
#[cfg(feature = "instrument")]
use crate::common::clock::ParkingClock;
#[cfg(feature = "instrument")]
use crate::common::poll::within_hang_guard;
#[cfg(feature = "instrument")]
use crate::common::trace::recorded_labels;

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

/// The [`anonymous_hive_tls`] of a fresh `CN=Hive Test Server` certificate.
fn hive_tls() -> HiveTlsConfig {
	let (cert, signing_key) = create_test_cert_with_key("CN=Hive Test Server", 365).expect("hive TLS material");
	anonymous_hive_tls(TestIdentity::presenting(cert, &signing_key))
}

// A hive with X.509 material serves a control plane under its certificate, so
// a client that trusts the certificate completes the handshake and reads the
// count of the hive's servlets from a signed heartbeat.
tb_scenario! {
	name: hive_establish_with_x509,
	spec: HiveEstablishSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Test Server"),
		start: |SetupEnv { trace, context: signer }| async move {
			let mut conf = serving_conf(&signer)?;
			conf.pool.mux_offer = Some(Arc::new(TransportOffer::mux(4)));
			start_serving_hive_under(&trace, conf).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;
			let beat = signed_heartbeat_frame(&signer.identity, b"hb-x509").await?;

			let answer = emit_command(&mut client, beat).await?;
			hive.stop();
			assert_eq!(heartbeat_capacity(answer), (TransitStatus::Ok, 1));
			Ok(())
		}
	}
}

/// A trace that refuses `HIVE_ESTABLISHED` fails the establish before the
/// control plane serves. The hive stays provisional with no address, and a
/// later establish on a trace that records the event succeeds.
#[cfg(feature = "testing-fault")]
#[tokio::test]
async fn a_refused_established_event_leaves_the_hive_provisional() -> TestResult {
	use tightbeam::testing::FaultModel;

	let refused = || TightBeamError::ChannelClosed;
	let model = FaultModel::default().with_event_fault(events::HIVE_ESTABLISHED, refused, tightbeam::bps!(10000));
	let refusing = Arc::new(TraceCollector::new().with_fault_model(model));
	let mut hive = HiveX509Test::new(Some(HiveConfig { hive_tls: Some(Arc::new(hive_tls())), ..Default::default() }))?;

	let first = hive.establish(refusing).await;
	let unbound = hive.addr().is_none();
	let second = hive.establish(Arc::new(TraceCollector::new())).await;
	hive.stop();

	assert!(matches!(
		(first, unbound, second),
		(Err(TightBeamError::ChannelClosed), true, Ok(()))
	));
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

/// A [`command_frame_with_order`] frame issued at the time of the call.
///
/// # Errors
///
/// - [`TightBeamError`] -- the frame fails to build.
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
		let anchor = pinning_validator(&self.certificate);

		let authentication = PeerAuthentication::Anonymous.and(anchor);
		let tls = HiveTlsConfig::from_identity(self.identity.clone(), authentication, KeyPurposes::HOUSE);
		tls.expect("a fixture certificate admits the house signer purpose")
	}
}

/// A [`TrustedSignerContext`] on a fresh key, whose certificate names
/// `subject`.
fn trusted_signer(subject: impl AsRef<str>) -> TrustedSignerContext {
	let subject = subject.as_ref();
	let (certificate, signing_key) = create_test_cert_with_key(subject, 365).expect("signer material");
	let identity = TestIdentity::presenting(certificate.to_owned(), &signing_key);
	TrustedSignerContext { certificate, identity }
}

/// Starts an established hive with the context signer pinned in its trust
/// store.
async fn start_trusted_hive(
	trace: &TraceCollector,
	ctx: &TrustedSignerContext,
	mut conf: HiveConfig,
) -> Result<HiveX509Test, TightBeamError> {
	conf.trust_store = Some(combined_trust(&[&ctx.certificate]));
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
	connect_hive_as(hive, ctx, ctx).await
}

/// Dials the hive control plane, which presents the certificate of
/// `trusted`, with a client that presents the identity of `presenting`.
async fn connect_hive_as(
	hive: &HiveX509Test,
	trusted: &TrustedSignerContext,
	presenting: &TrustedSignerContext,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	let client = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(combined_trust(&[&trusted.certificate]))
		.with_client_identity(presenting.identity.clone())
		.build();

	let addr = hive.addr().ok_or(TightBeamError::NotEstablished)?;
	Ok(client.connect(addr.to_owned()).await?)
}

/// Emits the command `frame` through `client`, and returns the answer of the
/// hive.
///
/// # Errors
///
/// - [`TightBeamError::TransportError`] -- the emit fails.
/// - [`TightBeamError::MissingResponse`] -- the hive answers with no frame.
/// - The errors of [`Frame::decode_message`] -- the reply does not decode as a [`ClusterCommandResponse`].
async fn emit_command(
	client: &mut GenericClient<TokioListener>,
	frame: Frame,
) -> Result<ClusterCommandResponse, TightBeamError> {
	let response = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
	response.decode_message()
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

/// The status and the count of servlets that a heartbeat reply reports. The
/// reply names the heartbeat alternative.
fn heartbeat_capacity(response: ClusterCommandResponse) -> (TransitStatus, u32) {
	let ClusterCommandResponse::Heartbeat(heartbeat) = response else {
		panic!("a heartbeat reply names the heartbeat alternative");
	};

	(heartbeat.status, heartbeat.active_servlets)
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

/// Signs a command frame of [`heartbeat_command`] with `identity`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the frame fails to build or to sign.
async fn signed_heartbeat_frame(identity: &SigningIdentity, id: impl AsRef<[u8]>) -> Result<Frame, TightBeamError> {
	let id = id.as_ref();
	let mut frame = command_frame(id, heartbeat_command())?;
	frame.sign_with_provider(identity).await?;
	Ok(frame)
}

/// A heartbeat that carries the signature of another heartbeat of `identity`.
/// A trusted signer's signature transplanted from another frame is the one
/// failure class that the breaker of a hive counts.
///
/// # Errors
///
/// - [`TightBeamError`] -- a frame fails to build or to sign.
async fn transplanted_heartbeat_frame(identity: &SigningIdentity) -> Result<Frame, TightBeamError> {
	let now = UnixMillis::now();
	let mut donor = command_frame_with_order(b"hb-donor", heartbeat_command(), now.get())?;
	donor.sign_with_provider(identity).await?;

	let transplanted = donor.nonrepudiation().cloned().ok_or(TightBeamError::MissingSignature)?;
	let forged_order = now.saturating_add(Duration::from_millis(1)).get();
	let mut forged = command_frame_with_order(b"hb-forged", heartbeat_command(), forged_order)?;
	forged.attach_signer_info(transplanted)?;
	Ok(forged)
}

/// Signs a [`stop_command_frame`] with `identity`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the frame fails to build or to sign.
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

/// Signs a [`spawn_command_frame`] of `servlet_type` with `identity`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the frame fails to build or to sign.
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

/// Signs a [`stop_instance_frame`] of `servlet_id` with `identity`.
///
/// # Errors
///
/// - [`TightBeamError`] -- the frame fails to build or to sign.
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
	let trust_store = Some(combined_trust(&[&ctx.certificate]));
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
			let mut conf = serving_conf(&signer)?;
			conf.control.circuit_breaker_threshold = 1;
			conf.control.circuit_breaker_cooldown = Duration::from_secs(60);
			start_serving_hive_under(&trace, conf).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;

			// An unsigned heartbeat must come back in the heartbeat CHOICE
			// with no capacity data before authentication. The hive holds one
			// servlet, so a reply that leaks its capacity counts that servlet.
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

			// The hive must accept a signed heartbeat end to end, and the reply
			// counts the servlet that the refusal above hides.
			let signed_heartbeat = signed_heartbeat_frame(&signer.identity, b"hb-signed").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			assert_eq!(heartbeat_capacity(response), (TransitStatus::Ok, 1));

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

			// Trip the breaker at threshold 1.
			let forged = transplanted_heartbeat_frame(&signer.identity).await?;
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
	pub HiveOpenBreakerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::HIVE_COMMAND_REFUSED, exactly!(2), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// An open breaker refuses a valid heartbeat with no capacity data. The hive
// holds its one servlet throughout, and the heartbeat ahead of the breaker
// counts that servlet, so a refusal that leaks its capacity shows the count.
tb_scenario! {
	name: an_open_breaker_seals_the_capacity_of_a_serving_hive,
	spec: HiveOpenBreakerSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Sealed Breaker"),
		start: |SetupEnv { trace, context: signer }| async move {
			let mut conf = serving_conf(&signer)?;
			conf.control.circuit_breaker_threshold = 1;
			conf.control.circuit_breaker_cooldown = Duration::from_secs(60);
			start_serving_hive_under(&trace, conf).await
		},
		client: |HiveEnv { context: signer, hive, .. }| async move {
			let mut client = connect_hive(&hive, &signer).await?;
			let beat = signed_heartbeat_frame(&signer.identity, b"hb-closed").await?;
			let answered = emit_command(&mut client, beat).await?;
			let forged = transplanted_heartbeat_frame(&signer.identity).await?;
			emit_command(&mut client, forged).await?;

			let sealed = signed_heartbeat_frame(&signer.identity, b"hb-sealed").await?;
			let response = emit_command(&mut client, sealed).await?;
			hive.stop();
			assert_eq!(heartbeat_capacity(answered), (TransitStatus::Ok, 1));
			assert_eq!(heartbeat_shape_status(response, true)?, TransitStatus::PermissionDenied);
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
			let mut conf = serving_conf(&signer)?;
			conf.control.backpressure_threshold = BasisPoints::default();

			start_serving_hive_under(&trace, conf).await
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
			// in the heartbeat CHOICE with the count of its servlets, and the
			// ResourceExhausted status reflects saturation.
			let signed_heartbeat = signed_heartbeat_frame(&signer.identity, b"hb-bp").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			assert_eq!(heartbeat_capacity(response), (TransitStatus::ResourceExhausted, 1));

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
async fn a_provisional_hive_refuses_to_register() -> TestResult {
	let hive = HiveX509Test::new(None)?;
	let cluster_addr: <TokioListener as Protocol>::Address = "127.0.0.1:9".parse()?;
	let refused = hive.register_with_cluster(&cluster_addr).await;
	hive.stop();

	assert!(matches!(refused, Err(TightBeamError::NotEstablished)));
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
async fn start_single_instance_hive(ctx: &TrustedSignerContext) -> HiveX509Test {
	let bounds = ServletScaleConfig::new(1, 1, tightbeam::bps!(8000), tightbeam::bps!(2000));
	let bounds = bounds.expect("one instance is a legal range");
	let mut conf = serving_conf(ctx).expect("a fixture signer pins in a trust store");
	conf.scaling.overrides.insert(servlet_urn("test_servlet"), bounds);

	let hive = start_serving_hive_under(&TraceCollector::new(), conf).await;
	hive.expect("a serving hive establishes")
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
async fn a_manage_spawn_past_max_instances_is_refused_at_capacity() -> TestResult {
	let signer = trusted_signer("CN=Hive At Capacity");
	let hive = start_single_instance_hive(&signer).await;
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
async fn a_manage_stop_under_min_instances_is_refused() -> TestResult {
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
///
/// A house servlet reports itself healthy while it serves, so this box stands
/// in for one that reports itself unhealthy.
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
async fn start_hive_with_an_unhealthy_servlet(ctx: &TrustedSignerContext) -> HiveX509Test {
	let trace = TraceCollector::new();
	let servlet = HiveTestServlet::start(Arc::new(trace.share()), ServletConfig::cleartext()).await;
	let servlet = servlet.expect("a cleartext servlet starts on a free port");

	let conf = serving_conf(ctx).expect("a fixture signer pins in a trust store");
	let mut hive = HiveX509Test::new(Some(conf)).expect("a hive on fixture TLS builds");
	let registered = hive.register(servlet_urn("test_servlet"), servlet, |t| {
		HiveTestServlet::start(t, ServletConfig::cleartext())
	});
	registered.expect("a fresh hive registers its first servlet");
	let registered = hive.register(servlet_urn("unhealthy"), UnhealthyServlet, |_| async { Ok(UnhealthyServlet) });
	registered.expect("a hive registers a servlet of a second type");

	let established = hive.establish(Arc::new(trace.share())).await;
	established.expect("a hive establishes on a free port");
	hive
}

/// The count of servlets that a heartbeat reply reports. The reply names the
/// heartbeat alternative.
fn heartbeat_active_servlets(response: ClusterCommandResponse) -> u32 {
	let (_status, active_servlets) = heartbeat_capacity(response);
	active_servlets
}

/// A heartbeat counts the servlets that report themselves healthy, so a
/// gateway reads the capacity that serves.
#[tokio::test]
async fn a_heartbeat_counts_only_the_servlets_that_report_healthy() -> TestResult {
	let signer = trusted_signer("CN=Hive Healthy Count");
	let hive = start_hive_with_an_unhealthy_servlet(&signer).await;
	let mut client = connect_hive(&hive, &signer).await?;

	let beat = signed_heartbeat_frame(&signer.identity, b"beat-healthy-count").await?;
	let active = heartbeat_active_servlets(emit_command(&mut client, beat).await?);
	hive.stop();

	assert_eq!(active, 1);
	Ok(())
}

/// The scaling cadence of a gauged hive, on its manual clock. The scaling
/// loop is the one loop of a hive that sleeps for this span, so a wait for a
/// sleep of it waits for the scaling loop.
#[cfg(feature = "instrument")]
const SCALING_PERIOD: Duration = Duration::from_secs(7);

/// The configuration of a hive on `clock` that decides its scale once each
/// [`SCALING_PERIOD`].
#[cfg(feature = "instrument")]
fn scaling_conf(clock: &Arc<ParkingClock>) -> HiveConfig {
	let mut conf = HiveConfig { clock: Arc::clone(clock) as Arc<dyn Clock>, ..Default::default() };
	conf.scaling.cooldown = SCALING_PERIOD;
	conf
}

/// Starts a servlet that reads `gauge` and records on `trace`.
#[cfg(feature = "instrument")]
async fn gauged_servlet(trace: &TraceCollector, gauge: Arc<dyn UtilizationGauge>) -> HiveTestServlet {
	let builder = ServletConfig::<TokioListener, HiveTestRequest>::builder().with_utilization(gauge);
	let servlet = HiveTestServlet::start(Arc::new(trace.share()), builder.allow_cleartext().build()).await;
	servlet.expect("a cleartext servlet starts on a free port")
}

/// Starts a hive on `clock` with no control plane, whose `gauged` type holds
/// two servlets that read `load`, and which records on `trace`.
#[cfg(feature = "instrument")]
async fn start_gauged_hive(trace: &TraceCollector, clock: &Arc<ParkingClock>, load: BasisPoints) -> HiveX509Test {
	let first = gauged_servlet(trace, tracker_at(load)).await;
	let second = gauged_servlet(trace, tracker_at(load)).await;
	let spawn = |t: Arc<TraceCollector>| HiveTestServlet::start(t, ServletConfig::cleartext());

	let mut hive = HiveX509Test::new(Some(scaling_conf(clock))).expect("a hive with no control plane builds");
	let registered = hive.register(servlet_urn("gauged"), first, spawn);
	registered.expect("a fresh hive registers its first servlet");
	let registered = hive.register(servlet_urn("gauged"), second, spawn);
	registered.expect("a hive registers a second instance of a type");

	hive.establish(Arc::new(trace.share())).await.expect("a hive establishes");
	hive
}

/// Lets the scaling loop of a hive on `clock` evaluate once, and returns once
/// the loop sleeps again, so the evaluation has ended.
#[cfg(feature = "instrument")]
async fn scale_once(clock: &ParkingClock) {
	clock.parked(SCALING_PERIOD).await;
	clock.advance(SCALING_PERIOD);
	clock.parked(SCALING_PERIOD).await;
}

// The scaling loop records each instance it adds to a loaded type, and each
// instance it takes out of an idle type above its floor, so the trail shows
// every scale (CWE-778).
#[cfg(feature = "instrument")]
tightbeam::tb_cases! {
	async fn a_scale_records_hive_scaled((load, label): (BasisPoints, &str)) {
		let trace = TraceCollector::new();
		let clock = Arc::new(ParkingClock::default());
		let hive = start_gauged_hive(&trace, &clock, load).await;

		scale_once(&clock).await;
		hive.stop();

		let labels = recorded_labels(&trace, events::HIVE_SCALED);
		assert_eq!(labels, [Some(String::from(label))]);
	}
	cases {
		added_under_full_load => (BasisPoints::MAX, "Added"),
		removed_under_no_load => (BasisPoints::MIN, "Removed"),
	}
}

/// The configuration of a serving hive on `clock` that decides its scale once
/// each [`SCALING_PERIOD`], and whose `gated` type holds two instances at most.
/// The re-announce beat of its control plane is off, so the scaling loop is
/// the one beat on `clock`.
#[cfg(feature = "instrument")]
fn contended_conf(ctx: &TrustedSignerContext, clock: &Arc<ParkingClock>) -> HiveConfig {
	let bounds = ServletScaleConfig::new(1, 2, tightbeam::bps!(8000), tightbeam::bps!(2000));
	let bounds = bounds.expect("two instances is a legal range");
	let mut conf = serving_conf(ctx).expect("a fixture signer pins in a trust store");
	conf.clock = Arc::clone(clock) as Arc<dyn Clock>;
	conf.control.reregister_interval = None;
	conf.scaling.cooldown = SCALING_PERIOD;
	conf.scaling.overrides.insert(servlet_urn("gated"), bounds);
	conf
}

/// Starts a serving hive under `conf` whose `gated` servlet reads full load,
/// and whose type spawns each instance only once `gate` releases it. The hive
/// records on `trace`.
#[cfg(feature = "instrument")]
async fn start_contended_hive(trace: &TraceCollector, conf: HiveConfig, gate: &SpawnGate) -> HiveX509Test {
	let servlet = gauged_servlet(trace, tracker_at(BasisPoints::MAX)).await;
	let mut hive = HiveX509Test::new(Some(conf)).expect("a hive on fixture TLS builds");
	let gate = gate.clone();
	let registered = hive.register(servlet_urn("gated"), servlet, move |t| {
		let gate = gate.clone();
		async move {
			gate.pass().await;
			HiveTestServlet::start(t, ServletConfig::cleartext()).await
		}
	});
	registered.expect("a fresh hive registers its first servlet");

	let established = hive.establish(Arc::new(trace.share())).await;
	established.expect("a hive establishes on a free port");

	hive
}

/// Moves `clock` one scaling period once the scaling loop sleeps on it, and
/// waits until the scale-up that the period starts waits at `gate`.
///
/// The wait is bounded, so a hive that starts no scale-up fails the test.
#[cfg(feature = "instrument")]
async fn scale_up_into(gate: &SpawnGate, clock: &ParkingClock) {
	clock.parked(SCALING_PERIOD).await;
	clock.advance(SCALING_PERIOD);

	let entered = gate.entered_by(1);
	within_hang_guard(entered, "a loaded type below its bound scales up within the hang guard").await;
}

/// A scale-up that a spawn command beats to the bound of its type records its
/// refusal at capacity, so the trail shows a scale that added no instance
/// (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_scale_up_beaten_to_the_bound_records_hive_scale_refused() {
	let signer = trusted_signer("CN=Hive Scale Refused");
	let (trace, waiter) = TraceWaiter::trace();
	let clock = Arc::new(ParkingClock::default());
	let gate = SpawnGate::default();
	let hive = start_contended_hive(&trace, contended_conf(&signer, &clock), &gate).await;

	// 1. The command waits at the gate ahead of the scale-up, so the first
	//    permit lets the command alone through.
	let release_the_command = async {
		gate.entered_by(1).await;
		scale_up_into(&gate, &clock).await;
		gate.release(1);
	};
	let command = spawn_gated(&hive, &signer, b"spawn-ahead");
	let (spawned, ()) = tokio::join!(command, release_the_command);

	// 2. The command holds the last slot of the type, so the scale-up meets
	//    the bound.
	gate.release(1);
	let recorded = waiter.until(events::HIVE_SCALE_REFUSED, 1).await;
	hive.stop();

	let labels = recorded_labels(&trace, events::HIVE_SCALE_REFUSED);
	let at_capacity = (TransitStatus::Ok, true, vec![Some(String::from("AtCapacity"))]);
	assert_eq!((spawned, recorded, labels), at_capacity);
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
	async fn pass(&self) {
		self.entered.add_permits(1);
		let released = self.release.acquire().await;
		released.expect("a spawn gate stays open").forget();
	}

	/// Resolves once `spawns` spawners wait at the gate.
	async fn entered_by(&self, spawns: u32) {
		let entered = self.entered.acquire_many(spawns).await;
		entered.expect("a spawn gate stays open").forget();
	}

	/// Lets `spawns` spawners that wait at the gate start their servlets.
	fn release(&self, spawns: usize) {
		self.release.add_permits(spawns);
	}
}

/// The configuration of a serving hive on `clock` that drains within
/// [`GATED_DRAIN_TIMEOUT`].
fn gated_drain_conf(ctx: &TrustedSignerContext, clock: &Arc<ManualClock>) -> HiveConfig {
	let mut conf = serving_conf(ctx).expect("a fixture signer pins in a trust store");
	conf.clock = Arc::clone(clock) as Arc<dyn Clock>;
	conf.control.drain_timeout = GATED_DRAIN_TIMEOUT;

	conf
}

/// Starts a serving hive under `conf` whose `gated` type spawns each instance
/// only once `gate` releases it.
async fn start_gated_hive(conf: HiveConfig, gate: &SpawnGate) -> HiveX509Test {
	let trace = Arc::new(TraceCollector::new());
	let servlet = HiveTestServlet::start(Arc::clone(&trace), ServletConfig::cleartext()).await;
	let servlet = servlet.expect("a cleartext servlet starts on a free port");

	let mut hive = HiveX509Test::new(Some(conf)).expect("a hive on fixture TLS builds");
	let gate = gate.clone();
	let registered = hive.register(servlet_urn("gated"), servlet, move |t| {
		let gate = gate.clone();
		async move {
			gate.pass().await;
			HiveTestServlet::start(t, ServletConfig::cleartext()).await
		}
	});
	registered.expect("a fresh hive registers its first servlet");

	hive.establish(trace).await.expect("a hive establishes on a free port");
	hive
}

/// Drains `hive` with a command in flight, moves `clock` past the drain
/// timeout once the drain waits on it, and returns the outcome of the drain.
///
/// The event list holds no event for the start of a drain, so a bounded poll
/// of the drain mode of the hive waits for that start. A hive that stays out
/// of drain fails the test.
async fn drain_past_the_timeout(hive: &HiveX509Test, clock: &ManualClock) -> Result<(), TightBeamError> {
	let expire = async {
		let draining = poll_until(50, Duration::from_millis(100), || hive.is_draining()).await;
		draining.then_some(()).expect("the hive reports draining once its drain begins");

		clock.advance(GATED_DRAIN_TIMEOUT);
	};

	let (drained, ()) = tokio::join!(hive.drain(), expire);
	drained
}

/// A spawn whose spawner outlives the drain timeout lands in a drained hive,
/// which reports its deadline and registers no servlet for the spawn
/// (CWE-362).
#[tokio::test]
async fn a_spawn_that_outlives_the_drain_timeout_registers_no_servlet() -> TestResult {
	let signer = trusted_signer("CN=Hive Late Spawn");
	let clock = Arc::new(ManualClock::default());
	let gate = SpawnGate::default();
	let hive = start_gated_hive(gated_drain_conf(&signer, &clock), &gate).await;
	let mut client = connect_hive(&hive, &signer).await?;
	let spawn = signed_spawn_frame(&signer.identity, b"spawn-late", "gated").await?;
	let spawned = tokio::spawn(async move { emit_command(&mut client, spawn).await });

	gate.entered_by(1).await;
	let drained = drain_past_the_timeout(&hive, &clock).await;
	gate.release(1);

	joined(spawned).await?;

	let registered = hive.servlet_addresses();

	hive.stop();

	let deadline = matches!(
		drained,
		Err(TightBeamError::TransportError(TransportError::OperationFailed(
			TransportFailure::DeadlineExceeded
		)))
	);
	assert_eq!((deadline, registered), (true, Vec::new()));
	Ok(())
}

/// Starts a serving hive whose `gated` type holds two instances at most, the
/// one it registers among them, and spawns each instance only once `gate`
/// releases it.
async fn start_gated_hive_short_of_its_bound(ctx: &TrustedSignerContext, gate: &SpawnGate) -> HiveX509Test {
	let bounds = ServletScaleConfig::new(1, 2, tightbeam::bps!(8000), tightbeam::bps!(2000));
	let bounds = bounds.expect("two instances is a legal range");
	let mut conf = serving_conf(ctx).expect("a fixture signer pins in a trust store");
	conf.scaling.overrides.insert(servlet_urn("gated"), bounds);

	start_gated_hive(conf, gate).await
}

/// Spawns one `gated` instance on `hive` as the context signer, on a
/// connection of its own, and returns the status of the reply.
async fn spawn_gated(hive: &HiveX509Test, signer: &TrustedSignerContext, id: impl AsRef<[u8]>) -> TransitStatus {
	let mut client = connect_hive(hive, signer).await.expect("a trusted signer connects to its hive");
	let spawn = signed_spawn_frame(&signer.identity, id, "gated").await;
	let spawn = spawn.expect("a spawn frame signs");
	let reply = emit_command(&mut client, spawn).await.expect("the hive answers a spawn");
	manage_spawn_shape_status(reply).expect("a spawn reply names the spawn alternative")
}

/// `statuses` in the order of their wire values, so a test compares them as
/// an unordered pair.
fn by_wire_value(mut statuses: [TransitStatus; 2]) -> [TransitStatus; 2] {
	statuses.sort_by_key(|status| *status as u8);
	statuses
}

/// Two spawns that overlap one short of the bound of their type admit one
/// instance and refuse the other at capacity, so the bound holds for commands
/// in flight together (CWE-362, CWE-770). Either spawn may win.
#[tokio::test]
async fn two_spawns_that_overlap_at_the_bound_admit_one() {
	let signer = trusted_signer("CN=Hive Overlapping Spawns");
	let gate = SpawnGate::default();
	let hive = start_gated_hive_short_of_its_bound(&signer, &gate).await;
	let release_both = async {
		gate.entered_by(2).await;
		gate.release(2);
	};

	let first = spawn_gated(&hive, &signer, b"spawn-first");
	let second = spawn_gated(&hive, &signer, b"spawn-second");
	let (first, second, ()) = tokio::join!(first, second, release_both);

	hive.stop();

	let statuses = by_wire_value([first, second]);
	assert_eq!(statuses, [TransitStatus::Ok, TransitStatus::ResourceExhausted]);
}

/// The two signals of a spawner that holds its worker thread: the one it
/// sends when it starts, and the barrier it waits at before its servlet
/// starts.
///
/// The spawner blocks where a [`SpawnGate`] spawner awaits, so the control
/// task that runs it is mid-poll while the test drops the hive, and the abort
/// of the control plane lands once that poll ends.
#[cfg(feature = "instrument")]
#[derive(Clone)]
struct BlockingGate {
	entered: Arc<Notify>,
	release: Arc<Barrier>,
}

#[cfg(feature = "instrument")]
impl Default for BlockingGate {
	fn default() -> Self {
		Self { entered: Arc::default(), release: Arc::new(Barrier::new(2)) }
	}
}

/// Starts a serving hive whose `blocking` type spawns each instance behind
/// `gate`. Each instance it spawns records its stop on `stops`, and the
/// instance it registers records nothing.
#[cfg(feature = "instrument")]
async fn start_blocking_hive(ctx: &TrustedSignerContext, gate: &BlockingGate, stops: &TraceCollector) -> HiveX509Test {
	let registered = LocatorStopProbe { trace: stops.share(), addr: b"127.0.0.1:7200".to_vec(), report_stop: false };
	let gate = gate.clone();
	let stops = stops.share();

	let conf = serving_conf(ctx).expect("a fixture signer pins in a trust store");
	let mut hive = HiveX509Test::new(Some(conf)).expect("a hive on fixture TLS builds");
	let registered = hive.register(servlet_urn("blocking"), registered, move |_| {
		let gate = gate.clone();
		let trace = stops.share();
		async move {
			gate.entered.notify_one();
			gate.release.wait();
			Ok(LocatorStopProbe { trace, addr: b"127.0.0.1:7201".to_vec(), report_stop: true })
		}
	});
	registered.expect("a fresh hive registers its first servlet");

	let established = hive.establish(Arc::new(TraceCollector::new())).await;
	established.expect("a hive establishes on a free port");
	hive
}

/// A spawn that lands after its hive drops has its servlet stopped by the
/// hive, so the servlet ends with the hive (CWE-362, CWE-772).
///
/// The runtime has two workers, so the spawner holds one of them while the
/// test drops the hive on its own thread.
#[cfg(feature = "instrument")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spawn_that_lands_after_the_hive_drops_stops_its_servlet() -> TestResult {
	let signer = trusted_signer("CN=Hive Dropped Spawn");
	let gate = BlockingGate::default();
	let (stops, waiter) = TraceWaiter::trace();
	let hive = start_blocking_hive(&signer, &gate, &stops).await;
	let mut client = connect_hive(&hive, &signer).await?;
	let spawn = signed_spawn_frame(&signer.identity, b"spawn-dropped", "blocking").await?;
	// The drop of the hive ends the connection, so the stop of the servlet is
	// the observable and the reply goes unread.
	let _reply = tokio::spawn(async move { emit_command(&mut client, spawn).await });
	gate.entered.notified().await;

	drop(hive);
	gate.release.wait();

	// The probe records its stop as an assertion, which reaches the sink under
	// `ASSERT_LABEL`, and the probe records nothing else.
	let arrived = waiter.until(events::ASSERT_LABEL, 1).await;
	assert_eq!((arrived, stops.recorded(SERVLET_STOPPED)), (true, 1));
	Ok(())
}

/// A probe servlet with a caller-chosen locator. It emits [`SERVLET_STOPPED`]
/// on teardown when `report_stop` is set.
///
/// A house servlet binds an address of its own, and a test needs a locator
/// it names and a record of the stop, so this probe stands in for one.
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
// `stop_boxed` before the registration returns.
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

			let stopped_at_registration = trace.recorded(SERVLET_STOPPED);
			hive.stop();
			assert_eq!(stopped_at_registration, 1);
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

	let trust_store = combined_trust(&[&materials.certificate]);
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
		context: ServerMaterials::fixed(),
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

			let response: HiveTestResponse = reply.decode_message()?;
			assert_eq!(response.doubled, 42, "the contract servlet doubles 21");

			hive.stop();
			Ok(())
		}
	}
}

/// The connection trace of the established `hive`, shared.
fn connection_trace_of(hive: &HiveX509Test) -> TraceCollector {
	let connections = hive.connection_trace();
	connections.expect("an established hive holds a connection trace").share()
}

/// The events among `kept` that a hive records, in order, as its control
/// plane answers one unsigned heartbeat: the trail of its own trace, then of
/// its connection trace. The client dials with a default endpoint, so both
/// traces hold the hive's events alone.
async fn hive_trails(kept: &[Urn<'static>]) -> (Vec<Urn<'static>>, Vec<Urn<'static>>) {
	let trace = TraceCollector::new();
	let signer = trusted_signer("CN=Hive Trail Cluster");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await;
	let hive = hive.expect("a hive establishes on a free port");
	let connections = connection_trace_of(&hive);
	let client = connect_hive(&hive, &signer).await;
	let mut client = client.expect("a trusted signer connects to its hive");
	let beat = command_frame(b"hb-trail", heartbeat_command()).expect("a heartbeat frame builds");

	let reply = emit_command(&mut client, beat).await;
	reply.expect("the hive answers an unsigned heartbeat");

	hive.stop();

	(TestTrace::trail(&trace, kept), TestTrace::trail(&connections, kept))
}

// A hive records the gate verdict of each command that its control plane
// answers on its connection trace, and its own refusal of an unsigned command
// on its own trace.
tightbeam::tb_cases! {
	async fn a_hive_records((kept, trails): (&[Urn<'static>], (Vec<Urn<'static>>, Vec<Urn<'static>>))) {
		let recorded = hive_trails(kept).await;
		assert_eq!(recorded, trails);
	}
	cases {
		/// The connection trace holds the gate verdict, and the hive's own
		/// trace holds none.
		the_gate_verdicts_of_its_control_plane_on_its_connection_trace => (
			&[events::GATE_ACCEPT, events::GATE_REJECT],
			(vec![], vec![events::GATE_ACCEPT]),
		),
		/// The hive's own trace holds its refusal, and the connection trace
		/// holds the verdict of the transport gate that admitted the frame.
		its_refusal_on_its_own_trace_apart_from_the_gate_verdict => (
			&[events::GATE_ACCEPT, events::HIVE_COMMAND_REFUSED],
			(vec![events::HIVE_COMMAND_REFUSED], vec![events::GATE_ACCEPT]),
		),
	}
}

/// The trace of a hive after it carries out one spawn and one stop for
/// `signer`, beside the instance that the two commands changed. The trace
/// keeps the digest of each payload.
#[cfg(feature = "instrument")]
async fn carried_out_records(signer: &TrustedSignerContext) -> (TraceCollector, Urn<'static>) {
	let trace = payload_trace();
	let hive = start_serving_hive(&trace, signer).await.expect("a serving hive establishes");
	let carried = spawn_and_stop(&hive, signer).await;
	let carried = carried.expect("a trusted signer spawns and stops an instance");

	hive.stop();

	(trace, carried.instance)
}

/// A hive names each spawn and each stop it carries out by the command and
/// the instance it changed, so its trail shows which servlet started and
/// which stopped (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_names_each_command_it_carries_out() {
	let (trace, instance) = carried_out_records(&trusted_signer("CN=Hive Carried Out Cluster")).await;
	let labels = recorded_labels(&trace, events::HIVE_COMMAND_ACCEPTED);
	assert_eq!(labels, [Some(format!("Spawn/{instance}")), Some(format!("Stop/{instance}"))]);
}

/// A hive names the peer of each spawn and stop it carries out by the peer's
/// canonical key, so its trail shows who started and who stopped a servlet
/// (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_names_the_peer_of_each_command_it_carries_out() {
	let signer = trusted_signer("CN=Hive Carried Out Peer");
	let peer = session_digest(&signer.certificate);

	let (trace, _instance) = carried_out_records(&signer).await;
	let payloads = payload_digests(&trace, events::HIVE_COMMAND_ACCEPTED);
	assert_eq!(payloads, [Some(peer), Some(peer)]);
}

/// The count of peers that fail the handshake of a hive's control plane, and
/// the bound of the hive's trace, in the test of that bound.
#[cfg(feature = "instrument")]
const REFUSED_PEERS: usize = 4;

/// Dials `hive` as `stranger`, a signer whose certificate the hive does not
/// pin, and sends one heartbeat. The client trusts the certificate of
/// `signer`, which the hive presents.
#[cfg(feature = "instrument")]
async fn dial_as_stranger(
	hive: &HiveX509Test,
	signer: &TrustedSignerContext,
	stranger: &TrustedSignerContext,
) -> Result<ClusterCommandResponse, TightBeamError> {
	let mut client = connect_hive_as(hive, signer, stranger).await?;
	emit_command(&mut client, command_frame(b"hb-stranger", heartbeat_command())?).await
}

/// What a hive records after [`REFUSED_PEERS`] strangers fail its
/// control-plane handshake and it records one event of its own: the hive's own
/// events its trace keeps, its overflow latch, and the count of refused
/// certificates on its connection trace. Each trace holds at most
/// [`REFUSED_PEERS`] events.
#[cfg(feature = "instrument")]
async fn hive_traces_after_refused_peers() -> (Vec<Urn<'static>>, bool, usize) {
	let trace = bounded_trace(REFUSED_PEERS as u32);
	let signer = trusted_signer("CN=Hive Bound Cluster");
	let stranger = trusted_signer("CN=Hive Bound Stranger");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await;
	let hive = hive.expect("a hive establishes on a free port");
	let connections = connection_trace_of(&hive);
	// The start records into the trace, so a drain gives every slot to the
	// strangers. A drain keeps the latch.
	let _started = trace.drain_events();

	for _ in 0..REFUSED_PEERS {
		// The hive refuses the stranger's certificate, so the heartbeat fails
		// and the test reads the refusal from the trace.
		let _refused = dial_as_stranger(&hive, &signer, &stranger).await;
	}

	// The test measures the default sink of the connection trace, which wakes
	// no wait on a record, so a bounded poll waits for the refusals. A wait
	// that runs out leaves the connection trace short of the strangers, which
	// the count of refused certificates then shows.
	let refused = || connections.recorded(events::SESSION_CERT_REJECTED) >= REFUSED_PEERS;
	poll_until(50, Duration::from_millis(100), refused).await;
	let own = trace.emit_event(events::HIVE_REREGISTERED);
	own.expect("a trace records a house event");
	hive.stop();

	let kept = TestTrace::trail(&trace, &[events::HIVE_REREGISTERED]);
	(kept, trace.overflowed(), connections.recorded(events::SESSION_CERT_REJECTED))
}

/// Peers that never authenticate record on a hive's connection trace, so the
/// hive's own bounded trace keeps its next event and sets no overflow latch.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn refused_peers_leave_the_trace_of_a_hive_to_its_own_events() {
	let recorded = hive_traces_after_refused_peers().await;
	assert_eq!(recorded, (vec![events::HIVE_REREGISTERED], false, REFUSED_PEERS));
}

/// The count of commands that a client with no certificate sends to a hive,
/// and the bound of the hive's trace, in the test of that bound.
#[cfg(feature = "instrument")]
const ANONYMOUS_COMMANDS: usize = 4;

/// What a hive keeps after [`ANONYMOUS_COMMANDS`] anonymous heartbeats to a
/// control plane that demands no certificate, then one event of its own: its
/// own events in its trace's sink, the overflow latch, and the refusals.
#[cfg(feature = "instrument")]
async fn hive_traces_after_anonymous_commands() -> (Vec<Urn<'static>>, bool, usize) {
	let trace = bounded_trace(ANONYMOUS_COMMANDS as u32);
	let signer = trusted_signer("CN=Hive Anonymous Cluster");
	let hive_tls = anonymous_hive_tls(signer.identity.clone());
	let hive = HiveX509Test::new(Some(HiveConfig { hive_tls: Some(Arc::new(hive_tls)), ..Default::default() }));
	let mut hive = hive.expect("a hive on fixture TLS builds");
	let established = hive.establish(Arc::new(trace.share())).await;
	established.expect("a hive establishes on a free port");

	let connections = connection_trace_of(&hive);
	// The establish records into the trace, so a drain gives every slot to
	// the commands. A drain keeps the latch.
	let _started = trace.drain_events();

	let trust = combined_trust(&[&signer.certificate]);
	let client = ClientBuilder::<TokioListener>::builder().with_trust_store(trust).build();
	let addr = hive.addr().expect("an established hive has an address");
	let client = client.connect(addr.to_owned()).await;
	let mut client = client.expect("an anonymous client connects to the hive");
	for _ in 0..ANONYMOUS_COMMANDS {
		let beat = command_frame(b"hb-anonymous", heartbeat_command()).expect("a heartbeat frame builds");
		// The hive has no trust store, so it refuses each command.
		let _refused = emit_command(&mut client, beat).await;
	}

	let own = trace.emit_event(events::HIVE_REREGISTERED);
	own.expect("a trace records a house event");
	hive.stop();

	let kept = TestTrace::trail(&trace, &[events::HIVE_REREGISTERED]);
	(kept, trace.overflowed(), connections.recorded(events::HIVE_COMMAND_REFUSED))
}

/// Anonymous commands leave the bounded trace of a hive to its own events.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn anonymous_commands_leave_the_trace_of_a_hive_to_its_own_events() {
	let recorded = hive_traces_after_anonymous_commands().await;
	assert_eq!(recorded, (vec![events::HIVE_REREGISTERED], false, ANONYMOUS_COMMANDS));
}

/// The accepted connections that reach the sink of a hive's trace as one
/// trusted signer sends a heartbeat.
#[cfg(feature = "instrument")]
async fn forwarded_connections_of_a_hive() -> usize {
	let (trace, waiter) = TraceWaiter::trace();
	let signer = trusted_signer("CN=Hive Forward Cluster");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await;
	let hive = hive.expect("a hive establishes on a free port");
	let client = connect_hive(&hive, &signer).await;
	let mut client = client.expect("a trusted signer connects to its hive");
	let beat = command_frame(b"hb-forward", heartbeat_command()).expect("a heartbeat frame builds");
	emit_command(&mut client, beat).await.expect("the hive answers a heartbeat");
	hive.stop();

	waiter.count(events::CONNECTION_ACCEPTED)
}

/// A connection of a hive reaches the sink of the hive's trace (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_connection_reaches_the_sink_of_the_trace_of_the_hive() {
	assert_eq!(forwarded_connections_of_a_hive().await, 1);
}

/// The dials that a hive's own trace records as a caller reaches a sibling
/// servlet through the hive context. The servlet records into its own trace, so
/// the hive's trace holds the dials of its servlet pool alone.
async fn hive_sibling_dials() -> Vec<Urn<'static>> {
	let trace = TraceCollector::new();
	let materials = ServerMaterials::fixed();
	let hive = start_contract_hive(trace.share(), TraceCollector::new(), &materials).await;
	let hive = hive.expect("a contract hive establishes");
	let unsigned = FrameBuilder::from(Version::V2)
		.with_id(b"hive-pool-dial")
		.with_order(UnixMillis::now().get())
		.with_previous_hash(TestDigest::info())
		.with_message(HiveTestRequest { value: 21 })
		.build()
		.expect("a V2 call frame builds");

	let signed = sign_contract_frame(unsigned).await.expect("the contract key signs a frame");
	let answered = hive.context().call(&servlet_urn("contract"), signed).await;
	answered.expect("the sibling servlet answers the call");
	hive.stop();

	TestTrace::trail(&trace, &[events::POOL_DIAL])
}

/// A hive records each dial of its servlet pool on its own trace, the trace
/// it establishes with.
#[tokio::test]
async fn a_hive_records_the_dials_of_its_servlet_pool_on_its_own_trace() {
	assert_eq!(hive_sibling_dials().await, [events::POOL_DIAL]);
}
