//! The integration tests of the Hive with X.509 certificates.
//!
//! The tests drive the Hive lifecycle through its public interface with TLS.

use core::time::Duration;
use std::sync::Arc;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::utils::time::UnixMillis;

use tightbeam::crypto::x509::policy::DirectTrustValidator;

use sha3::Sha3_256;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::{
	builder::{frame::FrameBuilder, CheckDigestOid, TypeBuilder},
	colony::{
		hive::{Hive, HiveConfig, HiveTlsConfig, ServletBox},
		protocol::{
			ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams, HiveManagement,
			HiveManagementOutcome, SpawnServletParams, StopServletParams,
		},
		servlet::ServletConfig,
		urn::ColonyNamespace,
	},
	compose,
	crypto::{
		key::Secp256k1KeyProvider,
		profiles::DefaultCryptoProvider,
		sign::ecdsa::Secp256k1SigningKey,
		x509::{Certificate, CertificateSpec, KeyPurposes, PeerCertificate, Signing},
	},
	decode,
	der::Sequence,
	exactly, hive,
	instrumentation::{events, TbInstrumentationConfig},
	policy::TransitStatus,
	servlet, tb_assert_spec, tb_scenario,
	testing::{fixtures::TestTrace, HiveEnv, SetupEnv, TestCertificate, TestDigest, TestIdentity, TestKey},
	trace::{TraceCollector, TraceConfig},
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
		GenericClient, Protocol,
	},
	urn::Urn,
	utils::BasisPoints,
	Beamable, Frame, Message, TightBeamError, Version,
};

use crate::common::poll::poll_until;
use crate::common::security::{expectation_failure, pinning_trust_store, ServerMaterials};
use crate::common::x509::{create_test_cert_with_key, signing_identity};

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

/// Registers a test servlet and establishes the hive on the scenario trace,
/// where the hive records [`events::HIVE_ESTABLISHED`] with the count of
/// servlets it registered.
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
		vec![],
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
// control plane serves, so the hive stays provisional, with no address, and a
// later establish on a trace that records the event succeeds.
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

/// Builds a command frame with an integrity witness. The frame stays
/// unsigned until the caller signs it. `metadata.order` is the freshness
/// binding (CWE-294).
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
	let stop = StopServletParams { servlet_id };
	let manage_cmd = ClusterCommand::Manage(HiveManagement::Stop(stop));

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
	/// the handshake proves, so a control plane that proves no peer has no
	/// budget to key on.
	fn control_tls(&self) -> HiveTlsConfig {
		let anchor = DirectTrustValidator::default().with_trust_chain([self.certificate.to_owned()]);

		HiveTlsConfig::new(
			CertificateSpec::Built(Box::new(self.certificate.to_owned())),
			self.identity.provider_arc(),
			vec![Arc::new(anchor)],
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

/// Dials the hive control plane as the trusted signer.
///
/// The client presents `ctx` as its certificate, so the accept side proves
/// a peer and the security gate has an identity to key its breaker on.
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

			// The hive answers a signed heartbeat during drain, because a
			// liveness command survives the drain, so the cluster reads the
			// hive's health through it.
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

			// A spawn refused by the drain answers in the spawn alternative,
			// which is the one its sender decodes.
			let signed_spawn = signed_spawn_frame(&signer.identity, b"spawn-draining", "orphan").await?;
			let response = emit_command(&mut client, signed_spawn).await?;
			let status = manage_spawn_shape_status(response)?;
			assert_eq!(status, TransitStatus::Unavailable, "a draining hive refuses a signed spawn in the spawn shape");

			// Trip the breaker at threshold 1. A trusted signer identity with a
			// signature transplanted from a different frame is the one failure
			// class the breaker counts.
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

// A backpressure refusal of ResourceExhausted must also come back in the
// sender's CHOICE. Only manage commands hit the gate (heartbeats are exempt),
// so the ResourceExhausted verdict must use the manage shape.
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

/// A provisional `addr` from `Hive::new` must not reach the cluster, so the
/// hive refuses registration before establish with `NotEstablished`.
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

// A spawner that fails is a refusal a retry can change, so the hive answers
// Unavailable and releases the replay slot. The hive then admits the same
// signed frame again, and the retry succeeds.
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

/// A probe servlet with a caller-chosen locator. It emits [`SERVLET_STOPPED`]
/// on teardown when `report_stop` is set. The non-UTF-8 spawn scenario seeds it
/// with a UTF-8 locator, so `register` succeeds, and spawns it with a non-UTF-8
/// locator, so the instance URN fails to build.
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

// The hive must refuse registration of a manage spawn whose locator is not
// UTF-8, and tear the orphaned servlet down through `stop_boxed`.
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

pub(crate) const CONTRACT_FRAME_CLIENT_ID: Urn<'static> =
	tightbeam::urn!("test", "event:hive/contract-frame-client-id");
pub(crate) const CONTRACT_FRAME_SIGNED: Urn<'static> = tightbeam::urn!("test", "event:hive/contract-frame-signed");
pub(crate) const CONTRACT_FRAME_PREVIOUS: Urn<'static> = tightbeam::urn!("test", "event:hive/contract-frame-previous");
pub(crate) const CONTRACT_FRAME_SIG_VALID: Urn<'static> =
	tightbeam::urn!("test", "event:hive/contract-frame-sig-valid");

/// Returns the deterministic contract key that the caller and the sibling
/// servlet share, so each side can verify the other's frame signature
/// without key distribution.
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

/// Returns true when the signature on `frame` verifies against the
/// certificate of the shared contract key. A verified signature proves byte
/// fidelity end to end.
fn contract_signature_verifies(frame: &Frame) -> bool {
	let certificate = TestCertificate::self_signed(&contract_signing_key());
	let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer);
	let signer = signer.expect("the contract certificate asserts digitalSignature");
	frame.verify(&signer).is_ok()
}

servlet! {
	/// Records what the handler observes about the frame it receives for an
	/// intra-hive call, and responds with a signed frame so the caller can
	/// verify the response envelope the same way.
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

			// The public surface under test is `HiveContext::call`. The
			// caller's complete signed frame goes out as composed, and the
			// servlet's complete reply frame comes back.
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

/// The events among `kept` that a hive's own trace records, in order, as its
/// control plane answers one unsigned heartbeat. The client dials with a
/// default endpoint, so the trace holds the events of the hive alone.
async fn hive_trail(kept: &[Urn<'static>]) -> Result<Vec<Urn<'static>>, TightBeamError> {
	let trace = TraceCollector::new();
	let signer = trusted_signer("CN=Hive Trail Cluster");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await?;
	let mut client = connect_hive(&hive, &signer).await?;
	emit_command(&mut client, command_frame(b"hb-trail", heartbeat_command())?).await?;
	hive.stop();

	Ok(TestTrace::trail(&trace, kept))
}

/// A hive's trace records the gate verdict of each command its control plane
/// answers.
#[tokio::test]
async fn a_hive_records_the_gate_verdicts_of_its_control_plane_on_its_own_trace() -> Result<(), TightBeamError> {
	assert_eq!(
		hive_trail(&[events::GATE_ACCEPT, events::GATE_REJECT]).await?,
		[events::GATE_ACCEPT]
	);
	Ok(())
}

/// A hive's trace records its refusal of an unsigned command after the
/// verdict of the transport gate that admitted the frame.
#[tokio::test]
async fn a_hive_records_its_refusal_after_the_gate_verdict_on_its_own_trace() -> Result<(), TightBeamError> {
	let trail = hive_trail(&[events::GATE_ACCEPT, events::HIVE_COMMAND_REFUSED]).await?;
	assert_eq!(trail, [events::GATE_ACCEPT, events::HIVE_COMMAND_REFUSED]);
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

/// The events of its own that a hive's trace keeps, and its overflow latch,
/// after [`REFUSED_PEERS`] strangers fail the handshake of its control plane
/// and the hive then records an event of its own. The trace holds
/// [`REFUSED_PEERS`] events.
async fn hive_trace_after_refused_peers() -> Result<(Vec<Urn<'static>>, bool), TightBeamError> {
	let config = TbInstrumentationConfig { max_events: REFUSED_PEERS as u32, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let signer = trusted_signer("CN=Hive Bound Cluster");
	let stranger = trusted_signer("CN=Hive Bound Stranger");
	let hive = start_trusted_hive(&trace, &signer, HiveConfig::default()).await?;
	// The start records into the trace, so a drain gives every slot to the
	// strangers. A drain keeps the latch.
	let _started = trace.drain_events();

	for _ in 0..REFUSED_PEERS {
		// The hive refuses the certificate of the stranger, so the heartbeat
		// fails, and the test reads the refusal from the trace instead.
		let _refused = dial_as_stranger(&hive, &signer, &stranger).await;
	}

	// A wait that runs out leaves the trace short of the strangers, so the
	// assertion then reads the event of the hive in the trace.
	let refused = || trace.recorded(events::SESSION_CERT_REJECTED) >= REFUSED_PEERS;
	poll_until(50, Duration::from_millis(100), refused).await;
	trace.emit_event(events::HIVE_REREGISTERED)?;
	hive.stop();

	Ok((TestTrace::trail(&trace, &[events::HIVE_REREGISTERED]), trace.overflowed()))
}

/// Peers that never authenticate fill a hive's bounded trace, so the default
/// sink drops the next event of the hive's own and sets its overflow latch.
#[tokio::test]
async fn refused_peers_fill_the_trace_of_a_hive_ahead_of_its_own_events() -> Result<(), TightBeamError> {
	assert_eq!(hive_trace_after_refused_peers().await?, (vec![], true));
	Ok(())
}

/// The dials that a hive's own trace records as a caller reaches a sibling
/// servlet through the hive context. The servlet records into a trace of its
/// own, so the hive's trace holds the dials of the hive's servlet pool alone.
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
