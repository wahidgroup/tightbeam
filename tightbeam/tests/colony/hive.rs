//! Integration tests for Hive with X.509 certificates
//!
//! Tests the Hive lifecycle through its public interface with TLS.

use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::{
	builder::{frame::FrameBuilder, TypeBuilder},
	colony::{
		common::{
			current_timestamp_ms, servlet_instance, ClusterCommand, ClusterCommandResponse, ClusterStatus,
			ColonyNamespace, HeartbeatParams, HiveManagementRequest, SpawnServletParams, StopServletParams,
		},
		hive::{Hive, HiveConf, HiveTlsConfig, ServletBox},
	},
	compose,
	crypto::{
		key::Secp256k1KeyProvider,
		x509::{Certificate, CertificateSpec},
	},
	decode,
	der::Sequence,
	exactly, hive,
	policy::TransitStatus,
	servlet, tb_assert_spec, tb_scenario,
	testing::{HiveEnv, SetupEnv},
	trace::TraceCollector,
	transport::{
		handshake::negotiation::TransportOffer, tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder,
		GenericClient,
	},
	utils::{urn::Urn, BasisPoints},
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::security::{expectation_failure, pinning_trust_store};
use crate::common::x509::create_test_cert_with_key;

fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

fn servlet_urn(name: &str) -> Urn<'static> {
	colony_ns().servlet(name).expect("test names satisfy the mint grammar")
}

pub(crate) const BACKPRESSURE_HEARTBEAT_HEARTBEAT_SHAPE: Urn<'static> =
	Urn::new("test", "event:hive/backpressure-heartbeat-heartbeat-shape");
pub(crate) const BACKPRESSURE_MANAGE_MANAGE_SHAPE: Urn<'static> =
	Urn::new("test", "event:hive/backpressure-manage-manage-shape");
pub(crate) const DRAINING_MANAGE_MANAGE_SHAPE: Urn<'static> =
	Urn::new("test", "event:hive/draining-manage-manage-shape");
pub(crate) const FIRST_SPAWN_FORBIDDEN: Urn<'static> = Urn::new("test", "event:hive/first-spawn-forbidden");
pub(crate) const FORGED_HEARTBEAT_DENIED: Urn<'static> = Urn::new("test", "event:hive/forged-heartbeat-denied");
pub(crate) const HIVE_ESTABLISHED: Urn<'static> = Urn::new("test", "event:hive/hive-established");
pub(crate) const HIVE_STARTED: Urn<'static> = Urn::new("test", "event:hive/hive-started");
pub(crate) const OPEN_BREAKER_HEARTBEAT_SHAPE: Urn<'static> =
	Urn::new("test", "event:hive/open-breaker-heartbeat-shape");
pub(crate) const RETRY_SPAWN_ACCEPTED: Urn<'static> = Urn::new("test", "event:hive/retry-spawn-accepted");
pub(crate) const SERVLET_RECEIVE: Urn<'static> = Urn::new("test", "event:hive/servlet-receive");
pub(crate) const SERVLET_RESPOND: Urn<'static> = Urn::new("test", "event:hive/servlet-respond");
pub(crate) const SERVLET_STOPPED: Urn<'static> = Urn::new("test", "event:hive/servlet-stopped");
pub(crate) const SIGNED_HEARTBEAT_ACCEPTED: Urn<'static> = Urn::new("test", "event:hive/signed-heartbeat-accepted");
pub(crate) const SPAWN_NON_UTF8_FORBIDDEN: Urn<'static> = Urn::new("test", "event:hive/spawn-non-utf8-forbidden");
pub(crate) const UNSIGNED_HEARTBEAT_HEARTBEAT_SHAPE: Urn<'static> =
	Urn::new("test", "event:hive/unsigned-heartbeat-heartbeat-shape");
pub(crate) const UNSIGNED_MANAGE_MANAGE_SHAPE: Urn<'static> =
	Urn::new("test", "event:hive/unsigned-manage-manage-shape");

// ============================================================================
// Test Messages
// ============================================================================

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct HiveTestRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct HiveTestResponse {
	pub doubled: u32,
}

// ============================================================================
// Test Servlets
// ============================================================================

servlet! {
	HiveTestServlet<HiveTestRequest, EnvConfig = ()>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = ctx.trace();
		trace.event(SERVLET_RECEIVE)?;
		trace.event(SERVLET_RESPOND)?;

		Ok(Some(compose! {
			V0: id: &frame.metadata.id,
				message: HiveTestResponse { doubled: req.value * 2 }
		}?))
	}
}

// ============================================================================
// Test Hive
// ============================================================================

hive! {
	HiveX509Test,
	protocol: TokioListener
}

// ============================================================================
// Assertion Spec
// ============================================================================

tb_assert_spec! {
	pub HiveEstablishSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(HIVE_STARTED, exactly!(1)),
			(HIVE_ESTABLISHED, exactly!(1), equals!(1u64))
		]
	}
}

// ============================================================================
// Integration Test
// ============================================================================

/// Registers a test servlet, establishes the hive, and records the
/// establish events on the scenario trace; `HIVE_ESTABLISHED` carries
/// the registered-servlet count for the spec to value-assert.
async fn establish_registered_hive(
	trace: &TraceCollector,
	conf: Option<HiveConf>,
) -> Result<HiveX509Test, TightBeamError> {
	trace.event(HIVE_STARTED)?;

	let servlet = HiveTestServlet::start(Arc::new(trace.share()), None).await?;
	let mut hive = HiveX509Test::new(conf)?;
	hive.register(servlet_urn("test_servlet"), servlet, |t| HiveTestServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;

	trace.event_with(HIVE_ESTABLISHED, &[], hive.servlet_addresses().len() as u64)?;
	Ok(hive)
}

fn hive_tls() -> HiveTlsConfig {
	let (cert, signing_key) = create_test_cert_with_key("CN=Hive Test Server", 365).expect("hive TLS material");
	HiveTlsConfig {
		certificate: CertificateSpec::Built(Box::new(cert)),
		key: Arc::new(Secp256k1KeyProvider::from(signing_key)),
		validators: vec![],
	}
}

tb_scenario! {
	name: hive_establish_with_x509,
	spec: HiveEstablishSpec,
	environment Hive {
		context: hive_tls(),
		start: |SetupEnv { trace, context: tls }| async move {
			establish_registered_hive(
				&trace,
				Some(HiveConf {
					hive_tls: Some(tls),
					mux_offer: Some(TransportOffer::mux(4)),
					..Default::default()
				}),
			)
			.await
		},
		client: |HiveEnv { hive, .. }| async move {
			hive.stop();
			Ok(())
		}
	}
}

// ============================================================================
// Gate Reply Shapes - fixtures
// ============================================================================

/// Fresh heartbeat command (unique `issued_at_ms` per call site via clock).
fn heartbeat_command(issued_at_ms: u64) -> ClusterCommand {
	ClusterCommand {
		issued_at_ms,
		heartbeat: Some(HeartbeatParams { cluster_status: ClusterStatus::Healthy }),
		manage: None,
	}
}

/// Command frame with integrity witness (unsigned until the caller signs it).
fn command_frame(id: &[u8], cmd: ClusterCommand) -> Result<Frame, TightBeamError> {
	FrameBuilder::from(Version::V1)
		.with_id(id)
		.with_message(cmd)
		.with_witness_hasher::<Sha3_256>()
		.build()
}

/// Manage command with a stop request (unique id per call site).
fn stop_command_frame(id: &[u8]) -> Result<Frame, TightBeamError> {
	let manage_cmd = ClusterCommand {
		issued_at_ms: current_timestamp_ms(),
		heartbeat: None,
		manage: Some(HiveManagementRequest {
			spawn: None,
			list: None,
			stop: Some(StopServletParams { servlet_id: servlet_instance(&servlet_urn("none"), "127.0.0.1:0") }),
		}),
	};

	command_frame(id, manage_cmd)
}

/// Manage command with a spawn request.
fn spawn_command_frame(id: &[u8], servlet_type: &str) -> Result<Frame, TightBeamError> {
	let manage_cmd = ClusterCommand {
		issued_at_ms: current_timestamp_ms(),
		heartbeat: None,
		manage: Some(HiveManagementRequest {
			spawn: Some(SpawnServletParams { servlet_type: servlet_urn(servlet_type), config: None }),
			list: None,
			stop: None,
		}),
	};

	command_frame(id, manage_cmd)
}

/// Signer pinned by the hive trust store. `start` builds the trust store
/// from the certificate. The client signs command frames with the provider.
struct TrustedSignerContext {
	certificate: Certificate,
	provider: Secp256k1KeyProvider,
}

fn trusted_signer(subject: &str) -> TrustedSignerContext {
	let (certificate, signing_key) = create_test_cert_with_key(subject, 365).expect("signer material");
	TrustedSignerContext { certificate, provider: Secp256k1KeyProvider::from(signing_key) }
}

/// Starts an established hive with the context signer pinned in its trust store.
async fn start_trusted_hive(
	trace: &TraceCollector,
	ctx: &TrustedSignerContext,
	mut conf: HiveConf,
) -> Result<HiveX509Test, TightBeamError> {
	conf.trust_store = Some(pinning_trust_store(&ctx.certificate)?);

	let mut hive = HiveX509Test::new(Some(conf))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

async fn connect_hive(hive: &HiveX509Test) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder().build().connect(hive.addr()).await?)
}

async fn emit_command(
	client: &mut GenericClient<TokioListener>,
	frame: Frame,
) -> Result<ClusterCommandResponse, TightBeamError> {
	let response = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
	decode(&response.message)
}

/// Heartbeat CHOICE present; manage CHOICE absent; optional sealed
/// capacity (no pre-auth leak). Returns the status for the caller to
/// record as a valued event the spec asserts.
fn heartbeat_shape_status(
	response: &ClusterCommandResponse,
	sealed_capacity: bool,
) -> Result<TransitStatus, TightBeamError> {
	if response.manage.is_some() {
		return Err(expectation_failure("heartbeat response must not use the manage shape"));
	}

	let heartbeat = response
		.heartbeat
		.as_ref()
		.ok_or_else(|| expectation_failure("heartbeat CHOICE required"))?;
	if sealed_capacity && (heartbeat.utilization.get() != 0 || heartbeat.active_servlets != 0) {
		return Err(expectation_failure("pre-auth reject must not leak capacity"));
	}

	Ok(heartbeat.status)
}

/// Manage/stop CHOICE present; heartbeat CHOICE absent. Returns the
/// stop status for the caller to record as a valued event.
fn manage_stop_shape_status(response: &ClusterCommandResponse) -> Result<TransitStatus, TightBeamError> {
	if response.heartbeat.is_some() {
		return Err(expectation_failure("manage response must not use the heartbeat shape"));
	}

	let stop = response
		.manage
		.as_ref()
		.and_then(|manage| manage.stop.as_ref())
		.ok_or_else(|| expectation_failure("manage/stop CHOICE required"))?;
	Ok(stop.status)
}

/// Manage/spawn CHOICE present; heartbeat CHOICE absent. Returns the
/// spawn status for the caller to record as a valued event.
fn manage_spawn_shape_status(response: &ClusterCommandResponse) -> Result<TransitStatus, TightBeamError> {
	if response.heartbeat.is_some() {
		return Err(expectation_failure("manage response must not use the heartbeat shape"));
	}

	let spawn = response
		.manage
		.as_ref()
		.and_then(|manage| manage.spawn.as_ref())
		.ok_or_else(|| expectation_failure("manage/spawn CHOICE required"))?;
	Ok(spawn.status)
}

async fn signed_heartbeat_frame(provider: &Secp256k1KeyProvider, id: &[u8]) -> Result<Frame, TightBeamError> {
	command_frame(id, heartbeat_command(current_timestamp_ms()))?
		.sign_with_provider::<Sha3_256, _>(provider)
		.await
}

async fn signed_stop_frame(provider: &Secp256k1KeyProvider, id: &[u8]) -> Result<Frame, TightBeamError> {
	stop_command_frame(id)?.sign_with_provider::<Sha3_256, _>(provider).await
}

async fn signed_spawn_frame(
	provider: &Secp256k1KeyProvider,
	id: &[u8],
	servlet_type: &str,
) -> Result<Frame, TightBeamError> {
	spawn_command_frame(id, servlet_type)?
		.sign_with_provider::<Sha3_256, _>(provider)
		.await
}

tb_assert_spec! {
	pub HiveGateShapeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(UNSIGNED_HEARTBEAT_HEARTBEAT_SHAPE, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(UNSIGNED_MANAGE_MANAGE_SHAPE, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(SIGNED_HEARTBEAT_ACCEPTED, exactly!(1), equals!(TransitStatus::Ok)),
			(OPEN_BREAKER_HEARTBEAT_SHAPE, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	},
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(UNSIGNED_HEARTBEAT_HEARTBEAT_SHAPE, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(UNSIGNED_MANAGE_MANAGE_SHAPE, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(SIGNED_HEARTBEAT_ACCEPTED, exactly!(1), equals!(TransitStatus::Ok)),
			(DRAINING_MANAGE_MANAGE_SHAPE, exactly!(1), equals!(TransitStatus::Unavailable)),
			(FORGED_HEARTBEAT_DENIED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(OPEN_BREAKER_HEARTBEAT_SHAPE, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// Security rejects must come back in the CHOICE the sender expects:
// a heartbeat rejected in the manage shape decodes as MalformedResponse
// on the cluster and counts toward eviction, severing a control plane
// whose breaker would otherwise recover after cooldown.
tb_scenario! {
	name: hive_gate_reply_shapes,
	spec: HiveGateShapeSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Gate Cluster"),
		start: |SetupEnv { trace, context: signer }| async move {
			start_trusted_hive(
				&trace,
				&signer,
				HiveConf {
					circuit_breaker_threshold: 1,
					circuit_breaker_cooldown_ms: 60_000,
					..Default::default()
				},
			)
			.await
		},
		client: |HiveEnv { trace, context: signer, hive }| async move {
			let mut client = connect_hive(&hive).await?;

			// Unsigned heartbeat: heartbeat CHOICE, no capacity data pre-auth
			let unsigned_heartbeat = command_frame(b"hb-unsigned", heartbeat_command(current_timestamp_ms()))?;
			let response = emit_command(&mut client, unsigned_heartbeat).await?;
			trace.event_with(UNSIGNED_HEARTBEAT_HEARTBEAT_SHAPE, &[], heartbeat_shape_status(&response, true)?)?;

			// Unsigned manage: manage CHOICE (security verdict, no drain probe)
			let unsigned_stop = stop_command_frame(b"manage-unsigned")?;
			let response = emit_command(&mut client, unsigned_stop).await?;
			trace.event_with(UNSIGNED_MANAGE_MANAGE_SHAPE, &[], manage_stop_shape_status(&response)?)?;

			// Signed heartbeat: accepted end-to-end
			let signed_heartbeat = signed_heartbeat_frame(&signer.provider, b"hb-signed").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			trace.event_with(SIGNED_HEARTBEAT_ACCEPTED, &[], heartbeat_shape_status(&response, false)?)?;

			// A signed manage command during drain must come back
			// Unavailable in the manage CHOICE.
			hive.drain().await?;

			let signed_stop = signed_stop_frame(&signer.provider, b"manage-draining").await?;
			let response = emit_command(&mut client, signed_stop).await?;
			trace.event_with(DRAINING_MANAGE_MANAGE_SHAPE, &[], manage_stop_shape_status(&response)?)?;

			// Trip the breaker (threshold 1): a trusted signer identity with a
			// signature transplanted from a different frame is the one failure
			// class the breaker counts.
			let now = current_timestamp_ms();
			let donor_heartbeat = command_frame(b"hb-donor", heartbeat_command(now))?;
			let donor = donor_heartbeat.sign_with_provider::<Sha3_256, _>(&signer.provider).await?;

			let mut forged = command_frame(b"hb-forged", heartbeat_command(now.saturating_add(1)))?;
			forged.nonrepudiation = donor.nonrepudiation.to_owned();

			let response = emit_command(&mut client, forged).await?;
			trace.event_with(FORGED_HEARTBEAT_DENIED, &[], heartbeat_shape_status(&response, false)?)?;

			// Open breaker: a valid heartbeat is rejected during cooldown but
			// keeps the heartbeat CHOICE, so the cluster records a reply
			// instead of MalformedResponse eviction pressure.
			let signed_heartbeat = signed_heartbeat_frame(&signer.provider, b"hb-open").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			trace.event_with(OPEN_BREAKER_HEARTBEAT_SHAPE, &[], heartbeat_shape_status(&response, true)?)?;

			hive.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveBackpressureShapeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(BACKPRESSURE_MANAGE_MANAGE_SHAPE, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(BACKPRESSURE_HEARTBEAT_HEARTBEAT_SHAPE, exactly!(1), equals!(TransitStatus::ResourceExhausted))
		]
	}
}

// Backpressure ResourceExhausted must also come back in the sender's CHOICE. Only manage
// commands hit the gate (heartbeats are exempt), so the ResourceExhausted verdict must
// use the manage shape.
tb_scenario! {
	name: hive_backpressure_reply_shape,
	spec: HiveBackpressureShapeSpec,
	environment Hive {
		context: trusted_signer("CN=Hive Backpressure Cluster"),
		// Threshold zero: idle utilization already saturates the gate,
		// so every manage command sees the backpressure verdict.
		start: |SetupEnv { trace, context: signer }| async move {
			start_trusted_hive(
				&trace,
				&signer,
				HiveConf {
					backpressure_threshold: BasisPoints::default(),
					..Default::default()
				},
			)
			.await
		},
		client: |HiveEnv { trace, context: signer, hive }| async move {
			let mut client = connect_hive(&hive).await?;

			let signed_stop = signed_stop_frame(&signer.provider, b"manage-bp").await?;
			let response = emit_command(&mut client, signed_stop).await?;
			trace.event_with(BACKPRESSURE_MANAGE_MANAGE_SHAPE, &[], manage_stop_shape_status(&response)?)?;

			// Signed heartbeat is exempt from the gate: heartbeat CHOICE
			// with real capacity data (ResourceExhausted status reflects saturation).
			let signed_heartbeat = signed_heartbeat_frame(&signer.provider, b"hb-bp").await?;
			let response = emit_command(&mut client, signed_heartbeat).await?;
			trace.event_with(BACKPRESSURE_HEARTBEAT_HEARTBEAT_SHAPE, &[], heartbeat_shape_status(&response, false)?)?;

			hive.stop();

			Ok(())
		}
	}
}

// Test without TLS to verify basic hive functionality
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

// ============================================================================
// Replay forget on manage handler failure
// ============================================================================

tb_assert_spec! {
	pub HiveSpawnRetrySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(FIRST_SPAWN_FORBIDDEN, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(RETRY_SPAWN_ACCEPTED, exactly!(1), equals!(TransitStatus::Ok))
		]
	}
}

tb_scenario! {
	name: hive_manage_failure_allows_signed_retry,
	spec: HiveSpawnRetrySpec,
	environment Hive {
		context: trusted_signer("CN=Hive Spawn Retry"),
		start: |SetupEnv { trace, context: signer }| async move {
			use core::sync::atomic::{AtomicBool, Ordering};

			let fail_once = Arc::new(AtomicBool::new(true));
			let seed = HiveTestServlet::start(Arc::new(trace.share()), None).await?;
			let trust_store = pinning_trust_store(&signer.certificate)?;

			let conf = HiveConf { trust_store: Some(trust_store), ..Default::default() };
			let mut hive = HiveX509Test::new(Some(conf))?;
			hive.register(servlet_urn("flaky"), seed, move |t| {
				let fail_flag = Arc::clone(&fail_once);
				async move {
					if fail_flag.swap(false, Ordering::SeqCst) {
						return Err(TightBeamError::MissingResponse);
					}

					HiveTestServlet::start(t, None).await
				}
			})?;

			hive.establish(Arc::new(trace.share())).await?;
			Ok(hive)
		},
		client: |HiveEnv { trace, context: signer, hive }| async move {
			let mut client = connect_hive(&hive).await?;
			let signed = signed_spawn_frame(&signer.provider, b"spawn-retry", "flaky").await?;
			let replay = signed.to_owned();

			let first = emit_command(&mut client, signed).await?;
			trace.event_with(FIRST_SPAWN_FORBIDDEN, &[], manage_spawn_shape_status(&first)?)?;

			let second = emit_command(&mut client, replay).await?;
			trace.event_with(RETRY_SPAWN_ACCEPTED, &[], manage_spawn_shape_status(&second)?)?;

			hive.stop();
			Ok(())
		}
	}
}

/// Probe servlet with a caller-chosen locator. Seed uses UTF-8 so
/// `register` succeeds; spawn uses non-UTF-8 so instance URN minting
/// fails. Only the spawn probe emits [`SERVLET_STOPPED`] on teardown.
struct LocatorStopProbe {
	trace: TraceCollector,
	addr: Vec<u8>,
	report_stop: bool,
}

impl ServletBox for LocatorStopProbe {
	fn addr_bytes(&self) -> Vec<u8> {
		self.addr.clone()
	}

	fn stop_boxed(self: Box<Self>) {
		if self.report_stop {
			let _ = self.trace.event(SERVLET_STOPPED);
		}
	}
}

tb_assert_spec! {
	pub HiveSpawnNonUtf8Spec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(SPAWN_NON_UTF8_FORBIDDEN, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

// A manage spawn whose locator is not UTF-8 must refuse registration and
// still tear the orphaned servlet down through `stop_boxed`.
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
			let conf = HiveConf { trust_store: Some(trust_store), ..Default::default() };
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
		client: |HiveEnv { trace, context: signer, hive }| async move {
			let mut client = connect_hive(&hive).await?;
			let signed = signed_spawn_frame(&signer.provider, b"spawn-orphan", "orphan").await?;
			let response = emit_command(&mut client, signed).await?;
			trace.event_with(SPAWN_NON_UTF8_FORBIDDEN, &[], manage_spawn_shape_status(&response)?)?;

			hive.stop();
			Ok(())
		}
	}
}
