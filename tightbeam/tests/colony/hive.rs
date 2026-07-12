//! Integration tests for Hive with X.509 certificates
//!
//! Tests the Hive lifecycle through its public interface with TLS.

use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::{
	builder::{frame::FrameBuilder, TypeBuilder},
	colony::{
		common::{
			current_timestamp_ms, ClusterCommand, ClusterCommandResponse, ClusterStatus, HeartbeatParams,
			HiveManagementRequest, SpawnServletParams, StopServletParams,
		},
		hive::{Hive, HiveConf, HiveTlsConfig},
	},
	compose,
	crypto::{key::Secp256k1KeyProvider, x509::CertificateSpec},
	decode,
	der::Sequence,
	exactly, hive,
	policy::TransitStatus,
	servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	trace::TraceCollector,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, GenericClient},
	utils::BasisPoints,
	Beamable, Frame, TightBeamError, Version,
};

use crate::common::security::pinning_trust_store;
use crate::common::x509::create_test_cert_with_key;

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
		trace.event("servlet_receive")?;
		trace.event("servlet_respond")?;

		Ok(Some(compose! {
			V0: id: frame.metadata.id.clone(),
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
		gate: Accepted,
		assertions: [
			("hive_started", exactly!(1)),
			("hive_established", exactly!(1))
		]
	}
}

// ============================================================================
// Integration Test
// ============================================================================

async fn establish_registered_hive(trace: &TraceCollector, conf: Option<HiveConf>) -> Result<(), TightBeamError> {
	trace.event("hive_started")?;

	let servlet = HiveTestServlet::start(Arc::new(TraceCollector::new()), None).await?;
	let mut hive = HiveX509Test::new(conf)?;
	hive.register("test_servlet", servlet, |t| HiveTestServlet::start(t, None))?;
	hive.establish(Arc::new(TraceCollector::new())).await?;

	trace.event("hive_established")?;

	assert!(!hive.servlet_addresses().is_empty(), "Hive should have registered servlets");
	hive.stop();
	Ok(())
}

tb_scenario! {
	name: hive_establish_with_x509,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveEstablishSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let (cert, signing_key) = create_test_cert_with_key("CN=Hive Test Server", 365)?;
			let tls_config = Arc::new(HiveTlsConfig {
				certificate: CertificateSpec::Built(Box::new(cert)),
				key: Arc::new(Secp256k1KeyProvider::from(signing_key)),
				validators: vec![],
			});

			establish_registered_hive(
				&trace,
				Some(HiveConf { hive_tls: Some(tls_config), ..Default::default() }),
			)
			.await
		}
	}
}

// ============================================================================
// Gate Reply Shapes — fixtures / harness
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
			stop: Some(StopServletParams { servlet_id: b"none".to_vec() }),
		}),
	};

	command_frame(id, manage_cmd)
}

/// Manage command with a spawn request.
fn spawn_command_frame(id: &[u8], servlet_type: &[u8]) -> Result<Frame, TightBeamError> {
	let manage_cmd = ClusterCommand {
		issued_at_ms: current_timestamp_ms(),
		heartbeat: None,
		manage: Some(HiveManagementRequest {
			spawn: Some(SpawnServletParams { servlet_type: servlet_type.to_vec(), config: None }),
			list: None,
			stop: None,
		}),
	};

	command_frame(id, manage_cmd)
}

/// Unestablished hive + signer pinned by the hive trust store.
struct TrustedHiveParts {
	hive: HiveX509Test,
	provider: Secp256k1KeyProvider,
}

fn trusted_hive_parts(subject: &str, mut conf: HiveConf) -> Result<TrustedHiveParts, TightBeamError> {
	let (cert, signing_key) = create_test_cert_with_key(subject, 365)?;

	conf.trust_store = Some(pinning_trust_store(&cert)?);

	let provider = Secp256k1KeyProvider::from(signing_key);
	let hive = HiveX509Test::new(Some(conf))?;
	Ok(TrustedHiveParts { hive, provider })
}

/// Established hive + connected client + signer pinned by the hive trust store.
struct TrustedHiveSession {
	hive: HiveX509Test,
	client: GenericClient<TokioListener>,
	provider: Secp256k1KeyProvider,
}

async fn trusted_hive_session(subject: &str, conf: HiveConf) -> Result<TrustedHiveSession, TightBeamError> {
	let TrustedHiveParts { mut hive, provider } = trusted_hive_parts(subject, conf)?;
	hive.establish(Arc::new(TraceCollector::new())).await?;

	let client = ClientBuilder::<TokioListener>::builder().build().connect(hive.addr()).await?;
	Ok(TrustedHiveSession { hive, client, provider })
}

async fn emit_command(
	client: &mut GenericClient<TokioListener>,
	frame: Frame,
) -> Result<ClusterCommandResponse, TightBeamError> {
	let response = client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
	decode(&response.message)
}

/// Heartbeat CHOICE present; manage CHOICE absent. Optional sealed capacity (no leak).
fn assert_heartbeat_shape(response: &ClusterCommandResponse, status: TransitStatus, sealed_capacity: bool) {
	assert!(response.manage.is_none(), "heartbeat response must not use the manage shape");

	let heartbeat = response.heartbeat.as_ref().expect("heartbeat CHOICE required");
	assert_eq!(heartbeat.status, status);
	if sealed_capacity {
		assert_eq!(heartbeat.utilization.get(), 0, "pre-auth reject must not leak utilization");
		assert_eq!(heartbeat.active_servlets, 0, "pre-auth reject must not leak servlet count");
	}
}

/// Manage/stop CHOICE present; heartbeat CHOICE absent.
fn assert_manage_stop_shape(response: &ClusterCommandResponse, status: TransitStatus) {
	assert!(response.heartbeat.is_none(), "manage response must not use the heartbeat shape");

	let manage = response.manage.as_ref().expect("manage CHOICE required");
	let stop = manage.stop.as_ref().expect("stop result required");
	assert_eq!(stop.status, status);
}

/// Manage/spawn CHOICE present; heartbeat CHOICE absent.
fn assert_manage_spawn_shape(response: &ClusterCommandResponse, status: TransitStatus) {
	assert!(response.heartbeat.is_none(), "manage response must not use the heartbeat shape");

	let manage = response.manage.as_ref().expect("manage CHOICE required");
	let spawn = manage.spawn.as_ref().expect("spawn result required");
	assert_eq!(spawn.status, status);
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
	servlet_type: &[u8],
) -> Result<Frame, TightBeamError> {
	spawn_command_frame(id, servlet_type)?
		.sign_with_provider::<Sha3_256, _>(provider)
		.await
}

tb_assert_spec! {
	pub HiveGateShapeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("unsigned_heartbeat_heartbeat_shape", exactly!(1)),
			("unsigned_manage_manage_shape", exactly!(1)),
			("signed_heartbeat_accepted", exactly!(1)),
			("open_breaker_heartbeat_shape", exactly!(1))
		]
	},
	V(1,1,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("unsigned_heartbeat_heartbeat_shape", exactly!(1)),
			("unsigned_manage_manage_shape", exactly!(1)),
			("signed_heartbeat_accepted", exactly!(1)),
			("draining_manage_manage_shape", exactly!(1)),
			("open_breaker_heartbeat_shape", exactly!(1))
		]
	}
}

// Security rejects must come back in the CHOICE the sender expects:
// a heartbeat rejected in the manage shape decodes as MalformedResponse
// on the cluster and counts toward eviction, severing a control plane
// whose breaker would otherwise recover after cooldown.
tb_scenario! {
	name: hive_gate_reply_shapes,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveGateShapeSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			let mut session = trusted_hive_session(
				"CN=Hive Gate Cluster",
				HiveConf {
					circuit_breaker_threshold: 1,
					circuit_breaker_cooldown_ms: 60_000,
					..Default::default()
				},
			)
			.await?;

			// Unsigned heartbeat: heartbeat CHOICE, no capacity data pre-auth
			let unsigned_heartbeat = command_frame(b"hb-unsigned", heartbeat_command(current_timestamp_ms()))?;
			let response = emit_command(&mut session.client, unsigned_heartbeat).await?;
			assert_heartbeat_shape(&response, TransitStatus::Unauthorized, true);

			trace.event("unsigned_heartbeat_heartbeat_shape")?;

			// Unsigned manage: manage CHOICE (security verdict, no drain probe)
			let unsigned_stop = stop_command_frame(b"manage-unsigned")?;
			let response = emit_command(&mut session.client, unsigned_stop).await?;
			assert_manage_stop_shape(&response, TransitStatus::Unauthorized);

			trace.event("unsigned_manage_manage_shape")?;

			// Signed heartbeat: accepted end-to-end
			let signed_heartbeat = signed_heartbeat_frame(&session.provider, b"hb-signed").await?;
			let response = emit_command(&mut session.client, signed_heartbeat).await?;
			assert_heartbeat_shape(&response, TransitStatus::Accepted, false);

			trace.event("signed_heartbeat_accepted")?;

			// A signed manage command during drain must come back Busy in
			// the manage CHOICE.
			session.hive.drain().await?;

			let signed_stop = signed_stop_frame(&session.provider, b"manage-draining").await?;
			let response = emit_command(&mut session.client, signed_stop).await?;
			assert_manage_stop_shape(&response, TransitStatus::Busy);

			trace.event("draining_manage_manage_shape")?;

			// Trip the breaker (threshold 1): a trusted signer identity with a
			// signature transplanted from a different frame is the one failure
			// class the breaker counts.
			let now = current_timestamp_ms();
			let donor_heartbeat = command_frame(b"hb-donor", heartbeat_command(now))?;
			let donor = donor_heartbeat.sign_with_provider::<Sha3_256, _>(&session.provider).await?;

			let mut forged = command_frame(b"hb-forged", heartbeat_command(now.saturating_add(1)))?;
			forged.nonrepudiation = donor.nonrepudiation.clone();

			let response = emit_command(&mut session.client, forged).await?;
			assert_heartbeat_shape(&response, TransitStatus::Forbidden, false);

			// Open breaker: a valid heartbeat is rejected during cooldown but
			// keeps the heartbeat CHOICE, so the cluster records a reply
			// instead of MalformedResponse eviction pressure.
			let signed_heartbeat = signed_heartbeat_frame(&session.provider, b"hb-open").await?;
			let response = emit_command(&mut session.client, signed_heartbeat).await?;
			assert_heartbeat_shape(&response, TransitStatus::Forbidden, true);

			trace.event("open_breaker_heartbeat_shape")?;

			session.hive.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub HiveBackpressureShapeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("backpressure_manage_manage_shape", exactly!(1)),
			("backpressure_heartbeat_heartbeat_shape", exactly!(1))
		]
	}
}

// Backpressure Busy must also come back in the sender's CHOICE. Only manage
// commands hit the gate (heartbeats are exempt), so the Busy verdict must
// use the manage shape.
tb_scenario! {
	name: hive_backpressure_reply_shape,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveBackpressureShapeSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			// Threshold zero: idle utilization already saturates the gate,
			// so every manage command sees the backpressure verdict.
			let mut session = trusted_hive_session(
				"CN=Hive Backpressure Cluster",
				HiveConf {
					backpressure_threshold: BasisPoints::default(),
					..Default::default()
				},
			)
			.await?;

			let signed_stop = signed_stop_frame(&session.provider, b"manage-bp").await?;
			let response = emit_command(&mut session.client, signed_stop).await?;
			assert_manage_stop_shape(&response, TransitStatus::Busy);

			trace.event("backpressure_manage_manage_shape")?;

			// Signed heartbeat is exempt from the gate: heartbeat CHOICE
			// with real capacity data (Busy status reflects saturation).
			let signed_heartbeat = signed_heartbeat_frame(&session.provider, b"hb-bp").await?;
			let response = emit_command(&mut session.client, signed_heartbeat).await?;
			assert_heartbeat_shape(&response, TransitStatus::Busy, false);

			trace.event("backpressure_heartbeat_heartbeat_shape")?;

			session.hive.stop();

			Ok(())
		}
	}
}

// Test without TLS to verify basic hive functionality
tb_scenario! {
	name: hive_establish_no_tls,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveEstablishSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move { establish_registered_hive(&trace, None).await }
	}
}

// ============================================================================
// Replay forget on manage handler failure
// ============================================================================

tb_assert_spec! {
	pub HiveSpawnRetrySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("first_spawn_forbidden", exactly!(1)),
			("retry_spawn_accepted", exactly!(1))
		]
	}
}

tb_scenario! {
	name: hive_manage_failure_allows_signed_retry,
	config: ScenarioConf::<()>::builder()
		.with_spec(HiveSpawnRetrySpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			use core::sync::atomic::{AtomicBool, Ordering};

			let TrustedHiveParts { mut hive, provider } =
				trusted_hive_parts("CN=Hive Spawn Retry", HiveConf::default())?;
			let fail_once = Arc::new(AtomicBool::new(true));
			let fail_flag = Arc::clone(&fail_once);

			let seed = HiveTestServlet::start(Arc::new(TraceCollector::new()), None).await?;
			hive.register("flaky", seed, move |t| {
				let fail_flag = Arc::clone(&fail_flag);
				async move {
					if fail_flag.swap(false, Ordering::SeqCst) {
						return Err(TightBeamError::MissingResponse);
					}

					HiveTestServlet::start(t, None).await
				}
			})?;
			hive.establish(Arc::new(TraceCollector::new())).await?;

			let mut client = ClientBuilder::<TokioListener>::builder().build().connect(hive.addr()).await?;
			let signed = signed_spawn_frame(&provider, b"spawn-retry", b"flaky").await?;
			let replay = signed.clone();

			let first = emit_command(&mut client, signed).await?;
			assert_manage_spawn_shape(&first, TransitStatus::Forbidden);
			trace.event("first_spawn_forbidden")?;

			let second = emit_command(&mut client, replay).await?;
			assert_manage_spawn_shape(&second, TransitStatus::Accepted);
			trace.event("retry_spawn_accepted")?;

			hive.stop();
			Ok(())
		}
	}
}
