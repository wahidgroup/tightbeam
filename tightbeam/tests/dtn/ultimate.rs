//! DTN Test - Mission-Critical Framework Demonstration
//!
//! ## Scenario: Mission Control ↔ Earth Relay ↔ Mars Relay ↔ Rover
//!
//! This test demonstrates a realistic 4-tier DTN architecture with:
//! - Mission Control (Earth-based command center)
//! - Earth Relay Satellite (orbiting Earth)
//! - Mars Relay Satellite (orbiting Mars)
//! - Mars Rover (surface operations)
//!
//! Features:
//! - Realistic NASA-inspired rover telemetry (APXS, ChemCam, Mastcam)
//! - Simulated mission clock with realistic Mars-Earth delays
//! - Cryptographic chain validation using previous_frame hash chains
//! - Matrix bit field for rover fault flags
//! - Graceful fault handling (low power -> recharge -> resume)
//! - Cascading gap recovery
//!
//! ## Realistic Timeline
//! - T+0: Mission Control sends command
//! - T+1.5s: Earth Relay forwards
//! - T+12.5min: Mars Relay forwards
//! - T+13min: Rover receives, executes, sends stateful ACK
//! - T+25min: Mission Control receives ACK
//! - T+0: Rover sends telemetry
//! - T+1.5s: Mars Relay forwards
//! - T+12.5min: Earth Relay forwards
//! - T+13min: Mission Control receives, sends next command

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tightbeam::{
	asn1::MessagePriority,
	at_most,
	builder::TypeBuilder,
	crypto::{
		aead::Aes256Gcm,
		hash::Sha3_256,
		key::SigningKeySpec,
		policy::Secp256k1Policy,
		sign::ecdsa::{Secp256k1, Secp256k1SigningKey},
		x509::{
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	error::TightBeamError,
	exactly,
	instrumentation::TbInstrumentationConfig,
	prelude::*,
	tb_assert_spec, tb_compose_spec, tb_process_spec, tb_scenario,
	testing::{fdr::FdrConfig, specs::composition::CompositionSpec, ScenarioConf},
	trace::{LogFilter, LogLevel, LoggerConfig, StdoutBackend, TraceCollector, TraceConfig},
	transport::{
		tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, ConnectionPool, GenericClient, PoolConfig,
	},
	utils::urn::Urn,
	wcet,
};

use crate::dtn::events::*;
use crate::dtn::messages::RoverInstrument;

/// Gap-recovery steps shared by servlets and workers.
///
/// Dynamic `node_name` call sites resolve through this enum onto the URN
/// inventory above, keeping event identity URN-only.
#[derive(Clone, Copy)]
pub(crate) enum GapRecoveryStep {
	GapDetected,
	SendFrameRequest,
	ReceiveFrameRequest,
	SendFrameResponse,
	ReceiveFrameResponse,
	CascadeFrameRequest,
}

/// Resolve the URN for a gap-recovery step on the named DTN node.
pub(crate) fn gap_recovery_event(node: impl AsRef<str>, step: GapRecoveryStep) -> Urn<'static> {
	let index = match node.as_ref() {
		"mission_control" => 0,
		"earth_relay" => 1,
		"mars_relay" => 2,
		_ => 3,
	};
	let table = match step {
		GapRecoveryStep::GapDetected => [
			MISSION_CONTROL_GAP_DETECTED,
			EARTH_RELAY_GAP_DETECTED,
			MARS_RELAY_GAP_DETECTED,
			ROVER_GAP_DETECTED,
		],
		GapRecoveryStep::SendFrameRequest => [
			MISSION_CONTROL_SEND_FRAME_REQUEST,
			EARTH_RELAY_SEND_FRAME_REQUEST,
			MARS_RELAY_SEND_FRAME_REQUEST,
			ROVER_SEND_FRAME_REQUEST,
		],
		GapRecoveryStep::ReceiveFrameRequest => [
			MISSION_CONTROL_RECEIVE_FRAME_REQUEST,
			EARTH_RELAY_RECEIVE_FRAME_REQUEST,
			MARS_RELAY_RECEIVE_FRAME_REQUEST,
			ROVER_RECEIVE_FRAME_REQUEST,
		],
		GapRecoveryStep::SendFrameResponse => [
			MISSION_CONTROL_SEND_FRAME_RESPONSE,
			EARTH_RELAY_SEND_FRAME_RESPONSE,
			MARS_RELAY_SEND_FRAME_RESPONSE,
			ROVER_SEND_FRAME_RESPONSE,
		],
		GapRecoveryStep::ReceiveFrameResponse => [
			MISSION_CONTROL_RECEIVE_FRAME_RESPONSE,
			EARTH_RELAY_RECEIVE_FRAME_RESPONSE,
			MARS_RELAY_RECEIVE_FRAME_RESPONSE,
			ROVER_RECEIVE_FRAME_RESPONSE,
		],
		GapRecoveryStep::CascadeFrameRequest => [
			MISSION_CONTROL_CASCADE_FRAME_REQUEST,
			EARTH_RELAY_CASCADE_FRAME_REQUEST,
			MARS_RELAY_CASCADE_FRAME_REQUEST,
			ROVER_CASCADE_FRAME_REQUEST,
		],
	};
	table[index].clone()
}
use crate::dtn::{
	certs::{EARTH_RELAY_PINNING, MARS_RELAY_PINNING, MISSION_CONTROL_PINNING, ROVER_PINNING},
	messages::RelayMessage,
};

use crate::dtn::{
	bms::BatteryManagementSystem,
	certs::{
		earth_relay_verifying_key, generate_shared_cipher, mars_relay_verifying_key, mission_control_verifying_key,
		rover_verifying_key, EARTH_RELAY_CERT, EARTH_RELAY_KEY, MARS_RELAY_CERT, MARS_RELAY_KEY, MISSION_CONTROL_CERT,
		MISSION_CONTROL_KEY, ROVER_CERT, ROVER_KEY,
	},
	chain_processor::ChainProcessor,
	clock::{advance_clock, delays, init_mission_clock, mission_time_ms},
	fault_manager::{BatteryUpdate, FaultManager},
	fault_matrix::FaultMatrix,
	faults::RoverFaultHandler,
	frame_builder::FrameBuilderHelper,
	messages::{EarthCommand, MessageChainState, RoverCommand, RoverTelemetry},
	ordering::OutOfOrderBuffer,
	servlets::{
		EarthRelaySatelliteServlet, EarthRelaySatelliteServletConf, MarsRelaySatelliteServlet,
		MarsRelaySatelliteServletConf, MissionControlServlet, MissionControlServletConf, MissionState, RoverServlet,
		RoverServletConf,
	},
	storage::FrameStore,
	workers::{
		CommandAckHandlerWorker, CommandExecutionWorker, FrameRequestHandlerWorker, FrameRequestHandlerWorkerConf,
		FrameResponseHandlerWorker, FrameResponseHandlerWorkerConf, MissionControlTelemetryHandlerWorker,
		MissionControlTelemetryHandlerWorkerConf, RoverCommandHandlerWorker, RoverCommandHandlerWorkerConf,
		TelemetryBuilderWorker, TelemetryBuilderWorkerConf,
	},
};

// ============================================================================
// Test Helpers
// ============================================================================

fn make_trust_store(cert_spec: CertificateSpec) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let cert = Certificate::try_from(cert_spec)?;
	Ok(Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert)?
			.build(),
	))
}

// ============================================================================
// DTN Scenario Configuration
// ============================================================================

/// Configuration for 4-tier DTN scenario
/// Only contains state that is SHARED between multiple components or accessed
/// by test client
pub struct DtnScenarioConfig {
	// === SHARED CRYPTOGRAPHIC MATERIAL ===
	/// Rover's signing key (shared: RoverServlet + mission loop client)
	pub rover_signing_key: Secp256k1SigningKey,
	/// Shared AES-256-GCM cipher (Mission Control ↔ Rover end-to-end
	/// encryption)
	pub shared_cipher: Aes256Gcm,

	// === ROVER STATE (SHARED WITH CLIENT) ===
	/// Battery Management System (mission loop monitors battery)
	pub bms: RwLock<BatteryManagementSystem>,
	/// Fault handler for recovery logic
	pub rover_fault_handler: RwLock<RoverFaultHandler>,
	/// Current fault state (encapsulated encoding/decoding)
	pub fault_matrix: RwLock<FaultMatrix>,
	/// Rover's chain processor (shared: RoverServlet + mission loop client)
	pub rover_chain_processor: Arc<ChainProcessor>,

	// === COORDINATION ===
	/// Node addresses (for dynamic servlet coordination)
	pub mission_control_addr: RwLock<Option<TightBeamSocketAddr>>,
	pub earth_relay_addr: RwLock<Option<TightBeamSocketAddr>>,
	pub mars_relay_addr: RwLock<Option<TightBeamSocketAddr>>,
	pub rover_addr: RwLock<Option<TightBeamSocketAddr>>,

	/// Shared mission state (RoverServlet + mission loop synchronization)
	pub mission_state: Arc<RwLock<MissionState>>,

	// === SERVLET LIFECYCLE ===
	/// Servlet handles (keeps servlets alive for test duration)
	pub _mission_control_servlet: RwLock<Option<MissionControlServlet>>,
	pub _earth_relay_servlet: RwLock<Option<EarthRelaySatelliteServlet>>,
	pub _mars_relay_servlet: RwLock<Option<MarsRelaySatelliteServlet>>,
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		// Create Rover storage (shared with Rover's chain processor)
		let rover_store = Arc::new(RwLock::new(
			FrameStore::new(PathBuf::from("temp/dtn/rover")).expect("Failed to create rover storage"),
		));

		// Extract Rover key bytes
		let rover_key_bytes = match ROVER_KEY {
			SigningKeySpec::Bytes(bytes) => bytes,
			_ => panic!("ROVER_KEY must be KeySpec::Bytes"),
		};

		// Create Rover's chain processor (shared between RoverServlet and mission loop
		// client)
		let rover_chain_proc = Arc::new(ChainProcessor::new(
			Arc::clone(&rover_store),
			Arc::new(RwLock::new(MessageChainState::new("Rover".to_string()))),
			Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
		));

		Self {
			// Shared cryptographic material
			rover_signing_key: Secp256k1SigningKey::from_slice(rover_key_bytes).expect("ROVER_KEY is valid"),
			shared_cipher: generate_shared_cipher(),

			// Rover state (shared with mission loop client)
			bms: RwLock::new(BatteryManagementSystem::default()),
			rover_fault_handler: RwLock::new(RoverFaultHandler::new()),
			fault_matrix: RwLock::new(FaultMatrix::new()),
			rover_chain_processor: rover_chain_proc,

			// Coordination
			mission_control_addr: RwLock::new(None),
			earth_relay_addr: RwLock::new(None),
			mars_relay_addr: RwLock::new(None),
			rover_addr: RwLock::new(None),
			mission_state: Arc::new(RwLock::new(MissionState::default())),

			// Servlet lifecycle
			_mission_control_servlet: RwLock::new(None),
			_earth_relay_servlet: RwLock::new(None),
			_mars_relay_servlet: RwLock::new(None),
		}
	}
}

impl Drop for DtnScenarioConfig {
	fn drop(&mut self) {
		// Shutdown servlets gracefully (Drop trait handles cleanup)
		self._mission_control_servlet.write().ok().and_then(|mut g| g.take());
		self._earth_relay_servlet.write().ok().and_then(|mut g| g.take());
		self._mars_relay_servlet.write().ok().and_then(|mut g| g.take());

		// Remove storage directories
		let _ = std::fs::remove_dir_all("temp/dtn/rover");
		let _ = std::fs::remove_dir_all("temp/dtn/mission_control");
		let _ = std::fs::remove_dir_all("temp/dtn/earth_relay");
		let _ = std::fs::remove_dir_all("temp/dtn/mars_relay");
		let _ = std::fs::remove_dir_all("temp/dtn");
	}
}

// ============================================================================
// Test Configuration
// ============================================================================

/// Number of command/response round-trips for the test.
const COMMAND_ROUND_TRIPS: usize = 6;

// ============================================================================
// DTN Process Specifications - Parallel Composition
// ============================================================================

// Telemetry Flow: Rover -> Mars Relay -> Earth Relay -> Mission Control
tb_process_spec! {
	pub DtnTelemetryFlow,
	events {
		observable {
			ROVER_SEND_TELEMETRY,
			MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER,
			MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH,
			EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS,
			EARTH_RELAY_FORWARD_TELEMETRY_TO_MC,
			MISSION_CONTROL_RECEIVE_TELEMETRY,
			MISSION_CONTROL_ANALYZE_TELEMETRY
		}
		hidden { }
	}
	states {
		TelemetryIdle => {
			ROVER_SEND_TELEMETRY => TelemetryMarsRelayReceive
		},
		TelemetryMarsRelayReceive => {
			MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER => TelemetryMarsRelayForward
		},
		TelemetryMarsRelayForward => {
			MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH => TelemetryEarthRelayReceive
		},
		TelemetryEarthRelayReceive => {
			EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS => TelemetryEarthRelayForward
		},
		TelemetryEarthRelayForward => {
			EARTH_RELAY_FORWARD_TELEMETRY_TO_MC => TelemetryMissionControlReceive
		},
		TelemetryMissionControlReceive => {
			MISSION_CONTROL_RECEIVE_TELEMETRY => TelemetryMissionControlAnalyze
		},
		TelemetryMissionControlAnalyze => {
			MISSION_CONTROL_ANALYZE_TELEMETRY => TelemetryIdle
		}
	}
	terminal { TelemetryIdle }
	timing {
		wcet: {
			ROVER_SEND_TELEMETRY => wcet!(Duration::from_millis(100)),
			MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER => wcet!(Duration::from_millis(50)),
			MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH => wcet!(Duration::from_millis(50)),
			EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS => wcet!(Duration::from_millis(50)),
			EARTH_RELAY_FORWARD_TELEMETRY_TO_MC => wcet!(Duration::from_millis(50)),
			MISSION_CONTROL_RECEIVE_TELEMETRY => wcet!(Duration::from_millis(50)),
			MISSION_CONTROL_ANALYZE_TELEMETRY => wcet!(Duration::from_millis(200))
		}
	}
}

// Command Flow: Mission Control -> Earth Relay -> Mars Relay -> Rover -> ACK back
tb_process_spec! {
	pub DtnCommandFlow,
	events {
		observable {
			MISSION_CONTROL_SEND_COMMAND,
			EARTH_RELAY_RECEIVE_FROM_MC,
			EARTH_RELAY_FORWARD_TO_MARS,
			MARS_RELAY_RECEIVE_FROM_EARTH,
			MARS_RELAY_FORWARD_TO_ROVER,
			ROVER_RECEIVE_COMMAND,
			ROVER_EXECUTE_COMMAND,
			ROVER_EXECUTE_COLLECT_SAMPLE,
			ROVER_EXECUTE_PROBE_LOCATION,
			ROVER_EXECUTE_TAKE_PHOTO,
			ROVER_EXECUTE_STANDBY,
			ROVER_COMMAND_COMPLETE,
			ROVER_SEND_ACK,
			MARS_RELAY_RECEIVE_ACK_FROM_ROVER,
			MARS_RELAY_FORWARD_ACK_TO_EARTH,
			EARTH_RELAY_RECEIVE_ACK_FROM_MARS,
			EARTH_RELAY_FORWARD_ACK_TO_MC,
			MISSION_CONTROL_RECEIVE_ACK
		}
		hidden { }
	}
	states {
		CommandIdle => {
			MISSION_CONTROL_SEND_COMMAND => CommandEarthRelayReceive
		},
		CommandEarthRelayReceive => {
			EARTH_RELAY_RECEIVE_FROM_MC => CommandEarthRelayForward
		},
		CommandEarthRelayForward => {
			EARTH_RELAY_FORWARD_TO_MARS => CommandMarsRelayReceive
		},
		CommandMarsRelayReceive => {
			MARS_RELAY_RECEIVE_FROM_EARTH => CommandMarsRelayForward
		},
		CommandMarsRelayForward => {
			MARS_RELAY_FORWARD_TO_ROVER => CommandRoverReceive
		},
		CommandRoverReceive => {
			ROVER_RECEIVE_COMMAND => CommandExecuting
		},
		CommandExecuting => {
			ROVER_EXECUTE_COMMAND => CommandExecuted
		},
		CommandExecuted => {
			ROVER_EXECUTE_COLLECT_SAMPLE => CommandSpecificExecute,
			ROVER_EXECUTE_PROBE_LOCATION => CommandSpecificExecute,
			ROVER_EXECUTE_TAKE_PHOTO => CommandSpecificExecute,
			ROVER_EXECUTE_STANDBY => CommandSpecificExecute,
			ROVER_COMMAND_COMPLETE => CommandAckSend
		},
		CommandSpecificExecute => {
			ROVER_COMMAND_COMPLETE => CommandAckSend
		},
		CommandAckSend => {
			ROVER_SEND_ACK => AckMarsRelayReceive
		},
		AckMarsRelayReceive => {
			MARS_RELAY_RECEIVE_ACK_FROM_ROVER => AckMarsRelayForward
		},
		AckMarsRelayForward => {
			MARS_RELAY_FORWARD_ACK_TO_EARTH => AckEarthRelayReceive
		},
		AckEarthRelayReceive => {
			EARTH_RELAY_RECEIVE_ACK_FROM_MARS => AckEarthRelayForward
		},
		AckEarthRelayForward => {
			EARTH_RELAY_FORWARD_ACK_TO_MC => AckMissionControlReceive
		},
		AckMissionControlReceive => {
			MISSION_CONTROL_RECEIVE_ACK => CommandIdle
		}
	}
	terminal { CommandIdle }
	timing {
		wcet: {
			MISSION_CONTROL_SEND_COMMAND => wcet!(Duration::from_millis(50)),
			EARTH_RELAY_RECEIVE_FROM_MC => wcet!(Duration::from_millis(50)),
			EARTH_RELAY_FORWARD_TO_MARS => wcet!(Duration::from_millis(50)),
			MARS_RELAY_RECEIVE_FROM_EARTH => wcet!(Duration::from_millis(50)),
			MARS_RELAY_FORWARD_TO_ROVER => wcet!(Duration::from_millis(50)),
			ROVER_RECEIVE_COMMAND => wcet!(Duration::from_millis(50)),
			ROVER_EXECUTE_COMMAND => wcet!(Duration::from_millis(500)),
			ROVER_COMMAND_COMPLETE => wcet!(Duration::from_millis(100)),
			ROVER_SEND_ACK => wcet!(Duration::from_millis(50))
		}
	}
}

// Mission Lifecycle and Fault Events
tb_process_spec! {
	pub DtnMissionLifecycle,
	events {
		observable {
			MISSION_START,
			FAULT_LOW_POWER_DETECTED,
			COMMS_HALTED,
			FAULT_CLEARED,
			MISSION_COMPLETE
		}
		hidden { }
	}
	states {
		LifecycleStart => {
			MISSION_START => LifecycleActive
		},
		LifecycleActive => {
			FAULT_LOW_POWER_DETECTED => LifecycleFault,
			MISSION_COMPLETE => LifecycleEnd
		},
		LifecycleFault => {
			COMMS_HALTED => LifecycleRecharging
		},
		LifecycleRecharging => {
			FAULT_CLEARED => LifecycleActive
		},
		LifecycleEnd => { }
	}
	terminal { LifecycleEnd }
}

// First compose telemetry and command flows
tb_compose_spec! {
	pub DtnDataFlows,
	processes: {
		DtnTelemetryFlow,
		DtnCommandFlow
	},
	composition: Interleaved,
	properties: {
		deadlock_free: true,
		livelock_free: true,
		deterministic: false
	},
	annotations {
		description: "DTN data flows (telemetry and commands) - fully asynchronous"
	}
}

// Then compose data flows with lifecycle
tb_compose_spec! {
	pub DtnComposedSystem,
	processes: {
		DtnDataFlows,
		DtnMissionLifecycle
	},
	composition: Interleaved,
	properties: {
		deadlock_free: true,
		livelock_free: true,
		deterministic: false
	},
	annotations {
		description: "DTN system with independent interleaved telemetry, command, and lifecycle flows"
	}
}

// Event Count Assertion Spec (4-Tier Architecture)
tb_assert_spec! {
	pub DtnEventCountSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			// Lifecycle
			(MISSION_START, exactly!(1)),
			(MISSION_COMPLETE, exactly!(1)),

			// Mission Control events
			(MISSION_CONTROL_SEND_COMMAND, exactly!(6)),
			(MISSION_CONTROL_RECEIVE_ACK, exactly!(6)),
			(MISSION_CONTROL_RECEIVE_TELEMETRY, exactly!(6)),
			(MISSION_CONTROL_ANALYZE_TELEMETRY, exactly!(6)),

			// Mission Control gap recovery
			(MISSION_CONTROL_GAP_DETECTED, at_most!(0)),
			(MISSION_CONTROL_SEND_FRAME_REQUEST, at_most!(0)),
			(MISSION_CONTROL_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(MISSION_CONTROL_SEND_FRAME_RESPONSE, at_most!(0)),
			(MISSION_CONTROL_RECEIVE_FRAME_RESPONSE, at_most!(0)),

			// Earth Relay events
			(EARTH_RELAY_RECEIVE_FROM_MC, exactly!(6)),
			(EARTH_RELAY_FORWARD_TO_MARS, exactly!(6)),
			(EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS, exactly!(6)),
			(EARTH_RELAY_RECEIVE_ACK_FROM_MARS, exactly!(6)),
			(EARTH_RELAY_FORWARD_TELEMETRY_TO_MC, exactly!(6)),
			(EARTH_RELAY_FORWARD_ACK_TO_MC, exactly!(6)),

			// Earth Relay gap recovery
			(EARTH_RELAY_GAP_DETECTED, at_most!(0)),
			(EARTH_RELAY_SEND_FRAME_REQUEST, at_most!(0)),
			(EARTH_RELAY_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(EARTH_RELAY_SEND_FRAME_RESPONSE, at_most!(0)),
			(EARTH_RELAY_RECEIVE_FRAME_RESPONSE, at_most!(0)),
			(EARTH_RELAY_CASCADE_FRAME_REQUEST, at_most!(0)),

			// Mars Relay events
			(MARS_RELAY_RECEIVE_FROM_EARTH, exactly!(6)),
			(MARS_RELAY_FORWARD_TO_ROVER, exactly!(6)),
			(MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER, exactly!(6)),
			(MARS_RELAY_RECEIVE_ACK_FROM_ROVER, exactly!(6)),
			(MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH, exactly!(6)),
			(MARS_RELAY_FORWARD_ACK_TO_EARTH, exactly!(6)),

			// Mars Relay gap recovery
			(MARS_RELAY_GAP_DETECTED, at_most!(0)),
			(MARS_RELAY_SEND_FRAME_REQUEST, at_most!(0)),
			(MARS_RELAY_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(MARS_RELAY_SEND_FRAME_RESPONSE, at_most!(0)),
			(MARS_RELAY_RECEIVE_FRAME_RESPONSE, at_most!(0)),
			(MARS_RELAY_CASCADE_FRAME_REQUEST, at_most!(0)),

			// Rover events
			(ROVER_RECEIVE_COMMAND, exactly!(6)),
			(ROVER_EXECUTE_COMMAND, exactly!(6)),
			(ROVER_COMMAND_COMPLETE, exactly!(6)),
			(ROVER_SEND_ACK, exactly!(6)),
			(ROVER_SEND_TELEMETRY, exactly!(6)),

			// Rover gap recovery
			(ROVER_GAP_DETECTED, at_most!(0)),
			(ROVER_SEND_FRAME_REQUEST, at_most!(0)),
			(ROVER_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(ROVER_SEND_FRAME_RESPONSE, at_most!(0)),
			(ROVER_RECEIVE_FRAME_RESPONSE, at_most!(0))
		]
	}
}

// ============================================================================
// Mission Loop Helpers
// ============================================================================

/// Build and send telemetry to Relay (one-way, no response expected)
/// Relay will forward to Earth Ground Station
async fn send_telemetry_to_mars_relay(
	trace: &TraceCollector,
	rover_client: &mut GenericClient<TokioListener>,
	rover_processor: &Arc<ChainProcessor>,
	rover_frame_builder: &Arc<FrameBuilderHelper>,
	fault_manager: &Arc<FaultManager>,
	rover_signing_key: &Secp256k1SigningKey,
	shared_cipher: &Aes256Gcm,
) -> Result<(), TightBeamError> {
	// Gather telemetry data (default instrument for periodic telemetry)
	let instrument = RoverInstrument::Apxs;
	let data = b"STATUS:OK".to_vec();
	let battery = fault_manager.battery_percent()?;
	let fault_matrix_snapshot = fault_manager.fault_matrix()?;

	trace.event(ROVER_SEND_TELEMETRY)?;

	let telemetry = RoverTelemetry::new(instrument, data, mission_time_ms(), battery, -20);
	let (next_order, previous_digest) = rover_processor.prepare_outgoing()?;
	let rover_frame = rover_frame_builder.build_relay_telemetry_frame(
		telemetry,
		fault_matrix_snapshot,
		next_order,
		previous_digest,
		rover_signing_key,
		shared_cipher,
	)?;

	// Send telemetry to Mars Relay (gets stateless ACK back)
	rover_client.emit(rover_frame, None).await?;

	Ok(())
}

/// Run the rover mission loop: sends telemetry periodically
///
/// Fully async architecture:
/// - Rover sends telemetry -> Satellite -> Earth
/// - Earth responds with command -> Satellite -> Rover
/// - Rover sends ACK -> Satellite -> Earth
/// - Rover executes command and sends next telemetry
#[allow(clippy::too_many_arguments)]
async fn run_mission_loop(
	trace: &TraceCollector,
	rover_client: &mut GenericClient<TokioListener>,
	rover_processor: &Arc<ChainProcessor>,
	rover_frame_builder: &Arc<FrameBuilderHelper>,
	fault_manager: &Arc<FaultManager>,
	rover_signing_key: &Secp256k1SigningKey,
	shared_cipher: &Aes256Gcm,
	shared_mission_state: &Arc<RwLock<MissionState>>,
) -> Result<(), TightBeamError> {
	let mut wait_iterations = 0;
	const MAX_WAIT_ITERATIONS: usize = 100;
	while shared_mission_state.read()?.completed_rounds < 1 {
		tokio::time::sleep(Duration::from_millis(100)).await;
		wait_iterations += 1;
		if wait_iterations >= MAX_WAIT_ITERATIONS {
			panic!("Timeout waiting for first command to arrive");
		}
	}

	// Loop exactly COMMAND_ROUND_TRIPS times (6 rounds)
	// We start from round 0 since we've completed command 0 and need to send its
	// telemetry
	for round in 0..COMMAND_ROUND_TRIPS {
		// Update battery state and check for faults
		let battery_update = fault_manager.update_battery_state()?;
		match battery_update {
			BatteryUpdate::LowPowerDetected(_battery) => {
				trace.event(FAULT_LOW_POWER_DETECTED)?;
				trace.event(COMMS_HALTED)?;

				advance_clock(delays::ROVER_RECHARGE_MS);

				// Re-energize battery to full
				while fault_manager.battery_percent()? < 100 {
					fault_manager.reenergize_battery()?;
				}

				trace.event(FAULT_CLEARED)?;
			}
			BatteryUpdate::FaultCleared(_battery) => {
				// Fault cleared
			}
			BatteryUpdate::Updated => {
				// Normal battery drain
				fault_manager.drain_battery()?;
			}
		}

		// Send telemetry to Mars Relay (which forwards to Earth Relay -> Mission
		// Control)
		send_telemetry_to_mars_relay(
			trace,
			rover_client,
			rover_processor,
			rover_frame_builder,
			fault_manager,
			rover_signing_key,
			shared_cipher,
		)
		.await?;

		// Advance clock for propagation delays (realistic but fast)
		advance_clock(delays::ROVER_TO_RELAY_MS);
		advance_clock(delays::RELAY_TO_EARTH_MS);

		// Wait for NEXT command to be executed by RoverServlet
		// (except for the last round where there's no next command)
		if round < COMMAND_ROUND_TRIPS - 1 {
			let target_completed = round + 2; // We've done command `round`, waiting for command `round+1`
			let mut wait_iterations = 0;
			const MAX_WAIT_ITERATIONS: usize = 100;
			while shared_mission_state.read()?.completed_rounds < target_completed {
				tokio::time::sleep(Duration::from_millis(100)).await;
				wait_iterations += 1;
				if wait_iterations >= MAX_WAIT_ITERATIONS {
					break;
				}
			}
		}
	}

	Ok(())
}

// ============================================================================
// Tests
// ============================================================================

/// Build FDR configuration for DTN testing
///
/// With the framework's dual-mode FDR:
/// 1. CSP spec exploration: Framework automatically explores DtnComposedSystem state space
/// 2. Trace refinement: Validates runtime trace against spec (via specs field)
fn build_dtn_fdr_config_refinement() -> FdrConfig {
	FdrConfig {
		seeds: 2, // Multiple seeds for exploring different interleavings of the CSP model
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 15000,
		specs: vec![DtnComposedSystem::process()], // Triggers trace refinement checking
		fail_fast: true,
		expect_failure: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: None,
		#[cfg(feature = "testing-fmea")]
		fmea_config: None,
	}
}

tb_scenario! {
	name: dtn_ultimate_realistic,
	config: ScenarioConf::builder()
		.with_spec(DtnEventCountSpec::latest())
		.with_csp(DtnComposedSystem)
		.with_fdr(build_dtn_fdr_config_refinement())
		.with_trace(TraceConfig::builder()
			.with_instrumentation(TbInstrumentationConfig {
				enable_payloads: false,
				enable_internal_detail: true,
				sample_enabled_sets: true,
				sample_refusals: true,
				divergence_heuristics: true,
				record_durations: true,
				max_events: 4096,
			})
			.with_logger(LoggerConfig::new(
				Box::new(StdoutBackend),
				LogFilter::new(LogLevel::Error)
			).with_default_level(LogLevel::Debug))
			.build()
			.into()
		)
		.build(),
	environment Servlet {
		context: DtnScenarioConfig::default(),
		start: |env| async move {
			let (trace, config) = (Arc::new(env.trace), env.context);
			// ================================================================
			// 4-TIER DTN ARCHITECTURE SETUP
			// Start: Rover -> Mars Relay -> Earth Relay -> Mission Control
			// This ensures each servlet has the addresses it needs to connect
			// ================================================================

			// ================================================================
			// SHARED COMPONENTS (from scenario config)
			// ================================================================
			let shared_cipher = config.shared_cipher.to_owned();
			let rover_signing_key = config.rover_signing_key.to_owned();
			let shared_mission_state = Arc::clone(&config.mission_state);
			let rover_processor = Arc::clone(&config.rover_chain_processor);

			// Verifying keys (shared across servlets)
			let mc_verifying_key = mission_control_verifying_key();
			let earth_relay_verifying_key_val = earth_relay_verifying_key();
			let mars_relay_verifying_key_val = mars_relay_verifying_key();
			let rover_verifying_key_val = rover_verifying_key();

			// ================================================================
			// SERVLET-SPECIFIC COMPONENTS (local to start block)
			// ================================================================

			// Mission Control: store, signing key, chain processor, frame builder
			let mc_key_bytes = match MISSION_CONTROL_KEY {
				SigningKeySpec::Bytes(bytes) => bytes,
				_ => panic!("MISSION_CONTROL_KEY must be KeySpec::Bytes"),
			};
			let mission_control_signing_key = Secp256k1SigningKey::from_slice(mc_key_bytes)?;
			let mc_store = Arc::new(RwLock::new(
				FrameStore::new(PathBuf::from("temp/dtn/mission_control"))?,
			));
			let mc_processor = Arc::new(ChainProcessor::new(
				Arc::clone(&mc_store),
				Arc::new(RwLock::new(MessageChainState::new("MissionControl".to_string()))),
				Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
			));
			let mc_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&mc_processor)));

			// Earth Relay: store, chain processor, frame builder
			let earth_relay_store = Arc::new(RwLock::new(
				FrameStore::new(PathBuf::from("temp/dtn/earth_relay"))?,
			));
			let earth_relay_processor = Arc::new(ChainProcessor::new(
				Arc::clone(&earth_relay_store),
				Arc::new(RwLock::new(MessageChainState::new("EarthRelay".to_string()))),
				Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
			));
			let earth_relay_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&earth_relay_processor)));

			// Mars Relay: store, chain processor, frame builder
			let mars_relay_store = Arc::new(RwLock::new(
				FrameStore::new(PathBuf::from("temp/dtn/mars_relay"))?,
			));
			let mars_relay_processor = Arc::new(ChainProcessor::new(
				Arc::clone(&mars_relay_store),
				Arc::new(RwLock::new(MessageChainState::new("MarsRelay".to_string()))),
				Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
			));
			let mars_relay_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&mars_relay_processor)));

			// Rover: frame builder (processor already created in Default)
			let rover_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&rover_processor)));

			// ================================================================
			// CONNECTION POOLS (per-destination with TLS and mutual auth)
			// ================================================================

			// Pool configuration for relay connections (max 3 per destination)
			let pool_config = PoolConfig { max_connections: 3, ..PoolConfig::default() };

			// Mission Control -> Earth Relay pool
			let mc_earth_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(EARTH_RELAY_CERT)?)
				.with_client_identity(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Earth Relay -> Mission Control pool
			let earth_mc_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(MISSION_CONTROL_CERT)?)
				.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Earth Relay -> Mars Relay pool
			let earth_mars_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(MARS_RELAY_CERT)?)
				.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Mars Relay -> Earth Relay pool
			let mars_earth_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(EARTH_RELAY_CERT)?)
				.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Mars Relay -> Rover pool
			let mars_rover_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(ROVER_CERT)?)
				.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Rover -> Mars Relay pool
			let rover_mars_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config)
				.with_trust_store(make_trust_store(MARS_RELAY_CERT)?)
				.with_client_identity(ROVER_CERT, ROVER_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// ================================================================
			// 1. START ROVER SERVLET
			// ================================================================

			let rover_fault_manager = Arc::new(FaultManager::from_refs(
				&config.bms,
				&config.fault_matrix,
				&config.rover_fault_handler,
			));

			let rover_config = RoverServletConf {
				mars_relay_addr: TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0))), // Placeholder
				mars_relay_pool: rover_mars_pool,
				rover_signing_key: rover_signing_key.to_owned(),
				mission_control_verifying_key: mc_verifying_key,
				mars_relay_verifying_key: mars_relay_verifying_key_val,
				shared_cipher: shared_cipher.to_owned(),
				chain_processor: Arc::clone(&rover_processor),
				_fault_manager: Arc::clone(&rover_fault_manager),
				frame_builder: Arc::clone(&rover_frame_builder),
				max_rounds: COMMAND_ROUND_TRIPS,
			};

			// Initialize workers for Rover
			let command_handler_worker = RoverCommandHandlerWorker::new(RoverCommandHandlerWorkerConf {
				mission_state: Arc::clone(&shared_mission_state),
			});
			let command_worker = CommandExecutionWorker::new(());
			let telemetry_worker = TelemetryBuilderWorker::new(TelemetryBuilderWorkerConf {
				default_battery: 85,
				default_temp: -63,
			});
			let rover_frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConf {
				chain_processor: Arc::clone(&rover_processor),
				can_cascade: false, // Rover is origin, cannot cascade
			});
			let rover_frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConf {
				chain_processor: Arc::clone(&rover_processor),
			});

			let rover_servlet_conf = tightbeam::colony::servlet::ServletConf::<TokioListener, RelayMessage>::builder()
				.with_certificate(ROVER_CERT, ROVER_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(ROVER_PINNING)])?
				.with_config(Arc::new(rover_config))
				.with_worker(command_handler_worker)
				.with_worker(command_worker)
				.with_worker(telemetry_worker)
				.with_worker(rover_frame_request_handler_worker)
				.with_worker(rover_frame_response_handler_worker)
				.build();
			let rover_servlet = RoverServlet::start(Arc::clone(&trace), Some(rover_servlet_conf)).await?;
			let rover_addr = rover_servlet.addr();

			// Store rover address
			config.rover_addr.write()?.replace(rover_addr);

			// ================================================================
			// 2. START MARS RELAY SERVLET
			// ================================================================

			// Extract Mars Relay signing key
			let mars_relay_key_bytes = match MARS_RELAY_KEY {
				SigningKeySpec::Bytes(bytes) => bytes,
				_ => panic!("MARS_RELAY_KEY must be KeySpec::Bytes"),
			};
			let mars_relay_signing_key = Secp256k1SigningKey::from_slice(mars_relay_key_bytes)?;

			// Mars Relay needs earth_relay_addr which we don't have yet
			// We'll use an Arc<RwLock<Option<>>> pattern and update it after Earth Relay starts
			let mars_earth_relay_addr = Arc::new(RwLock::new(None));
			let mars_relay_config = MarsRelaySatelliteServletConf {
				mars_relay_signing_key: mars_relay_signing_key.to_owned(),
				mission_control_verifying_key: mc_verifying_key,
				earth_relay_verifying_key: earth_relay_verifying_key_val,
				rover_verifying_key: rover_verifying_key_val,
				shared_cipher: shared_cipher.to_owned(),
				rover_addr,
				earth_relay_addr: Arc::clone(&mars_earth_relay_addr),
				earth_relay_pool: mars_earth_pool,
				rover_pool: mars_rover_pool,
				chain_processor: Arc::clone(&mars_relay_processor),
				frame_builder: Arc::clone(&mars_relay_frame_builder),
			};

			// Initialize workers for Mars Relay
			let mars_frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConf {
				chain_processor: Arc::clone(&mars_relay_processor),
				can_cascade: true, // Mars Relay can cascade in both directions
			});
			let mars_frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConf {
				chain_processor: Arc::clone(&mars_relay_processor),
			});

			let mars_relay_servlet_conf = tightbeam::colony::servlet::ServletConf::<TokioListener, RelayMessage>::builder()
				.with_certificate(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(MARS_RELAY_PINNING)])?
				.with_config(Arc::new(mars_relay_config))
				.with_worker(mars_frame_request_handler_worker)
				.with_worker(mars_frame_response_handler_worker)
				.build();
			let mars_relay_servlet_conf = Some(mars_relay_servlet_conf);
			let mars_relay_servlet = MarsRelaySatelliteServlet::start(Arc::clone(&trace), mars_relay_servlet_conf).await?;
			let mars_relay_addr = mars_relay_servlet.addr();

			// Store Mars Relay servlet and address
			config._mars_relay_servlet.write()?.replace(mars_relay_servlet);
			config.mars_relay_addr.write()?.replace(mars_relay_addr);

			// ================================================================
			// 3. START EARTH RELAY SERVLET
			// ================================================================

			// Extract Earth Relay signing key
			let earth_relay_key_bytes = match EARTH_RELAY_KEY {
				SigningKeySpec::Bytes(bytes) => bytes,
				_ => panic!("EARTH_RELAY_KEY must be KeySpec::Bytes"),
			};
			let earth_relay_signing_key = Secp256k1SigningKey::from_slice(earth_relay_key_bytes)?;

			// Earth Relay needs mission_control_addr which we don't have yet
			let earth_mission_control_addr = Arc::new(RwLock::new(None));
			let earth_relay_config = EarthRelaySatelliteServletConf {
				earth_relay_signing_key: earth_relay_signing_key.to_owned(),
				mission_control_verifying_key: mc_verifying_key,
				mars_relay_verifying_key: mars_relay_verifying_key_val,
				rover_verifying_key: rover_verifying_key_val,
				shared_cipher: shared_cipher.to_owned(),
				mars_relay_addr, // Now we have the real address!
				mission_control_addr: Arc::clone(&earth_mission_control_addr),
				mission_control_pool: earth_mc_pool,
				mars_relay_pool: earth_mars_pool,
				chain_processor: Arc::clone(&earth_relay_processor),
				frame_builder: Arc::clone(&earth_relay_frame_builder),
			};

			// Initialize workers for Earth Relay
			let earth_frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConf {
				chain_processor: Arc::clone(&earth_relay_processor),
				can_cascade: true, // Earth Relay can cascade in both directions
			});
			let earth_frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConf {
				chain_processor: Arc::clone(&earth_relay_processor),
			});

			let earth_relay_servlet_conf = tightbeam::colony::servlet::ServletConf::<TokioListener, RelayMessage>::builder()
				.with_certificate(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(EARTH_RELAY_PINNING)])?
				.with_config(Arc::new(earth_relay_config))
				.with_worker(earth_frame_request_handler_worker)
				.with_worker(earth_frame_response_handler_worker)
				.build();
			let earth_relay_servlet_conf = Some(earth_relay_servlet_conf);
			let earth_relay_servlet = EarthRelaySatelliteServlet::start(Arc::clone(&trace), earth_relay_servlet_conf).await?;
			let earth_relay_addr = earth_relay_servlet.addr();

			// Update Mars Relay's earth_relay_addr
			*mars_earth_relay_addr.write()? = Some(earth_relay_addr);

			// Store Earth Relay servlet and address
			config._earth_relay_servlet.write()?.replace(earth_relay_servlet);
			config.earth_relay_addr.write()?.replace(earth_relay_addr);

			// ================================================================
			// 4. START MISSION CONTROL SERVLET
			// ================================================================

			let mc_config = MissionControlServletConf {
				mission_control_signing_key: mission_control_signing_key.to_owned(),
				rover_verifying_key: rover_verifying_key_val,
				earth_relay_verifying_key: earth_relay_verifying_key_val,
				shared_cipher: shared_cipher.to_owned(),
				chain_processor: Arc::clone(&mc_processor),
				frame_builder: Arc::clone(&mc_frame_builder),
				earth_relay_addr, // Real address!
				earth_relay_pool: mc_earth_pool,
			};

			// Initialize workers for Mission Control
			let telemetry_handler_worker = MissionControlTelemetryHandlerWorker::new(MissionControlTelemetryHandlerWorkerConf {
				mission_state: Arc::clone(&shared_mission_state),
				max_commands: COMMAND_ROUND_TRIPS as u64,
			});
			let frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConf {
				chain_processor: Arc::clone(&mc_processor),
				can_cascade: false, // Mission Control is origin, cannot cascade
			});
			let frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConf {
				chain_processor: Arc::clone(&mc_processor),
			});
			let command_ack_handler_worker = CommandAckHandlerWorker::new(());

			let mc_servlet_conf = tightbeam::colony::servlet::ServletConf::<TokioListener, RelayMessage>::builder()
				.with_certificate(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(MISSION_CONTROL_PINNING)])?
				.with_config(Arc::new(mc_config))
				.with_worker(telemetry_handler_worker)
				.with_worker(frame_request_handler_worker)
				.with_worker(frame_response_handler_worker)
				.with_worker(command_ack_handler_worker)
				.build();
			let mc_servlet = MissionControlServlet::start(Arc::clone(&trace), Some(mc_servlet_conf)).await?;
			let mc_addr = mc_servlet.addr();

			// Update Earth Relay's mission_control_addr
			*earth_mission_control_addr.write()? = Some(mc_addr);

			// Store Mission Control servlet and address
			config._mission_control_servlet.write()?.replace(mc_servlet);
			config.mission_control_addr.write()?.replace(mc_addr);

			// ================================================================
			// 5. INITIALIZE MISSION CLOCK
			// ================================================================

			init_mission_clock();
			trace.event(MISSION_START)?;

			// ================================================================
			// 6. SEND INITIAL COMMAND FROM MISSION CONTROL
			// ================================================================

			{
				let initial_cmd = RoverCommand::ProbeLocation { x: 100, y: 200 };
				let (next_order, previous_digest) = mc_processor.prepare_outgoing()?;
				let command = EarthCommand::new(initial_cmd, MessagePriority::Standard, mission_time_ms());

				trace.event(MISSION_CONTROL_SEND_COMMAND)?;

				let command_frame = mc_frame_builder.build_relay_command_frame(
					command,
					next_order,
					previous_digest,
					&mission_control_signing_key,
					&shared_cipher,
				)?;

				// Connect to Earth Relay and send initial command
				let mut earth_relay_client = ClientBuilder::<TokioListener>::builder()
					.with_trust_store(make_trust_store(EARTH_RELAY_CERT)?)
					.with_client_identity(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?)?
					.with_timeout(Duration::from_millis(5000))
					.build()
					.connect(earth_relay_addr)
					.await?;

				earth_relay_client.emit(command_frame, None).await?;
			}

			Ok(rover_servlet)
		},
		setup: |env| async move {
			let config = env.context;
			let mars_relay_addr = (*config.mars_relay_addr.read()?).ok_or(TightBeamError::MissingConfiguration)?;

			// Connect Rover client to Mars Relay
			let client = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_trust_store(MARS_RELAY_CERT)?)
				.with_client_identity(ROVER_CERT, ROVER_KEY.to_provider::<Secp256k1>()?)?
				.with_timeout(Duration::from_millis(5000))
				.build()
				.connect(mars_relay_addr)
				.await?;

			Ok(client)
		},
		client: |env| async move {
			let (trace, mut rover_client, config) = (env.trace, env.client, env.context);
			// Get components from config
			let rover_processor = Arc::clone(&config.rover_chain_processor);
			let rover_fault_manager = Arc::new(FaultManager::from_refs(
				&config.bms,
				&config.fault_matrix,
				&config.rover_fault_handler,
			));
			let rover_signing_key = config.rover_signing_key.to_owned();
			let shared_cipher = config.shared_cipher.to_owned();
			let shared_mission_state = Arc::clone(&config.mission_state);
			let rover_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&rover_processor)));

			// Run mission loop (sends telemetry to Mars Relay)
			run_mission_loop(
				&trace,
				&mut rover_client,
				&rover_processor,
				&rover_frame_builder,
				&rover_fault_manager,
				&rover_signing_key,
				&shared_cipher,
				&shared_mission_state,
			).await?;

			trace.event(MISSION_COMPLETE)?;

			Ok(())
		}
	}
}
