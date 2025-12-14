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
//! - Graceful fault handling (low power → recharge → resume)
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
		key::SigningKeySpec,
		sign::ecdsa::{Secp256k1, Secp256k1SigningKey},
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
	wcet,
};

use crate::dtn::messages::RoverInstrument;
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

// Telemetry Flow: Rover → Mars Relay → Earth Relay → Mission Control
tb_process_spec! {
	pub DtnTelemetryFlow,
	events {
		observable {
			"rover_send_telemetry",
			"mars_relay_receive_telemetry_from_rover",
			"mars_relay_forward_telemetry_to_earth",
			"earth_relay_receive_telemetry_from_mars",
			"earth_relay_forward_telemetry_to_mc",
			"mission_control_receive_telemetry",
			"mission_control_analyze_telemetry"
		}
		hidden { }
	}
	states {
		TelemetryIdle => {
			"rover_send_telemetry" => TelemetryMarsRelayReceive
		},
		TelemetryMarsRelayReceive => {
			"mars_relay_receive_telemetry_from_rover" => TelemetryMarsRelayForward
		},
		TelemetryMarsRelayForward => {
			"mars_relay_forward_telemetry_to_earth" => TelemetryEarthRelayReceive
		},
		TelemetryEarthRelayReceive => {
			"earth_relay_receive_telemetry_from_mars" => TelemetryEarthRelayForward
		},
		TelemetryEarthRelayForward => {
			"earth_relay_forward_telemetry_to_mc" => TelemetryMissionControlReceive
		},
		TelemetryMissionControlReceive => {
			"mission_control_receive_telemetry" => TelemetryMissionControlAnalyze
		},
		TelemetryMissionControlAnalyze => {
			"mission_control_analyze_telemetry" => TelemetryIdle
		}
	}
	terminal { TelemetryIdle }
	timing {
		wcet: {
			"rover_send_telemetry" => wcet!(Duration::from_millis(100)),
			"mars_relay_receive_telemetry_from_rover" => wcet!(Duration::from_millis(50)),
			"mars_relay_forward_telemetry_to_earth" => wcet!(Duration::from_millis(50)),
			"earth_relay_receive_telemetry_from_mars" => wcet!(Duration::from_millis(50)),
			"earth_relay_forward_telemetry_to_mc" => wcet!(Duration::from_millis(50)),
			"mission_control_receive_telemetry" => wcet!(Duration::from_millis(50)),
			"mission_control_analyze_telemetry" => wcet!(Duration::from_millis(200))
		}
	}
}

// Command Flow: Mission Control → Earth Relay → Mars Relay → Rover → ACK back
tb_process_spec! {
	pub DtnCommandFlow,
	events {
		observable {
			"mission_control_send_command",
			"earth_relay_receive_from_mc",
			"earth_relay_forward_to_mars",
			"mars_relay_receive_from_earth",
			"mars_relay_forward_to_rover",
			"rover_receive_command",
			"rover_execute_command",
			"rover_execute_collect_sample",
			"rover_execute_probe_location",
			"rover_execute_take_photo",
			"rover_execute_standby",
			"rover_command_complete",
			"rover_send_ack",
			"mars_relay_receive_ack_from_rover",
			"mars_relay_forward_ack_to_earth",
			"earth_relay_receive_ack_from_mars",
			"earth_relay_forward_ack_to_mc",
			"mission_control_receive_ack"
		}
		hidden { }
	}
	states {
		CommandIdle => {
			"mission_control_send_command" => CommandEarthRelayReceive
		},
		CommandEarthRelayReceive => {
			"earth_relay_receive_from_mc" => CommandEarthRelayForward
		},
		CommandEarthRelayForward => {
			"earth_relay_forward_to_mars" => CommandMarsRelayReceive
		},
		CommandMarsRelayReceive => {
			"mars_relay_receive_from_earth" => CommandMarsRelayForward
		},
		CommandMarsRelayForward => {
			"mars_relay_forward_to_rover" => CommandRoverReceive
		},
		CommandRoverReceive => {
			"rover_receive_command" => CommandExecuting
		},
		CommandExecuting => {
			"rover_execute_command" => CommandExecuted
		},
		CommandExecuted => {
			"rover_execute_collect_sample" => CommandSpecificExecute,
			"rover_execute_probe_location" => CommandSpecificExecute,
			"rover_execute_take_photo" => CommandSpecificExecute,
			"rover_execute_standby" => CommandSpecificExecute,
			"rover_command_complete" => CommandAckSend
		},
		CommandSpecificExecute => {
			"rover_command_complete" => CommandAckSend
		},
		CommandAckSend => {
			"rover_send_ack" => AckMarsRelayReceive
		},
		AckMarsRelayReceive => {
			"mars_relay_receive_ack_from_rover" => AckMarsRelayForward
		},
		AckMarsRelayForward => {
			"mars_relay_forward_ack_to_earth" => AckEarthRelayReceive
		},
		AckEarthRelayReceive => {
			"earth_relay_receive_ack_from_mars" => AckEarthRelayForward
		},
		AckEarthRelayForward => {
			"earth_relay_forward_ack_to_mc" => AckMissionControlReceive
		},
		AckMissionControlReceive => {
			"mission_control_receive_ack" => CommandIdle
		}
	}
	terminal { CommandIdle }
	timing {
		wcet: {
			"mission_control_send_command" => wcet!(Duration::from_millis(50)),
			"earth_relay_receive_from_mc" => wcet!(Duration::from_millis(50)),
			"earth_relay_forward_to_mars" => wcet!(Duration::from_millis(50)),
			"mars_relay_receive_from_earth" => wcet!(Duration::from_millis(50)),
			"mars_relay_forward_to_rover" => wcet!(Duration::from_millis(50)),
			"rover_receive_command" => wcet!(Duration::from_millis(50)),
			"rover_execute_command" => wcet!(Duration::from_millis(500)),
			"rover_command_complete" => wcet!(Duration::from_millis(100)),
			"rover_send_ack" => wcet!(Duration::from_millis(50))
		}
	}
}

// Mission Lifecycle and Fault Events
tb_process_spec! {
	pub DtnMissionLifecycle,
	events {
		observable {
			"mission_start",
			"fault_low_power_detected",
			"comms_halted",
			"fault_cleared",
			"mission_complete"
		}
		hidden { }
	}
	states {
		LifecycleStart => {
			"mission_start" => LifecycleActive
		},
		LifecycleActive => {
			"fault_low_power_detected" => LifecycleFault,
			"mission_complete" => LifecycleEnd
		},
		LifecycleFault => {
			"comms_halted" => LifecycleRecharging
		},
		LifecycleRecharging => {
			"fault_cleared" => LifecycleActive
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
		gate: Accepted,
		assertions: [
			// Lifecycle
			("mission_start", exactly!(1)),
			("mission_complete", exactly!(1)),

			// Mission Control events
			("mission_control_send_command", exactly!(6)),
			("mission_control_receive_ack", exactly!(6)),
			("mission_control_receive_telemetry", exactly!(6)),
			("mission_control_analyze_telemetry", exactly!(6)),

			// Mission Control gap recovery
			("mission_control_gap_detected", at_most!(0)),
			("mission_control_send_frame_request", at_most!(0)),
			("mission_control_receive_frame_request", at_most!(0)),
			("mission_control_send_frame_response", at_most!(0)),
			("mission_control_receive_frame_response", at_most!(0)),

			// Earth Relay events
			("earth_relay_receive_from_mc", exactly!(6)),
			("earth_relay_forward_to_mars", exactly!(6)),
			("earth_relay_receive_telemetry_from_mars", exactly!(6)),
			("earth_relay_receive_ack_from_mars", exactly!(6)),
			("earth_relay_forward_telemetry_to_mc", exactly!(6)),
			("earth_relay_forward_ack_to_mc", exactly!(6)),

			// Earth Relay gap recovery
			("earth_relay_gap_detected", at_most!(0)),
			("earth_relay_send_frame_request", at_most!(0)),
			("earth_relay_receive_frame_request", at_most!(0)),
			("earth_relay_send_frame_response", at_most!(0)),
			("earth_relay_receive_frame_response", at_most!(0)),
			("earth_relay_cascade_frame_request", at_most!(0)),

			// Mars Relay events
			("mars_relay_receive_from_earth", exactly!(6)),
			("mars_relay_forward_to_rover", exactly!(6)),
			("mars_relay_receive_telemetry_from_rover", exactly!(6)),
			("mars_relay_receive_ack_from_rover", exactly!(6)),
			("mars_relay_forward_telemetry_to_earth", exactly!(6)),
			("mars_relay_forward_ack_to_earth", exactly!(6)),

			// Mars Relay gap recovery
			("mars_relay_gap_detected", at_most!(0)),
			("mars_relay_send_frame_request", at_most!(0)),
			("mars_relay_receive_frame_request", at_most!(0)),
			("mars_relay_send_frame_response", at_most!(0)),
			("mars_relay_receive_frame_response", at_most!(0)),
			("mars_relay_cascade_frame_request", at_most!(0)),

			// Rover events
			("rover_receive_command", exactly!(6)),
			("rover_execute_command", exactly!(6)),
			("rover_command_complete", exactly!(6)),
			("rover_send_ack", exactly!(6)),
			("rover_send_telemetry", exactly!(6)),

			// Rover gap recovery
			("rover_gap_detected", at_most!(0)),
			("rover_send_frame_request", at_most!(0)),
			("rover_receive_frame_request", at_most!(0)),
			("rover_send_frame_response", at_most!(0)),
			("rover_receive_frame_response", at_most!(0))
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

	trace.event("rover_send_telemetry")?;

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
/// - Rover sends telemetry → Satellite → Earth
/// - Earth responds with command → Satellite → Rover
/// - Rover sends ACK → Satellite → Earth
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
				trace.event("fault_low_power_detected")?;
				trace.event("comms_halted")?;

				advance_clock(delays::ROVER_RECHARGE_MS);

				// Re-energize battery to full
				while fault_manager.battery_percent()? < 100 {
					fault_manager.reenergize_battery()?;
				}

				trace.event("fault_cleared")?;
			}
			BatteryUpdate::FaultCleared(_battery) => {
				// Fault cleared
			}
			BatteryUpdate::Updated => {
				// Normal battery drain
				fault_manager.drain_battery()?;
			}
		}

		// Send telemetry to Mars Relay (which forwards to Earth Relay → Mission
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
	config: ScenarioConf::<DtnScenarioConfig>::builder()
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
		.with_env_config(DtnScenarioConfig::default())
		.build(),
	environment Servlet {
		servlet: RoverServlet,
		start: |trace, config| async move {
			// ================================================================
			// 4-TIER DTN ARCHITECTURE SETUP
			// Start: Rover → Mars Relay → Earth Relay → Mission Control
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
			let pool_config = PoolConfig { idle_timeout: None, max_connections: 3 };

			// Mission Control → Earth Relay pool
			let mc_earth_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.clone())
				.with_server_certificate(EARTH_RELAY_CERT)?
				.with_client_identity(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Earth Relay → Mission Control pool
			let earth_mc_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.clone())
				.with_server_certificate(MISSION_CONTROL_CERT)?
				.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Earth Relay → Mars Relay pool
			let earth_mars_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.clone())
				.with_server_certificate(MARS_RELAY_CERT)?
				.with_client_identity(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Mars Relay → Earth Relay pool
			let mars_earth_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.clone())
				.with_server_certificate(EARTH_RELAY_CERT)?
				.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Mars Relay → Rover pool
			let mars_rover_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.clone())
				.with_server_certificate(ROVER_CERT)?
				.with_client_identity(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?)?
				.build());

			// Rover → Mars Relay pool
			let rover_mars_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config)
				.with_server_certificate(MARS_RELAY_CERT)?
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
			trace.event("mission_start")?;

			// ================================================================
			// 6. SEND INITIAL COMMAND FROM MISSION CONTROL
			// ================================================================

			{
				let initial_cmd = RoverCommand::ProbeLocation { x: 100, y: 200 };
				let (next_order, previous_digest) = mc_processor.prepare_outgoing()?;
				let command = EarthCommand::new(initial_cmd, MessagePriority::Normal, mission_time_ms());

				trace.event("mission_control_send_command")?;

				let command_frame = mc_frame_builder.build_relay_command_frame(
					command,
					next_order,
					previous_digest,
					&mission_control_signing_key,
					&shared_cipher,
				)?;

				// Connect to Earth Relay and send initial command
				let mut earth_relay_client = ClientBuilder::<TokioListener>::builder()
					.with_server_certificate(EARTH_RELAY_CERT)?
					.with_client_identity(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?)?
					.with_timeout(Duration::from_millis(5000))
					.build()
					.connect(earth_relay_addr)
					.await?;

				earth_relay_client.emit(command_frame, None).await?;
			}

			Ok(rover_servlet)
		},
		setup: |_rover_addr, config: Arc<DtnScenarioConfig>| async move {
			let mars_relay_addr = (*config.mars_relay_addr.read()?).expect("Mars Relay address must be set");
			// Connect Rover client to Mars Relay
			let client = ClientBuilder::<TokioListener>::builder()
				.with_server_certificate(MARS_RELAY_CERT)?
				.with_client_identity(ROVER_CERT, ROVER_KEY.to_provider::<Secp256k1>()?)?
				.with_timeout(Duration::from_millis(5000))
				.build()
				.connect(mars_relay_addr)
				.await?;

			Ok(client)
		},
		client: |trace, mut rover_client, config| async move {
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

			trace.event("mission_complete")?;

			Ok(())
		}
	}
}
