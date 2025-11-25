//! DTN Ultimate Test - Mission-Critical Framework Demonstration
//!
//! ## Scenario: Mars Rover → Relay Satellite → Earth Ground Station
//!
//! This test demonstrates a realistic 3-tier DTN architecture with:
//! - Realistic NASA-inspired rover telemetry (APXS, ChemCam, Mastcam)
//! - Earth command & control
//! - Simulated mission clock with realistic Mars-Earth delays (~25 min round-trip)
//! - 2/3 consensus validation using previous_frame hash chains
//! - UUID-based message IDs for idempotence
//! - Matrix bit field for rover fault flags
//! - Graceful fault handling (low power → recharge → resume)
//!
//! ## Realistic Timeline
//! - T+0: Rover sends APXS telemetry
//! - T+1.5s: Relay receives
//! - T+12.5min: Earth receives
//! - T+25min: Rover receives Earth's command
//! - T+25min: Low power fault detected
//! - T+55min: Recharge complete, resume operations
//!
//! ## Debug Logging
//!
//! Set the `TIGHTBEAM_DEBUG` environment variable to see detailed execution logs:
//!
//! ```bash
//! TIGHTBEAM_DEBUG=1 cargo test --features=... dtn_ultimate_realistic -- --nocapture
//! ```
//!
//! Without this variable, only critical events are logged.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand_core::OsRng;

use tightbeam::{
	asn1::MessagePriority,
	crypto::{
		aead::Aes256Gcm,
		key::KeySpec,
		sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey},
	},
	error::TightBeamError,
	exactly,
	macros::client::builder::{ClientBuilder, GenericClient},
	prelude::*,
	tb_assert_spec, tb_compose_spec, tb_process_spec, tb_scenario,
	testing::{fdr::FdrConfig, specs::composition::CompositionSpec},
	trace::TraceCollector,
	transport::{policy::RestartExponentialBackoff, tcp::r#async::TokioListener},
};

use crate::{
	debug_log,
	dtn::{
		bms::BatteryManagementSystem,
		certs::{
			generate_shared_cipher, rover_verifying_key, EARTH_CERT, EARTH_KEY, ROVER_CERT, ROVER_KEY, SATELLITE_CERT,
		},
		chain_processor::ChainProcessor,
		clock::{advance_clock, delays, init_mission_clock, mission_time_ms},
		command_executor::CommandExecutor,
		fault_manager::{BatteryUpdate, FaultManager},
		fault_matrix::FaultMatrix,
		faults::RoverFaultHandler,
		frame_builder::FrameBuilderHelper,
		messages::{EarthCommand, MessageChainState, RoverCommand, RoverTelemetry},
		ordering::OutOfOrderBuffer,
		servlets::{
			EarthGroundStationServlet, EarthGroundStationServletConf, MissionState, RelaySatelliteServlet,
			RelaySatelliteServletConf, RoverServlet, RoverServletConf,
		},
		storage::FrameStore,
		utils::format_mission_time,
	},
};

// ============================================================================
// DTN Scenario Configuration
// ============================================================================

/// Configuration for DTN scenario with cryptographic keys and chain state
pub struct DtnScenarioConfig {
	/// Rover's signing key for nonrepudiation
	pub rover_signing_key: Secp256k1SigningKey,
	/// Shared AES-256-GCM cipher (Earth ↔ Rover only)
	pub shared_cipher: Aes256Gcm,
	/// Earth's verifying key for signature verification (set by servlet start)
	pub earth_verifying_key: RwLock<Option<Secp256k1VerifyingKey>>,
	/// Battery Management System
	pub bms: RwLock<BatteryManagementSystem>,
	/// Fault handler for recovery logic (time tracking, decisions)
	pub rover_fault_handler: RwLock<RoverFaultHandler>,
	/// Current fault state (encapsulated encoding/decoding)
	pub fault_matrix: RwLock<FaultMatrix>,
	/// Frame storage for Rover
	pub rover_store: RwLock<FrameStore>,
	/// Frame storage for Earth
	pub earth_store: RwLock<FrameStore>,
	/// Frame storage for Relay
	pub relay_store: RwLock<FrameStore>,
	/// Relay address for rover client to connect to
	pub relay_addr: RwLock<Option<TightBeamSocketAddr>>,
	/// Shared mission state between RoverServlet and mission loop
	pub mission_state: Arc<RwLock<MissionState>>,
	/// Rover servlet address for async commands
	pub rover_addr: RwLock<Option<TightBeamSocketAddr>>,
	/// Relay servlet handle (keeps the servlet task alive)
	pub _relay_servlet: RwLock<Option<RelaySatelliteServlet>>,
	/// Earth servlet handle (keeps the servlet task alive)
	pub _earth_servlet: RwLock<Option<EarthGroundStationServlet>>,
	/// Command queue for async command execution on Rover
	pub command_queue: Arc<RwLock<VecDeque<EarthCommand>>>,
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		// Create storage directories (fail fast)
		let rover_store = FrameStore::new(PathBuf::from("temp/dtn/rover")).expect("Failed to create rover storage");
		let earth_store = FrameStore::new(PathBuf::from("temp/dtn/earth")).expect("Failed to create earth storage");
		let relay_store = FrameStore::new(PathBuf::from("temp/dtn/relay")).expect("Failed to create relay storage");

		let rover_key_bytes = match ROVER_KEY {
			KeySpec::Bytes(bytes) => bytes,
			_ => panic!("ROVER_KEY must be KeySpec::Bytes"),
		};

		Self {
			rover_signing_key: Secp256k1SigningKey::from_slice(rover_key_bytes).expect("ROVER_KEY is valid"),
			shared_cipher: generate_shared_cipher(),
			earth_verifying_key: RwLock::new(None),
			bms: RwLock::new(BatteryManagementSystem::default()),
			rover_fault_handler: RwLock::new(RoverFaultHandler::new()),
			fault_matrix: RwLock::new(FaultMatrix::new()),
			rover_store: RwLock::new(rover_store),
			earth_store: RwLock::new(earth_store),
			relay_store: RwLock::new(relay_store),
			relay_addr: RwLock::new(None),
			rover_addr: RwLock::new(None),
			_relay_servlet: RwLock::new(None),
			_earth_servlet: RwLock::new(None),
			command_queue: Arc::new(RwLock::new(VecDeque::new())),
			mission_state: Arc::new(RwLock::new(MissionState::default())),
		}
	}
}

impl Drop for DtnScenarioConfig {
	fn drop(&mut self) {
		// Shutdown servlets gracefully
		debug_log!("[Cleanup] Shutting down servlets...");

		// Access and drop Earth servlet
		if let Ok(mut servlet_guard) = self._earth_servlet.write() {
			if let Some(_servlet) = servlet_guard.take() {
				debug_log!("[Cleanup] Earth servlet stopped");
			}
		}

		// Access and drop Relay servlet
		if let Ok(mut servlet_guard) = self._relay_servlet.write() {
			if let Some(_servlet) = servlet_guard.take() {
				debug_log!("[Cleanup] Relay servlet stopped");
			}
		}

		// Clean up storage directories
		if let Ok(mut store) = self.rover_store.write() {
			let _ = store.clear();
		}
		if let Ok(mut store) = self.earth_store.write() {
			let _ = store.clear();
		}
		if let Ok(mut store) = self.relay_store.write() {
			let _ = store.clear();
		}

		// Remove storage directories
		let _ = std::fs::remove_dir_all("temp/dtn/rover");
		let _ = std::fs::remove_dir_all("temp/dtn/earth");
		let _ = std::fs::remove_dir_all("temp/dtn/relay");
		let _ = std::fs::remove_dir_all("temp/dtn");

		debug_log!("[Cleanup] DTN test cleanup complete");
	}
}

// ============================================================================
// Test Configuration
// ============================================================================

/// Number of command/response round-trips for the test.
const COMMAND_ROUND_TRIPS: usize = 6;

/// Earth Mission Control task: sends commands to Relay (which forwards to Rover)
async fn earth_mission_control_task(
	trace: Arc<TraceCollector>,
	relay_addr: TightBeamSocketAddr,
	earth_signing_key: Secp256k1SigningKey,
	shared_cipher: Aes256Gcm,
	earth_processor: Arc<ChainProcessor>,
	frame_builder: Arc<FrameBuilderHelper>,
	max_rounds: usize,
) -> Result<(), TightBeamError> {
	println!("[Earth Mission Control] Task STARTING - {} rounds", max_rounds);

	debug_log!(
		"[{}] [Earth Mission Control] Task started - {} rounds",
		format_mission_time(mission_time_ms()),
		max_rounds
	);

	for round in 0..max_rounds {
		println!("[Earth Mission Control] Round {}/{}", round + 1, max_rounds);
		debug_log!(
			"[{}] [Earth Mission Control] Preparing command {}/{}",
			format_mission_time(mission_time_ms()),
			round + 1,
			max_rounds
		);

		let rover_cmd = match round % 3 {
			0 => RoverCommand::ProbeLocation { x: 100, y: 200 },
			1 => RoverCommand::TakePhoto { direction: "North".to_string(), resolution: 1080 },
			_ => RoverCommand::CollectSample { location: "Site Alpha".to_string() },
		};

		trace.event("earth_send_command")?;

		println!("[Earth Mission Control] Building command");
		let earth_command = EarthCommand::new(rover_cmd, MessagePriority::Normal, mission_time_ms());
		println!("[Earth Mission Control] Preparing outgoing frame");
		let (next_order, previous_digest) = earth_processor.prepare_outgoing()?;
		println!("[Earth Mission Control] Building relay command frame");
		let command_frame = frame_builder.build_relay_command_frame(
			earth_command,
			next_order,
			previous_digest,
			&earth_signing_key,
			&shared_cipher,
		)?;
		println!("[Earth Mission Control] Command frame built");

		debug_log!(
			"[{}] [Earth Mission Control] Sending command {}/{} to Relay",
			format_mission_time(mission_time_ms()),
			round + 1,
			max_rounds
		);

		// Connect to Relay and send command
		println!("[Earth Mission Control] Connecting to Relay at {:?}", relay_addr);
		let mut relay_client = ClientBuilder::<TokioListener>::connect(relay_addr)
			.await?
			.with_server_certificate(SATELLITE_CERT)?
			.with_client_identity(EARTH_CERT, EARTH_KEY)?
			.with_timeout(Duration::from_millis(5000))
			.build()?;

		println!("[Earth Mission Control] Sending command frame to Relay");
		let _response = relay_client.emit(command_frame, None).await?;
		println!("[Earth Mission Control] Command sent successfully");
		debug_log!(
			"[{}] [Earth Mission Control] Command {}/{} sent",
			format_mission_time(mission_time_ms()),
			round + 1,
			max_rounds
		);

		// Wait between commands (simulate realistic operations tempo)
		tokio::time::sleep(Duration::from_millis(2000)).await;
	}

	debug_log!(
		"[{}] [Earth Mission Control] All commands sent",
		format_mission_time(mission_time_ms())
	);
	Ok(())
}

// ============================================================================
// Assertion Specification
// ============================================================================

tb_assert_spec! {
	pub DtnRealisticSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			// Lifecycle
			("mission_start", exactly!(1)),
			("mission_complete", exactly!(1)),

			// Earth events (async architecture)
			("earth_send_command", exactly!(6)),

			// Relay events (bidirectional async)
			("relay_receive_from_earth", exactly!(6)),
			("relay_forward_downlink", exactly!(6)),

			// Rover events (async command reception)
			("rover_receive_async_command", exactly!(6)),
			("rover_command_complete", exactly!(6))
		]
	}
}

// ============================================================================
// DTN Process Specifications - Parallel Composition
// ============================================================================

// Telemetry Flow: Rover → Relay → Earth (one-way pipeline)
tb_process_spec! {
	pub DtnTelemetryFlow,
	events {
		observable {
			"rover_send_telemetry",
			"relay_receive_from_rover",
			"relay_forward_uplink",
			"earth_receive_telemetry",
			"earth_analyze_telemetry"
		}
		hidden { }
	}
	states {
		TelemetryIdle => {
			"rover_send_telemetry" => TelemetryRelayReceive
		},
		TelemetryRelayReceive => {
			"relay_receive_from_rover" => TelemetryRelayForward
		},
		TelemetryRelayForward => {
			"relay_forward_uplink" => TelemetryEarthReceive
		},
		TelemetryEarthReceive => {
			"earth_receive_telemetry" => TelemetryEarthAnalyze
		},
		TelemetryEarthAnalyze => {
			"earth_analyze_telemetry" => TelemetryIdle
		}
	}
}

// Command Flow: Earth → Relay → Rover (one-way async pipeline)
tb_process_spec! {
	pub DtnCommandFlow,
	events {
		observable {
			"earth_send_command",
			"relay_receive_from_earth",
			"relay_forward_downlink",
			"rover_receive_async_command",
			"rover_execute_collect_sample",
			"rover_execute_probe_location",
			"rover_execute_take_photo",
			"rover_execute_standby",
			"rover_command_complete"
		}
		hidden { }
	}
	states {
		CommandIdle => {
			"earth_send_command" => CommandRelayReceive
		},
		CommandRelayReceive => {
			"relay_receive_from_earth" => CommandRelayForward
		},
		CommandRelayForward => {
			"relay_forward_downlink" => CommandRoverReceive
		},
		CommandRoverReceive => {
			"rover_receive_async_command" => CommandExecuting
		},
		CommandExecuting => {
			"rover_execute_collect_sample" => CommandComplete,
			"rover_execute_probe_location" => CommandComplete,
			"rover_execute_take_photo" => CommandComplete,
			"rover_execute_standby" => CommandComplete
		},
		CommandComplete => {
			"rover_command_complete" => CommandIdle
		}
	}
}

// Composed System: Interface Parallel with Relay Synchronization
// Both flows synchronize on relay events (shared satellite infrastructure)
tb_compose_spec! {
	pub DtnComposedSystem,
	processes: {
		DtnTelemetryFlow,
		DtnCommandFlow
	},
	composition: interface_parallel(
		"relay_receive_from_rover",
		"relay_forward_uplink",
		"relay_receive_from_earth",
		"relay_forward_downlink"
	),
	properties: {
		deadlock_free: true,
		livelock_free: true,
		deterministic: false
	},
	annotations {
		description: "DTN system with relay-synchronized telemetry and command flows"
	}
}

// Event Count Assertion Spec
tb_assert_spec! {
	pub DtnEventCountSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("rover_send_telemetry", exactly!(6)),
			("earth_send_command", exactly!(6)),
			("rover_command_complete", exactly!(6)),
			("earth_analyze_telemetry", exactly!(6))
		]
	}
}

// ============================================================================
// Mission Loop Helpers
// ============================================================================

/// Build and send telemetry to Relay (one-way, no response expected)
/// Relay will forward to Earth Ground Station
async fn send_telemetry_to_relay(
	trace: &TraceCollector,
	frame_builder: &FrameBuilderHelper,
	command_executor: &RwLock<CommandExecutor>,
	fault_manager: &FaultManager,
	rover_signing_key: &Secp256k1SigningKey,
	shared_cipher: &Aes256Gcm,
	relay_addr: TightBeamSocketAddr,
) -> Result<(), TightBeamError> {
	// Gather telemetry data
	let (instrument, name, data) = command_executor.read()?.determine_next_instrument();
	let battery = fault_manager.battery_percent()?;
	let fault_matrix_snapshot = fault_manager.fault_matrix()?;

	trace.event("rover_send_telemetry")?;

	let telemetry = RoverTelemetry::new(instrument, data, mission_time_ms(), battery, -20);
	let rover_frame =
		frame_builder.build_telemetry_frame(telemetry, fault_matrix_snapshot, rover_signing_key, shared_cipher)?;

	debug_log!(
		"  [{}] [Rover] Sending {} telemetry (Battery: {}%) [ENCRYPTED]",
		format_mission_time(mission_time_ms()),
		name,
		battery
	);

	// Initiate connection to Relay to send telemetry (one-way)
	let mut telemetry_client = ClientBuilder::<TokioListener>::connect(relay_addr)
		.await?
		.with_server_certificate(SATELLITE_CERT)?
		.with_client_identity(ROVER_CERT, ROVER_KEY)?
		.with_timeout(Duration::from_millis(5000))
		.build()?;

	// Send telemetry to Relay (which forwards to Earth), ignore any response
	let _ = telemetry_client.emit(rover_frame, None).await?;

	Ok(())
}

/// Run the rover mission loop: sends telemetry, receives commands, executes
///
/// NOTE: Currently uses old synchronous request/response pattern for stability.
/// TODO: Migrate to Earth-initiated async pattern once FrameBuilder supports RelayMessage enum.
async fn run_mission_loop(
	trace: &TraceCollector,
	_rover_client: &mut GenericClient<TokioListener>,
	rover_config: Arc<RoverServletConf>,
	shared_mission_state: Arc<RwLock<MissionState>>,
) -> Result<(), TightBeamError> {
	let rover_signing_key = &rover_config.rover_signing_key;
	let shared_cipher = &rover_config.shared_cipher;
	let fault_manager = Arc::clone(&rover_config.fault_manager);
	let command_executor = Arc::clone(&rover_config.command_executor);
	let frame_builder = Arc::clone(&rover_config.frame_builder);
	let mission_state = shared_mission_state;

	// Main mission loop: send telemetry, receive command, execute (old synchronous pattern)
	debug_log!("[Rover Mission Loop] Started - telemetry only, commands executed by RoverServlet");

	// Loop until mission is complete (updated by isolated RoverServlet)
	loop {
		// Check if mission is complete
		if mission_state.read()?.mission_complete {
			debug_log!(
				"  [{}] [Rover Client] Mission complete detected!",
				format_mission_time(mission_time_ms())
			);
			break;
		}

		let mut completed_rounds = mission_state.read()?.completed_rounds;
		debug_log!(
			"\n═══════════════ Round {} {} ═══════════════",
			completed_rounds + 1,
			format_mission_time(mission_time_ms())
		);

		// Update battery state and check for faults
		let battery_update = fault_manager.update_battery_state()?;
		match battery_update {
			BatteryUpdate::LowPowerDetected(battery) => {
				trace.event("fault_low_power_detected")?;
				println!(
					"  [{}] [Rover] ⚠ LOW POWER DETECTED ({}%) - Halting communications",
					format_mission_time(mission_time_ms()),
					battery
				);
				trace.event("comms_halted")?;

				// Simulate recharge period
				println!(
					"  [{}] [Rover] Entering recharge mode (30 minutes)...",
					format_mission_time(mission_time_ms())
				);
				advance_clock(delays::ROVER_RECHARGE_MS);

				// Re-energize battery to full
				while fault_manager.battery_percent()? < 100 {
					fault_manager.reenergize_battery()?;
				}

				println!(
					"  [{}] [Rover] ✓ Recharge complete (Battery: 100%) - Resuming operations",
					format_mission_time(mission_time_ms())
				);
				trace.event("fault_cleared")?;
			}
			BatteryUpdate::FaultCleared(battery) => {
				println!(
					"  [{}] [Rover] ✓ Battery recharged to {}%",
					format_mission_time(mission_time_ms()),
					battery
				);
			}
			BatteryUpdate::Updated => {
				// Normal battery drain
				fault_manager.drain_battery()?;
			}
		}

		// ONE-WAY: Send telemetry to Relay (which forwards to Earth)
		let relay_addr = rover_config.relay_addr;
		send_telemetry_to_relay(
			trace,
			&frame_builder,
			&command_executor,
			&fault_manager,
			rover_signing_key,
			shared_cipher,
			relay_addr,
		)
		.await?;

		// Simulate propagation delays
		advance_clock(delays::ROVER_TO_RELAY_MS);
		debug_log!(
			"  [{}] [Relay] Received telemetry from Rover, forwarding to Earth...",
			format_mission_time(mission_time_ms())
		);

		advance_clock(delays::RELAY_TO_EARTH_MS);
		debug_log!(
			"  [{}] [Earth] Received telemetry from Relay",
			format_mission_time(mission_time_ms())
		);

		// Check mission state (updated by RoverServlet when it executes commands)
		// Servlets are isolated - we can only share state via DtnScenarioConfig
		let state = mission_state.read()?;
		if state.completed_rounds > completed_rounds {
			completed_rounds = state.completed_rounds;
			debug_log!(
				"  [{}] [Rover Client] Mission progress: {}/{} commands executed by RoverServlet",
				format_mission_time(mission_time_ms()),
				completed_rounds,
				COMMAND_ROUND_TRIPS
			);
		}

		// Note: Commands are executed by the isolated RoverServlet when received from Earth via Relay
		// The rover client just sends telemetry and monitors mission completion via shared state
	}

	Ok(())
}

// ============================================================================
// Tests
// ============================================================================

/// Build FDR configuration for DTN testing
/// NOTE: Reserved for future FDR (Failures, Divergence, Refinement) testing
#[cfg(feature = "testing-fault")]
#[allow(dead_code)]
fn build_dtn_fdr_config() -> FdrConfig {
	FdrConfig {
		seeds: 10,
		max_depth: 50,
		max_internal_run: 10,
		timeout_ms: 30000,
		specs: vec![],
		fail_fast: false,
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
	spec: DtnEventCountSpec,
	csp: DtnComposedSystem,
	config: DtnScenarioConfig::default(),
	environment Servlet {
		servlet: RoverServlet,
		start: |trace, config| async move {
			// Generate Earth's signing key
			let earth_signing_key = Secp256k1SigningKey::random(&mut OsRng);

			// Get verifying keys using helper functions
			let rover_verifying_key_value = rover_verifying_key();
			let earth_verifying_key_value = earth_signing_key.verifying_key().to_owned();

			// Store Earth's verifying key in config for Rover client to use
			*config.write()?.earth_verifying_key.write()? = Some(earth_verifying_key_value);

			// Get shared cipher from config
			let shared_cipher = config.read()?.shared_cipher.to_owned();

			let earth_store = Arc::new(RwLock::new(FrameStore::new(PathBuf::from("temp/dtn/earth"))?));
			let earth_chain_state = Arc::new(RwLock::new(MessageChainState::new("earth".to_string())));
			let earth_order_buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(10)));
			let earth_processor = Arc::new(ChainProcessor::new(
				earth_store,
				earth_chain_state,
				earth_order_buffer,
				"Earth".to_string(),
			));

			let earth_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&earth_processor)));

			let relay_store = Arc::new(RwLock::new(FrameStore::new(PathBuf::from("temp/dtn/relay"))?));
			let relay_chain_state = Arc::new(RwLock::new(MessageChainState::new("relay".to_string())));
			let relay_order_buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(10)));
			let relay_processor = Arc::new(ChainProcessor::new(
				relay_store,
				relay_chain_state,
				relay_order_buffer,
				"Satellite".to_string(),
			));

			let relay_signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let relay_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&relay_processor)));

			// Start Earth Ground Station servlet with config (relay_addr added later in separate task)
			let earth_config = EarthGroundStationServletConf {
				earth_signing_key: earth_signing_key.to_owned(),
				rover_verifying_key: rover_verifying_key_value,
				shared_cipher: shared_cipher.to_owned(),
				chain_processor: Arc::clone(&earth_processor),
				frame_builder: Arc::clone(&earth_frame_builder),
				relay_addr: TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0))), // Placeholder
			};
			println!("[START] Starting Earth Ground Station");
			let earth_servlet = EarthGroundStationServlet::start(Arc::clone(&trace), Arc::new(earth_config)).await?;
			let earth_addr = earth_servlet.addr();
			println!("[START] Earth servlet started at {:?}", earth_addr);

			// Store Earth servlet handle in config to keep it alive
			{
				let config_guard = config.write()?;
				config_guard._earth_servlet.write()?.replace(earth_servlet);
			}

			// CREATE ROVER SERVLET FIRST (so we have its real address for the Relay)
			println!("[START] Creating Rover servlet configuration");

			// Get needed values from config, then drop the lock immediately
			let (rover_signing_key_owned, command_queue_arc) = {
				let config_guard = config.read()?;
				let rover_fault_manager = Arc::new(FaultManager::from_refs(
					&config_guard.bms,
					&config_guard.fault_matrix,
					&config_guard.rover_fault_handler,
				));
				drop(config_guard); // Explicitly drop read lock

				let config_guard2 = config.read()?;
				(
					config_guard2.rover_signing_key.to_owned(),
					Arc::clone(&config_guard2.command_queue),
				)
			};

			let rover_store = Arc::new(RwLock::new(FrameStore::new(PathBuf::from("temp/dtn/rover"))?));
			let rover_chain_state = Arc::new(RwLock::new(MessageChainState::new("rover".to_string())));
			let rover_order_buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(10)));
			let rover_processor = Arc::new(ChainProcessor::new(
				rover_store,
				rover_chain_state,
				rover_order_buffer,
				"Rover".to_string(),
			));

			let rover_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&rover_processor)));
			let rover_fault_manager = {
				let config_guard = config.read()?;
				Arc::new(FaultManager::from_refs(
					&config_guard.bms,
					&config_guard.fault_matrix,
					&config_guard.rover_fault_handler,
				))
			};

			let rover_command_executor = Arc::new(RwLock::new(CommandExecutor::default()));
			// Use shared mission state from DtnScenarioConfig
			let shared_mission_state = Arc::clone(&config.read()?.mission_state);
			let rover_config = RoverServletConf {
				relay_addr: TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0))), // Placeholder (RoverServlet doesn't connect to Relay)
				rover_signing_key: rover_signing_key_owned,
				earth_verifying_key: earth_verifying_key_value,
				shared_cipher: shared_cipher.clone(),
				chain_processor: rover_processor,
				fault_manager: rover_fault_manager,
				command_executor: rover_command_executor,
				frame_builder: rover_frame_builder,
				mission_state: shared_mission_state,
				max_rounds: COMMAND_ROUND_TRIPS,
				command_queue: command_queue_arc,
			};

			// Start the Rover servlet to receive async commands
			println!("[START] Starting Rover servlet");
			let rover_config_arc = Arc::new(rover_config);
			let rover_servlet = RoverServlet::start(Arc::clone(&trace), rover_config_arc).await?;
			let rover_addr = rover_servlet.addr();

			println!("[START] Rover servlet started at {:?}", rover_addr);

			// Store rover address in config for mission loop
			*config.read()?.rover_addr.write()? = Some(rover_addr);

			// NOW create Relay servlet with the REAL rover_addr
			println!("[START] Creating Relay servlet configuration with rover_addr: {:?}", rover_addr);
			let relay_config = RelaySatelliteServletConf {
				earth_addr,
				rover_addr, // Real address, not placeholder!
				rover_verifying_key: rover_verifying_key_value,
				earth_verifying_key: earth_verifying_key_value,
				chain_processor: relay_processor,
				shared_cipher: shared_cipher.clone(),
				relay_signing_key,
				frame_builder: relay_frame_builder,
			};

			println!("[START] Starting Relay satellite");
			let relay_servlet_handle = RelaySatelliteServlet::start(Arc::clone(&trace), Arc::new(relay_config)).await?;
			let relay_addr = relay_servlet_handle.addr();
			println!("[START] Relay servlet started at {:?}", relay_addr);

			// Store relay address and servlet handle in config
			println!("[START] Storing relay address in config");
			{
				let config_guard = config.write()?;
				println!("[START] Got config write lock");
				config_guard.relay_addr.write()?.replace(relay_addr);
				println!("[START] Stored relay_addr");
				config_guard._relay_servlet.write()?.replace(relay_servlet_handle);
				println!("[START] Stored relay_servlet handle");
			}
			println!("[START] Released config lock");

			// Initialize mission clock for the entire test
			println!("[START] Initializing mission clock");
		init_mission_clock();

		//  Emit mission_start event
		trace.event("mission_start")?;

		// Spawn Earth Mission Control task for async command sending
		println!("[START] Spawning Earth Mission Control task");
			let earth_task_trace = Arc::clone(&trace);
			let earth_task_signing_key = earth_signing_key.to_owned();
			let earth_task_cipher = shared_cipher.to_owned();
			let earth_task_processor = Arc::clone(&earth_processor);
			let earth_task_builder = Arc::clone(&earth_frame_builder);
			tokio::spawn(async move {
				if let Err(e) = earth_mission_control_task(
					earth_task_trace,
					relay_addr,
					earth_task_signing_key,
					earth_task_cipher,
					earth_task_processor,
					earth_task_builder,
					COMMAND_ROUND_TRIPS,
				).await {
					eprintln!("[Earth Mission Control] Task error: {:?}", e);
				}
			});
			println!("[START] Earth Mission Control task spawned");

			println!("[START] Returning Rover servlet to scenario");
			Ok(rover_servlet)
		},
		setup: |rover_addr, config| async move {
			debug_log!("[Setup] Rover servlet address: {:?}", rover_addr);

			let _earth_verifying_key = config.read()?.earth_verifying_key.read()?
				.clone()
				.expect("Earth verifying key must be set before setup");
			debug_log!("[Setup] Earth verifying key found");

			let relay_addr = config.read()?.relay_addr.read()?
				.clone()
				.expect("Relay address must be set before setup");
			debug_log!("[Setup] Relay address found: {:?}", relay_addr);

			// Exponential backoff: 100ms, 200ms, 400ms (max 3 attempts)
			let restart_policy = RestartExponentialBackoff::new(3, 100, None);
			let client = ClientBuilder::<TokioListener>::connect(relay_addr)
				.await?
				.with_server_certificate(SATELLITE_CERT)?
				.with_client_identity(ROVER_CERT, ROVER_KEY)?
				.with_restart(restart_policy)
				.with_timeout(Duration::from_millis(2000))
				.build()?;

			Ok(client)
		},
		client: |trace, mut rover_client, config| async move {
			println!("╔════════════════════════════════════════════════════════════╗");
			println!("║  Mars Rover DTN Mission - {} Round Trips                   ║", COMMAND_ROUND_TRIPS);
			println!("╚════════════════════════════════════════════════════════════╝\n");

			let earth_verifying_key = config.read()?.earth_verifying_key.read()?
				.to_owned()
				.expect("Earth verifying key must be set before client");

			// Recreate rover components for mission loop
			let config_guard = config.read()?;
			let rover_store = Arc::new(RwLock::new(FrameStore::new(PathBuf::from("temp/dtn/rover"))?));
			let rover_chain_state = Arc::new(RwLock::new(MessageChainState::new("rover".to_string())));
			let rover_order_buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(10)));
			let rover_processor = Arc::new(ChainProcessor::new(
				rover_store,
				rover_chain_state,
				rover_order_buffer,
				"Rover".to_string(),
			));

			let rover_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&rover_processor)));
			let rover_fault_manager = Arc::new(FaultManager::from_refs(
				&config_guard.bms,
				&config_guard.fault_matrix,
				&config_guard.rover_fault_handler,
			));

			let rover_command_executor = Arc::new(RwLock::new(CommandExecutor::default()));
			let rover_mission_state = Arc::new(RwLock::new(MissionState::default()));

			let relay_addr = config.read()?.relay_addr.read()?
				.clone()
				.expect("Relay address must be set before client");

			let rover_servlet_config = RoverServletConf {
				relay_addr,
				earth_verifying_key,
				rover_signing_key: config_guard.rover_signing_key.to_owned(),
				shared_cipher: config_guard.shared_cipher.to_owned(),
				chain_processor: rover_processor,
				fault_manager: rover_fault_manager,
				command_executor: rover_command_executor,
				frame_builder: rover_frame_builder,
				mission_state: rover_mission_state,
				max_rounds: COMMAND_ROUND_TRIPS,
				command_queue: Arc::clone(&config.read()?.command_queue),
			};

			// Get shared mission state from config (same Arc as RoverServlet uses)
			let shared_mission_state = Arc::clone(&config.read()?.mission_state);

			drop(config_guard);
			run_mission_loop(&trace, &mut rover_client, Arc::new(rover_servlet_config), shared_mission_state).await?;

			trace.event("mission_complete")?;
			println!("╔════════════════════════════════════════════════════════════╗");
			println!("║  Mission Complete - {} commands                            ║", COMMAND_ROUND_TRIPS);
			println!("╚════════════════════════════════════════════════════════════╝");

			Ok(())
		}
	}
}
