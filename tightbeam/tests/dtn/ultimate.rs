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

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand_core::OsRng;
use tightbeam::{
	crypto::{
		aead::Aes256Gcm,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	error::TightBeamError,
	exactly,
	macros::client::builder::{ClientBuilder, GenericClient},
	prelude::*,
	tb_assert_spec, tb_process_spec, tb_scenario,
	testing::fdr::FdrConfig,
	trace::TraceCollector,
	transport::{policy::RestartExponentialBackoff, tcp::r#async::TokioListener},
};

use crate::dtn::{
	bms::BatteryManagementSystem,
	certs::{generate_shared_cipher, ROVER_CERT, ROVER_KEY, SATELLITE_CERT},
	chain_processor::ChainProcessor,
	clock::init_mission_clock,
	command_executor::CommandExecutor,
	fault_manager::FaultManager,
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
	pub earth_verifying_key: RwLock<Option<tightbeam::crypto::sign::ecdsa::Secp256k1VerifyingKey>>,
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
	/// Relay servlet handle (keeps the servlet task alive)
	pub relay_servlet: RwLock<Option<crate::dtn::servlets::RelaySatelliteServlet>>,
	/// Earth servlet handle (keeps the servlet task alive)
	pub earth_servlet: RwLock<Option<crate::dtn::servlets::EarthGroundStationServlet>>,
	/// Command queue for async command execution on Rover
	pub command_queue: Arc<RwLock<VecDeque<EarthCommand>>>,
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		// Create storage directories (fail fast)
		let rover_store = FrameStore::new(PathBuf::from("temp/dtn/rover")).expect("Failed to create rover storage");
		let earth_store = FrameStore::new(PathBuf::from("temp/dtn/earth")).expect("Failed to create earth storage");
		let relay_store = FrameStore::new(PathBuf::from("temp/dtn/relay")).expect("Failed to create relay storage");

		Self {
			rover_signing_key: Secp256k1SigningKey::random(&mut OsRng),
			shared_cipher: generate_shared_cipher(),
			earth_verifying_key: RwLock::new(None),
			bms: RwLock::new(BatteryManagementSystem::default()),
			rover_fault_handler: RwLock::new(RoverFaultHandler::new()),
			fault_matrix: RwLock::new(FaultMatrix::new()),
			rover_store: RwLock::new(rover_store),
			earth_store: RwLock::new(earth_store),
			relay_store: RwLock::new(relay_store),
			relay_addr: RwLock::new(None),
			relay_servlet: RwLock::new(None),
			earth_servlet: RwLock::new(None),
			command_queue: Arc::new(RwLock::new(VecDeque::new())),
		}
	}
}

impl Drop for DtnScenarioConfig {
	fn drop(&mut self) {
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
	}
}

// ============================================================================
// Test Configuration
// ============================================================================

/// Number of command/response round-trips for the test.
const COMMAND_ROUND_TRIPS: usize = 6;

// ============================================================================
// Helper Functions
// ============================================================================

/// Earth Mission Control task: sends commands to Relay (which forwards to Rover)
// NOTE: Currently unused - for future Earth-initiated async flow
#[allow(dead_code)]
async fn earth_mission_control_task(
	trace: Arc<TraceCollector>,
	_relay_addr: TightBeamSocketAddr,
	_earth_signing_key: Secp256k1SigningKey,
	_shared_cipher: Aes256Gcm,
	_earth_processor: Arc<ChainProcessor>,
	max_rounds: usize,
) -> Result<(), TightBeamError> {
	println!(
		"[Earth Mission Control] Task started (stubbed for future use) - {} rounds",
		max_rounds
	);
	trace.event("earth_send_command")?;

	// Wait a bit for rover servlet to be ready
	tokio::time::sleep(Duration::from_millis(500)).await;

	for round in 0..max_rounds {
		println!("[Earth Mission Control] Sending command {}/{}", round + 1, max_rounds);

		// Create command
		let rover_cmd = match round % 3 {
			0 => RoverCommand::ProbeLocation { x: 100, y: 200 },
			1 => RoverCommand::TakePhoto { direction: "North".to_string(), resolution: 1080 },
			_ => RoverCommand::CollectSample { location: "Site Alpha".to_string() },
		};

		// For now, stub out command sending (TODO: implement proper frame building for RelayMessage)
		println!(
			"[Earth Mission Control] Command {} would be sent here (implementation pending)",
			round + 1
		);
		trace.event("earth_send_command")?;
		tokio::time::sleep(Duration::from_millis(500)).await;
	}

	println!("[Earth Mission Control] All commands sent");
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

			// Earth events
			("earth_receive_telemetry", exactly!(6)),
			("earth_analyze_telemetry", exactly!(6)),

			// Relay events (uplink only - downlink is synchronous response)
			("relay_receive_from_rover", exactly!(6)),
			("relay_forward_uplink", exactly!(6)),

			// Rover events
			("rover_send_telemetry", exactly!(6)),
			("rover_receive_command", exactly!(6)),
			("rover_command_complete", exactly!(6))
		]
	}
}

// ============================================================================
// DTN Process Specification
// ============================================================================

tb_process_spec! {
	pub DtnRoverEarthFlow,
	events {
		observable {
			// Rover events
			"rover_send_telemetry", "rover_receive_command",
			"rover_execute_collect_sample", "rover_execute_probe_location",
			"rover_execute_take_photo", "rover_execute_standby",
			"rover_command_complete",

			// Relay events
			"relay_receive_from_rover", "relay_forward_uplink",
			"relay_receive_from_earth", "relay_forward_downlink",

			// Earth events
			"earth_receive_telemetry", "earth_analyze_telemetry",

			// Fault events
			"fault_low_power_detected", "comms_halted", "fault_cleared",

			// Security events
			"signature_verification_failed",

			// Lifecycle events
			"mission_start", "mission_complete"
		}
		hidden { }
	}
	states {
		MissionStart => { "mission_start" => TelemetrySending },

		// Rover initiates telemetry (synchronous request/response pattern)
		TelemetrySending => {
			"rover_send_telemetry" => UplinkInProgress
		},
		UplinkInProgress => {
			"relay_receive_from_rover" => RelayForwardingTelemetry
		},
		RelayForwardingTelemetry => {
			"relay_forward_uplink" => EarthBound
		},
		EarthBound => {
			"earth_receive_telemetry" => EarthAnalyzing
		},
		EarthAnalyzing => {
			"earth_analyze_telemetry" => CommandDownlink
		},

		// Earth responds with command (synchronous response - relay transparent)
		CommandDownlink => {
			"rover_receive_command" => CommandExecution
		},
		CommandExecution => {
			"rover_execute_collect_sample" => CommandComplete,
			"rover_execute_probe_location" => CommandComplete,
			"rover_execute_take_photo" => CommandComplete,
			"rover_execute_standby" => CommandComplete
		},
		CommandComplete => {
			"rover_command_complete" => RoundComplete
		},

		// Loop back or complete
		RoundComplete => {
			"rover_send_telemetry" => UplinkInProgress,
			"mission_complete" => MissionEnd
		},

		// Fault handling
		CommandExecution => {
			"fault_low_power_detected" => FaultHandling
		},
		FaultHandling => {
			"comms_halted" => FaultWait
		},
		FaultWait => {
			"fault_cleared" => TelemetrySending
		}
	}
	terminal { MissionEnd }
}

// ============================================================================
// Mission Loop Helpers
// ============================================================================

/// Build and send telemetry to Relay after command execution
async fn send_telemetry_to_relay(
	trace: &TraceCollector,
	frame_builder: &FrameBuilderHelper,
	command_executor: &RwLock<CommandExecutor>,
	fault_manager: &FaultManager,
	rover_signing_key: &Secp256k1SigningKey,
	shared_cipher: &Aes256Gcm,
	relay_addr: TightBeamSocketAddr,
) -> Result<(), TightBeamError> {
	use crate::dtn::{
		certs::{ROVER_CERT, ROVER_KEY, SATELLITE_CERT},
		clock::mission_time_ms,
	};

	// Gather telemetry data
	let (instrument, name, data) = command_executor.read()?.determine_next_instrument();
	let battery = fault_manager.battery_percent()?;
	let fault_matrix_snapshot = fault_manager.fault_matrix()?;

	trace.event("rover_send_telemetry")?;

	let telemetry = RoverTelemetry::new(instrument, data, mission_time_ms(), battery, -20);

	// Build telemetry frame
	let rover_frame =
		frame_builder.build_telemetry_frame(telemetry, fault_matrix_snapshot, rover_signing_key, shared_cipher)?;

	println!("  [Rover] Sending {} telemetry (Battery: {}%) [ENCRYPTED]", name, battery);

	// Initiate connection to Relay to send telemetry
	let mut telemetry_client = ClientBuilder::<TokioListener>::connect(relay_addr)
		.await?
		.with_server_certificate(SATELLITE_CERT)?
		.with_client_identity(ROVER_CERT, ROVER_KEY)?
		.with_timeout(Duration::from_millis(5000))
		.build()?;

	telemetry_client.emit(rover_frame, None).await?;
	println!("  [Rover] Telemetry sent to Relay");

	Ok(())
}

/// Run the rover mission loop: sends telemetry, receives commands, executes
///
/// NOTE: Currently uses old synchronous request/response pattern for stability.
/// TODO: Migrate to Earth-initiated async pattern once FrameBuilder supports RelayMessage enum.
async fn run_mission_loop(
	trace: &TraceCollector,
	rover_client: &mut GenericClient<TokioListener>,
	rover_config: Arc<RoverServletConf>,
) -> Result<(), TightBeamError> {
	use crate::dtn::clock::mission_time_ms;

	let rover_signing_key = &rover_config.rover_signing_key;
	let shared_cipher = &rover_config.shared_cipher;
	let earth_verifying_key = rover_config.earth_verifying_key;
	let fault_manager = Arc::clone(&rover_config.fault_manager);
	let command_executor = Arc::clone(&rover_config.command_executor);
	let frame_builder = Arc::clone(&rover_config.frame_builder);
	let mission_state = Arc::clone(&rover_config.mission_state);

	// Main mission loop: send telemetry, receive command, execute (old synchronous pattern)
	let mut completed_rounds = 0usize;
	println!("[Rover Mission Loop] Started - using synchronous telemetry/command pattern");

	while completed_rounds < COMMAND_ROUND_TRIPS {
		println!("═══════════════ Round {} ═══════════════", completed_rounds + 1);

		// Update battery state
		fault_manager.update_battery_state()?;
		fault_manager.drain_battery()?;

		// Build and send telemetry
		let (instrument, name, data) = command_executor.read()?.determine_next_instrument();
		let battery = fault_manager.battery_percent()?;
		let fault_matrix_snapshot = fault_manager.fault_matrix()?;

		trace.event("rover_send_telemetry")?;

		let telemetry = RoverTelemetry::new(instrument, data, mission_time_ms(), battery, -20);
		let rover_frame =
			frame_builder.build_telemetry_frame(telemetry, fault_matrix_snapshot, rover_signing_key, shared_cipher)?;

		println!("  [Rover] Sending {} telemetry (Battery: {}%) [ENCRYPTED]", name, battery);

		// Send telemetry and receive command response (synchronous)
		let response = rover_client.emit(rover_frame, None).await?;

		if let Some(response_frame) = response {
			// Verify Earth's signature
			response_frame.verify::<Secp256k1Signature>(&earth_verifying_key)?;
			println!("  [Rover] ✓ Earth signature verified");

			// Process command response
			match rover_config.chain_processor.process_incoming(response_frame)? {
				crate::dtn::chain_processor::ProcessResult::Processed(ordered_frames) => {
					for ordered_frame in ordered_frames {
						trace.event("rover_receive_command")?;

						// Decode command
						let command: EarthCommand = if ordered_frame.metadata.confidentiality.is_some() {
							use tightbeam::compress::{Inflator, ZstdCompression};
							let inflator: Option<&dyn Inflator> = if ordered_frame.metadata.compactness.is_some() {
								Some(&ZstdCompression)
							} else {
								None
							};
							ordered_frame.decrypt::<EarthCommand>(shared_cipher, inflator)?
						} else {
							tightbeam::decode(&ordered_frame.message)?
						};

						let cmd_type = RoverCommand::try_from(command.command_type)?;
						println!("  [Rover] Command: {}", cmd_type);

						// Execute command
						command_executor.write()?.execute_command(cmd_type, trace)?;
						trace.event("rover_command_complete")?;

						// Update mission state
						completed_rounds += 1;
						{
							let mut state = mission_state.write()?;
							state.completed_rounds = completed_rounds;
							if completed_rounds >= COMMAND_ROUND_TRIPS {
								state.mission_complete = true;
							}
						}
					}
				}
				_ => {
					println!("  [Rover] No command received or buffered");
				}
			}
		}

		println!("  [Rover] Round {} complete\n", completed_rounds);
	}

	Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(feature = "testing-fault")]
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
	spec: DtnRealisticSpec,
	csp: DtnRoverEarthFlow,
	config: DtnScenarioConfig::default(),
	environment Servlet {
		servlet: RoverServlet,
		start: |trace, config| async move {
			// Generate Earth's signing key
			let earth_signing_key = Secp256k1SigningKey::random(&mut OsRng);

			// Get verifying keys
			let rover_verifying_key = config.read()?.rover_signing_key.verifying_key().to_owned();
			let earth_verifying_key = earth_signing_key.verifying_key().to_owned();

			// Store Earth's verifying key in config for Rover client to use
			*config.write()?.earth_verifying_key.write()? = Some(earth_verifying_key);

			// Get shared cipher from config
			let shared_cipher = config.read()?.shared_cipher.to_owned();

			// Create ChainProcessors for servlets
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

			// Start Earth Ground Station servlet with config (relay_addr added later in separate task)
			let earth_config = EarthGroundStationServletConf {
				earth_signing_key: earth_signing_key.to_owned(),
				rover_verifying_key,
				shared_cipher: shared_cipher.to_owned(),
				chain_processor: Arc::clone(&earth_processor),
				frame_builder: earth_frame_builder,
				relay_addr: TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0))), // Placeholder
			};
			let earth_servlet = EarthGroundStationServlet::start(Arc::clone(&trace), Arc::new(earth_config)).await?;
			let earth_addr = earth_servlet.addr();

			// Store Earth servlet handle in config to keep it alive
			{
				let config_guard = config.write()?;
				config_guard.earth_servlet.write()?.replace(earth_servlet);
			}

			// Create Relay servlet config (relay only needs earth_addr, not the servlet handle)
			let relay_config = RelaySatelliteServletConf {
				earth_addr,
				rover_addr: TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0))), // Placeholder
				rover_verifying_key,
				earth_verifying_key,
				chain_processor: relay_processor,
				shared_cipher: shared_cipher.clone(),
			};

			// Start Relay Satellite servlet (servlet spawns background task, handle keeps it alive)
			let relay_servlet_handle = RelaySatelliteServlet::start(Arc::clone(&trace), Arc::new(relay_config)).await?;
			let relay_addr = relay_servlet_handle.addr();
			// Store relay address and servlet handle in config
			{
				let config_guard = config.write()?;
				config_guard.relay_addr.write()?.replace(relay_addr);
				config_guard.relay_servlet.write()?.replace(relay_servlet_handle);
			}

			// Give servlets time to be ready
			tokio::time::sleep(Duration::from_millis(100)).await;

			// NOTE: Earth Mission Control task disabled - using synchronous request/response pattern
			// TODO: Enable when RelayMessage frame building is implemented

			// Create Rover components
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

			// Create FaultManager by wrapping the RwLocks from config in Arc
			let rover_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&rover_processor)));
			let rover_fault_manager = Arc::new(FaultManager::from_refs(
				&config_guard.bms,
				&config_guard.fault_matrix,
				&config_guard.rover_fault_handler,
			));

			let rover_command_executor = Arc::new(RwLock::new(CommandExecutor::default()));
			let rover_mission_state = Arc::new(RwLock::new(MissionState::default()));
			let rover_config = RoverServletConf {
				relay_addr,
				rover_signing_key: config_guard.rover_signing_key.to_owned(),
				earth_verifying_key,
				shared_cipher,
				chain_processor: rover_processor,
				fault_manager: rover_fault_manager,
				command_executor: rover_command_executor,
				frame_builder: rover_frame_builder,
				mission_state: rover_mission_state,
				max_rounds: COMMAND_ROUND_TRIPS,
				command_queue: Arc::clone(&config.read()?.command_queue),
			};

			// Start and return the Rover servlet
			RoverServlet::start(Arc::clone(&trace), Arc::new(rover_config)).await
		},
		setup: |_rover_addr, config| async move {
			// Wait for Earth verifying key and relay address to be set by the servlet start
			let _earth_verifying_key = loop {
				if let Some(key) = config.read()?.earth_verifying_key.read()?.clone() {
					break key;
				}

				// Give the servlet a moment to initialize
				tokio::time::sleep(Duration::from_millis(10)).await;
			};

			// Get relay address from config
			let relay_addr = loop {
				if let Some(addr) = config.read()?.relay_addr.read()?.clone() {
					break addr;
				}

				// Give the servlet a moment to initialize
				tokio::time::sleep(Duration::from_millis(50)).await;
			};

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
			// Initialize mission clock at T+0
			init_mission_clock();

			trace.event("mission_start")?;
			println!("╔════════════════════════════════════════════════════════════╗");
			println!("║  Mars Rover DTN Mission - {} Round Trips                   ║", COMMAND_ROUND_TRIPS);
			println!("╚════════════════════════════════════════════════════════════╝\n");

			// Wait for Earth verifying key to be set
			let earth_verifying_key = loop {
				if let Some(key) = config.read()?.earth_verifying_key.read()?.to_owned() {
					break key;
				}

				tokio::time::sleep(Duration::from_millis(10)).await;
			};

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

			// Get relay address from config
			let relay_addr = loop {
				if let Some(addr) = config.read()?.relay_addr.read()?.clone() {
					break addr;
				}

				// Give the servlet a moment to initialize
				tokio::time::sleep(Duration::from_millis(10)).await;
			};

			// Create rover servlet config for mission loop
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

			drop(config_guard);
			run_mission_loop(&trace, &mut rover_client, Arc::new(rover_servlet_config)).await?;

			trace.event("mission_complete")?;
			println!("╔════════════════════════════════════════════════════════════╗");
			println!("║  Mission Complete - {} commands                            ║", COMMAND_ROUND_TRIPS);
			println!("╚════════════════════════════════════════════════════════════╝");

			Ok(())
		}
	}
}
