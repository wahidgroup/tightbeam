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

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand_core::OsRng;
use tightbeam::{
	compress::{Inflator, ZstdCompression},
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
	chain_processor::{ChainProcessor, ProcessResult},
	clock::{advance_clock, delays, init_mission_clock, mission_time_ms},
	command_executor::CommandExecutor,
	fault_manager::{BatteryUpdate, FaultAction, FaultManager},
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
// Assertion Specification
// ============================================================================

tb_assert_spec! {
	pub DtnRealisticSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("mission_start", exactly!(1)),
			("rover_send_telemetry", exactly!(6)),
			("rover_receive_command", exactly!(6)),
			("rover_command_complete", exactly!(6)),
			("mission_complete", exactly!(1))
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
			"earth_select_command", "earth_send_command",

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
		MissionStart => { "mission_start" => Idle },
		Idle => {
			"rover_send_telemetry" => UplinkInProgress,
			"fault_low_power_detected" => FaultHandling
		},
		UplinkInProgress => {
			"relay_receive_from_rover" => RelayProcessing
		},
		RelayProcessing => {
			"relay_forward_uplink" => EarthBound
		},
		EarthBound => {
			"earth_receive_telemetry" => EarthAnalyzing
		},
		EarthAnalyzing => {
			"earth_analyze_telemetry" => CommandSelection
		},
		CommandSelection => {
			"earth_select_command" => EarthSending
		},
		EarthSending => {
			"earth_send_command" => DownlinkInProgress
		},
		DownlinkInProgress => {
			"relay_receive_from_earth" => RelayReturning
		},
		RelayReturning => {
			"relay_forward_downlink" => RoverBound
		},
		RoverBound => {
			"rover_receive_command" => CommandExecution
		},
		CommandExecution => {
			"rover_execute_collect_sample" => CommandComplete,
			"rover_execute_probe_location" => CommandComplete,
			"rover_execute_take_photo" => CommandComplete,
			"rover_execute_standby" => CommandComplete
		},
		CommandComplete => {
			"rover_command_complete" => Idle
		},
		FaultHandling => {
			"comms_halted" => FaultWait
		},
		FaultWait => {
			"fault_low_power_detected" => FaultRecharging,
			"fault_cleared" => Idle
		},
		FaultRecharging => {
			"comms_halted" => FaultWait
		},
		Idle => {
			"mission_complete" => MissionEnd
		}
	}
	terminal { MissionEnd }
}

// ============================================================================
// Mission Loop Helper
// ============================================================================

/// Run the rover mission loop using the provided components
async fn run_mission_loop(
	trace: &TraceCollector,
	rover_client: &mut GenericClient<TokioListener>,
	rover_config: Arc<RoverServletConf>,
) -> Result<(), TightBeamError> {
	let rover_signing_key = &rover_config.rover_signing_key;
	let shared_cipher = &rover_config.shared_cipher;
	let earth_verifying_key = rover_config.earth_verifying_key;
	let fault_manager = Arc::clone(&rover_config.fault_manager);
	let command_executor = Arc::clone(&rover_config.command_executor);
	let frame_builder = Arc::clone(&rover_config.frame_builder);
	let chain_processor = Arc::clone(&rover_config.chain_processor);
	let mission_state = Arc::clone(&rover_config.mission_state);

	// Main mission loop
	let mut completed_rounds = 0usize;
	while completed_rounds < COMMAND_ROUND_TRIPS {
		// Update battery state and check for faults
		match fault_manager.update_battery_state()? {
			BatteryUpdate::LowPowerDetected(battery) => {
				println!("⚠ LOW POWER FAULT - Battery: {}% - Beginning recharge", battery);
			}
			BatteryUpdate::FaultCleared(battery) => {
				trace.event("fault_cleared")?;
				println!("✓ BATTERY FULLY RECHARGED ({}%) - Fault cleared", battery);
			}
			BatteryUpdate::Updated => {}
		}

		// Check if comms should halt
		match fault_manager.check_and_handle_faults()? {
			FaultAction::HaltComms => {
				trace.event("fault_low_power_detected")?;
				trace.event("comms_halted")?;
				let new_charge = fault_manager.reenergize_battery()?;
				println!("⚠ RECHARGING - Battery: {}% - Skipping round", new_charge);
				continue;
			}
			FaultAction::Continue => {}
		}

		// Drain battery for operational round
		fault_manager.drain_battery()?;

		println!("═══════════════ Round {} ═══════════════", completed_rounds + 1);

		// Determine instrument based on last command
		let (instrument, name, data) = command_executor.read()?.determine_next_instrument();
		let battery = fault_manager.battery_percent()?;
		let fault_matrix_snapshot = fault_manager.fault_matrix()?;

		// Rover sends telemetry
		trace.event("rover_send_telemetry")?;

		// Build frame using FrameBuilderHelper
		let telemetry = RoverTelemetry::new(instrument, data, mission_time_ms(), battery, -20);
		let rover_frame = frame_builder.build_telemetry_frame(
			telemetry,
			fault_matrix_snapshot,
			&rover_signing_key,
			&shared_cipher,
		)?;

		println!("  [Rover] {} telemetry (Battery: {}%) [ENCRYPTED]", name, battery);
		if fault_matrix_snapshot.has_fault() {
			let active: Vec<_> = fault_matrix_snapshot.active_faults().collect();
			println!("  [Rover] ⚠ Active faults: {:?}", active);
		}

		// Send telemetry and receive command response
		let response = rover_client.emit(rover_frame, None).await?;
		if let Some(response_frame) = response {
			// Verify Earth's signature
			match response_frame.verify::<Secp256k1Signature>(&earth_verifying_key) {
				Ok(_) => println!("  [Rover] ✓ Earth signature verified"),
				Err(e) => return Err(e),
			}

			// Process response frame - commands come as responses, so we process them here
			// but emit CSP events in the correct order to match the specification
			match chain_processor.process_incoming(response_frame.clone())? {
				ProcessResult::Processed(ordered_frames) => {
					for ordered_frame in ordered_frames {
						// Emit CSP events in the correct order
						trace.event("rover_receive_command")?;

						// Decrypt and execute command (matching servlet handler logic)
						let command: EarthCommand = if ordered_frame.metadata.confidentiality.is_some() {
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

						println!("  [Rover] Command: {}", cmd_type.to_string());

						// Execute command (emits rover_execute_* events)
						command_executor.write()?.execute_command(cmd_type, trace)?;

						// Emit command complete event
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

					advance_clock(delays::ROVER_TO_RELAY_MS * 2);
					println!("  [Rover] Complete - MET: T+{:05}s\n", mission_time_ms() / 1000);
				}
				ProcessResult::Buffered => {
					// Wait for more frames
					continue;
				}
				ProcessResult::ChainGap { .. } => {
					eprintln!("  [Rover] Chain gap detected");
					continue;
				}
			}
		} else {
			// No response received - this shouldn't happen in normal operation
			eprintln!("  [Rover] Warning: No response received from Earth");
			continue;
		}
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

			// Start Earth Ground Station servlet with config
			let earth_config = EarthGroundStationServletConf {
				earth_signing_key,
				rover_verifying_key,
				shared_cipher: shared_cipher.clone(),
				chain_processor: earth_processor,
				frame_builder: earth_frame_builder,
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
				rover_verifying_key,
				earth_verifying_key,
				chain_processor: relay_processor,
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
				shared_cipher: shared_cipher,
				chain_processor: rover_processor,
				fault_manager: rover_fault_manager,
				command_executor: rover_command_executor,
				frame_builder: rover_frame_builder,
				mission_state: rover_mission_state,
				max_rounds: COMMAND_ROUND_TRIPS,
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
