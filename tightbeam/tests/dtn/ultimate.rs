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

#![cfg(all(
	feature = "testing-csp",
	feature = "testing-fdr",
	feature = "std",
	feature = "tcp",
	feature = "tokio",
	feature = "signature",
	feature = "secp256k1",
	feature = "sha3",
	feature = "x509"
))]

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand_core::OsRng;
use tightbeam::{
	builder::{frame::FrameBuilder, TypeBuilder},
	crypto::{
		aead::{Aes256Gcm, Aes256GcmOid},
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	decode, exactly,
	macros::client::builder::ClientBuilder,
	matrix::MatrixDyn,
	prelude::Version,
	tb_assert_spec, tb_process_spec, tb_scenario,
	transport::{policy::RestartExponentialBackoff, tcp::r#async::TokioListener},
};

use crate::dtn::{
	bms::BatteryManagementSystem,
	certs::{generate_shared_cipher, ROVER_CERT, ROVER_KEY, SATELLITE_CERT},
	chain_processor::{ChainProcessor, ProcessResult},
	clock::{advance_clock, delays, init_mission_clock, mission_time_ms},
	fault_matrix::{FaultMatrix, FaultType},
	faults::RoverFaultHandler,
	messages::{EarthCommand, MessageChainState, RoverCommand, RoverInstrument, RoverTelemetry},
	ordering::OutOfOrderBuffer,
	servlets::{
		EarthGroundStationServlet, EarthGroundStationServletConf, RelaySatelliteServlet, RelaySatelliteServletConf,
	},
	storage::FrameStore,
	utils::generate_message_id,
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
	/// Rover chain state for consensus
	pub rover_chain_state: RwLock<MessageChainState>,
	/// Earth chain state for consensus
	pub earth_chain_state: RwLock<MessageChainState>,
	/// Relay chain state for consensus
	pub relay_chain_state: RwLock<MessageChainState>,
	/// Frame storage for Rover
	pub rover_store: RwLock<FrameStore>,
	/// Frame storage for Earth
	pub earth_store: RwLock<FrameStore>,
	/// Frame storage for Relay
	pub relay_store: RwLock<FrameStore>,
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		// Create storage directories
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
			rover_chain_state: RwLock::new(MessageChainState::new("rover".to_string())),
			earth_chain_state: RwLock::new(MessageChainState::new("earth".to_string())),
			relay_chain_state: RwLock::new(MessageChainState::new("relay".to_string())),
			rover_store: RwLock::new(rover_store),
			earth_store: RwLock::new(earth_store),
			relay_store: RwLock::new(relay_store),
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
// Tests
// ============================================================================

#[cfg(feature = "testing-fault")]
fn build_dtn_fdr_config() -> tightbeam::testing::fdr::FdrConfig {
	tightbeam::testing::fdr::FdrConfig {
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
		servlet: RelaySatelliteServlet,
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
			let config_read = config.read()?;
			drop(config_read);

			let earth_store = Arc::new(RwLock::new(FrameStore::new(PathBuf::from("temp/dtn/earth"))?));
			let earth_chain_state = Arc::new(RwLock::new(MessageChainState::new("earth".to_string())));
			let earth_order_buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(10)));

			let earth_processor = Arc::new(ChainProcessor::new(
				earth_store,
				earth_chain_state,
				earth_order_buffer,
				"Earth".to_string(),
			));

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
			};
			let earth_servlet = EarthGroundStationServlet::start(Arc::clone(&trace), Arc::new(earth_config)).await?;
			// Get Earth's address
			let earth_addr = earth_servlet.addr();

			// Create Relay servlet config
			let relay_config = RelaySatelliteServletConf {
				earth_servlet,
				earth_addr,
				rover_verifying_key,
				earth_verifying_key,
				chain_processor: relay_processor,
			};

			// Start and return the Relay Satellite servlet with config
			RelaySatelliteServlet::start(Arc::clone(&trace), Arc::new(relay_config)).await
		},
		setup: |relay_addr, _config| async move {
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

		let rover_signing_key = config.read()?.rover_signing_key.clone();
		let shared_cipher = config.read()?.shared_cipher.clone();

		// Wait for Earth verifying key to be set by the servlet start
		let earth_verifying_key = loop {
			if let Some(key) = config.read()?.earth_verifying_key.read()?.clone() {
				break key;
			}
			// Give the servlet a moment to initialize
			tokio::time::sleep(Duration::from_millis(10)).await;
		};

		// Create ChainProcessor for Rover
		let rover_store = Arc::new(RwLock::new(FrameStore::new(PathBuf::from("temp/dtn/rover"))?));
		let rover_chain_state = Arc::new(RwLock::new(MessageChainState::new("rover".to_string())));
		let rover_order_buffer = Arc::new(RwLock::new(OutOfOrderBuffer::new(10)));

		let chain_processor = Arc::new(ChainProcessor::new(
			rover_store,
			rover_chain_state,
			rover_order_buffer,
			"Rover".to_string(),
		));

		let mut completed_rounds = 0;
		let mut last_command = RoverCommand::Standby;

		// Main mission loop
		while completed_rounds < COMMAND_ROUND_TRIPS {
			// Get battery status from BMS
			let battery = {
				let config_guard = config.read()?;
				let bms_guard = config_guard.bms.read()?;
				bms_guard.charge_percent()
			};

			// Update fault matrix based on battery and store battery percentage
			{
				let config_guard = config.write()?;
				let mut fault_matrix_guard = config_guard.fault_matrix.write()?;
				let bms_guard = config_guard.bms.read()?;
				let was_fault = fault_matrix_guard.is_fault_active(FaultType::LowPower);

				// Store battery percentage in matrix
				fault_matrix_guard.set_battery_percent(battery);

				if bms_guard.is_low_power() && !was_fault {
					// Battery critically low - trigger fault and start recharging
					fault_matrix_guard.set_fault(FaultType::LowPower);
					drop(fault_matrix_guard);
					drop(bms_guard);
					config_guard.rover_fault_handler.write()?.start_low_power_fault();
					println!("⚠ LOW POWER FAULT - Battery: {}% - Beginning recharge", battery);
				} else if bms_guard.is_fully_charged() && was_fault {
					// Battery fully recharged - clear fault
					fault_matrix_guard.clear_fault(FaultType::LowPower);
					drop(fault_matrix_guard);
					drop(bms_guard);
					config_guard.rover_fault_handler.write()?.clear_low_power_fault();
					trace.event("fault_cleared")?;
					println!("✓ BATTERY FULLY RECHARGED ({}%) - Fault cleared", battery);
				}
			}

			// Check for faults using FaultMatrix abstraction
			{
				let fault_matrix = *config.read()?.fault_matrix.read()?;
				let fault_handler = *config.read()?.rover_fault_handler.read()?;
				if fault_handler.should_halt_comms(&fault_matrix) {
					trace.event("fault_low_power_detected")?;
					trace.event("comms_halted")?;
					// Recharge battery during fault
					{
						let config_guard = config.write()?;
						let mut bms_guard = config_guard.bms.write()?;
						let new_charge = bms_guard.recharge();
						println!("⚠ RECHARGING - Battery: {}% - Skipping round", new_charge);
					}
					continue;
				}
			}

			// Drain battery for operational round
			{
				let config_guard = config.write()?;
				let mut bms_guard = config_guard.bms.write()?;
				bms_guard.drain();
			}

			println!("═══════════════ Round {} ═══════════════", completed_rounds + 1);

			// Determine instrument based on last Earth command
			let (instrument, name, data) = match last_command {
				RoverCommand::CollectSample { .. } => (RoverInstrument::APXS, "APXS", b"Fe2O3:42.1%".to_vec()),
				RoverCommand::ProbeLocation { .. } => (RoverInstrument::ChemCam, "ChemCam", b"Na:580nm:12.3".to_vec()),
				RoverCommand::TakePhoto { .. } => (RoverInstrument::Mastcam, "Mastcam", b"IMG:1024x768".to_vec()),
				RoverCommand::Standby => (RoverInstrument::APXS, "APXS", b"STATUS:OK".to_vec()),
			};

				let fault_matrix_snapshot = *config.read()?.fault_matrix.read()?;

				// Rover sends telemetry
				trace.event("rover_send_telemetry")?;

				let telemetry = RoverTelemetry::new(
					instrument,
					data,
					mission_time_ms(),
					battery,
					-20,
				);

			// Prepare outgoing telemetry with previous_frame hash
			let (next_order, previous_digest) = chain_processor.prepare_outgoing()?;

			// Convert FaultMatrix to MatrixDyn for frame
			let matrix_dyn = MatrixDyn::try_from(fault_matrix_snapshot)?;

			// Build frame with previous_frame support
			let mut builder = FrameBuilder::from(Version::V3)
				.with_id(generate_message_id("telemetry", "rover"))
				.with_order(next_order)
				.with_message(telemetry)
				.with_matrix(matrix_dyn)
				.with_message_hasher::<Sha3_256>()
				.with_witness_hasher::<Sha3_256>()
				.with_cipher::<Aes256GcmOid, _>(shared_cipher.clone())
				.with_signer::<Secp256k1Signature, _>(rover_signing_key.clone());

			// Set previous_frame if not the first frame
			if let Some(digest) = previous_digest {
				builder = builder.with_previous_hash(digest);
			}

			let rover_frame = builder.build()?;

			println!("  [Rover] {} telemetry (Battery: {}%) [ENCRYPTED]", name, battery);
				if fault_matrix_snapshot.has_fault() {
					let active: Vec<_> = fault_matrix_snapshot.active_faults().collect();
					println!("  [Rover] ⚠ Active faults: {:?}", active);
				}

			// Finalize outgoing frame
			chain_processor.finalize_outgoing(&rover_frame)?;

			let response = rover_client.emit(rover_frame, None).await?;
			if let Some(response_frame) = response {
				// Verify Earth's signature
				match response_frame.verify::<Secp256k1Signature>(&earth_verifying_key) {
					Ok(_) => println!("  [Rover] ✓ Earth signature verified"),
					Err(e) => return Err(e),
				}

				// Process response
				match chain_processor.process_incoming(response_frame)? {
					ProcessResult::Processed(ordered_frames) => {
						for ordered_frame in ordered_frames {
							trace.event("rover_receive_command")?;

							// Decrypt command
							let command: EarthCommand = if ordered_frame.metadata.confidentiality.is_some() {
								println!("  [Rover] Decrypting command with shared cipher");
								ordered_frame.decrypt::<EarthCommand>(&shared_cipher, None)?
							} else {
								decode(&ordered_frame.message)?
							};

							let cmd_type = RoverCommand::from_u8(command.command_type)
								.ok_or_else(|| tightbeam::TightBeamError::InvalidBody)?;

							println!("  [Rover] Command: {}", cmd_type.to_string());

							// Execute command and update state
							match cmd_type {
								RoverCommand::CollectSample { .. } => {
									trace.event("rover_execute_collect_sample")?;
									println!("  [Rover] Collecting sample...");
									last_command = cmd_type;
								},
								RoverCommand::ProbeLocation { .. } => {
									trace.event("rover_execute_probe_location")?;
									println!("  [Rover] Probing location...");
									last_command = cmd_type;
								},
								RoverCommand::TakePhoto { .. } => {
									trace.event("rover_execute_take_photo")?;
									println!("  [Rover] Capturing image...");
									last_command = cmd_type;
								},
								RoverCommand::Standby => {
									trace.event("rover_execute_standby")?;
									println!("  [Rover] Entering standby...");
									last_command = cmd_type;
								},
							}

							advance_clock(delays::ROVER_TO_RELAY_MS * 2);
							trace.event("rover_command_complete")?;

							println!("  [Rover] Complete - MET: T+{:05}s\n", mission_time_ms() / 1000);

							completed_rounds += 1;
						}
					},
					ProcessResult::Buffered => {
						// Wait for more frames
						continue;
					},
					ProcessResult::ChainGap { .. } => {
						eprintln!("  [Rover] Chain gap detected");
						// TODO: Request missing frames
						continue;
					}
				}
			}
		}

			trace.event("mission_complete")?;
			println!("╔════════════════════════════════════════════════════════════╗");
			println!("║  Mission Complete - {} commands                           ║", completed_rounds);
			println!("╚════════════════════════════════════════════════════════════╝");

			Ok(())
		}
	}
}
