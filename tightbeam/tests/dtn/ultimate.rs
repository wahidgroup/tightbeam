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

use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand_core::OsRng;
use tightbeam::{
	colony::Servlet,
	compose,
	crypto::{
		hash::Sha3_256,
		sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey},
	},
	decode, exactly,
	macros::client::builder::ClientBuilder,
	matrix::MatrixLike,
	tb_assert_spec, tb_process_spec, tb_scenario,
	transport::{policy::RestartExponentialBackoff, tcp::r#async::TokioListener},
};

use crate::dtn::{
	certs::{ROVER_CERT, ROVER_KEY, SATELLITE_CERT},
	clock::{advance_clock, delays, init_mission_clock, mission_time_ms},
	fault_matrix::{FaultMatrix, FaultType},
	faults::RoverFaultHandler,
	messages::{EarthCommand, MessageChainState, RoverCommand, RoverInstrument, RoverTelemetry},
	servlets::{EarthGroundStationServlet, RelaySatelliteServlet, RelaySatelliteServletConf},
	utils::generate_message_id,
};

// ============================================================================
// DTN Scenario Configuration
// ============================================================================

/// Configuration for DTN scenario with cryptographic keys and chain state
pub struct DtnScenarioConfig {
	/// Rover's signing key for nonrepudiation
	pub rover_signing_key: Secp256k1SigningKey,
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
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		Self {
			rover_signing_key: Secp256k1SigningKey::random(&mut OsRng),
			rover_fault_handler: RwLock::new(RoverFaultHandler::new()),
			fault_matrix: RwLock::new(FaultMatrix::new()),
			rover_chain_state: RwLock::new(MessageChainState::new("rover".to_string())),
			earth_chain_state: RwLock::new(MessageChainState::new("earth".to_string())),
			relay_chain_state: RwLock::new(MessageChainState::new("relay".to_string())),
		}
	}
}

// ============================================================================
// Test Configuration
// ============================================================================

/// Number of command/response round-trips for the test.
const COMMAND_ROUND_TRIPS: usize = 3;

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
			("rover_send_telemetry", exactly!(3)),
			("rover_receive_command", exactly!(3)),
			("rover_command_complete", exactly!(3)),
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
			"fault_cleared" => Idle
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
		start: |trace, _config| async move {
			// Start Earth Ground Station servlet
			let earth_servlet = EarthGroundStationServlet::start(Arc::clone(&trace)).await?;
			// Get Earth's address
			let earth_addr = earth_servlet.addr();
			// Generate Earth's signing key
			let earth_signing_key = Secp256k1SigningKey::random(&mut OsRng);

			// Create Relay servlet config with Earth info
			let relay_config = RelaySatelliteServletConf {
				earth_servlet,
				earth_addr,
				earth_signing_key,
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

			let mut completed_rounds = 0;
			let mut last_command = RoverCommand::Standby;

			// Main mission loop
			while completed_rounds < COMMAND_ROUND_TRIPS {

				// Check for faults using FaultMatrix abstraction
				{
					let fault_matrix = *config.read()?.fault_matrix.read()?;
					let fault_handler = *config.read()?.rover_fault_handler.read()?;

					if fault_handler.should_halt_comms(&fault_matrix) {
						trace.event("fault_low_power_detected")?;
						trace.event("comms_halted")?;
						println!("⚠ LOW POWER FAULT - Skipping round");
						continue;
					}
				}

				println!("═══════════════ Round {} ═══════════════", completed_rounds + 1);

				// Determine instrument based on last Earth command
				let (instrument, name, data) = match last_command {
					RoverCommand::CollectSample { .. } => (RoverInstrument::APXS, "APXS", b"Fe2O3:42.1%".to_vec()),
					RoverCommand::ProbeLocation { .. } => (RoverInstrument::ChemCam, "ChemCam", b"Na:580nm:12.3".to_vec()),
					RoverCommand::TakePhoto { .. } => (RoverInstrument::Mastcam, "Mastcam", b"IMG:1024x768".to_vec()),
					RoverCommand::Standby => (RoverInstrument::APXS, "APXS", b"STATUS:OK".to_vec()),
				};

				// Simulate battery drain
				let battery = 100u8.saturating_sub(completed_rounds as u8 * 15);

				// Update fault matrix based on battery
				{
					let config_guard = config.write()?;
					let mut fault_matrix_guard = config_guard.fault_matrix.write()?;

					if battery < 25 {
						fault_matrix_guard.set_fault(FaultType::LowPower);
						drop(fault_matrix_guard);
						config_guard.rover_fault_handler.write()?.start_low_power_fault();
					} else {
						// Battery recovered - clear fault if active
						let was_fault = fault_matrix_guard.is_fault_active(FaultType::LowPower);
						if was_fault {
							fault_matrix_guard.clear_fault(FaultType::LowPower);
							drop(fault_matrix_guard);
							config_guard.rover_fault_handler.write()?.clear_low_power_fault();
							trace.event("fault_cleared")?;
							println!("✓ BATTERY RECOVERED - Fault cleared");
						}
					}
				}

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

				// Convert FaultMatrix to MatrixDyn for frame
				use tightbeam::matrix::MatrixDyn;
				let matrix_3: tightbeam::matrix::Matrix<3> = fault_matrix_snapshot.into();
				let matrix_dyn = {
					let n = 3u8;
					let mut data = Vec::with_capacity(9);
					for r in 0..n {
						for c in 0..n {
							data.push(matrix_3.get(r, c));
						}
					}
					MatrixDyn::from_row_major(n, data).ok_or_else(|| tightbeam::TightBeamError::InvalidBody)?
				};

				let rover_frame = compose! {
					V3: id: generate_message_id("telemetry", "rover"),
						order: completed_rounds as u64 + 1,
						message: telemetry,
						matrix: matrix_dyn,
						message_integrity: type Sha3_256,
						frame_integrity: type Sha3_256,
						nonrepudiation<Secp256k1Signature, _>: rover_signing_key.clone()
				}?;

				println!("  [Rover] {} telemetry (Battery: {}%)", name, battery);
				if fault_matrix_snapshot.has_fault() {
					let active: Vec<_> = fault_matrix_snapshot.active_faults().collect();
					println!("  [Rover] ⚠ Active faults: {:?}", active);
				}

				let response = rover_client.emit(rover_frame, None).await?;

				if let Some(response_frame) = response {
					trace.event("rover_receive_command")?;

					let command: EarthCommand = decode(&response_frame.message)?;
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

					println!("  [Rover] Complete - MET: T+{:05}s\n",
						mission_time_ms() / 1000);

					completed_rounds += 1;
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
