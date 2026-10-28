//! The DTN test runs the framework end to end on a simulated Mars mission.
//!
//! # Scenario
//!
//! A four-tier DTN path links Mission Control, two relay satellites and a Mars
//! rover:
//!
//! - Mission Control (Earth-based command center)
//! - Earth Relay Satellite (orbiting Earth)
//! - Mars Relay Satellite (orbiting Mars)
//! - Mars Rover (surface operations)
//!
//! # Features
//!
//! - Rover telemetry modelled on NASA instruments (APXS, ChemCam, Mastcam)
//! - A simulated mission clock with the Mars-Earth delays of the timeline below
//! - Cryptographic chain validation over `previous_frame` hash chains
//! - A matrix bit field for the rover fault flags
//! - Fault recovery: low power, then recharge, then resume
//! - Cascading gap recovery
//!
//! # Timeline
//!
//! Each leg restarts its clock at T+0.
//!
//! | Leg | Step | Mission time |
//! | --- | --- | --- |
//! | Command | Mission Control sends the command | T+0 |
//! | Command | Earth Relay forwards | T+1.5s |
//! | Command | Mars Relay forwards | T+12.5min |
//! | Command | Rover receives, executes, and sends a stateful ACK | T+13min |
//! | Command | Mission Control receives the ACK | T+25min |
//! | Telemetry | Rover sends telemetry | T+0 |
//! | Telemetry | Mars Relay forwards | T+1.5s |
//! | Telemetry | Earth Relay forwards | T+12.5min |
//! | Telemetry | Mission Control receives it and sends the next command | T+13min |

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tightbeam::{
	asn1::MessagePriority,
	at_most,
	crypto::sign::ecdsa::Secp256k1SigningKey,
	error::TightBeamError,
	exactly,
	instrumentation::TbInstrumentationConfig,
	prelude::*,
	tb_assert_spec, tb_compose_spec, tb_process_spec, tb_scenario,
	testing::{fdr::FdrConfig, specs::composition::CompositionSpec, specs::csp::Process, ScenarioConfig},
	trace::{LogFilter, LogLevel, LoggerConfig, StdoutBackend, TraceCollector, TraceConfig},
	transport::{tcp::r#async::TokioListener, GenericClient},
	urn::Urn,
	wcet,
};

use crate::common::poll::poll_until;
use crate::common::security::expectation_failure;
use crate::dtn::events::*;
use crate::dtn::messages::RoverInstrument;

/// The gap-recovery steps that servlets and workers share.
///
/// Each step resolves, on the node of a [`DtnRole`], to a URN constant of
/// `dtn::events`, so event identity stays URN-only.
#[derive(Clone, Copy)]
pub(crate) enum GapRecoveryStep {
	GapDetected,
	SendFrameRequest,
	ReceiveFrameRequest,
	SendFrameResponse,
	ReceiveFrameResponse,
	CascadeFrameRequest,
}

impl GapRecoveryStep {
	/// The URN of this step on the node of `role`.
	pub(crate) fn event_on(self, role: DtnRole) -> Urn<'static> {
		let [mission_control, earth_relay, mars_relay, rover] = match self {
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

		match role {
			DtnRole::MissionControl => mission_control,
			DtnRole::EarthRelay => earth_relay,
			DtnRole::MarsRelay => mars_relay,
			DtnRole::Rover => rover,
		}
	}
}
use crate::dtn::{
	bms::BatteryManagementSystem,
	certs::{generate_shared_cipher, SharedCipher},
	chain_processor::ChainProcessor,
	clock::{advance_clock, delays, init_mission_clock, mission_time_ms},
	fault_manager::{BatteryUpdate, FaultManager},
	fault_matrix::FaultMatrix,
	faults::RoverFaultHandler,
	frame_builder::FrameBuilderHelper,
	messages::{EarthCommand, RoverCommand, RoverTelemetry},
	nodes::{DtnPath, DtnRole, NodeChain},
	servlets::{EarthRelaySatelliteServlet, LateAddr, MarsRelaySatelliteServlet, MissionControlServlet, MissionState},
	storage::StorageRoot,
};

/// The configuration of the four-tier DTN scenario. It holds only the state
/// that more than one component shares or that the test client reads.
pub struct DtnScenarioConfig {
	/// The rover's signing key, which the rover servlet and the mission loop
	/// client share.
	pub rover_signing_key: Secp256k1SigningKey,
	/// The AES-256-GCM cipher that Mission Control and the rover share for
	/// end-to-end encryption.
	pub shared_cipher: SharedCipher,

	/// The battery management system, which the mission loop monitors.
	pub bms: RwLock<BatteryManagementSystem>,
	/// The fault handler that runs the rover's recovery logic.
	pub rover_fault_handler: RwLock<RoverFaultHandler>,
	/// The current fault state, as a matrix that encapsulates its encoding and
	/// decoding.
	pub fault_matrix: RwLock<FaultMatrix>,
	/// The rover's chain processor, which the rover servlet and the mission
	/// loop client share.
	pub rover_chain_processor: Arc<ChainProcessor>,

	/// The address of Mission Control, recorded once its servlet starts.
	pub mission_control_addr: RwLock<Option<TightBeamSocketAddr>>,
	/// The address of the Earth relay, recorded once its servlet starts.
	pub earth_relay_addr: RwLock<Option<TightBeamSocketAddr>>,
	/// The address of the Mars relay, recorded once its servlet starts, which
	/// the rover client connects to.
	pub mars_relay_addr: RwLock<Option<TightBeamSocketAddr>>,
	/// The address of the rover, recorded once its servlet starts.
	pub rover_addr: RwLock<Option<TightBeamSocketAddr>>,

	/// The mission state through which the rover servlet and the mission loop
	/// synchronize.
	pub mission_state: Arc<RwLock<MissionState>>,

	/// The Mission Control servlet, held to keep it alive for the test.
	pub _mission_control_servlet: RwLock<Option<MissionControlServlet>>,
	/// The Earth relay servlet, held to keep it alive for the test.
	pub _earth_relay_servlet: RwLock<Option<EarthRelaySatelliteServlet>>,
	/// The Mars relay servlet, held to keep it alive for the test.
	pub _mars_relay_servlet: RwLock<Option<MarsRelaySatelliteServlet>>,

	/// The storage root of every node's frame store, which this scenario owns
	/// alone. [`Drop`] removes it after it stops the servlets that write into
	/// it.
	storage: Option<StorageRoot>,
}

impl DtnScenarioConfig {
	/// The storage root that every node's frame store sits in.
	fn storage(&self) -> &StorageRoot {
		self.storage.as_ref().expect("the storage root lives until the scenario drops")
	}
}

impl Default for DtnScenarioConfig {
	fn default() -> Self {
		let storage = StorageRoot::create().expect("Failed to create the storage root");

		let rover_chain = NodeChain::open(&storage, DtnRole::Rover.node_name());
		let rover_chain_proc = rover_chain.expect("Failed to create rover storage").processor;

		Self {
			// The components share this key material.
			rover_signing_key: DtnRole::Rover.signing_key(),
			shared_cipher: generate_shared_cipher(),

			// The mission loop client shares the rover state.
			bms: RwLock::new(BatteryManagementSystem::default()),
			rover_fault_handler: RwLock::new(RoverFaultHandler::new()),
			fault_matrix: RwLock::new(FaultMatrix::new()),
			rover_chain_processor: rover_chain_proc,

			// Each address stays empty until its servlet starts.
			mission_control_addr: RwLock::new(None),
			earth_relay_addr: RwLock::new(None),
			mars_relay_addr: RwLock::new(None),
			rover_addr: RwLock::new(None),
			mission_state: Arc::new(RwLock::new(MissionState::default())),

			// Each servlet slot stays empty until the servlet starts.
			_mission_control_servlet: RwLock::new(None),
			_earth_relay_servlet: RwLock::new(None),
			_mars_relay_servlet: RwLock::new(None),
			storage: Some(storage),
		}
	}
}

impl Drop for DtnScenarioConfig {
	fn drop(&mut self) {
		// Each servlet shuts down when its handle drops here.
		self._mission_control_servlet.write().ok().and_then(|mut g| g.take());
		self._earth_relay_servlet.write().ok().and_then(|mut g| g.take());
		self._mars_relay_servlet.write().ok().and_then(|mut g| g.take());

		// The servlets write into the storage tree, so the tree goes after
		// them.
		drop(self.storage.take());
	}
}

/// The number of command and response round trips the test runs.
const COMMAND_ROUND_TRIPS: usize = 6;

// Telemetry flows from the rover through the Mars relay and the Earth relay to
// Mission Control.
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

// Commands flow from Mission Control through the Earth relay and the Mars relay
// to the rover, and the ACK travels back.
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

// This process models the mission lifecycle and its low-power fault recovery.
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

// The data flows interleave the telemetry flow and the command flow.
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
		deterministic: true
	},
	annotations {
		description: "DTN data flows (telemetry and commands) - fully asynchronous"
	}
}

// The full system then interleaves the data flows with the mission lifecycle.
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
		deterministic: true
	},
	annotations {
		description: "DTN system with independent interleaved telemetry, command, and lifecycle flows"
	}
}

// This spec states the event counts that the four-tier run must reach.
tb_assert_spec! {
	pub DtnEventCountSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			// The mission starts and completes once.
			(MISSION_START, exactly!(1)),
			(MISSION_COMPLETE, exactly!(1)),

			// Each Mission Control event fires once per round trip.
			(MISSION_CONTROL_SEND_COMMAND, exactly!(6)),
			(MISSION_CONTROL_RECEIVE_ACK, exactly!(6)),
			(MISSION_CONTROL_RECEIVE_TELEMETRY, exactly!(6)),
			(MISSION_CONTROL_ANALYZE_TELEMETRY, exactly!(6)),

			// Mission Control records zero gap-recovery events.
			(MISSION_CONTROL_GAP_DETECTED, at_most!(0)),
			(MISSION_CONTROL_SEND_FRAME_REQUEST, at_most!(0)),
			(MISSION_CONTROL_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(MISSION_CONTROL_SEND_FRAME_RESPONSE, at_most!(0)),
			(MISSION_CONTROL_RECEIVE_FRAME_RESPONSE, at_most!(0)),

			// Each Earth relay event fires once per round trip.
			(EARTH_RELAY_RECEIVE_FROM_MC, exactly!(6)),
			(EARTH_RELAY_FORWARD_TO_MARS, exactly!(6)),
			(EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS, exactly!(6)),
			(EARTH_RELAY_RECEIVE_ACK_FROM_MARS, exactly!(6)),
			(EARTH_RELAY_FORWARD_TELEMETRY_TO_MC, exactly!(6)),
			(EARTH_RELAY_FORWARD_ACK_TO_MC, exactly!(6)),

			// The Earth relay records zero gap-recovery events.
			(EARTH_RELAY_GAP_DETECTED, at_most!(0)),
			(EARTH_RELAY_SEND_FRAME_REQUEST, at_most!(0)),
			(EARTH_RELAY_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(EARTH_RELAY_SEND_FRAME_RESPONSE, at_most!(0)),
			(EARTH_RELAY_RECEIVE_FRAME_RESPONSE, at_most!(0)),
			(EARTH_RELAY_CASCADE_FRAME_REQUEST, at_most!(0)),

			// Each Mars relay event fires once per round trip.
			(MARS_RELAY_RECEIVE_FROM_EARTH, exactly!(6)),
			(MARS_RELAY_FORWARD_TO_ROVER, exactly!(6)),
			(MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER, exactly!(6)),
			(MARS_RELAY_RECEIVE_ACK_FROM_ROVER, exactly!(6)),
			(MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH, exactly!(6)),
			(MARS_RELAY_FORWARD_ACK_TO_EARTH, exactly!(6)),

			// The Mars relay records zero gap-recovery events.
			(MARS_RELAY_GAP_DETECTED, at_most!(0)),
			(MARS_RELAY_SEND_FRAME_REQUEST, at_most!(0)),
			(MARS_RELAY_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(MARS_RELAY_SEND_FRAME_RESPONSE, at_most!(0)),
			(MARS_RELAY_RECEIVE_FRAME_RESPONSE, at_most!(0)),
			(MARS_RELAY_CASCADE_FRAME_REQUEST, at_most!(0)),

			// Each rover event fires once per round trip.
			(ROVER_RECEIVE_COMMAND, exactly!(6)),
			(ROVER_EXECUTE_COMMAND, exactly!(6)),
			(ROVER_COMMAND_COMPLETE, exactly!(6)),
			(ROVER_SEND_ACK, exactly!(6)),
			(ROVER_SEND_TELEMETRY, exactly!(6)),

			// The rover records zero gap-recovery events.
			(ROVER_GAP_DETECTED, at_most!(0)),
			(ROVER_SEND_FRAME_REQUEST, at_most!(0)),
			(ROVER_RECEIVE_FRAME_REQUEST, at_most!(0)),
			(ROVER_SEND_FRAME_RESPONSE, at_most!(0)),
			(ROVER_RECEIVE_FRAME_RESPONSE, at_most!(0))
		]
	}
}

/// Builds a telemetry frame and sends it one way to the Mars relay, which
/// forwards it through the Earth relay to Mission Control.
async fn send_telemetry_to_mars_relay(
	trace: &TraceCollector,
	rover_client: &mut GenericClient<TokioListener>,
	rover_processor: &Arc<ChainProcessor>,
	rover_frame_builder: &Arc<FrameBuilderHelper>,
	fault_manager: &Arc<FaultManager>,
	rover_signing_key: &Secp256k1SigningKey,
	shared_cipher: &SharedCipher,
) -> Result<(), TightBeamError> {
	// Periodic telemetry reads the default instrument, APXS.
	let instrument = RoverInstrument::Apxs;
	let data = b"STATUS:OK".to_vec();
	let battery = fault_manager.battery_percent()?;
	let fault_matrix_snapshot = fault_manager.fault_matrix()?;

	trace.event(ROVER_SEND_TELEMETRY)?;

	let telemetry = RoverTelemetry::new(instrument, data, mission_time_ms(), battery, -20)?;
	let (next_order, previous_digest) = rover_processor.prepare_outgoing()?;
	let rover_frame = rover_frame_builder.build_relay_telemetry_frame(
		telemetry,
		fault_matrix_snapshot,
		next_order,
		previous_digest,
		rover_signing_key,
		shared_cipher,
	)?;

	// The Mars relay answers with a stateless ACK, which the rover discards
	// because the ACK joins no chain.
	rover_client.emit(rover_frame, None).await?;

	Ok(())
}

/// Runs the rover mission loop, which sends telemetry periodically.
///
/// Each round runs these steps asynchronously, in order:
///
/// 1. The rover sends telemetry through a satellite to Earth.
/// 2. Earth answers with a command through a satellite to the rover.
/// 3. The rover sends an ACK through a satellite to Earth.
/// 4. The rover executes the command and sends the next telemetry.
#[allow(clippy::too_many_arguments)]
async fn run_mission_loop(
	trace: &TraceCollector,
	rover_client: &mut GenericClient<TokioListener>,
	rover_processor: &Arc<ChainProcessor>,
	rover_frame_builder: &Arc<FrameBuilderHelper>,
	fault_manager: &Arc<FaultManager>,
	rover_signing_key: &Secp256k1SigningKey,
	shared_cipher: &SharedCipher,
	shared_mission_state: &Arc<RwLock<MissionState>>,
) -> Result<(), TightBeamError> {
	if !await_completed_rounds(shared_mission_state, 1).await {
		return Err(expectation_failure("the first command never reached the rover"));
	}

	// The loop runs COMMAND_ROUND_TRIPS (6) rounds from round 0, because the
	// rover has executed command 0 and owes its telemetry.
	for round in 0..COMMAND_ROUND_TRIPS {
		let battery_update = fault_manager.update_battery_state()?;
		match battery_update {
			BatteryUpdate::LowPowerDetected(_battery) => {
				trace.event(FAULT_LOW_POWER_DETECTED)?;
				trace.event(COMMS_HALTED)?;

				advance_clock(delays::ROVER_RECHARGE_MS);

				while fault_manager.battery_percent()? < 100 {
					fault_manager.reenergize_battery()?;
				}

				trace.event(FAULT_CLEARED)?;
			}
			BatteryUpdate::FaultCleared(_battery) => {
				// The battery is full again, so this round skips the drain.
			}
			BatteryUpdate::Updated => {
				// Each normal round drains the battery.
				fault_manager.drain_battery()?;
			}
		}

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

		// The simulated mission clock advances past the propagation delays, so
		// the test runs fast.
		advance_clock(delays::ROVER_TO_RELAY_MS);
		advance_clock(delays::RELAY_TO_EARTH_MS);

		// Every round but the last waits for the rover servlet to execute the
		// next command.
		if round < COMMAND_ROUND_TRIPS - 1 {
			let target_completed = round + 2; // It covers commands 0 to `round + 1`.
			if !await_completed_rounds(shared_mission_state, target_completed).await {
				return Err(expectation_failure("the rover never executed the next command"));
			}
		}
	}

	Ok(())
}

/// Waits up to 10 s for the rover servlet to complete `rounds` commands, and
/// returns whether it did.
async fn await_completed_rounds(state: &RwLock<MissionState>, rounds: usize) -> bool {
	let reached = || state.read().is_ok_and(|mission| mission.completed_rounds >= rounds);
	poll_until(100, Duration::from_millis(100), reached).await
}

/// Builds the FDR configuration of the DTN test.
///
/// The framework's FDR runs in two modes:
///
/// 1. CSP spec exploration: the framework explores the state space of `DtnComposedSystem`.
/// 2. Trace refinement: the framework checks the runtime trace against the spec in `specs`.
fn build_dtn_fdr_config_refinement(process: Process) -> FdrConfig {
	FdrConfig {
		seeds: 2, // Each seed explores another interleaving of the CSP model.
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 15000,
		specs: vec![process], // It turns on trace refinement.
		fail_fast: true,
		scheduler: None,
		fault_model: None,
		#[cfg(feature = "testing-fmea")]
		fmea_config: None,
	}
}

/// The configuration of the DTN scenario over `trace`. It grades the event
/// counts, checks the run and the claims of [`DtnComposedSystem`], and refines
/// the run against it.
fn dtn_config(trace: TraceCollector) -> Result<ScenarioConfig, Box<dyn core::error::Error>> {
	let fdr = build_dtn_fdr_config_refinement(DtnComposedSystem::process()?);
	let builder = ScenarioConfig::builder()
		.with_spec(DtnEventCountSpec::latest())
		.with_csp(DtnComposedSystem);
	Ok(builder.with_fdr(fdr).with_trace(trace).build()?)
}

tb_scenario! {
	name: dtn_ultimate_realistic,
	config: dtn_config(TraceConfig::with_instrumentation(TbInstrumentationConfig {
				enable_payloads: false,
				enable_internal_detail: true,
				sample_enabled_sets: true,
				sample_refusals: true,
				divergence_heuristics: true,
				record_durations: true,
				max_events: 4096,
			})
			.with_logger(LoggerConfig::new(
				StdoutBackend,
				LogFilter::new(LogLevel::Error)
			).with_default_level(LogLevel::Debug))
			.into()
		),
	environment Servlet {
		context: DtnScenarioConfig::default(),
		start: |env| async move {
			let (trace, config) = (Arc::new(env.trace), env.context);
			// Servlets start from the rover outward: the Mars relay, then the
			// Earth relay, then Mission Control. Each one then holds the
			// address it connects to.

			// The scenario config shares these components with every servlet.
			let path = DtnPath {
				trace: Arc::clone(&trace),
				cipher: config.shared_cipher.to_owned(),
				mission_state: Arc::clone(&config.mission_state),
				rounds: COMMAND_ROUND_TRIPS,
			};

			// Each node gets a chain of its own, and the rover's chain runs
			// over the processor from `Default`, which the mission loop client
			// shares.
			let mc_chain = NodeChain::open(config.storage(), DtnRole::MissionControl.node_name())?;
			let earth_relay_chain = NodeChain::open(config.storage(), DtnRole::EarthRelay.node_name())?;
			let mars_relay_chain = NodeChain::open(config.storage(), DtnRole::MarsRelay.node_name())?;
			let rover_chain = NodeChain::over(Arc::clone(&config.rover_chain_processor));

			// A node that starts after the node that dials it publishes its
			// address into one of these slots.
			let rover_mars_relay_addr = LateAddr::default();
			let mars_earth_relay_addr = LateAddr::default();
			let earth_mission_control_addr = LateAddr::default();


			// 1. Start the rover servlet.
			let rover_fault_manager = Arc::new(FaultManager::from_refs(
				&config.bms,
				&config.fault_matrix,
				&config.rover_fault_handler,
			));

			let rover_servlet = path.start_rover(&rover_chain, &rover_mars_relay_addr, rover_fault_manager).await?;
			let rover_addr = rover_servlet.addr().to_owned();

			config.rover_addr.write()?.replace(rover_addr);


			// 2. Start the Mars relay servlet.
			let mars_relay_servlet = path.start_mars_relay(&mars_relay_chain, rover_addr, &mars_earth_relay_addr).await?;
			let mars_relay_addr = mars_relay_servlet.addr().to_owned();

			// The rover reads the Mars relay address from this slot.
			*rover_mars_relay_addr.write()? = Some(mars_relay_addr);

			// The config keeps the servlet alive and holds its address.
			config._mars_relay_servlet.write()?.replace(mars_relay_servlet);
			config.mars_relay_addr.write()?.replace(mars_relay_addr);


			// 3. Start the Earth relay servlet.
			let earth_relay_servlet = path.start_earth_relay(&earth_relay_chain, mars_relay_addr, &earth_mission_control_addr).await?;
			let earth_relay_addr = earth_relay_servlet.addr().to_owned();

			// The Mars relay reads the Earth relay address from this slot.
			*mars_earth_relay_addr.write()? = Some(earth_relay_addr);

			// The config keeps the servlet alive and holds its address.
			config._earth_relay_servlet.write()?.replace(earth_relay_servlet);
			config.earth_relay_addr.write()?.replace(earth_relay_addr);

			// 4. Start the Mission Control servlet.
			let mc_servlet = path.start_mission_control(&mc_chain, earth_relay_addr).await?;
			let mc_addr = mc_servlet.addr().to_owned();

			// The Earth relay reads the Mission Control address from this slot.
			*earth_mission_control_addr.write()? = Some(mc_addr);

			// The config keeps the servlet alive and holds its address.
			config._mission_control_servlet.write()?.replace(mc_servlet);
			config.mission_control_addr.write()?.replace(mc_addr);


			// 5. Initialize the mission clock.
			init_mission_clock();
			trace.event(MISSION_START)?;


			// 6. Send the initial command from Mission Control.
			{
				let initial_cmd = RoverCommand::ProbeLocation { x: 100, y: 200 };
				let (next_order, previous_digest) = mc_chain.processor.prepare_outgoing()?;
				let command = EarthCommand::new(initial_cmd, MessagePriority::Standard, mission_time_ms())?;

				trace.event(MISSION_CONTROL_SEND_COMMAND)?;

				let command_frame = mc_chain.frame_builder.build_relay_command_frame(
					command,
					next_order,
					previous_digest,
					&DtnRole::MissionControl.signing_key(),
					&path.cipher,
				)?;

				// Mission Control sends the first command to the Earth relay
				// over a client of its own.
				let mut earth_relay_client = DtnRole::MissionControl.connect(DtnRole::EarthRelay, earth_relay_addr).await?;

				earth_relay_client.emit(command_frame, None).await?;
			}

			Ok(rover_servlet)
		},
		setup: |env| async move {
			let config = env.context;
			let mars_relay_addr = (*config.mars_relay_addr.read()?).ok_or(TightBeamError::MissingConfiguration)?;

			// The mission loop sends through this client to the Mars relay.
			let client = DtnRole::Rover.connect(DtnRole::MarsRelay, mars_relay_addr).await?;
			Ok(client)
		},
		client: |env| async move {
			let (trace, mut rover_client, config) = (env.trace, env.client, env.context);
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

#[cfg(test)]
mod tests {
	use tightbeam::tb_cases;

	use super::*;

	// A gap-recovery step records the event of the node that it runs on.
	tb_cases! {
		fn a_gap_step_records_the_event_of_its_node((role, event): (DtnRole, Urn<'static>)) -> Result<(), TightBeamError> {
			let trace = TraceCollector::new();
			trace.event(GapRecoveryStep::GapDetected.event_on(role))?;
			assert_eq!(trace.recorded(event), 1);
			Ok(())
		}
		cases {
			mission_control => (DtnRole::MissionControl, MISSION_CONTROL_GAP_DETECTED),
			earth_relay => (DtnRole::EarthRelay, EARTH_RELAY_GAP_DETECTED),
			mars_relay => (DtnRole::MarsRelay, MARS_RELAY_GAP_DETECTED),
			rover => (DtnRole::Rover, ROVER_GAP_DETECTED),
		}
	}
}
