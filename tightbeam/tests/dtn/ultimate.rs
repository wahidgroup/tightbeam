//! The DTN test runs a mission-critical demonstration of the framework.
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
//! - Realistic NASA-inspired rover telemetry (APXS, ChemCam, Mastcam)
//! - Simulated mission clock with realistic Mars-Earth delays
//! - Cryptographic chain validation over `previous_frame` hash chains
//! - Matrix bit field for rover fault flags
//! - Graceful fault handling: low power, then recharge, then resume
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

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::{
	asn1::MessagePriority,
	at_most,
	builder::TypeBuilder,
	crypto::{
		key::SigningKeySpec,
		policy::Secp256k1Policy,
		sign::ecdsa::{Secp256k1, Secp256k1SigningKey},
		x509::{
			policy::CertificateValidation,
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
			Certificate, CertificateSpec,
		},
	},
	error::TightBeamError,
	exactly,
	instrumentation::TbInstrumentationConfig,
	prelude::*,
	tb_assert_spec, tb_compose_spec, tb_process_spec, tb_scenario,
	testing::{fdr::FdrConfig, specs::composition::CompositionSpec, ScenarioConfig},
	trace::{LogFilter, LogLevel, LoggerConfig, StdoutBackend, TraceCollector, TraceConfig},
	transport::{
		tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder, ConnectionPool, GenericClient, PoolConfig,
	},
	urn::Urn,
	wcet,
};

use crate::common::poll::poll_until;
use crate::common::security::expectation_failure;
use crate::dtn::events::*;
use crate::dtn::messages::RoverInstrument;

/// Gap-recovery steps shared by servlets and workers.
///
/// Call sites with a dynamic `node_name` resolve through this enum to the URN
/// constants of `dtn::events`, so event identity stays URN-only.
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
	certs::{earth_relay_pinning, mars_relay_pinning, mission_control_pinning, rover_pinning},
	messages::RelayMessage,
};

use crate::dtn::{
	bms::BatteryManagementSystem,
	certs::{
		earth_relay_signer, generate_shared_cipher, mars_relay_signer, mission_control_signer, rover_signer,
		SharedCipher, EARTH_RELAY_CERT, EARTH_RELAY_KEY, MARS_RELAY_CERT, MARS_RELAY_KEY, MISSION_CONTROL_CERT,
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
		EarthRelaySatelliteServlet, EarthRelaySatelliteServletConfig, MarsRelaySatelliteServlet,
		MarsRelaySatelliteServletConfig, MissionControlServlet, MissionControlServletConfig, MissionState,
		RoverServlet, RoverServletConfig,
	},
	storage::{FrameStore, StorageRoot},
	workers::{
		CommandAckHandlerWorker, CommandExecutionWorker, FrameRequestHandlerWorker, FrameRequestHandlerWorkerConfig,
		FrameResponseHandlerWorker, FrameResponseHandlerWorkerConfig, MissionControlTelemetryHandlerWorker,
		MissionControlTelemetryHandlerWorkerConfig, RoverCommandHandlerWorker, RoverCommandHandlerWorkerConfig,
		TelemetryBuilderWorker, TelemetryBuilderWorkerConfig,
	},
};

fn make_trust_store(cert_spec: CertificateSpec) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let cert = Certificate::try_from(cert_spec)?;
	let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	Ok(Arc::new(builder.with_certificate(cert)?.build()))
}

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

	/// Storage root of every node's frame store, which this scenario owns
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
		// The rover's chain processor shares this frame store.
		let rover_store = Arc::new(RwLock::new(
			FrameStore::new(storage.node("rover")).expect("Failed to create rover storage"),
		));

		let rover_key_bytes = match ROVER_KEY {
			SigningKeySpec::Bytes(bytes) => bytes,
			_ => panic!("ROVER_KEY must be KeySpec::Bytes"),
		};

		// The rover servlet and the mission loop client share this chain
		// processor.
		let rover_chain_proc = Arc::new(ChainProcessor::new(
			Arc::clone(&rover_store),
			Arc::new(RwLock::new(MessageChainState::new("Rover".to_string()))),
			Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
		));

		Self {
			// The components share this key material.
			rover_signing_key: Secp256k1SigningKey::from_slice(rover_key_bytes).expect("ROVER_KEY is valid"),
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
		deterministic: false
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
		deterministic: false
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

/// Build a telemetry frame and send it one way to the Mars relay, which
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

	// The Mars relay answers with a stateless ACK, which the rover discards
	// because the ACK joins no chain.
	rover_client.emit(rover_frame, None).await?;

	Ok(())
}

/// Run the rover mission loop, which sends telemetry periodically.
///
/// Each round is fully async:
///
/// - The rover sends telemetry through a satellite to Earth.
/// - Earth answers with a command through a satellite to the rover.
/// - The rover sends an ACK through a satellite to Earth.
/// - The rover executes the command and sends the next telemetry.
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

		// Send telemetry to the Mars relay, which forwards it through the Earth
		// relay to Mission Control.
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

		// The simulated mission clock jumps over the realistic propagation
		// delays, so the test runs fast.
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

/// Wait up to 10 s for the rover servlet to complete `rounds` commands.
async fn await_completed_rounds(state: &RwLock<MissionState>, rounds: usize) -> bool {
	let reached = || state.read().is_ok_and(|mission| mission.completed_rounds >= rounds);
	poll_until(100, Duration::from_millis(100), reached).await
}

/// Build the FDR configuration of the DTN test.
///
/// The framework's FDR runs in two modes:
/// 1. CSP spec exploration: the framework explores the state space of `DtnComposedSystem`.
/// 2. Trace refinement: the framework checks the runtime trace against the spec in `specs`.
fn build_dtn_fdr_config_refinement() -> FdrConfig {
	FdrConfig {
		seeds: 2, // Each seed explores another interleaving of the CSP model.
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 15000,
		specs: vec![DtnComposedSystem::process()], // It turns on trace refinement.
		fail_fast: true,
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
	config: ScenarioConfig::builder()
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
				StdoutBackend,
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
			// Servlets start from the rover outward: the Mars relay, then the
			// Earth relay, then Mission Control. Each one then holds the
			// address it connects to.

			// The scenario config shares these components with every servlet.
			let shared_cipher = config.shared_cipher.to_owned();
			let rover_signing_key = config.rover_signing_key.to_owned();
			let shared_mission_state = Arc::clone(&config.mission_state);
			let rover_processor = Arc::clone(&config.rover_chain_processor);

			// The servlets share these signer certificates.
			let mc_signer = mission_control_signer();
			let earth_relay_signer_val = earth_relay_signer();
			let mars_relay_signer_val = mars_relay_signer();
			let rover_signer_val = rover_signer();


			// Mission Control gets a store, a signing key, a chain processor,
			// and a frame builder.
			let mc_key_bytes = match MISSION_CONTROL_KEY {
				SigningKeySpec::Bytes(bytes) => bytes,
				_ => panic!("MISSION_CONTROL_KEY must be KeySpec::Bytes"),
			};
			let mission_control_signing_key = Secp256k1SigningKey::from_slice(mc_key_bytes)?;
			let mc_store = Arc::new(RwLock::new(
				FrameStore::new(config.storage().node("mission_control"))?,
			));
			let mc_processor = Arc::new(ChainProcessor::new(
				Arc::clone(&mc_store),
				Arc::new(RwLock::new(MessageChainState::new("MissionControl".to_string()))),
				Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
			));
			let mc_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&mc_processor)));

			// The Earth relay gets a store, a chain processor, and a
			// frame builder.
			let earth_relay_store = Arc::new(RwLock::new(
				FrameStore::new(config.storage().node("earth_relay"))?,
			));
			let earth_relay_processor = Arc::new(ChainProcessor::new(
				Arc::clone(&earth_relay_store),
				Arc::new(RwLock::new(MessageChainState::new("EarthRelay".to_string()))),
				Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
			));
			let earth_relay_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&earth_relay_processor)));

			// The Mars relay gets a store, a chain processor, and a
			// frame builder.
			let mars_relay_store = Arc::new(RwLock::new(
				FrameStore::new(config.storage().node("mars_relay"))?,
			));
			let mars_relay_processor = Arc::new(ChainProcessor::new(
				Arc::clone(&mars_relay_store),
				Arc::new(RwLock::new(MessageChainState::new("MarsRelay".to_string()))),
				Arc::new(RwLock::new(OutOfOrderBuffer::new(10))),
			));
			let mars_relay_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&mars_relay_processor)));

			// The rover's frame builder runs over the processor from `Default`.
			let rover_frame_builder = Arc::new(FrameBuilderHelper::new(Arc::clone(&rover_processor)));

			// Every pool dials its destination over TLS with mutual
			// authentication and holds at most 3 connections per destination.
			let pool_config = PoolConfig { max_connections: 3, ..PoolConfig::default() };

			// Mission Control dials the Earth relay through this pool.
			let mc_earth_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(EARTH_RELAY_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?)?)
				.build());

			// The Earth relay dials Mission Control through this pool.
			let earth_mc_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(MISSION_CONTROL_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?)?)
				.build());

			// The Earth relay dials the Mars relay through this pool.
			let earth_mars_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(MARS_RELAY_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?)?)
				.build());

			// The Mars relay dials the Earth relay through this pool.
			let mars_earth_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(EARTH_RELAY_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?)?)
				.build());

			// The Mars relay dials the rover through this pool.
			let mars_rover_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config.to_owned())
				.with_trust_store(make_trust_store(ROVER_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(MARS_RELAY_CERT, MARS_RELAY_KEY.to_provider::<Secp256k1>()?)?)
				.build());

			// The rover dials the Mars relay through this pool.
			let rover_mars_pool = Arc::new(ConnectionPool::<TokioListener>::builder()
				.with_config(pool_config)
				.with_trust_store(make_trust_store(MARS_RELAY_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(ROVER_CERT, ROVER_KEY.to_provider::<Secp256k1>()?)?)
				.build());


			// 1. Start the rover servlet.
			let rover_fault_manager = Arc::new(FaultManager::from_refs(
				&config.bms,
				&config.fault_matrix,
				&config.rover_fault_handler,
			));

			let socket_addr = TightBeamSocketAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
			let rover_config = RoverServletConfig {
				mars_relay_addr: socket_addr,
				mars_relay_pool: rover_mars_pool,
				rover_signing_key: rover_signing_key.to_owned(),
				mission_control_signer: mc_signer.to_owned(),
				mars_relay_signer: mars_relay_signer_val.to_owned(),
				shared_cipher: shared_cipher.to_owned(),
				chain_processor: Arc::clone(&rover_processor),
				_fault_manager: Arc::clone(&rover_fault_manager),
				frame_builder: Arc::clone(&rover_frame_builder),
				max_rounds: COMMAND_ROUND_TRIPS,
			};

			// The rover servlet runs these five workers.
			let command_handler_worker = RoverCommandHandlerWorker::new(RoverCommandHandlerWorkerConfig {
				mission_state: Arc::clone(&shared_mission_state),
			});
			let command_worker = CommandExecutionWorker::new(());
			let telemetry_worker = TelemetryBuilderWorker::new(TelemetryBuilderWorkerConfig {
				default_battery: 85,
				default_temp: -63,
			});
			let rover_frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
				chain_processor: Arc::clone(&rover_processor),
				can_cascade: false, // The rover is an origin of the path.
			});
			let rover_frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
				chain_processor: Arc::clone(&rover_processor),
			});

			let rover_key = ROVER_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(rover_pinning()) as Arc<dyn CertificateValidation>];
			let rover_servlet_conf = tightbeam::colony::servlet::ServletConfig::<TokioListener, RelayMessage>::builder()
				.with_certificate(ROVER_CERT, rover_key, validators)?
				.with_config(Arc::new(rover_config))
				.with_worker(command_handler_worker)
				.with_worker(command_worker)
				.with_worker(telemetry_worker)
				.with_worker(rover_frame_request_handler_worker)
				.with_worker(rover_frame_response_handler_worker)
				.build();
			let rover_servlet = RoverServlet::start(Arc::clone(&trace), rover_servlet_conf).await?;
			let rover_addr = rover_servlet.addr().to_owned();

			config.rover_addr.write()?.replace(rover_addr);


			// 2. Start the Mars relay servlet.
			let mars_relay_key_bytes = match MARS_RELAY_KEY {
				SigningKeySpec::Bytes(bytes) => bytes,
				_ => panic!("MARS_RELAY_KEY must be KeySpec::Bytes"),
			};
			let mars_relay_signing_key = Secp256k1SigningKey::from_slice(mars_relay_key_bytes)?;

			// The Earth relay starts after the Mars relay, so the Mars relay
			// reads its address from a shared slot that step 3 fills.
			let mars_earth_relay_addr = Arc::new(RwLock::new(None));
			let mars_relay_config = MarsRelaySatelliteServletConfig {
				mars_relay_signing_key: mars_relay_signing_key.to_owned(),
				mission_control_signer: mc_signer.to_owned(),
				earth_relay_signer: earth_relay_signer_val.to_owned(),
				rover_signer: rover_signer_val.to_owned(),
				shared_cipher: shared_cipher.to_owned(),
				rover_addr,
				earth_relay_addr: Arc::clone(&mars_earth_relay_addr),
				earth_relay_pool: mars_earth_pool,
				rover_pool: mars_rover_pool,
				chain_processor: Arc::clone(&mars_relay_processor),
				frame_builder: Arc::clone(&mars_relay_frame_builder),
			};

			// The Mars relay servlet runs these two workers.
			let mars_frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
				chain_processor: Arc::clone(&mars_relay_processor),
				can_cascade: true, // The Mars relay cascades both ways.
			});
			let mars_frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
				chain_processor: Arc::clone(&mars_relay_processor),
			});

			let mars_relay_key = MARS_RELAY_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(mars_relay_pinning()) as Arc<dyn CertificateValidation>];
			let mars_relay_servlet_conf = tightbeam::colony::servlet::ServletConfig::<TokioListener, RelayMessage>::builder()
				.with_certificate(MARS_RELAY_CERT, mars_relay_key, validators)?
				.with_config(Arc::new(mars_relay_config))
				.with_worker(mars_frame_request_handler_worker)
				.with_worker(mars_frame_response_handler_worker)
				.build();

			let mars_relay_servlet = MarsRelaySatelliteServlet::start(Arc::clone(&trace), mars_relay_servlet_conf).await?;
			let mars_relay_addr = mars_relay_servlet.addr().to_owned();

			// The config keeps the servlet alive and holds its address.
			config._mars_relay_servlet.write()?.replace(mars_relay_servlet);
			config.mars_relay_addr.write()?.replace(mars_relay_addr);


			// 3. Start the Earth relay servlet.
			let earth_relay_key_bytes = match EARTH_RELAY_KEY {
				SigningKeySpec::Bytes(bytes) => bytes,
				_ => panic!("EARTH_RELAY_KEY must be KeySpec::Bytes"),
			};
			let earth_relay_signing_key = Secp256k1SigningKey::from_slice(earth_relay_key_bytes)?;

			// Mission Control starts after the Earth relay, so the Earth relay
			// reads its address from a shared slot that step 4 fills.
			let earth_mission_control_addr = Arc::new(RwLock::new(None));
			let earth_relay_config = EarthRelaySatelliteServletConfig {
				earth_relay_signing_key: earth_relay_signing_key.to_owned(),
				mission_control_signer: mc_signer.to_owned(),
				mars_relay_signer: mars_relay_signer_val.to_owned(),
				rover_signer: rover_signer_val.to_owned(),
				shared_cipher: shared_cipher.to_owned(),
				mars_relay_addr, // The Mars relay started in step 2.
				mission_control_addr: Arc::clone(&earth_mission_control_addr),
				mission_control_pool: earth_mc_pool,
				mars_relay_pool: earth_mars_pool,
				chain_processor: Arc::clone(&earth_relay_processor),
				frame_builder: Arc::clone(&earth_relay_frame_builder),
			};

			// The Earth relay servlet runs these two workers.
			let earth_frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
				chain_processor: Arc::clone(&earth_relay_processor),
				can_cascade: true, // The Earth relay cascades both ways.
			});
			let earth_frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
				chain_processor: Arc::clone(&earth_relay_processor),
			});

			let earth_relay_servlet_conf = tightbeam::colony::servlet::ServletConfig::<TokioListener, RelayMessage>::builder()
				.with_certificate(EARTH_RELAY_CERT, EARTH_RELAY_KEY.to_provider::<Secp256k1>()?, vec![Arc::new(earth_relay_pinning()) as Arc<dyn CertificateValidation>])?
				.with_config(Arc::new(earth_relay_config))
				.with_worker(earth_frame_request_handler_worker)
				.with_worker(earth_frame_response_handler_worker)
				.build();
			let earth_relay_servlet = EarthRelaySatelliteServlet::start(Arc::clone(&trace), earth_relay_servlet_conf).await?;
			let earth_relay_addr = earth_relay_servlet.addr().to_owned();

			// The Mars relay reads the Earth relay address from this slot.
			*mars_earth_relay_addr.write()? = Some(earth_relay_addr);

			// The config keeps the servlet alive and holds its address.
			config._earth_relay_servlet.write()?.replace(earth_relay_servlet);
			config.earth_relay_addr.write()?.replace(earth_relay_addr);


			// 4. Start the Mission Control servlet.
			let mc_config = MissionControlServletConfig {
				mission_control_signing_key: mission_control_signing_key.to_owned(),
				rover_signer: rover_signer_val.to_owned(),
				earth_relay_signer: earth_relay_signer_val.to_owned(),
				shared_cipher: shared_cipher.to_owned(),
				chain_processor: Arc::clone(&mc_processor),
				frame_builder: Arc::clone(&mc_frame_builder),
				earth_relay_addr, // The Earth relay started in step 3.
				earth_relay_pool: mc_earth_pool,
			};

			// The Mission Control servlet runs these four workers.
			let telemetry_handler_worker = MissionControlTelemetryHandlerWorker::new(MissionControlTelemetryHandlerWorkerConfig {
				mission_state: Arc::clone(&shared_mission_state),
				max_commands: COMMAND_ROUND_TRIPS as u64,
			});
			let frame_request_handler_worker = FrameRequestHandlerWorker::new(FrameRequestHandlerWorkerConfig {
				chain_processor: Arc::clone(&mc_processor),
				can_cascade: false, // Mission Control is an origin of the path.
			});
			let frame_response_handler_worker = FrameResponseHandlerWorker::new(FrameResponseHandlerWorkerConfig {
				chain_processor: Arc::clone(&mc_processor),
			});
			let command_ack_handler_worker = CommandAckHandlerWorker::new(());

			let mission_control_key = MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?;
			let validators = vec![Arc::new(mission_control_pinning()) as Arc<dyn CertificateValidation>];
			let mc_servlet_conf = tightbeam::colony::servlet::ServletConfig::<TokioListener, RelayMessage>::builder()
				.with_certificate(MISSION_CONTROL_CERT, mission_control_key, validators)?
				.with_config(Arc::new(mc_config))
				.with_worker(telemetry_handler_worker)
				.with_worker(frame_request_handler_worker)
				.with_worker(frame_response_handler_worker)
				.with_worker(command_ack_handler_worker)
				.build();

			let mc_servlet = MissionControlServlet::start(Arc::clone(&trace), mc_servlet_conf).await?;
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

				// Mission Control sends the first command to the Earth relay
				// over a client of its own.
				let mut earth_relay_client = ClientBuilder::<TokioListener>::builder()
					.with_trust_store(make_trust_store(EARTH_RELAY_CERT)?)
					.with_client_identity(SigningIdentity::from_spec(MISSION_CONTROL_CERT, MISSION_CONTROL_KEY.to_provider::<Secp256k1>()?)?)
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

			// The mission loop sends through this client to the Mars relay.
			let client = ClientBuilder::<TokioListener>::builder()
				.with_trust_store(make_trust_store(MARS_RELAY_CERT)?)
				.with_client_identity(SigningIdentity::from_spec(ROVER_CERT, ROVER_KEY.to_provider::<Secp256k1>()?)?)
				.with_timeout(Duration::from_millis(5000))
				.build()
				.connect(mars_relay_addr)
				.await?;

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
