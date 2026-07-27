//! DTN ultimate-scenario event URN inventory.

use tightbeam::utils::urn::Urn;

pub(crate) const COMMS_HALTED: Urn<'static> = Urn::new("test", "event:ultimate/comms-halted");
pub(crate) const EARTH_RELAY_CASCADE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-cascade-frame-request");
pub(crate) const EARTH_RELAY_FORWARD_ACK_TO_MC: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-forward-ack-to-mc");
pub(crate) const EARTH_RELAY_FORWARD_TELEMETRY_TO_MC: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-forward-telemetry-to-mc");
pub(crate) const EARTH_RELAY_FORWARD_TO_MARS: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-forward-to-mars");
pub(crate) const EARTH_RELAY_GAP_DETECTED: Urn<'static> = Urn::new("test", "event:ultimate/earth-relay-gap-detected");
pub(crate) const EARTH_RELAY_RECEIVE_ACK_FROM_MARS: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-receive-ack-from-mars");
pub(crate) const EARTH_RELAY_RECEIVE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-receive-frame-request");
pub(crate) const EARTH_RELAY_RECEIVE_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-receive-frame-response");
pub(crate) const EARTH_RELAY_RECEIVE_FROM_MC: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-receive-from-mc");
pub(crate) const EARTH_RELAY_RECEIVE_TELEMETRY_FROM_MARS: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-receive-telemetry-from-mars");
pub(crate) const EARTH_RELAY_SEND_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-send-frame-request");
pub(crate) const EARTH_RELAY_SEND_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/earth-relay-send-frame-response");
pub(crate) const FAULT_CLEARED: Urn<'static> = Urn::new("test", "event:ultimate/fault-cleared");
pub(crate) const FAULT_LOW_POWER_DETECTED: Urn<'static> = Urn::new("test", "event:ultimate/fault-low-power-detected");
pub(crate) const MARS_RELAY_CASCADE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-cascade-frame-request");
pub(crate) const MISSION_CONTROL_CASCADE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-cascade-frame-request");
pub(crate) const ROVER_CASCADE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/rover-cascade-frame-request");
pub(crate) const MARS_RELAY_FORWARD_ACK_TO_EARTH: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-forward-ack-to-earth");
pub(crate) const MARS_RELAY_FORWARD_TELEMETRY_TO_EARTH: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-forward-telemetry-to-earth");
pub(crate) const MARS_RELAY_FORWARD_TO_ROVER: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-forward-to-rover");
pub(crate) const MARS_RELAY_GAP_DETECTED: Urn<'static> = Urn::new("test", "event:ultimate/mars-relay-gap-detected");
pub(crate) const MARS_RELAY_RECEIVE_ACK_FROM_ROVER: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-receive-ack-from-rover");
pub(crate) const MARS_RELAY_RECEIVE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-receive-frame-request");
pub(crate) const MARS_RELAY_RECEIVE_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-receive-frame-response");
pub(crate) const MARS_RELAY_RECEIVE_FROM_EARTH: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-receive-from-earth");
pub(crate) const MARS_RELAY_RECEIVE_TELEMETRY_FROM_ROVER: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-receive-telemetry-from-rover");
pub(crate) const MARS_RELAY_SEND_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-send-frame-request");
pub(crate) const MARS_RELAY_SEND_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/mars-relay-send-frame-response");
pub(crate) const MISSION_COMPLETE: Urn<'static> = Urn::new("test", "event:ultimate/mission-complete");
pub(crate) const MISSION_CONTROL_ANALYZE_TELEMETRY: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-analyze-telemetry");
pub(crate) const MISSION_CONTROL_GAP_DETECTED: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-gap-detected");
pub(crate) const MISSION_CONTROL_RECEIVE_ACK: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-receive-ack");
pub(crate) const MISSION_CONTROL_RECEIVE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-receive-frame-request");
pub(crate) const MISSION_CONTROL_RECEIVE_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-receive-frame-response");
pub(crate) const MISSION_CONTROL_RECEIVE_TELEMETRY: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-receive-telemetry");
pub(crate) const MISSION_CONTROL_SEND_COMMAND: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-send-command");
pub(crate) const MISSION_CONTROL_SEND_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-send-frame-request");
pub(crate) const MISSION_CONTROL_SEND_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/mission-control-send-frame-response");
pub(crate) const MISSION_START: Urn<'static> = Urn::new("test", "event:ultimate/mission-start");
pub(crate) const ROVER_COMMAND_COMPLETE: Urn<'static> = Urn::new("test", "event:ultimate/rover-command-complete");
pub(crate) const ROVER_EXECUTE_COLLECT_SAMPLE: Urn<'static> =
	Urn::new("test", "event:ultimate/rover-execute-collect-sample");
pub(crate) const ROVER_EXECUTE_COMMAND: Urn<'static> = Urn::new("test", "event:ultimate/rover-execute-command");
pub(crate) const ROVER_EXECUTE_PROBE_LOCATION: Urn<'static> =
	Urn::new("test", "event:ultimate/rover-execute-probe-location");
pub(crate) const ROVER_EXECUTE_STANDBY: Urn<'static> = Urn::new("test", "event:ultimate/rover-execute-standby");
pub(crate) const ROVER_EXECUTE_TAKE_PHOTO: Urn<'static> = Urn::new("test", "event:ultimate/rover-execute-take-photo");
pub(crate) const ROVER_GAP_DETECTED: Urn<'static> = Urn::new("test", "event:ultimate/rover-gap-detected");
pub(crate) const ROVER_RECEIVE_COMMAND: Urn<'static> = Urn::new("test", "event:ultimate/rover-receive-command");
pub(crate) const ROVER_RECEIVE_FRAME_REQUEST: Urn<'static> =
	Urn::new("test", "event:ultimate/rover-receive-frame-request");
pub(crate) const ROVER_RECEIVE_FRAME_RESPONSE: Urn<'static> =
	Urn::new("test", "event:ultimate/rover-receive-frame-response");
pub(crate) const ROVER_SEND_ACK: Urn<'static> = Urn::new("test", "event:ultimate/rover-send-ack");
pub(crate) const ROVER_SEND_FRAME_REQUEST: Urn<'static> = Urn::new("test", "event:ultimate/rover-send-frame-request");
pub(crate) const ROVER_SEND_FRAME_RESPONSE: Urn<'static> = Urn::new("test", "event:ultimate/rover-send-frame-response");
pub(crate) const ROVER_SEND_TELEMETRY: Urn<'static> = Urn::new("test", "event:ultimate/rover-send-telemetry");
