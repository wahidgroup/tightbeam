//! The workers of the DTN test components.
//!
//! Each variant of [`RelayMessage`](crate::dtn::messages::RelayMessage) has a
//! worker. The workers hold the mission logic, and the servlets hold the frame
//! operations.

pub mod command_ack_handler;
pub mod command_execution;
pub mod frame_request_handler;
pub mod frame_response_handler;
pub mod messages;
pub mod mission_control_telemetry_handler;
pub mod rover_command_handler;
pub mod telemetry_builder;

pub use command_ack_handler::CommandAckHandlerWorker;
pub use command_execution::CommandExecutionWorker;
pub use frame_request_handler::{FrameRequestHandlerWorker, FrameRequestHandlerWorkerConfig};
pub use frame_response_handler::FrameResponseHandlerWorker;
pub use mission_control_telemetry_handler::{
	MissionControlTelemetryHandlerWorker, MissionControlTelemetryHandlerWorkerConfig,
};
pub use rover_command_handler::{RoverCommandHandlerWorker, RoverCommandHandlerWorkerConfig};
pub use telemetry_builder::{TelemetryBuilderWorker, TelemetryBuilderWorkerConfig};
