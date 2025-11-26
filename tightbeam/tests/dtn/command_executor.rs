//! Command execution for rover operations
//!
//! Encapsulates command execution logic and instrument selection

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

use tightbeam::trace::TraceCollector;
use tightbeam::TightBeamError;

use crate::dtn::messages::{RoverCommand, RoverInstrument};

/// Executes rover commands and manages command state
#[derive(Default)]
pub struct CommandExecutor {
	last_command: RoverCommand,
}

impl CommandExecutor {
	/// Execute a rover command and emit trace events
	pub fn execute_command(&mut self, command: RoverCommand, trace: &TraceCollector) -> Result<(), TightBeamError> {
		match command {
			RoverCommand::CollectSample { .. } => {
				trace.event("rover_execute_collect_sample")?;
				println!("  [Rover] Collecting sample...");
				self.last_command = command;
			}
			RoverCommand::ProbeLocation { .. } => {
				trace.event("rover_execute_probe_location")?;
				println!("  [Rover] Probing location...");
				self.last_command = command;
			}
			RoverCommand::TakePhoto { .. } => {
				trace.event("rover_execute_take_photo")?;
				println!("  [Rover] Capturing image...");
				self.last_command = command;
			}
			RoverCommand::Standby => {
				trace.event("rover_execute_standby")?;
				println!("  [Rover] Entering standby...");
				self.last_command = command;
			}
		}

		Ok(())
	}

	/// Determine next instrument and data based on last command
	pub fn determine_next_instrument(&self) -> (RoverInstrument, &'static str, Vec<u8>) {
		match self.last_command() {
			RoverCommand::CollectSample { .. } => (RoverInstrument::Apxs, "APXS", b"Fe2O3:42.1%".to_vec()),
			RoverCommand::ProbeLocation { .. } => (RoverInstrument::ChemCam, "ChemCam", b"Na:580nm:12.3".to_vec()),
			RoverCommand::TakePhoto { .. } => (RoverInstrument::Mastcam, "Mastcam", b"IMG:1024x768".to_vec()),
			RoverCommand::Standby => (RoverInstrument::Apxs, "APXS", b"STATUS:OK".to_vec()),
		}
	}

	/// Get the last executed command
	pub fn last_command(&self) -> &RoverCommand {
		&self.last_command
	}
}
