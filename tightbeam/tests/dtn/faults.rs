//! Fault handling logic for rover operations
//!
//! This module focuses on fault **handling** (recovery time, decision logic),
//! not fault **encoding** (which is handled by FaultMatrix).
//!
//! When low power is detected, communications halt and the rover "recharges"
//! by advancing the simulated mission clock.

use crate::dtn::clock::{delays, mission_time_ms};
use crate::dtn::fault_matrix::{FaultMatrix, FaultType};

/// Handles rover fault recovery logic.
///
/// This struct focuses on fault **handling** (recovery time, decision logic),
/// not fault **encoding** (which is handled by FaultMatrix).
#[derive(Debug, Clone, Copy)]
pub struct RoverFaultHandler {
	/// Time when low power fault was first detected (for recharge tracking).
	low_power_start_time_ms: Option<u64>,
}

impl RoverFaultHandler {
	pub fn new() -> Self {
		Self { low_power_start_time_ms: None }
	}

	/// Check if the rover should halt communications due to faults.
	pub fn should_halt_comms(&self, fault_matrix: &FaultMatrix) -> bool {
		fault_matrix.is_fault_active(FaultType::LowPower)
	}

	/// Begin tracking a low power fault.
	pub fn start_low_power_fault(&mut self) {
		if self.low_power_start_time_ms.is_none() {
			self.low_power_start_time_ms = Some(mission_time_ms());
		}
	}

	/// Calculate time remaining until recharge complete.
	pub fn time_until_recharged_ms(&self) -> Option<u64> {
		self.low_power_start_time_ms.map(|start_time| {
			let elapsed = mission_time_ms().saturating_sub(start_time);
			delays::ROVER_RECHARGE_MS.saturating_sub(elapsed)
		})
	}

	/// Check if recharge is complete.
	pub fn is_recharged(&self) -> bool {
		self.time_until_recharged_ms().map_or(true, |t| t == 0)
	}

	/// Clear low power fault tracking.
	pub fn clear_low_power_fault(&mut self) {
		self.low_power_start_time_ms = None;
	}
}

impl Default for RoverFaultHandler {
	fn default() -> Self {
		Self::new()
	}
}

