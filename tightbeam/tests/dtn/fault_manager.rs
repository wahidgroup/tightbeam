//! Fault management for rover operations
//!
//! Encapsulates fault detection, handling, and battery management

use std::sync::{Arc, RwLock};

use tightbeam::TightBeamError;

use crate::dtn::{
	bms::BatteryManagementSystem,
	fault_matrix::{FaultMatrix, FaultType},
	faults::RoverFaultHandler,
};

/// Result of battery state update
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryUpdate {
	/// Battery state updated, no fault changes
	Updated,
	/// Low power fault detected
	LowPowerDetected(u8),
	/// Fault cleared (battery recharged)
	FaultCleared(u8),
}

/// Action to take based on fault state
/// NOTE: Available for explicit fault action handling in complex scenarios
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FaultAction {
	/// Continue normal operations
	Continue,
	/// Halt communications and recharge
	HaltComms,
}

/// Manages rover fault detection and handling
pub struct FaultManager {
	bms: Arc<RwLock<BatteryManagementSystem>>,
	fault_matrix: Arc<RwLock<FaultMatrix>>,
	fault_handler: Arc<RwLock<RoverFaultHandler>>,
}

impl FaultManager {
	/// Create a new FaultManager from references
	pub fn from_refs(
		bms: &RwLock<BatteryManagementSystem>,
		fault_matrix: &RwLock<FaultMatrix>,
		fault_handler: &RwLock<RoverFaultHandler>,
	) -> Self {
		Self {
			bms: Arc::new(RwLock::new(bms.read().ok().map(|g| g.clone()).unwrap_or_default())),
			fault_matrix: Arc::new(RwLock::new(fault_matrix.read().ok().map(|g| g.clone()).unwrap_or_default())),
			fault_handler: Arc::new(RwLock::new(fault_handler.read().ok().map(|g| g.clone()).unwrap_or_default())),
		}
	}

	/// Update battery state and check for fault transitions
	pub fn update_battery_state(&self) -> Result<BatteryUpdate, TightBeamError> {
		let battery = {
			let bms_guard = self.bms.read()?;
			bms_guard.to_energy_percent()
		};

		let mut fault_matrix_guard = self.fault_matrix.write()?;
		let was_fault = fault_matrix_guard.is_fault_active(FaultType::LowPower);

		// Store battery percentage in matrix
		fault_matrix_guard.set_battery_percent(battery);

		let (is_low_power, is_fully_charged) = {
			let bms_guard = self.bms.read()?;
			(bms_guard.is_low_power(), bms_guard.is_full())
		};

		if is_low_power && !was_fault {
			// Battery critically low - trigger fault and start recharging
			fault_matrix_guard.set_fault(FaultType::LowPower);
			drop(fault_matrix_guard);
			self.fault_handler.write()?.start_low_power_fault();
			Ok(BatteryUpdate::LowPowerDetected(battery))
		} else if is_fully_charged && was_fault {
			// Battery fully recharged - clear fault
			fault_matrix_guard.clear_fault(FaultType::LowPower);
			drop(fault_matrix_guard);
			self.fault_handler.write()?.clear_low_power_fault();
			Ok(BatteryUpdate::FaultCleared(battery))
		} else {
			drop(fault_matrix_guard);
			Ok(BatteryUpdate::Updated)
		}
	}

	/// Check for faults and return action to take
	/// NOTE: Available for scenarios requiring explicit fault action decisions
	#[allow(dead_code)]
	pub fn check_and_handle_faults(&self) -> Result<FaultAction, TightBeamError> {
		let fault_matrix = *self.fault_matrix.read()?;
		let fault_handler = *self.fault_handler.read()?;

		if fault_handler.should_halt_comms(&fault_matrix) {
			Ok(FaultAction::HaltComms)
		} else {
			Ok(FaultAction::Continue)
		}
	}

	/// Get current battery percentage
	pub fn battery_percent(&self) -> Result<u8, TightBeamError> {
		let bms_guard = self.bms.read()?;
		Ok(bms_guard.to_energy_percent())
	}

	/// Drain battery for operational round
	pub fn drain_battery(&self) -> Result<u8, TightBeamError> {
		let mut bms_guard = self.bms.write()?;
		Ok(bms_guard.drain())
	}

	/// Re-energize battery during fault
	pub fn reenergize_battery(&self) -> Result<u8, TightBeamError> {
		let mut bms_guard = self.bms.write()?;
		Ok(bms_guard.reenergize())
	}

	/// Get current fault matrix snapshot
	pub fn fault_matrix(&self) -> Result<FaultMatrix, TightBeamError> {
		Ok(*self.fault_matrix.read()?)
	}
}
