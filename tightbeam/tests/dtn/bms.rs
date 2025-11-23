//! Battery Management System (BMS)
//!
//! Handles battery state, charge/discharge logic, and fault detection for the DTN rover.

/// Battery Management System for Mars Rover
///
/// Manages battery state including:
/// - Current charge level (0-100%)
/// - Drain rate during operations
/// - Recharge rate during faults
/// - Fault detection for low power
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryManagementSystem {
	/// Current battery charge percentage (0-100)
	charge_percent: u8,
	/// Drain rate per operational round (percentage points)
	drain_rate: u8,
	/// Recharge rate per skipped round (percentage points)
	recharge_rate: u8,
	/// Low power fault threshold (percentage)
	fault_threshold: u8,
	/// Full charge threshold for clearing faults (percentage)
	full_charge_threshold: u8,
}

impl BatteryManagementSystem {
	/// Create a BMS with custom parameters
	pub fn with_config(
		initial_charge: u8,
		drain_rate: u8,
		recharge_rate: u8,
		fault_threshold: u8,
		full_charge_threshold: u8,
	) -> Self {
		Self {
			charge_percent: initial_charge.min(100),
			drain_rate,
			recharge_rate,
			fault_threshold,
			full_charge_threshold,
		}
	}

	/// Get current battery charge percentage
	pub fn charge_percent(&self) -> u8 {
		self.charge_percent
	}

	/// Drain battery by one operational round
	///
	/// Returns the new charge level after draining
	pub fn drain(&mut self) -> u8 {
		self.charge_percent = self.charge_percent.saturating_sub(self.drain_rate);
		self.charge_percent
	}

	/// Recharge battery by one cycle
	///
	/// Returns the new charge level after recharging
	pub fn recharge(&mut self) -> u8 {
		self.charge_percent = self.charge_percent.saturating_add(self.recharge_rate).min(100);
		self.charge_percent
	}

	/// Check if battery is in low power fault state
	pub fn is_low_power(&self) -> bool {
		self.charge_percent < self.fault_threshold
	}

	/// Check if battery is fully recharged (fault clear condition)
	pub fn is_fully_charged(&self) -> bool {
		self.charge_percent >= self.full_charge_threshold
	}

	/// Reset battery to full charge
	pub fn reset(&mut self) {
		self.charge_percent = 100;
	}

	/// Set charge to a specific percentage (for testing/initialization)
	pub fn set_charge(&mut self, charge: u8) {
		self.charge_percent = charge.min(100);
	}
}

impl Default for BatteryManagementSystem {
	fn default() -> Self {
		Self {
			charge_percent: 100,
			drain_rate: 25,
			recharge_rate: 25,
			fault_threshold: 25,
			full_charge_threshold: 100,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_bms_default() {
		let bms = BatteryManagementSystem::default();
		assert_eq!(bms.charge_percent(), 100);
		assert!(!bms.is_low_power());
		assert!(bms.is_fully_charged());
	}

	#[test]
	fn test_bms_drain() {
		let mut bms = BatteryManagementSystem::default();

		assert_eq!(bms.drain(), 75); // 100 - 25
		assert_eq!(bms.drain(), 50); // 75 - 25
		assert_eq!(bms.drain(), 25); // 50 - 25
		assert_eq!(bms.drain(), 0); // 25 - 25
		assert_eq!(bms.drain(), 0); // Can't go below 0

		assert!(bms.is_low_power());
		assert!(!bms.is_fully_charged());
	}

	#[test]
	fn test_bms_recharge() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_charge(0);

		assert_eq!(bms.recharge(), 25); // 0 + 25
		assert_eq!(bms.recharge(), 50); // 25 + 25
		assert_eq!(bms.recharge(), 75); // 50 + 25
		assert_eq!(bms.recharge(), 100); // 75 + 25
		assert_eq!(bms.recharge(), 100); // Can't go above 100

		assert!(!bms.is_low_power());
		assert!(bms.is_fully_charged());
	}

	#[test]
	fn test_bms_fault_threshold() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_charge(25);
		assert!(!bms.is_low_power()); // Exactly at threshold is OK

		bms.set_charge(24);
		assert!(bms.is_low_power()); // Below threshold triggers fault
	}

	#[test]
	fn test_bms_custom_config() {
		let bms = BatteryManagementSystem::with_config(50, 10, 15, 20, 90);
		assert_eq!(bms.charge_percent(), 50);
		assert!(!bms.is_low_power()); // 50 >= 20
		assert!(!bms.is_fully_charged()); // 50 < 90
	}

	#[test]
	fn test_bms_reset() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_charge(25);
		assert_eq!(bms.charge_percent(), 25);

		bms.reset();
		assert_eq!(bms.charge_percent(), 100);
	}
}
