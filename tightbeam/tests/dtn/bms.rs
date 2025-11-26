//! Battery Management System (BMS)

/// Battery Management System for Mars Rover
///
/// Manages battery state including:
/// - Current charge level (0-100%)
/// - Drain rate during operations
/// - Re-energize rate during faults
/// - Fault detection for low power
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryManagementSystem {
	/// Current battery energy percentage (0-100)
	energy_percent: u8,
	/// Drain rate per operational round (percentage points)
	drain_rate: u8,
	/// Re-energize rate per skipped round (percentage points)
	reenergize_rate: u8,
	/// Low power fault threshold (percentage)
	fault_threshold: u8,
	/// Full threshold for clearing faults (percentage)
	full_threshold: u8,
}

impl BatteryManagementSystem {
	/// Create a BMS with custom parameters
	pub fn with_config(
		energy_percent: u8,
		drain_rate: u8,
		reenergize_rate: u8,
		fault_threshold: u8,
		full_threshold: u8,
	) -> Self {
		Self {
			energy_percent: energy_percent.min(100),
			drain_rate,
			reenergize_rate,
			fault_threshold,
			full_threshold,
		}
	}

	/// Get current battery percentage
	pub fn to_energy_percent(self) -> u8 {
		self.energy_percent
	}

	/// Drain battery by one operational round
	///
	/// Returns the new charge level after draining
	pub fn drain(&mut self) -> u8 {
		self.energy_percent = self.energy_percent.saturating_sub(self.drain_rate);
		self.energy_percent
	}

	/// Re-energize battery by one cycle
	///
	/// Returns the new charge level after re-energizing
	pub fn reenergize(&mut self) -> u8 {
		self.energy_percent = self.energy_percent.saturating_add(self.reenergize_rate).min(100);
		self.energy_percent
	}

	/// Check if battery is in low power fault state
	pub fn is_low_power(&self) -> bool {
		self.energy_percent < self.fault_threshold
	}

	/// Check if battery is fully energized
	pub fn is_full(&self) -> bool {
		self.energy_percent >= self.full_threshold
	}

	/// Reset battery to full charge
	pub fn reset(&mut self) {
		self.energy_percent = 100;
	}

	/// Set energy level to a specific percentage
	pub fn set_energy_level(&mut self, energy_level: u8) {
		self.energy_percent = energy_level.min(100);
	}
}

impl Default for BatteryManagementSystem {
	fn default() -> Self {
		Self {
			energy_percent: 100,
			drain_rate: 25,
			reenergize_rate: 25,
			fault_threshold: 25,
			full_threshold: 100,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_bms_default() {
		let bms = BatteryManagementSystem::default();
		assert_eq!(bms.to_energy_percent(), 100);
		assert!(!bms.is_low_power());
		assert!(bms.is_full());
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
		assert!(!bms.is_full());
	}

	#[test]
	fn test_bms_recharge() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_energy_level(0);

		assert_eq!(bms.reenergize(), 25); // 0 + 25
		assert_eq!(bms.reenergize(), 50); // 25 + 25
		assert_eq!(bms.reenergize(), 75); // 50 + 25
		assert_eq!(bms.reenergize(), 100); // 75 + 25
		assert_eq!(bms.reenergize(), 100); // Can't go above 100

		assert!(!bms.is_low_power());
		assert!(bms.is_full());
	}

	#[test]
	fn test_bms_fault_threshold() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_energy_level(25);
		assert!(!bms.is_low_power()); // Exactly at threshold is OK

		bms.set_energy_level(24);
		assert!(bms.is_low_power()); // Below threshold triggers fault
	}

	#[test]
	fn test_bms_custom_config() {
		let bms = BatteryManagementSystem::with_config(50, 10, 15, 20, 90);
		assert_eq!(bms.to_energy_percent(), 50);
		assert!(!bms.is_low_power()); // 50 >= 20
		assert!(!bms.is_full()); // 50 < 90
	}

	#[test]
	fn test_bms_reset() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_energy_level(25);
		assert_eq!(bms.to_energy_percent(), 25);

		bms.reset();
		assert_eq!(bms.to_energy_percent(), 100);
	}
}
