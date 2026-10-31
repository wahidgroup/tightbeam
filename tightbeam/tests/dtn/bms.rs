//! The battery management system (BMS) of the Mars rover.
//!
//! The battery is a simulation of this suite, so the tests of this file are
//! self-checks of the harness, and no tightbeam code runs in them.

/// The battery of the Mars rover, which each operational round drains and
/// each skipped round re-energizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryManagementSystem {
	/// The charge level, from 0 to 100 percent.
	energy_percent: u8,
	/// The percentage points that one operational round drains.
	drain_rate: u8,
	/// The percentage points that one skipped round re-energizes.
	reenergize_rate: u8,
	/// The charge level below which the battery reads low power.
	fault_threshold: u8,
	/// The charge level from which the battery reads full, which clears a
	/// low-power fault.
	full_threshold: u8,
}

impl BatteryManagementSystem {
	/// A battery of these parameters, with its charge level capped at 100
	/// percent.
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

	/// The charge level, in percent.
	pub fn to_energy_percent(self) -> u8 {
		self.energy_percent
	}

	/// Drains the battery by one operational round, and returns the new
	/// charge level.
	pub fn drain(&mut self) -> u8 {
		self.energy_percent = self.energy_percent.saturating_sub(self.drain_rate);
		self.energy_percent
	}

	/// Re-energizes the battery by one cycle, up to 100 percent, and returns
	/// the new charge level.
	pub fn reenergize(&mut self) -> u8 {
		self.energy_percent = self.energy_percent.saturating_add(self.reenergize_rate).min(100);
		self.energy_percent
	}

	/// Whether the charge level is below the low-power threshold.
	pub fn is_low_power(&self) -> bool {
		self.energy_percent < self.fault_threshold
	}

	/// Whether the charge level is at the full threshold or above it.
	pub fn is_full(&self) -> bool {
		self.energy_percent >= self.full_threshold
	}

	/// Refills the battery to 100 percent.
	pub fn reset(&mut self) {
		self.energy_percent = 100;
	}

	/// Sets the charge level to `energy_level`, capped at 100 percent.
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

mod tests {
	use tightbeam::tb_cases;

	use super::*;

	// A drain or a recharge moves the charge of the default battery by its rate
	// of 25 points, within 0 and 100.
	tb_cases! {
		fn a_step_moves_the_charge_by_its_rate((step, start, after): (fn(&mut BatteryManagementSystem) -> u8, u8, u8)) {
			let mut bms = BatteryManagementSystem::default();
			bms.set_energy_level(start);

			let charge = step(&mut bms);
			assert_eq!(charge, after);
		}
		cases {
			drain_from_full => (BatteryManagementSystem::drain, 100, 75),
			drain_from_the_threshold => (BatteryManagementSystem::drain, 25, 0),
			drain_at_empty => (BatteryManagementSystem::drain, 0, 0),
			recharge_from_empty => (BatteryManagementSystem::reenergize, 0, 25),
			recharge_to_full => (BatteryManagementSystem::reenergize, 75, 100),
			recharge_at_full => (BatteryManagementSystem::reenergize, 100, 100),
		}
	}

	// The default battery reads low power below its threshold of 25 points, and
	// full at 100 points.
	tb_cases! {
		fn a_charge_reads_low_and_full_by_the_thresholds((level, low, full): (u8, bool, bool)) {
			let mut bms = BatteryManagementSystem::default();
			bms.set_energy_level(level);

			let reads = (bms.is_low_power(), bms.is_full());
			assert_eq!(reads, (low, full));
		}
		cases {
			full => (100, false, true),
			at_the_threshold => (25, false, false),
			below_the_threshold => (24, true, false),
			empty => (0, true, false),
		}
	}

	/// A battery of a custom configuration reads its charge by its own
	/// thresholds, where the default thresholds read it low and not full.
	#[test]
	fn a_custom_config_reads_its_own_thresholds() {
		let bms = BatteryManagementSystem::with_config(20, 10, 15, 10, 20);

		let reads = (bms.to_energy_percent(), bms.is_low_power(), bms.is_full());
		assert_eq!(reads, (20, false, true));
	}

	/// A reset refills the battery to a full charge.
	#[test]
	fn a_reset_refills_the_battery() {
		let mut bms = BatteryManagementSystem::default();
		bms.set_energy_level(25);

		bms.reset();
		assert_eq!(bms.to_energy_percent(), 100);
	}
}
