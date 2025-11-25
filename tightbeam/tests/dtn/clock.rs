//! Simulated mission clock for realistic DTN timing without actual delays
//!
//! This module provides a simulated Mission Elapsed Time (MET) clock that allows
//! tests to simulate realistic Mars-Earth communication delays (8-20 minutes)
//! without actually sleeping. The clock is advanced programmatically.

use std::sync::{OnceLock, RwLock};

/// Simulated mission elapsed time (MET) in milliseconds
static MISSION_CLOCK: OnceLock<RwLock<u64>> = OnceLock::new();

/// Initialize the mission clock at T+0
pub fn init_mission_clock() {
	MISSION_CLOCK.get_or_init(|| RwLock::new(0));
}

/// Get current mission elapsed time (milliseconds)
pub fn mission_time_ms() -> u64 {
	MISSION_CLOCK
		.get()
		.expect("Mission clock not initialized")
		.read()
		.unwrap()
		.clone()
}

/// Advance mission clock by specified duration
pub fn advance_clock(duration_ms: u64) {
	let mut time = MISSION_CLOCK
		.get()
		.expect("Mission clock not initialized")
		.write()
		.unwrap();
	*time += duration_ms;
}

/// Advance clock to specific absolute time
pub fn advance_to(target_ms: u64) {
	let mut time = MISSION_CLOCK
		.get()
		.expect("Mission clock not initialized")
		.write()
		.unwrap();
	if target_ms > *time {
		*time = target_ms;
	}
}

/// Realistic Mars-Earth light-time delays
pub mod delays {
	// Mars-Earth distance varies from 54.6M km (closest) to 401M km (farthest)
	// Light speed = 299,792 km/s

	/// Minimum light-time delay (closest approach): ~3 minutes
	/// NOTE: Available for scenarios testing minimum Mars-Earth distance
	#[allow(dead_code)]
	pub const MIN_LIGHT_TIME_MS: u64 = 3 * 60 * 1000;

	/// Average light-time delay (mean distance): ~12.5 minutes
	pub const AVG_LIGHT_TIME_MS: u64 = 12 * 60 * 1000 + 30 * 1000;

	/// Maximum light-time delay (farthest): ~22 minutes
	/// NOTE: Available for scenarios testing maximum Mars-Earth distance
	#[allow(dead_code)]
	pub const MAX_LIGHT_TIME_MS: u64 = 22 * 60 * 1000;

	/// Rover → Relay delay (Mars orbit): ~1-2 seconds
	pub const ROVER_TO_RELAY_MS: u64 = 1500;

	/// Relay → Earth delay (use average for test)
	pub const RELAY_TO_EARTH_MS: u64 = AVG_LIGHT_TIME_MS;

	/// Earth → Relay delay
	pub const EARTH_TO_RELAY_MS: u64 = AVG_LIGHT_TIME_MS;

	/// Relay → Rover delay
	pub const RELAY_TO_ROVER_MS: u64 = 1500;

	/// Total round-trip time (Rover → Earth → Rover)
	/// NOTE: Useful for calculating expected completion times in tests
	#[allow(dead_code)]
	pub const ROUND_TRIP_MS: u64 =
		ROVER_TO_RELAY_MS + RELAY_TO_EARTH_MS + EARTH_TO_RELAY_MS + RELAY_TO_ROVER_MS;

	/// Rover recharge time (simulated battery recharge): 30 minutes
	pub const ROVER_RECHARGE_MS: u64 = 30 * 60 * 1000;
}

/// Track message transmission with delay
///
/// NOTE: This struct provides a wrapper for messages with simulated propagation delays.
/// Currently unused as the test uses direct `advance_clock()` calls for timing simulation.
/// Reserved for future use in more complex DTN scenarios with message queuing.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct DelayedMessage<T> {
	pub payload: T,
	pub sent_at_ms: u64,
	pub arrival_at_ms: u64,
}

#[allow(dead_code)]
impl<T> DelayedMessage<T> {
	pub fn new(payload: T, delay_ms: u64) -> Self {
		let sent_at = mission_time_ms();
		Self { payload, sent_at_ms: sent_at, arrival_at_ms: sent_at + delay_ms }
	}

	pub fn is_arrived(&self) -> bool {
		mission_time_ms() >= self.arrival_at_ms
	}

	pub fn wait_for_arrival(&self) {
		advance_to(self.arrival_at_ms);
	}
}

