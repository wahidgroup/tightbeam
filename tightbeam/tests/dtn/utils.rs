//! Utility functions for DTN testing
//!
//! Provides helper functions like UUID generation for message IDs.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::dtn::clock::mission_time_ms;

static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique message ID using mission time and counter
///
/// Format: `{prefix}-{node}-MET{mission_time_hex}-{counter_hex}`
///
/// Example: `telemetry-rover-MET00000000000003e8-00000001`
pub fn generate_message_id(prefix: &str, node: &str) -> Vec<u8> {
	let counter = UUID_COUNTER.fetch_add(1, Ordering::SeqCst);
	let mission_time = mission_time_ms();

	format!("{}-{}-MET{:016x}-{:08x}", prefix, node, mission_time, counter).into_bytes()
}

