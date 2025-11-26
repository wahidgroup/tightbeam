//! Utility functions for DTN testing
//!
//! Provides helper functions like UUID generation for message IDs,
//! time formatting, and debug logging.

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

/// Format mission time for display (converts milliseconds to human-readable)
pub fn format_mission_time(ms: u64) -> String {
	let seconds = ms / 1000;
	let minutes = seconds / 60;
	let hours = minutes / 60;
	let days = hours / 24;

	if days > 0 {
		format!("T+{}d {:02}h {:02}m {:02}s", days, hours % 24, minutes % 60, seconds % 60)
	} else if hours > 0 {
		format!("T+{}h {:02}m {:02}s", hours, minutes % 60, seconds % 60)
	} else if minutes > 0 {
		format!("T+{}m {:02}s", minutes, seconds % 60)
	} else {
		format!("T+{}s", seconds)
	}
}

/// Debug log macro that only prints if TIGHTBEAM_DEBUG env var is set
///
/// Usage:
/// ```rust
/// debug_log!("Processing frame {}", frame_id);
/// debug_log!("Status: {:?}", status);
/// ```
#[macro_export]
macro_rules! debug_log {
	($($arg:tt)*) => {
		if std::env::var("TIGHTBEAM_DEBUG").is_ok() {
			println!($($arg)*);
		}
	};
}
