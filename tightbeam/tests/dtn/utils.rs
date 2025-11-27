//! Utility functions for DTN testing
//!
//! Provides helper functions like UUID generation for message IDs,
//! time formatting, and debug logging.

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
