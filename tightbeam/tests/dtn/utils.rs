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
