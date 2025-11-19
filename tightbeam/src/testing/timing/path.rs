//! Path-based WCET analysis
//!
//! Provides compositional WCET analysis by verifying that the sum of execution
//! times along specific execution paths does not exceed specified limits.

use std::time::Duration;

use crate::instrumentation::TbEvent;
use crate::testing::specs::csp::{Event, Process};
use crate::trace::ConsumedTrace;

/// Execution path with timing information
///
/// Represents a sequence of events observed in a trace, along with their
/// individual durations and total path duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPath {
	/// Sequence of events in path (in order)
	pub events: Vec<Event>,
	/// Observed duration for each event (None if not measured)
	pub durations: Vec<Option<u64>>,
	/// Total path duration (sum of event durations, in nanoseconds)
	pub total_duration: u64,
}

/// Path-based WCET constraint
///
/// Defines a maximum allowed total duration for a specific sequence of events.
/// The path WCET is verified by summing the durations of events along the path
/// and comparing to the maximum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWcet {
	/// Sequence of events defining the path (must match in order)
	pub path: Vec<Event>,
	/// Maximum allowed total duration for path
	pub max_duration: Duration,
}

impl ExecutionPath {
	/// Create a new execution path from events and durations
	pub fn new(events: Vec<Event>, durations: Vec<Option<u64>>) -> Self {
		let total_duration = durations.iter().filter_map(|&d| d).sum();
		Self { events, durations, total_duration }
	}

	/// Check if this path matches a given path pattern
	///
	/// Returns true if the events in this path match the pattern in order.
	/// Pattern can be shorter (prefix match) or exact match.
	pub fn matches_pattern(&self, pattern: &[Event]) -> bool {
		if pattern.is_empty() {
			return false;
		}
		if pattern.len() > self.events.len() {
			return false;
		}
		// Check if the first N events match the pattern (compare string content, not pointers)
		self.events
			.iter()
			.take(pattern.len())
			.zip(pattern.iter())
			.all(|(a, b)| a.0 == b.0)
	}

	/// Get duration for a specific event in the path
	pub fn duration_for_event(&self, event: &Event) -> Option<u64> {
		self.events
			.iter()
			.position(|e| e == event)
			.and_then(|idx| self.durations.get(idx).copied().flatten())
	}
}

impl PathWcet {
	/// Create a new path-based WCET constraint
	pub fn new(path: Vec<Event>, max_duration: Duration) -> Self {
		Self { path, max_duration }
	}

	/// Get maximum duration in nanoseconds
	pub fn max_duration_ns(&self) -> u64 {
		self.max_duration.as_nanos() as u64
	}
}

/// Extract execution paths from a consumed trace
///
/// Uses CSP process to identify valid execution paths by matching trace events
/// to process transitions. Groups consecutive events into paths.
pub fn extract_paths(trace: &ConsumedTrace, process: &Process) -> Vec<ExecutionPath> {
	let mut paths = Vec::new();
	let mut current_path_events = Vec::new();
	let mut current_path_durations = Vec::new();
	let mut current_state = process.initial;

	// Extract timing events from trace
	let timing_events: Vec<&TbEvent> = {
		#[cfg(feature = "instrument")]
		{
			use crate::instrumentation::event_kinds;
			trace
				.instrument_events
				.iter()
				.filter(|ev| ev.urn == event_kinds::TIMING_WCET || ev.urn == event_kinds::TIMING_DEADLINE)
				.collect()
		}
		#[cfg(not(feature = "instrument"))]
		{
			Vec::new()
		}
	};

	// Build paths by following CSP transitions
	for event in timing_events {
		// Extract event label
		let event_label = match &event.label {
			Some(label) => label,
			None => continue,
		};

		// Convert String to &'static str (leak for path extraction)
		let static_label = Box::leak(event_label.clone().into_boxed_str());
		let csp_event = Event(static_label);

		// Check if event is enabled in current state
		let enabled = process.enabled(current_state);
		let is_enabled = enabled.iter().any(|a| a.event == csp_event);

		if !is_enabled {
			// Event not enabled - start new path
			if !current_path_events.is_empty() {
				paths.push(ExecutionPath::new(current_path_events.clone(), current_path_durations.clone()));
				current_path_events.clear();
				current_path_durations.clear();
			}
			current_state = process.initial; // Reset to initial state
			continue;
		}

		// Perform transition
		let next_states = process.step(current_state, &csp_event);
		if next_states.is_empty() {
			// Deadlock - finalize current path
			if !current_path_events.is_empty() {
				paths.push(ExecutionPath::new(current_path_events.clone(), current_path_durations.clone()));
				current_path_events.clear();
				current_path_durations.clear();
			}
			current_state = process.initial;
			continue;
		}

		// Add event to current path
		current_path_events.push(csp_event);
		current_path_durations.push(event.duration_ns);

		// Update state (take first if multiple)
		current_state = next_states[0];

		// Note: We don't finalize path on terminal state because the process
		// may allow transitions from terminal states (e.g., self-loops)
	}

	// Finalize any remaining path
	if !current_path_events.is_empty() {
		paths.push(ExecutionPath::new(current_path_events, current_path_durations));
	}

	paths
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::{Process, State};

	#[test]
	fn test_execution_path_new() {
		let events = vec![Event("start"), Event("process"), Event("end")];
		let durations = vec![Some(10_000_000), Some(20_000_000), Some(5_000_000)];
		let path = ExecutionPath::new(events.clone(), durations.clone());

		assert_eq!(path.events, events);
		assert_eq!(path.durations, durations);
		assert_eq!(path.total_duration, 35_000_000);
	}

	#[test]
	fn test_execution_path_matches_pattern() {
		let events = vec![Event("start"), Event("process"), Event("end")];
		let durations = vec![Some(10_000_000), Some(20_000_000), Some(5_000_000)];
		let path = ExecutionPath::new(events, durations);

		// Exact match
		assert!(path.matches_pattern(&[Event("start"), Event("process"), Event("end")]));

		// Prefix match
		assert!(path.matches_pattern(&[Event("start"), Event("process")]));

		// No match
		assert!(!path.matches_pattern(&[Event("start"), Event("wrong")]));

		// Pattern too long
		assert!(!path.matches_pattern(&[Event("start"), Event("process"), Event("end"), Event("extra")]));
	}

	#[test]
	fn test_path_wcet_new() {
		let path = vec![Event("start"), Event("process"), Event("end")];
		let max_duration = Duration::from_millis(50);
		let path_wcet = PathWcet::new(path.clone(), max_duration);

		assert_eq!(path_wcet.path, path);
		assert_eq!(path_wcet.max_duration, max_duration);
		assert_eq!(path_wcet.max_duration_ns(), 50_000_000);
	}

	/// Helper to create a simple test process: start -> process -> end
	fn create_test_process() -> Result<Process, &'static str> {
		Process::builder("test")
			.initial_state(State("s0"))
			.add_terminal(State("s2"))
			.add_observable("start")
			.add_observable("process")
			.add_observable("end")
			.add_transition(State("s0"), "start", State("s1"))
			.add_transition(State("s1"), "process", State("s2"))
			.add_transition(State("s2"), "end", State("s2"))
			.build()
	}

	/// Helper to create a trace with timing events
	fn create_trace_with_timing_events(events: &[(&str, u64)]) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		#[cfg(feature = "instrument")]
		{
			use crate::instrumentation::event_kinds;
			trace.instrument_events = events
				.iter()
				.enumerate()
				.map(|(idx, (label, duration_ns))| TbEvent {
					seq: idx as u32 + 1,
					urn: event_kinds::TIMING_WCET,
					label: Some(label.to_string()),
					payload_hash: None,
					duration_ns: Some(*duration_ns),
					flags: 0,
					extras: None,
				})
				.collect();
		}
		trace
	}

	#[test]
	fn test_extract_paths_simple() -> Result<(), &'static str> {
		let process = create_test_process()?;
		let trace =
			create_trace_with_timing_events(&[("start", 10_000_000), ("process", 20_000_000), ("end", 5_000_000)]);
		let paths = extract_paths(&trace, &process);

		// Should extract one path with all three events
		assert_eq!(paths.len(), 1);
		assert_eq!(paths[0].events.len(), 3);
		assert_eq!(paths[0].total_duration, 35_000_000);
		Ok(())
	}
}
