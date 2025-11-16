//! Timing and real-time verification module
//!
//! Provides WCET (Worst-Case Execution Time) verification and deadline checking
//! for real-time systems. Integrates with CSP process specifications and
//! instrumentation events.

use crate::instrumentation::{TbEvent, TbEventKind};
use crate::testing::specs::csp::{Event, Process};
use crate::trace::ConsumedTrace;
use crate::TightBeamError;

use std::collections::HashMap;
use std::time::Duration;

/// Timing constraint for an event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingConstraint {
	/// Worst-case execution time (WCET)
	Wcet(Duration),
	/// End-to-end deadline
	Deadline(Duration),
	/// Maximum jitter
	Jitter(Duration),
	/// Timing slack (available time before deadline)
	Slack(Duration),
}

/// Timing constraints for a CSP process
#[derive(Debug, Clone)]
pub struct TimingConstraints {
	/// Map from event label to timing constraint
	constraints: HashMap<Event, TimingConstraint>,
}

impl TimingConstraints {
	/// Create new empty timing constraints
	pub fn new() -> Self {
		Self { constraints: HashMap::new() }
	}

	/// Add a timing constraint for an event
	pub fn add(&mut self, event: Event, constraint: TimingConstraint) {
		self.constraints.insert(event, constraint);
	}

	/// Get timing constraint for an event
	pub fn get(&self, event: &Event) -> Option<&TimingConstraint> {
		self.constraints.get(event)
	}

	/// Check if event has any timing constraint
	pub fn has_constraint(&self, event: &Event) -> bool {
		self.constraints.contains_key(event)
	}

	/// Get all constrained events
	pub fn constrained_events(&self) -> impl Iterator<Item = &Event> {
		self.constraints.keys()
	}
}

impl Default for TimingConstraints {
	fn default() -> Self {
		Self::new()
	}
}

/// Timing verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingVerificationResult {
	/// Whether all timing constraints were satisfied
	pub passed: bool,
	/// WCET violations found
	pub wcet_violations: Vec<TimingViolation>,
	/// Deadline misses found
	pub deadline_misses: Vec<DeadlineMiss>,
	/// Jitter violations found
	pub jitter_violations: Vec<JitterViolation>,
}

/// WCET violation: observed duration exceeded WCET
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimingViolation {
	/// Event label that violated WCET
	pub event: Event,
	/// WCET constraint (nanoseconds)
	pub wcet_ns: u64,
	/// Observed duration (nanoseconds)
	pub observed_ns: u64,
	/// Sequence number of violating event
	pub seq: u32,
}

/// Deadline miss: event-to-event latency exceeded deadline
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlineMiss {
	/// Start event label
	pub start_event: Event,
	/// End event label
	pub end_event: Event,
	/// Deadline constraint (nanoseconds)
	pub deadline_ns: u64,
	/// Observed latency (nanoseconds)
	pub observed_ns: u64,
	/// Sequence numbers of events
	pub start_seq: u32,
	pub end_seq: u32,
}

/// Jitter violation: timing variation exceeded maximum jitter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitterViolation {
	/// Event label that violated jitter
	pub event: Event,
	/// Maximum jitter constraint (nanoseconds)
	pub max_jitter_ns: u64,
	/// Observed jitter (nanoseconds)
	pub observed_jitter_ns: u64,
	/// Sequence numbers of events
	pub seqs: Vec<u32>,
}

impl Default for TimingVerificationResult {
	fn default() -> Self {
		Self {
			passed: true,
			wcet_violations: Vec::new(),
			deadline_misses: Vec::new(),
			jitter_violations: Vec::new(),
		}
	}
}

/// Verify timing constraints against trace
///
/// Checks observed durations from instrumentation events against timing
/// constraints defined in CSP process specification.
#[cfg(feature = "testing-timing")]
pub fn verify_timing(
	_process: &Process,
	timing_constraints: &TimingConstraints,
	trace: &ConsumedTrace,
) -> Result<TimingVerificationResult, TightBeamError> {
	let mut result = TimingVerificationResult::default();

	// Extract timing events from trace
	#[cfg(feature = "instrument")]
	let timing_events: Vec<&TbEvent> = trace
		.instrument_events
		.iter()
		.filter(|ev| {
			matches!(
				ev.kind,
				TbEventKind::TimingWcet | TbEventKind::TimingDeadline | TbEventKind::TimingJitter
			)
		})
		.collect();
	#[cfg(not(feature = "instrument"))]
	let timing_events: Vec<&TbEvent> = Vec::new();

	// Group events by label for jitter calculation
	let mut events_by_label: HashMap<String, Vec<&TbEvent>> = HashMap::new();
	for event in &timing_events {
		if let Some(label) = &event.label {
			events_by_label.entry(label.clone()).or_default().push(event);
		}
	}

	// Check WCET constraints
	for (event, constraint) in timing_constraints.constraints.iter() {
		if let TimingConstraint::Wcet(wcet) = constraint {
			let wcet_ns = wcet.as_nanos() as u64;
			let event_label = event.0;

			// Find all events with this label
			if let Some(events) = events_by_label.get(event_label) {
				for ev in events {
					if let Some(observed_ns) = ev.duration_ns {
						if observed_ns > wcet_ns {
							result.passed = false;
							result.wcet_violations.push(TimingViolation {
								event: event.clone(),
								wcet_ns,
								observed_ns,
								seq: ev.seq,
							});
						}
					}
				}
			}
		}
	}

	// Check deadline constraints (event-to-event latency)
	for (event, constraint) in timing_constraints.constraints.iter() {
		if let TimingConstraint::Deadline(deadline) = constraint {
			let deadline_ns = deadline.as_nanos() as u64;
			let event_label = event.0;

			// Find pairs of events with this label (start -> end)
			// For now, check consecutive events with same label
			// TODO: Support explicit start/end event pairs
			if let Some(events) = events_by_label.get(event_label) {
				if events.len() >= 2 {
					for i in 0..events.len() - 1 {
						let start = events[i];
						let end = events[i + 1];

						if let (Some(start_ns), Some(end_ns)) = (start.duration_ns, end.duration_ns) {
							let latency_ns = end_ns.saturating_sub(start_ns);
							if latency_ns > deadline_ns {
								result.passed = false;
								result.deadline_misses.push(DeadlineMiss {
									start_event: event.clone(),
									end_event: event.clone(),
									deadline_ns,
									observed_ns: latency_ns,
									start_seq: start.seq,
									end_seq: end.seq,
								});
							}
						}
					}
				}
			}
		}
	}

	// Check jitter constraints
	for (event, constraint) in timing_constraints.constraints.iter() {
		if let TimingConstraint::Jitter(max_jitter) = constraint {
			let max_jitter_ns = max_jitter.as_nanos() as u64;
			let event_label = event.0;

			if let Some(events) = events_by_label.get(event_label) {
				if events.len() >= 2 {
					let durations: Vec<u64> = events.iter().filter_map(|ev| ev.duration_ns).collect();

					if durations.len() >= 2 {
						let min_duration = durations.iter().min().copied().unwrap_or(0);
						let max_duration = durations.iter().max().copied().unwrap_or(0);
						let observed_jitter = max_duration.saturating_sub(min_duration);

						if observed_jitter > max_jitter_ns {
							result.passed = false;
							result.jitter_violations.push(JitterViolation {
								event: event.clone(),
								max_jitter_ns,
								observed_jitter_ns: observed_jitter,
								seqs: events.iter().map(|ev| ev.seq).collect(),
							});
						}
					}
				}
			}
		}
	}

	Ok(result)
}

#[cfg(not(feature = "testing-timing"))]
pub fn verify_timing(
	_process: &Process,
	_timing_constraints: &TimingConstraints,
	_trace: &ConsumedTrace,
) -> Result<TimingVerificationResult, TightBeamError> {
	// No-op when feature disabled
	Ok(TimingVerificationResult::default())
}
