//! Timing violation types

use crate::testing::specs::csp::Event;

/// WCET violation: observed duration exceeded WCET
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
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
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
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
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
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

/// Slack violation: observed slack below minimum required slack
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct TimingSlackViolation {
	/// Start event label
	pub start_event: Event,
	/// End event label
	pub end_event: Event,
	/// Required minimum slack (nanoseconds)
	pub required_slack_ns: u64,
	/// Observed slack (nanoseconds)
	pub observed_slack_ns: u64,
	/// Deadline constraint (nanoseconds)
	pub deadline_ns: u64,
	/// Observed latency (nanoseconds)
	pub observed_latency_ns: u64,
	/// Sequence numbers of events
	pub start_seq: u32,
	pub end_seq: u32,
}

/// Path WCET violation: total path duration exceeded path WCET
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct PathWcetViolation {
	/// Path events that violated WCET
	pub path: Vec<Event>,
	/// Maximum allowed path duration (nanoseconds)
	pub max_path_duration_ns: u64,
	/// Observed path duration (nanoseconds)
	pub observed_path_duration_ns: u64,
	/// Sequence numbers of events in path
	pub seqs: Vec<u32>,
}
