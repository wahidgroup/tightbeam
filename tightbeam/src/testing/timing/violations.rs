//! The violations that timing verification reports.

use crate::testing::specs::csp::Event;

/// A WCET violation, where the measure of the samples of an event exceeds its
/// WCET.
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct TimingViolation {
	/// The event whose samples exceed the WCET.
	pub event: Event,
	/// The WCET bound, in nanoseconds.
	pub wcet_ns: u64,
	/// The measure that the bound tests, in nanoseconds: the longest sample,
	/// or the percentile of a percentile bound.
	pub observed_ns: u64,
	/// The sequence number of a longest sample of the event.
	pub seq: u64,
}

/// A deadline miss, where the latency from the start event to the end event
/// exceeds the deadline.
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct DeadlineMiss {
	/// The event that opens the window.
	pub start_event: Event,
	/// The event that closes the window.
	pub end_event: Event,
	/// The deadline, in nanoseconds.
	pub deadline_ns: u64,
	/// The latency of the window, in nanoseconds.
	pub observed_ns: u64,
	/// The sequence number of the start marker.
	pub start_seq: u64,
	/// The sequence number of the end marker.
	pub end_seq: u64,
}

/// A jitter violation, where the timing variation of an event exceeds its
/// largest allowed jitter.
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct JitterViolation {
	/// The event whose jitter exceeds the bound.
	pub event: Event,
	/// The largest jitter that the constraint allows, in nanoseconds.
	pub max_jitter_ns: u64,
	/// The jitter of the samples, in nanoseconds.
	pub observed_jitter_ns: u64,
	/// The sequence numbers of the samples that the jitter measures.
	pub seqs: Vec<u64>,
}

/// A slack violation, where the slack of a window falls below the minimum
/// that the deadline requires.
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct TimingSlackViolation {
	/// The event that opens the window.
	pub start_event: Event,
	/// The event that closes the window.
	pub end_event: Event,
	/// The minimum slack that the deadline requires, in nanoseconds.
	pub required_slack_ns: u64,
	/// The slack that the window leaves, in nanoseconds.
	pub observed_slack_ns: u64,
	/// The deadline, in nanoseconds.
	pub deadline_ns: u64,
	/// The latency of the window, in nanoseconds.
	pub observed_latency_ns: u64,
	/// The sequence number of the start marker.
	pub start_seq: u64,
	/// The sequence number of the end marker.
	pub end_seq: u64,
}

/// A path WCET violation, where the total duration of a path exceeds its WCET.
#[derive(Debug, Clone, PartialEq, Eq, crate::der::Sequence)]
pub struct PathWcetViolation {
	/// The events of the path whose duration exceeds the bound, in order.
	pub path: Vec<Event>,
	/// The longest duration that the path WCET allows, in nanoseconds.
	pub max_path_duration_ns: u64,
	/// The total duration of the runs of the path, in nanoseconds.
	pub observed_path_duration_ns: u64,
	/// The sequence numbers of the trace events whose label lies on the path.
	pub seqs: Vec<u64>,
}
