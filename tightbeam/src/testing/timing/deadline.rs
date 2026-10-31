//! The deadline constraint between a start event and an end event.

use super::saturating_nanos;
use crate::builder::TypeBuilder;
use crate::testing::error::TestingError;
use crate::testing::specs::csp::Event;
use std::time::Duration;

/// A deadline constraint between an explicit start event and end event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deadline {
	/// The longest time that the deadline allows from the start event to the
	/// end event.
	pub duration: Duration,
	/// The event that opens a deadline window.
	pub start_event: Event,
	/// The event that closes a deadline window.
	pub end_event: Event,
	/// The slack that a window must leave under `duration`, or `None` when the
	/// deadline requires none.
	pub min_slack: Option<Duration>,
}

impl Deadline {
	/// The duration of the deadline in nanoseconds, saturated at `u64::MAX`.
	pub(crate) fn duration_ns(&self) -> u64 {
		saturating_nanos(self.duration)
	}

	/// The minimum slack in nanoseconds, saturated at `u64::MAX`, or `None`
	/// when the deadline requires none.
	pub(crate) fn min_slack_ns(&self) -> Option<u64> {
		self.min_slack.map(saturating_nanos)
	}

	/// The latency `latency_ns` of a window, when it exceeds this deadline,
	/// or `None` when the window meets it.
	pub(crate) fn excess(&self, latency_ns: u64) -> Option<u64> {
		(latency_ns > self.duration_ns()).then_some(latency_ns)
	}

	/// The slack that a window of latency `latency_ns` leaves under this
	/// deadline, when it falls short of the minimum slack, or `None` when it
	/// keeps the minimum or the deadline requires none.
	pub(crate) fn slack_shortfall(&self, latency_ns: u64) -> Option<u64> {
		let required_ns = self.min_slack_ns()?;
		let slack_ns = self.duration_ns().saturating_sub(latency_ns);

		(slack_ns < required_ns).then_some(slack_ns)
	}
}

#[cfg(test)]
impl Deadline {
	/// A deadline of `millis` milliseconds from `start` to `end`, with no
	/// minimum slack.
	pub(crate) fn of_millis(millis: u64, start: &'static str, end: &'static str) -> Self {
		let (start_event, end_event) = (Event(start), Event(end));
		Deadline { duration: Duration::from_millis(millis), start_event, end_event, min_slack: None }
	}
}

/// The builder of a [`Deadline`].
#[derive(Debug, Default, Clone)]
pub struct DeadlineBuilder {
	duration: Option<Duration>,
	start_event: Option<Event>,
	end_event: Option<Event>,
	min_slack: Option<Duration>,
}

impl DeadlineBuilder {
	/// Sets the longest time that the deadline allows.
	pub fn with_duration(mut self, duration: Duration) -> Self {
		self.duration = Some(duration);
		self
	}

	/// Sets the event that opens a deadline window.
	pub fn with_start_event(mut self, start_event: Event) -> Self {
		self.start_event = Some(start_event);
		self
	}

	/// Sets the event that closes a deadline window.
	pub fn with_end_event(mut self, end_event: Event) -> Self {
		self.end_event = Some(end_event);
		self
	}

	/// Sets the slack that a window must leave under the duration.
	pub fn with_min_slack(mut self, min_slack: Duration) -> Self {
		self.min_slack = Some(min_slack);
		self
	}
}

impl TypeBuilder<Deadline> for DeadlineBuilder {
	type Error = TestingError;

	fn build(self) -> Result<Deadline, Self::Error> {
		let duration = self.duration.ok_or(TestingError::InvalidTimingConstraint)?;
		let start_event = self.start_event.ok_or(TestingError::InvalidTimingConstraint)?;
		let end_event = self.end_event.ok_or(TestingError::InvalidTimingConstraint)?;

		// A minimum slack past the duration is a bound that no window meets.
		if let Some(slack) = self.min_slack {
			if slack > duration {
				return Err(TestingError::InvalidSlack);
			}
		}

		Ok(Deadline { duration, start_event, end_event, min_slack: self.min_slack })
	}
}
