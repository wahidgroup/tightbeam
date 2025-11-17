//! Deadline constraint definitions

use crate::builder::TypeBuilder;
use crate::testing::error::TestingError;
use crate::testing::specs::csp::Event;
use std::time::Duration;

/// Deadline constraint with explicit start and end events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deadline {
	/// Maximum allowed duration between start and end events
	pub duration: Duration,
	/// Start event label
	pub start_event: Event,
	/// End event label
	pub end_event: Event,
	/// Minimum required slack (optional)
	pub min_slack: Option<Duration>,
}

/// Builder for creating `Deadline` instances.
#[derive(Debug, Default, Clone)]
pub struct DeadlineBuilder {
	duration: Option<Duration>,
	start_event: Option<Event>,
	end_event: Option<Event>,
	min_slack: Option<Duration>,
}

impl DeadlineBuilder {
	/// Set the deadline duration.
	pub fn with_duration(mut self, duration: Duration) -> Self {
		self.duration = Some(duration);
		self
	}

	/// Set the start event.
	pub fn with_start_event(mut self, start_event: Event) -> Self {
		self.start_event = Some(start_event);
		self
	}

	/// Set the end event.
	pub fn with_end_event(mut self, end_event: Event) -> Self {
		self.end_event = Some(end_event);
		self
	}

	/// Set the minimum required slack.
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

		// Validate: slack cannot exceed duration
		if let Some(slack) = self.min_slack {
			if slack > duration {
				return Err(TestingError::InvalidSlack);
			}
		}

		Ok(Deadline { duration, start_event, end_event, min_slack: self.min_slack })
	}
}
