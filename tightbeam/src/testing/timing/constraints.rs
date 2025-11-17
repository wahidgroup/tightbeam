//! Timing constraint definitions

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::deadline::Deadline;
use super::path::PathWcet;
use super::wcet::WcetConfig;
use crate::testing::specs::csp::Event;
use crate::utils::jitter::JitterCalculator;

#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulabilityError, SchedulerType, Task, TaskSet};

/// Timing constraint for an event
#[derive(Debug, Clone)]
pub enum TimingConstraint {
	/// Worst-case execution time (WCET) with configurable analysis
	Wcet(WcetConfig),
	/// End-to-end deadline (using Deadline struct)
	Deadline(Deadline),
	/// Maximum jitter with optional calculator
	Jitter(Duration, Option<Arc<dyn JitterCalculator>>),
}

/// Timing constraints for a CSP process
#[derive(Debug, Default, Clone)]
pub struct TimingConstraints {
	/// Map from event label to timing constraint (WCET, Jitter)
	pub(crate) constraints: HashMap<Event, TimingConstraint>,
	/// Separate storage for deadlines (event pairs)
	deadlines: Vec<Deadline>,
	/// Separate storage for path-based WCET constraints
	path_wcets: Vec<PathWcet>,
}

impl TimingConstraints {
	/// Add a timing constraint for an event (WCET or Jitter)
	pub fn add(&mut self, event: Event, constraint: TimingConstraint) {
		// Skip Deadline constraints - they should be added via add_deadline()
		if !matches!(constraint, TimingConstraint::Deadline(_)) {
			self.constraints.insert(event, constraint);
		}
	}

	/// Add a deadline constraint (event pair)
	pub fn add_deadline(&mut self, deadline: Deadline) {
		self.deadlines.push(deadline);
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
	pub fn constrained_events_iter(&self) -> impl Iterator<Item = &Event> {
		self.constraints.keys()
	}

	/// Get all deadlines
	pub fn deadlines(&self) -> &[Deadline] {
		&self.deadlines
	}

	/// Add a path-based WCET constraint
	pub fn add_path_wcet(&mut self, path_wcet: PathWcet) {
		self.path_wcets.push(path_wcet);
	}

	/// Get all path-based WCET constraints
	pub fn path_wcets(&self) -> &[PathWcet] {
		&self.path_wcets
	}

	/// Convert timing constraints to task set for schedulability analysis
	///
	/// Requires period mapping (event -> period) since periods are not
	/// part of timing constraints.
	#[cfg(feature = "testing-timing")]
	pub fn to_task_set(
		&self,
		periods: &HashMap<Event, Duration>,
		scheduler: SchedulerType,
	) -> Result<TaskSet, SchedulabilityError> {
		let mut tasks = Vec::new();

		// Extract tasks from WCET constraints
		for (event, constraint) in &self.constraints {
			if let TimingConstraint::Wcet(wcet_config) = constraint {
				let period = periods
					.get(event)
					.ok_or_else(|| SchedulabilityError::MissingPeriod(event.0.to_string()))?;

				// Find deadline for this event (if exists)
				let deadline = self
					.deadlines
					.iter()
					.find(|d| &d.start_event == event || &d.end_event == event)
					.map(|d| d.duration)
					.unwrap_or(*period); // Default: deadline = period

				// Calculate priority for RMA (shorter period = higher priority)
				let priority = if matches!(scheduler, SchedulerType::RateMonotonic) {
					Some(period.as_nanos() as u32) // Use period as priority (lower = higher priority)
				} else {
					None
				};

				tasks.push(Task {
					id: event.0.to_string(),
					period: *period,
					deadline,
					wcet: wcet_config.duration,
					priority,
				});
			}
		}

		Ok(TaskSet { tasks, scheduler })
	}
}
