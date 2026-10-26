//! The timing constraints that a CSP process states on its events.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::deadline::Deadline;
use super::jitter::JitterCalculator;
use super::path::PathWcet;
use super::wcet::WcetConfig;
use crate::testing::specs::csp::Event;

#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulabilityError, SchedulerType, Task, TaskSet};

/// A timing constraint on one event.
#[derive(Debug, Clone)]
pub enum TimingConstraint {
	/// A worst-case execution time (WCET) bound, under the analysis that its
	/// configuration selects.
	Wcet(WcetConfig),
	/// An end-to-end deadline between two events.
	Deadline(Deadline),
	/// A maximum jitter, with an optional calculator that measures it.
	Jitter(Duration, Option<Arc<dyn JitterCalculator>>),
}

impl TimingConstraint {
	/// Whether this constraint and `other` state one bound under one
	/// analysis.
	///
	/// An analyzer or a jitter calculator is a trait object with no equality
	/// of its own, so two of them agree only when they are one instance.
	pub(crate) fn agrees_with(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Wcet(mine), Self::Wcet(theirs)) => {
				let same_bound = mine.duration == theirs.duration && mine.percentile == theirs.percentile;
				same_bound && same_instance(&mine.analyzer, &theirs.analyzer)
			}
			(Self::Jitter(mine, my_calculator), Self::Jitter(theirs, their_calculator)) => {
				mine == theirs && same_instance(my_calculator, their_calculator)
			}
			(Self::Deadline(mine), Self::Deadline(theirs)) => mine == theirs,
			_ => false,
		}
	}
}

/// Whether `mine` and `theirs` hold one instance, or both hold none.
fn same_instance<T: ?Sized>(mine: &Option<Arc<T>>, theirs: &Option<Arc<T>>) -> bool {
	match (mine, theirs) {
		(Some(mine), Some(theirs)) => Arc::ptr_eq(mine, theirs),
		(None, None) => true,
		_ => false,
	}
}

/// The timing constraints of a CSP process.
#[derive(Debug, Default, Clone)]
pub struct TimingConstraints {
	/// The WCET or jitter constraint of each event.
	pub(crate) constraints: HashMap<Event, TimingConstraint>,
	/// The deadlines, each between a pair of events.
	deadlines: Vec<Deadline>,
	/// The path WCET constraints.
	path_wcets: Vec<PathWcet>,
}

impl TimingConstraints {
	/// Adds a WCET or jitter constraint on `event`, and skips a deadline
	/// constraint, which [`Self::add_deadline`] adds.
	pub fn add(&mut self, event: Event, constraint: TimingConstraint) {
		if !matches!(constraint, TimingConstraint::Deadline(_)) {
			self.constraints.insert(event, constraint);
		}
	}

	/// Adds a deadline constraint between a pair of events.
	pub fn add_deadline(&mut self, deadline: Deadline) {
		self.deadlines.push(deadline);
	}

	/// The WCET or jitter constraint on `event`, or `None` when it has none.
	pub fn get(&self, event: &Event) -> Option<&TimingConstraint> {
		self.constraints.get(event)
	}

	/// Whether `event` has a WCET or jitter constraint.
	pub fn has_constraint(&self, event: &Event) -> bool {
		self.constraints.contains_key(event)
	}

	/// The events that have a WCET or jitter constraint.
	pub fn constrained_events_iter(&self) -> impl Iterator<Item = &Event> {
		self.constraints.keys()
	}

	/// Every deadline constraint.
	pub fn deadlines(&self) -> &[Deadline] {
		&self.deadlines
	}

	/// Adds a path WCET constraint.
	pub fn add_path_wcet(&mut self, path_wcet: PathWcet) {
		self.path_wcets.push(path_wcet);
	}

	/// Every path WCET constraint.
	pub fn path_wcets(&self) -> &[PathWcet] {
		&self.path_wcets
	}

	/// The constraints of `self` and of `other` together.
	///
	/// An event that both constrain keeps one constraint when the two agree,
	/// and a deadline or a path WCET that both hold appears once.
	///
	/// # Errors
	///
	/// - The first event, in name order, that the two constrain in ways that do not agree.
	pub(crate) fn union(&self, other: &Self) -> Result<Self, Event> {
		let mut joined = self.clone();
		let mut entries: Vec<(&Event, &TimingConstraint)> = other.constraints.iter().collect();
		entries.sort_unstable_by_key(|(event, _)| **event);

		for (event, constraint) in entries {
			joined.admit(*event, constraint)?;
		}

		for deadline in &other.deadlines {
			joined.admit_deadline(deadline.clone());
		}
		for path_wcet in &other.path_wcets {
			joined.admit_path_wcet(path_wcet.clone());
		}

		Ok(joined)
	}

	/// These constraints with each event mapped through `rename`.
	///
	/// A rename may map two events to one, and the two constraints then
	/// become one when they agree.
	///
	/// # Errors
	///
	/// - The first renamed event, in the name order of the events it renames,
	///   that two constraints which do not agree map to.
	pub(crate) fn renamed<R>(&self, rename: R) -> Result<Self, Event>
	where
		R: Fn(Event) -> Event,
	{
		let mut renamed = Self::default();
		let mut entries: Vec<(&Event, &TimingConstraint)> = self.constraints.iter().collect();
		entries.sort_unstable_by_key(|(event, _)| **event);

		for (event, constraint) in entries {
			renamed.admit(rename(*event), constraint)?;
		}

		for deadline in &self.deadlines {
			let start_event = rename(deadline.start_event);
			let end_event = rename(deadline.end_event);
			renamed.admit_deadline(Deadline { start_event, end_event, ..deadline.clone() });
		}
		for path_wcet in &self.path_wcets {
			let path = path_wcet.path.iter().map(|event| rename(*event));
			renamed.admit_path_wcet(PathWcet::new(path, path_wcet.max_duration));
		}

		Ok(renamed)
	}

	/// Adds `constraint` on `event`, or keeps the one held when the two
	/// agree.
	///
	/// # Errors
	///
	/// - `event`, when it holds a constraint that does not agree with `constraint`.
	fn admit(&mut self, event: Event, constraint: &TimingConstraint) -> Result<(), Event> {
		match self.constraints.get(&event) {
			Some(held) if held.agrees_with(constraint) => Ok(()),
			Some(_) => Err(event),
			None => {
				self.constraints.insert(event, constraint.clone());
				Ok(())
			}
		}
	}

	/// Adds `deadline` unless the set holds an equal deadline.
	fn admit_deadline(&mut self, deadline: Deadline) {
		if !self.deadlines.contains(&deadline) {
			self.deadlines.push(deadline);
		}
	}

	/// Adds `path_wcet` unless the set holds an equal path WCET.
	fn admit_path_wcet(&mut self, path_wcet: PathWcet) {
		if !self.path_wcets.contains(&path_wcet) {
			self.path_wcets.push(path_wcet);
		}
	}

	/// Converts the WCET constraints to a task set for schedulability
	/// analysis.
	///
	/// `periods` maps each event to its period, because a timing constraint
	/// states no period. A WCET event with no period fails with
	/// `SchedulabilityError::MissingPeriod`.
	#[cfg(feature = "testing-timing")]
	pub fn to_task_set(
		&self,
		periods: &HashMap<Event, Duration>,
		scheduler: SchedulerType,
	) -> Result<TaskSet, SchedulabilityError> {
		let mut tasks = Vec::new();

		for (event, constraint) in &self.constraints {
			if let TimingConstraint::Wcet(wcet_config) = constraint {
				let period = periods
					.get(event)
					.ok_or_else(|| SchedulabilityError::MissingPeriod(event.0.to_string()))?;

				// A deadline constraint that starts or ends at the event sets
				// the task deadline.
				let deadline = self
					.deadlines
					.iter()
					.find(|d| &d.start_event == event || &d.end_event == event)
					.map(|d| d.duration)
					.unwrap_or(*period); // Default: deadline = period

				// Rate monotonic analysis (RMA) ranks a task by its period, so
				// a shorter period is a higher priority.
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
