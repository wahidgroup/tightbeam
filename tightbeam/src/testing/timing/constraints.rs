//! The timing constraints that a CSP process states on its events.

use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::deadline::Deadline;
use super::jitter::{JitterCalculator, MinMaxJitter};
use super::path::PathWcet;
use super::saturating_nanos;
use super::wcet::WcetConfig;
use crate::testing::error::TestingError;
use crate::testing::specs::csp::Event;

#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulabilityError, SchedulerType, Task, TaskSet};

/// A timing constraint on one event.
#[derive(Debug, Clone)]
pub enum TimingConstraint {
	/// A worst-case execution time (WCET) bound, under the analysis that its
	/// configuration selects.
	Wcet(WcetConfig),
	/// A maximum jitter, with an optional calculator that measures it.
	Jitter(Duration, Option<Arc<dyn JitterCalculator>>),
}

impl TimingConstraint {
	/// Whether this constraint and `other` state one bound under one analysis.
	///
	/// An analyzer or a jitter calculator is a trait object with no equality
	/// of its own, so two of them agree only when they are one instance.
	pub(crate) fn agrees_with(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Wcet(mine), Self::Wcet(theirs)) => mine.agrees_with(theirs),
			(Self::Jitter(mine, my_calculator), Self::Jitter(theirs, their_calculator)) => {
				mine == theirs && same_instance(my_calculator, their_calculator)
			}
			_ => false,
		}
	}

	/// The bound of this constraint in nanoseconds, saturated at `u64::MAX`.
	pub(crate) fn bound_ns(&self) -> u64 {
		match self {
			Self::Wcet(wcet) => wcet.bound_ns(),
			Self::Jitter(max_jitter, _) => saturating_nanos(*max_jitter),
		}
	}

	/// The measure of the samples `durations` of `event`, in nanoseconds,
	/// when it exceeds this constraint, or `None` when the samples hold it.
	///
	/// A WCET bound measures the samples by its [`WcetConfig`]. A jitter bound
	/// measures their spread with its calculator, or with [`MinMaxJitter`] when
	/// it names none. A single sample has no spread, and a set with nothing to
	/// measure holds the bound.
	///
	/// # Errors
	///
	/// - [`TestingError::WcetAnalysisFailed`] -- the analyzer of a WCET percentile fails on `durations`.
	/// - [`TestingError::WcetPercentileMissing`] -- the analyzer of a WCET percentile gives no value for it.
	/// - [`TestingError::JitterCalculationFailed`] -- the calculator of a jitter bound fails on `durations`.
	pub(crate) fn excess(&self, event: Event, durations: &[u64]) -> Result<Option<u64>, TestingError> {
		let measure = match self {
			Self::Wcet(wcet) => wcet.measure(event, durations)?,
			Self::Jitter(_, _) if durations.len() < 2 => None,
			Self::Jitter(_, calculator) => {
				let calculator = calculator.as_deref().unwrap_or(&MinMaxJitter);
				let jitter = calculator.calculate(durations);
				let jitter =
					jitter.map_err(|cause| TestingError::JitterCalculationFailed { event, cause: Box::new(cause) })?;
				Some(jitter)
			}
		};

		Ok(measure.filter(|measure| *measure > self.bound_ns()))
	}
}

/// Whether `mine` and `theirs` hold one instance, or both hold none.
pub(super) fn same_instance<T: ?Sized>(mine: &Option<Arc<T>>, theirs: &Option<Arc<T>>) -> bool {
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
	/// Adds a WCET or jitter constraint on `event`, or keeps the one that
	/// `event` holds when the two agree.
	///
	/// # Errors
	///
	/// - [`TestingError::ConflictingTimingConstraint`] -- `event` holds a
	///   constraint that disagrees with `constraint`.
	///
	/// # Examples
	///
	/// ```
	/// use core::time::Duration;
	///
	/// use tightbeam::builder::TypeBuilder;
	/// use tightbeam::testing::error::TestingError;
	/// use tightbeam::testing::specs::csp::Event;
	/// use tightbeam::testing::timing::{TimingConstraint, TimingConstraints, WcetConfigBuilder};
	///
	/// let wcet = WcetConfigBuilder::default().with_duration(Duration::from_millis(10)).build()?;
	/// let mut constraints = TimingConstraints::default();
	/// constraints.add(Event("send"), TimingConstraint::Wcet(wcet))?;
	///
	/// let jitter = TimingConstraint::Jitter(Duration::from_millis(2), None);
	/// let refused = constraints.add(Event("send"), jitter);
	/// assert!(matches!(refused, Err(TestingError::ConflictingTimingConstraint(Event("send")))));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn add(&mut self, event: Event, constraint: TimingConstraint) -> Result<(), TestingError> {
		let admitted = self.admit(event, Cow::Owned(constraint));
		admitted.map_err(TestingError::ConflictingTimingConstraint)
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
			joined.admit(*event, Cow::Borrowed(constraint))?;
		}

		for deadline in &other.deadlines {
			joined.admit_deadline(Cow::Borrowed(deadline));
		}
		for path_wcet in &other.path_wcets {
			joined.admit_path_wcet(Cow::Borrowed(path_wcet));
		}

		Ok(joined)
	}

	/// These constraints with each event mapped through `rename`.
	///
	/// When a rename maps two events to one, their constraints merge if they
	/// agree.
	///
	/// # Errors
	///
	/// - The first renamed event, in the name order of the source events, that
	///   two disagreeing constraints map to.
	pub(crate) fn renamed<R>(&self, rename: R) -> Result<Self, Event>
	where
		R: Fn(Event) -> Event,
	{
		let mut renamed = Self::default();

		let mut entries: Vec<(&Event, &TimingConstraint)> = self.constraints.iter().collect();
		entries.sort_unstable_by_key(|(event, _)| **event);
		for (event, constraint) in entries {
			renamed.admit(rename(*event), Cow::Borrowed(constraint))?;
		}

		for deadline in &self.deadlines {
			let start_event = rename(deadline.start_event);
			let end_event = rename(deadline.end_event);
			renamed.admit_deadline(Cow::Owned(Deadline { start_event, end_event, ..deadline.clone() }));
		}
		for path_wcet in &self.path_wcets {
			let path = path_wcet.path.iter().map(|event| rename(*event));
			renamed.admit_path_wcet(Cow::Owned(PathWcet::new(path, path_wcet.max_duration)));
		}

		Ok(renamed)
	}

	/// Adds `constraint` on `event`, or keeps the one held when the two
	/// agree. A borrowed constraint is copied only when the set takes it.
	///
	/// # Errors
	///
	/// - `event`, when it holds a constraint that does not agree with `constraint`.
	fn admit(&mut self, event: Event, constraint: Cow<'_, TimingConstraint>) -> Result<(), Event> {
		match self.constraints.entry(event) {
			Entry::Occupied(held) if held.get().agrees_with(&constraint) => Ok(()),
			Entry::Occupied(_) => Err(event),
			Entry::Vacant(slot) => {
				slot.insert(constraint.into_owned());
				Ok(())
			}
		}
	}

	/// Adds `deadline` unless the set holds an equal deadline.
	fn admit_deadline(&mut self, deadline: Cow<'_, Deadline>) {
		if !self.deadlines.contains(&deadline) {
			self.deadlines.push(deadline.into_owned());
		}
	}

	/// Adds `path_wcet` unless the set holds an equal path WCET.
	fn admit_path_wcet(&mut self, path_wcet: Cow<'_, PathWcet>) {
		if !self.path_wcets.contains(&path_wcet) {
			self.path_wcets.push(path_wcet.into_owned());
		}
	}

	/// Converts the WCET constraints to a task set for schedulability analysis.
	///
	/// `periods` maps each event to its period, because a timing constraint
	/// states no period. Each task takes the rate-monotonic priority of its
	/// period (a `None` [`Task::priority`]).
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::MissingPeriod`] -- a WCET event has no period in `periods`.
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
					.unwrap_or(*period); // With no deadline, the task deadline is its period.

				tasks.push(Task {
					id: event.0.to_string(),
					period: *period,
					deadline,
					wcet: wcet_config.duration,
					priority: None,
				});
			}
		}

		Ok(TaskSet { tasks, scheduler })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::schedulability::{ResponseTime, TaskResponseTime};
	use crate::testing::timing::{DefaultStatisticalAnalyzer, Percentile, StatisticalAnalyzer, WcetPercentile};
	use crate::testing::TestResult;

	/// A P99 WCET bound of 10 ms under an analyzer of its own.
	fn p99_wcet_under_its_own_analyzer() -> TimingConstraint {
		let analyzer: Arc<dyn StatisticalAnalyzer> = Arc::new(DefaultStatisticalAnalyzer);
		let percentile = Some(WcetPercentile { percentile: Percentile::P99, analyzer: Some(analyzer) });
		TimingConstraint::Wcet(WcetConfig { duration: Duration::from_millis(10), percentile })
	}

	// A second constraint on `process` that disagrees with the one it holds is
	// refused: two bounds under two analyzers, and two bounds of two kinds.
	crate::tb_cases! {
		fn add_refuses_a_disagreeing_constraint((held, added): (TimingConstraint, TimingConstraint)) -> TestResult {
			let mut constraints = TimingConstraints::default();
			constraints.add(Event("process"), held)?;

			let refused = constraints.add(Event("process"), added);
			assert!(matches!(refused, Err(TestingError::ConflictingTimingConstraint(Event("process")))));
			Ok(())
		}

		cases {
			under_another_analyzer => (p99_wcet_under_its_own_analyzer(), p99_wcet_under_its_own_analyzer()),
			of_another_kind => (
				TimingConstraint::Wcet(WcetConfig::of_millis(10)),
				TimingConstraint::Jitter(Duration::from_millis(5), None),
			),
		}
	}

	/// A task set keeps the rate order of periods past four seconds. The task
	/// of the 4 s period runs first: R = 1 s, and the other task takes
	/// R = 2 + ⌈3/4⌉ * 1 = 3 s. The order of the 5 s period first gives 2 s and
	/// 3 s.
	#[test]
	fn a_task_set_keeps_the_rate_order_of_periods_past_four_seconds() -> TestResult {
		let mut constraints = TimingConstraints::default();
		constraints.add(Event("fast"), TimingConstraint::Wcet(WcetConfig::of_millis(1_000)))?;
		constraints.add(Event("slow"), TimingConstraint::Wcet(WcetConfig::of_millis(2_000)))?;

		let periods = HashMap::from([(Event("fast"), Duration::from_secs(4)), (Event("slow"), Duration::from_secs(5))]);
		let task_set = constraints.to_task_set(&periods, SchedulerType::RateMonotonic)?;
		let response_times = task_set.response_time_analysis()?;

		let one_second = ResponseTime::Converged(Duration::from_secs(1));
		let three_seconds = ResponseTime::Converged(Duration::from_secs(3));
		let named = TaskResponseTime::named(&response_times);
		assert_eq!(named, [("fast", one_second), ("slow", three_seconds)]);
		Ok(())
	}
}
