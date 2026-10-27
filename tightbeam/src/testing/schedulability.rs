//! The schedulability analysis of real-time systems.
//!
//! It has three schedulability tests for a real-time task set:
//! - Rate Monotonic Analysis (RMA).
//! - Earliest Deadline First (EDF).
//! - Response Time Analysis, the exact test.

use crate::Errorizable;
use core::time::Duration;

/// A task of the real-time task model.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
	/// The identifier of the task.
	pub id: String,
	/// The period `T` of the task.
	pub period: Duration,
	/// The relative deadline `D` of the task.
	pub deadline: Duration,
	/// The worst-case execution time `C` of the task.
	pub wcet: Duration,
	/// The fixed priority that response time analysis ranks the task by, lower
	/// number first, or `None` for the rate-monotonic priority of its period.
	/// A task set declares a priority on every task or on none. Tasks of one
	/// priority keep the rate order.
	pub priority: Option<u32>,
}

/// A task set for the schedulability analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskSet {
	/// The tasks of the set.
	pub tasks: Vec<Task>,
	/// The scheduler that runs the set.
	pub scheduler: SchedulerType,
}

/// The scheduling policy of a task set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerType {
	/// Rate Monotonic Scheduling.
	RateMonotonic,
	/// Earliest Deadline First.
	EarliestDeadlineFirst,
}

impl core::fmt::Display for SchedulerType {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::RateMonotonic => write!(f, "rate monotonic"),
			Self::EarliestDeadlineFirst => write!(f, "earliest deadline first"),
		}
	}
}

/// The result of a schedulability test.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulabilityResult {
	/// The scheduler that the analysis assumed.
	pub scheduler: SchedulerType,
	/// Whether the task set passes the test.
	pub is_schedulable: bool,
	/// The total utilization, Σ(Ci/Ti).
	pub utilization: f64,
	/// The utilization bound of the scheduler.
	pub utilization_bound: f64,
	/// The violations that the test found, empty for a schedulable set.
	pub violations: Vec<TaskViolationDetail>,
}

/// The response time of one task, which [`TaskSet::response_time_analysis`]
/// finds.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam::testing::schedulability::{ResponseTime, SchedulerType, Task, TaskSet};
///
/// let task = |id: &str, period_ms, wcet_ms| Task {
///     id: id.to_string(),
///     period: Duration::from_millis(period_ms),
///     deadline: Duration::from_millis(period_ms),
///     wcet: Duration::from_millis(wcet_ms),
///     priority: None,
/// };
/// let tasks = vec![task("slow", 20, 5), task("fast", 10, 3)];
/// let task_set = TaskSet { tasks, scheduler: SchedulerType::RateMonotonic };
///
/// let response_times = task_set.response_time_analysis()?;
/// let named: Vec<_> = response_times.iter().map(|time| (time.task.id.as_str(), time.response_time)).collect();
/// let fast = ResponseTime::Converged(Duration::from_millis(3));
/// let slow = ResponseTime::Converged(Duration::from_millis(8));
/// assert_eq!(named, [("fast", fast), ("slow", slow)]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TaskResponseTime {
	/// The task that the response time belongs to.
	pub task: Task,
	/// What the analysis found for the task.
	pub response_time: ResponseTime,
}

impl TaskResponseTime {
	/// The violation of this response time, or `None` for a time within the
	/// deadline of the task.
	///
	/// A time past the deadline is a miss. An inconclusive recurrence is a
	/// violation too, because it proves no bound.
	fn violation(&self) -> Option<TaskViolationDetail> {
		let deadline = self.task.deadline;
		let message = match self.response_time {
			ResponseTime::Converged(_) => return None,
			ResponseTime::ExceedsDeadline { lower_bound } => {
				format!("Response time of at least {lower_bound:?} exceeds deadline {deadline:?}")
			}
			ResponseTime::Inconclusive => {
				"Response time recurrence did not converge within iteration budget".to_string()
			}
		};

		Some(TaskViolationDetail { task_id: self.task.id.clone(), message })
	}
}

/// What response time analysis finds for one task.
///
/// The recurrence grows at each step, so it stops at the first step past the
/// deadline.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam::testing::schedulability::{ResponseTime, SchedulerType, Task, TaskSet};
///
/// let task = |id: &str, period_ms, wcet_ms| Task {
///     id: id.to_string(),
///     period: Duration::from_millis(period_ms),
///     deadline: Duration::from_millis(period_ms),
///     wcet: Duration::from_millis(wcet_ms),
///     priority: None,
/// };
/// let tasks = vec![task("fast", 10, 8), task("slow", 20, 5)];
/// let task_set = TaskSet { tasks, scheduler: SchedulerType::RateMonotonic };
///
/// let response_times = task_set.response_time_analysis()?;
/// let times: Vec<_> = response_times.iter().map(|time| time.response_time).collect();
/// let past = ResponseTime::ExceedsDeadline { lower_bound: Duration::from_millis(21) };
/// assert_eq!(times, [ResponseTime::Converged(Duration::from_millis(8)), past]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseTime {
	/// The recurrence converged on this time, within the deadline.
	Converged(Duration),
	/// The recurrence passed the deadline, so the task misses it.
	ExceedsDeadline {
		/// The first step of the recurrence past the deadline.
		lower_bound: Duration,
	},
	/// The recurrence spent its iteration budget before it converged.
	Inconclusive,
}

/// The detail of one violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskViolationDetail {
	/// The ID of the task, or `"system"` for a violation of the whole set.
	pub task_id: String,
	/// The message that describes the violation.
	pub message: String,
}

/// The errors of a schedulability analysis.
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum SchedulabilityError {
	/// An event has no period.
	#[error("Missing period for event: {0}")]
	MissingPeriod(String),
	/// The task set holds no task.
	#[error("Task set contains no tasks")]
	EmptyTaskSet,
	/// A task has a zero period.
	#[error("Task `{task}` has a zero period")]
	ZeroPeriod { task: String },
	/// A task's deadline exceeds its period, and the analyses assume D <= T.
	#[error("Task `{task}` deadline exceeds its period (D <= T required)")]
	DeadlineExceedsPeriod { task: String },
	/// The task set names a scheduler other than a fixed-priority one, which
	/// response time analysis requires.
	#[error("Response time analysis requires a fixed-priority scheduler, got {scheduler}")]
	FixedPriorityRequired { scheduler: SchedulerType },
	/// A task declares no priority, and another task of the set declares
	/// one, so response time analysis has no order for the two.
	#[error("Task `{task}` declares no priority, and another task of the set declares one")]
	PriorityMissing { task: String },
}

impl TaskSet {
	/// Validates the structural preconditions that every analysis shares.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::EmptyTaskSet`] -- the set holds no task.
	/// - [`SchedulabilityError::ZeroPeriod`] -- a task has a period of zero.
	/// - [`SchedulabilityError::DeadlineExceedsPeriod`] -- a task has a deadline past its own period.
	fn validate(&self) -> Result<(), SchedulabilityError> {
		if self.tasks.is_empty() {
			return Err(SchedulabilityError::EmptyTaskSet);
		}

		for task in &self.tasks {
			if task.period.is_zero() {
				return Err(SchedulabilityError::ZeroPeriod { task: task.id.clone() });
			}
			if task.deadline > task.period {
				return Err(SchedulabilityError::DeadlineExceedsPeriod { task: task.id.clone() });
			}
		}

		Ok(())
	}

	/// The total utilization Σ(Ci/Ti).
	///
	/// The sum reads the periods directly, so [`Self::validate`] runs first.
	fn utilization(&self) -> f64 {
		self.tasks.iter().map(|t| t.wcet.as_secs_f64() / t.period.as_secs_f64()).sum()
	}

	/// This set in rate-monotonic order: a shorter period is a higher priority.
	fn by_rate(&self) -> TaskSet {
		let mut tasks = self.tasks.clone();
		tasks.sort_by(|a, b| a.period.cmp(&b.period));
		TaskSet { tasks, scheduler: self.scheduler }
	}

	/// This set in its declared fixed-priority order, lowest number first.
	/// Tasks of one priority keep the rate order, so a set that declares no
	/// priority takes the rate order.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::PriorityMissing`] -- one task declares a priority, and another declares none.
	fn by_priority(&self) -> Result<TaskSet, SchedulabilityError> {
		let undeclared = self.tasks.iter().find(|task| task.priority.is_none());
		let declares_any = self.tasks.iter().any(|task| task.priority.is_some());
		if let Some(task) = undeclared.filter(|_| declares_any) {
			return Err(SchedulabilityError::PriorityMissing { task: task.id.clone() });
		}

		let mut ranked = self.by_rate();
		ranked.tasks.sort_by_key(|task| task.priority);
		Ok(ranked)
	}

	/// The response time of each task, paired with the task, in the order of
	/// this set, highest priority first.
	fn response_times(self) -> Vec<TaskResponseTime> {
		let tasks = &self.tasks;
		let mut times = Vec::with_capacity(tasks.len());
		for (i, task) in tasks.iter().enumerate() {
			let higher_priority = tasks.get(..i).unwrap_or_default();
			times.push(task.response_time(higher_priority));
		}

		let timed = self.tasks.into_iter().zip(times);
		let response_times = timed.map(|(task, response_time)| TaskResponseTime { task, response_time });
		response_times.collect()
	}

	/// Rate Monotonic Analysis (RMA) schedulability test.
	///
	/// The Liu & Layland utilization bound Σ(Ci/Ti) ≤ n(2^(1/n) - 1) is
	/// *sufficient only* and assumes implicit deadlines (D = T):
	/// - A task set at or below the bound is schedulable.
	/// - A task set above the bound *may* be schedulable too.
	/// - Above the bound, or for a constrained deadline D < T, the recurrence of
	///   [`Self::response_time_analysis`] decides, in the rate order.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::EmptyTaskSet`] -- the set holds no task.
	/// - [`SchedulabilityError::ZeroPeriod`] -- a task has a period of zero.
	/// - [`SchedulabilityError::DeadlineExceedsPeriod`] -- a task has a deadline past its own period.
	pub fn is_rm_schedulable(&self) -> Result<SchedulabilityResult, SchedulabilityError> {
		self.validate()?;

		let scheduler = SchedulerType::RateMonotonic;
		let utilization = self.utilization();

		let n = self.tasks.len() as f64;
		let utilization_bound = if n == 1.0 {
			1.0
		} else {
			n * (2f64.powf(1.0 / n) - 1.0)
		};

		let implicit_deadlines = self.tasks.iter().all(|t| t.deadline == t.period);
		if implicit_deadlines && utilization <= utilization_bound {
			return Ok(SchedulabilityResult {
				scheduler,
				is_schedulable: true,
				utilization,
				utilization_bound,
				violations: Vec::new(),
			});
		}

		let violations = self.rta_violations();
		let is_schedulable = violations.is_empty();

		Ok(SchedulabilityResult { scheduler, is_schedulable, utilization, utilization_bound, violations })
	}

	/// Runs RTA in the rate order, which RMA assumes, and collects each task's
	/// deadline miss or non-convergence.
	fn rta_violations(&self) -> Vec<TaskViolationDetail> {
		let response_times = self.by_rate().response_times();
		response_times.iter().filter_map(TaskResponseTime::violation).collect()
	}

	/// Earliest Deadline First (EDF) schedulability test.
	///
	/// The utilization bound is Σ(Ci/Ti) ≤ 1. It is exact (necessary and
	/// sufficient) for implicit deadlines (D = T), and necessary only for
	/// constrained deadlines (D < T).
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::EmptyTaskSet`] -- the set holds no task.
	/// - [`SchedulabilityError::ZeroPeriod`] -- a task has a period of zero.
	/// - [`SchedulabilityError::DeadlineExceedsPeriod`] -- a task has a deadline past its own period.
	pub fn is_edf_schedulable(&self) -> Result<SchedulabilityResult, SchedulabilityError> {
		self.validate()?;

		let scheduler = SchedulerType::EarliestDeadlineFirst;
		let utilization = self.utilization();
		let utilization_bound = 1.0;
		let is_schedulable = utilization <= utilization_bound;

		let mut violations = Vec::new();
		if !is_schedulable {
			violations.push(TaskViolationDetail {
				task_id: "system".to_string(),
				message: format!("Utilization {utilization} exceeds bound {utilization_bound}"),
			});
		}

		Ok(SchedulabilityResult { scheduler, is_schedulable, utilization, utilization_bound, violations })
	}

	/// Response Time Analysis, the exact fixed-priority test for D ≤ T.
	///
	/// It iterates R_i = C_i + Σ_{j∈hp(i)} ⌈R_i / T_j⌉ * C_j, where hp(i) is
	/// the set of tasks with a higher priority than task i. The recurrence of
	/// Joseph and Pandya holds for any fixed-priority order, so the analysis
	/// ranks the tasks by [`Task::priority`]. Each [`TaskResponseTime`] names
	/// its task, highest priority first.
	///
	/// # Errors
	///
	/// - [`SchedulabilityError::FixedPriorityRequired`] -- the task set names a
	///   dynamic-priority scheduler (EDF), because the recurrence models
	///   fixed-priority scheduling alone.
	/// - [`SchedulabilityError::EmptyTaskSet`] -- the set holds no task.
	/// - [`SchedulabilityError::ZeroPeriod`] -- a task has a period of zero.
	/// - [`SchedulabilityError::DeadlineExceedsPeriod`] -- a task has a deadline past its own period.
	/// - [`SchedulabilityError::PriorityMissing`] -- one task declares a priority, and another declares none.
	///
	/// # Sources
	///
	/// - Joseph & Pandya, "Finding Response Times in a Real-Time System", *The Computer Journal* 29(5), 1986
	pub fn response_time_analysis(&self) -> Result<Vec<TaskResponseTime>, SchedulabilityError> {
		if self.scheduler != SchedulerType::RateMonotonic {
			return Err(SchedulabilityError::FixedPriorityRequired { scheduler: self.scheduler });
		}

		self.validate()?;

		let ranked = self.by_priority()?;
		Ok(ranked.response_times())
	}
}

impl Task {
	/// Solves the RTA recurrence for this task against its higher-priority set.
	fn response_time(&self, higher_priority: impl AsRef<[Task]>) -> ResponseTime {
		let higher_priority = higher_priority.as_ref();
		const MAX_ITERATIONS: u32 = 1000;

		let mut r = self.wcet;
		let mut prev_r = Duration::ZERO;
		let mut iterations = 0;
		while r != prev_r {
			if r > self.deadline {
				// The recurrence never decreases, so a lower bound past the
				// deadline is a definite miss.
				return ResponseTime::ExceedsDeadline { lower_bound: r };
			}

			if iterations >= MAX_ITERATIONS {
				return ResponseTime::Inconclusive;
			}

			prev_r = r;
			iterations += 1;

			let mut interference = Duration::ZERO;
			for hp in higher_priority {
				// The validation refuses a zero period, and `div_ceil` in u128
				// nanoseconds keeps the preemption count exact.
				let preemptions = r.as_nanos().div_ceil(hp.period.as_nanos());
				let preemptions = u32::try_from(preemptions).unwrap_or(u32::MAX);
				interference = interference.saturating_add(hp.wcet.saturating_mul(preemptions));
			}

			r = self.wcet.saturating_add(interference);
		}

		ResponseTime::Converged(r)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// One case of the RMA and EDF schedulability tables.
	struct SchedulabilityTestCase {
		/// The task rows, each (id, period_ms, deadline_ms, wcet_ms, priority).
		tasks: &'static [(&'static str, u64, u64, u64, Option<u32>)],
		expected_schedulable: bool,
		expected_utilization: f64,
	}

	/// Each response time of `response_times` under the ID of its task.
	fn named(response_times: &[TaskResponseTime]) -> Vec<(&str, ResponseTime)> {
		let named = response_times.iter().map(|time| (time.task.id.as_str(), time.response_time));
		named.collect()
	}

	/// A converged response time of `millis` milliseconds.
	fn converged(millis: u64) -> ResponseTime {
		ResponseTime::Converged(Duration::from_millis(millis))
	}

	/// Creates a [`TaskSet`] from the task rows.
	fn create_task_set_from_data(
		tasks_data: &[(&'static str, u64, u64, u64, Option<u32>)],
		scheduler: SchedulerType,
	) -> TaskSet {
		let tasks: Vec<Task> = tasks_data
			.iter()
			.map(|(id, period_ms, deadline_ms, wcet_ms, priority)| Task {
				id: id.to_string(),
				period: Duration::from_millis(*period_ms),
				deadline: Duration::from_millis(*deadline_ms),
				wcet: Duration::from_millis(*wcet_ms),
				priority: *priority,
			})
			.collect();

		TaskSet { tasks, scheduler }
	}

	// Each task set gets the rate-monotonic verdict and the utilization of its
	// row.
	crate::tb_cases! {
		fn rm_schedulability(case: SchedulabilityTestCase) -> Result<(), SchedulabilityError> {
			let task_set = create_task_set_from_data(case.tasks, SchedulerType::RateMonotonic);
			let result = task_set.is_rm_schedulable()?;
			assert_eq!(result.is_schedulable, case.expected_schedulable);
			assert!((result.utilization - case.expected_utilization).abs() < 0.01);
			Ok(())
		}

		cases {
			// Utilization: 3/10 + 5/20 = 0.3 + 0.25 = 0.55
			// Bound for n=2: 2*(2^(1/2) - 1) ≈ 0.828
			// 0.55 < 0.828, so the L&L bound proves the set schedulable.
			under_the_utilization_bound => SchedulabilityTestCase {
				tasks: &[("T1", 10, 10, 3, Some(1)), ("T2", 20, 20, 5, Some(2))],
				expected_schedulable: true,
				expected_utilization: 0.55,
			},
			// Utilization: 8/10 + 5/20 = 0.8 + 0.25 = 1.05 > bound ≈ 0.828
			// RTA decides: R1 = 8 <= 10, but R2 passes its 20ms deadline
			// (5 + ⌈13/10⌉*8 = 21), so the set is not schedulable.
			past_a_deadline => SchedulabilityTestCase {
				tasks: &[("T1", 10, 10, 8, Some(1)), ("T2", 20, 20, 5, Some(2))],
				expected_schedulable: false,
				expected_utilization: 1.05,
			},
			// Utilization: 1/2 + 1/4 + 2/8 = 1.0 > bound for n=3 ≈ 0.780,
			// yet RTA proves the harmonic set schedulable:
			// R1 = 1 <= 2, R2 = 2 <= 4, R3 = 8 <= 8
			harmonic_past_the_utilization_bound => SchedulabilityTestCase {
				tasks: &[("T1", 2, 2, 1, Some(1)), ("T2", 4, 4, 1, Some(2)), ("T3", 8, 8, 2, Some(3))],
				expected_schedulable: true,
				expected_utilization: 1.0,
			},
			// A constrained deadline (D < T) bypasses the L&L bound even at a
			// low utilization. RTA: R1 = 3 <= 4, R2 = 5 + ⌈5/10⌉*3 = 8 <= 15
			constrained_deadline => SchedulabilityTestCase {
				tasks: &[("T1", 10, 4, 3, Some(1)), ("T2", 20, 15, 5, Some(2))],
				expected_schedulable: true,
				expected_utilization: 0.55,
			},
		}
	}

	// Each task set gets the EDF verdict and the utilization of its row. The
	// EDF bound is a utilization of 1.0.
	crate::tb_cases! {
		fn edf_schedulability(case: SchedulabilityTestCase) -> Result<(), SchedulabilityError> {
			let task_set = create_task_set_from_data(case.tasks, SchedulerType::EarliestDeadlineFirst);
			let result = task_set.is_edf_schedulable()?;
			assert_eq!(result.is_schedulable, case.expected_schedulable);
			assert!((result.utilization - case.expected_utilization).abs() < 0.01);
			Ok(())
		}

		cases {
			// Utilization: 3/10 + 5/20 = 0.3 + 0.25 = 0.55
			at_55_percent_utilization => SchedulabilityTestCase {
				tasks: &[("T1", 10, 10, 3, None), ("T2", 20, 20, 5, None)],
				expected_schedulable: true,
				expected_utilization: 0.55,
			},
			// Utilization: 6/10 + 5/20 = 0.6 + 0.25 = 0.85
			at_85_percent_utilization => SchedulabilityTestCase {
				tasks: &[("T1", 10, 10, 6, None), ("T2", 20, 20, 5, None)],
				expected_schedulable: true,
				expected_utilization: 0.85,
			},
			// Utilization: 7/10 + 5/20 = 0.7 + 0.25 = 0.95
			at_95_percent_utilization => SchedulabilityTestCase {
				tasks: &[("T1", 10, 10, 7, None), ("T2", 20, 20, 5, None)],
				expected_schedulable: true,
				expected_utilization: 0.95,
			},
			// Utilization: 8/10 + 5/20 = 0.8 + 0.25 = 1.05 > 1.0
			past_full_utilization => SchedulabilityTestCase {
				tasks: &[("T1", 10, 10, 8, None), ("T2", 20, 20, 5, None)],
				expected_schedulable: false,
				expected_utilization: 1.05,
			},
		}
	}

	// T1 (higher priority): R1 = C1 = 3ms
	// T2 (lower priority): R2 = C2 + ⌈R2/T1⌉ * C1
	// Iteration: R2 = 5 + ⌈5/10⌉ * 3 = 5 + 1 * 3 = 8
	// R2 = 5 + ⌈8/10⌉ * 3 = 5 + 1 * 3 = 8 (converged)
	#[test]
	fn test_response_time_analysis() -> Result<(), SchedulabilityError> {
		let tasks = [("T1", 10, 10, 3, Some(1)), ("T2", 20, 20, 5, Some(2))];
		let task_set = create_task_set_from_data(&tasks, SchedulerType::RateMonotonic);

		let response_times = task_set.response_time_analysis()?;
		let expected = [("T1", converged(3)), ("T2", converged(8))];
		assert_eq!(named(&response_times), expected);
		Ok(())
	}

	// R2 steps through 5, 13, and 21 ms, and 21 ms passes its 20 ms deadline.
	#[test]
	fn a_task_past_its_deadline_reports_a_lower_bound() -> Result<(), SchedulabilityError> {
		let tasks = [("T1", 10, 10, 8, Some(1)), ("T2", 20, 20, 5, Some(2))];
		let task_set = create_task_set_from_data(&tasks, SchedulerType::RateMonotonic);

		let response_times = task_set.response_time_analysis()?;
		let past = ResponseTime::ExceedsDeadline { lower_bound: Duration::from_millis(21) };
		assert_eq!(named(&response_times), [("T1", converged(8)), ("T2", past)]);
		Ok(())
	}

	// T2 declares the higher priority, so it runs first: R2 = C2 = 5ms.
	// T1: R1 = 3 + ⌈3/20⌉ * 5 = 8, and R1 = 3 + ⌈8/20⌉ * 5 = 8 (converged)
	#[test]
	fn response_time_analysis_ranks_the_tasks_by_declared_priority() -> Result<(), SchedulabilityError> {
		let tasks = [("T1", 10, 10, 3, Some(2)), ("T2", 20, 20, 5, Some(1))];
		let task_set = create_task_set_from_data(&tasks, SchedulerType::RateMonotonic);

		let response_times = task_set.response_time_analysis()?;
		let expected = [("T2", converged(5)), ("T1", converged(8))];
		assert_eq!(named(&response_times), expected);
		Ok(())
	}

	// The declared priorities reverse the rate order. RMA ranks by rate, and
	// R1 = 1 <= 2, R2 = 2 <= 4, and R3 = 8 <= 8 prove the set schedulable.
	// The declared order would give R1 = 1 + ⌈1/8⌉ * 2 + ⌈1/4⌉ * 1 = 4 > 2.
	#[test]
	fn rate_monotonic_analysis_ranks_the_tasks_by_rate() -> Result<(), SchedulabilityError> {
		let tasks = [("T1", 2, 2, 1, Some(3)), ("T2", 4, 4, 1, Some(2)), ("T3", 8, 8, 2, Some(1))];
		let task_set = create_task_set_from_data(&tasks, SchedulerType::RateMonotonic);

		let result = task_set.is_rm_schedulable()?;
		assert!(result.is_schedulable);
		Ok(())
	}

	#[test]
	fn response_time_analysis_refuses_a_set_that_declares_some_priorities() -> Result<(), SchedulabilityError> {
		let tasks = [("T1", 10, 10, 3, Some(1)), ("T2", 20, 20, 5, None)];
		let task_set = create_task_set_from_data(&tasks, SchedulerType::RateMonotonic);

		let refused = task_set.response_time_analysis();
		assert_eq!(refused, Err(SchedulabilityError::PriorityMissing { task: "T2".to_string() }));
		Ok(())
	}

	#[test]
	fn test_rta_rejects_edf() {
		let task_set = create_task_set_from_data(&[("T1", 10, 10, 3, None)], SchedulerType::EarliestDeadlineFirst);
		assert!(matches!(
			task_set.response_time_analysis(),
			Err(SchedulabilityError::FixedPriorityRequired { scheduler: SchedulerType::EarliestDeadlineFirst })
		));
	}

	#[test]
	fn test_empty_task_set_rejected() {
		let task_set = TaskSet { tasks: Vec::new(), scheduler: SchedulerType::RateMonotonic };
		assert!(matches!(task_set.is_rm_schedulable(), Err(SchedulabilityError::EmptyTaskSet)));
	}

	#[test]
	fn test_zero_period_rejected() {
		let task_set = create_task_set_from_data(&[("T1", 0, 10, 3, Some(1))], SchedulerType::RateMonotonic);
		assert!(matches!(
			task_set.is_rm_schedulable(),
			Err(SchedulabilityError::ZeroPeriod { task }) if task == "T1"
		));
	}

	#[test]
	fn test_deadline_exceeding_period_rejected() {
		let task_set = create_task_set_from_data(&[("T1", 10, 20, 3, Some(1))], SchedulerType::RateMonotonic);
		assert!(matches!(
			task_set.is_rm_schedulable(),
			Err(SchedulabilityError::DeadlineExceedsPeriod { task }) if task == "T1"
		));
	}
}
