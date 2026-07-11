//! Schedulability analysis for real-time systems
//!
//! Provides schedulability tests for real-time task sets:
//! - Rate Monotonic Analysis (RMA)
//! - Earliest Deadline First (EDF)
//! - Response Time Analysis (exact test)

use core::time::Duration;

/// Real-time task model
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
	/// Task identifier
	pub id: String,
	/// T - task period
	pub period: Duration,
	/// D - relative deadline
	pub deadline: Duration,
	/// C - worst-case execution time
	pub wcet: Duration,
	/// Priority (for RMA: rate monotonic priority)
	pub priority: Option<u32>,
}

/// Task set for schedulability analysis
#[derive(Debug, Clone, PartialEq)]
pub struct TaskSet {
	/// Tasks in the set
	pub tasks: Vec<Task>,
	/// Scheduler type
	pub scheduler: SchedulerType,
}

/// Scheduler type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerType {
	/// Rate Monotonic Scheduling
	RateMonotonic,
	/// Earliest Deadline First
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

/// Schedulability result
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulabilityResult {
	/// Scheduler type used for analysis
	pub scheduler: SchedulerType,
	/// Whether the task set is schedulable
	pub is_schedulable: bool,
	/// Total utilization (Σ(Ci/Ti))
	pub utilization: f64,
	/// Utilization bound for the scheduler
	pub utilization_bound: f64,
	/// Violations (if any)
	pub violations: Vec<TaskViolationDetail>,
}

/// Per-task violation detail
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskViolationDetail {
	/// Task ID (or "system" for system-level violations)
	pub task_id: String,
	/// Violation message
	pub message: String,
}

/// Schedulability error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulabilityError {
	/// Missing period for an event
	MissingPeriod(String),
	/// Task set contains no tasks
	EmptyTaskSet,
	/// Task has a zero period
	ZeroPeriod { task: String },
	/// Task deadline exceeds its period (analyses assume D <= T)
	DeadlineExceedsPeriod { task: String },
	/// Response time analysis requires a fixed-priority scheduler
	FixedPriorityRequired { scheduler: SchedulerType },
}

impl core::fmt::Display for SchedulabilityError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::MissingPeriod(event) => {
				write!(f, "Missing period for event: {event}")
			}
			Self::EmptyTaskSet => {
				write!(f, "Task set contains no tasks")
			}
			Self::ZeroPeriod { task } => {
				write!(f, "Task `{task}` has a zero period")
			}
			Self::DeadlineExceedsPeriod { task } => {
				write!(f, "Task `{task}` deadline exceeds its period (D <= T required)")
			}
			Self::FixedPriorityRequired { scheduler } => {
				write!(f, "Response time analysis requires a fixed-priority scheduler, got {scheduler}")
			}
		}
	}
}

impl core::error::Error for SchedulabilityError {}

/// Validate structural task-set preconditions shared by every analysis
fn validate_task_set(task_set: &TaskSet) -> Result<(), SchedulabilityError> {
	if task_set.tasks.is_empty() {
		return Err(SchedulabilityError::EmptyTaskSet);
	}

	for task in &task_set.tasks {
		if task.period.is_zero() {
			return Err(SchedulabilityError::ZeroPeriod { task: task.id.clone() });
		}

		if task.deadline > task.period {
			return Err(SchedulabilityError::DeadlineExceedsPeriod { task: task.id.clone() });
		}
	}

	Ok(())
}

/// Calculate total utilization Σ(Ci/Ti)
///
/// Callers must have validated the task set (non-empty, non-zero periods).
fn calculate_utilization(tasks: &[Task]) -> f64 {
	tasks.iter().map(|t| t.wcet.as_secs_f64() / t.period.as_secs_f64()).sum()
}

/// Clone tasks sorted rate-monotonically (shorter period = higher priority)
fn tasks_by_rate(task_set: &TaskSet) -> Vec<Task> {
	let mut tasks = task_set.tasks.clone();
	tasks.sort_by(|a, b| a.period.cmp(&b.period));
	tasks
}

/// Create violation message for utilization exceeding bound
fn create_utilization_violation(utilization: f64, bound: f64) -> TaskViolationDetail {
	TaskViolationDetail {
		task_id: "system".to_string(),
		message: format!("Utilization {utilization} exceeds bound {bound}"),
	}
}

/// Rate Monotonic Analysis (RMA) schedulability test
///
/// The Liu & Layland utilization bound Σ(Ci/Ti) ≤ n(2^(1/n) - 1) is
/// *sufficient only* and assumes implicit deadlines (D = T): task sets below
/// the bound are schedulable, but sets above it *may* still be schedulable.
/// When the bound is inconclusive (utilization above it, or constrained
/// deadlines D < T), [`response_time_analysis`] arbitrates.
pub fn is_rm_schedulable(task_set: &TaskSet) -> Result<SchedulabilityResult, SchedulabilityError> {
	validate_task_set(task_set)?;

	let scheduler = SchedulerType::RateMonotonic;
	let utilization = calculate_utilization(&task_set.tasks);

	let n = task_set.tasks.len() as f64;
	let utilization_bound = if n == 1.0 {
		1.0
	} else {
		n * (2f64.powf(1.0 / n) - 1.0)
	};

	let implicit_deadlines = task_set.tasks.iter().all(|t| t.deadline == t.period);
	if implicit_deadlines && utilization <= utilization_bound {
		return Ok(SchedulabilityResult {
			scheduler,
			is_schedulable: true,
			utilization,
			utilization_bound,
			violations: Vec::new(),
		});
	}

	let violations = rta_violations(task_set)?;
	let is_schedulable = violations.is_empty();

	Ok(SchedulabilityResult { scheduler, is_schedulable, utilization, utilization_bound, violations })
}

/// Run RTA and collect per-task deadline misses and non-convergence
fn rta_violations(task_set: &TaskSet) -> Result<Vec<TaskViolationDetail>, SchedulabilityError> {
	let tasks = tasks_by_rate(task_set);
	let response_times = response_time_analysis(task_set)?;

	let mut violations = Vec::new();
	for (task, response) in tasks.iter().zip(&response_times) {
		match response {
			Some(r) if *r <= task.deadline => {}
			Some(r) => violations.push(TaskViolationDetail {
				task_id: task.id.clone(),
				message: format!("Response time {r:?} exceeds deadline {:?}", task.deadline),
			}),
			None => violations.push(TaskViolationDetail {
				task_id: task.id.clone(),
				message: "Response time recurrence did not converge within iteration budget".to_string(),
			}),
		}
	}

	Ok(violations)
}

/// Earliest Deadline First (EDF) schedulability test
///
/// Utilization bound: Σ(Ci/Ti) ≤ 1. This test is exact (necessary and
/// sufficient) for implicit deadlines (D = T); for constrained deadlines
/// (D < T) it is necessary only.
pub fn is_edf_schedulable(task_set: &TaskSet) -> Result<SchedulabilityResult, SchedulabilityError> {
	validate_task_set(task_set)?;

	let scheduler = SchedulerType::EarliestDeadlineFirst;
	let utilization = calculate_utilization(&task_set.tasks);
	let utilization_bound = 1.0;
	let is_schedulable = utilization <= utilization_bound;

	let mut violations = Vec::new();
	if !is_schedulable {
		violations.push(create_utilization_violation(utilization, utilization_bound));
	}

	Ok(SchedulabilityResult { scheduler, is_schedulable, utilization, utilization_bound, violations })
}

/// Response Time Analysis (exact fixed-priority schedulability test, D ≤ T)
///
/// Iterative calculation: R_i = C_i + Σ_{j∈hp(i)} ⌈R_i / T_j⌉ * C_j
/// where hp(i) = tasks with higher priority than task i.
///
/// The recurrence only models fixed-priority scheduling, so dynamic-priority
/// schedulers (EDF) are rejected with
/// [`SchedulabilityError::FixedPriorityRequired`].
///
/// Returns per-task response times in rate-monotonic priority order
/// (shortest period first). `Some(r)` is the converged response time, or a
/// lower bound that already exceeds the task deadline (definitive miss).
/// `None` marks a recurrence that did not converge within the iteration
/// budget (inconclusive).
pub fn response_time_analysis(task_set: &TaskSet) -> Result<Vec<Option<Duration>>, SchedulabilityError> {
	if task_set.scheduler != SchedulerType::RateMonotonic {
		return Err(SchedulabilityError::FixedPriorityRequired { scheduler: task_set.scheduler });
	}

	validate_task_set(task_set)?;

	let tasks = tasks_by_rate(task_set);
	let mut response_times = Vec::with_capacity(tasks.len());
	for (i, task) in tasks.iter().enumerate() {
		response_times.push(task_response_time(task, &tasks[..i]));
	}

	Ok(response_times)
}

/// Solve the RTA recurrence for one task against its higher-priority set
fn task_response_time(task: &Task, higher_priority: &[Task]) -> Option<Duration> {
	const MAX_ITERATIONS: u32 = 1000;

	let mut r = task.wcet;
	let mut prev_r = Duration::ZERO;
	let mut iterations = 0;
	while r != prev_r {
		if r > task.deadline {
			// The recurrence is monotonically non-decreasing, so a lower
			// bound past the deadline is already a definitive miss.
			return Some(r);
		}

		if iterations >= MAX_ITERATIONS {
			return None;
		}

		prev_r = r;
		iterations += 1;

		let mut interference = Duration::ZERO;
		for hp in higher_priority {
			// Periods are validated non-zero; div_ceil in u128 nanoseconds
			// keeps the preemption count exact.
			let preemptions = r.as_nanos().div_ceil(hp.period.as_nanos());
			let preemptions = u32::try_from(preemptions).unwrap_or(u32::MAX);
			interference = interference.saturating_add(hp.wcet.saturating_mul(preemptions));
		}

		r = task.wcet.saturating_add(interference);
	}

	Some(r)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Test case for schedulability tests (RMA/EDF)
	struct SchedulabilityTestCase {
		/// Task data: (id, period_ms, deadline_ms, wcet_ms, priority)
		tasks: &'static [(&'static str, u64, u64, u64, Option<u32>)],
		scheduler: SchedulerType,
		expected_schedulable: bool,
		expected_utilization: Option<f64>,
	}

	/// Test case for response time analysis
	struct ResponseTimeTestCase {
		/// Task data: (id, period_ms, deadline_ms, wcet_ms, priority)
		tasks: &'static [(&'static str, u64, u64, u64, Option<u32>)],
		scheduler: SchedulerType,
		expected_response_times: &'static [u64], // in milliseconds
	}

	/// Helper to create TaskSet from task data
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

	/// Run RMA schedulability test case
	fn run_rm_test_case(case: &SchedulabilityTestCase) -> Result<(), SchedulabilityError> {
		let task_set = create_task_set_from_data(case.tasks, case.scheduler);
		let result = is_rm_schedulable(&task_set)?;

		assert_eq!(result.is_schedulable, case.expected_schedulable);
		if let Some(expected_util) = case.expected_utilization {
			assert!((result.utilization - expected_util).abs() < 0.01);
		}

		Ok(())
	}

	/// Run EDF schedulability test case
	fn run_edf_test_case(case: &SchedulabilityTestCase) -> Result<(), SchedulabilityError> {
		let task_set = create_task_set_from_data(case.tasks, case.scheduler);
		let result = is_edf_schedulable(&task_set)?;

		assert_eq!(result.is_schedulable, case.expected_schedulable);
		if let Some(expected_util) = case.expected_utilization {
			assert!((result.utilization - expected_util).abs() < 0.01);
		}

		Ok(())
	}

	/// Run response time analysis test case
	fn run_rta_test_case(case: &ResponseTimeTestCase) -> Result<(), SchedulabilityError> {
		let task_set = create_task_set_from_data(case.tasks, case.scheduler);
		let response_times = response_time_analysis(&task_set)?;

		assert_eq!(response_times.len(), case.expected_response_times.len());
		for (actual, expected_ms) in response_times.iter().zip(case.expected_response_times.iter()) {
			assert_eq!(*actual, Some(Duration::from_millis(*expected_ms)));
		}

		Ok(())
	}

	const RMA_TEST_CASES: &[SchedulabilityTestCase] = &[
		SchedulabilityTestCase {
			// Utilization: 3/10 + 5/20 = 0.3 + 0.25 = 0.55
			// Bound for n=2: 2*(2^(1/2) - 1) ≈ 0.828
			// 0.55 < 0.828, so schedulable via the L&L bound
			tasks: &[("T1", 10, 10, 3, Some(1)), ("T2", 20, 20, 5, Some(2))],
			scheduler: SchedulerType::RateMonotonic,
			expected_schedulable: true,
			expected_utilization: Some(0.55),
		},
		SchedulabilityTestCase {
			// Utilization: 8/10 + 5/20 = 0.8 + 0.25 = 1.05 > bound ≈ 0.828
			// RTA arbitrates: R1 = 8 <= 10, but R2 diverges past its
			// 20ms deadline (5 + ⌈13/10⌉*8 = 21), so not schedulable
			tasks: &[("T1", 10, 10, 8, Some(1)), ("T2", 20, 20, 5, Some(2))],
			scheduler: SchedulerType::RateMonotonic,
			expected_schedulable: false,
			expected_utilization: Some(1.05),
		},
		SchedulabilityTestCase {
			// Utilization: 1/2 + 1/4 + 2/8 = 1.0 > bound for n=3 ≈ 0.780,
			// yet RTA proves the harmonic set schedulable:
			// R1 = 1 <= 2, R2 = 2 <= 4, R3 = 8 <= 8
			// (bound is sufficient-only; above it is not a verdict)
			tasks: &[("T1", 2, 2, 1, Some(1)), ("T2", 4, 4, 1, Some(2)), ("T3", 8, 8, 2, Some(3))],
			scheduler: SchedulerType::RateMonotonic,
			expected_schedulable: true,
			expected_utilization: Some(1.0),
		},
		SchedulabilityTestCase {
			// Constrained deadline (D < T) bypasses the L&L bound even at
			// low utilization; RTA: R1 = 3 <= 4, R2 = 5 + ⌈5/10⌉*3 = 8 <= 15
			tasks: &[("T1", 10, 4, 3, Some(1)), ("T2", 20, 15, 5, Some(2))],
			scheduler: SchedulerType::RateMonotonic,
			expected_schedulable: true,
			expected_utilization: Some(0.55),
		},
	];

	const EDF_TEST_CASES: &[SchedulabilityTestCase] = &[
		SchedulabilityTestCase {
			// Utilization: 3/10 + 5/20 = 0.3 + 0.25 = 0.55
			// Bound: 1.0
			// 0.55 < 1.0, so schedulable
			tasks: &[("T1", 10, 10, 3, None), ("T2", 20, 20, 5, None)],
			scheduler: SchedulerType::EarliestDeadlineFirst,
			expected_schedulable: true,
			expected_utilization: Some(0.55),
		},
		SchedulabilityTestCase {
			// Utilization: 6/10 + 5/20 = 0.6 + 0.25 = 0.85
			// Bound: 1.0
			// 0.85 < 1.0, so schedulable
			tasks: &[("T1", 10, 10, 6, None), ("T2", 20, 20, 5, None)],
			scheduler: SchedulerType::EarliestDeadlineFirst,
			expected_schedulable: true,
			expected_utilization: Some(0.85),
		},
		SchedulabilityTestCase {
			// Utilization: 7/10 + 5/20 = 0.7 + 0.25 = 0.95
			// Bound: 1.0
			// 0.95 < 1.0, so schedulable
			tasks: &[("T1", 10, 10, 7, None), ("T2", 20, 20, 5, None)],
			scheduler: SchedulerType::EarliestDeadlineFirst,
			expected_schedulable: true,
			expected_utilization: Some(0.95),
		},
		SchedulabilityTestCase {
			// Utilization: 8/10 + 5/20 = 0.8 + 0.25 = 1.05
			// Bound: 1.0
			// 1.05 > 1.0, so not schedulable
			tasks: &[("T1", 10, 10, 8, None), ("T2", 20, 20, 5, None)],
			scheduler: SchedulerType::EarliestDeadlineFirst,
			expected_schedulable: false,
			expected_utilization: Some(1.05),
		},
	];

	const RTA_TEST_CASES: &[ResponseTimeTestCase] = &[ResponseTimeTestCase {
		// T1 (higher priority): R1 = C1 = 3ms
		// T2 (lower priority): R2 = C2 + ⌈R2/T1⌉ * C1
		// Iteration: R2 = 5 + ⌈5/10⌉ * 3 = 5 + 1 * 3 = 8
		// R2 = 5 + ⌈8/10⌉ * 3 = 5 + 1 * 3 = 8 (converged)
		tasks: &[("T1", 10, 10, 3, Some(1)), ("T2", 20, 20, 5, Some(2))],
		scheduler: SchedulerType::RateMonotonic,
		expected_response_times: &[3, 8],
	}];

	#[test]
	fn test_rm_schedulability() -> Result<(), SchedulabilityError> {
		for case in RMA_TEST_CASES {
			run_rm_test_case(case)?;
		}

		Ok(())
	}

	#[test]
	fn test_edf_schedulability() -> Result<(), SchedulabilityError> {
		for case in EDF_TEST_CASES {
			run_edf_test_case(case)?;
		}

		Ok(())
	}

	#[test]
	fn test_response_time_analysis() -> Result<(), SchedulabilityError> {
		for case in RTA_TEST_CASES {
			run_rta_test_case(case)?;
		}

		Ok(())
	}

	#[test]
	fn test_rta_rejects_edf() {
		let task_set = create_task_set_from_data(&[("T1", 10, 10, 3, None)], SchedulerType::EarliestDeadlineFirst);
		assert!(matches!(
			response_time_analysis(&task_set),
			Err(SchedulabilityError::FixedPriorityRequired { scheduler: SchedulerType::EarliestDeadlineFirst })
		));
	}

	#[test]
	fn test_empty_task_set_rejected() {
		let task_set = TaskSet { tasks: Vec::new(), scheduler: SchedulerType::RateMonotonic };
		assert!(matches!(is_rm_schedulable(&task_set), Err(SchedulabilityError::EmptyTaskSet)));
	}

	#[test]
	fn test_zero_period_rejected() {
		let task_set = create_task_set_from_data(&[("T1", 0, 10, 3, Some(1))], SchedulerType::RateMonotonic);
		assert!(matches!(
			is_rm_schedulable(&task_set),
			Err(SchedulabilityError::ZeroPeriod { task }) if task == "T1"
		));
	}

	#[test]
	fn test_deadline_exceeding_period_rejected() {
		let task_set = create_task_set_from_data(&[("T1", 10, 20, 3, Some(1))], SchedulerType::RateMonotonic);
		assert!(matches!(
			is_rm_schedulable(&task_set),
			Err(SchedulabilityError::DeadlineExceedsPeriod { task }) if task == "T1"
		));
	}
}
