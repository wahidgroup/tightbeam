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
#[derive(Debug, Clone, PartialEq)]
pub enum SchedulabilityError {
	/// Missing period for an event
	MissingPeriod(String),
	/// Invalid task set (e.g., empty task set)
	InvalidTaskSet(String),
}

impl core::fmt::Display for SchedulabilityError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			SchedulabilityError::MissingPeriod(event) => {
				write!(f, "Missing period for event: {event}")
			}
			SchedulabilityError::InvalidTaskSet(msg) => {
				write!(f, "Invalid task set: {msg}")
			}
		}
	}
}

/// Calculate total utilization for a task set
///
/// Returns utilization as f64, or error if task set is invalid.
fn calculate_utilization(task_set: &TaskSet) -> Result<f64, SchedulabilityError> {
	if task_set.tasks.is_empty() {
		return Err(SchedulabilityError::InvalidTaskSet("Empty task set".to_string()));
	}

	let utilization: f64 = task_set
		.tasks
		.iter()
		.map(|t| {
			let ci = t.wcet.as_secs_f64();
			let ti = t.period.as_secs_f64();
			if ti == 0.0 {
				return f64::INFINITY;
			}
			ci / ti
		})
		.sum();

	Ok(utilization)
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
/// Utilization bound: Σ(Ci/Ti) ≤ n(2^(1/n) - 1)
/// where n = number of tasks, Ci = WCET, Ti = period
pub fn is_rm_schedulable(task_set: &TaskSet) -> Result<SchedulabilityResult, SchedulabilityError> {
	let scheduler = SchedulerType::RateMonotonic;
	let utilization = calculate_utilization(task_set)?;
	// Calculate utilization bound
	let n = task_set.tasks.len() as f64;
	let utilization_bound = if n == 1.0 {
		1.0
	} else {
		n * (2f64.powf(1.0 / n) - 1.0)
	};
	let is_schedulable = utilization <= utilization_bound;

	let mut violations = Vec::new();
	if !is_schedulable {
		violations.push(create_utilization_violation(utilization, utilization_bound));
	}

	Ok(SchedulabilityResult { scheduler, is_schedulable, utilization, utilization_bound, violations })
}

/// Earliest Deadline First (EDF) schedulability test
///
/// Utilization bound: Σ(Ci/Ti) ≤ 1
pub fn is_edf_schedulable(task_set: &TaskSet) -> Result<SchedulabilityResult, SchedulabilityError> {
	let scheduler = SchedulerType::EarliestDeadlineFirst;
	let utilization = calculate_utilization(task_set)?;
	let utilization_bound = 1.0;
	let is_schedulable = utilization <= utilization_bound;

	let mut violations = Vec::new();
	if !is_schedulable {
		violations.push(create_utilization_violation(utilization, utilization_bound));
	}

	Ok(SchedulabilityResult { scheduler, is_schedulable, utilization, utilization_bound, violations })
}

/// Response Time Analysis (exact schedulability test)
///
/// Iterative calculation: R_i = C_i + Σ_{j∈hp(i)} ⌈R_i / T_j⌉ * C_j
/// where hp(i) = tasks with higher priority than task i
///
/// Returns response times for each task (in order of priority, highest first).
pub fn response_time_analysis(task_set: &TaskSet) -> Result<Vec<Duration>, SchedulabilityError> {
	if task_set.tasks.is_empty() {
		return Err(SchedulabilityError::InvalidTaskSet("Empty task set".to_string()));
	}

	// Sort tasks by priority (highest first)
	// For RMA: shorter period = higher priority
	// For EDF: earlier deadline = higher priority
	let mut tasks = task_set.tasks.clone();
	match task_set.scheduler {
		SchedulerType::RateMonotonic => {
			tasks.sort_by(|a, b| {
				// Shorter period = higher priority
				a.period.cmp(&b.period)
			});
		}
		SchedulerType::EarliestDeadlineFirst => {
			tasks.sort_by(|a, b| {
				// Earlier deadline = higher priority
				a.deadline.cmp(&b.deadline)
			});
		}
	}

	let mut response_times = Vec::new();

	for (i, task) in tasks.iter().enumerate() {
		let mut r = task.wcet;
		let mut prev_r = Duration::ZERO;

		// Iterate until convergence or deadline exceeded
		let max_iterations = 1000;
		let mut iterations = 0;
		while r != prev_r && r <= task.deadline && iterations < max_iterations {
			prev_r = r;
			iterations += 1;

			// Calculate interference from higher priority tasks
			let mut interference = Duration::ZERO;
			for higher_priority_task in &tasks[..i] {
				let r_nanos = r.as_nanos() as f64;
				let t_nanos = higher_priority_task.period.as_nanos() as f64;
				if t_nanos > 0.0 {
					let ceil = (r_nanos / t_nanos).ceil() as u64;
					interference += higher_priority_task.wcet * ceil as u32;
				}
			}

			r = task.wcet + interference;
		}

		response_times.push(r);
	}

	Ok(response_times)
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
			assert_eq!(*actual, Duration::from_millis(*expected_ms));
		}

		Ok(())
	}

	const RMA_TEST_CASES: &[SchedulabilityTestCase] = &[
		SchedulabilityTestCase {
			// Utilization: 3/10 + 5/20 = 0.3 + 0.25 = 0.55
			// Bound for n=2: 2*(2^(1/2) - 1) ≈ 0.828
			// 0.55 < 0.828, so schedulable
			tasks: &[("T1", 10, 10, 3, Some(1)), ("T2", 20, 20, 5, Some(2))],
			scheduler: SchedulerType::RateMonotonic,
			expected_schedulable: true,
			expected_utilization: Some(0.55),
		},
		SchedulabilityTestCase {
			// Utilization: 8/10 + 5/20 = 0.8 + 0.25 = 1.05
			// Bound for n=2: 2*(2^(1/2) - 1) ≈ 0.828
			// 1.05 > 0.828, so not schedulable
			tasks: &[("T1", 10, 10, 8, Some(1)), ("T2", 20, 20, 5, Some(2))],
			scheduler: SchedulerType::RateMonotonic,
			expected_schedulable: false,
			expected_utilization: Some(1.05),
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
}
