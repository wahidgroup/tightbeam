use crate::Errorizable;

pub type Result<T> = core::result::Result<T, TestingError>;

/// FDR configuration error details
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdrConfigError {
	pub field: &'static str,
	pub reason: &'static str,
}

impl core::fmt::Display for FdrConfigError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "Invalid FDR config field '{}': {}", self.field, self.reason)
	}
}

/// Schedulability violation details
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulabilityViolationDetail {
	pub task_id: &'static str,
	pub message: &'static str,
	pub utilization: Option<f64>,
	pub deadline_miss: Option<core::time::Duration>,
}

impl core::fmt::Display for SchedulabilityViolationDetail {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "Task '{}': {}", self.task_id, self.message)?;

		if let Some(u) = self.utilization {
			write!(f, " (utilization: {u:.3})")?;
		}
		if let Some(d) = self.deadline_miss {
			write!(f, " (deadline miss: {d:?})")?;
		}

		Ok(())
	}
}

/// Testing error types
#[derive(Debug, Errorizable)]
pub enum TestingError {
	#[error("Fuzz input exhausted")]
	FuzzInputExhausted,
	#[error("Fuzz oracle deadlock in state {0}")]
	FuzzDeadlock(&'static str),
	#[error("Fuzz oracle rejected event {0}")]
	FuzzEventRejected(&'static str),
	#[error("Fuzz input unavailable")]
	FuzzInputUnavailable,
	#[error("Fuzz input lock poisoned")]
	FuzzInputLockPoisoned,
	#[error("Invalid timing constraint configuration")]
	InvalidTimingConstraint,
	#[error("Slack exceeds deadline duration")]
	InvalidSlack,
	#[error("Invalid FDR configuration: {0}")]
	InvalidFdrConfig(FdrConfigError),
	#[error("Invalid fault model configuration")]
	InvalidFaultModel,
	#[error("Schedulability violation: {0}")]
	SchedulabilityViolation(SchedulabilityViolationDetail),
	#[error("Invariant violated")]
	InvariantViolated,
}

#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for TestingError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		TestingError::FuzzInputLockPoisoned
	}
}
