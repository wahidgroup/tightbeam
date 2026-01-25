#[cfg(feature = "derive")]
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
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum TestingError {
	#[cfg_attr(feature = "derive", error("Fuzz input exhausted"))]
	FuzzInputExhausted,
	#[cfg_attr(feature = "derive", error("Fuzz input unavailable"))]
	FuzzInputUnavailable,
	#[cfg_attr(feature = "derive", error("Fuzz input lock poisoned"))]
	FuzzInputLockPoisoned,
	#[cfg_attr(feature = "derive", error("Invalid timing constraint configuration"))]
	InvalidTimingConstraint,
	#[cfg_attr(feature = "derive", error("Slack exceeds deadline duration"))]
	InvalidSlack,
	#[cfg_attr(feature = "derive", error("Invalid FDR configuration: {0}"))]
	InvalidFdrConfig(FdrConfigError),
	#[cfg_attr(feature = "derive", error("Invalid fault model configuration"))]
	InvalidFaultModel,
	#[cfg_attr(feature = "derive", error("Schedulability violation: {0}"))]
	SchedulabilityViolation(SchedulabilityViolationDetail),
}

crate::impl_error_display!(TestingError {
	FuzzInputExhausted => "Fuzz input exhausted",
	FuzzInputUnavailable => "Fuzz input unavailable",
	FuzzInputLockPoisoned => "Fuzz input lock poisoned",
	InvalidTimingConstraint => "Invalid timing constraint configuration",
	InvalidSlack => "Slack exceeds deadline duration",
	InvalidFdrConfig(detail) => "Invalid FDR configuration: {detail}",
	InvalidFaultModel => "Invalid fault model configuration",
	SchedulabilityViolation(detail) => "Schedulability violation: {detail}",
});

#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for TestingError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		TestingError::FuzzInputLockPoisoned
	}
}
