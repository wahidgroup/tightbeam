use crate::Errorizable;

#[cfg(feature = "testing-timing")]
use crate::error::TightBeamError;
#[cfg(feature = "testing-timing")]
use crate::testing::specs::Event;
#[cfg(feature = "testing-timing")]
use crate::testing::timing::Percentile;

pub type Result<T> = core::result::Result<T, TestingError>;

/// The field of an FDR configuration that breaks a rule, and the rule it
/// breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdrConfigError {
	/// The field that breaks the rule.
	pub field: &'static str,
	/// The rule that the field breaks.
	pub reason: &'static str,
}

impl core::fmt::Display for FdrConfigError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "Invalid FDR config field '{}': {}", self.field, self.reason)
	}
}

impl core::error::Error for FdrConfigError {}

/// The details of a schedulability violation: the task, a message, and the
/// utilization or the deadline miss that the check measured.
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

/// An error of the testing surface.
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
	/// A panic that held a lock of the testing surface poisoned the lock.
	///
	/// [`From<PoisonError>`](std::sync::PoisonError) produces it for every
	/// lock, and [`Self::FuzzInputLockPoisoned`] names the fuzz cursor alone.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Mutex;
	///
	/// use tightbeam::testing::error::TestingError;
	///
	/// let lock = Mutex::new(0u8);
	/// let poisoned = std::panic::catch_unwind(|| {
	///     let _held = lock.lock();
	///     panic!("poison the lock");
	/// });
	/// assert!(poisoned.is_err());
	///
	/// let refused = lock.lock().map(|_| ()).map_err(TestingError::from);
	/// assert!(matches!(refused, Err(TestingError::LockPoisoned)));
	/// ```
	#[error("A lock of the testing surface is poisoned")]
	LockPoisoned,
	#[error("Invalid timing constraint configuration")]
	InvalidTimingConstraint,
	#[error("Slack exceeds deadline duration")]
	InvalidSlack,
	/// The event holds a WCET or jitter constraint that disagrees with the
	/// one added.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::TestingError;
	/// use tightbeam::testing::specs::csp::Event;
	///
	/// let refused = TestingError::ConflictingTimingConstraint(Event("send"));
	/// assert_eq!(refused.to_string(), "Event send holds a timing constraint that disagrees with the one added");
	/// ```
	#[cfg(feature = "testing-timing")]
	#[error("Event {0} holds a timing constraint that disagrees with the one added")]
	ConflictingTimingConstraint(Event),
	/// The trace holds fewer events than its run emitted, so it decides no
	/// timing bound.
	#[cfg(feature = "testing-timing")]
	#[error("The trace holds a truncated record, which decides no timing bound")]
	TimingRecordIncomplete,
	/// A timing record of a constrained event carries no measure: a run of
	/// an event under a WCET or jitter bound with no duration, or a deadline
	/// marker with no timestamp. A trace holds durations only when its
	/// instrumentation config sets `record_durations`.
	#[cfg(feature = "testing-timing")]
	#[error("The timing record {seq} of event {event} carries no measure")]
	TimingSampleUnmeasured {
		/// The event of the record.
		event: Event,
		/// The sequence number of the record.
		seq: u64,
	},
	/// A deadline start marker has no end marker after it, so the window it
	/// opens has no latency.
	#[cfg(feature = "testing-timing")]
	#[error("The deadline window that record {seq} of event {start} opens has no {end} after it")]
	DeadlineUnterminated {
		/// The start event of the deadline.
		start: Event,
		/// The end event of the deadline.
		end: Event,
		/// The sequence number of the start marker.
		seq: u64,
	},
	/// The analyzer of a percentile WCET bound failed on the samples of its
	/// event. The cause sits in a box, because a `TightBeamError` can hold a
	/// `TestingError`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::TestingError;
	/// use tightbeam::testing::specs::csp::Event;
	/// use tightbeam::TightBeamError;
	///
	/// let cause = Box::new(TightBeamError::MissingConfiguration);
	/// let refused = TestingError::WcetAnalysisFailed { event: Event("send"), cause };
	/// assert!(refused.to_string().starts_with("The analyzer of the WCET bound on event send failed"));
	/// ```
	#[cfg(feature = "testing-timing")]
	#[error("The analyzer of the WCET bound on event {event} failed: {cause}")]
	WcetAnalysisFailed {
		/// The event of the bound.
		event: Event,
		/// The error of the analyzer.
		cause: Box<TightBeamError>,
	},
	/// The analyzer of a percentile WCET bound gave no value for that
	/// percentile.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::TestingError;
	/// use tightbeam::testing::specs::csp::Event;
	/// use tightbeam::testing::timing::Percentile;
	///
	/// let refused = TestingError::WcetPercentileMissing { event: Event("send"), percentile: Percentile::P99 };
	/// assert_eq!(refused.to_string(), "The analyzer of the WCET bound on event send gave no P99 value");
	/// ```
	#[cfg(feature = "testing-timing")]
	#[error("The analyzer of the WCET bound on event {event} gave no {percentile:?} value")]
	WcetPercentileMissing {
		/// The event of the bound.
		event: Event,
		/// The percentile of the bound.
		percentile: Percentile,
	},
	/// The calculator of a jitter bound failed on the samples of its event.
	/// The cause sits in a box, because a `TightBeamError` can hold a
	/// `TestingError`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::TestingError;
	/// use tightbeam::testing::specs::csp::Event;
	/// use tightbeam::TightBeamError;
	///
	/// let cause = Box::new(TightBeamError::MissingConfiguration);
	/// let refused = TestingError::JitterCalculationFailed { event: Event("send"), cause };
	/// assert!(refused.to_string().starts_with("The jitter calculator of the bound on event send failed"));
	/// ```
	#[cfg(feature = "testing-timing")]
	#[error("The jitter calculator of the bound on event {event} failed: {cause}")]
	JitterCalculationFailed {
		/// The event of the bound.
		event: Event,
		/// The error of the calculator.
		cause: Box<TightBeamError>,
	},
	/// A test harness observed an outcome that its scenario rules out, for
	/// the stated reason.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::TestingError;
	///
	/// let refused = TestingError::UnexpectedOutcome("the peer accepted a forged frame");
	/// assert_eq!(refused.to_string(), "Unexpected outcome: the peer accepted a forged frame");
	/// ```
	#[error("Unexpected outcome: {0}")]
	UnexpectedOutcome(&'static str),
	/// A test harness names a step at `index` that the flow under test lacks.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::TestingError;
	///
	/// let refused = TestingError::UnknownFlowStep(7);
	/// assert_eq!(refused.to_string(), "The flow under test has no step 7");
	/// ```
	#[error("The flow under test has no step {0}")]
	UnknownFlowStep(usize),
	#[error("Invalid fault model configuration")]
	InvalidFaultModel,
	#[error("Schedulability violation: {0}")]
	SchedulabilityViolation(SchedulabilityViolationDetail),
	#[error("Invariant violated")]
	InvariantViolated,
	/// An FDR configuration that breaks a rule of the run, such as a scheduler
	/// constraint that does not fit the process under verification.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::error::{FdrConfigError, TestingError};
	///
	/// let refused = TestingError::from(FdrConfigError { field: "seeds", reason: "must be positive" });
	/// assert_eq!(refused.to_string(), "Invalid FDR config field 'seeds': must be positive");
	/// ```
	#[error("{0}")]
	FdrConfig(FdrConfigError),
}

impl From<FdrConfigError> for TestingError {
	fn from(error: FdrConfigError) -> Self {
		TestingError::FdrConfig(error)
	}
}

impl From<FdrConfigError> for crate::error::TightBeamError {
	fn from(error: FdrConfigError) -> Self {
		crate::error::TightBeamError::TestingError(TestingError::FdrConfig(error))
	}
}

#[cfg(feature = "std")]
impl<T> From<std::sync::PoisonError<T>> for TestingError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		TestingError::LockPoisoned
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Mutex;

	use super::TestingError;
	use crate::testing::fixtures::poison;

	/// A lock that a panic poisoned outside the fuzz cursor reads as
	/// `LockPoisoned`.
	#[test]
	fn a_poisoned_lock_outside_the_fuzz_cursor_reads_as_lock_poisoned() {
		let lock = Mutex::new(0u8);
		poison(&lock);

		let refused = lock.lock().map(|_| ()).map_err(TestingError::from);
		assert!(matches!(refused, Err(TestingError::LockPoisoned)));
	}
}
