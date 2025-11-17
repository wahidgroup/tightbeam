#[cfg(feature = "derive")]
use crate::Errorizable;

pub type Result<T> = core::result::Result<T, TestingError>;

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
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for TestingError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{self:?}")
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for TestingError {}
