//! Cluster-specific error types

/// Errors specific to clusters
#[cfg_attr(feature = "derive", derive(crate::Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterError {
	/// Lock poisoned
	#[cfg_attr(feature = "derive", error("Lock poisoned"))]
	LockPoisoned,
	/// Unknown servlet type
	#[cfg_attr(feature = "derive", error("Unknown servlet type: {:#?}"))]
	UnknownServletType(Vec<u8>),
	/// No hives available for servlet type
	#[cfg_attr(feature = "derive", error("No hives available for servlet type: {:#?}"))]
	NoHivesAvailable(Vec<u8>),
	/// Hive communication failed
	#[cfg_attr(feature = "derive", error("Hive communication failed: {:#?}"))]
	HiveCommunicationFailed(Vec<u8>),
	/// Registration failed
	#[cfg_attr(feature = "derive", error("Registration failed"))]
	RegistrationFailed,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for ClusterError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ClusterError::LockPoisoned => write!(f, "Lock poisoned"),
			ClusterError::UnknownServletType(t) => {
				write!(f, "Unknown servlet type: {}", String::from_utf8_lossy(t))
			}
			ClusterError::NoHivesAvailable(t) => {
				write!(f, "No hives available for servlet type: {}", String::from_utf8_lossy(t))
			}
			ClusterError::HiveCommunicationFailed(msg) => {
				write!(f, "Hive communication failed: {}", String::from_utf8_lossy(msg))
			}
			ClusterError::RegistrationFailed => write!(f, "Registration failed"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for ClusterError {}

impl<T> From<std::sync::PoisonError<T>> for ClusterError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		ClusterError::LockPoisoned
	}
}
