use crate::error::TightBeamError;
use crate::transport::TransitStatus;

/// Transport error types
#[derive(Debug)]
pub enum TransportError {
	ConnectionFailed,
	SendFailed,
	ReceiveFailed,
	Timeout,
	Busy,
	Unauthorized,
	Forbidden,
	InvalidMessage,
	InvalidReply,
	MissingRequest,
	MaxRetriesExceeded,
	TightBeamError(TightBeamError),
	#[cfg(feature = "std")]
	IoError(std::io::Error),
}

impl core::fmt::Display for TransportError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{self:?}")
	}
}

crate::impl_from!(TightBeamError => TransportError::TightBeamError);

#[cfg(feature = "std")]
crate::impl_from!(std::io::Error => TransportError::IoError);

impl From<TransitStatus> for TransportError {
	fn from(status: TransitStatus) -> Self {
		match status {
			TransitStatus::Request => TransportError::InvalidMessage,
			TransitStatus::Accepted => TransportError::InvalidMessage,
			TransitStatus::Busy => TransportError::Busy,
			TransitStatus::Unauthorized => TransportError::Unauthorized,
			TransitStatus::Forbidden => TransportError::Forbidden,
			TransitStatus::Timeout => TransportError::Timeout,
		}
	}
}

impl core::error::Error for TransportError {}
