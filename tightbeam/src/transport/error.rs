use crate::policy::TransitStatus;
#[cfg(feature = "derive")]
use crate::Errorizable;

/// Transport error types
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug)]
pub enum TransportError {
	#[cfg_attr(feature = "derive", error("Connection failed"))]
	ConnectionFailed,
	#[cfg_attr(feature = "derive", error("Send failed"))]
	SendFailed,
	#[cfg_attr(feature = "derive", error("Receive failed"))]
	ReceiveFailed,
	#[cfg_attr(feature = "derive", error("Timeout"))]
	Timeout,
	#[cfg_attr(feature = "derive", error("Busy"))]
	Busy,
	#[cfg_attr(feature = "derive", error("Unauthorized"))]
	Unauthorized,
	#[cfg_attr(feature = "derive", error("Forbidden"))]
	Forbidden,
	#[cfg_attr(feature = "derive", error("Invalid message"))]
	InvalidMessage,
	#[cfg_attr(feature = "derive", error("Invalid reply"))]
	InvalidReply,
	#[cfg_attr(feature = "derive", error("Missing request"))]
	MissingRequest,
	#[cfg_attr(feature = "derive", error("Max retries exceeded"))]
	MaxRetriesExceeded,
	#[cfg_attr(feature = "derive", error("DER error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	DerError(der::Error),
	#[cfg(feature = "std")]
	#[cfg_attr(feature = "derive", error("I/O error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	IoError(std::io::Error),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for TransportError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{self:?}")
	}
}

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

#[cfg(not(feature = "derive"))]
impl core::error::Error for TransportError {}

#[cfg(all(feature = "std", not(feature = "derive")))]
crate::impl_from!(std::io::Error => TransportError::IoError);
