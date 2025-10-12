#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "derive")]
use crate::Errorizable;

#[cfg(feature = "standards-rfc")]
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RFCError {
	#[cfg(feature = "standards-rfc")]
	#[cfg_attr(feature = "derive", error("{0}"))]
	#[cfg_attr(feature = "derive", from)]
	RFC5424Error(crate::standards::rfc::rfc5424::RFC5424Error),
}

#[cfg(feature = "standards-iso")]
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ISOError {
	#[cfg_attr(feature = "derive", error("ISO error: {0}"))]
	Message(String),
}

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
	#[cfg_attr(feature = "derive", error("{0}"))]
	#[cfg_attr(feature = "derive", from)]
	RFC(RFCError),
	#[cfg_attr(feature = "derive", error("{0}"))]
	#[cfg_attr(feature = "derive", from)]
	ISO(ISOError),
}

#[cfg(not(feature = "derive"))]
impl From<RFCError> for StandardError {
	fn from(e: RFCError) -> Self {
		StandardError::RFC(e)
	}
}

#[cfg(not(feature = "derive"))]
impl From<ISOError> for StandardError {
	fn from(e: ISOError) -> Self {
		StandardError::ISO(e)
	}
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for RFCError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			RFCError::InvalidSeverityValue(v) => write!(f, "invalid RFC5424 severity value: {v}"),
			RFCError::InvalidSeverityName(s) => write!(f, "invalid RFC5424 severity name: {s}"),
			RFCError::Der(e) => write!(f, "DER error: {e}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for ISOError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			ISOError::Message(s) => write!(f, "ISO error: {s}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for StandardError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			StandardError::RFC(e) => write!(f, "{e}"),
			StandardError::ISO(e) => write!(f, "{e}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for RFCError {}
#[cfg(not(feature = "derive"))]
impl core::error::Error for ISOError {}
#[cfg(not(feature = "derive"))]
impl core::error::Error for StandardError {}
