//! Hive-specific error types

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to hives
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HiveError {
	/// Invalid servlet ID
	#[cfg_attr(feature = "derive", error("Invalid servlet ID: {:#?}"))]
	InvalidServletId(Vec<u8>),
	/// Transport/IO error (message stored as string since io::Error isn't Clone)
	#[cfg_attr(feature = "derive", error("IO error: {:#?}"))]
	Io(Vec<u8>),
	/// Message composition failed
	#[cfg_attr(feature = "derive", error("Message composition failed: {:#?}"))]
	ComposeFailed(Vec<u8>),
	/// Message emission failed
	#[cfg_attr(feature = "derive", error("Message emission failed"))]
	EmitFailed,
	/// No response received
	#[cfg_attr(feature = "derive", error("No response received"))]
	NoResponse,
	/// Message decoding failed
	#[cfg_attr(feature = "derive", error("Message decoding failed"))]
	DecodeFailed,
	/// Lock poisoned
	#[cfg_attr(feature = "derive", error("Lock poisoned"))]
	LockPoisoned,
	/// No trusted keys configured for ClusterSecurityGate
	#[cfg_attr(feature = "derive", error("No trusted keys configured"))]
	NoTrustedKeys,
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for HiveError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			HiveError::InvalidServletId(id) => write!(f, "Invalid servlet ID: {:#?}", id),
			HiveError::Io(msg) => write!(f, "IO error: {}", String::from_utf8_lossy(msg)),
			HiveError::ComposeFailed(msg) => write!(f, "Message composition failed: {}", String::from_utf8_lossy(msg)),
			HiveError::EmitFailed => write!(f, "Message emission failed"),
			HiveError::NoResponse => write!(f, "No response received"),
			HiveError::DecodeFailed => write!(f, "Message decoding failed"),
			HiveError::LockPoisoned => write!(f, "Lock poisoned"),
			HiveError::NoTrustedKeys => write!(f, "No trust store configured"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for HiveError {}

#[cfg(feature = "std")]
impl<T> From<::std::sync::PoisonError<T>> for HiveError {
	fn from(_: ::std::sync::PoisonError<T>) -> Self {
		HiveError::LockPoisoned
	}
}

#[cfg(feature = "std")]
impl From<::std::io::Error> for HiveError {
	fn from(e: ::std::io::Error) -> Self {
		HiveError::Io(e.to_string().into_bytes())
	}
}

impl From<crate::transport::TransportError> for HiveError {
	fn from(e: crate::transport::TransportError) -> Self {
		HiveError::Io(format!("{:?}", e).into_bytes())
	}
}

#[cfg(not(feature = "derive"))]
impl From<crate::TightBeamError> for HiveError {
	fn from(e: crate::TightBeamError) -> Self {
		HiveError::ComposeFailed(e.to_string().into_bytes())
	}
}
