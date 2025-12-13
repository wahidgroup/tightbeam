//! Drone-specific error types

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to drones
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DroneError {
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
impl core::fmt::Display for DroneError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			DroneError::InvalidServletId(id) => write!(f, "Invalid servlet ID: {:#?}", id),
			DroneError::Io(msg) => write!(f, "IO error: {}", String::from_utf8_lossy(msg)),
			DroneError::ComposeFailed(msg) => write!(f, "Message composition failed: {}", String::from_utf8_lossy(msg)),
			DroneError::EmitFailed => write!(f, "Message emission failed"),
			DroneError::NoResponse => write!(f, "No response received"),
			DroneError::DecodeFailed => write!(f, "Message decoding failed"),
			DroneError::LockPoisoned => write!(f, "Lock poisoned"),
			DroneError::NoTrustedKeys => write!(f, "No trusted keys configured"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for DroneError {}

#[cfg(feature = "std")]
impl<T> From<::std::sync::PoisonError<T>> for DroneError {
	fn from(_: ::std::sync::PoisonError<T>) -> Self {
		DroneError::LockPoisoned
	}
}

#[cfg(feature = "std")]
impl From<::std::io::Error> for DroneError {
	fn from(e: ::std::io::Error) -> Self {
		DroneError::Io(e.to_string().into_bytes())
	}
}

impl From<crate::transport::TransportError> for DroneError {
	fn from(e: crate::transport::TransportError) -> Self {
		DroneError::Io(format!("{:?}", e).into_bytes())
	}
}

#[cfg(not(feature = "derive"))]
impl From<crate::TightBeamError> for DroneError {
	fn from(e: crate::TightBeamError) -> Self {
		DroneError::ComposeFailed(e.to_string().into_bytes())
	}
}

