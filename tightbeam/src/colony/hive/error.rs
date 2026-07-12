//! Hive-specific error types

use crate::transport::error::TransportError;
use crate::{Errorizable, TightBeamError};

/// Errors specific to hives
///
/// Failure modes are distinct variants (not string payloads) so callers
/// can branch on them, and wrapper variants preserve their cause chain
/// through [`core::error::Error::source`].
#[derive(Errorizable, Debug)]
pub enum HiveError {
	/// Invalid servlet ID
	#[error("Invalid servlet ID: {:#?}")]
	InvalidServletId(Vec<u8>),

	/// Transport/IO error
	#[error("IO error: {0}")]
	#[from]
	#[source]
	Io(std::io::Error),

	/// Transport-level failure while communicating with a cluster/servlet
	#[error("Transport error: {0}")]
	#[from]
	#[source]
	Transport(TransportError),

	/// Frame encode/decode/build/sign failure
	#[error("Frame error: {0}")]
	#[source]
	Frame(Box<TightBeamError>),

	/// Message emission failed
	#[error("Message emission failed")]
	EmitFailed,

	/// No response received
	#[error("No response received")]
	NoResponse,

	/// Message decoding failed
	#[error("Message decoding failed")]
	DecodeFailed,

	/// Lock poisoned
	#[error("Lock poisoned")]
	LockPoisoned,

	/// No trusted keys configured for ClusterSecurityGate
	#[error("No trusted keys configured")]
	NoTrustedKeys,
}

impl<T> From<std::sync::PoisonError<T>> for HiveError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		HiveError::LockPoisoned
	}
}

// Boxed manually: `TightBeamError` embeds `HiveError`, so the unboxed
// wrapper would be infinitely sized.
impl From<TightBeamError> for HiveError {
	fn from(e: TightBeamError) -> Self {
		HiveError::Frame(Box::new(e))
	}
}
