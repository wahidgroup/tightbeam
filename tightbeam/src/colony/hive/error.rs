//! The error type of the hive framework.

use crate::transport::error::TransportError;
use crate::{Errorizable, TightBeamError};

/// The errors a hive returns.
///
/// Each failure mode is its own variant, so a caller can branch on it. A
/// wrapper variant keeps its cause chain through
/// [`core::error::Error::source`].
#[derive(Errorizable, Debug)]
pub enum HiveError {
	/// The servlet ID is not valid. The variant carries the ID bytes.
	#[error("Invalid servlet ID: {:#?}")]
	InvalidServletId(Vec<u8>),

	/// An I/O operation of the transport failed.
	#[error("IO error: {0}")]
	#[from]
	Io(std::io::Error),

	/// The transport failed during an exchange with a cluster or a servlet.
	#[error("Transport error: {0}")]
	#[from]
	Transport(TransportError),

	/// A frame failed to encode, decode, build, or sign.
	#[error("Frame error: {0}")]
	#[source]
	Frame(Box<TightBeamError>),

	/// The hive failed to emit a message.
	#[error("Message emission failed")]
	EmitFailed,

	/// The exchange ended before a response arrived.
	#[error("No response received")]
	NoResponse,

	/// A message failed to decode.
	#[error("Message decoding failed")]
	DecodeFailed,

	/// A thread panicked while it held a lock, so the lock is poisoned.
	#[error("Lock poisoned")]
	LockPoisoned,

	/// The [`ClusterSecurityGate`](super::gates::ClusterSecurityGate) has no
	/// trusted keys configured.
	#[error("No trusted keys configured")]
	NoTrustedKeys,

	/// A hive got a servlet registry that already holds a registration.
	#[error("The servlet registry already holds a registration")]
	OccupiedRegistry,
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
