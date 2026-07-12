//! Cluster-specific error types

use crate::transport::error::TransportError;
use crate::{Errorizable, TightBeamError};

/// Errors specific to clusters
///
/// Failure modes are distinct variants (not string payloads) so callers
/// can branch on them, and wrapper variants preserve their cause chain
/// through [`core::error::Error::source`].
#[derive(Errorizable, Debug)]
pub enum ClusterError {
	/// Lock poisoned
	#[error("Lock poisoned")]
	LockPoisoned,

	/// Unknown servlet type
	#[error("Unknown servlet type: {:#?}")]
	UnknownServletType(Vec<u8>),

	/// No hives available for servlet type
	#[error("No hives available for servlet type: {:#?}")]
	NoHivesAvailable(Vec<u8>),

	/// Connection to the selected hive/servlet could not be established
	#[error("Connect failed")]
	ConnectFailed,

	/// Peer accepted the request but returned no response frame
	#[error("No response")]
	NoResponse,

	/// Transport-level failure while communicating with a hive/servlet
	#[error("Transport error: {0}")]
	#[from]
	#[source]
	Transport(TransportError),

	/// Frame encode/decode/build/sign failure
	#[error("Frame error: {0}")]
	#[from]
	#[source]
	Frame(TightBeamError),

	/// Response decoded but did not carry the expected field
	#[error("Malformed response")]
	MalformedResponse,

	/// Registration failed
	#[error("Registration failed")]
	RegistrationFailed,

	/// Invalid servlet address format
	#[error("Invalid address: {:#?}")]
	InvalidAddress(Vec<u8>),

	/// Servlet address update referenced a route owned by a different hive
	#[error("Servlet not owned by hive")]
	ServletNotOwned,
}

impl<T> From<std::sync::PoisonError<T>> for ClusterError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		ClusterError::LockPoisoned
	}
}
