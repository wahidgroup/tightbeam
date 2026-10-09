//! Cluster gateway error types.

use core::net::AddrParseError;

use crate::policy::TransitStatus;
use crate::transport::error::TransportError;
use crate::{Errorizable, TightBeamError};

/// The errors of a cluster gateway.
///
/// Each failure mode is its own variant, so a caller can branch on it. A
/// wrapper variant preserves its cause chain through
/// [`core::error::Error::source`].
#[derive(Errorizable, Debug)]
pub enum ClusterError {
	/// A thread panicked while it held a cluster lock, so the lock is poisoned.
	#[error("Lock poisoned")]
	LockPoisoned,

	/// A configured peer or allowlist entry names no socket address.
	#[error("Peer address does not parse")]
	InvalidPeerAddress,

	/// A federating gateway bound the wildcard address and configured no
	/// advertise address, so every peer would refuse its advertisement.
	#[error("A wildcard bind needs an advertise address to federate")]
	AdvertiseAddressRequired,

	/// The URN names no servlet type that a route can answer.
	#[error("Unknown servlet type: {:#?}")]
	UnknownServletType(Vec<u8>),

	/// No hive is available for the servlet type.
	#[error("No hives available for servlet type: {:#?}")]
	NoHivesAvailable(Vec<u8>),

	/// The connection to the selected hive, servlet, or peer gateway could not
	/// be established.
	#[error("Connect failed")]
	ConnectFailed,

	/// The peer accepted the request but returned no response frame.
	#[error("No response")]
	NoResponse,

	/// The transport failed while the gateway talked to a hive, a servlet, or
	/// a peer gateway.
	#[error("Transport error: {0}")]
	#[from]
	Transport(TransportError),

	/// A frame failed to encode, decode, build, or sign.
	#[error("Frame error: {0}")]
	#[from]
	Frame(TightBeamError),

	/// The response decoded but did not carry the expected field.
	#[error("Malformed response")]
	MalformedResponse,

	/// A hive registration failed.
	#[error("Registration failed")]
	RegistrationFailed,

	/// An address is not one the protocol can dial, or a servlet locator names
	/// another address than the one beside it.
	#[error("Invalid address: {:#?}")]
	InvalidAddress(Vec<u8>),

	/// A hive's slate or address update claimed a route that another owner
	/// holds.
	#[error("Servlet not owned by hive")]
	ServletNotOwned,

	/// A servlet address update named a locator to remove that is not
	/// registered.
	#[error("Servlet address not found")]
	ServletNotFound,

	/// A re-registration or an address update presented a signer other than
	/// the one bound to the hive.
	#[error("Signer does not match hive binding")]
	SignerMismatch,

	/// A peer slate's key or dial address collides with a route another owner
	/// holds.
	#[error("Peer slate conflicts with local routes")]
	PeerSlateConflict,

	/// A peer slate would exceed the gateway cap or the route cap.
	#[error("Peer slate exceeds caps")]
	PeerCapExceeded,

	/// The peer advertisement is older than the newest one applied for its
	/// bucket.
	#[error("Peer advertisement is stale")]
	StalePeerAd,

	/// The gossip journal refused a record because a capacity bound was
	/// reached.
	#[error("Gossip journal at capacity")]
	GossipJournalAtCapacity,

	/// The gossip journal backend could not service the request.
	#[error("Gossip journal unavailable")]
	GossipJournalUnavailable,

	/// A reconcile reply exceeded the want-list cap or the peer-exchange cap.
	#[error("Oversized reconcile reply")]
	OversizedReconcileReply,
}

impl From<AddrParseError> for ClusterError {
	fn from(_: AddrParseError) -> Self {
		Self::InvalidPeerAddress
	}
}

impl ClusterError {
	/// The status a refused hive registration or address update answers
	/// with.
	///
	/// A poisoned registry is this gateway's fault, so the hive is told the
	/// gateway is unavailable rather than that it lacks the right to
	/// register. Every other refusal is a claim the gateway judged and
	/// denied.
	#[must_use]
	pub(crate) fn transit_status(&self) -> TransitStatus {
		match self {
			ClusterError::LockPoisoned => TransitStatus::Unavailable,
			_ => TransitStatus::PermissionDenied,
		}
	}

	/// Transit status a failed forward relays to the caller.
	///
	/// A servlet refusal relays unchanged so the caller keeps its
	/// retryability contract. Everything else degrades to
	/// [`TransitStatus::Unavailable`].
	#[must_use]
	pub(crate) fn forward_status(self) -> TransitStatus {
		match self {
			ClusterError::Transport(TransportError::OperationFailed(failure)) => {
				TransitStatus::try_from(failure).unwrap_or(TransitStatus::Unavailable)
			}
			_ => TransitStatus::Unavailable,
		}
	}
}

impl<T> From<std::sync::PoisonError<T>> for ClusterError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		ClusterError::LockPoisoned
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tb_cases;

	// A poisoned lock is the gateway's own fault and answers unavailable.
	// Every other refusal denies the hive's claim.
	tb_cases! {
		fn transit_status_of((error, expected): (ClusterError, TransitStatus)) {
			let status = error.transit_status();

			assert_eq!(status, expected);
		}
		cases {
			a_poisoned_lock_is_unavailable => (ClusterError::LockPoisoned, TransitStatus::Unavailable),
			a_signer_mismatch_is_denied => (ClusterError::SignerMismatch, TransitStatus::PermissionDenied),
			an_unowned_servlet_is_denied => (ClusterError::ServletNotOwned, TransitStatus::PermissionDenied),
		}
	}
}
