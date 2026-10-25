//! The error types of a cluster gateway.

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

	/// A gateway that federates bound the wildcard address and configured no
	/// advertise address, so every peer would refuse its advertisement.
	#[error("A wildcard bind needs an advertise address to federate")]
	AdvertiseAddressRequired,

	/// The URN names no servlet type that a route can answer.
	#[error("Unknown servlet type: {:#?}")]
	UnknownServletType(Vec<u8>),

	/// No hive is available for the servlet type.
	#[error("No hives available for servlet type: {:#?}")]
	NoHivesAvailable(Vec<u8>),

	/// The gateway could not connect to the selected hive, servlet, or peer
	/// gateway, because the dial or the handshake failed, or a peer route met
	/// a gateway with no peer plane.
	#[error("Connect failed")]
	ConnectFailed,

	/// The party that answered a bound dial presented no certificate, or one
	/// its route or its registration does not name, so the gateway ended the
	/// dial before it sent any frame to that party.
	#[error("Peer identity mismatch")]
	PeerMismatch,

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

	/// An address is not one the protocol can dial, a servlet locator names an
	/// address other than the one beside it, or a heartbeat names an address
	/// that no hive registered.
	#[error("Invalid address: {:#?}")]
	InvalidAddress(Vec<u8>),

	/// A hive's slate or address update claimed a route that another owner
	/// holds.
	#[error("Servlet not owned by hive")]
	ServletNotOwned,

	/// A servlet address update named a locator to remove, and the registry
	/// routes nothing at its key.
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

	/// The peer advertisement is older than the newest one the gateway applied
	/// for its bucket.
	#[error("Peer advertisement is stale")]
	StalePeerAd,

	/// The gossip journal refused a record because the journal reached its
	/// capacity, or the record's signer reached its cap for records of that
	/// kind.
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
	/// A poisoned registry is this gateway's fault, so the gateway tells the
	/// hive it is unavailable rather than that the hive lacks the right to
	/// register. Every other refusal is a claim the gateway judged and
	/// denied.
	#[must_use]
	pub(crate) fn transit_status(&self) -> TransitStatus {
		match self {
			ClusterError::LockPoisoned => TransitStatus::Unavailable,
			_ => TransitStatus::PermissionDenied,
		}
	}

	/// The transit status a failed forward relays to the caller.
	///
	/// - A refusal the far end answered relays unchanged, so the caller keeps its retryability contract.
	/// - A fault that [`Self::proves_undelivered`] answers [`TransitStatus::Unavailable`].
	/// - Any other fault answers [`TransitStatus::Unknown`], because the frame may have run.
	///
	/// A gateway that forwards to this one therefore reads `Unavailable` as a
	/// frame that never ran, and retries it on another route.
	#[must_use]
	pub(crate) fn forward_status(&self) -> TransitStatus {
		let answered = match self {
			ClusterError::Transport(error) => error.transit_status(),
			_ => None,
		};

		match answered {
			Some(status) => status,
			None if self.proves_undelivered() => TransitStatus::Unavailable,
			None => TransitStatus::Unknown,
		}
	}

	/// Whether this forward fault proves that the frame never reached its
	/// party, so a retry on another route runs it at most once.
	///
	/// Two kinds of fault prove it:
	///
	/// - A refused connect or handshake, an answer from another identity, or an
	///   address the protocol cannot dial.
	/// - A transport fault that [`TransportError::proves_unsent`] names.
	///
	/// Every other fault, such as a closed connection or a reply that never
	/// came, can follow a frame that arrived, so the frame may have run.
	#[must_use]
	pub(crate) fn proves_undelivered(&self) -> bool {
		match self {
			ClusterError::ConnectFailed | ClusterError::PeerMismatch | ClusterError::InvalidAddress(_) => true,
			ClusterError::Transport(fault) => fault.proves_unsent(),
			_ => false,
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
	use crate::transport::error::TransportFailure;

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

	// A hop that never reached its gateway answers unavailable, so the trail
	// weakens and the bounded retry takes the next route. A hop that may have
	// delivered answers unknown, so a gateway upstream keeps it on its first
	// route.
	tb_cases! {
		fn forward_status_of((error, expected): (ClusterError, TransitStatus)) {
			let status = error.forward_status();

			assert_eq!(status, expected);
		}

		cases {
			a_failed_dial_is_unavailable => (ClusterError::ConnectFailed, TransitStatus::Unavailable),
			another_gateway_at_the_socket_is_unavailable => (ClusterError::PeerMismatch, TransitStatus::Unavailable),
			a_reply_that_never_came_is_unknown => (ClusterError::NoResponse, TransitStatus::Unknown),
			a_closed_connection_is_unknown => (
				ClusterError::Transport(TransportError::ConnectionClosed),
				TransitStatus::Unknown
			),
			an_answered_refusal_relays => (
				ClusterError::Transport(TransportError::OperationFailed(TransportFailure::PermissionDenied)),
				TransitStatus::PermissionDenied
			),
		}
	}

	// A fault before the frame's write completed, or the far end's own
	// `Unavailable`, proves the frame never ran. A fault after the write proves
	// nothing.
	tb_cases! {
		fn proves_undelivered_of((error, expected): (ClusterError, bool)) {
			let undelivered = error.proves_undelivered();

			assert_eq!(undelivered, expected);
		}

		cases {
			a_refused_connect_proves_it => (ClusterError::ConnectFailed, true),
			an_answer_from_another_identity_proves_it => (ClusterError::PeerMismatch, true),
			a_failed_write_proves_it => (ClusterError::Transport(TransportError::SendFailed), true),
			an_unavailable_reply_proves_it => (
				ClusterError::Transport(TransportError::OperationFailed(TransportFailure::Unavailable)),
				true
			),
			a_full_stream_table_proves_it => (
				ClusterError::Transport(TransportError::OperationFailed(TransportFailure::StreamsExhausted)),
				true
			),
			a_reply_header_past_the_cap_does_not => (
				ClusterError::Transport(TransportError::OperationFailed(TransportFailure::SizeExceeded)),
				false
			),
			a_reply_that_never_came_does_not => (ClusterError::NoResponse, false),
			a_closed_connection_does_not => (ClusterError::Transport(TransportError::ConnectionClosed), false),
			a_malformed_reply_does_not => (ClusterError::MalformedResponse, false),
		}
	}
}
