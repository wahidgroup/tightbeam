//! The error types of a cluster gateway.

use core::net::AddrParseError;

use crate::policy::TransitStatus;
use crate::transport::error::TransportError;
use crate::urn::UrnValidationError;
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

	/// The dial or the handshake to the selected hive, servlet, or peer gateway
	/// failed.
	#[error("Connect failed")]
	ConnectFailed,

	/// The party that answered a bound dial presented no certificate, or one
	/// that its route or registration does not name. The gateway ended the dial
	/// before it sent that party a frame.
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

	/// A signature that this gateway made fails to verify under its own
	/// signing certificate, so its key backend signs with a key that its
	/// identity does not certify.
	#[error("Own signature refused: {0}")]
	#[source]
	OwnSignatureRefused(TightBeamError),

	/// The response decoded but did not carry the expected field.
	#[error("Malformed response")]
	MalformedResponse,

	/// A hive registration failed.
	#[error("Registration failed")]
	RegistrationFailed,

	/// An address does not parse as one the protocol binds or dials, a servlet
	/// locator names an address other than the one beside it, or a heartbeat
	/// names an address that no hive registered.
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

	/// The gossip journal refused a record: the journal is at capacity, or the
	/// record's signer is at its cap for that record kind.
	#[error("Gossip journal at capacity")]
	GossipJournalAtCapacity,

	/// The gossip journal backend could not service the request.
	#[error("Gossip journal unavailable")]
	GossipJournalUnavailable,

	/// A reconcile reply exceeded the want-list cap or the peer-exchange cap.
	#[error("Oversized reconcile reply")]
	OversizedReconcileReply,

	/// A URN that a hive sent names no resource of the kind its field needs
	/// in this gateway's namespace, such as a hive of a foreign realm. The
	/// variant carries the cause.
	#[error("Invalid URN: {0}")]
	#[source]
	InvalidUrn(UrnValidationError),
}

impl From<AddrParseError> for ClusterError {
	fn from(_: AddrParseError) -> Self {
		Self::InvalidPeerAddress
	}
}

impl ClusterError {
	/// The status a refused hive registration or address update answers with.
	///
	/// A poisoned registry is this gateway's fault, so it answers `Unavailable`
	/// and not a denial of the hive's right to register. Every other refusal is
	/// a claim the gateway judged and denied.
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
	/// An upstream gateway reads `Unavailable` as a frame that never ran, and
	/// retries it on another route.
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

	/// Whether a refused peer slate or relay trail is the fault of the
	/// gateway that advertised it.
	///
	/// - A slate that conflicts with a held route, a slate past a cap, and a
	///   stale advertisement are the advertiser's.
	/// - Every other error is this gateway's own, such as a poisoned registry lock.
	///
	/// The direct advertisement answers the advertiser's fault with
	/// `PermissionDenied` and its own with `Unavailable`. The rumor path drops
	/// a rumor for the advertiser's fault and ends its loop for its own.
	#[must_use]
	pub(crate) fn blames_the_advertiser(&self) -> bool {
		match self {
			Self::PeerSlateConflict | Self::PeerCapExceeded | Self::StalePeerAd => true,
			Self::LockPoisoned
			| Self::InvalidPeerAddress
			| Self::AdvertiseAddressRequired
			| Self::UnknownServletType(_)
			| Self::NoHivesAvailable(_)
			| Self::ConnectFailed
			| Self::PeerMismatch
			| Self::NoResponse
			| Self::Transport(_)
			| Self::Frame(_)
			| Self::OwnSignatureRefused(_)
			| Self::MalformedResponse
			| Self::RegistrationFailed
			| Self::InvalidAddress(_)
			| Self::ServletNotOwned
			| Self::ServletNotFound
			| Self::SignerMismatch
			| Self::GossipJournalAtCapacity
			| Self::GossipJournalUnavailable
			| Self::OversizedReconcileReply
			| Self::InvalidUrn(_) => false,
		}
	}

	/// The label of a refused hive registration or address update for this
	/// error: the name of [`Self::transit_status`], a slash, and the error's
	/// stable kebab-case name, such as `PermissionDenied/invalid-urn`.
	///
	/// The name leaves out the error's fields, so one cause reads as one
	/// label whatever it names.
	#[must_use]
	pub(crate) fn refusal_label(&self) -> String {
		let status = self.transit_status();
		format!("{}/{}", status.as_str(), self.as_str())
	}

	crate::macros::names::refusal_names! {
		[
			/// The stable kebab-case name of this error, for audit labels.
			#[must_use]
			fn as_str = "";
			/// The label of an [`TransitStatus::Unavailable`] refusal for this
			/// error, a fault of the gateway's own: `Unavailable/` and the
			/// error's stable kebab-case name.
			///
			/// The name leaves out the error's fields, so one fault reads as
			/// one label whatever it names.
			#[must_use]
			fn unavailable_label = "Unavailable/";
		]
		{
			Self::LockPoisoned => "lock-poisoned",
			Self::InvalidPeerAddress => "invalid-peer-address",
			Self::AdvertiseAddressRequired => "advertise-address-required",
			Self::UnknownServletType(_) => "unknown-servlet-type",
			Self::NoHivesAvailable(_) => "no-hives-available",
			Self::ConnectFailed => "connect-failed",
			Self::PeerMismatch => "peer-mismatch",
			Self::NoResponse => "no-response",
			Self::Transport(_) => "transport",
			Self::Frame(_) => "frame",
			Self::OwnSignatureRefused(_) => "own-signature-refused",
			Self::MalformedResponse => "malformed-response",
			Self::RegistrationFailed => "registration-failed",
			Self::InvalidAddress(_) => "invalid-address",
			Self::ServletNotOwned => "servlet-not-owned",
			Self::ServletNotFound => "servlet-not-found",
			Self::SignerMismatch => "signer-mismatch",
			Self::PeerSlateConflict => "peer-slate-conflict",
			Self::PeerCapExceeded => "peer-cap-exceeded",
			Self::StalePeerAd => "stale-peer-ad",
			Self::GossipJournalAtCapacity => "gossip-journal-at-capacity",
			Self::GossipJournalUnavailable => "gossip-journal-unavailable",
			Self::OversizedReconcileReply => "oversized-reconcile-reply",
			Self::InvalidUrn(_) => "invalid-urn",
		}
	}
}

impl<T> From<std::sync::PoisonError<T>> for ClusterError {
	fn from(_: std::sync::PoisonError<T>) -> Self {
		ClusterError::LockPoisoned
	}
}

#[cfg(test)]
impl ClusterError {
	/// The variant of the error that `result` holds, or [`None`] for an `Ok`,
	/// for a test whose refusal carries a payload that is not its behavior.
	pub(crate) fn variant_of<T>(result: &Result<T, ClusterError>) -> Option<core::mem::Discriminant<ClusterError>> {
		result.as_ref().err().map(core::mem::discriminant)
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
	// delivered answers unknown, so an upstream gateway keeps its first route.
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
	// `Unavailable`, proves the frame never ran. A fault after the write leaves
	// open whether the frame ran.
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

	// A slate the registry judged and refused is the advertiser's fault. A
	// registry this gateway cannot read is its own.
	tb_cases! {
		fn blames_the_advertiser_of((error, expected): (ClusterError, bool)) {
			let blamed = error.blames_the_advertiser();
			assert_eq!(blamed, expected);
		}

		cases {
			a_conflicting_slate_is_the_advertisers => (ClusterError::PeerSlateConflict, true),
			a_slate_past_a_cap_is_the_advertisers => (ClusterError::PeerCapExceeded, true),
			a_stale_advertisement_is_the_advertisers => (ClusterError::StalePeerAd, true),
			a_poisoned_registry_is_the_gateways => (ClusterError::LockPoisoned, false),
		}
	}
}
